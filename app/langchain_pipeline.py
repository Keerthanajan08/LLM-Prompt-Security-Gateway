"""
The check pipeline, composed with LangChain's Runnable interface:

    prepare -> embedding stage (cached) -> deterministic stage -> decide -> response

Each stage is a small RunnableLambda passing a state dict along. The
pipeline is linear on purpose; it needs composition, not an agent.

The same pipeline screens both directions:
- direction="prompt":   outbound prompts (leaks + prompt injection), enforced
                        with ON_LEAK_ACTION
- direction="response": the LLM's answer (leaks only), enforced with
                        ON_RESPONSE_LEAK_ACTION
"""

from __future__ import annotations

import time
from typing import Literal

from langchain_core.runnables import RunnableLambda

from app.cache import cache_key, get_result_cache
from app.config import settings
from app.detectors.injection_detector import (
    InjectionMatch,
    detect_injection_heuristics,
    detect_injection_semantic,
)
from app.detectors.pattern_detector import detect_patterns
from app.detectors.semantic_detector import SemanticMatch, detect_semantic_leak, get_corpus
from app.embeddings import get_embedder
from app.schemas import (
    CheckResponse,
    InjectionMatchOut,
    PatternMatchOut,
    SemanticMatchOut,
)
from app.text_utils import chunk_text, mask_value, redact_spans

Direction = Literal["prompt", "response"]


class PromptTooLargeError(ValueError):
    pass


def _fingerprint() -> str:
    embedder = get_embedder()
    model = getattr(embedder, "model_name", embedder.name)
    return ":".join(
        str(p)
        for p in (
            "v2",
            model,
            settings.semantic_leak_threshold,
            settings.injection_similarity_threshold,
            settings.max_chunks_per_prompt,
            get_corpus().fingerprint,
        )
    )


# --- stages ------------------------------------------------------------------


def _prepare(inputs: dict) -> dict:
    text = inputs["text"]
    if len(text) > settings.max_prompt_chars:
        raise PromptTooLargeError(
            f"Input is {len(text)} characters; the limit is {settings.max_prompt_chars} (MAX_PROMPT_CHARS)."
        )
    return {**inputs, "started": time.perf_counter()}


def _embedding_stage(state: dict) -> dict:
    """Semantic-leak and injection-similarity search. The only expensive part,
    so the only part that is cached."""
    cache = get_result_cache()
    key = cache_key(state["text"], _fingerprint())
    cached = cache.get(key)
    if cached is not None:
        corpus = get_corpus()
        semantic = [SemanticMatch(snippet=corpus.text_for(m["doc_id"]), **m) for m in cached["semantic"]]
        inj_sem = [InjectionMatch(**m) for m in cached["injection"]]
        return {**state, "semantic": semantic, "injection_semantic": inj_sem, "from_cache": True}

    chunks = chunk_text(state["text"], settings.max_chunks_per_prompt)
    vectors = get_embedder().encode_batch([c.text for c in chunks]) if chunks else None
    semantic = detect_semantic_leak(chunks, vectors) if chunks else []
    inj_sem = detect_injection_semantic(chunks, vectors) if chunks else []

    cache.set(
        key,
        {
            # Offsets, scores and corpus ids only: no prompt text, and no
            # corpus text either (it is confidential too).
            "semantic": [
                {"doc_id": m.doc_id, "similarity": m.similarity, "start": m.start, "end": m.end} for m in semantic
            ],
            "injection": [m.__dict__ for m in inj_sem],
        },
    )
    return {**state, "semantic": semantic, "injection_semantic": inj_sem, "from_cache": False}


def _deterministic_stage(state: dict) -> dict:
    """Regex detectors. Always run, cache hit or not."""
    return {
        **state,
        "patterns": detect_patterns(state["text"]),
        "injection_heuristic": detect_injection_heuristics(state["text"]),
    }


def _decide(state: dict) -> dict:
    direction: Direction = state["direction"]
    patterns, semantic = state["patterns"], state["semantic"]
    check_injection = state["check_injection"] and settings.enable_injection_detection and direction == "prompt"
    injection = (state["injection_heuristic"] + state["injection_semantic"]) if check_injection else []
    action = settings.on_leak_action if direction == "prompt" else settings.on_response_leak_action

    categories: list[str] = []
    for m in patterns:
        if m.category not in categories:
            categories.append(m.category)
    if semantic:
        categories.append("confidential")
    if injection:
        categories.append("injection")

    reasons: list[str] = []
    if patterns:
        rules = sorted({m.rule_name for m in patterns})
        reasons.append(f"{len(patterns)} pattern match(es): {', '.join(rules)}")
    if semantic:
        docs = sorted({m.doc_id.split("#")[0] for m in semantic})
        reasons.append(f"{len(semantic)} passage(s) resemble confidential documents: {', '.join(docs)}")
    if injection:
        reasons.append(f"possible prompt injection: {', '.join(sorted({m.rule_name for m in injection}))}")

    sanitized = None
    if not categories:
        verdict, action_taken = "safe", "none"
        reasons.append("no sensitive data or injection detected")
    elif action == "log_only":
        verdict, action_taken = "flagged", "log_only"
        reasons.append("ON_LEAK_ACTION=log_only: flagged for review, not enforced")
    elif action == "block":
        verdict, action_taken = "blocked", "block"
    elif injection:
        # An attack can't be redacted into something safe; its intent is
        # spread across the whole prompt.
        verdict, action_taken = "blocked", "block"
        reasons.append("prompt injection cannot be redacted, so the prompt was blocked")
    else:
        verdict, action_taken = "redacted", "redact"
        spans = [(m.start, m.end, m.rule_name) for m in patterns]
        spans += [(m.start, m.end, "confidential") for m in semantic]
        sanitized = redact_spans(state["text"], spans)

    return {
        **state,
        "injection": injection,
        "categories": categories,
        "reasons": reasons,
        "verdict": verdict,
        "action_taken": action_taken,
        "sanitized": sanitized,
    }


def _dedupe_semantic(matches: list[SemanticMatch]) -> list[SemanticMatch]:
    best: dict[str, SemanticMatch] = {}
    for m in matches:
        if m.doc_id not in best or m.similarity > best[m.doc_id].similarity:
            best[m.doc_id] = m
    return sorted(best.values(), key=lambda m: -m.similarity)


def _build_response(state: dict) -> CheckResponse:
    mask = settings.mask_matches_in_response
    return CheckResponse(
        verdict=state["verdict"],
        action_taken=state["action_taken"],
        categories=state["categories"],
        reasons=state["reasons"],
        pattern_matches=[
            PatternMatchOut(
                rule_name=m.rule_name,
                pack=m.pack,
                category=m.category,
                matched_text=mask_value(m.text) if mask else m.text,
                start=m.start,
                end=m.end,
            )
            for m in state["patterns"]
        ],
        semantic_matches=[
            SemanticMatchOut(
                doc_id=m.doc_id,
                similarity=m.similarity,
                start=m.start,
                end=m.end,
                snippet=m.snippet if settings.expose_corpus_snippets else None,
            )
            for m in _dedupe_semantic(state["semantic"])
        ],
        injection_matches=[
            InjectionMatchOut(rule_name=m.rule_name, kind=m.kind, start=m.start, end=m.end, similarity=m.similarity)
            for m in state["injection"]
        ],
        sanitized_prompt=state["sanitized"],
        from_cache=state["from_cache"],
        latency_ms=round((time.perf_counter() - state["started"]) * 1000, 2),
    )


security_check_chain = (
    RunnableLambda(_prepare)
    | RunnableLambda(_embedding_stage)
    | RunnableLambda(_deterministic_stage)
    | RunnableLambda(_decide)
    | RunnableLambda(_build_response)
)


def run_security_check(text: str, *, direction: Direction = "prompt", check_injection: bool = True) -> CheckResponse:
    return security_check_chain.invoke({"text": text, "direction": direction, "check_injection": check_injection})
