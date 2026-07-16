"""
LangChain's job here: compose the check -> decide -> forward pipeline as
a runnable sequence, instead of one long function. Each stage is a small
RunnableLambda; LangChain wires them together and passes state through.

This is a genuinely small use of LangChain — deliberately so. The
pipeline is simple enough that it doesn't need agentic branching (that's
what the LangGraph-based Decision Intelligence project is for); it needs
composition. Using LangChain's Runnable interface for that is honest: the
right tool for a linear, well-defined pipeline, not an agent for an agent's
sake.
"""
import time

from langchain_core.runnables import RunnableLambda

from app.cache import get_verdict_cache
from app.detectors.pattern_detector import detect_patterns, redact_patterns
from app.detectors.semantic_detector import detect_semantic_leak
from app.embeddings import get_embedder
from app.config import settings
from app.schemas import CheckResponse, PatternMatch, MatchedSource


def _run_check(prompt: str) -> dict:
    start = time.perf_counter()
    embedder = get_embedder()
    cache = get_verdict_cache()

    vector = embedder.encode(prompt)

    # Fast path: has a near-identical prompt already been verdicted?
    cached = cache.lookup(vector)
    if cached.hit:
        latency_ms = (time.perf_counter() - start) * 1000
        return {
            "prompt": prompt,
            "vector": vector,
            "verdict": cached.verdict.verdict,
            "reasons": cached.verdict.reasons + ["served from verdict cache"],
            "pattern_matches": [],
            "semantic_matches": [],
            "latency_ms": latency_ms,
            "from_cache": True,
        }

    # Stage 1: pattern detection (cheap, structural)
    pattern_result = detect_patterns(prompt)

    # Stage 2: semantic detection (catches paraphrased/contextual leaks)
    semantic_result = detect_semantic_leak(vector)

    reasons = []
    if pattern_result.has_matches:
        reasons.append(f"{len(pattern_result.matches)} pattern rule(s) matched")
    if semantic_result.has_matches:
        reasons.append(f"{len(semantic_result.matches)} semantic match(es) against confidential corpus")

    if pattern_result.has_matches or semantic_result.has_matches:
        verdict = "blocked" if settings.on_leak_action == "block" else (
            "redacted" if settings.on_leak_action == "redact" else "safe"
        )
        if settings.on_leak_action == "log_only":
            reasons.append("action=log_only: flagged but not blocked")
    else:
        verdict = "safe"
        reasons.append("no pattern or semantic matches")

    cache.store(prompt, verdict, reasons, vector)
    latency_ms = (time.perf_counter() - start) * 1000

    return {
        "prompt": prompt,
        "vector": vector,
        "verdict": verdict,
        "reasons": reasons,
        "pattern_matches": pattern_result.matches,
        "semantic_matches": semantic_result.matches,
        "latency_ms": latency_ms,
        "from_cache": False,
    }


def _build_response(state: dict) -> CheckResponse:
    sanitized = None
    if state["verdict"] == "redacted":
        sanitized = redact_patterns(state["prompt"])

    return CheckResponse(
        verdict=state["verdict"],
        action_taken=settings.on_leak_action if state["verdict"] != "safe" else "none",
        reasons=state["reasons"],
        pattern_matches=[PatternMatch(rule_name=n, matched_text=t) for n, t in state["pattern_matches"]],
        semantic_matches=[
            MatchedSource(doc_id=d, snippet=s, similarity=sc) for d, s, sc in state["semantic_matches"]
        ],
        sanitized_prompt=sanitized,
        latency_ms=round(state["latency_ms"], 2),
    )


# The actual LangChain composition: two RunnableLambdas chained with `|`.
security_check_chain = RunnableLambda(_run_check) | RunnableLambda(_build_response)


def run_security_check(prompt: str) -> CheckResponse:
    return security_check_chain.invoke(prompt)
