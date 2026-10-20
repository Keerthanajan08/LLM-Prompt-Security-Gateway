"""Request/response models for the native API (/check, /query, /stats)."""

from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, Field

Verdict = Literal["safe", "blocked", "redacted", "flagged"]
Category = Literal["secret", "financial", "pii", "confidential", "injection"]


class CheckRequest(BaseModel):
    prompt: str = Field(..., min_length=1, description="Text to screen before it reaches an LLM.")


class QueryRequest(CheckRequest):
    pass


class PatternMatchOut(BaseModel):
    rule_name: str
    pack: str
    category: str
    matched_text: str = Field(..., description="Masked unless MASK_MATCHES_IN_RESPONSE=false.")
    start: int
    end: int


class SemanticMatchOut(BaseModel):
    doc_id: str
    similarity: float
    start: int
    end: int
    snippet: str | None = Field(
        None, description="Corpus text; only returned when EXPOSE_CORPUS_SNIPPETS=true (debugging)."
    )


class InjectionMatchOut(BaseModel):
    rule_name: str
    kind: Literal["heuristic", "semantic"]
    start: int
    end: int
    similarity: float | None = None


class CheckResponse(BaseModel):
    verdict: Verdict
    action_taken: Literal["none", "block", "redact", "log_only"]
    categories: list[Category]
    reasons: list[str]
    pattern_matches: list[PatternMatchOut] = []
    semantic_matches: list[SemanticMatchOut] = []
    injection_matches: list[InjectionMatchOut] = []
    sanitized_prompt: str | None = None
    from_cache: bool = False
    latency_ms: float


class QueryResponse(BaseModel):
    check: CheckResponse
    forwarded_to_llm: bool
    provider: str | None = None
    model: str | None = None
    answer: str | None = None
    response_check: CheckResponse | None = Field(
        None, description="Result of scanning the LLM's answer for leaks before returning it."
    )


class StatsResponse(BaseModel):
    total_checked: int
    safe: int
    blocked: int
    redacted: int
    flagged: int
    block_rate: float
    cache_hits: int
    injection_detections: int
    responses_scanned: int
    response_leaks: int
