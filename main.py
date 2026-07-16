"""
LLM Prompt-Security Gateway
============================

POST /check  -> run detection only, return the verdict (no LLM call)
POST /query  -> run detection, then forward to the LLM only if safe/redacted
GET  /stats  -> running counters

Detection pipeline (see app/langchain_pipeline.py):
  1. Verdict cache lookup (skip re-checking near-identical prompts)
  2. Pattern detection (regex — API keys, SSNs, credit cards, etc.)
  3. Semantic detection (embedding similarity against a confidential
     document corpus — catches paraphrased leaks regex can't)
  4. Verdict: safe / blocked / redacted, based on ON_LEAK_ACTION config

Run it:
    uvicorn app.main:app --reload
"""
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.config import settings
from app.langchain_pipeline import run_security_check
from app.llm_providers import get_llm_provider
from app.schemas import CheckRequest, CheckResponse, QueryRequest, QueryResponse, StatsResponse

app = FastAPI(
    title="LLM Prompt-Security Gateway",
    description="Detects pattern-based and semantic (paraphrased) leakage of sensitive data in outbound LLM prompts.",
    version="0.1.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

_stats = {"total_checked": 0, "blocked": 0, "redacted": 0, "safe": 0, "cache_hits": 0}


@app.get("/health")
def health():
    return {"status": "ok", "llm_provider": settings.llm_provider, "on_leak_action": settings.on_leak_action}


@app.post("/check", response_model=CheckResponse)
def check(request: CheckRequest):
    result = run_security_check(request.prompt)
    _stats["total_checked"] += 1
    _stats[result.verdict] = _stats.get(result.verdict, 0) + 1
    if "served from verdict cache" in result.reasons:
        _stats["cache_hits"] += 1
    return result


@app.post("/query", response_model=QueryResponse)
def query(request: QueryRequest):
    check_result = run_security_check(request.prompt)
    _stats["total_checked"] += 1
    _stats[check_result.verdict] = _stats.get(check_result.verdict, 0) + 1
    if "served from verdict cache" in check_result.reasons:
        _stats["cache_hits"] += 1

    if check_result.verdict == "blocked":
        return QueryResponse(check=check_result, answer=None, forwarded_to_llm=False)

    prompt_to_send = check_result.sanitized_prompt or request.prompt
    llm = get_llm_provider()
    answer = llm.generate(prompt_to_send)

    return QueryResponse(check=check_result, answer=answer, forwarded_to_llm=True, provider=llm.name)


@app.get("/stats", response_model=StatsResponse)
def stats():
    total = _stats["total_checked"]
    return StatsResponse(
        total_checked=total,
        blocked=_stats["blocked"],
        redacted=_stats["redacted"],
        safe=_stats["safe"],
        block_rate=round((_stats["blocked"] + _stats["redacted"]) / total, 4) if total else 0.0,
        cache_hits=_stats["cache_hits"],
    )
