"""
LLM Prompt-Security Gateway
============================

GET  /health                -> liveness + active configuration
POST /check                 -> screen a prompt, return the verdict (no LLM call)
POST /query                 -> screen, forward to the LLM if allowed, screen the answer
POST /v1/chat/completions   -> OpenAI-compatible drop-in proxy (see app/openai_compat.py)
GET  /stats                 -> running counters

Detection pipeline (app/langchain_pipeline.py):
  1. Pattern detection: regex + checksum rules in configurable packs
  2. Semantic detection: per-sentence embedding similarity against a
     confidential corpus (catches paraphrased leaks regex can't)
  3. Prompt-injection detection: heuristics + similarity to known attacks
  4. Verdict: safe / blocked / redacted / flagged, per ON_LEAK_ACTION

Run it:
    uvicorn app.main:app --reload
"""

from contextlib import asynccontextmanager

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from app.config import settings
from app.detectors.injection_detector import get_exemplars
from app.detectors.pattern_detector import rules_for_packs
from app.detectors.semantic_detector import get_corpus
from app.langchain_pipeline import PromptTooLargeError, run_security_check
from app.llm_providers import LLMConfigError, LLMProviderError, get_llm_provider
from app.openai_compat import openai_error
from app.openai_compat import router as openai_router
from app.schemas import CheckRequest, CheckResponse, QueryRequest, QueryResponse, StatsResponse
from app.stats import stats

__version__ = "0.2.0"


@asynccontextmanager
async def lifespan(_: FastAPI):
    # Fail fast on bad config, and load the model + corpus at startup instead
    # of on the first request.
    rules_for_packs(tuple(settings.rule_pack_list))
    get_corpus()
    get_exemplars()
    yield


app = FastAPI(
    title="LLM Prompt-Security Gateway",
    description=(
        "Screens LLM traffic for secrets, PII, paraphrased leaks of confidential documents "
        "and prompt injection, in both directions."
    ),
    version=__version__,
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.include_router(openai_router)


@app.exception_handler(PromptTooLargeError)
async def _too_large(request: Request, exc: PromptTooLargeError):
    if request.url.path.startswith("/v1/"):
        return openai_error(413, str(exc), "prompt_too_large", "invalid_request_error")
    return JSONResponse(status_code=413, content={"detail": str(exc)})


@app.exception_handler(LLMProviderError)
async def _upstream_error(_: Request, exc: LLMProviderError):
    return JSONResponse(status_code=502, content={"detail": str(exc)})


@app.exception_handler(LLMConfigError)
async def _config_error(_: Request, exc: LLMConfigError):
    return JSONResponse(status_code=500, content={"detail": str(exc)})


@app.get("/health")
def health():
    return {
        "status": "ok",
        "version": __version__,
        "llm_provider": settings.llm_provider,
        "on_leak_action": settings.on_leak_action,
        "on_response_leak_action": settings.on_response_leak_action,
        "rule_packs": settings.rule_pack_list,
        "embedding_backend": settings.embedding_backend,
        "corpus_chunks": len(get_corpus()),
        "injection_detection": settings.enable_injection_detection,
    }


@app.post("/check", response_model=CheckResponse)
def check(request: CheckRequest):
    result = run_security_check(request.prompt)
    stats.record_prompt(result)
    return result


@app.post("/query", response_model=QueryResponse)
def query(request: QueryRequest):
    check_result = run_security_check(request.prompt)
    stats.record_prompt(check_result)
    if check_result.verdict == "blocked":
        return QueryResponse(check=check_result, forwarded_to_llm=False)

    prompt_to_send = check_result.sanitized_prompt or request.prompt
    llm = get_llm_provider()
    result = llm.generate(prompt_to_send)

    response_check = run_security_check(result.text, direction="response")
    stats.record_response(response_check)
    if response_check.verdict == "blocked":
        answer = None
    elif response_check.verdict == "redacted":
        answer = response_check.sanitized_prompt
    else:
        answer = result.text

    return QueryResponse(
        check=check_result,
        forwarded_to_llm=True,
        provider=llm.name,
        model=result.model,
        answer=answer,
        response_check=response_check,
    )


@app.get("/stats", response_model=StatsResponse)
def get_stats():
    return stats.snapshot()
