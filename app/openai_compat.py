"""
OpenAI-compatible endpoint: POST /v1/chat/completions.

Any app using an OpenAI SDK can route through the gateway by changing its
base URL, with no code changes:

    client = OpenAI(base_url="http://localhost:8000/v1", api_key="unused")

Every message is screened before it is forwarded, and the model's answer is
screened before it is returned:

- Leak detection runs on every message. Injection detection runs only on
  `user` and `tool` content: system/developer prompts are written by the
  application owner, and tool output is the classic indirect-injection path.
- A blocked prompt gets an OpenAI-style 400 error (code "prompt_blocked").
- A leak in the answer is redacted, or the answer is withheld with
  finish_reason "content_filter", depending on ON_RESPONSE_LEAK_ACTION.

Streaming (`stream: true`) is supported, but buffered: the full answer has
to be scanned before any of it can be released, so it arrives as a single
content chunk. Token-by-token streaming would let a secret reach the client
before the scanner sees the end of it.
"""

from __future__ import annotations

import json
import time
import uuid
from typing import Any

from fastapi import APIRouter
from fastapi.responses import JSONResponse, StreamingResponse
from pydantic import BaseModel, ConfigDict

from app.langchain_pipeline import run_security_check
from app.llm_providers import LLMConfigError, LLMProviderError, get_llm_provider
from app.schemas import CheckResponse
from app.stats import stats

router = APIRouter(prefix="/v1", tags=["OpenAI-compatible"])

INJECTION_CHECKED_ROLES = {"user", "tool", "function"}
WITHHELD_MESSAGE = "[Response withheld by the prompt-security gateway: it contained sensitive data.]"
_SEVERITY = {"safe": 0, "flagged": 1, "redacted": 2, "blocked": 3}


class ChatMessage(BaseModel):
    model_config = ConfigDict(extra="allow")
    role: str
    content: str | list[dict[str, Any]] | None = None


class ChatCompletionRequest(BaseModel):
    model_config = ConfigDict(extra="allow")
    model: str = "auto"
    messages: list[ChatMessage]
    max_tokens: int | None = None
    max_completion_tokens: int | None = None
    temperature: float | None = None
    stream: bool = False


def openai_error(status: int, message: str, code: str, err_type: str, extra: dict | None = None) -> JSONResponse:
    body = {"error": {"message": message, "type": err_type, "param": None, "code": code}}
    if extra:
        body["error"].update(extra)
    return JSONResponse(status_code=status, content=body)


def _screen_text(text: str, role: str) -> CheckResponse:
    result = run_security_check(text, check_injection=role in INJECTION_CHECKED_ROLES)
    stats.record_prompt(result)
    return result


def _screen_messages(messages: list[ChatMessage]) -> tuple[list[dict], str, list[dict]]:
    """Return (sanitised messages, overall verdict, per-part findings)."""
    sanitised, findings, worst = [], [], "safe"

    def note(index: int, part: int | None, result: CheckResponse) -> None:
        nonlocal worst
        if _SEVERITY[result.verdict] > _SEVERITY[worst]:
            worst = result.verdict
        if result.verdict != "safe":
            findings.append(
                {
                    "message_index": index,
                    "content_part": part,
                    "verdict": result.verdict,
                    "categories": result.categories,
                    "reasons": result.reasons,
                }
            )

    for i, msg in enumerate(messages):
        out = msg.model_dump(exclude_none=True)
        if isinstance(msg.content, str) and msg.content:
            result = _screen_text(msg.content, msg.role)
            note(i, None, result)
            if result.sanitized_prompt is not None:
                out["content"] = result.sanitized_prompt
        elif isinstance(msg.content, list):
            parts = []
            for j, part in enumerate(msg.content):
                part = dict(part)
                if part.get("type") == "text" and isinstance(part.get("text"), str) and part["text"]:
                    result = _screen_text(part["text"], msg.role)
                    note(i, j, result)
                    if result.sanitized_prompt is not None:
                        part["text"] = result.sanitized_prompt
                parts.append(part)
            out["content"] = parts
        sanitised.append(out)
    return sanitised, worst, findings


@router.get("/models")
def list_models():
    provider = get_llm_provider()
    return {
        "object": "list",
        "data": [{"id": provider.default_model, "object": "model", "created": 0, "owned_by": provider.name}],
    }


@router.post("/chat/completions")
def chat_completions(request: ChatCompletionRequest):
    if not request.messages:
        return openai_error(400, "messages must not be empty", "invalid_messages", "invalid_request_error")

    sanitised, prompt_verdict, findings = _screen_messages(request.messages)
    headers = {"x-gateway-prompt-verdict": prompt_verdict}

    if prompt_verdict == "blocked":
        reasons = sorted({r for f in findings if f["verdict"] == "blocked" for r in f["reasons"]})
        resp = openai_error(
            400,
            "Request blocked by the prompt-security gateway: " + "; ".join(reasons),
            "prompt_blocked",
            "invalid_request_error",
            {"gateway": {"verdict": "blocked", "findings": findings}},
        )
        resp.headers.update(headers)
        return resp

    try:
        provider = get_llm_provider()
        result = provider.chat(
            sanitised,
            model=request.model,
            max_tokens=request.max_completion_tokens or request.max_tokens,
            temperature=request.temperature,
        )
    except LLMConfigError as exc:
        return openai_error(500, str(exc), "gateway_misconfigured", "server_error")
    except LLMProviderError as exc:
        return openai_error(502, str(exc), "upstream_error", "api_error")

    response_check = run_security_check(result.text, direction="response")
    stats.record_response(response_check)
    content, finish_reason = result.text, "stop"
    if response_check.verdict == "blocked":
        content, finish_reason = WITHHELD_MESSAGE, "content_filter"
    elif response_check.verdict == "redacted":
        content = response_check.sanitized_prompt
    headers["x-gateway-response-verdict"] = response_check.verdict

    completion_id = f"chatcmpl-gw-{uuid.uuid4().hex[:24]}"
    created = int(time.time())
    gateway_info = {
        "prompt_verdict": prompt_verdict,
        "response_verdict": response_check.verdict,
        "findings": findings,
        "provider": provider.name,
    }

    if request.stream:

        def events():
            base = {"id": completion_id, "object": "chat.completion.chunk", "created": created, "model": result.model}
            for delta, reason in (({"role": "assistant"}, None), ({"content": content}, None), ({}, finish_reason)):
                chunk = {**base, "choices": [{"index": 0, "delta": delta, "finish_reason": reason}]}
                yield f"data: {json.dumps(chunk)}\n\n"
            yield "data: [DONE]\n\n"

        return StreamingResponse(events(), media_type="text/event-stream", headers=headers)

    body = {
        "id": completion_id,
        "object": "chat.completion",
        "created": created,
        "model": result.model,
        "choices": [{"index": 0, "message": {"role": "assistant", "content": content}, "finish_reason": finish_reason}],
        "usage": result.usage or {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        "gateway": gateway_info,
    }
    return JSONResponse(content=body, headers=headers)
