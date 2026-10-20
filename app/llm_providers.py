"""
LLM providers behind one interface.

OpenAI, Groq and Gemini all expose the OpenAI chat-completions protocol, so
one httpx-based client covers all three (and anything else that speaks it:
OpenRouter, Ollama, vLLM, LM Studio...) via LLM_BASE_URL. No vendor SDKs.

MockProvider needs no API key, so the whole gateway runs for $0.
"""

from __future__ import annotations

import hashlib
import threading
from dataclasses import dataclass, field

import httpx

from app.config import settings


class LLMProviderError(RuntimeError):
    """The upstream LLM call failed (network, auth, rate limit, bad response)."""


class LLMConfigError(RuntimeError):
    """The provider is misconfigured (e.g. missing API key)."""


@dataclass
class LLMResult:
    text: str
    model: str
    usage: dict = field(default_factory=dict)


class BaseLLMProvider:
    name = "base"
    default_model = ""

    def resolve_model(self, requested: str | None) -> str:
        if settings.llm_model:
            return settings.llm_model
        if requested and requested.lower() not in ("auto", "default", "gateway"):
            return requested
        return self.default_model

    def chat(
        self,
        messages: list[dict],
        *,
        model: str | None = None,
        max_tokens: int | None = None,
        temperature: float | None = None,
    ) -> LLMResult:
        raise NotImplementedError

    def generate(self, prompt: str) -> LLMResult:
        return self.chat([{"role": "user", "content": prompt}])


class MockProvider(BaseLLMProvider):
    name = "mock"
    default_model = "mock-1"

    def chat(self, messages, *, model=None, max_tokens=None, temperature=None) -> LLMResult:
        last = next((m for m in reversed(messages) if m.get("role") == "user"), messages[-1])
        content = last.get("content") if isinstance(last.get("content"), str) else str(last.get("content"))
        digest = hashlib.sha256(content.encode()).hexdigest()[:8]
        return LLMResult(
            text=f"[mock-llm:{digest}] Response generated for the (already security-checked) prompt.",
            model=self.resolve_model(model),
            usage={"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        )


class OpenAICompatibleProvider(BaseLLMProvider):
    def __init__(
        self,
        name: str,
        base_url: str,
        api_key: str | None,
        default_model: str,
        client: httpx.Client | None = None,
    ):
        if not api_key:
            raise LLMConfigError(f"LLM_PROVIDER={name} but no API key is set ({name.upper()}_API_KEY).")
        self.name = name
        self.default_model = default_model
        self._url = base_url.rstrip("/") + "/chat/completions"
        self._headers = {"Authorization": f"Bearer {api_key}"}
        self._client = client or httpx.Client(timeout=settings.llm_timeout_seconds)

    def chat(self, messages, *, model=None, max_tokens=None, temperature=None) -> LLMResult:
        resolved = self.resolve_model(model)
        body: dict = {
            "model": resolved,
            "messages": messages,
            "max_tokens": max_tokens or settings.llm_max_tokens,
        }
        if temperature is not None:
            body["temperature"] = temperature
        try:
            resp = self._client.post(self._url, json=body, headers=self._headers)
        except httpx.HTTPError as exc:
            raise LLMProviderError(f"{self.name}: request failed: {exc.__class__.__name__}") from exc
        if resp.status_code >= 400:
            # Don't echo the upstream body: it can include request details.
            raise LLMProviderError(f"{self.name}: upstream returned HTTP {resp.status_code}")
        try:
            data = resp.json()
            text = data["choices"][0]["message"]["content"] or ""
        except (ValueError, KeyError, IndexError, TypeError) as exc:
            raise LLMProviderError(f"{self.name}: unexpected response format") from exc
        return LLMResult(text=text, model=data.get("model", resolved), usage=data.get("usage") or {})


# Defaults current as of October 2026; override with LLM_MODEL as models change.
PROVIDER_PRESETS = {
    "openai": ("https://api.openai.com/v1", "openai_api_key", "gpt-5-mini"),
    "groq": ("https://api.groq.com/openai/v1", "groq_api_key", "openai/gpt-oss-120b"),
    "gemini": ("https://generativelanguage.googleapis.com/v1beta/openai", "gemini_api_key", "gemini-3.8-flash"),
}


def build_provider(name: str, client: httpx.Client | None = None) -> BaseLLMProvider:
    if name == "mock":
        return MockProvider()
    if name not in PROVIDER_PRESETS:
        # Config validation already restricts LLM_PROVIDER; this guards direct
        # callers. v0.1 silently fell back to the mock here, which meant a
        # typo in production returned fake answers instead of failing.
        raise LLMConfigError(f"Unknown LLM provider {name!r}")
    base_url, key_attr, default_model = PROVIDER_PRESETS[name]
    return OpenAICompatibleProvider(
        name=name,
        base_url=settings.llm_base_url or base_url,
        api_key=getattr(settings, key_attr),
        default_model=default_model,
        client=client,
    )


_provider_instance: BaseLLMProvider | None = None
_provider_lock = threading.Lock()


def get_llm_provider() -> BaseLLMProvider:
    global _provider_instance
    with _provider_lock:
        if _provider_instance is None:
            _provider_instance = build_provider(settings.llm_provider)
        return _provider_instance


def set_llm_provider(provider: BaseLLMProvider | None) -> None:
    """Swap the active provider (tests, or wiring a custom provider)."""
    global _provider_instance
    with _provider_lock:
        _provider_instance = provider
