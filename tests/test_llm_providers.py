import json

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings, settings
from app.llm_providers import (
    PROVIDER_PRESETS,
    LLMConfigError,
    LLMProviderError,
    MockProvider,
    OpenAICompatibleProvider,
    build_provider,
)


def make_provider(handler, **kwargs):
    client = httpx.Client(transport=httpx.MockTransport(handler))
    return OpenAICompatibleProvider(
        name=kwargs.get("name", "openai"),
        base_url=kwargs.get("base_url", "https://api.example.com/v1/"),
        api_key="test-key",
        default_model="default-model",
        client=client,
    )


def ok_handler(captured):
    def handler(request: httpx.Request):
        captured["url"] = str(request.url)
        captured["auth"] = request.headers["authorization"]
        captured["body"] = json.loads(request.content)
        return httpx.Response(
            200,
            json={
                "model": captured["body"]["model"],
                "choices": [{"message": {"role": "assistant", "content": "hi!"}}],
                "usage": {"total_tokens": 3},
            },
        )

    return handler


def test_sends_openai_chat_completions_request():
    captured = {}
    provider = make_provider(ok_handler(captured))
    result = provider.chat([{"role": "user", "content": "hello"}], model="gpt-x", temperature=0.2, max_tokens=50)
    assert captured["url"] == "https://api.example.com/v1/chat/completions"
    assert captured["auth"] == "Bearer test-key"
    assert captured["body"] == {
        "model": "gpt-x",
        "messages": [{"role": "user", "content": "hello"}],
        "max_tokens": 50,
        "temperature": 0.2,
    }
    assert result.text == "hi!" and result.model == "gpt-x" and result.usage == {"total_tokens": 3}


@pytest.mark.parametrize("requested, expected", [(None, "default-model"), ("auto", "default-model"), ("m-2", "m-2")])
def test_model_resolution(requested, expected):
    captured = {}
    make_provider(ok_handler(captured)).chat([{"role": "user", "content": "x"}], model=requested)
    assert captured["body"]["model"] == expected


def test_configured_model_overrides_client_choice(monkeypatch):
    monkeypatch.setattr(settings, "llm_model", "pinned-model")
    captured = {}
    make_provider(ok_handler(captured)).chat([{"role": "user", "content": "x"}], model="client-choice")
    assert captured["body"]["model"] == "pinned-model"


def test_http_error_becomes_provider_error_without_echoing_body():
    provider = make_provider(lambda r: httpx.Response(429, text="rate limited for prompt: SECRET"))
    with pytest.raises(LLMProviderError) as exc:
        provider.generate("hello")
    assert "429" in str(exc.value) and "SECRET" not in str(exc.value)


def test_network_error_becomes_provider_error():
    def handler(request):
        raise httpx.ConnectTimeout("timed out", request=request)

    with pytest.raises(LLMProviderError, match="ConnectTimeout"):
        make_provider(handler).generate("hello")


def test_malformed_response_becomes_provider_error():
    with pytest.raises(LLMProviderError, match="unexpected response"):
        make_provider(lambda r: httpx.Response(200, json={"nope": True})).generate("hello")


def test_missing_api_key_is_a_config_error(monkeypatch):
    monkeypatch.setattr(settings, "groq_api_key", None)
    with pytest.raises(LLMConfigError, match="GROQ_API_KEY"):
        build_provider("groq")


def test_unknown_provider_is_an_error_not_a_silent_mock():
    with pytest.raises(LLMConfigError):
        build_provider("not-a-provider")


def test_config_rejects_unknown_provider_name():
    with pytest.raises(ValidationError):
        Settings(llm_provider="chatgpt")


@pytest.mark.parametrize("name", sorted(PROVIDER_PRESETS))
def test_presets_point_at_openai_compatible_endpoints(name, monkeypatch):
    monkeypatch.setattr(settings, f"{name}_api_key", "k")
    provider = build_provider(name)
    assert provider._url == PROVIDER_PRESETS[name][0] + "/chat/completions"


def test_base_url_override_supports_any_compatible_server(monkeypatch):
    monkeypatch.setattr(settings, "openai_api_key", "k")
    monkeypatch.setattr(settings, "llm_base_url", "http://localhost:11434/v1")  # e.g. Ollama
    assert build_provider("openai")._url == "http://localhost:11434/v1/chat/completions"


def test_mock_provider_is_deterministic():
    a = MockProvider().generate("hello").text
    assert a == MockProvider().generate("hello").text
    assert a != MockProvider().generate("goodbye").text
