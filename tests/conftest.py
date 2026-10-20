"""
Test setup. The environment is pinned *before* app modules are imported,
because app.config builds its Settings object at import time. That keeps a
developer's local .env (real API keys, Redis URL...) out of the test run.
"""

import os

os.environ.update(
    {
        "EMBEDDING_BACKEND": "hashing",
        "LLM_PROVIDER": "mock",
        "ON_LEAK_ACTION": "block",
        "ON_RESPONSE_LEAK_ACTION": "redact",
        "RULE_PACKS": "global,us",
        "REDIS_URL": "",
        "LLM_MODEL": "",
        "LLM_BASE_URL": "",
    }
)

from pathlib import Path  # noqa: E402

import pytest  # noqa: E402

from app.cache import reset_result_cache  # noqa: E402
from app.config import settings  # noqa: E402
from app.detectors.injection_detector import get_exemplars  # noqa: E402
from app.detectors.semantic_detector import get_corpus  # noqa: E402
from app.embeddings import get_embedder  # noqa: E402
from app.llm_providers import BaseLLMProvider, LLMResult, set_llm_provider  # noqa: E402
from app.stats import stats  # noqa: E402


def clear_singletons() -> None:
    get_embedder.cache_clear()
    get_corpus.cache_clear()
    get_exemplars.cache_clear()
    reset_result_cache()
    set_llm_provider(None)
    stats.reset()


@pytest.fixture(autouse=True)
def _isolate(monkeypatch):
    # Empty-string env vars above mean "unset" for these optional settings.
    monkeypatch.setattr(settings, "llm_model", None)
    monkeypatch.setattr(settings, "llm_base_url", None)
    monkeypatch.setattr(settings, "redis_url", None)
    clear_singletons()
    yield
    clear_singletons()


@pytest.fixture
def corpus_dir(tmp_path: Path, monkeypatch) -> Path:
    """A tiny confidential corpus; the hashing embedder matches on word overlap."""
    (tmp_path / "plans.md").write_text(
        "# Secret plans\n\n"
        "Project Bluefin will acquire Orchard Systems for forty million dollars in March.\n\n"
        "The quarterly revenue fell sharply after losing the Meridian enterprise contract.\n",
        encoding="utf-8",
    )
    monkeypatch.setattr(settings, "corpus_dir", tmp_path)
    monkeypatch.setattr(settings, "semantic_leak_threshold", 0.6)
    get_corpus.cache_clear()
    return tmp_path


class RecordingProvider(BaseLLMProvider):
    """Fake LLM: records what it was sent and returns a canned answer."""

    name = "recording"
    default_model = "fake-1"

    def __init__(self, answer: str = "A perfectly ordinary answer.", error: Exception | None = None):
        self.answer = answer
        self.error = error
        self.calls: list[dict] = []

    def chat(self, messages, *, model=None, max_tokens=None, temperature=None):
        self.calls.append({"messages": messages, "model": model, "max_tokens": max_tokens})
        if self.error:
            raise self.error
        return LLMResult(text=self.answer, model=self.resolve_model(model), usage={"total_tokens": 7})


@pytest.fixture
def fake_llm():
    def install(**kwargs) -> RecordingProvider:
        provider = RecordingProvider(**kwargs)
        set_llm_provider(provider)
        return provider

    return install


@pytest.fixture
def client():
    from fastapi.testclient import TestClient

    from app.main import app

    with TestClient(app) as c:
        yield c
