"""
Env-driven settings. Every knob the gateway has lives here, so a deployment
is configured entirely through environment variables (or a .env file).
"""

from pathlib import Path
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent

LeakAction = Literal["block", "redact", "log_only"]
ResponseLeakAction = Literal["redact", "block", "log_only"]


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8", extra="ignore")

    # --- LLM provider -----------------------------------------------------
    llm_provider: Literal["mock", "openai", "groq", "gemini"] = "mock"
    # Forces a model for every request. Leave unset to honour the `model`
    # field clients send to /v1/chat/completions (or the provider default).
    llm_model: str | None = None
    # Overrides the provider's base URL, e.g. an OpenRouter, Ollama or vLLM
    # endpoint (all speak the OpenAI chat-completions protocol).
    llm_base_url: str | None = None
    llm_timeout_seconds: float = 30.0
    llm_max_tokens: int = 512
    openai_api_key: str | None = None
    groq_api_key: str | None = None
    gemini_api_key: str | None = None

    # --- Embeddings ---------------------------------------------------------
    # "hashing" is a dependency-free lexical embedder for tests/offline demos;
    # semantic (paraphrase) detection needs the real sentence-transformers model.
    embedding_backend: Literal["sentence-transformers", "hashing"] = "sentence-transformers"
    # bge-small-en-v1.5: same size as all-MiniLM-L6-v2 (33M params, 384 dims)
    # but separates paraphrased leaks from look-alike questions much better on
    # this project's eval set (see evals/results.md).
    embedding_model: str = "BAAI/bge-small-en-v1.5"

    # --- Detection ----------------------------------------------------------
    # Comma-separated. "global" = secrets, payment data, contact details.
    # Regional packs: us, uk, eu, in.
    rule_packs: str = "global,us"
    semantic_leak_threshold: float = Field(0.66, ge=0.0, le=1.0)  # calibrated: evals/results.md
    injection_similarity_threshold: float = Field(0.67, ge=0.0, le=1.0)  # calibrated: evals/results.md
    enable_injection_detection: bool = True

    # --- Enforcement --------------------------------------------------------
    on_leak_action: LeakAction = "block"
    on_response_leak_action: ResponseLeakAction = "redact"

    # --- Limits & hygiene ---------------------------------------------------
    max_prompt_chars: int = Field(20_000, gt=0)
    max_chunks_per_prompt: int = Field(64, gt=0)
    # Mask matched secrets in API responses so /check never echoes them back.
    mask_matches_in_response: bool = True
    # The corpus is confidential; returning its text to whoever calls /check
    # would itself be a leak. Only enable for local debugging.
    expose_corpus_snippets: bool = False
    cors_origins: str = "*"

    # --- Cache --------------------------------------------------------------
    redis_url: str | None = None
    cache_ttl_seconds: int = Field(3600, gt=0)
    cache_max_entries: int = Field(10_000, gt=0)

    # --- Data -----------------------------------------------------------------
    corpus_dir: Path = PROJECT_ROOT / "confidential_docs"
    injection_exemplars_path: Path = PROJECT_ROOT / "app" / "data" / "injection_exemplars.txt"

    @field_validator("rule_packs")
    @classmethod
    def _normalise_packs(cls, value: str) -> str:
        return ",".join(p.strip().lower() for p in value.split(",") if p.strip())

    @property
    def rule_pack_list(self) -> list[str]:
        return [p for p in self.rule_packs.split(",") if p]

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]


settings = Settings()
