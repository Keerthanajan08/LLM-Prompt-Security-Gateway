"""
Embedding backends behind one interface.

- SentenceTransformerEmbedder: the real model (bge-small-en-v1.5 by default).
  Needed for paraphrase detection.
- HashingEmbedder: a deterministic, dependency-free bag-of-words embedder.
  It only captures lexical overlap, which is exactly what unit tests and CI
  need: fast, reproducible, and no 90MB model download.

All vectors are L2-normalised, so cosine similarity is a plain dot product.
"""

from __future__ import annotations

import hashlib
import re
from functools import lru_cache

import numpy as np

from app.config import settings

_TOKEN_RE = re.compile(r"[a-z0-9]+")


class BaseEmbedder:
    name = "base"
    dim = 0

    def encode(self, text: str) -> np.ndarray:
        return self.encode_batch([text])[0]

    def encode_batch(self, texts: list[str]) -> np.ndarray:
        raise NotImplementedError


class HashingEmbedder(BaseEmbedder):
    name = "hashing"

    def __init__(self, dim: int = 512):
        self.dim = dim

    def _features(self, text: str) -> list[str]:
        tokens = _TOKEN_RE.findall(text.lower())
        bigrams = [f"{a}_{b}" for a, b in zip(tokens, tokens[1:], strict=False)]
        return tokens + bigrams

    def encode_batch(self, texts: list[str]) -> np.ndarray:
        out = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for feature in self._features(text):
                # hashlib, not hash(): Python's hash() is salted per process,
                # which would make vectors differ between runs.
                h = int.from_bytes(hashlib.blake2b(feature.encode(), digest_size=8).digest(), "big")
                sign = 1.0 if (h >> 63) & 1 else -1.0
                out[row, h % self.dim] += sign
        return _normalise(out)


class SentenceTransformerEmbedder(BaseEmbedder):
    name = "sentence-transformers"

    def __init__(self, model_name: str):
        from sentence_transformers import SentenceTransformer  # heavy import, keep lazy

        self.model = SentenceTransformer(model_name)
        getter = getattr(self.model, "get_embedding_dimension", None) or self.model.get_sentence_embedding_dimension
        self.dim = getter()
        self.model_name = model_name

    def encode_batch(self, texts: list[str]) -> np.ndarray:
        if not texts:
            return np.zeros((0, self.dim), dtype=np.float32)
        vectors = self.model.encode(texts, normalize_embeddings=True, convert_to_numpy=True)
        return vectors.astype(np.float32)


def _normalise(matrix: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(matrix, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return matrix / norms


def cosine_similarity(a: np.ndarray, b: np.ndarray) -> float:
    denom = float(np.linalg.norm(a) * np.linalg.norm(b))
    return float(np.dot(a, b) / denom) if denom else 0.0


@lru_cache(maxsize=1)
def get_embedder() -> BaseEmbedder:
    if settings.embedding_backend == "hashing":
        return HashingEmbedder()
    return SentenceTransformerEmbedder(settings.embedding_model)
