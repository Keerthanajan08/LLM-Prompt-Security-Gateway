"""
Caches the (prompt embedding -> verdict) result of a full detection pass.
If a near-identical prompt has already been checked, reuse that verdict
instead of re-running pattern + semantic detection from scratch.

Same shape as the semantic cache gateway project: in-memory backend for
zero-setup local dev, Redis backend for anything you'd actually deploy,
both behind one interface so swapping is a config change.
"""
import json
import time
from dataclasses import dataclass
from typing import Optional

import numpy as np

from app.config import settings
from app.embeddings import cosine_similarity

VERDICT_MATCH_THRESHOLD = 0.97  # stricter than the leak-detection threshold on purpose:
# reusing a *security* verdict should require near-identical prompts, not
# just "similar topic" — a false-negative here is worse than a cache miss.


@dataclass
class CachedVerdict:
    prompt: str
    verdict: str
    reasons: list[str]
    vector: np.ndarray


@dataclass
class VerdictLookupResult:
    hit: bool
    verdict: Optional[CachedVerdict] = None
    similarity: float = 0.0


class BaseVerdictCache:
    def lookup(self, vector: np.ndarray) -> VerdictLookupResult:
        raise NotImplementedError

    def store(self, prompt: str, verdict: str, reasons: list[str], vector: np.ndarray) -> None:
        raise NotImplementedError

    def size(self) -> int:
        raise NotImplementedError


class InMemoryVerdictCache(BaseVerdictCache):
    def __init__(self):
        self._entries: list[CachedVerdict] = []

    def lookup(self, vector: np.ndarray) -> VerdictLookupResult:
        best, best_score = None, -1.0
        for entry in self._entries:
            score = cosine_similarity(vector, entry.vector)
            if score > best_score:
                best, best_score = entry, score
        if best is not None and best_score >= VERDICT_MATCH_THRESHOLD:
            return VerdictLookupResult(hit=True, verdict=best, similarity=best_score)
        return VerdictLookupResult(hit=False, similarity=max(best_score, 0.0))

    def store(self, prompt: str, verdict: str, reasons: list[str], vector: np.ndarray) -> None:
        self._entries.append(CachedVerdict(prompt, verdict, reasons, vector))

    def size(self) -> int:
        return len(self._entries)


class RedisVerdictCache(BaseVerdictCache):
    KEY_PREFIX = "verdictcache:"

    def __init__(self, redis_url: str):
        import redis

        self.client = redis.from_url(redis_url, decode_responses=True)

    def _all_keys(self):
        return self.client.scan_iter(match=f"{self.KEY_PREFIX}*")

    def lookup(self, vector: np.ndarray) -> VerdictLookupResult:
        best, best_score = None, -1.0
        for key in self._all_keys():
            raw = self.client.hgetall(key)
            if not raw:
                continue
            cached_vec = np.array(json.loads(raw["vector"]), dtype=np.float32)
            score = cosine_similarity(vector, cached_vec)
            if score > best_score:
                best = CachedVerdict(
                    prompt=raw["prompt"],
                    verdict=raw["verdict"],
                    reasons=json.loads(raw["reasons"]),
                    vector=cached_vec,
                )
                best_score = score
        if best is not None and best_score >= VERDICT_MATCH_THRESHOLD:
            return VerdictLookupResult(hit=True, verdict=best, similarity=best_score)
        return VerdictLookupResult(hit=False, similarity=max(best_score, 0.0))

    def store(self, prompt: str, verdict: str, reasons: list[str], vector: np.ndarray) -> None:
        key = f"{self.KEY_PREFIX}{int(time.time() * 1000)}:{hash(prompt) & 0xffffffff}"
        self.client.hset(
            key,
            mapping={
                "prompt": prompt,
                "verdict": verdict,
                "reasons": json.dumps(reasons),
                "vector": json.dumps(vector.tolist()),
            },
        )

    def size(self) -> int:
        return sum(1 for _ in self._all_keys())


_cache_instance: Optional[BaseVerdictCache] = None


def get_verdict_cache() -> BaseVerdictCache:
    global _cache_instance
    if _cache_instance is None:
        if settings.redis_url:
            _cache_instance = RedisVerdictCache(settings.redis_url)
        else:
            _cache_instance = InMemoryVerdictCache()
    return _cache_instance
