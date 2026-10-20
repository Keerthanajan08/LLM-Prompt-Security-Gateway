"""
Caches the expensive part of a check: chunking + embedding + similarity
search (the semantic-leak and injection-similarity results).

What changed from v0.1, and why
-------------------------------
v0.1 reused a whole *verdict* for any prompt whose embedding was >= 0.97
similar to a cached one, and skipped regex detection on a hit. Embeddings
barely move when a short secret is appended to a long prompt: a ~130-word
incident report scored 0.998 against the same report with an AWS key
appended (all-MiniLM-L6-v2). So a prompt carrying a credential could be
served a cached "safe" verdict without the regex ever running.

Now:
- Only embedding-stage results are cached. Regex and injection heuristics
  run on every request; they cost microseconds.
- Lookups are by exact SHA-256 of the prompt plus a fingerprint of the
  detection config (model, thresholds, corpus contents). Change any of
  those and old entries simply stop matching.
- Nothing stored contains prompt text: keys are hashes, values hold doc
  ids, scores and character offsets. The v0.1 Redis cache stored raw
  prompts — including the secrets it had just detected — in plaintext with
  no expiry.
- Both backends are bounded: LRU + TTL in memory, TTL in Redis.
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict

from app.config import settings

log = logging.getLogger(__name__)


def cache_key(text: str, fingerprint: str) -> str:
    return hashlib.sha256(f"{fingerprint}\x00{text}".encode()).hexdigest()


class BaseResultCache:
    def get(self, key: str) -> dict | None:
        raise NotImplementedError

    def set(self, key: str, value: dict) -> None:
        raise NotImplementedError

    def size(self) -> int:
        raise NotImplementedError


class InMemoryResultCache(BaseResultCache):
    def __init__(self, max_entries: int, ttl_seconds: int):
        self._data: OrderedDict[str, tuple[float, dict]] = OrderedDict()
        self._max = max_entries
        self._ttl = ttl_seconds
        self._lock = threading.Lock()

    def get(self, key: str) -> dict | None:
        with self._lock:
            item = self._data.get(key)
            if item is None:
                return None
            stored_at, value = item
            if time.monotonic() - stored_at > self._ttl:
                del self._data[key]
                return None
            self._data.move_to_end(key)
            return value

    def set(self, key: str, value: dict) -> None:
        with self._lock:
            self._data[key] = (time.monotonic(), value)
            self._data.move_to_end(key)
            while len(self._data) > self._max:
                self._data.popitem(last=False)

    def size(self) -> int:
        return len(self._data)


class RedisResultCache(BaseResultCache):
    KEY_PREFIX = "promptgw:v2:"

    def __init__(self, client, ttl_seconds: int):
        self.client = client
        self._ttl = ttl_seconds

    @classmethod
    def from_url(cls, url: str, ttl_seconds: int) -> RedisResultCache:
        import redis

        return cls(redis.from_url(url, decode_responses=True, socket_timeout=0.5), ttl_seconds)

    # A cache outage must never take detection down with it, so Redis errors
    # degrade to a cache miss (detection still runs in full).
    def get(self, key: str) -> dict | None:
        try:
            raw = self.client.get(self.KEY_PREFIX + key)
        except Exception as exc:  # noqa: BLE001 - any client/network error
            log.warning("verdict cache read failed, treating as miss: %s", exc)
            return None
        return json.loads(raw) if raw else None

    def set(self, key: str, value: dict) -> None:
        try:
            self.client.set(self.KEY_PREFIX + key, json.dumps(value), ex=self._ttl)
        except Exception as exc:  # noqa: BLE001
            log.warning("verdict cache write failed: %s", exc)

    def size(self) -> int:
        try:
            return sum(1 for _ in self.client.scan_iter(match=f"{self.KEY_PREFIX}*", count=500))
        except Exception:  # noqa: BLE001
            return -1


_cache_instance: BaseResultCache | None = None
_cache_lock = threading.Lock()


def get_result_cache() -> BaseResultCache:
    global _cache_instance
    with _cache_lock:
        if _cache_instance is None:
            if settings.redis_url:
                _cache_instance = RedisResultCache.from_url(settings.redis_url, settings.cache_ttl_seconds)
            else:
                _cache_instance = InMemoryResultCache(settings.cache_max_entries, settings.cache_ttl_seconds)
        return _cache_instance


def reset_result_cache() -> None:
    global _cache_instance
    with _cache_lock:
        _cache_instance = None
