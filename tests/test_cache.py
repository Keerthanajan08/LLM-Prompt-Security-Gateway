import json

import fakeredis
import pytest

from app import cache as cache_mod
from app.cache import InMemoryResultCache, RedisResultCache, cache_key, get_result_cache
from app.config import settings
from app.langchain_pipeline import run_security_check

LONG_SAFE_PROMPT = "Please summarise this incident report for the weekly ops review. " + " ".join(
    f"At {h:02d}:00 the checkout service latency rose above the SLO, autoscaling added "
    "two replicas and latency recovered within ten minutes."
    for h in range(1, 7)
)


def test_cache_bypass_regression():
    """v0.1 reused a cached verdict for any prompt >= 0.97 similar to a cached
    one, without re-running the regex. Appending a key to a long safe prompt
    barely moves its embedding (0.998 with all-MiniLM-L6-v2), so the key
    sailed through on the cached "safe" verdict."""
    first = run_security_check(LONG_SAFE_PROMPT)
    assert first.verdict == "safe"

    leaked = run_security_check(LONG_SAFE_PROMPT + " AKIAIOSFODNN7EXAMPLE")
    assert leaked.verdict == "blocked"
    assert [m.rule_name for m in leaked.pattern_matches] == ["aws_access_key_id"]


def test_identical_prompt_is_served_from_cache_and_still_regex_checked():
    prompt = "My SSN is 123-45-6789"
    first = run_security_check(prompt)
    second = run_security_check(prompt)
    assert not first.from_cache and second.from_cache
    assert second.verdict == "blocked"
    assert second.pattern_matches  # regex ran on the cache hit too


def test_config_change_invalidates_cached_results(corpus_dir, monkeypatch):
    prompt = "Project Bluefin will acquire Orchard Systems for forty million dollars"
    assert run_security_check(prompt).verdict == "blocked"
    monkeypatch.setattr(settings, "semantic_leak_threshold", 0.999)
    result = run_security_check(prompt)
    assert not result.from_cache
    assert result.verdict == "safe"


def test_key_depends_on_text_and_fingerprint():
    assert cache_key("a", "f1") != cache_key("b", "f1")
    assert cache_key("a", "f1") != cache_key("a", "f2")
    assert len(cache_key("a", "f1")) == 64


def test_in_memory_cache_is_lru_bounded():
    c = InMemoryResultCache(max_entries=2, ttl_seconds=60)
    c.set("a", {"v": 1})
    c.set("b", {"v": 2})
    assert c.get("a") == {"v": 1}  # touch "a" so "b" is least recently used
    c.set("c", {"v": 3})
    assert c.get("b") is None
    assert c.get("a") and c.get("c")
    assert c.size() == 2


def test_in_memory_cache_expires_entries(monkeypatch):
    now = [1000.0]
    monkeypatch.setattr(cache_mod.time, "monotonic", lambda: now[0])
    c = InMemoryResultCache(max_entries=10, ttl_seconds=5)
    c.set("k", {"v": 1})
    now[0] += 4
    assert c.get("k") == {"v": 1}
    now[0] += 2
    assert c.get("k") is None


@pytest.fixture
def redis_cache(monkeypatch):
    client = fakeredis.FakeRedis(decode_responses=True)
    instance = RedisResultCache(client, ttl_seconds=120)
    monkeypatch.setattr(cache_mod, "_cache_instance", instance)
    return client


def test_redis_round_trip_with_ttl(redis_cache):
    c = get_result_cache()
    c.set("abc", {"semantic": [], "injection": []})
    assert c.get("abc") == {"semantic": [], "injection": []}
    assert 0 < redis_cache.ttl(RedisResultCache.KEY_PREFIX + "abc") <= 120
    assert c.size() == 1


def test_redis_never_stores_prompt_text(redis_cache, corpus_dir):
    """v0.1 stored raw prompts, including the secrets it had just found, in
    Redis with no expiry."""
    secret_prompt = "Project Bluefin will acquire Orchard Systems. My SSN is 123-45-6789, key AKIAIOSFODNN7EXAMPLE"
    run_security_check(secret_prompt)
    dump = json.dumps({k: redis_cache.get(k) for k in redis_cache.keys("*")})
    for fragment in ("123-45-6789", "AKIAIOSFODNN7EXAMPLE", "My SSN", "Bluefin will acquire"):
        assert fragment not in dump


def test_redis_outage_degrades_to_a_miss_not_an_error(monkeypatch):
    class Broken:
        def get(self, *_a, **_k):
            raise ConnectionError("redis down")

        set = get

        def scan_iter(self, *_a, **_k):
            raise ConnectionError("redis down")

    monkeypatch.setattr(cache_mod, "_cache_instance", RedisResultCache(Broken(), ttl_seconds=60))
    result = run_security_check("My SSN is 123-45-6789")
    assert result.verdict == "blocked" and not result.from_cache
    assert get_result_cache().size() == -1


def test_redis_backend_selected_from_config(monkeypatch):
    monkeypatch.setattr(settings, "redis_url", "redis://localhost:6379/0")
    monkeypatch.setattr(
        RedisResultCache, "from_url", classmethod(lambda cls, url, ttl: cls(fakeredis.FakeRedis(), ttl))
    )
    assert isinstance(get_result_cache(), RedisResultCache)


def test_cache_hit_restores_semantic_matches(corpus_dir, monkeypatch):
    monkeypatch.setattr(settings, "expose_corpus_snippets", True)
    prompt = "Project Bluefin will acquire Orchard Systems for forty million dollars"
    first, second = run_security_check(prompt), run_security_check(prompt)
    assert second.from_cache and second.verdict == "blocked"
    assert second.semantic_matches == first.semantic_matches
    assert "Bluefin" in second.semantic_matches[0].snippet
