"""Process-local counters. FastAPI runs sync endpoints in a thread pool, so
updates go through a lock (v0.1 mutated a plain dict from many threads)."""

import threading

from app.schemas import CheckResponse, StatsResponse


class Stats:
    def __init__(self):
        self._lock = threading.Lock()
        self.reset()

    def reset(self) -> None:
        self._c = dict.fromkeys(
            (
                "total_checked",
                "safe",
                "blocked",
                "redacted",
                "flagged",
                "cache_hits",
                "injection_detections",
                "responses_scanned",
                "response_leaks",
            ),
            0,
        )

    def record_prompt(self, result: CheckResponse) -> None:
        with self._lock:
            self._c["total_checked"] += 1
            self._c[result.verdict] += 1
            self._c["cache_hits"] += int(result.from_cache)
            self._c["injection_detections"] += int("injection" in result.categories)

    def record_response(self, result: CheckResponse) -> None:
        with self._lock:
            self._c["responses_scanned"] += 1
            self._c["response_leaks"] += int(result.verdict != "safe")

    def snapshot(self) -> StatsResponse:
        with self._lock:
            c = dict(self._c)
        total = c["total_checked"]
        enforced = c["blocked"] + c["redacted"]
        return StatsResponse(**c, block_rate=round(enforced / total, 4) if total else 0.0)


stats = Stats()
