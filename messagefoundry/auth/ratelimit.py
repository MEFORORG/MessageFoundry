"""In-process sliding-window rate limiter for the unauthenticated auth surface (AUTH-RATE).

Bounds brute-force / password-spray and argon2 CPU-burn on ``/auth/login`` and friends *ahead*
of the per-account lockout (which a spray across many usernames never trips). It is in-process and
per-app, **not** distributed — an exposed or multi-host deployment must additionally front the API
with a proxy/WAF limiter. Decisions use ``time.monotonic()`` so a wall-clock step can't widen the
window. Calls are synchronous and complete without ``await``, so they're atomic on the event loop.
"""

from __future__ import annotations

import time
from collections import deque

__all__ = ["SlidingWindowRateLimiter"]


class SlidingWindowRateLimiter:
    """Allow up to ``per_key`` hits per key and ``glob`` hits overall within ``window_seconds``.

    A falsy ``per_key``/``glob`` disables that dimension. Empty per-key buckets are dropped as they
    age out, so memory is bounded by the number of *active* keys in the window.
    """

    def __init__(self, *, per_key: int, glob: int, window_seconds: float = 60.0) -> None:
        self._per_key = per_key
        self._global = glob
        self._window = window_seconds
        self._hits: dict[str, deque[float]] = {}
        self._global_hits: deque[float] = deque()

    def _prune(self, dq: deque[float], now: float) -> None:
        cutoff = now - self._window
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def allow(self, key: str) -> bool:
        """Record and allow an attempt for ``key``, or return ``False`` if it would exceed a limit."""
        now = time.monotonic()
        self._prune(self._global_hits, now)
        bucket = self._hits.get(key)
        if bucket is not None:
            self._prune(bucket, now)
            if not bucket:
                del self._hits[key]
                bucket = None
        global_full = bool(self._global) and len(self._global_hits) >= self._global
        key_full = bucket is not None and bool(self._per_key) and len(bucket) >= self._per_key
        if global_full or key_full:
            return False  # a rejected attempt does not count toward the window
        self._global_hits.append(now)
        self._hits.setdefault(key, deque()).append(now)
        return True
