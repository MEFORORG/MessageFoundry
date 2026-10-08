# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

    ``min_interval_seconds`` adds a GAP floor beside the count (BACKLOG #2301, ASVS 2.4.2): a hit
    for a key is refused while that key's last allowed hit is younger than this. A count alone
    admits its whole budget back to back; the gap is what makes a burst wait. 0 disables it. It must
    be shorter than the window, or the key's last hit is pruned before the gap is measured.
    """

    def __init__(
        self,
        *,
        per_key: int,
        glob: int,
        window_seconds: float = 60.0,
        min_interval_seconds: float = 0.0,
    ) -> None:
        self._per_key = per_key
        self._global = glob
        self._window = window_seconds
        if min_interval_seconds and min_interval_seconds >= window_seconds:
            raise ValueError("min_interval_seconds must be shorter than window_seconds")
        self._min_interval = min_interval_seconds
        self._hits: dict[str, deque[float]] = {}
        self._global_hits: deque[float] = deque()

    def _prune(self, dq: deque[float], now: float) -> None:
        cutoff = now - self._window
        while dq and dq[0] <= cutoff:
            dq.popleft()

    def _has_room(self, key: str, now: float) -> bool:
        """Prune both windows to ``now`` and report whether an attempt for ``key`` would fit.

        Shared by :meth:`allow` and :meth:`would_allow` rather than duplicated into each, because a
        caller that consults one and charges the other must never see them disagree.

        Prunes, so it is **not** side-effect-free — but it never appends, which is the property
        :meth:`would_allow` sells. Dropping the prune would compare against stale counts.
        """
        self._prune(self._global_hits, now)
        bucket = self._hits.get(key)
        if bucket is not None:
            self._prune(bucket, now)
            if not bucket:
                del self._hits[key]
                bucket = None
        global_full = bool(self._global) and len(self._global_hits) >= self._global
        key_full = bucket is not None and bool(self._per_key) and len(bucket) >= self._per_key
        too_soon = bucket is not None and now - bucket[-1] < self._min_interval
        return not (global_full or key_full or too_soon)

    def allow(self, key: str) -> bool:
        """Record and allow an attempt for ``key``, or return ``False`` if it would exceed a limit."""
        now = time.monotonic()
        if not self._has_room(key, now):
            return False  # a rejected attempt does not count toward the window
        self._global_hits.append(now)
        self._hits.setdefault(key, deque()).append(now)
        return True

    def would_allow(self, key: str) -> bool:
        """Whether an attempt for ``key`` would be allowed, **without recording one**.

        The read-only sibling of :meth:`allow`, added for ADR 0154 D6. Intake authentication has to
        consult a budget *before* comparing a credential, but must charge it only when the comparison
        fails — otherwise ``intake_auth_rate_limit=10`` stops being a brute-force bound and becomes a
        hard ten-requests-per-minute-per-peer **throughput cap**, silently refusing a correctly
        authenticated partner's eleventh message. That refusal is pre-ingress, so the message would
        not even be counted: silent, uncounted loss on the feature's happy path.

        Every other caller of this class consumes its budget per *attempt* and should keep using
        :meth:`allow`.
        """
        return self._has_room(key, time.monotonic())

    def retry_after(self, key: str) -> float:
        """Seconds until an attempt for ``key`` would next be admitted; 0.0 if one would be now.

        The wait a refusal's ``Retry-After`` should carry (BACKLOG #2144). It is the later of the
        two per-key gates: the key's oldest hit leaving the window, when the count is full, and the
        gap since the key's last hit. Records nothing.

        A full **global** budget answers with the whole window instead of the true wait. That wait
        depends on when other keys hit, and a refused caller must not be able to read it.
        """
        now = time.monotonic()
        if self._has_room(key, now):
            return 0.0
        if self._global and len(self._global_hits) >= self._global:
            return self._window
        bucket = self._hits[key]  # a per-key gate fired, so the key has hits
        wait = bucket[-1] + self._min_interval - now
        if self._per_key and len(bucket) >= self._per_key:
            # Room opens when the hit that keeps the count at the budget ages out. Clamped to the
            # bucket: a negative budget loads and refuses every hit after a key's first, and its
            # room opens only when the last hit ages out.
            blocking = min(max(len(bucket) - self._per_key, 0), len(bucket) - 1)
            wait = max(wait, bucket[blocking] + self._window - now)
        return max(wait, 0.0)
