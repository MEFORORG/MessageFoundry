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
from collections import OrderedDict, deque

__all__ = ["SlidingWindowRateLimiter"]

# More than one, so aged buckets drain even while every call adds a new key.
_EVICT_PER_CALL = 2


class SlidingWindowRateLimiter:
    """Allow up to ``per_key`` hits per key and ``glob`` hits overall within ``window_seconds``.

    A falsy ``per_key``/``glob`` disables that dimension.

    A key's bucket goes once its newest hit leaves the window, whether or not the key comes back
    (BACKLOG #2714). The table is ordered by each key's newest hit. Each call drops at most
    ``_EVICT_PER_CALL`` aged buckets from the front, and stops early at the first live one. A call
    adds at most one bucket, and aged buckets sit at the front, so the table cannot grow while any
    aged bucket remains. It never grows past the most keys live at one time. The cap keeps each call's cost constant: the login path is
    unauthenticated, and one call that dropped a million aged buckets would stall the event loop.
    A limiter with no per-key gate (falsy ``per_key`` and no gap) keeps no buckets at all.

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
        self._keeps_buckets = bool(per_key) or bool(min_interval_seconds)
        # The key whose newest hit is oldest comes first: ``allow`` moves a key to the end.
        self._hits: OrderedDict[str, deque[float]] = OrderedDict()
        self._global_hits: deque[float] = deque()

    @staticmethod
    def _aged(hit: float, cutoff: float) -> bool:
        # The one expiry test, shared by both prunes. Keep it ``<=``: under a NaN window every
        # comparison is false, so this keeps every hit, and ``not hit > cutoff`` would drop them.
        return hit <= cutoff

    def _prune(self, dq: deque[float], cutoff: float) -> None:
        while dq and self._aged(dq[0], cutoff):
            dq.popleft()

    def _evict_aged(self, cutoff: float) -> None:
        """Drop up to ``_EVICT_PER_CALL`` buckets from the front whose newest hit has aged out.

        Only a bucket with no live hit goes, so a key a caller is being refused for keeps its
        bucket: :meth:`retry_after` reads it right after :meth:`_has_room` refuses.
        """
        for _ in range(_EVICT_PER_CALL):
            if not self._hits:
                return
            key, bucket = next(iter(self._hits.items()))
            if not self._aged(bucket[-1], cutoff):
                return
            del self._hits[key]

    def _has_room(self, key: str, now: float) -> bool:
        """Prune to ``now`` and report whether an attempt for ``key`` would fit.

        Prunes the global window and ``key``'s bucket, and drops a few aged buckets of other keys.
        Shared by :meth:`allow` and :meth:`would_allow` rather than duplicated into each, because a
        caller that consults one and charges the other must never see them disagree.

        Prunes, so it is **not** side-effect-free — but it never appends, which is the property
        :meth:`would_allow` sells. Dropping the prune would compare against stale counts.
        """
        cutoff = now - self._window
        self._prune(self._global_hits, cutoff)
        self._evict_aged(cutoff)
        bucket = self._hits.get(key)
        if bucket is not None:
            self._prune(bucket, cutoff)
            if not bucket:  # aged, but still queued behind other aged buckets
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
        if self._keeps_buckets:
            bucket = self._hits.get(key)
            if bucket is None:
                self._hits[key] = deque((now,))
            else:
                bucket.append(now)
                self._hits.move_to_end(key)
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
        # Each wait is written as the gate writes its own test (``now - last < gap`` in
        # ``_has_room``, ``hit <= now - window`` in ``_prune``). Regrouping the same sum rounds
        # differently, and could then report 0.0 for a key the gate still refuses.
        wait = self._min_interval - (now - bucket[-1])
        if self._per_key and len(bucket) >= self._per_key:
            # Room opens when the oldest hit ages out. ``allow`` never grows a bucket past a
            # positive budget, and a negative budget (which loads) admits one hit and then
            # refuses, so the oldest hit is always the one holding the count at the budget.
            wait = max(wait, bucket[0] - (now - self._window))
        return max(wait, 0.0)
