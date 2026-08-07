# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Step-boundary-safe TOTP codes for tests.

**The race.** A TOTP code identifies a 30 s time step, and
:meth:`AuthService._verify_second_factor` verifies it with ``window=settings.totp_skew_steps``,
whose default is **0** — strict current-step only (the tightest replay window, ASVS 6.5.1). So a
code computed in step *N* and compared in step *N+1* does not match, **at all**: there is no
tolerance to absorb the crossing.

Any test that computes a live code and then feeds it to a verify therefore has a latent race whose
window is the wall-clock time between the two — normally milliseconds, but on a loaded CI runner
long enough to straddle a boundary. It surfaces as a bare ``assert False is True`` with no hint of
timing, on a test that passes every time locally.

**Why "recompute the code later" does not fix it.** That was the previous mitigation, and it only
shrinks the gap: there is always *some* time between generating a code and the verify comparing it,
so the boundary can always fall inside it. Shrinking a race is not closing one.

**What this does instead.** Ensure the step has enough time left *before* the code is generated, so
the whole generate → verify sequence provably lands inside one step. That removes the race rather
than narrowing it, and it does not weaken what the test asserts: the code is still a real live TOTP
verified through the real strict-window path.

The alternative — pinning ``now`` on both sides — is not available here: ``totp.totp`` accepts
``now=``, but the service reads the wall clock internally, so only the *generating* half could be
pinned. Waiting is what actually makes both halves agree.
"""

from __future__ import annotations

import time

import pytest

from messagefoundry.auth import totp

__all__ = ["fresh_totp", "pin_totp_clock", "step_remaining"]

#: Seconds that must remain in the current step before a code is generated. Comfortably larger than
#: any plausible generate → verify gap (a store read plus an HMAC; the argon2id recovery-code path
#: only runs when the TOTP does *not* match), while small enough that the wait is rarely triggered:
#: with a 30 s period a call sleeps roughly 1 time in 10, for under `_HEADROOM` seconds.
_HEADROOM = 3.0


def step_remaining(*, period: int = totp.DEFAULT_PERIOD, now: float | None = None) -> float:
    """Seconds left in the current TOTP time step."""
    return period - ((time.time() if now is None else now) % period)


def fresh_totp(
    secret: str, *, headroom: float = _HEADROOM, period: int = totp.DEFAULT_PERIOD
) -> str:
    """A live TOTP code for ``secret`` guaranteed at least ``headroom`` seconds of step validity.

    Blocks until the next step begins when the current one is nearly over, so the caller's
    subsequent verify cannot land in a later step than the code it was given. Use this **anywhere a
    generated code is later checked by the service**; ``totp.totp(..., now=...)`` remains the right
    tool for tests that pin time and assert on the primitive itself (they carry no race).

    ``period`` exists so the wait branch can be exercised against a short step instead of burning a
    real 30 s one in CI; callers verifying against the service must leave it at the default."""
    remaining = step_remaining(period=period)
    if remaining < headroom:
        # Cross the boundary deliberately, then generate inside the fresh step. The small overshoot
        # keeps a coarse clock from returning the step we just left.
        time.sleep(remaining + 0.05)
    return totp.totp(secret, period=period)


class _PinnedClock:
    """A minimal stand-in for the ``time`` module exposing only ``time()`` at a fixed instant.

    ``totp`` reads the wall clock solely as ``time.time()`` (two call sites: :func:`totp.totp` and
    :func:`totp.verify_totp_step`), so swapping the module reference for this pins the TOTP step
    deterministically while leaving every OTHER clock — the service's session-expiry, rate-limiting
    and audit timestamps, all on their own ``time`` imports — real. That surgical scope is what lets
    a test place enrollment and a later verify in DISTINCT, provably-adjacent steps without the 30 s
    boundary flake :func:`fresh_totp` can only narrow.
    """

    def __init__(self, instant: float) -> None:
        self._instant = instant

    def time(self) -> float:
        return self._instant


def pin_totp_clock(monkeypatch: pytest.MonkeyPatch, instant: float) -> None:
    """Pin the ``totp`` module's clock to ``instant`` for the rest of the test (monkeypatch restores
    the real clock at teardown).

    Generate codes with ``totp.totp(secret, now=instant)`` so they land in the same step the pinned
    service-side verify computes. Unlike :func:`fresh_totp` — which guarantees headroom WITHIN a step
    but cannot advance one — this can place two verifies in strictly different steps, which is needed
    now that enrollment consumes the activating step (BACKLOG #1021): a later login code must live in
    a higher step than the consumed enrollment step to be accepted."""
    monkeypatch.setattr(totp, "time", _PinnedClock(instant))
