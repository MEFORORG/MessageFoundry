# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The step-boundary guard behind :mod:`tests._totp_clock`.

These pin the property the auth tests depend on: a code handed out by :func:`fresh_totp` is still in
its own step by the time the service compares it. The service verifies with
``window=totp_skew_steps`` (default **0** — strict current step only), so a code that crosses a
boundary between generation and comparison does not merely lose tolerance, it fails outright."""

from __future__ import annotations

from _totp_clock import _HEADROOM, fresh_totp, step_remaining

from messagefoundry.auth import totp

SECRET = totp.generate_secret()


def test_step_remaining_is_the_time_left_in_the_current_step() -> None:
    """Pure arithmetic, pinned — no wall clock, so this cannot itself flake."""
    period = totp.DEFAULT_PERIOD
    assert step_remaining(period=period, now=0.0) == period  # a step boundary: all of it remains
    assert step_remaining(period=period, now=period - 1.0) == 1.0  # one second left
    assert step_remaining(period=period, now=period * 3 + 10.0) == period - 10.0


def test_fresh_totp_guarantees_headroom_in_the_step() -> None:
    """The contract: after the call, the step has room left for the caller's verify.

    This is what a bare ``totp.totp()`` cannot promise — called with 20 ms left in the step it hands
    back a code that is stale before the service reads it. The wait branch is exercised whenever the
    call lands near a boundary; either way the postcondition holds."""
    for _ in range(3):
        fresh_totp(SECRET)
        # Allow a small epsilon for the time spent inside the call itself.
        assert step_remaining() >= _HEADROOM - 0.5


def test_fresh_totp_verifies_under_the_services_strict_window() -> None:
    """Mirrors :meth:`AuthService._verify_second_factor`: ``window=0``, the default posture.

    A code generated near a boundary by the old pattern fails exactly here, with no diagnostic — the
    assertion that flaked in CI was one indirection above this line."""
    for _ in range(3):
        code = fresh_totp(SECRET)
        assert totp.verify_totp_step(SECRET, code, window=0) is not None


def test_a_wide_headroom_always_takes_the_wait_branch() -> None:
    """Forces the branch a normally-timed run may never reach.

    ``headroom`` above the period cannot be satisfied by the current step, so the helper must cross
    into a fresh one — proving the wait actually resets the budget rather than returning early. Run
    against a **short** period: the branch is identical, and asserting it against the real 30 s step
    would spend up to a full period sleeping on every CI run to learn the same thing."""
    period = 2
    fresh_totp(SECRET, headroom=period + 1.0, period=period)
    assert step_remaining(period=period) >= period - 0.5
