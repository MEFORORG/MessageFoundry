# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Regression for SEC-014 (CWE-287): the TOTP verify window tolerates a near-boundary fast-clock
authenticator without letting the single-use high-water mark advance past the current step.

``verify_totp_step`` accepts the forward half of the skew window (so a user whose authenticator clock
runs ~25-30 s fast can still log in) but **clamps the returned step to the current step**. Otherwise
consuming the future step ``counter+1`` would reject the user's own genuine current-step code (a
non-greater step) for up to ~30 s — a self-inflicted lockout. The clamp only lowers the recorded step,
so single-use is preserved."""

from __future__ import annotations

from messagefoundry.auth import totp

# 160-bit base32 secret (any valid secret works; the math is secret-agnostic).
SECRET = totp.generate_secret()
PERIOD = totp.DEFAULT_PERIOD


def _step(now: float) -> int:
    return int(now // PERIOD)


def test_fast_clock_future_code_is_clamped_to_current_step() -> None:
    # The engine clock is one step BEHIND the user's fast authenticator: the user submits the code for
    # step floor(T/30) while the engine's "now" is T-30 (current step floor((T-30)/30)).
    t = 5_000 * PERIOD + 5.0  # comfortably mid-step
    engine_now = t - PERIOD
    user_future_code = totp.totp(SECRET, now=t)  # code for the user's (fast) current step

    matched = totp.verify_totp_step(SECRET, user_future_code, now=engine_now)
    # Accepted (forward window) but reported as the ENGINE's current step, not the future step.
    assert matched == _step(engine_now)
    assert matched != _step(t)


def test_genuine_current_code_after_future_code_is_strictly_greater() -> None:
    # No self-lockout: after the clamped future code is consumed at the engine's current step, the
    # user's genuine code for the engine's NEXT step still resolves to a strictly greater step.
    t = 5_000 * PERIOD + 5.0
    engine_now = t - PERIOD
    future_code = totp.totp(SECRET, now=t)
    consumed = totp.verify_totp_step(SECRET, future_code, now=engine_now)
    assert consumed is not None

    # The engine's clock catches up to the user's step; the genuine current code now verifies.
    genuine_code = totp.totp(SECRET, now=t)
    genuine_step = totp.verify_totp_step(SECRET, genuine_code, now=t)
    assert genuine_step is not None
    assert genuine_step > consumed  # strictly greater → single-use guard lets it through


def test_single_use_preserved_same_code_same_now() -> None:
    # The same code at the same now resolves to the same step both times; a single-use store rejecting
    # a non-greater step would reject the replay. (We assert the returned step is identical/stable.)
    t = 5_000 * PERIOD + 5.0
    code = totp.totp(SECRET, now=t)
    first = totp.verify_totp_step(SECRET, code, now=t)
    second = totp.verify_totp_step(SECRET, code, now=t)
    assert first == second == _step(t)


def test_prior_and_current_in_window_but_two_steps_future_rejected() -> None:
    t = 5_000 * PERIOD + 5.0
    prior_code = totp.totp(SECRET, now=t - PERIOD)
    current_code = totp.totp(SECRET, now=t)
    two_steps_future = totp.totp(SECRET, now=t + 2 * PERIOD)

    # Prior step is accepted (and is its own step — strictly less than current).
    assert totp.verify_totp_step(SECRET, prior_code, now=t) == _step(t - PERIOD)
    # Current step accepted as current.
    assert totp.verify_totp_step(SECRET, current_code, now=t) == _step(t)
    # Two steps into the future is outside the ±1 window → no match.
    assert totp.verify_totp_step(SECRET, two_steps_future, now=t) is None
