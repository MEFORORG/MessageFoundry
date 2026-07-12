# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""TOTP clock-skew window semantics ([auth].totp_skew_steps, BACKLOG #187; ASVS 6.5.5) + the SEC-014
(CWE-287) fast-clock clamp.

The verify window is an operator knob: ``AuthService`` threads ``[auth].totp_skew_steps`` into
:func:`~messagefoundry.auth.totp.verify_totp_step`.

- Default ``totp_skew_steps = 0`` is STRICT: only the CURRENT 30 s step verifies, so the prior AND the
  next step are rejected and a captured code is replayable for at most the remainder of its own step
  (ASVS 6.5.5 prefers the tightest window).
- The documented opt-out ``totp_skew_steps = 1`` restores RFC-6238 ±1 tolerance. There the SEC-014
  accommodation applies: the forward half of the window is *accepted* (a near-boundary fast-clock
  authenticator can still log in) but the returned step is **clamped to the current step**, so consuming
  a tolerated future code never advances the single-use high-water mark past ``now`` — otherwise the
  user's own genuine current-step code (a non-greater step) would be rejected for up to ~30 s, a
  self-inflicted lockout, not a bypass. The clamp only lowers the recorded step, so single-use holds.

These call ``verify_totp_step`` directly with an EXPLICIT ``window`` so both the strict default and the
opt-out are pinned regardless of the module-level ``DEFAULT_WINDOW`` (which stays 1 for callers that
don't pass one)."""

from __future__ import annotations

from messagefoundry.auth import totp

# 160-bit base32 secret (any valid secret works; the math is secret-agnostic).
SECRET = totp.generate_secret()
PERIOD = totp.DEFAULT_PERIOD


def _step(now: float) -> int:
    return int(now // PERIOD)


# --- strict default: totp_skew_steps = 0 (current step only, ASVS 6.5.5) -----


def test_strict_window_accepts_only_the_current_step() -> None:
    t = 5_000 * PERIOD + 5.0  # comfortably mid-step
    current = totp.totp(SECRET, now=t)
    assert totp.verify_totp_step(SECRET, current, now=t, window=0) == _step(t)


def test_strict_window_rejects_the_prior_step() -> None:
    t = 5_000 * PERIOD + 5.0
    prior = totp.totp(SECRET, now=t - PERIOD)
    # Even one step back is outside the strict window → no match (tighter than the historical ±1).
    assert totp.verify_totp_step(SECRET, prior, now=t, window=0) is None


def test_strict_window_rejects_the_next_step() -> None:
    t = 5_000 * PERIOD + 5.0
    future = totp.totp(SECRET, now=t + PERIOD)
    # A fast-clock (future) code is NOT tolerated at window=0 — the tightest replay posture (6.5.5).
    assert totp.verify_totp_step(SECRET, future, now=t, window=0) is None


# --- opt-out: totp_skew_steps = 1 restores ±1 (with the SEC-014 clamp) --------


def test_optout_window_accepts_prior_and_current_and_clamps_the_future() -> None:
    t = 5_000 * PERIOD + 5.0
    prior = totp.totp(SECRET, now=t - PERIOD)
    current = totp.totp(SECRET, now=t)
    future = totp.totp(SECRET, now=t + PERIOD)
    # Prior step is accepted and reported as its own (strictly-less) step.
    assert totp.verify_totp_step(SECRET, prior, now=t, window=1) == _step(t - PERIOD)
    # Current step accepted as current.
    assert totp.verify_totp_step(SECRET, current, now=t, window=1) == _step(t)
    # The forward step is ACCEPTED but its reported step is clamped down to the current step (SEC-014),
    # so burning it can't advance the single-use high-water mark past now.
    assert totp.verify_totp_step(SECRET, future, now=t, window=1) == _step(t)


def test_optout_two_steps_into_the_future_is_still_rejected() -> None:
    t = 5_000 * PERIOD + 5.0
    two_future = totp.totp(SECRET, now=t + 2 * PERIOD)
    assert totp.verify_totp_step(SECRET, two_future, now=t, window=1) is None


def test_optout_fast_clock_future_code_causes_no_self_lockout() -> None:
    # SEC-014: the engine clock is one step BEHIND the user's fast authenticator. The user submits the
    # code for step floor(T/30) while the engine's "now" is T-PERIOD. It is accepted (forward window)
    # but recorded at the engine's CURRENT step, not the future step.
    t = 5_000 * PERIOD + 5.0
    engine_now = t - PERIOD
    future_code = totp.totp(SECRET, now=t)
    consumed = totp.verify_totp_step(SECRET, future_code, now=engine_now, window=1)
    assert consumed == _step(engine_now)
    assert consumed != _step(t)
    # When the engine clock catches up, the user's genuine current code resolves to a STRICTLY GREATER
    # step, so a single-use store rejecting a non-greater step still lets it through (no lockout).
    genuine = totp.verify_totp_step(SECRET, totp.totp(SECRET, now=t), now=t, window=1)
    assert genuine is not None and genuine > consumed


def test_single_use_step_is_stable_for_the_same_code_and_now() -> None:
    # The same code at the same now resolves to the same step both times (a single-use store rejecting a
    # non-greater step then rejects the replay). Holds under both the strict and the opt-out window.
    t = 5_000 * PERIOD + 5.0
    for window in (0, 1):
        code = totp.totp(SECRET, now=t)
        first = totp.verify_totp_step(SECRET, code, now=t, window=window)
        second = totp.verify_totp_step(SECRET, code, now=t, window=window)
        assert first == second == _step(t)
