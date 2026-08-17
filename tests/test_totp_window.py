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
  self-inflicted lockout, not a bypass. ⚠️ The clamp does NOT preserve single-use here — it is what
  costs it: recording a tolerated future code at ``now`` leaves that code's OWN step unspent, so the
  same code verifies again one step later (two successful uses, ASVS 6.5.1). Single-use holds only at
  the strict default. See test_optout_lets_one_tolerated_future_code_be_used_twice.

These call ``verify_totp_step`` directly with an EXPLICIT ``window`` so both the strict default and the
opt-out are pinned regardless of the module-level ``DEFAULT_WINDOW`` (which stays 1 for callers that
don't pass one)."""

from __future__ import annotations

import hmac

import pytest

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


def test_optout_lets_one_tolerated_future_code_be_used_twice() -> None:
    """The clamp's COST, pinned — one code, two successful uses, at ``totp_skew_steps >= 1``.

    This is the gap the neighbouring tests leave. ``test_single_use_step_is_stable_for_the_same_code``
    replays the same code at the SAME ``now``; ``test_optout_fast_clock...no_self_lockout`` replays a
    DIFFERENT (genuine) code at a later ``now``. Nobody replayed the SAME code at a LATER ``now``, which
    is where the clamp bites: recording a tolerated ``counter+1`` code at ``counter`` leaves its own step
    unspent, so it verifies again when the clock arrives there. A high-water store that rejects a
    non-greater step accepts BOTH, because the second resolution is strictly greater.

    Three docstrings previously drew the opposite conclusion from the same true premise ("the clamp only
    lowers the recorded step, so single-use is preserved"). It lowers the step, and that is precisely
    why the code survives. ASVS 6.5.1 requires TOTPs be "only successfully usable once"; that holds at
    the shipped default and not at the opt-out, so the opt-out carries a real cost the docs now name.
    """
    t = 5_000 * PERIOD + 5.0
    future = totp.totp(SECRET, now=t + PERIOD)

    first = totp.verify_totp_step(SECRET, future, now=t, window=1)
    second = totp.verify_totp_step(SECRET, future, now=t + PERIOD, window=1)
    assert first == _step(t)  # clamped down, per SEC-014
    assert second == _step(t + PERIOD)  # its own step, still unspent
    assert second is not None and first is not None and second > first, (
        "the second resolution must be STRICTLY GREATER — that is what makes a high-water store "
        "accept the same code a second time"
    )

    # The strict default is the control: the same code cannot be used twice, because the first
    # presentation is refused outright rather than clamped.
    assert totp.verify_totp_step(SECRET, future, now=t, window=0) is None
    assert totp.verify_totp_step(SECRET, future, now=t + PERIOD, window=0) == _step(t + PERIOD)


def test_single_use_step_is_stable_for_the_same_code_and_now() -> None:
    # The same code at the same now resolves to the same step both times (a single-use store rejecting a
    # non-greater step then rejects the replay). Holds under both the strict and the opt-out window.
    t = 5_000 * PERIOD + 5.0
    for window in (0, 1):
        code = totp.totp(SECRET, now=t)
        first = totp.verify_totp_step(SECRET, code, now=t, window=window)
        second = totp.verify_totp_step(SECRET, code, now=t, window=window)
        assert first == second == _step(t)


# --- ASVS 11.2.4: the compare count is WINDOW-fixed, never match-dependent ----


class _CompareCounter:
    """Counts (and delegates) ``hmac.compare_digest`` calls made while installed."""

    def __init__(self) -> None:
        self.calls = 0
        self._real = hmac.compare_digest

    def __call__(self, a: object, b: object) -> bool:
        self.calls += 1
        return bool(self._real(a, b))  # type: ignore[arg-type]


def _compare_count(code: str, *, now: float, window: int, monkeypatch: pytest.MonkeyPatch) -> int:
    counter = _CompareCounter()
    monkeypatch.setattr(hmac, "compare_digest", counter)
    try:
        totp.verify_totp_step(SECRET, code, now=now, window=window)
    finally:
        monkeypatch.undo()
    return counter.calls


def test_compare_count_is_window_fixed_regardless_of_matching_step(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The L3 assessment's 11.2.4 residual named a second defect — "the TOTP verify loop short-circuits on the
    first matching step" — is STALE: there is no ``break``. This pins the refutation mechanically.

    A `now` well past the epoch is used deliberately: the loop's ``if step < 0: continue`` guard makes
    the candidate count vary near t=0, so a fixture pinning a synthetic small `now` would measure a
    legitimately different number and mis-pin the invariant. What must hold is that the count depends on
    ``window`` ALONE — not on which step matched, nor on whether any did."""
    t = 5_000 * PERIOD + 5.0
    window = 2
    expected = 2 * window + 1

    # Vary WHICH step matches across the whole window, plus the no-match case. The count must not move.
    counts = {
        offset: _compare_count(
            totp.totp(SECRET, now=t + offset * PERIOD),
            now=t,
            window=window,
            monkeypatch=monkeypatch,
        )
        for offset in range(-window, window + 1)
    }
    counts["none"] = _compare_count(  # type: ignore[index]
        "000000" if totp.totp(SECRET, now=t) != "000000" else "999999",
        now=t,
        window=window,
        monkeypatch=monkeypatch,
    )
    assert set(counts.values()) == {expected}, counts
    # Sanity: an early break at the first candidate would have made the -window case cost 1.
    assert expected > 1


def test_compare_count_scales_only_with_the_window(monkeypatch: pytest.MonkeyPatch) -> None:
    t = 5_000 * PERIOD + 5.0
    current = totp.totp(SECRET, now=t)
    for window in (0, 1, 2, 3):
        assert (
            _compare_count(current, now=t, window=window, monkeypatch=monkeypatch) == 2 * window + 1
        )
