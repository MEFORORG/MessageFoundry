# Copyright (c) MessageFoundry contributors.
# SPDX-License-Identifier: Apache-2.0
"""A4 — structural guards against the harness's ONE bug class.

Nine defects (B1, B6, B7, B8, B9, B10 and the D-series) share a single shape: **a fixed constant
bounding a parameter-scaled interval which, on expiry, silently fabricates a plausible result.** Point
fixes closed each instance. These tests close the *class*, so a future gate cannot reintroduce it without
turning a test red.

Two invariants, each stated as a property over a parameter grid rather than as a spot check — a spot check
is exactly what let every one of these through.

**(1) Every derived timeout strictly dominates the interval it guards.**
    The B1/B6/B7 family. A timeout is a *bound*, never a wait: overshooting costs nothing, undershooting
    fabricates a collapse (or, for B7, a false negative). So each `_derive_*_timeout` must exceed the sum
    of the steps it must survive, for *every* `(hold, drain)` in the operating range — not merely at the
    defaults the constant was tuned against.

**(2) The honest sustainable rate is invariant to the hold length.**
    The B8 defect: a 60 s climb rung is a *volume* test read as a *rate* test. If an engine truly sustains
    `S` msg/s and is offered `R > S` for a hold `H`, it accumulates a backlog of `(R - S) * H` and needs
    `D = (R - S) * H / S` to drain it. Substituting into the honest rate:

        R * H / (H + D)  ==  R * H / (H + (R - S) * H / S)  ==  R * S / R  ==  S

    The hold cancels **exactly**. So `sustainable_ingress_rate` must return `S` for every `H` — if it
    varies with `H`, the reduction is measuring how long we ran, not how fast the engine goes.
"""

from __future__ import annotations

import pytest

from harness.load.shardcert import (
    _derive_drive_complete_timeout,
    _derive_driver_done_timeout,
    _derive_engine_drained_timeout,
)
from harness.load.shardcert_ladder import RungVerdict

from tests.test_shardcert_ladder_two_box import _honest_rung

# The operating range the CLI actually admits. `hold` spans a climb rung (60 s) to a long soak (1800 s);
# `drain` spans the default (150 s) and the ~300 s ceiling past which raising it re-arms B7.
HOLDS = (60.0, 120.0, 300.0, 600.0, 900.0, 1800.0)
DRAINS = (30.0, 60.0, 150.0, 300.0)
CHILD_READY = (30.0, 120.0)


@pytest.mark.parametrize("hold", HOLDS)
@pytest.mark.parametrize("drain", DRAINS)
def test_driver_done_timeout_dominates_the_hold_it_guards(hold: float, drain: float) -> None:
    # B1/B3: DRIVER_DONE is posted after the hold, BEFORE the drain. The bound must exceed the hold for
    # every hold, not just the one the old fixed 600.0 happened to cover.
    got = _derive_driver_done_timeout(hold, drain, None)
    assert got > hold, f"driver_done bound {got} does not dominate hold {hold}"


@pytest.mark.parametrize("drain", DRAINS)
def test_engine_drained_timeout_dominates_the_drain_it_guards(drain: float) -> None:
    # B7: the engine's own drain is bounded by the SAME drain_timeout we were handed. A fixed 300.0 was
    # safe only while the drain stayed under ~150 s, so raising --drain-timeout quietly disarmed the gate.
    got = _derive_engine_drained_timeout(drain, None)
    assert got > drain, f"engine_drained bound {got} does not dominate drain {drain}"


@pytest.mark.parametrize("await_engine_drained", [True, False])
@pytest.mark.parametrize("child_ready", CHILD_READY)
@pytest.mark.parametrize("drain", DRAINS)
@pytest.mark.parametrize("hold", HOLDS)
def test_drive_complete_timeout_dominates_every_coordinator_step(
    hold: float, drain: float, child_ready: float, await_engine_drained: bool
) -> None:
    # B6, the nastiest of the family: the SINK's window strictly CONTAINS the driver's — it opens at
    # SINK_BOUND and closes after DRIVE_COMPLETE, which trails DRIVER_DONE by the drain AND the
    # ENGINE_DRAINED gate. The bound must dominate the SUM of those steps, at every parameterisation.
    engine_drained = _derive_engine_drained_timeout(drain, None)
    got = _derive_drive_complete_timeout(
        hold,
        drain,
        child_ready_timeout=child_ready,
        engine_drained_timeout=engine_drained,
        await_engine_drained=await_engine_drained,
    )
    guarded = (
        2.0 * child_ready  # the M-1 sinks bind, then the K senders arm
        + _derive_driver_done_timeout(hold, drain, None)  # DRIVE_GO -> every DRIVER_DONE
        + drain  # the drive's own /stats drain poll
        + (engine_drained if await_engine_drained else 0.0)  # the ENGINE_DRAINED gate
    )
    assert got > guarded, f"drive_complete bound {got} does not dominate its steps {guarded}"


@pytest.mark.parametrize("hold", HOLDS)
@pytest.mark.parametrize("true_rate", [10.0, 22.5, 90.0])
@pytest.mark.parametrize("overload", [1.5, 2.0, 5.0])
def test_honest_sustainable_rate_is_invariant_to_hold(
    hold: float, true_rate: float, overload: float
) -> None:
    """The B8 guard, and the sharpest test in this file.

    Offer `overload x true_rate` for `hold` seconds against an engine that truly sustains `true_rate`.
    The backlog is `(offered - true) * hold`, draining at `true_rate`. The honest rate must recover
    `true_rate` EXACTLY, for every hold — the hold cancels algebraically.

    Before B8's fix the ladder reported the raw offered rate, overstating the truth by
    `(hold + drain) / hold`. At the ceiling run that factor was ~3.5x.
    """
    offered = overload * true_rate
    backlog = (offered - true_rate) * hold
    drain = backlog / true_rate

    rung = _honest_rung(offered, RungVerdict.SUSTAINED, drain_seconds=drain, hold=hold)

    assert rung.sustainable_ingress_rate == pytest.approx(true_rate, rel=1e-9)


@pytest.mark.parametrize("hold", HOLDS)
def test_a_kept_up_rung_reports_its_offered_rate(hold: float) -> None:
    # The other end of the same property: zero drain means the engine kept up in real time, so the honest
    # rate IS the offered rate. Guards against a "fix" that discounts unconditionally (double-discounting,
    # the error the ceiling-ladder doc explicitly warns about).
    rung = _honest_rung(90.0, RungVerdict.SUSTAINED, drain_seconds=0.0, hold=hold)
    assert rung.sustainable_ingress_rate == pytest.approx(90.0)


def test_the_honest_rate_declines_as_the_offer_rises_past_the_true_ceiling() -> None:
    """The reading the rig had to correct by hand: on a fleet at its ceiling the honest series *declines*
    as the offer climbs — the engine is not gaining headroom, it is absorbing a larger burst and draining
    it afterwards. A climb whose honest rate rises with the offer has not found the ceiling yet."""
    true_rate, hold = 20.0, 60.0
    honest = []
    for offered in (24.0, 30.0, 40.0, 60.0):
        drain = (offered - true_rate) * hold / true_rate
        rung = _honest_rung(offered, RungVerdict.SUSTAINED, drain_seconds=drain, hold=hold)
        rate = rung.sustainable_ingress_rate
        assert rate is not None
        honest.append(rate)
    # Every rung recovers the same true ceiling; none of them "gains" from being offered more.
    assert honest == pytest.approx([true_rate] * 4)
    assert max(honest) - min(honest) < 1e-9


def test_every_derived_bound_scales_with_the_parameter_it_guards() -> None:
    """**The bug class, stated structurally.** This is the test that makes the rest non-vacuous.

    A bound that guards a parameter-scaled interval must itself *scale with that parameter*. A fixed
    constant satisfies "bound > interval" at the parameterisation it was tuned against and fails silently
    everywhere else — which is precisely B1 (fixed 600 s vs a hold up to 1800 s), B6 (a second, separate
    fixed 600 s on the sink) and B7 (fixed 300 s vs a drain raised past 300 s).

    So: strictly increase each guarded parameter and require the bound to strictly increase. Any future
    reversion to a constant turns this red, regardless of how generous the constant is.
    """
    # B1 — must scale with `hold`.
    assert _derive_driver_done_timeout(1800.0, 150.0, None) > _derive_driver_done_timeout(
        60.0, 150.0, None
    )
    # B1 — and with `drain`.
    assert _derive_driver_done_timeout(60.0, 300.0, None) > _derive_driver_done_timeout(
        60.0, 30.0, None
    )
    # B7 — must scale with `drain`.
    assert _derive_engine_drained_timeout(300.0, None) > _derive_engine_drained_timeout(30.0, None)

    def _dc(hold: float, drain: float, child_ready: float = 30.0) -> float:
        return _derive_drive_complete_timeout(
            hold,
            drain,
            child_ready_timeout=child_ready,
            engine_drained_timeout=_derive_engine_drained_timeout(drain, None),
            await_engine_drained=True,
        )

    # B6 — must scale with `hold`, with `drain`, AND with `child_ready` (it spans two child spawns).
    assert _dc(1800.0, 150.0) > _dc(60.0, 150.0)
    assert _dc(60.0, 300.0) > _dc(60.0, 30.0)
    assert _dc(60.0, 150.0, child_ready=120.0) > _dc(60.0, 150.0, child_ready=30.0)


def test_an_explicit_override_still_wins_outright() -> None:
    # The escape hatch must remain exact: an operator-supplied bound is returned verbatim, never
    # re-derived. (Deliberate-bracket-testing path; also how a rig pins a known-good window.)
    assert _derive_driver_done_timeout(1800.0, 300.0, 42.0) == 42.0
    assert _derive_engine_drained_timeout(300.0, 42.0) == 42.0
    assert (
        _derive_drive_complete_timeout(
            1800.0,
            300.0,
            child_ready_timeout=30.0,
            engine_drained_timeout=300.0,
            await_engine_drained=True,
            override=42.0,
        )
        == 42.0
    )


def test_a_sustained_rung_always_has_a_measured_drain() -> None:
    # B8/D1's own precondition: sustainable_ingress_rate returns None only when NO drain was measured.
    # A SUSTAINED rung is guaranteed an engine-side store-truth drain, so it must never be dropped from
    # the pinned ceiling for want of one. A rung with no drain at all is the only None case.
    assert _honest_rung(50.0, drain_seconds=None).sustainable_ingress_rate is None
    assert _honest_rung(50.0, drain_seconds=0.0).sustainable_ingress_rate is not None
