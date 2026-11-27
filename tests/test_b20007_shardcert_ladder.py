# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two-box shardcert ladder verdict ordering and soak handshake (BACKLOG #5862, #5953).

Unit tests over synthetic counters: no load run, no database, no fleet.
"""

from __future__ import annotations

import dataclasses

from harness.load.shardcert_ladder import (
    LadderRung,
    RungOutcome,
    RungVerdict,
    build_consolidated_report,
    build_rung_outcome,
)
from tests.test_shardcert_failclosed_verdicts import (
    _ABORTED_GATE,
    _DESTS,
    _clean_gate,
    _consolidated,
    _drive,
    _result_line,
    _sustained,
)

_SOAK_RUNG = LadderRung(
    index=9, ingress_rate=20.0, hold_seconds=900.0, drain_timeout=150.0, is_soak=True
)


def _underdriven_soak(*, inversions: int = 0, repeats: int = 0) -> RungOutcome:
    """A soak whose load generator sent half its plan (DRIVE_SHORTFALL: the scheduler, not the engine,
    deferred the sends), with ``inversions`` FIFO inversions and ``repeats`` duplicates at the sinks."""
    full = _drive(20.0)
    drive = dataclasses.replace(
        full,
        offered=full.offered * 2,
        deferred_backpressure=0,
        deferred_schedule=full.offered,
        lane_inversions=inversions,
        lane_repeats=repeats,
    )
    return build_rung_outcome(_SOAK_RUNG, drive, _clean_gate(), None)


# --- BACKLOG #5862: a measured correctness break is FAIL, never hidden behind a setup degradation ----------


def test_soak_break_under_a_drive_shortfall_is_fail() -> None:
    """The climb held; the soak was under-driven by the rig AND showed a FIFO inversion at the sinks. The
    inversion was measured on the copies that were sent, so it is a correctness break: FAIL / exit 1, not
    the SETUP_DEGRADED / exit 2 a rig shortfall alone earns."""
    soak = _underdriven_soak(inversions=2)
    assert soak.verdict is RungVerdict.CORRECTNESS_FAIL
    rep = _consolidated([_sustained(0, 20.0), _sustained(1, 24.0)], soak=soak)
    assert rep.soak_drive_shortfall is True
    assert rep.exit_code == 1
    assert rep.result_label == "FAIL"
    assert _result_line(rep).startswith("RESULT: FAIL")


def test_soak_duplicate_under_a_drive_shortfall_is_fail() -> None:
    soak = _underdriven_soak(repeats=1)
    rep = _consolidated([_sustained(0, 20.0)], soak=soak)
    assert rep.exit_code == 1
    assert rep.result_label == "FAIL"


def test_clean_underdriven_soak_stays_setup_degraded() -> None:
    """Control: with no break the rig shortfall is still a setup degradation."""
    rep = _consolidated([_sustained(0, 20.0)], soak=_underdriven_soak())
    assert rep.soak_drive_shortfall is True
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


def test_soak_break_on_an_engine_aborted_soak_stays_setup_degraded() -> None:
    """A soak the engine marked aborted had its sinks torn down mid-delivery, so a repeat there can be the
    teardown's redelivery: unproven, and the run stays exit 2."""
    drive = dataclasses.replace(_drive(20.0, drained=False), lane_repeats=3)
    soak = build_rung_outcome(_SOAK_RUNG, drive, _ABORTED_GATE, None)
    rep = _consolidated([_sustained(0, 20.0)], soak=soak)
    assert rep.soak_aborted is True
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


def test_soak_break_under_a_drive_side_soak_abort_stays_setup_degraded() -> None:
    soak = _underdriven_soak(inversions=2)
    rep = build_consolidated_report(
        shards=("a", "b"),
        dests=_DESTS,
        handlers=_DESTS,
        delivering=_DESTS,
        routing="broadcast",
        lanes_per_shard=1,
        driver_count=2,
        sink_count=_DESTS,
        climb=[_sustained(0, 20.0)],
        soak=soak,
        climb_aborted=False,
        soak_aborted=True,
    )
    assert rep.exit_code == 2
