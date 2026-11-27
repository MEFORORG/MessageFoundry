# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two-box shardcert ladder verdict ordering (BACKLOG #5862) and engine-ladder rung timings (BACKLOG #5953,
S27-75).

Unit tests over synthetic counters: no load run, no database, no fleet.
"""

from __future__ import annotations

import asyncio
import dataclasses
import threading
from pathlib import Path
from typing import Any

import pytest

from harness.load.shardcert_ladder import (
    LadderRung,
    RungOutcome,
    RungVerdict,
    build_rung_outcome,
)
from tests.test_shardcert_failclosed_verdicts import (
    _ABORTED_GATE,
    _clean_gate,
    _consolidated,
    _drive,
    _result_line,
    _rung,
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


def _engine_aborted_soak(*, inversions: int = 0, repeats: int = 0) -> RungOutcome:
    """A soak the engine marked aborted (its sinks torn down mid-delivery)."""
    drive = dataclasses.replace(
        _drive(20.0, drained=False), lane_inversions=inversions, lane_repeats=repeats
    )
    return build_rung_outcome(_SOAK_RUNG, drive, _ABORTED_GATE, None)


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


def test_soak_inversion_on_an_engine_aborted_soak_is_fail() -> None:
    """The tracker counts an inversion only for a NEW seq below a lane's high-water, which a teardown's
    redelivery cannot produce, so an inversion on an aborted soak is still a measured break."""
    rep = _consolidated([_sustained(0, 20.0)], soak=_engine_aborted_soak(inversions=2))
    assert rep.soak_aborted is True
    assert rep.exit_code == 1
    assert rep.result_label == "FAIL"


def test_soak_inversion_behind_an_unconfirmed_climb_rung_is_fail() -> None:
    """A climb rung whose store-truth never arrived is INCONCLUSIVE, which says nothing about the order the
    soak's sinks observed: the soak's inversion is still FAIL / exit 1."""
    unconfirmed = build_rung_outcome(_rung(1, 24.0), _drive(24.0), None, None)
    assert unconfirmed.verdict is RungVerdict.INCONCLUSIVE
    soak = build_rung_outcome(
        _SOAK_RUNG, dataclasses.replace(_drive(20.0), lane_inversions=3), _clean_gate(), None
    )
    rep = _consolidated([_sustained(0, 20.0), unconfirmed], soak=soak)
    assert rep.store_truth_unconfirmed is True
    assert rep.exit_code == 1
    assert rep.result_label == "FAIL"


def _unconfirmed_climb_rung() -> RungOutcome:
    """A climb rung whose engine store-truth never arrived: INCONCLUSIVE."""
    rung = build_rung_outcome(_rung(1, 24.0), _drive(24.0), None, None)
    assert rung.verdict is RungVerdict.INCONCLUSIVE
    return rung


def test_soak_duplicate_on_a_driven_soak_behind_an_unconfirmed_climb_rung_is_fail() -> None:
    """A soak the rig fully drove and the engine did not abort saw a duplicate at its sinks. Neither cause
    that makes a soak repeat unproven (a teardown's redelivery, an overloaded sink's late ACK) applies, and
    another rung's missing store-truth says nothing about this soak's sinks: FAIL / exit 1."""
    soak = build_rung_outcome(
        _SOAK_RUNG, dataclasses.replace(_drive(20.0), lane_repeats=2), _clean_gate(), None
    )
    assert soak.verdict is RungVerdict.CORRECTNESS_FAIL
    rep = _consolidated([_sustained(0, 20.0), _unconfirmed_climb_rung()], soak=soak)
    assert rep.store_truth_unconfirmed is True
    assert not (rep.soak_aborted or rep.soak_drive_shortfall)
    assert rep.exit_code == 1
    assert rep.result_label == "FAIL"


def test_single_lane_driven_soak_behind_an_unconfirmed_climb_rung_is_fail() -> None:
    """The single-lane term is waived only for an under-driven soak; a fully driven soak that saw one lane
    has vacuous FIFO evidence whatever another rung's store-truth says: FAIL / exit 1."""
    soak = build_rung_outcome(
        _SOAK_RUNG, dataclasses.replace(_drive(20.0), lanes_observed=1), _clean_gate(), None
    )
    assert soak.verdict is RungVerdict.SUSTAINED
    rep = _consolidated([_sustained(0, 20.0), _unconfirmed_climb_rung()], soak=soak)
    assert rep.store_truth_unconfirmed is True
    assert rep.exit_code == 1
    assert rep.result_label == "FAIL"


def test_soak_duplicate_with_an_unattributed_shortfall_behind_an_unconfirmed_climb_rung_stays_degraded() -> (
    None
):
    """A soak whose ``sent`` fell short with the cause unrecorded (OFFER_SHORTFALL) may be one the rig could
    not drive, so its duplicate is not proven next to an unconfirmed climb rung: exit 2."""
    full = _drive(20.0)
    drive = dataclasses.replace(
        full,
        offered=full.offered * 2,
        deferred_backpressure=-1,
        deferred_schedule=-1,
        lane_repeats=1,
    )
    soak = build_rung_outcome(_SOAK_RUNG, drive, _clean_gate(), None)
    rep = _consolidated([_sustained(0, 20.0), _unconfirmed_climb_rung()], soak=soak)
    assert rep.soak_offer_shortfall is True
    assert rep.ok is False
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


def test_clean_soak_behind_an_unconfirmed_climb_rung_stays_setup_degraded() -> None:
    """Control: with no break anywhere, the unconfirmed climb rung is still exit 2."""
    soak = build_rung_outcome(_SOAK_RUNG, _drive(20.0), _clean_gate(), None)
    rep = _consolidated([_sustained(0, 20.0), _unconfirmed_climb_rung()], soak=soak)
    assert rep.ok is True
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


def test_climb_break_behind_an_unconfirmed_climb_rung_stays_setup_degraded() -> None:
    """Unchanged: a CLIMB duplicate next to an unconfirmed climb rung is still exit 2."""
    dup = build_rung_outcome(
        _rung(2, 28.0), dataclasses.replace(_drive(28.0), lane_repeats=1), _clean_gate(), None
    )
    assert dup.verdict is RungVerdict.CORRECTNESS_FAIL
    soak = build_rung_outcome(_SOAK_RUNG, _drive(20.0), _clean_gate(), None)
    rep = _consolidated([_sustained(0, 20.0), _unconfirmed_climb_rung(), dup], soak=soak)
    assert rep.exit_code == 2


def test_clean_underdriven_soak_stays_setup_degraded() -> None:
    """Control: with no break the rig shortfall is still a setup degradation."""
    rep = _consolidated([_sustained(0, 20.0)], soak=_underdriven_soak())
    assert rep.soak_drive_shortfall is True
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


def test_soak_duplicate_under_a_drive_shortfall_stays_setup_degraded() -> None:
    """An overloaded load-gen box can ACK late and provoke a redelivery, which counts as a repeat, so a
    duplicate on an under-driven soak is not a proven break."""
    rep = _consolidated([_sustained(0, 20.0)], soak=_underdriven_soak(repeats=1))
    assert rep.soak_drive_shortfall is True
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


def test_single_lane_underdriven_soak_stays_setup_degraded() -> None:
    """The soak's single-lane term is not a hard break: an under-driven soak can see few lanes."""
    full = _drive(20.0)
    drive = dataclasses.replace(
        full,
        offered=full.offered * 2,
        deferred_backpressure=0,
        deferred_schedule=full.offered,
        lanes_observed=1,
    )
    soak = build_rung_outcome(_SOAK_RUNG, drive, _clean_gate(), None)
    assert soak.verdict is RungVerdict.SUSTAINED
    rep = _consolidated([_sustained(0, 20.0)], soak=soak)
    assert rep.ok is False
    assert rep.exit_code == 2


def test_soak_duplicate_on_an_engine_aborted_soak_stays_setup_degraded() -> None:
    """A soak the engine marked aborted had its sinks torn down mid-delivery, so a repeat there can be the
    teardown's redelivery: unproven, and the run stays exit 2."""
    rep = _consolidated([_sustained(0, 20.0)], soak=_engine_aborted_soak(repeats=3))
    assert rep.soak_aborted is True
    assert rep.exit_code == 2
    assert rep.result_label == "SETUP_DEGRADED"


# --- BACKLOG #5953 (S27-75): the timing blocks name the lever that fills them, and are read off the loop ---


def test_empty_episode_block_names_its_own_lever() -> None:
    """S_lane is gated by MEFOR_PIPELINE_LANE_EPISODE_TIMING, not MEFOR_DELIVERY_PHASE_TIMING
    (messagefoundry.pipeline.phase_timing). An operator told the wrong lever turns on only the delivery one
    and still gets an empty episode block. The harness writes the name as a literal; this pins it."""
    from harness.load.shardcert_ladder import _EMPTY_EPISODE_TIMING
    from messagefoundry.pipeline.phase_timing import LANE_EPISODE_TIMING_ENV

    rendered = _EMPTY_EPISODE_TIMING.render()
    assert LANE_EPISODE_TIMING_ENV in rendered
    assert "MEFOR_DELIVERY_PHASE_TIMING" not in rendered


async def test_engine_ladder_reads_the_node_logs_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Aggregating a rung's node logs is file I/O over every engine shard's log; it runs on a worker
    thread, not on the event loop the engine ladder awaits its coord on, at the climb and the soak call
    sites both. The drive's LADDER_STOP is lost here so the run reaches the soak."""
    import harness.load.shardcert_ladder as ladder
    from harness.load.coord import LADDER_SOAK, CoordTimeout, FileDropCoord
    from tests.test_shardcert_two_box import _engine_ladder_kwargs, _fake_engine_report

    loop_thread = threading.get_ident()
    attach_threads: list[int] = []
    coord = FileDropCoord(tmp_path / "coord", run_id="offloop")

    async def fake_engine(**kwargs: Any) -> Any:
        if kwargs["coord"].run_id.endswith(".r1"):
            coord.post(LADDER_SOAK, {"soak_rate": 10.0, "hold_seconds": 1.0, "drain_timeout": 1.0})
            raise CoordTimeout("no DRIVE_START")
        return _fake_engine_report(aborted=False)

    def record_attach(payload: dict[str, object], logs: Any) -> None:
        attach_threads.append(threading.get_ident())

    monkeypatch.setattr(ladder, "run_shardcert_engine", fake_engine)
    monkeypatch.setattr(ladder, "_engine_rung_payload", lambda report: {})
    monkeypatch.setattr(ladder, "_attach_rung_timings", record_attach)
    result = await asyncio.wait_for(
        ladder.run_engine_ladder(**_engine_ladder_kwargs(coord, tmp_path)), timeout=10.0
    )
    assert result.rungs_armed == ["r0", "soak"], result.notes
    assert len(attach_threads) == 2
    assert loop_thread not in attach_threads
