# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two-box shardcert ladder verdict ordering and soak handshake (BACKLOG #5862, #5953).

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
    rep = _consolidated([_sustained(0, 20.0)], soak=soak, soak_aborted=True)
    assert rep.exit_code == 2


# --- BACKLOG #5953 (S27-75): the timing blocks name the lever that fills them, and are read off the loop ---


def test_empty_episode_block_names_its_own_lever() -> None:
    """S_lane is gated by MEFOR_PIPELINE_LANE_EPISODE_TIMING, not MEFOR_DELIVERY_PHASE_TIMING
    (messagefoundry.pipeline.phase_timing). An operator told the wrong lever turns on only the delivery one
    and still gets an empty episode block."""
    from harness.load.shardcert_ladder import _EMPTY_EPISODE_TIMING
    from messagefoundry.pipeline.phase_timing import LANE_EPISODE_TIMING_ENV

    rendered = _EMPTY_EPISODE_TIMING.render()
    assert LANE_EPISODE_TIMING_ENV in rendered
    assert "MEFOR_DELIVERY_PHASE_TIMING" not in rendered


async def test_engine_ladder_reads_the_node_logs_off_the_event_loop(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    """Aggregating a rung's node logs is file I/O over every shard's log; it runs on a worker thread, not
    on the event loop the engine ladder awaits its coord on."""
    import harness.load.shardcert_ladder as ladder
    from harness.load.coord import FileDropCoord
    from tests.test_shardcert_two_box import _engine_ladder_kwargs, _fake_engine_report

    loop_thread = threading.get_ident()
    attach_threads: list[int] = []

    async def fake_engine(**kwargs: Any) -> Any:
        return _fake_engine_report(aborted=True)

    def record_attach(payload: dict[str, object], logs: Any) -> None:
        attach_threads.append(threading.get_ident())

    monkeypatch.setattr(ladder, "run_shardcert_engine", fake_engine)
    monkeypatch.setattr(ladder, "_engine_rung_payload", lambda report: {})
    monkeypatch.setattr(ladder, "_attach_rung_timings", record_attach)
    coord = FileDropCoord(tmp_path / "coord", run_id="offloop")
    await asyncio.wait_for(
        ladder.run_engine_ladder(**_engine_ladder_kwargs(coord, tmp_path)), timeout=10.0
    )
    assert len(attach_threads) == 1
    assert attach_threads[0] != loop_thread
