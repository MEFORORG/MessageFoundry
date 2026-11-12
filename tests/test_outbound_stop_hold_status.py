# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An outbound halted on a STOP only an operator may lift (BACKLOG #5700, #5701).

Each test starts a runner whose scheduled outbound has just STOPPED on a credential fault, in its
window, through the rig in ``tests/test_connection_scheduler.py``. The status reads must say the
lane is down, and an operator start must bring it back up in either claim mode.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from tests.test_connection_scheduler import (
    _IN_WINDOW,
    _Clock,
    _CollectingDestination,
    _start_credential_fault_rig,
    _wait_until,
    _weekday_window,
)

_OB = "OB_SCHED"
# A re-armed lane delivers its retained row in well under a second; an unarmed one never does.
_DELIVER_BOUND_SECONDS = 5.0


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "hold.db")
    yield s
    await s.close()


async def _stopped_rig(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> tuple[RegistryRunner, _CollectingDestination]:
    runner, _ = await _start_credential_fault_rig(
        store, tmp_path, claim_mode, _Clock(_IN_WINDOW), _weekday_window()
    )
    good = _CollectingDestination()
    runner._destinations[_OB] = good  # type: ignore[assignment]  # the operator fixed the credential
    return runner, good


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_a_lane_a_credential_fault_stopped_reads_as_stopped(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    """BACKLOG #5701. Before the fix both reads saw only the halt latch and the pause set, so a
    lane the STOP had taken down read as running while it delivered nothing."""
    runner, _ = await _stopped_rig(store, tmp_path, claim_mode)
    try:
        assert ("outbound", _OB) in runner._stop_held  # the control: the STOP really held it
        assert not runner.outbound_running(_OB)
        assert runner.outbound_status(_OB) == "stopped"
    finally:
        await runner.stop()


async def test_a_pooled_lane_its_dispatcher_holds_stopped_reads_as_stopped(
    store: MessageStore, tmp_path: Path
) -> None:
    """A pooled lane at STOPPED with no operator hold recorded, as a leadership-loss STOP leaves
    one, is not delivering either, so the reads say so."""
    runner, _ = await _stopped_rig(store, tmp_path, "pooled")
    try:
        runner._stop_held.discard(("outbound", _OB))
        assert runner._dispatchers[Stage.OUTBOUND].stopped(_OB)  # the control
        assert not runner.outbound_running(_OB)
        assert runner.outbound_status(_OB) == "stopped"
    finally:
        await runner.stop()


@pytest.mark.parametrize("claim_mode", ["per_lane", "pooled"])
async def test_an_operator_start_re_arms_a_lane_a_credential_fault_stopped(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    """BACKLOG #5700. Before the fix a pooled start called resume_lane, which re-armed only a
    PAUSED lane: the start returned as if it had worked, and the lane stayed STOPPED, delivering
    nothing. The per_lane worker was already respawned; it is the control."""
    runner, good = await _stopped_rig(store, tmp_path, claim_mode)
    try:
        await runner.start_outbound(_OB)
        await _wait_until(lambda: len(good.sent) == 1, timeout=_DELIVER_BOUND_SECONDS)
        assert ("outbound", _OB) not in runner._stop_held  # the calendar owns the lane again
        assert runner.outbound_running(_OB)
        assert runner.outbound_status(_OB) == "running"
    finally:
        await runner.stop()
