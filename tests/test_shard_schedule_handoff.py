# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A non-owner engine shard never resumes a pooled lane its calendar handoff took (BACKLOG #5703).

A reload whose window is closed passes an engine park to the calendar (vault BACKLOG #3262), and a
later reload that removes the schedule resumes the lane (``_resume_unscheduled_outbound``). Every
engine shard ran the handoff, and the resume reached the pooled re-arm with no ownership test, so
an engine shard that does not own the lane (ADR 0073) re-armed it on its own dispatcher and claimed beside
the owner: two claimers on one FIFO lane. The DR activation's reload is one way in; the park an
``auto_start = false`` lane leaves is another, and is the one driven here.

A non-owner's dispatcher now never holds the lane at all (``_pause_pooled_outbound``), so the
tests read that invariant directly: no state for the foreign lane on this engine shard.

Viewed from engine shard ``a`` of a two-engine-shard universe, over one store. Ownership is computed
with the production hash, as in ``tests/test_shard_lane_ownership.py``.
"""

from __future__ import annotations

import asyncio
import time as _time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Priority, Schedule
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.sharding import filter_registry_for_shard
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from tests.test_connection_scheduler import _OUT_OF_WINDOW, _wait_until, _weekday_window
from tests.test_shard_lane_ownership import ADT, UNIVERSE, _pick_dest

_WINDOW = _weekday_window()  # closed at _OUT_OF_WINDOW
_SWEEP_SECONDS = 0.05
# Ten sweeps after the owner's lane delivered: a lane re-armed beside it, at the same moment,
# claims and writes its row well inside this.
_TOP_UP_SECONDS = 10 * _SWEEP_SECONDS


def _delivered(outdir: Path) -> bool:
    return any(outdir.iterdir())


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "handoff.db")
    yield s
    await s.close()


def _registry(
    tmp_path: Path, dests: list[str], *, auto_start: bool, schedule: Schedule | None
) -> Registry:
    """Engine shard ``a``'s view: one inbound on ``a``, the shared outbounds each writing to its own
    directory, every one with the given ``auto_start`` and ``schedule``."""
    inbox = tmp_path / "in_a"
    inbox.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in_a",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
            shard="a",
        )
    )
    reg.add_inbound(
        InboundConnection(
            "in_b",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "in_b"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
            shard="b",
        )
    )
    for dest in dests:
        outdir = tmp_path / dest
        outdir.mkdir(exist_ok=True)
        reg.add_outbound(
            OutboundConnection(
                dest,
                ConnectionSpec(
                    ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
                ),
                auto_start=auto_start,
                schedule=schedule,
            )
        )
    reg.add_router("r", lambda m: [])
    reg.add_handler("h", lambda m: Send(dests[0], m))
    filtered = filter_registry_for_shard(reg, "a")
    assert filtered.shard_id == "a" and filtered.all_shard_ids == UNIVERSE  # premise
    return filtered


def _runner(store: MessageStore, registry: Registry, **kwargs: Any) -> RegistryRunner:
    """A pooled runner over ``registry``, sweeping fast, with egress open."""
    return RegistryRunner(
        registry,
        store,
        claim_mode="pooled",
        pooled_sweep_interval=_SWEEP_SECONDS,
        egress=EgressSettings(deny_by_default=False),
        **kwargs,
    )


async def test_a_non_owner_does_not_resume_a_lane_its_handoff_took(
    store: MessageStore, tmp_path: Path
) -> None:
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    dests = [owned, foreign]
    runner = _runner(
        store,
        _registry(tmp_path, dests, auto_start=False, schedule=_WINDOW),
        schedule_clock=lambda: _OUT_OF_WINDOW,
    )
    await runner.start()
    try:
        assert {
            owned,
            foreign,
        } <= runner._gate_parked  # the boot gate parked both, on every engine shard
        ids = {
            dest: await store.enqueue_message(
                channel_id="in_a", raw=ADT, deliveries=[(dest, ADT)], now=_time.time()
            )
            for dest in dests
        }
        # auto_start back on with the window closed: the handoff passes the park to the calendar,
        # on every engine shard. Only the owner's calendar runs the lane.
        await runner.reload(_registry(tmp_path, dests, auto_start=True, schedule=_WINDOW))
        assert {owned, foreign} <= runner._schedule_parked
        # The schedule goes: the owner resumes its lane, and this engine shard must not arm the other.
        await runner.reload(_registry(tmp_path, dests, auto_start=True, schedule=None))
        # The control: the resume path is live here, for the lane this engine shard owns.
        await _wait_until(lambda: _delivered(tmp_path / owned))
        await asyncio.sleep(_TOP_UP_SECONDS)
        (foreign_row,) = await store.outbox_for(ids[foreign])
        assert foreign_row["status"] == "pending" and foreign_row["attempts"] == 0
        assert list((tmp_path / foreign).iterdir()) == []
        # The invariant itself, timing-free: this engine shard's dispatcher holds no state for the
        # lane, so nothing there can claim it.
        assert runner._dispatchers[Stage.OUTBOUND].phase(foreign) is None
    finally:
        await runner.stop()


async def test_a_non_owner_start_of_a_paused_lane_arms_nothing(
    store: MessageStore, tmp_path: Path
) -> None:
    """The shared primitive itself: ``_start_outbound_unsafe`` reached on a non-owner, by any
    internal caller, leaves the pooled lane unarmed. Its public door refuses first."""
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    runner = _runner(store, _registry(tmp_path, [owned, foreign], auto_start=False, schedule=None))
    await runner.start()
    try:
        message_id = await store.enqueue_message(
            channel_id="in_a", raw=ADT, deliveries=[(foreign, ADT), (owned, ADT)], now=_time.time()
        )
        async with runner._reload_lock:
            await runner._start_outbound_unsafe(foreign)
            await runner._start_outbound_unsafe(owned)  # the control
        await _wait_until(lambda: _delivered(tmp_path / owned))
        await asyncio.sleep(_TOP_UP_SECONDS)
        (row,) = [r for r in await store.outbox_for(message_id) if r["destination_name"] == foreign]
        assert row["status"] == "pending" and row["attempts"] == 0
        assert list((tmp_path / foreign).iterdir()) == []
        # The invariant itself, timing-free: this engine shard's dispatcher holds no state for the
        # lane, so nothing there can claim it.
        assert runner._dispatchers[Stage.OUTBOUND].phase(foreign) is None
    finally:
        await runner.stop()


async def test_a_non_owner_pause_after_a_resume_reads_quiesced(
    store: MessageStore, tmp_path: Path
) -> None:
    """The runner primitives alone: pause, resume, pause again on a non-owner. The second pause
    used to clear the quiescence signal and ask the dispatcher for a pause it still held from the
    first, so the lane read ``stopping`` for good."""
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    runner = _runner(store, _registry(tmp_path, [owned, foreign], auto_start=True, schedule=None))
    await runner.start()
    try:
        async with runner._reload_lock:
            for name in (owned, foreign):  # the owned lane is the control
                runner._stop_outbound_unsafe(name)
                await runner._start_outbound_unsafe(name)
                runner._stop_outbound_unsafe(name)
        await _wait_until(lambda: runner.outbound_quiesced(owned))
        assert runner.outbound_status(foreign) == "stopped"
        assert runner._dispatchers[Stage.OUTBOUND].phase(foreign) is None
    finally:
        await runner.stop()


async def test_a_non_owner_lane_a_handoff_left_quiesces_when_the_box_goes_passive(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A closed-window reload on a non-owner, then a passive DR park, leaves the lane quiesced.

    The handoff reload resumed the foreign lane in the runner's records only: the pause and the
    quiescence signal went, while this engine shard's dispatcher kept the lane PAUSED. The passive
    park then paused it again, which cleared the quiescence signal and asked the dispatcher for a
    pause it already had, so nothing set the signal again. The lane read ``stopping`` for good, and
    ``close_passive_connectors`` waited out its bound and left the connector open."""
    monkeypatch.setattr(wiring_runner, "_PASSIVE_QUIESCE_WAIT_SECONDS", 1.0)
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    dests = [owned, foreign]
    runner = _runner(
        store,
        _registry(tmp_path, dests, auto_start=False, schedule=_WINDOW),
        schedule_clock=lambda: _OUT_OF_WINDOW,
    )
    await runner.start()
    try:
        await runner.reload(_registry(tmp_path, dests, auto_start=True, schedule=_WINDOW))
        assert owned in runner._schedule_parked  # the control: the handoff ran
        runner.set_dr_threshold(None, standby=Priority.CRITICAL)  # a release: the box is passive
        await runner.close_passive_connectors()
        assert runner.outbound_status(owned) == "stopped"  # the control
        assert owned not in runner._destinations
        assert runner.outbound_status(foreign) == "stopped"
        assert foreign not in runner._destinations
    finally:
        await runner.stop()
