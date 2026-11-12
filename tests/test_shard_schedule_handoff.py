# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A non-owner engine shard never resumes a pooled lane its calendar handoff took (BACKLOG #5703).

A reload whose window is closed passes an engine park to the calendar (vault BACKLOG #3262), and a
later reload that removes the schedule resumes the lane (``_resume_unscheduled_outbound``). Every
engine shard ran the handoff, and the resume reached the pooled re-arm with no ownership test, so
an engine shard that does not own the lane (ADR 0073) re-armed it on its own dispatcher and claimed beside
the owner: two claimers on one FIFO lane. The DR activation's reload is one way in; the park an
``auto_start = false`` lane leaves is another, and is the one driven here.

Viewed from engine shard ``a`` of a two-engine-shard universe, over one store. Ownership is computed
with the production hash, as in ``tests/test_shard_lane_ownership.py``.
"""

from __future__ import annotations

import asyncio
import time as _time
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Schedule
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
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


async def test_a_non_owner_does_not_resume_a_lane_its_handoff_took(
    store: MessageStore, tmp_path: Path
) -> None:
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    dests = [owned, foreign]
    runner = RegistryRunner(
        _registry(tmp_path, dests, auto_start=False, schedule=_WINDOW),
        store,
        claim_mode="pooled",
        pooled_sweep_interval=_SWEEP_SECONDS,
        schedule_clock=lambda: _OUT_OF_WINDOW,
        egress=EgressSettings(deny_by_default=False),
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
        # auto_start back on with the window closed: the handoff passes the owner's park to the
        # calendar. A non-owner has no calendar for the lane, so it takes no such park.
        await runner.reload(_registry(tmp_path, dests, auto_start=True, schedule=_WINDOW))
        assert owned in runner._schedule_parked  # the control: the handoff ran
        assert foreign not in runner._schedule_parked
        # The schedule goes: the owner resumes its lane, and this engine shard must not arm the other.
        await runner.reload(_registry(tmp_path, dests, auto_start=True, schedule=None))
        # The control: the resume path is live here, for the lane this engine shard owns.
        await _wait_until(lambda: _delivered(tmp_path / owned))
        await asyncio.sleep(_TOP_UP_SECONDS)
        (foreign_row,) = await store.outbox_for(ids[foreign])
        assert foreign_row["status"] == "pending" and foreign_row["attempts"] == 0
        assert list((tmp_path / foreign).iterdir()) == []
        # The invariant itself, timing-free: this engine shard's dispatcher still holds the lane
        # PAUSED, where a re-arm would have moved it on.
        assert runner._dispatchers[Stage.OUTBOUND].paused(foreign)
    finally:
        await runner.stop()


async def test_a_non_owner_start_of_a_paused_lane_arms_nothing(
    store: MessageStore, tmp_path: Path
) -> None:
    """The shared primitive itself: ``_start_outbound_unsafe`` reached on a non-owner, by any
    internal caller, leaves the pooled lane unarmed. Its public door refuses first."""
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    runner = RegistryRunner(
        _registry(tmp_path, [owned, foreign], auto_start=False, schedule=None),
        store,
        claim_mode="pooled",
        pooled_sweep_interval=_SWEEP_SECONDS,
        egress=EgressSettings(deny_by_default=False),
    )
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
        # The invariant itself, timing-free: this engine shard's dispatcher still holds the lane
        # PAUSED, where a re-arm would have moved it on.
        assert runner._dispatchers[Stage.OUTBOUND].paused(foreign)
    finally:
        await runner.stop()
