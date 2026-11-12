# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A non-owner engine shard never resumes a pooled lane its calendar handoff took (BACKLOG #5703).

A reload whose window is closed passes an engine park to the calendar (vault BACKLOG #3262), and a
later reload that removes the schedule resumes the lane (``_resume_unscheduled_outbound``). Every
engine shard ran the handoff, and the resume reached the pooled re-arm with no ownership test, so
a shard that does not own the lane (ADR 0073) re-armed it on its own dispatcher and claimed beside
the owner: two claimers on one FIFO lane. The DR activation's reload is one way in; the park an
``auto_start = false`` lane leaves is another, and is the one driven here.

Viewed from engine shard ``a`` of a two-engine-shard universe, over one store. Ownership is computed
with the production hash, as in ``tests/test_shard_lane_ownership.py``.
"""

from __future__ import annotations

import asyncio
import time as _time
from datetime import UTC, datetime, time
from pathlib import Path

import pytest

from messagefoundry.config.models import ActiveWindow, ConnectorType, Schedule
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
from messagefoundry.store import MessageStore
from tests.test_shard_lane_ownership import ADT, UNIVERSE, _pick_dest

# Monday 18:00 UTC, after a weekday 08:00-17:00 window has closed.
_OUT_OF_WINDOW = datetime(2026, 7, 13, 18, tzinfo=UTC)
_WINDOW = Schedule(
    windows=[
        ActiveWindow(
            days=frozenset({0, 1, 2, 3, 4}), start=time(8, 0), end=time(17, 0), timezone="UTC"
        )
    ]
)
# Ten pooled sweep intervals: a lane that was re-armed claims its row well inside this.
_CLAIM_WINDOW_SECONDS = 0.5


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "handoff.db")
    yield s
    await s.close()


def _registry(
    tmp_path: Path, dests: list[str], *, auto_start: bool, schedule: Schedule | None
) -> Registry:
    """Shard ``a``'s view: one inbound on ``a``, the shared outbounds each writing to its own
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
        pooled_sweep_interval=0.05,
        schedule_clock=lambda: _OUT_OF_WINDOW,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        assert {owned, foreign} <= runner._gate_parked  # the boot gate parked both, on every shard
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
        # The schedule goes: the owner resumes its lane, and this shard must not arm the other.
        await runner.reload(_registry(tmp_path, dests, auto_start=True, schedule=None))
        await asyncio.sleep(_CLAIM_WINDOW_SECONDS)
        (owned_row,) = await store.outbox_for(ids[owned])
        assert owned_row["status"] == "done"  # the control: the resume path is live here
        (foreign_row,) = await store.outbox_for(ids[foreign])
        assert foreign_row["status"] == "pending" and foreign_row["attempts"] == 0
        assert list((tmp_path / foreign).iterdir()) == []
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
        pooled_sweep_interval=0.05,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        message_id = await store.enqueue_message(
            channel_id="in_a", raw=ADT, deliveries=[(foreign, ADT)], now=_time.time()
        )
        async with runner._reload_lock:
            await runner._start_outbound_unsafe(foreign)
        await asyncio.sleep(_CLAIM_WINDOW_SECONDS)
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0
        assert list((tmp_path / foreign).iterdir()) == []
    finally:
        await runner.stop()
