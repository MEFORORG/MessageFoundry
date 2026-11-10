# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An intake alert whose process label never returns expires (BACKLOG #3269).

Each engine process raises ``intake:<reason>@<process>`` about its own gate, so a subject whose
process is gone for good has nobody to clear it. Every monitor with a sink sweeps the open
``intake_paused`` instances of other processes and resolves one that has taken no raise for
``STALE_SECONDS`` of its own clock. One test per way a label goes away, and a live-label control
that keeps reminding and stays open.
"""

from __future__ import annotations

from pathlib import Path
from typing import cast

import pytest

from messagefoundry.pipeline import intake_bound
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import AlertSink
from messagefoundry.pipeline.intake_bound import (
    DEPTH_REASON,
    STALE_SECONDS,
    IntakeBoundMonitor,
    intake_alert_subject,
)
from messagefoundry.store import MessageStore, Store
from messagefoundry.transports.base import IntakeGate
from tests.test_alert_state import _drain
from tests.test_intake_pause import _FakeStore


async def _raise_pause(store: MessageStore, subject: str) -> None:
    """What a paused process leaves behind: one open ``intake_paused`` instance under its subject."""
    sink = NotifierAlertSink([], store=store)
    sink.intake_paused(subject, reason=DEPTH_REASON, value=11, limit=10, store_kind="sqlite")
    await _drain(sink)


async def _is_open(store: MessageStore, subject: str) -> bool:
    rows = await store.open_alert_generations(event_type="intake_paused", connection=subject)
    return bool(rows)


def _sweeper(store: MessageStore, node: str | None) -> IntakeBoundMonitor:
    """A live process's monitor: its own depth is fine, and it sweeps the shared store."""
    return IntakeBoundMonitor(
        cast(Store, store),
        IntakeGate(),
        max_staged_depth=10,
        alert_sink=cast(AlertSink, NotifierAlertSink([], store=store)),
        node=node,
    )


@pytest.mark.parametrize(
    ("gone", "live"),
    [
        pytest.param("node:host:111:aaaa", "node:host:222:bbbb", id="unpinned-node-crashed-paused"),
        pytest.param(None, "shard:0", id="lone-engine-became-engine-shards"),
        pytest.param("shard:2", "shard:0", id="engine-shard-count-shrank"),
        pytest.param("node:old-name", "node:new-name", id="node-id-renamed"),
    ],
)
async def test_a_subject_whose_label_never_returns_expires(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gone: str | None, live: str
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        stale = intake_alert_subject(DEPTH_REASON, gone)
        await _raise_pause(store, stale)
        monitor = _sweeper(store, live)
        assert await monitor.sweep_once() == 0, "the first sweep only starts watching"
        clock[0] += STALE_SECONDS - 1
        assert await monitor.sweep_once() == 0
        assert await _is_open(store, stale), "not stale yet"
        clock[0] += 1
        assert await monitor.sweep_once() == 1
        assert not await _is_open(store, stale), "nobody raised it for STALE_SECONDS: expired"
    finally:
        await store.close()


async def test_a_live_paused_subject_keeps_reminding_and_stays_open(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The control: a paused process that is alive raises a reminder every REALERT_SECONDS, which
    moves its count, so another process's sweep never finds it stale. The sweeper's own subject is
    not its to expire either."""
    clock = [1000.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        paused_sink = NotifierAlertSink([], store=store)
        paused = IntakeBoundMonitor(
            cast(Store, _FakeStore(depth=50)),
            IntakeGate(),
            max_staged_depth=10,
            alert_sink=cast(AlertSink, paused_sink),
            node="node:b",
        )
        live = intake_alert_subject(DEPTH_REASON, "node:b")
        own = intake_alert_subject(DEPTH_REASON, "node:a")
        await _raise_pause(store, own)
        sweeper = _sweeper(store, "node:a")
        step = 60.0
        elapsed = 0.0
        while elapsed <= 3 * STALE_SECONDS:
            await paused.check_once()
            await _drain(paused_sink)
            assert await sweeper.sweep_once() == 0
            clock[0] += step
            elapsed += step
        assert await _is_open(store, live), "a reminding subject is live and stays open"
        assert await _is_open(store, own), "a monitor never expires its own subject"
    finally:
        await store.close()


async def test_a_raise_between_the_read_and_the_resolve_keeps_the_row_open(
    tmp_path: Path,
) -> None:
    """The resolve is bounded by the count it read, with no clock: a raise that lands first moves
    the count past the bound, so the row stays open."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        subject = intake_alert_subject(DEPTH_REASON, "node:x")
        await _raise_pause(store, subject)
        [seen] = await store.open_alert_generations(event_type="intake_paused")
        await _raise_pause(store, subject)  # a reminder lands after the read
        assert await store.resolve_alert_generation(alert_id=seen.id, through_count=seen.count) == 0
        assert await _is_open(store, subject)
        [now] = await store.open_alert_generations(event_type="intake_paused")
        assert (now.id, now.count) == (seen.id, seen.count + 1)
        assert await store.resolve_alert_generation(alert_id=now.id, through_count=now.count) == 1
        assert not await _is_open(store, subject)
    finally:
        await store.close()


async def test_the_sweep_runs_with_both_bounds_off_only_when_a_sink_is_wired(
    tmp_path: Path,
) -> None:
    """A stale subject can outlive the config that raised it, so the sweep task starts whenever a
    sink is wired. With no sink there is nothing to sweep for, and no task."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        with_sink = IntakeBoundMonitor(
            cast(Store, store),
            IntakeGate(),
            alert_sink=cast(AlertSink, NotifierAlertSink([], store=store)),
        )
        without = IntakeBoundMonitor(cast(Store, store), IntakeGate())
        assert not with_sink.enabled and not without.enabled
        with_sink.start()
        without.start()
        try:
            assert with_sink._task is not None
            assert without._task is None
        finally:
            await with_sink.stop()
            await without.stop()
    finally:
        await store.close()


async def test_a_failed_sweep_changes_nothing_and_warns_once(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        monitor = _sweeper(store, "node:a")

        async def broken(**_kw: object) -> list[object]:
            raise RuntimeError("store unavailable")

        monkeypatch.setattr(store, "open_alert_generations", broken)
        with caplog.at_level("WARNING", logger="messagefoundry.pipeline.intake_bound"):
            assert await monitor.sweep_once() == 0
            assert await monitor.sweep_once() == 0
        assert sum("sweep failed" in r.getMessage() for r in caplog.records) == 1
    finally:
        await store.close()


async def test_the_sqlite_store_keeps_the_generation_contract(tmp_path: Path) -> None:
    """The contract the Postgres and SQL Server suites run on their hosted legs."""
    from tests._alert_generation_contract import check_alert_generation_contract

    store = await MessageStore.open(tmp_path / "s.db")
    try:
        await check_alert_generation_contract(store)
    finally:
        await store.close()
