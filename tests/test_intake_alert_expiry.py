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

import asyncio
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


async def test_the_sweep_runs_on_its_own_task_only_when_a_sink_is_wired(tmp_path: Path) -> None:
    """A stale subject can outlive the config that raised it, so the sweep task starts whenever a
    sink is wired, bounds on or off, and apart from the measuring task, so a slow sweep cannot
    delay a measurement. With no sink there is nothing to sweep for, and no task."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        sink = cast(AlertSink, NotifierAlertSink([], store=store))
        off = IntakeBoundMonitor(cast(Store, store), IntakeGate(), alert_sink=sink)
        on = IntakeBoundMonitor(
            cast(Store, store), IntakeGate(), max_staged_depth=10, alert_sink=sink
        )
        without = IntakeBoundMonitor(cast(Store, store), IntakeGate())
        assert not off.enabled and on.enabled and not without.enabled
        for monitor in (off, on, without):
            monitor.start()
        try:
            assert off._task is None and off._sweep_task is not None
            assert on._task is not None and on._sweep_task is not None
            assert on._task is not on._sweep_task
            assert without._task is None and without._sweep_task is None
        finally:
            for monitor in (off, on, without):
                await monitor.stop()
            await _drain(cast(NotifierAlertSink, sink))
        assert off._sweep_task is None and on._task is None and on._sweep_task is None
    finally:
        await store.close()


async def test_a_failed_read_changes_nothing_and_warns_once_per_streak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        stale = intake_alert_subject(DEPTH_REASON, "node:gone")
        await _raise_pause(store, stale)
        monitor = _sweeper(store, "node:a")
        assert await monitor.sweep_once() == 0
        real = store.open_alert_generations

        async def broken(**_kw: object) -> list[object]:
            raise RuntimeError("store unavailable")

        monkeypatch.setattr(store, "open_alert_generations", broken)
        clock[0] += STALE_SECONDS
        with caplog.at_level("WARNING", logger="messagefoundry.pipeline.intake_bound"):
            assert await monitor.sweep_once() == 0
            assert await monitor.sweep_once() == 0
            monkeypatch.setattr(store, "open_alert_generations", real)
            assert await _is_open(store, stale), "a failed read resolves nothing"
            assert await monitor.sweep_once() == 0, (
                "a failed read forgot the watch: the outage time does not count toward staleness"
            )
            clock[0] += STALE_SECONDS
            assert await monitor.sweep_once() == 1
            monkeypatch.setattr(store, "open_alert_generations", broken)
            assert await monitor.sweep_once() == 0
        failures = [r for r in caplog.records if "sweep: the read failed" in r.getMessage()]
        assert len(failures) == 2, "one WARNING per streak, and a good sweep ends the streak"
    finally:
        await store.close()


async def test_a_failed_resolve_does_not_stop_the_rest_of_the_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    clock = [1000.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        first = intake_alert_subject(DEPTH_REASON, "node:gone-1")
        second = intake_alert_subject(DEPTH_REASON, "node:gone-2")
        await _raise_pause(store, first)
        await _raise_pause(store, second)
        [stuck, _other] = await store.open_alert_generations(event_type="intake_paused")
        monitor = _sweeper(store, "node:a")
        assert await monitor.sweep_once() == 0
        real = store.resolve_alert_generation

        async def flaky(*, alert_id: int, through_count: int, now: float | None = None) -> int:
            if alert_id == stuck.id:
                raise RuntimeError("writer busy")
            return await real(alert_id=alert_id, through_count=through_count, now=now)

        monkeypatch.setattr(store, "resolve_alert_generation", flaky)
        clock[0] += STALE_SECONDS
        assert await monitor.sweep_once() == 1, "the second subject still expires"
        assert await _is_open(store, first) and not await _is_open(store, second)
        monkeypatch.setattr(store, "resolve_alert_generation", real)
        assert await monitor.sweep_once() == 1, "the failed one stayed watched and expires next"
        assert not await _is_open(store, first)
    finally:
        await store.close()


async def test_an_acknowledged_stale_subject_expires_too(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An acknowledged instance is still live, so it expires like an open one, as any other
    auto-resolve closes it."""
    from tests._store_audit import ALERT_AUDIT

    clock = [1000.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        stale = intake_alert_subject(DEPTH_REASON, "node:gone")
        await _raise_pause(store, stale)
        [gen] = await store.open_alert_generations(event_type="intake_paused")
        assert await store.ack_alert_instance(gen.id, actor="op", audit=ALERT_AUDIT)
        monitor = _sweeper(store, "node:a")
        assert await monitor.sweep_once() == 0
        clock[0] += STALE_SECONDS
        assert await monitor.sweep_once() == 1
        got = await store.get_alert_instance(gen.id, allowed_channels=None)
        assert got is not None and got.status == "resolved"
    finally:
        await store.close()


async def test_the_sqlite_store_keeps_the_generation_contract(tmp_path: Path) -> None:
    """The contract the Postgres and SQL Server suites run on their hosted legs."""
    from tests._alert_generation_contract import (
        check_alert_generation_contract,
        check_fenced_resolve_contract,
    )

    store = await MessageStore.open(tmp_path / "s.db")
    try:
        await check_alert_generation_contract(store)
        await check_fenced_resolve_contract(store)
    finally:
        await store.close()


async def test_a_cancelled_stop_still_opens_the_gate_and_passes_the_cancel_on(
    tmp_path: Path,
) -> None:
    """Review finding F8: stop() awaits the tasks it cancelled, and a cancel of stop()'s own caller
    arriving then is passed on, after the gate has opened, rather than swallowed."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        gate = IntakeGate()
        monitor = IntakeBoundMonitor(cast(Store, store), gate, max_staged_depth=10)
        gate.hold(DEPTH_REASON)
        release = asyncio.Event()

        async def slow_to_stop() -> None:
            try:
                await asyncio.Event().wait()
            finally:
                await asyncio.shield(release.wait())

        monitor._task = asyncio.ensure_future(slow_to_stop())
        await asyncio.sleep(0)
        stopping = asyncio.ensure_future(monitor.stop())
        await asyncio.sleep(0)
        stopping.cancel()
        await asyncio.sleep(0)
        release.set()
        with pytest.raises(asyncio.CancelledError):
            await stopping
        assert not gate.reasons, "the gate opened before the cancel went on"
    finally:
        await store.close()


async def test_a_check_that_raises_does_not_end_measuring(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Review finding F4: one raising check is logged, and the loop measures again."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        monitor = IntakeBoundMonitor(
            cast(Store, store), IntakeGate(), max_staged_depth=10, check_seconds=0.01
        )
        calls = 0

        async def flaky() -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("synthetic check defect")

        monkeypatch.setattr(monitor, "check_once", flaky)
        monitor.start()
        try:
            for _ in range(200):
                if calls >= 2:
                    break
                await asyncio.sleep(0.01)
        finally:
            await monitor.stop()
        assert calls >= 2
    finally:
        await store.close()
