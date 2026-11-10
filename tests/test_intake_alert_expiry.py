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
import logging
from collections.abc import Callable
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
                "the outage time does not count toward staleness"
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


async def test_a_cancel_taken_before_stop_is_not_raised_again(tmp_path: Path) -> None:
    """Review round 2: a caller that already took a cancel and goes on to stop the monitor in its
    cleanup does not get a second, spurious CancelledError from the tasks' own expected cancels."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        monitor = IntakeBoundMonitor(cast(Store, store), IntakeGate(), max_staged_depth=10)

        async def forever() -> None:
            await asyncio.Event().wait()

        async def cleanup_after_a_cancel() -> str:
            try:
                await forever()
            except asyncio.CancelledError:
                monitor._task = asyncio.ensure_future(forever())
                await asyncio.sleep(0)
                await monitor.stop()
                return "stopped"
            return "not reached"

        caller = asyncio.ensure_future(cleanup_after_a_cancel())
        await asyncio.sleep(0)
        caller.cancel()
        assert await caller == "stopped"
    finally:
        await store.close()


async def test_a_check_that_keeps_raising_logs_once_per_streak(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        monitor = IntakeBoundMonitor(
            cast(Store, store), IntakeGate(), max_staged_depth=10, check_seconds=0.01
        )
        calls = 0

        async def broken() -> None:
            nonlocal calls
            calls += 1
            raise RuntimeError("synthetic check defect")

        monkeypatch.setattr(monitor, "check_once", broken)
        with caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.intake_bound"):
            monitor.start()
            try:
                for _ in range(200):
                    if calls >= 4:
                        break
                    await asyncio.sleep(0.01)
            finally:
                await monitor.stop()
        assert calls >= 4
        assert sum("intake bound check raised" in r.getMessage() for r in caplog.records) == 1
    finally:
        await store.close()


async def test_a_cancel_passed_on_by_the_monitor_still_lets_the_engine_close_the_store(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-3 item 4: the monitor's stop passes a caller's cancel on. Engine.stop holds it until
    the alert-state drain and the store close have run, then raises it."""
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.engine import Engine

    engine = await Engine.create(
        tmp_path / "engine.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    await engine.start()
    assert engine._intake_monitor is not None
    real_monitor: IntakeBoundMonitor = engine._intake_monitor

    class _CancelledStop:
        async def stop(self) -> None:
            await real_monitor.stop()
            raise asyncio.CancelledError

    engine._intake_monitor = cast(IntakeBoundMonitor, _CancelledStop())
    closed: list[bool] = []
    real_close = engine.store.close

    async def close() -> None:
        closed.append(True)
        await real_close()

    monkeypatch.setattr(engine.store, "close", close)
    with pytest.raises(asyncio.CancelledError):
        await engine.stop()
    assert closed == [True], "the store closed before the cancel went on"
    assert engine._intake_monitor is None


@pytest.mark.parametrize("monitor_cancels", [True, False], ids=["cancel-deferred", "no-cancel"])
async def test_a_later_teardown_step_that_raises_still_closes_the_store(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    monitor_cancels: bool,
) -> None:
    """Round-4 item 2: the teardown after the monitor runs inside try/finally. The store closes
    even if a later step raises, and a cancel the monitor passed on is what Engine.stop raises."""
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.engine import Engine

    engine = await Engine.create(
        tmp_path / "engine.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    await engine.start()
    assert engine._intake_monitor is not None
    real_monitor: IntakeBoundMonitor = engine._intake_monitor

    class _MaybeCancelledStop:
        async def stop(self) -> None:
            await real_monitor.stop()
            if monitor_cancels:
                raise asyncio.CancelledError

    engine._intake_monitor = cast(IntakeBoundMonitor, _MaybeCancelledStop())
    real_drain = engine.drain_config_writes

    async def failing_drain(timeout: float) -> None:
        await real_drain(timeout)
        raise RuntimeError("synthetic teardown fault")

    monkeypatch.setattr(engine, "drain_config_writes", failing_drain)
    closed: list[bool] = []
    real_close = engine.store.close

    async def close() -> None:
        closed.append(True)
        await real_close()

    monkeypatch.setattr(engine.store, "close", close)
    expected: type[BaseException] = asyncio.CancelledError if monitor_cancels else RuntimeError
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.engine"),
        pytest.raises(expected),
    ):
        await engine.stop()
    assert closed == [True], "the store closed although a later teardown step raised"
    logged = any("failed after the stop was cancelled" in r.getMessage() for r in caplog.records)
    assert logged is monitor_cancels, "the error the cancel replaces is logged, and only then"


async def test_one_failed_read_costs_a_watch_only_that_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Lander hold on engine PR 2863, item 4: a failed read cleared every watch, so one transient
    failure threw away all the staleness already counted. It now keeps the watch and discounts
    the gap from the last good read to the next one, and holds what it counted to 380 s short of
    stale (the grace, pinned here as a number), so a live process's next reminder can land."""
    clock = [1000.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        stale = intake_alert_subject(DEPTH_REASON, "node:gone")
        await _raise_pause(store, stale)
        monitor = _sweeper(store, "node:a")
        assert await monitor.sweep_once() == 0  # watched from t=1000
        clock[0] += STALE_SECONDS - 10
        assert await monitor.sweep_once() == 0  # S-10 counted
        real = store.open_alert_generations

        async def broken(**_kw: object) -> list[object]:
            raise RuntimeError("store unavailable")

        monkeypatch.setattr(store, "open_alert_generations", broken)
        clock[0] += 5
        assert await monitor.sweep_once() == 0
        monkeypatch.setattr(store, "open_alert_generations", real)
        clock[0] += 5
        assert await monitor.sweep_once() == 0, "the 10s gap around the failure is not counted"
        assert await _is_open(store, stale)
        clock[0] += 379
        assert await monitor.sweep_once() == 0, "the watch is held to 380 s short of stale"
        clock[0] += 1
        assert await monitor.sweep_once() == 1, (
            "the S-380 kept across the failure still counts: the watch was not cleared"
        )
    finally:
        await store.close()


async def test_a_store_close_that_raises_does_not_replace_the_deferred_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Lander hold on engine PR 2863, item 4: with a cancel deferred from the monitor's stop, a
    store close that raised propagated in its place, so the caller never saw its cancel."""
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.engine import Engine

    engine = await Engine.create(
        tmp_path / "engine.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    await engine.start()
    assert engine._intake_monitor is not None
    real_monitor: IntakeBoundMonitor = engine._intake_monitor

    class _CancelledStop:
        async def stop(self) -> None:
            await real_monitor.stop()
            raise asyncio.CancelledError

    engine._intake_monitor = cast(IntakeBoundMonitor, _CancelledStop())
    real_close = engine.store.close

    async def failing_close() -> None:
        await real_close()
        raise RuntimeError("synthetic close fault")

    monkeypatch.setattr(engine.store, "close", failing_close)
    with (
        caplog.at_level(logging.ERROR, logger="messagefoundry.pipeline.engine"),
        pytest.raises(asyncio.CancelledError),
    ):
        await engine.stop()
    assert any(
        "store close failed after the stop was cancelled" in r.getMessage() for r in caplog.records
    ), "the close error the cancel replaces is logged"


async def _sweep_schedule(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    *,
    fails: Callable[[float], bool],
    raises_at: tuple[float, ...] = (),
    until: float,
) -> float | None:
    """Sweep ``node:gone``'s subject every 60 s from t=30 until ``until``, with the read failing
    at each sweep time ``fails`` names and the subject's own process raising at ``raises_at``.
    Returns when the sweep resolved it, or None."""
    clock = [0.0]
    monkeypatch.setattr(intake_bound, "_monotonic", lambda: clock[0])
    subject = intake_alert_subject(DEPTH_REASON, "node:gone")
    await _raise_pause(store, subject)
    monitor = _sweeper(store, "node:a")
    real = store.open_alert_generations

    async def broken(**_kw: object) -> list[object]:
        raise RuntimeError("store unavailable")

    pending = sorted(raises_at)
    t = 30.0
    while t <= until:
        while pending and pending[0] <= t:
            await _raise_pause(store, subject)
            pending.pop(0)
        clock[0] = t
        monkeypatch.setattr(store, "open_alert_generations", broken if fails(t) else real)
        if await monitor.sweep_once():
            return t
        t += 60.0
    return None


async def test_flapping_reads_still_expire_a_dead_subject(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The grace is held, not stacked (the review of d148527dbe): with one failed read in every
    ten sweeps a dead subject expires, by t=1650 here against t=1230 with no failure. Stacked
    graces never expired it at all."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        never = await _sweep_schedule(store, monkeypatch, fails=lambda t: False, until=5000)
        assert never == 1230.0
    finally:
        await store.close()
    store = await MessageStore.open(tmp_path / "f.db")
    try:
        flapping = await _sweep_schedule(
            store, monkeypatch, fails=lambda t: int((t - 30) // 60) % 10 == 9, until=86400
        )
        assert flapping is not None and flapping <= 1650.0, flapping
    finally:
        await store.close()


async def test_a_live_alert_survives_an_outage_that_ate_its_reminder(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The review of 37215543de: the subject's process raises at 0, its reminders at 300, 600 and
    900 fail on its side, an outage from 1150 to 1250 fails the sweeper's reads and eats the 1200
    one, and its 1500 reminder lands. With the watch kept but no grace, the sweep resolved it at
    t=1410, while the process was still paused."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        resolved = await _sweep_schedule(
            store,
            monkeypatch,
            fails=lambda t: 1150 <= t <= 1250,
            raises_at=(1500.0, 1800.0, 2100.0),
            until=2200,
        )
        assert resolved is None, f"a live alert expired at t={resolved}"
    finally:
        await store.close()


async def _started_engine(tmp_path: Path) -> object:
    from messagefoundry.config.settings import EgressSettings
    from messagefoundry.pipeline.engine import Engine

    engine = await Engine.create(
        tmp_path / "engine.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    await engine.start()
    return engine


@pytest.mark.parametrize(
    ("step_raises", "expected"),
    [
        (None, RuntimeError),
        (asyncio.CancelledError, asyncio.CancelledError),
        (KeyboardInterrupt, KeyboardInterrupt),
    ],
    ids=["close-raises-no-cancel", "later-step-cancelled", "later-step-interrupt"],
)
async def test_engine_stop_keeps_the_right_exception_when_the_close_also_raises(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    step_raises: type[BaseException] | None,
    expected: type[BaseException],
) -> None:
    """The review of 37215543de: a raising close replaced a cancel from a later step, and a cancel
    deferred from the monitor swallowed a KeyboardInterrupt. A close that raises with nothing
    pending still propagates its own error."""
    from messagefoundry.pipeline.engine import Engine

    engine = cast(Engine, await _started_engine(tmp_path))
    real_drain = engine.drain_config_writes

    async def drain(timeout: float) -> None:
        await real_drain(timeout)
        if step_raises is not None:
            raise step_raises

    monkeypatch.setattr(engine, "drain_config_writes", drain)
    real_close = engine.store.close
    closed: list[bool] = []

    async def failing_close() -> None:
        await real_close()
        closed.append(True)
        raise RuntimeError("synthetic close fault")

    monkeypatch.setattr(engine.store, "close", failing_close)
    with pytest.raises(expected):
        await engine.stop()
    assert closed == [True], "the store closed whatever the later step raised"
