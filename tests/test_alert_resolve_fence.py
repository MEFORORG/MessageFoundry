# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An auto-resolve cannot close a newer raise of its key from another process (BACKLOG #4916).

Two writers share one real SQLite store, as two engine shards or nodes would. Writer A's clear is
held back, as the per-key FIFO and the retry backoff hold one back; writer B raises the same key in
the window. Unfenced, A's late clear closes B's raise. The fence closes the instance only when its
newest raise is A's own (#2272 defect 8) or it took no raise past A's snapshot, and compares no
clock, so clock skew cannot leave an alert open for good.
"""

from __future__ import annotations

import asyncio
import logging
import time
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.store import MessageStore
from tests.test_alert_state import _drain

KEY = "intake:staged_depth@node:a"
_FENCED = "resolve_alert_instances_fenced"


class _Gated:
    """One writer's view of the shared store. A named method can be held at a gate, hidden, or
    counted; ``returned[name]`` is set once a call to it has returned."""

    def __init__(self, inner: MessageStore) -> None:
        self._inner = inner
        self.gates: dict[str, asyncio.Event] = {}
        self.hidden: set[str] = set()
        self.returned: dict[str, asyncio.Event] = {}
        self.calls: dict[str, int] = {}

    def __getattr__(self, name: str) -> Any:
        if name in self.hidden:
            raise AttributeError(name)
        attr = getattr(self._inner, name)
        if not callable(attr):
            return attr
        gate = self.gates.get(name)
        done = self.returned.setdefault(name, asyncio.Event())

        async def wrapped(*args: Any, **kwargs: Any) -> Any:
            self.calls[name] = self.calls.get(name, 0) + 1
            if gate is not None:
                await gate.wait()
            try:
                return await attr(*args, **kwargs)
            finally:
                done.set()

        return wrapped

    def gate(self, name: str) -> asyncio.Event:
        self.returned[name] = asyncio.Event()  # only a call made from here on sets it
        self.gates[name] = asyncio.Event()
        return self.gates[name]

    async def wait_returned(self, name: str) -> None:
        await asyncio.wait_for(self.returned.setdefault(name, asyncio.Event()).wait(), 5.0)
        self.returned[name] = asyncio.Event()


def _raise(sink: NotifierAlertSink) -> None:
    sink.intake_paused(KEY, reason="staged_depth", value=11, limit=10, store_kind="sqlite")


def _clear(sink: NotifierAlertSink) -> None:
    sink.intake_resumed(KEY, reason="staged_depth", value=0, limit=10, store_kind="sqlite")


async def _live(store: MessageStore) -> list[tuple[int, int]]:
    return [
        (g.id, g.count)
        for g in await store.open_alert_generations(event_type="intake_paused", connection=KEY)
    ]


@pytest.mark.parametrize("other_raises", [True, False], ids=["other-node-raises", "control"])
async def test_a_held_back_clear_does_not_close_a_raise_that_landed_while_it_waited(
    tmp_path: Path, other_raises: bool
) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        a = NotifierAlertSink([], store=view_a)
        b = NotifierAlertSink([], store=store)
        _raise(a)
        await _drain(a)
        gate = view_a.gate(_FENCED)
        _clear(a)  # emitted now; its write waits at the gate, as behind a slow write or a retry
        await view_a.wait_returned("open_alert_generations")  # the snapshot
        if other_raises:
            _raise(b)
            await _drain(b)
        gate.set()
        await _drain(a)
        if other_raises:
            [(_id, count)] = await _live(store)
            assert count == 2, "B's raise, which landed after A's snapshot, stays open"
            _clear(b)
            await _drain(b)
            assert await _live(store) == [], "B's own clear then closes B's raise"
        else:
            assert await _live(store) == [], "the control: with no newer raise, the clear closes it"
    finally:
        await store.close()


async def test_unfenced_the_same_held_back_clear_closes_the_newer_raise(tmp_path: Path) -> None:
    """The race itself, on the path every store took before the fence: a store without the
    fence methods resolves by key alone, and B's newer raise is closed."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        view_a.hidden = {"open_alert_generations", _FENCED}
        a = NotifierAlertSink([], store=view_a)
        b = NotifierAlertSink([], store=store)
        _raise(a)
        await _drain(a)
        gate = view_a.gate("resolve_alert_instances_for")
        _clear(a)
        await asyncio.sleep(0)
        _raise(b)
        await _drain(b)
        gate.set()
        await _drain(a)
        assert await _live(store) == [], "unfenced, the late clear closed B's newer raise"
    finally:
        await store.close()


@pytest.mark.parametrize("other_raises", [True, False], ids=["other-node-raises", "control"])
async def test_an_own_raise_emitted_before_the_clear_is_still_closed_by_it(
    tmp_path: Path, other_raises: bool
) -> None:
    """#2272 defect 8: A raises, then clears, and the raise is slow, so it lands after the clear's
    snapshot. The clear still closes it, since its newest raise is A's own. A raise from B that
    lands after A's raise and before A's clear runs is not A's to close, and keeps it open."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        a = NotifierAlertSink([], store=view_a)
        b = NotifierAlertSink([], store=store)
        _raise(a)
        await _drain(a)
        upsert = view_a.gate("upsert_alert_instance")
        resolve = view_a.gate(_FENCED)
        _raise(a)  # slow: it holds the key's lock, so the clear queues behind it
        _clear(a)
        await view_a.wait_returned("open_alert_generations")
        upsert.set()
        await view_a.wait_returned("upsert_alert_instance")
        if other_raises:
            _raise(b)
            await _drain(b)
        resolve.set()
        await _drain(a)
        if other_raises:
            [(_id, count)] = await _live(store)
            assert count == 3, "A's two raises and B's one; B's is the newest"
        else:
            assert await _live(store) == [], "A's own late raise came before its clear"
    finally:
        await store.close()


@pytest.mark.parametrize("b_lands_last", [True, False], ids=["b-newest", "a-newest"])
async def test_two_processes_raising_and_clearing_at_once_do_not_leave_it_open(
    tmp_path: Path, b_lands_last: bool
) -> None:
    """Review finding F1: both raise and both clear the key at once, each raise slow enough to land
    after both clears' snapshots. Whichever raise lands last, its writer's clear closes it."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a, view_b = _Gated(store), _Gated(store)
        a = NotifierAlertSink([], store=view_a)
        b = NotifierAlertSink([], store=view_b)
        up_a, up_b = view_a.gate("upsert_alert_instance"), view_b.gate("upsert_alert_instance")
        _raise(a)
        _clear(a)
        _raise(b)
        _clear(b)
        await view_a.wait_returned("open_alert_generations")
        await view_b.wait_returned("open_alert_generations")
        first, second = (up_a, up_b) if b_lands_last else (up_b, up_a)
        first_view = view_a if b_lands_last else view_b
        first.set()
        await first_view.wait_returned("upsert_alert_instance")
        second.set()
        await _drain(a)
        await _drain(b)
        assert await _live(store) == []
    finally:
        await store.close()


async def test_a_clear_whose_clock_runs_behind_the_raise_still_closes_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refuted ``last_seen <= now`` guard would leave this open for good: the raise was stamped
    by a clock a day ahead of the clearing process's. The fence reads no clock."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        a = NotifierAlertSink([], store=store)
        b = NotifierAlertSink([], store=store)
        real = time.time
        monkeypatch.setattr(time, "time", lambda: real() + 86400.0)
        _raise(b)
        await _drain(b)
        monkeypatch.setattr(time, "time", real)
        _clear(a)
        await _drain(a)
        assert await _live(store) == []
    finally:
        await store.close()


async def test_a_superseded_clear_settles_as_not_landed_and_is_not_retried(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Review finding F3: a zero-row resolve with a live instance left is not reported as landed,
    so connection_started's in-memory clear goes back; nor is it retried or logged as given up."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        a = NotifierAlertSink([], store=view_a)
        b = NotifierAlertSink([], store=store)
        _raise(a)
        await _drain(a)
        gate = view_a.gate(_FENCED)
        settled: list[bool] = []
        with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.alert_sinks"):
            a._record_state(
                {"type": "intake_resumed", "connection": KEY}, "info", on_settled=settled.append
            )
            await view_a.wait_returned("open_alert_generations")
            _raise(b)
            await _drain(b)
            gate.set()
            await _drain(a)
        assert settled == [False]
        assert view_a.calls[_FENCED] == 1, "a superseded clear is not retried"
        assert any("does not speak for" in r.getMessage() for r in caplog.records)
        assert not any("assuming" in r.getMessage() for r in caplog.records), (
            "observed, not assumed"
        )
        assert not any(r.levelno >= logging.ERROR for r in caplog.records)
        [(_id, count)] = await _live(store)
        assert count == 2
    finally:
        await store.close()


async def test_a_clear_with_nothing_open_settles_as_landed(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        a = NotifierAlertSink([], store=store)
        settled: list[bool] = []
        a._record_state(
            {"type": "intake_resumed", "connection": KEY}, "info", on_settled=settled.append
        )
        await _drain(a)
        assert settled == [True]
    finally:
        await store.close()


class _FlakySnapshot(_Gated):
    """A view whose first ``fail`` reads of the key raise, as a transient borrow timeout would."""

    def __init__(self, inner: MessageStore, fail: int) -> None:
        super().__init__(inner)
        self.fail = fail
        self.reads = 0

    def __getattr__(self, name: str) -> Any:
        if name == "open_alert_generations":

            async def read(**kw: Any) -> Any:
                self.reads += 1
                if self.reads <= self.fail:
                    raise RuntimeError("synthetic: store unavailable")
                return await self._inner.open_alert_generations(**kw)

            return read
        return super().__getattr__(name)


async def test_a_restart_and_a_transient_snapshot_failure_still_close_the_old_runs_alert(
    tmp_path: Path,
) -> None:
    """Round-c69a5607 item a: an earlier run of this process (another writer id) raised the key.
    The first clear after the restart fails its snapshot read once. That attempt fails, the retry
    reads again, and the clear closes the earlier run's alert."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        earlier_run = NotifierAlertSink([], store=store)
        _raise(earlier_run)
        await _drain(earlier_run)
        view = _FlakySnapshot(store, fail=1)
        restarted = NotifierAlertSink([], store=view)
        _clear(restarted)
        await _drain(restarted)
        assert view.reads >= 2, "the retry read the snapshot again"
        assert await _live(store) == []
    finally:
        await store.close()


@pytest.mark.parametrize("other_raised_last", [False, True], ids=["own-raise", "other-raise"])
async def test_a_snapshot_that_never_reads_gives_up_and_closes_nothing(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, other_raised_last: bool
) -> None:
    """With every read failing, each attempt fails, the resolve gives up as any failed resolve
    does, and nothing is closed unfenced: another process's newer raise is never this clear's."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        a = NotifierAlertSink([], store=store)
        b = NotifierAlertSink([], store=store)
        _raise(a)
        await _drain(a)
        if other_raised_last:
            _raise(b)
            await _drain(b)
        view = _FlakySnapshot(store, fail=99)
        a._store = view
        settled: list[bool] = []
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alert_sinks"):
            a._record_state(
                {"type": "intake_resumed", "connection": KEY}, "info", on_settled=settled.append
            )
            await _drain(a)
        assert settled == [False]
        assert len(await _live(store)) == 1
        assert any("gave up" in r.getMessage() for r in caplog.records)
        assert view.calls.get(_FENCED) is None, "no UPDATE runs without a snapshot"
    finally:
        await store.close()


async def test_a_failed_first_clear_does_not_restore_state_a_second_clear_then_closed(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Round-c69a5607 item b: the second clear drops nothing (the first already took the suspend
    and the count), but it is queued all the same. When the first clear's resolve gives up, the
    second takes its state over, and once it closes the row nothing comes back."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        a = NotifierAlertSink([], store=store)
        monkeypatch.setattr(a, "_INVERSE_RETRY_DELAYS", (0.0,))
        key = f"intake_paused:{KEY}"
        _raise(a)
        _raise(a)
        await _drain(a)
        a._suspended[key] = time.time() + 3600.0
        real = store.resolve_alert_instances_fenced
        failures = [RuntimeError("synthetic: locked"), RuntimeError("synthetic: locked")]

        async def failing_first(**kw: Any) -> int:
            if failures:
                raise failures.pop()
            return await real(**kw)

        monkeypatch.setattr(store, "resolve_alert_instances_fenced", failing_first)
        _clear(a)  # both of its attempts fail
        _clear(a)  # drops nothing; lands
        await _drain(a)
        assert await _live(store) == []
        assert key not in a._suspended, "the closed row's suspend did not come back"
        assert key not in a._occurrences, "nor its occurrence count"
        assert key not in a._pending_clears
    finally:
        await store.close()


async def test_a_clear_with_nothing_open_reads_twice_and_settles_its_queued_state(
    tmp_path: Path,
) -> None:
    """Every inverse queues the state it dropped (round-c69a5607 item b), so each one settles, and
    one that closes nothing pays for the verdict re-read: the snapshot, the UPDATE and one more
    read. With nothing live, it settles as landed and its queue entry goes."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        a = NotifierAlertSink([], store=view_a)
        _clear(a)
        await _drain(a)
        assert view_a.calls.get("open_alert_generations") == 2
        assert view_a.calls.get(_FENCED) == 1
        assert f"intake_paused:{KEY}" not in a._pending_clears
    finally:
        await store.close()


async def test_a_superseded_clear_gives_back_the_suspend_and_occurrence_count(
    tmp_path: Path,
) -> None:
    """Round-3 item 1: an inverse drops the key's suspend window and occurrence count as it is
    emitted. A superseded resolve leaves the row open, so both go back, and a later raise is still
    muted by the operator's suspend and counts on from where it was."""
    from tests.test_alert_sinks import _RecordingTransport

    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        sent = _RecordingTransport("rec")
        a = NotifierAlertSink([sent], store=view_a)
        b = NotifierAlertSink([], store=store)
        a.start()
        key = f"intake_paused:{KEY}"
        _raise(a)
        _raise(a)
        await _drain(a)
        a._suspended[key] = time.time() + 3600.0  # an operator's suspend, as the API route sets it
        gate = view_a.gate(_FENCED)
        _clear(a)
        assert key not in a._suspended, "the clear drops the suspend as it is emitted"
        await view_a.wait_returned("open_alert_generations")
        _raise(b)
        await _drain(b)
        gate.set()
        await _drain(a)
        assert key in a._suspended, "the superseded clear gave the suspend back"
        assert a._occurrences[key] == 2, "and the occurrence count"
        await asyncio.sleep(0.05)
        before = len(sent.events)
        _raise(a)
        await _drain(a)
        await asyncio.sleep(0.05)
        assert len(sent.events) == before, "the operator's suspend still mutes the next raise"
        assert a._occurrences[key] == 3, "the escalation count goes on from where it was"
        await a.aclose()
    finally:
        await store.close()


async def test_a_clear_that_closes_the_row_keeps_the_suspend_dropped(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        a = NotifierAlertSink([], store=store)
        key = f"intake_paused:{KEY}"
        _raise(a)
        await _drain(a)
        a._suspended[key] = time.time() + 3600.0
        _clear(a)
        await _drain(a)
        assert await _live(store) == []
        assert key not in a._suspended and key not in a._occurrences
        assert key not in a._pending_clears
    finally:
        await store.close()


async def test_a_failed_verdict_re_read_is_not_retried_and_logs_no_error(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Round-3 item 3: the fenced UPDATE has committed when the re-read runs, so a fault there is
    not a failed resolve: no retry, no "gave up" ERROR, and the cleared state is kept."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        reads = 0

        class _ReReadFails(_Gated):
            def __getattr__(self, name: str) -> Any:
                if name == "open_alert_generations":

                    async def read(**kw: Any) -> Any:
                        nonlocal reads
                        reads += 1
                        if reads > 1:
                            raise RuntimeError("store unavailable")
                        return await store.open_alert_generations(**kw)

                    return read
                return super().__getattr__(name)

        view_a = _ReReadFails(store)
        a = NotifierAlertSink([], store=view_a)
        settled: list[bool] = []
        with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.alert_sinks"):
            a._record_state(
                {"type": "intake_resumed", "connection": KEY}, "info", on_settled=settled.append
            )
            await _drain(a)
        assert reads == 2
        assert view_a.calls[_FENCED] == 1, "not retried"
        assert settled == [False], "not knowing, the clear is kept as not landed"
        assert not any(r.levelno >= logging.ERROR for r in caplog.records)
        assert any("re-read failed" in r.getMessage() for r in caplog.records)
        assert not any("does not speak for" in r.getMessage() for r in caplog.records), (
            "round-4 item 4: an assumed superseded is not logged as an observed one"
        )
    finally:
        await store.close()
