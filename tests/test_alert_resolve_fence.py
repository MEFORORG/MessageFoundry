# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An auto-resolve cannot close a newer raise of its key from another process (BACKLOG #4916).

Two writers share one real SQLite store, as two engine shards or nodes would. Writer A's clear is
held back, as the per-key FIFO and the retry backoff hold one back; writer B raises the same key in
the window. Unfenced, A's late clear closes B's raise. The fence bounds the clear to the ``(id,
count)`` the key had when the clear was emitted, plus A's own raises emitted before it (#2272 defect
8), and compares no clock, so clock skew cannot leave an alert open for good.
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


class _Gated:
    """One writer's view of the shared store: a named method can be held at a gate, or hidden."""

    def __init__(self, inner: MessageStore) -> None:
        self._inner = inner
        self.gates: dict[str, asyncio.Event] = {}
        self.hidden: set[str] = set()

    def __getattr__(self, name: str) -> Any:
        if name in self.hidden:
            raise AttributeError(name)
        attr = getattr(self._inner, name)
        gate = self.gates.get(name)
        if gate is None:
            return attr

        async def gated(*args: Any, **kwargs: Any) -> Any:
            await gate.wait()
            return await attr(*args, **kwargs)

        return gated


def _raise(sink: NotifierAlertSink) -> None:
    sink.intake_paused(KEY, reason="staged_depth", value=11, limit=10, store_kind="sqlite")


def _clear(sink: NotifierAlertSink) -> None:
    sink.intake_resumed(KEY, reason="staged_depth", value=0, limit=10, store_kind="sqlite")


async def _live(store: MessageStore) -> list[tuple[int, int]]:
    return [
        (g.id, g.count)
        for g in await store.open_alert_generations(event_type="intake_paused", connection=KEY)
    ]


async def _let_the_snapshot_land() -> None:
    # The clear's snapshot read runs on aiosqlite's thread; give it real time, not just a tick.
    await asyncio.sleep(0.2)


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
        gate = view_a.gates["resolve_alert_generation"] = asyncio.Event()
        _clear(a)  # emitted now; its write waits at the gate, as behind a slow write or a retry
        await _let_the_snapshot_land()
        if other_raises:
            _raise(b)
            await _drain(b)
        gate.set()
        await _drain(a)
        if other_raises:
            [(alert_id, count)] = await _live(store)
            assert count == 2, "B's raise, which landed after A's clear was emitted, stays open"
        else:
            assert await _live(store) == [], "the control: with no newer raise, the clear closes it"
    finally:
        await store.close()


async def test_unfenced_the_same_held_back_clear_closes_the_newer_raise(tmp_path: Path) -> None:
    """The race itself, on the path every store took before the fence: a store without the
    generation methods resolves by key alone, and B's newer raise is closed."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        view_a.hidden = {"open_alert_generations", "resolve_alert_generation"}
        a = NotifierAlertSink([], store=view_a)
        b = NotifierAlertSink([], store=store)
        _raise(a)
        await _drain(a)
        gate = view_a.gates["resolve_alert_instances_for"] = asyncio.Event()
        _clear(a)
        await _let_the_snapshot_land()
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
    snapshot. The clear still closes it. A raise from B that lands in the same window is not A's
    to close, and keeps the row open."""
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        a = NotifierAlertSink([], store=view_a)
        b = NotifierAlertSink([], store=store)
        _raise(a)
        await _drain(a)
        gate = view_a.gates["upsert_alert_instance"] = asyncio.Event()
        _raise(a)  # slow: it holds the key's lock, so the clear queues behind it
        _clear(a)
        await _let_the_snapshot_land()
        if other_raises:
            _raise(b)
            await _drain(b)
        gate.set()
        await _drain(a)
        if other_raises:
            [(_id, count)] = await _live(store)
            assert count == 3, "A's two raises and B's one; B's landed after the clear"
        else:
            assert await _live(store) == [], "A's own late raise came before its clear"
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


async def test_a_failed_snapshot_resolves_unfenced_and_says_so(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        view_a = _Gated(store)
        a = NotifierAlertSink([], store=view_a)
        _raise(a)
        await _drain(a)

        class _Broken(_Gated):
            def __getattr__(self, name: str) -> Any:
                if name == "open_alert_generations":

                    async def broken(**_kw: Any) -> Any:
                        raise RuntimeError("store unavailable")

                    return broken
                return super().__getattr__(name)

        a._store = _Broken(store)
        with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.alert_sinks"):
            _clear(a)
            await _drain(a)
        assert await _live(store) == [], "the behaviour before the fence, not a weaker one"
        assert any("resolving unfenced" in r.getMessage() for r in caplog.records)
        assert a._raise_watchers == {}, "the fence unregistered its collector"
    finally:
        await store.close()


async def test_an_upsert_returns_the_generation_it_left(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "s.db")
    try:
        first = await store.upsert_alert_instance(
            event_type="intake_paused", connection=KEY, severity="warning"
        )
        second = await store.upsert_alert_instance(
            event_type="intake_paused", connection=KEY, severity="warning"
        )
        assert (second.id, second.count) == (first.id, 2)
        assert await _live(store) == [(first.id, 2)]
    finally:
        await store.close()
