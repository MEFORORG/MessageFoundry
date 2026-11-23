# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Two overlapping loads of one reference set write in start order (BACKLOG #5892).

The stores here are real SQLite. Only the source read is scripted, so a test can hold one load
between its read and its write while another runs."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import DatabaseRef, ReferenceSpec
from messagefoundry.pipeline import reference_sync
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.store.store import MessageStore

_EGRESS = EgressSettings(deny_by_default=False)
_BOUND = 5.0  # a hang fails the test rather than the run


def _spec(name: str, server: str = "db.example.test") -> ReferenceSpec:
    return ReferenceSpec(
        name=name,
        source=DatabaseRef(
            server=server,
            database="refdb",
            statement="SELECT k, v FROM t",
            key_column="k",
            value_column="v",
        ),
    )


class _Read:
    """One scripted source read: it reports entry, waits for release, then returns or raises."""

    def __init__(self, rows: dict[str, Any] | None = None, error: Exception | None = None) -> None:
        self.rows = rows
        self.error = error
        self.entered = asyncio.Event()
        self.release = asyncio.Event()

    async def run(self) -> dict[str, Any]:
        self.entered.set()
        await self.release.wait()
        if self.error is not None:
            raise self.error
        assert self.rows is not None
        return self.rows


def _script(monkeypatch: pytest.MonkeyPatch, reads: dict[str, list[_Read]]) -> None:
    """Answer each set's source reads, in call order, from ``reads``."""

    async def load(_settings: Mapping[str, Any], _egress: Any, **kw: Any) -> dict[str, Any]:
        return await reads[kw["name"]].pop(0).run()

    monkeypatch.setattr(reference_sync, "_load_database_source", load)


async def _entered(read: _Read) -> None:
    await asyncio.wait_for(read.entered.wait(), _BOUND)


async def _active_version(store: MessageStore) -> str:
    cur = await store._db.execute("SELECT version FROM reference_version WHERE name='codes'")
    row = await cur.fetchone()
    assert row is not None
    return str(row["version"])


async def test_older_load_finishing_after_a_newer_write_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    old, new = _Read({"A": "OLD"}), _Read({"A": "NEW"})
    _script(monkeypatch, {"codes": [old, new]})
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(
        store, lambda: [_spec("codes")], ReferenceSettings(), egress=_EGRESS
    )
    try:
        background = asyncio.create_task(runner.run_once())
        await _entered(old)
        new.release.set()
        forced = await asyncio.wait_for(runner.sync_all(), _BOUND)
        assert forced.synced == 1
        assert store.reference_view()["codes"] == {"A": "NEW"}
        version = await _active_version(store)

        caplog.clear()
        with caplog.at_level(logging.DEBUG, logger=reference_sync.__name__):
            old.release.set()
            result = await asyncio.wait_for(background, _BOUND)

        assert result.synced == 1 and result.failed == 0  # counted: a newer load wrote this name
        assert store.reference_view()["codes"] == {"A": "NEW"}
        assert await _active_version(store) == version  # no second write at all
        messages = [r.getMessage() for r in caplog.records]
        assert not any("materialized" in m for m in messages)
        skipped = [r for r in caplog.records if "later-started" in r.getMessage()]
        assert len(skipped) == 1 and skipped[0].levelno == logging.DEBUG
    finally:
        await store.close()


async def test_newer_load_whose_source_fails_lets_the_older_write_land(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, bad = _Read({"A": "OLD"}), _Read(error=RuntimeError("source down"))
    _script(monkeypatch, {"codes": [old, bad]})
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(
        store, lambda: [_spec("codes")], ReferenceSettings(), egress=_EGRESS
    )
    try:
        background = asyncio.create_task(runner.run_once())
        await _entered(old)
        bad.release.set()
        assert (await asyncio.wait_for(runner.sync_all(), _BOUND)).failed == 1
        old.release.set()
        assert (await asyncio.wait_for(background, _BOUND)).synced == 1
        assert store.reference_view()["codes"] == {"A": "OLD"}
    finally:
        await store.close()


async def test_newer_load_whose_write_fails_lets_the_older_write_land(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The sequence is recorded only after the store returns, so a refused write claims nothing."""
    old, new = _Read({"A": "OLD"}), _Read({"A": "NEW"})
    _script(monkeypatch, {"codes": [old, new]})
    store = await MessageStore.open(tmp_path / "r.db")
    real_write = store.write_reference_snapshot
    calls = 0

    async def fail_first(*, name: str, version: str, rows: Mapping[str, Any]) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("store refused")
        await real_write(name=name, version=version, rows=rows)

    monkeypatch.setattr(store, "write_reference_snapshot", fail_first)
    runner = ReferenceSyncRunner(
        store, lambda: [_spec("codes")], ReferenceSettings(), egress=_EGRESS
    )
    try:
        background = asyncio.create_task(runner.run_once())
        await _entered(old)
        new.release.set()
        assert (await asyncio.wait_for(runner.sync_all(), _BOUND)).failed == 1
        old.release.set()
        assert (await asyncio.wait_for(background, _BOUND)).synced == 1
        assert calls == 2
        assert store.reference_view()["codes"] == {"A": "OLD"}
    finally:
        await store.close()


async def test_wedged_read_blocks_neither_another_set_nor_a_later_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wedged, later, other = _Read({"A": "WEDGED"}), _Read({"A": "LATER"}), _Read({"B": "OTHER"})
    _script(monkeypatch, {"codes": [wedged, later], "other": [other]})
    later.release.set()
    other.release.set()
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(store, lambda: [], ReferenceSettings(), egress=_EGRESS)
    stuck = asyncio.create_task(runner._sync_one(_spec("codes")))
    try:
        await _entered(wedged)
        await asyncio.wait_for(runner._sync_one(_spec("other")), _BOUND)
        await asyncio.wait_for(runner._sync_one(_spec("codes")), _BOUND)
        assert store.reference_view()["other"] == {"B": "OTHER"}
        assert store.reference_view()["codes"] == {"A": "LATER"}
        assert not stuck.done()
        wedged.release.set()
        await asyncio.wait_for(stuck, _BOUND)
        # The wedged load started first and finished last, so it changed nothing.
        assert store.reference_view()["codes"] == {"A": "LATER"}
    finally:
        wedged.release.set()
        await asyncio.wait_for(stuck, _BOUND)
        await store.close()


async def test_write_in_progress_is_not_interleaved_by_a_later_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """An older write already in the store finishes first, so the later load's rows end up active."""
    old, new = _Read({"A": "OLD"}), _Read({"A": "NEW"})
    old.release.set()
    new.release.set()
    _script(monkeypatch, {"codes": [old, new]})
    store = await MessageStore.open(tmp_path / "r.db")
    real_write = store.write_reference_snapshot
    in_write, finish = asyncio.Event(), asyncio.Event()
    order: list[str] = []

    async def gated(*, name: str, version: str, rows: Mapping[str, Any]) -> None:
        value = str(rows["A"])
        order.append(f"start {value}")
        if value == "OLD":
            in_write.set()
            await finish.wait()
        await real_write(name=name, version=version, rows=rows)
        order.append(f"end {value}")

    monkeypatch.setattr(store, "write_reference_snapshot", gated)
    runner = ReferenceSyncRunner(store, lambda: [], ReferenceSettings(), egress=_EGRESS)
    try:
        first = asyncio.create_task(runner._sync_one(_spec("codes")))
        await asyncio.wait_for(in_write.wait(), _BOUND)
        second = asyncio.create_task(runner._sync_one(_spec("codes")))
        for _ in range(5):
            await asyncio.sleep(0)
        assert order == ["start OLD"]  # the later load is waiting for the write, not inside it
        finish.set()
        await asyncio.wait_for(asyncio.gather(first, second), _BOUND)
        assert order == ["start OLD", "end OLD", "start NEW", "end NEW"]
        assert store.reference_view()["codes"] == {"A": "NEW"}
    finally:
        finish.set()
        await store.close()


async def test_pass_on_the_old_graph_does_not_outrank_a_reload_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A pass still iterating the old graph starts its next set after the reload's load of it, so
    that load must read the live declaration, or the replaced source wins the ordering."""
    old_host, new_host = "old.example.test", "new.example.test"
    a_entered, a_release, b_entered, b_release = (asyncio.Event() for _ in range(4))
    new_b_reads = 0

    async def load(settings: Mapping[str, Any], _egress: Any, **kw: Any) -> dict[str, Any]:
        nonlocal new_b_reads
        server = str(settings["server"])
        if kw["name"] == "a" and server == old_host:
            a_entered.set()
            await a_release.wait()
        if kw["name"] == "b" and server == new_host:
            new_b_reads += 1
            if new_b_reads == 1:  # the reload's own load of b holds here
                b_entered.set()
                await b_release.wait()
        return {"K": server}

    monkeypatch.setattr(reference_sync, "_load_database_source", load)
    graph = {name: _spec(name, old_host) for name in ("a", "b")}
    current = [graph]
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(
        store, lambda: current[0].values(), ReferenceSettings(), egress=_EGRESS
    )
    background = asyncio.create_task(runner.run_once())
    forced: asyncio.Task[Any] | None = None
    try:
        await asyncio.wait_for(a_entered.wait(), _BOUND)
        current[0] = {name: _spec(name, new_host) for name in ("a", "b")}
        forced = asyncio.create_task(runner.sync_all())
        await asyncio.wait_for(b_entered.wait(), _BOUND)
        a_release.set()
        await asyncio.wait_for(background, _BOUND)
        b_release.set()
        await asyncio.wait_for(forced, _BOUND)
        assert store.reference_view()["a"] == {"K": new_host}
        assert store.reference_view()["b"] == {"K": new_host}
    finally:
        a_release.set()
        b_release.set()
        await asyncio.gather(background, *([forced] if forced else []), return_exceptions=True)
        await store.close()


async def test_start_sequence_is_taken_before_the_env_read(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A load that read the env before a newer load started must order as the older of the two."""
    read = _Read({"A": "1"})
    read.release.set()
    _script(monkeypatch, {"codes": [read]})
    store = await MessageStore.open(tmp_path / "r.db")
    seen: list[int] = []

    def env_values() -> Mapping[str, Any]:
        seen.append(runner._load_sequence)
        return {}

    runner = ReferenceSyncRunner(
        store, lambda: [], ReferenceSettings(), env_values=env_values, egress=_EGRESS
    )
    try:
        await runner._sync_one(_spec("codes"))
        assert seen == [1]
    finally:
        await store.close()
