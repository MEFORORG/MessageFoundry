# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Overlapping loads of one reference set are ordered by start and committed graph (BACKLOG #5892).

The stores and the registry runner are real. Only the source read is scripted, so a test can hold
one load between its read and its write while another load or a reload runs."""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, ReferenceSettings
from messagefoundry.config.wiring import DatabaseRef, ReferenceSpec, Registry
from messagefoundry.pipeline import reference_sync
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store.store import MessageStore
from tests.test_adr0157_inc2_reload_recovery import _registry

_EGRESS = EgressSettings(deny_by_default=False)
_BOUND = 5.0  # a hang fails the test rather than the run
_COMMITTED, _REFUSED, _NEXT = "committed.example.test", "refused.example.test", "next.example.test"


def _spec(name: str = "codes", server: str = "db.example.test") -> ReferenceSpec:
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
        await asyncio.wait_for(self.release.wait(), _BOUND)
        if self.error is not None:
            raise self.error
        assert self.rows is not None
        return self.rows


def _script(monkeypatch: pytest.MonkeyPatch, reads: dict[str, list[_Read]]) -> None:
    async def load(_settings: Mapping[str, Any], _egress: Any, **kw: Any) -> dict[str, Any]:
        return await reads[kw["name"]].pop(0).run()

    monkeypatch.setattr(reference_sync, "_load_database_source", load)


def _by_host(monkeypatch: pytest.MonkeyPatch, held: dict[str, _Read] | None = None) -> list[str]:
    """Each load returns the host it read, and a host in ``held`` waits on that read once."""
    hosts: list[str] = []
    waiting = dict(held or {})

    async def load(settings: Mapping[str, Any], _egress: Any, **_kw: Any) -> dict[str, Any]:
        host = str(settings["server"])
        hosts.append(host)
        read = waiting.pop(host, None)
        if read is not None:
            return await read.run()
        return {"K": host}

    monkeypatch.setattr(reference_sync, "_load_database_source", load)
    return hosts


def _graph(tmp_path: Path, server: str) -> Registry:
    registry = _registry(tmp_path / "in")
    registry.references["codes"] = _spec(server=server)
    return registry


async def _engine_on_graph(
    store: MessageStore, tmp_path: Path
) -> tuple[RegistryRunner, ReferenceSyncRunner]:
    runner = RegistryRunner(
        _graph(tmp_path, _COMMITTED),
        store,
        claim_mode="per_lane",
        poll_interval=30.0,
        egress=_EGRESS,
    )
    await runner.start()
    engine = Engine(store, egress_settings=_EGRESS)
    engine._registry_runner = runner
    return runner, engine._make_reference_runner()


async def test_older_load_finishing_after_a_newer_write_is_skipped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old, new = _Read({"A": "OLD"}), _Read({"A": "NEW"})
    _script(monkeypatch, {"codes": [old, new]})
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(store, lambda: [_spec()], ReferenceSettings(), egress=_EGRESS)
    try:
        background = asyncio.create_task(runner.run_once())
        await asyncio.wait_for(old.entered.wait(), _BOUND)
        new.release.set()
        assert (await asyncio.wait_for(runner.sync_all(), _BOUND)).synced == 1
        old.release.set()
        result = await asyncio.wait_for(background, _BOUND)
        assert (result.synced, result.failed) == (0, 0)  # superseded, so not reported as a sync
        assert store.reference_view()["codes"] == {"A": "NEW"}
    finally:
        old.release.set()
        await store.close()


@pytest.mark.parametrize("fails_at", ["source", "store"])
async def test_newer_load_that_fails_lets_the_older_write_land(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, fails_at: str
) -> None:
    old = _Read({"A": "OLD"})
    new = _Read(error=RuntimeError("down")) if fails_at == "source" else _Read({"A": "NEW"})
    _script(monkeypatch, {"codes": [old, new]})
    store = await MessageStore.open(tmp_path / "r.db")
    if fails_at == "store":
        real_write = store.write_reference_snapshot
        calls = 0

        async def fail_first(*, name: str, version: str, rows: Mapping[str, Any]) -> None:
            nonlocal calls
            calls += 1
            if calls == 1:
                raise RuntimeError("store refused")
            await real_write(name=name, version=version, rows=rows)

        monkeypatch.setattr(store, "write_reference_snapshot", fail_first)
    runner = ReferenceSyncRunner(store, lambda: [_spec()], ReferenceSettings(), egress=_EGRESS)
    try:
        background = asyncio.create_task(runner.run_once())
        await asyncio.wait_for(old.entered.wait(), _BOUND)
        new.release.set()
        assert (await asyncio.wait_for(runner.sync_all(), _BOUND)).failed == 1
        old.release.set()
        assert (await asyncio.wait_for(background, _BOUND)).synced == 1
        assert store.reference_view()["codes"] == {"A": "OLD"}
    finally:
        old.release.set()
        await store.close()


async def test_wedged_source_blocks_neither_another_set_nor_a_later_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    wedged, later, other = _Read({"A": "WEDGED"}), _Read({"A": "LATER"}), _Read({"B": "OTHER"})
    later.release.set()
    other.release.set()
    _script(monkeypatch, {"codes": [wedged, later], "other": [other]})
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(store, lambda: [], ReferenceSettings(), egress=_EGRESS)
    stuck = asyncio.create_task(runner._sync_one(_spec()))
    try:
        await asyncio.wait_for(wedged.entered.wait(), _BOUND)
        await asyncio.wait_for(runner._sync_one(_spec("other")), _BOUND)
        await asyncio.wait_for(runner._sync_one(_spec()), _BOUND)
        assert store.reference_view()["other"] == {"B": "OTHER"}
        assert store.reference_view()["codes"] == {"A": "LATER"}
        assert not stuck.done()
        wedged.release.set()
        assert await asyncio.wait_for(stuck, _BOUND) is False
        assert store.reference_view()["codes"] == {"A": "LATER"}
    finally:
        wedged.release.set()
        await asyncio.gather(stuck, return_exceptions=True)
        await store.close()


async def test_pass_during_a_refused_reload_keeps_the_committed_load(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The in-flight load of the committed graph still lands, the refused graph is never read, and
    the rollback leaves the committed graph's rows."""
    in_flight = _Read({"K": _COMMITTED})
    hosts = _by_host(monkeypatch, {_COMMITTED: in_flight})
    store = await MessageStore.open(tmp_path / "r.db")
    runner, references = await _engine_on_graph(store, tmp_path)
    load = asyncio.create_task(references.sync_all())
    try:
        await asyncio.wait_for(in_flight.entered.wait(), _BOUND)
        generation = runner.committed_graph()[0]

        async def pass_then_refuse(*_a: Any, **_k: Any) -> None:
            assert runner.committed_graph()[0] == generation  # the swap does not advance it
            await references.sync_all()  # runs while the refused graph is live
            raise RuntimeError("outbound reconcile failed")

        monkeypatch.setattr(runner, "_reconcile_outbounds", pass_then_refuse)
        with pytest.raises(RuntimeError, match="outbound reconcile failed"):
            await runner.reload(_graph(tmp_path, _REFUSED))

        assert runner.committed_graph()[0] == generation  # nor does the rollback
        in_flight.release.set()
        await asyncio.wait_for(load, _BOUND)
        assert _REFUSED not in hosts
        assert store.reference_view()["codes"] == {"K": _COMMITTED}
    finally:
        in_flight.release.set()
        await asyncio.gather(load, return_exceptions=True)
        await runner.stop()
        await store.close()


@pytest.mark.parametrize("reload_load_fails", [False, True])
async def test_load_from_a_replaced_graph_does_not_land_after_a_committed_reload(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, reload_load_fails: bool
) -> None:
    """A committed reload's load wins. If it failed, the replaced graph's rows still do not land."""
    in_flight = _Read({"K": _COMMITTED})
    held: dict[str, _Read] = {_COMMITTED: in_flight}
    if reload_load_fails:
        failing = _Read(error=RuntimeError("down"))
        failing.release.set()
        held[_NEXT] = failing
    _by_host(monkeypatch, held)
    store = await MessageStore.open(tmp_path / "r.db")
    runner, references = await _engine_on_graph(store, tmp_path)
    load = asyncio.create_task(references.sync_all())
    try:
        await asyncio.wait_for(in_flight.entered.wait(), _BOUND)
        before = runner.committed_graph()[0]
        await runner.reload(_graph(tmp_path, _NEXT))
        assert runner.committed_graph()[0] > before
        await asyncio.wait_for(references.sync_all(), _BOUND)
        in_flight.release.set()
        result = await asyncio.wait_for(load, _BOUND)
        assert result.synced == 0
        if reload_load_fails:
            assert "codes" not in store.reference_view()
        else:
            assert store.reference_view()["codes"] == {"K": _NEXT}
    finally:
        in_flight.release.set()
        await asyncio.gather(load, return_exceptions=True)
        await runner.stop()
        await store.close()


async def test_a_graph_that_cannot_be_named_loads_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    hosts = _by_host(monkeypatch)
    store = await MessageStore.open(tmp_path / "r.db")
    runner = ReferenceSyncRunner(
        store,
        lambda: [_spec()],
        ReferenceSettings(),
        graph_generation=lambda: None,
        egress=_EGRESS,
    )
    try:
        result = await runner.sync_all()
        assert (result.synced, result.failed, hosts) == (0, 0, [])
        assert "codes" not in store.reference_view()
    finally:
        await store.close()


async def test_generation_never_repeats_across_runners(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "r.db")
    try:
        first = RegistryRunner(_graph(tmp_path, _COMMITTED), store, egress=_EGRESS)
        second = RegistryRunner(_graph(tmp_path, _COMMITTED), store, egress=_EGRESS)
        assert second.committed_graph()[0] > first.committed_graph()[0]
    finally:
        await store.close()
