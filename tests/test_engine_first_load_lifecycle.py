# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a first load leaves behind when its start is cancelled (BACKLOG #5705)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings, SecretRotationSettings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner, TeardownReason
from tests.test_cluster_graph_gating import _FlipCoordinator
from tests.test_cluster_graph_gating import _minimal_graph as _graph


async def _engine(tmp_path: Path, **kwargs: Any) -> Engine:
    return await Engine.create(
        tmp_path / "e.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
        **kwargs,
    )


def _hold_start(monkeypatch: pytest.MonkeyPatch) -> asyncio.Event:
    """Park every start just after it built its outbound, so a cancel lands mid-start."""
    reached = asyncio.Event()
    real = RegistryRunner._start_outbound

    async def held(self: RegistryRunner, *args: Any, **kwargs: Any) -> None:
        await real(self, *args, **kwargs)
        reached.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(RegistryRunner, "_start_outbound", held)
    return reached


def _failing_teardown(monkeypatch: pytest.MonkeyPatch) -> None:
    real = RegistryRunner._teardown_unsafe
    calls = 0

    async def failing(self: RegistryRunner, *args: Any, **kwargs: Any) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("a source stop failed")
        await real(self, *args, **kwargs)

    monkeypatch.setattr(RegistryRunner, "_teardown_unsafe", failing)


async def test_a_cancelled_start_tears_down_what_it_built(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path)
    runner = eng.add_registry(load_config(cfg))
    reached = _hold_start(monkeypatch)
    task = asyncio.create_task(runner.start())
    await asyncio.wait_for(reached.wait(), 5)
    assert runner._destinations and runner._inflight_watch is not None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    try:
        assert task.cancelled()
        assert not runner._destinations
        assert runner._inflight_watch is None
        assert runner.running is False
        assert runner.start_cancel_unwound is True
    finally:
        await eng.stop()


async def test_a_failed_cancel_teardown_still_ends_in_the_cancel(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path)
    runner = eng.add_registry(load_config(cfg))
    reached = _hold_start(monkeypatch)
    _failing_teardown(monkeypatch)
    task = asyncio.create_task(runner.start())
    await asyncio.wait_for(reached.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    try:
        assert task.cancelled()
        assert runner.start_cancel_unwound is False
    finally:
        await runner._teardown_unsafe(TeardownReason.SHUTDOWN)
        await eng.stop()


async def test_a_cancelled_first_load_clears_the_runner_it_unwound(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path)
    await eng.start()
    before = eng._env_values
    reached = _hold_start(monkeypatch)
    # Called directly with distinct values: a reload of a graph with no environment passes the
    # same empty mapping, and an identity check on it could not tell restored from replaced.
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(reached.wait(), 15)
    assert eng._env_values == {"K": "new"}
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    try:
        assert eng._registry_runner is None
        assert eng._env_values is before
    finally:
        await eng.stop()


async def test_a_cancelled_first_load_keeps_a_runner_it_could_not_unwind(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path)
    await eng.start()
    reached = _hold_start(monkeypatch)
    _failing_teardown(monkeypatch)
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(reached.wait(), 15)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    runner = eng._registry_runner
    try:
        assert runner is not None, "engine.stop() could no longer reach the partial start"
        assert runner._destinations
        assert eng._env_values == {"K": "new"}
    finally:
        await eng.stop()
    assert runner is not None and not runner._destinations


def _record_starts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real = RegistryRunner.start

    async def recording(self: RegistryRunner, **kwargs: Any) -> None:
        calls.append(kwargs)
        await real(self, **kwargs)

    monkeypatch.setattr(RegistryRunner, "start", recording)
    return calls


async def test_a_standby_first_load_installs_without_starting(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    coord = _FlipCoordinator(leader=False)
    eng = await _engine(tmp_path, coordinator=coord)
    await eng.start()
    calls = _record_starts(monkeypatch)
    try:
        await eng._first_load(load_config(cfg), {"K": "new"})
        runner = eng._registry_runner
        assert runner is not None and runner.running is False
        assert calls == []
        assert eng._graph_supervisor is not None
        # The first load's CA reading is not carried to a later promotion.
        coord.leader = True
        await eng._reconcile_graph()
        assert runner.running is True
        assert calls == [{}]
    finally:
        await eng.stop()


async def test_a_leader_first_load_starts_once_with_the_checked_lookups(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, coordinator=_FlipCoordinator(leader=True))
    await eng.start()
    calls = _record_starts(monkeypatch)
    try:
        runner = await eng._first_load(load_config(cfg), {"K": "new"})
        assert runner.running is True
        assert eng._graph_supervisor is not None
        assert calls == [{"warn_query_credentials": False, "fhir_lookup_refused": {}}]
    finally:
        await eng.stop()


async def test_a_leader_first_load_start_failure_raises_and_clears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, coordinator=_FlipCoordinator(leader=True))
    await eng.start()
    before = eng._env_values

    async def failing(self: RegistryRunner, **kwargs: Any) -> None:
        raise RuntimeError("the start failed")

    monkeypatch.setattr(RegistryRunner, "start", failing)
    try:
        with pytest.raises(RuntimeError, match="the start failed"):
            await eng._first_load(load_config(cfg), {"K": "new"})
        assert eng._registry_runner is None
        assert eng._env_values is before
        assert eng._graph_supervisor is None
    finally:
        await eng.stop()


async def test_a_stop_during_a_clustered_first_load_starts_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The bring-up yields before the runner's start, which a single-node first load never does."""
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, coordinator=_FlipCoordinator(leader=True))
    await eng.start()
    calls = _record_starts(monkeypatch)
    in_bring_up = asyncio.Event()
    release = asyncio.Event()
    real_sweep = eng.store.dead_letter_missing_destinations

    async def held(*args: Any, **kwargs: Any) -> Any:
        in_bring_up.set()
        await release.wait()
        return await real_sweep(*args, **kwargs)

    monkeypatch.setattr(eng.store, "dead_letter_missing_destinations", held)
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(in_bring_up.wait(), 15)
    eng._stopping = True
    release.set()
    with pytest.raises(RuntimeError, match="stopping"):
        await task
    assert calls == []
    assert eng._registry_runner is None
    assert eng._graph_supervisor is None
    await eng.stop()


@pytest.mark.parametrize("gate", ["enforce_store_key_expiry", "enforce_secret_expiry"])
async def test_an_expiry_refusal_comes_before_the_graph_starts(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, gate: str
) -> None:
    """BACKLOG #5615: a single node would otherwise bind listeners, then refuse."""
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, secret_rotation_settings=SecretRotationSettings())
    eng.add_registry(load_config(cfg))
    calls = _record_starts(monkeypatch)

    def refuse(*args: Any, **kwargs: Any) -> None:
        raise RuntimeError("refused by the expiry gate")

    monkeypatch.setattr(f"messagefoundry.pipeline.engine.{gate}", refuse)
    try:
        with pytest.raises(RuntimeError, match="refused by the expiry gate"):
            await eng.start()
        assert calls == []
    finally:
        await eng.stop()


@pytest.mark.parametrize("still_leader", [True, False])
async def test_a_kept_clustered_runner_is_supervised_only_on_a_standby(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, still_leader: bool
) -> None:
    """On a leader the supervisor would start the graph of a reload that did not apply."""
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    coord = _FlipCoordinator(leader=True)
    eng = await _engine(tmp_path, coordinator=coord)
    await eng.start()
    reached = _hold_start(monkeypatch)
    _failing_teardown(monkeypatch)
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(reached.wait(), 15)
    coord.leader = still_leader
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    try:
        assert eng._registry_runner is not None
        assert (eng._graph_supervisor is not None) is (not still_leader)
    finally:
        monkeypatch.undo()
        await eng.stop()


async def test_a_clustered_first_load_cancelled_before_its_start_installs_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, coordinator=_FlipCoordinator(leader=True))
    await eng.start()
    before = eng._env_values
    calls = _record_starts(monkeypatch)
    in_bring_up = asyncio.Event()

    async def held(*args: Any, **kwargs: Any) -> Any:
        in_bring_up.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(eng.store, "dead_letter_missing_destinations", held)
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(in_bring_up.wait(), 15)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    try:
        assert calls == []
        assert eng._registry_runner is None
        assert eng._env_values is before
        assert eng._graph_supervisor is None
    finally:
        monkeypatch.undo()
        await eng.stop()
