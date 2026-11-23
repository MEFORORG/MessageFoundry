# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a first load leaves behind when its start is cancelled (BACKLOG #5705)."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.pipeline.wiring_runner as wiring_runner
from messagefoundry.config.settings import EgressSettings
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


class _HungSource:
    """A source whose stop() hangs until released, and honours a cancel."""

    def __init__(self) -> None:
        self.release = asyncio.Event()
        self.stop_calls = 0

    async def stop(self) -> None:
        self.stop_calls += 1
        await self.release.wait()


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


async def test_a_hung_source_stop_does_not_hold_a_cancelled_start(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression 2: the teardown holds the reload lock, which engine.stop() needs."""
    monkeypatch.setattr(wiring_runner, "_CANCELLED_STOP_GRACE_SECONDS", 0.05)
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path)
    await eng.start()
    reached = _hold_start(monkeypatch)
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(reached.wait(), 15)
    runner = eng._registry_runner
    assert runner is not None
    source = _HungSource()
    runner._sources["hung"] = source  # type: ignore[assignment]
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await asyncio.wait_for(task, 5)
    try:
        assert task.cancelled()
        assert source.stop_calls == 1
        assert runner.start_cancel_unwound is False
        assert eng._registry_runner is runner, "engine.stop() could no longer reach it"
        assert "hung" in runner._sources
        assert eng._env_values == {"K": "new"}
        assert not runner._reload_lock.locked()
    finally:
        source.release.set()
        await eng.stop()
    assert "hung" not in runner._sources


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


async def test_a_single_node_first_load_failure_still_raises_and_clears(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path)
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
    finally:
        await eng.stop()


# --- a clustered first load (BACKLOG #5743) ---------------------------------------------------


def _record_starts(monkeypatch: pytest.MonkeyPatch) -> list[dict[str, Any]]:
    calls: list[dict[str, Any]] = []
    real = RegistryRunner.start

    async def recording(self: RegistryRunner, **kwargs: Any) -> None:
        calls.append(kwargs)
        await real(self, **kwargs)

    monkeypatch.setattr(RegistryRunner, "start", recording)
    return calls


def _record_destructive(eng: Engine, monkeypatch: pytest.MonkeyPatch) -> list[str]:
    """Record each dead-letter sweep and startup reference write a bring-up makes."""
    seen: list[str] = []

    def sweep_for(name: str) -> Any:
        async def sweep(*_a: Any, **_k: Any) -> int:
            seen.append(name)
            return 0

        return sweep

    for name in (
        "dead_letter_missing_destinations",
        "dead_letter_missing_handlers",
        "dead_letter_missing_inbounds",
    ):
        monkeypatch.setattr(eng.store, name, sweep_for(name))
    real_sync = eng._reconcile_reference_sync

    async def sync(*, startup: bool) -> None:
        if startup:
            seen.append("reference_sync_startup")
        await real_sync(startup=startup)

    monkeypatch.setattr(eng, "_reconcile_reference_sync", sync)
    return seen


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


async def test_a_failed_leader_first_load_commits_no_sweep_and_leaves_no_supervisor(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regressions 1 and 3, and the failure semantics of a leader's first load."""
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, coordinator=_FlipCoordinator(leader=True))
    await eng.start()
    before = eng._env_values
    seen = _record_destructive(eng, monkeypatch)

    async def failing(self: RegistryRunner, **kwargs: Any) -> None:
        raise RuntimeError("the start failed")

    monkeypatch.setattr(RegistryRunner, "start", failing)
    try:
        with pytest.raises(RuntimeError, match="the start failed"):
            await eng._first_load(load_config(cfg), {"K": "new"})
        assert seen == []
        assert eng._registry_runner is None
        assert eng._env_values is before
        assert eng._graph_supervisor is None
    finally:
        await eng.stop()


@pytest.mark.parametrize("still_leader", [True, False])
async def test_a_kept_runner_gets_no_supervisor_to_start_it(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, still_leader: bool
) -> None:
    """Regression 3: a supervisor would start the failed reload's graph on a promotion."""
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
        assert eng._graph_supervisor is None
    finally:
        monkeypatch.undo()
        await eng.stop()


async def test_no_runner_is_visible_during_a_clustered_recovery(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A DR activation reads the installed runner, so none may sit unstarted in this window."""
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, coordinator=_FlipCoordinator(leader=True))
    await eng.start()
    before = eng._env_values
    calls = _record_starts(monkeypatch)
    in_recovery = asyncio.Event()

    async def held() -> None:
        in_recovery.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(eng, "_recover_for_bring_up", held)
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(in_recovery.wait(), 15)
    assert eng._registry_runner is None
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    try:
        assert calls == []
        assert eng._registry_runner is None
        assert eng._env_values is before
        assert eng._graph_supervisor is None
    finally:
        await eng.stop()


async def test_a_stop_during_a_clustered_first_load_starts_nothing(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    eng = await _engine(tmp_path, coordinator=_FlipCoordinator(leader=True))
    await eng.start()
    calls = _record_starts(monkeypatch)
    in_recovery = asyncio.Event()
    release = asyncio.Event()

    async def held() -> None:
        in_recovery.set()
        await release.wait()

    monkeypatch.setattr(eng, "_recover_for_bring_up", held)
    task = asyncio.create_task(eng._first_load(load_config(cfg), {"K": "new"}))
    await asyncio.wait_for(in_recovery.wait(), 15)
    eng._stopping = True
    release.set()
    with pytest.raises(RuntimeError, match="stopping"):
        await task
    assert calls == []
    assert eng._registry_runner is None
    assert eng._graph_supervisor is None
    await eng.stop()


async def test_a_promotion_still_runs_the_sweeps(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    cfg = tmp_path / "cfg"
    _graph(cfg, tmp_path)
    coord = _FlipCoordinator(leader=False)
    eng = await _engine(tmp_path, coordinator=coord)
    eng.add_registry(load_config(cfg))
    await eng.start()
    seen = _record_destructive(eng, monkeypatch)
    try:
        coord.leader = True
        await eng._reconcile_graph()
        assert seen == [
            "dead_letter_missing_destinations",
            "dead_letter_missing_handlers",
            "dead_letter_missing_inbounds",
            "reference_sync_startup",
        ]
    finally:
        await eng.stop()
