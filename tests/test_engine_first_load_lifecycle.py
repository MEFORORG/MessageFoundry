# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""What a first load leaves behind when its start is cancelled (BACKLOG #5705)."""

from __future__ import annotations

import asyncio
import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.wiring_runner import RegistryRunner, TeardownReason


def _graph(cfgdir: Path, tmp_path: Path) -> None:
    cfgdir.mkdir()
    inbox = tmp_path / f"in-{cfgdir.name}"
    inbox.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import inbound, outbound, router, handler, Send, File
            inbound("in", File(directory={str(inbox)!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")
            outbound("out", File(directory={str(tmp_path / "out")!r}, filename="x.hl7"))

            @router("r")
            def route(msg):
                return ["h"]

            @handler("h")
            def handle(msg):
                return Send("out", msg)
            """
        ),
        encoding="utf-8",
    )


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
