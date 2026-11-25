# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reload's worker-thread hops run on the loop when the default executor refuses them (BACKLOG
#5755, items 3 to 5).

Each test shuts the loop's default executor down first, the realistic refusal: ``run_in_executor``
then raises ``RuntimeError`` at submit, as ``asyncio.to_thread`` did at every one of these hops
before the fix."""

from __future__ import annotations

import asyncio
import concurrent.futures
import logging
import threading
from collections.abc import AsyncIterator
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from messagefoundry import threadhop
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.pipeline import engine as engine_mod
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.threadhop import to_thread_or_loop
from messagefoundry.transports import dicom


@pytest.fixture(autouse=True)
async def _restore_default_executor() -> AsyncIterator[None]:
    """The loop outlives a test, so each test hands it back the default executor it found. The
    attribute is private to asyncio's base loop; ``None`` there means "make one when needed"."""
    loop = asyncio.get_running_loop()
    original = getattr(loop, "_default_executor", None)
    yield
    loop._default_executor = original  # type: ignore[attr-defined]


def _refuse_default_executor() -> None:
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    pool.shutdown()
    asyncio.get_running_loop().set_default_executor(pool)


# --- the helper ----------------------------------------------------------------------------------


def _add(a: int, b: int) -> tuple[int, threading.Thread]:
    return a + b, threading.current_thread()


async def test_a_refused_hop_runs_on_a_thread_of_its_own_with_a_warning(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Off the loop still: a shut-down executor is not a reason to block the loop."""
    _refuse_default_executor()
    caplog.set_level(logging.WARNING, logger=threadhop.__name__)
    total, ran_on = await to_thread_or_loop("probe hop", _add, 2, b=3)
    assert total == 5
    assert ran_on is not threading.current_thread()
    assert ran_on.name == "threadhop-fallback"
    assert "the executor never began the probe hop, so it runs on its own thread" in caplog.text


async def test_a_refused_hop_runs_on_the_loop_when_no_thread_can_start(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    _refuse_default_executor()
    caplog.set_level(logging.WARNING, logger=threadhop.__name__)

    def no_thread(self: threading.Thread) -> None:
        raise RuntimeError("can't start new thread")

    monkeypatch.setattr(threading.Thread, "start", no_thread)
    total, ran_on = await to_thread_or_loop("probe hop", _add, 2, b=3)
    assert (total, ran_on) == (5, threading.current_thread())
    assert "runs on the event loop, since no thread could start" in caplog.text


async def test_a_refused_hop_raises_the_work_s_own_refusal_unchained() -> None:
    _refuse_default_executor()

    def refuse() -> None:
        raise ValueError("synthetic refusal")

    with pytest.raises(ValueError, match="synthetic refusal") as raised:
        await to_thread_or_loop("probe hop", refuse)
    assert raised.value.__context__ is None


async def test_a_working_executor_runs_the_hop_off_the_loop() -> None:
    """The control: with a working executor nothing runs on the loop."""
    ran_on: list[threading.Thread] = []
    await to_thread_or_loop("probe hop", lambda: ran_on.append(threading.current_thread()))
    assert ran_on and ran_on[0] is not threading.current_thread()


async def test_work_the_executor_cancels_while_queued_runs_on_the_loop() -> None:
    """``shutdown(cancel_futures=True)`` cancels queued work; it runs on its own thread instead."""
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=1)
    asyncio.get_running_loop().set_default_executor(pool)
    taken, release = threading.Event(), threading.Event()

    def block() -> None:
        taken.set()
        release.wait(5)

    blocker = asyncio.get_running_loop().run_in_executor(None, block)
    queued = asyncio.create_task(to_thread_or_loop("probe hop", threading.current_thread))
    while not taken.is_set():  # the one worker holds the blocker, not the hop
        await asyncio.sleep(0.01)
    await asyncio.sleep(0)  # the hop is submitted, so it sits queued behind the blocker
    pool.shutdown(wait=False, cancel_futures=True)
    release.set()
    assert (await asyncio.wait_for(queued, 5)).name == "threadhop-fallback"
    await blocker


# --- the hops a reload makes ---------------------------------------------------------------------


class _Session:
    def __init__(self, *, fails: bool = False, gate: threading.Event | None = None) -> None:
        self.closed = False
        self._fails = fails
        self._gate = gate

    def close(self) -> None:
        if self._gate is not None:
            self._gate.wait(5)
        self.closed = True
        if self._fails:
            raise OSError("synthetic reap failure")


def _runner_with(sessions: dict[str, _Session]) -> Any:
    tracked: set[asyncio.Task[object]] = set()
    return SimpleNamespace(
        _sandbox_sessions=dict(sessions), _track_detached_close=tracked.add, tracked=tracked
    )


async def test_a_refused_sandbox_close_still_closes_every_session() -> None:
    """Item 4: the sessions left tracking before the hop, so a refused hop dropped them unclosed,
    with their worker children alive, and raised."""
    sessions = {"IB_A": _Session(), "IB_B": _Session()}
    runner = _runner_with(sessions)
    _refuse_default_executor()
    await RegistryRunner._close_sandbox_sessions(runner)
    assert all(s.closed for s in sessions.values())
    assert runner._sandbox_sessions == {}


async def test_one_failing_sandbox_close_stops_no_other() -> None:
    sessions = {"IB_A": _Session(fails=True), "IB_B": _Session()}
    await RegistryRunner._close_sandbox_sessions(_runner_with(sessions))
    assert all(s.closed for s in sessions.values())


async def test_a_cancelled_sandbox_close_still_closes_the_sessions() -> None:
    """The sessions are out of tracking before the hop, so a cancellation of the caller must stop
    only the wait. The close task is tracked, so teardown waits for it."""
    gate = threading.Event()
    sessions = {"IB_A": _Session(gate=gate), "IB_B": _Session()}
    runner = _runner_with(sessions)
    caller = asyncio.create_task(RegistryRunner._close_sandbox_sessions(runner))
    await asyncio.sleep(0.05)
    caller.cancel()
    with pytest.raises(asyncio.CancelledError):
        await caller
    gate.set()
    (closing,) = runner.tracked
    await asyncio.wait_for(closing, 5)
    assert all(s.closed for s in sessions.values())


def _scp() -> dicom.DicomScpSource:
    return dicom.DicomScpSource(
        Source(
            type=ConnectorType.DIMSE,
            settings={"ae_title": "MF_SCP", "port": 0, "host": "127.0.0.1"},
        )
    )


class _Server:
    def __init__(self) -> None:
        self.shut = False

    def shutdown(self) -> None:
        self.shut = True


async def test_a_refused_dicom_stop_still_shuts_the_server_down() -> None:
    """Item 3: a rollback's stop of a DICOM listener raised and kept the server, port and all."""
    source = _scp()
    server = _Server()
    source._server = server
    _refuse_default_executor()
    await source.stop()
    assert server.shut
    assert source._server is None


async def test_a_refused_dicom_start_still_starts_the_server(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Item 3: a rollback's restart of a DICOM listener raised, leaving the inbound down."""
    source = _scp()
    started: list[bool] = []
    monkeypatch.setattr(dicom, "require_receipt", lambda handler, *, source: handler)
    monkeypatch.setattr(source, "_start_server", lambda: started.append(True))
    _refuse_default_executor()
    await source.start(object())  # type: ignore[arg-type]
    assert started == [True]


async def test_a_refused_reload_target_check_still_resolves(tmp_path: Path) -> None:
    """Item 5: a reload's target check failed the reload on a refused hop."""
    engine: Any = SimpleNamespace(_existing_reload_target_blocking=lambda d: Path(d).resolve())
    _refuse_default_executor()
    assert await engine_mod.Engine._existing_reload_target(engine, tmp_path) == tmp_path.resolve()


async def test_a_refused_config_directory_read_still_reads(tmp_path: Path) -> None:
    """Item 5: a reload's read of its config directory failed the reload on a refused hop."""
    snap = object()
    engine: Any = SimpleNamespace(
        _reload_snapshot_blocking=lambda path, value_file: snap,
        _content_snapshot_blocking=lambda path, value_file: snap,
        _value_file=lambda: None,
    )
    _refuse_default_executor()
    assert await engine_mod.Engine._reload_snapshot(engine, tmp_path) is snap
    assert await engine_mod.Engine._content_snapshot(engine, tmp_path) is snap
