# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Long-lived background tasks survive a transient error instead of dying silently (review H-1,
H-4, M-33). The failure mode these guard against is the worst kind for an interface engine: an
outbound that stops draining (or a poller that stops receiving) while everything still reports
healthy."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api import app as api_app
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.transports.file import FileSource


async def _until(predicate: Any, timeout: float = 2.0) -> None:
    elapsed = 0.0
    while not predicate():
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


class _FlakyStore:
    """Store stub whose claim raises the first ``fail_times`` calls, then returns no work. Covers
    both claim paths so it works whichever ordering mode the worker uses (FIFO is the default)."""

    def __init__(self, fail_times: int = 1) -> None:
        self.calls = 0
        self.fail_times = fail_times

    def _tick(self) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("simulated store outage")

    async def claim_ready(self, **kwargs: Any) -> list[Any]:
        self._tick()
        return []

    async def claim_next_fifo(self, *args: Any, **kwargs: Any) -> Any:
        self._tick()
        return None


async def _stop_runner(runner: RegistryRunner, name: str) -> None:
    runner._stop.set()
    runner._work.set()
    runner._workers[name].cancel()
    await asyncio.gather(runner._workers[name], return_exceptions=True)


# --- H-1: delivery worker ----------------------------------------------------


async def test_delivery_worker_survives_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.01)
    store = _FlakyStore(fail_times=1)
    runner = RegistryRunner(Registry(), store, poll_interval=0.02)  # type: ignore[arg-type]
    runner._running = True
    runner._spawn_worker("OB")
    try:
        # It retries after the error (calls climb past the failing first call) and does NOT die.
        await _until(lambda: store.calls >= 2)
        assert not runner._workers["OB"].done()
    finally:
        await _stop_runner(runner, "OB")


async def test_dead_worker_is_respawned_while_running() -> None:
    runner = RegistryRunner(Registry(), _FlakyStore(fail_times=0), poll_interval=0.02)  # type: ignore[arg-type]
    runner._running = True

    async def _boom() -> None:
        raise RuntimeError("worker died")

    dead = asyncio.ensure_future(_boom())
    await asyncio.gather(dead, return_exceptions=True)  # let it finish with the exception
    runner._workers["OB"] = dead

    runner._on_worker_done("OB", dead)  # simulate the done-callback firing
    try:
        assert runner._workers["OB"] is not dead  # a fresh worker took its place
        assert not runner._workers["OB"].done()
    finally:
        await _stop_runner(runner, "OB")


# --- H-4: file source poller -------------------------------------------------


async def test_file_poller_survives_scan_error(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    src = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "poll_seconds": 0.02})
    )
    scans = {"n": 0}
    real_scan = src._scan_once

    async def flaky_scan() -> None:
        scans["n"] += 1
        if scans["n"] == 1:
            raise OSError("watch dir vanished")
        await real_scan()

    src._scan_once = flaky_scan  # type: ignore[method-assign]

    async def handler(raw: bytes) -> None:
        return None

    await src.start(handler)
    try:
        await _until(lambda: scans["n"] >= 3)  # kept polling past the error
        assert src._task is not None and not src._task.done()
    finally:
        await src.stop()  # must not re-raise the (now-survived) scan error


# --- M-33: API session reaper ------------------------------------------------


async def test_session_reaper_survives_purge_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_app, "_SESSION_REAP_INTERVAL", 0.01)
    calls = {"n": 0}

    class _Store:
        async def purge_expired_sessions(self) -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("db blip")

    task = asyncio.ensure_future(api_app._session_reaper(_Store()))  # type: ignore[arg-type]
    try:
        await _until(lambda: calls["n"] >= 3)  # survived the first-call error, kept purging
        assert not task.done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)
