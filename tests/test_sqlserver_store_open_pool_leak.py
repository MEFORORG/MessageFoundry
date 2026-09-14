# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1627: ``SqlServerStore.open()`` must release BOTH the ``aioodbc`` pool and its dedicated
thread-pool executor when a post-pool-creation initialization step fails -- even when closing the
pool itself hangs.

``open()`` already wrapped the post-pool-creation awaits in ``try``/``except`` and closed the pool on
failure (M-6), but the executor built for that pool (``_build_pool_executor`` / ``store._pool_executor``)
was released nowhere on this path -- a hung ``pool.wait_closed()`` (a connection stuck in a bad state)
left its threads running with nothing left to reach them, and even a clean ``wait_closed()`` never
freed them either. The fix moves ``executor.shutdown(wait=False)`` into a ``finally`` wrapped around
the pool-close sequence, mirroring the ordering ``close()`` already uses.

**Why the fake.** ``aioodbc`` is the optional ``sqlserver`` extra and CI does not install it on every
leg, so this test stands a recording module in for it -- the lazy ``import aioodbc`` inside ``open()``
resolves it via ``sys.modules`` -- and drives the real ``SqlServerStore.open()`` code path end to end,
no real SQL Server involved. ``_ensure_database_options`` (run before the pool exists) makes its own
standalone ``aioodbc.connect()``, which this fake module does not provide; that failure is caught and
degraded to a log warning inside ``_ensure_database_options`` itself (a pre-existing, unrelated
behavior), so it never reaches this test.
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

import messagefoundry.store.sqlserver as sqlserver_module
from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.sqlserver import SqlServerStore


class _FakePool:
    """Mimics aioodbc's pool close pair: ``close()`` is synchronous, ``wait_closed()`` is awaited.
    ``wait_closed_hangs`` makes the await raise instead of returning, standing in for a wedged wait."""

    def __init__(self, *, wait_closed_hangs: bool = False) -> None:
        self.closed = 0
        self.wait_closed_called = 0
        self._wait_closed_hangs = wait_closed_hangs

    def close(self) -> None:
        self.closed += 1

    async def wait_closed(self) -> None:
        self.wait_closed_called += 1
        if self._wait_closed_hangs:
            raise RuntimeError("wait_closed wedged")


class _FakeExecutor:
    """Stands in for the real ``ThreadPoolExecutor`` ``_build_pool_executor`` returns, recording every
    ``shutdown()`` call instead of actually owning threads."""

    def __init__(self) -> None:
        self.shutdown_calls: list[bool] = []

    def shutdown(self, wait: bool = True) -> None:
        self.shutdown_calls.append(wait)


def _install_fake_aioodbc(monkeypatch: pytest.MonkeyPatch, pool: _FakePool) -> None:
    async def _create_pool(**kwargs: Any) -> _FakePool:
        return pool

    module = types.ModuleType("aioodbc")
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)


def _settings() -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.SQLSERVER, server="localhost", database="mefor_test", username="sa"
    )


async def _boom_ensure_schema(self: SqlServerStore) -> bool:
    raise RuntimeError("schema boom")


async def test_open_closes_pool_and_shuts_down_executor_when_ensure_schema_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation this pins: no ``executor.shutdown`` call anywhere on the init-failure path. Red: the
    fake executor is never told to shut down, so its threads (a real one, off this test) would leak on
    every failed open, hang or not."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _boom_ensure_schema)

    fake_executor = _FakeExecutor()
    monkeypatch.setattr(sqlserver_module, "_build_pool_executor", lambda settings: fake_executor)

    with pytest.raises(RuntimeError, match="schema boom"):
        await SqlServerStore.open(_settings())

    assert pool.closed == 1
    assert pool.wait_closed_called == 1
    assert fake_executor.shutdown_calls == [False]


async def test_open_still_shuts_down_the_executor_when_wait_closed_hangs(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """THE MUTATION THIS PINS: releasing the executor only AFTER ``await pool.wait_closed()`` returns,
    instead of in a ``finally`` wrapped around it. Red (pre-fix ordering): ``wait_closed()`` raising
    skips straight past the shutdown line, so ``fake_executor.shutdown_calls`` stays empty even though
    the pool-close path ran."""
    pool = _FakePool(wait_closed_hangs=True)
    _install_fake_aioodbc(monkeypatch, pool)
    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _boom_ensure_schema)

    fake_executor = _FakeExecutor()
    monkeypatch.setattr(sqlserver_module, "_build_pool_executor", lambda settings: fake_executor)

    with pytest.raises(RuntimeError, match="wait_closed wedged"):
        await SqlServerStore.open(_settings())

    assert pool.closed == 1
    assert pool.wait_closed_called == 1
    # The executor shutdown must still fire even though wait_closed() raised instead of returning.
    assert fake_executor.shutdown_calls == [False]
