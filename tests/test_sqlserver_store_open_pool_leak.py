# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1627: ``SqlServerStore.open()`` must release the dedicated thread-pool executor it built
whenever ANYTHING after it fails -- whether the ``aioodbc`` pool itself never comes up, or a
post-pool-creation initialization step fails, even when closing the pool hangs.

``open()`` already wrapped the post-pool-creation awaits in ``try``/``except`` and closed the pool on
failure (M-6), but the executor built for that pool (``_build_pool_executor`` / ``store._pool_executor``)
was released nowhere on this path -- a hung ``pool.wait_closed()`` (a connection stuck in a bad state)
left its threads running with nothing left to reach them, and even a clean ``wait_closed()`` never
freed them either. The fix moves ``executor.shutdown(wait=False)`` into a ``finally`` wrapped around
the pool-close sequence, mirroring the ordering ``close()`` already uses -- and, found during the same
pass, ``aioodbc.create_pool()`` itself failing (bad DSN, connect timeout, auth failure) left the
executor built one line earlier just as orphaned, since nothing referenced it yet; that call is now
wrapped too.

**Why the fake.** ``aioodbc`` is the optional ``sqlserver`` extra and CI does not install it on every
leg, so this test stands a recording module in for it -- the lazy ``import aioodbc`` inside ``open()``
resolves it via ``sys.modules`` -- and drives the real ``SqlServerStore.open()`` code path end to end,
no real SQL Server involved. ``_ensure_database_options`` (run before the pool exists) makes its own
standalone ``aioodbc.connect()``; the fake answers it with RCSI already ON, because since BACKLOG #1628
that probe FAILS the open when it cannot verify RCSI, and this test is about what happens after it.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import types
from typing import Any

import pytest

import messagefoundry.store.sqlserver as sqlserver_module
from messagefoundry.config.settings import SchemaManagement, StoreBackend, StoreSettings
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
            raise ConnectionResetError("wait_closed wedged")


class _FakeExecutor:
    """Stands in for the real ``ThreadPoolExecutor`` ``_build_pool_executor`` returns, recording every
    ``shutdown()`` call instead of actually owning threads."""

    def __init__(self) -> None:
        self.shutdown_calls: list[bool] = []

    def shutdown(self, wait: bool = True) -> None:
        self.shutdown_calls.append(wait)


class _RcsiOnCursor:
    """Answers the open-time RCSI probe with RCSI and snapshot isolation both ON."""

    async def execute(self, sql: str, *params: Any) -> None:
        return None

    async def fetchone(self) -> tuple[int, int]:
        return (1, 1)


class _RcsiOnConn:
    async def cursor(self) -> _RcsiOnCursor:
        return _RcsiOnCursor()

    async def close(self) -> None:
        return None


async def _connect_rcsi_on(**kwargs: Any) -> _RcsiOnConn:
    return _RcsiOnConn()


def _install_fake_aioodbc(monkeypatch: pytest.MonkeyPatch, pool: _FakePool) -> None:
    async def _create_pool(**kwargs: Any) -> _FakePool:
        return pool

    module = types.ModuleType("aioodbc")
    module.connect = _connect_rcsi_on  # type: ignore[attr-defined]
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)


def _install_fake_aioodbc_that_never_connects(monkeypatch: pytest.MonkeyPatch) -> None:
    """``create_pool()`` itself raises, the way a bad DSN / connect timeout / auth failure would."""

    async def _create_pool(**kwargs: Any) -> Any:
        raise RuntimeError("connect boom")

    module = types.ModuleType("aioodbc")
    module.connect = _connect_rcsi_on  # type: ignore[attr-defined]
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)


def _settings() -> StoreSettings:
    # AUTO: the open-time RCSI probe the fake answers runs only there (#305); the external default
    # makes no probe connection, and the leak paths below are the same in both modes.
    return StoreSettings(
        backend=StoreBackend.SQLSERVER,
        server="localhost",
        database="mefor_test",
        username="sa",
        schema_management=SchemaManagement.AUTO,
    )


async def _boom_ensure_schema(self: SqlServerStore, **_kwargs: object) -> bool:
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
    monkeypatch.setattr(
        sqlserver_module, "_build_pool_executor", lambda settings, maxsize=None: fake_executor
    )

    with pytest.raises(RuntimeError, match="schema boom"):
        await SqlServerStore.open(_settings())

    assert pool.closed == 1
    assert pool.wait_closed_called == 1
    assert fake_executor.shutdown_calls == [False]


async def test_open_still_shuts_down_the_executor_when_wait_closed_hangs(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """THE MUTATION THIS PINS: releasing the executor only AFTER ``await pool.wait_closed()`` returns,
    instead of in a ``finally`` wrapped around it. Red (pre-fix ordering): ``wait_closed()`` raising
    skips straight past the shutdown line, so ``fake_executor.shutdown_calls`` stays empty even though
    the pool-close path ran.

    Since vault BACKLOG #3054 the cleanup's own failure is logged by class and the OPEN's error
    propagates, so a failed cleanup never hides why the open failed (an audit chain read that
    `audit-verify` must report, among others). It used to be the cleanup's error that escaped."""
    pool = _FakePool(wait_closed_hangs=True)
    _install_fake_aioodbc(monkeypatch, pool)
    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _boom_ensure_schema)

    fake_executor = _FakeExecutor()
    monkeypatch.setattr(
        sqlserver_module, "_build_pool_executor", lambda settings, maxsize=None: fake_executor
    )

    with (
        caplog.at_level(logging.WARNING, logger=sqlserver_module.__name__),
        pytest.raises(RuntimeError, match="schema boom"),
    ):
        await SqlServerStore.open(_settings())
    assert "closing the pool after a failed open also failed (ConnectionResetError)" in caplog.text
    assert "wait_closed wedged" not in caplog.text  # by class only

    assert pool.closed == 1
    assert pool.wait_closed_called == 1
    # The executor shutdown must still fire even though wait_closed() raised instead of returning.
    assert fake_executor.shutdown_calls == [False]


async def test_open_shuts_down_the_executor_when_create_pool_itself_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A DIFFERENT leak window than the two tests above: the executor is built before
    ``aioodbc.create_pool()`` is even called, so a failure THERE (no pool, ever) has to release the
    executor through its own guard -- the post-pool-creation except block never runs because there is
    no ``pool`` local to close."""
    _install_fake_aioodbc_that_never_connects(monkeypatch)
    fake_executor = _FakeExecutor()
    monkeypatch.setattr(
        sqlserver_module, "_build_pool_executor", lambda settings, maxsize=None: fake_executor
    )

    with pytest.raises(RuntimeError, match="connect boom"):
        await SqlServerStore.open(_settings())

    assert fake_executor.shutdown_calls == [False]


def _keyed_open_steps(monkeypatch: pytest.MonkeyPatch, settles: list[bool]) -> None:
    """Stand the writable open's at-open steps down to no-ops, recording each invocation checkpoint
    by its ``settle`` flag, so a test can fail exactly one later step (BACKLOG #5720)."""

    async def _noop(*_args: object, **_kwargs: object) -> Any:
        return None

    async def _checkpoint(
        self: SqlServerStore, *, settle: bool = False, strict: bool = False
    ) -> None:
        settles.append(settle)

    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _noop)
    monkeypatch.setattr(SqlServerStore, "_report_state_key_collation", _noop)
    monkeypatch.setattr(sqlserver_module, "check_open_store_pin", _noop)
    monkeypatch.setattr(sqlserver_module, "bind_store_salt", _noop)
    monkeypatch.setattr(SqlServerStore, "checkpoint_cipher_invocations", _checkpoint)


async def _sweep_boom(self: SqlServerStore) -> None:
    raise RuntimeError("at-rest sweep boom")


def _fake_executor(monkeypatch: pytest.MonkeyPatch) -> _FakeExecutor:
    executor = _FakeExecutor()
    monkeypatch.setattr(
        sqlserver_module, "_build_pool_executor", lambda settings, maxsize=None: executor
    )
    return executor


async def test_a_cancelled_open_closes_the_pool_and_releases_the_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: a cancel is a ``BaseException``, so the ``except Exception`` cleanup let it
    pass, and the pool and the executor's threads stayed. Red before the fix: nothing closed."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)

    async def _cancelled(self: SqlServerStore, **_kwargs: object) -> bool:
        raise asyncio.CancelledError

    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _cancelled)

    with pytest.raises(asyncio.CancelledError):
        await SqlServerStore.open(_settings())

    assert pool.closed == 1
    assert pool.wait_closed_called == 1
    assert executor.shutdown_calls == [False]


async def test_a_cancelled_create_pool_releases_the_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: ``_create_pool`` released the executor on an ``Exception`` only, so a cancel
    while the pool connected leaked its threads. Red before the fix: no shutdown call."""

    async def _create_pool(**kwargs: Any) -> Any:
        raise asyncio.CancelledError

    module = types.ModuleType("aioodbc")
    module.connect = _connect_rcsi_on  # type: ignore[attr-defined]
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "aioodbc", module)
    executor = _fake_executor(monkeypatch)

    with pytest.raises(asyncio.CancelledError):
        await SqlServerStore.open(_settings())

    assert executor.shutdown_calls == [False]


async def test_a_failed_keyed_open_forfeits_the_block_it_reserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720, decision d20261114T010249807-7b3140: the cleanup releases the pool and executor and
    settles nothing, so the reserved block is forfeited, as on main."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)
    monkeypatch.setattr(SqlServerStore, "_encrypt_existing_rows", _sweep_boom)

    with pytest.raises(RuntimeError, match="at-rest sweep boom"):
        await SqlServerStore.open(_settings())

    assert settles == [False]
    assert pool.closed == 1
    assert executor.shutdown_calls == [False]


@pytest.mark.parametrize("step", ["check_open_store_pin", "bind_store_salt"])
async def test_an_open_that_fails_at_or_before_the_salt_bind_settles_nothing(
    monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """BACKLOG #5720: an open that fails at or before its salt bind has taken no reserve, since
    the reserve comes after the bind, and its cleanup settles nothing. The server cleanup never
    settles (``test_a_failed_keyed_open_forfeits_the_block_it_reserved``), so what this pins
    beyond that one is the ORDER, open item 15.

    Mutation: take the reserve before ``bind_store_salt``. Red: ``settles`` is ``[False]``."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)

    async def _refused(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"{step} refused")

    monkeypatch.setattr(sqlserver_module, step, _refused)

    with pytest.raises(RuntimeError, match=f"{step} refused"):
        await SqlServerStore.open(_settings())

    assert settles == []
    assert pool.closed == 1
    assert executor.shutdown_calls == [False]


async def test_a_cancel_during_the_cleanup_still_releases_everything(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: a cancel landing while the failed open waits for its pool to close must not
    skip the executor release, and the caller still sees the cancel."""
    closing = asyncio.Event()

    class _SlowPool(_FakePool):
        async def wait_closed(self) -> None:
            closing.set()
            await asyncio.sleep(0.2)
            await super().wait_closed()

    pool = _SlowPool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _boom_ensure_schema)

    task = asyncio.create_task(SqlServerStore.open(_settings()))
    await asyncio.wait_for(closing.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as raised:
        await task

    assert pool.closed == 1
    assert pool.wait_closed_called == 1
    assert executor.shutdown_calls == [False]
    assert isinstance(raised.value.__cause__, RuntimeError)


async def test_a_constructor_that_raises_releases_the_pool_and_executor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720, open item 9: the store was built outside the cleanup's ``try``, so a
    constructor that raised left the pool open and the executor's threads running. Red before the
    fix: nothing closed."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)

    def _boom(self: SqlServerStore, *_args: object, **_kwargs: object) -> None:
        raise RuntimeError("constructor boom")

    monkeypatch.setattr(SqlServerStore, "__init__", _boom)
    with pytest.raises(RuntimeError, match="constructor boom"):
        await SqlServerStore.open(_settings())
    assert pool.closed == 1
    assert executor.shutdown_calls == [False]


async def test_a_cancelled_open_with_a_wedged_wait_closed_ends_and_forces_the_release(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5720, open item 6: the open-level test of the SQL Server forced release. A
    cancelled open whose ``wait_closed()`` never returns ends within the bound, and the forced
    release closes the pool and shuts the executor down without waiting.

    Mutation: make ``_force_release`` a no-op in ``SqlServerStore.open``. Red: the second
    ``close()`` and ``shutdown()`` never happen."""
    monkeypatch.setattr("messagefoundry.store.store.FAILED_OPEN_CANCEL_BOUND_S", 0.05)
    unwedge = asyncio.Event()

    class _WedgedPool(_FakePool):
        async def wait_closed(self) -> None:
            self.wait_closed_called += 1
            await unwedge.wait()

    pool = _WedgedPool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)

    async def _cancelled(self: SqlServerStore, **_kwargs: object) -> bool:
        raise asyncio.CancelledError

    monkeypatch.setattr(SqlServerStore, "_ensure_schema", _cancelled)
    task = asyncio.create_task(SqlServerStore.open(_settings()))
    try:
        done, _pending = await asyncio.wait({task}, timeout=3)
        assert task in done, "a cancelled open still waited on a wedged wait_closed"
        assert pool.closed == 2, "the cleanup's close, then the forced release's"
        assert executor.shutdown_calls == [False]
    finally:
        unwedge.set()
        await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        task.result()
    assert "did not finish within 0.05 s of a cancel" in caplog.text


async def test_a_cancel_during_a_one_connection_stores_close_still_releases_it(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720, open item 9: ``_one_connection_store`` closed the store in an unshielded
    ``finally``, so a cancel landing in that close cut it short and left the executor's threads.
    Red before the fix: no shutdown call."""
    closing = asyncio.Event()

    class _SlowPool(_FakePool):
        async def wait_closed(self) -> None:
            closing.set()
            await asyncio.sleep(0.2)
            await super().wait_closed()

    pool = _SlowPool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    monkeypatch.setattr(sqlserver_module, "check_pinned_certificate", lambda *a, **k: None)

    async def body() -> None:
        async with SqlServerStore._one_connection_store(_settings(), posture=None):
            raise RuntimeError("probe boom")

    task = asyncio.create_task(body())
    await asyncio.wait_for(closing.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as raised:
        await task
    assert pool.wait_closed_called == 1
    assert executor.shutdown_calls == [False]
    assert isinstance(raised.value.__cause__, RuntimeError)


async def test_an_aclose_closes_a_one_connection_store_gracefully_first(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: under ``aclose()`` the graceful close runs first, as on main: the pool is
    closed and waited on, and the executor shut down once, by that close."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    monkeypatch.setattr(sqlserver_module, "check_pinned_certificate", lambda *a, **k: None)
    cm = SqlServerStore._one_connection_store(_settings(), posture=None)
    await cm.__aenter__()
    await cm.gen.aclose()
    assert pool.closed == 1
    assert pool.wait_closed_called == 1
    assert executor.shutdown_calls == [False]


async def test_an_aclose_whose_graceful_close_fails_forces_the_release(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: when the graceful close under ``aclose()`` fails, the forced release runs:
    the pool is closed again and the executor shut down without waiting."""
    pool = _FakePool(wait_closed_hangs=True)
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    monkeypatch.setattr(sqlserver_module, "check_pinned_certificate", lambda *a, **k: None)
    cm = SqlServerStore._one_connection_store(_settings(), posture=None)
    await cm.__aenter__()
    await cm.gen.aclose()
    assert pool.closed == 2
    assert executor.shutdown_calls == [False, False]  # the close's own, then the forced one


async def test_a_keyboard_interrupt_during_an_acloses_graceful_close_propagates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: a ``KeyboardInterrupt`` raised by the graceful close under ``aclose()``
    propagates, as it did on main."""

    class _InterruptedPool(_FakePool):
        async def wait_closed(self) -> None:
            raise KeyboardInterrupt

    pool = _InterruptedPool()
    _install_fake_aioodbc(monkeypatch, pool)
    _fake_executor(monkeypatch)
    monkeypatch.setattr(sqlserver_module, "check_pinned_certificate", lambda *a, **k: None)
    cm = SqlServerStore._one_connection_store(_settings(), posture=None)
    await cm.__aenter__()
    with pytest.raises(KeyboardInterrupt):
        await cm.gen.aclose()


async def test_a_close_that_raises_on_the_error_path_still_releases_and_keeps_the_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5720: on the one-connection store's error path, a ``close()`` that raises before
    its own pool step still has the pool closed and the executor shut down, and the block's own
    error is raised, the close failure logged by class, as the docstring says.

    Mutation: re-raise the close's error in place of the block's. Red: ``RuntimeError`` raised."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    monkeypatch.setattr(sqlserver_module, "check_pinned_certificate", lambda *a, **k: None)

    def _boom(self: SqlServerStore) -> None:
        raise RuntimeError("sync pool close boom")

    monkeypatch.setattr(SqlServerStore, "close_sync_handoff_pool", _boom)
    with caplog.at_level(logging.WARNING), pytest.raises(ValueError, match="probe boom"):
        async with SqlServerStore._one_connection_store(_settings(), posture=None):
            raise ValueError("probe boom")
    assert pool.closed >= 1
    assert pool.wait_closed_called >= 1
    assert executor.shutdown_calls and executor.shutdown_calls[0] is False
    assert "after an error also failed (RuntimeError)" in caplog.text
    assert "sync pool close boom" not in caplog.text


async def test_a_close_failure_never_replaces_a_cancel_on_the_error_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: a cancel that reaches the body of a one-connection store is raised as a
    cancel even when the close after it fails.

    Mutation: re-raise the close's error in place of the block's. Red: ``RuntimeError`` raised."""
    pool = _FakePool()
    _install_fake_aioodbc(monkeypatch, pool)
    _fake_executor(monkeypatch)
    monkeypatch.setattr(sqlserver_module, "check_pinned_certificate", lambda *a, **k: None)

    def _boom(self: SqlServerStore) -> None:
        raise RuntimeError("sync pool close boom")

    monkeypatch.setattr(SqlServerStore, "close_sync_handoff_pool", _boom)
    entered = asyncio.Event()

    async def body() -> None:
        async with SqlServerStore._one_connection_store(_settings(), posture=None):
            entered.set()
            await asyncio.Event().wait()

    task = asyncio.create_task(body())
    await asyncio.wait_for(entered.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


async def test_a_failed_close_then_a_wedged_wait_closed_is_bounded(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5720: after the store's own close fails on the error path, the pool is closed
    again and waited on for at most the failed-open bound, so a pool that never finishes closing
    cannot hang the error path, and the executor is still shut down.

    Mutation: drop the ``wait_for`` around that ``wait_closed()``. Red: the body never ends."""
    monkeypatch.setattr(sqlserver_module, "FAILED_OPEN_CANCEL_BOUND_S", 0.05)
    unwedge = asyncio.Event()

    class _WedgedPool(_FakePool):
        async def wait_closed(self) -> None:
            self.wait_closed_called += 1
            await unwedge.wait()

    pool = _WedgedPool()
    _install_fake_aioodbc(monkeypatch, pool)
    executor = _fake_executor(monkeypatch)
    monkeypatch.setattr(sqlserver_module, "check_pinned_certificate", lambda *a, **k: None)

    def _boom(self: SqlServerStore) -> None:
        raise RuntimeError("sync pool close boom")

    monkeypatch.setattr(SqlServerStore, "close_sync_handoff_pool", _boom)

    async def body() -> None:
        async with SqlServerStore._one_connection_store(_settings(), posture=None):
            raise ValueError("probe boom")

    task = asyncio.create_task(body())
    try:
        done, _pending = await asyncio.wait({task}, timeout=3)
        assert task in done, "the error path waited on a wedged wait_closed without a bound"
    finally:
        unwedge.set()
    with pytest.raises(ValueError, match="probe boom"):
        task.result()
    assert executor.shutdown_calls == [False]
    assert "closing the pool after that also failed (TimeoutError)" in caplog.text
