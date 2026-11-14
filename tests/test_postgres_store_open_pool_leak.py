# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1627: ``PostgresStore.open()`` must not leak the ``asyncpg`` pool when a
post-pool-creation initialization step fails.

Before this fix, ``open()`` created the pool via ``asyncpg.create_pool(...)`` and then ran six more
awaits (``_ensure_schema`` through ``_load_reference_cache``) with no ``try``/``except`` around them:
a failure in any one of them left the pool created but unreferenced by anything -- its connections
held open against the database with nothing left to close them (a leak on a deploying site's first
failed open, not a live one; MessageFoundry carries zero production instances today).

**Why the fake.** ``asyncpg`` is the optional ``postgres`` extra and CI does not install it on every
leg, so this test stands a recording module in for it -- the lazy ``import asyncpg`` inside ``open()``
resolves it via ``sys.modules`` -- and drives the real ``PostgresStore.open()`` code path end to end,
no real Postgres server involved.
"""

from __future__ import annotations

import asyncio
import logging
import sys
import types
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.postgres import PostgresStore


class _FakePool:
    """Records whether (and how many times) ``close()`` was awaited."""

    def __init__(self, *, close_fails: bool = False) -> None:
        self.closed = 0
        self._close_fails = close_fails

    async def close(self) -> None:
        self.closed += 1
        if self._close_fails:
            raise ConnectionResetError("pool close wedged")

    def terminate(self) -> None:
        """asyncpg's synchronous release, the forced fallback a cancel reaches (BACKLOG #5720)."""


def _install_fake_asyncpg(monkeypatch: pytest.MonkeyPatch, pool: _FakePool) -> None:
    async def _create_pool(**kwargs: Any) -> _FakePool:
        return pool

    module = types.ModuleType("asyncpg")
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "asyncpg", module)


def _settings() -> StoreSettings:
    return StoreSettings(
        backend=StoreBackend.POSTGRES, server="localhost", database="mefor_test", username="mefor"
    )


async def test_open_closes_the_pool_when_ensure_schema_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Mutation this pins: drop the ``try``/``except`` around the six post-pool-creation awaits in
    ``open()``. Red: the fake pool's ``close()`` is never awaited, so ``pool.closed`` stays ``0`` and
    the original ``RuntimeError`` still propagates unchanged either way -- only the leaked pool tells
    the two cases apart."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)

    async def _boom(self: PostgresStore, **_kwargs: object) -> bool:
        raise RuntimeError("schema boom")

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _boom)

    with pytest.raises(RuntimeError, match="schema boom"):
        await PostgresStore.open(_settings())

    assert pool.closed == 1


async def test_a_pool_close_that_fails_does_not_replace_the_opens_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Vault BACKLOG #3054: the cleanup's failure is logged by class, and the OPEN's error
    propagates. Before, the cleanup's error escaped and hid why the open failed, a tagged audit
    chain read that `audit-verify` must report among others."""
    pool = _FakePool(close_fails=True)
    _install_fake_asyncpg(monkeypatch, pool)

    async def _boom(self: PostgresStore, **_kwargs: object) -> bool:
        raise RuntimeError("schema boom")

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _boom)

    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.store.postgres"),
        pytest.raises(RuntimeError, match="schema boom"),
    ):
        await PostgresStore.open(_settings())
    assert pool.closed == 1
    assert "closing the pool after a failed open also failed (ConnectionResetError)" in caplog.text
    assert "pool close wedged" not in caplog.text  # by class only


async def test_open_closes_the_pool_when_a_later_init_step_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same defect, a different one of the six awaits -- ``_ensure_schema`` succeeds but
    ``_load_reference_cache`` (the last of the six) fails. Guards against a fix that only wraps the
    first call."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)

    async def _noop(self: PostgresStore, **_kwargs: object) -> Any:
        return None

    async def _boom(self: PostgresStore) -> None:
        raise RuntimeError("reference cache boom")

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _noop)
    monkeypatch.setattr(PostgresStore, "checkpoint_cipher_invocations", _noop)
    monkeypatch.setattr(PostgresStore, "_encrypt_existing_rows", _noop)
    # The audit chain's load is the shared function the backend module imports, not a method.
    monkeypatch.setattr("messagefoundry.store.postgres.load_audit_chain", _noop)
    monkeypatch.setattr(PostgresStore, "_load_state_cache", _noop)
    monkeypatch.setattr(PostgresStore, "_load_reference_cache", _boom)

    with pytest.raises(RuntimeError, match="reference cache boom"):
        await PostgresStore.open(_settings())

    assert pool.closed == 1


async def test_a_read_only_open_writes_nothing_and_loads_no_cache(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #1780: a read-only open skips the at-open writes and, as on SQLite, the two cache
    loads, which decrypt every cell. Each skipped step raises here, so reaching one fails the open."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    seen: list[str] = []

    async def _ensure(self: PostgresStore, **kwargs: object) -> bool:
        seen.append(f"ensure read_only={kwargs.get('read_only')}")
        return False

    async def _audit(self: PostgresStore, *, read_only: bool) -> None:
        # The loader writes the genesis row only when it is NOT told the open is read-only.
        seen.append(f"audit read_only={read_only}")

    async def _forbidden(self: PostgresStore, *args: object, **kwargs: object) -> None:
        raise AssertionError("a read-only open reached a step it must skip")

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _ensure)
    monkeypatch.setattr("messagefoundry.store.postgres.load_audit_chain", _audit)
    for step in (
        "_ensure_store_salt",
        "checkpoint_cipher_invocations",
        "_encrypt_existing_rows",
        "_load_state_cache",
        "_load_reference_cache",
    ):
        monkeypatch.setattr(PostgresStore, step, _forbidden)

    store = await PostgresStore.open(_settings(), read_only=True)

    assert seen == ["ensure read_only=True", "audit read_only=True"]
    assert store._read_only is True
    assert pool.closed == 0


def _keyed_open_steps(monkeypatch: pytest.MonkeyPatch, settles: list[bool]) -> None:
    """Stand the writable open's at-open steps down to no-ops, recording each invocation checkpoint
    by its ``settle`` flag, so a test can fail exactly one later step (BACKLOG #5720)."""

    async def _noop(*_args: object, **_kwargs: object) -> Any:
        return None

    async def _checkpoint(self: PostgresStore, *, settle: bool = False) -> None:
        settles.append(settle)

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _noop)
    monkeypatch.setattr("messagefoundry.store.postgres.check_open_store_pin", _noop)
    monkeypatch.setattr("messagefoundry.store.postgres.bind_store_salt", _noop)
    monkeypatch.setattr(PostgresStore, "checkpoint_cipher_invocations", _checkpoint)


async def _sweep_boom(self: PostgresStore) -> None:
    raise RuntimeError("at-rest sweep boom")


async def test_a_cancelled_open_closes_the_pool(monkeypatch: pytest.MonkeyPatch) -> None:
    """BACKLOG #5720: a cancel is a ``BaseException``, so the ``except Exception`` cleanup let it
    pass and the pool stayed open. Red before the fix: ``pool.closed`` is 0."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)

    async def _cancelled(self: PostgresStore, **_kwargs: object) -> bool:
        raise asyncio.CancelledError

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _cancelled)

    with pytest.raises(asyncio.CancelledError):
        await PostgresStore.open(_settings())

    assert pool.closed == 1


async def test_a_failed_keyed_open_forfeits_the_block_it_reserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720, decision d20261114T005827: the open reserves a block of AES-GCM invocations
    and then fails. Its cleanup closes the pool and settles nothing, so the block is forfeited, as
    on main: a forfeit only over-counts, the conservative direction for the bound."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)
    monkeypatch.setattr(PostgresStore, "_encrypt_existing_rows", _sweep_boom)

    with pytest.raises(RuntimeError, match="at-rest sweep boom"):
        await PostgresStore.open(_settings())

    assert settles == [False]
    assert pool.closed == 1


@pytest.mark.parametrize("step", ["check_open_store_pin", "bind_store_salt"])
async def test_an_open_that_fails_at_or_before_the_salt_bind_settles_nothing(
    monkeypatch: pytest.MonkeyPatch, step: str
) -> None:
    """BACKLOG #5720, the guard on the settlement: until the bind holds, the cipher may count for
    another store or for none, so a settle here would write a foreign reserve into this store or
    switch on the bound of a cipher a retried open then could not bind."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)

    async def _refused(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError(f"{step} refused")

    monkeypatch.setattr(f"messagefoundry.store.postgres.{step}", _refused)

    with pytest.raises(RuntimeError, match=f"{step} refused"):
        await PostgresStore.open(_settings())

    assert settles == []
    assert pool.closed == 1


async def test_a_cancelled_open_with_a_wedged_pool_close_ends_and_terminates(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5720, decision d20261114T002244771-017417: a cancelled open whose pool close
    never returns ends within the bound, and ``terminate()`` drops the connections. Red at
    faa7869c8e: the shielded cleanup absorbs the cancel and the open never returns."""
    monkeypatch.setattr("messagefoundry.store.store.FAILED_OPEN_CANCEL_BOUND_S", 0.05)
    unwedge = asyncio.Event()
    pool = _FakePool()
    terminated: list[str] = []

    async def wedged_close() -> None:
        pool.closed += 1
        await unwedge.wait()

    pool.close = wedged_close  # type: ignore[method-assign]
    pool.terminate = lambda: terminated.append("terminated")  # type: ignore[method-assign]
    _install_fake_asyncpg(monkeypatch, pool)

    async def _cancelled(self: PostgresStore, **_kwargs: object) -> bool:
        raise asyncio.CancelledError

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _cancelled)

    task = asyncio.create_task(PostgresStore.open(_settings()))
    try:
        done, _pending = await asyncio.wait({task}, timeout=3)
        assert task in done, "a cancelled open still waited on a wedged pool close"
    finally:
        unwedge.set()
        await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        task.result()
    assert pool.closed == 1
    assert terminated == ["terminated"]


async def test_a_cancel_during_the_cleanup_still_closes_the_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: a cancel landing while the failed open closes its pool must not cut the close
    short, and the caller sees the cancel, chained to the open's own failure."""
    closing = asyncio.Event()
    pool = _FakePool()
    real_close = pool.close

    async def slow_close() -> None:
        closing.set()
        await asyncio.sleep(0.2)
        await real_close()

    pool.close = slow_close  # type: ignore[method-assign]
    _install_fake_asyncpg(monkeypatch, pool)

    async def _boom(self: PostgresStore, **_kwargs: object) -> bool:
        raise RuntimeError("schema boom")

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _boom)

    task = asyncio.create_task(PostgresStore.open(_settings()))
    await asyncio.wait_for(closing.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError) as raised:
        await task

    assert pool.closed == 1
    assert isinstance(raised.value.__cause__, RuntimeError)


async def test_a_pool_without_terminate_keeps_the_opens_error(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5720, decision d20261114T005827: a pool with no ``terminate()`` must not replace
    the open's error. The forced release looks it up only when it runs, inside the logged call."""
    monkeypatch.setattr("messagefoundry.store.store.FAILED_OPEN_CANCEL_BOUND_S", 0.05)
    unwedge = asyncio.Event()

    class _NoTerminatePool:
        closed = 0

        async def close(self) -> None:
            self.closed += 1
            await unwedge.wait()

    pool = _NoTerminatePool()

    async def _create_pool(**kwargs: Any) -> _NoTerminatePool:
        return pool

    module = types.ModuleType("asyncpg")
    module.create_pool = _create_pool  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "asyncpg", module)

    async def _cancelled(self: PostgresStore, **_kwargs: object) -> bool:
        raise asyncio.CancelledError

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _cancelled)
    task = asyncio.create_task(PostgresStore.open(_settings()))
    try:
        done, _pending = await asyncio.wait({task}, timeout=3)
        assert task in done
    finally:
        unwedge.set()
        await asyncio.sleep(0)
    with pytest.raises(asyncio.CancelledError):
        task.result()
    assert "forcing the release after a failed store open also failed (AttributeError)" in (
        caplog.text
    )
