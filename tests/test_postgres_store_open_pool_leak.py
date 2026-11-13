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


async def test_a_failed_keyed_open_settles_the_block_it_reserved(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: the open reserves a block of AES-GCM invocations and then fails. Its cleanup
    closed the pool without settling, so the whole block was charged to the key for nothing. Red
    before the fix: ``settles`` is ``[False]``, the reserve and no settlement."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)

    async def _boom(self: PostgresStore) -> None:
        raise RuntimeError("at-rest sweep boom")

    monkeypatch.setattr(PostgresStore, "_encrypt_existing_rows", _boom)

    with pytest.raises(RuntimeError, match="at-rest sweep boom"):
        await PostgresStore.open(_settings())

    assert settles == [False, True]
    assert pool.closed == 1


async def test_an_open_whose_salt_bind_failed_settles_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720, the guard on the settlement: a cipher whose bind to this store's salt failed
    may already count for another store, so settling it here would write that store's reserve
    into this one. The SQLite open already refuses that; the server backends now do the same."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)

    async def _foreign(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("salt bind boom")

    monkeypatch.setattr("messagefoundry.store.postgres.bind_store_salt", _foreign)

    with pytest.raises(RuntimeError, match="salt bind boom"):
        await PostgresStore.open(_settings())

    assert settles == []
    assert pool.closed == 1


async def test_a_cancel_during_the_cleanup_still_closes_the_pool(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720: a second cancel landing while the failed open cleans up must not cut the
    cleanup short. The settle is the slow step here; the pool still closes, and the caller sees
    the cancel."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)
    settling = asyncio.Event()

    async def _slow_checkpoint(self: PostgresStore, *, settle: bool = False) -> None:
        settles.append(settle)
        if settle:
            settling.set()
            await asyncio.sleep(0.2)

    async def _boom(self: PostgresStore) -> None:
        raise RuntimeError("at-rest sweep boom")

    monkeypatch.setattr(PostgresStore, "checkpoint_cipher_invocations", _slow_checkpoint)
    monkeypatch.setattr(PostgresStore, "_encrypt_existing_rows", _boom)

    task = asyncio.create_task(PostgresStore.open(_settings()))
    await asyncio.wait_for(settling.wait(), 5)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert settles == [False, True]
    assert pool.closed == 1


async def test_an_open_that_fails_before_the_salt_bind_settles_nothing(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #5720 round 1: a failure BEFORE the bind (here the pin check) must not settle
    either. The cipher is not yet this store's, and a settle would switch on the bound of a
    cipher a retried open then could not bind."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)

    async def _pin_refused(*_args: object, **_kwargs: object) -> None:
        raise RuntimeError("pin refused")

    monkeypatch.setattr("messagefoundry.store.postgres.check_open_store_pin", _pin_refused)

    with pytest.raises(RuntimeError, match="pin refused"):
        await PostgresStore.open(_settings())

    assert settles == []
    assert pool.closed == 1


async def test_a_settle_that_hangs_does_not_hold_the_pool_open(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5720 round 3: the failed open's cleanup settles through close(), a server round trip
    that ``command_timeout = 0`` leaves unbounded. close() now bounds the settle, so the pool still
    closes, and the settle's failure is logged by class only (vault BACKLOG #3054)."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)
    monkeypatch.setattr("messagefoundry.store.postgres.CLOSE_SETTLE_TIMEOUT", 0.05)

    async def _hanging_settle(self: PostgresStore, *, settle: bool = False) -> None:
        settles.append(settle)
        if settle:
            await asyncio.Event().wait()

    async def _boom(self: PostgresStore) -> None:
        raise RuntimeError("at-rest sweep boom")

    monkeypatch.setattr(PostgresStore, "checkpoint_cipher_invocations", _hanging_settle)
    monkeypatch.setattr(PostgresStore, "_encrypt_existing_rows", _boom)

    with (
        caplog.at_level(logging.WARNING, logger="messagefoundry.store.postgres"),
        pytest.raises(RuntimeError, match="at-rest sweep boom"),
    ):
        await asyncio.wait_for(PostgresStore.open(_settings()), 5)

    assert settles == [False, True]
    assert pool.closed == 1
    assert "could not settle the AES-GCM invocation bound at close (TimeoutError)" in caplog.text


async def test_a_settle_failure_at_close_is_logged_by_class_only(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5720 round 3, vault BACKLOG #3054: a failed open now reaches close()'s settle log,
    which named the driver's text and traceback. It names the class only."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)
    settles: list[bool] = []
    _keyed_open_steps(monkeypatch, settles)

    async def _failing_settle(self: PostgresStore, *, settle: bool = False) -> None:
        if settle:
            raise ConnectionResetError("server db01 refused login mefor")

    async def _boom(self: PostgresStore) -> None:
        raise RuntimeError("at-rest sweep boom")

    monkeypatch.setattr(PostgresStore, "checkpoint_cipher_invocations", _failing_settle)
    monkeypatch.setattr(PostgresStore, "_encrypt_existing_rows", _boom)

    with (
        caplog.at_level(logging.DEBUG, logger="messagefoundry.store.postgres"),
        pytest.raises(RuntimeError, match="at-rest sweep boom"),
    ):
        await PostgresStore.open(_settings())

    assert pool.closed == 1
    assert "(ConnectionResetError)" in caplog.text
    assert "db01" not in caplog.text
