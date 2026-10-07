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
            raise RuntimeError("pool close wedged")


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
    assert "closing the pool after a failed open also failed (RuntimeError)" in caplog.text
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
