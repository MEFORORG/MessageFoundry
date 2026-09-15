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

import sys
import types
from typing import Any

import pytest

from messagefoundry.config.settings import StoreBackend, StoreSettings
from messagefoundry.store.postgres import PostgresStore


class _FakePool:
    """Records whether (and how many times) ``close()`` was awaited."""

    def __init__(self) -> None:
        self.closed = 0

    async def close(self) -> None:
        self.closed += 1


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

    async def _boom(self: PostgresStore) -> bool:
        raise RuntimeError("schema boom")

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _boom)

    with pytest.raises(RuntimeError, match="schema boom"):
        await PostgresStore.open(_settings())

    assert pool.closed == 1


async def test_open_closes_the_pool_when_a_later_init_step_raises(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Same defect, a different one of the six awaits -- ``_ensure_schema`` succeeds but
    ``_load_reference_cache`` (the last of the six) fails. Guards against a fix that only wraps the
    first call."""
    pool = _FakePool()
    _install_fake_asyncpg(monkeypatch, pool)

    async def _noop(self: PostgresStore) -> Any:
        return None

    async def _boom(self: PostgresStore) -> None:
        raise RuntimeError("reference cache boom")

    monkeypatch.setattr(PostgresStore, "_ensure_schema", _noop)
    monkeypatch.setattr(PostgresStore, "checkpoint_cipher_invocations", _noop)
    monkeypatch.setattr(PostgresStore, "_encrypt_existing_rows", _noop)
    monkeypatch.setattr(PostgresStore, "_load_audit_chain_meta", _noop)
    monkeypatch.setattr(PostgresStore, "_load_state_cache", _noop)
    monkeypatch.setattr(PostgresStore, "_load_reference_cache", _boom)

    with pytest.raises(RuntimeError, match="reference cache boom"):
        await PostgresStore.open(_settings())

    assert pool.closed == 1
