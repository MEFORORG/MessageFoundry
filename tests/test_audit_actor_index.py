# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3120, item (d) and review follow-up 5: an (actor, action, id) audit index.

The lock notice's 24-hour throttle reads one account's ``auth.lock_notice`` rows through
``list_audit(actor=, action=, since=, limit=50)``. With only ``ix_audit_ts`` and
``ix_audit_action`` that read walked every recent row of the action, for every account.
``ix_audit_actor`` lets it seek the account's own rows, newest first.

Backend-parametrized like ``test_fifo_index_migration``: the SQLite case runs everywhere; the SQL
Server and Postgres cases run only when their ``MEFOR_TEST_*`` env is set, which the hosted service-
container legs do.
"""

from __future__ import annotations

import contextlib
import os
from collections.abc import AsyncIterator, Sequence
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.store import MessageStore

_SQLSERVER_ON = bool(os.getenv("MEFOR_TEST_SQLSERVER"))
_POSTGRES_ON = bool(os.getenv("MEFOR_TEST_POSTGRES"))

_LOCK_NOTICE = "auth.lock_notice"


async def _open(backend: str, path: Path) -> Any:
    if backend == "sqlite":
        return await MessageStore.open(path)
    from messagefoundry.config.settings import load_settings

    settings = load_settings(environ=os.environ).store
    if backend == "postgres":
        from messagefoundry.store.postgres import PostgresStore

        return await PostgresStore.open(settings)
    from messagefoundry.store.sqlserver import SqlServerStore

    return await SqlServerStore.open(settings)


@pytest.fixture(params=["sqlite", "sqlserver", "postgres"])
async def store(request: pytest.FixtureRequest, tmp_path: Path) -> AsyncIterator[Any]:
    backend = request.param
    if backend == "sqlserver" and not _SQLSERVER_ON:
        pytest.skip("set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* env) to run the SQL Server case")
    if backend == "postgres" and not _POSTGRES_ON:
        pytest.skip("set MEFOR_TEST_POSTGRES=1 (+ MEFOR_STORE_* env) to run the Postgres case")
    s: Any = await _open(backend, tmp_path / "actor_idx.db")
    s._test_backend = backend
    try:
        yield s
    finally:
        await s.close()


async def _index_columns(store: Any, name: str) -> list[str]:
    """The key columns of the ``audit_log`` index ``name``, in key order; empty when it is absent."""
    backend = store._test_backend
    if backend == "sqlite":
        async with store._read() as db:
            cur = await db.execute(f"PRAGMA index_info({name})")
            return [r[2] for r in sorted(await cur.fetchall(), key=lambda r: r[0])]
    if backend == "postgres":
        rows = await store._fetchall(
            "SELECT a.attname FROM pg_index i"
            " JOIN pg_class c ON c.oid = i.indexrelid"
            " JOIN LATERAL unnest(i.indkey) WITH ORDINALITY AS k(attnum, ord) ON true"
            " JOIN pg_attribute a ON a.attrelid = i.indrelid AND a.attnum = k.attnum"
            " WHERE c.relname = $1 ORDER BY k.ord",
            name,
        )
        return [r["attname"] for r in rows]
    rows = await store._fetchall(  # sqlserver
        "SELECT c.name FROM sys.indexes i"
        " JOIN sys.index_columns ic ON ic.object_id=i.object_id AND ic.index_id=i.index_id"
        " JOIN sys.columns c ON c.object_id=i.object_id AND c.column_id=ic.column_id"
        " WHERE i.object_id=OBJECT_ID('audit_log') AND i.name=? AND ic.key_ordinal > 0"
        " ORDER BY ic.key_ordinal",
        (name,),
    )
    return [r["name"] for r in rows]


async def test_the_actor_index_exists_on_every_backend(store: Any) -> None:
    assert await _index_columns(store, "ix_audit_actor") == ["actor", "action", "id"]
    # The control: the same probe reads the index that was already there, so an empty list above
    # would be the index missing, not the probe failing.
    assert await _index_columns(store, "ix_audit_action") == ["action", "id"]


async def test_the_throttle_read_seeks_the_actor_index_on_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan of the statement ``list_audit`` runs for the throttle names ``ix_audit_actor``.

    The statement and its parameters are captured off the read connection as ``list_audit``
    really runs them, not rebuilt here, so the test cannot drift from the method. The control is
    an action-only read, whose plan names ``ix_audit_action``, so the instrument is known to report
    the index it uses."""
    store = await MessageStore.open(tmp_path / "plan.db")
    real_read = store._read

    async def plan(**filters: Any) -> str:
        seen: list[tuple[str, Sequence[Any]]] = []

        class _Spy:
            def __init__(self, db: Any) -> None:
                self._db = db

            async def execute(self, sql: str, params: Sequence[Any] = ()) -> Any:
                seen.append((sql, params))
                return await self._db.execute(sql, params)

        @contextlib.asynccontextmanager
        async def spy_read() -> AsyncIterator[_Spy]:
            async with real_read() as db:
                yield _Spy(db)

        with monkeypatch.context() as m:
            m.setattr(store, "_read", spy_read)
            await store.list_audit(limit=50, **filters)
        [(sql, params)] = seen
        async with real_read() as db:
            cur = await db.execute(f"EXPLAIN QUERY PLAN {sql}", params)
            return " | ".join(str(r[-1]) for r in await cur.fetchall())

    try:
        throttle = await plan(actor="owner", action=_LOCK_NOTICE, since=0.0)
        control = await plan(action=_LOCK_NOTICE)
    finally:
        await store.close()
    assert "ix_audit_actor" in throttle, throttle
    assert "ix_audit_action" in control, control
