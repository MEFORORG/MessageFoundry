# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Finding A: SQL Server schema-init takes the cross-node schema applock BEFORE any CREATE, so two
nodes doing an HA cold start against a virgin DB serialize the DDL instead of both running the
check-then-create `IF OBJECT_ID(...) IS NULL CREATE` guards and racing the loser into a 2714 ("There
is already an object named ..."). The real race needs a real SQL Server + two concurrent opens (the
gated service-container suite / the dogfood box), but the *contract* — applock first, then DDL, under
one transaction — is verifiable here with a fake aioodbc conn/cursor and NO ODBC driver.
"""

from __future__ import annotations

import types
from contextlib import asynccontextmanager

from messagefoundry.store.sqlserver import _SCHEMA_LOCK, SqlServerStore


class _FakeCursor:
    def __init__(self, executed: list[tuple[str, object]]):
        self._executed = executed
        self.description = None

    async def execute(self, sql: str, params: object = None) -> None:
        self._executed.append((sql, params))

    async def fetchone(self) -> object:
        return (0,)  # sp_getapplock return code >= 0 (lock granted)

    async def fetchall(self) -> list[object]:
        return []

    async def close(self) -> None:
        pass


class _FakeConn:
    def __init__(self, executed: list[tuple[str, object]]):
        self.cursor_obj = _FakeCursor(executed)
        self.committed = 0
        self.rolledback = 0

    async def cursor(self) -> _FakeCursor:
        return self.cursor_obj

    async def commit(self) -> None:
        self.committed += 1

    async def rollback(self) -> None:
        self.rolledback += 1


class _FakePool:
    def __init__(self, conn: _FakeConn):
        self._conn = conn

    def acquire(self) -> object:
        conn = self._conn

        @asynccontextmanager
        async def _cm():  # type: ignore[no-untyped-def]
            yield conn

        return _cm()


def _make_store(conn: _FakeConn) -> SqlServerStore:
    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = _FakePool(conn)  # type: ignore[assignment]
    store._settings = types.SimpleNamespace(command_timeout=0)  # type: ignore[assignment]
    return store


async def test_ensure_schema_takes_applock_before_any_create() -> None:
    executed: list[tuple[str, object]] = []
    conn = _FakeConn(executed)
    store = _make_store(conn)

    await store._ensure_schema()

    # The very first statement is an exclusive schema applock naming the cross-node resource...
    sql0, params0 = executed[0]
    assert "sp_getapplock" in sql0
    assert params0 is not None and _SCHEMA_LOCK in params0
    # ...and it precedes every CREATE TABLE (so two virgin-DB nodes serialize rather than race to 2714).
    first_create = next(i for i, (sql, _) in enumerate(executed) if "CREATE TABLE" in sql)
    assert first_create > 0
    # Single committed DDL batch; the txn-scoped applock auto-releases on that commit.
    assert conn.committed == 1
    assert conn.rolledback == 0


async def test_schema_lock_resource_matches_postgres_name() -> None:
    # Both backends must take the SAME logical schema lock name family ("mefor...schema_init") so the
    # intent is obvious; the SQL Server resource is colon-namespaced like its sibling applocks.
    assert _SCHEMA_LOCK == "mefor:schema_init"
