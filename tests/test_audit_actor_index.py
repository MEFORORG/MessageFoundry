# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3120, item (d) and review follow-up 5: the audit actor indexes.

The lock notice's 24-hour throttle reads one account's ``auth.lock_notice`` rows through
``list_audit(actor=, action=, since=, limit=50)``. With only ``ix_audit_ts`` and
``ix_audit_action`` that read walked every recent row of the action, for every account.
``ix_audit_actor`` (actor, action, id) lets it seek the account's own rows, newest first.

That index alone regressed the reads filtered by actor WITHOUT an action equality (``GET
/audit?actor=``, its export pages, ``/me/security-events``): SQLite sought the actor on it and then
sorted every one of the actor's rows to return the newest few. ``ix_audit_actor_id`` (actor, id)
serves those reads in id order. On Postgres both key a prefix of the actor, which is unbounded TEXT
there. Only the SQLite plans are measured here; on the server backends this file checks that the
indexes exist, not that the planner picks them.

Backend-parametrized like ``test_fifo_index_migration``: the SQLite case runs everywhere; the SQL
Server and Postgres cases run only when their ``MEFOR_TEST_*`` env is set, which the hosted service-
container legs do.
"""

from __future__ import annotations

import contextlib
import hashlib
import os
from collections.abc import AsyncIterator, Awaitable, Callable, Sequence
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
        # pg_get_indexdef per key position, so an expression key reads as its expression. The
        # store's own schema only, so a same-named index in another schema cannot answer for it.
        rows = await store._fetchall(
            "SELECT pg_get_indexdef(c.oid, k.ord, true) AS col FROM pg_class c"
            " JOIN pg_index i ON i.indexrelid = c.oid"
            " CROSS JOIN LATERAL generate_series(1, i.indnkeyatts::int) AS k(ord)"
            " WHERE c.relname = $1 AND c.relnamespace = current_schema()::regnamespace"
            " ORDER BY k.ord",
            name,
        )
        return [str(r["col"]).replace('"', "").replace(" ", "") for r in rows]
    rows = await store._fetchall(  # sqlserver
        "SELECT c.name FROM sys.indexes i"
        " JOIN sys.index_columns ic ON ic.object_id=i.object_id AND ic.index_id=i.index_id"
        " JOIN sys.columns c ON c.object_id=i.object_id AND c.column_id=ic.column_id"
        " WHERE i.object_id=OBJECT_ID('audit_log') AND i.name=? AND ic.key_ordinal > 0"
        " ORDER BY ic.key_ordinal",
        (name,),
    )
    return [r["name"] for r in rows]


async def test_the_actor_indexes_exist_on_every_backend(store: Any) -> None:
    # Postgres keys a prefix of the unbounded TEXT actor; see the next test.
    actor = "left(actor,200)" if store._test_backend == "postgres" else "actor"
    assert await _index_columns(store, "ix_audit_actor") == [actor, "action", "id"]
    assert await _index_columns(store, "ix_audit_actor_id") == [actor, "id"]
    # The control: the same probe reads the index that was already there, so an empty list above
    # would be the index missing, not the probe failing.
    assert await _index_columns(store, "ix_audit_action") == ["action", "id"]


async def test_an_overlong_actor_is_still_audited_and_found(store: Any) -> None:
    """A btree entry over about 2.7 KB fails its INSERT on Postgres, and ``actor`` is unbounded
    there. An index on the whole value would turn an overlong typed username into a failed audit
    write. The Postgres indexes key a prefix, and ``list_audit`` still matches the whole value,
    with or without an action filter.

    SQL Server is left out: its ``actor`` column is NVARCHAR(256), which refuses such a row at the
    column whatever the index, so the case is not this change's to pin there."""
    if store._test_backend == "sqlserver":
        pytest.skip("SQL Server's actor column is NVARCHAR(256)")
    # Random hex, which pglz cannot shrink, so compressing the index entry cannot rescue it.
    long_actor = "".join(hashlib.sha256(str(i).encode()).hexdigest() for i in range(125))  # 8000
    near = long_actor[:200] + "-another"  # same prefix, another actor
    await store.record_audit(_LOCK_NOTICE, actor=long_actor, detail='{"lock": "sign_in"}')
    await store.record_audit(_LOCK_NOTICE, actor=near, detail='{"lock": "second_step"}')
    rows = await store.list_audit(actor=long_actor, action=_LOCK_NOTICE, since=0.0, limit=50)
    assert [r["detail"] for r in rows] == ['{"lock": "sign_in"}']
    rows = await store.list_audit(actor=long_actor, since=0.0, limit=50)
    assert [r["detail"] for r in rows] == ['{"lock": "sign_in"}']


async def _plan(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    call: Callable[[MessageStore], Awaitable[object]],
) -> str:
    """The SQLite plan of the one statement ``call`` runs on the store's read connection.

    The statement and its parameters are captured off the read connection as the store method
    really runs them, not rebuilt here, so the SQL cannot drift from the method."""
    real_read = store._read
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
        await call(store)
    [(sql, params)] = seen
    async with real_read() as db:
        cur = await db.execute(f"EXPLAIN QUERY PLAN {sql}", params)
        return " | ".join(str(r[-1]) for r in await cur.fetchall())


async def test_the_throttle_read_seeks_the_actor_index_on_sqlite(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The plan of the statement ``list_audit`` runs for the throttle seeks ``ix_audit_actor`` on
    both the actor and the action, not ``ix_audit_actor_id`` on the actor alone.

    The filters are the ones ``AuthService._lock_notice_held_back`` passes today, written out here.
    The control is an action-only read, whose plan names ``ix_audit_action``, so the instrument is
    known to report the index it uses."""
    store = await MessageStore.open(tmp_path / "plan.db")
    try:
        throttle = await _plan(
            store,
            monkeypatch,
            lambda s: s.list_audit(actor="owner", action=_LOCK_NOTICE, since=0.0, limit=50),
        )
        control = await _plan(store, monkeypatch, lambda s: s.list_audit(action=_LOCK_NOTICE))
    finally:
        await store.close()
    assert "ix_audit_actor (actor=? AND action=?)" in throttle, throttle
    assert "TEMP B-TREE" not in throttle, throttle
    assert "ix_audit_action" in control, control


# Every read filtered by actor without an action equality: the audit page and its total, the export
# pages (a keyset cursor, or an offset), a time-bounded read, and the self-service security events.
_ACTOR_ONLY_READS: dict[str, Callable[[MessageStore], Awaitable[object]]] = {
    "list_audit": lambda s: s.list_audit(actor="owner", limit=50),
    "list_audit_offset": lambda s: s.list_audit(actor="owner", limit=50, offset=500),
    "list_audit_before_id": lambda s: s.list_audit(actor="owner", limit=50, before_id=1000),
    "list_audit_since": lambda s: s.list_audit(actor="owner", since=0.0, until=9e9, limit=50),
    "count_audit_capped": lambda s: s.count_audit(actor="owner", limit=1000),
    "security_events": lambda s: s.security_events_for_user("owner", limit=100, until=9e9),
}


@pytest.mark.parametrize("read", sorted(_ACTOR_ONLY_READS))
async def test_an_actor_only_read_walks_the_actor_in_id_order_on_sqlite(
    read: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """With ``ix_audit_actor`` alone, SQLite sought the actor on it and then sorted all of the
    actor's rows into a temporary B-tree to read the newest few: about 45 ms for a 300k-row actor
    against 0.05 ms before it, and an export paging by offset re-sorted every page. ``(actor, id)``
    hands the rows over already in ``id`` order.

    An empty database plans like a full one here, because SQLite has no statistics until ANALYZE
    and the store never runs it."""
    store = await MessageStore.open(tmp_path / "plan.db")
    try:
        plan = await _plan(store, monkeypatch, _ACTOR_ONLY_READS[read])
    finally:
        await store.close()
    assert "ix_audit_actor_id (actor=?" in plan, plan
    assert "TEMP B-TREE" not in plan, plan
