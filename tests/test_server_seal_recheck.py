# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4994: under the opt-out, the server seal leaves a blank a peer engine shard has claimed.

Under ``[store].allow_unmarked_ciphertext`` a keyed open seals a live blank on a surface that peer
engine shards already write. A peer may claim that blank, find it refused, and dead-letter it. If
this open sealed ``encrypt('')`` into the row first, the dead row would be replayable as a zero-byte
send. Two controls stop that: on a sealed surface only a ``pending`` blank qualifies
(``PENDING_INLINE_ROW``), and the UPDATE re-checks the predicate the SELECT used.

The live Postgres and SQL Server legs cannot stage these interleavings on demand, so this drives each
backend's real ``_seal_surface`` against an in-memory SQLite table, with each backend's own blank
predicates. The SELECT and the UPDATE run there for real, and the peer's write lands between them.
Only the transport is faked.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import AsyncIterator, Callable, Iterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.store import postgres as pg_mod
from messagefoundry.store import sqlserver as ss_mod
from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.queue_tag import LIVE_INLINE_ROW, PENDING_INLINE_ROW

_LIKE = f"{MARKER_PREFIX}%"
_ROW = "Q-BLANK-1"
#: What the peer does between this open's SELECT and its UPDATE.
_PEER_WRITES = {
    "none": None,
    "claims": "UPDATE queue SET status='inflight' WHERE id=?",
    "dead_letters": "UPDATE queue SET status='dead' WHERE id=?",
}


@pytest.fixture
def db() -> Iterator[sqlite3.Connection]:
    """One blank inline ``pending`` row, as a keyless run leaves it on a sealed surface."""
    conn = sqlite3.connect(":memory:")
    conn.row_factory = sqlite3.Row
    conn.create_function(
        "DATALENGTH", 1, lambda v: None if v is None else len(v.encode("utf-16-le"))
    )
    conn.execute(
        "CREATE TABLE queue (id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL,"
        " stage TEXT NOT NULL, body_ref TEXT)"
    )
    conn.execute("INSERT INTO queue VALUES (?, '', 'pending', 'outbound', NULL)", (_ROW,))
    try:
        yield conn
    finally:
        conn.close()


def _payload(db: sqlite3.Connection) -> str:
    return str(db.execute("SELECT payload FROM queue WHERE id=?", (_ROW,)).fetchone()[0])


async def _noop(*_a: Any, **_k: Any) -> None:
    return None


def _prepare(monkeypatch: pytest.MonkeyPatch, mod: Any, cls: type) -> Any:
    """A store of ``cls`` with no connection, keyed under the opt-out, on a sealed surface."""
    monkeypatch.setattr(mod, "reserve_invocations_ahead", _noop)
    store: Any = object.__new__(cls)
    store._cipher = make_cipher(generate_key(), write_v2=True, allow_unmarked=True)
    store._charge_bound_batch = _noop

    async def keyed(_table: str, _column: str) -> bool:
        return True  # the surface is sealed: the opt-out is the only reason a blank is sealed

    store._surface_keyed = keyed
    return store


def _counter(db: sqlite3.Connection, translate: Callable[[str], str]) -> Callable[..., Any]:
    async def count(sql: str, *params: Any) -> int:
        return int(db.execute(translate(sql), params).fetchone()[0])

    return count


def _select_then_peer(
    db: sqlite3.Connection, peer: str
) -> Callable[[str, tuple[Any, ...]], list[Any]]:
    """Run a SELECT; after the first one, the peer writes the row it returned."""
    calls = {"n": 0}

    def run(sql: str, params: tuple[Any, ...]) -> list[Any]:
        rows = db.execute(sql, params).fetchall()
        calls["n"] += 1
        write = _PEER_WRITES[peer]
        if calls["n"] == 1 and write is not None:
            assert [r["id"] for r in rows] == [_ROW]  # the premise: this open selected the blank
            db.execute(write, (_ROW,))
        return rows

    return run


def _pg_sql(sql: str) -> str:
    return re.sub(r"\$(\d+)", r"?\1", sql)


async def _postgres_seal(
    monkeypatch: pytest.MonkeyPatch, db: sqlite3.Connection, peer: str, keys: tuple[str, ...]
) -> int:
    store = _prepare(monkeypatch, pg_mod, pg_mod.PostgresStore)
    store._fetchval = _counter(db, _pg_sql)
    select = _select_then_peer(db, peer)

    class Conn:
        async def fetchval(self, *_a: Any) -> None:
            return None  # a peer wrote the marker, so this open did not claim the surface

        async def fetch(self, sql: str, *params: Any) -> list[Any]:
            return select(_pg_sql(sql), params)

        async def execute(self, sql: str, *params: Any) -> str:
            return f"UPDATE {db.execute(_pg_sql(sql), params).rowcount}"

        @asynccontextmanager
        async def transaction(self) -> AsyncIterator[None]:
            yield

    @asynccontextmanager
    async def acquire() -> AsyncIterator[Conn]:
        yield Conn()

    store._timed_acquire = acquire
    sealed: int = await store._seal_surface(
        "queue",
        "payload",
        _LIKE,
        aad_cols=("id",),
        key_cols=keys,
        blank_where=f"payload = '' AND {LIVE_INLINE_ROW}",
        sealed_blank_where=f"payload = '' AND {PENDING_INLINE_ROW}",
    )
    return sealed


def _ss_sql(sql: str) -> str:
    sql = sql.replace("COUNT_BIG(", "COUNT(")
    top = re.match(r"SELECT TOP \((\d+)\) (.*)$", sql, re.S)
    if top:
        return f"SELECT {top.group(2)} LIMIT {top.group(1)}"
    output = re.search(r" OUTPUT inserted\.(\[\w+\])", sql)
    if output:
        return sql.replace(output.group(0), "") + f" RETURNING {output.group(1)}"
    return sql


async def _sqlserver_seal(
    monkeypatch: pytest.MonkeyPatch, db: sqlite3.Connection, peer: str, keys: tuple[str, ...]
) -> int:
    store = _prepare(monkeypatch, ss_mod, ss_mod.SqlServerStore)
    store._count_unmarked = _counter(db, _ss_sql)
    store._commit = _noop
    select = _select_then_peer(db, peer)

    async def not_claimed(*_a: Any) -> bool:
        return False

    store._claim_keyed_surface = not_claimed

    class Cursor:
        description: list[tuple[str]] = []
        _rows: list[Any] = []

        async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            sql = _ss_sql(sql)
            self._rows = (
                select(sql, params)
                if sql.startswith("SELECT")
                else (db.execute(sql, params).fetchall())
            )
            self.description = [(n,) for n in (self._rows[0].keys() if self._rows else [])]

        async def fetchall(self) -> list[tuple[Any, ...]]:
            return [tuple(r) for r in self._rows]

    class Conn:
        async def rollback(self) -> None:
            return None

    @asynccontextmanager
    async def acquire() -> AsyncIterator[Conn]:
        yield Conn()

    @asynccontextmanager
    async def cursor(_conn: Any) -> AsyncIterator[Cursor]:
        yield Cursor()

    store._acquire = acquire
    store._cursor = cursor
    sealed: int = await store._seal_surface(
        "queue",
        "payload",
        _LIKE,
        aad_cols=("id",),
        key_cols=keys,
        blank_where=f"DATALENGTH([payload]) = 0 AND {LIVE_INLINE_ROW}",
        sealed_blank_where=f"DATALENGTH([payload]) = 0 AND {PENDING_INLINE_ROW}",
    )
    return sealed


_SEALS = {"postgres": _postgres_seal, "sqlserver": _sqlserver_seal}
#: One key, and a composite one, so the UPDATE's parameter numbering is exercised past ``id``.
_KEYS = [("id",), ("id", "stage")]


@pytest.mark.parametrize("keys", _KEYS, ids=["id", "id+stage"])
@pytest.mark.parametrize("peer", ["claims", "dead_letters"])
@pytest.mark.parametrize("backend", sorted(_SEALS))
async def test_the_seal_leaves_a_blank_a_peer_took_after_the_select(
    monkeypatch: pytest.MonkeyPatch,
    db: sqlite3.Connection,
    backend: str,
    peer: str,
    keys: tuple[str, ...],
) -> None:
    """A peer that claimed the blank will dead-letter it, and one may have done so already. Either
    way the row left the predicate the SELECT used, so the UPDATE's re-check matches nothing."""
    sealed = await _SEALS[backend](monkeypatch, db, peer, keys)
    assert _payload(db) == "", "the peer's row took a seal and would replay as an empty body"
    assert sealed == 0


@pytest.mark.parametrize("keys", _KEYS, ids=["id", "id+stage"])
@pytest.mark.parametrize("backend", sorted(_SEALS))
async def test_the_seal_still_seals_a_pending_blank_no_peer_touched(
    monkeypatch: pytest.MonkeyPatch, db: sqlite3.Connection, backend: str, keys: tuple[str, ...]
) -> None:
    """The control: with no peer write between the SELECT and the UPDATE, the re-check matches and
    the live blank is sealed, so the case above fails for the reason it names."""
    sealed = await _SEALS[backend](monkeypatch, db, "none", keys)
    assert _payload(db).startswith(MARKER_PREFIX)
    assert sealed == 1


@pytest.mark.parametrize("backend", sorted(_SEALS))
async def test_an_inflight_blank_on_a_sealed_surface_is_not_selected(
    monkeypatch: pytest.MonkeyPatch, db: sqlite3.Connection, backend: str
) -> None:
    """A blank already ``inflight`` may be a peer's claim, about to be dead-lettered, so the opt-out
    does not seal it on a sealed surface: ``PENDING_INLINE_ROW`` leaves it out of the SELECT."""
    db.execute("UPDATE queue SET status='inflight' WHERE id=?", (_ROW,))
    sealed = await _SEALS[backend](monkeypatch, db, "none", ("id",))
    assert _payload(db) == ""
    assert sealed == 0
