# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #4994: the server seal's UPDATE re-checks the row it selected.

Under ``[store].allow_unmarked_ciphertext`` a keyed open seals a live blank on a surface that peer
engine shards already write. A peer can claim that blank and dead-letter it after this open's SELECT.
Sealing ``encrypt('')`` into the dead row would make it replayable as a zero-byte send, so the
UPDATE must re-check the selection predicate and match nothing.

The live Postgres and SQL Server legs cannot stage that interleaving on demand, so this drives each
backend's real ``_seal_surface`` against an in-memory SQLite table. The SELECT and the UPDATE run
there for real, and the peer's dead-letter lands between them. Only the transport is faked.
"""

from __future__ import annotations

import re
import sqlite3
from collections.abc import AsyncIterator, Callable
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.store import postgres as pg_mod
from messagefoundry.store import sqlserver as ss_mod
from messagefoundry.store.crypto import MARKER_PREFIX, generate_key, make_cipher
from messagefoundry.store.queue_tag import LIVE_INLINE_ROW

_LIKE = f"{MARKER_PREFIX}%"
_BLANK_WHERE = f"payload = '' AND {LIVE_INLINE_ROW}"
_ROW = "Q-BLANK-1"


def _queue() -> sqlite3.Connection:
    """One live blank inline row, as a keyless run leaves it on a sealed surface."""
    db = sqlite3.connect(":memory:")
    db.row_factory = sqlite3.Row
    db.create_function("DATALENGTH", 1, lambda v: None if v is None else len(v.encode("utf-16-le")))
    db.execute(
        "CREATE TABLE queue (id TEXT PRIMARY KEY, payload TEXT NOT NULL, status TEXT NOT NULL,"
        " stage TEXT NOT NULL, body_ref TEXT)"
    )
    db.execute("INSERT INTO queue VALUES (?, '', 'pending', 'outbound', NULL)", (_ROW,))
    return db


def _payload(db: sqlite3.Connection) -> str:
    return str(db.execute("SELECT payload FROM queue WHERE id=?", (_ROW,)).fetchone()[0])


async def _noop(*_a: Any, **_k: Any) -> None:
    return None


def _patch_common(monkeypatch: pytest.MonkeyPatch, mod: Any, store: Any) -> None:
    monkeypatch.setattr(mod, "reserve_invocations_ahead", _noop)
    store._cipher = make_cipher(generate_key(), write_v2=True, allow_unmarked=True)
    store._charge_bound_batch = _noop

    async def keyed(_table: str, _column: str) -> bool:
        return True  # the surface is sealed: the opt-out is the only reason a blank is sealed

    store._surface_keyed = keyed


def _counter(db: sqlite3.Connection, translate: Callable[[str], str]) -> Callable[..., Any]:
    async def count(sql: str, *params: Any) -> int:
        return int(db.execute(translate(sql), params).fetchone()[0])

    return count


def _select_then_peer(
    db: sqlite3.Connection, *, peer: bool
) -> Callable[[str, tuple[Any, ...]], list[Any]]:
    """Run a SELECT; after the first one, the peer (if any) dead-letters the row it returned."""
    calls = {"n": 0}

    def run(sql: str, params: tuple[Any, ...]) -> list[Any]:
        rows = db.execute(sql, params).fetchall()
        calls["n"] += 1
        if calls["n"] == 1:
            assert [r["id"] for r in rows] == [_ROW]  # the premise: this open selected the blank
            if peer:
                db.execute("UPDATE queue SET status='dead' WHERE id=?", (_ROW,))
        return rows

    return run


def _pg_sql(sql: str) -> str:
    return re.sub(r"\$(\d+)", r"?\1", sql)


async def _postgres_seal(monkeypatch: pytest.MonkeyPatch, *, peer: bool) -> tuple[str, int]:
    """Run Postgres's ``_seal_surface`` over the table; return the row's payload and the count."""
    db = _queue()
    store: Any = object.__new__(pg_mod.PostgresStore)
    _patch_common(monkeypatch, pg_mod, store)
    store._fetchval = _counter(db, _pg_sql)
    select = _select_then_peer(db, peer=peer)

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

    sealed = await store._seal_surface(
        "queue", "payload", _LIKE, aad_cols=("id",), key_cols=("id",), blank_where=_BLANK_WHERE
    )
    return _payload(db), sealed


def _ss_sql(sql: str) -> str:
    m = re.match(r"SELECT TOP \((\d+)\) (.*)$", sql, re.S)
    sql = sql.replace("COUNT_BIG(", "COUNT(")
    return f"SELECT {m.group(2)} LIMIT {m.group(1)}" if m else sql


async def _sqlserver_seal(monkeypatch: pytest.MonkeyPatch, *, peer: bool) -> tuple[str, int]:
    """Run SQL Server's ``_seal_surface`` over the table; return the row's payload and the count."""
    db = _queue()
    store: Any = object.__new__(ss_mod.SqlServerStore)
    _patch_common(monkeypatch, ss_mod, store)
    store._count_unmarked = _counter(db, _ss_sql)
    store._commit = _noop
    select = _select_then_peer(db, peer=peer)

    async def not_claimed(*_a: Any) -> bool:
        return False

    store._claim_keyed_surface = not_claimed

    class Cursor:
        description: list[tuple[str]] = []
        rowcount = -1
        _rows: list[Any] = []

        async def execute(self, sql: str, params: tuple[Any, ...] = ()) -> None:
            sql = _ss_sql(sql)
            if sql.startswith("SELECT"):
                self._rows = select(sql, params)
                names = self._rows[0].keys() if self._rows else []
                self.description = [(n,) for n in names]
            else:
                self.rowcount = db.execute(sql, params).rowcount

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

    sealed = await store._seal_surface(
        "queue", "payload", _LIKE, aad_cols=("id",), key_cols=("id",), blank_where=_BLANK_WHERE
    )
    return _payload(db), sealed


_SEALS = {"postgres": _postgres_seal, "sqlserver": _sqlserver_seal}


@pytest.mark.parametrize("backend", sorted(_SEALS))
async def test_the_seal_does_not_seal_a_blank_a_peer_dead_lettered(
    monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    payload, sealed = await _SEALS[backend](monkeypatch, peer=True)
    assert payload == "", "the dead row took a seal and would replay as an empty body"
    assert sealed == 0


@pytest.mark.parametrize("backend", sorted(_SEALS))
async def test_the_seal_still_seals_a_blank_no_peer_touched(
    monkeypatch: pytest.MonkeyPatch, backend: str
) -> None:
    """The control: with no peer write between the SELECT and the UPDATE, the re-check matches and
    the live blank is sealed, so the case above fails for the reason it names."""
    payload, sealed = await _SEALS[backend](monkeypatch, peer=False)
    assert payload.startswith(MARKER_PREFIX)
    assert sealed == 1
