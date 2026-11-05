# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3411, key custody slice S3: the keyring table.

Schema only: nothing writes the keyring yet. These tests pin that the table exists on all three
backends with one set of columns and one primary key, and that each live-schema check expects it.
Which columns come from the key-custody draft, and why the key spans three of them, is in the
comment above the SQLite ``_SCHEMA``'s keyring.
"""

from __future__ import annotations

import re
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.schema_verify import SchemaMismatchError
from messagefoundry.store.server_schema_verify import (
    ColumnShape,
    _pk_columns,
    live_shape,
    server_schema_differences,
)
from tests._server_schema_rows import mssql_declared, pg_declared

#: The keyring's primary key, the same on every backend.
_KEYRING_KEY = frozenset({"key_id", "purpose", "wrapped_by"})
#: The keyring's columns, the same on every backend.
_KEYRING_COLUMNS = frozenset(
    {
        "key_id",
        "purpose",
        "key_class",
        "state",
        "period_from",
        "period_to",
        "wrapped_by",
        "wrapped",
        "created_at",
        "state_at",
        "proved_at",
    }
)


# --- the keyring table -------------------------------------------------------------------------------


async def test_a_sqlite_store_has_the_keyring_and_its_schema_check_passes(tmp_path: Path) -> None:
    db = tmp_path / "keyring.db"
    store = await MessageStore.open(db)  # the open runs the live-schema check
    await store.close()
    conn = sqlite3.connect(db)
    try:
        rows = conn.execute("SELECT name, type, \"notnull\", pk FROM pragma_table_info('keyring')")
        columns = {name: (kind, bool(notnull), bool(pk)) for name, kind, notnull, pk in rows}
        assert conn.execute("SELECT count(*) FROM keyring").fetchone() == (0,)  # nothing writes it
    finally:
        conn.close()
    assert set(columns) == _KEYRING_COLUMNS
    assert columns["key_id"] == ("TEXT", True, True)  # NOT NULL, as on both server backends
    assert {name for name, (_, _, pk) in columns.items() if pk} == _KEYRING_KEY
    # Every key column is NOT NULL: SQLite would let a NULL in, and a unique index treats NULLs as
    # distinct, so the same wrap could be inserted twice.
    assert all(columns[name][1] for name in _KEYRING_KEY)
    nullable = {name for name, (_, notnull, pk) in columns.items() if not notnull and not pk}
    assert nullable == {"period_from", "period_to", "proved_at"}
    store = await MessageStore.open(db)  # and a reopen passes the same check
    await store.close()


_INSERT = (
    "INSERT INTO keyring (key_id, purpose, state, wrapped_by, created_at, state_at)"
    " VALUES (?, ?, 's', ?, 0, 0)"
)


async def test_a_sqlite_keyring_refuses_a_null_key_id(tmp_path: Path) -> None:
    """SQLite lets a non-integer primary key hold NULL unless the column says NOT NULL; both server
    backends refuse one, so this backend must too. The control is the same row with a key id."""
    db = tmp_path / "null.db"
    store = await MessageStore.open(db)
    await store.close()
    conn = sqlite3.connect(db)
    try:
        conn.execute(_INSERT, ("k", "p", "w"))
        with pytest.raises(sqlite3.IntegrityError, match="keyring.key_id"):
            conn.execute(_INSERT, (None, "p", "w"))
    finally:
        conn.close()


async def test_a_sqlite_keyring_holds_several_wraps_of_one_key_and_refuses_a_duplicate(
    tmp_path: Path,
) -> None:
    """The draft wraps one key in several rows: the recovery wrap and the master handover row both
    wrap a master key, and each host wrap names its own wrapping key. Each coexists; the same wrap
    twice is refused."""
    db = tmp_path / "wraps.db"
    store = await MessageStore.open(db)
    await store.close()
    conn = sqlite3.connect(db)
    try:
        conn.execute(_INSERT, ("master", "recovery-wrap", "recovery"))
        conn.execute(_INSERT, ("master", "master-handover", "old-master"))
        conn.execute(_INSERT, ("master", "host-wrap", "host-a"))
        conn.execute(_INSERT, ("master", "host-wrap", "host-b"))
        assert conn.execute("SELECT count(*) FROM keyring").fetchone() == (4,)
        with pytest.raises(sqlite3.IntegrityError, match="UNIQUE"):
            conn.execute(_INSERT, ("master", "recovery-wrap", "recovery"))
    finally:
        conn.close()


async def test_a_sqlite_keyring_keyed_on_the_key_id_alone_is_refused(tmp_path: Path) -> None:
    """A keyring keyed on ``key_id`` alone, as an earlier build of this slice made it, could not
    hold the wraps above, so the live-schema check refuses it."""
    db = tmp_path / "narrow.db"
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "CREATE TABLE keyring (key_id TEXT NOT NULL PRIMARY KEY, purpose TEXT NOT NULL,"
            " key_class TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, period_from REAL,"
            " period_to REAL, wrapped_by TEXT NOT NULL, wrapped TEXT NOT NULL DEFAULT '',"
            " created_at REAL NOT NULL, state_at REAL NOT NULL, proved_at REAL)"
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert "table 'keyring' is missing the constraint index" in str(info.value)


async def test_a_sqlite_keyring_missing_a_column_is_refused(tmp_path: Path) -> None:
    """The control for the first test's open: a keyring an older build left without a column is
    refused."""
    db = tmp_path / "short.db"
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "CREATE TABLE keyring (key_id TEXT NOT NULL, purpose TEXT NOT NULL,"
            " key_class TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, period_from REAL,"
            " period_to REAL, wrapped_by TEXT NOT NULL, wrapped TEXT NOT NULL DEFAULT '',"
            " created_at REAL NOT NULL, state_at REAL NOT NULL,"
            " PRIMARY KEY (key_id, purpose, wrapped_by))"
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert "table 'keyring' is missing column 'proved_at'" in str(info.value)


def test_each_server_batch_declares_the_keyring_with_the_same_columns() -> None:
    pg = pg_declared()
    ms = mssql_declared()
    assert pg.columns["keyring"] == ms.columns["keyring"] == _KEYRING_COLUMNS
    assert pg.column_shapes["keyring"]["key_id"] == ColumnShape("text", False)
    assert pg.column_shapes["keyring"]["wrapped"] == ColumnShape("text", False)
    assert pg.column_shapes["keyring"]["proved_at"] == ColumnShape("double precision", True)
    bin2 = "latin1_general_100_bin2"
    assert ms.column_shapes["keyring"]["key_id"] == ColumnShape("nvarchar(128)", False, False, bin2)
    assert ms.column_shapes["keyring"]["wrapped"] == ColumnShape("nvarchar(max)", False)
    assert ms.column_shapes["keyring"]["proved_at"] == ColumnShape("float", True)
    for declared in (pg, ms):
        nullable = {c for c, s in declared.column_shapes["keyring"].items() if s.nullable}
        assert nullable == {"period_from", "period_to", "proved_at"}


def test_each_server_batch_keys_the_keyring_as_sqlite_does() -> None:
    """The server checks compare no primary key, so the batch text is read here: each declares the
    keyring's key once, on the same three columns as SQLite."""
    from messagefoundry.store import postgres, sqlserver

    for batch in (postgres._SCHEMA, sqlserver._SCHEMA):
        ddl = [s for s in batch if re.search(r"CREATE TABLE (IF NOT EXISTS )?keyring\b", s)]
        assert len(ddl) == 1 and len(re.findall(r"PRIMARY\s+KEY", ddl[0])) == 1
        assert _pk_columns(ddl[0]) == _KEYRING_KEY


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
def test_each_server_check_refuses_a_store_without_the_keyring(backend: str) -> None:
    """The verifier expects what the batch declares: a store provisioned before the keyring existed
    is refused until it is provisioned again, and one with it passes."""
    declared = pg_declared() if backend == "postgres" else mssql_declared()
    assert server_schema_differences(declared, declared, {}) == []
    columns = {t: set(c) for t, c in declared.columns.items() if t != "keyring"}
    before = live_shape(columns, dict(declared.named_indexes))
    assert server_schema_differences(declared, before, {}) == ["table 'keyring' is missing"]
