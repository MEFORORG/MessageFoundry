# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #3411, key custody slice S3: the keyring table.

Schema only: nothing writes the keyring yet. These tests pin that the table exists on all three
backends with one set of columns, the ones the key-custody draft's rule 6 names for a row, and that
each live-schema check expects it.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.schema_verify import SchemaMismatchError
from messagefoundry.store.server_schema_verify import (
    ColumnShape,
    live_shape,
    server_schema_differences,
)
from tests._server_schema_rows import mssql_declared, pg_declared

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
    nullable = {name for name, (_, notnull, pk) in columns.items() if not notnull and not pk}
    assert nullable == {"period_from", "period_to", "proved_at"}
    store = await MessageStore.open(db)  # and a reopen passes the same check
    await store.close()


async def test_a_sqlite_keyring_refuses_a_null_key_id(tmp_path: Path) -> None:
    """SQLite lets a non-integer primary key hold NULL unless the column says NOT NULL; both server
    backends refuse one, so this backend must too."""
    db = tmp_path / "null.db"
    store = await MessageStore.open(db)
    await store.close()
    conn = sqlite3.connect(db)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO keyring (key_id, purpose, state, wrapped_by, created_at, state_at)"
                " VALUES (NULL, 'p', 's', 'w', 0, 0)"
            )
    finally:
        conn.close()


async def test_a_sqlite_keyring_missing_a_column_is_refused(tmp_path: Path) -> None:
    """The control for the check above: a keyring an older build left without a column is refused."""
    db = tmp_path / "short.db"
    conn = sqlite3.connect(db)
    try:
        conn.execute(
            "CREATE TABLE keyring (key_id TEXT NOT NULL PRIMARY KEY, purpose TEXT NOT NULL,"
            " key_class TEXT NOT NULL DEFAULT '', state TEXT NOT NULL, period_from REAL,"
            " period_to REAL, wrapped_by TEXT NOT NULL, wrapped TEXT NOT NULL DEFAULT '',"
            " created_at REAL NOT NULL, state_at REAL NOT NULL)"
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


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
def test_each_server_check_refuses_a_store_without_the_keyring(backend: str) -> None:
    """The verifier expects what the batch declares: a store provisioned before the keyring existed
    is refused until it is provisioned again, and one with it passes."""
    declared = pg_declared() if backend == "postgres" else mssql_declared()
    assert server_schema_differences(declared, declared, {}) == []
    columns = {t: set(c) for t, c in declared.columns.items() if t != "keyring"}
    before = live_shape(columns, dict(declared.named_indexes))
    assert server_schema_differences(declared, before, {}) == ["table 'keyring' is missing"]
