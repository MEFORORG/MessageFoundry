# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #6719 and #6720: the SQLite schema check and objects that are not ordinary tables.

#6719: the index read skipped virtual tables, but the table and column reads did not, so a virtual
table whose module this process does not load made the check raise "no such module" instead of
reporting a difference. The same text from a schema step or the read-only load is now a refusal too.

#6720: an expected name held by an object of another kind (an index, a table or a view) fails the
schema script or a migration with a SQLite message the step-error test did not know, so the failure
escaped as the driver's bare error instead of the refusal with its remedy. The messages below are
measured from the local SQLite, not copied from the row.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite
import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.schema_verify import (
    SchemaMismatchError,
    is_schema_step_error,
    live_schema_differences,
    read_schema_shape,
)
from messagefoundry.store.store import _SCHEMA, _await_connection_worker_exit


def _sql(path: Path, *statements: str) -> None:
    conn = sqlite3.connect(path)
    try:
        for statement in statements:
            conn.execute(statement)
        conn.commit()
    finally:
        conn.close()


def _plant_unloaded_virtual_table(path: Path, name: str) -> None:
    """A virtual table whose module no process here loads, as another tool could leave one."""
    _sql(
        path,
        "PRAGMA writable_schema = ON",
        "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES"
        f" ('table', '{name}', '{name}', 0, 'CREATE VIRTUAL TABLE {name} USING no_such_module(x)')",
    )


@asynccontextmanager
async def _connected(path: Path | str) -> AsyncIterator[aiosqlite.Connection]:
    db = await aiosqlite.connect(path)
    try:
        yield db
    finally:
        await db.close()
        await _await_connection_worker_exit(db)


def _fts5_loaded() -> bool:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE VIRTUAL TABLE probe USING fts5(a)")
    except sqlite3.OperationalError:
        return False
    finally:
        conn.close()
    return True


_NEEDS_FTS5 = pytest.mark.skipif(not _fts5_loaded(), reason="this SQLite has no fts5")


async def _fresh(path: Path) -> None:
    await (await MessageStore.open(path)).close()


# --- BACKLOG #6719 ---------------------------------------------------------------------------------


async def test_a_virtual_table_whose_module_is_not_loaded_does_not_break_the_read(
    tmp_path: Path,
) -> None:
    path = tmp_path / "vt.db"
    _sql(path, "CREATE TABLE t (a TEXT)")
    _plant_unloaded_virtual_table(path, "vt")
    # Positive control: the planted table is the one a pragma cannot read.
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.OperationalError, match="no such module"):
            conn.execute("SELECT * FROM pragma_table_info('vt')").fetchall()
    finally:
        conn.close()
    async with _connected(path) as db:
        assert (await read_schema_shape(db)).columns == {"t": frozenset({"a"})}
        named = await read_schema_shape(db, ["t", "vt"])
    # Named in the request, a virtual table reads as holding no columns, the shape of a missing one.
    assert named.columns == {"t": frozenset({"a"}), "vt": frozenset()}


async def test_an_expected_table_held_by_an_unloaded_virtual_table_is_reported(
    tmp_path: Path,
) -> None:
    path = tmp_path / "held.db"
    await _fresh(path)
    _sql(path, "DROP TABLE search_presets")
    _plant_unloaded_virtual_table(path, "search_presets")
    # The read-only open runs this compare without the schema script: it must report, not raise.
    async with _connected(path) as db:
        problems = await live_schema_differences(db, schema=_SCHEMA, migrate=MessageStore._migrate)
    assert "table 'search_presets' is missing" in problems
    # The writable open refuses it too: the script's index on it fails first, with the remedy.
    with pytest.raises(SchemaMismatchError, match="virtual tables may not be indexed"):
        await _fresh(path)


async def test_an_unindexed_expected_table_held_by_an_unloaded_virtual_table_is_refused(
    tmp_path: Path,
) -> None:
    # The script indexes nothing on users, so the first step to touch it is a migration's pragma,
    # which fails on the module rather than on an index.
    path = tmp_path / "users.db"
    await _fresh(path)
    _sql(path, "DROP TABLE users")
    _plant_unloaded_virtual_table(path, "users")
    with pytest.raises(SchemaMismatchError) as info:
        await _fresh(path)
    assert str(info.value).startswith(f"store {path} is from an incompatible version; recreate it:")
    assert info.value.cause is not None and "no such module" in info.value.cause


async def test_the_read_only_open_refuses_an_audit_log_held_by_an_unloaded_virtual_table(
    tmp_path: Path,
) -> None:
    path = tmp_path / "ro.db"
    await _fresh(path)
    _sql(path, "DROP TABLE audit_log")
    _plant_unloaded_virtual_table(path, "audit_log")
    with pytest.raises(
        SchemaMismatchError, match="opened read-only and lacks what this build reads"
    ):
        await (await MessageStore.open(path, read_only=True)).close()


async def test_a_counted_store_whose_salt_table_is_virtual_gets_the_new_key_remedy(
    tmp_path: Path,
) -> None:
    from messagefoundry.store.schema_verify import _counts_under_a_dek

    path = tmp_path / "counted.db"
    _sql(
        path,
        "CREATE TABLE cipher_meta (key_id TEXT, invocations INTEGER)",
        "INSERT INTO cipher_meta VALUES ('k', 1)",
    )
    _plant_unloaded_virtual_table(path, "store_salt")
    async with _connected(path) as db:
        assert await _counts_under_a_dek(db) is True


@pytest.mark.parametrize(
    "salt",
    [
        pytest.param("CREATE VIRTUAL TABLE store_salt USING fts5(salt)", marks=_NEEDS_FTS5),
        "CREATE VIEW store_salt AS SELECT 's' AS salt",
    ],
)
async def test_a_counted_store_whose_salt_is_a_readable_foreign_object_gets_the_new_key_remedy(
    tmp_path: Path, salt: str
) -> None:
    # A loaded module or a view that yields a row is still not a salt this build minted, so the
    # remedy must not hang on whether the module happens to load.
    from messagefoundry.store.schema_verify import _counts_under_a_dek

    path = tmp_path / "readable.db"
    _sql(
        path,
        "CREATE TABLE cipher_meta (key_id TEXT, invocations INTEGER)",
        "INSERT INTO cipher_meta VALUES ('k', 1)",
        salt,
    )
    if salt.startswith("CREATE VIRTUAL"):
        _sql(path, "INSERT INTO store_salt VALUES ('s')")
    async with _connected(path) as db:
        async with db.execute("SELECT count(*) FROM store_salt") as cur:
            row = await cur.fetchone()
        assert row is not None and row[0] == 1  # control: the foreign object reads as one salt
        assert await _counts_under_a_dek(db) is True


_VIRTUAL_TABLES = "SELECT name FROM sqlite_master WHERE sql LIKE 'CREATE VIRTUAL TABLE%'"


async def test_the_expected_shape_holds_no_virtual_table() -> None:
    # The reads skip virtual tables, so one this build created would never be verified. Adding one
    # must fail here until the check learns to compare it.
    async with _connected(":memory:") as db:
        db.row_factory = aiosqlite.Row
        await db.executescript(_SCHEMA)
        await MessageStore._migrate(db)
        async with db.execute(_VIRTUAL_TABLES) as cur:
            virtual = [tuple(r) for r in await cur.fetchall()]
        async with db.execute("SELECT count(*) FROM sqlite_master WHERE type = 'table'") as cur:
            row = await cur.fetchone()
    assert row is not None and row[0] > 0  # positive control: the scratch schema was built
    assert virtual == []


@_NEEDS_FTS5
async def test_the_virtual_table_probe_finds_one() -> None:
    # Negative control for the pin above: the same query does find a virtual table when one exists.
    async with _connected(":memory:") as db:
        await db.execute("CREATE VIRTUAL TABLE probe USING fts5(a)")
        async with db.execute(_VIRTUAL_TABLES) as cur:
            assert [tuple(r) for r in await cur.fetchall()] == [("probe",)]


# --- BACKLOG #6720 ---------------------------------------------------------------------------------


_VIEW = "CREATE VIEW x AS SELECT a FROM other"
_VIRTUAL = "CREATE VIRTUAL TABLE x USING fts5(a)"

_COLLISIONS = [
    pytest.param(
        "CREATE INDEX x ON other(a)", "CREATE TABLE IF NOT EXISTS x (a TEXT)", id="table-vs-index"
    ),
    pytest.param(
        "CREATE TABLE x (a TEXT)", "CREATE INDEX IF NOT EXISTS x ON other(a)", id="index-vs-table"
    ),
    pytest.param(_VIEW, "CREATE INDEX IF NOT EXISTS x ON other(a)", id="index-vs-view"),
    pytest.param(
        _VIEW, "CREATE INDEX IF NOT EXISTS ix_x ON x(a)", id="index-on-a-table-that-is-a-view"
    ),
    pytest.param(_VIEW, "ALTER TABLE x ADD COLUMN b TEXT", id="alter-a-table-that-is-a-view"),
    pytest.param(_VIEW, "UPDATE x SET a = 'b'", id="write-a-table-that-is-a-view"),
    pytest.param(_VIEW, "DROP TABLE IF EXISTS x", id="drop-a-table-that-is-a-view"),
    pytest.param(
        _VIRTUAL,
        "CREATE INDEX IF NOT EXISTS ix_x ON x(a)",
        id="index-on-a-table-that-is-virtual",
        marks=_NEEDS_FTS5,
    ),
    pytest.param(
        _VIRTUAL,
        "ALTER TABLE x ADD COLUMN b TEXT",
        id="alter-a-table-that-is-virtual",
        marks=_NEEDS_FTS5,
    ),
]


@pytest.mark.parametrize(("existing", "step"), _COLLISIONS)
def test_a_name_held_by_another_kind_of_object_is_a_schema_step_error(
    existing: str, step: str
) -> None:
    conn = sqlite3.connect(":memory:")
    try:
        conn.execute("CREATE TABLE other (a TEXT)")
        conn.execute(existing)
        with pytest.raises(sqlite3.OperationalError) as info:
            conn.execute(step)
    finally:
        conn.close()
    # Real SQLite errors, so the code and the text are SQLite's own, not this test's guess.
    assert info.value.sqlite_errorcode & 0xFF == sqlite3.SQLITE_ERROR
    assert is_schema_step_error(info.value), str(info.value)


def test_no_such_module_is_a_schema_step_error(tmp_path: Path) -> None:
    # This build creates no virtual table (pinned above), so a module the open cannot find belongs
    # to an object some other tool left in the file.
    path = tmp_path / "module.db"
    _plant_unloaded_virtual_table(path, "vt")
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.OperationalError) as info:
            conn.execute("SELECT * FROM vt")
    finally:
        conn.close()
    assert "no such module" in str(info.value)
    assert info.value.sqlite_errorcode & 0xFF == sqlite3.SQLITE_ERROR
    assert is_schema_step_error(info.value)


@pytest.mark.parametrize(
    ("statements", "cause"),
    [
        pytest.param(
            ("CREATE TABLE zz (a TEXT)", "CREATE INDEX messages ON zz(a)"),
            "there is already an index named messages",
            id="expected-table-held-by-an-index",
        ),
        pytest.param(
            ("CREATE TABLE ix_queue_fifo_in_seq (a TEXT)",),
            "there is already a table named ix_queue_fifo_in_seq",
            id="expected-index-held-by-a-table",
        ),
        pytest.param(
            ("CREATE VIEW ix_queue_fifo_in_seq AS SELECT 1 AS a",),
            "there is already a table named ix_queue_fifo_in_seq",
            id="expected-index-held-by-a-view",
        ),
        pytest.param(
            ("CREATE VIEW upload_quota AS SELECT 1 AS a",),
            "use DROP VIEW to delete view upload_quota",
            id="dropped-table-held-by-a-view",
        ),
        pytest.param(
            ("CREATE VIEW messages AS SELECT 1 AS id",),
            "views may not be indexed",
            id="expected-table-held-by-a-view",
        ),
    ],
)
async def test_the_open_refuses_a_name_held_by_another_kind_of_object(
    tmp_path: Path, statements: tuple[str, ...], cause: str
) -> None:
    path = tmp_path / "collide.db"
    _sql(path, *statements)
    with pytest.raises(SchemaMismatchError) as info:
        await _fresh(path)
    text = str(info.value)
    assert text.startswith(f"store {path} is from an incompatible version; recreate it:"), text
    assert info.value.cause is not None and cause in info.value.cause, info.value.cause
    assert isinstance(info.value.__cause__, sqlite3.OperationalError)
