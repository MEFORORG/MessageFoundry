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
import traceback
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

import aiosqlite
import pytest

from messagefoundry.redaction import _COUNT_OPENER, safe_exc
from messagefoundry.store import MessageStore
from messagefoundry.store.schema_verify import (
    _ORDINARY_TABLE,
    SchemaMismatchError,
    _remedy,
    is_schema_step_error,
    live_schema_differences,
    read_schema_shape,
    run_schema_step,
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


#: Every table with a flag saying whether it is virtual, so one walk both counts the tables it saw
#: and finds the virtual ones (a virtual table's ``type`` is ``table`` too). The flag is the module's
#: own predicate, so the pin and the reads it guards cannot disagree (BACKLOG #6719 item 9).
_TABLES_FLAGGED_VIRTUAL = (
    f"SELECT m.name, NOT ({_ORDINARY_TABLE}) FROM sqlite_master AS m WHERE m.type = 'table'"
)
#: Every schema object with a flag saying whether it is a view or a trigger, so one walk both counts
#: what it saw and finds those (a query for them alone returns nothing on the built schema, so it
#: cannot show it ran). The flag is in the SQL, so the negative control below pins the same predicate.
_OBJECTS_FLAGGED_VIEW_OR_TRIGGER = "SELECT name, type IN ('view', 'trigger') FROM sqlite_master"


async def test_the_expected_shape_holds_no_virtual_table() -> None:
    # The reads skip virtual tables, so one this build created would never be verified. Adding one
    # must fail here until the check learns to compare it.
    async with _connected(":memory:") as db:
        db.row_factory = aiosqlite.Row
        await db.executescript(_SCHEMA)
        await MessageStore._migrate(db)
        async with db.execute(_TABLES_FLAGGED_VIRTUAL) as cur:
            tables = [tuple(r) for r in await cur.fetchall()]
        async with db.execute(_OBJECTS_FLAGGED_VIEW_OR_TRIGGER) as cur:
            objects = [tuple(r) for r in await cur.fetchall()]
    # Positive control: the walk saw the built schema (40 tables when this floor was set), so the
    # absence below cannot pass on an empty walk.
    assert len(tables) >= 30, f"the scratch schema holds only {len(tables)} tables"
    # The view walk's own floor (105 objects when it was set: 40 tables, 65 indexes). The tables are
    # among these objects, so it adds nothing to the floor above beyond catching a query narrowed to
    # fewer than 30 rows, such as a views-only one; the vacuous-absence lint needs it on this walk.
    assert len(objects) >= 30, f"the scratch schema holds only {len(objects)} objects"
    virtual = [name for name, is_virtual in tables if is_virtual]
    assert virtual == []
    # The reads skip views too, so a view this build created would never be verified either
    # (BACKLOG #6719 item 10). And the foreign-object remedy tells the operator to drop a view or a
    # trigger that stops an upgrade, which is safe only while this build creates neither.
    views_or_triggers = [name for name, flagged in objects if flagged]
    assert views_or_triggers == []


async def test_the_virtual_table_probe_finds_one_without_fts5(tmp_path: Path) -> None:
    # Negative control for the pin above that needs no fts5 (BACKLOG #6719 item 8): a planted
    # virtual table is flagged, an ordinary one is not, and the view flag marks a view and a trigger.
    path = tmp_path / "probe.db"
    _sql(
        path,
        "CREATE TABLE plain (a)",
        "CREATE VIEW v AS SELECT 1",
        "CREATE TRIGGER tr AFTER INSERT ON plain BEGIN SELECT 1; END",
    )
    _plant_unloaded_virtual_table(path, "planted")
    async with _connected(path) as db:
        async with db.execute(_TABLES_FLAGGED_VIRTUAL) as cur:
            rows = {r[0]: bool(r[1]) for r in await cur.fetchall()}
        async with db.execute(_OBJECTS_FLAGGED_VIEW_OR_TRIGGER) as cur:
            flagged = {name for name, is_one in await cur.fetchall() if is_one}
    assert rows == {"plain": False, "planted": True}
    assert flagged == {"v", "tr"}


async def test_a_planted_ordinary_table_with_rootpage_zero_is_not_skipped(tmp_path: Path) -> None:
    # A rootpage of 0 does not make a row virtual: its stored SQL is an ordinary CREATE TABLE, so
    # the reads do not skip it, and reading the salt table it names fails as corrupt.
    path = tmp_path / "rootless.db"
    _sql(path, "CREATE TABLE cipher_meta (key_id TEXT)", "INSERT INTO cipher_meta VALUES ('k')")
    _sql(
        path,
        "PRAGMA writable_schema = ON",
        "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table',"
        " 'store_salt', 'store_salt', 0, 'CREATE TABLE store_salt (salt BLOB)')",
    )
    from messagefoundry.store.schema_verify import _counts_under_a_dek

    async with _connected(path) as db:
        shape = await read_schema_shape(db)
        assert set(shape.columns) == {"cipher_meta", "store_salt"}
        with pytest.raises(sqlite3.DatabaseError, match="malformed"):
            await _counts_under_a_dek(db)


@pytest.mark.parametrize(
    "cipher_meta",
    [
        "CREATE TABLE cipher_meta (key_id TEXT, invocations INTEGER)",
        "CREATE VIEW cipher_meta AS SELECT 'k' AS key_id, 1 AS invocations",
    ],
    ids=["ordinary-table", "view"],
)
async def test_a_readable_count_leans_to_the_new_key_remedy(
    tmp_path: Path, cipher_meta: str
) -> None:
    # A readable count, whatever object holds the name, picks the remedy that cannot zero a DEK's
    # count. Pinned so the store_salt ordinary-table rule is not copied onto cipher_meta unread.
    from messagefoundry.store.schema_verify import _counts_under_a_dek

    path = tmp_path / "count.db"
    _sql(path, cipher_meta)
    if cipher_meta.startswith("CREATE TABLE"):
        _sql(path, "INSERT INTO cipher_meta VALUES ('k', 1)")
    async with _connected(path) as db:
        assert await _counts_under_a_dek(db) is True


@_NEEDS_FTS5
async def test_the_virtual_table_probe_finds_one() -> None:
    # Negative control for the pin above: the same query does flag a virtual table when one exists,
    # and only that one (fts5's shadow tables are ordinary tables).
    async with _connected(":memory:") as db:
        await db.execute("CREATE VIRTUAL TABLE probe USING fts5(a)")
        async with db.execute(_TABLES_FLAGGED_VIRTUAL) as cur:
            rows = [tuple(r) for r in await cur.fetchall()]
    assert [name for name, is_virtual in rows if is_virtual] == ["probe"]


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


# --- BACKLOG #6719 item 3: a foreign view or trigger that stops the upgrade ------------------------


def _preset_columns(path: Path) -> set[str]:
    conn = sqlite3.connect(path)
    try:
        return {r[1] for r in conn.execute("PRAGMA table_info(search_presets)")}
    finally:
        conn.close()


@pytest.mark.parametrize(
    ("kind", "dependent", "drop"),
    [
        pytest.param("view", "CREATE VIEW vv AS SELECT x FROM vt", "DROP VIEW vv", id="view"),
        pytest.param(
            "trigger",
            "CREATE TRIGGER tt AFTER INSERT ON users BEGIN SELECT x FROM vt; END",
            "DROP TRIGGER tt",
            id="trigger",
        ),
    ],
)
async def test_a_foreign_object_that_stops_a_migration_gets_the_drop_remedy(
    tmp_path: Path, kind: str, dependent: str, drop: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A 0.3.2 preset table needs the RENAME COLUMN migration, and SQLite re-checks every view and
    # trigger after it. One that reads an unloaded module fails that check, naming itself. The store
    # is otherwise this build's, so the remedy is to drop that object, not to recreate the store.
    # A short relative path keeps the remedy inside the cut whatever the runner's temp path is.
    monkeypatch.chdir(tmp_path)
    path = Path("foreign.db")
    await _fresh(path)
    _sql(path, "ALTER TABLE search_presets RENAME COLUMN owner_user_id TO owner")
    _plant_unloaded_virtual_table(path, "vt")
    name, table = dependent.split()[2], "vv" if kind == "view" else "users"
    conn = sqlite3.connect(path)
    try:
        conn.execute("PRAGMA writable_schema = ON")
        conn.execute(
            "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES (?, ?, ?, 0, ?)",
            (kind, name, table, dependent),
        )
        conn.commit()
    finally:
        conn.close()
    with pytest.raises(SchemaMismatchError) as info:
        await _fresh(path)
    cause = info.value.cause
    assert cause is not None and cause.startswith(f"error in {kind} {name}: no such module"), cause
    text = str(info.value)
    assert text.startswith(
        f"store {path}: save the CREATE statement of the {kind} '{name}' from sqlite_master, drop"
        " it, and restart."
    ), text
    assert "recreate" not in text and "NEW store key" not in text, text
    # The remedy is true: with that object dropped, the same migration runs and the open succeeds.
    _sql(path, drop)
    await _fresh(path)
    assert "owner_user_id" in _preset_columns(path)


# --- BACKLOG #6720 item 4: the verify's own read --------------------------------------------------


async def test_a_shape_error_from_the_verify_read_is_refused_with_the_remedy(
    tmp_path: Path,
) -> None:
    # No statement of the script or the migrations touches shared_body, so the first read of it is
    # the verify's column read. A virtual table whose stored SQL the ordinary-table predicate does
    # not recognise (two spaces) is read there, and its unloaded module raises.
    path = tmp_path / "read.db"
    await _fresh(path)
    _sql(
        path,
        "DROP TABLE shared_body",
        "PRAGMA writable_schema = ON",
        "INSERT INTO sqlite_master (type, name, tbl_name, rootpage, sql) VALUES ('table',"
        " 'shared_body', 'shared_body', 0,"
        " 'CREATE  VIRTUAL TABLE shared_body USING no_such_module(x)')",
    )
    with pytest.raises(SchemaMismatchError) as info:
        await _fresh(path)
    text = str(info.value)
    assert text.startswith(f"store {path} is from an incompatible version; recreate it:"), text
    assert "The schema step failed: no such module" in text, text
    cause = info.value.__cause__
    assert isinstance(cause, sqlite3.OperationalError)
    # The verify's read raised it, not the script or a migration.
    frames = {f.name for f in traceback.extract_tb(cause.__traceback__)}
    assert {"run_schema_step", "read_schema_shape"} <= frames, frames


def _real_sqlite_error(statement: str) -> sqlite3.OperationalError:
    conn = sqlite3.connect(":memory:")
    try:
        with pytest.raises(sqlite3.OperationalError) as info:
            conn.execute(statement)
    finally:
        conn.close()
    return info.value


async def _verify_raising(
    monkeypatch: pytest.MonkeyPatch, target: str, exc: sqlite3.OperationalError
) -> BaseException:
    """``verify_live_schema`` with ``target`` raising ``exc``; returns what the verify raised."""
    from messagefoundry.store import schema_verify

    # Warm the expected shape first: its scratch build calls read_schema_shape too, and on a cold
    # cache the patched error would come from there rather than from the live read.
    await schema_verify._expected_shape(_SCHEMA, MessageStore._migrate)

    async def raising(*_args: object, **_kwargs: object) -> object:
        raise exc

    monkeypatch.setattr(schema_verify, target, raising)
    async with _connected(":memory:") as db:
        with pytest.raises(sqlite3.OperationalError) as info:
            await schema_verify.verify_live_schema(
                db,
                schema=_SCHEMA,
                migrate=MessageStore._migrate,
                path="x.db",
                counts_under_dek=False,
            )
    return info.value


async def test_a_read_error_that_is_not_a_shape_keeps_its_own_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Control: a real SQLITE_ERROR whose message names no shape is not given the remedy.
    exc = _real_sqlite_error("SELEC 1")
    assert exc.sqlite_errorcode & 0xFF == sqlite3.SQLITE_ERROR
    assert await _verify_raising(monkeypatch, "read_schema_shape", exc) is exc
    frames = {f.name for f in traceback.extract_tb(exc.__traceback__)}
    assert "run_schema_step" in frames, frames


async def test_a_failure_building_the_expected_shape_keeps_its_own_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # A shape message from this build's own scratch build is this build's defect, which recreating
    # the store would not fix, so only the live read is classified.
    exc = _real_sqlite_error("SELECT missing FROM sqlite_master")
    assert is_schema_step_error(exc), str(exc)
    assert await _verify_raising(monkeypatch, "_expected_shape", exc) is exc


@pytest.mark.parametrize(
    ("view_name", "cause", "found"),
    [
        pytest.param("vv", "error in view vv: no such module: m", ("view", "vv"), id="plain"),
        pytest.param(
            "vv", "error in view vv after rename: no such column: c", ("view", "vv"), id="suffix"
        ),
        pytest.param("a:b", "error in view a:b: no such module: m", ("view", "a:b"), id="colon"),
        pytest.param("users", "error in view users: no such module: m", None, id="expected-table"),
        pytest.param(
            "USERS", "error in view USERS after rename: no such column: c", None, id="expected-case"
        ),
        pytest.param(
            "ix_queue_fifo_in_seq",
            "error in view ix_queue_fifo_in_seq: no such module: m",
            None,
            id="expected-index",
        ),
        pytest.param("vv", "error in table vv: no such module: m", None, id="a-table"),
        pytest.param("vv", "error in view other: no such module: m", None, id="not-in-the-file"),
    ],
)
async def test_the_foreign_object_is_matched_against_the_file(
    tmp_path: Path, view_name: str, cause: str, found: tuple[str, str] | None
) -> None:
    from messagefoundry.store.schema_verify import _foreign_objects

    path = tmp_path / "named.db"
    _sql(path, f'CREATE VIEW "{view_name}" AS SELECT 1 AS a')
    async with _connected(path) as db:
        assert await _foreign_objects(db, cause) == ((found,) if found else ())


@pytest.mark.parametrize(
    ("views", "reads", "statement", "expected_cause", "found"),
    [
        pytest.param(
            ("vv", "vv after"),
            "c FROM t",
            "ALTER TABLE t DROP COLUMN c",
            "error in view vv after drop column: no such column: c",
            ("vv",),
            id="vv-after-the-change",
        ),
        pytest.param(
            ("vv after", "vv"),
            "c FROM t",
            "ALTER TABLE t DROP COLUMN c",
            "error in view vv after after drop column: no such column: c",
            ("vv", "vv after"),
            id="vv-after-after-the-change",
        ),
        pytest.param(
            ("vv", "vv after"),
            "missing FROM t",
            "ALTER TABLE t RENAME TO t2",
            "error in view vv: no such column: missing",
            ("vv",),
            id="vv-before-the-change",
        ),
        pytest.param(
            ("vv after", "vv"),
            "missing FROM t",
            "ALTER TABLE t RENAME TO t2",
            "error in view vv after: no such column: missing",
            ("vv after",),
            id="vv-after-before-the-change",
        ),
        pytest.param(
            ("vv", "vv after drop column"),
            "c FROM t",
            "ALTER TABLE t DROP COLUMN c",
            "error in view vv after drop column: no such column: c",
            ("vv", "vv after drop column"),
            id="broken-vv-beside-a-healthy-suffix-name",
        ),
        pytest.param(
            ("vv", "vv: no such column"),
            "missing FROM t",
            "ALTER TABLE t RENAME TO t2",
            "error in view vv: no such column: missing",
            ("vv", "vv: no such column"),
            id="broken-vv-beside-a-healthy-message-name",
        ),
        pytest.param(
            ("a:b", "a"),
            "missing FROM t",
            "ALTER TABLE t RENAME TO t2",
            "error in view a:b: no such column: missing",
            ("a:b",),
            id="a-bare-colon-is-not-the-separator",
        ),
        pytest.param(
            ("users after drop column", "users"),
            "missing FROM t",
            "ALTER TABLE t RENAME TO t2",
            "error in view users after drop column: no such column: missing",
            (),
            id="a-candidate-under-an-expected-name",
        ),
    ],
)
async def test_a_name_that_is_a_prefix_of_another_is_told_apart(
    tmp_path: Path,
    views: tuple[str, str],
    reads: str,
    statement: str,
    expected_cause: str,
    found: tuple[str, ...],
) -> None:
    # Views "vv" and "vv after" both fit "error in view vv after ...", so the longest name alone
    # would tell the operator to drop "vv after" when "vv" stopped the change. Each cause is
    # SQLite's own text, and views[0] is the broken view. A view already broken fails SQLite's
    # first check, with no suffix; a view the change breaks fails its re-check after the change,
    # with the "after drop column" suffix. Where both names rank first the code does not pick
    # between them, so both are returned and the remedy names neither. In the suffix-name pair the
    # text itself cannot settle the pair, since the healthy view's own name holds the suffix. The
    # message-name pair and "vv after after drop column" are ones a list of SQLite's messages or
    # suffixes could settle, and the code keeps none (see _foreign_objects). SQLite writes ": "
    # after a name, so "a" is no candidate for "a:b". A view under a name this build creates among
    # the candidates gives the plain remedy, so nothing is returned.
    from messagefoundry.store.schema_verify import _foreign_objects

    path = tmp_path / "prefix.db"
    _sql(path, "CREATE TABLE t (a, c)", "CREATE TABLE u (c)")
    broken, healthy = views
    _sql(path, f'CREATE VIEW "{broken}" AS SELECT {reads}')
    _sql(path, f'CREATE VIEW "{healthy}" AS SELECT c FROM u')
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.OperationalError) as info:
            conn.execute(statement)
    finally:
        conn.close()
    assert str(info.value) == expected_cause
    async with _connected(path) as db:
        assert await _foreign_objects(db, expected_cause) == tuple(("view", n) for n in found)


_SERVICE_PATH = r"C:\ProgramData\MessageFoundry\data\stores\production\instance-a\messagefoundry.db"
_CAUSE = "error in view {} after drop column: no such column: c"


def _named(name: str) -> tuple[str, str]:
    """The one-name remedy for view ``name`` on _SERVICE_PATH, and the whole message."""
    remedy = (
        f"store {_SERVICE_PATH}: save the CREATE statement of the view {name!r} from sqlite_master,"
        " drop it, and restart."
    )
    message = (
        f"{remedy} This build did not create it, and it stops the store's upgrade. The schema step"
        f" failed: {_CAUSE.format(name)}."
    )
    return remedy, message


async def _refusal(path: Path, broken: str) -> SchemaMismatchError:
    # The refusal for one broken view, which the DROP COLUMN re-check names.
    _sql(path, "CREATE TABLE t (a, c)", f'CREATE VIEW "{broken}" AS SELECT c FROM t')
    async with _connected(path) as db:
        with pytest.raises(SchemaMismatchError) as info:
            await run_schema_step(
                db,
                db.execute("ALTER TABLE t DROP COLUMN c"),
                path=_SERVICE_PATH,
                counts_under_dek=False,
            )
    assert isinstance(info.value.__cause__, sqlite3.OperationalError)
    return info.value


def _plain(cause: str) -> str:
    return f"store {_SERVICE_PATH} {_remedy(False)} The schema step failed: {cause}."


async def test_one_name_is_named_only_while_its_whole_remedy_survives_the_cut(
    tmp_path: Path,
) -> None:
    # safe_exc cuts a printed error at 200 characters, marking the cut with _COUNT_OPENER. The
    # longest name whose remedy ends before that marker is named, with the whole text pinned; one
    # character more and the remedy would be cut, so the plain remedy names no object.
    stem = "daily_census_by_unit_and_attending_for_the_weekly_report_of_the_quality_team"
    fits = 0
    for k in range(1, len(stem) + 1):
        remedy, message = _named(stem[:k])
        rendered = safe_exc(SchemaMismatchError(message))
        if not rendered.startswith(f"SchemaMismatchError: {remedy}"):
            break
        fits = k
    assert 0 < fits < len(stem)
    name, longer = stem[:fits], stem[: fits + 1]

    remedy, message = _named(name)
    refusal = await _refusal(tmp_path / "fits.db", name)
    assert str(refusal) == message
    assert refusal.cause == _CAUSE.format(name)
    rendered = safe_exc(refusal)
    assert rendered.startswith(f"SchemaMismatchError: {remedy}"), rendered

    remedy, message = _named(longer)
    rendered = safe_exc(SchemaMismatchError(message))
    assert remedy not in rendered and _COUNT_OPENER in rendered, rendered
    refusal = await _refusal(tmp_path / "cut.db", longer)
    assert str(refusal) == _plain(_CAUSE.format(longer))


@pytest.mark.parametrize(
    ("healthy", "reads", "statement", "cause"),
    [
        pytest.param(
            "vv after drop column",
            "c FROM t",
            "ALTER TABLE t DROP COLUMN c",
            "error in view vv after drop column: no such column: c",
            id="healthy-suffix-name",
        ),
        pytest.param(
            "vv: no such column",
            "missing FROM t",
            "ALTER TABLE t RENAME TO t2",
            "error in view vv: no such column: missing",
            id="healthy-message-name",
        ),
    ],
)
async def test_two_candidates_get_the_plain_remedy(
    tmp_path: Path, healthy: str, reads: str, statement: str, cause: str
) -> None:
    # A broken vv beside a healthy view. The text fits both, so naming either could tell the
    # operator to drop the healthy one.
    path = tmp_path / "both.db"
    _sql(path, "CREATE TABLE t (a, c)", "CREATE TABLE u (c)")
    _sql(path, f"CREATE VIEW vv AS SELECT {reads}")
    _sql(path, f'CREATE VIEW "{healthy}" AS SELECT c FROM u')
    async with _connected(path) as db:
        with pytest.raises(SchemaMismatchError) as info:
            await run_schema_step(
                db, db.execute(statement), path=_SERVICE_PATH, counts_under_dek=False
            )
    assert info.value.cause == cause
    assert str(info.value) == _plain(cause)


async def test_a_last_rank_only_match_gets_the_plain_remedy(tmp_path: Path) -> None:
    # A broken TEMP view "vv x" is outside the main schema the match reads, so the only name the
    # text fits is the healthy "vv", with the remainder " x: ...". That is no form SQLite writes
    # after the object it names, so "vv" is not named and the remedy is main's plain one.
    path = tmp_path / "temp.db"
    _sql(path, "CREATE TABLE t (a)", "CREATE VIEW vv AS SELECT a FROM t")
    async with _connected(path) as db:
        await db.execute('CREATE TEMP VIEW "vv x" AS SELECT missing FROM t')
        with pytest.raises(SchemaMismatchError) as info:
            await run_schema_step(
                db,
                db.execute("ALTER TABLE t RENAME TO t2"),
                path=_SERVICE_PATH,
                counts_under_dek=False,
            )
    cause = "error in view vv x: no such column: missing"
    assert info.value.cause == cause
    assert str(info.value) == _plain(cause)


@pytest.mark.parametrize(
    ("kind", "names", "cause", "found"),
    [
        pytest.param(
            "view",
            ("vv", "vv after"),
            "error in view vv after rename: no such module: m",
            ("vv",),
            id="vv-after-rename",
        ),
        pytest.param(
            "view",
            ("vv", "vv after"),
            "error in view vv after after rename: no such module: m",
            ("vv", "vv after"),
            id="vv-after-after-rename",
        ),
        pytest.param(
            "view",
            ("vv", "vv: x"),
            "error in view vv: x after rename: no such module: m",
            ("vv", "vv: x"),
            id="colon-name-after-rename",
        ),
        pytest.param(
            "view",
            ("vv", "vv: x"),
            "error in view vv: no such module: m",
            ("vv",),
            id="colon-name-prefix",
        ),
        pytest.param(
            "view",
            ("vv", "vv after x"),
            "error in view vv after x: no such module: m",
            ("vv", "vv after x"),
            id="colon-outranks-a-shorter-after",
        ),
        pytest.param(
            "trigger",
            ("tr", "tr after"),
            "error in trigger tr after rename: no such module: m",
            ("tr",),
            id="trigger-after-rename",
        ),
        pytest.param(
            "trigger",
            ("tr", "tr after"),
            "error in trigger tr after after rename: no such module: m",
            ("tr", "tr after"),
            id="trigger-after-after-rename",
        ),
    ],
)
async def test_a_prefix_name_is_told_apart_in_the_rename_recheck(
    tmp_path: Path, kind: str, names: tuple[str, str], cause: str, found: tuple[str, ...]
) -> None:
    # The RENAME COLUMN migration's re-check writes the " after rename" suffix. These causes are
    # written out in SQLite's form rather than raised, so one test can cover a colon name and a
    # trigger pair without a view or trigger built to break under each.
    from messagefoundry.store.schema_verify import _foreign_objects

    path = tmp_path / "prefix.db"
    _sql(path, "CREATE TABLE t (a)")
    for name in names:
        if kind == "view":
            _sql(path, f'CREATE VIEW "{name}" AS SELECT a FROM t')
        else:
            _sql(path, f'CREATE TRIGGER "{name}" AFTER INSERT ON t BEGIN SELECT 1; END')
    async with _connected(path) as db:
        assert await _foreign_objects(db, cause) == tuple((kind, n) for n in found)


# --- BACKLOG #6720 item 1: a foreign view using an unloaded function or collation ----------------


@pytest.mark.parametrize(
    "view",
    [
        pytest.param("CREATE VIEW vf AS SELECT f(name) AS n FROM search_presets", id="function"),
        pytest.param(
            "CREATE VIEW vf AS SELECT name FROM search_presets ORDER BY name COLLATE mycoll",
            id="collation",
        ),
    ],
)
async def test_a_foreign_view_using_an_unloaded_function_or_collation_stops_nothing(
    tmp_path: Path, view: str
) -> None:
    # Measured on the local SQLite: neither the script, the RENAME COLUMN migration nor the verify
    # fails on such a view, so there is no failure for the step test to classify. Reading the view
    # fails, as the control below shows, and the open succeeds all the same.
    path = tmp_path / "foreign-view.db"
    await _fresh(path)
    _sql(path, "ALTER TABLE search_presets RENAME COLUMN owner_user_id TO owner")
    conn = sqlite3.connect(path)
    try:
        conn.create_function("f", 1, lambda x: x)
        conn.create_collation("mycoll", lambda a, b: (a > b) - (a < b))
        conn.execute(view)
        conn.commit()
    finally:
        conn.close()
    # Positive control: without the function or collation loaded, reading the view does fail.
    conn = sqlite3.connect(path)
    try:
        with pytest.raises(sqlite3.OperationalError, match="no such (function|collation)"):
            conn.execute("SELECT * FROM vf").fetchall()
    finally:
        conn.close()
    await _fresh(path)
    assert "owner_user_id" in _preset_columns(path)
