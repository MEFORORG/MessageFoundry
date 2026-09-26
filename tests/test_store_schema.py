# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1720: the SQLite store verifies its live schema on open.

Every ``CREATE`` in ``_SCHEMA`` is ``IF NOT EXISTS`` and every ``_migrate`` step is an additive guarded
``ALTER``, so an object an incompatible version left under an expected name is skipped rather than
fixed. Before this check, a v0.3.2 store opened cleanly and failed later, at the first preset use, with
``no such column: owner_user_id``. These tests pin the refusal and the one-sided rule: missing things
refuse, extra things are tolerated.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store import MessageStore
from messagefoundry.store.schema_verify import (
    IndexShape,
    SchemaMismatchError,
    SchemaShape,
    schema_differences,
)
from messagefoundry.store.store import _SCHEMA

# The search_presets DDL as release v0.3.2 shipped it, copied from `git show
# v0.3.2:messagefoundry/store/store.py` (the table and its index; comments trimmed). Embedded rather than
# read from the tag at test time: a shallow CI clone carries no tags.
_V032_SEARCH_PRESETS = """
CREATE TABLE IF NOT EXISTS search_presets (
    id         TEXT PRIMARY KEY,
    owner      TEXT NOT NULL,
    name       TEXT NOT NULL,
    criteria   TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    last_used_at REAL
);
CREATE UNIQUE INDEX IF NOT EXISTS ux_search_presets_owner_name ON search_presets(owner, name);
"""


async def _fresh(path: Path) -> None:
    store = await MessageStore.open(path)
    await store.close()


def _sql(path: Path, script: str) -> None:
    conn = sqlite3.connect(path)
    try:
        conn.executescript(script)
    finally:
        conn.close()


async def test_a_fresh_store_opens_and_reopens(tmp_path: Path) -> None:
    db = tmp_path / "fresh.db"
    await _fresh(db)
    await _fresh(db)


async def test_the_v032_search_presets_table_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "v032.db"
    _sql(db, _V032_SEARCH_PRESETS)
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    text = str(info.value)
    assert "table 'search_presets' is missing column 'owner_user_id'" in text
    assert (
        "index 'ux_search_presets_owner_name' is on search_presets(owner, name) [unique],"
        " expected on search_presets(owner_user_id, name) [unique]"
    ) in text
    # The remedy leads, because the paths that print an uncaught error cut it at about 200 chars.
    assert text.startswith(
        f"store {db} is from an incompatible version; recreate it: move the file"
    )
    assert isinstance(info.value, sqlite3.DatabaseError)  # so the CLI reports it and exits 2
    # Only search_presets differs from what this version builds, so nothing else is named.
    assert text.count("table '") == 1 and text.count("index '") == 1


# Plausible Windows service data paths. The 200-character cut in safe_exc bites on both, and the
# longer one is where an instruction placed at the END of the lead used to be cut off.
_SERVICE_PATHS = (
    r"C:\ProgramData\MessageFoundry\data\messagefoundry.db",
    r"C:\ProgramData\MessageFoundry\data\stores\production\instance-a\messagefoundry.db",
)
_KEYED_LEAD = (
    "is from an incompatible version: set a NEW store key, then move it and its -wal/-shm aside and"
    " restart."
)
_KEYED_DETAIL = (
    " Make the key with `messagefoundry gen-key`, `messagefoundry protect-key --generate`, or your"
    " key provider. Keep the old key in MEFOR_STORE_ENCRYPTION_KEYS_RETIRED: the moved file, uploads"
    " and backups still need it. Restarting under the old key would zero its AES-GCM use count, which"
    " lives in the store. If you set [secret_rotation].store_key_last_rotated, update it."
)


def _lead_survives_the_cut(text: str, db: Path, lead: str) -> None:
    from messagefoundry.redaction import safe_exc

    for service_path in _SERVICE_PATHS:
        rendered = safe_exc(SchemaMismatchError(text.replace(str(db), service_path)))
        assert f"store {service_path} {lead}" in rendered


async def test_a_keyed_refusal_names_a_new_store_key(tmp_path: Path) -> None:
    # The AES-GCM use count lives in the store file (measured: a count of 2**31 in one store, 0 in a
    # fresh store under the same key), so recreating under the SAME key is the reset gcm_bound.py
    # refuses to offer. The keyed remedy must send the operator to a new key instead.
    from messagefoundry.store.crypto import generate_key, make_cipher

    db = tmp_path / "keyed.db"
    _sql(db, _V032_SEARCH_PRESETS)
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db, cipher=make_cipher(generate_key()))
    text = str(info.value)
    assert text.startswith(f"store {db} {_KEYED_LEAD}{_KEYED_DETAIL} Differences: ")
    _lead_survives_the_cut(text, db, _KEYED_LEAD)


async def test_a_keyed_store_opened_without_its_key_still_gets_the_new_key_remedy(
    tmp_path: Path,
) -> None:
    # An operator shell without the service's key opens the store keyless. The file's own count row
    # says it is keyed, and the same-key reset must not be what that operator is told to do.
    from messagefoundry.store.crypto import generate_key, make_cipher

    db = tmp_path / "keyed-then-keyless.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    await store.close()
    _sql(db, "DROP TABLE search_presets;" + _V032_SEARCH_PRESETS)
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert str(info.value).startswith(f"store {db} {_KEYED_LEAD}")


async def test_a_keyless_refusal_does_not_mention_a_key(tmp_path: Path) -> None:
    db = tmp_path / "plain.db"
    _sql(db, _V032_SEARCH_PRESETS)
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    text = str(info.value)
    assert "key" not in text.removeprefix(f"store {db} ").split(" Differences: ")[0]
    assert "gen-key" not in text and "RETIRED" not in text
    _lead_survives_the_cut(text, db, text.removeprefix(f"store {db} ").split(" Differences: ")[0])


async def test_the_refusal_releases_the_file_so_the_remedy_works(tmp_path: Path) -> None:
    db = tmp_path / "v032.db"
    _sql(db, _V032_SEARCH_PRESETS)
    with pytest.raises(SchemaMismatchError):
        await MessageStore.open(db)
    for suffix in ("", "-wal", "-shm"):
        side = db.with_name(db.name + suffix)
        if side.exists():
            side.rename(side.with_name(side.name + ".old"))
    await _fresh(db)


async def test_a_refusal_rolls_the_migrations_back(tmp_path: Path) -> None:
    # The pre-ADR-0060 FIFO index is one _migrate DROPs. Refused, the store must still hold it, so the
    # file the remedy sets aside is the one the old version wrote rather than a half-upgraded one.
    db = tmp_path / "rollback.db"
    await _fresh(db)
    _sql(
        db,
        "DROP TABLE search_presets;"
        + _V032_SEARCH_PRESETS
        + "CREATE INDEX ix_queue_fifo_in ON queue(stage, channel_id, created_at);",
    )
    with pytest.raises(SchemaMismatchError):
        await MessageStore.open(db)
    conn = sqlite3.connect(db)
    try:
        left = conn.execute(
            "SELECT 1 FROM sqlite_master WHERE name = 'ix_queue_fifo_in'"
        ).fetchall()
    finally:
        conn.close()
    assert left == [(1,)]


async def test_an_integer_primary_key_that_lost_its_row_id_is_refused(tmp_path: Path) -> None:
    # CREATE TABLE AS SELECT keeps the columns and drops the key, so `id` stops being the row id and a
    # new row gets NULL. No index exists to miss: an INTEGER PRIMARY KEY never has one.
    db = tmp_path / "rowid.db"
    await _fresh(db)
    _sql(
        db,
        "CREATE TABLE ce_copy AS SELECT * FROM connection_event;"
        " DROP TABLE connection_event;"
        " ALTER TABLE ce_copy RENAME TO connection_event;",
    )
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert "table 'connection_event' column 'id' is not its INTEGER PRIMARY KEY" in str(info.value)


@pytest.mark.parametrize(
    "ddl",
    [
        pytest.param("id INTEGER PRIMARY KEY DESC, {rest}) ", id="desc-key"),
        pytest.param("id INTEGER PRIMARY KEY, {rest}) WITHOUT ROWID", id="without-rowid"),
    ],
)
async def test_an_integer_key_that_is_not_the_row_id_is_refused(tmp_path: Path, ddl: str) -> None:
    # Both spellings declare `id INTEGER PRIMARY KEY` and neither makes it the row id: SQLite gives
    # each an ordinary column plus a key index, so an insert that omits `id` stores NULL or fails.
    db = tmp_path / "notrowid.db"
    await _fresh(db)
    conn = sqlite3.connect(db)
    try:
        rest = ", ".join(
            f"{r[1]} {r[2]}"
            for r in conn.execute("PRAGMA table_info(connection_event)")
            if r[1] != "id"
        )
    finally:
        conn.close()
    _sql(
        db,
        f"DROP TABLE connection_event; CREATE TABLE connection_event ({ddl.format(rest=rest)};",
    )
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert "table 'connection_event' column 'id' is not its INTEGER PRIMARY KEY" in str(info.value)


async def test_a_without_rowid_key_index_is_part_of_the_shape() -> None:
    # A WITHOUT ROWID table's key index has no sqlite_master row; the shape must still carry it.
    import aiosqlite

    from messagefoundry.store.schema_verify import read_schema_shape
    from messagefoundry.store.store import _await_connection_worker_exit

    db = await aiosqlite.connect(":memory:")
    try:
        await db.execute("CREATE TABLE pair (a TEXT, b TEXT, PRIMARY KEY (a, b)) WITHOUT ROWID")
        shape = await read_schema_shape(db)
    finally:
        await db.close()
        await _await_connection_worker_exit(db)
    assert shape.constraint_indexes == {IndexShape("pair", ("a", "b"), True, False)}
    assert shape.rowid_columns == {}


async def test_an_index_with_a_different_collation_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "coll.db"
    await _fresh(db)
    _sql(
        db,
        "DROP INDEX ix_queue_fifo_in_seq;"
        " CREATE INDEX ix_queue_fifo_in_seq ON queue(stage, channel_id COLLATE NOCASE, status DESC);",
    )
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert (
        "index 'ix_queue_fifo_in_seq' is on queue(stage, channel_id COLLATE NOCASE, status DESC),"
        " expected on queue(stage, channel_id, status)"
    ) in str(info.value)


async def test_an_index_name_taken_on_another_table_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "collide.db"
    await _fresh(db)
    _sql(
        db,
        "DROP INDEX ix_queue_fifo_in_seq;"
        " CREATE INDEX ix_queue_fifo_in_seq ON messages(channel_id);",
    )
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert (
        "index 'ix_queue_fifo_in_seq' is on messages(channel_id),"
        " expected on queue(stage, channel_id, status)"
    ) in str(info.value)


async def test_an_index_with_the_right_name_and_wrong_columns_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "cols.db"
    await _fresh(db)
    _sql(db, "DROP INDEX ix_queue_fifo_in_seq; CREATE INDEX ix_queue_fifo_in_seq ON queue(stage);")
    with pytest.raises(SchemaMismatchError, match=r"ix_queue_fifo_in_seq' is on queue\(stage\),"):
        await MessageStore.open(db)


async def test_an_index_that_lost_its_uniqueness_is_refused(tmp_path: Path) -> None:
    db = tmp_path / "uniq.db"
    await _fresh(db)
    _sql(
        db,
        "DROP INDEX ux_search_presets_owner_name;"
        " CREATE INDEX ux_search_presets_owner_name ON search_presets(owner_user_id, name);",
    )
    with pytest.raises(SchemaMismatchError) as info:
        await MessageStore.open(db)
    assert (
        "index 'ux_search_presets_owner_name' is on search_presets(owner_user_id, name),"
        " expected on search_presets(owner_user_id, name) [unique]"
    ) in str(info.value)


async def test_extra_columns_and_indexes_are_tolerated(tmp_path: Path) -> None:
    db = tmp_path / "extra.db"
    await _fresh(db)
    _sql(
        db,
        "ALTER TABLE messages ADD COLUMN operator_note TEXT;"
        " CREATE INDEX ix_operator_own ON messages(operator_note);"
        " CREATE TABLE operator_scratch (x INTEGER);",
    )
    await _fresh(db)


async def test_the_expected_shape_includes_what_only_migrate_builds(tmp_path: Path) -> None:
    # ix_queue_body_ref and ux_users_federated_subject exist only in _migrate, not in _SCHEMA: the
    # derivation has to run both, or a missing migration-built index would pass unnoticed.
    from messagefoundry.store.schema_verify import _expected_shape

    shape = await _expected_shape(_SCHEMA, MessageStore._migrate)
    assert shape.named_indexes["ix_queue_body_ref"] == IndexShape(
        "queue", ("body_ref",), False, False
    )
    assert shape.named_indexes["ux_users_federated_subject"].partial
    assert "owner_user_id" in shape.columns["search_presets"]
    # The queue lease `owner` column is a server-backend column; the SQLite queue has none.
    assert "owner" not in shape.columns["queue"]


def _shape(
    columns: dict[str, set[str]],
    named: dict[str, IndexShape] | None = None,
    constraint: set[IndexShape] | None = None,
) -> SchemaShape:
    return SchemaShape(
        {t: frozenset(c) for t, c in columns.items()}, {}, named or {}, frozenset(constraint or ())
    )


def test_a_missing_table_and_a_missing_named_index_are_reported() -> None:
    idx = IndexShape("t", ("a",), False, False)
    expected = _shape({"t": {"a"}, "u": {"b"}}, named={"ix_t_a": idx})
    live = _shape({"t": {"a"}, "u": set()})
    assert schema_differences(expected, live) == [
        "table 'u' is missing",
        "index 'ix_t_a' is missing (expected on t(a))",
    ]


def test_a_constraint_index_is_matched_by_shape_not_by_name() -> None:
    pk = IndexShape("t", ("a", "b"), True, False)
    expected = _shape({"t": {"a", "b"}}, constraint={pk})
    # The same shape under a CREATE INDEX name satisfies it; its absence does not.
    assert schema_differences(expected, _shape({"t": {"a", "b"}}, named={"x": pk})) == []
    assert schema_differences(expected, _shape({"t": {"a", "b"}})) == [
        "table 't' is missing the constraint index on t(a, b) [unique]"
    ]


async def test_a_table_whose_name_starts_with_sqlite_is_still_read(tmp_path: Path) -> None:
    # `_` is a LIKE wildcard: an unescaped 'sqlite_%' would drop this table from the expected shape.
    import aiosqlite

    from messagefoundry.store.schema_verify import read_schema_shape
    from messagefoundry.store.store import _await_connection_worker_exit

    db = await aiosqlite.connect(":memory:")
    try:
        await db.execute("CREATE TABLE sqlitex_meta (a TEXT)")
        shape = await read_schema_shape(db)
    finally:
        await db.close()
        await _await_connection_worker_exit(db)
    assert shape.columns == {"sqlitex_meta": frozenset({"a"})}
