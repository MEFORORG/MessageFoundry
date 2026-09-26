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
    assert "Recreate it" in text
    # Only search_presets differs from what this version builds, so nothing else is named.
    assert text.count("table '") == 1 and text.count("index '") == 1


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
        {t: frozenset(c) for t, c in columns.items()}, named or {}, frozenset(constraint or ())
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
