# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Saved-search preset store CRUD (BACKLOG #151, ADR 0136) — per-user + encrypted criteria.

Postgres/SQL Server parity is CI's job; these run on SQLite."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.store.crypto import Cipher, generate_key, make_cipher
from messagefoundry.store.store import MessageStore

CRIT = json.dumps({"content": "MRN12345", "target": "raw", "message_type": "ADT^A01"})


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    # A key + aad_bind so criteria is v2-encrypted (cell-AAD bound) at rest.
    cipher = make_cipher(generate_key(), write_v2=True)
    s = await MessageStore.open(tmp_path / "presets.db", cipher=cipher)
    try:
        yield s
    finally:
        await s.close()


async def test_create_encrypts_and_lists(store: MessageStore, tmp_path: Path) -> None:
    eid, replaced = await store.upsert_search_preset(
        preset_id="p1", owner_user_id="op", name="ACME ADT", criteria=CRIT
    )
    assert eid == "p1" and replaced is False

    listed = await store.list_search_presets("op")
    assert [p["name"] for p in listed] == ["ACME ADT"]
    assert "criteria" not in listed[0]  # list NEVER carries criteria

    got = await store.get_search_preset(preset_id="p1", owner_user_id="op")
    assert got is not None and json.loads(got["criteria"]) == json.loads(CRIT)

    # On-disk criteria is ciphertext, not the PHI-shaped needle.
    async with store._read() as db:
        cur = await db.execute("SELECT criteria FROM search_presets WHERE id='p1'")
        row = await cur.fetchone()
        assert row is not None
        raw = row["criteria"]
    assert raw.startswith("mfenc:") and "MRN12345" not in raw


async def test_presets_are_owner_scoped(store: MessageStore) -> None:
    await store.upsert_search_preset(
        preset_id="pa", owner_user_id="alice", name="mine", criteria=CRIT
    )
    # Bob can't see, get, or delete Alice's preset.
    assert await store.list_search_presets("bob") == []
    assert await store.get_search_preset(preset_id="pa", owner_user_id="bob") is None
    assert await store.delete_search_preset(preset_id="pa", owner_user_id="bob") is False
    # Alice still has it.
    assert await store.get_search_preset(preset_id="pa", owner_user_id="alice") is not None


async def test_save_by_name_replaces(store: MessageStore) -> None:
    id1, r1 = await store.upsert_search_preset(
        preset_id="first", owner_user_id="op", name="dup", criteria=CRIT
    )
    other = json.dumps({"field_path": "PID-3", "field_value": "X", "target": "raw"})
    id2, r2 = await store.upsert_search_preset(
        preset_id="second", owner_user_id="op", name="dup", criteria=other
    )
    assert r1 is False and r2 is True
    assert id2 == id1  # the id is reused (stable cell-AAD across a replace)
    # Only one row, carrying the NEW criteria (decrypts under the reused id's AAD).
    listed = await store.list_search_presets("op")
    assert len(listed) == 1
    got = await store.get_search_preset(preset_id=id1, owner_user_id="op")
    assert got is not None and json.loads(got["criteria"]) == json.loads(other)


async def test_delete_is_idempotent(store: MessageStore) -> None:
    await store.upsert_search_preset(preset_id="p", owner_user_id="op", name="n", criteria=CRIT)
    assert await store.delete_search_preset(preset_id="p", owner_user_id="op") is True
    assert await store.delete_search_preset(preset_id="p", owner_user_id="op") is False
    assert await store.list_search_presets("op") == []


def test_the_queue_lease_column_is_still_named_owner() -> None:
    """GUARD FOR BACKLOG #1232, AND IT PROTECTS A DIFFERENT TABLE THAN THE ONE THAT WAS RENAMED.

    Two columns named ``owner`` live in these modules and they mean unrelated things:
    ``search_presets.owner`` held an ``Identity.user_id`` and was renamed to ``owner_user_id``
    because the name misled; ``queue.owner`` is the ROW-CLAIM LEASE HOLDER, written by the
    claim/release path, and is central to at-least-once delivery.

    ``store.py:380`` names the distinction in its own words: *"Distinct from the row-claim ``owner``
    column"*. A future rename done by SYMBOL rather than by reading -- the obvious way to do it, and
    the way the item's own reference count invites -- would rename BOTH. Nothing else in the suite
    would notice: the preset tests would stay green because their column is correct, and a lease
    regression surfaces as delivery behaviour, not as a schema error.

    So this asserts the column that must NOT move, which is the only assertion that can fail for the
    right reason."""
    from messagefoundry.store import postgres, sqlserver

    pg = "\n".join(postgres._SCHEMA)
    assert "owner            TEXT," in pg, "queue.owner vanished from the PostgreSQL DDL"
    ms = "\n".join(sqlserver._SCHEMA)
    assert "owner NVARCHAR(256) NULL" in ms, "queue.owner vanished from the SQL Server DDL"

    # And the renamed one is genuinely renamed on both, so this test cannot pass vacuously by
    # asserting a state that predates the change.
    assert "owner_user_id TEXT NOT NULL" in pg
    assert "owner_user_id NVARCHAR(256) NOT NULL" in ms


# The search_presets DDL as release v0.3.2 shipped it on SQLite, copied from `git show
# v0.3.2:messagefoundry/store/store.py` (the table and its index; comments trimmed). Embedded rather
# than read from the tag at test time: a shallow CI clone carries no tags. 0.3.2 wrote the owner's
# USERNAME into `owner`; this version keys on the user id in `owner_user_id`.
V032_SEARCH_PRESETS = """
CREATE TABLE search_presets (
    id         TEXT PRIMARY KEY,
    owner      TEXT NOT NULL,
    name       TEXT NOT NULL,
    criteria   TEXT,
    created_at REAL NOT NULL,
    updated_at REAL NOT NULL,
    last_used_at REAL
);
CREATE UNIQUE INDEX ux_search_presets_owner_name ON search_presets(owner, name);
"""


async def _seed_v032_store(db: Path, cipher: Cipher) -> None:
    """Write presets with this version, then move them into the 0.3.2 table under usernames.

    Sealing them first shows the criteria still open after the migration: they are bound to the
    preset id, which it leaves alone. ``ghost`` matches no account. ``pc`` was last saved before
    the ``carol`` account existed (created at 1.0), so an earlier holder of that username wrote it;
    ``pr`` was created then too, but the current ``carol`` saved it again at 2.0. ``system`` is the
    no-auth identity: its rows cannot be told from a deleted account's named ``system``."""
    import sqlite3

    s = await MessageStore.open(db, cipher=cipher)
    try:
        for uid, name in (("u-alice", "alice"), ("u-bob", "bob"), ("u-carol", "carol")):
            await s.create_user(
                user_id=uid,
                username=name,
                auth_provider="local",
                now=1.0,
                password_generated=False,
            )
        for pid, owner, name, now in (
            ("pa", "alice", "ACME ADT", None),
            ("pb", "bob", "ACME ADT", None),
            ("pg", "ghost", "orphan", None),
            ("pc", "carol", "inherited", 0.5),
            ("pr", "carol", "resaved", 0.5),
            ("pr", "carol", "resaved", 2.0),
            ("ps", "system", "no-auth", None),
        ):
            await s.upsert_search_preset(
                preset_id=pid, owner_user_id=owner, name=name, criteria=CRIT, now=now
            )
    finally:
        await s.close()

    conn = sqlite3.connect(db)
    try:
        rows = conn.execute(
            "SELECT id, owner_user_id, name, criteria, created_at, updated_at, last_used_at"
            " FROM search_presets"
        ).fetchall()
        conn.executescript("DROP TABLE search_presets;" + V032_SEARCH_PRESETS)
        conn.executemany("INSERT INTO search_presets VALUES (?,?,?,?,?,?,?)", rows)
        conn.commit()
        # Positive control: the table really is in the 0.3.2 shape before the open.
        cols = {r[1] for r in conn.execute("PRAGMA table_info(search_presets)")}
        assert "owner" in cols and "owner_user_id" not in cols
    finally:
        conn.close()


async def test_a_v032_preset_table_is_migrated_on_open(tmp_path: Path) -> None:
    """BACKLOG #1909: a 0.3.2 ``search_presets`` table opens, keeps its owners' presets, and lists
    and deletes by user id. A preset no current account owned is dropped, not inherited."""
    db = tmp_path / "v032.db"
    cipher = make_cipher(generate_key(), write_v2=True)
    await _seed_v032_store(db, cipher)

    for reopened in (False, True):  # the second open finds nothing to move
        s = await MessageStore.open(db, cipher=cipher)
        try:
            listed = await s.list_search_presets("u-alice")
            assert [p["id"] for p in listed] == ["pa"]
            got = await s.get_search_preset(preset_id="pa", owner_user_id="u-alice")
            assert got is not None and json.loads(got["criteria"]) == json.loads(CRIT)
            assert [p["id"] for p in await s.list_search_presets("u-bob")] == ["pb"]
            assert [p["id"] for p in await s.list_search_presets("u-carol")] == ["pr"]
            assert await s.list_search_presets("system") == []
            async with s._read() as rdb:
                cur = await rdb.execute("SELECT id FROM search_presets ORDER BY id")
                assert [r["id"] for r in await cur.fetchall()] == ["pa", "pb", "pr"]
            if reopened:
                await s.delete_user("u-bob")
                assert await s.list_search_presets("u-bob") == []
                assert [p["id"] for p in await s.list_search_presets("u-alice")] == ["pa"]
        finally:
            await s.close()


async def test_a_refused_open_leaves_the_v032_preset_table_untouched(tmp_path: Path) -> None:
    """BACKLOG #1909: the migration runs in the open's transaction. A store refused for another
    stale object keeps its 0.3.2 presets table, rows and column name, for the remedy to set aside."""
    import sqlite3

    from messagefoundry.store.schema_verify import SchemaMismatchError

    db = tmp_path / "v032-refused.db"
    cipher = make_cipher(generate_key(), write_v2=True)
    await _seed_v032_store(db, cipher)
    conn = sqlite3.connect(db)
    try:
        conn.executescript(
            "DROP INDEX ix_queue_fifo_in_seq; CREATE INDEX ix_queue_fifo_in_seq ON queue(stage);"
        )
    finally:
        conn.close()

    with pytest.raises(SchemaMismatchError):
        await MessageStore.open(db, cipher=cipher)

    conn = sqlite3.connect(db)
    try:
        cols = {r[1] for r in conn.execute("PRAGMA table_info(search_presets)")}
        owners = sorted(r[0] for r in conn.execute("SELECT owner FROM search_presets"))
    finally:
        conn.close()
    assert "owner" in cols and "owner_user_id" not in cols
    assert owners == ["alice", "bob", "carol", "carol", "ghost", "system"]
