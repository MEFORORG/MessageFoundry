# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Saved-search preset store CRUD (BACKLOG #151, ADR 0136) — per-user + encrypted criteria.

Postgres/SQL Server parity is CI's job; these run on SQLite."""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
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
        preset_id="p1", owner="op", name="ACME ADT", criteria=CRIT
    )
    assert eid == "p1" and replaced is False

    listed = await store.list_search_presets("op")
    assert [p["name"] for p in listed] == ["ACME ADT"]
    assert "criteria" not in listed[0]  # list NEVER carries criteria

    got = await store.get_search_preset(preset_id="p1", owner="op")
    assert got is not None and json.loads(got["criteria"]) == json.loads(CRIT)

    # On-disk criteria is ciphertext, not the PHI-shaped needle.
    async with store._read() as db:
        cur = await db.execute("SELECT criteria FROM search_presets WHERE id='p1'")
        raw = (await cur.fetchone())["criteria"]
    assert raw.startswith("mfenc:") and "MRN12345" not in raw


async def test_presets_are_owner_scoped(store: MessageStore) -> None:
    await store.upsert_search_preset(preset_id="pa", owner="alice", name="mine", criteria=CRIT)
    # Bob can't see, get, or delete Alice's preset.
    assert await store.list_search_presets("bob") == []
    assert await store.get_search_preset(preset_id="pa", owner="bob") is None
    assert await store.delete_search_preset(preset_id="pa", owner="bob") is False
    # Alice still has it.
    assert await store.get_search_preset(preset_id="pa", owner="alice") is not None


async def test_save_by_name_replaces(store: MessageStore) -> None:
    id1, r1 = await store.upsert_search_preset(
        preset_id="first", owner="op", name="dup", criteria=CRIT
    )
    other = json.dumps({"field_path": "PID-3", "field_value": "X", "target": "raw"})
    id2, r2 = await store.upsert_search_preset(
        preset_id="second", owner="op", name="dup", criteria=other
    )
    assert r1 is False and r2 is True
    assert id2 == id1  # the id is reused (stable cell-AAD across a replace)
    # Only one row, carrying the NEW criteria (decrypts under the reused id's AAD).
    listed = await store.list_search_presets("op")
    assert len(listed) == 1
    got = await store.get_search_preset(preset_id=id1, owner="op")
    assert got is not None and json.loads(got["criteria"]) == json.loads(other)


async def test_delete_is_idempotent(store: MessageStore) -> None:
    await store.upsert_search_preset(preset_id="p", owner="op", name="n", criteria=CRIT)
    assert await store.delete_search_preset(preset_id="p", owner="op") is True
    assert await store.delete_search_preset(preset_id="p", owner="op") is False
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
