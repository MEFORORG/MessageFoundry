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
