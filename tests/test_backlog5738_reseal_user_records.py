# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5738: ``reseal_user_records`` (the ``rotate-key`` user pass) on the SQLite store.

Two defects, one test each, each with its control:

* The AES-GCM invocation bound was charged once, after the whole loop, and outside the writer lock
  the charge's commit needs. It is now charged after each committed record, under the lock.
* The work filter used ``NOT LIKE``, which SQLite folds for ASCII case, so a record whose seal
  prefix differed from the active one only in case was skipped, neither moved nor counted refused.

The Postgres and SQL Server copies take the same change; their live suites run the pass.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path

import pytest

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import SEAL_PREFIX, RowSealer
from messagefoundry.store.store import MessageStore
from tests._session_seal_contract import _user


@pytest.fixture
async def keyed(tmp_path: Path) -> AsyncIterator[tuple[MessageStore, Path]]:
    path = tmp_path / "reseal.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        yield store, path
    finally:
        await store.close()


def _rotate_sealer(store: MessageStore) -> None:
    """Make the store's current seal key a retired one, so every record has re-seal work."""
    old = store._row_sealer
    assert isinstance(old, RowSealer)
    store._row_sealer = RowSealer(bytes(32), retired_keys=[old._key])


async def test_the_bound_is_charged_per_record_under_the_writer_lock(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = keyed
    for uid in ("r-1", "r-2", "r-3"):
        await _user(store, uid)
    _rotate_sealer(store)
    held: list[bool] = []

    async def charge() -> None:
        held.append(store._lock.locked())

    monkeypatch.setattr(store, "_charge_bound_batch", charge)
    assert await store.reseal_user_records() == (3, 0)
    assert held == [True, True, True]
    held.clear()
    assert await store.reseal_user_records() == (0, 0)  # control: nothing left, nothing charged
    assert held == []


async def test_a_seal_prefix_differing_only_in_case_is_not_skipped(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    await _user(store, "c-1")
    sealer = store._row_sealer
    assert isinstance(sealer, RowSealer) and sealer.key_id.upper() != sealer.key_id
    assert await store.reseal_user_records() == (0, 0)  # control: under the active key, no work
    folded = f"{SEAL_PREFIX}{sealer.key_id.upper()}:bogus"
    with sqlite3.connect(path) as db:
        db.execute("UPDATE users SET authz_seal=? WHERE id=?", (folded, "c-1"))
    # Selected and refused (its seal names no key this store holds), never silently passed over.
    assert await store.reseal_user_records() == (0, 1)
