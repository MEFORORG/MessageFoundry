# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5738: ``reseal_user_records`` (the ``rotate-key`` user pass) on the SQLite store.

Two defects, one test each, each with its control:

* The AES-GCM invocation bound was charged once, after the whole loop, and outside the writer lock
  the charge's commit needs. It is now charged after each record the pass did not refuse, a lost
  compare-and-set included, through ``checkpoint_cipher_invocations``, which takes the lock.
* The work filter used ``NOT LIKE``, which SQLite folds for ASCII case, so a record whose seal
  prefix differed from the active one only in case was skipped, neither moved nor counted refused.

The Postgres and SQL Server copies take the same change; their live suites run the pass.
"""

from __future__ import annotations

import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

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


async def test_the_bound_is_charged_per_record_through_the_locked_checkpoint(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    store, _ = keyed
    for uid in ("r-1", "r-2", "r-3"):
        await _user(store, uid)
    _rotate_sealer(store)
    charged: list[str] = []

    async def unlocked_charge() -> None:
        charged.append("unlocked")

    async def checkpoint(**_kwargs: Any) -> None:
        charged.append("checkpoint")

    monkeypatch.setattr(store, "_charge_bound_batch", unlocked_charge)
    monkeypatch.setattr(store, "checkpoint_cipher_invocations", checkpoint)
    assert await store.reseal_user_records() == (3, 0)
    assert charged == ["checkpoint"] * 3
    charged.clear()
    assert await store.reseal_user_records() == (0, 0)  # control: nothing left, nothing charged
    assert charged == []


async def test_a_seal_prefix_differing_only_in_case_is_not_skipped(
    keyed: tuple[MessageStore, Path],
) -> None:
    store, path = keyed
    await _user(store, "c-1")
    sealer = store._row_sealer
    assert isinstance(sealer, RowSealer)
    assert await store.reseal_user_records() == (0, 0)  # control: under the active key, no work
    # The fixed letters of the prefix are folded, so the case differs whatever the random key id.
    folded = f"{SEAL_PREFIX.upper()}{sealer.key_id}:bogus"
    with sqlite3.connect(path) as db:
        db.execute("UPDATE users SET authz_seal=? WHERE id=?", (folded, "c-1"))
    # Selected and refused (its seal names no key this store holds), never silently passed over.
    assert await store.reseal_user_records() == (0, 1)


# --- a compare-and-set that lost is still charged (engine PR 2989 open finding 5) -------------------
#
# The change re-encrypts the TOTP secret before the compare-and-set write, so a write that lost to a
# concurrent writer has already spent an AES-GCM invocation. The pass charged the bound only when the
# write landed, so a lost compare left that invocation to a later checkpoint: the next record's, or
# the close's settle. A hard kill before either outran the reserve-ahead by that record's spend.
# These tests pin that the pass checkpoints after a lost compare; the accounts carry no TOTP secret,
# so they do not measure the spend itself, which the checkpoint charges whatever it is.


async def test_a_lost_compare_and_set_is_still_charged(
    keyed: tuple[MessageStore, Path], monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store import store as store_module

    store, _ = keyed
    await _user(store, "l-1")
    _rotate_sealer(store)
    charged: list[str] = []

    async def checkpoint(**_kwargs: Any) -> None:
        charged.append("checkpoint")

    real_params = store_module.user_reseal_params

    def lost_compare(new: Any, old: Any) -> tuple[object, ...]:
        # The seal the compare expects is not the stored one: what a concurrent write leaves.
        *head, _seal = real_params(new, old)
        return (*head, "seal-a-concurrent-writer-left")

    monkeypatch.setattr(store, "checkpoint_cipher_invocations", checkpoint)
    monkeypatch.setattr(store_module, "user_reseal_params", lost_compare)
    assert await store.reseal_user_records() == (0, 0)  # neither re-sealed nor refused
    assert charged == ["checkpoint"]


def _server_store(cls: type[Any], charged: list[str]) -> Any:
    store = object.__new__(cls)
    store._cipher = make_cipher(generate_key(), write_v2=True)
    store._row_sealer = RowSealer(bytes(32))

    async def fetchall(*_args: Any, **_kwargs: Any) -> list[dict[str, str]]:
        return [{"id": "s-1"}]

    async def write_user_txn(_user_id: str, _change: Any) -> None:
        return None  # the compare-and-set lost

    async def charge() -> None:
        charged.append("charge")

    store._fetchall = fetchall
    store._write_user_txn = write_user_txn
    store._charge_bound_batch = charge
    return store


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_a_lost_compare_and_set_is_still_charged_on_the_server_backends(backend: str) -> None:
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.sqlserver import SqlServerStore

    charged: list[str] = []
    store = _server_store(PostgresStore if backend == "postgres" else SqlServerStore, charged)
    assert await store.reseal_user_records() == (0, 0)
    assert charged == ["charge"]
