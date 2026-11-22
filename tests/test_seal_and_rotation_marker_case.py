# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5506 and #5611: the at-open seal and ``rotate-key`` read the cipher marker byte-exact.

SQLite's ``LIKE`` folds ASCII case, so ``MFENC:...`` used to count as ciphertext. On a surface with
no ciphertext that would have left the value in plaintext and written the keyed marker. In a
rotation it would have skipped the value as already under the active key. Every synthetic value
here is made up. The SQL Server statements are pinned by source only; its live leg runs them.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store.cipher_cells import SQLITE_CIPHER_CELLS, _surface_sealed
from messagefoundry.store.crypto import (
    AesGcmCipher,
    CipherError,
    cell_aad,
    generate_key,
    make_cipher,
)
from messagefoundry.store.sqlserver import SqlServerStore
from messagefoundry.store.store import MessageStore
from tests._session_seal_contract import _user

_BIN2 = "COLLATE Latin1_General_100_BIN2"


def _reason(path: Path, connection: str) -> str:
    with sqlite3.connect(path) as db:
        row = db.execute(
            "SELECT reason FROM connection_event WHERE connection=?", (connection,)
        ).fetchone()
    return str(row[0])


def _plant_reasons(path: Path, *rows: tuple[str, str]) -> None:
    """``connection_event.reason`` is read by nothing at open, so a plant reaches the sweep alone."""
    with sqlite3.connect(path) as db:
        db.executemany(
            "INSERT INTO connection_event (ts, connection, transport, direction, kind, reason)"
            " VALUES (1.0, ?, 'mllp', 'inbound', 'k', ?)",
            rows,
        )


def _keyed_marker(path: Path, table: str, column: str) -> bool:
    with sqlite3.connect(path) as db:
        return (
            db.execute(
                "SELECT 1 FROM keyed_surface WHERE surface_table=? AND surface_column=?",
                (table, column),
            ).fetchone()
            is not None
        )


async def test_an_uppercase_marker_on_an_unsealed_surface_is_sealed(tmp_path: Path) -> None:
    path = tmp_path / "s.db"
    await (await MessageStore.open(path)).close()
    _plant_reasons(path, ("plant", "MFENC:synthetic-plant"), ("plain", "synthetic-plain"))
    cipher = make_cipher(generate_key())
    await (await MessageStore.open(path, cipher=cipher)).close()
    for name, value in (("plant", "MFENC:synthetic-plant"), ("plain", "synthetic-plain")):
        stored = _reason(path, name)
        assert stored.startswith("mfenc:"), name
        aad = cell_aad("connection_event", "reason", name, 1.0, "k")
        assert cipher.decrypt(stored, aad=aad) == value
    assert _keyed_marker(path, "connection_event", "reason")


async def test_an_uppercase_marker_on_a_keyed_surface_stays_refused_and_is_reported(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    path = tmp_path / "s.db"
    key = generate_key()
    await (await MessageStore.open(path, cipher=make_cipher(key))).close()
    assert _keyed_marker(path, "connection_event", "reason")
    _plant_reasons(path, ("plant", "MFENC:synthetic-plant"))
    with caplog.at_level(logging.WARNING):
        await (await MessageStore.open(path, cipher=make_cipher(key))).close()
    assert _reason(path, "plant") == "MFENC:synthetic-plant"
    assert any("connection_event.reason is sealed" in r.getMessage() for r in caplog.records)
    with pytest.raises(CipherError):
        make_cipher(key).decrypt(
            "MFENC:synthetic-plant", aad=cell_aad("connection_event", "reason", "plant", 1.0, "k")
        )


async def test_the_opt_out_never_seals_an_uppercase_marker_on_a_sealed_surface(
    tmp_path: Path,
) -> None:
    path = tmp_path / "s.db"
    key = generate_key()
    await (await MessageStore.open(path, cipher=make_cipher(key))).close()
    _plant_reasons(path, ("plant", "MFENC:synthetic-plant"), ("plain", "synthetic-plain"))
    await (await MessageStore.open(path, cipher=make_cipher(key, allow_unmarked=True))).close()
    assert _reason(path, "plant") == "MFENC:synthetic-plant"
    assert _reason(path, "plain").startswith("mfenc:")  # control: the opt-out still seals plaintext


async def test_a_null_key_row_fails_the_keyed_open_instead_of_spinning(tmp_path: Path) -> None:
    path = tmp_path / "s.db"
    await (await MessageStore.open(path)).close()
    with sqlite3.connect(path) as db:
        db.execute(
            "INSERT INTO shared_body (hash, body, refcount, created_at)"
            " VALUES (NULL, 'synthetic-plain', 1, 0)"
        )
    with pytest.raises(CipherError, match=r"shared_body\.body"):
        await asyncio.wait_for(MessageStore.open(path, cipher=make_cipher(generate_key())), 10)
    # The surface rolled back whole: no marker, and the value as it was.
    assert not _keyed_marker(path, "shared_body", "body")
    with sqlite3.connect(path) as db:
        assert db.execute("SELECT body FROM shared_body").fetchone()[0] == "synthetic-plain"


def test_the_walk_reads_an_uppercase_marker_as_the_store_now_does(tmp_path: Path) -> None:
    spec = next(c for c in SQLITE_CIPHER_CELLS if (c.table, c.column) == ("state", "value"))
    conn = sqlite3.connect(tmp_path / "w.db")
    conn.execute("CREATE TABLE state (namespace TEXT, key TEXT, value)")
    conn.execute("INSERT INTO state VALUES ('n', 'k', 'MFENC:synthetic-plant')")
    assert not _surface_sealed(conn, spec, {"state"})
    conn.execute("INSERT INTO state VALUES ('n', 'j', 'mfenc:v1:x')")
    assert _surface_sealed(conn, spec, {"state"})  # control: a real marker still counts
    conn.close()


def test_the_sql_server_scans_compare_the_marker_in_binary() -> None:
    for fn in (SqlServerStore._seal_surface, SqlServerStore._surface_holds_ciphertext):
        assert _BIN2 in inspect.getsource(fn), fn.__name__
    rotation = inspect.getsource(SqlServerStore._rotation_scan)
    assert _BIN2 in rotation and "DATALENGTH" in rotation
    body = inspect.getsource(SqlServerStore.reencrypt_to_active)
    assert " NOT LIKE ?" not in body  # every scan goes through _rotation_scan


async def _rotation_rig(tmp_path: Path) -> tuple[Path, str, str, AesGcmCipher]:
    path = tmp_path / "r.db"
    old, new = generate_key(), generate_key()
    old_cipher = make_cipher(old)
    assert isinstance(old_cipher, AesGcmCipher)
    store = await MessageStore.open(path, cipher=old_cipher)
    await _user(store, "u-refused")
    await _user(store, "u-unsealed")
    await store.close()
    return path, old, new, old_cipher


def _user_cell(path: Path, user_id: str) -> str:
    with sqlite3.connect(path) as db:
        return str(db.execute("SELECT totp_secret FROM users WHERE id=?", (user_id,)).fetchone()[0])


def _set_totp(path: Path, user_id: str, value: str, *, clear_seal: bool = False) -> None:
    with sqlite3.connect(path) as db:
        db.execute("UPDATE users SET totp_secret=? WHERE id=?", (value, user_id))
        if clear_seal:
            db.execute("UPDATE users SET authz_seal='' WHERE id=?", (user_id,))


async def test_rotation_leaves_a_refused_record_and_rotates_an_unsealed_one(
    tmp_path: Path,
) -> None:
    path, old, new, old_cipher = await _rotation_rig(tmp_path)
    refused = old_cipher.encrypt(
        "JBSWY3DPSYNTHETIC", aad=cell_aad("users", "totp_secret", "u-refused")
    )
    unsealed = old_cipher.encrypt(
        "JBSWY3DPSYNTHETIC", aad=cell_aad("users", "totp_secret", "u-unsealed")
    )
    _set_totp(path, "u-refused", refused)  # the seal no longer covers these bytes
    _set_totp(path, "u-unsealed", unsealed, clear_seal=True)
    cipher = make_cipher(new, [old])
    assert isinstance(cipher, AesGcmCipher)
    store = await MessageStore.open(path, cipher=cipher)
    try:
        await store.reencrypt_to_active()
    finally:
        await store.close()
    assert _user_cell(path, "u-refused") == refused
    assert _user_cell(path, "u-unsealed").startswith(cipher.active_marker_prefix)


async def test_rotation_still_aborts_on_a_refused_record_with_an_unopenable_secret(
    tmp_path: Path,
) -> None:
    path, old, new, _ = await _rotation_rig(tmp_path)
    foreign = make_cipher(generate_key())
    planted = foreign.encrypt("synthetic", aad=cell_aad("users", "totp_secret", "u-refused"))
    _set_totp(path, "u-refused", planted)
    store = await MessageStore.open(path, cipher=make_cipher(new, [old]))
    try:
        with pytest.raises(CipherError):
            await store.reencrypt_to_active()
    finally:
        await store.close()
    assert _user_cell(path, "u-refused") == planted


async def test_rotation_aborts_on_the_uppercase_of_the_active_prefix(tmp_path: Path) -> None:
    path = tmp_path / "r.db"
    key = generate_key()
    cipher = make_cipher(key)
    assert isinstance(cipher, AesGcmCipher)
    await (await MessageStore.open(path, cipher=cipher)).close()
    plant = f"{cipher.active_marker_prefix.upper()}synthetic"
    _plant_reasons(path, ("plant", plant))
    store = await MessageStore.open(path, cipher=make_cipher(key))
    try:
        with pytest.raises(CipherError):
            await store.reencrypt_to_active()
    finally:
        await store.close()
    assert _reason(path, "plant") == plant
