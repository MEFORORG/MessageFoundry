# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Vault BACKLOG #5635: ``rotate-key`` and a sealed record under a retired key it was not given.

The user, role, approval and directory-map re-seal passes leave a record whose seal they cannot
check as it is, and only logged a count. So a run that left a role sealed under a retired key
nobody supplied printed OK and exited 0, and an operator who then dropped that key stranded the
role. Such a run now stops short: the store pass refuses before it re-encrypts any cell, so the
command exits 1, rolls nothing, writes no stamp and leaves the rotation record open. It refuses
rather than going on, because the cell pass would re-encrypt such a user's TOTP secret, which the
user's seal covers, and leave the record verifying under no key.

A record whose seal fails under a key the run holds, or is malformed, is the control. No key
re-seals it, so failing on it would fail every later run too (the BACKLOG #3181 precedent); the
run completes and says so in a note. The SQLite store contract runs here too; the Postgres and SQL
Server suites run it on their own legs.
"""

from __future__ import annotations

import asyncio
import base64
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.__main__ import main
from messagefoundry.auth.service import AuthService
from messagefoundry.config.settings import AuthSettings
from messagefoundry.pipeline.secret_rotation import ROTATION_RECORD_ID, dek_fingerprint
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.row_seal import RowSealer, RowSealError
from messagefoundry.store.store import MessageStore, require_user_seal_for_write
from tests._reseal_outcome_contract import (
    MALFORMED_SEAL,
    UNHELD_KEY_ID,
    UNHELD_SEAL,
    assert_reseal_outcome_contract,
)
from tests.test_rotate_key_rotation_record import _DEK, _OLD_DATE, _env, _key_id, _rows, _seed

#: A synthetic TOTP secret, derived so a secret scanner does not read it as a credential.
_TOTP = base64.b32encode(b"rotate-key-unheld-ab").decode("ascii")


def _raw_for(path: Path) -> Any:
    """Runs one statement on its own stdlib connection, which holds no store key."""

    async def raw(sql: str, params: tuple[Any, ...]) -> None:
        conn = sqlite3.connect(path)
        try:
            conn.execute(sql, params)
            conn.commit()
        finally:
            conn.close()

    return raw


async def _open(db: Path, key: str, *retired: str) -> MessageStore:
    cipher = make_cipher(key, retired)
    return await MessageStore.open(db, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


async def _role_with_seal(db: Path, key: str, seal: str) -> str:
    """A custom role written by the store under ``key``, then given ``seal`` outside the store."""
    store = await _open(db, key)
    try:
        service = AuthService(store, AuthSettings())
        await service.initialize()
        role_id = (
            await service.create_custom_role(
                display_name=f"r-{seal[-6:]}",
                description=None,
                permissions=["messages:replay"],
                actor="t",
            )
        ).id
    finally:
        await store.close()
    await _raw_for(db)("UPDATE roles SET seal=? WHERE id=?", (seal, role_id))
    return role_id


async def _user_with_totp(db: Path, key: str) -> None:
    store = await _open(db, key)
    try:
        await store.create_user(
            user_id="u-totp",
            username="u-totp",
            auth_provider="local",
            password_generated=False,
            audits=(),
        )
        await store.set_totp_secret("u-totp", secret=_TOTP)
    finally:
        await store.close()


def _snapshot(db: Path) -> dict[str, list[tuple[Any, ...]]]:
    """Every column of every users and roles row, read with no store key."""
    conn = sqlite3.connect(db)
    try:
        return {
            table: sorted(conn.execute(f"SELECT * FROM {table}").fetchall(), key=repr)
            for table in ("users", "roles")
        }
    finally:
        conn.close()


async def _user_seal_holds(db: Path, key: str, *retired: str) -> bool:
    store = await _open(db, key, *retired)
    try:
        record = await store._read_user_record("u-totp")
        assert record is not None
        try:
            await require_user_seal_for_write(store.row_sealer(), record)
        except RowSealError:
            return False
        return True
    finally:
        await store.close()


@pytest.fixture
def rig(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, Path, str, str]:
    monkeypatch.chdir(tmp_path)
    db, uploads = tmp_path / "rot.db", tmp_path / "uploads"
    key_a, key_b = generate_key(), generate_key()
    asyncio.run(_seed(db, uploads, key_a))
    return db, uploads, key_a, key_b


def test_a_role_under_a_retired_key_not_supplied_stops_the_run(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """The failing case: printed OK and exited 0 before #5635. The re-run after the record is
    removed is the control: the same store completes once nothing is left under that key."""
    db, uploads, key_a, key_b = rig
    role_id = asyncio.run(_role_with_seal(db, key_a, UNHELD_SEAL))
    # Rows the passes would re-seal under the new key: the built-in roles and a user with a TOTP
    # secret, all under the supplied prior key. The abort must leave every one as it was.
    asyncio.run(_user_with_totp(db, key_a))
    before = _snapshot(db)
    assert any("u-totp" in row for row in before["users"])  # control: the user is there
    _env(monkeypatch, key_b, key_a, uploads)

    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert _snapshot(db) == before  # the pre-flight refused before any pass wrote
    assert "OK:" not in captured.out
    assert "rotation aborted" in captured.err
    assert "Nothing was written by this pass" in captured.err
    assert "1 user, role, open approval or directory-map record(s) in roles" in captured.err
    assert UNHELD_KEY_ID in captured.err
    rows = asyncio.run(_rows(db, key_b, key_a))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_a))  # no stamp
    assert rows[_DEK].last_rotated == _OLD_DATE
    assert rows[ROTATION_RECORD_ID].fingerprint == dek_fingerprint(_key_id(key_b))  # still open

    asyncio.run(_raw_for(db)("DELETE FROM roles WHERE id=?", (role_id,)))
    assert main(["rotate-key", "--db", str(db)]) == 0
    assert "OK:" in capsys.readouterr().out
    rows = asyncio.run(_rows(db, key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[ROTATION_RECORD_ID].fingerprint == ""


def test_a_user_sealed_under_a_key_not_supplied_survives_until_it_is(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A user whose TOTP secret is under the first key and whose seal is under a third, as after a
    start on that third key. A run given only the first key must not touch the secret the seal
    covers, so the record still verifies under the third key after it. The remedy the error names,
    a re-run with the third key supplied, then completes and leaves the record under the new key
    alone. Before the abort, the first run re-encrypted the secret and no key opened it again."""
    db, uploads, key_a, key_b = rig
    key_c = generate_key()

    async def user_under_a() -> None:
        store = await _open(db, key_a)
        try:
            await store.create_user(
                user_id="u-totp",
                username="u-totp",
                auth_provider="local",
                password_generated=False,
                audits=(),
            )
            await store.set_totp_secret("u-totp", secret=_TOTP)
        finally:
            await store.close()

    async def touch_under_c() -> None:
        store = await _open(db, key_c, key_a)
        try:
            await store.set_user_channel_scope("u-totp", '["IB_A"]', source="manual")
        finally:
            await store.close()

    asyncio.run(user_under_a())
    asyncio.run(touch_under_c())
    assert asyncio.run(_user_seal_holds(db, key_c, key_a))  # control

    _env(monkeypatch, key_b, key_a, uploads)
    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert "rotation aborted" in captured.err and "in users" in captured.err
    assert asyncio.run(_user_seal_holds(db, key_c, key_a))  # the secret was not re-encrypted

    _env(monkeypatch, key_b, f"{key_a},{key_c}", uploads)
    assert main(["rotate-key", "--db", str(db)]) == 0, capsys.readouterr()
    assert "OK:" in capsys.readouterr().out
    assert asyncio.run(_user_seal_holds(db, key_b))


def test_a_role_whose_seal_no_key_reseals_does_not_fail_the_run(
    rig: tuple[Path, Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A malformed seal is refused by the pass as the unheld one is, but no key re-seals it, so it
    must not hold the rotation open. It is named in a note on stdout, not only in the log."""
    db, uploads, key_a, key_b = rig
    asyncio.run(_role_with_seal(db, key_a, MALFORMED_SEAL))
    _env(monkeypatch, key_b, key_a, uploads)

    assert main(["rotate-key", "--db", str(db)]) == 0
    captured = capsys.readouterr()
    assert "OK:" in captured.out and "PARTIAL:" not in captured.out
    assert "note: 1 user, role, open approval or directory-map record(s) were left" in captured.out
    # Items 5, 14 and 15: the log counts only what each pass refused, so the note does not send
    # the operator there; and a sound seal a running engine wrote is counted here too, so the
    # note says to re-run with every engine stopped before dropping the prior key.
    assert "The log names each kind" not in captured.out
    assert "stop every engine using this store and re-run before dropping" in captured.out
    assert "rotation aborted" not in captured.err
    rows = asyncio.run(_rows(db, key_b))
    assert rows[_DEK].fingerprint == dek_fingerprint(_key_id(key_b))
    assert rows[ROTATION_RECORD_ID].fingerprint == ""


def test_names_unheld_key_tells_a_key_it_holds_from_one_it_does_not() -> None:
    """The helper the command's refusal rests on: the active key, a held retired key, an unheld
    key, and a seal that names no key."""
    active, retired = b"a" * 32, b"r" * 32
    sealer = RowSealer(active, retired_keys=[retired])
    old = RowSealer(retired)
    assert not sealer.names_unheld_key(sealer.seal("role", [("x", 1)]))
    assert not sealer.names_unheld_key(old.seal("role", [("x", 1)]))
    assert sealer.names_unheld_key(UNHELD_SEAL)
    assert RowSealer(active).names_unheld_key(old.seal("role", [("x", 1)]))
    # Malformed: no id, an id no key could have, an empty id, and values that are not seals.
    for stored in (
        MALFORMED_SEAL,
        f"mfseal:v1::{'0' * 64}",
        f"mfseal:v1:zz:{'0' * 64}",
        f"mfseal:v1:{UNHELD_KEY_ID.upper()}:{'0' * 64}",
        "",
        None,
        7,
    ):
        assert not sealer.names_unheld_key(stored), stored


async def test_the_reseal_outcome_contract_holds_on_sqlite(tmp_path: Path) -> None:
    path = tmp_path / "contract.db"
    store = await MessageStore.open(path, cipher=make_cipher(generate_key(), write_v2=True))
    try:
        await assert_reseal_outcome_contract(store, _raw_for(path))
    finally:
        await store.close()
