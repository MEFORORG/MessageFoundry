# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1915 -- ``rotate-key`` is offline-only, so it must refuse a store an engine holds open.

The defect, reproduced at engine ``87d70eccc`` with synthetic data: ``rotate-key`` said "run with the
engine stopped" in its help and docstring, and nothing checked. It ran to OK against a SQLite store
another connection held open, which is how a serving engine holds it. A live engine keeps appending
under the range it read at open, so a rotation beside it races the audit chain and the cipher columns.

The fix uses the lock SQLite already keeps. In WAL mode every open connection holds a SHARED lock on
the database file for as long as it is open, so a connection in EXCLUSIVE locking mode cannot read
while any other is open. ``rotate-key`` makes that probe before it opens the store and refuses when it
fails. It cannot see an engine started after the probe; that window is stated in ``_rotate_key``.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment's
operator would have hit by rotating without stopping the service.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import AUDIT_KEY_EPOCH_ACTION, MessageStore

_AT_REST_ENV = (
    "MEFOR_STORE_ENCRYPTION_KEY",
    "MEFOR_STORE_ENCRYPTION_KEY_FILE",
    "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED",
    "MEFOR_STORE_KEY_PROVIDER",
    "MEFOR_STORE_CIPHER_PROVIDER",
)


async def _open(path: Path, active: str, retired: tuple[str, ...] = ()) -> MessageStore:
    cipher = make_cipher(active, retired)
    return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


async def _seed(path: Path, active: str) -> None:
    store = await _open(path, active)
    try:
        for i in range(3):
            await store.record_audit("a", actor="u", detail=json.dumps({"n": i}))
    finally:
        await store.close()


def _epoch_rows(path: Path) -> int:
    conn = sqlite3.connect(path)
    try:
        row = conn.execute(
            "SELECT COUNT(*) FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        ).fetchone()
        return int(row[0])
    finally:
        conn.close()


@pytest.fixture
def rotation(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> tuple[Path, str, str]:
    """A store seeded under A, with the environment set for rotating to B."""
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, a, b = tmp_path / "live.db", generate_key(), generate_key()
    asyncio.run(_seed(db, a))
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", b)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", a)
    return db, a, b


def test_the_control_a_store_nobody_holds_rotates(
    rotation: tuple[Path, str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """Without this arm a refusal below could be the probe failing on every store."""
    db, _a, _b = rotation
    assert main(["rotate-key", "--db", str(db)]) == 0, capsys.readouterr()
    assert _epoch_rows(db) == 1


async def test_rotate_key_refuses_while_an_engine_store_holds_the_file(
    rotation: tuple[Path, str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """The store opened exactly as ``serve`` opens it: the writer connection and the read pool."""
    db, a, b = rotation
    engine = await _open(db, b, (a,))
    try:
        # main() runs its own event loop, so it runs off this one, as a separate command would.
        code = await asyncio.to_thread(main, ["rotate-key", "--db", str(db)])
    finally:
        await engine.close()
    captured = capsys.readouterr()
    assert code == 2, captured
    assert "OK:" not in captured.out, captured.out
    assert "open in another process" in captured.err, captured.err
    assert _epoch_rows(db) == 0, "a refused rotation must write nothing"


def test_rotate_key_refuses_while_a_plain_wal_connection_holds_the_file(
    rotation: tuple[Path, str, str], capsys: pytest.CaptureFixture[str]
) -> None:
    """The lock the probe reads is SQLite's, so any open connection counts, not only an engine."""
    db, _a, _b = rotation
    other = sqlite3.connect(db)
    try:
        other.execute("SELECT COUNT(*) FROM audit_log").fetchone()
        assert main(["rotate-key", "--db", str(db)]) == 2
    finally:
        other.close()
    assert "open in another process" in capsys.readouterr().err
    assert main(["rotate-key", "--db", str(db)]) == 0, "closing the holder must clear the refusal"


def test_the_probe_does_not_create_a_store(tmp_path: Path) -> None:
    from messagefoundry.__main__ import _sqlite_store_held_elsewhere

    missing = tmp_path / "absent.db"
    assert not _sqlite_store_held_elsewhere(str(missing))
    assert not missing.exists()
