# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1904 -- a store key rotation must not break the audit chain.

The defect, reproduced at engine ``fcbe2f93a`` with synthetic data: ``AesGcmCipher`` derived the
audit MAC key from the ACTIVE key only, ``audit_chain_meta`` recorded no key, and ``rotate-key`` never
touched the audit chain. So after the rotation ``docs/PHI.md`` documents -- new key B active, old key A
retired, ``rotate-key``, then drop A -- ``audit-verify`` reported the chain broken at row 1, for good
once A was gone, and ``rekey-audit`` still printed OK over it.

The design these tests pin (ADR 0193): every keyed range of the chain names its key, the first in
``audit_chain_meta.key_id`` and each later one in an ``audit.key_epoch`` row that ``rotate-key``
appends. That row is the first row of the new range, MAC'd under the NEW key, and it carries a
digest of the range it closes. So the old range stays provable after its key is dropped, and a
forged or moved range fails verification instead of redirecting it.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what the first key
rotation on a first deployment would have hit.
"""

from __future__ import annotations

import asyncio
import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import AUDIT_KEY_EPOCH_ACTION, MessageStore, audit_row_hash

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


async def _seed(store: MessageStore, tag: str, n: int) -> None:
    for i in range(n):
        await store.record_audit(tag, actor="u", detail=json.dumps({"n": i}))


async def _verify(
    path: Path, active: str, retired: tuple[str, ...] = ()
) -> tuple[bool, str | None]:
    store = await _open(path, active, retired)
    try:
        return await store.verify_audit_chain()
    finally:
        await store.close()


async def _rotate(path: Path, a: str, b: str) -> None:
    """A active -> B active with A retired -> roll the audit range, the store-level rotate-key step."""
    store = await _open(path, b, (a,))
    try:
        ok, msg = await store.roll_audit_key_epoch()
        assert ok, msg
    finally:
        await store.close()


# --- the round trip --------------------------------------------------------------------------------


async def test_a_chain_with_no_rotation_verifies(tmp_path: Path) -> None:
    """The control: the no-rotation arm must pass, so a red below is about rotation."""
    path, a = tmp_path / "control.db", generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "before", 3)
    finally:
        await store.close()
    assert (await _verify(path, a))[0]


async def test_the_documented_rotation_verifies_at_every_step(tmp_path: Path) -> None:
    path, a, b = tmp_path / "rotate.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "under-a", 3)
    finally:
        await store.close()
    ok, msg = await _verify(path, a)
    assert ok, msg

    # Step 1: B active, A retired. Before rotate-key the chain must still verify, and appends made
    # in this window stay in A's range rather than silently starting an unannounced B range.
    ok, msg = await _verify(path, b, (a,))
    assert ok, f"B active with A retired must verify before the roll: {msg}"
    store = await _open(path, b, (a,))
    try:
        await _seed(store, "pending", 1)
    finally:
        await store.close()
    ok, msg = await _verify(path, b, (a,))
    assert ok, msg

    # Step 2: rotate-key rolls the audit range; new rows land under B.
    await _rotate(path, a, b)
    store = await _open(path, b, (a,))
    try:
        await _seed(store, "under-b", 2)
    finally:
        await store.close()
    ok, msg = await _verify(path, b, (a,))
    assert ok, msg

    # Step 3: A dropped. A's range is proved by the digest the B-keyed epoch row carries.
    ok, msg = await _verify(path, b)
    assert ok, f"the chain must verify with A dropped: {msg}"
    store = await _open(path, b)
    try:
        await _seed(store, "after-drop", 1)
        ok, msg = await store.verify_audit_chain()
        assert ok, msg
    finally:
        await store.close()


async def test_two_rotations_chain_the_proof_through_a_dropped_middle_key(tmp_path: Path) -> None:
    """A -> B -> C, then drop A and B: C's epoch row proves B's range, which carries A's proof."""
    path, a, b, c = tmp_path / "twice.db", generate_key(), generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
    finally:
        await store.close()
    await _rotate(path, a, b)
    store = await _open(path, b, (a,))
    try:
        await _seed(store, "b", 2)
    finally:
        await store.close()
    await _rotate(path, b, c)
    ok, msg = await _verify(path, c)
    assert ok, msg


async def test_rolling_is_idempotent_and_refuses_a_broken_chain(tmp_path: Path) -> None:
    path, a, b = tmp_path / "roll.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 2)
        ok, msg = await store.roll_audit_key_epoch()
        assert ok and "already" in msg, msg  # nothing to roll under the same key
        await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=1")
        await store._db.commit()
    finally:
        await store.close()
    store = await _open(path, b, (a,))
    try:
        ok, msg = await store.roll_audit_key_epoch()
        assert not ok and "refusing" in msg, msg
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 0, "a refused roll must write nothing"
    finally:
        await store.close()


# --- forged and moved ranges -----------------------------------------------------------------------


async def _rotated_and_dropped(tmp_path: Path) -> tuple[Path, str, str]:
    path, a, b = tmp_path / "forge.db", generate_key(), generate_key()
    store = await _open(path, a)
    try:
        await _seed(store, "a", 3)
    finally:
        await store.close()
    await _rotate(path, a, b)
    store = await _open(path, b)
    try:
        await _seed(store, "b", 2)
    finally:
        await store.close()
    assert (await _verify(path, b))[0]
    return path, a, b


async def test_editing_a_row_of_a_dropped_keys_range_is_caught(tmp_path: Path) -> None:
    path, _a, b = await _rotated_and_dropped(tmp_path)
    store = await _open(path, b)
    try:
        await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
        await store._db.commit()
        ok, msg = await store.verify_audit_chain()
        assert not ok, "A's range must stay tamper-evident after A is dropped"
    finally:
        await store.close()


async def test_a_moved_range_boundary_is_caught(tmp_path: Path) -> None:
    path, _a, b = await _rotated_and_dropped(tmp_path)
    store = await _open(path, b)
    try:
        cur = await store._db.execute(
            "SELECT id, detail FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None
        detail = json.loads(row["detail"])
        detail["closes"]["to_id"] -= 1  # claim A's range ended one row earlier
        await store._db.execute(
            "UPDATE audit_log SET detail=? WHERE id=?", (json.dumps(detail), row["id"])
        )
        await store._db.commit()
        ok, msg = await store.verify_audit_chain()
        assert not ok and f"id={row['id']}" in (msg or ""), msg
    finally:
        await store.close()


async def test_a_forged_range_meta_is_caught(tmp_path: Path) -> None:
    """Re-pointing the first range at the key that is still configured must fail, not redirect."""
    path, _a, b = await _rotated_and_dropped(tmp_path)
    store = await _open(path, b)
    try:
        cur = await store._db.execute(
            "SELECT detail FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None
        b_id = json.loads(row["detail"])["key_id"]
        await store._db.execute("UPDATE audit_chain_meta SET key_id=? WHERE id=1", (b_id,))
        await store._db.commit()
    finally:
        await store.close()
    ok, _msg = await _verify(
        path, b
    )  # the range record is read at open, so reopen after the forgery
    assert not ok


async def test_a_leaked_retired_key_cannot_open_a_range_after_the_active_one(
    tmp_path: Path,
) -> None:
    """The reason keys are rotated is that one may have leaked. With A leaked and B active, an
    attacker who can write rows appends an epoch row switching BACK to A, MAC'd under A, then forges
    freely under A. A key never returns once rotated away from, so the switch-back fails."""
    path, a, b = await _rotated_and_dropped(tmp_path)
    leaked = make_cipher(a).audit_mac_key()
    store = await _open(path, b, (a,))
    try:
        cur = await store._db.execute(
            "SELECT row_hash, detail FROM audit_log WHERE action=? ORDER BY id",
            (AUDIT_KEY_EPOCH_ACTION,),
        )
        first = await cur.fetchone()
        assert first is not None
        a_id = json.loads(first["detail"])["closes"]["key_id"]
        cur = await store._db.execute("SELECT row_hash FROM audit_log ORDER BY id DESC LIMIT 1")
        head = await cur.fetchone()
        assert head is not None
        detail = json.dumps({"key_id": a_id, "closes": {}}, sort_keys=True)
        forged = audit_row_hash(
            head["row_hash"],
            ts=1.0,
            actor="mallory",
            action=AUDIT_KEY_EPOCH_ACTION,
            channel_id=None,
            detail=detail,
            key=leaked,
        )
        await store._db.execute(
            "INSERT INTO audit_log (ts, actor, action, channel_id, detail, client, row_hash)"
            " VALUES (?,?,?,?,?,?,?)",
            (1.0, "mallory", AUDIT_KEY_EPOCH_ACTION, None, detail, None, forged),
        )
        await store._db.commit()
        ok, _msg = await store.verify_audit_chain()
        assert not ok
    finally:
        await store.close()


# --- the CLI surface -------------------------------------------------------------------------------


def test_rotate_key_then_audit_verify_round_trip_through_the_cli(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, a, b = tmp_path / "cli.db", generate_key(), generate_key()

    async def seed() -> None:
        store = await _open(db, a)
        try:
            await _seed(store, "a", 3)
        finally:
            await store.close()

    asyncio.run(seed())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", a)
    assert main(["audit-verify", "--db", str(db)]) == 0

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", b)
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED", a)
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()
    assert main(["rotate-key", "--db", str(db)]) == 0, capsys.readouterr()
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()

    monkeypatch.delenv("MEFOR_STORE_ENCRYPTION_KEYS_RETIRED")
    capsys.readouterr()
    assert main(["audit-verify", "--db", str(db)]) == 0, capsys.readouterr()


def test_rekey_audit_does_not_print_ok_over_a_chain_that_does_not_verify(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, a = tmp_path / "rekey.db", generate_key()

    async def seed_and_tamper() -> None:
        store = await _open(db, a)
        try:
            await _seed(store, "a", 3)
            await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
            await store._db.commit()
        finally:
            await store.close()

    asyncio.run(seed_and_tamper())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", a)
    assert main(["rekey-audit", "--db", str(db)]) != 0
    out = capsys.readouterr().out
    assert "OK" not in out and "FAIL" in out, out


# --- the server backends, offline ------------------------------------------------------------------


def _rows_across_a_rotation(a_key: bytes, b_key: bytes) -> list[dict[str, object]]:
    """Three rows under A, a range row under B closing them, two rows under B -- the shape
    ``rotate-key`` leaves, built here with the shared helpers so both backends read one fixture."""
    from messagefoundry.store.crypto import audit_key_id
    from messagefoundry.store.store import audit_epoch_detail, audit_range_closing

    rows: list[dict[str, object]] = []
    prev = ""

    def add(action: str, detail: str | None, key: bytes) -> None:
        nonlocal prev
        rid = len(rows) + 1
        row: dict[str, object] = {
            "id": rid,
            "ts": float(rid),
            "actor": "u",
            "action": action,
            "channel_id": None,
            "detail": detail,
            "client": None,
        }
        prev = audit_row_hash(
            prev,
            ts=float(rid),
            actor="u",
            action=action,
            channel_id=None,
            detail=detail,
            key=key,
        )
        row["row_hash"] = prev
        rows.append(row)

    for i in range(3):
        add("a", json.dumps({"n": i}), a_key)
    closes = audit_range_closing(rows, key_id=audit_key_id(a_key), from_id=1)
    add(AUDIT_KEY_EPOCH_ACTION, audit_epoch_detail(audit_key_id(b_key), closes), b_key)
    for i in range(2):
        add("b", json.dumps({"n": i}), b_key)
    return rows


@pytest.mark.parametrize("backend", ["postgres", "sqlserver"])
async def test_both_server_backends_verify_across_a_rotation_with_the_old_key_dropped(
    backend: str,
) -> None:
    """The real ``verify_audit_chain`` of each server backend, driven offline through the same
    bare-instance seam the Transit rider uses. Their live-database legs run on a hosted runner."""
    from typing import Any

    from messagefoundry.store.crypto import audit_key_id
    from tests.test_asvs_transit_audit_mac_server_backends import _bare

    a_key, b_key = b"a" * 32, b"b" * 32
    rows = _rows_across_a_rotation(a_key, b_key)
    store = _bare(backend, mac_key=b_key)  # A dropped: only B is held
    store._audit_keyed_from = 1
    store._audit_first_key_id = audit_key_id(a_key)

    async def _fetchall(_sql: str, *_a: Any, **_kw: Any) -> list[dict[str, Any]]:
        return rows

    store._fetchall = _fetchall
    ok, msg = await store.verify_audit_chain()
    assert ok, f"{backend}: {msg}"

    rows[1]["actor"] = "mallory"  # a row of the dropped key's range
    ok, msg = await store.verify_audit_chain()
    assert not ok and "id=4" in (msg or ""), (
        f"{backend}: the closing range row must catch it: {msg}"
    )
