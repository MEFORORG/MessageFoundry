# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1945 -- ``rotate-key`` must not report OK over an audit chain ``audit-verify`` calls broken.

The defect, reproduced at engine ``87d70eccc`` with synthetic data: once the key of the audit chain's
CURRENT range is dropped from the keyring, the store routes new rows to the active key (#1904 keeps the
audit trail writing rather than stopping sign-in). ``rotate-key`` read that routing as the chain's own
state, so it printed ``OK: audit chain already under the active key`` and exited 0, while
``audit-verify`` on the same store reported the chain broken. An operator reading OK takes the rotation
as complete.

The fix: the roll checks that the key the chain's own current range names is configured, and it
verifies the chain before it reports the no-op. Either failure is a refusal, never OK.

Severity is conditional (CLAUDE.md section 0): zero deployments, so this is what a first deployment's
key rotation would have hit.
"""

from __future__ import annotations

import asyncio
import json
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


async def _seed(path: Path, active: str, tag: str, n: int, retired: tuple[str, ...] = ()) -> None:
    store = await _open(path, active, retired)
    try:
        for i in range(n):
            await store.record_audit(tag, actor="u", detail=json.dumps({"n": i}))
    finally:
        await store.close()


async def _roll(path: Path, active: str, retired: tuple[str, ...] = ()) -> tuple[bool, str]:
    store = await _open(path, active, retired)
    try:
        return await store.roll_audit_key_epoch()
    finally:
        await store.close()


async def _verify(path: Path, active: str, retired: tuple[str, ...] = ()) -> bool:
    store = await _open(path, active, retired)
    try:
        return (await store.verify_audit_chain())[0]
    finally:
        await store.close()


async def _epoch_rows(path: Path, active: str) -> int:
    store = await _open(path, active)
    try:
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM audit_log WHERE action=?", (AUDIT_KEY_EPOCH_ACTION,)
        )
        row = await cur.fetchone()
        assert row is not None
        return int(row["n"])
    finally:
        await store.close()


# --- the store-level roll ----------------------------------------------------------------------------


async def test_the_control_a_held_current_range_rolls_and_then_reports_the_no_op(
    tmp_path: Path,
) -> None:
    """Without this arm a refusal below could be the roll failing for every store."""
    path, a, b = tmp_path / "control.db", generate_key(), generate_key()
    await _seed(path, a, "a", 2)
    ok, msg = await _roll(path, b, (a,))
    assert ok and "closed" in msg, msg
    ok, msg = await _roll(path, b)  # A dropped after the roll: B's range is current and held
    assert ok and "already" in msg, msg
    assert await _verify(path, b)


async def test_a_dropped_key_for_the_first_range_is_refused_not_reported_as_the_no_op(
    tmp_path: Path,
) -> None:
    """A keys the only range; B is made active and A is dropped before any roll."""
    path, a, b = tmp_path / "first.db", generate_key(), generate_key()
    await _seed(path, a, "a", 3)
    assert not await _verify(path, b), "the precondition: audit-verify calls this chain broken"
    ok, msg = await _roll(path, b)
    assert not ok, msg
    assert "already" not in msg and "not configured" in msg, msg
    assert await _epoch_rows(path, b) == 0, "a refused roll must write nothing"


async def test_a_dropped_key_for_a_later_range_is_refused_not_reported_as_the_no_op(
    tmp_path: Path,
) -> None:
    """A -> B rolled, so B keys the current range; then C is made active and B is dropped."""
    path, a, b, c = tmp_path / "later.db", generate_key(), generate_key(), generate_key()
    await _seed(path, a, "a", 2)
    ok, msg = await _roll(path, b, (a,))
    assert ok, msg
    await _seed(path, b, "b", 2)
    assert not await _verify(path, c), "the precondition: audit-verify calls this chain broken"
    ok, msg = await _roll(path, c)
    assert not ok and "not configured" in msg, msg
    assert await _epoch_rows(path, c) == 1, "a refused roll must write nothing"


async def test_restoring_the_dropped_key_lets_the_roll_finish(tmp_path: Path) -> None:
    """The refusal names a fix, and the fix works: with A back in the retired set, the roll runs."""
    path, a, b = tmp_path / "restore.db", generate_key(), generate_key()
    await _seed(path, a, "a", 2)
    ok, _msg = await _roll(path, b)
    assert not ok
    ok, msg = await _roll(path, b, (a,))
    assert ok and "closed" in msg, msg
    assert await _verify(path, b)


async def test_the_no_op_verifies_the_chain_before_it_reports_ok(tmp_path: Path) -> None:
    """Under the active key there is nothing to roll, but a tampered chain is still not OK."""
    path, a = tmp_path / "tamper.db", generate_key()
    await _seed(path, a, "a", 3)
    store = await _open(path, a)
    try:
        await store._db.execute("UPDATE audit_log SET actor='mallory' WHERE id=2")
        await store._db.commit()
        ok, msg = await store.roll_audit_key_epoch()
        assert not ok and "id=2" in msg, msg
    finally:
        await store.close()


# --- the CLI surface ---------------------------------------------------------------------------------


def test_rotate_key_and_audit_verify_agree_when_the_current_ranges_key_is_dropped(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The item's own reproduction, end to end: the two commands must not disagree."""
    for name in _AT_REST_ENV:
        monkeypatch.delenv(name, raising=False)
    monkeypatch.chdir(tmp_path)
    db, a, b = tmp_path / "cli.db", generate_key(), generate_key()
    asyncio.run(_seed(db, a, "a", 3))

    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", b)  # A dropped, never rolled
    assert main(["audit-verify", "--db", str(db)]) != 0
    capsys.readouterr()
    assert main(["rotate-key", "--db", str(db)]) == 1
    captured = capsys.readouterr()
    assert "OK:" not in captured.out and "PARTIAL:" in captured.out, captured.out
    assert "not configured" in captured.err, captured.err
