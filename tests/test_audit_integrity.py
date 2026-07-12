# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-8 AUDIT-INTEGRITY: tamper-evident audit-log hash chain + verification."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import (
    _GCM_MAX_INVOCATIONS,
    _GCM_SOFT_WARN_INVOCATIONS,
    AesGcmCipher,
    CipherError,
    IdentityCipher,
    generate_key,
    make_cipher,
)
from messagefoundry.store.store import audit_row_hash, should_record_event


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "audit.db")
    yield s
    await s.close()


async def _keyed_store(path: Path) -> MessageStore:
    """Open an encrypted store whose audit chain is HMAC-keyed (#190)."""
    cipher = make_cipher(generate_key())
    return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


async def test_chain_verifies_after_normal_appends(store: MessageStore) -> None:
    for i in range(3):
        await store.record_audit("action", actor="u", detail=f'{{"n":{i}}}')
    ok, message = await store.verify_audit_chain()
    assert ok and "3" in (message or "")


async def test_edit_breaks_the_chain(store: MessageStore) -> None:
    await store.record_audit("login", actor="u")
    await store.record_audit("view", actor="u")
    # Tamper with a row's content out-of-band (its stored hash no longer matches its content).
    await store._db.execute("UPDATE audit_log SET action='HACKED' WHERE id=1")
    await store._db.commit()
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=1" in (message or "")


async def test_delete_breaks_the_chain(store: MessageStore) -> None:
    for action in ("a", "b", "c"):
        await store.record_audit(action, actor="u")
    await store._db.execute("DELETE FROM audit_log WHERE action='b'")  # drop a middle row
    await store._db.commit()
    ok, _ = await store.verify_audit_chain()
    assert not ok  # 'c' now chains from the wrong predecessor


async def test_tail_truncation_caught_only_with_external_anchor(store: MessageStore) -> None:
    # low-1: deleting the NEWEST rows leaves a shorter chain that still verifies; only an anchor
    # snapshotted out-of-band catches it.
    for action in ("a", "b", "c"):
        await store.record_audit(action, actor="u")
    anchor = await store.audit_anchor()
    assert anchor[0] == 3 and anchor[1]  # (count, non-empty head hash)
    await store._db.execute("DELETE FROM audit_log WHERE action='c'")  # drop the newest row
    await store._db.commit()
    ok, _ = await store.verify_audit_chain()
    assert ok  # the within-DB walk can't see tail-truncation
    ok, message = await store.verify_audit_chain(expected_anchor=anchor)
    assert not ok and "anchor" in (message or "")  # the external anchor does


async def test_backfill_chains_legacy_unhashed_rows(tmp_path: Path) -> None:
    db = tmp_path / "legacy.db"
    store = await MessageStore.open(db)
    try:
        # Simulate rows written before hash-chaining: row_hash NULL.
        for i in range(3):
            await store._db.execute(
                "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                " VALUES (?,?,?,?,?,NULL)",
                (float(i), "u", "legacy", None, None),
            )
        await store._db.commit()
        await store._backfill_audit_chain()
        ok, _ = await store.verify_audit_chain()
        assert ok  # backfill established a continuous chain over the legacy rows
    finally:
        await store.close()


# --- #190 keyed HMAC audit chain -------------------------------------------------------------------


def test_keyless_hash_is_byte_identical_frozen_fixture() -> None:
    # HARD compatibility gate: audit_row_hash(key=None) must stay BYTE-IDENTICAL to the pre-#190
    # unkeyed SHA-256 chain, so keyless deployments + every legacy row still verify. Pinned to a frozen
    # digest AND to the exact canonical formula (breaks if either the encoding or the keyless branch
    # changes).
    args = dict(ts=1.5, actor="alice", action="view", channel_id="ch", detail='{"n":1}')
    keyless = audit_row_hash("prev", key=None, **args)  # type: ignore[arg-type]
    assert keyless == "f189c34ba475757a3d41c56861b6215de8c1d0ed68618e52a4ae2ae0b878981e"
    canonical = json.dumps(
        ["prev", 1.5, "alice", "view", "ch", '{"n":1}'], sort_keys=True, default=str
    )
    assert keyless == hashlib.sha256(canonical.encode("utf-8")).hexdigest()
    # Keyed is a DIFFERENT digest (HMAC over the same canonical), and matches stdlib hmac exactly.
    key = b"\x00" * 32
    keyed = audit_row_hash("prev", key=key, **args)  # type: ignore[arg-type]
    assert keyed != keyless
    assert keyed == hmac.new(key, canonical.encode("utf-8"), hashlib.sha256).hexdigest()


async def test_keyed_store_chain_verifies(tmp_path: Path) -> None:
    store = await _keyed_store(tmp_path / "keyed.db")
    try:
        assert store._audit_keyed_from == 1  # fresh encrypted store auto-keys from row 1
        for i in range(3):
            await store.record_audit("action", actor="u", detail=f'{{"n":{i}}}')
        ok, message = await store.verify_audit_chain()
        assert ok and "3" in (message or "")
        # The stored hash really is the HMAC (not the keyless SHA-256) — an attacker without the DEK
        # cannot recompute it.
        cur = await store._db.execute("SELECT row_hash FROM audit_log ORDER BY id LIMIT 1")
        row = await cur.fetchone()
        assert row is not None
        keyless = audit_row_hash(
            "",
            ts=0.0,
            actor="u",
            action="action",
            channel_id=None,
            detail='{"n":0}',
            key=None,
        )
        assert row["row_hash"] != keyless  # it's keyed, not the forgeable keyless hash
    finally:
        await store.close()


async def test_keyed_edit_breaks_verify(tmp_path: Path) -> None:
    store = await _keyed_store(tmp_path / "keyed_edit.db")
    try:
        await store.record_audit("login", actor="u")
        await store.record_audit("view", actor="u")
        await store._db.execute("UPDATE audit_log SET action='HACKED' WHERE id=1")
        await store._db.commit()
        ok, message = await store.verify_audit_chain()
        assert not ok and "id=1" in (message or "")
    finally:
        await store.close()


async def test_keyed_chain_unverifiable_without_the_key(tmp_path: Path) -> None:
    # A store keyed by a prior run, reopened WITHOUT the DEK, must report honestly rather than falsely
    # verify or mis-flag every keyed row as tampered.
    path = tmp_path / "reopen.db"
    store = await _keyed_store(path)
    try:
        await store.record_audit("login", actor="u")
    finally:
        await store.close()
    plain = await MessageStore.open(path)  # no cipher, no audit_mac_key
    try:
        assert plain._audit_keyed_from == 1  # watermark persisted
        ok, message = await plain.verify_audit_chain()
        assert not ok and "no store encryption key" in (message or "")
    finally:
        await plain.close()


async def test_keyed_store_refuses_keyless_append_without_the_key(tmp_path: Path) -> None:
    # review major-1: a keyed store reopened WRITABLE without its DEK must REFUSE to append (raise),
    # never write a keyless row above the keying watermark. Such a row would hash keyless yet land at an
    # id ≥ the watermark, so a later keyed verify would expect an HMAC there and report a FALSE tamper —
    # silently corrupting the tamper-evidence chain. Fail closed instead.
    path = tmp_path / "refuse.db"
    store = await _keyed_store(path)
    try:
        await store.record_audit("login", actor="u")
    finally:
        await store.close()
    plain = await MessageStore.open(path)  # no cipher/key, but the watermark persisted
    try:
        assert plain._audit_keyed_from == 1
        with pytest.raises(RuntimeError, match="no store encryption key"):
            await plain.record_audit("view", actor="u")
        # The refusal is total — no keyless row leaked in above the watermark.
        cur = await plain._db.execute("SELECT COUNT(*) AS n FROM audit_log")
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 1
    finally:
        await plain.close()


async def test_rekey_migration_of_existing_keyless_chain(tmp_path: Path) -> None:
    # #190-D: an existing keyless chain is NOT auto-keyed on open; rekey_audit_chain enables keying from
    # the next id — existing keyless rows keep verifying, new rows are keyed.
    path = tmp_path / "migrate.db"
    key = generate_key()
    store = await MessageStore.open(path)  # keyless first
    try:
        await store.record_audit("legacy1", actor="u")
        await store.record_audit("legacy2", actor="u")
        assert store._audit_keyed_from is None  # existing keyless chain left keyless
    finally:
        await store.close()
    cipher = make_cipher(key)
    store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    try:
        # Opening with a key does NOT silently re-key an existing non-empty chain.
        assert store._audit_keyed_from is None
        ok, msg = await store.rekey_audit_chain()
        assert ok and "keyed from id=3" in msg
        assert store._audit_keyed_from == 3
        await store.record_audit("new_keyed", actor="u")
        ok, _ = await store.verify_audit_chain()  # keyless prefix + keyed suffix both verify
        assert ok
    finally:
        await store.close()


async def test_rekey_refuses_broken_chain(tmp_path: Path) -> None:
    # rekey must run ONLY on an operator-verified chain — a tampered keyless chain is never blessed.
    path = tmp_path / "broken.db"
    key = generate_key()
    store = await MessageStore.open(path)
    try:
        await store.record_audit("a", actor="u")
        await store.record_audit("b", actor="u")
        await store._db.execute("UPDATE audit_log SET action='HACKED' WHERE id=1")
        await store._db.commit()
    finally:
        await store.close()
    cipher = make_cipher(key)
    store = await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())
    try:
        ok, msg = await store.rekey_audit_chain()
        assert not ok and "refusing" in msg
        assert store._audit_keyed_from is None  # watermark not set on refusal
    finally:
        await store.close()


# --- #190-F GCM invocation ceiling -----------------------------------------------------------------


def test_gcm_soft_warn_then_fail_closed(caplog: pytest.LogCaptureFixture) -> None:
    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    # Jump the in-memory counter to just below the soft-warn threshold, then encrypt across it.
    cipher._invocations = _GCM_SOFT_WARN_INVOCATIONS - 1
    with caplog.at_level("WARNING"):
        cipher.encrypt("x")  # crosses 2**31 → one soft warning
    assert any("2**31" in r.message for r in caplog.records)
    # Approaching 2**32 fails CLOSED rather than risking a nonce-reuse birthday collision.
    cipher._invocations = _GCM_MAX_INVOCATIONS - 1
    with pytest.raises(CipherError):
        cipher.encrypt("y")


def test_identity_cipher_has_no_audit_key() -> None:
    assert IdentityCipher().audit_mac_key() is None
    assert isinstance(make_cipher(generate_key()).audit_mac_key(), bytes)


# --- #63 message_events verbosity gate -------------------------------------------------------------


def test_should_record_event_floor_and_levels() -> None:
    # Compliance FLOOR retained at EVERY level — even "off".
    for level in ("all", "errors", "off"):
        for floor in ("viewed", "dead", "error", "failed"):
            assert should_record_event(floor, level), (floor, level)
    # Routine events pass only at "all".
    for routine in ("received", "delivered", "replayed", "filtered", "transformed"):
        assert should_record_event(routine, "all")
        assert not should_record_event(routine, "errors")
        assert not should_record_event(routine, "off")


async def test_message_events_gate_suppresses_routine_keeps_floor(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "gate.db", message_events="off")
    try:
        # A routine 'received'/ingress row on the hot ACK path is suppressed at "off"…
        mid = await store.enqueue_ingress(channel_id="ch", raw="MSH|^~\\&|A|B")
        # …but the message itself is still persisted (count-and-log is separate from the event log).
        assert await store.get_message(mid) is not None
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM message_events WHERE message_id=? AND event='received'",
            (mid,),
        )
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 0  # routine row suppressed
        # A 'viewed' PHI-access event is on the floor → retained even at "off".
        await store.record_view(mid, actor="operator")
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM message_events WHERE message_id=? AND event='viewed'",
            (mid,),
        )
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 1
    finally:
        await store.close()


async def test_message_events_all_records_routine(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "gate_all.db", message_events="all")
    try:
        mid = await store.enqueue_ingress(channel_id="ch", raw="MSH|^~\\&|A|B")
        cur = await store._db.execute(
            "SELECT COUNT(*) AS n FROM message_events WHERE message_id=? AND event='received'",
            (mid,),
        )
        row = await cur.fetchone()
        assert row is not None and int(row["n"]) == 1  # default keeps the routine row
    finally:
        await store.close()


def test_audit_verify_cli(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "cli.db"

    async def _seed() -> None:
        s = await MessageStore.open(db)
        await s.record_audit("login", actor="x")
        await s.record_audit("view", actor="x")
        await s.close()

    asyncio.run(_seed())
    assert main(["audit-verify", "--db", str(db)]) == 0
    assert "OK" in capsys.readouterr().out


def test_audit_verify_cli_refuses_missing_db(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # M-31: a typo'd --db must NOT create a fresh DB and report a false "OK: verified 0 rows".
    missing = tmp_path / "typo.db"
    assert main(["audit-verify", "--db", str(missing)]) == 2
    assert "no audit database" in capsys.readouterr().err
    assert not missing.exists()  # we refused before opening, so no empty DB was littered


def test_rekey_audit_cli(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # review major-2: the #190-D migration must be operator-reachable. Seed a keyless chain, then run
    # `rekey-audit` with the DEK in the env — it re-verifies the keyless chain and enables keying.
    db = tmp_path / "rekey.db"

    async def _seed() -> None:
        s = await MessageStore.open(db)
        await s.record_audit("legacy1", actor="x")
        await s.record_audit("legacy2", actor="x")
        await s.close()

    asyncio.run(_seed())
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    assert main(["rekey-audit", "--db", str(db)]) == 0
    assert "OK" in (out := capsys.readouterr().out) and "keyed from id=3" in out
    # Re-running is an idempotent no-op — already keyed, never a second watermark move.
    assert main(["rekey-audit", "--db", str(db)]) == 0
    assert "already keyed" in capsys.readouterr().out


def test_rekey_audit_cli_refuses_missing_db(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    # A typo'd --db must NOT create a fresh SQLite DB (mirrors audit-verify's M-31 guard).
    monkeypatch.setenv("MEFOR_STORE_ENCRYPTION_KEY", generate_key())
    missing = tmp_path / "typo.db"
    assert main(["rekey-audit", "--db", str(missing)]) == 2
    assert "no audit database" in capsys.readouterr().err
    assert not missing.exists()
