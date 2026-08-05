# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-8 AUDIT-INTEGRITY: tamper-evident audit-log hash chain + verification."""

from __future__ import annotations

import asyncio
import base64
import hashlib
import hmac
import json
import re
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
    args = dict(ts=1.5, actor="alice", action="view", channel_id="ch", detail='{"n":1}')  # noqa: C408
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


# --- BACKLOG #328: `audit-anchor` + `audit-verify --expected-anchor` -----------------------------
#
# The hash chain links each row to its predecessor, so deleting the NEWEST rows leaves a shorter chain
# that still walks cleanly: a bare `audit-verify` reports OK on a truncated log. `audit_anchor()` and
# `verify_audit_chain(expected_anchor=...)` already existed on the store protocol and all three
# backends; nothing exposed them to an operator, so the capability was unreachable from the CLI.
#
# The anchor is an EXACT point-in-time seal (measured, not assumed — see
# test_an_anchor_goes_stale_on_the_next_appended_row): it compares BOTH the row count and the head
# hash, so it is checked against a quiesced chain, not carried across normal operation.


def _seed_audit_rows(db: Path, n: int) -> None:
    """Write ``n`` audit rows into a fresh store at ``db`` and close it."""

    async def _run() -> None:
        s = await MessageStore.open(db)
        for i in range(n):
            await s.record_audit(f"act{i}", actor="x")
        await s.close()

    asyncio.run(_run())


def _truncate_audit_tail(db: Path, keep: int) -> None:
    """Delete every audit row past the first ``keep`` — the attack the chain walk cannot see."""

    async def _run() -> None:
        s = await MessageStore.open(db)
        await s._db.execute("DELETE FROM audit_log WHERE id > ?", (keep,))
        await s._db.commit()
        await s.close()

    asyncio.run(_run())


def test_audit_anchor_cli_prints_count_and_head(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    db = tmp_path / "anchor.db"
    _seed_audit_rows(db, 2)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor = capsys.readouterr().out.strip()
    assert re.fullmatch(r"2:[0-9a-f]{64}", anchor), anchor

    # The printed form must be exactly what the verify flag consumes — a round-trip, not two shapes
    # that merely look alike.
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", anchor]) == 0
    assert "OK" in capsys.readouterr().out


def test_audit_anchor_cli_json(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    db = tmp_path / "anchor_json.db"
    _seed_audit_rows(db, 2)

    assert main(["audit-anchor", "--db", str(db), "--json"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 2
    assert re.fullmatch(r"[0-9a-f]{64}", payload["head"])
    # `anchor` is the pre-joined COUNT:HEAD a job can hand straight back, so a caller never has to
    # re-derive the separator convention from two fields.
    assert payload["anchor"] == f"{payload['count']}:{payload['head']}"


def test_audit_anchor_cli_refuses_missing_db(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # M-31 parity with the verify twin, and it bites harder here: opening a SQLite store CREATES it,
    # so a typo'd --db would mint an empty DB and print `0:` — an anchor OF NOTHING, which a later
    # verify against that same wrong database would confirm forever.
    missing = tmp_path / "typo.db"
    assert main(["audit-anchor", "--db", str(missing)]) == 2
    assert "no audit database" in capsys.readouterr().err
    assert not missing.exists()


def test_expected_anchor_detects_a_truncated_tail(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The load-bearing case: the blindness, and the thing that closes it, in one test.

    Half (a) pins the gap this feature exists for — a bare verify reports OK after the tail is cut.
    If half (a) ever fails, the walk itself has changed and this whole subcommand needs re-reasoning.
    Half (b) is the fix. Asserting only (b) would let someone "close" the finding by changing the
    walk while nobody noticed the two halves had stopped describing the same system.
    """
    db = tmp_path / "trunc.db"
    _seed_audit_rows(db, 4)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor = capsys.readouterr().out.strip()

    _truncate_audit_tail(db, keep=2)

    # (a) the surviving prefix still chains cleanly — the bare walk cannot see the deletion.
    assert main(["audit-verify", "--db", str(db)]) == 0
    assert "OK" in capsys.readouterr().out

    # (b) the anchor sees it.
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", anchor]) == 1
    out = capsys.readouterr().out
    assert "truncated or rewritten" in out and "FAIL" in out


def test_expected_anchor_rejects_a_malformed_value(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A silently-ignored anchor is worse than no anchor: the command still exits 0, so the compliance
    # job reports green while checking nothing. It must refuse loudly and name the form.
    db = tmp_path / "malformed.db"
    _seed_audit_rows(db, 2)

    assert main(["audit-verify", "--db", str(db), "--expected-anchor", "garbage"]) == 2
    err = capsys.readouterr().err
    assert "COUNT:HEAD" in err and "malformed audit anchor" in err


def test_expected_anchor_accepts_the_empty_log_anchor(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # `audit_anchor()` returns (0, "") for an empty log, so `0:` must round-trip — otherwise a fresh
    # instance is the one state that cannot be anchored, and the parser's strictness would have
    # created a hole exactly where an operator starts.
    db = tmp_path / "empty.db"
    _seed_audit_rows(db, 0)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    assert capsys.readouterr().out.strip() == "0:"
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", "0:"]) == 0


def test_expected_anchor_file_round_trips(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The real compliance-job shape: `audit-anchor > anchor.txt` now, `--expected-anchor-file` later.
    db = tmp_path / "file.db"
    anchor_file = tmp_path / "anchor.txt"
    _seed_audit_rows(db, 4)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor_file.write_text(capsys.readouterr().out, encoding="utf-8")  # trailing newline included

    assert main(["audit-verify", "--db", str(db), "--expected-anchor-file", str(anchor_file)]) == 0
    assert "OK" in capsys.readouterr().out

    _truncate_audit_tail(db, keep=1)
    assert main(["audit-verify", "--db", str(db), "--expected-anchor-file", str(anchor_file)]) == 1
    assert "truncated or rewritten" in capsys.readouterr().out


def test_expected_anchor_file_refuses_an_unreadable_path(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # A missing anchor file must not degrade to an unanchored verify: an attacker who can cut the
    # audit tail can also delete the file that would prove it.
    db = tmp_path / "nofile.db"
    _seed_audit_rows(db, 2)

    assert (
        main(["audit-verify", "--db", str(db), "--expected-anchor-file", str(tmp_path / "x")]) == 2
    )
    assert "cannot read --expected-anchor-file" in capsys.readouterr().err


def test_expected_anchor_file_refuses_a_utf16_file_without_crashing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A mis-encoded anchor file must exit 2, not raise — and above all not exit 1.

    ``UnicodeDecodeError`` subclasses ``ValueError``, NOT ``OSError``, so a guard that catches only
    ``OSError`` lets a decode error escape as an unhandled traceback whose exit code is **1** — the
    same code ``audit-verify`` returns for a BROKEN CHAIN. A compliance job keying on exit codes would
    read "your anchor file is UTF-16" as "the audit log was tampered with".

    Not an exotic input: this product deploys as a Windows service, and PowerShell 5.1's ``>``
    redirection writes UTF-16LE with a BOM.
    """
    db = tmp_path / "utf16.db"
    anchor_file = tmp_path / "anchor-utf16.txt"
    _seed_audit_rows(db, 3)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor = capsys.readouterr().out.strip()
    anchor_file.write_bytes(anchor.encode("utf-16"))  # BOM + UTF-16LE: what PS 5.1 `>` writes
    assert anchor_file.read_bytes()[:2] == b"\xff\xfe", "fixture is not the UTF-16LE BOM shape"

    rc = main(["audit-verify", "--db", str(db), "--expected-anchor-file", str(anchor_file)])
    assert rc == 2, "a file-encoding problem must not share an exit code with a detected tamper"
    err = capsys.readouterr().err
    assert "cannot read --expected-anchor-file" in err
    assert "UTF-8" in err  # names the actual requirement, not just the exception


def test_expected_anchor_file_accepts_a_utf8_bom(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    # The other half of the same Windows reality: PS 5.1's `Out-File`/`Set-Content -Encoding utf8`
    # writes UTF-8 WITH a BOM. Refusing that would leave a Windows operator with no working idiom, so
    # the read is `utf-8-sig`, which absorbs it (and is a no-op on BOM-less UTF-8).
    db = tmp_path / "utf8bom.db"
    anchor_file = tmp_path / "anchor-bom.txt"
    _seed_audit_rows(db, 3)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor = capsys.readouterr().out.strip()
    anchor_file.write_bytes(anchor.encode("utf-8-sig"))
    assert anchor_file.read_bytes()[:3] == b"\xef\xbb\xbf", "fixture is not the UTF-8 BOM shape"

    assert main(["audit-verify", "--db", str(db), "--expected-anchor-file", str(anchor_file)]) == 0
    assert "OK" in capsys.readouterr().out


def test_expected_anchor_accepts_an_uppercased_head(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """An upper-cased head is the SAME anchor and must verify, not raise a tamper alarm.

    ``verify_audit_chain`` compares the head byte-exactly (``hmac.compare_digest`` over
    ``audit_mac_bytes``), so a head differing only in case reports ``truncated or rewritten`` on a
    chain nothing has touched. Anchors get copied through tickets, spreadsheets and change records,
    which upper-case things; a control whose FAIL is supposed to mean something must not be able to
    manufacture one out of its own input handling. The parser normalises instead.
    """
    db = tmp_path / "upper.db"
    _seed_audit_rows(db, 3)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    count, _, head = capsys.readouterr().out.strip().partition(":")
    assert head.islower() and len(head) == 64  # the shape being normalised away

    rc = main(["audit-verify", "--db", str(db), "--expected-anchor", f"{count}:{head.upper()}"])
    assert rc == 0
    assert "OK" in capsys.readouterr().out


def test_expected_anchor_refuses_a_truncated_head_as_malformed_not_tampering(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A short head is bad INPUT (rc 2), never a tamper detection (rc 1).

    The trap is baited by the product itself: the FAIL message prints both heads truncated to 12
    characters, so an operator retrying with the value they can see supplies a 12-character head. A
    hex-only check accepts it, the byte-exact comparator cannot match it, and the operator gets
    ``truncated or rewritten`` — with the message's own evidence line showing the two heads as
    IDENTICAL, because it truncates the live one to the same 12 characters. Requiring the full digest
    width turns that into an actionable input error.
    """
    db = tmp_path / "shorthead.db"
    _seed_audit_rows(db, 3)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    count, _, head = capsys.readouterr().out.strip().partition(":")

    rc = main(["audit-verify", "--db", str(db), "--expected-anchor", f"{count}:{head[:12]}"])
    assert rc == 2
    captured = capsys.readouterr()
    assert "malformed audit anchor" in captured.err and "64-character digest" in captured.err
    assert "truncated or rewritten" not in captured.out, (
        "a 12-character head is malformed input, but the chain was reported as truncated or "
        "rewritten — a false tamper alarm costs this control as much as a missed one"
    )


def test_parse_anchor_passes_an_isolated_module_mac_through() -> None:
    """An ADR 0138 ``vault_transit`` head is NOT hex, and must round-trip anyway.

    In that mode ``audit_row_hash`` delegates to ``TransitCipher.audit_hmac``, which returns Vault's
    own opaque ``vault:v1:<base64>`` string; that string is what lands in ``audit_log.row_hash`` and
    therefore what ``audit_anchor()`` prints. A hex-only head check refuses it — so the operator
    control would have been unusable on the one store mode where the audit chain is keyed with no
    in-heap key. Unit-level because reaching it end-to-end needs a live Transit backend.
    """
    from messagefoundry.__main__ import _parse_anchor

    head = "vault:v1:" + base64.b64encode(b"\x01" * 32).decode("ascii")
    assert not all(c in "0123456789abcdefABCDEF" for c in head)  # the reason this case exists
    # The count/head split must survive the MAC's own internal colons (partition on the FIRST only).
    assert _parse_anchor(f"7:{head}") == (7, head)


def test_expected_anchor_and_file_are_mutually_exclusive(tmp_path: Path) -> None:
    # Two transports for one value: argparse refuses both rather than letting one silently win.
    db = tmp_path / "excl.db"
    _seed_audit_rows(db, 1)
    with pytest.raises(SystemExit) as exc:
        main(
            [
                "audit-verify",
                "--db",
                str(db),
                "--expected-anchor",
                "1:" + "0" * 64,
                "--expected-anchor-file",
                str(tmp_path / "a.txt"),
            ]
        )
    assert exc.value.code == 2


def test_an_anchor_goes_stale_on_the_next_appended_row(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The anchor is an EXACT seal, not a monotonic-prefix check — pinned so nobody loosens it.

    Measured against the shipped comparator: ``count < exp_count or not head_ok``, where ``head_ok``
    compares the LAST row's hash. Appending one legitimate row therefore moves the head and the
    anchor reports ``truncated or rewritten`` on a chain that merely GREW.

    That is a real ergonomic sharp edge, and the docs say so — anchor against a quiesced chain. It is
    pinned here because the obvious "fix" (drop the head compare, keep ``count < exp_count``) would
    take a real detection with it: see
    ``test_expected_anchor_detects_a_same_count_tail_replacement``, which a count-only comparator
    would pass. The false alarm and that detection are the SAME check. If this test ever needs to
    change, the comparator semantics are being changed with it.
    """
    db = tmp_path / "stale.db"
    _seed_audit_rows(db, 4)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor = capsys.readouterr().out.strip()

    async def _append_one() -> None:
        s = await MessageStore.open(db)
        await s.record_audit("legitimate", actor="x")
        await s.close()

    asyncio.run(_append_one())

    assert main(["audit-verify", "--db", str(db), "--expected-anchor", anchor]) == 1
    assert "truncated or rewritten" in capsys.readouterr().out


def test_expected_anchor_detects_a_same_count_tail_replacement(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The case that makes the head compare load-bearing rather than merely strict.

    An attacker who cuts the newest rows and forges the same number of replacements restores the row
    COUNT and leaves a chain that walks cleanly (on a keyless store they can recompute it end to end).
    Measured: the bare walk reports ``verified 4 audit row(s)``, and a hypothetical count-only
    comparator would pass too, because ``4 < 4`` is false. Only the head hash differs.

    So the head compare is not redundant with the row count, and the false alarm pinned by
    ``test_an_anchor_goes_stale_on_the_next_appended_row`` is the price of THIS detection — not an
    independent wart that can be filed off on its own.
    """
    db = tmp_path / "replaced.db"
    _seed_audit_rows(db, 4)

    assert main(["audit-anchor", "--db", str(db)]) == 0
    anchor = capsys.readouterr().out.strip()
    expected_count = int(anchor.split(":", 1)[0])

    _truncate_audit_tail(db, keep=2)

    async def _forge_two() -> None:
        s = await MessageStore.open(db)
        for i in range(2):
            await s.record_audit(f"forged{i}", actor="attacker")
        await s.close()

    asyncio.run(_forge_two())

    # The row count is back to where it started, so a count-only check has nothing to complain about.
    assert main(["audit-anchor", "--db", str(db)]) == 0
    assert int(capsys.readouterr().out.strip().split(":", 1)[0]) == expected_count

    # And the chain itself walks cleanly — the forged rows chain correctly from their predecessor.
    assert main(["audit-verify", "--db", str(db)]) == 0
    assert "OK" in capsys.readouterr().out

    # The head hash is what gives it away.
    assert main(["audit-verify", "--db", str(db), "--expected-anchor", anchor]) == 1
    assert "truncated or rewritten" in capsys.readouterr().out


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


# --- ADR 0150: the client address on the chained audit row ------------------------------------------


def test_absent_client_reproduces_the_legacy_digest_exactly() -> None:
    """The compatibility gate for ADR 0150. The address is a CONDITIONAL 7th element, so a row with no
    client must hash over the same 6-element list as before — otherwise every row written before the
    column existed would fail verification the moment the engine was upgraded."""
    args = dict(ts=1.5, actor="alice", action="view", channel_id="ch", detail='{"n":1}')  # noqa: C408
    legacy = "f189c34ba475757a3d41c56861b6215de8c1d0ed68618e52a4ae2ae0b878981e"
    # Omitted and explicitly-None must BOTH collapse to the frozen pre-0150 digest.
    assert audit_row_hash("prev", **args) == legacy  # type: ignore[arg-type]
    assert audit_row_hash("prev", client=None, **args) == legacy  # type: ignore[arg-type]
    # An UNCONDITIONAL 7th element would have produced this instead — the bug this test pins against.
    unconditional = json.dumps(
        ["prev", 1.5, "alice", "view", "ch", '{"n":1}', None], sort_keys=True, default=str
    )
    assert legacy != hashlib.sha256(unconditional.encode("utf-8")).hexdigest()


def test_client_is_inside_the_chained_payload() -> None:
    """The address must be CHAINED, not an unchained sibling column: attribution an attacker can
    rewrite without breaking tamper-evidence would be worse than no attribution at all."""
    args = dict(ts=1.5, actor="alice", action="view", channel_id="ch", detail='{"n":1}')  # noqa: C408
    assert audit_row_hash("prev", client="10.0.0.1", **args) != audit_row_hash("prev", **args)  # type: ignore[arg-type]
    # …and two different addresses are two different digests (the field is genuinely covered).
    assert audit_row_hash("prev", client="10.0.0.1", **args) != audit_row_hash(  # type: ignore[arg-type]
        "prev", client="10.0.0.2", **args
    )


def test_no_crafted_detail_can_forge_the_trailing_client_element() -> None:
    """JSON is uniquely decodable, so a 6- and a 7-element list can never render to the same bytes and
    string values are escaped — a detail ending in a quote-comma-quote run cannot impersonate a client."""
    forged = audit_row_hash(
        "prev", ts=1.5, actor="a", action="v", channel_id=None, detail='x", "10.0.0.1'
    )
    real = audit_row_hash(
        "prev", ts=1.5, actor="a", action="v", channel_id=None, detail="x", client="10.0.0.1"
    )
    assert forged != real


async def test_authenticated_action_records_the_address(store: MessageStore) -> None:
    await store.record_audit("messages.export", actor="alice", client="10.4.2.9")
    row = dict((await store.list_audit(limit=1))[0])
    assert row["client"] == "10.4.2.9"
    ok, _ = await store.verify_audit_chain()
    assert ok


async def test_system_write_records_null_rather_than_inheriting(store: MessageStore) -> None:
    """A background/`system` action must record NULL — never the address of whatever request happened
    to run before it. This is the concrete failure mode that rejected a ContextVar carrier: it leaks
    across asyncio.create_task boundaries and would stamp a live operator's host onto these rows."""
    await store.record_audit("messages.export", actor="alice", client="10.4.2.9")
    await store.record_audit("retention.purge", actor="system")  # engine-internal: no client
    rows = [dict(r) for r in await store.list_audit(limit=2)]
    assert rows[0]["action"] == "retention.purge" and rows[0]["client"] is None
    assert rows[1]["client"] == "10.4.2.9"
    # Still one continuous chain across a with-client and a without-client row.
    ok, _ = await store.verify_audit_chain()
    assert ok


async def test_chain_verifies_across_mixed_old_and_new_format_rows(tmp_path: Path) -> None:
    """The load-bearing migration property: one chain spanning rows written BEFORE the client column
    existed and rows written after it, interleaved."""
    store = await MessageStore.open(tmp_path / "mixed.db")
    try:
        await store.record_audit("legacy.a", actor="u")  # 6-element payload
        await store.record_audit("new.b", actor="u", client="10.0.0.7")  # 7-element payload
        await store.record_audit("legacy.c", actor="system")  # 6-element again
        await store.record_audit("new.d", actor="u", client="192.168.1.5")
        ok, message = await store.verify_audit_chain()
        assert ok, message
        assert "4" in (message or "")
    finally:
        await store.close()


async def test_tampering_with_a_recorded_address_breaks_the_chain(store: MessageStore) -> None:
    """Rewriting the address out-of-band must be detected — that is the whole point of chaining it."""
    await store.record_audit("messages.export", actor="alice", client="10.4.2.9")
    await store.record_audit("messages.export", actor="alice", client="10.4.2.9")
    await store._db.execute("UPDATE audit_log SET client='127.0.0.1' WHERE id=1")
    await store._db.commit()
    ok, message = await store.verify_audit_chain()
    assert not ok and "id=1" in (message or "")


async def test_migration_adds_client_to_a_preexisting_store(tmp_path: Path) -> None:
    """Open a DB whose audit_log predates the column (the real upgrade path): the ALTER lands, the
    legacy rows keep their original hashes, and the chain still verifies — then a NEW row carrying an
    address chains cleanly onto them."""
    import aiosqlite

    db = tmp_path / "preexisting.db"
    # Build the pre-ADR-0150 audit_log by hand, with correctly-computed OLD-FORMAT hashes.
    async with aiosqlite.connect(db) as raw:
        await raw.execute(
            "CREATE TABLE audit_log (id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL NOT NULL,"
            " actor TEXT, action TEXT NOT NULL, channel_id TEXT, detail TEXT, row_hash TEXT)"
        )
        prev = ""
        for i in range(3):
            prev = audit_row_hash(
                prev, ts=float(i), actor="u", action="legacy", channel_id=None, detail=None
            )
            await raw.execute(
                "INSERT INTO audit_log (ts, actor, action, channel_id, detail, row_hash)"
                " VALUES (?,?,?,?,?,?)",
                (float(i), "u", "legacy", None, None, prev),
            )
        await raw.commit()
    legacy_head = prev

    store = await MessageStore.open(db)
    try:
        cur = await store._db.execute("PRAGMA table_info(audit_log)")
        assert "client" in {r["name"] for r in await cur.fetchall()}  # the ALTER ran
        # The pre-existing rows were NOT rewritten, and they still verify.
        cur = await store._db.execute("SELECT client, row_hash FROM audit_log ORDER BY id")
        rows = await cur.fetchall()
        assert [r["client"] for r in rows] == [None, None, None]
        assert rows[-1]["row_hash"] == legacy_head
        ok, message = await store.verify_audit_chain()
        assert ok, message
        # A new address-bearing row chains onto the legacy tail without breaking it.
        await store.record_audit("messages.export", actor="alice", client="10.4.2.9")
        ok, message = await store.verify_audit_chain()
        assert ok, message
        assert "4" in (message or "")
    finally:
        await store.close()
