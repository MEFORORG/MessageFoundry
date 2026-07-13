# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Phase-8 STORE-1: PHI-at-rest encryption — the cipher + the store seam + migration."""

from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store.crypto import (
    MARKER_PREFIX,
    PREFIX,
    AesGcmCipher,
    CipherError,
    IdentityCipher,
    generate_key,
    make_cipher,
)
from messagefoundry.store.store import MessageStore
import logging

ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|MSG1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _raw_at_rest(db_path: Path, column: str = "raw", table: str = "messages") -> str:
    """Read a column straight from the DB file, bypassing the store's decryption."""
    con = sqlite3.connect(db_path)
    try:
        return str(con.execute(f"SELECT {column} FROM {table}").fetchone()[0])
    finally:
        con.close()


# --- cipher unit tests -------------------------------------------------------


def test_cipher_round_trip_and_hides_plaintext() -> None:
    cipher = make_cipher(generate_key())
    token = cipher.encrypt(ADT)
    assert token.startswith(PREFIX)
    # PHI-hidden, asserted deterministically: the whole plaintext can never appear in the token
    # (it contains non-base64 bytes like '|' and '\r'), and the round-trip proves real encryption.
    # NEVER assert short-substring absence ("MSH"/"DOE") — a random base64 body contains any given
    # 3-char run with probability ~len/64^3, and that assertion HAS flaked in CI.
    assert ADT not in token
    assert cipher.decrypt(token) == ADT
    assert cipher.encrypt(ADT) != token  # fresh nonce per encryption — tokens never repeat


def test_identity_cipher_is_passthrough() -> None:
    cipher = make_cipher(None)
    assert isinstance(cipher, IdentityCipher) and not cipher.encrypts
    assert cipher.encrypt(ADT) == ADT and cipher.decrypt(ADT) == ADT


def test_decrypt_passes_through_legacy_plaintext() -> None:
    # A value without the prefix is pre-encryption plaintext — returned as-is (migration support).
    assert make_cipher(generate_key()).decrypt(ADT) == ADT


def test_wrong_key_fails_loudly() -> None:
    token = make_cipher(generate_key()).encrypt(ADT)
    with pytest.raises(CipherError):  # no configured key authenticates the GCM tag
        make_cipher(generate_key()).decrypt(token)


def test_make_cipher_rejects_bad_key_length() -> None:
    with pytest.raises(ValueError):
        make_cipher(base64.b64encode(b"too-short").decode())


# --- store seam --------------------------------------------------------------


async def test_bodies_encrypted_at_rest(tmp_path: Path) -> None:
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", ADT)])
    finally:
        await store.close()
    raw = _raw_at_rest(db)
    payload = _raw_at_rest(db, column="payload", table="queue")
    assert raw.startswith(PREFIX) and "DOE" not in raw  # body is ciphertext on disk
    assert payload.startswith(PREFIX)


async def test_reads_and_delivery_decrypt(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", ADT)])
        record = await store.get_message(mid)
        assert record is not None and record["raw"] == ADT  # detail view decrypts
        items = await store.claim_ready()
        assert items and items[0].payload == ADT  # delivery worker gets the plaintext body
    finally:
        await store.close()


async def test_off_by_default_stores_plaintext(tmp_path: Path) -> None:
    db = tmp_path / "plain.db"
    store = await MessageStore.open(db)  # no cipher → identity (backward compatible)
    try:
        await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[])
    finally:
        await store.close()
    assert _raw_at_rest(db) == ADT  # unchanged behavior when no key is configured


async def test_claim_ready_dead_letters_undecryptable_row(tmp_path: Path) -> None:
    """A poison outbox row (corrupt blob / rotated key) is dead-lettered, not allowed to blow up the
    whole claim and strand the batch — the rest of the batch still delivers (review H-1c)."""
    from messagefoundry.store.store import OutboxStatus

    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        await store.enqueue_message(
            channel_id="ch", raw=ADT, deliveries=[("good", "PAYLOAD-GOOD"), ("bad", "PAYLOAD-BAD")]
        )
        cur = await store._db.execute("SELECT id, destination_name FROM queue")
        bad_id = next(r["id"] for r in await cur.fetchall() if r["destination_name"] == "bad")
        # A token encrypted under a DIFFERENT key: prefixed + valid base64, but decrypt raises
        # InvalidTag — exactly the rotated-MEFOR_STORE_ENCRYPTION_KEY case.
        wrong_key_token = make_cipher(generate_key()).encrypt("PAYLOAD-BAD")
        await store._db.execute("UPDATE queue SET payload=? WHERE id=?", (wrong_key_token, bad_id))
        await store._db.commit()

        items = await store.claim_ready(limit=10)
        assert [i.destination_name for i in items] == ["good"]  # good row still delivered
        cur = await store._db.execute("SELECT status, last_error FROM queue WHERE id=?", (bad_id,))
        row = await cur.fetchone()
        assert row["status"] == OutboxStatus.DEAD.value  # poison row dead-lettered, not stranded
        # last_error is itself ciphered now (WP-5), so decrypt it before checking the reason.
        assert "undecryptable" in store._cipher.decrypt(row["last_error"] or "")
    finally:
        await store.close()


async def test_claim_ingress_dead_letters_undecryptable_row(tmp_path: Path) -> None:
    """An undecryptable INGRESS row (corrupt blob / rotated key) is dead-lettered without stranding
    the ingress lane — and the message lands ERROR (the sender already got AA, so the disposition is
    the operator's signal). Staged-pipeline variant of the outbound poison-row guard."""
    from messagefoundry.store.store import MessageStatus, OutboxStatus, Stage

    store = await MessageStore.open(tmp_path / "enc.db", cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_ingress(channel_id="ch", raw=ADT)
        cur = await store._db.execute("SELECT id FROM queue WHERE stage=?", (Stage.INGRESS.value,))
        ingress_id = (await cur.fetchone())["id"]
        wrong_key_token = make_cipher(generate_key()).encrypt(ADT)
        await store._db.execute(
            "UPDATE queue SET payload=? WHERE id=?", (wrong_key_token, ingress_id)
        )
        await store._db.commit()

        # Claiming the poison ingress head dead-letters it (returns None) rather than raising.
        assert await store.claim_next_fifo("ch", stage=Stage.INGRESS.value) is None
        cur = await store._db.execute(
            "SELECT status, last_error FROM queue WHERE id=?", (ingress_id,)
        )
        row = await cur.fetchone()
        assert row["status"] == OutboxStatus.DEAD.value  # poison row dead-lettered, not stranded
        # last_error is itself ciphered now (WP-5), so decrypt it before checking the reason.
        assert "undecryptable" in store._cipher.decrypt(row["last_error"] or "")
        # Dead ingress row with no outbound rows → the message is finalized to ERROR.
        assert (await store.get_message(mid))["status"] == MessageStatus.ERROR.value
    finally:
        await store.close()


async def test_migration_encrypts_existing_rows(tmp_path: Path) -> None:
    db = tmp_path / "mig.db"
    plain = await MessageStore.open(db)  # write plaintext first (no key)
    try:
        mid = await plain.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", ADT)])
    finally:
        await plain.close()
    assert _raw_at_rest(db) == ADT  # plaintext at rest before migration

    key = generate_key()
    encrypted = await MessageStore.open(db, cipher=make_cipher(key))  # reopen with a key → migrate
    try:
        assert _raw_at_rest(db).startswith(PREFIX)  # existing row now encrypted on disk
        assert _raw_at_rest(db, column="payload", table="queue").startswith(PREFIX)
        record = await encrypted.get_message(mid)
        assert record is not None and record["raw"] == ADT  # still readable
    finally:
        await encrypted.close()


# --- WP-5: cipher coverage of error / last_error / detail --------------------

# A NON-HL7-shaped secret: HL7-delimited content is now scrubbed at the write chokepoint (#120) before
# it ever reaches these columns, so the at-rest cipher's remaining job is to protect the *residual*
# free-text PHI a script can invent (a bare name/identifier with no HL7 delimiters, which the scrub
# deliberately can't detect). This value passes through safe_text unchanged, so it exercises encryption
# round-trip identity — the scrub's own behavior is covered in test_store/test_redaction.
PHI_ERR = "parse failed for patient SECRETNAME mrn 999 not found"


async def test_error_and_event_detail_encrypted_at_rest_and_decrypt(tmp_path: Path) -> None:
    from messagefoundry.store.store import MessageStatus

    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.record_received(
            channel_id="ch", raw=ADT, status=MessageStatus.ERROR, error=PHI_ERR
        )
        # messages.error and the message_events.detail copy are both ciphertext on disk...
        err_at_rest = _raw_at_rest(db, column="error")
        det_at_rest = _raw_at_rest(db, column="detail", table="message_events")
        assert err_at_rest.startswith(PREFIX) and "SECRET" not in err_at_rest
        assert det_at_rest.startswith(PREFIX) and "SECRET" not in det_at_rest
        # ...and decrypt on every read path.
        assert (await store.get_message(mid))["error"] == PHI_ERR
        assert any(m["error"] == PHI_ERR for m in await store.list_messages())
        assert any(e["detail"] == PHI_ERR for e in await store.events_for(mid))
    finally:
        await store.close()


async def test_last_error_encrypted_at_rest_and_decrypts(tmp_path: Path) -> None:
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", "P")])
        [row] = await store.outbox_for(mid)
        await store.claim_ready()
        await store.dead_letter_now(row["id"], PHI_ERR)
        at_rest = _raw_at_rest(db, column="last_error", table="queue")
        assert at_rest.startswith(PREFIX) and "SECRET" not in at_rest
        dead = await store.list_dead()
        assert dead and dead[0]["last_error"] == PHI_ERR  # dead-letter view decrypts
        assert (await store.outbox_for(mid))[0]["last_error"] == PHI_ERR  # detail view decrypts
    finally:
        await store.close()


async def test_null_and_purged_blank_values_are_not_ciphered(tmp_path: Path) -> None:
    # WP-12 interaction: a NULL error stays NULL and a purged '' body stays '' — never ciphertext.
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[], now=1000.0)
        con = sqlite3.connect(db)
        try:
            assert (
                con.execute("SELECT error FROM messages").fetchone()[0] is None
            )  # NULL stays NULL
        finally:
            con.close()
        await store.purge_message_bodies(older_than=2000.0)
        assert _raw_at_rest(db) == ""  # purged body is blank, not ciphertext-of-empty
        rec = await store.get_message(mid)
        assert rec is not None and rec["raw"] == "" and rec["error"] is None
    finally:
        await store.close()


# --- EF-3: summary + metadata (MRN + patient name) encrypted at rest ---------

# Stand-ins for the MRN + patient name + operator-attached values the listener derives and attaches.
# These are DIRECT identifiers, so EF-3 ciphers them at rest like the body — they are not left cleartext
# "for fast search" (no SQL search on summary exists). Sentinels chosen to be unmistakable in a blob.
EF3_SUMMARY = "MRN=999001 NAME=DOE^JANE ORDER=A01"
EF3_METADATA = '{"priority": "STAT", "site": "WESTWING"}'


async def test_summary_and_metadata_encrypted_at_rest_and_decrypt(tmp_path: Path) -> None:
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(
            channel_id="ch",
            raw=ADT,
            deliveries=[("d", ADT)],
            summary=EF3_SUMMARY,
            metadata=EF3_METADATA,
        )
        # ...ciphertext on disk (no MRN/name/site visible)...
        sm = _raw_at_rest(db, column="summary")
        md = _raw_at_rest(db, column="metadata")
        assert sm.startswith(PREFIX) and "999001" not in sm and "DOE" not in sm
        assert md.startswith(PREFIX) and "WESTWING" not in md
        # ...and decrypt on the detail + tracking-list read paths.
        rec = await store.get_message(mid)
        assert rec is not None and rec["summary"] == EF3_SUMMARY and rec["metadata"] == EF3_METADATA
        listed = await store.list_messages()
        assert any(m["summary"] == EF3_SUMMARY and m["metadata"] == EF3_METADATA for m in listed)
    finally:
        await store.close()


async def test_summary_in_dead_letter_view_decrypts(tmp_path: Path) -> None:
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(
            channel_id="ch", raw=ADT, deliveries=[("d", "P")], summary=EF3_SUMMARY
        )
        [row] = await store.outbox_for(mid)
        await store.claim_ready()
        await store.dead_letter_now(row["id"], "boom")
        dead = await store.list_dead()
        assert dead and dead[0]["summary"] == EF3_SUMMARY  # dead-letter view decrypts summary
    finally:
        await store.close()


async def test_migration_encrypts_existing_summary_metadata(tmp_path: Path) -> None:
    db = tmp_path / "mig.db"
    plain = await MessageStore.open(db)  # plaintext first (no key)
    try:
        await plain.enqueue_message(
            channel_id="ch", raw=ADT, deliveries=[], summary=EF3_SUMMARY, metadata=EF3_METADATA
        )
    finally:
        await plain.close()
    assert _raw_at_rest(db, column="summary") == EF3_SUMMARY  # cleartext at rest before migration

    encrypted = await MessageStore.open(db, cipher=make_cipher(generate_key()))  # reopen → migrate
    try:
        assert _raw_at_rest(db, column="summary").startswith(PREFIX)  # migrated on disk
        assert _raw_at_rest(db, column="metadata").startswith(PREFIX)
        [m] = await encrypted.list_messages()
        assert m["summary"] == EF3_SUMMARY and m["metadata"] == EF3_METADATA  # still readable
    finally:
        await encrypted.close()


async def test_null_summary_and_metadata_are_not_ciphered(tmp_path: Path) -> None:
    # A message with no summary/metadata: NULL stays NULL, never ciphertext-of-empty.
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[])
        con = sqlite3.connect(db)
        try:
            sm, md = con.execute("SELECT summary, metadata FROM messages").fetchone()
        finally:
            con.close()
        assert sm is None and md is None  # NULL stays NULL
    finally:
        await store.close()


# --- WP-5: keyring fingerprint + legacy key_id + rotation --------------------


def test_key_id_is_a_fingerprint_not_zero() -> None:
    import base64

    from messagefoundry.store.crypto import _fingerprint

    key_b64 = generate_key()
    token = make_cipher(key_b64).encrypt("x")
    fp = _fingerprint(base64.b64decode(key_b64))
    assert token.startswith(f"{PREFIX}{fp}:")  # self-identifying key_id
    assert not token.startswith(f"{PREFIX}0:")  # not the old hardcoded "0"


def test_legacy_key_id_zero_decrypts_via_fallback() -> None:
    # A pre-WP-5 row was tagged key_id '0'. The keyring's try-all fallback still decrypts it.
    import base64
    import os

    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_b64 = generate_key()
    key = base64.b64decode(key_b64)
    nonce = os.urandom(12)
    blob = base64.b64encode(nonce + AESGCM(key).encrypt(nonce, b"LEGACY", None)).decode()
    legacy = f"{PREFIX}0:{blob}"
    assert make_cipher(key_b64).decrypt(legacy) == "LEGACY"


async def test_rotation_reencrypts_and_retired_key_bridges(tmp_path: Path) -> None:
    db = tmp_path / "rot.db"
    key_a, key_b = generate_key(), generate_key()
    seed = await MessageStore.open(db, cipher=make_cipher(key_a))
    try:
        mid = await seed.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", ADT)])
    finally:
        await seed.close()
    raw_a = _raw_at_rest(db)

    # Reopen with B active + A retired: existing A-rows still read (decrypt via the retired key),
    # then rotate them to B.
    rotating = await MessageStore.open(db, cipher=make_cipher(key_b, [key_a]))
    try:
        assert (await rotating.get_message(mid))["raw"] == ADT
        assert await rotating.reencrypt_to_active() >= 2  # raw + the outbound payload
        assert await rotating.reencrypt_to_active() == 0  # idempotent
    finally:
        await rotating.close()
    raw_b = _raw_at_rest(db)
    assert raw_b.startswith(PREFIX) and raw_b != raw_a  # re-encrypted under the new key

    # B alone (no retired key) now reads everything — the bridge key is no longer needed.
    final = await MessageStore.open(db, cipher=make_cipher(key_b))
    try:
        assert (await final.get_message(mid))["raw"] == ADT
    finally:
        await final.close()


async def test_rotation_without_prior_key_raises(tmp_path: Path) -> None:
    db = tmp_path / "rot.db"
    key_a, key_b = generate_key(), generate_key()
    seed = await MessageStore.open(db, cipher=make_cipher(key_a))
    try:
        await seed.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", ADT)])
    finally:
        await seed.close()
    # Reopen with B active but WITHOUT supplying A as retired → the A-rows can't be decrypted, so
    # rotation aborts loudly (no silent data loss) rather than corrupting them.
    store = await MessageStore.open(db, cipher=make_cipher(key_b))
    try:
        with pytest.raises(CipherError):
            await store.reencrypt_to_active()
    finally:
        await store.close()


# --- M9: additive mfenc:v2 crypto-agility (version/alg dispatch) -------------
#
# The hard constraint is CRYPTO-1: the mfenc:v1 WRITER is frozen — existing v1 ciphertext and new v1
# writes stay byte-identical. M9 adds *agility infrastructure only*: a version/alg-dispatching cipher
# that is DECODE-CAPABLE of mfenc:v2 and CAN write it (opt-in), but WRITES v1 BY DEFAULT. AES-256-GCM
# stays the only registered algorithm. These tests pin: (1) v1 byte-identical (frozen fixture); (2) v2
# round-trip; (3) a v2-active cipher reads v1 with no rotation; (4) mixed v1+v2 rows; (5) fail-closed
# CipherError on an unknown marker version AND an unknown alg id.

# A FROZEN FIXTURE: a v1 blob written by the pre-M9 writer for plaintext "LEGACY-V1" under the key below
# (nonce fixed to 12 zero bytes). Hardcoded so a regression in the v1 reader is caught against a value
# this code did NOT just produce. key_b64 = base64(b"\x01"*32); nonce = b"\x00"*12.
_FROZEN_V1_KEY_B64 = base64.b64encode(b"\x01" * 32).decode()
_FROZEN_V1_PLAINTEXT = "LEGACY-V1"


def _v1_blob(key_b64: str, plaintext: str, nonce: bytes) -> str:
    """Reproduce the EXACT pre-M9 v1 marker layout for a fixed key+plaintext+nonce, independent of the
    cipher under test — the oracle the byte-identical assertions compare against."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    from messagefoundry.store.crypto import _fingerprint

    key = base64.b64decode(key_b64)
    ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
    blob = base64.b64encode(nonce + ct).decode("ascii")
    return f"mfenc:v1:{_fingerprint(key)}:{blob}"


def test_v1_frozen_fixture_decrypts() -> None:
    # A v1 blob built by the standalone oracle (not the cipher) still decrypts — the v1 READER is intact.
    frozen = _v1_blob(_FROZEN_V1_KEY_B64, _FROZEN_V1_PLAINTEXT, b"\x00" * 12)
    assert frozen.startswith("mfenc:v1:")
    assert make_cipher(_FROZEN_V1_KEY_B64).decrypt(frozen) == _FROZEN_V1_PLAINTEXT


def test_v1_writer_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    """The v1 WRITER output is byte-identical to the frozen layout for a fixed key+plaintext+nonce —
    the CRYPTO-1 guarantee. Pin the nonce (the only random input) so the full marker is deterministic,
    then compare the whole string against the independent oracle."""
    fixed_nonce = b"\x00" * 12
    monkeypatch.setattr("messagefoundry.store.crypto.os.urandom", lambda n: fixed_nonce)

    cipher = make_cipher(_FROZEN_V1_KEY_B64)  # default writer = v1
    produced = cipher.encrypt(_FROZEN_V1_PLAINTEXT)
    expected = _v1_blob(_FROZEN_V1_KEY_B64, _FROZEN_V1_PLAINTEXT, fixed_nonce)
    assert produced == expected  # full-string byte-identical, not just the prefix
    assert produced.startswith("mfenc:v1:") and ":v2:" not in produced


def test_default_writer_is_v1_not_v2() -> None:
    # The shipping default never emits a v2 marker — no at-rest format change ships with M9.
    token = make_cipher(generate_key()).encrypt("x")
    assert token.startswith(PREFIX)  # mfenc:v1:
    assert not token.startswith("mfenc:v2:")


def test_v2_round_trip_marker_and_decrypt() -> None:
    cipher = make_cipher(generate_key(), write_v2=True)
    token = cipher.encrypt(ADT)
    # mfenc:v2:<alg>:<key_id>:<b64> — alg id present, PHI hidden.
    assert token.startswith("mfenc:v2:a256gcm:")
    assert token.startswith(MARKER_PREFIX) and cipher.is_encrypted(token)
    # Deterministic PHI-hidden assertions (see test_cipher_round_trip_and_hides_plaintext —
    # the short-substring "MSH"/"DOE" check flaked in CI on a chance base64 collision).
    assert ADT not in token
    assert cipher.decrypt(token) == ADT
    assert cipher.encrypt(ADT) != token  # fresh nonce per encryption — tokens never repeat


def test_v2_active_decrypts_v1_without_rotation() -> None:
    # A v2-writing cipher must still READ v1 rows in place (the whole point of decode-capability — no
    # forced migration). Same key, so the v2-active cipher decrypts the v1 blob it did not write.
    key = generate_key()
    v1_token = make_cipher(key).encrypt(ADT)  # written by a v1 cipher
    assert v1_token.startswith(PREFIX)
    v2_cipher = make_cipher(key, write_v2=True)
    assert v2_cipher.decrypt(v1_token) == ADT  # decoded with no rotation


def test_v1_active_decrypts_v2() -> None:
    # Symmetric: the default v1-writing cipher decodes a v2 blob written under the same key.
    key = generate_key()
    v2_token = make_cipher(key, write_v2=True).encrypt(ADT)
    assert make_cipher(key).decrypt(v2_token) == ADT


def test_active_marker_prefix_v1_and_v2() -> None:
    # The rotation seam: active_marker_prefix carries the key fingerprint in the RIGHT position for each
    # version, and the value the writer emits starts with it (so rotation recognises active-key rows).
    key_b64 = generate_key()
    fp = AesGcmCipher(base64.b64decode(key_b64)).active_key_id

    v1 = make_cipher(key_b64)
    assert isinstance(v1, AesGcmCipher)
    assert v1.active_marker_prefix == f"mfenc:v1:{fp}:"
    assert v1.encrypt("x").startswith(v1.active_marker_prefix)

    v2 = make_cipher(key_b64, write_v2=True)
    assert isinstance(v2, AesGcmCipher)
    assert v2.active_marker_prefix == f"mfenc:v2:a256gcm:{fp}:"
    assert v2.encrypt("x").startswith(v2.active_marker_prefix)


def test_unknown_marker_version_fails_closed() -> None:
    # A future/garbage version under the mfenc: umbrella must raise, never pass through or mis-decode.
    cipher = make_cipher(generate_key())
    with pytest.raises(CipherError, match="unknown at-rest marker version"):
        cipher.decrypt("mfenc:v3:deadbeef:QUJD")


def test_unknown_v2_alg_fails_closed() -> None:
    # A v2 marker naming an algorithm this build doesn't register must raise (fail-closed agility).
    cipher = make_cipher(generate_key())
    with pytest.raises(CipherError, match="unknown/unsupported at-rest cipher algorithm"):
        cipher.decrypt("mfenc:v2:chacha20:deadbeef:QUJD")


def test_marker_prefix_is_version_agnostic() -> None:
    # Both versions sit under the bare mfenc: umbrella so a find-all LIKE matches either.
    key = generate_key()
    assert make_cipher(key).encrypt("x").startswith(MARKER_PREFIX)
    assert make_cipher(key, write_v2=True).encrypt("x").startswith(MARKER_PREFIX)
    assert MARKER_PREFIX == "mfenc:"


async def test_store_migration_skips_existing_v2_rows(tmp_path: Path) -> None:
    """A v2 ciphertext already on disk is recognised as encrypted by the version-agnostic find-all
    anchor, so the on-open migration leaves it untouched (it is NOT re-wrapped into v1-of-v2)."""
    db = tmp_path / "mixed.db"
    key = generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        # Hand-plant a v2 blob into a body column, bypassing the (v1-writing) store cipher.
        v2_token = make_cipher(key, write_v2=True).encrypt(ADT)
        mid = await store.enqueue_message(channel_id="ch", raw="placeholder", deliveries=[])
        await store._db.execute("UPDATE messages SET raw=? WHERE id=?", (v2_token, mid))
        await store._db.commit()
    finally:
        await store.close()

    # Reopen with a key → the on-open migration runs; the v2 row must be left byte-for-byte as-is.
    reopened = await MessageStore.open(db, cipher=make_cipher(key))
    try:
        assert _raw_at_rest(db) == v2_token  # untouched on disk (find-all saw it as encrypted)
        rec = await reopened.get_message(mid)
        assert rec is not None and rec["raw"] == ADT  # and still decrypts on read
    finally:
        await reopened.close()


async def test_store_reads_mixed_v1_and_v2_rows(tmp_path: Path) -> None:
    """Mixed v1 + v2 ciphertext under the same key in one table both decrypt on the normal read path —
    the decode-capable dispatch in action across rows."""
    db = tmp_path / "mixed2.db"
    key = generate_key()
    store = await MessageStore.open(db, cipher=make_cipher(key))  # writes v1
    try:
        m1 = await store.enqueue_message(channel_id="ch", raw=ADT, deliveries=[])  # v1 row
        # Plant a second message whose body is a v2 blob of a distinct payload.
        other = (
            "MSH|^~\\&|S|F|R|RF|20260101||ADT^A02|MSG2|P|2.5.1\rPID|1||200^^^H^MR||ROE^RICHARD\r"
        )
        v2_token = make_cipher(key, write_v2=True).encrypt(other)
        m2 = await store.enqueue_message(channel_id="ch", raw="ph", deliveries=[])
        await store._db.execute("UPDATE messages SET raw=? WHERE id=?", (v2_token, m2))
        await store._db.commit()

        rec1 = await store.get_message(m1)
        rec2 = await store.get_message(m2)
        assert rec1 is not None and rec1["raw"] == ADT  # v1 row decrypts
        assert rec2 is not None and rec2["raw"] == other  # v2 row decrypts
    finally:
        await store.close()


# --- SECMEM (#198): in-use memory hygiene (ASVS 13.3.3 / 11.7.2) --------------
#
# Best-effort lock + zeroize on the DEK and the transient plaintext buffers. The wipe is the only HARD
# assertion (memset is deterministic); locking is verified only to the extent that its *absence* never
# breaks the round trip (VirtualLock/mlock legitimately fail without privilege, so a real success can't
# be asserted portably). The v1 byte-identity gate lives in test_v1_frozen_fixture_decrypts above and
# must remain UNCHANGED.


def test_secure_zero_clears_bytearray() -> None:
    from messagefoundry.store.crypto import _secure_zero

    buf = bytearray(b"\x01" * 32)
    _secure_zero(buf)
    assert buf == bytearray(32)  # every byte scrubbed to 0x00
    assert len(buf) == 32  # length preserved, only the contents wiped


def test_secure_zero_empty_and_immutable_never_raise() -> None:
    from messagefoundry.store.crypto import _secure_zero

    _secure_zero(bytearray())  # empty buffer is a no-op, never raises
    # An immutable bytes handed in (defensive: the DEK path is bytearray) must be swallowed, not crash.
    _secure_zero(b"\x02" * 16)  # type: ignore[arg-type]


def test_round_trip_after_key_zeroization() -> None:
    # __init__ wipes the DEK bytearray after AESGCM copies the key; the cipher must still work.
    cipher = make_cipher(generate_key())
    token = cipher.encrypt(ADT)
    assert cipher.decrypt(token) == ADT


def test_lock_and_zero_run_on_the_dek_path(monkeypatch: pytest.MonkeyPatch) -> None:
    # Spy that the DEK (32 bytes) is offered to _lock_memory AND actually zeroized during construction.
    import messagefoundry.store.crypto as crypto

    locked_lens: list[int] = []
    zeroed_lens: list[int] = []
    real_zero = crypto._secure_zero

    def spy_lock(buf: bytearray) -> bool:
        locked_lens.append(len(buf))
        return False  # force the no-lock path (see the forced-failure round-trip test too)

    def spy_zero(buf: bytearray) -> None:
        zeroed_lens.append(len(buf))
        real_zero(buf)  # still perform the real wipe so behaviour is unchanged

    monkeypatch.setattr(crypto, "_lock_memory", spy_lock)
    monkeypatch.setattr(crypto, "_secure_zero", spy_zero)

    make_cipher(generate_key())  # constructing the keyring installs + wipes the DEK
    assert 32 in locked_lens  # the 32-byte DEK buffer was offered to _lock_memory
    assert 32 in zeroed_lens  # and was zeroized


def test_round_trip_when_lock_memory_unavailable(monkeypatch: pytest.MonkeyPatch) -> None:
    # Locking is best-effort: with _lock_memory forced to always fail (as it does unprivileged), the
    # cipher must still encrypt + decrypt correctly and _unlock_memory must not be invoked.
    import messagefoundry.store.crypto as crypto

    monkeypatch.setattr(crypto, "_lock_memory", lambda buf: False)

    def fail_unlock(buf: bytearray) -> None:
        raise AssertionError("_unlock_memory must not run when the lock was not taken")

    monkeypatch.setattr(crypto, "_unlock_memory", fail_unlock)

    cipher = make_cipher(generate_key())
    token = cipher.encrypt(ADT)
    assert cipher.decrypt(token) == ADT


def test_cipher_does_not_retain_raw_key_bytearray() -> None:
    # The raw DEK bytearray is not kept as an attribute — only the fingerprint + the AESGCM survive.
    from messagefoundry.store.crypto import AesGcmCipher

    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    assert not any(isinstance(v, bytearray) for v in vars(cipher).values())


# --- CRYPTO-6: require_encryption fail-CLOSED negative (configured-but-unusable key) ----------
#
# require_encryption is a *presence* guard (see tests/test_cli.py), not a key-usability validator, so a
# CONFIGURED-but-unusable key (foreign / rotated-away DEK) makes serve START. These two tests lock the
# runtime + cipher-level halves of the fail-closed net that catches such a key: it can NEVER silently
# degrade to the plaintext IdentityCipher (cipher level), and an unusable key at delivery time REFUSES
# the payload via per-row dead-lettering rather than handing the worker plaintext (runtime level). This
# is the exact boundary a security audit mistook for a bug: usability is enforced at runtime, not startup.


def test_configured_key_never_degrades_to_identity_cipher() -> None:
    # Cipher-level fail-CLOSED invariant: a CONFIGURED key — even a fixed "foreign" one that matches
    # nothing on a given store's disk — builds an *encrypting* AesGcmCipher, NEVER the passthrough
    # IdentityCipher. make_cipher returns IdentityCipher ONLY for an absent key, so a configured-but-
    # unusable key can never silently downgrade PHI to plaintext at rest. (Contrast the passthrough in
    # test_identity_cipher_is_passthrough, which is reached ONLY with no key.)
    for key in (generate_key(), _FROZEN_V1_KEY_B64):  # a fresh key and a fixed "foreign" key
        cipher = make_cipher(key)
        assert isinstance(cipher, AesGcmCipher) and cipher.encrypts
        assert not isinstance(cipher, IdentityCipher)
    # Only an ABSENT key (None or "") yields the plaintext passthrough — the sole path to identity.
    assert isinstance(make_cipher(None), IdentityCipher) and not make_cipher(None).encrypts
    assert isinstance(make_cipher(""), IdentityCipher)


async def test_foreign_key_at_runtime_dead_letters_rather_than_degrading(tmp_path: Path) -> None:
    # Runtime fail-CLOSED invariant: when the CONFIGURED store key is unusable against the rows on disk
    # — the "rotated-away DEK / foreign key" case (open under key B, rows written under key A, with NO
    # retired bridge key supplied) — the store REFUSES the payload (per-row dead-letter, "undecryptable"
    # reason). It never returns plaintext to the delivery worker and never degrades to the identity
    # cipher. This is the runtime safety net that backs require_encryption's presence-only startup guard.
    from messagefoundry.store.store import OutboxStatus

    db = tmp_path / "foreign.db"
    key_a, key_b = generate_key(), generate_key()
    seed = await MessageStore.open(db, cipher=make_cipher(key_a))
    try:
        mid = await seed.enqueue_message(channel_id="ch", raw=ADT, deliveries=[("d", "PAYLOAD-A")])
    finally:
        await seed.close()

    # Reopen under key B ALONE: the on-open migration skips already-encrypted (mfenc:) rows, so open
    # succeeds; the key mismatch surfaces only when a row is claimed for delivery.
    store = await MessageStore.open(db, cipher=make_cipher(key_b))
    try:
        # The reopened store still ENCRYPTS (never silently degrades to identity) despite the mismatch.
        assert isinstance(store._cipher, AesGcmCipher) and store._cipher.encrypts
        [row] = await store.outbox_for(mid)  # metadata-only read (no payload decrypt) → succeeds
        # Claiming the row REFUSES it: the undecryptable payload is dead-lettered, not returned/delivered.
        items = await store.claim_ready(limit=10)
        assert items == []  # nothing handed to the delivery worker (no plaintext leak)
        cur = await store._db.execute(
            "SELECT status, last_error FROM queue WHERE id=?", (row["id"],)
        )
        dead = await cur.fetchone()
        assert dead["status"] == OutboxStatus.DEAD.value  # poison row dead-lettered, not stranded
        # last_error is ciphered (WP-5) under the ACTIVE key B, so the reopened store decrypts it.
        assert "undecryptable" in store._cipher.decrypt(dead["last_error"] or "")
    finally:
        await store.close()


# --- CRYPTO-10: no key-material / PHI leak on the cipher failure + tripwire paths ---
#
# Positive regression guards for the PHI/key-at-rest invariant. A wrong-key decrypt failure and the
# 2**31 GCM invocation soft-warn must each carry ONLY the one-way key_id fingerprint — never the base64
# DEK, the wrapped ciphertext blob, or the plaintext body — in str(exc) OR in any DEBUG-level log record.


def test_cipher_decrypt_failure_leaks_no_key_material(caplog: pytest.LogCaptureFixture) -> None:
    key_a, key_b = generate_key(), generate_key()
    body = (
        "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|LEAKCANARY|P|2.5.1\r"
        "PID|1||100^^^H^MR||SECRETNAME^JANE\r"
    )
    token = make_cipher(key_a).encrypt(body)
    blob = token.split(":")[
        -1
    ]  # the base64(nonce ‖ ciphertext ‖ tag) segment of mfenc:v1:<kid>:<blob>

    with caplog.at_level(logging.DEBUG):
        with pytest.raises(CipherError) as excinfo:
            make_cipher(key_b).decrypt(token)  # no configured key authenticates the GCM tag

    for hay in (str(excinfo.value), caplog.text):
        assert body not in hay  # the plaintext body never surfaces on the failure path
        assert "SECRETNAME" not in hay  # nor a PHI fragment of it
        assert key_a not in hay and key_b not in hay  # no base64 DEK (only the one-way fingerprint)
        assert blob not in hay  # no wrapped ciphertext blob


def test_gcm_invocation_warning_leaks_no_key_material(caplog: pytest.LogCaptureFixture) -> None:
    import messagefoundry.store.crypto as crypto

    key = generate_key()
    cipher = make_cipher(key)
    assert isinstance(cipher, AesGcmCipher)
    body = "SECRETBODYCANARY residual free-text PHI"
    # Jump the in-memory counter to just below the soft-warn threshold, then encrypt across it (idiom
    # from test_audit_integrity.test_gcm_soft_warn_then_fail_closed) so the tripwire logs exactly once.
    cipher._invocations = crypto._GCM_SOFT_WARN_INVOCATIONS - 1
    with caplog.at_level(logging.DEBUG):
        cipher.encrypt(body)  # crosses 2**31 → one soft warning naming only the key fingerprint

    assert any(
        "2**31" in r.getMessage() for r in caplog.records
    )  # the tripwire fired (not vacuous)
    assert key not in caplog.text  # the base64 DEK is never logged (only the one-way fingerprint)
    assert body not in caplog.text and "SECRETBODYCANARY" not in caplog.text  # nor the plaintext


def test_every_secret_buffer_is_actually_zeroized_across_the_full_cipher_path(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # #198 — the DEK spy above only covers CONSTRUCTION. This pins the invariant across the whole
    # code-owned mutable-buffer surface: the DEK (install), the encrypt plaintext buffer, AND the
    # decrypt plaintext buffer are each not merely *offered* to the wiper but end genuinely all-zero.
    import messagefoundry.store.crypto as crypto

    real_zero = crypto._secure_zero
    wiped_nonempty: list[bool] = []

    def spy_zero(buf: bytearray) -> None:
        had_secret = len(buf) > 0 and any(buf)  # a buffer that actually held bytes to scrub
        real_zero(buf)  # perform the real wipe — behaviour must be unchanged
        if had_secret:
            wiped_nonempty.append(all(b == 0 for b in buf))  # …and confirm it is now scrubbed

    monkeypatch.setattr(crypto, "_secure_zero", spy_zero)

    cipher = make_cipher(generate_key())  # DEK buffer installed + wiped
    token = cipher.encrypt(ADT)  # plaintext-encode buffer wiped after the AEAD consumed it
    assert (
        cipher.decrypt(token) == ADT
    )  # decrypt plaintext buffer wiped after decode; round trip holds
    # At least the DEK + the two plaintext buffers were non-empty secrets, and every one ended all-zero.
    assert len(wiped_nonempty) >= 3
    assert all(wiped_nonempty)
