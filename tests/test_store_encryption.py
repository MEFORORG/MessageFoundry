"""Phase-8 STORE-1: PHI-at-rest encryption — the cipher + the store seam + migration."""

from __future__ import annotations

import base64
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.store.crypto import (
    PREFIX,
    CipherError,
    IdentityCipher,
    generate_key,
    make_cipher,
)
from messagefoundry.store.store import MessageStore

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
    assert "DOE" not in token and "MSH" not in token  # PHI not visible in the ciphertext
    assert cipher.decrypt(token) == ADT


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

PHI_ERR = "parse failed at PID|1||999^^^H^MR||SECRET^PATIENT"


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
