# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0196 (BACKLOG #2070): a fresh or rewound store must not restart a store key's AES-GCM count.

The cell-bound writer seals under a per-store sub-key, ``HKDF(DEK, info = label ‖ store salt)``, and
the persisted invocation bound counts that sub-key. Each acceptance criterion has an arm here. Per the
ADR's own rule, every route arm starts with the old key's count set near 2**31 and asserts WHICH key
the next write lands under: an arm that only asserted "the count is not zero" would pass with no fix.

The server backends' salt insert (Postgres ON CONFLICT, SQL Server HOLDLOCK MERGE) runs only on the
hosted server legs; the SQLite arms here exercise the same backend-agnostic ``bind_store_salt``.
"""

from __future__ import annotations

import asyncio
import base64
import hashlib
import io
import json
import os
import shutil
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.config.settings import BackupSettings, StoreSettings
from messagefoundry.pipeline import dr_backup as dr
from messagefoundry.pipeline.dr_backup import BackupError, BackupRunner, run_restore
from messagefoundry.store import MessageStore, crypto
from messagefoundry.store import backup_codec as bc
from messagefoundry.store.crypto import (
    STORE_SALT_BYTES,
    AesGcmCipher,
    CipherError,
    cell_aad,
    derive_store_data_key,
    generate_key,
    make_cipher,
    store_data_key_id,
)
from messagefoundry.store.gcm_bound import bind_store_salt, counts_under_dek
from messagefoundry.store.store import forget_store_salt

_NEAR_SOFT_WARN = 2**31 - 5
_BODY = "synthetic-ingress-body-{i}"


def _cell_bound(key: str, retired: list[str] | None = None) -> AesGcmCipher:
    cipher = make_cipher(key, retired or [], write_v2=True)
    assert isinstance(cipher, AesGcmCipher)
    return cipher


async def _open(path: Path, cipher: AesGcmCipher) -> MessageStore:
    return await MessageStore.open(path, cipher=cipher, audit_mac_key=cipher.audit_mac_key())


def _marker_salt(stored: str) -> bytes:
    """The salt a v4 marker names: ``mfenc:v4:<alg>:<key_id>:<salt_hex>:<b64>``."""
    parts = stored.split(":")
    assert parts[:2] == ["mfenc", "v4"], stored[:24]
    return bytes.fromhex(parts[4])


def _raw_on_disk(db: Path, message_id: str) -> str:
    conn = sqlite3.connect(db)
    try:
        return str(
            conn.execute("SELECT raw FROM messages WHERE id = ?", (message_id,)).fetchone()[0]
        )
    finally:
        conn.close()


def _salt_row(db: Path) -> str | None:
    conn = sqlite3.connect(db)
    try:
        row = conn.execute("SELECT salt FROM store_salt WHERE id = 1").fetchone()
    finally:
        conn.close()
    return None if row is None else str(row[0])


async def _persisted(db: Path, key_id: str) -> int:
    """A key's persisted count, read by a keyless open that reserves nothing."""
    plain = await MessageStore.open(db)
    try:
        return await plain.cipher_invocations(key_id)
    finally:
        await plain.close()


# --- the derivation ---------------------------------------------------------------------------


def test_the_cipher_derivation_is_rfc5869_hkdf_over_the_dek_and_salt() -> None:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    for _ in range(8):
        dek = os.urandom(32)
        salt = os.urandom(STORE_SALT_BYTES)
        reference = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"mefor/store-data-key/v1" + salt,
        ).derive(dek)
        assert bytes(derive_store_data_key(dek, salt)) == reference
        # The cipher's own path never keeps the DEK; it must still land on the same key.
        assert bytes(crypto._SubkeyDeriver(bytearray(dek)).derive(salt)) == reference
        assert reference != dek


def test_different_salts_give_different_keys_under_one_dek() -> None:
    dek = os.urandom(32)
    ids = {store_data_key_id(dek, os.urandom(STORE_SALT_BYTES)) for _ in range(16)}
    assert len(ids) == 16
    assert hashlib.sha256(dek).hexdigest()[:16] not in ids


def test_the_cipher_holds_no_copy_of_the_dek() -> None:
    key = generate_key()
    dek = base64.b64decode(key)
    cipher = _cell_bound(key)
    for value in vars(cipher).values():
        if isinstance(value, bytes | bytearray):
            assert dek not in bytes(value)


def test_the_writer_seals_under_the_sub_key_and_names_it_by_the_dek() -> None:
    key = generate_key()
    dek = base64.b64decode(key)
    cipher = _cell_bound(key)
    token = cipher.encrypt("x", aad=b"cell")
    salt = _marker_salt(token)
    assert salt == cipher.store_salt
    assert token.split(":")[3] == cipher.active_key_id == hashlib.sha256(dek).hexdigest()[:16]
    assert cipher.invocation_key_id == store_data_key_id(dek, salt) != cipher.active_key_id


def test_the_frozen_v1_writer_still_seals_under_the_dek() -> None:
    cipher = make_cipher(generate_key())
    assert isinstance(cipher, AesGcmCipher)
    assert cipher.store_salt is None
    assert cipher.invocation_key_id == cipher.active_key_id
    assert cipher.encrypt("x").startswith(f"mfenc:v1:{cipher.active_key_id}:")
    assert counts_under_dek(cipher) and not counts_under_dek(_cell_bound(generate_key()))


# --- AC-5: nothing written before, or under another salt, is stranded -------------------------


def test_AC5_a_value_sealed_under_the_raw_dek_still_opens() -> None:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key = generate_key()
    dek = base64.b64decode(key)
    kid = hashlib.sha256(dek).hexdigest()[:16]
    aad = cell_aad("messages", "raw", "m1")
    nonce = os.urandom(12)
    # A v2 value exactly as the pre-ADR-0196 writer produced it: the raw DEK, the cell AAD.
    v2 = "mfenc:v2:a256gcm:{}:{}".format(
        kid, base64.b64encode(nonce + AESGCM(dek).encrypt(nonce, b"legacy-v2", aad)).decode()
    )
    v1 = make_cipher(key).encrypt("legacy-v1")
    cipher = _cell_bound(key)
    assert cipher.decrypt(v2, aad=aad) == "legacy-v2"
    assert cipher.decrypt(v1, aad=aad) == "legacy-v1"


def test_AC5_a_value_under_an_earlier_salt_or_a_retired_dek_opens() -> None:
    old_key, key = generate_key(), generate_key()
    aad = cell_aad("uploaded_file", "body", "f1")
    earlier = _cell_bound(key).encrypt("earlier-salt", aad=aad)
    retired = _cell_bound(old_key).encrypt("retired-dek", aad=aad)
    cipher = _cell_bound(key, [old_key])
    assert _marker_salt(earlier) != cipher.store_salt
    assert cipher.decrypt(earlier, aad=aad) == "earlier-salt"
    assert cipher.decrypt(retired, aad=aad) == "retired-dek"


def test_tampering_with_the_marker_salt_fails_authentication() -> None:
    cipher = _cell_bound(generate_key())
    aad = cell_aad("messages", "raw", "m1")
    token = cipher.encrypt("body", aad=aad)
    parts = token.split(":")
    salt_hex = parts[4]
    flipped = ("1" if salt_hex[0] == "0" else "0") + salt_hex[1:]
    tampered = ":".join([*parts[:4], flipped, parts[5]])
    with pytest.raises(CipherError, match="no configured key decrypts"):
        cipher.decrypt(tampered, aad=aad)
    for bad in (salt_hex.upper(), salt_hex[:-2], salt_hex + "00", "zz" + salt_hex[2:]):
        if bad == salt_hex:
            continue
        with pytest.raises(CipherError):
            cipher.decrypt(":".join([*parts[:4], bad, parts[5]]), aad=aad)


def test_a_cipher_that_has_encrypted_refuses_a_second_salt() -> None:
    cipher = _cell_bound(generate_key())
    cipher.bind_store_salt(os.urandom(STORE_SALT_BYTES))  # before any encrypt: allowed
    cipher.encrypt("x")
    cipher.bind_store_salt(cipher.store_salt or b"")  # the same salt again: a no-op
    with pytest.raises(RuntimeError, match="another store salt"):
        cipher.bind_store_salt(os.urandom(STORE_SALT_BYTES))


async def test_a_refused_second_store_does_not_settle_the_first_stores_reserve(
    tmp_path: Path,
) -> None:
    """A cipher already counting for store A is refused by store B's open. The failed open's cleanup
    closes B, and that close must not settle A's reserve into B: the refund would land in B's row
    under A's sub-key, and would reset the cipher's cumulative figure for A."""
    cipher = _cell_bound(generate_key())
    first = await _open(tmp_path / "a.db", cipher)
    try:
        await first.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
        before = cipher.cumulative_invocations()
        assert before > 0
        with pytest.raises(RuntimeError, match="another store salt"):
            await _open(tmp_path / "b.db", cipher)
        assert cipher.cumulative_invocations() == before
    finally:
        await first.close()
    assert await _persisted(tmp_path / "b.db", cipher.invocation_key_id) == 0


# --- AC-1: a new store is a new key -----------------------------------------------------------


async def test_AC1_a_store_recreated_under_the_same_dek_seals_under_a_new_key(
    tmp_path: Path,
) -> None:
    """Route 1: the store file is moved aside and ``serve`` recreates it under the same key."""
    key = generate_key()
    dek = base64.b64decode(key)
    db = tmp_path / "store.db"
    first = _cell_bound(key)
    store = await _open(db, first)
    await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
    await store.add_cipher_invocations(first.invocation_key_id, _NEAR_SOFT_WARN)
    await store.close()  # settles the reserve, so the row now holds exactly what was spent
    old_total = await _persisted(db, first.invocation_key_id)
    assert old_total >= _NEAR_SOFT_WARN
    old_salt = first.store_salt
    moved = tmp_path / "moved-aside.db"
    for suffix in ("", "-wal", "-shm"):
        side = db.with_name(db.name + suffix)
        if side.exists():
            side.rename(moved.with_name(moved.name + suffix))

    second = _cell_bound(key)
    store = await _open(db, second)
    try:
        mid = await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=1))
        # The next write lands under a key no other store has used...
        written_under = _marker_salt(_raw_on_disk(db, mid))
        assert written_under == second.store_salt != old_salt
        assert store_data_key_id(dek, written_under) == second.invocation_key_id
        assert second.invocation_key_id != first.invocation_key_id
        # ...whose count is its own true count, not the used key's count zeroed.
        assert second.cumulative_invocations() < 2**20
        assert await store.cipher_invocations(first.invocation_key_id) == 0
    finally:
        await store.close()
    # The old store's count is untouched: nothing zeroed it, and nothing will seal under it again.
    assert await _persisted(moved, first.invocation_key_id) == old_total


async def test_AC1_a_reopen_keeps_the_salt_and_inherits_the_count(tmp_path: Path) -> None:
    key = generate_key()
    db = tmp_path / "store.db"
    first = _cell_bound(key)
    store = await _open(db, first)
    await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
    await store.add_cipher_invocations(first.invocation_key_id, _NEAR_SOFT_WARN)
    await store.close()
    salt_hex = _salt_row(db)
    assert salt_hex == (first.store_salt or b"").hex()

    again = _cell_bound(key)
    store = await _open(db, again)
    try:
        assert again.store_salt == first.store_salt
        assert again.invocation_key_id == first.invocation_key_id
        assert again.cumulative_invocations() >= _NEAR_SOFT_WARN
    finally:
        await store.close()


async def test_AC1_a_wiped_store_counts_nothing_under_the_old_sub_key(tmp_path: Path) -> None:
    """Route 2: the data directory is wiped while the key stays in the environment."""
    key = generate_key()
    db = tmp_path / "store.db"
    first = _cell_bound(key)
    store = await _open(db, first)
    await store.add_cipher_invocations(first.invocation_key_id, _NEAR_SOFT_WARN)
    await store.close()
    shutil.rmtree(tmp_path)
    tmp_path.mkdir()

    second = _cell_bound(key)
    store = await _open(db, second)
    try:
        assert second.invocation_key_id != first.invocation_key_id
        await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
    finally:
        await store.close()
    assert await _persisted(db, first.invocation_key_id) == 0
    assert await _persisted(db, second.invocation_key_id) > 0


# --- AC-2: concurrent first opens settle on one salt -----------------------------------------


async def test_AC2_every_handle_on_one_store_settles_on_one_salt(tmp_path: Path) -> None:
    """The engine-shard shape on SQLite: several live handles on one file. They open one after
    another, because SQLite's own schema step does not take concurrent opens; the race itself is
    covered by the binder test below and, on the server backends, by the hosted legs."""
    key = generate_key()
    db = tmp_path / "shared.db"
    ciphers = [_cell_bound(key) for _ in range(4)]
    assert len({c.store_salt for c in ciphers}) == 4  # each starts on its own stand-in salt
    stores = [await _open(db, c) for c in ciphers]
    try:
        assert len({c.store_salt for c in ciphers}) == 1
        assert len({c.invocation_key_id for c in ciphers}) == 1
        assert _salt_row(db) == (ciphers[0].store_salt or b"").hex()
    finally:
        for store in stores:
            await store.close()


async def test_AC2_the_binder_takes_the_salt_the_store_returns_not_its_candidate() -> None:
    cipher = _cell_bound(generate_key())
    winner = os.urandom(STORE_SALT_BYTES).hex()
    seen: list[str] = []

    async def _ensure(candidate: str) -> str:
        seen.append(candidate)
        return winner  # another process inserted first

    await bind_store_salt(cipher, _ensure)
    assert seen and seen[0] != winner
    assert cipher.store_salt == bytes.fromhex(winner)


async def test_the_binder_ignores_a_cipher_with_no_local_salt() -> None:
    async def _never(candidate: str) -> str:
        raise AssertionError("no salt should be minted for this cipher")

    await bind_store_salt(make_cipher(generate_key()), _never)  # frozen v1 writer
    await bind_store_salt(make_cipher(None), _never)  # identity


# --- AC-4: rotation and a new active key --------------------------------------------------------


async def test_AC4_a_new_active_dek_starts_at_zero_with_no_operator_step(tmp_path: Path) -> None:
    old_key, new_key = generate_key(), generate_key()
    db = tmp_path / "rotate.db"
    old = _cell_bound(old_key)
    store = await _open(db, old)
    await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
    await store.add_cipher_invocations(old.invocation_key_id, _NEAR_SOFT_WARN)
    await store.close()

    new = _cell_bound(new_key, [old_key])
    store = await _open(db, new)
    try:
        assert new.store_salt == old.store_salt  # same store, same salt
        assert new.invocation_key_id != old.invocation_key_id  # a new DEK is a new sub-key
        assert new.cumulative_invocations() == 0
        rewritten = await store.reencrypt_to_active()
        assert rewritten > 0
        assert new.cumulative_invocations() >= rewritten
    finally:
        await store.close()
    assert await _persisted(db, old.invocation_key_id) >= _NEAR_SOFT_WARN


async def test_rotate_key_reseals_a_value_left_under_an_older_salt(tmp_path: Path) -> None:
    key = generate_key()
    db = tmp_path / "resalt.db"
    first = _cell_bound(key)
    store = await _open(db, first)
    mid = await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
    await store.close()
    assert forget_store_salt(db) is True

    second = _cell_bound(key)
    store = await _open(db, second)
    try:
        assert _marker_salt(_raw_on_disk(db, mid)) == first.store_salt
        got = await store.get_message(mid)
        assert got is not None and got["raw"] == _BODY.format(i=0)  # AC-5 at store level
        assert await store.reencrypt_to_active() > 0
        assert _marker_salt(_raw_on_disk(db, mid)) == second.store_salt
    finally:
        await store.close()


# --- AC-7: key age stays on the root DEK ---------------------------------------------------------


async def test_AC7_the_key_age_id_is_the_dek_fingerprint_across_a_resalt(tmp_path: Path) -> None:
    """``engine.py`` stamps key age with ``store.cipher_info().active_key_id``. A re-salt must not
    change it, or ``reconcile_rotation_meta`` would read a new salt as a rotation of a DEK that never
    changed."""
    key = generate_key()
    dek_id = hashlib.sha256(base64.b64decode(key)).hexdigest()[:16]
    db = tmp_path / "age.db"
    first = _cell_bound(key)
    store = await _open(db, first)
    assert store.cipher_info().active_key_id == dek_id != first.invocation_key_id
    await store.close()
    forget_store_salt(db)
    second = _cell_bound(key)
    store = await _open(db, second)
    try:
        assert second.invocation_key_id != first.invocation_key_id
        assert store.cipher_info().active_key_id == dek_id
    finally:
        await store.close()


# --- the DR archive codec ------------------------------------------------------------------------


def test_a_salted_archive_round_trips_with_the_dek_alone() -> None:
    dek = base64.b64decode(generate_key())
    salt = os.urandom(STORE_SALT_BYTES)
    payload = os.urandom(3 * 1024 + 7)
    out = io.BytesIO()
    kid = bc.encrypt_stream(io.BytesIO(payload), out, dek, chunk_size=1024, salt=salt)
    assert kid == bc.key_fingerprint(dek)  # the header still names the DEK, for the key match
    header = bc.read_header(io.BytesIO(out.getvalue()))
    assert header.format_version == 2 and header.salt == salt
    back = io.BytesIO()
    bc.decrypt_stream(io.BytesIO(out.getvalue()), back, dek)
    assert back.getvalue() == payload


def test_an_archive_is_sealed_under_the_sub_key_not_the_dek() -> None:
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dek = base64.b64decode(generate_key())
    salt = os.urandom(STORE_SALT_BYTES)
    out = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"frame"), out, dek, salt=salt)
    blob = out.getvalue()
    src = io.BytesIO(blob)
    header = bc.read_header(src)
    nonce = src.read(12)
    (ctlen,) = bc._U32.unpack(src.read(4))
    ct = src.read(ctlen)
    aad = bc._aad(hashlib.sha256(header.to_json_bytes()).digest(), 0, final=True)
    assert AESGCM(bytes(derive_store_data_key(dek, salt))).decrypt(nonce, ct, aad) == b"frame"
    with pytest.raises(InvalidTag):
        AESGCM(dek).decrypt(nonce, ct, aad)


def test_tampering_with_the_archive_salt_fails_authentication() -> None:
    dek = base64.b64decode(generate_key())
    salt = os.urandom(STORE_SALT_BYTES)
    out = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"payload"), out, dek, salt=salt)
    other = os.urandom(STORE_SALT_BYTES).hex()
    tampered = out.getvalue().replace(salt.hex().encode(), other.encode())
    assert tampered != out.getvalue()
    with pytest.raises(bc.BackupCodecError, match="authentication failed"):
        bc.decrypt_stream(io.BytesIO(tampered), io.BytesIO(), dek)


def test_a_version_1_archive_sealed_under_the_dek_still_decrypts() -> None:
    """Built the way the pre-ADR-0196 writer built it: version byte 1, no ``salt`` key, raw DEK."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    dek = base64.b64decode(generate_key())
    header = json.dumps(
        {
            "format_version": 1,
            "alg": "a256gcm",
            "key_id": bc.key_fingerprint(dek),
            "chunk_size": 1024,
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    digest = hashlib.sha256(header).digest()
    nonce = os.urandom(12)
    ct = AESGCM(dek).encrypt(nonce, b"old-archive", bc._aad(digest, 0, final=True))
    blob = bc.MAGIC + bytes([1]) + bc._U32.pack(len(header)) + header
    blob += nonce + bc._U32.pack(len(ct)) + ct
    back = io.BytesIO()
    got = bc.decrypt_stream(io.BytesIO(blob), back, dek)
    assert got.format_version == 1 and got.salt is None
    assert back.getvalue() == b"old-archive"


def test_a_malformed_archive_salt_is_a_header_refusal() -> None:
    dek = base64.b64decode(generate_key())
    header = json.dumps(
        {
            "format_version": 2,
            "alg": "a256gcm",
            "key_id": bc.key_fingerprint(dek),
            "chunk_size": 1024,
            "salt": "NOT-HEX",
        },
        sort_keys=True,
        separators=(",", ":"),
    ).encode()
    blob = bc.MAGIC + bytes([2]) + bc._U32.pack(len(header)) + header
    with pytest.raises(bc.BackupCodecError, match="missing/invalid field"):
        bc.read_header(io.BytesIO(blob))


# --- AC-6 and AC-3: the backup runner and restore -----------------------------------------------


def _store_settings(path: Path, key: str) -> StoreSettings:
    return StoreSettings(path=str(path), encryption_key=key)


async def _live_store(db: Path, key: str) -> tuple[MessageStore, AesGcmCipher]:
    cipher = _cell_bound(key)
    store = await _open(db, cipher)
    await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
    return store, cipher


async def test_AC6_archive_frames_are_charged_to_the_key_they_are_sealed_under(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    db = tmp_path / "live.db"
    store, cipher = await _live_store(db, key)
    frames: list[int] = []
    real = bc.encrypt_stream  # what dr_backup imported; patched there by name below

    def _spy(src, dst, k, *, chunk_size=None, on_frames=None, salt=None):
        assert salt == cipher.store_salt, "the frames must be sealed under the live store's salt"

        def _record(n: int) -> None:
            frames.append(n)
            if on_frames is not None:
                on_frames(n)

        return real(src, dst, k, chunk_size=chunk_size, on_frames=_record, salt=salt)

    monkeypatch.setattr(dr, "encrypt_stream", _spy)
    try:
        before = await store.cipher_invocations(cipher.invocation_key_id)
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "backups")),
            store_settings=_store_settings(db, key),
            config_dir=None,
            instance="dev",
        )
        result = await runner.run_once(now=1000.0)
        assert result is not None and result.encrypted
        assert sum(frames) > 0
        assert await store.cipher_invocations(cipher.invocation_key_id) - before == sum(frames)
        # Nothing is charged to the DEK's own row: no frame was sealed under the DEK.
        assert await store.cipher_invocations(cipher.active_key_id) == 0
        header = bc.read_header(io.BytesIO(Path(result.archive_path).read_bytes()))
        assert header.salt == cipher.store_salt
    finally:
        await store.close()


async def test_AC6_a_run_that_fails_after_sealing_still_charges_its_frames(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    db = tmp_path / "live.db"
    store, cipher = await _live_store(db, key)
    frames: list[int] = []
    real = bc.encrypt_stream  # what dr_backup imported; patched there by name below

    def _dies_after_sealing(src, dst, k, *, chunk_size=None, on_frames=None, salt=None):
        def _record(n: int) -> None:
            frames.append(n)
            if on_frames is not None:
                on_frames(n)

        real(src, dst, k, chunk_size=chunk_size, on_frames=_record, salt=salt)
        raise OSError("the destination went away after the frames were sealed")

    monkeypatch.setattr(dr, "encrypt_stream", _dies_after_sealing)
    try:
        before = await store.cipher_invocations(cipher.invocation_key_id)
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "backups")),
            store_settings=_store_settings(db, key),
            config_dir=None,
            instance="dev",
        )
        with pytest.raises(BackupError):
            await runner.run_once(now=1000.0)
        assert sum(frames) > 0
        assert await store.cipher_invocations(cipher.invocation_key_id) - before == sum(frames)
        assert runner._frames == []  # nothing is left for a later run to charge under its key
    finally:
        await store.close()


async def test_AC6_frames_whose_charge_fails_stay_queued_for_the_next_run(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A failed charge puts its frames back rather than dropping them, so the key's persisted count
    never under-reads by them; the next charge lands them on their own key."""
    key = generate_key()
    db = tmp_path / "live.db"
    store, cipher = await _live_store(db, key)
    try:
        runner = BackupRunner(
            store,
            BackupSettings(enabled=True, destination=str(tmp_path / "backups")),
            store_settings=_store_settings(db, key),
            config_dir=None,
            instance="dev",
        )
        key_id = cipher.invocation_key_id
        before = await store.cipher_invocations(key_id)
        runner._record_frames(key_id, 7)

        async def _down(_key_id: str, _count: int) -> int:
            raise sqlite3.OperationalError("database is locked")

        with monkeypatch.context() as m:
            m.setattr(store, "add_cipher_invocations", _down)
            await runner._charge_archive_invocations()
        assert runner._frames == [(key_id, 7)]
        await runner._charge_archive_invocations()
        assert runner._frames == []
        assert await store.cipher_invocations(key_id) - before == 7
    finally:
        await store.close()


async def test_AC3_a_restored_store_seals_under_a_new_key(tmp_path: Path) -> None:
    key = generate_key()
    dek = base64.b64decode(key)
    db = tmp_path / "live.db"
    store, live = await _live_store(db, key)
    mid = await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=1))
    await store.add_cipher_invocations(live.invocation_key_id, _NEAR_SOFT_WARN)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "backups")),
        store_settings=_store_settings(db, key),
        config_dir=None,
        instance="dev",
    )
    result = await runner.run_once(now=1000.0)
    assert result is not None
    await store.close()

    dest = tmp_path / "restored" / "store.db"
    await run_restore(
        result.archive_path, dest_store_path=dest, store_settings=_store_settings(dest, key)
    )
    assert _salt_row(dest) is None  # re-salted before it could open

    restored_cipher = _cell_bound(key)
    restored = await _open(dest, restored_cipher)
    try:
        assert restored_cipher.store_salt != live.store_salt
        assert restored_cipher.invocation_key_id != live.invocation_key_id
        # The archive's low row for the live sub-key comes along, and nothing seals under it again.
        assert await restored.cipher_invocations(live.invocation_key_id) >= _NEAR_SOFT_WARN
        new_mid = await restored.enqueue_ingress(channel_id="c", raw=_BODY.format(i=2))
        salt = _marker_salt(_raw_on_disk(dest, new_mid))
        assert store_data_key_id(dek, salt) == restored_cipher.invocation_key_id
        # AC-5: the restored values, sealed under the live salt, still open with the DEK alone.
        got = await restored.get_message(mid)
        assert got is not None and got["raw"] == _BODY.format(i=1)
    finally:
        await restored.close()


async def test_AC8_the_full_restore_verify_seals_nothing_under_the_live_sub_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    key = generate_key()
    db = tmp_path / "live.db"
    store, live = await _live_store(db, key)
    snap = tmp_path / "snap.db"
    await store.snapshot_to(snap)
    await store.close()
    assert _salt_row(snap) == (live.store_salt or b"").hex()

    bound: list[bytes] = []
    real_bind = AesGcmCipher.bind_store_salt

    def _record(self: AesGcmCipher, salt: bytes) -> None:
        bound.append(bytes(salt))
        real_bind(self, salt)

    monkeypatch.setattr(AesGcmCipher, "bind_store_salt", _record)
    # Off the loop, as the verify path runs it: it drives its own event loop.
    status, msg, cells = await asyncio.to_thread(
        dr._full_open_check, snap, _store_settings(snap, key)
    )
    assert status == "PASS", msg
    assert cells > 0
    assert bound, "the scratch open must have bound a salt, or this proves nothing"
    assert live.store_salt not in bound


def test_forget_store_salt_on_a_file_with_no_salt_table(tmp_path: Path) -> None:
    db = tmp_path / "old.db"
    conn = sqlite3.connect(db)
    conn.execute("CREATE TABLE t (x)")
    conn.commit()
    conn.close()
    assert forget_store_salt(db) is False


def _wal_only_salt_copy(tmp_path: Path) -> Path:
    """A store copy whose salt row exists ONLY in its ``-wal``: the main file and the WAL are copied
    while the writer still holds them, so nothing was checkpointed into the main file."""
    src = tmp_path / "src.db"
    conn = sqlite3.connect(src, isolation_level=None)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA wal_autocheckpoint=0")
    conn.execute("CREATE TABLE store_salt (id INTEGER PRIMARY KEY, salt TEXT, created_at REAL)")
    conn.execute("INSERT INTO store_salt VALUES (1, ?, 0)", ("ab" * 16,))
    copy = tmp_path / "copy.db"
    shutil.copyfile(src, copy)
    shutil.copyfile(src.with_name("src.db-wal"), copy.with_name("copy.db-wal"))
    conn.close()
    return copy


def test_forget_store_salt_proves_the_row_is_gone_from_the_main_file(tmp_path: Path) -> None:
    copy = _wal_only_salt_copy(tmp_path)
    assert copy.with_name("copy.db-wal").stat().st_size > 0, "the row must start in the WAL"
    assert forget_store_salt(copy) is True
    # What restore places is the main file alone, so read exactly that: a lone copy of it.
    lone = tmp_path / "lone.db"
    shutil.copyfile(copy, lone)
    assert _salt_row(lone) is None
    wal = copy.with_name("copy.db-wal")
    assert not wal.exists() or wal.stat().st_size == 0


def test_forget_store_salt_refuses_a_file_another_connection_holds(tmp_path: Path) -> None:
    copy = _wal_only_salt_copy(tmp_path)
    holder = sqlite3.connect(copy, isolation_level=None)
    try:
        holder.execute("BEGIN")
        holder.execute("SELECT count(*) FROM store_salt").fetchone()
        with pytest.raises(sqlite3.OperationalError):
            forget_store_salt(copy)
    finally:
        holder.close()


async def test_AC3_restore_refuses_rather_than_place_a_store_it_could_not_resalt(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    from messagefoundry.store import store as store_module

    key = generate_key()
    db = tmp_path / "live.db"
    store, _live = await _live_store(db, key)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "backups")),
        store_settings=_store_settings(db, key),
        config_dir=None,
        instance="dev",
    )
    result = await runner.run_once(now=1000.0)
    assert result is not None
    await store.close()

    def _cannot(path: Path) -> bool:
        raise sqlite3.OperationalError("simulated: the WAL could not be checkpointed")

    monkeypatch.setattr(store_module, "forget_store_salt", _cannot)
    dest = tmp_path / "restored" / "store.db"
    with pytest.raises(BackupError, match="WAL could not be checkpointed"):
        await run_restore(
            result.archive_path, dest_store_path=dest, store_settings=_store_settings(dest, key)
        )
    assert not dest.exists()


async def test_AC6_frames_a_cancelled_run_reports_late_are_charged_to_their_own_key(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A build cancelled on the loop keeps sealing on its worker thread and reports its frames AFTER
    that run's charge. The next run must charge them under the key they were sealed under, not its
    own -- which differs after a re-salt or a rotation."""
    key = generate_key()
    dek = base64.b64decode(key)
    db = tmp_path / "live.db"
    store, cipher = await _live_store(db, key)
    first_salt = cipher.store_salt
    assert first_salt is not None
    first_id = store_data_key_id(dek, first_salt)
    stashed: list[object] = []
    real = bc.encrypt_stream

    def _reports_nothing_yet(src, dst, k, *, chunk_size=None, on_frames=None, salt=None):
        stashed.append(on_frames)  # the report a still-running worker would make later
        return real(src, dst, k, chunk_size=chunk_size, on_frames=None, salt=salt)

    monkeypatch.setattr(dr, "encrypt_stream", _reports_nothing_yet)
    runner = BackupRunner(
        store,
        BackupSettings(enabled=True, destination=str(tmp_path / "backups")),
        store_settings=_store_settings(db, key),
        config_dir=None,
        instance="dev",
    )
    try:
        assert await runner.run_once(now=1000.0) is not None
        before_first = await store.cipher_invocations(first_id)
        late = stashed[0]
        assert callable(late)
        late(7)  # the cancelled run's worker finally reports

        # The next run seals under a different sub-key, as it would after a re-salt.
        second_salt = os.urandom(STORE_SALT_BYTES)
        second_id = store_data_key_id(dek, second_salt)
        monkeypatch.setattr(runner, "_store_salt", lambda: second_salt)
        own: list[int] = []

        def _counts(src, dst, k, *, chunk_size=None, on_frames=None, salt=None):
            def _record(n: int) -> None:
                own.append(n)
                if on_frames is not None:
                    on_frames(n)

            return real(src, dst, k, chunk_size=chunk_size, on_frames=_record, salt=salt)

        monkeypatch.setattr(dr, "encrypt_stream", _counts)
        before_second = await store.cipher_invocations(second_id)
        assert await runner.run_once(now=90000.0) is not None
        # The late 7 land on the key they were sealed under, and none of them on the new one.
        assert await store.cipher_invocations(first_id) - before_first == 7
        assert sum(own) > 0
        assert await store.cipher_invocations(second_id) - before_second == sum(own)
    finally:
        await store.close()


async def test_the_gcm_invocations_alert_names_the_dek_not_the_sub_key(tmp_path: Path) -> None:
    from messagefoundry.pipeline.gcm_invocations import GcmInvocationRunner

    calls: list[str] = []

    class _Sink:
        def gcm_invocations(
            self, name: str, *, key_id: str, invocations: int, ceiling: int
        ) -> None:
            calls.append(key_id)

        def __getattr__(self, _name: str) -> object:
            return lambda *a, **k: None

    key = generate_key()
    db = tmp_path / "alert.db"
    cipher = _cell_bound(key)
    store = await _open(db, cipher)
    try:
        await store.enqueue_ingress(channel_id="c", raw=_BODY.format(i=0))
        runner = GcmInvocationRunner(store, alert_sink=_Sink(), warn_at=1)  # type: ignore[arg-type]
        await runner.run_once()
        assert calls == [cipher.active_key_id]
        assert cipher.active_key_id != cipher.invocation_key_id
    finally:
        await store.close()


def test_the_archive_frame_sub_key_is_wiped_after_use(monkeypatch: pytest.MonkeyPatch) -> None:
    dek = base64.b64decode(generate_key())
    salt = os.urandom(STORE_SALT_BYTES)
    handed_out: list[bytearray] = []
    real = derive_store_data_key  # the name backup_codec imported; patched there below

    def _tracked(k: bytes | bytearray, s: bytes) -> bytearray:
        sub = real(k, s)
        handed_out.append(sub)
        return sub

    monkeypatch.setattr(bc, "derive_store_data_key", _tracked)
    out = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"payload"), out, dek, salt=salt)
    back = io.BytesIO()
    bc.decrypt_stream(io.BytesIO(out.getvalue()), back, dek)
    assert back.getvalue() == b"payload"
    assert len(handed_out) == 2  # one derivation to seal, one to open
    assert all(sub == bytearray(len(sub)) for sub in handed_out)
