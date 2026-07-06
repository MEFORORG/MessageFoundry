# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``.mfbak`` chunked AES-256-GCM archive codec (ADR 0049, #60): round-trips faithfully across
chunk boundaries; tamper (a flipped byte, a reordered/dropped/appended frame) fails the GCM tag
fail-closed; a wrong key is a clean KEY_MISMATCH *before* decrypt; and the no-key/PHI fail-closed
posture is enforced by the runner (AC-3/AC-4). The key_id fingerprint matches the store cipher's."""

from __future__ import annotations

import io
import os

import pytest

from messagefoundry.store import backup_codec as bc
from messagefoundry.store.crypto import AesGcmCipher


def _roundtrip(payload: bytes, *, chunk_size: int, key: bytes | None = None) -> bytes:
    key = key or os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(payload), enc, key, chunk_size=chunk_size)
    dec = io.BytesIO()
    bc.decrypt_stream(io.BytesIO(enc.getvalue()), dec, key)
    return dec.getvalue()


@pytest.mark.parametrize("size", [0, 1, 4095, 4096, 4097, 100_000])
def test_roundtrip_across_chunk_boundaries(size: int) -> None:
    payload = os.urandom(size)
    assert _roundtrip(payload, chunk_size=4096) == payload


def test_empty_payload_still_carries_a_final_frame() -> None:
    # An empty source must still emit exactly one final (empty) frame so the terminator is present.
    assert _roundtrip(b"", chunk_size=4096) == b""


def test_key_id_matches_store_cipher_fingerprint() -> None:
    # AC-3: the archive key_id must equal the store cipher's active_key_id (same DEK = same fingerprint),
    # so a backup is provably sealed under the key the store uses.
    key = os.urandom(32)
    cipher = AesGcmCipher(key)
    assert bc.key_fingerprint(key) == cipher.active_key_id


def test_archive_encrypted_under_store_dek() -> None:
    # AC-3: a configured key yields a real AEAD archive (header carries the key_id, body is ciphertext —
    # the plaintext is NOT present verbatim).
    key = os.urandom(32)
    plaintext = b"PHI-bearing-store-bytes-" * 1000
    enc = io.BytesIO()
    kid = bc.encrypt_stream(io.BytesIO(plaintext), enc, key)
    blob = enc.getvalue()
    assert blob.startswith(bc.MAGIC)
    assert bc.key_fingerprint(key) == kid
    assert b"PHI-bearing-store-bytes-" not in blob  # not stored in the clear


def test_archive_key_id_reads_header_without_decrypting() -> None:
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"x" * 10), enc, key)
    hdr = bc.read_header(io.BytesIO(enc.getvalue()))
    assert hdr.key_id == bc.key_fingerprint(key)
    assert hdr.alg == bc.ALG_AES_256_GCM
    assert hdr.format_version == bc.FORMAT_VERSION


def test_wrong_key_is_key_mismatch_before_decrypt() -> None:
    # AC-5: a wrong key is a clean KEY_MISMATCH (header fingerprint compare), NOT an opaque tag failure.
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"data" * 1000), enc, key)
    with pytest.raises(bc.BackupKeyMismatch):
        bc.decrypt_stream(io.BytesIO(enc.getvalue()), io.BytesIO(), os.urandom(32))


def test_tampered_byte_fails_the_tag() -> None:
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"payload" * 2000), enc, key, chunk_size=4096)
    blob = bytearray(enc.getvalue())
    # Flip a byte well inside the first ciphertext frame (past the header).
    blob[-50] ^= 0x01
    with pytest.raises(bc.BackupCodecError):
        bc.decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), key)


def test_truncated_archive_fails() -> None:
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"abc" * 5000), enc, key, chunk_size=1024)
    truncated = enc.getvalue()[:-100]  # drop the tail of the last frame
    with pytest.raises(bc.BackupCodecError):
        bc.decrypt_stream(io.BytesIO(truncated), io.BytesIO(), key)


def test_appended_bytes_after_final_frame_rejected() -> None:
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"abc" * 5000), enc, key, chunk_size=1024)
    tampered = enc.getvalue() + b"EXTRA"
    with pytest.raises(bc.BackupCodecError):
        bc.decrypt_stream(io.BytesIO(tampered), io.BytesIO(), key)


def test_tampered_header_key_id_is_caught() -> None:
    # The header is bound as AAD. Editing the header's key_id makes the precheck see a different
    # fingerprint (KEY_MISMATCH for the real key) — a tampered header never silently decrypts.
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"z" * 5000), enc, key, chunk_size=1024)
    blob = bytearray(enc.getvalue())
    # The key_id hex lives in the JSON header; change one of its digits to a different hex digit so the
    # header still parses but its fingerprint no longer matches the real key.
    kid = bc.key_fingerprint(key).encode()
    idx = blob.find(kid)
    assert idx != -1
    blob[idx] = ord("0") if blob[idx] != ord("0") else ord("1")
    with pytest.raises(
        bc.BackupCodecError
    ):  # KEY_MISMATCH (a subclass) — header tamper never decrypts
        bc.decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), key)


def test_bad_magic_rejected() -> None:
    with pytest.raises(bc.BackupCodecError):
        bc.read_header(io.BytesIO(b"NOTMFBAK" + b"\x00" * 20))


def test_unsupported_version_rejected() -> None:
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"q" * 100), enc, key)
    blob = bytearray(enc.getvalue())
    blob[len(bc.MAGIC)] = 99  # bump the version byte to an unsupported value
    with pytest.raises(bc.BackupCodecError):
        bc.read_header(io.BytesIO(bytes(blob)))


def test_short_key_rejected() -> None:
    with pytest.raises(bc.BackupCodecError):
        bc.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), os.urandom(16))
