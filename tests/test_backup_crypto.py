# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The ``.mfbak`` chunked AES-256-GCM archive codec (ADR 0049, #60): round-trips faithfully across
chunk boundaries; tamper (a flipped byte, a reordered/dropped/appended frame) fails the GCM tag
fail-closed; a wrong key is a clean KEY_MISMATCH *before* decrypt; and the no-key/PHI fail-closed
posture is enforced by the runner (AC-3/AC-4). The key_id fingerprint matches the store cipher's."""

from __future__ import annotations

import base64
import io
import json
import logging
import os
import struct

import pytest

from messagefoundry.store import backup_codec as bc
from messagefoundry.store.crypto import STORE_SALT_BYTES, AesGcmCipher


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
    # A bytearray COPY: the cipher owns and zeroizes the buffer it is given, so `key` stays intact.
    cipher = AesGcmCipher(bytearray(key))
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


# --- CRYPTO-10: no key-material / PHI leak on the .mfbak failure paths ---
#
# BackupKeyMismatch (wrong-key precheck) and BackupCodecError (a failed AEAD tag) must each carry ONLY
# the one-way key_id fingerprint / frame index — never the raw DEK (hex or base64) or the archived
# plaintext — in str(exc) OR in any DEBUG-level log record. The codec module logs nothing, so caplog
# stays empty; the guard catches a future regression that starts leaking on these paths.


def test_key_mismatch_leaks_no_key_material(caplog: pytest.LogCaptureFixture) -> None:
    seal_key = os.urandom(32)
    wrong_key = os.urandom(32)
    plaintext = b"PHI-BODY-CANARY archived bytes " * 200
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(plaintext), enc, seal_key)

    with caplog.at_level(logging.DEBUG), pytest.raises(bc.BackupKeyMismatch) as excinfo:
        bc.decrypt_stream(io.BytesIO(enc.getvalue()), io.BytesIO(), wrong_key)

    seal_b64 = base64.b64encode(seal_key).decode()
    wrong_b64 = base64.b64encode(wrong_key).decode()
    for hay in (str(excinfo.value), caplog.text):
        assert seal_key.hex() not in hay and wrong_key.hex() not in hay  # no raw DEK hex
        assert seal_b64 not in hay and wrong_b64 not in hay  # no base64 DEK
        assert "PHI-BODY-CANARY" not in hay  # nor the archived plaintext


def test_auth_failure_leaks_no_key_material(caplog: pytest.LogCaptureFixture) -> None:
    key = os.urandom(32)
    plaintext = b"PHI-BODY-CANARY tamper payload " * 200
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(plaintext), enc, key, chunk_size=4096)
    blob = bytearray(enc.getvalue())
    blob[-50] ^= 0x01  # flip a byte inside the final ciphertext frame → GCM tag fails (correct key)

    with caplog.at_level(logging.DEBUG), pytest.raises(bc.BackupCodecError) as excinfo:
        bc.decrypt_stream(io.BytesIO(bytes(blob)), io.BytesIO(), key)

    key_b64 = base64.b64encode(key).decode()
    for hay in (str(excinfo.value), caplog.text):
        assert key.hex() not in hay and key_b64 not in hay  # no raw DEK (hex or base64)
        assert "PHI-BODY-CANARY" not in hay  # nor the archived plaintext


# --- BACKLOG #1570: every attacker-declared length is bounded BEFORE the read it drives ---
#
# `hdrlen` and each frame's `ctlen` are uint32 fields in a PLAINTEXT, as-yet-unauthenticated prefix.
# A reader that hands them straight to read() allocates whatever an attacker wrote there -- before
# key matching, and before any GCM tag has authenticated anything at all.

_U32 = struct.Struct("<I")
#: 12, the format's fixed per-frame nonce width. Read off the module under test rather than re-typed,
#: so a format change moves the crafting helpers with it instead of silently mis-aiming them.
_NONCE_BYTES = bc._NONCE_BYTES


class _OversizedRead(Exception):
    """The parser asked its source for more bytes than the test permits -- that is, it READ FIRST and
    would have validated afterwards."""


class _GuardedSource(io.BytesIO):
    """A ``.mfbak`` source that refuses to serve an oversized read.

    THIS IS THE INSTRUMENT, and without it every test below passes vacuously. Asserting only that a
    crafted archive raises ``BackupCodecError`` cannot tell a bound that rejects BEFORE the read from
    one that allocates 4 GiB first and then fails on the short read -- both raise the same type with a
    plausible message. Capping what the source will serve makes the difference observable: a parser
    that reads first dies here instead, with a different exception class that ``pytest.raises`` will
    not swallow."""

    def __init__(self, data: bytes, *, allow: int) -> None:
        super().__init__(data)
        self._allow = allow

    def read(self, size: int | None = -1, /) -> bytes:
        if size is None or size < 0 or size > self._allow:
            raise _OversizedRead(
                f"parser requested {size} bytes (this source allows {self._allow})"
            )
        return super().read(size)


def _crafted(*, key: bytes, chunk_size: int | None = None, ctlen: int | None = None) -> bytes:
    """A real archive with its UNAUTHENTICATED prefix edited -- exactly an attacker's reach.

    The magic, version, key_id and ciphertext are all genuine; only the header's declared
    ``chunk_size`` and the first frame's declared ``ctlen`` are rewritten (each left alone when
    ``None``). ``hdrlen`` is refitted to the rewritten header so the stream stays well-formed and the
    parser reaches the bound under test rather than tripping over a length that no longer matches."""
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"x" * 100), enc, key, chunk_size=1024)
    blob = enc.getvalue()
    off = len(bc.MAGIC) + 1
    (old_len,) = _U32.unpack(blob[off : off + _U32.size])
    obj = json.loads(blob[off + _U32.size : off + _U32.size + old_len])
    if chunk_size is not None:
        obj["chunk_size"] = chunk_size
    header = json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()
    frames = bytearray(blob[off + _U32.size + old_len :])
    if ctlen is not None:  # frame layout: nonce(12) | ctlen(uint32) | ciphertext
        frames[_NONCE_BYTES : _NONCE_BYTES + _U32.size] = _U32.pack(ctlen)
    return blob[:off] + _U32.pack(len(header)) + header + bytes(frames)


def test_the_guarded_source_actually_fires() -> None:
    # Positive control for the instrument. A _GuardedSource that never raised would make every
    # "refused before the read" assertion below true for the wrong reason.
    src = _GuardedSource(b"abc", allow=2)
    assert src.read(2) == b"ab"
    with pytest.raises(_OversizedRead):
        src.read(3)


def test_declared_header_length_is_refused_before_the_read() -> None:
    # READ SITE 1: hdrlen -> _read_exact(src, hdrlen, "header"). The first allocation any reader of a
    # .mfbak makes, and the one furthest from anything authenticated.
    blob = bc.MAGIC + bytes([bc.FORMAT_VERSION]) + _U32.pack(0xFFFFFFFF) + b"{}"
    with pytest.raises(bc.BackupCodecError, match="exceeds"):
        bc.read_header(_GuardedSource(blob, allow=bc.MAX_HEADER_BYTES))


def test_header_length_bound_is_inclusive_at_the_cap() -> None:
    # Off-by-one control: MAX_HEADER_BYTES itself is LEGAL, so a header declaring exactly the cap must
    # get past the bound and fail for an unrelated reason. A `>=` would report "exceeds" instead.
    blob = bc.MAGIC + bytes([bc.FORMAT_VERSION]) + _U32.pack(bc.MAX_HEADER_BYTES) + b"{}"
    with pytest.raises(bc.BackupCodecError, match="short read on header"):
        bc.read_header(io.BytesIO(blob))


def test_a_declared_4_gib_chunk_size_is_refused_at_the_header() -> None:
    # THE SUBTLE ONE. chunk_size is not itself a read site -- it is the ceiling that makes the frame
    # bound mean something. A frame check written as `ctlen <= header.chunk_size + _TAG_BYTES` alone
    # is defeated by declaring chunk_size = 0xFFFFFFFF, and it passes a naive suite while doing so.
    blob = _crafted(key=os.urandom(32), chunk_size=0xFFFFFFFF)
    with pytest.raises(bc.BackupCodecError, match="chunk_size"):
        bc.read_header(io.BytesIO(blob))


def test_a_declared_4_gib_chunk_licenses_no_4_gib_frame_read() -> None:
    # The same defeat, driven end-to-end through decrypt_stream with a frame length inflated to match
    # the declared chunk. An implementation that trusts the declared chunk_size asks this source for
    # 4294967295 bytes and dies with _OversizedRead, which pytest.raises(BackupCodecError) will not
    # catch -- so this test fails loudly for exactly the defect it is written against.
    key = os.urandom(32)
    blob = _crafted(key=key, chunk_size=0xFFFFFFFF, ctlen=0xFFFFFFFF)
    with pytest.raises(bc.BackupCodecError):
        bc.decrypt_stream(_GuardedSource(blob, allow=64 * 1024), io.BytesIO(), key)


def test_zero_chunk_size_still_rejected() -> None:
    # The pre-existing lower bound must survive being folded into the new two-sided check.
    blob = _crafted(key=os.urandom(32), chunk_size=0)
    with pytest.raises(bc.BackupCodecError, match="chunk_size"):
        bc.read_header(io.BytesIO(blob))


def test_oversized_frame_length_is_refused_before_the_read() -> None:
    # READ SITE 2: ctlen -> _read_exact(src, ctlen, "frame ciphertext"). Still pre-authentication --
    # no tag is checked against these bytes until aes.decrypt, which runs after the read.
    key = os.urandom(32)
    blob = _crafted(key=key, ctlen=0xFFFFFFFF)
    with pytest.raises(bc.BackupCodecError, match="declared ciphertext length"):
        bc.decrypt_stream(_GuardedSource(blob, allow=64 * 1024), io.BytesIO(), key)


def test_frame_bound_is_exact_at_chunk_size_plus_the_tag() -> None:
    # AESGCM appends EXACTLY 16 bytes, so chunk_size + _TAG_BYTES is the true maximum and carries no
    # slack. One byte over is refused by the bound; the bound itself is admitted and fails later on
    # the short read. The two different messages are what prove the boundary sits where it claims.
    key = os.urandom(32)
    exact = 1024 + bc._TAG_BYTES
    with pytest.raises(bc.BackupCodecError, match="declared ciphertext length"):
        bc.decrypt_stream(
            _GuardedSource(_crafted(key=key, ctlen=exact + 1), allow=exact), io.BytesIO(), key
        )
    with pytest.raises(bc.BackupCodecError, match="short read on frame ciphertext"):
        bc.decrypt_stream(io.BytesIO(_crafted(key=key, ctlen=exact)), io.BytesIO(), key)


def test_frame_length_below_the_tag_is_refused() -> None:
    key = os.urandom(32)
    blob = _crafted(key=key, ctlen=bc._TAG_BYTES - 1)
    with pytest.raises(bc.BackupCodecError, match="declared ciphertext length"):
        bc.decrypt_stream(io.BytesIO(blob), io.BytesIO(), key)


def test_cumulative_plaintext_cap_stops_before_the_write() -> None:
    # READ SITE 3: the cumulative plaintext written to dst. Checked BEFORE each write, so an over-cap
    # archive never lands a byte past the ceiling -- 2048 out, not 3072 and then an error.
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"z" * 5000), enc, key, chunk_size=1024)
    out = io.BytesIO()
    with pytest.raises(bc.BackupCodecError, match="plaintext ceiling"):
        bc.decrypt_stream(io.BytesIO(enc.getvalue()), out, key, max_plaintext_bytes=2048)
    assert len(out.getvalue()) == 2048


def test_cumulative_cap_admits_an_archive_exactly_at_the_ceiling() -> None:
    # Off-by-one control for the cap, and the proof that it is opt-in: the same archive round-trips
    # both at exactly its own size and with no cap supplied at all.
    key = os.urandom(32)
    payload = b"z" * 5000
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(payload), enc, key, chunk_size=1024)
    for cap in (len(payload), None):
        out = io.BytesIO()
        bc.decrypt_stream(io.BytesIO(enc.getvalue()), out, key, max_plaintext_bytes=cap)
        assert out.getvalue() == payload


def test_writer_refuses_a_chunk_size_its_own_reader_would_reject() -> None:
    # Closure, not defence: read_header refuses a chunk_size over MAX_CHUNK_SIZE, so a writer allowed
    # to exceed it would produce an archive THIS BUILD cannot read -- discovered at restore time.
    with pytest.raises(bc.BackupCodecError, match="chunk_size"):
        bc.encrypt_stream(
            io.BytesIO(b"x"), io.BytesIO(), os.urandom(32), chunk_size=bc.MAX_CHUNK_SIZE + 1
        )


def test_writer_header_stays_far_under_the_cap() -> None:
    # The measurement MAX_HEADER_BYTES is sized against. chunk_size=MAX_CHUNK_SIZE and a store salt
    # (ADR 0196, what a cell-bound store's archive carries by default) give the widest header this
    # build can emit; reading a 64 MiB request off a 1-byte BytesIO allocates nothing.
    key = os.urandom(32)
    enc = io.BytesIO()
    bc.encrypt_stream(
        io.BytesIO(b"x"),
        enc,
        key,
        chunk_size=bc.MAX_CHUNK_SIZE,
        salt=os.urandom(STORE_SALT_BYTES),
    )
    off = len(bc.MAGIC) + 1
    (hdrlen,) = _U32.unpack(enc.getvalue()[off : off + _U32.size])
    assert hdrlen < 160  # the "well under 160 bytes" the MAX_HEADER_BYTES note cites
    assert hdrlen * 8 < bc.MAX_HEADER_BYTES  # and the cap keeps room for future additive fields


# --- BACKLOG #6686: chunk_size is validated as given, never coerced by truthiness ------------------


@pytest.mark.parametrize("bad", [0, -1, True, False, 1024.0])
def test_writer_refuses_a_chunk_size_that_is_not_a_positive_int(bad: int) -> None:
    # `chunk_size or DEFAULT_CHUNK_SIZE` turned 0 (and False) into 1 MiB, so the documented 1..MAX
    # guard never saw it; True passed it as a 1-byte chunk, and a float reached the header. Only
    # None selects the default.
    with pytest.raises(bc.BackupCodecError, match="chunk_size"):
        bc.encrypt_stream(io.BytesIO(b"x"), io.BytesIO(), os.urandom(32), chunk_size=bad)


def test_writer_none_chunk_size_selects_the_default() -> None:
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(b"x"), enc, os.urandom(32), chunk_size=None)
    assert bc.read_header(io.BytesIO(enc.getvalue())).chunk_size == bc.DEFAULT_CHUNK_SIZE


# --- BACKLOG #6687: a short read that is not EOF is not a truncation -------------------------------


class _Trickle(io.BytesIO):
    """A source that serves at most ``step`` bytes per read, as a raw pipe or socket may.

    A short read from such a source is legal and is NOT end of stream; only an empty read is. Once
    ``block_after`` bytes have been served, every read reports "no data yet" as ``None``, as a
    non-blocking raw stream does."""

    def __init__(self, data: bytes, *, step: int = 1, block_after: int | None = None) -> None:
        super().__init__(data)
        self._step = step
        self._block_after = block_after

    def read(self, size: int | None = -1, /) -> bytes:
        if self._block_after is not None and self.tell() >= self._block_after:
            return None  # type: ignore[return-value]  # what a non-blocking raw stream returns
        if size is None or size < 0:
            size = self._step
        return super().read(min(size, self._step))


class _Gush(io.BytesIO):
    """A source that breaks the read contract by returning more than it was asked for, after
    ``honest`` well-behaved short reads of one byte each."""

    def __init__(self, data: bytes, *, honest: int = 0) -> None:
        super().__init__(data)
        self._honest = honest

    def read(self, size: int | None = -1, /) -> bytes:
        if self._honest > 0:
            self._honest -= 1
            return super().read(1)
        return super().read()


def _archive(payload: bytes, key: bytes) -> tuple[bytes, int, int]:
    """A real 1024-byte-chunk archive, the offset its first frame starts at, and one frame's length."""
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(payload), enc, key, chunk_size=1024)
    blob = enc.getvalue()
    off = len(bc.MAGIC) + 1
    (hdrlen,) = _U32.unpack(blob[off : off + _U32.size])
    return blob, off + _U32.size + hdrlen, _NONCE_BYTES + _U32.size + 1024 + bc._TAG_BYTES


def test_the_trickle_source_actually_short_reads() -> None:
    # Positive control: without it, every test below could pass on a source that never short-reads.
    src = _Trickle(b"abcdef", step=2)
    assert src.read(5) == b"ab"


@pytest.mark.parametrize("step", [1, 7, 1000])
def test_decrypt_and_read_header_fill_short_reads(step: int) -> None:
    key = os.urandom(32)
    payload = os.urandom(5000)
    enc = io.BytesIO()
    bc.encrypt_stream(io.BytesIO(payload), enc, key, chunk_size=1024)
    blob = enc.getvalue()
    assert bc.read_header(_Trickle(blob, step=step)).chunk_size == 1024
    out = io.BytesIO()
    bc.decrypt_stream(_Trickle(blob, step=step), out, key)
    assert out.getvalue() == payload


@pytest.mark.parametrize(
    "where", ["magic", "header", "before frame 0", "after frame 0", "inside frame 1", "last byte"]
)
def test_a_truncated_archive_still_fails_through_short_reads(where: str) -> None:
    # Looping to fill must stop at true EOF: a cut archive is still refused, as a truncation,
    # whether the cut lands in the prefix, on a frame boundary, or inside a frame.
    key = os.urandom(32)
    blob, first, frame = _archive(os.urandom(3000), key)
    cut = {
        "magic": 3,
        "header": first - 5,
        "before frame 0": first,
        "after frame 0": first + frame,
        "inside frame 1": first + frame + 30,
        "last byte": len(blob) - 1,
    }[where]
    with pytest.raises(bc.BackupCodecError, match="truncated"):
        bc.decrypt_stream(_Trickle(blob[:cut], step=5), io.BytesIO(), key)


def test_encrypt_fills_each_frame_from_a_short_reading_source() -> None:
    # Every frame but the last carries a full chunk_size of plaintext, so the declared header
    # chunk_size describes the archive whatever the source's read granularity.
    key = os.urandom(32)
    payload = os.urandom(5000)
    enc = io.BytesIO()
    bc.encrypt_stream(_Trickle(payload, step=100), enc, key, chunk_size=1024)
    src = io.BytesIO(enc.getvalue())
    bc.read_header(src)
    lengths = []
    while nonce := src.read(_NONCE_BYTES):
        assert len(nonce) == _NONCE_BYTES
        (ctlen,) = _U32.unpack(src.read(_U32.size))
        src.read(ctlen)
        lengths.append(ctlen - bc._TAG_BYTES)
    assert lengths == [1024, 1024, 1024, 1024, 5000 - 4 * 1024]
    out = io.BytesIO()
    bc.decrypt_stream(io.BytesIO(enc.getvalue()), out, key)
    assert out.getvalue() == payload


def test_a_writer_source_with_no_data_ready_is_refused_not_read_as_eof() -> None:
    # A non-blocking raw stream returns None for "nothing yet". Reading that as EOF after two full
    # chunks would let the writer seal a silently truncated backup as a complete, authentic archive.
    for block_after in (0, 1024, 2048, 2500):
        with pytest.raises(bc.BackupCodecError, match="no data"):
            bc.encrypt_stream(
                _Trickle(b"x" * 5000, step=300, block_after=block_after),
                io.BytesIO(),
                os.urandom(32),
                chunk_size=1024,
            )


@pytest.mark.parametrize("where", ["prefix", "between frames", "inside a frame", "after final"])
def test_a_reader_source_with_no_data_ready_is_refused_not_read_as_eof(where: str) -> None:
    # On the read side, None after the final frame must not pass the trailing-byte check as EOF.
    key = os.urandom(32)
    blob, first, frame = _archive(os.urandom(3000), key)
    block_after = {
        "prefix": 4,
        "between frames": first + frame,
        "inside a frame": first + frame + 30,
        "after final": len(blob),
    }[where]
    with pytest.raises(bc.BackupCodecError, match="no data"):
        bc.decrypt_stream(_Trickle(blob, step=7, block_after=block_after), io.BytesIO(), key)


def test_a_source_that_returns_more_than_asked_is_refused() -> None:
    # An over-long read would let the writer seal a frame past its declared chunk_size, which this
    # build's own reader then rejects at restore time.
    # Both on the first read and inside the fill loop, after a short read.
    key = os.urandom(32)
    blob, _, _ = _archive(b"x" * 3000, key)
    for honest in (0, 1):
        with pytest.raises(bc.BackupCodecError, match="returned"):
            bc.encrypt_stream(_Gush(b"x" * 3000, honest=honest), io.BytesIO(), key, chunk_size=1024)
        with pytest.raises(bc.BackupCodecError, match="returned"):
            bc.decrypt_stream(_Gush(blob, honest=honest), io.BytesIO(), key)


class _OneEof(io.BytesIO):
    """A source that refuses to be read again once it has returned end of stream."""

    def __init__(self, data: bytes) -> None:
        super().__init__(data)
        self.eofs = 0

    def read(self, size: int | None = -1, /) -> bytes:
        if self.eofs:
            raise AssertionError("read again past an end of stream already returned")
        data = super().read(size)
        if not data:
            self.eofs += 1
        return data


@pytest.mark.parametrize("length", [0, 1000, 1024, 5000])
def test_encrypt_reads_the_source_past_eof_at_most_once(length: int) -> None:
    # A TTY or similar source may block, or raise, when read again after it reported EOF.
    key = os.urandom(32)
    payload = os.urandom(length)
    enc = io.BytesIO()
    bc.encrypt_stream(_OneEof(payload), enc, key, chunk_size=1024)
    out = io.BytesIO()
    bc.decrypt_stream(io.BytesIO(enc.getvalue()), out, key)
    assert out.getvalue() == payload
