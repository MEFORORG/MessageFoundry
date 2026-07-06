# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The ``.mfbak`` chunked AES-256-GCM archive codec (ADR 0049, #60 — DR backup at rest).

The DR backup writes the consistent SQLite snapshot + the loaded config bundle as a single tar
container, then **streams** that tar through this codec to an AES-256-GCM-encrypted ``.mfbak`` file —
encrypted at rest because the config bundle can carry secrets and the snapshot carries PHI bodies.

**Why a NEW codec (not ``store/crypto.py``).** The store cipher (``AesGcmCipher`` / ``make_cipher``) is
a *per-value string* cipher — ``encrypt(plaintext: str) -> str`` over one in-memory buffer behind the
``mfenc:`` marker. It cannot stream a multi-GB archive (it would base64-expand the whole file in RAM).
So ``.mfbak`` uses a **chunked AES-256-GCM streaming framing** — a magic + version header, then
fixed-size chunks each sealed with ``cryptography``'s ``AESGCM`` under the resolved store DEK. Only the
**key source** is reused (the ADR 0019 KeyProvider / ``resolve_active_key`` DEK, fingerprinted by
``active_key_id``); the cipher *mechanism* is net-new. Because this module imports ``cryptography`` /
``hashlib``, it is registered in ``scripts/security/crypto_inventory_check.py`` INVENTORY (ASVS 11.1.3).

**Format (version 1).** A little-endian stream::

    magic    = b"MFBAK\x00"                      # 6 bytes — identifies a .mfbak archive
    version  = 1 byte                             # FORMAT_VERSION (a future bump + ADR 0048's reader agree)
    hdrlen   = uint32                             # length of the JSON header that follows
    header   = JSON bytes                         # PHI-free: {format_version, alg, key_id, chunk_size}
    then, repeated until the plaintext is exhausted, one frame per chunk:
        nonce      = 12 bytes                     # per-chunk random 96-bit nonce
        ctlen      = uint32                       # length of (ciphertext ‖ GCM tag)
        ciphertext = AESGCM.encrypt(nonce, chunk, aad)   # ‖ 16-byte tag appended by AESGCM

The per-chunk **AAD binds**: ``header_sha256 ‖ frame_counter(uint64) ‖ final_flag(uint8)``. So a
reordered, dropped, truncated, or appended chunk — or a tampered header (the ``key_id`` / ``chunk_size``)
— changes the AAD and **fails the GCM tag** (fail-closed). ``final_flag = 1`` on the last frame and the
decoder requires it, so a truncation that drops the tail frame is detected as a missing terminator, not
silently accepted. The frame counter is **monotonic from 0**, re-derived on decode, so a frame replayed
out of order authenticates against the wrong counter and fails the tag.

The codec is **synchronous + streaming** (file-in → file-out, ``chunk_size`` at a time): the
:class:`~messagefoundry.pipeline.dr_backup.BackupRunner` runs it in a worker thread
(``asyncio.to_thread``), never on the event loop and never loading the whole store into one buffer.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO

# Magic + version: identify a .mfbak archive and let a future format change be additive (ADR 0048's
# reader and a future writer agree on FORMAT_VERSION).
MAGIC = b"MFBAK\x00"
FORMAT_VERSION = 1
#: The only registered AEAD for the archive (mirrors store/crypto.py's single-algorithm posture).
ALG_AES_256_GCM = "a256gcm"

_NONCE_BYTES = 12  # 96-bit random nonce, the standard size for AES-GCM
_TAG_BYTES = 16  # AES-GCM authentication tag (appended to the ciphertext by AESGCM)
#: Default plaintext chunk size (1 MiB). Fixed per-archive (recorded in the header); a large-but-bounded
#: chunk keeps the per-frame overhead (nonce + tag + length) negligible while bounding peak memory.
DEFAULT_CHUNK_SIZE = 1024 * 1024

_U32 = struct.Struct("<I")
_U64 = struct.Struct("<Q")
_DEK_BYTES = 32  # AES-256 key length


class BackupCodecError(Exception):
    """The ``.mfbak`` archive could not be processed: a bad magic/version/header, a malformed frame, or
    — the security-relevant case — a **failed AEAD tag** (corrupt/tampered/truncated archive, or the
    wrong key). Fail-closed: call sites surface this as a ``FAIL`` restore-verify result + a
    ``backup_failed`` alert, never a silent pass-through (mirrors ``store/crypto.py``'s ``CipherError``)."""


class BackupKeyMismatch(BackupCodecError):
    """The resolved store key does not match the key the archive was sealed under — detected **before**
    any decryption attempt by comparing the manifest/header ``key_id`` fingerprint to the resolved key's
    ``active_key_id`` (incl. retired keys). A clean, early ``KEY_MISMATCH`` result (ADR 0049 AC-5), not
    an opaque AEAD-tag failure. The DR site simply does not hold the matching DEK (env/external provider
    required — DPAPI is machine-bound; see the #61 cold-seed key contract)."""


def key_fingerprint(key: bytes) -> str:
    """The one-way ``key_id`` fingerprint for a 32-byte DEK — first 16 hex of SHA-256(key), IDENTICAL to
    ``store/crypto.py``'s ``_fingerprint`` so the archive's ``key_id`` matches the store cipher's
    ``active_key_id`` (a backup is provably sealed under the same key the store uses). One-way, so
    embedding it in the header/manifest reveals nothing about the key."""
    return hashlib.sha256(key).hexdigest()[:16]


@dataclass(frozen=True)
class ArchiveHeader:
    """The PHI-free, plaintext (but AAD-bound) header at the front of a ``.mfbak`` archive. Carries only
    enough to identify the archive + drive decryption; the rich manifest (row counts, fingerprints, …)
    lives INSIDE the encrypted tar. ``key_id`` is a one-way fingerprint — **never** key bytes."""

    format_version: int
    alg: str
    key_id: str
    chunk_size: int

    def to_json_bytes(self) -> bytes:
        # sort_keys so the header bytes (and thus the AAD digest) are deterministic for a given header.
        return json.dumps(
            {
                "format_version": self.format_version,
                "alg": self.alg,
                "key_id": self.key_id,
                "chunk_size": self.chunk_size,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")


def _validate_key(key: bytes) -> None:
    if len(key) != _DEK_BYTES:
        raise BackupCodecError(
            f"the store DEK must be {_DEK_BYTES} bytes for AES-256-GCM (got {len(key)})"
        )


def _aad(header_digest: bytes, frame_index: int, *, final: bool) -> bytes:
    """The per-frame AAD: ``header_sha256 ‖ frame_index(uint64) ‖ final_flag(uint8)``. Binds the header
    (so a tampered key_id/chunk_size fails the tag), the frame order (so a reorder/drop fails), and the
    terminator (so a tail-truncation fails as a missing final frame)."""
    return header_digest + _U64.pack(frame_index) + (b"\x01" if final else b"\x00")


def encrypt_stream(
    src: BinaryIO, dst: BinaryIO, key: bytes, *, chunk_size: int | None = None
) -> str:
    """Encrypt the byte stream ``src`` into the ``.mfbak`` stream ``dst`` under ``key`` (the resolved
    32-byte store DEK), returning the key's ``key_id`` fingerprint (recorded in the manifest by the
    caller). Streaming: at most ``chunk_size`` plaintext bytes are in memory at once — never the whole
    archive. Synchronous; the BackupRunner calls it off the event loop (``asyncio.to_thread``)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _validate_key(key)
    size = chunk_size or DEFAULT_CHUNK_SIZE
    if size <= 0:
        raise BackupCodecError("chunk_size must be > 0")
    kid = key_fingerprint(key)
    header = ArchiveHeader(
        format_version=FORMAT_VERSION, alg=ALG_AES_256_GCM, key_id=kid, chunk_size=size
    )
    header_bytes = header.to_json_bytes()
    header_digest = hashlib.sha256(header_bytes).digest()

    dst.write(MAGIC)
    dst.write(bytes([FORMAT_VERSION]))
    dst.write(_U32.pack(len(header_bytes)))
    dst.write(header_bytes)

    aes = AESGCM(key)
    # Read one chunk AHEAD so we know which frame is the LAST one (its AAD carries final=1). An empty
    # source still emits exactly one final empty frame, so the terminator is always present + checked.
    frame_index = 0
    current = src.read(size)
    while True:
        nxt = src.read(size)
        final = not nxt  # this is the last frame iff there is no more plaintext after it
        nonce = os.urandom(_NONCE_BYTES)
        ct = aes.encrypt(nonce, current, _aad(header_digest, frame_index, final=final))
        dst.write(nonce)
        dst.write(_U32.pack(len(ct)))
        dst.write(ct)
        if final:
            break
        current = nxt
        frame_index += 1
    return kid


def _read_exact(src: BinaryIO, n: int, what: str) -> bytes:
    """Read exactly ``n`` bytes or raise — a short read means a truncated/corrupt archive."""
    data = src.read(n)
    if len(data) != n:
        raise BackupCodecError(f"truncated .mfbak archive (short read on {what})")
    return data


def read_header(src: BinaryIO) -> ArchiveHeader:
    """Parse + validate the magic/version/header at the front of ``src``, returning the
    :class:`ArchiveHeader`. Does NOT decrypt — used by the key-fingerprint precheck (AC-5) to read the
    ``key_id`` before attempting any decryption."""
    magic = _read_exact(src, len(MAGIC), "magic")
    if magic != MAGIC:
        raise BackupCodecError("not a .mfbak archive (bad magic)")
    version = _read_exact(src, 1, "version")[0]
    if version != FORMAT_VERSION:
        # A future mfbak v2 must not be mis-read as v1 — fail closed (mirrors store/crypto's version
        # dispatch). ADR 0048's cold-seed reader checks this to refuse an archive it can't interpret.
        raise BackupCodecError(
            f"unsupported .mfbak format version {version}; this build reads version {FORMAT_VERSION}"
        )
    (hdrlen,) = _U32.unpack(_read_exact(src, _U32.size, "header length"))
    header_bytes = _read_exact(src, hdrlen, "header")
    try:
        obj = json.loads(header_bytes)
    except json.JSONDecodeError as exc:
        raise BackupCodecError("malformed .mfbak header (bad JSON)") from exc
    if not isinstance(obj, dict):
        raise BackupCodecError("malformed .mfbak header (not an object)")
    try:
        header = ArchiveHeader(
            format_version=int(obj["format_version"]),
            alg=str(obj["alg"]),
            key_id=str(obj["key_id"]),
            chunk_size=int(obj["chunk_size"]),
        )
    except (KeyError, TypeError, ValueError) as exc:
        raise BackupCodecError("malformed .mfbak header (missing/invalid field)") from exc
    if header.alg != ALG_AES_256_GCM:
        raise BackupCodecError(
            f"unsupported .mfbak archive algorithm {header.alg!r}; this build supports AES-256-GCM only"
        )
    if header.chunk_size <= 0:
        raise BackupCodecError("malformed .mfbak header (chunk_size must be > 0)")
    return header


def archive_key_id(path: str | Path) -> str:
    """Read just the ``.mfbak`` header from ``path`` and return its ``key_id`` fingerprint — for the
    pre-decryption key-availability check (ADR 0049 AC-5: compare to the resolved key BEFORE decrypting,
    so a missing/wrong key is a clean ``KEY_MISMATCH``, not an opaque AEAD-tag failure)."""
    with open(path, "rb") as fh:
        return read_header(fh).key_id


def decrypt_stream(src: BinaryIO, dst: BinaryIO, key: bytes) -> ArchiveHeader:
    """Decrypt the ``.mfbak`` stream ``src`` into the plaintext (tar) stream ``dst`` under ``key``,
    returning the parsed header. Re-derives the monotonic frame counter and requires the AAD-bound
    ``final`` terminator, so a reordered/dropped/truncated/appended chunk or a tampered header **fails
    the GCM tag** (``BackupCodecError``). Fail-closed: nothing decrypts unless every frame authenticates.

    Raises :class:`BackupKeyMismatch` when the header ``key_id`` does not match ``key`` — checked first,
    so a wrong key is a clean early error, not an opaque tag failure."""
    from cryptography.exceptions import InvalidTag
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _validate_key(key)
    header = read_header(src)
    expected_kid = key_fingerprint(key)
    if header.key_id != expected_kid:
        raise BackupKeyMismatch(
            f"the resolved store key (key_id={expected_kid}) does not match the archive's key "
            f"(key_id={header.key_id}); the DR site must hold the same DEK to restore (ADR 0049)"
        )
    header_digest = hashlib.sha256(header.to_json_bytes()).digest()
    aes = AESGCM(key)
    frame_index = 0
    saw_final = False
    while True:
        nonce = _read_exact(src, _NONCE_BYTES, "frame nonce")
        (ctlen,) = _U32.unpack(_read_exact(src, _U32.size, "frame length"))
        if ctlen < _TAG_BYTES:
            raise BackupCodecError("malformed .mfbak frame (ciphertext shorter than the GCM tag)")
        ct = _read_exact(src, ctlen, "frame ciphertext")
        # We don't know up front whether this is the final frame, so try the final-flag AAD first
        # (the common case for the last frame) and fall back to the non-final AAD. Exactly one matches
        # for an authentic frame; if neither does, the frame is corrupt/tampered/wrong-key — fail closed.
        plaintext: bytes | None = None
        this_final = False
        for final_try in (False, True):
            try:
                plaintext = aes.decrypt(
                    nonce, ct, _aad(header_digest, frame_index, final=final_try)
                )
                this_final = final_try
                break
            except InvalidTag:
                continue
        if plaintext is None:
            raise BackupCodecError(
                f"authentication failed on frame {frame_index} (corrupt/tampered/truncated archive, "
                "or the wrong key)"
            )
        dst.write(plaintext)
        if this_final:
            saw_final = True
            break
        frame_index += 1
    if not saw_final:  # defensive — the loop only exits on a final frame or a raise
        raise BackupCodecError("truncated .mfbak archive (no final frame)")
    # A trailing byte after the authenticated final frame is an append-tampering attempt — reject it.
    if src.read(1):
        raise BackupCodecError("trailing bytes after the final .mfbak frame (tampered archive)")
    return header
