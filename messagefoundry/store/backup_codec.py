# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

**Every attacker-declared length is bounded BEFORE the read it drives.** ``hdrlen`` and each frame's
``ctlen`` are uint32 fields in a plaintext, as-yet-unauthenticated prefix, so a reader that hands them
straight to ``read()`` allocates whatever an attacker put there — before key matching, and before any
GCM tag has authenticated anything at all. :data:`MAX_HEADER_BYTES` bounds the first;
:data:`MAX_CHUNK_SIZE` bounds the declared ``chunk_size``, which is in turn what makes the per-frame
bound in :func:`decrypt_stream` a real limit instead of a self-referential one. The cumulative
plaintext ceiling belongs to the caller (``decrypt_stream(..., max_plaintext_bytes=...)``), because the
budget it expresses lives a layer up in ``pipeline/`` and ``store/`` may not import that.

The codec is **synchronous + streaming** (file-in → file-out, ``chunk_size`` at a time): the
:class:`~messagefoundry.pipeline.dr_backup.BackupRunner` runs it in a worker thread
(``asyncio.to_thread``), never on the event loop and never loading the whole store into one buffer.
"""

from __future__ import annotations

import hashlib
import json
import os
import struct
from collections.abc import Callable
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

#: Hard ceiling on the attacker-declared ``hdrlen`` that precedes the JSON header. That length is the
#: FIRST attacker-controlled allocation any reader of a ``.mfbak`` makes -- it is consumed before the
#: key_id is known, so before key matching and before any frame's GCM tag authenticates anything. The
#: writer's header is well under 100 bytes (pinned by ``test_writer_header_stays_far_under_the_cap``),
#: so 4096 leaves room for a future additive field while keeping that allocation small.
MAX_HEADER_BYTES = 4096
#: Hard ceiling on the attacker-declared ``chunk_size`` in the header.
#:
#: **This is not a read site.** It is the ceiling that makes the per-frame bound in
#: :func:`decrypt_stream` mean anything. A frame check written as ``ctlen <= header.chunk_size +
#: _TAG_BYTES`` is defeated outright by declaring ``chunk_size = 0xFFFFFFFF``, because the header is
#: plaintext and is not authenticated until the FIRST FRAME's tag is checked -- which happens only
#: after that frame has already been read into memory. Bounding ``chunk_size`` at parse time is what
#: converts the frame bound from self-referential into a real limit.
#:
#: The writer only ever emits :data:`DEFAULT_CHUNK_SIZE` (1 MiB) and there is no operator knob, so
#: 64 MiB sits far above anything this build produces.
MAX_CHUNK_SIZE = 64 * 1024 * 1024

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
    src: BinaryIO,
    dst: BinaryIO,
    key: bytes,
    *,
    chunk_size: int | None = None,
    on_frames: Callable[[int], None] | None = None,
) -> str:
    """Encrypt the byte stream ``src`` into the ``.mfbak`` stream ``dst`` under ``key`` (the resolved
    32-byte store DEK), returning the key's ``key_id`` fingerprint (recorded in the manifest by the
    caller). Streaming: at most ``chunk_size`` plaintext bytes are in memory at once — never the whole
    archive. Synchronous; the BackupRunner calls it off the event loop (``asyncio.to_thread``).

    ``on_frames`` receives the number of AES-GCM invocations this run performed — one per frame, each
    drawing its own 96-bit nonce under the SAME DEK the store cipher uses. These MUST be charged to that
    key's persisted invocation bound (ASVS 11.3.4): the codec builds its own ``AESGCM`` from the raw key
    and never touches ``AesGcmCipher``, so counting only the store cipher would under-count the key's
    birthday budget by every backup run — a bound that is provably wrong in the low direction. The
    caller does the aggregate add after the run (this function is synchronous and holds no store)."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    _validate_key(key)
    size = chunk_size or DEFAULT_CHUNK_SIZE
    # The upper half is not defensive, it is a closure check: read_header refuses a chunk_size over
    # MAX_CHUNK_SIZE, so a writer allowed to exceed it would produce an archive THIS BUILD'S OWN
    # READER rejects -- an unreadable backup discovered at restore time, which is the worst moment.
    if not 0 < size <= MAX_CHUNK_SIZE:
        raise BackupCodecError(f"chunk_size must be in 1..{MAX_CHUNK_SIZE} bytes (got {size})")
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
    # Counted separately from frame_index and incremented only AFTER a successful aes.encrypt, so the
    # figure is the invocations actually performed rather than the frames intended.
    performed = 0
    current = src.read(size)
    try:
        while True:
            nxt = src.read(size)
            final = not nxt  # this is the last frame iff there is no more plaintext after it
            nonce = os.urandom(_NONCE_BYTES)
            ct = aes.encrypt(nonce, current, _aad(header_digest, frame_index, final=final))
            performed += 1
            dst.write(nonce)
            dst.write(_U32.pack(len(ct)))
            dst.write(ct)
            if final:
                break
            current = nxt
            frame_index += 1
    finally:
        # In a `finally`, because a run that dies part-way (a full disk, a broken destination) has still
        # SPENT every invocation it already made. Reporting only on success would charge zero for them
        # and leave the key's persisted bound trailing what the DEK actually encrypted — the same
        # under-count, in the same direction, that counting the store cipher alone would produce.
        if on_frames is not None and performed:
            on_frames(performed)
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
    # BEFORE the read, not inside _read_exact: that helper also serves the 6-byte magic and the
    # 12-byte nonce, whose lengths are ours and fixed. Only the call sites fed an ATTACKER-DECLARED
    # uint32 need a bound, and the bound each one needs is different.
    if hdrlen > MAX_HEADER_BYTES:
        raise BackupCodecError(
            f"malformed .mfbak header (declared length {hdrlen} exceeds the {MAX_HEADER_BYTES}-byte "
            "maximum)"
        )
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
    # See MAX_CHUNK_SIZE: this bound is what stops a declared 4 GiB chunk_size from licensing a 4 GiB
    # frame read further down, while the header carrying it is still unauthenticated.
    if not 0 < header.chunk_size <= MAX_CHUNK_SIZE:
        raise BackupCodecError(
            f"malformed .mfbak header (chunk_size must be in 1..{MAX_CHUNK_SIZE} bytes, got "
            f"{header.chunk_size})"
        )
    return header


def archive_key_id(path: str | Path) -> str:
    """Read just the ``.mfbak`` header from ``path`` and return its ``key_id`` fingerprint — for the
    pre-decryption key-availability check (ADR 0049 AC-5: compare to the resolved key BEFORE decrypting,
    so a missing/wrong key is a clean ``KEY_MISMATCH``, not an opaque AEAD-tag failure)."""
    with open(path, "rb") as fh:
        return read_header(fh).key_id


def decrypt_stream(
    src: BinaryIO, dst: BinaryIO, key: bytes, *, max_plaintext_bytes: int | None = None
) -> ArchiveHeader:
    """Decrypt the ``.mfbak`` stream ``src`` into the plaintext (tar) stream ``dst`` under ``key``,
    returning the parsed header. Re-derives the monotonic frame counter and requires the AAD-bound
    ``final`` terminator, so a reordered/dropped/truncated/appended chunk or a tampered header **fails
    the GCM tag** (``BackupCodecError``). Fail-closed: nothing decrypts unless every frame authenticates.

    Raises :class:`BackupKeyMismatch` when the header ``key_id`` does not match ``key`` — checked first,
    so a wrong key is a clean early error, not an opaque tag failure.

    ``max_plaintext_bytes`` caps the CUMULATIVE plaintext written to ``dst`` (``None`` = uncapped). It is
    a **caller-supplied parameter and not a constant of this module**, deliberately: the ceiling a
    restore wants is the restore's own extract budget, which lives one layer up in ``pipeline/``, and
    ``store/`` may not import ``pipeline/`` — the dependency direction is one-way. Reaching upward for
    that constant would invert it; re-declaring the same number down here would fork it. The bound is
    checked BEFORE each write, so an over-cap archive never lands a byte past the ceiling."""
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
    # AESGCM appends EXACTLY _TAG_BYTES to a chunk of at most chunk_size, so this bound is exact and
    # holds no slack. The min() is redundant WHILE read_header caps chunk_size, and it is kept anyway:
    # it makes this read's bound provable from the line itself rather than from a check twenty lines
    # away, so the frame read stays bounded even if that check is ever loosened or moved.
    max_ctlen = min(header.chunk_size, MAX_CHUNK_SIZE) + _TAG_BYTES
    frame_index = 0
    written = 0
    saw_final = False
    while True:
        nonce = _read_exact(src, _NONCE_BYTES, "frame nonce")
        (ctlen,) = _U32.unpack(_read_exact(src, _U32.size, "frame length"))
        # Both halves BEFORE the read: a declared length is rejected rather than allocated, and this
        # is still pre-authentication -- ct has no tag checked against it until aes.decrypt below.
        if not _TAG_BYTES <= ctlen <= max_ctlen:
            raise BackupCodecError(
                f"malformed .mfbak frame (declared ciphertext length {ctlen} outside "
                f"{_TAG_BYTES}..{max_ctlen} for a {header.chunk_size}-byte chunk)"
            )
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
        if max_plaintext_bytes is not None and written + len(plaintext) > max_plaintext_bytes:
            raise BackupCodecError(
                f"the .mfbak archive decrypts to more than the caller's {max_plaintext_bytes}-byte "
                f"plaintext ceiling (stopped at frame {frame_index})"
            )
        dst.write(plaintext)
        written += len(plaintext)
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
