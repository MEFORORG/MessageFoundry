# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PHI-at-rest encryption for the message store (STORE-1; WP-5 keyring + rotation; M9 crypto-agility).

The store persists raw HL7 message bodies and a few PHI-bearing text columns (`messages.error`,
`queue.last_error`, `message_events.detail`). This module is the cipher behind the store's
encode/decode seam: with a key configured it transparently AES-256-GCM-encrypts those values before
they hit disk and decrypts them on read; with **no** key it is the identity (backward-compatible
default).

Stored format — two **decode-capable** marker versions (M9 crypto-agility, ADR 0019):

    mfenc:v1:<key_id>:<base64(nonce ‖ ciphertext ‖ tag)>          # legacy, the DEFAULT writer
    mfenc:v2:<alg>:<key_id>:<base64(nonce ‖ ciphertext ‖ tag)>    # versioned, self-describing alg

``key_id`` is a **fingerprint of the key** (first 16 hex of SHA-256(key)) — stable and
self-identifying, so the keyring needs no manual numbering and a stored value names the key that
wrote it. ``alg`` (v2 only) names the AEAD algorithm so the format is **crypto-agile**: the cipher
*dispatches* on the marker version + alg id, fails closed (``CipherError``) on an unknown version or
unknown alg, and never mis-decrypts or silently passes ciphertext through. AES-GCM is an AEAD cipher,
so a wrong key or tampered value fails the authentication tag.

**CRYPTO-1 frozen seam (ADR 0019).** The ``mfenc:v1`` writer is **literally unchanged** — existing v1
ciphertext and new v1 writes stay **byte-identical** (a frozen-fixture test pins this). M9 adds *agility
infrastructure only*: the cipher becomes version/alg-**dispatching** and v2-**capable**, but **writes v1
by default** — no at-rest format change ships. AES-256-GCM stays the **only** registered algorithm; v2
is wired + tested, not the default writer. (The marker has always carried ``v1``; before M9 it just was
not *dispatched on*.)

**Key rotation (WP-5, ASVS 11.2.2).** The cipher is a **keyring**: it encrypts with the single
*active* key and decrypts with whichever configured key matches (active + any retired decrypt-only
keys), falling back to trying every key — which transparently covers legacy ``key_id='0'`` rows and
in-progress rotations. ``messagefoundry rotate-key`` re-encrypts every ciphered value under the active
key. Keys are 32-byte secrets supplied base64 via ``MEFOR_STORE_ENCRYPTION_KEY`` (active) and
``MEFOR_STORE_ENCRYPTION_KEYS_RETIRED`` (comma-separated, decrypt-only) — never the config file.
"""

from __future__ import annotations

import base64
import hashlib
import os
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

# Version-agnostic marker prefix. Every encrypted value — v1 or v2 — starts with this; the store's
# find-all/migration LIKE patterns anchor on it (so a v2 row is recognised as already-encrypted), and
# `is_encrypted()` tests it. NEVER narrow a find-all scan to a version-specific prefix or it misses
# the other version's rows.
MARKER_PREFIX = "mfenc:"
PREFIX = "mfenc:v1:"  # the v1 writer marker — FROZEN (CRYPTO-1); v1 output stays byte-identical
_V2_PREFIX = "mfenc:v2:"  # additive, decode-capable; not written by default

# The algorithm id carried in the v2 marker for AES-256-GCM. AES-256-GCM is the ONLY registered
# algorithm (owner decision, M9: agility infrastructure only — no second cipher). The registry exists
# so a future alg is an *additive* registration, never a v1/v2 seam change.
_ALG_AES_256_GCM = "a256gcm"

_NONCE_BYTES = 12  # 96-bit random nonce, the standard size for AES-GCM
_KEY_ID_LEN = 16  # hex chars of the SHA-256 key fingerprint embedded as key_id


class CipherError(Exception):
    """A stored ciphertext could not be decrypted by **any** configured key — an unknown ``key_id``
    with no matching key, a failed AEAD tag (corrupt blob, or a key/old key that wasn't supplied), a
    malformed value, **or an unknown marker version / algorithm id** (M9 — fail-closed, never a silent
    pass-through). Call sites **contain** this (dead-letter the row) rather than letting a raw
    ``cryptography`` exception escape into a worker."""


@runtime_checkable
class Cipher(Protocol):
    """Encode/decode seam for at-rest values. ``encrypts`` is False for the identity cipher."""

    encrypts: bool

    def encrypt(self, plaintext: str) -> str: ...

    def decrypt(self, stored: str) -> str: ...

    def is_encrypted(self, stored: str) -> bool: ...


def _fingerprint(key: bytes) -> str:
    """A stable, self-identifying ``key_id``: first ``_KEY_ID_LEN`` hex of SHA-256(key). One-way
    (preimage-resistant), so embedding it in the stored prefix reveals nothing about the key."""
    return hashlib.sha256(key).hexdigest()[:_KEY_ID_LEN]


class IdentityCipher:
    """No-op cipher: values are stored as-is (the default when no key is configured)."""

    encrypts = False

    def encrypt(self, plaintext: str) -> str:
        return plaintext

    def decrypt(self, stored: str) -> str:
        return stored

    def is_encrypted(self, stored: str) -> bool:
        return stored.startswith(MARKER_PREFIX)


class AesGcmCipher:
    """AES-256-GCM **keyring** cipher with M9 crypto-agility. Encrypts with the active key; decrypts
    with whichever configured key matches the embedded ``key_id`` (and falls back to trying every key,
    which covers legacy ``key_id='0'`` rows and in-progress rotations). Construct via :func:`make_cipher`.

    **Version dispatch (M9).** :meth:`decrypt` is decode-capable of both marker versions —
    ``mfenc:v1:<key_id>:<b64>`` and ``mfenc:v2:<alg>:<key_id>:<b64>`` — and **fails closed**
    (``CipherError``) on an unknown version or an unknown/unsupported ``alg``. :meth:`encrypt` writes
    **v1 byte-identically by default** (CRYPTO-1 frozen seam); set ``write_v2=True`` to opt a *new*
    cipher instance into writing the additive v2 marker (wired + tested, not the shipping default)."""

    encrypts = True

    def __init__(
        self,
        active_key: bytes,
        retired_keys: Sequence[bytes] = (),
        *,
        write_v2: bool = False,
    ) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._active_id = _fingerprint(active_key)
        self._write_v2 = write_v2
        # Insertion order = active first, then retired — the order decrypt() tries keys in. (Dicts
        # preserve insertion order.)
        self._keyring: dict[str, AESGCM] = {self._active_id: AESGCM(active_key)}
        for key in retired_keys:
            self._keyring.setdefault(_fingerprint(key), AESGCM(key))

    @property
    def active_key_id(self) -> str:
        """The fingerprint of the key new writes are encrypted under (rotation re-encrypts to this)."""
        return self._active_id

    @property
    def active_marker_prefix(self) -> str:
        """The marker prefix THROUGH the active key's fingerprint of values this cipher writes — the
        seam the stores' rotation scans anchor on (a value already under this prefix is under the active
        key in the active format, so rotation skips it). v1: ``mfenc:v1:<key_id>:``;
        v2: ``mfenc:v2:<alg>:<key_id>:``. Generalising the rotation ``active_like`` off this property
        (instead of a baked-in ``mfenc:v1:<key_id>:``) is what makes a v2-active rotation terminate and
        find v2 rows (M9). The trailing ``:`` keeps a fingerprint prefix-collision (one fp a prefix of
        another) from matching the wrong key's rows."""
        if self._write_v2:
            return f"{_V2_PREFIX}{_ALG_AES_256_GCM}:{self._active_id}:"
        return f"{PREFIX}{self._active_id}:"

    def is_encrypted(self, stored: str) -> bool:
        return stored.startswith(MARKER_PREFIX)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        ct = self._keyring[self._active_id].encrypt(nonce, plaintext.encode("utf-8"), None)
        blob = base64.b64encode(nonce + ct).decode("ascii")
        if self._write_v2:
            # Additive v2 marker: self-describing alg id between the version and the key fingerprint.
            return f"{_V2_PREFIX}{_ALG_AES_256_GCM}:{self._active_id}:{blob}"
        # v1 writer — FROZEN, byte-identical with the pre-M9 output (CRYPTO-1).
        return f"{PREFIX}{self._active_id}:{blob}"

    def _parse(self, stored: str) -> tuple[str, str]:
        """Dispatch on the marker version → ``(key_id, base64_blob)``. Fails closed (``CipherError``) on
        an unknown version or, for v2, an unknown/unsupported ``alg``. ``base64`` and the hex ``key_id``
        contain no ``:``, so each segment splits unambiguously on ``:``."""
        if stored.startswith(PREFIX):
            # v1: "<key_id>:<base64>".
            key_id, _, blob = stored[len(PREFIX) :].partition(":")
            return key_id, blob
        if stored.startswith(_V2_PREFIX):
            # v2: "<alg>:<key_id>:<base64>".
            alg, _, rest = stored[len(_V2_PREFIX) :].partition(":")
            if alg != _ALG_AES_256_GCM:
                raise CipherError(
                    f"unknown/unsupported at-rest cipher algorithm {alg!r} in mfenc:v2 marker; this "
                    "build registers only AES-256-GCM"
                )
            key_id, _, blob = rest.partition(":")
            return key_id, blob
        # A "mfenc:" value with a version this build does not dispatch (e.g. a future mfenc:v3) must NOT
        # be passed through as plaintext or mis-decrypted — fail closed.
        version = stored[len(MARKER_PREFIX) :].partition(":")[0]
        raise CipherError(
            f"unknown at-rest marker version {version!r}; this build decodes mfenc:v1 and mfenc:v2 only"
        )

    def decrypt(self, stored: str) -> str:
        from cryptography.exceptions import InvalidTag

        if not stored.startswith(MARKER_PREFIX):
            return stored  # legacy plaintext (pre-encryption) or a purged/blank value
        key_id, blob = self._parse(stored)
        try:
            raw = base64.b64decode(blob)
        except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
            raise CipherError(f"malformed ciphertext (bad base64, key_id={key_id!r})") from exc
        nonce, ct = raw[:_NONCE_BYTES], raw[_NONCE_BYTES:]
        # Try the named key first (the fast path for current-format rows), then every other key — this
        # transparently decrypts legacy key_id='0' rows and rows written under a retired key mid-rotation.
        candidates = [self._keyring[key_id]] if key_id in self._keyring else []
        candidates += [aes for kid, aes in self._keyring.items() if kid != key_id]
        for aes in candidates:
            try:
                return aes.decrypt(nonce, ct, None).decode("utf-8")
            except InvalidTag:
                continue
        raise CipherError(
            f"no configured key decrypts this value (key_id={key_id!r}); if rotating, supply the "
            "prior key via MEFOR_STORE_ENCRYPTION_KEYS_RETIRED"
        )


def _decode_key(key_b64: str, name: str) -> bytes:
    try:
        key = base64.b64decode(key_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise ValueError(f"{name} must be valid base64") from exc
    if len(key) != 32:
        raise ValueError(
            f"{name} must decode to 32 bytes (got {len(key)}); generate one with `messagefoundry gen-key`"
        )
    return key


def make_cipher(
    key_b64: str | None, retired_b64: Sequence[str] = (), *, write_v2: bool = False
) -> Cipher:
    """Build the store cipher. ``key_b64`` is the active key (base64 32-byte); ``retired_b64`` are
    decrypt-only keys to keep available during a rotation window. Empty active key → identity cipher
    (backward-compatible default). ``write_v2`` opts the cipher into writing the additive ``mfenc:v2``
    marker — wired + tested for M9 crypto-agility, but **off by default** so v1 stays the shipping
    at-rest format (CRYPTO-1: v1 byte-identical)."""
    if not key_b64:
        return IdentityCipher()
    active = _decode_key(key_b64, "MEFOR_STORE_ENCRYPTION_KEY")
    retired = [_decode_key(k, "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED") for k in retired_b64 if k]
    return AesGcmCipher(active, retired, write_v2=write_v2)


def generate_key() -> str:
    """Mint a fresh base64-encoded 32-byte key for ``MEFOR_STORE_ENCRYPTION_KEY``."""
    return base64.b64encode(os.urandom(32)).decode("ascii")


@dataclass(frozen=True)
class CipherInfo:
    """A **non-secret** posture view of the store's at-rest cipher, for the M5 ``GET /security/posture``
    route. Carries only whether encryption is on and, when on, the active key's **fingerprint**
    (``active_key_id`` — the first 16 hex of SHA-256(key), one-way/preimage-resistant), **never** any key
    bytes. ``active_key_id`` is ``None`` for the identity cipher (no key)."""

    encrypts: bool
    active_key_id: str | None


def cipher_info(cipher: Cipher) -> CipherInfo:
    """The non-secret :class:`CipherInfo` for a live store cipher — the public accessor the API uses so
    it never has to reach a store's private ``_cipher`` directly. Exposes only the on/off bit and the
    key **fingerprint** (``active_key_id``), so no key material can leak through it."""
    # active_key_id is a property only on the real keyring cipher (AesGcmCipher); the identity cipher has
    # no key, so report None. getattr keeps this duck-typed against the Cipher protocol.
    active_key_id = getattr(cipher, "active_key_id", None) if cipher.encrypts else None
    return CipherInfo(encrypts=cipher.encrypts, active_key_id=active_key_id)
