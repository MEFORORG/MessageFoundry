# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PHI-at-rest encryption for the message store (STORE-1; WP-5 keyring + rotation).

The store persists raw HL7 message bodies and a few PHI-bearing text columns (`messages.error`,
`queue.last_error`, `message_events.detail`). This module is the cipher behind the store's
encode/decode seam: with a key configured it transparently AES-256-GCM-encrypts those values before
they hit disk and decrypts them on read; with **no** key it is the identity (backward-compatible
default).

Stored format (in the existing text columns)::

    mfenc:v1:<key_id>:<base64(nonce ‖ ciphertext ‖ tag)>

``key_id`` is a **fingerprint of the key** (first 16 hex of SHA-256(key)) — stable and
self-identifying, so the keyring needs no manual numbering and a stored value names the key that
wrote it. The ``mfenc:v1:`` prefix lets :meth:`decrypt` tell ciphertext from legacy plaintext (so
reads work during the one-time migration). AES-GCM is an AEAD cipher, so a wrong key or tampered
value fails the authentication tag.

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
from typing import Protocol, runtime_checkable

PREFIX = "mfenc:v1:"
_NONCE_BYTES = 12  # 96-bit random nonce, the standard size for AES-GCM
_KEY_ID_LEN = 16  # hex chars of the SHA-256 key fingerprint embedded as key_id


class CipherError(Exception):
    """A stored ciphertext could not be decrypted by **any** configured key — an unknown ``key_id``
    with no matching key, a failed AEAD tag (corrupt blob, or a key/old key that wasn't supplied), or
    a malformed value. Call sites **contain** this (dead-letter the row) rather than letting a raw
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
        return stored.startswith(PREFIX)


class AesGcmCipher:
    """AES-256-GCM **keyring** cipher. Encrypts with the active key; decrypts with whichever configured
    key matches the embedded ``key_id`` (and falls back to trying every key, which covers legacy
    ``key_id='0'`` rows and in-progress rotations). Construct via :func:`make_cipher`."""

    encrypts = True

    def __init__(self, active_key: bytes, retired_keys: Sequence[bytes] = ()) -> None:
        from cryptography.hazmat.primitives.ciphers.aead import AESGCM

        self._active_id = _fingerprint(active_key)
        # Insertion order = active first, then retired — the order decrypt() tries keys in. (Python
        # 3.11 dicts preserve insertion order.)
        self._keyring: dict[str, AESGCM] = {self._active_id: AESGCM(active_key)}
        for key in retired_keys:
            self._keyring.setdefault(_fingerprint(key), AESGCM(key))

    @property
    def active_key_id(self) -> str:
        """The fingerprint of the key new writes are encrypted under (rotation re-encrypts to this)."""
        return self._active_id

    def is_encrypted(self, stored: str) -> bool:
        return stored.startswith(PREFIX)

    def encrypt(self, plaintext: str) -> str:
        nonce = os.urandom(_NONCE_BYTES)
        ct = self._keyring[self._active_id].encrypt(nonce, plaintext.encode("utf-8"), None)
        blob = base64.b64encode(nonce + ct).decode("ascii")
        return f"{PREFIX}{self._active_id}:{blob}"

    def decrypt(self, stored: str) -> str:
        from cryptography.exceptions import InvalidTag

        if not stored.startswith(PREFIX):
            return stored  # legacy plaintext (pre-encryption) or a purged/blank value
        # After the prefix: "<key_id>:<base64>". base64 has no ':' so partition is unambiguous.
        key_id, _, blob = stored[len(PREFIX) :].partition(":")
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


def make_cipher(key_b64: str | None, retired_b64: Sequence[str] = ()) -> Cipher:
    """Build the store cipher. ``key_b64`` is the active key (base64 32-byte); ``retired_b64`` are
    decrypt-only keys to keep available during a rotation window. Empty active key → identity cipher
    (backward-compatible default)."""
    if not key_b64:
        return IdentityCipher()
    active = _decode_key(key_b64, "MEFOR_STORE_ENCRYPTION_KEY")
    retired = [_decode_key(k, "MEFOR_STORE_ENCRYPTION_KEYS_RETIRED") for k in retired_b64 if k]
    return AesGcmCipher(active, retired)


def generate_key() -> str:
    """Mint a fresh base64-encoded 32-byte key for ``MEFOR_STORE_ENCRYPTION_KEY``."""
    return base64.b64encode(os.urandom(32)).decode("ascii")
