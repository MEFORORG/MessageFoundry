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

**In-use memory protection (ASVS 13.3.3 / 11.7.1 / 11.7.2).** The raw DEK and the transient plaintext
buffers this module owns are held in **mutable ``bytearray``s**, best-effort **memory-locked**
(``VirtualLock``/``mlock`` — kept resident so the key is not paged to swap) and **zeroized**
(``memset``) the instant the AEAD has copied the key/data into its own buffer. Both the lock and the
wipe are *best-effort*: they swallow every failure (no privilege, ``rlimit`` exhaustion, an exported
buffer) and never raise or log — they are hardening, not correctness.

This is an **honest, documented PARTIAL** close of 13.3.3, not a complete one. The unavoidable
**residual**: (1) CPython ``str``/``bytes`` are **immutable** with no wipe hook, so the caller's
plaintext ``str``, the base64 marker ``str`` we return, and the ``bytes`` ``cryptography`` hands back
from ``decrypt`` linger in the interpreter's heap until GC/reuse; (2) ``cryptography`` copies the key
into an **internal OpenSSL** ``EVP`` buffer we cannot reach to wipe. Full **11.7.1** in-use memory
*encryption* is **host/hypervisor territory** (SGX/SEV/TDX, encrypted RAM) — out of this process's
reach; the deployment therefore carries it as a **stated environment requirement** (trusted host,
disabled/encrypted swap, restricted local admin) accepted via a signed risk acceptance, not something
this code can enforce. See the PR for the acceptance statement.
"""

from __future__ import annotations

import base64
import ctypes
import hashlib
import logging
import os
import sys
from collections.abc import Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Protocol, runtime_checkable

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

_log = logging.getLogger(__name__)

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

# HKDF info label for the audit-chain HMAC key (#190). Versioned so a future re-derivation is an
# additive label, never a silent change to an existing deployment's derived key.
_AUDIT_MAC_INFO = b"mefor/audit-chain/v1"
_AUDIT_MAC_LEN = 32  # bytes — HMAC-SHA256 key

# AES-GCM single-key invocation safety (#190-F, defense-in-depth). With a fresh 96-bit RANDOM nonce
# per encrypt, the birthday-bound nonce-collision risk stays negligible only while a single key
# encrypts well under 2**32 messages (NIST SP 800-38D). The random-nonce scheme is standard and safe to
# ~2**32; this counter is a belt-and-suspenders tripwire so a pathological single long-lived key can
# never silently cross the bound. The counter is IN-MEMORY (resets on restart — cheap, and a restart
# re-derives the same key so the true lifetime bound is a deployment/rotation concern, not this
# process): a soft WARNING near 2**31, a fail-closed CipherError at 2**32.
_GCM_SOFT_WARN_INVOCATIONS = 2**31
_GCM_MAX_INVOCATIONS = 2**32


# --- in-use memory hygiene (ASVS 13.3.3 / 11.7.2) — all best-effort, see the module docstring -------
#
# These operate on the *mutable* bytearrays this module owns (the raw DEK, transient plaintext) so the
# secret does not linger after the AEAD has copied it. Every ctypes call is wrapped and swallows its
# failure (returns False / no-op, never raises, never logs a PHI-adjacent value) — hardening, not a
# correctness requirement. All ctypes access is confined to these three functions so the rest of the
# module (and the Linux mypy leg) stays free of platform-specific typing.


def _secure_zero(buf: bytearray) -> None:
    """Best-effort in-place wipe of a mutable secret buffer. WHY ``ctypes.memset`` over a Python loop:
    a pure-Python overwrite can be optimised away or touch a copy; ``memset`` on the buffer's real
    address is the closest CPython offers to a guaranteed scrub. Never raises — an unwritable/exported
    buffer just leaves the bytes (a best-effort hygiene wipe, not a hard guarantee)."""
    n = len(buf)
    if n == 0:
        return
    try:
        ctypes.memset((ctypes.c_char * n).from_buffer(buf), 0, n)
    except (ValueError, TypeError):
        # from_buffer refuses a read-only / already-exported buffer; fall back to an in-place overwrite
        # when the object supports item assignment, else give up (best-effort).
        try:
            for i in range(n):
                buf[i] = 0
        except (TypeError, ValueError):
            return


def _lock_memory(buf: bytearray) -> bool:
    """Best-effort pin of a secret buffer into RAM so the OS will not page it to swap/disk
    (``VirtualLock`` on Windows, ``mlock`` on POSIX). Returns whether the lock was taken; **swallows
    every failure** (returns False, never raises, never logs) — locking commonly fails without
    privilege or against the per-process locked-memory rlimit. Pair each True with a later
    :func:`_unlock_memory`."""
    n = len(buf)
    if n == 0:
        return False
    try:
        addr = ctypes.addressof((ctypes.c_char * n).from_buffer(buf))
        if sys.platform == "win32":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            return bool(kernel32.VirtualLock(ctypes.c_void_p(addr), ctypes.c_size_t(n)))
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            return bool(libc.mlock(ctypes.c_void_p(addr), ctypes.c_size_t(n)) == 0)
    except (OSError, ValueError, TypeError, AttributeError):
        return False


def _unlock_memory(buf: bytearray) -> None:
    """Best-effort release of a :func:`_lock_memory` pin (``VirtualUnlock`` / ``munlock``). Swallows
    every failure — never raises, never logs. Call only when the matching lock returned True."""
    n = len(buf)
    if n == 0:
        return
    try:
        addr = ctypes.addressof((ctypes.c_char * n).from_buffer(buf))
        if sys.platform == "win32":
            kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
            kernel32.VirtualUnlock(ctypes.c_void_p(addr), ctypes.c_size_t(n))
        else:
            libc = ctypes.CDLL(None, use_errno=True)
            libc.munlock(ctypes.c_void_p(addr), ctypes.c_size_t(n))
    except (OSError, ValueError, TypeError, AttributeError):
        return


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

    def audit_mac_key(self) -> bytes | None: ...


def _fingerprint(key: bytes | bytearray) -> str:
    """A stable, self-identifying ``key_id``: first ``_KEY_ID_LEN`` hex of SHA-256(key). One-way
    (preimage-resistant), so embedding it in the stored prefix reveals nothing about the key. Accepts a
    ``bytearray`` so it can fingerprint an owned DEK buffer *before* it is zeroized, without forcing an
    immutable copy."""
    return hashlib.sha256(key).hexdigest()[:_KEY_ID_LEN]


def _derive_audit_mac_key(dek: bytes | bytearray) -> bytes:
    """Derive the audit-chain HMAC key from the store DEK via HKDF-SHA256 (#190-B).

    The audit hash-chain becomes an HMAC keyed on THIS derived key (not the raw DEK — domain separation
    via the ``mefor/audit-chain/v1`` info label), so an attacker who can write ``audit_log`` rows but
    does not hold the DEK cannot forge a self-consistent chain. Called on the LIVE active-DEK bytes at
    cipher construction, *before* ``_install_key`` zeroizes them; the returned key is the only artifact
    retained. ``bytes(dek)`` is a transient immutable copy HKDF consumes — the documented residual (see
    the module docstring), same shape as ``_install_key``'s ``bytes(key_ba)``."""
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(algorithm=hashes.SHA256(), length=_AUDIT_MAC_LEN, salt=None, info=_AUDIT_MAC_INFO)
    return hkdf.derive(bytes(dek))


def _install_key(key_ba: bytearray) -> tuple[str, AESGCM]:
    """Fingerprint a raw DEK and build its :class:`AESGCM`, then best-effort **lock + wipe** the
    plaintext key ``bytearray`` the caller owns. Returns ``(key_id, aesgcm)`` for keyring insertion.

    The fingerprint is taken on the live bytes *before* the wipe (it is one-way, safe to keep). Once
    ``AESGCM`` has copied the key into its own (internal, immutable, OpenSSL-owned — the documented
    residual) buffer, the mutable ``key_ba`` no longer needs to hold the secret, so it is zeroized in a
    ``finally`` even if the constructor raised."""
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    key_id = _fingerprint(key_ba)  # one-way; taken on the live bytes before the wipe
    locked = _lock_memory(key_ba)
    try:
        # bytes(key_ba) is the transient immutable copy AESGCM consumes; it (and AESGCM's internal
        # OpenSSL key copy) are unreachable to wipe — the documented residual (see module docstring).
        aes = AESGCM(bytes(key_ba))
    finally:
        _secure_zero(key_ba)
        if locked:
            _unlock_memory(key_ba)
    return key_id, aes


class IdentityCipher:
    """No-op cipher: values are stored as-is (the default when no key is configured)."""

    encrypts = False

    def encrypt(self, plaintext: str) -> str:
        return plaintext

    def decrypt(self, stored: str) -> str:
        return stored

    def is_encrypted(self, stored: str) -> bool:
        return stored.startswith(MARKER_PREFIX)

    def audit_mac_key(self) -> None:
        """No DEK → no derived key → the audit chain stays the keyless SHA-256 chain (byte-identical to
        the pre-#190 default). ``None`` is the signal to keep ``audit_row_hash`` unkeyed."""
        return None


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
        active_key: bytearray,
        retired_keys: Sequence[bytearray] = (),
        *,
        write_v2: bool = False,
    ) -> None:
        # Keys arrive as mutable bytearrays this cipher owns: _install_key fingerprints + builds each
        # AESGCM, then locks + zeroizes the plaintext key buffer (best-effort). The raw key bytearray is
        # NOT retained as an attribute — only the fingerprint (one-way) and the AESGCM (holding OpenSSL's
        # internal, unreachable copy) survive.
        self._write_v2 = write_v2
        # Derive the audit-chain HMAC key from the LIVE active DEK before _install_key zeroizes it (#190).
        # Only the derived key is retained; the raw DEK is never held as an attribute.
        self._audit_mac_key = _derive_audit_mac_key(active_key)
        # In-memory GCM invocation counter (#190-F) — a fail-closed tripwire below 2**32 encrypts/key.
        self._invocations = 0
        self._warned_gcm_soft = False
        self._active_id, active_aes = _install_key(active_key)
        # Insertion order = active first, then retired — the order decrypt() tries keys in, and the exact
        # keyring order the pre-existing tests pin. (Dicts preserve insertion order.)
        self._keyring: dict[str, AESGCM] = {self._active_id: active_aes}
        for key in retired_keys:
            key_id, aes = _install_key(key)
            self._keyring.setdefault(key_id, aes)

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

    def audit_mac_key(self) -> bytes:
        """The HKDF-derived HMAC key for the tamper-evident audit chain (#190-B). Keys the
        ``audit_row_hash`` chain so it cannot be forged without the DEK. Non-secret to *hold* here (it
        never leaves the process); never logged."""
        return self._audit_mac_key

    def _count_invocation(self) -> None:
        """Advance the in-memory GCM invocation counter and enforce the single-key safety bound (#190-F):
        soft-WARN once near 2**31, then fail closed (``CipherError``) at 2**32 so a pathological
        long-lived key can never silently cross the AES-GCM birthday bound. Never logs a PHI value."""
        self._invocations += 1
        if self._invocations >= _GCM_MAX_INVOCATIONS:
            raise CipherError(
                "AES-GCM invocation ceiling reached for the active key "
                f"(>= 2**32 encrypts this process, key_id={self._active_id!r}); rotate the store "
                "encryption key (`messagefoundry rotate-key`) and restart before encrypting further"
            )
        if not self._warned_gcm_soft and self._invocations >= _GCM_SOFT_WARN_INVOCATIONS:
            self._warned_gcm_soft = True
            _log.warning(
                "AES-GCM active key %r has encrypted >= 2**31 values this process; plan a key rotation "
                "before the 2**32 fail-closed ceiling",
                self._active_id,
            )

    def encrypt(self, plaintext: str) -> str:
        self._count_invocation()  # fail-closed before 2**32 (#190-F); no-op cost otherwise
        nonce = os.urandom(_NONCE_BYTES)
        # Own the encoded plaintext in a mutable buffer so it can be wiped once the AEAD has consumed it.
        # RESIDUAL (documented): the source `plaintext` str and the returned marker str are immutable —
        # CPython gives no hook to wipe a str — and `bytes(pt)` is a transient immutable copy AESGCM
        # requires; the returned marker carries only base64 CIPHERTEXT, so it holds no plaintext PHI.
        pt = bytearray(plaintext.encode("utf-8"))
        locked = _lock_memory(pt)
        try:
            ct = self._keyring[self._active_id].encrypt(nonce, bytes(pt), None)
        finally:
            _secure_zero(pt)
            if locked:
                _unlock_memory(pt)
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
                decrypted = aes.decrypt(nonce, ct, None)
            except InvalidTag:
                continue
            # Copy the plaintext into an owned, lockable buffer so its mutable lifetime is bounded and it
            # is wiped after decoding. RESIDUAL (documented): `cryptography.decrypt` returns an IMMUTABLE
            # `bytes` we cannot scrub, and the returned `str` is immutable too — both linger until GC.
            pt = bytearray(decrypted)
            locked = _lock_memory(pt)
            try:
                return pt.decode("utf-8")
            finally:
                _secure_zero(pt)
                if locked:
                    _unlock_memory(pt)
        raise CipherError(
            f"no configured key decrypts this value (key_id={key_id!r}); if rotating, supply the "
            "prior key via MEFOR_STORE_ENCRYPTION_KEYS_RETIRED"
        )


def _decode_key(key_b64: str, name: str) -> bytearray:
    # Return a MUTABLE bytearray (not immutable bytes) so the cipher that receives it can lock + zeroize
    # the raw key material after AESGCM has copied it in (ASVS 13.3.3). base64.b64decode returns bytes;
    # bytearray(...) makes the single owned, wipeable copy the DEK travels in.
    try:
        decoded = base64.b64decode(key_b64, validate=True)
    except (ValueError, base64.binascii.Error) as exc:  # type: ignore[attr-defined]
        raise ValueError(f"{name} must be valid base64") from exc
    if len(decoded) != 32:
        raise ValueError(
            f"{name} must decode to 32 bytes (got {len(decoded)}); generate one with `messagefoundry gen-key`"
        )
    return bytearray(decoded)


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
