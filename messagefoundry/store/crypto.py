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

**Cell-bound AAD (ASVS 11.3.3, ADR 0019).** The ``v2`` writer additionally folds a canonical
:func:`cell_aad` (``(table, column, primary-key)``) into the AES-GCM Associated Data, so a ciphertext is
cryptographically bound to the cell it lives in — a blob cut-and-pasted into another row/column/table
fails the auth tag (``CipherError``) instead of decrypting. ``v1`` never carries AAD and stays frozen;
:meth:`~AesGcmCipher.decrypt` dispatches the AAD by marker version (v1→``None``, v2→caller-supplied), so
legacy v1 rows still read (dual-read). Bound writes are selected by ``[store].aad_bind`` (which sets
``write_v2``); **ON by default** since ADR 0148 GIVEN 1, so the default at-rest format is ``mfenc:v2``.
Setting the knob false selects the frozen v1 writer — byte-identical at rest (CRYPTO-1), and a declared
loosening.

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
import json
import logging
import os
import sys
import threading
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Protocol, runtime_checkable

#: An audit-chain MAC provider (ADR 0138 follow-up). Given the canonical row bytes it returns the row's
#: MAC as a string — used INSTEAD of the in-process ``hmac.new(key, …)`` when the crypto must run inside
#: an isolated module (Vault/OpenBao Transit's ``generate_hmac``). ``None`` from ``Cipher.audit_mac_fn``
#: keeps the in-process keyed/keyless path (byte-identical to pre-ADR-0138 for the default cipher).
AuditMacFn = Callable[[bytes], str]

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
# Transit-wrapped marker (ADR 0138). The value after the prefix is Vault/OpenBao Transit's own
# `vault:v1:…` ciphertext — the plaintext DEK lives ONLY inside the isolated module, never in engine
# heap (ASVS 13.3.3). Written/decoded by `store/crypto_transit.py`'s TransitCipher, NEVER by
# AesGcmCipher: an in-process cipher cannot read a v3 value (it holds no key), so AesGcmCipher._parse
# fails closed on it — which is the correct refusal, not a bug.
_V3_PREFIX = "mfenc:v3:"

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

# HKDF info label for the secret-rotation fingerprint MAC key (ASVS 13.3.4, BACKLOG #282). A DEDICATED,
# domain-separated subkey off the DEK: the rotation watcher fingerprints each tracked secret with a KEYED
# MAC (never a salted hash — a salted hash of a low-entropy SMTP/AD password is offline-guessable), and
# this is the key it is HMAC'd under. Versioned like _AUDIT_MAC_INFO so a future re-derivation is an
# additive label, never a silent change to an existing deployment's derived key.
_ROTATION_FP_INFO = b"mefor/secret-rotation-fingerprint/v1"
_ROTATION_FP_LEN = 32  # bytes — HMAC-SHA256 key

# AES-GCM single-key invocation safety (#190-F; ASVS 11.3.4). With a fresh 96-bit RANDOM nonce per
# encrypt, the birthday-bound nonce-collision risk stays negligible only while a single key encrypts
# well under 2**32 messages (NIST SP 800-38D). Nonce GENERATION was never the gap — the BOUND was: the
# counter used to be purely in-memory and reset on every restart, so across a deployment's lifetime the
# ceiling was unreachable and "rotate before 2**32" was unenforced. It is now backed by a PERSISTED
# per-key_id cumulative total in the store (see `store/gcm_bound.py` + the `cipher_meta` table), shared
# by every process on the one unified store — engine shards and `[cluster]` HA nodes alike — so the
# bound is a property of the KEY, not of a process. A soft WARNING (and an AlertSink `gcm_invocations`
# alert) near 2**31; fail-closed `CipherError` at 2**32.
_GCM_SOFT_WARN_INVOCATIONS = 2**31
_GCM_MAX_INVOCATIONS = 2**32

# Reserve-then-spend block size for the persisted bound. A process RESERVES a block (one atomic add to
# the key's persisted total) BEFORE spending it, so an UNCLEAN exit can only ever OVER-count — never
# undercount, which is the only bias that keeps the ceiling honest. 2**16 is ~18 s of headroom at the
# product's own peak encrypt rate (~6 ciphered writes/message at ~600 ev/s), so the refill costs one DB
# round trip per ~65k encrypts instead of one per encrypt (the hot path is already a serial commit chain).
_GCM_RESERVE_BLOCK = 2**16
# Ask for a refill once the reserve falls to half a block. The request is DEMAND-driven, not poll-driven:
# crossing this watermark fires the refill hook immediately (see `set_refill_hook`), so the reserve does
# not silently fall behind a fixed poll interval once the encrypt rate exceeds block/interval.
_GCM_RESERVE_REFILL_AT = _GCM_RESERVE_BLOCK // 2

# --- cell-bound AAD (ASVS 11.3.3, ADR 0019) -----------------------------------------------------------
# The scheme tag prefixed into every cell_aad. Its own version so the AAD-construction scheme can evolve
# additively (a future mfenc-aad/v2 would be a different bound value — a deliberate, migrated change,
# never a silent one). NOT related to the mfenc marker version.
_AAD_SCHEME = b"mfenc-aad/v1"


def cell_aad(table: str, column: str, *pk: object) -> bytes:
    """Build the AES-GCM Associated Data that binds a v2 ciphertext to its storage cell (ASVS 11.3.3).

    ``table``/``column`` name the cell; ``*pk`` are the row's primary-key component(s) — the row ``id``, a
    composite PK's parts, or a content-address hash — i.e. the *stable* identity that is byte-identical at
    every legitimate read of that value (see ADR 0019 for the per-cell key choice). The v2 writer folds
    this into the GCM tag, so a ciphertext moved to a different ``(table, column, pk)`` fails the tag.

    The byte form is (a) **unambiguous**: every field is length-prefixed (4-byte big-endian) so no two
    distinct field tuples collide (``("a","bc")`` != ``("ab","c")``); (b) **versioned**: the ``_AAD_SCHEME``
    tag leads; (c) **backend-agnostic**: each component is ``str(...)``-encoded, so the same logical cell
    yields identical AAD whether the PK is a SQLite ``INTEGER`` id or a Postgres/SQL Server ``BIGINT`` —
    the re-encrypt/rotation and cross-backend restore paths must reconstruct the same value. AAD length is
    irrelevant to GCM (it is hashed into the tag), so a verbose, collision-free form is free."""
    fields = (
        _AAD_SCHEME,
        table.encode("utf-8"),
        column.encode("utf-8"),
        *(str(p).encode("utf-8") for p in pk),
    )
    return b"".join(len(f).to_bytes(4, "big") + f for f in fields)


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


def memory_locking_available(probe_bytes: int = 32) -> bool:
    """One-shot probe: can this process pin a *secret-sized* buffer into RAM right now?

    WHY a probe exists at all: :func:`_lock_memory` is best-effort and **swallows its failures by
    design** (see its docstring) — which is correct for the hot path, and is also exactly how a
    silently-degraded deployment stays invisible. A residency guarantee nobody can observe is a
    residency guarantee nobody can trust, so ``serve`` probes it once at startup and says so if it is
    not holding (ADR 0152 Phase 0). This is memory *hygiene* — it does not bear on ASVS 11.7.1.

    **CALL ONLY BEFORE ANY SECRET IS RESIDENT — this helper is not safe at an arbitrary point.**
    :func:`_lock_memory` / :func:`_unlock_memory` are PAGE-granular and are reference-counted on no
    platform: Windows ``VirtualUnlock`` unlocks the page regardless of how many ``VirtualLock`` calls
    preceded it, and POSIX ``munlock`` unlocks the whole page. The unlock this probe performs on its
    own scratch buffer therefore releases that entire page — and if a live DEK happened to share it,
    the DEK would be silently unpinned, which is the exact failure this probe exists to detect. Today
    the sole caller is ``serve``'s startup path, which runs long before the store cipher installs a
    key. A later caller (a diagnostics route, a health check, a periodic re-probe) would NOT be safe
    and must not be added.

    ``probe_bytes`` defaults to a DEK-sized buffer because that is the only lock whose failure is
    unconditional. The plaintext lock in :meth:`AesGcmCipher.encrypt` is sized by the *message*, and
    on Windows ``VirtualLock`` is bounded by the process minimum working-set quota (a few hundred KB
    by default, shared across every concurrent lock), so a large body or enough concurrency will fail
    to lock regardless of what this returns. Probing the DEK case answers "is locking available at
    all", not "will every lock succeed".

    Never raises: allocates its own scratch buffer, locks, unlocks, and reports."""
    scratch = bytearray(probe_bytes)
    locked = _lock_memory(scratch)
    if locked:
        _unlock_memory(scratch)
    return locked


class CipherError(Exception):
    """A stored ciphertext could not be decrypted by **any** configured key — an unknown ``key_id``
    with no matching key, a failed AEAD tag (corrupt blob, or a key/old key that wasn't supplied), a
    malformed value, **or an unknown marker version / algorithm id** (M9 — fail-closed, never a silent
    pass-through). Call sites **contain** this (dead-letter the row) rather than letting a raw
    ``cryptography`` exception escape into a worker."""


class StoreKeylessError(RuntimeError):
    """A store eager-read seam met an **encrypted** value (an ``mfenc:`` marker) but **no store key is
    configured** — a keyless (mis)configured open of a store that carries key-encrypted rows at rest.

    Without a key the :class:`IdentityCipher` returns the ciphertext unchanged, so a downstream
    ``json.loads`` chokes on it with a bare ``JSONDecodeError`` that names neither the table nor the
    fix (and one backend previously *silently skipped* such rows — worse). This is the operator-facing
    replacement: it names the offending table and the remedy. **Fail-closed** (a PHI hard rule): the
    store must refuse to open rather than degrade to serving partial PHI or dropping encrypted rows.
    Distinct from :class:`CipherError`, which is a *keyed* store that cannot decrypt a specific row."""


def decrypt_json_cell(cipher: Cipher, stored: str, *, aad: bytes | None, table: str) -> Any:
    """Decrypt a stored JSON value at an eager read seam (the ``state`` / ``reference`` open-time cache
    warm-ups) and ``json.loads`` it — failing **closed** on a keyless open of an encrypted store.

    The keyless-open trap (#241 F2): with no key configured the identity cipher returns an ``mfenc:``
    value unchanged, so ``json.loads`` raises a raw, un-actionable ``JSONDecodeError``. This detects
    that case (``is_encrypted`` is True) and raises :class:`StoreKeylessError` naming ``table`` + the
    remedy instead. A **keyed** cipher that cannot decrypt a row already raises the operator-facing
    :class:`CipherError` from :meth:`Cipher.decrypt` below — that propagates unchanged (still
    fail-closed); callers **must not** swallow it into a silent skip. A genuinely malformed *legacy
    plaintext* value (not encrypted) surfaces its ``JSONDecodeError`` unchanged — a real data problem,
    not a keyless open — so it is never mis-reported as a missing key."""
    plaintext = cipher.decrypt(stored, aad=aad)  # keyed: raises CipherError on an undecryptable row
    try:
        return json.loads(plaintext)
    except json.JSONDecodeError as exc:
        if cipher.is_encrypted(stored):
            raise StoreKeylessError(
                f"store table {table!r} carries encrypted rows (mfenc: markers) but no store "
                "encryption key is configured; set MEFOR_STORE_ENCRYPTION_KEY to the key that wrote "
                "them — the store cannot decrypt PHI at rest without it (fail-closed)"
            ) from exc
        raise


@runtime_checkable
class Cipher(Protocol):
    """Encode/decode seam for at-rest values. ``encrypts`` is False for the identity cipher."""

    encrypts: bool

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str: ...

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str: ...

    def is_encrypted(self, stored: str) -> bool: ...

    def audit_mac_key(self) -> bytes | None: ...

    def audit_mac_fn(self) -> AuditMacFn | None: ...


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


def rotation_fingerprint_key(cipher: Cipher) -> bytes | None:
    """Derive the secret-rotation fingerprint MAC key from the store DEK (ASVS 13.3.4, BACKLOG #282).

    HKDF-SHA256 over the cipher's in-heap audit-MAC key (itself a DEK-derived subkey), under a dedicated
    ``mefor/secret-rotation-fingerprint/v1`` info label so it is **domain-separated** from the audit-chain
    key. The rotation watcher fingerprints each tracked secret as ``HMAC(this-key, value)`` — a KEYED MAC,
    never a salted hash — so the persisted fingerprint of a low-entropy AD/SMTP secret is not offline-
    guessable and reveals nothing about the value; the key is never stored beside the fingerprint.

    Returns ``None`` when there is no in-heap keying material: the identity (keyless) cipher, OR a
    ``vault_transit`` cipher whose DEK never enters the engine heap (``audit_mac_key()`` is ``None`` — the
    audit MAC runs inside Transit). In both cases per-secret fingerprinting is unavailable in-process and
    the watcher tracks only the non-secret DEK key-id stamp."""
    base = cipher.audit_mac_key()
    if base is None:
        return None
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(
        algorithm=hashes.SHA256(), length=_ROTATION_FP_LEN, salt=None, info=_ROTATION_FP_INFO
    )
    return hkdf.derive(base)


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

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        return plaintext  # identity: no encryption, so nothing to bind (aad ignored)

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        return stored

    def is_encrypted(self, stored: str) -> bool:
        return stored.startswith(MARKER_PREFIX)

    def audit_mac_key(self) -> None:
        """No DEK → no derived key → the audit chain stays the keyless SHA-256 chain (byte-identical to
        the pre-#190 default). ``None`` is the signal to keep ``audit_row_hash`` unkeyed."""
        return None

    def audit_mac_fn(self) -> None:
        """No isolated-module MAC — the identity cipher's chain is in-process keyless SHA-256."""
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
        # GCM invocation accounting (#190-F / ASVS 11.3.4). `_invocations` counts THIS process's encrypts
        # (it is also the whole bound when no store backs the counter — CLI/offline ciphers). When a store
        # enables the persisted bound, `_bound_total` is the fleet-wide RESERVED cumulative total for this
        # key_id and `_reserve_remaining` is what is left of this process's reserved block; the enforced
        # figure is then `_bound_total - _reserve_remaining` (see :meth:`cumulative_invocations`).
        self._invocations = 0
        self._warned_gcm_soft = False
        self._bound_enabled = False
        self._bound_total = 0
        self._reserve_remaining = 0
        # The counter is mutated from MORE THAN the event-loop thread: the ADR 0134 uploaded-logs store
        # shares this very instance and does its crypto in a worker thread (`asyncio.to_thread`), so a
        # bare `-= 1` could lose an update against a concurrent store write — an under-count, the one
        # direction the bound may never drift in. A plain lock is ~50 ns against an encrypt measured in
        # microseconds, so it costs nothing measurable on the hot path.
        self._count_lock = threading.Lock()
        # Demand-driven refill signalling: fired ONCE per watermark crossing (reset when a grant lands)
        # so the store tops the reserve up when it is actually low, not merely when a poll comes round.
        self._refill_signalled = False
        self._refill_hook: Callable[[], None] | None = None
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

    def audit_mac_fn(self) -> None:
        """The in-process cipher keys the chain with :meth:`audit_mac_key` (in-heap HMAC), not an
        isolated-module MAC — so no ``audit_mac_fn`` provider. Keeping this ``None`` leaves the default
        ``aesgcm`` audit chain BYTE-IDENTICAL to pre-ADR-0138."""
        return None

    # --- persisted per-key invocation bound (ASVS 11.3.4) --------------------

    def enable_invocation_bound(self) -> None:
        """Switch this cipher from process-local counting to the PERSISTED per-key_id bound.

        Called by a store that can durably account for this key (``store/gcm_bound.py``). Idempotent.
        The cipher never writes to the DB itself: ``encrypt`` is synchronous and runs inside the store's
        write lock, so a DB round trip from there would either deadlock the store or block the event
        loop. The store reserves blocks asynchronously and hands them over via
        :meth:`grant_invocations`; the cipher only ever does arithmetic.

        Anything already encrypted before the bound was enabled (a CLI that encrypted before its store
        finished opening) is carried across as an OVERSPENT reserve, so the first reservation covers it
        and none of it is lost."""
        with self._count_lock:
            if self._bound_enabled:
                return
            self._bound_enabled = True
            self._reserve_remaining = -self._invocations

    @property
    def invocation_bound_enabled(self) -> bool:
        return self._bound_enabled

    def set_refill_hook(self, hook: Callable[[], None] | None) -> None:
        """Register the callback fired when the reserve crosses the refill watermark (``None`` clears it).

        The refill is DEMAND-driven for a reason: with a fixed poll alone, the "the reserve always leads
        actual spend" guarantee silently degrades above ``block / interval`` encrypts per second — past
        that rate the reserve goes persistently negative between passes and an unclean exit under-counts.
        The hook lets a spender say "I am running low" the moment it is, so the poll is only a floor.

        The hook is called from whichever thread performed the encrypt (the store's writes are on the
        event loop; the ADR 0134 uploaded-logs store encrypts in a worker thread), so an implementation
        MUST be thread-safe — ``loop.call_soon_threadsafe(event.set)`` is the shape the engine runner
        uses. It is invoked at most once per crossing and never inside the counter lock. If the reserve is
        already low when the hook is registered, it fires immediately rather than waiting for the next
        encrypt."""
        with self._count_lock:
            self._refill_hook = hook
            pending = self._bound_enabled and self._reserve_remaining <= _GCM_RESERVE_REFILL_AT
        if hook is not None and pending:
            self._signal_refill()

    def _signal_refill(self) -> None:
        """Fire the refill hook, swallowing anything it raises — advisory accounting must never break an
        encrypt (the in-process ceiling still applies, and the periodic poll is the backstop)."""
        hook = self._refill_hook
        if hook is None:
            return
        try:
            hook()
        except Exception:  # noqa: BLE001 — a failing hook must never fail the encrypt
            _log.debug("AES-GCM invocation refill hook raised; the periodic checkpoint still runs")

    def cumulative_invocations(self) -> int:
        """The invocation figure the 2**31 / 2**32 thresholds are enforced against.

        Unbounded (no store): this process's own count — the pre-existing behaviour, unchanged.

        Bounded: ``reserved_total - our_unspent_reserve``. Every reservation is a durable atomic add on
        the ONE unified store, so ``reserved_total`` already folds in every other process's reservations
        (engine shards, `[cluster]` HA nodes, an offline ``rotate-key``). Subtracting only OUR unspent
        remainder biases the figure HIGH — a sibling's unspent reserve is charged as if consumed — which
        is the deliberate direction: the bound may fire early, never late. When the reserve is overspent
        (a starved refill) ``_reserve_remaining`` is negative and the overspend is added in, so counting
        never stalls at the reservation."""
        with self._count_lock:
            return self._cumulative_locked()

    def _cumulative_locked(self) -> int:
        """:meth:`cumulative_invocations` with the counter lock already held (it is not reentrant)."""
        if not self._bound_enabled:
            return self._invocations
        return self._bound_total - self._reserve_remaining

    def invocation_reserve_shortfall(self) -> int:
        """How many invocations the store should reserve NOW (0 = the reserve is healthy).

        Rounded UP to whole ``_GCM_RESERVE_BLOCK`` blocks, so the persisted total always runs AHEAD of
        what has actually been spent — the unclean-exit-can-only-over-count guarantee. Returns 0 while
        more than half a block is left, so the refill costs one DB write per ~2**15 encrypts, not one per
        encrypt."""
        with self._count_lock:
            if not self._bound_enabled:
                return 0
            if self._reserve_remaining > _GCM_RESERVE_REFILL_AT:
                return 0
            need = _GCM_RESERVE_BLOCK - self._reserve_remaining
            return ((need + _GCM_RESERVE_BLOCK - 1) // _GCM_RESERVE_BLOCK) * _GCM_RESERVE_BLOCK

    def invocation_settlement(self) -> int:
        """The EXACT correction that makes the key's persisted total equal what this process actually
        spent: positive = overspend still to charge, negative = unspent reserve to refund, 0 = square.

        Used at store close (and at the end of a long offline burst) so a burst that outran its refills —
        ``rotate-key`` re-encrypting a whole store in one offline process is the extreme case — is charged
        exactly rather than lost, AND so a short-lived process that reserved a whole block to encrypt a
        handful of values does not burn 2**16 of the key's budget on paper. Forfeiting the block was the
        original behaviour and it does not survive arithmetic: ~65k opens would exhaust a key with no
        cryptographic cause, and a crash-looping service under NSSM auto-restart (~8.6k opens/day at a
        10 s restart) reaches the fail-closed 2**32 in about a week.

        The conservative bias is preserved where it is actually needed — an UNCLEAN exit, which never
        reaches a settlement and therefore still forfeits its whole reserved block. A clean settlement is
        durable and is followed by no further encrypts on this store handle (``close()`` settles before
        tearing the connection down), so writing the exact figure cannot under-count."""
        with self._count_lock:
            return -self._reserve_remaining

    def grant_invocations(self, count: int, cumulative_total: int) -> None:
        """Hand the cipher a reserved block: ``count`` invocations, with ``cumulative_total`` being the
        key's persisted total AFTER the atomic add that reserved them. A NEGATIVE ``count`` is a
        settlement refund of an unspent reserve (see :meth:`invocation_settlement`)."""
        with self._count_lock:
            self._reserve_remaining += count
            # A refund LOWERS the key's persisted total, so the authoritative post-add figure replaces
            # ours; a reservation can only raise it, and `max` there guards a stale/racy read.
            self._bound_total = (
                cumulative_total if count < 0 else max(self._bound_total, cumulative_total)
            )
            if self._reserve_remaining > _GCM_RESERVE_REFILL_AT:
                self._refill_signalled = False  # armed again for the next crossing

    def _count_invocation(self) -> None:
        """Advance the GCM invocation counter and enforce the single-key safety bound (#190-F / ASVS
        11.3.4): soft-WARN once near 2**31, then fail closed (``CipherError``) at 2**32 so a key can never
        silently cross the AES-GCM birthday bound. Never logs a PHI value.

        The ceiling is enforced against :meth:`cumulative_invocations`, which under the persisted bound is
        the KEY's lifetime figure, not this process's. That is the control the requirement asks for, and
        it is deliberately a hard stop: no write path catches ``CipherError``, so crossing 2**32 halts
        ingest. The 2**31 soft warn — surfaced as a routable ``gcm_invocations`` alert by
        :class:`~messagefoundry.pipeline.gcm_invocations.GcmInvocationRunner`, not just a log line —
        leaves HALF the birthday budget to rotate in.

        The arithmetic runs under :attr:`_count_lock` (this instance is shared with the off-loop
        uploaded-logs store); the refill hook, the WARNING and the raise all happen OUTSIDE it, so a slow
        hook or log handler never serializes concurrent encrypts."""
        with self._count_lock:
            self._invocations += 1
            want_refill = False
            if self._bound_enabled:
                self._reserve_remaining -= 1
                if self._reserve_remaining <= _GCM_RESERVE_REFILL_AT and not self._refill_signalled:
                    self._refill_signalled = True
                    want_refill = True
            total = self._cumulative_locked()
            warn = not self._warned_gcm_soft and total >= _GCM_SOFT_WARN_INVOCATIONS
            if warn:
                self._warned_gcm_soft = True
            scope = "cumulative for this key" if self._bound_enabled else "this process"
        if want_refill:
            # Demand-driven: ask for the next block the moment the reserve crosses the watermark, rather
            # than waiting out a fixed poll (which is what let a high encrypt rate outrun the reserve).
            self._signal_refill()
        if total >= _GCM_MAX_INVOCATIONS:
            raise CipherError(
                "AES-GCM invocation ceiling reached for the active key "
                f"(>= 2**32 encrypts {scope}, key_id={self._active_id!r}); rotate the store "
                "encryption key (`messagefoundry rotate-key`) and restart before encrypting further"
            )
        if warn:
            _log.warning(
                "AES-GCM active key %r has encrypted >= 2**31 values (%s); plan a key rotation "
                "before the 2**32 fail-closed ceiling",
                self._active_id,
                scope,
            )

    def encrypt(self, plaintext: str, *, aad: bytes | None = None) -> str:
        self._count_invocation()  # fail-closed before 2**32 (#190-F); no-op cost otherwise
        nonce = os.urandom(_NONCE_BYTES)
        # Cell-bound AAD (ASVS 11.3.3) is bound ONLY on the v2 writer. The v1 writer is FROZEN (CRYPTO-1):
        # it always encrypts with None AAD so its output stays byte-identical even if a caller passes
        # `aad`. So `aad` takes effect iff this cipher writes v2 (the [store].aad_bind knob → write_v2).
        gcm_aad = aad if self._write_v2 else None
        # Own the encoded plaintext in a mutable buffer so it can be wiped once the AEAD has consumed it.
        # RESIDUAL (documented): the source `plaintext` str and the returned marker str are immutable —
        # CPython gives no hook to wipe a str — and `bytes(pt)` is a transient immutable copy AESGCM
        # requires; the returned marker carries only base64 CIPHERTEXT, so it holds no plaintext PHI.
        pt = bytearray(plaintext.encode("utf-8"))
        locked = _lock_memory(pt)
        try:
            ct = self._keyring[self._active_id].encrypt(nonce, bytes(pt), gcm_aad)
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

    def decrypt(self, stored: str, *, aad: bytes | None = None) -> str:
        from cryptography.exceptions import InvalidTag

        if not stored.startswith(MARKER_PREFIX):
            return stored  # legacy plaintext (pre-encryption) or a purged/blank value
        # AAD dispatch (ASVS 11.3.3): a v1 marker was written with None AAD (frozen, legacy) so it MUST
        # decrypt with None — dual-read keeps every pre-aad_bind row readable regardless of the caller's
        # `aad`. A v2 marker was written with the cell's AAD, so it decrypts with the caller-supplied
        # `aad`; a v2 blob cut-and-pasted into another cell (a different `aad`) fails the tag below →
        # CipherError (fail-closed, never a silent mis-decrypt).
        gcm_aad = aad if stored.startswith(_V2_PREFIX) else None
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
                decrypted = aes.decrypt(nonce, ct, gcm_aad)
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
