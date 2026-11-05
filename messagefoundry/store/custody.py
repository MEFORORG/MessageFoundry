# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Key custody primitives: the master key, the store id, the recovery key, and where they are held.

The design is the key custody ADR draft, accepted for build by the owner on 2026-11-04 and held in
the vault at ``docs/security/security-architecture-review-2026-10-01/adr-drafts/ADR-DRAFT-key-custody.md``
(rules 1 to 4, 3b and 13; vault BACKLOG #3411, slice S3). This module holds the primitives only.
Nothing in the engine calls them yet: no command mints a store with them, and no store opens with
them.

What is here:

* **Mint.** :meth:`MasterKey.mint` (32 bytes), :meth:`StoreId.mint` (16 bytes) and
  :meth:`RecoveryKey.mint` (32 bytes), each from ``os.urandom``. A recovery key is shown to a person
  as grouped text with a checksum (:meth:`RecoveryKey.text`), and :meth:`RecoveryKey.parse` refuses
  an entry with a mistyped character.
* **The host blob** (:class:`HostBlob`): the master key, the current store id and the earlier store
  ids, in a versioned binary form. A version this code does not know is refused.
* **The recovery wrap** (:func:`wrap_master_key`, :func:`unwrap_master_key`): the master key under
  AES-256-GCM, keyed by HKDF-SHA256 over the recovery key, with the store id in the associated data.
  The wrap is not secret; it opens only with the right recovery key AND the right store id.
* **The host provider.** Windows: the host blob under user-scope DPAPI, made by the service account
  itself (:func:`protect_host_blob`). POSIX: the host blob in a file only its owner can read (rule
  3b), and a reader for a systemd credential (:func:`read_systemd_credential`).
* **The handoff blob** (:func:`write_handoff_file`): machine-scope DPAPI, in a file created
  restricted with read for the service account and for no package SID. It carries the key from the
  administrator who mints it to the service's first start, which re-wraps it in its own user scope.

The file path and the credential name are always parameters. How a host with several stores names
their files is not decided here.

**Key material never reaches a log line, an exception message or a repr.** This module logs
nothing. Every type that holds key material redacts it from its repr, and every refusal says what
was wrong without quoting the bytes or the text it read. Python cannot wipe an immutable ``bytes``,
so the master key stays in memory as long as its object lives; that is the same residual
:mod:`messagefoundry.store.crypto` documents.
"""

from __future__ import annotations

import hashlib
import hmac
import os
import stat
import struct
import sys
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, BinaryIO, Self

if TYPE_CHECKING:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

__all__ = [
    "MASTER_KEY_BYTES",
    "RECOVERY_KEY_BYTES",
    "STORE_ID_BYTES",
    "CredentialUnavailable",
    "CustodyError",
    "HostBlob",
    "MasterKey",
    "RecoveryKey",
    "StoreId",
    "protect_host_blob",
    "read_handoff_file",
    "read_host_file",
    "read_systemd_credential",
    "unprotect_host_blob",
    "unwrap_master_key",
    "wrap_master_key",
    "write_handoff_file",
    "write_host_file",
]

MASTER_KEY_BYTES = 32
STORE_ID_BYTES = 16
RECOVERY_KEY_BYTES = 32


class CustodyError(ValueError):
    """A custody value could not be read, parsed or opened.

    The message names what was wrong and never carries key material: not the bytes read, not the
    text typed, and not a fragment of either."""


class CredentialUnavailable(CustodyError):
    """No systemd credential is offered: ``$CREDENTIALS_DIRECTORY`` is unset, or holds no file of
    that name. A caller may take this as "use another provider"; every other refusal it may not."""


# --- the three minted values ----------------------------------------------------------------------


class _SecretKey:
    """A fixed-size key whose repr names its type and nothing else. Equality is constant-time, and
    a key is not hashable, so no stable value derived from it sits in a dict or a set."""

    __slots__ = ("_key",)
    _SIZE: int
    _WHAT: str

    def __init__(self, key: bytes) -> None:
        if len(key) != self._SIZE:
            raise CustodyError(f"a {self._WHAT} is {self._SIZE} bytes, not {len(key)}")
        self._key = bytes(key)

    @classmethod
    def mint(cls) -> Self:
        return cls(os.urandom(cls._SIZE))

    def material(self) -> bytes:
        """The key bytes, for the one call that needs them. Never log or print the result."""
        return self._key

    def __repr__(self) -> str:
        return f"{type(self).__name__}(<redacted>)"

    def __eq__(self, other: object) -> bool:
        if not isinstance(other, _SecretKey) or type(other) is not type(self):
            return NotImplemented
        return hmac.compare_digest(self._key, other._key)

    __hash__ = None  # type: ignore[assignment]


class MasterKey(_SecretKey):
    """The 32-byte master key. It wraps; it never seals data itself (draft rule 6)."""

    __slots__ = ()
    _SIZE = MASTER_KEY_BYTES
    _WHAT = "master key"


@dataclass(frozen=True, slots=True, repr=False)
class StoreId:
    """The 16-byte store id, which names a store outside its database. It is not a secret."""

    value: bytes

    def __post_init__(self) -> None:
        if len(self.value) != STORE_ID_BYTES:
            raise CustodyError(f"a store id is {STORE_ID_BYTES} bytes, not {len(self.value)}")

    @classmethod
    def mint(cls) -> StoreId:
        return cls(os.urandom(STORE_ID_BYTES))

    def hex(self) -> str:
        return self.value.hex()

    def __repr__(self) -> str:
        return f"StoreId({self.hex()})"


# Crockford's base32: no I, L, O or U, so a hand-copied key has no 1/I/L or 0/O confusion to make.
# On input the look-alikes are read as the digit they resemble.
_ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"
_DECODE = {ch: i for i, ch in enumerate(_ALPHABET)} | {"O": 0, "I": 1, "L": 1}
_CHECK_BYTES = 3  # a mistyped character passes with odds of about 1 in 16 million
_CHECK_LABEL = b"mefor/recovery-key-check/v1\x00"
# 32 key bytes and 3 check bytes are 280 bits, exactly 56 base32 characters.
_TEXT_CHARS = (RECOVERY_KEY_BYTES + _CHECK_BYTES) * 8 // 5
_GROUP = 4


def _check(key: bytes) -> bytes:
    return hashlib.sha256(_CHECK_LABEL + key).digest()[:_CHECK_BYTES]


class RecoveryKey(_SecretKey):
    """The 32-byte recovery key, held in escrow by a person and never on the host after the mint.

    :meth:`text` renders it for that person: 56 base32 characters in groups of four, the last few
    of them a checksum. :meth:`parse` reads it back and refuses a mistyped entry."""

    __slots__ = ()
    _SIZE = RECOVERY_KEY_BYTES
    _WHAT = "recovery key"

    def text(self) -> str:
        """The key as a person copies it down: grouped base32 with a checksum. Show it once."""
        number = int.from_bytes(self._key + _check(self._key), "big")
        chars = [_ALPHABET[(number >> (5 * i)) & 0x1F] for i in reversed(range(_TEXT_CHARS))]
        return "-".join("".join(chars[i : i + _GROUP]) for i in range(0, _TEXT_CHARS, _GROUP))

    @classmethod
    def parse(cls, entry: str) -> RecoveryKey:
        """Read a recovery key a person typed. Case, dashes and spaces do not matter.

        Raises :class:`CustodyError` for an entry of the wrong length, a character the alphabet
        does not hold, or a checksum that does not match. The message gives a count or a position,
        never a character of the entry."""
        compact = "".join(entry.split()).replace("-", "").upper()
        if len(compact) != _TEXT_CHARS:
            raise CustodyError(
                f"a recovery key has {_TEXT_CHARS} characters, not counting dashes and spaces; "
                f"this entry has {len(compact)}"
            )
        number = 0
        for position, ch in enumerate(compact, start=1):
            digit = _DECODE.get(ch)
            if digit is None:
                raise CustodyError(
                    f"character {position} of the recovery key is not one a recovery key uses"
                )
            number = (number << 5) | digit
        raw = number.to_bytes(RECOVERY_KEY_BYTES + _CHECK_BYTES, "big")
        key, check = raw[:RECOVERY_KEY_BYTES], raw[RECOVERY_KEY_BYTES:]
        if not hmac.compare_digest(check, _check(key)):
            raise CustodyError(
                "the recovery key's checksum does not match, so at least one character was "
                "mistyped; check the entry against the copy that was kept"
            )
        return cls(key)


# --- the two versioned binary forms ---------------------------------------------------------------

_FORMAT_VERSION = 1  # the one version of the host blob and of the recovery wrap this code reads


def _check_header(data: bytes, magic: bytes, what: str) -> None:
    """Refuse ``data`` unless it opens with ``magic`` and a version byte of 1. Never quotes it."""
    if len(data) <= len(magic) or data[: len(magic)] != magic:
        raise CustodyError(f"this is not a {what}")
    if data[len(magic)] != _FORMAT_VERSION:
        raise CustodyError(
            f"the {what} is version {data[len(magic)]}, and this engine reads version "
            f"{_FORMAT_VERSION} only"
        )


# --- the host blob --------------------------------------------------------------------------------

_HOST_BLOB_MAGIC = b"MFHB"
# magic, version (1 byte), master key, current store id, count of earlier ids (2 bytes, big-endian)
_HOST_BLOB_HEAD = struct.Struct(f">4sB{MASTER_KEY_BYTES}s{STORE_ID_BYTES}sH")
#: Far more restores than any store will see, and small enough that a planted count cannot make a
#: parse allocate much.
_MAX_EARLIER_STORE_IDS = 4096


@dataclass(frozen=True, slots=True, repr=False)
class HostBlob:
    """What the host provider holds: the master key, the current store id, and the earlier ids.

    An earlier id seals nothing new; it is kept to read what was written under it (draft rule 4,
    *What a restore does*). Its repr names the store ids and redacts the key."""

    master_key: MasterKey
    store_id: StoreId
    earlier_store_ids: tuple[StoreId, ...] = ()

    def __post_init__(self) -> None:
        ids = [self.store_id.value, *(s.value for s in self.earlier_store_ids)]
        if len(set(ids)) != len(ids):
            raise CustodyError(
                "a host blob names each store id once, and the current id is not also an earlier one"
            )
        if len(self.earlier_store_ids) > _MAX_EARLIER_STORE_IDS:
            raise CustodyError(
                f"a host blob holds at most {_MAX_EARLIER_STORE_IDS} earlier store ids"
            )

    def serialize(self) -> bytes:
        head = _HOST_BLOB_HEAD.pack(
            _HOST_BLOB_MAGIC,
            _FORMAT_VERSION,
            self.master_key.material(),
            self.store_id.value,
            len(self.earlier_store_ids),
        )
        return head + b"".join(s.value for s in self.earlier_store_ids)

    @classmethod
    def parse(cls, data: bytes) -> HostBlob:
        """Read a serialized host blob. Raises :class:`CustodyError` for anything but version 1 in
        exactly its own length. The message never quotes the bytes."""
        _check_header(data, _HOST_BLOB_MAGIC, "host blob")
        if len(data) < _HOST_BLOB_HEAD.size:
            raise CustodyError("the host blob is shorter than its fixed part")
        _magic, _version, key, store_id, count = _HOST_BLOB_HEAD.unpack_from(data)
        if count > _MAX_EARLIER_STORE_IDS:
            raise CustodyError(
                f"a host blob holds at most {_MAX_EARLIER_STORE_IDS} earlier store ids"
            )
        if len(data) != _HOST_BLOB_HEAD.size + count * STORE_ID_BYTES:
            raise CustodyError("the host blob's length does not match the store ids it names")
        tail = data[_HOST_BLOB_HEAD.size :]
        earlier = tuple(
            StoreId(tail[i : i + STORE_ID_BYTES]) for i in range(0, len(tail), STORE_ID_BYTES)
        )
        return cls(MasterKey(key), StoreId(store_id), earlier)

    def __repr__(self) -> str:
        earlier = ", ".join(s.hex() for s in self.earlier_store_ids)
        return (
            f"HostBlob(master_key=<redacted>, store_id={self.store_id.hex()}, earlier=[{earlier}])"
        )


# --- the recovery wrap ----------------------------------------------------------------------------

_WRAP_MAGIC = b"MFRW"
_WRAP_HEADER = _WRAP_MAGIC + bytes([_FORMAT_VERSION])
_WRAP_KEY_INFO = b"mefor/recovery-wrap/v1"
_NONCE_BYTES = 12
_TAG_BYTES = 16
_WRAP_BYTES = len(_WRAP_HEADER) + _NONCE_BYTES + MASTER_KEY_BYTES + _TAG_BYTES


def _wrap_cipher(recovery_key: RecoveryKey) -> AESGCM:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF

    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=_WRAP_KEY_INFO)
    return AESGCM(hkdf.derive(recovery_key.material()))


def wrap_master_key(master_key: MasterKey, recovery_key: RecoveryKey, store_id: StoreId) -> bytes:
    """The recovery wrap: ``master_key`` under AES-256-GCM, keyed by HKDF-SHA256 over the recovery
    key, with the wrap's header and ``store_id`` as the associated data.

    The result is not secret (draft rule 4): it is kept in the store and in each archive header."""
    nonce = os.urandom(_NONCE_BYTES)
    sealed = _wrap_cipher(recovery_key).encrypt(
        nonce, master_key.material(), _WRAP_HEADER + store_id.value
    )
    return _WRAP_HEADER + nonce + sealed


def unwrap_master_key(wrapped: bytes, recovery_key: RecoveryKey, store_id: StoreId) -> MasterKey:
    """Open a recovery wrap. Raises :class:`CustodyError` when ``wrapped`` is not a version 1 wrap,
    and when the recovery key or the store id is not the one it was made with. The two cannot be
    told apart, and the message does not try."""
    from cryptography.exceptions import InvalidTag

    _check_header(wrapped, _WRAP_MAGIC, "recovery wrap")
    if len(wrapped) != _WRAP_BYTES:
        raise CustodyError(f"a recovery wrap is {_WRAP_BYTES} bytes, not {len(wrapped)}")
    nonce = wrapped[len(_WRAP_HEADER) : len(_WRAP_HEADER) + _NONCE_BYTES]
    sealed = wrapped[len(_WRAP_HEADER) + _NONCE_BYTES :]
    try:
        key = _wrap_cipher(recovery_key).decrypt(nonce, sealed, _WRAP_HEADER + store_id.value)
    except InvalidTag:
        raise CustodyError(
            "the recovery key does not open this recovery wrap for this store id: either the key "
            "is not the one issued for this store, or the wrap belongs to another store"
        ) from None
    return MasterKey(key)


# --- the host provider: Windows user-scope DPAPI, POSIX owner-only file ---------------------------

#: The most a custody file may hold. A host blob is well under this; a larger file is not one.
_MAX_FILE_BYTES = 1 << 20


def protect_host_blob(blob: HostBlob) -> bytes:
    """The host blob under user-scope DPAPI, which only the calling account can open (draft rule 3).

    The service account must make this call itself; an administrator cannot make a user-scope wrap
    for another account, which is what the handoff blob is for. Raises
    :class:`~messagefoundry.secrets_dpapi.DpapiUnavailable` off Windows and
    :class:`~messagefoundry.secrets_dpapi.DpapiError` when the protect call fails."""
    from messagefoundry.secrets_dpapi import dpapi_protect

    return dpapi_protect(blob.serialize(), machine_scope=False)


def unprotect_host_blob(protected: bytes) -> HostBlob:
    """Open a blob :func:`protect_host_blob` made, as the account that made it."""
    from messagefoundry.secrets_dpapi import dpapi_unprotect

    return HostBlob.parse(dpapi_unprotect(protected))


def _posix_file_problem(
    mode: int, owner: int, euid: int, *, forbidden: int, owner_only: bool
) -> str | None:
    """Why a custody file of this ``mode`` and ``owner`` must not be used, or ``None``.

    ``forbidden`` is the permission bits that refuse the file. Kept free of I/O so the decision is
    testable on every platform."""
    if not stat.S_ISREG(mode):
        return "it is not a regular file"
    if stat.S_IMODE(mode) & forbidden:
        return (
            f"its mode is {stat.S_IMODE(mode):04o}, so accounts other than its owner can reach it"
        )
    if owner_only and owner != euid:
        return f"it is owned by uid {owner}, not by the account the engine runs as (uid {euid})"
    return None


def _read_capped(handle: BinaryIO, path: Path) -> bytes:
    data = handle.read(_MAX_FILE_BYTES + 1)
    if len(data) > _MAX_FILE_BYTES:
        raise CustodyError(f"{path} is larger than any custody file, so it is not one")
    return data


def _read_posix_checked(path: Path, *, forbidden: int, owner_only: bool) -> bytes:
    """Read a custody file on POSIX, checking the file it opened rather than the name.

    ``O_NOFOLLOW`` refuses a link, and the mode and owner are read from the open descriptor, so the
    file checked is the file read. ``FileNotFoundError`` propagates as it is."""
    if sys.platform == "win32":  # pragma: no cover - guard for the type checker on Windows
        raise CustodyError("the POSIX custody file check runs on POSIX only")
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
    except FileNotFoundError:
        raise
    except OSError as exc:
        raise CustodyError(
            f"{path} could not be opened: {exc.strerror or type(exc).__name__}"
        ) from None
    with os.fdopen(fd, "rb") as handle:
        status = os.fstat(handle.fileno())
        problem = _posix_file_problem(
            status.st_mode, status.st_uid, os.geteuid(), forbidden=forbidden, owner_only=owner_only
        )
        if problem is not None:
            raise CustodyError(f"{path} is refused: {problem}")
        return _read_capped(handle, path)


def _read_windows_checked(path: Path) -> bytes:
    """Read a custody file on Windows, refusing one a known broad group can read or change."""
    from messagefoundry.restricted_file import broad_access_problem

    if not path.exists():
        raise FileNotFoundError(path)
    problem = broad_access_problem(path)
    if problem is not None:
        raise CustodyError(f"{path} is refused: {problem}")
    with path.open("rb") as handle:
        return _read_capped(handle, path)


def write_host_file(path: Path, blob: HostBlob) -> None:
    """Write the host blob to a NEW file at ``path``, created restricted in the call that makes it.

    Windows: the blob under user-scope DPAPI (:func:`protect_host_blob`), in a file whose access list
    names SYSTEM, Administrators and the calling account. POSIX: the blob itself, in a file of mode
    ``0600`` owned by the calling account (draft rule 3b). Raises ``FileExistsError`` when ``path``
    exists, and what :func:`~messagefoundry.restricted_file.write_restricted_file` raises otherwise;
    after any failure but ``FileExistsError`` there is no file at ``path``."""
    from messagefoundry.restricted_file import write_restricted_file

    data = protect_host_blob(blob) if sys.platform == "win32" else blob.serialize()
    write_restricted_file(path, data)


def read_host_file(path: Path) -> HostBlob:
    """Read the host blob :func:`write_host_file` wrote, refusing a file others can reach.

    Windows: a file a known broad group can read or change is refused before it is read
    (:func:`~messagefoundry.restricted_file.broad_access_problem`), then the blob is opened with
    user-scope DPAPI. POSIX: a link, a file whose mode grants any group or other access, or one the
    engine's own account does not own is refused. Raises ``FileNotFoundError`` when there is no
    file, and :class:`CustodyError` (or a DPAPI error on Windows) for every other refusal."""
    if sys.platform == "win32":
        return unprotect_host_blob(_read_windows_checked(path))
    return HostBlob.parse(_read_posix_checked(path, forbidden=0o077, owner_only=True))


# --- the handoff blob (Windows) -------------------------------------------------------------------


def write_handoff_file(path: Path, blob: HostBlob, *, service_account: str) -> None:
    """Write the handoff blob: ``blob`` under machine-scope DPAPI, in a NEW file created restricted.

    Its access list names SYSTEM, Administrators and the calling account with full control, and
    ``service_account`` (an account name such as ``NT SERVICE\\MessageFoundry``, or a SID with or
    without a leading ``*``) with read. An account that resolves to a package SID is refused, so no
    AppContainer package is ever granted the handoff. Machine scope lets any account on the host
    unprotect the blob, so that access list is the only control, which is why the handoff lives only
    from install to the service's first start (draft rule 3).

    Windows only: raises :class:`~messagefoundry.secrets_dpapi.DpapiUnavailable` elsewhere, because
    a POSIX host needs no handoff."""
    from messagefoundry.restricted_file import write_restricted_file
    from messagefoundry.secrets_dpapi import DpapiUnavailable, dpapi_protect

    if sys.platform != "win32":
        raise DpapiUnavailable("the handoff blob is Windows-only; a POSIX host needs no handoff")
    # write_restricted_file refuses a grant that resolves to a package SID or a broad group.
    write_restricted_file(
        path, dpapi_protect(blob.serialize(), machine_scope=True), read_grants=[service_account]
    )


def read_handoff_file(path: Path) -> HostBlob:
    """Read a handoff blob, refusing a file a known broad group can read or change.

    Raises ``FileNotFoundError`` when there is none, :class:`CustodyError` for a broad file or a
    blob that is not a host blob, and the DPAPI errors of
    :func:`~messagefoundry.secrets_dpapi.dpapi_unprotect`. Windows only, as the write is."""
    from messagefoundry.secrets_dpapi import DpapiUnavailable, dpapi_unprotect

    if sys.platform != "win32":
        raise DpapiUnavailable("the handoff blob is Windows-only; a POSIX host needs no handoff")
    return HostBlob.parse(dpapi_unprotect(_read_windows_checked(path)))


# --- the systemd credential (POSIX, draft rule 3b) ------------------------------------------------

_CREDENTIALS_DIRECTORY = "CREDENTIALS_DIRECTORY"


def read_systemd_credential(name: str, *, environ: Mapping[str, str] | None = None) -> HostBlob:
    """Read the host blob a systemd unit passes as the credential ``name``
    (``LoadCredentialEncrypted=``), from ``$CREDENTIALS_DIRECTORY/<name>``.

    ``$CREDENTIALS_DIRECTORY`` is a path, not a secret, so reading it from the environment does not
    break draft rule 13. ``environ`` defaults to the process environment.

    Raises :class:`CredentialUnavailable` when the variable is unset, names no such file, or the
    host is Windows. Raises :class:`CustodyError` for a name that is not a plain file name, a
    directory that is not an absolute path, a file that is a link or grants any access to other
    accounts, or content that is not a host blob. systemd decides the file's owner and group, so
    only the other-account bits are checked."""
    if not name or name in {".", ".."} or any(c in name for c in "/\\\x00"):
        raise CustodyError("a credential name is a plain file name, with no directory part")
    directory = (os.environ if environ is None else environ).get(_CREDENTIALS_DIRECTORY)
    if not directory:
        raise CredentialUnavailable(
            f"${_CREDENTIALS_DIRECTORY} is not set, so no credential is offered"
        )
    if sys.platform == "win32":
        raise CredentialUnavailable("a systemd credential is offered on Linux only")
    if not os.path.isabs(directory):
        raise CustodyError(f"${_CREDENTIALS_DIRECTORY} must be an absolute path")
    try:
        data = _read_posix_checked(Path(directory) / name, forbidden=0o007, owner_only=False)
    except FileNotFoundError:
        raise CredentialUnavailable(
            f"${_CREDENTIALS_DIRECTORY} holds no credential named {name!r}"
        ) from None
    return HostBlob.parse(data)
