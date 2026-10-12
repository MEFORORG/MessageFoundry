# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Integrity seals for the store's authority rows (BACKLOG #2592).

A **seal** is an HMAC-SHA256 over a typed encoding of one row, stored in the row as::

    mfseal:v1:<key id>:<hex mac>

It is a MAC, not a ciphertext. An ``mfenc:`` value is a sealed CELL (encrypted); an ``mfseal:`` value
is a sealed ROW (authenticated). The row stays readable plaintext; the seal makes a change to it that
was not made through the store's own write helper detectable by any process that holds the key.

**Whose key.** The seal key is derived from the store key's authorization root and the store id
(:func:`~messagefoundry.store.crypto.derive_row_seal_key`). The key id in a stored seal is a one-way
digest of that derived key, so it changes when either input changes. A process with no in-process
root (a keyless store, or one whose keys live only in an external module) has no
:class:`RowSealer`, and then writes and checks no seals.

**One encoder.** :func:`seal_bytes` writes a scheme tag, the row's kind, and then each field as its
name, a one-byte type and its value, every part length-prefixed. So ``None``, the empty string and the
text ``"None"`` encode differently, and a seal of one kind never verifies as another. Floats are
encoded with :meth:`float.hex`, which is exact, so a value that round-trips through a ``REAL`` /
``DOUBLE PRECISION`` / ``FLOAT`` column seals identically on every backend.
"""

from __future__ import annotations

import hashlib
import hmac
from collections.abc import Iterable
from typing import Final

from messagefoundry.store.crypto import NO_STORE_ID, Cipher, derive_row_seal_key, row_seal_key_id

#: The marker every stored seal starts with. Versioned, so a later format is an added version and
#: never a silent change to what an existing seal means.
SEAL_PREFIX: Final = "mfseal:v1:"

#: The kind a session row is sealed under. Each sealed table has its own kind.
SESSION_KIND: Final = "session"

# Leads every encoding, so a seal can never be mistaken for a MAC over some other construction.
_SCHEME: Final = b"mfseal/v1"

# One type byte per encodable value type.
_TYPE_NONE: Final = b"N"
_TYPE_BOOL: Final = b"T"
_TYPE_INT: Final = b"I"
_TYPE_FLOAT: Final = b"F"
_TYPE_STR: Final = b"S"
_TYPE_BYTES: Final = b"B"

_MAC_HEX_LEN: Final = 64  # HMAC-SHA256, hex


class RowSealError(Exception):
    """A store write helper read a row whose seal does not verify, and refused the write.

    The helper never re-seals such a row, because the next honest write would otherwise turn a
    change made outside the helper into a sealed row. Carries the kind only, never a key or a row
    value."""

    def __init__(self, kind: str) -> None:
        super().__init__(f"the {kind} row's integrity seal does not verify; the write was refused")
        self.kind = kind


def _part(value: bytes) -> bytes:
    return len(value).to_bytes(4, "big") + value


def _encode_value(value: object) -> tuple[bytes, bytes]:
    # bool before int: bool is an int subclass, and True must not encode as the integer 1.
    if value is None:
        return _TYPE_NONE, b""
    if isinstance(value, bool):
        return _TYPE_BOOL, b"1" if value else b"0"
    if isinstance(value, int):
        return _TYPE_INT, str(value).encode("ascii")
    if isinstance(value, float):
        return _TYPE_FLOAT, value.hex().encode("ascii")
    if isinstance(value, str):
        # surrogatepass, so a value a driver decoded with surrogateescape still encodes.
        return _TYPE_STR, value.encode("utf-8", "surrogatepass")
    if isinstance(value, bytes | bytearray):
        return _TYPE_BYTES, bytes(value)
    raise TypeError(f"a row seal cannot encode a value of type {type(value).__name__}")


def seal_bytes(kind: str, fields: Iterable[tuple[str, object]]) -> bytes:
    """The canonical bytes a seal is computed over: the scheme tag, ``kind``, then each
    ``(name, value)`` in the order given. The caller supplies a fixed order (a dataclass's field
    order), so two processes encoding one row agree."""
    out = [_part(_SCHEME), _part(kind.encode("utf-8"))]
    for name, value in fields:
        type_byte, encoded = _encode_value(value)
        out.append(_part(name.encode("utf-8")) + type_byte + _part(encoded))
    return b"".join(out)


class RowSealer:
    """Seals and checks rows under one derived row-seal key. Construct with :meth:`for_cipher`."""

    __slots__ = ("_key", "_retired", "key_id")

    def __init__(self, key: bytes, *, retired_keys: Iterable[bytes] = ()) -> None:
        self._key = bytes(key)
        #: The non-secret id every seal this sealer writes names.
        self.key_id: str = row_seal_key_id(self._key)
        # The seal keys the retired store keys derive, by id. Nothing is ACCEPTED under them; they
        # only tell a row a retired key genuinely sealed from one nobody sealed.
        self._retired: dict[str, bytes] = {
            row_seal_key_id(k): bytes(k) for k in retired_keys if bytes(k) != self._key
        }

    @classmethod
    def for_cipher(cls, cipher: Cipher, *, store_id: bytes = NO_STORE_ID) -> RowSealer | None:
        """The sealer for ``cipher``'s authorization root and ``store_id``, or ``None`` when the
        cipher holds no in-process root."""
        root = cipher.authz_root()
        if root is None:
            return None
        retired = [derive_row_seal_key(r, store_id) for r in cipher.retired_authz_roots()]
        return cls(derive_row_seal_key(root, store_id), retired_keys=retired)

    def sealed_by_retired_key(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """Whether ``stored`` is a valid seal over ``fields`` under a RETIRED key's seal key: a row
        sealed before the store key changed. Such a row is still not accepted; this only lets the
        caller end it quietly rather than report it as an integrity failure."""
        parsed = self._parse(stored)
        key = None if parsed is None else self._retired.get(parsed[0])
        return (
            parsed is not None and key is not None and self._matches(key, kind, fields, parsed[1])
        )

    @staticmethod
    def _parse(stored: str | None) -> tuple[str, str] | None:
        """``(key id, mac)`` from a stored seal, or ``None`` when it is missing or malformed."""
        if not stored or not stored.startswith(SEAL_PREFIX):
            return None
        key_id, sep, mac = stored[len(SEAL_PREFIX) :].partition(":")
        if not sep or len(mac) != _MAC_HEX_LEN:
            return None
        return key_id, mac

    @staticmethod
    def _matches(key: bytes, kind: str, fields: Iterable[tuple[str, object]], mac: str) -> bool:
        expected = hmac.new(key, seal_bytes(kind, fields), hashlib.sha256).hexdigest()
        # As bytes: compare_digest refuses a str holding non-ASCII, which a stored value may.
        return hmac.compare_digest(mac.encode("utf-8", "surrogatepass"), expected.encode("ascii"))

    def seal(self, kind: str, fields: Iterable[tuple[str, object]]) -> str:
        """The stored seal for a row of ``kind`` holding ``fields``."""
        mac = hmac.new(self._key, seal_bytes(kind, fields), hashlib.sha256).hexdigest()
        return f"{SEAL_PREFIX}{self.key_id}:{mac}"

    def verify(self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None) -> bool:
        """Whether ``stored`` is this sealer's seal over ``fields``. A missing, empty or malformed
        seal fails, and so does one that names another key. The MAC compare is constant-time."""
        parsed = self._parse(stored)
        return (
            parsed is not None
            and parsed[0] == self.key_id
            and self._matches(self._key, kind, fields, parsed[1])
        )
