# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Integrity seals for the store's authority rows (BACKLOG #2592).

A **seal** is an HMAC-SHA256 over a typed encoding of one row, stored in the row as::

    mfseal:v1:<key id>:<hex mac>

It is a MAC, not a ciphertext. An ``mfenc:`` value is a sealed CELL (encrypted); an ``mfseal:`` value
is a sealed ROW (authenticated). The row stays readable plaintext; the seal makes a change to it that
was not made through the store's own write helper detectable by any process that holds the key.

**Except a rollback** (BACKLOG #3510). A seal covers one record and nothing outside it counts the
record's versions, so an earlier copy that the helper sealed, put back whole with its seal (and, for
a user, its role rows), verifies. That restores whatever the copy held: a removed role, an old
password, a cleared lockout. The seal proves a record was written by the helper, not that it is the
latest one.

**Whose key.** The seal key is derived from the store key's authorization root and the store id
(:func:`~messagefoundry.store.crypto.derive_row_seal_key`). The key id in a stored seal is a one-way
digest of that derived key, so it changes when either input changes. A keyless store has no sealer,
and then writes and checks no seals.

**Under ``vault_transit``** (ADR-draft decision D14) no key is in the process. The seal is Transit's
own HMAC instead, through :class:`TransitRowSealer`, so the seal key never enters the heap. That
class says what the stored form holds, what the cache keeps and what an outage does.

**Every store and service call site awaits** :meth:`RowSealer.seal_async`,
:meth:`RowSealer.verify_async` or :meth:`RowSealer.verify_held_async`. Under Transit each is a
network call, and CLAUDE.md section 6 forbids blocking the event loop on one, so the Transit sealer
runs it in a worker thread. The local sealer answers in the calling coroutine with no I/O. Its
synchronous methods remain for it alone.

**One encoder.** :func:`seal_bytes` writes a scheme tag, the row's kind, and then each field as its
name, a one-byte type and its value, every part length-prefixed. So ``None``, the empty string and the
text ``"None"`` encode differently, and a seal of one kind never verifies as another. Floats are
encoded with :meth:`float.hex`, which is exact, so a value that round-trips through a ``REAL`` /
``DOUBLE PRECISION`` / ``FLOAT`` column seals identically on every backend.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import logging
import sys
import time
from collections.abc import Iterable
from typing import TYPE_CHECKING, Final

from messagefoundry.store.crypto import (
    NO_STORE_ID,
    Cipher,
    CipherError,
    derive_row_seal_key,
    row_seal_key_id,
)

if TYPE_CHECKING:
    from messagefoundry.store.crypto_transit import TransitCipher

log = logging.getLogger(__name__)

#: The marker every stored seal starts with. Versioned, so a later format is an added version and
#: never a silent change to what an existing seal means.
SEAL_PREFIX: Final = "mfseal:v1:"

#: The kind a session row is sealed under. Each sealed table has its own kind.
SESSION_KIND: Final = "session"

#: The kind a user's authorization record is sealed under: the ``users`` row, the account's
#: ``user_roles`` rows and a digest of its passkeys, under one seal.
USER_KIND: Final = "user"

#: The kind a ``roles`` row is sealed under: one seal per role definition, over the whole row.
ROLE_KIND: Final = "role"

#: The kind a directory map is sealed under: one seal per map, over its sorted pairs, stored in
#: ``authority_set_seal``. The map's name is inside the sealed bytes, so one map's seal never
#: verifies for another.
ADSET_KIND: Final = "adset"

#: The kind a ``pending_approvals`` row is sealed under: one seal per dual-control request, over
#: the whole row, so its captured params and its requester id are bound to the request.
APPROVAL_KIND: Final = "approval"

#: The label a passkey digest is computed under. Not a seal kind: the digest is a plain SHA-256 that
#: the user seal covers, so it needs no key of its own.
PASSKEYS_LABEL: Final = "passkeys"

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


#: How often one failing row is reported again while it keeps being presented, in seconds.
SEAL_FAILURE_REPORT_INTERVAL_SECONDS: Final = 300.0
#: How many failing rows a :class:`SealFailureThrottle` remembers; the oldest is forgotten first.
SEAL_FAILURE_TRACK_MAX: Final = 1024


class SealFailureThrottle:
    """Decides when a row that failed its seal is reported again (BACKLOG #2592): at most once per
    :data:`SEAL_FAILURE_REPORT_INTERVAL_SECONDS` per key, remembering at most
    :data:`SEAL_FAILURE_TRACK_MAX` keys. One per reporter: the auth service and the approval gate
    each hold one, so both follow one policy."""

    __slots__ = ("_last",)

    def __init__(self) -> None:
        self._last: dict[str, float] = {}

    def due(self, key: str) -> bool:
        """Whether ``key`` should be reported now; if so, records that it was."""
        now = time.monotonic()
        last = self._last.get(key)
        if last is not None and now - last < SEAL_FAILURE_REPORT_INTERVAL_SECONDS:
            return False
        self._last.pop(key, None)
        if len(self._last) >= SEAL_FAILURE_TRACK_MAX:
            self._last.pop(next(iter(self._last)))
        self._last[key] = now
        return True


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
        # The seal keys the retired store keys derive, by id. A session is never accepted under one;
        # they tell a session a retired key genuinely sealed from one nobody sealed. A user record
        # is, through verify_held, until rotate-key re-seals it under the active key.
        self._retired: dict[str, bytes] = {
            row_seal_key_id(k): bytes(k) for k in retired_keys if bytes(k) != self._key
        }

    @classmethod
    def for_cipher(cls, cipher: Cipher, *, store_id: bytes = NO_STORE_ID) -> Sealer | None:
        """The sealer for ``cipher``'s authorization root and ``store_id``. A ``vault_transit``
        cipher holds no root and gets a :class:`TransitRowSealer` (ADR-draft decision D14).
        ``None`` for any other cipher with no in-process root: a keyless store."""
        root = cipher.authz_root()
        if root is None:
            # A TransitCipher exists only once its module is loaded, so a keyless store never
            # imports the Vault module just to learn it is not one.
            transit = sys.modules.get("messagefoundry.store.crypto_transit")
            if transit is not None and isinstance(cipher, transit.TransitCipher):
                return TransitRowSealer(cipher, store_id=store_id)
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

    def verify_held(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """Whether ``stored`` is a seal over ``fields`` under the key it names, when that key is the
        active one or a retired one this process holds.

        For the records that outlive a key change: a user, which ``rotate-key`` re-seals under the
        active key and which must keep resolving until it has. A session never uses this; its seal
        verifies under the active key alone (:meth:`verify`)."""
        parsed = self._parse(stored)
        if parsed is None:
            return False
        key = self._key if parsed[0] == self.key_id else self._retired.get(parsed[0])
        return key is not None and self._matches(key, kind, fields, parsed[1])

    def is_active(self, stored: str | None) -> bool:
        """Whether ``stored`` names the active key. Says nothing about whether it verifies."""
        parsed = self._parse(stored)
        return parsed is not None and parsed[0] == self.key_id

    # The awaited forms every store and service call site uses, so one call site serves this sealer
    # and TransitRowSealer. No I/O here: each answers in the calling coroutine.

    async def seal_async(self, kind: str, fields: Iterable[tuple[str, object]]) -> str:
        """:meth:`seal`, awaitable."""
        return self.seal(kind, fields)

    async def verify_async(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """:meth:`verify`, awaitable."""
        return self.verify(kind, fields, stored)

    async def verify_held_async(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """:meth:`verify_held`, awaitable."""
        return self.verify_held(kind, fields, stored)


class TransitSealUnavailableError(Exception):
    """A Transit call for a row seal did not complete (ADR-draft decision D14).

    Not an integrity failure: the row may be sound and Vault may be restarting. So no caller reads
    it as a failed seal, and no ``integrity.authority_seal_failed`` audit row is written. It
    propagates instead, which denies the request or rolls the write back, and the sealer logs an
    ERROR line. Deliberately NOT a :class:`CipherError`: the handlers that read a ``CipherError``
    as "this cell did not open" must not file a Vault outage as a factor or cell problem. Its text
    is Vault's failure text, never row data."""


#: The label a Transit seal input starts with. It stands where the HKDF label stands under the
#: local sealer, so a seal input never reads as another MAC's input under the same Transit key.
_TRANSIT_SEAL_LABEL: Final = b"mefor/row-seal/transit/v1"
#: The label a Transit sealer's key id is a digest under.
_TRANSIT_KEY_ID_LABEL: Final = b"mefor/row-seal-transit-key-id/v1\x00"
_TRANSIT_KEY_ID_LEN: Final = 16
#: The longest Transit MAC string a check sends to Vault. A SHA-256 HMAC is ``vault:v<N>:`` and 44
#: base64 characters, so this leaves room for any version number and refuses a planted giant.
_TRANSIT_MAC_MAX_LEN: Final = 128
_TRANSIT_MAC_PREFIX: Final = "vault:v"

#: How long one successful Transit check is trusted, in seconds. D14 caps an entry at the session
#: idle timeout, and ``[auth].session_idle_timeout_minutes`` counts whole minutes, so one minute is
#: within every setting above zero. The row is still read on every request, so a blanked seal, a
#: changed row or a bumped epoch takes effect at once whatever the cache holds.
TRANSIT_SEAL_CACHE_TTL_SECONDS: Final = 60.0
#: How many successful checks the cache holds; the oldest is dropped first.
TRANSIT_SEAL_CACHE_MAX: Final = 4096


def transit_seal_key_id(key_name: str) -> str:
    """The key id a Transit seal names (ADR-draft decision D14; settled under BACKLOG #2592).

    A one-way digest of the Transit key's NAME under its own label: fixed-width hex like every
    other key id, so it holds no ``:`` and never matches a local sealer's id. It names the key and
    not its version. Transit's own string, which the seal stores, carries the version, and the MAC
    input carries the store id, so both things a local key id tells apart are still present. Every
    store passes ``NO_STORE_ID`` until the store-id pin lands (vault BACKLOG #3411), so today that
    part tells no two stores apart, exactly as under the local sealer."""
    return hashlib.sha256(_TRANSIT_KEY_ID_LABEL + key_name.encode("utf-8")).hexdigest()[
        :_TRANSIT_KEY_ID_LEN
    ]


def _transit_version(mac: str) -> int | None:
    """The key version a Transit MAC string names (``vault:v<N>:<base64>``), or ``None`` when it
    is not that shape. Parsed by hand, so no regex sees stored text. ``N`` follows the audit
    chain's ``_TRANSIT_MAC_VERSION`` rule in ``store.py``: 1 to 10 digits, no leading zero."""
    # ASCII only: a planted non-ASCII value fails here, never later as an encode error.
    if (
        len(mac) > _TRANSIT_MAC_MAX_LEN
        or not mac.isascii()
        or not mac.startswith(_TRANSIT_MAC_PREFIX)
    ):
        return None
    version, sep, body = mac[len(_TRANSIT_MAC_PREFIX) :].partition(":")
    if not sep or not body or not version.isdigit():
        return None
    if len(version) > 10 or version.startswith("0"):
        return None
    return int(version)


class TransitRowSealer:
    """Seals and checks rows with Vault/OpenBao Transit's own HMAC (ADR-draft decision D14).

    **Stored form.** ``mfseal:v1:<key id>:<Transit's string>``: the local prefix, with
    :func:`transit_seal_key_id` as the key id and Transit's ``vault:v<N>:...`` string, which names
    the key version, as the MAC.

    **Sealing** is one Transit ``hmac`` call per write, under the latest key version. **Checking**
    is Transit's ``verify`` call with the stored string, which pins the version that string names.
    It never regenerates and compares, because a MAC regenerated under a newer version differs from
    every stored one. The MAC input is :data:`_TRANSIT_SEAL_LABEL`, the store id, then
    :func:`seal_bytes`, each part length-prefixed.

    **The cache holds successful checks only**, keyed by a digest of the length-prefixed input and
    the stored Transit string, which carries the version. An entry lives
    :data:`TRANSIT_SEAL_CACHE_TTL_SECONDS`, which also bounds how long a check outlives a version
    Transit later retires. The cache is emptied when this process first sees a newer key version.
    It holds a result and nothing else; the caller reads the row afresh every time.

    **An outage is not a failed seal.** A call that does not complete raises
    :class:`TransitSealUnavailableError` and logs an ERROR line, at most once per
    :data:`SEAL_FAILURE_REPORT_INTERVAL_SECONDS`. No alert sink is notified. Transit refusing the
    check while its key still answers means "does not verify"
    (:meth:`~messagefoundry.store.crypto_transit.TransitCipher.verify_seal_hmac` says how the two
    are told apart).

    **The seam (CLAUDE.md section 6).** Each Transit call runs in a worker thread
    (:func:`asyncio.to_thread`), so a seal or a check never blocks the event loop. So only the
    awaited methods exist here, and the cache is touched on the calling coroutine's thread alone.

    **No retired keys.** Transit keeps its own versions, so :meth:`sealed_by_retired_key` is always
    False: a session under a version Transit no longer holds is refused as a failed seal. And
    :meth:`is_active` asks only whether a seal names this Transit key, at any version."""

    __slots__ = ("_backend", "_cache", "_latest_version", "_prefix", "_throttle", "key_id")

    def __init__(self, backend: TransitCipher, *, store_id: bytes = NO_STORE_ID) -> None:
        self._backend = backend
        #: The non-secret id every seal this sealer writes names.
        self.key_id: str = transit_seal_key_id(backend.seal_key_name)
        self._prefix = _part(_TRANSIT_SEAL_LABEL) + _part(bytes(store_id))
        self._cache: dict[bytes, float] = {}
        self._latest_version = 0
        self._throttle = SealFailureThrottle()

    def _saw_version(self, version: int) -> None:
        # A newer key version means Transit rotated; no check made before it stays trusted.
        if version > self._latest_version:
            self._cache.clear()
            self._latest_version = version

    def _unavailable(self, exc: Exception) -> TransitSealUnavailableError:
        if self._throttle.due("transit"):
            log.error(
                "a row seal could not be made or checked because Vault transit did not answer; the"
                " request was refused and no seal failure was recorded (BACKLOG #2592): %s",
                exc,
            )
        return TransitSealUnavailableError(f"Transit row seal unavailable: {exc}")

    def _parse(self, stored: str | None) -> tuple[str, int] | None:
        """``(Transit string, version)`` from a stored seal naming this key, or ``None``."""
        if not stored or not stored.startswith(SEAL_PREFIX):
            return None
        key_id, sep, mac = stored[len(SEAL_PREFIX) :].partition(":")
        if not sep or key_id != self.key_id:
            return None
        version = _transit_version(mac)
        return None if version is None else (mac, version)

    async def seal_async(self, kind: str, fields: Iterable[tuple[str, object]]) -> str:
        """The stored seal for a row of ``kind`` holding ``fields``: one Transit ``hmac`` call."""
        data = self._prefix + seal_bytes(kind, fields)
        try:
            mac = await asyncio.to_thread(self._backend.seal_hmac, data)
        except CipherError as exc:
            raise self._unavailable(exc) from exc
        version = _transit_version(mac)
        if version is None:
            raise self._unavailable(CipherError("Transit returned a MAC of an unexpected shape"))
        self._saw_version(version)
        return f"{SEAL_PREFIX}{self.key_id}:{mac}"

    async def verify_async(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """Whether ``stored`` is a Transit seal over ``fields`` under this key, at the version it
        names. A missing, malformed or foreign seal fails with no Transit call."""
        parsed = self._parse(stored)
        if parsed is None:
            return False
        mac, version = parsed
        data = self._prefix + seal_bytes(kind, fields)
        entry = hashlib.sha256(_part(data) + _part(mac.encode("ascii"))).digest()
        expires = self._cache.pop(entry, None)
        if expires is not None and time.monotonic() < expires:
            self._cache[entry] = expires
            return True
        try:
            valid = await asyncio.to_thread(self._backend.verify_seal_hmac, data, mac)
        except CipherError as exc:
            raise self._unavailable(exc) from exc
        if not valid:
            return False
        self._saw_version(version)
        if len(self._cache) >= TRANSIT_SEAL_CACHE_MAX:
            self._cache.pop(next(iter(self._cache)))
        self._cache[entry] = time.monotonic() + TRANSIT_SEAL_CACHE_TTL_SECONDS
        return True

    async def verify_held_async(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """:meth:`verify_async`: every version Transit still holds counts as held here."""
        return await self.verify_async(kind, fields, stored)

    def sealed_by_retired_key(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """Always False: Transit, not this process, retires key versions."""
        return False

    def is_active(self, stored: str | None) -> bool:
        """Whether ``stored`` names this Transit key. Says nothing about whether it verifies."""
        return self._parse(stored) is not None


#: Either sealer. Every store and service call site takes this and awaits the ``*_async`` methods.
type Sealer = RowSealer | TransitRowSealer
