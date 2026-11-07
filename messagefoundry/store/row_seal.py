# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Integrity seals for the store's authority rows (BACKLOG #2592).

A **seal** is an HMAC-SHA256 over a typed encoding of one row, stored in the row as::

    mfseal:v1:<key id>:<hex mac>

Under a ``vault_transit`` store the seal is instead Transit's own HMAC, under the audit key, of
a SHA-256 digest of that encoding, stored as ``mfseal:v1:<key id>:vault:v<N>:<base64>`` with a key id
derived from the key's mount and name (:class:`TransitRowSealer`, ADR 0217); no seal key enters the
heap.

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

import asyncio
import base64
import binascii
import contextvars
import functools
import hashlib
import hmac
import logging
import time
from collections.abc import Callable, Iterable
from concurrent.futures import ThreadPoolExecutor
from typing import Final, Protocol

from messagefoundry.store.crypto import (
    NO_STORE_ID,
    Cipher,
    CipherError,
    derive_row_seal_key,
    row_seal_key_id,
)
from messagefoundry.store.crypto import (
    TransitSealRefused as TransitSealRefused,
)

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

#: The kind a rejected request's tombstone seal is computed under (BACKLOG #3638): the seal a
#: Reject writes on a ``pending_approvals`` row that failed its own seal. A kind of its own, so a
#: tombstone never verifies as an approval seal and never vouches for the row's other columns.
APPROVAL_TOMBSTONE_KIND: Final = "approval_tombstone"

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
    change made outside the helper into a sealed row. ``args`` are exactly ``(kind, subject)``
    (ADR 0217 (c) step 1, #4739 item 12): ``subject`` is the bounded, readable reference a caller
    builds for the row, such as a stored id or a 12-hex prefix, never a key or a whole token hash,
    so ``repr()``, copy and pickle carry nothing more. Empty where the raising site has no subject to give."""

    def __init__(self, kind: str, subject: str = "") -> None:
        super().__init__(kind, subject)
        self.kind = kind
        self.subject = subject

    def __str__(self) -> str:
        return f"the {self.kind} row's integrity seal does not verify; the write was refused"


class RowSealUnverifiableError(Exception):
    """A store write helper read a row whose seal Vault transit would not check, and refused the
    write (ADR 0217 (c) step 1).

    A SIBLING of :class:`RowSealError`, never a subclass, so no ``except RowSealError`` runs its
    forged-row fallback (a raw delete, a count) on a row that may be sound and only unverifiable.
    The type is the cause. ``args`` are exactly ``(kind, subject)``, as for :class:`RowSealError`.
    ``stored_version`` and ``probe_version`` are the Transit verdict's two integers, triage detail
    for the audit row (ADR 0217 (a)), kept outside ``args``; 0 where no Transit verdict gave them."""

    def __init__(
        self, kind: str, subject: str = "", *, stored_version: int = 0, probe_version: int = 0
    ) -> None:
        super().__init__(kind, subject)
        self.kind = kind
        self.subject = subject
        self.stored_version = stored_version
        self.probe_version = probe_version

    def __str__(self) -> str:
        return (
            f"the {self.kind} row's integrity seal cannot be verified by Vault transit; the write"
            " was refused"
        )


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

    # The awaited forms (ADR 0217 slice 1, the async seal seam), so one call site can serve this
    # sealer and :class:`TransitRowSealer`. No I/O: each answers in the calling coroutine.

    async def seal_async(self, kind: str, fields: Iterable[tuple[str, object]]) -> str:
        """:meth:`seal`, awaitable."""
        return self.seal(kind, fields)

    async def verify_async(
        self,
        kind: str,
        fields: Iterable[tuple[str, object]],
        stored: str | None,
        *,
        fresh: bool = False,
    ) -> bool:
        """:meth:`verify`, awaitable. ``fresh`` is accepted so one call site serves both sealers;
        this sealer keeps no cache, so every answer is already fresh."""
        return self.verify(kind, fields, stored)

    async def verify_held_async(
        self,
        kind: str,
        fields: Iterable[tuple[str, object]],
        stored: str | None,
        *,
        fresh: bool = False,
    ) -> bool:
        """:meth:`verify_held`, awaitable. ``fresh`` is accepted so one call site serves both sealers;
        this sealer keeps no cache, so every answer is already fresh."""
        return self.verify_held(kind, fields, stored)

    async def sealed_by_retired_key_async(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """:meth:`sealed_by_retired_key`, awaitable."""
        return self.sealed_by_retired_key(kind, fields, stored)


# --- The Transit row sealer (ADR 0217, "The four answers, defined once") ---------------------------
#
# Not yet returned by RowSealer.for_cipher: wiring it into the stores' write and read paths is the
# rest of ADR 0217 slice 1. Until then a vault_transit store still writes and checks no seals, as on
# main; this class changes nothing it does not yet reach.


class TransitSealUnavailableError(Exception):
    """A Transit call for a row seal did not complete, or did not answer as Transit answers: the
    **Outage** answer. Not an integrity failure: the row may be sound. It refuses the request or
    rolls the write back, ends nothing, and records no seal failure.

    Deliberately neither a :class:`~messagefoundry.store.crypto.CipherError` nor a
    :class:`RowSealError` (ADR 0217 (c) step 2), so no ``except CipherError`` and no forged-row
    fallback catches it. Raised outside any handler, so it chains nothing, and its text is fixed:
    never row data, a token hash or Vault's text. Its ``args`` are empty, so copy and pickle
    rebuild it."""

    def __str__(self) -> str:
        return "a row seal could not be made or checked through Vault transit"


class TransitSealUnverifiableError(Exception):
    """A well-formed row seal that Transit refused to check while its active key still answers:
    the **Unverifiable** answer. A planted version, a node that lags a rotation and a retired
    version all give this reply, and it cannot tell them apart, so it denies like a forged seal.

    Neither a :class:`~messagefoundry.store.crypto.CipherError` nor a :class:`RowSealError`.
    ``args`` are exactly ``(kind, stored_version, probe_version)``: the row kind and two integers
    of at most ten digits parsed from Transit-shaped strings, triage detail that no decision reads
    (ADR 0217 (a)). Raised outside any handler; its text is fixed."""

    def __init__(self, kind: str, stored_version: int, probe_version: int) -> None:
        super().__init__(kind, stored_version, probe_version)
        self.kind = kind
        self.stored_version = stored_version
        self.probe_version = probe_version

    def __str__(self) -> str:
        return f"the {self.kind} row's integrity seal cannot be verified by Vault transit"


class TransitSealBackend(Protocol):
    """The three Transit calls the sealer makes. Each blocks; the sealer runs it in a worker thread
    so a seal or a check never blocks the event loop (CLAUDE.md section 6). Each returns Transit's
    raw value, and the sealer checks its shape.
    :class:`~messagefoundry.store.crypto_transit.TransitCipher` is the implementation."""

    @property
    def seal_key_name(self) -> str:
        """The active Transit key seals are made under. A name, never key material."""
        ...

    @property
    def seal_mount(self) -> str:
        """The Transit mount the key lives on."""
        ...

    def seal_hmac(self, digest: bytes) -> object:
        """Transit's ``hmac`` of ``digest`` under the active key's latest version. The three
        calls raise :class:`~messagefoundry.store.crypto.CipherError` for a Vault failure, and
        :class:`~messagefoundry.store.crypto.TransitSealRefused` for an HTTP 400 or 403. On this
        call and the probe the sealer reads either as an Outage; on ``verify`` a refusal is
        classified (*The four answers*). Any other exception is a defect."""
        ...

    def verify_seal_hmac(self, key_name: str, digest: bytes, mac: str) -> object:
        """Transit's ``verify`` of ``mac`` over ``digest`` under ``key_name`` at the version ``mac``
        names, its raw ``valid``. Raises :class:`~messagefoundry.store.crypto.TransitSealRefused`
        for an HTTP 400 or 403."""
        ...

    def seal_probe(self) -> object:
        """Transit's ``hmac`` over a fixed input under the active key's latest version."""
        ...


#: Leads every Transit seal input's SHA-256 preimage, so a seal input is never the digest of
#: another row-seal encoding that lacks it. It does NOT keep a row seal apart from another MAC
#: under the same Transit key: Transit receives only the 32-byte digest, never this label, so that
#: separation holds only while no other caller asks Transit to MAC a bare 32-byte value under the
#: audit key. A caller that does, over a value someone else chooses, can mint row seals; this
#: module does not check that none does.
_TRANSIT_SEAL_LABEL: Final = b"mefor/row-seal/transit/v1"
#: The digest length a well-formed Transit seal's MAC decodes to: SHA-256's.
_TRANSIT_DIGEST_LEN: Final = 32
_TRANSIT_MAC_PREFIX: Final = "vault:v"
_TRANSIT_VERSION_MAX_DIGITS: Final = 10
#: How long one Holds, Forged or Unverifiable answer is reused, in seconds. Within every
#: ``session_idle_timeout_minutes`` setting, which counts whole minutes.
TRANSIT_SEAL_CACHE_TTL_SECONDS: Final = 60.0
#: How many answers the cache holds; the oldest is dropped first.
TRANSIT_SEAL_CACHE_MAX: Final = 4096
# Cached answers. An Outage is never cached.
_HOLDS: Final = "holds"
_FORGED: Final = "forged"
_UNVERIFIABLE: Final = "unverifiable"


#: The most ROW SEAL Transit calls in flight at once, process-wide. They run on this pool, not
#: asyncio's default executor, so a slow Vault cannot fill the default executor with seal checks.
#: Only row-seal calls: the audit chain's Transit MACs still run on the default executor. The
#: queue past the bound has no deadline, so a check waits for a free thread for as long as the
#: calls ahead of it take, each bounded by the Vault client's own timeout; a thread whose caller
#: was cancelled finishes its call, and interpreter exit waits for it.
TRANSIT_SEAL_WORKERS: Final = 8


@functools.cache
def _transit_pool() -> ThreadPoolExecutor:
    # Built on first use, so a process that never seals through Transit builds no pool.
    return ThreadPoolExecutor(
        max_workers=TRANSIT_SEAL_WORKERS, thread_name_prefix="mefor-transit-seal"
    )


async def _in_transit_pool[**P, T](call: Callable[P, T], *args: P.args, **kwargs: P.kwargs) -> T:
    """``call(*args, **kwargs)`` on the row-seal Transit pool, in a copy of the caller's context
    as :func:`asyncio.to_thread` runs it."""
    context = contextvars.copy_context()
    loop = asyncio.get_running_loop()
    bound = functools.partial(context.run, call, *args, **kwargs)
    return await loop.run_in_executor(_transit_pool(), bound)


def transit_seal_key_id(mount: str, key_name: str) -> str:
    """The key id a Transit seal names: :func:`row_seal_key_id` of the SHA-256 of the mount and the
    key's NAME, each length-prefixed (ADR 0217, *The key id, and a retired key*). Neither is
    secret, so the id reveals nothing; it is fixed-width hex, so it holds no ``:``."""
    named = hashlib.sha256(_part(mount.encode("utf-8")) + _part(key_name.encode("utf-8")))
    return row_seal_key_id(named.digest())


def transit_mac_version(mac: str) -> int | None:
    """The key version a well-formed Transit MAC string names, or ``None`` when it is not one.

    Well-formed is ``vault:v<N>:`` with ``N`` of 1 to 10 ASCII digits and no leading zero, then
    base64 that decodes strictly (``validate=True``) to exactly the SHA-256 digest length (ADR
    0217, *The strict parse*). It must also re-encode to the same text: ``validate=True`` accepts
    non-zero pad bits, and this rule, which the ADR does not state, leaves one stored form per
    seal. Parsed by hand; anything else is Forged with no Transit call, so no malformed body
    reaches Transit to draw a 400."""
    if not mac.isascii() or not mac.startswith(_TRANSIT_MAC_PREFIX):
        return None
    version, sep, body = mac[len(_TRANSIT_MAC_PREFIX) :].partition(":")
    if not sep or not version or len(version) > _TRANSIT_VERSION_MAX_DIGITS:
        return None
    if not all("0" <= c <= "9" for c in version) or version.startswith("0"):
        return None
    try:
        digest = base64.b64decode(body, validate=True)
    except binascii.Error:
        return None
    if len(digest) != _TRANSIT_DIGEST_LEN:
        return None
    # Canonical only: ``validate=True`` still accepts non-zero pad bits, so several strings would
    # name one MAC. Re-encoding and comparing leaves one stored form per seal.
    if base64.b64encode(digest).decode("ascii") != body:
        return None
    return int(version)


class TransitRowSealer:
    """Seals and checks rows with Transit's own HMAC under the audit key, so no seal key enters the
    heap (ADR 0217).

    **Stored form.** ``mfseal:v1:<key id>:vault:v<N>:<base64>``, ``<key id>`` from
    :func:`transit_seal_key_id`. **Input.** Transit receives the 32-byte SHA-256 of the label, the
    store id and :func:`seal_bytes`, each length-prefixed, never the row: every call is one size,
    and no token hash or row value reaches Transit or its error text.

    **The four answers** of a check: *Holds* (``True``); *Forged* (``False``: Transit's
    ``valid: false``, a seal that fails :func:`transit_mac_version`, or one naming a key id this
    sealer does not hold, with no Transit call for either of the last two); *Unverifiable*
    (:class:`TransitSealUnverifiableError`: an HTTP 400 while the active key's fixed-input probe
    answers with a well-formed MAC, whatever version it names; or a 400 or 403 on a seal naming a
    retired key while that probe works); *Outage* (:class:`TransitSealUnavailableError`: every
    other Vault failure, which the backend raises as :class:`~messagefoundry.store.crypto.CipherError`,
    including a 403 on the active key and a probe that fails or answers malformed). Any other
    exception is a defect, not an Outage, and propagates as itself.

    **Threads.** Every Transit call runs on a pool of :data:`TRANSIT_SEAL_WORKERS` threads of its
    own, never on the event loop and never on asyncio's default executor.

    **Retired keys.** ``retired_key_names`` are the store's earlier Transit audit keys. A seal under
    one is checked under that key: :meth:`verify_held_async` accepts it, as ``verify_held`` does;
    :meth:`verify_async`, the session check, never does, and :meth:`sealed_by_retired_key_async`
    lets the caller end such a session quietly.

    **The caches.** A Holds, Forged or Unverifiable answer is reused for
    :data:`TRANSIT_SEAL_CACHE_TTL_SECONDS`, keyed by a digest of the seal input's SHA-256, the key
    id and the stored Transit string, never by a row id. Both are emptied whenever a probe (a refused
    check's, or :meth:`probe_async`) names a different latest version than the last one did, and a check that began before
    that keeps its answer for its own caller only. An Outage is never cached."""

    __slots__ = (
        "_backend",
        "_cache",
        "_clock",
        "_generation",
        "_keys",
        "_prefix",
        "_probed_version",
        "_throttle",
        "key_id",
    )

    def __init__(
        self,
        backend: TransitSealBackend,
        *,
        retired_key_names: Iterable[str] = (),  # names, never a bare str
        store_id: bytes = NO_STORE_ID,
        clock: Callable[[], float] = time.monotonic,
    ) -> None:
        if isinstance(retired_key_names, str):
            raise TypeError("retired_key_names is a collection of key names, not one name")
        retired = list(retired_key_names)
        if not all(isinstance(name, str) and name for name in retired):
            raise ValueError("every retired Transit key name must be a non-empty string")
        self._backend = backend
        mount = backend.seal_mount
        #: The non-secret id every seal this sealer writes names.
        self.key_id: str = transit_seal_key_id(mount, backend.seal_key_name)
        # key id -> (key name, whether it is a retired key).
        self._keys: dict[str, tuple[str, bool]] = {
            transit_seal_key_id(mount, name): (name, True)
            for name in retired
            if name != backend.seal_key_name
        }
        self._keys[self.key_id] = (backend.seal_key_name, False)
        self._prefix = _part(_TRANSIT_SEAL_LABEL) + _part(bytes(store_id))
        self._cache: dict[bytes, tuple[float, str, int, int]] = {}
        self._generation = 0
        self._probed_version = 0
        self._clock = clock
        self._throttle = SealFailureThrottle()

    def _digest(self, kind: str, fields: Iterable[tuple[str, object]]) -> bytes:
        return hashlib.sha256(self._prefix + _part(seal_bytes(kind, fields))).digest()

    def _outage(self, exc: CipherError) -> TransitSealUnavailableError:
        # ERROR line, throttled per cause so a second cause inside the window is still logged. A
        # CipherError's text is this package's own fixed wording, never Vault's.
        cause = str(exc)
        if self._throttle.due(f"outage:{cause}"):
            log.error(
                "a row seal could not be made or checked through Vault transit (%s): an outage,"
                " not a seal failure",
                cause,
            )
        return TransitSealUnavailableError()

    @staticmethod
    def _parse(stored: str | None) -> tuple[str, str, int] | None:
        """``(key id, Transit string, version)`` from a well-formed stored seal, or ``None``."""
        if not stored or not stored.startswith(SEAL_PREFIX):
            return None
        key_id, sep, mac = stored[len(SEAL_PREFIX) :].partition(":")
        version = transit_mac_version(mac) if sep else None
        if version is None:
            return None
        return key_id, mac, version

    def is_active(self, stored: str | None) -> bool:
        """Whether ``stored`` is well-formed and names the active key. Says nothing about whether
        it verifies."""
        parsed = self._parse(stored)
        return parsed is not None and parsed[0] == self.key_id

    async def seal_async(self, kind: str, fields: Iterable[tuple[str, object]]) -> str:
        """The stored seal for a row of ``kind`` holding ``fields``: one Transit ``hmac`` call."""
        digest = self._digest(kind, fields)
        failure: CipherError | None = None
        mac: object = None
        try:
            mac = await _in_transit_pool(self._backend.seal_hmac, digest)
        except CipherError as exc:  # the backend's form of every Vault failure: an Outage
            failure = exc
        except TransitSealRefused as refused:  # a refused hmac is a Vault failure too
            failure = CipherError(f"Transit refused a seal hmac (HTTP {refused.status})")
        if failure is not None or not isinstance(mac, str) or transit_mac_version(mac) is None:
            raise self._outage(
                failure or CipherError("Transit returned a MAC of an unexpected shape")
            )
        return f"{SEAL_PREFIX}{self.key_id}:{mac}"

    async def verify_async(
        self,
        kind: str,
        fields: Iterable[tuple[str, object]],
        stored: str | None,
        *,
        fresh: bool = False,
    ) -> bool:
        """The session check: whether ``stored`` holds under the ACTIVE key. A seal under a retired
        key is ``False`` with no Transit call (:meth:`sealed_by_retired_key_async` tells it apart).
        ``fresh`` skips the cache read, for a check that must ask Transit now; its answer is still
        cached."""
        return await self._check(kind, fields, stored, accept_retired=False, fresh=fresh)

    async def verify_held_async(
        self,
        kind: str,
        fields: Iterable[tuple[str, object]],
        stored: str | None,
        *,
        fresh: bool = False,
    ) -> bool:
        """The record check: whether ``stored`` holds under the active key or a listed retired one."""
        return await self._check(kind, fields, stored, accept_retired=True, fresh=fresh)

    async def sealed_by_retired_key_async(
        self, kind: str, fields: Iterable[tuple[str, object]], stored: str | None
    ) -> bool:
        """Whether ``stored`` holds under a RETIRED key: a session the caller ends quietly rather
        than reports. ``False`` for a seal under the active key or no held key. Unlike the local
        form it can raise :class:`TransitSealUnverifiableError` or
        :class:`TransitSealUnavailableError`, as any Transit check can."""
        parsed = self._parse(stored)
        if parsed is None or parsed[0] == self.key_id or parsed[0] not in self._keys:
            return False
        return await self._check(kind, fields, stored, accept_retired=True, fresh=False)

    async def _check(
        self,
        kind: str,
        fields: Iterable[tuple[str, object]],
        stored: str | None,
        *,
        accept_retired: bool,
        fresh: bool,
    ) -> bool:
        parsed = self._parse(stored)
        if parsed is None:
            return False
        key_id, mac, stored_version = parsed
        held = self._keys.get(key_id)
        if held is None:
            return False
        key_name, retired = held
        if retired and not accept_retired:
            return False
        digest = self._digest(kind, fields)
        entry = hashlib.sha256(
            _part(digest) + _part(key_id.encode("ascii")) + _part(mac.encode("ascii"))
        ).digest()
        cached = None if fresh else self._cache.get(entry)
        if cached is not None:
            expires, answer, cached_stored, cached_probe = cached
            if self._clock() < expires:
                if answer == _UNVERIFIABLE:
                    raise TransitSealUnverifiableError(kind, cached_stored, cached_probe)
                return answer == _HOLDS
            del self._cache[entry]
        generation = self._generation
        refused_status: int | None = None
        failure: CipherError | None = None
        valid: object = None
        try:
            valid = await _in_transit_pool(self._backend.verify_seal_hmac, key_name, digest, mac)
        except TransitSealRefused as refused:
            refused_status = refused.status
        except CipherError as exc:  # the backend's form of every other Vault failure: an Outage
            failure = exc
        if refused_status is not None:
            if refused_status != 400 and not (refused_status == 403 and retired):
                raise self._outage(
                    CipherError(f"Transit refused a seal check (HTTP {refused_status})")
                )
            probe_version = await self._probe(after_refusal=True)
            if self._generation == generation:
                # Not stored when anything, its own probe included, emptied the cache meanwhile.
                self._remember(entry, _UNVERIFIABLE, stored_version, probe_version)
            raise TransitSealUnverifiableError(kind, stored_version, probe_version)
        if failure is not None:
            raise self._outage(failure)
        if not isinstance(valid, bool):
            raise self._outage(
                CipherError("Transit returned a verify reply of an unexpected shape")
            )
        if self._generation == generation:
            # A check that began before the cache was emptied keeps its answer for its own caller.
            self._remember(entry, _HOLDS if valid else _FORGED, 0, 0)
        return valid

    async def probe_async(self) -> int:
        """The start check: the active key's fixed-input probe, which proves the token can reach
        Transit and ``hmac`` under the audit key. Returns the version it names; raises
        :class:`TransitSealUnavailableError` otherwise. Empties the caches when the version moved,
        as any probe does."""
        return await self._probe(after_refusal=False)

    async def _probe(self, *, after_refusal: bool) -> int:
        """The latest version the active key's fixed-input probe names, emptying both caches when
        it moved. Raises
        :class:`TransitSealUnavailableError` when the probe fails or answers in an unexpected
        shape: then a refusal is an Outage, never Unverifiable."""
        failure: CipherError | None = None
        answered: object = None
        try:
            answered = await _in_transit_pool(self._backend.seal_probe)
        except CipherError as exc:  # a probe that fails makes the refusal an Outage
            failure = exc
        except TransitSealRefused as refused:  # a refused hmac is a Vault failure too
            failure = CipherError(f"Transit refused a seal hmac (HTTP {refused.status})")
        version = transit_mac_version(answered) if isinstance(answered, str) else None
        if failure is not None or version is None:
            failure = failure or CipherError("Transit's key probe returned an unexpected shape")
            if after_refusal and self._throttle.due(f"probe:{failure}"):
                # Says what the ERROR line cannot: a refused check was not called Unverifiable.
                log.warning(
                    "the Vault transit key probe failed (%s), so a refused row seal check counts"
                    " as an outage",
                    failure,
                )
            raise self._outage(failure)
        if version != self._probed_version:
            self._probed_version = version
            self._cache.clear()
            self._generation += 1
        return version

    def _remember(self, entry: bytes, answer: str, stored_version: int, probe_version: int) -> None:
        self._cache.pop(entry, None)
        if len(self._cache) >= TRANSIT_SEAL_CACHE_MAX:
            self._cache.pop(next(iter(self._cache)))
        expires = self._clock() + TRANSIT_SEAL_CACHE_TTL_SECONDS
        self._cache[entry] = (expires, answer, stored_version, probe_version)


#: Either sealer: one call site awaits the same four methods on both.
AnyRowSealer = RowSealer | TransitRowSealer


async def require_seal_for_write(
    sealer: AnyRowSealer | None,
    kind: str,
    fields: Iterable[tuple[str, object]],
    stored: str | None,
    *,
    subject: str,
) -> None:
    """Refuse a write over a stored row whose seal does not hold (ADR 0217 (c) step 1).

    Raises :class:`RowSealError` for a Forged row and its sibling :class:`RowSealUnverifiableError`
    for an Unverifiable one, each with ``args`` exactly ``(kind, subject)``; the caller builds
    ``subject``, a bounded readable reference, never a whole token hash. An Outage is never either:
    :class:`TransitSealUnavailableError` propagates as itself. The kind picks the check: a session
    holds under the active key only, never a retired one; every other row under the active key or a
    listed retired one. So a session sealed under a retired key raises :class:`RowSealError` here,
    and a caller that ends such a session quietly asks ``sealed_by_retired_key_async`` first. No
    sealer means a store that seals nothing, so nothing is refused. The subject is not checked
    here; a whole token hash in it would reach ``args``."""
    if sealer is None:
        return
    check = sealer.verify_async if kind == SESSION_KIND else sealer.verify_held_async
    verdict: TransitSealUnverifiableError | None = None
    holds = False
    try:
        holds = await check(kind, fields, stored)
    except TransitSealUnverifiableError as exc:
        verdict = exc
    except TypeError:  # a stored value the encoder cannot read fails its seal, as on main
        holds = False
    # Raised outside the handler, so neither chains the Transit verdict.
    if verdict is not None:
        raise RowSealUnverifiableError(
            kind,
            subject,
            stored_version=verdict.stored_version,
            probe_version=verdict.probe_version,
        )
    if not holds:
        raise RowSealError(kind, subject)
