# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sealed read-through caches: the transform-state and reference caches hold ciphertext, not PHI.

Every store backend keeps two read-through caches so a Handler's synchronous ``state_get(ns, key)``
and ``reference(name).get(key)`` resolve without awaiting the database (ADR 0005 / ADR 0006). Before
BACKLOG #1174 each cache held the DECRYPTED value of every live key for the store object's lifetime,
so a heap dump or swapped page carried every correlation value and reference row in plaintext.

:class:`SealedDict` is the replacement. It is a ``MutableMapping`` that stores each value as AES-256-GCM
ciphertext and decrypts it inside the synchronous accessor, so plaintext exists only for the one read
that asked for it. The store code that mutates the caches is unchanged: ``cache[k] = v`` seals and
``cache[k]`` opens.

**Why not evict instead (the correctness trap).** An idle-TTL or LRU eviction over the cache of record
is silently wrong. The store read is async while the Handler read path is synchronous, so an evicted
live key cannot be repopulated and would read as absent -- a suppression or de-duplication Handler
would then act on a missing key with no error. Sealing keeps every key present, so there are no
misses.

**Why a process-local key and not the at-rest form.** Holding the store's own ``mfenc:`` ciphertext
and decrypting it with the store cipher on each read reuses ciphertext the store already has, and was
the first proposal (BACKLOG #1185). Two things in the code rule it out:

1. Under ``[store].cipher_provider = "vault_transit"`` every store decrypt is a Vault Transit HTTP
   call (:mod:`messagefoundry.store.crypto_transit`). Each ``state_get`` would become a network round
   trip, and a Vault outage after startup would turn every read into a Handler error.
2. Even in-process, the store cipher's decrypt locks and wipes a buffer on every call. Measured
   2026-09-29 on CPython 3.14, Windows: about 25 to 40 microseconds a read, against about 2 to 4
   here.

The keyless-open refusal (``decrypt_json_cell`` raising ``StoreKeylessError``) is unchanged: each
backend still decrypts every row once at open, exactly as before, and only then seals the decoded
value here. So a keyless or wrong-key open still fails at startup and never inside a Handler.

**What this does not claim.** The key lives in the same process, so an attacker with memory access
who finds the key can still open the cache. This raises the cost of a heap scrape; it is not
encryption against a process-memory attacker, and the value a Handler reads back is an ordinary
Python object with no wipe hook. ASVS 11.7.2 stays partial (BACKLOG #1174).

**Nonces.** A fresh random 256-bit key per process, and a 96-bit nonce made of a 4-byte per-process
prefix plus an 8-byte counter, so a nonce never repeats under one key. A forked child picks a new
random prefix (it inherits the key and must be able to open inherited entries), so parent and child
never share a nonce except by a 1-in-2**32 prefix collision.
"""

from __future__ import annotations

import json
import os
import threading
from collections.abc import Callable, Hashable, Iterable, Iterator, Mapping, MutableMapping
from types import MappingProxyType
from typing import Any, Final, cast

from messagefoundry.store.crypto import _install_key
from messagefoundry.store.metadata import encode_reference_value

__all__ = [
    "SealedDict",
    "new_reference_set",
    "new_state_cache",
    "point_in_time",
    "sealed_reference_set",
]

_NONCE_PREFIX_BYTES: Final = 4
_COUNTER_BYTES: Final = 8
_NONCE_BYTES: Final = _NONCE_PREFIX_BYTES + _COUNTER_BYTES
_COUNTER_LIMIT: Final = 1 << (8 * _COUNTER_BYTES)
_MISSING: Final = object()


class _Sealer:
    """One AES-256-GCM key for this process, with collision-free counter nonces."""

    def __init__(self) -> None:
        # _install_key builds the AESGCM and then locks + wipes the mutable key buffer (best effort),
        # the same handling the store DEK gets. The fingerprint it returns is not needed here.
        _, self._aes = _install_key(bytearray(os.urandom(32)))
        self._lock = threading.Lock()
        self._prefix = os.urandom(_NONCE_PREFIX_BYTES)
        self._counter = 0

    def reseed_after_fork(self) -> None:
        """Give a forked child its own nonce space under the key it inherited."""
        self._lock = threading.Lock()  # a lock held by another thread at fork time stays held
        self._prefix = os.urandom(_NONCE_PREFIX_BYTES)

    def seal(self, plaintext: bytes, aad: bytes) -> bytes:
        with self._lock:
            n = self._counter
            if n >= _COUNTER_LIMIT:  # unreachable in practice; refuse rather than reuse a nonce
                raise RuntimeError("sealed-cache nonce counter exhausted")
            self._counter = n + 1
            nonce = self._prefix + n.to_bytes(_COUNTER_BYTES, "big")
        return nonce + self._aes.encrypt(nonce, plaintext, aad)

    def open(self, blob: bytes, aad: bytes) -> bytes:
        return self._aes.decrypt(blob[:_NONCE_BYTES], blob[_NONCE_BYTES:], aad)


_sealer: _Sealer | None = None
_sealer_lock = threading.Lock()


def _process_sealer() -> _Sealer:
    global _sealer
    sealer = _sealer
    if sealer is None:
        with _sealer_lock:
            if _sealer is None:
                _sealer = _Sealer()
            sealer = _sealer
    return sealer


def _after_fork_in_child() -> None:
    global _sealer_lock
    _sealer_lock = threading.Lock()  # a fork mid-_process_sealer() would leave it held
    if _sealer is not None:
        _sealer.reseed_after_fork()


def _canonical(key: object) -> bytes:
    """The key's bytes for the AEAD associated data.

    It must be the same for every key the dict treats as equal, or a read with an equal key would
    find the entry and then fail to open it. ``repr`` is not: a ``StrEnum`` namespace that a Handler
    passed to ``SetState`` equals and hashes like its plain ``str`` value, which is what a reopened
    store reads back, but its ``repr`` differs. So each ``str`` part is taken by value
    (``str.__str__`` drops any subclass) and length-prefixed, which also keeps ``("a", "bc")`` apart
    from ``("ab", "c")``.
    """
    if isinstance(key, tuple):
        parts: tuple[object, ...] = key
        out = [b"t"]
    else:
        parts = (key,)
        out = [b"s"]
    for part in parts:
        # Every backend keys its caches by str. repr() is a fallback for any other hashable, where
        # equal-but-differently-repr'd keys would still fail closed rather than read wrongly.
        # A per-part tag keeps a str part apart from a non-str part with the same text.
        if isinstance(part, str):
            tag, text = b"S", str.__str__(part)
        else:
            tag, text = b"R", repr(part)
        raw = text.encode("utf-8", "surrogatepass")
        out.append(tag + len(raw).to_bytes(4, "big") + raw)
    return b"".join(out)


if hasattr(os, "register_at_fork"):
    os.register_at_fork(after_in_child=_after_fork_in_child)


class SealedDict[K: Hashable](MutableMapping[K, Any]):
    """A mapping that keeps each value as ciphertext and decodes it on every read.

    Values go in through ``encode`` (a JSON encoder) and come out through ``json.loads``, so a read
    returns the same form a reopened store would load: a fresh object on every call, which a Handler
    can mutate without touching the cache. Each ciphertext is bound (as AEAD associated data) to its
    ``scope`` and key, so one entry's ciphertext cannot be opened as another's.

    Membership, length and iteration touch only the keys and never decrypt. ``copy`` duplicates the
    ciphertext, so a point-in-time snapshot costs the same as copying a plain dict.
    """

    __slots__ = ("_scope", "_encode", "_data", "_sealer")

    def __init__(self, scope: str, encode: Callable[[Any], str] = json.dumps) -> None:
        self._scope = scope.encode("utf-8") + b"\x00"
        self._encode = encode
        self._data: dict[K, bytes] = {}
        self._sealer = _process_sealer()

    def _aad(self, key: K) -> bytes:
        return self._scope + _canonical(key)

    def _open(self, key: K, blob: bytes) -> Any:
        return json.loads(self._sealer.open(blob, self._aad(key)))

    def put_encoded(self, key: K, text: str) -> None:
        """Seal a value that is already JSON text (skips a decode and re-encode)."""
        self._data[key] = self._sealer.seal(text.encode("utf-8"), self._aad(key))

    def __setitem__(self, key: K, value: Any) -> None:
        self.put_encoded(key, self._encode(value))

    def __getitem__(self, key: K) -> Any:
        return self._open(key, self._data[key])

    def get(self, key: K, default: Any = None) -> Any:
        blob = self._data.get(key)
        return default if blob is None else self._open(key, blob)

    def __delitem__(self, key: K) -> None:
        del self._data[key]

    def __contains__(self, key: object) -> bool:
        return key in self._data

    def __iter__(self) -> Iterator[K]:
        return iter(self._data)

    def __len__(self) -> int:
        return len(self._data)

    def pop(self, key: K, default: Any = _MISSING) -> Any:
        blob = self._data.pop(key, None)
        if blob is None:
            if default is _MISSING:
                raise KeyError(key)
            return default
        return self._open(key, blob)

    def discard(self, key: K) -> None:
        """Remove ``key`` if present, without decrypting it (``pop`` must decrypt to return it)."""
        self._data.pop(key, None)

    def clear(self) -> None:
        self._data.clear()

    def copy(self) -> SealedDict[K]:
        """A point-in-time copy that shares no state with ``self`` and decrypts nothing."""
        dup: SealedDict[K] = SealedDict.__new__(SealedDict)
        dup._scope = self._scope
        dup._encode = self._encode
        dup._data = dict(self._data)
        dup._sealer = self._sealer
        return dup

    def __repr__(self) -> str:
        # Never the values: a repr lands in logs and tracebacks.
        return f"SealedDict(scope={self._scope[:-1].decode('utf-8')!r}, entries={len(self._data)})"


def new_state_cache() -> SealedDict[tuple[str, str]]:
    """An empty transform-state cache (ADR 0005), keyed by ``(namespace, key)``."""
    return SealedDict("state")


def new_reference_set(name: str) -> SealedDict[str]:
    """An empty cache for one reference snapshot (ADR 0006), encoded as the ``reference`` table is."""
    return SealedDict("reference " + repr(str.__str__(name)), encode_reference_value)


def sealed_reference_set(name: str, encoded: Iterable[tuple[str, str]]) -> SealedDict[str]:
    """A reference-set cache filled from ``(key, json_text)`` pairs the caller already encoded for
    the ``reference`` table, so each value is encoded once for both the database and the cache."""
    cache = new_reference_set(name)
    for key, text in encoded:
        cache.put_encoded(key, text)
    return cache


def point_in_time[K, V](view: Mapping[K, V]) -> Mapping[K, V]:
    """A frozen copy of a live cache view that decrypts nothing.

    ``dict(view)`` over a sealed cache would decrypt every entry. A ``MappingProxyType``'s ``copy``
    calls its target's ``copy``, which for a :class:`SealedDict` copies ciphertext, so the snapshot
    stays sealed and costs what copying a plain dict does. Any other mapping is copied into a dict.
    """
    if isinstance(view, (MappingProxyType, SealedDict)):
        try:
            return MappingProxyType(cast(Mapping[K, V], view.copy()))
        except AttributeError:
            pass  # a proxy over a mapping with no copy(): fall through to a plain copy
    return dict(view)
