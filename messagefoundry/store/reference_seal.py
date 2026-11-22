# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Prepare a reference snapshot for writing, on every store backend (ADR 0006, BACKLOG #5688).

A snapshot is one large burst of encrypts that runs before its write transaction opens. So the
persisted AES-GCM invocation bound is charged for the whole burst first, and the CPU work (and, under
``vault_transit``, the blocking HTTP) runs in a worker thread rather than on the event loop.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Callable, Mapping, MutableMapping
from contextlib import AbstractAsyncContextManager, nullcontext
from dataclasses import dataclass
from typing import Any, Final

from messagefoundry.store.crypto import Cipher, cell_aad, encrypt_many
from messagefoundry.store.gcm_bound import (
    AddInvocations,
    bounded_cipher,
    reserve_invocations_ahead,
)
from messagefoundry.store.metadata import encode_reference_value
from messagefoundry.store.sealed_cache import SealedDict, sealed_reference_set

__all__ = [
    "REFERENCE_INSERT_BATCH",
    "SealedSnapshot",
    "apply_converged",
    "seal_reference_snapshot",
]

log = logging.getLogger(__name__)

#: Rows per INSERT round trip on the server backends. SQL Server takes at most 2100 parameters per
#: statement and four are bound per row. On Postgres it keeps each ``executemany`` well inside the
#: per-call ``command_timeout``, which one call for a whole large set could exceed.
REFERENCE_INSERT_BATCH: Final = 500

#: Values sealed between two checks for a cancellation.
_SEAL_CHUNK: Final = 128


@dataclass(frozen=True, slots=True, repr=False)
class SealedSnapshot:
    """A snapshot ready to write. ``rows`` are ``(name, version, key, ciphertext)``. ``cache`` is the
    read cache to swap in after commit. No repr, because a reference key may be PHI."""

    rows: list[tuple[str, str, str, str]]
    cache: SealedDict[str]


async def seal_reference_snapshot(
    cipher: Cipher,
    add_invocations: AddInvocations,
    *,
    name: str,
    version: str,
    rows: Mapping[str, Any],
    reserve_scope: Callable[[], AbstractAsyncContextManager[None]] | None = None,
) -> SealedSnapshot:
    """Encode ``rows``, reserve one invocation per row, then encrypt them, all off the event loop.

    A failed reservation RAISES, and nothing is encrypted. ``reserve_invocations_ahead`` alone logs a
    failed add on a hydrated cipher and lets the burst proceed, which would spend a whole snapshot
    with the persisted total behind it. Failing here keeps the last-good snapshot and the sync retries
    on its next pass. A reservation whose sync later fails stays charged: an over-count, the safe
    direction for this bound.

    ``reserve_scope`` is entered around the reservation. SQLite passes its writer guard, because the
    bound's pass lock must be taken INSIDE the writer lock (BACKLOG #5608), and ``add_invocations`` is
    then its lock-held add.

    A cancellation stops the seal at its next chunk and is held until the worker has exited. A worker
    left running would go on encrypting after the store's closing settlement, which the persisted
    bound would then under-count."""

    def _encode() -> list[tuple[str, str]]:
        return [(k, encode_reference_value(v)) for k, v in rows.items()]

    encoded = await asyncio.to_thread(_encode)

    failure: Exception | None = None

    async def _recording_add(key_id: str, count: int) -> int:
        nonlocal failure
        try:
            return await add_invocations(key_id, count)
        except Exception as exc:
            failure = exc
            raise

    try:
        if encoded and bounded_cipher(cipher) is not None:
            async with reserve_scope() if reserve_scope is not None else nullcontext():
                await reserve_invocations_ahead(cipher, _recording_add, len(encoded))
        if failure is not None:
            raise failure
    finally:
        # Breaks the exception -> traceback -> this frame cycle, whose locals hold plaintext.
        failure = None

    stop = threading.Event()

    def _seal() -> SealedSnapshot | None:
        items = [(text, cell_aad("reference", "value", name, version, k)) for k, text in encoded]
        values: list[str] = []
        for start in range(0, len(items), _SEAL_CHUNK):
            if stop.is_set():
                return None
            values.extend(encrypt_many(cipher, items[start : start + _SEAL_CHUNK]))
        sealed = [(name, version, k, value) for (k, _), value in zip(encoded, values, strict=True)]
        return SealedSnapshot(rows=sealed, cache=sealed_reference_set(name, encoded))

    # An executor future, not a task: a shutdown that cancels every task cannot detach the worker.
    worker = asyncio.get_running_loop().run_in_executor(None, _seal)
    cancelled = False
    while not worker.done():
        try:
            await asyncio.wait((worker,))
        except asyncio.CancelledError:
            cancelled = True
            stop.set()
    if cancelled:
        if not worker.cancelled() and (error := worker.exception()) is not None:
            # The class only: the traceback's frames hold plaintext.
            log.warning(
                "reference set seal failed after its write was cancelled: %s", type(error).__name__
            )
        raise asyncio.CancelledError
    snapshot = worker.result()
    if snapshot is None:  # only a set `stop` returns None, and only a cancellation sets it
        raise asyncio.CancelledError
    return snapshot


def apply_converged(
    live_cache: MutableMapping[str, Any],
    live_versions: MutableMapping[str, str],
    held: Mapping[str, str],
    cache: Mapping[str, Any],
    versions: Mapping[str, str],
) -> list[str]:
    """Swap in each set whose shared version differs, and return the names swapped.

    ``held`` is ``live_versions`` as it stood before the read. A set whose live version moved during
    the read is left alone, since the read may predate that write. If the shared version is newer
    still, the next pass picks it up."""
    refreshed: list[str] = []
    for name, version in versions.items():
        live = live_versions.get(name)
        if live == held.get(name) and live != version:
            live_cache[name] = cache[name]
            live_versions[name] = version
            refreshed.append(name)
    return refreshed
