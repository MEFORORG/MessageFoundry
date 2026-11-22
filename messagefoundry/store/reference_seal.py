# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Prepare a reference snapshot for writing, on every store backend (ADR 0006, BACKLOG #5688).

A snapshot is one large burst of encrypts that runs before its write transaction opens. So the
persisted AES-GCM invocation bound is charged for the whole burst first, and the CPU work (and, under
``vault_transit``, the blocking HTTP) runs in a worker thread rather than on the event loop.
"""

from __future__ import annotations

import asyncio
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from messagefoundry.store.crypto import Cipher, cell_aad
from messagefoundry.store.gcm_bound import AddInvocations, reserve_invocations_ahead
from messagefoundry.store.metadata import encode_reference_value
from messagefoundry.store.sealed_cache import SealedDict, sealed_reference_set

__all__ = ["REFERENCE_INSERT_BATCH", "SealedSnapshot", "seal_reference_snapshot"]

#: Rows per INSERT round trip on the server backends. SQL Server takes at most 2100 parameters per
#: statement and four are bound per row. On Postgres it keeps each ``executemany`` well inside the
#: per-call ``command_timeout``, which one call for a whole large set could exceed.
REFERENCE_INSERT_BATCH: Final = 500


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
) -> SealedSnapshot:
    """Encode ``rows``, reserve one invocation per row, then encrypt them, all off the event loop.

    A failed reservation RAISES, and nothing is encrypted. ``reserve_invocations_ahead`` alone logs a
    failed add on a hydrated cipher and lets the burst proceed, which would spend a whole snapshot
    with the persisted total behind it. Failing here keeps the last-good snapshot and the sync retries
    on its next pass. A reservation whose sync later fails stays charged: an over-count, the safe
    direction for this bound."""

    def _encode() -> list[tuple[str, str]]:
        return [(k, encode_reference_value(v)) for k, v in rows.items()]

    encoded = await asyncio.to_thread(_encode)

    failures: list[Exception] = []

    async def _recording_add(key_id: str, count: int) -> int:
        try:
            return await add_invocations(key_id, count)
        except Exception as exc:
            failures.append(exc)
            raise

    await reserve_invocations_ahead(cipher, _recording_add, len(encoded))
    if failures:
        raise failures[0]

    def _seal() -> SealedSnapshot:
        sealed = [
            (
                name,
                version,
                k,
                cipher.encrypt(text, aad=cell_aad("reference", "value", name, version, k)),
            )
            for k, text in encoded
        ]
        return SealedSnapshot(rows=sealed, cache=sealed_reference_set(name, encoded))

    return await asyncio.to_thread(_seal)
