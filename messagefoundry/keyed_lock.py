# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A per-key FIFO lock table, shared by the auth service and the alert sink.

A leaf module: it imports nothing from the engine, so any package may use it."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass, field


@dataclass
class KeyedLock:
    """One entry of a per-key lock table, with a count of the tasks holding or awaiting it so the
    entry can be dropped when the last one leaves. The auth service's re-proof, credential and
    lock-notice tables (BACKLOG #2216) and the alert sink's state-write table (BACKLOG #2272) each
    use it (:func:`hold_keyed_lock`)."""

    lock: asyncio.Lock = field(default_factory=asyncio.Lock)
    users: int = 0


@asynccontextmanager
async def hold_keyed_lock(table: dict[str, KeyedLock], key: str) -> AsyncIterator[None]:
    """Hold ``table``'s lock for ``key``, creating the entry on first use and dropping it once no
    task holds or awaits it, so the table never outgrows the attempts in flight.

    ``asyncio.Lock`` wakes its waiters in arrival order, so the attempts queued on one key run in the
    order they arrived. A waiter cancelled in the middle of the queue leaves the others in order."""
    entry = table.get(key)
    if entry is None:
        entry = table[key] = KeyedLock()
    entry.users += 1
    try:
        async with entry.lock:
            yield
    finally:
        entry.users -= 1
        if entry.users == 0:
            del table[key]
