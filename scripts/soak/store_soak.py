# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Production-like soak of the aiosqlite message store under a single, long-lived asyncio loop.

**Purpose — settle BACKLOG #17.** The intermittent py3.11 CI hang is an asyncio <-> aiosqlite
*lost-wakeup* deadlock (the event loop sits idle in the selector while aiosqlite's worker thread sits
idle on ``tx.get()`` — a completed query's ``loop.call_soon_threadsafe(future.set_result, ...)`` never
wakes the loop). It has **only** ever appeared under pytest, whose per-test event-loop churn and
log-capture teardown are the suspected triggers. The open question: is it a real product bug, or a
test-harness artifact?

This script answers it by running the store the way the **engine does in production** — ONE
``asyncio.run()`` loop for the whole process, **no pytest** — and hammering aiosqlite with many
*concurrent* awaited DB operations, i.e. the exact path the worker thread resolves via
``call_soon_threadsafe``:

* If a steady-state lost-wakeup is real, this **hangs** (and the CI job's ``timeout`` catches it),
  giving a clean, pytest-free repro that confirms a production bug.
* If it runs clean — repeatedly, on **py3.11** — that is strong evidence the hang is a
  **test-lifecycle artifact**, not a MessageFoundry defect.

Usage::

    python scripts/soak/store_soak.py [concurrency] [ops_per_worker]

Exits 0 with a ``SOAK OK`` line on success; a hang is surfaced by the caller's timeout (the script
itself does not bound the run, so a real deadlock is observable rather than masked).
"""

from __future__ import annotations

import asyncio
import sys
import tempfile
import time
from pathlib import Path

from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.store import MessageStore

# A small synthetic HL7 body — synthetic only, never real PHI (per project rules).
_SAMPLE = (
    "MSH|^~\\&|EPIC|SF|MFOR|RF|20240101120000||ADT^A01|SOAK|P|2.5.1\rPID|1||MRN1^^^H||DOE^JANE\r"
)


async def _worker(store: MessageStore, worker_id: int, ops: int) -> int:
    """One coroutine doing ``ops`` enqueue+read cycles — each ``await`` is an aiosqlite round-trip."""
    channel = f"soak-{worker_id}"
    for i in range(ops):
        await store.enqueue_message(
            channel_id=channel,
            raw=_SAMPLE,
            deliveries=[("dest", _SAMPLE)],
            control_id=f"{worker_id}-{i}",
        )
        await store.list_messages(channel_id=channel, limit=10)
    return ops


async def main(concurrency: int, ops_per_worker: int) -> int:
    """Open one store on the current loop and run ``concurrency`` workers concurrently against it.

    High concurrency keeps many coroutines parked on DB futures at once, maximizing the rate at which
    aiosqlite's single worker thread must wake the loop — the condition under which a lost wakeup, if
    real, would surface.
    """
    with tempfile.TemporaryDirectory() as tmp:
        db = Path(tmp) / "soak.db"
        # Keyed cipher so the soak exercises the AES-256-GCM at-rest path too (production-like).
        store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
        try:
            started = time.monotonic()
            results = await asyncio.gather(
                *(_worker(store, w, ops_per_worker) for w in range(concurrency))
            )
            elapsed = time.monotonic() - started
        finally:
            await store.close()
    total = sum(results)
    print(
        f"SOAK OK: {total} enqueue+list cycles "
        f"({concurrency} workers x {ops_per_worker}) in {elapsed:.1f}s "
        f"on Python {sys.version.split()[0]}"
    )
    return total


if __name__ == "__main__":
    concurrency = int(sys.argv[1]) if len(sys.argv) > 1 else 48
    ops_per_worker = int(sys.argv[2]) if len(sys.argv) > 2 else 250
    asyncio.run(main(concurrency, ops_per_worker))
