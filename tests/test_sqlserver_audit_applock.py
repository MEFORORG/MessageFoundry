# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SQL Server audit append must serialize ACROSS PROCESSES — BACKLOG #1605.

``SqlServerStore.record_audit`` guards its read-tail-then-INSERT with ``self._audit_lock``, an
``asyncio.Lock`` created per store instance. Engine sharding (``serve --shard``, ADR 0037 +
ADR 0063) runs one process per shard over ONE unified store, so N shards are N unrelated locks over
one hash chain: two of them read the same prev hash and the chain forks. A forked chain makes
``verify_audit_chain`` report tampering on every later run, indistinguishable from a real tamper.

**Why this file spawns real subprocesses.** An ``asyncio.gather`` rig would run inside one
interpreter, where the in-process lock is sufficient by construction — it would pass against the
BROKEN code, which is worse than having no test. Two OS processes hold two unrelated
``asyncio.Lock`` objects and two independent connections, which is exactly the shipped
``serve --shard`` shape. Verified as a negative control: with the applock removed from
``record_audit`` this test fails on a forked chain.

**Gated**, like the rest of the server-backend suite: skipped unless ``MEFOR_TEST_SQLSERVER`` is set
(plus ``MEFOR_STORE_*`` connection env). The CI ``sql server (store + connector) 2022`` leg sets it.

Separate module from ``tests/test_sqlserver_store.py`` on purpose: that file is a single large
fixture-driven suite, and this rig needs neither its fixture nor its clean-slate table list.
"""

from __future__ import annotations

import os
import sys
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from tests._process_rig import ProcessRig

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

_REPO_ROOT = Path(__file__).resolve().parents[1]
_WORKER = _REPO_ROOT / "tests" / "_audit_append_worker.py"

#: Per shard. The vault's reproduction forked the chain in 3 of 3 runs at this depth; below roughly
#: 20 the two runs can finish without ever overlapping and the negative control stops being reliable.
_APPENDS_PER_SHARD = 60
#: Two store opens plus 120 serialized appends against a loopback server; the whole test runs in
#: about 3 seconds locally. These two budgets must SUM below the suite's 60s pytest-timeout ceiling,
#: or a wedge is killed by the harness with no message instead of failing here with one.
_BARRIER_TIMEOUT_SECONDS = 20.0
_RUN_TIMEOUT_SECONDS = 30.0


@pytest.fixture
async def clean_audit_store() -> AsyncIterator[Any]:
    """A store handle over an ``audit_log`` cleared to a clean slate.

    The handle reads the chain's state at open. A keyed chain left by another test would make
    every keyless ``record_audit`` in this module refuse, so the state is read again once the log
    is empty. A keyless handle writes nothing there.
    """
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore
    from messagefoundry.store.store import load_audit_chain

    store = await SqlServerStore.open(load_settings(environ=os.environ).store)
    await _truncate_audit(store)
    await load_audit_chain(store, read_only=False)
    yield store
    await store.close()


async def _truncate_audit(store: Any) -> None:
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("DELETE FROM audit_log")
        await conn.commit()


async def _audit_row_count(store: Any) -> int:
    async with store._pool.acquire() as conn:
        cur = await conn.cursor()
        await cur.execute("SELECT COUNT(*) FROM audit_log")
        row = await cur.fetchone()
        await conn.commit()  # close the read txn on this autocommit=False pooled connection
        return int(row[0])


async def test_two_processes_appending_audit_rows_cannot_fork_the_chain(
    clean_audit_store: Any, tmp_path: Path
) -> None:
    store = clean_audit_store
    # The rig is tests/_process_rig.py, shared with the repeat-request race (vault BACKLOG #3193
    # N5). Each worker inherits the MEFOR_STORE_* connection env this leg already runs under.
    with ProcessRig(tmp_path, "applock") as rig:
        rig.start(
            [
                [sys.executable, str(_WORKER), tag, str(_APPENDS_PER_SHARD), str(rig.go)]
                for tag in ("a", "b")
            ],
            ready_timeout=_BARRIER_TIMEOUT_SECONDS,
        )
        # Both stores are open and idle, so the table is empty AT THE MOMENT the appends start:
        # a fresh chain from prev="" is what verify_audit_chain walks.
        await _truncate_audit(store)
        rig.release("go")
        rig.finish(timeout=_RUN_TIMEOUT_SECONDS)

    # Positive control: both shards really did append, so a green verify below is not green-on-empty.
    assert await _audit_row_count(store) == 2 * _APPENDS_PER_SHARD

    ok, detail = await store.verify_audit_chain()
    assert ok, f"two shards forked the audit chain: {detail}"
