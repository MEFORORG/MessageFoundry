# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5759: the Postgres on-promotion recovery carries the fail-closed claim guard on the
held epoch, so a node that stalled between its in-memory leader check and the write cannot
re-pend a successor's live rows.

Ungated: the write is captured from a stand-in connection, so no database is needed. The live
behaviour is ``test_a_stale_promotion_recovery_spares_the_successors_rows`` in
``tests/test_adr0157_postgres_fence.py``, gated on ``MEFOR_TEST_POSTGRES``.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

from messagefoundry.store import OutboxStatus
from messagefoundry.store.postgres import _EPOCH_GUARD_CLAIM, PostgresStore

_KEY = "public:mefor_cluster_leader"


class _Conn:
    def __init__(self) -> None:
        self.calls: list[tuple[str, tuple[Any, ...]]] = []

    @asynccontextmanager
    async def transaction(self) -> AsyncIterator[None]:
        yield

    async def execute(self, sql: str, *args: Any) -> str:
        self.calls.append((sql, args))
        return "UPDATE 0"


def _store(epoch: int | None) -> tuple[PostgresStore, _Conn]:
    store = object.__new__(PostgresStore)
    conn = _Conn()

    @asynccontextmanager
    async def acquire(*, record: bool = True) -> AsyncIterator[_Conn]:
        yield conn

    store._timed_acquire = acquire  # type: ignore[method-assign]
    store._owner = "me"
    store._leader_epoch = epoch
    store._lease_key = _KEY if epoch is not None else None
    return store, conn


async def test_an_armed_epoch_fences_the_recovery() -> None:
    """Before the fix the write carried no guard, so a stale node's recovery matched a successor's
    rows."""
    store, conn = _store(5)
    await store.recover_inflight_on_promotion(now=1.0)
    [(sql, args)] = conn.calls
    assert sql.endswith(_EPOCH_GUARD_CLAIM.format(k=5, h=6))
    assert args == (OutboxStatus.PENDING.value, 1.0, OutboxStatus.INFLIGHT.value, "me", _KEY, 5)


async def test_no_epoch_leaves_the_recovery_unfenced() -> None:
    """With no epoch armed the statement is the one it was before the fix."""
    store, conn = _store(None)
    await store.recover_inflight_on_promotion(now=1.0)
    [(sql, args)] = conn.calls
    assert "leader_lease" not in sql
    assert sql.endswith("WHERE status=$3 AND owner IS DISTINCT FROM $4")
    assert args == (OutboxStatus.PENDING.value, 1.0, OutboxStatus.INFLIGHT.value, "me")
