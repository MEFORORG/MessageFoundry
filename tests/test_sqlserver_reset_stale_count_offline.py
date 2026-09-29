# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #2097: SQL Server ``reset_stale_inflight`` counts re-pended rows from its OUTPUT rowset.

**Deliberately NOT env-gated**, so it runs everywhere. The fake cursor reports ``rowcount`` as ``-1``,
the DB-API "not reported" value that a session-wide ``SET NOCOUNT ON`` produces. The hosted SQL
Server legs once saw the old code sum that into ``-4`` (one ``-1`` per stage). Mutation: put
``recovered += cur.rowcount`` back in either branch and the matching test here fails.

Whether a pooled session can carry NOCOUNT at all is a separate, live reading. That probe is
``test_backlog_2097_nocount_persistence_probe`` in ``tests/test_sqlserver_store.py``.
"""

from __future__ import annotations

from messagefoundry.store import Stage
from messagefoundry.store.store import OwnedLanes
from tests.test_adr0157_sqlserver_fence_offline import _Conn, _Cursor, _store, _updates


async def test_the_unscoped_reset_counts_the_output_rowset_not_rowcount() -> None:
    cur, conn = _Cursor(matched=2), _Conn()
    store, _ = _store(cur, conn, epoch=None)

    assert await store.reset_stale_inflight(now=1.0) == 2 * len(Stage)

    updates = _updates(cur)
    assert len(updates) == len(Stage)
    assert all(" OUTPUT inserted.id WHERE status=? AND stage=?" in sql for sql, _ in updates)
    assert conn.commits == 1 and conn.rollbacks == 0


async def test_a_reset_that_matches_nothing_returns_zero() -> None:
    """The case the hosted legs hit: under NOCOUNT the old code read ``-1`` here, and ``-4`` is truthy,
    so a reload would have logged "re-pended -4 row(s)"."""
    store, _ = _store(_Cursor(matched=0), _Conn(), epoch=None)

    assert await store.reset_stale_inflight(now=1.0) == 0


async def test_the_ownership_scoped_reset_counts_every_chunk() -> None:
    """One statement per stage whose owned set is non-empty. The outbound stage keys on destinations,
    every other stage on channels, so an empty destination set emits no outbound statement."""
    cur, conn = _Cursor(matched=3), _Conn()
    store, _ = _store(cur, conn, epoch=None)
    owned = OwnedLanes(channels=frozenset({"IB1", "IB2"}), destinations=frozenset())

    recovered = await store.reset_stale_inflight(now=1.0, owned=owned)

    updates = _updates(cur)
    assert len(updates) == len(Stage) - 1
    assert recovered == 3 * len(updates)
    assert all(" OUTPUT inserted.id WHERE " in sql and " IN (?,?)" in sql for sql, _ in updates)
