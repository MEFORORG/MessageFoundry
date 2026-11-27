# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""SQL Server error paths that may hold an applock roll back only after the cursor closes, and
through ``_rollback_or_discard`` (BACKLOG #5752, #5753).

A failed rollback can leave the transaction, and the applock it holds, open. ``_acquire`` recycles a
connection on an ordinary error, so the next borrower would inherit the lock. ``_rollback_or_discard``
discards such a connection instead, and it runs after the cursor closes so a discard cannot race the
cursor's own close. Offline: a pool-less store over recording fakes.
"""

from __future__ import annotations

from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.config.settings import StoreSettings
from messagefoundry.store.crypto import IdentityCipher
from messagefoundry.store.sqlserver import SqlServerStore


class _Boom(RuntimeError):
    pass


class _Cursor:
    """Raises on the first statement starting with ``fail_on``; answers the leading reads."""

    def __init__(self, events: list[str], fail_on: str, rows: dict[str, Any]) -> None:
        self.events = events
        self.fail_on = fail_on
        self.rows = rows
        self._last = ""

    async def execute(self, sql: str, params: Any = ()) -> None:
        self._last = sql
        if sql.startswith(self.fail_on):
            self.events.append("raise")
            raise _Boom(sql)

    async def fetchone(self) -> Any:
        for prefix, row in self.rows.items():
            if self._last.startswith(prefix):
                return row
        return None

    async def fetchall(self) -> list[Any]:
        # The attachment header insert reports one inserted row through OUTPUT.
        return [("ref",)] if self._last.startswith("INSERT INTO attachment ") else []


class _Conn:
    def __init__(self, events: list[str]) -> None:
        self.events = events

    async def commit(self) -> None:
        self.events.append("commit")

    async def rollback(self) -> None:
        self.events.append("bare-rollback")


def _store(events: list[str], cur: _Cursor) -> SqlServerStore:
    store = object.__new__(SqlServerStore)
    store._settings = StoreSettings()
    store._cipher = IdentityCipher()
    store.committed_txns = 0
    store.body_copies = 0
    store.fenced_writes = 0
    store._leader_epoch = None
    store._lease_key = None
    # complete_with_response builds its delivered event before the finalize applock, through
    # _prepare_event rather than the stubbed _event, so the verbosity gate reads this (BACKLOG #3929).
    store._message_events = "all"
    conn = _Conn(events)

    @asynccontextmanager
    async def acquire() -> AsyncIterator[_Conn]:
        yield conn

    @asynccontextmanager
    async def cursor(_conn: Any) -> AsyncIterator[_Cursor]:
        try:
            yield cur
        finally:
            events.append("cursor-closed")

    async def rollback_or_discard(_conn: Any, *, within: float | None = None) -> None:
        events.append("rollback-or-discard")

    async def noop(*_a: Any, **_k: Any) -> None:
        return None

    store._acquire = acquire  # type: ignore[method-assign]
    store._cursor = cursor  # type: ignore[method-assign,assignment]
    store._rollback_or_discard = rollback_or_discard  # type: ignore[method-assign,assignment]
    store._applock = noop  # type: ignore[method-assign]
    store._event = noop  # type: ignore[method-assign]
    store._maybe_finalize = noop  # type: ignore[method-assign]
    store._record_delivered_key = noop  # type: ignore[method-assign]
    return store


def _tail_after_raise(events: list[str]) -> list[str]:
    return events[events.index("raise") + 1 :]


async def test_complete_with_response_failure_discards_after_the_cursor_closes() -> None:
    """The MAX(response_seq) read runs under the finalize applock. Its failure must reach
    ``_rollback_or_discard`` after the cursor closes, never a bare ``conn.rollback()``. Mutations
    that must break it: restoring ``await conn.rollback()``, or moving the except back inside the
    cursor block."""
    events: list[str] = []
    cur = _Cursor(
        events,
        fail_on="SELECT COALESCE(MAX(response_seq)",
        rows={"SELECT message_id, destination_name": ("m1", "OB_X", "h1", 1, "inflight")},
    )
    store = _store(events, cur)

    with pytest.raises(_Boom):
        await store.complete_with_response("row-1", body="AA", outcome="ok", now=1.0)

    assert _tail_after_raise(events) == ["cursor-closed", "rollback-or-discard"]
    assert "bare-rollback" not in events and "commit" not in events


async def test_put_attachment_failure_discards_after_the_cursor_closes() -> None:
    """A failed chunk insert holds the attachment applock. Its rollback must run after the cursor
    closes, through ``_rollback_or_discard``. Mutation that must break it: moving the except back
    inside the cursor block."""
    events: list[str] = []
    cur = _Cursor(events, fail_on="INSERT INTO attachment_chunk", rows={})
    store = _store(events, cur)

    async def add_invocations(_n: int) -> None:
        return None

    store.add_cipher_invocations = add_invocations  # type: ignore[method-assign,assignment]

    with pytest.raises(_Boom):
        await store.put_attachment(["hello"], "text/plain")

    assert _tail_after_raise(events) == ["cursor-closed", "rollback-or-discard"]
    assert "bare-rollback" not in events
    # Only the dedup read's commit ran; the failed write committed nothing.
    assert events.count("commit") == 1 and events.index("commit") < events.index("raise")


async def test_put_attachment_dedup_hit_under_the_lock_commits_once_after_the_cursor() -> None:
    """A concurrent identical put that inserted no header commits its read and writes no chunk."""
    events: list[str] = []

    class _NoInsert(_Cursor):
        async def fetchall(self) -> list[Any]:
            return []

    cur = _NoInsert(events, fail_on="INSERT INTO attachment_chunk", rows={})
    store = _store(events, cur)

    async def add_invocations(_n: int) -> None:
        return None

    store.add_cipher_invocations = add_invocations  # type: ignore[method-assign,assignment]

    ref = await store.put_attachment(["hello"], "text/plain")

    assert len(ref) == 64
    assert "raise" not in events and "rollback-or-discard" not in events
    assert events[-2:] == ["cursor-closed", "commit"]
