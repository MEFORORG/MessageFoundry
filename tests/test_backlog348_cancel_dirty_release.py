# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""BACKLOG #348 / ADR 0159 — a cancelled store call must never hand the next borrower a pooled SQL
Server connection that is still MID-TRANSACTION.

``asyncio.CancelledError`` derives from ``BaseException``, so the store's house idiom
(``except Exception: await conn.rollback(); raise`` — 90 of the 91 ``_acquire()`` sites) never runs
its rollback on a cancellation. Nothing downstream compensates: aioodbc's ``Pool.release()`` appends
the connection straight back onto the free deque with no rollback, no reset and no transaction check
(aioodbc 0.5.0 ``pool.py:196-205``), and ``_ContextManager.__aexit__`` releases identically on the
exception path (``utils.py:60-62``, ``:90-103``). The next borrower then inherits an open transaction
still holding X locks on ``queue`` rows; a claimer that blocks on them under ``SET LOCK_TIMEOUT 0``
(ADR 0066 §9) raises error 1222, which the claim path translates into a *silent* EMPTY-all yield.

Measured against a live SQL Server BEFORE the fix: cancelling ``release_claimed`` left 7 KEY X locks
on ``queue``, the connection went back onto the pool's free list, an independent ``claim_fifo_heads``
returned EMPTY-all, and a raw writer got 1222. ``mark_done`` (9 locks) and ``enqueue_ingress`` (11)
leaked identically — this is the file's dominant idiom, not a two-method slip.

NOT a claim_fifo_heads analogue. That method's shielded finally is a ``SET LOCK_TIMEOUT`` *reset*
guard, not a rollback guard: ADR 0114 §2 states there is **no rollback** on its cancellation path and
``test_adr0114_claim_fold.py::test_ac3_cancellation_at_body_await_no_rollback_guard_runs`` freezes
that. It ends on a clean boundary only because the guard COMMITS.

The fake pool below mirrors aioodbc's REAL release rule (``if not conn.closed: free.append(conn)``),
so these tests assert the contract that actually matters — *can the next borrower be handed this
connection?* — rather than an implementation detail of how it was made safe.
"""

from __future__ import annotations

import asyncio
import types
from contextlib import asynccontextmanager
from typing import Any

import pytest

from messagefoundry.store.pool_metrics import AcquireWaitHistogram
from messagefoundry.store.sqlserver import SqlServerStore

# The three methods are deliberately NOT the two the original lead named: mark_done is included to
# pin that the guarantee is a property of the _acquire chokepoint, not of two patched call sites.
_METHODS: list[tuple[str, dict[str, Any]]] = [
    ("release_claimed", {"ids": ["row-1"], "now": 100.0}),
    ("reschedule_claimed", {"ids": ["row-1"], "next_attempt_at": 900.0, "now": 100.0}),
    ("mark_done", {"outbox_id": "row-1", "now": 100.0}),
]


class _RawConn:
    """Stands in for the underlying ``pyodbc.Connection`` that aioodbc wraps as ``conn._conn``.

    ``close()`` is synchronous and blocking, exactly like pyodbc's — the store must therefore not
    perform it inline on the event loop.
    """

    def __init__(self, ops: list[str]) -> None:
        self.ops = ops
        self.timeout = 0
        self.closed = False
        self.release_close = None  # type: Any

    def close(self) -> None:
        if self.release_close is not None:
            self.release_close.wait()  # a threading.Event — hold the close open mid-flight
        self.ops.append("raw.close")
        self.closed = True


class _FakeConn:
    """An aioodbc-shaped connection. ``closed`` is derived from ``_conn`` exactly as aioodbc's is."""

    def __init__(self, ops: list[str], *, gate: asyncio.Event | None = None) -> None:
        self.ops = ops
        self._conn: _RawConn | None = _RawConn(ops)
        self._gate = gate
        self.cursor_obj = _GatedCursor(ops, gate)

    @property
    def closed(self) -> bool:
        return self._conn is None

    async def cursor(self) -> _GatedCursor:
        return self.cursor_obj

    async def commit(self) -> None:
        self.ops.append("commit")

    async def rollback(self) -> None:
        self.ops.append("rollback")


class _GatedCursor:
    def __init__(self, ops: list[str], gate: asyncio.Event | None) -> None:
        self.ops = ops
        self._gate = gate
        self.description = None

    async def execute(self, sql: str, params: object = None) -> None:
        self.ops.append("execute")
        if self._gate is not None:
            await self._gate.wait()  # suspend inside the method body; the test cancels here

    async def fetchall(self) -> list[object]:
        return []

    async def fetchone(self) -> object | None:
        # mark_done SELECTs first; None makes it commit-and-return without the event/finalize path.
        return None

    async def close(self) -> None:
        self.ops.append("cursor.close")


class _FakePool:
    """aioodbc's pool semantics, verbatim on the point that matters: a released connection rejoins
    the FREE list — and so becomes lendable to the next borrower — only when it is not ``closed``
    (aioodbc 0.5.0 ``pool.py:200-204``)."""

    def __init__(self, conn: _FakeConn, ops: list[str]) -> None:
        self._conn = conn
        self.ops = ops
        self.free: list[_FakeConn] = []

    def acquire(self) -> Any:
        conn = self._conn
        ops = self.ops
        free = self.free

        @asynccontextmanager
        async def _cm() -> Any:
            try:
                yield conn
            finally:
                ops.append("release")
                if not conn.closed:
                    free.append(conn)  # lendable again

        return _cm()


def _make_store(conn: _FakeConn, ops: list[str]) -> SqlServerStore:
    store = SqlServerStore.__new__(SqlServerStore)
    store._pool = _FakePool(conn, ops)  # type: ignore[assignment]
    store._settings = types.SimpleNamespace(command_timeout=0)  # type: ignore[assignment]
    store._acquire_wait = AcquireWaitHistogram()
    store.committed_txns = 0
    store.body_copies = 0
    return store


async def _cancel_inside(
    store: SqlServerStore, method: str, kwargs: dict[str, Any]
) -> asyncio.Task:
    """Drive ``method`` until it suspends inside its body, then cancel it there."""
    task: asyncio.Task = asyncio.create_task(getattr(store, method)(**kwargs))
    for _ in range(200):  # let the task reach the gated execute
        await asyncio.sleep(0)
        if "execute" in store._pool.ops:  # type: ignore[attr-defined]
            break
    assert "execute" in store._pool.ops, "never reached the gated execute"  # type: ignore[attr-defined]
    task.cancel()
    return task


@pytest.mark.parametrize(("method", "kwargs"), _METHODS, ids=[m for m, _ in _METHODS])
async def test_cancelled_call_never_returns_a_dirty_connection_to_the_pool(
    method: str, kwargs: dict[str, Any]
) -> None:
    """THE regression gate. Unpatched this fails on every arm: the body's ``except Exception`` does
    not see CancelledError, so no rollback runs and the connection rejoins the free list holding its
    X locks."""
    ops: list[str] = []
    conn = _FakeConn(ops, gate=asyncio.Event())
    store = _make_store(conn, ops)
    pool = store._pool  # type: ignore[attr-defined]

    task = await _cancel_inside(store, method, kwargs)
    with pytest.raises(asyncio.CancelledError):
        await task

    assert pool.free == [], (
        f"{method}: a cancelled call returned the connection to the pool's free list while its"
        f" transaction was still open — the next borrower inherits its X locks (ops={ops})"
    )
    assert conn.closed, f"{method}: the poisoned connection was not quarantined (ops={ops})"


@pytest.mark.parametrize(("method", "kwargs"), _METHODS, ids=[m for m, _ in _METHODS])
async def test_second_cancellation_cannot_defeat_the_quarantine(
    method: str, kwargs: dict[str, Any]
) -> None:
    """A cleanup that *awaits* before making the connection unlendable is defeated by a second
    cancellation — shutdown cancels, then the gather cancels again — and would silently restore the
    original bug while the single-cancel gate above stayed green. So the quarantine must be
    established with NO await in front of it."""
    import threading

    ops: list[str] = []
    conn = _FakeConn(ops, gate=asyncio.Event())
    assert conn._conn is not None
    hold = threading.Event()
    conn._conn.release_close = hold  # block the raw close mid-flight
    store = _make_store(conn, ops)
    pool = store._pool  # type: ignore[attr-defined]

    task = await _cancel_inside(store, method, kwargs)
    for _ in range(50):  # let the cleanup start while the raw close is held open
        await asyncio.sleep(0)
    task.cancel()  # the SECOND cancellation, landing during cleanup
    hold.set()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert pool.free == [], (
        f"{method}: a second cancellation let the connection back into the pool mid-transaction"
        f" (ops={ops})"
    )


@pytest.mark.parametrize(("method", "kwargs"), _METHODS, ids=[m for m, _ in _METHODS])
async def test_ordinary_exception_still_rolls_back_and_recycles(
    method: str, kwargs: dict[str, Any]
) -> None:
    """The non-vacuous control. An ordinary error must keep today's behaviour — the body rolls back
    and the connection is RECYCLED, not discarded — so the gate above cannot be satisfied by
    blanket-discarding on every exit."""
    ops: list[str] = []
    conn = _FakeConn(ops, gate=None)
    store = _make_store(conn, ops)
    pool = store._pool  # type: ignore[attr-defined]

    async def boom(sql: str, params: object = None) -> None:
        ops.append("execute")
        raise RuntimeError("execute boom")

    conn.cursor_obj.execute = boom  # type: ignore[assignment]

    with pytest.raises(RuntimeError, match="execute boom"):
        await getattr(store, method)(**kwargs)

    assert "rollback" in ops, f"{method}: the ordinary-error rollback regressed (ops={ops})"
    assert pool.free == [conn], (
        f"{method}: an ordinary error must not discard the connection — only a cancellation, which"
        f" leaves it mid-transaction, does (ops={ops})"
    )
    assert not conn.closed


@pytest.mark.parametrize(("method", "kwargs"), _METHODS, ids=[m for m, _ in _METHODS])
async def test_success_path_unchanged(method: str, kwargs: dict[str, Any]) -> None:
    """The happy path must still commit and recycle the connection untouched."""
    ops: list[str] = []
    conn = _FakeConn(ops, gate=None)
    store = _make_store(conn, ops)
    pool = store._pool  # type: ignore[attr-defined]

    await getattr(store, method)(**kwargs)

    assert "commit" in ops
    assert "rollback" not in ops
    assert pool.free == [conn]
    assert not conn.closed
