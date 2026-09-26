# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Inc 3 gate probe (BACKLOG #1497): does a coroutine cancelled mid-``execute`` inside a SQL
Server store transaction leave that transaction COMMITTED or ROLLED BACK?

**This file is a MEASUREMENT, not a regression suite.** ADR 0157 Inc 3 (epoch fences on SQL Server
``claim_ready`` and the terminal resolves) is gated on that one question, and the ADR says to pin it on
the live CI leg rather than build on a guess. Every test prints its readings as::

    ADR0157-INC3-PROBE <case>.<subject>: <COMMITTED|ROLLED_BACK|LEAKED_OPEN_TXN|...> (details)

to the REAL stderr (``capsys.disabled()``, so it shows without ``-s``) and repeats them in the
assertion message, so the CI log answers the question whether the test passes or fails. Each case
also prints an ``ARMED`` line just before it cancels. **An ARMED line with no ``.write`` line after it
means the process died inside the cancel** -- read it as a reading, not as noise. The CI step runs
under ``retry-native-crash.sh``, which re-runs the whole step on a native crash, so look for this in
every attempt the log shows, not only the last.

**What reading the store already says, and where it stops.** The house idiom's ``except Exception:
await conn.rollback()`` never sees a ``CancelledError``. The ``_acquire`` chokepoint does (``except
BaseException``, BACKLOG #348 / ADR 0159): it drops the pooled connection's raw handle so aioodbc's
``Pool.release`` cannot re-lend it, then closes the raw pyodbc handle off-loop, bounded at
``_DIRTY_CLOSE_TIMEOUT``. pyodbc's ``close()`` rolls back an ``autocommit=False`` connection before it
disconnects. So by reading, for a method on the house idiom the answer is ROLLED_BACK, with the
abandoned transaction's locks held until that close lands. Reading cannot settle three things:

1. whether the close really rolls back while the abandoned statement is still running on the store's
   executor thread (aioodbc cannot interrupt it, so the close races it);
2. how long the abandoned transaction keeps its locks, and whether the cancelled task can finish
   unwinding before the in-flight statement ends;
3. whether a statement that completes server-side AFTER the cancel can end up committed.

**The reading is scoped to the house idiom, and one claim path is NOT on it.** ``claim_fifo_heads``
runs a shielded ``SET LOCK_TIMEOUT -1`` + ``_commit`` in its ``finally`` and waits for it on
cancellation (ADR 0114 §2). A cancel there COMMITS whatever its claim statement had done. Nothing in
this file measures that path, and nothing here should be quoted as covering it.

**The cases, one test each.** All three run the store's REAL transaction path (``_acquire`` ->
``_cursor`` -> execute -> ``_commit`` / ``except Exception: rollback``). The store's pool is sized to
ONE connection, so "what does the next borrower get" has exactly one candidate. The observer and the
blockers borrow from a SECOND store's pool, the proven shape for outside sessions in this suite.

* ``house_idiom_waitfor`` -- the store's own idiom, driven directly: a write, then ``WAITFOR DELAY``,
  cancelled while the WAITFOR runs.
* ``mark_done_blocked_on_finalize_applock`` -- a real terminal resolve. An outside session holds the
  per-message finalize applock, so ``mark_done`` blocks inside ``sp_getapplock`` AFTER its DONE flip.
* ``claim_ready_blocked_then_completes`` -- a real ``claim_ready``. An outside session holds a table
  lock on ``queue`` (``READPAST`` skips row locks, not a table lock), so the claim UPDATE is queued at
  cancel time and can only run after the cancel, once the outside lock is released.

**Gated** like the rest of the server-backend suite: skipped unless ``MEFOR_TEST_SQLSERVER`` is set
(plus ``MEFOR_STORE_*`` connection env). CI runs it in the ``sqlserver-store`` job's catch-all step.
"""

from __future__ import annotations

import asyncio
import os
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from time import monotonic
from typing import Any
from uuid import uuid4

import pytest

pytestmark = [
    pytest.mark.skipif(
        not os.getenv("MEFOR_TEST_SQLSERVER"),
        reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
    ),
    # Two store opens, a bounded arm, a bounded settle and a bounded teardown. Every wait below is
    # bounded, and their worst-case sum stays under this, so a wedge fails with a reading instead of
    # reaching this kill, which prints none.
    pytest.mark.timeout(180),
]

# A synthetic ADT header -- never real PHI.
RAW = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"

#: The in-flight statement in the house-idiom case.
_WAITFOR_S = 4
_WAITFOR = f"WAITFOR DELAY '00:00:0{_WAITFOR_S}'"
#: How long an outside lock is held after the cancel before it is released.
_HOLD_AFTER_CANCEL_S = 1.5
#: Bound on the cancelled task finishing its unwind once nothing blocks it. Covers the rest of an
#: in-flight statement plus the store's own 5s bounded dirty close.
_TASK_SETTLE_S = 15.0
#: Bound on the abandoned transaction ending, measured from the moment watching starts.
_RESOLVE_DEADLINE_S = 15.0
#: Bound on reaching the armed state (the write done, the victim waiting where the case says).
_ARM_DEADLINE_S = 10.0
#: The house-idiom write marker. A committed write leaves attempts at or above it.
_ATTEMPTS_MARK = 1000
#: Bound on the next borrower getting a connection, shorter than the store's own acquire_timeout.
_BORROW_S = 10.0

_LOCKED = "LOCKED"
#: SQL Server native errors that mean "this login may not read that DMV": 297 (no permission for
#: the action) and 300 (VIEW SERVER STATE denied). Only these switch the probe to lock reads alone;
#: any other DMV error is a transient reading and the watch keeps polling.
_DMV_DENIED = ("(297)", "(300)")


def _emit(capsys: pytest.CaptureFixture[str], line: str) -> str:
    """Write a probe line to the real stderr, past pytest's capture, and return it for assertions."""
    with capsys.disabled():
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    return line


async def _exec(conn: Any, sql: str, params: tuple[Any, ...] = (), *, fetch: bool = False) -> Any:
    cur = await conn.cursor()
    try:
        await cur.execute(sql, params)
        return await cur.fetchone() if fetch else None
    finally:
        await cur.close()


async def _open_store(pool_size: int) -> Any:
    from messagefoundry.config.settings import load_settings
    from messagefoundry.store.sqlserver import SqlServerStore

    settings = load_settings(environ=os.environ).store.model_copy(update={"pool_size": pool_size})
    return await SqlServerStore.open(settings)


async def _close_store(store: Any, capsys: pytest.CaptureFixture[str], name: str) -> None:
    # Bounded: a task still holding the pool's one connection would park wait_closed() for good.
    try:
        await asyncio.wait_for(store.close(), timeout=20.0)
    except TimeoutError:
        _emit(capsys, f"ADR0157-INC3-PROBE teardown: {name}.close() did not finish in 20s")


@pytest.fixture
async def probe_store(capsys: pytest.CaptureFixture[str]) -> AsyncIterator[Any]:
    """The store under test. ONE pooled connection, so the victim's successor is unambiguous."""
    store = await _open_store(1)
    try:
        yield store
    finally:
        await _close_store(store, capsys, "probe_store")


@pytest.fixture
async def outside_store(capsys: pytest.CaptureFixture[str]) -> AsyncIterator[Any]:
    """A second store whose pool supplies the observer and blocker sessions."""
    store = await _open_store(3)
    try:
        yield store
    finally:
        await _close_store(store, capsys, "outside_store")


async def _borrow_outside(outside: Any, lock_timeout_ms: int) -> Any:
    conn = await outside._pool.acquire()
    await _exec(conn, f"SET LOCK_TIMEOUT {int(lock_timeout_ms)}")
    await conn.commit()
    return conn


async def _return_outside(outside: Any, conn: Any) -> None:
    """Roll back, restore the session default, and hand the connection back to its pool."""
    try:
        await conn.rollback()
        await _exec(conn, "SET LOCK_TIMEOUT -1")
        await conn.commit()
    finally:
        await outside._pool.release(conn)


@pytest.fixture
async def observer(outside_store: Any) -> AsyncIterator[Any]:
    """An outside session that never waits on a lock: a held lock reads as error 1222, not a stall."""
    conn = await _borrow_outside(outside_store, 0)
    try:
        yield conn
    finally:
        await _return_outside(outside_store, conn)


@pytest.fixture
async def cleanup(
    outside_store: Any, capsys: pytest.CaptureFixture[str]
) -> AsyncIterator[list[str]]:
    """Remove the probe's rows afterwards, so a later step on the same database never claims them."""
    message_ids: list[str] = []
    yield message_ids
    if not message_ids:
        return
    # Short: if a case leaked, these rows are still locked and the reading is already printed.
    conn = await _borrow_outside(outside_store, 2000)
    try:
        for mid in message_ids:
            for sql in (
                "DELETE FROM delivered_keys WHERE message_id=?",
                "DELETE FROM message_events WHERE message_id=?",
                "DELETE FROM queue WHERE message_id=?",
                "DELETE FROM messages WHERE id=?",
            ):
                try:
                    await _exec(conn, sql, (mid,))
                except Exception as exc:  # noqa: BLE001 - best-effort cleanup must not mask it
                    _emit(capsys, f"ADR0157-INC3-PROBE cleanup: {sql!r} failed: {exc}")
        await conn.commit()
    finally:
        await _return_outside(outside_store, conn)


async def _read_row(observer: Any, row_id: str) -> Any:
    """``(status, attempts)`` as committed, ``None`` if absent, or ``_LOCKED`` if a transaction still
    holds the row. ``READCOMMITTEDLOCK`` forces a locking read even under RCSI, so an uncommitted writer
    shows as a lock rather than hiding behind its row version."""
    from messagefoundry.store.sqlserver import _is_lock_timeout

    try:
        row = await _exec(
            observer,
            "SELECT status, attempts FROM queue WITH (READCOMMITTEDLOCK) WHERE id=?",
            (row_id,),
            fetch=True,
        )
    except Exception as exc:
        if _is_lock_timeout(exc):
            return _LOCKED
        raise
    finally:
        await observer.rollback()
    return None if row is None else (row[0], int(row[1]))


@dataclass
class _Victim:
    """One DMV read of the victim session. Needs VIEW SERVER STATE (the CI leg runs as sa). A denied
    permission sets ``available`` False and the probe falls back to lock reads alone. Any other DMV
    error sets ``error`` and is never read as "the transaction is over"."""

    available: bool
    error: bool = False
    gone: bool = False
    open_txn: int = 0
    request: str | None = None
    wait: str | None = None
    text: str = ""

    @property
    def txn_open(self) -> bool:
        return self.available and not self.error and not self.gone and self.open_txn > 0

    @property
    def settled(self) -> bool:
        """Gone, or present with no open transaction AND no statement still running."""
        if not self.available or self.error:
            return False
        return self.gone or (self.open_txn == 0 and self.request is None)


@dataclass(frozen=True)
class _Ident:
    """The victim session. ``login_time`` pins it, so a reused session id is never read as the victim."""

    spid: int
    login_time: str | None


async def _victim(observer: Any, ident: _Ident) -> _Victim:
    sql = (
        "SELECT s.open_transaction_count, r.status, r.wait_type"
        " FROM sys.dm_exec_sessions s"
        " LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id"
        " WHERE s.session_id = ?"
    )
    params: tuple[Any, ...] = (ident.spid,)
    if ident.login_time is not None:
        # Compared as text on both sides. A datetime parameter against the datetime column would
        # be widened to datetime2 under compat >= 130 (.003 -> .0033333) and never match, which
        # would read a live victim as gone.
        sql += " AND CONVERT(varchar(30), s.login_time, 126) = ?"
        params = (ident.spid, ident.login_time)
    try:
        row = await _exec(observer, sql, params, fetch=True)
    except Exception as exc:  # noqa: BLE001 - a DMV failure is a reading, not a test failure
        if any(code in str(exc) for code in _DMV_DENIED):
            return _Victim(available=False, text=f"n/a(denied:{type(exc).__name__})")
        return _Victim(available=True, error=True, text=f"error({type(exc).__name__}: {exc})")
    finally:
        await observer.rollback()
    if row is None:
        return _Victim(available=True, gone=True, text="session_gone")
    v = _Victim(available=True, open_txn=int(row[0]), request=row[1], wait=row[2])
    v.text = f"open_txn={v.open_txn} request={v.request} wait={v.wait}"
    return v


async def _identify(cur: Any) -> _Ident:
    """Run ON the victim connection. A session can always read its own row of dm_exec_sessions, so
    this needs no permission."""
    await cur.execute(
        "SELECT @@SPID, (SELECT CONVERT(varchar(30), login_time, 126)"
        " FROM sys.dm_exec_sessions WHERE session_id = @@SPID)"
    )
    row = await cur.fetchone()
    return _Ident(spid=int(row[0]), login_time=row[1])


async def _queue_update_ops(observer: Any) -> int | None:
    """Cumulative leaf-level update operations on every ``queue`` index. These counters are not
    transactional, so an UPDATE that ran and was then rolled back still moves them, and a statement
    that never ran does not. ``None`` when the login may not read the DMV."""
    try:
        row = await _exec(
            observer,
            "SELECT SUM(leaf_update_count)"
            " FROM sys.dm_db_index_operational_stats(DB_ID(), OBJECT_ID('queue'), NULL, NULL)",
            fetch=True,
        )
    except Exception:  # noqa: BLE001 - evidence only; its absence is reported as UNPROVEN
        return None
    finally:
        await observer.rollback()
    return None if row is None or row[0] is None else int(row[0])


async def _await_row_locked(observer: Any, row_id: str) -> bool:
    t0 = monotonic()
    while monotonic() - t0 < _ARM_DEADLINE_S:
        if await _read_row(observer, row_id) == _LOCKED:
            return True
        await asyncio.sleep(0.05)
    return False


async def _await_lock_wait(observer: Any, ident: _Ident) -> str:
    """Wait until the victim is parked on a lock (``LCK_M_*``). Without DMV access, fall back to a
    fixed pause and say so, so the reading is never mistaken for a verified one."""
    t0 = monotonic()
    while monotonic() - t0 < _ARM_DEADLINE_S:
        v = await _victim(observer, ident)
        if not v.available:
            await asyncio.sleep(1.0)
            return f"UNVERIFIED({v.text}, paused 1s)"
        if v.wait and v.wait.startswith("LCK_M"):
            return f"dmv:{v.wait}"
        await asyncio.sleep(0.05)
    return "NOT_BLOCKED"


async def _borrow_ident(store: Any) -> tuple[Any, _Ident]:
    """Borrow the pool's one connection and identify its session."""
    async with store._acquire() as conn, store._cursor(conn) as cur:
        ident = await _identify(cur)
        await store._commit_read(conn)
    return conn, ident


def _spy_quarantine(store: Any) -> list[Any]:
    """Record every connection the store quarantines (ADR 0159), without changing what it does."""
    seen: list[Any] = []
    real: Callable[[Any], Awaitable[None]] = store._release_dirty

    async def _spy(conn: Any) -> None:
        seen.append(conn)
        await real(conn)

    setattr(store, "_release_dirty", _spy)  # noqa: B010 - instance shadow, on purpose
    return seen


async def _enqueue(store: Any, cleanup: list[str]) -> tuple[str, str, str]:
    tag = uuid4().hex[:10]
    dest = f"OB_PROBE_{tag}"
    mid = await store.enqueue_message(
        channel_id=f"IB_PROBE_{tag}", raw=RAW, deliveries=[(dest, "p")], now=100.0
    )
    cleanup.append(mid)
    rows = await store.outbox_for(mid)
    assert len(rows) == 1, rows
    return mid, dest, str(rows[0]["id"])


@dataclass
class _Reading:
    """Everything observed from the cancel onward. Times are seconds from the first cancel."""

    t_cancel: float
    state: str = "HUNG"
    recancelled: bool = False
    unwind_s: float | None = None
    done_before_release: bool | None = None
    victim_at_release: str = "-"
    seen: Any = None
    resolved: bool = False
    locks_released_s: float | None = None
    lock_seen_while_watching: bool = False
    victim_after: _Victim = field(default_factory=lambda: _Victim(available=False))


async def _watch(
    reading: _Reading, observer: Any, row_id: str, ident: _Ident, task: asyncio.Task[Any]
) -> None:
    """Poll until the abandoned transaction is over: the task is done, the row is not locked, and the
    victim session is gone or idle with no open transaction. Without DMV access, a lock-free read held
    for one second stands in for the last condition. A first unlocked read is never enough on its own:
    a statement released after the cancel may not have taken its lock yet."""
    t0 = monotonic()
    quiet_since: float | None = None
    while True:
        seen = await _read_row(observer, row_id)
        now = monotonic()
        if seen == _LOCKED:
            reading.lock_seen_while_watching = True
            quiet_since = None
        elif task.done():
            v = await _victim(observer, ident)
            if v.settled:
                reading.seen, reading.victim_after, reading.resolved = seen, v, True
                reading.locks_released_s = now - reading.t_cancel
                return
            if not v.available:
                quiet_since = quiet_since or now
                if now - quiet_since >= 1.0:
                    reading.seen, reading.victim_after, reading.resolved = seen, v, True
                    reading.locks_released_s = quiet_since - reading.t_cancel
                    return
        if now - t0 > _RESOLVE_DEADLINE_S:
            reading.seen = seen
            reading.victim_after = await _victim(observer, ident)
            return
        await asyncio.sleep(0.005)


async def _cancel_and_watch(
    task: asyncio.Task[Any],
    observer: Any,
    row_id: str,
    ident: _Ident,
    release: Callable[[], Awaitable[None]] | None,
) -> _Reading:
    """Cancel, hold any outside lock a little longer, release it, then watch the abandoned
    transaction end while the task settles. Every wait is bounded."""
    done_at: list[float] = []
    task.add_done_callback(lambda _t: done_at.append(monotonic()))
    task.cancel()
    reading = _Reading(t_cancel=monotonic())
    if release is not None:
        early, _ = await asyncio.wait({task}, timeout=_HOLD_AFTER_CANCEL_S)
        reading.done_before_release = bool(early)
        reading.victim_at_release = (await _victim(observer, ident)).text
        await release()
    watcher = asyncio.create_task(_watch(reading, observer, row_id, ident, task))
    await asyncio.wait({task}, timeout=_TASK_SETTLE_S)
    if not task.done():
        # Contain it, so teardown is not parked behind it. Recorded: a task that needed a second
        # cancel did not honour the first, and must never read as a clean CANCELLED.
        reading.recancelled = True
        task.cancel()
        await asyncio.wait({task}, timeout=5.0)
    await watcher
    if done_at:
        reading.unwind_s = done_at[0] - reading.t_cancel
        if task.cancelled():
            reading.state = "CANCELLED_AFTER_RECANCEL" if reading.recancelled else "CANCELLED"
        else:
            exc = task.exception()
            reading.state = "RETURNED" if exc is None else f"RAISED:{type(exc).__name__}:{exc}"
    return reading


def _classify_write(
    r: _Reading, *, committed: Callable[[Any], bool], rolled_back: Callable[[Any], bool]
) -> str:
    if r.seen == _LOCKED or r.victim_after.txn_open:
        return "LEAKED_OPEN_TXN"
    if not r.resolved:
        return "UNRESOLVED"
    if r.seen is None:
        return "ROW_MISSING"
    if committed(r.seen):
        return "COMMITTED"
    if rolled_back(r.seen):
        return "ROLLED_BACK"
    return f"UNEXPECTED{r.seen!r}"


async def _next_borrower(store: Any, victim_conn: Any, reading: _Reading) -> tuple[str, str]:
    """What the pool hands the next caller after the cancellation. An open transaction there is the
    leak: that borrower's own COMMIT would commit the abandoned write, so it is rolled back here."""
    if reading.state == "HUNG":
        return "NOT_RUN", "the cancelled task still holds the pool's only connection"

    async def _borrow() -> tuple[int, int, bool]:
        async with store._acquire() as conn, store._cursor(conn) as cur:
            await cur.execute("SELECT @@SPID, @@TRANCOUNT")
            row = await cur.fetchone()
            if int(row[1]):
                await conn.rollback()
            else:
                await store._commit_read(conn)
            return int(row[0]), int(row[1]), conn is victim_conn

    try:
        spid, trancount, same = await asyncio.wait_for(_borrow(), timeout=_BORROW_S)
    except Exception as exc:  # noqa: BLE001 - e.g. HY000 busy on a re-lent connection; a reading
        return f"BORROWER_ERROR:{type(exc).__name__}", str(exc)
    if trancount:
        outcome = "LEAKED_OPEN_TXN"
    elif same:
        outcome = "REUSED_SAME_CONNECTION_CLEAN"
    else:
        outcome = "FRESH_CONNECTION"
    pool = store._pool
    return outcome, f"spid={spid} trancount={trancount} pool_size={pool.size} free={pool.freesize}"


def _fmt_s(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}s"


async def _report(
    capsys: pytest.CaptureFixture[str],
    case: str,
    store: Any,
    victim_conn: Any,
    quarantined: list[Any],
    reading: _Reading,
    *,
    write: str,
    safe: frozenset[str] = frozenset({"ROLLED_BACK"}),
    extra: str = "",
) -> None:
    """Print the two readings for a case, then assert the safe outcome with both lines attached."""
    quarantine = any(q is victim_conn for q in quarantined)
    line_w = _emit(
        capsys,
        f"ADR0157-INC3-PROBE {case}.write: {write} (task={reading.state}"
        f" unwind={_fmt_s(reading.unwind_s)} done_before_release={reading.done_before_release}"
        f" victim_at_release=[{reading.victim_at_release}]"
        f" locks_released_after_cancel={_fmt_s(reading.locks_released_s)}"
        f" lock_seen_while_watching={reading.lock_seen_while_watching}"
        f" seen={reading.seen!r} quarantined={quarantine}"
        f" victim_after=[{reading.victim_after.text}]{extra})",
    )
    borrower, detail = await _next_borrower(store, victim_conn, reading)
    line_b = _emit(capsys, f"ADR0157-INC3-PROBE {case}.next_borrower: {borrower} ({detail})")
    lines = f"{line_w}\n{line_b}"
    assert reading.state == "CANCELLED", lines
    assert write in safe, lines
    assert borrower in {"FRESH_CONNECTION", "REUSED_SAME_CONNECTION_CLEAN"}, lines


async def test_adr0157_inc3_probe_house_idiom_waitfor(
    probe_store: Any,
    observer: Any,
    cleanup: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = "house_idiom_waitfor"
    store = probe_store
    _, _, row_id = await _enqueue(store, cleanup)
    quarantined = _spy_quarantine(store)
    victim: dict[str, Any] = {}
    written = asyncio.Event()

    async def _body() -> None:
        # The store's own transaction idiom, statement for statement, through its own chokepoints.
        async with store._acquire() as conn, store._cursor(conn) as cur:
            try:
                victim["ident"] = await _identify(cur)
                victim["conn"] = conn
                await cur.execute(
                    "UPDATE queue SET attempts = attempts + ? WHERE id = ?",
                    (_ATTEMPTS_MARK, row_id),
                )
                victim["waitfor_at"] = monotonic()
                written.set()
                await cur.execute(_WAITFOR)
                await store._commit(conn)
            except Exception:
                await conn.rollback()
                raise

    task = asyncio.create_task(_body())
    waiter = asyncio.create_task(written.wait())
    await asyncio.wait({task, waiter}, timeout=_ARM_DEADLINE_S, return_when=asyncio.FIRST_COMPLETED)
    waiter.cancel()
    if task.done():
        task.result()  # surface the body's real error instead of a bare timeout
    assert written.is_set(), "the house-idiom body never reached its WAITFOR"
    ident: _Ident = victim["ident"]
    await asyncio.sleep(0.5)  # inside the WAITFOR now
    armed = await _victim(observer, ident)
    _emit(capsys, f"ADR0157-INC3-PROBE {case}: ARMED (victim [{armed.text}])")
    reading = await _cancel_and_watch(task, observer, row_id, ident, None)

    remaining = _WAITFOR_S - (reading.t_cancel - victim["waitfor_at"])
    waited = reading.unwind_s is not None and reading.unwind_s >= remaining - 0.25
    write = _classify_write(
        reading,
        committed=lambda s: s[1] >= _ATTEMPTS_MARK,
        rolled_back=lambda s: s[1] < _ATTEMPTS_MARK,
    )
    await _report(
        capsys,
        case,
        store,
        victim["conn"],
        quarantined,
        reading,
        write=write,
        extra=f" waitfor_remaining_at_cancel={remaining:.2f}s unwind_waited_for_statement={waited}",
    )


async def test_adr0157_inc3_probe_mark_done_blocked_on_finalize_applock(
    probe_store: Any,
    outside_store: Any,
    observer: Any,
    cleanup: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from messagefoundry.store import OutboxStatus
    from messagefoundry.store.sqlserver import _SQL_APPLOCK

    case = "mark_done_blocked_on_finalize_applock"
    store = probe_store
    mid, dest, row_id = await _enqueue(store, cleanup)
    items = await store.claim_ready(now=200.0, destination_name=dest)
    assert [i.id for i in items] == [row_id], items
    victim_conn, ident = await _borrow_ident(store)
    quarantined = _spy_quarantine(store)

    blocker = await _borrow_outside(outside_store, 10000)
    try:
        # A transaction-owned applock needs an open transaction to attach to. Under autocommit=False
        # the driver runs IMPLICIT_TRANSACTIONS, and a table-reading SELECT is what opens one.
        await _exec(blocker, "SELECT COUNT(*) FROM messages WHERE id=?", (mid,), fetch=True)
        rc = await _exec(blocker, _SQL_APPLOCK, (f"mefor:finalize:{mid}", 0), fetch=True)
        assert rc is not None and int(rc[0]) >= 0, f"blocker could not take the applock: {rc!r}"

        task = asyncio.create_task(store.mark_done(row_id, now=300.0))
        # The DONE flip precedes the finalize applock, so a locked row means mark_done has written.
        wrote = await _await_row_locked(observer, row_id)
        parked = await _await_lock_wait(observer, ident)
        _emit(capsys, f"ADR0157-INC3-PROBE {case}: ARMED (wrote={wrote} parked={parked})")
        if not wrote or parked == "NOT_BLOCKED":
            task.cancel()
            await blocker.rollback()
            await asyncio.wait({task}, timeout=_TASK_SETTLE_S)
            pytest.fail(f"{case}: never armed (wrote={wrote} parked={parked})")
        reading = await _cancel_and_watch(task, observer, row_id, ident, blocker.rollback)
    finally:
        await _return_outside(outside_store, blocker)

    write = _classify_write(
        reading,
        committed=lambda s: s[0] == OutboxStatus.DONE.value,
        rolled_back=lambda s: s[0] == OutboxStatus.INFLIGHT.value,
    )
    await _report(
        capsys,
        case,
        store,
        victim_conn,
        quarantined,
        reading,
        write=write,
        extra=f" parked={parked}",
    )


async def test_adr0157_inc3_probe_claim_ready_blocked_then_completes(
    probe_store: Any,
    outside_store: Any,
    observer: Any,
    cleanup: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    from messagefoundry.store import OutboxStatus
    from messagefoundry.store.sqlserver import _is_lock_timeout

    case = "claim_ready_blocked_then_completes"
    store = probe_store
    _, dest, row_id = await _enqueue(store, cleanup)
    victim_conn, ident = await _borrow_ident(store)
    quarantined = _spy_quarantine(store)

    blocker = await _borrow_outside(outside_store, 10000)
    try:
        # A TABLE lock: READPAST skips row and page locks but must wait on this one. Bounded, because
        # a session an earlier case leaked would otherwise park this blocker for good.
        try:
            await _exec(blocker, "SELECT COUNT(*) FROM queue WITH (TABLOCKX, HOLDLOCK)", fetch=True)
        except Exception as exc:
            if _is_lock_timeout(exc):
                pytest.fail(
                    _emit(
                        capsys,
                        f"ADR0157-INC3-PROBE {case}: BLOCKER_TIMEOUT (another session still holds"
                        " locks on queue -- read the earlier cases' LEAKED lines)",
                    )
                )
            raise
        # Nothing can modify queue while the table lock is held, so this is the baseline for
        # "did the claim UPDATE run after the release".
        ops_before = await _queue_update_ops(observer)

        task = asyncio.create_task(store.claim_ready(now=200.0, destination_name=dest))
        parked = await _await_lock_wait(observer, ident)
        _emit(capsys, f"ADR0157-INC3-PROBE {case}: ARMED (parked={parked})")
        if parked == "NOT_BLOCKED":
            task.cancel()
            await blocker.rollback()
            await asyncio.wait({task}, timeout=_TASK_SETTLE_S)
            pytest.fail(f"{case}: never armed (parked={parked})")
        reading = await _cancel_and_watch(task, observer, row_id, ident, blocker.rollback)
        ops_after = await _queue_update_ops(observer)
    finally:
        await _return_outside(outside_store, blocker)

    # Question 3 is about a statement that RUNS after the cancel. A row still PENDING says nothing
    # was committed, but only evidence that the UPDATE ran makes that an answer to question 3.
    # A lock seen on the row, or the non-transactional update counters moving, is that evidence.
    ops_delta = None if ops_before is None or ops_after is None else ops_after - ops_before
    if reading.lock_seen_while_watching or (ops_delta is not None and ops_delta > 0):
        ran = "YES"
    elif ops_delta == 0:
        ran = "NO"
    else:
        ran = "UNPROVEN"
    write = _classify_write(
        reading,
        committed=lambda s: s[0] == OutboxStatus.INFLIGHT.value,
        rolled_back=lambda s: s[0] == OutboxStatus.PENDING.value and s[1] == 0,
    )
    if write == "ROLLED_BACK" and ran != "YES":
        # Not committed either way. NOT_RUN is still safe, and says the statement never executed;
        # UNPROVEN fails, because it answers nothing.
        write = "NOT_RUN" if ran == "NO" else "ROLLED_BACK_UNPROVEN_RUN"
    await _report(
        capsys,
        case,
        store,
        victim_conn,
        quarantined,
        reading,
        write=write,
        safe=frozenset({"ROLLED_BACK", "NOT_RUN"}),
        extra=f" parked={parked} update_ran={ran} queue_update_ops_delta={ops_delta}",
    )
