# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""ADR 0157 Inc 3 gate probe (BACKLOG #1497): does a coroutine cancelled mid-``execute`` inside a SQL
Server store transaction leave that transaction COMMITTED or ROLLED BACK?

**This file is a MEASUREMENT, not a regression suite.** ADR 0157 Inc 3 (epoch fences on SQL Server
``claim_ready`` and the terminal resolves) is gated on that one question, and the ADR says to pin it on
the live CI leg rather than build on a guess. Every case prints its readings as::

    ADR0157-INC3-PROBE <case>.<subject>: <COMMITTED|ROLLED_BACK|LEAKED_OPEN_TXN|...> (details)

**Each case runs in its own CHILD process.** Round 1 (CI run 36219288548) showed that cancelling a
store call mid-statement can segfault the interpreter inside ``msodbcsql``: 4 of 4 armed
``claim_ready`` cancels and 1 of 5 house-idiom cancels died with SIGSEGV, which killed the whole CI
step and starved every case after it. So the outer test only launches a child pytest on the matching
``inner`` test, re-prints the child's probe lines, and turns a native crash into its own reading,
``<case>.write: CRASHED_NATIVE``, with the top native frames attached (``<case>.after_write`` when
the child had already printed its write reading). A crash is a finding about the store's cancel path,
not noise. A child that dies is followed by an orphan-cleanup child, because this file runs FIRST in
its CI step and later files must not claim its rows. ``START`` marks each attempt, since the step's
native-crash wrapper can re-run the whole file.

**What reading the store already says, and where it stops.** The house idiom's ``except Exception:
await conn.rollback()`` never sees a ``CancelledError``. The ``_acquire`` chokepoint does (``except
BaseException``, BACKLOG #348 / ADR 0159): it drops the pooled connection's raw handle so aioodbc's
``Pool.release`` cannot re-lend it, then closes the raw pyodbc handle off-loop, bounded at
``_DIRTY_CLOSE_TIMEOUT``. pyodbc's ``close()`` rolls back an ``autocommit=False`` connection before it
disconnects. Reading cannot settle whether that close really rolls back while the abandoned statement
still runs on the store's executor thread, how long the locks stay held, or whether a statement that
completes AFTER the cancel can end up committed.

**The reading is scoped to the house idiom, and one claim path is NOT on it.** ``claim_fifo_heads``
runs a shielded ``SET LOCK_TIMEOUT -1`` + ``_commit`` in its ``finally`` and waits for it on
cancellation (ADR 0114 §2). A cancel there COMMITS whatever its claim statement had done. Nothing in
this file measures that path, and nothing here should be quoted as covering it.

**How a case decides its answer.**

* ``.write`` is the FINAL state of the abandoned write, read with a locking read
  (``READCOMMITTEDLOCK``, ``LOCK_TIMEOUT 0``) once the victim session is gone or holds no locks, or
  at a bounded deadline. LEAKED_OPEN_TXN means the write's locks were STILL held at that point.
* ``.victim_session`` reports what happened to the cancelled connection's server session: gone, idle
  at the baseline, or alive with an open transaction. Round 1 saw it alive at +15s with
  ``open_txn=1`` and the write already undone, so this is reported apart from the write.
* ``.control_idle_quarantine`` runs the store's quarantine on an IDLE connection first, so a surviving
  victim session can be told apart from a close that never disconnects anything.
* ``.baseline`` measures a brand-new pooled connection exactly the way ``.next_borrower`` is measured,
  once during the borrow and once at rest. With autocommit off the driver runs IMPLICIT_TRANSACTIONS,
  so ``@@TRANCOUNT`` on a clean connection is compared against this baseline, never against zero.
  That was round 1's suspected false positive. The borrower is also flagged if it holds granted
  locks, or if its transaction is OLDER than the borrow itself, which catches an inherited
  transaction that holds no locks and so matches the baseline count.
* ``claim_ready`` reads ROLLED_BACK only with positive evidence that its UPDATE ran after the release
  (a row lock, a granted victim lock, or the update counters moving). Without that evidence it reads
  NOT_COMMITTED_UPDATE_RUN_UNPROVEN and fails, because it answers nothing.

**The cases.** All three run the store's REAL transaction path (``_acquire`` -> ``_cursor`` ->
execute -> ``_commit`` / ``except Exception: rollback``). The store's pool holds ONE connection, so
"what does the next borrower get" has exactly one candidate. The observer and the blockers borrow from
a SECOND store's pool.

* ``house_idiom_waitfor`` -- the store's own idiom, driven directly: a write, then ``WAITFOR DELAY``,
  cancelled while the WAITFOR runs.
* ``mark_done_blocked_on_finalize_applock`` -- a real terminal resolve. An outside session holds the
  per-message finalize applock, so ``mark_done`` blocks inside ``sp_getapplock`` AFTER its DONE flip.
* ``claim_ready_blocked_then_completes`` -- a real ``claim_ready``. An outside session holds a table
  lock on ``queue`` (``READPAST`` skips row locks, not a table lock), so the claim UPDATE is queued at
  cancel time and can only run after the cancel, once the outside lock is released.

**Gated** like the rest of the server-backend suite: skipped unless ``MEFOR_TEST_SQLSERVER`` is set
(plus ``MEFOR_STORE_*`` connection env). CI runs it first in the ``sqlserver-store`` job's catch-all
step.
"""

from __future__ import annotations

import asyncio
import os
import subprocess
import sys
from collections.abc import AsyncIterator, Awaitable, Callable
from dataclasses import dataclass, field
from pathlib import Path
from time import monotonic
from typing import Any
from uuid import uuid4

import pytest

pytestmark = pytest.mark.skipif(
    not os.getenv("MEFOR_TEST_SQLSERVER"),
    reason="set MEFOR_TEST_SQLSERVER=1 (+ MEFOR_STORE_* connection env) to run SQL Server tests",
)

_INNER_ENV = "MEFOR_ADR0157_PROBE_INNER"
_IS_INNER = os.getenv(_INNER_ENV) == "1"
_REPO_ROOT = Path(__file__).resolve().parents[1]
_THIS = Path(__file__).resolve().relative_to(_REPO_ROOT).as_posix()

inner = pytest.mark.skipif(not _IS_INNER, reason="run in a child process by its outer probe test")
outer = pytest.mark.skipif(_IS_INNER, reason="the outer launcher does not run inside its own child")

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
#: Bound on the victim session going away or going idle, from the moment watching starts.
_RESOLVE_DEADLINE_S = 15.0
#: Bound on the idle-quarantine control's session going away.
_CONTROL_DEADLINE_S = 8.0
#: Bound on reaching the armed state (the write done, the victim waiting where the case says).
_ARM_DEADLINE_S = 10.0
#: The house-idiom write marker. A committed write leaves attempts at or above it.
_ATTEMPTS_MARK = 1000
#: Bound on the next borrower getting a connection, shorter than the store's own acquire_timeout.
_BORROW_S = 10.0
#: Child budget. The inner case's own worst case is about 130s; the outer waits a little longer.
_INNER_TIMEOUT_S = 180
_CHILD_TIMEOUT_S = 210

_LOCKED = "LOCKED"
#: SQL Server native errors that mean "this login may not read that DMV": 297 (no permission for
#: the action) and 300 (VIEW SERVER STATE denied). Only these switch the probe to lock reads alone;
#: any other DMV error is a transient reading and the watch keeps polling.
_DMV_DENIED = ("(297)", "(300)")


def _emit(capsys: pytest.CaptureFixture[str], line: str) -> str:
    """Write a probe line to the real stderr, past pytest's capture, and return it for assertions.
    Flushed at once, so a line written just before a native crash still reaches the parent."""
    with capsys.disabled():
        sys.stderr.write(line + "\n")
        sys.stderr.flush()
    return line


# --------------------------------------------------------------------------------------------------
# Outer launchers: one child process per case, so a native crash is a reading, not a dead step.
# --------------------------------------------------------------------------------------------------


def _native_frames(text: str) -> str:
    """The top ODBC/pyodbc frames of a faulthandler C stack, e.g.
    ``libmsodbcsql-18.7.so.1.1", at SQLDescribeColW+0xc4 [0x...]`` -> ``libmsodbcsql-18.7.so.1.1
    SQLDescribeColW+0xc4``."""
    frames = []
    for ln in text.splitlines():
        if "Binary file" not in ln or "odbc" not in ln:
            continue
        lib, _, rest = ln.rsplit("/", 1)[-1].partition('", at ')
        frames.append(f"{lib} {rest.split(' [', 1)[0]}")
    return "; ".join(frames[:5]) or "none captured"


def _as_text(value: bytes | str | None) -> str:
    if value is None:
        return ""
    return value.decode("utf-8", "replace") if isinstance(value, bytes) else value


def _run_case(case: str, inner_test: str, capsys: pytest.CaptureFixture[str]) -> None:
    # The step's native-crash wrapper can re-run this whole file; START separates the attempts.
    _emit(capsys, f"ADR0157-INC3-PROBE {case}: START (launcher pid={os.getpid()})")
    env = dict(os.environ)
    env[_INNER_ENV] = "1"
    env.setdefault("PYTHONFAULTHANDLER", "1")
    cmd = [
        sys.executable,
        "-m",
        "pytest",
        "-q",
        "-s",
        "-p",
        "no:cacheprovider",
        f"--timeout={_INNER_TIMEOUT_S}",
        f"{_THIS}::{inner_test}",
    ]
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(_REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=_CHILD_TIMEOUT_S,
            check=False,
        )
        out, rc = _as_text(proc.stdout) + _as_text(proc.stderr), proc.returncode
    except subprocess.TimeoutExpired as exc:
        # Captured output on a timeout is bytes even under text=True.
        out, rc = _as_text(exc.stdout) + _as_text(exc.stderr), None
    probe = [ln for ln in out.splitlines() if ln.startswith("ADR0157-INC3-PROBE")]
    for ln in probe:
        _emit(capsys, ln)
    last = probe[-1] if probe else "none"
    tail = "\n".join(out.splitlines()[-40:])
    # A crash or hang AFTER the .write reading is about the borrow or teardown, not the write, so it
    # gets its own subject rather than a second, contradictory .write line.
    subject = "after_write" if any(f"{case}.write:" in ln for ln in probe) else "write"
    failure: str | None = None
    if rc is None:
        failure = _emit(
            capsys,
            f"ADR0157-INC3-PROBE {case}.{subject}: CHILD_TIMEOUT (no exit in {_CHILD_TIMEOUT_S}s;"
            f" last=[{last}])",
        )
    elif rc < 0 or rc in (134, 139):
        failure = _emit(
            capsys,
            f"ADR0157-INC3-PROBE {case}.{subject}: CRASHED_NATIVE (rc={rc} last=[{last}]"
            f" native=[{_native_frames(out)}])",
        )
    elif not any(f"{case}.{s}:" in ln for ln in probe for s in ("write", "next_borrower")):
        # Not a reading: a harness error, a never-armed case, or the child's own pytest-timeout
        # (thread method, os._exit(1)). Labelled so it can never be mistaken for a safe answer.
        failure = _emit(
            capsys,
            f"ADR0157-INC3-PROBE {case}.write: CHILD_FAILED_NO_READING (child rc={rc};"
            f" timeout_in_output={'Timeout' in out} last=[{last}])",
        )
    if rc != 0:
        _run_orphan_cleanup(capsys, case)
    if failure is not None:
        pytest.fail(f"{failure}\n{tail}")
    assert rc == 0, "\n".join(probe) + "\n--- child tail ---\n" + tail


def _run_orphan_cleanup(capsys: pytest.CaptureFixture[str], case: str) -> None:
    """A child that crashed or was killed never ran its cleanup fixture, and this file now runs FIRST
    in its CI step. Remove every probe row in a separate child, so later files never claim them."""
    env = dict(os.environ)
    env[_INNER_ENV] = "1"
    cmd = [sys.executable, "-m", "pytest", "-q", "-s", "-p", "no:cacheprovider"]
    cmd.append(f"{_THIS}::test_inner_cleanup_orphaned_probe_rows")
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(_REPO_ROOT),
            env=env,
            capture_output=True,
            text=True,
            timeout=90,
            check=False,
        )
        rc: int | None = proc.returncode
    except subprocess.TimeoutExpired:
        rc = None
    _emit(capsys, f"ADR0157-INC3-PROBE {case}.orphan_cleanup: rc={rc}")


@outer
@pytest.mark.timeout(_CHILD_TIMEOUT_S + 30)
def test_adr0157_inc3_probe_house_idiom_waitfor(capsys: pytest.CaptureFixture[str]) -> None:
    _run_case("house_idiom_waitfor", "test_inner_house_idiom_waitfor", capsys)


@outer
@pytest.mark.timeout(_CHILD_TIMEOUT_S + 30)
def test_adr0157_inc3_probe_mark_done_blocked_on_finalize_applock(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _run_case(
        "mark_done_blocked_on_finalize_applock",
        "test_inner_mark_done_blocked_on_finalize_applock",
        capsys,
    )


@outer
@pytest.mark.timeout(_CHILD_TIMEOUT_S + 30)
def test_adr0157_inc3_probe_claim_ready_blocked_then_completes(
    capsys: pytest.CaptureFixture[str],
) -> None:
    _run_case(
        "claim_ready_blocked_then_completes",
        "test_inner_claim_ready_blocked_then_completes",
        capsys,
    )


# --------------------------------------------------------------------------------------------------
# Inner machinery. Everything below runs only in the child.
# --------------------------------------------------------------------------------------------------


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
    """One DMV read of a session. Needs VIEW SERVER STATE (the CI leg runs as sa). A denied permission
    sets ``available`` False and the probe falls back to lock reads alone. Any other DMV error sets
    ``error`` and is never read as "the transaction is over"."""

    available: bool
    error: bool = False
    gone: bool = False
    open_txn: int = 0
    request: str | None = None
    wait: str | None = None
    locks: int = 0
    txn: str = "-"
    txn_age_ms: int | None = None
    login: str | None = None
    text: str = ""

    @property
    def readable(self) -> bool:
        return self.available and not self.error

    @property
    def holds_locks(self) -> bool:
        return self.readable and not self.gone and self.locks > 0

    def idle_at(self, baseline_open_txn: int) -> bool:
        """Present, running nothing, holding no locks, and no more open transactions than a clean
        connection shows."""
        return (
            self.readable
            and not self.gone
            and self.request is None
            and self.locks == 0
            and self.open_txn <= baseline_open_txn
        )


@dataclass(frozen=True)
class _Ident:
    """A session. ``login_time`` pins it, so a reused session id is never read as the same session."""

    spid: int
    login_time: str | None


# Locks: GRANTED only (a parked request is not a held lock), in THIS database only (tempdb and
# metadata locks elsewhere say nothing about the write), and not the shared DATABASE lock every
# connected session holds. Transaction: the oldest one the session has open, its name
# (implicit_transaction / user_transaction) and its age, so "a new empty transaction opened after the
# cancel" can be told apart from "the abandoned one is still open".
_SESSION_SQL = (
    "SELECT s.open_transaction_count, r.status, r.wait_type,"
    " (SELECT COUNT(*) FROM sys.dm_tran_locks l"
    "   WHERE l.request_session_id = s.session_id AND l.resource_type <> 'DATABASE'"
    "   AND l.request_status = 'GRANT' AND l.resource_database_id = DB_ID()),"
    " (SELECT TOP 1 a.name FROM sys.dm_tran_session_transactions t"
    "   JOIN sys.dm_tran_active_transactions a ON a.transaction_id = t.transaction_id"
    "   WHERE t.session_id = s.session_id ORDER BY a.transaction_begin_time),"
    " (SELECT TOP 1 DATEDIFF(millisecond, a.transaction_begin_time, SYSDATETIME())"
    "   FROM sys.dm_tran_session_transactions t"
    "   JOIN sys.dm_tran_active_transactions a ON a.transaction_id = t.transaction_id"
    "   WHERE t.session_id = s.session_id ORDER BY a.transaction_begin_time),"
    " CONVERT(varchar(30), s.login_time, 126)"
    " FROM sys.dm_exec_sessions s"
    " LEFT JOIN sys.dm_exec_requests r ON r.session_id = s.session_id"
    " WHERE s.session_id = ?"
)


async def _session(observer: Any, ident: _Ident) -> _Victim:
    sql = _SESSION_SQL
    params: tuple[Any, ...] = (ident.spid,)
    if ident.login_time is not None:
        # Compared as text on both sides. A datetime parameter against the datetime column would be
        # widened to datetime2 under compat >= 130 (.003 -> .0033333) and never match.
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
    v = _Victim(
        available=True,
        open_txn=int(row[0]),
        request=row[1],
        wait=row[2],
        locks=int(row[3] or 0),
        txn=row[4] or "-",
        txn_age_ms=None if row[5] is None else int(row[5]),
        login=row[6],
    )
    v.text = (
        f"open_txn={v.open_txn} locks={v.locks} txn={v.txn} txn_age_ms={v.txn_age_ms}"
        f" request={v.request} wait={v.wait}"
    )
    return v


async def _identify(cur: Any) -> _Ident:
    """Run ON the victim connection. A session can always read its own row of dm_exec_sessions."""
    await cur.execute(
        "SELECT @@SPID, (SELECT CONVERT(varchar(30), login_time, 126)"
        " FROM sys.dm_exec_sessions WHERE session_id = @@SPID)"
    )
    row = await cur.fetchone()
    return _Ident(spid=int(row[0]), login_time=row[1])


async def _self_view(cur: Any) -> tuple[int, int]:
    """``(@@SPID, @@TRANCOUNT)`` as the session sees itself. The SAME statement is used for the
    baseline and for the next borrower, so the two are comparable."""
    await cur.execute("SELECT @@SPID, @@TRANCOUNT")
    row = await cur.fetchone()
    return int(row[0]), int(row[1])


@dataclass
class _Baseline:
    """A brand-new pooled connection, read twice: DURING the borrow (right after ``_self_view``, the
    state the next borrower is compared against) and AT REST after ``_commit_read`` (the state a
    settled victim session is compared against)."""

    self_trancount: int
    in_borrow: _Victim
    at_rest: _Victim

    @staticmethod
    def _txns(v: _Victim) -> int:
        return v.open_txn if v.readable and not v.gone else 0

    @property
    def in_borrow_open_txn(self) -> int:
        return self._txns(self.in_borrow)

    @property
    def open_txn(self) -> int:
        """At rest. What an idle, clean session shows."""
        return self._txns(self.at_rest)


async def _control_and_baseline(
    store: Any, observer: Any, capsys: pytest.CaptureFixture[str], case: str
) -> _Baseline:
    """Two measurements the case needs before it cancels anything.

    1. The CONTROL: run the store's own quarantine on an IDLE pooled connection and watch whether its
       session goes away. If it survives too, a surviving victim session says nothing about the cancel.
    2. The BASELINE: the quarantine emptied the one-slot pool, so the next borrow is a brand-new
       connection. Measure it exactly the way ``_next_borrower`` measures its borrow."""
    conn = await store._pool.acquire()
    try:
        cur = await conn.cursor()
        try:
            ident = await _identify(cur)
        finally:
            await cur.close()
        await conn.commit()
        await store._release_dirty(conn)
    finally:
        await store._pool.release(conn)
    t0 = monotonic()
    seen = await _session(observer, ident)
    # Only a denied permission stops the poll; a transient DMV error is polled through.
    while seen.available and not seen.gone and monotonic() - t0 < _CONTROL_DEADLINE_S:
        await asyncio.sleep(0.1)
        seen = await _session(observer, ident)
    if seen.gone:
        verdict = "SESSION_GONE"
    elif not seen.readable:
        verdict = "UNKNOWN"
    else:
        verdict = "SURVIVED"
    _emit(
        capsys,
        f"ADR0157-INC3-PROBE {case}.control_idle_quarantine: {verdict}"
        f" (after={monotonic() - t0:.2f}s spid={ident.spid} session=[{seen.text}])",
    )

    async with store._acquire() as bconn, store._cursor(bconn) as bcur:
        spid, trancount = await _self_view(bcur)
        in_borrow = await _session(observer, _Ident(spid, None))
        await store._commit_read(bconn)
    # Read at rest while the connection sits idle in the pool, after the borrow's commit.
    at_rest = await _session(observer, _Ident(spid, None))
    base = _Baseline(self_trancount=trancount, in_borrow=in_borrow, at_rest=at_rest)
    _emit(
        capsys,
        f"ADR0157-INC3-PROBE {case}.baseline: self_trancount={trancount}"
        f" (brand-new pooled connection, spid={spid}, in_borrow=[{in_borrow.text}]"
        f" at_rest=[{at_rest.text}])",
    )
    return base


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
        v = await _session(observer, ident)
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


@dataclass
class _Quarantine:
    """Every connection the store quarantined (ADR 0159), and how long each ``_release_dirty`` took.
    A duration near ``_DIRTY_CLOSE_TIMEOUT`` (5s) means the close did not finish inside its bound."""

    conns: list[Any] = field(default_factory=list)
    seconds: list[float] = field(default_factory=list)

    def of(self, conn: Any) -> str:
        for c, s in zip(self.conns, self.seconds, strict=False):
            if c is conn:
                return f"yes(close_bound_wait={s:.2f}s)"
        return "no"


def _spy_quarantine(store: Any) -> _Quarantine:
    """Record quarantines without changing what the store does."""
    seen = _Quarantine()
    real: Callable[[Any], Awaitable[None]] = store._release_dirty

    async def _spy(conn: Any) -> None:
        seen.conns.append(conn)
        t0 = monotonic()
        try:
            await real(conn)
        finally:
            seen.seconds.append(monotonic() - t0)

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
    settled: bool = False
    settled_s: float | None = None
    last_lock_s: float | None = None
    lock_seen_while_watching: bool = False
    victim_locks_seen_while_watching: bool = False
    victim_after: _Victim = field(default_factory=lambda: _Victim(available=False))


async def _watch(
    reading: _Reading,
    observer: Any,
    row_id: str,
    ident: _Ident,
    task: asyncio.Task[Any],
    baseline: _Baseline,
) -> None:
    """Poll until the abandoned transaction is over: the task is done, the row is not locked, and the
    victim session is gone or idle at the baseline. Without DMV access, a lock-free read held for one
    second stands in for the last condition. At the deadline, stop and report whatever holds then.
    ``last_lock_s`` records the last moment anything of the victim's was still locked."""
    t0 = monotonic()
    quiet_since: float | None = None
    while True:
        seen = await _read_row(observer, row_id)
        v = await _session(observer, ident)
        now = monotonic()
        if seen == _LOCKED or v.holds_locks:
            reading.lock_seen_while_watching = reading.lock_seen_while_watching or seen == _LOCKED
            reading.victim_locks_seen_while_watching = (
                reading.victim_locks_seen_while_watching or v.holds_locks
            )
            reading.last_lock_s = now - reading.t_cancel
            quiet_since = None
        elif task.done():
            if v.gone or v.idle_at(baseline.open_txn):
                reading.seen, reading.victim_after, reading.settled = seen, v, True
                reading.settled_s = now - reading.t_cancel
                return
            if not v.available:
                quiet_since = quiet_since or now
                if now - quiet_since >= 1.0:
                    reading.seen, reading.victim_after, reading.settled = seen, v, True
                    reading.settled_s = quiet_since - reading.t_cancel
                    return
        if now - t0 > _RESOLVE_DEADLINE_S:
            reading.seen, reading.victim_after = seen, v
            return
        await asyncio.sleep(0.005)


async def _cancel_and_watch(
    task: asyncio.Task[Any],
    observer: Any,
    row_id: str,
    ident: _Ident,
    baseline: _Baseline,
    capsys: pytest.CaptureFixture[str],
    case: str,
    release: Callable[[], Awaitable[None]] | None,
) -> _Reading:
    """Cancel, hold any outside lock a little longer, release it, then watch the abandoned
    transaction end while the task settles. Every wait is bounded. CANCELLED and RELEASED lines are
    printed as they happen, so a native crash can be placed against them."""
    done_at: list[float] = []
    task.add_done_callback(lambda _t: done_at.append(monotonic()))
    task.cancel()
    reading = _Reading(t_cancel=monotonic())
    _emit(capsys, f"ADR0157-INC3-PROBE {case}: CANCELLED")
    if release is not None:
        early, _ = await asyncio.wait({task}, timeout=_HOLD_AFTER_CANCEL_S)
        reading.done_before_release = bool(early)
        reading.victim_at_release = (await _session(observer, ident)).text
        await release()
        _emit(
            capsys,
            f"ADR0157-INC3-PROBE {case}: RELEASED"
            f" (+{monotonic() - reading.t_cancel:.2f}s task_done={task.done()})",
        )
    watcher = asyncio.create_task(_watch(reading, observer, row_id, ident, task, baseline))
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
    """The FINAL state of the write. LEAKED_OPEN_TXN only if its locks were still held when watching
    stopped; a surviving session that holds nothing is reported on its own line instead."""
    if r.seen == _LOCKED or r.victim_after.holds_locks:
        return "LEAKED_OPEN_TXN"
    if r.seen is None:
        return "ROW_MISSING"
    if committed(r.seen):
        return "COMMITTED"
    if rolled_back(r.seen):
        return "ROLLED_BACK"
    return f"UNEXPECTED{r.seen!r}"


def _classify_session(r: _Reading, baseline: _Baseline) -> str:
    v = r.victim_after
    if not v.available:
        return "UNKNOWN_NO_DMV"
    if v.error:
        return "UNKNOWN_DMV_ERROR"
    if v.gone:
        return "GONE"
    if v.holds_locks:
        return f"HOLDING_LOCKS({v.locks})"
    if v.idle_at(baseline.open_txn):
        return "ALIVE_IDLE_AT_BASELINE"
    if v.request is not None:
        return "ALIVE_RUNNING"
    return "ALIVE_OPEN_TXN_NO_LOCKS"


async def _next_borrower(
    store: Any, observer: Any, victim_conn: Any, victim: _Ident, reading: _Reading, base: _Baseline
) -> tuple[str, str]:
    """What the pool hands the next caller after the cancellation, measured exactly like the
    baseline. A leak is locks held on the borrow, or more transactions than a clean borrow shows."""
    if reading.state == "HUNG":
        return "NOT_MEASURED", "the cancelled task still holds the pool's only connection"

    async def _borrow() -> tuple[int, int, bool, _Victim, float]:
        async with store._acquire() as conn, store._cursor(conn) as cur:
            # Everything that opened on this session during THIS borrow is younger than this.
            t_borrow = monotonic()
            spid, trancount = await _self_view(cur)
            dmv = await _session(observer, _Ident(spid, None))
            borrow_ms = (monotonic() - t_borrow) * 1000.0
            await conn.rollback()  # end whatever the borrow shows; this is a read-only check
            return spid, trancount, conn is victim_conn, dmv, borrow_ms

    try:
        spid, trancount, same_obj, dmv, borrow_ms = await asyncio.wait_for(
            _borrow(), timeout=_BORROW_S
        )
    except Exception as exc:  # noqa: BLE001 - e.g. HY000 busy on a re-lent connection; a reading
        return f"BORROWER_ERROR:{type(exc).__name__}", str(exc)
    same_session = spid == victim.spid and dmv.login is not None and dmv.login == victim.login_time
    # Three independent signs of an inherited transaction, each against a clean borrow measured the
    # same way: locks held, more transactions than the baseline, or a transaction OLDER than this
    # borrow (so it was already open when the pool handed the connection over). The last one catches
    # a lock-free abandoned transaction the counts alone would read as equal to the baseline.
    older = dmv.txn_age_ms is not None and dmv.txn_age_ms > borrow_ms + 250.0
    if (
        dmv.holds_locks
        or trancount > base.self_trancount
        or (dmv.readable and not dmv.gone and dmv.open_txn > base.in_borrow_open_txn)
        or older
    ):
        outcome = "LEAKED_OPEN_TXN"
    elif same_obj:
        outcome = "REUSED_SAME_CONNECTION_CLEAN"
    else:
        outcome = "FRESH_CONNECTION"
    pool = store._pool
    return outcome, (
        f"spid={spid} trancount={trancount} baseline_trancount={base.self_trancount}"
        f" baseline_in_borrow_open_txn={base.in_borrow_open_txn}"
        f" txn_older_than_borrow={older} borrow_ms={borrow_ms:.0f}"
        f" same_session_as_victim={same_session} victim_spid={victim.spid}"
        f" dmv=[{dmv.text}] pool_size={pool.size} free={pool.freesize}"
    )


def _fmt_s(value: float | None) -> str:
    return "n/a" if value is None else f"{value:.2f}s"


async def _report(
    capsys: pytest.CaptureFixture[str],
    case: str,
    store: Any,
    observer: Any,
    victim_conn: Any,
    victim: _Ident,
    quarantined: _Quarantine,
    reading: _Reading,
    base: _Baseline,
    *,
    write: str,
    extra: str = "",
) -> None:
    """Print the readings for a case, then assert the safe outcome with every line attached."""
    quarantine = quarantined.of(victim_conn)
    line_w = _emit(
        capsys,
        f"ADR0157-INC3-PROBE {case}.write: {write} (task={reading.state}"
        f" unwind={_fmt_s(reading.unwind_s)} done_before_release={reading.done_before_release}"
        f" victim_at_release=[{reading.victim_at_release}]"
        f" last_lock_seen_at=+{_fmt_s(reading.last_lock_s)}"
        f" settled_at=+{_fmt_s(reading.settled_s)}"
        f" row_lock_seen_while_watching={reading.lock_seen_while_watching}"
        f" victim_locks_seen_while_watching={reading.victim_locks_seen_while_watching}"
        f" seen={reading.seen!r} quarantined={quarantine}{extra})",
    )
    line_s = _emit(
        capsys,
        f"ADR0157-INC3-PROBE {case}.victim_session: {_classify_session(reading, base)}"
        f" (spid={victim.spid} settled={reading.settled} baseline_open_txn={base.open_txn}"
        f" session=[{reading.victim_after.text}])",
    )
    borrower, detail = await _next_borrower(store, observer, victim_conn, victim, reading, base)
    line_b = _emit(capsys, f"ADR0157-INC3-PROBE {case}.next_borrower: {borrower} ({detail})")
    lines = f"{line_w}\n{line_s}\n{line_b}"
    assert reading.state == "CANCELLED", lines
    assert write == "ROLLED_BACK", lines
    assert borrower in {"FRESH_CONNECTION", "REUSED_SAME_CONNECTION_CLEAN"}, lines


@inner
@pytest.mark.timeout(_INNER_TIMEOUT_S)
async def test_inner_house_idiom_waitfor(
    probe_store: Any,
    observer: Any,
    cleanup: list[str],
    capsys: pytest.CaptureFixture[str],
) -> None:
    case = "house_idiom_waitfor"
    store = probe_store
    _, _, row_id = await _enqueue(store, cleanup)
    base = await _control_and_baseline(store, observer, capsys, case)
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
    armed = await _session(observer, ident)
    _emit(capsys, f"ADR0157-INC3-PROBE {case}: ARMED (spid={ident.spid} victim=[{armed.text}])")
    reading = await _cancel_and_watch(task, observer, row_id, ident, base, capsys, case, None)

    # unwind includes the quarantine's own bounded close wait, which the .write line prints on its
    # own (quarantined=yes(close_bound_wait=...)), so the two can be told apart.
    remaining = _WAITFOR_S - (reading.t_cancel - victim["waitfor_at"])
    write = _classify_write(
        reading,
        committed=lambda s: s[1] >= _ATTEMPTS_MARK,
        rolled_back=lambda s: s[1] < _ATTEMPTS_MARK,
    )
    await _report(
        capsys,
        case,
        store,
        observer,
        victim["conn"],
        ident,
        quarantined,
        reading,
        base,
        write=write,
        extra=f" waitfor_remaining_at_cancel={remaining:.2f}s",
    )


@inner
@pytest.mark.timeout(_INNER_TIMEOUT_S)
async def test_inner_mark_done_blocked_on_finalize_applock(
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
    base = await _control_and_baseline(store, observer, capsys, case)
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
        _emit(
            capsys,
            f"ADR0157-INC3-PROBE {case}: ARMED (spid={ident.spid} wrote={wrote} parked={parked})",
        )
        if not wrote or parked == "NOT_BLOCKED":
            task.cancel()
            await blocker.rollback()
            await asyncio.wait({task}, timeout=_TASK_SETTLE_S)
            pytest.fail(f"{case}: never armed (wrote={wrote} parked={parked})")
        reading = await _cancel_and_watch(
            task, observer, row_id, ident, base, capsys, case, blocker.rollback
        )
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
        observer,
        victim_conn,
        ident,
        quarantined,
        reading,
        base,
        write=write,
        extra=f" parked={parked}",
    )


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


@inner
@pytest.mark.timeout(_INNER_TIMEOUT_S)
async def test_inner_claim_ready_blocked_then_completes(
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
    base = await _control_and_baseline(store, observer, capsys, case)
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
                        " locks on queue)",
                    )
                )
            raise
        # Nothing can modify queue while the table lock is held, so this is the baseline for
        # "did the claim UPDATE run after the release".
        ops_before = await _queue_update_ops(observer)

        task = asyncio.create_task(store.claim_ready(now=200.0, destination_name=dest))
        parked = await _await_lock_wait(observer, ident)
        _emit(capsys, f"ADR0157-INC3-PROBE {case}: ARMED (spid={ident.spid} parked={parked})")
        if parked == "NOT_BLOCKED":
            task.cancel()
            await blocker.rollback()
            await asyncio.wait({task}, timeout=_TASK_SETTLE_S)
            pytest.fail(f"{case}: never armed (parked={parked})")
        reading = await _cancel_and_watch(
            task, observer, row_id, ident, base, capsys, case, blocker.rollback
        )
        ops_after = await _queue_update_ops(observer)
    finally:
        await _return_outside(outside_store, blocker)

    # This case asks about a statement that RUNS after the cancel. A row still PENDING says nothing
    # was committed, but only positive evidence that the UPDATE ran makes that an answer: a lock on
    # the row, a GRANTED lock held by the victim after the release, or the non-transactional update
    # counters moving. A zero delta is NOT evidence the statement never ran (it can match nothing,
    # or the counters can reset), so there is no "never ran" verdict here -- only proven or not.
    ops_delta = None if ops_before is None or ops_after is None else ops_after - ops_before
    ran = (
        reading.lock_seen_while_watching
        or reading.victim_locks_seen_while_watching
        or (ops_delta is not None and ops_delta > 0)
    )
    write = _classify_write(
        reading,
        committed=lambda s: s[0] == OutboxStatus.INFLIGHT.value,
        rolled_back=lambda s: s[0] == OutboxStatus.PENDING.value and s[1] == 0,
    )
    if write == "ROLLED_BACK" and not ran:
        # Not committed, but not an answer either: fails, and says why.
        write = "NOT_COMMITTED_UPDATE_RUN_UNPROVEN"
    await _report(
        capsys,
        case,
        store,
        observer,
        victim_conn,
        ident,
        quarantined,
        reading,
        base,
        write=write,
        extra=f" parked={parked} update_ran={'YES' if ran else 'UNPROVEN'}"
        f" queue_update_ops_delta={ops_delta}",
    )


@inner
@pytest.mark.timeout(80)
async def test_inner_cleanup_orphaned_probe_rows(outside_store: Any) -> None:
    """Run by a launcher only after a child died without its own cleanup. Every probe row carries an
    ``IB_PROBE_`` channel, so this removes exactly the probe's rows and nothing else."""
    conn = await _borrow_outside(outside_store, 10000)
    try:
        sub = "SELECT id FROM messages WHERE channel_id LIKE 'IB[_]PROBE[_]%'"
        for sql in (
            f"DELETE FROM delivered_keys WHERE message_id IN ({sub})",
            f"DELETE FROM message_events WHERE message_id IN ({sub})",
            f"DELETE FROM queue WHERE message_id IN ({sub})",
            "DELETE FROM messages WHERE channel_id LIKE 'IB[_]PROBE[_]%'",
        ):
            await _exec(conn, sql)
        await conn.commit()
    finally:
        await _return_outside(outside_store, conn)
