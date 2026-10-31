# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""One pyodbc call at a time per aioodbc connection, so a cancellation never frees a handle under a
running statement (BACKLOG #2049, #2394).

aioodbc runs every call on an executor thread, and cancelling the awaiting task does not stop that
thread. A cleanup that closes the cursor or the connection on ANOTHER thread while the statement is
still running frees the handles the statement returns to. pyodbc then reads the result's column
metadata from freed memory, and the process dies natively (``SQLDescribeColW``,
``SQLColAttributeW``). Every engine user of aioodbc has that crash class, so the gate lives here, a
leaf beside :mod:`messagefoundry.odbc_env`, where the store and a transport can both reach it
without one importing the other.

The SQL Server store installs it on every pooled connection, every claim holder and its open-time
probe connections. The DATABASE connector installs it on every pooled connection it borrows, and
hands a cursor close to a running call with :meth:`CallGate.run_after_running_call`. The detach that quarantines a cancelled pooled connection stays in the store,
because it is the pool's rule, not the gate's. The exits of an unpooled one-shot connection,
:func:`close_one_shot` and :func:`abandon_one_shot`, live here: they need no pool, so a transport
can use them without importing the store.

Standard library only: nothing here imports aioodbc or pyodbc. It recognises an aioodbc connection
by its bound ``_execute`` method, and reaches its raw handles through ``_conn``, ``_executor`` and a
cursor's ``_impl``, as aioodbc 0.5.0 names them.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import threading
from collections.abc import Callable
from functools import partial
from typing import Any

__all__ = [
    "CallGate",
    "abandon_one_shot",
    "call_gate",
    "close_one_shot",
    "install_call_gate",
    "raw_closer",
]

log = logging.getLogger(__name__)


class CallGate:
    """Runs one connection's pyodbc calls one at a time, and frees its handles only between calls.

    BACKLOG #2049. aioodbc runs every call on an executor thread, and cancelling the awaiting task
    does not stop that thread. Before this gate, the cancellation path closed the cursor and the
    connection on OTHER threads while the statement was still running. When it returned, pyodbc
    read the result's column metadata from freed handles, and a deploying SQL Server site would
    have lost the whole engine process to a native crash (``SQLDescribeColW``,
    ``SQLColAttributeW``). pyodbc declares DB-API ``threadsafety = 1``: threads may share the module
    but not connections. aioodbc already moves each connection across executor threads, one call at
    a time, and that is only sound while the calls really are one at a time. ``_lock`` restores
    that after a cancellation; it does not make the caller conform to level 1.

    On the normal path each call waits for the previous one anyway, so the lock is never contended.
    A quarantine that arrives while a call runs is handed to that call, which closes the connection
    on its own thread as it returns: no extra thread waits, and the event loop never does.
    """

    __slots__ = ("_abandoned", "_after", "_deferred", "_lock", "_running", "_state")

    def __init__(self) -> None:
        self._lock = threading.Lock()  # held for the whole of each pyodbc call
        # Guards the fields below. Held only for a few bytecodes, so the event loop may take it.
        self._state = threading.Lock()
        self._running = False
        self._deferred: Any = None  # a raw connection to close when the running call returns
        self._after: list[Callable[[], None]] = []  # jobs to run as the running call returns
        # Cursors whose owner was cancelled. The quarantine closes them before the connection, in
        # the same locked step, so a later garbage collection never frees a statement beside it.
        self._abandoned: list[Any] = []

    def run(self, func: Callable[..., Any], /, *args: Any, **kwargs: Any) -> Any:
        with self._lock:
            with self._state:
                self._running = True
            try:
                return func(*args, **kwargs)
            finally:
                with self._state:
                    self._running = False
                    after, self._after = self._after, []
                    deferred, self._deferred = self._deferred, None
                for job in after:  # still under the lock, so before the next call and the close
                    try:
                        job()
                    except Exception:  # noqa: BLE001 - never replace the running call's outcome
                        log.warning("odbc: a job handed to a running call failed", exc_info=True)
                if deferred is not None:
                    self._close_locked(deferred, reraise=False)

    def run_after_running_call(self, job: Callable[[], None]) -> bool:
        """If a call is running, have it run ``job`` on its own thread as it returns, still inside
        the gate, and say so. Never waits. ``False`` means nothing is running, so the caller runs
        ``job`` itself, through :meth:`run`."""
        with self._state:
            if self._running:
                self._after.append(job)
            return self._running

    def abandon(self, raw_cursor: Any) -> None:
        """Hand a cancelled owner's cursor to the quarantine. Never waits: it runs on the loop.

        Call it BEFORE handing over the connection's close (:meth:`close_after_running_call` or
        :meth:`close`). A cursor abandoned after a close already drained the list stays in it, and
        the collector frees it after its connection closed."""
        self._abandoned.append(raw_cursor)

    def close_after_running_call(self, raw_conn: Any) -> bool:
        """If a call is running, have it close ``raw_conn`` as it returns, and say so. Never waits."""
        with self._state:
            if self._running:
                self._deferred = raw_conn
            return self._running

    def close(self, raw_conn: Any) -> None:
        """Close the abandoned cursors, then the connection, once no call is running on it."""
        with self._lock:
            self._close_locked(raw_conn, reraise=True)

    def _close_locked(self, raw_conn: Any, *, reraise: bool) -> None:
        while self._abandoned:
            try:
                self._abandoned.pop().close()
            except Exception:  # noqa: BLE001 - the connection close below still has to run
                log.debug("odbc: closing an abandoned cursor failed", exc_info=True)
        try:
            raw_conn.close()
        except Exception as exc:  # noqa: BLE001 - inside a call, never replace that call's outcome
            if reraise:  # a caller awaiting this close logs it in its own words
                raise
            log.warning(
                "odbc: close of a quarantined connection failed; the server may hold its"
                " transaction until the session ends: %s",
                exc,
            )


def install_call_gate(conn: Any) -> None:
    """Route every pyodbc call an aioodbc connection makes through a :class:`CallGate`. Idempotent.

    aioodbc 0.5.0 sends every call through ``Connection._execute(func, *args, **kwargs)``: cursor
    operations reach it through ``Cursor._run_operation``, and the connection's own ``cursor``,
    ``commit``, ``rollback`` and ``close`` call it directly. Wrapping that one method covers those
    calls. It does NOT cover aioodbc's ``Connection.__del__``, which closes a handle the connection
    still holds directly, on whatever thread runs the collector. So a caller abandoning a connection
    on a cancellation must also drop its ``_conn``, as the SQL Server store's detach does, rather
    than leave the close to the collector. A connection without a bound ``_execute`` (a test
    double) is left alone and keeps the pre-gate behaviour. A real aioodbc connection that cannot
    be gated is logged at ERROR, because it brings the native crash back; the store's live suite
    also pins that a pooled connection is gated.
    """
    if call_gate(conn) is not None:
        return
    execute = getattr(conn, "_execute", None)
    if not inspect.ismethod(execute):
        if type(conn).__module__.startswith("aioodbc"):
            log.error(
                "odbc: aioodbc %s has no bound _execute to gate; a cancelled call can free ODBC"
                " handles under a running statement (BACKLOG #2049)",
                type(conn).__qualname__,
            )
        return
    gate = CallGate()
    conn._execute = partial(execute, gate.run)
    conn._mefor_call_gate = gate


def call_gate(conn: Any) -> CallGate | None:
    """The gate :func:`install_call_gate` put on ``conn``, or ``None`` when it has none."""
    gate = getattr(conn, "_mefor_call_gate", None)
    return gate if isinstance(gate, CallGate) else None


def raw_closer(conn: Any, raw: Any) -> Callable[[], None]:
    """The blocking close for a discarded connection's raw handle: through its gate when it has one,
    so the close runs only between pyodbc calls (BACKLOG #2049)."""
    gate = call_gate(conn)
    return raw.close if gate is None else partial(gate.close, raw)


def abandon_one_shot(conn: Any, cur: Any) -> bool:
    """The exit of an unpooled one-shot connection when a cancellation lands during one of its
    statements (BACKLOG #2394): the pooled quarantine's rule for a connection with no pool.
    Returns whether it took the connection.

    The cursor goes to the gate, and the connection's handle is dropped at once, so aioodbc's
    ``__del__`` cannot close it outside the gate. The running call closes both as it returns,
    cursor first; with no call running, a close is scheduled through the gate. Nothing here awaits,
    so the cancellation does not wait for a statement that may be an ``ALTER DATABASE`` with no
    command timeout.

    A connection with no gate (a stand-in, or one :func:`install_call_gate` could not wrap and
    logged at ERROR) or no handle is not taken. The caller then runs :func:`close_one_shot`, which
    closes it beside the running statement: the hazard the gate exists to remove. A cursor still
    being created is not held here, so the collector frees it."""
    gate = call_gate(conn)
    raw = getattr(conn, "_conn", None)
    if gate is None or raw is None:
        return False
    _hand_off(conn, raw, _raw_cursor(cur), gate, logging.WARNING)
    return True


async def close_one_shot(conn: Any, cur: Any) -> None:
    """The normal exit of an unpooled one-shot connection: the cursor, then the connection, in one
    job on the connection's executor, through its gate (BACKLOG #2394).

    A cursor left for the collector after its connection closed is freed from wherever the
    interpreter happens to be, the native-abort shape ``tests/_live_scratch.py`` records. A failure
    is logged, not raised: a peer's ``ROLLBACK IMMEDIATE`` may already have killed the session.

    **A cancellation cannot cut the close short.** The handle is dropped before the job is
    scheduled, so aioodbc's ``__del__`` never closes it, and the job is awaited through
    :func:`asyncio.wait`, which never cancels what it waits on: the cancellation propagates at
    once, and the job still closes the cursor once, then the connection once, whether it was
    waiting for a worker or running. Its outcome is logged by the job's own callback. An ungated
    connection gets a gate of its own for the job. That gate only keeps the job's two closes in
    order: it does not serialize them against a call already running on the connection, which is
    why :func:`abandon_one_shot` does not take an ungated connection's close as safe.

    A connection or cursor with no raw handle (a stand-in) is closed through its own ``close``
    methods instead, best effort, and a cancellation can cut that short. A real aioodbc cursor
    with no ``_impl`` takes that path too, which is logged at ERROR, as an ungateable connection
    is: aioodbc renamed what this reads."""
    raw = getattr(conn, "_conn", None)
    raw_cur = _raw_cursor(cur)
    if raw is None or (cur is not None and raw_cur is None):
        await _close_through_methods(conn, cur)
        return
    closing = _hand_off(conn, raw, raw_cur, call_gate(conn) or CallGate(), logging.DEBUG)
    if closing is not None:
        await asyncio.wait((closing,))


def _raw_cursor(cur: Any) -> Any:
    """``cur``'s pyodbc cursor, or ``None``. A real aioodbc cursor without one is logged at ERROR,
    as an ungateable connection is: aioodbc renamed what this reads, and the cursor is then left
    for the collector or closed outside the one-shot job."""
    raw_cur = getattr(cur, "_impl", None)
    if raw_cur is None and cur is not None and type(cur).__module__.startswith("aioodbc"):
        log.error(
            "odbc: aioodbc %s has no _impl; a one-shot exit cannot hand its cursor to the call"
            " gate (BACKLOG #2394)",
            type(cur).__qualname__,
        )
    return raw_cur


def _hand_off(
    conn: Any, raw: Any, raw_cur: Any, gate: CallGate, level: int
) -> asyncio.Future[None] | None:
    """Give ``raw_cur`` and ``raw`` to ``gate`` to close, cursor first, and drop the connection's
    handle. The close's future, or ``None`` when the running call took it or none was scheduled."""
    if raw_cur is not None:
        gate.abandon(raw_cur)
    conn._conn = None  # first, and await-free: aioodbc's __del__ closes only a handle it holds
    if gate.close_after_running_call(raw):
        return None
    return _schedule_close(conn, partial(gate.close, raw), level)


def _schedule_close(
    conn: Any, close: Callable[[], None], level: int
) -> asyncio.Future[None] | None:
    """Run ``close`` on ``conn``'s executor, where aioodbc runs its calls, and log a failure at
    ``level``. ``None`` when the executor refused the work, at loop teardown: pyodbc then closes
    the handle when it is collected."""
    loop = asyncio.get_running_loop()  # outside the try: no loop is a caller's bug, not teardown
    try:
        closing = loop.run_in_executor(getattr(conn, "_executor", None), close)
    except RuntimeError:  # the executor is shut down; see the docstring
        log.warning(
            "odbc: could not schedule the close of a one-shot connection; it closes when collected",
            exc_info=True,
        )
        return None
    closing.add_done_callback(partial(_log_close_failure, level))
    return closing


def _log_close_failure(level: int, fut: asyncio.Future[None]) -> None:
    exc = None if fut.cancelled() else fut.exception()
    if exc is not None:
        log.log(level, "odbc: close of a one-shot connection failed: %s", exc, exc_info=exc)


async def _close_through_methods(conn: Any, cur: Any) -> None:
    for handle in (cur, conn):
        if handle is not None:
            try:
                await handle.close()
            except Exception:  # noqa: BLE001 - best effort; the caller's own outcome stands
                log.debug("odbc: one-shot close failed", exc_info=True)
