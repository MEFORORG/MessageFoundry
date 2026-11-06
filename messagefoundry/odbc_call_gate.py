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
cursor's ``_impl``, as aioodbc 0.5.0 names them. ``pyproject.toml`` pins aioodbc to that release
for this reason (BACKLOG #5005). For the call gate, a cursor's ``_impl`` is read only in
:func:`raw_cursor`, so the DATABASE connector and the store's pooled cursor read it one way. Other
readers outside the gate remain, at least the store's ``_sync_setinputsizes`` (ADR 0114), so a move
of the pin still greps the engine for the name. Where a real aioodbc object
lacks a name the gate needs, ERROR is logged once per process for each type, not on every borrow.
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
    "drop_handle",
    "install_call_gate",
    "raw_closer",
    "raw_cursor",
    "report_once",
]

log = logging.getLogger(__name__)

#: The (check, type) pairs already reported by :func:`report_once` in this process.
_REPORTED: set[tuple[str, str]] = set()


def report_once(check: str, obj: Any, message: str) -> None:
    """Log ``message`` at ERROR the first time ``check`` fails for ``obj``'s type, and never again
    for that pair (BACKLOG #5005). ``message`` takes the type's name as its one ``%s``. A pool
    borrows on every send, so logging each time buried the one line that matters under copies of
    it; the condition is a property of the installed aioodbc, so one line says it all."""
    name = type(obj).__qualname__
    key = (check, f"{type(obj).__module__}.{name}")
    if key in _REPORTED:
        return
    _REPORTED.add(key)
    log.error(message + "; logged once per process", name)


def drop_handle(conn: Any) -> Any:
    """Take ``conn``'s pyodbc connection off it and return that, or ``None`` when it has none.

    A plain attribute write, so a caller can make it before any await. aioodbc 0.5.0 derives
    ``Connection.closed`` from ``_conn``, so its pool never lends a connection with none again, and
    its ``__del__`` closes only a handle the connection still holds."""
    raw = getattr(conn, "_conn", None)
    if raw is not None:
        conn._conn = None
    return raw


class _Call:
    """One call :meth:`CallGate.submit` handed to aioodbc. ``abandoned`` is written on the loop and
    read on the worker thread, both under the gate's ``_state`` lock."""

    __slots__ = ("abandoned",)

    def __init__(self) -> None:
        self.abandoned = False


def _close_orphaned_cursor(func: Callable[..., Any], result: Any) -> None:
    """Under the gate's lock, as a cancelled call returns: close the cursor it made, if it made one.

    Its awaiting future was cancelled, so the result reaches nobody, and aioodbc never wraps it.
    Left alone, the collector would free it from wherever the interpreter happens to be, possibly
    after its connection closed: the native-abort shape ``tests/_live_scratch.py`` records. The
    result is the key, not the call's name: of what pyodbc returns, only a cursor has ``close``, and
    a NEW one is any but the call's own (``Cursor.execute`` returns its cursor, which is its owner's
    to close). Never raises."""
    if result is None or result is getattr(func, "__self__", None):
        return
    close = getattr(result, "close", None)
    if not callable(close):
        return
    try:
        close()
    except Exception:  # noqa: BLE001 - never replace the cancelled call's outcome
        log.debug("odbc: closing a cancelled call's new cursor failed", exc_info=True)


def _skippable(func: Callable[..., Any]) -> bool:
    """Whether an abandoned call that never entered the gate may be skipped: any but a close
    (``Connection.close``, ``Cursor.close``), which frees a handle and must still run in the gate."""
    return getattr(func, "__name__", None) != "close"


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

    **A call aioodbc submits is tracked from its submission, not from when it starts** (BACKLOG
    #2394). A cancellation can land after aioodbc handed a call to its executor and before that
    call took the lock: queued for a worker, picked up, or waiting behind another call. That call
    was not running, so a cleanup's close was not handed to it, and the two raced for the lock: the
    close could win, and the call then ran on the handle it had freed, or on a connection already
    lent to its next borrower. Now a call whose awaiting future was cancelled before it entered
    never runs, as an executor already skips one it cancels before a worker takes it: nothing
    awaits its result, and the cancelled task's cleanup reads the gate after the mark is made
    (:meth:`submit` says why). A ``close`` is the exception: it still runs, inside the gate,
    because skipping it would leave its handle for aioodbc's ``__del__`` or the collector, outside
    the gate; a close of a handle a cleanup already closed only fails, and nobody awaits that. One
    that had entered runs to its end, and a cursor it makes is closed as it returns, since nobody
    else ever holds it.
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
        """Run ``func`` inside the gate, on the calling thread. Never skipped: the engine's own
        jobs (a hand-off's close, a settled cursor close) call this, and nothing cancels them."""
        return self._run(None, func, *args, **kwargs)

    def submit(
        self, execute: Callable[..., Any], func: Callable[..., Any], /, *args: Any, **kwargs: Any
    ) -> Any:
        """aioodbc's ``Connection._execute``, through the gate: ``execute`` is the connection's own
        bound ``_execute``, which hands the call to its executor. :func:`install_call_gate` installs
        this in its place.

        The call is marked abandoned when the future ``execute`` returns is cancelled, which is
        what a cancellation of the task awaiting it does. That mark is a done callback added here,
        before the caller awaits the future, so the loop runs it before the cancelled task resumes:
        any cleanup that task runs reads the gate with the mark already made. A future with no
        ``add_done_callback`` (a stand-in's) is not tracked, and its calls run as :meth:`run`'s do.
        """
        call = _Call()
        fut = execute(self._run, call, func, *args, **kwargs)
        add_done_callback = getattr(fut, "add_done_callback", None)
        if callable(add_done_callback):
            add_done_callback(partial(self._abandon_if_cancelled, call))
        return fut

    def _abandon_if_cancelled(self, call: _Call, fut: Any) -> None:
        """On the loop: mark ``call`` abandoned once its awaiting future was cancelled."""
        if fut.cancelled():
            with self._state:
                call.abandoned = True

    def _run(
        self, call: _Call | None, func: Callable[..., Any], /, *args: Any, **kwargs: Any
    ) -> Any:
        with self._lock:
            with self._state:
                if call is not None and call.abandoned and _skippable(func):
                    # Cancelled before it entered: nobody awaits it, so it never runs.
                    return None
                self._running = True
            result = None
            try:
                result = func(*args, **kwargs)
                return result
            finally:
                with self._state:
                    self._running = False
                    orphaned = call is not None and call.abandoned
                    after = self._after
                    if after:  # a new list only after a hand-off, not on every call
                        self._after = []
                    deferred, self._deferred = self._deferred, None
                if orphaned:  # first: a cursor closes before any connection close below
                    _close_orphaned_cursor(func, result)
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
    be gated is logged at ERROR, because it brings the native crash back. That is logged once per
    process for its type, not on every borrow (BACKLOG #5005); every later borrow of such a
    connection goes ungated just the same. The store's live suite also pins that a pooled
    connection is gated.
    """
    if call_gate(conn) is not None:
        return
    execute = getattr(conn, "_execute", None)
    if not inspect.ismethod(execute):
        if type(conn).__module__.startswith("aioodbc"):
            report_once(
                "_execute",
                conn,
                "odbc: aioodbc %s has no bound _execute to gate; a cancelled call can free ODBC"
                " handles under a running statement (BACKLOG #2049), and no connection of this"
                " type is gated",
            )
        return
    gate = CallGate()
    conn._execute = partial(gate.submit, execute)
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
    being created when the cancellation landed is not held here; the gate closes it as its
    ``cursor()`` call returns, before the connection close handed to that call (BACKLOG #2394)."""
    gate = call_gate(conn)
    raw = getattr(conn, "_conn", None)
    if gate is None or raw is None:
        return False
    _hand_off(conn, raw, raw_cursor(cur), gate, logging.WARNING)
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
    raw_cur = raw_cursor(cur)
    if raw is None or (cur is not None and raw_cur is None):
        await _close_through_methods(conn, cur)
        return
    closing = _hand_off(conn, raw, raw_cur, call_gate(conn) or CallGate(), logging.DEBUG)
    if closing is not None:
        await asyncio.wait((closing,))


def raw_cursor(cur: Any) -> Any:
    """``cur``'s pyodbc cursor (aioodbc 0.5.0's ``_impl``), or ``None``: the one place the engine
    reads that name for the call gate (BACKLOG #5005).

    ``None`` sends the caller to its fallback, which closes the cursor through its own ``close()``
    outside the gate, or leaves it to the collector. A test double takes that path silently. A
    real aioodbc cursor without one is logged at ERROR, once per process for its type, as an
    ungateable connection is: aioodbc renamed what this reads, so every such cursor takes the
    fallback."""
    raw_cur = getattr(cur, "_impl", None)
    if raw_cur is None and cur is not None and type(cur).__module__.startswith("aioodbc"):
        report_once(
            "_impl",
            cur,
            "odbc: aioodbc %s has no _impl; its cursors are closed outside the call gate, beside"
            " any call still running (BACKLOG #2394)",
        )
    return raw_cur


def _hand_off(
    conn: Any, raw: Any, raw_cur: Any, gate: CallGate, level: int
) -> asyncio.Future[None] | None:
    """Give ``raw_cur`` and ``raw`` to ``gate`` to close, cursor first, and drop the connection's
    handle. The close's future, or ``None`` when the running call took it or none was scheduled."""
    if raw_cur is not None:
        gate.abandon(raw_cur)
    drop_handle(conn)  # first, and await-free: aioodbc's __del__ closes only a handle it holds
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
