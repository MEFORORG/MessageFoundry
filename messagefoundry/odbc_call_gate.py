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
probe connections. The detach that quarantines a cancelled pooled connection stays in the store,
because it is the pool's rule, not the gate's.

Standard library only: nothing here imports aioodbc or pyodbc. It recognises an aioodbc connection
by its bound ``_execute`` method.
"""

from __future__ import annotations

import inspect
import logging
import threading
from collections.abc import Callable
from functools import partial
from typing import Any

__all__ = ["CallGate", "call_gate", "install_call_gate", "raw_closer"]

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

    __slots__ = ("_abandoned", "_deferred", "_lock", "_running", "_state")

    def __init__(self) -> None:
        self._lock = threading.Lock()  # held for the whole of each pyodbc call
        # Guards the two fields below. Held only for a few bytecodes, so the event loop may take it.
        self._state = threading.Lock()
        self._running = False
        self._deferred: Any = None  # a raw connection to close when the running call returns
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
                    deferred, self._deferred = self._deferred, None
                if deferred is not None:
                    self._close_locked(deferred, reraise=False)

    def abandon(self, raw_cursor: Any) -> None:
        """Hand a cancelled owner's cursor to the quarantine. Never waits: it runs on the loop."""
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
    ``commit``, ``rollback`` and ``close`` call it directly. Wrapping that one method covers them
    all. A connection without a bound ``_execute`` (a test double) is left alone and keeps the
    pre-gate behaviour. A real aioodbc connection that cannot be gated is logged at ERROR, because
    it brings the native crash back; the store's live suite also pins that a pooled connection is
    gated.
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
