# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Keep a listener on the Windows Proactor loop alive when a peer drops one connection.

**The stdlib defect.** On ``asyncio.ProactorEventLoop``, the accept loop that
``asyncio.start_server`` and ``loop.create_server`` run (``BaseProactorEventLoop._start_serving``)
closes its LISTENING socket on the first accept that fails with ``OSError``. ``AcceptEx`` fails that
way when a peer connects and then resets its connection while it waits in the backlog: Windows
reports ERROR_NETNAME_DELETED (winerror 64), which CPython raises as a plain ``OSError`` whose errno
is EINVAL. Read on CPython 3.14.7: ``proactor_events.py`` ``_start_serving``, the ``except OSError``
arm of its ``loop`` closure, and ``windows_events.py`` ``IocpProactor.accept``, whose
``finish_accept`` calls ``ov.getresult()``. The server still reads as serving, and nothing accepts
on that port again. So one TCP health probe that closes with a reset, or one connect scan, would
stop every engine listener on the loop for good: MLLP, the HTTP listener, TCP, X12, and the API
uvicorn serves. The selector loops do not have this defect: their accept loop stays registered
after a failed accept.

**The guard.** :func:`guard_accepts` wraps the loop's own proactor ``accept`` so that an accept the
PEER ended is posted again instead of failing. Every other failure reaches the stdlib accept loop
unchanged, so a listening socket that is itself gone still stops it as before. It is per loop and
idempotent, and does nothing on any other loop. It rests on at least three things the stdlib does
not document: the loop's ``_proactor`` attribute; its ``accept(listener)`` method, which returns a
future of ``(conn, address)``; and that ``accept`` starts its helper task (below) through
``loop.create_task``. If ``_proactor`` is missing, the guard logs a WARNING and installs nothing.
``tests/test_proactor_accept.py`` pins the defect without the guard, and the fix and the single
report with it, so a stdlib change to any of the three fails a test rather than passing silently.

A skipped connection is logged at DEBUG only, so a peer resetting connections cannot fill the log.
It carried no message: it was dropped before it was accepted. The stdlib's accept also starts a
helper task that fails with every failed accept and would report it a second time, as "Task
exception was never retrieved"; :func:`_post` marks that task's exception read.
"""

from __future__ import annotations

import asyncio
import logging
import socket
import sys
from collections.abc import Callable
from typing import Any

from messagefoundry.redaction import safe_exc

logger = logging.getLogger(__name__)

#: The Windows codes AcceptEx reports for a connection its peer dropped before the accept finished:
#: ERROR_NETNAME_DELETED and ERROR_CONNECTION_ABORTED. CPython maps both to errno EINVAL.
_PEER_DROPPED_WINERRORS = frozenset({64, 1236})

#: Marks the wrapper this module installs as a proactor's ``accept``, so a second call is a no-op.
_GUARDED = "_messagefoundry_accept_guard"

type _Accept = Callable[[socket.socket], asyncio.Future[tuple[socket.socket, Any]]]


def _peer_dropped(exc: BaseException) -> bool:
    """Whether a failed accept is the peer's own dropped connection, not a fault of the listener."""
    if isinstance(exc, ConnectionError):
        return True
    return isinstance(exc, OSError) and getattr(exc, "winerror", None) in _PEER_DROPPED_WINERRORS


def _retrieve(task: asyncio.Future[Any]) -> None:
    """Mark a finished helper task's exception as read. The same failure reaches the caller through
    the accept future, so the task's own "never retrieved" report would only repeat it."""
    if not task.cancelled():
        task.exception()


def _post(
    loop: asyncio.AbstractEventLoop, accept: _Accept, listener: socket.socket
) -> asyncio.Future[tuple[socket.socket, Any]]:
    """One ``accept(listener)``, with the helper task it starts marked to have its exception read.

    ``IocpProactor.accept`` starts a task that only closes the accept socket on cancellation, and
    that task fails with every failed accept. The task is caught by a task factory set for the
    length of the call; the call is synchronous, on the loop's thread, so it starts no other task.
    """
    previous = loop.get_task_factory()
    started: list[asyncio.Future[Any]] = []

    def capture(loop: asyncio.AbstractEventLoop, coro: Any, **kwargs: Any) -> asyncio.Future[Any]:
        task: asyncio.Future[Any] = (
            previous(loop, coro, **kwargs)
            if previous is not None
            else asyncio.Task(coro, loop=loop, **kwargs)
        )
        started.append(task)
        return task

    loop.set_task_factory(capture)
    try:
        inner = accept(listener)
    finally:
        loop.set_task_factory(previous)
    for task in started:
        task.add_done_callback(_retrieve)
    return inner


def _guarded(loop: asyncio.AbstractEventLoop, accept: _Accept) -> _Accept:
    """``accept``, posted again for as long as each try ends in a peer-dropped connection on a
    listening socket that is still open. The future it returns settles as the first other outcome
    does, and cancelling it cancels the try in flight."""

    def guarded_accept(listener: socket.socket) -> asyncio.Future[tuple[socket.socket, Any]]:
        outer: asyncio.Future[tuple[socket.socket, Any]] = loop.create_future()
        # The first post raises synchronously, as the unguarded call does, so the stdlib accept
        # loop's own handling of a listener that cannot accept at all is unchanged.
        current = _post(loop, accept, listener)

        def settle(inner: asyncio.Future[tuple[socket.socket, Any]]) -> None:
            nonlocal current
            if outer.done():
                return
            if inner.cancelled():
                outer.cancel()
                return
            exc = inner.exception()
            if exc is None:
                outer.set_result(inner.result())
                return
            if not _peer_dropped(exc) or listener.fileno() == -1:
                outer.set_exception(exc)
                return
            if logger.isEnabledFor(logging.DEBUG):  # a peer chooses how often this runs
                logger.debug(
                    "listener on %r skipped a connection its peer dropped before the accept: %s",
                    listener.getsockname(),
                    safe_exc(exc),
                )
            try:
                current = _post(loop, accept, listener)
            except OSError as again:
                # Posting the next accept failed: report that, as the stdlib loop would have.
                outer.set_exception(again)
                return
            current.add_done_callback(settle)

        def cancel_inner(done: asyncio.Future[tuple[socket.socket, Any]]) -> None:
            if done.cancelled():
                current.cancel()

        current.add_done_callback(settle)
        outer.add_done_callback(cancel_inner)
        return outer

    setattr(guarded_accept, _GUARDED, True)
    return guarded_accept


def guard_accepts(loop: asyncio.AbstractEventLoop | None = None) -> None:
    """Install the accept guard on ``loop`` (default: the running loop) if it is a stdlib
    ``ProactorEventLoop``. Call it before the loop's first listener starts; a listener started
    earlier keeps the unguarded accept until its next accept is posted. Idempotent."""
    if sys.platform != "win32":
        return
    loop = loop or asyncio.get_running_loop()
    if not isinstance(loop, asyncio.ProactorEventLoop):
        return
    proactor = getattr(loop, "_proactor", None)
    accept = getattr(proactor, "accept", None)
    if not callable(accept):
        logger.warning(
            "the Proactor accept guard found no proactor accept on %s; one peer reset can stop "
            "this loop's listeners",
            type(loop).__name__,
        )
        return
    if getattr(accept, _GUARDED, False):
        return
    proactor.accept = _guarded(loop, accept)  # type: ignore[union-attr,unused-ignore]
