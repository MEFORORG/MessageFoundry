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
on that port again. So one TCP health probe that closes with a reset would stop the listener it
probed for good, and a connect scan would stop each listener it touched. Every engine listener on
the loop is exposed: MLLP, the HTTP listener, TCP, X12, and the API uvicorn serves. The selector
loops do not have this defect: their accept loop stays registered after a failed accept.

**The guard.** :func:`guard_accepts` wraps the loop's own proactor ``accept`` so that an accept the
PEER ended is posted again instead of failing, whether ``AcceptEx`` reports it through the
completion port or at once. Every other failure reaches the stdlib accept loop unchanged, so a
listening socket that is itself gone still stops it as before. It is per loop and idempotent, and
does nothing on any other loop. It rests on at least three things the stdlib does not document: the
loop's ``_proactor`` attribute; its ``accept(listener)`` method, which returns a future of
``(conn, address)``; and that ``accept`` starts its helper task (below) through
``loop.create_task``, with the accept socket among its arguments. If ``_proactor`` is missing, the
guard logs a WARNING and installs nothing. ``tests/test_proactor_accept.py`` pins the defect without
the guard, and the fix and the single report with it.

A skipped connection is logged at DEBUG, and one WARNING marks each run of ``_SKIP_WARN_EVERY`` in a
row, so a peer resetting connections cannot fill the log and a fault that only looks like a peer's
is still seen. It carried no message: it was dropped before it was accepted. The guard closes the
accept socket a failed try leaves, which the stdlib closes only on cancellation. The stdlib's
accept also starts a helper task that fails with every failed accept and would report it a second
time, as "Task exception was never retrieved"; :func:`_post` marks that task's exception read.
"""

from __future__ import annotations

import asyncio
import inspect
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

#: Every this many connections in a row that one accept skips, it logs a WARNING.
_SKIP_WARN_EVERY = 100

#: Marks the wrapper this module installs as a proactor's ``accept``, so a second call is a no-op.
_GUARDED = "_messagefoundry_accept_guard"

type _Accepted = asyncio.Future[tuple[socket.socket, Any]]
type _Accept = Callable[[socket.socket], _Accepted]


def _peer_dropped(exc: BaseException) -> bool:
    """Whether a failed accept is the peer's own dropped connection, not a fault of the listener."""
    if isinstance(exc, ConnectionError):
        return True
    return isinstance(exc, OSError) and getattr(exc, "winerror", None) in _PEER_DROPPED_WINERRORS


def _retrieve(task: asyncio.Future[Any]) -> None:
    """Mark a finished helper task's exception as read. The failure is the accept's own, which
    :func:`_guarded` passes on, skips with a log line, or drops because the accept was cancelled and
    nothing waits on it; the task's report would only repeat it."""
    if not task.cancelled():
        task.exception()


def _post(
    loop: asyncio.AbstractEventLoop, accept: _Accept, listener: socket.socket
) -> tuple[_Accepted, list[socket.socket]]:
    """One ``accept(listener)``, and the accept sockets its helper task holds.

    ``IocpProactor.accept`` starts a task that only closes the accept socket on cancellation, and
    that task fails with every failed accept. The task is caught by a task factory set for the
    length of the call; the call is synchronous, on the loop's thread, so it starts no other task.
    Its exception is marked read, and the sockets among its arguments are returned for the caller
    to close if the accept fails.
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
    held: list[socket.socket] = []
    for task in started:
        task.add_done_callback(_retrieve)
        coro = task.get_coro() if isinstance(task, asyncio.Task) else None
        if inspect.iscoroutine(coro):
            held.extend(
                value
                for value in inspect.getcoroutinelocals(coro).values()
                if isinstance(value, socket.socket) and value is not listener
            )
    return inner, held


def _guarded(loop: asyncio.AbstractEventLoop, accept: _Accept) -> _Accept:
    """``accept``, posted again for as long as each try ends in a peer-dropped connection on a
    listening socket that is still open. The future it returns settles as the first other outcome
    does, and cancelling it cancels the try in flight."""

    def guarded_accept(listener: socket.socket) -> _Accepted:
        outer: _Accepted = loop.create_future()
        skips = 0

        def skip(exc: BaseException) -> None:
            nonlocal skips
            skips += 1
            if skips % _SKIP_WARN_EVERY == 0:
                logger.warning(
                    "listener on %r skipped %d connections in a row that read as dropped by their "
                    "peers before the accept; the last: %s",
                    listener.getsockname(),
                    skips,
                    safe_exc(exc),
                )
            elif logger.isEnabledFor(logging.DEBUG):  # a peer chooses how often this runs
                logger.debug(
                    "listener on %r skipped a connection its peer dropped before the accept: %s",
                    listener.getsockname(),
                    safe_exc(exc),
                )

        def post() -> tuple[_Accepted, list[socket.socket]]:
            # AcceptEx can report a peer's reset at once, as well as through the completion port.
            # Any other synchronous failure raises, as the unguarded call does, so the stdlib
            # accept loop's own handling of a listener that cannot accept at all is unchanged.
            while True:
                try:
                    return _post(loop, accept, listener)
                except OSError as exc:
                    if not _peer_dropped(exc) or listener.fileno() == -1:
                        raise
                    skip(exc)

        current, held = post()

        def settle(inner: _Accepted) -> None:
            nonlocal current, held
            if inner.cancelled():  # the helper task closes the accept socket on cancellation
                outer.cancel()
                return
            exc = inner.exception()
            if exc is not None or outer.done():
                # A failed try's socket, or a connection accepted after the caller cancelled: no
                # transport will own either, and the stdlib closes neither.
                for sock in held:
                    sock.close()
            if outer.done():
                return
            if exc is None:
                outer.set_result(inner.result())
                return
            if not _peer_dropped(exc) or listener.fileno() == -1:
                outer.set_exception(exc)
                return
            skip(exc)
            try:
                current, held = post()
            except OSError as again:
                # Posting the next accept failed: report that, as the stdlib loop would have.
                outer.set_exception(again)
                return
            current.add_done_callback(settle)

        def cancel_inner(done: _Accepted) -> None:
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
            "a listener on this loop",
            type(loop).__name__,
        )
        return
    if getattr(accept, _GUARDED, False):
        return
    proactor.accept = _guarded(loop, accept)  # type: ignore[union-attr,unused-ignore]
