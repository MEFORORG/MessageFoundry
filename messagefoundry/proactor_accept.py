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
probed for good, and a connect scan would stop each listener it touched. Every listener on the loop
is exposed, at least the MLLP, HTTP, TCP and X12 sources and the API uvicorn serves. The selector
loops do not have this defect: their accept loop stays registered after a failed accept.

**The guard.** :func:`guard_accepts` wraps the loop's own proactor ``accept`` so that an accept the
PEER ended is posted again instead of failing, whether ``AcceptEx`` reports it through the
completion port or at once. A re-post after an immediate failure waits for the loop's next
iteration, so a failure that repeats cannot hold the loop. Every other failure reaches the stdlib
accept loop unchanged, so a listening socket that is itself gone still stops it as before. It is
per loop and idempotent, and does nothing on any other loop. It rests on at least three things the
stdlib does not document: the loop's ``_proactor`` attribute; its ``accept(listener)`` method, which
returns a future of ``(conn, address)``; and that ``accept`` starts its helper task (below) through
``loop.create_task``, with the accept socket among its arguments. If ``_proactor`` is missing, the
guard logs a WARNING and installs nothing. ``tests/test_proactor_accept.py`` pins the defect without
the guard, and the fix, the closed socket and the single report with it.

A skipped connection is logged at DEBUG. A run of ``_SKIP_WARN_EVERY`` in a row logs a WARNING, at
most once per ``_WARN_INTERVAL`` seconds on a loop, so a peer resetting connections cannot fill the
log and a fault that only looks like a peer's is still seen. A skipped connection carried no
message: it was dropped before it was accepted. The guard closes the accept socket a failed try
leaves, which the stdlib closes only on cancellation; it finds that socket among the helper task's
arguments, or in the frames of an immediate failure, so a helper that has already finished when it
is started, as under an eager task factory, leaves it to the garbage collector as the stdlib does.
The helper task also fails with every failed accept and would report it a second time, as "Task
exception was never retrieved"; :func:`_post` marks that task's exception read.
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import socket
import sys
from collections.abc import Callable
from types import TracebackType
from typing import Any

from messagefoundry.redaction import safe_exc

logger = logging.getLogger(__name__)

#: The Windows codes AcceptEx reports for a connection its peer dropped before the accept finished:
#: ERROR_NETNAME_DELETED and ERROR_CONNECTION_ABORTED. CPython maps both to errno EINVAL.
_PEER_DROPPED_WINERRORS = frozenset({64, 1236})

#: A run of this many connections in a row that one accept skips is worth a WARNING.
_SKIP_WARN_EVERY = 100

#: The fewest seconds between two such WARNINGs on one loop.
_WARN_INTERVAL = 60.0

#: Marks the wrapper this module installs as a proactor's ``accept``, so a second call is a no-op.
_GUARDED = "_messagefoundry_accept_guard"

type _Accepted = asyncio.Future[tuple[socket.socket, Any]]
type _Accept = Callable[[socket.socket], _Accepted]


def _peer_dropped(exc: BaseException) -> bool:
    """Whether a failed accept is the peer's own dropped connection, not a fault of the listener:
    a reset or an abort, as the selector loop's accept skips too, or their Windows codes."""
    if isinstance(exc, (ConnectionResetError, ConnectionAbortedError)):
        return True
    return isinstance(exc, OSError) and getattr(exc, "winerror", None) in _PEER_DROPPED_WINERRORS


def _close_sockets_in(tb: TracebackType | None, listener: socket.socket) -> None:
    """Close each socket but ``listener`` that the frames of an immediate accept failure hold: the
    accept socket ``IocpProactor.accept`` made before ``AcceptEx`` raised, which nothing else
    closes."""
    while tb is not None:
        for value in tb.tb_frame.f_locals.values():
            if isinstance(value, socket.socket) and value is not listener:
                value.close()
        tb = tb.tb_next


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
    to close if the accept fails. An immediate failure raises, with its accept socket closed.
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
    except OSError as exc:
        _close_sockets_in(exc.__traceback__, listener)
        raise
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
    last_warned: float | None = None

    def guarded_accept(listener: socket.socket) -> _Accepted:
        outer: _Accepted = loop.create_future()
        skips = 0
        current: _Accepted | None = None
        held: list[socket.socket] = []

        def skip(exc: BaseException) -> None:
            nonlocal skips, last_warned
            skips += 1
            now = loop.time()
            if skips >= _SKIP_WARN_EVERY and (
                last_warned is None or now - last_warned >= _WARN_INTERVAL
            ):
                last_warned = now
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

        def attempt() -> None:
            """Post the next try, on a later iteration than an immediate failure it follows."""
            nonlocal current, held
            if outer.done():
                return
            try:
                current, held = _post(loop, accept, listener)
            except OSError as exc:
                if _peer_dropped(exc) and listener.fileno() != -1:
                    skip(exc)
                    loop.call_soon(attempt)
                else:
                    # Posting the next accept failed: report that, as the stdlib loop would have.
                    outer.set_exception(exc)
                return
            current.add_done_callback(settle)

        def settle(inner: _Accepted) -> None:
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
            elif _peer_dropped(exc) and listener.fileno() != -1:
                skip(exc)
                attempt()
            else:
                outer.set_exception(exc)

        def cancel_inner(done: _Accepted) -> None:
            if done.cancelled() and current is not None:
                current.cancel()

        # The first post raises an immediate failure that is not a peer's, as the unguarded call
        # does, so the stdlib accept loop's own handling of a listener that cannot accept at all
        # is unchanged.
        try:
            current, held = _post(loop, accept, listener)
        except OSError as exc:
            if not _peer_dropped(exc) or listener.fileno() == -1:
                raise
            skip(exc)
            loop.call_soon(attempt)
        else:
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
