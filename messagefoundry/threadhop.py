# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A worker-thread hop that falls back to the event loop when the default executor refuses it.

:func:`to_thread_or_loop` is :func:`asyncio.to_thread` for a hop whose work must still happen
when the loop's default executor cannot run it: shut down, a broken pool, or no thread it could
start. A reload's rollback is the case it exists for. A refused hop there used to abort the
rollback before the previous graph's inbounds were back up, and a refused hop in the forward
reload failed a reload the graph could have taken (BACKLOG #5755, items 3 to 5).

The fallback blocks the loop for as long as the work takes, which is what the work did before it
left the loop, so it is logged at WARNING every time. It is not for a network call, author or
embedder code, or anything whose result changes when it runs on the loop thread. A file read can
still stall on an unreachable share, and a call site that takes that trade says so. The runner's connector builds have their own copy of this fallback, which also closes
what a cancelled build made (``_build_off_loop`` in :mod:`messagefoundry.pipeline.wiring_runner`).

**Keep this a leaf.** It imports the stdlib and :mod:`messagefoundry.redaction` only, so
``transports/``, ``auth/`` and ``pipeline/`` can all import it."""

from __future__ import annotations

import asyncio
import concurrent.futures
import contextvars
import functools
import logging
from collections.abc import Callable
from contextlib import suppress

from messagefoundry.redaction import safe_exc

__all__ = ["to_thread_or_loop"]

log = logging.getLogger(__name__)


async def to_thread_or_loop[**P, T](
    what: str, func: Callable[P, T], /, *args: P.args, **kwargs: P.kwargs
) -> T:
    """``func(*args, **kwargs)`` in the default executor, in a copy of the caller's context, as
    :func:`asyncio.to_thread` runs it, or on the event loop when the executor never began it.
    ``what`` names the hop in the WARNING; it comes first so ``kwargs`` stay ``func``'s own.

    The executor never began it when it refused the work at submit, or cancelled or failed it
    while it was queued, for example in ``shutdown(cancel_futures=True)``. ``func`` then runs on
    the loop instead, with a WARNING naming ``what`` and the executor's fault, and its own result
    or refusal is the answer. ``func`` never began in those cases, so it never runs twice. A pool
    that queued the work and then failed to start a thread for it raises at submit: the work is
    cancelled first, so a later dequeue runs nothing, or, if a worker already took it, its own
    outcome is awaited. Work queued behind a busy or hung pool has not been refused, so the caller
    waits for it.

    A cancellation of the caller cancels work still queued, so it never runs. Work already running
    finishes in its thread, as with :func:`asyncio.to_thread`. A fault in the WARNING itself, such
    as a raising log filter, never stops or strands the work (:func:`_warn_refused`)."""
    loop = asyncio.get_running_loop()
    context = contextvars.copy_context()
    call = functools.partial(func, *args, **kwargs)
    result: concurrent.futures.Future[T] = concurrent.futures.Future()

    def run() -> None:
        if not result.set_running_or_notify_cancel():
            return  # cancelled while queued: it never runs
        try:
            value = context.run(call)
        except BaseException as exc:  # noqa: BLE001 - handed to the awaiting caller, not swallowed
            result.set_exception(exc)
        else:
            result.set_result(value)

    def settle(queued: asyncio.Future[None]) -> None:
        # Work the executor cancelled or failed before run() began leaves ``result`` pending; run
        # it here, on the loop, so the caller is not left waiting. The fault is read even when
        # ``result`` is done, so asyncio never logs it as an exception nobody retrieved.
        fault = None if queued.cancelled() else queued.exception()
        if result.done():
            return
        if fault is not None and not isinstance(fault, Exception):
            result.set_exception(fault)  # a BaseException that is not an Exception passes through
            return
        try:
            _warn_refused(loop, what, fault)
        finally:
            run()

    try:
        queued = loop.run_in_executor(None, run)
    except RuntimeError as exc:  # the executor was shut down, or its pool is broken
        refused = result.cancel()
        _warn_refused(loop, what, exc, taken=not refused)
    else:
        refused = False
        queued.add_done_callback(settle)
    if refused:
        # Outside the handler, so a refusal ``func`` raises does not carry the executor's fault
        # as its context.
        return context.run(call)
    return await asyncio.wrap_future(result, loop=loop)


def _warn_refused(
    loop: asyncio.AbstractEventLoop,
    what: str,
    fault: BaseException | None,
    *,
    taken: bool = False,
) -> None:
    """Log the WARNING :func:`to_thread_or_loop` gives for an executor ``fault`` (``None`` for a
    cancellation) that met ``what``: that it runs on the loop instead, or, when ``taken``, that a
    worker already took it and its own outcome stands.

    It never raises an Exception. A fault in it goes to ``loop``'s exception handler, naming the
    executor's fault by type alone, so the executor's text is not logged unredacted."""
    try:
        cause = f"the executor cancelled the {what}" if fault is None else safe_exc(fault)
        if taken:
            log.warning(
                "the executor failed after a worker took the %s; its own outcome stands: %s",
                what,
                cause,
            )
        else:
            log.warning(
                "the executor never began the %s, so it runs on the event loop: %s", what, cause
            )
    except Exception as log_fault:  # noqa: BLE001 - reported to the loop's handler below
        log_fault.__suppress_context__ = True
        kind = "a cancellation" if fault is None else type(fault).__name__
        with suppress(Exception):
            loop.call_exception_handler(
                {
                    "message": f"the WARNING about the {what} failed to log; the executor's "
                    f"fault: {kind}",
                    "exception": log_fault,
                }
            )
