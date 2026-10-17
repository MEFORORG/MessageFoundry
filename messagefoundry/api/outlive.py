# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Long operations that outlive the HTTP request that started them (vault BACKLOG #2751-#2753).

:class:`~messagefoundry.api.request_timeout.RequestTimeoutMiddleware` cancels a handler that has not
begun responding within its deadline. For most routes that is the point. For a DR activation, a DR
release and a config reload it is not: each stops and restarts listeners and changes state the
engine reports, and a cancellation partway through would leave that state half changed with no
outcome audit row. So those routes run the operation through :meth:`OutlivingOperations.run`. The
deadline still ends the RESPONSE (the caller gets the middleware's 503), and the operation finishes
on its own and writes its own outcome row. A DR retry meets the coordinator's lock and then the
first call's outcome, not a half-applied state. A config reload retry is a second reload: it waits
on the runner's reload lock and then runs again.

It is the same shape as :func:`~messagefoundry.api.approvals._outlive_caller`, which it reuses, rather
than an exemption from the deadline: an exempt route would hold its worker for as long as it ran,
which is the thing the deadline exists to stop. The web console's ``/ui`` routes call the same
handlers in process, so they get the same protection.

The managed lifespan calls :meth:`OutlivingOperations.drain` before ``engine.stop()``. What is still
running then is cancelled, and each operation's own cancellation arm restores its state and records
an ``interrupted`` outcome while the store is still open.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from contextvars import ContextVar
from typing import Any

from messagefoundry.api.approvals import _outlive_caller
from messagefoundry.pipeline.dr import _HOOK_REAP_SECONDS
from messagefoundry.redaction import safe_exc

__all__ = [
    "CANCEL_GRACE_SECONDS",
    "DRAIN_TIMEOUT_SECONDS",
    "OutlivingOperations",
    "cancel_grace_left",
]

log = logging.getLogger(__name__)

#: How long :meth:`OutlivingOperations.drain` lets a running operation finish at shutdown before it
#: cancels it. It shares NSSM's 15 s graceful-stop window with the other shutdown steps, so it is
#: short; an operation it cancels records ``interrupted``. The API lifespans pass at most this, and
#: less when their shutdown budget is short (``_SHUTDOWN_BUDGET_SECONDS`` in ``api/app.py``).
DRAIN_TIMEOUT_SECONDS = 0.5

#: How long the drain then waits for the cancelled operations' rollback arms to finish, so their
#: interrupted rows reach the store before ``engine.stop()`` closes it. Longer than the drain itself
#: because at least one arm waits on a process: a cancelled DR takeover hook is killed and reaped
#: for up to ``_HOOK_REAP_SECONDS`` before the activation's arm writes its row, so this is that
#: bound plus a second for the write. It is an upper limit: the API lifespans hand the drain a share
#: of one shutdown budget (``_SHUTDOWN_BUDGET_SECONDS`` in ``api/app.py``, BACKLOG #3191). With the
#: managed lifespan's full set of steps that share is below this, and below the reap alone, even
#: when they are idle, so at least a takeover hook that takes most of its reap can still be rolling
#: back when the store closes, and the drain logs it.
CANCEL_GRACE_SECONDS = _HOOK_REAP_SECONDS + 1.0

#: The holder of the operation running in this context. Set only around the task's creation in
#: :meth:`OutlivingOperations.run`, so the task's copy of the context carries it and its caller's
#: does not.
_running_in: ContextVar[OutlivingOperations | None] = ContextVar("_running_in", default=None)


def cancel_grace_left() -> float | None:
    """Seconds left of the grace :meth:`OutlivingOperations.drain` gave the operation running in
    this context, or ``None`` outside a drain's grace or outside such an operation.

    It is the drain's own ``grace``, the share of the shutdown budget a lifespan handed it (BACKLOG
    #3191), counted from when the drain cancelled. A cancellation arm that waits on work of its
    own bounds that wait by it, so the drain does not give up on an arm still waiting (BACKLOG
    #3157). At or below zero, the drain has already stopped waiting."""
    holder = _running_in.get()
    return None if holder is None else holder.grace_left()


def _log_orphan_outcome(task: asyncio.Future[Any], label: str) -> None:
    """Log how an operation ended after its caller had gone, since nobody else will read it.

    Reading the error here also marks it retrieved, so asyncio does not report it a second time."""
    if task.cancelled():
        log.warning("%s: cancelled after its caller had gone", label)
        return
    error = task.exception()
    if error is None:
        log.warning(
            "%s: finished after its caller had gone; its audit row records the outcome", label
        )
    else:
        log.warning("%s: failed after its caller had gone: %s", label, safe_exc(error))


class OutlivingOperations:
    """Runs operations that a cancelled caller must not cut short, and holds them until they end.

    Held per app, so :meth:`drain` sees only this app's operations and no set outlives the loop its
    tasks ran on (the reason the approval gate's own set moved per gate, BACKLOG #2087)."""

    def __init__(self) -> None:
        # The event loop keeps only a weak reference to a running task, and a caller that was
        # cancelled no longer holds one, so this map is what keeps the operation alive.
        self._inflight: dict[asyncio.Future[Any], str] = {}
        # The loop time the drain's grace ends, set when the drain cancels (cancel_grace_left).
        self._grace_ends: float | None = None

    @property
    def inflight(self) -> list[str]:
        """The labels of the operations still running."""
        return list(self._inflight.values())

    async def run[T](self, coro: Coroutine[Any, Any, T], label: str) -> T:
        """Await ``coro`` so that cancelling the CALLER does not cancel it.

        A cancellation delivered while this awaits reaches the caller at once, and the operation
        goes on. Its result or error is then logged once, with ``label``, which names the operation
        and nothing from the request body."""
        token = _running_in.set(self)
        try:
            task = asyncio.ensure_future(coro)
        finally:
            _running_in.reset(token)
        self._inflight[task] = label
        task.add_done_callback(self._forget)
        try:
            return await _outlive_caller(task)
        except asyncio.CancelledError:
            # A task that was itself cancelled raised this through task.result(); its own
            # cancellation arm already recorded the outcome, and there is nothing left to read.
            if not task.cancelled():
                if not task.done():
                    log.warning(
                        "%s: the caller was cancelled (at least a request timeout does this); "
                        "the operation continues and records its own outcome",
                        label,
                    )
                task.add_done_callback(lambda t: _log_orphan_outcome(t, label))
            raise

    def _forget(self, task: asyncio.Future[Any]) -> None:
        self._inflight.pop(task, None)

    def grace_left(self) -> float | None:
        """Seconds left of the grace the drain gave its cancelled operations, or ``None`` before a
        drain has cancelled any (:func:`cancel_grace_left`)."""
        if self._grace_ends is None:
            return None
        return self._grace_ends - asyncio.get_running_loop().time()

    async def drain(
        self,
        timeout: float = DRAIN_TIMEOUT_SECONDS,
        *,
        grace: float = CANCEL_GRACE_SECONDS,
    ) -> list[str]:
        """Wait up to ``timeout`` for running operations, then cancel what is left.

        Returns the labels of the operations it had to cancel. It waits up to ``grace`` more for
        their cancellation arms, which restore state and record ``interrupted``. An operation still
        running after that is logged and left: it is not awaited past the bound, so a stuck one
        cannot hold the shutdown."""
        pending = set(self._inflight)
        if not pending:
            return []
        _done, left = await asyncio.wait(pending, timeout=timeout)
        if not left:
            return []
        cancelled = sorted(self._inflight.get(task, "?") for task in left)
        log.warning(
            "shutdown: cancelling %d operation(s) still running after %.1fs: %s",
            len(left),
            timeout,
            ", ".join(cancelled),
        )
        # Set before the cancels, so an arm reading cancel_grace_left() as its cancel lands sees it.
        self._grace_ends = asyncio.get_running_loop().time() + grace
        for task in left:
            task.cancel()
        _done, stuck = await asyncio.wait(left, timeout=grace)
        if stuck:
            log.error(
                "shutdown: %d cancelled operation(s) had not finished rolling back after %.1fs",
                len(stuck),
                grace,
            )
        return cancelled
