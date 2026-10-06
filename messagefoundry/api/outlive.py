# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Long operations that outlive the HTTP request that started them (vault BACKLOG #2751-#2753).

:class:`~messagefoundry.api.request_timeout.RequestTimeoutMiddleware` cancels a handler that has not
begun responding within its deadline. For most routes that is the point. For a DR activation, a DR
release and a config reload it is not: each stops and restarts listeners and changes state the
engine reports, and a cancellation partway through would leave that state half changed with no
outcome audit row. So those routes run the operation through :meth:`OutlivingOperations.run`. The
deadline still ends the RESPONSE (the caller gets the middleware's 503), and the operation finishes
on its own and writes its own outcome row. A retry meets the operation's own lock and then its
outcome, not a half-applied state.

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
from typing import Any

from messagefoundry.api.approvals import _outlive_caller
from messagefoundry.redaction import safe_exc

__all__ = ["CANCEL_GRACE_SECONDS", "DRAIN_TIMEOUT_SECONDS", "OutlivingOperations"]

log = logging.getLogger(__name__)

#: How long :meth:`OutlivingOperations.drain` lets a running operation finish at shutdown before it
#: cancels it. It shares NSSM's 15 s graceful-stop window with the upload runner's stop and the
#: approval gate's drain, so it is short; an operation it cancels records ``interrupted``.
DRAIN_TIMEOUT_SECONDS = 2.0

#: How long the drain then waits for the cancelled operations' rollback arms to finish, so their
#: interrupted rows reach the store before ``engine.stop()`` closes it.
CANCEL_GRACE_SECONDS = 2.0


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

    @property
    def inflight(self) -> list[str]:
        """The labels of the operations still running."""
        return list(self._inflight.values())

    async def run[T](self, coro: Coroutine[Any, Any, T], label: str) -> T:
        """Await ``coro`` so that cancelling the CALLER does not cancel it.

        A cancellation delivered while this awaits reaches the caller at once, and the operation
        goes on. Its result or error is then logged once, with ``label``, which names the operation
        and nothing from the request body."""
        task = asyncio.ensure_future(coro)
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
            "shutdown: cancelling %d operation(s) still running after %.0fs: %s",
            len(left),
            timeout,
            ", ".join(cancelled),
        )
        for task in left:
            task.cancel()
        _done, stuck = await asyncio.wait(left, timeout=grace)
        if stuck:
            log.error(
                "shutdown: %d cancelled operation(s) had not finished rolling back after %.0fs",
                len(stuck),
                grace,
            )
        return cancelled
