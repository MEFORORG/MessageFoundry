# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Hold a cancellation across a store close's teardown steps (BACKLOG #5668).

A cancellation landing on one step of a sequential close used to unwind past every step after it. On
SQLite that left non-daemon aiosqlite workers alive, and interpreter exit then hung on them.

Steps run inline in the closing task, never in a task of their own: a ``SystemExit`` or
``KeyboardInterrupt`` raised in a child task would leave through the event loop instead of reaching
whoever awaits the close.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any, Final

log = logging.getLogger(__name__)

#: How long the later steps of a close are given, in all, once a cancellation has arrived: at this
#: bound the running step is cancelled. A step may overrun by its own unwind, such as the group
#: committer's bounded rollback, so this is not a hard limit on the close.
CANCELLED_CLOSE_GRACE_SECONDS: Final[float] = 5.0

#: The least any step is given past that bound, so that it still starts.
_STEP_FLOOR_SECONDS: Final[float] = 0.05


class CloseSteps:
    """Holds the first cancellation of a close until :meth:`reraise`.

    Before a cancellation a step has no time limit, exactly as a plain ``await`` has none. After one,
    every later step shares one bound. A step's own exception propagates from :meth:`run`.
    """

    def __init__(self) -> None:
        self._cancelled: asyncio.CancelledError | None = None
        self._deadline = 0.0

    @property
    def cancelled(self) -> bool:
        return self._cancelled is not None

    def hold(self, exc: asyncio.CancelledError) -> None:
        """Keep ``exc`` to re-raise, and start the shared bound on the first one."""
        if self._cancelled is None:
            self._cancelled = exc
            self._deadline = asyncio.get_running_loop().time() + CANCELLED_CLOSE_GRACE_SECONDS

    def remaining(self) -> float:
        """Seconds a step may still take under the bound. Meaningful once :attr:`cancelled`."""
        left = self._deadline - asyncio.get_running_loop().time()
        return max(left, _STEP_FLOOR_SECONDS)

    async def run(self, step: Coroutine[Any, Any, None], what: str) -> None:
        """Await ``step``, holding a cancellation; once one is held, only up to the bound."""
        if self._cancelled is None:
            try:
                await step
            except asyncio.CancelledError as exc:
                self.hold(exc)
            return
        bound = asyncio.timeout(self.remaining())
        try:
            async with bound:
                await step
        except asyncio.CancelledError as exc:
            self.hold(exc)
        except TimeoutError as exc:
            if bound.expired():
                log.warning("store close gave up waiting on %s after a cancellation", what)
            else:
                self.absorb(exc)  # the step's own TimeoutError, not the bound
        except Exception as exc:  # noqa: BLE001 — a held cancel wins; absorb logs this by class
            self.absorb(exc)

    def absorb(self, failure: Exception) -> None:
        """With no cancellation held, raise ``failure``. With one held, log it by class, since the
        cancellation will replace it (the traceback at DEBUG: a driver's message may carry a path
        or a value, CLAUDE.md section 9)."""
        if self._cancelled is None:
            raise failure
        log.warning("store close step failed after a cancellation (%s)", type(failure).__name__)
        log.debug("the close step's failure", exc_info=failure)

    def reraise(self) -> None:
        """Raise the held cancellation, if one arrived."""
        if self._cancelled is not None:
            raise self._cancelled
