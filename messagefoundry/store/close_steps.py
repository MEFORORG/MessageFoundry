# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Run a store close's teardown steps so a cancellation cannot skip a later one (BACKLOG #5668).

A cancellation landing on one step of a sequential close used to unwind past every step after it. On
SQLite that left non-daemon aiosqlite workers alive, and interpreter exit then hung on them.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Coroutine
from typing import Any, Final

log = logging.getLogger(__name__)

#: How long the steps of a close may keep running, in all, once a cancellation has arrived. The
#: caller asked to stop, so a step that cannot finish (a wedged driver call) must not hold it forever.
CANCELLED_CLOSE_GRACE_SECONDS: Final[float] = 5.0

#: The least any step is given past that bound, so it still STARTS. Starting is what matters most for
#: a SQLite connection: aiosqlite queues its worker's stop on the way out of ``close``, however that
#: close ends.
_STEP_FLOOR_SECONDS: Final[float] = 0.05


class CloseSteps:
    """Runs each step in its own task and holds a cancellation until :meth:`reraise`.

    A cancellation of the closing task is passed to the running step, which unwinds, and the next
    step then runs. Before the first cancellation a step has no time limit, exactly as a plain
    ``await`` has none. A step's own exception propagates from :meth:`run`.
    """

    def __init__(self) -> None:
        self._cancelled: asyncio.CancelledError | None = None
        self._deadline: float | None = None

    def _note_cancel(self, exc: asyncio.CancelledError) -> None:
        if self._cancelled is None:
            self._cancelled = exc
        if self._deadline is None:
            self._deadline = asyncio.get_running_loop().time() + CANCELLED_CLOSE_GRACE_SECONDS

    def _timeout(self) -> float | None:
        if self._deadline is None:
            return None
        left = self._deadline - asyncio.get_running_loop().time()
        return max(left, _STEP_FLOOR_SECONDS)

    async def run(self, step: Coroutine[Any, Any, None], what: str) -> None:
        """Run ``step`` to its end, or until the bound once a cancellation has arrived."""
        task = asyncio.ensure_future(step)
        while not task.done():
            try:
                done, _pending = await asyncio.wait({task}, timeout=self._timeout())
            except asyncio.CancelledError as exc:
                self._note_cancel(exc)
                task.cancel()
                continue
            if not done:
                # Past the bound. The cancel is what makes aiosqlite queue its worker's stop.
                task.cancel()
                log.warning("store close gave up waiting on %s after a cancellation", what)
                return
        try:
            task.result()
        except asyncio.CancelledError as exc:
            # Either the cancel passed on above, or the step cancelled itself: both must surface.
            self._note_cancel(exc)

    def reraise(self) -> None:
        """Raise the held cancellation, if one arrived."""
        if self._cancelled is not None:
            raise self._cancelled
