# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A shutdown run as ordered steps, each bounded by a share of one budget (BACKLOG #3191).

The managed API lifespan runs its teardown through :func:`run_teardown`, and so does
:meth:`Engine.stop <messagefoundry.pipeline.engine.Engine.stop>` when it is handed a budget, so the
whole stop fits NSSM's graceful-stop window. Here rather than in ``api/`` because the engine runs it
too, and ``pipeline/`` never imports ``api/``.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable, Sequence
from dataclasses import dataclass
from typing import Final

__all__ = ["CUT_GRACE_SECONDS", "INNER_SHARE", "TeardownStep", "run_teardown"]

log = logging.getLogger(__name__)

#: The part of a step's bound handed to the step's own graceful wait, so that wait ends, and cancels
#: what it owns, before the teardown cuts the step.
INNER_SHARE: Final = 0.8
#: How long a step cut at its bound gets to unwind its cancellation before the teardown stops waiting
#: for it and moves on, leaving it to finish or fail on its own.
CUT_GRACE_SECONDS: Final = 0.1

#: Steps the teardown stopped waiting for. The event loop holds only a weak reference to a task, so
#: this keeps one alive until it ends.
_left_running: set[asyncio.Future[object]] = set()


@dataclass(frozen=True)
class TeardownStep:
    """One shutdown step for :func:`run_teardown`.

    ``floor`` is the time the step is guaranteed whatever the steps before it took. ``run`` is given
    the step's bound and returns what to await. A step that does not apply is left out of the list,
    which frees its floor. ``bounded=False`` runs the step to completion and is never cut. At least
    these steps run that way: the reap of the managed lifespan's store-reading tasks, since a task
    left running would meet the closed store; engine.stop() in that lifespan, which bounds its own
    waits by the bound it is handed; and the store's close inside engine.stop(), since a store left
    open keeps a non-daemon worker thread alive, which is the hang BACKLOG #2087 fixed."""

    label: str
    floor: float
    run: Callable[[float], Awaitable[object]]
    bounded: bool = True


def _log_late_outcome(label: str) -> Callable[[asyncio.Future[object]], None]:
    """Log how a step the teardown left running ended, since nobody else reads it."""

    def _done(work: asyncio.Future[object]) -> None:
        _left_running.discard(work)
        if not work.cancelled() and (error := work.exception()) is not None:
            log.error("shutdown: %s failed after the teardown moved on", label, exc_info=error)

    return _done


async def _await_step(work: asyncio.Future[object], bound: float | None, label: str) -> bool:
    """Wait for one step, through any cancel of the caller, for at most ``bound`` seconds.

    A cancel of the caller is noted once and does not reach the step: the step finishes, or is cut
    at its bound, as it would have been with no cancel. At the bound the step is cancelled and gets
    :data:`CUT_GRACE_SECONDS` to unwind; one still running then is left to end on its own. Returns
    whether the step ended on its own, so its outcome is the caller's to read.

    The wait is asyncio.wait, never asyncio.shield: once the caller is cancelled, shield reports a
    later failure of the step to the loop's exception handler as well, so it would be logged twice
    (BACKLOG #2087, #2263)."""
    loop = asyncio.get_running_loop()
    give_up = None if bound is None else loop.time() + bound
    cut = noted = False
    while not work.done():
        remaining = None if give_up is None else give_up - loop.time()
        if remaining is not None and remaining <= 0:
            if cut:
                log.error(
                    "shutdown: %s was still running %.2fs after it was cut; continuing the "
                    "teardown without it",
                    label,
                    CUT_GRACE_SECONDS,
                )
                _left_running.add(work)
                work.add_done_callback(_log_late_outcome(label))
                return False
            log.error("shutdown: %s did not finish within %.2fs; cutting it", label, bound)
            cut = True
            work.cancel()
            give_up = loop.time() + CUT_GRACE_SECONDS
            continue
        try:
            await asyncio.wait((work,), timeout=remaining)
        except asyncio.CancelledError:
            # Once per step: a cancel that is re-delivered on every pass of the loop, as an anyio
            # cancel scope does, would otherwise log a line per pass.
            if not noted:
                noted = True
                log.warning(
                    "shutdown: cancelled during %s; it and the remaining steps run before the "
                    "cancel propagates",
                    label,
                )
    return not (cut and work.cancelled())


async def run_teardown(steps: Sequence[TeardownStep], budget: float) -> None:
    """Run every step in order, whatever the steps before it did (BACKLOG #3191).

    Each step runs as its own task. A step that raises, or overruns its bound and is cut, is logged,
    and the next step runs. Each bounded step gets what is left of ``budget`` after the floors of the
    steps still to come, and never less than its own floor, so a slow step spends slack and not a
    later step's share. The whole run takes at most the larger of ``budget`` and the sum of the
    floors, plus :data:`CUT_GRACE_SECONDS` for each step cut, plus whatever an unbounded step
    overruns its floor by.

    A cancel of the caller reaches no step (:func:`_await_step`), and is raised once every step has
    run. So is the first other exception a step ends with that is not an :class:`Exception`: the
    steps after it still run, so engine.stop() still closes the store. KeyboardInterrupt and
    SystemExit are not among them, since asyncio raises those out of the event loop itself."""
    loop = asyncio.get_running_loop()
    deadline = loop.time() + budget
    current = asyncio.current_task()
    # Compared at the end, so a cancel that arrived while this ran is raised, and one already on its
    # way out when the teardown began is left to the exception carrying it.
    baseline = 0 if current is None else current.cancelling()
    later = sum(step.floor for step in steps)
    fatal: BaseException | None = None
    for step in steps:
        later -= step.floor
        bound = max(step.floor, deadline - loop.time() - later)
        # Called inside the task, so an error raised while building the awaitable is the step's
        # failure like any other, and cannot skip the steps after it.
        work = asyncio.ensure_future(_invoke(step.run, bound))
        if not await _await_step(work, bound if step.bounded else None, step.label):
            continue
        try:
            work.result()
        except asyncio.CancelledError:
            log.error("shutdown: %s ended cancelled; continuing the teardown", step.label)
        except Exception:
            log.exception("shutdown: %s failed; continuing the teardown", step.label)
        except BaseException as exc:  # re-raised below, once the later steps have run
            log.exception("shutdown: %s raised; it is re-raised after the teardown", step.label)
            fatal = fatal or exc
    if fatal is not None:
        raise fatal
    if current is not None and current.cancelling() > baseline:
        raise asyncio.CancelledError


async def _invoke(run: Callable[[float], Awaitable[object]], bound: float) -> object:
    """A step's body, as the coroutine :func:`run_teardown` runs in the step's own task."""
    return await run(bound)
