# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Record a script the remote-debugging guard refused (vault BACKLOG #2742).

The guard (:mod:`messagefoundry.remotedebug`) refuses a script that another process injects through
the interpreter's remote debugging. Its hook runs where a signal handler would, so it only counts,
queues a file name and raises, and a daemon thread writes one WARNING for each refusal. A log line
was the only record. This watch reads the guard's count on a timer, on the event loop, and turns a
rise into one ``remote_debug_refused`` audit row.

**One row for each pass, with a count.** The injecting process chooses how often it tries. However
many scripts were refused since the last pass, the pass writes one row that says how many. So the
audit log gains at most one row every :data:`CHECK_INTERVAL_SECONDS`, whatever the rate.

**No file name.** The injecting process chooses the script's name too, so the row does not carry
it. The name stays in the guard's WARNING line, which bounds and escapes it.

**Counted from the start of the process.** The first pass reports every refusal since the process
started, so one made before the engine opened its store is recorded. The loop makes one more pass
as it stops, for a refusal in the last interval. A process that is killed loses at most the
refusals since its last pass; the guard's WARNING lines still have them.

**``serve`` only.** The engine starts this watch, and of the ``messagefoundry`` commands only
``serve`` builds an engine. ``supervise``, ``rotate-key``, ``backup`` and the rest hold no open
store, so a refusal there is the guard's WARNING line and nothing more. An engine shard starts with
the interface off (``messagefoundry/childenv.py``), so its count never moves.

**It reads the count, not whether the guard answers.** The count rises wherever the hook runs. That
includes the state where an earlier audit hook raises on the engine's probe event: the posture then
reads the guard as missing and no WARNING is written, but the hook still refuses and counts, so the
row is still written. Where the hook is truly missing nothing is refused and nothing is counted.

**A row the store refuses is owed, not lost.** The mark moves only once the row is written. A
store that refuses it leaves the mark where it was, and the next pass writes one row with the
larger count.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from collections.abc import Callable

from messagefoundry.audit_write import write_audit_soft
from messagefoundry.remotedebug import remote_debug_posture
from messagefoundry.store.base import AuditStore

__all__ = ["AUDIT_ACTION", "CHECK_INTERVAL_SECONDS", "RemoteDebugRefusalWatch"]

log = logging.getLogger(__name__)

#: The audit action of the row a pass writes.
AUDIT_ACTION = "remote_debug_refused"
#: How often the watch reads the guard's count. The most rows one hour can add is 3600 over this.
CHECK_INTERVAL_SECONDS = 30.0
#: How long :meth:`RemoteDebugRefusalWatch.stop` waits for the last pass before it cancels it.
_STOP_SECONDS = 5.0


def _refused_scripts() -> int:
    return remote_debug_posture().refused_scripts


class RemoteDebugRefusalWatch:
    """Reads the guard's refusal count every ``interval_seconds`` and writes one audit row for a
    rise. :meth:`start`/:meth:`stop` run the loop; :meth:`run_once` is one pass, for tests too."""

    def __init__(
        self,
        store: AuditStore,
        *,
        read: Callable[[], int] = _refused_scripts,
        node: str | None = None,
        interval_seconds: float = CHECK_INTERVAL_SECONDS,
    ) -> None:
        self._store = store
        self._read = read
        #: Which engine process this is (``Engine.instance_identity``), or ``None`` for a lone
        #: engine. Written into the row, because every process on a store reports its own count.
        self._node = node
        self._interval = interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        #: The count the last written row reported up to. Zero is the start of the process.
        self._audited = 0
        self._passing = asyncio.Lock()

    def start(self) -> None:
        """Spawn the loop. Its first pass runs at once."""
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Signal the loop, let it make its last pass, and await its exit (idempotent)."""
        self._stop.set()
        task, self._task = self._task, None
        if task is None:
            return
        try:
            await asyncio.wait_for(task, _STOP_SECONDS)
        except TimeoutError:
            log.warning(
                "remote-debug refusal watch: the last pass did not finish in %.0f s and was "
                "cancelled, so a refusal since the pass before it may have no audit row",
                _STOP_SECONDS,
            )

    async def _run(self) -> None:
        while not self._stop.is_set():
            await self._pass()
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), self._interval)
        # One more, so a refusal in the last interval is recorded before the store closes.
        await self._pass()

    async def _pass(self) -> None:
        try:
            await self.run_once()
        except Exception:
            # The mark a failed pass did not move is reported by the next one.
            log.exception("remote-debug refusal check failed; the next pass retries")

    async def run_once(self) -> None:
        """One pass: a row for the refusals no row has reported yet.

        Passes take turns. The mark moves after the write, so two passes running at once would
        each write a row for the same refusals."""
        async with self._passing:
            total = self._read()
            # The count only rises in one process. A lower reading is a count that was put back,
            # which only a test does, and it is measured from there.
            self._audited = min(self._audited, total)
            if total > self._audited and await self._record(total - self._audited, total):
                self._audited = total

    async def _record(self, count: int, total: int) -> bool:
        """Write the row, and say whether it was written. Counts and this process's own label
        only: never a script's file name."""
        detail = json.dumps(
            {"count": count, "total": total, "process": self._node, "pid": os.getpid()},
            sort_keys=True,
        )
        # ``actor="system"``: no user acted, as for the other rows a background task writes.
        # ``defects=()``: the row is retried by the next pass whatever stopped it, so a raise here
        # would only end this pass early.
        return await write_audit_soft(
            lambda: self._store.record_audit(AUDIT_ACTION, actor="system", detail=detail),
            log=log,
            message=(
                "remote-debug refusal watch: the remote_debug_refused audit row failed, and the "
                "next pass writes it with the count so far. Unwritten row: detail=%s"
            ),
            args=(detail,),
            defects=(),
        )
