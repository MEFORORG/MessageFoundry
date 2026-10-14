# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Record and page a script the remote-debugging guard refused (vault BACKLOG #2742).

The guard (:mod:`messagefoundry.remotedebug`) refuses a script that another process injects through
the interpreter's remote debugging. Its hook runs where a signal handler would, so it only counts,
queues a file name and raises, and a daemon thread writes one WARNING for each refusal. A log line
was the only record. This watch reads the guard's count on a timer, on the event loop, and turns a
rise into one ``remote_debug_refused`` audit row and one ``remote_debug_refused`` alert.

**One row and one alert for each pass, with a count.** The injecting process chooses how often it
tries. However many scripts were refused since the last pass, the pass writes one row and raises
one alert, and each says how many. So the audit log gains at most one row, and the sink one alert,
every :data:`CHECK_INTERVAL_SECONDS`, whatever the rate.

**No file name.** The injecting process chooses the script's name too, so neither the row nor the
alert carries it. The name stays in the guard's WARNING line, which bounds and escapes it.

**Counted from the start of the process.** The first pass reports every refusal since the process
started, so one made before the engine opened its store is recorded. The loop makes one more pass
as it stops, for a refusal in the last interval. A process that is killed loses at most the
refusals since its last pass; the guard's WARNING lines still have them. The count belongs to the
process and each watch keeps its own marks, so a second watch in one process would report the
earlier refusals again. An engine builds one, and ``serve`` builds one engine.

**``serve`` only.** The engine starts this watch, and of the ``messagefoundry`` commands only
``serve`` builds an engine. ``supervise``, ``rotate-key``, ``backup`` and the rest hold no open
store and no notifier, so a refusal there is the guard's WARNING line and nothing more. An engine
shard starts with the interface off (``messagefoundry/childenv.py``), so its count never moves.

**It reads the count, not whether the guard answers.** The count rises wherever the hook runs. That
includes the state where an earlier audit hook raises on the engine's probe event: the posture then
reads the guard as missing and no WARNING is written, but the hook still refuses and counts, so the
row and the alert still come. Where the hook is truly missing nothing is refused and nothing is
counted.

**Each is owed each refusal once.** The row and the alert keep a mark each, and a mark moves only
once its own call succeeded. A store that refuses the row leaves the row's mark where it was, and
the next pass writes one row with the larger count. The alert was raised meanwhile, and is not
raised again for those refusals. A sink that raises is retried the same way.

**The alert has no inverse.** A refusal is an event, not a state that can clear, so nothing
resolves the alert instance. An operator does.

**On the event loop.** The notifier writes its alert-instance row from a task it schedules, which
needs the running loop: an alert raised from another thread leaves no row. Every pass runs on the
loop, so the alert is always raised there.
"""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
from collections.abc import Callable

from messagefoundry.audit_write import write_audit_soft
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.intake_bound import process_alert_subject
from messagefoundry.remotedebug import remote_debug_posture
from messagefoundry.store.base import AuditStore

__all__ = ["ALERT_SUBJECT", "AUDIT_ACTION", "CHECK_INTERVAL_SECONDS", "RemoteDebugRefusalWatch"]

log = logging.getLogger(__name__)

#: The audit action of the row a pass writes. The alert's event type is the same word.
AUDIT_ACTION = "remote_debug_refused"
#: The alert's subject on a lone engine. Not a connection name: it carries a colon.
ALERT_SUBJECT = "remote_debug:refused"
#: How often the watch reads the guard's count. The most rows one hour can add is 3600 over this.
CHECK_INTERVAL_SECONDS = 30.0
#: How long :meth:`RemoteDebugRefusalWatch.stop` waits for the last pass before it cancels it.
_STOP_SECONDS = 5.0


def _refused_scripts() -> int:
    return remote_debug_posture().refused_scripts


class RemoteDebugRefusalWatch:
    """Reads the guard's refusal count every ``interval_seconds``, and for a rise writes one audit
    row and raises one ``remote_debug_refused`` alert. :meth:`start`/:meth:`stop` run the loop;
    :meth:`run_once` is one pass, for tests too."""

    def __init__(
        self,
        store: AuditStore,
        *,
        alert_sink: AlertSink | None = None,
        read: Callable[[], int] = _refused_scripts,
        node: str | None = None,
        interval_seconds: float = CHECK_INTERVAL_SECONDS,
    ) -> None:
        self._store = store
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._read = read
        #: Which engine process this is (``Engine.instance_identity``), or ``None`` for a lone
        #: engine. In the row and in the alert's subject, because every process on a store reports
        #: its own count. Fixed for the watch's life, so each alert lands on the same instance.
        self._node = node
        self._subject = process_alert_subject(ALERT_SUBJECT, node)
        self._interval = interval_seconds
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        #: The count the last written row, and the last raised alert, reported up to. Zero is the
        #: start of the process.
        self._audited = 0
        self._alerted = 0
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
        # ``wait``, not ``wait_for``: a loop task that something else cancelled must not make
        # this call look cancelled, which would end the engine's stop before it closed the store.
        try:
            done, _pending = await asyncio.wait({task}, timeout=_STOP_SECONDS)
        except asyncio.CancelledError:
            task.cancel()
            raise
        if not done:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
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
            # A mark a failed pass did not move is reported by the next one.
            log.exception("remote-debug refusal check failed; the next pass retries")

    async def run_once(self) -> None:
        """One pass: a row, then an alert, for the refusals each has not reported yet.

        Passes take turns. A mark moves after its call, so two passes running at once would each
        write a row for the same refusals."""
        async with self._passing:
            total = self._read()
            # The count only rises in one process. A lower reading is a count that was put back,
            # which only a test does, and it is measured from there.
            self._audited = min(self._audited, total)
            self._alerted = min(self._alerted, total)
            if total > self._audited and await self._record(total - self._audited, total):
                self._audited = total
            if total > self._alerted and self._raise(total - self._alerted, total):
                self._alerted = total

    async def _record(self, count: int, total: int) -> bool:
        """Write the row, and say whether it was written. Counts and this process's own label
        only: never a script's file name."""
        detail = json.dumps(
            {"count": count, "total": total, "process": self._node, "pid": os.getpid()},
            sort_keys=True,
        )
        # ``actor="system"``: no user acted, as for the other rows a background task writes.
        # ``defects=()``: a raise here would skip the alert below, and the next pass retries the
        # row whatever stopped it.
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

    def _raise(self, count: int, total: int) -> bool:
        """Raise the alert, and say whether the sink took it. Two counts and the subject only."""
        try:
            self._alert_sink.remote_debug_refused(self._subject, count=count, total=total)
        except Exception:
            # A sink that breaks its never-raise contract must not stop the next pass, which
            # raises the alert again with the count so far.
            log.exception(
                "remote-debug refusal watch: the remote_debug_refused alert could not be "
                "raised, and the next pass raises it with the count so far"
            )
            return False
        return True
