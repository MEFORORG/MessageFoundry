# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Page when the off-box log forwarder is absent, losing records, or not sending (BACKLOG #2612).

The forwarder counts its own drops on its own threads, and ``logging_setup`` may not import the
alert sink. So this watch reads :func:`~messagefoundry.logging_setup.forwarder_status` on a timer
and turns a reading into a ``log_forward_failed`` alert. The read is memory only: no socket, no
disk, no store.

**One per engine process, whoever leads.** The forwarder hangs on the process's root logger, so a
cluster standby and every engine shard has its own, and each watches its own. That is why this is
an engine maintenance task, like the certificate monitor, and not part of the message graph.

**What fires, and how often.** At least these kinds, each its own alert key: ``forwarder:<kind>``
on a lone engine, and ``forwarder:<kind>@node:<node_id>`` or ``forwarder:<kind>@shard:<id>`` where
several engine processes share the store, so each process has its own alert row and the row says
which process lost its forwarder. The suffix is the intake alert's (BACKLOG #2272), built by the
same :func:`~messagefoundry.pipeline.intake_bound.process_alert_subject`.

* ``not_installed``: a forwarder was configured and is not attached, or its listener thread has
  ended. At once when it is first seen absent, then again every :data:`REALERT_SECONDS` while it
  stays absent: the notifier's cooldown, suspend and escalation all assume a standing fault is
  emitted again. The reason is the start failure's fixed word, or ``stopped`` when it went away
  later.
* ``dropping``: a loss counter rose. The count is :attr:`ForwarderStatus.lost`, a floor on the
  records lost since the process started.
* ``spool_unreadable``: the on-disk spool could not be read. Held, not lost.
* ``not_sending``: every pass for a whole re-alert window found
  :attr:`ForwarderStatus.send_failing` set, and a send has failed since the last alert. Not raised
  when the same pass raises ``dropping`` for an unreachable collector, which without a spool is
  the usual case: the two counters are read without a lock. A spool keeps the records while
  it has room; when it is full this fires beside ``dropping``.

Every kind sends a ``count``. Only ``dropping`` puts a number of lost records in it; the other
kinds send ``0``, which says nothing about losses.

All of them share one throttle: after any kind fires, none fires for :data:`REALERT_SECONDS`. The
one exception is the first pass that finds the forwarder absent, which fires whatever the
throttle says. The default sink's alert is a log line, and a log line is one more record for a
forwarder that is already losing them.

**Over UDP only queue and spool losses can fire.** No failed send is counted over UDP, so a collector
that is down looks the same as one that is up (:attr:`ForwarderStatus.delivery_confirmed`).

The alert carries counts, fixed words and this process's own label only: never a record, the
collector's host name or an error text. An unpinned cluster node's label holds this engine's own
host name, as its ``node_id`` does everywhere else.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable

from messagefoundry.logging_setup import FORWARD_LOSS_COUNTERS, ForwarderStatus, forwarder_status
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.intake_bound import process_alert_subject

__all__ = ["CHECK_INTERVAL_SECONDS", "REALERT_SECONDS", "LogForwardWatch"]

log = logging.getLogger(__name__)

#: How often the watch reads the forwarder.
CHECK_INTERVAL_SECONDS = 30.0
#: The least time between two alerts while a fault stands, and how long sends must keep failing
#: before ``not_sending`` fires. The same five minutes the queue-buildup alert re-fires on.
REALERT_SECONDS = 300.0
#: Added to the throttle. The notifier's default cooldown is the same 300 seconds on its own
#: later clock reads, so an alert re-fired at exactly 300 could land inside it and be dropped.
_THROTTLE_MARGIN_SECONDS = 1.0

#: The first part of the alert key. Not a connection name: the key always carries a colon.
_LABEL = "forwarder"


def _restarted(status: ForwarderStatus, last: ForwarderStatus) -> bool:
    """Whether a count went DOWN since ``last``. Counts only rise in one forwarder, so this is a
    forwarder that was built again, and its counts are measured from zero."""
    return (
        status.spool_read_errors < last.spool_read_errors
        or status.send_failures < last.send_failures
        or any(getattr(status, field) < getattr(last, field) for field, _ in FORWARD_LOSS_COUNTERS)
    )


class LogForwardWatch:
    """Reads the forwarder every :data:`CHECK_INTERVAL_SECONDS` and raises ``log_forward_failed``.
    :meth:`start`/:meth:`stop` run the loop; :meth:`run_once` is one pass, for tests too."""

    def __init__(
        self,
        *,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.monotonic,
        read: Callable[[], ForwarderStatus] = forwarder_status,
        node: str | None = None,
    ) -> None:
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        #: Which engine process this is (``Engine.instance_identity``), or ``None`` for a lone
        #: engine. Fixed for the watch's life, so a re-fire lands on the same alert row.
        self._node = node
        self._clock = clock
        self._read = read
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        #: Whether the forwarder was absent on the last pass. The pass that first finds it absent
        #: fires at once; later ones wait for the shared throttle.
        self._absent = False
        #: The reading the last alert was raised on. A rise is measured from it.
        self._alerted = ForwarderStatus()
        self._next_alert = 0.0
        #: When sends started failing without a break, or ``None`` while one succeeds.
        self._failing_since: float | None = None

    def start(self) -> None:
        """Spawn the loop. Its first pass runs at once, so a forwarder that did not start pages at
        start and not one interval later."""
        if self._task is not None:
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task, self._task = self._task, None
        if task is not None:
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)

    async def _run(self) -> None:
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                # The state a failed pass did not commit is retried by the next one.
                log.exception("log forwarder check failed; the next pass retries")
            with contextlib.suppress(TimeoutError):
                await asyncio.wait_for(self._stop.wait(), CHECK_INTERVAL_SECONDS)

    def run_once(self) -> None:
        """One pass. The baseline a rise is measured from moves only AFTER the sink took the
        alert, so a sink that raises leaves the alert to be raised again."""
        status = self._read()
        if not status.configured:
            return
        now = self._clock()
        if not status.installed:
            self._failing_since = None  # a forwarder attached later starts its own clock
            if self._absent and now < self._next_alert:
                return
            # Armed BEFORE the sink is called, as below. A sink that raises on the first absent
            # pass leaves ``_absent`` unset, so the very next pass tries again.
            self._next_alert = now + REALERT_SECONDS + _THROTTLE_MARGIN_SECONDS
            self._fire("not_installed", status.start_failure or "stopped")
            self._absent = True
            return
        self._absent = False
        if not status.send_failing:
            self._failing_since = None
        elif self._failing_since is None:
            self._failing_since = now
        last = ForwarderStatus() if _restarted(status, self._alerted) else self._alerted
        rose = [
            word
            for field, word in FORWARD_LOSS_COUNTERS
            if getattr(status, field) > getattr(last, field)
        ]
        unread = status.spool_read_errors > last.spool_read_errors
        # "Still failing" needs a send that failed since the last alert. The flag alone is only
        # the last send's result, and on a quiet engine that can be an hour old.
        stuck = (
            self._failing_since is not None
            and now - self._failing_since >= REALERT_SECONDS
            and status.send_failures > last.send_failures
        )
        if not (rose or unread or stuck) or now < self._next_alert:
            return
        # Armed BEFORE the sink is called. If a call below raises, the baseline has not moved, so
        # the pass is tried again, but after a window and not every 30 seconds.
        self._next_alert = now + REALERT_SECONDS + _THROTTLE_MARGIN_SECONDS
        if rose:
            self._fire("dropping", ",".join(rose), status.lost)
        if unread:
            self._fire("spool_unreadable", "spool_read_failed")
        if stuck and "collector_unreachable" not in rose:  # else "dropping" has just said so
            self._fire("not_sending", "collector_unreachable")
        self._alerted = status

    def _fire(self, kind: str, reason: str, count: int = 0) -> None:
        # The kind is in the key because the notifier throttles and de-duplicates on it: two
        # kinds raised in one pass would otherwise be one notification and one alert row. The
        # process is in it for the same reason: every process on a store watches its own forwarder.
        self._alert_sink.log_forward_failed(
            process_alert_subject(f"{_LABEL}:{kind}", self._node), reason=reason, count=count
        )
