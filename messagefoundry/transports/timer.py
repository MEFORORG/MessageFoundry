# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Timer / scheduled source — emit a configured body on a schedule (ADR 0011).

Unlike every other source, a timer reads **no external resource**: it *fires* on a clock and hands
an operator-configured ``body`` to the pipeline handler. It follows the File/Database poll skeleton
(a cooperatively-cancellable :mod:`asyncio` loop that logs-and-continues on error, never crashing the
connection) but drops the resource scan, content validation, and mark/move — each tick just emits the
body.

A timer is **leader-gated** (:attr:`polls_shared_resource` ``True``): the schedule is a *shared
trigger*, so in a cluster only the leader fires it — otherwise every node would emit each message. On
a single node ``NullCoordinator.is_leader()`` is always ``True``, so behaviour is byte-identical to an
ungated loop (the runner already passes ``leader_gate=is_leader`` to every source). See ADR 0011 for
the at-least-once / re-run contract: the body is committed to the ingress stage and frozen there, so
downstream re-runs stay pure; only the *timing* boundary is at-least-once (a clock, not a queue).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable
from datetime import datetime, timedelta
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.transports.base import InboundHandler, SourceConnector, register_source

logger = logging.getLogger(__name__)

# How often a not-yet-fired ``run_once`` timer re-checks leadership when no interval is configured
# (so a follower that wins leadership fires reasonably promptly). On a single node it fires on the
# first tick regardless, so this only matters in a cluster.
DEFAULT_RUN_ONCE_POLL_SECONDS = 1.0

# Cron loop (ADR 0011 amendment): the per-tick sleep is capped so the loop re-evaluates the schedule
# against the wall clock at least this often — a clock/DST change is then picked up promptly rather
# than being frozen inside one long sleep. Correctness never depends on the cap (next-fire is
# recomputed each wake), only responsiveness to a clock jump.
_MAX_CRON_SLEEP_SECONDS = 30.0

# Search horizon for the next cron fire. Just over 4 years so a leap-day-only expression (``* * 29 2 *``)
# is still found; an unsatisfiable expression (e.g. ``* * 30 2 *``) exhausts it and fails loud at parse.
_CRON_HORIZON_DAYS = 4 * 366 + 2


class _CronSchedule:
    """A pure, stdlib-only 5-field cron next-fire evaluator (ADR 0011 amendment, BACKLOG #160).

    Fields, in order: ``minute hour day-of-month month day-of-week``. Each supports ``*``, lists
    (``1,3,5``), ranges (``1-5``), and steps (``*/5``, ``0-30/10``). Day-of-week is ``0-6`` with
    **Sunday = 0** (``7`` is also accepted as Sunday). When **both** day-of-month and day-of-week are
    restricted (neither starts with ``*``) a match on **either** fires (the Vixie OR rule); otherwise
    both must match. Named months/weekdays are out of scope (numeric only). No external dependency —
    :mod:`datetime` arithmetic + the caller's timezone give DST-correct wall-clock scheduling."""

    __slots__ = ("expr", "minutes", "hours", "doms", "months", "dows", "_dom_star", "_dow_star")

    def __init__(
        self,
        expr: str,
        minutes: frozenset[int],
        hours: frozenset[int],
        doms: frozenset[int],
        months: frozenset[int],
        dows: frozenset[int],
        dom_star: bool,
        dow_star: bool,
    ) -> None:
        self.expr = expr
        self.minutes = minutes
        self.hours = hours
        self.doms = doms
        self.months = months
        self.dows = dows
        self._dom_star = dom_star
        self._dow_star = dow_star

    @classmethod
    def parse(cls, expr: str) -> _CronSchedule:
        fields = expr.split()
        if len(fields) != 5:
            raise ValueError(
                f"cron_expression must have exactly 5 space-separated fields "
                f"(minute hour day-of-month month day-of-week), got {len(fields)}: {expr!r}"
            )
        minute_s, hour_s, dom_s, month_s, dow_s = fields
        minutes = _parse_cron_field(minute_s, 0, 59, "minute")
        hours = _parse_cron_field(hour_s, 0, 23, "hour")
        doms = _parse_cron_field(dom_s, 1, 31, "day-of-month")
        months = _parse_cron_field(month_s, 1, 12, "month")
        dows_raw = _parse_cron_field(dow_s, 0, 7, "day-of-week")
        # Normalize Sunday: cron accepts both 0 and 7 for Sunday.
        dows = frozenset(0 if d == 7 else d for d in dows_raw)
        # Vixie OR-rule keys on whether the *field text* starts with '*' (so `*/2` is NOT restricted).
        sched = cls(
            expr,
            minutes,
            hours,
            doms,
            months,
            dows,
            dom_star=dom_s.startswith("*"),
            dow_star=dow_s.startswith("*"),
        )
        # Fail loud at parse (wiring / `messagefoundry check`) if the expression can never fire, so the
        # runtime loop never scans the full horizon repeatedly. A valid expression resolves quickly.
        sched.next_after(datetime(2001, 1, 1, 0, 0))
        return sched

    def matches(self, dt: datetime) -> bool:
        if (
            dt.minute not in self.minutes
            or dt.hour not in self.hours
            or dt.month not in self.months
        ):
            return False
        dom_ok = dt.day in self.doms
        # datetime.weekday(): Mon=0..Sun=6. Cron: Sun=0..Sat=6 → shift.
        dow_ok = ((dt.weekday() + 1) % 7) in self.dows
        if not self._dom_star and not self._dow_star:
            return dom_ok or dow_ok  # both restricted → OR (Vixie semantics)
        return dom_ok and dow_ok

    def next_after(self, dt: datetime) -> datetime:
        """The first scheduled minute strictly **after** ``dt`` (never ``dt`` itself, never the past).

        Preserves ``dt``'s ``tzinfo`` (naive stays naive, aware stays aware), so the caller's timezone
        choice drives DST. Raises ``ValueError`` if no fire time exists within :data:`_CRON_HORIZON_DAYS`
        (an unsatisfiable expression)."""
        t = (dt + timedelta(minutes=1)).replace(second=0, microsecond=0)
        limit = t + timedelta(days=_CRON_HORIZON_DAYS)
        while t <= limit:
            if self.matches(t):
                return t
            t += timedelta(minutes=1)
        raise ValueError(
            f"cron_expression {self.expr!r} has no fire time within {_CRON_HORIZON_DAYS} days "
            "(unsatisfiable schedule)"
        )


def _parse_cron_field(spec: str, lo: int, hi: int, name: str) -> frozenset[int]:
    """Expand one cron field (``*`` | list | range | step) to the set of matching integers in ``[lo, hi]``."""
    values: set[int] = set()
    for part in spec.split(","):
        rng, _, step_s = part.partition("/")
        if _:  # a "/" was present
            if not step_s.isdigit() or int(step_s) == 0:
                raise ValueError(f"cron {name} field has an invalid step in {part!r}")
            step = int(step_s)
        else:
            step = 1
        if rng == "*":
            start, end = lo, hi
        elif "-" in rng:
            a, b = rng.split("-", 1)
            start, end = _cron_int(a, name), _cron_int(b, name)
        else:
            start = end = _cron_int(rng, name)
        if start < lo or end > hi or start > end:
            raise ValueError(
                f"cron {name} field value out of range or reversed in {part!r} (allowed {lo}-{hi})"
            )
        values.update(range(start, end + 1, step))
    return frozenset(values)


def _cron_int(token: str, name: str) -> int:
    if not token.isdigit():
        raise ValueError(
            f"cron {name} field has a non-numeric value {token!r} (numeric fields only)"
        )
    return int(token)


class TimerSource(SourceConnector):
    """Emit a configured ``body`` on an interval (or exactly once), feeding it to the pipeline handler."""

    # A schedule is a shared trigger — leader-gate it so exactly one node fires (see module docstring).
    polls_shared_resource = True

    def __init__(self, config: Source) -> None:
        s = config.settings
        if "body" not in s:
            raise ValueError("timer source requires a 'body' setting")
        self.body = str(s["body"])
        self.encoding = str(s.get("encoding", "utf-8"))
        # Pre-encode once: the emitted bytes are deterministic across fires (re-run-stable, ADR 0011 §5).
        self._body_bytes = self.body.encode(self.encoding)
        self.run_once = bool(s.get("run_once", False))
        iv = s.get("interval_seconds")
        self.interval_seconds: float | None = float(iv) if iv is not None else None
        if self.interval_seconds is not None and self.interval_seconds <= 0:
            raise ValueError("timer source 'interval_seconds' must be > 0")
        # Cron / calendar schedule (ADR 0011 amendment, BACKLOG #160). Exclusive with interval/run_once;
        # DST is driven by the optional `timezone` (an IANA name → aware wall clock) or, by default, the
        # system-local wall clock (the OS handles local DST, no tzdata needed).
        cron_expr = s.get("cron_expression")
        self._cron: _CronSchedule | None = None
        self._tz: ZoneInfo | None = None
        if cron_expr:
            if self.interval_seconds is not None or self.run_once:
                raise ValueError(
                    "timer source 'cron_expression' is exclusive with 'interval_seconds'/'run_once'"
                )
            self._cron = _CronSchedule.parse(str(cron_expr))
            tz_name = s.get("timezone")
            if tz_name:
                try:
                    self._tz = ZoneInfo(str(tz_name))
                except (ZoneInfoNotFoundError, ValueError) as exc:
                    raise ValueError(
                        f"timer source 'timezone' {tz_name!r} is not a known IANA zone"
                    ) from exc
        elif s.get("timezone"):
            raise ValueError("timer source 'timezone' only applies together with 'cron_expression'")
        if self._cron is None and self.interval_seconds is None and not self.run_once:
            raise ValueError(
                "timer source requires 'interval_seconds', 'run_once', or 'cron_expression'"
            )
        # The loop's sleep cadence: the interval when set, else a short re-check for a run_once follower.
        self._tick_seconds = (
            self.interval_seconds
            if self.interval_seconds is not None
            else DEFAULT_RUN_ONCE_POLL_SECONDS
        )
        self._handler: InboundHandler | None = None
        # Leader-gate (Track B Step 4b): when set, only fire while it returns True so exactly one node
        # emits. None = always fire (single-node / direct callers / tests) — byte-identical.
        self._leader_gate: Callable[[], bool] | None = None
        self._skipping = False  # whether the last tick was gated out (for a single transition log)
        self._fired = False  # has run_once already fired? (so it fires once, then idles until stop)
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        """Begin firing in the background. Returns once the source is set up so the caller can rely
        on it being live (consistent with the other sources)."""
        self._handler = handler
        self._leader_gate = leader_gate
        self._stop.clear()
        self._fired = False
        self._task = asyncio.create_task(self._run())

    async def stop(self) -> None:
        self._stop.set()
        if self._task is not None:
            # return_exceptions: a faulted timer task must not re-raise here — stop() runs during reload
            # quiesce, outside its rollback. _run already guards each fire; this is belt-and-suspenders.
            await asyncio.gather(self._task, return_exceptions=True)
            self._task = None

    async def _run(self) -> None:
        if self._cron is not None:
            await self._run_cron()
            return
        # Fire immediately on start (a heartbeat starts at t=0), then every interval. The first tick of
        # each pass checks the leader gate; a follower skips and re-checks next tick (reactive-by-polling).
        while not self._stop.is_set():
            try:
                if self._may_fire():
                    await self._fire()
                    self._fired = True
            except asyncio.CancelledError:
                raise
            except Exception:
                # A fire failure is an infrastructure error (the durable ingress write failed — DB
                # locked, disk full): the handler records every message-level outcome itself. It must
                # NOT kill the source (that would silently stop intake while still reporting running).
                # Log and retry on the next tick (at-least-once). _fired stays False, so a run_once timer
                # retries until it lands.
                logger.exception("timer source fire failed; retrying next tick")
            if self.run_once and self._fired:
                # Single-shot done: idle until stop so the task joins cleanly rather than busy-ticking.
                await self._stop.wait()
                return
            try:  # noqa: SIM105
                await asyncio.wait_for(self._stop.wait(), self._tick_seconds)
            except TimeoutError:
                pass  # tick elapsed; fire / re-check again

    def _now(self) -> datetime:
        """Current wall clock the cron schedule matches against: an IANA-aware clock when a ``timezone``
        was configured, else the system-local naive clock (the OS handles local DST)."""
        return datetime.now(self._tz) if self._tz is not None else datetime.now()

    async def _run_cron(self) -> None:
        # Unlike the interval heartbeat, cron does NOT fire at t=0: the first fire is the next scheduled
        # minute strictly after now. The per-tick sleep is recomputed each wake and capped so a
        # clock/DST jump is picked up promptly. next_after is always strictly future, so there is no
        # busy-loop when a fire time is "in the past".
        next_fire = self._cron.next_after(self._now())  # type: ignore[union-attr]
        while not self._stop.is_set():
            remaining = (next_fire - self._now()).total_seconds()
            if remaining > 0:
                try:  # noqa: SIM105
                    await asyncio.wait_for(
                        self._stop.wait(), min(remaining, _MAX_CRON_SLEEP_SECONDS)
                    )
                except TimeoutError:
                    pass  # sleep slice elapsed — re-check remaining against the wall clock
                continue
            # Due. Leader-gated like every fire: a follower advances the schedule without emitting.
            try:
                if self._may_fire():
                    await self._fire()
            except asyncio.CancelledError:
                raise
            except Exception:
                # A fire failure is an infrastructure error (durable ingress write failed) — it must not
                # kill the source; the schedule advances and the next slot is attempted (mirrors _run).
                logger.exception("timer source cron fire failed; the schedule advances")
            # Recompute strictly after the current time → the next slot (never re-fires the same minute).
            next_fire = self._cron.next_after(self._now())  # type: ignore[union-attr]

    def _may_fire(self) -> bool:
        """Whether this tick may fire. False on a follower (leader-gated, Step 4b): a non-leader must
        not emit, since the schedule is shared and two nodes firing would duplicate the message. The
        loop still ticks, so a node that becomes leader fires on its next tick (no restart). When the
        gate is None or True, behaves exactly as an ungated loop. Logged once per transition (never per
        skipped tick — that would spam a follower's log every tick)."""
        if self._leader_gate is None or self._leader_gate():
            if self._skipping:
                self._skipping = False
                logger.debug("timer source resuming (now leader)")
            return True
        if not self._skipping:
            self._skipping = True
            logger.debug("timer source skipping fire (not leader; another node emits it)")
        return False

    async def _fire(self) -> None:
        assert self._handler is not None
        await self._handler(self._body_bytes)


register_source(ConnectorType.TIMER, TimerSource)
