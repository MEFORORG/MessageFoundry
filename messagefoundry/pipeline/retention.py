"""Data-retention + store-maintenance worker (PHI.md §8, ASVS 14.2.x).

Without enforcement, PHI accumulates in the message store indefinitely — including dead-lettered
raw bodies. :class:`RetentionRunner` is the single background task that enforces the ``[retention]``
service settings: past the configured windows it **nulls message/dead-letter bodies while keeping
their metadata rows** (the Mirth Data-Pruner pattern — counts, disposition, and the audit trail stay
intact; nothing is deleted), checkpoints the WAL, and ``VACUUM``s on a daily off-peak schedule. Each
pass that does real work writes **one** ``audit_log`` entry recording the cutoffs + counts (never any
message content). When the store outgrows ``max_db_mb`` it raises an advisory ``storage_threshold``
alert.

It is owned by the :class:`~messagefoundry.pipeline.engine.Engine` (started in ``start``, cancelled in
``stop``) rather than the per-graph runner, so it is independent of config reloads and runs once per
process. The clock is injected so the windows and the daily VACUUM time are deterministically testable
(``run_once`` performs a full pass for a given ``now``); the loop only governs cadence.

Engine-side and dependency-light (stdlib + the store/alert seams only), so it never pulls the API or
console into the engine.
"""

from __future__ import annotations

import asyncio
import json
import logging
import time
from collections.abc import Callable
from dataclasses import dataclass

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.store import Store

__all__ = ["RetentionRunner", "RetentionPass"]

log = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86_400
_BYTES_PER_MB = 1_000_000


@dataclass(frozen=True)
class RetentionPass:
    """What one :meth:`RetentionRunner.run_once` pass did — returned for the audit entry + tests."""

    messages_purged: int
    dead_purged: int
    state_purged: int
    wal_checkpointed: bool
    vacuumed: bool
    size_bytes: int
    over_limit: bool

    @property
    def did_work(self) -> bool:
        """Whether the pass changed anything worth an audit row (a routine WAL checkpoint alone
        isn't — it leaves no data trace and would otherwise spam the audit log every pass)."""
        return (
            self.messages_purged > 0
            or self.dead_purged > 0
            or self.state_purged > 0
            or self.vacuumed
            or self.over_limit
        )


class RetentionRunner:
    """Enforces ``[retention]`` on the message store: body-purge + WAL checkpoint + VACUUM + a size
    alert, audited per pass. Construct with the store + settings; call :meth:`start`/:meth:`stop` for
    the supervised loop, or :meth:`run_once` to perform a single deterministic pass (tests)."""

    def __init__(
        self,
        store: Store,
        settings: RetentionSettings,
        *,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
        coordinator: ClusterCoordinator | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        # Default to the logging sink so an over-limit store is at least visible without a notifier.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._clock = clock
        # Retention is a leader-only WRITE singleton (it purges PHI bodies + writes audit rows), so in
        # a cluster it must run on exactly one node. Default NullCoordinator → always leader → always
        # runs, so an existing caller/test that passes no coordinator is byte-identical (Track B Step 4).
        self._coordinator: ClusterCoordinator = coordinator or NullCoordinator()
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None
        # Maintenance cadence state (loop-driven; only read/written on the single task).
        self._last_wal = 0.0
        self._last_vacuum_day: str | None = None

    @property
    def enabled(self) -> bool:
        """True when any window/threshold/maintenance knob is configured. When False, :meth:`start`
        spawns no task — retention is entirely off by default."""
        s = self._settings
        return bool(
            s.messages_days
            or s.dead_letter_days
            or s.state_max_age_days
            or s.max_db_mb
            or s.wal_checkpoint_seconds
            or s.vacuum_time() is not None
        )

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised purge/maintenance loop (no-op when nothing is configured)."""
        if self._task is not None:
            return
        if not self.enabled:
            log.debug("retention disabled (no [retention] windows configured); not starting")
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "retention enabled: messages_days=%d dead_letter_days=%d max_db_mb=%d "
            "wal_checkpoint_seconds=%g vacuum_at=%r (every %gs)",
            self._settings.messages_days,
            self._settings.dead_letter_days,
            self._settings.max_db_mb,
            self._settings.wal_checkpoint_seconds,
            self._settings.vacuum_at,
            self._settings.purge_interval_seconds,
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:
                await task
            except asyncio.CancelledError:
                pass

    async def _run(self) -> None:
        # One isolated pass per interval; an error in a pass is logged and the loop continues (a
        # retention hiccup must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                await self.run_once()
            except asyncio.CancelledError:
                raise
            except Exception:
                log.exception("retention pass failed; will retry next interval")
            await self._sleep(self._settings.purge_interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    async def run_once(self, now: float | None = None) -> RetentionPass:
        """Run a full retention pass for ``now`` (default: the injected clock): purge bodies past the
        configured windows, checkpoint the WAL / VACUUM if due, check the size threshold, and write a
        single ``audit_log`` entry when the pass did real work. Returns a :class:`RetentionPass`.

        Leader-gated (Track B Step 4): a non-leader node returns a did-nothing pass without touching the
        store, so in a cluster exactly one node purges. The loop keeps ticking on followers
        (reactive-by-polling), so when a follower becomes leader the very next pass acts. A follower
        never advances its WAL/VACUUM cadence state (the gate returns before those timers update), so a
        newly-promoted leader runs any due WAL checkpoint / daily VACUUM on its first acting pass — which
        is the correct behavior (the new leader picks up the maintenance the cluster owes). Single-node
        (the NullCoordinator default) is always leader, so this is byte-identical there."""
        if not self._coordinator.is_leader():
            return RetentionPass(
                messages_purged=0,
                dead_purged=0,
                state_purged=0,
                wal_checkpointed=False,
                vacuumed=False,
                size_bytes=0,
                over_limit=False,
            )
        now = self._clock() if now is None else now
        s = self._settings

        messages_purged = 0
        if s.messages_days > 0:
            messages_purged = await self._store.purge_message_bodies(
                older_than=now - s.messages_days * _SECONDS_PER_DAY, now=now
            )
        dead_purged = 0
        if s.dead_letter_days > 0:
            dead_purged = await self._store.purge_dead_letters(
                older_than=now - s.dead_letter_days * _SECONDS_PER_DAY, now=now
            )
        state_purged = 0
        if s.state_max_age_days > 0:
            state_purged = await self._store.purge_state(
                older_than=now - s.state_max_age_days * _SECONDS_PER_DAY, now=now
            )

        wal_checkpointed = False
        if s.wal_checkpoint_seconds > 0 and now - self._last_wal >= s.wal_checkpoint_seconds:
            await self._store.wal_checkpoint()
            self._last_wal = now
            wal_checkpointed = True

        vacuumed = False
        if self._vacuum_due(now):
            await self._store.vacuum()
            self._last_vacuum_day = self._day_key(now)
            vacuumed = True

        size_bytes, over_limit = await self._check_size()

        result = RetentionPass(
            messages_purged=messages_purged,
            dead_purged=dead_purged,
            state_purged=state_purged,
            wal_checkpointed=wal_checkpointed,
            vacuumed=vacuumed,
            size_bytes=size_bytes,
            over_limit=over_limit,
        )
        if result.did_work:
            await self._audit(result)
        return result

    async def _check_size(self) -> tuple[int, bool]:
        """Return ``(db_size_bytes, over_limit)``, emitting the advisory alert when over. Skips the
        size query entirely when ``max_db_mb`` is off."""
        if self._settings.max_db_mb <= 0:
            return 0, False
        size_bytes = (await self._store.db_status()).size_bytes
        limit_bytes = self._settings.max_db_mb * _BYTES_PER_MB
        over = size_bytes > limit_bytes
        if over:
            # The sink never raises (contract), but be defensive — an alert failure must not abort
            # the purge pass that produced it.
            try:
                self._alert_sink.storage_threshold(
                    self._store.path, size_bytes=size_bytes, limit_bytes=limit_bytes
                )
            except Exception:
                log.warning("storage_threshold alert sink failed", exc_info=True)
        return size_bytes, over

    async def _audit(self, result: RetentionPass) -> None:
        """Append one audit row recording the cutoffs + counts (no message content — no PHI)."""
        detail = json.dumps(
            {
                "messages_days": self._settings.messages_days,
                "messages_purged": result.messages_purged,
                "dead_letter_days": self._settings.dead_letter_days,
                "dead_purged": result.dead_purged,
                "state_max_age_days": self._settings.state_max_age_days,
                "state_purged": result.state_purged,
                "vacuumed": result.vacuumed,
                "db_size_bytes": result.size_bytes,
                "max_db_mb": self._settings.max_db_mb,
                "over_limit": result.over_limit,
            },
            sort_keys=True,
        )
        await self._store.record_audit("retention_purge", actor="system", detail=detail)

    # --- daily VACUUM schedule ----------------------------------------------

    def _vacuum_due(self, now: float) -> bool:
        """True when a daily VACUUM time is configured, the local clock has reached it, and we haven't
        already vacuumed today. (At-most-once per local day; a late start that day still catches up.)"""
        target = self._settings.vacuum_time()
        if target is None:
            return False
        lt = time.localtime(now)
        reached = (lt.tm_hour, lt.tm_min) >= target
        return reached and self._last_vacuum_day != self._day_key(now)

    @staticmethod
    def _day_key(now: float) -> str:
        lt = time.localtime(now)
        return f"{lt.tm_year:04d}-{lt.tm_mon:02d}-{lt.tm_mday:02d}"
