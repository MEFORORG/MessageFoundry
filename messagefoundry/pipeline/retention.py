# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.store import Store, StripResult

__all__ = ["RetentionRunner", "RetentionPass"]

log = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86_400
_BYTES_PER_MB = 1_000_000

#: Per-connection "keep forever" (#34, ADR 0027): a cutoff of -inf makes ``received_at < cutoff`` always
#: false, so that connection's bodies are never purged even while the global window prunes others.
_KEEP_FOREVER = float("-inf")


@dataclass(frozen=True)
class RetentionPass:
    """What one :meth:`RetentionRunner.run_once` pass did — returned for the audit entry + tests."""

    messages_purged: int
    dead_purged: int
    state_purged: int
    conn_events_purged: int
    wal_checkpointed: bool
    vacuumed: bool
    size_bytes: int
    over_limit: bool
    # Per-connection retention overrides resolved this pass (#34, ADR 0027): inbound name -> messages_days
    # and outbound name -> dead_letter_days (0 = keep forever). Recorded in the audit detail (cutoffs,
    # metadata-only — no message content). Empty in a global-only deployment (byte-identical audit).
    messages_overrides: Mapping[str, int] = field(default_factory=dict)
    dead_letter_overrides: Mapping[str, int] = field(default_factory=dict)
    # Embedded-document pruning this pass (#47, ADR 0042): how many messages had >=1 embedded document
    # stripped, the total documents stripped, the on-disk base64 bytes reclaimed, and the per-connection
    # windows applied (inbound name -> prune_documents_after days). Metadata only — no message content.
    documents_messages_stripped: int = 0
    documents_stripped: int = 0
    documents_bytes_reclaimed: int = 0
    document_prune_overrides: Mapping[str, int] = field(default_factory=dict)
    # Resolved operator-alert instances pruned this pass (#56, ADR 0044) — metadata-only, on the same
    # window as connection events. Never an open/acknowledged instance.
    alert_instances_purged: int = 0

    @property
    def did_work(self) -> bool:
        """Whether the pass changed anything worth an audit row (a routine WAL checkpoint alone
        isn't — it leaves no data trace and would otherwise spam the audit log every pass)."""
        return (
            self.messages_purged > 0
            or self.dead_purged > 0
            or self.state_purged > 0
            or self.conn_events_purged > 0
            or self.documents_messages_stripped > 0
            or self.alert_instances_purged > 0
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
        registry_source: Callable[[], Registry | None] | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        # Per-connection retention overrides (#34, ADR 0027) are read from the LIVE registry each pass, so
        # a reload that changes an override takes effect on the next pass. None (the default) = no registry
        # wired → no overrides → a single global cutoff, byte-identical to the prior behaviour.
        self._registry_source = registry_source
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
        spawns no task — retention is entirely off by default.

        Embedded-document pruning (#47, ADR 0042) has no ``[retention]`` setting — it is a purely
        per-connection knob — so the runner must also start when any inbound sets ``prune_documents_after``
        even if no global window is configured. The registry is consulted via ``_registry_source`` (None
        when no registry is wired)."""
        s = self._settings
        if (
            s.messages_days
            or s.dead_letter_days
            or s.state_max_age_days
            or s.connection_event_retention_hours
            or s.max_db_mb
            or s.wal_checkpoint_seconds
            or s.vacuum_time() is not None
        ):
            return True
        registry = self._registry_source() if self._registry_source is not None else None
        if registry is not None and any(
            ic.prune_documents_after is not None for ic in registry.inbound.values()
        ):
            return True
        return False

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
                conn_events_purged=0,
                wal_checkpointed=False,
                vacuumed=False,
                size_bytes=0,
                over_limit=False,
            )
        now = self._clock() if now is None else now
        s = self._settings

        # L1 pre-purge leadership re-check (active-passive HA). The top-of-method gate above ran when the
        # pass began; leadership can be lost (a self-fence) BETWEEN that gate and the purges below — a
        # demoted node must not null PHI bodies / write audit rows as a stale ex-leader. A cheap,
        # SYNCHRONOUS is_leader() read (cached state, no DB round-trip) closes that narrow window: if we
        # are no longer leader, return a did-nothing pass WITHOUT touching the store — the message bodies
        # stay intact and the new leader purges on its next acting pass (count-and-log: nothing is
        # purged-and-lost on a demoted node). This is a cheap fast-path guard, not the authority — the
        # purge writes themselves are leader-only WRITE singletons gated above; this only tightens the
        # gate→purge window. Single-node (NullCoordinator) is always leader, so this never fires.
        if not self._coordinator.is_leader():
            return RetentionPass(
                messages_purged=0,
                dead_purged=0,
                state_purged=0,
                conn_events_purged=0,
                wal_checkpointed=False,
                vacuumed=False,
                size_bytes=0,
                over_limit=False,
            )

        # Per-connection retention overrides (#34, ADR 0027), resolved once per pass from the LIVE
        # registry: inbound name -> messages_days, outbound name -> dead_letter_days (0 = keep forever,
        # None = inherit the global window so the connection is omitted from the cutoff map → it uses the
        # global cutoff). Empty when no registry/overrides → byte-identical single global cutoff.
        msg_days_overrides, dead_days_overrides = self._resolve_overrides()
        # A per-connection purge can run even when the GLOBAL window is off (a connection sets its own
        # window while the global default is keep-forever). Run the purge whenever the global window is
        # set OR any connection overrides it.
        messages_purged = 0
        if s.messages_days > 0 or msg_days_overrides:
            messages_purged = await self._store.purge_message_bodies(
                older_than=self._global_cutoff(now, s.messages_days),
                now=now,
                connection_cutoffs=self._cutoff_map(now, msg_days_overrides),
            )
        dead_purged = 0
        if s.dead_letter_days > 0 or dead_days_overrides:
            dead_purged = await self._store.purge_dead_letters(
                older_than=self._global_cutoff(now, s.dead_letter_days),
                now=now,
                connection_cutoffs=self._cutoff_map(now, dead_days_overrides),
            )
        # Embedded-document pruning (#47, ADR 0042): an in-place strip of bulky base64 attachments on a
        # per-connection window, layered over NO global default (it never runs unless a connection sets
        # prune_documents_after). Driven in the same pass; the cutoff map is the per-connection windows
        # mapped to cutoffs, the global ELSE is keep-forever (nothing without an override is stripped).
        # Each connection may set its OWN size threshold, so the strip is run once per distinct min_bytes
        # value with the connections sharing it (a single call carries one threshold).
        doc_overrides, doc_min_bytes, doc_content_types = self._resolve_document_prune()
        strip = StripResult()
        for threshold in sorted(set(doc_min_bytes.values())):
            group = {n: d for n, d in doc_overrides.items() if doc_min_bytes[n] == threshold}
            part = await self._store.strip_embedded_documents(
                older_than=_KEEP_FOREVER,  # no global document-prune default → keep-forever ELSE
                now=now,
                connection_cutoffs=self._cutoff_map(now, group),
                min_bytes=threshold,
                content_types={n: doc_content_types[n] for n in group if n in doc_content_types},
            )
            strip = StripResult(
                messages_stripped=strip.messages_stripped + part.messages_stripped,
                documents_stripped=strip.documents_stripped + part.documents_stripped,
                bytes_reclaimed=strip.bytes_reclaimed + part.bytes_reclaimed,
            )
        state_purged = 0
        if s.state_max_age_days > 0:
            state_purged = await self._store.purge_state(
                older_than=now - s.state_max_age_days * _SECONDS_PER_DAY, now=now
            )
        # Connection events (#46): the dedicated `connection_event_retention_hours` window if set,
        # else inherit the message-body window (the ADR 0021 §7.5 default — bound the log alongside
        # the bodies). A positive hours value can keep events longer OR shorter than message bodies.
        conn_events_purged = 0
        if s.connection_event_retention_hours > 0:
            conn_events_purged = await self._store.purge_connection_events(
                older_than=now - s.connection_event_retention_hours * 3600.0, now=now
            )
        elif s.messages_days > 0:
            conn_events_purged = await self._store.purge_connection_events(
                older_than=now - s.messages_days * _SECONDS_PER_DAY, now=now
            )

        # Resolved operator-alert instances (#56, ADR 0044): pruned on the SAME window as connection
        # events (metadata-only, one pass). Only RESOLVED instances are eligible — an open/acknowledged
        # condition is never aged out from under an operator. No window set ⇒ inherit the body window.
        alert_instances_purged = 0
        if s.connection_event_retention_hours > 0:
            alert_instances_purged = await self._store.purge_alert_instances(
                older_than=now - s.connection_event_retention_hours * 3600.0, now=now
            )
        elif s.messages_days > 0:
            alert_instances_purged = await self._store.purge_alert_instances(
                older_than=now - s.messages_days * _SECONDS_PER_DAY, now=now
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
            conn_events_purged=conn_events_purged,
            wal_checkpointed=wal_checkpointed,
            vacuumed=vacuumed,
            size_bytes=size_bytes,
            over_limit=over_limit,
            messages_overrides=msg_days_overrides,
            dead_letter_overrides=dead_days_overrides,
            documents_messages_stripped=strip.messages_stripped,
            documents_stripped=strip.documents_stripped,
            documents_bytes_reclaimed=strip.bytes_reclaimed,
            document_prune_overrides=doc_overrides,
            alert_instances_purged=alert_instances_purged,
        )
        if result.did_work:
            await self._audit(result)
        return result

    # --- per-connection retention overrides (#34, ADR 0027) ------------------

    def _resolve_overrides(self) -> tuple[dict[str, int], dict[str, int]]:
        """Read the LIVE registry and return ``(messages_overrides, dead_letter_overrides)`` — the
        per-connection retention windows that DIFFER from "inherit the global window" (i.e. an explicit
        ``messages_days``/``dead_letter_days`` on the connection). ``None`` (inherit) connections are
        omitted so they fall back to the global cutoff; ``0`` (keep forever) and ``>0`` (days) are kept.

        Resolved each pass so a reload that changes an override takes effect on the next pass. Returns
        empty maps when no registry is wired (single global cutoff, byte-identical to the prior
        behaviour)."""
        registry = self._registry_source() if self._registry_source is not None else None
        if registry is None:
            return {}, {}
        messages = {
            ic.name: ic.messages_days
            for ic in registry.inbound.values()
            if ic.messages_days is not None
        }
        dead = {
            oc.name: oc.dead_letter_days
            for oc in registry.outbound.values()
            if oc.dead_letter_days is not None
        }
        return messages, dead

    def _resolve_document_prune(
        self,
    ) -> tuple[dict[str, int], dict[str, int], dict[str, str]]:
        """Read the LIVE registry and return ``(windows, min_bytes, content_types)`` for the inbounds that
        set ``prune_documents_after`` (#47, ADR 0042): ``windows`` is ``{inbound -> prune_documents_after
        days}`` (only the connections that opt in — there is NO global default, so an inbound without the
        field never strips), ``min_bytes`` is ``{inbound -> threshold}`` (0 when the connection omits it),
        and ``content_types`` is ``{inbound -> declared content_type}`` used to label a bare-mfb64
        tombstone. Resolved each pass so a reload takes effect next pass; empty when no registry is
        wired."""
        registry = self._registry_source() if self._registry_source is not None else None
        if registry is None:
            return {}, {}, {}
        windows: dict[str, int] = {}
        min_bytes: dict[str, int] = {}
        content_types: dict[str, str] = {}
        for ic in registry.inbound.values():
            if ic.prune_documents_after is None:
                continue
            windows[ic.name] = ic.prune_documents_after
            min_bytes[ic.name] = ic.prune_documents_min_bytes or 0
            content_types[ic.name] = ic.content_type.value
        return windows, min_bytes, content_types

    @staticmethod
    def _global_cutoff(now: float, days: int) -> float:
        """The global ``older_than`` cutoff for a window of ``days`` (the ELSE branch of the per-connection
        CASE — connections with no override use this). ``days <= 0`` means the global default is
        keep-forever, so the global cutoff is ``-inf`` (nothing without an override is purged)."""
        return now - days * _SECONDS_PER_DAY if days > 0 else _KEEP_FOREVER

    @staticmethod
    def _cutoff_map(now: float, day_overrides: Mapping[str, int]) -> dict[str, float]:
        """Turn a ``{connection -> days}`` override map into the ``{connection -> cutoff}`` the store
        purge takes: ``0`` = keep forever (``-inf`` → never purged), ``>0`` = ``now - days``. Empty in,
        empty out (so the purge SQL stays byte-identical to the single global cutoff)."""
        return {
            name: (now - days * _SECONDS_PER_DAY if days > 0 else _KEEP_FOREVER)
            for name, days in day_overrides.items()
        }

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
                "connection_event_retention_hours": self._settings.connection_event_retention_hours,
                "conn_events_purged": result.conn_events_purged,
                # Per-connection retention overrides applied this pass (#34, ADR 0027): the per-connection
                # cutoffs (connection name -> days; 0 = keep forever) alongside the global windows + the
                # aggregate purged counts above. Metadata only — never any message content (no PHI).
                # Empty in a global-only deployment (the audit detail stays byte-identical there).
                "messages_overrides": dict(result.messages_overrides),
                "dead_letter_overrides": dict(result.dead_letter_overrides),
                # Embedded-document pruning this pass (#47, ADR 0042): the per-connection windows
                # (inbound -> prune_documents_after days) + aggregate counts/bytes. Metadata only — no
                # message content. Empty when no connection sets a document-pruning window.
                "document_prune_overrides": dict(result.document_prune_overrides),
                "documents_messages_stripped": result.documents_messages_stripped,
                "documents_stripped": result.documents_stripped,
                "documents_bytes_reclaimed": result.documents_bytes_reclaimed,
                # Resolved operator-alert instances pruned this pass (#56, ADR 0044) — metadata only.
                "alert_instances_purged": result.alert_instances_purged,
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
