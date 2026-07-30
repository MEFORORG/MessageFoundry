# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Data-retention + store-maintenance worker (PHI.md §8, ASVS 14.2.x).

Without enforcement, PHI accumulates in the message store indefinitely — including dead-lettered
raw bodies. :class:`RetentionRunner` is the single background task that enforces the ``[retention]``
service settings: past the configured windows it **nulls message/dead-letter bodies while keeping
the message ROW** (the Mirth Data-Pruner pattern — counts, disposition, and the audit trail stay
intact; the row survives, its PHI columns — ``metadata`` included, ASVS 14.2.7 — do not). Tiers that
carry nothing BUT PHI and back no count (transform state, connection events, saved-search presets) are
DELETEd outright rather than blanked. It also checkpoints the WAL and ``VACUUM``s on a daily off-peak
schedule. Each
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
import os
import shutil
import tempfile
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field

from messagefoundry.config.settings import RetentionSettings
from messagefoundry.config.wiring import Registry
from messagefoundry.parsing.compression import CompressionError, gzip_compress, gzip_decompress
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pipeline.cluster import ClusterCoordinator, NullCoordinator
from messagefoundry.store import Store, StripResult

__all__ = ["RetentionRunner", "RetentionPass"]

log = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86_400
_BYTES_PER_MB = 1_000_000

#: What counts as an "application log file" in ``[logging].log_dir`` — the same notion the ``/status``
#: metering and the support-bundle tail use. Shared by the #120 delete sweep and the #119 compressor.
_APP_LOG_SUFFIXES = (".log", ".txt")
#: Suffix of the #119 gzip artifact, and of the temp file it is staged through (never a swept suffix,
#: so a crash mid-write can't leave a half-file that a later pass mistakes for a finished archive).
_GZ_SUFFIX = ".gz"
_GZ_TMP_SUFFIX = ".gz.mftmp"
#: Prefix of the staging file. The rest of the name is RANDOM (:func:`tempfile.mkstemp`), never derived
#: from the source: a predictable staging path in a directory a second process (or an attacker) can write
#: is an arbitrary-file-overwrite / log-destruction primitive — see :meth:`RetentionRunner._stage_archive`.
_GZ_TMP_PREFIX = "mfgz-"
#: Free-space precheck margin (#119): the peak on-disk cost of compressing a file is the source PLUS the
#: archive, and gzip's worst case (incompressible input) is marginally LARGER than the source — so the
#: requirement is ``size + max(10% of size, 1 MiB)``. Below that the file is skipped and logged rather
#: than attempted, so a maintenance pass can never be what fills the volume.
_COMPRESS_FREE_MARGIN_RATIO = 10  # divisor: size // 10 == 10%
_COMPRESS_FREE_MIN_MARGIN_BYTES = 1 << 20  # 1 MiB
#: Per-file ceiling (#119). The codec is bytes-in/bytes-out, so one file costs ~2x its size in RAM
#: (source + archive) plus the round-trip buffer during validation. NSSM rotates at ~10 MB, so 64 MiB is
#: ample headroom while bounding a maintenance pass's memory. A larger file is skipped and logged.
_COMPRESS_MAX_FILE_BYTES = 64 << 20  # 64 MiB

#: Per-connection "keep forever" (#34, ADR 0027): a cutoff of -inf makes ``received_at < cutoff`` always
#: false, so that connection's bodies are never purged even while the global window prunes others.
_KEEP_FOREVER = float("-inf")


def _is_app_log_name(name: str, *, include_archives: bool) -> bool:
    """Is ``name`` an application-log file this runner owns? ``.log``/``.txt`` always; the ``.log.gz``/
    ``.txt.gz`` archives the #119 compressor produces only when ``include_archives`` (so an unrelated
    ``.gz`` parked in the log directory is never swept, and neither is any ``.gz`` at all on a deployment
    that has not enabled compression)."""
    stem, ext = os.path.splitext(name.lower())
    if ext in _APP_LOG_SUFFIXES:
        return True
    if include_archives and ext == _GZ_SUFFIX:
        return os.path.splitext(stem)[1] in _APP_LOG_SUFFIXES
    return False


def _verify_archive(path: str, original: bytes, *, name: str) -> bool:
    """Integrity-validate a written gzip archive: re-read it **off disk**, decompress it, and compare it
    **byte-for-byte** with the source bytes. Only a True here may be followed by deleting the original.

    The original's length is the exact expected output size, so it doubles as the decompression-bomb
    ceiling (:func:`~messagefoundry.parsing.compression.gzip_decompress` refuses incrementally past it —
    a corrupt archive claiming to expand to gigabytes is rejected, not materialized). Every failure is
    logged with the file NAME and byte counts only; the round-tripped bytes are never logged (an
    application log is operational text, PHI.md §7)."""
    try:
        with open(path, "rb") as fh:
            blob = fh.read()
    except OSError:
        log.warning(
            "app-log archive for %r could not be re-read for validation; original kept", name
        )
        return False
    try:
        round_trip = gzip_decompress(blob, max_output_bytes=len(original))
    except CompressionError:
        log.warning(
            "app-log archive for %r failed integrity validation (corrupt/truncated); original kept",
            name,
        )
        return False
    if round_trip != original:
        log.warning(
            "app-log archive for %r failed integrity validation (%d bytes round-tripped, %d expected); "
            "original kept",
            name,
            len(round_trip),
            len(original),
        )
        return False
    return True


def _unlink_quietly(path: str) -> None:
    """Best-effort removal of a staging file. A leftover ``*.gz.mftmp`` is inert (never a swept suffix,
    never mistaken for an archive), so a failure here is logged at debug and otherwise ignored."""
    try:
        os.remove(path)
    except OSError:
        log.debug("could not remove the staging file %r", path, exc_info=True)


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
    # Application log FILES deleted this pass (#120): app-log files past the `app_log_days` window
    # removed from `[logging].log_dir`. Metadata only (mtime) — file content is never read. 0 when the
    # window/log_dir is unset (byte-identical audit for a deployment that doesn't use it).
    app_logs_deleted: int = 0
    # Application log FILES gzipped this pass (#119) and the on-disk bytes reclaimed (source size minus
    # archive size, summed over the files that compressed AND passed integrity validation). A file that
    # was skipped (no free space, oversized, already archived) or whose archive failed validation counts
    # in neither. Metadata only (names/sizes/mtimes) — file content is never logged or audited. Both 0
    # when the window/log_dir is unset, so a deployment that doesn't use it has a byte-identical audit.
    app_logs_compressed: int = 0
    app_log_bytes_reclaimed: int = 0
    # Saved-search presets DELETEd this pass (ADR 0136, ASVS 14.2.7): rows whose `updated_at` is past
    # the `search_preset_days` window. Metadata only — the count, never a needle. 0 when the window is
    # unset (the default), so a deployment that doesn't use it has a byte-identical audit detail.
    search_presets_purged: int = 0
    # Orphaned reference-snapshot ROWS deleted (ADR 0006, ASVS 14.2.7) — sets config no longer
    # declares. Metadata only: a count, never a key or a value. 0 when the window is unset, when no
    # registry is wired, or when the registry declares no reference sets (the positive-signal skip).
    reference_snapshots_purged: int = 0
    # This pass hit the `max_pass_seconds` between-phase duration cap (#121, ADR 0137) and SKIPPED its
    # remaining phases — the skipped tail (incl. any due WAL-checkpoint/VACUUM) re-runs next interval with
    # its last-run marker unadvanced. Always False when the cap is off (`max_pass_seconds<=0`, the
    # default), so a deployment that doesn't use the cap is byte-identical.
    capped: bool = False

    @property
    def did_work(self) -> bool:
        """Whether the pass changed anything worth an audit row (a routine WAL checkpoint alone
        isn't — it leaves no data trace and would otherwise spam the audit log every pass).

        A ``capped`` pass counts as work worth recording: an operator needs to see that maintenance ran
        out of its time budget and deferred phases (#121). With the cap off this is always False, so the
        audit cadence is unchanged."""
        return (
            self.messages_purged > 0
            or self.dead_purged > 0
            or self.state_purged > 0
            or self.conn_events_purged > 0
            or self.documents_messages_stripped > 0
            or self.alert_instances_purged > 0
            or self.app_logs_deleted > 0
            or self.app_logs_compressed > 0
            or self.search_presets_purged > 0
            or self.reference_snapshots_purged > 0
            or self.vacuumed
            or self.over_limit
            or self.capped
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
        monotonic: Callable[[], float] = time.monotonic,
        coordinator: ClusterCoordinator | None = None,
        registry_source: Callable[[], Registry | None] | None = None,
        log_dir: str | None = None,
    ) -> None:
        self._store = store
        self._settings = settings
        # The configured `[logging].log_dir` for application-log-file retention (#120). None (the
        # default; embedding/tests, or a stdout-only deployment) → the app-log sweep is a no-op.
        self._log_dir = log_dir
        # Per-connection retention overrides (#34, ADR 0027) are read from the LIVE registry each pass, so
        # a reload that changes an override takes effect on the next pass. None (the default) = no registry
        # wired → no overrides → a single global cutoff, byte-identical to the prior behaviour.
        self._registry_source = registry_source
        # Default to the logging sink so an over-limit store is at least visible without a notifier.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._clock = clock
        # A monotonic clock for the #121 between-phase duration cap — SEPARATE from `clock` (which is the
        # wall clock feeding the retention *window* cutoffs and is often frozen in tests). Measuring
        # elapsed pass time against a frozen window clock would never advance; monotonic can't go backwards.
        self._monotonic = monotonic
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
            or s.search_preset_days
            or s.reference_snapshot_days
            or s.max_db_mb
            or s.wal_checkpoint_seconds
            or s.vacuum_time() is not None
        ):
            return True
        # Application log-file retention (#120 delete, #119 compress) needs BOTH a window and a log_dir
        # to do anything, so only start the runner for it when both are present (avoids a no-op task for
        # a configured window on a stdout-only deployment).
        if (s.app_log_days > 0 or s.app_log_compress_days > 0) and self._log_dir:
            return True
        registry = self._registry_source() if self._registry_source is not None else None
        if registry is not None and any(  # noqa: SIM103
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
            "wal_checkpoint_seconds=%g vacuum_at=%r app_log_days=%d app_log_compress_days=%d "
            "max_pass_seconds=%g (every %gs)",
            self._settings.messages_days,
            self._settings.dead_letter_days,
            self._settings.max_db_mb,
            self._settings.wal_checkpoint_seconds,
            self._settings.vacuum_at,
            self._settings.app_log_days,
            self._settings.app_log_compress_days,
            self._settings.max_pass_seconds,
            self._settings.purge_interval_seconds,
        )

    async def stop(self) -> None:
        """Signal the loop and await its exit (idempotent)."""
        self._stop.set()
        task = self._task
        self._task = None
        if task is not None:
            task.cancel()
            try:  # noqa: SIM105
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
        try:  # noqa: SIM105
            await asyncio.wait_for(self._stop.wait(), delay)
        except TimeoutError:
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

        # Between-phase duration cap (#121, ADR 0137): bound the wall time one maintenance pass may spend
        # so a long pass can't run unbounded into the next window. `cap <= 0` (the default) disables it —
        # byte-identical to the pre-#121 pass. `_deadline_hit()` reads a MONOTONIC clock (not `now`, the
        # window wall-clock, which is often frozen in tests) and LATCHES `capped` the first time the elapsed
        # pass time reaches the cap; each phase below runs only while the deadline is NOT yet hit. The check
        # sits strictly BETWEEN phases — a phase that has already started always runs to completion, so a
        # running VACUUM is never interrupted (its deadline check happens only BEFORE it is dispatched).
        # Once the cap is hit the remaining phases are skipped and re-run next interval; a skipped
        # WAL-checkpoint/VACUUM leaves its last-run marker unadvanced, so it stays due (defer, don't drop).
        pass_start = self._monotonic()
        cap = s.max_pass_seconds
        capped = False

        def _deadline_hit() -> bool:
            nonlocal capped
            if not capped and cap > 0 and self._monotonic() - pass_start >= cap:
                capped = True
            return capped

        # Per-connection retention overrides (#34, ADR 0027), resolved once per pass from the LIVE
        # registry: inbound name -> messages_days, outbound name -> dead_letter_days (0 = keep forever,
        # None = inherit the global window so the connection is omitted from the cutoff map → it uses the
        # global cutoff). Empty when no registry/overrides → byte-identical single global cutoff.
        msg_days_overrides, dead_days_overrides = self._resolve_overrides()
        # A per-connection purge can run even when the GLOBAL window is off (a connection sets its own
        # window while the global default is keep-forever). Run the purge whenever the global window is
        # set OR any connection overrides it.
        messages_purged = 0
        if not _deadline_hit() and (s.messages_days > 0 or msg_days_overrides):
            messages_purged = await self._store.purge_message_bodies(
                older_than=self._global_cutoff(now, s.messages_days),
                now=now,
                connection_cutoffs=self._cutoff_map(now, msg_days_overrides),
            )
        dead_purged = 0
        if not _deadline_hit() and (s.dead_letter_days > 0 or dead_days_overrides):
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
        # The whole embedded-document strip is one phase: skip it (empty threshold set) if the cap was hit
        # before it; otherwise strip once per distinct min_bytes threshold.
        doc_thresholds: list[int] = [] if _deadline_hit() else sorted(set(doc_min_bytes.values()))
        for threshold in doc_thresholds:
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
        if not _deadline_hit() and s.state_max_age_days > 0:
            state_purged = await self._store.purge_state(
                older_than=now - s.state_max_age_days * _SECONDS_PER_DAY, now=now
            )
        # Connection events (#46): the dedicated `connection_event_retention_hours` window if set,
        # else inherit the message-body window (the ADR 0021 §7.5 default — bound the log alongside
        # the bodies). A positive hours value can keep events longer OR shorter than message bodies.
        conn_events_purged = 0
        if not _deadline_hit():
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
        if not _deadline_hit():
            if s.connection_event_retention_hours > 0:
                alert_instances_purged = await self._store.purge_alert_instances(
                    older_than=now - s.connection_event_retention_hours * 3600.0, now=now
                )
            elif s.messages_days > 0:
                alert_instances_purged = await self._store.purge_alert_instances(
                    older_than=now - s.messages_days * _SECONDS_PER_DAY, now=now
                )

        # Saved-search presets (ADR 0136, ASVS 14.2.7): the stored `criteria` is a PHI-shaped needle, so
        # it gets a window like every other PHI tier. A PLAIN window with NO inheritance — unlike
        # connection events above, an unset `search_preset_days` does NOT fall back to the body window.
        # A preset is a user-authored artifact whose `updated_at` only moves on a SAVE, so inheriting a
        # body window would silently delete every preset not re-saved inside it on the first pass after
        # upgrade (a PHI instance always has a bounded body window). Opt-in only. BACKLOG #306 softened
        # this further — the purge now keys on MAX(updated_at, last_used_at), so a preset merely RECALLED
        # inside the window survives; the argument above still holds for the first pass after upgrade,
        # where every pre-#306 row's `last_used_at` is NULL and the key degrades to `updated_at`.
        search_presets_purged = 0
        if not _deadline_hit() and s.search_preset_days > 0:
            search_presets_purged = await self._store.purge_search_presets(
                older_than=now - s.search_preset_days * _SECONDS_PER_DAY, now=now
            )

        # Orphaned reference snapshots (ADR 0006, ASVS 14.2.7): `reference.value` is PL-2 and had NO
        # purge path at all — a set dropped from config kept its decryptable rows forever, because the
        # only thing that ever replaced them was the next sync's build-new-then-flip, which never comes
        # for a set nobody declares.
        #
        # THE GUARD IS POSITIVE-SIGNAL, and that is the whole design. `declared` is the keep-set, so an
        # EMPTY one reads as "every set is abandoned" and would purge the entire store. `registry is
        # None` does not cover it: a registry that LOADS FINE while declaring zero reference sets — a
        # subset `--config`, a per-team config split, a harness-redirect run pointed at the real DB —
        # yields `references == {}`. Absence-based guards fail open by construction, so this one
        # requires a POSITIVE signal: at least one declared set, or the phase does not run at all. A
        # registry declaring zero reference sets can never authorize purging any.
        #
        # The store ALSO raises on an empty `declared` rather than trusting this check — belt and
        # braces, because the cost of one refactor dropping this line is every snapshot in the store.
        #
        # Worse without it: ReferenceSyncRunner deliberately does NOT advance `synced_at` when a source
        # fetch fails, so the rows most likely to look "stale" belong to a still-wired set whose source
        # is merely down — precisely the last-good copy an operator would want kept.
        reference_snapshots_purged = 0
        if not _deadline_hit() and s.reference_snapshot_days > 0:
            registry = self._registry_source() if self._registry_source is not None else None
            declared = frozenset(registry.references) if registry is not None else frozenset()
            if declared:
                reference_snapshots_purged = await self._store.purge_reference_snapshots(
                    older_than=now - s.reference_snapshot_days * _SECONDS_PER_DAY,
                    declared=declared,
                    now=now,
                )
            else:
                log.warning(
                    "reference-snapshot retention skipped: the loaded registry declares no reference "
                    "sets, so there is no keep-set and a purge would delete every snapshot in the "
                    "store. Set [retention].reference_snapshot_days=0 to silence this, or check that "
                    "--config points at the configuration this store belongs to."
                )

        # Application log-file retention (#120): delete app-log FILES older than `app_log_days` from
        # `[logging].log_dir`. Filesystem I/O (scandir/stat/unlink is blocking), so it runs off the
        # event loop; metadata only (mtime) — file content is never read (no PHI). A no-op unless the
        # window and a log_dir are both set, so a deployment that doesn't use it is byte-identical.
        app_logs_deleted = 0
        if not _deadline_hit() and s.app_log_days > 0 and self._log_dir:
            app_logs_deleted = await asyncio.to_thread(self._sweep_app_logs, now)

        # Application log-file compression (#119): gzip app-log FILES older than `app_log_compress_days`
        # in place, free-space-prechecked and integrity-validated before the original is removed. Its own
        # phase beside the #120 sweep and deliberately AFTER it, so a file the delete window has already
        # aged out is never compressed first (wasted I/O on a file about to vanish). Blocking file I/O
        # (scandir/read/write/fsync/unlink), so it runs off the event loop exactly as the sweep does. It
        # is the one phase that takes the deadline INSIDE itself (`_deadline_hit` is handed to the worker
        # and re-read PER FILE): it is a loop over an unbounded directory of up-to-64 MiB files, so
        # checking only before dispatch would let one dispatch run the whole directory and blow straight
        # through `max_pass_seconds` (#121). Per-file granularity is the natural interruption point — a
        # file is compressed whole or not at all, and whatever is left is simply still there next pass. A
        # no-op unless the window and a log_dir are both set → byte-identical for a deployment that's off.
        app_logs_compressed = 0
        app_log_bytes_reclaimed = 0
        if not _deadline_hit() and s.app_log_compress_days > 0 and self._log_dir:
            app_logs_compressed, app_log_bytes_reclaimed = await asyncio.to_thread(
                self._compress_app_logs, now, _deadline_hit
            )

        # Maintenance phases (WAL-checkpoint, then daily VACUUM). Their cadence markers advance ONLY when
        # the phase actually runs, so a phase SKIPPED by the cap stays due for the next pass (#121). A
        # running VACUUM is non-interruptible: the deadline is checked only BEFORE it is dispatched.
        wal_checkpointed = False
        if (
            not _deadline_hit()
            and s.wal_checkpoint_seconds > 0
            and now - self._last_wal >= s.wal_checkpoint_seconds
        ):
            await self._store.wal_checkpoint()
            self._last_wal = now
            wal_checkpointed = True

        vacuumed = False
        if not _deadline_hit() and self._vacuum_due(now):
            await self._store.vacuum()
            self._last_vacuum_day = self._day_key(now)
            vacuumed = True

        size_bytes, over_limit = (0, False) if _deadline_hit() else await self._check_size()

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
            app_logs_deleted=app_logs_deleted,
            app_logs_compressed=app_logs_compressed,
            app_log_bytes_reclaimed=app_log_bytes_reclaimed,
            search_presets_purged=search_presets_purged,
            reference_snapshots_purged=reference_snapshots_purged,
            capped=capped,
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

    def _sweep_app_logs(self, now: float) -> int:
        """Delete application-log FILES older than ``app_log_days`` from ``[logging].log_dir`` — one
        level, non-recursive, only ``.log``/``.txt`` regular files (the same notion of "app-log file"
        the ``/status`` metering and support-bundle tail use), by **mtime** so the currently-written
        file is never eligible. **Metadata only** — file content is never read (no PHI). Blocking
        (``scandir``/``stat``/``unlink``), so the caller runs it off the event loop. Never raises: a
        locked/vanished/permission-denied entry is skipped, not fatal — a log-retention hiccup must
        never take a purge pass down. Returns the number of files deleted.

        When (and ONLY when) compression is enabled (#119) the sweep also covers the archives it
        produces — ``*.log.gz``/``*.txt.gz`` — on the same window, so compressing a file does not make
        it immortal (the archive inherits the source's mtime, so it ages out on the original's clock).
        With ``app_log_compress_days = 0`` the eligible set is exactly the pre-#119 one, so a deployment
        that hasn't opted into compression is byte-identical."""
        days = self._settings.app_log_days
        if days <= 0 or not self._log_dir:
            return 0
        include_archives = self._settings.app_log_compress_days > 0
        cutoff = now - days * _SECONDS_PER_DAY
        deleted = 0
        try:
            entries = list(os.scandir(self._log_dir))
        except OSError:
            return 0  # directory absent/unreadable → nothing swept, never raise
        for entry in entries:
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                if not _is_app_log_name(entry.name, include_archives=include_archives):
                    continue
                if entry.stat(follow_symlinks=False).st_mtime >= cutoff:
                    continue
                os.remove(entry.path)
                deleted += 1
            except OSError:
                continue  # locked/vanished/denied file → skip, never fatal
        return deleted

    # --- application log-file compression (#119) -----------------------------

    def _compress_app_logs(self, now: float, deadline_hit: Callable[[], bool]) -> tuple[int, int]:
        """Gzip application-log FILES older than ``app_log_compress_days`` in ``[logging].log_dir`` to
        ``<name>.gz``, returning ``(files_compressed, bytes_reclaimed)``.

        Same file selection as the #120 sweep (one level, non-recursive, ``.log``/``.txt`` regular files,
        by **mtime** so the currently-written file is never eligible) — archives are never re-compressed.
        Five safety rules, in order, per file:

        0. **Stop at the pass deadline.** ``deadline_hit`` (the caller's ``max_pass_seconds`` latch, #121)
           is re-read **before every file**, so the phase releases the pass between files instead of
           running the whole directory in one uninterruptible call. Whatever is left is untouched and is
           simply picked up by the next pass — nothing is dropped, only deferred.
        1. **Never clobber.** An existing ``<name>.gz`` means the file is already archived (or a crash
           landed the archive but not the unlink); it is skipped, and the delete window cleans up.
        2. **Free-space precheck.** ``shutil.disk_usage`` must show room for the source *plus* its
           archive plus a margin, else the file is skipped and logged — a maintenance pass must never be
           what fills the volume. Re-read per file, since each compression changes what is free.
        3. **Never grow.** An archive that is not SMALLER than its source (an empty or already-compressed
           log) is discarded and the original left alone — compressing must not cost disk.
        4. **Integrity validation before deletion.** The archive is staged to an exclusively created,
           unpredictably named temp file (:meth:`_stage_archive`), ``fsync``ed, validated, renamed into
           place, and then **re-validated at ``dest``** — that last check, on the bytes actually sitting
           where the log used to be, is the only thing that authorizes removing the original. Any failure
           leaves the original **untouched** and is logged (:meth:`_compress_one`).

        The archive inherits the source's mtime so the ``app_log_days`` delete window keeps applying to
        it. Blocking I/O throughout, so the caller runs it off the event loop. Never raises — a
        locked/vanished/denied entry is skipped, not fatal. Names, counts and sizes are logged; file
        **content** never is (an application log is itself operational text, PHI.md §7)."""
        days = self._settings.app_log_compress_days
        if days <= 0 or not self._log_dir:
            return 0, 0
        cutoff = now - days * _SECONDS_PER_DAY
        compressed = 0
        reclaimed = 0
        try:
            entries = list(os.scandir(self._log_dir))
        except OSError:
            return 0, 0  # directory absent/unreadable → nothing compressed, never raise
        for entry in entries:
            # Per-file, not per-phase: one dispatch must not be able to overrun the whole pass budget.
            # Checked BETWEEN files, so a file already being compressed always finishes (the same
            # "never interrupt a started unit of work" rule the sibling phases follow).
            if deadline_hit():
                log.info(
                    "app-log compression stopped at the pass cap after %d file(s); "
                    "the rest are left for the next pass",
                    compressed,
                )
                break
            try:
                if not entry.is_file(follow_symlinks=False):
                    continue
                # include_archives=False: an existing `.gz` is the OUTPUT of this phase, never its input.
                if not _is_app_log_name(entry.name, include_archives=False):
                    continue
                st = entry.stat(follow_symlinks=False)
                if st.st_mtime >= cutoff:
                    continue
                dest = entry.path + _GZ_SUFFIX
                if os.path.exists(dest):
                    continue  # already archived — never clobber an existing artifact
                if st.st_size > _COMPRESS_MAX_FILE_BYTES:
                    log.warning(
                        "app-log compression skipped %r: %d bytes exceeds the %d-byte per-file ceiling",
                        entry.name,
                        st.st_size,
                        _COMPRESS_MAX_FILE_BYTES,
                    )
                    continue
                if not self._has_free_space(st.st_size, name=entry.name):
                    continue
                saved = self._compress_one(entry.path, dest, atime=st.st_atime, mtime=st.st_mtime)
                if saved is None:
                    continue  # skipped or failed validation — the original is still in place
                compressed += 1
                reclaimed += saved
            except OSError:
                # Locked/vanished/denied entry → skip, never fatal. Name only, never content.
                log.warning("app-log compression skipped %r (filesystem error)", entry.name)
                continue
        return compressed, reclaimed

    def _has_free_space(self, size: int, *, name: str) -> bool:
        """Free-space precheck: is there room to write ``size``'s archive **beside** it?

        Peak cost is the source plus the archive, and gzip's worst case (incompressible input) is
        marginally larger than the source — so the bar is ``size + max(10% of size, 1 MiB)``. Under it,
        the file is skipped and logged rather than attempted, so compression can never be what fills the
        volume. A free-space read that itself fails is treated as "no room" (fail closed)."""
        assert self._log_dir is not None  # guarded by the caller
        try:
            free = self._free_bytes(self._log_dir)
        except OSError:
            log.warning("app-log compression skipped %r: free space could not be read", name)
            return False
        required = size + max(size // _COMPRESS_FREE_MARGIN_RATIO, _COMPRESS_FREE_MIN_MARGIN_BYTES)
        if free < required:
            log.warning(
                "app-log compression skipped %r: %d bytes free on %r, %d required for a %d-byte source",
                name,
                free,
                self._log_dir,
                required,
                size,
            )
            return False
        return True

    @staticmethod
    def _free_bytes(path: str) -> int:
        """Bytes free on the filesystem holding ``path``. Split out from :meth:`_has_free_space` so the
        precheck is directly testable — a full volume cannot otherwise be simulated."""
        return shutil.disk_usage(path).free

    def _compress_one(self, source: str, dest: str, *, atime: float, mtime: float) -> int | None:
        """Gzip ``source`` → ``dest``, **validating the bytes at ``dest`` before removing the original**.

        Returns the bytes reclaimed, or ``None`` when the original was left in place (read/codec/write
        failure, a failed integrity check, or an archive that would not be SMALLER than the source).

        **What authorizes the unlink** is a read-back of ``dest`` *after* the rename — never a check
        against the staging path. Validating the staged file and then renaming "whatever is at that
        path" is a TOCTOU: any process that rewrites the staging file inside that window puts UNVALIDATED
        bytes at ``dest`` while the source is unlinked anyway, which destroys the only copy of the log and
        reports it as a success. Both checks are kept — the staged one so an unvalidated artifact is never
        placed at ``dest`` at all, the ``dest`` one because it is the only one that describes the bytes
        the delete is traded for. (The staging file itself is unpredictable and exclusively created, see
        :meth:`_stage_archive`, so that window is closed from the other side too.)"""
        name = os.path.basename(source)
        try:
            with open(source, "rb") as fh:
                data = fh.read()
        except OSError:
            log.warning("app-log compression skipped %r: unreadable", name)
            return None
        try:
            blob = gzip_compress(data)
        except CompressionError:
            # Message names the codec only — never content (parsing/compression.py contract).
            log.warning("app-log compression failed for %r: codec error; original kept", name)
            return None
        if len(blob) >= len(data):
            # Compressing would COST disk, not save it — an empty log (NSSM's `service.err.log` is
            # routinely 0 bytes, and a gzip member still carries an 18-byte header/trailer) or already-
            # compressed content. Leave the original alone rather than swap it for something bigger.
            # Re-evaluated each pass, which is the right trade: a few reads beat a permanent marker file.
            log.debug("app-log compression skipped %r: the archive would not be smaller", name)
            return None
        tmp = self._stage_archive(blob, os.path.dirname(source) or ".", name=name)
        if tmp is None:
            return None
        if not _verify_archive(tmp, data, name=name):
            _unlink_quietly(tmp)
            return None
        try:
            # Inherit the source's timestamps so the `app_log_days` delete window still ages the archive
            # out on the ORIGINAL file's clock (compressing a log must not reset its retention clock).
            os.utime(tmp, (atime, mtime))
            os.replace(tmp, dest)
        except OSError:
            log.warning(
                "app-log compression failed for %r: archive rename failed; original kept", name
            )
            _unlink_quietly(tmp)
            return None
        if not _verify_archive(dest, data, name=name):
            # The ONLY gate on the unlink below, and it did not pass: whatever is at `dest` is not this
            # log. Keep the original (it is still the only good copy) and do not count it as compressed.
            # The artifact at `dest` is deliberately NOT removed: under a concurrent compressor it may be
            # a VALID archive of a longer read of the same log whose source is already gone, and deleting
            # that would be the very data loss this check exists to prevent. It is inert (the next pass
            # skips a source whose `<name>.gz` exists) and the `app_log_days` window still ages it out.
            log.warning(
                "app-log %r: the archive did not validate AFTER being renamed into place; the original "
                "is kept and NOT counted as compressed. The unvalidated %r needs an operator's review.",
                name,
                os.path.basename(dest),
            )
            return None
        try:
            os.remove(source)
        except OSError:
            # The VALIDATED archive is in place but the original could not be removed (locked). Not
            # counted as compressed — the next pass sees `dest` and skips, and the delete window (or the
            # operator) clears the leftover. Nothing is lost either way.
            log.warning("app-log %r archived but the original could not be removed", name)
            return None
        # Measured against the bytes actually archived, not the earlier `stat` — the two differ if the
        # file grew between the scan and the read, and the reclaim figure must describe what happened.
        return len(data) - len(blob)

    @staticmethod
    def _stage_archive(blob: bytes, directory: str, *, name: str) -> str | None:
        """Write ``blob`` to a **freshly created, unpredictably named** staging file in ``directory``
        (the log directory, so the later :func:`os.replace` is a same-filesystem atomic rename), returning
        its path — or ``None``, with the failure logged, if it could not be written.

        :func:`tempfile.mkstemp` is what makes this safe, and both halves matter:

        * **Unpredictable.** The old name was ``<source>.gz.mftmp`` — derived from the source, so every
          process (and anything else able to write to the log directory) could compute it in advance and
          plant or rewrite the file the compressor is about to validate-and-rename. Predictability is
          what turns the rename into an attack primitive rather than a race one has to win blind.
        * **Exclusive.** ``mkstemp`` opens ``O_CREAT|O_EXCL`` (plus ``O_NOFOLLOW`` where the platform has
          it), so it **creates** the file or fails — it never truncates an existing file and never follows
          a symlink to one (CWE-59/CWE-377). Plain ``open(path, "wb")`` does both, which made the staging
          write an arbitrary-file-overwrite: a symlink at the predictable path pointed the compressor's
          write at any file the service account could touch, including other logs.

        This also makes concurrent compressors safe by construction — every shard runs its own
        RetentionRunner over the SAME ``[logging].log_dir`` (each shard is its own leader under
        ``NullCoordinator``), so a shared staging path was guaranteed collision, not a rare race."""
        fd = -1
        tmp = ""
        try:
            fd, tmp = tempfile.mkstemp(dir=directory, prefix=_GZ_TMP_PREFIX, suffix=_GZ_TMP_SUFFIX)
            with os.fdopen(fd, "wb") as out:
                fd = -1  # ownership handed to the file object; don't double-close in the handler
                out.write(blob)
                out.flush()
                # fsync so the validation reads what actually reached the disk, not the page cache —
                # the whole point is to prove the artifact before deleting the only other copy.
                os.fsync(out.fileno())
        except OSError:
            log.warning(
                "app-log compression failed for %r: archive write failed; original kept", name
            )
            if fd >= 0:
                try:
                    os.close(fd)
                except OSError:
                    log.debug("could not close the staging descriptor for %r", name, exc_info=True)
            if tmp:
                _unlink_quietly(tmp)
            return None
        return tmp

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
                # Application log files deleted this pass (#120) + the window — metadata only, no PHI.
                "app_log_days": self._settings.app_log_days,
                "app_logs_deleted": result.app_logs_deleted,
                # Application log files gzipped this pass (#119) + the window + bytes reclaimed. Counts
                # and sizes only — never a file name and never any file content (no PHI).
                "app_log_compress_days": self._settings.app_log_compress_days,
                "app_logs_compressed": result.app_logs_compressed,
                "app_log_bytes_reclaimed": result.app_log_bytes_reclaimed,
                # Saved-search presets DELETEd this pass (ADR 0136, ASVS 14.2.7) + the window. The COUNT
                # only — a preset's criteria is a PHI-shaped needle and never enters the audit detail.
                "search_preset_days": self._settings.search_preset_days,
                "search_presets_purged": result.search_presets_purged,
                # Orphaned reference-snapshot ROWS deleted (ADR 0006, ASVS 14.2.7) + the window. The
                # COUNT only — never a set name, key or value. A set name is operator-authored config
                # rather than PHI, but the ROWS are PL-2 and naming the set in a durable audit row would
                # narrow which patient cohort was dropped; the count is what an assessor needs.
                "reference_snapshot_days": self._settings.reference_snapshot_days,
                "reference_snapshots_purged": result.reference_snapshots_purged,
                # Between-phase duration cap (#121, ADR 0137): the configured ceiling + whether THIS pass
                # hit it and skipped its remaining phases. Timing metadata only — no PHI.
                "max_pass_seconds": self._settings.max_pass_seconds,
                "capped": result.capped,
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
