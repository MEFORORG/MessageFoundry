# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Operational alert emit-points for the delivery pipeline.

The conservative ordering defaults (FIFO head-of-line blocking, retry-forever, stop-connection on
internal error) are only *safe* if an operator is told when a lane stalls — a stopped connection or a
building backlog needs a human. A full alerting/notification framework is future work
(``docs/BACKLOG.md`` item 5); until it lands, the delivery worker emits these events to an
:class:`AlertSink` whose default implementation simply **logs** them at ``WARNING``. Wiring a real
notifier later is then a matter of passing a different sink to the
:class:`~messagefoundry.pipeline.wiring_runner.RegistryRunner` — the emit-points don't change.

This module is engine-side and dependency-light (stdlib logging only), so it never pulls the API or
console into the engine.
"""

from __future__ import annotations

import logging
from typing import Protocol

__all__ = ["AlertSink", "LoggingAlertSink"]

log = logging.getLogger(__name__)


class AlertSink(Protocol):
    """Where the delivery pipeline reports operational stalls. A real notifier (email/PagerDuty/…)
    implements this later; today the default :class:`LoggingAlertSink` just logs.

    Implementations must be cheap and non-blocking — they run inline on a delivery worker, so a slow
    sink would stall the lane it's reporting on. Never raise: an alert failure must not break delivery.
    """

    def connection_stopped(self, name: str, *, detail: str) -> None:
        """An outbound connection's delivery worker halted (``InternalErrorPolicy.STOP`` fired on an
        internal/code error). The lane is frozen until an operator intervenes (fix + reload/restart)."""
        ...

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        """An outbound connection's backlog crossed a depth / oldest-in-lane-age threshold — e.g. a
        retry-forever head is blocking the lane. (Emitted by the buildup detector — ordering Layer 4b.)"""
        ...

    def lane_stuck(self, name: str, *, detail: str) -> None:
        """A pooled lane is retrying a **persistent T17 machinery/infra fault** at capped backoff under
        the ``retry_forever`` infra-fault policy (ADR 0070) — the head has re-faulted past the stuck
        horizon but the lane is deliberately never STOPped, so this is an **alert only, never terminal**
        (auto-resolved on the next clean head via ADR-0044 durable state when wired). Distinct from
        :meth:`connection_stopped` (the ``stop``-policy terminal) so an operator can route a "still
        retrying, look at the dependency" signal apart from a halted lane. ``name`` is the stage-lane
        label; ``detail`` is a PHI-free reason (stage + streak). Emitted by the ``StageDispatcher``."""
        ...

    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None:
        """An outbound connection's **oldest undelivered message** aged past the configured
        ``StallThreshold`` (Corepoint "Max Message Stall", #50). Fired off the same oldest-pending age
        (``delivered_age``) as :meth:`queue_buildup`, but on a dedicated age-only threshold so an
        operator can page on "a message stuck > N seconds" independently of backlog *depth*. Off by
        default (deny-by-default — only fires when a threshold is configured). No PHI — the connection
        name + age only."""
        ...

    def saturation_rising(
        self, name: str, *, stage: str, depth: int, depth_start: int, growth_per_second: float
    ) -> None:
        """A lane is **becoming** overloaded (#93, ADR 0014 amendment): its pending backlog has been
        **rising sustained** across the sampling window — the DERIVATIVE signal, distinct from the
        absolute-snapshot ceilings of :meth:`queue_buildup` / :meth:`message_stall`. Sustained rising
        depth is, by conservation of the queue, ingest > drain held over the window, so a
        bursty-but-DRAINING lane (a spike that then falls back) never fires this while a genuinely
        saturating one does. ``name`` is the lane (connection) label; ``stage`` is the pipeline stage
        (``ingress``/``routed``/``outbound``) the backlog is growing in; ``depth`` is the current
        pending depth, ``depth_start`` the window's starting depth, ``growth_per_second`` the net rise
        rate. Off by default (deny-by-default — only fires when a threshold is configured). No PHI —
        the connection name + queue-shape derivative only. Emitted by the ``RegistryRunner``."""
        ...

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        """An outbound connection's delivery lane went **down** — the first transport failure
        (``DeliveryError``) after the lane was healthy, edge-triggered so a retry storm fires at most
        one alert per lane per cooldown (#46, Corepoint "connection lost"). ``kind`` is the connection-
        event kind (``connection_lost``); ``detail`` is a ``safe_exc``-scrubbed reason (no PHI). A
        partner *rejection* (``NegativeAckError``) is NOT a connection error and never fires this."""
        ...

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        """The message store grew past the configured ``[retention] max_db_mb`` advisory threshold.
        Emitted by the :class:`~messagefoundry.pipeline.retention.RetentionRunner` once per pass while
        over the limit; ``path`` identifies the DB, never any message content (no PHI)."""
        ...

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        """A served TLS certificate is expired or within the configured warn window. ``name`` labels
        which cert (``"api"`` or the connection name); ``path`` is the PEM file; ``not_after`` is the
        ISO expiry; ``days_remaining`` is negative once expired. No key material is read or logged.
        Emitted by the :class:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner`."""
        ...

    def secret_rotation_due(
        self, name: str, *, secret: str, last_rotated: str, days_overdue: int
    ) -> None:
        """A tracked long-lived secret is overdue (or within the warn window) for rotation (#195b, ADR
        0019 §5). ``name`` labels the secret (e.g. ``"store data-encryption key"``); ``secret`` is the
        secret's config/env **identifier** (e.g. ``"MEFOR_STORE_ENCRYPTION_KEY"``); ``last_rotated`` is
        the operator-configured ISO date it was last rotated; ``days_overdue`` is positive once past the
        max age, negative while still within the warn window. **No key material** is ever read or logged —
        only the identifier + rotation dates (no PHI). Emitted by the
        :class:`~messagefoundry.pipeline.secret_rotation.SecretRotationRunner`. Dedicated (not reusing
        :meth:`cert_expiry`) so an operator can route a rotation reminder apart from a cert-expiry alert."""
        ...

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        """Startup self-attestation found loaded engine module(s) that do not match the installed
        wheel ``RECORD`` baseline — a runtime in-place tamper tripwire (ADR 0041 D3, #54). ``name``
        labels the source (``"engine-integrity"``); ``reason`` is a PHI-free summary string;
        ``drift_count`` is how many module files drifted. Carries no file content (no PHI, nothing
        sensitive). Emitted by :func:`~messagefoundry.integrity.run_startup_attestation`. Dedicated
        rather than reusing :meth:`connection_stopped` so an operator can route/triage a tamper signal
        independently of a stalled delivery lane."""
        ...

    def update_available(self, name: str, *, current_version: str, pinned_version: str) -> None:
        """A newer MessageFoundry version is pinned/installed than is running (#30, ADR 0026). ``name``
        labels the package (``"messagefoundry"``); ``current_version`` is the running
        :data:`messagefoundry.__version__`; ``pinned_version`` is what the install pins. Carries **only**
        version strings — no PHI, no dependency list, no host data. Emitted by
        :class:`~messagefoundry.pipeline.update_check.UpdateCheckRunner` (the no-network local diff)."""
        ...

    def connection_restored(self, name: str) -> None:
        """An outbound lane recovered — the **inverse** of :meth:`connection_error` (``connection_lost``).
        Emits **no** notification (a recovery needs no page); it exists so durable alert-state (ADR 0044,
        #56) can **auto-resolve** the matching open ``connection_error`` instance when wired. The default
        :class:`LoggingAlertSink` and any state-less sink treat it as a no-op. ``name`` is the connection
        label only (no PHI)."""
        ...

    def backup_failed(self, name: str, *, kind: str, detail: str | None = None) -> None:
        """A scheduled or on-demand DR backup failed (ADR 0049, #60) — the snapshot, encrypt, write, or
        restore-verify step. ``name`` labels the source (``"dr_backup"``); ``kind`` is the failing phase
        (``snapshot``/``encrypt``/``write``/``verify``/``destination``); ``detail`` is a PHI-free,
        ``safe_exc``-scrubbed error **class/reason** — never a message body or key material. Dedicated
        (not reusing :meth:`storage_threshold`) so an operator can route/triage a backup failure
        independently of a store-size alert. Emitted by the
        :class:`~messagefoundry.pipeline.dr_backup.BackupRunner` (and the ``backup`` CLI), so a silent
        backup failure surfaces as an alert + the ``dr_backup`` ERROR disposition, not as a missing
        archive discovered during a disaster."""
        ...

    def rcsi_off_degraded(self, name: str, *, detail: str) -> None:
        """Pooled claim mode (ADR 0066) started on SQL Server with ``READ_COMMITTED_SNAPSHOT`` OFF and
        ``[pipeline].require_rcsi_for_pooled=false`` downgraded the fail-closed startup gate to a
        warning. The §3.2 correctness proofs + §8 CI gates are scoped to RCSI-on snapshot visibility,
        so this surfaces the degraded posture for an operator (it pairs with the ``/stats``
        ``rcsi_off_degraded`` gauge). ``name`` labels the source (``"pipeline"``); ``detail`` is a
        PHI-free reason. Dedicated (not reusing :meth:`connection_stopped`) so a degraded-posture signal
        is routable independently of a stalled delivery lane. No message content."""
        ...


class LoggingAlertSink:
    """Default :class:`AlertSink`: log each event at ``WARNING``. No PHI — only the connection name
    and queue shape are recorded, never a message body."""

    def connection_stopped(self, name: str, *, detail: str) -> None:
        log.warning(
            "ALERT connection_stopped: outbound %r halted on internal error: %s", name, detail
        )

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        log.warning(
            "ALERT queue_buildup: outbound %r backlog depth=%d oldest=%.0fs",
            name,
            depth,
            oldest_age_seconds,
        )

    def lane_stuck(self, name: str, *, detail: str) -> None:
        log.warning(
            "ALERT lane_stuck: lane %r retrying a persistent infra fault (retry_forever): %s",
            name,
            detail,
        )

    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None:
        log.warning(
            "ALERT message_stall: outbound %r oldest undelivered message stalled %.0fs",
            name,
            oldest_age_seconds,
        )

    def saturation_rising(
        self, name: str, *, stage: str, depth: int, depth_start: int, growth_per_second: float
    ) -> None:
        log.warning(
            "ALERT saturation: lane %r (%s) backlog RISING — depth %d→%d (+%.2f/s); ingest exceeding drain",
            name,
            stage,
            depth_start,
            depth,
            growth_per_second,
        )

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        log.warning("ALERT connection_error: outbound %r %s: %s", name, kind, detail or "")

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        log.warning(
            "ALERT storage_threshold: store %r is %.1f MB, over the %.1f MB retention limit",
            path,
            size_bytes / 1_000_000,
            limit_bytes / 1_000_000,
        )

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        if days_remaining < 0:
            log.warning(
                "ALERT cert_expiry: %r certificate (%s) EXPIRED %d day(s) ago (not_after=%s)",
                name,
                path,
                -days_remaining,
                not_after,
            )
        else:
            log.warning(
                "ALERT cert_expiry: %r certificate (%s) expires in %d day(s) (not_after=%s)",
                name,
                path,
                days_remaining,
                not_after,
            )

    def secret_rotation_due(
        self, name: str, *, secret: str, last_rotated: str, days_overdue: int
    ) -> None:
        if days_overdue > 0:
            log.warning(
                "ALERT secret_rotation: %r (%s) is OVERDUE for rotation by %d day(s) "
                "(last_rotated=%s)",
                name,
                secret,
                days_overdue,
                last_rotated,
            )
        else:
            log.warning(
                "ALERT secret_rotation: %r (%s) is due for rotation in %d day(s) (last_rotated=%s)",
                name,
                secret,
                -days_overdue,
                last_rotated,
            )

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        log.warning(
            "ALERT integrity_drift: %r detected %d drifted engine module(s): %s",
            name,
            drift_count,
            reason,
        )

    def update_available(self, name: str, *, current_version: str, pinned_version: str) -> None:
        log.warning(
            "ALERT update_available: %r running %s but %s is pinned/installed — update available",
            name,
            current_version,
            pinned_version,
        )

    def connection_restored(self, name: str) -> None:
        # State-less sink: a recovery needs no page and there is no instance to auto-resolve, so this is
        # a no-op (the connection_event lifecycle row is recorded by the runner, not here). ADR 0044 #56.
        return

    def backup_failed(self, name: str, *, kind: str, detail: str | None = None) -> None:
        log.warning("ALERT backup_failed: %r %s backup failed: %s", name, kind, detail or "")

    def rcsi_off_degraded(self, name: str, *, detail: str) -> None:
        log.warning(
            "ALERT rcsi_off_degraded: %r pooled claim mode running with READ_COMMITTED_SNAPSHOT OFF "
            "(require_rcsi_for_pooled=false): %s",
            name,
            detail,
        )
