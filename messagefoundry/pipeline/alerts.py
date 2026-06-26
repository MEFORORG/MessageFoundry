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
