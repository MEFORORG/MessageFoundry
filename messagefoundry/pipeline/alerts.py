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

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        """The message store grew past the configured ``[retention] max_db_mb`` advisory threshold.
        Emitted by the :class:`~messagefoundry.pipeline.retention.RetentionRunner` once per pass while
        over the limit; ``path`` identifies the DB, never any message content (no PHI)."""
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

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        log.warning(
            "ALERT storage_threshold: store %r is %.1f MB, over the %.1f MB retention limit",
            path,
            size_bytes / 1_000_000,
            limit_bytes / 1_000_000,
        )
