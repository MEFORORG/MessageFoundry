# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Secret-rotation reminder (#195b / ADR 0019 §5) — the secret-side twin of the TLS cert monitor.

Long-lived secrets (the store data-encryption key today; connector credentials in a future
``SecretProvider`` follow-on) have no natural expiry the way a TLS certificate does, so a stale key can
sit unrotated indefinitely with no in-engine signal. :class:`SecretRotationRunner` is a small background
task that periodically compares each tracked secret's **operator-configured last-rotated date** against
its **max age** and raises a ``secret_rotation_due`` alert when it is overdue or within
``[secret_rotation].warn_days`` of due.

**PHI-free / no key material:** it reads only the rotation *dates* an operator supplied in
``[secret_rotation]`` (plus a static human label + config identifier per secret) — it **never** reads,
loads, or logs any secret value. That is deliberate: a reminder needs the *when*, not the *what*.

Modelled **verbatim** on :class:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner`: an injected
clock + a pure :meth:`run_once` make it deterministically testable; the loop only governs cadence. The
set of secrets to watch is supplied by an injected **callable** so it is recomputed each pass (a config
reload is picked up automatically, and tests can drive it with a literal list). Engine-side and stdlib-
only, so it never pulls the API or console into the engine.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink

if TYPE_CHECKING:
    from messagefoundry.config.settings import SecretRotationSettings

__all__ = [
    "MonitoredSecret",
    "SecretCheck",
    "SecretRotationRunner",
    "secrets_from_settings",
]

log = logging.getLogger(__name__)

_UTC = datetime.timezone.utc


@dataclass(frozen=True)
class MonitoredSecret:
    """A long-lived secret whose rotation age the engine tracks. ``label`` names it in the alert (e.g.
    ``"store data-encryption key"``); ``secret`` is its config/env **identifier** (e.g.
    ``"MEFOR_STORE_ENCRYPTION_KEY"``) — **never the value**; ``last_rotated`` is the operator-configured
    date it was last rotated; ``max_age_days`` is how long it may live before rotation is due."""

    label: str
    secret: str
    last_rotated: datetime.date
    max_age_days: int


@dataclass(frozen=True)
class SecretCheck:
    """The outcome of inspecting one :class:`MonitoredSecret` — returned from
    :meth:`SecretRotationRunner.run_once` for the audit/test surface. ``days_overdue`` is positive once
    past the max age (overdue), negative while still within the warn window (approaching)."""

    label: str
    secret: str
    last_rotated_iso: str
    days_overdue: int

    @property
    def overdue(self) -> bool:
        return self.days_overdue > 0


def secrets_from_settings(settings: SecretRotationSettings) -> list[MonitoredSecret]:
    """Enumerate the secrets to watch from ``[secret_rotation]``. Today that is the **store DEK**, tracked
    **deny-by-default**: it is watched only once an operator sets ``store_key_last_rotated`` (an ISO date).
    An unset last-rotated → the DEK is not tracked (empty list → the runner is a no-op). The connector-
    credential ``SecretProvider`` generalization (ADR 0019 §5) is a design-only follow-on and is not
    enumerated here yet."""
    secrets: list[MonitoredSecret] = []
    if settings.store_key_last_rotated:
        # Validated at settings load (ISO YYYY-MM-DD), so fromisoformat is safe here.
        secrets.append(
            MonitoredSecret(
                label="store data-encryption key",
                secret="MEFOR_STORE_ENCRYPTION_KEY",  # nosec B106 — the secret's env-var NAME/label, never its value
                last_rotated=datetime.date.fromisoformat(settings.store_key_last_rotated),
                max_age_days=settings.store_key_max_age_days,
            )
        )
    return secrets


class SecretRotationRunner:
    """Periodically scans the tracked secrets and raises ``secret_rotation_due`` alerts for any overdue or
    within-window. Construct with a ``secret_source`` callable (recomputed each pass) + the
    ``[secret_rotation]`` settings; call :meth:`start`/:meth:`stop` for the supervised loop, or
    :meth:`run_once` for a single deterministic pass (tests)."""

    def __init__(
        self,
        secret_source: Callable[[], Sequence[MonitoredSecret]],
        settings: SecretRotationSettings,
        *,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._secret_source = secret_source
        self._settings = settings
        # Default to the logging sink so an overdue secret is at least visible without a notifier.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._clock = clock
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @property
    def enabled(self) -> bool:
        """True when ``warn_days > 0``. When False, :meth:`start` spawns no task (the reminder is off)."""
        return self._settings.warn_days > 0

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised scan loop (no-op when ``warn_days`` is 0)."""
        if self._task is not None:
            return
        if not self.enabled:
            log.debug(
                "secret rotation reminder disabled (secret_rotation.warn_days=0); not starting"
            )
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "secret rotation reminder enabled: warn within %d days (every %gs)",
            self._settings.warn_days,
            self._settings.check_interval_seconds,
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
        # One isolated scan per interval; an error in a pass is logged and the loop continues (a reminder
        # scan must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("secret rotation scan failed; will retry next interval")
            await self._sleep(self._settings.check_interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    def run_once(self, now: float | None = None) -> list[SecretCheck]:
        """Inspect every tracked secret for ``now`` (default: the injected clock), emitting a
        ``secret_rotation_due`` alert for each overdue or within-window secret. Pure + synchronous;
        returns one :class:`SecretCheck` per secret. No secret value is read — only the configured dates."""
        now = self._clock() if now is None else now
        today = datetime.datetime.fromtimestamp(now, tz=_UTC).date()
        checks: list[SecretCheck] = []
        warn_days = self._settings.warn_days
        for secret in self._secret_source():
            age_days = (today - secret.last_rotated).days
            days_overdue = age_days - secret.max_age_days
            check = SecretCheck(
                label=secret.label,
                secret=secret.secret,
                last_rotated_iso=secret.last_rotated.isoformat(),
                days_overdue=days_overdue,
            )
            checks.append(check)
            # Emit once overdue OR within warn_days of due — the secret-side mirror of the cert monitor's
            # `days_remaining <= warn_days` (here days_until_due = -days_overdue).
            if days_overdue >= -warn_days:
                # The sink never raises (contract), but be defensive — one bad sink call must not abort
                # the scan of the remaining secrets.
                try:
                    self._alert_sink.secret_rotation_due(
                        check.label,
                        secret=check.secret,
                        last_rotated=check.last_rotated_iso,
                        days_overdue=check.days_overdue,
                    )
                except Exception:
                    log.warning(
                        "secret_rotation alert sink failed for %r", check.label, exc_info=True
                    )
        return checks
