# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""TLS-certificate expiry monitor (Q5c / ADR 0002).

Now that native off-loopback TLS is the supported posture, a **silently expired** API or MLLP
certificate is a hard PHI-feed outage at renewal time with no in-engine alarm. :class:`CertExpiryRunner`
is a small background task that periodically reads the certificate PEM files the engine actually serves
with — the ``[api]`` TLS cert and every connection's ``tls_cert_file`` (MLLP server/client identity) —
and raises a ``cert_expiry`` alert when one is expired or within ``[cert_monitor].warn_days`` of expiry.
It reads only the **public certificate** (``notAfter``), never any private key, and never message
content (no PHI).

Engine-owned (started in :meth:`Engine.start`, stopped in :meth:`Engine.stop`) and modelled on the
:class:`~messagefoundry.pipeline.retention.RetentionRunner`: an injected clock + a pure :meth:`run_once`
make it deterministically testable; the loop only governs cadence. The set of certs to watch is supplied
by an injected **callable** so it is recomputed each pass — a config reload that adds or removes a TLS
connection is picked up automatically — and so tests can drive it with a literal list.

Engine-side and dependency-light (stdlib + ``cryptography`` — already a core dep for PHI-at-rest), so it
never pulls the API or console into the engine.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from cryptography import x509

from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink

if TYPE_CHECKING:
    from messagefoundry.config.wiring import Registry

__all__ = ["MonitoredCert", "CertCheck", "CertExpiryRunner", "certs_from_registry"]

log = logging.getLogger(__name__)

_SECONDS_PER_DAY = 86_400


@dataclass(frozen=True)
class MonitoredCert:
    """A certificate file the engine serves with: ``label`` identifies it in the alert (``"api"`` or a
    connection name); ``path`` is the PEM file to read (public cert only — never its key)."""

    label: str
    path: str


@dataclass(frozen=True)
class CertCheck:
    """The outcome of inspecting one :class:`MonitoredCert` — returned from :meth:`CertExpiryRunner.run_once`
    for the audit/test surface. ``days_remaining`` is negative once the cert is expired."""

    label: str
    path: str
    not_after_iso: str
    days_remaining: int

    @property
    def expired(self) -> bool:
        return self.days_remaining < 0


def certs_from_registry(
    registry: Registry | None, api_tls_cert_file: str | None
) -> list[MonitoredCert]:
    """Enumerate the certs the engine serves with: the ``[api]`` TLS cert plus every wired connection
    carrying a ``tls_cert_file`` (MLLP inbound server identity / outbound mTLS client cert). A cert path
    supplied as a deferred ``env()`` reference (not yet a literal ``str``) is skipped — it is resolved
    per-environment elsewhere and is not a readable path here."""
    certs: list[MonitoredCert] = []
    if isinstance(api_tls_cert_file, str) and api_tls_cert_file:
        certs.append(MonitoredCert("api", api_tls_cert_file))
    if registry is not None:
        # Separate loops (not a merged tuple) so each connection keeps its concrete type — mypy widens a
        # star-unpacked ``(*inbound, *outbound)`` of two different value views to ``object``.
        for ib in registry.inbound.values():
            ib_path = ib.spec.settings.get("tls_cert_file")
            if isinstance(ib_path, str) and ib_path:
                certs.append(MonitoredCert(ib.name, ib_path))
        for ob in registry.outbound.values():
            ob_path = ob.spec.settings.get("tls_cert_file")
            if isinstance(ob_path, str) and ob_path:
                certs.append(MonitoredCert(ob.name, ob_path))
    return certs


class CertExpiryRunner:
    """Periodically scans the served certs and raises ``cert_expiry`` alerts for any expired or
    within-window. Construct with a ``cert_source`` callable (recomputed each pass) + the
    ``[cert_monitor]`` settings; call :meth:`start`/:meth:`stop` for the supervised loop, or
    :meth:`run_once` for a single deterministic pass (tests)."""

    def __init__(
        self,
        cert_source: Callable[[], Sequence[MonitoredCert]],
        settings: CertMonitorSettings,
        *,
        alert_sink: AlertSink | None = None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._cert_source = cert_source
        self._settings = settings
        # Default to the logging sink so an expiring cert is at least visible without a notifier.
        self._alert_sink: AlertSink = alert_sink or LoggingAlertSink()
        self._clock = clock
        self._stop = asyncio.Event()
        self._task: asyncio.Task[None] | None = None

    @property
    def enabled(self) -> bool:
        """True when ``warn_days > 0``. When False, :meth:`start` spawns no task (the monitor is off)."""
        return self._settings.warn_days > 0

    # --- lifecycle -----------------------------------------------------------

    def start(self) -> None:
        """Spawn the supervised scan loop (no-op when ``warn_days`` is 0)."""
        if self._task is not None:
            return
        if not self.enabled:
            log.debug("cert monitor disabled (cert_monitor.warn_days=0); not starting")
            return
        self._stop.clear()
        self._task = asyncio.create_task(self._run())
        log.info(
            "cert monitor enabled: warn within %d days (every %gs)",
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
        # One isolated scan per interval; an error in a pass is logged and the loop continues (a cert
        # check must never take the engine down). Cooperatively cancellable via _stop.
        while not self._stop.is_set():
            try:
                self.run_once()
            except Exception:
                log.exception("cert expiry scan failed; will retry next interval")
            await self._sleep(self._settings.check_interval_seconds)

    async def _sleep(self, delay: float) -> None:
        """Sleep up to ``delay``, waking immediately on stop (so shutdown isn't held by the interval)."""
        try:
            await asyncio.wait_for(self._stop.wait(), delay)
        except asyncio.TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    def run_once(self, now: float | None = None) -> list[CertCheck]:
        """Inspect every served cert for ``now`` (default: the injected clock), emitting a
        ``cert_expiry`` alert for each expired or within-window cert. Synchronous (a few small file
        reads); returns one :class:`CertCheck` per readable cert. Unreadable/missing certs are logged
        and skipped — a typo'd path must not silence the monitor for the others."""
        now = self._clock() if now is None else now
        checks: list[CertCheck] = []
        for cert in self._cert_source():
            check = self._inspect(cert, now)
            if check is None:
                continue
            checks.append(check)
            if check.days_remaining <= self._settings.warn_days:
                # The sink never raises (contract), but be defensive — one bad sink call must not
                # abort the scan of the remaining certs.
                try:
                    self._alert_sink.cert_expiry(
                        check.label,
                        path=check.path,
                        not_after=check.not_after_iso,
                        days_remaining=check.days_remaining,
                    )
                except Exception:
                    log.warning("cert_expiry alert sink failed for %r", check.label, exc_info=True)
        return checks

    def _inspect(self, cert: MonitoredCert, now: float) -> CertCheck | None:
        try:
            with open(cert.path, "rb") as fh:
                pem = fh.read()
            certificate = x509.load_pem_x509_certificate(pem)
            not_after = certificate.not_valid_after_utc  # tz-aware UTC (cryptography >= 42)
        except FileNotFoundError:
            log.warning("cert_expiry: certificate for %r not found: %s", cert.label, cert.path)
            return None
        except Exception:
            log.warning(
                "cert_expiry: could not read/parse certificate for %r (%s)",
                cert.label,
                cert.path,
                exc_info=True,
            )
            return None
        days_remaining = int((not_after.timestamp() - now) // _SECONDS_PER_DAY)
        return CertCheck(
            label=cert.label,
            path=cert.path,
            not_after_iso=not_after.isoformat(),
            days_remaining=days_remaining,
        )
