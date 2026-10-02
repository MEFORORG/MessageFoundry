# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import datetime
import gc
import logging
import ssl
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from messagefoundry.config.loaded_crls import HeldCrlSnapshot, crl_fingerprint
from messagefoundry.config.loaded_crls import snapshot as held_crl_snapshot
from messagefoundry.config.settings import CertMonitorSettings
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink
from messagefoundry.pki import (
    CertFacts,
    CrlFacts,
    read_cert_facts,
    read_soonest_crl_facts,
    soonest_crl,
)

if TYPE_CHECKING:
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.wiring import Registry

__all__ = [
    "MonitoredCert",
    "CertCheck",
    "CertExpiryRunner",
    "certs_from_registry",
    "crls_from_settings",
    "held_crl_label",
    "peer_cert_expiry",
]

log = logging.getLogger(__name__)

#: Day length for ``days_remaining``. Pinned equal to :mod:`messagefoundry.pki`'s own constant (a test
#: asserts the parity) so a cert observed at the mTLS handshake and the same cert read from a PEM file
#: report the SAME days-remaining — otherwise the two 6.4.5 monitor arms could disagree by a day.
_SECONDS_PER_DAY = 86_400


@dataclass(frozen=True)
class MonitoredCert:
    """A certificate file the engine serves with: ``label`` identifies it in the alert (``"api"`` or a
    connection name); ``path`` is the PEM file to read (public cert only — never its key)."""

    label: str
    path: str
    #: ``"cert"`` or ``"crl"`` (BACKLOG #1005). Defaults so every existing construction is unchanged.
    #: A CRL is watched by the same monitor because the operator question is identical -- "is a file
    #: I depend on about to expire" -- but it alerts down a SEPARATE sink method, because an expired
    #: CRL fails every handshake it verifies rather than degrading one identity.
    kind: str = "cert"


@dataclass(frozen=True)
class CertCheck:
    """The outcome of inspecting one :class:`MonitoredCert` — returned from :meth:`CertExpiryRunner.run_once`
    for the audit/test surface. ``days_remaining`` is negative once the cert is expired."""

    label: str
    path: str
    not_after_iso: str
    days_remaining: int
    kind: str = "cert"

    @property
    def expired(self) -> bool:
        return self.days_remaining < 0


def _noun(cert: MonitoredCert) -> str:
    """What to call the file in a log line, so a broken CRL is not reported as a certificate."""
    return "CRL" if cert.kind == "crl" else "certificate"


def client_cert_label(path: str) -> str:
    """The alert label for an operator-listed **service-caller** client cert (ASVS 6.4.5), namespaced so
    it can never collide with the ``"api"`` label or a connection name.

    Built from the **whole path**, not the file stem, because this label becomes the alert event's
    ``connection`` — the key for the re-alert throttle AND the durable ``alert_instance`` row. A stem
    is not unique across the configured list: the natural per-partner layout
    (``…/acme/client.pem``, ``…/globex/client.pem``) collapses to one key, and since
    :meth:`CertExpiryRunner.run_once` emits every cert in ONE synchronous pass, the second would land
    inside the first's ``realert_seconds`` cooldown and be dropped before any transport saw it — on
    every pass, permanently. That is invisible on the ``LoggingAlertSink`` (which never throttles) and
    only bites where a real notifier is wired, i.e. exactly where an operator relies on being paged.
    Full paths are injective by construction and are what an operator needs anyway (which file to
    renew) — the same reason :meth:`AlertSink.storage_threshold` keys on the DB path."""
    return f"api-client:{path}"


def certs_from_registry(
    registry: Registry | None,
    api_tls_cert_file: str | None,
    client_cert_files: Sequence[str] = (),
) -> list[MonitoredCert]:
    """Enumerate the certs the engine serves with: the ``[api]`` TLS cert plus every wired connection
    carrying a ``tls_cert_file`` (MLLP inbound server identity / outbound mTLS client cert). A cert path
    supplied as a deferred ``env()`` reference (not yet a literal ``str``) is skipped — it is resolved
    per-environment elsewhere and is not a readable path here.

    ``client_cert_files`` (``[api].tls_client_cert_files``) additionally folds in the certs of **inbound
    service callers** the operator holds copies of (ASVS 6.4.5). Those are certs the engine *verifies*
    rather than *presents*, so they are invisible to the served-cert enumeration above; listing them here
    closes the handshake monitor's admitted gap — a caller that simply stops connecting would otherwise
    expire silently, since a handshake-observed cert can only be seen while that caller still calls."""
    certs: list[MonitoredCert] = []
    if isinstance(api_tls_cert_file, str) and api_tls_cert_file:
        certs.append(MonitoredCert("api", api_tls_cert_file))
    for client_path in client_cert_files:
        if isinstance(client_path, str) and client_path:
            certs.append(MonitoredCert(client_cert_label(client_path), client_path))
    if registry is not None:
        # Separate loops (not a merged tuple) so each connection keeps its concrete type — mypy widens a
        # star-unpacked ``(*inbound, *outbound)`` of two different value views to ``object``.
        for ib in registry.inbound.values():
            ib_path = ib.spec.settings.get("tls_cert_file")
            if isinstance(ib_path, str) and ib_path:
                certs.append(MonitoredCert(ib.name, ib_path))
            # BACKLOG #1005: a configured CRL expires like a certificate, and unrefreshed it takes
            # the listener DOWN -- past nextUpdate OpenSSL refuses every client, not just revoked
            # ones. Per-connection only on inbound: an outbound hop has no per-connection CRL knob,
            # and its CRLs are instance-wide settings that crls_from_settings collects (BACKLOG #299).
            ib_crl = ib.spec.settings.get("tls_crl_file")
            if isinstance(ib_crl, str) and ib_crl:
                certs.append(MonitoredCert(ib.name, ib_crl, kind="crl"))
        for ob in registry.outbound.values():
            ob_path = ob.spec.settings.get("tls_cert_file")
            if isinstance(ob_path, str) and ob_path:
                certs.append(MonitoredCert(ob.name, ob_path))
    return certs


def crls_from_settings(settings: ServiceSettings) -> list[MonitoredCert]:
    """The CRL files the service settings configure, each as a ``kind="crl"`` :class:`MonitoredCert`
    (BACKLOG #299).

    These are the instance-wide CRL knobs that no connection carries, so :func:`certs_from_registry`
    cannot see them. All but one are outbound: ``[tls].crl_file`` (the outbound hops whose context
    the engine builds from the resolved ``[tls]`` trust anchor), ``[logging].forward_tls_crl_file``,
    ``[auth].oidc_tls_crl_file`` and ``[store].ssl_crl_file``. ``[api].tls_client_crl_file`` is the
    API listener's inbound CRL. Each is read when its hop builds a TLS context. Past ``nextUpdate``
    it fails every handshake it verifies. Before this, an outbound CRL going stale raised nothing
    until a handshake or a context build failed on it.

    A knob is watched whenever it is set, even where no hop loads it (for example
    ``[api].tls_client_crl_file`` with no client CA). That errs toward a spurious alert over a
    missed one, and it keeps this list free of copies of each consumer's own conditions.

    The label is the setting's dotted name, such as ``"tls.crl_file"``. The labels stay injective:
    a connection name cannot hold ``.``, ``"api"`` is bare, and a service-caller label starts with
    ``"api-client:"``, which no dotted name here does. So the re-alert throttle, which keys on the
    label, can never merge two hops. The name holds no ``[`` or ``]`` on purpose: an alert rule
    matches the label with ``fnmatch``, which reads brackets as a character class, so a rule that
    copied a bracketed label would never match it. Two knobs naming one file give two rows, one
    per hop that depends on it."""
    knobs = (
        ("tls.crl_file", settings.tls.crl_file),
        ("logging.forward_tls_crl_file", settings.logging.forward_tls_crl_file),
        ("auth.oidc_tls_crl_file", settings.auth.oidc_tls_crl_file),
        ("store.ssl_crl_file", settings.store.ssl_crl_file),
        ("api.tls_client_crl_file", settings.api.tls_client_crl_file),
    )
    # The isinstance guard matches certs_from_registry: a value that is not yet a literal path string
    # is not a readable file here, so it is skipped rather than handed to open().
    return [
        MonitoredCert(label, path, kind="crl")
        for label, path in knobs
        if isinstance(path, str) and path
    ]


def peer_cert_expiry(peercert: Mapping[str, Any], *, now: float) -> tuple[str, int] | None:
    """``(not_after_iso, days_remaining)`` for a verified peer certificate, or ``None`` when the cert
    carries no parseable ``notAfter`` (ASVS 6.4.5).

    Pure. Takes the ``ssl.getpeercert()`` **dict** an mTLS handshake yields — the form the API's
    cert-identity resolver already holds — rather than PEM bytes, so a service caller's cert can be
    checked at handshake time with no file to read and no key material touched. ``days_remaining`` is
    negative once expired and uses the same day math as :func:`~messagefoundry.pki.read_cert_facts`, so
    the handshake arm and the file-based monitor never disagree about the same cert.

    Never raises: an absent/garbled ``notAfter`` returns ``None`` (the caller then simply does not
    alert) — a monitoring signal must not be able to fail an authentication path."""
    raw = peercert.get("notAfter")
    if not isinstance(raw, str) or not raw:
        return None
    try:
        # OpenSSL's own textual form ("Jun  1 12:00:00 2027 GMT") — parsed by the stdlib, never by hand.
        epoch = float(ssl.cert_time_to_seconds(raw))
    except (ValueError, OverflowError, OSError):
        return None
    try:
        not_after_iso = datetime.datetime.fromtimestamp(epoch, tz=datetime.UTC).isoformat()
    except (ValueError, OverflowError, OSError):
        return None
    return (not_after_iso, int((epoch - now) // _SECONDS_PER_DAY))


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
        watch_unlisted_held_crls: bool = False,
    ) -> None:
        self._cert_source = cert_source
        self._settings = settings
        # BACKLOG #299: also judge CRL files that live hops hold and no row names. The registry is
        # process-wide, so this is for the engine's own monitor; a runner handed a literal list (a
        # test, a one-off scan) leaves it off and judges exactly the rows it was given.
        self._watch_unlisted_held_crls = watch_unlisted_held_crls
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
            try:  # noqa: SIM105
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
        try:  # noqa: SIM105
            await asyncio.wait_for(self._stop.wait(), delay)
        except TimeoutError:
            pass

    # --- one pass ------------------------------------------------------------

    def run_once(self, now: float | None = None) -> list[CertCheck]:
        """Inspect every served cert for ``now`` (default: the injected clock), emitting a
        ``cert_expiry`` alert for each expired or within-window cert. Synchronous (a few small file
        reads); returns one :class:`CertCheck` per cert it could judge. An unreadable or missing file
        is logged, and skipped unless it is a CRL a live TLS context still holds a copy of, which is
        then judged by that copy (BACKLOG #299). A typo'd path must not silence the others."""
        now = self._clock() if now is None else now
        held = self._held_snapshot()
        checks: list[CertCheck] = []
        for cert in self._rows(held):
            check = self._inspect(cert, now, held)
            if check is None:
                continue
            checks.append(check)
            if check.days_remaining <= self._settings.warn_days:
                if check.kind == "crl":
                    try:
                        self._alert_sink.crl_expiry(
                            check.label,
                            path=check.path,
                            not_after=check.not_after_iso,
                            days_remaining=check.days_remaining,
                        )
                    except Exception:
                        log.warning(
                            "crl_expiry alert sink failed for %r", check.label, exc_info=True
                        )
                    continue
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

    def _held_snapshot(self) -> HeldCrlSnapshot:
        """One snapshot of the CRL copies live contexts hold, taken once per pass (BACKLOG #299).

        The engine's monitor collects garbage first, so a probe or discarded connector caught in a
        reference cycle does not read as a live hop holding a copy. A failure is logged and yields
        an empty snapshot, which leaves each file's own verdict standing."""
        try:
            if self._watch_unlisted_held_crls:
                gc.collect()
            return held_crl_snapshot()
        except Exception:
            log.error("cert_expiry: could not read the CRL copies live hops hold", exc_info=True)
            return HeldCrlSnapshot(())

    def _rows(self, held: HeldCrlSnapshot) -> list[MonitoredCert]:
        """The injected rows, plus one per CRL file a live context holds that no row names.

        BACKLOG #299: a hop can load a CRL from a path the rows cannot spell, such as an inbound
        ``tls_crl_file`` given as a deferred ``env()`` value, which :func:`certs_from_registry`
        skips. Without a row, that copy could lapse and refuse every peer with no alert."""
        rows = list(self._cert_source())
        if not self._watch_unlisted_held_crls:
            return rows
        unwatched = held.unwatched(row.path for row in rows if row.kind == "crl")
        rows.extend(MonitoredCert(held_crl_label(path), path, kind="crl") for path in unwatched)
        return rows

    def _inspect(
        self, cert: MonitoredCert, now: float, held: HeldCrlSnapshot | None = None
    ) -> CertCheck | None:
        # The load / notAfter / days-remaining path lives once in pki.read_cert_facts; this monitor
        # only needs notAfter + days_remaining from the returned public facts.
        pem: bytes | None = None
        crl_facts: CrlFacts | None = None
        facts: CertFacts | None = None
        try:
            with open(cert.path, "rb") as fh:
                pem = fh.read()
            if cert.kind == "crl":
                # The soonest nextUpdate in the file, not the first block's: a multi-issuer file
                # fails a handshake once ANY of its CRLs lapses (BACKLOG #299).
                crl_facts = read_soonest_crl_facts(pem, now=now)
            else:
                facts = read_cert_facts(pem, now=now)
        except FileNotFoundError:
            log.warning("cert_expiry: %s for %r not found: %s", _noun(cert), cert.label, cert.path)
        except Exception:
            log.warning(
                "cert_expiry: could not read/parse %s for %r (%s)",
                _noun(cert),
                cert.label,
                cert.path,
                exc_info=True,
            )
        if cert.kind == "crl":
            return _judge_crl(
                cert, now, pem, crl_facts, held if held is not None else held_crl_snapshot()
            )
        if facts is None:
            return None
        return CertCheck(
            label=cert.label,
            path=cert.path,
            not_after_iso=facts.not_after_iso,
            days_remaining=facts.days_remaining,
        )


def held_crl_label(path: str) -> str:
    """The alert label for a CRL file a live hop holds that no configured row names (BACKLOG #299).

    Namespaced like :func:`client_cert_label` and for the same reason: the label keys the re-alert
    throttle, and a full path is injective where a connection name or setting name might not be."""
    return f"held-crl:{path}"


def _judge_crl(
    cert: MonitoredCert,
    now: float,
    pem: bytes | None,
    file_facts: CrlFacts | None,
    held: HeldCrlSnapshot,
) -> CertCheck | None:
    """Judge a CRL by its file AND by the copies of it that live TLS contexts hold (BACKLOG #299).

    A hop reads its CRL when it builds its context and keeps that copy, so once the file is replaced
    the file is not what a running hop checks against. Judging only the file let the alert clear
    while the hop still held a copy that would lapse and refuse every peer. So every held copy that
    differs from the file is judged too, and the soonest ``nextUpdate`` of the file and those copies
    decides, by the rule the file's own blocks follow (:func:`~messagefoundry.pki.soonest_crl`).

    The alert therefore stays up until no context holds the old copy: the reload pass applied the file
    to it (:mod:`messagefoundry.pipeline.crl_reload`), or a restart or a rebuild of that hop replaced
    it. A copy the reload refused names the refusal in the log line. A file that cannot be read or parsed (``file_facts`` is ``None``) no longer
    silences the check while a hop still holds a copy of it. ``None`` only when nothing can be judged.
    A failure judging the held copies is logged and leaves the file's own verdict standing."""
    stale: list[CrlFacts] = []
    try:
        copies = held.copies(cert.path)
        fingerprint = crl_fingerprint(pem) if copies and pem is not None else None
        copies = [copy for copy in copies if copy.fingerprint != fingerprint]
        # One verdict per distinct copy: many hops sharing one file hold identical copies.
        stale = [copy.facts.at(now) for copy in {c.fingerprint: c for c in copies}.values()]
        if copies:
            oldest = soonest_crl(stale)
            if pem is None:
                why, remedy = (
                    "whose file cannot be read",
                    "Restore a readable CRL file before restarting: the engine refuses to "
                    "start on one it cannot read",
                )
            elif file_facts is None:
                why, remedy = (
                    "whose file cannot be parsed",
                    "Restore a valid CRL file before restarting: the engine refuses to start "
                    "on one it cannot parse",
                )
            elif (refused := held.refusal(cert.path, crl_fingerprint(pem))) is not None:
                # BACKLOG #299: the reload pass tried the file on the running hop and refused it.
                why = "that differs from the file, which the engine refused to apply to it"
                remedy = f"Reason: {refused.reason}. " + (
                    "Restart the engine to apply the file"
                    if refused.restart_applies
                    else "Fix the file: the engine would refuse to start on it too"
                )
            else:
                # The reload pass applies a replaced file to the running hop within about a minute
                # (pipeline/crl_reload.py); a restart applies it at once.
                why, remedy = "that differs from the file", "Restart the engine to apply the file"
            holders = sorted({copy.setting or "a connection's tls_crl_file" for copy in copies})
            log.warning(
                "cert_expiry: a running TLS hop still holds a copy of %r CRL %s %s (%d load(s), "
                "from %s). The hop keeps the copy it read when it built its context; the soonest "
                "CRL in it (issuer %r) lapses at %s. %s.",
                cert.label,
                cert.path,
                why,
                len(copies),
                ", ".join(holders),
                oldest.issuer,
                oldest.next_update_iso,
                remedy,
            )
    except Exception:
        log.error(
            "cert_expiry: could not judge the copies of %r CRL %s that live hops hold",
            cert.label,
            cert.path,
            exc_info=True,
        )
        stale = []
    judged = [*([file_facts] if file_facts is not None else []), *stale]
    if not judged:
        return None
    facts = soonest_crl(judged)
    return CertCheck(
        label=cert.label,
        path=cert.path,
        not_after_iso=facts.next_update_iso,
        days_remaining=facts.days_remaining,
        kind="crl",
    )
