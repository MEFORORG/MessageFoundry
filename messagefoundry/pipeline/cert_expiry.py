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
from collections.abc import Callable, Hashable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from messagefoundry.config.loaded_crls import (
    HeldCrlSnapshot,
    ReloadRefusal,
    ca_bundle_fingerprint,
    crl_fingerprint,
    crl_path_key,
)
from messagefoundry.config.loaded_crls import snapshot as held_crl_snapshot
from messagefoundry.config.settings import CertMonitorSettings, StoreBackend
from messagefoundry.config.tls_policy import (
    crl_not_in_effect,
    crl_scratch_context,
    judge_crl_bytes,
    staged_crl,
)
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink, crl_expiry_detail
from messagefoundry.pipeline.crl_reload import NO_ISSUER, RELOAD_INTERVAL_SECONDS, RESTART, RETRY
from messagefoundry.pki import (
    CertFacts,
    CrlFacts,
    crl_pem_blocks,
    judge_crl_signatures,
    read_cert_facts,
    read_soonest_crl_facts,
    soonest_crl,
)
from messagefoundry.redaction import log_timestamp

if TYPE_CHECKING:
    from messagefoundry.config.settings import ServiceSettings
    from messagefoundry.config.wiring import Registry

__all__ = [
    "MonitoredCert",
    "CertCheck",
    "CertExpiryRunner",
    "certs_from_registry",
    "certs_from_settings",
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
    #: True when ``not_after_iso`` is not the file's but an older copy's that a running hop holds
    #: and that lapses first (vault BACKLOG #2319). Only ever True for a CRL.
    held_copy: bool = False
    #: What the scan found about held copies of this CRL, and what to do, or ``""`` when no running
    #: hop holds a copy that differs from the file. Config metadata only, no PHI.
    detail: str = ""

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


def certs_from_settings(settings: ServiceSettings) -> list[MonitoredCert]:
    """The certificate files the service settings name that no connection carries, each a
    ``kind="cert"`` :class:`MonitoredCert`. Today that is the SQL Server ``[store].ssl_root_cert``
    pin, labelled ``"store.ssl_root_cert"`` in the dotted style of :func:`crls_from_settings`.

    Vault BACKLOG #2223: the store sends that pin with ``Encrypt=strict``, where a pin match stands in
    for the driver's own expiry check. The store refuses an expired pin at connect, so watching it here
    is what warns before that refusal. A PostgreSQL ``ssl_root_cert`` is a CA bundle the driver
    validates itself, so it is not listed."""
    store, pin = settings.store, settings.store.ssl_root_cert
    # Only where the store sends it: an escaped weakened posture sends no pin.
    sends_pin = store.encrypt and not store.trust_server_certificate
    if store.backend is StoreBackend.SQLSERVER and sends_pin and isinstance(pin, str) and pin:
        return [MonitoredCert("store.ssl_root_cert", pin)]
    return []


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
        rows = self._rows(held)
        said = _HeldCopyLog.for_rows(rows)
        for cert in rows:
            check = self._inspect(cert, now, held, said=said)
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
                            held_copy=check.held_copy,
                            detail=check.detail,
                            # Vault BACKLOG #2319: the other rows naming this file. A held copy is
                            # matched by its file, not its hop, so it is reported under each.
                            shared_with=said.others(check),
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
        self,
        cert: MonitoredCert,
        now: float,
        held: HeldCrlSnapshot | None = None,
        *,
        said: _HeldCopyLog,
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
                cert, now, pem, crl_facts, held if held is not None else held_crl_snapshot(), said
            )
        if facts is None:
            return None
        return CertCheck(
            label=cert.label,
            path=cert.path,
            not_after_iso=facts.not_after_iso,
            days_remaining=facts.days_remaining,
        )


def _rows_by_crl_file(
    rows: Sequence[MonitoredCert],
) -> tuple[dict[str, tuple[str, ...]], dict[str, str]]:
    """The labels of the CRL rows naming each file, keyed as held copies are (vault BACKLOG #2319),
    and each CRL row's path in that key form.

    Several settings or connections can name one CRL file, and each gets its own row, since each
    hop depends on it. A held copy is matched by its file, so each of those rows reports it.

    BACKLOG #3512: one pass builds both, so they cannot disagree. A path ``crl_path_key`` cannot
    key is logged and left out of both, so it shares with no row, and the other rows still group."""
    keys: dict[str, str] = {}
    unkeyed: set[str] = set()
    by_file: dict[str, list[str]] = {}
    for row in rows:
        if row.kind != "crl" or row.path in unkeyed:
            continue
        if row.path not in keys:
            try:
                keys[row.path] = crl_path_key(row.path)
            except (OSError, TypeError, ValueError):
                log.error(
                    "cert_expiry: could not key CRL %s, so its rows share with none",
                    row.path,
                    exc_info=True,
                )
                unkeyed.add(row.path)
                continue
        labels = by_file.setdefault(keys[row.path], [])
        if row.label not in labels:
            labels.append(row.label)
    return {key: tuple(labels) for key, labels in by_file.items()}, keys


@dataclass(frozen=True)
class _HeldCopyAccount:
    """The facts a held-copy warning gives of a file, but the row and the path's spelling (vault
    BACKLOG #3099). The line formats them, so two accounts fold only when their facts match. Named
    fields, so the fold's key and the line's arguments cannot be put out of order."""

    why: str
    loads: int
    holders: tuple[str, ...]
    issuer: str
    next_update_iso: str
    remedy: str


#: :meth:`_HeldCopyLog.unchecked_later_crl`'s fold token: one such line a pass for each file.
_UNCHECKED_LATER_CRL = "unchecked-later-crl"


class _HeldCopyLog:
    """The rows naming each CRL file, and the held-copy warnings one scan pass has logged (vault
    BACKLOG #3099). The pass keys a row's file here, for its line and for its alert.

    A held copy is matched by its file, so every row naming a file judges the same copies and
    reaches the same account of them. N listeners sharing one CRL file logged that account N times
    a pass, each line listing the same N holders. A pass now logs an account once, under the first
    row to reach it, and that line names the other rows.

    Only the scan's own line is folded. Each row still returns its own check and raises its own
    alert, with its own ``detail`` and ``shared_with`` (vault BACKLOG #2319), and a sink that logs
    its alerts still logs one for each row."""

    def __init__(self, sharing: Mapping[str, tuple[str, ...]], keys: Mapping[str, str]) -> None:
        self._sharing = sharing
        # Each CRL row's path in key form, worked out once inside the grouping's guard, so the
        # lookups below never key a path themselves (BACKLOG #3512).
        self._keys = keys
        # Each line logged this pass: the file's key, and what the line said of it.
        self._logged: set[tuple[str, Hashable]] = set()

    @classmethod
    def for_rows(cls, rows: Sequence[MonitoredCert]) -> _HeldCopyLog:
        """One pass's log over ``rows``, grouped by file. A failed grouping is logged and folds
        nothing: BACKLOG #3176 loses only the alerts' ``shared_with``, not the scan or an alert.
        A path that cannot be keyed costs only its own rows that (BACKLOG #3512)."""
        try:
            return cls(*_rows_by_crl_file(rows))
        except Exception:
            log.error("cert_expiry: could not group the CRL rows by file", exc_info=True)
            return cls({}, {})

    def others(self, row: MonitoredCert | CertCheck) -> tuple[str, ...]:
        """The other rows naming ``row``'s file: the alert's ``shared_with``, and the rows a
        folded line names. Never raises: its call sits inside the guard around the alert sink,
        where a raise would cost the row its alert under a "sink failed" line (BACKLOG #3512)."""
        # "" keys no file, so a row the grouping does not hold shares with none.
        labels = self._sharing.get(self._keys.get(row.path, ""), ())
        return tuple(label for label in labels if label != row.label)

    def warn(self, cert: MonitoredCert, account: _HeldCopyAccount) -> None:
        """Log ``account`` of ``cert``'s file, unless this pass already has (vault BACKLOG #3099).

        Each row reads the file itself, so a file replaced part way through a pass can give a later
        row another account, and that one is logged too. A file the grouping does not hold is
        always logged, because no line could name the rows a fold left out: a failed grouping
        (BACKLOG #3176) costs the fold and no row its mention.

        Only log bookkeeping runs here, after the verdict, so a failure in it is logged and costs
        the row no date and no alert (vault BACKLOG #3548). An account counts as logged only once
        its line is, so a failure leaves the next row sharing the file to log it."""
        self._log_once(
            cert,
            account,
            "cert_expiry: a running TLS hop still holds a copy of %r CRL %s %s (%d load(s), from "
            "%s). The hop keeps the copy it read when it built its context; the soonest CRL in it "
            "(issuer %r) lapses at %s. %s.%s",
            account.why,
            account.loads,
            ", ".join(account.holders),
            account.issuer,
            log_timestamp(account.next_update_iso),
            account.remedy,
            failure="could not log the held copies of",
        )

    def unchecked_later_crl(self, cert: MonitoredCert) -> None:
        """Log that a later CRL in ``cert``'s CA file did not parse for the signature check, so an
        earlier CRL's unconfirmed verdict stands (BACKLOG #3512). Called inside the ``except``, so
        the line carries the cause. Folded as :meth:`warn` folds."""
        self._log_once(
            cert,
            _UNCHECKED_LATER_CRL,
            "cert_expiry: could not check the signature of a later CRL in %r CA file %s, so an "
            "earlier CRL's unconfirmed signature decides the alert.%s",
            failure="could not log the unchecked CRL of",
            exc_info=True,
        )

    def _log_once(
        self,
        cert: MonitoredCert,
        token: Hashable,
        message: str,
        *args: object,
        failure: str,
        exc_info: bool = False,
    ) -> None:
        """Log ``message`` about ``cert``'s file once a pass for each ``token`` (vault BACKLOG #3099).
        ``message`` starts with the row's label and path and ends with the other rows' clause, each
        a ``%`` field filled here, around ``args``.

        Only log bookkeeping runs here, so a failure in it is logged and costs the row no date and
        no alert (vault BACKLOG #3548). A line counts as logged only once it is, so a failure leaves
        the next row sharing the file to log it. A file the grouping does not hold is always
        logged, because no line could name the rows a fold left out."""
        try:
            # Every keyed path is in the grouping, so a key is the fold's key.
            fold_key = self._keys.get(cert.path)
            if fold_key is not None and (fold_key, token) in self._logged:
                return
            # The alert's own words for the rows sharing a file, without its clause that each of
            # those rows reports the copy too: a folded line is the one report of it in the log.
            also = crl_expiry_detail(held_copy=False, detail="", shared_with=self.others(cert))
            log.warning(
                message,
                cert.label,
                cert.path,
                *args,
                f" {also}" if also else "",
                exc_info=exc_info,
            )
            if fold_key is not None:
                self._logged.add((fold_key, token))
        except Exception:
            log.error("cert_expiry: %s %r CRL %s", failure, cert.label, cert.path, exc_info=True)


def held_crl_label(path: str) -> str:
    """The alert label for a CRL file a live hop holds that no configured row names (BACKLOG #299).

    Namespaced like :func:`client_cert_label` and for the same reason: the label keys the re-alert
    throttle, and a full path is injective where a connection name or setting name might not be."""
    return f"held-crl:{path}"


def _ca_file_crl_refusal(
    pem: bytes,
    now: float,
    file_facts: CrlFacts | None,
    *,
    ca_file_only: bool,
    on_unchecked: Callable[[], None],
) -> tuple[str, str] | None:
    """Why a restart into this CA file would refuse peers, or might, as ``(why, remedy)``, or
    ``None`` when its CRLs pass the checks below, or it holds none (BACKLOG #3176). "Might" is a
    signature the engine could not confirm (BACKLOG #3512).

    Nothing judges a CA file's CRL at start, so a restart loads it whatever it is. The checks are a
    CRL setting's start rules (:func:`~messagefoundry.config.tls_policy.judge_crl_bytes`, then
    :func:`~messagefoundry.config.tls_policy.crl_not_in_effect` with no clock skew), then OpenSSL
    loading exactly the CRLs judged, then the signature check a start and the reload make
    (:func:`~messagefoundry.pki.judge_crl_signatures`): each CRL signed by the CA OpenSSL loads
    from this file for its issuer. Only a signature proven bad says handshakes fail;
    one the engine could not confirm asks for a check (BACKLOG #3512). With ``ca_file_only``, that
    remedy then says to restart. Otherwise a CRL setting names the file too. The caller then orders
    the restart, after the reload's verdict. A CRL whose issuer this file does not hold is not
    refused: the issuer can be an intermediate the peer sends, which the reload treats the same
    way. ``file_facts`` is the lenient reading, which tells an expired CRL from one that cannot be
    judged. ``on_unchecked`` is called, inside the ``except``, when a later CRL does not parse
    and an earlier one's verdict stands. Each remedy leads, because the alert instance keeps only
    the start of it."""
    if not crl_pem_blocks(pem):
        return None  # the CRL was moved out, and a CA file with none starts
    unjudged = (
        "whose CA file now holds a CRL the engine cannot judge",
        "Replace the CRL in the CA file with one the engine can judge before restarting: a "
        "restart loads the CA file whole",
    )
    try:
        # As the reload does: the time a CRL takes effect is asked below, for its own remedy.
        _, blocks = judge_crl_bytes(pem, label="the CA file", now=now, require_in_effect=False)
    except ValueError:
        if file_facts is not None and file_facts.expired:
            return (
                "whose CA file now holds an expired CRL",
                "Replace the CRL in the CA file with a current one before restarting: a restart "
                "would load the expired one",
            )
        return unjudged
    # No clock skew allowed, unlike a CRL setting's start: nothing at start refuses this CRL, and
    # OpenSSL allows none, so a restart before it takes effect refuses peers until then.
    if (early := crl_not_in_effect(blocks, now=now, skew=0.0)) is not None:
        # main's words and main's wait, unchanged by BACKLOG #3512: a test holds them to main's.
        return (
            "whose CA file now holds a CRL that is not yet in effect",
            f"Replace the CRL in the CA file with one in effect now, or wait until "
            f"{log_timestamp(early.this_update)}, before restarting: until then it refuses every "
            "peer under its issuer",
        )
    try:
        # OpenSSL's own reading of these bytes, not of the file again, which may have changed.
        with staged_crl(pem) as copy:
            scratch = crl_scratch_context(str(copy), blocks, label="the CA file")
        # The states of the file's CRLs, merged. pki.crl_signature_refusal's flag is True for
        # three of them, and only ``bad`` proves a failure (BACKLOG #3512).
        states: set[str] = set()
        try:
            for sig in judge_crl_signatures(pem, scratch.get_ca_certs(binary_form=True)):
                states.add(sig.state)
                if sig.state == "bad":
                    break  # proven: no later block changes the remedy
        except ValueError:
            # main's check stopped at the first unconfirmed block, so a later block that does not
            # parse, the one failure judge_crl_signatures documents, never cost that verdict. Keep
            # the verdict the earlier blocks gave. Any other type is unexpected and takes the outer
            # path, as before (BACKLOG #3512).
            if not states - {"verified", "unlisted"}:
                raise
            on_unchecked()
    except ValueError:
        return unjudged  # OpenSSL loads other CRLs than were judged
    except ssl.SSLError as exc:
        # Any block can cause it, a certificate as well as a CRL, and a restart fails on it too.
        return (
            "whose CA file OpenSSL cannot load",
            f"Fix the CA file before restarting: OpenSSL cannot load it ({exc.reason or exc})",
        )
    except Exception as exc:
        # Not a verdict on the file, such as a disk that refuses the private copy. Said, rather
        # than raised, so the held copy's date still stands this pass.
        log.warning("cert_expiry: could not check the CRL in a CA file", exc_info=True)
        return (
            "whose CA file the scan could not check",
            "Check the CRL in the CA file before restarting: the scan could not check it "
            f"({type(exc).__name__}), and tries again each pass",
        )
    if "bad" in states:
        # The claim and the fix a start gives a CRL setting in the proven case
        # (tls_policy._check_crl_signatures). OpenSSL can prefer a newer good CRL from the issuer.
        # The fix and its claim are one sentence, short enough for the alert list's cut (#3512).
        return (
            "whose CA file now holds a CRL its issuer's key does not verify",
            "Replace the CRL in the CA file with one its CA signed before restarting: a handshake "
            "OpenSSL judges by it fails. If a good CRL from that issuer is already in the file, "
            "remove this one instead",
        )
    if states & {"unproven", "uncheckable"}:
        # Not proven either way, and pki.CrlSignature names a case where handshakes still pass.
        # So the remedy asks for a check and claims no failure. ``why`` says which CA was tried.
        unconfirmed = "the engine could not confirm its signature"
        check = "Check that the CRL in the CA file is one its CA signed"
        return (
            "whose CA file now holds a CRL whose signature the engine could not confirm with the "
            "CA the file lists for its issuer",
            # Only a restart applies a CA file. Where a CRL setting names the file too, the
            # restart waits for the reload's verdict, as #3176 orders it (BACKLOG #3512).
            f"{check}, then restart the engine to apply the CA file: {unconfirmed}"
            if ca_file_only
            else f"{check} before restarting: {unconfirmed}",
        )
    return None


#: BACKLOG #3176: what follows a refused reload's remedy that is not itself a restart. It comes
#: after the remedy, not instead of it, and never "either way": a remedy can say to wait first.
_CA_FILE_HOP_RESTARTS = (
    "Once the file is applied, a hop that loaded it as its CA file still needs a restart"
)


#: The reload's remedies that order a plain restart of the engine, which applies the file to the
#: CA-file hop too, so no second restart follows them. ``_NOT_PROVABLE`` is not one: its restart
#: is conditional, on the CRL-setting hop's trust, and says nothing of the CA-file hop. This is the
#: set main's "Restart the engine" substring test chose, named so a new remedy is a decision here
#: (BACKLOG #3512).
_RESTARTS_THE_ENGINE = frozenset({RESTART, NO_ISSUER, RETRY})


def _after_the_reload(refused: ReloadRefusal | None) -> str:
    """The steps for a changed file that a CRL setting names and a hop loaded as its CA file.

    BACKLOG #3176: the reload applies the file to the CRL-setting hops, but only a restart applies
    it to the CA-file hop. The restart comes after the reload's verdict, which can find the file
    one a start would refuse. A refused reload's steps (:func:`_refused_steps`) follow. BACKLOG
    #3512: the CA-file arm ends with these too, after its own step."""
    if refused is None:
        return (
            "Restart the engine once the reload has applied the file, within "
            f"{RELOAD_INTERVAL_SECONDS:g} seconds: only a restart applies it to a hop that loaded "
            "it as its CA file. If the reload refuses it, this alert says why"
        )
    return (
        "The reload refused the file for a hop that loads it as its CRL setting: "
        f"{_refused_steps(refused, ca_file_hop=True)}"
    )


def _refused_steps(refused: ReloadRefusal, *, ca_file_hop: bool) -> str:
    """A refused reload's remedy, its reason, then with ``ca_file_hop`` the CA-file hop's restart
    unless the remedy is a plain restart (:data:`_RESTARTS_THE_ENGINE`). Every arm of the
    ``crl_expiry`` alert formats a refusal here, so they keep one policy (BACKLOG #3512).

    This alert keeps the reason, as ``docs/CONFIGURATION.md`` says, unlike ``crl_reload_refused``
    (#2904). It trails the remedy, so the alert list's cut keeps the remedy first."""
    steps = f"{refused.remedy}. Reason: {refused.reason}"
    if ca_file_hop and refused.remedy not in _RESTARTS_THE_ENGINE:
        steps += f". {_CA_FILE_HOP_RESTARTS}"
    return steps


def _judge_crl(
    cert: MonitoredCert,
    now: float,
    pem: bytes | None,
    file_facts: CrlFacts | None,
    held: HeldCrlSnapshot,
    said: _HeldCopyLog,
) -> CertCheck | None:
    """Judge a CRL by its file AND by the copies of it that live TLS contexts hold (BACKLOG #299).

    A hop reads its CRL when it builds its context and keeps that copy, so once the file is replaced
    the file is not what a running hop checks against. Judging only the file let the alert clear
    while the hop still held a copy that would lapse and refuse every peer. So every held copy that
    differs from the file is judged too, and the soonest ``nextUpdate`` of the file and those copies
    decides, by the rule the file's own blocks follow (:func:`~messagefoundry.pki.soonest_crl`).

    The alert therefore stays up until no context holds the old copy: the reload pass applied the file
    to it (:mod:`messagefoundry.pipeline.crl_reload`), or a restart or a rebuild of that hop replaced
    it. A copy the reload refused names the refusal in the log line. ``said`` keeps rows that share
    a file from each logging the same line in one pass (vault BACKLOG #3099). A file that cannot be
    read or parsed (``file_facts`` is ``None``) no longer silences the check while a hop still holds
    a copy of it. ``None`` only when nothing can be judged. A failure judging the held copies is
    logged and leaves the file's own verdict standing."""
    stale: list[CrlFacts] = []
    detail = ""
    account: _HeldCopyAccount | None = None
    try:
        copies = held.copies(cert.path)
        # BACKLOG #3512: whether a CRL setting names this file, for the wording alone: a start
        # judges that setting, so the CA-file step says "before restarting" rather than ordering a
        # restart. Any row but a held-crl one is a CRL setting, and so is a held copy from one,
        # stale or not: a store hop records none. Whether a restart waits for the reload is a
        # different question, answered below by a stale non-bundle copy alone.
        crl_setting_too = cert.label != held_crl_label(cert.path) or any(
            not c.ca_bundle for c in copies
        )
        fingerprint = crl_fingerprint(pem) if copies and pem is not None else None
        # Vault BACKLOG #2319: a CA-bundle copy is a copy of the file's CRLs alone, so it is
        # compared on those, and a certificate added beside an unchanged CRL is not a stale copy.
        bundle_fp = (
            ca_bundle_fingerprint(pem)
            if pem is not None and any(c.ca_bundle for c in copies)
            else None
        )
        copies = [
            copy
            for copy in copies
            if copy.fingerprint != (bundle_fp if copy.ca_bundle else fingerprint)
        ]
        # One verdict per distinct copy: many hops sharing one file hold identical copies.
        stale = [copy.facts.at(now) for copy in {c.fingerprint: c for c in copies}.values()]
        if copies:
            oldest = soonest_crl(stale)
            kinds = {copy.ca_bundle for copy in copies}
            bundle_only, some_bundle = kinds == {True}, True in kinds
            # BACKLOG #299: the reload pass tried the file on a running CRL-setting hop and
            # refused it. Read first, so the CA-file arm below keeps it (BACKLOG #3512).
            refused = (
                held.refusal(cert.path, fingerprint)
                if fingerprint is not None and not bundle_only
                else None
            )
            if pem is None:
                what = "CA file" if bundle_only else "CRL file"
                why, remedy = (
                    "whose file cannot be read",
                    f"Restore a readable {what} before restarting: the engine refuses to "
                    "start on one it cannot read",
                )
            elif (
                some_bundle
                and (
                    unsafe := _ca_file_crl_refusal(
                        pem,
                        now,
                        file_facts,
                        ca_file_only=not crl_setting_too,
                        on_unchecked=lambda: said.unchecked_later_crl(cert),
                    )
                )
                is not None
            ):
                # BACKLOG #3176: nothing judges a CA file's CRL at start, so a restart would load
                # this one, which refuses peers under its issuer or, unconfirmed, might (#3512).
                # Fix or check it first.
                why, remedy = unsafe
                if not bundle_only:
                    # BACKLOG #3512: a stale copy from a CRL setting is what the reload judges
                    # (crl_reload._held_by_path skips CA-file copies), so only then does a restart
                    # wait for its verdict. The CA-file step leads, then the reload's remedy and
                    # the CA-file hop's restart after it, or the restart after the verdict.
                    remedy += f". Do that first. {_after_the_reload(refused)}"
            elif bundle_only:
                # Vault BACKLOG #2319: the reload pass never applies a CA file, so no wait helps.
                # A CA file whose CRL was moved out still starts, so a restart is safe then too.
                why, remedy = (
                    "that it loaded from its CA file, which the engine does not reload",
                    "Restart the engine to apply the CA file. A CRL in the hop's CRL setting "
                    "instead is applied without a restart",
                )
            elif file_facts is None:
                why, remedy = (
                    "whose file cannot be parsed",
                    "Restore a valid CRL file before restarting: the engine refuses to start "
                    "on one it cannot parse",
                )
            elif refused is not None:
                why = "that differs from the file, which the engine refused to apply to it"
                # The remedy leads: the alert instance keeps only the start of it (#2319).
                remedy = _refused_steps(refused, ca_file_hop=some_bundle)
            elif some_bundle:
                why, remedy = (
                    "that differs from the file, which a hop loaded as its CA file",
                    _after_the_reload(None),
                )
            else:
                # No refusal recorded: the reload pass (pipeline/crl_reload.py) has not judged
                # these bytes yet, and will within its interval.
                why, remedy = (
                    "that differs from the file",
                    "A reload is pending: the engine applies the file to the running hop within "
                    f"{RELOAD_INTERVAL_SECONDS:g} seconds, unless it refuses the file and logs why",
                )
            holders = tuple(sorted({copy.setting or "an unnamed setting" for copy in copies}))
            # Vault BACKLOG #2319: the same account for the alert, which the log line gives only
            # to the log. The remedy leads, because the alert instance keeps only the start of it.
            # The date is the alert's own not_after, so it is not repeated here.
            detail = f"{remedy}. Held by: {', '.join(holders)}."
            account = _HeldCopyAccount(
                why=why,
                loads=len(copies),
                holders=holders,
                issuer=oldest.issuer,
                next_update_iso=oldest.next_update_iso,
                remedy=remedy,
            )
    except Exception:
        log.error(
            "cert_expiry: could not judge the copies of %r CRL %s that live hops hold",
            cert.label,
            cert.path,
            exc_info=True,
        )
        stale = []
    if account is not None:
        said.warn(cert, account)
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
        # The file comes first in ``judged``, and soonest_crl keeps the first of a tie, so a held
        # copy that lapses with the file does not take the date from it (vault BACKLOG #2319).
        held_copy=facts is not file_facts,
        detail=detail if stale else "",
    )
