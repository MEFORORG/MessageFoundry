# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Secret-rotation reminder (#195b / ADR 0019 §5) — the secret-side twin of the TLS cert monitor.

Long-lived secrets (the store data-encryption key + the connector/AD/SMTP/Vault/OIDC credentials the
engine holds) have no natural expiry the way a TLS certificate does, so a stale key can sit unrotated
indefinitely with no in-engine signal. :class:`SecretRotationRunner` is a small background task that
periodically compares each tracked secret's **last-rotated date** against its **max age** and raises a
``secret_rotation_due`` alert when it is overdue or within ``[secret_rotation].warn_days`` of due.

**Live-by-default (ASVS 13.3.4, BACKLOG #282).** The DEK is tracked without operator action: at first
keyed start :func:`reconcile_rotation_meta` persists a NON-SECRET stamp (the DEK's one-way key-id + a
*tracked-since* floor date) in store meta, and the runner falls back to it when
``store_key_last_rotated`` is unset. The enumeration is widened beyond the DEK: each configured secret
class the engine holds is fingerprinted with a **DEK-derived KEYED MAC** (HMAC — never a salted hash, so
a low-entropy secret is not offline-guessable) into store meta; when a fingerprint changes the clock is
reset (rotation **auto-detected**, never operator-attested). Under ``[security].enforcement=ENFORCE`` a
DEK past ``max_age + grace`` escalates its alert severity at restart.

**PHI/secret-safe:** a secret value is read only transiently to compute its keyed MAC; only the MAC +
the *dates* (plus a static human label + config identifier per secret) are ever persisted, alerted, or
logged — **never** a secret value. A reminder needs the *when* and *whether-it-changed*, not the *what*.

**Tracked-since is an age FLOOR:** a pre-existing (possibly year-old) key gets a fresh clock on upgrade
and does **not** retroactively alert — the stamp records when tracking began, not the key's true age.

Modelled **verbatim** on :class:`~messagefoundry.pipeline.cert_expiry.CertExpiryRunner`: an injected
clock + a pure :meth:`run_once` make it deterministically testable; the loop only governs cadence. The
set of secrets to watch is supplied by an injected **callable** so it is recomputed each pass (a config
reload is picked up automatically, and tests can drive it with a literal list). Engine-side and stdlib-
only, so it never pulls the API or console into the engine.
"""

from __future__ import annotations

import asyncio
import datetime
import hashlib
import hmac
import logging
import os
import time
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING

from messagefoundry.config.ai_policy import SecurityEnforcement
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink

if TYPE_CHECKING:
    from messagefoundry.config.settings import SecretRotationSettings
    from messagefoundry.store.store import SecretRotationMetaStore

__all__ = [
    "MonitoredSecret",
    "SecretCheck",
    "SecretRotationRunner",
    "SecretStamp",
    "reconcile_rotation_meta",
    "secrets_from_settings",
    "secrets_from_settings_and_stamps",
]

log = logging.getLogger(__name__)

_UTC = datetime.UTC


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


#: The store DEK's registry class id — the one secret whose "fingerprint" is its one-way key-id (not a
#: keyed MAC of a value, since the raw DEK is never handled here).
_DEK_SECRET_ID = "MEFOR_STORE_ENCRYPTION_KEY"  # nosec B105 - an env-var NAME, not a secret value
_DEK_LABEL = "store data-encryption key"

# The fixed ``MEFOR_*`` env-var secret classes the engine holds in its own environment (ASVS 13.3.4,
# BACKLOG #282) — store-DB / AD / SMTP passwords, both Vault tokens, the OIDC confidential-client secret,
# and the off-loopback TLS key passphrase. Each is fingerprinted (keyed MAC) into store meta so a change
# auto-detects a rotation. The connector-per-Connection ``env()`` credentials are NOT engine-global env
# vars, so they are resolved from the live graph by ``config.wiring.connector_secret_env_values`` and the
# engine passes them here as ``reconcile_rotation_meta(..., extra_values=…)`` — they ride the SAME keyed-MAC
# mechanism (merged into ``held`` below), NOT this fixed list. Values are read only to MAC them — never
# persisted or logged. (Kept aligned with ``CRITICAL_SECRETS`` in test_secret_rotation_inventory.)
_ENV_SECRET_CLASSES: tuple[tuple[str, str], ...] = (
    ("MEFOR_STORE_PASSWORD", "SQL/Postgres store password"),
    ("MEFOR_AUTH_AD_BIND_PASSWORD", "Active Directory bind password"),
    ("MEFOR_ALERTS_EMAIL_PASSWORD", "SMTP alert password"),
    ("MEFOR_AUTH_OIDC_CLIENT_SECRET", "OIDC confidential-client secret"),
    ("MEFOR_API_TLS_KEY_PASSWORD", "off-loopback TLS private-key passphrase"),
    ("MEFOR_STORE_VAULT_TOKEN", "Vault token — store DEK provider"),
    ("MEFOR_SECRETS_VAULT_TOKEN", "Vault token — connector KV provider"),
)

_FP_HEX_LEN = (
    32  # hex chars of the HMAC-SHA256 fingerprint kept (128-bit — ample, keeps the row compact)
)


def _keyed_fingerprint(key: bytes, value: str) -> str:
    """A one-way KEYED-MAC fingerprint of ``value`` under the DEK-derived ``key`` (ASVS 13.3.4). HMAC-
    SHA256, NOT a salted hash: a salted hash of a low-entropy AD/SMTP password is offline-guessable,
    whereas without the DEK-derived key this MAC is not — the persisted fingerprint reveals nothing about
    the value. Truncated to :data:`_FP_HEX_LEN`; used only to detect *change*, never to recover a value."""
    return hmac.new(key, value.encode("utf-8"), hashlib.sha256).hexdigest()[:_FP_HEX_LEN]


def held_env_secret_values(environ: Mapping[str, str] | None = None) -> dict[str, str]:
    """The fixed ``MEFOR_*`` secret values the engine actually holds — present and non-empty — in
    ``environ`` (default :data:`os.environ`). Returned transiently to be fingerprinted; **never** stored
    or logged. A class absent from the environment is simply not tracked (deny-by-default)."""
    env = os.environ if environ is None else environ
    out: dict[str, str] = {}
    for name, _label in _ENV_SECRET_CLASSES:
        val = env.get(name)
        if val:
            out[name] = val
    return out


@dataclass(frozen=True)
class SecretStamp:
    """The reconciled watch state for one tracked secret class (ASVS 13.3.4). NON-SECRET: ``fingerprint``
    is a keyed MAC / DEK key-id, ``tracked_since`` the age-floor first-observed date, ``last_rotated`` the
    date the fingerprint last changed. Carries ``max_age_days`` so the runner can build a
    :class:`MonitoredSecret` per class."""

    secret: str
    label: str
    fingerprint: str
    tracked_since: datetime.date
    last_rotated: datetime.date
    max_age_days: int


def secrets_from_settings(settings: SecretRotationSettings) -> list[MonitoredSecret]:
    """Enumerate the secrets to watch from ``[secret_rotation]`` **alone** (no persisted stamps): the
    store DEK, and only when the operator set ``store_key_last_rotated``. Live-by-default DEK tracking +
    the fingerprinted connector/AD/SMTP/Vault/OIDC classes come from
    :func:`secrets_from_settings_and_stamps` with the reconciled store-meta stamps. Kept as the pure
    settings-only helper (and for callers/tests without a store)."""
    return secrets_from_settings_and_stamps(settings, {})


def secrets_from_settings_and_stamps(
    settings: SecretRotationSettings, stamps: Mapping[str, SecretStamp]
) -> list[MonitoredSecret]:
    """The effective monitored-secret set: the DEK (operator ``store_key_last_rotated`` when set, else the
    auto-detected tracked-since / rotation stamp — so the DEK is tracked LIVE-BY-DEFAULT without operator
    action, ASVS 13.3.4) plus one entry per reconciled non-DEK class stamp. PHI-free: dates + identifiers
    only."""
    secrets: list[MonitoredSecret] = []
    dek_stamp = stamps.get(_DEK_SECRET_ID)
    if settings.store_key_last_rotated:
        # Operator override wins (validated ISO YYYY-MM-DD at settings load, so fromisoformat is safe).
        secrets.append(
            MonitoredSecret(
                label=_DEK_LABEL,
                secret=_DEK_SECRET_ID,  # nosec B106 — the secret's env-var NAME/label, never its value
                last_rotated=datetime.date.fromisoformat(settings.store_key_last_rotated),
                max_age_days=settings.store_key_max_age_days,
            )
        )
    elif dek_stamp is not None:
        secrets.append(
            MonitoredSecret(
                label=dek_stamp.label,
                secret=_DEK_SECRET_ID,  # nosec B106 — identifier/label, never the value
                last_rotated=dek_stamp.last_rotated,
                max_age_days=settings.store_key_max_age_days,
            )
        )
    for secret_id, stamp in stamps.items():
        if secret_id == _DEK_SECRET_ID:
            continue
        secrets.append(
            MonitoredSecret(
                label=stamp.label,
                secret=secret_id,  # nosec B106 — identifier/label, never the value
                last_rotated=stamp.last_rotated,
                max_age_days=stamp.max_age_days,
            )
        )
    return secrets


async def reconcile_rotation_meta(
    meta_store: SecretRotationMetaStore,
    settings: SecretRotationSettings,
    *,
    dek_key_id: str | None,
    enforcement: SecurityEnforcement,
    alert_sink: AlertSink | None = None,
    now: float | None = None,
    extra_values: Mapping[str, str] | None = None,
    env_values: Mapping[str, str] | None = None,
) -> dict[str, SecretStamp]:
    """Reconcile the persisted secret-rotation stamps against what the engine holds RIGHT NOW, at engine
    start (ASVS 13.3.4, BACKLOG #282). For each tracked class — the store DEK (by its one-way key-id) and
    every configured ``MEFOR_*`` / connector secret the engine holds (fingerprinted with a DEK-derived
    KEYED MAC) — this:

    * stamps a NEW class with ``tracked_since = last_rotated = today`` (an age FLOOR — a pre-existing
      year-old key gets a fresh clock on upgrade and does **not** retroactively alert);
    * on a CHANGED fingerprint resets ``last_rotated = today`` (rotation is AUTO-DETECTED, never
      operator-attested) while keeping ``tracked_since``;
    * leaves an unchanged class untouched (no rewrite).

    It then arms the **ENFORCE escalation**: under ``[security].enforcement=ENFORCE``, a DEK older than
    ``store_key_max_age_days + enforce_grace_days`` emits its ``secret_rotation_due`` alert with
    ``enforced=True`` at restart. Returns the reconciled stamps for the runner's live secret source.

    PHI/secret-safe: a secret value is read only to compute its keyed MAC; only the MAC + dates are ever
    persisted or alerted, never the value."""
    ts = time.time() if now is None else now
    today = datetime.datetime.fromtimestamp(ts, tz=_UTC).date()
    stored = await meta_store.get_secret_rotation_meta()

    # (secret_id, label, fingerprint, max_age_days) for every class the engine currently holds.
    classes: list[tuple[str, str, str, int]] = []
    if dek_key_id:
        # The DEK's fingerprint IS its one-way key-id (SHA-256 of the key) — no value is handled here.
        classes.append((_DEK_SECRET_ID, _DEK_LABEL, dek_key_id, settings.store_key_max_age_days))
    fp_key = meta_store.secret_rotation_fingerprint_key()
    if fp_key is not None:
        held: dict[str, str] = dict(held_env_secret_values(env_values))
        if extra_values:  # per-Connection env() credentials the engine resolved (same mechanism)
            held.update(extra_values)
        labels = dict(_ENV_SECRET_CLASSES)
        for secret_id, value in held.items():
            label = labels.get(secret_id, secret_id)
            classes.append(
                (secret_id, label, _keyed_fingerprint(fp_key, value), settings.secret_max_age_days)
            )

    stamps: dict[str, SecretStamp] = {}
    for secret_id, label, fingerprint, max_age in classes:
        prior = stored.get(secret_id)
        if prior is None:
            tracked_since = today
            last_rotated = today
            changed = True
        elif prior.fingerprint != fingerprint:
            tracked_since = datetime.date.fromisoformat(prior.tracked_since)
            last_rotated = today  # rotation auto-detected → reset the clock
            changed = True
        else:
            tracked_since = datetime.date.fromisoformat(prior.tracked_since)
            last_rotated = datetime.date.fromisoformat(prior.last_rotated)
            changed = False
        if changed:
            await meta_store.upsert_secret_rotation_meta(
                secret_id,
                fingerprint=fingerprint,
                tracked_since=tracked_since.isoformat(),
                last_rotated=last_rotated.isoformat(),
            )
        stamps[secret_id] = SecretStamp(
            secret=secret_id,
            label=label,
            fingerprint=fingerprint,
            tracked_since=tracked_since,
            last_rotated=last_rotated,
            max_age_days=max_age,
        )

    _maybe_escalate_dek(
        settings,
        stamps,
        today,
        enforcement=enforcement,
        alert_sink=alert_sink or LoggingAlertSink(),
    )
    return stamps


def _maybe_escalate_dek(
    settings: SecretRotationSettings,
    stamps: Mapping[str, SecretStamp],
    today: datetime.date,
    *,
    enforcement: SecurityEnforcement,
    alert_sink: AlertSink,
) -> None:
    """ASVS 13.3.4 ENFORCE escalation arm (committed): under ENFORCE, if the DEK is past
    ``max_age + enforce_grace_days``, emit its ``secret_rotation_due`` alert with ``enforced=True`` at
    restart. The DEK's effective last-rotated is the operator override when set, else its stamp."""
    if enforcement is not SecurityEnforcement.ENFORCE:
        return
    dek_stamp = stamps.get(_DEK_SECRET_ID)
    if settings.store_key_last_rotated:
        eff_last = datetime.date.fromisoformat(settings.store_key_last_rotated)
    elif dek_stamp is not None:
        eff_last = dek_stamp.last_rotated
    else:
        return  # DEK not tracked (keyless) — nothing to escalate
    age_days = (today - eff_last).days
    days_overdue = age_days - settings.store_key_max_age_days
    if days_overdue > settings.enforce_grace_days:
        try:
            alert_sink.secret_rotation_due(
                _DEK_LABEL,
                secret=_DEK_SECRET_ID,
                last_rotated=eff_last.isoformat(),
                days_overdue=days_overdue,
                enforced=True,
            )
        except Exception:
            log.warning("secret_rotation ENFORCE escalation sink failed", exc_info=True)


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
            try:  # noqa: SIM105
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
        try:  # noqa: SIM105
            await asyncio.wait_for(self._stop.wait(), delay)
        except TimeoutError:
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
