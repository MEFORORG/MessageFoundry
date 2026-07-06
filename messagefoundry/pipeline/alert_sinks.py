# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Real :class:`~messagefoundry.pipeline.alerts.AlertSink` transports — webhook + email.

The :class:`AlertSink` emit methods are called **inline on a delivery worker** and must be cheap and
non-blocking (the lane is already stalled when we're alerting — the notification must never block or
hang it). So :class:`NotifierAlertSink` does no network I/O inline: each event is built and dropped on
a bounded in-memory queue, and a **background task** drains the queue and performs the actual sends
(webhook POST / SMTP) off the event loop via :func:`asyncio.to_thread`. A send failure is logged and
the other transports still run — alerting is best-effort and never breaks delivery.

Transports use only the **standard library** (``urllib.request`` / ``smtplib``), so wiring real
notifications adds no dependency. Payloads carry the connection name + queue shape only — **no PHI**.

Construction is config-driven: :func:`notifier_from_settings` turns an
:class:`~messagefoundry.config.settings.AlertsSettings` into a :class:`NotifierAlertSink`, or ``None``
when neither transport is configured (the engine then falls back to the logging sink).
"""

from __future__ import annotations

import abc
import asyncio
import fnmatch
import json
import logging
import smtplib
import time
import urllib.parse
import urllib.request
from collections.abc import Coroutine, Mapping, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Generic, Protocol, TypeVar

from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AlertRule,
    AlertSeverity,
    AlertsSettings,
    insecure_tls_allowed,
)

__all__ = [
    "AlertTransport",
    "WebhookTransport",
    "EmailTransport",
    "AlertRuleSet",
    "NotifierAlertSink",
    "notifier_from_settings",
]

log = logging.getLogger(__name__)

# Bound the in-memory backlog so a wedged transport (unreachable webhook) can't grow without limit;
# excess events are dropped with a warning rather than stalling the worker that enqueues them.
_MAX_QUEUE = 1000


class _AlertStateStore(Protocol):
    """The narrow alert-state slice (ADR 0044, #56) the sink uses — a structural subset of the store's
    ``QueueStore`` protocol, kept inline so this module stays dependency-light. The upsert/auto-resolve
    are pure observers (no queue row, no finalizer) and are scheduled fail-soft off ``_emit``."""

    async def upsert_alert_instance(
        self,
        *,
        event_type: str,
        connection: str,
        severity: str,
        reason: str | None = ...,
        now: float | None = ...,
    ) -> None: ...

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = ...
    ) -> int: ...


#: Auto-resolution map (ADR 0044 D2): an inverse lifecycle event type resolves the matching open
#: instance(s) of the failure event type it cancels. ``connection_restored`` cancels the
#: ``connection_error`` raised on ``connection_lost``; a re-emitted ``connection_started`` clears a
#: ``connection_stopped``. Keyed by the inverse event's ``type`` → the failure event ``type`` it resolves.
_AUTO_RESOLVE: dict[str, str] = {
    "connection_restored": "connection_error",
    "connection_started": "connection_stopped",
}

_T = TypeVar("_T")


class _BackgroundDispatcher(abc.ABC, Generic[_T]):
    """A bounded in-memory queue drained by a single background task — the shared lifecycle behind
    :class:`NotifierAlertSink` (operator alerts) and the per-user security-event notifier. The queue
    caps the backlog so a wedged downstream can't grow memory without bound; excess items are dropped
    with a warning (see :meth:`_enqueue`).

    Subclasses implement :meth:`_handle` for the per-item work. It runs inside the background task,
    must push any blocking I/O off the loop (``asyncio.to_thread``), and must be **best-effort** — it
    swallows its own errors and never raises, since an exception out of ``_handle`` would kill the
    drain loop. Lifecycle: :meth:`start` once an event loop is running (the ASGI lifespan does this),
    :meth:`aclose` on shutdown (enqueues a ``None`` sentinel, drains what's queued, then stops)."""

    def __init__(self, *, max_queue: int = _MAX_QUEUE) -> None:
        self._queue: asyncio.Queue[_T | None] = asyncio.Queue(maxsize=max_queue)
        self._task: asyncio.Task[None] | None = None

    def _enqueue(self, item: _T, *, dropped: str) -> None:
        """Non-blocking enqueue; on a full queue, drop the item with a warning (``dropped`` names it)."""
        try:
            self._queue.put_nowait(item)
        except asyncio.QueueFull:
            log.warning("%s queue full; dropping %s", type(self).__name__, dropped)

    def start(self) -> None:
        if self._task is None:
            self._task = asyncio.create_task(self._run())

    async def aclose(self) -> None:
        if self._task is None:
            return
        await self._queue.put(None)  # sentinel: drain what's queued, then stop
        try:
            await self._task
        finally:
            self._task = None

    async def _run(self) -> None:
        while True:
            item = await self._queue.get()
            if item is None:
                return
            await self._handle(item)

    @abc.abstractmethod
    async def _handle(self, item: _T) -> None:
        """Process one queued item (best-effort, blocking I/O off-loop). Must not raise."""


class AlertTransport(Protocol):
    """One delivery channel for an alert event. ``send`` does the actual (blocking) I/O — the
    :class:`NotifierAlertSink` always calls it from a background task, never inline on a worker."""

    name: str

    async def send(self, event: dict[str, Any]) -> None: ...


def _subject(event: dict[str, Any]) -> str:
    severity = str(event.get("severity", "warning")).upper()
    return f"[MessageFoundry] {severity} {event['type']} — {event['connection']}"


def _body(event: dict[str, Any]) -> str:
    lines = [f"{k}: {v}" for k, v in event.items()]
    return "\n".join(lines)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Refuse to follow HTTP redirects on the outbound webhook POST (ASVS 15.3.2): a 3xx could
    divert the alert to an unintended host or be chained to probe an internal endpoint. Returning
    ``None`` makes urllib raise on the redirect instead of following it, so the send fails (logged)
    — the safe default for a fire-and-forget webhook."""

    def redirect_request(
        self,
        req: urllib.request.Request,
        fp: Any,
        code: int,
        msg: str,
        headers: Any,
        newurl: str,
    ) -> urllib.request.Request | None:
        return None


# A shared opener that never follows redirects; reused for every webhook POST.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler)


class WebhookTransport:
    """POST the event as JSON to a configured URL (fronts Slack/Teams/PagerDuty/custom webhooks)."""

    def __init__(
        self, url: str, *, timeout: float = 10.0, allowed_hosts: tuple[str, ...] = ()
    ) -> None:
        # Refuse a plaintext http:// webhook target unless the explicit dev escape is set: the alert
        # POST otherwise crosses the network in cleartext (ASVS 12.2.1 — no insecure fallback). https
        # is the only scheme accepted by default; http(s) remain the only schemes at all (see _post).
        # Same refuse-unless-MEFOR_ALLOW_INSECURE_TLS pattern as LDAPS / SQL Server / MLLP — stricter
        # than the credentialed-only http refusal on REST/SOAP, since a webhook has no PHI but should
        # still never fall back to cleartext.
        scheme = urllib.parse.urlsplit(url).scheme.lower()
        if scheme not in ("http", "https"):
            raise ValueError(f"webhook url must be http or https, got scheme {scheme!r}")
        if scheme == "http" and not insecure_tls_allowed():
            raise ValueError(
                f"webhook url {url!r} uses plaintext http; refused unless "
                f"{INSECURE_TLS_ESCAPE_ENV} is set (dev/trusted-network only) — use https"
            )
        if scheme == "http":
            log.warning(
                "webhook target uses plaintext http; permitted only because %s is set "
                "(cleartext, MITM-able — trusted-network/dev use only)",
                INSECURE_TLS_ESCAPE_ENV,
            )
        self.url = url
        self.timeout = timeout
        # Optional egress allowlist (lower-cased); empty = any host. SSRF defense-in-depth (1.3.6).
        self.allowed_hosts = tuple(h.lower() for h in allowed_hosts)
        self.name = "webhook"

    async def send(self, event: dict[str, Any]) -> None:
        await asyncio.to_thread(self._post, event)

    def _post(self, event: dict[str, Any]) -> None:
        # Guard the scheme before opening: urllib would otherwise honour file:/ftp:/custom schemes
        # (bandit B310). The URL is operator-configured, but an http(s)-only check is cheap
        # defense-in-depth so a typo'd or hostile config can't turn an alert POST into a local-file
        # read. With the scheme provably http/https here, the Request nosec is justified.
        split = urllib.parse.urlsplit(self.url)
        if split.scheme.lower() not in ("http", "https"):
            raise ValueError(f"webhook url must be http or https, got scheme {split.scheme!r}")
        host = (split.hostname or "").lower()
        if self.allowed_hosts and host not in self.allowed_hosts:
            raise ValueError(f"webhook host {host!r} is not in the configured allowlist")
        data = json.dumps(event).encode("utf-8")
        req = urllib.request.Request(  # noqa: S310  # nosec B310 — scheme guarded to http(s) above
            self.url,
            data=data,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        # The no-redirect opener (not urllib.request.urlopen) so a 3xx can't divert the POST (15.3.2).
        with _NO_REDIRECT_OPENER.open(req, timeout=self.timeout) as resp:
            resp.read()  # drain so the connection can be reused/closed cleanly


def send_plain_email(
    *,
    host: str,
    port: int,
    sender: str,
    recipients: list[str],
    subject: str,
    body: str,
    use_tls: bool = True,
    username: str | None = None,
    password: str | None = None,
    timeout: float = 30.0,
    allowed_hosts: tuple[str, ...] = (),
) -> None:
    """Send one plain-text email via SMTP (STARTTLS by default). Blocking — call via
    ``asyncio.to_thread``. Shared by :class:`EmailTransport` (ops alerts) and the per-user
    security-event notifier. An optional ``allowed_hosts`` egress allowlist gates the SMTP host."""
    allowed = tuple(h.lower() for h in allowed_hosts)
    if allowed and host.lower() not in allowed:
        raise ValueError(f"SMTP host {host!r} is not in the configured allowlist")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)
    with smtplib.SMTP(host, port, timeout=timeout) as smtp:
        if use_tls:
            smtp.starttls()
        if username is not None:
            smtp.login(username, password or "")
        smtp.send_message(msg)


class EmailTransport:
    """Send the event as a short plain-text email via SMTP (STARTTLS by default)."""

    def __init__(
        self,
        *,
        host: str,
        port: int,
        sender: str,
        recipients: list[str],
        use_tls: bool = True,
        username: str | None = None,
        password: str | None = None,
        timeout: float = 30.0,
        allowed_hosts: tuple[str, ...] = (),
    ) -> None:
        self.host = host
        self.port = port
        self.sender = sender
        self.recipients = recipients
        self.use_tls = use_tls
        self.username = username
        self.password = password
        self.timeout = timeout
        # Optional egress allowlist (lower-cased) for the SMTP host; empty = any (WP-11c, parity with
        # the webhook allowlist). The alert payload carries no PHI, so this is general egress control.
        self.allowed_hosts = tuple(h.lower() for h in allowed_hosts)
        self.name = "email"

    async def send(self, event: dict[str, Any]) -> None:
        await asyncio.to_thread(self._send, event)

    def _send(self, event: dict[str, Any]) -> None:
        send_plain_email(
            host=self.host,
            port=self.port,
            sender=self.sender,
            recipients=self.recipients,
            subject=_subject(event),
            body=_body(event),
            use_tls=self.use_tls,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            allowed_hosts=self.allowed_hosts,
        )


@dataclass(frozen=True)
class _RuleDecision:
    """How to handle one event: its ``severity``, the transports to fire (``None`` = every configured
    transport; ``()`` = suppress entirely), and the re-alert ``cooldown_seconds`` (``None`` = the
    notifier's global ``realert_seconds``)."""

    severity: str
    transports: tuple[str, ...] | None
    cooldown_seconds: float | None


# An event matching no rule keeps today's behaviour: warning, every transport, the global throttle.
_DEFAULT_DECISION = _RuleDecision(
    severity=AlertSeverity.WARNING.value, transports=None, cooldown_seconds=None
)


class AlertRuleSet:
    """Evaluate operator alert rules (ADR 0014) against an event, returning the **first** matching
    rule's :class:`_RuleDecision` (severity / transports / cooldown) or the default. Pure and
    synchronous, so the notifier consults it inline on the worker and it is unit-testable without the
    async sink."""

    def __init__(self, rules: Sequence[AlertRule]) -> None:
        self._rules = tuple(rules)

    def decide(self, event: Mapping[str, Any]) -> _RuleDecision:
        for rule in self._rules:
            if self._matches(rule, event):
                transports = None if rule.transports is None else tuple(rule.transports)
                return _RuleDecision(rule.severity.value, transports, rule.cooldown_seconds)
        return _DEFAULT_DECISION

    @staticmethod
    def _matches(rule: AlertRule, event: Mapping[str, Any]) -> bool:
        etype = str(event.get("type", ""))
        if rule.event_type != "any" and rule.event_type != etype:
            return False
        # Case-sensitive, OS-independent glob (connection names are case-sensitive).
        if not fnmatch.fnmatchcase(str(event.get("connection", "")), rule.connection):
            return False
        # Depth applies only to queue_buildup (you can't be "over depth" on a stopped connection); the
        # age threshold applies to BOTH age-carrying events — queue_buildup and message_stall (#50) —
        # since both fire on the same oldest-undelivered age (delivered_age). A rule setting a threshold
        # never matches an event type that lacks it.
        if rule.min_depth is not None:
            if etype != "queue_buildup" or int(event.get("depth", 0)) < rule.min_depth:
                return False
        if rule.min_oldest_seconds is not None:
            if etype not in ("queue_buildup", "message_stall") or (
                float(event.get("oldest_age_seconds", 0.0)) < rule.min_oldest_seconds
            ):
                return False
        return True


class NotifierAlertSink(_BackgroundDispatcher[dict[str, Any]]):
    """:class:`AlertSink` that fans each event out to one or more :class:`AlertTransport` on a
    background task, with a per-(event, connection) re-alert throttle. An optional :class:`AlertRuleSet`
    (ADR 0014) refines each event's severity, which transports fire, the cooldown, and suppression;
    with no rules the behaviour is byte-identical (every event → every transport, global throttle).

    The emit methods are synchronous and return immediately (enqueue only). Call :meth:`start` once a
    loop is running (the ASGI lifespan does this) and :meth:`aclose` on shutdown."""

    def __init__(
        self,
        transports: list[AlertTransport],
        *,
        realert_seconds: float = 300.0,
        rules: Sequence[AlertRule] | None = None,
        store: "_AlertStateStore | None" = None,
    ) -> None:
        super().__init__()
        self._transports = transports
        self._realert_seconds = realert_seconds
        self._rules = AlertRuleSet(rules or [])
        self._last_sent: dict[str, float] = {}
        # Durable alert-state (ADR 0044, #56): when wired, every emit upserts a resolvable instance on
        # the (type, connection) key BEFORE the throttle, and an inverse signal auto-resolves it. None =
        # state tracking off (byte-identical to pre-#56 — fire-and-forget only).
        self._store = store
        self._state_tasks: set[asyncio.Task[None]] = set()

    # --- AlertSink emit methods (sync, non-blocking) -------------------------

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self._emit({"type": "connection_stopped", "connection": name, "detail": detail})

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        self._emit(
            {
                "type": "queue_buildup",
                "connection": name,
                "depth": depth,
                "oldest_age_seconds": round(oldest_age_seconds, 1),
            }
        )

    def lane_stuck(self, name: str, *, detail: str) -> None:
        # ADR 0070 retry_forever: a pooled lane is retrying a persistent T17 infra fault at capped
        # backoff (never STOPped). The shared _emit throttle keys on (type, connection), so an ongoing
        # stuck lane collapses to one notification per cooldown; detail is a PHI-free stage+streak reason.
        self._emit({"type": "lane_stuck", "connection": name, "detail": detail})

    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None:
        # #50: the oldest undelivered message aged past the StallThreshold. The shared _emit throttle
        # keys on (type, connection), so an ongoing stall collapses to one notification per cooldown.
        self._emit(
            {
                "type": "message_stall",
                "connection": name,
                "oldest_age_seconds": round(oldest_age_seconds, 1),
            }
        )

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        # #46: an outbound lane went down. The shared _emit throttle keys on (type, connection), so a
        # retry storm on one lane collapses to one notification per cooldown. detail is safe_exc-scrubbed.
        self._emit({"type": "connection_error", "connection": name, "kind": kind, "detail": detail})

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        # The DB path stands in for "connection" so the realert throttle + subject keying work
        # uniformly; the event carries no message content (no PHI), only sizes.
        self._emit(
            {
                "type": "storage_threshold",
                "connection": path,
                "size_bytes": size_bytes,
                "limit_bytes": limit_bytes,
            }
        )

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        # The cert label stands in for "connection" so the realert throttle keys per cert; the payload
        # carries the PEM path + expiry only (no key material, no message content — no PHI).
        self._emit(
            {
                "type": "cert_expiry",
                "connection": name,
                "path": path,
                "not_after": not_after,
                "days_remaining": days_remaining,
            }
        )

    def integrity_drift(self, name: str, *, reason: str, drift_count: int) -> None:
        # #54: startup attestation found in-place-tampered engine module(s). The label ("engine-
        # integrity") stands in for "connection" so the realert throttle + subject keying + rule
        # matching work uniformly; the payload carries only a PHI-free reason + the drifted count.
        self._emit(
            {
                "type": "integrity_drift",
                "connection": name,
                "reason": reason,
                "drift_count": drift_count,
            }
        )

    def update_available(self, name: str, *, current_version: str, pinned_version: str) -> None:
        # #30 (ADR 0026): a newer version is pinned than is running. The package name ("messagefoundry")
        # stands in for "connection" so the realert throttle + subject keying + rule matching work
        # uniformly; the payload carries ONLY version strings (no PHI, no dependency list).
        self._emit(
            {
                "type": "update_available",
                "connection": name,
                "current_version": current_version,
                "pinned_version": pinned_version,
            }
        )

    def backup_failed(self, name: str, *, kind: str, detail: str | None = None) -> None:
        # #60 (ADR 0049): a DR backup failed. The source label ("dr_backup") stands in for "connection"
        # so the realert throttle + subject keying + rule matching work uniformly; the payload carries
        # only the failing phase (kind) + a PHI-free, safe_exc-scrubbed reason (no body, no key bytes).
        self._emit({"type": "backup_failed", "connection": name, "kind": kind, "detail": detail})

    def rcsi_off_degraded(self, name: str, *, detail: str) -> None:
        # ADR 0066: pooled claim mode started on SQL Server with RCSI OFF (require_rcsi_for_pooled=false
        # downgraded the fail-closed gate). The source label ("pipeline") stands in for "connection" so
        # the realert throttle + subject keying + rule matching work uniformly; the payload is a PHI-free
        # reason only (no message content).
        self._emit({"type": "rcsi_off_degraded", "connection": name, "detail": detail})

    def set_store(self, store: "_AlertStateStore | None") -> None:
        """Wire (or clear) the alert-state store (ADR 0044, #56). The lifespan calls this once the store
        is open, since :func:`notifier_from_settings` builds the sink from settings before the store
        exists. None disables state tracking (fire-and-forget only)."""
        self._store = store

    def connection_restored(self, name: str) -> None:
        """An outbound lane recovered (the inverse of ``connection_error``/``connection_lost``). Records
        NO notification (a recovery needs no page — the runner only stores the lifecycle row) but, when
        alert-state is wired (ADR 0044), **auto-resolves** the matching open ``connection_error`` instance
        so the dashboard clears. A no-op when no store is set (byte-identical to pre-#56)."""
        self._record_state({"type": "connection_restored", "connection": name}, "info")

    def _emit(self, event: dict[str, Any]) -> None:
        decision = self._rules.decide(event)
        # Durable alert-state (ADR 0044, #56) is recorded BEFORE the suppression/throttle returns: an
        # instance reflects the open *condition*, which a notification choice (suppress/throttle) must
        # not hide (AC-3). connection_restored/started auto-resolve their matching open instance instead.
        self._record_state(event, decision.severity)
        if decision.transports is not None and not decision.transports:
            return  # a rule suppressed this event (transports = [])
        cooldown = (
            decision.cooldown_seconds
            if decision.cooldown_seconds is not None
            else self._realert_seconds
        )
        key = f"{event['type']}:{event['connection']}"
        now = time.monotonic()
        last = self._last_sent.get(key)
        if last is not None and now - last < cooldown:
            return  # throttled — same event/connection notified too recently
        self._last_sent[key] = now
        event["ts"] = time.time()
        event["severity"] = (
            decision.severity
        )  # carried in the payload (webhook JSON / email subject)
        if decision.transports is not None:
            event["_transports"] = list(decision.transports)  # internal routing; popped before send
        self._enqueue(event, dropped=f"{event['type']} for {event['connection']!r}")

    # --- durable alert-state side observer (ADR 0044, #56) -------------------

    def _record_state(self, event: dict[str, Any], severity: str) -> None:
        """Schedule the alert-instance upsert (or auto-resolve) off ``_emit`` — a fail-soft side observer
        (ADR 0044 D2). Synchronous + non-blocking: it only creates a background task, never awaits the
        store. A no-op when no store is wired (state tracking off). The store write never raises into the
        ``_emit`` caller — a failure is swallowed/logged in :meth:`_run_state` so it can't wedge a worker."""
        store = self._store
        if store is None:
            return
        etype = str(event.get("type", ""))
        connection = str(event.get("connection", ""))
        inverse_of = _AUTO_RESOLVE.get(etype)
        coro: Coroutine[Any, Any, Any]
        if inverse_of is not None:
            coro = store.resolve_alert_instances_for(event_type=inverse_of, connection=connection)
        else:
            # reason: prefer the safe, PHI-free diagnostic the event already carries (detail/reason).
            raw_reason = event.get("detail") or event.get("reason")
            reason = str(raw_reason) if raw_reason is not None else None
            coro = store.upsert_alert_instance(
                event_type=etype, connection=connection, severity=severity, reason=reason
            )
        try:
            task = asyncio.ensure_future(self._run_state(coro))
        except RuntimeError:
            # No running loop (e.g. an emit on a non-async test path) — the state write is best-effort,
            # so drop it rather than raise into the caller. The notification path is unaffected.
            coro.close()
            return
        self._state_tasks.add(task)
        task.add_done_callback(self._state_tasks.discard)

    @staticmethod
    async def _run_state(coro: Any) -> None:
        try:
            await coro
        except Exception:
            # The alert-instance write is a side observer: a store error must never wedge a delivery
            # worker or drop the notification. Log metadata only (no event body).
            log.warning("alert-instance state write failed", exc_info=True)

    async def _handle(self, event: dict[str, Any]) -> None:
        targets = event.pop("_transports", None)  # a rule's transport subset (None = all)
        for transport in self._transports:
            if targets is not None and transport.name not in targets:
                continue  # this transport isn't in the matching rule's routing
            try:
                await transport.send(event)
            except Exception:
                # Best-effort: a failing transport must not drop the event for the others, nor
                # ever propagate into the engine. Detail (not PHI) is in the event itself.
                log.warning(
                    "alert transport %s failed for %s/%r",
                    transport.name,
                    event.get("type"),
                    event.get("connection"),
                    exc_info=True,
                )


def notifier_from_settings(alerts: AlertsSettings) -> NotifierAlertSink | None:
    """Build a :class:`NotifierAlertSink` from ``[alerts]`` settings, or ``None`` when no transport is
    configured (the caller then leaves the engine on its default logging sink)."""
    transports: list[AlertTransport] = []
    if alerts.webhook_url:
        transports.append(
            WebhookTransport(
                alerts.webhook_url,
                timeout=alerts.webhook_timeout,
                allowed_hosts=tuple(alerts.webhook_allowed_hosts),
            )
        )
    if alerts.email_smtp_host and alerts.email_from and alerts.email_to:
        transports.append(
            EmailTransport(
                host=alerts.email_smtp_host,
                port=alerts.email_smtp_port,
                sender=alerts.email_from,
                recipients=list(alerts.email_to),
                use_tls=alerts.email_use_tls,
                username=alerts.email_username,
                password=alerts.email_password,
                timeout=alerts.email_timeout,
                allowed_hosts=tuple(alerts.smtp_allowed_hosts),
            )
        )
    if not transports:
        return None
    # Fail loud at config time if a rule routes to a transport that isn't configured (a typo or a
    # missing webhook_url/email block) — caught at startup/reload, not silently swallowed at send.
    configured = {t.name for t in transports}
    for i, rule in enumerate(alerts.rules):
        unknown = [t for t in (rule.transports or []) if t not in configured]
        if unknown:
            raise ValueError(
                f"[alerts].rules[{i}] routes to unconfigured transport(s) {unknown}; "
                f"configured: {sorted(configured)}"
            )
    return NotifierAlertSink(transports, realert_seconds=alerts.realert_seconds, rules=alerts.rules)
