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
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Generic, Protocol, TypeVar

from messagefoundry.config.settings import AlertRule, AlertSeverity, AlertsSettings

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
        # Depth/age thresholds apply only to queue_buildup — a rule that sets one never matches another
        # event type (you can't be "over depth" on a stopped connection).
        if rule.min_depth is not None:
            if etype != "queue_buildup" or int(event.get("depth", 0)) < rule.min_depth:
                return False
        if rule.min_oldest_seconds is not None:
            if etype != "queue_buildup" or (
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
    ) -> None:
        super().__init__()
        self._transports = transports
        self._realert_seconds = realert_seconds
        self._rules = AlertRuleSet(rules or [])
        self._last_sent: dict[str, float] = {}

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

    def _emit(self, event: dict[str, Any]) -> None:
        decision = self._rules.decide(event)
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
