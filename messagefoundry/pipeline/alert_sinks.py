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

import asyncio
import json
import logging
import smtplib
import time
import urllib.parse
import urllib.request
from email.message import EmailMessage
from typing import Any, Protocol

from messagefoundry.config.settings import AlertsSettings

__all__ = [
    "AlertTransport",
    "WebhookTransport",
    "EmailTransport",
    "NotifierAlertSink",
    "notifier_from_settings",
]

log = logging.getLogger(__name__)

# Bound the in-memory backlog so a wedged transport (unreachable webhook) can't grow without limit;
# excess events are dropped with a warning rather than stalling the worker that enqueues them.
_MAX_QUEUE = 1000


class AlertTransport(Protocol):
    """One delivery channel for an alert event. ``send`` does the actual (blocking) I/O — the
    :class:`NotifierAlertSink` always calls it from a background task, never inline on a worker."""

    name: str

    async def send(self, event: dict[str, Any]) -> None: ...


def _subject(event: dict[str, Any]) -> str:
    return f"[MessageFoundry] {event['type']} — {event['connection']}"


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
        if self.allowed_hosts and self.host.lower() not in self.allowed_hosts:
            raise ValueError(f"SMTP host {self.host!r} is not in the configured allowlist")
        msg = EmailMessage()
        msg["Subject"] = _subject(event)
        msg["From"] = self.sender
        msg["To"] = ", ".join(self.recipients)
        msg.set_content(_body(event))
        with smtplib.SMTP(self.host, self.port, timeout=self.timeout) as smtp:
            if self.use_tls:
                smtp.starttls()
            if self.username is not None:
                smtp.login(self.username, self.password or "")
            smtp.send_message(msg)


class NotifierAlertSink:
    """:class:`AlertSink` that fans each event out to one or more :class:`AlertTransport` on a
    background task, with a per-(event, connection) re-alert throttle.

    The emit methods are synchronous and return immediately (enqueue only). Call :meth:`start` once a
    loop is running (the ASGI lifespan does this) and :meth:`aclose` on shutdown."""

    def __init__(self, transports: list[AlertTransport], *, realert_seconds: float = 300.0) -> None:
        self._transports = transports
        self._realert_seconds = realert_seconds
        self._queue: asyncio.Queue[dict[str, Any] | None] = asyncio.Queue(maxsize=_MAX_QUEUE)
        self._last_sent: dict[str, float] = {}
        self._task: asyncio.Task[None] | None = None

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

    def _emit(self, event: dict[str, Any]) -> None:
        key = f"{event['type']}:{event['connection']}"
        now = time.monotonic()
        last = self._last_sent.get(key)
        if last is not None and now - last < self._realert_seconds:
            return  # throttled — same event/connection notified too recently
        self._last_sent[key] = now
        event["ts"] = time.time()
        try:
            self._queue.put_nowait(event)
        except asyncio.QueueFull:
            log.warning("alert queue full; dropping %s for %r", event["type"], event["connection"])

    # --- lifecycle -----------------------------------------------------------

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
            event = await self._queue.get()
            if event is None:
                return
            for transport in self._transports:
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
    return NotifierAlertSink(transports, realert_seconds=alerts.realert_seconds)
