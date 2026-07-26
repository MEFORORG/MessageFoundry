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
import datetime
import fnmatch
import html
import json
import logging
import smtplib
import string
import time
import urllib.parse
import urllib.request
from collections.abc import Awaitable, Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from email.message import EmailMessage
from typing import Any, Generic, Protocol, TypeVar

from messagefoundry.config.secretprovider import SecretProvider, resolve_connector_secret
from messagefoundry.config.settings import (
    INSECURE_TLS_ESCAPE_ENV,
    AlertRule,
    AlertSeverity,
    AlertsSettings,
    EscalationTier,
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

#: #144 (ADR 0128): the injected async connection-control callback the notifier calls when a rule with a
#: ``control_action`` fires — ``(action, target)`` where ``action`` is ``restart_inbound`` /
#: ``restart_outbound`` and ``target`` is the connection name. Wired from ``api/app.py`` to the
#: ``RegistryRunner`` so the sink never imports the runner (ADR 0128 §2).
ControlCallback = Callable[[str, str], Awaitable[None]]

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
        escalation_tier: int = ...,
        now: float | None = ...,
    ) -> None: ...

    async def resolve_alert_instances_for(
        self, *, event_type: str, connection: str, now: float | None = ...
    ) -> int: ...

    async def list_active_alert_instances(self, *, limit: int = ...) -> Sequence[Any]: ...


#: Auto-resolution map (ADR 0044 D2): an inverse lifecycle event type resolves the matching open
#: instance(s) of the failure event type it cancels. ``connection_restored`` cancels the
#: ``connection_error`` raised on ``connection_lost``; a re-emitted ``connection_started`` clears a
#: ``connection_stopped``. Keyed by the inverse event's ``type`` → the failure event ``type`` it resolves.
_AUTO_RESOLVE: dict[str, str] = {
    "connection_restored": "connection_error",
    "connection_started": "connection_stopped",
    # #145: a leadership step-down / clean release / self-fence resolves this node's open leadership_acquired
    # instance; a DR fail-back resolves the open dr_activated. The open set then tracks the live leaders.
    "leadership_lost": "leadership_acquired",
    "dr_released": "dr_activated",
}

_T = TypeVar("_T")


class _BackgroundDispatcher(abc.ABC, Generic[_T]):  # noqa: UP046
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
    :class:`NotifierAlertSink` always calls it from a background task, never inline on a worker.

    ``recipients`` (#146) is the per-rule EMAIL recipient override the matching rule carried (``None`` =
    the transport's own default); ``context`` (#138) carries the extra non-PHI template values the
    notifier popped off the event (rule label + effective cooldown). Both are meaningful only to
    :class:`EmailTransport`; other transports (the webhook) accept and ignore them so the fan-out loop
    can call every transport uniformly."""

    name: str

    async def send(
        self,
        event: dict[str, Any],
        *,
        recipients: Sequence[str] | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None: ...


def _subject(event: dict[str, Any]) -> str:
    severity = str(event.get("severity", "warning")).upper()
    return f"[MessageFoundry] {severity} {event['type']} — {event['connection']}"


def _body(event: dict[str, Any]) -> str:
    lines = [f"{k}: {v}" for k, v in event.items() if not k.startswith("_")]
    return "\n".join(lines)


# --- #138 (ADR 0127) operator-editable alert-email templates -----------------
#
# A template is a {name} placeholder string over the CLOSED non-PHI allowlist (settings
# ``_ALERT_TEMPLATE_VARS``), validated at config-load. Rendering re-walks ``string.Formatter().parse``
# (never ``str.format`` — no attribute/index/format-spec surface) and substitutes only allowlisted
# values; the HTML variant HTML-escapes every substituted value (the operator's literal markup is left
# intact). The subject strips CR/LF (header-injection defence). Values are non-PHI by construction.

_TEMPLATE_FORMATTER = string.Formatter()


def _iso_ts(ts: Any) -> str:
    """Render an epoch-seconds timestamp as ISO-8601 UTC, or ``""`` when absent/unparseable (a template
    value must never raise — it is best-effort formatting on the alert path)."""
    if ts is None:
        return ""
    try:
        return datetime.datetime.fromtimestamp(float(ts), tz=datetime.UTC).isoformat()
    except (TypeError, ValueError, OSError, OverflowError):
        return ""


def _num(value: Any) -> str:
    """Render a numeric template value (depth / age / cooldown), or ``""`` when the event lacks it."""
    return "" if value is None else str(value)


def _template_values(event: Mapping[str, Any], context: Mapping[str, Any]) -> dict[str, str]:
    """Build the substitution values for an alert-email template — EXACTLY the keys in
    ``_ALERT_TEMPLATE_VARS`` (a test pins the two in sync). All values are strings and non-PHI by
    construction; ``context`` carries the rule label + effective cooldown the notifier popped off the
    event (never on the webhook wire)."""
    return {
        "severity": str(event.get("severity", "warning")),
        "type": str(event.get("type", "")),
        "connection": str(event.get("connection", "")),
        "timestamp": _iso_ts(event.get("ts")),
        "depth": _num(event.get("depth")),
        "oldest_age_seconds": _num(event.get("oldest_age_seconds")),
        "cooldown_seconds": _num(context.get("cooldown_seconds")),
        "rule_id": str(context.get("rule_id") or ""),
    }


def _render_template(template: str, values: Mapping[str, str], *, escape: bool) -> str:
    """Substitute allowlisted ``{name}`` placeholders in ``template`` from ``values``. ``escape`` HTML-
    escapes each substituted VALUE (not the literal markup) for the HTML part. The template was validated
    at config-load, so every field name is a bare allowlisted identifier."""
    out: list[str] = []
    for literal, field, _spec, _conv in _TEMPLATE_FORMATTER.parse(template):
        out.append(literal)
        if field is not None:
            value = values.get(field, "")
            out.append(html.escape(value) if escape else value)
    return "".join(out)


def _render_subject(template: str, values: Mapping[str, str]) -> str:
    """Render a subject template and collapse CR/LF to spaces — a subject is one header line, so a
    stray newline (header-injection) is neutralised (values are non-PHI regardless)."""
    rendered = _render_template(template, values, escape=False)
    return rendered.replace("\r", " ").replace("\n", " ")


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

    async def send(
        self,
        event: dict[str, Any],
        *,
        recipients: Sequence[str] | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        # recipients (#146) + context (#138) are EMAIL-only; a webhook has neither a per-rule recipient nor
        # an email template — accept and ignore them so the notifier's fan-out loop is uniform.
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
        # Never serialize INTERNAL routing keys (``_``-prefixed: e.g. the #146 ``_recipients`` override)
        # onto the wire — the fan-out loop pops them before send, but strip defensively so a webhook
        # payload can never carry recipient addresses / internal metadata even if a key slips through.
        payload = {k: v for k, v in event.items() if not k.startswith("_")}
        data = json.dumps(payload).encode("utf-8")
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
    html_body: str | None = None,
) -> None:
    """Send one email via SMTP (STARTTLS by default). Blocking — call via ``asyncio.to_thread``. Shared
    by :class:`EmailTransport` (ops alerts) and the per-user security-event notifier. An optional
    ``allowed_hosts`` egress allowlist gates the SMTP host. ``body`` (plain text) is ALWAYS the primary
    part; ``html_body`` (#138) adds an HTML **alternative** (``multipart/alternative``) when provided —
    the message is never HTML-only."""
    allowed = tuple(h.lower() for h in allowed_hosts)
    if allowed and host.lower() not in allowed:
        raise ValueError(f"SMTP host {host!r} is not in the configured allowlist")
    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = sender
    msg["To"] = ", ".join(recipients)
    msg.set_content(body)  # plain-text part is always kept (never HTML-only)
    if html_body is not None:
        msg.add_alternative(html_body, subtype="html")
    with smtplib.SMTP(host, port, timeout=timeout) as smtp:
        if use_tls:
            smtp.starttls()
        if username is not None:
            smtp.login(username, password or "")
        smtp.send_message(msg)


class EmailTransport:
    """Send the event as an email via SMTP (STARTTLS by default). By default a fixed subject + key/value
    plain-text body; with #138 (ADR 0127) templates configured, an operator-authored subject / plain body
    / HTML alternative over the closed non-PHI variable allowlist (validated at config-load)."""

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
        subject_template: str | None = None,
        body_template: str | None = None,
        html_template: str | None = None,
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
        # #138: operator-editable templates (None = fixed subject/body). Validated at config-load.
        self.subject_template = subject_template
        self.body_template = body_template
        self.html_template = html_template
        self.name = "email"

    async def send(
        self,
        event: dict[str, Any],
        *,
        recipients: Sequence[str] | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        await asyncio.to_thread(self._send, event, recipients, context)

    def _send(
        self,
        event: dict[str, Any],
        recipients: Sequence[str] | None = None,
        context: Mapping[str, Any] | None = None,
    ) -> None:
        # #146: a matching rule may re-target the email — use its recipients when present, else the
        # global [alerts].email_to this transport was built with. Addresses are operator config (not PHI).
        to = list(recipients) if recipients else self.recipients
        # #138: render operator templates when configured, else the fixed subject/body. The plain-text
        # part is ALWAYS present (an html_template alone still sends the default/plain body as text).
        subject = _subject(event)
        body = _body(event)
        html_body: str | None = None
        if self.subject_template or self.body_template or self.html_template:
            values = _template_values(event, context or {})
            if self.subject_template:
                subject = _render_subject(self.subject_template, values)
            if self.body_template:
                body = _render_template(self.body_template, values, escape=False)
            if self.html_template:
                html_body = _render_template(self.html_template, values, escape=True)
        send_plain_email(
            host=self.host,
            port=self.port,
            sender=self.sender,
            recipients=to,
            subject=subject,
            body=body,
            use_tls=self.use_tls,
            username=self.username,
            password=self.password,
            timeout=self.timeout,
            allowed_hosts=self.allowed_hosts,
            html_body=html_body,
        )


@dataclass(frozen=True)
class _RuleDecision:
    """How to handle one event: its ``severity``, the transports to fire (``None`` = every configured
    transport; ``()`` = suppress entirely), the re-alert ``cooldown_seconds`` (``None`` = the notifier's
    global ``realert_seconds``), and the per-rule email ``recipients`` override (``None`` = the global
    ``[alerts].email_to``; #146)."""

    severity: str
    transports: tuple[str, ...] | None
    cooldown_seconds: float | None
    recipients: tuple[str, ...] | None = None
    rule_id: str | None = None  # #138 — the matching rule's operator label ({rule_id} template var)
    control_action: str | None = None  # #144 — restart_inbound/restart_outbound to fire on match
    control_target: str | None = None  # #144 — the connection to act on (None = the event's own)
    # #81 (ADR 0133) — the matched rule's occurrence-driven escalation tiers, SORTED ascending by
    # after_count so _emit applies the highest satisfied tier by the in-memory occurrence count. () = none.
    escalate: tuple[EscalationTier, ...] = ()


# An event matching no rule keeps today's behaviour: warning, every transport, the global throttle, the
# global recipient list, no rule label, no control action.
_DEFAULT_DECISION = _RuleDecision(
    severity=AlertSeverity.WARNING.value,
    transports=None,
    cooldown_seconds=None,
    recipients=None,
    rule_id=None,
    control_action=None,
    control_target=None,
)


class AlertRuleSet:
    """Evaluate operator alert rules (ADR 0014) against an event, returning the **first** matching
    rule's :class:`_RuleDecision` (severity / transports / cooldown) or the default. Pure and
    synchronous, so the notifier consults it inline on the worker and it is unit-testable without the
    async sink."""

    def __init__(self, rules: Sequence[AlertRule]) -> None:
        self._rules = tuple(rules)

    def decide(self, event: Mapping[str, Any], now: float | None = None) -> _RuleDecision:
        # #81 (ADR 0133): `now` (epoch wall-clock) makes schedule-aware rules time-dependent; the caller
        # (_emit) passes time.time(). None keeps the previous unconditional behaviour for direct callers.
        now_dt = datetime.datetime.fromtimestamp(
            time.time() if now is None else now, tz=datetime.UTC
        )
        for rule in self._rules:
            if self._matches(rule, event, now_dt):
                # #143: a per-rule static mute suppresses the NOTIFICATION (transports=()) — equivalent to
                # transports=[], but reads as intent. State is still recorded (AC-3, in _emit before the
                # suppression return) and a #144 control action still fires (quiet auto-remediation).
                transports: tuple[str, ...] | None
                if rule.mute:
                    transports = ()
                else:
                    transports = None if rule.transports is None else tuple(rule.transports)
                recipients = None if rule.recipients is None else tuple(rule.recipients)
                # #81: carry the escalation tiers SORTED ascending by after_count so _emit applies the
                # highest satisfied tier and breaks at the first unsatisfied one.
                escalate = tuple(sorted(rule.escalate, key=lambda t: t.after_count))
                return _RuleDecision(
                    rule.severity.value,
                    transports,
                    rule.cooldown_seconds,
                    recipients,
                    rule.id,
                    rule.control_action,
                    rule.control_target,
                    escalate,
                )
        return _DEFAULT_DECISION

    @staticmethod
    def _matches(rule: AlertRule, event: Mapping[str, Any], now_dt: datetime.datetime) -> bool:
        etype = str(event.get("type", ""))
        if rule.event_type != "any" and rule.event_type != etype:
            return False
        # Case-sensitive, OS-independent glob (connection names are case-sensitive).
        if not fnmatch.fnmatchcase(str(event.get("connection", "")), rule.connection):
            return False
        # #81 (ADR 0133): schedule-aware — a scheduled rule applies ONLY when its Schedule is active at the
        # event time (or, with invert, only outside its windows). No schedule = always applies.
        if rule.schedule is not None and not rule.schedule.is_active(now_dt):
            return False
        # #81: content-label filter — route a content_match event by its (non-PHI operator) label.
        if rule.content_label is not None and str(event.get("label", "")) != rule.content_label:
            return False
        # Depth applies only to queue_buildup (you can't be "over depth" on a stopped connection); the
        # age threshold applies to BOTH age-carrying events — queue_buildup and message_stall (#50) —
        # since both fire on the same oldest-undelivered age (delivered_age). A rule setting a threshold
        # never matches an event type that lacks it.
        if rule.min_depth is not None:  # noqa: SIM102
            if etype != "queue_buildup" or int(event.get("depth", 0)) < rule.min_depth:
                return False
        if rule.min_oldest_seconds is not None:  # noqa: SIM102
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
        store: _AlertStateStore | None = None,
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
        # #143 (ADR 0044 amendment): windowed NOTIFICATION-mute cache — (type:connection) → until-epoch.
        # The synchronous suspend gate _emit consults; in-memory + per-node (the same advisory posture as
        # the _last_sent throttle above). The DURABLE record is alert_instance.suspended_until; this cache
        # is seeded from it at startup (prime_suspensions) and updated live by the API suspend/resume route.
        self._suspended: dict[str, float] = {}
        # #81 (ADR 0133): per-(type:connection) OCCURRENCE counter driving occurrence-based escalation.
        # Mirrors the store's `count` (both increment once per emit) but read SYNCHRONOUSLY in _emit to
        # pick the escalation tier. In-memory + per-node (advisory, like _last_sent); reset on auto-resolve
        # + operator resolve (the durable count/escalation_tier is the cross-restart record).
        self._occurrences: dict[str, int] = {}
        # #144 (ADR 0128): the injected async connection-control callback (action, target) → awaitable,
        # wired by the api/app.py lifespan to RegistryRunner.restart_inbound/restart_outbound. None = no
        # control wired (a control_action rule then no-ops, logged). The sink NEVER imports the runner.
        self._control_cb: ControlCallback | None = None
        self._control_tasks: set[asyncio.Task[None]] = set()

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

    def saturation_rising(
        self, name: str, *, stage: str, depth: int, depth_start: int, growth_per_second: float
    ) -> None:
        # #93 (ADR 0014 amendment): the lane is BECOMING overloaded — its backlog is rising sustained
        # (the ingest>drain derivative). The shared _emit throttle keys on (type, connection), so an
        # ongoing saturation collapses to one notification per cooldown; the payload carries only the
        # queue-shape derivative (stage + start/end depth + growth rate — no PHI).
        self._emit(
            {
                "type": "saturation",
                "connection": name,
                "stage": stage,
                "depth": depth,
                "depth_start": depth_start,
                "growth_per_second": round(growth_per_second, 3),
            }
        )

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        # #46: an outbound lane went down. The shared _emit throttle keys on (type, connection), so a
        # retry storm on one lane collapses to one notification per cooldown. detail is safe_exc-scrubbed.
        self._emit({"type": "connection_error", "connection": name, "kind": kind, "detail": detail})

    def content_match(self, connection: str, *, label: str, rule_id: str | None = None) -> None:
        # #81 (ADR 0133): a code-first Handler ("Action Point") inspected a message and decided to alert.
        # PHI-FREE BY CONTRACT: there is NO value parameter — the event carries ONLY the connection, an
        # operator `label` (e.g. "STAT order"), and an optional operator rule id — NEVER the matched field
        # value. Rides the SAME (type, connection) throttle + ADR 0044 dedup as every other event, so a
        # transform RE-RUN's re-emit folds into the one instance (idempotent) and is throttled to one
        # notification per cooldown — the purity / at-least-once reconciliation (ADR 0133 D3). A rule can
        # route it by `label` via AlertRule.content_label.
        event: dict[str, Any] = {"type": "content_match", "connection": connection, "label": label}
        if rule_id is not None:
            event["rule_id"] = rule_id  # non-PHI operator id (payload key; not the matched value)
        self._emit(event)

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

    def secret_rotation_due(
        self,
        name: str,
        *,
        secret: str,
        last_rotated: str,
        days_overdue: int,
        enforced: bool = False,
    ) -> None:
        # #195b (ADR 0019 §5) / ASVS 13.3.4: a tracked secret is overdue/near-due for rotation. The secret
        # label stands in for "connection" so the realert throttle keys per secret; the payload carries the
        # secret's config/env IDENTIFIER + rotation dates + the ENFORCE-escalation flag only (never a key
        # value or its keyed-MAC fingerprint — no PHI). `enforced` lets a matching rule tag it CRITICAL.
        self._emit(
            {
                "type": "secret_rotation",
                "connection": name,
                "secret": secret,
                "last_rotated": last_rotated,
                "days_overdue": days_overdue,
                "enforced": enforced,
            }
        )

    def bootstrap_admin_expiring(self, name: str, *, expires_at: str, hours_remaining: int) -> None:
        # ASVS 6.4.5 arm 2: the UNCLAIMED first-run bootstrap admin is nearing its auto-disable deadline.
        # The fixed label ("bootstrap-admin") stands in for "connection" so the realert throttle + subject
        # keying + rule matching work uniformly; the payload carries only the ISO deadline + whole hours
        # remaining (never the password or any secret — no PHI). The AuthService latch already collapses
        # it to one emit per process; the (type, connection) throttle is a second belt.
        self._emit(
            {
                "type": "bootstrap_admin_expiring",
                "connection": name,
                "expires_at": expires_at,
                "hours_remaining": hours_remaining,
            }
        )

    def gcm_invocations(self, name: str, *, key_id: str, invocations: int, ceiling: int) -> None:
        # ASVS 11.3.4: the active DEK is approaching its AES-GCM invocation ceiling. The key label
        # stands in for "connection" so the realert throttle + subject keying + rule matching work
        # uniformly; the payload carries the one-way key_id fingerprint + counts only (no key material,
        # no PHI).
        self._emit(
            {
                "type": "gcm_invocations",
                "connection": name,
                "key_id": key_id,
                "invocations": invocations,
                "ceiling": ceiling,
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

    def leadership_acquired(self, node: str, *, role: str, epoch: int | None = None) -> None:
        # #145: a node went non-leader→leader (HA failover / election). The node id stands in for
        # "connection" so the realert throttle + rule matching key per node; the payload carries only
        # node/role/epoch (cluster-topology facts — no PHI). leadership_lost is the auto-resolving inverse.
        self._emit(
            {
                "type": "leadership_acquired",
                "connection": node,
                "node": node,
                "role": role,
                "epoch": epoch,
            }
        )

    def leadership_lost(self, node: str, *, role: str, reason: str) -> None:
        # #145: the INVERSE — no notification (a step-down needs no page); auto-resolves this node's open
        # leadership_acquired instance via _AUTO_RESOLVE (ADR 0044), mirroring connection_restored.
        self._record_state({"type": "leadership_lost", "connection": node}, "info")

    def dr_activated(self, node: str, *, role: str) -> None:
        # #145 (ADR 0048): a third-tier DR standby was promoted. The DR box label stands in for
        # "connection"; the payload carries only node/role (no PHI). dr_released is the auto-resolving inverse.
        self._emit({"type": "dr_activated", "connection": node, "node": node, "role": role})

    def dr_released(self, node: str, *, role: str) -> None:
        # #145 (ADR 0048): the INVERSE — a clean fail-back needs no page; auto-resolves the open
        # dr_activated instance via _AUTO_RESOLVE (ADR 0044).
        self._record_state({"type": "dr_released", "connection": node}, "info")

    def set_store(self, store: _AlertStateStore | None) -> None:
        """Wire (or clear) the alert-state store (ADR 0044, #56). The lifespan calls this once the store
        is open, since :func:`notifier_from_settings` builds the sink from settings before the store
        exists. None disables state tracking (fire-and-forget only)."""
        self._store = store

    def set_control_callback(self, cb: ControlCallback | None) -> None:
        """Wire (or clear) the #144 (ADR 0128) connection-control callback. The ``api/app.py`` lifespan
        calls this once the engine/runner exist, since :func:`notifier_from_settings` builds the sink
        before them. The sink NEVER imports :class:`RegistryRunner` — the callback is injected DOWN.
        None disables control actions (a ``control_action`` rule then no-ops, logged)."""
        self._control_cb = cb

    # --- #143 (ADR 0044 amendment) windowed suspend / mute (notification-only) ---

    def suspend(self, event_type: str, connection: str, *, until: float) -> None:
        """Mute NOTIFICATIONS for ``(event_type, connection)`` until ``until`` (an epoch) — the running-
        sink half of the operator's windowed suspend (``POST /alerts/{id}/suspend``). The durable record
        is ``alert_instance.suspended_until``; the API calls this so the mute takes effect immediately
        without waiting for a re-observation. NOTIFICATION-only (AC-3): the durable instance keeps firing
        into the state observer (it stays open/counted/visible) — only the transport enqueue is gated.
        In-memory + per-node (the ``_last_sent`` throttle's advisory posture)."""
        self._suspended[f"{event_type}:{connection}"] = until

    def resume(self, event_type: str, connection: str) -> None:
        """Clear a windowed suspend for ``(event_type, connection)`` (``POST /alerts/{id}/resume``) so
        re-alerts resume immediately. Does NOT reset the escalation counter — the condition persists."""
        self._suspended.pop(f"{event_type}:{connection}", None)

    def forget(self, event_type: str, connection: str) -> None:
        """Drop ALL in-memory advisory state for ``(event_type, connection)`` — the suspend window AND the
        #81 escalation occurrence counter. Called by the API on an operator **resolve** (the condition is
        closed), so a later re-open of the same key starts un-suspended at the base escalation tier,
        matching the fresh durable instance the store opens."""
        self._suspended.pop(f"{event_type}:{connection}", None)
        self._occurrences.pop(f"{event_type}:{connection}", None)

    async def prime_suspensions(self) -> None:
        """Seed the in-memory suspend cache from durable ``alert_instance.suspended_until`` at startup, so
        a suspend set before this process started is honored without waiting for the condition to re-fire.
        A no-op when no store is wired. Best-effort — a store error is swallowed (the notify path is
        unaffected). Only still-future windows are loaded; an already-elapsed window is ignored."""
        store = self._store
        if store is None:
            return
        try:
            rows = await store.list_active_alert_instances(limit=1000)
        except Exception:
            log.warning("alert suspend-cache prime failed", exc_info=True)
            return
        now = time.time()
        for a in rows:
            until = getattr(a, "suspended_until", None)
            if until is not None and until > now:
                self._suspended[f"{a.event_type}:{a.connection}"] = float(until)

    def connection_restored(self, name: str) -> None:
        """An outbound lane recovered (the inverse of ``connection_error``/``connection_lost``). Records
        NO notification (a recovery needs no page — the runner only stores the lifecycle row) but, when
        alert-state is wired (ADR 0044), **auto-resolves** the matching open ``connection_error`` instance
        so the dashboard clears. A no-op when no store is set (byte-identical to pre-#56)."""
        self._record_state({"type": "connection_restored", "connection": name}, "info")

    @staticmethod
    def _apply_escalation(
        decision: _RuleDecision, occurrences: int
    ) -> tuple[str, tuple[str, ...] | None, tuple[str, ...] | None, int]:
        """#81 (ADR 0133): apply the highest OCCURRENCE-satisfied escalation tier over the base decision.
        ``decision.escalate`` is sorted ascending by ``after_count`` (see :meth:`AlertRuleSet.decide`), so
        we accumulate every tier the count has crossed and break at the first unsatisfied one — the last
        applied is the highest. Returns ``(severity, transports, recipients, tier_level)`` where
        ``tier_level`` (0 = base) is the number of crossed tiers, persisted to ``alert_instance``."""
        severity = decision.severity
        transports = decision.transports
        recipients = decision.recipients
        tier = 0
        for step in decision.escalate:
            if occurrences < step.after_count:
                break  # sorted ascending → no later tier is satisfied either
            tier += 1
            if step.severity is not None:
                severity = step.severity.value
            if step.transports is not None:
                transports = tuple(step.transports)
            if step.recipients is not None:
                recipients = tuple(step.recipients)
        return severity, transports, recipients, tier

    def _emit(self, event: dict[str, Any]) -> None:
        now_wall = time.time()
        # #81: schedule-aware decide is time-dependent, so pass the wall clock.
        decision = self._rules.decide(event, now_wall)
        key = f"{event['type']}:{event['connection']}"
        # #81 (ADR 0133): occurrence-driven escalation. The in-memory occurrence count mirrors the store's
        # `count` (both bump once per emit); apply the highest tier the count has crossed. tier is persisted
        # to alert_instance.escalation_tier via _record_state below.
        occ = self._occurrences.get(key, 0) + 1
        self._occurrences[key] = occ
        severity, transports, recipients, tier = self._apply_escalation(decision, occ)
        # Durable alert-state (ADR 0044, #56) is recorded BEFORE the suppression/throttle returns: an
        # instance reflects the open *condition*, which a notification choice (suppress/throttle) must
        # not hide (AC-3). connection_restored/started auto-resolve their matching open instance instead.
        self._record_state(event, severity, escalation_tier=tier)
        cooldown = (
            decision.cooldown_seconds
            if decision.cooldown_seconds is not None
            else self._realert_seconds
        )
        now = time.monotonic()
        last = self._last_sent.get(key)
        if last is not None and now - last < cooldown:
            return  # throttled — throttles BOTH the notification and any #144 control action for this window
        self._last_sent[key] = now
        # #144 (ADR 0128): fire the auto-remediation control action on a fresh (non-throttled) alert —
        # BEFORE the transport-suppression return, so a rule may auto-remediate QUIETLY (transports=[]) or
        # alongside a page. Dispatched off-worker + never-raise (see _dispatch_control).
        if decision.control_action is not None:
            target = decision.control_target or str(event["connection"])
            self._dispatch_control(decision.control_action, target)
        # #143 (ADR 0044 amendment): the windowed suspend gate — NOTIFICATION-only. The durable instance
        # was already recorded above (AC-3: a suspended alert stays open/counted/visible), and any #144
        # control action already dispatched; a still-active suspend window only mutes the transport enqueue.
        # An elapsed window (now >= until) falls through and re-alerts, so expiry needs no timer/sweep.
        suspended_until = self._suspended.get(key)
        if suspended_until is not None:
            if now_wall < suspended_until:
                return  # muted for the window — notification suppressed, condition still visible
            del self._suspended[key]  # window elapsed — drop the stale entry and notify normally
        # #81: the escalated transports (a tier may raise/route/suppress) drive suppression + fan-out.
        if transports is not None and not transports:
            return  # a rule/tier suppressed the NOTIFICATION (any control action already dispatched above)
        event["ts"] = time.time()
        event["severity"] = severity  # carried in the payload (webhook JSON / email subject)
        if transports is not None:
            event["_transports"] = list(transports)  # internal routing; popped before send
        if recipients is not None:
            # #146: per-rule EMAIL recipient override — an internal routing key popped in _handle before
            # any send, so the webhook payload NEVER carries recipient addresses (defense also in _post).
            event["_recipients"] = list(recipients)
        # #138: the email-template context (rule label + effective cooldown) — internal ``_``-keys popped
        # in _handle into the render context, so they never cross the webhook wire (_post strips ``_*``).
        event["_rule_id"] = decision.rule_id or ""
        event["_cooldown_seconds"] = cooldown
        self._enqueue(event, dropped=f"{event['type']} for {event['connection']!r}")

    # --- durable alert-state side observer (ADR 0044, #56) -------------------

    def _record_state(
        self, event: dict[str, Any], severity: str, *, escalation_tier: int = 0
    ) -> None:
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
            # #143/#81: a resolved condition has nothing left to mute OR escalate — drop the windowed-
            # suspend cache entry AND the escalation occurrence counter for the resolved key, so a later
            # re-open of the SAME key starts un-suspended at the base tier (the durable suspended_until /
            # escalation_tier were on the now-resolved row and never return via list_active).
            self._suspended.pop(f"{inverse_of}:{connection}", None)
            self._occurrences.pop(f"{inverse_of}:{connection}", None)
            coro = store.resolve_alert_instances_for(event_type=inverse_of, connection=connection)
        else:
            # reason: prefer the safe, PHI-free diagnostic the event already carries (detail/reason);
            # a content_match event carries only its non-PHI operator `label` (#81, ADR 0133) — NEVER the
            # matched field value — so fall back to it so the instance shows what the content alert is about.
            raw_reason = event.get("detail") or event.get("reason") or event.get("label")
            reason = str(raw_reason) if raw_reason is not None else None
            coro = store.upsert_alert_instance(
                event_type=etype,
                connection=connection,
                severity=severity,
                reason=reason,
                escalation_tier=escalation_tier,
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

    # --- #144 (ADR 0128) connection-control action (off-worker, never-raise) --

    def _dispatch_control(self, action: str, target: str) -> None:
        """Schedule the injected connection-control callback OFF the delivery worker (a fire-and-forget
        task, exactly like the ADR 0044 state observer). Synchronous + non-blocking: it only creates the
        task, never awaits the runner, so a slow/hung restart can never stall the worker that emitted the
        alert. A no-op when no callback is wired (logged once at emit)."""
        cb = self._control_cb
        if cb is None:
            log.warning(
                "alert control_action %s for %r requested but no control callback is wired",
                action,
                target,
            )
            return
        try:
            task = asyncio.ensure_future(self._run_control(cb, action, target))
        except RuntimeError:
            # No running loop (e.g. a control emit on a non-async test path) — best-effort, drop it rather
            # than raise into the caller. The notification path is unaffected.
            return
        self._control_tasks.add(task)
        task.add_done_callback(self._control_tasks.discard)

    @staticmethod
    async def _run_control(cb: ControlCallback, action: str, target: str) -> None:
        try:
            await cb(action, target)
        except Exception:
            # NEVER-RAISE (ADR 0128 §3): a rejected/hung restart (unknown / not-deployed / shard-not-owner
            # connection) must never break alerting or delivery. Swallow + log metadata only (no PHI).
            log.warning("alert control_action %s for %r failed", action, target, exc_info=True)

    async def _handle(self, event: dict[str, Any]) -> None:
        targets = event.pop("_transports", None)  # a rule's transport subset (None = all)
        # #146: pop the per-rule EMAIL recipient override BEFORE the fan-out loop so it never reaches the
        # webhook (which serializes the event to JSON); only the email transport consumes it.
        recipients = event.pop("_recipients", None)
        # #138: pop the email-template context (rule label + effective cooldown) into a side mapping so the
        # event delivered to every transport is clean (no internal ``_``-keys); only the email uses it.
        context = {
            "rule_id": event.pop("_rule_id", ""),
            "cooldown_seconds": event.pop("_cooldown_seconds", None),
        }
        for transport in self._transports:
            if targets is not None and transport.name not in targets:
                continue  # this transport isn't in the matching rule's routing
            try:
                await transport.send(event, recipients=recipients, context=context)
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


def notifier_from_settings(
    alerts: AlertsSettings, *, secret_provider: SecretProvider | None = None
) -> NotifierAlertSink | None:
    """Build a :class:`NotifierAlertSink` from ``[alerts]`` settings, or ``None`` when no transport is
    configured (the caller then leaves the engine on its default logging sink).

    ``secret_provider`` (ADR 0019 §5) resolves the SMTP password from a ``[secrets].provider`` when
    ``email_password_secret`` is set (fail-closed); ``None``/no reference → the env-sourced
    ``email_password`` is used, byte-identical to before."""
    smtp_password = resolve_connector_secret(
        secret_provider,
        ref=alerts.email_password_secret,
        literal=alerts.email_password,
        label="[alerts].email_password",
    )
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
                password=smtp_password,
                timeout=alerts.email_timeout,
                allowed_hosts=tuple(alerts.smtp_allowed_hosts),
                # #138: operator-editable templates (None = fixed subject/body; validated at config-load).
                subject_template=alerts.email_subject_template,
                body_template=alerts.email_body_template,
                html_template=alerts.email_html_template,
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
        # #81 (ADR 0133): an escalation tier's transport override must also name only configured transports.
        for j, step in enumerate(rule.escalate):
            unknown_tier = [t for t in (step.transports or []) if t not in configured]
            if unknown_tier:
                raise ValueError(
                    f"[alerts].rules[{i}].escalate[{j}] routes to unconfigured transport(s) "
                    f"{unknown_tier}; configured: {sorted(configured)}"
                )
    return NotifierAlertSink(transports, realert_seconds=alerts.realert_seconds, rules=alerts.rules)
