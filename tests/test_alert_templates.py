# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Operator-editable alert-email templates (#138, ADR 0127): the CLOSED non-PHI variable allowlist
(fail-closed at config-load), the HTML-escaped alternative + always-kept plain part, the header-injection
guard on the subject, and the renderer↔allowlist sync invariant."""

from __future__ import annotations

from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import (
    _ALERT_TEMPLATE_VARS,
    AlertRule,
    AlertsSettings,
    validate_alert_template,
)
from messagefoundry.pipeline.alert_sinks import EmailTransport, _template_values

# --- the renderer provides EXACTLY the allowlisted variables -----------------


def test_renderer_values_match_the_allowlist() -> None:
    # The config-load allowlist (_ALERT_TEMPLATE_VARS) and the values the renderer supplies MUST stay in
    # sync, or a template could pass validation yet render "" for a "valid" name (or vice-versa).
    values = _template_values({}, {})
    assert set(values) == _ALERT_TEMPLATE_VARS


# --- config-load validation (fail-closed) ------------------------------------


def test_valid_template_accepted_at_config_load() -> None:
    s = AlertsSettings(
        email_subject_template="[{severity}] {type} on {connection} @ {timestamp}",
        email_body_template="rule={rule_id} depth={depth} age={oldest_age_seconds} cd={cooldown_seconds}",
        email_html_template="<b>{severity}</b> {connection}",
    )
    assert s.email_subject_template is not None


def test_unknown_variable_rejected_fail_closed() -> None:
    # The headline PHI guard: a message-body / arbitrary field is not on the allowlist → refused at load.
    with pytest.raises(ValidationError, match="unknown / PHI-unsafe template variable"):
        AlertsSettings(email_body_template="patient={raw}")
    with pytest.raises(ValidationError, match="unknown / PHI-unsafe template variable"):
        AlertsSettings(
            email_subject_template="{detail}"
        )  # 'detail' is deliberately NOT allowlisted


def test_attribute_and_index_access_rejected() -> None:
    # str.format's attribute/index access is an injection surface — bare names only.
    with pytest.raises(ValidationError, match="unknown / PHI-unsafe|not allowed"):
        AlertsSettings(email_body_template="{connection.__class__}")
    with pytest.raises(ValidationError, match="unknown / PHI-unsafe|not allowed"):
        AlertsSettings(email_body_template="{0}")


def test_format_spec_and_conversion_rejected() -> None:
    with pytest.raises(ValidationError, match="conversion / format-spec"):
        AlertsSettings(email_body_template="{depth:>10}")
    with pytest.raises(ValidationError, match="conversion / format-spec"):
        AlertsSettings(email_body_template="{connection!r}")


def test_empty_placeholder_rejected() -> None:
    with pytest.raises(ValidationError, match="empty"):
        AlertsSettings(email_body_template="value={}")


def test_escaped_braces_are_literal() -> None:
    # {{ and }} are literal braces, not placeholders — must not trip the allowlist.
    s = AlertsSettings(email_body_template="literal {{braces}} and {connection}")
    assert s.email_body_template is not None


def test_validate_alert_template_direct() -> None:
    validate_alert_template("{severity} {type} {connection}", where="x")  # ok
    with pytest.raises(ValueError, match="unknown / PHI-unsafe"):
        validate_alert_template("{message_body}", where="x")


# --- rendering: EmailTransport end-to-end ------------------------------------


def _capture_smtp(monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    captured: dict[str, Any] = {}

    class _FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
            pass

        def __enter__(self) -> _FakeSMTP:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def starttls(self) -> None:
            pass

        def send_message(self, msg: Any) -> None:
            captured["subject"] = msg["Subject"]
            plain = html = None
            for part in msg.walk():
                ct = part.get_content_type()
                if ct == "text/plain":
                    plain = part.get_content()
                elif ct == "text/html":
                    html = part.get_content()
            captured["plain"] = plain
            captured["html"] = html

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.smtplib.SMTP", _FakeSMTP)
    return captured


def test_default_no_template_is_fixed_subject_body(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = _capture_smtp(monkeypatch)
    t = EmailTransport(host="smtp.example", port=587, sender="mf@x", recipients=["ops@x"])
    t._send(
        {
            "type": "connection_stopped",
            "connection": "OB_X",
            "detail": "boom",
            "severity": "warning",
        }
    )
    assert cap["subject"] == "[MessageFoundry] WARNING connection_stopped — OB_X"
    assert cap["html"] is None  # no HTML part by default
    assert "connection: OB_X" in cap["plain"]


def test_template_renders_subject_and_body_and_html(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = _capture_smtp(monkeypatch)
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@x",
        recipients=["ops@x"],
        subject_template="{severity} {type} {connection}",
        body_template="lane {connection} rule={rule_id} cd={cooldown_seconds}",
        html_template="<h1>{severity}</h1><p>{connection}</p>",
    )
    event = {"type": "queue_buildup", "connection": "OB_X", "depth": 5, "severity": "critical"}
    t._send(event, None, {"rule_id": "R1", "cooldown_seconds": 60.0})
    assert cap["subject"] == "critical queue_buildup OB_X"
    assert cap["plain"].strip() == "lane OB_X rule=R1 cd=60.0"
    assert "<h1>critical</h1>" in cap["html"]  # HTML alternative present + rendered


def test_html_values_are_escaped(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = _capture_smtp(monkeypatch)
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@x",
        recipients=["ops@x"],
        html_template="<p>conn={connection}</p>",
    )
    # A value containing markup must be HTML-escaped (defence-in-depth on the off-box surface).
    t._send({"type": "connection_stopped", "connection": "A<script>B", "severity": "warning"})
    assert "A&lt;script&gt;B" in cap["html"]
    assert "<script>" not in cap["html"]
    # The plain-text part is ALWAYS kept even when only an HTML template is set.
    assert cap["plain"] is not None


def test_subject_strips_newlines_header_injection(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = _capture_smtp(monkeypatch)
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@x",
        recipients=["ops@x"],
        subject_template="Alert {connection}",
    )
    # A CR/LF reaching the rendered subject (here via a value) must be neutralised — a subject is one line.
    t._send(
        {"type": "connection_stopped", "connection": "OB_X\r\nBcc: evil@x", "severity": "warning"}
    )
    assert "\n" not in cap["subject"] and "\r" not in cap["subject"]
    assert "Bcc: evil@x" in cap["subject"]  # collapsed onto the one line, not a separate header


def test_timestamp_and_missing_counts_render(monkeypatch: pytest.MonkeyPatch) -> None:
    cap = _capture_smtp(monkeypatch)
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@x",
        recipients=["ops@x"],
        body_template="t={timestamp} depth={depth}",
    )
    # connection_stopped has no depth → {depth} renders "" (never raises); ts renders ISO-8601.
    t._send(
        {
            "type": "connection_stopped",
            "connection": "OB_X",
            "ts": 1_700_000_000.0,
            "severity": "warning",
        }
    )
    assert "depth=" in cap["plain"] and "depth=None" not in cap["plain"]
    assert "2023-" in cap["plain"]  # ISO timestamp from the epoch


# --- end-to-end through the NotifierAlertSink --------------------------------


async def test_notifier_flows_rule_id_context_to_email_and_not_webhook(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    import asyncio

    from messagefoundry.pipeline.alert_sinks import NotifierAlertSink

    cap = _capture_smtp(monkeypatch)
    email = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@x",
        recipients=["ops@x"],
        subject_template="{type} {connection} [{rule_id}]",
    )

    class _RecWebhook:
        name = "webhook"

        def __init__(self) -> None:
            self.events: list[dict[str, Any]] = []

        async def send(
            self, event: dict[str, Any], *, recipients: Any = None, context: Any = None
        ) -> None:
            self.events.append(event)

    web = _RecWebhook()
    rule = AlertRule(event_type="connection_stopped", id="R-42")
    sink = NotifierAlertSink([email, web], rules=[rule])
    sink.connection_stopped("OB_X", detail="boom")
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()

    # email rendered {rule_id} from the popped context
    assert cap["subject"] == "connection_stopped OB_X [R-42]"
    # the webhook event is clean — no internal _rule_id/_cooldown_seconds keys reached it
    assert web.events and "_rule_id" not in web.events[0]
    assert "_cooldown_seconds" not in web.events[0]


# --- AlertRule.id ------------------------------------------------------------


def test_alert_rule_id_field() -> None:
    assert AlertRule().id is None
    assert AlertRule(id="my-rule").id == "my-rule"
