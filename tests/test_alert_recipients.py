# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Per-rule alert recipients (#146, ADR 0014 amendment): a matching rule re-targets the EMAIL
transport's recipients, the override is popped before any webhook payload (no addresses on the wire),
and the model rejects an empty override."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import AlertRule, AlertsSettings
from messagefoundry.pipeline.alert_sinks import (
    AlertRuleSet,
    EmailTransport,
    NotifierAlertSink,
    WebhookTransport,
)


class _RecordingTransport:
    """Records each (event, recipients) it's handed — recipients is the #146 email override."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.calls: list[tuple[dict[str, Any], Any]] = []

    async def send(
        self, event: dict[str, Any], *, recipients: Any = None, context: Any = None
    ) -> None:
        self.calls.append((event, recipients))


async def _drain(sink: NotifierAlertSink) -> None:
    sink.start()
    await asyncio.sleep(0)
    await sink.aclose()


# --- decide() carries the override -------------------------------------------


def test_decide_returns_recipients_override() -> None:
    rules = AlertRuleSet(
        [AlertRule(event_type="connection_stopped", recipients=["oncall@x", "lead@x"])]
    )
    d = rules.decide({"type": "connection_stopped", "connection": "OB_X"})
    assert d.recipients == ("oncall@x", "lead@x")
    # a non-matching event falls through to the default (global recipients)
    assert rules.decide({"type": "queue_buildup", "connection": "OB_X"}).recipients is None


# --- the email transport is re-targeted --------------------------------------


async def test_rule_recipients_reach_email_transport() -> None:
    email = _RecordingTransport("email")
    rule = AlertRule(event_type="connection_stopped", recipients=["oncall@x"])
    sink = NotifierAlertSink([email], rules=[rule])
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert len(email.calls) == 1
    event, recipients = email.calls[0]
    assert recipients == ["oncall@x"]  # the rule's override, handed to the transport
    assert "_recipients" not in event  # popped before send — never in the delivered payload


async def test_no_rule_leaves_recipients_none() -> None:
    # Byte-identical default: with no matching rule the transport gets recipients=None (→ its own
    # global email_to), exactly as before #146.
    email = _RecordingTransport("email")
    sink = NotifierAlertSink([email])
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    _event, recipients = email.calls[0]
    assert recipients is None


async def test_recipients_never_reach_the_webhook_payload(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The headline PHI/secret guard: recipient addresses are an internal routing key that must never be
    # serialized onto the webhook wire. Use a real WebhookTransport with a captured opener.
    captured: dict[str, Any] = {}

    class _Resp:
        def __enter__(self) -> _Resp:
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return b""

    def fake_open(req: Any, timeout: float | None = None) -> _Resp:
        captured["body"] = req.data
        return _Resp()

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks._NO_REDIRECT_OPENER.open", fake_open)
    web = WebhookTransport("https://hooks.example/x")
    rule = AlertRule(event_type="connection_stopped", recipients=["oncall@secret.example"])
    sink = NotifierAlertSink([web], rules=[rule])
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    body = captured["body"].decode("utf-8")
    assert "oncall@secret.example" not in body
    assert "_recipients" not in body
    assert "recipients" not in body


# --- EmailTransport honours the override directly ----------------------------


def test_email_transport_uses_override_recipients(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict[str, Any] = {}

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
            sent["to"] = msg["To"]

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.smtplib.SMTP", _FakeSMTP)
    t = EmailTransport(
        host="smtp.example", port=587, sender="mf@example", recipients=["default@example"]
    )
    # override present → the email goes to the rule's recipients, not the transport default
    t._send({"type": "connection_stopped", "connection": "OB_X", "detail": "x"}, ["a@x", "b@x"])
    assert sent["to"] == "a@x, b@x"
    # no override → falls back to the transport's global recipients
    t._send({"type": "connection_stopped", "connection": "OB_X", "detail": "x"}, None)
    assert sent["to"] == "default@example"


# --- model validation --------------------------------------------------------


def test_rule_rejects_empty_recipients() -> None:
    with pytest.raises(ValidationError, match="recipients must be a non-empty list"):
        AlertRule(recipients=[])
    with pytest.raises(ValidationError, match="recipients must be a non-empty list"):
        AlertRule(recipients=["   "])  # all-blank collapses to empty


def test_rule_recipients_none_is_default() -> None:
    assert AlertRule().recipients is None  # unset = fall through to global email_to


def test_settings_accepts_per_rule_recipients() -> None:
    s = AlertsSettings(
        webhook_url="https://hooks.example/x",
        rules=[AlertRule(event_type="connection_stopped", recipients=["oncall@x"])],
    )
    assert s.rules[0].recipients == ["oncall@x"]
