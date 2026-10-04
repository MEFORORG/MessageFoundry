# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Per-rule alert recipients (#146, ADR 0014 amendment): a matching rule re-targets the EMAIL
transport's recipients, the override is popped before any webhook payload (no addresses on the wire),
and the model rejects an empty override.

The SMTP envelope section reads the wire: every sender and recipient passes the Email destination's
address rule, and MAIL FROM and RCPT TO carry exactly the checked text (vault BACKLOG #2870)."""

from __future__ import annotations

import asyncio
import ssl
from collections.abc import Iterator
from email.message import EmailMessage
from typing import Any

import pytest
from pydantic import ValidationError

from messagefoundry.config.settings import AlertRule, AlertsSettings, EscalationTier
from messagefoundry.pipeline.alert_sinks import (
    AlertRuleSet,
    EmailTransport,
    NotifierAlertSink,
    WebhookTransport,
    notifier_from_settings,
    send_plain_email,
)
from tests.test_email_destination import (
    _ALL_ATEXT_SENDER,
    _ENCODED_LOCAL,
    _NORMALISED_RECIPIENTS,
    _REFUSED_ADDRESS_IDS,
    _REFUSED_ADDRESSES,
    _WireCapture,
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

        def read(self, amt: int = -1) -> bytes:
            return b"" if amt < 0 else (b"")[:amt]

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

        def starttls(self, context: ssl.SSLContext | None = None) -> None:
            pass

        def send_message(self, msg: Any, **envelope: Any) -> None:
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


# --- the SMTP envelope on the wire (vault BACKLOG #2870) ---------------------
#
# Each test reads the MAIL and RCPT lines a loopback listener received, so it checks what a relay
# would act on rather than what the transport handed smtplib.


@pytest.fixture
def wire() -> Iterator[_WireCapture]:
    capture = _WireCapture()
    try:
        yield capture
    finally:
        capture.close()


def _send_to(port: int, sender: str, recipients: list[str]) -> None:
    # Cleartext and unauthenticated, which this cell allows; the listener speaks no TLS.
    send_plain_email(
        host="127.0.0.1",
        port=port,
        sender=sender,
        recipients=recipients,
        subject="synthetic",
        body="synthetic alert",
        use_tls=False,
        timeout=5.0,
    )


@pytest.mark.parametrize(
    "setting, address",
    list(_NORMALISED_RECIPIENTS.values()),
    ids=list(_NORMALISED_RECIPIENTS),
)
def test_alert_mail_from_and_rcpt_name_exactly_the_checked_addresses(
    wire: _WireCapture, setting: str, address: str
) -> None:
    _send_to(wire.port, _ALL_ATEXT_SENDER, [setting])
    assert wire.mail_lines == [("mail from:<" + _ALL_ATEXT_SENDER + ">").encode()]
    assert wire.rcpt_lines == [("rcpt to:<" + address + ">").encode()]
    [from_line] = [line for line in wire.data if line.lower().startswith(b"from:")]
    assert from_line.rstrip(b"\r\n") == ("From: " + _ALL_ATEXT_SENDER).encode()
    [to_line] = [line for line in wire.data if line.lower().startswith(b"to:")]
    assert to_line.rstrip(b"\r\n") == ("To: " + address).encode()


def test_alert_envelope_does_not_follow_the_headers(
    wire: _WireCapture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A plain address reads the same either way, so every From: and To: the cell writes is swapped
    # for another address. MAIL FROM and RCPT TO must still be the checked values, which they are
    # only when passed explicitly.
    class _SwappedHeaders(EmailMessage):
        def __setitem__(self, name: str, val: Any) -> None:
            if name.lower() in ("from", "to"):
                val = "another@partner.example"
            super().__setitem__(name, val)

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.EmailMessage", _SwappedHeaders)
    _send_to(wire.port, "engine@hospital.example", ["ops@hospital.example"])
    assert wire.mail_lines == [b"mail from:<engine@hospital.example>"]
    assert wire.rcpt_lines == [b"rcpt to:<ops@hospital.example>"]


@pytest.mark.parametrize("field, value", _REFUSED_ADDRESSES, ids=_REFUSED_ADDRESS_IDS)
def test_alert_send_refuses_an_address_that_is_not_one_plain_mailbox_before_any_connection(
    wire: _WireCapture, field: str, value: str
) -> None:
    # The chokepoint every caller passes: a rule's override and a per-user notice address too.
    sender = value if field == "sender" else "engine@hospital.example"
    recipients = [value] if field == "recipients" else ["ops@hospital.example"]
    with pytest.raises(ValueError, match="sender" if field == "sender" else "recipient"):
        _send_to(wire.port, sender, recipients)
    assert wire.connections == 0
    assert wire.mail_lines == []


@pytest.mark.parametrize("field, value", _REFUSED_ADDRESSES, ids=_REFUSED_ADDRESS_IDS)
def test_email_transport_refuses_the_same_addresses_at_construction(field: str, value: str) -> None:
    sender = value if field == "sender" else "engine@hospital.example"
    recipients = [value] if field == "recipients" else ["ops@hospital.example"]
    with pytest.raises(ValueError, match="sender" if field == "sender" else "recipient"):
        EmailTransport(host="smtp.example", port=587, sender=sender, recipients=recipients)


@pytest.mark.parametrize("where", ["rule", "tier"])
def test_a_rule_recipient_override_is_checked_when_the_notifier_is_built(where: str) -> None:
    bad = [_ENCODED_LOCAL[0]]
    rule = (
        AlertRule(event_type="connection_stopped", recipients=bad)
        if where == "rule"
        else AlertRule(
            event_type="connection_stopped",
            escalate=[EscalationTier(after_count=2, recipients=bad)],
        )
    )
    alerts = AlertsSettings(
        email_smtp_host="smtp.example",
        email_from="engine@hospital.example",
        email_to=["ops@hospital.example"],
        rules=[rule],
    )
    expected = r"\[alerts\]\.rules\[0\]" + (r"\.escalate\[0\]" if where == "tier" else "")
    with pytest.raises(ValueError, match=expected + ": a recipient"):
        notifier_from_settings(alerts)


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
