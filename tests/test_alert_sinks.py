# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The real AlertSink notifier: webhook + email transports, background fan-out, dedup, PHI-safety."""

from __future__ import annotations

import asyncio
from typing import Any

import pytest

from messagefoundry.config.settings import AlertsSettings, load_settings
from messagefoundry.pipeline.alert_sinks import (
    EmailTransport,
    NotifierAlertSink,
    WebhookTransport,
    notifier_from_settings,
)


class _RecordingTransport:
    """Test transport that records the events it's handed (and can be told to fail)."""

    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any]) -> None:
        if self.fail:
            raise RuntimeError("transport down")
        self.events.append(event)


async def _drain(sink: NotifierAlertSink) -> None:
    """Start, let the dispatch task run, then close (which drains the queue)."""
    sink.start()
    await asyncio.sleep(0)  # let the dispatch task pick up
    await sink.aclose()


async def test_notifier_fans_out_to_every_transport() -> None:
    a, b = _RecordingTransport("a"), _RecordingTransport("b")
    sink = NotifierAlertSink([a, b])
    sink.connection_stopped("OB_ACME_ADT", detail="ValueError delivering abc123")
    sink.queue_buildup("OB_ACME_ORU", depth=42, oldest_age_seconds=600.5)
    await _drain(sink)
    assert [e["type"] for e in a.events] == ["connection_stopped", "queue_buildup"]
    assert a.events == b.events  # both transports saw the same two events
    assert a.events[1]["depth"] == 42 and a.events[1]["connection"] == "OB_ACME_ORU"


async def test_one_failing_transport_does_not_starve_the_others() -> None:
    bad, good = _RecordingTransport("bad", fail=True), _RecordingTransport("good")
    sink = NotifierAlertSink([bad, good])
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert len(good.events) == 1  # delivered despite the sibling transport raising


async def test_realert_throttle_suppresses_repeats() -> None:
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t], realert_seconds=10_000.0)
    sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)
    sink.queue_buildup("OB_X", depth=2, oldest_age_seconds=2.0)  # throttled (same event/connection)
    sink.queue_buildup("OB_Y", depth=1, oldest_age_seconds=1.0)  # different connection → allowed
    await _drain(sink)
    keys = [(e["connection"], e["depth"]) for e in t.events]
    assert keys == [("OB_X", 1), ("OB_Y", 1)]


async def test_events_carry_no_message_body_only_queue_shape() -> None:
    # PHI-safety: the payload is name + queue shape + a non-PHI detail string — never a message body.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t])
    sink.connection_stopped("OB_X", detail="ValueError delivering 9f3c")
    sink.queue_buildup("OB_X", depth=5, oldest_age_seconds=12.0)
    await _drain(sink)
    for event in t.events:
        assert set(event) <= {
            "type",
            "connection",
            "detail",
            "depth",
            "oldest_age_seconds",
            "ts",
            "severity",  # non-PHI rule outcome (info/warning/critical)
        }


async def test_notifier_integrity_drift_fans_out_phi_free() -> None:
    # #54: the dedicated integrity_drift channel emits a fan-out event carrying only a label, a
    # PHI-free reason string, and the drifted-module count — never any file content.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t])
    sink.integrity_drift("engine-integrity", reason="3 module(s) drifted", drift_count=3)
    await _drain(sink)
    assert len(t.events) == 1
    ev = t.events[0]
    assert ev["type"] == "integrity_drift"
    assert ev["connection"] == "engine-integrity"
    assert ev["reason"] == "3 module(s) drifted"
    assert ev["drift_count"] == 3
    assert set(ev) <= {"type", "connection", "reason", "drift_count", "ts", "severity"}


def test_logging_sink_integrity_drift(caplog: pytest.LogCaptureFixture) -> None:
    # The default LoggingAlertSink logs the tamper signal at WARNING (no file content — name + count).
    from messagefoundry.pipeline.alerts import LoggingAlertSink

    with caplog.at_level("WARNING"):
        LoggingAlertSink().integrity_drift(
            "engine-integrity", reason="2 module(s) drifted", drift_count=2
        )
    assert any("integrity_drift" in r.getMessage() for r in caplog.records)


def test_webhook_transport_posts_json(monkeypatch: pytest.MonkeyPatch) -> None:
    captured: dict[str, Any] = {}

    class _Resp:
        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def read(self) -> bytes:
            return b""

    def fake_open(req: Any, data: Any = None, timeout: float | None = None) -> _Resp:
        captured["url"] = req.full_url
        captured["body"] = req.data
        captured["method"] = req.get_method()
        captured["ctype"] = req.headers.get("Content-type")
        return _Resp()

    # The transport now sends via the shared no-redirect opener (WP-7a, ASVS 15.3.2), not
    # urllib.request.urlopen, so patch the opener's open().
    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks._NO_REDIRECT_OPENER.open", fake_open)
    t = WebhookTransport("https://hooks.example/x", timeout=5.0)
    asyncio.run(t.send({"type": "queue_buildup", "connection": "OB_X", "depth": 3}))
    assert captured["url"] == "https://hooks.example/x"
    assert captured["method"] == "POST"
    assert captured["ctype"] == "application/json"
    assert b'"connection": "OB_X"' in captured["body"]


def test_email_transport_sends_via_smtp(monkeypatch: pytest.MonkeyPatch) -> None:
    sent: dict[str, Any] = {}

    class _FakeSMTP:
        def __init__(self, host: str, port: int, timeout: float | None = None) -> None:
            sent["host"] = host
            sent["port"] = port

        def __enter__(self) -> "_FakeSMTP":
            return self

        def __exit__(self, *a: object) -> None:
            return None

        def starttls(self) -> None:
            sent["tls"] = True

        def login(self, user: str, password: str) -> None:
            sent["login"] = (user, password)

        def send_message(self, msg: Any) -> None:
            sent["subject"] = msg["Subject"]
            sent["to"] = msg["To"]
            sent["body"] = msg.get_content()

    monkeypatch.setattr("messagefoundry.pipeline.alert_sinks.smtplib.SMTP", _FakeSMTP)
    t = EmailTransport(
        host="smtp.example",
        port=587,
        sender="mf@example",
        recipients=["ops@example", "oncall@example"],
        username="mf",
        password="secret",
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    assert sent["host"] == "smtp.example"
    assert sent["tls"] is True
    assert sent["login"] == ("mf", "secret")
    assert "OB_X" in sent["subject"]
    assert sent["to"] == "ops@example, oncall@example"


def test_email_transport_rejects_host_outside_allowlist() -> None:
    # WP-11c: an SMTP host not on [alerts].smtp_allowed_hosts is refused *before* connecting (egress
    # control, parity with the webhook). The check fires first, so no SMTP fake is needed.
    t = EmailTransport(
        host="smtp.evil.example",
        port=587,
        sender="mf@example",
        recipients=["ops@example"],
        allowed_hosts=("smtp.corp.example",),
    )
    with pytest.raises(ValueError, match="not in the configured allowlist"):
        t._send({"type": "connection_stopped", "connection": "OB_X", "detail": "x"})


# --- settings → notifier construction ----------------------------------------


def test_notifier_none_when_nothing_configured() -> None:
    assert notifier_from_settings(AlertsSettings()) is None  # disabled by default


def test_notifier_builds_configured_transports() -> None:
    sink = notifier_from_settings(
        AlertsSettings(
            webhook_url="https://hooks.example/x",
            email_smtp_host="smtp.example",
            email_from="mf@example",
            email_to=["ops@example"],
        )
    )
    assert sink is not None
    assert sorted(t.name for t in sink._transports) == ["email", "webhook"]


def test_notifier_email_needs_host_from_and_to() -> None:
    # Missing recipients → email transport not built (and nothing else configured → None).
    assert (
        notifier_from_settings(
            AlertsSettings(email_smtp_host="smtp.example", email_from="mf@example")
        )
        is None
    )


def test_alerts_email_recipients_split_from_env_string() -> None:
    # MEFOR_ALERTS_EMAIL_TO arrives as one comma-separated string; it must parse to a list.
    settings = load_settings(environ={"MEFOR_ALERTS_EMAIL_TO": "ops@example, oncall@example"})
    assert settings.alerts.email_to == ["ops@example", "oncall@example"]


def test_alerts_password_via_env(monkeypatch: pytest.MonkeyPatch) -> None:
    settings = load_settings(environ={"MEFOR_ALERTS_EMAIL_PASSWORD": "s3cret"})
    assert settings.alerts.email_password == "s3cret"
