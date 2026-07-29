# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The real AlertSink notifier: webhook + email transports, background fan-out, dedup, PHI-safety."""

from __future__ import annotations

import asyncio
import time
from typing import Any

import pytest

from messagefoundry.config.settings import AlertRule, AlertsSettings, load_settings
from messagefoundry.pipeline.alert_sinks import (
    EmailTransport,
    NotifierAlertSink,
    WebhookTransport,
    notifier_from_settings,
)
from messagefoundry.pipeline.alerts import LoggingAlertSink


class _RecordingTransport:
    """Test transport that records the events it's handed (and can be told to fail)."""

    def __init__(self, name: str, *, fail: bool = False) -> None:
        self.name = name
        self.fail = fail
        self.events: list[dict[str, Any]] = []

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
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


async def test_bootstrap_admin_expiring_emits_phi_free() -> None:
    # ASVS 6.4.5 arm 2: the reminder rides the standard fan-out; its payload is the ISO deadline + whole
    # hours remaining only — never the password or any secret.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t])
    sink.bootstrap_admin_expiring(
        "bootstrap-admin", expires_at="2026-07-27T12:00:00+00:00", hours_remaining=24
    )
    await _drain(sink)
    assert len(t.events) == 1
    ev = t.events[0]
    assert ev["type"] == "bootstrap_admin_expiring"
    assert ev["connection"] == "bootstrap-admin"
    assert ev["expires_at"] == "2026-07-27T12:00:00+00:00"
    assert ev["hours_remaining"] == 24
    # no credential material ever rides the payload
    assert not any(k in ev for k in ("password", "secret", "token"))


def test_bootstrap_admin_expiring_logging_sink_states_deadline_not_password(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The fallback LoggingAlertSink surfaces the deadline + hours at WARNING (so an operator sees it with
    # no notifier wired) and never a secret — there is no secret in the signature to leak.
    import logging

    with caplog.at_level(logging.WARNING):
        LoggingAlertSink().bootstrap_admin_expiring(
            "bootstrap-admin", expires_at="2026-07-27T12:00:00+00:00", hours_remaining=24
        )
    assert "bootstrap_admin_expiring" in caplog.text
    assert "2026-07-27T12:00:00+00:00" in caplog.text
    assert "24 hour" in caplog.text


async def test_suspend_gate_mutes_notification() -> None:
    # #143: a suspended (type, connection) is muted at the notification enqueue while the window is
    # active; a different, un-suspended key still delivers. NOTIFICATION-only.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t], realert_seconds=0.0)
    sink.suspend("connection_stopped", "OB_X", until=time.time() + 1000.0)
    sink.connection_stopped("OB_X", detail="boom")  # muted for the window
    sink.connection_stopped("OB_Y", detail="boom")  # not suspended → delivered
    await _drain(sink)
    assert [e["connection"] for e in t.events] == ["OB_Y"]


async def test_resume_re_enables_notification() -> None:
    # #143: resume clears the window so a subsequent fire notifies again.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t], realert_seconds=0.0)
    sink.suspend("connection_stopped", "OB_X", until=time.time() + 1000.0)
    sink.connection_stopped("OB_X", detail="boom")  # muted
    sink.resume("connection_stopped", "OB_X")
    sink.connection_stopped("OB_X", detail="boom")  # resumed → delivered
    await _drain(sink)
    assert [e["connection"] for e in t.events] == ["OB_X"]


async def test_suspend_window_expiry_notifies_without_a_timer() -> None:
    # #143: an already-elapsed window (until in the past) falls through and notifies — expiry needs no
    # timer/sweep — and the stale cache entry is dropped.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t], realert_seconds=0.0)
    sink.suspend("connection_stopped", "OB_X", until=time.time() - 1.0)  # already expired
    sink.connection_stopped("OB_X", detail="boom")
    await _drain(sink)
    assert [e["connection"] for e in t.events] == ["OB_X"]
    assert "connection_stopped:OB_X" not in sink._suspended


async def test_per_rule_mute_suppresses_notification() -> None:
    # #143: a rule with mute=True suppresses the notification (like transports=[]) for matching events.
    t = _RecordingTransport("t")
    rule = AlertRule(event_type="connection_stopped", connection="*", mute=True)
    sink = NotifierAlertSink([t], rules=[rule])
    sink.connection_stopped("OB_X", detail="boom")  # muted by the rule
    sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)  # unmatched rule → delivered
    await _drain(sink)
    assert [e["type"] for e in t.events] == ["queue_buildup"]


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
        def __enter__(self) -> _Resp:
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

        def __enter__(self) -> _FakeSMTP:
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


def test_webhook_url_length_is_bounded_at_construction() -> None:
    """ASVS 4.2.5. Construction-only is sufficient and not a shortcut: the URL is operator config and
    the sole header is a fixed Content-Type, so nothing is added between construction and the wire.

    Mutation: delete the `enforce_outbound_length_limits` call in `WebhookTransport.__init__`. Red:
    DID NOT RAISE."""
    with pytest.raises(ValueError, match="over the 8192-char limit"):
        WebhookTransport("https://hooks.example/x?q=" + "a" * 9000, timeout=5.0)


def test_webhook_ordinary_url_still_constructs() -> None:
    """Byte-identity control. Mutation: drop MAX_OUTBOUND_URL_LEN to 8 -> this reds."""
    assert WebhookTransport("https://hooks.example/x", timeout=5.0).name == "webhook"
