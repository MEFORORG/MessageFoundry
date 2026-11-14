# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The real AlertSink notifier: webhook + email transports, background fan-out, dedup, PHI-safety."""

from __future__ import annotations

import asyncio
import ssl
import time
from typing import Any

import pytest

from messagefoundry.config.settings import AlertRule, AlertsSettings, load_settings
from messagefoundry.config.tls_policy import HopPosture
from messagefoundry.pipeline.alert_sinks import (
    _DRAIN_CANCEL_GRACE_SECONDS,
    EmailTransport,
    NotifierAlertSink,
    WebhookTransport,
    _shared_no_redirect_opener,
    notifier_from_settings,
)
from messagefoundry.pipeline.alerts import AlertSink, LoggingAlertSink

#: The [alerts] revocation guards count no posture as enforcing (ADR 0173 section 12), so an
#: off-box hop built here to test something else is built on a warn posture.
_NOT_ENFORCING = HopPosture(enforcing=False)


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


async def test_the_delivery_observer_hears_only_sends_that_returned() -> None:
    """Vault BACKLOG #3849, repair 3: the observer is told of a send that returned, and not of one
    that raised; an observer that raises is logged and the other transports still get the event."""
    good, bad, last = (
        _RecordingTransport("good"),
        _RecordingTransport("bad", fail=True),
        _RecordingTransport("last"),
    )
    heard: list[str] = []

    def observe(name: str, event: dict[str, Any]) -> None:
        heard.append(name)
        raise RuntimeError("observer fault")

    sink = NotifierAlertSink([good, bad, last])
    sink.set_delivery_observer(observe)
    sink.connection_stopped("OB_X", detail="boom")
    sink.connection_stopped("OB_Y", detail="boom")
    await _drain(sink)
    # The observer raised for `good`, and `last` still got each event. The sends run at once, so
    # the order across transports is not promised (BACKLOG #5907).
    assert sorted(heard) == ["good", "good", "last", "last"]
    assert len(last.events) == 2


class _HungTransport:
    """A transport whose send never returns until cancelled, recording the cancel."""

    def __init__(self, name: str) -> None:
        self.name = name
        self.entered = asyncio.Event()
        self.cancelled = False

    async def send(self, event: dict[str, Any], **_kw: Any) -> None:
        self.entered.set()
        try:
            await asyncio.Event().wait()
        except asyncio.CancelledError:
            self.cancelled = True
            raise


async def test_a_hung_transport_does_not_hold_the_alert_from_a_healthy_one() -> None:
    """BACKLOG #5907: each alert went to its transports in turn, so a hung first transport held the
    alert from every one after it. The alert being handled now reaches the healthy transport, and
    the observer hears that send, while the hung one is still waiting."""
    hung, good = _HungTransport("webhook"), _RecordingTransport("email")
    heard: list[str] = []
    delivered = asyncio.Event()

    def observe(name: str, _event: dict[str, Any]) -> None:
        heard.append(name)
        delivered.set()

    sink = NotifierAlertSink([hung, good])
    sink.set_delivery_observer(observe)
    sink.start()
    try:
        sink.connection_stopped("OB_X", detail="boom")
        await asyncio.wait_for(delivered.wait(), 5.0)
        assert hung.entered.is_set() and not hung.cancelled  # the control: still hung
        assert len(good.events) == 1
        assert heard == ["email"]  # only the send that returned
        # A close cut at its bound cancels the drain, and that cancel reaches the hung send.
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(sink.aclose(), 0.2)
        assert hung.cancelled
        assert sink._task is None
    finally:
        if sink._task is not None:
            sink._task.cancel()
            await asyncio.gather(sink._task, return_exceptions=True)


async def test_a_failing_transport_does_not_stop_a_slower_sibling() -> None:
    """A send that raises while a sibling's send is still running leaves that sibling to finish.
    The first send finishes only once the second has raised, so in-turn sends would never end."""
    raised = asyncio.Event()

    class _Slow(_RecordingTransport):
        async def send(self, event: dict[str, Any], **kw: Any) -> None:
            await raised.wait()
            await super().send(event, **kw)

    class _Bad(_RecordingTransport):
        async def send(self, event: dict[str, Any], **kw: Any) -> None:
            raised.set()
            raise RuntimeError("transport down")

    slow, bad = _Slow("slow"), _Bad("bad")
    heard: list[str] = []
    sink = NotifierAlertSink([slow, bad])
    sink.set_delivery_observer(lambda name, _event: heard.append(name))
    sink.connection_stopped("OB_X", detail="boom")
    await asyncio.wait_for(_drain(sink), 5.0)
    assert len(slow.events) == 1
    assert heard == ["slow"]


@pytest.mark.parametrize("how", ["raises", "cancels_own_task", "cancels_own_task_and_returns"])
async def test_a_send_cancelled_on_its_own_does_not_end_the_drain(
    caplog: pytest.LogCaptureFixture, how: str
) -> None:
    """A send that ends cancelled without the drain being cancelled leaves its sibling to finish,
    and the drain goes on to the next alert. The lost send is logged, not dropped in silence.
    A transport that cancels its own task with current_task().cancel() leaves the cancel count on
    that task, not on the drain; it was read as the drain's cancel, which ended the drain with
    nothing logged. ``cancels_own_task_and_returns`` returns before the cancel lands, so the send
    went out: the observer hears it, no loss is logged, and its task's late cancel is logged and
    ends nothing."""
    heard: list[str] = []
    returns = how == "cancels_own_task_and_returns"

    class _SelfCancelled(_RecordingTransport):
        async def send(self, event: dict[str, Any], **kw: Any) -> None:
            if how == "raises":
                raise asyncio.CancelledError
            task = asyncio.current_task()
            assert task is not None
            task.cancel()
            if how == "cancels_own_task":
                await asyncio.sleep(0)

    odd, good = _SelfCancelled("odd"), _RecordingTransport("good")
    sink = NotifierAlertSink([odd, good])
    sink.set_delivery_observer(lambda name, _event: heard.append(name))
    sink.connection_stopped("OB_X", detail="boom")
    sink.connection_stopped("OB_Y", detail="boom")
    await asyncio.wait_for(_drain(sink), 5.0)
    assert [e["connection"] for e in good.events] == ["OB_X", "OB_Y"]
    lost = [r for r in caplog.records if "alert transport odd was cancelled" in r.getMessage()]
    assert len(lost) == (0 if returns else 2), caplog.text
    late = [r for r in caplog.records if "transport odd ended cancelled" in r.getMessage()]
    assert len(late) == (2 if returns else 0), caplog.text
    assert sorted(heard) == (["good", "good", "odd", "odd"] if returns else ["good", "good"])


async def test_a_lost_send_is_logged_while_a_sibling_still_hangs(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A send that cancels its own task is logged as it ends, not once its siblings end: a hung
    sibling, or a drain cut while it hangs, does not hold back or drop the line."""

    class _CancelsItself(_RecordingTransport):
        async def send(self, event: dict[str, Any], **kw: Any) -> None:
            task = asyncio.current_task()
            assert task is not None
            task.cancel()
            await asyncio.sleep(0)

    hung = _HungTransport("webhook")
    sink = NotifierAlertSink([_CancelsItself("email"), hung])
    sink.start()
    try:
        sink.connection_stopped("OB_X", detail="boom")
        await asyncio.wait_for(hung.entered.wait(), 5.0)
        for _ in range(3):
            await asyncio.sleep(0)
        assert "alert transport email was cancelled" in caplog.text
        assert not hung.cancelled  # the control: the sibling is still hung
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(sink.aclose(), 0.2)
        assert hung.cancelled
        assert caplog.text.count("alert transport email was cancelled") == 1
    finally:
        if sink._task is not None:
            sink._task.cancel()
            await asyncio.gather(sink._task, return_exceptions=True)


async def test_a_cut_drain_waits_for_every_send_to_finish_its_cancel_cleanup() -> None:
    """A drain cancelled while two sends wait ends only once both sends' tasks have ended, where
    each ends inside the grace. One send's cancel ends at once and the other's async cleanup
    awaits; the drain used to end with the first, leaving the second's cleanup running after
    aclose() returned."""
    cleanup_done = asyncio.Event()
    quick_ended_first: list[bool] = []

    class _SlowCleanup(_HungTransport):
        async def send(self, event: dict[str, Any], **kw: Any) -> None:
            try:
                await super().send(event, **kw)
            except asyncio.CancelledError:
                for _ in range(3):  # an async cleanup that ends well inside the grace
                    await asyncio.sleep(0)
                quick_ended_first.append(quick.cancelled)
                cleanup_done.set()
                raise

    slow, quick = _SlowCleanup("email"), _HungTransport("webhook")
    sink = NotifierAlertSink([slow, quick])
    sink.start()
    try:
        sink.connection_stopped("OB_X", detail="boom")
        await asyncio.wait_for(slow.entered.wait(), 5.0)
        await asyncio.wait_for(quick.entered.wait(), 5.0)
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(sink.aclose(), 0.2)
        # The control: the quick send's cancel had ended before the slow cleanup finished.
        assert quick_ended_first == [True]
        assert cleanup_done.is_set()
        assert sink._task is None
    finally:
        if sink._task is not None:
            sink._task.cancel()
            await asyncio.gather(sink._task, return_exceptions=True)


async def test_a_send_that_swallows_the_cancel_does_not_hold_a_cut_close(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A drain cancelled while a send swallows every cancel and goes on waiting ends within the
    grace, not when that send ends: the send held aclose() past its caller's bound, so a probe
    returned after 1.22 s against a 0.2 s bound. The send left past the grace is logged as a count,
    with no alert content."""
    release = asyncio.Event()
    swallowed: list[bool] = []

    class _Swallows(_HungTransport):
        async def send(self, event: dict[str, Any], **kw: Any) -> None:
            self.entered.set()
            while not release.is_set():
                try:
                    await release.wait()
                except asyncio.CancelledError:
                    swallowed.append(True)

    stubborn = _Swallows("webhook")
    sink = NotifierAlertSink([stubborn])
    sink.start()
    try:
        sink.connection_stopped("OB_SECRETNAME", detail="boom")
        await asyncio.wait_for(stubborn.entered.wait(), 5.0)
        bound = 0.2
        started = time.monotonic()
        with pytest.raises(TimeoutError):
            await asyncio.wait_for(sink.aclose(), bound)
        elapsed = time.monotonic() - started
        assert swallowed  # the control: the send did swallow the cancel
        assert sink._left_sends and not any(t.done() for t in sink._left_sends)  # and still runs
        # The bound and one grace, with slack for a loaded runner, under the 1.22 s measured.
        assert elapsed < bound + _DRAIN_CANCEL_GRACE_SECONDS + 0.5, elapsed
        assert sink._task is None
        left = [r for r in caplog.records if "alert send task(s) still running" in r.getMessage()]
        assert left and left[0].levelname == "WARNING", caplog.text
        assert "1 alert send task(s)" in left[0].getMessage()
        assert all("OB_SECRETNAME" not in r.getMessage() for r in left)
    finally:
        release.set()
        await asyncio.sleep(0.05)
        if sink._task is not None:
            sink._task.cancel()
            await asyncio.gather(sink._task, return_exceptions=True)


async def test_a_repeat_drain_cancel_reaches_a_send_in_its_cancel_cleanup(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A second cancel of the drain, during the grace, reaches a send whose cleanup of the first
    cancel is still waiting, so that cleanup is cut rather than left running past the grace."""
    seen: list[int] = []

    class _LongCleanup(_HungTransport):
        async def send(self, event: dict[str, Any], **kw: Any) -> None:
            try:
                await super().send(event, **kw)
            except asyncio.CancelledError:
                seen.append(1)
                try:
                    await asyncio.sleep(5)
                except asyncio.CancelledError:
                    seen.append(2)
                    raise

    slow = _LongCleanup("email")
    sink = NotifierAlertSink([slow])
    sink.start()
    drain = sink._task
    assert drain is not None
    sink.connection_stopped("OB_X", detail="boom")
    await asyncio.wait_for(slow.entered.wait(), 5.0)
    try:
        drain.cancel()
        for _ in range(3):
            await asyncio.sleep(0)
        assert seen == [1]  # the control: the first cancel reached the send, and it is cleaning up
        drain.cancel()
        await asyncio.wait_for(asyncio.gather(drain, return_exceptions=True), 5.0)
        assert drain.cancelled()
        assert seen == [1, 2]
        assert "alert send task(s) still running" not in caplog.text
        assert not sink._left_sends
    finally:
        drain.cancel()
        await asyncio.gather(drain, *sink._left_sends, return_exceptions=True)


def test_the_drain_grace_nests_inside_the_teardown_cut_grace() -> None:
    """A close the API teardown cuts gets _CUT_GRACE_SECONDS to end, so the drain's own grace for
    its sends must be shorter, or the teardown leaves the close running and its line is lost."""
    from messagefoundry.api import app

    assert _DRAIN_CANCEL_GRACE_SECONDS < app._CUT_GRACE_SECONDS


async def test_realert_throttle_suppresses_repeats() -> None:
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t], realert_seconds=10_000.0)
    sink.queue_buildup("OB_X", depth=1, oldest_age_seconds=1.0)
    sink.queue_buildup("OB_X", depth=2, oldest_age_seconds=2.0)  # throttled (same event/connection)
    sink.queue_buildup("OB_Y", depth=1, oldest_age_seconds=1.0)  # different connection → allowed
    await _drain(sink)
    keys = [(e["connection"], e["depth"]) for e in t.events]
    assert keys == [("OB_X", 1), ("OB_Y", 1)]


def test_no_sink_carries_the_retired_bootstrap_admin_expiring_event() -> None:
    # ADR 0183 Amendment A, Wave 3 (BACKLOG #1136): the default account and its expiry reminder are
    # gone, so the protocol and both sinks drop the method with them.
    for sink_type in (AlertSink, LoggingAlertSink, NotifierAlertSink):
        assert not hasattr(sink_type, "bootstrap_admin_expiring"), sink_type.__name__


async def test_initial_credential_expiring_emits_phi_free_keyed_on_the_holder() -> None:
    # BACKLOG #1141 (ASVS 6.4.5): the holder's username stands in for "connection", so the throttle
    # and the alert instance key per account. The payload is the deadline and the hours only.
    t = _RecordingTransport("t")
    sink = NotifierAlertSink([t])
    sink.initial_credential_expiring(
        "user:alice", expires_at="2026-07-27T12:00:00Z", hours_remaining=5
    )
    await _drain(sink)
    assert len(t.events) == 1
    ev = t.events[0]
    assert ev["type"] == "initial_credential_expiring"
    assert ev["connection"] == "user:alice"
    assert ev["expires_at"] == "2026-07-27T12:00:00Z"
    assert ev["hours_remaining"] == 5
    assert "2026-07-27T12:00:00Z" in ev["reason"]  # the durable alert row carries the deadline
    assert not any(k in ev for k in ("password", "secret", "token"))


def test_initial_credential_expiring_logging_sink_states_holder_and_deadline(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # The LoggingAlertSink fallback is what an instance with no [alerts] notifier gets.
    import logging

    with caplog.at_level(logging.WARNING):
        LoggingAlertSink().initial_credential_expiring(
            "alice", expires_at="2026-07-27T12:00:00Z", hours_remaining=5
        )
    assert "initial_credential_expiring" in caplog.text
    assert "'alice'" in caplog.text
    assert "2026-07-27T12:00:00Z" in caplog.text
    assert "5 hour" in caplog.text


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

        def read(self, amt: int = -1) -> bytes:
            return b"" if amt < 0 else (b"")[:amt]

    def fake_open(req: Any, data: Any = None, timeout: float | None = None) -> _Resp:
        captured["url"] = req.full_url
        captured["body"] = req.data
        captured["method"] = req.get_method()
        captured["ctype"] = req.headers.get("Content-type")
        return _Resp()

    # The transport now sends via the shared no-redirect opener (WP-7a, ASVS 15.3.2), not
    # urllib.request.urlopen, so patch the opener's open().
    monkeypatch.setattr(_shared_no_redirect_opener(), "open", fake_open)
    t = WebhookTransport("https://hooks.example/x", timeout=5.0, posture=_NOT_ENFORCING)
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

        def starttls(self, context: ssl.SSLContext | None = None) -> None:
            sent["tls"] = True
            # #323 layer 3: RECORD the context. This fake accepted the kwarg from PR #132 onward but
            # threw it away, so `sent["tls"] is True` below stayed green for the entire period the hop
            # was accepting any certificate. "STARTTLS was issued" is not a security assertion.
            sent["context"] = context

        # BACKLOG #1171: production drives auth() directly, never login() -- login() tries
        # CRAM-MD5 first, an HMAC over MD5. CRAM-MD5 IS ADVERTISED HERE ON PURPOSE so a
        # regression back to login() would pick it and be visible.
        esmtp_features = {"auth": "CRAM-MD5 PLAIN LOGIN"}
        user = ""
        password = ""

        def ehlo_or_helo_if_needed(self) -> None:
            return None

        def has_extn(self, name: str) -> bool:
            return name.lower() == "auth"

        def auth(
            self, mechanism: str, authobject: Any, *, initial_response_ok: bool = True
        ) -> None:
            sent["auth_mechanism"] = mechanism
            sent["login"] = (self.user, self.password)

        def auth_plain(self, challenge: bytes | None = None) -> str:
            return ""

        def auth_login(self, challenge: bytes | None = None) -> str:
            return ""

        def send_message(self, msg: Any, **envelope: Any) -> None:
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
        posture=_NOT_ENFORCING,
    )
    asyncio.run(t.send({"type": "connection_stopped", "connection": "OB_X", "detail": "boom"}))
    assert sent["host"] == "smtp.example"
    assert sent["tls"] is True
    # #323 layer 3: the hop must AUTHENTICATE the relay, not merely encrypt to it. Without a context
    # smtplib falls back to ssl._create_stdlib_context, which IS _create_unverified_context
    # (CERT_NONE / check_hostname=False) — so these two lines are the whole point of the fix.
    assert sent["context"] is not None
    assert sent["context"].verify_mode is ssl.CERT_REQUIRED
    assert sent["context"].check_hostname is True
    assert sent["login"] == ("mf", "secret")
    assert "OB_X" in sent["subject"]
    assert sent["to"] == "ops@example, oncall@example"


def test_email_transport_rejects_host_outside_allowlist() -> None:
    # WP-11c: an SMTP host not on [alerts].smtp_allowed_hosts is refused *before* connecting (egress
    # control, parity with the webhook). The check fires first, so no SMTP fake is needed. Since
    # BACKLOG #5088 the build refuses it too, a tightening: it used to build and fail every send.
    with pytest.raises(ValueError, match="not in the configured allowlist"):
        EmailTransport(
            host="smtp.evil.example",
            port=587,
            sender="mf@example",
            recipients=["ops@example"],
            allowed_hosts=("smtp.corp.example",),
        )
    t = EmailTransport(
        host="smtp.corp.example", port=587, sender="mf@example", recipients=["ops@example"]
    )
    t.allowed_hosts = ("smtp.corp.example",)
    t.host = "smtp.evil.example"  # the send's own check, on a transport the build admitted
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
        ),
        posture=_NOT_ENFORCING,
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
    assert (
        WebhookTransport("https://hooks.example/x", timeout=5.0, posture=_NOT_ENFORCING).name
        == "webhook"
    )
