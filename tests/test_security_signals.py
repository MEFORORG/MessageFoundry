# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The security-signal rule layer over the audit stream (vault BACKLOG #2613).

Each detector has a test that fires it and a control that does not. The tap is exercised through a
real SQLite store, so the rows reach the detector the way production rows do: after the commit,
through the off-box tee."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import logging
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry.api import app as app_module
from messagefoundry.auth.audit_visibility import DIRECTORY_LOCKED_REFUSAL_DETAIL
from messagefoundry.auth.service import AuthService
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    _SECURITY_SIGNAL_COUNTS,
    AlertsSettings,
    AuthSettings,
    ClusterSettings,
    _security_signal_loosenings,
)
from messagefoundry.connection_names import inbound_record_name
from messagefoundry.pipeline.alert_sinks import _AUTO_RESOLVE, NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.security_signals import (
    _DIRECTORY_LOCKED_DETAIL,
    MAX_SUBJECT_ALERTS,
    MAX_SUBJECTS,
    SECURITY_SIGNAL_TYPES,
    SecuritySignalDetector,
    SecuritySignalThresholds,
    install_security_signals,
)
from messagefoundry.store import audit_tee
from messagefoundry.store.store import MessageStore
from messagefoundry.transports import admission
from messagefoundry.transports.admission import (
    ListenerAdmission,
    add_refusal_observer,
    remove_refusal_observer,
)
from messagefoundry.transports.dicom import DicomScpSource


class _Sink(LoggingAlertSink):
    """Records each security signal as ``(signal, subject, count, detail)``."""

    def __init__(self) -> None:
        self.signals: list[tuple[str, str, int, str]] = []

    def security_signal(self, name: str, *, signal: str, count: int, detail: str) -> None:
        self.signals.append((signal, name, count, detail))


class _Clock:
    def __init__(self) -> None:
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


def _thresholds(**overrides: Any) -> SecuritySignalThresholds:
    return dataclasses.replace(
        SecuritySignalThresholds.from_settings(AlertsSettings()), **overrides
    )


def _detector(**thresholds: Any) -> tuple[SecuritySignalDetector, _Sink, _Clock]:
    sink, clock = _Sink(), _Clock()
    return (
        SecuritySignalDetector(sink, _thresholds(**thresholds), clock=clock),
        sink,
        clock,
    )


def _rows(
    det: SecuritySignalDetector,
    action: str,
    n: int,
    *,
    actor: str | None = "alice",
    client: str | None = "10.1.2.3",
    detail: str | None = None,
) -> None:
    for _ in range(n):
        det.observe(action, actor, None, client, detail)


# --- the six detectors ----------------------------------------------------------------------------


def test_signin_failure_burst_fires_per_address_and_never_names_the_typed_username() -> None:
    det, sink, _ = _detector(signin_failures=5)
    _rows(det, "auth.login_failed", 5, actor="hunter2-typed-in-the-name-box")
    ((signal, subject, count, detail),) = sink.signals
    assert (signal, subject, count) == ("signin_failure_burst", "signin:10.1.2.3", 5)
    assert "hunter2" not in subject and "hunter2" not in detail


def test_signin_failures_spread_across_addresses_do_not_fire() -> None:
    det, sink, _ = _detector(signin_failures=5)
    for i in range(20):
        det.observe("auth.login_failed", "alice", None, f"10.0.0.{i}", None)
    assert sink.signals == []


def test_signin_failures_spread_over_time_do_not_fire() -> None:
    det, sink, clock = _detector(signin_failures=5, window_seconds=60)
    for _ in range(12):
        _rows(det, "auth.login_failed", 1)
        clock.now += 15  # four per window, never five
    assert sink.signals == []


def test_access_denied_burst_counts_all_three_refusals_for_one_account() -> None:
    det, sink, _ = _detector(denials=6)
    for action in ("auth.permission_denied", "auth.channel_denied", "auth.mfa_denied") * 2:
        det.observe(action, "mallory", None, "10.9.9.9", json.dumps({"path": "/x"}))
    assert [(s, n, c) for s, n, c, _d in sink.signals] == [
        ("access_denied_burst", "account:mallory", 6)
    ]


def test_denials_below_the_threshold_do_not_fire() -> None:
    det, sink, _ = _detector(denials=6)
    _rows(det, "auth.permission_denied", 5, actor="mallory")
    _rows(det, "auth.permission_denied", 5, actor="bob")
    assert sink.signals == []


def test_body_view_burst_fires_and_restarts_its_count() -> None:
    det, sink, _ = _detector(body_views=4)
    _rows(det, "message_body_view", 4, detail=json.dumps({"message_id": "m-secret"}))
    _rows(det, "message_body_view", 3)
    ((signal, subject, count, detail),) = sink.signals
    assert (signal, subject, count) == ("body_view_burst", "account:alice", 4)
    assert "m-secret" not in detail  # never a message id
    _rows(det, "message_body_view", 1)
    assert len(sink.signals) == 2


def test_bulk_export_fires_on_one_large_export() -> None:
    det, sink, _ = _detector(export_messages=1000)
    det.observe("messages_export", "alice", None, None, json.dumps({"selected": 1000}))
    assert [(s, n, c) for s, n, c, _d in sink.signals] == [("bulk_export", "account:alice", 1000)]


def test_bulk_export_sums_one_accounts_exports_over_the_window() -> None:
    det, sink, clock = _detector(export_messages=1000, window_seconds=60)
    det.observe("messages_export", "alice", None, None, json.dumps({"selected": 999}))
    det.observe("messages_export", "bob", None, None, json.dumps({"selected": 999}))
    clock.now += 61
    det.observe("messages_export", "alice", None, None, json.dumps({"selected": 600}))
    assert sink.signals == []  # the controls: other accounts, and an export past the window
    det.observe("messages_export", "alice", None, None, json.dumps({"selected": 400}))
    assert [(s, n, c) for s, n, c, _d in sink.signals] == [("bulk_export", "account:alice", 1000)]


@pytest.mark.parametrize(
    ("action", "detail"),
    [
        ("message_body_view", json.dumps({"message_id": "m1"})),
        ("attachment_download", None),
        ("outbound.read", json.dumps({"message_id": "m1", "count": 2})),
        ("response.read", json.dumps({"message_id": "m1", "count": 1, "body": True})),
    ],
)
def test_every_stored_body_read_counts_toward_body_view_burst(
    action: str, detail: str | None
) -> None:
    det, sink, _ = _detector(body_views=3)
    _rows(det, action, 3, detail=detail)
    assert [s for s, _n, _c, _d in sink.signals] == ["body_view_burst"]


@pytest.mark.parametrize(
    ("action", "detail"),
    [
        ("outbound.read", json.dumps({"message_id": "m1", "count": 0})),
        ("response.read", json.dumps({"message_id": "m1", "count": 3, "body": False})),
        ("response.read", json.dumps({"message_id": "m1", "count": 0, "body": True})),
    ],
)
def test_a_read_that_returned_no_body_does_not_count(action: str, detail: str) -> None:
    det, sink, _ = _detector(body_views=3)
    _rows(det, action, 10, detail=detail)
    assert sink.signals == []


def test_the_withheld_directory_lock_refusal_is_not_counted() -> None:
    assert _DIRECTORY_LOCKED_DETAIL == DIRECTORY_LOCKED_REFUSAL_DETAIL
    det, sink, _ = _detector(signin_failures=3)
    _rows(det, "auth.login_failed", 10, detail=DIRECTORY_LOCKED_REFUSAL_DETAIL)
    assert sink.signals == []  # a lock refusal alone never trips it
    _rows(det, "auth.login_failed", 3, detail=json.dumps({"reason": "bad_credentials"}))
    assert [c for _s, _n, c, _d in sink.signals] == [3]


def test_a_spread_of_subjects_collapses_onto_one_shared_subject() -> None:
    det, sink, _ = _detector(signin_failures=2)
    for i in range(MAX_SUBJECT_ALERTS + 3):
        _rows(det, "auth.login_failed", 2, client=f"198.51.100.{i}")
    subjects = [n for _s, n, _c, _d in sink.signals]
    assert subjects[:MAX_SUBJECT_ALERTS] == [f"signin:198.51.100.{i}" for i in range(5)]
    assert subjects[MAX_SUBJECT_ALERTS:] == ["signin:*"] * 3


def test_one_subject_tripping_often_keeps_its_name_and_spends_no_one_elses() -> None:
    det, sink, _ = _detector(signin_failures=2)
    _rows(det, "auth.login_failed", 2 * (MAX_SUBJECT_ALERTS + 2), client="203.0.113.1")
    _rows(det, "auth.login_failed", 2, client="203.0.113.2")
    subjects = [n for _s, n, _c, _d in sink.signals]
    assert set(subjects) == {"signin:203.0.113.1", "signin:203.0.113.2"}


def test_a_long_subject_is_cut_to_fit_the_alert_table() -> None:
    det, sink, _ = _detector(denials=1)
    _rows(det, "auth.permission_denied", 1, actor="u" * 300)
    ((_s, subject, _c, _d),) = sink.signals
    assert len(subject) <= 200 and subject.startswith("account:uuu")


@pytest.mark.parametrize("detail", [None, "not json", "[1]", json.dumps({"selected": "9999"})])
def test_bulk_export_ignores_a_detail_it_cannot_read(detail: str | None) -> None:
    det, sink, _ = _detector(export_messages=1)
    det.observe("messages_export", "alice", None, None, detail)
    assert sink.signals == []


def test_log_level_debug_fires_on_a_raise_to_debug_and_on_a_refused_one() -> None:
    det, sink, _ = _detector()
    det.observe(
        "logging_level_change", "op", None, None, json.dumps({"from": "INFO", "to": "INFO"})
    )
    det.observe(
        "logging_level_change_denied",
        "op",
        None,
        None,
        json.dumps({"from": "INFO", "requested": "WARNING", "reason": "production_instance"}),
    )
    assert sink.signals == []  # the controls: a level other than DEBUG
    det.observe(
        "logging_level_change", "op", None, None, json.dumps({"from": "INFO", "to": "DEBUG"})
    )
    det.observe(
        "logging_level_change_denied",
        "op",
        None,
        None,
        json.dumps({"from": "INFO", "requested": "debug", "reason": "production_instance"}),
    )
    assert [(s, n) for s, n, _c, _d in sink.signals] == [
        ("log_level_debug", "logging:debug"),
        ("log_level_debug", "logging:debug"),
    ]
    assert "raised to DEBUG by op" in sink.signals[0][3]
    assert "refused" in sink.signals[1][3]


@pytest.mark.parametrize("loosenings", [[], None])
def test_posture_loosened_does_not_fire_without_a_listed_loosening(loosenings: Any) -> None:
    det, sink, _ = _detector()
    det.observe("config_loaded", "system", None, None, json.dumps({"loosenings": loosenings}))
    assert sink.signals == []


def test_posture_loosened_fires_with_the_switch_names() -> None:
    det, sink, _ = _detector()
    det.observe(
        "config_loaded",
        "system",
        None,
        None,
        json.dumps({"loosenings": ["security.allow_x", "store.encryption_off"]}),
    )
    ((signal, subject, count, detail),) = sink.signals
    assert (signal, subject, count) == ("posture_loosened", "posture:start", 2)
    assert "security.allow_x, store.encryption_off" in detail


def test_a_zero_threshold_switches_a_detector_off() -> None:
    det, sink, _ = _detector(signin_failures=0, denials=0, body_views=0, export_messages=0)
    _rows(det, "auth.login_failed", 50)
    _rows(det, "auth.permission_denied", 50)
    _rows(det, "message_body_view", 500)
    det.observe("messages_export", "alice", None, None, json.dumps({"selected": 10**6}))
    assert sink.signals == []


def test_unwatched_actions_and_lock_rows_raise_nothing() -> None:
    det, sink, _ = _detector(signin_failures=1, denials=1)
    for action in (
        "auth.login_locked",
        "auth.directory_login_locked",
        "auth.account_locked",
        "auth.permission_granted",
    ):
        _rows(det, action, 5)
    assert sink.signals == []


def test_the_subject_table_is_bounded() -> None:
    det, sink, _ = _detector(signin_failures=2)
    for i in range(MAX_SUBJECTS + 10):
        det.observe("auth.login_failed", None, None, f"addr-{i}", None)
    assert len(det._signin._seen) == MAX_SUBJECTS
    assert sink.signals == []


def test_a_failing_sink_never_reaches_the_audit_writer() -> None:
    class _Broken(LoggingAlertSink):
        def security_signal(self, name: str, *, signal: str, count: int, detail: str) -> None:
            raise RuntimeError("sink down")

    det = SecuritySignalDetector(_Broken(), _thresholds(signin_failures=1))
    det.observe("auth.login_failed", None, None, "10.0.0.1", None)  # must not raise


# --- settings and sinks ---------------------------------------------------------------------------


def test_the_signal_types_are_routable_and_only_the_posture_one_resolves() -> None:
    assert SECURITY_SIGNAL_TYPES <= _ALERT_EVENT_TYPES
    assert not SECURITY_SIGNAL_TYPES & _ALERT_CONTROL_EVENT_TYPES
    assert not SECURITY_SIGNAL_TYPES & set(_AUTO_RESOLVE)
    assert SECURITY_SIGNAL_TYPES & set(_AUTO_RESOLVE.values()) == {"posture_loosened"}
    assert _AUTO_RESOLVE["posture_restored"] == "posture_loosened"
    assert "posture_restored" not in _ALERT_EVENT_TYPES  # an inverse pages nobody


def test_settings_defaults_and_bounds() -> None:
    s = AlertsSettings()
    assert s.security_signals is True
    t = SecuritySignalThresholds.from_settings(s)
    assert (
        t.window_seconds,
        t.signin_failures,
        t.denials,
        t.body_views,
        t.export_messages,
        t.peer_refusals,
        t.enabled,
    ) == (300.0, 20, 20, 100, 5000, 100, True)
    off = SecuritySignalThresholds.from_settings(AlertsSettings(security_signals=False))
    assert off.enabled is False
    with pytest.raises(ValidationError):
        AlertsSettings(security_window_seconds=0)
    with pytest.raises(ValidationError):
        AlertsSettings(security_window_seconds=float("inf"))
    with pytest.raises(ValidationError):
        AlertsSettings(security_denials=-1)


async def test_the_notifier_pages_a_signal_under_its_own_type_with_labels_only(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sent: list[dict[str, Any]] = []
    sink = NotifierAlertSink([], realert_seconds=300.0)

    def _capture(event: dict[str, Any], *, dropped: str | None) -> None:
        sent.append(dict(event))

    monkeypatch.setattr(sink, "_enqueue", _capture)
    sink.security_signal("account:alice", signal="bulk_export", count=1500, detail="one export")
    sink.security_signal("account:alice", signal="bulk_export", count=1500, detail="one export")
    assert len(sent) == 1  # the realert throttle collapses the repeat
    event = sent[0]
    assert (event["type"], event["connection"], event["count"], event["detail"]) == (
        "bulk_export",
        "account:alice",
        1500,
        "one export",
    )
    assert {k for k in event if not k.startswith("_")} == {
        "type",
        "connection",
        "count",
        "detail",
        "ts",
        "severity",
    }


# --- the tap: a real store, after the commit ------------------------------------------------------


async def test_rows_reach_the_detector_through_the_store_tee(tmp_path: Path) -> None:
    sink = _Sink()
    remove = install_security_signals(
        sink, _thresholds(signin_failures=3), asyncio.get_running_loop()
    )
    store = await MessageStore.open(str(tmp_path / "s.db"))
    try:
        for _ in range(3):
            await store.record_audit(
                "auth.login_failed", actor="whoever", detail="{}", client="192.0.2.7"
            )
        assert [(s, n) for s, n, _c, _d in sink.signals] == [
            ("signin_failure_burst", "signin:192.0.2.7")
        ]
        remove()
        for _ in range(3):
            await store.record_audit("auth.login_failed", detail="{}", client="192.0.2.7")
        assert len(sink.signals) == 1  # removed: the control
    finally:
        remove()  # idempotent
        await store.close()


async def test_a_marked_directory_lock_refusal_from_the_real_writer_is_not_counted(
    tmp_path: Path,
) -> None:
    """BACKLOG #3726: a directory lock refusal is written under its own action, which the sign-in
    detector does not read, even when the OIDC floor-exempt marker rides it. Counting it would show
    a lock to a reader without users:manage. The control: the same writer's ``disabled`` refusal,
    an ordinary ``auth.login_failed``, does count."""
    sink = _Sink()
    store = await MessageStore.open(str(tmp_path / "s.db"))
    remove = install_security_signals(
        sink, _thresholds(signin_failures=3), asyncio.get_running_loop()
    )
    try:
        service = AuthService(store, AuthSettings())
        marker = {"callback_floor_exempt_amr": ["wia"]}
        for _ in range(5):
            await service._refuse_directory_row("jdoe", "locked", client="192.0.2.9", extra=marker)
        assert sink.signals == []
        for _ in range(3):
            await service._refuse_directory_row(
                "jdoe", "disabled", client="192.0.2.9", extra=marker
            )
        assert [(s, n) for s, n, _c, _d in sink.signals] == [
            ("signin_failure_burst", "signin:192.0.2.9")
        ]
    finally:
        remove()
        await store.close()


async def test_a_row_teed_off_the_loop_thread_is_judged_on_the_loop() -> None:
    sink = _Sink()
    loop = asyncio.get_running_loop()
    remove = install_security_signals(sink, _thresholds(), loop)
    try:
        seen_on: list[int] = []
        original = sink.security_signal

        def _record(name: str, *, signal: str, count: int, detail: str) -> None:
            seen_on.append(threading.get_ident())
            original(name, signal=signal, count=count, detail=detail)

        sink.security_signal = _record  # type: ignore[method-assign]
        detail = json.dumps({"from": "INFO", "to": "DEBUG"})
        thread = threading.Thread(
            target=lambda: cast(Any, audit_tee).emit_audit_tee(
                action="logging_level_change",
                actor="op",
                channel_id=None,
                detail=detail,
                ts=0.0,
                row_id=1,
                seq=1,
                row_hash="0" * 64,
            )
        )
        thread.start()
        thread.join()
        assert sink.signals == []  # not judged on the writer's thread
        for _ in range(50):
            if sink.signals:
                break
            await asyncio.sleep(0.01)
        assert [s for s, _n, _c, _d in sink.signals] == ["log_level_debug"]
        assert seen_on == [threading.get_ident()]
    finally:
        remove()


def test_an_observer_fault_does_not_stop_the_next_observer(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # The once-per-process flag is restored afterwards, so no later test sees it already set.
    monkeypatch.setattr(audit_tee, "_OBSERVER_FAILURE_LOGGED", False)
    seen: list[str] = []

    def broken(*_args: Any) -> None:
        raise RuntimeError("boom")

    def good(action: str, *_rest: Any) -> None:
        seen.append(action)

    audit_tee.add_audit_observer(broken)
    audit_tee.add_audit_observer(good)
    try:
        audit_tee.emit_audit_tee(
            action="anything",
            actor=None,
            channel_id=None,
            detail=None,
            ts=0.0,
            row_id=1,
            seq=1,
            row_hash="0" * 64,
        )
    finally:
        audit_tee.remove_audit_observer(broken)
        audit_tee.remove_audit_observer(good)
    assert seen == ["anything"]


# --- refused peers: the one input that is not an audit row ----------------------------------------


class _Writer:
    """The one thing admission reads off a writer: the peer's address."""

    def __init__(self, host: str) -> None:
        self.host = host

    def get_extra_info(self, key: str) -> object:
        return (self.host, 50000) if key == "peername" else None


def _admission(**caps: Any) -> ListenerAdmission:
    settings: dict[str, Any] = {
        "max_connections": None,
        "max_connections_per_host": None,
        "source_ip_allowlist": None,
    }
    settings.update(caps)
    return ListenerAdmission(transport="MLLP", name="IB_ACME_ADT", **settings)


def _refuse(gate: ListenerAdmission, n: int, host: str = "203.0.113.9") -> None:
    for _ in range(n):
        assert gate.check(cast(Any, _Writer(host)), host) is not None


def test_peer_refused_burst_fires_per_listener_and_never_names_the_address() -> None:
    det, sink, _ = _detector(peer_refusals=4)
    for i in range(4):  # four addresses, one listener: a scan still trips it
        det.observe_refusal("IB_ACME_ADT")
        det.observe_refusal(f"IB_OTHER_{i}")
    ((signal, subject, count, detail),) = sink.signals
    assert (signal, subject, count) == ("peer_refused_burst", "inbound:IB_ACME_ADT", 4)
    assert "allowlist" in detail


def test_refusals_below_the_threshold_or_past_the_window_do_not_fire() -> None:
    det, sink, clock = _detector(peer_refusals=4, window_seconds=60)
    for _ in range(3):
        det.observe_refusal("IB_ACME_ADT")
    clock.now += 61
    for _ in range(3):
        det.observe_refusal("IB_ACME_ADT")
    assert sink.signals == []


def test_a_flood_raises_once_per_listener_per_window() -> None:
    det, sink, clock = _detector(peer_refusals=4, window_seconds=60)
    for _ in range(400):
        det.observe_refusal("IB_ACME_ADT")
    det.observe_refusal("IB_OTHER")  # the control: another listener still counts
    assert [n for _s, n, _c, _d in sink.signals] == ["inbound:IB_ACME_ADT"]
    clock.now += 61
    for _ in range(4):
        det.observe_refusal("IB_ACME_ADT")
    assert [n for _s, n, _c, _d in sink.signals] == ["inbound:IB_ACME_ADT"] * 2


def test_a_long_window_holds_a_listener_quiet_for_at_most_five_minutes() -> None:
    det, sink, clock = _detector(peer_refusals=2, window_seconds=86400)
    for _ in range(2):
        det.observe_refusal("IB_ACME_ADT")
    assert det.refusal_quiet("IB_ACME_ADT")
    clock.now += 301
    assert not det.refusal_quiet("IB_ACME_ADT")
    for _ in range(2):
        det.observe_refusal("IB_ACME_ADT")
    assert len(sink.signals) == 2


def test_a_refusal_alert_the_sink_refused_starts_no_quiet_period() -> None:
    class _Flaky(_Sink):
        def __init__(self) -> None:
            super().__init__()
            self.down = True

        def security_signal(self, name: str, *, signal: str, count: int, detail: str) -> None:
            if self.down:
                raise RuntimeError("sink down")
            super().security_signal(name, signal=signal, count=count, detail=detail)

    sink, clock = _Flaky(), _Clock()
    det = SecuritySignalDetector(sink, _thresholds(peer_refusals=2), clock=clock)
    for _ in range(2):
        det.observe_refusal("IB_ACME_ADT")
    assert not det.refusal_quiet("IB_ACME_ADT")  # nobody received it, so nothing is held back
    sink.down = False
    for _ in range(2):
        det.observe_refusal("IB_ACME_ADT")
    assert [n for _s, n, _c, _d in sink.signals] == ["inbound:IB_ACME_ADT"]
    # The control: the alert the sink took does start the quiet period.
    assert det.refusal_quiet("IB_ACME_ADT")


#: Planted in every failing sink's exception message, to prove the log never carries it.
_LEAK_TOKEN = "LEAK-7f3a"


class _Switchable(_Sink):
    """A sink whose calls raise while ``down`` holds; records what it took otherwise."""

    def __init__(self) -> None:
        super().__init__()
        self.down = True
        self.restored: list[str] = []

    def security_signal(self, name: str, *, signal: str, count: int, detail: str) -> None:
        if self.down:
            raise RuntimeError(f"{_LEAK_TOKEN} sink down for {name}")
        super().security_signal(name, signal=signal, count=count, detail=detail)

    def posture_restored(self, name: str) -> None:
        if self.down:
            raise RuntimeError(f"{_LEAK_TOKEN} sink down for {name}")
        self.restored.append(name)


def _failed_lines(caplog: pytest.LogCaptureFixture) -> list[str]:
    return [r.getMessage() for r in caplog.records if "could not be raised" in r.getMessage()]


def test_a_sink_that_keeps_failing_backs_off_and_counts_under_a_refusal_flood(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = _Switchable()
    det = SecuritySignalDetector(sink, _thresholds(peer_refusals=1), clock=_Clock())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.security_signals"):
        for _ in range(500):
            det.observe_refusal("IB_ACME_ADT")
        lines = _failed_lines(caplog)
        # The 1st, 2nd, 4th ... 256th failure, each with the run's count.
        assert len(lines) == 9 and lines[-1].endswith("(consecutive failures: 256)")
        # caplog.text is formatted with each record's exception text, so a sink message that
        # reached a record through exc_info would show here, token and subject both.
        assert "sink down" not in caplog.text and _LEAK_TOKEN not in caplog.text
        assert "IB_ACME_ADT" not in caplog.text
        sink.down = False
        det.observe_refusal("IB_ACME_ADT")
    assert any("recovered after 500 consecutive failures" in r.getMessage() for r in caplog.records)


def test_a_spread_of_failing_subjects_writes_a_bounded_number_of_lines(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = _Switchable()
    det = SecuritySignalDetector(sink, _thresholds(signin_failures=1), clock=_Clock())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.security_signals"):
        for i in range(1000):
            det.observe("auth.login_failed", None, None, f"2001:db8::{i:x}", None)
        signin = [line for line in _failed_lines(caplog) if "signin_failure_burst" in line]
        # One run for the event type: the 1st, 2nd, 4th ... 512th failure, not one per address.
        assert len(signin) == 10 and signin[-1].endswith("(consecutive failures: 512)")
        # The control: another event type in the middle of that run still logs its own line.
        det.observe("logging_level_change", "op", None, None, json.dumps({"to": "DEBUG"}))
    assert [line for line in _failed_lines(caplog) if "log_level_debug" in line] == [
        "security-signal alert log_level_debug could not be raised (consecutive failures: 1)"
    ]


def test_a_release_whose_resolve_failed_can_be_tried_again() -> None:
    sink = _Switchable()
    sink.down = False
    det = SecuritySignalDetector(sink, _thresholds(), clock=_Clock())
    _start(det, ["security.allow_x"])
    sink.down = True
    det.release()
    assert sink.restored == []
    sink.down = False
    det.release()  # the alert is still recorded as raised, so this resolves it
    assert sink.restored == ["posture:start"]
    det.release()  # the control: once resolved, nothing is left to resolve
    assert sink.restored == ["posture:start"]


def test_one_events_failing_run_does_not_silence_another_events_failure(
    caplog: pytest.LogCaptureFixture,
) -> None:
    sink = _Switchable()
    det = SecuritySignalDetector(sink, _thresholds(peer_refusals=1), clock=_Clock())
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.security_signals"):
        for _ in range(3):
            det.observe_refusal("IB_ACME_ADT")
        before = len(_failed_lines(caplog))
        _start(det, ["security.allow_x"])  # a different event fails inside the run
        det.release()
        lines = _failed_lines(caplog)[before:]
    assert [line.split(" could")[0] for line in lines] == [
        "security-signal alert posture_loosened",
        "security-signal alert posture_restored",
    ]
    # The control: the refusal key's third failure was held back by its own backoff.
    assert before == 2


def test_failed_raises_spend_no_named_slot() -> None:
    sink = _Switchable()
    det = SecuritySignalDetector(sink, _thresholds(peer_refusals=1), clock=_Clock())
    for i in range(MAX_SUBJECT_ALERTS + 2):
        det.observe_refusal(f"IB_{i}")
        det.observe_refusal(f"IB_{i}")  # a retry of the same failing subject
    sink.down = False
    det.observe_refusal("IB_NEW")
    assert [n for _s, n, _c, _d in sink.signals] == ["inbound:IB_NEW"]
    # The control: delivered raises do spend slots, so the sixth distinct one collapses.
    for i in range(MAX_SUBJECT_ALERTS):
        det.observe_refusal(f"IB_LATER_{i}")
    assert sink.signals[-1][1] == "inbound:*"


def test_the_refusal_sentence_states_the_quiet_period() -> None:
    det, sink, _ = _detector(peer_refusals=1, window_seconds=3600)
    det.observe_refusal("IB_ACME_ADT")
    assert "not counted for 300 s" in sink.signals[0][3]
    det, sink, _ = _detector(peer_refusals=1, window_seconds=60)
    det.observe_refusal("IB_ACME_ADT")
    assert "not counted for 60 s" in sink.signals[0][3]


def test_the_refusal_subject_is_spelled_as_an_inbound_record_name() -> None:
    det, sink, _ = _detector(peer_refusals=1)
    det.observe_refusal("IB_ACME_ADT")
    assert sink.signals[0][1] == inbound_record_name("IB_ACME_ADT")


def test_two_long_inbound_names_with_one_head_keep_two_subjects() -> None:
    det, sink, _ = _detector(peer_refusals=1)
    head = "IB_" + "X" * 240
    det.observe_refusal(head + "_A")
    det.observe_refusal(head + "_B")
    subjects = [n for _s, n, _c, _d in sink.signals]
    assert len(set(subjects)) == 2 and all(len(n) <= 200 for n in subjects)


def test_a_zero_peer_refusal_count_switches_that_detector_off() -> None:
    det, sink, _ = _detector(peer_refusals=0)
    for _ in range(500):
        det.observe_refusal("IB_ACME_ADT")
    assert sink.signals == []


async def test_allowlist_and_cap_refusals_reach_the_detector_and_a_stopping_one_does_not() -> None:
    sink = _Sink()
    remove = install_security_signals(
        sink, _thresholds(peer_refusals=3), asyncio.get_running_loop()
    )
    try:
        _refuse(_admission(source_ip_allowlist=["10.0.0.0/8"]), 2)
        full = _admission(max_connections=1)
        full.admit("192.0.2.1")
        _refuse(full, 1)
        assert [(s, n, c) for s, n, c, _d in sink.signals] == [
            ("peer_refused_burst", "inbound:IB_ACME_ADT", 3)
        ]
        # The controls: a stopping listener's refusal and an admitted peer are not counted.
        stopping = _admission(source_ip_allowlist=["10.0.0.0/8"])
        stopping.stopping = True
        _refuse(stopping, 5)
        assert _admission().check(cast(Any, _Writer("10.1.1.1")), "10.1.1.1") is None
        remove()
        _refuse(_admission(source_ip_allowlist=["10.0.0.0/8"]), 5)  # removed: nothing counts
        assert len(sink.signals) == 1
    finally:
        remove()  # idempotent


def test_a_dicom_refusal_reaches_the_refusal_observers() -> None:
    seen: list[str] = []
    scp = DicomScpSource(
        Source(
            type=ConnectorType.DIMSE,
            name="IB_PACS",
            settings={"ae_title": "MEFOR_SCP", "host": "127.0.0.1", "port": 0},
        )
    )
    add_refusal_observer(seen.append)
    try:
        scp._log_refused_peer("203.0.113.9", "a connection", "peer IP not in source_ip_allowlist")
    finally:
        remove_refusal_observer(seen.append)
    assert seen == ["IB_PACS"]


def test_a_failing_refusal_observer_never_reaches_the_listener(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(admission, "_OBSERVER_FAILURE_LOG_AFTER", 0.0)

    def broken(_connection: str) -> None:
        raise RuntimeError("observer down")

    add_refusal_observer(broken)
    try:
        refusal = _admission(source_ip_allowlist=["10.0.0.0/8"]).check(
            cast(Any, _Writer("203.0.113.9")), "203.0.113.9"
        )
        admission.notify_refusal("IB_ACME_ADT")  # a second fault logs nothing more
    finally:
        remove_refusal_observer(broken)
    assert refusal is not None and refusal.kind == "peer_not_allowlisted"
    warned = [r for r in caplog.records if "refusal observer failed" in r.getMessage()]
    assert len(warned) == 1 and warned[0].levelno == logging.WARNING


# --- the layer switched off is a loosening, and the posture detector still reports it -------------


def _loosenings(alerts: AlertsSettings) -> list[str]:
    return [name for name, _risk in _security_signal_loosenings(alerts)]


def test_the_layer_off_or_a_detector_at_zero_is_a_named_loosening() -> None:
    assert _loosenings(AlertsSettings()) == []  # the control: shipped defaults loosen nothing
    assert _loosenings(AlertsSettings(security_signals=False)) == ["alerts.security_signals"]
    assert _loosenings(
        AlertsSettings(security_signals=False, security_denials=0, security_peer_refusals=0)
    ) == ["alerts.security_signals"]
    assert _loosenings(AlertsSettings(security_denials=0, security_peer_refusals=0)) == [
        "alerts.security_denials",
        "alerts.security_peer_refusals",
    ]


def test_a_count_above_its_default_or_a_shorter_window_is_a_named_loosening() -> None:
    assert _loosenings(AlertsSettings(security_signin_failures=21)) == [
        "alerts.security_signin_failures"
    ]
    assert _loosenings(AlertsSettings(security_window_seconds=60)) == [
        "alerts.security_window_seconds"
    ]
    # The controls: a stricter count, and a longer window, loosen nothing, and nor does a
    # shorter window that no running counting detector reads.
    assert _loosenings(AlertsSettings(security_signin_failures=5)) == []
    assert _loosenings(AlertsSettings(security_window_seconds=600)) == []
    off = AlertsSettings.model_validate(
        {"security_window_seconds": 60, **{f: 0 for f, _s, _w in _SECURITY_SIGNAL_COUNTS}}
    )
    assert "alerts.security_window_seconds" not in _loosenings(off)


def test_the_count_table_covers_every_count_setting_and_only_signal_types() -> None:
    counts = {
        name
        for name, field in AlertsSettings.model_fields.items()
        if name.startswith("security_") and field.annotation is int
    }
    assert {field for field, _signal, _what in _SECURITY_SIGNAL_COUNTS} == counts
    assert {signal for _field, signal, _what in _SECURITY_SIGNAL_COUNTS} <= SECURITY_SIGNAL_TYPES


def test_the_peer_refusal_count_is_bounded() -> None:
    AlertsSettings(security_peer_refusals=100_000)
    with pytest.raises(ValidationError):
        AlertsSettings(security_peer_refusals=100_001)


def test_the_layer_off_still_raises_its_posture_and_nothing_else() -> None:
    det, sink, _ = _detector(enabled=False, signin_failures=1, denials=1, peer_refusals=1)
    _rows(det, "auth.login_failed", 5)
    _rows(det, "auth.permission_denied", 5)
    det.observe("logging_level_change", "op", None, None, json.dumps({"to": "DEBUG"}))
    det.observe_refusal("IB_ACME_ADT")
    assert sink.signals == []
    det.observe(
        "config_loaded",
        "system",
        None,
        None,
        json.dumps({"loosenings": ["alerts.security_signals"]}),
    )
    assert [(s, n) for s, n, _c, _d in sink.signals] == [("posture_loosened", "posture:start")]
    assert "alerts.security_signals" in sink.signals[0][3]


@pytest.mark.parametrize("off", [{"enabled": False}, {"peer_refusals": 0}])
async def test_a_detector_that_counts_no_refusal_registers_no_refusal_observer(
    off: dict[str, Any],
) -> None:
    before = admission._REFUSAL_OBSERVERS
    remove = install_security_signals(_Sink(), _thresholds(**off), asyncio.get_running_loop())
    try:
        assert before == admission._REFUSAL_OBSERVERS
    finally:
        remove()
    remove = install_security_signals(_Sink(), _thresholds(), asyncio.get_running_loop())
    try:
        assert len(admission._REFUSAL_OBSERVERS) == len(before) + 1  # the control: on, it does
    finally:
        remove()
    assert before == admission._REFUSAL_OBSERVERS


# --- posture_restored: the inverse that resolves posture_loosened ---------------------------------


class _PostureSink(_Sink):
    def __init__(self) -> None:
        super().__init__()
        self.restored: list[str] = []

    def posture_restored(self, name: str) -> None:
        self.restored.append(name)


def _start(det: SecuritySignalDetector, loosenings: Any) -> None:
    det.observe("config_loaded", "system", None, None, json.dumps({"loosenings": loosenings}))


def test_a_clean_start_raises_posture_restored_and_a_loosened_or_unread_one_does_not() -> None:
    sink = _PostureSink()
    det = SecuritySignalDetector(sink, _thresholds())
    _start(det, ["security.allow_x"])
    _start(det, None)  # an unread list says nothing either way
    assert sink.restored == []
    _start(det, [])
    assert sink.restored == ["posture:start"]
    assert [s for s, _n, _c, _d in sink.signals] == ["posture_loosened"]


def test_the_posture_subject_names_the_process_where_several_share_the_store() -> None:
    sink = _PostureSink()
    det = SecuritySignalDetector(sink, _thresholds(), identity=lambda: "node:a")
    _start(det, ["security.allow_x"])
    _start(det, [])
    assert [n for _s, n, _c, _d in sink.signals] == ["posture:start@node:a"]
    assert sink.restored == ["posture:start@node:a"]


def test_an_identity_fault_still_raises_under_the_bare_subject() -> None:
    def broken() -> str | None:
        raise RuntimeError("coordinator down")

    sink = _PostureSink()
    _start(SecuritySignalDetector(sink, _thresholds(), identity=broken), ["security.allow_x"])
    assert [(s, n) for s, n, _c, _d in sink.signals] == [("posture_loosened", "posture:start")]


async def test_resolve_on_stop_clears_the_posture_alert_this_process_raised() -> None:
    sink = _PostureSink()
    loop = asyncio.get_running_loop()
    remove = install_security_signals(
        sink, _thresholds(), loop, identity=lambda: "node:h-1", resolve_on_stop=True
    )
    try:
        detail = json.dumps({"loosenings": ["security.allow_x"]})
        cast(Any, audit_tee).emit_audit_tee(
            action="config_loaded",
            actor="system",
            channel_id=None,
            detail=detail,
            ts=0.0,
            row_id=1,
            seq=1,
            row_hash="0" * 64,
        )
    finally:
        remove()
    assert sink.restored == ["posture:start@node:h-1"]
    # The controls: without the flag, or with nothing raised, a stop resolves nothing.
    quiet = _PostureSink()
    install_security_signals(quiet, _thresholds(), loop, resolve_on_stop=True)()
    assert quiet.restored == []


class _Coordinator:
    def __init__(self, clustered: bool) -> None:
        self.clustered = clustered

    def is_clustered(self) -> bool:
        return self.clustered


class _Engine:
    def __init__(self, identity: str | None, clustered: bool) -> None:
        self.instance_identity = identity
        self.coordinator = _Coordinator(clustered)


@pytest.mark.parametrize(
    ("clustered", "node_id", "resolved_at_stop"),
    [(True, None, True), (True, "pinned", False), (False, None, False)],
)
async def test_the_lifespan_wiring_names_the_process_and_resolves_only_an_unpinned_node(
    clustered: bool, node_id: str | None, resolved_at_stop: bool
) -> None:
    sink = _PostureSink()
    engine = _Engine("node:h-1" if clustered else None, clustered)
    remove = app_module._install_security_signals(
        cast(Any, engine),
        sink,
        AlertsSettings(security_signals=False),  # installed even with the layer off
        ClusterSettings(node_id=node_id),
    )
    try:
        cast(Any, audit_tee).emit_audit_tee(
            action="config_loaded",
            actor="system",
            channel_id=None,
            detail=json.dumps({"loosenings": ["alerts.security_signals"]}),
            ts=0.0,
            row_id=1,
            seq=1,
            row_hash="0" * 64,
        )
    finally:
        remove()
    subject = "posture:start@node:h-1" if clustered else "posture:start"
    assert [(s, n) for s, n, _c, _d in sink.signals] == [("posture_loosened", subject)]
    assert sink.restored == ([subject] if resolved_at_stop else [])


def test_a_failing_posture_restored_never_reaches_the_audit_writer() -> None:
    class _Broken(LoggingAlertSink):
        def posture_restored(self, name: str) -> None:
            raise RuntimeError("sink down")

    _start(SecuritySignalDetector(_Broken(), _thresholds()), [])  # must not raise


async def test_the_notifier_resolves_posture_loosened_without_a_page() -> None:
    upserts: list[str] = []
    resolves: list[tuple[str, str]] = []

    class _Store:
        async def upsert_alert_instance(self, *, event_type: str, **_kw: Any) -> None:
            upserts.append(event_type)

        async def resolve_alert_instances_for(
            self, *, event_type: str, connection: str, **_kw: Any
        ) -> None:
            resolves.append((event_type, connection))

    sink = NotifierAlertSink([], store=cast(Any, _Store()))
    sink.posture_restored("posture:start")
    for _ in range(50):
        if resolves:
            break
        await asyncio.sleep(0.01)
    assert resolves == [("posture_loosened", "posture:start")]
    assert upserts == []


def test_the_logging_sink_logs_posture_restored_at_debug(caplog: pytest.LogCaptureFixture) -> None:
    with caplog.at_level(logging.DEBUG, logger="messagefoundry.pipeline.alerts"):
        LoggingAlertSink().posture_restored("posture:start")
    (record,) = caplog.records
    assert record.levelno == logging.DEBUG and "posture_restored" in record.getMessage()
