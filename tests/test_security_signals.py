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
import threading
from pathlib import Path
from typing import Any, cast

import pytest
from pydantic import ValidationError

from messagefoundry.auth.audit_visibility import DIRECTORY_LOCKED_REFUSAL_DETAIL
from messagefoundry.config.settings import (
    _ALERT_CONTROL_EVENT_TYPES,
    _ALERT_EVENT_TYPES,
    AlertsSettings,
)
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
    for action in ("auth.login_locked", "auth.account_locked", "auth.permission_granted"):
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


def test_the_signal_types_are_routable_and_never_control_or_resolve_types() -> None:
    assert SECURITY_SIGNAL_TYPES <= _ALERT_EVENT_TYPES
    assert not SECURITY_SIGNAL_TYPES & _ALERT_CONTROL_EVENT_TYPES
    assert not SECURITY_SIGNAL_TYPES & set(_AUTO_RESOLVE) and not SECURITY_SIGNAL_TYPES & set(
        _AUTO_RESOLVE.values()
    )


def test_settings_defaults_and_bounds() -> None:
    s = AlertsSettings()
    assert s.security_signals is True
    t = SecuritySignalThresholds.from_settings(s)
    assert (t.window_seconds, t.signin_failures, t.denials, t.body_views, t.export_messages) == (
        300.0,
        20,
        20,
        100,
        5000,
    )
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
