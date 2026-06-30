# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Update-check (#30, ADR 0026) tests: the no-network pinned-vs-current diff, off-by-default switch,
the version comparator, that the alert fires only on drift, and the [update_check] config clamps."""

from __future__ import annotations

import asyncio

import pytest

from messagefoundry.config.settings import UpdateCheckSettings
from messagefoundry.pipeline.update_check import (
    UpdateCheckRunner,
    compare_versions,
)


class _RecordingSink:
    """A minimal AlertSink stub capturing update_available calls (structural — no inheritance)."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str]] = []

    def update_available(self, name: str, *, current_version: str, pinned_version: str) -> None:
        self.calls.append((name, current_version, pinned_version))


def test_compare_versions() -> None:
    assert compare_versions("0.2.9", "0.3.0") == -1
    assert compare_versions("0.3.0", "0.2.9") == 1
    assert compare_versions("0.2.9", "0.2.9") == 0
    # Short tuples right-pad with zeros.
    assert compare_versions("0.2", "0.2.0") == 0
    assert compare_versions("1.0", "1.0.1") == -1
    # Tolerant of pre-release/build markers (release tuple ordering only).
    assert compare_versions("0.3.0rc1", "0.3.0") == 0
    assert compare_versions("0.2.9", "0.3.0.dev1") == -1


def test_diff_update_available_fires_alert() -> None:
    sink = _RecordingSink()
    runner = UpdateCheckRunner(
        UpdateCheckSettings(),
        alert_sink=sink,
        current_version="0.2.9",
        pinned_source=lambda: "0.3.0",
    )
    result = runner.run_once()
    assert result.update_available is True
    assert result.current_version == "0.2.9"
    assert result.pinned_version == "0.3.0"
    assert sink.calls == [("messagefoundry", "0.2.9", "0.3.0")]
    assert runner.latest == result


def test_diff_up_to_date_no_alert() -> None:
    sink = _RecordingSink()
    runner = UpdateCheckRunner(
        UpdateCheckSettings(),
        alert_sink=sink,
        current_version="0.3.0",
        pinned_source=lambda: "0.3.0",
    )
    result = runner.run_once()
    assert result.update_available is False
    assert sink.calls == []


def test_diff_running_newer_no_alert() -> None:
    # A source/dev build running ahead of the installed pin is NOT "an update available".
    sink = _RecordingSink()
    runner = UpdateCheckRunner(
        UpdateCheckSettings(),
        alert_sink=sink,
        current_version="0.4.0",
        pinned_source=lambda: "0.3.0",
    )
    result = runner.run_once()
    assert result.update_available is False
    assert sink.calls == []


def test_no_pinned_metadata_no_alert() -> None:
    # A checkout with no installed distribution metadata -> pinned None -> no diff, no alert.
    sink = _RecordingSink()
    runner = UpdateCheckRunner(
        UpdateCheckSettings(),
        alert_sink=sink,
        current_version="0.2.9",
        pinned_source=lambda: None,
    )
    result = runner.run_once()
    assert result.update_available is False
    assert result.pinned_version is None
    assert sink.calls == []


def test_disabled_runner_does_not_start() -> None:
    runner = UpdateCheckRunner(
        UpdateCheckSettings(enabled=False),
        current_version="0.2.9",
        pinned_source=lambda: "0.3.0",
    )
    assert runner.enabled is False
    runner.start()  # no event loop needed; disabled start is a no-op
    assert runner.latest is None  # no pass ran


def test_settings_default_enabled_local() -> None:
    s = UpdateCheckSettings()
    assert s.enabled is True
    assert s.mode == "local"
    assert s.check_interval_seconds == 86_400.0


def test_settings_live_mode_rejected() -> None:
    with pytest.raises(ValueError, match="not implemented"):
        UpdateCheckSettings(mode="live")


def test_settings_bad_mode_rejected() -> None:
    with pytest.raises(ValueError, match="must be 'local'"):
        UpdateCheckSettings(mode="phone-home")


def test_settings_bad_interval_rejected() -> None:
    with pytest.raises(ValueError, match="must be > 0"):
        UpdateCheckSettings(check_interval_seconds=0)


def test_update_available_in_alert_event_types() -> None:
    from messagefoundry.config.settings import AlertRule

    # A rule may now match the new event type (lockstep with the AlertSink methods).
    rule = AlertRule(event_type="update_available")
    assert rule.event_type == "update_available"


def test_logging_sink_update_available(caplog: pytest.LogCaptureFixture) -> None:
    from messagefoundry.pipeline.alerts import LoggingAlertSink

    with caplog.at_level("WARNING"):
        LoggingAlertSink().update_available(
            "messagefoundry", current_version="0.2.9", pinned_version="0.3.0"
        )
    assert any("update_available" in r.getMessage() for r in caplog.records)


async def test_notifier_sink_update_available_phi_free() -> None:
    # Lockstep: the NotifierAlertSink emits a fan-out event carrying ONLY version strings (no PHI).
    from messagefoundry.pipeline.alert_sinks import NotifierAlertSink

    class _RecordingTransport:
        def __init__(self) -> None:
            self.name = "t"
            self.events: list[dict] = []

        async def send(self, event: dict) -> None:
            self.events.append(event)

    t = _RecordingTransport()
    sink = NotifierAlertSink([t])  # type: ignore[list-item]
    sink.start()
    sink.update_available("messagefoundry", current_version="0.2.9", pinned_version="0.3.0")
    await asyncio.sleep(0)  # let the dispatch task pick up
    await sink.aclose()  # flush the background dispatcher
    assert len(t.events) == 1
    ev = t.events[0]
    assert ev["type"] == "update_available"
    assert ev["connection"] == "messagefoundry"
    assert ev["current_version"] == "0.2.9"
    assert ev["pinned_version"] == "0.3.0"
    assert set(ev) <= {
        "type",
        "connection",
        "current_version",
        "pinned_version",
        "ts",
        "severity",
    }


async def test_start_runs_immediate_pass_then_stops() -> None:
    sink = _RecordingSink()
    runner = UpdateCheckRunner(
        UpdateCheckSettings(check_interval_seconds=3600.0),
        alert_sink=sink,
        current_version="0.2.9",
        pinned_source=lambda: "0.3.0",
    )
    runner.start()
    try:
        # start() runs one immediate pass so /status has a result without waiting the interval.
        assert runner.latest is not None
        assert runner.latest.update_available is True
        assert sink.calls == [("messagefoundry", "0.2.9", "0.3.0")]
    finally:
        await runner.stop()
