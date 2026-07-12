# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for the secret-rotation reminder (pipeline/secret_rotation.py, #195b / ADR 0019 §5).

Mirrors tests/test_cert_expiry.py: a fixed instant + an injected clock + a recording sink drive the
pure run_once so overdue/within-window/healthy are deterministic. PHI-free — the doubles carry only a
label + a config identifier + rotation dates, never a secret value (synthetic labels only)."""

from __future__ import annotations

import asyncio
import datetime

from messagefoundry.config.settings import SecretRotationSettings
from messagefoundry.pipeline.alert_sinks import NotifierAlertSink
from messagefoundry.pipeline.alerts import LoggingAlertSink
from messagefoundry.pipeline.secret_rotation import (
    MonitoredSecret,
    SecretRotationRunner,
    secrets_from_settings,
)

_UTC = datetime.timezone.utc
# A fixed reference instant so the rotation windows + the runner's clock are deterministic.
_REF = datetime.datetime(2026, 6, 15, 12, 0, tzinfo=_UTC)
_REF_TS = _REF.timestamp()
_TODAY = _REF.date()


class _RecordingSink:
    """An AlertSink that records secret_rotation_due calls; the other methods are inert."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, str, int]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        pass

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        pass

    def storage_threshold(self, path: str, *, size_bytes: int, limit_bytes: int) -> None:
        pass

    def cert_expiry(self, name: str, *, path: str, not_after: str, days_remaining: int) -> None:
        pass

    def secret_rotation_due(
        self, name: str, *, secret: str, last_rotated: str, days_overdue: int
    ) -> None:
        self.calls.append((name, secret, last_rotated, days_overdue))


def _secret(*, age_days: int, max_age_days: int = 365) -> MonitoredSecret:
    """A synthetic tracked secret last rotated `age_days` before the fixed instant."""
    return MonitoredSecret(
        label="store data-encryption key",
        secret="MEFOR_STORE_ENCRYPTION_KEY",
        last_rotated=_TODAY - datetime.timedelta(days=age_days),
        max_age_days=max_age_days,
    )


def _runner(
    secrets: list[MonitoredSecret], sink: _RecordingSink, warn_days: int = 14
) -> SecretRotationRunner:
    return SecretRotationRunner(
        lambda: secrets,
        SecretRotationSettings(warn_days=warn_days),
        alert_sink=sink,
        clock=lambda: _REF_TS,
    )


# --- run_once: the core scan ------------------------------------------------


def test_healthy_secret_does_not_alert() -> None:
    sink = _RecordingSink()
    checks = _runner([_secret(age_days=100)], sink).run_once()  # 265 days until due
    assert sink.calls == []
    assert len(checks) == 1
    assert checks[0].days_overdue == -265
    assert checks[0].overdue is False


def test_overdue_secret_alerts_with_positive_days() -> None:
    sink = _RecordingSink()
    checks = _runner([_secret(age_days=400)], sink).run_once()  # 35 days past a 365-day max
    assert len(sink.calls) == 1
    name, secret, last_rotated, days = sink.calls[0]
    assert name == "store data-encryption key"
    assert secret == "MEFOR_STORE_ENCRYPTION_KEY"
    assert days == 35
    assert checks[0].overdue is True


def test_within_warn_window_alerts_before_due() -> None:
    # 355 days old, 365-day max → due in 10 days, inside the 14-day warn window → alerts (days_overdue<0).
    sink = _RecordingSink()
    _runner([_secret(age_days=355)], sink, warn_days=14).run_once()
    assert len(sink.calls) == 1
    assert sink.calls[0][3] == -10


def test_boundary_is_inclusive() -> None:
    # Exactly warn_days from due (351 old, 365 max → 14 days out) still alerts (>= -warn_days).
    sink = _RecordingSink()
    _runner([_secret(age_days=351)], sink, warn_days=14).run_once()
    assert len(sink.calls) == 1
    assert sink.calls[0][3] == -14


def test_just_outside_window_is_silent() -> None:
    # 15 days from due is one day beyond the 14-day window → silent.
    sink = _RecordingSink()
    _runner([_secret(age_days=350)], sink, warn_days=14).run_once()
    assert sink.calls == []


def test_one_secret_does_not_block_others() -> None:
    sink = _RecordingSink()
    secrets = [_secret(age_days=100), _secret(age_days=500)]
    _runner(secrets, sink).run_once()
    # Only the overdue one alerts; the healthy one is silent but still scanned.
    assert [c[3] for c in sink.calls] == [135]


# --- secrets_from_settings --------------------------------------------------


def test_secrets_from_settings_tracks_store_dek_when_configured() -> None:
    s = SecretRotationSettings(store_key_last_rotated="2026-01-01", store_key_max_age_days=90)
    secrets = secrets_from_settings(s)
    assert len(secrets) == 1
    assert secrets[0].secret == "MEFOR_STORE_ENCRYPTION_KEY"
    assert secrets[0].last_rotated == datetime.date(2026, 1, 1)
    assert secrets[0].max_age_days == 90


def test_secrets_from_settings_deny_by_default() -> None:
    # No last-rotated date configured → the store DEK is not tracked (empty → runner no-op).
    assert secrets_from_settings(SecretRotationSettings()) == []


# --- enabled / lifecycle ----------------------------------------------------


def test_disabled_when_warn_days_zero() -> None:
    runner = SecretRotationRunner(lambda: [], SecretRotationSettings(warn_days=0))
    assert runner.enabled is False


def test_start_stop_clean_with_no_secrets() -> None:
    async def _go() -> None:
        sink = _RecordingSink()
        settings = SecretRotationSettings(warn_days=14, check_interval_seconds=0.01)
        runner = SecretRotationRunner(lambda: [], settings, alert_sink=sink)
        runner.start()
        await asyncio.sleep(0.03)
        await runner.stop()
        assert sink.calls == []

    asyncio.run(_go())


def test_start_is_noop_when_disabled() -> None:
    async def _go() -> None:
        runner = SecretRotationRunner(lambda: [], SecretRotationSettings(warn_days=0))
        runner.start()
        await runner.stop()  # idempotent, no task ever spawned

    asyncio.run(_go())


# --- the sinks --------------------------------------------------------------


def test_logging_sink_secret_rotation_does_not_raise() -> None:
    sink = LoggingAlertSink()
    sink.secret_rotation_due(
        "store data-encryption key",
        secret="MEFOR_STORE_ENCRYPTION_KEY",
        last_rotated="2025-01-01",
        days_overdue=30,
    )
    sink.secret_rotation_due(
        "store data-encryption key",
        secret="MEFOR_STORE_ENCRYPTION_KEY",
        last_rotated="2026-01-01",
        days_overdue=-5,
    )


def test_notifier_sink_emits_secret_rotation_event() -> None:
    class _RecordTransport:
        name = "rec"

        def __init__(self) -> None:
            self.events: list[dict[str, object]] = []

        async def send(self, event: dict[str, object]) -> None:
            self.events.append(event)

    async def _go() -> None:
        t = _RecordTransport()
        sink = NotifierAlertSink([t], realert_seconds=0.0)
        sink.start()
        sink.secret_rotation_due(
            "store data-encryption key",
            secret="MEFOR_STORE_ENCRYPTION_KEY",
            last_rotated="2025-01-01",
            days_overdue=30,
        )
        await asyncio.sleep(0.02)
        await sink.aclose()
        assert any(
            e["type"] == "secret_rotation"
            and e["connection"] == "store data-encryption key"
            and e["days_overdue"] == 30
            for e in t.events
        )

    asyncio.run(_go())
