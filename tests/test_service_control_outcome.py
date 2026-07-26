# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Outcome-aware elevation `control_service_ex` (ADR 0113 §4).

The native ShellExecuteExW/wait/exit-code plumbing (`_runas_wait`) is Windows-only and covered by
manual QA (it triggers a real UAC prompt). These tests pin the security-relevant logic without a
real elevation: the guard ordering, the System32-only command construction, and the outcome
mapping — by monkeypatching `_runas_wait`.
"""

from __future__ import annotations

import pytest

import messagefoundry.service as service
from messagefoundry.service import ServiceControlOutcome, control_service_ex


def test_rejects_unsafe_name_before_platform_check(monkeypatch: pytest.MonkeyPatch) -> None:
    # An unsafe name must raise on every OS (before the platform check) and never elevate.
    tripped: list[object] = []
    monkeypatch.setattr(service, "_runas_wait", lambda *a: tripped.append(a))
    monkeypatch.setattr(service.sys, "platform", "linux")
    with pytest.raises(ValueError, match="unsafe service name"):
        control_service_ex("start", 'evil" & calc.exe & "')
    assert tripped == []


def test_rejects_unknown_action(monkeypatch: pytest.MonkeyPatch) -> None:
    tripped: list[object] = []
    monkeypatch.setattr(service, "_runas_wait", lambda *a: tripped.append(a))
    with pytest.raises(ValueError, match="unknown service action"):
        control_service_ex("obliterate", "MessageFoundry")
    assert tripped == []


def test_off_windows_is_unsupported_without_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    tripped: list[object] = []
    monkeypatch.setattr(service, "_runas_wait", lambda *a: tripped.append(a))
    monkeypatch.setattr(service.sys, "platform", "linux")
    assert control_service_ex("start", "MessageFoundry") is ServiceControlOutcome.UNSUPPORTED
    assert tripped == []  # never elevated


@pytest.mark.parametrize(
    ("action", "expected_params"),
    [
        ("start", '/c net start "MyEngine"'),
        ("stop", '/c net stop "MyEngine"'),
        ("restart", '/c net stop "MyEngine" & net start "MyEngine"'),
    ],
)
def test_builds_system32_command_and_delegates(
    monkeypatch: pytest.MonkeyPatch, action: str, expected_params: str
) -> None:
    # Elevation must target System32 cmd.exe with the validated name — never a user-writable path.
    recorded: list[tuple[str, str]] = []

    def fake_runas(file: str, params: str) -> ServiceControlOutcome:
        recorded.append((file, params))
        return ServiceControlOutcome.DISPATCHED

    monkeypatch.setattr(service, "_runas_wait", fake_runas)
    monkeypatch.setattr(service.sys, "platform", "win32")

    assert control_service_ex(action, "MyEngine") is ServiceControlOutcome.DISPATCHED
    assert recorded == [("cmd.exe", expected_params)]


@pytest.mark.parametrize(
    "outcome",
    [
        ServiceControlOutcome.CANCELLED,
        ServiceControlOutcome.FAILED,
        ServiceControlOutcome.DISPATCHED,
    ],
)
def test_outcome_passthrough(
    monkeypatch: pytest.MonkeyPatch, outcome: ServiceControlOutcome
) -> None:
    monkeypatch.setattr(service, "_runas_wait", lambda _f, _p: outcome)
    monkeypatch.setattr(service.sys, "platform", "win32")
    assert control_service_ex("start", "MyEngine") is outcome


def test_control_service_bool_contract_is_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    # The original fire-and-forget control_service is untouched: still bool, still off-Windows False.
    monkeypatch.setattr(service.sys, "platform", "linux")
    assert service.control_service("start", "MyEngine") is False
