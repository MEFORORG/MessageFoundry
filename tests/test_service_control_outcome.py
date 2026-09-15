# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Outcome-aware elevation `control_service_ex` (ADR 0113 §4).

The native ShellExecuteExW/wait/exit-code plumbing (`_runas_wait`) is Windows-only and covered by
manual QA (it triggers a real UAC prompt). These tests pin the security-relevant logic without a
real elevation: the guard ordering, the System32-only command construction, and the outcome
mapping — by monkeypatching `_runas_wait`.
"""

from __future__ import annotations

import ctypes
import os

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


_SYSDIR = service._system_dir()
_CMD = os.path.join(_SYSDIR, "cmd.exe")
_NET = os.path.join(_SYSDIR, "net.exe")


@pytest.mark.parametrize("action", ["start", "stop", "restart"])
def test_builds_system32_command_and_delegates(
    monkeypatch: pytest.MonkeyPatch, action: str
) -> None:
    """Elevation must target the system directory's ``cmd.exe`` and ``net.exe``, with the validated
    name — never a program a search path resolves out of the caller's working directory.

    This test's name claimed System32 while it asserted the bare names; BACKLOG #1680 made the code
    match the claim. The ``/s`` and the extra quote pair are how a quoted absolute path survives
    ``cmd``'s own parsing — see ``service._elevated_cmd_params``."""
    recorded: list[tuple[str, str]] = []

    def fake_runas(file: str, params: str) -> ServiceControlOutcome:
        recorded.append((file, params))
        return ServiceControlOutcome.DISPATCHED

    monkeypatch.setattr(service, "_runas_wait", fake_runas)
    monkeypatch.setattr(service.sys, "platform", "win32")
    tail = (
        f'"{_NET}" stop "MyEngine" & "{_NET}" start "MyEngine"'
        if action == "restart"
        else f'"{_NET}" {action} "MyEngine"'
    )

    assert control_service_ex(action, "MyEngine") is ServiceControlOutcome.DISPATCHED
    assert recorded == [(_CMD, f'/s /c "{tail}"')]


def test_runas_wait_pins_the_image_and_the_working_directory(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """``_runas_wait`` itself: the struct it hands ShellExecuteExW names an absolute image and the
    system directory. A null ``lpDirectory`` would start the elevated child in the caller's working
    directory — the directory a planted program would sit in (BACKLOG #1680).

    No real elevation: ``ctypes.WinDLL`` is replaced, so ShellExecuteExW is never loaded."""
    seen: list[service._SHELLEXECUTEINFOW] = []

    class _Func:
        argtypes: object = None
        restype: object = None

        def __call__(self, ref: object) -> int:
            seen.append(ref._obj)  # type: ignore[attr-defined]  # byref() keeps the struct here
            return 1  # success, hProcess left NULL -> DISPATCHED without touching kernel32

    class _FakeDll:
        def __init__(self, _name: str, **_kw: object) -> None:
            self.ShellExecuteExW = _Func()

    monkeypatch.setattr(service.sys, "platform", "win32")
    monkeypatch.setattr(service.ctypes, "WinDLL", _FakeDll, raising=False)

    assert service._runas_wait(_CMD, "/s /c rem") is ServiceControlOutcome.DISPATCHED
    info = seen[0]
    assert info.lpVerb == "runas"
    assert info.lpFile == _CMD
    assert info.lpDirectory == _SYSDIR
    assert info.cbSize == ctypes.sizeof(service._SHELLEXECUTEINFOW)


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
