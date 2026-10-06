# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The `messagefoundry service {install,start,stop,status}` CLI subparser (ADR 0088).

Dispatch-level coverage: `status` shells `sc query` (mocked here), and the elevated actions delegate
to messagefoundry.service. No real service is touched."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

import messagefoundry.service as svc
from messagefoundry.__main__ import main


def test_service_status_dispatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """`service status` calls service_state, which shells `sc query` — mock the subprocess so the
    dispatch runs on any host OS."""

    class _Result:
        returncode = 0
        stdout = "        STATE              : 4  RUNNING"

    monkeypatch.setattr(sys, "platform", "win32")  # the same module object service.py reads
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Result())

    rc = main(["service", "status", "--name", "MessageFoundry"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "running"


def test_service_start_dispatch(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[tuple[str, str]] = []

    def _control(action: str, name: str) -> svc.ServiceControlOutcome:
        calls.append((action, name))
        return svc.ServiceControlOutcome.DISPATCHED

    monkeypatch.setattr(svc, "control_service_ex", _control)

    assert main(["service", "start", "--name", "MyEngine"]) == 0
    assert calls == [("start", "MyEngine")]
    assert "completed" in capsys.readouterr().out


def test_service_stop_off_windows_returns_1(monkeypatch: pytest.MonkeyPatch) -> None:
    # control_service_ex is UNSUPPORTED off Windows (no-op); the CLI surfaces that as a non-zero exit.
    monkeypatch.setattr(
        svc, "control_service_ex", lambda action, name: svc.ServiceControlOutcome.UNSUPPORTED
    )
    assert main(["service", "stop"]) == 1


@pytest.mark.parametrize("action", ["start", "stop"])
@pytest.mark.parametrize(
    ("outcome", "says"),
    [
        (svc.ServiceControlOutcome.CANCELLED, "UAC prompt was declined"),
        (svc.ServiceControlOutcome.FAILED, "failed"),
        (svc.ServiceControlOutcome.UNSUPPORTED, "Windows-only"),
    ],
)
def test_service_start_stop_refused_elevation_exits_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
    outcome: svc.ServiceControlOutcome,
    says: str,
) -> None:
    """A declined UAC prompt or a failed elevation is a non-zero exit with the reason on stderr, so
    a wrapper script never reads it as success (vault BACKLOG #2787). The elevation is stubbed."""
    monkeypatch.setattr(svc, "control_service_ex", lambda action, name: outcome)

    assert main(["service", action, "--name", "MyEngine"]) == 1
    captured = capsys.readouterr()
    assert says in captured.err
    assert captured.out == ""


def test_service_install_requires_env(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["service", "install"]) == 2
    assert "requires --env" in capsys.readouterr().err


def test_service_install_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    installs: list[tuple[str, str]] = []
    monkeypatch.setattr(svc, "install_script_path", lambda: Path("install-service.ps1"))

    def _install(script: str, env: str) -> svc.ServiceControlOutcome:
        installs.append((script, env))
        return svc.ServiceControlOutcome.DISPATCHED

    monkeypatch.setattr(svc, "install_service", _install)

    assert main(["service", "install", "--env", "dev"]) == 0
    assert installs == [("install-service.ps1", "dev")]


@pytest.mark.parametrize(
    ("outcome", "says"),
    [
        (svc.ServiceControlOutcome.FAILED, "did not launch"),
        (svc.ServiceControlOutcome.UNSUPPORTED, "Windows-only"),
    ],
)
def test_service_install_refused_launch_exits_1(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    outcome: svc.ServiceControlOutcome,
    says: str,
) -> None:
    """A declined UAC prompt or a failed launch of the installer exits 1 (vault BACKLOG #2787)."""
    monkeypatch.setattr(svc, "install_script_path", lambda: Path("install-service.ps1"))
    monkeypatch.setattr(svc, "install_service", lambda script, env: outcome)

    assert main(["service", "install", "--env", "dev"]) == 1
    captured = capsys.readouterr()
    assert says in captured.err
    assert captured.out == ""


def test_service_install_missing_script(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(svc, "install_script_path", lambda: None)
    assert main(["service", "install", "--env", "dev"]) == 2
    assert "install-service.ps1" in capsys.readouterr().err
