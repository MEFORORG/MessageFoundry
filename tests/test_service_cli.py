# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The `messagefoundry service {install,start,stop,status}` CLI subparser (ADR 0088).

Dispatch-level coverage: `status` shells `sc query` (mocked here), and the elevated actions delegate
to messagefoundry.service. No real service is touched."""

from __future__ import annotations

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

    monkeypatch.setattr(svc.sys, "platform", "win32")
    monkeypatch.setattr(svc.subprocess, "run", lambda *a, **k: _Result())

    rc = main(["service", "status", "--name", "MessageFoundry"])
    assert rc == 0
    assert capsys.readouterr().out.strip() == "running"


def test_service_start_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    calls: list[tuple[str, str]] = []
    monkeypatch.setattr(
        svc, "control_service", lambda action, name: calls.append((action, name)) or True
    )

    assert main(["service", "start", "--name", "MyEngine"]) == 0
    assert calls == [("start", "MyEngine")]


def test_service_stop_off_windows_returns_1(monkeypatch: pytest.MonkeyPatch) -> None:
    # control_service returns False off Windows (no-op); the CLI surfaces that as a non-zero exit.
    monkeypatch.setattr(svc, "control_service", lambda action, name: False)
    assert main(["service", "stop"]) == 1


def test_service_install_requires_env(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["service", "install"]) == 2
    assert "requires --env" in capsys.readouterr().err


def test_service_install_dispatch(monkeypatch: pytest.MonkeyPatch) -> None:
    installs: list[tuple[str, str]] = []
    monkeypatch.setattr(svc, "install_script_path", lambda: Path("install-service.ps1"))
    monkeypatch.setattr(
        svc, "install_service", lambda script, env: installs.append((script, env)) or True
    )

    assert main(["service", "install", "--env", "dev"]) == 0
    assert installs == [("install-service.ps1", "dev")]


def test_service_install_missing_script(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(svc, "install_script_path", lambda: None)
    assert main(["service", "install", "--env", "dev"]) == 2
    assert "install-service.ps1" in capsys.readouterr().err
