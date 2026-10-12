# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The `messagefoundry service {install,start,stop,status}` CLI subparser (ADR 0088).

Dispatch-level coverage: `status` shells `sc query` (mocked here), and the elevated actions delegate
to messagefoundry.service. No test reads or changes a real OS service, on any host.

`start` and `stop` read the service state before they elevate, so a test that stubbed only the
elevation still ran a real `sc query`. Its result then depended on the host's service, not on the
test (BACKLOG #3441). The autouse fixture below fails any test that reaches the real boundary."""

from __future__ import annotations

import ctypes
import os
import subprocess
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

import pytest

import messagefoundry.service as svc
from messagefoundry.__main__ import main


class _ReachedServiceManager(BaseException):
    """A test reached a real service-manager call.

    A BaseException, because `run_cli` catches `Exception` and turns it into exit 1. An ordinary
    exception would let a test that expects exit 1 pass after reaching the real call."""


def _tripwire(what: str, hits: list[str]) -> Callable[..., object]:
    def _trip(*_args: object, **_kwargs: object) -> object:
        hits.append(what)
        raise _ReachedServiceManager(f"a test reached the real {what}")

    return _trip


_SPAWN = "subprocess.Popen (sc query)"
_ELEVATE = "ShellExecuteExW elevation"
_SHELL32 = "ctypes.windll.shell32"


class _WindllTripwire:
    """Stands in for `ctypes.windll`. Only `shell32`, the `ShellExecuteW` that `install_service`
    elevates through, trips. Any other DLL comes from the real `windll`, and off Windows it is an
    AttributeError, as it would be with no `windll` at all."""

    def __init__(self, hits: list[str], real: object) -> None:
        self._hits = hits
        self._real = real

    def __getattr__(self, name: str) -> object:
        if name == "shell32":
            self._hits.append(_SHELL32)
            raise _ReachedServiceManager(f"a test reached the real {_SHELL32}")
        if self._real is None:
            raise AttributeError(name)
        return getattr(self._real, name)


@pytest.fixture(autouse=True)
def _no_real_service_manager(monkeypatch: pytest.MonkeyPatch) -> Iterator[list[str]]:
    """Replace every service-manager call in `messagefoundry.service` with a tripwire.

    The calls are a spawned `sc query`, the ShellExecuteExW elevation and `ctypes.windll.shell32`.
    `Popen` is the one `run`, `check_output` and `call` all go through. A test that needs a call
    stubs it itself, which replaces the tripwire for that test. The teardown check catches a hit
    that something swallowed, so an unswallowed hit also shows as a teardown error."""
    hits: list[str] = []
    monkeypatch.setattr(subprocess, "Popen", _tripwire(_SPAWN, hits))
    monkeypatch.setattr(svc, "_runas_wait", _tripwire(_ELEVATE, hits))
    real_windll = getattr(ctypes, "windll", None)
    monkeypatch.setattr(ctypes, "windll", _WindllTripwire(hits, real_windll), raising=False)
    yield hits
    assert hits == [], f"a test reached the real service manager: {hits}"


@pytest.mark.parametrize(
    ("argv", "state", "boundary"),
    [
        (["service", "status"], None, _SPAWN),
        (["service", "stop"], None, _SPAWN),
        (["service", "start"], None, _SPAWN),
        # The state read is stubbed, so these reach the elevation that comes after it.
        (["service", "stop"], "running", _ELEVATE),
        (["service", "start"], "stopped", _ELEVATE),
        (["service", "install", "--env", "dev", "--config", "cfg"], None, _SHELL32),
    ],
)
def test_the_guard_trips_on_every_unstubbed_service_call(
    monkeypatch: pytest.MonkeyPatch,
    _no_real_service_manager: list[str],
    argv: list[str],
    state: str | None,
    boundary: str,
) -> None:
    """The control for the fixture above: with the platform forced to win32 and the boundary left
    unstubbed, each command reaches that exact tripwire. This runs on every host, so the guard is
    proved on Linux too."""
    monkeypatch.setattr(sys, "platform", "win32")
    monkeypatch.setattr(svc, "install_script_path", lambda: Path("install-service.ps1"))
    # The CLI passes --config as an absolute host path, which off Windows is not a Windows path, so
    # the install row would stop at the path check before the elevation this test is about.
    if os.name != "nt":
        monkeypatch.setattr(svc, "_install_params", lambda *_a, **_k: "")
    if state is not None:
        monkeypatch.setattr(svc, "service_state", lambda name: state)

    with pytest.raises(_ReachedServiceManager):
        main(argv)
    assert _no_real_service_manager == [boundary]
    _no_real_service_manager.clear()  # the hit was the point; keep the teardown check green


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

    monkeypatch.setattr(svc, "service_state", lambda name: "stopped")
    monkeypatch.setattr(svc, "control_service_ex", _control)

    assert main(["service", "start", "--name", "MyEngine"]) == 0
    assert calls == [("start", "MyEngine")]
    assert "completed" in capsys.readouterr().out


def test_service_stop_off_windows_returns_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """Off Windows the state read is `unavailable` and the elevation is UNSUPPORTED, so `stop` exits
    1. The platform is forced, so the real off-Windows path runs on a Windows host too."""
    monkeypatch.setattr(sys, "platform", "linux")  # the same module object service.py reads

    assert main(["service", "stop"]) == 1
    assert "Windows-only" in capsys.readouterr().err


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
    a wrapper script never reads it as success (vault BACKLOG #2787). The elevation is stubbed, and
    so is the state read. It reports the other state, and again when a FAILED makes the CLI re-ask."""
    other = "running" if action == "stop" else "stopped"
    monkeypatch.setattr(svc, "service_state", lambda name: other)
    monkeypatch.setattr(svc, "control_service_ex", lambda action, name: outcome)

    assert main(["service", action, "--name", "MyEngine"]) == 1
    captured = capsys.readouterr()
    assert says in captured.err
    assert captured.out == ""


@pytest.mark.parametrize(("action", "state"), [("stop", "stopped"), ("start", "running")])
def test_service_already_in_the_requested_state_exits_0_without_elevating(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
    state: str,
) -> None:
    """Stopping a stopped service is the end state asked for, not a failure: `net stop` exits
    non-zero there, and an operator script or the uninstall path that stops first must not abort.
    The state is asked first, so no UAC prompt is raised for a no-op."""
    elevations: list[str] = []

    def _control(action: str, name: str) -> svc.ServiceControlOutcome:
        elevations.append(action)
        return svc.ServiceControlOutcome.FAILED

    monkeypatch.setattr(svc, "service_state", lambda name: state)
    monkeypatch.setattr(svc, "control_service_ex", _control)

    assert main(["service", action, "--name", "MyEngine"]) == 0
    captured = capsys.readouterr()
    assert f"already {state}" in captured.out
    assert captured.err == ""
    assert elevations == []


@pytest.mark.parametrize(("action", "state"), [("stop", "stopped"), ("start", "running")])
def test_service_reaching_the_state_during_a_failed_call_exits_0(
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
    action: str,
    state: str,
) -> None:
    """The state is asked again after a FAILED, for a service that got there while `net` ran."""
    states = iter(["running" if state == "stopped" else "stopped", state])
    monkeypatch.setattr(svc, "service_state", lambda name: next(states))
    monkeypatch.setattr(
        svc, "control_service_ex", lambda action, name: svc.ServiceControlOutcome.FAILED
    )

    assert main(["service", action, "--name", "MyEngine"]) == 0
    assert f"already {state}" in capsys.readouterr().out


def test_service_stop_that_genuinely_fails_still_exits_1(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The control: a stop that fails with the service still running is a failure."""
    monkeypatch.setattr(svc, "service_state", lambda name: "running")
    monkeypatch.setattr(
        svc, "control_service_ex", lambda action, name: svc.ServiceControlOutcome.FAILED
    )

    assert main(["service", "stop", "--name", "MyEngine"]) == 1
    captured = capsys.readouterr()
    assert "failed" in captured.err
    assert captured.out == ""


def test_service_install_requires_env(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["service", "install"]) == 2
    assert "requires --env" in capsys.readouterr().err


def test_service_install_requires_config(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """The installer has no default config directory (vault BACKLOG #2626), so the CLI asks for one
    before it raises a UAC prompt."""
    launched: list[object] = []
    monkeypatch.setattr(svc, "install_service", lambda *a, **k: launched.append(a))
    assert main(["service", "install", "--env", "dev"]) == 2
    assert "requires --config" in capsys.readouterr().err
    assert launched == []


def test_service_install_dispatch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """``--config`` and ``--service-config`` reach the installer ABSOLUTE, because the elevated
    child starts in the system directory (vault BACKLOG #2626)."""
    installs: list[tuple[str, str, str, str | None]] = []
    monkeypatch.setattr(svc, "install_script_path", lambda: Path("install-service.ps1"))

    def _install(
        script: str, env: str, *, config: str, service_config: str | None = None
    ) -> svc.ServiceControlOutcome:
        installs.append((script, env, config, service_config))
        return svc.ServiceControlOutcome.DISPATCHED

    monkeypatch.setattr(svc, "install_service", _install)
    monkeypatch.chdir(tmp_path)

    install = ["service", "install", "--env", "dev", "--config", "cfg"]
    assert main(install) == 0
    assert main([*install, "--service-config", "messagefoundry.toml"]) == 0
    config = os.path.abspath(tmp_path / "cfg")
    settings = os.path.abspath(tmp_path / "messagefoundry.toml")
    assert installs == [
        ("install-service.ps1", "dev", config, None),
        ("install-service.ps1", "dev", config, settings),
    ]


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
    monkeypatch.setattr(svc, "install_service", lambda script, env, **_paths: outcome)

    assert main(["service", "install", "--env", "dev", "--config", "cfg"]) == 1
    captured = capsys.readouterr()
    assert says in captured.err
    assert captured.out == ""


def test_service_install_missing_script(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(svc, "install_script_path", lambda: None)
    assert main(["service", "install", "--env", "dev", "--config", "cfg"]) == 2
    assert "install-service.ps1" in capsys.readouterr().err
