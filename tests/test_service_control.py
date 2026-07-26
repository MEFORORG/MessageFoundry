# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Windows service-control helpers: state parsing + a real missing-service query.

The body moved to :mod:`messagefoundry.service` (ADR 0088); this exercises it there so the
``sys``/``subprocess`` monkeypatches land where ``service_state`` resolves them (the
``messagefoundry.console.service_control`` shim just re-exports these)."""

from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

import messagefoundry.service as service_control
from messagefoundry.__main__ import main
from messagefoundry.service import (
    _install_params,
    control_service,
    install_script_path,
    install_service,
    is_safe_environment,
    parse_service_state,
    service_state,
)

# ShellExecuteW lives on ``ctypes.windll`` (Windows-only); the elevated-dispatch tests monkeypatch
# it, so they can only construct/replace that attribute where it exists. They still run on the
# Windows CI leg — nothing here performs a real elevation (the fake records args and returns).
_win32_only = pytest.mark.skipif(sys.platform != "win32", reason="ctypes.windll is Windows-only")


class _ShellExecRecorder:
    """Captures ShellExecuteW calls in place of a real (elevating) call — returns a truthy HINSTANCE."""

    def __init__(self) -> None:
        self.calls: list[tuple[object, ...]] = []

    def ShellExecuteW(self, *args: object) -> int:  # noqa: N802 (matches the WinAPI name)
        self.calls.append(args)
        return 42


def test_parse_service_state() -> None:
    assert parse_service_state("        STATE              : 4  RUNNING") == "running"
    assert parse_service_state("        STATE              : 1  STOPPED") == "stopped"
    assert parse_service_state("nonsense") == "unknown"


def test_service_state_for_missing_service() -> None:
    # Windows -> 'not installed'; other platforms / no `sc` -> 'unavailable'. Either is fine.
    assert service_state("MessageFoundryNoSuchService_zzz") in {"not installed", "unavailable"}


def test_service_state_query_suppresses_console_window(monkeypatch) -> None:  # type: ignore[no-untyped-def]
    """Regression: ``sc query`` must run with CREATE_NO_WINDOW so the windowless GUI process doesn't
    flash a console window on every Status-page poll. Fake win32 + capture the kwargs so the guard
    holds on any host OS (``_NO_WINDOW`` is 0 off Windows, so we assert the flag is *passed*)."""

    class _Result:
        returncode = 0
        stdout = "STATE : 4  RUNNING"

    captured: dict[str, object] = {}

    def _fake_run(*args: object, **kwargs: object) -> _Result:
        captured.update(kwargs)
        return _Result()

    monkeypatch.setattr(service_control.sys, "platform", "win32")
    monkeypatch.setattr(service_control.subprocess, "run", _fake_run)

    assert service_state("MessageFoundry") == "running"
    assert "creationflags" in captured  # the flag must be passed (no console-window flash)
    assert captured["creationflags"] == service_control._NO_WINDOW


def test_install_script_path_is_found() -> None:
    path = install_script_path()
    assert path is not None
    assert path.name == "install-service.ps1"
    assert path.exists()


def _install_script_text() -> str:
    """Read the installer, or skip when this is a non-editable install (no script on disk)."""
    path = install_script_path()
    if path is None or not path.exists():
        pytest.skip("install-service.ps1 not present (non-editable install)")
    return path.read_text(encoding="utf-8")


def test_installer_configures_graceful_ctrl_c_drain_window() -> None:
    """DEPLOY-5 config half: the NSSM stop method must stay the Ctrl+C console drain with a 15s window.

    This locks the config against silent drift — a shrunk window, or a switch to ``AppStopMethodSkip``
    that would let NSSM SIGKILL uvicorn and skip the ``engine.stop()`` connection drain entirely. It is
    a static manifest assertion; it does NOT exercise the actual drain (that lives on the SIGTERM path
    proven by docker-smoke, and in the windows-service-smoke in-flight ci-leg still owed)."""
    text = _install_script_text()

    # Ctrl+C console-signal stop with a full 15s (15000 ms) drain window.
    assert re.search(r"AppStopMethodConsole\s+15000", text), (
        "install-service.ps1 must set 'AppStopMethodConsole 15000' — the 15s Ctrl+C graceful-drain "
        "window. A shrunk window or a removed setting would cut the connection drain short."
    )

    # A hard SIGKILL-first posture would defeat the drain: NSSM must not be told to Skip the console
    # signal on stop.
    assert not re.search(r"AppStopMethodSkip\b", text), (
        "install-service.ps1 sets AppStopMethodSkip — that would skip the Ctrl+C signal and let NSSM "
        "terminate uvicorn without draining in-flight connections."
    )


def test_installer_keeps_restart_and_throttle_guardrails() -> None:
    """Guardrails around the drain window: restart-on-unexpected-exit, throttled against a crash-loop."""
    text = _install_script_text()

    assert re.search(r"AppExit\s+Default\s+Restart", text), (
        "install-service.ps1 must set 'AppExit Default Restart' so the engine restarts on unexpected exit."
    )
    assert re.search(r"AppThrottle\s+\d+", text), (
        "install-service.ps1 must set 'AppThrottle <ms>' to throttle restarts and avoid a crash-loop."
    )


# --- DEPLOY-23: control_service / install_service elevated-dispatch guards + ShellExecuteW args ---
#
# service.py's own elevated-dispatch guards (the service-name / environment metacharacter rejections)
# and the exact ShellExecuteW argument construction had no coverage: test_service_cli mocks
# control_service / install_service wholesale so the real ShellExecuteW line is never reached, and
# test_service_status covers a *different* module's is_safe_service_name. These fill that gap without a
# real elevation (ShellExecuteW is monkeypatched) or a real installed service.


@_win32_only
def test_control_service_start_shellexecute_args(monkeypatch: pytest.MonkeyPatch) -> None:
    """``control_service('start', name)`` runs an elevated hidden ``cmd /c net start "<name>"``."""
    rec = _ShellExecRecorder()
    monkeypatch.setattr(service_control.sys, "platform", "win32")
    monkeypatch.setattr(service_control.ctypes.windll.shell32, "ShellExecuteW", rec.ShellExecuteW)

    assert control_service("start", "MyEngine") is True
    # (hwnd, verb, file, params, dir, nShow): elevated ("runas"), via cmd.exe, hidden (SW_HIDE=0).
    assert rec.calls == [(None, "runas", "cmd.exe", '/c net start "MyEngine"', None, 0)]


@_win32_only
def test_control_service_stop_shellexecute_args(monkeypatch: pytest.MonkeyPatch) -> None:
    rec = _ShellExecRecorder()
    monkeypatch.setattr(service_control.sys, "platform", "win32")
    monkeypatch.setattr(service_control.ctypes.windll.shell32, "ShellExecuteW", rec.ShellExecuteW)

    assert control_service("stop", "MyEngine") is True
    assert rec.calls == [(None, "runas", "cmd.exe", '/c net stop "MyEngine"', None, 0)]


@_win32_only
def test_control_service_restart_chains_stop_then_start(monkeypatch: pytest.MonkeyPatch) -> None:
    """restart chains two elevated ``net`` calls with ``&`` — that's why it must go through cmd.exe."""
    rec = _ShellExecRecorder()
    monkeypatch.setattr(service_control.sys, "platform", "win32")
    monkeypatch.setattr(service_control.ctypes.windll.shell32, "ShellExecuteW", rec.ShellExecuteW)

    assert control_service("restart", "MyEngine") is True
    assert rec.calls == [
        (None, "runas", "cmd.exe", '/c net stop "MyEngine" & net start "MyEngine"', None, 0)
    ]


@_win32_only
def test_install_service_shellexecute_args(monkeypatch: pytest.MonkeyPatch) -> None:
    """``install_service`` launches a *visible* (SW_SHOWNORMAL=1) elevated PowerShell installer."""
    rec = _ShellExecRecorder()
    monkeypatch.setattr(service_control.sys, "platform", "win32")
    monkeypatch.setattr(service_control.ctypes.windll.shell32, "ShellExecuteW", rec.ShellExecuteW)

    assert install_service(r"C:\repo\install-service.ps1", "dev") is True
    assert rec.calls == [
        (
            None,
            "runas",
            "powershell.exe",
            '-NoExit -ExecutionPolicy Bypass -File "C:\\repo\\install-service.ps1" -Environment "dev"',
            None,
            1,
        )
    ]


def test_install_params_builds_expected_string() -> None:
    assert _install_params("script.ps1", "staging") == (
        '-NoExit -ExecutionPolicy Bypass -File "script.ps1" -Environment "staging"'
    )


@pytest.mark.parametrize("bad", [";", "&", '"', "a b", "$x", "`", "a/b", "a\\b", "a&b", ""])
def test_install_params_rejects_unsafe_environment(bad: str) -> None:
    """The env name is interpolated into an elevated PowerShell line — reject shell metacharacters."""
    with pytest.raises(ValueError, match="unsafe environment name"):
        _install_params("script.ps1", bad)


def test_control_service_rejects_unsafe_name_before_platform_check(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Guard ordering: the service-name rejection must fire *before* the platform check, so an unsafe
    name is refused on every OS (not silently returned False off Windows). Force a non-win32 platform
    and assert it still raises — this also proves the guard needs no ``ctypes.windll`` to run."""
    monkeypatch.setattr(service_control.sys, "platform", "linux")
    with pytest.raises(ValueError, match="unsafe service name"):
        control_service("start", 'evil" & calc.exe & "')


@pytest.mark.parametrize("bad", ['a"b', "a&b", "a|b", "a$b", "a`b", "a/b", "a\\b", "a;b", ""])
def test_control_service_rejects_unsafe_names(bad: str) -> None:
    with pytest.raises(ValueError, match="unsafe service name"):
        control_service("start", bad)


def test_control_service_off_windows_returns_false_without_dispatch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off Windows a safe-named action is a no-op (False) and must never reach ShellExecuteW."""
    tripped: list[bool] = []

    class _Boom:
        class shell32:  # noqa: N801
            @staticmethod
            def ShellExecuteW(*_a: object) -> int:  # noqa: N802
                tripped.append(True)
                return 0

    monkeypatch.setattr(service_control.sys, "platform", "linux")
    monkeypatch.setattr(service_control.ctypes, "windll", _Boom, raising=False)

    assert control_service("start", "MyEngine") is False
    assert tripped == []  # never dispatched


def test_install_service_off_windows_returns_false_but_still_validates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Off Windows install is a no-op (False) — but env validation still runs (it's platform-independent)."""
    monkeypatch.setattr(service_control.sys, "platform", "linux")
    assert install_service("script.ps1", "dev") is False
    with pytest.raises(ValueError, match="unsafe environment name"):
        install_service("script.ps1", "bad;env")


@pytest.mark.parametrize("name", ["dev", "staging", "prod", "env-1", "env_2", "a.b", "A9"])
def test_is_safe_environment_accepts_valid(name: str) -> None:
    assert is_safe_environment(name) is True


@pytest.mark.parametrize(
    "name", ["", "a b", "a;b", "a&b", 'a"b', "a/b", "a\\b", "a$b", "a`b", "a|b"]
)
def test_is_safe_environment_rejects_invalid(name: str) -> None:
    assert is_safe_environment(name) is False


def test_cli_start_unsafe_name_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``service start --name '<unsafe>'`` surfaces the ValueError guard as exit 2 (not a dispatch)."""
    monkeypatch.setattr(service_control.sys, "platform", "linux")  # guard fires before this anyway
    rc = main(["service", "start", "--name", "bad & name"])
    assert rc == 2
    assert "unsafe service name" in capsys.readouterr().err


def test_cli_install_unsafe_env_exits_2(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """``service install --env '<unsafe>'`` surfaces the env-validation ValueError as exit 2."""
    monkeypatch.setattr(service_control, "install_script_path", lambda: Path("install-service.ps1"))
    monkeypatch.setattr(service_control.sys, "platform", "linux")
    rc = main(["service", "install", "--env", "bad;env"])
    assert rc == 2
    assert "unsafe environment name" in capsys.readouterr().err
