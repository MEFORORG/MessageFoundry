# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Windows service control for the Engine Status page.

The engine can't control its *own* hosting service through the API (stopping it kills the API;
once stopped there's no API to start it), and service control needs admin rights — so this is
done locally via the Windows SCM: ``sc query`` for state (no elevation) and an elevated
``net start/stop`` for actions (one UAC prompt each). Same-machine, Windows-only; on other
platforms / when ``sc`` is absent, state is ``"unavailable"`` and actions are no-ops.

Elevated actions come in two forms: :func:`control_service` is fire-and-forget (the elevated
process is detached, output isn't captured) — poll :func:`service_state` to observe the result;
:func:`control_service_ex` (ADR 0113) waits on the elevated child and returns a
:class:`ServiceControlOutcome` that distinguishes a cancelled UAC prompt from a failure, for the
tray service-manager. Both elevate the same System32-only ``net`` command; neither elevates
user-writable code.
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import sys
from ctypes import wintypes
from enum import Enum
from pathlib import Path

import messagefoundry

# sc.exe is a console program; launched from the GUI process (pythonw has no console) each call
# would briefly pop a console window — on the Status page's state poll that means a terminal
# flashing every few seconds. CREATE_NO_WINDOW suppresses it (Windows-only flag; 0/no-op elsewhere,
# and via getattr so it type-checks on non-Windows where the attribute doesn't exist).
_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)

__all__ = [
    "ServiceControlOutcome",
    "control_service",
    "control_service_ex",
    "install_script_path",
    "install_service",
    "is_safe_environment",
    "parse_service_state",
    "service_state",
]

_ACTIONS = {
    "start": '{0} start "{1}"',
    "stop": '{0} stop "{1}"',
    "restart": '{0} stop "{1}" & {0} start "{1}"',
}

# The restart action chains two `net` calls with `&`, so control_service can't avoid cmd.exe — and
# that line runs ELEVATED. A service name with a quote/`&`/`|` could break out of its quoted argument
# and run arbitrary commands as admin. Windows service names need none of those, so allow only a
# conservative set and reject the rest (review low-16).
_SAFE_SERVICE_NAME = re.compile(r"^[A-Za-z0-9 ._-]+$")


def _is_safe_service_name(name: str) -> bool:
    return bool(_SAFE_SERVICE_NAME.match(name))


# The active-environment name is passed to install-service.ps1 as `-Environment <name>`, interpolated
# into an ELEVATED PowerShell command line (ShellExecuteW "runas"). It also becomes a filename segment
# (environments/<name>.toml), so constrain it to the same token charset the engine validates
# ([ai].environment) and reject anything else — an unsafe value could break out of the quoted arg and
# run as admin (cf. the service-name guard above).
_SAFE_ENV_NAME = re.compile(r"^[A-Za-z0-9._-]+$")


def is_safe_environment(name: str) -> bool:
    """True if ``name`` is a valid active-environment name (letters, digits, ``.``, ``_``, ``-``)."""
    return bool(_SAFE_ENV_NAME.match(name))


def parse_service_state(sc_output: str) -> str:
    """Map ``sc query`` output to ``running`` / ``stopped`` / ``unknown``."""
    text = sc_output.upper()
    if "RUNNING" in text:
        return "running"
    if "STOP" in text:  # STOPPED or STOP_PENDING
        return "stopped"
    return "unknown"


def service_state(name: str) -> str:
    """``running`` | ``stopped`` | ``not installed`` | ``unavailable`` (non-Windows / no ``sc``)."""
    if sys.platform != "win32":
        return "unavailable"
    if not _is_safe_service_name(name):
        return "unavailable"  # never let an unsafe name enable the (elevated) control buttons
    try:
        # nosec: fixed system tool (sc), no shell; `name` is validated above (low-16).
        proc = subprocess.run(
            ["sc", "query", name],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=_NO_WINDOW,  # don't flash a console window from the GUI process
        )  # nosec B603 B607
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    if proc.returncode != 0:
        return "not installed"  # e.g. error 1060: service does not exist
    return parse_service_state(proc.stdout)


def control_service(action: str, name: str) -> bool:
    """Start/stop/restart ``name`` with a one-time UAC elevation. Returns False off Windows.

    Uses ``net`` (synchronous) under an elevated, hidden ``cmd``. Output isn't captured;
    call :func:`service_state` afterwards to see the new state.

    Raises :class:`ValueError` for a service name with shell metacharacters — it would be
    interpolated into an elevated cmd.exe line (review low-16)."""
    if not _is_safe_service_name(name):
        raise ValueError(f"unsafe service name {name!r}")
    if sys.platform != "win32":
        return False
    command = _ACTIONS[action].format("net", name)
    # ShellExecuteW with the "runas" verb raises the UAC prompt; SW_HIDE (0) hides the console.
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "cmd.exe", f"/c {command}", None, 0)
    return True


class ServiceControlOutcome(Enum):
    """The result of an :func:`control_service_ex` elevation attempt.

    Unlike :func:`control_service` (fire-and-forget, ``bool``), this distinguishes a user-cancelled
    UAC prompt from a genuine failure — the tray service-manager needs it to render an honest
    "action cancelled" vs "action failed" (ADR 0113 §4).
    """

    DISPATCHED = "dispatched"  # the elevated command ran and exited 0
    CANCELLED = "cancelled"  # the user dismissed the UAC prompt (ERROR_CANCELLED 1223)
    FAILED = "failed"  # elevation failed, or the elevated command exited non-zero
    UNSUPPORTED = "unsupported"  # not Windows — a no-op


# ShellExecuteEx / process constants.
_ERROR_CANCELLED = 1223
_SEE_MASK_NOCLOSEPROCESS = 0x00000040  # populate hProcess so we can wait + read the exit code
_SW_HIDE = 0
_WAIT_TIMEOUT_MS = 60_000  # NSSM's graceful stop (~15s) + a start; generous


class _SHELLEXECUTEINFOW(ctypes.Structure):
    """``SHELLEXECUTEINFOW`` (shellapi.h) — the ``SEE_MASK_NOCLOSEPROCESS`` form yields ``hProcess``."""

    _fields_ = (
        ("cbSize", wintypes.DWORD),
        ("fMask", wintypes.ULONG),
        ("hwnd", wintypes.HWND),
        ("lpVerb", wintypes.LPCWSTR),
        ("lpFile", wintypes.LPCWSTR),
        ("lpParameters", wintypes.LPCWSTR),
        ("lpDirectory", wintypes.LPCWSTR),
        ("nShow", ctypes.c_int),
        ("hInstApp", wintypes.HINSTANCE),
        ("lpIDList", ctypes.c_void_p),
        ("lpClass", wintypes.LPCWSTR),
        ("hkeyClass", wintypes.HKEY),
        ("dwHotKey", wintypes.DWORD),
        ("hIcon", wintypes.HANDLE),  # union { hIcon; hMonitor } — a single handle slot
        ("hProcess", wintypes.HANDLE),
    )


def _runas_wait(file: str, params: str) -> ServiceControlOutcome:
    """Windows-only: elevate ``file params`` via ShellExecuteExW "runas", wait, read the exit code.

    A cancelled UAC prompt is a FALSE return with ``GetLastError() == ERROR_CANCELLED`` (verified,
    ADR 0113); a genuine elevation failure is any other FALSE. On success the child is waited on and
    its exit code decides DISPATCHED vs FAILED. Never raises.
    """
    if sys.platform != "win32":  # unreachable at runtime (control_service_ex guards) — narrows mypy
        return ServiceControlOutcome.UNSUPPORTED
    shell32 = ctypes.WinDLL("shell32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    shell32.ShellExecuteExW.argtypes = (ctypes.c_void_p,)
    shell32.ShellExecuteExW.restype = wintypes.BOOL

    info = _SHELLEXECUTEINFOW()
    info.cbSize = ctypes.sizeof(info)
    info.fMask = _SEE_MASK_NOCLOSEPROCESS
    info.lpVerb = "runas"
    info.lpFile = file
    info.lpParameters = params
    info.nShow = _SW_HIDE

    if not shell32.ShellExecuteExW(ctypes.byref(info)):
        err = ctypes.get_last_error()
        return (
            ServiceControlOutcome.CANCELLED
            if err == _ERROR_CANCELLED
            else ServiceControlOutcome.FAILED
        )

    handle = info.hProcess
    if not handle:
        return ServiceControlOutcome.DISPATCHED  # launched, but no handle to wait on

    kernel32.WaitForSingleObject.argtypes = (wintypes.HANDLE, wintypes.DWORD)
    kernel32.WaitForSingleObject.restype = wintypes.DWORD
    kernel32.GetExitCodeProcess.argtypes = (wintypes.HANDLE, wintypes.LPDWORD)
    kernel32.GetExitCodeProcess.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = (wintypes.HANDLE,)
    try:
        kernel32.WaitForSingleObject(handle, _WAIT_TIMEOUT_MS)
        code = wintypes.DWORD()
        if kernel32.GetExitCodeProcess(handle, ctypes.byref(code)) and code.value == 0:
            return ServiceControlOutcome.DISPATCHED
        return ServiceControlOutcome.FAILED
    finally:
        kernel32.CloseHandle(handle)


def control_service_ex(action: str, name: str) -> ServiceControlOutcome:
    """Start/stop/restart ``name`` with one UAC elevation, reporting the outcome (ADR 0113 §4).

    An outcome-aware sibling of :func:`control_service`: it elevates the same System32-only command
    (``cmd.exe /c net …``, single prompt even for restart), but via ShellExecuteExW so it can
    distinguish a cancelled UAC prompt (:data:`ServiceControlOutcome.CANCELLED`) from a failure. It
    never elevates user-writable code. Returns :data:`UNSUPPORTED` off Windows.

    Raises :class:`ValueError` for an unknown ``action`` or a service name with shell metacharacters
    (it is interpolated into an elevated ``cmd.exe`` line — review low-16), *before* the platform
    check so an unsafe input is refused on every OS.
    """
    if action not in _ACTIONS:
        raise ValueError(f"unknown service action {action!r}")
    if not _is_safe_service_name(name):
        raise ValueError(f"unsafe service name {name!r}")
    if sys.platform != "win32":
        return ServiceControlOutcome.UNSUPPORTED
    command = _ACTIONS[action].format("net", name)
    return _runas_wait("cmd.exe", f"/c {command}")


def install_script_path() -> Path | None:
    """Locate ``scripts/service/install-service.ps1`` in the (editable-installed) repo."""
    pkg = messagefoundry.__file__
    if pkg is None:
        return None
    script = Path(pkg).resolve().parents[1] / "scripts" / "service" / "install-service.ps1"
    return script if script.exists() else None


def _install_params(script_path: str, environment: str) -> str:
    """Build the argument string for the elevated installer launch.

    ``environment`` is the active environment the service will run as (``serve --env``); it is
    interpolated into an elevated command line, so reject anything that isn't a plain environment
    name (raises :class:`ValueError`). Validation runs on every platform so it is unit-testable."""
    if not is_safe_environment(environment):
        raise ValueError(f"unsafe environment name {environment!r}")
    return f'-NoExit -ExecutionPolicy Bypass -File "{script_path}" -Environment "{environment}"'


def install_service(script_path: str, environment: str) -> bool:
    """Run the install script elevated in a *visible* PowerShell window (one-time setup, so the
    operator can read the output / 'next steps' and any errors). ``environment`` is the active
    environment the service runs as (ADR 0017 — install-service.ps1 requires it). Returns False off
    Windows. Raises :class:`ValueError` for an unsafe environment name (it runs elevated)."""
    params = _install_params(script_path, environment)  # validates env on every platform
    if sys.platform != "win32":
        return False
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", params, None, 1)
    return True
