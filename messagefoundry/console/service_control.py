"""Windows service control for the Engine Status page.

The engine can't control its *own* hosting service through the API (stopping it kills the API;
once stopped there's no API to start it), and service control needs admin rights — so this is
done locally via the Windows SCM: ``sc query`` for state (no elevation) and an elevated
``net start/stop`` for actions (one UAC prompt each). Same-machine, Windows-only; on other
platforms / when ``sc`` is absent, state is ``"unavailable"`` and actions are no-ops.

Elevated actions are fire-and-forget (the elevated process is detached, so output isn't
captured) — poll :func:`service_state` to observe the result.
"""

from __future__ import annotations

import ctypes
import re
import subprocess
import sys
from pathlib import Path

import messagefoundry

__all__ = [
    "service_state",
    "control_service",
    "parse_service_state",
    "install_script_path",
    "install_service",
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
        proc = subprocess.run(["sc", "query", name], capture_output=True, text=True, timeout=5)  # nosec B603 B607
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


def install_script_path() -> Path | None:
    """Locate ``scripts/service/install-service.ps1`` in the (editable-installed) repo."""
    pkg = messagefoundry.__file__
    if pkg is None:
        return None
    script = Path(pkg).resolve().parents[1] / "scripts" / "service" / "install-service.ps1"
    return script if script.exists() else None


def install_service(script_path: str) -> bool:
    """Run the install script elevated in a *visible* PowerShell window (one-time setup, so the
    operator can read the output / 'next steps' and any errors). Returns False off Windows."""
    if sys.platform != "win32":
        return False
    params = f'-NoExit -ExecutionPolicy Bypass -File "{script_path}"'
    ctypes.windll.shell32.ShellExecuteW(None, "runas", "powershell.exe", params, None, 1)
    return True
