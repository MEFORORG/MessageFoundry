# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Opt-in autostart via the HKCU Run key (ADR 0113 §9).

Autostart is **off by default** and toggled from the menu. The launch command pins the **absolute**
``pythonw.exe`` of the running interpreter (the real risk is the *wrong* interpreter, not the cwd —
the editable install exposes the repo root on ``sys.path``), so a Start-at-Login entry resolves
``-m messagefoundry.tray`` regardless of where Explorer launches it. Branding (``MessageFoundryTray.exe`` — ADR
0113) is applied at runtime by the ``__main__`` re-exec, so autostart never depends on the derived
branded exe surviving between logins. The command builder is pure/tested; the ``winreg`` read/write
is Windows-only and guarded.
"""

from __future__ import annotations

import contextlib
import sys
from pathlib import Path

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_VALUE_NAME = "MessageFoundryTray"


def pythonw_executable(executable: str | None = None) -> str:
    """The console-less interpreter to launch with: the ``pythonw.exe`` beside ``sys.executable``."""
    exe = Path(executable or sys.executable)
    candidate = exe.with_name("pythonw.exe")
    return str(candidate if candidate.exists() else exe)


def launcher_command(pythonw: str | None = None) -> str:
    """The HKCU Run command string: ``"<abs pythonw.exe>" -m messagefoundry.tray`` (quoted, absolute)."""
    return f'"{pythonw or pythonw_executable()}" -m messagefoundry.tray'


def is_autostart_enabled() -> bool:
    """True iff the Run value is present. Windows-only; False (and never raises) elsewhere."""
    if sys.platform != "win32":
        return False
    import winreg

    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
            winreg.QueryValueEx(key, _VALUE_NAME)
    except OSError:
        return False
    return True


def set_autostart(enabled: bool) -> bool:
    """Add or remove the Run value. Returns the resulting enabled state. Windows-only (else False).

    Self-heals a stale value: enabling always rewrites the current absolute launcher command, so a
    venv rebuild or repo move is corrected on the next toggle.
    """
    if sys.platform != "win32":
        return False
    import winreg

    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
        if enabled:
            winreg.SetValueEx(key, _VALUE_NAME, 0, winreg.REG_SZ, launcher_command())
            return True
        with contextlib.suppress(OSError):
            winreg.DeleteValue(key, _VALUE_NAME)
        return False
