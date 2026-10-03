# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opt-in autostart via the HKCU Run key (ADR 0113 §9).

Autostart is **off by default** and toggled from the menu. The launch command pins the **absolute**
``pythonw.exe`` of the running interpreter, so a Start-at-Login entry runs the interpreter the tray
was installed into. The working directory is a risk as well, not only the interpreter. A ``-m``
start puts the working directory first on the import path, and Windows, not this code, picks the
working directory of a Run-key start. So the command starts the tray the way the engine starts its
Python children, through :func:`messagefoundry.childenv.python_child_argv` (vault BACKLOG #2822):
``-P`` and ``-X disable-remote-debug``, then the child bootstrap script by its absolute path. A
script start never searches the working directory, and ``-P`` drops the script's own folder, so a
file planted in either cannot stand in for a module the first tray process imports. ``-P`` on a
``-m`` start is not enough: from a checkout that is not installed, the interpreter then cannot find
the package. The bootstrap finds it from its own location.

Branding (``MessageFoundryTray.exe``, ADR 0113) is applied at runtime by the ``__main__`` re-exec,
so autostart never depends on the derived branded exe surviving between logins. The command builder
is pure and tested; the ``winreg`` read and write is Windows-only and guarded.
"""

from __future__ import annotations

import contextlib
import subprocess
import sys
from pathlib import Path

from messagefoundry.childenv import python_child_argv

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_VALUE_NAME = "MessageFoundryTray"
_MODULE = "messagefoundry.tray"


def pythonw_executable(executable: str | None = None) -> str:
    """The console-less interpreter to launch with: the ``pythonw.exe`` beside ``sys.executable``."""
    exe = Path(executable or sys.executable)
    candidate = exe.with_name("pythonw.exe")
    return str(candidate if candidate.exists() else exe)


def launcher_command(pythonw: str | None = None) -> str:
    """The HKCU Run command string: :func:`~messagefoundry.childenv.python_child_argv` joined by
    ``subprocess.list2cmdline``, which quotes the way the Windows command-line parser reads back.
    ``<abs pythonw.exe> -P -X disable-remote-debug <abs _child_bootstrap.py> messagefoundry.tray``.
    """
    return subprocess.list2cmdline(
        python_child_argv(_MODULE, executable=pythonw or pythonw_executable())
    )


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
