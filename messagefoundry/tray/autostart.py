# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opt-in autostart via the HKCU Run key (ADR 0113 §9).

Autostart is **off by default** and toggled from the menu. The launch command pins the **absolute**
``pythonw.exe`` of the running interpreter, so a Start-at-Login entry runs the interpreter the tray
was installed into. The working directory is a risk as well, not only the interpreter. A plain
``-m`` start puts the working directory first on the import path. Windows, not this code, picks the
working directory of a Run-key start (vault BACKLOG #2822).

So the command carries :data:`~messagefoundry.childenv.CHILD_INTERPRETER_FLAGS`, which include
``-P``, and takes one of two forms:

* **Installed** (the package sits in a site-packages folder): ``-m messagefoundry.tray``. On a
  ``-m`` start, ``-P`` drops the working directory, and the interpreter finds the package in
  site-packages. This is the short form.
* **Source checkout** (anything else, editable installs included): the child bootstrap script by
  its absolute path, as :func:`~messagefoundry.childenv.python_child_argv` builds it. ``-P`` on a
  ``-m`` start cannot find a package that is not installed; the bootstrap finds it from its own
  location.

Windows documents a Run value as a command line of at most :data:`RUN_VALUE_LIMIT` characters
(vault BACKLOG #2837). Enabling refuses a longer command: it logs a warning, removes any value
already there, and reports autostart off. It never falls back to a command without the flags.

Branding (``MessageFoundryTray.exe``, ADR 0113) is applied at runtime by the ``__main__`` re-exec,
so autostart never depends on the derived branded exe surviving between logins. The command builder
is pure and tested; the ``winreg`` read and write is Windows-only and guarded.
"""

from __future__ import annotations

import contextlib
import logging
import os
import site
import subprocess
import sys
from pathlib import Path

from messagefoundry.childenv import CHILD_INTERPRETER_FLAGS, python_child_argv
from messagefoundry.tray import ENTRY_MODULE

log = logging.getLogger("messagefoundry.tray.autostart")

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_VALUE_NAME = "MessageFoundryTray"

#: The longest command line Microsoft documents for a Run or RunOnce value ("Run and RunOnce
#: Registry Keys", learn.microsoft.com).
RUN_VALUE_LIMIT = 260

#: The folder that holds the ``messagefoundry`` package this module belongs to.
_PACKAGE_ROOT = Path(__file__).resolve().parents[2]


def pythonw_executable(executable: str | None = None) -> str:
    """The console-less interpreter to launch with: the ``pythonw.exe`` beside ``sys.executable``."""
    exe = Path(executable or sys.executable)
    candidate = exe.with_name("pythonw.exe")
    return str(candidate if candidate.exists() else exe)


def _norm(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(path))


def installed_in_site_packages(package_root: Path = _PACKAGE_ROOT) -> bool:
    """Whether the package sits in one of this interpreter's site-packages folders, where a ``-P``
    ``-m`` start finds it. False for a source checkout, editable installs included."""
    sites = list(site.getsitepackages())
    if site.ENABLE_USER_SITE:
        sites.append(site.getusersitepackages())
    return _norm(package_root) in {_norm(entry) for entry in sites if entry}


def launcher_command(pythonw: str | None = None, *, installed: bool | None = None) -> str:
    """The HKCU Run command string, quoted by ``subprocess.list2cmdline`` the way the Windows
    command-line parser reads it back. ``installed`` defaults to
    :func:`installed_in_site_packages`; the module docstring describes both forms."""
    exe = pythonw or pythonw_executable()
    if installed is None:
        installed = installed_in_site_packages()
    if installed:
        argv = [exe, *CHILD_INTERPRETER_FLAGS, "-m", ENTRY_MODULE]
    else:
        argv = python_child_argv(ENTRY_MODULE, executable=exe)
    return subprocess.list2cmdline(argv)


def checked_launcher_command() -> str | None:
    """:func:`launcher_command`, or ``None`` with a logged warning when it is longer than
    :data:`RUN_VALUE_LIMIT`."""
    command = launcher_command()
    if len(command) > RUN_VALUE_LIMIT:
        log.warning(
            "Start at Login was not turned on: the login command is %d characters, and Windows "
            "documents %d as the longest a Run value may be. Install the tray in a shorter folder.",
            len(command),
            RUN_VALUE_LIMIT,
        )
        return None
    return command


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
    venv rebuild or repo move is corrected on the next toggle. A command over
    :data:`RUN_VALUE_LIMIT` is refused: the value is removed and the result is False.
    """
    if sys.platform != "win32":
        return False
    import winreg

    command = checked_launcher_command() if enabled else None
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, _RUN_KEY) as key:
        if command is not None:
            winreg.SetValueEx(key, _VALUE_NAME, 0, winreg.REG_SZ, command)
            return True
        with contextlib.suppress(OSError):
            winreg.DeleteValue(key, _VALUE_NAME)
        return False
