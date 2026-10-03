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

* Where the interpreter can import the package on its own, from a site-packages folder or a
  ``.pth`` entry in one (an editable install), the short form from
  :func:`~messagefoundry.childenv.python_module_argv`: ``-m messagefoundry.tray``. On a ``-m``
  start, ``-P`` drops the working directory.
* Anywhere else, the child bootstrap script by its absolute path, from
  :func:`~messagefoundry.childenv.python_child_argv`. A ``-P -m`` start cannot find a package the
  interpreter has not been told about; the bootstrap finds it from its own location.

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

from messagefoundry.childenv import python_child_argv, python_module_argv
from messagefoundry.tray import ENTRY_MODULE

log = logging.getLogger("messagefoundry.tray.autostart")

_RUN_KEY = r"Software\Microsoft\Windows\CurrentVersion\Run"
_VALUE_NAME = "MessageFoundryTray"

#: The longest command line Microsoft documents for a Run or RunOnce value ("Run and RunOnce
#: Registry Keys", learn.microsoft.com: "no longer than 260 characters").
RUN_VALUE_LIMIT = 260


def pythonw_executable(executable: str | None = None) -> str:
    """The console-less interpreter to launch with: the ``pythonw.exe`` beside ``sys.executable``."""
    exe = Path(executable or sys.executable)
    candidate = exe.with_name("pythonw.exe")
    return str(candidate if candidate.exists() else exe)


def _norm(path: str | Path) -> str:
    return os.path.normcase(os.path.realpath(path))


def _pth_paths(site_dir: str) -> set[str]:
    """The folders the ``.pth`` files in ``site_dir`` add to the path, read the way ``site`` reads
    them but never executed: comment and ``import`` lines are skipped."""
    found: set[str] = set()
    with contextlib.suppress(OSError):
        for pth in Path(site_dir).glob("*.pth"):
            with contextlib.suppress(OSError):
                for line in pth.read_text(encoding="utf-8-sig", errors="replace").splitlines():
                    entry = line.strip()
                    if entry and not entry.startswith(("#", "import ", "import\t")):
                        found.add(_norm(os.path.join(site_dir, entry)))
    return found


def installed_in_site_packages(package_root: Path | None = None) -> bool:
    """Whether the running interpreter imports the package from its site configuration, with no
    working directory and no bootstrap: the folder holding it is a site-packages folder, or a
    ``.pth`` file in one names it. A source checkout run any other way is not."""
    root = _norm(package_root or Path(__file__).resolve().parents[2])
    sites = [entry for entry in site.getsitepackages() if entry]
    if site.ENABLE_USER_SITE and site.getusersitepackages():
        sites.append(site.getusersitepackages())
    return any(root == _norm(entry) or root in _pth_paths(entry) for entry in sites)


def launcher_command(pythonw: str | None = None, *, installed: bool | None = None) -> str:
    """The HKCU Run command string, quoted by ``subprocess.list2cmdline`` the way the Windows
    command-line parser reads it back. ``installed`` defaults to :func:`installed_in_site_packages`
    for the RUNNING interpreter, so pass ``pythonw`` only for that interpreter or with
    ``installed``. The module docstring describes both forms."""
    exe = pythonw or pythonw_executable()
    if installed is None:
        installed = installed_in_site_packages()
    build = python_module_argv if installed else python_child_argv
    return subprocess.list2cmdline(build(ENTRY_MODULE, executable=exe))


def _windows_length(command: str) -> int:
    """Length as Windows counts it, in UTF-16 code units: a character outside the Basic
    Multilingual Plane counts twice."""
    return len(command.encode("utf-16-le")) // 2


def checked_launcher_command() -> str | None:
    """:func:`launcher_command`, or ``None`` with a logged warning when it is longer than
    :data:`RUN_VALUE_LIMIT`."""
    command = launcher_command()
    length = _windows_length(command)
    if length > RUN_VALUE_LIMIT:
        # Lower case on purpose: tray.log's redactor reads a run of capitalized words as a name.
        log.warning(
            "autostart not turned on: the login command is %d characters, over the %d that Windows "
            "documents for a Run value; install the tray in a shorter folder",
            length,
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
