# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tray actions: open the console, the repo in VS Code, and the service log (ADR 0113 §5/§7).

Side-effecting shells (open a browser tab, spawn ``code``, open a file) kept thin; the resolution
logic — the exact ``/ui`` URL, whether the ``code`` CLI and repo resolve, whether a log exists — is
pure/injectable so it is unit-testable without launching anything. The tray never opens the bare
engine URL (FastAPI 404s there — there is no ``/`` route); it always appends ``/ui``.
"""

from __future__ import annotations

import ctypes
import ntpath
import os
import re
import shutil
import subprocess
import sys
import webbrowser
from collections.abc import Callable
from pathlib import Path

from messagefoundry.tray.config import is_engine_url

# Common VS Code install locations to try if `code` is not on PATH (user + machine installs).
_VSCODE_FALLBACKS = (
    r"%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code.cmd",
    r"%ProgramFiles%\Microsoft VS Code\bin\code.cmd",
    r"%ProgramFiles(x86)%\Microsoft VS Code\bin\code.cmd",
)
_CREATE_NO_WINDOW = 0x08000000  # keep `code`'s launcher from flashing a console window


def console_url(engine_url: str) -> str:
    """The exact monitor-console URL — always ``<engine_url>/ui``, never the bare root."""
    return engine_url.rstrip("/") + "/ui"


def _is_file(path: str) -> bool:
    return Path(path).is_file()


def _is_dir(path: str) -> bool:
    return Path(path).is_dir()


def resolve_vscode(
    *,
    which: Callable[[str], str | None] = shutil.which,
    is_file: Callable[[str], bool] = _is_file,
    expandvars: Callable[[str], str] = os.path.expandvars,
) -> str | None:
    """Locate the ``code`` CLI: PATH first, then the common install locations. ``None`` if absent."""
    found = which("code")
    if found:
        return found
    for template in _VSCODE_FALLBACKS:
        candidate = expandvars(template)
        if "%" not in candidate and is_file(candidate):
            return candidate
    return None


def repo_open_available(
    repo_path: str | None,
    vscode: str | None,
    *,
    is_dir: Callable[[str], bool] = _is_dir,
) -> bool:
    """True iff Open-Repo can work: a real directory and a resolved ``code`` CLI."""
    return bool(repo_path) and vscode is not None and is_dir(repo_path or "")


def log_available(log_path: str | None, *, is_file: Callable[[str], bool] = _is_file) -> bool:
    """True iff a service log file is known and present."""
    return bool(log_path) and is_file(log_path or "")


class ConsoleUrlRefused(ValueError):
    """Open Console refused ``engine_url`` because it is not a plain http or https URL.

    The message is fixed text. The URL comes from ``tray.toml`` and could carry a secret, and even
    its parsed "scheme" can be a username (``admin:pw@host`` parses as scheme ``admin``), so no
    part of it is echoed.
    """

    def __init__(self) -> None:
        super().__init__("engine_url in tray.toml is not a plain http or https URL with a host")


def open_console(engine_url: str, *, opener: Callable[[str], object] | None = None) -> None:
    """Open ``<engine_url>/ui`` in the default browser, or raise :class:`ConsoleUrlRefused`.

    ``engine_url`` comes from ``tray.toml``, and on Windows ``webbrowser.open`` reaches
    ``os.startfile``, which launches whatever handler owns the scheme. So anything but an http or
    https URL is refused before it reaches the opener (BACKLOG #1993, ASVS 1.2.2). The default
    opener is looked up at call time, so a test can replace ``webbrowser.open``.
    """
    url = console_url(engine_url)
    if not is_engine_url(url):
        raise ConsoleUrlRefused
    (opener or webbrowser.open)(url)


def _run_detached(args: list[str]) -> None:
    creationflags = _CREATE_NO_WINDOW if sys.platform == "win32" else 0
    subprocess.Popen(args, shell=False, creationflags=creationflags)  # nosec B603 - fixed argv (resolved code CLI + repo path), shell=False, no shell interpolation


def open_repo(
    repo_path: str,
    code_cmd: str,
    *,
    runner: Callable[[list[str]], object] = _run_detached,
) -> None:
    """Open ``repo_path`` as a folder in VS Code via the resolved ``code`` CLI (list argv, no shell)."""
    runner([code_cmd, repo_path])


def _open_path(target: str) -> None:
    if sys.platform == "win32":
        os.startfile(target)  # nosec B606 - only a path open_log() approved reaches here (BACKLOG #2086)
    else:
        webbrowser.open(target)


#: The only suffixes View Log hands to the OS opener (BACKLOG #2086). ``os.startfile`` launches
#: whatever handler owns the suffix, so a ``.bat``, ``.lnk``, ``.hta`` or ``.url`` would run.
_VIEWABLE_LOG_SUFFIXES = frozenset({".log", ".txt"})


class LogPathRefused(ValueError):
    """View Log refused ``log_path``: it does not name an existing ``.log`` or ``.txt`` file.

    The message is fixed text. The path comes from ``tray.toml`` or the service's registry hint, so
    no part of it is echoed, which matches :class:`ConsoleUrlRefused`.
    """

    def __init__(self) -> None:
        super().__init__("log_path must name an existing .log or .txt file")


def _viewable_name(path: str) -> bool:
    """True when the last component of ``path`` ends in an allowed suffix, compared casefolded.

    Windows path rules decide it on every OS, since the tray runs only there. Three shapes fail
    on the exact match alone. A trailing dot or space (``x.bat.``) leaves a suffix of ``.`` or
    ``.bat ``, and Windows would strip it. A double suffix (``x.log.bat``) keeps its last one. A
    ``.lnk`` keeps its own suffix, so it is refused without following it. A colon in the name
    names an alternate data stream and is refused outright, because the suffix match alone would
    pass ``run.bat:notes.log``.
    """
    name = ntpath.basename(path)
    if ":" in name:
        return False
    return ntpath.splitext(name)[1].casefold() in _VIEWABLE_LOG_SUFFIXES


#: A local drive path: a drive letter, a colon, then a separator. Nothing else is a local path.
_LOCAL_DRIVE_PATH = re.compile(r"[A-Za-z]:[\\/]")

_DRIVE_REMOTE = 4  # GetDriveTypeW's DRIVE_REMOTE: a mapped network drive


def _is_remote_drive(path: str) -> bool:
    """True when ``path``'s drive letter is a mapped network drive (``GetDriveTypeW``).

    It reads the local drive table and sends nothing to the server. Off Windows the tray does not
    run, so the answer there is False.
    """
    if sys.platform != "win32":
        return False
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    kernel32.GetDriveTypeW.argtypes = [ctypes.c_wchar_p]
    kernel32.GetDriveTypeW.restype = ctypes.c_uint
    return bool(kernel32.GetDriveTypeW(path[:2] + "\\") == _DRIVE_REMOTE)


def _is_local_drive_path(path: str) -> bool:
    """True when ``path`` has the shape of a path on a local drive letter.

    The shape is an allowlist, so every remote form fails it without a list of its own: a UNC path
    (``\\\\host\\share``, ``//host/share``), a WebDAV path (``\\\\host@SSL\\DavWWWRoot``), and the
    device and extended forms (``\\\\?\\UNC\\...``, ``\\\\?\\C:\\...``, ``\\\\.\\...``). So do a
    relative path, a drive-relative one (``C:x.log``), a rooted one with no drive (``\\logs``), and
    the ``shell:``, ``file:`` and ``https:`` forms the OS opener would launch.
    """
    return _LOCAL_DRIVE_PATH.match(path) is not None


def open_log(
    log_path: str,
    *,
    opener: Callable[[str], object] = _open_path,
    resolve: Callable[[str], str] = os.path.realpath,
    is_file: Callable[[str], bool] = _is_file,
    is_remote_drive: Callable[[str], bool] = _is_remote_drive,
) -> None:
    """Open the service log in the default text viewer, or raise :class:`LogPathRefused`.

    ``log_path`` comes from ``tray.toml`` or the NSSM ``AppStdout`` registry value, and every check
    runs before the opener (BACKLOG #2086).

    The configured string is judged first, before anything touches the file system, so no probe
    can reach a remote host. It must name a path on a local drive letter
    (:func:`_is_local_drive_path`), that drive must not be a mapped network drive, and the name
    must pass :func:`_viewable_name`.

    Then the path is resolved, and the resolved target must pass the same shape and name tests and
    be a file. The opener gets that resolved path. So a symlink named ``x.log`` that points at
    ``evil.bat`` or at a UNC path is refused. ``os.path.realpath`` follows symlinks and junctions.
    It does not follow a shell ``.lnk``, which is why a ``.lnk`` is refused by its own suffix.

    Residual: resolving a local symlink that points at a UNC path reaches that host before the
    resolved target is refused. Planting one needs write access to the log's own directory.
    """
    if (
        not _is_local_drive_path(log_path)
        or not _viewable_name(log_path)
        or is_remote_drive(log_path)
    ):
        raise LogPathRefused
    # The refusal is raised outside the handler, so the OSError (which quotes the path) is not
    # chained onto it (tests/test_from_none_is_not_redaction.py).
    target: str | None
    try:
        target = resolve(log_path)
    except (OSError, ValueError):
        target = None
    if (
        target is None
        or not _is_local_drive_path(target)
        or not _viewable_name(target)
        or is_remote_drive(target)
        or not is_file(target)
    ):
        raise LogPathRefused
    opener(target)
