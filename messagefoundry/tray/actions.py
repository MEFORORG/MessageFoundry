# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tray actions: open the console, the repo in VS Code, and the service log (ADR 0113 §5/§7).

Side-effecting shells (open a browser tab, spawn ``code``, open a file) kept thin; the resolution
logic — the exact ``/ui`` URL, whether the ``code`` CLI and repo resolve, whether a log exists — is
pure/injectable so it is unit-testable without launching anything. The tray never opens the bare
engine URL (FastAPI 404s there — there is no ``/`` route); it always appends ``/ui``.
"""

from __future__ import annotations

import os
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
        os.startfile(target)  # nosec B606 - opens a local path in the user's default viewer, their ACLs apply
    else:
        webbrowser.open(target)


def open_log(log_path: str, *, opener: Callable[[str], object] = _open_path) -> None:
    """Open the service log in the default text viewer (read access is the operator's own ACLs)."""
    opener(log_path)
