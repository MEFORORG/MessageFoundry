# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tray actions: open the console, the repo in VS Code, and the service log (ADR 0113 §5/§7).

Side-effecting shells (open a browser tab, start VS Code, open a file) kept thin; the resolution
logic — the exact ``/ui`` URL, whether a VS Code launcher and repo resolve, whether a log exists — is
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
from collections.abc import Callable, Iterator
from pathlib import Path

from messagefoundry.controlchars import has_control_char
from messagefoundry.tray.config import is_engine_url

# Common VS Code install locations to try if `code` is not on PATH (user + machine installs).
_VSCODE_FALLBACKS = (
    r"%LOCALAPPDATA%\Programs\Microsoft VS Code\bin\code.cmd",
    r"%ProgramFiles%\Microsoft VS Code\bin\code.cmd",
    r"%ProgramFiles(x86)%\Microsoft VS Code\bin\code.cmd",
)
_CREATE_NO_WINDOW = 0x08000000  # keep `code`'s launcher from flashing a console window

#: The editor executable a standard install keeps one folder above its ``bin`` folder. The
#: ``code.cmd`` in ``bin`` starts it by that relative path itself.
_VSCODE_EXE = "Code.exe"
#: Suffixes Windows runs under ``cmd.exe``.
_BATCH_SUFFIXES = frozenset({".cmd", ".bat"})
#: Characters ``cmd.exe`` reads as syntax in a batch file's command line. Quoting does not make
#: them all safe: ``%`` expands inside double quotes, and so does ``!`` under delayed expansion.
#: ``,`` ``;`` and ``=`` are argument delimiters there: in an unquoted batch-file path they cut
#: the program name short, so a different file can run. :func:`_cmd_would_reread` adds control
#: characters. docs/TRAY.md shows operators this set, and a test holds the two together.
_CMD_REREAD_CHARS = frozenset('&|<>^%!()",;=')
#: Electron reads this as "run as plain Node, not as the editor". ``code.cmd`` manages it itself;
#: a direct start of the editor must not inherit it.
_ELECTRON_RUN_AS_NODE = "ELECTRON_RUN_AS_NODE"


def console_url(engine_url: str) -> str:
    """The exact monitor-console URL — always ``<engine_url>/ui``, never the bare root."""
    return engine_url.rstrip("/") + "/ui"


def _is_file(path: str) -> bool:
    return Path(path).is_file()


def _is_dir(path: str) -> bool:
    return Path(path).is_dir()


def _is_batch_file(path: str) -> bool:
    """True when Windows would run ``path`` under ``cmd.exe`` (a ``.cmd`` or ``.bat`` file).

    Windows drops trailing dots and spaces from a file name, so ``code.cmd.`` is judged without
    them.
    """
    return ntpath.splitext(path.rstrip(". "))[1].casefold() in _BATCH_SUFFIXES


def _cmd_would_reread(text: str) -> bool:
    """True when ``text`` has a ``cmd.exe`` metacharacter or a control character (CR, LF, ...)."""
    return has_control_char(text) or any(ch in _CMD_REREAD_CHARS for ch in text)


def _launcher_for(cli: str, is_file: Callable[[str], bool]) -> str | None:
    """The program Open Repo starts for the ``code`` CLI found at ``cli``, or ``None``.

    A batch ``code.cmd`` is replaced by the editor executable beside its ``bin`` folder when that
    file exists, so ``cmd.exe`` takes no part in the launch (BACKLOG #2327). With no such
    executable (a shim, or a layout this does not know) the batch file is all there is, and it is
    used only if ``cmd.exe`` would not re-read its own path. Anything else is returned as found.
    """
    if not _is_batch_file(cli):
        return cli
    bin_dir = ntpath.dirname(cli)
    if ntpath.basename(bin_dir).casefold() == "bin":
        exe = ntpath.join(ntpath.dirname(bin_dir), _VSCODE_EXE)
        if is_file(exe):
            return exe
    return None if _cmd_would_reread(cli) else cli


def resolve_vscode(
    *,
    which: Callable[[str], str | None] = shutil.which,
    is_file: Callable[[str], bool] = _is_file,
    expandvars: Callable[[str], str] = os.path.expandvars,
) -> str | None:
    """Locate the program that opens a folder in VS Code. ``None`` if there is none to use.

    The ``code`` CLI is looked up on PATH first, then in the common install locations. Each one
    found goes through :func:`_launcher_for`, so the result is the editor executable where a
    standard install has one, and a batch file only as the fallback :func:`open_repo` screens.
    """

    def found_clis() -> Iterator[str]:  # lazy: a usable PATH hit probes no install location
        on_path = which("code")
        if on_path:
            yield on_path
        for template in _VSCODE_FALLBACKS:
            candidate = expandvars(template)
            if "%" not in candidate and is_file(candidate):
                yield candidate

    for cli in found_clis():
        launcher = _launcher_for(cli, is_file)
        if launcher is not None:
            return launcher
    return None


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


def _on_a_local_drive(path: str, is_remote_drive: Callable[[str], bool]) -> bool:
    """True when ``path`` is on a local drive letter that is not a mapped network drive.

    It judges the string and the local drive table only, so it sends nothing to any host. At
    least :func:`open_log` and the two menu predicates run their probes behind it (BACKLOG #2086,
    #2332). Other configured paths, such as ``engine_cacert``, do not pass through it.
    """
    return _is_local_drive_path(path) and not is_remote_drive(path)


def repo_open_available(
    repo_path: str | None,
    vscode: str | None,
    *,
    is_dir: Callable[[str], bool] = _is_dir,
    is_remote_drive: Callable[[str], bool] = _is_remote_drive,
) -> bool:
    """True iff Open-Repo is offered: a real directory on a local drive and a resolved launcher.

    Offered is not the same as opened: :func:`open_repo` can still refuse the path, and says why.

    The menu calls this on every build, so the path is screened by :func:`_on_a_local_drive`
    before ``is_dir`` touches it. A UNC or mapped-drive ``repo_path`` is never probed.
    """
    if not repo_path or vscode is None:
        return False
    return _on_a_local_drive(repo_path, is_remote_drive) and is_dir(repo_path)


def log_available(
    log_path: str | None,
    *,
    is_file: Callable[[str], bool] = _is_file,
    is_remote_drive: Callable[[str], bool] = _is_remote_drive,
) -> bool:
    """True iff a service log file is known, on a local drive, and present.

    The menu calls this on every build, so the path gets the same no-touch screen
    :func:`open_log` applies before ``is_file`` touches it (BACKLOG #2332). A UNC, device,
    relative or mapped-drive ``log_path`` is never probed, and View Log would refuse it anyway.
    """
    if not log_path:
        return False
    return _on_a_local_drive(log_path, is_remote_drive) and is_file(log_path)


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
    # The child gets the tray's environment, which is the signed-in user's, less the one variable
    # that would make the editor executable run the folder as a script.
    env = {k: v for k, v in os.environ.items() if k.upper() != _ELECTRON_RUN_AS_NODE}
    # shell=False does not keep cmd.exe out of a batch-file launch; see open_repo().
    subprocess.Popen(args, shell=False, creationflags=creationflags, env=env)  # nosec B603 - argv is the launcher resolve_vscode() chose plus repo_path as one list item; open_repo() screens the batch-file case (BACKLOG #2327)


class RepoPathRefused(ValueError):
    """Open Repo refused a batch-file launch that ``cmd.exe`` would re-read.

    The message is fixed text. ``repo_path`` comes from ``tray.toml`` or the service's registry
    hint, so no part of it is echoed, which matches :class:`ConsoleUrlRefused`.
    """

    def __init__(self) -> None:
        super().__init__(
            "the code launcher is a batch file, and its path or repo_path has a character "
            "the Windows command shell would re-read"
        )


def open_repo(
    repo_path: str,
    launcher: str,
    *,
    runner: Callable[[list[str]], object] = _run_detached,
) -> None:
    """Open ``repo_path`` as a folder in VS Code, or raise :class:`RepoPathRefused`.

    ``launcher`` is what :func:`resolve_vscode` returned. Normally that is the editor executable,
    which takes the folder as one argv item with no shell, so any folder name opens.

    The fallback is a batch file, used when no editor executable was found beside it. Windows runs
    a batch file under ``cmd.exe``, which re-reads the whole command line, and Python's argv
    quoting does not escape ``&``, ``|`` or ``%``. ``cmd.exe`` cannot be avoided there, so the
    launch is refused when either string fails :func:`_cmd_would_reread`. Nothing is escaped. That
    test is wider than ``cmd.exe`` needs: it also refuses characters that are harmless in some
    positions, such as parentheses or a quoted ``&``.
    """
    # resolve_vscode() never returns a batch file whose own path fails the test. The launcher is
    # tested again here because this is the last stop before the start, whoever the caller is.
    if _is_batch_file(launcher) and (_cmd_would_reread(repo_path) or _cmd_would_reread(launcher)):
        raise RepoPathRefused
    runner([launcher, repo_path])


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
    if not _viewable_name(log_path) or not _on_a_local_drive(log_path, is_remote_drive):
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
        or not _viewable_name(target)
        or not _on_a_local_drive(target, is_remote_drive)
        or not is_file(target)
    ):
        raise LogPathRefused
    opener(target)
