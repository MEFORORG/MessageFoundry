# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Where fleet coordination state lives: the Python twin of ``scripts/coord/coord-root.ps1``.

That file's header is the source of record for the two roots, the resolution order, the root.toml
format and the reachability probe. This module answers the same questions for the Python git hooks
and out-of-repo helpers, and ``tests/test_coord_root.py`` holds the two to one answer.

Stdlib only, and it imports nothing from ``messagefoundry``: the installed git hooks run it from
``.git/hooks`` with whatever interpreter the hook found. The hooks load this file by path rather than
carry a copy, and ``install-git-hooks.ps1`` puts it beside them.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess  # nosec B404 - fixed argv, no shell
import threading
import time
from dataclasses import dataclass
from pathlib import Path

SHARED_KINDS: tuple[str, ...] = (
    "seats",
    "mail",
    "claims",
    "alloc",
    "handoffs",
    "wiki",
    "lanes",
    "owner-log",
)
ROOT_ENV = "MEFOR_COORD_ROOT"
ROOT_FILE = "root.toml"
DOWN_FILE = "coord-root-down.json"
DOWN_TTL_SECONDS = 60
PROBE_TIMEOUT_SECONDS = 1.5

# ASCII space and tab only, on both twins. Python's \s and str.strip() also take \x1c-\x1f and \x85,
# which .NET's do not, so a stray control character would resolve on one side and fail on the other.
_WS = " \t\r\n"
_ROOT_LINE = re.compile(r"\A[ \t]*shared_root[ \t]*=[ \t]*'([^']*)'[ \t]*(#.*)?\Z")
_BLANK_OR_COMMENT = re.compile(r"\A[ \t]*(#.*)?\Z")
_LINE_BREAK = re.compile(r"\r\n|\n|\r")
# A drive letter, colon and separator, a UNC \\server\share, or (off Windows) a leading slash.
_ABSOLUTE = re.compile(r"\A(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+|/(?![\\/]))")
_UNC = re.compile(r"\A[\\/]{2}([^\\/]+)[\\/]")


@dataclass(frozen=True)
class CoordDir:
    path: Path | None
    shared: bool
    source: str
    error: str | None


def local_root(start: str | os.PathLike[str] | None = None) -> Path | None:
    """``<git-common-dir>/mefor-coord`` for the repository at ``start``, or None when git cannot say."""
    args = ["git"]
    if start:
        args += ["-C", str(start)]
    args += ["rev-parse", "--path-format=absolute", "--git-common-dir"]
    try:
        proc = subprocess.run(args, capture_output=True, text=True, check=False)  # nosec B603 B607 - fixed argv, no shell
    except OSError:
        return None
    common = proc.stdout.strip()
    if proc.returncode != 0 or not common:
        return None
    return Path(common) / "mefor-coord"


def shared_root(
    start: str | os.PathLike[str] | None = None, *, local: Path | None = None
) -> tuple[Path | None, str, str | None]:
    """``(path, source, error)``. ``source`` is ``env``, ``file`` or ``local``; path is None on error.

    No probe; ``resolve_shared_root`` adds one. A caller already holding ``<common>/mefor-coord``
    passes it as ``local`` and no git process is spawned.
    """
    env = os.environ.get(ROOT_ENV, "").strip(_WS)
    if env:
        if not _absolute(env):
            return None, "env", f"{ROOT_ENV} is not an absolute path: {env}"
        return Path(env), "env", None
    if local is None:
        local = local_root(start)
    if local is None:
        return None, "local", f"git could not name the common dir for '{start}'"
    file = local / ROOT_FILE
    try:
        if not file.exists():
            return local, "local", None
        if not file.is_file():
            return None, "file", f"{file} exists but is not a file"
        text = _decode(file.read_bytes())
    except OSError as exc:
        return None, "file", f"{file} could not be read: {exc}"
    except UnicodeDecodeError:
        return None, "file", f"{file} is not UTF-8 or UTF-16 with a byte-order mark"
    found: str | None = None
    # CR/LF only, as the PowerShell twin splits; str.splitlines() also breaks on \x0b, \x0c,
    # \x1c-\x1e, \x85 and \u2028, so the two would read different lines out of one file.
    for line in _LINE_BREAK.split(text):
        if _BLANK_OR_COMMENT.match(line):
            continue
        m = _ROOT_LINE.match(line)
        if not m or not m.group(1).strip(_WS):
            return (
                None,
                "file",
                f"{file} has a line that is not shared_root = '<path>' (single quotes): {line}",
            )
        if found is not None:
            return None, "file", f"{file} names shared_root more than once"
        found = m.group(1).strip(_WS)
    if found is None:
        return None, "file", f"{file} names no shared_root"
    if not _absolute(found):
        return None, "file", f"{file} names a shared_root that is not an absolute path: {found}"
    return Path(found), "file", None


def _absolute(path: str) -> bool:
    """A drive-rooted or UNC path. A relative root resolves against each process's own cwd, which
    puts two sessions on two registries; ``C:share`` and ``\\share`` are relative on Windows too."""
    return bool(_ABSOLUTE.match(path))


def _decode(raw: bytes) -> str:
    """UTF-16 with a BOM, UTF-8 with or without one, strictly. The PowerShell twin decodes the same way."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16")
    if raw.startswith(b"\xef\xbb\xbf"):
        raw = raw[3:]
    return raw.decode("utf-8", errors="strict")


def unc_host(path: str) -> str | None:
    m = _UNC.match(path)
    return m.group(1) if m else None


def probe_root(path: Path, local: Path | None) -> str | None:
    """None when ``path`` answers; else why not. Fast on a dead SMB server."""
    server = unc_host(str(path))
    if server:
        down = local / DOWN_FILE if local else None
        # The verdict is about ONE root. A cache written for another root, or stamped in the future by a
        # skewed clock or a copied file, is ignored rather than trusted.
        try:
            if down is not None and down.is_file():
                age = time.time() - down.stat().st_mtime
                cached = json.loads(down.read_text(encoding="utf-8")).get("root")
                if cached == str(path) and 0 <= age < DOWN_TTL_SECONDS:
                    return f"shared root {path} was unreachable {int(age)} s ago (cached in {down})"
        except (OSError, ValueError, AttributeError):
            pass
        if not _reachable(server):
            if down is not None:
                try:
                    down.parent.mkdir(parents=True, exist_ok=True)
                    down.write_text(
                        json.dumps(
                            {
                                "root": str(path),
                                "at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                            }
                        ),
                        encoding="utf-8",
                    )
                except OSError:
                    pass
            ms = int(PROBE_TIMEOUT_SECONDS * 1000)
            return f"shared root {path} is unreachable: no answer from {server}:445 within {ms} ms"
    try:
        if path.is_dir():
            return None
    except OSError as exc:
        return f"shared root {path} cannot be read: {exc}"
    return f"shared root {path} does not exist or is not a directory"


def _reachable(server: str) -> bool:
    """A TCP connect to port 445, bounded as a WHOLE by PROBE_TIMEOUT_SECONDS.

    ``socket.create_connection``'s timeout covers each connect, not name resolution, and it tries every
    resolved address in turn. Measured: an unresolvable single-label name took 7.2 s with a 1.5 s
    timeout. So the attempt runs on a daemon thread and the caller waits only the bound.
    """
    result: list[bool] = []

    def attempt() -> None:
        try:
            with socket.create_connection((server, 445), timeout=PROBE_TIMEOUT_SECONDS):
                result.append(True)
        except OSError:
            result.append(False)

    t = threading.Thread(target=attempt, daemon=True)
    t.start()
    t.join(PROBE_TIMEOUT_SECONDS)
    return bool(result and result[0])


def resolve_shared_root(
    start: str | os.PathLike[str] | None = None, *, local: Path | None = None
) -> tuple[Path | None, str, str | None]:
    """The shared root itself, probed: ``(path, source, error)``.

    A caller needing several shared kinds resolves once and joins each kind onto the path.
    """
    if local is None:
        local = local_root(start)
    root, source, error = shared_root(start, local=local)
    if error is not None or root is None:
        return None, source, error or "no shared root"
    if source != "local":
        why = probe_root(root, local)
        if why is not None:
            return None, source, why
    return root, source, None


def resolve(
    kind: str, start: str | os.PathLike[str] | None = None, *, local: Path | None = None
) -> CoordDir:
    """The directory for one kind of coordination state. Never falls back to LOCAL for a shared kind."""
    if local is None:
        local = local_root(start)
    if kind not in SHARED_KINDS:
        if local is None:
            return CoordDir(
                None, False, "local", f"git could not name the common dir for '{start}'"
            )
        return CoordDir(local / kind, False, "local", None)
    root, source, error = resolve_shared_root(start, local=local)
    if root is None:
        return CoordDir(None, True, source, error or "no shared root")
    return CoordDir(root / kind, True, source, None)


def host() -> str:
    """The name every shared record carries. Matches PowerShell's ``[Environment]::MachineName``."""
    return os.environ.get("COMPUTERNAME") or socket.gethostname().split(".")[0].upper()


# What a host field that is present but not a string reads as. It never equals a machine name, so the
# record is NOT CHECKABLE HERE: only an ABSENT field means legacy, and guessing "this machine" for a
# malformed one would let this disk judge, and reap, another PC's record.
UNREADABLE_HOST = "<unreadable host>"


def record_host(record: object) -> str:
    """The host a record names, stripped; '' when it names none; UNREADABLE_HOST when it is not text."""
    if not isinstance(record, dict) or record.get("host") is None:
        return ""
    value = record["host"]
    return value.strip(_WS) if isinstance(value, str) else UNREADABLE_HOST


def record_is_here(record: object) -> bool:
    """True when a record is this machine's to judge: it names no host, or names this one."""
    recorded = record_host(record)
    return not recorded or recorded.casefold() == host().casefold()


# The SMB read retry, the same numbers as Read-CoordText in coord-root.ps1, whose header says why it
# exists. Python only reads shared records, so the rename half of that helper has no twin here.
RETRY_TRIES = 8
RETRY_FIRST_SECONDS = 0.025
RETRY_MAX_SLEEP_SECONDS = 0.25
# ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION.
_SHARING_WINERRORS = frozenset({32, 33})


def sharing_violation(exc: OSError) -> bool:
    """True for what a Windows sharing or lock violation can look like. Never for a missing file.

    Measured 2026-10-21: ``open()`` goes through the C runtime, which reports a sharing violation as a
    bare ``PermissionError(13)`` with no ``winerror``. That is indistinguishable from a real access
    denial, so on Windows both are retried; a real denial costs one bounded wait, then raises as before.
    """
    winerror = getattr(exc, "winerror", None)
    if winerror is not None:
        return winerror in _SHARING_WINERRORS
    return os.name == "nt" and isinstance(exc, PermissionError)


def read_text(path: str | os.PathLike[str], encoding: str = "utf-8") -> str:
    """A file's text, retrying a sharing violation briefly.

    A missing file raises FileNotFoundError at once. When the tries run out, the last sharing
    violation propagates, so a caller never reads one as "missing" or "torn" without trying first.
    """
    sleep = RETRY_FIRST_SECONDS
    for _ in range(RETRY_TRIES - 1):
        try:
            return Path(path).read_text(encoding=encoding)
        except OSError as exc:
            if not sharing_violation(exc):
                raise
        time.sleep(sleep)
        sleep = min(sleep * 2, RETRY_MAX_SLEEP_SECONDS)
    return Path(path).read_text(encoding=encoding)
