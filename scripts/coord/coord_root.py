# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Where fleet coordination state lives: the Python twin of ``scripts/coord/coord-root.ps1``.

That file's header is the source of record for the two roots, the resolution order, the root.toml
format and the reachability probe. This module answers the same questions for the Python git hooks
and out-of-repo helpers, and ``tests/test_coord_root.py`` holds the two to one answer.

Stdlib only, and it imports nothing from ``messagefoundry``: the installed git hooks run it from
``.git/hooks`` with whatever interpreter the hook found. A hook that cannot import this file carries
a copy; ``SHARED_KINDS`` and the regex are what a parity test compares.
"""

from __future__ import annotations

import json
import os
import re
import socket
import subprocess  # nosec B404 - fixed argv, no shell
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

_ROOT_LINE = re.compile(r"\A\s*shared_root\s*=\s*'([^']*)'\s*(#.*)?\Z")
_BLANK_OR_COMMENT = re.compile(r"\A\s*(#.*)?\Z")
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


def shared_root(start: str | os.PathLike[str] | None = None) -> tuple[Path | None, str, str | None]:
    """``(path, source, error)``. ``source`` is ``env``, ``file`` or ``local``; path is None on error."""
    env = os.environ.get(ROOT_ENV, "")
    if env.strip():
        return Path(env.strip()), "env", None
    local = local_root(start)
    if local is None:
        return None, "local", f"git could not name the common dir for '{start}'"
    file = local / ROOT_FILE
    try:
        if not file.is_file():
            return local, "local", None
        for line in file.read_text(encoding="utf-8-sig").splitlines():
            if _BLANK_OR_COMMENT.match(line):
                continue
            m = _ROOT_LINE.match(line)
            if m and m.group(1).strip():
                return Path(m.group(1).strip()), "file", None
            return (
                None,
                "file",
                f"{file} has a line that is not shared_root = '<path>' (single quotes): {line}",
            )
        return None, "file", f"{file} names no shared_root"
    except OSError as exc:
        return None, "file", f"{file} could not be read: {exc}"


def unc_host(path: str) -> str | None:
    m = _UNC.match(path)
    return m.group(1) if m else None


def probe_root(path: Path, local: Path | None) -> str | None:
    """None when ``path`` answers; else why not. Fast on a dead SMB server."""
    server = unc_host(str(path))
    if server:
        down = local / DOWN_FILE if local else None
        try:
            if down is not None and down.is_file():
                age = time.time() - down.stat().st_mtime
                if age < DOWN_TTL_SECONDS:
                    return f"shared root {path} was unreachable {int(age)} s ago (cached in {down})"
        except OSError:
            pass
        try:
            with socket.create_connection((server, 445), timeout=PROBE_TIMEOUT_SECONDS):
                pass
        except OSError:
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


def resolve(kind: str, start: str | os.PathLike[str] | None = None) -> CoordDir:
    """The directory for one kind of coordination state. Never falls back to LOCAL for a shared kind."""
    local = local_root(start)
    if kind not in SHARED_KINDS:
        if local is None:
            return CoordDir(
                None, False, "local", f"git could not name the common dir for '{start}'"
            )
        return CoordDir(local / kind, False, "local", None)
    root, source, error = shared_root(start)
    if error is not None or root is None:
        return CoordDir(None, True, source, error or "no shared root")
    if source != "local":
        why = probe_root(root, local)
        if why is not None:
            return CoordDir(None, True, source, why)
    return CoordDir(root / kind, True, source, None)


def host() -> str:
    """The name every shared record carries. Matches PowerShell's ``[Environment]::MachineName``."""
    return os.environ.get("COMPUTERNAME") or socket.gethostname().split(".")[0].upper()
