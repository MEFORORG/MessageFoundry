# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Read-only Windows-service state for the engine's own host (L6a, ADR 0065, BACKLOG #75).

The engine can optionally report the run state of the NSSM service that hosts it (``[service]``), so
the ops console shows a live "service: running/stopped" badge. This is **read-only and unprivileged**:
``sc query <service_name>`` with a **validated** name, **no shell**, **no elevation**, run **off the
event loop**. There is deliberately NO control here — start/stop/restart is cut, because the engine
can't restart its own host over the API (stopping it kills the API). Windows-only; elsewhere / when
``sc`` is absent the state is ``"unavailable"``.

Neutral (stdlib-only) so both :mod:`messagefoundry.config` (name validation) and :mod:`messagefoundry.api`
(the endpoint) may import it without crossing a layer boundary.

Being the neutral leaf is also why :func:`_system_exe` lives here rather than beside the elevated
callers: :mod:`messagefoundry.service` imports it, so the two modules share one System32 pin instead
of drifting apart (BACKLOG #1680). It is private, and it has an importer — do not read it as dead.
:func:`parse_service_state` is shared the same way and for the same reason -- it lived here and in
:mod:`messagefoundry.service` as two identical copies, so the defect BACKLOG #1556 names had to be
fixed twice. See :data:`_STATE_LINE` for what that defect was.
"""

from __future__ import annotations

import asyncio
import ctypes
import os
import re
import subprocess  # nosec B404 - fixed system tool (sc), no shell, validated arg (below)
import sys

__all__ = ["ServiceState", "is_safe_service_name", "parse_service_state", "query_service_state"]

# One of: running | stopped | unknown | not_installed | unavailable | disabled.
ServiceState = str

# A Windows service name needs only letters/digits/space/dot/underscore/hyphen. Even though this call
# uses an argv list (no shell), keep the name strictly validated so a hostile/typo'd config value can
# never reach the subprocess as anything but a plain service name (defense-in-depth; mirrors the
# console's elevated-path guard). The name MUST start with an alphanumeric — so a leading '-'/space
# (which `sc` could read as a token) or a whitespace-only name is rejected outright.
_SAFE_SERVICE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 ._-]*$")


# ``ctypes.windll`` is Windows-only; probed by getattr so this module still imports and type-checks
# elsewhere, and so a test that fakes ``sys.platform`` can't reach an API that isn't loaded.
_WINDLL = getattr(ctypes, "windll", None)
_MAX_PATH = 260  # Windows MAX_PATH; what GetSystemDirectoryW's buffer is documented to need


def _system_dir() -> str:
    """The absolute Windows system directory (``%SystemRoot%\\System32``).

    Asked of the OS rather than read from ``%SystemRoot%``: an environment block is inherited from
    whoever launched this process, and that is the same party :func:`_system_exe` defends against,
    so the env var is the weaker source. It is the fallback only where the API is unreachable.
    """
    if _WINDLL is not None:
        buf = ctypes.create_unicode_buffer(_MAX_PATH)
        if _WINDLL.kernel32.GetSystemDirectoryW(buf, _MAX_PATH):
            return buf.value
    root = os.environ.get("SystemRoot", "C:\\Windows")  # noqa: SIM112
    return os.path.join(root, "System32")


def _system_exe(*parts: str) -> str:
    """An absolute path to a stock Windows program under the system directory.

    Every program this module and :mod:`messagefoundry.service` hand to the OS goes through here.
    Windows resolves an *unqualified* program name through a search path that reaches the caller's
    working directory, so a ``sc.exe``/``cmd.exe``/``net.exe`` planted in the directory an operator
    happened to launch from would be run instead. On the elevated (``runas``) paths in
    :mod:`messagefoundry.service` it would run as administrator, behind a UAC prompt that names the
    planted file. Pinning the path removes the search (BACKLOG #1680).

    Nothing here elevates or uses a shell — this module only ever runs ``sc query`` as an argv list.
    Naming the elevating API in this docstring would put this file in the THREAT-MODEL.md 15.1.5
    shell-site inventory, which scans for the token, so the API is named in ``service.py`` instead.

    This lives in the neutral leaf so both modules share one pin. Before BACKLOG #1680 there were
    two, and they disagreed: the elevated module pinned nothing at all, and the ``sc`` pin here fell
    back to the bare name when ``%SystemRoot%`` was unset.
    """
    return os.path.join(_system_dir(), *parts)


# sc.exe is a console program; suppress the transient console window when launched from a windowless
# host (Windows-only flag; 0/no-op elsewhere, via getattr so it type-checks on non-Windows).
_NO_WINDOW: int = getattr(subprocess, "CREATE_NO_WINDOW", 0)


def is_safe_service_name(name: str) -> bool:
    """True iff ``name`` is a non-empty, plain Windows service name (no shell metacharacters)."""
    return bool(name) and bool(_SAFE_SERVICE_NAME.match(name))


# `sc query` prints one field per line, and the run state is the STATE field, whose value is the
# numeric SCM code followed by that code's name:
#
#     STATE              : 4  RUNNING  (STOPPABLE, PAUSABLE, ACCEPTS_SHUTDOWN)
#
# Anchor on that line. Searching the whole output for the bare word instead reads the service's own
# name, its display name and the capability flags as if they were the state (BACKLOG #1556): a
# service named `AcmeRunningSync` reads as running whatever it is doing, and every genuinely running
# service prints STOPPABLE and ACCEPTS_SHUTDOWN on the very same line.
#
# Two limits come with anchoring here, both deliberate. `sc` localizes this field name, so on a
# non-English host nothing matches and the verdict is `unknown` -- the same verdict the whole-output
# search gave there, and a wrong-but-confident one is worse. And the FIRST match wins, so output
# listing several services reports the first; every caller in this package passes one validated
# service name, and `parse_service_state` is documented for that output.
_STATE_LINE = re.compile(r"^[ \t]*STATE[ \t]*:[ \t]*(?:(\d+)[ \t]+)?(\w+)", re.MULTILINE)

# SCM service-state codes (`winsvc.h`, SERVICE_STOPPED / SERVICE_STOP_PENDING / SERVICE_RUNNING).
# The code is read in preference to the word because the SCM defines it. `sc` always prints the
# code, so the word table is reached only by output that omits it and never on this package's own
# path -- it is a fallback, not the normal case. Only the two verdicts this module reports are
# mapped, so a paused,
# starting or continuing service reads as `unknown` -- the caller is told the state is not one it
# knows, rather than being handed the nearest of the two it does.
_STATE_CODES = {1: "stopped", 3: "stopped", 4: "running"}
_STATE_WORDS = {"STOPPED": "stopped", "STOP_PENDING": "stopped", "RUNNING": "running"}


def parse_service_state(sc_output: str) -> ServiceState:
    """Map the output of ``sc query <one service name>`` to ``running`` / ``stopped`` / ``unknown``.

    Reads the **STATE field**, never the whole output -- see :data:`_STATE_LINE` for what a
    substring search over everything ``sc`` prints gets wrong, and for the two limits that come
    with anchoring there (a localized host, and multi-service output)."""
    match = _STATE_LINE.search(sc_output.upper())
    if match is None:
        return "unknown"
    code, word = match.groups()
    if code is not None:
        return _STATE_CODES.get(int(code), "unknown")
    return _STATE_WORDS.get(word, "unknown")


def _query(name: str) -> ServiceState:
    if sys.platform != "win32":
        return "unavailable"
    try:
        proc = subprocess.run(  # nosec B603 B607 - pinned tool, argv list (no shell), validated name
            [_system_exe("sc.exe"), "query", name],
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=_NO_WINDOW,
        )
    except (OSError, subprocess.SubprocessError):
        return "unavailable"
    if proc.returncode != 0:
        return "not_installed"  # e.g. error 1060: service does not exist
    return parse_service_state(proc.stdout)


async def query_service_state(name: str) -> ServiceState:
    """The service's run state, queried **off the event loop**. ``unavailable`` for an unsafe/empty
    name, off Windows, or when ``sc`` can't be run — never raises."""
    if not is_safe_service_name(name):
        return "unavailable"
    return await asyncio.to_thread(_query, name)
