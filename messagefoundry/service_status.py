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
    ``CreateProcess``/``ShellExecuteW`` resolve an *unqualified* name through a search path that
    reaches the caller's working directory, so a ``sc.exe``/``cmd.exe``/``net.exe`` planted in the
    directory an operator happened to launch from would be run instead. On the ``runas`` (elevated)
    paths in :mod:`messagefoundry.service` it would run as administrator, behind a UAC prompt that
    names the planted file. Pinning the path removes the search (BACKLOG #1680).

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


def parse_service_state(sc_output: str) -> ServiceState:
    """Map ``sc query`` output to ``running`` / ``stopped`` / ``unknown``."""
    text = sc_output.upper()
    if "RUNNING" in text:
        return "running"
    if "STOP" in text:  # STOPPED or STOP_PENDING
        return "stopped"
    return "unknown"


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
