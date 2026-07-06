# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Read-only Windows-service state for the engine's own host (L6a, ADR 0065, BACKLOG #75).

The engine can optionally report the run state of the NSSM service that hosts it (``[service]``), so
the ops console shows a live "service: running/stopped" badge. This is **read-only and unprivileged**:
``sc query <service_name>`` with a **validated** name, **no shell**, **no elevation**, run **off the
event loop**. There is deliberately NO control here — start/stop/restart is cut, because the engine
can't restart its own host over the API (stopping it kills the API). Windows-only; elsewhere / when
``sc`` is absent the state is ``"unavailable"``.

Neutral (stdlib-only) so both :mod:`messagefoundry.config` (name validation) and :mod:`messagefoundry.api`
(the endpoint) may import it without crossing a layer boundary.
"""

from __future__ import annotations

import asyncio
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


def _sc_path() -> str:
    """The absolute path to ``sc.exe`` under System32 — pinned so a ``sc.exe`` planted earlier in the
    process PATH/CWD can never be run instead (PATH/CWD-hijack defense). Falls back to the bare name
    only if ``%SystemRoot%`` is somehow unset."""
    system_root = os.environ.get("SystemRoot")
    if system_root:
        return os.path.join(system_root, "System32", "sc.exe")
    return "sc"


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
            [_sc_path(), "query", name],
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
