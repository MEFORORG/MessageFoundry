# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""OS-side probes for the connection-scale harness — FD/handle count + reload timing (B11).

Two pure-measurement helpers, both run OFF the event loop (in a thread), psutil-free (stdlib +
Windows/Unix built-ins so no new runtime dep):

* :class:`FdSampler` — the engine PID's open-handle / socket count (wall #4). On Windows it reads the
  process handle count (``Get-Process -Id <pid>``); on POSIX it counts ``/proc/<pid>/fd`` entries, or
  falls back to ``lsof``. Returns ``None`` when it can't read (a missing tool / a dead PID), so the
  runner records a gap rather than crashing the sample.
* :func:`time_reload` — times one ``EngineClient.reload_config(dir)`` round-trip (wall #5), the
  O(connections) quiesce-and-swap.

It reads only counts / timings — never a message body or any PHI.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from pathlib import Path

from messagefoundry.console.client import ApiError, EngineClient

_WINDOWS = sys.platform == "win32"
# Bound every shell-out so a hung child (a stuck WMI/Get-Process or lsof) can't wedge a poll tick.
_PROBE_TIMEOUT_S = 5.0


class FdSampler:
    """Sample the engine process's open-handle / socket count by PID (wall #4), psutil-free.

    Constructed with the engine subprocess PID (the harness owns the engine, so it has it). Each
    :meth:`sample` returns the current open-handle count (Windows) / open-fd count (POSIX), or
    ``None`` when unreadable (dead PID / missing tool) so a poll tick records a gap, never raises."""

    def __init__(self, pid: int) -> None:
        self._pid = pid

    @property
    def pid(self) -> int:
        return self._pid

    def sample(self) -> int | None:
        """The current handle/fd count for the engine PID, or ``None`` if it can't be read. Runs the
        OS probe synchronously — the runner calls it in ``run_in_executor`` (off the event loop)."""
        if _WINDOWS:
            return self._sample_windows()
        return self._sample_posix()

    def _sample_windows(self) -> int | None:
        # The process HandleCount is the broadest cheap signal (it rises with sockets + threads + the
        # store/pool handles), which is exactly the "FD pressure rises ~linearly with N" curve.
        try:
            out = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    f"(Get-Process -Id {self._pid} -ErrorAction Stop).HandleCount",
                ],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode != 0:
            return None
        text = out.stdout.strip()
        try:
            return int(text)
        except ValueError:
            return None

    def _sample_posix(self) -> int | None:
        # Linux: /proc/<pid>/fd is the cheapest, most direct count (one listdir, no shell-out).
        proc_fd = Path(f"/proc/{self._pid}/fd")
        try:
            return sum(1 for _ in os.scandir(proc_fd))
        except OSError:
            pass
        # Fallback (macOS / no /proc): lsof -p <pid>, count the rows.
        try:
            out = subprocess.run(
                ["lsof", "-p", str(self._pid)],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError):
            return None
        if out.returncode != 0:
            return None
        lines = [ln for ln in out.stdout.splitlines() if ln.strip()]
        # Drop the header row if present.
        return max(0, len(lines) - 1) if lines else 0


def time_reload(client: EngineClient, config_dir: str | None) -> float | None:
    """Time one ``reload_config(config_dir)`` round-trip in seconds (wall #5), or ``None`` if the
    reload errors. Synchronous — the runner calls it in ``run_in_executor`` (off the event loop, like
    the rest of the engine polling). ``config_dir=None`` reloads the server's startup --config dir."""
    t0 = time.perf_counter()
    try:
        client.reload_config(config_dir)
    except ApiError:
        return None
    return time.perf_counter() - t0
