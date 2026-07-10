# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""OS-side probes for the connection-scale harness — FD/handle + CPU/RSS count + reload timing (B11).

Two pure-measurement helpers, both run OFF the event loop (in a thread), psutil-free (stdlib +
Windows/Unix built-ins so no new runtime dep):

* :class:`FdSampler` — the engine's open-handle / socket count (wall #4) **plus** its cumulative
  process CPU-seconds and working-set (RSS) footprint, summed across the engine's process **subtree**.
  The subtree matters because ``messagefoundry serve`` runs the uvicorn engine as a **child** on
  Windows, so ``EngineNode.pid`` is a thin idle launcher (~61 handles / ~6 MB) while the real engine is
  a descendant (hundreds of handles / tens of MB); keying only to the root PID measured the launcher.
  The sampler resolves the subtree PIDs ONCE (a single process-table walk) and then sums a cheap
  per-tick read of each: on Windows ``Get-Process -Id <pids>`` (HandleCount / TotalProcessorTime /
  WorkingSet64); on POSIX ``/proc/<pid>/fd`` + ``/proc/<pid>/stat`` (utime+stime) + ``/proc/<pid>/
  statm`` (resident pages). On Linux the engine IS the root (no child), so the subtree is just that one
  process — byte-identical to single-process sampling. Every field is ``None`` when nothing in the
  subtree could be read (a dead tree / a missing tool), so the runner records a gap rather than
  crashing.
* :func:`time_reload` — times one ``EngineClient.reload_config(dir)`` round-trip (wall #5), the
  O(connections) quiesce-and-swap.

It reads only counts / timings — never a message body or any PHI.
"""

from __future__ import annotations

import os
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path

from messagefoundry.console.client import ApiError, EngineClient

_WINDOWS = sys.platform == "win32"
# Bound every shell-out so a hung child (a stuck WMI/Get-Process or lsof) can't wedge a poll tick.
_PROBE_TIMEOUT_S = 5.0
# Windows TotalProcessorTime is exposed as .Ticks (100-ns units); seconds = ticks / this. Reading the
# integer ticks (not the culture-formatted .CPU double) keeps the parse locale-proof.
_WIN_CPU_TICKS_PER_S = 10_000_000.0
# A3: re-walk the process table every N sample ticks so a sharded engine's late-spawned `serve --shard`
# workers join the subtree. A full walk is the expensive part of a tick, so amortise it rather than
# paying it every time; at the runner's poll cadence this re-checks the topology every few seconds.
_RESOLVE_EVERY_TICKS = 8


@dataclass(frozen=True)
class ProcSample:
    """One OS-side reading of the engine process (all ``None`` when unreadable — a poll tick gap).

    * ``handles`` — open-handle count (Windows) / open-fd count (POSIX): wall #4 FD pressure.
    * ``cpu_seconds`` — CUMULATIVE process CPU-seconds since the process started (monotonic); the
      runner differences consecutive readings for CPU utilisation and totals.
    * ``working_set_bytes`` — resident working set (RSS) in bytes."""

    handles: int | None
    cpu_seconds: float | None
    working_set_bytes: int | None


_EMPTY_PROC = ProcSample(handles=None, cpu_seconds=None, working_set_bytes=None)


class FdSampler:
    """Sample the engine process SUBTREE's handle count, CPU-seconds, and working set, psutil-free.

    Constructed with the engine subprocess PID (the harness owns the engine, so it has it). The subtree
    (root + descendants) is resolved ONCE on first use — because ``messagefoundry serve`` runs the
    uvicorn engine as a child on Windows, so the root PID alone would measure the idle launcher — then
    each :meth:`sample_proc` sums a cheap per-PID read across it. :meth:`sample` keeps the legacy
    handle-count-only shape (``int | None``). Every field is ``None`` when nothing in the subtree could
    be read (a dead tree / a missing tool) so a poll tick records a gap, never raises."""

    def __init__(self, pid: int, *, resolve_every: int = _RESOLVE_EVERY_TICKS) -> None:
        self._pid = pid
        self._pids: list[int] | None = None  # [root, *descendants], re-resolved every N ticks
        # True while the last subtree resolution ERRORED (Windows enumeration failed/timed out) — as
        # opposed to a genuine no-descendants result. An errored resolution is NOT cached (so a later
        # tick retries) and its samples are reported probe-degraded (all None) rather than measuring the
        # thin launcher process, whose footprint is NOT the engine's on Windows.
        self._resolve_errored = False
        # A3: the subtree is NOT stable for a SHARDED engine — ADR 0037's supervisor spawns one
        # `serve --shard` subprocess per shard, and a subtree cached before they appear measures an idle
        # supervisor forever (a flat CPU counter that used to render as a plausible 0.00). Re-resolve
        # periodically so late-spawned workers are counted. `resolve_every=1` re-walks every tick.
        self._resolve_every = max(1, resolve_every)
        self._ticks_since_resolve = 0

    @property
    def pid(self) -> int:
        return self._pid

    def sample(self) -> int | None:
        """The current handle/fd count across the engine subtree, or ``None`` if it can't be read
        (legacy shape). Delegates to :meth:`sample_proc` so it stays one cheap read per PID."""
        return self.sample_proc().handles

    def sample_proc(self) -> ProcSample:
        """Handle count + cumulative CPU-seconds + working-set bytes SUMMED across the engine subtree,
        each field ``None`` when nothing could be read. Runs the OS probe synchronously — the runner
        calls it in ``run_in_executor`` (off the event loop), like the rest of the sampling."""
        pids = self._resolve_pids()
        if self._resolve_errored:
            # Subtree resolution ERRORED (a failed/timed-out Windows enumeration). Reading the root PID
            # alone would report the idle launcher's footprint (~61 handles / ~6 MB / ~0 CPU) as the
            # engine's — worse than a gap, because it's a plausible-looking WRONG number that could flip
            # a footprint delta. Record a probe-degraded gap (all None) and let a later tick retry.
            return _EMPTY_PROC
        if _WINDOWS:
            return self._sample_windows(pids)
        return self._sample_posix(pids)

    def _resolve_pids(self) -> list[int]:
        """Resolve the engine's process subtree (root + descendants), re-walking every
        ``resolve_every`` ticks so a sharded engine's late-spawned workers are picked up. A cached
        resolution serves the ticks in between, so this costs one process-table walk per N ticks, not one
        per tick.

        A3: the subtree was previously resolved exactly ONCE, on the premise that "the engine doesn't
        re-spawn mid-hold". That holds for a single-process engine but NOT for a sharded one (ADR 0037
        spawns one ``serve --shard`` subprocess per shard). A subtree resolved before those children
        appear pins the sampler to an idle supervisor for the whole run — its CPU counter never advances,
        which used to surface as a plausible ``0.00`` rather than a gap.

        An ERRORED Windows resolution (enumeration failed/timed out under load) is deliberately NOT
        cached: on Windows the real engine is a CHILD of the thin launcher ``self._pid``, so caching a
        root-only fallback would measure the launcher for the ENTIRE run. It returns root-only for the
        current tick, flags ``_resolve_errored`` (so :meth:`sample_proc` emits a degraded gap instead of
        the launcher footprint), and leaves ``_pids`` unresolved so the next tick retries. A GENUINE
        no-descendants result (``[]`` — the normal Linux case, engine == root) IS cached and NOT flagged."""
        if self._pids is not None:
            self._ticks_since_resolve += 1
            if self._ticks_since_resolve < self._resolve_every:
                # Serving a previously-VALIDATED subtree. If the last re-resolve errored, that error
                # applied to that tick only — the cached subtree is still the best known truth, and
                # degrading every tick until the next re-walk would turn one transient enumeration
                # failure into a run-long blackout. Clear the flag so this tick reports a real reading.
                self._resolve_errored = False
                return self._pids
        self._ticks_since_resolve = 0
        descendants = self._descendants_windows() if _WINDOWS else self._descendants_posix()
        if descendants is None:
            self._resolve_errored = True
            return [self._pid]  # transient (this tick only), not cached — retry next tick
        self._resolve_errored = False
        ordered = [self._pid]
        for pid in descendants:
            if pid not in ordered:
                ordered.append(pid)
        self._pids = ordered
        return self._pids

    # --- subtree resolution (one-time) ---------------------------------------

    def _descendants_windows(self) -> list[int] | None:
        # Enumerate the process table ONCE (ProcessId, ParentProcessId) and walk every descendant of
        # the root — messagefoundry serve's real engine is a child of EngineNode.pid on Windows. Returns
        # ``None`` to signal the enumeration ERRORED (so the caller retries + degrades rather than
        # caching a root-only fallback that would measure the idle launcher); a list (possibly empty) on
        # a successful enumeration.
        try:
            out = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    "Get-CimInstance Win32_Process | ForEach-Object "
                    "{ '{0} {1}' -f $_.ProcessId, $_.ParentProcessId }",
                ],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError):
            return None  # errored/timed out — NOT "no descendants"
        # Parse whatever rows came back regardless of the exit code (a partial result is still usable).
        children: dict[int, list[int]] = {}
        rows = 0
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) != 2:
                continue
            pid, ppid = _as_int(parts[0]), _as_int(parts[1])
            if pid is None or ppid is None:
                continue
            children.setdefault(ppid, []).append(pid)
            rows += 1
        # A COMPLETED enumeration that yielded zero usable rows is an error, not a genuine empty result:
        # a live Windows box always has many processes, so zero rows means the walk didn't actually run
        # (a silent failure / truncated output). Signal errored so the caller retries + degrades rather
        # than caching root-only and reporting the launcher's footprint as the engine's.
        if rows == 0:
            return None
        return _walk_descendants(children, self._pid)

    def _descendants_posix(self) -> list[int]:
        # Build the ppid→children map from /proc/<pid>/stat (field 4 = ppid), then walk from the root.
        # ALWAYS a list (never the errored sentinel): on Linux the engine IS the root, so a genuine
        # no-descendants result (``[]``) is the normal case and must NOT be flagged degraded; and if
        # /proc is unreadable the per-PID reads of the root also return None, self-degrading honestly
        # (no launcher confound — there is no separate launcher on Linux).
        children: dict[int, list[int]] = {}
        try:
            entries = os.listdir("/proc")
        except OSError:
            return []
        for name in entries:
            if not name.isdigit():
                continue
            try:
                raw = Path(f"/proc/{name}/stat").read_text()
            except OSError:
                continue
            after = raw.rpartition(")")[2].split()
            # after[0] == field 3 (state); ppid is field 4 → index 1.
            if len(after) < 2:
                continue
            pid, ppid = _as_int(name), _as_int(after[1])
            if pid is None or ppid is None:
                continue
            children.setdefault(ppid, []).append(pid)
        return _walk_descendants(children, self._pid)

    # --- per-tick sampling (summed across the subtree) -----------------------

    def _sample_windows(self, pids: list[int]) -> ProcSample:
        # One Get-Process for the whole PID list (SilentlyContinue tolerates a since-exited launcher);
        # sum HandleCount / TotalProcessorTime.Ticks / WorkingSet64 across the returned rows.
        idlist = ",".join(str(p) for p in pids)
        command = (
            "Get-Process -Id " + idlist + " -ErrorAction SilentlyContinue | ForEach-Object "
            "{ '{0} {1} {2}' -f $_.HandleCount, $_.TotalProcessorTime.Ticks, $_.WorkingSet64 }"
        )
        try:
            out = subprocess.run(
                ["powershell", "-NoProfile", "-NonInteractive", "-Command", command],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError):
            return _EMPTY_PROC
        # NB: ignore the exit code. `Get-Process -Id a,b` where one PID has since exited emits a
        # non-terminating error (exit 1) EVEN under -ErrorAction SilentlyContinue, yet still writes the
        # live processes' rows to stdout. Trust the parsed rows; only zero rows ⇒ a genuine gap.
        handles = 0
        cpu_ticks = 0
        rss = 0
        rows = 0
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            h, t, w = _as_int(parts[0]), _as_int(parts[1]), _as_int(parts[2])
            if h is None or t is None or w is None:
                continue
            handles += h
            cpu_ticks += t
            rss += w
            rows += 1
        if rows == 0:
            return _EMPTY_PROC
        return ProcSample(
            handles=handles,
            cpu_seconds=cpu_ticks / _WIN_CPU_TICKS_PER_S,
            working_set_bytes=rss,
        )

    def _sample_posix(self, pids: list[int]) -> ProcSample:
        handles_sum = 0
        cpu_sum = 0.0
        rss_sum = 0
        h_seen = c_seen = r_seen = 0
        for pid in pids:
            h = self._posix_handles(pid)
            if h is not None:
                handles_sum += h
                h_seen += 1
            c = self._posix_cpu_seconds(pid)
            if c is not None:
                cpu_sum += c
                c_seen += 1
            r = self._posix_rss_bytes(pid)
            if r is not None:
                rss_sum += r
                r_seen += 1
        return ProcSample(
            handles=handles_sum if h_seen else None,
            cpu_seconds=cpu_sum if c_seen else None,
            working_set_bytes=rss_sum if r_seen else None,
        )

    def _posix_handles(self, pid: int) -> int | None:
        # Linux: /proc/<pid>/fd is the cheapest, most direct count (one listdir, no shell-out).
        proc_fd = Path(f"/proc/{pid}/fd")
        try:
            return sum(1 for _ in os.scandir(proc_fd))
        except OSError:
            pass
        # Fallback (macOS / no /proc): lsof -p <pid>, count the rows.
        try:
            out = subprocess.run(
                ["lsof", "-p", str(pid)],
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

    def _posix_cpu_seconds(self, pid: int) -> float | None:
        # /proc/<pid>/stat: utime (field 14) + stime (field 15), in clock ticks. The comm field (2)
        # can contain spaces/parens, so split after the LAST ')' — everything after is field 3 onward.
        try:
            raw = Path(f"/proc/{pid}/stat").read_text()
        except OSError:
            return None
        after = raw.rpartition(")")[2].split()
        # after[0] == field 3 (state); utime is field 14 → index 11, stime is field 15 → index 12.
        if len(after) < 13:
            return None
        utime = _as_int(after[11])
        stime = _as_int(after[12])
        if utime is None or stime is None:
            return None
        clk = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
        if not clk or clk <= 0:
            clk = 100
        return (utime + stime) / float(clk)

    def _posix_rss_bytes(self, pid: int) -> int | None:
        # /proc/<pid>/statm: field 2 is resident set size in PAGES; × page size → bytes.
        try:
            fields = Path(f"/proc/{pid}/statm").read_text().split()
        except OSError:
            return None
        if len(fields) < 2:
            return None
        pages = _as_int(fields[1])
        if pages is None:
            return None
        page_size = os.sysconf("SC_PAGE_SIZE") if hasattr(os, "sysconf") else 4096
        if not page_size or page_size <= 0:
            page_size = 4096
        return pages * int(page_size)


def _walk_descendants(children: dict[int, list[int]], root: int) -> list[int]:
    """BFS the ppid→children map from ``root``, returning every descendant PID (root excluded).
    Cycle-guarded (a reused PID can't loop) and root-excluded so the caller prepends it once."""
    out: list[int] = []
    seen = {root}
    queue = list(children.get(root, []))
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        out.append(pid)
        queue.extend(children.get(pid, []))
    return out


def _as_int(text: str) -> int | None:
    try:
        return int(text.strip())
    except (ValueError, AttributeError):
        return None


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
