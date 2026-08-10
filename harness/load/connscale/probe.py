# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""OS-side probes for the connection-scale harness — FD/handle + CPU/RSS count + reload timing (B11).

Two pure-measurement helpers, both run OFF the event loop (in a thread), psutil-free (stdlib +
Windows/Unix built-ins so no new runtime dep):

* :class:`FdSampler` — the engine's open-handle / socket count (wall #4) **plus** its cumulative
  process CPU-seconds and working-set (RSS) footprint, summed across the engine's process **subtree**.
  The subtree matters because ``EngineNode`` spawns the engine as ``sys.executable -m messagefoundry
  serve``, and on Windows a venv's ``Scripts\\python.exe`` can be a **launcher shim** that re-execs the
  base interpreter as a CHILD — so ``EngineNode.pid`` is then a thin idle process while the real engine
  is a descendant, and keying only to the root PID measures the shim. (Note the child is NOT ``serve``
  spawning uvicorn: ``uvicorn.run`` is in-process, and the child-spawning path in ``serve`` is at least
  the ``--shards`` supervisor, which the connscale smoke does not use. The shim is a property of the
  *launching* interpreter, not of ``serve``, so whether the root is thin is environment-dependent —
  measured on the maintainer's box 2026-08-10, a stdlib venv over a ``pythoncore-3.14`` install: root
  61 handles / 6.55 MB, its re-exec child 141 handles / 15.2 MB.)
  The sampler resolves the subtree PIDs periodically (a process-table walk) and then sums a cheap
  per-tick read of each: on Windows ``Get-Process -Id <pids>`` (HandleCount / TotalProcessorTime /
  WorkingSet64); on POSIX ``/proc/<pid>/fd`` + ``/proc/<pid>/stat`` (utime+stime) + ``/proc/<pid>/
  statm`` (resident pages). Where the launching interpreter spawns no shim the subtree is just the one
  process — byte-identical to single-process sampling. Every field is ``None`` when nothing in the
  subtree could be read (a dead tree / a missing tool), so the runner records a gap rather than
  crashing.

  The walk is **provenance-checked** (BACKLOG #1210): a candidate that PREDATES the root is not a
  descendant of it, so it is rejected along with its subtree. Windows never rewrites
  ``ParentProcessId`` when a parent exits and it recycles PIDs, so an unvalidated ppid walk adopts any
  live process whose recorded parent PID was later reissued to the engine — summing an unrelated tree
  into a gauge a merge-blocking SLO then judges.
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

from messagefoundry.apiclient import ApiError, EngineClient

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
# .NET DateTime.Ticks are 100-ns units on the same scale as TotalProcessorTime.Ticks above, but they
# mean an INSTANT, not a duration — kept as its own name so the two never get conflated.
_WIN_DATETIME_TICKS_PER_S = 10_000_000.0
# #1210: how much older than its root a candidate may look before the walk rejects it. This absorbs
# CLOCK GRANULARITY, not age. Win32_Process CreationDate is a wall-clock stamp whose kernel source
# ticks at ~15.6 ms by default; /proc starttime is quantised to SC_CLK_TCK (10 ms typical). A genuinely
# adopted subtree is old BY CONSTRUCTION — its real parent had to exit and the PID space had to wrap
# before the root could be issued that PID — so one second sits orders of magnitude below the gap this
# must catch and far above the gap it must not trip on. Note the tolerance is one-sided: it only ever
# ADMITS a candidate, so setting it too small would wrongly reject a genuine child (measuring the thin
# launcher alone), which is why it is not zero.
_CREATION_SKEW_TOLERANCE_S = 1.0

#: One process-table row: ``(pid, ppid, created_s)``. ``created_s`` is an instant in seconds on an
#: arbitrary but host-COMMON origin (Windows: .NET UTC ticks / 1e7; POSIX: /proc starttime ticks since
#: boot / SC_CLK_TCK) — only differences between rows are meaningful. ``None`` = not recorded.
type ProcRow = tuple[int, int, float | None]


@dataclass(frozen=True)
class ProcSample:
    """One OS-side reading of the engine process (all ``None`` when unreadable — a poll tick gap).

    * ``handles`` — open-handle count (Windows) / open-fd count (POSIX): wall #4 FD pressure.
    * ``cpu_seconds`` — CUMULATIVE process CPU-seconds since the process started (monotonic); the
      runner differences consecutive readings for CPU utilisation and totals.
    * ``working_set_bytes`` — resident working set (RSS) in bytes.
    * ``cpu_pids`` — the exact set of PIDs whose CPU-seconds were summed into ``cpu_seconds`` this
      tick (``None`` **iff** ``cpu_seconds`` is ``None``). The runner differences consecutive readings
      to derive utilisation, and that difference is only a clean CPU delta when the summed-over PID set
      is unchanged — A3's periodic subtree re-resolution can add a joining ``serve --shard`` worker or
      drop a departing one mid-window, so the runner uses this set to sum only same-set intervals and
      degrade the rest to a gap (BACKLOG #220)."""

    handles: int | None
    cpu_seconds: float | None
    working_set_bytes: int | None
    cpu_pids: frozenset[int] | None = None


_EMPTY_PROC = ProcSample(handles=None, cpu_seconds=None, working_set_bytes=None, cpu_pids=None)


class FdSampler:
    """Sample the engine process SUBTREE's handle count, CPU-seconds, and working set, psutil-free.

    Constructed with the engine subprocess PID (the harness owns the engine, so it has it). The subtree
    (root + descendants, see the module docstring for why the root alone is not enough on Windows) is
    resolved periodically and cached in between; each :meth:`sample_proc` sums a cheap per-PID read
    across it. :meth:`sample` keeps the legacy handle-count-only shape (``int | None``). Every field is
    ``None`` when nothing in the subtree could be read (a dead tree / a missing tool) so a poll tick
    records a gap, never raises."""

    def __init__(self, pid: int, *, resolve_every: int = _RESOLVE_EVERY_TICKS) -> None:
        self._pid = pid
        self._pids: list[int] | None = None  # [root, *descendants], re-resolved every N ticks
        # True while the last subtree resolution ERRORED (Windows enumeration failed/timed out, or the
        # root's own creation instant was absent so nothing could be validated against it) — as opposed
        # to a genuine no-descendants result. An errored resolution is NOT cached (so a later tick
        # retries) and its samples are reported probe-degraded (all None) rather than measuring a root
        # that may be only the launcher shim.
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
            # Subtree resolution ERRORED (a failed/timed-out Windows enumeration, or no row for the
            # root). Reading the root PID alone would report a launcher shim's footprint as the
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

        An ERRORED Windows resolution (enumeration failed/timed out under load, or a snapshot with no
        row for the root) is deliberately NOT cached: where ``self._pid`` is only a launcher shim,
        caching a root-only fallback would measure the shim for the ENTIRE run. It returns root-only for
        the current tick, flags ``_resolve_errored`` (so :meth:`sample_proc` emits a degraded gap instead
        of the shim's footprint), and leaves ``_pids`` unresolved so the next tick retries. A GENUINE
        no-descendants result (``[]``) IS cached and NOT flagged."""
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

    # --- subtree resolution --------------------------------------------------

    def _enumerate_windows(self) -> list[ProcRow] | None:
        """One process-table snapshot as ``(pid, ppid, created_s)`` rows, or ``None`` if the
        enumeration ERRORED (so the caller retries + degrades rather than caching a root-only fallback
        that would measure a thin launcher shim).

        ``created_s`` is the process creation instant in seconds on an arbitrary but COMMON origin
        (.NET ticks / 1e7, taken in UTC so a DST transition mid-run cannot reorder two processes). It
        is ``None`` where Windows records no creation date — the walk then refuses to validate that
        candidate rather than assuming it."""
        try:
            out = subprocess.run(
                [
                    "powershell",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    # $c can be $null (the Idle/System pseudo-processes); emit 0 rather than an empty
                    # field so the row still parses. DateTime.Ticks == 0 is year 0001, so it can never
                    # collide with a real creation instant and reads unambiguously as "not recorded".
                    "Get-CimInstance Win32_Process | ForEach-Object "
                    "{ $c = $_.CreationDate; if ($c) { $t = $c.ToUniversalTime().Ticks } "
                    "else { $t = 0 }; '{0} {1} {2}' -f $_.ProcessId, $_.ParentProcessId, $t }",
                ],
                capture_output=True,
                text=True,
                timeout=_PROBE_TIMEOUT_S,
            )
        except (OSError, subprocess.SubprocessError):
            return None  # errored/timed out — NOT "no descendants"
        # Parse whatever rows came back regardless of the exit code (a partial result is still usable).
        rows: list[ProcRow] = []
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) != 3:
                continue
            pid, ppid, ticks = _as_int(parts[0]), _as_int(parts[1]), _as_int(parts[2])
            if pid is None or ppid is None:
                continue
            created = ticks / _WIN_DATETIME_TICKS_PER_S if ticks else None
            rows.append((pid, ppid, created))
        # A COMPLETED enumeration that yielded zero usable rows is an error, not a genuine empty result:
        # a live Windows box always has many processes, so zero rows means the walk didn't actually run
        # (a silent failure / truncated output). Signal errored so the caller retries + degrades rather
        # than caching root-only and reporting the launcher shim's footprint as the engine's.
        if not rows:
            return None
        return rows

    def _enumerate_posix(self) -> list[ProcRow]:
        """One /proc snapshot as ``(pid, ppid, created_s)`` rows. ALWAYS a list (never the errored
        sentinel): a genuine no-descendants result is the normal Linux case and must NOT be flagged
        degraded, and if /proc is unreadable the per-PID reads of the root also return ``None``, which
        self-degrades honestly."""
        rows: list[ProcRow] = []
        try:
            entries = os.listdir("/proc")
        except OSError:
            return rows
        for name in entries:
            if not name.isdigit():
                continue
            try:
                raw = Path(f"/proc/{name}/stat").read_text()
            except OSError:
                continue
            pid = _as_int(name)
            parsed = _posix_stat_ppid_starttime(raw)
            if pid is None or parsed is None:
                continue
            ppid, created = parsed
            rows.append((pid, ppid, created))
        return rows

    def _descendants_windows(self) -> list[int] | None:
        rows = self._enumerate_windows()
        if rows is None:
            return None
        return _validated_descendants(rows, self._pid)

    def _descendants_posix(self) -> list[int]:
        walked = _validated_descendants(self._enumerate_posix(), self._pid)
        # A POSIX walk never reports "errored" (see :meth:`_enumerate_posix`): an unknown root
        # start time means we cannot validate ANY candidate, so adopt none — root-only, fail closed.
        return [] if walked is None else walked

    # --- per-tick sampling (summed across the subtree) -----------------------

    def _sample_windows(self, pids: list[int]) -> ProcSample:
        # One Get-Process for the whole PID list (SilentlyContinue tolerates a since-exited launcher);
        # sum HandleCount / TotalProcessorTime.Ticks / WorkingSet64 across the returned rows.
        idlist = ",".join(str(p) for p in pids)
        command = (
            "Get-Process -Id " + idlist + " -ErrorAction SilentlyContinue | ForEach-Object "
            "{ '{0} {1} {2} {3}' -f $_.HandleCount, $_.TotalProcessorTime.Ticks, "
            "$_.WorkingSet64, $_.Id }"
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
        cpu_pids: set[int] = set()  # the exact PIDs summed into cpu_ticks this tick (#220)
        for line in out.stdout.splitlines():
            parts = line.split()
            if len(parts) != 4:
                continue
            h, t, w, pid = (
                _as_int(parts[0]),
                _as_int(parts[1]),
                _as_int(parts[2]),
                _as_int(parts[3]),
            )
            if h is None or t is None or w is None or pid is None:
                continue
            handles += h
            cpu_ticks += t
            rss += w
            cpu_pids.add(pid)
            rows += 1
        if rows == 0:
            return _EMPTY_PROC
        return ProcSample(
            handles=handles,
            cpu_seconds=cpu_ticks / _WIN_CPU_TICKS_PER_S,
            working_set_bytes=rss,
            cpu_pids=frozenset(cpu_pids),
        )

    def _sample_posix(self, pids: list[int]) -> ProcSample:
        handles_sum = 0
        cpu_sum = 0.0
        rss_sum = 0
        h_seen = c_seen = r_seen = 0
        cpu_pids: set[int] = set()  # the exact PIDs summed into cpu_sum this tick (#220)
        for pid in pids:
            h = self._posix_handles(pid)
            if h is not None:
                handles_sum += h
                h_seen += 1
            c = self._posix_cpu_seconds(pid)
            if c is not None:
                cpu_sum += c
                c_seen += 1
                cpu_pids.add(pid)
            r = self._posix_rss_bytes(pid)
            if r is not None:
                rss_sum += r
                r_seen += 1
        return ProcSample(
            handles=handles_sum if h_seen else None,
            cpu_seconds=cpu_sum if c_seen else None,
            working_set_bytes=rss_sum if r_seen else None,
            cpu_pids=frozenset(cpu_pids) if c_seen else None,
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


def _validated_descendants(rows: list[ProcRow], root: int) -> list[int] | None:
    """BFS the ppid→children map built from ``rows``, returning every descendant PID that PASSES the
    provenance check (root excluded, so the caller prepends it once). ``None`` means the ROOT's own
    creation instant is not in the snapshot, so nothing can be validated against it.

    BACKLOG #1210 — the walk used to be cycle-guarded and nothing else. Windows does not rewrite
    ``ParentProcessId`` when a parent exits, and it recycles PIDs, so any live process whose recorded
    parent PID is later reissued to the engine root is adopted along with its whole subtree; its
    handles and RSS are then summed into a gauge the connscale SLO judges, and ``max()`` latches the
    result for the step. The check: **a genuine descendant cannot predate its root**, because the
    parent must already exist to create the child. Reject any candidate that started more than
    ``_CREATION_SKEW_TOLERANCE_S`` before the root.

    Two deliberate fail-closed choices:

    * A candidate with **no** creation instant is rejected. Unvalidatable is not validated — admitting
      it would leave exactly the hole this check exists to close.
    * A rejected candidate's **subtree is pruned**, not re-walked from its children. If the node is not
      ours, its children are not ours either, and re-entering them is what turns one wrong ppid link
      into a whole unrelated process tree."""
    children: dict[int, list[int]] = {}
    created: dict[int, float] = {}
    for pid, ppid, started in rows:
        children.setdefault(ppid, []).append(pid)
        if started is not None:
            created[pid] = started
    root_created = created.get(root)
    if root_created is None:
        return None
    floor = root_created - _CREATION_SKEW_TOLERANCE_S
    out: list[int] = []
    seen = {root}
    queue = list(children.get(root, []))
    while queue:
        pid = queue.pop(0)
        if pid in seen:
            continue
        seen.add(pid)
        started = created.get(pid)
        if started is None or started < floor:
            continue
        out.append(pid)
        queue.extend(children.get(pid, []))
    return out


def _posix_stat_ppid_starttime(raw: str) -> tuple[int, float | None] | None:
    """Parse ``(ppid, starttime_seconds)`` out of one ``/proc/<pid>/stat`` body, or ``None`` if the
    line is too short to carry them.

    The comm field (2) can contain spaces and parens, so split after the LAST ``)`` — everything after
    it is field 3 onward, i.e. field N is at index N-3. ppid is field 4 (index 1); **starttime is
    field 22 (index 19)**, expressed in clock ticks since boot. Ticks-since-boot is the same origin
    for every process on the host, so it compares directly across the snapshot; it is divided by
    ``SC_CLK_TCK`` only so the caller's tolerance can be stated in seconds."""
    after = raw.rpartition(")")[2].split()
    if len(after) < 2:
        return None
    ppid = _as_int(after[1])
    if ppid is None:
        return None
    if len(after) < 20:
        return ppid, None
    ticks = _as_int(after[19])
    if ticks is None:
        return ppid, None
    clk = os.sysconf("SC_CLK_TCK") if hasattr(os, "sysconf") else 100
    if not clk or clk <= 0:
        clk = 100
    return ppid, ticks / float(clk)


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
