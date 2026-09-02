# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Subprocess isolation for Routers/Handlers (ADR 0087, BACKLOG #197).

Routers and Handlers are admin-authored *pure* Python that the engine runs in its own address space
(the service account's DEK, the tamper-evident audit chain, and every live socket live in that same
process). ASVS 15.2.5 wants a hard isolation boundary between that trusted core and admin-supplied
code; this module is the **opt-in** boundary that closes the documented residual WP-L3-17.

**Modes (``[sandbox].mode``).**

* ``off`` (default) — :func:`run_sandboxed` calls the Router/Handler **in-process**, byte-identically
  and with **zero** overhead (no subprocess, no marshalling). The isolation seam is invisible.
* ``subprocess`` — the Router/Handler runs in a **persistent per-inbound worker subprocess**
  (:mod:`messagefoundry.pipeline._sandbox_worker`). The parent marshals ``(id, phase, name, payload,
  run_context)`` over a length-prefixed **non-executing** pipe codec
  (:mod:`messagefoundry.pipeline._sandbox_codec`); the worker looks the function up in **its own**
  freshly-loaded :class:`~messagefoundry.config.wiring.Registry`, re-establishes the run-scoped
  context providers (over the ENGINE's code-set tables, which arrive once in the boot frame — the
  child's own re-read of ``codesets/`` is never authoritative), runs the function, and describes its
  result back. The worker is *long-lived* (one child per inbound), never a per-message fork — a fork
  per message would destroy the throughput target.

**Both legs of the pipe are untrusted by contract.** The child runs exactly the code the sandbox
exists to distrust: while it lives, a grandchild it spawns inherits fd 1 (the response pipe) and can
write onto it. Killing the worker now reaps its whole process tree — a Windows
``JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`` job object, or a POSIX new-session process group killed with
``killpg`` (see :meth:`SandboxSession._kill`) — so no such grandchild lingers as an orphan past the
kill. That reap is best-effort process *hygiene*, not the trust control: a grandchild can still stage
a frame while the worker is alive, so the wire is **MFW2**, a closed-tag JSON+segment codec whose
decode path is ``json.loads`` plus ``bytes.decode`` and a literal tag match — it cannot name a type,
import a module, or reach ``__reduce__``. Nothing is pickled in either direction.

**Frames answer requests, never the other way round.** Each dispatch mints a fresh
:func:`secrets.token_hex` request id and binds the whole ``(id, phase, name)`` triple on the way back,
and :meth:`SandboxSession.dispatch` treats a frame that is queued *before* a request — or left over
*after* its answer — as fatal to that worker. Together those close the window in which a pre-staged
frame could be read as the NEXT dispatch's answer (for ``phase="accepts"``, a routing-verdict flip on a
message the attacker never saw: no ``ERROR``, no disposition anomaly). What they do **not** do is
confine one Handler from another *inside* a worker: code running a dispatch is handed that dispatch's
id, and it could just as easily rebind a sibling in the child's own registry. ``mode=off`` draws no such
line either — the boundary this seam draws is to the **engine**, not between admin functions.

**What isolation buys (and its honest limits).** The child is a *separate OS process*: even if the
admin code opens a socket or spins the CPU, it cannot touch the parent's DEK, audit chain, or
sockets — those objects are never constructed in the child (it loads the message *graph*, not the
store/crypto). On top of that address-space boundary the child adds defence-in-depth: a
forbidden-import guard (``socket``/store/crypto), a wall-clock cap enforced by the parent (plus
POSIX ``RLIMIT_CPU``/``RLIMIT_AS`` when available), and a fail-closed refusal of the live
``db_lookup``/``fhir_lookup`` bridges (they re-enter the event loop, which a process boundary
breaks — forwarding them over IPC is a documented next-phase residual). The import guard is
**defence-in-depth only** — a module imported before it goes up keeps a live reference, so the
address-space boundary and the codec are the load-bearing controls.

**Fail-closed.** Any isolation denial — a forbidden import/op, a resource cap exceeded, a worker
crash, a rejected frame, or an unmarshallable payload/run-context — raises :class:`SandboxError`. The
caller (the router/transform worker) routes it to ``ERROR``/dead-letter **post-ACK** via the existing
``_apply_router_internal_error`` / ``_apply_transform_internal_error`` paths — never a NAK, never an
accept-and-drop, never a crashed connection.

**Engine-side validation stays engine-side.** The worker describes only the *shape* of the
Router/Handler return value; the fail-closed handler-name / outbound-name validation (see
:func:`messagefoundry.pipeline.dryrun.route_only` / ``transform_one``) runs in the parent on the
rebuilt result, so a compromised worker cannot smuggle an unknown destination past the graph. That
validation is now genuinely downstream of decoding: the decoder builds nothing but a closed set of
plain data types before it runs.

**Layering (CLAUDE.md §4).** This is a pure ``pipeline/`` library — no ``api/`` or ``console/``
imports. It depends only on ``config`` (the :class:`RunContext` shape), its own codec, and the stdlib.
"""

from __future__ import annotations

import ctypes
import enum
import logging
import os
import queue
import secrets
import signal
import struct
import subprocess
import sys
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from typing import IO, Any, Final

from messagefoundry.config.code_sets import CodeSet
from messagefoundry.config.run_context import RunContext
from messagefoundry.logging_setup import scrub_control_chars
from messagefoundry.pipeline import _sandbox_codec as codec
from messagefoundry.pipeline._sandbox_codec import SandboxCodecError, SandboxError

__all__ = [
    "SandboxMode",
    "SandboxError",
    "SandboxCodecError",
    "SandboxPolicy",
    "SandboxSession",
    "run_sandboxed",
    "DEFAULT_FORBIDDEN_MODULES",
    "WORKER_MODULE",
]

log = logging.getLogger(__name__)

#: The worker is launched as ``python -m <WORKER_MODULE>`` (stdlib runpy), inheriting this
#: interpreter + ``sys.path`` so it imports the same ``messagefoundry`` build.
WORKER_MODULE = "messagefoundry.pipeline._sandbox_worker"

#: Top-level dotted module prefixes a sandboxed Router/Handler may not import. The address-space
#: boundary already denies reach to the parent's live objects; this guard makes the *intent* explicit
#: and fails an attempt loudly instead of letting the child open its own socket / re-init crypto.
#: ``messagefoundry`` itself is NOT blocked (the child needs ``messagefoundry.config`` /
#: ``messagefoundry.parsing`` to run the graph) — only its I/O- and secret-bearing subpackages.
DEFAULT_FORBIDDEN_MODULES: tuple[str, ...] = (
    "socket",
    "ssl",
    "asyncio",
    "multiprocessing",
    "messagefoundry.store",
    "messagefoundry.transports",
    "messagefoundry.auth",
    "messagefoundry.crypto",
    "messagefoundry.api",
    "cryptography",
)


class SandboxMode(str, enum.Enum):  # noqa: UP042
    """How a Router/Handler is executed relative to the engine process."""

    OFF = "off"  # in-process, byte-identical, zero overhead (default)
    SUBPROCESS = "subprocess"  # persistent per-inbound worker child


@dataclass(frozen=True)
class SandboxPolicy:
    """Resolved ``[sandbox]`` policy. Pure data so the caps travel to the worker.

    ``mode=off`` (default) is the zero-overhead, byte-identical parity mode. ``wall_seconds`` is the
    **authoritative** cap on every platform — the parent kills a worker that overruns it (so a
    pathological busy-loop Router/Handler can never wedge intake). ``cpu_seconds`` / ``mem_mb`` add a
    POSIX ``RLIMIT_CPU`` / ``RLIMIT_AS`` backstop *inside* the child where the ``resource`` module
    exists (a no-op on Windows, where the wall cap governs). ``startup_seconds`` bounds the one-time
    child bootstrap (config load)."""

    mode: SandboxMode = SandboxMode.OFF
    wall_seconds: float = 5.0
    cpu_seconds: float = 2.0
    mem_mb: int | None = 512
    startup_seconds: float = 30.0
    forbidden_modules: tuple[str, ...] = DEFAULT_FORBIDDEN_MODULES


# --- length-prefixed framing over the worker pipe ----------------------------
# The OUTER frame only. The body's schema (and every type that may cross) lives in _sandbox_codec.

_LEN = struct.Struct(">I")
#: 64 MiB ceiling — a hostile frame length can't force a huge alloc. Sourced from the codec so the
#: outer framing and the body decoder's own header bound are the SAME number by construction.
_MAX_FRAME: Final = codec.MAX_FRAME


class _Eof:
    """The dead-peer sentinel the reader thread enqueues on EOF.

    A parent-PRIVATE singleton with **no wire representation**: the old ``{"__eof__": True}`` frame was
    structurally indistinguishable from one the child could forge, handing a compromised worker a free
    kill-and-respawn lever (which also reset its own state)."""

    __slots__ = ()

    def __repr__(self) -> str:  # pragma: no cover - diagnostics only
        return "<sandbox EOF>"


_EOF: Final = _Eof()


# --- child stderr relay (BACKLOG #343, ADR 0176) ------------------------------

#: One ``read(2)``. The child is spawned with ``bufsize=0``, so ``proc.stderr`` is RAW: this is the
#: syscall size, not a buffer fill, and a short read is normal. Sized well above the line cap so a
#: flooding child costs syscalls proportional to volume, not to line count.
_STDERR_READ: Final = 65536

#: Longest run held while waiting for a newline. A MEMORY bound on the parent, never a redaction: a
#: Handler can write megabytes with no terminator, and an unbounded carry lets the child size the
#: parent's heap. Reaching it splits one write across several DEBUG records and DISCARDS NOTHING --
#: which is exactly what distinguishes it from the per-line byte cap ADR 0176 rejected. That cap was
#: rejected for a reason specific to this payload: truncating an HL7 v2 message to its first N bytes
#: keeps MSH and PID -- the header and the patient identifiers -- and discards the clinically bulky
#: remainder, so it preserves precisely the most identifying part of the record. It is the worst
#: available redaction for this format, not merely a weak one.
_STDERR_LINE_CAP: Final = 8192

#: Floor between two stderr notice records for one worker generation. The notice is what an operator
#: at INFO gets INSTEAD of content, so it must not become the flood it reports. Lines inside a window
#: are COUNTED and carried by the next notice, so nothing is dropped silently.
_STDERR_NOTICE_SECONDS: Final = 60.0

#: How long :meth:`SandboxSession.close` waits for each drain thread. Bounded on purpose: a surviving
#: grandchild can hold the pipes open indefinitely, and this runs under the session lock.
_STDERR_JOIN_SECONDS: Final = 1.0


class _StderrRelay:
    """One worker GENERATION's stderr, turned into log records (BACKLOG #343, ADR 0176).

    Content at DEBUG and only DEBUG; at INFO and above an attributed, rate-limited notice carrying
    identity and a COUNT and no content. CLAUDE.md section 9 holds here **by construction** rather than
    by operator discipline: there is no call site at which child stderr content becomes a record above
    DEBUG, so no configuration, verbosity setting or error path can put a printed message body on a
    default-level log. The rejected per-line byte cap is recorded on :data:`_STDERR_LINE_CAP`.

    One instance per spawn, reachable only through its own daemon thread. A relay whose child was killed
    can still be draining that child's buffered output while the next generation runs, so every counter
    lives here rather than on the session: a respawn replaces the session's thread list and the stale
    relay goes with it, unable to write into the live generation's state -- the same stale-generation
    isolation the fresh :class:`queue.Queue` gives the frame reader. The notice budget therefore resets
    on respawn; accepted, because a respawn costs a full ``load_config()``.

    PHI redaction is deliberately NOT re-implemented here. It is a property of the engine's log
    HANDLERS (:func:`~messagefoundry.logging_setup._install_phi_filters`), which this parent-side call
    site rides exactly like any other engine log record; a second call site would be the drift SDS-3.5
    warns about. Control-character scrubbing IS applied here, because "one child write is one log
    record" is this class's own framing contract and must not depend on how the host process configured
    logging (an embedded runner may carry plain handlers). The honest residual: in a host that never
    called ``configure_logging``, relayed DEBUG content reaches that host's handlers unredacted --
    exactly as any engine log line does, not a new exclusion. Identity is ``(inbound, pid,
    generation)``: pid alone is not unique, because an OS recycles pids and the whole design turns on a
    stale generation's relay coexisting with the live one."""

    __slots__ = ("_inbound", "_pid", "_gen", "_buf", "_pending", "_total", "_last_notice")

    def __init__(self, inbound: str, pid: int, generation: int) -> None:
        self._inbound = inbound
        self._pid = pid
        self._gen = generation
        self._buf = bytearray()
        self._pending = 0
        self._total = 0
        self._last_notice: float | None = None

    def run(self, stream: IO[bytes]) -> None:
        """Drain ``stream`` to EOF on a daemon thread. Never raises: an escaping exception would end
        the drain, and a pipe nobody drains blocks the child once the OS buffer fills."""
        try:
            while True:
                chunk = stream.read(_STDERR_READ)
                if not chunk:
                    break
                self.feed(chunk)
        except OSError:
            pass  # the pipe died with the worker; the kill path reports that, this thread does not
        finally:
            self.close()

    def feed(self, chunk: bytes) -> None:
        """Accumulate ``chunk`` and emit every complete line (or cap-length run) it completes."""
        self._buf.extend(chunk)
        while True:
            newline = self._buf.find(b"\n")
            # ``<=``, not ``<``: a terminator landing exactly ON the bound is a complete line of cap
            # length, not an over-length run. Splitting there instead would consume the bytes and leave
            # the newline to open the next pass, emitting a spurious empty record.
            if 0 <= newline <= _STDERR_LINE_CAP:
                line = bytes(self._buf[:newline])
                del self._buf[: newline + 1]
            elif len(self._buf) >= _STDERR_LINE_CAP:
                # No terminator within the bound: split rather than hold. Splitting mid-character is
                # why the decode below is `errors="replace"` and not strict.
                line = bytes(self._buf[:_STDERR_LINE_CAP])
                del self._buf[:_STDERR_LINE_CAP]
            else:
                return
            self._line(line)

    def close(self) -> None:
        """Flush a trailing unterminated write and force a final notice, so a child that exits
        mid-line is still both relayed and counted."""
        if self._buf:
            line = bytes(self._buf)
            self._buf.clear()
            self._line(line)
        self._notice(force=True)

    def _line(self, line: bytes) -> None:
        self._pending += 1
        self._total += 1
        self._notice(force=False)
        if not log.isEnabledFor(logging.DEBUG):
            # Section 9 rests on TWO independent facts, and this guard is only the second of them.
            # First: the sole call site carrying content is the ``log.debug`` below, so raising the
            # service level is the only way content becomes a record at all. Second: this guard, which
            # means the bytes never even become a `str` below DEBUG -- so the property survives an edit
            # that raises that call site, and no decode/scrub cost is paid on a flooding child. Both
            # were measured: breaking either alone still keeps a printed body off an INFO log.
            return
        # `errors="replace"`, never strict: a decode raise here would kill the drain and re-create the
        # deadlock this thread exists to prevent. Never latin-1 either -- it corrupts on NUL (CLAUDE.md
        # section 8).
        text = scrub_control_chars(line.removesuffix(b"\r").decode("utf-8", "replace"))
        log.debug(
            "sandbox stderr [%s pid %d gen %d]: %s", self._inbound, self._pid, self._gen, text
        )

    def _notice(self, *, force: bool) -> None:
        """Report THAT the child wrote to stderr -- identity and counts, never content.

        WARNING, not INFO: an operator running ``[logging].level = WARNING`` would never see an INFO
        notice, and a printing Handler would be completely invisible -- the accept-and-drop shape the
        count-and-log invariant forbids, reintroduced by the fix for it. Cry-wolf is answered by the
        throttle instead: one record per generation at first output, then at most one per window, and
        worker spawns are per-inbound-per-reload rather than per-message."""
        if self._pending == 0:
            return
        now = time.monotonic()
        throttled = (
            self._last_notice is not None and now - self._last_notice < _STDERR_NOTICE_SECONDS
        )
        if not force and throttled:
            return
        lines, self._pending = self._pending, 0
        self._last_notice = now
        log.warning(
            "sandbox worker wrote to stderr [%s pid %d gen %d]: %d line(s) since the last notice, "
            "%d total for this worker; content is relayed at DEBUG only (ADR 0176)",
            self._inbound,
            self._pid,
            self._gen,
            lines,
            self._total,
        )


def _write_frame(stream: Any, body: bytes) -> None:
    """Write one length-prefixed frame body. Raises on an over-cap frame (fail-closed) or a broken
    pipe; the caller maps either to :class:`SandboxError`."""
    if len(body) > _MAX_FRAME:
        raise SandboxError(f"sandbox frame too large: {len(body)} bytes")
    stream.write(_LEN.pack(len(body)))
    stream.write(body)
    stream.flush()


def _read_exact(stream: Any, n: int) -> bytes | None:
    """Read exactly ``n`` bytes, or ``None`` on EOF (a closed/crashed peer)."""
    chunks: list[bytes] = []
    remaining = n
    while remaining > 0:
        chunk = stream.read(remaining)
        if not chunk:
            return None
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def _read_frame_bytes(stream: Any) -> bytes | None:
    """Read one length-prefixed frame **body**, or ``None`` on EOF / a dead peer.

    Deliberately does **no** decoding: on the parent this runs on the daemon reader thread, whose
    ``except`` catches only ``OSError`` — a rejection raised there would kill the reader silently and
    the dispatch would HANG to the wall cap instead of failing closed. Decoding happens on the
    dispatch thread, inside its existing ``try``."""
    header = _read_exact(stream, _LEN.size)
    if header is None:
        return None
    (length,) = _LEN.unpack(header)
    if length > _MAX_FRAME:
        return None  # a corrupt/hostile length — treat as a dead peer
    return _read_exact(stream, length)


# --- process-tree reaping (Windows job object / POSIX process group) ----------
# A sandboxed Handler can spawn a grandchild that inherits fd 1 (the response pipe). Killing only the
# immediate worker would leave that grandchild alive, still holding the pipe and lingering as an
# orphan for the engine's lifetime. So the worker is spawned as its own process-group leader (POSIX)
# or assigned to a kill-on-close job object (Windows), and :meth:`SandboxSession._kill` reaps the
# whole tree. This is best-effort process hygiene, NOT the trust control — ADR 0087's codec, the
# per-dispatch ``secrets`` id, and the unsolicited-frame check are what keep a stray grandchild frame
# harmless — so a setup failure degrades to a single-process kill (logged) rather than wedging a feed.

#: ``SetInformationJobObject`` info class + the ``LimitFlags`` bit for a job that terminates its whole
#: process tree when the job is closed/terminated (``JOBOBJECTINFOCLASS`` / ``winnt.h``).
_JobObjectExtendedLimitInformation: Final = 9
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE: Final = 0x2000


# The three Win32 structs below are plain ctypes layout classes (no Windows-only ctypes types), so
# they define cleanly on every platform and are only ever *used* under a ``sys.platform == "win32"``
# guard. Field names/types mirror ``winnt.h`` exactly — the layout must match for the API to read it.
class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("PerProcessUserTimeLimit", ctypes.c_int64),
        ("PerJobUserTimeLimit", ctypes.c_int64),
        ("LimitFlags", ctypes.c_uint32),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", ctypes.c_uint32),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", ctypes.c_uint32),
        ("SchedulingClass", ctypes.c_uint32),
    )


class _IO_COUNTERS(ctypes.Structure):
    _fields_ = (
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    )


class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
    _fields_ = (
        ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
        ("IoInfo", _IO_COUNTERS),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    )


def _kill_single(proc: subprocess.Popen[bytes]) -> None:
    """Best-effort single-process kill (the reap fallback when no job/group is available)."""
    try:  # noqa: SIM105
        proc.kill()
    except OSError:
        pass


def _close_handle(kernel32: Any, handle: int) -> None:
    """Close a Win32 handle, swallowing a failure (nothing to do about it, and it must not raise
    from a kill path)."""
    try:  # noqa: SIM105
        kernel32.CloseHandle(ctypes.c_void_p(handle))
    except OSError:
        pass


def _assign_kill_on_close_job(proc: subprocess.Popen[bytes]) -> int | None:
    """Assign ``proc`` to a fresh Windows job object whose whole tree dies when the job is terminated
    or its last handle closes; return the job handle (an int) to hold open for the worker's lifetime.

    Returns ``None`` off Windows or on ANY failure (missing API, a job-setup error) — the caller then
    degrades to a single-process kill and a lingering grandchild is a hygiene residual, not a trust
    hole (ADR 0087). Mirrors the fail-open ctypes pattern in :mod:`messagefoundry.crashdump`."""
    if sys.platform != "win32":
        return None
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover - kernel32 is always present on win32
        return None
    create = getattr(kernel32, "CreateJobObjectW", None)
    set_info = getattr(kernel32, "SetInformationJobObject", None)
    assign = getattr(kernel32, "AssignProcessToJobObject", None)
    if create is None or set_info is None or assign is None:  # pragma: no cover - defensive
        log.warning(
            "sandbox: Windows job-object API missing; kill degrades to a single-process kill"
        )
        return None
    create.restype = ctypes.c_void_p
    create.argtypes = [ctypes.c_void_p, ctypes.c_wchar_p]
    set_info.restype = ctypes.c_int
    set_info.argtypes = [ctypes.c_void_p, ctypes.c_int, ctypes.c_void_p, ctypes.c_uint32]
    assign.restype = ctypes.c_int
    assign.argtypes = [ctypes.c_void_p, ctypes.c_void_p]
    handle = create(None, None)
    if not handle:  # pragma: no cover - defensive
        log.warning("sandbox: CreateJobObject failed; kill degrades to a single-process kill")
        return None
    info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
    info.BasicLimitInformation.LimitFlags = _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    set_ok = set_info(
        handle, _JobObjectExtendedLimitInformation, ctypes.byref(info), ctypes.sizeof(info)
    )
    # `proc._handle` is the CreateProcess handle (full access); race-free vs PID reuse, unlike a
    # re-OpenProcess by pid. It is a private CPython attr not in typeshed, hence the ignore.
    if not set_ok or not assign(handle, int(proc._handle)):  # type: ignore[attr-defined,unused-ignore]
        log.warning("sandbox: job-object setup failed; kill degrades to a single-process kill")
        _close_handle(kernel32, int(handle))
        return None
    return int(handle)


def _terminate_job(job: int) -> None:
    """Terminate every process in ``job`` (the worker and its whole tree) and close the handle."""
    if sys.platform != "win32":  # pragma: no cover - guard for the type-checker / non-Windows
        return
    try:
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
    except OSError:  # pragma: no cover - kernel32 is always present on win32
        return
    terminate = getattr(kernel32, "TerminateJobObject", None)
    if terminate is not None:
        terminate.argtypes = [ctypes.c_void_p, ctypes.c_uint32]
        terminate.restype = ctypes.c_int
        try:  # noqa: SIM105
            terminate(ctypes.c_void_p(job), 1)
        except OSError:  # pragma: no cover - defensive
            pass
    _close_handle(kernel32, job)


def _reap_process_tree(proc: subprocess.Popen[bytes], job: int | None) -> None:
    """Kill the worker AND every process it spawned.

    Windows: terminate the kill-on-close job the worker was assigned to (falling back to a
    single-process kill when none was assigned). POSIX: ``SIGKILL`` the worker's own process group,
    which ``start_new_session=True`` made it the leader of — guarded on ``pgid == proc.pid`` so this
    only ever signals the worker's own group and never the caller's (e.g. the engine/pytest group)."""
    if sys.platform == "win32":
        if job is not None:
            _terminate_job(job)
        else:
            _kill_single(proc)
        return
    try:
        pgid = os.getpgid(proc.pid)
    except (ProcessLookupError, PermissionError, OSError):
        _kill_single(proc)
        return
    if pgid == proc.pid:
        try:  # noqa: SIM105
            os.killpg(pgid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError, OSError):  # pragma: no cover - defensive
            pass
    else:  # pragma: no cover - start_new_session guarantees leadership; belt-and-suspenders
        _kill_single(proc)


# --- the persistent worker session (parent side) -----------------------------


class SandboxSession:
    """A persistent per-inbound sandbox worker (the parent-side handle).

    One session owns at most one live child process. Calls are **serialized** (a persistent worker
    handles one request at a time), which matches the per-inbound router/transform worker cadence.
    The child is spawned lazily on first dispatch and **re-spawned** transparently if it has died.
    ``mode=off`` sessions never spawn anything — :meth:`dispatch` isn't called on them (the caller
    branches on :attr:`mode`)."""

    def __init__(
        self,
        policy: SandboxPolicy,
        *,
        inbound: str,
        config_dir: str | Path,
        env: str | None,
        code_sets: Mapping[str, CodeSet] | None = None,
    ) -> None:
        self.policy = policy
        # Required, with no default, deliberately: this is what attributes a relayed stderr line to a
        # feed (ADR 0176), and a default would silently reinstate the unattributable relay for every
        # future caller. Parent-side only -- it is not marshalled, on the same rule as ``_env`` below.
        self._inbound = inbound
        self._config_dir = str(Path(config_dir))
        # Kept for the caller's signature (``engine.py`` resolves it into the config source and
        # ``wiring_runner._sandbox_for`` passes it here), but NOT marshalled: the
        # worker never read it — `load_config()` takes only a directory — and a dead field on the wire
        # is a field nobody validates.
        self._env = env
        # The ENGINE's live code-set tables, sent once per spawn in the boot frame so the child serves
        # exactly what mode=off would rather than its own re-read of `codesets/` (see
        # codec.enc_code_sets). `None` = the caller published none, so the child keeps its own load.
        self._code_sets = code_sets
        self._proc: subprocess.Popen[bytes] | None = None
        # The Windows kill-on-close job handle the current worker is assigned to (``None`` on POSIX,
        # off Windows, or when the worker has no live job). Always tracks ``self._proc``: set right
        # after spawn, cleared by every ``_kill``. POSIX reaps via the worker's process group instead.
        self._job: int | None = None
        self._responses: queue.Queue[Any] = queue.Queue()
        # The current generation's drain threads (frames on fd 1, stderr on fd 2), joined ONLY on the
        # shutdown path -- see :meth:`close`.
        self._threads: list[threading.Thread] = []
        # Monotonic per-session worker counter. Part of a relayed line's identity because a pid is NOT
        # a unique generation id: an OS recycles pids (aggressively on Windows), and a stale relay can
        # still be draining a killed child while the next one runs -- two generations' records would
        # then be byte-indistinguishable, which is the attribution defect this change exists to fix.
        self._generation = 0
        self._lock = threading.Lock()
        self._closed = False

    @property
    def mode(self) -> SandboxMode:
        return self.policy.mode

    # -- lifecycle ------------------------------------------------------------

    def _spawn(self) -> None:
        """Launch the child and complete its bootstrap (config load + guard install). Fail-closed."""
        # Reap any prior generation FIRST. A worker that died on its own (the ``_live_worker`` respawn
        # path) leaves its kill-on-close job handle in ``self._job``; overwriting it below without
        # reaping would leak the handle and let that dead worker's orphaned grandchild tree survive.
        # A no-op on the first spawn and whenever there is no live proc.
        self._kill(self._proc)
        # A fresh response queue per spawn so a prior (killed) worker's trailing EOF can't leak into
        # this generation's reads.
        self._responses = queue.Queue()
        self._generation += 1
        # Fixed argv (this interpreter + our own worker module), no shell, no
        # untrusted input in the command line — so B603 does not apply. ``start_new_session`` puts the
        # worker in its own POSIX process group so ``_kill`` can ``killpg`` its whole tree; it is a
        # POSIX-only ``setsid`` (False on Windows, where a job object does the reaping instead).
        proc = subprocess.Popen(  # nosec B603
            [sys.executable, "-m", WORKER_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            # CAPTURED, not inherited (BACKLOG #343, ADR 0176): with ``stderr=None`` the child's stderr
            # WAS the engine's, so admin-authored Handler code wrote unframed, unattributed bytes --
            # including whole message bodies -- straight into the operator's log of record.
            stderr=subprocess.PIPE,
            bufsize=0,
            close_fds=True,
            start_new_session=sys.platform != "win32",
        )
        assert proc.stdin is not None and proc.stdout is not None and proc.stderr is not None
        # BOTH drains start before anything that can raise between here and the boot frame write. For
        # fd 1 that ordering is pre-existing; for fd 2 it is a REQUIREMENT this change creates. A PIPE
        # nobody drains blocks its writer once the fixed OS buffer fills (tens of KiB), and the boot frame
        # below triggers ``load_config()`` -- top-level admin config, the earliest untrusted code and
        # the first thing that can print. Undrained, every spawn would hang to ``startup_seconds`` and
        # report a startup timeout naming the wrong cause. Starting them before the job assignment also
        # closes the window in which that assignment raising would leave a live child with an undrained
        # pipe and no reaper. Per-generation state travels as THREAD ARGUMENTS, never off ``self``, so
        # a stale generation's drain cannot write into the live one's counters.
        gen = self._generation
        relay = _StderrRelay(self._inbound, proc.pid, gen)
        self._threads = [
            threading.Thread(
                target=self._reader_loop,
                args=(proc.stdout, self._responses),
                name=f"mf-sandbox-frames-{self._inbound}-{gen}",
                daemon=True,
            ),
            threading.Thread(
                target=relay.run,
                args=(proc.stderr,),
                name=f"mf-sandbox-stderr-{self._inbound}-{gen}",
                daemon=True,
            ),
        ]
        for thread in self._threads:
            thread.start()
        # Assign the Windows kill-on-close job BEFORE the boot frame. The boot frame triggers
        # ``load_config()``, which runs top-level admin config — the earliest untrusted code and the
        # first chance to spawn a grandchild. Until then the worker parks on its first stdin read, so
        # assigning here is race-free: any process the worker later spawns is already in the job. The
        # drains above do not disturb that argument, which turns on the CHILD's first stdin read and
        # not on what the parent's threads are doing.
        self._job = _assign_kill_on_close_job(proc)
        try:
            _write_frame(
                proc.stdin,
                codec.encode_boot(
                    config_dir=self._config_dir,
                    forbidden=self.policy.forbidden_modules,
                    cpu_seconds=self.policy.cpu_seconds,
                    mem_mb=self.policy.mem_mb,
                    code_sets=self._code_sets,
                ),
            )
        except (OSError, SandboxError) as exc:
            self._kill(proc)
            raise SandboxError(f"failed to bootstrap sandbox worker: {exc}") from exc
        try:
            frame = self._responses.get(timeout=self.policy.startup_seconds)
        except queue.Empty:
            self._kill(proc)
            raise SandboxError(
                f"sandbox worker did not start within {self.policy.startup_seconds}s"
            ) from None
        if frame is _EOF:
            self._kill(proc)
            raise SandboxError("sandbox worker exited during bootstrap")
        try:
            ready, detail = codec.decode_boot_reply(frame)
        except SandboxError as exc:
            self._kill(proc)
            raise SandboxError(f"sandbox worker bootstrap frame was rejected: {exc}") from exc
        if not ready:
            self._kill(proc)
            raise SandboxError(f"sandbox worker bootstrap failed: {detail}")
        self._proc = proc

    def _reader_loop(self, stdout: Any, sink: queue.Queue[Any]) -> None:
        """Drain the child's stdout into ``sink`` — **framing only**, never decoding (see
        :func:`_read_frame_bytes`). Runs on a daemon thread; a fresh queue per spawn means a stale
        reader's writes are harmlessly ignored."""
        try:
            while True:
                body = _read_frame_bytes(stdout)
                if body is None:
                    sink.put(_EOF)
                    return
                sink.put(body)
        except OSError:
            sink.put(_EOF)

    def _kill(self, proc: subprocess.Popen[bytes] | None) -> None:
        if proc is None:
            return
        # Reap the WHOLE tree, not just ``proc``: a grandchild the Handler spawned inherited fd 1 (the
        # response pipe) and would outlive a bare ``proc.kill()`` as an orphan still holding the pipe.
        # ``self._job`` is the current worker's kill-on-close job on Windows (``None`` on POSIX, where
        # the worker's process group is reaped instead). Clear it after — the handle is now closed.
        #
        # The same reap EOFs fd 2, so the stderr relay thread ends on its own here exactly as the frame
        # reader does. Neither thread is joined on THIS path (a respawn must not wait on a grandchild
        # that holds a pipe open, and this runs under the session lock), and neither pipe is closed:
        # closing a file object under a mid-read thread raises ``ValueError``, which is not what either
        # drain's ``except OSError`` catches, so it would escape into ``threading.excepthook``. The
        # shutdown-only bounded join lives in :meth:`close`.
        _reap_process_tree(proc, self._job)
        self._job = None
        try:  # noqa: SIM105
            proc.wait(timeout=5)
        except (subprocess.TimeoutExpired, OSError):
            pass
        if proc is self._proc:
            self._proc = None

    def close(self) -> None:
        """Stop the worker cleanly (idempotent). Safe to call from a shutdown path."""
        with self._lock:
            self._closed = True
            self._kill(self._proc)
            for thread in self._threads:
                # A bounded join, and ONLY on the shutdown path. The stderr relay LOGS, and a daemon
                # thread that logs can still be inside a handler's ``emit`` when ``logging.shutdown``
                # runs at exit -- writing to a closed stream, or holding a handler lock the atexit hook
                # then blocks on. An UNBOUNDED join would be wrong (a surviving grandchild holds the
                # pipes, and this runs under ``self._lock`` from ``asyncio.to_thread``), but a short one
                # lets the final flush land before the handlers close. The reap above EOFs both pipes,
                # so the usual cost is microseconds; the budget is spent only when a grandchild survived
                # it, and the runner closes sessions SEQUENTIALLY, so that ceiling is per inbound.
                # The respawn path in :meth:`_spawn` deliberately does not join at all.
                thread.join(timeout=_STDERR_JOIN_SECONDS)
            self._threads = []

    def _reject_unsolicited(self, proc: subprocess.Popen[bytes] | None, when: str) -> None:
        """Drop the worker if anything is pending that no outstanding request asked for.

        The protocol is strictly one request, one frame, so a FRAME queued **before** a dispatch or
        left over **after** its answer was written by something other than the call we made — a
        Handler writing straight to fd 1, or a grandchild that inherited it while the worker was
        alive. Letting such a frame sit in the queue is the whole exploit: the next dispatch would
        take it as its own answer. Drop the
        worker and dead-letter the message in hand; :meth:`_kill` then reaps that grandchild along
        with the rest of the worker's tree, so it cannot keep writing to the pipe.

        **The justification is the protocol violation, NOT a claim that fd 1 is unreachable.** An
        earlier version of this docstring said the ADR 0176 stdout rebind meant "the text layer cannot
        reach fd 1 at all", so "there is no benign case to preserve". **Both were false, and this
        docstring is where a DESTRUCTIVE action is reasoned from, which is what made it worth
        correcting rather than softening.** Rebinding the *name* ``sys.stdout`` leaves the descriptor
        wide open: ``sys.__stdout__`` is still a text layer on fd 1 — its ``.buffer`` is the very
        ``BufferedWriter`` :func:`_sandbox_worker.main` captured as the frame writer — and
        ``os.write(1, ...)`` and ``open(1, "wb")`` reach it too. What the rebind actually removes is
        the *accidental* case (a bare ``print()`` in a Handler), which is worth having and is all it
        claims in ADR 0176 and in the worker's own bootstrap comment; asserting more here contradicted
        both, in the same change that wrote them.

        The action is unchanged and does not need the stronger claim: a frame no outstanding request
        asked for violates the one-request-one-frame protocol whether it was written deliberately or
        by accident, and the queue cannot tell the difference. Benign-but-unsolicited is still a frame
        the next dispatch would misread as its answer.

        :data:`_EOF` is the opposite case and must NOT be treated the same way. It is a parent-private
        singleton with no wire form (see :class:`_Eof`), so a worker cannot manufacture one — it
        carries no trust information at all, only "the peer is gone". Dead-lettering on it would fail
        closed against a signal that proves nothing: a child that crashes in the instant *after*
        writing a correct, correlation-proven answer would lose a message it had already answered, and
        a child that died between dispatches would lose the next one instead of respawning
        transparently. Reap it and let the caller carry on."""
        try:
            stray = self._responses.get_nowait()
        except queue.Empty:
            return
        self._kill(proc)
        if stray is _EOF:
            return
        raise SandboxError(
            f"sandbox worker wrote an unsolicited response frame {when} a dispatch — "
            "the pipe is not trustworthy"
        )

    def _live_worker(self) -> subprocess.Popen[bytes]:
        """The session's worker — spawned or respawned as needed — on a pipe nothing is waiting on.

        The unsolicited check runs **after** the liveness check, not before: a killed worker's queue is
        discarded wholesale by :meth:`_spawn`, so its leftovers are neither reachable nor evidence
        about the *new* child. Only a REUSED worker can hand us a leftover, and only there is one worth
        judging. A leftover EOF reaps it (see :meth:`_reject_unsolicited`), so spawn once more rather
        than dead-letter this message on a peer that merely died."""
        if self._proc is None or self._proc.poll() is not None:
            self._spawn()
        self._reject_unsolicited(self._proc, "before")
        if self._proc is None:
            self._spawn()
        proc = self._proc
        assert proc is not None
        return proc

    # -- dispatch -------------------------------------------------------------

    def dispatch(
        self,
        phase: str,
        name: str,
        payload: object,
        run_context: RunContext,
        *,
        origin: tuple[str | bytes, str] | None = None,
    ) -> object:
        """Run ``name`` on ``payload`` in the worker; return its rebuilt result.

        ``phase`` is ``"router"``, ``"transform"``, or ``"accepts"`` (ADR 0084) — for ``"accepts"``,
        ``name`` keys the HANDLER whose predicate is being run and the worker re-establishes the ROUTER
        run-context phase (a predicate is a router-stage peek). ``origin`` is the ``(raw,
        content_type)`` the caller derived ``payload`` from, when it did; the child then rebuilds a
        byte-faithful object with the identical constructor. Serialized against concurrent callers. Any
        isolation fault (crash / timeout / denial / codec rejection) raises :class:`SandboxError`;
        a plain, still-alive worker survives a *denied* call so the next message reuses it. The one
        thing it does **not** survive is writing a frame nobody asked for
        (see :meth:`_reject_unsolicited`) — that is a lost worker and a dead-lettered message."""
        with self._lock:
            if self._closed:
                raise SandboxError("sandbox session is closed")
            proc = self._live_worker()
            assert proc.stdin is not None
            # A FRESH unpredictable id per dispatch, not a counter: the worker learns it only when it
            # reads this request frame, which the check above proves is the first thing it can answer.
            # A derivable id (a per-spawn nonce plus a sequence) let the code running dispatch N
            # compute N+1's and pre-stage its answer.
            request_id = secrets.token_hex(16)
            try:
                _write_frame(
                    proc.stdin,
                    codec.encode_request(
                        request_id=request_id,
                        phase=phase,
                        name=name,
                        payload=payload,
                        origin=origin,
                        run_context=run_context,
                    ),
                )
            except (OSError, SandboxError) as exc:
                # A payload/run-context outside the closed grammar, or a broken pipe: fail closed and
                # reset the worker.
                self._kill(proc)
                raise SandboxError(f"failed to marshal sandbox {phase} {name!r}: {exc}") from exc
            try:
                frame = self._responses.get(timeout=self.policy.wall_seconds)
            except queue.Empty:
                # Wall cap exceeded — the authoritative resource bound on every platform. Kill the
                # runaway child (a busy-loop can't wedge intake) and fail closed.
                self._kill(proc)
                raise SandboxError(
                    f"sandbox {phase} {name!r} exceeded the {self.policy.wall_seconds}s wall cap"
                ) from None
            if frame is _EOF:
                self._kill(proc)
                raise SandboxError(f"sandbox worker crashed while running {phase} {name!r}")
            try:
                # Decoding happens HERE, on the dispatch thread, inside this try — not on the daemon
                # reader thread, where a rejection would be a silent reader death and a wall-cap hang.
                resp = codec.decode_response(frame, request_id=request_id, phase=phase, name=name)
            except SandboxError as exc:
                # A desynchronized or forged frame: the worker's stream can no longer be trusted to
                # line up with our requests, so drop it and respawn on the next message.
                self._kill(proc)
                raise SandboxError(
                    f"sandbox {phase} {name!r} returned an invalid frame: {exc}"
                ) from exc
            # One request, one frame: a second FRAME already queued means the worker is writing frames
            # nobody asked for, so this answer is not trustworthy either. (A queued EOF is only a dead
            # peer — it reaps the worker and leaves this proven answer standing.)
            self._reject_unsolicited(proc, "after")
            if not resp.ok:
                verdict = "denied" if resp.kind == "denied" else "failed"
                raise SandboxError(f"sandbox {verdict} {phase} {name!r}: {resp.error}")
            return resp.result


def run_sandboxed(
    fn: Callable[[Any], Any],
    payload: object,
    *,
    phase: str,
    name: str,
    run_context: RunContext | None,
    session: SandboxSession | None,
    origin: tuple[str | bytes, str] | None = None,
) -> object:
    """Run ``fn`` on ``payload`` under the isolation policy of ``session`` and return its result.

    With ``session is None`` or ``session.mode is OFF`` this is exactly ``fn(payload)`` — in-process,
    byte-identical, zero overhead (the parity default); nothing above that branch touches ``payload``,
    ``origin``, or the codec. With ``session.mode is SUBPROCESS`` the call is marshalled to the
    persistent worker via :meth:`SandboxSession.dispatch`, enforcing the forbidden-import / resource
    caps and raising :class:`SandboxError` on any violation.

    ``origin`` is the ``(raw, content_type)`` the caller built ``payload`` from — pass it **only** when
    the caller derived the payload itself, so the child can rebuild it byte-faithfully; ``None`` makes
    the codec describe the caller's actual object instead."""
    if session is None or session.mode is SandboxMode.OFF:
        return fn(payload)
    rc = run_context if run_context is not None else RunContext()
    return session.dispatch(phase, name, payload, rc, origin=origin)
