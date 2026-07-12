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
  (:mod:`messagefoundry.pipeline._sandbox_worker`). The parent marshals ``(phase, name, payload,
  run_context)`` over a length-prefixed pickle pipe; the worker looks the function up in **its own**
  freshly-loaded :class:`~messagefoundry.config.wiring.Registry`, re-establishes the run-scoped
  context providers, runs the function, and returns its raw result. The worker is *long-lived* (one
  child per inbound), never a per-message fork — a fork per message would destroy the throughput
  target.

**What isolation buys (and its honest limits).** The child is a *separate OS process*: even if the
admin code opens a socket or spins the CPU, it cannot touch the parent's DEK, audit chain, or
sockets — those objects are never constructed in the child (it loads the message *graph*, not the
store/crypto). On top of that address-space boundary the child adds defence-in-depth: a
forbidden-import guard (``socket``/store/crypto), a wall-clock cap enforced by the parent (plus
POSIX ``RLIMIT_CPU``/``RLIMIT_AS`` when available), and a fail-closed refusal of the live
``db_lookup``/``fhir_lookup`` bridges (they re-enter the event loop, which a process boundary
breaks — forwarding them over IPC is a documented next-phase residual).

**Fail-closed.** Any isolation denial — a forbidden import/op, a resource cap exceeded, a worker
crash, or an unmarshallable payload/run-context — raises :class:`SandboxError`. The caller (the
router/transform worker) routes it to ``ERROR``/dead-letter **post-ACK** via the existing
``_apply_router_internal_error`` / ``_apply_transform_internal_error`` paths — never a NAK, never an
accept-and-drop, never a crashed connection.

**Engine-side validation stays engine-side.** The worker returns only the *raw* Router/Handler
return value; the fail-closed handler-name / outbound-name validation (see
:func:`messagefoundry.pipeline.dryrun.route_only` / ``transform_one``) runs in the parent on that
result, so a compromised worker cannot smuggle an unknown destination past the graph.

**Layering (CLAUDE.md §4).** This is a pure ``pipeline/`` library — no ``api/`` or ``console/``
imports. It depends only on ``config`` (the :class:`RunContext` shape) and the stdlib.
"""

from __future__ import annotations

import enum
import logging
import pickle  # nosec B403 — pickle only carries IPC frames between the engine and its own spawned sandbox worker, never external/untrusted input
import queue
import struct
import subprocess
import sys
import threading
from collections.abc import Mapping
from dataclasses import dataclass, replace
from pathlib import Path
from typing import Any, Callable

from messagefoundry.config.run_context import RunContext

__all__ = [
    "SandboxMode",
    "SandboxError",
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


class SandboxMode(str, enum.Enum):
    """How a Router/Handler is executed relative to the engine process."""

    OFF = "off"  # in-process, byte-identical, zero overhead (default)
    SUBPROCESS = "subprocess"  # persistent per-inbound worker child


class SandboxError(RuntimeError):
    """A sandboxed Router/Handler was denied, timed out, crashed, or could not be marshalled.

    Raised only on the ``subprocess`` path (``off`` never raises this). The caller treats it exactly
    like any other post-ACK router/transform failure: ``ERROR``/dead-letter, no NAK."""


@dataclass(frozen=True)
class SandboxPolicy:
    """Resolved ``[sandbox]`` policy. Pure data (picklable) so the caps travel to the worker.

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


# --- length-prefixed pickle framing over the worker pipe ---------------------

_LEN = struct.Struct(">I")
_MAX_FRAME = 64 * 1024 * 1024  # 64 MiB ceiling — a hostile frame length can't force a huge alloc


def _write_frame(stream: Any, obj: object) -> None:
    """Pickle ``obj`` and write it length-prefixed. Raises on an unpicklable object (fail-closed) or a
    broken pipe; the caller maps either to :class:`SandboxError`."""
    body = pickle.dumps(obj, protocol=pickle.HIGHEST_PROTOCOL)
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


def _read_frame(stream: Any) -> Any:
    """Read one length-prefixed pickled frame, or ``None`` on EOF. Sentinel used to signal a dead peer."""
    header = _read_exact(stream, _LEN.size)
    if header is None:
        return None
    (length,) = _LEN.unpack(header)
    if length > _MAX_FRAME:
        return None  # a corrupt/hostile length — treat as a dead peer
    body = _read_exact(stream, length)
    if body is None:
        return None
    # `body` is an IPC frame read from a private pipe whose other end is our own
    # spawned sandbox worker (child) / engine (parent) — never external/untrusted
    # data — so the pickle-deserialization risk (B301 / semgrep) does not apply here.
    return pickle.loads(body)  # nosec B301  # nosemgrep: mf-no-insecure-deserialization


# --- the persistent worker session (parent side) -----------------------------


class SandboxSession:
    """A persistent per-inbound sandbox worker (the parent-side handle).

    One session owns at most one live child process. Calls are **serialized** (a persistent worker
    handles one request at a time), which matches the per-inbound router/transform worker cadence.
    The child is spawned lazily on first dispatch and **re-spawned** transparently if it has died.
    ``mode=off`` sessions never spawn anything — :meth:`dispatch` isn't called on them (the caller
    branches on :attr:`mode`)."""

    def __init__(self, policy: SandboxPolicy, *, config_dir: str | Path, env: str | None) -> None:
        self.policy = policy
        self._config_dir = str(Path(config_dir))
        self._env = env
        self._proc: subprocess.Popen[bytes] | None = None
        self._responses: queue.Queue[Any] = queue.Queue()
        self._lock = threading.Lock()
        self._closed = False

    @property
    def mode(self) -> SandboxMode:
        return self.policy.mode

    # -- lifecycle ------------------------------------------------------------

    def _spawn(self) -> None:
        """Launch the child and complete its bootstrap (config load + guard install). Fail-closed."""
        # A fresh response queue per spawn so a prior (killed) worker's trailing EOF can't leak into
        # this generation's reads.
        self._responses = queue.Queue()
        # Fixed argv (this interpreter + our own worker module), no shell, no
        # untrusted input in the command line — so B603 does not apply.
        proc = subprocess.Popen(  # nosec B603
            [sys.executable, "-m", WORKER_MODULE],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=None,  # let the child's stderr (logging) pass through to the engine's stderr
            bufsize=0,
            close_fds=True,
        )
        assert proc.stdin is not None and proc.stdout is not None
        reader = threading.Thread(
            target=self._reader_loop, args=(proc.stdout, self._responses), daemon=True
        )
        reader.start()
        try:
            _write_frame(
                proc.stdin,
                {
                    "config_dir": self._config_dir,
                    "env": self._env,
                    "forbidden": list(self.policy.forbidden_modules),
                    "cpu_seconds": self.policy.cpu_seconds,
                    "mem_mb": self.policy.mem_mb,
                },
            )
        except (OSError, SandboxError) as exc:
            self._kill(proc)
            raise SandboxError(f"failed to bootstrap sandbox worker: {exc}") from exc
        try:
            ready = self._responses.get(timeout=self.policy.startup_seconds)
        except queue.Empty:
            self._kill(proc)
            raise SandboxError(
                f"sandbox worker did not start within {self.policy.startup_seconds}s"
            ) from None
        if isinstance(ready, dict) and ready.get("__eof__"):
            self._kill(proc)
            raise SandboxError("sandbox worker exited during bootstrap")
        if not (isinstance(ready, dict) and ready.get("ready")):
            self._kill(proc)
            detail = ready.get("error") if isinstance(ready, dict) else repr(ready)
            raise SandboxError(f"sandbox worker bootstrap failed: {detail}")
        self._proc = proc

    def _reader_loop(self, stdout: Any, sink: queue.Queue[Any]) -> None:
        """Drain the child's stdout into ``sink``. Runs on a daemon thread; a fresh queue per spawn
        means a stale reader's writes are harmlessly ignored."""
        try:
            while True:
                frame = _read_frame(stdout)
                if frame is None:
                    sink.put({"__eof__": True})
                    return
                sink.put(frame)
        except OSError:
            sink.put({"__eof__": True})

    def _kill(self, proc: subprocess.Popen[bytes] | None) -> None:
        if proc is None:
            return
        try:
            proc.kill()
        except OSError:
            pass
        try:
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

    # -- dispatch -------------------------------------------------------------

    def dispatch(self, phase: str, name: str, payload: object, run_context: RunContext) -> object:
        """Run ``name`` on ``payload`` in the worker; return its raw result.

        ``phase`` is ``"router"``, ``"transform"``, or ``"accepts"`` (ADR 0084) — for ``"accepts"``,
        ``name`` keys the HANDLER whose predicate is being run and the worker re-establishes the ROUTER
        run-context phase (a predicate is a router-stage peek). Serialized against concurrent callers. Any
        isolation fault (crash / timeout / denial / marshalling failure) raises :class:`SandboxError`;
        a plain, still-alive worker survives a *denied* call so the next message reuses it."""
        with self._lock:
            if self._closed:
                raise SandboxError("sandbox session is closed")
            if self._proc is None or self._proc.poll() is not None:
                self._spawn()
            proc = self._proc
            assert proc is not None and proc.stdin is not None
            try:
                _write_frame(
                    proc.stdin,
                    {"phase": phase, "name": name, "payload": payload, "run_context": run_context},
                )
            except (OSError, SandboxError, pickle.PicklingError, TypeError) as exc:
                # Unpicklable payload/run-context, or a broken pipe: fail closed and reset the worker.
                self._kill(proc)
                raise SandboxError(f"failed to marshal sandbox {phase} {name!r}: {exc}") from exc
            try:
                resp = self._responses.get(timeout=self.policy.wall_seconds)
            except queue.Empty:
                # Wall cap exceeded — the authoritative resource bound on every platform. Kill the
                # runaway child (a busy-loop can't wedge intake) and fail closed.
                self._kill(proc)
                raise SandboxError(
                    f"sandbox {phase} {name!r} exceeded the {self.policy.wall_seconds}s wall cap"
                ) from None
            if isinstance(resp, dict) and resp.get("__eof__"):
                self._kill(proc)
                raise SandboxError(f"sandbox worker crashed while running {phase} {name!r}")
            if not (isinstance(resp, dict) and resp.get("ok")):
                detail = resp.get("error") if isinstance(resp, dict) else repr(resp)
                raise SandboxError(f"sandbox denied {phase} {name!r}: {detail}")
            return resp["result"]


def _snapshot_view(view: Any) -> Any:
    """Coerce one run-scoped view to a picklable point-in-time snapshot for the worker pipe.

    The engine builds ``reference_view``/``state_view`` (and, later, ``response_view``) as live
    :class:`types.MappingProxyType` windows onto the store's caches
    (:meth:`Store.reference_view`/:meth:`Store.state_view`) — and a ``mappingproxy`` is **not**
    picklable, so a live view would fail-closed at marshal time (dead-lettering every message) rather
    than reach the worker. Snapshot it to a plain ``dict`` (both levels of the ``{name: {key: value}}``
    reference view), which is exactly the read-only content the router/transform would have seen at
    this instant in-process — and re-run stability (CLAUDE.md §2) makes a point-in-time copy the
    contract anyway. Non-mapping / already-picklable views (``None``, a plain ``dict``) pass through
    unchanged (a plain ``dict`` is still copied so the worker can't observe a later parent mutation)."""
    if isinstance(view, Mapping):
        return {k: (dict(v) if isinstance(v, Mapping) else v) for k, v in view.items()}
    return view


def _picklable_run_context(rc: RunContext) -> RunContext:
    """Return a marshalling-safe copy of ``rc`` with its live store views snapshotted to plain dicts.

    The mapping fields the engine fills from the live store are the only unpicklable members; the
    scalar fields and ``code_sets`` (a ``{name: CodeSet}`` of ``__slots__`` mappings) already pickle,
    so they pass through :func:`dataclasses.replace` unchanged."""
    return replace(
        rc,
        reference_view=_snapshot_view(rc.reference_view),
        state_view=_snapshot_view(rc.state_view),
        response_view=_snapshot_view(rc.response_view),
    )


def run_sandboxed(
    fn: Callable[[Any], Any],
    payload: object,
    *,
    phase: str,
    name: str,
    run_context: RunContext | None,
    session: SandboxSession | None,
) -> object:
    """Run ``fn`` on ``payload`` under the isolation policy of ``session`` and return its raw result.

    With ``session is None`` or ``session.mode is OFF`` this is exactly ``fn(payload)`` — in-process,
    byte-identical, zero overhead (the parity default). With ``session.mode is SUBPROCESS`` the call
    is marshalled to the persistent worker via :meth:`SandboxSession.dispatch`, enforcing the
    forbidden-import / resource caps and raising :class:`SandboxError` on any violation. The live
    ``RunContext`` is snapshotted to a picklable form first (:func:`_picklable_run_context`) so the
    store-backed ``MappingProxyType`` views the engine always passes cross the process boundary."""
    if session is None or session.mode is SandboxMode.OFF:
        return fn(payload)
    rc = run_context if run_context is not None else RunContext()
    return session.dispatch(phase, name, payload, _picklable_run_context(rc))
