# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The sandbox worker child process (ADR 0087, BACKLOG #197).

Launched by :class:`messagefoundry.pipeline.sandbox.SandboxSession` through
:func:`messagefoundry.childenv.python_child_argv`, which runs this module the way ``python -m``
would. It speaks the length-prefixed **MFW2** codec
(:mod:`messagefoundry.pipeline._sandbox_codec`) on stdin/stdout — a closed-tag JSON+segment wire whose
decode path cannot name a type, import a module, or reach ``__reduce__``. Nothing is pickled in either
direction, in either process.

1. **Bootstrap** — reads one ``boot`` frame ``{snapshot, forbidden, mem_mb, code_sets}``, loads
   the message :class:`~messagefoundry.config.wiring.Registry` from the engine's config snapshot
   (``load_snapshot``, the loader the engine uses, over the bytes the engine loaded and checked; the
   worker never reads the config directory, vault BACKLOG #2596),
   **adopts the engine's code-set tables** from the frame in place of the snapshot's ``codesets/``,
   which the frame then leaves out (when the parent published any — a session constructed without
   them sends the files and leaves the child to parse them), applies the POSIX resource caps where available, installs the forbidden-import guard, and
   replies ``ready`` (or ``bootfail`` on any failure).
2. **Serve** — for each subsequent ``req`` frame ``{id, phase, name, payload, rc}`` it rebuilds the
   payload with the engine's own constructor, looks the Router/Handler up in *its own* registry,
   re-establishes the run-scoped context providers for the phase (substituting the boot-carried code
   sets, which the per-dispatch frame deliberately does not repeat), runs the function, and
   **describes** the result back as ``ok`` — or ``fail`` with ``kind`` ``denied`` (forbidden import, a
   live ``db_lookup``/``fhir_lookup`` at ``mode=subprocess``), ``error`` (a plain handler raise, an
   undescribable result, or at ``mode=isolated`` a lookup error, the lookup having been asked of the
   parent through :class:`_Broker` while the Handler ran) or
   ``memory`` (a ``MemoryError``, after which the worker exits so the parent starts a fresh one).
   The reply echoes the request's ``id``, ``phase`` and ``name`` so the parent can prove the frame
   answers the call it made.

stdout is the binary IPC channel — **nothing else may write to it**, and :func:`_redirect_stdout_to_stderr`
states that intent by pointing ``sys.stdout`` at stderr for the rest of the process (ADR 0176). Logging
and any diagnostics go to stderr — which the parent CAPTURES and relays, attributed, with content
confined below INFO — through the **same PHI-redaction + control-char-scrub filter chain the engine
installs on its own handlers** (:func:`~messagefoundry.logging_setup.configure_stderr_logging`), so a
child log line carrying message-derived content is redacted and CR/LF-neutralized here as well as on
the parent's own handlers. The engine parent enforces the wall-clock cap and kills a runaway child, so
this process never needs its own watchdog.
"""

from __future__ import annotations

import contextlib
import logging
import os
import sys
import threading
from dataclasses import replace
from typing import Any

from messagefoundry.logging_setup import configure_stderr_logging

# stdout is the IPC channel, so the root logger goes to stderr — a stray log line there cannot corrupt
# a frame. It is `configure_stderr_logging` rather than a bare `basicConfig` because redaction is a
# property of the HANDLER: basicConfig's handler carries no filters, so this child's records would
# reach the engine's stderr with neither PHI redaction nor CR/LF scrubbing (BACKLOG #1054).
configure_stderr_logging()
log = logging.getLogger("messagefoundry.sandbox.worker")

#: Keeps the startup ``sys.stdout`` wrapper alive for the process lifetime. Load-bearing, not
#: belt-and-braces: :func:`main` captures ``sys.stdout.buffer`` (the ``BufferedWriter``), which does
#: **not** keep its ``TextIOWrapper`` alive; after the rebind ``sys.__stdout__`` is the only other
#: reference, ``TextIOWrapper.__del__`` closes its buffer, and admin config -- which runs after the
#: rebind -- may assign ``sys.__stdout__``. A one-line ``sys.__stdout__ = None`` in a config module
#: would otherwise close fd 1 and make the next frame write raise ``ValueError``, which none of
#: :func:`main`'s ``except (OSError, SandboxError)`` clauses catch.
_ORIGINAL_STDOUT: Any = None


def _redirect_stdout_to_stderr() -> None:
    """Point ``sys.stdout`` at ``sys.stderr`` so ordinary text output cannot reach fd 1 (BACKLOG #343).

    fd 1 is the MFW2 frame channel. A Handler's ``print()`` lands in the startup ``TextIOWrapper``'s
    buffer while frames go through the underlying ``BufferedWriter``, so today it happens not to
    corrupt a frame -- an artifact of two buffers over one descriptor that nobody chose and nothing
    pins. Aliasing the NAME states the intent: text goes to stderr, where the parent's relay attributes
    it and confines its content below INFO.

    Design intent, **not** an enforced invariant: ``sys.__stdout__.buffer``, ``os.write(1, ...)`` and
    ``open(1, "wb")`` still reach fd 1. The closed-tag codec plus the parent's unsolicited-frame check
    remain the control for a raw writer -- claiming fd 1 is enforced frames-only would be a
    compensating control resting on a false premise (SDS-3.7).

    Not ``os.dup2(2, 1)``, which moves the DESCRIPTOR and would take the frame writer's own
    ``BufferedWriter`` with it; not ``detach()``, which leaves ``sys.__stdout__`` unusable."""
    global _ORIGINAL_STDOUT
    _ORIGINAL_STDOUT = sys.stdout
    sys.stdout = sys.stderr


class _ForbiddenImportFinder:
    """A ``sys.meta_path`` finder that fails a forbidden import loudly.

    Matches the exact dotted module or a submodule of it (``socket`` blocks ``socket`` and
    ``socket.x``; ``messagefoundry.store`` blocks only that subtree, never ``messagefoundry`` itself).
    Returns ``None`` for everything else so normal resolution continues."""

    def __init__(self, prefixes: tuple[str, ...]) -> None:
        self._prefixes = prefixes

    def find_spec(self, name: str, path: Any = None, target: Any = None) -> None:
        from messagefoundry.pipeline._sandbox_codec import SandboxError

        for prefix in self._prefixes:
            if name == prefix or name.startswith(prefix + "."):
                raise SandboxError(f"import of {name!r} is forbidden inside the sandbox (ADR 0087)")
        return None


#: The cap a ``MemoryError`` reply names when :func:`_apply_resource_caps` set none.
_NO_MEMORY_CAP = "no memory cap is in force in this worker"


def _proc_status_kib(field: str) -> int | None:
    """One ``kB`` field of ``/proc/self/status``, such as ``VmData``, or ``None`` where it cannot be
    read (no procfs, or no such field)."""
    try:
        # latin-1, not ascii: the first line is the process name, which may not be ASCII.
        with open("/proc/self/status", encoding="latin-1") as status:
            for line in status:
                if line.startswith(field + ":"):
                    return int(line.split()[1])
    except (OSError, ValueError, IndexError):
        return None
    return None


def _rlimit_data_counts_mmap() -> bool:
    """Whether this kernel counts private writable ``mmap`` memory against ``RLIMIT_DATA``. Linux
    4.7 and later do; earlier kernels count only the ``brk`` heap, which would leave most large
    allocations outside the cap, so the caller falls back to ``RLIMIT_AS`` there."""
    try:
        release = os.uname().release  # type: ignore[attr-defined,unused-ignore]
        major, minor = (int(part) for part in release.split(".")[:2])
    except (AttributeError, ValueError):
        return False
    return (major, minor) >= (4, 7)


def _apply_resource_caps(mem_mb: int | None) -> str:
    """Best-effort POSIX memory backstop (a no-op on Windows); return the cap in words, for the reply
    to a call that runs out of memory. The parent's wall-clock cap is the authoritative bound on every
    platform. There is deliberately no ``RLIMIT_CPU``, so CPU spent outside a call has no bound (ADR
    0087, amendment of 2026-10-07).

    Where ``/proc/self/status`` gives a ``VmData`` (Linux), ``mem_mb`` is HEADROOM above what the
    worker holds once its graph is loaded: the cap is ``RLIMIT_DATA`` at that ``VmData`` plus
    ``mem_mb`` (vault BACKLOG #3133 part 2, owner ruling 2026-10-11). Called right after
    ``load_config``, so a graph larger than ``mem_mb`` does not start the worker over its cap.
    ``RLIMIT_DATA`` counts writable private memory and not address space that is only reserved. A
    thread's glibc malloc arena reserves about 64 MiB and keeps it mapped after the thread exits, so
    an ``RLIMIT_AS`` cap became a lifetime budget that innocent threads used up. An arena's peak
    writable size does count after its threads exit, which is why the parent also starts this
    process with ``MALLOC_ARENA_MAX=2``. A live thread's stack counts too, and glibc keeps up to
    about 40 MiB of exited threads' stacks mapped for reuse.
    Elsewhere on POSIX ``mem_mb`` stays an absolute ``RLIMIT_AS`` cap, and a log line says so."""
    try:
        import resource
    except ImportError:
        return _NO_MEMORY_CAP  # Windows / no rlimit support — wall cap governs
    with contextlib.suppress(ValueError, OSError):
        # No core file of a worker that holds message bodies: a crash signal such as SIGSEGV or
        # SIGABRT would otherwise dump one.
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))  # type: ignore[attr-defined,unused-ignore]
    if mem_mb is None:
        return _NO_MEMORY_CAP
    mib = 1024 * 1024
    baseline_kib = _proc_status_kib("VmData") if _rlimit_data_counts_mmap() else None
    if baseline_kib is not None:
        rlimit, name = resource.RLIMIT_DATA, "RLIMIT_DATA"  # type: ignore[attr-defined,unused-ignore]
        baseline = baseline_kib * 1024
    else:
        rlimit, name = resource.RLIMIT_AS, "RLIMIT_AS"  # type: ignore[attr-defined,unused-ignore]
        baseline = 0
        log.warning(
            "sandbox worker: no VmData in /proc/self/status, or a kernel older than Linux 4.7, so "
            "[sandbox].mem_mb is an absolute RLIMIT_AS cap of %d MiB here, not headroom above the "
            "loaded graph",
            mem_mb,
        )
    limit = baseline + int(mem_mb) * mib
    try:
        hard = resource.getrlimit(rlimit)[1]  # type: ignore[attr-defined,unused-ignore]
        if hard != resource.RLIM_INFINITY:  # type: ignore[attr-defined,unused-ignore]
            # An inherited hard limit (a service unit, a container) cannot be raised. Stay under it
            # rather than fail the setrlimit and run with no cap at all.
            limit = min(limit, hard)
        resource.setrlimit(rlimit, (limit, limit))  # type: ignore[attr-defined,unused-ignore]
    except (ValueError, OSError) as exc:
        log.warning("sandbox worker: could not set the memory cap (%s)", exc)
        return _NO_MEMORY_CAP
    # From the limit actually set, so a hard-limit clamp is not reported as the larger mem_mb.
    allowed = max(0, limit - baseline) // mib
    if baseline:
        return f"[sandbox].mem_mb allows {allowed} MiB above the loaded graph ({name})"
    return f"[sandbox].mem_mb allows {allowed} MiB of address space in all ({name})"


def _install_import_guard(forbidden: tuple[str, ...]) -> None:
    """Purge any already-imported forbidden module (so a cached import re-triggers the guard) and put
    the finder first on ``sys.meta_path``."""
    for name in list(sys.modules):
        for prefix in forbidden:
            if name == prefix or name.startswith(prefix + "."):
                sys.modules.pop(name, None)
                break
    sys.meta_path.insert(0, _ForbiddenImportFinder(forbidden))


class _Broker:
    """The worker's half of the ``mode=isolated`` lookup broker (ADR 0147).

    Its two runners stand in for the engine's while a Handler runs: each writes one ``lookup`` frame
    to the parent and blocks on the parent's one reply, so a ``db_lookup``/``fhir_lookup`` call
    returns what the parent's own runner returned, or raises the lookup's own error type with the
    parent's reason. The parent decides every call; this side only asks.

    Calls are serialized under one lock, because the pipe carries one exchange at a time. A call made
    while no dispatch is in flight, such as from a thread a Handler left running, is refused rather
    than written: the parent would read the frame as unsolicited and drop the worker, and its read of
    stdin would take the next request frame as its reply. A desynchronized or closed pipe marks the
    broker broken, and :func:`main` exits after the dispatch, so the parent starts a fresh worker."""

    def __init__(self, stdin: Any, stdout: Any) -> None:
        self._stdin = stdin
        self._stdout = stdout
        self._lock = threading.Lock()
        self._req: Any = None
        self._seq = 0
        self.broken = False

    def begin(self, req: Any) -> None:
        with self._lock:
            self._req, self._seq = req, 0

    def end(self) -> None:
        """Close the dispatch. Taken under the lock, so a lookup still in flight on another thread
        finishes, inside the dispatch, before the answer frame is written."""
        with self._lock:
            self._req = None

    def db(self, connection: str, statement: str, params: Any = None) -> Any:
        from messagefoundry.config.db_lookup import DbLookupError
        from messagefoundry.pipeline._sandbox_codec import LOOKUP_DB

        return self._ask(LOOKUP_DB, DbLookupError, "db_lookup", connection, statement, params)

    def fhir(self, connection: str, query: str, params: Any = None) -> Any:
        from messagefoundry.config.fhir_lookup import FhirLookupError
        from messagefoundry.pipeline._sandbox_codec import LOOKUP_FHIR

        return self._ask(LOOKUP_FHIR, FhirLookupError, "fhir_lookup", connection, query, params)

    def _ask(
        self,
        kind: str,
        error: type[Exception],
        fn: str,
        connection: object,
        target: object,
        params: object,
    ) -> Any:
        from messagefoundry.pipeline import _sandbox_codec as codec
        from messagefoundry.pipeline._sandbox_codec import SandboxError
        from messagefoundry.pipeline.sandbox import _read_frame_bytes, _write_frame

        with self._lock:
            req = self._req
            if req is None or self.broken:
                raise error(f"{fn}: no Handler dispatch is in flight in this sandbox worker")
            self._seq += 1
            seq = self._seq
            try:
                frame = codec.encode_lookup(
                    request_id=req.request_id,
                    phase=req.phase,
                    name=req.name,
                    seq=seq,
                    kind=kind,
                    connection=connection,
                    target=target,
                    params=params,
                )
            except SandboxError as exc:
                # A bad argument fails as the call would in-process: the lookup's own error, and the
                # pipe untouched. Nothing was written.
                raise error(f"{fn}: its arguments cannot cross the sandbox: {exc}") from None
            try:
                _write_frame(self._stdout, frame)
                body = _read_frame_bytes(self._stdin)
                if body is None:
                    raise SandboxError("the engine closed the pipe")
                ok, result, reason = codec.decode_lookup_reply(
                    body, request_id=req.request_id, phase=req.phase, name=req.name, seq=seq
                )
            except (OSError, SandboxError) as exc:
                # An over-cap frame raises before a byte is written, so only a pipe the parent
                # abandoned, or a reply that does not answer this call, gets here. Either way the
                # pipe no longer lines up with the protocol.
                self.broken = True
                raise error(f"{fn}: the sandbox lookup broker failed: {exc}") from None
        if not ok:
            raise error(reason)
        return result


def _run_one(
    registry: Any, req: Any, code_sets: Any, broker: _Broker | None = None
) -> tuple[bool, object, str, str]:
    """Execute one router/handler request; return ``(ok, result, kind, error)``. Never raises.

    ``broker`` is set at ``mode=isolated`` (ADR 0147): a Handler's ``db_lookup``/``fhir_lookup``
    is then asked of the parent, and an error it raises is that Handler's error, as at ``mode=off``.
    Without it, both lookups are refused in the worker, as ADR 0087 built them."""
    from messagefoundry.config import db_lookup as db_lookup_mod
    from messagefoundry.config import fhir_lookup as fhir_lookup_mod
    from messagefoundry.config.db_lookup import DbLookupError
    from messagefoundry.config.fhir_lookup import FhirLookupError
    from messagefoundry.config.run_context import run_contexts
    from messagefoundry.config.wiring import handler_result_items
    from messagefoundry.pipeline._sandbox_codec import SandboxError

    phase = req.phase
    name = req.name
    # code_sets never travel per dispatch — the ENGINE's tables arrived once in the boot frame, so
    # publish those. Falling back to this child's own load only happens when the parent published
    # none at all (a session constructed without them); using the child's copy when the engine HAS
    # one would let a `codesets/` edit made without a /config/reload diverge from mode=off.
    run_context = replace(
        req.run_context, code_sets=registry.code_sets if code_sets is None else code_sets
    )

    if phase == "router":
        fn = registry.routers.get(name)
        phase_key = "router"
    elif phase == "transform":
        fn = registry.handlers.get(name)
        phase_key = "transform"
    elif phase == "accepts":
        # An `accepts=` predicate (ADR 0084) is user code that runs at ROUTING time, so it must be
        # isolated exactly like the Router it runs beside — otherwise a predicate would be the one
        # piece of config code executing engine-side, outside the forbidden-import + resource caps.
        # `name` keys the HANDLER whose predicate this is; the run-context phase is the router phase
        # (run_context._PHASES is {router, transform} — "accepts" is a dispatch phase, not a run phase),
        # which is also what makes a live db_lookup/fhir_lookup inside a predicate raise.
        fn = registry.handler_accepts.get(name)
        phase_key = "router"
    else:
        return False, None, "error", f"unknown sandbox phase {phase!r}"
    if fn is None:
        return False, None, "error", f"no such {phase} {name!r} in registry"

    # The brokered runners exist only for a Handler: a Router or an accepts= predicate finds no
    # runner, so its lookup raises the "unavailable here" error it raises at mode=off.
    brokered = broker is not None and phase == "transform"
    try:
        with (
            run_contexts(run_context, phase=phase_key),
            db_lookup_mod.activated(broker.db if brokered and broker else None),
            fhir_lookup_mod.activated(broker.fhir if brokered and broker else None),
        ):
            result = fn(req.payload)
            if phase == "transform":
                # Materialise a CONTAINER return here, INSIDE the run context (BACKLOG #341). A
                # generator Handler's body runs lazily, at whatever point something iterates it — and
                # the codec's `enc_result`, which is where that would otherwise happen, is called from
                # `_respond`, OUTSIDE this `with`. Materialising there would execute the Handler body
                # with no active run context, so a `code_set(...)` inside a generator Handler would
                # raise CodeSetError under mode=subprocess while working under mode=off: a
                # mode-dependent disposition, exactly what ADR 0087's parity rule forbids. Applying the
                # same rule again in `enc_result` is deliberate and free — list(list) is an idempotent
                # shallow copy, and the codec is also exercised directly (parity table), bypassing this.
                items = handler_result_items(result)
                if items is not None:
                    result = items
        if phase == "accepts":
            # HandlerAccepts is contractually ``(msg) -> bool`` and the PARENT coerces the verdict with
            # ``bool(...)`` (dryrun._accepted). Coerce HERE too, BEFORE the result is described back: a
            # predicate that returns a truthy NON-bool (a natural shape the parent's ``bool()`` sanctions,
            # e.g. ``re.search(...)`` -> re.Match) would otherwise be rejected by the codec's strict
            # JSON-bool slot — content-dependent, since a non-match returns None. Coercing to the
            # contract type here is what lets the parent demand a strict bool, and makes
            # ``[sandbox].mode`` never change the routing decision (ADR 0087).
            result = bool(result)
    except (DbLookupError, FhirLookupError) as exc:
        if broker is not None:
            # mode=isolated: the lookup ran, or was refused, through the parent, so its error is the
            # Handler's error exactly as at mode=off. A Router's lookup lands here too, with the
            # "unavailable here" text mode=off gives it.
            return False, None, "error", _error_text(exc)
        # db_lookup/fhir_lookup bridge back onto the engine event loop (run_coroutine_threadsafe),
        # which a subprocess boundary breaks — forbidden + fail-closed at mode=subprocess (ADR 0087).
        return (
            False,
            None,
            "denied",
            f"{type(exc).__name__}: live db_lookup/fhir_lookup is forbidden inside the "
            "sandbox (ADR 0087) — run this Handler with [sandbox].mode=off if it needs live enrichment",
        )
    except SandboxError as exc:
        return False, None, "denied", str(exc)
    except MemoryError:
        raise  # not a plain handler error: main() answers it and recycles the worker
    except Exception as exc:  # noqa: BLE001 — a handler raise is content, reported not crashed
        return False, None, "error", _error_text(exc)
    return True, result, "", ""


def _error_text(exc: BaseException) -> str:
    """``Type: message`` for an error reported across the process boundary. A Unicode error's str()
    names the character or byte it failed on (vault BACKLOG #3185), and mode=off renders it from its
    attributes, so this boundary must too. An error that HOLDS one, as ``ValueError("bad", exc)``,
    prints that error's repr, the whole input, so it renders the same way (vault BACKLOG #3295).
    Never raises: the error's own __str__ may, and so may the import after untrusted config has
    run, and either would kill the worker mid-report."""
    try:
        # cached: logging_setup imported it at load
        from messagefoundry.redaction import codec_safe_line

        return codec_safe_line(exc)
    except Exception:  # noqa: BLE001 — the class name is all that is left to report
        return type(exc).__name__


def _respond(registry: Any, req: Any, code_sets: Any, broker: _Broker | None = None) -> bytes:
    """Build the response frame for one request. Never raises — an undescribable result is
    reported — except ``MemoryError``, which :func:`main` answers."""
    from messagefoundry.pipeline import _sandbox_codec as codec
    from messagefoundry.pipeline._sandbox_codec import SandboxError

    ok, result, kind, error = _run_one(registry, req, code_sets, broker)
    if ok:
        try:
            return codec.encode_ok(
                request_id=req.request_id, phase=req.phase, name=req.name, result=result
            )
        except SandboxError as exc:
            # A result outside the closed grammar (an exotic Send payload, a Handler returning an
            # object that is not describable) — report it instead of dying so the worker survives for
            # the next message.
            return codec.encode_fail(
                request_id=req.request_id,
                phase=req.phase,
                name=req.name,
                kind="error",
                error=f"unmarshallable result: {exc}",
            )
    return codec.encode_fail(
        request_id=req.request_id, phase=req.phase, name=req.name, kind=kind, error=error
    )


def main() -> int:
    from messagefoundry.pipeline import _sandbox_codec as codec
    from messagefoundry.pipeline._sandbox_codec import SandboxError
    from messagefoundry.pipeline.sandbox import _read_frame_bytes, _write_frame, graph_shape

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer
    # Sequenced deliberately: AFTER the frame writer captures its raw handle (at module scope the
    # capture above would resolve to fd 2 and send every frame to the wrong pipe) and BEFORE the boot
    # frame read below, whose reply path runs ``load_config()`` -- the earliest untrusted code.
    _redirect_stdout_to_stderr()

    frame = _read_frame_bytes(stdin)
    if frame is None:
        return 0  # parent closed the pipe before bootstrap — nothing to do
    try:
        boot = codec.decode_boot(frame)
        from messagefoundry.config.wiring import load_snapshot

        # The engine's own bytes, never the directory: a respawn runs what the engine loaded, not
        # what is on disk now (vault BACKLOG #2596). The engine ran the trust check when it read
        # them. The engine's parsed tables, when it sent any, stand in for codesets/, whose files
        # the frame then leaves out.
        registry = load_snapshot(boot.snapshot, code_sets=boot.code_sets)
        # Pre-import every module the serve loop touches BEFORE the guard goes up, so a first-time
        # (transitive) import of an engine helper can't be misread as a forbidden user import. Once
        # cached in sys.modules, a later `import` short-circuits ahead of the meta_path finder.
        import messagefoundry.config.db_lookup  # noqa: F401
        import messagefoundry.config.fhir_lookup  # noqa: F401
        import messagefoundry.config.run_context  # noqa: F401

        memory_cap = _apply_resource_caps(boot.mem_mb)
        _install_import_guard(boot.forbidden)
    except Exception as exc:  # noqa: BLE001 — report a bootstrap failure, do not crash silently
        try:  # noqa: SIM105
            _write_frame(stdout, codec.encode_bootfail(_error_text(exc)))
        except (OSError, SandboxError):
            pass
        return 1
    try:
        # The graph this process loaded goes back with ``ready``. The engine compares it with its
        # own and refuses a worker whose graph differs (vault BACKLOG #2587).
        _write_frame(stdout, codec.encode_ready(graph_shape(registry)))
    except (OSError, SandboxError):
        return 1

    # mode=isolated (ADR 0147): a Handler's lookups are asked of the parent over this same pipe.
    broker = _Broker(stdin, stdout) if boot.broker else None
    while True:
        if broker is not None and broker.broken:
            # A lookup exchange went out of step with the protocol; the next request frame cannot be
            # trusted to line up either. The parent reads EOF and starts a fresh worker.
            return 1
        frame = _read_frame_bytes(stdin)
        if frame is None:
            return 0  # parent closed the pipe — clean shutdown
        try:
            req = codec.decode_request(frame)
        except SandboxError as exc:
            # We have no trustworthy correlation id to answer with, so we cannot report this as a
            # per-message error. Exit: the parent reads EOF, fails THIS message closed (SandboxError →
            # dead-letter) and respawns a clean child, rather than hanging to the wall cap.
            log.error("sandbox worker: undecodable request frame (%s)", exc)
            return 1
        if broker is not None:
            broker.begin(req)
        try:
            resp: bytes | None = _respond(registry, req, boot.code_sets, broker)
        except MemoryError as exc:
            # Caught here rather than around the Handler alone, so a result too big to encode is
            # answered the same way. Only the text is kept: the reply is built AFTER this block,
            # because until it ends the traceback keeps the Handler's frames, and the memory their
            # locals hold, alive.
            resp, detail = None, _error_text(exc)
        if broker is not None:
            broker.end()  # before the answer: no lookup frame may follow it
        if resp is None:
            # A call that ran out of memory may leave memory held (a module global, a cache, a
            # fragmented heap), and the next innocent message would pay for it. Answer, then exit so
            # the parent starts a fresh worker (vault BACKLOG #3133 part 2).
            with contextlib.suppress(OSError, SandboxError, MemoryError):
                _write_frame(
                    stdout,
                    codec.encode_fail(
                        request_id=req.request_id,
                        phase=req.phase,
                        name=req.name,
                        kind=codec.FAIL_MEMORY,
                        error=f"{detail}; {memory_cap}",
                    ),
                )
            return 1  # with no reply sent, the parent reads EOF and reports a crash instead
        try:
            _write_frame(stdout, resp)
        except (OSError, SandboxError) as exc:
            # An over-cap response frame (a huge fan-out) raises in _write_frame, not at describe time —
            # report it instead of dying so the child's "survives for the next message" contract holds,
            # rather than the parent reading EOF and paying a full config-reload respawn.
            try:
                _write_frame(
                    stdout,
                    codec.encode_fail(
                        request_id=req.request_id,
                        phase=req.phase,
                        name=req.name,
                        kind="error",
                        error=f"unmarshallable result: {exc}",
                    ),
                )
            except (OSError, SandboxError):
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
