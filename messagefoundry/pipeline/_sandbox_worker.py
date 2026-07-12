# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The sandbox worker child process (ADR 0087, BACKLOG #197).

Launched by :class:`messagefoundry.pipeline.sandbox.SandboxSession` as ``python -m
messagefoundry.pipeline._sandbox_worker``. It speaks a tiny length-prefixed pickle protocol on
stdin/stdout (``sandbox._read_frame`` / ``_write_frame``):

1. **Bootstrap** — reads one frame ``{config_dir, env, forbidden, cpu_seconds, mem_mb}``, loads the
   message :class:`~messagefoundry.config.wiring.Registry` from ``config_dir`` (the same loader the
   engine uses — it executes admin config under the unchanged safe-source gate), applies the POSIX
   resource caps where available, installs the forbidden-import guard, and replies ``{ready: True}``
   (or ``{ready: False, error}`` on any failure).
2. **Serve** — for each subsequent request frame ``{phase, name, payload, run_context}`` it looks the
   Router/Handler up in *its own* registry, re-establishes the run-scoped context providers for the
   phase, runs the function on the unpickled payload, and replies ``{ok: True, result}`` — or
   ``{ok: False, kind, error}`` on a denial (forbidden import, a live ``db_lookup``/``fhir_lookup``,
   an unpicklable result) or a plain handler error.

stdout is the binary IPC channel — **nothing else may write to it**. Logging and any diagnostics go
to stderr (inherited by the engine). The engine parent enforces the wall-clock cap and kills a
runaway child, so this process never needs its own watchdog.
"""

from __future__ import annotations

import logging
import math
import pickle  # nosec B403 — pickle only carries IPC frames between the engine and its own spawned sandbox worker, never external/untrusted input
import sys
from typing import Any

# stdout is the IPC channel; keep the root logger on stderr so a stray log line can't corrupt a frame.
logging.basicConfig(stream=sys.stderr, level=logging.WARNING)
log = logging.getLogger("messagefoundry.sandbox.worker")


class _ForbiddenImportFinder:
    """A ``sys.meta_path`` finder that fails a forbidden import loudly.

    Matches the exact dotted module or a submodule of it (``socket`` blocks ``socket`` and
    ``socket.x``; ``messagefoundry.store`` blocks only that subtree, never ``messagefoundry`` itself).
    Returns ``None`` for everything else so normal resolution continues."""

    def __init__(self, prefixes: tuple[str, ...]) -> None:
        self._prefixes = prefixes

    def find_spec(self, name: str, path: Any = None, target: Any = None) -> None:
        from messagefoundry.pipeline.sandbox import SandboxError

        for prefix in self._prefixes:
            if name == prefix or name.startswith(prefix + "."):
                raise SandboxError(f"import of {name!r} is forbidden inside the sandbox (ADR 0087)")
        return None


def _apply_resource_caps(cpu_seconds: float, mem_mb: int | None) -> None:
    """Best-effort POSIX ``RLIMIT_CPU`` / ``RLIMIT_AS`` backstop (a no-op on Windows). The parent's
    wall-clock cap is the authoritative bound on every platform; this just lets the OS reap a runaway
    child sooner where the ``resource`` module exists."""
    try:
        import resource
    except ImportError:
        return  # Windows / no rlimit support — wall cap governs
    try:
        cpu = max(1, math.ceil(cpu_seconds))
        resource.setrlimit(resource.RLIMIT_CPU, (cpu, cpu))  # type: ignore[attr-defined,unused-ignore]
    except (ValueError, OSError):
        pass
    if mem_mb is not None:
        try:
            limit = int(mem_mb) * 1024 * 1024
            resource.setrlimit(resource.RLIMIT_AS, (limit, limit))  # type: ignore[attr-defined,unused-ignore]
        except (ValueError, OSError):
            pass


def _install_import_guard(forbidden: tuple[str, ...]) -> None:
    """Purge any already-imported forbidden module (so a cached import re-triggers the guard) and put
    the finder first on ``sys.meta_path``."""
    for name in list(sys.modules):
        for prefix in forbidden:
            if name == prefix or name.startswith(prefix + "."):
                sys.modules.pop(name, None)
                break
    sys.meta_path.insert(0, _ForbiddenImportFinder(forbidden))


def _run_one(registry: Any, req: dict[str, Any]) -> dict[str, Any]:
    """Execute one router/handler request and build the response dict (never raises)."""
    from messagefoundry.config.db_lookup import DbLookupError
    from messagefoundry.config.fhir_lookup import FhirLookupError
    from messagefoundry.config.run_context import RunContext, run_contexts
    from messagefoundry.pipeline.sandbox import SandboxError

    phase = req.get("phase")
    name = req.get("name")
    payload = req.get("payload")
    rc = req.get("run_context")
    run_context = rc if isinstance(rc, RunContext) else RunContext()

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
        return {"ok": False, "kind": "error", "error": f"unknown sandbox phase {phase!r}"}
    if fn is None:
        return {"ok": False, "kind": "error", "error": f"no such {phase} {name!r} in registry"}

    try:
        with run_contexts(run_context, phase=phase_key):
            result = fn(payload)
        if phase == "accepts":
            # HandlerAccepts is contractually ``(msg) -> bool`` and the PARENT coerces the verdict with
            # ``bool(...)`` (dryrun._accepted). Coerce HERE too, BEFORE the result is pickled back: a
            # predicate that returns a truthy NON-bool (a natural shape the parent's ``bool()`` sanctions,
            # e.g. ``re.search(...)`` -> re.Match) would otherwise be marshalled raw and crash the child on
            # an unpicklable object — content-dependent, since a non-match returns picklable None. Coercing
            # to the contract type here makes ``[sandbox].mode`` never change the routing decision (ADR 0087).
            result = bool(result)
    except (DbLookupError, FhirLookupError) as exc:
        # db_lookup/fhir_lookup bridge back onto the engine event loop (run_coroutine_threadsafe),
        # which a subprocess boundary breaks — forbidden + fail-closed for this PR (ADR 0087).
        return {
            "ok": False,
            "kind": "denied",
            "error": f"{type(exc).__name__}: live db_lookup/fhir_lookup is forbidden inside the "
            "sandbox (ADR 0087) — run this Handler with [sandbox].mode=off if it needs live enrichment",
        }
    except SandboxError as exc:
        return {"ok": False, "kind": "denied", "error": str(exc)}
    except Exception as exc:  # noqa: BLE001 — a handler raise is content, reported not crashed
        return {"ok": False, "kind": "error", "error": f"{type(exc).__name__}: {exc}"}
    return {"ok": True, "result": result}


def main() -> int:
    from messagefoundry.pipeline.sandbox import SandboxError, _read_frame, _write_frame

    stdin = sys.stdin.buffer
    stdout = sys.stdout.buffer

    boot = _read_frame(stdin)
    if not isinstance(boot, dict):
        return 0  # parent closed the pipe before bootstrap — nothing to do
    try:
        from messagefoundry.config.wiring import load_config

        registry = load_config(boot["config_dir"])
        # Pre-import every module the serve loop touches BEFORE the guard goes up, so a first-time
        # (transitive) import of an engine helper can't be misread as a forbidden user import. Once
        # cached in sys.modules, a later `import` short-circuits ahead of the meta_path finder.
        import messagefoundry.config.db_lookup  # noqa: F401
        import messagefoundry.config.fhir_lookup  # noqa: F401
        import messagefoundry.config.run_context  # noqa: F401

        _apply_resource_caps(float(boot.get("cpu_seconds", 2.0)), boot.get("mem_mb"))
        _install_import_guard(tuple(boot.get("forbidden", ())))
    except Exception as exc:  # noqa: BLE001 — report a bootstrap failure, do not crash silently
        try:
            _write_frame(stdout, {"ready": False, "error": f"{type(exc).__name__}: {exc}"})
        except (OSError, SandboxError):
            pass
        return 1
    try:
        _write_frame(stdout, {"ready": True})
    except (OSError, SandboxError):
        return 1

    while True:
        req = _read_frame(stdin)
        if req is None:
            return 0  # parent closed the pipe — clean shutdown
        if not isinstance(req, dict):
            continue
        resp = _run_one(registry, req)
        try:
            _write_frame(stdout, resp)
        except (OSError, SandboxError, pickle.PicklingError, TypeError) as exc:
            # A result that will not pickle (e.g. an exotic Send payload, or a Handler returning an
            # unpicklable object) — report it instead of dying so the worker survives for the next
            # message. pickle.dumps raises TypeError/PicklingError on an unmarshallable object; those are
            # caught here (not just OSError/SandboxError) so the child's own "survives for the next
            # message" contract actually holds — otherwise an unpicklable result kills the child and the
            # parent reads EOF, dead-letters this message, and pays a full config-reload respawn next.
            try:
                _write_frame(
                    stdout,
                    {"ok": False, "kind": "error", "error": f"unmarshallable result: {exc}"},
                )
            except (OSError, SandboxError):
                return 1


if __name__ == "__main__":
    raise SystemExit(main())
