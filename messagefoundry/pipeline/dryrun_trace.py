# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Traced dry-run: a ``sys.settrace`` observer around the Router/Handler run (ADR 0072).

This wraps the **existing** dry-run path (:func:`messagefoundry.pipeline.dryrun.dry_run`) with a
line-addressable execution tracer and emits a JSON trace: per Router/Handler invocation, the lines it
executed, the locals each line assigned, the ``msg[...]``/``msg.set(...)`` field writes on each line,
the routing decision / would-send outbounds, and — for a live ``db_lookup``/``fhir_lookup`` that a pure
dry-run cannot run — a ``live_lookup_skipped`` annotation. It is the data source for the #92 live-debug
loop and #84 profiling/coverage.

**Additive + preview-only (do not break).** The tracer is a *pure observer*: it never mutates a frame's
locals, never swallows a Router/Handler exception, and never resumes a handler past a raised live-lookup
error. The dry-run it drives is byte-identical to an untraced :func:`dry_run` — disposition, routed-to,
and would-send outbounds are computed by the *same* :func:`~messagefoundry.pipeline.dryrun.route_message`
call path, with the tracer passed through as an optional hook (``tracer=None`` on every existing call
site keeps them unchanged).

**Capture semantics.**

* *Prev-tracer restore.* Each invocation saves ``prev = sys.gettrace()`` and restores it in a ``finally``
  — never ``sys.settrace(None)`` — so a surrounding ``coverage.py`` / ``pytest-cov`` tracer (whether it
  uses the legacy ``sys.settrace`` C tracer or PEP 669 ``sys.monitoring``) survives untouched.
* *Frame-scoped.* The global trace function line-traces **only** the exact Router/Handler frame (matched
  by code-object identity, so recursion / same-module helpers are not double-traced) and returns ``None``
  for every other frame.
* *Locals-diff attribution.* ``sys.settrace`` "line" events fire on line **entry**, so a value assigned
  on line *N* is first observed at the line event for *N+1*; each diff is attributed back to the
  **producing** line *N*.
* *Thread-locality.* ``sys.settrace`` is per-thread. The pure dry-run runs the Router/Handler
  **synchronously on the calling thread**, so the tracer is installed on that same thread; ``trace_ok``
  in the result verifies a non-empty trace was actually captured.
* *Python 3.14.* The tracer only touches ``sys.settrace`` — it never installs a ``sys.monitoring`` tool
  — so it coexists with coverage tooling on either mechanism.

**PHI (CLAUDE.md §9).** Assigned-local values and ``msg``-write values are PHI. They serialize as
``"REDACTED"`` unless ``show_phi`` is set (the same gate as ``dryrun --show-phi``). Line numbers, local
*names*, outbound *names*, dispositions, and annotations carry no PHI. The trace is produced in-process /
to stdout — never written to a persisted file.
"""

from __future__ import annotations

import inspect
import sys
from contextlib import contextmanager
from contextvars import ContextVar
from types import CodeType, FrameType
from typing import Any, Iterator

from messagefoundry.config.db_lookup import DbLookupError
from messagefoundry.config.fhir_lookup import FhirLookupError
from messagefoundry.config.wiring import HandlerFn, Payload, RouterFn, Send
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import dry_run

__all__ = ["trace_dry_run"]

# A single pathological loop must not emit an unbounded trace; cap events per invocation (the rest is
# marked ``truncated``). A long string local / write value is likewise capped so a body can't be dumped
# in full even under --show-phi.
_MAX_EVENTS = 5000
_MAX_VALUE_LEN = 120


# --- value serialization (PHI-gated) -----------------------------------------


def _safe_value(value: object, show_phi: bool) -> Any:
    """A JSON-safe, PHI-gated rendering of a captured value.

    Without ``show_phi`` every value collapses to ``"REDACTED"`` (values are message-derived, hence PHI).
    With it, scalars pass through and any other object is ``repr``'d; both are length-capped so a full
    message body can never be dumped."""
    if not show_phi:
        return "REDACTED"
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, str):
        text = value
    else:
        try:
            text = repr(value)
        except Exception:  # noqa: BLE001 — a hostile __repr__ must not break the trace
            text = f"<{type(value).__name__}>"
    if len(text) > _MAX_VALUE_LEN:
        return text[:_MAX_VALUE_LEN] + "…(truncated)"
    return text


def _diff(now: dict[str, Any], before: dict[str, Any], show_phi: bool) -> dict[str, Any]:
    """Locals that were (re)bound between ``before`` and ``now`` — new names or rebinding to a different
    object (identity), so an unchanged parameter never shows up. Values are PHI-gated."""
    out: dict[str, Any] = {}
    for name, value in now.items():
        if name not in before or before[name] is not value:
            out[name] = _safe_value(value, show_phi)
    return out


def _safe_snapshot(frame: FrameType) -> dict[str, Any]:
    try:
        return dict(frame.f_locals)
    except Exception:  # noqa: BLE001 — never let snapshotting locals break execution
        return {}


def _sends_from(result: object) -> list[str]:
    """Outbound names in a Handler's raw return (``Send``/``SetState``/list/``None``) — mirrors the
    ``Send`` half of :func:`messagefoundry.pipeline.dryrun._partition`, name-only (no payload = no PHI)."""
    if result is None:
        return []
    items = result if isinstance(result, list) else [result]
    return [it.to for it in items if isinstance(it, Send)]


def _routed_from(result: object) -> list[str]:
    """Handler names in a Router's raw return (``list``/``str``/``None``)."""
    if isinstance(result, str):
        return [result]
    if isinstance(result, list):
        return [str(name) for name in result]
    return []


# --- per-invocation recorder -------------------------------------------------


class _Recorder:
    """Captures one Router or Handler invocation's execution trace."""

    def __init__(self, kind: str, name: str, fn: RouterFn | HandlerFn, show_phi: bool) -> None:
        self.kind = kind
        self.name = name
        self.show_phi = show_phi
        target = inspect.unwrap(
            fn
        )  # decorators register the raw fn today; unwrap is future-proofing
        self.target_code: CodeType | None = getattr(target, "__code__", None)
        self.module: str | None = getattr(fn, "__module__", None)
        self.filename: str | None = self.target_code.co_filename if self.target_code else None
        self.def_line: int | None = self.target_code.co_firstlineno if self.target_code else None
        self.events: list[dict[str, Any]] = []
        self.annotations: list[dict[str, Any]] = []
        self.sends: list[str] = []
        self.routed_to: list[str] = []
        self.truncated = False
        # trace state
        self.frame: FrameType | None = None
        self._last_line: int | None = None
        self._snap_before: dict[str, Any] = {}
        self._writes_by_line: dict[int, list[dict[str, Any]]] = {}

    # tracer callbacks ---------------------------------------------------------

    def on_call(self, frame: FrameType) -> None:
        self.frame = frame
        self._snap_before = _safe_snapshot(frame)
        self._last_line = None

    def on_line(self, frame: FrameType) -> None:
        current = frame.f_lineno
        if self._last_line is not None:
            self._finalize(frame, self._last_line)
        self._last_line = current

    def on_return(self, frame: FrameType) -> None:
        if self._last_line is not None:
            self._finalize(frame, self._last_line)
            self._last_line = None

    # on an exception propagating out of the frame, the last executed line's effect is still worth
    # attributing; a trailing return event then finds _last_line cleared (no double emit).
    on_exception = on_return

    def _finalize(self, frame: FrameType, line: int) -> None:
        if len(self.events) >= _MAX_EVENTS:
            self.truncated = True
            return
        now = _safe_snapshot(frame)
        assigned = _diff(now, self._snap_before, self.show_phi)
        self._snap_before = now
        event: dict[str, Any] = {"line": line, "event": "line", "assigned": assigned}
        writes = self._writes_by_line.pop(line, None)
        if writes:
            event["writes"] = writes
        self.events.append(event)

    # message-write capture (called from the patched Message.set) --------------

    def record_write(self, path: str, value: object) -> None:
        line = self.frame.f_lineno if self.frame is not None else (self.def_line or 0)
        self._writes_by_line.setdefault(line, []).append(
            {"path": path, "value": _safe_value(value, self.show_phi)}
        )

    # terminal classification --------------------------------------------------

    def record_return(self, result: object) -> None:
        if self.kind == "router":
            self.routed_to = _routed_from(result)
        else:
            self.sends = _sends_from(result)

    def classify_live_lookup(self, exc: BaseException) -> None:
        """Add a ``live_lookup_skipped`` annotation for a terminal ``db_lookup``/``fhir_lookup`` raise.

        Walks the exception traceback (never resuming the handler) to name the call and the Handler line
        it was made on. The exception is re-raised by the caller, so disposition stays byte-identical."""
        call_name: str | None = None
        handler_line: int | None = None
        tb = exc.__traceback__
        while tb is not None:
            code = tb.tb_frame.f_code
            if code.co_name in ("db_lookup", "fhir_lookup"):
                call_name = code.co_name
            if self.target_code is not None and code is self.target_code:
                handler_line = tb.tb_lineno
            tb = tb.tb_next
        if call_name is None:  # fall back on the exception type if the frame name was inlined away
            call_name = "fhir_lookup" if isinstance(exc, FhirLookupError) else "db_lookup"
        self.annotations.append(
            {
                "line": handler_line if handler_line is not None else self.def_line,
                "kind": "live_lookup_skipped",
                "call": call_name,
            }
        )

    def to_dict(self, disposition: str) -> dict[str, Any]:
        out: dict[str, Any] = {
            "kind": self.kind,
            "name": self.name,
            "module": self.module,
            "file": self.filename,
            "def_line": self.def_line,
            "events": self.events,
            "disposition": disposition,
            "sends": [{"outbound": o} for o in self.sends],
            "routed_to": self.routed_to,
            "annotations": self.annotations,
        }
        if self.truncated:
            out["truncated"] = True
        return out


# The recorder currently being traced, so the patched Message.set attributes a write to it. A contextvar
# (not a bare global) keeps it thread-/context-local; the pure dry-run runs one invocation at a time.
_active_recorder: ContextVar[_Recorder | None] = ContextVar(
    "mefor_dryrun_trace_recorder", default=None
)


def _make_global_trace(rec: _Recorder) -> Any:
    """A frame-scoped global trace function: line-trace ONLY ``rec``'s exact frame, ``None`` otherwise."""
    target_code = rec.target_code

    def _local(frame: FrameType, event: str, arg: Any) -> Any:
        if event == "line":
            rec.on_line(frame)
        elif event == "return":
            rec.on_return(frame)
        elif event == "exception":
            rec.on_exception(frame)
        return _local

    def _global(frame: FrameType, event: str, arg: Any) -> Any:
        # Trace only the outermost invocation of the exact target function (rec.frame is None until we
        # latch onto it); every other frame — helpers it calls, a recursive re-entry — returns None.
        if event == "call" and frame.f_code is target_code and rec.frame is None:
            rec.on_call(frame)
            return _local
        return None

    return _global


class _Tracer:
    """The trace hook passed into the dry-run: installs ``sys.settrace`` around each Router/Handler call.

    Satisfies :class:`messagefoundry.pipeline.dryrun.TraceHook` structurally."""

    def __init__(self, show_phi: bool) -> None:
        self.show_phi = show_phi
        self.invocations: list[_Recorder] = []

    def trace_router(self, fn: RouterFn, name: str, payload: Payload) -> Any:
        return self._run("router", fn, name, payload)

    def trace_handler(self, fn: HandlerFn, name: str, payload: Payload) -> Any:
        return self._run("handler", fn, name, payload)

    def _run(self, kind: str, fn: RouterFn | HandlerFn, name: str, payload: Payload) -> Any:
        rec = _Recorder(kind, name, fn, self.show_phi)
        self.invocations.append(rec)
        prev = (
            sys.gettrace()
        )  # NEVER settrace(None) — restore whatever coverage/pytest-cov installed
        token = _active_recorder.set(rec)
        try:
            sys.settrace(_make_global_trace(rec))
            try:
                result = fn(payload)
            except (DbLookupError, FhirLookupError) as exc:
                # A live lookup can't run in a pure dry-run: classify + annotate, then RE-RAISE so the
                # disposition (ERROR) is byte-identical to an untraced run. Never swallowed / resumed.
                rec.classify_live_lookup(exc)
                raise
            rec.record_return(result)
            return result
        finally:
            sys.settrace(prev)
            _active_recorder.reset(token)


# --- Message.set patch (msg[...] / msg.set(...) write capture) ----------------

_ORIG_MESSAGE_SET = Message.set


def _recording_set(
    self: Message, path: str, value: str, *, occurrence: int = 1, repetition: int | None = None
) -> None:
    rec = _active_recorder.get()
    if rec is not None:
        rec.record_write(path, value)
    _ORIG_MESSAGE_SET(self, path, value, occurrence=occurrence, repetition=repetition)


@contextmanager
def _patched_message_writes() -> Iterator[None]:
    """Record ``msg.set(...)`` / ``msg[...] = ...`` (``__setitem__`` delegates to ``set``) writes for the
    active recorder, then restore the original method. A no-op passthrough whenever no recorder is active,
    so it never perturbs the mutation itself."""
    Message.set = _recording_set  # type: ignore[method-assign]
    try:
        yield
    finally:
        Message.set = _ORIG_MESSAGE_SET  # type: ignore[method-assign]


def trace_dry_run(
    registry: Any, raw: str | bytes, *, inbound: str | None = None, show_phi: bool = False
) -> dict[str, Any]:
    """Dry-run ``raw`` against ``registry`` with the execution tracer installed; return the trace JSON.

    Byte-identical to :func:`messagefoundry.pipeline.dryrun.dry_run` in disposition / routed-to /
    would-send outbounds (it drives the same call path); adds a per-invocation execution trace. See the
    module docstring for the emitted shape and capture semantics."""
    tracer = _Tracer(show_phi=show_phi)
    with _patched_message_writes():
        result = dry_run(registry, raw, inbound=inbound, tracer=tracer)
    disposition = result.disposition.value
    return {
        "inbound": result.inbound,
        "disposition": disposition,
        "message_type": result.message_type,
        "control_id": result.control_id,
        # message-level routing outcome (the untraced dry-run's authoritative fields)
        "handlers": result.handlers,
        "sends": [{"outbound": d.to} for d in result.deliveries],
        "error": result.error,
        # trace_ok verifies the tracer actually observed lines on the calling thread (thread-locality).
        "trace_ok": any(rec.events for rec in tracer.invocations),
        "invocations": [rec.to_dict(disposition) for rec in tracer.invocations],
    }
