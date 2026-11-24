# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Traced dry-run (ADR 0072): the ADR gate tests + capture-semantics coverage.

Gates asserted here (ADR 0072):
  1. Byte-identical — a traced run's disposition + sends/routed_to equal the untraced run's. Since the
     2026-08-04 amendment the gate is stated by level: 1a (message level) is absolute; 1b (the
     per-invocation mirror) carves out a generator Router/Handler, whose body has not run at record
     time, and requires that invocation to declare `lazy_result` rather than look inert.
  2. Live-lookup identical — a handler hitting an unstubbed db_lookup/fhir_lookup yields the identical
     ERROR disposition with and without the tracer, plus a `live_lookup_skipped` annotation.
  3. Coverage-intact — a traced run restores the prior tracer (prev-tracer, not None), so a surrounding
     coverage.py / pytest-cov tracer survives.
  4. PHI — assigned locals + msg writes are "REDACTED" without --show-phi, real values with it.
"""

from __future__ import annotations

import contextlib
import json
import sys
from collections.abc import Iterator
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.db_lookup import db_lookup
from messagefoundry.config.fhir_lookup import fhir_lookup
from messagefoundry.config.models import ConnectorType, Validation
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.pipeline.dryrun_trace import trace_dry_run
from messagefoundry.store import MessageStatus

ADT_A01 = (
    "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260101\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


def _registry(route, handlers, *, strict: bool = False, accepts=None) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in",
            ConnectionSpec(ConnectorType.MLLP, {"host": "0.0.0.0", "port": 2575}),
            router="r",
            validation=Validation(strict=strict, hl7_version="2.5.1"),
        )
    )
    reg.add_outbound(
        OutboundConnection("out", ConnectionSpec(ConnectorType.FILE, {"directory": "./out"}))
    )
    reg.add_router("r", route)
    acc = accepts or {}  # ADR 0084 `accepts=` predicates, keyed by handler name (sparse)
    for name, fn in handlers.items():
        reg.add_handler(name, fn, acc.get(name))
    return reg


# --- sample Routers/Handlers (real functions, so sys.settrace sees multiple lines) --------------


def route_to_h(msg: Message) -> list[str]:
    picked = ["h"]
    return picked


def route_to_h_tuple(msg: Message) -> tuple[str, ...]:
    picked = ("h",)
    return picked


def route_to_h_set(msg: Message) -> set[str]:
    picked = {"h"}
    return picked


def route_to_h_generator(msg: Message) -> Iterator[str]:
    yield "h"


class _SinglePassIterable:
    """Iterable but NOT an Iterator -- `__iter__` hands back a stored generator, so it is one-shot.

    The shape the first cut of BACKLOG #1694 got wrong: `isinstance(x, Iterator)` is False and
    `isinstance(x, Iterable)` is True, so an Iterable-gated observer WALKS it and the real routing
    then finds it empty. The traced run delivered 0 where the untraced run delivered 1.
    """

    def __init__(self, *items: str) -> None:
        self._gen = (i for i in items)

    def __iter__(self) -> Iterator[str]:
        return self._gen


class _GetItemOnly:
    """Iterable by the legacy sequence protocol only: `isinstance(x, Iterable)` is False."""

    def __init__(self, *items: str) -> None:
        self._items = items

    def __getitem__(self, index: int) -> str:
        return self._items[index]


class _HostileStr(str):
    """A genuine handler name -- it equals and hashes as ``"h"`` -- whose ``__str__`` raises."""

    def __str__(self) -> str:  # pragma: no cover - raising IS the behaviour under test
        raise RuntimeError("hostile __str__")


def handle_transform(msg: Message) -> Send:
    mrn = msg["PID-3.1"]  # a PHI-bearing local
    msg["MSH-3"] = "FOUNDRY"  # a msg field write on this line
    _unused = mrn  # keep the local referenced
    return Send("out", msg)


def handle_db(msg: Message) -> Send:
    # db_lookup has no runner in a pure dry-run, so it raises DbLookupError → the handler terminates
    # with ERROR, identically to an untraced run.
    rows = db_lookup("clarity", "SELECT npi FROM p WHERE mrn = :mrn", {"mrn": msg["PID-3.1"]})
    _ = rows
    return Send("out", msg)


def handle_fhir(msg: Message) -> Send:
    patient = fhir_lookup("epic", "Patient/123")
    _ = patient
    return Send("out", msg)


def _handler_invocation(trace: dict) -> dict:
    return next(inv for inv in trace["invocations"] if inv["kind"] == "handler")


def _router_invocation(trace: dict) -> dict:
    return next(inv for inv in trace["invocations"] if inv["kind"] == "router")


def _all_assigned(inv: dict) -> dict:
    out: dict = {}
    for ev in inv["events"]:
        out.update(ev.get("assigned", {}))
    return out


def _all_writes(inv: dict) -> list:
    return [w for ev in inv["events"] for w in ev.get("writes", [])]


# --- Gate 1: byte-identical -------------------------------------------------------------------


def test_gate_byte_identical_disposition_and_routing() -> None:
    reg = _registry(route_to_h, {"h": handle_transform})
    plain = dry_run(reg, ADT_A01)
    traced = trace_dry_run(reg, ADT_A01)

    assert traced["disposition"] == plain.disposition.value == MessageStatus.RECEIVED.value
    assert [s["outbound"] for s in traced["sends"]] == [d.to for d in plain.deliveries] == ["out"]
    assert traced["handlers"] == plain.handlers == ["h"]
    assert traced["trace_ok"] is True

    # per-invocation routing/sends
    assert _router_invocation(traced)["routed_to"] == ["h"]
    assert _handler_invocation(traced)["sends"] == [{"outbound": "out"}]


def test_routed_to_reports_a_tuple_or_set_router() -> None:
    """BACKLOG #1694: `routed_to` follows `_handler_names`, which takes any non-str iterable.

    A tuple- or set-returning Router routes for real -- `plain.handlers` proves it on the same run
    -- so a trace saying `routed_to: []` beside it contradicts the run it is observing."""
    for route in (route_to_h_tuple, route_to_h_set):
        reg = _registry(route, {"h": handle_transform})
        plain = dry_run(reg, ADT_A01)
        traced = trace_dry_run(reg, ADT_A01)

        assert plain.handlers == ["h"], route.__name__
        assert _router_invocation(traced)["routed_to"] == ["h"], route.__name__
        # The gate this row is really about: the trace agrees with the untraced run.
        assert _router_invocation(traced)["routed_to"] == plain.handlers, route.__name__
        # `lazy_result` is emitted only when true, so its ABSENCE is the non-degraded case.
        assert "lazy_result" not in _router_invocation(traced), route.__name__


def test_routed_to_never_invents_a_name_the_run_did_not_route_to() -> None:
    """ADR 0072 gate 1b: the trace may say LESS than the run did, never something different.

    `_handler_names` passes elements through uncoerced, so `str()` in the observer manufactures
    names: `b"h"` materialises to `[104]` for the real routing and traced as `['104']`, and
    `range(2)` traced as `['0', '1']`. `return msg["PID-5.1"].encode()` reaches it in one keystroke.
    Found by an independent review of the first cut, which shipped exactly that coercion.
    """
    for returned in (b"h", bytearray(b"h"), memoryview(b"h"), range(2)):
        reg = _registry(lambda msg, r=returned: r, {"h": handle_transform})
        traced = trace_dry_run(reg, ADT_A01)
        inv = _router_invocation(traced)
        assert inv["routed_to"] == [], f"{returned!r} invented {inv['routed_to']}"
        assert inv["lazy_result"] is True, f"{returned!r} was dropped without declaring it"


def test_routed_to_does_not_stringify_a_name_and_so_cannot_raise_on_one() -> None:
    """A str subclass with a raising `__str__` is still a valid handler name.

    Coercing it turned a delivering run into an ERROR -- a gate 1a break, since the untraced run
    delivers. Emitting elements that are ALREADY `str`, uncoerced, never calls `__str__` at all.
    """
    reg_plain = _registry(lambda msg: (_HostileStr("h"),), {"h": handle_transform})
    plain = dry_run(reg_plain, ADT_A01)
    reg_traced = _registry(lambda msg: (_HostileStr("h"),), {"h": handle_transform})
    traced = trace_dry_run(reg_traced, ADT_A01)

    assert plain.disposition.value == "received"
    assert traced["disposition"] == plain.disposition.value
    assert traced["handlers"] == plain.handlers
    assert _router_invocation(traced)["routed_to"] == ["h"]


def test_routed_to_does_not_drain_a_single_pass_iterable_that_is_not_an_iterator() -> None:
    """The carve-out's real subject is SINGLE-PASS, and `isinstance(x, Iterator)` does not test it.

    THIS IS THE ARM THAT PINS THE ALLOWLIST. An Iterable-gated observer walks `_SinglePassIterable`,
    the real routing then finds it exhausted, and the traced run reports `unrouted` with zero
    deliveries while the untraced run delivers one. Worse, `lazy_result` did not fire, so the single
    case where the tracer actually broke the run was the one case it failed to declare.
    """
    reg_plain = _registry(lambda msg: _SinglePassIterable("h"), {"h": handle_transform})
    plain = dry_run(reg_plain, ADT_A01)
    reg_traced = _registry(lambda msg: _SinglePassIterable("h"), {"h": handle_transform})
    traced = trace_dry_run(reg_traced, ADT_A01)

    # Byte-identical: the observer consumed nothing.
    assert plain.handlers == ["h"]
    assert traced["handlers"] == plain.handlers
    assert traced["disposition"] == plain.disposition.value
    assert len(traced["sends"]) == len(plain.deliveries) == 1
    # ...and the omission is declared rather than read as a Router that selected nothing.
    inv = _router_invocation(traced)
    assert inv["routed_to"] == []
    assert inv["lazy_result"] is True


def test_routed_to_declares_rather_than_silently_skips_a_getitem_only_sequence() -> None:
    """`isinstance(x, Iterable)` is False for it, yet `_handler_names`' `list()` routes it fine.

    So the trace cannot report it, which is allowed -- but it must SAY so. Reporting `[]` with no
    `lazy_result` is the original #1694 defect wearing a different shape."""
    reg_plain = _registry(lambda msg: _GetItemOnly("h"), {"h": handle_transform})
    plain = dry_run(reg_plain, ADT_A01)
    reg_traced = _registry(lambda msg: _GetItemOnly("h"), {"h": handle_transform})
    traced = trace_dry_run(reg_traced, ADT_A01)

    assert plain.handlers == ["h"]
    assert traced["handlers"] == plain.handlers
    inv = _router_invocation(traced)
    assert inv["routed_to"] == []
    assert inv["lazy_result"] is True


def test_routed_to_still_declines_to_drain_a_generator_router() -> None:
    """The one shape that stays empty, and it is declared rather than silent.

    Draining the one-shot iterator here would leave the real routing nothing to materialise, so the
    traced run would deliver 0 where the untraced run delivers 1. `lazy_result` says so."""
    reg = _registry(route_to_h_generator, {"h": handle_transform})
    plain = dry_run(reg, ADT_A01)
    traced = trace_dry_run(reg, ADT_A01)

    assert plain.handlers == ["h"]
    assert _router_invocation(traced)["routed_to"] == []
    assert _router_invocation(traced)["lazy_result"] is True
    # Byte-identical despite the empty routed_to: the tracer did not consume the generator.
    assert traced["handlers"] == plain.handlers == ["h"]


def _two_out_registry(handle) -> Registry:
    """``_registry`` plus a second outbound, so a fan-out has two distinguishable destinations."""
    reg = _registry(route_to_h, {"h": handle})
    reg.add_outbound(
        OutboundConnection("out2", ConnectionSpec(ConnectorType.FILE, {"directory": "./out2"}))
    )
    return reg


def handle_generator(msg: Message) -> Iterator[Send]:
    """A generator Handler: it delivers (BACKLOG #341) but its body runs *after* the tracer detaches."""
    yield Send("out", msg)
    yield Send("out2", msg)


def test_gate_1a_a_generator_handler_traces_byte_identically_at_message_level() -> None:
    """ADR 0072 gate 1a for the shape that most nearly broke it.

    ``_sends_from`` mirrors ``_partition`` — but ``_partition``'s rule now materialises **any**
    non-``str`` iterable, and materialising a generator CONSUMES it. Mirroring that rule literally
    would leave the real ``_partition`` an exhausted iterator, so the *traced* run would deliver 0
    where the untraced run delivers 2: a tracer that changes the disposition, which is the one thing
    ADR 0072 forbids. ``_sends_from``'s refusal to walk a return it cannot prove re-iterable (an
    ``isinstance(result, Iterator)`` guard until BACKLOG #6823) is what prevents it, and before this
    test nothing covered it — deleting the guard left the whole tracer
    suite green while turning a traced generator Handler into an accept-and-drop.

    The untraced side is asserted non-empty first, so this cannot pass by both runs delivering nothing
    (which is exactly how it would have "passed" before #341 widened ``_partition``)."""
    reg = _two_out_registry(handle_generator)
    plain = dry_run(reg, ADT_A01)
    traced = trace_dry_run(reg, ADT_A01)

    assert [d.to for d in plain.deliveries] == ["out", "out2"]  # the untraced run really delivers
    assert [s["outbound"] for s in traced["sends"]] == [d.to for d in plain.deliveries]
    assert traced["disposition"] == plain.disposition.value
    assert traced["handlers"] == plain.handlers == ["h"]


def test_gate_1b_a_generator_invocation_declares_lazy_result() -> None:
    """ADR 0072 gate 1b: the per-invocation mirror's declared carve-out.

    A generator function returns without running its body, so this record legitimately has no line
    events and no measurable sends. That under-report is honest only if it is *declared* — otherwise
    the payload contradicts itself (top level: two sends; invocation: nothing ran) while ``trace_ok``
    asserts the trace is trustworthy. The ``lazy_result`` flag is the declaration; the list Handler
    below is the control, proving the flag is not simply always set."""
    traced = trace_dry_run(_two_out_registry(handle_generator), ADT_A01)
    inv = _handler_invocation(traced)
    assert inv["lazy_result"] is True
    assert inv["sends"] == [] and inv["events"] == []  # the documented under-report, pinned
    assert traced["sends"] == [{"outbound": "out"}, {"outbound": "out2"}]  # 1a still holds

    control = trace_dry_run(_registry(route_to_h, {"h": handle_transform}), ADT_A01)
    control_inv = _handler_invocation(control)
    assert "lazy_result" not in control_inv  # absent, not False — an eagerly-returning handler
    assert control_inv["sends"] == [{"outbound": "out"}] and control_inv["events"]


class _SinglePassSends:
    """A Handler's single-pass Iterable of ``Send``s: ``__iter__`` returns one stored generator.

    Not an ``Iterator``, so the ``Iterator`` guard alone let ``_sends_from`` walk it, drain it, and
    hand ``_partition`` an empty iterable (BACKLOG #6823)."""

    def __init__(self, *items: Send) -> None:
        self._gen = (i for i in items)

    def __iter__(self) -> Iterator[Send]:
        return self._gen


def handle_single_pass(msg: Message) -> _SinglePassSends:
    return _SinglePassSends(Send("out", msg), Send("out2", msg))


def test_gate_1a_a_single_pass_iterable_handler_traces_byte_identically() -> None:
    """ADR 0072 gate 1a for a Handler returning a single-pass Iterable that is not an Iterator.

    Walking it in the observer exhausted it, so the traced run reported FILTERED with zero
    deliveries while the untraced run delivered two (BACKLOG #6823). The untraced side is asserted
    to deliver first, so the test cannot pass by both runs delivering nothing. The under-report on
    the invocation is declared with ``lazy_result``, as for a generator Handler."""
    plain = dry_run(_two_out_registry(handle_single_pass), ADT_A01)
    traced = trace_dry_run(_two_out_registry(handle_single_pass), ADT_A01)

    assert [d.to for d in plain.deliveries] == ["out", "out2"]
    assert [s["outbound"] for s in traced["sends"]] == [d.to for d in plain.deliveries]
    assert traced["disposition"] == plain.disposition.value
    inv = _handler_invocation(traced)
    assert inv["sends"] == []
    assert inv["lazy_result"] is True


class _GenList(list[Send]):
    """A ``list`` subclass whose ``__iter__`` is single-pass: ``isinstance(x, list)`` is True."""

    def __init__(self, *items: Send) -> None:
        super().__init__(items)
        self._gen = (i for i in items)

    def __iter__(self) -> Iterator[Send]:
        return self._gen


class _IterList(list[Send]):
    """A ``list`` subclass that is also its own one-shot ``Iterator``."""

    def __init__(self, *items: Send) -> None:
        super().__init__(items)
        self._pos = 0

    def __iter__(self) -> _IterList:
        return self

    def __next__(self) -> Send:
        if self._pos >= len(self):
            raise StopIteration
        self._pos += 1
        return list.__getitem__(self, self._pos - 1)


@pytest.mark.parametrize("cls", [_GenList, _IterList])
def test_gate_1a_a_single_pass_container_subclass_handler_is_not_drained(cls: type) -> None:
    """The allowlist is tested on the EXACT type: a builtin-container subclass may be single-pass."""

    def handle(msg: Message) -> object:
        return cls(Send("out", msg), Send("out2", msg))

    plain = dry_run(_two_out_registry(handle), ADT_A01)
    traced = trace_dry_run(_two_out_registry(handle), ADT_A01)

    assert [d.to for d in plain.deliveries] == ["out", "out2"]
    assert [s["outbound"] for s in traced["sends"]] == [d.to for d in plain.deliveries]
    assert traced["disposition"] == plain.disposition.value
    inv = _handler_invocation(traced)
    assert inv["sends"] == []
    assert inv["lazy_result"] is True


@pytest.mark.parametrize("make", [list, tuple, set, frozenset])
def test_handler_invocation_still_traces_re_iterable_containers(make: type) -> None:
    """Control for the allowlist: re-iterable containers are still walked and not marked lazy."""

    def handle(msg: Message) -> object:
        return make([Send("out", msg), Send("out2", msg)])

    inv = _handler_invocation(trace_dry_run(_two_out_registry(handle), ADT_A01))
    assert sorted(s["outbound"] for s in inv["sends"]) == ["out", "out2"]
    assert "lazy_result" not in inv


def test_gate_byte_identical_unrouted_and_filtered() -> None:
    unrouted = trace_dry_run(_registry(lambda m: [], {}), ADT_A01)
    assert unrouted["disposition"] == MessageStatus.UNROUTED.value
    assert unrouted["sends"] == [] and unrouted["handlers"] == []

    filtered = trace_dry_run(_registry(route_to_h, {"h": lambda m: None}), ADT_A01)
    assert filtered["disposition"] == MessageStatus.FILTERED.value
    assert filtered["handlers"] == ["h"] and filtered["sends"] == []


# --- Passive per-line timing (#84 profiling) — must stay byte-identical -------------------------


def test_timing_is_passive_and_byte_identical() -> None:
    # Adding per-line `t` timing must NOT change disposition / routed-to / would-send outbounds.
    reg = _registry(route_to_h, {"h": handle_transform})
    plain = dry_run(reg, ADT_A01)
    traced = trace_dry_run(reg, ADT_A01)

    assert traced["disposition"] == plain.disposition.value == MessageStatus.RECEIVED.value
    assert [s["outbound"] for s in traced["sends"]] == [d.to for d in plain.deliveries] == ["out"]
    assert traced["handlers"] == plain.handlers == ["h"]

    # every line event carries a non-negative float `t` (wall time attributed to that line)
    inv = _handler_invocation(traced)
    assert inv["events"], "expected line events"
    for ev in inv["events"]:
        assert "t" in ev, "each line event must carry a passive `t` timing"
        assert isinstance(ev["t"], float)
        assert ev["t"] >= 0.0


def test_timing_emitted_regardless_of_show_phi() -> None:
    # Timings are not PHI, so they are emitted with OR without --show-phi (values stay REDACTED).
    reg = _registry(route_to_h, {"h": handle_transform})
    redacted = _handler_invocation(trace_dry_run(reg, ADT_A01, show_phi=False))
    assert all(isinstance(ev.get("t"), float) for ev in redacted["events"])
    assert _all_assigned(redacted).get("mrn") == "REDACTED"  # value still gated

    shown = _handler_invocation(trace_dry_run(reg, ADT_A01, show_phi=True))
    assert all(isinstance(ev.get("t"), float) for ev in shown["events"])


# --- Gate 2: live-lookup identical + annotation -----------------------------------------------


def test_gate_live_db_lookup_identical_and_annotated() -> None:
    reg = _registry(route_to_h, {"h": handle_db})
    plain = dry_run(reg, ADT_A01)
    traced = trace_dry_run(reg, ADT_A01)

    assert plain.disposition is MessageStatus.ERROR
    assert traced["disposition"] == MessageStatus.ERROR.value
    assert traced["sends"] == []  # nothing delivered, with or without the tracer

    ann = _handler_invocation(traced)["annotations"]
    assert any(a["kind"] == "live_lookup_skipped" and a["call"] == "db_lookup" for a in ann)


def test_gate_live_fhir_lookup_identical_and_annotated() -> None:
    reg = _registry(route_to_h, {"h": handle_fhir})
    plain = dry_run(reg, ADT_A01)
    traced = trace_dry_run(reg, ADT_A01)

    assert plain.disposition is MessageStatus.ERROR
    assert traced["disposition"] == MessageStatus.ERROR.value
    assert traced["sends"] == []

    ann = _handler_invocation(traced)["annotations"]
    assert any(a["kind"] == "live_lookup_skipped" and a["call"] == "fhir_lookup" for a in ann)


# --- Gate 3: coverage-intact (prev-tracer restored) -------------------------------------------


def test_gate_coverage_intact_prev_tracer_restored() -> None:
    def sentinel(frame, event, arg):
        return sentinel

    prev = sys.gettrace()
    sys.settrace(sentinel)
    try:
        assert sys.gettrace() is sentinel
        traced = trace_dry_run(_registry(route_to_h, {"h": handle_transform}), ADT_A01)
        # The tracer saved-and-restored our sentinel rather than clobbering it with None.
        assert sys.gettrace() is sentinel
        assert traced["trace_ok"] is True
    finally:
        sys.settrace(prev)


def test_prev_tracer_none_is_restored() -> None:
    prev = sys.gettrace()
    sys.settrace(None)
    try:
        trace_dry_run(_registry(route_to_h, {"h": handle_transform}), ADT_A01)
        assert sys.gettrace() is None
    finally:
        sys.settrace(prev)


# --- Gate 4: PHI redaction --------------------------------------------------------------------


def test_gate_phi_redacted_by_default() -> None:
    reg = _registry(route_to_h, {"h": handle_transform})
    traced = trace_dry_run(reg, ADT_A01, show_phi=False)
    inv = _handler_invocation(traced)

    assigned = _all_assigned(inv)
    assert assigned.get("mrn") == "REDACTED"

    writes = _all_writes(inv)
    assert writes, "expected the msg['MSH-3'] write to be captured"
    assert any(w["path"] == "MSH-3" for w in writes)
    assert all(w["value"] == "REDACTED" for w in writes)


def test_gate_phi_shown_with_flag() -> None:
    reg = _registry(route_to_h, {"h": handle_transform})
    traced = trace_dry_run(reg, ADT_A01, show_phi=True)
    inv = _handler_invocation(traced)

    assert _all_assigned(inv).get("mrn") == "100"  # PID-3.1 of ADT_A01
    writes = _all_writes(inv)
    assert any(w["path"] == "MSH-3" and w["value"] == "FOUNDRY" for w in writes)


# --- capture semantics ------------------------------------------------------------------------


def test_events_are_line_addressable_within_the_def() -> None:
    reg = _registry(route_to_h, {"h": handle_transform})
    inv = _handler_invocation(trace_dry_run(reg, ADT_A01, show_phi=True))

    def_line = handle_transform.__code__.co_firstlineno
    assert inv["def_line"] == def_line
    assert inv["module"] == handle_transform.__module__
    lines = [ev["line"] for ev in inv["events"]]
    assert lines, "expected line events"
    # every event line falls inside the function body (after its def line)
    assert all(line > def_line for line in lines)
    # the mrn assignment is attributed to a line strictly before the MSH-3 write's line
    mrn_line = next(ev["line"] for ev in inv["events"] if "mrn" in ev.get("assigned", {}))
    write_line = next(ev["line"] for ev in inv["events"] if ev.get("writes"))
    assert mrn_line < write_line


def test_non_target_frames_are_not_line_traced() -> None:
    # A handler that calls a same-module helper: only the handler frame is traced (code-object scoped),
    # so no helper-internal lines leak into the handler's events.
    def helper(x: str) -> str:
        secret = x + "!"
        return secret

    def handle_calls_helper(msg: Message) -> Send:
        out = helper("hi")
        _ = out
        return Send("out", msg)

    reg = _registry(route_to_h, {"h": handle_calls_helper})
    inv = _handler_invocation(trace_dry_run(reg, ADT_A01, show_phi=True))
    assigned = _all_assigned(inv)
    assert "out" in assigned  # the handler's own local was captured
    assert "secret" not in assigned  # the helper's local was NOT (frame-scoped)


# --- CLI wiring -------------------------------------------------------------------------------

_CONFIG_MODULE = """\
# SPDX-License-Identifier: AGPL-3.0-or-later
from messagefoundry import MLLP, Send, handler, inbound, outbound, router

inbound("IB_TEST", MLLP(port=2599), router="r")
outbound("OB_TEST", MLLP(host="127.0.0.1", port=2600))


@router("r")
def route(msg):
    return ["h"]


@handler("h")
def handle(msg):
    mrn = msg["PID-3.1"]
    msg["MSH-3"] = "FOUNDRY"
    _ = mrn
    return Send("OB_TEST", msg)
"""


def _write_config(tmp_path: Path) -> tuple[str, str]:
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "IB_TEST.py").write_text(_CONFIG_MODULE, encoding="utf-8")
    msg = tmp_path / "adt.hl7"
    msg.write_text(ADT_A01, encoding="utf-8")
    return str(cfg), str(msg)


def test_cli_trace_flag_emits_json(tmp_path: Path, capsys) -> None:
    cfg, msg = _write_config(tmp_path)
    rc = main(["dryrun", "--config", cfg, "--messages", msg, "--trace", "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    assert isinstance(out, list) and len(out) == 1
    entry = out[0]
    assert entry["disposition"] == MessageStatus.RECEIVED.value
    assert entry["sends"] == [{"outbound": "OB_TEST"}]
    assert entry["trace_ok"] is True
    handler_inv = next(inv for inv in entry["invocations"] if inv["kind"] == "handler")
    # PHI redacted by default (no --show-phi)
    assigned = {k: v for ev in handler_inv["events"] for k, v in ev.get("assigned", {}).items()}
    assert assigned.get("mrn") == "REDACTED"


def test_cli_trace_show_phi(tmp_path: Path, capsys) -> None:
    cfg, msg = _write_config(tmp_path)
    rc = main(["dryrun", "--config", cfg, "--messages", msg, "--trace", "json", "--show-phi"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    handler_inv = next(inv for inv in out[0]["invocations"] if inv["kind"] == "handler")
    writes = [w for ev in handler_inv["events"] for w in ev.get("writes", [])]
    assert any(w["path"] == "MSH-3" and w["value"] == "FOUNDRY" for w in writes)


# --- BACKLOG #6822: --show-phi values must still serialize as RFC 8259 JSON --------------------


def handle_non_json_numbers(msg: Message) -> Send:
    nan = float("nan")
    pos_inf = float("inf")
    neg_inf = float("-inf")
    huge = 10**5000  # past CPython's default 4300-digit int-to-str limit
    _unused = (nan, pos_inf, neg_inf, huge)
    return Send("out", msg)


def handle_ordinary_numbers(msg: Message) -> Send:
    count = 42
    ratio = 0.5
    pos_cap = 10**119  # 120 characters: the longest int still kept as a JSON number
    neg_cap = 1 - 10**119  # 120 characters with the sign
    over_cap = -(10**119)  # 121 characters: truncated like a string
    flag = True
    _unused = (count, ratio, pos_cap, neg_cap, over_cap, flag)
    return Send("out", msg)


class _HostileInt(int):
    def __abs__(self) -> int:
        raise RuntimeError("user __abs__ ran")

    def __repr__(self) -> str:
        raise RuntimeError("user __repr__ ran")


class _HostileFloat(float):
    def __repr__(self) -> str:
        raise RuntimeError("user __repr__ ran")

    def __gt__(self, other: object) -> bool:
        raise RuntimeError("user __gt__ ran")


def handle_hostile_numbers(msg: Message) -> Send:
    h_int = _HostileInt(10**200)
    h_nan = _HostileFloat("nan")
    h_inf = _HostileFloat("inf")
    _unused = (h_int, h_nan, h_inf)
    return Send("out", msg)


def _strict_assigned(handler) -> dict:
    reg = _registry(route_to_h, {"h": handler})
    traced = trace_dry_run(reg, ADT_A01, show_phi=True)
    # The traced run stays a pure observer: same disposition as the untraced one (ADR 0072 gate 1).
    assert traced["disposition"] == dry_run(reg, ADT_A01).disposition.value
    text = json.dumps(traced, allow_nan=False)  # raises on NaN/Infinity or an unprintable int
    return _all_assigned(_handler_invocation(json.loads(text)))


def test_show_phi_values_serialize_as_strict_json() -> None:
    # Under --show-phi a NaN/Infinity float passed through unchanged, so the CLI's json.dumps wrote the
    # bare tokens NaN/Infinity (not JSON), and a >4300-digit int made json.dumps raise ValueError.
    assigned = _strict_assigned(handle_non_json_numbers)
    assert assigned["nan"] == "<float: nan>"
    assert assigned["pos_inf"] == "<float: inf>"
    assert assigned["neg_inf"] == "<float: -inf>"
    assert assigned["huge"] == "<int: too large>"


def test_show_phi_keeps_ordinary_numbers_as_numbers() -> None:
    assigned = _strict_assigned(handle_ordinary_numbers)
    assert assigned["count"] == 42
    assert assigned["ratio"] == 0.5
    assert assigned["pos_cap"] == 10**119
    assert assigned["neg_cap"] == 1 - 10**119
    assert assigned["over_cap"] == str(-(10**119))[:120] + "…(truncated)"
    assert assigned["flag"] is True


def test_show_phi_numbers_call_no_subclass_hook() -> None:
    # The tracer must not run user code a numeric subclass defines, or a traced run could ERROR where
    # the untraced one delivers.
    assigned = _strict_assigned(handle_hostile_numbers)
    assert assigned["h_int"] == str(10**200)[:120] + "…(truncated)"
    assert assigned["h_nan"] == "<float: nan>"
    assert assigned["h_inf"] == "<float: inf>"


def test_cli_trace_show_phi_writes_strict_json(tmp_path: Path, capsys) -> None:
    # The real serializer: `dryrun --trace --show-phi` stdout must parse with NaN/Infinity refused.
    module = _CONFIG_MODULE.replace(
        '    mrn = msg["PID-3.1"]\n',
        '    mrn = msg["PID-3.1"]\n    nan = float("nan")\n    huge = 10**5000\n',
    )
    assert module != _CONFIG_MODULE
    cfg = tmp_path / "config"
    cfg.mkdir()
    (cfg / "IB_TEST.py").write_text(module, encoding="utf-8")
    msg = tmp_path / "adt.hl7"
    msg.write_text(ADT_A01, encoding="utf-8")
    rc = main(["dryrun", "--config", str(cfg), "--messages", str(msg), "--trace", "--show-phi"])
    assert rc == 0

    def _refuse(token: str) -> object:
        raise ValueError(f"non-JSON token {token}")

    out = json.loads(capsys.readouterr().out, parse_constant=_refuse)
    assigned = _all_assigned(_handler_invocation(out[0]))
    assert assigned["nan"] == "<float: nan>"
    assert assigned["huge"] == "<int: too large>"


# --- ADR 0084: an `accepts=` decline is surfaced in the trace ----------------------------------


def route_to_both(msg: Message) -> list[str]:
    picked = ["h", "h_declines"]
    return picked


def accepts_adt(msg: Message) -> bool:
    mtype = msg["MSH-9.1"]  # a pure peek — the sanctioned shape of a predicate
    return mtype == "ADT"


def accepts_never(msg: Message) -> bool:
    verdict = False
    return verdict


def test_trace_marks_accepts_declined() -> None:
    """A handler declined at the router stage never runs, so it vanishes from `handlers` — with no
    trace of WHY. `accepts_declined` names it (and the predicate's own lines are traced as an
    "accepts" invocation), which is the #92 live-debug question: *why didn't my handler fire?*"""
    reg = _registry(
        route_to_both,
        {"h": handle_transform, "h_declines": handle_transform},
        accepts={"h": accepts_adt, "h_declines": accepts_never},
    )
    plain = dry_run(reg, ADT_A01)
    traced = trace_dry_run(reg, ADT_A01)

    # Byte-identical to the untraced run (the tracer stays a pure observer of the verdict).
    assert traced["handlers"] == plain.handlers == ["h"]
    assert traced["disposition"] == plain.disposition.value == MessageStatus.RECEIVED.value
    # …and the declined handler is named, not silently absent.
    assert traced["accepts_declined"] == ["h_declines"]

    # Both predicates were traced; the accepting one is NOT reported as declined.
    accepts_invs = [inv for inv in traced["invocations"] if inv["kind"] == "accepts"]
    assert [inv["name"] for inv in accepts_invs] == ["h", "h_declines"]
    assert all(inv["events"] for inv in accepts_invs)  # real lines captured, not an empty shell
    # The declining predicate's own local is visible (redacted without --show-phi).
    declined_locals = _all_assigned(accepts_invs[1])
    assert "verdict" in declined_locals


def test_trace_all_declined_is_unrouted() -> None:
    reg = _registry(
        route_to_both,
        {"h": handle_transform, "h_declines": handle_transform},
        accepts={"h": accepts_never, "h_declines": accepts_never},
    )
    traced = trace_dry_run(reg, ADT_A01)
    assert traced["handlers"] == []
    assert traced["accepts_declined"] == ["h", "h_declines"]
    # The ratified §4 semantic: no handler took it ⇒ UNROUTED (never FILTERED).
    assert traced["disposition"] == MessageStatus.UNROUTED.value


def test_trace_accepts_declined_is_empty_without_predicates() -> None:
    # AC-7 in the trace surface: a graph with no `accepts=` emits an empty list, never a missing key.
    traced = trace_dry_run(_registry(route_to_h, {"h": handle_transform}), ADT_A01)
    assert traced["accepts_declined"] == []
    assert not [inv for inv in traced["invocations"] if inv["kind"] == "accepts"]


# --- bounded capture + the shared Message patch (BACKLOG #6824, #6825) --------------------------


def _capture_tracers(monkeypatch: pytest.MonkeyPatch) -> list:
    """Keep each `_Tracer` that `trace_dry_run` builds, so a test can read its recorders."""
    from messagefoundry.pipeline import dryrun_trace as dt

    made: list = []

    class _Kept(dt._Tracer):
        def __init__(self, show_phi: bool) -> None:
            super().__init__(show_phi)
            made.append(self)

    monkeypatch.setattr(dt, "_Tracer", _Kept)
    return made


def _retained_writes(rec) -> int:
    pending = sum(len(v) for v in rec._writes_by_line.values())
    return pending + sum(len(ev.get("writes", [])) for ev in rec.events)


def test_writes_after_the_event_cap_are_not_retained(monkeypatch: pytest.MonkeyPatch) -> None:
    # Past _MAX_EVENTS no line is finalized, so a write recorded then is never emitted. It must not
    # be kept either, or a long mutating loop grows the recorder without bound (BACKLOG #6824).
    from messagefoundry.pipeline.dryrun_trace import _MAX_EVENTS

    def handle_loops(msg: Message) -> Send:
        for _ in range(_MAX_EVENTS * 2):
            msg["MSH-3"] = "X"
        return Send("out", msg)

    made = _capture_tracers(monkeypatch)
    traced = trace_dry_run(_registry(route_to_h, {"h": handle_loops}), ADT_A01)
    assert traced["sends"] == [{"outbound": "out"}]
    inv = _handler_invocation(traced)
    assert inv.get("truncated") is True
    rec = next(r for r in made[0].invocations if r.kind == "handler")
    assert rec._writes_by_line == {}
    assert _retained_writes(rec) <= _MAX_EVENTS
    assert _all_writes(inv), "writes before the cap are still emitted"


def test_writes_from_a_helper_loop_are_bounded(monkeypatch: pytest.MonkeyPatch) -> None:
    # A helper the Handler calls is not line-traced, so all its writes land on one Handler line.
    # The per-invocation write cap must bound those too, and say so as `writes_truncated`: every
    # line is still present, so `truncated` (which a consumer reads as short line coverage) stays
    # off (BACKLOG #6824).
    from messagefoundry.pipeline.dryrun_trace import _MAX_WRITES

    def fill(msg: Message) -> None:
        for _ in range(_MAX_WRITES * 2):
            msg["MSH-3"] = "X"

    def handle_calls_fill(msg: Message) -> Send:
        fill(msg)
        return Send("out", msg)

    made = _capture_tracers(monkeypatch)
    traced = trace_dry_run(_registry(route_to_h, {"h": handle_calls_fill}), ADT_A01)
    assert traced["sends"] == [{"outbound": "out"}]
    inv = _handler_invocation(traced)
    assert inv.get("writes_truncated") is True
    assert "truncated" not in inv
    rec = next(r for r in made[0].invocations if r.kind == "handler")
    assert _retained_writes(rec) <= _MAX_WRITES
    assert len(_all_writes(inv)) == _MAX_WRITES


def test_a_refused_write_is_not_recorded_and_spends_no_write_budget() -> None:
    # Only a write that took is recorded, so refused writes cannot push a real one past the cap.
    from messagefoundry.pipeline.dryrun_trace import _MAX_WRITES

    def try_absent(msg: Message) -> None:
        for _ in range(_MAX_WRITES):
            with contextlib.suppress(KeyError, ValueError):
                msg["ZZZ-1"] = "X"

    def handle_refused_then_real(msg: Message) -> Send:
        try_absent(msg)
        msg["MSH-3"] = "REAL"
        return Send("out", msg)

    traced = trace_dry_run(
        _registry(route_to_h, {"h": handle_refused_then_real}), ADT_A01, show_phi=True
    )
    inv = _handler_invocation(traced)
    assert [w["path"] for w in _all_writes(inv)] == ["MSH-3"]
    assert "writes_truncated" not in inv


def test_message_write_patch_survives_a_concurrent_trace_exiting() -> None:
    # Two threads tracing at once share the class-level Message._write. The one that finishes first
    # must not restore the original under the other, which would silently stop recording its writes
    # (BACKLOG #6825).
    import threading

    from messagefoundry.pipeline import dryrun_trace as dt

    assert dt._patch_holders == 0
    a_entered = threading.Event()
    b_exited = threading.Event()
    seen: dict[str, object] = {}

    def run_a() -> None:
        with dt._patched_message_writes():
            a_entered.set()
            b_exited.wait(10)
            seen["a_during"] = Message._write

    def run_b() -> None:
        a_entered.wait(10)
        with dt._patched_message_writes():
            pass
        b_exited.set()

    ta = threading.Thread(target=run_a)
    tb = threading.Thread(target=run_b)
    ta.start()
    tb.start()
    ta.join(20)
    tb.join(20)
    assert b_exited.is_set()
    assert seen["a_during"] is dt._recording_write
    assert Message._write is dt._ORIG_MESSAGE_WRITE
    assert dt._patch_holders == 0


def test_concurrent_traced_dry_runs_each_record_their_writes() -> None:
    # End to end: a trace that finishes while another is mid-Handler must not cost the other its
    # later writes (BACKLOG #6825).
    import threading

    from messagefoundry.pipeline import dryrun_trace as dt

    a_paused = threading.Event()
    b_done = threading.Event()
    results: dict[str, dict] = {}

    def handle_pauses(msg: Message) -> Send:
        a_paused.set()
        b_done.wait(10)
        msg["MSH-3"] = "AFTER"
        return Send("out", msg)

    def run_a() -> None:
        reg = _registry(route_to_h, {"h": handle_pauses})
        results["a"] = trace_dry_run(reg, ADT_A01, show_phi=True)

    def run_b() -> None:
        a_paused.wait(10)
        results["b"] = trace_dry_run(_registry(route_to_h, {"h": handle_transform}), ADT_A01)
        b_done.set()

    ta = threading.Thread(target=run_a)
    tb = threading.Thread(target=run_b)
    ta.start()
    tb.start()
    ta.join(20)
    tb.join(20)
    assert b_done.is_set()
    assert any(w["path"] == "MSH-3" for w in _all_writes(_handler_invocation(results["b"])))
    a_writes = _all_writes(_handler_invocation(results["a"]))
    assert any(w["path"] == "MSH-3" and w["value"] == "AFTER" for w in a_writes)
    assert Message._write is dt._ORIG_MESSAGE_WRITE
