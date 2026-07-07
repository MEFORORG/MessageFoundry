# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Traced dry-run (ADR 0072): the ADR gate tests + capture-semantics coverage.

Gates asserted here (ADR 0072):
  1. Byte-identical — a traced run's disposition + sends/routed_to equal the untraced run's.
  2. Live-lookup identical — a handler hitting an unstubbed db_lookup/fhir_lookup yields the identical
     ERROR disposition with and without the tracer, plus a `live_lookup_skipped` annotation.
  3. Coverage-intact — a traced run restores the prior tracer (prev-tracer, not None), so a surrounding
     coverage.py / pytest-cov tracer survives.
  4. PHI — assigned locals + msg writes are "REDACTED" without --show-phi, real values with it.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

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


def _registry(route, handlers, *, strict: bool = False) -> Registry:  # type: ignore[no-untyped-def]
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
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    return reg


# --- sample Routers/Handlers (real functions, so sys.settrace sees multiple lines) --------------


def route_to_h(msg: Message) -> list[str]:
    picked = ["h"]
    return picked


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


def _handler_invocation(trace: dict) -> dict:  # type: ignore[type-arg]
    return next(inv for inv in trace["invocations"] if inv["kind"] == "handler")


def _router_invocation(trace: dict) -> dict:  # type: ignore[type-arg]
    return next(inv for inv in trace["invocations"] if inv["kind"] == "router")


def _all_assigned(inv: dict) -> dict:  # type: ignore[type-arg]
    out: dict = {}
    for ev in inv["events"]:
        out.update(ev.get("assigned", {}))
    return out


def _all_writes(inv: dict) -> list:  # type: ignore[type-arg]
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


def test_gate_byte_identical_unrouted_and_filtered() -> None:
    unrouted = trace_dry_run(_registry(lambda m: [], {}), ADT_A01)
    assert unrouted["disposition"] == MessageStatus.UNROUTED.value
    assert unrouted["sends"] == [] and unrouted["handlers"] == []

    filtered = trace_dry_run(_registry(route_to_h, {"h": lambda m: None}), ADT_A01)
    assert filtered["disposition"] == MessageStatus.FILTERED.value
    assert filtered["handlers"] == ["h"] and filtered["sends"] == []


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
    def sentinel(frame, event, arg):  # type: ignore[no-untyped-def]
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


def test_cli_trace_flag_emits_json(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
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


def test_cli_trace_show_phi(tmp_path: Path, capsys) -> None:  # type: ignore[no-untyped-def]
    cfg, msg = _write_config(tmp_path)
    rc = main(["dryrun", "--config", cfg, "--messages", msg, "--trace", "json", "--show-phi"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    handler_inv = next(inv for inv in out[0]["invocations"] if inv["kind"] == "handler")
    writes = [w for ev in handler_inv["events"] for w in ev.get("writes", [])]
    assert any(w["path"] == "MSH-3" and w["value"] == "FOUNDRY" for w in writes)
