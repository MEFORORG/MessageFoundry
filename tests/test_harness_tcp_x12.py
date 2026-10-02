# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The raw-TCP and X12 harness families (vault BACKLOG #2674): drivers, sinks, the synthetic X12
builder, and negative controls for the scenarios.

The scenarios themselves run against the REAL ``harness/config`` graph in
``tests/test_harness_scenarios.py::test_every_registered_scenario_passes_against_the_real_graph``.
This file pairs each driver with its sink on loopback, pins the coverage rows, and proves the
scenario checks can say no: each control below must FAIL, and is asserted to.
"""

from __future__ import annotations

import socket
import time
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

import pytest

from harness import drivers, endpoints, sinks
from harness.__main__ import main
from harness.drivers._x12_interchange import fresh_control_number, interchange, isa, ta1
from harness.drivers.tcp import TcpDriver
from harness.drivers.x12 import X12Driver
from harness.endpoints import Endpoints
from harness.scenarios import SCENARIOS, run_scenario
from harness.scenarios.tcp import TcpScenario, ack_code, verify_delivered_bytes
from harness.scenarios.x12 import X12Rows, X12Scenario, verify_interchanges
from harness.sinks import Record
from harness.sinks.tcp import TcpSink
from harness.sinks.x12 import X12Sink, isa13_of
from messagefoundry.apiclient import EngineClient
from messagefoundry.framing import MLLP_CODEC
from messagefoundry.parsing.x12 import X12FrameReader, X12Message, check_integrity
from tests._harness_engine import ephemeral_overrides, serve_harness_config


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Endpoints]]:
    """The real harness/config graph, served on ephemeral endpoints."""
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path)) as served:
        yield served


@contextmanager
def _refusing_port() -> Iterator[int]:
    """A loopback port that is bound but not listening, held for the block: a dial there is
    refused, and no other test can take the port meanwhile (a just-stopped sink's port could be)."""
    holder = socket.socket()
    try:
        holder.bind(("127.0.0.1", 0))
        yield int(holder.getsockname()[1])
    finally:
        holder.close()


def _hl7(control_id: str) -> bytes:
    raw = "MSH|^~\\&|A|B|C|D|20260101000000||ADT^A04|" + control_id + "|P|2.5.1\rPID|1||X\r"
    return raw.encode()


# --- discovery, endpoints, coverage -----------------------------------------------------------------


def test_the_families_are_discovered_and_their_endpoints_default_into_the_row_range() -> None:
    assert {"tcp", "x12"} <= set(drivers.registry())
    assert {"tcp", "x12"} <= set(sinks.registry())
    defaults = {
        k: endpoints.registry()[k].default for k in ("tcp_in", "tcp_out", "x12_in", "x12_out")
    }
    assert all(2580 <= int(v) <= 2589 for v in defaults.values()), defaults
    assert len(set(defaults.values())) == 4


def test_coverage_shows_tcp_and_x12_in_both_directions(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["--coverage"]) == 0
    lines = capsys.readouterr().out.splitlines()

    def row(direction: str, kind: str) -> set[str]:
        hits = [ln for ln in lines if ln.split()[:2] == [direction, kind]]
        assert len(hits) == 1, (direction, kind, lines)
        return set(hits[0].split(None, 2)[2].split(", "))

    assert row("inbound", "tcp") >= {"tcp_delivered", "tcp_handler_error", "tcp_not_hl7_nak"}
    assert row("outbound", "tcp") >= {"tcp_delivered", "tcp_dead_letter"}
    assert row("inbound", "x12") >= {"x12_delivered", "x12_envelope_rejected"}
    assert row("outbound", "x12") >= {"x12_delivered", "x12_ta1_reject_dead_letter"}


def test_the_tcp_and_x12_sinks_bind_loopback_whatever_the_host_endpoint_says() -> None:
    eps = Endpoints({"host": "0.0.0.0"}, environ={})  # noqa: S104  (the point of the test)
    for kind, key in (("tcp", "tcp_out"), ("x12", "x12_out")):
        sink = sinks.build(kind, eps, key)
        assert isinstance(sink, (TcpSink, X12Sink))
        assert sink._server.host == sinks.LOOPBACK


def test_the_family_scenarios_refuse_a_shape_they_cannot_run() -> None:
    with pytest.raises(ValueError, match="drives and sinks tcp only"):
        TcpScenario("x", "", "ADT", "A04", sink="mllp", sink_endpoint="mllp_echo")
    with pytest.raises(ValueError, match="needs a sink to refuse"):
        X12Scenario("x", "", expect="dead_letter")
    with pytest.raises(ValueError, match="count must be"):
        X12Scenario("x", "", count=0)


def test_only_a_scenario_with_a_sink_claims_an_outbound() -> None:
    assert SCENARIOS["tcp_handler_error"].covers == {("tcp", "inbound")}
    assert SCENARIOS["tcp_delivered"].covers == {("tcp", "inbound"), ("tcp", "outbound")}
    assert SCENARIOS["x12_envelope_rejected"].covers == {("x12", "inbound")}
    assert SCENARIOS["x12_delivered"].covers == {("x12", "inbound"), ("x12", "outbound")}


# --- the synthetic X12 builder ----------------------------------------------------------------------


def test_the_builder_makes_an_interchange_that_ties_out_and_frames_whole() -> None:
    control = fresh_control_number()
    good = interchange(control)
    assert len(isa(control)) == 106
    assert check_integrity(good.decode()) == []
    assert isa13_of(good) == control
    reader = X12FrameReader()
    framed = [frame for byte in good for frame in reader.feed(bytes([byte]))]
    assert framed == [good]  # fed one byte at a time, reassembled whole


def test_a_corrupt_trailer_frames_but_does_not_tie_out() -> None:
    """Control for the test above: the integrity check the graph's handler runs can fail."""
    control = "000000123"
    bad = interchange(control, corrupt_trailer=True)
    assert list(X12FrameReader().feed(bad)) == [bad]
    problems = check_integrity(bad.decode())
    assert problems == ["ISA13 '000000123' != IEA02 '000000124'"]


def test_the_ta1_parses_as_the_acknowledgement_the_engine_classifies() -> None:
    reply = X12Message.parse(ta1("000000123", "R", control="000000999"))
    assert reply.segment_ids()[:2] == ["ISA", "TA1"]
    assert reply.get("TA1-01") == "000000123"
    assert reply.get("TA1-04") == "R"
    assert reply.get("ISA-13") == "000000999"
    with pytest.raises(ValueError, match="TA104"):
        ta1("000000123", "X")
    with pytest.raises(ValueError, match="nine digits"):
        isa("12")


# --- drivers and sinks, paired ----------------------------------------------------------------------


def test_the_tcp_driver_and_sink_round_trip_byte_for_byte() -> None:
    with TcpSink() as sink:
        out = TcpDriver("127.0.0.1", sink.port, timeout=5.0).inject([_hl7("T1"), _hl7("T2")])
        records = sink.wait_for(lambda rs: len(rs) == 2, 5.0)
    assert [o.error for o in out] == ["", ""]
    assert [o.reply for o in out] == [b"ACK", b"ACK"]  # the sink's reply frame, deframed
    assert [r.payload for r in records] == [_hl7("T1"), _hl7("T2")]  # STX/ETX stripped, exact


def test_a_tcp_sink_can_refuse_and_honour_another_codec() -> None:
    with TcpSink(refuse=True) as sink:
        (out,) = TcpDriver("127.0.0.1", sink.port, timeout=5.0).inject([_hl7("T3")])
        records = sink.wait_for(bool, 5.0)
    assert out.error == "" and out.reply is None  # recorded, then closed with no answer
    assert [r.payload for r in records] == [_hl7("T3")]
    with TcpSink(codec=MLLP_CODEC, reply=b"OK") as sink:
        driver = TcpDriver("127.0.0.1", sink.port, codec=MLLP_CODEC, timeout=5.0)
        assert driver.inject([_hl7("T4")])[0].reply == b"OK"
    with _refusing_port() as port:
        (gone,) = TcpDriver("127.0.0.1", port, timeout=2.0).inject([_hl7("T5")])
    assert gone.error  # reported in the Injection, not raised


def test_the_x12_driver_and_sink_round_trip_and_answer_ta1() -> None:
    controls = [fresh_control_number() for _ in range(2)]
    sent = [interchange(c) for c in controls]
    with X12Sink() as sink:
        out = X12Driver("127.0.0.1", sink.port, timeout=5.0).inject(sent)
        records = sink.wait_for(lambda rs: len(rs) == 2, 5.0)
    assert [r.payload for r in records] == sent
    assert [r.meta["isa13"] for r in records] == controls
    for injection, control in zip(out, controls, strict=True):
        assert injection.reply is not None
        reply = X12Message.parse(injection.reply)
        assert (reply.get("TA1-01"), reply.get("TA1-04")) == (control, "A")


def test_a_silent_x12_sink_answers_nothing_and_a_dead_port_is_an_error() -> None:
    with X12Sink(ta1=None) as sink:
        (out,) = X12Driver("127.0.0.1", sink.port, timeout=5.0).inject([interchange("000000001")])
        assert sink.wait_for(bool, 5.0)
    assert out.error == "" and out.reply is None
    with _refusing_port() as port:
        (gone,) = X12Driver("127.0.0.1", port, timeout=2.0).inject([interchange("000000002")])
    assert gone.error
    with pytest.raises(ValueError, match="ta1 must be"):
        X12Sink(ta1="Q")


# --- the byte checks can say no ---------------------------------------------------------------------


def test_verify_delivered_bytes_rejects_an_altered_or_missing_copy() -> None:
    sent = {"C1": _hl7("C1"), "C2": _hl7("C2")}
    exact = [Record(_hl7("C1")), Record(_hl7("C2"))]
    assert verify_delivered_bytes(sent, exact, 1)[0]
    altered = [Record(_hl7("C1")), Record(_hl7("C2").replace(b"PID|1", b"PID|2"))]
    ok, detail = verify_delivered_bytes(sent, altered, 1)
    assert not ok and "1 arrived altered" in detail
    ok, detail = verify_delivered_bytes(sent, exact, 2)  # each arrived once, twice was required
    assert not ok and detail.startswith("0/2 reached")


def test_verify_interchanges_rejects_a_duplicate_or_altered_interchange() -> None:
    good = interchange("000000005")
    sent = {"000000005": good}
    assert verify_interchanges(sent, [Record(good)], 1)[0]
    assert not verify_interchanges(sent, [Record(good), Record(good)], 1)[0]  # a retry crept in
    altered = good.replace(b"ST*837", b"ST*835")
    ok, detail = verify_interchanges(sent, [Record(altered)], 1)
    assert not ok and "altered" in detail


def test_ack_code_reads_msa_1_and_nothing_else() -> None:
    assert ack_code(b"MSH|^~\\&|A|B|C|D|20260101||ACK|1|P|2.5.1\rMSA|AR|1\r") == "AR"
    assert ack_code(b"not hl7") is None
    assert ack_code(None) is None


# --- negative controls against the real graph -------------------------------------------------------


def test_a_tcp_scenario_expecting_a_nak_for_good_messages_fails(
    server: tuple[str, Endpoints],
) -> None:
    api_url, eps = server
    wrong = TcpScenario("wrong_code", "", "ADT", "A04", 2, "processed", reply_code="AR")
    with EngineClient(api_url) as client:
        result = run_scenario(wrong, client, timeout=15.0, endpoints=eps)
    assert not result.ok
    assert "0/2 replies were AR" in result.detail and "'AA'" in result.detail


def test_a_tcp_dead_letter_scenario_fails_when_the_sink_answers(
    server: tuple[str, Endpoints],
) -> None:
    """The dead-letter scenario passes because its sink refuses; with an answering sink the same
    messages are delivered, so the dead-letter check must come back empty."""
    api_url, eps = server
    answered = TcpScenario(
        "answered",
        "",
        "ADT",
        "A01",
        2,
        "dead_letter",
        dead_letter_destination="OB_Harness_TCP",
        sink="tcp",
        sink_endpoint="tcp_out",
    )
    with EngineClient(api_url) as client:
        result = run_scenario(answered, client, timeout=3.0, endpoints=eps)
    assert not result.ok
    assert result.detail.startswith("0/2 of this run's messages dead-lettered")


def test_an_x12_scenario_expecting_the_wrong_disposition_fails(
    server: tuple[str, Endpoints],
) -> None:
    api_url, eps = server
    wrong = X12Scenario("wrong_x12", "", count=2, expect="processed", corrupt=True)
    with EngineClient(api_url) as client:
        # The loop ends as soon as both rows are terminal, so a generous timeout costs nothing here.
        result = run_scenario(wrong, client, timeout=15.0, endpoints=eps)
    assert not result.ok
    assert "0/2 interchanges reached 'processed'" in result.detail
    assert "statuses seen: ['error']" in result.detail


def test_an_x12_sink_scenario_fails_when_nothing_reaches_the_sink(
    server: tuple[str, Endpoints],
) -> None:
    """A corrupt envelope errors in the handler, so it never reaches the outbound: the disposition
    check passes and the sink check must still fail the scenario."""
    api_url, eps = server
    scenario = X12Scenario("no_sink", "", count=2, expect="error", corrupt=True, sink_ta1="A")
    with EngineClient(api_url) as client:
        result = run_scenario(scenario, client, timeout=8.0, endpoints=eps)
    assert not result.ok
    assert "2/2 interchanges reached 'error'" in result.detail
    assert result.detail.endswith("0/2 reached the x12 sink exactly 1x")


def test_the_x12_lookup_matches_by_this_runs_isa13_not_by_rows_on_the_inbound(
    server: tuple[str, Endpoints],
) -> None:
    """A row already on the inbound must not satisfy a lookup for another ISA13; the same lookup
    for the ISA13 that WAS sent finds it (the positive control that keeps the empty answer honest)."""
    api_url, eps = server
    sent, unsent = fresh_control_number(), fresh_control_number()
    assert X12Driver(eps.host, eps.port("x12_in")).inject([interchange(sent)])[0].error == ""
    with EngineClient(api_url) as client:
        found = X12Rows(client, "IB_Harness_X12", [sent])
        deadline = time.monotonic() + 10.0
        while not found.by_isa13 and time.monotonic() < deadline:
            time.sleep(0.2)
            found.refresh()
        other = X12Rows(client, "IB_Harness_X12", [unsent])
        other.refresh()
    assert set(found.by_isa13) == {sent}
    assert other.by_isa13 == {}
