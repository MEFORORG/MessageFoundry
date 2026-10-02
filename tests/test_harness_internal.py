# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The internal-inbound scenarios (TIMER, PassThrough, Loopback) against the REAL harness graph.

The positive runs are also parametrized by ``test_harness_scenarios.py``; this file adds what that
one cannot: a negative control for each assertion the scenarios lean on, so a pass means the check
can fail, and the coverage claim the brief asks for.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import replace
from pathlib import Path
from types import SimpleNamespace

import pytest

from harness.coverage import coverage_rows, registered_kinds
from harness.endpoints import Endpoints
from harness.endpoints import internal as names
from harness.scenarios import INBOUND, SCENARIOS, BaseScenario, ScenarioContext, run_scenario
from harness.scenarios.internal import (
    LOOPBACK,
    PASSTHROUGH,
    TIMER,
    SinkCheck,
    _acknowledged_control_id,
)
from messagefoundry.apiclient import EngineClient
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import load_config
from messagefoundry.mllpcodec import build_ack
from messagefoundry.parsing.message import Message
from tests._harness_engine import ephemeral_overrides, serve_harness_config


@pytest.fixture
def server(tmp_path: Path) -> Iterator[tuple[str, Endpoints]]:
    with serve_harness_config(tmp_path, ephemeral_overrides(tmp_path)) as served:
        yield served


def _run(server: tuple[str, Endpoints], scenario: BaseScenario, timeout: float) -> tuple[bool, str]:
    api_url, eps = server
    with EngineClient(api_url) as client:
        result = run_scenario(scenario, client, timeout=timeout, endpoints=eps)
    return result.ok, result.detail


# --- the graph ---------------------------------------------------------------------------------


def test_the_internal_graph_declares_one_inbound_of_each_internal_kind() -> None:
    registry = load_config("harness/config")
    registry.validate()
    kinds = {
        names.TIMER_INBOUND: ConnectorType.TIMER,
        names.PT_INBOUND: ConnectorType.PT,
        names.LB_INBOUND: ConnectorType.LOOPBACK,
    }
    for name, kind in kinds.items():
        assert registry.inbound[name].spec.type is kind
    for name in (names.PT_ENTRY_INBOUND, names.LB_ENTRY_INBOUND):
        assert registry.inbound[name].spec.type is ConnectorType.MLLP
    # The graph spells the timer marker as a literal (it may not import the harness): pin it.
    assert names.TIMER_CONTROL_ID in registry.inbound[names.TIMER_INBOUND].spec.settings["body"]
    query = registry.outbound[names.LB_QUERY_OUTBOUND].spec.settings
    assert query["reingress_to"] == names.LB_INBOUND
    assert query["capture_response"] is True  # reingress_to implies capture


def test_coverage_reports_timer_passthrough_and_loopback_inbound_covered() -> None:
    rows = coverage_rows(registered_kinds(), SCENARIOS.values())
    covered = {(r.kind, r.direction): r.scenarios for r in rows if r.registered}
    assert covered[("timer", INBOUND)] == ("internal_timer",)
    assert covered[("passthrough", INBOUND)] == ("internal_passthrough",)
    assert covered[("loopback", INBOUND)] == ("internal_loopback",)


# --- served: each scenario passes, and each check it leans on can fail -------------------------


def test_timer_scenario_passes(server: tuple[str, Endpoints]) -> None:
    ok, detail = _run(server, TIMER, 20.0)
    assert ok, detail


def test_timer_scenario_fails_when_its_sink_watches_the_wrong_directory(
    server: tuple[str, Endpoints],
) -> None:
    """Negative control for the sink half: the timer still fires and is still processed, so the
    disposition half passes, and a sink on a directory the timer never writes must fail the run."""
    elsewhere = replace(TIMER, sink_endpoint="file_out")
    ok, detail = _run(server, elsewhere, 6.0)
    assert not ok
    assert "0/2 delivered to the file sink" in detail
    assert not detail.startswith("0/"), detail  # the disposition half did see the timer fire


def test_timer_scenario_fails_when_its_records_are_on_another_inbound(
    server: tuple[str, Endpoints],
) -> None:
    """Negative control for the disposition half: the archive still arrives, so the sink half
    passes, and asking for the timer's records on an inbound that has none must fail the run."""
    elsewhere = replace(TIMER, inbound="IB_Coverage_MLLP")
    ok, detail = _run(server, elsewhere, 6.0)
    assert not ok
    assert detail.startswith("0/2 timer messages"), detail
    assert "0/2 delivered" not in detail  # the sink half did see the archive arrive


@pytest.mark.xfail(
    strict=True,
    raises=AssertionError,
    reason=(
        "engine defect: a PassThrough child is recorded with control_id, message_type and summary "
        "all None (MessageStore._insert_passthrough_child does not peek the body), while a Loopback "
        "re-ingress peeks it (ADR 0013 Q5); a PT child is not findable by its control id"
    ),
)
def test_a_passthrough_child_is_findable_by_its_control_id(server: tuple[str, Endpoints]) -> None:
    """The reproducer for the gap PASSTHROUGH works around with ``by_body``: the same scenario,
    told to look the PT child up by its recorded control id, as LOOPBACK does for its child."""
    by_control_id = replace(PASSTHROUGH, by_body=())
    ok, detail = _run(server, by_control_id, 8.0)
    # Any OTHER failure must not read as the known gap: it raises something the xfail does not
    # accept, so the test reports it as a failure.
    if f"{names.PT_ENTRY_INBOUND}: 3/3 processed" not in detail:
        raise RuntimeError(f"the entry hop itself failed, not the PT lookup: {detail}")
    assert ok, detail


def test_passthrough_sink_is_not_mistaken_for_a_loopback_reply(
    server: tuple[str, Endpoints],
) -> None:
    """Negative control for the Loopback reply check: the PassThrough sink receives the original
    messages, so asking it for ACKs naming those control ids must fail. That is what makes the
    Loopback scenario's reply assertion mean "the captured ACK came back", not "a copy arrived"."""
    as_acks = replace(PASSTHROUGH, sink_checks=(SinkCheck("internal_pt_sink", expect_ack=True),))
    ok, detail = _run(server, as_acks, 5.0)
    assert not ok
    assert "0/3 ACKs for them at sink internal_pt_sink" in detail


def test_loopback_scenario_passes(server: tuple[str, Endpoints]) -> None:
    ok, detail = _run(server, LOOPBACK, 20.0)
    assert ok, detail
    assert f"{names.LB_INBOUND}: 3/3 processed" in detail
    assert "3/3 ACKs for them at sink internal_lb_reply" in detail


def test_loopback_scenario_fails_when_the_peer_rejects(server: tuple[str, Endpoints]) -> None:
    """Negative control: the query sink answers AR, a negative ACK, which retries and dead-letters
    rather than re-ingressing. No record may appear on the Loopback inbound, so the run fails."""
    rejecting = replace(
        LOOPBACK,
        sink_checks=(
            SinkCheck("internal_lb_query", reply="AR"),
            SinkCheck("internal_lb_reply", expect_ack=True),
        ),
    )
    ok, detail = _run(server, rejecting, 6.0)
    assert not ok
    assert f"{names.LB_INBOUND}: 0/3 processed" in detail


# --- unserved: the timer cannot be satisfied by an earlier run ---------------------------------


def test_timer_ignores_rows_recorded_before_the_scenario_started(tmp_path: Path) -> None:
    class Client:
        def list_messages(self, **kwargs: object) -> object:
            old = SimpleNamespace(
                status="processed", received_at=0.0, control_id=names.TIMER_CONTROL_ID
            )
            return SimpleNamespace(messages=[old] * 5)

    eps = Endpoints({"internal_timer_out": str(tmp_path / "out")})
    ctx = ScenarioContext(Client(), eps, timeout=0.3)  # type: ignore[arg-type]
    result = TIMER.run(ctx)
    assert not result.ok
    assert "0/2 timer messages since start" in result.detail


def test_acknowledged_control_id_reads_msa2_only_from_an_ack() -> None:
    message = Message.parse(
        "MSH|^~\\&|A|B|C|D|20260101||ADT^A04^ADT_A01|CID-1|P|2.5.1\rEVN|A04|20260101\r"
    )
    assert _acknowledged_control_id(str(message).encode()) is None
    ack = build_ack(str(message), code="AA", timestamp="20260101")
    assert _acknowledged_control_id(ack.encode()) == "CID-1"
    assert _acknowledged_control_id(b"not hl7") is None
