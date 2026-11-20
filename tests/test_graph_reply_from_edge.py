# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An ``Http`` inbound's ``reply_from`` is a declared ``inbound -> outbound`` edge in the static
wiring graph (BACKLOG #5966), from a ``.py`` factory and from a ``connections.toml`` entry alike, so
the reference index finds the outbound's referrer. The edge points from the inbound that NAMES the
outbound to the outbound it names; one naming no outbound is dangling instead."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from messagefoundry.__main__ import main
from messagefoundry.config.graph import DanglingRef, build_wiring_graph
from messagefoundry.config.reachability import build_reference_index
from messagefoundry.config.wiring import load_config

LOGIC = """\
from messagefoundry import Send, handler, router


@router("route_req")
def route_req(msg):
    return "to_partner"


@handler("to_partner")
def to_partner(msg):
    return Send("OB_PARTNER", msg)
"""

PY_CONNECTIONS_TEMPLATE = """\
from messagefoundry import Http, Rest, inbound, outbound

inbound("IB_REQ", Http(port=18765, reply_from="{target}"), router="route_req", deployed={deployed})
outbound("OB_PARTNER", Rest(url="https://partner.example/ingest", capture_response=True))
outbound("OB_OTHER", Rest(url="https://other.example/ingest"))
"""
PY_CONNECTIONS = PY_CONNECTIONS_TEMPLATE.format(target="OB_PARTNER", deployed=True)

TOML_CONNECTIONS = """\
[[inbound]]
name = "IB_REQ"
transport = "http"
router = "route_req"
[inbound.settings]
port = 18765
reply_from = "OB_PARTNER"

[[outbound]]
name = "OB_PARTNER"
transport = "rest"
[outbound.settings]
url = "https://partner.example/ingest"
capture_response = true

[[outbound]]
name = "OB_OTHER"
transport = "rest"
[outbound.settings]
url = "https://other.example/ingest"
"""


def _config(tmp_path: Path, filename: str, connections: str) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    (d / filename).write_text(connections, encoding="utf-8")
    (d / "logic.py").write_text(LOGIC, encoding="utf-8")
    return d


@pytest.mark.parametrize(
    ("filename", "connections"),
    [("connections.py", PY_CONNECTIONS), ("connections.toml", TOML_CONNECTIONS)],
)
def test_reply_from_is_a_declared_inbound_to_outbound_edge(
    tmp_path: Path, filename: str, connections: str
) -> None:
    registry = load_config(_config(tmp_path, filename, connections))
    graph = build_wiring_graph(registry)
    out = {(e.target_kind, e.target, e.provenance) for e in graph.targets("inbound", "IB_REQ")}
    assert out == {("router", "route_req", "declared"), ("outbound", "OB_PARTNER", "declared")}
    assert {(e.source_kind, e.source) for e in graph.referrers("outbound", "OB_PARTNER")} == {
        ("handler", "to_partner"),
        ("inbound", "IB_REQ"),
    }
    assert graph.referrers("outbound", "OB_OTHER") == []
    assert not graph.dangling
    # The reference index behind delete impact sees the inbound as the outbound's referrer.
    refs = build_reference_index(registry).referrers("outbound", "OB_PARTNER")
    assert ("inbound", "IB_REQ") in {(r.referrer_kind, r.referrer) for r in refs}


@pytest.mark.parametrize("deployed", [True, False])
def test_reply_from_naming_no_outbound_is_dangling_not_an_edge(
    tmp_path: Path, deployed: bool
) -> None:
    # load_config runs no cross-registry check, so a typo loads; build-check would refuse it on a
    # deployed inbound and skips a not-deployed one, where only the graph reports it.
    bad = PY_CONNECTIONS_TEMPLATE.format(target="OB_NOPE", deployed=deployed)
    graph = build_wiring_graph(load_config(_config(tmp_path, "connections.py", bad)))
    assert {e.target_kind for e in graph.targets("inbound", "IB_REQ")} == {"router"}
    assert graph.dangling == (DanglingRef("inbound", "IB_REQ", "OB_NOPE", "outbound"),)


def test_graph_cli_carries_replies_to(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    config_dir = _config(tmp_path, "connections.py", PY_CONNECTIONS)
    assert main(["graph", "--config", str(config_dir), "--json"]) == 0
    data = json.loads(capsys.readouterr().out)
    outbound = {o["name"]: o for o in data["outbound"]}
    assert outbound["OB_PARTNER"]["replies_to"] == ["IB_REQ"]
    assert outbound["OB_PARTNER"]["receives_from"] == ["to_partner"]  # handler senders only
    assert outbound["OB_OTHER"]["replies_to"] == []
    inbound = {i["name"]: i for i in data["inbound"]}
    assert inbound["IB_REQ"]["reingressed_from"] == []  # reply_from is no re-ingress
