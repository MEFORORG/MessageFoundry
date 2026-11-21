# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An ``Http`` inbound's ``reply_from`` is a declared ``inbound -> outbound`` edge in the static
wiring graph (BACKLOG #5966), from a ``.py`` factory and from a ``connections.toml`` entry alike, so
the reference index finds the outbound's referrer. The edge points from the inbound that NAMES the
outbound to the outbound it names; one naming no outbound is dangling instead.

The edge is tagged with its ``reply_from`` relation, which carries no data: delete impact and rename
follow it, and the reachability walk and the data-flow graph route do not."""

from __future__ import annotations

import json
from pathlib import Path

import httpx
import pytest

from messagefoundry.__main__ import main
from messagefoundry.api import create_app
from messagefoundry.config.graph import DanglingRef, build_wiring_graph
from messagefoundry.config.impact import delete_impact
from messagefoundry.config.reachability import Reference, build_reference_index
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline import Engine
from messagefoundry_toolkit.__main__ import main as toolkit_main

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


# --- the relation tag: what each edge's naming means ---------------------------------------------


def test_every_edge_carries_its_relation(tmp_path: Path) -> None:
    graph = build_wiring_graph(load_config(_config(tmp_path, "connections.py", PY_CONNECTIONS)))
    relations = {
        (e.source_kind, e.target_kind, e.target): (e.relation, e.carries_data) for e in graph.edges
    }
    assert relations == {
        ("inbound", "router", "route_req"): ("router", True),
        ("router", "handler", "to_partner"): ("routes", True),
        ("handler", "outbound", "OB_PARTNER"): ("sends", True),
        ("inbound", "outbound", "OB_PARTNER"): ("reply_from", False),
    }


def _reply_only(tmp_path: Path) -> Path:
    """IB_REQ's reply_from names OB_OTHER, which no handler sends to."""
    body = PY_CONNECTIONS_TEMPLATE.format(target="OB_OTHER", deployed=True)
    return _config(tmp_path, "connections.py", body)


def test_reachability_does_not_walk_a_reply_from(tmp_path: Path) -> None:
    # The reply_from names OB_OTHER but sends it nothing, so nothing ever produces the reply: the
    # walk reports it dead. The reference index still lists the inbound as its referrer.
    registry = load_config(_reply_only(tmp_path))
    index = build_reference_index(registry)
    assert index.unreferenced(registry) == [("outbound", "OB_OTHER")]
    refs = index.referrers("outbound", "OB_OTHER")
    assert [(r.referrer_kind, r.referrer, r.relation) for r in refs] == [
        ("inbound", "IB_REQ", "reply_from")
    ]


def test_delete_impact_names_the_reply_from_referrer(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    config_dir = _reply_only(tmp_path)
    referrers = delete_impact(
        build_reference_index(load_config(config_dir)), "outbound", "OB_OTHER"
    )
    assert referrers == [Reference("inbound", "IB_REQ", "outbound", "OB_OTHER")]
    argv = ["impact", "--config", str(config_dir), "outbound", "OB_OTHER", "--delete", "--json"]
    assert toolkit_main(argv) == 0
    out = json.loads(capsys.readouterr().out)
    assert [(r["referrer"], r["relation"]) for r in out["referrers"]] == [("IB_REQ", "reply_from")]


def test_delete_impact_names_a_reply_from_written_as_an_env_default(tmp_path: Path) -> None:
    # The wiring graph reads only a literal setting, so the index adds this referrer itself; delete
    # impact and rename both read the index.
    body = PY_CONNECTIONS.replace(
        'reply_from="OB_PARTNER"', 'reply_from=env("REPLY_OB", default="OB_OTHER")'
    ).replace("import Http,", "import Http, env,")
    config_dir = _config(tmp_path, "connections.py", body)
    referrers = delete_impact(
        build_reference_index(load_config(config_dir)), "outbound", "OB_OTHER"
    )
    assert [(r.referrer_kind, r.referrer, r.relation) for r in referrers] == [
        ("inbound", "IB_REQ", "reply_from")
    ]


async def test_the_data_flow_graph_route_leaves_out_a_reply_from(tmp_path: Path) -> None:
    # The web console draws GET /graph/edges as data flow; a reply_from drawn there would be a
    # forward line against the reply's own flow.
    eng = await Engine.create(
        tmp_path / "g.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    try:
        eng.add_registry(load_config(_config(tmp_path, "connections.py", PY_CONNECTIONS)))
        app = create_app(eng, allow_no_auth=True)
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            body = (await c.get("/graph/edges")).json()
    finally:
        await eng.stop()
    pairs = {(e["source_kind"], e["source"], e["target_kind"], e["target"]) for e in body["edges"]}
    assert ("handler", "to_partner", "outbound", "OB_PARTNER") in pairs
    assert ("inbound", "IB_REQ", "outbound", "OB_PARTNER") not in pairs
