# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""An outbound's ``reingress_to`` is a declared ``outbound -> inbound`` edge in the static wiring
graph (BACKLOG #5966), from a ``.py`` factory and from a ``connections.toml`` entry alike, so the
graph shows the response cycle and the reference index finds the loopback inbound's referrer."""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.graph import build_wiring_graph
from messagefoundry.config.reachability import build_reference_index
from messagefoundry.config.wiring import load_config

LOGIC = """\
from messagefoundry import Send, handler, router


@router("route_req")
def route_req(msg):
    return "to_partner"


@router("route_loop")
def route_loop(msg):
    return "to_result"


@handler("to_partner")
def to_partner(msg):
    return Send("OB_PARTNER", msg)


@handler("to_result")
def to_result(msg):
    return Send("OB_RESULT", msg)
"""

PY_CONNECTIONS = """\
from messagefoundry import MLLP, File, Loopback, inbound, outbound

inbound("IB_REQ", File(directory="in_req"), router="route_req")
inbound("IB_LOOP", Loopback(), router="route_loop")
outbound("OB_PARTNER", MLLP(host="127.0.0.1", port=2575, reingress_to="IB_LOOP"))
outbound("OB_RESULT", File(directory="out_result"))
"""

# connections.toml has no loopback transport, so the Loopback inbound stays in a .py module.
TOML_LOOPBACK = """\
from messagefoundry import Loopback, inbound

inbound("IB_LOOP", Loopback(), router="route_loop")
"""

TOML_CONNECTIONS = """\
[[inbound]]
name = "IB_REQ"
transport = "file"
router = "route_req"
[inbound.settings]
directory = "in_req"

[[outbound]]
name = "OB_PARTNER"
transport = "mllp"
[outbound.settings]
host = "127.0.0.1"
port = 2575
reingress_to = "IB_LOOP"

[[outbound]]
name = "OB_RESULT"
transport = "file"
[outbound.settings]
directory = "out_result"
"""


def _config(tmp_path: Path, filename: str, connections: str) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    (d / filename).write_text(connections, encoding="utf-8")
    (d / "logic.py").write_text(LOGIC, encoding="utf-8")
    return d


def _assert_reingress_edge(config_dir: Path) -> None:
    registry = load_config(config_dir)
    graph = build_wiring_graph(registry)
    out = {(e.target_kind, e.target, e.provenance) for e in graph.targets("outbound", "OB_PARTNER")}
    assert out == {("inbound", "IB_LOOP", "declared")}
    # The loopback's fan-in is the capturing outbound, so the cycle closes in the graph.
    assert {(e.source_kind, e.source) for e in graph.referrers("inbound", "IB_LOOP")} == {
        ("outbound", "OB_PARTNER")
    }
    # An outbound with no reingress_to carries no outgoing edge.
    assert graph.targets("outbound", "OB_RESULT") == []
    assert not graph.dangling
    # The reference index (rename/delete impact) sees the outbound as the loopback's referrer.
    refs = build_reference_index(registry).referrers("inbound", "IB_LOOP")
    assert {(r.referrer_kind, r.referrer) for r in refs} == {("outbound", "OB_PARTNER")}


def test_py_reingress_to_is_a_declared_outbound_to_inbound_edge(tmp_path: Path) -> None:
    _assert_reingress_edge(_config(tmp_path, "connections.py", PY_CONNECTIONS))


def test_toml_reingress_to_is_a_declared_outbound_to_inbound_edge(tmp_path: Path) -> None:
    config_dir = _config(tmp_path, "connections.toml", TOML_CONNECTIONS)
    (config_dir / "loopback.py").write_text(TOML_LOOPBACK, encoding="utf-8")
    _assert_reingress_edge(config_dir)


def test_reingress_to_naming_no_registered_inbound_emits_no_edge(tmp_path: Path) -> None:
    typo = PY_CONNECTIONS.replace('reingress_to="IB_LOOP"', 'reingress_to="IB_NOPE"')
    graph = build_wiring_graph(load_config(_config(tmp_path, "connections.py", typo)))
    assert graph.targets("outbound", "OB_PARTNER") == []
    assert graph.referrers("inbound", "IB_NOPE") == []
