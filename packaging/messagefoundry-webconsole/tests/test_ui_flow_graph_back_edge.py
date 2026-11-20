# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The monitoring flow graph draws an outbound's ``reingress_to`` back-edge into its Loopback
inbound as a routed back-edge, not as a forward line across the whole graph, and the cycle it closes
leaves the column layout untouched (BACKLOG #5966)."""

from __future__ import annotations

import re

from messagefoundry.api.models import GraphEdge, GraphNode, GraphResponse
from messagefoundry_webconsole.pages.monitoring import _flow_graph

_NODES = [
    GraphNode(name="IB_REQ", kind="inbound", status="running"),
    GraphNode(name="IB_LOOP", kind="inbound", status="running"),
    GraphNode(name="route_req", kind="router"),
    GraphNode(name="to_partner", kind="handler"),
    GraphNode(name="OB_PARTNER", kind="outbound", status="running"),
]
_FORWARD = [
    GraphEdge(
        source="IB_REQ",
        source_kind="inbound",
        target="route_req",
        target_kind="router",
        provenance="declared",
    ),
    GraphEdge(
        source="route_req",
        source_kind="router",
        target="to_partner",
        target_kind="handler",
        provenance="literal",
    ),
    GraphEdge(
        source="to_partner",
        source_kind="handler",
        target="OB_PARTNER",
        target_kind="outbound",
        provenance="literal",
    ),
]
_BACK = GraphEdge(
    source="OB_PARTNER",
    source_kind="outbound",
    target="IB_LOOP",
    target_kind="inbound",
    provenance="declared",
)


def _rects(svg: str) -> list[str]:
    return re.findall(r"<rect [^>]*>", svg)


def _lines(svg: str) -> list[tuple[int, int]]:
    return [(int(a), int(b)) for a, b in re.findall(r'<line x1="(\d+)" y1="\d+" x2="(\d+)"', svg)]


def test_reingress_back_edge_is_a_routed_path_not_a_backward_line() -> None:
    svg = str(_flow_graph(GraphResponse(nodes=_NODES, edges=[*_FORWARD, _BACK])))
    # Every straight line runs left to right; the back-edge is not one of them.
    assert len(_lines(svg)) == len(_FORWARD)
    assert all(x1 < x2 for x1, x2 in _lines(svg))
    paths = re.findall(r'<path d="([^"]+)" class="([^"]+)"', svg)
    assert len(paths) == 1
    d, cls = paths[0]
    assert cls == "gedge gedge-declared gedge-back"
    # It leaves the outbound's right side and ends on the loopback inbound's left side, by its lane
    # under the rows: OB_PARTNER sits in column 3 (x=642), IB_LOOP in column 0 row 0 (x=12, y=40).
    assert d.startswith("M 792 55 ")
    assert d.endswith(" V 55 H 12")


def test_the_cycle_leaves_the_column_layout_untouched() -> None:
    without = str(_flow_graph(GraphResponse(nodes=_NODES, edges=_FORWARD)))
    with_back = str(_flow_graph(GraphResponse(nodes=_NODES, edges=[*_FORWARD, _BACK])))
    assert _rects(with_back) == _rects(without)


def test_each_back_edge_gets_its_own_lane() -> None:
    second = GraphEdge(
        source="to_partner",
        source_kind="handler",
        target="IB_REQ",
        target_kind="inbound",
        provenance="literal",
    )
    svg = str(_flow_graph(GraphResponse(nodes=_NODES, edges=[*_FORWARD, _BACK, second])))
    lanes = [int(m) for m in re.findall(r'<path d="M \d+ \d+ H \d+ V (\d+) ', svg)]
    assert len(lanes) == 2
    assert len(set(lanes)) == 2
    # The SVG grows to hold both lanes below the rows.
    match = re.search(r'<svg [^>]*height="(\d+)"', svg)
    assert match is not None
    assert int(match.group(1)) > max(lanes)
