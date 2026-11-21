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


def _rect_rows(svg: str) -> list[tuple[str, str]]:
    """Each node box's row (y) and the label it holds, in drawing order. The x is left out: the left
    margin widens to hold a back-edge's gutter run, shifting every column by the same amount."""
    return re.findall(r'<rect x="\d+" y="(\d+)"[^>]*>.*?class="gnodelabel">([^<]*)<', svg)


def _lines(svg: str) -> list[tuple[int, int]]:
    return [(int(a), int(b)) for a, b in re.findall(r'<line x1="(\d+)" y1="\d+" x2="(\d+)"', svg)]


def test_reingress_back_edge_is_a_routed_path_not_a_backward_line() -> None:
    svg = str(_flow_graph(GraphResponse(nodes=_NODES, edges=[*_FORWARD, _BACK])))
    # Every straight line runs left to right; the back-edge is not one of them.
    assert len(_lines(svg)) == len(_FORWARD)
    assert all(x1 < x2 for x1, x2 in _lines(svg))
    paths = re.findall(r'<path d="([^"]+)" fill="none" class="([^"]+)"', svg)
    assert len(paths) == 1
    d, cls = paths[0]
    assert cls == "gedge gedge-declared gedge-back"
    # It leaves the outbound's right side and ends on the loopback inbound's left side, by its lane
    # under the rows, 8px below each node's middle where no forward line attaches. One back-edge
    # widens the left margin from 12 to 17: OB_PARTNER sits in column 3 (x=647), IB_LOOP in column 0
    # row 0 (x=17, y=40, middle 55).
    assert d.startswith("M 797 63 ")
    assert d.endswith(" V 63 H 17")


def test_the_cycle_leaves_the_column_layout_untouched() -> None:
    without = str(_flow_graph(GraphResponse(nodes=_NODES, edges=_FORWARD)))
    with_back = str(_flow_graph(GraphResponse(nodes=_NODES, edges=[*_FORWARD, _BACK])))
    assert _rect_rows(with_back) == _rect_rows(without)
    assert len(_rect_rows(without)) == len(_NODES)


def test_each_back_edge_gets_its_own_lane() -> None:
    second = GraphEdge(
        source="to_partner",
        source_kind="handler",
        target="IB_REQ",
        target_kind="inbound",
        provenance="literal",
    )
    svg = str(_flow_graph(GraphResponse(nodes=_NODES, edges=[*_FORWARD, _BACK, second])))
    runs = re.findall(r'<path d="M \d+ \d+ H (\d+) V (\d+) H (\d+) ', svg)
    lanes = [int(lane) for _src_x, lane, _dst_x in runs]
    assert len(lanes) == 2
    assert len(set(lanes)) == 2
    # Each back-edge has its own vertical run on both sides, so no two can be read as crossed.
    assert len({src_x for src_x, _lane, _dst_x in runs}) == 2
    assert len({dst_x for _src_x, _lane, dst_x in runs}) == 2
    # The SVG grows to hold both lanes below the rows.
    match = re.search(r'<svg [^>]*height="(\d+)"', svg)
    assert match is not None
    assert int(match.group(1)) > max(lanes)


def test_every_back_edge_run_stays_inside_the_svg() -> None:
    # Three outbounds, each re-entering its own Loopback inbound: the source-side runs sit right of
    # the outbound column, so the right margin must widen with the gutter as the left one does.
    nodes = [GraphNode(name=f"IB_L{i}", kind="inbound", status="running") for i in range(3)]
    nodes += [GraphNode(name=f"OB_{i}", kind="outbound", status="running") for i in range(3)]
    back = [
        GraphEdge(
            source=f"OB_{i}",
            source_kind="outbound",
            target=f"IB_L{i}",
            target_kind="inbound",
            provenance="declared",
        )
        for i in range(3)
    ]
    svg = str(_flow_graph(GraphResponse(nodes=nodes, edges=back)))
    match = re.search(r'<svg [^>]*width="(\d+)"', svg)
    assert match is not None
    runs = [int(x) for x in re.findall(r'<path d="M \d+ \d+ H (\d+) ', svg)]
    assert len(runs) == 3
    assert max(runs) < int(match.group(1))
