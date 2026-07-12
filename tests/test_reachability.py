# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Reverse-reachability index (#176 dead-config detection, #152 reverse-dependency / impact analysis).

Loads real config modules so the router->handler / handler->Send() edges come from genuinely-compiled
``co_consts``, then checks the reverse index and the advisory ``dead-config`` check."""

from __future__ import annotations

from pathlib import Path

from messagefoundry.checks import _check_dead_config
from messagefoundry.config.reachability import Reference, build_reference_index
from messagefoundry.config.wiring import load_config

_LIVE_AND_DEAD = """
from messagefoundry import MLLP, Send, handler, inbound, outbound, router

inbound("IB_LIVE", MLLP(port=2601), router="r_live")
outbound("OB_LIVE", MLLP(host="127.0.0.1", port=6000))
outbound("OB_DEAD", MLLP(host="127.0.0.1", port=6001))


@router("r_live")
def route(msg):
    return ["h_live"]


@handler("h_live")
def handle_live(msg):
    return Send("OB_LIVE", msg)


@handler("h_dead")
def handle_dead(msg):
    return Send("OB_DEAD", msg)
"""

_ALL_LIVE = """
from messagefoundry import MLLP, Send, handler, inbound, outbound, router

inbound("IB_LIVE", MLLP(port=2602), router="r_live")
outbound("OB_LIVE", MLLP(host="127.0.0.1", port=6002))


@router("r_live")
def route(msg):
    return ["h_live"]


@handler("h_live")
def handle_live(msg):
    return Send("OB_LIVE", msg)
"""


def _write_config(tmp_path: Path, body: str) -> Path:
    d = tmp_path / "config"
    d.mkdir()
    (d / "mod.py").write_text(body, encoding="utf-8")
    return d


def test_unreferenced_lists_dead_handler_and_transitively_dead_outbound(tmp_path: Path) -> None:
    registry = load_config(_write_config(tmp_path, _LIVE_AND_DEAD))
    dead = build_reference_index(registry).unreferenced(registry)
    # h_dead is unreached from the inbound root; OB_DEAD is named only by h_dead → transitively dead.
    assert dead == [("handler", "h_dead"), ("outbound", "OB_DEAD")]


def test_referrers_reports_forward_edges_in_reverse(tmp_path: Path) -> None:
    idx = build_reference_index(load_config(_write_config(tmp_path, _LIVE_AND_DEAD)))
    assert Reference("inbound", "IB_LIVE", "router", "r_live") in idx.referrers("router", "r_live")
    assert Reference("router", "r_live", "handler", "h_live") in idx.referrers("handler", "h_live")
    assert Reference("handler", "h_live", "outbound", "OB_LIVE") in idx.referrers(
        "outbound", "OB_LIVE"
    )
    # The dead outbound's only referrer is the dead handler.
    assert idx.referrers("outbound", "OB_DEAD") == [
        Reference("handler", "h_dead", "outbound", "OB_DEAD")
    ]


def test_check_dead_config_is_advisory_and_names_the_dead(tmp_path: Path) -> None:
    result = _check_dead_config(_write_config(tmp_path, _LIVE_AND_DEAD))
    assert result.required is False and result.blocking is False  # advisory — never fails the gate
    assert result.ok is False
    assert "h_dead" in result.detail and "OB_DEAD" in result.detail


def test_check_dead_config_clean_when_all_reachable(tmp_path: Path) -> None:
    result = _check_dead_config(_write_config(tmp_path, _ALL_LIVE))
    assert result.ok is True and result.skipped is True
    assert "no dead config" in result.detail
