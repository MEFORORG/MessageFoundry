# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Estate-shape SUT graph (#216) — the HETEROGENEOUS N-inbound code-first graph: a majority of simple
1-in-1-out feeds + a minority of fan-out hubs, desugared through the SAME inbound()/outbound() factories
into a flat endpoint list (no "channel" element). The topology split is by CONNECTION COUNT, decided by
the pure ``hub_flags`` the driver also imports — independent of any traffic."""

from __future__ import annotations

import re

import pytest

from harness.config.estate._shape import (
    events_per_msg,
    hub_flags,
    load_estate_shape,
    simple_count,
)
from messagefoundry.config.wiring import load_config

_OB_RE = re.compile(r"^OB_ES_(\d{5})_(\d{2})$")


def _outbounds_by_index(reg: object) -> dict[int, int]:
    """Group the registered outbound connections by their owning connection index → fan-out count."""
    counts: dict[int, int] = {}
    for name in reg.outbound:  # type: ignore[attr-defined]
        m = _OB_RE.match(name)
        assert m is not None, f"unexpected outbound name {name!r}"
        idx = int(m.group(1))
        counts[idx] = counts.get(idx, 0) + 1
    return counts


# --------------------------------------------------------------------------- #
# Pure topology math — the headline 1,500-conn split, by connection COUNT (not traffic)
# --------------------------------------------------------------------------- #


def test_topology_split_by_connection_count_at_1500() -> None:
    # 1,500 connections, 72% simple → EXACTLY 1,080 simple / 420 hub, decided by count, not traffic.
    flags = hub_flags(1500, 0.72)
    assert len(flags) == 1500
    n_hub = sum(flags)
    n_simple = len(flags) - n_hub
    assert n_simple == 1080
    assert n_hub == 420
    assert simple_count(1500, 0.72) == 1080
    # Contiguous + reproducible: indices [0, 1080) simple, the rest hubs (so the graph process and the
    # driver process agree without sharing a seed).
    assert flags[:1080] == (False,) * 1080
    assert flags[1080:] == (True,) * 420


def test_events_per_msg_and_events_sum() -> None:
    fanout = 3
    # Simple = 1 in + 1 out = 2 events; hub = 1 in + F out = 1 + F events.
    assert events_per_msg(False, fanout) == 2
    assert events_per_msg(True, fanout) == 1 + fanout
    # The derived events-per-message SUM over the estate: 1080·2 + 420·(1+3).
    flags = hub_flags(1500, 0.72)
    total_events_per_pass = sum(events_per_msg(f, fanout) for f in flags)
    assert total_events_per_pass == 1080 * 2 + 420 * (1 + fanout)


@pytest.mark.parametrize(
    "count, fraction, expected_simple",
    [
        (100, 0.72, 72),
        (100, 1.0, 100),  # all simple
        (100, 0.0, 0),  # all hub
        (10, 0.5, 5),
        (7, 0.72, 5),  # round(5.04) = 5
    ],
)
def test_simple_count_rounds_and_clamps(count: int, fraction: float, expected_simple: int) -> None:
    assert simple_count(count, fraction) == expected_simple
    assert sum(hub_flags(count, fraction)) == count - expected_simple


# --------------------------------------------------------------------------- #
# The ACTUAL loaded graph — simple conns register 1 outbound, hubs register F
# --------------------------------------------------------------------------- #


def test_loaded_graph_wires_simple_and_hub_outbounds(monkeypatch: pytest.MonkeyPatch) -> None:
    # A moderate count with both classes present: 25 conns, 72% simple → 18 simple / 7 hub, fan-out 3.
    monkeypatch.setenv("MEFOR_ESTATE_COUNT", "25")
    monkeypatch.setenv("MEFOR_ESTATE_SIMPLE_FRACTION", "0.72")
    monkeypatch.setenv("MEFOR_ESTATE_HUB_FANOUT", "3")
    monkeypatch.setenv("MEFOR_ESTATE_BASE_PORT", "2600")
    monkeypatch.setenv("MEFOR_ESTATE_SINK_PORT", "2700")
    reg = load_config("harness/config/estate")

    assert len(reg.inbound) == 25
    assert len(reg.routers) == 25
    assert len(reg.handlers) == 25

    by_index = _outbounds_by_index(reg)
    assert len(by_index) == 25  # every inbound owns at least one outbound
    simple = [i for i, n in by_index.items() if n == 1]
    hub = [i for i, n in by_index.items() if n == 3]
    # The split is by CONNECTION COUNT: 18 simple (1 outbound each) + 7 hub (3 outbounds each).
    assert len(simple) == 18
    assert len(hub) == 7
    # No connection has an unexpected fan-out (only 1 or 3 here).
    assert set(by_index.values()) == {1, 3}
    # Total outbound registrations = 18·1 + 7·3.
    assert len(reg.outbound) == 18 * 1 + 7 * 3
    # Each inbound binds base_port + i; a flat graph wired by name (no bundling).
    ports = sorted(c.spec.settings.get("port") for c in reg.inbound.values())
    assert ports == list(range(2600, 2625))


def test_all_simple_when_fraction_is_one(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ESTATE_COUNT", "8")
    monkeypatch.setenv("MEFOR_ESTATE_SIMPLE_FRACTION", "1.0")
    monkeypatch.setenv("MEFOR_ESTATE_HUB_FANOUT", "4")
    reg = load_config("harness/config/estate")
    by_index = _outbounds_by_index(reg)
    assert set(by_index.values()) == {1}  # every connection is simple → 1 outbound each
    assert len(reg.outbound) == 8


def test_edit_transform_is_optional(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ESTATE_COUNT", "4")
    monkeypatch.setenv("MEFOR_ESTATE_TRANSFORM", "edit")
    reg = load_config("harness/config/estate")
    assert len(reg.handlers) == 4  # loads with the edit transform branch active


# --------------------------------------------------------------------------- #
# Fail-loud shape guards (in _shape, before any listener binds)
# --------------------------------------------------------------------------- #


def test_shape_fails_loud_on_port_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ESTATE_COUNT", "200")
    monkeypatch.setenv("MEFOR_ESTATE_BASE_PORT", "2650")
    monkeypatch.setenv("MEFOR_ESTATE_SINK_PORT", "2700")  # 2700 is inside [2650, 2849]
    with pytest.raises(ValueError, match="overlaps the sink port range"):
        load_estate_shape()


def test_shape_fails_loud_past_port_space(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ESTATE_COUNT", "200")
    monkeypatch.setenv("MEFOR_ESTATE_BASE_PORT", "65500")
    with pytest.raises(ValueError, match="past port 65535"):
        load_estate_shape()


def test_shape_fails_loud_on_out_of_range_fraction(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_ESTATE_SIMPLE_FRACTION", "1.5")
    with pytest.raises(ValueError, match="within"):
        load_estate_shape()
