# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The pass-through (PT) re-ingress SUT graph (``harness/config/passthrough``).

Verifies the §7 S7.4/S7.5 shape: an external MLLP entry hub whose handler ``Send``\\ s every message
INTO an internal :func:`PassThrough` inbound, which carries its own router/handler forwarding to a real
outbound (the harness sink). Asserts the graph loads + validates (entry inbound + PT inbound + both
handlers) and that a dry-run of the entry inbound yields a Send into the PT connector (an
``is_passthrough`` delivery), i.e. the re-ingress handoff is wired.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import load_config
from messagefoundry.generators import _core, all_types  # noqa: F401  (registers message types)
from messagefoundry.pipeline.dryrun import dry_run

_CONFIG = "harness/config/passthrough"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "MEFOR_LOAD_FANOUT",
        "MEFOR_LOAD_SINK_HOST",
        "MEFOR_LOAD_SINK_PORT",
        "MEFOR_LOAD_SINK_PORTS",
        "MEFOR_LOAD_ADT_PORT",
    ):
        monkeypatch.delenv(key, raising=False)


def test_graph_loads_entry_and_pt_inbounds() -> None:
    reg = load_config(_CONFIG)
    reg.validate()
    assert set(reg.inbound) == {"IB_PT_Entry", "PT_Relay"}
    assert set(reg.handlers) == {"pt_entry_handler", "pt_relay_handler"}
    assert "OB_PT_Sink" in reg.outbound
    # The internal inbound is a real pass-through connector (no listener).
    assert reg.inbound["PT_Relay"].spec.type is ConnectorType.PT


def test_entry_dry_run_sends_into_the_pt_connector() -> None:
    reg = load_config(_CONFIG)
    result = dry_run(reg, _core.generate_message("ADT", "A01", 1), inbound="IB_PT_Entry")
    # The entry handler hands off to the PT inbound (named like an outbound) — one delivery, flagged
    # as a pass-through re-ingress (not a terminal outbound delivery).
    assert len(result.deliveries) == 1
    delivery = result.deliveries[0]
    assert delivery.to == "PT_Relay"
    assert delivery.is_passthrough


def test_pt_relay_router_forwards_to_the_sink() -> None:
    # The PT inbound's OWN router/handler forward the re-ingressed body to the real outbound. Dry-run
    # the PT inbound directly to confirm its half of the graph terminates at the sink.
    reg = load_config(_CONFIG)
    result = dry_run(reg, _core.generate_message("ADT", "A01", 1), inbound="PT_Relay")
    assert len(result.deliveries) == 1
    assert result.deliveries[0].to == "OB_PT_Sink"
    assert not result.deliveries[0].is_passthrough  # terminal outbound delivery
