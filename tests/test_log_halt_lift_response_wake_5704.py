# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Lifting the #122 log halt on a per_lane inbound wakes a RESPONSE lane only for a loopback
inbound (vault BACKLOG #5704 items 26 and 68).

Only a loopback inbound runs a RESPONSE worker (ADR 0013). ``_lift_log_halt`` woke the RESPONSE
lane of every inbound it lifted. With per-lane wake on, ``_lane_event`` is get-or-create, so each
non-loopback lift left a stray Event in ``_lane_events[RESPONSE]``; with it off, the shared
RESPONSE singleton was set and woke every loopback response worker for nothing.
"""

from __future__ import annotations

import asyncio

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection
from messagefoundry.store import MessageStore
from messagefoundry.store.store import Stage
from tests.test_log_write_guard import INBOUND, _graph, _RecordingSink, store  # noqa: F401

_LOOP = "IB_TEST_LOOP"


async def test_a_lift_on_a_non_loopback_inbound_leaves_no_response_event(
    store: MessageStore,  # noqa: F811
) -> None:
    runner, _source = _graph(store, _RecordingSink())
    runner._claim_mode = "per_lane"
    runner._per_lane_wake = True
    runner._log_halted.add(INBOUND)

    runner._lift_log_halt(INBOUND)

    assert INBOUND not in runner._log_halted
    assert INBOUND not in runner._lane_events[Stage.RESPONSE]
    # The stages it does run are still woken.
    assert runner._lane_events[Stage.INGRESS][INBOUND].is_set()
    assert runner._lane_events[Stage.ROUTED][INBOUND].is_set()


async def test_a_lift_on_a_non_loopback_inbound_leaves_the_response_singleton_unset(
    store: MessageStore,  # noqa: F811
) -> None:
    runner, _source = _graph(store, _RecordingSink())
    runner._claim_mode = "per_lane"
    runner._per_lane_wake = False
    runner._log_halted.add(INBOUND)

    runner._lift_log_halt(INBOUND)

    assert not runner._singleton_for_stage[Stage.RESPONSE].is_set()
    assert runner._singleton_for_stage[Stage.ROUTED].is_set()


async def test_a_lift_on_a_loopback_inbound_wakes_its_response_lane(
    store: MessageStore,  # noqa: F811
) -> None:
    runner, _source = _graph(store, _RecordingSink())
    runner.registry.add_inbound(
        InboundConnection(_LOOP, ConnectionSpec(ConnectorType.LOOPBACK, {}), router="r")
    )
    runner._claim_mode = "per_lane"
    runner._per_lane_wake = True
    runner._log_halted.add(_LOOP)

    runner._lift_log_halt(_LOOP)

    event = runner._lane_events[Stage.RESPONSE].get(_LOOP)
    assert isinstance(event, asyncio.Event) and event.is_set()
