# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pass-through (PT) re-ingress system-under-test (§7 S7.4/S7.5).

A minimal graph exercising the ADR 0013 (generalized) **pass-through** primitive: an MLLP entry hub
routes every message to a handler that ``Send``\\ s it *into* an internal :func:`PassThrough` inbound
(``PT_Relay``) — naming it like an outbound. The engine re-ingresses that body as a new, independent
inbound message on ``PT_Relay``, whose **own** router/handler then forward it to the real outbound
(the harness correlation sink). So one logical feed crosses an internal hop before delivery, with no
external round-trip — the shape the PT re-ingress throughput rows measure.

Synthetic + generic; reuses the load graph's ``_shape`` for the entry port and sink endpoint, so
``MEFOR_LOAD_ADT_PORT`` / ``MEFOR_LOAD_SINK_PORT`` behave as in ``harness/config/load``. Serve it::

    MEFOR_LOAD_ADT_PORT=2600 MEFOR_LOAD_SINK_PORT=2700 \
      python -m messagefoundry serve --config harness/config/passthrough --db ./pt.db
"""

from __future__ import annotations

from messagefoundry import MLLP, PassThrough, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.parsing.message import Message, RawMessage

from harness.config.load._shape import load_shape

_SHAPE = load_shape()

_RETRY = RetryPolicy(
    max_attempts=5, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=5.0
)

# The real egress: one outbound delivering to the harness correlation sink.
_SINK_HOST, _SINK_PORT = _SHAPE.sink_endpoint(0)
outbound(
    "OB_PT_Sink",
    MLLP(host=_SINK_HOST, port=_SINK_PORT, connect_timeout=2.0, timeout_seconds=5.0),
    retry=_RETRY,
)

# The entry hub: an external MLLP inbound whose handler hands every message off to the PT inbound.
inbound("IB_PT_Entry", MLLP(port=_SHAPE.adt_port), router="pt_entry_router")

# The internal pass-through inbound: no socket; fed only by the Send-into-PT handoff below. Its own
# router/handler re-route the re-ingressed body to the real sink outbound.
inbound("PT_Relay", PassThrough(), router="pt_relay_router")


@router("pt_entry_router")
def route_entry(msg: Message | RawMessage) -> list[str]:
    return ["pt_entry_handler"]


@handler("pt_entry_handler")
def to_passthrough(msg: Message | RawMessage) -> Send:
    # Send INTO the PT inbound (named like an outbound) → the engine re-ingresses it on PT_Relay.
    return Send("PT_Relay", msg)


@router("pt_relay_router")
def route_relay(msg: Message | RawMessage) -> list[str]:
    return ["pt_relay_handler"]


@handler("pt_relay_handler")
def to_sink(msg: Message | RawMessage) -> Send:
    # The PT inbound's own handler forwards the re-ingressed body to the real outbound.
    return Send("OB_PT_Sink", msg)
