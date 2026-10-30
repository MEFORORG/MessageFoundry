# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Wire the connection-scale graph for one :class:`ConnScaleShape` (B11).

The loader skips ``_*`` modules, so this is imported, never loaded as config. Two config modules
call it: :mod:`harness.config.connscale.graph`, which reads the shape from ``MEFOR_CONNSCALE_*``, and
the module the connscale runner generates per sweep step with the shape written in as literals
(``harness.load.connscale.stepconfig``, BACKLOG #3132). One wiring, so the two routes cannot build
different graphs for the same shape.

Each of the N inbounds gets its own trivial Router (returns the one handler) -> Handler (filter-free
pass-through, optionally a representative whole-field ``edit``) -> one outbound delivering to the
harness correlation sink. A flat list of registrations wired by name, with no bundling "channel"
object (CLAUDE.md section 1). Every value is synthetic and generic.
"""

from __future__ import annotations

from harness.config.connscale._shape import EDIT, ConnScaleShape
from messagefoundry import MLLP, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.wiring import HandlerFn, RouterFn
from messagefoundry.parsing.message import Message, RawMessage

# A few attempts with brief backoff: the sink always AA's, so retries shouldn't fire — but a transient
# hiccup under heavy connection count should ride out rather than dead-letter and dirty the no-loss check.
_RETRY = RetryPolicy(
    max_attempts=5, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=5.0
)


def _apply_transform(
    msg: Message | RawMessage, shape: ConnScaleShape, index: int
) -> Message | RawMessage:
    """Apply the configured transform cost. ``cheap`` returns the receipt unchanged (cheapest graph);
    ``edit`` rewrites representative whole fields via the Message model (never string slicing). MSH-10
    is left intact — the correlation sink matches on the control id, so the delivered copy must carry
    the same one it arrived with."""
    if shape.transform == EDIT and isinstance(msg, Message):
        msg["MSH-4"] = "MEFOR_CONNSCALE"  # sending facility
        msg["MSH-6"] = f"SINK_{index:05d}"  # receiving facility = this destination
    return msg


def _make_passthrough(dest: str, shape: ConnScaleShape, index: int) -> HandlerFn:
    """A per-connection handler: apply the (trivial) transform, deliver to its own outbound. Each
    handler runs on its own fresh parse of the raw (one routed row per handler), so mutation is
    isolated."""

    def handle(msg: Message | RawMessage) -> Send:
        return Send(dest, _apply_transform(msg, shape, index))

    return handle


def _route_to(handler_name: str) -> RouterFn:
    """A trivial router: every received message goes to the one handler bound to this inbound."""

    def route(_msg: Message | RawMessage) -> list[str]:
        return [handler_name]

    return route


def wire_graph(shape: ConnScaleShape) -> None:
    """Register N independent inbound->router->handler->outbound chains by name. Conn i: IB_CS_{i}
    on base_port+i -> R_CS_{i} -> H_CS_{i} -> OB_CS_{i} -> the sink. Names run through
    ``ConnScaleShape.conn_name``, so a per-engine name prefix gives each engine DISTINCT names on a
    shared store (disjoint FIFO lanes); an empty prefix is byte-identical to the historical
    single-engine names."""
    for i in range(shape.count):
        dest = shape.conn_name("OB", i)
        host, port = shape.sink_endpoint(i)
        outbound(
            dest,
            MLLP(host=host, port=port, connect_timeout=2.0, timeout_seconds=5.0),
            retry=_RETRY,
        )
        hname = shape.conn_name("H", i)
        handler(hname)(_make_passthrough(dest, shape, i))
        rname = shape.conn_name("R", i)
        router(rname)(_route_to(hname))
        inbound(shape.conn_name("IB", i), MLLP(port=shape.base_port + i), router=rname)
