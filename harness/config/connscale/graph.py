# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Connection-scale system-under-test: N inbound MLLP connections, each a trivial route → handler →
one outbound to the correlation sink (B11).

Where ``harness/config/load`` models a high-FAN-OUT estate (3 hubs each fanning to many outbounds),
this models a high-CONNECTION-COUNT estate: ``MEFOR_CONNSCALE_COUNT`` inbound MLLP listeners, each
with its own trivial Router (returns the one handler) → Handler (filter-free pass-through, optionally
a representative whole-field ``edit``) → one outbound delivering to the harness correlation sink. The
graph is a **flat list of inbound()/outbound() registrations wired by name** — no bundling "channel"
object (CLAUDE.md §1) — and the router/handler logic stays code-first.

The connection-scale harness sets ``MEFOR_CONNSCALE_COUNT=N`` (+ the matching base/sink env) in the
engine subprocess environment before each sweep step, so this ONE graph file serves 500 / 1000 / 1500
(and the CI smoke's 50 / 100) by env alone — no per-N file generation. The trivial route+handler keep
the measured cost the engine's *per-connection machinery* (workers, wake events, pool, executor hops),
not transform CPU. Serve it on its own::

    MEFOR_CONNSCALE_COUNT=500 MEFOR_CONNSCALE_BASE_PORT=2600 MEFOR_CONNSCALE_SINK_PORT=2700 \
      python -m messagefoundry serve --config harness/config/connscale --db ./connscale.db

Every value here is synthetic and generic — no real partner, site, host, or volume. See
``docs/LOAD-TESTING.md``.
"""

from __future__ import annotations

from messagefoundry import MLLP, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.wiring import HandlerFn, RouterFn
from messagefoundry.parsing.message import Message, RawMessage

from harness.config.connscale._shape import EDIT, ConnScaleShape, load_connscale_shape

_SHAPE = load_connscale_shape()

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


# Wire N independent inbound→router→handler→outbound chains by name (a flat graph, no enclosing
# "channel" element). Conn i: IB_CS_{i} on base_port+i → R_CS_{i} → H_CS_{i} → OB_CS_{i} → the sink.
for _i in range(_SHAPE.count):
    _dest = f"OB_CS_{_i:05d}"
    _host, _port = _SHAPE.sink_endpoint(_i)
    outbound(
        _dest,
        MLLP(host=_host, port=_port, connect_timeout=2.0, timeout_seconds=5.0),
        retry=_RETRY,
    )
    _hname = f"H_CS_{_i:05d}"
    handler(_hname)(_make_passthrough(_dest, _SHAPE, _i))
    _rname = f"R_CS_{_i:05d}"
    router(_rname)(_route_to(_hname))
    inbound(f"IB_CS_{_i:05d}", MLLP(port=_SHAPE.base_port + _i), router=_rname)
