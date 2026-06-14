"""Synthetic high-fan-out system-under-test for load testing.

Models the *shape* of a large integration estate — one big ADT hub plus results/orders hubs, each
fanning every received message out to many outbound connections that all deliver to the harness
correlation sink. The fan-out factor and per-transform cost are env-tunable (see :mod:`_shape`), so
one graph spans a cheap pass-through run and a transform-bound ceiling run. Serve it on its own::

    # SQLite (smoke/dev); swap --db for the Postgres scale-out comparison
    MEFOR_LOAD_FANOUT=20 MEFOR_LOAD_TRANSFORM=edit MEFOR_LOAD_SINK_PORT=2700 \
      python -m messagefoundry serve --config harness/config/load --db ./load.db

Every value here is synthetic and generic — no real partner, site, host, or volume. Each hub routes
**every** message it receives to its lane's handlers (the load sender pre-partitions message types to
the matching hub port), so received traffic is delivered, not filtered — keeping end-to-end
correlation clean. See ``docs/LOAD-TESTING.md``.
"""

from __future__ import annotations

from messagefoundry import MLLP, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.wiring import HandlerFn
from messagefoundry.parsing.message import Message, RawMessage

from harness.config.load._shape import Shape, apply_transform, load_shape

_SHAPE = load_shape()

# A few attempts with brief backoff: the sink always AA's, so retries shouldn't fire — but a transient
# hiccup under heavy load should ride out rather than dead-letter and dirty the no-loss check.
_RETRY = RetryPolicy(
    max_attempts=5, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=5.0
)


def _make_handler(dest: str, shape: Shape, lane: str, index: int) -> HandlerFn:
    """A per-destination handler: apply the transform cost, deliver to its own outbound. Each handler
    runs on its own fresh parse of the raw (one routed row per handler), so mutation is isolated."""

    def handle(msg: Message | RawMessage) -> Send:
        return Send(dest, apply_transform(msg, shape, lane, index))

    return handle


def _register_lane(lane: str, fanout: int, shape: Shape) -> list[str]:
    """Declare ``fanout`` outbound destinations (all → the sink) and a handler feeding each. Returns
    the handler names for the lane's router to fan to."""
    handler_names: list[str] = []
    for i in range(fanout):
        dest = f"OB_Sink_{lane}_{i:02d}"
        host, port = shape.sink_endpoint(i)
        outbound(
            dest,
            MLLP(host=host, port=port, connect_timeout=2.0, timeout_seconds=5.0),
            retry=_RETRY,
        )
        name = f"H_{lane}_{i:02d}"
        handler(name)(_make_handler(dest, shape, lane, i))
        handler_names.append(name)
    return handler_names


_ADT_HANDLERS = _register_lane("ADT", _SHAPE.fanout, _SHAPE)
_RES_HANDLERS = _register_lane("RES", _SHAPE.results_fanout, _SHAPE)
_OTH_HANDLERS = _register_lane("OTH", _SHAPE.results_fanout, _SHAPE)


# Three inbound MLLP hubs matching the load profiles' target ports. Each fans every received message
# to its lane's full handler set (the sender sends only the matching types to each port).
inbound("IB_Load_ADT", MLLP(port=_SHAPE.adt_port), router="adt_router")
inbound("IB_Load_Results", MLLP(port=_SHAPE.results_port), router="results_router")
inbound("IB_Load_Other", MLLP(port=_SHAPE.other_port), router="other_router")


@router("adt_router")
def route_adt(msg: Message | RawMessage) -> list[str]:
    return _ADT_HANDLERS


@router("results_router")
def route_results(msg: Message | RawMessage) -> list[str]:
    return _RES_HANDLERS


@router("other_router")
def route_other(msg: Message | RawMessage) -> list[str]:
    return _OTH_HANDLERS
