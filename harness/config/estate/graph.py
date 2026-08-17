# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Estate-shape system-under-test: a HETEROGENEOUS estate of N inbound MLLP connections (#216).

A ``MEFOR_ESTATE_SIMPLE_FRACTION`` majority are **simple** feeds (1 inbound → 1 outbound to the
correlation sink, 2 pipeline events per message); the rest are **hubs** (1 inbound → ``hub_fanout``
outbounds, ``1 + hub_fanout`` events per message). Each inbound has its own trivial code-first Router
(returns the one handler) → Handler (pass-through, optionally a whole-field ``edit``) → its outbound(s).
The graph is a **flat list of inbound()/outbound() registrations wired by name** — no bundling
"channel" object (CLAUDE.md §1) — and the router/handler logic stays code-first.

Which indices are simple vs hub is decided by :func:`harness.config.estate._shape.hub_flags` — the same
pure function the ``--estate`` driver imports — so the served fan-out and the driver's per-connection
rate calibration derive from ONE definition. Serve it on its own::

    MEFOR_ESTATE_COUNT=1500 MEFOR_ESTATE_SIMPLE_FRACTION=0.72 MEFOR_ESTATE_HUB_FANOUT=3 \
      python -m messagefoundry serve --config harness/config/estate --db ./estate.db

Every value here is synthetic and generic — no real partner, site, host, or volume. See
``docs/LOAD-TESTING.md``.
"""

from __future__ import annotations

from harness.config.estate._shape import EDIT, EstateShape, load_estate_shape
from messagefoundry import MLLP, Send, SetMeta, SetState, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.wiring import HandlerFn, RouterFn
from messagefoundry.parsing.message import Message, RawMessage

_SHAPE = load_estate_shape()

# A few attempts with brief backoff: the sink always AA's, so retries shouldn't fire — but a transient
# hiccup under heavy connection count should ride out rather than dead-letter and dirty the no-loss check.
_RETRY = RetryPolicy(
    max_attempts=5, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=5.0
)


def _apply_transform(
    msg: Message | RawMessage, shape: EstateShape, index: int
) -> Message | RawMessage:
    """Apply the configured transform cost. ``cheap`` returns the receipt unchanged (cheapest graph);
    ``edit`` rewrites representative whole fields via the Message model (never string slicing). MSH-10
    is left intact — the correlation sink matches on the control id, so every delivered copy must carry
    the same one it arrived with."""
    if shape.transform == EDIT and isinstance(msg, Message):
        msg["MSH-4"] = "MEFOR_ESTATE"  # sending facility
        msg["MSH-6"] = f"SINK_{index:05d}"  # receiving facility = this feed
    return msg


def _make_simple(dest: str, shape: EstateShape, index: int) -> HandlerFn:
    """A simple feed's handler: apply the (trivial) transform, deliver to its ONE outbound (2 events)."""

    def handle(msg: Message | RawMessage) -> Send:
        return Send(dest, _apply_transform(msg, shape, index))

    return handle


def _make_hub(dests: list[str], shape: EstateShape, index: int) -> HandlerFn:
    """A hub's handler: apply the (trivial) transform, FAN OUT to its ``len(dests)`` outbounds — one
    :class:`Send` per destination, so a received message produces ``1 + fanout`` events. Each handler
    runs on its own fresh parse of the raw, so the shared-``msg`` fan-out is isolated per routed row."""

    def handle(msg: Message | RawMessage) -> list[Send | SetState | SetMeta]:
        transformed = _apply_transform(msg, shape, index)
        # Typed to the Handler's element union (not bare ``list[Send]``) so the annotation states the
        # full contract. It is no longer required for assignability: since BACKLOG #341 ``HandlerFn``
        # returns an ``Iterable``, which is covariant, so a plain ``list[Send]`` would assign too.
        sends: list[Send | SetState | SetMeta] = [Send(dest, transformed) for dest in dests]
        return sends

    return handle


def _route_to(handler_name: str) -> RouterFn:
    """A trivial router: every received message goes to the one handler bound to this inbound."""

    def route(_msg: Message | RawMessage) -> list[str]:
        return [handler_name]

    return route


# Wire N independent inbound→router→handler→outbound(s) chains by name (a flat graph, no enclosing
# "channel" element). Conn i: IB_ES_{i} on base_port+i → R_ES_{i} → H_ES_{i} → its outbound(s) → sink.
# Simple conns register ONE outbound; hub conns register ``hub_fanout`` outbounds (each fanning across
# the contiguous sink port band via ``sink_endpoint``).
_HUB_FLAGS = _SHAPE.hub_flags()
for _i in range(_SHAPE.count):
    _is_hub = _HUB_FLAGS[_i]
    _fanout = _SHAPE.hub_fanout if _is_hub else 1
    _dests: list[str] = []
    for _j in range(_fanout):
        _dest = _SHAPE.conn_name("OB", _i, _j)
        _host, _port = _SHAPE.sink_endpoint(_i + _j)
        outbound(
            _dest,
            MLLP(host=_host, port=_port, connect_timeout=2.0, timeout_seconds=5.0),
            retry=_RETRY,
        )
        _dests.append(_dest)
    _hname = _SHAPE.conn_name("H", _i)
    if _is_hub:
        handler(_hname)(_make_hub(_dests, _SHAPE, _i))
    else:
        handler(_hname)(_make_simple(_dests[0], _SHAPE, _i))
    _rname = _SHAPE.conn_name("R", _i)
    router(_rname)(_route_to(_hname))
    inbound(_SHAPE.conn_name("IB", _i), MLLP(port=_SHAPE.base_port + _i), router=_rname)
