# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""N-active engine-shard CERTIFICATION system-under-test (ADR 0073).

N shard-tagged inbound hubs (one per shard) whose handlers ALL deliver to the SAME shared pool of
outbound destinations — the OVERLAP the multishard/load graphs deliberately avoid. Served under N
``serve --shard <id>`` processes on ONE unified server store, each shared destination lane is
produced-into by every shard and drained by exactly ONE owner shard (ADR 0073 single delivery
consumer per outbound lane); a killed shard's owned lanes recover via the ownership-scoped startup
reset when the supervisor restarts it. Serve it (all shards, unsharded, for a smoke) as::

    MEFOR_SHARDCERT_SHARDS=a,b,c,d MEFOR_SHARDCERT_SINK_PORT=3700 \
      python -m messagefoundry serve --config harness/config/shardcert --db ./shardcert.db

or one shard against a server store::

    MEFOR_STORE_BACKEND=sqlserver ... \
      python -m messagefoundry serve --config harness/config/shardcert --shard a --port 8801

Every value here is synthetic and generic — no real partner, site, host, or volume.
"""

from __future__ import annotations

from messagefoundry import MLLP, Send, handler, inbound, outbound, router
from messagefoundry.config.models import RetryPolicy
from messagefoundry.config.wiring import HandlerFn, RouterFn
from messagefoundry.parsing.message import Message, RawMessage

from harness.config.shardcert._shape import (
    ShardCertShape,
    apply_transform,
    load_shape,
    shared_dest_name,
)

_SHAPE = load_shape()

# A few attempts with brief backoff: the sink always AA's, so retries shouldn't fire — but a transient
# hiccup under heavy load should ride out rather than dead-letter and dirty the no-loss check.
_RETRY = RetryPolicy(
    max_attempts=5, backoff_seconds=0.5, backoff_multiplier=2.0, max_backoff_seconds=5.0
)


# One SHARED pool of outbound destinations — declared ONCE, every shard's handlers Send to these, so
# each destination lane overlaps across shards (the single-consumer invariant is exercised only when a
# lane is produced-into by more than one shard). Each delivers to the correlation sink.
for _d in range(_SHAPE.dests):
    _host, _port = _SHAPE.sink_endpoint(_d)
    outbound(
        shared_dest_name(_d),
        MLLP(host=_host, port=_port, connect_timeout=2.0, timeout_seconds=5.0),
        retry=_RETRY,
    )


def _make_handler(shape: ShardCertShape, shard: str, dest_index: int) -> HandlerFn:
    """A per-(shard, destination) handler: transform + stamp the (shard,dest) FIFO lane into MSH-6, then
    deliver to the SHARED destination. Each handler runs on its own fresh parse of the raw (one routed
    row per handler), so mutation is isolated."""
    dest = shared_dest_name(dest_index)

    def handle(msg: Message | RawMessage) -> Send:
        return Send(dest, apply_transform(msg, shape, shard, dest_index))

    return handle


def _make_router(handler_names: list[str]) -> RouterFn:
    """A shard's router: fan every received message to that shard's full handler set (one per shared
    destination)."""

    def route(msg: Message | RawMessage) -> list[str]:
        return handler_names

    return route


# For each shard: one inbound tagged shard=<id> on a contiguous port, plus a handler per shared
# destination (so the shard fans every message to ALL shared destinations = maximal overlap), and a
# router fanning to that shard's handlers.
for _i, _shard in enumerate(_SHAPE.shards):
    _handler_names: list[str] = []
    for _d in range(_SHAPE.dests):
        _hname = f"H_{_shard}_{_d:02d}"
        handler(_hname)(_make_handler(_SHAPE, _shard, _d))
        _handler_names.append(_hname)
    _rname = f"route_{_shard}"
    router(_rname)(_make_router(_handler_names))
    inbound(
        f"IB_S_{_shard}",
        MLLP(port=_SHAPE.inbound_port(_i)),
        router=_rname,
        shard=_shard,
    )
