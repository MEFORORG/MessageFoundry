# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""N-active engine-shard CERTIFICATION system-under-test (ADR 0073).

N shard-tagged inbound hubs (one per shard) whose handlers deliver to the SAME shared pool of outbound
destinations — the OVERLAP the multishard/load graphs deliberately avoid. Served under N
``serve --shard <id>`` processes on ONE unified server store, each shared destination lane is
produced-into by every shard and drained by exactly ONE owner shard (ADR 0073 single delivery
consumer per outbound lane); a killed shard's owned lanes recover via the ownership-scoped startup
reset when the supervisor restarts it.

Three shape knobs that USED to be one (BACKLOG #209 — see ``_shape``): ``dests`` is TOPOLOGY (how many
shared outbound connections exist), ``handlers`` (H) is how many the router SELECTS, and ``delivering``
(D) is how many an accepted message actually DELIVERS to. They default to each other (H = D = dests = 8),
which is the graph as it was; splitting them is what lets the bench model a real ``H=20, D=4`` hub, where
16 selected handlers self-filter after already costing 2 transactions each. Serve it (all shards,
unsharded, for a smoke) as::

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
        # persistent=_SHAPE.persistent (default False) flips these from connect-per-delivery to the
        # ADR 0067 persistent connection for the sizing bench — off ⇒ byte-identical to today.
        MLLP(
            host=_host,
            port=_port,
            connect_timeout=2.0,
            timeout_seconds=5.0,
            persistent=_SHAPE.persistent,
        ),
        retry=_RETRY,
    )


def _make_handler(
    shape: ShardCertShape, shard: str, dest_index: int, lane_index: int | None = None
) -> HandlerFn:
    """A per-(shard, lane, destination) handler: transform + stamp the (shard, [lane,] dest) FIFO lane
    into MSH-6, then deliver to the SHARED destination. Each handler runs on its own fresh parse of the
    raw (one routed row per handler), so mutation is isolated. ``lane_index`` is ``None`` for the
    single-lane shape (key stays ``{shard}_{dest}``)."""
    dest = shared_dest_name(dest_index)

    def handle(msg: Message | RawMessage) -> Send:
        return Send(dest, apply_transform(msg, shape, shard, dest_index, lane_index))

    return handle


def _make_filtering_handler() -> HandlerFn:
    """A SELF-FILTERING handler (BACKLOG #209): the router selects it like any other, so it costs the FULL
    2 transactions — the routed-row claim plus a ``transform_handoff`` with ZERO deliveries — and produces
    no outbound row. That 2-txn-for-nothing is the quantity ``accepts=`` (ADR 0084) removes and this graph
    exists to make visible; a bench where every selected handler delivers cannot see it at all.

    It READS a field before declining, because a real hub's self-filtering handler decides on CONTENT
    (trigger event, patient class) — a handler that returned ``None`` without touching the message would
    understate the CPU a decliner actually costs."""

    def handle(msg: Message | RawMessage) -> None:
        if isinstance(msg, Message):
            _ = msg["MSH-9"]  # the trigger a real content filter branches on
        return None

    return handle


def _make_router(handler_names: list[str]) -> RouterFn:
    """BROADCAST: fan every received message to that shard's FULL handler set — including the self-filtering
    ones. Deliberately unconditional: the whole point of the H != D shape is that the router SELECTS ``H``
    handlers while only ``D`` of them deliver, so the ``2H`` cost is charged before any handler runs (ADR
    0051).

    This is ALSO the shape that caps the bench: every accepted message is delivered to EVERY destination, and
    an outbound lane is strict-FIFO hard-1, so every lane must serve every message and the per-lane cycle
    clamps INGRESS to one message per cycle (~16 msg/s) at ANY destination count. See ``partitioned``."""

    def route(msg: Message | RawMessage) -> list[str]:
        return handler_names

    return route


def _make_partitioned_router(handler_names: list[str], shape: ShardCertShape) -> RouterFn:
    """PARTITIONED: select EXACTLY ONE handler — the one owning destination ``splitmix64(seq) % dests``,
    where ``seq`` is the harness sequence number carried in MSH-10.

    This is the whole mode. Delivery is UNCHANGED (the same ``dests`` lanes, the same strict-FIFO per-lane
    cycle); what changes is that a message now occupies ONE lane instead of all of them, so the per-lane cycle
    no longer clamps ingress — aggregate deliveries scale with the lane count, and ingress == aggregate
    deliveries because each message IS exactly one delivery.

    The selector MIXES the seq rather than taking it modulo ``dests`` directly, and that is not decoration:
    the sender's connection round-robin is driven by the SAME counter, so a bare modulo would leave each
    destination lane produced-into by exactly ONE shard — destroying the cross-shard lane overlap this whole
    graph exists to certify (see the module docstring above and
    :meth:`~harness.config.shardcert._shape.ShardCertShape.destination_index`).

    ``handler_names[j]`` owns destination ``j`` (:meth:`ShardCertShape.delivers_to` returns ``j`` for every
    created handler under PARTITIONED, and :func:`load_shape` pins ``H == D == dests``), so indexing the name
    list by the destination index is exactly "route to the handler that owns this destination".

    :meth:`~ShardCertShape.destination_index` RAISES on a message whose control id does not decode — the
    router does not catch it. That is deliberate: a silent fallback to destination 0 would funnel every
    message onto a single FIFO lane and fabricate the very ~16 msg/s plateau this mode exists to disprove,
    while still reporting a clean PASS. Raising sends the message down the engine's error/dead-letter path,
    which breaks the sink no-loss identity and voids the run LOUDLY."""

    def route(msg: Message | RawMessage) -> list[str]:
        return [handler_names[shape.destination_index(msg)]]

    return route


def _make_partitioned_fanout_router(handler_names: list[str], shape: ShardCertShape) -> RouterFn:
    """PARTITIONED-FANOUT: select ``D`` (== ``fanout`` == ``delivering``) DISTINCT owner handlers — the ones
    owning the D distinct destinations :meth:`ShardCertShape.destination_indices` draws from the MSH-10
    sequence number.

    Same high-ingress partition scaling as :func:`_make_partitioned_router` (a message still occupies only
    D of the ``dests`` lanes, not all of them), but delivers D copies instead of 1 — the shape the D≈4
    certification soak needs to drive ingress ~= dests/(D*cycle) at events/msg = 1 + D.

    ``handler_names[j]`` owns destination ``j`` (:meth:`ShardCertShape.delivers_to` returns ``j`` for every
    built handler under any partitioned mode; :func:`load_shape` pins ``H == dests``), so the D DISTINCT
    dest indices map to D DISTINCT owner handlers → D deliveries, never the same lane twice.

    :meth:`destination_indices` RAISES on an undecodable control id and the router does NOT catch it — a
    silent dest-0 fallback would funnel traffic onto one lane and fabricate the ~16 msg/s plateau this mode
    exists to disprove, while still reporting a clean PASS. Raising voids the run LOUDLY."""

    def route(msg: Message | RawMessage) -> list[str]:
        return [handler_names[i] for i in shape.destination_indices(msg)]

    return route


# For each shard: ``lanes_per_shard`` DISTINCT inbound→router→handler chains (one fat lane by default),
# each on a contiguous port, each with ``handlers`` (H) handlers the router selects unconditionally. The
# lane index is folded into the connection / router / handler names AND the MSH-6 FIFO lane key so
# many-thin-lanes keep per-lane FIFO accounting. With lanes_per_shard == 1 the suffix/lane index vanish →
# byte-identical to the single-lane graph.
#
# BACKLOG #209: the loop iterates HANDLERS (H), not dests, and names by HANDLER index. Handler ``j``
# delivers to destination ``j`` while ``j < delivering`` (D) and SELF-FILTERS beyond it. At the default
# H = D = dests every handler delivers and the names are unchanged (H_a_00..H_a_07) — no published run
# moves. At H=20/D=4 the graph finally expresses the reference ADT hub: 20 routed rows, 4 delivered.
_LANES = _SHAPE.lanes_per_shard
for _i, _shard in enumerate(_SHAPE.shards):
    for _l in range(_LANES):
        _suffix = "" if _LANES == 1 else f"_L{_l:02d}"
        _lane_index = None if _LANES == 1 else _l
        _handler_names: list[str] = []
        for _j in range(_SHAPE.handlers):
            _hname = f"H_{_shard}{_suffix}_{_j:02d}"
            _dest_index = _SHAPE.delivers_to(_j)
            if _dest_index is None:
                handler(_hname)(_make_filtering_handler())
            else:
                handler(_hname)(_make_handler(_SHAPE, _shard, _dest_index, _lane_index))
            _handler_names.append(_hname)
        _rname = f"route_{_shard}{_suffix}"
        # BROADCAST (default) selects every handler; PARTITIONED selects the ONE owning dest `seq % dests`;
        # PARTITIONED-FANOUT selects the D DISTINCT owners of `destination_indices(seq)`. Under either
        # partitioned mode load_shape pins H == dests, so `_handler_names` has exactly one owner per
        # destination and NO self-filtering handler was built above (delivers_to returns j for every j).
        if _SHAPE.partitioned_fanout:
            router(_rname)(_make_partitioned_fanout_router(_handler_names, _SHAPE))
        elif _SHAPE.partitioned:
            router(_rname)(_make_partitioned_router(_handler_names, _SHAPE))
        else:
            router(_rname)(_make_router(_handler_names))
        inbound(
            f"IB_S_{_shard}{_suffix}",
            MLLP(port=_SHAPE.inbound_port(_i, _l)),
            router=_rname,
            shard=_shard,
        )
