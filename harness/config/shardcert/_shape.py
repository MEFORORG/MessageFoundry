# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shape parameters for the N-active engine-shard CERTIFICATION graph (ADR 0073).

Loader skips ``_*`` modules, so this is *imported* by :mod:`graph`, not loaded as config. It models a
sharded estate whose distinguishing feature — the thing the multishard/load graphs deliberately avoid
(disjoint lanes) — is **OVERLAPPING outbound destinations across shards**: every shard's inbound fans
every received message to the SAME shared pool of outbound destinations. On one unified store that
means each destination lane is produced-into by all shards and (post-ADR-0073) drained by exactly ONE
owner shard (`owner_shard_of_destination`). Serving this graph under N ``serve --shard`` processes on
one server store is what exercises the single-delivery-consumer-per-outbound-lane invariant and the
ownership-scoped crash recovery.

Knobs (all optional; safe defaults so a plain ``serve`` works):

* ``MEFOR_SHARDCERT_SHARDS``       — comma list of shard ids (default ``a,b,c,d``). Shard ``i`` (sorted)
  owns inbound ``IB_S_<id>`` on ``inbound_base + i`` (one lane) or ``IB_S_<id>_L<l>`` on
  ``inbound_base + i*lanes + l`` (many lanes).
* ``MEFOR_SHARDCERT_INBOUND_BASE`` — first inbound MLLP port; lane ``l`` of shard ``i`` binds
  ``base + i*lanes_per_shard + l`` (default 3600), so the ``N*lanes`` ports stay contiguous.
* ``MEFOR_SHARDCERT_LANES_PER_SHARD`` — inbound→router→handler chains PER shard (default 1 = one fat
  lane, byte-identical to today). ``C>1`` gives ``N*C`` many-thin-lanes (distinct inbound + port each);
  the MSH-6 FIFO lane key gains the lane index so per-lane FIFO/inversion accounting stays meaningful.
* ``MEFOR_SHARDCERT_DESTS``        — count of SHARED outbound destinations every shard sends to (default 4).
* ``MEFOR_SHARDCERT_SINK_HOST``    — sink host every destination delivers to (default 127.0.0.1).
* ``MEFOR_SHARDCERT_SINK_PORT``    — base sink port (default 3700).
* ``MEFOR_SHARDCERT_SINK_PORTS``   — contiguous sink ports to round-robin across (default 1).
* ``MEFOR_SHARDCERT_TRANSFORM``    — ``cheap`` | ``edit`` (default ``edit``; ``edit`` stamps MSH-6, the
  per-(source-shard, destination) FIFO lane key the sink/tracker read).
* ``MEFOR_SHARDCERT_PERSISTENT``   — truthy (``1``/``true``/``yes``/``on``) to give every shared outbound
  the ADR 0067 PERSISTENT connection (reuse one connection across deliveries) instead of the default
  connect-per-delivery. Default off (byte-identical to today); the sizing bench sets it (the W1 fix, so
  per-message TCP handshake / ``TIME_WAIT`` port pressure isn't the wall being measured).

The graph is synthetic and generic — no real partner/site/host/volume.
"""

from __future__ import annotations

import os
from dataclasses import dataclass

from messagefoundry.parsing.message import Message, RawMessage

CHEAP = "cheap"
EDIT = "edit"
_TRANSFORMS = frozenset({CHEAP, EDIT})


def _env_int(name: str, default: int, *, minimum: int = 1) -> int:
    raw = os.environ.get(name)
    if not raw:
        return default
    try:
        value = int(raw)
    except ValueError as exc:
        raise ValueError(f"{name} must be an integer, got {raw!r}") from exc
    if value < minimum:
        raise ValueError(f"{name} must be >= {minimum}, got {value}")
    return value


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _env_shards(name: str) -> tuple[str, ...]:
    raw = os.environ.get(name) or "a,b,c,d"
    ids = tuple(sorted({s.strip() for s in raw.split(",") if s.strip()}))
    if not ids:
        raise ValueError(f"{name} named no shard ids")
    return ids


@dataclass(frozen=True)
class ShardCertShape:
    """Resolved certification-graph parameters (read once from the environment at load time)."""

    shards: tuple[str, ...]  # sorted shard ids — one inbound each
    inbound_base: int
    dests: int
    sink_host: str
    sink_port: int
    sink_ports: int
    transform: str
    persistent: bool  # give the shared outbounds the ADR 0067 persistent connection (default off)
    lanes_per_shard: int  # inbound→router→handler chains per shard (1 = one fat lane, default)

    def inbound_port(self, shard_index: int, lane_index: int = 0) -> int:
        """Lane ``l`` of shard ``i`` (both in sorted/enumerated order) binds
        ``inbound_base + i*lanes_per_shard + l`` — contiguous + non-overlapping over the ``N*lanes``
        ports, so the driver maps one persistent connection per (shard, lane). With the default
        ``lanes_per_shard == 1`` this reduces to ``inbound_base + i`` (byte-identical to today)."""
        return self.inbound_base + shard_index * self.lanes_per_shard + lane_index

    def sink_endpoint(self, index: int) -> tuple[str, int]:
        return self.sink_host, self.sink_port + (index % self.sink_ports)


def load_shape() -> ShardCertShape:
    transform = (os.environ.get("MEFOR_SHARDCERT_TRANSFORM", EDIT).strip().lower()) or EDIT
    if transform not in _TRANSFORMS:
        raise ValueError(
            f"MEFOR_SHARDCERT_TRANSFORM must be one of {sorted(_TRANSFORMS)}, got {transform!r}"
        )
    return ShardCertShape(
        shards=_env_shards("MEFOR_SHARDCERT_SHARDS"),
        inbound_base=_env_int("MEFOR_SHARDCERT_INBOUND_BASE", 3600),
        dests=_env_int("MEFOR_SHARDCERT_DESTS", 8),
        sink_host=os.environ.get("MEFOR_SHARDCERT_SINK_HOST", "127.0.0.1") or "127.0.0.1",
        sink_port=_env_int("MEFOR_SHARDCERT_SINK_PORT", 3700),
        sink_ports=_env_int("MEFOR_SHARDCERT_SINK_PORTS", 1),
        transform=transform,
        persistent=_env_bool("MEFOR_SHARDCERT_PERSISTENT"),
        lanes_per_shard=_env_int("MEFOR_SHARDCERT_LANES_PER_SHARD", 1),
    )


def shared_dest_name(index: int) -> str:
    """The shared outbound destination name every shard's handler ``Send``s to (overlap)."""
    return f"OB_SHARED_{index:02d}"


def fifo_lane(shard: str, dest_index: int, lane_index: int | None = None) -> str:
    """The per-(source-shard, [lane,] destination) FIFO lane key stamped into MSH-6.

    Keying on (source shard, dest) — not the shared destination alone — is what makes the per-lane
    ordering check meaningful: within one shard's stream to one destination the delivered order is a
    monotonic subsequence of the sender's send order, so a real inversion is a true FIFO break. Keying
    on the shared destination alone would false-positive on legitimate cross-shard interleaving (two
    independent source streams merging into one outbound queue have no defined mutual order).

    ``lane_index`` is ``None`` for the single-lane shape (``lanes_per_shard == 1``) — the key stays
    ``{shard}_{dest}`` (byte-identical to today). With many thin lanes per shard it is the lane index,
    folded into the key (``{shard}_L{lane}_{dest}``) so each (shard, lane, dest) is its OWN FIFO lane —
    otherwise two independent lanes of the same shard fanning to one destination would false-positive
    as inversions (they have no defined mutual order, exactly like cross-shard interleaving)."""
    if lane_index is None:
        return f"{shard}_{dest_index:02d}"
    return f"{shard}_L{lane_index:02d}_{dest_index:02d}"


def apply_transform(
    msg: Message | RawMessage,
    shape: ShardCertShape,
    shard: str,
    dest_index: int,
    lane_index: int | None = None,
) -> Message | RawMessage:
    """Apply the (cheap) transform and stamp the FIFO lane into MSH-6. Never touches MSH-10 (the
    correlation id the sink matches on). ``lane_index`` distinguishes many-thin-lanes per shard; it is
    ``None`` (and omitted from the key) for the default single-lane shape."""
    if shape.transform == CHEAP or not isinstance(msg, Message):
        return msg
    msg["MSH-4"] = "MEFOR_SHARDCERT"  # sending facility
    msg["MSH-6"] = fifo_lane(
        shard, dest_index, lane_index
    )  # receiving facility = (source shard, [lane,] destination) FIFO lane
    return msg
