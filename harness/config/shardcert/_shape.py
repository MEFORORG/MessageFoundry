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
* ``MEFOR_SHARDCERT_DESTS``        — **TOPOLOGY ONLY** (BACKLOG #209): the count of SHARED outbound
  destination CONNECTIONS every shard declares, i.e. the width of the sink port band. It is **not** the
  fan-out and **not** the transform-stage width — those are ``DELIVERING`` and ``HANDLERS`` below. Default 8.
* ``MEFOR_SHARDCERT_HANDLERS``     — ``H``: handlers the router SELECTS per (shard, lane). Feeds the reported
  ``txn/msg = 3 + 2H + 2D`` (ADR 0051) and NEVER appears in delivery arithmetic. Default ``= dests``.
* ``MEFOR_SHARDCERT_DELIVERING``   — ``D``: destinations each accepted message ACTUALLY delivers to — **the
  fan-out**. Handler ``j`` owns destination ``j`` for ``j < D``; handlers ``j >= D`` are SELF-FILTERING (they
  read a field, then return ``None``), so they cost the full 2 txn (routed-row claim + a zero-delivery
  ``transform_handoff``) and produce no outbound row. That 2-txn-for-nothing is the quantity the ``accepts=``
  seam (BACKLOG #213 / ADR 0084) removes, and what this knob exists to make measurable. Default ``= dests``.

  Invariants (**fail loud**): ``1 <= D <= dests`` and ``D <= H``. The defaults ``H = D = dests`` reproduce the
  pre-#209 graph byte-for-byte (``routed == delivered``), so no published run changes. Setting ``dests`` alone
  to model an ``H=20, N=4`` hub would build 20 outbound connections and 20 delivered copies and report
  ``events/msg = 21`` against a truth of ``5`` — a 4.2x overstatement of the headline number (harness defect
  class B10, in the permissive direction). Split the three, never overload ``dests``.
* ``MEFOR_SHARDCERT_ROUTING``      — ``broadcast`` (default) | ``partitioned`` | ``partitioned-fanout``.
  **The shape of the hub the bench models.**

  ``broadcast`` is the historical graph, unchanged byte-for-byte: the router selects EVERY handler, so every
  accepted message is delivered to EVERY destination. Because an outbound lane is strict-FIFO (``per_lane_limit``
  clamped to 1) and every lane must serve every message, the per-lane cycle CAPS INGRESS at one message per
  cycle (~16 msg/s) *at any destination count, by construction* — the bench shape imposes a ceiling that looks
  exactly like an engine wall. It also charges ``3 + 2H + 2D = 259`` store transactions per message at
  ``H = D = 64``: ~37x the store work of a real hub.

  ``partitioned`` is the REAL hub shape: the router selects exactly ONE handler per message, and that handler
  delivers to exactly ONE destination. Delivery is otherwise IDENTICAL (the same ``dests`` lanes, the same
  per-lane cycle) — but a message now occupies ONE lane instead of all of them, so ingress is no longer clamped
  by the per-lane cycle::

      aggregate deliveries ~= dests / cycle     (the lane-scaling law, unchanged)
      ingress              ~= aggregate deliveries   (each message = exactly ONE delivery)
      events/s             = ingress x 2        (one receipt + one delivery)

  The destination is chosen from the harness SEQUENCE NUMBER carried in MSH-10, through a seed-free integer
  MIXER (``dest = splitmix64(seq) % dests`` — see :meth:`ShardCertShape.destination_index`): deterministic
  across the N shard SUBPROCESSES, statistically uniform across the lanes, and — critically — **never**
  :func:`hash` of a string, which ``PYTHONHASHSEED`` randomises per process and which would therefore give
  each shard a DIFFERENT mapping and a silently skewed lane load. The MIX (rather than a bare ``seq % dests``)
  is what keeps the selector DECORRELATED from the sender's connection round-robin — see
  :meth:`ShardCertShape.destination_index`; a bare modulo destroys the cross-shard lane overlap this graph
  exists to certify.

  In ``partitioned`` the fan-out per message is 1, so the ACCOUNTING must read ``H = D = 1``
  (:func:`reported_shape`) while the GRAPH still builds ``H = D = dests`` handlers/connections (every created
  handler owns a destination; the fan-out of 1 lives in the ROUTER, never in :meth:`delivers_to`).
  ``txn/msg`` accordingly drops to ``3 + 2(1) + 2(1) = 7``.

  ``partitioned-fanout`` keeps that high-ingress partition scaling but the router selects ``D`` (=
  ``DELIVERING``) **DISTINCT** owner handlers per message (:meth:`destination_indices`, a splitmix64 partial
  Fisher-Yates over the ``dests`` lanes), so each accepted message delivers D copies. The GRAPH still builds
  ``H = dests`` owners (none self-filter — that is a ``broadcast``-only shape); the fan-out is D, expressed
  in the ROUTER. ACCOUNTING is ``H = D`` (:func:`reported_shape` → ``(D, D)``): ``events/msg = 1 + D``,
  ``txn/msg = 3 + 2D + 2D``, sink no-loss ``S == A * D``, A4b ``free = A*(D − D) = 0``. **Fail-loud, never
  clamp:** ``2 <= D < dests`` (``D == 1`` is plain ``partitioned``; ``D >= dests`` fans to all lanes -> use ``broadcast``). **⚠️ SIZE ``dests`` so the outbound
  lane cycle does NOT re-cap ingress below the engine ceiling:** each message occupies D of the ``dests``
  strict-FIFO lanes, so the lane-limited ingress ceiling ``≈ dests / (D * cycle)`` (vs ``dests / cycle`` at
  D=1). Size **``dests >= D * G``** (``G = shards * lanes_per_shard``, the inbound band count) so the
  effective outbound width ``dests / D`` stays at least as wide as the inbound band. The fan-out
  lane-headroom pre-flight (``harness.load.shardcert.check_fanout_lane_headroom``) WARNS, and REFUSES under
  ``--strict-inbound-bands``, when it does not. Under-sizing manufactures the same ~16 msg/s plateau this
  mode disproves and — being lossless — NO drive/RungFidelity gate catches it, which is why the dedicated
  D-aware pre-flight exists (``check_inbound_bands`` compares G to the RAW dests and is fan-out-unaware).
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

from harness.load.ids import SHARDCERT_IDS

CHEAP = "cheap"
EDIT = "edit"
_TRANSFORMS = frozenset({CHEAP, EDIT})

BROADCAST = "broadcast"
PARTITIONED = "partitioned"
# The partitioned HIGH-INGRESS shape with fan-out D>1: keeps partitioned's one-lane-per-pick ingress
# scaling but the router selects D DISTINCT owner handlers per message (each delivering to its own dest),
# so events/msg = 1 + D and txn/msg = 3 + 2D + 2D. D is carried in the DELIVERING field/knob (reused, not
# a new env var — see reported_shape). This is the shape the D≈4 certification soak needs.
PARTITIONED_FANOUT = "partitioned-fanout"
_ROUTINGS = frozenset({BROADCAST, PARTITIONED, PARTITIONED_FANOUT})

_M64 = (1 << 64) - 1

# A fixed large ODD 64-bit stride for the per-pick offset in destination_indices' partial Fisher-Yates.
# Odd ⇒ coprime with 2^64, so `seq + i*_FANOUT_STRIDE` visits distinct residues per pick i; every offset
# is still fed through _mix64, so the D picks stay non-linear + seed-free (same rationale as _mix64).
# Deliberately DISTINCT from _mix64's internal add-constant (a different avalanche input per pick).
_FANOUT_STRIDE = 0xD1B54A32D192ED03


def _mix64(x: int) -> int:
    """The splitmix64 FINALIZER — a seed-free integer avalanche used to decorrelate the destination
    selector from the sender's connection round-robin (:meth:`ShardCertShape.destination_index`).

    Chosen over every alternative for three properties this bench actually needs:

    * **Deterministic across processes** — pure integer arithmetic, no seed, no string hashing, so the N
      ``serve --shard`` SUBPROCESSES all agree on the mapping (``PYTHONHASHSEED`` cannot touch it).
    * **NON-LINEAR** — this is the whole point. Any LINEAR map ``(a*seq + b) % L`` leaves ``seq mod C`` and
      ``dest`` coupled through ``gcd(C, L)``, which is exactly the defect being fixed; a bijective avalanche
      breaks the congruence.
    * **Cheap** — six integer ops on the router's hot path (no ``hashlib`` call, no bytes allocation)."""
    x = (x + 0x9E3779B97F4A7C15) & _M64
    x ^= x >> 30
    x = (x * 0xBF58476D1CE4E5B9) & _M64
    x ^= x >> 27
    x = (x * 0x94D049BB133111EB) & _M64
    x ^= x >> 31
    return x


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
    # TOPOLOGY ONLY: shared outbound destination CONNECTIONS = sink port-band width. NOT the fan-out.
    dests: int
    sink_host: str
    sink_port: int
    sink_ports: int
    transform: str
    persistent: bool  # give the shared outbounds the ADR 0067 persistent connection (default off)
    lanes_per_shard: int  # inbound→router→handler chains per shard (1 = one fat lane, default)
    # H: handlers the router SELECTS per (shard, lane) under BROADCAST. Under PARTITIONED this is the count
    # of handlers CREATED (== dests); the router selects exactly ONE of them. See `selected_handlers`.
    handlers: int
    # D: destinations an accepted message actually delivers to. *** THE FAN-OUT *** Under BROADCAST, handler
    # j<D delivers and j>=D self-filters. Under PARTITIONED this is the count of OWNER handlers built (==
    # dests); the fan-out per message is 1 (`fanout` overrides). Under PARTITIONED-FANOUT this CARRIES D:
    # the router selects D distinct owners per message; `fanout` == `selected_handlers` == D. See `fanout`.
    delivering: int
    #: broadcast (every handler selected, fan-out D) | partitioned (ONE handler selected, fan-out 1).
    routing: str = BROADCAST

    @property
    def partitioned(self) -> bool:
        # STRICTLY the plain D=1 shape — deliberately NOT true for partitioned-fanout, so `fanout` and the
        # legacy single-select router path fall through to the D>1 behaviour rather than pinning to 1.
        return self.routing == PARTITIONED

    @property
    def partitioned_fanout(self) -> bool:
        """The partitioned HIGH-INGRESS shape with fan-out D>1 (D carried in ``delivering``): the router
        selects D DISTINCT owner handlers per message, each delivering to its own dest."""
        return self.routing == PARTITIONED_FANOUT

    @property
    def any_partitioned(self) -> bool:
        """Either partitioned shape. Under both, every BUILT handler owns a destination (no self-filtering
        in :meth:`delivers_to`); the fan-out (1 or D) is expressed by the ROUTER select, never here."""
        return self.partitioned or self.partitioned_fanout

    def delivers_to(self, handler_index: int) -> int | None:
        """The destination index handler ``handler_index`` delivers to, or ``None`` if it SELF-FILTERS.

        BROADCAST: handler ``j`` owns destination ``j`` for ``j < delivering`` (so at the default
        ``H == D == dests`` every handler delivers and the graph is byte-identical to the pre-#209 one);
        handlers ``j >= D`` take the message, read it, and deliver nothing — the real hub shape (``H=20``
        selected, ``D=4`` delivered) the bench previously could not express.

        PARTITIONED / PARTITIONED-FANOUT (``any_partitioned``): **EVERY created handler owns a destination,
        unconditionally.** The fan-out (1 for partitioned, D for partitioned-fanout) is expressed in the
        ROUTER (it selects 1 / D DISTINCT owner handlers), NEVER by self-filtering. This is a deliberate
        guard, not a redundancy: :func:`load_shape` pins ``H == D == dests`` (built) under both, but if a
        future edit relaxed that and this method gated on ``delivering`` (which under partitioned-fanout is
        the fan-out D < dests), handlers ``D..dests-1`` would silently self-filter and traffic would funnel
        onto D lanes — a manufactured plateau INDISTINGUISHABLE from the broadcast wall this mode disproves."""
        if self.any_partitioned:
            return handler_index
        return handler_index if handler_index < self.delivering else None

    @property
    def selected_handlers(self) -> int:
        """``H`` as the COST MODEL means it: handlers the router selects PER MESSAGE. Under BROADCAST that is
        every created handler; under PARTITIONED the router selects exactly ONE, so it is 1 regardless of how
        many were created; under PARTITIONED-FANOUT it selects D DISTINCT owners (== ``delivering``), so it is
        D. Reporting the CREATED count (``dests``) under either partitioned mode would inflate ``txn/msg`` AND
        hand the ladder's A4b cross-observer guard a ``free = acked * (H - D)`` strand budget, effectively
        DISARMING it (shardcert_ladder.observers_inconclusive). Under partitioned-fanout H == D == ``delivering``
        so ``free == 0`` (no self-filtering handlers exist), which keeps the guard armed and correct."""
        if self.partitioned_fanout:
            return self.delivering
        return 1 if self.partitioned else self.handlers

    @property
    def fanout(self) -> int:
        """``D`` as the DELIVERY ARITHMETIC means it: destinations ONE accepted message delivers to. Under
        PARTITIONED that is exactly 1 (one selected handler, one destination) even though ``dests`` lanes
        exist and all of them are used in aggregate; under PARTITIONED-FANOUT it is D == ``delivering`` (the
        router selects D DISTINCT owners, each delivering once). This is the multiplier in the sink no-loss
        identity (``S == A * D``); keying it on ``dests`` would read FALSE LOSS on every healthy rung.
        (``self.partitioned`` is STRICTLY the D=1 shape, so partitioned-fanout falls through to
        ``self.delivering`` here — the same branch broadcast uses.)"""
        return 1 if self.partitioned else self.delivering

    def destination_index(self, msg: Message | RawMessage) -> int:
        """PARTITIONED: the ONE destination this message is routed to — ``splitmix64(seq) % dests``, where
        ``seq`` is the dense monotonic sequence number the harness sender stamps into MSH-10 as
        ``SC<12 digits>`` (:data:`~harness.load.ids.SHARDCERT_IDS`).

        **The MIX is load-bearing — a bare ``seq % dests`` is a DEFECT, not a simplification.** The sender's
        connection round-robin is keyed on the SAME counter: :func:`harness.load.shardcert._drive_load` does
        ``out = corpus.next(sampler); conn = conns[rr % len(conns)]; rr += 1``, and ``Corpus.next`` hands out
        ``seq = 0, 1, 2, …`` one per call — so ``rr == seq`` and the sender band is ``seq % C`` (C = that
        process's connection count). A selector of ``seq % L`` is then ALIGNED with it: band ``b`` only ever
        carries ``seq ≡ b (mod C)``, so it only ever reaches destinations ``≡ b (mod gcd(C, L))``. Every
        sizing ``L`` is a multiple of the shard count, so at the ``--driver-count 1`` default EVERY
        destination lane ends up produced-into by EXACTLY ONE shard — and cross-shard production into a
        shared lane is the ENTIRE premise of this graph (``graph`` module docstring; ADR 0073's
        single-delivery-consumer invariant "is exercised only when a lane is produced-into by more than one
        shard"). Measured on the real arithmetic at shards=4, L=64: ``seq % L`` yields 64 of the 256 possible
        (shard, dest) FIFO lane keys and 1 feeding shard per destination; the mix yields all 256 and 4.
        A coprime multiplier does NOT save it — for any LINEAR map the two moduli stay coupled through
        ``gcd``. It has to be non-linear.

        Balance is therefore STATISTICAL, not exact: at 48k messages over 64 lanes the spread is
        ~750 ± 45 (~6%), which is immaterial to a lane-scaling claim and is the price of the decorrelation.

        Deliberately NOT ``hash(...)`` of any string: Python randomises str hashing per process via
        ``PYTHONHASHSEED``, so with N shard SUBPROCESSES a hash-based selector would give each shard a
        DIFFERENT seq→dest mapping and a silently skewed lane load. :func:`_mix64` is pure integer
        arithmetic — identical in every process, forever.

        **FAILS LOUD** on a message whose control id does not decode (a ``RawMessage``, an unstamped MSH-10, a
        foreign id). A silent fallback to destination 0 would funnel ALL traffic onto ONE lane and manufacture
        a fake ~16 msg/s plateau — the exact artefact this mode exists to disprove — while still reporting a
        clean PASS. Raising instead routes the message to the engine's error/dead-letter path, which breaks the
        no-loss identity and VOIDS the run visibly."""
        control_id = msg.control_id if isinstance(msg, Message) else None
        seq = SHARDCERT_IDS.parse(control_id)
        if seq is None:
            raise ValueError(
                f"MEFOR_SHARDCERT_ROUTING={PARTITIONED} needs the harness sequence number in MSH-10 "
                f"(expected {SHARDCERT_IDS.prefix}<{SHARDCERT_IDS.width} digits>, got {control_id!r}). "
                "Refusing to fall back to destination 0: that would funnel every message onto one FIFO "
                "lane and fabricate a plateau."
            )
        return _mix64(seq) % self.dests

    def destination_indices(self, msg: Message | RawMessage) -> list[int]:
        """PARTITIONED-FANOUT: the ``fanout`` (== D) DISTINCT destinations one accepted message delivers to.

        Drawn from the harness sequence number via a partial Fisher-Yates over ``[0, dests)`` — pick ``i``
        swaps ``pool[i]`` with ``pool[i + _mix64(seq + i*_FANOUT_STRIDE) % (dests - i)]`` — so the first
        ``fanout`` entries are a permutation PREFIX: provably all-distinct in EXACTLY ``fanout`` draws (a
        hard bound, unlike rejection sampling). Distinct dests → distinct owner handlers → D deliveries,
        never the same lane twice (which would under-deliver and read FALSE LOSS against ``S == A * D``).

        Every pick routes through :func:`_mix64` (pure integer avalanche, no ``hash``/``PYTHONHASHSEED``,
        no seed), so the selector is NON-LINEAR (decorrelated from the sender's ``rr == seq`` round-robin,
        preserving the cross-shard lane overlap this graph certifies) and IDENTICAL in every ``serve
        --shard`` subprocess. At ``fanout == 1`` the i=0 draw is ``_mix64(seq) % dests``, so this returns
        exactly ``[destination_index(msg)]`` — plain PARTITIONED keeps its singular path unchanged.

        Shares :meth:`destination_index`'s FAIL-LOUD raise on an undecodable control id (no dest-0 fallback:
        that would funnel messages onto one FIFO lane and fabricate a plateau while reporting a clean PASS).
        ``dests - i`` is never 0 because :func:`load_shape` validates ``fanout <= dests``."""
        control_id = msg.control_id if isinstance(msg, Message) else None
        seq = SHARDCERT_IDS.parse(control_id)
        if seq is None:
            raise ValueError(
                f"MEFOR_SHARDCERT_ROUTING={PARTITIONED_FANOUT} needs the harness sequence number in MSH-10 "
                f"(expected {SHARDCERT_IDS.prefix}<{SHARDCERT_IDS.width} digits>, got {control_id!r}). "
                "Refusing to fall back to destination 0: that would funnel messages onto one FIFO lane and "
                "fabricate a plateau."
            )
        pool = list(range(self.dests))
        for i in range(self.fanout):
            j = i + (_mix64((seq + i * _FANOUT_STRIDE) & _M64) % (self.dests - i))
            pool[i], pool[j] = pool[j], pool[i]
        return pool[: self.fanout]

    @property
    def txn_per_message(self) -> int:
        """The ADR 0051 durable-write cost of one ingress message on THIS shape: ``3 + 2H + 2D``, keyed on the
        SELECTED handlers and the FAN-OUT — never the counts CREATED in the graph. Under BROADCAST a
        self-filtering handler still costs its 2 (routed-row claim + a zero-delivery ``transform_handoff``),
        which is why ``H`` — not ``D`` — carries the ``2H`` term. Under PARTITIONED only ONE handler is routed
        to, so the true cost is ``3 + 2 + 2 = 7`` against BROADCAST's 259 at ``H = D = 64``."""
        return 3 + 2 * self.selected_handlers + 2 * self.fanout

    @property
    def events_per_message(self) -> int:
        """Counted message events per ingress message (the 45M/day currency): the message itself plus ONE
        per DELIVERED copy — ``1 + D``. Never ``1 + dests``: a destination CONNECTION that no handler sends
        to produces no event. Under PARTITIONED this is 2 (one receipt + one delivery) — and unlike
        BROADCAST's ``1 + 64``, every one of those events corresponds to a message that genuinely arrived."""
        return 1 + self.fanout

    def inbound_port(self, shard_index: int, lane_index: int = 0) -> int:
        """Lane ``l`` of shard ``i`` (both in sorted/enumerated order) binds
        ``inbound_base + i*lanes_per_shard + l`` — contiguous + non-overlapping over the ``N*lanes``
        ports, so the driver maps one persistent connection per (shard, lane). With the default
        ``lanes_per_shard == 1`` this reduces to ``inbound_base + i`` (byte-identical to today)."""
        return self.inbound_base + shard_index * self.lanes_per_shard + lane_index

    def sink_endpoint(self, index: int) -> tuple[str, int]:
        return self.sink_host, self.sink_port + (index % self.sink_ports)


def load_routing() -> str:
    """The routing mode, read once from the environment and VALIDATED (never clamped, never guessed).

    Public because the bench driver (``harness.load.shardcert``) must resolve the SAME mode the served graph
    resolves, to derive the ACCOUNTING shape it reports and posts to the drive box (:func:`reported_shape`)."""
    routing = (os.environ.get("MEFOR_SHARDCERT_ROUTING", BROADCAST).strip().lower()) or BROADCAST
    if routing not in _ROUTINGS:
        raise ValueError(
            f"MEFOR_SHARDCERT_ROUTING must be one of {sorted(_ROUTINGS)}, got {routing!r}"
        )
    return routing


def reported_shape(handlers: int, delivering: int, routing: str) -> tuple[int, int]:
    """The ``(H, D)`` every ACCOUNTING consumer must use, given the GRAPH-BUILD pair and the routing mode.

    BROADCAST: the build pair IS the accounting pair (the router selects all H, and D of them deliver).

    PARTITIONED: the graph BUILDS ``H = D = dests`` (every created handler owns a destination) but the router
    selects exactly ONE handler, which delivers to exactly ONE destination — so the accounting pair is
    ``(1, 1)``. This split is the whole hazard of the mode. ``delivering`` is the multiplier in the sink
    no-loss identity (``S == A * D``, shardcert.no_loss / ShardCertRung.outbound_delivered_expected) and in the
    45M/day headline (``sustained_events_per_s = p * (1 + D)``); ``handlers`` feeds ``txn/msg = 3 + 2H + 2D``
    and the A4b guard's ``free = acked * (H - D)`` strand budget. A consumer left keyed on the BUILD pair
    reads FALSE LOSS on every healthy rung (``S == A*1`` vs an expectation of ``A*64``) — which at least fails
    loud — or, via ``free``, silently DISARMS the cross-observer over-count guard, which does not.

    PARTITIONED-FANOUT: the graph likewise BUILDS ``H = D = dests`` owners, but the router selects ``D``
    DISTINCT ones (``delivering`` carries D), each delivering once — so the accounting pair is ``(D, D)``.
    Both terms are D: the ``2D`` fan-out multiplier AND the ``2H`` selected term (there are no self-filtering
    handlers, so ``free = acked * (H - D) == 0`` keeps the A4b guard armed). Returning ``(1, 1)`` here reads
    FALSE LOSS; ``(dests, dests)`` over-expects.

    Kept as a free function (not just a shape property) because the two-box ENGINE half must derive it for the
    SHARDS_READY post WITHOUT loading the graph: that post is the ONLY channel by which the drive box learns
    the fan-out, and its ``handlers``/``delivering`` keys are REQUIRED reads with no default."""
    if routing == PARTITIONED_FANOUT:
        return delivering, delivering
    if routing == PARTITIONED:
        return 1, 1
    return handlers, delivering


def load_shape() -> ShardCertShape:
    transform = (os.environ.get("MEFOR_SHARDCERT_TRANSFORM", EDIT).strip().lower()) or EDIT
    if transform not in _TRANSFORMS:
        raise ValueError(
            f"MEFOR_SHARDCERT_TRANSFORM must be one of {sorted(_TRANSFORMS)}, got {transform!r}"
        )
    routing = load_routing()
    dests = _env_int("MEFOR_SHARDCERT_DESTS", 8)
    # H and D both DEFAULT to dests ⇒ H = D = dests, the pre-#209 graph, byte-for-byte.
    handlers = _env_int("MEFOR_SHARDCERT_HANDLERS", dests)
    delivering = _env_int("MEFOR_SHARDCERT_DELIVERING", dests)
    # PARTITIONED pins the GRAPH-BUILD pair to H = D = dests: every created handler must OWN a destination
    # (delivers_to(j) = j for all j), because the fan-out of 1 is expressed by the ROUTER selecting one
    # handler — never by self-filtering. H/D are therefore NOT free parameters here, and a caller that set
    # them is describing a shape this mode cannot serve: fail loud rather than quietly serve a different
    # graph than the operator asked for. (The self-filtering H > D hub is a BROADCAST-only shape.)
    if routing == PARTITIONED and not (handlers == delivering == dests):
        raise ValueError(
            f"MEFOR_SHARDCERT_ROUTING={PARTITIONED} pins the graph to HANDLERS == DELIVERING == DESTS "
            f"(every handler owns one destination; the router selects ONE of them), got "
            f"HANDLERS={handlers}, DELIVERING={delivering}, DESTS={dests}. The per-message fan-out is 1 by "
            f"construction — it is NOT set via DELIVERING (see reported_shape); the self-filtering H > D hub "
            f"is a {BROADCAST}-only shape."
        )
    # PARTITIONED-FANOUT builds one OWNER handler per destination (H == dests, none self-filter — the
    # H > D self-filtering hub is a BROADCAST-only shape), and the router selects D == DELIVERING DISTINCT
    # owners per message: THE FAN-OUT. D must be a real fan-out (>= 2; D == 1 is plain PARTITIONED) and no
    # larger than the destinations that exist (the `delivering > dests` check below). Fail loud, never clamp.
    if routing == PARTITIONED_FANOUT:
        # The CLI requires --delivering, but the env/`serve` path defaults DELIVERING to DESTS — which would
        # silently serve D == DESTS (every message fans to ALL lanes → ingress re-capped to the ~16 msg/s
        # plateau this mode disproves). Require it EXPLICITLY on the env path too, matching the CLI gate, so a
        # direct `serve` cannot quietly run the worst-case fan-to-all shape.
        if os.environ.get("MEFOR_SHARDCERT_DELIVERING") is None:
            raise ValueError(
                f"MEFOR_SHARDCERT_ROUTING={PARTITIONED_FANOUT} REQUIRES MEFOR_SHARDCERT_DELIVERING (the "
                f"fan-out D, 2 <= D < DESTS): each message delivers to D distinct destinations. Unset, it "
                f"defaults to DESTS ({dests}) and fans to ALL lanes — re-capping ingress. Set it explicitly."
            )
        if handlers != dests:
            raise ValueError(
                f"MEFOR_SHARDCERT_ROUTING={PARTITIONED_FANOUT} builds one owner handler per destination "
                f"(HANDLERS == DESTS), got HANDLERS={handlers}, DESTS={dests}. The fan-out is D=DELIVERING "
                f"selected in the ROUTER, not a self-filtering H > D hub (that is a {BROADCAST}-only shape)."
            )
        if delivering < 2:
            raise ValueError(
                f"MEFOR_SHARDCERT_ROUTING={PARTITIONED_FANOUT} needs a real fan-out DELIVERING >= 2 "
                f"(got DELIVERING={delivering}); DELIVERING == 1 is plain {PARTITIONED} (use that instead)."
            )
        if delivering >= dests:
            raise ValueError(
                f"MEFOR_SHARDCERT_ROUTING={PARTITIONED_FANOUT} needs DELIVERING < DESTS (got "
                f"DELIVERING={delivering}, DESTS={dests}): D >= DESTS fans every message to ALL lanes and "
                f"re-caps ingress — use {BROADCAST} for full fan-out."
            )
    # FAIL LOUD, never clamp: a silently-truncated fan-out would make `events/msg = 1 + D` and the sink's
    # socket truth `S == A*D` disagree with the graph the fleet actually serves — a fabricated headline
    # number, which is precisely the harness's B1-B10 defect class.
    if delivering > dests:
        raise ValueError(
            f"MEFOR_SHARDCERT_DELIVERING ({delivering}) > MEFOR_SHARDCERT_DESTS ({dests}): a message "
            "cannot deliver to more destinations than the graph declares connections for"
        )
    if handlers < delivering:
        raise ValueError(
            f"MEFOR_SHARDCERT_HANDLERS ({handlers}) < MEFOR_SHARDCERT_DELIVERING ({delivering}): every "
            "delivering destination needs a handler that owns it (handler j owns destination j)"
        )
    return ShardCertShape(
        shards=_env_shards("MEFOR_SHARDCERT_SHARDS"),
        inbound_base=_env_int("MEFOR_SHARDCERT_INBOUND_BASE", 3600),
        dests=dests,
        sink_host=os.environ.get("MEFOR_SHARDCERT_SINK_HOST", "127.0.0.1") or "127.0.0.1",
        sink_port=_env_int("MEFOR_SHARDCERT_SINK_PORT", 3700),
        sink_ports=_env_int("MEFOR_SHARDCERT_SINK_PORTS", 1),
        transform=transform,
        persistent=_env_bool("MEFOR_SHARDCERT_PERSISTENT"),
        lanes_per_shard=_env_int("MEFOR_SHARDCERT_LANES_PER_SHARD", 1),
        handlers=handlers,
        delivering=delivering,
        routing=routing,
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
