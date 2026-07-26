# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PARTITIONED routing for the shardcert bench — the REAL hub shape.

The shardcert bench has only ever modelled a BROADCAST hub: ``graph._make_router`` returns the full handler
list unconditionally, so every accepted message is delivered to EVERY destination. Because an outbound lane
is strict-FIFO (``per_lane_limit`` clamped to 1) and every lane must therefore serve every message, the
per-lane cycle CAPS INGRESS at one message per cycle (~16 msg/s) — **at any destination count, by
construction**. That is a property of the BENCH SHAPE, not of the engine.

PARTITIONED routing selects ONE handler per message, which delivers to ONE destination. Delivery is
unchanged (same lanes, same strict-FIFO cycle) but a message now occupies ONE lane instead of all of them,
so ingress is no longer clamped:

    aggregate deliveries ~= dests / cycle   (lane-scaling, unchanged)
    ingress              ~= aggregate deliveries        (each message IS exactly one delivery)
    events/s             = ingress x 2

These tests pin the four things that could silently fabricate a number:

* **The selector** must be deterministic across the N shard SUBPROCESSES (never ``hash()`` of a string —
  ``PYTHONHASHSEED`` randomises str hashing per process) **and DECORRELATED from the sender's connection
  round-robin**. The sender picks its connection with ``rr % len(conns)`` where ``rr`` IS the corpus seq, so
  a selector of ``seq % dests`` is ALIASED with it and leaves every destination lane fed by exactly ONE
  shard — silently deleting the cross-shard overlap the shardcert exists to certify (ADR 0073). Hence the
  splitmix64 mix.
* **The accounting** must key on the FAN-OUT (1), not on the handlers CREATED (``dests``) — a consumer left
  on the build pair reads FALSE LOSS, or (via the A4b ``free`` budget) silently DISARMS the cross-observer
  guard.
* **The FIFO check** must stay MONOTONE, not dense — partitioned traffic gives each destination lane a
  STRIDED subsequence of the seq stream.
* **The provenance** must reach the report — the derived (H, D) = (1, 1) is a pair a legal BROADCAST run can
  also produce, from a ~50x slower graph.

BROADCAST stays the default and stays byte-identical; the pins for that live here and in
``test_shardcert_config.py``.
"""

from __future__ import annotations

import os
import subprocess
import sys
import textwrap
from collections import Counter
from pathlib import Path

import pytest

from harness.config.shardcert._shape import (
    BROADCAST,
    PARTITIONED,
    ShardCertShape,
    load_routing,
    load_shape,
    reported_shape,
    shared_dest_name,
)
from harness.load.corpus import SEQ_BASE_STRIDE
from harness.load.failover_track import FailoverTracker
from harness.load.ids import SHARDCERT_IDS
from harness.load.shardcert import QueueBreakdown, _summarize_queue_rows
from harness.load.shardcert_ladder import observers_inconclusive
from messagefoundry.config.wiring import Registry, Send, load_config
from messagefoundry.parsing.message import Message, RawMessage

_CONFIG_DIR = "harness/config/shardcert"

#: Repo root — the cwd the PYTHONHASHSEED subprocesses need so `harness` / `messagefoundry` import.
_REPO_ROOT = Path(__file__).resolve().parent.parent

_SAMPLE_HL7 = (
    "MSH|^~\\&|SND|SF|RCV|RF|20260101000000||ADT^A01|MSG00001|P|2.5\r"
    "EVN|A01|20260101000000\r"
    "PID|1||1^^^MRN||DOE^JOHN"
)


def _msg(seq: int) -> Message:
    """A harness message carrying sequence ``seq`` in MSH-10 — exactly what the sender puts on the wire
    (``Corpus.next`` stamps ``ids.format(seq)`` into MSH-10, and ``apply_transform`` never overwrites it)."""
    msg = Message.parse(_SAMPLE_HL7)
    msg["MSH-10"] = SHARDCERT_IDS.format(seq)
    return msg


def _route(reg: Registry, name: str, msg: Message) -> list[str]:
    """The router's selection, narrowed. ``RouterFn`` returns ``list[str] | str | None``; every shardcert
    router returns a list, and asserting that here keeps the call sites readable AND mypy-strict clean."""
    selected = reg.routers[name](msg)
    assert isinstance(selected, list), f"router {name} returned {selected!r}, expected a list"
    return selected


def _partitioned_env(monkeypatch: pytest.MonkeyPatch, *, dests: int, shards: str = "a") -> None:
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", shards)
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", str(dests))
    monkeypatch.delenv("MEFOR_SHARDCERT_HANDLERS", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_DELIVERING", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_ROUTING", PARTITIONED)


# =====================================================================================================
# (a) BROADCAST IS BYTE-IDENTICAL — the no-published-run-may-move gate.
# =====================================================================================================


def test_routing_defaults_to_broadcast(monkeypatch: pytest.MonkeyPatch) -> None:
    # The knob unset ⇒ broadcast. If this ever flips, every published shardcert number silently moves.
    monkeypatch.delenv("MEFOR_SHARDCERT_ROUTING", raising=False)
    assert load_routing() == BROADCAST
    assert load_shape().routing == BROADCAST
    assert load_shape().partitioned is False


def test_broadcast_graph_router_and_cost_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    # THE regression pin: with the routing knob unset, the default graph is exactly the pre-partitioned one
    # — the router selects EVERY handler, every handler delivers, and the cost/event model is untouched.
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_DESTS", raising=False)  # default 8
    monkeypatch.delenv("MEFOR_SHARDCERT_HANDLERS", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_DELIVERING", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_ROUTING", raising=False)
    reg = load_config(_CONFIG_DIR)

    assert sorted(reg.handlers) == [f"H_a_{j:02d}" for j in range(8)]
    assert len(reg.outbound) == 8
    # The router still fans to ALL 8, unconditionally — the broadcast contract.
    assert _route(reg, "route_a", _msg(3)) == [f"H_a_{j:02d}" for j in range(8)]
    for name in reg.handlers:
        assert isinstance(reg.handlers[name](_msg(3)), Send)

    shape = load_shape()
    assert (shape.handlers, shape.delivering) == (8, 8)
    assert (shape.selected_handlers, shape.fanout) == (8, 8)  # broadcast: derived == built
    assert shape.txn_per_message == 35  # 3 + 2*8 + 2*8 — unchanged
    assert shape.events_per_message == 9  # 1 + 8 — unchanged
    assert [shape.delivers_to(j) for j in range(8)] == list(range(8))


def test_broadcast_self_filtering_hub_unchanged(monkeypatch: pytest.MonkeyPatch) -> None:
    # The H=20/D=4 ADT hub (BACKLOG #209) is a BROADCAST-only shape and must still work exactly as before:
    # 20 handlers selected, 4 deliver, 16 self-filter.
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "4")
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", "20")
    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", "4")
    monkeypatch.delenv("MEFOR_SHARDCERT_ROUTING", raising=False)
    shape = load_shape()

    assert [shape.delivers_to(j) for j in range(6)] == [0, 1, 2, 3, None, None]
    assert (shape.selected_handlers, shape.fanout) == (20, 4)
    assert shape.txn_per_message == 51 and shape.events_per_message == 5
    assert reported_shape(20, 4, BROADCAST) == (20, 4)  # broadcast never rewrites the pair


# =====================================================================================================
# (b) PARTITIONED: the router selects EXACTLY ONE handler, and the destination is the MIXED seq.
# =====================================================================================================


def test_partitioned_router_selects_exactly_one_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    _partitioned_env(monkeypatch, dests=8)
    reg = load_config(_CONFIG_DIR)

    for seq in range(40):
        selected = _route(reg, "route_a", _msg(seq))
        assert len(selected) == 1, (
            f"seq {seq} selected {len(selected)} handlers, expected exactly 1"
        )


def test_partitioned_routes_to_the_handler_owning_the_selected_dest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # handler j owns destination j ⇒ the selected handler is H_a_{shape.destination_index(msg)}, and it
    # really does Send to the matching SHARED destination (end to end, not just by name).
    dests = 8
    _partitioned_env(monkeypatch, dests=dests)
    shape = load_shape()
    reg = load_config(_CONFIG_DIR)

    for seq in range(40):
        want = shape.destination_index(_msg(seq))
        assert _route(reg, "route_a", _msg(seq)) == [f"H_a_{want:02d}"]

    for seq in (0, 1, 7, 8, 63, 64, 65):
        (name,) = _route(reg, "route_a", _msg(seq))
        out = reg.handlers[name](_msg(seq))
        assert isinstance(out, Send)
        assert out.to == shared_dest_name(shape.destination_index(_msg(seq)))


def test_partitioned_selector_is_balanced_within_tolerance(monkeypatch: pytest.MonkeyPatch) -> None:
    # The mixer trades EXACT round-robin for DECORRELATION from the sender's connection round-robin (see
    # test_selector_is_decorrelated_from_the_sender_band — the property a bare `seq % dests` destroys). So
    # balance is now STATISTICAL, and the bar is a tolerance band, not equality. An unbalanced selector would
    # overload one lane and depress the measured aggregate — a fake ceiling — so the band is kept tight.
    dests = 64
    _partitioned_env(monkeypatch, dests=dests)
    shape = load_shape()

    n = dests * 750  # 48,000 messages — the scale of a real rung
    counts = Counter(shape.destination_index(_msg(seq)) for seq in range(n))
    assert len(counts) == dests, "some lane was never selected"

    mean = n / dests
    worst = max(abs(c - mean) / mean for c in counts.values())
    assert worst < 0.15, (
        f"lane load deviates {worst:.1%} from uniform (counts={sorted(counts.values())})"
    )


def test_partitioned_builds_no_self_filtering_handler(monkeypatch: pytest.MonkeyPatch) -> None:
    # ⭐ THE FALSE-PLATEAU GUARD. `delivers_to` gates on `delivering` under broadcast; if partitioned were
    # implemented by forcing delivering=1, handlers 1..L-1 would SELF-FILTER and 100% of traffic would land
    # on destination 0 — one lane, ~16 msg/s, a plateau indistinguishable from the wall being disproved.
    # EVERY created handler must own a destination, and NONE may return None.
    dests = 16
    _partitioned_env(monkeypatch, dests=dests)
    shape = load_shape()
    reg = load_config(_CONFIG_DIR)

    assert [shape.delivers_to(j) for j in range(dests)] == list(range(dests))
    assert len(reg.handlers) == dests  # H (created) == dests
    assert len(reg.outbound) == dests  # every destination lane exists

    # Every handler delivers, and each owns a DISTINCT destination — no lane is unreachable.
    targets = set()
    for j in range(dests):
        out = reg.handlers[f"H_a_{j:02d}"](_msg(j))
        assert isinstance(out, Send), f"H_a_{j:02d} self-filtered — the fake-plateau bug"
        targets.add(out.to)
    assert targets == {shared_dest_name(d) for d in range(dests)}

    # And traffic really does spread across ALL the lanes, not funnel onto destination 0.
    reached = {_route(reg, "route_a", _msg(seq))[0] for seq in range(dests * 40)}
    assert len(reached) == dests, "traffic funnelled onto a subset of lanes"


def test_partitioned_rejects_handlers_delivering_overrides(monkeypatch: pytest.MonkeyPatch) -> None:
    # Partitioned pins H = D = dests (the fan-out lives in the ROUTER). A caller asking for the self-filtering
    # H>D hub here is describing a shape this mode cannot serve — fail loud, never quietly serve another graph.
    _partitioned_env(monkeypatch, dests=8)
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", "20")
    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", "4")
    with pytest.raises(ValueError, match="pins the graph to HANDLERS == DELIVERING == DESTS"):
        load_shape()


def test_routing_knob_fails_loud_on_garbage(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("MEFOR_SHARDCERT_ROUTING", "partitionned")  # typo
    with pytest.raises(ValueError, match="MEFOR_SHARDCERT_ROUTING must be one of"):
        load_routing()


# =====================================================================================================
# (c) ⭐ THE SELECTOR MUST BE DECORRELATED FROM THE SENDER'S CONNECTION ROUND-ROBIN.
# =====================================================================================================
#
# THE BLOCKER THIS SECTION EXISTS FOR. `_drive_load` does:
#
#     out = corpus.next(sampler)          # hands out seq = 0, 1, 2, ... one per call
#     conn = conns[rr % len(conns)]       # rr starts at 0 and increments once per message
#     rr += 1
#
# so `rr == seq` and the SENDER BAND is `seq % C` (C = that process's connection count = shards*lanes at the
# single-corpus default). A selector of `seq % L` shares that modulus: band b only ever carries seqs
# ≡ b (mod C), hence only ever reaches dests ≡ b (mod gcd(C, L)). Every sizing L is a multiple of the shard
# count, so EVERY destination lane ends up fed by exactly ONE shard — and "each shared destination lane is
# produced-into by every shard" is the LITERAL premise of the shardcert graph (graph.py:5-10; the ADR 0073
# single-consumer invariant "is exercised only when a lane is produced-into by more than one shard").
#
# A coprime multiplier cannot save it (any LINEAR map keeps the two moduli coupled through gcd). It takes a
# NON-LINEAR mix — splitmix64, seed-free, PYTHONHASHSEED-immune, no string hashing.


def _lane_keys_under_the_real_drive_rule(
    shape: ShardCertShape, *, shards: tuple[str, ...], n: int
) -> tuple[set[tuple[str, int]], dict[int, set[str]]]:
    """Replay the REAL sender rule (band = seq % K, one shared monotonic corpus) against the REAL selector,
    and return the (shard, dest) FIFO lane keys + the set of shards feeding each destination."""
    k = len(shards)
    keys: set[tuple[str, int]] = set()
    feeders: dict[int, set[str]] = {d: set() for d in range(shape.dests)}
    for seq in range(n):
        shard = shards[seq % k]  # conns[rr % len(conns)], rr == seq
        dest = shape.destination_index(_msg(seq))
        keys.add((shard, dest))
        feeders[dest].add(shard)
    return keys, feeders


def test_selector_is_decorrelated_from_the_sender_band(monkeypatch: pytest.MonkeyPatch) -> None:
    # ⭐ THE TEST THAT CATCHES THE BLOCKER. With `seq % dests` this reads: 64 of 256 lane keys, and exactly
    # ONE feeding shard per destination — the ADR 0073 cross-shard overlap silently GONE, on every run, at
    # the `--driver-count 1` default. With the mix: all 256 keys, all 4 shards into every destination.
    shards = ("a", "b", "c", "d")
    dests = 64
    _partitioned_env(monkeypatch, dests=dests, shards=",".join(shards))
    shape = load_shape()

    keys, feeders = _lane_keys_under_the_real_drive_rule(shape, shards=shards, n=48_000)

    # EVERY destination is produced-into by MORE THAN ONE shard — the invariant the shardcert certifies.
    thin = {d: sorted(f) for d, f in feeders.items() if len(f) < 2}
    assert not thin, f"destinations fed by a single shard (the aliasing defect): {thin}"
    assert all(f == set(shards) for f in feeders.values()), (
        "not every shard reaches every destination"
    )

    # ...and the FIFO lane space is FULL: K x L keys, not L.
    assert len(keys) == len(shards) * dests == 256


@pytest.mark.parametrize("dests", [8, 16, 32, 64])
def test_every_destination_is_multi_shard_at_every_sizing(
    monkeypatch: pytest.MonkeyPatch, dests: int
) -> None:
    # The aliasing bit at EVERY L the ladder uses (all multiples of the shard count — which is exactly why
    # gcd(K, L) == K and the degeneracy was total rather than partial).
    shards = ("a", "b", "c", "d")
    _partitioned_env(monkeypatch, dests=dests, shards=",".join(shards))
    shape = load_shape()

    keys, feeders = _lane_keys_under_the_real_drive_rule(shape, shards=shards, n=12_000)
    assert min(len(f) for f in feeders.values()) >= 2
    assert len(keys) == len(shards) * dests


def test_selector_is_not_a_bare_modulo(monkeypatch: pytest.MonkeyPatch) -> None:
    # Pin the NEGATIVE directly: a future "simplify this to seq % dests" edit must fail HERE, loudly, rather
    # than silently deleting the cross-shard overlap and voiding a whole certification run.
    _partitioned_env(monkeypatch, dests=64)
    shape = load_shape()
    identity = sum(1 for seq in range(512) if shape.destination_index(_msg(seq)) == seq % 64)
    # A bare modulo scores 512/512. A decorrelated mix scores ~1/64 of that by chance (~8).
    assert identity < 40, (
        "the selector is (or has reverted to) a bare `seq % dests` — see the block above"
    )


def test_selector_is_stable_across_pythonhashseed() -> None:
    # ⭐ THE CROSS-PROCESS PROOF. The shardcert fleet is N `serve --shard` SUBPROCESSES, each resolving the
    # selector independently. Python randomises str hashing per process (PYTHONHASHSEED), so a hash()-based
    # selector would give each shard a DIFFERENT seq->dest mapping: the lanes would silently skew and the
    # lane-scaling law would not hold. Run the real selector under three different hash seeds and require the
    # mapping to be IDENTICAL. (splitmix64 is pure integer arithmetic, so it cannot vary — this is the pin
    # that stops anyone "improving" it into hashlib-of-a-string or the builtin hash.)
    script = textwrap.dedent(
        """
        import os
        os.environ["MEFOR_SHARDCERT_SHARDS"] = "a"
        os.environ["MEFOR_SHARDCERT_DESTS"] = "64"
        os.environ["MEFOR_SHARDCERT_ROUTING"] = "partitioned"
        os.environ.pop("MEFOR_SHARDCERT_HANDLERS", None)
        os.environ.pop("MEFOR_SHARDCERT_DELIVERING", None)
        os.environ.pop("MEFOR_SHARDCERT_LANES_PER_SHARD", None)

        from messagefoundry.parsing.message import Message
        from harness.config.shardcert._shape import load_shape
        from harness.load.ids import SHARDCERT_IDS

        shape = load_shape()
        raw = (
            "MSH|^~\\\\&|SND|SF|RCV|RF|20260101000000||ADT^A01|MSG00001|P|2.5\\r"
            "EVN|A01|20260101000000\\r"
            "PID|1||1^^^MRN||DOE^JOHN"
        )
        out = []
        for seq in range(200):
            msg = Message.parse(raw)
            msg["MSH-10"] = SHARDCERT_IDS.format(seq)
            out.append(shape.destination_index(msg))
        print(",".join(str(d) for d in out))
        """
    )

    def _run(seed: str) -> str:
        # Drop any ambient shape env so the subprocess resolves the shape from the script alone.
        env = {k: v for k, v in os.environ.items() if not k.startswith("MEFOR_SHARDCERT_")}
        env["PYTHONHASHSEED"] = seed
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            check=True,
            env=env,
            cwd=_REPO_ROOT,
        )
        return proc.stdout.strip()

    seed0 = _run("0")
    seed1 = _run("1")
    seed2 = _run("12345")

    assert seed0, "the subprocess produced no mapping"
    assert seed0 == seed1 == seed2, (
        "the destination selector CHANGED with PYTHONHASHSEED — it is hashing a string. Across the N shard "
        "subprocesses that silently skews every lane."
    )


# =====================================================================================================
# (c2) ⭐ THE K SENDER PROCESSES MUST NOT EMIT THE SAME SEQ STREAM.
# =====================================================================================================


def test_driver_workers_get_disjoint_seq_space(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each `run_shardcert_driver_worker` builds its OWN Corpus in its OWN process, and a Corpus starts at
    # seq 0 — so unbased, ALL K workers emit the identical stream 0,1,2,…. That stamps the same control id on
    # K different messages AND phase-locks the partitioned selector (which derives the lane FROM the seq): all
    # K workers would target the SAME lane at the same instant, walking the lane space K-deep in bursts rather
    # than spreading K concurrent messages over K distinct lanes. Long-run per-lane load is unchanged, so no
    # headline moves — but the bursty arrival aliases against the soak's 0.5s in_pipeline sampler.
    #
    # The seq bases must therefore be DISJOINT across workers, and the selector must spread them.
    dests = 64
    _partitioned_env(monkeypatch, dests=dests)
    shape = load_shape()

    k = 4
    inflight_lanes = []
    for step in range(
        200
    ):  # the workers march in near-lockstep: each is at ~the same offset at time t
        lanes = {
            shape.destination_index(
                _msg(j * SEQ_BASE_STRIDE + step)
            )  # worker j's seq at this instant
            for j in range(k)
        }
        inflight_lanes.append(len(lanes))

    # With disjoint bases the K concurrent messages land on K DISTINCT lanes almost always (collisions are
    # birthday-chance at 4-of-64). Phase-locked (all bases 0) this would be 1, every single time.
    assert sum(inflight_lanes) / len(inflight_lanes) > 3.5, (
        "the K sender processes are phase-locked onto the same lane — check the corpus seq_base"
    )
    assert min(inflight_lanes) >= 2

    # And the control ids never collide across workers (they did when every corpus started at 0).
    ids = {SHARDCERT_IDS.format(j * SEQ_BASE_STRIDE + step) for j in range(k) for step in range(50)}
    assert len(ids) == k * 50
    # ...and every one still fits the 12-digit MSH-10 width the router parses back.
    for cid in ids:
        assert len(cid) == len("SC") + SHARDCERT_IDS.width
        assert SHARDCERT_IDS.parse(cid) is not None


# =====================================================================================================
# (d) ⭐ FAIL-LOUD on an undecodable control id — never a silent fallback to destination 0.
# =====================================================================================================


@pytest.mark.parametrize(
    "control_id",
    [
        "MSG00001",  # not one of ours (no SC prefix)
        "",  # unstamped MSH-10
        "SC",  # prefix with no digits
        "SCABCDEFGHIJKL",  # prefix with non-digits
        "XX000000000042",  # foreign prefix
    ],
)
def test_undecodable_control_id_raises_never_falls_back_to_dest_zero(
    monkeypatch: pytest.MonkeyPatch, control_id: str
) -> None:
    # ⭐ A silent `return 0` here would funnel ALL traffic onto ONE FIFO lane and manufacture the very
    # ~16 msg/s plateau this mode exists to disprove — while still reporting a clean PASS. It must RAISE.
    _partitioned_env(monkeypatch, dests=8)
    shape = load_shape()
    msg = Message.parse(_SAMPLE_HL7)
    msg["MSH-10"] = control_id

    with pytest.raises(ValueError, match="Refusing to fall back to destination 0"):
        shape.destination_index(msg)


def test_raw_message_raises_in_partitioned(monkeypatch: pytest.MonkeyPatch) -> None:
    # A RawMessage carries no MSH-10 to key on. Same rule: raise, never funnel to lane 0.
    _partitioned_env(monkeypatch, dests=8)
    shape = load_shape()
    with pytest.raises(ValueError, match="Refusing to fall back to destination 0"):
        shape.destination_index(RawMessage('{"not": "hl7"}', "json"))


def test_router_propagates_the_fail_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    # The ROUTER must not swallow it either — the raise has to reach the engine's error/dead-letter path so
    # the run breaks the no-loss identity and VOIDS loudly instead of publishing a fabricated ceiling.
    _partitioned_env(monkeypatch, dests=8)
    reg = load_config(_CONFIG_DIR)
    bad = Message.parse(_SAMPLE_HL7)  # MSH-10 is "MSG00001" — not a harness seq
    with pytest.raises(ValueError, match="Refusing to fall back to destination 0"):
        reg.routers["route_a"](bad)


def test_the_control_id_scheme_is_a_one_place_constant() -> None:
    # The prefix is now a SENDER↔ROUTER contract (the graph decodes what the sender stamps) across PROCESS
    # boundaries. It used to be re-spelled as `ControlIds(prefix="SC")` in FIVE places (four senders + the
    # shape); change four of the five and the router raises on every message, voiding the whole run. There is
    # now exactly ONE definition (harness.load.ids.SHARDCERT_IDS) and everything imports it.
    for module in ("harness/load/shardcert.py", "harness/config/shardcert/_shape.py"):
        src = (_REPO_ROOT / module).read_text(encoding="utf-8")
        assert 'ControlIds(prefix="SC")' not in src, (
            f"{module} re-spells the shardcert control-id scheme — import SHARDCERT_IDS instead"
        )
        assert "SHARDCERT_IDS" in src, f"{module} does not use the one-place SHARDCERT_IDS constant"

    # And it really is the scheme the router decodes: a sender-formatted id round-trips to its seq.
    assert SHARDCERT_IDS.parse(SHARDCERT_IDS.format(12_345)) == 12_345


# =====================================================================================================
# (e) ACCOUNTING: fan-out is 1; dests stays L; the no-loss identity holds.
# =====================================================================================================


def test_partitioned_accounting_is_fanout_one(monkeypatch: pytest.MonkeyPatch) -> None:
    # ⭐ `handlers` is OVERLOADED: created (L) vs selected (1). Every cost/accounting consumer needs SELECTED.
    dests = 64
    _partitioned_env(monkeypatch, dests=dests)
    shape = load_shape()

    assert shape.dests == dests  # topology / lane count / sink port-band width — UNCHANGED
    assert shape.handlers == dests  # GRAPH BUILD: every handler owns a destination
    assert shape.delivering == dests  # GRAPH BUILD: (ditto — never used as the fan-out here)
    assert shape.selected_handlers == 1  # ACCOUNTING: the router selects ONE
    assert shape.fanout == 1  # ACCOUNTING: THE fan-out
    assert shape.events_per_message == 2  # 1 receipt + 1 delivery
    assert shape.txn_per_message == 7  # 3 + 2(1) + 2(1) — vs 3 + 2(64) + 2(64) = 259 broadcast

    # The pair the driver REPORTS / posts to the drive box.
    assert reported_shape(shape.handlers, shape.delivering, PARTITIONED) == (1, 1)


def test_no_loss_identity_holds_in_partitioned() -> None:
    # ⭐ The sink no-loss identity is S == A * delivering. In partitioned each message is exactly ONE
    # delivery, so the expectation must be A * 1 == A. Keyed on the BUILD pair (64) it would expect 64*A and
    # read FALSE LOSS on every healthy rung.
    acked = 5_000
    r_handlers, r_delivering = reported_shape(64, 64, PARTITIONED)
    assert (r_handlers, r_delivering) == (1, 1)

    expected = (
        acked * r_delivering
    )  # ShardCertRung.outbound_delivered_expected() / TwoBoxReport.no_loss
    assert expected == acked

    # The two headline figures the 45M/day claim is made of.
    events_per_message = 1 + r_delivering
    txn_per_message = 3 + 2 * r_handlers + 2 * r_delivering
    assert events_per_message == 2
    assert txn_per_message == 7


def test_reported_handlers_keep_the_a4b_guard_armed() -> None:
    # ⭐ THE SUBTLE ONE. observers_inconclusive computes `free = acked * max(0, handlers - delivering)` — a
    # budget of routed-row strands it will FORGIVE. Reporting the CREATED handler count (64) with a fan-out
    # of 1 hands the guard a 63x-acked budget and effectively DISARMS it: a disarmed guard is how a
    # fabricated ceiling gets published. The DERIVED pair (1, 1) gives free == 0 — the pre-#209 behaviour
    # the guard was written for.
    acked, sink_received = 1_000, 1_000

    # A sink that is FULLY lossless (S >= A*D) while the engine reports stranded rows is a hard
    # contradiction that no handler budget may explain ⇒ INCONCLUSIVE.
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=acked,
            sink_received=sink_received,
            delivering=1,  # DERIVED fan-out
            handlers=1,  # DERIVED selected  ⇒ free = 0, guard ARMED
            engine_stranded=50,
            engine_dead_total=0,
        )
        is True
    )

    # The BUG this pins: the same rung, reported with the CREATED handler count, still trips (a) here — but
    # the `free` budget it would hand the UNDER-count branch is 63 * acked, which is the disarming.
    free_derived = acked * max(0, 1 - 1)
    free_created = acked * max(0, 64 - 1)
    assert free_derived == 0
    assert free_created == 63_000  # 63x acked of forgiven strands — the guard, effectively off

    # A healthy partitioned rung (engine clean, sink exactly A*1) must NOT be flagged.
    assert (
        observers_inconclusive(
            engine_ok=True,
            acked=acked,
            sink_received=acked * 1,
            delivering=1,
            handlers=1,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is False
    )


# --- BACKLOG #229: the pure per-stage strand summariser ---------------------------------------------
#
# `_summarize_queue_rows` factors the `GROUP BY stage, status` reduction out of `_queue_breakdown` so it is
# unit-testable without a DB. It must (1) preserve the all-stage `nonterminal` / `dead_total` totals the
# store-truth verdict gates on, (2) split the DELIVERY-BLOCKING rows (non-terminal AND dead, jointly) by the
# stage they are stuck at — the per-stage weights the A4b permit needs — and (3) keep the exact summary
# string. The per-stage split must SUM to `nonterminal + dead_total` (every row sits at exactly one stage).


def test_summarize_queue_rows_splits_nonterminal_and_dead_per_stage() -> None:
    # A synthetic scan spanning all three stages and both blocking kinds. Statuses: received/pending/inflight
    # are non-terminal (delivery-blocking); dead is terminal-but-blocking; done is terminal and NOT blocking.
    rows = [
        ("ingress", "received", 5),  # non-terminal at ingress
        ("ingress", "dead", 2),  # dead at ingress
        ("routed", "pending", 7),  # non-terminal at routed
        ("routed", "done", 100),  # terminal-done ⇒ blocks nothing
        ("outbound", "inflight", 3),  # non-terminal at outbound
        ("outbound", "dead", 4),  # dead at outbound
        ("outbound", "done", 900),  # terminal-done ⇒ blocks nothing
    ]
    qb = _summarize_queue_rows(rows)
    assert isinstance(qb, QueueBreakdown)
    # Totals: non-terminal = 5 + 7 + 3 = 15; dead = 2 + 4 = 6 (done rows excluded from both).
    assert qb.nonterminal == 15
    assert qb.dead_total == 6
    # Per-stage = (non-terminal + dead) at that stage.
    assert qb.ingress_stranded == 5 + 2  # 7
    assert qb.routed_stranded == 7  # only the pending row (done is not blocking)
    assert qb.outbound_stranded == 3 + 4  # 7
    # The split sums to the all-stage blocking total — the invariant the A4b permit relies on.
    assert (
        qb.ingress_stranded + qb.routed_stranded + qb.outbound_stranded
        == qb.nonterminal + qb.dead_total
    )
    # The summary string is preserved verbatim.
    assert qb.summary == (
        "QUEUE ingress/received=5 ingress/dead=2 routed/pending=7 routed/done=100 "
        "outbound/inflight=3 outbound/dead=4 outbound/done=900"
    )


def test_summarize_queue_rows_empty_and_all_terminal() -> None:
    # No rows at all ⇒ everything zero and the "<empty>" render.
    empty = _summarize_queue_rows([])
    assert empty == QueueBreakdown(0, 0, 0, 0, 0, "QUEUE <empty>")
    # A fully-drained store (only done rows) ⇒ zero blocking, no strands anywhere.
    drained = _summarize_queue_rows([("ingress", "done", 10), ("outbound", "done", 80)])
    assert drained.nonterminal == 0 and drained.dead_total == 0
    assert drained.ingress_stranded == drained.routed_stranded == drained.outbound_stranded == 0


def test_summarize_queue_rows_is_case_insensitive_on_status_and_stage() -> None:
    # Statuses are stored lower-case, but the reducer lower-cases defensively so a collation quirk cannot
    # silently miscount a DEAD row as blocking-or-not.
    qb = _summarize_queue_rows([("INGRESS", "DEAD", 3), ("Routed", "Pending", 2)])
    assert qb.dead_total == 3
    assert qb.nonterminal == 2
    assert qb.ingress_stranded == 3
    assert qb.routed_stranded == 2
    assert qb.outbound_stranded == 0


def test_dests_stays_the_lane_count_in_partitioned(monkeypatch: pytest.MonkeyPatch) -> None:
    # The whole sink/port-band/partition layer keys on `dests` (the LANE count), and it must NOT collapse to
    # the fan-out: the graph still declares L outbound connections and the sink still binds an L-wide band.
    dests = 32
    _partitioned_env(monkeypatch, dests=dests)
    shape = load_shape()
    reg = load_config(_CONFIG_DIR)

    assert len(reg.outbound) == dests
    assert shape.dests == dests
    # sink_endpoint still tiles across the band (topology untouched by the routing mode).
    monkeypatch.setenv("MEFOR_SHARDCERT_SINK_PORTS", str(dests))
    monkeypatch.setenv("MEFOR_SHARDCERT_SINK_PORT", "3700")
    banded = load_shape()
    assert [banded.sink_endpoint(d)[1] for d in range(4)] == [3700, 3701, 3702, 3703]


# =====================================================================================================
# (f) ⭐ FIFO: the per-lane check is HIGH-WATER MONOTONE, not DENSE.
# =====================================================================================================
#
# THE DESIGN RISK, settled by reading the tracker: FailoverTracker.on_delivery compares each NEW seq against
# the lane's running high-water (`seq < prev` ⇒ inversion). There is NO consecutive-seq/dense check anywhere.
# The lane is keyed on the DESTINATION (sink.py passes MSH-6 = fifo_lane(shard, dest, lane)).
#
# Under BROADCAST each lane already sees a STRIDED subsequence today (the drive loop round-robins ONE shared
# monotonic Corpus across the K = N*lanes sender connections, so band b only ever sees seqs = b mod K) — so
# density has never been required, and every published green run proves it.
#
# Under PARTITIONED lane (shard, lane, dest j) sees {seq : seq = b mod K AND select(seq) == j} — still a
# subsequence of a strictly increasing sequence, hence strictly increasing ⇒ 0 inversions; and each seq maps
# to exactly ONE dest ⇒ 0 repeats.
#
# These tests LOCK the monotone semantics so a future "tighten this to dense" edit fails here rather than
# voiding a whole partitioned run.


def test_strided_per_lane_subsequence_reads_zero_inversions() -> None:
    # ⭐ The partitioned lane's view: destination j sees seq = j, j+L, j+2L, ... — NON-DENSE but MONOTONE.
    lanes, stride = 64, 64
    tracker = FailoverTracker()
    for j in range(lanes):
        lane = f"a_{j:02d}"
        for k in range(50):
            tracker.on_delivery(lane, j + k * stride)  # 3, 67, 131, ... for j=3

    assert tracker.lane_inversions == 0, (
        "a strided (non-dense) monotone subsequence read as an inversion"
    )
    assert tracker.lane_repeats == 0
    assert tracker.lanes_observed == lanes  # non-vacuous: well above the >= 2 bar


def test_full_partitioned_traffic_pattern_reads_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    # The REAL pattern, end to end, through the REAL selector: K sender bands round-robining one monotonic
    # seq stream, each message landing on exactly ONE destination. Every (shard, dest) key must read clean —
    # and the lane space must be FULL (K x L), which is the aliasing guard restated in FIFO terms.
    shards, dests = ("a", "b", "c", "d"), 64
    _partitioned_env(monkeypatch, dests=dests, shards=",".join(shards))
    shape = load_shape()
    tracker = FailoverTracker()

    for seq in range(20_000):
        shard = shards[
            seq % len(shards)
        ]  # the drive loop's round-robin over the persistent connections
        dest = shape.destination_index(_msg(seq))  # the partitioned selector
        tracker.on_delivery(f"{shard}_{dest:02d}", seq)

    assert tracker.lane_inversions == 0
    assert tracker.lane_repeats == 0  # each seq -> exactly ONE dest ⇒ no lane ever sees a seq twice
    # NOT merely ">= 2": the FULL K x L lane space. This is the assertion whose absence let the aliasing
    # defect through — under `seq % dests` it reads 64 here, not 256, and a `>= 2` bar sails right past it.
    assert tracker.lanes_observed == len(shards) * dests == 256


def test_the_fifo_check_can_still_fail() -> None:
    # The check must remain CAPABLE of failing — a test that only ever passes proves nothing. A genuinely
    # OUT-OF-ORDER arrival (a NEW seq below the lane's high-water) is a true FIFO break.
    tracker = FailoverTracker()
    for seq in (3, 67, 131, 195):
        tracker.on_delivery("a_03", seq)
    assert tracker.lane_inversions == 0

    tracker.on_delivery("a_03", 99)  # NEW seq, below the high-water of 195 — a real inversion
    assert tracker.lane_inversions == 1

    # And an already-seen seq is a REPEAT (an at-least-once re-delivery), never an inversion.
    tracker.on_delivery("a_03", 131)
    assert tracker.lane_repeats == 1
    assert tracker.lane_inversions == 1


def test_lane_key_is_the_destination_not_the_sender_band() -> None:
    # Two sender bands (shards) fanning into the SAME destination are DIFFERENT lane keys — they have no
    # defined mutual order, and merging them would false-positive as inversions. This is why fifo_lane keys
    # on (source shard, [lane,] dest) and not on the shared destination alone.
    tracker = FailoverTracker()
    tracker.on_delivery("a_00", 100)
    tracker.on_delivery("b_00", 5)  # a DIFFERENT lane — not an inversion of a_00's high-water
    assert tracker.lane_inversions == 0
    assert tracker.lanes_observed == 2
    assert tracker.lane_keys == ("a_00", "b_00")


def test_msh6_is_load_bearing_for_the_fifo_verdict() -> None:
    # HAZARD PIN: the sink passes `peek.receiving_facility or ""`. If MSH-6 were ever left unstamped (the
    # `cheap` transform), EVERY delivery collapses onto the lane key "" — lanes_observed == 1 and the
    # per-lane ordering check goes VACUOUS while still reporting PASS. The >= 2 non-vacuity bar is what
    # catches it, so partitioned must keep transform=edit.
    tracker = FailoverTracker()
    for seq in range(100):
        tracker.on_delivery("", seq)  # every delivery, unstamped
    assert tracker.lane_inversions == 0  # "clean"...
    assert (
        tracker.lanes_observed == 1
    )  # ...but VACUOUS — this is what the >= 2 bar exists to reject
    assert tracker.lane_keys == ("",)


# =====================================================================================================
# Shape-level sanity: the dataclass is constructible directly (no env) and the modes behave.
# =====================================================================================================


def _shape(routing: str, *, dests: int = 8) -> ShardCertShape:
    return ShardCertShape(
        shards=("a",),
        inbound_base=3600,
        dests=dests,
        sink_host="127.0.0.1",
        sink_port=3700,
        sink_ports=1,
        transform="edit",
        persistent=False,
        lanes_per_shard=1,
        handlers=dests,
        delivering=dests,
        routing=routing,
    )


def test_shape_defaults_to_broadcast_when_unspecified() -> None:
    # The dataclass default must be BROADCAST — a shape constructed without naming a mode is the old one.
    shape = ShardCertShape(
        shards=("a",),
        inbound_base=3600,
        dests=8,
        sink_host="127.0.0.1",
        sink_port=3700,
        sink_ports=1,
        transform="edit",
        persistent=False,
        lanes_per_shard=1,
        handlers=8,
        delivering=8,
    )
    assert shape.routing == BROADCAST
    assert shape.partitioned is False
    assert shape.txn_per_message == 35 and shape.events_per_message == 9


def test_mode_flips_only_the_accounting_not_the_topology() -> None:
    b, p = _shape(BROADCAST, dests=64), _shape(PARTITIONED, dests=64)
    assert b.dests == p.dests == 64  # topology identical
    assert b.handlers == p.handlers == 64  # graph build identical
    assert (b.selected_handlers, b.fanout) == (64, 64)
    assert (p.selected_handlers, p.fanout) == (1, 1)
    assert b.txn_per_message == 259 and b.events_per_message == 65
    assert p.txn_per_message == 7 and p.events_per_message == 2
