# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""PARTITIONED-FANOUT routing — partitioned's high-ingress shape, but with a real fan-out D>1.

``partitioned`` (see test_shardcert_partitioned.py) selects ONE handler per message → one delivery →
events/msg = 2. ``partitioned-fanout`` keeps that one-lane-per-pick ingress scaling but the router selects
**D DISTINCT** owner handlers (D = ``delivering``), so each accepted message delivers D copies:

    ingress          ~= dests / (D * cycle)   (D of the dests lanes occupied per message)
    events/s         = ingress * (1 + D)

This is the shape the D≈4 certification soak needs to drive ingress high enough to reach the engine
ceiling at a real fan-out — the one topology the earlier D=1 soaks could not express.

The pins below guard the same things the D=1 tests do, plus the two the fan-out introduces:

* **D DISTINCT dests per message** — :meth:`destination_indices` (a splitmix64 partial Fisher-Yates) must
  return D *different* lanes, never the same twice. A repeat would under-deliver and read FALSE LOSS
  against ``S == A * D``.
* **The accounting is (D, D)** — ``fanout == selected_handlers == D`` (there are NO self-filtering handlers,
  so the A4b ``free = acked*(H - D)`` budget is 0 and the guard stays armed). ``reported_shape`` returns
  ``(D, D)``; ``events/msg = 1 + D``; ``txn/msg = 3 + 2D + 2D``.
* **Byte-identity at D=1** — the partial Fisher-Yates' i=0 draw is exactly ``_mix64(seq) % dests``, so the
  algorithm degenerates to the singular selector; plain ``partitioned`` keeps its own path untouched.
* **The same fail-loud / decorrelation / cross-process determinism** the D=1 selector has.
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
    PARTITIONED_FANOUT,
    ShardCertShape,
    load_shape,
    reported_shape,
    shared_dest_name,
)
from harness.load.failover_track import FailoverTracker
from harness.load.ids import SHARDCERT_IDS
from harness.load.shardcert import (
    FanoutLaneHeadroomTooLow,
    InboundBandTooNarrow,
    check_fanout_lane_headroom,
    check_inbound_bands,
    fanout_lane_warning,
)
from harness.load.shardcert_ladder import observers_inconclusive
from messagefoundry.config.wiring import Registry, Send, load_config
from messagefoundry.parsing.message import Message, RawMessage

_CONFIG_DIR = "harness/config/shardcert"
_REPO_ROOT = Path(__file__).resolve().parent.parent

_SAMPLE_HL7 = (
    "MSH|^~\\&|SND|SF|RCV|RF|20260101000000||ADT^A01|MSG00001|P|2.5\r"
    "EVN|A01|20260101000000\r"
    "PID|1||1^^^MRN||DOE^JOHN"
)


def _msg(seq: int) -> Message:
    msg = Message.parse(_SAMPLE_HL7)
    msg["MSH-10"] = SHARDCERT_IDS.format(seq)
    return msg


def _route(reg: Registry, name: str, msg: Message) -> list[str]:
    selected = reg.routers[name](msg)
    assert isinstance(selected, list), f"router {name} returned {selected!r}, expected a list"
    return selected


def _fanout_env(
    monkeypatch: pytest.MonkeyPatch, *, dests: int, fanout: int, shards: str = "a"
) -> None:
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", shards)
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", str(dests))
    monkeypatch.delenv("MEFOR_SHARDCERT_HANDLERS", raising=False)  # defaults to dests
    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", str(fanout))  # DELIVERING carries D
    monkeypatch.setenv("MEFOR_SHARDCERT_ROUTING", PARTITIONED_FANOUT)


def _direct_shape(
    routing: str, *, dests: int, delivering: int, handlers: int | None = None
) -> ShardCertShape:
    """Construct the dataclass directly (bypassing load_shape's validation) so we can probe shapes the CLI
    forbids — e.g. a partitioned-fanout shape at delivering=1 to prove the D=1 algorithm identity."""
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
        handlers=dests if handlers is None else handlers,
        delivering=delivering,
        routing=routing,
    )


# =====================================================================================================
# (a) ⭐ D DISTINCT destinations per message — the core fan-out guarantee.
# =====================================================================================================


@pytest.mark.parametrize("fanout", [2, 3, 4])
@pytest.mark.parametrize("dests", [8, 64, 176])
def test_destination_indices_are_D_distinct_and_in_range(
    monkeypatch: pytest.MonkeyPatch, dests: int, fanout: int
) -> None:
    # For EVERY message: exactly D indices, ALL distinct, ALL in [0, dests). A repeat is the false-loss bug.
    _fanout_env(monkeypatch, dests=dests, fanout=fanout)
    shape = load_shape()
    for seq in range(5_000):
        picks = shape.destination_indices(_msg(seq))
        assert len(picks) == fanout, f"seq {seq}: {len(picks)} picks, expected {fanout}"
        assert len(set(picks)) == fanout, (
            f"seq {seq}: repeated dest in {picks} (would under-deliver)"
        )
        assert all(0 <= d < dests for d in picks), f"seq {seq}: out-of-range dest in {picks}"


def test_destination_indices_at_fanout_one_equals_the_singular_selector() -> None:
    # ⭐ BYTE-IDENTITY at D=1: the partial Fisher-Yates i=0 draw is _mix64(seq) % dests, so the plural
    # returns exactly [destination_index]. (load_shape forbids D=1 for the CLI; probe it directly.)
    shape = _direct_shape(PARTITIONED_FANOUT, dests=64, delivering=1)
    assert shape.fanout == 1
    for seq in range(500):
        assert shape.destination_indices(_msg(seq)) == [shape.destination_index(_msg(seq))]


def test_fanout_lane_load_is_balanced_within_tolerance(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each of the dests lanes is hit ~ n*D/dests times; the mixer keeps it statistically uniform (an
    # unbalanced selector would overload a lane and depress the measured aggregate — a fake ceiling).
    dests, fanout = 64, 4
    _fanout_env(monkeypatch, dests=dests, fanout=fanout)
    shape = load_shape()
    n = dests * 750
    counts: Counter[int] = Counter()
    for seq in range(n):
        counts.update(shape.destination_indices(_msg(seq)))
    assert len(counts) == dests, "some lane was never selected"
    mean = n * fanout / dests
    worst = max(abs(c - mean) / mean for c in counts.values())
    assert worst < 0.15, f"lane load deviates {worst:.1%} from uniform"


# =====================================================================================================
# (b) ⭐ ACCOUNTING: fanout == selected == D; the no-loss identity is S == A*D; the A4b guard stays armed.
# =====================================================================================================


def test_fanout_accounting_is_D_D(monkeypatch: pytest.MonkeyPatch) -> None:
    dests, fanout = 176, 4
    _fanout_env(monkeypatch, dests=dests, fanout=fanout)
    shape = load_shape()

    assert shape.dests == dests  # topology / lane count — UNCHANGED
    assert shape.handlers == dests  # GRAPH BUILD: one owner per destination
    assert shape.delivering == fanout  # DELIVERING carries D
    assert shape.selected_handlers == fanout  # ACCOUNTING: the router selects D
    assert shape.fanout == fanout  # ACCOUNTING: THE fan-out
    assert shape.events_per_message == 1 + fanout  # 1 receipt + D deliveries
    assert shape.txn_per_message == 3 + 2 * fanout + 2 * fanout  # 3 + 2D + 2D

    # No handler self-filters — every built handler owns its dest.
    assert [shape.delivers_to(j) for j in range(dests)] == list(range(dests))

    # The pair the driver REPORTS / posts to the drive box.
    assert reported_shape(shape.handlers, shape.delivering, PARTITIONED_FANOUT) == (fanout, fanout)


def test_no_loss_identity_is_acked_times_D() -> None:
    # ⭐ S == A * delivering. Under fanout each message is D deliveries, so the expectation is A*D — NOT A
    # (that reads false loss on every healthy rung) and NOT A*dests (over-expects).
    acked, fanout = 5_000, 4
    r_handlers, r_delivering = reported_shape(176, fanout, PARTITIONED_FANOUT)
    assert (r_handlers, r_delivering) == (fanout, fanout)
    assert acked * r_delivering == acked * fanout  # outbound_delivered_expected
    assert 1 + r_delivering == 5  # events/msg
    assert 3 + 2 * r_handlers + 2 * r_delivering == 19  # txn/msg


def test_a4b_guard_stays_armed_under_fanout() -> None:
    # ⭐ free = acked * max(0, handlers - delivering). Under fanout H == D == 4 ⇒ free == 0, so the
    # cross-observer over-count guard is armed (there are no self-filtering handlers to forgive). Reporting
    # the CREATED count (dests) instead would hand it a (dests-D)*acked budget and DISARM it.
    acked = 1_000
    r_handlers, r_delivering = reported_shape(176, 4, PARTITIONED_FANOUT)
    assert acked * max(0, r_handlers - r_delivering) == 0

    # A lossless sink (S >= A*D) with engine-reported stranded rows is a contradiction ⇒ INCONCLUSIVE,
    # and the guard must still fire (it is not disarmed).
    assert (
        observers_inconclusive(
            engine_ok=False,
            acked=acked,
            sink_received=acked * r_delivering,
            delivering=r_delivering,
            handlers=r_handlers,
            engine_stranded=50,
            engine_dead_total=0,
        )
        is True
    )
    # A healthy fanout rung (engine clean, sink exactly A*D) must NOT be flagged.
    assert (
        observers_inconclusive(
            engine_ok=True,
            acked=acked,
            sink_received=acked * r_delivering,
            delivering=r_delivering,
            handlers=r_handlers,
            engine_stranded=0,
            engine_dead_total=0,
        )
        is False
    )


# =====================================================================================================
# (c) ⭐ THE ROUTER selects D DISTINCT owner handlers, each delivering to a distinct destination.
# =====================================================================================================


def test_router_selects_D_distinct_owner_handlers(monkeypatch: pytest.MonkeyPatch) -> None:
    dests, fanout = 16, 4
    _fanout_env(monkeypatch, dests=dests, fanout=fanout)
    shape = load_shape()
    reg = load_config(_CONFIG_DIR)

    assert len(reg.handlers) == dests  # one owner per destination built
    assert len(reg.outbound) == dests

    for seq in range(200):
        want = shape.destination_indices(_msg(seq))
        got = _route(reg, "route_a", _msg(seq))
        assert got == [f"H_a_{d:02d}" for d in want]
        assert len(set(got)) == fanout  # distinct handlers

    # End to end: each selected handler really Sends to a DISTINCT shared destination.
    for seq in (0, 1, 7, 63, 175):
        names = _route(reg, "route_a", _msg(seq))
        targets = set()
        for name in names:
            out = reg.handlers[name](_msg(seq))
            assert isinstance(out, Send)
            targets.add(out.to)
        assert len(targets) == fanout
        assert targets == {shared_dest_name(d) for d in shape.destination_indices(_msg(seq))}


def test_traffic_spreads_across_all_lanes_not_a_subset(monkeypatch: pytest.MonkeyPatch) -> None:
    # Every lane must be reachable — fan-out must not funnel onto D fixed lanes (a plateau).
    dests, fanout = 32, 4
    _fanout_env(monkeypatch, dests=dests, fanout=fanout)
    reg = load_config(_CONFIG_DIR)
    reached: set[str] = set()
    for seq in range(dests * 60):
        reached.update(_route(reg, "route_a", _msg(seq)))
    assert len(reached) == dests, "traffic funnelled onto a subset of lanes"


# =====================================================================================================
# (d) ⭐ CROSS-SHARD OVERLAP + DECORRELATION preserved under fan-out.
# =====================================================================================================


def _fanout_lane_keys(
    shape: ShardCertShape, *, shards: tuple[str, ...], n: int
) -> tuple[set[tuple[str, int]], dict[int, set[str]]]:
    """Replay the real sender rule (band = seq % K) against the fan-out selector: each message contributes
    D (shard, dest) FIFO lane keys."""
    k = len(shards)
    keys: set[tuple[str, int]] = set()
    feeders: dict[int, set[str]] = {d: set() for d in range(shape.dests)}
    for seq in range(n):
        shard = shards[seq % k]
        for dest in shape.destination_indices(_msg(seq)):
            keys.add((shard, dest))
            feeders[dest].add(shard)
    return keys, feeders


def test_fanout_preserves_cross_shard_overlap(monkeypatch: pytest.MonkeyPatch) -> None:
    # The ADR 0073 premise: every destination lane produced-into by MORE than one shard, and the full K×L
    # FIFO lane space reached — must survive the D-distinct multi-select, not collapse to one feeder/lane.
    shards, dests, fanout = ("a", "b", "c", "d"), 64, 4
    _fanout_env(monkeypatch, dests=dests, fanout=fanout, shards=",".join(shards))
    shape = load_shape()
    keys, feeders = _fanout_lane_keys(shape, shards=shards, n=48_000)
    thin = {d: sorted(f) for d, f in feeders.items() if len(f) < 2}
    assert not thin, f"destinations fed by a single shard: {thin}"
    assert all(f == set(shards) for f in feeders.values())
    assert len(keys) == len(shards) * dests == 256


def test_fanout_selector_is_stable_across_pythonhashseed() -> None:
    # ⭐ Cross-process determinism: the N serve --shard subprocesses must compute the identical seq→[dests]
    # map. splitmix64 is pure integer arithmetic (no hash/PYTHONHASHSEED). Run under three seeds; require
    # identical output.
    script = textwrap.dedent(
        """
        import os
        os.environ["MEFOR_SHARDCERT_SHARDS"] = "a"
        os.environ["MEFOR_SHARDCERT_DESTS"] = "64"
        os.environ["MEFOR_SHARDCERT_DELIVERING"] = "4"
        os.environ["MEFOR_SHARDCERT_ROUTING"] = "partitioned-fanout"
        os.environ.pop("MEFOR_SHARDCERT_HANDLERS", None)
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
            out.append("-".join(str(d) for d in shape.destination_indices(msg)))
        print(",".join(out))
        """
    )

    def _run(seed: str) -> str:
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

    seed0, seed1, seed2 = _run("0"), _run("1"), _run("12345")
    assert seed0, "the subprocess produced no mapping"
    assert seed0 == seed1 == seed2, (
        "the fan-out selector CHANGED with PYTHONHASHSEED — it is hashing a string"
    )


# =====================================================================================================
# (e) ⭐ FAIL-LOUD on an undecodable control id — never a silent fallback to destination 0.
# =====================================================================================================


@pytest.mark.parametrize("control_id", ["MSG00001", "", "SC", "SCABCDEFGHIJKL", "XX000000000042"])
def test_fanout_undecodable_control_id_raises(
    monkeypatch: pytest.MonkeyPatch, control_id: str
) -> None:
    _fanout_env(monkeypatch, dests=8, fanout=4)
    shape = load_shape()
    msg = Message.parse(_SAMPLE_HL7)
    msg["MSH-10"] = control_id
    with pytest.raises(ValueError, match="Refusing to fall back to destination 0"):
        shape.destination_indices(msg)


def test_fanout_raw_message_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    _fanout_env(monkeypatch, dests=8, fanout=4)
    shape = load_shape()
    with pytest.raises(ValueError, match="Refusing to fall back to destination 0"):
        shape.destination_indices(RawMessage('{"not": "hl7"}', "json"))


def test_fanout_router_propagates_the_fail_loud(monkeypatch: pytest.MonkeyPatch) -> None:
    _fanout_env(monkeypatch, dests=8, fanout=4)
    reg = load_config(_CONFIG_DIR)
    bad = Message.parse(_SAMPLE_HL7)  # MSH-10 = "MSG00001" — not a harness seq
    with pytest.raises(ValueError, match="Refusing to fall back to destination 0"):
        reg.routers["route_a"](bad)


# =====================================================================================================
# (f) ⭐ LOAD_SHAPE validation — the authority; fail loud, never clamp.
# =====================================================================================================


def test_load_shape_accepts_valid_fanout(monkeypatch: pytest.MonkeyPatch) -> None:
    _fanout_env(monkeypatch, dests=176, fanout=4)
    shape = load_shape()
    assert shape.routing == PARTITIONED_FANOUT
    assert shape.partitioned_fanout is True
    assert shape.partitioned is False  # STRICTLY the D=1 shape
    assert shape.any_partitioned is True
    assert (shape.fanout, shape.selected_handlers) == (4, 4)


def test_load_shape_rejects_fanout_below_two(monkeypatch: pytest.MonkeyPatch) -> None:
    _fanout_env(monkeypatch, dests=8, fanout=1)  # D=1 is plain partitioned
    with pytest.raises(ValueError, match="needs a real fan-out DELIVERING >= 2"):
        load_shape()


def test_load_shape_rejects_fanout_at_or_above_dests(monkeypatch: pytest.MonkeyPatch) -> None:
    # D >= dests fans every message to ALL lanes ⇒ re-caps ingress (use broadcast). Both D==dests and
    # D>dests hit the same fail-loud gate.
    for fanout in (8, 9):
        _fanout_env(monkeypatch, dests=8, fanout=fanout)
        with pytest.raises(ValueError, match="needs DELIVERING < DESTS"):
            load_shape()


def test_load_shape_rejects_unset_delivering_under_fanout(monkeypatch: pytest.MonkeyPatch) -> None:
    # ⭐ THE ENV-PATH FAIL-LOUD (adversarial review): the CLI requires --delivering, but a direct `serve`
    # with ROUTING=partitioned-fanout and no DELIVERING would default D to dests and silently fan to ALL
    # lanes — the ~16 msg/s re-cap this mode disproves. load_shape must refuse it, matching the CLI.
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a")
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "64")
    monkeypatch.delenv("MEFOR_SHARDCERT_HANDLERS", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_DELIVERING", raising=False)  # UNSET — the hazard
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_ROUTING", PARTITIONED_FANOUT)
    with pytest.raises(ValueError, match="REQUIRES MEFOR_SHARDCERT_DELIVERING"):
        load_shape()


def test_load_shape_rejects_handlers_override_under_fanout(monkeypatch: pytest.MonkeyPatch) -> None:
    _fanout_env(monkeypatch, dests=8, fanout=4)
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", "20")  # a self-filtering hub is broadcast-only
    with pytest.raises(ValueError, match="builds one owner handler per destination"):
        load_shape()


# =====================================================================================================
# (g) ⭐ BYTE-IDENTITY: adding the mode disturbs neither broadcast nor plain partitioned.
# =====================================================================================================


def test_broadcast_and_partitioned_accounting_unchanged() -> None:
    # reported_shape for the OTHER two modes must be exactly what test_shardcert_partitioned.py pins.
    assert reported_shape(20, 4, BROADCAST) == (20, 4)  # build pair passes through
    assert reported_shape(64, 64, PARTITIONED) == (1, 1)  # D=1 pinned
    # A directly-built partitioned shape is still fanout=1 / selected=1 (not caught by the new branch).
    p = _direct_shape(PARTITIONED, dests=64, delivering=64)
    assert (p.fanout, p.selected_handlers) == (1, 1)
    assert (p.txn_per_message, p.events_per_message) == (7, 2)
    b = _direct_shape(BROADCAST, dests=64, delivering=64)
    assert (b.fanout, b.selected_handlers) == (64, 64)
    assert (b.txn_per_message, b.events_per_message) == (259, 65)


def test_partitioned_property_excludes_fanout() -> None:
    # The invariant graph.py + fanout depend on: `partitioned` is STRICTLY the D=1 mode, so partitioned-
    # fanout falls through to the D>1 router + fanout==delivering. If this ever loosened, fanout would pin
    # to 1 and every fanout run would silently read false loss.
    pf = _direct_shape(PARTITIONED_FANOUT, dests=64, delivering=4)
    assert pf.partitioned is False
    assert pf.partitioned_fanout is True
    assert pf.fanout == 4


# =====================================================================================================
# (h) ⭐ FIFO: each (shard, dest) lane still sees a strided monotone subsequence under fan-out.
# =====================================================================================================


def test_fanout_fifo_reads_clean(monkeypatch: pytest.MonkeyPatch) -> None:
    # Each message contributes D deliveries; each (shard, dest) lane still sees a strictly-increasing
    # subsequence of the seq stream (a seq is delivered to a lane at most once), so 0 inversions / 0 repeats.
    shards, dests, fanout = ("a", "b", "c", "d"), 64, 4
    _fanout_env(monkeypatch, dests=dests, fanout=fanout, shards=",".join(shards))
    shape = load_shape()
    tracker = FailoverTracker()
    for seq in range(20_000):
        shard = shards[seq % len(shards)]
        for dest in shape.destination_indices(_msg(seq)):
            tracker.on_delivery(f"{shard}_{dest:02d}", seq)
    assert tracker.lane_inversions == 0
    assert tracker.lane_repeats == 0  # a seq reaches any one lane at most once (distinct dests)
    assert tracker.lanes_observed == len(shards) * dests == 256


# =====================================================================================================
# (i) ⭐ FAN-OUT LANE-HEADROOM PRE-FLIGHT — the fake-wall guard neither G<L nor RungFidelity catches.
# =====================================================================================================
#
# Under fan-out D each message occupies D of the `dests` strict-FIFO lanes, so the effective outbound width
# is dests/D. If that drops below the inbound band count G, the OUTBOUND fan-out pool caps ingress and the
# run PLATEAUS on the bench lane cycle — losslessly (S==A*D holds), so it reads ADMISSIBLE/SUSTAINED and
# neither check_inbound_bands (G vs RAW dests) nor RungFidelity catches it. The balance is dests >= D*G.


def test_fanout_lane_headroom_passes_when_dests_ge_D_times_G() -> None:
    # shards=4, lanes_per_shard=9 => G=36; D=4 => need dests >= 144. Sized runs return no note.
    assert fanout_lane_warning(4, 9, dests=144, delivering=4) is None
    assert fanout_lane_warning(4, 9, dests=176, delivering=4) is None
    assert check_fanout_lane_headroom(4, 9, 176, 4, PARTITIONED_FANOUT, strict=True) is None


def test_fanout_lane_headroom_warns_and_refuses_when_undersized() -> None:
    # dests < D*G => the outbound fan-out lanes cap ingress, a fake plateau. WARN (record) by default;
    # RAISE under strict (a certification soak must refuse a shape that measures the bench, not the engine).
    note = fanout_lane_warning(4, 9, dests=64, delivering=4)  # 64 < 4*36 = 144
    assert note is not None and "FAN-OUT LANES NARROWER" in note
    assert "144" in note  # the D*G floor it tells the operator to reach
    assert check_fanout_lane_headroom(4, 9, 64, 4, PARTITIONED_FANOUT, strict=False) is not None
    with pytest.raises(FanoutLaneHeadroomTooLow, match="FAN-OUT LANES NARROWER"):
        check_fanout_lane_headroom(4, 9, 64, 4, PARTITIONED_FANOUT, strict=True)


def test_fanout_lane_headroom_is_a_noop_for_non_fanout_modes() -> None:
    # Broadcast/partitioned are fan-out 1; their balance is check_inbound_bands' G-vs-dests, not this. This
    # guard must NOT fire for them even at a dests the D*G math would trip — no double-warning.
    assert check_fanout_lane_headroom(4, 9, 8, 1, BROADCAST, strict=True) is None
    assert check_fanout_lane_headroom(4, 9, 8, 1, PARTITIONED, strict=True) is None


def test_fanout_pre_flight_is_wired_into_both_discovery_paths() -> None:
    # The pure guard is useless if unwired. Pin that BOTH the single-box AND two-box discovery paths call it
    # (the `filling`-gate lesson: a check live on one path and dead on the other is worse than none).
    src = (_REPO_ROOT / "harness/load/shardcert.py").read_text(encoding="utf-8")
    # 1 definition + 2 call sites.
    assert src.count("check_fanout_lane_headroom(") >= 3, (
        "the fan-out pre-flight is defined but not wired into both discovery paths"
    )


def test_strict_does_not_false_abort_a_well_sized_fanout_run() -> None:
    # ⭐ REGRESSION: the raw check_inbound_bands strict-raises on G < dests, but a well-sized fanout run
    # ALWAYS has dests >= D*G > G — so under --strict-inbound-bands the D-UNAWARE raw check would abort
    # EVERY fanout run before the D-aware check even runs. The fix gates the raw check's strict-raise off
    # under partitioned-fanout (the D-aware check supersedes it there).
    # (a) the false-positive the gating exists to suppress — the raw check DOES raise on a fanout shape:
    with pytest.raises(InboundBandTooNarrow):
        check_inbound_bands(
            4, 12, 256, strict=True
        )  # G=48 < dests=256, yet the fanout run is well-sized
    # (b) the D-aware check correctly PASSES that same shape (dests/D = 64 >= G = 48):
    assert check_fanout_lane_headroom(4, 12, 256, 4, PARTITIONED_FANOUT, strict=True) is None
    # (c) BOTH dispatch paths gate the raw check's strict off under fanout, so it can never abort a fanout
    # run — only the D-aware check can. (A grep pin, like the wired-into-both-paths test above.)
    src = (_REPO_ROOT / "harness/load/shardcert.py").read_text(encoding="utf-8")
    assert src.count("strict=strict_bands and routing != PARTITIONED_FANOUT") >= 2, (
        "check_inbound_bands must not strict-raise under partitioned-fanout at BOTH dispatch sites"
    )
