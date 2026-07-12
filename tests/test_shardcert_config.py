# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Shape + graph construction for the N-active engine-shard SIZING bench (ADR 0073).

Non-gated (no SQL Server): these build the ``harness/config/shardcert`` graph via the SAME
inbound()/outbound() factories the loader uses and inspect the resulting flat endpoint list — the
persistent-outbound knob (W1), the per-shard lane-count knob (many-thin-lanes), and the contiguous
port layout. The live 4-shard SS certification/sizing drive is gated in
``tests/test_shard_cert_sqlserver.py``.
"""

from __future__ import annotations

import pytest

from messagefoundry.config.wiring import Send, load_config
from messagefoundry.parsing.message import Message

from harness.config.shardcert._shape import (
    apply_transform,
    fifo_lane,
    load_shape,
    shared_dest_name,
)

_CONFIG_DIR = "harness/config/shardcert"

_SAMPLE_HL7 = (
    "MSH|^~\\&|SND|SF|RCV|RF|20260101000000||ADT^A01|MSG00001|P|2.5\r"
    "EVN|A01|20260101000000\r"
    "PID|1||1^^^MRN||DOE^JOHN"
)


def test_persistent_off_by_default(monkeypatch: pytest.MonkeyPatch) -> None:
    # Default (knob unset) ⇒ the shared outbounds stay connect-per-delivery — byte-identical to today.
    monkeypatch.delenv("MEFOR_SHARDCERT_PERSISTENT", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "3")
    reg = load_config(_CONFIG_DIR)
    assert len(reg.outbound) == 3
    for conn in reg.outbound.values():
        assert conn.spec.settings.get("persistent") is False


def test_persistent_env_plumbs_true_into_built_outbounds(monkeypatch: pytest.MonkeyPatch) -> None:
    # MEFOR_SHARDCERT_PERSISTENT truthy ⇒ every shared outbound connector carries persistent=True
    # (the ADR 0067 connection reuse the sizing bench needs so per-message TCP handshake isn't the wall).
    monkeypatch.setenv("MEFOR_SHARDCERT_PERSISTENT", "1")
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "3")
    reg = load_config(_CONFIG_DIR)
    assert reg.outbound, "no outbound destinations were built"
    for conn in reg.outbound.values():
        assert conn.spec.settings.get("persistent") is True


@pytest.mark.parametrize("raw,expected", [("1", True), ("true", True), ("yes", True), ("on", True)])
def test_persistent_truthy_spellings(
    monkeypatch: pytest.MonkeyPatch, raw: str, expected: bool
) -> None:
    monkeypatch.setenv("MEFOR_SHARDCERT_PERSISTENT", raw)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "2")
    reg = load_config(_CONFIG_DIR)
    assert all(c.spec.settings.get("persistent") is expected for c in reg.outbound.values())


@pytest.mark.parametrize("raw", ["0", "false", "no", "off", ""])
def test_persistent_falsy_spellings(monkeypatch: pytest.MonkeyPatch, raw: str) -> None:
    monkeypatch.setenv("MEFOR_SHARDCERT_PERSISTENT", raw)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", "2")
    reg = load_config(_CONFIG_DIR)
    assert all(c.spec.settings.get("persistent") is False for c in reg.outbound.values())


# --- per-shard lane-count knob (many-thin-lanes) -----------------------------


def _shard_env(monkeypatch: pytest.MonkeyPatch, *, shards: str, lanes: int, dests: int) -> None:
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", shards)
    monkeypatch.setenv("MEFOR_SHARDCERT_LANES_PER_SHARD", str(lanes))
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", str(dests))
    monkeypatch.setenv("MEFOR_SHARDCERT_INBOUND_BASE", "3600")


def test_lanes_default_one_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    # lanes_per_shard unset (== 1) ⇒ the exact single-lane names + ports + FIFO keys of today.
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    _shard_env(monkeypatch, shards="a,b", lanes=1, dests=2)
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)  # keep it truly unset
    reg = load_config(_CONFIG_DIR)
    assert set(reg.inbound) == {"IB_S_a", "IB_S_b"}  # no _L suffix
    assert set(reg.routers) == {"route_a", "route_b"}
    assert "H_a_00" in reg.handlers and "H_a_01" in reg.handlers  # no _L suffix
    ports = sorted(c.spec.settings.get("port") for c in reg.inbound.values())
    assert ports == [3600, 3601]  # base + i


def test_lanes_per_shard_multiplies_chains(monkeypatch: pytest.MonkeyPatch) -> None:
    # N=2 shards x C=3 lanes ⇒ 6 inbound + 6 routers + 6*dests handlers, each a DISTINCT chain.
    _shard_env(monkeypatch, shards="a,b", lanes=3, dests=2)
    reg = load_config(_CONFIG_DIR)
    assert len(reg.inbound) == 6
    assert len(reg.routers) == 6
    assert len(reg.handlers) == 6 * 2
    # Each lane has its own inbound with the _L suffix.
    assert "IB_S_a_L00" in reg.inbound
    assert "IB_S_a_L02" in reg.inbound
    assert "IB_S_b_L02" in reg.inbound


def test_lanes_ports_contiguous_and_non_overlapping(monkeypatch: pytest.MonkeyPatch) -> None:
    _shard_env(monkeypatch, shards="a,b", lanes=3, dests=2)
    reg = load_config(_CONFIG_DIR)
    ports = sorted(c.spec.settings.get("port") for c in reg.inbound.values())
    # 2 shards x 3 lanes = 6 contiguous ports from the base, none overlapping.
    assert ports == list(range(3600, 3606))
    assert len(ports) == len(set(ports))
    # Lane l of shard i binds base + i*lanes + l (i=1 → shard b's block starts at base+3).
    assert reg.inbound["IB_S_a_L00"].spec.settings.get("port") == 3600
    assert reg.inbound["IB_S_b_L00"].spec.settings.get("port") == 3603


def test_multi_lane_fifo_keys_unique(monkeypatch: pytest.MonkeyPatch) -> None:
    # The (shard, lane, dest) FIFO keys stamped into MSH-6 must be pairwise distinct so per-lane FIFO
    # accounting stays meaningful with many lanes per shard.
    shards, lanes, dests = ("a", "b", "c"), 3, 4
    keys = [fifo_lane(s, d, lane) for s in shards for lane in range(lanes) for d in range(dests)]
    assert len(keys) == len(shards) * lanes * dests
    assert len(set(keys)) == len(keys)  # no collisions
    assert fifo_lane("a", 3, 2) == "a_L02_03"


def test_single_lane_fifo_key_byte_identical() -> None:
    # lane_index=None (the single-lane path) keeps the original {shard}_{dest} key exactly.
    assert fifo_lane("a", 3, None) == "a_03"
    assert fifo_lane("b", 0) == "b_00"


def test_apply_transform_stamps_lane_key(monkeypatch: pytest.MonkeyPatch) -> None:
    # End-to-end: the handler's apply_transform stamps the lane-qualified key into MSH-6 (and the
    # single-lane path stamps the legacy key), never touching MSH-10 (the correlation id).
    monkeypatch.delenv("MEFOR_SHARDCERT_TRANSFORM", raising=False)  # default 'edit'
    monkeypatch.setenv("MEFOR_SHARDCERT_LANES_PER_SHARD", "4")
    shape = load_shape()

    multi = Message.parse(_SAMPLE_HL7)
    apply_transform(multi, shape, "a", 3, 2)
    assert multi["MSH-6"] == "a_L02_03"
    assert multi["MSH-10"] == "MSG00001"  # correlation id untouched

    single = Message.parse(_SAMPLE_HL7)
    apply_transform(single, shape, "a", 3, None)
    assert single["MSH-6"] == "a_03"


# --- BACKLOG #209: the H != D shape split (routed_fanout != delivered) --------
#
# `dests` used to do THREE jobs at once — topology (outbound connections / sink port band), fan-out
# (deliveries per accepted message), and transform-stage width (handlers the router selects) — which only
# coincided because the graph hardwired H = N = dests. These pin the split: `dests` keeps its ONE meaning
# (topology), `handlers` is H, `delivering` is D (the fan-out), and the defaults reproduce today exactly.


def _shape_split_env(
    monkeypatch: pytest.MonkeyPatch, *, dests: int, handlers: int, delivering: int
) -> None:
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.setenv("MEFOR_SHARDCERT_DESTS", str(dests))
    monkeypatch.setenv("MEFOR_SHARDCERT_HANDLERS", str(handlers))
    monkeypatch.setenv("MEFOR_SHARDCERT_DELIVERING", str(delivering))


def test_default_shape_is_byte_identical(monkeypatch: pytest.MonkeyPatch) -> None:
    # THE no-published-run-may-change gate. With neither knob set, H = D = dests = 8: 8 handlers, the same
    # names as before the split, the router selects all 8, and EVERY one returns a Send. If this drifts,
    # every number the bench has ever published silently moves.
    monkeypatch.setenv("MEFOR_SHARDCERT_SHARDS", "a")
    monkeypatch.delenv("MEFOR_SHARDCERT_LANES_PER_SHARD", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_DESTS", raising=False)  # default 8
    monkeypatch.delenv("MEFOR_SHARDCERT_HANDLERS", raising=False)
    monkeypatch.delenv("MEFOR_SHARDCERT_DELIVERING", raising=False)
    reg = load_config(_CONFIG_DIR)

    assert sorted(reg.handlers) == [f"H_a_{j:02d}" for j in range(8)]
    assert len(reg.outbound) == 8
    assert reg.routers["route_a"](Message.parse(_SAMPLE_HL7)) == [f"H_a_{j:02d}" for j in range(8)]
    # routed == delivered: every selected handler produces a Send. This is exactly the property that
    # makes the default bench BLIND to the accepts= seam — and why #209 had to add the knobs, not
    # redefine dests.
    for name in reg.handlers:
        out = reg.handlers[name](Message.parse(_SAMPLE_HL7))
        assert isinstance(out, Send), f"{name} did not deliver at the default shape"


def test_handlers_and_delivering_split_builds_the_adt_hub(monkeypatch: pytest.MonkeyPatch) -> None:
    # The reference hub: 4 shared outbound CONNECTIONS, the router SELECTS 20 handlers, only 4 deliver.
    _shape_split_env(monkeypatch, dests=4, handlers=20, delivering=4)
    reg = load_config(_CONFIG_DIR)

    assert len(reg.handlers) == 20  # transform-stage width == H, NOT dests
    assert len(reg.outbound) == 4  # topology == dests, NOT H
    selected = reg.routers["route_a"](Message.parse(_SAMPLE_HL7))
    assert selected == [
        f"H_a_{j:02d}" for j in range(20)
    ]  # the router selects ALL H, unconditionally


def test_non_delivering_handlers_return_none(monkeypatch: pytest.MonkeyPatch) -> None:
    # Handler j < D delivers; j >= D self-filters (returns None). The decliners still cost the full 2 txn
    # (routed-row claim + a zero-delivery transform_handoff) — that 2-txn-for-nothing IS the quantity #209
    # exists to make visible, and #213's accepts= seam exists to remove.
    _shape_split_env(monkeypatch, dests=4, handlers=20, delivering=4)
    reg = load_config(_CONFIG_DIR)

    delivered = reg.handlers["H_a_00"](Message.parse(_SAMPLE_HL7))
    assert isinstance(delivered, Send)
    assert delivered.to == shared_dest_name(0)  # handler j owns destination j

    for j in range(4, 20):  # every handler at or beyond D
        assert reg.handlers[f"H_a_{j:02d}"](Message.parse(_SAMPLE_HL7)) is None

    # Exactly D of the H selected handlers deliver — the bench's fan-out is D, not dests and not H.
    delivering = sum(
        1 for name in reg.handlers if reg.handlers[name](Message.parse(_SAMPLE_HL7)) is not None
    )
    assert delivering == 4


def test_delivering_below_dests_leaves_the_tail_connections_unused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # dests stays TOPOLOGY: all 8 outbound connections (and so the 8-wide sink port band) are declared even
    # though only the first 3 receive anything. Collapsing dests to D would shrink the port band under the
    # sink partition and silently drop deliveries the reconcile never counts.
    _shape_split_env(monkeypatch, dests=8, handlers=8, delivering=3)
    reg = load_config(_CONFIG_DIR)

    assert len(reg.outbound) == 8
    sends = [reg.handlers[f"H_a_{j:02d}"](Message.parse(_SAMPLE_HL7)) for j in range(8)]
    targets = {s.to for s in sends if isinstance(s, Send)}
    assert targets == {shared_dest_name(d) for d in range(3)}
    assert all(s is None for s in sends[3:])


def test_non_delivering_handler_reads_the_message(monkeypatch: pytest.MonkeyPatch) -> None:
    # A self-filtering handler must READ a field before declining — a real hub handler filters on CONTENT
    # (trigger / patient class). One that returned None without touching the message would understate the
    # CPU a decliner actually costs, and the bench would report the transform stage as cheaper than it is.
    _shape_split_env(monkeypatch, dests=1, handlers=2, delivering=1)
    reg = load_config(_CONFIG_DIR)

    reads: list[str] = []

    class _SpyMessage(Message):
        def __getitem__(self, key: str) -> str:
            reads.append(key)
            return super().__getitem__(key)

    spy = _SpyMessage.parse(_SAMPLE_HL7)
    assert reg.handlers["H_a_01"](spy) is None  # the self-filtering one
    assert reads, "the self-filtering handler declined WITHOUT reading the message"


@pytest.mark.parametrize(
    ("dests", "handlers", "delivering", "match"),
    [
        (4, 20, 8, "DELIVERING"),  # D > dests: cannot deliver to a connection that does not exist
        (8, 2, 4, "HANDLERS"),  # H < D: a delivering destination with no handler to own it
    ],
)
def test_shape_validation_fails_loud(
    monkeypatch: pytest.MonkeyPatch, dests: int, handlers: int, delivering: int, match: str
) -> None:
    # FAIL LOUD, never clamp. A silently-truncated shape would serve a graph the report does not describe.
    _shape_split_env(monkeypatch, dests=dests, handlers=handlers, delivering=delivering)
    with pytest.raises(ValueError, match=match):
        load_shape()


def test_shape_cost_and_event_model(monkeypatch: pytest.MonkeyPatch) -> None:
    # The shape's SELF-REPORT: txn/msg = 3 + 2H + 2D (ADR 0051), events/msg = 1 + D. Both key on D, never
    # on dests — `events/msg = 1 + dests` at the hub would read 5 as 21, a 4.2x overstatement (B10).
    _shape_split_env(monkeypatch, dests=4, handlers=20, delivering=4)
    hub = load_shape()
    assert hub.txn_per_message == 51 and hub.events_per_message == 5

    _shape_split_env(monkeypatch, dests=8, handlers=8, delivering=8)
    default = load_shape()
    assert default.txn_per_message == 35 and default.events_per_message == 9


def test_delivers_to_maps_handler_to_destination(monkeypatch: pytest.MonkeyPatch) -> None:
    _shape_split_env(monkeypatch, dests=4, handlers=20, delivering=4)
    shape = load_shape()
    assert [shape.delivers_to(j) for j in range(6)] == [0, 1, 2, 3, None, None]
