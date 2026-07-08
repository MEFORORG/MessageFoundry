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

from messagefoundry.config.wiring import load_config
from messagefoundry.parsing.message import Message

from harness.config.shardcert._shape import apply_transform, fifo_lane, load_shape

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
