# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A Handler ``Send`` into a pass-through (PT) inbound another engine shard owns (vault BACKLOG #2755).

Engine shards (ADR 0037) run over ONE unified store (ADR 0063), and each shard's registry holds only
its own inbounds. Before the fix, ``transform_one`` resolved a PT target against that filtered map,
so a Send into a sibling shard's PT raised "unknown outbound/pass-through" on every message, after the
sender was ACKed. These tests pin the two halves the ledger row requires together:

* the filter pins the whole config's PT inbounds (name -> deployed), and ``transform_one`` accepts a
  foreign PT target (and still declines a not-deployed one, identically on every shard);
* ``_wake_lane`` drops an INGRESS wake for a lane this shard does not own, so the producing shard
  never registers itself as a second claimer of the PT's lane;

and an end-to-end run with TWO runners (shard ``a`` and shard ``b``) on one store, where the
message crosses from shard ``a``'s Handler into shard ``b``'s PT and is delivered.
"""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    PassThrough,
    Registry,
    Send,
    WiringError,
    build_inbound_connection,
)
from messagefoundry.pipeline import wiring_runner as wiring_runner_mod
from messagefoundry.pipeline.dryrun import transform_one
from messagefoundry.pipeline.sharding import filter_registry_for_shard, owner_shard_of_destination
from messagefoundry.pipeline.wiring_runner import RegistryRunner, check_pt_backend_supported
from messagefoundry.store import MessageStatus, MessageStore, Stage

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG2755|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)
UNIVERSE = ("a", "b")


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "shard_pt.db")
    yield s
    await s.close()


def _graph(tmp_path: Path, *, pt_deployed: bool = True) -> Registry:
    """``in_a`` (shard a) routes to ``h_a``, which Sends into ``PT_X`` (shard b) and, when present,
    into the not-deployed ``PT_OFF`` (shard b). ``PT_X`` routes to ``h_pt``, which Sends to ``OUT``."""
    inbox = tmp_path / "in_a"
    inbox.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in_a",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r_a",
            shard="a",
        )
    )
    reg.add_inbound(build_inbound_connection("PT_X", PassThrough(), router="r_pt", shard="b"))
    reg.add_inbound(
        build_inbound_connection(
            "PT_OFF", PassThrough(), router="r_pt", shard="b", deployed=pt_deployed
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "OUT",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(tmp_path), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r_a", lambda m: ["h_a"])
    reg.add_router("r_pt", lambda m: ["h_pt"])
    reg.add_handler("h_a", lambda m: [Send("PT_X", m), Send("PT_OFF", m)])
    reg.add_handler("h_pt", lambda m: Send("OUT", m))
    return reg


class _Collector:
    """A recording outbound connector (delivery = append; non-capturing)."""

    def __init__(self) -> None:
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        self.deliveries.append(payload)

    async def aclose(self) -> None:
        return None


class _StubDispatcher:
    """Records ``mark_ready`` keys, the only surface ``_wake_lane`` touches in pooled mode."""

    def __init__(self) -> None:
        self.ready: list[str] = []

    def mark_ready(self, key: str, *, woken: bool = True) -> None:
        self.ready.append(key)


async def _until(pred, *, timeout: float = 10.0) -> None:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if await pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


# --- the filter pins the whole config's PT inbounds -------------------------------------------


def test_filter_pins_unfiltered_pt_inbounds_with_their_deployed_flag(tmp_path: Path) -> None:
    reg = _graph(tmp_path, pt_deployed=False)
    a = filter_registry_for_shard(reg, "a")
    assert "PT_X" not in a.inbound  # the slice still holds only shard a's inbounds...
    assert a.all_pt_inbound == {"PT_X": True, "PT_OFF": False}  # ...but the PTs are pinned
    assert a.passthrough_inbounds() is a.all_pt_inbound  # the pinned map, not the slice
    assert reg.all_pt_inbound is None  # the filter never mutates the source


def test_single_shard_filter_pins_no_pt_map(tmp_path: Path) -> None:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("PT_ONLY", PassThrough(), router="r"))
    f = filter_registry_for_shard(reg, "default")
    assert f.all_pt_inbound is None
    assert f.passthrough_inbounds() == {"PT_ONLY": True}  # derived from its own inbounds


# --- transform_one resolves a foreign PT -----------------------------------------------------


def test_transform_one_accepts_a_pt_owned_by_another_shard(tmp_path: Path) -> None:
    a = filter_registry_for_shard(_graph(tmp_path, pt_deployed=False), "a")
    outcome = transform_one(a, "h_a", ADT, ContentType.HL7V2.value)
    assert [(d.to, d.is_passthrough) for d in outcome.deliveries] == [("PT_X", True)]
    # A not-deployed PT on another shard is DECLINED, exactly as the owning shard would decide.
    assert outcome.declined == ["PT_OFF"]


def test_transform_one_still_refuses_an_unknown_target_when_sharded(tmp_path: Path) -> None:
    reg = _graph(tmp_path)
    reg.add_handler("h_typo", lambda m: Send("PT_NOPE", m))
    a = filter_registry_for_shard(reg, "a")
    with pytest.raises(ValueError, match="unknown outbound/pass-through"):
        transform_one(a, "h_typo", ADT, ContentType.HL7V2.value)


# --- the PT backend gate sees the whole config -----------------------------------------------


async def test_pt_backend_gate_counts_a_sibling_shards_pt(
    store: MessageStore, tmp_path: Path
) -> None:
    a = filter_registry_for_shard(_graph(tmp_path), "a")
    assert not any(ic.spec.type is ConnectorType.PT for ic in a.inbound.values())  # premise
    store.supports_pt_reingress = False  # a backend without PT re-ingress
    with pytest.raises(WiringError, match="'PT_X'"):
        check_pt_backend_supported(a, store)


# --- _wake_lane: no second claimer for a foreign inbound lane ----------------------------------


async def test_wake_lane_drops_ingress_wake_for_a_foreign_pt(
    store: MessageStore, tmp_path: Path
) -> None:
    a = filter_registry_for_shard(_graph(tmp_path), "a")
    runner = RegistryRunner(
        a, store, claim_mode="pooled", egress=EgressSettings(deny_by_default=False)
    )
    ingress, routed = _StubDispatcher(), _StubDispatcher()
    runner._dispatchers[Stage.INGRESS] = ingress  # type: ignore[assignment]
    runner._dispatchers[Stage.ROUTED] = routed  # type: ignore[assignment]
    runner._wake_lane(Stage.INGRESS, "PT_X")  # shard b's PT: mark_ready would make a second claimer
    runner._wake_lane(Stage.ROUTED, "PT_X")
    assert ingress.ready == [] and routed.ready == []
    runner._wake_lane(Stage.INGRESS, "in_a")
    runner._wake_lane(Stage.ROUTED, "in_a")
    assert ingress.ready == ["in_a"] and routed.ready == ["in_a"]


async def test_wake_lane_ungated_for_ingress_when_unsharded(
    store: MessageStore, tmp_path: Path
) -> None:
    reg = Registry()
    reg.add_inbound(build_inbound_connection("PT_ONLY", PassThrough(), router="r"))
    reg.add_router("r", lambda m: [])
    runner = RegistryRunner(
        reg, store, claim_mode="pooled", egress=EgressSettings(deny_by_default=False)
    )
    stub = _StubDispatcher()
    runner._dispatchers[Stage.INGRESS] = stub  # type: ignore[assignment]
    runner._wake_lane(Stage.INGRESS, "not_declared")
    assert stub.ready == ["not_declared"]


# --- end to end: two engine shards on one store -----------------------------------------------


@pytest.mark.parametrize(
    ("claim_mode", "per_lane_wake"), [("per_lane", False), ("per_lane", True), ("pooled", False)]
)
async def test_send_into_another_shards_pt_is_delivered(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    claim_mode: str,
    per_lane_wake: bool,
) -> None:
    # per_lane_wake=True: the producing shard's INGRESS wake for PT_X is dropped (the gate), and no
    # wake crosses processes, so shard b finds the child only on its idle backstop. Shrink the
    # backstop so the test proves that path without waiting the shipped 30s.
    monkeypatch.setattr(wiring_runner_mod, "_PER_LANE_IDLE_BACKSTOP_SECONDS", 0.1)
    reg = _graph(tmp_path)
    shards = {s: filter_registry_for_shard(reg, s) for s in UNIVERSE}
    runners = {
        s: RegistryRunner(
            r,
            store,
            poll_interval=0.02,
            claim_mode=claim_mode,
            per_lane_wake=per_lane_wake,
            pooled_sweep_interval=0.05,
            egress=EgressSettings(deny_by_default=False),
        )
        for s, r in shards.items()
    }
    started: list[RegistryRunner] = []
    collector = _Collector()
    try:
        for r in runners.values():
            await r.start()
            started.append(r)
        # Only the rendezvous owner of OUT claims its lane (ADR 0073); give that runner the recorder,
        # closing the connector it built first.
        owner = runners[owner_shard_of_destination("OUT", UNIVERSE)]
        await owner._destinations["OUT"].aclose()
        owner._destinations["OUT"] = collector  # type: ignore[assignment]
        a = runners["a"]
        await a._handle_inbound(a.registry.inbound["in_a"], ADT.encode("utf-8"))

        async def _delivered() -> bool:
            return bool(collector.deliveries)

        await _until(_delivered)
        assert "MSG2755" in collector.deliveries[0]

        parents = await store.list_messages(channel_id="in_a")
        children = await store.list_messages(channel_id="PT_X")
        assert len(parents) == 1 and len(children) == 1

        async def _settled() -> bool:
            p = await store.get_message(parents[0]["id"])
            c = await store.get_message(children[0]["id"])
            return (
                p is not None
                and c is not None
                and p["status"] == MessageStatus.PROCESSED.value
                and c["status"] == MessageStatus.PROCESSED.value
            )

        # The parent finalizes PROCESSED (its Send was delivered into the PT, not an ERROR at
        # transform), and the child shard b re-routed reaches PROCESSED at OUT.
        await _until(_settled)
    finally:
        for r in started:
            await r.stop()
