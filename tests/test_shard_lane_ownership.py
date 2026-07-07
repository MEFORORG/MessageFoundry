# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ADR 0073 — single-delivery-consumer-per-outbound-lane in the RegistryRunner (SQLite-backed).

Engine shards on one unified store share every outbound lane, but exactly ONE shard (the
deterministic rendezvous owner, :func:`owner_shard_of_destination`) may claim/deliver a lane —
otherwise N concurrent head-claimers can invert per-lane FIFO. These tests pin the runner-side
gates on a 2-shard registry viewed from shard ``a``:

* the ownership predicate (``_owns_destination`` / public ``destination_owner``) — total over any
  name, and a no-op (owner ``None`` / owns everything) on an unsharded registry;
* per_lane mode spawns delivery workers ONLY for owned lanes (the connector is still built);
* the pooled OUTBOUND lane provider filters ``registry.outbound | _destinations`` by ownership —
  including a reload-dropped-but-still-built lane, which keeps draining IFF owned;
* ``_wake_lane`` drops OUTBOUND wakes for non-owned lanes and RESPONSE wakes for foreign inbounds;
* outbound CONTROLS (stop/start/restart) refuse a non-owned lane with ShardLaneOwnershipError
  (the API maps it to 409) while an owned lane still pauses/quiesces normally;
* the sharded-only non-owned-lane watchdog pages queue_buildup on a lane the owner isn't draining,
  and an unsharded runner spawns no watchdog at all.

Ownership is COMPUTED with the production hash in every test (never assumed), so a hash change
re-picks names rather than silently inverting the assertions.
No hashlib/hmac/secrets/ssl here (crypto-inventory gate)."""

from __future__ import annotations

import asyncio
import time
from pathlib import Path

import pytest

from messagefoundry.config.models import BuildupThreshold, ConnectorType
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import wiring_runner as wiring_runner_mod
from messagefoundry.pipeline.sharding import (
    filter_registry_for_shard,
    owner_shard_of_destination,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, ShardLaneOwnershipError
from messagefoundry.store import MessageStore, Stage

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)

#: The pinned 2-shard universe every sharded test runs under (viewed from shard "a").
UNIVERSE = ("a", "b")


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "shard.db")
    yield s
    await s.close()


def _pick_dest(owner: str, *, prefix: str = "dest") -> str:
    """The first candidate name the PRODUCTION rendezvous hash assigns to ``owner`` — computed,
    never assumed, so a hash change re-picks rather than inverting the test's premise."""
    for i in range(256):
        name = f"{prefix}_{i}"
        if owner_shard_of_destination(name, UNIVERSE) == owner:
            return name
    raise AssertionError(f"no candidate destination owned by shard {owner!r} in 256 tries")


def _sharded_registry(
    tmp_path: Path,
    dests: list[str],
    *,
    send_to: str,
    buildup: dict[str, BuildupThreshold] | None = None,
) -> Registry:
    """A 2-shard graph (inbound ``in_a`` tagged shard=a, ``in_b`` shard=b; the outbounds shared),
    filtered to shard ``a`` — so the result carries shard_id='a' + all_shard_ids=('a','b')."""
    inbox_a, inbox_b, outdir = tmp_path / "in_a", tmp_path / "in_b", tmp_path / "out"
    for d in (inbox_a, inbox_b, outdir):
        d.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "in_a",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox_a), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
            shard="a",
        )
    )
    reg.add_inbound(
        InboundConnection(
            "in_b",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox_b), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
            shard="b",
        )
    )
    for dest in dests:
        reg.add_outbound(
            OutboundConnection(
                dest,
                ConnectionSpec(
                    ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
                ),
                buildup=(buildup or {}).get(dest),
            )
        )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(send_to, m))
    filtered = filter_registry_for_shard(reg, "a")
    assert filtered.shard_id == "a" and filtered.all_shard_ids == UNIVERSE  # premise, not behavior
    return filtered


def _unsharded_registry(tmp_path: Path) -> Registry:
    """A plain single-shard graph (no shard tags) — shard_id/all_shard_ids stay None."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir(exist_ok=True)
    outdir.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    return reg


class _Collector:
    """A recording outbound connector (delivery = append; non-capturing)."""

    def __init__(self) -> None:
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        self.deliveries.append(payload)
        return None

    async def aclose(self) -> None:
        return None


class _StubDispatcher:
    """Records ``mark_ready`` keys — the only surface ``_wake_lane`` touches in pooled mode."""

    def __init__(self) -> None:
        self.ready: list[str] = []

    def mark_ready(self, key: str, *, woken: bool = True) -> None:
        self.ready.append(key)


class _RecordingAlertSink:
    """Test AlertSink that records emitted events instead of logging them."""

    def __init__(self) -> None:
        self.stopped: list[tuple[str, str]] = []
        self.buildups: list[tuple[str, int, float]] = []
        self.stalls: list[tuple[str, float]] = []
        self.errors: list[tuple[str, str]] = []

    def connection_stopped(self, name: str, *, detail: str) -> None:
        self.stopped.append((name, detail))

    def queue_buildup(self, name: str, *, depth: int, oldest_age_seconds: float) -> None:
        self.buildups.append((name, depth, oldest_age_seconds))

    def message_stall(self, name: str, *, oldest_age_seconds: float) -> None:
        self.stalls.append((name, oldest_age_seconds))

    def connection_error(self, name: str, *, kind: str, detail: str | None = None) -> None:
        self.errors.append((name, kind))

    def connection_restored(self, name: str) -> None: ...


async def _until(pred, *, timeout: float = 5.0) -> None:  # type: ignore[no-untyped-def]
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if pred():
            return
        await asyncio.sleep(0.02)
    raise AssertionError("timed out waiting for condition")


# --- 1. the ownership predicate ------------------------------------------------------------


async def test_unsharded_runner_owns_everything(store: MessageStore, tmp_path: Path) -> None:
    # Unsharded (shard_id None): owner is None and the predicate is True for EVERY name — the
    # single-process engine is byte-identical to pre-ADR-0073 (no gate anywhere).
    runner = RegistryRunner(_unsharded_registry(tmp_path), store)
    assert runner.registry.shard_id is None
    for name in ("file_out", "never_declared_anywhere"):
        assert runner.destination_owner(name) is None
        assert runner._owns_destination(name) is True


async def test_single_shard_filter_attaches_no_shard_identity(tmp_path: Path) -> None:
    # A single-shard config filtered through filter_registry_for_shard stays UNSHARDED (shard_id /
    # all_shard_ids None) — byte-identical to plain serve, no ADR 0073 behaviors armed.
    reg = _unsharded_registry(tmp_path)
    filtered = filter_registry_for_shard(reg, "default")
    assert filtered.shard_id is None
    assert filtered.all_shard_ids is None
    assert set(filtered.inbound) == {"file_in"}


async def test_sharded_predicate_matches_rendezvous_owner(
    store: MessageStore, tmp_path: Path
) -> None:
    # Sharded: destination_owner == the production rendezvous owner for every declared lane, and
    # the predicate is TOTAL — a name no registry ever declared still resolves one owner.
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    reg = _sharded_registry(tmp_path, [owned, foreign], send_to=owned)
    runner = RegistryRunner(reg, store)
    for dest in (owned, foreign):
        expect = owner_shard_of_destination(dest, UNIVERSE)
        assert runner.destination_owner(dest) == expect
        assert runner._owns_destination(dest) is (expect == "a")
    # Predicate totality over an undeclared name (a reload-dropped lane keeps exactly one owner).
    ghost = _pick_dest("b", prefix="ghost")
    assert runner.destination_owner(ghost) == "b"
    assert runner._owns_destination(ghost) is False


# --- 2. per_lane mode: delivery workers only for owned lanes --------------------------------


async def test_per_lane_spawns_delivery_workers_only_for_owned_lanes(
    store: MessageStore, tmp_path: Path
) -> None:
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    reg = _sharded_registry(tmp_path, [owned, foreign], send_to=owned)
    runner = RegistryRunner(reg, store, poll_interval=0.02, claim_mode="per_lane")
    await runner.start()
    try:
        # Single consumer per lane: THIS shard runs a delivery worker only for the lane it owns.
        assert set(runner._workers) == {owned}
        assert foreign not in runner._workers
        # ...but the non-owned connector is STILL BUILT (status/reload/dead-letter sweeps key off
        # the full outbound map) — only claiming/delivering is gated.
        assert foreign in runner._destinations
        # Sharded start also arms the non-owned-lane watchdog (per_lane included).
        assert runner._shard_watchdog is not None
    finally:
        await runner.stop()


# --- 3. pooled lane provider filters by ownership --------------------------------------------


async def test_pooled_outbound_lane_provider_filters_to_owned(
    store: MessageStore, tmp_path: Path
) -> None:
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    reg = _sharded_registry(tmp_path, [owned, foreign], send_to=owned)
    runner = RegistryRunner(reg, store, claim_mode="pooled")
    provider = runner._pooled_lane_provider(Stage.OUTBOUND)
    assert provider() == {owned}
    # A reload-dropped-but-still-built lane (in _destinations, NOT in registry.outbound) appears
    # IFF this shard owns it — the predicate stays total over names outside the registry, so a
    # dropped lane keeps draining on exactly its owner.
    extra_owned, extra_foreign = _pick_dest("a", prefix="extra"), _pick_dest("b", prefix="extra")
    runner._destinations[extra_owned] = _Collector()  # type: ignore[assignment]
    runner._destinations[extra_foreign] = _Collector()  # type: ignore[assignment]
    assert provider() == {owned, extra_owned}


# --- 4. the _wake_lane ownership gate ---------------------------------------------------------


async def test_wake_lane_drops_non_owned_outbound_and_foreign_response(
    store: MessageStore, tmp_path: Path
) -> None:
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    reg = _sharded_registry(tmp_path, [owned, foreign], send_to=owned)
    runner = RegistryRunner(reg, store, claim_mode="pooled")
    out_stub, resp_stub = _StubDispatcher(), _StubDispatcher()
    runner._dispatchers[Stage.OUTBOUND] = out_stub  # type: ignore[assignment]
    runner._dispatchers[Stage.RESPONSE] = resp_stub  # type: ignore[assignment]
    # OUTBOUND: a wake for a lane another shard owns is dropped BEFORE the dispatcher (mark_ready
    # is create-or-stick — an ungated wake would register a second concurrent claimer).
    runner._wake_lane(Stage.OUTBOUND, foreign)
    assert out_stub.ready == []
    runner._wake_lane(Stage.OUTBOUND, owned)
    assert out_stub.ready == [owned]
    # RESPONSE: a loopback key that is NOT one of this shard's inbounds is dropped (the reingress
    # target lives on — and is drained by — another shard); an owned inbound's wake goes through.
    runner._wake_lane(Stage.RESPONSE, "in_b")  # shard b's inbound, filtered out of this registry
    assert resp_stub.ready == []
    runner._wake_lane(Stage.RESPONSE, "in_a")
    assert resp_stub.ready == ["in_a"]


async def test_wake_lane_ungated_when_unsharded(store: MessageStore, tmp_path: Path) -> None:
    # Unsharded: no gate — every OUTBOUND wake reaches the dispatcher (byte-identical semantics).
    runner = RegistryRunner(_unsharded_registry(tmp_path), store, claim_mode="pooled")
    stub = _StubDispatcher()
    runner._dispatchers[Stage.OUTBOUND] = stub  # type: ignore[assignment]
    runner._wake_lane(Stage.OUTBOUND, "file_out")
    runner._wake_lane(Stage.OUTBOUND, "not_even_declared")
    assert stub.ready == ["file_out", "not_even_declared"]


# --- 5. outbound controls refuse non-owned lanes ---------------------------------------------


async def test_outbound_controls_refuse_non_owned_lane(store: MessageStore, tmp_path: Path) -> None:
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    reg = _sharded_registry(tmp_path, [owned, foreign], send_to=owned)
    runner = RegistryRunner(reg, store, claim_mode="pooled", pooled_sweep_interval=0.05)
    await runner.start()
    try:
        # A non-owning shard's pause would report quiesced instantly (no local worker/lane) and
        # unlock the require-stopped purge while the owner keeps delivering — so all three controls
        # refuse, naming the owner so the operator can retarget that shard's API.
        for control in (runner.stop_outbound, runner.start_outbound, runner.restart_outbound):
            with pytest.raises(ShardLaneOwnershipError) as ei:
                await control(foreign)
            assert ei.value.name == foreign
            assert ei.value.owner == "b"
            assert ei.value.shard == "a"
        assert foreign not in runner._outbound_paused  # the refused control changed nothing
        # An OWNED lane still pauses + quiesces normally (idle lane → quiescence is prompt)...
        await runner.stop_outbound(owned)
        assert runner.outbound_running(owned) is False
        await _until(lambda: runner.outbound_quiesced(owned))
        # ...and resumes.
        await runner.start_outbound(owned)
        assert runner.outbound_running(owned) is True
        assert runner.outbound_quiesced(owned) is False
        await runner.restart_outbound(owned)
        assert runner.outbound_running(owned) is True
    finally:
        await runner.stop()


# --- 6/7. the non-owned-lane watchdog ---------------------------------------------------------


async def test_watchdog_pages_buildup_on_non_owned_lane(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A shard-a inbound Sends to a shard-b-owned destination: shard a routes + transforms the
    # message but must NOT deliver it (single consumer per lane), so the outbound row stays
    # PENDING here — and the sharded-only watchdog pages queue_buildup for that lane, because the
    # owner's own buildup/stall alerts fire only inside ITS delivery path (a hung owner would
    # otherwise stall the lane with zero paging anywhere).
    owned, foreign = _pick_dest("a"), _pick_dest("b")
    reg = _sharded_registry(
        tmp_path,
        [owned, foreign],
        send_to=foreign,  # the handler produces into the lane this shard does NOT own
        buildup={foreign: BuildupThreshold(max_depth=1, max_oldest_seconds=None)},
    )
    monkeypatch.setattr(wiring_runner_mod, "_SHARD_WATCHDOG_INTERVAL_SECONDS", 0.05)
    sink = _RecordingAlertSink()
    runner = RegistryRunner(
        reg,
        store,
        claim_mode="pooled",
        pooled_sweep_interval=0.05,
        alert_sink=sink,  # type: ignore[arg-type]
    )
    await runner.start()
    foreign_collector = _Collector()
    runner._destinations[foreign] = foreign_collector  # type: ignore[assignment]
    try:
        assert runner._shard_watchdog is not None  # sharded start arms the watchdog
        # Inject one message through the real inbound path; the pooled dispatchers carry it
        # ingress → routed → outbound (those lanes are keyed by in_a, which this shard owns).
        await runner._handle_inbound(runner.registry.inbound["in_a"], ADT.encode("utf-8"))

        await _until(lambda: bool(sink.buildups))
        # The alert names the NON-owned lane; the owned lane never pages from the watchdog (its
        # checks belong to the owner's delivery path — and it has no backlog here).
        assert {name for name, _depth, _age in sink.buildups} == {foreign}
        depth, _oldest = await store.pending_depth(foreign, stage=Stage.OUTBOUND.value)
        assert depth >= 1  # the row is still queued for the owning shard...
        assert foreign_collector.deliveries == []  # ...and was never delivered locally
    finally:
        await runner.stop()


async def test_unsharded_runner_spawns_no_watchdog(store: MessageStore, tmp_path: Path) -> None:
    runner = RegistryRunner(_unsharded_registry(tmp_path), store, claim_mode="pooled")
    assert runner._shard_watchdog is None
    await runner.start()
    try:
        assert runner._shard_watchdog is None  # sharded-only: never armed without a shard_id
    finally:
        await runner.stop()
    assert runner._shard_watchdog is None
