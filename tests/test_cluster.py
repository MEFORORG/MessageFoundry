# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Cluster coordination seam (Track B Step 3) — the always-run unit tests (no DB needed).

These prove the **no-op safety layer**: the :class:`NullCoordinator` default makes every gate True
and start()/stop() inert, the engine + runner accept and hold a coordinator without calling its
gates, and :func:`build_coordinator` returns the null coordinator for a disabled/non-Postgres store —
so single-node operation (SQLite and single-node Postgres) is byte-identical to before this seam.

The DbCoordinator behaviour against a real Postgres lives in the gated tests/test_postgres_store.py.
"""

from __future__ import annotations

import asyncio
import re
import textwrap
from collections.abc import Callable
from pathlib import Path

import pytest

from messagefoundry.config.settings import ClusterSettings
from messagefoundry.config.wiring import Registry, load_config
from messagefoundry.pipeline.cluster import (
    ClusterCoordinator,
    ClusterMember,
    DbCoordinator,
    NullCoordinator,
    build_coordinator,
    default_node_id,
)
from messagefoundry.pipeline.config_convergence import ConfigConvergenceRunner
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.reference_sync import ReferenceSyncRunner
from messagefoundry.pipeline.state_convergence import StateConvergenceRunner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.config.settings import ReferenceSettings
from messagefoundry.config.wiring import FileRef, ReferenceSpec
from messagefoundry.store import MessageStatus, MessageStore, Stage
from messagefoundry.transports.base import InboundHandler, SourceConnector

# host:pid:hex8 — the shared identity shape (== PostgresStore._owner).
_NODE_ID_RE = re.compile(r"^.+:\d+:[0-9a-f]{8}$")


class _NotLeaderCoordinator:
    """A tiny clustered stand-in whose gates report NOT leader / NOT owning — used to prove the engine
    and the runner merely accept + hold the coordinator, and (Step 6) that a follower converges without
    materializing from source. ``is_clustered`` is True (a real multi-node stand-in) but the config
    version token is inert here (0 / no-op bump) — the live token is exercised in the gated PG suite."""

    def __init__(self) -> None:
        self.node_id = "test-node"

    async def start(self) -> None:
        return None

    async def stop(self) -> None:
        return None

    def is_leader(self) -> bool:
        return False

    def reclaims_inflight(self) -> bool:
        return False

    def is_clustered(self) -> bool:
        return True

    async def config_version(self) -> int:
        return 0

    def config_version_cached(self) -> int:
        return 0

    async def bump_config_version(self) -> int:
        return 0

    async def cluster_members(self) -> list[ClusterMember]:
        # A clustered follower stand-in: report itself as a non-leader member (Step 7). The live
        # membership read against Postgres is exercised in the gated PG suite.
        return [
            ClusterMember(
                node_id=self.node_id,
                host=None,
                pid=None,
                started_at=None,
                last_seen=None,
                status="active",
                is_leader=False,
            )
        ]

    async def leadership_lease(self) -> tuple[str | None, float | None]:
        # A follower stand-in: it holds no lease (Workstream A5). The live lease read is in the gated PG
        # suite. Present so this stand-in still structurally satisfies the ClusterCoordinator protocol.
        return (None, None)


# --- NullCoordinator (the byte-identical default) ---------------------------


def test_default_node_id_shape() -> None:
    assert _NODE_ID_RE.match(default_node_id())


async def test_null_coordinator_gates_always_true() -> None:
    coord = NullCoordinator()
    assert _NODE_ID_RE.match(coord.node_id)
    assert coord.is_leader() is True


async def test_null_coordinator_cluster_members_is_single_self_leader() -> None:
    # Track B Step 7: single-node synthesizes exactly one self-member, always leader, no DB. started_at/
    # last_seen are None (no heartbeat), so /cluster/nodes is byte-identical in shape to a real cluster.
    coord = NullCoordinator(node_id="solo")
    members = await coord.cluster_members()
    assert len(members) == 1
    m = members[0]
    assert isinstance(m, ClusterMember)
    assert m.node_id == "solo"
    assert m.is_leader is True
    assert m.status == "active"
    assert m.started_at is None and m.last_seen is None


def test_null_coordinator_does_not_reclaim_inflight() -> None:
    # Single-node: the engine keeps the unconditional startup reset (immediate self-recovery), so the
    # null coordinator reports it does NOT own the periodic reclaim sweep. (Track B Step 4.)
    assert NullCoordinator().reclaims_inflight() is False


def test_db_coordinator_reclaims_inflight() -> None:
    # Clustered: the leader's periodic reclaim sweep recovers crashed nodes' rows, so the engine must
    # SKIP the unconditional startup reset. Construction-only (no pool touched). (Track B Step 4.)
    assert DbCoordinator(None, "n").reclaims_inflight() is True


async def test_null_coordinator_leadership_lease_is_self_no_expiry() -> None:
    # Workstream A5: single-node is permanently leader with no lease row, so leadership_lease() reports
    # itself as the owner with no expiry — keeping /cluster/nodes byte-identical in shape to a cluster.
    owner, expires = await NullCoordinator(node_id="solo").leadership_lease()
    assert owner == "solo"
    assert expires is None


def test_db_coordinator_lease_key_namespaced_by_schema() -> None:
    # The leadership-lease key is a DISTINCT, schema-namespaced key (not the nodes-DDL key), so the
    # single leader_lease row is per-deployment and two schemas elect independently.
    assert DbCoordinator(None, "n")._lease_key == "public:mefor_cluster_leader"
    assert (
        DbCoordinator(None, "n", db_schema="tenant_a")._lease_key == "tenant_a:mefor_cluster_leader"
    )
    # ...and it differs from the nodes-DDL lock key.
    c = DbCoordinator(None, "n", db_schema="tenant_a")
    assert c._lease_key != c._lock_key


def test_db_coordinator_starts_not_leader() -> None:
    # is_leader() reads cached state; before any maintenance tick a freshly-built coordinator is NOT yet
    # leader (it becomes leader only after acquiring the leadership lease on its maintenance tick).
    assert DbCoordinator(None, "n").is_leader() is False


def test_db_coordinator_logs_cluster_enabled_once(monkeypatch, caplog) -> None:
    # Track B Step 7: the active-passive HA feature set is COMPLETE, so the one-time cluster-enabled
    # banner is now an INFO (not a WARNING) that states the feature set is built and summarizes the
    # operational assumptions operators must honor. Lock that it: (1) fires exactly once at INFO level,
    # (2) NO LONGER calls the cluster feature "experimental", (3) still credits Steps 4/4b/6/6b AND now
    # Step 7, and (4) names the NTP / identical-config / coordinated-restart assumptions + points at the
    # docs. A regression that reverts it to the old experimental WARNING, drops a step, or drops the
    # assumptions is caught. The banner is process-global one-time, so reset the guard for a fresh emit.
    import logging

    import messagefoundry.pipeline.cluster as cluster_mod

    monkeypatch.setattr(cluster_mod, "_logged_cluster_enabled", False)
    coord = DbCoordinator(None, "n")  # pool is never touched by _log_cluster_enabled_once
    with caplog.at_level(logging.INFO, logger=cluster_mod.log.name):
        coord._log_cluster_enabled_once()
        coord._log_cluster_enabled_once()  # second call is a no-op (one-time guard)
    enabled = [r for r in caplog.records if "[cluster].enabled" in r.getMessage()]
    assert len(enabled) == 1
    assert enabled[0].levelno == logging.INFO  # INFO now, not WARNING
    msg = enabled[0].getMessage()
    # The cluster feature is no longer called experimental anywhere in the banner.
    assert "experimental" not in msg.lower()
    # Still credits the full built active-passive HA feature set, including the Step-7 observability API.
    assert "active-passive" in msg.lower()
    assert "Step 4b" in msg and "poll-source" in msg.lower()
    assert "Step 6" in msg and "convergence" in msg.lower()
    assert "Step 6b" in msg and "Step 7" in msg
    assert "/cluster/status" in msg and "/cluster/nodes" in msg
    # Names the operational assumptions + points at the operator doc.
    assert "NTP" in msg
    assert "identical" in msg.lower() and "coordinated" in msg.lower()
    assert "docs/CLUSTERING.md" in msg


async def test_null_coordinator_start_stop_are_idempotent_noops() -> None:
    coord = NullCoordinator()
    # Safe to call twice in either order — no DB, no task, nothing to tear down.
    await coord.start()
    await coord.start()
    await coord.stop()
    await coord.stop()
    assert coord.is_leader() is True


def test_null_coordinator_accepts_node_id_override() -> None:
    assert NullCoordinator(node_id="pinned").node_id == "pinned"


def test_null_coordinator_satisfies_protocol() -> None:
    # runtime_checkable Protocol: the null + the fake both structurally match the contract.
    assert isinstance(NullCoordinator(), ClusterCoordinator)
    assert isinstance(_NotLeaderCoordinator(), ClusterCoordinator)


# --- the seam: Engine + RegistryRunner accept + hold a coordinator ----------


async def test_engine_create_defaults_to_null_coordinator(tmp_path: Path) -> None:
    """A SQLite-backed Engine (the convenience path) ends up with a NullCoordinator, documenting the
    byte-identical single-node default."""
    eng = await Engine.create(tmp_path / "cluster.db", poll_interval=0.02)
    try:
        assert isinstance(eng._coordinator, NullCoordinator)
        assert eng._coordinator.is_leader() is True
    finally:
        await eng.store.close()


async def test_engine_holds_passed_coordinator(tmp_path: Path) -> None:
    fake = _NotLeaderCoordinator()
    eng = await Engine.create(tmp_path / "cluster2.db", poll_interval=0.02, coordinator=fake)
    try:
        # The engine holds exactly the object passed (it does not wrap or replace it), and a False
        # gate is accepted without error — no gate call site exists in the engine logic yet.
        assert eng._coordinator is fake
    finally:
        await eng.store.close()


def test_runner_holds_passed_coordinator() -> None:
    fake = _NotLeaderCoordinator()
    runner = RegistryRunner(Registry(), store=_NullStore(), coordinator=fake)  # type: ignore[arg-type]
    assert runner._coordinator is fake
    assert runner.coordinator is fake  # exposed for Steps 4/5


def test_runner_defaults_to_null_coordinator() -> None:
    runner = RegistryRunner(Registry(), store=_NullStore())  # type: ignore[arg-type]
    assert isinstance(runner.coordinator, NullCoordinator)


async def test_engine_add_registry_threads_coordinator_into_runner(tmp_path: Path) -> None:
    fake = _NotLeaderCoordinator()
    eng = await Engine.create(tmp_path / "cluster3.db", poll_interval=0.02, coordinator=fake)
    try:
        runner = eng.add_registry(Registry())
        assert runner.coordinator is fake  # the engine threads its coordinator into the runner
    finally:
        await eng.store.close()


# --- build_coordinator factory ----------------------------------------------


def test_build_coordinator_none_settings_returns_null() -> None:
    assert isinstance(build_coordinator(_NullStore(), None), NullCoordinator)


def test_build_coordinator_disabled_returns_null() -> None:
    coord = build_coordinator(_NullStore(), ClusterSettings(enabled=False))
    assert isinstance(coord, NullCoordinator)


def test_build_coordinator_enabled_but_non_postgres_store_returns_null() -> None:
    # Defensive: enabled is gated to backend=postgres by ServiceSettings, but a store without a
    # `_pool` (SQLite) still falls back to the safe single-node null coordinator rather than crashing.
    coord = build_coordinator(_NullStore(), ClusterSettings(enabled=True))
    assert isinstance(coord, NullCoordinator)


async def test_build_coordinator_sqlite_store_returns_null(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "factory.db")
    try:
        coord = build_coordinator(store, ClusterSettings(enabled=True))
        assert isinstance(coord, NullCoordinator)  # SQLite has no _pool → null
    finally:
        await store.close()


# --- DbCoordinator construction (DB-free; the live behaviour is in the gated PG tests) ------


def test_db_coordinator_lock_key_namespaced_by_schema() -> None:
    """The nodes-DDL advisory lock key is schema-namespaced (matching PostgresStore._lock_key), so two
    deployments sharing one database via different schemas don't contend. No DB needed — the key is
    computed at construction (the pool is never touched)."""
    assert DbCoordinator(None, "n")._lock_key == "public:mefor_cluster_nodes"
    assert (
        DbCoordinator(None, "n", db_schema="tenant_a")._lock_key == "tenant_a:mefor_cluster_nodes"
    )


class _PoolStore:
    """A store stand-in that LOOKS Postgres-backed (has ``_pool``) and carries a ``_settings`` with a
    ``db_schema``, so build_coordinator threads the schema through to the DbCoordinator's lock key."""

    class _Settings:
        db_schema = "tenant_a"

    def __init__(self) -> None:
        self._pool = object()  # non-None → build_coordinator treats it as Postgres
        self._owner = "host:1:abcd1234"
        self._settings = self._Settings()


def test_build_coordinator_threads_store_schema_into_lock_key() -> None:
    coord = build_coordinator(_PoolStore(), ClusterSettings(enabled=True))
    assert isinstance(coord, DbCoordinator)
    assert coord.node_id == "host:1:abcd1234"  # reuses store._owner
    assert coord._lock_key == "tenant_a:mefor_cluster_nodes"  # store schema threaded through


# --- Step 4b: the runner threads coordinator.is_leader into each source ------


class _SpySource(SourceConnector):
    """A source that records the leader_gate the runner passed to start(), so a test can prove the
    runner threads the coordinator's is_leader predicate through (not the coordinator object)."""

    polls_shared_resource = True
    last_gate: Callable[[], bool] | None = None

    def __init__(self) -> None:
        type(self).last_gate = None

    async def start(
        self, handler: InboundHandler, *, leader_gate: Callable[[], bool] | None = None
    ) -> None:
        type(self).last_gate = leader_gate

    async def stop(self) -> None:
        return None


class _ListenSpySource(_SpySource):
    """Like :class:`_SpySource` but a LISTEN source (its own per-node endpoint) — so the runner must
    NOT emit the 'intake is leader-gated' start-time notice for it."""

    polls_shared_resource = False


async def test_runner_threads_coordinator_is_leader_into_source(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The runner must pass coordinator.is_leader (a cheap sync bound method = Callable[[], bool]) to
    # source.start — NOT the coordinator object — so transports/ stays free of any pipeline import.
    # Under active-passive (Workstream A1) the graph (and thus the source) starts only on the LEADER, so
    # drive a clustered LEADER coordinator: the engine brings the graph up and the runner threads the
    # predicate, which on the leader reports True.
    fake = _LeaderCoordinator()
    monkeypatch.setattr(wiring_runner, "build_source", lambda cfg: _SpySource())

    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    inbox = tmp_path / "in"
    inbox.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import inbound, outbound, router, handler, Send, File
            inbound("in", File(directory={str(inbox)!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")
            outbound("out", File(directory={str(tmp_path / "out")!r}, filename="x.hl7"))

            @router("r")
            def route(msg):
                return ["h"]

            @handler("h")
            def handle(msg):
                return Send("out", msg)
            """
        ),
        encoding="utf-8",
    )
    eng = await Engine.create(tmp_path / "thread.db", poll_interval=0.05, coordinator=fake)
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        # The spy captured the exact bound method the coordinator exposes — calling it reflects this
        # leader's gate (True), proving the live predicate (not the object) was threaded through.
        assert _SpySource.last_gate == fake.is_leader
        assert _SpySource.last_gate is not None and _SpySource.last_gate() is True
    finally:
        await eng.stop()


async def test_runner_logs_leader_gated_only_for_poll_sources(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # The operator-facing 'intake is leader-gated' start-time INFO line is the signal an operator
    # relies on to know only the leader polls this resource. It must fire for a POLL source
    # (polls_shared_resource True) and NOT for a LISTEN source — so a silent drop or an inverted
    # polls_shared_resource guard in the runner is caught. Under active-passive (Workstream A1) the
    # graph only starts on the LEADER, so drive a clustered LEADER coordinator (the runner emits the
    # line when it starts the poll source on the leader).
    import logging

    def _build(source_cls: type[_SpySource]) -> str:
        monkeypatch.setattr(wiring_runner, "build_source", lambda cfg: source_cls())
        cfgdir = tmp_path / source_cls.__name__
        cfgdir.mkdir()
        inbox = tmp_path / f"in-{source_cls.__name__}"
        inbox.mkdir()
        (cfgdir / "c.py").write_text(
            textwrap.dedent(
                f"""
                from messagefoundry import inbound, outbound, router, handler, Send, File
                inbound("in", File(directory={str(inbox)!r}, pattern="*.hl7", poll_seconds=0.05),
                        router="r")
                outbound("out", File(directory={str(tmp_path / "out")!r}, filename="x.hl7"))

                @router("r")
                def route(msg):
                    return ["h"]

                @handler("h")
                def handle(msg):
                    return Send("out", msg)
                """
            ),
            encoding="utf-8",
        )
        return str(cfgdir)

    async def _run(source_cls: type[_SpySource]) -> list[str]:
        cfgdir = _build(source_cls)
        eng = await Engine.create(
            tmp_path / f"{source_cls.__name__}.db", poll_interval=0.05, coordinator=fake
        )
        eng.add_registry(load_config(Path(cfgdir)))
        caplog.clear()
        with caplog.at_level(logging.INFO, logger=wiring_runner.log.name):
            await eng.start()
            try:
                return [r.getMessage() for r in caplog.records if "leader-gated" in r.getMessage()]
            finally:
                await eng.stop()

    fake = _LeaderCoordinator()
    poll_msgs = await _run(_SpySource)  # polls_shared_resource True → logged
    assert any("intake is leader-gated" in m for m in poll_msgs)
    listen_msgs = await _run(_ListenSpySource)  # listen source → NOT logged
    assert listen_msgs == []


async def test_follower_file_source_does_not_ingest(tmp_path: Path) -> None:
    # End-to-end: a real FileSource on a node whose coordinator reports NOT leader must leave a
    # dropped file untouched. Under active-passive (Workstream A1) a follower does not run the graph at
    # all, so the source is never even started (an even stronger guarantee than Step 4b's poll-skip).
    # Single-node (the null coordinator, is_leader True) ingests it — covered by test_wiring_serve; here
    # we prove the follower side stays idle.
    fake = _NotLeaderCoordinator()
    cfgdir = tmp_path / "cfg"
    cfgdir.mkdir()
    inbox = tmp_path / "in"
    inbox.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import inbound, outbound, router, handler, Send, File
            inbound("in", File(directory={str(inbox)!r}, pattern="*.hl7", poll_seconds=0.02),
                    router="r")
            outbound("out", File(directory={str(tmp_path / "out")!r}, filename="{{MSH-10}}.hl7"))

            @router("r")
            def route(msg):
                return ["h"]

            @handler("h")
            def handle(msg):
                return Send("out", msg)
            """
        ),
        encoding="utf-8",
    )
    (inbox / "a.hl7").write_bytes(b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\r")
    eng = await Engine.create(tmp_path / "follower.db", poll_interval=0.02, coordinator=fake)
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        await asyncio.sleep(0.15)  # several poll intervals — a follower scans none of them
        assert (inbox / "a.hl7").exists()  # left untouched (not read, not moved)
        assert not (inbox / ".processed" / "a.hl7").exists()
    finally:
        await eng.stop()


# --- the FIFO workers claim each lane without an owner kwarg (active-active excised) ----


class _FifoClaimSpyStore:
    """A store stand-in whose ``claim_next_fifo`` records the args it was called with, then stops the
    worker loop and returns ``None``. Lets a test prove each FIFO worker still claims its lane after the
    active-active ``owner`` kwarg was removed (no owner threading remains)."""

    supports_ingest_stage = True

    def __init__(self, stop: asyncio.Event) -> None:
        self._stop = stop
        self.calls: list[tuple[str, str]] = []

    async def claim_next_fifo(
        self,
        name: str,
        now: float | None = None,
        *,
        stage: str = "outbound",
    ) -> None:
        self.calls.append((name, stage))
        self._stop.set()  # one claim then break the worker loop
        return None


async def _run_one_claim(coordinator: ClusterCoordinator, worker: str) -> list[tuple[str, str]]:
    """Drive a single FIFO worker through exactly one claim against the spy store and return the
    recorded (name, stage) calls."""
    from messagefoundry.pipeline.wiring_runner import RegistryRunner

    # poll_interval=0 so the post-claim _wait_for_work returns instantly (the spy already set _stop, so
    # the loop exits on the next guard) — keeps the test fast and deterministic.
    runner = RegistryRunner(
        Registry(), store=_NullStore(), coordinator=coordinator, poll_interval=0.0
    )  # type: ignore[arg-type]
    spy = _FifoClaimSpyStore(runner._stop)
    runner.store = spy  # type: ignore[assignment]
    await getattr(runner, worker)("LANE")
    return spy.calls


async def test_fifo_workers_claim_lane_single_node() -> None:
    # NullCoordinator (single node): each FIFO worker claims its lane by name + stage with no owner
    # kwarg (active-active lane ownership was excised).
    expected = {
        "_delivery_worker": ("LANE", "outbound"),
        "_router_worker": ("LANE", "ingress"),
        "_transform_worker": ("LANE", "routed"),
    }
    for worker, call in expected.items():
        calls = await _run_one_claim(NullCoordinator(), worker)
        assert calls == [call]


async def test_fifo_workers_claim_lane_when_clustered() -> None:
    # A clustered (active-passive) coordinator: the workers still claim their lane the same way — there
    # is no per-node owner threading anymore (the graph runs on the leader only).
    fake = _NotLeaderCoordinator()
    for worker in ("_delivery_worker", "_router_worker", "_transform_worker"):
        calls = await _run_one_claim(fake, worker)
        assert len(calls) == 1


class _NullStore:
    """A do-nothing stand-in for the store the RegistryRunner holds — the runner only stores the
    reference at construction (the gate-threading we exercise here never touches it). Crucially it
    has NO ``_pool``, so build_coordinator treats it as non-Postgres."""


# --- Step 6: NullCoordinator config-token + convergence are no-ops (byte-identical single-node) ----


def test_null_coordinator_is_not_clustered() -> None:
    # Single-node: NOT a cluster → the engine spawns no config-convergence loop and an operator reload
    # never bumps a shared version token. Byte-identical to before Step 6.
    assert NullCoordinator().is_clustered() is False


async def test_null_coordinator_config_version_is_zero_and_bump_noop() -> None:
    coord = NullCoordinator()
    assert await coord.config_version() == 0
    assert coord.config_version_cached() == 0
    assert await coord.bump_config_version() == 0  # no-op, still 0 (nothing to coordinate)
    assert coord.config_version_cached() == 0


def test_db_coordinator_is_clustered() -> None:
    # Clustered: the engine spawns the config-convergence loop and an operator reload bumps the token.
    # Construction-only (no pool touched).
    assert DbCoordinator(None, "n").is_clustered() is True


def test_db_coordinator_config_version_cached_reads_attribute() -> None:
    # config_version_cached() is a cheap sync read of the value the maintenance loop refreshes (and that
    # bump_config_version updates immediately). Construction-only: drive the attribute directly (the
    # live DB read/bump is in the gated PG suite).
    coord = DbCoordinator(None, "n")
    assert coord.config_version_cached() == 0  # 0 until the first read/refresh
    coord._config_version = 7
    assert coord.config_version_cached() == 7


async def test_sqlite_converge_reference_cache_is_noop(tmp_path: Path) -> None:
    # SQLite is single-node (sole writer), so converge_reference_cache() is a no-op returning []: a
    # write keeps the cache current, and a converge after it refreshes nothing.
    store = await MessageStore.open(tmp_path / "conv.db")
    try:
        assert await store.converge_reference_cache() == []
        await store.write_reference_snapshot(name="codes", version="v1", rows={"A": "1"})
        assert store.reference_view()["codes"] == {"A": "1"}
        assert await store.converge_reference_cache() == []  # still a no-op, cache already current
    finally:
        await store.close()


async def test_sqlite_converge_state_cache_is_noop(tmp_path: Path) -> None:
    # Track B Step 6b: SQLite is single-node (sole writer), so converge_state_cache() is a no-op returning
    # [] and enable_state_convergence() is a harmless no-op (no cross-node convergence on this backend).
    store = await MessageStore.open(tmp_path / "state-conv.db")
    try:
        assert store.enable_state_convergence() is None  # harmless no-op
        assert await store.converge_state_cache() == []
        # A write still keeps the cache current the single-node way; converge stays a no-op.
        mid = await store.enqueue_ingress(channel_id="IB", raw="MSH|^~\\&|x\r", now=100.0)
        ingress = await store.claim_next_fifo("IB", now=110.0, stage=Stage.INGRESS.value)
        await store.route_handoff(
            ingress_id=ingress.id,
            message_id=mid,
            channel_id="IB",
            handlers=[("H1", "MSH|^~\\&|x\r")],
            disposition=MessageStatus.ROUTED,
            now=120.0,
        )
        routed = await store.claim_next_fifo("IB", now=130.0, stage=Stage.ROUTED.value)
        await store.transform_handoff(
            routed_id=routed.id,
            message_id=mid,
            channel_id="IB",
            deliveries=[("OB1", "x")],
            state_ops=[("ns", "k", {"v": 1})],
            now=140.0,
        )
        assert store.state_view()[("ns", "k")] == {"v": 1}  # already current
        assert await store.converge_state_cache() == []  # still a no-op
    finally:
        await store.close()


# --- Step 6: ReferenceSyncRunner leader-gates materialize + always converges ----


class _LeaderCoordinator(NullCoordinator):
    """Leader by default (is_leader True) but is_clustered True — a clustered LEADER stand-in."""

    def is_clustered(self) -> bool:
        return True


class _CountingStore:
    """A store stand-in counting write_reference_snapshot vs converge_reference_cache calls, to prove a
    follower does NOT materialize from source but DOES converge, and a leader materializes as today."""

    def __init__(self) -> None:
        self.writes = 0
        self.converges = 0

    async def write_reference_snapshot(self, *, name: str, version: str, rows: object) -> None:
        self.writes += 1

    async def converge_reference_cache(self) -> list[str]:
        self.converges += 1
        return []

    async def record_audit(self, action: str, *, actor: str, detail: str) -> None:
        pass


def _file_spec(tmp_path: Path) -> ReferenceSpec:
    csv = tmp_path / "codes.csv"
    csv.write_text("key,value\nA,1\n", encoding="utf-8")
    return ReferenceSpec(name="codes", source=FileRef(path=str(csv)))


async def test_reference_runner_follower_converges_without_materializing(tmp_path: Path) -> None:
    # A follower (is_leader False): run_once must NOT materialize from source (no write) but MUST
    # converge the local cache from the shared snapshot the leader wrote.
    store = _CountingStore()
    runner = ReferenceSyncRunner(
        store,  # type: ignore[arg-type]
        lambda: [_file_spec(tmp_path)],
        ReferenceSettings(),
        coordinator=_NotLeaderCoordinator(),  # is_leader False
    )
    result = await runner.run_once(force=True)
    assert store.writes == 0  # follower never re-reads the source
    assert store.converges == 1  # but always converges
    assert result.synced == 0


async def test_reference_runner_leader_materializes_and_converges(tmp_path: Path) -> None:
    # A leader (is_leader True): run_once materializes from source (write) AND converges (the converge
    # is a no-op on its own just-written snapshot, but the call still happens every pass).
    store = _CountingStore()
    runner = ReferenceSyncRunner(
        store,  # type: ignore[arg-type]
        lambda: [_file_spec(tmp_path)],
        ReferenceSettings(),
        coordinator=_LeaderCoordinator(),  # is_leader True, is_clustered True
    )
    result = await runner.run_once(force=True)
    assert store.writes == 1  # leader re-reads the source and writes the shared snapshot
    assert store.converges == 1
    assert result.synced == 1


async def test_reference_runner_default_coordinator_materializes_as_today(tmp_path: Path) -> None:
    # No coordinator passed → NullCoordinator (is_leader True) → byte-identical single-node behaviour:
    # materialize from source every pass, converge a no-op.
    store = await MessageStore.open(tmp_path / "ref.db")
    try:
        runner = ReferenceSyncRunner(store, lambda: [_file_spec(tmp_path)], ReferenceSettings())
        result = await runner.run_once(force=True)
        assert result.synced == 1
        assert store.reference_view()["codes"] == {"A": "1"}  # materialized exactly as before
    finally:
        await store.close()


# --- Step 6: ConfigConvergenceRunner reloads a follower when the version advances ----


class _FakeClusterToken:
    """A clustered coordinator whose cached config version is operator-driveable, to exercise the
    config-convergence loop without a real DB. ``is_clustered`` True; the cached version is set by
    tests to simulate an operator reload on a sibling node bumping the shared token."""

    def __init__(self) -> None:
        self.node_id = "fake"
        self._cached = 0

    def is_clustered(self) -> bool:
        return True

    def config_version_cached(self) -> int:
        return self._cached


async def test_config_convergence_reloads_when_version_advances() -> None:
    # A follower at applied=0 sees the shared version jump to 3 → it reloads ONCE and advances applied
    # to 3; a second pass with no further change does NOT reload (idempotent / no feedback loop).
    coord = _FakeClusterToken()
    applied = {"v": 0}
    reloads: list[int] = []

    async def fake_reload() -> None:
        reloads.append(coord.config_version_cached())

    runner = ConfigConvergenceRunner(
        coord,  # type: ignore[arg-type]
        applied_version=lambda: applied["v"],
        set_applied_version=lambda v: applied.__setitem__("v", v),
        reload=fake_reload,
        interval_seconds=10.0,
    )
    assert await runner.converge_once() is False  # version unchanged (0 == 0) → no reload
    coord._cached = 3  # a sibling operator reload bumped the shared token
    assert await runner.converge_once() is True  # behind → reload + advance applied to 3
    assert reloads == [3] and applied["v"] == 3
    assert await runner.converge_once() is False  # caught up → no second reload
    assert reloads == [3]


async def test_config_convergence_initiator_does_not_re_reload() -> None:
    # The node that initiated the reload already advanced its applied version to the bumped value (the
    # engine does this right after bumping), so its own loop sees no change and does NOT re-reload.
    coord = _FakeClusterToken()
    coord._cached = 5  # this node just bumped to 5...
    applied = {"v": 5}  # ...and advanced its own applied version to match
    reloads: list[int] = []

    async def fake_reload() -> None:
        reloads.append(1)

    runner = ConfigConvergenceRunner(
        coord,  # type: ignore[arg-type]
        applied_version=lambda: applied["v"],
        set_applied_version=lambda v: applied.__setitem__("v", v),
        reload=fake_reload,
        interval_seconds=10.0,
    )
    assert await runner.converge_once() is False  # 5 <= 5 → the initiator does not re-reload
    assert reloads == []


async def test_config_convergence_bad_reload_does_not_advance_or_kill_loop() -> None:
    # A bad local config during convergence: converge_once propagates (the loop isolates+logs it), and
    # the applied version is NOT advanced, so the next tick retries rather than silently skipping it.
    coord = _FakeClusterToken()
    coord._cached = 2
    applied = {"v": 0}

    async def bad_reload() -> None:
        raise RuntimeError("bad local config")

    runner = ConfigConvergenceRunner(
        coord,  # type: ignore[arg-type]
        applied_version=lambda: applied["v"],
        set_applied_version=lambda v: applied.__setitem__("v", v),
        reload=bad_reload,
        interval_seconds=10.0,
    )
    with pytest.raises(RuntimeError, match="bad local config"):
        await runner.converge_once()
    assert applied["v"] == 0  # NOT advanced — a failed convergence retries next tick


async def test_engine_single_node_spawns_no_convergence_loop(tmp_path: Path) -> None:
    # Single-node (NullCoordinator, is_clustered False): the engine must NOT spawn the config-
    # convergence loop, so behaviour is byte-identical.
    eng = await Engine.create(tmp_path / "single.db", poll_interval=0.02)
    try:
        await eng.start()
        assert eng._config_convergence is None  # never spawned single-node
        assert eng._state_convergence is None  # Track B Step 6b: also never spawned single-node
    finally:
        await eng.stop()


async def test_engine_clustered_spawns_convergence_and_seeds_applied(tmp_path: Path) -> None:
    # Clustered (is_clustered True): the engine spawns the convergence loop and seeds the applied
    # version from the coordinator's current config_version, so a fresh node doesn't self-reload.
    class _SeededCoordinator(_NotLeaderCoordinator):
        async def config_version(self) -> int:
            return 4  # the cluster is already at version 4 when this node joins

    eng = await Engine.create(
        tmp_path / "clustered.db", poll_interval=0.02, coordinator=_SeededCoordinator()
    )
    try:
        await eng.start()
        assert eng._config_convergence is not None  # spawned in clustered mode
        assert eng._state_convergence is not None  # Track B Step 6b: also spawned in clustered mode
        assert eng._applied_config_version == 4  # seeded → fresh node does not self-reload
    finally:
        await eng.stop()


# --- Step 6: engine reload(propagate=...) bumps the shared token (initiator side) ----


class _BumpRecordingCoordinator(_NotLeaderCoordinator):
    """A clustered coordinator that records bump_config_version calls and returns an incrementing
    version, so a test can prove an operator-initiated reload bumps the shared token exactly once and
    advances the initiator's applied version (the feedback-avoidance the convergence story relies on)."""

    def __init__(self) -> None:
        super().__init__()
        self.bumps = 0
        self._version = 0

    async def config_version(self) -> int:
        return self._version

    async def bump_config_version(self) -> int:
        self.bumps += 1
        self._version += 1
        return self._version


def _minimal_config(cfgdir: Path, tmp_path: Path) -> None:
    """Write a minimal valid config dir (one inbound→handler→outbound graph) for an engine reload."""
    cfgdir.mkdir()
    inbox = tmp_path / f"in-{cfgdir.name}"
    inbox.mkdir()
    (cfgdir / "c.py").write_text(
        textwrap.dedent(
            f"""
            from messagefoundry import inbound, outbound, router, handler, Send, File
            inbound("in", File(directory={str(inbox)!r}, pattern="*.hl7", poll_seconds=0.05),
                    router="r")
            outbound("out", File(directory={str(tmp_path / f"out-{cfgdir.name}")!r}, filename="x.hl7"))

            @router("r")
            def route(msg):
                return ["h"]

            @handler("h")
            def handle(msg):
                return Send("out", msg)
            """
        ),
        encoding="utf-8",
    )


async def test_engine_operator_reload_propagate_bumps_and_advances_applied(tmp_path: Path) -> None:
    # The OPERATOR-initiated arm of config convergence (what /config/reload drives with
    # propagate=not dry_run): a successful non-dry-run reload in clustered mode bumps the shared token
    # exactly once AND advances THIS node's applied version to the bumped value, so the initiator's own
    # convergence loop sees no change and does not re-reload (feedback-avoidance).
    coord = _BumpRecordingCoordinator()
    cfgdir = tmp_path / "cfg"
    _minimal_config(cfgdir, tmp_path)
    eng = await Engine.create(
        tmp_path / "propagate.db", poll_interval=0.05, config_dir=cfgdir, coordinator=coord
    )
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        await eng.reload(propagate=True)  # the startup --config dir; the operator-initiated arm
        assert coord.bumps == 1  # bumped exactly once on the operator reload
        assert eng._applied_config_version == 1  # advanced to the bumped value (no self re-reload)
    finally:
        await eng.stop()


async def test_engine_convergence_reload_does_not_propagate(tmp_path: Path) -> None:
    # The per-node convergence reload (propagate=False, the _converge_reload path) must NOT bump the
    # shared token — otherwise nodes would chase each other's reloads. Proven by a propagate=False
    # reload leaving the recorded bump count at zero.
    coord = _BumpRecordingCoordinator()
    cfgdir = tmp_path / "cfg"
    _minimal_config(cfgdir, tmp_path)
    eng = await Engine.create(
        tmp_path / "noprop.db", poll_interval=0.05, config_dir=cfgdir, coordinator=coord
    )
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        await eng.reload(propagate=False)  # the convergence arm — must not bump
        assert coord.bumps == 0  # convergence reload never bumps
    finally:
        await eng.stop()


# --- Step 6b: StateConvergenceRunner read-throughs newer transform-state (no DB) ----


async def test_state_convergence_runner_returns_refreshed_namespaces() -> None:
    # A converge callback that reports a refreshed namespace → converge_once surfaces it unchanged.
    async def fake_converge() -> list[str]:
        return ["ns1"]

    runner = StateConvergenceRunner(converge=fake_converge, interval_seconds=10.0)
    assert await runner.converge_once() == ["ns1"]


async def test_state_convergence_runner_isolates_errors() -> None:
    # A converge that raises must NOT propagate: converge_once swallows it (logs the class only, alerts)
    # and returns [] so the supervised loop keeps going and retries next interval.
    async def bad_converge() -> list[str]:
        raise RuntimeError("decrypt boom")

    runner = StateConvergenceRunner(converge=bad_converge, interval_seconds=10.0)
    assert await runner.converge_once() == []  # isolated, not raised


# --- build_coordinator backend dispatch (no DB; stub stores) ----------------


def test_build_coordinator_dispatches_sqlserver_to_its_own_coordinator() -> None:
    # A SQL Server store ALSO exposes a `_pool` (aioodbc), but DbCoordinator drives asyncpg — so it must
    # be dispatched to SqlServerCoordinator, not the (crashing) DbCoordinator path. Stub store; no DB.
    from messagefoundry.pipeline.cluster import build_coordinator
    from messagefoundry.pipeline.cluster_sqlserver import SqlServerCoordinator

    class _Backend:
        value = "sqlserver"

    class _Settings:
        backend = _Backend()
        db_schema = None

    class _Store:
        _pool = object()
        _owner = "host:1:abcd"
        _settings = _Settings()

    class _Cluster:
        enabled = True
        node_id = None

    coord = build_coordinator(_Store(), _Cluster())
    assert isinstance(coord, SqlServerCoordinator)
    assert coord.node_id == "host:1:abcd"  # reuses store._owner as the node id


def test_build_coordinator_postgres_still_gets_dbcoordinator() -> None:
    # Dispatch must NOT regress the Postgres path: a non-sqlserver store with a pool still gets DbCoordinator.
    from messagefoundry.pipeline.cluster import DbCoordinator, build_coordinator

    class _Backend:
        value = "postgres"

    class _Settings:
        backend = _Backend()
        db_schema = None

    class _Store:
        _pool = object()
        _owner = "host:2:beef"
        _settings = _Settings()

    class _Cluster:
        enabled = True
        node_id = None

    assert isinstance(build_coordinator(_Store(), _Cluster()), DbCoordinator)
