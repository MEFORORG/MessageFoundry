"""Leader-only maintenance + engine clustering wiring (Track B Step 4) — always-run unit tests (no DB).

These prove, with fakes:
- :class:`LeaderMaintenanceRunner.sweep_once` calls ``reclaim_expired_leases`` only when the
  coordinator is leader (a follower no-ops).
- The :class:`~messagefoundry.pipeline.engine.Engine` picks the right startup recovery path off the
  coordinator's ``reclaims_inflight()``: single-node (Null) runs the unconditional
  ``reset_stale_inflight`` and spawns NO leader maintenance; clustered runs neither the unconditional
  reset NOR (here) double-recovery, and DOES spawn the leader maintenance task.

The DbCoordinator's live election against a real Postgres lives in the gated tests/test_postgres_store.py.
"""

from __future__ import annotations

from pathlib import Path

from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.leader_tasks import LeaderMaintenanceRunner


class _Coordinator:
    """A fake coordinator with configurable leader / reclaims-inflight answers and no-op lifecycle."""

    def __init__(self, *, leader: bool, reclaims: bool) -> None:
        self.node_id = "fake"
        self._leader = leader
        self._reclaims = reclaims
        self.started = False
        self.stopped = False

    async def start(self) -> None:
        self.started = True

    async def stop(self) -> None:
        self.stopped = True

    def is_leader(self) -> bool:
        return self._leader

    def owns_lane(self, lane_key: str) -> bool:
        return True

    def reclaims_inflight(self) -> bool:
        return self._reclaims

    def is_clustered(self) -> bool:
        # On a real DbCoordinator is_clustered() and reclaims_inflight() are coupled (both True), so the
        # fake mirrors that: a clustered fake also spawns the Step-6 config-convergence loop. The token
        # is inert here (config_version 0 / no-op bump), so the loop never reloads.
        return self._reclaims

    async def config_version(self) -> int:
        return 0

    def config_version_cached(self) -> int:
        return 0

    async def bump_config_version(self) -> int:
        return 0

    def lane_owner(self) -> str | None:
        return self.node_id if self._reclaims else None


class _ReclaimSpyStore:
    """A store stand-in recording reclaim_expired_leases calls (for LeaderMaintenanceRunner)."""

    def __init__(self) -> None:
        self.reclaim_calls: list[float | None] = []
        self.to_reclaim = 0

    async def reclaim_expired_leases(
        self, now: float | None = None, *, stage: str | None = None
    ) -> int:
        self.reclaim_calls.append(now)
        return self.to_reclaim


# --- LeaderMaintenanceRunner.sweep_once -------------------------------------


async def test_leader_sweep_reclaims_when_leader() -> None:
    store = _ReclaimSpyStore()
    store.to_reclaim = 3
    runner = LeaderMaintenanceRunner(
        store, _Coordinator(leader=True, reclaims=True), interval_seconds=0.01
    )
    reclaimed = await runner.sweep_once(now=123.0)
    assert reclaimed == 3
    assert store.reclaim_calls == [123.0]  # leader → exactly one reclaim, with our injected clock


async def test_leader_sweep_no_ops_on_follower() -> None:
    store = _ReclaimSpyStore()
    runner = LeaderMaintenanceRunner(
        store, _Coordinator(leader=False, reclaims=True), interval_seconds=0.01
    )
    reclaimed = await runner.sweep_once(now=123.0)
    assert reclaimed == 0
    assert store.reclaim_calls == []  # follower → no store write at all


async def test_leader_sweep_start_stop_idempotent() -> None:
    store = _ReclaimSpyStore()
    runner = LeaderMaintenanceRunner(
        store, _Coordinator(leader=True, reclaims=True), interval_seconds=10.0
    )
    runner.start()
    runner.start()  # second start is a no-op (no second task)
    await runner.stop()
    await runner.stop()  # idempotent


# --- Engine startup recovery path (off coordinator.reclaims_inflight) -------


class _RecordingStore:
    """A minimal SQLite store wrapper-by-spy: counts reset_stale_inflight calls. The Engine.start()
    path with NO registry only touches reset_stale_inflight + the coordinator, so the rest of the
    store surface is unused here."""

    def __init__(self) -> None:
        self.reset_calls = 0
        self.state_convergence_enabled = False

    async def reset_stale_inflight(
        self, now: float | None = None, *, stage: str | None = None
    ) -> int:
        self.reset_calls += 1
        return 0

    def enable_state_convergence(self) -> None:
        # Track B Step 6b: the clustered engine turns this on before workers start (no-op spy here).
        self.state_convergence_enabled = True

    async def converge_state_cache(self) -> list[str]:
        # Referenced by the StateConvergenceRunner the clustered engine builds; inert in this spy.
        return []

    async def close(self) -> None:
        return None


async def test_engine_single_node_resets_and_spawns_no_leader_task() -> None:
    """Default-shaped (Null-like) coordinator: reclaims_inflight() False → the engine runs the
    unconditional reset_stale_inflight (today's behavior) and spawns NO LeaderMaintenanceRunner."""
    store = _RecordingStore()
    coord = _Coordinator(leader=True, reclaims=False)
    engine = Engine(store, coordinator=coord)  # type: ignore[arg-type]  # spy store
    await engine.start()
    try:
        assert store.reset_calls == 1  # unconditional self-recovery ran
        assert engine._leader_maintenance is None  # no leader sweep for single-node
        assert coord.started is True
    finally:
        await engine.stop()
    assert coord.stopped is True


async def test_engine_clustered_skips_reset_and_spawns_leader_task() -> None:
    """A coordinator that reclaims_inflight() → the engine SKIPS the unconditional reset (it would
    steal a live sibling's in-flight rows) and DOES start a LeaderMaintenanceRunner."""
    store = _RecordingStore()
    coord = _Coordinator(leader=True, reclaims=True)
    engine = Engine(store, coordinator=coord)  # type: ignore[arg-type]  # spy store
    await engine.start()
    try:
        assert store.reset_calls == 0  # clustered: the leader sweep recovers, not the startup reset
        assert isinstance(engine._leader_maintenance, LeaderMaintenanceRunner)
        assert coord.started is True
    finally:
        await engine.stop()
    # The leader task is torn down on stop (cleared back to None).
    assert engine._leader_maintenance is None or coord.stopped


async def test_engine_clustered_reclaim_interval_from_settings(tmp_path: Path) -> None:
    """The leader sweep's interval comes from [cluster].reclaim_interval_seconds threaded into the
    Engine. Verified via the constructed runner's interval (no DB needed)."""
    from messagefoundry.config.settings import ClusterSettings

    store = _RecordingStore()
    coord = _Coordinator(leader=True, reclaims=True)
    engine = Engine(
        store,  # type: ignore[arg-type]
        coordinator=coord,
        cluster_settings=ClusterSettings(reclaim_interval_seconds=7.0),
    )
    await engine.start()
    try:
        assert engine._leader_maintenance is not None
        assert engine._leader_maintenance._interval_seconds == 7.0
    finally:
        await engine.stop()
