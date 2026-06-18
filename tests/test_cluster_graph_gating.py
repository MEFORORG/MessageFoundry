# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Active-passive graph gating (Workstream A1/A3/A4) — the always-run unit tests (no DB needed).

These prove the engine runs the wired graph **only while this node holds leadership**: a clustered
follower stays warm without binding listeners or running workers, a node starts the graph on
acquiring leadership and stops it on losing it, and single-node stays byte-identical (the graph is
brought up directly at start()). The live multi-node behaviour against a real Postgres lands with the
failover suite (Increment 3); here the leadership gate is a controllable stand-in coordinator.
"""

from __future__ import annotations

import textwrap
from pathlib import Path

from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.engine import Engine


class _FlipCoordinator(NullCoordinator):
    """A clustered coordinator whose leadership is flippable by a test (``leader`` attribute), so the
    engine's graph supervisor can be driven through acquire/lose deterministically. ``is_clustered`` is
    True (the active-passive path); ``reclaims_inflight`` stays False (NullCoordinator) so the engine
    spawns no Postgres-only leader sweep against the SQLite test store."""

    def __init__(self, *, leader: bool = False) -> None:
        super().__init__(node_id="flip")
        self.leader = leader

    def is_leader(self) -> bool:
        return self.leader

    def is_clustered(self) -> bool:
        return True


def _minimal_graph(cfgdir: Path, tmp_path: Path) -> None:
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


async def test_clustered_follower_does_not_start_the_graph(tmp_path: Path) -> None:
    # A clustered node that is NOT the leader stays warm: the registry runner is never started (no
    # listeners bound, no workers running), but the engine itself is up (coordinator + convergence).
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    coord = _FlipCoordinator(leader=False)
    eng = await Engine.create(tmp_path / "follower.db", poll_interval=0.05, coordinator=coord)
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        assert eng._registry_runner is not None
        assert eng._registry_runner.running is False  # standby: graph not running
        assert eng._graph_supervisor is not None  # but the supervisor is watching for promotion
    finally:
        await eng.stop()


async def test_clustered_leader_starts_the_graph_at_startup(tmp_path: Path) -> None:
    # A clustered node that is already the leader at start() brings the graph up synchronously (the
    # immediate reconcile), so it is processing right after start() — no poll-interval delay.
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    coord = _FlipCoordinator(leader=True)
    eng = await Engine.create(tmp_path / "leader.db", poll_interval=0.05, coordinator=coord)
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        assert eng._registry_runner is not None and eng._registry_runner.running is True
    finally:
        await eng.stop()


async def test_reconcile_starts_on_promotion_and_stops_on_demotion(tmp_path: Path) -> None:
    # Drive the reconcile directly (no loop timing): a follower's graph is stopped; on promotion the
    # next reconcile starts it; on demotion the next reconcile stops it again. This is the failover
    # behaviour the supervisor loop polls for.
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    coord = _FlipCoordinator(leader=False)
    eng = await Engine.create(tmp_path / "flip.db", poll_interval=0.05, coordinator=coord)
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        assert eng._registry_runner is not None
        assert eng._registry_runner.running is False  # standby

        coord.leader = True
        await eng._reconcile_graph()
        assert eng._registry_runner.running is True  # promoted → graph up

        coord.leader = False
        await eng._reconcile_graph()
        assert eng._registry_runner.running is False  # demoted → graph down

        coord.leader = True
        await eng._reconcile_graph()
        assert eng._registry_runner.running is True  # re-promoted → graph back up (restartable)
    finally:
        await eng.stop()


async def test_reconcile_is_idempotent_while_leader(tmp_path: Path) -> None:
    # A second reconcile while already leader+running must NOT re-start the graph (the runner's own
    # running guard makes _start_graph a no-op), so repeated supervisor polls are harmless.
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    coord = _FlipCoordinator(leader=True)
    eng = await Engine.create(tmp_path / "idem.db", poll_interval=0.05, coordinator=coord)
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        assert eng._registry_runner is not None and eng._registry_runner.running is True
        await eng._reconcile_graph()
        await eng._reconcile_graph()
        assert eng._registry_runner.running is True  # still up, no churn
    finally:
        await eng.stop()


class _LeaderThenLostCoordinator(NullCoordinator):
    """Clustered; reports leader for the first ``true_calls`` is_leader() reads, then False — to
    simulate leadership lost DURING a slow _start_graph (a fence mid-bring-up). _reconcile_graph reads
    is_leader() once to enter _start_graph, then re-checks after it returns; the re-check must see the
    loss and stop the graph straight back down."""

    def __init__(self, *, true_calls: int) -> None:
        super().__init__(node_id="lost")
        self._remaining = true_calls

    def is_leader(self) -> bool:
        if self._remaining > 0:
            self._remaining -= 1
            return True
        return False

    def is_clustered(self) -> bool:
        return True


async def test_leadership_lost_during_start_graph_tears_back_down(tmp_path: Path) -> None:
    # Finding-3 guard: if leadership is lost mid-_start_graph, _reconcile_graph's post-start re-check
    # must stop the graph in the same pass — a demoted node never keeps the graph running. The
    # coordinator reports leader for exactly the entry check, then not-leader for the re-check.
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    coord = _LeaderThenLostCoordinator(true_calls=1)
    eng = await Engine.create(tmp_path / "lost.db", poll_interval=0.05, coordinator=coord)
    eng.add_registry(load_config(cfgdir))
    # start() runs the immediate reconcile: enter _start_graph (leader), re-check (not leader) → stop.
    await eng.start()
    try:
        assert eng._registry_runner is not None
        assert eng._registry_runner.running is False  # started then torn straight back down
    finally:
        await eng.stop()


async def test_single_node_starts_graph_directly_no_supervisor(tmp_path: Path) -> None:
    # Single-node (NullCoordinator, is_clustered False): the graph is brought up directly at start()
    # (byte-identical) and NO graph supervisor is spawned.
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    eng = await Engine.create(tmp_path / "single.db", poll_interval=0.05)
    eng.add_registry(load_config(cfgdir))
    await eng.start()
    try:
        assert eng._registry_runner is not None and eng._registry_runner.running is True
        assert eng._graph_supervisor is None  # never spawned single-node
    finally:
        await eng.stop()


class _ReclaimingFlipCoordinator(NullCoordinator):
    """Mimics the SqlServerCoordinator profile: clustered + ``reclaims_inflight`` True (so the engine
    SKIPS the unconditional startup reset), but on a SQLite store with no ``reclaim_expired_leases`` —
    so ``_leader_maintenance`` stays None and failover recovery must come from the on-promotion
    ``reset_stale_inflight`` in ``_start_graph``."""

    def __init__(self, *, leader: bool = False) -> None:
        super().__init__(node_id="flip")
        self.leader = leader

    def is_leader(self) -> bool:
        return self.leader

    def is_clustered(self) -> bool:
        return True

    def reclaims_inflight(self) -> bool:
        return True


async def test_active_passive_recovers_inflight_on_promotion(tmp_path: Path) -> None:
    # Active-passive without per-row leases (SQL Server profile): startup skips the unconditional reset
    # (reclaims_inflight True), and there is no leader reclaim sweep (the SQLite store has no
    # reclaim_expired_leases), so the ONLY in-flight recovery is the on-promotion reset_stale_inflight in
    # _start_graph. A booting standby must not reset (would steal the primary's rows); a promoted node must.
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    coord = _ReclaimingFlipCoordinator(leader=False)
    eng = await Engine.create(tmp_path / "ap.db", poll_interval=0.05, coordinator=coord)
    eng.add_registry(load_config(cfgdir))

    calls: list[int] = []
    orig = eng.store.reset_stale_inflight

    async def _spy(*a: object, **k: object) -> int:
        calls.append(1)
        return await orig(*a, **k)

    eng.store.reset_stale_inflight = _spy  # type: ignore[method-assign]
    await eng.start()
    try:
        assert eng._leader_maintenance is None  # SQLite has no reclaim sweep
        assert (
            calls == []
        )  # booting standby must NOT reset (no startup reset, not leader → no _start_graph)
        coord.leader = True
        await eng._reconcile_graph()  # promotion
        assert eng._registry_runner is not None and eng._registry_runner.running is True
        assert len(calls) == 1  # recovered the prior leader's in-flight rows exactly on promotion
    finally:
        await eng.stop()


async def test_postgres_promotion_uses_recover_on_promotion_not_sweep(tmp_path: Path) -> None:
    # #293: on the per-row-lease (Postgres) profile, _start_graph's promotion recovery is the
    # owner-scoped, lease-BLIND recover_on_promotion (re-pend the prior leader's rows + take over its
    # lane leases at once) — NOT the lease-gated periodic sweep (which recovers nothing until the ~60s
    # TTL ages out, the bug) and NOT the SQL Server reset_stale_inflight branch. Give the SQLite test
    # store the two Postgres-only methods so _leader_maintenance is spawned, then spy the on-promotion call.
    cfgdir = tmp_path / "cfg"
    _minimal_graph(cfgdir, tmp_path)
    coord = _ReclaimingFlipCoordinator(leader=False)
    eng = await Engine.create(tmp_path / "pg_ap.db", poll_interval=0.05, coordinator=coord)
    eng.add_registry(load_config(cfgdir))

    promotion_calls: list[str | None] = []
    reset_calls: list[int] = []

    async def _reclaim(now: float | None = None, *, stage: str | None = None) -> int:
        return (
            0  # a no-op sweep, just so hasattr → _leader_maintenance is spawned (Postgres profile)
        )

    async def _recover(*, lane_owner: str | None, now: float | None = None) -> int:
        promotion_calls.append(lane_owner)
        return 0

    orig_reset = eng.store.reset_stale_inflight

    async def _reset_spy(*a: object, **k: object) -> int:
        reset_calls.append(1)
        return await orig_reset(*a, **k)  # type: ignore[arg-type]

    eng.store.reclaim_expired_leases = _reclaim  # type: ignore[attr-defined]
    eng.store.recover_inflight_on_promotion = _recover  # type: ignore[attr-defined]
    eng.store.reset_stale_inflight = _reset_spy  # type: ignore[method-assign]

    await eng.start()
    try:
        assert eng._leader_maintenance is not None  # Postgres profile spawns the leader maintenance
        coord.leader = True
        await eng._reconcile_graph()  # promotion
        assert eng._registry_runner is not None and eng._registry_runner.running is True
        assert len(promotion_calls) == 1  # the owner-scoped on-promotion recovery ran exactly once
        assert reset_calls == []  # NOT the SQL Server reset_stale_inflight branch
    finally:
        await eng.stop()
