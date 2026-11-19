# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5984: transform-state convergence runs where another process shares the store, and only
where the store really converges.

Three defects, each pinned here. A clustered engine over a backend whose ``converge_state_cache`` is a
no-op (SQL Server) started a ``StateConvergenceRunner`` whose start line announced a convergence nothing
performed. An engine shard of a multi-shard config runs the NullCoordinator over the same unified store,
so it never started the runner, nor turned on the version bump a sibling shard's runner reads. And a
SQL Server standby promoted to leader served the state cache it warmed at open. No DB is needed: the
engine tests run over SQLite with a stand-in coordinator, the store test over a bare SQL Server handle.
"""

from __future__ import annotations

import json
import logging
import textwrap
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.sharding import filter_registry_for_shard
from messagefoundry.store.crypto import cell_aad, generate_key, make_cipher
from messagefoundry.store.sealed_cache import new_state_cache


class _ClusterCoordinator(NullCoordinator):
    """Clustered, leadership flippable. ``reclaims_inflight`` True gives the SqlServerCoordinator
    profile: no startup reset, and over a store without ``reclaim_expired_leases`` no leader sweep, so
    promotion takes the active-passive branch of ``_start_graph``."""

    def __init__(self, *, leader: bool = False) -> None:
        super().__init__(node_id="n1")
        self.leader = leader

    def is_leader(self) -> bool:
        return self.leader

    def is_clustered(self) -> bool:
        return True

    def reclaims_inflight(self) -> bool:
        return True


def _graph(cfgdir: Path, tmp_path: Path, *, shards: tuple[str, ...] = ()) -> None:
    """One inbound per shard tag (one untagged inbound when ``shards`` is empty)."""
    cfgdir.mkdir()
    lines = ["from messagefoundry import inbound, outbound, router, handler, Send, File"]
    for i, shard in enumerate(shards or (None,)):
        inbox = tmp_path / f"in-{i}"
        inbox.mkdir()
        tag = f", shard={shard!r}" if shard else ""
        lines.append(
            f"inbound('in{i}', File(directory={str(inbox)!r}, pattern='*.hl7', poll_seconds=0.05),"
            f" router='r'{tag})"
        )
    lines.append(f"outbound('out', File(directory={str(tmp_path / 'out')!r}, filename='x.hl7'))")
    body = textwrap.dedent(
        """
        @router('r')
        def route(msg):
            return ['h']

        @handler('h')
        def handle(msg):
            return Send('out', msg)
        """
    )
    (cfgdir / "c.py").write_text("\n".join(lines) + "\n" + body, encoding="utf-8")


async def _engine(tmp_path: Path, **kw: Any) -> Engine:
    return await Engine.create(
        tmp_path / "e.db",
        poll_interval=0.05,
        egress_settings=EgressSettings(deny_by_default=False),
        **kw,
    )


async def test_cluster_over_a_store_that_cannot_converge_starts_no_runner_and_says_so(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    eng = await _engine(tmp_path, coordinator=_ClusterCoordinator())
    assert eng.store.converges_transform_state is False
    caplog.set_level(logging.INFO)
    await eng.start()
    try:
        assert eng._state_convergence is None
        text = caplog.text
        assert "transform-state convergence enabled" not in text
        assert "transform state does not converge" in text
        assert "promotion re-reads it whole" in text
    finally:
        await eng.stop()


async def test_cluster_over_a_converging_store_starts_the_runner(tmp_path: Path) -> None:
    eng = await _engine(tmp_path, coordinator=_ClusterCoordinator())
    eng.store.converges_transform_state = True  # the Postgres profile
    await eng.start()
    try:
        assert eng._state_convergence is not None
    finally:
        await eng.stop()
    assert eng._state_convergence is None  # stop() tears it down


async def test_an_engine_shard_turns_on_convergence(tmp_path: Path) -> None:
    cfgdir = tmp_path / "cfg"
    _graph(cfgdir, tmp_path, shards=("a", "b"))
    eng = await _engine(tmp_path)  # NullCoordinator: an engine shard is not a cluster node
    eng.store.converges_transform_state = True  # the Postgres profile
    enabled: list[int] = []
    eng.store.enable_state_convergence = lambda: enabled.append(1)  # type: ignore[method-assign]
    eng.add_registry(filter_registry_for_shard(load_config(cfgdir), "a"))
    await eng.start()
    try:
        assert enabled == [1]  # the sibling shard's runner can see this shard's writes
        assert eng._state_convergence is not None  # and this shard reads through the sibling's
    finally:
        await eng.stop()


async def test_an_engine_shard_over_a_store_that_cannot_converge_warns(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfgdir = tmp_path / "cfg"
    _graph(cfgdir, tmp_path, shards=("a", "b"))
    eng = await _engine(tmp_path)
    eng.add_registry(filter_registry_for_shard(load_config(cfgdir), "a"))
    caplog.set_level(logging.WARNING)
    await eng.start()
    try:
        assert eng._state_convergence is None
        assert "transform state does not converge" in caplog.text
        assert "promotion" not in caplog.text  # no promotion on an engine shard
    finally:
        await eng.stop()


async def test_a_single_shard_config_stays_a_lone_process(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfgdir = tmp_path / "cfg"
    _graph(cfgdir, tmp_path, shards=("a",))
    eng = await _engine(tmp_path)
    eng.store.converges_transform_state = True
    eng.add_registry(filter_registry_for_shard(load_config(cfgdir), "a"))
    caplog.set_level(logging.WARNING)
    await eng.start()
    try:
        assert eng._state_convergence is None
        assert "transform state does not converge" not in caplog.text
    finally:
        await eng.stop()


async def test_active_passive_promotion_reloads_the_state_cache(tmp_path: Path) -> None:
    cfgdir = tmp_path / "cfg"
    _graph(cfgdir, tmp_path)
    coord = _ClusterCoordinator(leader=False)
    eng = await _engine(tmp_path, coordinator=coord)
    eng.add_registry(load_config(cfgdir))
    order: list[str] = []
    orig_reset = eng.store.reset_stale_inflight

    async def _reset(*a: Any, **k: Any) -> int:
        order.append("reset")
        return await orig_reset(*a, **k)

    async def _reload() -> None:
        order.append("reload")

    eng.store.reset_stale_inflight = _reset  # type: ignore[method-assign]
    eng.store.reload_state_cache = _reload  # type: ignore[method-assign]
    await eng.start()
    try:
        assert order == []  # a booting standby keeps the cache it warmed at open
        coord.leader = True
        await eng._reconcile_graph()  # promotion
        assert eng._registry_runner is not None and eng._registry_runner.running is True
        assert order == ["reset", "reload"]
    finally:
        await eng.stop()


async def test_sqlserver_reload_state_cache_rereads_the_shared_table() -> None:
    from messagefoundry.store.sqlserver import SqlServerStore

    cipher = make_cipher(generate_key())
    store: Any = object.__new__(SqlServerStore)
    store._cipher = cipher
    store._state_cache = new_state_cache()
    store._state_cache[("ns", "STALE")] = "the prior leader deleted this"
    rows = [
        {
            "namespace": "ns",
            "key": "MRN1",
            "value": str(
                cipher.encrypt(json.dumps("fresh"), aad=cell_aad("state", "value", "ns", "MRN1"))
            ),
        }
    ]

    async def _fetchall(sql: str, *args: Any) -> list[dict[str, Any]]:
        assert "FROM state" in sql
        return rows

    store._fetchall = _fetchall
    assert SqlServerStore.converges_transform_state is False
    await store.reload_state_cache()
    assert store._state_cache[("ns", "MRN1")] == "fresh"
    assert ("ns", "STALE") not in store._state_cache


async def test_sqlite_and_postgres_reload_are_no_ops() -> None:
    from messagefoundry.store.postgres import PostgresStore
    from messagefoundry.store.store import MessageStore

    assert PostgresStore.converges_transform_state is True
    assert MessageStore.converges_transform_state is False
    for cls in (PostgresStore, MessageStore):
        bare: Any = object.__new__(cls)
        assert await bare.reload_state_cache() is None  # touches nothing on the handle


def test_postgres_records_only_a_contiguous_own_bump() -> None:
    from messagefoundry.store.postgres import PostgresStore

    store: Any = object.__new__(PostgresStore)
    store._state_versions = {"corr": 5, "solo": 3}
    # "corr": a sibling shard bumped to 6 before this handle's own write bumped to 7, so recording 7
    # would make the next converge skip the sibling's write. "solo": contiguous, so 4 is reflected.
    # "new": this handle's write created the namespace at version 1.
    store._record_own_state_bumps([("corr", 7), ("solo", 4), ("new", 1)])
    assert store._state_versions == {"corr": 6, "solo": 4, "new": 1}


async def test_postgres_open_reads_versions_before_rows() -> None:
    from messagefoundry.store.postgres import PostgresStore

    store: Any = object.__new__(PostgresStore)
    store._cipher = make_cipher(generate_key())
    order: list[str] = []

    async def _fetchall(sql: str, *args: Any) -> list[dict[str, Any]]:
        is_versions = "state_version" in sql
        order.append("versions" if is_versions else "rows")
        return [{"namespace": "ns", "version": 9}] if is_versions else []

    store._fetchall = _fetchall
    await store._load_state_cache()
    assert order == ["versions", "rows"]  # a write between the reads leaves the version behind
    assert store._state_versions == {"ns": 9}
