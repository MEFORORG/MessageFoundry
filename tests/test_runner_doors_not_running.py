# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A runner whose graph is down refuses the run-state controls (BACKLOG #5702).

The ADR 0157 demoted follower stops its runner and keeps its API serving, so a control can still
reach the runner. Before the fix the start doors bound a listener or spawned a delivery worker on
it, outside the engine lifecycle, and ``stop_outbound`` recorded a pause the next start inherited.

A node that lost its lease before ``_stop_graph`` ran still has a running graph, so its start and
restart doors also ask the coordinator for leadership (BACKLOG #5906, #8214 item 16).
"""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import _alert_control_action, _outbound_down_detail
from messagefoundry.config.settings import EgressSettings
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    RunnerLeaseLostError,
    RunnerNotRunningError,
    TeardownReason,
)
from messagefoundry.store import MessageStore
from tests.test_shard_lane_ownership import _unsharded_registry

_IN, _OUT = "file_in", "file_out"  # _unsharded_registry's names
CLAIM_MODES = ["per_lane", "pooled"]


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "doors.db")
    yield s
    await s.close()


async def _demoted_runner(store: MessageStore, tmp_path: Path, claim_mode: str) -> RegistryRunner:
    """A runner that ran its graph and was then demoted, as a follower's is."""
    runner = RegistryRunner(
        _unsharded_registry(tmp_path),
        store,
        claim_mode=claim_mode,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        assert runner.running and _IN in runner._sources  # the control: the graph really ran
    finally:
        await runner.stop(reason=TeardownReason.DEMOTE, budget_seconds=2.0)
    assert not runner.running
    return runner


def _doors(runner: RegistryRunner) -> list[tuple[str, Any]]:
    return [
        ("start_inbound", lambda: runner.start_inbound(_IN, operator=True)),
        ("restart_inbound", lambda: runner.restart_inbound(_IN, operator=True)),
        ("start_outbound", lambda: runner.start_outbound(_OUT)),
        ("stop_outbound", lambda: runner.stop_outbound(_OUT)),
        ("restart_outbound", lambda: runner.restart_outbound(_OUT)),
    ]


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_demoted_runner_refuses_every_run_state_door(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    runner = await _demoted_runner(store, tmp_path, claim_mode)
    try:
        for door, call in _doors(runner):
            with pytest.raises(RunnerNotRunningError) as ei:
                await call()
            assert ei.value.name in (_IN, _OUT), door
        # Nothing was bound, spawned or recorded behind the refusals.
        assert runner._sources == {}
        assert runner._workers == {}
        assert runner._outbound_paused == set()
        # A resend refusal names the downed graph, not the start it refuses.
        assert "graph is not running" in _outbound_down_detail(runner, _OUT)
        # An inbound stop has nothing to undo on a downed graph, so it is not refused.
        await runner.stop_inbound(_IN)
        # The pause the old stop_outbound recorded here outlived the teardown that had already
        # run, so the next promotion's start brought the lane up paused with no operator act.
        await runner.start()
        assert runner.outbound_status(_OUT) == "running"
    finally:
        await runner.stop()


async def test_a_never_started_runner_refuses_an_inbound_start(
    store: MessageStore, tmp_path: Path
) -> None:
    runner = RegistryRunner(
        _unsharded_registry(tmp_path), store, egress=EgressSettings(deny_by_default=False)
    )
    try:
        with pytest.raises(RunnerNotRunningError):
            await runner.start_inbound(_IN, operator=True)
        assert runner._sources == {}
    finally:
        await runner.stop()


async def test_an_alert_control_action_on_a_downed_graph_does_nothing(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """An alert rule's restart on a demoted node is logged at INFO and not raised. The node that
    runs the graph acts on its own alert."""
    runner = await _demoted_runner(store, tmp_path, "pooled")
    engine: Any = SimpleNamespace(registry_runner=runner)
    try:
        caplog.set_level("INFO")
        await _alert_control_action(engine, "restart_inbound", _IN, default_target=False)
        await _alert_control_action(engine, "restart_outbound", _OUT, default_target=False)
        assert runner._sources == {} and runner._outbound_paused == set()
        assert sum("graph is not running" in r.getMessage() for r in caplog.records) == 2
    finally:
        await runner.stop()


async def test_the_control_route_answers_503_on_a_downed_graph(tmp_path: Path) -> None:
    """The API keeps serving on a demoted follower, so its control route meets the refusal. It
    answers 503, as it does with no runner at all; an inbound stop still answers 200."""
    engine = await Engine.create(
        tmp_path / "api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_unsharded_registry(tmp_path))
    await engine.start()
    try:
        rr = engine.registry_runner
        assert rr is not None
        await rr.stop(reason=TeardownReason.DEMOTE, budget_seconds=2.0)
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            for name, action in (
                (_IN, "start"),
                (_IN, "restart"),
                (_OUT, "start"),
                (_OUT, "stop"),
                (_OUT, "restart"),
            ):
                r = await c.post(f"/connections/{name}/{action}")
                assert r.status_code == 503, (name, action, r.text)
                assert "graph is not running" in r.text
            assert (await c.post(f"/connections/{_IN}/stop")).status_code == 200
        assert rr._sources == {} and rr._workers == {} and rr._outbound_paused == set()
        # Each refusal is audited as a refused control, which the accepted inbound stop is not.
        details = [
            json.loads(row["detail"] or "{}")
            for row in await engine.store.list_audit(action="connection_control")
        ]
        refused = sorted((d["connection"], d["action"]) for d in details if d.get("refused"))
        assert refused == sorted(
            [(_IN, "start"), (_IN, "restart"), (_OUT, "start"), (_OUT, "stop"), (_OUT, "restart")]
        )
    finally:
        await engine.stop()


class _LeaseCoordinator(NullCoordinator):
    """A cluster node whose lease the test takes away while its graph still runs."""

    def __init__(self) -> None:
        super().__init__("node-under-test")
        self.leader = True

    def is_leader(self) -> bool:
        return self.leader


async def _lease_lost_runner(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> tuple[RegistryRunner, _LeaseCoordinator]:
    """A runner whose node lost its lease after its graph came up and before ``_stop_graph`` ran
    (#8214 item 16): ``_running`` is still True."""
    coordinator = _LeaseCoordinator()
    runner = RegistryRunner(
        _unsharded_registry(tmp_path),
        store,
        claim_mode=claim_mode,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        coordinator=coordinator,
    )
    await runner.start()
    assert runner.running and _IN in runner._sources  # the control: the graph really runs
    coordinator.leader = False
    assert runner.running  # the window: the lease is gone and the graph is not yet stopped
    return runner, coordinator


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_node_that_lost_its_lease_refuses_the_start_and_restart_doors(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    """BACKLOG #5906, #8214 item 16. The refusal is a RunnerNotRunningError, so the API's 503
    mapping takes it, and it does not claim the graph is down: here it still runs."""
    runner, _ = await _lease_lost_runner(store, tmp_path, claim_mode)
    try:
        # The stops take work down, which a node losing its lease should do, so they still pass.
        await runner.stop_inbound(_IN)
        await runner.stop_outbound(_OUT)
        assert _IN not in runner._sources and _OUT in runner._outbound_paused
        for door, call in _doors(runner):
            if door == "stop_outbound":
                continue
            with pytest.raises(RunnerLeaseLostError) as ei:
                await call()
            assert isinstance(ei.value, RunnerNotRunningError), door
            assert ei.value.name in (_IN, _OUT), door
            assert "lease" in str(ei.value) and "graph is not running" not in str(ei.value)
        # Nothing was bound or resumed behind the refusals.
        assert _IN not in runner._sources
        assert _OUT in runner._outbound_paused
        assert ("inbound", _IN) not in runner._failed  # a refusal is not a failed start
    finally:
        await runner.stop()


async def test_the_scheduler_starts_nothing_on_a_node_that_lost_its_lease(
    store: MessageStore, tmp_path: Path
) -> None:
    """A window open is the engine, not an operator, and the lease-lost door would refuse it; the
    tick must not record that refusal as a failed start that pages."""
    runner, _ = await _lease_lost_runner(store, tmp_path, "pooled")
    always: Any = SimpleNamespace(is_active=lambda _now: True)
    try:
        await runner.stop_inbound(_IN)
        await runner.stop_outbound(_OUT)
        await runner._reconcile_schedule(_IN, "inbound", always)
        await runner._reconcile_schedule(_OUT, "outbound", always)
        assert _IN not in runner._sources and _OUT in runner._outbound_paused
        assert ("inbound", _IN) not in runner._failed
    finally:
        await runner.stop()


async def test_a_leader_takes_the_start_doors_as_before(
    store: MessageStore, tmp_path: Path
) -> None:
    """The negative control: with the lease held, the same doors act."""
    runner, coordinator = await _lease_lost_runner(store, tmp_path, "pooled")
    coordinator.leader = True
    try:
        await runner.stop_inbound(_IN)
        await runner.stop_outbound(_OUT)
        await runner.start_inbound(_IN, operator=True)
        await runner.start_outbound(_OUT)
        assert _IN in runner._sources and _OUT not in runner._outbound_paused
    finally:
        await runner.stop()


async def test_an_outbound_stop_still_pauses_a_lane_a_failed_teardown_left(
    store: MessageStore, tmp_path: Path
) -> None:
    """A teardown that raised or was cancelled clears ``_running`` and can leave lanes delivering
    (ADR 0157 D7). An operator's stop must still pause them; the next start tears them down."""
    runner = RegistryRunner(
        _unsharded_registry(tmp_path),
        store,
        claim_mode="pooled",
        egress=EgressSettings(deny_by_default=False),
    )
    await runner.start()
    try:
        runner._running = False  # the residual state a raised teardown leaves behind
        assert runner.has_residual_state  # the premise
        await runner.stop_outbound(_OUT)
        assert _OUT in runner._outbound_paused
        with pytest.raises(RunnerNotRunningError):
            await runner.start_outbound(_OUT)  # a start is still refused there
    finally:
        await runner.stop()
