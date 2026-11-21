# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A runner whose graph is down refuses the run-state controls (BACKLOG #5702).

The ADR 0157 demoted follower stops its runner and keeps its API serving, so a control can still
reach the runner. Before the fix the start doors bound a listener or spawned a delivery worker on
it, outside the engine lifecycle, and ``stop_outbound`` recorded a pause the next start inherited.

A node that lost its lease before ``_stop_graph`` ran still has a running graph, so its start and
restart doors also ask the coordinator for leadership (BACKLOG #5906, #8214 item 16). So do a
reload and the single-row send right before it sends.
"""

from __future__ import annotations

import asyncio
import json
import logging
from collections.abc import Mapping
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import httpx
import pytest

from messagefoundry.api import create_app
from messagefoundry.api.app import (
    _alert_control_action,
    _audit_refused_reload,
    _build_approval_gate,
    _inbound_down_detail,
    _outbound_down_detail,
)
from messagefoundry.api.approvals import ApprovalError, ApprovalGate
from messagefoundry.api.outlive import OutlivingOperations
from messagefoundry.auth.permissions import Permission
from messagefoundry.config.models import ConnectorType, RetryPolicy
from messagefoundry.config.settings import ApprovalsSettings, EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline import Engine
from messagefoundry.pipeline.cluster import NullCoordinator
from messagefoundry.pipeline.config_convergence import ConfigConvergenceRunner
from messagefoundry.pipeline.wiring_runner import (
    RegistryRunner,
    RunnerLeaseLostError,
    RunnerNotRunningError,
    TeardownReason,
    _ItemOutcome,
)
from messagefoundry.store import MessageStore
from messagefoundry.transports.base import NegativeAckError
from tests._pending_approval_store_contract import _REQUESTER_ID, _resolve, _StandingStore
from tests.test_reload_retired_connector_send import _Recorder as _SendRecorder
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
        inbound = _inbound_down_detail(runner, _IN)
        assert "graph is not running" in inbound and "resend through" not in inbound
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

    def is_clustered(self) -> bool:
        return True  # as a real cluster coordinator is, so the clustered branches run


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
    try:
        assert runner.running and _IN in runner._sources  # the control: the graph really runs
        coordinator.leader = False
        assert runner.running  # the window: the lease is gone and the graph is not yet stopped
    except BaseException:
        await runner.stop()
        raise
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


async def test_a_lease_lost_while_a_window_open_waits_on_the_lock_is_not_a_failed_start(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The scheduler's own lease read is a fast path taken before the reload lock. A lease lost
    while the tick waits on that lock reaches the door's refusal, which is still not recorded as a
    failed start and does not escape the tick."""
    runner, coordinator = await _lease_lost_runner(store, tmp_path, "pooled")
    always: Any = SimpleNamespace(is_active=lambda _now: True)
    try:
        await runner.stop_inbound(_IN)
        await runner.stop_outbound(_OUT)
        coordinator.leader = True  # the lease is held when each tick reads it
        async with runner._reload_lock:
            ticks = [
                asyncio.ensure_future(runner._reconcile_schedule(_IN, "inbound", always)),
                asyncio.ensure_future(runner._reconcile_schedule(_OUT, "outbound", always)),
            ]
            for _ in range(5):
                await asyncio.sleep(0)  # both ticks pass their lease read and wait on the lock
            assert not any(t.done() for t in ticks)
            coordinator.leader = False
        caplog.set_level("INFO")
        await asyncio.gather(*ticks)  # neither raises
        assert _IN not in runner._sources and _OUT in runner._outbound_paused
        assert ("inbound", _IN) not in runner._failed
        # The premise: both ticks got past their own lease read and met the door's refusal, rather
        # than first running after the flip and taking the fast path.
        assert sum("not started" in r.getMessage() for r in caplog.records) == 2
    finally:
        await runner.stop()


async def test_a_lease_lost_restart_is_refused_before_its_stop_half(
    store: MessageStore, tmp_path: Path
) -> None:
    """A live listener and a delivering lane keep their state: the refusal comes before the stop
    half of either restart, so nothing is unbound or turned into an operator pause."""
    runner, _ = await _lease_lost_runner(store, tmp_path, "pooled")
    try:
        assert _IN in runner._sources and _OUT not in runner._outbound_paused  # the premise
        with pytest.raises(RunnerLeaseLostError):
            await runner.restart_inbound(_IN, operator=True)
        with pytest.raises(RunnerLeaseLostError):
            await runner.restart_outbound(_OUT)
        assert _IN in runner._sources and _OUT not in runner._outbound_paused
    finally:
        await runner.stop()


async def test_the_control_route_answers_503_on_a_node_that_lost_its_lease(
    tmp_path: Path,
) -> None:
    """The API's existing RunnerNotRunningError arms take the subclass: a 503 naming the lease,
    and a refused-control audit row, while the stops still answer 200."""
    engine = await Engine.create(
        tmp_path / "api.db",
        poll_interval=0.02,
        egress_settings=EgressSettings(deny_by_default=False),
    )
    engine.add_registry(_unsharded_registry(tmp_path))
    await engine.start()
    try:
        rr = engine.registry_runner
        assert rr is not None and rr.running
        coordinator = _LeaseCoordinator()
        coordinator.leader = False
        rr._coordinator = coordinator  # the lease is gone; _stop_graph has not run yet
        transport = httpx.ASGITransport(app=create_app(engine, allow_no_auth=True))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            assert (await c.post(f"/connections/{_IN}/stop")).status_code == 200
            assert (await c.post(f"/connections/{_OUT}/stop")).status_code == 200
            for name, action in (
                (_IN, "start"),
                (_IN, "restart"),
                (_OUT, "start"),
                (_OUT, "restart"),
            ):
                r = await c.post(f"/connections/{name}/{action}")
                assert r.status_code == 503, (name, action, r.text)
                assert "lease" in r.text and "graph is not running" not in r.text
        assert _IN not in rr._sources and _OUT in rr._outbound_paused
        details = [
            json.loads(row["detail"] or "{}")
            for row in await engine.store.list_audit(action="connection_control")
        ]
        refused = sorted((d["connection"], d["action"]) for d in details if d.get("refused"))
        assert refused == sorted(
            [(_IN, "start"), (_IN, "restart"), (_OUT, "start"), (_OUT, "restart")]
        )
    finally:
        await engine.stop()


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
        # The scheduler's positive control: the same window-open calls the lease-lost test makes
        # do start an engine-stopped inbound here.
        await runner.stop_inbound(_IN)
        always: Any = SimpleNamespace(is_active=lambda _now: True)
        await runner._reconcile_schedule(_IN, "inbound", always)
        assert _IN in runner._sources
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


async def test_a_lease_lost_node_names_the_lease_in_its_alert_log_and_resend_refusal(
    store: MessageStore, tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """BACKLOG #5906: on a node that lost its lease the graph still runs, so the alert action's log
    line and the resend 409 must not say the graph is down, and the 409 must not send the operator
    to a start the lease-lost door refuses."""
    runner, _ = await _lease_lost_runner(store, tmp_path, "pooled")
    engine: Any = SimpleNamespace(registry_runner=runner)
    try:
        await runner.stop_outbound(_OUT)  # an operator-paused lane, so a resend is refused
        await runner.stop_inbound(
            _IN
        )  # an operator-stopped inbound, so an upload resend is refused
        detail = _outbound_down_detail(runner, _OUT)
        assert "lease" in detail and "leader" in detail
        assert "graph is not running" not in detail and "start it" not in detail
        # An uploaded file lives in this node's uploads_dir, so the upload resend names no remedy:
        # the leader would not hold the file.
        detail = _inbound_down_detail(runner, _IN)
        assert "lease" in detail and "refused here" in detail
        assert "leader" not in detail and "start it" not in detail
        caplog.set_level("INFO")
        await _alert_control_action(engine, "restart_inbound", _IN, default_target=False)
        await _alert_control_action(engine, "restart_outbound", _OUT, default_target=False)
        lines = [r.getMessage() for r in caplog.records if "alert control_action" in r.getMessage()]
        assert len(lines) == 2, lines
        assert all("cluster lease" in m and "graph is not running" not in m for m in lines)
        assert _IN not in runner._sources and _OUT in runner._outbound_paused  # nothing acted
    finally:
        await runner.stop()


async def test_a_leader_resend_refusal_still_says_start_it(
    store: MessageStore, tmp_path: Path
) -> None:
    """The negative control: with the lease held, an operator-paused lane's 409 is unchanged."""
    runner, coordinator = await _lease_lost_runner(store, tmp_path, "pooled")
    coordinator.leader = True
    try:
        await runner.stop_outbound(_OUT)
        await runner.stop_inbound(_IN)
        assert "start it before resending" in _outbound_down_detail(runner, _OUT)
        assert "start it before resending" in _inbound_down_detail(runner, _IN)
    finally:
        await runner.stop()


# --- BACKLOG #5906 closing steps 1 and 2: the single-row send and the reload ----------------------


async def _claimed_row(
    store: MessageStore, coordinator: _LeaseCoordinator
) -> tuple[RegistryRunner, _SendRecorder, str, Any]:
    """A bare runner wired to one recording outbound, with one row of it claimed."""
    runner = RegistryRunner(
        Registry(),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        coordinator=coordinator,
    )
    recorder = _SendRecorder()
    runner._destinations[_OUT] = recorder
    runner._retry[_OUT] = RetryPolicy()
    raw = "MSH|^~\\&|A|B|C|D|20260101000001||ADT^A01|MSG1|P|2.5.1\rPID|1||100||DOE^P\r"
    message_id = await store.enqueue_message(
        channel_id="c1", raw=raw, deliveries=[(_OUT, raw)], now=100.0
    )
    item = await store.claim_next_fifo(_OUT)
    assert item is not None
    return runner, recorder, message_id, item


def _demote_during_hydration(runner: RegistryRunner, coordinator: _LeaseCoordinator) -> None:
    """Make the re-attach read, an await after the send path's first lease read and before the
    send, the moment this node loses its lease."""
    hydrate = runner._hydrate_payload

    async def demoting(payload: str, message_id: str) -> str:
        coordinator.leader = False
        return await hydrate(payload, message_id)

    runner._hydrate_payload = demoting  # type: ignore[method-assign]


async def test_a_single_row_is_not_sent_when_the_lease_goes_before_its_send(
    store: MessageStore,
) -> None:
    """Closing step 1. The row is released for the new leader with no attempt spent, and the lane
    stops, as at the path's first lease read."""
    coordinator = _LeaseCoordinator()
    runner, recorder, message_id, item = await _claimed_row(store, coordinator)
    try:
        _demote_during_hydration(runner, coordinator)
        outcome, retry_until = await runner._process_delivery_item(_OUT, item)
        assert recorder.sent == []
        assert (outcome, retry_until) == (_ItemOutcome.STOPPED, None)
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]
    finally:
        await runner.stop()


async def test_a_single_row_is_not_sent_when_a_pause_lands_before_its_send(
    store: MessageStore,
) -> None:
    """The same gate as the batch's (#5706): a pause that lands during the reads is not sent
    through. The leader hands the row back unsent and uncharged."""
    coordinator = _LeaseCoordinator()
    runner, recorder, message_id, item = await _claimed_row(store, coordinator)
    hydrate = runner._hydrate_payload

    async def pausing(payload: str, message_id: str) -> str:
        runner._outbound_paused.add(_OUT)
        return await hydrate(payload, message_id)

    runner._hydrate_payload = pausing  # type: ignore[method-assign]
    try:
        outcome, _ = await runner._process_delivery_item(_OUT, item)
        assert recorder.sent == [] and outcome is _ItemOutcome.PROCESSED
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]
    finally:
        await runner.stop()


async def test_a_single_row_is_sent_while_the_lease_holds(store: MessageStore) -> None:
    """The negative control: the same path, with the lease kept, sends and completes the row."""
    coordinator = _LeaseCoordinator()
    runner, recorder, message_id, item = await _claimed_row(store, coordinator)
    try:
        outcome, _ = await runner._process_delivery_item(_OUT, item)
        assert outcome is _ItemOutcome.PROCESSED and len(recorder.sent) == 1
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "done"
    finally:
        await runner.stop()


def _with_second_inbound(tmp_path: Path) -> Registry:
    reg = _unsharded_registry(tmp_path)
    inbox = tmp_path / "in2"
    inbox.mkdir(exist_ok=True)
    reg.add_inbound(
        InboundConnection(
            "file_in2",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
        )
    )
    return reg


@pytest.mark.parametrize("claim_mode", CLAIM_MODES)
async def test_a_node_that_lost_its_lease_refuses_a_reload(
    store: MessageStore, tmp_path: Path, claim_mode: str
) -> None:
    """Closing step 2. The reload would unbind and rebind every listener and bind the one it adds;
    it is refused before step 1, so the running listener is the same object and nothing binds."""
    runner, _ = await _lease_lost_runner(store, tmp_path, claim_mode)
    try:
        before = runner._sources[_IN]
        old_registry = runner.registry
        with pytest.raises(RunnerLeaseLostError) as ei:
            await runner.reload(_with_second_inbound(tmp_path))
        assert "reload" in str(ei.value) and "graph is not running" not in str(ei.value)
        assert runner._sources == {_IN: before}
        assert runner.registry is old_registry
    finally:
        await runner.stop()


async def test_a_lease_lost_reload_is_refused_before_its_build_check(
    store: MessageStore, tmp_path: Path
) -> None:
    """The entry read: refused before the build check, so the lock the demotion teardown waits on
    is not held through it."""
    runner, _ = await _lease_lost_runner(store, tmp_path, "pooled")

    async def no_build_check(*args: Any, **kwargs: Any) -> None:
        raise AssertionError("the build check ran on a lease-lost node")

    runner.build_check_off_loop = no_build_check  # type: ignore[method-assign]
    try:
        with pytest.raises(RunnerLeaseLostError):
            await runner.reload(_with_second_inbound(tmp_path))
    finally:
        await runner.stop()


async def test_a_leader_reload_binds_the_inbound_it_adds(
    store: MessageStore, tmp_path: Path
) -> None:
    """The negative control: with the lease held, the same reload applies."""
    runner, coordinator = await _lease_lost_runner(store, tmp_path, "pooled")
    coordinator.leader = True
    try:
        await runner.reload(_with_second_inbound(tmp_path))
        assert set(runner._sources) == {_IN, "file_in2"}
    finally:
        await runner.stop()


async def test_a_lease_lost_during_the_reload_prepare_is_refused_before_the_quiesce(
    store: MessageStore, tmp_path: Path
) -> None:
    """Closing step 2: the entry read passes, and the lease goes during the connector builds, the
    last await before step 1. The second read refuses there, so no listener is unbound or bound."""
    runner, coordinator = await _lease_lost_runner(store, tmp_path, "pooled")
    coordinator.leader = True
    prepare = runner._prepare_outbound_reconcile

    async def demoting(*args: Any, **kwargs: Any) -> None:
        coordinator.leader = False
        await prepare(*args, **kwargs)

    runner._prepare_outbound_reconcile = demoting  # type: ignore[method-assign]
    try:
        before = runner._sources[_IN]
        with pytest.raises(RunnerLeaseLostError):
            await runner.reload(_with_second_inbound(tmp_path))
        assert runner._sources == {_IN: before}
    finally:
        await runner.stop()


async def test_a_reload_refused_for_the_lease_audits_lease_lost_and_answers_503(
    store: MessageStore,
) -> None:
    """Not a bad graph and not a fault inside the reload: its own reason, and the 503 the start
    doors answer on such a node."""
    engine: Any = SimpleNamespace(store=store)
    status, answer = await _audit_refused_reload(
        engine, RunnerLeaseLostError.for_reload(), actor="t", requested=None, dry_run=False
    )
    assert status == 503 and "lease" in answer
    (row,) = await store.list_audit(action="config_reload_failed")
    assert json.loads(row["detail"])["reason"] == "lease_lost"


# --- BACKLOG #5906 repair (Lander hold on engine PR 3136) -----------------------------------------


class _FramingRecorder(_SendRecorder):
    """A recording outbound that frames, so the shadow path runs its frame check's hydrate."""

    def __init__(self) -> None:
        super().__init__()
        self.checked: list[str] = []

    def check_frame(self, payload: str, *, rewrite: bool = True) -> None:
        self.checked.append(payload)


async def test_a_shadow_row_is_not_marked_done_when_the_lease_goes_during_its_frame_check(
    store: MessageStore,
) -> None:
    """The shadow branch: its frame check's hydrate is an await, so the gate asks again after it,
    and the row is released for the new leader rather than marked done."""
    coordinator = _LeaseCoordinator()
    runner, _, message_id, item = await _claimed_row(store, coordinator)
    framing = _FramingRecorder()
    runner._destinations[_OUT] = framing
    runner._simulate[_OUT] = True
    _demote_during_hydration(runner, coordinator)
    try:
        outcome, retry_until = await runner._process_delivery_item(_OUT, item)
        assert framing.checked == [] and framing.sent == []  # gated before the frame check
        assert (outcome, retry_until) == (_ItemOutcome.STOPPED, None)
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]
    finally:
        await runner.stop()


async def test_a_shadow_row_completes_while_the_lease_holds(store: MessageStore) -> None:
    """The negative control: the same shadow path, the lease kept, marks the row done."""
    coordinator = _LeaseCoordinator()
    runner, _, message_id, item = await _claimed_row(store, coordinator)
    framing = _FramingRecorder()
    runner._destinations[_OUT] = framing
    runner._simulate[_OUT] = True
    try:
        outcome, _ = await runner._process_delivery_item(_OUT, item)
        assert outcome is _ItemOutcome.PROCESSED and len(framing.checked) == 1
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "done"
    finally:
        await runner.stop()


class _RefusingFrame(_FramingRecorder):
    """A framing outbound whose frame check refuses every payload, permanently."""

    def check_frame(self, payload: str, *, rewrite: bool = True) -> None:
        super().check_frame(payload, rewrite=rewrite)
        raise NegativeAckError("re-encode refused", code="reencode", permanent=True)


async def test_a_shadow_frame_refusal_does_not_dead_letter_on_a_node_that_lost_its_lease(
    store: MessageStore,
) -> None:
    """The gate comes between the hydrate and the frame check, so a node that lost its lease
    during the hydrate does not dead-letter the row a successor may own; it releases it."""
    coordinator = _LeaseCoordinator()
    runner, _, message_id, item = await _claimed_row(store, coordinator)
    refusing = _RefusingFrame()
    runner._destinations[_OUT] = refusing
    runner._simulate[_OUT] = True
    _demote_during_hydration(runner, coordinator)
    try:
        outcome, _ = await runner._process_delivery_item(_OUT, item)
        assert refusing.checked == [] and outcome is _ItemOutcome.STOPPED
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]
    finally:
        await runner.stop()


async def test_a_single_row_is_not_sent_when_the_log_write_halt_lands_before_its_send(
    store: MessageStore,
) -> None:
    """The #122 halt is part of the same gate: a halt that lands during the reads is not sent
    through, and the leader hands the row back unsent and uncharged."""
    coordinator = _LeaseCoordinator()
    runner, recorder, message_id, item = await _claimed_row(store, coordinator)
    hydrate = runner._hydrate_payload

    async def halting(payload: str, message_id: str) -> str:
        runner._log_write_stopped = True
        return await hydrate(payload, message_id)

    runner._hydrate_payload = halting  # type: ignore[method-assign]
    try:
        outcome, _ = await runner._process_delivery_item(_OUT, item)
        assert recorder.sent == [] and outcome is _ItemOutcome.PROCESSED
        (row,) = await store.outbox_for(message_id)
        assert row["status"] == "pending" and row["attempts"] == 0 and not row["last_error"]
    finally:
        runner._log_write_stopped = False
        await runner.stop()


def _release_gate(engine: Any) -> ApprovalGate:
    settings = ApprovalsSettings(enabled=True, operations=["config_reload"], min_dwell_seconds=0.0)
    return _build_approval_gate(engine, settings, outliving=OutlivingOperations())


async def test_a_release_on_a_lease_lost_node_is_refused_before_the_claim(
    store: MessageStore,
) -> None:
    """Regression 1 of the hold: the reload's own refusal comes after the gate's claim, so the
    approval was compensated to 'failed' and could not be released on the leader. The registered
    hook refuses first with 503, so the gate never claims the request."""
    engine: Any = SimpleNamespace(store=store, registry_runner=SimpleNamespace(lease_lost=True))
    hook = _release_gate(engine)._ops["config_reload"].before_claim
    assert hook is not None
    with pytest.raises(ApprovalError) as ei:
        await hook({"requester": "maker", "config_dir": None})
    assert ei.value.status == 503 and "leader" in ei.value.detail and "claim" in ei.value.detail


@pytest.mark.parametrize("runner", [None, SimpleNamespace(lease_lost=False)])
async def test_a_release_on_a_leading_or_graphless_node_passes_the_hook(
    store: MessageStore, runner: Any
) -> None:
    """The negative control: nothing is refused or written where the lease is not lost."""
    engine: Any = SimpleNamespace(store=store, registry_runner=runner)
    hook = _release_gate(engine)._ops["config_reload"].before_claim
    assert hook is not None
    await hook({"requester": "maker", "config_dir": None})


async def test_the_gate_leaves_a_request_its_before_claim_refuses_pending(
    store: MessageStore,
) -> None:
    """The gate's half: a raise from ``before_claim`` comes before the claim, so the executor does
    not run, the row is still pending, and an ``approval.node_refused`` row names the approver;
    once the hook passes, the same request releases."""
    settings = ApprovalsSettings(
        enabled=True, operations=["dead_letter_replay"], min_dwell_seconds=0.0
    )
    gate = ApprovalGate(_StandingStore(store), settings, resolve_identity=_resolve)
    runs: list[str] = []
    refuse = [True]

    async def execute(_p: Mapping[str, Any]) -> dict[str, Any]:
        runs.append("ran")
        return {"requeued": 0}

    async def before_claim(_p: Mapping[str, Any]) -> None:
        if refuse[0]:
            raise ApprovalError(409, "not on this node")

    gate.register(
        "dead_letter_replay",
        "op",
        execute,
        permission=Permission.MESSAGES_REPLAY,
        before_claim=before_claim,
    )
    await store.create_pending_approval(
        approval_id="a1",
        operation="dead_letter_replay",
        params=json.dumps({"requester": "maker"}),
        requester="maker",
        requester_user_id=_REQUESTER_ID,
        requested_at=1.0,
        expires_at=None,
    )
    with pytest.raises(ApprovalError) as ei:
        await gate.approve("a1", approver="checker", approver_user_id="checker-id")
    assert ei.value.status == 409 and runs == []
    row = await store.get_pending_approval("a1")
    assert row is not None and str(row["status"]) == "pending"
    assert await store.list_audit(action="approval.release_attempted") == []
    (refused,) = await store.list_audit(action="approval.node_refused")
    assert refused["actor"] == "checker"
    detail = json.loads(refused["detail"])
    assert detail["approval_id"] == "a1" and detail["status"] == 409
    assert detail["refusal"] == "not on this node" and detail["requester"] == "maker"
    refuse[0] = False
    await gate.approve("a1", approver="checker", approver_user_id="checker-id")
    assert runs == ["ran"]


class _VersionCoordinator(NullCoordinator):
    def __init__(self) -> None:
        super().__init__("node-under-test")

    def config_version_cached(self) -> int:
        return 2


async def test_a_convergence_pass_refused_for_the_lease_logs_once_without_a_traceback(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Regression 3 of the hold: every pass on a lease-lost node logged an ERROR traceback for a
    designed refusal. Through a run of refused passes only the first logs at INFO (its converging
    line and one refusal line, which does not repeat the manual-reload advice), and the version
    is not marked applied, so the pass is retried. A real fault still logs its traceback."""
    applied: list[int] = []
    error: list[Exception] = [RunnerLeaseLostError.for_reload()]

    async def reload(_version: int) -> None:
        raise error[0]

    runner = ConfigConvergenceRunner(
        _VersionCoordinator(),
        applied_version=lambda: 1,
        set_applied_version=applied.append,
        reload=reload,
        interval_seconds=1.0,
        refusals=(RunnerLeaseLostError,),
    )
    name = "messagefoundry.pipeline.config_convergence"
    with caplog.at_level(logging.DEBUG, logger=name):
        for _ in range(3):
            await runner._pass_once()
    info = [r for r in caplog.records if r.name == name and r.levelno >= logging.INFO]
    assert [("converging" in r.getMessage(), r.levelno) for r in info] == [
        (True, logging.INFO),
        (False, logging.INFO),
    ]
    assert info[1].exc_info is None and "refused" in info[1].getMessage()
    assert "leader" not in info[1].getMessage()
    assert applied == []
    caplog.clear()
    error[0] = ValueError("a bad local config")
    with caplog.at_level(logging.DEBUG, logger=name):
        await runner._pass_once()
    (fault,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert fault.exc_info is not None
    # The fault ended the run: its version is named at INFO, though its converging line was quiet.
    assert any(
        r.levelno == logging.INFO and "failed to converge" in r.getMessage() for r in caplog.records
    )


async def test_the_pass_that_ends_a_run_of_refusals_logs_its_convergence_at_info(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """After refused passes the converging line is quiet, so a pass that does converge says so at
    INFO, and the next refusal run logs at INFO again."""
    applied: list[int] = []
    refuse = [True]

    async def reload(_version: int) -> None:
        if refuse[0]:
            raise RunnerLeaseLostError.for_reload()

    runner = ConfigConvergenceRunner(
        _VersionCoordinator(),
        applied_version=lambda: 1,
        set_applied_version=applied.append,
        reload=reload,
        interval_seconds=1.0,
        refusals=(RunnerLeaseLostError,),
    )
    name = "messagefoundry.pipeline.config_convergence"
    with caplog.at_level(logging.DEBUG, logger=name):
        await runner._pass_once()
        await runner._pass_once()
        caplog.clear()
        refuse[0] = False
        await runner._pass_once()
    assert applied == [2]
    info = [r.getMessage() for r in caplog.records if r.levelno == logging.INFO]
    assert info == ["cluster: converged on shared config version 2 after refused passes"]


async def test_a_convergence_reload_on_a_lease_lost_node_loads_no_config(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The pass is refused before ``reload_detail`` runs the config modules and the preflights,
    since it is retried every interval; the failure hook still sees it, so its row is written."""
    engine = await Engine.create(
        tmp_path / "converge.db", egress_settings=EgressSettings(deny_by_default=False)
    )
    try:
        seen: list[type[BaseException]] = []

        async def no_load(**_kwargs: Any) -> None:
            raise AssertionError("reload_detail ran on a lease-lost node")

        async def failed(exc: Exception, _version: int, _reported: set[str]) -> None:
            seen.append(type(exc))

        monkeypatch.setattr(engine, "reload_detail", no_load)
        monkeypatch.setattr(engine, "_registry_runner", SimpleNamespace(lease_lost=True))
        engine.convergence_reload_failed = failed
        with pytest.raises(RunnerLeaseLostError):
            await engine._converge_reload(2)
        assert seen == [RunnerLeaseLostError]
    finally:
        monkeypatch.undo()
        await engine.stop()
