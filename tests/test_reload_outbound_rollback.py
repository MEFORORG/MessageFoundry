# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reload that fails or is cancelled before its outbound reconcile changes a lane leaves every
outbound lane as it was, a retired connector closes only once the swap commits, and one reload
judges a schedule window at one time (BACKLOG #5755).

``RegistryRunner.reload``'s rollback restored the registry, the env values, the lookups and
intake, but never the outbound state step 3 (``_reconcile_outbounds``) had already written: a
connector built from the refused graph stayed mapped, and its retry, simulate and pause state with
it, until a restart. Three of step 3's branches also closed a retired connector with a bare
``aclose()``, so a close that raised rolled the reload back after the mapping changed. Step 3 now
builds every connector before it changes any lane, then makes every lane change with no await.
"""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import AsyncIterator, Mapping
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import build_destination
from messagefoundry.transports.base import DestinationConnector
from messagefoundry.transports.file import FileDestination

_OB = "file_out"
_OB2 = "file_out_2"
_CLAIM_MODES = ["pooled", "per_lane"]
_POLICY_MAPS = (
    "_retry",
    "_ordering",
    "_internal_error",
    "_buildup",
    "_stall",
    "_send_pace",
    "_simulate",
)


def _outbound(name: str, directory: Path, **kwargs: Any) -> OutboundConnection:
    return OutboundConnection(
        name,
        ConnectionSpec(
            ConnectorType.FILE, {"directory": str(directory), "filename": "{MSH-10}.hl7"}
        ),
        **kwargs,
    )


def _registry(
    tmp_path: Path,
    outdir: str,
    *,
    deployed: bool = True,
    simulate: bool = False,
    second: str | None = None,
    third: str | None = None,
) -> Registry:
    inbox = tmp_path / "in"
    inbox.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_outbound(_outbound(_OB, tmp_path / outdir, deployed=deployed, simulate=simulate))
    if second is not None:
        reg.add_outbound(_outbound(_OB2, tmp_path / second))
    if third is not None:
        reg.add_outbound(_outbound("file_out_3", tmp_path / third))
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 0.02},
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send(_OB, m))
    return reg


class _CloseFails(DestinationConnector):
    """A connector whose close raises, as a transport whose socket teardown fails does."""

    async def send(self, payload: str, *, metadata: Mapping[str, str] | None = None) -> None:
        return None

    async def aclose(self) -> None:
        raise OSError("teardown failed")


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "reload-outbound-rollback.db")
    yield s
    await s.close()


async def _started(
    store: MessageStore, registry: Registry, *, claim_mode: str = "pooled", **kwargs: Any
) -> RegistryRunner:
    rr = RegistryRunner(
        registry,
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        claim_mode=claim_mode,
        **kwargs,
    )
    await rr.start()
    return rr


@pytest.fixture(params=_CLAIM_MODES)
async def runner(
    request: pytest.FixtureRequest, store: MessageStore, tmp_path: Path
) -> AsyncIterator[RegistryRunner]:
    rr = await _started(store, _registry(tmp_path, "out", second="out2"), claim_mode=request.param)
    assert _OB in rr._destinations and _OB2 in rr._destinations
    yield rr
    await rr.stop()


def _lanes(rr: RegistryRunner) -> dict[str, Any]:
    """Every piece of outbound lane state a reload's step 3 writes, by identity where it holds an
    object, so a comparison says the lanes are exactly as they were."""
    return {
        "destinations": {n: id(c) for n, c in rr._destinations.items()},
        "workers": {n: id(t) for n, t in rr._workers.items()},
        "paused": set(rr._outbound_paused),
        "gate_parked": set(rr._gate_parked),
        "schedule_parked": set(rr._schedule_parked),
        "policies": {attr: dict(getattr(rr, attr)) for attr in _POLICY_MAPS},
        "failed": dict(rr._failed),
        "filtered": dict(rr._filtered),
        "dr_unbuilt": dict(rr._dr_unbuilt),
        "anchor_refused": dict(rr._anchor_refused),
    }


def _directory(runner: RegistryRunner, name: str = _OB) -> Path:
    return Path(runner._destinations[name].directory)  # type: ignore[attr-defined]


def _fault_nth_build(
    monkeypatch: pytest.MonkeyPatch, n: int, *, hang: asyncio.Event | None = None
) -> list[Any]:
    """Make the ``n``-th outbound connector build a reload's step 3 runs fail, or hang once
    ``hang`` is set. Returns the connectors the earlier builds made."""
    real = wiring_runner._build_off_loop
    made: list[Any] = []
    calls = {"n": 0}

    async def nth_fails(*args: Any, **kwargs: Any) -> Any:
        build = args[1]
        # Only outbound builds count: the build check runs through the same helper with another
        # callable.
        if getattr(build, "func", None) is not build_destination:
            return await real(*args, **kwargs)
        calls["n"] += 1
        if calls["n"] == n:
            if hang is not None:
                hang.set()
                await asyncio.Event().wait()
            raise RuntimeError("a later lane's build failed")
        built = await real(*args, **kwargs)
        made.append(built)
        return built

    monkeypatch.setattr(wiring_runner, "_build_off_loop", nth_fails)
    return made


def _record_closes(runner: RegistryRunner, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    closed: list[Any] = []
    real_close = runner._close_replaced

    async def record(
        name: str, replaced: Any, failures: list[tuple[str, str]], **kwargs: Any
    ) -> None:
        closed.append(replaced)
        await real_close(name, replaced, failures, **kwargs)

    monkeypatch.setattr(runner, "_close_replaced", record)
    return closed


async def _settle(runner: RegistryRunner) -> None:
    """Let the detached closes a reload or its rollback scheduled run."""
    for _ in range(3):
        await asyncio.sleep(0)
    if runner._lookup_close_tasks:
        await asyncio.wait(runner._lookup_close_tasks, timeout=10)


async def test_a_failed_reload_leaves_every_outbound_lane_as_it_was(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Both lanes change, and the second one's build fails. Before the fix the first lane kept the
    refused graph's connector and its simulate flag."""
    old = runner.registry
    before = _lanes(runner)
    made = _fault_nth_build(monkeypatch, 2)
    closed = _record_closes(runner, monkeypatch)
    with pytest.raises(RuntimeError, match="later lane"):
        await runner.reload(_registry(tmp_path, "out_v2", simulate=True, second="out2_v2"))
    await _settle(runner)

    assert runner.registry is old
    assert _lanes(runner) == before
    assert _directory(runner) == tmp_path / "out"
    # The connector the refused graph built for the first lane is closed, not left open.
    assert made and all(c in closed for c in made)
    assert runner.inbound_running("file_in")
    assert runner.outbound_running(_OB)


@pytest.mark.parametrize("nth", [1, 2])
async def test_a_reload_cancelled_at_any_build_leaves_every_outbound_lane_as_it_was(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, nth: int
) -> None:
    """A cancellation at either await of step 3's builds leaves every lane byte for byte as it
    was: connector identity, workers, pause and park sets, policy maps and records."""
    old = runner.registry
    before = _lanes(runner)
    entered = asyncio.Event()
    made = _fault_nth_build(monkeypatch, nth, hang=entered)
    closed = _record_closes(runner, monkeypatch)
    task = asyncio.create_task(
        runner.reload(_registry(tmp_path, "out_v2", simulate=True, second="out2_v2"))
    )
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _settle(runner)

    assert runner.registry is old
    assert _lanes(runner) == before
    assert all(c in closed for c in made)
    assert runner.inbound_running("file_in")


async def _left_the_dr_park_unbuilt(rr: RegistryRunner) -> None:
    """Put ``_OB`` in the state a lane whose build failed as it left the DR park is held in: no
    connector, parked by the engine, marked unbuilt (vault BACKLOG #3263). Its next reload builds
    it as a start does, with its CA check, build and ``validate_startup``."""
    connector = rr._destinations.pop(_OB)
    await connector.aclose()
    rr._park_outbound_lane(_OB)
    rr._dr_unbuilt[_OB] = True


@pytest.mark.parametrize("await_point", ["anchor", "build", "validate"])
@pytest.mark.parametrize("claim_mode", _CLAIM_MODES)
async def test_a_reload_cancelled_building_a_lane_that_leaves_the_dr_park_changes_nothing(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    await_point: str,
    claim_mode: str,
) -> None:
    """Each await of the build a lane leaving the DR park takes. Before the fix the reconcile
    dropped the lane's unbuilt mark and its records before the first one."""
    entered = asyncio.Event()
    armed: list[bool] = []  # not at the start, which checks the lane too

    async def anchor(direction: str, name: str, settings: object) -> None:
        if armed and await_point == "anchor" and name == _OB:
            entered.set()
            await asyncio.Event().wait()

    rr = await _started(
        store,
        _registry(tmp_path, "out", second="out2"),
        claim_mode=claim_mode,
        lane_anchor_check=anchor,
    )
    try:
        await _left_the_dr_park_unbuilt(rr)
        rr._record_failed(_OB, RuntimeError("the build failed at the takeover"), kind="outbound")
        before = _lanes(rr)
        armed.append(True)
        if await_point == "build":
            _fault_nth_build(monkeypatch, 1, hang=entered)
        if await_point == "validate":
            real_validate = FileDestination.validate_startup

            async def hang_validate(self: FileDestination) -> None:
                if Path(self.directory) == tmp_path / "out":
                    entered.set()
                    await asyncio.Event().wait()
                await real_validate(self)

            monkeypatch.setattr(FileDestination, "validate_startup", hang_validate)
        task = asyncio.create_task(
            rr.reload(_registry(tmp_path, "out", simulate=True, second="out2"))
        )
        await asyncio.wait_for(entered.wait(), 10)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
        await _settle(rr)

        assert _lanes(rr) == before
        assert rr.inbound_running("file_in")
    finally:
        await rr.stop()


async def test_a_retired_connector_that_fails_to_close_is_reported_not_rolled_back(
    runner: RegistryRunner, tmp_path: Path
) -> None:
    await runner._destinations[_OB].aclose()
    runner._destinations[_OB] = _CloseFails()
    new = _registry(tmp_path, "out", deployed=False, second="out2")

    # Before the fix the not-deployed branch's bare aclose() raised and rolled the reload back.
    failures = await runner.reload(new)

    assert runner.registry is new
    assert [name for name, _ in failures] == [_OB]
    assert _OB not in runner._destinations


async def test_a_failed_reload_leaves_a_dropped_lane_draining_on_its_own_connector(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lane an earlier reload dropped keeps draining on its connector. A refused reload that
    re-adds it changed, and fails at a later lane's build, leaves that connector in place and
    closes the one it built for the lane."""
    await runner.reload(_registry(tmp_path, "out"))  # drops file_out_2, which keeps draining
    assert _OB2 not in runner.registry.outbound
    draining = runner._destinations[_OB2]
    closed = _record_closes(runner, monkeypatch)
    made = _fault_nth_build(monkeypatch, 2)
    with pytest.raises(RuntimeError, match="later lane"):
        await runner.reload(_registry(tmp_path, "out", second="out2_v2", third="out3"))
    await _settle(runner)

    assert runner._destinations[_OB2] is draining
    assert draining not in closed
    assert made and all(c in closed for c in made)


async def test_a_retired_connector_closes_only_once_the_swap_commits_even_if_the_tail_raises(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The scheduler reconcile, the commit tail's one await before the closes, raises. The
    connector step 3 swapped out is still closed, and only after the swap committed. Before the
    fix it was closed inside step 3, before the commit, so a rollback had nothing to put back."""
    before = runner._destinations[_OB]
    closed = _record_closes(runner, monkeypatch)
    at_commit: list[bool] = []

    async def schedulers_fail() -> None:
        at_commit.append(before in closed)
        raise RuntimeError("scheduler reconcile failed")

    monkeypatch.setattr(runner, "_reconcile_schedulers", schedulers_fail)
    with pytest.raises(RuntimeError, match="scheduler reconcile"):
        await runner.reload(_registry(tmp_path, "out_v2", second="out2"))
    await _settle(runner)

    assert runner._destinations[_OB] is not before
    assert at_commit == [False]  # not closed before the swap committed
    assert before in closed


async def test_a_reload_cancelled_in_its_commit_tail_still_closes_every_retired_connector(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A cancellation in the commit tail hands the retired connectors to a detached close. Before
    the fix they were closed before the commit, so nothing waited on the tail."""
    before = {name: runner._destinations[name] for name in (_OB, _OB2)}
    closed = _record_closes(runner, monkeypatch)
    entered = asyncio.Event()
    in_tail: list[bool] = []

    async def schedulers_hang() -> None:
        in_tail.append(not closed)
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(runner, "_reconcile_schedulers", schedulers_hang)
    task = asyncio.create_task(runner.reload(_registry(tmp_path, "out_v2", second="out2_v2")))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    await _settle(runner)

    assert in_tail == [True]  # nothing was closed before the commit tail
    assert all(c in closed for c in before.values())


async def test_a_synchronous_raise_in_the_commit_tail_still_closes_the_retired_connectors(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    before = runner._destinations[_OB]
    closed = _record_closes(runner, monkeypatch)
    at_raise: list[bool] = []

    def forget_fails() -> None:
        at_raise.append(before in closed)
        raise RuntimeError("retain_lanes failed")

    monkeypatch.setattr(runner, "_forget_removed_anchor_lanes", forget_fails)
    with pytest.raises(RuntimeError, match="retain_lanes"):
        await runner.reload(_registry(tmp_path, "out_v2", second="out2"))
    await _settle(runner)

    assert at_raise == [False]  # not closed before the swap committed
    assert before in closed


async def test_a_rollback_whose_sandbox_close_raises_still_restores_intake(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Item 3: a refused worker-thread hop in the rollback's sandbox close stopped the rollback,
    so the reload's own error was replaced and intake stayed down."""

    async def reconcile_fails(*_args: Any) -> list[Any]:
        raise RuntimeError("step 3 failed")

    calls = {"n": 0}

    async def sandbox_close_fails() -> None:
        calls["n"] += 1
        if calls["n"] > 1:  # the rollback's close, not step 2's
            raise RuntimeError("cannot schedule new futures after shutdown")

    monkeypatch.setattr(runner, "_reconcile_outbounds", reconcile_fails)
    monkeypatch.setattr(runner, "_close_sandbox_sessions", sandbox_close_fails)
    old = runner.registry
    with pytest.raises(RuntimeError, match="step 3 failed"):
        await runner.reload(_registry(tmp_path, "out_v2", second="out2"))

    assert runner.registry is old
    assert runner.inbound_running("file_in")


async def test_the_lane_anchor_check_reads_the_reloads_one_schedule_time(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    start = datetime(2026, 11, 16, 8, 0, tzinfo=UTC)
    reads: list[datetime] = []

    def clock() -> datetime:
        reads.append(start + timedelta(minutes=len(reads)))
        return reads[-1]

    async def passes(direction: str, name: str, settings: object) -> None:
        return None

    # The FILE poller reads no CA; treat it as one that does, so the pre-check reaches its window
    # test (_listener_skip) rather than skipping it first.
    monkeypatch.setattr(wiring_runner, "_inbound_lane_reads_ca", lambda ic: True)
    rr = await _started(
        store,
        _registry(tmp_path, "out"),
        schedule_clock=clock,
        schedule_tick=3600,
        lane_anchor_check=passes,
    )
    try:
        judged: list[datetime | None] = []
        real_skip = rr._listener_skip

        def record(ic: Any, listening: Any, *, binding_now: bool, now: Any = None) -> Any:
            if not binding_now:
                judged.append(now)
            return real_skip(ic, listening, binding_now=binding_now, now=now)

        monkeypatch.setattr(rr, "_listener_skip", record)
        build_times: list[datetime | None] = []
        real_build = rr.build_check_off_loop

        async def build(*args: Any, now: datetime | None = None, **kwargs: Any) -> Any:
            build_times.append(now)
            return await real_build(*args, now=now, **kwargs)

        monkeypatch.setattr(rr, "build_check_off_loop", build)
        await rr.reload(_registry(tmp_path, "out"))

        # Before the fix the pre-check passed no time, so its window test read the clock again.
        assert build_times and build_times[0] is not None
        assert judged and set(judged) == {build_times[0]}
    finally:
        await rr.stop()


async def test_a_committed_reload_builds_only_the_connectors_it_puts_in_a_lane(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: Any
) -> None:
    """The prepare reads the apply's gates: an unchanged lane is not built again, a changed one
    is, and the apply never finds a lane it was not built for."""
    made = _fault_nth_build(monkeypatch, 0)  # never faults
    unchanged = runner._destinations[_OB]
    with caplog.at_level("ERROR", logger="messagefoundry.pipeline.wiring_runner"):
        await runner.reload(_registry(tmp_path, "out", second="out2_v2"))

    assert runner._destinations[_OB] is unchanged
    assert made == [runner._destinations[_OB2]]
    assert _directory(runner, _OB2) == tmp_path / "out2_v2"
    assert "had no connector built for it" not in caplog.text


async def test_a_reload_that_re_enables_a_start_disabled_lane_builds_it(
    store: MessageStore, tmp_path: Path
) -> None:
    """``auto_start`` flipped on: the prepare builds the lane the apply then starts."""
    base = _registry(tmp_path, "out", second="out2")
    base.outbound[_OB] = dataclasses.replace(base.outbound[_OB], auto_start=False)
    rr = await _started(store, base)
    try:
        assert not rr.outbound_running(_OB) and _OB not in rr._destinations
        await rr.reload(_registry(tmp_path, "out", second="out2"))
        assert rr.outbound_running(_OB)
        assert _directory(rr) == tmp_path / "out"
    finally:
        await rr.stop()


async def test_a_build_step_3_adds_after_the_quiesce_that_fails_restores_every_lane_and_intake(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lane comes to need a connector only once intake has stopped, so step 3 tops the plan up
    after the quiesce, and that build fails. Every lane keeps its connector, the connector the
    first prepare built is closed, and intake is restored."""
    old = runner.registry
    before = dict(runner._destinations)
    real_residue = runner._recover_stopped_worker_residue

    async def a_lane_fails_meanwhile() -> int:
        # Step 1a, inside the quiesce: the lane reads failed, so step 3 must swap its connector.
        runner._record_failed(_OB, RuntimeError("failed meanwhile"), kind="outbound")
        return await real_residue()

    monkeypatch.setattr(runner, "_recover_stopped_worker_residue", a_lane_fails_meanwhile)
    made = _fault_nth_build(monkeypatch, 2)  # build 1 is the first prepare's, for file_out_2
    closed = _record_closes(runner, monkeypatch)
    with pytest.raises(RuntimeError, match="later lane"):
        await runner.reload(_registry(tmp_path, "out", second="out2_v2"))
    await _settle(runner)

    assert runner.registry is old
    assert runner._destinations == before
    assert len(made) == 1 and made[0] in closed
    assert runner.inbound_running("file_in")


async def test_a_reload_that_retires_nothing_starts_no_close_task(
    runner: RegistryRunner, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Nothing retired, nothing to close: the reload returns with no close task and no wait on
    one. Red before the short-circuit: an empty retired list still made a task, and the reload
    awaited it."""
    calls: list[object] = []
    real = runner._close_retired

    def record(retired: list[tuple[str, DestinationConnector]]) -> Any:
        calls.append(list(retired))
        return real(retired)

    monkeypatch.setattr(runner, "_close_retired", record)
    assert await runner.reload() == ()
    assert calls == []
