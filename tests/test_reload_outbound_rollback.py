# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A rolled-back reload puts its outbound lanes back, a retired connector's close failure does
not roll a reload back, and one reload judges a schedule window at one time (BACKLOG #5755).

``RegistryRunner.reload``'s rollback restored the registry, the env values, the lookups and
intake, but never the outbound state step 3 (``_reconcile_outbounds``) had already written: a
connector built from the refused graph stayed mapped, and its retry, simulate and pause state with
it, until a restart. Three of step 3's branches also closed a retired connector with a bare
``aclose()``, so a close that raised rolled the reload back after the mapping changed. And the
lane anchor pre-check judged an inbound's schedule window at its own clock read, not at the one the
build check and the listener loop share.
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

_OB = "file_out"


def _registry(
    tmp_path: Path,
    outdir: str,
    *,
    deployed: bool = True,
    simulate: bool = False,
    second: str | None = None,
) -> Registry:
    inbox = tmp_path / "in"
    inbox.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            _OB,
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / outdir), "filename": "{MSH-10}.hl7"},
            ),
            deployed=deployed,
            simulate=simulate,
        )
    )
    if second is not None:
        reg.add_outbound(
            OutboundConnection(
                "file_out_2",
                ConnectionSpec(
                    ConnectorType.FILE,
                    {"directory": str(tmp_path / second), "filename": "{MSH-10}.hl7"},
                ),
            )
        )
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


@pytest.fixture
async def runner(store: MessageStore, tmp_path: Path) -> AsyncIterator[RegistryRunner]:
    rr = RegistryRunner(
        _registry(tmp_path, "out", second="out2"),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
    )
    await rr.start()
    assert _OB in rr._destinations
    yield rr
    await rr.stop()


def _directory(runner: RegistryRunner, name: str = _OB) -> Path:
    return Path(runner._destinations[name].directory)  # type: ignore[attr-defined]


def _fail_second_build(
    runner: RegistryRunner, monkeypatch: pytest.MonkeyPatch, *, hang: asyncio.Event | None = None
) -> None:
    """Make step 3's second connector build fail, or hang once ``hang`` is set, after the first
    lane already holds the refused graph's connector."""
    real = wiring_runner._build_off_loop
    calls = {"n": 0}

    async def second_fails(*args: Any, **kwargs: Any) -> Any:
        build = args[1]
        # Only step 3's outbound builds count: the build check and step 2's source builds run
        # through the same helper with other callables.
        if getattr(build, "func", None) is build_destination:
            calls["n"] += 1
        if calls["n"] == 2:
            # Inside step 3, with the first lane already swapped to the refused graph's connector.
            step3 = runner._outbound_pass
            assert step3 is not None and _OB in step3.lanes
            assert runner._destinations[_OB] is not step3.lanes[_OB].connector
            calls["n"] += 1  # once
            if hang is not None:
                hang.set()
                await asyncio.Event().wait()
            raise RuntimeError("a later lane failed mid-reconcile")
        return await real(*args, **kwargs)

    monkeypatch.setattr(wiring_runner, "_build_off_loop", second_fails)


async def test_a_failed_reload_puts_a_swapped_outbound_connector_back(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = runner.registry
    before = runner._destinations[_OB]
    retry_before = runner._retry[_OB]
    _fail_second_build(runner, monkeypatch)
    new = _registry(tmp_path, "out_v2", simulate=True, second="out2_v2")
    with pytest.raises(RuntimeError, match="mid-reconcile"):
        await runner.reload(new)

    assert runner.registry is old
    # Before the fix the first lane kept the refused graph's connector and its simulate flag.
    assert runner._destinations[_OB] is before  # put back open, not built again
    assert runner._simulate[_OB] is False
    assert runner._retry[_OB] is retry_before
    assert _directory(runner, "file_out_2") == tmp_path / "out2"
    assert runner.inbound_running("file_in")
    assert runner.outbound_running(_OB)


async def test_a_cancelled_reload_puts_a_swapped_outbound_connector_back(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    old = runner.registry
    before = runner._destinations[_OB]
    entered = asyncio.Event()
    _fail_second_build(runner, monkeypatch, hang=entered)
    task = asyncio.create_task(runner.reload(_registry(tmp_path, "out_v2", second="out2_v2")))
    await asyncio.wait_for(entered.wait(), 10)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task

    assert runner.registry is old
    assert runner._destinations[_OB] is before
    assert runner.inbound_running("file_in")


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


async def test_a_failed_reload_rolls_back_a_retired_lane(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lane the refused graph took out of deployment comes back running, on its own connector,
    which step 3 had not closed."""
    before = runner._destinations[_OB]
    closed: list[str] = []
    real_close = runner._close_replaced

    async def record_close(name: str, replaced: Any, failures: list[tuple[str, str]]) -> None:
        closed.append(name)
        await real_close(name, replaced, failures)

    real = runner._reconcile_outbounds

    async def fail_after_forward(*args: Any, **kwargs: Any) -> list[tuple[str, str]]:
        await real(*args, **kwargs)
        raise RuntimeError("step 3 failed after its last lane")

    monkeypatch.setattr(runner, "_close_replaced", record_close)
    monkeypatch.setattr(runner, "_reconcile_outbounds", fail_after_forward)
    with pytest.raises(RuntimeError, match="after its last lane"):
        await runner.reload(_registry(tmp_path, "out", deployed=False, second="out2"))

    await asyncio.sleep(0)  # let any detached close the rollback scheduled run
    assert runner._destinations[_OB] is before
    assert closed == []
    assert runner.outbound_running(_OB)


async def test_a_failed_reload_leaves_a_lane_it_added_draining(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lane only the refused graph declares keeps the connector step 3 built, so rows its
    handlers queued during the reload still drain, as a lane a reload drops does."""
    new = _registry(tmp_path, "out", second="out2")
    new.add_outbound(
        OutboundConnection(
            "file_out_3",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(tmp_path / "out3"), "filename": "{MSH-10}.hl7"},
            ),
        )
    )
    real = runner._reconcile_outbounds

    async def fail_after_forward(*args: Any, **kwargs: Any) -> list[tuple[str, str]]:
        await real(*args, **kwargs)
        raise RuntimeError("step 3 failed after its last lane")

    monkeypatch.setattr(runner, "_reconcile_outbounds", fail_after_forward)
    with pytest.raises(RuntimeError, match="after its last lane"):
        await runner.reload(new)

    assert "file_out_3" not in runner.registry.outbound
    assert _directory(runner, "file_out_3") == tmp_path / "out3"


async def test_a_failed_reload_parks_again_a_start_disabled_lane_it_started(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refused graph flips ``auto_start`` on, and its step 3 starts the lane. The rollback
    parks it again, as the graph it restores declares it."""
    old = _registry(tmp_path, "out", second="out2")
    parked = dataclasses.replace(old.outbound[_OB], auto_start=False)
    old.outbound[_OB] = parked
    rr = RegistryRunner(
        old, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    await rr.start()
    try:
        assert not rr.outbound_running(_OB)
        real = rr._reconcile_outbounds

        async def fail_after_forward(*args: Any, **kwargs: Any) -> list[tuple[str, str]]:
            await real(*args, **kwargs)
            assert rr.outbound_running(_OB)  # the refused graph's step 3 started it
            raise RuntimeError("step 3 failed after its last lane")

        monkeypatch.setattr(rr, "_reconcile_outbounds", fail_after_forward)
        with pytest.raises(RuntimeError, match="after its last lane"):
            await rr.reload(_registry(tmp_path, "out", second="out2"))

        assert rr.registry is old
        assert not rr.outbound_running(_OB)
        assert _OB not in rr._destinations
    finally:
        await rr.stop()


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
    rr = RegistryRunner(
        _registry(tmp_path, "out"),
        store,
        poll_interval=0.02,
        egress=EgressSettings(deny_by_default=False),
        schedule_clock=clock,
        schedule_tick=3600,
        lane_anchor_check=passes,
    )
    await rr.start()
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


def _record_closes(runner: RegistryRunner, monkeypatch: pytest.MonkeyPatch) -> list[Any]:
    closed: list[Any] = []
    real_close = runner._close_replaced

    async def record(name: str, replaced: Any, failures: list[tuple[str, str]]) -> None:
        closed.append(replaced)
        await real_close(name, replaced, failures)

    monkeypatch.setattr(runner, "_close_replaced", record)
    return closed


async def _settle(runner: RegistryRunner) -> None:
    """Let the detached closes a reload or its rollback scheduled run."""
    for _ in range(3):
        await asyncio.sleep(0)
    if runner._lookup_close_tasks:
        await asyncio.wait(runner._lookup_close_tasks, timeout=10)


def _fail_after_forward(runner: RegistryRunner, monkeypatch: pytest.MonkeyPatch) -> None:
    real = runner._reconcile_outbounds

    async def fail_after_forward(*args: Any, **kwargs: Any) -> list[tuple[str, str]]:
        await real(*args, **kwargs)
        raise RuntimeError("step 3 failed after its last lane")

    monkeypatch.setattr(runner, "_reconcile_outbounds", fail_after_forward)


async def test_a_raise_after_the_swap_still_closes_the_retired_connectors(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The closes ran at the end of the commit tail, so a raise in the scheduler reconcile, the
    one await before them, left the connectors step 3 retired open with nothing holding them."""
    before = runner._destinations[_OB]
    closed = _record_closes(runner, monkeypatch)

    async def schedulers_fail() -> None:
        raise RuntimeError("scheduler reconcile failed")

    monkeypatch.setattr(runner, "_reconcile_schedulers", schedulers_fail)
    with pytest.raises(RuntimeError, match="scheduler reconcile"):
        await runner.reload(_registry(tmp_path, "out_v2", second="out2"))
    await _settle(runner)

    assert runner._destinations[_OB] is not before
    assert before in closed


async def test_a_rollback_puts_back_a_dropped_lane_still_draining(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lane an earlier reload dropped keeps draining on its connector. A refused reload that
    re-adds it changed retires that connector; the rollback puts it back rather than leak it."""
    await runner.reload(_registry(tmp_path, "out"))  # drops file_out_2, which keeps draining
    assert "file_out_2" not in runner.registry.outbound
    draining = runner._destinations["file_out_2"]
    closed = _record_closes(runner, monkeypatch)
    _fail_after_forward(runner, monkeypatch)
    with pytest.raises(RuntimeError, match="after its last lane"):
        await runner.reload(_registry(tmp_path, "out", second="out2_v2"))
    await _settle(runner)

    assert runner._destinations["file_out_2"] is draining
    assert draining not in closed
    assert closed  # the connector the refused graph built for it is closed


async def test_a_restore_that_raises_does_not_stop_the_rollback(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def restore_fails(*_args: Any) -> list[tuple[str, Any]]:
        raise RuntimeError("restore failed")

    monkeypatch.setattr(runner, "_restore_outbound_lanes", restore_fails)
    _fail_after_forward(runner, monkeypatch)
    old = runner.registry
    # Before the fix the restore's raise replaced the reload's error and left intake down.
    with pytest.raises(RuntimeError, match="after its last lane"):
        await runner.reload(_registry(tmp_path, "out_v2", second="out2"))

    assert runner.registry is old
    assert runner.inbound_running("file_in")


async def test_a_synchronous_raise_after_the_swap_still_closes_the_retired_connectors(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A raise in the commit tail's synchronous steps skipped the closes as an awaited one did."""
    before = runner._destinations[_OB]
    closed = _record_closes(runner, monkeypatch)

    def forget_fails() -> None:
        raise RuntimeError("retain_lanes failed")

    monkeypatch.setattr(runner, "_forget_removed_anchor_lanes", forget_fails)
    with pytest.raises(RuntimeError, match="retain_lanes"):
        await runner.reload(_registry(tmp_path, "out_v2", second="out2"))
    await _settle(runner)

    assert before in closed


async def test_a_lane_restore_that_raises_still_closes_the_refused_connectors(
    runner: RegistryRunner, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The refused graph takes the first lane out of deployment and rebuilds the second. The
    first lane's restore raises in its unpark. The second lane is still put back, and the
    connector the refused graph built for it is closed, not lost with the raise."""
    before = {name: runner._destinations[name] for name in (_OB, "file_out_2")}
    closed = _record_closes(runner, monkeypatch)
    refused: list[Any] = []
    real = runner._reconcile_outbounds

    async def fail_after_forward(*args: Any, **kwargs: Any) -> list[tuple[str, str]]:
        await real(*args, **kwargs)
        refused.append(runner._destinations["file_out_2"])

        def unpark_fails(name: str) -> None:
            raise RuntimeError("dispatcher refused the resume")

        monkeypatch.setattr(runner, "_unpark_outbound_lane", unpark_fails)
        raise RuntimeError("step 3 failed after its last lane")

    monkeypatch.setattr(runner, "_reconcile_outbounds", fail_after_forward)
    with pytest.raises(RuntimeError, match="after its last lane"):
        await runner.reload(_registry(tmp_path, "out", deployed=False, second="out2_v2"))
    await _settle(runner)

    assert refused and refused[0] is not before["file_out_2"]
    assert runner._destinations["file_out_2"] is before["file_out_2"]
    assert refused[0] in closed
    assert runner.inbound_running("file_in")


async def test_a_rollback_parks_again_a_dropped_lane_that_was_parked(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lane an earlier reload dropped while ``auto_start=False`` parked it has no connector,
    but it has state. A refused reload that re-adds it with ``auto_start`` on starts it; the
    rollback parks it again rather than leave it delivering on the refused graph's connector."""
    base = _registry(tmp_path, "out", second="out2")
    base.outbound["file_out_2"] = dataclasses.replace(base.outbound["file_out_2"], auto_start=False)
    rr = RegistryRunner(
        base, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    await rr.start()
    try:
        await rr.reload(_registry(tmp_path, "out"))  # drops the parked file_out_2
        assert "file_out_2" not in rr._destinations
        # Dropped and unknown to the registry, so read the park itself.
        assert "file_out_2" in rr._outbound_paused and "file_out_2" in rr._gate_parked
        real = rr._reconcile_outbounds

        async def fail_after_forward(*args: Any, **kwargs: Any) -> list[tuple[str, str]]:
            await real(*args, **kwargs)
            assert rr.outbound_running("file_out_2")  # the refused graph's step 3 started it
            raise RuntimeError("step 3 failed after its last lane")

        monkeypatch.setattr(rr, "_reconcile_outbounds", fail_after_forward)
        with pytest.raises(RuntimeError, match="after its last lane"):
            await rr.reload(_registry(tmp_path, "out", second="out2"))

        assert "file_out_2" in rr._outbound_paused and "file_out_2" in rr._gate_parked
        assert "file_out_2" not in rr._destinations
    finally:
        await rr.stop()
