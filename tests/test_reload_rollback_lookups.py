# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A failed or cancelled reload restores the lookup executors and inline eligibility of the graph it
rolls back to.

``RegistryRunner.reload`` rebuilt the DB-lookup executor from the NEW graph, closed the old one, rebuilt
the FHIR-lookup executor and recomputed ADR 0057 inline eligibility, all inside its ``try``. The
rollback arm put ``self.registry`` back and restarted the old inbounds, but left all three built from
the REFUSED graph: the restored graph would then run with a ``db_lookup``/``fhir_lookup`` runner that
names the refused graph's connections (or none at all), and take or skip the inline fast path for the
wrong graph. The old executor was closed at step 2 as well. Both retired executors now close in a
tracked, detached task, so a cancellation cannot cut a close off, and teardown waits for them.
"""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any, Literal

import pytest

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    DatabaseLookupSpec,
    FhirLookupSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner, TeardownReason
from messagefoundry.store import MessageStore
from messagefoundry.transports.database import DatabaseLookupExecutor

Failure = Literal["raise", "cancel"]


def _registry(tmp_path: Path, *, with_lookups: bool) -> Registry:
    """File-in -> router -> handler -> File-out, opted into the inline fast path. ``with_lookups``
    declares a DatabaseLookup and a FhirLookup, which turns inline eligibility off graph-wide."""
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir(exist_ok=True)
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(outdir), "filename": "{MSH-10}.hl7"}
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
            inline=True,
        )
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("file_out", m))
    if with_lookups:
        reg.add_lookup(
            DatabaseLookupSpec(name="clarity", settings={"server": "db.local", "database": "C"})
        )
        reg.add_fhir_lookup(FhirLookupSpec(name="epic", settings={"url": "https://h/fhir"}))
    return reg


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "reload-rollback-lookups.db")
    yield s
    await s.close()


@pytest.fixture
def closed(monkeypatch: pytest.MonkeyPatch) -> list[DatabaseLookupExecutor]:
    """Every DB-lookup executor ``aclose()`` was called on, in order."""
    calls: list[DatabaseLookupExecutor] = []
    real = DatabaseLookupExecutor.aclose

    async def spy(self: DatabaseLookupExecutor) -> None:
        calls.append(self)
        await real(self)

    monkeypatch.setattr(DatabaseLookupExecutor, "aclose", spy)
    return calls


async def _settle_closes(runner: RegistryRunner) -> None:
    """Let the detached close of a retired executor run, so ``closed`` is complete."""
    if runner._lookup_close_tasks:
        await asyncio.wait(runner._lookup_close_tasks)


async def _runner(store: MessageStore, registry: Registry) -> RegistryRunner:
    rr = RegistryRunner(
        registry, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    await rr.start()
    return rr


async def _failed_reload(
    runner: RegistryRunner, new: Registry, failure: Failure, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Drive ``reload(new)`` to fail at step 3, the outbound reconcile, after every executor rebuild
    and the new listeners' restart: the deepest point of the guarded span."""
    entered = asyncio.Event()

    async def failing_reconcile(*_args: Any, **_kwargs: Any) -> None:
        if failure == "raise":
            raise RuntimeError("synthetic reconcile failure")
        entered.set()
        await asyncio.Event().wait()

    monkeypatch.setattr(runner, "_reconcile_outbounds", failing_reconcile)
    if failure == "raise":
        with pytest.raises(RuntimeError, match="synthetic reconcile failure"):
            await runner.reload(new)
        return
    task = asyncio.create_task(runner.reload(new))
    reached = asyncio.create_task(entered.wait())
    # FIRST_COMPLETED, so a reload that fails before step 3 surfaces here instead of timing out.
    await asyncio.wait({task, reached}, timeout=10, return_when=asyncio.FIRST_COMPLETED)
    reached.cancel()
    assert entered.is_set(), task.exception() if task.done() else "step 3 not reached within 10s"
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task


@pytest.mark.parametrize("failure", ["raise", "cancel"])
async def test_a_rolled_back_reload_keeps_the_old_graphs_lookup_executors(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closed: list[DatabaseLookupExecutor],
    failure: Failure,
) -> None:
    # The refused graph REMOVES both lookups, so it would make the inline path eligible.
    runner = await _runner(store, _registry(tmp_path, with_lookups=True))
    try:
        old_db, old_fhir = runner._lookup_executor, runner._fhir_lookup_executor
        assert old_db is not None and old_fhir is not None
        assert runner._inline_ok["file_in"] is False

        old = runner.registry
        await _failed_reload(runner, _registry(tmp_path, with_lookups=False), failure, monkeypatch)
        await _settle_closes(runner)

        assert runner.registry is old
        assert runner._lookup_executor is old_db
        assert runner._fhir_lookup_executor is old_fhir
        assert old_db not in closed  # still serving the restored graph, so its pools stay open
        assert runner._inline_ok["file_in"] is False
    finally:
        await runner.stop()


@pytest.mark.parametrize("failure", ["raise", "cancel"])
async def test_a_rolled_back_reload_drops_the_refused_graphs_lookup_executors(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closed: list[DatabaseLookupExecutor],
    failure: Failure,
) -> None:
    # The refused graph ADDS both lookups, so it would make the inline path ineligible.
    runner = await _runner(store, _registry(tmp_path, with_lookups=False))
    try:
        assert runner._lookup_executor is None and runner._fhir_lookup_executor is None
        assert runner._inline_ok["file_in"] is True

        await _failed_reload(runner, _registry(tmp_path, with_lookups=True), failure, monkeypatch)
        await _settle_closes(runner)

        assert runner._lookup_executor is None
        assert runner._fhir_lookup_executor is None
        assert runner._inline_ok["file_in"] is True
        # The executor built for the refused graph is closed by the rollback, not leaked.
        assert [ex.connections for ex in closed] == [frozenset({"clarity"})]
    finally:
        await runner.stop()


async def test_the_rollback_restores_before_its_first_await(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The rollback's first await is _close_sandbox_sessions. Whatever runs during it, and every
    # await after it, must already see the old graph's executors and inline eligibility.
    runner = await _runner(store, _registry(tmp_path, with_lookups=True))
    try:
        old_db, old_fhir = runner._lookup_executor, runner._fhir_lookup_executor
        old_inline = dict(runner._inline_ok)
        seen: list[tuple[object, object, dict[str, bool]]] = []
        real_close = runner._close_sandbox_sessions

        async def recording_close() -> None:
            seen.append(
                (runner._lookup_executor, runner._fhir_lookup_executor, dict(runner._inline_ok))
            )
            await real_close()

        monkeypatch.setattr(runner, "_close_sandbox_sessions", recording_close)
        await _failed_reload(runner, _registry(tmp_path, with_lookups=False), "raise", monkeypatch)
        await _settle_closes(runner)

        # [0] is the forward step 2 call, made before the rebuild; [1] is the rollback's.
        assert len(seen) == 2
        assert seen[1] == (old_db, old_fhir, old_inline)
    finally:
        await runner.stop()


async def test_a_committed_reload_closes_the_old_executor_once_the_swap_holds(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closed: list[DatabaseLookupExecutor],
) -> None:
    runner = await _runner(store, _registry(tmp_path, with_lookups=True))
    try:
        old_db = runner._lookup_executor
        assert old_db is not None
        real_reconcile = runner._reconcile_outbounds
        open_during_step_3: list[bool] = []

        async def observing_reconcile(*args: Any, **kwargs: Any) -> None:
            open_during_step_3.append(old_db not in closed)
            await real_reconcile(*args, **kwargs)

        monkeypatch.setattr(runner, "_reconcile_outbounds", observing_reconcile)
        await runner.reload(_registry(tmp_path, with_lookups=True))
        await _settle_closes(runner)

        assert open_during_step_3 == [True]  # not closed before the swap could still roll back

        new_db = runner._lookup_executor
        assert new_db is not None and new_db is not old_db
        assert closed == [old_db]
        assert runner._fhir_lookup_executor is not None
        assert runner._inline_ok["file_in"] is False
    finally:
        await runner.stop()


async def test_a_reload_rolled_back_before_the_rebuild_closes_no_executor(
    store: MessageStore,
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    closed: list[DatabaseLookupExecutor],
) -> None:
    # Step 1a fails, so step 2 never rebuilt anything: the live executor must not be retired.
    runner = await _runner(store, _registry(tmp_path, with_lookups=True))
    try:
        old_db = runner._lookup_executor
        assert old_db is not None

        async def failing_recovery() -> None:
            raise RuntimeError("synthetic step 1a failure")

        monkeypatch.setattr(runner, "_recover_stopped_worker_residue", failing_recovery)
        with pytest.raises(RuntimeError, match="synthetic step 1a failure"):
            await runner.reload(_registry(tmp_path, with_lookups=False))
        await _settle_closes(runner)

        assert runner._lookup_executor is old_db
        assert closed == []
        assert runner._inline_ok["file_in"] is False
    finally:
        await runner.stop()


async def test_a_slow_close_of_the_old_executor_neither_holds_the_reload_nor_leaks(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The old executor's close blocks, as wait_closed does behind an in-flight lookup. The committed
    # reload returns anyway (no cancellation can land in the close and make it look failed), and
    # stop() waits for the close rather than abandoning the pools.
    runner = await _runner(store, _registry(tmp_path, with_lookups=True))
    release = asyncio.Event()
    try:
        old_db = runner._lookup_executor
        assert old_db is not None
        finished: list[DatabaseLookupExecutor] = []
        real = DatabaseLookupExecutor.aclose

        async def slow_aclose(self: DatabaseLookupExecutor) -> None:
            if self is old_db:
                await release.wait()
            await real(self)
            finished.append(self)

        monkeypatch.setattr(DatabaseLookupExecutor, "aclose", slow_aclose)
        new = _registry(tmp_path, with_lookups=True)
        await asyncio.wait_for(runner.reload(new), 10)
        assert runner.registry is new
        assert old_db not in finished

        # Teardown's last await before the retired-close wait is _close_sandbox_sessions, so once
        # it has returned the stop is at (or past) that wait. No wall clock: spin the loop instead.
        reached = asyncio.Event()
        real_close = runner._close_sandbox_sessions

        async def marking_close() -> None:
            await real_close()
            reached.set()

        monkeypatch.setattr(runner, "_close_sandbox_sessions", marking_close)
        stopping = asyncio.create_task(runner.stop())
        await asyncio.wait_for(reached.wait(), 10)
        for _ in range(50):
            await asyncio.sleep(0)
        assert not stopping.done()
        release.set()
        await asyncio.wait_for(stopping, 10)
        assert old_db in finished
    finally:
        release.set()
        await runner.stop()


async def test_a_demote_stop_bounds_the_wait_on_a_hanging_retired_close(
    store: MessageStore, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # ADR 0157: every DEMOTE bound is absorbed where it is set. A retired executor whose close never
    # finishes must not hold a demotion past its budget; the close is left running, not cancelled.
    runner = await _runner(store, _registry(tmp_path, with_lookups=True))
    release = asyncio.Event()
    try:
        old_db = runner._lookup_executor
        assert old_db is not None
        real = DatabaseLookupExecutor.aclose

        async def hanging_aclose(self: DatabaseLookupExecutor) -> None:
            if self is old_db:
                await release.wait()
            await real(self)

        monkeypatch.setattr(DatabaseLookupExecutor, "aclose", hanging_aclose)
        await asyncio.wait_for(runner.reload(_registry(tmp_path, with_lookups=True)), 10)
        pending = set(runner._lookup_close_tasks)
        assert len(pending) == 1

        await asyncio.wait_for(runner.stop(reason=TeardownReason.DEMOTE, budget_seconds=0.2), 5)
        assert not runner._running
        assert not any(t.done() for t in pending)  # abandoned, not cancelled
    finally:
        release.set()
        await _settle_closes(runner)
        await runner.stop()
