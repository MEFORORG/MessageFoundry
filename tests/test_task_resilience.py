# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Long-lived background tasks survive a transient error instead of dying silently (review H-1,
H-4, M-33). The failure mode these guard against is the worst kind for an interface engine: an
outbound that stops draining (or a poller that stops receiving) while everything still reports
healthy."""

from __future__ import annotations

import asyncio
import logging
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.api import app as api_app
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore, Stage
from messagefoundry.store.store import MessageStatus, OutboxItem
from messagefoundry.transports.file import FileSource


async def _until(predicate: Any, timeout: float = 2.0) -> None:
    elapsed = 0.0
    while not predicate():
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


async def _until_async(predicate: Any, timeout: float = 5.0) -> None:
    """:func:`_until` for a predicate that must await the store (a status read)."""
    elapsed = 0.0
    while not await predicate():
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError("condition not met within timeout")


class _FlakyStore:
    """Store stub whose claim raises the first ``fail_times`` calls, then returns no work. Covers
    both claim paths so it works whichever ordering mode the worker uses (FIFO is the default)."""

    def __init__(self, fail_times: int = 1) -> None:
        self.calls = 0
        self.fail_times = fail_times

    def _tick(self) -> None:
        self.calls += 1
        if self.calls <= self.fail_times:
            raise RuntimeError("simulated store outage")

    async def claim_ready(self, **kwargs: Any) -> list[Any]:
        self._tick()
        return []

    async def claim_next_fifo(self, *args: Any, **kwargs: Any) -> Any:
        self._tick()
        return None


async def _stop_runner(runner: RegistryRunner, name: str) -> None:
    runner._stop.set()
    runner._work.set()
    runner._workers[name].cancel()
    await asyncio.gather(runner._workers[name], return_exceptions=True)


# --- H-1: delivery worker ----------------------------------------------------


async def test_delivery_worker_survives_store_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.01)
    store = _FlakyStore(fail_times=1)
    # per_lane: exercises the per-outbound delivery worker respawn (pooled has no per-outbound worker).
    runner = RegistryRunner(Registry(), store, poll_interval=0.02, claim_mode="per_lane")  # type: ignore[arg-type]
    runner._running = True
    runner._spawn_worker("OB")
    try:
        # It retries after the error (calls climb past the failing first call) and does NOT die.
        await _until(lambda: store.calls >= 2)
        assert not runner._workers["OB"].done()
    finally:
        await _stop_runner(runner, "OB")


async def test_dead_worker_is_respawned_while_running() -> None:
    # per_lane: exercises the per-outbound delivery worker respawn (pooled has no per-outbound worker).
    runner = RegistryRunner(
        Registry(), _FlakyStore(fail_times=0), poll_interval=0.02, claim_mode="per_lane"
    )  # type: ignore[arg-type]
    runner._running = True

    async def _boom() -> None:
        raise RuntimeError("worker died")

    dead = asyncio.ensure_future(_boom())
    await asyncio.gather(dead, return_exceptions=True)  # let it finish with the exception
    runner._workers["OB"] = dead

    runner._on_worker_done("OB", dead)  # simulate the done-callback firing
    try:
        assert runner._workers["OB"] is not dead  # a fresh worker took its place
        assert not runner._workers["OB"].done()
    finally:
        await _stop_runner(runner, "OB")


# --- H-4: file source poller -------------------------------------------------


async def test_file_poller_survives_scan_error(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    src = FileSource(
        Source(type=ConnectorType.FILE, settings={"directory": str(inbox), "poll_seconds": 0.02})
    )
    scans = {"n": 0}
    real_scan = src._scan_once

    async def flaky_scan() -> None:
        scans["n"] += 1
        if scans["n"] == 1:
            raise OSError("watch dir vanished")
        await real_scan()

    src._scan_once = flaky_scan  # type: ignore[method-assign]

    async def handler(raw: bytes) -> None:
        return None

    await src.start(handler)
    try:
        await _until(lambda: scans["n"] >= 3)  # kept polling past the error
        assert src._task is not None and not src._task.done()
    finally:
        await src.stop()  # must not re-raise the (now-survived) scan error


# --- M-33: API session reaper ------------------------------------------------


async def test_session_reaper_survives_purge_error(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(api_app, "_SESSION_REAP_INTERVAL", 0.01)
    calls = {"n": 0}

    class _Store:
        async def purge_expired_sessions(self) -> None:
            calls["n"] += 1
            if calls["n"] == 1:
                raise RuntimeError("db blip")

    task = asyncio.ensure_future(api_app._session_reaper(_Store()))  # type: ignore[arg-type]
    try:
        await _until(lambda: calls["n"] >= 3)  # survived the first-call error, kept purging
        assert not task.done()
    finally:
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


# --- BACKLOG #1611 step 1: surviving the fault is not enough, the claimed row must come back ---
#
# The three tests above prove a worker SURVIVES a store fault. That is only half of it: the claim is
# its own committed transaction, so the row the worker was holding stays INFLIGHT when the handoff
# that follows raises. `claim_next_fifo` selects `status='pending'`, so the surviving worker never
# sees it again, and `reset_stale_inflight` runs from `Engine.start()` only -- not from `reload()`.
# The message therefore sits at `received`, overtaken by its successors, until a service restart,
# with the stall alert reading healthy (`pending_depth` counts pending rows only).

RAW_1611 = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|MSG1611|P|2.5.1\r"


def _repend_registry(outdir: Path) -> Registry:
    """Inbound 'IB' -> router 'r' -> handler 'h'; the handler filters (routing is what is measured)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(ConnectorType.FILE, {"directory": str(outdir)}),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.FILE, {"directory": str(outdir)}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: [])
    return reg


async def test_router_worker_recovers_claimed_row_after_handoff_fault_without_restart(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The ``per_lane`` row of #1611's measured table, as a test.

    Measured 2026-09-11 on engine ``2ffcf3347``: one injected ``route_handoff`` fault in ``per_lane``
    mode left the message ``received`` with its ingress row ``inflight`` and the worker alive for the
    whole window; ``reload()`` left it in flight; only stop + ``reset_stale_inflight`` + start
    delivered it. With the re-pend in the except arm the same lane recovers in place.
    """
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.01)
    store = await MessageStore.open(tmp_path / "repend.db")
    try:
        runner = RegistryRunner(
            _repend_registry(tmp_path), store, poll_interval=0.02, claim_mode="per_lane"
        )
        mid = await store.enqueue_ingress(channel_id="IB", raw=RAW_1611)

        faults = {"n": 0}
        real_handoff = store.route_handoff

        async def flaky_handoff(*a: Any, **k: Any) -> Any:
            faults["n"] += 1
            if faults["n"] == 1:
                raise RuntimeError("simulated store fault between the claim and the handoff")
            return await real_handoff(*a, **k)

        monkeypatch.setattr(store, "route_handoff", flaky_handoff)

        task = asyncio.ensure_future(runner._router_worker("IB"))
        try:
            await _until_async(
                lambda: _is_routed(store, mid),
                timeout=5.0,  # generous: the recovery is one backoff, not one restart
            )
            assert faults["n"] >= 2  # the fault really fired, and the row was really re-tried
            assert not task.done()  # recovered in place -- the same worker, never restarted
            # Nothing stranded: the ingress lane holds no inflight row.
            cur = await store._db.execute(
                "SELECT COUNT(*) AS c FROM queue WHERE stage=? AND channel_id=? AND status=?",
                (Stage.INGRESS.value, "IB", "inflight"),
            )
            assert (await cur.fetchone())["c"] == 0
        finally:
            runner._stop.set()
            runner._ingress_work.set()
            task.cancel()
            await asyncio.gather(task, return_exceptions=True)
    finally:
        await store.close()


async def _is_routed(store: MessageStore, mid: str) -> bool:
    return bool((await store.get_message(mid))["status"] == MessageStatus.ROUTED.value)


class _OneRowThenFaultStore:
    """Hands out exactly one claimed row, then reports the lane empty. Records every
    ``reschedule_claimed``. The per-item body is patched to raise, so the worker's ``except
    Exception`` arm is the only thing that can return the claimed row to ``pending``."""

    def __init__(self, stage: str) -> None:
        self.item = OutboxItem(
            id="row-1",
            message_id="msg-1",
            channel_id="IB",
            destination_name="OB",
            payload=RAW_1611,
            attempts=1,
            stage=stage,
        )
        self.claims = 0
        self.rescheduled: list[list[str]] = []

    async def claim_next_fifo(self, *a: Any, **k: Any) -> OutboxItem | None:
        self.claims += 1
        return self.item if self.claims == 1 else None

    async def claim_ready(self, **k: Any) -> list[OutboxItem]:
        self.claims += 1
        return [self.item] if self.claims == 1 else []

    async def reschedule_claimed(
        self, ids: Any, next_attempt_at: float, now: float | None = None
    ) -> None:
        self.rescheduled.append(list(ids))


@pytest.mark.parametrize(
    ("worker_attr", "body_attr", "stage"),
    [
        ("_router_worker", "_process_ingress_item", Stage.INGRESS.value),
        ("_transform_worker", "_process_routed_batch", Stage.ROUTED.value),
        ("_response_worker", "_process_response_item", Stage.RESPONSE.value),
        ("_delivery_worker", "_process_delivery_item", Stage.OUTBOUND.value),
    ],
)
async def test_every_per_lane_worker_repends_the_row_it_claimed(
    worker_attr: str, body_attr: str, stage: str, monkeypatch: pytest.MonkeyPatch
) -> None:
    """All FOUR per-lane workers, not three. #1611's "Where" names the router, transform, response and
    delivery workers; each `except Exception` logged and backed off while leaving its claimed head
    INFLIGHT. Drives each worker over a stub store whose claim succeeds and whose per-item body
    raises -- the exact shape of a fault after a committed claim."""
    monkeypatch.setattr(wiring_runner, "_WORKER_ERROR_BACKOFF_SECONDS", 0.01)
    store = _OneRowThenFaultStore(stage)
    runner = RegistryRunner(Registry(), store, poll_interval=0.02, claim_mode="per_lane")  # type: ignore[arg-type]
    runner._running = True

    raised = {"n": 0}

    async def raiser(*a: Any, **k: Any) -> Any:
        raised["n"] += 1
        raise RuntimeError("simulated fault after the claim committed")

    monkeypatch.setattr(runner, body_attr, raiser)

    task = asyncio.ensure_future(getattr(runner, worker_attr)("IB"))
    try:
        await _until(lambda: store.rescheduled, timeout=5.0)
        assert raised["n"] >= 1  # the fault fired in the per-item body, not somewhere upstream
        assert store.rescheduled[0] == ["row-1"]  # the claimed row was handed back for re-claim
    finally:
        runner._stop.set()
        for ev in (runner._work, runner._ingress_work, runner._routed_work, runner._response_work):
            ev.set()
        task.cancel()
        await asyncio.gather(task, return_exceptions=True)


# --- BACKLOG #1609: in pooled mode a dead stage claimer is respawned, and its stage keeps draining ---
#
# `pooled_claimers_per_stage` defaults to 1, so one claimer IS its whole stage. Measured 2026-09-11 by
# injection: the INGRESS claimer died, nothing respawned it, five further messages were ACKed and all
# sat at `received`, while `runner.running` and `dispatcher.running` read healthy.


def _pooled_registry(inbox: Path, outdir: Path) -> Registry:
    """Inbound 'IB' -> router 'r' -> handler 'h' -> outbound 'OB' (swapped for a collector)."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(inbox), "pattern": "*.hl7", "poll_seconds": 5.0},
            ),
            router="r",
        )
    )
    reg.add_outbound(
        OutboundConnection("OB", ConnectionSpec(ConnectorType.FILE, {"directory": str(outdir)}))
    )
    reg.add_router("r", lambda m: ["h"])
    reg.add_handler("h", lambda m: Send("OB", m))
    return reg


class _Collector:
    """A recording outbound connector (non-capturing, so delivery marks the row done)."""

    def __init__(self) -> None:
        self.deliveries: list[str] = []

    async def send(self, payload: str) -> None:
        self.deliveries.append(payload)

    async def aclose(self) -> None:
        return None


def _hl7(control_id: str) -> bytes:
    return f"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|{control_id}|P|2.5.1\r".encode()


async def _inflight_rows(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) AS c FROM queue WHERE status='inflight'")
    return int((await cur.fetchone())["c"])


async def _delivered_count(store: MessageStore) -> int:
    return int((await store.stats()).get("done", 0))


async def _start_runner(
    tmp_path: Path, claim_mode: str
) -> tuple[MessageStore, RegistryRunner, _Collector]:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    store = await MessageStore.open(tmp_path / f"{claim_mode}.db")
    runner = RegistryRunner(
        _pooled_registry(inbox, outdir),
        store,
        poll_interval=0.02,
        claim_mode=claim_mode,
        pooled_sweep_interval=0.05,
    )
    await runner.start()
    collector = _Collector()
    runner._destinations["OB"] = collector  # type: ignore[assignment]
    return store, runner, collector


def _kill_next_claims(
    dispatcher: Any, monkeypatch: pytest.MonkeyPatch, times: int
) -> dict[str, int]:
    """Make the next ``times`` claim round-trips on ``dispatcher`` kill its claimer task.

    The raise lands in ``_spawn_serializer``, which runs in the claimer's post-claim bookkeeping
    AFTER ``claim_fifo_heads`` committed -- so the dying claimer leaves the lane reserved and its
    rows INFLIGHT, the worst shape a claimer death can leave behind. Patched on ONE dispatcher
    instance, so no other stage's claimer can take the injection."""
    fired = {"n": 0}
    real = dispatcher._spawn_serializer

    def dying(lane: str, items: Any) -> None:
        if fired["n"] < times:
            fired["n"] += 1
            raise RuntimeError("injected claimer death after a committed claim")
        real(lane, items)

    monkeypatch.setattr(dispatcher, "_spawn_serializer", dying)
    return fired


async def test_pooled_dead_ingress_claimer_is_respawned_and_its_stage_drains(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    # Pin the capture on the dispatcher's own logger: a root level above ERROR filtered these
    # records out of an earlier probe, which then passed without seeing the line it asserted on.
    caplog.set_level(logging.ERROR, logger="messagefoundry.pipeline.stage_dispatcher")
    store, runner, collector = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[Stage.INGRESS]
        first = dispatcher._claimers[0].task
        assert first is not None and not first.done()
        fired = _kill_next_claims(dispatcher, monkeypatch, times=1)

        ib = runner.registry.inbound["IB"]
        await runner._handle_inbound(ib, _hl7("M1609A"))  # its claim kills the claimer
        await _until(first.done, timeout=5.0)
        assert fired["n"] == 1 and first.exception() is not None  # the injection really killed it

        # A replacement claimer is live, and the supervisor said so.
        def _replaced() -> bool:
            task = dispatcher._claimers[0].task
            return task is not None and task is not first and not task.done()

        await _until(_replaced, timeout=5.0)
        assert "exited unexpectedly; respawning" in caplog.text

        # A message enqueued AFTER the death reaches its outbound, and so does the one whose claim
        # killed the claimer: its INFLIGHT row was released, not stranded until a restart.
        await runner._handle_inbound(ib, _hl7("M1609B"))

        async def _both_delivered() -> bool:
            return await _delivered_count(store) >= 2

        await _until_async(_both_delivered, timeout=10.0)
        # In ORDER: had the replacement claimed before releasing, M1609B would overtake M1609A.
        assert [p.split("|")[9] for p in collector.deliveries] == ["M1609A", "M1609B"]
        assert await _inflight_rows(store) == 0
        assert runner.degraded_stages() == {}  # recovered, so nothing is reported degraded
    finally:
        await runner.stop()
        await store.close()


async def test_pooled_claimer_death_shows_on_status_while_the_respawn_is_backing_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A replacement that dies at once is not respawned in a spin: the second respawn backs off,
    and for that whole window the stage reads degraded instead of healthy."""
    from messagefoundry.pipeline import stage_dispatcher

    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_BASE_SECONDS", 60.0)
    store, runner, _collector = await _start_runner(tmp_path, "pooled")
    try:
        dispatcher = runner._dispatchers[Stage.INGRESS]
        fired = _kill_next_claims(dispatcher, monkeypatch, times=2)
        assert runner.degraded_stages() == {}

        await runner._handle_inbound(runner.registry.inbound["IB"], _hl7("M1609C"))
        await _until(lambda: fired["n"] == 2, timeout=5.0)  # the first replacement died too
        await _until(lambda: dispatcher.respawns == 2, timeout=5.0)

        degraded = runner.degraded_stages()
        assert set(degraded) == {"ingress"}, degraded
        assert "claimer-0" in degraded["ingress"] and "RuntimeError" in degraded["ingress"]
        # The second replacement is live but WAITING, not claiming: no third death in the window.
        replacement = dispatcher._claimers[0].task
        assert replacement is not None and not replacement.done()
        await asyncio.sleep(0.3)
        assert fired["n"] == 2 and dispatcher.respawns == 2
        # The runner still reads running -- which is exactly why the degraded surface must exist.
        assert runner.running
        # The waiting replacement has not yet released M1609C's claimed row. A stop in that window
        # deliberately leaves it INFLIGHT for reset_stale_inflight, like a cancelled serializer's:
        # stop runs on demotion too, where an unfenced release could re-pend a successor's row.
        assert await _inflight_rows(store) == 1
        await runner.stop()
        assert await _inflight_rows(store) == 1
    finally:
        await runner.stop()
        await store.close()


class _LaneStore:
    """A minimal in-memory queue for driving one ``StageDispatcher`` directly: one pending row per
    lane, claim moves rows to inflight, ``release_claimed`` moves them back. ``events`` records the
    order of claims and releases, which is what the FIFO argument is about."""

    def __init__(self, lanes: list[str]) -> None:
        self.pending: dict[str, list[str]] = {lane: [f"{lane}-1"] for lane in lanes}
        self.inflight: set[str] = set()
        self.events: list[tuple[str, list[str]]] = []

    async def claim_fifo_heads(
        self, stage: str, lanes: Any, now: float | None = None, *, per_lane_limit: int = 1
    ) -> Any:
        from messagefoundry.store import ClaimedHeads

        by_lane: dict[str, list[OutboxItem]] = {}
        for lane in lanes:
            if self.pending.get(lane):
                row = self.pending[lane].pop(0)
                self.inflight.add(row)
                by_lane[lane] = [
                    OutboxItem(
                        id=row,
                        message_id=row,
                        channel_id=lane,
                        destination_name=None,
                        payload="x",
                        attempts=1,
                        stage=stage,
                    )
                ]
        self.events.append(("claim", list(lanes)))
        return ClaimedHeads(by_lane=by_lane, rearm=frozenset())

    async def release_claimed(self, ids: Any, now: float | None = None) -> None:
        ids = list(ids)
        self.events.append(("release", ids))
        for row in ids:
            if row in self.inflight:
                self.inflight.discard(row)
                self.pending[row.rsplit("-", 1)[0]].insert(0, row)

    async def list_fifo_lanes(self, *a: Any, **k: Any) -> list[tuple[str, float]]:
        return []


def _dispatcher(store: _LaneStore, lanes: list[str], processed: list[str]) -> Any:
    from messagefoundry.pipeline.stage_dispatcher import (
        LaneItemResult,
        LaneResultKind,
        StageDispatcher,
    )

    async def process(lane: str, item: OutboxItem) -> LaneItemResult:
        store.inflight.discard(item.id)
        processed.append(item.id)
        return LaneItemResult(LaneResultKind.RESOLVED)

    return StageDispatcher(
        Stage.INGRESS,
        store,  # type: ignore[arg-type]
        process_item=process,
        lane_provider=lambda: set(lanes),
        per_lane_limit=1,
        sweep_interval=10.0,
    )


async def test_a_claimer_that_dies_mid_chunk_releases_exactly_the_lanes_it_had_not_dispatched(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Three lanes in one claim; the claimer dies spawning the SECOND lane's serializer. The first
    lane was dispatched and finishes on its own; the second (PROCESSING, no task) and the third
    (still CLAIMING) are the abandoned set. Their rows, and only theirs, are released -- and the
    release lands BEFORE the replacement's next claim."""
    lanes = ["A", "B", "C"]
    store = _LaneStore(lanes)
    processed: list[str] = []
    d = _dispatcher(store, lanes, processed)
    spawns = {"n": 0}
    real = d._spawn_serializer

    def die_on_second(lane: str, items: Any) -> None:
        spawns["n"] += 1
        if spawns["n"] == 2:
            raise RuntimeError("injected death mid-chunk")
        real(lane, items)

    monkeypatch.setattr(d, "_spawn_serializer", die_on_second)
    await d.start()
    try:
        await _until(lambda: len(processed) == 3, timeout=5.0)
        first_claim = store.events[0]
        assert first_claim[0] == "claim" and sorted(first_claim[1]) == lanes
        # The release names the rows of the lanes after the one that was dispatched, exactly.
        assert store.events[1] == ("release", [f"{lane}-1" for lane in first_claim[1][1:]])
        assert store.events[2][0] == "claim"  # and only then does the replacement claim
        assert sorted(processed) == ["A-1", "B-1", "C-1"]  # each row once, none lost or doubled
        assert d.respawns == 1 and d.busy_violations == 0
        await _until(lambda: d.slots_free == d._max_processing_lanes, timeout=2.0)
    finally:
        await d.stop()


async def test_a_claimer_that_keeps_dying_backs_off_and_never_resets_to_an_immediate_respawn(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Every claim kills the claimer. The respawn delays climb and hold at the cap; none of them
    returns to an immediate respawn while the deaths keep coming, and the fault stays reported."""
    from messagefoundry.pipeline import stage_dispatcher

    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_BASE_SECONDS", 0.01)
    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_CAP_SECONDS", 0.04)
    # A stable window just above the cap. The window must count HEALTHY running, not time since the
    # spawn: measured from the spawn, the capped wait alone would pass it and reset the streak.
    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_STABLE_SECONDS", 0.05)
    store = _LaneStore(["L"])
    d = _dispatcher(store, ["L"], [])
    delays: list[float] = []
    real_spawn_task = d._spawn_task

    def record(index: Any, *, delay: float = 0.0) -> None:
        delays.append(delay)
        real_spawn_task(index, delay=delay)

    def always_die(lane: str, items: Any) -> None:
        raise RuntimeError("injected death on every claim")

    monkeypatch.setattr(d, "_spawn_task", record)
    await d.start()
    monkeypatch.setattr(d, "_spawn_serializer", always_die)
    d.mark_ready("L")
    try:
        await _until(lambda: d.respawns >= 7, timeout=5.0)
        respawn_delays = delays[2:]  # the first two are start()'s claimer and sweep
        assert respawn_delays[0] == 0.0  # the first respawn is immediate, like per_lane
        assert respawn_delays[1:6] == [0.01, 0.02, 0.04, 0.04, 0.04], respawn_delays
        assert d.claimer_faults, "a claimer that keeps dying must keep reading degraded"
        # Every replacement released its predecessor's row before claiming it again: never more
        # than the one claim of the current (dying) round-trip is in flight.
        assert store.inflight <= {"L-1"}
        releases = [ids for kind, ids in store.events if kind == "release"]
        assert len(releases) >= 6 and all(ids == ["L-1"] for ids in releases)
    finally:
        await d.stop()


async def test_after_repeated_deaths_an_idle_claimer_ages_out_of_the_fault(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Two quick deaths keep the fault reported past the replacement's first iteration. A claimer
    that then drains and IDLES never iterates again, and must still stop reading degraded once the
    stable window has passed -- a quiet feed overnight must not hold the heart at down."""
    from messagefoundry.pipeline import stage_dispatcher

    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_BASE_SECONDS", 0.01)
    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_STABLE_SECONDS", 0.3)
    store = _LaneStore(["L"])
    processed: list[str] = []
    d = _dispatcher(store, ["L"], processed)
    fired = _kill_next_claims(d, monkeypatch, times=2)
    await d.start()
    try:
        await _until(lambda: processed == ["L-1"] and fired["n"] == 2, timeout=5.0)
        assert d.claimer_faults  # repeated deaths: still reported right after recovery
        await asyncio.sleep(0.45)  # idle, with no further iteration, past the stable window
        assert d.claimer_faults == {}
    finally:
        await d.stop()


async def test_a_claimer_that_dies_outside_the_dispatch_loop_still_frees_its_reserved_lanes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A death in the claim-ERROR handler records no abandonment of its own. The lanes it reserved
    are CLAIMING, which nothing but their claimer can move, so the respawn must free them."""
    store = _LaneStore(["L"])
    processed: list[str] = []
    d = _dispatcher(store, ["L"], processed)
    real_claim = store.claim_fifo_heads
    calls = {"n": 0}

    async def failing_claim(*a: Any, **k: Any) -> Any:
        calls["n"] += 1
        if calls["n"] == 1:
            raise RuntimeError("store fault")
        return await real_claim(*a, **k)

    monkeypatch.setattr(store, "claim_fifo_heads", failing_claim)
    real_release = d._release_slot
    released = {"n": 0}

    def die_in_the_error_handler() -> None:
        released["n"] += 1
        if released["n"] == 1:
            raise RuntimeError("injected death inside the claim-error handler")
        real_release()

    monkeypatch.setattr(d, "_release_slot", die_in_the_error_handler)
    await d.start()
    try:
        await _until(lambda: processed == ["L-1"], timeout=5.0)
        assert d.respawns == 1
    finally:
        await d.stop()


async def test_status_names_a_pooled_stage_whose_claimer_is_down(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The same death, read through ``GET /status`` -- the route the console's nav heart polls."""
    import httpx

    from messagefoundry.api import create_app
    from messagefoundry.auth import Role
    from messagefoundry.auth.identity import ALL_CHANNELS
    from messagefoundry.auth.service import AuthService
    from messagefoundry.config.settings import AuthSettings
    from messagefoundry.pipeline import Engine, stage_dispatcher

    monkeypatch.setattr(stage_dispatcher, "_RESPAWN_BACKOFF_BASE_SECONDS", 60.0)
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    outdir.mkdir()
    engine = await Engine.create(tmp_path / "api.db", poll_interval=0.02)
    engine.add_registry(_pooled_registry(inbox, outdir))
    try:
        service = AuthService(engine.store, AuthSettings(require_mfa=False))
        await service.initialize()
        pw = "Viewer-pw-1609-long-enough"
        uid = await service.create_local_user(
            username="vw",
            password=pw,
            display_name=None,
            email=None,
            roles=[Role.VIEWER.value],
            actor="test",
        )
        await service.set_channel_scope(uid, [ALL_CHANNELS], actor="test")
        u = await service.store.get_user(uid)
        assert u is not None and u.password_hash is not None
        await service.store.set_password(
            uid, password_hash=u.password_hash, must_change_password=False
        )
        await engine.start()
        runner = engine.registry_runner
        assert runner is not None
        dispatcher = runner._dispatchers[Stage.INGRESS]
        fired = _kill_next_claims(dispatcher, monkeypatch, times=2)

        transport = httpx.ASGITransport(app=create_app(engine, auth=service))
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            r = await c.post(
                "/auth/login", json={"username": "vw", "password": pw, "provider": "local"}
            )
            headers = {"Authorization": f"Bearer {r.json()['token']}"}
            before = (await c.get("/status", headers=headers)).json()["engine"]
            assert before["stages_degraded"] == {}

            await runner._handle_inbound(runner.registry.inbound["IB"], _hl7("M1609D"))
            await _until(lambda: fired["n"] == 2 and dispatcher.respawns == 2, timeout=5.0)
            after = (await c.get("/status", headers=headers)).json()["engine"]
        assert set(after["stages_degraded"]) == {"ingress"}, after
        assert "claimer-0" in after["stages_degraded"]["ingress"]
    finally:
        await engine.stop()
