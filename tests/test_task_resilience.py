# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Long-lived background tasks survive a transient error instead of dying silently (review H-1,
H-4, M-33). The failure mode these guard against is the worst kind for an interface engine: an
outbound that stops draining (or a poller that stops receiving) while everything still reports
healthy."""

from __future__ import annotations

import asyncio
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
