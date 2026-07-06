# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-013 (CWE-1322): the Router and Handler run OFF the asyncio event loop unconditionally.

Previously the transform worker only offloaded ``transform_one`` to a worker thread when the graph
declared a ``DatabaseLookup``; in the common no-lookup case it (and the router's ``route_only``) ran
INLINE on the single event loop. A Handler/Router is arbitrary synchronous Python whose CPU cost can
scale with attacker-influenced content (ReDoS, O(n^2) build), so an inline run could stall every
listener, worker, and the API. These tests prove both now hop off the loop via ``asyncio.to_thread``
(which copies the run-scoped provider ContextVars into the worker thread, so provider resolution still
works) and that the loop stays responsive while a slow handler runs.
"""

from __future__ import annotations

import asyncio
import threading
import time
from pathlib import Path

import pytest

from messagefoundry.config.wiring import (
    ConnectionSpec,
    ConnectorType,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.config.active_environment import current_environment
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, OutboxStatus

ADT = (
    "MSH|^~\\&|SENDINGAPP|SENDINGFAC|RECV|RFAC|20260604||ADT^A01|MSG1|P|2.5.1\r"
    "EVN|A01|20260604\r"
    "PID|1||100^^^H^MR||DOE^JANE\r"
)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(inbox: Path, outdir: Path, route, handlers: dict) -> Registry:  # type: ignore[no-untyped-def]
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
        )
    )
    reg.add_router("r", route)
    for name, fn in handlers.items():
        reg.add_handler(name, fn)
    return reg


def _drop_one(inbox: Path) -> None:
    inbox.mkdir(exist_ok=True)
    (inbox / "a.hl7").write_bytes(ADT.encode("utf-8"))


async def _until_stat(
    store: MessageStore, status: str, expected: int, timeout: float = 3.0
) -> None:
    elapsed = 0.0
    while (await store.stats()).get(status, 0) != expected:
        await asyncio.sleep(0.02)
        elapsed += 0.02
        if elapsed > timeout:
            raise AssertionError(f"{status} != {expected} within timeout")


# --- off-loop proof ----------------------------------------------------------


async def test_transform_runs_off_main_thread(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    _drop_one(inbox)
    seen: dict[str, bool] = {}

    def handle(m):  # type: ignore[no-untyped-def]
        seen["off_loop"] = threading.current_thread() is not threading.main_thread()
        return Send("file_out", str(m))

    reg = _registry(inbox, outdir, lambda m: ["h"], {"h": handle})
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()
    assert seen.get("off_loop") is True  # the Handler executed on a worker thread, not the loop


async def test_router_runs_off_main_thread(store: MessageStore, tmp_path: Path) -> None:
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    _drop_one(inbox)
    seen: dict[str, bool] = {}

    def route(m):  # type: ignore[no-untyped-def]
        seen["off_loop"] = threading.current_thread() is not threading.main_thread()
        return ["h"]

    reg = _registry(inbox, outdir, route, {"h": lambda m: Send("file_out", str(m))})
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    await runner.start()
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()
    assert seen.get("off_loop") is True  # the Router executed on a worker thread, not the loop


# --- loop-stays-responsive regression ----------------------------------------


async def test_slow_handler_does_not_stall_the_loop(store: MessageStore, tmp_path: Path) -> None:
    # A handler that blocks (time.sleep stands in for a CPU-pathological transform) must NOT freeze the
    # loop: a concurrent tick task keeps advancing during the handler's run. This FAILS on the old inline
    # code (the loop is blocked for the whole sleep, so the counter can't advance) and PASSES off-loop.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    _drop_one(inbox)

    handler_running = asyncio.Event()
    loop = asyncio.get_running_loop()

    def slow(m):  # type: ignore[no-untyped-def]
        loop.call_soon_threadsafe(handler_running.set)
        time.sleep(0.3)  # blocking stand-in for a heavy transform
        return Send("file_out", str(m))

    ticks = 0

    async def ticker() -> None:
        nonlocal ticks
        while True:
            await asyncio.sleep(0.01)
            ticks += 1

    reg = _registry(inbox, outdir, lambda m: ["h"], {"h": slow})
    runner = RegistryRunner(reg, store, poll_interval=0.02)
    tick_task = asyncio.ensure_future(ticker())
    await runner.start()
    try:
        await asyncio.wait_for(handler_running.wait(), timeout=3.0)
        ticks_at_start = ticks
        # Wait while the handler is mid-sleep; the loop must keep ticking the counter.
        await asyncio.sleep(0.2)
        assert ticks > ticks_at_start, (
            "loop was stalled while the handler ran (inline, not off-loop)"
        )
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        tick_task.cancel()
        await runner.stop()


# --- provider resolution survives the thread hop -----------------------------


async def test_provider_resolves_off_loop(store: MessageStore, tmp_path: Path) -> None:
    # current_environment() is published via run_contexts ContextVars on the loop; asyncio.to_thread
    # COPIES the current context into the worker thread, so the provider must still resolve there.
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    _drop_one(inbox)

    def handle(m):  # type: ignore[no-untyped-def]
        env = current_environment()  # resolves only if the ContextVar copied into this thread
        return Send("file_out", f"env={env}")

    reg = _registry(inbox, outdir, lambda m: ["h"], {"h": handle})
    runner = RegistryRunner(reg, store, poll_interval=0.02, active_environment="staging")
    await runner.start()
    try:
        await _until_stat(store, OutboxStatus.DONE.value, 1)
    finally:
        await runner.stop()

    # The outbound payload reflects the provider value, not a "no active context" default.
    mid = (await store.list_messages(channel_id="file_in", status=MessageStatus.PROCESSED.value))[
        0
    ]["id"]
    payloads = await store.outbox_payloads_for(mid)
    assert payloads and payloads[0]["payload"] == "env=staging"
