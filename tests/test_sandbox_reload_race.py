# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reload under ``[sandbox].mode=subprocess`` no longer dead-letters an in-flight message (vault
BACKLOG #2772).

A reload closes every sandbox session while the router and transform workers keep running. A worker
resolves its session on the event loop and dispatches to it from a thread, so the reload's close can
land between the two, and the dispatch then raises "sandbox session is closed". That error says
nothing about the message, yet the worker handed it to the internal-error policy, which dead-lettered
the message (or, under STOP, halted the lane).

The race is made deterministic here: the patched ``route_only``/``transform_one`` holds the worker's
thread after it resolved its session and before it dispatches, and a real ``reload`` runs meanwhile.
On the code before this change the message ends ``ERROR``. Synthetic HL7 only.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import load_config
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.dryrun import route_only, transform_one
from messagefoundry.pipeline.sandbox import (
    SandboxMode,
    SandboxPolicy,
    SandboxSession,
    SandboxSessionClosed,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage

RAW = "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||ADT^A01|RACE0001|P|2.5\rPID|1||MRN1\r"

_GRAPH = """
from messagefoundry import inbound, outbound, router, handler, File, Send

inbound("IB_RACE", File(directory={inbox!r}, poll_seconds=0.05), router="r")
outbound("OB_RACE", File(directory={outbox!r}))


@router("r")
def r(msg):
    return "h"


@handler("h")
def h(msg):
    return Send("OB_RACE", msg)
"""


@pytest.fixture
def config_dir(tmp_path: Path) -> str:
    inbox, outbox, cfg = tmp_path / "in", tmp_path / "out", tmp_path / "cfg"
    for d in (inbox, outbox, cfg):
        d.mkdir()
    (cfg / "graph.py").write_text(
        _GRAPH.format(inbox=str(inbox), outbox=str(outbox)), encoding="utf-8"
    )
    return str(cfg)


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "race.db")
    yield s
    await s.close()


def _runner(config_dir: str, store: MessageStore) -> RegistryRunner:
    return RegistryRunner(
        load_config(config_dir),
        store,
        sandbox_policy=SandboxPolicy(mode=SandboxMode.SUBPROCESS, wall_seconds=60.0),
        sandbox_config_source=(config_dir, None),
        egress=EgressSettings(deny_by_default=False),
    )


async def _status(store: MessageStore, mid: str) -> str:
    msg = await store.get_message(mid)
    assert msg is not None
    return str(msg["status"])


async def _settled(store: MessageStore, mid: str, timeout: float = 60.0) -> str:
    """The message's status once it is terminal, or whatever it is when ``timeout`` runs out."""
    terminal = {MessageStatus.PROCESSED.value, MessageStatus.ERROR.value}
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        status = await _status(store, mid)
        if status in terminal:
            return status
        await asyncio.sleep(0.05)
    return await _status(store, mid)


def _held(
    real: Callable[..., Any], held: threading.Event, release: threading.Event, seen: list[Any]
) -> Callable[..., Any]:
    """``real``, whose FIRST call parks its thread after the worker resolved its session and before
    the dispatch, which is the window a reload's close has to land in."""

    def call(*args: Any, sandbox: SandboxSession | None = None, **kwargs: Any) -> Any:
        seen.append(sandbox)
        if len(seen) == 1:
            held.set()
            assert release.wait(60), "the test never released the held dispatch"
        return real(*args, sandbox=sandbox, **kwargs)

    return call


@pytest.mark.parametrize("phase", ["route_only", "transform_one"])
async def test_a_reload_between_resolve_and_dispatch_does_not_dead_letter(
    phase: str, config_dir: str, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    held, release = threading.Event(), threading.Event()
    seen: list[Any] = []
    monkeypatch.setattr(
        wiring_runner, phase, _held(getattr(wiring_runner, phase), held, release, seen)
    )
    runner = _runner(config_dir, store)
    await runner.start()
    try:
        mid = await store.enqueue_ingress(
            channel_id="IB_RACE", raw=RAW, control_id="RACE0001", message_type="ADT^A01"
        )
        runner._wake_lane(Stage.INGRESS, "IB_RACE")
        assert await asyncio.to_thread(held.wait, 60), "the worker never reached the dispatch"

        await runner.reload(load_config(config_dir))
        resolved = seen[0]
        assert isinstance(resolved, SandboxSession)
        assert resolved._closed  # the reload closed the session the held worker resolved

        release.set()
        assert await _settled(store, mid) == MessageStatus.PROCESSED.value
        # It ran again on the session the runner resolves after the reload, not on the closed one.
        assert len(seen) >= 2
        assert seen[1] is not resolved
        assert isinstance(seen[1], SandboxSession) and not seen[1]._closed
    finally:
        release.set()
        await runner.stop()


def _closing(
    real: Callable[..., Any],
    runner: RegistryRunner,
    loop: asyncio.AbstractEventLoop,
    seen: list[Any],
) -> Callable[..., Any]:
    """``real``, with a reload's close landing between the resolve and EVERY dispatch -- a second
    reload, or a failed reload's rollback, inside the same call."""

    def call(*args: Any, sandbox: SandboxSession | None = None, **kwargs: Any) -> Any:
        seen.append(sandbox)
        asyncio.run_coroutine_threadsafe(runner._close_sandbox_sessions(), loop).result(30)
        return real(*args, sandbox=sandbox, **kwargs)

    return call


async def _queue_row(store: MessageStore, row_id: str) -> tuple[str, str]:
    cur = await store._db.execute("SELECT stage, status FROM queue WHERE id=?", (row_id,))
    row = await cur.fetchone()
    assert row is not None
    return str(row["stage"]), str(row["status"])


async def test_a_router_dispatch_closed_twice_is_an_infrastructure_fault(
    config_dir: str, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The retry is one: a session closed again under it propagates out of the item body, which the
    worker's own fault arm re-pends (per-lane #1611, pooled ADR 0070 T17). It never reaches the
    internal-error policy, so the row is not dead-lettered and the message stays RECEIVED."""
    runner = _runner(config_dir, store)
    seen: list[Any] = []
    monkeypatch.setattr(
        wiring_runner,
        "route_only",
        _closing(route_only, runner, asyncio.get_running_loop(), seen),
    )
    mid = await store.enqueue_ingress(
        channel_id="IB_RACE", raw=RAW, control_id="RACE0001", message_type="ADT^A01"
    )
    item = await store.claim_next_fifo("IB_RACE", stage=Stage.INGRESS.value)
    assert item is not None

    with pytest.raises(SandboxSessionClosed):
        await runner._process_ingress_item("IB_RACE", item)

    assert len(seen) == 2  # the first attempt and exactly one retry, each on its own session
    assert seen[0] is not seen[1]
    assert await _status(store, mid) == MessageStatus.RECEIVED.value
    assert await _queue_row(store, item.id) == (Stage.INGRESS.value, "inflight")


async def test_a_transform_dispatch_closed_twice_is_an_infrastructure_fault(
    config_dir: str, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner = _runner(config_dir, store)
    seen: list[Any] = []
    monkeypatch.setattr(
        wiring_runner,
        "transform_one",
        _closing(transform_one, runner, asyncio.get_running_loop(), seen),
    )
    mid = await store.enqueue_ingress(
        channel_id="IB_RACE", raw=RAW, control_id="RACE0001", message_type="ADT^A01"
    )
    ingress = await store.claim_next_fifo("IB_RACE", stage=Stage.INGRESS.value)
    assert ingress is not None
    await store.route_handoff(
        ingress_id=ingress.id,
        message_id=mid,
        channel_id="IB_RACE",
        handlers=[("h", RAW)],
        disposition=MessageStatus.ROUTED,
    )
    item = await store.claim_next_fifo("IB_RACE", stage=Stage.ROUTED.value)
    assert item is not None

    with pytest.raises(SandboxSessionClosed):
        await runner._process_routed_item("IB_RACE", item)

    assert len(seen) == 2
    assert await _status(store, mid) == MessageStatus.ROUTED.value
    assert await _queue_row(store, item.id) == (Stage.ROUTED.value, "inflight")


async def test_a_stopping_runner_does_not_retry_on_a_new_session(
    config_dir: str, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Shutdown closes the sessions too, after it has cancelled the workers. A retry then would start
    a worker process nothing is left to reap, so a stopping runner raises instead."""
    runner = _runner(config_dir, store)
    seen: list[Any] = []
    monkeypatch.setattr(
        wiring_runner,
        "route_only",
        _closing(route_only, runner, asyncio.get_running_loop(), seen),
    )
    await store.enqueue_ingress(
        channel_id="IB_RACE", raw=RAW, control_id="RACE0001", message_type="ADT^A01"
    )
    item = await store.claim_next_fifo("IB_RACE", stage=Stage.INGRESS.value)
    assert item is not None
    runner._stop.set()

    with pytest.raises(SandboxSessionClosed):
        await runner._process_ingress_item("IB_RACE", item)

    assert len(seen) == 1
    assert runner._sandbox_sessions == {}
