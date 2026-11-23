# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A reload landing while an inline row's Router runs (BACKLOG #5707, limb A).

The router worker reads the inline gates, awaits the Router, then runs the inline transform. A
reload during that await used to pair gates computed for the old graph with the new graph, so a
handler that now calls ``db_lookup`` ran with no lookup runner and was dead-lettered.

Every test holds the Router on its worker thread and runs a real :meth:`RegistryRunner.reload`
meanwhile. Synthetic HL7 only; the lookup executor's query is stubbed, so no database is reached.
"""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Callable, Mapping
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.db_lookup import db_lookup
from messagefoundry.config.models import ConnectorType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    ConnectionSpec,
    DatabaseLookupSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage
from messagefoundry.transports.database import DatabaseLookupExecutor
from messagefoundry.transports.file import FileDestination

_TERMINAL = {MessageStatus.PROCESSED.value, MessageStatus.ERROR.value}


def _hl7(control_id: str) -> str:
    return (
        f"MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||ADT^A01|{control_id}|P|2.5.1\r"
        "PID|1||100^^^H^MR||DOE^JANE\r"
    )


class _Gate:
    """Holds the Router's first ``holds`` calls until the test releases each one."""

    def __init__(self, holds: int = 1) -> None:
        self.holds = holds
        self.calls = 0
        self.entered = threading.Semaphore(0)
        self.resume = threading.Semaphore(0)
        self._lock = threading.Lock()

    def pause(self) -> None:
        with self._lock:
            self.calls += 1
            hold = self.calls <= self.holds
        if hold:
            self.entered.release()
            assert self.resume.acquire(timeout=60), "the test never released the Router"

    async def reached(self) -> None:
        assert await asyncio.to_thread(self.entered.acquire, True, 60), "the Router never ran"

    def release(self) -> None:
        self.resume.release()


def _deliver(msg: Message) -> Send:
    return Send("file_out", msg)


def _graph(
    root: Path,
    route: Any,
    *,
    handler: Any = _deliver,
    with_lookup: bool = False,
) -> Registry:
    reg = Registry()
    reg.add_outbound(
        OutboundConnection(
            "file_out",
            ConnectionSpec(
                ConnectorType.FILE, {"directory": str(root / "out"), "filename": "{MSH-10}.hl7"}
            ),
        )
    )
    reg.add_inbound(
        InboundConnection(
            "file_in",
            ConnectionSpec(
                ConnectorType.FILE,
                {"directory": str(root / "in"), "pattern": "*.hl7", "poll_seconds": 0.05},
            ),
            router="r",
            inline=True,
        )
    )
    reg.add_router("r", route)
    reg.add_handler("h", handler)
    if with_lookup:
        reg.add_lookup(
            DatabaseLookupSpec(name="clarity", settings={"server": "db.local", "database": "C"})
        )
    return reg


def _without_inbound(reg: Registry) -> Registry:
    del reg.inbound["file_in"]
    return reg


def _gated(gate: _Gate) -> Callable[[Message], list[str]]:
    def route(_msg: Message) -> list[str]:
        gate.pause()
        return ["h"]

    return route


def _plain(_msg: Message) -> list[str]:
    return ["h"]


def _uses_lookup(msg: Message) -> Send:
    db_lookup("clarity", "SELECT 1", {})
    return Send("file_out", msg)


@pytest.fixture
async def store(tmp_path: Path):
    (tmp_path / "in").mkdir()
    (tmp_path / "out").mkdir()
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


@pytest.fixture
def lookups(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    seen: list[str] = []

    async def query(
        _self: DatabaseLookupExecutor,
        connection: str,
        _statement: str,
        _params: Mapping[str, Any] | None,
    ) -> list[dict[str, Any]]:
        seen.append(connection)
        return []

    monkeypatch.setattr(DatabaseLookupExecutor, "query", query)
    return seen


async def _start(reg: Registry, store: MessageStore) -> RegistryRunner:
    runner = RegistryRunner(
        reg, store, poll_interval=0.02, egress=EgressSettings(deny_by_default=False)
    )
    await runner.start()
    return runner


async def _enqueue(runner: RegistryRunner, store: MessageStore, control_id: str) -> str:
    mid = await store.enqueue_ingress(
        channel_id="file_in",
        raw=_hl7(control_id),
        control_id=control_id,
        message_type="ADT^A01",
    )
    runner._wake_lane(Stage.INGRESS, "file_in")
    return mid


async def _status(store: MessageStore, mid: str) -> str:
    row = await store.get_message(mid)
    assert row is not None
    return str(row["status"])


async def _settled(store: MessageStore, mid: str, timeout: float = 20.0) -> str:
    deadline = asyncio.get_running_loop().time() + timeout
    while asyncio.get_running_loop().time() < deadline:
        status = await _status(store, mid)
        if status in _TERMINAL:
            return status
        await asyncio.sleep(0.02)
    return await _status(store, mid)


async def _delivered(root: Path, control_id: str, timeout: float = 10.0) -> bool:
    deadline = asyncio.get_running_loop().time() + timeout
    path = root / "out" / f"{control_id}.hl7"
    while asyncio.get_running_loop().time() < deadline:
        if path.exists():
            return True
        await asyncio.sleep(0.02)
    return path.exists()


async def test_a_handler_that_now_uses_a_lookup_is_not_dead_lettered(
    store: MessageStore, tmp_path: Path, lookups: list[str]
) -> None:
    gate = _Gate()
    runner = await _start(_graph(tmp_path, _gated(gate)), store)
    try:
        mid = await _enqueue(runner, store, "LOOKUP1")
        await gate.reached()
        await runner.reload(_graph(tmp_path, _plain, handler=_uses_lookup, with_lookup=True))
        gate.release()
        assert await _settled(store, mid) == MessageStatus.PROCESSED.value
        assert lookups == ["clarity"]
    finally:
        gate.release()
        await runner.stop()


async def test_a_row_behind_the_reloaded_row_is_delivered_after_it(
    store: MessageStore,
    tmp_path: Path,
    lookups: list[str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    order: list[str] = []
    real_send = FileDestination.send

    async def send(self: FileDestination, payload: Any, *a: Any, **k: Any) -> Any:
        text = payload.decode() if isinstance(payload, bytes) else str(payload)
        order.append(text.split("|")[9])
        return await real_send(self, payload, *a, **k)

    monkeypatch.setattr(FileDestination, "send", send)
    gate = _Gate()
    runner = await _start(_graph(tmp_path, _gated(gate)), store)
    try:
        m1 = await _enqueue(runner, store, "ORDER1")
        await gate.reached()
        m2 = await _enqueue(runner, store, "ORDER2")
        await runner.reload(_graph(tmp_path, _plain, handler=_uses_lookup, with_lookup=True))
        gate.release()
        assert await _settled(store, m1) == MessageStatus.PROCESSED.value
        assert await _settled(store, m2) == MessageStatus.PROCESSED.value
        assert order == ["ORDER1", "ORDER2"]
    finally:
        gate.release()
        await runner.stop()


async def test_an_inbound_dropped_during_the_router_still_delivers(
    store: MessageStore, tmp_path: Path
) -> None:
    gate = _Gate()
    runner = await _start(_graph(tmp_path, _gated(gate)), store)
    try:
        mid = await _enqueue(runner, store, "DROP1")
        await gate.reached()
        await runner.reload(_without_inbound(_graph(tmp_path, _plain)))
        gate.release()
        assert await _settled(store, mid) == MessageStatus.PROCESSED.value
        assert await _delivered(tmp_path, "DROP1")
    finally:
        gate.release()
        await runner.stop()


async def test_a_reload_dropping_the_whole_feed_refuses_the_row(
    store: MessageStore, tmp_path: Path
) -> None:
    """The dropped-inbound case runs on the SERVED graph. Finishing it on the replaced graph was
    measured to deliver the row to the outbound the reload removed, where this refuses it."""
    gate = _Gate()
    runner = await _start(_graph(tmp_path, _gated(gate)), store)
    try:
        mid = await _enqueue(runner, store, "FEEDGONE")
        await gate.reached()
        await runner.reload(Registry())
        gate.release()
        assert await _settled(store, mid) == MessageStatus.ERROR.value
        cur = await store._db.execute(
            "SELECT COUNT(*) FROM queue WHERE stage = ?", (Stage.OUTBOUND.value,)
        )
        row = await cur.fetchone()
        assert row is not None and row[0] == 0, "an outbound row was committed"
        assert not (tmp_path / "out" / "FEEDGONE.hl7").exists()
    finally:
        gate.release()
        await runner.stop()


@pytest.mark.parametrize("restore_before_release", [True, False], ids=["both-held", "a-then-b"])
async def test_reload_a_drops_reload_b_restores_leaves_no_stopped_lane(
    restore_before_release: bool, store: MessageStore, tmp_path: Path
) -> None:
    gate = _Gate()
    runner = await _start(_graph(tmp_path, _gated(gate)), store)
    try:
        m1 = await _enqueue(runner, store, "AB1")
        await gate.reached()
        await runner.reload(_without_inbound(_graph(tmp_path, _plain)))
        if restore_before_release:
            await runner.reload(_graph(tmp_path, _plain))
            gate.release()
        else:
            gate.release()
            assert await _settled(store, m1) == MessageStatus.PROCESSED.value
            await runner.reload(_graph(tmp_path, _plain))
        assert await _settled(store, m1) == MessageStatus.PROCESSED.value
        # The lane is alive: a later message on the restored inbound completes too.
        m2 = await _enqueue(runner, store, "AB2")
        assert await _settled(store, m2) == MessageStatus.PROCESSED.value
    finally:
        gate.release()
        await runner.stop()


async def test_repeated_reloads_terminate_and_the_row_completes(
    store: MessageStore, tmp_path: Path
) -> None:
    passes = RegistryRunner._INGRESS_RELOAD_REPASSES + 1
    gate = _Gate(holds=passes)
    route = _gated(gate)
    runner = await _start(_graph(tmp_path, route), store)
    try:
        mid = await _enqueue(runner, store, "REPEAT1")
        for _ in range(passes):
            await gate.reached()
            await runner.reload(_graph(tmp_path, route))
            gate.release()
        assert await _settled(store, mid) == MessageStatus.PROCESSED.value
        # An uncapped restart would make one more, unheld, Router call after the last reload.
        assert gate.calls == passes
    finally:
        for _ in range(passes):
            gate.release()
        await runner.stop()


class _Kill(BaseException):
    """Escapes every ``except Exception``, as a process-level fault in user code does."""


async def test_a_worker_death_on_the_second_pass_is_counted_once(
    store: MessageStore, tmp_path: Path
) -> None:
    gate = _Gate()
    killed = threading.Event()

    def second(_msg: Message) -> list[str]:
        if not killed.is_set():
            killed.set()
            raise _Kill
        return ["h"]

    runner = await _start(_graph(tmp_path, _gated(gate)), store)
    deaths: list[str] = []
    real = runner._record_worker_death

    async def counted(worker: str, name: str, item: Any, exc: BaseException) -> None:
        deaths.append(item.id)
        await real(worker, name, item, exc)

    runner._record_worker_death = counted  # type: ignore[method-assign]
    try:
        mid = await _enqueue(runner, store, "DEATH1")
        await gate.reached()
        await runner.reload(_graph(tmp_path, second))
        gate.release()
        for _ in range(500):
            if deaths:
                break
            await asyncio.sleep(0.02)
        assert killed.is_set()
        await asyncio.sleep(0.1)  # a second count, were there one, would land here
        assert len(deaths) == 1
        cur = await store._db.execute(
            "SELECT worker_deaths FROM queue WHERE message_id = ? AND stage = ?",
            (mid, Stage.INGRESS.value),
        )
        row = await cur.fetchone()
        assert row is not None and row[0] == 1
    finally:
        gate.release()
        await runner.stop()
