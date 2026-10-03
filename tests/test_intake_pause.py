# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runtime intake pause (BACKLOG #290, slice 2, ASVS 15.2.2).

Two bounds hold one engine-wide gate: the opt-in staged-backlog depth bound
(``[inbound].max_staged_depth``, off by default per owner ruling R1 of 2026-09-27) and the SQLite
low-disk floor (``[retention].min_free_disk_mb``, on by default since slice 1). The pause is
backpressure only, so the load-bearing tests here are the ZERO-LOSS ones: every message a sender
offers during a pause arrives, in order, once the pause ends -- and on the runner path it is
persisted too.

Every disk test fakes ``shutil.disk_usage``; none fills or measures a real disk.
"""

from __future__ import annotations

import asyncio
import logging
import shutil
from pathlib import Path
from typing import Any, NamedTuple, cast

import pytest
from pydantic import ValidationError

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.settings import InboundSettings, RetentionSettings, StoreBackend
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline import intake_bound
from messagefoundry.pipeline.engine import Engine
from messagefoundry.pipeline.intake_bound import (
    DEPTH_REASON,
    DISK_REASON,
    IntakeBoundMonitor,
    depth_resume_at,
    disk_resume_at,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore, Stage, Store
from messagefoundry.transports.base import IntakeGate, SourceConnector, wait_for_intake
from messagefoundry.transports.database import DatabaseSource
from messagefoundry.transports.file import FileSource
from messagefoundry.transports.http_listener import HttpSource
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source

MIB = 1 << 20
_STX, _ETX = 0x02, 0x03
#: Long enough that a listener which ignored the gate would have read and handled every frame.
_PAUSED_WINDOW = 0.6
ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|{cid}|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


# --- the gate ------------------------------------------------------------------------------------


def test_a_gate_opens_only_when_every_reason_is_released() -> None:
    gate = IntakeGate()
    assert gate.is_open
    assert gate.hold(DEPTH_REASON) is True
    assert gate.hold(DEPTH_REASON) is False, "a second hold of the same reason is not a new pause"
    assert gate.hold(DISK_REASON) is True
    assert gate.release(DEPTH_REASON) is True
    assert not gate.is_open, "a drained backlog must not reopen intake while the disk is low"
    assert gate.release(DISK_REASON) is True
    assert gate.is_open
    assert gate.release(DISK_REASON) is False


async def test_a_paused_waiter_returns_false_when_its_source_stops() -> None:
    gate = IntakeGate()
    gate.hold(DEPTH_REASON)
    stopping = False

    async def stop_soon() -> None:
        nonlocal stopping
        await asyncio.sleep(0.05)
        stopping = True

    stopper = asyncio.create_task(stop_soon())
    assert await wait_for_intake(gate, stopped=lambda: stopping, poll_seconds=0.01) is False
    await stopper


async def test_no_gate_and_an_open_gate_never_wait() -> None:
    assert await wait_for_intake(None, stopped=lambda: True) is True
    assert await wait_for_intake(IntakeGate(), stopped=lambda: True) is True


async def test_the_runner_injects_no_gate_unless_given_one(tmp_path: Path) -> None:
    assert SourceConnector.intake_gate is None
    store = await MessageStore.open(tmp_path / "nogate.db")
    try:
        runner = RegistryRunner(_tcp_registry(), store)
        await runner.start()
        try:
            assert runner._sources["IB_T_ADT"].intake_gate is None
        finally:
            await asyncio.wait_for(runner.stop(), timeout=10.0)
    finally:
        await store.close()


def _tcp_registry() -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_T_ADT",
            ConnectionSpec(
                ConnectorType.TCP, {"host": "127.0.0.1", "port": 0, "framing": "stx_etx"}
            ),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


# --- the depth bound -----------------------------------------------------------------------------


def test_the_depth_bound_ships_off() -> None:
    assert InboundSettings().max_staged_depth == 0


def test_a_negative_depth_bound_is_refused_at_load() -> None:
    with pytest.raises(ValidationError):
        InboundSettings(max_staged_depth=-1)


@pytest.mark.parametrize(("bound", "resume"), [(1, 0), (2, 1), (10, 9), (1000, 900)])
def test_depth_resumes_below_the_bound(bound: int, resume: int) -> None:
    assert depth_resume_at(bound) == resume


class _FakeStore:
    """Only what the monitor reads. ``backend``/``path`` decide whether the disk floor applies."""

    def __init__(
        self, *, depth: int = 0, backend: StoreBackend = StoreBackend.SQLITE, path: str = ":memory:"
    ) -> None:
        self.depth = depth
        self.backend = backend
        self.path = path
        self.fail = False

    async def staged_intake_depth(self, *, limit: int | None = None) -> int:
        if self.fail:
            raise RuntimeError("store unavailable")
        return self.depth if limit is None else min(self.depth, limit)


def _monitor(store: _FakeStore, gate: IntakeGate, **kw: Any) -> IntakeBoundMonitor:
    return IntakeBoundMonitor(cast(Store, store), gate, **kw)


def test_a_stock_monitor_on_an_in_memory_store_does_nothing() -> None:
    monitor = _monitor(_FakeStore(), IntakeGate(), min_free_disk_mb=1024)
    assert not monitor.depth_bound_on
    assert not monitor.disk_floor_on, "an in-memory store has no disk to measure"
    assert not monitor.enabled


async def test_the_depth_bound_pauses_and_resumes_with_hysteresis(
    caplog: pytest.LogCaptureFixture,
) -> None:
    store, gate = _FakeStore(depth=10), IntakeGate()
    monitor = _monitor(store, gate, max_staged_depth=10)
    await monitor.check_once()
    assert gate.is_open, "AT the bound is not over it"
    with caplog.at_level(logging.INFO, logger="messagefoundry.pipeline.intake_bound"):
        store.depth = 11
        await monitor.check_once()
        assert not gate.is_open
        assert any(r.levelno == logging.WARNING and "PAUSED" in r.message for r in caplog.records)
        # Between the resume line and the bound: still paused. This is the no-flap band.
        store.depth = 10
        await monitor.check_once()
        assert not gate.is_open, "a backlog hovering at the bound must not flap the pause"
        store.depth = 9
        await monitor.check_once()
        assert gate.is_open
        assert any(r.levelno == logging.INFO and "RESUMED" in r.message for r in caplog.records)


async def test_a_failed_depth_read_leaves_the_pause_as_it_was() -> None:
    store, gate = _FakeStore(depth=50), IntakeGate()
    monitor = _monitor(store, gate, max_staged_depth=10)
    await monitor.check_once()
    assert not gate.is_open
    store.fail = True
    await monitor.check_once()
    assert not gate.is_open, "an unreadable backlog is not evidence that it drained"
    store.fail, store.depth = False, 0
    await monitor.check_once()
    assert gate.is_open


async def test_a_hung_depth_read_times_out_instead_of_freezing_the_monitor(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(intake_bound, "PROBE_TIMEOUT_SECONDS", 0.05)
    store, gate = _FakeStore(depth=50), IntakeGate()
    monitor = _monitor(store, gate, max_staged_depth=10)
    await monitor.check_once()
    assert not gate.is_open

    async def hang(*, limit: int | None = None) -> int:
        await asyncio.sleep(3600)
        return 0

    monkeypatch.setattr(store, "staged_intake_depth", hang)
    await asyncio.wait_for(monitor.check_once(), 2.0)
    assert not gate.is_open, "a hung read is not evidence that the backlog drained"


async def test_stopping_the_monitor_opens_the_gate() -> None:
    store, gate = _FakeStore(depth=50), IntakeGate()
    monitor = _monitor(store, gate, max_staged_depth=10, check_seconds=0.01)
    monitor.start()
    for _ in range(100):
        if not gate.is_open:
            break
        await asyncio.sleep(0.01)
    assert not gate.is_open
    await monitor.stop()
    assert gate.is_open, "a stopped monitor cannot see the condition clear, so it must not hold it"


async def test_the_store_counts_ingress_and_routed_but_not_outbound(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "depth.db")
    try:
        assert await store.staged_intake_depth() == 0
        await store.enqueue_ingress(channel_id="c1", raw="x", now=0.0)
        await store.enqueue_ingress(channel_id="c2", raw="y", now=0.0)
        # One message moved on to the ROUTED stage, by the same handoff the router worker uses.
        mid = await store.enqueue_ingress(channel_id="c4", raw="r", now=0.0)
        ing = await store.claim_next_fifo("c4", stage=Stage.INGRESS.value)
        assert ing is not None
        assert await store.route_handoff(
            ingress_id=ing.id,
            message_id=mid,
            channel_id="c4",
            handlers=[("h", "r")],
            disposition=MessageStatus.ROUTED,
        )
        await store.enqueue_message(channel_id="c3", raw="z", deliveries=[("d1", "p1")], now=0.0)
        assert await store.in_pipeline_depth() == 4, "control: the outbound row is really there"
        assert await store.staged_intake_depth() == 3, "2 ingress + 1 routed, never the outbound"
        # Capped: the pause only asks "over the bound or not".
        assert await store.staged_intake_depth(limit=2) == 2
        assert await store.staged_intake_depth(limit=10) == 3
    finally:
        await store.close()


# --- the disk floor ------------------------------------------------------------------------------


class _Usage(NamedTuple):
    total: int
    used: int
    free: int


class _Disk:
    def __init__(self, free_mib: float) -> None:
        self.free_mib = free_mib
        self.calls = 0

    def __call__(self, path: object) -> _Usage:
        self.calls += 1
        free = int(self.free_mib * MIB)
        return _Usage(total=1 << 40, used=(1 << 40) - free, free=free)


async def test_the_disk_floor_pauses_a_sqlite_store_with_hysteresis(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    disk = _Disk(free_mib=2048)
    monkeypatch.setattr(shutil, "disk_usage", disk)
    gate = IntakeGate()
    monitor = _monitor(_FakeStore(path=str(tmp_path / "s.db")), gate, min_free_disk_mb=1024)
    assert monitor.disk_floor_on and not monitor.depth_bound_on
    await monitor.check_once()
    assert gate.is_open
    disk.free_mib = 1023
    await monitor.check_once()
    assert gate.reasons == {DISK_REASON}
    # Back over the floor but inside the band: still paused.
    disk.free_mib = 1100
    await monitor.check_once()
    assert not gate.is_open
    disk.free_mib = disk_resume_at(1024 * MIB) / MIB
    await monitor.check_once()
    assert gate.is_open
    assert disk.calls == 4


@pytest.mark.parametrize("backend", [StoreBackend.POSTGRES, StoreBackend.SQLSERVER])
async def test_the_disk_floor_never_applies_to_a_server_backend(
    backend: StoreBackend, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    disk = _Disk(free_mib=1)
    monkeypatch.setattr(shutil, "disk_usage", disk)
    gate = IntakeGate()
    monitor = _monitor(
        _FakeStore(backend=backend, path=str(tmp_path / "s.db")), gate, min_free_disk_mb=1024
    )
    assert not monitor.disk_floor_on
    await monitor.check_once()
    assert gate.is_open and disk.calls == 0


async def test_a_failed_disk_probe_does_not_pause(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    def broken(path: object) -> _Usage:
        raise OSError("probe failed")

    monkeypatch.setattr(shutil, "disk_usage", broken)
    gate = IntakeGate()
    monitor = _monitor(_FakeStore(path=str(tmp_path / "s.db")), gate, min_free_disk_mb=1024)
    await monitor.check_once()
    assert gate.is_open, "an unmeasured disk is not a low one"


# --- zero loss on the listeners ------------------------------------------------------------------


def _tcp_frame(payload: str) -> bytes:
    return bytes([_STX]) + payload.encode("utf-8") + bytes([_ETX])


def _isa(control: str) -> str:
    el = "*"
    segment = el.join(
        [
            "ISA",
            "00",
            " " * 10,
            "00",
            " " * 10,
            "ZZ",
            "SENDERID".ljust(15),
            "ZZ",
            "RECEIVERID".ljust(15),
            "240101",
            "1200",
            "^",
            "00501",
            control,
            "0",
            "P",
            ":",
        ]
    )
    assert len(segment) == 105
    return segment + "~"


def _interchange(control: str) -> bytes:
    return (
        _isa(control)
        + "GS*HS*SAPP*RAPP*20240101*1200*1*X*005010X279A1~"
        + "ST*270*0001~"
        + "BHT*0022*13*10001234*20240101*1200~"
        + "HL*1**20*1~"
        + "SE*4*0001~"
        + "GE*1*1~"
        + f"IEA*1*{control}~"
    ).encode("utf-8")


async def _stream_through_a_pause(src: TcpSource | X12Source, frames: list[bytes]) -> list[bytes]:
    """Send every frame while the gate is held, prove nothing was read, then release it."""
    gate = IntakeGate()
    gate.hold(DEPTH_REASON)
    src.intake_gate = gate
    seen: list[bytes] = []
    done = asyncio.Event()

    async def handler(raw: bytes) -> None:
        seen.append(raw)
        if len(seen) == len(frames):
            done.set()

    await src.start(handler)
    _reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
    try:
        for chunk in frames:
            writer.write(chunk)
        await writer.drain()
        await asyncio.sleep(_PAUSED_WINDOW)
        assert seen == [], "a paused listener read and handled a message"
        gate.release(DEPTH_REASON)
        await asyncio.wait_for(done.wait(), 10.0)
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        await asyncio.wait_for(src.stop(), timeout=5.0)
    return seen


async def test_a_paused_tcp_listener_loses_nothing() -> None:
    src = TcpSource(
        Source(
            name="IB_TCP",
            type=ConnectorType.TCP,
            settings={"host": "127.0.0.1", "port": 0, "framing": "stx_etx"},
        )
    )
    seen = await _stream_through_a_pause(src, [_tcp_frame(f"MSG-{i}") for i in range(5)])
    assert [b.decode() for b in seen] == [f"MSG-{i}" for i in range(5)]


async def test_a_paused_x12_listener_loses_nothing() -> None:
    src = X12Source(
        Source(name="IB_X12", type=ConnectorType.X12, settings={"host": "127.0.0.1", "port": 0})
    )
    seen = await _stream_through_a_pause(src, [_interchange(f"{i:09d}") for i in range(4)])
    assert [b.decode("utf-8")[90:99] for b in seen] == [f"{i:09d}" for i in range(4)]


async def test_a_paused_tcp_listener_still_stops_promptly() -> None:
    src = TcpSource(
        Source(
            name="IB_TCP",
            type=ConnectorType.TCP,
            settings={"host": "127.0.0.1", "port": 0, "framing": "stx_etx"},
        )
    )
    gate = IntakeGate()
    gate.hold(DISK_REASON)
    src.intake_gate = gate

    async def handler(raw: bytes) -> None:
        raise AssertionError("nothing may be read while paused")

    await src.start(handler)
    _reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
    try:
        writer.write(_tcp_frame("MSG"))
        await writer.drain()
        await asyncio.sleep(0.1)
        loop = asyncio.get_running_loop()
        began = loop.time()
        await asyncio.wait_for(src.stop(), timeout=5.0)
        assert loop.time() - began < 2.0, "a paused connection held stop() for its whole grace"
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)


async def test_a_peer_that_closes_during_a_pause_frees_its_slot() -> None:
    src = TcpSource(
        Source(
            name="IB_TCP",
            type=ConnectorType.TCP,
            settings={"host": "127.0.0.1", "port": 0, "framing": "stx_etx"},
        )
    )
    gate = IntakeGate()
    gate.hold(DEPTH_REASON)
    src.intake_gate = gate

    async def handler(raw: bytes) -> None:
        raise AssertionError("nothing was sent")

    await src.start(handler)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        for _ in range(100):
            if src._admission.active == 1:
                break
            await asyncio.sleep(0.02)
        assert src._admission.active == 1
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        for _ in range(150):
            if src._admission.active == 0:
                break
            await asyncio.sleep(0.02)
        assert src._admission.active == 0, (
            "a closed peer kept its max_connections slot for the whole pause"
        )
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)


async def _post(port: int, body: bytes) -> int:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    try:
        head = ["POST /ingest HTTP/1.1", "Host: localhost", f"Content-Length: {len(body)}", "", ""]
        writer.write("\r\n".join(head).encode("ascii") + body)
        await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), 10.0)
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
    return int(data.split(b" ", 2)[1])


async def test_a_paused_http_listener_withholds_the_read_and_then_serves_every_post() -> None:
    src = HttpSource(
        Source(name="IB_HTTP", type=ConnectorType.HTTP, settings={"host": "127.0.0.1", "port": 0})
    )
    gate = IntakeGate()
    gate.hold(DEPTH_REASON)
    src.intake_gate = gate
    seen: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        seen.append(raw)
        return f"msg-{len(seen)}"

    await src.start(handler)
    try:
        posts = [asyncio.create_task(_post(src.sockport, f"BODY-{i}".encode())) for i in range(3)]
        await asyncio.sleep(_PAUSED_WINDOW)
        assert seen == [], "a paused HTTP listener handed a body to the pipeline"
        assert not any(p.done() for p in posts), "a paused listener answered a request"
        gate.release(DEPTH_REASON)
        statuses = await asyncio.wait_for(asyncio.gather(*posts), 10.0)
        assert statuses == [202, 202, 202]
        assert sorted(seen) == [b"BODY-0", b"BODY-1", b"BODY-2"]
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)


# --- the poll sources ----------------------------------------------------------------------------


async def test_a_paused_file_source_leaves_the_file_until_resume(tmp_path: Path) -> None:
    inbox = tmp_path / "in"
    inbox.mkdir()
    (inbox / "m.hl7").write_bytes(ADT.format(cid="F1").encode("utf-8"))
    src = FileSource(
        Source(
            type=ConnectorType.FILE,
            settings={"directory": str(inbox), "after_read": "delete", "poll_seconds": 0.05},
        )
    )
    gate = IntakeGate()
    gate.hold(DISK_REASON)
    src.intake_gate = gate
    seen: list[bytes] = []

    async def handler(raw: bytes) -> None:
        seen.append(raw)

    await src.start(handler)
    try:
        await asyncio.sleep(_PAUSED_WINDOW)
        assert seen == [] and (inbox / "m.hl7").exists(), "a paused poll source took the file"
        gate.release(DISK_REASON)
        for _ in range(200):
            if seen:
                break
            await asyncio.sleep(0.05)
        assert len(seen) == 1
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)


async def test_a_paused_database_source_does_not_poll(monkeypatch: pytest.MonkeyPatch) -> None:
    src = DatabaseSource(
        Source(
            name="IB_DB",
            type=ConnectorType.DATABASE,
            settings={
                "server": "db.example",
                "dialect": "generic",
                "odbc_driver": "PostgreSQL Unicode",
                "poll_statement": "SELECT 1",
                "poll_seconds": 0.05,
            },
        )
    )
    polls = 0

    async def fake_poll_once() -> None:
        nonlocal polls
        polls += 1

    monkeypatch.setattr(src, "_poll_once", fake_poll_once)
    gate = IntakeGate()
    gate.hold(DEPTH_REASON)
    src.intake_gate = gate

    async def handler(raw: bytes) -> None:
        return None

    await src.start(handler)
    try:
        await asyncio.sleep(0.3)
        assert polls == 0, "a paused DATABASE source ran poll_statement"
        gate.release(DEPTH_REASON)
        for _ in range(100):
            if polls:
                break
            await asyncio.sleep(0.02)
        assert polls >= 1
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)


# --- the engine: one gate, the floor on by default, the depth bound off --------------------------


async def test_the_engine_pauses_intake_on_low_disk_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(shutil, "disk_usage", _Disk(free_mib=10))
    engine = await Engine.create(tmp_path / "engine.db", retention_settings=RetentionSettings())
    await engine.start()
    try:
        monitor = engine._intake_monitor
        assert monitor is not None and monitor.disk_floor_on
        assert not monitor.depth_bound_on, "the depth bound must stay opt-in"
        for _ in range(100):
            if not engine._intake_gate.is_open:
                break
            await asyncio.sleep(0.02)
        assert engine._intake_gate.reasons == {DISK_REASON}
    finally:
        await engine.stop()
    assert engine._intake_gate.is_open, "a stopped engine left intake paused"


async def test_an_engine_without_retention_settings_never_pauses(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    disk = _Disk(free_mib=10)
    monkeypatch.setattr(shutil, "disk_usage", disk)
    engine = await Engine.create(tmp_path / "engine2.db")
    await engine.start()
    try:
        monitor = engine._intake_monitor
        assert monitor is not None and not monitor.enabled
        await asyncio.sleep(0.1)
        assert engine._intake_gate.is_open and disk.calls == 0
    finally:
        await engine.stop()


# --- through the real seam: the runner injects the gate, and the messages are persisted ----------


async def test_messages_sent_during_a_pause_are_all_persisted_after_resume(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "pause.db")
    gate = IntakeGate()
    gate.hold(DEPTH_REASON)
    try:
        runner = RegistryRunner(_tcp_registry(), store, intake_gate=gate)
        await runner.start()
        try:
            source = runner._sources["IB_T_ADT"]
            assert source.intake_gate is gate, "the runner did not inject the engine's gate"
            port = source.sockport  # type: ignore[attr-defined]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            for i in range(3):
                writer.write(_tcp_frame(ADT.format(cid=f"P{i}")))
            await writer.drain()
            await asyncio.sleep(_PAUSED_WINDOW)
            assert await store.count_messages() == 0, "a paused listener committed a message"
            gate.release(DEPTH_REASON)
            for _ in range(200):
                if await store.count_messages() == 3:
                    break
                await asyncio.sleep(0.05)
            assert await store.count_messages() == 3, "a message offered during the pause was lost"
            writer.close()
            await asyncio.gather(writer.wait_closed(), return_exceptions=True)
            del reader
        finally:
            await asyncio.wait_for(runner.stop(), timeout=10.0)
    finally:
        await store.close()
