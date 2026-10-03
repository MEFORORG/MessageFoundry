# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The runtime intake pause on the MLLP listener, the DICOM SCP and the timer (BACKLOG #290).

Slice 2 (``tests/test_intake_pause.py``) covered tcp, x12, http and the pollers. This file covers
the three families it left out. Each pauses in the way its protocol allows:

* MLLP waits before its next socket read, exactly like tcp and x12, so a paused sender's bytes stay
  unread, and a frame already read is still committed and ACKed as before;
* the DICOM SCP refuses each NEW association with DICOM's "busy, retry later", while an association
  it already accepted finishes normally;
* the timer skips its tick, like the pollers.

Every gate here is a plain :class:`IntakeGate` held and released by the test. No network is used
beyond loopback.
"""

from __future__ import annotations

import asyncio
import contextlib
import threading
from collections.abc import Callable
from datetime import datetime, timedelta
from io import BytesIO
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.intake_bound import DEPTH_REASON, DISK_REASON
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.transports import timer as timer_mod
from messagefoundry.transports.base import IntakeGate
from messagefoundry.transports.mllp import CR, EB, MLLPSource, frame
from messagefoundry.transports.timer import TimerSource

#: Long enough that a source which ignored the gate would have read, fired or handled everything.
_PAUSED_WINDOW = 0.6
_ADT = "MSH|^~\\&|S|F|R|RF|20260101||ADT^A01|{cid}|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


async def _eventually(predicate: Callable[[], bool], timeout: float = 5.0) -> bool:
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while loop.time() < deadline:
        if predicate():
            return True
        await asyncio.sleep(0.02)
    return predicate()


def _held(reason: str = DEPTH_REASON) -> IntakeGate:
    gate = IntakeGate()
    gate.hold(reason)
    return gate


# --- MLLP ----------------------------------------------------------------------------------------


def _mllp(**settings: object) -> MLLPSource:
    return MLLPSource(
        Source(
            name="IB_MLLP",
            type=ConnectorType.MLLP,
            settings={"host": "127.0.0.1", "port": 0, **settings},
        )
    )


async def _read_reply(reader: asyncio.StreamReader, timeout: float = 5.0) -> bytes:
    """One framed reply through its trailing CR, or ``b""`` if the listener closed instead."""
    with contextlib.suppress(ConnectionResetError, asyncio.IncompleteReadError):
        return await asyncio.wait_for(reader.readuntil(bytes([EB, CR])), timeout)
    return b""


async def test_a_paused_mllp_listener_reads_nothing_then_handles_and_acks_every_frame() -> None:
    src = _mllp()
    gate = _held()
    src.intake_gate = gate
    seen: list[str] = []

    async def handler(raw: bytes) -> str:
        seen.append(raw.decode("utf-8"))
        return f"ACK-{len(seen)}"

    await src.start(handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
    try:
        messages = [_ADT.format(cid=f"M{i}") for i in range(5)]
        for message in messages:
            writer.write(frame(message))
        await writer.drain()
        await asyncio.sleep(_PAUSED_WINDOW)
        assert seen == [], "a paused MLLP listener read and handled a frame"
        gate.release(DEPTH_REASON)
        replies = [await _read_reply(reader) for _ in messages]
        assert seen == messages, "a frame offered during the pause was lost or reordered"
        assert replies == [frame(f"ACK-{i}") for i in range(1, 6)], "every frame gets its ACK"
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        await asyncio.wait_for(src.stop(), timeout=5.0)


async def test_a_pause_does_not_spend_a_partial_frames_budget() -> None:
    # The handler holds the gate as it handles the first frame, the way the monitor could between
    # two reads. The second frame is half-read at that moment, and its max_frame_seconds budget
    # must not run while the ENGINE declines to read.
    src = _mllp(max_frame_seconds=0.3)
    gate = IntakeGate()
    src.intake_gate = gate
    seen: list[str] = []

    async def handler(raw: bytes) -> str:
        seen.append(raw.decode("utf-8"))
        if len(seen) == 1:
            gate.hold(DEPTH_REASON)
        return f"ACK-{len(seen)}"

    await src.start(handler)
    reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
    try:
        second = frame(_ADT.format(cid="M2"))
        writer.write(frame(_ADT.format(cid="M1")) + second[:20])
        await writer.drain()
        assert await _read_reply(reader) == frame("ACK-1")
        await asyncio.sleep(_PAUSED_WINDOW)  # twice the frame budget
        assert len(seen) == 1
        gate.release(DEPTH_REASON)
        writer.write(second[20:])
        await writer.drain()
        assert await _read_reply(reader) == frame("ACK-2"), "the paused frame was dropped"
        assert seen[1] == _ADT.format(cid="M2")
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        await asyncio.wait_for(src.stop(), timeout=5.0)


async def test_a_paused_mllp_listener_still_stops_promptly() -> None:
    src = _mllp()
    src.intake_gate = _held(DISK_REASON)

    async def handler(raw: bytes) -> str:
        raise AssertionError("nothing may be read while paused")

    await src.start(handler)
    _reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
    try:
        writer.write(frame(_ADT.format(cid="M1")))
        await writer.drain()
        assert await _eventually(lambda: src._admission.active == 1)
        loop = asyncio.get_running_loop()
        began = loop.time()
        await asyncio.wait_for(src.stop(), timeout=5.0)
        # The shutdown grace is 5 s; a paused connection sees stop() within one 1 s poll.
        assert loop.time() - began < 3.5, "a paused connection held stop() for its whole grace"
    finally:
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)


async def test_an_mllp_peer_that_closes_during_a_pause_frees_its_slot() -> None:
    src = _mllp()
    src.intake_gate = _held()

    async def handler(raw: bytes) -> str:
        raise AssertionError("nothing was sent")

    await src.start(handler)
    try:
        _reader, writer = await asyncio.open_connection("127.0.0.1", src.sockport)
        assert await _eventually(lambda: src._admission.active == 1)
        writer.close()
        await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        assert await _eventually(lambda: src._admission.active == 0), "a closed peer kept its slot"
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)


def _mllp_registry() -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_M_ADT",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


async def test_mllp_messages_sent_during_a_pause_are_all_persisted_and_acked(
    tmp_path: Path,
) -> None:
    store = await MessageStore.open(tmp_path / "mllp-pause.db")
    gate = _held()
    try:
        runner = RegistryRunner(_mllp_registry(), store, intake_gate=gate)
        await runner.start()
        try:
            source = runner._sources["IB_M_ADT"]
            assert source.intake_gate is gate, "the runner did not inject the engine's gate"
            port = source.sockport  # type: ignore[attr-defined]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            try:
                for i in range(3):
                    writer.write(frame(_ADT.format(cid=f"P{i}")))
                await writer.drain()
                await asyncio.sleep(_PAUSED_WINDOW)
                assert await store.count_messages() == 0, "a paused listener committed a message"
                gate.release(DEPTH_REASON)
                replies = [await _read_reply(reader) for _ in range(3)]
                assert all(b"MSA|AA|" in reply for reply in replies), replies
                # Each ACK follows its commit, so all three are durable once the ACKs are in.
                assert await store.count_messages() == 3, "a message sent during the pause was lost"
            finally:
                writer.close()
                await asyncio.gather(writer.wait_closed(), return_exceptions=True)
        finally:
            await asyncio.wait_for(runner.stop(), timeout=10.0)
    finally:
        await store.close()


# --- DICOM SCP -----------------------------------------------------------------------------------

_SCP_AE = "MEFOR_SCP"


def _dicom_deps() -> None:
    pytest.importorskip("pydicom", reason="DICOM SCP tests need the [dicom] extra")
    pytest.importorskip("pynetdicom", reason="DICOM SCP tests need the [dicom] extra")


def _scp(**settings: object) -> Any:
    from messagefoundry.transports.dicom import DicomScpSource

    return DicomScpSource(
        Source(
            name="IB_DICOM",
            type=ConnectorType.DIMSE,
            settings={"ae_title": _SCP_AE, "host": "127.0.0.1", "port": 0, **settings},
        )
    )


def _object() -> bytes:
    from tests._dicom_sample import make_sr_part10

    return make_sr_part10()


class _Outcome:
    """What one blocking SCU association saw: established or not, the RJ fields, the C-STORE status."""

    def __init__(self) -> None:
        self.established = False
        self.rejection: tuple[int, int, int] | None = None
        self.status: int | None = None


def _associate(
    port: int, data: bytes, *, calling_ae: str = "MODALITY1"
) -> tuple[Any, Any, _Outcome]:
    from pydicom import dcmread
    from pynetdicom import AE

    ds = dcmread(BytesIO(data))
    ae = AE(ae_title=calling_ae)
    ae.add_requested_context(ds.SOPClassUID, ds.file_meta.TransferSyntaxUID)
    assoc = ae.associate("127.0.0.1", port, ae_title=_SCP_AE)
    outcome = _Outcome()
    outcome.established = bool(assoc.is_established)
    if assoc.is_rejected:
        rj: Any = assoc.acceptor.primitive
        assert rj is not None, "a rejected association carries its A-ASSOCIATE-RJ primitive"
        outcome.rejection = (int(rj.result), int(rj.result_source), int(rj.diagnostic))
    return assoc, ds, outcome


def _store_once(port: int, data: bytes, *, calling_ae: str = "MODALITY1") -> _Outcome:
    assoc, ds, outcome = _associate(port, data, calling_ae=calling_ae)
    if outcome.established:
        try:
            outcome.status = int(assoc.send_c_store(ds).Status)
        finally:
            assoc.release()
    return outcome


def _capture(captured: list[bytes]) -> Callable[[bytes], Any]:
    async def handler(data: bytes) -> str | None:
        # Mimics the runner's receipt handler: durably "commit", then return the message id.
        captured.append(data)
        return f"mid-{len(captured)}"

    return handler


async def test_a_paused_scp_refuses_a_new_association_as_busy_retry_later() -> None:
    _dicom_deps()
    captured: list[bytes] = []
    scp = _scp()
    scp.intake_gate = _held()
    await scp.start(_capture(captured))
    try:
        outcome = await asyncio.to_thread(_store_once, scp.sockport, _object())
        assert outcome.established is False
        # rejected-transient (2), service provider presentation (3), temporary congestion (1).
        assert outcome.rejection == (0x02, 0x03, 0x01), outcome.rejection
        assert captured == [], "a refused association must not reach the ingress"
    finally:
        await asyncio.wait_for(scp.stop(), timeout=15.0)


async def test_an_object_refused_during_a_pause_is_committed_when_resent_after_resume() -> None:
    _dicom_deps()
    captured: list[bytes] = []
    scp = _scp()
    gate = _held(DISK_REASON)
    scp.intake_gate = gate
    await scp.start(_capture(captured))
    try:
        data = _object()
        refused = await asyncio.to_thread(_store_once, scp.sockport, data)
        assert refused.rejection is not None and captured == []
        gate.release(DISK_REASON)
        resent = await asyncio.to_thread(_store_once, scp.sockport, data)
        assert resent.established and resent.status == 0x0000
        assert len(captured) == 1, "the object the sender retried was not committed"
    finally:
        await asyncio.wait_for(scp.stop(), timeout=15.0)


async def test_an_association_accepted_before_a_pause_finishes_normally() -> None:
    _dicom_deps()
    captured: list[bytes] = []
    scp = _scp()
    gate = IntakeGate()
    scp.intake_gate = gate
    await scp.start(_capture(captured))
    associated, go = threading.Event(), threading.Event()
    data = _object()

    def in_flight() -> _Outcome:
        assoc, ds, outcome = _associate(scp.sockport, data)
        associated.set()
        if not outcome.established:
            return outcome
        try:
            assert go.wait(10.0)
            outcome.status = int(assoc.send_c_store(ds).Status)
        finally:
            assoc.release()
        return outcome

    try:
        first = asyncio.create_task(asyncio.to_thread(in_flight))
        assert await asyncio.to_thread(associated.wait, 10.0)
        gate.hold(DEPTH_REASON)
        # A NEW association during the pause is refused, while the open one stays up.
        late = await asyncio.to_thread(_store_once, scp.sockport, data)
        assert late.rejection == (0x02, 0x03, 0x01)
        go.set()
        outcome = await asyncio.wait_for(first, 15.0)
        assert outcome.established is True
        assert outcome.status == 0x0000, "the in-flight association's C-STORE was not stored"
        assert len(captured) == 1, "exactly the in-flight object was committed"
    finally:
        go.set()
        await asyncio.wait_for(scp.stop(), timeout=15.0)


async def test_a_gate_injected_after_start_is_honoured() -> None:
    _dicom_deps()
    captured: list[bytes] = []
    scp = _scp()
    await scp.start(_capture(captured))
    try:
        scp.intake_gate = _held()
        outcome = await asyncio.to_thread(_store_once, scp.sockport, _object())
        assert outcome.rejection == (0x02, 0x03, 0x01), "the handler must read the gate live"
        assert captured == []
    finally:
        await asyncio.wait_for(scp.stop(), timeout=15.0)


async def test_a_peer_refused_anyway_gets_its_permanent_refusal_during_a_pause() -> None:
    _dicom_deps()
    scp = _scp(calling_ae_allowlist=["MODALITY1"])
    scp.intake_gate = _held()
    await scp.start(_capture([]))
    try:
        outcome = await asyncio.to_thread(
            _store_once, scp.sockport, _object(), calling_ae="STRANGER"
        )
        # rejected-permanent (1), service user (1), calling AE title not recognised (3): not "busy".
        assert outcome.rejection == (0x01, 0x01, 0x03), outcome.rejection
    finally:
        await asyncio.wait_for(scp.stop(), timeout=15.0)


async def test_a_refusal_that_fails_aborts_rather_than_accepts(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _dicom_deps()
    from pynetdicom.acse import ACSE

    def broken(self: object, result: int, source: int, diagnostic: int) -> None:
        raise RuntimeError("send_reject failed")

    monkeypatch.setattr(ACSE, "send_reject", broken)
    captured: list[bytes] = []
    scp = _scp()
    scp.intake_gate = _held()
    await scp.start(_capture(captured))
    try:
        outcome = await asyncio.to_thread(_store_once, scp.sockport, _object())
        assert outcome.established is False, "a failed refusal let the association in"
        assert captured == []
    finally:
        await asyncio.wait_for(scp.stop(), timeout=15.0)


# --- timer ---------------------------------------------------------------------------------------


def _timer(**settings: object) -> TimerSource:
    return TimerSource(Source(type=ConnectorType.TIMER, settings={"body": "TICK", **settings}))


async def test_a_paused_interval_timer_skips_its_ticks_until_resume() -> None:
    src = _timer(interval_seconds=0.05)
    gate = _held()
    src.intake_gate = gate
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    await src.start(handler)
    try:
        await asyncio.sleep(_PAUSED_WINDOW / 2)
        assert fired == [], "a paused timer fired"
        gate.release(DEPTH_REASON)
        assert await _eventually(lambda: len(fired) >= 2)
        assert set(fired) == {b"TICK"}
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)


async def test_a_paused_run_once_timer_fires_exactly_once_after_resume() -> None:
    src = _timer(run_once=True)
    gate = _held(DISK_REASON)
    src.intake_gate = gate
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    await src.start(handler)
    try:
        # A run_once timer with no interval re-checks every DEFAULT_RUN_ONCE_POLL_SECONDS (1 s).
        await asyncio.sleep(1.3)
        assert fired == [], "a paused run_once timer fired"
        gate.release(DISK_REASON)
        assert await _eventually(lambda: len(fired) == 1)
        await asyncio.sleep(0.2)
        assert fired == [b"TICK"], "a run_once timer fired more than once"
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)


async def test_a_paused_cron_timer_skips_the_due_slot_and_fires_the_next(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(timer_mod, "_MAX_CRON_SLEEP_SECONDS", 0.01)
    clock = [datetime(2026, 1, 5, 9, 0, 30)]
    src = _timer(cron_expression="* * * * *")
    monkeypatch.setattr(src, "_now", lambda: clock[0])
    gate = _held()
    src.intake_gate = gate
    fired: list[bytes] = []

    async def handler(raw: bytes) -> None:
        fired.append(raw)

    await src.start(handler)
    try:
        await asyncio.sleep(0.05)
        clock[0] += timedelta(minutes=1)  # the 09:01 slot is due, during the pause
        await asyncio.sleep(0.2)
        assert fired == [], "a paused cron timer fired its slot"
        gate.release(DEPTH_REASON)
        await asyncio.sleep(0.1)
        assert fired == [], "a slot skipped during the pause was fired late"
        clock[0] += timedelta(minutes=1)  # the next slot, with intake open
        assert await _eventually(lambda: fired == [b"TICK"])
    finally:
        await asyncio.wait_for(src.stop(), timeout=5.0)
