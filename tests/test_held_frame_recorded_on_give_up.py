# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1619 item 6: a held frame a no-reply listener loses at stop is recorded as ``ERROR``.

A TCP or MLLP inbound that sends no reply holds a frame whose ``put_attachment`` faults and retries
it with no attempt cap until it is recorded or the listener stops (BACKLOG #5022, decision
d20261103T214617030-d09d2a). Before this item a stop whose last attempt also failed lost the frame
with an ERROR log line and no message row, against the count-and-log invariant (CLAUDE.md section
2). The runner-injected ``record_lost_frame`` seam now records it as an ``ERROR`` row with a
value-free reason. It does not charge the refused-body allowance, since a store fault the same body
meets every time would drain that allowance for every refused body on the inbound, and a body larger
than a head stores only its head, so no such body lands whole in the row. A recovered hold is unchanged: ``tests/test_detach_attachment_write_fault.py`` pins it.

Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import asyncio
import base64
import json
import logging
import sqlite3
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.transports.base as base_mod
import messagefoundry.transports.tcp as tcp_mod
from messagefoundry.config.models import AckMode, ConnectorType, ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.parsing.binary import MARKER as CARRIAGE_MARKER
from messagefoundry.pipeline.refused_body import (
    HELD_FRAME_KEY,
    METADATA_KEY,
    RefusedBodyAllowance,
    RefusedBodyPolicy,
    head_only_resubmit_refusal,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.crypto import make_cipher
from messagefoundry.transports.base import SourceConnector
from messagefoundry.transports.mllp import MLLPSource, frame
from messagefoundry.transports.tcp import TcpSource
from messagefoundry.transports.x12 import X12Source
from tests.test_detach_attachment_write_fault import _doc_hl7
from tests.test_mllp_handler_failure import _drive as _drive_mllp
from tests.test_mllp_handler_failure import _no_reply as _mllp_no_reply
from tests.test_tcp_x12_handler_failure import LISTENERS, _ThenEof
from tests.test_tcp_x12_handler_failure import _no_reply as _no_reply_listener
from tests.test_x12_connection_events import _drive as _drive_tcp
from tests.test_x12_connection_events import _kinds, _Peer, _tcp

#: A small head, so the synthetic document (about 2.8 KB) is larger than it.
_POLICY = RefusedBodyPolicy(allowance_bytes=100_000, window_seconds=60.0, head_bytes=64)
_INBOUND = "IB_STREAM"
#: A store cipher with no key: the bound's own tests do not need a digest.
_KEYLESS = make_cipher(None)


@pytest.fixture
async def store(tmp_path: Path) -> AsyncIterator[MessageStore]:
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


@pytest.fixture(autouse=True)
def _no_retry_pauses(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(base_mod, "HANDLER_RETRY_DELAYS", (0.0,))


def _runner(
    store: MessageStore, connector: ConnectorType, settings: dict[str, Any] | None = None
) -> tuple[RegistryRunner, InboundConnection, RefusedBodyAllowance]:
    allowance = RefusedBodyAllowance(_POLICY, clock=lambda: 0.0)
    ic = InboundConnection(
        name=_INBOUND,
        spec=ConnectionSpec(connector, settings or {}),
        router="r",
        ack_mode=AckMode.NONE,
        content_type=ContentType.HL7V2,
        stream_threshold_bytes=500,
    )
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])  # no worker runs, so routing is never reached
    runner = RegistryRunner(
        reg, store, egress=EgressSettings(deny_by_default=False), refused_body_allowance=allowance
    )
    return runner, ic, allowance


class _PutFailsThenStop:
    """Stand in for ``put_attachment``: every call raises ``database is locked``, and the
    ``stop_after``-th sets the listener's stopping flag, so the hold's last attempt fails too."""

    def __init__(self, source: SourceConnector, stop_after: int = 2) -> None:
        self._source = source
        self._stop_after = stop_after
        self.calls = 0

    async def __call__(self, *_args: object) -> str:
        self.calls += 1
        if self.calls == self._stop_after:
            if isinstance(self._source, MLLPSource):
                self._source._stopping = True
            else:
                self._source._admission.stopping = True  # type: ignore[attr-defined]
        raise sqlite3.OperationalError("database is locked")


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    cur = await store._db.execute("SELECT id, status, error, raw FROM messages")
    return [dict(r) for r in await cur.fetchall()]


def _mllp_source() -> MLLPSource:
    source = _mllp_no_reply()
    source.content_type = ContentType.HL7V2  # as the runner injects it
    return source


def _tcp_source() -> TcpSource:
    source = _tcp()
    source.ack_mode = AckMode.NONE
    source.content_type = ContentType.HL7V2
    return source


async def _drive(source: SourceConnector, runner: RegistryRunner, ic: InboundConnection) -> object:
    body = _doc_hl7()
    if isinstance(source, MLLPSource):
        return await _drive_mllp(source, _ThenEof(frame(body)), _Peer(), runner._make_handler(ic))
    assert isinstance(source, TcpSource)
    wire = b"\x02" + body.encode("utf-8") + b"\x03"
    return await _drive_tcp(source, _ThenEof(wire), _Peer(), handler=runner._make_handler(ic))


_LISTENERS = [
    pytest.param(ConnectorType.MLLP, _mllp_source, id="mllp"),
    pytest.param(ConnectorType.TCP, _tcp_source, id="tcp"),
]


@pytest.mark.parametrize(("connector", "build"), _LISTENERS)
async def test_a_frame_whose_write_never_clears_is_recorded_error_once_at_stop(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    connector: ConnectorType,
    build: Any,
) -> None:
    runner, ic, allowance = _runner(store, connector)
    source = build()
    source.record_lost_frame = runner._make_lost_frame_recorder(ic)
    put = _PutFailsThenStop(source)
    monkeypatch.setattr(store, "put_attachment", put)

    with caplog.at_level(logging.WARNING):
        events = await _drive(source, runner, ic)

    # The stop lands during attempt 2, so attempt 3 is the last (hold_and_retry's docstring).
    assert put.calls == 3, "the hold did not make its last attempt at stop"
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    error = rows[0]["error"]
    body = _doc_hl7().encode("utf-8")
    assert error == (
        f"[held frame: stored only the head of a {len(body):,}-byte body] "
        "held until the listener stopped; handler failed 3 times (copies may exist): "
        "OperationalError: [driver message withheld]"
    ), error
    assert "DOE" not in error and "MRN123" not in error, "the reason carries message content"
    # Larger than a head, so only the head is stored, and the length and digest are recorded.
    assert rows[0]["raw"] == body[: _POLICY.head_bytes].decode("ascii")
    record = json.loads(await store.message_metadata_json(rows[0]["id"]) or "{}")[METADATA_KEY]
    assert record["bytes"] == len(body) and record["stored"] == "head"
    # Not charged: the whole allowance still fits.
    assert allowance.try_charge(ic.name, _POLICY.allowance_bytes)
    assert "handler_error" in _kinds(events)  # type: ignore[arg-type]
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any(f"is recorded as ERROR message {rows[0]['id']}" in m for m in errors), errors
    assert not any("is not recorded, nor is any frame" in m for m in errors), errors


@pytest.mark.parametrize(("connector", "build"), _LISTENERS)
async def test_a_failed_error_write_keeps_the_loss_line_and_does_not_raise(
    store: MessageStore,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    connector: ConnectorType,
    build: Any,
) -> None:
    runner, ic, allowance = _runner(store, connector)
    source = build()
    source.record_lost_frame = runner._make_lost_frame_recorder(ic)
    monkeypatch.setattr(store, "put_attachment", _PutFailsThenStop(source))
    writes: list[object] = []

    async def store_down(**kwargs: object) -> str:
        writes.append(kwargs["status"])
        raise sqlite3.OperationalError("disk I/O error")

    monkeypatch.setattr(store, "record_received", store_down)

    with caplog.at_level(logging.WARNING):
        await _drive(source, runner, ic)  # returns: the write's fault does not escape the listener

    assert writes == [MessageStatus.ERROR], "the ERROR write was never attempted"
    assert await _rows(store) == []
    messages = [r.getMessage() for r in caplog.records]
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("is not recorded, nor is any frame behind it" in m for m in errors), errors
    assert any("ERROR row for the held message" in m and "not written" in m for m in messages)
    assert allowance.try_charge(ic.name, _POLICY.allowance_bytes)


async def test_a_frame_whose_fault_clears_is_received_with_no_error_row(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The control: the recorder wired in changes nothing for a hold that recovers.
    runner, ic, _allowance = _runner(store, ConnectorType.TCP)
    source = _tcp_source()
    source.record_lost_frame = runner._make_lost_frame_recorder(ic)
    real = store.put_attachment
    calls = 0

    async def fails_once(*args: Any) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database is locked")
        return await real(*args)

    monkeypatch.setattr(store, "put_attachment", fails_once)

    events = await _drive(source, runner, ic)

    assert [r["status"] for r in await _rows(store)] == [MessageStatus.RECEIVED.value]
    assert _kinds(events) == ["established", "closed"]  # type: ignore[arg-type]


async def test_a_cancel_inside_an_attempt_still_records_the_frame(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # stop() cancels a client task still running past its grace. The second attempt blocks in the
    # store, so the cancel ends the hold; the frame is recorded, and its reason says the cut-off
    # attempt may also have recorded it.
    monkeypatch.setattr(tcp_mod, "_CLIENT_SHUTDOWN_GRACE", 0.1)
    runner, ic, allowance = _runner(store, ConnectorType.TCP)
    source = _tcp_source()
    source.record_lost_frame = runner._make_lost_frame_recorder(ic)
    blocked = asyncio.Event()
    calls = 0

    async def blocks_on_retry(*_args: object) -> str:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise sqlite3.OperationalError("database is locked")
        blocked.set()
        await asyncio.Event().wait()
        raise AssertionError("unreachable")

    monkeypatch.setattr(store, "put_attachment", blocks_on_retry)
    source._handler = runner._make_handler(ic)
    wire = b"\x02" + _doc_hl7().encode("utf-8") + b"\x03"
    client = asyncio.create_task(source._on_client(_ThenEof(wire), _Peer()))  # type: ignore[arg-type]
    await asyncio.wait_for(blocked.wait(), timeout=2.0)
    await asyncio.wait_for(source.stop(), timeout=5.0)

    assert client.cancelled()
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    assert (
        "; last attempt cancelled; handler failed 1 times (copies may exist)" in (rows[0]["error"])
    )
    assert allowance.try_charge(ic.name, _POLICY.allowance_bytes)


async def test_a_cut_off_reason_over_a_head_fits_the_error_column_whole(
    store: MessageStore,
) -> None:
    # A cut-off attempt over a frame larger than a head, the case that measured 205 characters:
    # the head note plus the reason fits the store's 200-character error column, so the fault
    # text at its end is not cut.
    runner, ic, _allowance = _runner(store, ConnectorType.TCP)
    body = _doc_hl7().encode("utf-8")
    fault = "OperationalError: [driver message withheld]"
    reason = base_mod._held_loss_reason(1, fault, cut_off=True)
    await runner._record_lost_frame(ic, body, reason)
    rows = await _rows(store)
    error = rows[0]["error"]
    note = f"[held frame: stored only the head of a {len(body):,}-byte body] "
    assert error == note + reason, error
    assert len(error) <= 200 and error.endswith(fault), (len(error), error)


async def test_the_runner_injects_the_recorder_at_start(store: MessageStore) -> None:
    runner, _ic, _allowance = _runner(
        store, ConnectorType.TCP, {"host": "127.0.0.1", "port": 0, "framing": "stx_etx"}
    )
    await runner.start()
    try:
        assert runner._sources[_INBOUND].record_lost_frame is not None
    finally:
        await asyncio.wait_for(runner.stop(), timeout=10.0)


def test_a_direct_build_records_nothing() -> None:
    assert _tcp_source().record_lost_frame is None
    assert _mllp_source().record_lost_frame is None


# --- the seam itself, on every listener that holds a frame -----------------------------------------


class _Recorder:
    """A ``record_lost_frame`` fake: keeps what it is handed, then returns an id, raises, or hangs."""

    def __init__(self, *, fault: Exception | None = None, hang: bool = False) -> None:
        self.calls: list[tuple[bytes, str]] = []
        self.entered = asyncio.Event()
        self._fault = fault
        self._hang = hang

    async def __call__(self, frame_bytes: bytes, reason: str) -> str:
        self.calls.append((frame_bytes, reason))
        self.entered.set()
        if self._hang:
            await asyncio.Event().wait()
        if self._fault is not None:
            raise self._fault
        return "mid-1"


def _stops_on_second(source: X12Source | TcpSource) -> Any:
    calls = 0

    async def handler(_raw: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            source._admission.stopping = True
        raise RuntimeError("synthetic store outage")

    return handler


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_every_holding_listener_hands_the_frame_to_the_recorder(
    caplog: pytest.LogCaptureFixture, transport: str, build: Any, wire: bytes, body: bytes
) -> None:
    source = _no_reply_listener(build)
    recorder = _Recorder()
    source.record_lost_frame = recorder
    with caplog.at_level(logging.ERROR):
        events = await _drive_tcp(source, _ThenEof(wire), _Peer(), handler=_stops_on_second(source))
    assert [f for f, _ in recorder.calls] == [body]
    assert recorder.calls[0][1].startswith("held until the listener stopped; handler failed")
    assert "handler_error" in _kinds(events)
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1 and "is recorded as ERROR message mid-1" in errors[0], errors


@pytest.mark.parametrize(("transport", "build", "wire", "body"), LISTENERS)
async def test_a_recorder_timeout_on_the_stopping_path_is_logged_not_raised(
    caplog: pytest.LogCaptureFixture, transport: str, build: Any, wire: bytes, body: bytes
) -> None:
    # A store can raise its own TimeoutError, as an OS ETIMEDOUT; the stopping path has no bound.
    source = _no_reply_listener(build)
    source.record_lost_frame = _Recorder(fault=TimeoutError("timed out"))
    with caplog.at_level(logging.WARNING):
        await _drive_tcp(source, _ThenEof(wire), _Peer(), handler=_stops_on_second(source))
    messages = [r.getMessage() for r in caplog.records]
    assert any("ERROR row for the held message" in m and "not written: " in m for m in messages)
    assert any("is not recorded, nor is any frame behind it" in m for m in messages)


async def test_a_second_cancel_during_the_write_still_logs_the_loss(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # stop() cancels a hold, then the cancel is repeated while the ERROR write hangs: the loss line
    # is still written, since it is logged in a finally, and the report was made before the write.
    recorder = _Recorder(hang=True)
    reports: list[str] = []
    calls = 0

    async def handler(_raw: bytes) -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            raise RuntimeError("synthetic store outage")
        await asyncio.Event().wait()

    async def report(reason: str) -> None:
        reports.append(reason)

    with caplog.at_level(logging.WARNING):
        task = asyncio.create_task(
            base_mod.hold_and_retry(
                handler,
                b"frame",
                "RuntimeError: synthetic store outage",
                transport="TCP",
                peer="peer",
                log=logging.getLogger("messagefoundry.transports.tcp"),
                stopped=lambda: False,
                report=report,
                record_loss=recorder,
            )
        )

        async def second_attempt() -> None:
            while calls < 2:
                await asyncio.sleep(0)

        await asyncio.wait_for(second_attempt(), timeout=2.0)
        task.cancel()
        await asyncio.wait_for(recorder.entered.wait(), timeout=2.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task
    messages = [r.getMessage() for r in caplog.records]
    assert reports, "the report is made before the write"
    assert any("may or may not be recorded" in m for m in messages), messages
    assert any("may or may not be written: the write was cancelled" in m for m in messages)


async def test_a_hung_write_after_one_cancel_is_bounded(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    # stop() waits for the task it cancelled, so a hung ERROR write must not hold it open.
    monkeypatch.setattr(base_mod, "_CANCELLED_REPORT_SECONDS", 0.05)
    recorder = _Recorder(hang=True)
    calls = 0

    async def handler(_raw: bytes) -> None:
        nonlocal calls
        calls += 1
        raise RuntimeError("synthetic store outage")

    async def report(_reason: str) -> None:
        return None

    with caplog.at_level(logging.WARNING):
        task = asyncio.create_task(
            base_mod.hold_and_retry(
                handler,
                b"frame",
                "RuntimeError: synthetic store outage",
                transport="TCP",
                peer="peer",
                log=logging.getLogger("messagefoundry.transports.tcp"),
                stopped=lambda: False,
                report=report,
                record_loss=recorder,
            )
        )

        async def retried() -> None:
            while calls < 2:
                await asyncio.sleep(0)

        await asyncio.wait_for(retried(), timeout=2.0)
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(task, timeout=2.0)
    messages = [r.getMessage() for r in caplog.records]
    assert recorder.calls, "the write was not attempted"
    assert any("not written within 0.1s of the cancel" in m for m in messages), messages
    assert any("is not recorded, nor is any frame behind it" in m for m in messages)


def test_a_frame_that_fits_in_a_head_is_stored_whole_and_charges_nothing() -> None:
    allowance = RefusedBodyAllowance(_POLICY, clock=lambda: 0.0)
    wire = b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X|P|2.5\r"
    bounded = allowance.bound_uncharged(wire, None, "hl7v2", "held", cipher=_KEYLESS)
    assert bounded.raw == wire.decode("ascii")
    assert bounded.record["stored"] == "whole" and bounded.record[HELD_FRAME_KEY] is True
    assert allowance.try_charge(_INBOUND, _POLICY.allowance_bytes)


def test_a_decoded_text_head_is_kept_readable() -> None:
    allowance = RefusedBodyAllowance(_POLICY, clock=lambda: 0.0)
    text = "PID|1||MRN||MÜLLER^ANNA\r" * 10
    bounded = allowance.bound_uncharged(
        text.encode("utf-8"), text, "hl7v2", "held", cipher=_KEYLESS
    )
    assert text.startswith(bounded.raw) and "Ü" in bounded.raw
    assert len(bounded.raw.encode("utf-8")) <= _POLICY.head_bytes


@pytest.mark.parametrize("wire", [b"\x89PNG\x01\x02", b"\x89" * 500], ids=["whole", "head"])
def test_a_binary_held_frame_is_stored_as_carriage(wire: bytes) -> None:
    allowance = RefusedBodyAllowance(_POLICY, clock=lambda: 0.0)
    bounded = allowance.bound_uncharged(wire, None, "binary", "held", cipher=_KEYLESS)
    assert bounded.raw.startswith(CARRIAGE_MARKER), bounded.raw[:20]
    kept = base64.b64decode(bounded.raw[len(CARRIAGE_MARKER) :])
    assert kept and wire.startswith(kept)
    assert len(bounded.raw) <= max(_POLICY.head_bytes, len(CARRIAGE_MARKER) + 8)


def test_the_resubmit_refusal_does_not_promise_a_resend_for_a_held_frame() -> None:
    allowance = RefusedBodyAllowance(_POLICY, clock=lambda: 0.0)
    held = allowance.bound_uncharged(
        _doc_hl7().encode("utf-8"), None, "hl7v2", "held", cipher=_KEYLESS
    )
    refusal = head_only_resubmit_refusal("m1", held.metadata)
    assert refusal is not None and "never resends" in refusal
    assert "send its own copy again" not in refusal


def test_the_resubmit_refusal_names_only_what_this_row_holds() -> None:
    # Hold finding 8: an attempt whose fault came after its commit may have left a committed copy,
    # so the refusal must not say this head is all the engine holds. That copy may since have moved
    # to any status, so the refusal names none.
    allowance = RefusedBodyAllowance(_POLICY, clock=lambda: 0.0)
    held = allowance.bound_uncharged(
        _doc_hl7().encode("utf-8"), None, "hl7v2", "held", cipher=_KEYLESS
    )
    refusal = head_only_resubmit_refusal("m1", held.metadata)
    assert refusal is not None and "this row holds only the frame's head" in refusal, refusal
    assert "all the engine holds" not in refusal, refusal
    assert "under any status" in refusal, refusal
    assert not [s.value for s in MessageStatus if s.value in refusal.lower()], refusal
    # A held frame was not refused, and a cancelled attempt may have committed a copy too.
    assert "refused body" not in refusal and "held frame" in refusal, refusal
    assert "faulted or was cancelled" in refusal, refusal


async def test_a_cancel_while_waiting_for_an_mllp_slot_is_recorded_as_a_cancel(
    caplog: pytest.LogCaptureFixture,
) -> None:
    # Hold finding 10: the retry waits for an in-flight slot that never frees, so the cancel lands
    # before the handler is called. No attempt was cut off, so neither the row nor the log says so.
    source = _mllp_source()
    source._inflight = asyncio.Semaphore(1)
    recorder = _Recorder()
    source.record_lost_frame = recorder
    calls = 0
    waiting = asyncio.Event()

    async def handler(_raw: bytes) -> None:
        nonlocal calls
        calls += 1
        # Every later attempt meets a bound with no free slot, as under a full listener.
        source._inflight = asyncio.Semaphore(0)
        waiting.set()
        raise RuntimeError("synthetic store outage")

    source._handler = handler
    with caplog.at_level(logging.WARNING):
        client = asyncio.create_task(
            source._on_client(_ThenEof(frame(_doc_hl7())), _Peer())  # type: ignore[arg-type]
        )
        await asyncio.wait_for(waiting.wait(), timeout=2.0)
        # A positive control: the retry is waiting on the slot, not in the pause, when cancelled.
        for _ in range(200):
            if getattr(source._inflight, "_waiters", None):
                break
            await asyncio.sleep(0)
        assert getattr(source._inflight, "_waiters", None), "the retry never waited for a slot"
        client.cancel()
        with pytest.raises(asyncio.CancelledError):
            await asyncio.wait_for(client, timeout=2.0)

    assert calls == 1, "the handler ran again, so the slot wait was not reached"
    assert len(recorder.calls) == 1
    reason = recorder.calls[0][1]
    assert "last attempt cancelled" not in reason, reason
    errors = [r.getMessage() for r in caplog.records if r.levelno >= logging.ERROR]
    assert any("is recorded as ERROR message mid-1" in m for m in errors), errors
    assert any("the listener task was cancelled" in m for m in errors), errors
    assert not any("cut-off attempt" in m or "inside attempt" in m for m in errors), errors


async def test_a_held_frame_that_does_not_decode_logs_a_warning_without_its_body(
    store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    # Hold finding 11: the decode failure is not swallowed silently, and the line holds no byte of
    # the frame.
    runner, ic, _allowance = _runner(store, ConnectorType.TCP)
    raw = b"MSH|^~\\&|A|B|C|D|20260101||ADT^A01|X|P|2.5\rPID|1||MRN123||DOE\xff\xfe\r"
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pipeline.wiring_runner"):
        mid = await runner._record_lost_frame(ic, raw, "held")
    assert mid
    lines = [
        r.getMessage()
        for r in caplog.records
        if r.name == "messagefoundry.pipeline.wiring_runner" and r.levelno == logging.WARNING
    ]
    assert any("did not decode as text" in m and _INBOUND in m for m in lines), lines
    assert any("any row written for it" in m for m in lines), lines
    assert not any("MRN123" in m or "DOE" in m for m in lines), lines
    assert not any("0xff" in m or "\xff" in m or "\xfe" in m for m in lines), lines
