# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The reconcile CaptureSink ACKs every delivered message and appends it to a JSONL capture.

Drives a real loopback MLLP connection into the sink (no engine) on an ephemeral port and asserts: each
message gets an AA whose MSA-2 echoes the control id, and the capture file holds one JSON line per
message with the control id + the exact raw. Async logic runs via ``asyncio.run`` (no pytest-asyncio
needed), mirroring tests/test_load_sink.py.
"""

from __future__ import annotations

import asyncio
import json
import time
from pathlib import Path
from typing import Any

import pytest

from harness.reconcile import __main__ as reconcile_cli
from harness.reconcile.capture import CaptureSink
from messagefoundry.transports.mllp import DEFAULT_MAX_FRAME_BYTES, MLLPDecoder, frame
from tests._mllp_over_cap import send_over_cap, send_valid_then_over_cap


def _message(control_id: str) -> str:
    return (
        f"MSH|^~\\&|SEND|FAC|RECV|FAC|20260101000000||ADT^A05^ADT_A05|{control_id}|P|2.5.1\r"
        f"EVN|A05|20260101000000\rPID|1||MRN123^^^FAC||DOE^JANE\r"
    )


async def _send(port: int, control_ids: list[str]) -> list[bytes]:
    reader, writer = await asyncio.open_connection("127.0.0.1", port)
    decoder = MLLPDecoder()
    acks: list[bytes] = []
    for cid in control_ids:
        writer.write(frame(_message(cid)))
        await writer.drain()
    deadline = time.monotonic() + 5.0
    while len(acks) < len(control_ids) and time.monotonic() < deadline:
        chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
        if not chunk:
            break
        acks.extend(decoder.feed(chunk))
    writer.close()
    await writer.wait_closed()
    return acks


def test_capture_acks_and_writes_jsonl(tmp_path: Path) -> None:
    out = tmp_path / "IB_ACME_ADT.jsonl"

    async def scenario() -> list[bytes]:
        sink = CaptureSink(out, host="127.0.0.1", ports=(0,))
        await sink.start()
        try:
            port = sink.bound_ports[0]
            acks = await _send(port, ["CID0001", "CID0002"])
        finally:
            await sink.stop()
        assert sink.captured == 2 and sink.unparseable == 0
        return acks

    acks = asyncio.run(scenario())
    # Each message got an AA echoing its control id (MSA-2).
    assert len(acks) == 2
    for cid, ack in zip(["CID0001", "CID0002"], acks):  # noqa: B905
        text = ack.decode("latin-1")
        assert "MSA|AA|" in text and cid in text

    # The capture holds one record per message, with the control id + exact raw.
    records = [
        json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert [r["control_id"] for r in records] == ["CID0001", "CID0002"]
    assert records[0]["raw"] == _message("CID0001")
    assert all(isinstance(r["received_at"], float) for r in records)


def test_capture_records_unparseable_without_acking(tmp_path: Path) -> None:
    out = tmp_path / "cap.jsonl"

    async def scenario() -> list[bytes]:
        sink = CaptureSink(out, host="127.0.0.1", ports=(0,))
        await sink.start()
        try:
            port = sink.bound_ports[0]
            reader, writer = await asyncio.open_connection("127.0.0.1", port)
            writer.write(frame("not an HL7 message"))  # no MSH → HL7PeekError, no ACK possible
            await writer.drain()
            writer.write(
                frame(_message("CID9"))
            )  # a valid one after → must still be captured + ACKed
            await writer.drain()
            decoder = MLLPDecoder()
            acks: list[bytes] = []
            deadline = time.monotonic() + 5.0
            while not acks and time.monotonic() < deadline:
                chunk = await asyncio.wait_for(reader.read(65536), timeout=5.0)
                if not chunk:
                    break
                acks.extend(decoder.feed(chunk))
            writer.close()
            await writer.wait_closed()
        finally:
            await sink.stop()
        assert (
            sink.captured == 2 and sink.unparseable == 1
        )  # both captured; one flagged unparseable
        return acks

    acks = asyncio.run(scenario())
    assert len(acks) == 1 and "CID9" in acks[0].decode(
        "latin-1"
    )  # only the valid message was ACKed
    records = [
        json.loads(line) for line in out.read_text(encoding="utf-8").splitlines() if line.strip()
    ]
    assert records[0]["control_id"] is None  # the unparseable one captured with no key
    assert records[1]["control_id"] == "CID9"


def test_capture_drops_an_over_cap_frame_and_keeps_nothing(tmp_path: Path) -> None:
    """The capture sink is an ASVS 5.1.1 upload feature (it persists what it receives), so it bounds a
    frame at the engine's MLLP cap and drops the connection rather than buffer, keep, or ACK it
    (BACKLOG #1127)."""
    out = tmp_path / "cap.jsonl"

    async def scenario() -> bytes:
        sink = CaptureSink(out, host="127.0.0.1", ports=(0,))
        await sink.start()
        try:
            got = await send_over_cap(sink.bound_ports[0], _message("BIG0001"))
        finally:
            await sink.stop()
        assert sink.captured == 0 and sink.unparseable == 0
        assert sink.refused == 1
        return got

    assert asyncio.run(scenario()) == b""  # no ACK: the connection was dropped
    assert out.read_text(encoding="utf-8") == ""


def test_capture_acks_a_valid_frame_before_dropping_a_pipelined_over_cap_one(
    tmp_path: Path,
) -> None:
    """A refusal must not take back the ACK the sink already built for an earlier frame in the same
    read. The valid frame is captured and acknowledged, then the connection closes (BACKLOG #1127
    follow-up)."""
    out = tmp_path / "cap.jsonl"
    message = _message("CID1")
    cap = len(message.encode())

    async def scenario() -> tuple[bytes, bool]:
        sink = CaptureSink(out, host="127.0.0.1", ports=(0,), max_frame_bytes=cap)
        await sink.start()
        try:
            got = await send_valid_then_over_cap(sink.bound_ports[0], message, cap)
        finally:
            await sink.stop()
        assert sink.captured == 1 and sink.refused == 1
        return got

    got, closed = asyncio.run(scenario())
    acks = list(MLLPDecoder().feed(got))
    assert closed, "the over-cap frame did not drop the connection"
    assert len(acks) == 1 and b"MSA|AA|CID1" in acks[0]
    records = [json.loads(line) for line in out.read_text(encoding="utf-8").splitlines()]
    assert [r["control_id"] for r in records] == ["CID1"]


def test_capture_max_frame_bytes_zero_turns_the_cap_off(tmp_path: Path) -> None:
    """``0`` means no cap, as on the engine's MLLP source. A live zero would refuse every frame."""

    async def scenario() -> list[bytes]:
        sink = CaptureSink(tmp_path / "cap.jsonl", host="127.0.0.1", ports=(0,), max_frame_bytes=0)
        await sink.start()
        try:
            return await _send(sink.bound_ports[0], ["CID1"])
        finally:
            await sink.stop()

    acks = asyncio.run(scenario())
    assert len(acks) == 1 and b"MSA|AA|CID1" in acks[0]


def test_capture_refuses_a_negative_max_frame_bytes(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="max_frame_bytes must be zero or more"):
        CaptureSink(tmp_path / "cap.jsonl", max_frame_bytes=-1)


def test_capture_refuses_a_fractional_max_frame_bytes(tmp_path: Path) -> None:
    """0.5 is neither zero nor a byte count; truncated, it would be a live cap refusing every frame."""
    half: Any = 0.5
    with pytest.raises(ValueError, match="max_frame_bytes must be zero or more whole bytes"):
        CaptureSink(tmp_path / "cap.jsonl", max_frame_bytes=half)


def test_capture_cli_refuses_a_negative_max_frame_bytes_at_parse(
    tmp_path: Path, capsys: pytest.CaptureFixture[str], monkeypatch: pytest.MonkeyPatch
) -> None:
    ran: list[Any] = []

    async def fake_run(args: Any) -> int:  # stands in for the sink, which would run until Ctrl-C
        ran.append(args)
        return 0

    monkeypatch.setattr(reconcile_cli, "_run_capture", fake_run)
    argv = ["capture", "--port", "0", "--out", str(tmp_path / "c.jsonl"), "--max-frame-bytes"]
    with pytest.raises(SystemExit) as excinfo:
        reconcile_cli.main([*argv, "-1"])
    assert excinfo.value.code == 2
    assert "--max-frame-bytes" in capsys.readouterr().err
    assert ran == []  # refused at parse, before a sink was built


def test_capture_cli_passes_zero_through_as_cap_off(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    seen: list[Any] = []

    async def fake_run(args: Any) -> int:
        seen.append(args.max_frame_bytes)
        return 0

    monkeypatch.setattr(reconcile_cli, "_run_capture", fake_run)
    argv = ["capture", "--port", "0", "--out", str(tmp_path / "c.jsonl")]
    assert reconcile_cli.main([*argv, "--max-frame-bytes", "0"]) == 0
    assert reconcile_cli.main(argv) == 0
    assert seen == [0, DEFAULT_MAX_FRAME_BYTES]
