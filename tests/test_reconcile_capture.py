# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

from messagefoundry.transports.mllp import MLLPDecoder, frame

from harness.reconcile.capture import CaptureSink


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
    for cid, ack in zip(["CID0001", "CID0002"], acks):
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
