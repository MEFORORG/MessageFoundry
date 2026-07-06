# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Base64-PDF end-to-end through the real engine (SYNTHETIC-TEST-PLAN §1.1.4-1.1.6).

Building on the ED-OBX fixtures (test_ed_documents.py / generators.documents), these drive a synthetic
base64-PDF ORU through the **whole pipeline** and assert the document survives byte-identical:

* 1.1.4 / 1.1.6 size ladder — File-in → router → handler → File-out: the delivered body, the stored
  inbound raw, AND the transformed outbound payload all decode to the original PDF (small + medium).
* 1.1.5 — at-rest: with an AES-256-GCM store the raw + transformed payload round-trip on read but are
  **ciphertext on disk** (the base64 never appears in the clear).
* 1.1.6 cap-edge — the MLLP frame cap accepts a just-under-cap base64-PDF frame and rejects (drops) a
  just-over-cap one; the real ~16 MiB default cap is exercised opt-in (``MEFOR_RUN_SLOW=1``).

Synthetic + PHI-free; real loopback sockets / temp files, no mocks.
"""

from __future__ import annotations

import asyncio
import base64
import os
import sqlite3
from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, Destination, Source
from messagefoundry.config.wiring import (
    ConnectionSpec,
    InboundConnection,
    OutboundConnection,
    Registry,
    Send,
)
from messagefoundry.generators.documents import oru_with_pdf, synthetic_pdf
from messagefoundry.parsing.message import Message
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.crypto import PREFIX, generate_key, make_cipher
from messagefoundry.transports import DeliveryError
from messagefoundry.transports.mllp import MLLPDestination, MLLPSource, build_ack

_RUN_SLOW = os.environ.get("MEFOR_RUN_SLOW") == "1"


def _last_obx_data(msg: Message) -> str | None:
    """The base64 ED data (``OBX-5.5``) of the last OBX — where the builders append the document."""
    return msg.field("OBX-5.5", occurrence=msg.count_segments("OBX"))


def _raw_at_rest(db_path: Path, column: str = "raw", table: str = "messages") -> str:
    """Read a column straight from the DB file, bypassing the store's decryption (mirrors
    tests/test_store_encryption.py)."""
    con = sqlite3.connect(db_path)
    try:
        return str(con.execute(f"SELECT {column} FROM {table}").fetchone()[0])  # noqa: S608
    finally:
        con.close()


# --- harness -----------------------------------------------------------------


@pytest.fixture
async def store(tmp_path: Path):  # type: ignore[no-untyped-def]
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _route(msg: Message) -> list[str]:
    return ["relay"]


def _relay(msg: Message) -> Send:
    return Send("file_out", msg)  # identity pass-through — the document must survive verbatim


def _passthrough_registry(inbox: Path, outdir: Path) -> Registry:
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
    reg.add_router("r", _route)
    reg.add_handler("relay", _relay)
    return reg


async def _until_status(
    store: MessageStore, status: str, *, channel_id: str = "file_in", timeout: float = 8.0
) -> list[dict[str, object]]:
    for _ in range(int(timeout / 0.02)):
        msgs = await store.list_messages(channel_id=channel_id, status=status)
        if msgs:
            return msgs
        await asyncio.sleep(0.02)
    raise AssertionError(f"no message reached {status} within {timeout}s")


# --- 1.1.4 / 1.1.6 size ladder: byte-identical through File-in → store → File-out --------------


@pytest.mark.parametrize("size", [2048, 262_144])  # small (~2 KiB) + medium (~256 KiB)
async def test_base64_pdf_survives_full_engine(
    store: MessageStore, tmp_path: Path, size: int
) -> None:
    pdf = synthetic_pdf(n_bytes=size, seed=f"e2e-{size}")
    source_b64 = base64.b64encode(pdf).decode("ascii")
    inbox, outdir = tmp_path / "in", tmp_path / "out"
    inbox.mkdir()
    (inbox / "a.hl7").write_bytes(oru_with_pdf(pdf, seed=f"e2e-{size}").encode("utf-8"))

    runner = RegistryRunner(_passthrough_registry(inbox, outdir), store, poll_interval=0.02)
    await runner.start()
    try:
        msgs = await _until_status(store, MessageStatus.PROCESSED.value)
    finally:
        await runner.stop()
    mid = str(msgs[0]["id"])

    # (a) the delivered outbound file
    delivered = Message.parse(next(outdir.glob("*.hl7")).read_bytes().decode("utf-8"))
    assert _last_obx_data(delivered) == source_b64
    assert base64.b64decode(_last_obx_data(delivered) or "") == pdf

    # (b) the stored inbound raw (preserve-the-original invariant)
    record = await store.get_message(mid)
    assert record is not None
    assert _last_obx_data(Message.parse(record["raw"])) == source_b64

    # (c) the transformed outbound payload (the parity read path, #14)
    payloads = await store.outbox_payloads_for(mid)
    assert payloads, "expected at least one outbound payload row"
    assert _last_obx_data(Message.parse(str(payloads[0]["payload"]))) == source_b64


# --- 1.1.5 at-rest: round-trips on read, ciphertext on disk -----------------------------------


async def test_base64_pdf_encrypted_at_rest(tmp_path: Path) -> None:
    pdf = synthetic_pdf(n_bytes=4096, seed="enc")
    source_b64 = base64.b64encode(pdf).decode("ascii")
    raw = oru_with_pdf(pdf, seed="enc")
    db = tmp_path / "enc.db"

    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        mid = await store.enqueue_message(channel_id="ch", raw=raw, deliveries=[("file_out", raw)])
        record = await store.get_message(mid)
        assert record is not None and record["raw"] == raw  # body decrypts on read
        assert _last_obx_data(Message.parse(record["raw"])) == source_b64
        payloads = await store.outbox_payloads_for(mid)
        assert payloads and payloads[0]["payload"] == raw  # transformed copy decrypts on read
    finally:
        await store.close()

    # On disk the PDF base64 is AES-256-GCM ciphertext, never plaintext.
    at_rest_raw = _raw_at_rest(db, column="raw", table="messages")
    at_rest_payload = _raw_at_rest(db, column="payload", table="queue")
    assert at_rest_raw.startswith(PREFIX)
    assert at_rest_payload.startswith(PREFIX)
    assert source_b64 not in at_rest_raw  # the document never hits disk in the clear
    assert source_b64 not in at_rest_payload


# --- 1.1.6 cap-edge: MLLP frame cap accept-just-under / reject-just-over -----------------------


async def _mllp_roundtrip(
    raw: str, *, source_cap: int | None, timeout: float = 5.0
) -> tuple[list[bytes], Exception | None]:
    """Send ``raw`` over a real loopback MLLP socket to a source with ``source_cap`` (omit when None →
    the 16 MiB default). Returns (frames the handler received, the delivery error if the send failed)."""
    received: list[bytes] = []

    async def handler(data: bytes) -> str:
        received.append(data)
        return build_ack(data, code="AA")

    settings: dict[str, object] = {"host": "127.0.0.1", "port": 0}
    if source_cap is not None:
        settings["max_frame_bytes"] = source_cap
    source = MLLPSource(Source(type=ConnectorType.MLLP, settings=settings))
    await source.start(handler)
    err: Exception | None = None
    try:
        dest = MLLPDestination(
            Destination(
                name="out",
                type=ConnectorType.MLLP,
                settings={"host": "127.0.0.1", "port": source.sockport, "timeout_seconds": timeout},
            )
        )
        try:
            await dest.send(raw)
        except (DeliveryError, OSError) as exc:  # over-cap → source drops → delivery fails
            err = exc
    finally:
        await source.stop()
    return received, err


async def test_mllp_cap_accepts_under_and_rejects_over() -> None:
    pdf = synthetic_pdf(n_bytes=4096, seed="cap")
    raw = oru_with_pdf(pdf, seed="cap")
    n = len(raw.encode("utf-8"))

    # Just under the cap → accepted; the handler receives the frame and the base64 PDF is intact.
    received, err = await _mllp_roundtrip(raw, source_cap=n + 4096)
    assert err is None
    assert received, "expected the under-cap frame to be delivered"
    delivered = Message.parse(received[0].decode("utf-8"))
    assert base64.b64decode(_last_obx_data(delivered) or "") == pdf

    # Just over the cap → the source drops the connection mid-frame; nothing is delivered.
    received_over, err_over = await _mllp_roundtrip(raw, source_cap=n // 2)
    assert err_over is not None  # delivery failed (no ACK — connection dropped)
    assert received_over == []  # the over-cap frame never reached the handler


@pytest.mark.skipif(
    not _RUN_SLOW, reason="~16 MiB MLLP cap-edge — set MEFOR_RUN_SLOW=1 (nightly / real-box leg)"
)
async def test_mllp_accepts_large_pdf_under_default_cap() -> None:
    from messagefoundry.transports.mllp import DEFAULT_MAX_FRAME_BYTES

    pdf = synthetic_pdf(n_bytes=11 * 1024 * 1024, seed="big")  # base64 ~1.33x → ~15 MiB message
    raw = oru_with_pdf(pdf, seed="big")
    n = len(raw.encode("utf-8"))
    assert (
        14 * 1024 * 1024 < n < DEFAULT_MAX_FRAME_BYTES
    )  # genuinely large, just under the real cap

    received, err = await _mllp_roundtrip(raw, source_cap=None, timeout=30.0)  # default 16 MiB cap
    assert err is None
    delivered = Message.parse(received[0].decode("utf-8"))
    assert base64.b64decode(_last_obx_data(delivered) or "") == pdf
