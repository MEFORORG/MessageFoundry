# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""P2c — _handle_inbound "Response Sent" ACK/NAK capture wiring (ADR 0021, #46)."""

from __future__ import annotations

from pathlib import Path

from messagefoundry.config.models import ConnectorType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher

ADT = "MSH|^~\\&|A|B|C|D|20260101||ADT^A01|M1|P|2.5.1\rPID|1||100^^^H^MR||DOE^JANE\r"


def _registry(**inbound_kw: object) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            "IB_X",
            ConnectionSpec(ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0}),
            router="r",
            **inbound_kw,  # type: ignore[arg-type]
        )
    )
    reg.add_router("r", lambda m: [])
    return reg


async def _only_message_id(store: MessageStore) -> str:
    cur = await store._db.execute("SELECT id FROM messages")
    row = await cur.fetchone()
    return str(row["id"])


async def _ack_rows(store: MessageStore):  # type: ignore[no-untyped-def]
    mid = await _only_message_id(store)
    return [r for r in await store.correlate_response(mid) if r.kind == "ack_sent"]


async def test_aa_captured_body_null_on_unencrypted_store(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "aa.db")
    try:
        runner = RegistryRunner(_registry(), store)
        ack = await runner._handle_inbound(runner.registry.inbound["IB_X"], ADT.encode())
        assert ack is not None  # AA returned to the sender
        rows = await _ack_rows(store)
        assert len(rows) == 1
        assert rows[0].ack_code == "AA" and rows[0].ack_phase == "ingest"
        assert rows[0].outcome == "accepted"
        assert rows[0].body is None  # fail-safe: AA body not stored on an unencrypted store
    finally:
        await store.close()


async def test_aa_body_stored_when_encrypted(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "aa_enc.db", cipher=make_cipher(generate_key()))
    try:
        runner = RegistryRunner(_registry(), store)
        await runner._handle_inbound(runner.registry.inbound["IB_X"], ADT.encode())
        rows = await _ack_rows(store)
        assert rows[0].ack_code == "AA"
        assert rows[0].body is not None and "MSA" in rows[0].body  # the AA frame, decrypted
    finally:
        await store.close()


async def test_parse_nak_captured_without_body(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "nak.db")
    try:
        runner = RegistryRunner(_registry(), store)
        ack = await runner._handle_inbound(runner.registry.inbound["IB_X"], b"not an hl7 message")
        assert ack is not None  # AR NAK returned
        rows = await _ack_rows(store)
        assert rows[0].ack_code == "AR" and rows[0].ack_phase == "parse"
        assert rows[0].body is None  # a NAK frame is never persisted (#120)
        assert rows[0].detail is not None  # a scrubbed reason is
    finally:
        await store.close()


async def test_capture_off_per_connection(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "off_conn.db")
    try:
        runner = RegistryRunner(_registry(capture_ack=False), store)
        await runner._handle_inbound(runner.registry.inbound["IB_X"], ADT.encode())
        assert await _ack_rows(store) == []
    finally:
        await store.close()


async def test_capture_off_via_master_switch(tmp_path: Path) -> None:
    store = await MessageStore.open(tmp_path / "off_master.db")
    try:
        runner = RegistryRunner(_registry(), store, response_sent_default=False)
        await runner._handle_inbound(runner.registry.inbound["IB_X"], ADT.encode())
        assert await _ack_rows(store) == []
    finally:
        await store.close()
