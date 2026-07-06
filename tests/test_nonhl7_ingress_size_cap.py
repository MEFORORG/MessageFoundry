# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""SEC-017 (CWE-770): engine-level ingress size guard for NON-HL7 content types.

The HL7 path enforces a 16 MiB ceiling via ``Peek.parse`` → ``enforce_size_limits``. The non-HL7
binary and text branches of ``_handle_inbound`` previously relied solely on the per-transport frame
cap (each individually disable-able). These tests prove the engine now applies the same ceiling as a
second layer of defense: an over-cap body is recorded ``ERROR`` (count-and-log, no ACK, no crash) and
an at/under-cap body is committed ``RECEIVED``.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _registry(name: str, content_type: ContentType) -> Registry:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name=name,
            spec=ConnectionSpec(ConnectorType.FILE, {}),
            router="r",
            content_type=content_type,
        )
    )
    reg.add_router("r", lambda m: [])  # no-op router; we never reach routing here
    return reg


async def _rows(store: MessageStore) -> list[dict]:
    cur = await store._db.execute("SELECT status, error, raw, message_type FROM messages")
    return [dict(r) for r in await cur.fetchall()]


# --- TEXT branch (JSON) -------------------------------------------------------


async def test_text_over_cap_records_error(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    body = ("x" * 100).encode("utf-8")  # 100 chars > 64 cap
    ack = await runner._handle_inbound(reg.inbound["IB_JSON"], body)

    assert ack is None  # no HL7 ACK for non-HL7
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert "exceeds max size" in rows[0]["error"]
    assert rows[0]["raw"] == "x" * 100  # raw preserved
    assert rows[0]["message_type"] == ContentType.JSON.value


async def test_text_under_cap_received(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_JSON"], b"hello")
    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.RECEIVED.value
    assert rows[0]["raw"] == "hello"


async def test_text_boundary_exact_cap_accepted(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_JSON", ContentType.JSON)
    runner = RegistryRunner(reg, store)

    # exactly len == cap is accepted (RECEIVED); cap + 1 is ERROR
    await runner._handle_inbound(reg.inbound["IB_JSON"], ("a" * 64).encode("utf-8"))
    await runner._handle_inbound(reg.inbound["IB_JSON"], ("b" * 65).encode("utf-8"))

    rows = sorted(await _rows(store), key=lambda r: len(r["raw"]))
    assert rows[0]["status"] == MessageStatus.RECEIVED.value  # 64 chars
    assert rows[1]["status"] == MessageStatus.ERROR.value  # 65 chars
    assert "exceeds max size" in rows[1]["error"]


# --- BINARY branch (DICOM) ----------------------------------------------------


async def test_binary_over_cap_records_error(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_DICOM", ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    # Include a NUL byte so we also prove the latin-1 lossless raw view round-trips for binary.
    body = b"\x00\xff" * 50  # 100 bytes > 64 cap
    ack = await runner._handle_inbound(reg.inbound["IB_DICOM"], body)

    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.ERROR.value
    assert "exceeds max size" in rows[0]["error"]
    # the latin-1 lossless raw is recoverable back to the exact bytes
    assert rows[0]["raw"].encode("latin-1") == body
    assert rows[0]["message_type"] == ContentType.DICOM.value


async def test_binary_under_cap_received(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_DICOM", ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    ack = await runner._handle_inbound(reg.inbound["IB_DICOM"], b"\x00\x01\x02\x03")
    assert ack is None
    rows = await _rows(store)
    assert len(rows) == 1
    assert rows[0]["status"] == MessageStatus.RECEIVED.value  # base64-carried, not ERROR


async def test_binary_boundary_measured_on_raw_bytes(store: MessageStore, monkeypatch) -> None:
    monkeypatch.setattr(wiring_runner, "_INGRESS_MAX_BYTES", 64)
    reg = _registry("IB_DICOM", ContentType.DICOM)
    runner = RegistryRunner(reg, store)

    # The cap is measured on the RAW bytes (pre-base64-inflation): 64 raw bytes is accepted even though
    # its base64 carriage form is larger; 65 raw bytes is rejected.
    await runner._handle_inbound(reg.inbound["IB_DICOM"], b"a" * 64)
    await runner._handle_inbound(reg.inbound["IB_DICOM"], b"b" * 65)

    rows = await _rows(store)
    statuses = sorted(r["status"] for r in rows)
    assert statuses == sorted([MessageStatus.RECEIVED.value, MessageStatus.ERROR.value])
