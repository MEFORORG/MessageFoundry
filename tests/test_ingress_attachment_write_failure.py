# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #1619: a ``put_attachment`` failure during the streaming detach is recorded and NAK'd.

Both callers of ``_detach_documents`` caught only the budget, unsupported-backend and doc-ref
refusals, so a driver error from ``put_attachment`` escaped the ingress handler with no message row.
It now becomes an ``ERROR`` row and an ``AE`` (MLLP) or a refused receipt (HTTP), beside the other
detach refusals.

When the store is down hard, the ``ERROR`` write fails too. That still propagates, so the transport's
last-resort NAK answers the sender and the ACK-after-commit tests (BACKLOG #1608) keep holding.

Every injected arm has an unpatched control over the same body. Synthetic HL7 only, never real PHI.
"""

from __future__ import annotations

import base64
import sqlite3
from pathlib import Path
from typing import Any, NoReturn

import pytest

from messagefoundry.config.models import AckMode, ConnectorType, ContentType
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore

# A driver error whose text quotes a segment, the way one quoting a bound parameter would.
_FAULT_TEXT = "disk I/O error binding PID|1||MRN123^^^FAC||DOE^JOHN"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _body() -> bytes:
    b64 = base64.b64encode(b"P" * 2000).decode("ascii")
    return (
        "MSH|^~\\&|APP|FAC|RCV|RCVF|20260101120000||MDM^T02|MSGID001|P|2.5\r"
        "EVN|T02|20260101120000\r"
        "PID|1||MRN123^^^FAC||DOE^JOHN\r"
        f"OBX|1|ED|PDF^Report||^Application^PDF^Base64^{b64}||||||F\r"
    ).encode()


def _runner(
    store: MessageStore, ack_mode: AckMode = AckMode.ORIGINAL
) -> tuple[RegistryRunner, InboundConnection]:
    ic = InboundConnection(
        name="IB_STREAM",
        spec=ConnectionSpec(ConnectorType.MLLP, {"port": 0}),
        router="r",
        ack_mode=ack_mode,
        content_type=ContentType.HL7V2,
        stream_threshold_bytes=500,
    )
    reg = Registry()
    reg.add_inbound(ic)
    reg.add_router("r", lambda m: [])
    return RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False)), ic


async def _fail_put(*args: Any, **kwargs: Any) -> NoReturn:
    raise sqlite3.OperationalError(_FAULT_TEXT)


def _msa1(ack: str | None) -> str | None:
    for seg in (ack or "").replace("\n", "\r").split("\r"):
        if seg.startswith("MSA|"):
            return seg.split("|")[1]
    return None


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    cur = await store._db.execute("SELECT status, error FROM messages")
    return [dict(r) for r in await cur.fetchall()]


async def _attachment_count(store: MessageStore) -> int:
    cur = await store._db.execute("SELECT COUNT(*) FROM attachment")
    row = await cur.fetchone()
    assert row is not None
    return int(row[0])


@pytest.mark.parametrize(("ack_mode", "code"), [(AckMode.ORIGINAL, "AE"), (AckMode.ENHANCED, "CE")])
async def test_mllp_put_attachment_failure_records_error_and_naks(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch, ack_mode: AckMode, code: str
) -> None:
    runner, ic = _runner(store, ack_mode)
    monkeypatch.setattr(store, "put_attachment", _fail_put)

    ack = await runner._handle_inbound(ic, _body())

    assert _msa1(ack) == code
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    assert "attachment write failed" in rows[0]["error"]
    assert "OperationalError" in rows[0]["error"]
    assert "DOE^JOHN" not in rows[0]["error"], (
        "the driver text reached the stored reason unscrubbed"
    )
    assert await store.in_pipeline_depth() == 0, "an ingress row landed though the detach failed"
    assert runner._stream_inflight_bytes == 0, "the in-flight budget was not released"


async def test_http_put_attachment_failure_records_error_and_refuses(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    runner, ic = _runner(store)
    monkeypatch.setattr(store, "put_attachment", _fail_put)

    mid = await runner._handle_inbound_http(ic, _body())

    assert mid is None, "a receipt came back though the attachment write failed"
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]
    assert "attachment write failed" in rows[0]["error"]
    assert await store.in_pipeline_depth() == 0


class _StoreDown(RuntimeError):
    pass


async def test_store_down_for_the_error_write_too_still_propagates(
    store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The hard-outage arm: nothing can be recorded, so the handler raises and the transport's
    # last-resort NAK (transports/mllp.py) answers. No frame comes back from the runner itself.
    async def _down(*args: Any, **kwargs: Any) -> NoReturn:
        raise _StoreDown("store unavailable")

    runner, ic = _runner(store)
    monkeypatch.setattr(store, "put_attachment", _fail_put)
    monkeypatch.setattr(store, "record_received", _down)

    with pytest.raises(_StoreDown):
        await runner._handle_inbound(ic, _body())
    assert runner._stream_inflight_bytes == 0


async def test_control_healthy_detach_acks_aa(store: MessageStore) -> None:
    runner, ic = _runner(store)

    ack = await runner._handle_inbound(ic, _body())

    assert _msa1(ack) == "AA"
    assert await _attachment_count(store) == 1
    assert await store.in_pipeline_depth() == 1
