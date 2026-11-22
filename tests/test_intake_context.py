# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake context: a stored message names the peer that sent it (vault BACKLOG #2607).

Before this, ``InboundHandler`` took the body and nothing else, so a stored message carried no
address, port or certificate subject; only the connection-event log named a peer, with no message
id on inbound rows. These cases drive real MLLP, raw-TCP and file sources into the runner's own
handler over a real SQLite store, and read the intake context back from the message's metadata.

Synthetic HL7 only; every certificate is generated here.
"""

from __future__ import annotations

import asyncio
import json
import sqlite3
from pathlib import Path
from typing import Any

import pytest

from messagefoundry.config.models import ConnectorType, ContentType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.mllpcodec import AckMode
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.store.crypto import generate_key, make_cipher
from messagefoundry.store.metadata import (
    INTAKE_KEY,
    intake_metadata_json,
    intake_of,
    merge_user_metadata,
    user_metadata,
)
from messagefoundry.transports.intake import (
    IntakeAuth,
    IntakeContext,
    deliver,
    intake_handler,
    peer_address,
)
from messagefoundry.transports.mllp import MLLPSource
from messagefoundry.transports.tcp import TcpSource
from tests.test_mllp_sender_allowlist import (
    _PERSON,
    SUBJECT,
    _bundle,
    _ca,
    _exchange,
    _issuer,
    _settings,
)
from tests.test_mllp_tls import tls_path as tls_path  # a pytest fixture, used by name below

_INBOUND = "IB_ACME_ADT"
_ADT = "MSH|^~\\&|ACME|FAC|MF|FAC|20260101||ADT^A01|CTRL2607|P|2.5\rPID|1||MRN1^^^H^MR||Doe^Jane\r"


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _runner(
    store: MessageStore, connector: ConnectorType, settings: dict[str, Any]
) -> tuple[RegistryRunner, InboundConnection]:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name=_INBOUND,
            spec=ConnectionSpec(connector, settings),
            router="r",
            content_type=ContentType.HL7V2,
            ack_mode=AckMode.ORIGINAL,
        )
    )
    reg.add_router("r", lambda m: [])  # no worker runs, so routing is never reached
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    return runner, reg.inbound[_INBOUND]


async def _intakes(store: MessageStore) -> list[dict[str, Any] | None]:
    rows = await store.list_messages(allowed_channels=None)
    return [intake_of(await store.message_metadata_json(row["id"])) for row in rows]


# --- the seam ---------------------------------------------------------------------------------


async def test_deliver_hands_the_context_only_to_a_handler_that_takes_one() -> None:
    seen: list[tuple[bytes, IntakeContext | None]] = []
    ctx = IntakeContext(transport="mllp", peer_host="192.0.2.7", peer_port=40001)

    async def plain(raw: bytes) -> str | None:
        seen.append((raw, None))
        return "plain"

    @intake_handler
    async def aware(raw: bytes, intake: IntakeContext | None = None) -> str | None:
        seen.append((raw, intake))
        return "aware"

    assert await deliver(plain, b"a", ctx) == "plain"
    assert await deliver(aware, b"b", ctx) == "aware"
    assert await deliver(aware, b"c", None) == "aware"
    assert seen == [(b"a", None), (b"b", ctx), (b"c", None)]


def test_the_context_fields_leave_out_what_the_source_could_not_say() -> None:
    ctx = IntakeContext(
        transport="mllp",
        peer_host="192.0.2.7",
        peer_port=40001,
        auth_mode=IntakeAuth.MTLS,
    )
    assert ctx.fields() == {
        "transport": "mllp",
        "peer_host": "192.0.2.7",
        "peer_port": 40001,
        "auth_mode": "mtls",
    }
    assert peer_address(("::1", 2575, 0, 0)) == ("::1", 2575)
    assert peer_address("/tmp/sock") == (None, None)


def test_the_intake_key_survives_a_setmeta_merge_and_never_reaches_the_user_bag() -> None:
    stored = intake_metadata_json({"transport": "tcp", "peer_host": "192.0.2.7"})
    assert stored is not None and intake_metadata_json(None) is None
    merged = merge_user_metadata(stored, [("k", "v")])
    assert intake_of(merged) == {"transport": "tcp", "peer_host": "192.0.2.7"}
    assert json.loads(user_metadata(merged) or "{}") == {"k": "v"}
    assert user_metadata(stored) is None


# --- the runner writes it in the ingress transaction ------------------------------------------


async def test_the_runner_writes_the_context_into_the_committed_message(
    store: MessageStore,
) -> None:
    runner, ic = _runner(store, ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0})
    handler = runner._make_handler(ic)
    ctx = IntakeContext(transport="mllp", peer_host="192.0.2.7", peer_port=40001)
    reply = await deliver(handler, _ADT.encode(), ctx)
    assert reply is not None and "MSA|AA|CTRL2607" in reply
    # Control: a source that knows no peer still commits, with no context.
    await handler(_ADT.encode())
    intakes = await _intakes(store)
    assert sorted(intakes, key=lambda i: i is None) == [ctx.fields(), None]


async def test_the_context_is_encrypted_at_rest(tmp_path: Path) -> None:
    db = tmp_path / "enc.db"
    store = await MessageStore.open(db, cipher=make_cipher(generate_key()))
    try:
        runner, ic = _runner(store, ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0})
        ctx = IntakeContext(transport="mllp", cert_subject=f"CN={_PERSON}")
        await deliver(runner._make_handler(ic), _ADT.encode(), ctx)
        assert await _intakes(store) == [ctx.fields()]  # control: it decrypts back
    finally:
        await store.close()
    con = sqlite3.connect(db)
    try:
        (cell,) = con.execute("SELECT metadata FROM messages").fetchone()
    finally:
        con.close()
    assert cell and _PERSON not in cell and INTAKE_KEY not in cell


# --- the sources hand it over -----------------------------------------------------------------


async def test_an_mllp_mtls_sender_is_named_by_address_port_and_certificate(
    tmp_path: Path, store: MessageStore, tls_path: str
) -> None:
    named = _ca("Partner CA")
    settings = _settings(tmp_path, [named[0]], {_issuer(named): [SUBJECT]})
    runner, ic = _runner(store, ConnectorType.MLLP, settings)
    source = MLLPSource(Source(type=ConnectorType.MLLP, settings=settings, ack_mode=ic.ack_mode))
    source.content_type = ic.content_type
    source.refuse_unlisted_sender = runner._make_unlisted_sender_refusal(ic)
    await source.start(runner._make_handler(ic))
    try:
        reply, _ = await _exchange(source, _bundle(tmp_path, named), _ADT)
        port = source.sockport
    finally:
        await source.stop()
    assert b"MSA|AA|CTRL2607" in reply
    (intake,) = await _intakes(store)
    assert intake is not None
    assert intake["transport"] == "mllp"
    assert intake["peer_host"] == "127.0.0.1"
    assert isinstance(intake["peer_port"], int) and intake["peer_port"] != port
    assert intake["listener"] == f"127.0.0.1:{port}"
    assert intake["auth_mode"] == IntakeAuth.MTLS_SUBJECTS.value
    assert intake["cert_subject"] == f"CN={_PERSON}"


async def test_two_tcp_connections_from_one_address_are_told_apart_by_port(
    store: MessageStore,
) -> None:
    settings = {"host": "127.0.0.1", "port": 0, "framing": "mllp"}
    runner, ic = _runner(store, ConnectorType.TCP, settings)
    source = TcpSource(Source(type=ConnectorType.TCP, settings=settings, ack_mode=ic.ack_mode))
    source.content_type = ic.content_type
    await source.start(runner._make_handler(ic))
    try:
        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport)
            try:
                writer.write(b"\x0b" + _ADT.encode() + b"\x1c\r")
                await writer.drain()
                await asyncio.wait_for(reader.readuntil(b"\x1c\r"), 10.0)
            finally:
                writer.close()
    finally:
        await source.stop()
    intakes = await _intakes(store)
    assert len(intakes) == 2 and all(i is not None for i in intakes)
    assert {i["peer_host"] for i in intakes if i} == {"127.0.0.1"}
    assert len({i["peer_port"] for i in intakes if i}) == 2
    assert {i["auth_mode"] for i in intakes if i} == {IntakeAuth.NONE.value}


async def test_a_file_source_records_the_path_it_read(tmp_path: Path, store: MessageStore) -> None:
    from messagefoundry.transports.file import FileSource

    inbox = tmp_path / "in"
    inbox.mkdir()
    dropped = inbox / "adt.hl7"
    dropped.write_bytes(_ADT.encode())
    settings = {"directory": str(inbox), "poll_seconds": 0.05}
    runner, ic = _runner(store, ConnectorType.FILE, settings)
    source = FileSource(Source(type=ConnectorType.FILE, settings=settings))
    source.content_type = ic.content_type
    await source.start(runner._make_handler(ic))
    try:
        for _ in range(200):
            if await store.list_messages(allowed_channels=None):
                break
            await asyncio.sleep(0.05)
    finally:
        await source.stop()
    rows = await store.list_messages(allowed_channels=None)
    assert [r["status"] for r in rows] == [MessageStatus.RECEIVED.value]
    assert await _intakes(store) == [{"transport": "file", "source": str(dropped)}]


async def test_a_message_the_engine_makes_from_another_carries_no_intake_key(
    store: MessageStore,
) -> None:
    """INTAKE_KEY's statement, for edit-and-resubmit: the child keeps lineage only, and its
    ``correlation_root_id`` leads back to the message that names the peer."""
    from tests._store_audit import no_operator_audit

    ctx = IntakeContext(transport="mllp", peer_host="192.0.2.7", peer_port=40001)
    origin = await store.enqueue_ingress(
        channel_id=_INBOUND, raw=_ADT, metadata=intake_metadata_json(ctx.fields())
    )
    out = await store.reingress(
        origin_message_id=origin, raw=_ADT, idempotency_key="k2607", audit=no_operator_audit
    )
    assert out.new_message_id and out.new_message_id != origin
    child = json.loads(await store.message_metadata_json(out.new_message_id) or "{}")
    assert INTAKE_KEY not in child
    assert child["correlation_root_id"] == origin
    # Control: the origin still names its peer.
    assert intake_of(await store.message_metadata_json(origin)) == ctx.fields()
