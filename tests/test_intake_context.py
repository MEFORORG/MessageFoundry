# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The intake context: a stored message records how its sender was admitted (vault BACKLOG #2607).

Before this, ``InboundHandler`` took the body and nothing else, so a stored message did not record
how its sender was admitted; only the connection-event log named a peer, with no message
id on inbound rows. These cases drive real MLLP, raw-TCP and file sources into the runner's own
handler over a real SQLite store, and read the intake context back from the message's metadata.

Synthetic HL7 only; every certificate is generated here.
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
import sqlite3
import ssl
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
    IntakeHandler,
    deliver,
    intake_handler,
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
#: An IPv4 dotted quad, or a run of hex groups joined by colons with a ``::`` or at least three
#: groups, which is how an IPv6 address reads.
_IP_SHAPED = re.compile(
    r"\b\d{1,3}(?:\.\d{1,3}){3}\b|[0-9A-Fa-f]{0,4}::[0-9A-Fa-f:]*|"
    r"\b[0-9A-Fa-f]{1,4}(?::[0-9A-Fa-f]{1,4}){2,}\b"
)
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
    ctx = IntakeContext(transport="mllp", auth_mode=IntakeAuth.NONE)

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


async def test_an_intake_handler_always_gets_the_keyword_and_a_wrong_one_fails_when_built() -> None:
    calls: list[dict[str, Any]] = []

    async def keyword_only(raw: bytes, *, intake: IntakeContext | None = None) -> str:
        calls.append({"raw": raw, "intake": intake})
        return "ok"

    wrapped = intake_handler(keyword_only)
    assert isinstance(wrapped, IntakeHandler)
    assert await deliver(wrapped, b"x", None) == "ok"
    assert calls == [{"raw": b"x", "intake": None}]

    async def one_argument(raw: bytes) -> str:
        return "no"

    async def required_intake(raw: bytes, intake: IntakeContext) -> str:
        return "no"

    for wrong in (one_argument, required_intake):
        with pytest.raises(TypeError, match="optional intake= keyword"):
            intake_handler(wrong)


async def test_a_one_argument_wrapper_around_the_runners_handler_is_not_given_the_context() -> None:
    """functools.wraps copies attributes, which broke an attribute mark; the class check does not
    carry over, so the wrapper is called with the body alone rather than failing every frame."""
    import functools

    @intake_handler
    async def inner(raw: bytes, intake: IntakeContext | None = None) -> str:
        return "inner"

    @functools.wraps(inner)
    async def outer(raw: bytes) -> str:
        return await inner(raw)

    ctx = IntakeContext(transport="mllp", auth_mode=IntakeAuth.NONE)
    assert await deliver(outer, b"x", ctx) == "inner"


def test_peer_subject_raises_a_defect_and_reads_an_unreadable_certificate_as_none() -> None:
    from messagefoundry.pki import peer_subject

    class _Raises:
        def __init__(self, exc: BaseException) -> None:
            self._exc = exc

        def getpeercert(self, binary_form: bool = False) -> bytes:
            raise self._exc

    assert peer_subject(_Raises(ValueError("handshake not done"))) is None
    assert peer_subject(_Raises(ssl.SSLError("bad"))) is None
    # Not a ValueError: cryptography raises it for a leaf version it cannot read, which OpenSSL
    # may still have verified, so it must not close the admitted sender's connection.
    from cryptography import x509 as _x509

    assert peer_subject(_Raises(_x509.InvalidVersion("unknown version", 7))) is None
    assert peer_subject(object()) is None  # no getpeercert: no certificate
    assert peer_subject(None) is None
    with pytest.raises(RuntimeError):
        peer_subject(_Raises(RuntimeError("a defect")))


def test_the_context_fields_leave_out_what_the_source_could_not_say() -> None:
    ctx = IntakeContext(
        transport="mllp",
        auth_mode=IntakeAuth.MTLS,
    )
    assert ctx.fields() == {"transport": "mllp", "auth_mode": "mtls"}


def test_the_intake_key_survives_a_setmeta_merge_and_never_reaches_the_user_bag() -> None:
    stored = intake_metadata_json({"transport": "tcp", "auth_mode": "none"})
    assert stored is not None and intake_metadata_json(None) is None
    merged = merge_user_metadata(stored, [("k", "v")])
    assert intake_of(merged) == {"transport": "tcp", "auth_mode": "none"}
    assert json.loads(user_metadata(merged) or "{}") == {"k": "v"}
    assert user_metadata(stored) is None


# --- the runner writes it in the ingress transaction ------------------------------------------


async def test_the_runner_writes_the_context_into_the_committed_message(
    store: MessageStore,
) -> None:
    runner, ic = _runner(store, ConnectorType.MLLP, {"host": "127.0.0.1", "port": 0})
    handler = runner._make_handler(ic)
    ctx = IntakeContext(transport="mllp", auth_mode=IntakeAuth.NONE)
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


async def test_an_mllp_mtls_sender_is_named_by_its_certificate_not_its_address(
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
    finally:
        await source.stop()
    assert b"MSA|AA|CTRL2607" in reply
    (intake,) = await _intakes(store)
    assert intake is not None
    assert intake["transport"] == "mllp"
    # Owner ruling 2026-11-22, "No IP in metadata": the stored context holds no socket address.
    assert not _IP_SHAPED.search(json.dumps(intake))
    assert intake["auth_mode"] == IntakeAuth.MTLS_SUBJECTS.value
    assert intake["cert_subject"] == f"CN={_PERSON}"


async def test_a_defect_reading_the_subject_still_serves_the_sender(
    tmp_path: Path,
    store: MessageStore,
    tls_path: str,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The intake record is optional, so an unexpected exception from ``peer_subject`` on a plain
    mTLS listener must not cut off a sender that was served before the record existed: the message is ACKed and stored
    without a subject, and one ERROR line names the exception's type but not its message."""
    import messagefoundry.pki as pki

    def broken(_ssl_object: object) -> str | None:
        raise RuntimeError(f"defect quoting {_PERSON}")

    monkeypatch.setattr(pki, "peer_subject", broken)
    named = _ca("Partner CA")
    settings = _settings(tmp_path, [named[0]], None)  # mTLS, no tls_client_subjects
    runner, ic = _runner(store, ConnectorType.MLLP, settings)
    source = MLLPSource(Source(type=ConnectorType.MLLP, settings=settings, ack_mode=ic.ack_mode))
    source.content_type = ic.content_type
    await source.start(runner._make_handler(ic))
    try:
        with caplog.at_level(logging.ERROR):
            reply, _ = await _exchange(source, _bundle(tmp_path, named), _ADT)
    finally:
        await source.stop()
    assert b"MSA|AA|CTRL2607" in reply
    rows = await store.list_messages(allowed_channels=None)
    assert [r["status"] for r in rows] == [MessageStatus.RECEIVED.value]
    assert await _intakes(store) == [{"transport": "mllp", "auth_mode": IntakeAuth.MTLS.value}]
    errors = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert len(errors) == 1, [r.getMessage() for r in errors]
    line = errors[0].getMessage()
    assert "RuntimeError" in line and "broken" in line
    assert _PERSON not in line and errors[0].exc_info is None


async def test_the_stored_context_holds_no_peer_address(
    store: MessageStore,
) -> None:
    """Owner ruling 2026-11-22, "No IP in metadata". No IP-shaped value, and neither the
    listener's port nor any client's own port, appears in the stored cell."""
    settings = {"host": "127.0.0.1", "port": 0, "framing": "mllp"}
    runner, ic = _runner(store, ConnectorType.TCP, settings)
    source = TcpSource(Source(type=ConnectorType.TCP, settings=settings, ack_mode=ic.ack_mode))
    source.content_type = ic.content_type
    await source.start(runner._make_handler(ic))
    client_ports: list[int] = []
    listen_port = source.sockport
    try:
        for _ in range(2):
            reader, writer = await asyncio.open_connection("127.0.0.1", listen_port)
            client_ports.append(writer.get_extra_info("sockname")[1])
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
    # Control: the context was stored for both connections.
    assert {i["auth_mode"] for i in intakes if i} == {IntakeAuth.NONE.value}
    rows = await store.list_messages(allowed_channels=None)
    cells = [await store.message_metadata_json(row["id"]) or "" for row in rows]
    for cell in cells:
        assert cell and not _IP_SHAPED.search(cell), cell
        for port in [listen_port, *client_ports]:
            assert str(port) not in cell


def test_the_ip_shape_check_finds_an_address() -> None:
    """The positive control for :data:`_IP_SHAPED`, so a check that finds nothing proves something."""
    assert _IP_SHAPED.search('{"x": "127.0.0.1:2575"}')
    assert _IP_SHAPED.search('{"x": "[::1]:2575"}')
    assert _IP_SHAPED.search('{"x": "fe80::1"}')
    assert not _IP_SHAPED.search(
        '{"auth_mode": "mtls", "cert_subject": "CN=jane.q.sender.example"}'
    )


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


def test_a_san_only_leaf_records_no_subject_rather_than_an_empty_one() -> None:
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    from messagefoundry.pki import peer_subject

    def leaf_der(subject: x509.Name) -> bytes:
        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.UTC)
        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, "CA")]))
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now)
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(
                x509.SubjectAlternativeName([x509.DNSName("partner.example")]), critical=True
            )
            .sign(key, hashes.SHA256())
        )
        return cert.public_bytes(serialization.Encoding.DER)

    class _Ssl:
        def __init__(self, der: bytes) -> None:
            self._der = der

        def getpeercert(self, binary_form: bool = False) -> bytes:
            return self._der

    assert peer_subject(_Ssl(leaf_der(x509.Name([])))) is None
    # Control: a leaf with a subject is named.
    named = x509.Name([x509.NameAttribute(x509.oid.NameOID.COMMON_NAME, _PERSON)])
    assert peer_subject(_Ssl(leaf_der(named))) == f"CN={_PERSON}"


async def test_a_message_the_engine_makes_from_another_carries_no_intake_key(
    store: MessageStore,
) -> None:
    """INTAKE_KEY's statement, for edit-and-resubmit: the child keeps lineage only, and its
    ``correlation_root_id`` leads back to the message that carries the context."""
    from tests._store_audit import no_operator_audit

    ctx = IntakeContext(transport="mllp", auth_mode=IntakeAuth.NONE)
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
    # Control: the origin still carries its context.
    assert intake_of(await store.message_metadata_json(origin)) == ctx.fields()
