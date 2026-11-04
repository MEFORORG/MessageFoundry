# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The MLLP listener's expected-sender allowlist, ``tls_client_subjects`` (BACKLOG #4907).

``tls_ca_file`` alone admits any certificate its CAs ever signed. With ``tls_client_subjects`` set,
a verified certificate with no listed name under the loaded CA whose key signed it is refused: its
first message is recorded as an ``ERROR`` row BEFORE it is answered ``AR``, and the connection closes.

These cases drive REAL TLS handshakes against a running :class:`MLLPSource`, with the runner's own
inbound handler and refusal bound to a real SQLite store, because the claims are about what OpenSSL
verified and what the store holds. The CA and client-certificate builders are
``tests/test_api_tls.py``'s, the ones the HTTP listener's issuer cases use. Every certificate is
generated here; no key leaves the test's temporary directory.

Each refusal has a control beside it that differs only in the one thing under test, so a listener
that refused everyone could not pass.
"""

from __future__ import annotations

import asyncio
import datetime
import logging
import ssl
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, ContentType, Source
from messagefoundry.config.settings import EgressSettings
from messagefoundry.config.wiring import (
    MLLP,
    ConnectionSpec,
    InboundConnection,
    Registry,
    WiringError,
    env,
    load_config,
)
from messagefoundry.pipeline.wiring_runner import RegistryRunner
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports.mllp import MLLPSource
from tests.test_api_tls import _NOW, _CaPair, _client_bundle, _dn, _new_ca, _pem, _self_signed
from tests.test_connections_file import _config

_INBOUND = "IB_ACME_ADT"
#: A subject that reads like a person, so the leak assertions below look for something specific.
_PERSON = "jane.q.sender.example"
SUBJECT = f"CN:{_PERSON}"
# Synthetic HL7 only (never real PHI).
_ADT = "MSH|^~\\&|ACME|FAC|MF|FAC|20260101||ADT^A01|CTRL4907|P|2.5\rPID|1||MRN1^^^H^MR||Doe^Jane\r"
_JSON = '{"synthetic": true}'


def _ca(cn: str) -> _CaPair:
    """``tests/test_api_tls.py``'s CA, with the ``keyUsage`` the listener's strict verify needs."""
    return _new_ca(
        _dn((NameOID.ORGANIZATION_NAME, "Synthetic"), (NameOID.COMMON_NAME, cn)),
        None,
        key_usage=True,
    )


def _issuer(ca: _CaPair) -> str:
    return ca[0].subject.rfc4514_string()


def _bundle(tmp_path: Path, signer: _CaPair, cn: str = _PERSON) -> Path:
    return _client_bundle(tmp_path, signer, cn=cn)


def _san_bundle(tmp_path: Path, signer: _CaPair, *, cn: str, dns: str) -> Path:
    """A client leaf carrying a DNS subjectAltName, signed by ``signer``."""
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_dn((NameOID.COMMON_NAME, cn)))
        .issuer_name(signer[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(minutes=5))
        .not_valid_after(_NOW + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns)]), critical=False)
        .add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer[1].public_key()),
            critical=False,
        )
        .sign(signer[1], hashes.SHA256())
    )
    bundle = tmp_path / f"san-{len(list(tmp_path.iterdir()))}.pem"
    bundle.write_bytes(
        _pem(leaf)
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return bundle


def _settings(
    tmp_path: Path, trusted: list[x509.Certificate], subjects: dict[str, list[str]] | None
) -> dict[str, Any]:
    """An MLLP inbound's settings through the ``MLLP()`` factory: loopback, mTLS against ``trusted``."""
    cert, key = _self_signed(tmp_path)
    ca_file = tmp_path / "client-ca.pem"
    ca_file.write_bytes(b"".join(_pem(c) for c in trusted))
    spec = MLLP(
        port=0,
        tls=True,
        tls_cert_file=str(cert),
        tls_key_file=str(key),
        tls_ca_file=str(ca_file),
        tls_client_subjects=subjects,
    )
    return {**spec.settings, "host": "127.0.0.1"}


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _runner(
    store: MessageStore, content_type: ContentType = ContentType.HL7V2
) -> tuple[RegistryRunner, InboundConnection]:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name=_INBOUND,
            spec=ConnectionSpec(ConnectorType.FILE, {}),
            router="r",
            content_type=content_type,
        )
    )
    reg.add_router("r", lambda m: [])  # no worker runs, so routing is never reached
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    return runner, reg.inbound[_INBOUND]


async def _wired(
    settings: dict[str, Any], store: MessageStore, content_type: ContentType = ContentType.HL7V2
) -> MLLPSource:
    """The listener started with the runner's handler and refusal, as ``_start_inbound`` wires them."""
    runner, ic = _runner(store, content_type)
    source = MLLPSource(Source(type=ConnectorType.MLLP, settings=settings))
    source.content_type = content_type
    source.refuse_unlisted_sender = runner._make_unlisted_sender_refusal(ic)
    await source.start(runner._make_handler(ic))
    return source


async def _exchange(source: MLLPSource, bundle: Path, body: str = _ADT) -> tuple[bytes, bytes]:
    """Send one framed message presenting ``bundle``; return ``(reply frame, bytes after it)``.

    The second element is read to EOF, so a listener that kept the connection open fails the case
    on the timeout rather than passing it."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the LISTENER side is the verifier under test
    ctx.load_cert_chain(bundle)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport, ssl=ctx)
    try:
        writer.write(b"\x0b" + body.encode("utf-8") + b"\x1c\r")
        await writer.drain()
        reply = await asyncio.wait_for(reader.readuntil(b"\x1c\r"), 10.0)
        try:
            rest = await asyncio.wait_for(reader.read(-1), 2.0)
        except TimeoutError:
            rest = b"<still open>"
    finally:
        writer.close()
    return reply, rest


async def _rows(store: MessageStore) -> list[dict[str, Any]]:
    listed = await store.list_messages(allowed_channels=None)
    return [await store.get_message(row["id"]) or {} for row in listed]


async def test_a_listed_sender_is_accepted_and_another_ca_issuing_its_name_is_refused(
    tmp_path: Path, store: MessageStore, caplog: pytest.LogCaptureFixture
) -> None:
    """The two-CA case: both chains verify at the TLS layer, and only the issuer differs."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}), store
    )
    try:
        # Control: the listed name from the CA it is listed under is accepted (AA) and committed.
        reply, _ = await _exchange(source, _bundle(tmp_path, named))
        assert b"MSA|AA|CTRL4907" in reply
        with caplog.at_level(logging.DEBUG):
            reply, rest = await _exchange(source, _bundle(tmp_path, other))
    finally:
        await source.stop()
    assert b"MSA|AR|CTRL4907" in reply and b"sender not permitted" in reply
    assert rest == b"", "the connection stayed open after the refusal"
    rows = await _rows(store)
    statuses = sorted(r["status"] for r in rows)
    assert statuses == sorted([MessageStatus.RECEIVED.value, MessageStatus.ERROR.value]), statuses
    (error_row,) = [r for r in rows if r["status"] == MessageStatus.ERROR.value]
    assert "certificate-subject allowlist" in error_row["error"]
    # No subject text in the row, the reply or any log line: a subject can name a person.
    assert _PERSON not in error_row["error"]
    assert _PERSON.encode() not in reply
    assert not [r for r in caplog.records if _PERSON in r.getMessage()]
    assert any("not on tls_client_subjects" in r.getMessage() for r in caplog.records)


async def test_an_unlisted_name_from_the_listed_ca_is_refused(
    tmp_path: Path, store: MessageStore
) -> None:
    named = _ca("Partner CA")
    source = await _wired(_settings(tmp_path, [named[0]], {_issuer(named): [SUBJECT]}), store)
    try:
        reply, rest = await _exchange(source, _bundle(tmp_path, named, cn="someone.else.example"))
        # Control on the same listener: the listed name is accepted.
        accepted, _ = await _exchange(source, _bundle(tmp_path, named))
    finally:
        await source.stop()
    assert b"MSA|AR|" in reply and rest == b""
    assert b"MSA|AA|" in accepted
    assert sorted(r["status"] for r in await _rows(store)) == sorted(
        [MessageStatus.ERROR.value, MessageStatus.RECEIVED.value]
    )


async def test_a_san_entry_matches_and_a_cn_entry_does_not_match_a_san(
    tmp_path: Path, store: MessageStore
) -> None:
    """Names are qualified: ``SAN:DNS:<v>`` matches a DNS subjectAltName exactly, and a ``CN:``
    entry with the same text does not, so a commonName cannot stand in for a pinned SAN."""
    named = _ca("Partner CA")
    (tmp_path / "san").mkdir()
    (tmp_path / "cn").mkdir()
    san_only = _settings(
        tmp_path / "san", [named[0]], {_issuer(named): ["SAN:DNS:feed.partner.example"]}
    )
    cn_only = _settings(tmp_path / "cn", [named[0]], {_issuer(named): ["CN:feed.partner.example"]})
    bundle = _san_bundle(tmp_path, named, cn="unrelated.example", dns="feed.partner.example")
    source = await _wired(san_only, store)
    try:
        accepted, _ = await _exchange(source, bundle)
    finally:
        await source.stop()
    source = await _wired(cn_only, store)
    try:
        refused, _ = await _exchange(source, bundle)
    finally:
        await source.stop()
    assert b"MSA|AA|" in accepted
    assert b"MSA|AR|" in refused


async def test_matching_is_exact_and_case_sensitive(tmp_path: Path, store: MessageStore) -> None:
    named = _ca("Partner CA")
    source = await _wired(
        _settings(tmp_path, [named[0]], {_issuer(named): [SUBJECT.upper()]}), store
    )
    try:
        reply, _ = await _exchange(source, _bundle(tmp_path, named))
    finally:
        await source.stop()
    assert b"MSA|AR|" in reply


async def test_without_the_allowlist_any_verified_certificate_is_accepted(
    tmp_path: Path, store: MessageStore
) -> None:
    """Off by default: the setting unset leaves a bare mTLS listener as it was."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(_settings(tmp_path, [named[0], other[0]], None), store)
    try:
        reply, _ = await _exchange(source, _bundle(tmp_path, other))
    finally:
        await source.stop()
    assert b"MSA|AA|" in reply


async def test_the_error_row_is_committed_before_the_ar(
    tmp_path: Path, store: MessageStore, monkeypatch: pytest.MonkeyPatch
) -> None:
    """If the ERROR row cannot be written, no AR goes back: the sender gets the handler-fault AE,
    which tells it to resend, and nothing is recorded. The AR is built only from a committed row."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}), store
    )

    async def failing(*_args: Any, **_kwargs: Any) -> str:
        raise RuntimeError("injected store failure")

    monkeypatch.setattr(store, "record_received", failing)
    try:
        reply, rest = await _exchange(source, _bundle(tmp_path, other))
    finally:
        await source.stop()
    assert b"MSA|AE|" in reply and b"MSA|AR|" not in reply
    assert rest == b""
    assert await _rows(store) == []


async def test_a_non_hl7_feed_records_the_message_and_closes_with_no_reply(
    tmp_path: Path, store: MessageStore
) -> None:
    """There is no HL7 reply to give on a feed that is not HL7 v2, so the refusal there is the
    close, with nothing written; the message is still recorded as ERROR."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}),
        store,
        ContentType.JSON,
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(_bundle(tmp_path, other))
    try:
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport, ssl=ctx)
        try:
            writer.write(b"\x0b" + _JSON.encode() + b"\x1c\r")
            await writer.drain()
            got = await asyncio.wait_for(reader.read(-1), 10.0)
        finally:
            writer.close()
    finally:
        await source.stop()
    assert got == b""
    rows = await _rows(store)
    assert [r["status"] for r in rows] == [MessageStatus.ERROR.value]


async def test_a_source_with_no_refusal_wired_reads_nothing_from_a_refused_sender(
    tmp_path: Path,
) -> None:
    """Built outside the runner, nothing can record the message, so none is read: the sender keeps
    it. The control on the same listener shows the handler does run for a listed sender."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    handled: list[bytes] = []

    async def handler(raw: bytes) -> str | None:
        handled.append(raw)
        return None

    source = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings=_settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}),
        )
    )
    await source.start(handler)

    async def send(bundle: Path) -> bytes:
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.load_cert_chain(bundle)
        reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport, ssl=ctx)
        try:
            writer.write(b"\x0b" + _ADT.encode() + b"\x1c\r")
            await writer.drain()
            try:
                return await asyncio.wait_for(reader.read(-1), 2.0)
            except TimeoutError:
                return b"<still open>"
        except ConnectionError:
            return b""
        finally:
            writer.close()

    try:
        refused = await send(_bundle(tmp_path, other))
        assert handled == []
        assert refused == b""
        await send(_bundle(tmp_path, named))  # control
    finally:
        await source.stop()
    assert len(handled) == 1


def test_an_issuer_key_naming_no_loaded_ca_is_warned_about(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    named = _ca("Partner CA")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
        MLLPSource(
            Source(
                type=ConnectorType.MLLP,
                settings=_settings(
                    tmp_path, [named[0]], {_issuer(named): [SUBJECT], "CN=Missing CA": [SUBJECT]}
                ),
            )
        )
    warned = [r.getMessage() for r in caplog.records]
    assert any("'CN=Missing CA'" in m and "names no CA" in m for m in warned), warned
    assert not any(_issuer(named) in m for m in warned), warned


def test_a_direct_build_without_a_client_ca_is_refused(tmp_path: Path) -> None:
    cert, key = _self_signed(tmp_path)
    with pytest.raises(ValueError, match="needs tls=true and tls_ca_file"):
        MLLPSource(
            Source(
                type=ConnectorType.MLLP,
                settings={
                    "host": "127.0.0.1",
                    "port": 0,
                    "tls": True,
                    "tls_cert_file": str(cert),
                    "tls_key_file": str(key),
                    "tls_client_subjects": {"CN=Partner CA": [SUBJECT]},
                },
            )
        )


@pytest.mark.parametrize("subjects", [[SUBJECT], {"CN=Partner CA": SUBJECT}, {}])
def test_a_direct_build_refuses_a_table_that_is_not_one(subjects: Any) -> None:
    with pytest.raises(ValueError, match="must be a non-empty table keyed by the issuing CA's DN"):
        MLLPSource(
            Source(
                type=ConnectorType.MLLP,
                settings={"host": "127.0.0.1", "port": 0, "tls_client_subjects": subjects},
            )
        )


# --- the factory -----------------------------------------------------------------------------------


def _mllp(subjects: Any, **overrides: Any) -> Any:
    kwargs: dict[str, Any] = {
        "port": 2575,
        "tls": True,
        "tls_cert_file": "server.pem",
        "tls_key_file": "server.key",
        "tls_ca_file": "ca.pem",
        "tls_client_subjects": subjects,
    }
    kwargs.update(overrides)
    return MLLP(**kwargs)


@pytest.mark.parametrize(
    ("subjects", "overrides", "message"),
    [
        pytest.param({}, {}, "names no issuing CA", id="empty-table"),
        pytest.param([SUBJECT], {}, "must be a table keyed by the DN of the CA", id="flat-list"),
        pytest.param({"CN=Partner CA": []}, {}, "names no subjects", id="empty-list"),
        pytest.param({"CN=Partner CA": ["partner.example"]}, {}, "must be qualified", id="bare"),
        pytest.param({"CN=Partner CA": ["CN:"]}, {}, "must be qualified", id="empty-cn"),
        pytest.param({"not a dn": [SUBJECT]}, {}, "is not an RFC 4514", id="not-a-dn"),
        pytest.param(env("subjects"), {}, "may not be an env", id="env-table"),
        pytest.param(
            {"CN=Partner CA": [SUBJECT]}, {"tls_ca_file": None}, "needs tls=True", id="no-ca"
        ),
        pytest.param({"CN=Partner CA": [SUBJECT]}, {"tls": False}, "needs tls=True", id="no-tls"),
    ],
)
def test_the_factory_refuses_what_cannot_work(
    subjects: Any, overrides: dict[str, Any], message: str
) -> None:
    with pytest.raises(WiringError, match=message) as excinfo:
        _mllp(subjects, **overrides)
    assert "MLLP tls_client_subjects" in str(excinfo.value)


def test_the_factory_carries_a_valid_table_and_leaves_it_off_by_default() -> None:
    spec = _mllp({"CN=Partner CA": [SUBJECT, "SAN:DNS:feed.partner.example"]})
    assert spec.settings["tls_client_subjects"] == {
        "CN=Partner CA": [SUBJECT, "SAN:DNS:feed.partner.example"]
    }
    assert MLLP(port=2575).settings["tls_client_subjects"] is None


def test_connections_toml_desugars_the_table_through_the_factory(tmp_path: Path) -> None:
    """A ``connections.toml`` inbound reaches the same factory, and its refusals with it."""
    head = """
        [[inbound]]
        name = "IB_ACME_ADT"
        transport = "mllp"
        router = "r"
          [inbound.settings]
          port = 2600
          tls = true
          tls_cert_file = "server.pem"
          tls_key_file = "server.key"
          tls_ca_file = "ca.pem"
          [inbound.settings.tls_client_subjects]
          "CN=Partner CA" = [NAMES]
    """
    (tmp_path / "ok").mkdir()
    ok = head.replace("NAMES", '"SAN:DNS:feed.partner.example"')
    reg = load_config(_config(tmp_path / "ok", ok))
    assert reg.inbound[_INBOUND].spec.settings["tls_client_subjects"] == {
        "CN=Partner CA": ["SAN:DNS:feed.partner.example"]
    }
    (tmp_path / "bad").mkdir()
    with pytest.raises(WiringError, match="must be qualified"):
        load_config(_config(tmp_path / "bad", head.replace("NAMES", '"feed.partner.example"')))
