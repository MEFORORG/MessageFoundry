# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The MLLP listener's expected-sender allowlist, ``tls_client_subjects`` (BACKLOG #4907).

``tls_ca_file`` alone admits any certificate its CAs ever signed. With ``tls_client_subjects`` set,
a verified certificate with no listed name under the loaded CA whose key signed it is refused: each
message its first read completes is recorded as an ``ERROR`` row BEFORE it is answered ``AR``, and
the connection closes.

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
import functools
import inspect
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
    INTAKE_AUTH_RATE_LIMIT_DEFAULT,
    INTAKE_AUTH_RATE_LIMIT_GLOBAL_DEFAULT,
    MLLP,
    ConnectionSpec,
    Http,
    InboundConnection,
    Registry,
    WiringError,
    env,
    load_config,
)
from messagefoundry.credential import OTHERNAMES_INTACT_KEY, cert_name_candidates
from messagefoundry.mllpcodec import AckMode
from messagefoundry.pipeline import wiring_runner
from messagefoundry.pipeline.wiring_runner import RegistryRunner, _IntakeRateLimiter
from messagefoundry.pki import san_othernames_intact
from messagefoundry.store import MessageStatus, MessageStore
from messagefoundry.transports import mllp as mllp_module
from messagefoundry.transports.mllp import _SENDER_DENIED, _SENDER_RATE_LIMITED, MLLPSource
from tests.test_api_tls import (
    _NOW,
    _NUL_UPN,
    _CaPair,
    _client_bundle,
    _dn,
    _new_ca,
    _pem,
    _self_signed,
    _upn,
)
from tests.test_connections_file import _config
from tests.test_mllp_tls import tls_path  # noqa: F401  -- a pytest fixture, used by name below

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


def _san_bundle(
    tmp_path: Path,
    signer: _CaPair,
    *,
    cn: str,
    dns: str,
    other: tuple[x509.GeneralName, ...] = (),
) -> Path:
    """A client leaf carrying a DNS subjectAltName, and any ``other`` names, signed by ``signer``."""
    key = ec.generate_private_key(ec.SECP256R1())
    leaf = (
        x509.CertificateBuilder()
        .subject_name(_dn((NameOID.COMMON_NAME, cn)))
        .issuer_name(signer[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(minutes=5))
        .not_valid_after(_NOW + datetime.timedelta(days=1))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName(dns), *other]), critical=False)
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
    tmp_path: Path,
    trusted: list[x509.Certificate],
    subjects: dict[str, list[str]] | None,
    **extra: Any,
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
        **extra,
    )
    return {**spec.settings, "host": "127.0.0.1"}


@pytest.fixture
async def store(tmp_path: Path):
    s = await MessageStore.open(tmp_path / "engine.db")
    yield s
    await s.close()


def _assert_tls_path(source: MLLPSource, tls_path: str) -> None:  # noqa: F811
    """The control for the ``tls_path`` fixture, which runs a case both ways the listener admits a
    socket before its handshake (BACKLOG #1606): the listener runs the path the case names, so the
    sender check is shown behind the listener's own accept loop too."""
    accept_loop = isinstance(source._server, mllp_module._AcceptingServer)
    assert accept_loop == (tls_path == "accept_loop"), (tls_path, source._server)


def _runner(
    store: MessageStore,
    settings: dict[str, Any],
    content_type: ContentType = ContentType.HL7V2,
    ack_mode: AckMode = AckMode.ORIGINAL,
) -> tuple[RegistryRunner, InboundConnection]:
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name=_INBOUND,
            spec=ConnectionSpec(ConnectorType.MLLP, settings),
            router="r",
            content_type=content_type,
            ack_mode=ack_mode,
        )
    )
    reg.add_router("r", lambda m: [])  # no worker runs, so routing is never reached
    runner = RegistryRunner(reg, store, egress=EgressSettings(deny_by_default=False))
    return runner, reg.inbound[_INBOUND]


async def _wired(
    settings: dict[str, Any],
    store: MessageStore,
    content_type: ContentType = ContentType.HL7V2,
    ack_mode: AckMode = AckMode.ORIGINAL,
    events: list[tuple[str, str | None, str | None]] | None = None,
) -> MLLPSource:
    """The listener started with the runner's handler, refusal, failed-attempt budget and audit
    sink, as ``_start_inbound`` wires them. ``events`` collects its connection events."""
    runner, ic = _runner(store, settings, content_type, ack_mode)
    source = MLLPSource(Source(type=ConnectorType.MLLP, settings=settings, ack_mode=ack_mode))
    source.content_type = content_type
    source.refuse_unlisted_sender = runner._make_unlisted_sender_refusal(ic)
    source.intake_rate_limiter = runner._make_intake_rate_limiter(ic)
    source.on_intake_audit = runner._make_intake_audit_sink(ic)
    if events is not None:

        async def collect(kind: str, peer_host: str | None, reason: str | None) -> None:
            events.append((kind, peer_host, reason))

        source.on_connection_event = collect
    await source.start(runner._make_handler(ic))
    return source


#: A failed-attempt window no test run reaches, for the tests that spend a whole budget.
_LONG_WINDOW_SECONDS = 3600.0


@pytest.fixture
def long_window(monkeypatch: pytest.MonkeyPatch) -> None:
    """The runner's budget with the factory's own counts but a window no test run reaches.

    A test that spends a whole budget makes one real TLS connection per refusal, up to the global
    count inside the real 60-second window. On a loaded runner that can take longer than the
    window, and a reset arm then lets a connection the test expects closed through. Only the
    window changes: ``_make_intake_rate_limiter`` still picks the counts."""
    monkeypatch.setattr(
        wiring_runner,
        "_IntakeRateLimiter",
        functools.partial(_IntakeRateLimiter, window_seconds=_LONG_WINDOW_SECONDS),
    )


def _assert_long_window(source: MLLPSource) -> None:
    """The control for ``long_window``: the listener holds the long-window budget, so a pass is
    not owed to a fast run inside the real window."""
    limiter = source.intake_rate_limiter
    assert isinstance(limiter, _IntakeRateLimiter), limiter
    assert limiter._window == _LONG_WINDOW_SECONDS


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
    tmp_path: Path,
    store: MessageStore,
    caplog: pytest.LogCaptureFixture,
    tls_path: str,  # noqa: F811
) -> None:
    """The two-CA case: both chains verify at the TLS layer, and only the issuer differs."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}), store
    )
    _assert_tls_path(source, tls_path)
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
    tmp_path: Path,
    store: MessageStore,
    tls_path: str,  # noqa: F811
) -> None:
    named = _ca("Partner CA")
    source = await _wired(_settings(tmp_path, [named[0]], {_issuer(named): [SUBJECT]}), store)
    _assert_tls_path(source, tls_path)
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


#: An otherName of a type OpenSSL does not print: ``ssl`` reports it as ``othername:<unsupported>``,
#: the same text for every such name, whatever it holds.
_UNPRINTED_OTHERNAME = x509.OtherName(x509.ObjectIdentifier("1.3.6.1.4.1.55555.1"), b"\x0c\x03abc")

#: A UPN otherName ``feed@partner.example<LF>x`` as a DER UTF8String. ``ssl`` stops reading the
#: printed line at the newline, so it reports ``UPN:feed@partner.example<LF>``: the first part of
#: every UPN that starts that way.
_CUT_UPN = x509.OtherName(
    x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3"), b"\x0c\x16" + b"feed@partner.example\nx"
)


async def test_a_placeholder_san_on_a_certificate_matches_no_entry(
    tmp_path: Path, store: MessageStore
) -> None:
    """``ssl`` reports a SAN it cannot render as placeholder text shared by a whole class of names,
    and cuts a printed name short at a newline, so either entry would admit every certificate
    carrying such a name. The factory refuses both; this listener is built past the factory, as a
    ``Source`` built some other way would be, to show the matcher itself never reads either from a
    certificate."""
    named = _ca("Partner CA")
    settings = _settings(tmp_path, [named[0]], {_issuer(named): ["SAN:DNS:feed.partner.example"]})
    settings["tls_client_subjects"] = {
        _issuer(named): [
            "SAN:othername:<unsupported>",
            "SAN:othername:UPN:feed@partner.example\n",
            "SAN:DNS:feed.partner.example",
        ]
    }
    unprinted = _san_bundle(
        tmp_path, named, cn="unrelated.example", dns="other.example", other=(_UNPRINTED_OTHERNAME,)
    )
    cut = _san_bundle(
        tmp_path, named, cn="unrelated.example", dns="other.example", other=(_CUT_UPN,)
    )
    listed = _san_bundle(tmp_path, named, cn="unrelated.example", dns="feed.partner.example")
    source = await _wired(settings, store)
    try:
        refused, rest = await _exchange(source, unprinted)
        refused_cut, rest_cut = await _exchange(source, cut)
        # Control on the same listener: a certificate carrying the listed DNS name is admitted.
        accepted, _ = await _exchange(source, listed)
    finally:
        await source.stop()
    assert b"MSA|AR|" in refused and rest == b""
    assert b"MSA|AR|" in refused_cut and rest_cut == b""
    assert b"MSA|AA|" in accepted


def test_the_shared_matcher_drops_every_placeholder_ssl_reports() -> None:
    """The forms measured from ``ssl.getpeercert()``, and ``<INVALID>``, which CPython's ``_ssl.c``
    writes for a Registered ID; a placeholder in either case is dropped. The real names beside them
    stay."""
    peercert = {
        OTHERNAMES_INTACT_KEY: True,
        "subject": ((("commonName", "partner.example"),),),
        "subjectAltName": (
            ("othername", "<unsupported>"),
            ("othername", "<UNSUPPORTED>"),
            ("X400Name", "<unsupported>"),
            ("EdiPartyName", "<unsupported>"),
            ("IP Address", "<invalid>"),
            ("Registered ID", "<INVALID>"),
            ("Registered ID", "<invalid>"),
            ("othername", "UPN:feed@partner.example\n"),
            ("othername", "UPN:" + "a" * 2032),
            ("Registered ID", "1.2." + "3" * 2040),
            ("othername", "UPN:feed@partner.example"),
            ("othername", "UPN:" + "a" * 2031),
            ("DNS", "feed.partner.example"),
            ("DNS", "d" * 3000),
        ),
    }
    assert cert_name_candidates(peercert) == [
        "CN:partner.example",
        "SAN:othername:UPN:feed@partner.example",
        "SAN:othername:UPN:" + "a" * 2031,
        "SAN:DNS:feed.partner.example",
        "SAN:DNS:" + "d" * 3000,
    ]


def test_an_othername_is_a_candidate_only_once_the_der_was_read() -> None:
    """``ssl`` cuts an otherName at its first NUL, so its text alone cannot show it is whole: an
    otherName is yielded only where the caller read the DER and set the key ``True`` (BACKLOG
    #4907). Absent or anything else, it is dropped and the other names stay."""
    rendered = {
        "subjectAltName": (("othername", "UPN:feed@partner.example"), ("DNS", "feed.example"))
    }
    assert cert_name_candidates(rendered) == ["SAN:DNS:feed.example"]
    assert cert_name_candidates({**rendered, OTHERNAMES_INTACT_KEY: False}) == [
        "SAN:DNS:feed.example"
    ]
    assert cert_name_candidates({**rendered, OTHERNAMES_INTACT_KEY: 1}) == ["SAN:DNS:feed.example"]
    assert cert_name_candidates({**rendered, OTHERNAMES_INTACT_KEY: True}) == [
        "SAN:othername:UPN:feed@partner.example",
        "SAN:DNS:feed.example",
    ]


def _leaf_der(*names: x509.GeneralName) -> bytes:
    ca = _ca("Partner CA")
    key = ec.generate_private_key(ec.SECP256R1())
    builder = (
        x509.CertificateBuilder()
        .subject_name(_dn((NameOID.COMMON_NAME, "any")))
        .issuer_name(ca[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(_NOW - datetime.timedelta(minutes=5))
        .not_valid_after(_NOW + datetime.timedelta(days=1))
    )
    if names:
        builder = builder.add_extension(x509.SubjectAlternativeName(list(names)), critical=False)
    return builder.sign(ca[1], hashes.SHA256()).public_bytes(serialization.Encoding.DER)


_UPN_OID = x509.ObjectIdentifier("1.3.6.1.4.1.311.20.2.3")


@pytest.mark.parametrize(
    ("leaf_der", "intact"),
    [
        pytest.param(_leaf_der(), True, id="no-san"),
        pytest.param(_leaf_der(x509.DNSName("feed.example")), True, id="no-othername"),
        pytest.param(_leaf_der(_upn(b"feed@partner.example")), True, id="whole-upn"),
        pytest.param(_leaf_der(_upn(_NUL_UPN)), False, id="nul-upn"),
        pytest.param(
            _leaf_der(_upn(b"feed@partner.example"), _upn(_NUL_UPN)), False, id="one-of-two"
        ),
        pytest.param(
            _leaf_der(x509.OtherName(_UPN_OID, b"\x1e\x04\x00a\x00b")), False, id="bmpstring"
        ),
        pytest.param(b"not a certificate", False, id="not-der"),
        pytest.param(b"", False, id="empty"),
        pytest.param(None, False, id="none"),
    ],
)
def test_the_der_read_refuses_an_othername_ssl_cannot_report_whole(
    leaf_der: bytes | None, intact: bool
) -> None:
    """A NUL in an otherName's content, and a certificate that cannot be read, count as not
    intact. So does a BMPString's zero byte, which can only refuse: ``ssl`` reports a BMPString UPN
    as ``<unsupported>``. ``cryptography`` refuses to build an otherName value that is not exactly
    one TLV, so that check has no case here."""
    assert san_othernames_intact(leaf_der) is intact


def test_the_der_read_never_raises_into_a_caller(
    monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    """Any fault reading the DER drops the otherNames and is logged by its type alone, rather than
    escaping into a listener's admission or the API shim's ``connection_made``."""

    class _Ssl:
        def getpeercert(self, binary_form: bool = False) -> bytes:
            return _leaf_der(_upn(b"feed@partner.example"))

    def _boom(leaf_der: bytes | None) -> bool:
        raise RuntimeError("feed@partner.example")

    from messagefoundry import pki

    assert pki.peer_othernames_intact(_Ssl()) is True  # control: the same certificate, read
    monkeypatch.setattr(pki, "san_othernames_intact", _boom)
    with caplog.at_level(logging.WARNING, logger="messagefoundry.pki"):
        assert pki.peer_othernames_intact(_Ssl()) is False
    assert "RuntimeError" in caplog.text
    assert "feed@partner.example" not in caplog.text


async def test_an_othername_holding_a_nul_on_a_certificate_matches_no_entry(
    tmp_path: Path, store: MessageStore
) -> None:
    """``ssl`` reports a UPN ``victim@acme.example<NUL>evil`` as ``UPN:victim@acme.example``, the
    whole of the listed name. The listener reads the leaf's DER, so it refuses that certificate,
    over a real handshake. Control on the same listener: the whole name is admitted."""
    named = _ca("Partner CA")
    settings = _settings(
        tmp_path, [named[0]], {_issuer(named): ["SAN:othername:UPN:victim@acme.example"]}
    )
    cut = _san_bundle(
        tmp_path, named, cn="unrelated.example", dns="other.example", other=(_upn(_NUL_UPN),)
    )
    whole = _san_bundle(
        tmp_path,
        named,
        cn="unrelated.example",
        dns="other.example",
        other=(_upn(b"victim@acme.example"),),
    )
    source = await _wired(settings, store)
    try:
        refused, rest = await _exchange(source, cut)
        accepted, _ = await _exchange(source, whole)
    finally:
        await source.stop()
    assert b"MSA|AR|" in refused and rest == b""
    assert b"MSA|AA|" in accepted


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
        pytest.param(
            {"CN=Partner CA": ["SAN:othername:<unsupported>"]},
            {},
            "a placeholder",
            id="othername-placeholder",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:X400Name:<unsupported>"]}, {}, "a placeholder", id="x400"
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:EdiPartyName:<unsupported>"]}, {}, "a placeholder", id="edi"
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:IP Address:<invalid>"]}, {}, "a placeholder", id="ip-invalid"
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:Registered ID:<INVALID>"]}, {}, "a placeholder", id="rid-upper"
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:othername:<UNSUPPORTED>"]},
            {},
            "a placeholder",
            id="othername-placeholder-upper",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:othername:UPN:victim@acme.example\x00evil"]},
            {},
            "an othername holding a NUL",
            id="othername-nul",
        ),
        pytest.param(
            {"CN=Partner CA": [SUBJECT, "SAN:IP:192.0.2.10"]},
            {},
            "ssl writes it 'IP Address'",
            id="ip-short",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:dns:feed.partner.example"]},
            {},
            "ssl writes it 'DNS'",
            id="dns-lower",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:Fingerprint:ab12"]}, {}, "a SAN type ssl never", id="no-type"
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:IP Address:2001:db8::1"]},
            {},
            "an IP address in a spelling ssl never writes",
            id="ipv6-compressed",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:othername:UPN:feed@partner.example\n"]},
            {},
            "a value ssl may have cut short",
            id="othername-newline",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:othername:UPN:" + "a" * 2032]},
            {},
            "a value ssl may have cut short",
            id="othername-line-full",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:DirName:CN=feed.partner.example"]},
            {},
            "a DirName in a form ssl never reports",
            id="dirname-dn",
        ),
        pytest.param(
            {"CN=Partner CA": ["SAN:othername:feed@partner.example"]},
            {},
            "an othername in a form ssl never reports",
            id="othername-no-form",
        ),
    ],
)
def test_the_factory_refuses_what_cannot_work(
    subjects: Any, overrides: dict[str, Any], message: str
) -> None:
    with pytest.raises(WiringError, match=message) as excinfo:
        _mllp(subjects, **overrides)
    assert "MLLP tls_client_subjects" in str(excinfo.value)


def test_the_factory_accepts_each_san_type_in_the_spelling_ssl_reports() -> None:
    """The control for the spelling refusals: the same entries, written as ``ssl`` writes them."""
    names = [
        "SAN:DNS:feed.partner.example",
        "SAN:IP Address:192.0.2.10",
        "SAN:IP Address:2001:DB8:0:0:0:0:0:1",
        "SAN:URI:https://feed.partner.example/",
        "SAN:email:feed@partner.example",
        "SAN:othername:UPN:feed@partner.example",
        "SAN:othername:UPN:" + "a" * 2031,
        "SAN:DirName:((('commonName', 'feed.partner.example'),),)",
        "SAN:DNS:" + "d" * 3000,
    ]
    assert _mllp({"CN=Partner CA": names}).settings["tls_client_subjects"] == {
        "CN=Partner CA": names
    }


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


async def _send_raw(source: MLLPSource, bundle: Path, wire: bytes) -> bytes:
    """Write ``wire`` in one go presenting ``bundle``, then read everything to EOF."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(bundle)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport, ssl=ctx)
    try:
        writer.write(wire)
        await writer.drain()
        return await asyncio.wait_for(reader.read(-1), 10.0)
    finally:
        writer.close()


def _frame(body: str) -> bytes:
    return b"\x0b" + body.encode("utf-8") + b"\x1c\r"


async def test_every_frame_of_the_refused_read_is_recorded_and_answered(
    tmp_path: Path, store: MessageStore
) -> None:
    """Two frames pipelined in one write: each is recorded as ERROR and answered AR before the
    close, so a frame read behind the first is never read and dropped."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}), store
    )
    second = _ADT.replace("CTRL4907", "CTRL4908")
    try:
        got = await _send_raw(source, _bundle(tmp_path, other), _frame(_ADT) + _frame(second))
    finally:
        await source.stop()
    assert b"MSA|AR|CTRL4907" in got and b"MSA|AR|CTRL4908" in got
    statuses = [r["status"] for r in await _rows(store)]
    assert statuses == [MessageStatus.ERROR.value, MessageStatus.ERROR.value], statuses


async def test_an_hl7_inbound_with_acks_off_records_and_closes_with_no_reply(
    tmp_path: Path, store: MessageStore
) -> None:
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}),
        store,
        ack_mode=AckMode.NONE,
    )
    try:
        got = await _send_raw(source, _bundle(tmp_path, other), _frame(_ADT))
    finally:
        await source.stop()
    assert got == b""
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]


async def test_enhanced_mode_answers_cr(tmp_path: Path, store: MessageStore) -> None:
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}),
        store,
        ack_mode=AckMode.ENHANCED,
    )
    try:
        got = await _send_raw(source, _bundle(tmp_path, other), _frame(_ADT))
    finally:
        await source.stop()
    assert b"MSA|CR|CTRL4907" in got, got


def test_an_outbound_that_sets_the_allowlist_is_refused(tmp_path: Path) -> None:
    """A destination never reads the table, so an outbound that sets it is refused, not ignored."""
    toml = """
        [[outbound]]
        name = "OB_ACME_ADT"
        transport = "mllp"
          [outbound.settings]
          host = "downstream.example"
          port = 2575
          tls = true
          tls_ca_file = "ca.pem"
          [outbound.settings.tls_client_subjects]
          "CN=Partner CA" = ["SAN:DNS:feed.partner.example"]
    """
    with pytest.raises(WiringError, match="tls_client_subjects names the senders an inbound"):
        load_config(_config(tmp_path, toml))


async def test_a_header_the_charset_cannot_decode_still_gets_its_ar(
    tmp_path: Path, store: MessageStore
) -> None:
    """On an ``ascii`` inbound, a byte the charset refuses in MSH must not reach the AR as U+FFFD,
    which would not re-encode and would leave the sender with no reply after the row was written."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}, encoding="ascii"),
        store,
    )
    body = b"MSH|^~\\&|ACM\xe9|FAC|MF|FAC|20260101||ADT^A01|CTRL4907|P|2.5\rPID|1\r"
    try:
        got = await _send_raw(source, _bundle(tmp_path, other), b"\x0b" + body + b"\x1c\r")
    finally:
        await source.stop()
    assert b"MSA|AR|" in got, got
    assert [r["status"] for r in await _rows(store)] == [MessageStatus.ERROR.value]


# --- held to the HTTP listener's posture: budget, audit row, connection event ----------------------


async def _send_from(
    source: MLLPSource, bundle: Path, wire: bytes, *, local_host: str = "127.0.0.1"
) -> bytes:
    """Send ``wire`` from ``local_host`` and return the first reply frame, or what came before EOF.

    A connection the listener closes unread may reset under the client's write, so a reset is read
    as the close it is (``b""``); a listener that neither replies nor closes fails on the timeout."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(bundle)
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", source.sockport, ssl=ctx, local_addr=(local_host, 0)
    )
    try:
        writer.write(wire)
        await writer.drain()
        return await asyncio.wait_for(reader.readuntil(b"\x1c\r"), 10.0)
    except asyncio.IncompleteReadError as eof:
        return eof.partial
    except (ConnectionError, ssl.SSLError):
        return b""
    finally:
        writer.close()


async def _audits(store: MessageStore) -> list[dict[str, Any]]:
    return [dict(row) for row in await store.list_audit(limit=200)]


async def test_a_refusal_writes_the_audit_row_and_event_http_writes(
    tmp_path: Path, store: MessageStore
) -> None:
    """One refused sender: one ``intake.auth_subject_denied`` audit row and one
    ``auth_subject_denied`` connection event, naming the peer address and no certificate field.
    The control on the same listener, a listed sender, writes neither."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    events: list[tuple[str, str | None, str | None]] = []
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}),
        store,
        events=events,
    )
    try:
        accepted = await _send_from(source, _bundle(tmp_path, named), _frame(_ADT))
        assert b"MSA|AA|" in accepted
        assert await _audits(store) == []
        assert "auth_subject_denied" not in [kind for kind, _, _ in events]
        refused = await _send_from(source, _bundle(tmp_path, other), _frame(_ADT))
    finally:
        await source.stop()
    assert b"MSA|AR|" in refused
    (audit,) = await _audits(store)
    assert audit["action"] == "intake.auth_subject_denied"
    assert audit["channel_id"] == _INBOUND
    assert audit["client"] == "127.0.0.1"
    assert audit["detail"] == "mode=tls_client_subjects"
    denied = [e for e in events if e[0] == "auth_subject_denied"]
    assert denied == [("auth_subject_denied", "127.0.0.1", _SENDER_DENIED)]
    assert all(_PERSON not in str(value) for value in audit.values())
    assert all(_PERSON not in str(value) for event in events for value in event)


async def test_a_refused_sender_that_reconnects_is_closed_unread_at_its_budget(
    tmp_path: Path,
    store: MessageStore,
    caplog: pytest.LogCaptureFixture,
    long_window: None,
    tls_path: str,  # noqa: F811
) -> None:
    """The failed-attempt budget HTTP charges for ``auth_subject_denied``, reused: each refusal is
    charged to the peer's address, and once the budget is spent the address is closed unread,
    before any certificate is compared, as HTTP answers it ``429``. That includes a listed
    certificate presented from the same address, which is HTTP's posture too. The control is a
    listed sender from another address, which the spent budget does not touch."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    events: list[tuple[str, str | None, str | None]] = []
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}),
        store,
        events=events,
    )
    _assert_long_window(source)
    _assert_tls_path(source, tls_path)
    refused_bundle, listed_bundle = _bundle(tmp_path, other), _bundle(tmp_path, named)
    budget = INTAKE_AUTH_RATE_LIMIT_DEFAULT
    try:
        with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.mllp"):
            for attempt in range(budget):
                got = await _send_from(source, refused_bundle, _frame(_ADT))
                assert b"MSA|AR|" in got, (attempt, got)
            over_budget = await _send_from(source, refused_bundle, _frame(_ADT))
        same_address_listed = await _send_from(source, listed_bundle, _frame(_ADT))
        other_address_listed = await _send_from(
            source, listed_bundle, _frame(_ADT), local_host="127.0.0.2"
        )
    finally:
        await source.stop()
    assert over_budget == b""
    assert same_address_listed == b""
    assert b"MSA|AA|" in other_address_listed
    statuses = sorted(r["status"] for r in await _rows(store))
    # Nothing was read from the two closed-unread connections, so they left no row: the sender
    # keeps those messages, and none is accepted and dropped.
    assert statuses == sorted(
        [MessageStatus.ERROR.value] * budget + [MessageStatus.RECEIVED.value]
    ), statuses
    actions = [row["action"] for row in await _audits(store)]
    assert actions.count("intake.auth_subject_denied") == budget
    assert actions.count("intake.auth_rate_limited") == 2
    limited = [e for e in events if e[0] == "auth_rate_limited"]
    assert limited == [("auth_rate_limited", "127.0.0.1", _SENDER_RATE_LIMITED)] * 2
    # Both lines are written for the one address inside one window: neither throttle hides the
    # other's line.
    logged = [r.getMessage() for r in caplog.records]
    assert any("not on tls_client_subjects" in m for m in logged), logged
    assert any("has spent its failed-attempt budget" in m for m in logged), logged


async def test_refusals_from_other_addresses_never_close_a_listed_sender(
    tmp_path: Path, store: MessageStore, long_window: None
) -> None:
    """The global arm bounds refusals, and a listed sender drives none, so it is consulted only once
    the compare has refused. Unlisted senders from six addresses spend the whole global budget, each
    inside its own per-address budget; a listed sender from a fresh address is then still accepted,
    where reading the global arm before the compare closed it unread, and MLLP has no setting that
    turns that arm off. Two controls: an unlisted sender from a fresh address is closed unread by
    the spent global arm, and a listed certificate from an address that spent its OWN budget is
    still closed unread before the compare, as ADR 0154 D6 requires."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    events: list[tuple[str, str | None, str | None]] = []
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}),
        store,
        events=events,
    )
    _assert_long_window(source)
    refused_bundle, listed_bundle = _bundle(tmp_path, other), _bundle(tmp_path, named)
    per_peer, glob = INTAKE_AUTH_RATE_LIMIT_DEFAULT, INTAKE_AUTH_RATE_LIMIT_GLOBAL_DEFAULT
    spenders = [f"127.0.0.{2 + i}" for i in range(-(-glob // per_peer))]
    try:
        refused = 0
        for host in spenders:
            for _ in range(per_peer):
                if refused == glob:
                    break
                got = await _send_from(source, refused_bundle, _frame(_ADT), local_host=host)
                assert b"MSA|AR|" in got, (host, refused, got)
                refused += 1
        assert refused == glob
        fresh_listed = await _send_from(
            source, listed_bundle, _frame(_ADT), local_host="127.0.0.50"
        )
        fresh_unlisted = await _send_from(
            source, refused_bundle, _frame(_ADT), local_host="127.0.0.51"
        )
        own_budget_listed = await _send_from(
            source, listed_bundle, _frame(_ADT), local_host=spenders[0]
        )
    finally:
        await source.stop()
    assert b"MSA|AA|" in fresh_listed, fresh_listed
    assert fresh_unlisted == b""
    assert own_budget_listed == b""
    limited = [e for e in events if e[0] == "auth_rate_limited"]
    assert limited == [
        ("auth_rate_limited", "127.0.0.51", _SENDER_RATE_LIMITED),
        ("auth_rate_limited", spenders[0], _SENDER_RATE_LIMITED),
    ]
    listed = await store.list_messages(allowed_channels=None, limit=glob + 10)
    statuses = sorted(row["status"] for row in listed)
    assert statuses == sorted(
        [MessageStatus.ERROR.value] * glob + [MessageStatus.RECEIVED.value]
    ), statuses


class _Limiter:
    """A failed-attempt budget that admits everyone and records each call."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str]] = []

    def check(self, peer: str) -> bool:
        self.calls.append(("check", peer))
        return True

    def check_peer(self, peer: str) -> bool:
        self.calls.append(("check_peer", peer))
        return True

    def charge_failure(self, peer: str) -> None:
        self.calls.append(("charge", peer))

    def note_success(self, peer: str) -> None:
        self.calls.append(("success", peer))


async def test_a_listed_sender_reads_only_its_own_arm_and_is_never_charged(
    tmp_path: Path, store: MessageStore
) -> None:
    """ADR 0154 D6's two invariants on this listener: the address's own budget is consulted before
    the subject is compared, and a listed sender is never charged. A listed sender never reaches the
    global arm (``check``), and is not noted as authenticated either: here the note would gate
    nothing for it and would only exempt an unlisted certificate from the same address from the
    global arm. The control is a refused sender, which reads the global arm once its compare has
    refused and is charged."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    source = await _wired(
        _settings(tmp_path, [named[0], other[0]], {_issuer(named): [SUBJECT]}), store
    )
    limiter = _Limiter()
    source.intake_rate_limiter = limiter
    second = _ADT.replace("CTRL4907", "CTRL4908")
    try:
        got = await _send_raw_until(
            source, _bundle(tmp_path, named), _frame(_ADT) + _frame(second), b"CTRL4908"
        )
        listed_calls = list(limiter.calls)
        limiter.calls.clear()
        await _send_from(source, _bundle(tmp_path, other), _frame(_ADT))
    finally:
        await source.stop()
    assert b"MSA|AA|CTRL4907" in got and b"MSA|AA|CTRL4908" in got
    assert listed_calls == [("check_peer", "127.0.0.1")], listed_calls
    assert limiter.calls == [
        ("check_peer", "127.0.0.1"),
        ("check", "127.0.0.1"),
        ("charge", "127.0.0.1"),
    ]


async def _send_raw_until(source: MLLPSource, bundle: Path, wire: bytes, until: bytes) -> bytes:
    """Write ``wire`` presenting ``bundle`` and read until ``until`` has arrived in a whole frame."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(bundle)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport, ssl=ctx)
    got = b""
    try:
        writer.write(wire)
        await writer.drain()
        while until not in got:
            got += await asyncio.wait_for(reader.readuntil(b"\x1c\r"), 10.0)
        return got
    finally:
        writer.close()


def test_the_budget_is_the_http_factory_default_and_only_with_the_allowlist(
    tmp_path: Path, store: MessageStore
) -> None:
    """The MLLP allowlist has no budget settings of its own; it takes ``Http()``'s defaults. An MLLP
    inbound without the allowlist gets no budget and no audit sink (the control)."""
    params = inspect.signature(Http).parameters
    assert params["intake_auth_rate_limit"].default == INTAKE_AUTH_RATE_LIMIT_DEFAULT
    assert params["intake_auth_rate_limit_global"].default == INTAKE_AUTH_RATE_LIMIT_GLOBAL_DEFAULT
    named = _ca("Partner CA")
    (tmp_path / "on").mkdir()
    (tmp_path / "off").mkdir()
    on = _settings(tmp_path / "on", [named[0]], {_issuer(named): [SUBJECT]})
    off = _settings(tmp_path / "off", [named[0]], None)
    runner, ic = _runner(store, on)
    assert runner._make_intake_rate_limiter(ic) is not None
    assert runner._make_intake_audit_sink(ic) is not None
    runner, ic = _runner(store, off)
    assert runner._make_intake_rate_limiter(ic) is None
    assert runner._make_intake_audit_sink(ic) is None


async def test_the_runner_wires_the_allowlist_seams_at_start(
    tmp_path: Path, store: MessageStore
) -> None:
    """Through ``RegistryRunner.start``, not by hand: the refusal, the budget and the audit sink are
    injected onto the started MLLP source with the allowlist, and a refused sender gets its ERROR
    row, its ``AR`` and its audit row. The control, the same listener without the allowlist, gets
    none of the three seams."""
    named, other = _ca("Partner CA"), _ca("Other CA")
    (tmp_path / "on").mkdir()
    (tmp_path / "off").mkdir()
    on = _settings(tmp_path / "on", [named[0], other[0]], {_issuer(named): [SUBJECT]})
    off = _settings(tmp_path / "off", [named[0], other[0]], None)
    runner, _ic = _runner(store, on)
    await runner.start()
    try:
        source = runner._sources[_INBOUND]
        assert isinstance(source, MLLPSource)
        assert source.refuse_unlisted_sender is not None
        assert source.intake_rate_limiter is not None
        assert source.on_intake_audit is not None
        got = await _send_from(source, _bundle(tmp_path, other), _frame(_ADT))
    finally:
        await asyncio.wait_for(runner.stop(), timeout=10.0)
    assert b"MSA|AR|" in got
    assert MessageStatus.ERROR.value in [r["status"] for r in await _rows(store)]
    assert [a["action"] for a in await _audits(store)] == ["intake.auth_subject_denied"]
    runner, _ic = _runner(store, off)
    await runner.start()
    try:
        source = runner._sources[_INBOUND]
        assert source.refuse_unlisted_sender is None
        assert source.intake_rate_limiter is None
        assert source.on_intake_audit is None
    finally:
        await asyncio.wait_for(runner.stop(), timeout=10.0)


def test_the_allowlist_refuses_tls_renegotiation(tmp_path: Path) -> None:
    """The certificate is checked once, after the handshake, so a TLS 1.2 renegotiation must not be
    able to swap it afterwards. The control: a bare mTLS listener's context is left as it was.

    Asserted on the context, not by a live renegotiation: Python's ``ssl`` module exposes no way
    for a client to start one, so no test here could attempt it."""
    named = _ca("Partner CA")
    (tmp_path / "on").mkdir()
    (tmp_path / "off").mkdir()
    on = MLLPSource(
        Source(
            type=ConnectorType.MLLP,
            settings=_settings(tmp_path / "on", [named[0]], {_issuer(named): [SUBJECT]}),
        )
    )
    off = MLLPSource(
        Source(type=ConnectorType.MLLP, settings=_settings(tmp_path / "off", [named[0]], None))
    )
    assert on._ssl is not None and off._ssl is not None
    assert on._ssl.options & ssl.OP_NO_RENEGOTIATION
    assert not off._ssl.options & ssl.OP_NO_RENEGOTIATION
