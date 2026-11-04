# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``intake_client_subjects`` is bound to the issuing CA (vault BACKLOG #2287, ADR 0154 amendment).

Before this, the ``Http()`` listener's ``mtls_subject`` allow-list matched a subject from ANY CA in
``tls_ca_file``, the flaw BACKLOG #2237 closed on the operator API. These cases drive REAL TLS
handshakes against a running :class:`HttpSource`, because the claims are about what OpenSSL verified:
which loaded CA certificate signed the leaf. A hand-written certificate dict would only test the code
against itself. The CA and client-certificate builders are ``tests/test_api_tls.py``'s, the ones
the API's own issuer cases use, so both surfaces are measured against the same certificates. The CA
here adds ``keyUsage``, which the listener's strict verify requires.

Each refusal case has a control beside it that differs only in the issuer, so a listener refusing
everything cannot pass.
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

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import Http, WiringError, env
from messagefoundry.pki import IssuerIndex
from messagefoundry.transports.http_listener import HttpSource, _client_issuer_index
from messagefoundry.transports.receipt import IngressReceipt, receipt_handler
from tests.test_api_tls import (
    _CaPair,
    _client_bundle,
    _dn,
    _labelled,
    _new_ca,
    _pem,
    _relabelled,
    _self_signed,
)

SUBJECT = "CN:partner.example"


def _ca(dn: x509.Name, by: _CaPair | None = None) -> _CaPair:
    """``tests/test_api_tls.py``'s CA, with the ``keyUsage`` the listener's strict verify needs."""
    return _new_ca(dn, by, key_usage=True)


def _bundle(tmp_path: Path, signer: _CaPair, **kwargs: Any) -> Path:
    """``tests/test_api_tls.py``'s client bundle, for the partner subject this module lists."""
    return _client_bundle(tmp_path, signer, cn="partner.example", **kwargs)


def _source(
    tmp_path: Path,
    trusted: list[x509.Certificate],
    subjects: dict[str, list[str]] | None,
    *,
    label: str = "CERTIFICATE",
    cadata: bytes | None = None,
) -> HttpSource:
    """A loopback mTLS listener trusting ``trusted``, built through the ``Http()`` factory.

    ``subjects`` set means ``mtls_subject``; ``None`` means a bare mTLS listener with no intake auth.
    ``label`` is the PEM label every block in ``tls_ca_file`` is written under. ``cadata``, when
    given, is written to ``tls_ca_file`` as it stands, in place of ``trusted``."""
    cert, key = _self_signed(tmp_path)
    ca_file = tmp_path / "client-ca.pem"
    ca_file.write_bytes(
        b"".join(_labelled(c, label) for c in trusted) if cadata is None else cadata
    )
    spec = Http(
        port=0,
        tls=True,
        tls_cert_file=str(cert),
        tls_key_file=str(key),
        tls_ca_file=str(ca_file),
        intake_auth="none" if subjects is None else "mtls_subject",
        intake_client_subjects=subjects,
    )
    return HttpSource(
        Source(type=ConnectorType.HTTP, settings={**spec.settings, "host": "127.0.0.1"})
    )


async def _started(source: HttpSource) -> HttpSource:
    async def handler(raw: bytes) -> IngressReceipt:
        return IngressReceipt.accepted("msg-1")  # stands in for the committed ingress message_id

    await source.start(receipt_handler(handler))
    return source


async def _status(source: HttpSource, bundle: Path, *, send: bool) -> int:
    """The HTTP status the listener answers a client presenting ``bundle``.

    A refusal is answered at accept, before any request byte is read, so a case expecting one sends
    nothing (``send=False``) and only reads: writing into a socket the listener is closing can reset
    it and lose the status. If such a client were admitted instead, the listener would wait for a
    request and the read would time out, failing the case. ``send=True`` posts a body first."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # the LISTENER side is the verifier under test
    ctx.load_cert_chain(bundle)
    reader, writer = await asyncio.open_connection("127.0.0.1", source.sockport, ssl=ctx)
    try:
        if send:
            writer.write(b"POST /ingest HTTP/1.1\r\nHost: localhost\r\nContent-Length: 2\r\n\r\n{}")
            await writer.drain()
        data = await asyncio.wait_for(reader.read(-1), 10.0)
    finally:
        writer.close()
    assert data.startswith(b"HTTP/1.1 "), data[:40]
    return int(data.split(b" ", 2)[1])


async def _refused(source: HttpSource, bundle: Path) -> int:
    return await _status(source, bundle, send=False)


async def _admitted(source: HttpSource, bundle: Path) -> int:
    return await _status(source, bundle, send=True)


@pytest.mark.parametrize("label", ["CERTIFICATE", "X509 CERTIFICATE"])
async def test_the_listed_issuer_is_admitted_and_another_ca_with_the_same_subject_is_not(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, label: str
) -> None:
    """The defect itself: two loaded CAs, and the unlisted one issues a listed subject.

    Run under both labels the TLS context loads a CA from. Under the legacy ``X509 CERTIFICATE`` the
    handshake verifies a leaf, but the shipped index read only ``BEGIN CERTIFICATE``, so it never
    held the CA: every partner under it would have been refused, with a start warning saying the key
    named no loaded CA rather than that a block went unread (BACKLOG #4948)."""
    named = _ca(_dn((NameOID.ORGANIZATION_NAME, "Acme"), (NameOID.COMMON_NAME, "Partner CA")))
    other = _ca(_dn((NameOID.ORGANIZATION_NAME, "Other"), (NameOID.COMMON_NAME, "Other CA")))
    listener_log = "messagefoundry.transports.http_listener"
    control = "capture control: the listener's logger reaches caplog"
    with caplog.at_level(logging.WARNING, logger=listener_log):
        # The listener should warn nothing here, so the capture's true floor is this control alone.
        # It keeps the empty check below from passing on a capture wired to the wrong logger.
        logging.getLogger(listener_log).warning(control)
        source = _source(
            tmp_path,
            [named[0], other[0]],
            {named[0].subject.rfc4514_string(): [SUBJECT]},
            label=label,
        )
    assert len(caplog.records) >= 1, "the capture missed its own control warning"
    at_start = [
        r.getMessage()
        for r in caplog.records
        if r.name == listener_log and r.getMessage() != control
    ]
    await _started(source)
    try:
        # Control: the same subject from the CA it is listed under is admitted.
        assert await _admitted(source, _bundle(tmp_path, named)) == 202
        # Both chains verify at the TLS layer; only the issuer differs.
        assert await _refused(source, _bundle(tmp_path, other)) == 403
    finally:
        await source.stop()
    assert not at_start, at_start


async def test_a_ca_with_a_lookalike_name_is_refused(tmp_path: Path) -> None:
    """The issuing CA writes the leaf's issuer field, and OpenSSL matches it to a loaded CA loosely,
    folding case and whitespace. So a CA named ``CN=ACME   CA`` can sign a leaf whose field reads
    ``CN=Acme CA`` and it verifies. The listener follows the signature, not the field."""
    named = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    lookalike = _ca(_dn((NameOID.COMMON_NAME, "ACME   CA")))
    source = await _started(_source(tmp_path, [named[0], lookalike[0]], {"CN=Acme CA": [SUBJECT]}))
    try:
        forged = _bundle(tmp_path, lookalike, leaf_issuer=named[0].subject)
        assert await _refused(source, forged) == 403
        assert await _admitted(source, _bundle(tmp_path, named)) == 202  # control
    finally:
        await source.stop()


async def test_a_leaf_signed_by_an_intermediate_the_client_sends_is_refused(
    tmp_path: Path,
) -> None:
    """Only a CA loaded from ``tls_ca_file`` counts as an issuer. Any loaded CA could mint an
    intermediate carrying another CA's exact name, so a client-sent one is never an issuer, even
    when a key names its DN. Loading that intermediate is what makes it count."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Acme Root CA")))
    intermediate = _ca(_dn((NameOID.COMMON_NAME, "Acme Partner CA")), by=root)
    subjects = {"CN=Acme Partner CA": [SUBJECT], "CN=Acme Root CA": [SUBJECT]}
    for name in ("sent", "root-only", "both"):
        (tmp_path / name).mkdir()
    sent = _bundle(tmp_path / "sent", intermediate, sent=(intermediate[0],))
    source = await _started(_source(tmp_path / "root-only", [root[0]], subjects))
    try:
        assert await _refused(source, sent) == 403
    finally:
        await source.stop()
    # Control: with the intermediate loaded too, the same certificate is admitted under it.
    source = await _started(_source(tmp_path / "both", [root[0], intermediate[0]], subjects))
    try:
        assert await _admitted(source, sent) == 202
    finally:
        await source.stop()


def test_an_issuer_key_naming_no_loaded_ca_is_warned_about(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A key that can never match would deny every certificate under it with nothing in the log."""
    named = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    subjects = {"CN=Acme CA": [SUBJECT], "CN=Missing CA": [SUBJECT]}
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        _source(tmp_path, [named[0]], subjects)
    warned = [r.getMessage() for r in caplog.records]
    assert any("'CN=Missing CA'" in m and "names no CA" in m for m in warned), warned
    assert not any("'CN=Acme CA'" in m for m in warned), warned


class _Ledger:
    """Stands in for the runner's rate limiter and audit sink, recording what each one is given."""

    def __init__(self) -> None:
        self.charges: list[str] = []
        self.audits: list[str] = []

    def check(self, peer: str) -> bool:
        return True

    def charge_failure(self, peer: str) -> None:
        self.charges.append(peer)

    def note_success(self, peer: str) -> None:
        pass

    async def audit(self, action: str, _peer: str | None, _detail: str | None) -> None:
        self.audits.append(action)


async def test_an_issuer_that_cannot_be_established_is_a_charged_audited_403(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """Whatever stops the issuer being found must deny through the intake-auth path: a 403 that is
    charged to the failed-attempt budget and audited, not an unexpected-error answer that is
    neither."""
    named = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    source = _source(tmp_path, [named[0]], {"CN=Acme CA": [SUBJECT]})
    ledger = _Ledger()
    source.intake_rate_limiter = ledger
    source.on_intake_audit = ledger.audit
    index = source._issuer_index
    assert index is not None

    def broken(_leaf_der: bytes) -> str:
        raise RuntimeError("an error the lookup does not anticipate")

    await _started(source)
    try:
        # Control first: the same certificate is admitted while the lookup works.
        assert await _admitted(source, _bundle(tmp_path, named)) == 202
        index.issuer_of = broken  # type: ignore[method-assign,assignment]
        with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
            assert await _refused(source, _bundle(tmp_path, named)) == 403
    finally:
        await source.stop()
    assert len(ledger.charges) == 1, ledger.charges
    assert ledger.audits == ["intake.auth_subject_denied"]
    assert any("could not establish" in r.getMessage() for r in caplog.records)


async def test_two_loaded_cas_with_one_name_and_different_keys_admit_neither(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A partner CA re-keyed under its old DN: the key names a name, so the two cannot be told apart,
    and neither CA's certificates are admitted (as on the API). The start warning names the key."""
    first = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    second = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    for name in ("both", "one"):
        (tmp_path / name).mkdir()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        source = _source(tmp_path / "both", [first[0], second[0]], {"CN=Acme CA": [SUBJECT]})
    assert any("'CN=Acme CA'" in r.getMessage() for r in caplog.records)
    await _started(source)
    try:
        assert await _refused(source, _bundle(tmp_path, first)) == 403
    finally:
        await source.stop()
    # Control: with only one of the two loaded, the same certificate is admitted.
    source = await _started(_source(tmp_path / "one", [first[0]], {"CN=Acme CA": [SUBJECT]}))
    try:
        assert await _admitted(source, _bundle(tmp_path, first)) == 202
    finally:
        await source.stop()


@pytest.mark.parametrize("legacy_one", ["first", "second"])
async def test_two_cas_with_one_name_admit_neither_when_one_uses_the_legacy_label(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, legacy_one: str
) -> None:
    """The same two CAs, one written under the legacy ``X509 CERTIFICATE`` label. In the shipped
    code the leaf under the legacy-label CA is refused too, since its key verifies under no CA the
    index holds; the leaf under the other would have been admitted, because the index saw only its
    CA and so could not know the two were ambiguous (BACKLOG #4948). Both are refused now, and the
    key is warned about as naming two."""
    first = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    second = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    legacy, plain = (first, second) if legacy_one == "first" else (second, first)
    cadata = b"".join(
        _labelled(ca[0], "X509 CERTIFICATE" if ca is legacy else "CERTIFICATE")
        for ca in (first, second)
    )
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        source = _source(tmp_path, [], {"CN=Acme CA": [SUBJECT]}, cadata=cadata)
    await _started(source)
    try:
        assert await _refused(source, _bundle(tmp_path, legacy)) == 403  # refused before, too
        assert await _refused(source, _bundle(tmp_path, plain)) == 403
    finally:
        await source.stop()
    assert any("'CN=Acme CA'" in r.getMessage() for r in caplog.records)
    assert source._issuer_index is not None
    reason = source._issuer_index.unmatched_keys(["CN=Acme CA"])["CN=Acme CA"]
    assert reason.startswith("names 2 loaded CA certificates"), reason


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _wrapped(der: bytes, label: str = "CERTIFICATE") -> bytes:
    """``der`` as one PEM block under ``label``, whatever bytes it holds."""
    return _relabelled(ssl.DER_cert_to_PEM_cert(der).encode("ascii"), label)


@pytest.mark.parametrize("label", ["CERTIFICATE", "X509 CERTIFICATE"])
def test_an_unparsable_certificate_in_the_trust_store_is_warned_about(
    caplog: pytest.LogCaptureFixture, label: str
) -> None:
    """Driven at the index builder: a block OpenSSL loads but ``cryptography`` refuses, a CA with
    bytes after its DER, is what this warns about. Under either label the context loads a CA from,
    such a block names no issuer and is counted, so the "could not be parsed" warning
    ``docs/SECURITY.md`` promises fires. The shipped index never reads a legacy-label block, so
    there it would not (BACKLOG #4948). The good CA beside it is still named."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    cadata = (_pem(good[0]) + _wrapped(_der(odd[0]) + b"\x30\x00", label)).decode("ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert len(ctx.get_ca_certs()) == 2  # the premise: OpenSSL loads the odd block
    subjects = {"CN=Acme CA": [SUBJECT], "CN=Odd CA": [SUBJECT]}
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        index = _client_issuer_index("IB_PARTNER", cadata, subjects)
    assert index is not None and index.unreadable == 1
    assert set(index.unmatched_keys(subjects)) == {"CN=Odd CA"}
    warned = [r.getMessage() for r in caplog.records]
    assert any("1 certificate(s) in tls_ca_file could not be parsed" in m for m in warned), warned
    # Control: the same store without the junk block warns about nothing.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        _client_issuer_index("IB_PARTNER", _pem(good[0]).decode("ascii"), {"CN=Acme CA": [SUBJECT]})
    assert not caplog.records


def _v4(cert: x509.Certificate) -> bytes:
    """``cert``'s DER with its version field set to 4, which OpenSSL loads and ``cryptography``
    refuses with ``InvalidVersion``, which is not a ``ValueError``."""
    der = _der(cert)
    v3 = b"\xa0\x03\x02\x01\x02"
    assert der.count(v3) == 1
    return der.replace(v3, b"\xa0\x03\x02\x01\x03")


def test_a_version_4_ca_names_nothing_and_does_not_end_the_build(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A CA OpenSSL loads with version 4 is refused by ``cryptography`` with ``InvalidVersion``. In
    the shipped code it raises out of the index, and so out of the listener's and the API's context
    build. It now names
    nothing and is counted, the "could not be parsed" warning fires, and the good CA beside it is
    still named (BACKLOG #4948)."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    cadata = (_pem(good[0]) + _wrapped(_v4(odd[0]))).decode("ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert len(ctx.get_ca_certs()) == 2  # the premise: OpenSSL loads it
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        index = _client_issuer_index("IB_PARTNER", cadata, {})
    assert index is not None and index.unreadable == 1
    assert set(index.unmatched_keys(["CN=Acme CA", "CN=Odd CA"])) == {"CN=Odd CA"}
    warned = [r.getMessage() for r in caplog.records]
    assert any("1 certificate(s) in tls_ca_file could not be parsed" in m for m in warned), warned


def test_a_version_4_leaf_names_no_issuer() -> None:
    """``issuer_of`` never raises, so a leaf ``cryptography`` refuses with ``InvalidVersion`` names
    no issuer rather than ending the connection's admission check (BACKLOG #4948)."""
    ca = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    index = IssuerIndex(_pem(ca[0]).decode("ascii"))
    assert index.issuer_of(_der(ca[0])) == "CN=Acme CA"  # control
    assert index.issuer_of(_v4(ca[0])) == ""


def _pinned(cn: str) -> x509.Certificate:
    """A self-signed client certificate with no ``basicConstraints`` or ``keyUsage``. OpenSSL does
    not count it as a CA, though the context holds it as an anchor and the index names it by its
    own subject."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = _dn((NameOID.COMMON_NAME, cn))
    now = datetime.datetime.now(datetime.UTC)
    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )


#: Text before a probe's BEGIN marker on its line, and text after it, each with whether OpenSSL 3.5.7
#: was measured to load the probe. OpenSSL reads a long line in 254-byte pieces, so a marker opening
#: the second piece loads (pki._OPENSSL_LINE_PIECE); it strips trailing bytes at or below a space.
_BEFORE = {
    "line": ("", True),
    "space": (" ", False),
    "text": ("x ", False),
    "lone-cr": ("\r", False),
    "254-bytes": ("y" * 254, True),
    "255-bytes": ("y" * 255, False),
}
_AFTER = {
    "spaces": ("  ", True),
    "tab": ("\t", True),
    "crlf": ("\r", True),
    "control": ("\x0b", True),
    "space-text": (" x", False),
    "text": ("x", False),
}


@pytest.mark.parametrize("pinned", [False, True], ids=["ca", "pinned"])
@pytest.mark.parametrize(
    ("before", "after", "loads"),
    [
        *(pytest.param(b, "", ok, id=f"before-{k}") for k, (b, ok) in _BEFORE.items()),
        *(pytest.param("", a, ok, id=f"after-{k}") for k, (a, ok) in _AFTER.items()),
    ],
)
@pytest.mark.parametrize(
    "label",
    [
        "CERTIFICATE",
        "X509 CERTIFICATE",
        "TRUSTED CERTIFICATE",
        "PKCS7",
        "CERTIFICATE PAIR",
        "x509 certificate",
    ],
)
def test_the_index_reads_a_block_where_the_context_loads_it(
    label: str, before: str, after: str, loads: bool, pinned: bool
) -> None:
    """On each shape here, the index reads a block where ``load_verify_locations(cadata=)`` loads
    it and skips it where that skips it: by label, and by what shares the BEGIN marker's line
    (BACKLOG #4948). The index models OpenSSL's reader; it is not that reader, so this is a sample.

    A CA the handshake trusts that the index skips denies every partner under it; a CA the index
    reads that the handshake never loaded could be named for a leaf whose chain ran through a
    client-sent copy of it. So each shape is asked of OpenSSL here, not assumed, for a CA and for a
    pinned client certificate OpenSSL does not count as one."""
    plain = _ca(_dn((NameOID.COMMON_NAME, "Plain CA")))
    probe = _pinned("Probe") if pinned else _ca(_dn((NameOID.COMMON_NAME, "Probe")))[0]
    marker = f"-----BEGIN {label}-----".encode("ascii")
    block = _labelled(probe, label).replace(marker, marker + after.encode("ascii"), 1)
    cadata = (_pem(plain[0]) + before.encode("ascii") + block).decode("ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    loaded = ctx.cert_store_stats()["x509"]
    # The measured premise, so the check below cannot pass by OpenSSL loading nothing.
    assert loaded == (2 if loads and label in ("CERTIFICATE", "X509 CERTIFICATE") else 1)
    index = IssuerIndex(cadata)
    assert index.unreadable == 0
    assert index.unmatched_keys(["CN=Plain CA"]) == {}  # control: always read
    probe_read = index.unmatched_keys(["CN=Probe"]) == {}
    assert probe_read == (loaded == 2), (label, before, after, pinned, loaded)


@pytest.mark.parametrize(
    "note",
    [
        pytest.param("note: -----BEGIN {}----- also loads\n", id="mid-line"),
        pytest.param("-----BEGIN {}----- blocks follow\n", id="line-start"),
    ],
)
@pytest.mark.parametrize("stray", ["CERTIFICATE", "X509 CERTIFICATE"])
def test_a_stray_begin_marker_hides_no_block_after_it(note: str, stray: str) -> None:
    """A note naming a BEGIN marker, mid-line or opening a line with text after it, is skipped by
    OpenSSL, and every block after it still loads. Two CAs here share a DN under different keys,
    with a legacy-label CA between them. A stray that ran to the next END of its label would swallow
    the blocks before it, so the index would read one block fewer, or one of the two CAs. With one
    of the two missing, a leaf under the other would be named although the two cannot be told apart.
    The index must read all three, so the name stays ambiguous (BACKLOG #4948)."""
    dup1, dup2 = (_ca(_dn((NameOID.COMMON_NAME, "Dup CA"))) for _ in range(2))
    mid = _ca(_dn((NameOID.COMMON_NAME, "Mid CA")))
    cadata = (
        note.format(stray).encode("ascii")
        + _pem(dup1[0])
        + _labelled(mid[0], "X509 CERTIFICATE")
        + _pem(dup2[0])
    ).decode("ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert ctx.cert_store_stats()["x509"] == 3  # the premise: every block loads past the note
    index = IssuerIndex(cadata)
    assert index.unreadable == 0
    assert index.unmatched_keys(["CN=Mid CA"]) == {}
    assert index.unmatched_keys(["CN=Dup CA"])["CN=Dup CA"].startswith("names 2 loaded CA")
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), dup2)[0])
    assert index.issuer_of(leaf) == ""


@pytest.mark.parametrize("label", ["CERTIFICATE", "X509 CERTIFICATE"])
def test_a_block_whose_begin_line_is_commented_out_names_no_issuer(label: str) -> None:
    """An intermediate disabled by commenting out only its BEGIN line is not loaded by OpenSSL. The
    index must not name it either: a client that sends that intermediate verifies through the root,
    and would otherwise map under the intermediate's name, though a client-sent intermediate never
    counts (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    partner = _ca(_dn((NameOID.COMMON_NAME, "Partner CA")), by=root)
    cadata = (_pem(root[0]) + b"# " + _labelled(partner[0], label)).decode("ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert ctx.cert_store_stats()["x509"] == 1  # the premise: only the root loads
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Root CA"]) == {}  # control
    assert "CN=Partner CA" in index.unmatched_keys(["CN=Partner CA"])
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), partner)[0])
    assert index.issuer_of(leaf) == ""


@pytest.mark.parametrize(
    "subjects",
    [
        pytest.param([SUBJECT], id="flat-list"),
        pytest.param({"CN=Acme CA": SUBJECT}, id="issuer-names-a-string"),
    ],
)
def test_a_directly_built_source_refuses_a_table_that_is_not_one(subjects: Any) -> None:
    """A ``Source`` built without the ``Http()`` factory still fails at construction on the retired
    flat list, or on an issuer naming a string, which would otherwise be read character by
    character and deny the partner with nothing in the log."""
    with pytest.raises(ValueError, match="must be a table keyed by the issuing CA's DN"):
        HttpSource(
            Source(
                type=ConnectorType.HTTP,
                settings={
                    "host": "127.0.0.1",
                    "port": 0,
                    "intake_auth": "mtls_subject",
                    "intake_client_subjects": subjects,
                },
            )
        )


def test_only_mtls_subject_builds_an_issuer_index(tmp_path: Path) -> None:
    """The index is read only under ``mtls_subject``; a bare mTLS listener parses nothing extra."""
    ca = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    (tmp_path / "bare").mkdir()
    assert _source(tmp_path / "bare", [ca[0]], None)._issuer_index is None
    assert _source(tmp_path, [ca[0]], {"CN=Acme CA": [SUBJECT]})._issuer_index is not None


# --- the factory: the shape is a table keyed by issuer --------------------------------------------


def _http(subjects: Any) -> Any:
    return Http(
        port=8443,
        tls=True,
        tls_cert_file="server.pem",
        tls_key_file="server.key",
        tls_ca_file="ca.pem",
        intake_auth="mtls_subject",
        intake_client_subjects=subjects,
    )


def test_the_flat_list_is_refused_naming_the_table_to_write() -> None:
    with pytest.raises(WiringError, match="must be a table keyed by the DN of the CA") as excinfo:
        _http([SUBJECT])
    assert "{'CN=Acme CA,O=Acme': ['CN:partner.example']}" in str(excinfo.value)


@pytest.mark.parametrize(
    ("subjects", "message"),
    [
        pytest.param(
            {"not a dn": [SUBJECT]}, "is not an RFC 4514 distinguished name", id="not-a-dn"
        ),
        pytest.param(
            # A hex escape for a plain character parses, but renders without it.
            {r"CN=\41cme CA": [SUBJECT]},
            "write it as the key 'CN=Acme CA'",
            id="non-canonical",
        ),
        pytest.param({"CN=Acme CA": []}, "names no subjects", id="empty-list"),
        pytest.param({"CN=Acme CA": SUBJECT}, "must name a list of subjects", id="bare-string"),
        pytest.param({"CN=Acme CA": [""]}, "item 0 must be a non-empty subject name", id="blank"),
        pytest.param({"CN=Acme CA": [5]}, "item 0 must be a non-empty subject name", id="not-str"),
        pytest.param({"CN=Acme CA": ["partner.example"]}, "must be qualified", id="unqualified"),
        pytest.param(
            {"CN=Acme CA": ["SAN:partner.example"]}, "must be qualified", id="san-no-type"
        ),
        pytest.param({"CN=Acme CA": ["CN:"]}, "must be qualified", id="empty-cn"),
    ],
)
def test_the_factory_refuses_what_cannot_match(subjects: Any, message: str) -> None:
    with pytest.raises(WiringError, match=message):
        _http(subjects)


def test_a_subject_table_is_refused_where_no_certificate_is_read() -> None:
    """The table is consulted only under ``mtls_subject``, so a key mode that sets it is refused, as
    ``intake_auth="none"`` already was: a control configured but never consulted."""
    for mode in ("api_key", "bearer"):
        with pytest.raises(WiringError, match=f"intake_auth='{mode}', which never reads"):
            Http(
                port=8443,
                intake_auth=mode,
                intake_api_key=env("acme_intake_key"),
                intake_client_subjects={"CN=Acme CA": [SUBJECT]},
            )


def test_a_valid_table_is_carried_onto_the_spec() -> None:
    spec = _http({"CN=Acme CA": [SUBJECT, "SAN:DNS:partner.example"], "CN=Other CA": [SUBJECT]})
    assert spec.settings["intake_client_subjects"] == {
        "CN=Acme CA": [SUBJECT, "SAN:DNS:partner.example"],
        "CN=Other CA": [SUBJECT],
    }
    # An empty table is no allow-list at all, so mtls_subject still refuses it.
    with pytest.raises(WiringError, match="needs a non-empty intake_client_subjects"):
        _http({})
