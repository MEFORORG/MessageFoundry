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
import base64
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
from tests.test_api_tls import _CaPair, _client_bundle, _dn, _new_ca, _pem, _self_signed

SUBJECT = "CN:partner.example"


def _ca(dn: x509.Name, by: _CaPair | None = None) -> _CaPair:
    """``tests/test_api_tls.py``'s CA, with the ``keyUsage`` the listener's strict verify needs."""
    return _new_ca(dn, by, key_usage=True)


def _bundle(tmp_path: Path, signer: _CaPair, **kwargs: Any) -> Path:
    """``tests/test_api_tls.py``'s client bundle, for the partner subject this module lists."""
    return _client_bundle(tmp_path, signer, cn="partner.example", **kwargs)


def _labelled(cert: x509.Certificate, label: str) -> bytes:
    """``cert`` as one PEM block under ``label`` in place of ``CERTIFICATE``, body unchanged."""
    return (
        _pem(cert)
        .replace(b"-----BEGIN CERTIFICATE-----", f"-----BEGIN {label}-----".encode("ascii"))
        .replace(b"-----END CERTIFICATE-----", f"-----END {label}-----".encode("ascii"))
    )


def _source(
    tmp_path: Path,
    trusted: list[x509.Certificate],
    subjects: dict[str, list[str]] | None,
    *,
    label: str = "CERTIFICATE",
    cadata: str | None = None,
) -> HttpSource:
    """A loopback mTLS listener trusting ``trusted``, built through the ``Http()`` factory.

    ``subjects`` set means ``mtls_subject``; ``None`` means a bare mTLS listener with no intake auth.
    ``label`` is the PEM label every block in ``tls_ca_file`` is written under. ``cadata``, when
    given, is written to ``tls_ca_file`` as it stands, in place of ``trusted``."""
    cert, key = _self_signed(tmp_path)
    ca_file = tmp_path / "client-ca.pem"
    if cadata is None:
        ca_file.write_bytes(b"".join(_labelled(c, label) for c in trusted))
    else:
        ca_file.write_text(cadata, encoding="ascii")
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
    handshake verified a leaf, but the index read only ``BEGIN CERTIFICATE``, so it never held the
    CA: every partner under it was refused, and the start warning said the key named no loaded CA
    rather than that a block went unread (BACKLOG #4948)."""
    named = _ca(_dn((NameOID.ORGANIZATION_NAME, "Acme"), (NameOID.COMMON_NAME, "Partner CA")))
    other = _ca(_dn((NameOID.ORGANIZATION_NAME, "Other"), (NameOID.COMMON_NAME, "Other CA")))
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        source = _source(
            tmp_path,
            [named[0], other[0]],
            {named[0].subject.rfc4514_string(): [SUBJECT]},
            label=label,
        )
    at_start = [r.getMessage() for r in caplog.records]
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


@pytest.mark.parametrize("label", ["CERTIFICATE", "X509 CERTIFICATE"])
def test_an_unparsable_certificate_in_the_trust_store_is_warned_about(
    caplog: pytest.LogCaptureFixture, label: str
) -> None:
    """Driven at the index builder: a block OpenSSL loads but ``cryptography`` refuses, a CA with
    bytes after its DER, is what this warns about. Under either label the context loads a CA from,
    such a block names no issuer and is counted once: fail closed, with a warning. The good CA
    beside it is still named (BACKLOG #4948)."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    junk = (
        _wrapped(_der(odd[0]) + b"\x30\x00")
        .replace("BEGIN CERTIFICATE", f"BEGIN {label}")
        .replace("END CERTIFICATE", f"END {label}")
    )
    cadata = _pem(good[0]).decode("ascii") + junk
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert len(ctx.get_ca_certs()) == 2  # the premise: OpenSSL loads the odd block
    subjects = {"CN=Acme CA": [SUBJECT], "CN=Odd CA": [SUBJECT]}
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        index = _client_issuer_index("IB_PARTNER", cadata, subjects)
    assert index is not None and (index.unreadable, index.unconfirmed) == (1, 0)
    assert set(index.unmatched_keys(subjects)) == {"CN=Odd CA"}
    warned = [r.getMessage() for r in caplog.records]
    assert any("1 certificate(s) in tls_ca_file could not be parsed" in m for m in warned), warned
    assert any("'CN=Odd CA'" in m and "1 certificate(s) set aside above" in m for m in warned), (
        warned
    )
    # Control: the same store without the junk block warns about nothing.
    caplog.clear()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        _client_issuer_index("IB_PARTNER", _pem(good[0]).decode("ascii"), {"CN=Acme CA": [SUBJECT]})
    assert not caplog.records


def test_a_refused_copy_of_a_ca_does_not_unname_a_good_copy(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """One CA in a good block and in a block ``cryptography`` refuses: the good block names it, the
    refused one is counted once, and the warning says the refusal holds unless the same certificate
    is loaded from another block (BACKLOG #4948)."""
    ca = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    cadata = _pem(ca[0]).decode("ascii") + _wrapped(_der(ca[0]) + b"\x30\x00")
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        index = _client_issuer_index("IB_PARTNER", cadata, {"CN=Acme CA": [SUBJECT]})
    assert index is not None and (index.unreadable, index.unconfirmed) == (1, 0)
    assert index.unmatched_keys(["CN=Acme CA"]) == {}
    warned = [r.getMessage() for r in caplog.records]
    assert (
        len(warned) == 1 and "unless the same certificate is loaded from another block" in warned[0]
    )


def _pinned(cn: str) -> x509.Certificate:
    """A self-signed client certificate with no ``basicConstraints`` or ``keyUsage``. OpenSSL does
    not count it as a CA, so ``get_ca_certs`` never lists it, though the context holds it as an
    anchor and the index names it by its own subject."""
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


def _der(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.DER)


def _wrapped(der: bytes) -> str:
    """``der`` as one ``CERTIFICATE`` PEM block, whatever bytes it holds."""
    body = base64.b64encode(der).decode("ascii")
    lines = "\n".join(body[at : at + 64] for at in range(0, len(body), 64))
    return f"-----BEGIN CERTIFICATE-----\n{lines}\n-----END CERTIFICATE-----\n"


def _probe(
    label: str, *, prefix: str = "", suffix: str = "", head: str = "", pinned: bool = False
) -> tuple[int, bool]:
    """How many certificates ``cadata=`` loads from a plain CA plus a probe written under ``label``,
    with ``prefix`` before and ``suffix`` after the marker on the probe's BEGIN line and ``head``
    above both blocks, and whether the index reads the probe. The probe is a CA, or with ``pinned``
    a self-signed client certificate OpenSSL does not count as one."""
    plain = _ca(_dn((NameOID.COMMON_NAME, "Plain CA")))
    probe = _pinned("Probe") if pinned else _ca(_dn((NameOID.COMMON_NAME, "Probe")))[0]
    marker = f"-----BEGIN {label}-----"
    block = _labelled(probe, label).decode("ascii").replace(marker, marker + suffix, 1)
    cadata = head + _pem(plain[0]).decode("ascii") + prefix + block
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    index = _client_issuer_index("IB_PARTNER", cadata, {})
    assert index is not None and index.unreadable == 0
    assert "CN=Plain CA" not in index.unmatched_keys(["CN=Plain CA"])  # control: always read
    return ctx.cert_store_stats()["x509"], "CN=Probe" not in index.unmatched_keys(["CN=Probe"])


@pytest.mark.parametrize("pinned", [False, True], ids=["ca", "pinned"])
@pytest.mark.parametrize("prefix", ["", " ", "x ", "\r"], ids=["line", "space", "text", "lone-cr"])
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
def test_the_index_reads_the_same_blocks_the_context_loads(
    label: str, prefix: str, pinned: bool
) -> None:
    """The index and ``load_verify_locations(cadata=)`` agree, block by block (BACKLOG #4948).

    Measured on CPython 3.14.7 / OpenSSL 3.5.7: beside a plain block, ``cadata=`` loads a certificate
    from a ``CERTIFICATE`` or an ``X509 CERTIFICATE`` block whose BEGIN marker starts a line, and
    skips, without a word, every other label and a marker after a space, text or a lone CR. A CA the
    handshake trusts that the index skips denies every partner under it; a CA the index reads that
    the handshake never loaded could be named for a leaf whose chain ran through a client-sent copy
    of it. So each shape is asked of OpenSSL here, not assumed, for a CA and for a pinned client
    certificate OpenSSL does not count as one, which the index confirms by another route."""
    loaded, indexed = _probe(label, prefix=prefix, pinned=pinned)
    assert loaded in (1, 2), loaded
    assert indexed == (loaded == 2), (label, prefix, pinned, loaded)


@pytest.mark.parametrize(
    ("suffix", "head"),
    [
        pytest.param("  ", "", id="trailing-spaces"),
        pytest.param("\t", "", id="trailing-tab"),
        pytest.param("\r", "", id="crlf"),
        pytest.param("\x0b", "", id="trailing-control"),
        pytest.param(" Comment: issuing CA\n", "", id="header-text-after"),
        pytest.param("x", "", id="text-after"),
        pytest.param("\rjunk", "", id="lone-cr-then-text"),
        pytest.param("", "-----BEGIN X509 CERTIFICATE----- also accepted\n", id="legacy-comment"),
        pytest.param("", "-----BEGIN CERTIFICATE----- blocks follow\n", id="plain-comment"),
    ],
)
@pytest.mark.parametrize("pinned", [False, True], ids=["ca", "pinned"])
@pytest.mark.parametrize("label", ["CERTIFICATE", "X509 CERTIFICATE"])
def test_the_index_reads_a_begin_line_only_where_the_context_does(
    label: str, suffix: str, head: str, pinned: bool
) -> None:
    """The rest of the BEGIN line, and a comment line naming a marker, agree too (BACKLOG #4948).

    Measured on CPython 3.14.7 / OpenSSL 3.5.7: OpenSSL strips trailing bytes at or below a space,
    then reads a BEGIN line only where the marker is the whole line, so it loads a probe after
    trailing spaces, a tab, a CR or a control byte, and skips one with text after its marker. A
    comment line that opens with a marker and goes on with text is skipped too, and the blocks below
    it still load. An index that read text after a marker would name a CA the context skipped; one
    that took a comment line for a block would lose the CA below it, or every CA after it."""
    loaded, indexed = _probe(label, suffix=suffix, head=head, pinned=pinned)
    assert loaded in (1, 2), loaded
    assert indexed == (loaded == 2), (label, suffix, head, pinned, loaded)


def test_a_ca_the_scan_skips_is_taken_from_what_the_context_loaded() -> None:
    """OpenSSL reads a long line in 254-byte pieces, so a BEGIN marker starting the second piece
    loads. The scan models a line, not those pieces, so it skips that block; the index then takes the
    CA from the scratch context's own list instead of denying every partner under it."""
    assert _probe("CERTIFICATE", prefix="y" * 254) == (2, True)


def test_a_ca_the_scan_reads_but_the_context_skipped_names_no_issuer(
    caplog: pytest.LogCaptureFixture,
) -> None:
    """The admit direction. An END marker that does not start its line is body text to OpenSSL, so
    it reads past it, and a CA block after it is never loaded. The scan finds that END anyway and
    reads the next block. The index names only what the context holds, sets the rest aside, and says
    so at start, rather than name a CA a client could present a cross-signed copy of."""
    a = _ca(_dn((NameOID.COMMON_NAME, "A CA")))
    b = _ca(_dn((NameOID.COMMON_NAME, "B CA")))
    cadata = _pem(a[0]).decode("ascii").replace(
        "-----END CERTIFICATE-----", " -----END CERTIFICATE-----"
    ) + _pem(b[0]).decode("ascii")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    held = [c["subject"] for c in ctx.get_ca_certs()]
    assert held == [((("commonName", "A CA"),),)], held  # the premise: B was never loaded
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        index = _client_issuer_index("IB_PARTNER", cadata, {"CN=B CA": [SUBJECT]})
    assert index is not None and index.unconfirmed >= 1
    assert set(index.unmatched_keys(["CN=A CA", "CN=B CA"])) == {"CN=B CA"}
    warned = [r.getMessage() for r in caplog.records]
    assert any("could not be matched to what the TLS context loaded" in m for m in warned), warned


def test_text_the_context_refuses_names_no_issuer() -> None:
    """No context can verify a peer against text it refuses, so the index names nothing from it."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    junk = "-----BEGIN CERTIFICATE-----\nbm90IGEgY2VydGlmaWNhdGU=\n-----END CERTIFICATE-----\n"
    index = _client_issuer_index("IB_PARTNER", _pem(good[0]).decode("ascii") + junk, {})
    assert index is not None and (index.unreadable, index.unconfirmed) == (1, 1)
    assert "CN=Acme CA" in index.unmatched_keys(["CN=Acme CA"])


def test_a_ca_the_context_skipped_is_not_named_when_the_counts_coincide() -> None:
    """The admit direction, where a count could not see it. The context holds CA ``A`` and a pinned
    ``Z`` the scan missed; the scan read ``A`` and a CA ``B`` the context skipped. Both hold one
    certificate besides ``A``, so a count of the certificates OpenSSL does not list agreed, and
    ``B`` was named. Each certificate is now asked of the context by itself (BACKLOG #4948)."""
    a = _ca(_dn((NameOID.COMMON_NAME, "A CA")))
    b = _ca(_dn((NameOID.COMMON_NAME, "B CA")))
    z = _pinned("Z pinned")
    cadata = (
        _pem(a[0])
        .decode("ascii")
        .replace("-----END CERTIFICATE-----", " -----END CERTIFICATE-----")
        + _pem(b[0]).decode("ascii")
        + "y" * 254
        + _pem(z).decode("ascii")
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert ctx.get_ca_certs(binary_form=True) == [_der(a[0])]  # the premise: B never loaded...
    assert ctx.cert_store_stats()["x509"] == 2  # ...and Z did
    index = IssuerIndex(cadata)
    unmatched = index.unmatched_keys(["CN=A CA", "CN=B CA", "CN=Z pinned"])
    # B is set aside and counted once; Z, which the context holds, is found by the loose pass.
    assert set(unmatched) == {"CN=B CA"}
    assert (index.unreadable, index.unconfirmed) == (0, 1)


def test_one_unreadable_pinned_certificate_does_not_drop_the_good_ones() -> None:
    """Each pinned certificate is judged by itself. A pinned certificate with bytes after its DER
    loads in OpenSSL and not in ``cryptography``: it names nothing and is counted once, as
    unreadable, and the two good pinned certificates beside it still name themselves. Before, the
    count of certificates OpenSSL does not list disagreed, so every one was set aside, and the larger
    count was added on top of the unreadable one (BACKLOG #4948)."""
    ca = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    good = [_pinned("One pinned"), _pinned("Two pinned")]
    bad = _pinned("Bad pinned")
    cadata = (
        _pem(ca[0]).decode("ascii")
        + "".join(_pem(c).decode("ascii") for c in good)
        + _wrapped(_der(bad) + b"\x30\x00")
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert ctx.cert_store_stats()["x509"] == 4  # the premise: OpenSSL loads the bad one
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Acme CA", "CN=One pinned", "CN=Two pinned"]) == {}
    assert "CN=Bad pinned" in index.unmatched_keys(["CN=Bad pinned"])
    assert (index.unreadable, index.unconfirmed) == (1, 0)
    for cert in good:
        assert index.issuer_of(_der(cert)) == cert.subject.rfc4514_string()


def test_a_pinned_certificate_the_scan_missed_is_named_only_where_the_context_holds_it() -> None:
    """A pinned certificate cannot be listed back from a context, so one OpenSSL loads from a block
    the scan skips is looked for with a marker anywhere on a line, as origin/main's scan read it,
    and named only where loading it adds nothing to the context's store. ``Missed`` starts the
    second 254-byte piece of a long line, which OpenSSL loads; ``Skipped`` follows text on its
    line, which OpenSSL does not. The loose pass finds both, and names only the one held."""
    ca = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    read, missed, skipped = _pinned("Read pinned"), _pinned("Missed pinned"), _pinned("Skipped")
    cadata = (
        _pem(ca[0]).decode("ascii")
        + _pem(read).decode("ascii")
        + "y" * 254
        + _pem(missed).decode("ascii")
        + "x "
        + _pem(skipped).decode("ascii")
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert ctx.cert_store_stats()["x509"] == 3  # the premise: Missed loads, Skipped does not
    index = IssuerIndex(cadata)
    keys = ["CN=Acme CA", "CN=Read pinned", "CN=Missed pinned", "CN=Skipped"]
    assert set(index.unmatched_keys(keys)) == {"CN=Skipped"}
    assert (index.unreadable, index.unconfirmed) == (0, 0)


def _v4(cert: x509.Certificate) -> bytes:
    """``cert``'s DER with its version field set to 4, which OpenSSL loads and ``cryptography``
    refuses with ``InvalidVersion``, which is not a ``ValueError``."""
    der = _der(cert)
    v3 = b"\xa0\x03\x02\x01\x02"
    assert der.count(v3) == 1
    return der.replace(v3, b"\xa0\x03\x02\x01\x03")


@pytest.mark.parametrize("prefix", ["", "y" * 254], ids=["scanned", "context-only"])
def test_a_version_4_ca_names_nothing_and_does_not_end_the_build(prefix: str) -> None:
    """A CA OpenSSL loads with version 4 is refused by ``cryptography`` with ``InvalidVersion``.
    Read by the scan or taken from the context, it raised out of the index, and so out of the
    listener's and the API's context build. It now names nothing and is counted once, and the good
    CA beside it is still named (BACKLOG #4948)."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    cadata = _pem(good[0]).decode("ascii") + prefix + _wrapped(_v4(odd[0]))
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert len(ctx.get_ca_certs()) == 2  # the premise: OpenSSL loads it
    index = IssuerIndex(cadata)
    assert set(index.unmatched_keys(["CN=Acme CA", "CN=Odd CA"])) == {"CN=Odd CA"}
    # Read by the scan, it is a block that could not be parsed; missed by the scan, a CA the
    # context holds that could not be read.
    assert (index.unreadable, index.unconfirmed) == ((0, 1) if prefix else (1, 0))


def test_a_version_4_leaf_names_no_issuer() -> None:
    """``issuer_of`` never raises, so a leaf ``cryptography`` refuses with ``InvalidVersion`` names
    no issuer rather than ending the connection's admission check."""
    ca = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    index = IssuerIndex(_pem(ca[0]).decode("ascii"))
    assert index.issuer_of(_der(ca[0])) == "CN=Acme CA"  # control
    assert index.issuer_of(_v4(ca[0])) == ""


async def test_a_ca_openssl_loads_but_cryptography_refuses_admits_no_partner(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """The case the start warning describes, through a real listener and handshake. A CA block with
    bytes after its DER loads in OpenSSL, so the handshake verifies a partner under it, and
    ``cryptography`` refuses the block. The index must not take that CA from the context instead:
    it names nothing, the warning that it could not be parsed and that no client certificate is
    admitted under it holds, and the partner is refused (BACKLOG #4948)."""
    refused = _ca(_dn((NameOID.COMMON_NAME, "Refused CA")))
    good = _ca(_dn((NameOID.COMMON_NAME, "Good CA")))
    cadata = _pem(good[0]).decode("ascii") + _wrapped(_der(refused[0]) + b"\x30\x00")
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    assert _der(refused[0]) in ctx.get_ca_certs(binary_form=True)  # the premise: OpenSSL holds it
    subjects = {"CN=Refused CA": [SUBJECT], "CN=Good CA": [SUBJECT]}
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        source = _source(tmp_path, [], subjects, cadata=cadata)
    warned = [r.getMessage() for r in caplog.records]
    assert any(
        "1 certificate(s) in tls_ca_file could not be parsed" in m
        and "no client certificate is admitted" in m
        for m in warned
    ), warned
    assert not any("could not be matched" in m for m in warned), warned  # counted once
    await _started(source)
    try:
        assert await _admitted(source, _bundle(tmp_path, good)) == 202  # control
        assert await _refused(source, _bundle(tmp_path, refused)) == 403
    finally:
        await source.stop()


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
