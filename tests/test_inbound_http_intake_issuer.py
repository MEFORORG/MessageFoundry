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
from collections import Counter
from dataclasses import replace
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.name import _ASN1Type
from cryptography.x509.oid import ExtensionOID, NameOID

from messagefoundry import pki
from messagefoundry.api.tls import _attach_issuer_index
from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import Http, WiringError, env
from messagefoundry.pki import IssuerIndex
from messagefoundry.transports.http_listener import HttpSource, _client_issuer_index
from messagefoundry.transports.mllp import _sender_issuer_lookup
from messagefoundry.transports.receipt import IngressReceipt, receipt_handler
from tests._approved_key_wrap import oid, seq, tlv
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


def _client_context(bundle: Path) -> ssl.SSLContext:
    """A client context presenting ``bundle`` that verifies nothing: the LISTENER side is the
    verifier under test."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.load_cert_chain(bundle)
    return ctx


async def _status(source: HttpSource, bundle: Path, *, send: bool) -> int:
    """The HTTP status the listener answers a client presenting ``bundle``.

    A refusal is answered at accept, before any request byte is read, so a case expecting one sends
    nothing (``send=False``) and only reads: writing into a socket the listener is closing can reset
    it and lose the status. If such a client were admitted instead, the listener would wait for a
    request and the read would time out, failing the case. ``send=True`` posts a body first."""
    reader, writer = await asyncio.open_connection(
        "127.0.0.1", source.sockport, ssl=_client_context(bundle)
    )
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

    def check_peer(self, peer: str) -> bool:
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


def _openssl_context(cadata: str) -> ssl.SSLContext:
    """A context that has run OpenSSL's ``load_verify_locations(cadata=)`` over ``cadata``."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_verify_locations(cadata=cadata)
    return ctx


def _openssl_loads(cadata: str) -> int:
    """How many certificates OpenSSL's ``load_verify_locations(cadata=)`` loads from ``cadata``."""
    return int(_openssl_context(cadata).cert_store_stats()["x509"])


def _wrapped(der: bytes, label: str = "CERTIFICATE") -> bytes:
    """``der`` as one PEM block under ``label``, whatever bytes it holds."""
    return _relabelled(ssl.DER_cert_to_PEM_cert(der).encode("ascii"), label)


@pytest.mark.parametrize("label", ["CERTIFICATE", "X509 CERTIFICATE"])
def test_an_unparsable_certificate_in_the_trust_store_refuses_the_build(
    caplog: pytest.LogCaptureFixture, label: str
) -> None:
    """Driven at the index builder: a block OpenSSL loads but ``cryptography`` refuses, a CA with
    bytes after its DER, refuses the build under either label the context loads a CA from, naming
    the listener's file. Counted and skipped instead, it left a CA the handshake trusts out of the
    index, which can hide a same-DN twin (BACKLOG #4948)."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    cadata = (_pem(good[0]) + _wrapped(_der(odd[0]) + b"\x30\x00", label)).decode("ascii")
    assert _openssl_loads(cadata) == 2  # the premise: OpenSSL loads the odd block
    with pytest.raises(
        ValueError, match=r"IB_PARTNER': tls_ca_file: .*certificate block 2 .*cannot be parsed"
    ):
        _client_issuer_index("IB_PARTNER", cadata, {"CN=Acme CA": [SUBJECT]})
    # Control: the same store without the junk block builds and warns about nothing.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        _client_issuer_index("IB_PARTNER", _pem(good[0]).decode("ascii"), {"CN=Acme CA": [SUBJECT]})
    assert not caplog.records


#: A certificate's DER version field, for version 3.
_VERSION_3 = b"\xa0\x03\x02\x01\x02"


def _v4(cert: x509.Certificate) -> bytes:
    """``cert``'s DER with its version field set to 4, which OpenSSL loads and ``cryptography``
    refuses with ``InvalidVersion``, which is not a ``ValueError``."""
    der = _der(cert)
    assert der.count(_VERSION_3) == 1
    return der.replace(_VERSION_3, b"\xa0\x03\x02\x01\x03")


def _odd_twin(cert: x509.Certificate, shape: str) -> bytes:
    """``cert`` as one PEM block that OpenSSL loads and ``cryptography`` refuses, by ``shape``."""
    if shape == "v4":
        return _wrapped(_v4(cert))
    if shape == "trailing-der":
        return _wrapped(_der(cert) + b"\x30\x00")
    lines = _pem(cert).split(b"\n")
    lines[1] += b"\x00junk"  # "nul-text": a NUL and more text inside a base64 line
    return b"\n".join(lines)


def test_a_version_4_ca_refuses_the_build() -> None:
    """A CA OpenSSL loads with version 4 is refused by ``cryptography`` with ``InvalidVersion``,
    which is not a ``ValueError``. In the shipped code it raises out of the index, and so out of
    the listener's and the API's context build. It still refuses that build, now as a
    ``ValueError`` naming the file (BACKLOG #4948)."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    cadata = (_pem(good[0]) + _odd_twin(odd[0], "v4")).decode("ascii")
    assert _openssl_loads(cadata) == 2  # the premise: OpenSSL loads it
    with pytest.raises(ValueError, match=r"IB_PARTNER': tls_ca_file: .*cannot be parsed"):
        _client_issuer_index("IB_PARTNER", cadata, {})


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
    # Bytes OpenSSL strips that cryptography refuses after a BEGIN marker: the index hands
    # cryptography the line OpenSSL read, so these name their CA rather than refuse the build.
    "nul": ("\x00", True),
    "soh": ("\x01", True),
    "us": ("\x1f", True),
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
    loaded = _openssl_loads(cadata)
    # The measured premise, so the check below cannot pass by OpenSSL loading nothing.
    assert loaded == (2 if loads and label in ("CERTIFICATE", "X509 CERTIFICATE") else 1)
    index = IssuerIndex(cadata)
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
    assert _openssl_loads(cadata) == 3  # the premise: every block loads past the note
    index = IssuerIndex(cadata)
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
    assert _openssl_loads(cadata) == 1  # the premise: only the root loads
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Root CA"]) == {}  # control
    assert "CN=Partner CA" in index.unmatched_keys(["CN=Partner CA"])
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), partner)[0])
    assert index.issuer_of(leaf) == ""


def _loaded_subjects(cadata: str) -> set[str]:
    """The subject of each CA certificate ``load_verify_locations(cadata=)`` loaded from
    ``cadata``. ``get_ca_certs`` lists CAs only, so a pinned non-CA certificate is not counted."""
    return {
        x509.load_der_x509_certificate(der).subject.rfc4514_string()
        for der in _openssl_context(cadata).get_ca_certs(binary_form=True)
    }


@pytest.mark.parametrize("outer", ["FOO", "X509 CRL"])
@pytest.mark.parametrize("header", [False, True], ids=["bare", "header"])
@pytest.mark.parametrize("inner", ["CERTIFICATE", "X509 CERTIFICATE"])
def test_a_certificate_nested_in_another_block_is_not_indexed(
    outer: str, header: bool, inner: str
) -> None:
    """OpenSSL reads every line of a block it does not load, up to that block's END line, and skips
    them, so a CERTIFICATE block nested inside another label's block is never loaded. An END line
    that does not open a line is part of the outer block's body to OpenSSL. The index must skip the
    same body: reading the nested BEGIN, it would run to the next END of that label, past the outer
    END, and ``cryptography`` would read the nested certificate from that text. A client sending the
    nested CA as its intermediate verifies through the root OpenSSL did load, so the index would
    name the nested CA, and a subject listed under it would be admitted (BACKLOG #4948)."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Good CA")))
    evil = _ca(_dn((NameOID.COMMON_NAME, "Evil CA")), by=good)
    end = f"-----END {inner}-----\n".encode("ascii")
    nested = _labelled(evil[0], inner).removesuffix(end)
    filler = b"aGVsbG8gd29ybGQ=\n"  # base64 for the outer block's own body
    outer_block = (
        f"-----BEGIN {outer}-----\n".encode("ascii")
        + (b"X: y\n" if header else b"")
        + nested
        + b" "  # OpenSSL reads this END as body, not as the end of a block
        + end
        + b"\n"
        + filler
        + f"-----END {outer}-----\n".encode("ascii")
    )
    cadata = (outer_block + _labelled(good[0], inner)).decode("ascii")
    assert _loaded_subjects(cadata) == {"CN=Good CA"}  # the premise: OpenSSL skips the nested CA
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Good CA"]) == {}  # control: what OpenSSL loaded is named
    assert "CN=Evil CA" in index.unmatched_keys(["CN=Evil CA"])
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), evil)[0])
    assert index.issuer_of(leaf) == ""


@pytest.mark.parametrize(
    ("width", "newline"),
    [
        pytest.param(254, "\n", id="254"),
        pytest.param(508, "\n", id="508"),
        pytest.param(253, "\r\n", id="253-crlf"),
    ],
)
def test_a_base64_line_wrapped_at_a_piece_boundary_is_read(width: int, newline: str) -> None:
    """OpenSSL reads a long line in 254-byte pieces, and a LF left alone by a full piece ends that
    line rather than being a blank line. The index must not hand ``cryptography`` a blank line in
    the body there, or a CA OpenSSL loads would refuse the build (BACKLOG #4948)."""
    plain = _ca(_dn((NameOID.COMMON_NAME, "Plain CA")))
    wide = _ca(_dn((NameOID.COMMON_NAME, "Wide CA")))
    b64 = "".join(_pem(wide[0]).decode("ascii").splitlines()[1:-1])
    assert len(b64) > width  # the premise: the body really spans a piece boundary
    rows = [b64[i : i + width] for i in range(0, len(b64), width)]
    block = newline.join(["-----BEGIN CERTIFICATE-----", *rows, "-----END CERTIFICATE-----", ""])
    cadata = _pem(plain[0]).decode("ascii") + block
    assert _loaded_subjects(cadata) == {"CN=Plain CA", "CN=Wide CA"}  # the premise
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Plain CA", "CN=Wide CA"]) == {}


def test_a_label_is_compared_up_to_a_nul_as_openssl_compares_it() -> None:
    """OpenSSL compares a PEM label with ``strcmp``, so ``CERTIFICATE`` then a NUL and more text
    loads as a certificate, with its END line naming ``CERTIFICATE``. The index must read it too,
    and must not take that END line as another label's and stop reading (BACKLOG #4948)."""
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    good = _ca(_dn((NameOID.COMMON_NAME, "Good CA")))
    marker = b"-----BEGIN CERTIFICATE-----"
    block = _pem(odd[0]).replace(marker, b"-----BEGIN CERTIFICATE\x00Z-----")
    cadata = (block + _pem(good[0])).decode("ascii")
    assert _loaded_subjects(cadata) == {"CN=Odd CA", "CN=Good CA"}  # the premise
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Odd CA", "CN=Good CA"]) == {}


@pytest.mark.parametrize(
    ("head", "tail"),
    [
        # OpenSSL's header check finds the ':' past the NUL.
        pytest.param(b"", b"\x00:junk", id="nul-then-colon"),
        # After a blank first body line, OpenSSL's 64-character data-line limit counts the byte
        # past the NUL.
        pytest.param(b"\n", b"\x00A", id="blank-then-nul-over-64"),
    ],
)
def test_a_body_line_with_a_nul_where_openssl_stops_refuses_the_build(
    head: bytes, tail: bytes
) -> None:
    """OpenSSL reads a body line past its first NUL in at least two checks, and on these shapes it
    silently stops loading the file there, so the intermediate after the root is never loaded. The
    index must not name that intermediate: a client sending it as its own intermediate verifies
    through the root, and a subject listed under the intermediate would be admitted. The build
    refuses (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    inter = _ca(_dn((NameOID.COMMON_NAME, "Inter CA")), by=root)
    lines = _pem(inter[0]).split(b"\n")
    lines[1] = head + lines[1] + tail
    cadata = (_pem(root[0]) + b"\n".join(lines)).decode("ascii")
    assert _loaded_subjects(cadata) == {"CN=Root CA"}  # the premise: OpenSSL stops after the root
    with pytest.raises(
        ValueError, match="the client CA file: certificate block 2 .*cannot be parsed"
    ):
        IssuerIndex(cadata)
    IssuerIndex(_pem(root[0]).decode("ascii"))  # control: the root alone builds


def test_a_ca_whose_base64_line_has_a_nul_and_more_base64_refuses_the_build() -> None:
    """OpenSSL loads a CA whose base64 line has a NUL and more base64 after it. The index reads
    the whole line, which ``cryptography`` refuses, so the build refuses: counted and skipped, the
    CA would be one the handshake trusts and the index misses (BACKLOG #4948)."""
    odd = _ca(_dn((NameOID.COMMON_NAME, "Odd CA")))
    good = _ca(_dn((NameOID.COMMON_NAME, "Good CA")))
    cadata = (_odd_twin(odd[0], "nul-text") + _pem(good[0])).decode("ascii")
    assert _loaded_subjects(cadata) == {"CN=Odd CA", "CN=Good CA"}  # the premise
    with pytest.raises(ValueError, match="cannot be parsed"):
        IssuerIndex(cadata)


@pytest.mark.parametrize("shape", ["v4", "trailing-der", "nul-text"])
def test_a_same_dn_twin_cryptography_cannot_parse_refuses_the_build(shape: str) -> None:
    """Two loaded CAs share a DN under different keys, and ``cryptography`` refuses one of them.
    OpenSSL loads both, so the handshake verifies a leaf under either. Counted as unreadable and
    dropped, the refused one left the other looking unambiguous, so a leaf under it was named
    although the two cannot be told apart. The build must refuse instead (BACKLOG #4948)."""
    twin1, twin2 = (_ca(_dn((NameOID.COMMON_NAME, "Acme CA"))) for _ in range(2))
    cadata = (_pem(twin1[0]) + _odd_twin(twin2[0], shape)).decode("ascii")
    assert _openssl_loads(cadata) == 2  # the premise: OpenSSL loads both twins
    with pytest.raises(ValueError, match="cannot be parsed"):
        IssuerIndex(cadata)
    # Controls: with both twins readable the name is ambiguous, and with one alone it is named.
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), twin1)[0])
    assert IssuerIndex((_pem(twin1[0]) + _pem(twin2[0])).decode("ascii")).issuer_of(leaf) == ""
    assert IssuerIndex(_pem(twin1[0]).decode("ascii")).issuer_of(leaf) == "CN=Acme CA"


_FILLER = b"aGVsbG8gd29ybGQ=\n"  # base64 for a non-certificate block's own body

#: Blocks after which OpenSSL 3.5.7 silently stops loading a file, while a PEM scan reads on.
_SILENT_STOPS = {
    "empty-foo": b"-----BEGIN FOO-----\n-----END FOO-----\n",
    "colon-label": b"-----BEGIN FOO:BAR-----\n" + _FILLER + b"-----END FOO:BAR-----\n",
    "blank-then-long": (
        b"-----BEGIN FOO-----\n" + _FILLER + b"\n" + b"QUFB" * 20 + b"\n-----END FOO-----\n"
    ),
}


@pytest.mark.parametrize("stop", list(_SILENT_STOPS))
def test_a_block_where_openssl_silently_stops_refuses_the_build(stop: str) -> None:
    """OpenSSL silently stops loading the file at each of these blocks, so the intermediate after
    them is never loaded, and a client sending it as its own intermediate verifies through the
    root. The PEM scan reads on and finds that intermediate, so the index would name it, and a
    subject listed under it would be admitted. The check against what OpenSSL loaded refuses the
    build, whatever the scan models (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    inter = _ca(_dn((NameOID.COMMON_NAME, "Inter CA")), by=root)
    cadata = (_pem(root[0]) + _SILENT_STOPS[stop] + _pem(inter[0])).decode("ascii")
    assert _loaded_subjects(cadata) == {"CN=Root CA"}  # the premise: OpenSSL stops after the root
    with pytest.raises(ValueError, match=r"does not load 1 CA certificate\(s\) the mTLS issuer"):
        IssuerIndex(cadata)
    # Control: with that block after the intermediate, OpenSSL loads both and the index names both.
    tail = (_pem(root[0]) + _pem(inter[0]) + _SILENT_STOPS[stop]).decode("ascii")
    assert _loaded_subjects(tail) == {"CN=Root CA", "CN=Inter CA"}
    assert IssuerIndex(tail).unmatched_keys(["CN=Root CA", "CN=Inter CA"]) == {}


def test_a_silent_stop_in_tls_ca_file_refuses_the_listener(tmp_path: Path) -> None:
    """The refusal reaches the listener's start, naming it and its file (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    inter = _ca(_dn((NameOID.COMMON_NAME, "Inter CA")), by=root)
    cadata = _pem(root[0]) + _SILENT_STOPS["empty-foo"] + _pem(inter[0])
    with pytest.raises(
        ValueError, match=r"HTTP listener .*: tls_ca_file: .*does not load 1 CA certificate"
    ):
        _source(tmp_path, [], {"CN=Inter CA": [SUBJECT]}, cadata=cadata)


def test_the_check_reads_what_openssl_lists_and_counts() -> None:
    """The premise the check rests on: ``get_ca_certs`` lists a CA as DER and not a pinned
    anchor, which only the count holds. A key rollover file, two CAs sharing a DN with a third
    between them, builds: on OpenSSL 3.5.7 a reload of the second twin there keeps a second copy,
    so a check resting on OpenSSL dropping a duplicate would refuse it (BACKLOG #4948)."""
    ca = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))[0]
    pinned = _pinned("Pinned")
    ctx = _openssl_context((_pem(ca) + _pem(pinned)).decode("ascii"))
    assert ctx.get_ca_certs(binary_form=True) == [_der(ca)]
    assert ctx.cert_store_stats() == {"x509": 2, "crl": 0, "x509_ca": 1}
    twin1, twin2 = (_ca(_dn((NameOID.COMMON_NAME, "Dup CA"))) for _ in range(2))
    mid = _ca(_dn((NameOID.COMMON_NAME, "Mid CA")))[0]
    index = IssuerIndex((_pem(twin1[0]) + _pem(mid) + _pem(twin2[0])).decode("ascii"))
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), twin2)[0])
    assert index.issuer_of(leaf) == ""  # the twins stay ambiguous


def test_a_rollover_file_listing_a_ca_twice_builds() -> None:
    """Two CAs share a DN, another CA sits between them, and the new one is listed twice. OpenSSL
    3.5.7 keeps both copies of it, so a check counting OpenSSL's CA list rather than comparing it
    as a set would refuse a file every handshake reads correctly (BACKLOG #4948)."""
    old, new = (_ca(_dn((NameOID.COMMON_NAME, "Acme CA"))) for _ in range(2))
    root = _ca(_dn((NameOID.COMMON_NAME, "Partner Root")))[0]
    cadata = (_pem(old[0]) + _pem(root) + _pem(new[0]) + _pem(new[0])).decode("ascii")
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Partner Root"]) == {}
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), new)[0])
    assert index.issuer_of(leaf) == ""  # the twins stay ambiguous


def test_the_check_refuses_a_ca_openssl_did_not_load_when_the_count_balances() -> None:
    """Driven at the check itself, with an index no scan produces: OpenSSL loaded a CA and a
    pinned certificate it reads as no CA, while the index holds that CA and another CA. Both hold
    two certificates, so only the per-certificate CA test catches the CA OpenSSL never loaded. And
    a CA OpenSSL loaded that the index missed refuses too (BACKLOG #4948)."""
    root = _der(_ca(_dn((NameOID.COMMON_NAME, "Root CA")))[0])
    phantom = _der(_ca(_dn((NameOID.COMMON_NAME, "Phantom CA")))[0])
    pinned = _pinned("Pinned")
    cadata = ssl.DER_cert_to_PEM_cert(root) + _pem(pinned).decode("ascii")
    assert _openssl_context(cadata).cert_store_stats() == {"x509": 2, "crl": 0, "x509_ca": 1}
    with pytest.raises(ValueError, match=r"does not load 1 CA certificate\(s\)"):
        pki._refuse_unless_openssl_loads(cadata, Counter([root, phantom]), label="x")
    with pytest.raises(ValueError, match=r"loads 1 CA certificate\(s\) .* did not read"):
        pki._refuse_unless_openssl_loads(cadata, Counter([_der(pinned)]), label="x")
    with pytest.raises(ValueError, match=r"loads 1 certificate\(s\) that are not CAs"):
        pki._refuse_unless_openssl_loads(cadata, Counter([root]), label="x")
    assert pki._refuse_unless_openssl_loads(cadata, Counter([root, _der(pinned)]), label="x") == {
        root
    }


def test_a_certificate_openssl_reads_as_no_ca_names_only_itself() -> None:
    """A pinned certificate OpenSSL reads as no CA is named for a leaf that is that certificate.
    OpenSSL never accepts it as the issuer of another leaf, so neither does the index: one that
    names a leaf its key signed would name a leaf whose chain ran through a client-sent CA with
    the same name and key (BACKLOG #4948)."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = _dn((NameOID.COMMON_NAME, "Pinned"))
    now = datetime.datetime.now(datetime.UTC)

    def _cert(subject: x509.Name) -> x509.Certificate:
        return (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(name)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=1))
            .sign(key, hashes.SHA256())
        )

    pinned, other = _cert(name), _cert(_dn((NameOID.COMMON_NAME, "leaf")))
    index = IssuerIndex(_pem(pinned).decode("ascii"))
    assert index.issuer_of(_der(pinned)) == "CN=Pinned"  # control: it names itself
    assert index.issuer_of(_der(other)) == ""


def _issued_no_ca(dn: x509.Name, by: _CaPair, *, skid: bool = True) -> x509.Certificate:
    """A certificate for ``dn`` that ``by`` signed, marked ``CA:FALSE``. It signs nothing OpenSSL
    verifies, and it does not sign itself, so the index never names it as itself. With ``skid``,
    its key identifier is set, as a real certificate's is, so OpenSSL does not try it as the issuer
    of a leaf whose authority key identifier names another key."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(dn)
        .issuer_name(by[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    )
    if skid:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False
        )
    return builder.sign(by[1], hashes.SHA256())


@pytest.mark.parametrize("other", ["ca", "pinned"])
def test_a_pinned_certificate_listed_twice_beside_one_with_its_subject_builds(other: str) -> None:
    """A self-signed pinned certificate listed twice, after another certificate with its subject
    and a CA between them. OpenSSL 3.5.7 keeps both copies of the pinned one, so a check counting
    what OpenSSL holds against the distinct certificates the index read refused a file the shipped
    code built (BACKLOG #4948). The two certificates still share a subject under different keys,
    and each could be named, so the name stays ambiguous."""
    pinned = _pinned("Acme Svc")
    twin = (
        _pinned("Acme Svc") if other == "pinned" else _ca(_dn((NameOID.COMMON_NAME, "Acme Svc")))[0]
    )
    mid = _ca(_dn((NameOID.COMMON_NAME, "Mid CA")))[0]
    cadata = (_pem(twin) + _pem(mid) + _pem(pinned) + _pem(pinned)).decode("ascii")
    # The premise, measured on OpenSSL 3.5.7: it keeps the second copy (4). Another build may drop
    # it (3); the file must build either way, so only an unexpected count fails here.
    assert _openssl_loads(cadata) in (3, 4)
    index = IssuerIndex(cadata)
    assert index.unmatched_keys(["CN=Mid CA"]) == {}
    assert index.issuer_of(_der(pinned)) == ""  # the two stay ambiguous
    reason = index.unmatched_keys(["CN=Acme Svc"])["CN=Acme Svc"]
    assert reason.startswith("names 2 loaded certificates"), reason
    assert "pinned" in reason, reason  # a pinned certificate is not called a CA
    # Control: listed once, OpenSSL holds one copy and the file builds as before.
    once = (_pem(twin) + _pem(mid) + _pem(pinned)).decode("ascii")
    assert _openssl_loads(once) == 3
    assert IssuerIndex(once).issuer_of(_der(pinned)) == ""


def test_the_count_of_certificates_that_are_no_ca_is_still_bounded() -> None:
    """Driven at the check itself: OpenSSL may hold a certificate listed twice once or twice, so
    the count it holds may lie between the distinct certificates the index read and every copy it
    read. Outside that, the start still refuses (BACKLOG #4948)."""
    root = _der(_ca(_dn((NameOID.COMMON_NAME, "Root CA")))[0])
    pinned = _der(_pinned("Pinned"))
    cadata = ssl.DER_cert_to_PEM_cert(root) + ssl.DER_cert_to_PEM_cert(pinned)
    assert _openssl_loads(cadata) == 2  # the premise: one copy of each
    # The index read the pinned certificate twice, and OpenSSL holds it once: within the bound.
    assert pki._refuse_unless_openssl_loads(cadata, Counter([root, pinned, pinned]), label="x") == {
        root
    }
    # OpenSSL holds as many as every copy the index read: the bound's upper edge, accepted.
    other = _der(_pinned("Other"))
    both = cadata + ssl.DER_cert_to_PEM_cert(other)
    assert _openssl_loads(both) == 3
    assert pki._refuse_unless_openssl_loads(both, Counter([root, pinned, pinned]), label="x") == {
        root
    }
    # One more than every copy read is above it.
    with pytest.raises(ValueError, match=r"loads 2 certificate\(s\) that are not CAs.*plain PEM"):
        pki._refuse_unless_openssl_loads(both, Counter([root, pinned]), label="x")
    # The index read one certificate that is no CA, and OpenSSL holds none: below the bound.
    alone = ssl.DER_cert_to_PEM_cert(root)
    with pytest.raises(ValueError, match=r"loads 0 certificate\(s\) that are not CAs.*empty or"):
        pki._refuse_unless_openssl_loads(alone, Counter([root, pinned, pinned]), label="x")
    # OpenSSL holds one certificate that is no CA, and the index read none: above the bound.
    with pytest.raises(ValueError, match=r"loads 1 certificate\(s\) that are not CAs.*plain PEM"):
        pki._refuse_unless_openssl_loads(cadata, Counter([root]), label="x")


def test_an_issuer_key_naming_only_a_certificate_that_is_no_ca_is_warned_about(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A key naming only a loaded certificate OpenSSL reads as no CA, which does not sign itself,
    can never match: such a certificate issues nothing, and is named as itself only when it signs
    itself, which this one does not. The key would
    deny every certificate under it with nothing in the log, so it is warned about at start
    (BACKLOG #4948). A self-signed pinned certificate names itself, so its key is not."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    service = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Partner Svc")), root)
    pinned = _pinned("Pinned")
    subjects = {k: [SUBJECT] for k in ("CN=Root CA", "CN=Partner Svc", "CN=Pinned")}
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        source = _source(tmp_path, [root[0], service, pinned], subjects)
    warned = [r.getMessage() for r in caplog.records]
    assert any("'CN=Partner Svc'" in m and "names no CA" in m for m in warned), warned
    assert not any("'CN=Root CA'" in m or "'CN=Pinned'" in m for m in warned), warned  # controls
    assert source._issuer_index is not None
    reason = source._issuer_index.unmatched_keys(["CN=Partner Svc"])["CN=Partner Svc"]
    assert reason.startswith("names no CA certificate"), reason
    # It is named under the CA that issued it, never under its own subject.
    assert source._issuer_index.issuer_of(_der(service)) == "CN=Root CA"


async def test_a_certificate_that_is_no_ca_sharing_a_cas_subject_is_no_twin(
    tmp_path: Path,
) -> None:
    """A loaded certificate OpenSSL reads as no CA, and that does not sign itself, shares a CA's
    subject under another key. It can never be named, so it is not a twin of that CA, and a leaf
    the CA signed is admitted under its subject. In the shipped code its key counted toward the
    same-DN ambiguity, so every certificate under the CA would have been refused on a first
    deployment (BACKLOG #4948): this LOOSENS a deny. A self-signed pinned certificate in its place
    could be named, as itself, so there the name stays ambiguous and the leaf names no issuer, as
    before."""
    acme = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), root)
    source = await _started(_source(tmp_path, [acme[0], namesake], {"CN=Acme CA": [SUBJECT]}))
    try:
        assert source._issuer_index is not None
        assert source._issuer_index.unmatched_keys(["CN=Acme CA"]) == {}
        assert await _admitted(source, _bundle(tmp_path, acme)) == 202
    finally:
        await source.stop()
    # Control: a self-signed pinned certificate with the CA's subject keeps the name ambiguous.
    leaf = _der(_new_ca(_dn((NameOID.COMMON_NAME, "leaf")), acme)[0])
    index = IssuerIndex((_pem(acme[0]) + _pem(_pinned("Acme CA"))).decode("ascii"))
    assert index.issuer_of(leaf) == ""
    assert "pinned" in index.unmatched_keys(["CN=Acme CA"])["CN=Acme CA"]
    # Control: with the CA alone, the same leaf is named.
    assert IssuerIndex(_pem(acme[0]).decode("ascii")).issuer_of(leaf) == "CN=Acme CA"


async def _handshake_refused(source: HttpSource, bundle: Path) -> bool:
    """Whether the listener ends the TLS handshake of a client presenting ``bundle``.

    Under TLS 1.3 the client finishes first, so the refusal reaches it as an alert, a reset or an
    empty read. A client the listener admitted sends nothing here, so the listener waits for a
    request and the read times out: that is ``False``. This listener closes with no bytes only
    when it refuses at the handshake or at accept, and a refusal at accept answers a status."""
    try:
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", source.sockport, ssl=_client_context(bundle)
        )
    except (ssl.SSLError, ConnectionError):
        return True
    try:
        data = await asyncio.wait_for(reader.read(-1), 3.0)
    except (ssl.SSLError, ConnectionError):
        return True
    except TimeoutError:
        return False
    finally:
        writer.close()
    assert not data.startswith(b"HTTP/1.1 "), data[:40]  # a status means it got past the handshake
    return data == b""


@pytest.mark.parametrize("cn", ["Acme CA", "ACME CA", " Acme  CA"], ids=["same", "case", "spacing"])
async def test_a_namesake_that_is_no_ca_is_warned_about_at_start(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, cn: str
) -> None:
    """A loaded certificate that is no CA, with no key identifier, with the subject of a loaded CA.
    OpenSSL may take it as the issuer of a client certificate that CA issued, and then refuses the
    chain, so every client of that CA fails the handshake. The index does not count it as a twin
    (fix 3 of BACKLOG #4948), so the key maps nothing wrong and no reason for it is given; the
    start warns instead, naming both certificates. In the shipped code such a namesake counted as
    a twin, so the start warned about the key, for the wrong reason; once fix 3 stopped counting
    it, the start was silent. The warning changes no outcome.

    Which of two certificates with one name OpenSSL tries first follows its sort of equal names,
    which differs by platform: on Windows, OpenSSL 3.5.7, it took the one listed later. So both
    orders are started, each must warn, and at least one must refuse the CA's client. A namesake
    differing from the CA only in ASCII case or white space is one name to OpenSSL, so it is
    measured too."""
    acme = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, cn)), root, skid=False)
    named = namesake.subject.rfc4514_string()
    subjects = {"CN=Acme CA": [SUBJECT]}
    refused = []
    for order, (ca_at, other_at) in (("ca-first", (1, 2)), ("namesake-first", (2, 1))):
        trusted = [acme[0], namesake] if ca_at == 1 else [namesake, acme[0]]
        (tmp_path / order).mkdir()
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
            source = await _started(_source(tmp_path / order, trusted, subjects))
        try:
            warned = [r.getMessage() for r in caplog.records]
            assert any(
                f"tls_ca_file certificate block {other_at} ({named}) is not a CA" in m
                and f"the CA certificate in block {ca_at}" in m
                and "refuse every client certificate of that CA" in m
                for m in warned
            ), (order, warned)
            assert source._issuer_index is not None
            assert source._issuer_index.unmatched_keys(subjects) == {}  # still no twin
            refused.append(await _handshake_refused(source, _bundle(tmp_path, acme)))
        finally:
            await source.stop()
    # The failure warned of, measured: in at least one order the CA's client fails the handshake.
    assert any(refused), refused
    # Control: with the CA alone, nothing is warned and the same CA's client is admitted.
    caplog.clear()
    (tmp_path / "alone").mkdir()
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        source = await _started(_source(tmp_path / "alone", [acme[0]], subjects))
    try:
        assert not caplog.records, [r.getMessage() for r in caplog.records]
        assert await _admitted(source, _bundle(tmp_path, acme)) == 202
    finally:
        await source.stop()


def _tlv_content(element: bytes) -> bytes:
    """The content of the DER element ``element`` opens with."""
    if element[1] < 0x80:
        return element[2 : 2 + element[1]]
    width = element[1] & 0x7F
    size = int.from_bytes(element[2 : 2 + width], "big")
    return element[2 + width : 2 + width + size]


def _as_version_1(v3: x509.Certificate, key: ec.EllipticCurvePrivateKey) -> x509.Certificate:
    """``v3`` as version 1, signed again by ``key``, with any extensions it was built with kept.
    ``cryptography`` builds only version 3, so the version field is cut from the to-be-signed
    bytes."""
    fields = _tlv_content(v3.tbs_certificate_bytes)
    assert fields.startswith(_VERSION_3)
    cert = x509.load_der_x509_certificate(_signed_der(fields.removeprefix(_VERSION_3), key))
    assert cert.version == x509.Version.v1  # the premise
    assert len(cert.extensions) == len(v3.extensions)
    return cert


def _signed_der(tbs_fields: bytes, key: ec.EllipticCurvePrivateKey) -> bytes:
    """A certificate's DER: ``tbs_fields`` as its to-be-signed fields, signed by ``key``."""
    tbs = seq(tbs_fields)
    signature = key.sign(tbs, ec.ECDSA(hashes.SHA256()))
    return seq(tbs, seq(oid("1.2.840.10045.4.3.2")), tlv(0x03, b"\x00" + signature))


def _v1_bundle(tmp_path: Path, signer: _CaPair) -> Path:
    """:func:`_bundle`'s client certificate as version 1 (:func:`_as_version_1`), so with no
    extensions and no authority key identifier, with its key."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    v3 = (
        x509.CertificateBuilder()
        .subject_name(_dn((NameOID.COMMON_NAME, "partner.example")))
        .issuer_name(signer[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(signer[1], hashes.SHA256())
    )
    leaf = _as_version_1(v3, signer[1])
    assert len(leaf.extensions) == 0  # the premise: no authority key identifier
    der = _der(leaf)
    leaf.verify_directly_issued_by(signer[0])
    bundle = tmp_path / f"client-v1-{len(list(tmp_path.iterdir()))}.pem"
    bundle.write_bytes(
        ssl.DER_cert_to_PEM_cert(der).encode("ascii")
        + key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    return bundle


async def test_a_namesake_with_another_key_identifier_is_warned_to_refuse_a_version_1_client(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    """A loaded certificate that is no CA, with a key identifier that differs from the CA's, with
    the CA's subject. OpenSSL rules it out for a client certificate whose authority key identifier
    names the CA's key, but not for one with none. A version-1 client certificate has none, and the
    listener's strict verification accepts it (the control below). Before this fix, on this
    branch, the warning said such a namesake could be taken only for a certificate strict
    verification refuses anyway, which would have told an operator a harmful namesake was
    harmless (BACKLOG #4948).

    Measured on Windows, OpenSSL 3.5.7: listed after the CA, the namesake refused the version-1
    client at the handshake, and listed first it did not; the version-3 client was admitted in both
    orders. The order OpenSSL tries equal names in differs by platform, as the case above records,
    so both orders are started, each must warn, and at least one must refuse the version-1 client.
    The warning changes no outcome."""
    acme = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), root)
    subjects = {"CN=Acme CA": [SUBJECT]}
    v1_client, v3_client = _v1_bundle(tmp_path, acme), _bundle(tmp_path, acme)
    refused = []
    for order, (ca_at, other_at) in (("ca-first", (1, 2)), ("namesake-first", (2, 1))):
        trusted = [acme[0], namesake] if ca_at == 1 else [namesake, acme[0]]
        (tmp_path / order).mkdir()
        caplog.clear()
        with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
            source = await _started(_source(tmp_path / order, trusted, subjects))
        try:
            warned = [r.getMessage() for r in caplog.records]
            assert any(
                f"tls_ca_file certificate block {other_at} (CN=Acme CA) is not a CA" in m
                and f"the CA certificate in block {ca_at}" in m
                and "that CA issued with no authority key identifier" in m
                and "Strict verification accepts such a certificate when it is version 1" in m
                and "every client certificate" not in m
                for m in warned
            ), (order, warned)
            refused.append(await _handshake_refused(source, v1_client))
            # A client certificate naming the CA's key is not refused this way, in either order.
            assert await _admitted(source, v3_client) == 202
        finally:
            await source.stop()
    assert any(refused), refused
    # Control: with the CA alone, strict verification admits the version-1 client.
    (tmp_path / "alone").mkdir()
    source = await _started(_source(tmp_path / "alone", [acme[0]], subjects))
    try:
        assert await _admitted(source, v1_client) == 202
    finally:
        await source.stop()


@pytest.mark.parametrize("namesake_skid", [True, False], ids=["namesake-key-id", "bare-namesake"])
async def test_a_namesake_of_a_ca_with_no_key_identifier_names_the_ca_as_the_cause(
    tmp_path: Path, namesake_skid: bool
) -> None:
    """A CA with no key identifiers, beside a namesake that is no CA. The listener verifies
    strictly, and strict verification refuses every client of such a CA with the CA ALONE,
    measured here for a version-3 client naming its key and a version-1 client. So the warning
    says every client whose chain runs through the CA is refused, and names the CA as the cause
    rather than the namesake. Before this fix, on this branch, a namesake with a key identifier
    took the differing-key-identifier warning, which named only clients with no authority key
    identifier and blamed the namesake (BACKLOG #4948)."""
    acme = _new_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), key_usage=True, key_ids=False)
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), root, skid=namesake_skid)
    with pytest.raises(x509.ExtensionNotFound):  # the premise: the CA has no key identifier
        acme[0].extensions.get_extension_for_class(x509.SubjectKeyIdentifier)
    cadata = (_pem(acme[0]) + _pem(namesake)).decode("ascii")
    (warning,) = IssuerIndex(cadata).namesake_warnings()
    assert "measured to apply it, refuses every client certificate whose chain runs" in warning
    assert "through block 1, whether or not block 2 is loaded" in warning, warning
    assert "refuses block 1 as a CA for at least this reason: it has no subject key" in warning
    assert _CA_REMEDY in warning, warning
    # The cause, measured: with the CA alone, the strict listener refuses both kinds of client.
    assert await _ca_alone_refuses(tmp_path, acme) == (True, True)


#: The remedy the CA-cause namesake warning gives, for a CA in block 1, up to the namesakes.
_CA_REMEDY = (
    "Re-issue block 1, with the same subject and key, as a version-3 CA with at least critical "
    "basic constraints CA:TRUE, key usage keyCertSign, and cRLSign too where the hop checks a CRL "
    "that block 1 signs, a subject key identifier equal to the key identifier its client "
    "certificates' authority key identifiers carry, and, unless it is self-signed, an authority "
    "key identifier carrying its issuer's subject key identifier, neither key identifier "
    "critical; a client certificate whose authority key identifier names the issuer and serial "
    "number of block 1, or another key identifier, must then be re-issued too. Or remove block 1 "
    "if it is not needed. While block 1 stays loaded, also remove"
)

#: Each reason the CA-cause warning can name, by the defect that produces it.
_CA_FAULTS = {
    "version-1": "it is version 1, so it has no extensions: no basic constraints, key usage or "
    "subject key identifier",
    "version-1-with-extensions": "it is version 1 but carries extensions, which strict "
    "verification refuses in a certificate before version 3",
    "no-basic-constraints": "it has no basic constraints",
    "basic-constraints-not-critical": "its basic constraints are not critical",
    "no-key-usage": "it has no key usage",
    "no-key-cert-sign": "its key usage does not include keyCertSign",
    "no-subject-key-identifier": "it has no subject key identifier",
    "subject-key-identifier-critical": "its subject key identifier is critical",
    "no-authority-key-identifier": "it is not self-signed and has no authority key identifier, "
    "which strict verification requires once its issuer is loaded",
    "authority-key-identifier-without-key-id": "it is not self-signed and its authority key "
    "identifier carries no key identifier, which strict verification requires once its issuer is "
    "loaded",
    "authority-key-identifier-critical": "its authority key identifier is critical",
}


def _strict_ca(
    *defects: str,
    akid: bool = True,
    by: _CaPair | None = None,
    subject: x509.Name | None = None,
    issuer_name: x509.Name | None = None,
) -> _CaPair:
    """A CA ``Acme CA``, or ``subject``, self-signed or signed by ``by``, with each of ``defects``
    named in :data:`_CA_FAULTS`, or with none: critical ``CA:TRUE`` basic constraints, a key usage
    with ``keyCertSign``, a subject key identifier and, with ``akid``, an authority key
    identifier, neither critical. ``issuer_name`` overrides the issuer field the signer writes."""
    key = ec.generate_private_key(ec.SECP256R1())
    name = _dn((NameOID.COMMON_NAME, "Acme CA")) if subject is None else subject
    issuer, signer = (name, key) if by is None else (by[0].subject, by[1])
    if issuer_name is not None:
        issuer = issuer_name
    now = datetime.datetime.now(datetime.UTC)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(issuer)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
    )
    if "version-1" in defects:
        v1 = _as_version_1(builder.sign(signer, hashes.SHA256()), signer)
        assert len(v1.extensions) == 0  # the premise
        return v1, key
    if "no-basic-constraints" not in defects:
        builder = builder.add_extension(
            x509.BasicConstraints(ca=True, path_length=None),
            critical="basic-constraints-not-critical" not in defects,
        )
    if "no-key-usage" not in defects:
        builder = builder.add_extension(
            x509.KeyUsage(
                digital_signature=True,
                content_commitment=False,
                key_encipherment=False,
                data_encipherment=False,
                key_agreement=False,
                key_cert_sign="no-key-cert-sign" not in defects,
                crl_sign=True,
                encipher_only=False,
                decipher_only=False,
            ),
            critical=True,
        )
    if "no-subject-key-identifier" not in defects:
        builder = builder.add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
            critical="subject-key-identifier-critical" in defects,
        )
    if "authority-key-identifier-without-key-id" in defects:
        assert by is not None
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier(None, [x509.DirectoryName(issuer)], by[0].serial_number),
            critical=False,
        )
    elif akid and "no-authority-key-identifier" not in defects:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(signer.public_key()),
            critical="authority-key-identifier-critical" in defects,
        )
    cert = builder.sign(signer, hashes.SHA256())
    if "version-1-with-extensions" in defects:
        cert = _as_version_1(cert, signer)
    return cert, key


async def _ca_alone_refuses(
    tmp_path: Path, ca: _CaPair, *, issuer: x509.Certificate | None = None
) -> tuple[bool, bool]:
    """Whether a strict listener trusting ``ca`` alone, or beside its ``issuer``, refuses at the
    handshake a version-3 client certificate naming its key and a version-1 client certificate,
    each ``ca`` signed."""
    (tmp_path / "alone").mkdir()
    trusted = [ca[0]] if issuer is None else [ca[0], issuer]
    source = await _started(_source(tmp_path / "alone", trusted, {"CN=Acme CA": [SUBJECT]}))
    try:
        return (
            await _handshake_refused(source, _bundle(tmp_path, ca)),
            await _handshake_refused(source, _v1_bundle(tmp_path, ca)),
        )
    finally:
        await source.stop()


def _ca_namesake_warning(ca: _CaPair, root: _CaPair) -> str:
    """The one namesake warning for ``ca`` in block 1, beside a namesake in block 2 that is no CA
    and has a key identifier of its own, and ``root`` in block 3."""
    namesake = _issued_no_ca(ca[0].subject, root)
    cadata = (_pem(ca[0]) + _pem(namesake) + _pem(root[0])).decode("ascii")
    (warning,) = IssuerIndex(cadata).namesake_warnings()
    return warning


@pytest.mark.parametrize(
    "defect",
    # OpenSSL reads a key usage without keyCertSign as no CA: the case after the controls.
    [defect for defect in _CA_FAULTS if defect != "no-key-cert-sign"],
)
async def test_a_namesake_of_a_ca_strict_verification_refuses_names_the_ca_and_its_faults(
    tmp_path: Path, defect: str
) -> None:
    """A CA that OpenSSL reads as a CA but strict verification refuses as one, beside a namesake
    with a key identifier of its own. Measured on Windows, OpenSSL 3.5.7, with the CA alone, or
    beside its issuer for the CA with no authority key identifier, which is not self-signed: the
    strict listener refuses a version-3 and a version-1 client of each. So the warning names the
    CA, and the fault found in it, as the cause, says the list is not complete, and says to
    re-issue the CA or remove it if it is not needed. Before this fix, on this branch, a CA with a
    key identifier took the warning that names only clients with no authority key identifier and
    says to remove the namesake, and a version-1 CA was said to lack only a key identifier (BACKLOG
    #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    issued = defect in ("no-authority-key-identifier", "authority-key-identifier-without-key-id")
    acme = _strict_ca(defect, by=root if issued else None)
    assert pki._openssl_reads_as_ca(_der(acme[0])) is True  # the premise: it is a CA to OpenSSL
    warning = _ca_namesake_warning(acme, root)
    assert warning.startswith("certificate block 2 (CN=Acme CA) is not a CA but has the subject")
    assert "every client certificate whose chain runs through block 1, whether or not block 2" in (
        warning
    )
    assert f"refuses block 1 as a CA for at least this reason: {_CA_FAULTS[defect]}." in warning
    assert all(fault not in warning for name, fault in _CA_FAULTS.items() if name != defect)
    assert _CA_REMEDY + " block 2 or re-issue it under another subject" in warning, warning
    assert "that CA issued with no authority key identifier" not in warning, warning
    # The cause, measured: the strict listener refuses both kinds of client.
    refused = await _ca_alone_refuses(tmp_path, acme, issuer=root[0] if issued else None)
    assert refused == (True, True)


@pytest.mark.parametrize(
    ("defects", "named"),
    [
        pytest.param(
            ("basic-constraints-not-critical", "no-key-usage"),
            "these reasons: its basic constraints are not critical; it has no key usage.",
            id="two-faults",
        ),
        # OpenSSL refuses a CA with no basic constraints as invalid before its other checks.
        pytest.param(
            ("no-basic-constraints", "no-subject-key-identifier"),
            "this reason: it has no basic constraints.",
            id="no-basic-constraints-hides-the-rest",
        ),
    ],
)
async def test_a_ca_cause_warning_names_each_fault_strict_verification_checks(
    tmp_path: Path, defects: tuple[str, ...], named: str
) -> None:
    """A CA with two faults is named for each one strict verification checks. With no basic
    constraints, OpenSSL refuses it as an invalid CA and does not check its key usage or key
    identifiers, so only that fault is named (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    acme = _strict_ca(*defects)
    warning = _ca_namesake_warning(acme, root)
    assert f"refuses block 1 as a CA for at least {named}" in warning, warning
    assert await _ca_alone_refuses(tmp_path, acme) == (True, True)


def test_a_ca_cause_warning_is_given_once_per_ca_naming_every_namesake() -> None:
    """Two namesakes of one CA strict verification refuses give one warning, naming both in block
    order, rather than one per namesake that repeats the cause (BACKLOG #4948)."""
    acme = _strict_ca("no-key-usage")
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    first = _issued_no_ca(_dn((NameOID.COMMON_NAME, "ACME CA")), root, skid=False)
    second = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), root)
    third = _issued_no_ca(_dn((NameOID.COMMON_NAME, "ACME CA")), root)
    cadata = (_pem(first) + _pem(acme[0]) + _pem(second) + _pem(third)).decode("ascii")
    (warning,) = IssuerIndex(cadata).namesake_warnings()
    assert warning.startswith(
        "certificate blocks 1 (CN=ACME CA), 3 (CN=Acme CA) and 4 (CN=ACME CA) are not CAs but have "
        "the subject of the CA certificate in block 2"
    ), warning
    assert "whether or not blocks 1, 3 and 4 are loaded" in warning, warning
    assert "also remove blocks 1, 3 and 4 or re-issue them under another subject" in warning


def test_several_cas_with_one_name_are_warned_about_in_block_order() -> None:
    """Two CAs strict verification refuses, whose names differ only in ASCII case, beside a
    namesake. One warning is given per CA, in block order. Before this fix, on this branch, they
    came in the order the exact names were first read, so the CA in block 3 was warned about
    before the one in block 2 (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, "ACME CA")), root)
    acme = _strict_ca("no-key-usage")
    upper = _new_ca(_dn((NameOID.COMMON_NAME, "ACME CA")), key_usage=True, key_ids=False)
    cadata = (_pem(namesake) + _pem(acme[0]) + _pem(upper[0])).decode("ascii")
    warnings = IssuerIndex(cadata).namesake_warnings()
    assert len(warnings) == 2, warnings
    assert "the subject of the CA certificate in block 2." in warnings[0], warnings
    assert "the subject of the CA certificate in block 3." in warnings[1], warnings


@pytest.mark.parametrize("akid", [True, False], ids=["conforming", "no-authority-key-id"])
async def test_a_namesake_of_a_ca_strict_verification_admits_still_names_the_namesake(
    tmp_path: Path, akid: bool
) -> None:
    """Controls: a self-signed CA strict verification admits, with or without an authority key
    identifier, which a self-signed CA may omit, beside a namesake with a different key
    identifier, still gets the warning that names clients with no authority key identifier and
    the namesake as the cause, not the CA-cause wording. Measured with the CA alone, the strict
    listener admits a version-3 and a version-1 client of it (BACKLOG #4948)."""
    acme = _strict_ca(akid=akid)
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    warning = _ca_namesake_warning(acme, root)
    assert "that CA issued with no authority key identifier" in warning, warning
    assert "Remove block 2, or re-issue it under another subject" in warning, warning
    assert "as a CA for at least" not in warning, warning
    assert not any(fault in warning for fault in _CA_FAULTS.values()), warning
    assert await _ca_alone_refuses(tmp_path, acme) == (False, False)


async def test_a_ca_with_an_issuer_and_an_authority_key_identifier_is_admitted_beside_it(
    tmp_path: Path,
) -> None:
    """Control for the two authority key identifier faults: a CA its root issued, with an
    authority key identifier carrying the root's key identifier, loaded beside the root. No fault
    is named, and a strict listener admits a version-3 and a version-1 client of it. So the
    refusals measured for a CA with no authority key identifier, or one carrying no key
    identifier, come from that fault and not from the CA having an issuer (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    acme = _strict_ca(by=root)
    assert acme[0].issuer == root[0].subject  # the premise: it is not self-signed
    warning = _ca_namesake_warning(acme, root)
    assert "that CA issued with no authority key identifier" in warning, warning
    assert "as a CA for at least" not in warning, warning
    source = await _started(_source(tmp_path, [acme[0], root[0]], {"CN=Acme CA": [SUBJECT]}))
    try:
        assert await _admitted(source, _bundle(tmp_path, acme)) == 202
        assert await _admitted(source, _v1_bundle(tmp_path, acme)) == 202
    finally:
        await source.stop()


async def test_a_root_whose_names_differ_only_in_string_type_is_self_signed(
    tmp_path: Path,
) -> None:
    """A self-signed root with no authority key identifier, its issuer's common name a
    PrintableString and its subject's a UTF8String. OpenSSL compares the two as one name, so it is
    self-signed there and may omit the identifier: measured on OpenSSL 3.5.7, a strict listener
    trusting it alone admits its clients. So no fault is named for it (BACKLOG #4948)."""
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    subject = _dn((NameOID.COMMON_NAME, "Acme CA"))
    printable = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, "Acme CA", _ASN1Type.PrintableString)]
    )
    root = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(printable)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(True, False, False, False, False, True, True, False, False),
            critical=True,
        )
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    assert root.issuer.public_bytes() != root.subject.public_bytes()  # the premise
    (anchor,) = IssuerIndex(_pem(root).decode("ascii"))._by_subject_name[subject]
    assert anchor.ca and pki._strict_ca_faults(anchor) == []
    assert await _ca_alone_refuses(tmp_path, (root, key)) == (False, False)


async def test_a_root_whose_issuer_openssl_reads_as_latin_1_is_self_signed(tmp_path: Path) -> None:
    """A root with no authority key identifier, its issuer's common name a T61String holding the
    UTF-8 bytes of a name with one letter outside ASCII, and its subject's the UTF8String those
    bytes spell when read one byte to a character. OpenSSL reads a T61String that way, as
    Latin-1, so the two are one name to it and the root is self-signed: measured on OpenSSL 3.5.7,
    a strict listener trusting it alone admits its clients. ``cryptography`` decodes the bytes as
    UTF-8, so read by :func:`pki._namesake_key` alone the root had an issuer, and was named for
    an authority key identifier it may omit (BACKLOG #4948). A control root whose issuer is
    another name is refused by the same listener, as no issuer of it is loaded, so admission
    tells the two readings apart."""
    spelled = b"Acm\xc3\xa9 CA"
    subject = _dn((NameOID.COMMON_NAME, spelled.decode("latin-1")))
    t61 = x509.Name(
        [x509.NameAttribute(NameOID.COMMON_NAME, spelled.decode("utf-8"), _ASN1Type.T61String)]
    )
    root, key = _strict_ca(akid=False, subject=subject, issuer_name=t61)
    assert b"\x14\x08Acm\xc3\xa9 CA" in root.tbs_certificate_bytes  # the premise
    assert pki._namesake_key(root.issuer) != pki._namesake_key(root.subject)
    (anchor,) = IssuerIndex(_pem(root).decode("ascii"))._by_subject_name[subject]
    assert anchor.ca and pki._strict_ca_faults(anchor) == []
    issuer_key = root.subject.rfc4514_string()
    source = await _started(_source(tmp_path, [root], {issuer_key: [SUBJECT]}))
    try:
        assert await _admitted(source, _bundle(tmp_path, (root, key))) == 202
        assert await _admitted(source, _v1_bundle(tmp_path, (root, key))) == 202
    finally:
        await source.stop()
    # Control: the same shape with an issuer OpenSSL reads as another name is refused.
    other = _strict_ca(akid=False, subject=subject, issuer_name=_dn((NameOID.COMMON_NAME, "Z")))
    (tmp_path / "control").mkdir()
    source = await _started(_source(tmp_path / "control", [other[0]], {issuer_key: [SUBJECT]}))
    try:
        assert await _handshake_refused(source, _bundle(tmp_path, other))
    finally:
        await source.stop()


async def test_a_key_usage_without_key_cert_sign_is_no_ca_to_openssl(tmp_path: Path) -> None:
    """A CA whose key usage lacks ``keyCertSign`` is refused by a strict listener with it alone
    (measured on OpenSSL 3.5.7), but OpenSSL reads it as no CA, so the index holds it as a
    certificate that is no CA and never gives it the CA-cause warning. The fault reader still names
    it, for a build whose read differs (BACKLOG #4948)."""
    acme = _strict_ca("no-key-cert-sign")
    assert pki._openssl_reads_as_ca(_der(acme[0])) is False
    index = IssuerIndex(_pem(acme[0]).decode("ascii"))
    (anchor,) = index._by_subject_name[acme[0].subject]
    assert not anchor.ca
    assert pki._strict_ca_faults(anchor) == [_CA_FAULTS["no-key-cert-sign"]]
    assert pki._strict_ca_faults(replace(anchor, cert=_strict_ca()[0])) == []
    assert await _ca_alone_refuses(tmp_path, acme) == (True, True)


def test_a_namesake_of_a_ca_whose_key_identifier_cannot_be_read_says_so(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A CA whose extensions ``cryptography`` cannot read may or may not have a key identifier
    OpenSSL reads, so the check cannot tell whether the CA itself is the cause, or, for a namesake
    with a key identifier, which clients rule it out. The warning then says every client may be
    refused, and what it cannot tell, with or without a key identifier on the namesake (BACKLOG
    #4948). The unreadable read is stood in for, as a CA OpenSSL loads whose extensions
    ``cryptography`` refuses is not built here."""
    acme = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    real = pki._key_identifier
    monkeypatch.setattr(
        pki, "_key_identifier", lambda anchor: (None, False) if anchor.ca else real(anchor)
    )
    for skid in (True, False):
        namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), acme, skid=skid)
        cadata = (_pem(acme[0]) + _pem(namesake)).decode("ascii")
        (warning,) = IssuerIndex(cadata).namesake_warnings()
        assert "refuse every client certificate of that CA" in warning, warning
        assert "extensions of block 1 cannot be read here" in warning, warning
        assert "whether block 1 itself is the cause" in warning, warning
        assert "Check block 1 too. Remove block 2, or re-issue it" in warning, warning
        assert ("rules block 2 out" in warning) is skid, warning
        assert "has no subject key identifier" not in warning, warning


@pytest.mark.parametrize(
    ("cn", "skid", "refused"),
    [
        pytest.param("ACME CA", False, "every client certificate of that CA", id="case"),
        pytest.param(" Acme  CA", False, "every client certificate of that CA", id="spacing"),
        pytest.param(
            "Acme CA", True, "that CA issued with no authority key identifier", id="key-id"
        ),
    ],
)
def test_a_namesake_warning_matches_names_as_openssl_does_and_says_whom_it_refuses(
    cn: str, skid: bool, refused: str
) -> None:
    """Names are grouped at least as loosely as OpenSSL matches an issuer by name, ASCII case and
    white space folded. A namesake with a key identifier of its own may still be taken as the
    issuer of a client certificate with no authority key identifier, so the warning names those
    (BACKLOG #4948)."""
    acme = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, cn)), acme, skid=skid)
    (warning,) = IssuerIndex((_pem(acme[0]) + _pem(namesake)).decode("ascii")).namesake_warnings()
    assert "block 2" in warning and "block 1" in warning and refused in warning, warning
    # Control: another name is no namesake.
    other = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA 2")), acme, skid=skid)
    assert IssuerIndex((_pem(acme[0]) + _pem(other)).decode("ascii")).namesake_warnings() == []


def test_a_namesake_whose_extensions_cannot_be_read_is_warned_about_without_raising() -> None:
    """A namesake that is no CA whose extensions ``cryptography`` refuses to read, here a duplicate
    key identifier, which OpenSSL loads. The warning reads the key identifier, so it must not raise
    out of the start, which it would refuse; it warns as for a namesake with none (BACKLOG
    #4948)."""
    acme = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.UTC)
    # The SKID's OID with its last arc set to 99, so it encodes to as many bytes.
    arcs = ExtensionOID.SUBJECT_KEY_IDENTIFIER.dotted_string.rsplit(".", 1)[0]
    placeholder = x509.ObjectIdentifier(f"{arcs}.99")
    cert = (
        x509.CertificateBuilder()
        .subject_name(acme[0].subject)
        .issuer_name(acme[0].subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .add_extension(x509.UnrecognizedExtension(placeholder, b"\x04\x01\x00"), critical=False)
        .sign(acme[1], hashes.SHA256())
    )
    der = _der(cert)
    assert der.count(b"\x06\x03\x55\x1d\x63") == 1
    der = der.replace(b"\x06\x03\x55\x1d\x63", b"\x06\x03\x55\x1d\x0e")
    with pytest.raises(x509.DuplicateExtension):  # the premise: cryptography refuses to read it
        _ = x509.load_der_x509_certificate(der).extensions
    cadata = (_pem(acme[0]) + _wrapped(der)).decode("ascii")
    assert _openssl_loads(cadata) == 2  # the premise: OpenSSL loads it
    (warning,) = IssuerIndex(cadata).namesake_warnings()
    assert "block 2" in warning and "refuse every client certificate of that CA" in warning


@pytest.mark.parametrize(
    ("defects", "fault"),
    [
        pytest.param((), None, id="conforming"),
        pytest.param(("no-key-usage",), "no-key-usage", id="fault-read-without-the-issuer"),
        pytest.param(("no-authority-key-identifier",), None, id="fault-needing-the-issuer"),
    ],
)
def test_a_ca_whose_issuer_name_cannot_be_read_is_warned_about_without_raising(
    tmp_path: Path, caplog: pytest.LogCaptureFixture, defects: tuple[str, ...], fault: str | None
) -> None:
    """A CA whose issuer name is a T61String holding bytes that are not UTF-8. OpenSSL loads it as
    a CA, and ``cryptography`` parses it but raises ``ValueError`` reading its issuer. The check
    for a CA strict verification refuses read that issuer outside any guard, to tell whether the
    CA is self-signed, so before this fix, on this branch, the namesake warning raised out of the
    listener's start and refused it. Only the authority key identifier faults need the issuer, so
    a fault read without it is still named, and with none the warning falls back to the namesake
    wording (BACKLOG #4948)."""
    root = _ca(_dn((NameOID.COMMON_NAME, "Root CA")))
    issuer = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Root ZZ", _ASN1Type.T61String)])
    v3 = _strict_ca(*defects, by=root, issuer_name=issuer)[0]
    fields = _tlv_content(v3.tbs_certificate_bytes)
    assert fields.count(b"\x14\x07Root ZZ") == 1
    der = _signed_der(fields.replace(b"\x14\x07Root ZZ", b"\x14\x07Root \xe9\xe9"), root[1])
    with pytest.raises(ValueError):  # the premise: cryptography cannot read the issuer
        _ = x509.load_der_x509_certificate(der).issuer
    assert pki._openssl_reads_as_ca(der) is True  # and OpenSSL loads it as a CA
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), root)
    cadata = _wrapped(der) + _pem(namesake)
    (warning,) = IssuerIndex(cadata.decode("ascii")).namesake_warnings()
    assert warning.startswith("certificate block 2 (CN=Acme CA) is not a CA"), warning
    if fault is None:
        assert "that CA issued with no authority key identifier" in warning, warning
        assert "as a CA for at least" not in warning, warning
    else:
        assert f"as a CA for at least this reason: {_CA_FAULTS[fault]}." in warning, warning
    # The start builds the listener and logs the warning.
    with caplog.at_level(logging.WARNING, logger="messagefoundry.transports.http_listener"):
        _source(tmp_path, [], {"CN=Acme CA": [SUBJECT]}, cadata=cadata)
    warned = [r.getMessage() for r in caplog.records]
    assert any("certificate block 2 (CN=Acme CA) is not a CA" in m for m in warned), warned


@pytest.mark.parametrize("surface", ["api", "mllp"])
def test_the_api_and_mllp_starts_warn_about_a_namesake_that_is_no_ca(
    caplog: pytest.LogCaptureFixture, surface: str
) -> None:
    """The API's and the MLLP listener's index builds log the same namesake warning as the HTTP
    listener's, naming their own file, and nothing for the CA alone (BACKLOG #4948)."""
    acme = _ca(_dn((NameOID.COMMON_NAME, "Acme CA")))
    namesake = _issued_no_ca(_dn((NameOID.COMMON_NAME, "Acme CA")), acme, skid=False)
    subjects = {"CN=Acme CA": [SUBJECT]}

    def build(cadata: str) -> list[str]:
        caplog.clear()
        with caplog.at_level(logging.WARNING):
            if surface == "api":
                _attach_issuer_index(ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER), cadata, subjects)
            else:
                _sender_issuer_lookup("IB_PARTNER", cadata, subjects)
        return [r.getMessage() for r in caplog.records]

    file = (
        "[api].tls_client_ca_file" if surface == "api" else "MLLP listener IB_PARTNER: tls_ca_file"
    )
    warned = build((_pem(acme[0]) + _pem(namesake)).decode("ascii"))
    assert any(
        m.startswith(f"{file} certificate block 2 (CN=Acme CA) is not a CA") and "block 1" in m
        for m in warned
    ), warned
    assert build(_pem(acme[0]).decode("ascii")) == []  # control


@pytest.mark.parametrize(
    ("nested", "label"),
    [
        pytest.param(False, "CERTIFICATE", id="certificate"),
        pytest.param(False, "X509 CERTIFICATE", id="legacy"),
        pytest.param(False, "FOO", id="other-label"),
        pytest.param(True, "FOO", id="other-label-over-a-certificate"),
    ],
)
def test_a_begin_with_no_end_refuses_the_build(nested: bool, label: str) -> None:
    """A BEGIN marker with no END line of its label after it makes OpenSSL refuse the file. The
    index must not silently stop reading there, as if the rest of the file held nothing, so the
    build refuses too. A whole certificate block after an unclosed other-label BEGIN is inside that
    block to OpenSSL, so the index must not name it either (BACKLOG #4948)."""
    good = _ca(_dn((NameOID.COMMON_NAME, "Good CA")))
    evil = _ca(_dn((NameOID.COMMON_NAME, "Evil CA")))
    if nested:  # an unclosed BEGIN, then a whole certificate block
        rest = f"-----BEGIN {label}-----\n".encode("ascii") + _pem(evil[0])
    else:  # a block cut off before its END line
        rest = _labelled(evil[0], label).removesuffix(f"-----END {label}-----\n".encode("ascii"))
    cadata = (_pem(good[0]) + rest).decode("ascii")
    with pytest.raises(ssl.SSLError):  # the premise: OpenSSL refuses the file
        _openssl_loads(cadata)
    with pytest.raises(ValueError, match="the TLS library refuses this file"):
        IssuerIndex(cadata)
    IssuerIndex(_pem(good[0]).decode("ascii"))  # control: the block before it alone builds


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
