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
import logging
import ssl
from pathlib import Path
from typing import Any

import pytest
from cryptography import x509
from cryptography.x509.oid import NameOID

from messagefoundry.config.models import ConnectorType, Source
from messagefoundry.config.wiring import Http, WiringError, env
from messagefoundry.transports.http_listener import HttpSource
from tests.test_api_tls import _CaPair, _client_bundle, _dn, _new_ca, _pem, _self_signed

SUBJECT = "CN:partner.example"


def _ca(dn: x509.Name, by: _CaPair | None = None) -> _CaPair:
    """``tests/test_api_tls.py``'s CA, with the ``keyUsage`` the listener's strict verify needs."""
    return _new_ca(dn, by, key_usage=True)


def _bundle(tmp_path: Path, signer: _CaPair, **kwargs: Any) -> Path:
    """``tests/test_api_tls.py``'s client bundle, for the partner subject this module lists."""
    return _client_bundle(tmp_path, signer, cn="partner.example", **kwargs)


def _source(
    tmp_path: Path, trusted: list[x509.Certificate], subjects: dict[str, list[str]] | None
) -> HttpSource:
    """A loopback mTLS listener trusting ``trusted``, built through the ``Http()`` factory.

    ``subjects`` set means ``mtls_subject``; ``None`` means a bare mTLS listener with no intake auth."""
    cert, key = _self_signed(tmp_path)
    ca_file = tmp_path / "client-ca.pem"
    ca_file.write_bytes(b"".join(_pem(c) for c in trusted))
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
    async def handler(raw: bytes) -> str | None:
        return "msg-1"  # stands in for the committed ingress message_id

    await source.start(handler)
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


async def test_the_listed_issuer_is_admitted_and_another_ca_with_the_same_subject_is_not(
    tmp_path: Path,
) -> None:
    """The defect itself: two loaded CAs, and the unlisted one issues a listed subject."""
    named = _ca(_dn((NameOID.ORGANIZATION_NAME, "Acme"), (NameOID.COMMON_NAME, "Partner CA")))
    other = _ca(_dn((NameOID.ORGANIZATION_NAME, "Other"), (NameOID.COMMON_NAME, "Other CA")))
    source = await _started(
        _source(
            tmp_path,
            [named[0], other[0]],
            {named[0].subject.rfc4514_string(): [SUBJECT]},
        )
    )
    try:
        # Control: the same subject from the CA it is listed under is admitted.
        assert await _admitted(source, _bundle(tmp_path, named)) == 202
        # Both chains verify at the TLS layer; only the issuer differs.
        assert await _refused(source, _bundle(tmp_path, other)) == 403
    finally:
        await source.stop()


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
