# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""XML-DSig ``verify()`` turns a signature the libraries cannot process into its documented outcome
(vault BACKLOG #2816, #5372).

Before this, malformed content inside ``ds:Signature`` escaped ``verify()`` as whatever signxml,
lxml or ``cryptography`` raised: ``DocumentInvalid``, ``ValueError``, ``TypeError``, ``KeyError``,
``NotImplementedError``, ``UnsupportedAlgorithm`` or ``C14NError``. Several of those messages quote
the document, against the module's PHI rule. Each shape below is one an inbound document can carry,
and each now raises :class:`XmlError` naming only the exception type, with nothing on
``__cause__`` or ``__context__``. A coverage comparison that cannot canonicalize the document fails
with ``UnsignedContent`` instead, because the cryptography has already passed by then.

A bad ANCHOR is the caller's fault, not the document's, so it keeps raising ``ValueError`` and is
never reported as an ``XmlError``.

All material is minted at run time, and every planted value is synthetic.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Any

import pytest

pytest.importorskip("signxml")

from cryptography.hazmat.primitives import serialization  # noqa: E402 - after the extra skip
from cryptography.hazmat.primitives.asymmetric import x25519  # noqa: E402

from messagefoundry.parsing.xml import signature as sigmod  # noqa: E402
from messagefoundry.parsing.xml.errors import XmlError  # noqa: E402
from messagefoundry.parsing.xml.signature import verify  # noqa: E402
from tests._content_free import assert_chain_severed  # noqa: E402
from tests.test_xml_signature_coverage import (  # noqa: E402
    _BODY,
    _BODY_WITH_ID,
    _cert_pem,
    _key,
    _sign,
)
from tests.test_xml_signature_key_floor import (  # noqa: E402
    _cert,
    _ec,
    _pem,
    _signed_and_anchor,
)
from tests.test_xml_signature_key_floor import _sign as _floor_sign  # noqa: E402

_PLANTED = "SYNTHETICPLANTED"
_PLANTED_B64 = base64.b64encode(_PLANTED.encode())
_DSIG11 = b"http://www.w3.org/2009/xmldsig11#"
#: RSA's SubjectPublicKeyInfo algorithm OID, and the same arc ending in 99, which names no key type.
_RSA_OID = bytes.fromhex("06092A864886F70D010101")
_UNKNOWN_OID = bytes.fromhex("06092A864886F70D010163")


def _replace(doc: bytes, pattern: bytes, replacement: bytes) -> bytes:
    out, count = re.subn(pattern, replacement, doc, count=1, flags=re.S)
    assert count == 1, f"the fixture no longer carries {pattern!r}"
    return out


def _der_key_value(der: bytes) -> bytes:
    return (
        b'<dsig11:DEREncodedKeyValue xmlns:dsig11="'
        + _DSIG11
        + b'">'
        + base64.b64encode(der)
        + b"</dsig11:DEREncodedKeyValue>"
    )


def _after_x509_data(doc: bytes, element: bytes) -> bytes:
    return _replace(doc, rb"(</ds:X509Data>)", rb"\1" + element)


def _unprocessable(doc: bytes, kwargs: dict[str, Any], fault: str, *planted: str) -> None:
    """``verify`` raises ``XmlError`` naming ``fault`` only, and the chain carries nothing."""
    with pytest.raises(XmlError) as caught:
        verify(doc, **kwargs)
    exc = caught.value
    assert str(exc) == f"document is not a verifiable XML-DSig payload: {fault}"
    assert_chain_severed(exc)
    for value in (_PLANTED, *planted):
        assert value not in f"{exc} {exc.args!r} {vars(exc)!r}"


def _pinned() -> dict[str, Any]:
    return {"x509_cert": _cert_pem()}


# --- positive controls: the unmodified fixtures verify ----------------------------------------------


def test_a_good_signature_still_verifies() -> None:
    result = verify(_sign(_BODY), **_pinned())
    assert result.verified, result.reason


def test_a_good_signature_still_verifies_on_the_ca_path(tmp_path: Path) -> None:
    doc, kwargs = _signed_and_anchor(_key(), "ca_pem_file", tmp_path)
    result = verify(doc, **kwargs)
    assert result.verified, result.reason


def test_a_good_ec_signature_with_its_key_value_still_verifies() -> None:
    doc, kwargs = _ec_signed_with_key_value()
    result = verify(doc, **kwargs)
    assert result.verified, result.reason


def test_a_well_formed_bad_signature_is_still_data() -> None:
    """The cryptographic failure stays a ``verified=False`` result, not an ``XmlError``."""
    doc = _replace(_sign(_BODY), rb"SYNTHETIC-WIDGET", b"SYNTHETIC-GADGET")
    result = verify(doc, **_pinned())
    assert result.verified is False
    assert result.reason == "InvalidDigest"


# --- the shapes that escaped ------------------------------------------------------------------------


def test_a_non_base64_signature_value() -> None:
    """signxml's schema check raised lxml's ``DocumentInvalid``, quoting the value.

    libxml2 skips a character outside the base64 alphabet and refuses only a bad length, so the
    value carries 17 alphabet characters as well as the ``!``.
    """
    doc = _replace(_sign(_BODY), rb"(<ds:SignatureValue>)[^<]*", rb"\1" + _PLANTED.encode() + b"X!")
    _unprocessable(doc, _pinned(), "DocumentInvalid")


def test_an_empty_signature_value() -> None:
    """``b64decode(None)`` raised ``TypeError``."""
    doc = _replace(
        _sign(_BODY), rb"<ds:SignatureValue>[^<]*</ds:SignatureValue>", b"<ds:SignatureValue/>"
    )
    _unprocessable(doc, _pinned(), "TypeError")


def test_a_der_encoded_key_value_that_is_not_a_key() -> None:
    """``load_der_public_key`` raised ``ValueError``."""
    doc = _after_x509_data(_sign(_BODY), _der_key_value(_PLANTED.encode()))
    _unprocessable(doc, _pinned(), "ValueError", _PLANTED_B64.decode())


def test_a_der_encoded_key_value_of_an_unknown_key_type() -> None:
    """``load_der_public_key`` raised ``UnsupportedAlgorithm``, quoting the OID."""
    der = (
        _key()
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    assert _RSA_OID in der
    doc = _after_x509_data(_sign(_BODY), _der_key_value(der.replace(_RSA_OID, _UNKNOWN_OID)))
    _unprocessable(doc, _pinned(), "UnsupportedAlgorithm", "1.2.840.113549.1.1.99")


def test_a_der_encoded_key_value_signxml_cannot_compare() -> None:
    """An X25519 key beside an RSA certificate: signxml raised ``NotImplementedError``."""
    der = (
        x25519.X25519PrivateKey.generate()
        .public_key()
        .public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    )
    doc = _after_x509_data(_sign(_BODY), _der_key_value(der))
    _unprocessable(doc, _pinned(), "NotImplementedError")


def test_an_x509_certificate_that_is_not_a_certificate_on_the_ca_path(tmp_path: Path) -> None:
    """On the ``ca_pem_file`` path signxml parses the document's own certificate: ``ValueError``."""
    doc, kwargs = _signed_and_anchor(_key(), "ca_pem_file", tmp_path)
    doc = _replace(doc, rb"(<ds:X509Certificate>)[^<]*", rb"\1" + _PLANTED_B64)
    _unprocessable(doc, kwargs, "ValueError", _PLANTED_B64.decode())


def _ec_signed_with_key_value() -> tuple[bytes, dict[str, Any]]:
    key = _ec("secp256r1")
    cert = _cert(key, key, "partner-signer", "partner-signer", ca=False)
    return _floor_sign(key, cert, always_add_key_value=True), {"x509_cert": _pem(cert)}


def test_an_ec_key_value_on_an_unknown_curve() -> None:
    """signxml looked the curve URI up in a dict: ``KeyError``, whose message is the URI."""
    doc, kwargs = _ec_signed_with_key_value()
    doc = _replace(doc, rb'(NamedCurve URI=")[^"]*', rb"\1urn:oid:" + _PLANTED.encode())
    _unprocessable(doc, kwargs, "KeyError")


def test_an_unknown_signature_method() -> None:
    """Already an ``XmlError``, but chained ``from`` signxml's ``InvalidInput``, which quotes it."""
    doc = _replace(
        _sign(_BODY), rb'(<ds:SignatureMethod Algorithm=")[^"]*', b"\\1urn:" + _PLANTED.encode()
    )
    _unprocessable(doc, _pinned(), "InvalidInput")


def test_a_relative_namespace_in_scope_of_the_signature() -> None:
    """signxml canonicalizes ``ds:SignedInfo`` with the document's namespaces in scope: ``C14NError``."""
    inner = _sign(_BODY_WITH_ID).split(b"?>", 1)[-1]
    doc = b'<Batch xmlns:z="relative/' + _PLANTED.encode() + b'">' + inner + b"</Batch>"
    _unprocessable(doc, _pinned(), "C14NError")


def test_a_relative_namespace_outside_the_signed_element_is_unsigned_content() -> None:
    """signxml never sees this namespace, so its checks pass, and the coverage comparison raised
    ``C14NError``. The content is outside the signed element, so it is refused as unsigned."""
    inner = _sign(_BODY_WITH_ID).split(b"?>", 1)[-1]
    doc = b'<Batch><z:Extra xmlns:z="relative/' + _PLANTED.encode() + b'"/>' + inner + b"</Batch>"
    result = verify(doc, **_pinned())
    assert result.verified is False
    assert result.reason == sigmod.UNSIGNED_CONTENT
    assert result.signed_content is None


# --- a bad anchor is the caller's fault and keeps its own error ------------------------------------


def test_a_pinned_certificate_that_cannot_be_read_is_not_blamed_on_the_document() -> None:
    with pytest.raises(ValueError) as caught:
        verify(_sign(_BODY), x509_cert=_PLANTED_B64)
    assert not isinstance(caught.value, XmlError)


def test_a_ca_file_that_cannot_be_read_is_not_blamed_on_the_document(tmp_path: Path) -> None:
    doc, kwargs = _signed_and_anchor(_key(), "ca_pem_file", tmp_path)
    Path(kwargs["ca_pem_file"]).write_bytes(b"not a certificate")
    with pytest.raises(ValueError) as caught:
        verify(doc, **kwargs)
    assert not isinstance(caught.value, XmlError)


def test_a_ca_file_is_not_read_when_a_certificate_is_pinned(tmp_path: Path) -> None:
    """signxml ignores ``ca_pem_file`` when ``x509_cert`` is set, so a bad one there changes nothing."""
    bad = tmp_path / "unused-ca.pem"
    bad.write_bytes(b"not a certificate")
    result = verify(_sign(_BODY), x509_cert=_cert_pem(), ca_pem_file=str(bad))
    assert result.verified, result.reason
