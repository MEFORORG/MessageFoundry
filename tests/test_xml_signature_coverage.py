# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""XML-DSig ``verify()`` trusts a document only when the signature covers all of it (vault BACKLOG #2315).

``verify()`` used to return a bare ``verified=True`` and drop the subtree signxml reported as signed.
A Handler then read its own parse of the whole document. So a document that carried a genuinely
signed element next to content nobody signed came back as trusted, and the Handler read the
unsigned part. The rule and its reasons are recorded once, on ``_coverage_refusal`` in
``messagefoundry/parsing/xml/signature.py``.

Every arm that must be refused has a positive control beside it that must verify, so a check that
refused everything could not pass this file.

All material is minted at run time. No certificate or key is embedded in this file.
"""

from __future__ import annotations

import datetime as dt
from functools import cache

import pytest

pytest.importorskip("signxml")

from cryptography import x509  # noqa: E402 - after the [xml]-extra skip on purpose
from cryptography.hazmat.primitives import hashes, serialization  # noqa: E402
from cryptography.hazmat.primitives.asymmetric import rsa  # noqa: E402
from cryptography.x509.oid import NameOID  # noqa: E402

# Read off the module at call time, so this file COLLECTS against code that predates the constant
# and its assertions -- not an ImportError -- report the defect.
from messagefoundry.parsing.xml import signature as sigmod  # noqa: E402
from messagefoundry.parsing.xml.signature import verify  # noqa: E402

_DS = "http://www.w3.org/2000/09/xmldsig#"
_BODY = b"<Order><Item>SYNTHETIC-WIDGET</Item><Qty>1</Qty></Order>"
_BODY_WITH_ID = b'<Order Id="order-1"><Item>SYNTHETIC-WIDGET</Item><Qty>1</Qty></Order>'
_WITH_COMMENTS = "http://www.w3.org/2006/12/xml-c14n11#WithComments"


@cache
def _key() -> rsa.RSAPrivateKey:
    return rsa.generate_private_key(public_exponent=65537, key_size=2048)


@cache
def _cert_pem() -> bytes:
    key = _key()
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "partner-signer")])
    now = dt.datetime.now(dt.UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - dt.timedelta(days=1))
        .not_valid_after(now + dt.timedelta(days=30))
        .sign(key, hashes.SHA256())
    )
    return cert.public_bytes(serialization.Encoding.PEM)


def _sign(body: bytes, *, c14n: str | None = None) -> bytes:
    from lxml import etree
    from signxml.signer import XMLSigner

    key_pem = _key().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    signer = XMLSigner() if c14n is None else XMLSigner(c14n_algorithm=c14n)
    # A test-only signer over a synthetic body parsed from a literal, never untrusted input.
    root = etree.fromstring(body)  # noqa: S320
    signed = signer.sign(root, key=key_pem, cert=[_cert_pem().decode()])
    return bytes(etree.tostring(signed))


def _verify(doc: bytes) -> sigmod.XmlSignatureResult:
    return verify(doc, x509_cert=_cert_pem())


def _refused(result: sigmod.XmlSignatureResult) -> None:
    assert result.verified is False, "a document with unsigned content came back as trusted"
    assert result.reason == sigmod.UNSIGNED_CONTENT
    assert result.signed_content is None


# --- positive controls: the accepted shapes ---------------------------------------------------------


@pytest.mark.parametrize("body", [_BODY, _BODY_WITH_ID], ids=["uri-empty", "uri-root-id"])
def test_a_signature_over_the_whole_document_verifies(body: bytes) -> None:
    """The two shapes signxml's own enveloped signer produces: ``URI=""``, and ``URI="#id"`` naming
    the document element. Both cover the whole document and must verify."""
    result = _verify(_sign(body))
    assert result.verified, f"a whole-document signature was refused: {result.reason}"
    assert result.reason is None


def test_signed_content_is_the_signed_document_without_the_signature() -> None:
    """``signed_content`` is what a Handler should read: the body as signed, with no ``ds:Signature``."""
    from lxml import etree

    result = _verify(_sign(_BODY))
    assert result.signed_content is not None
    root = etree.fromstring(result.signed_content)  # noqa: S320 - bytes this test just signed
    assert root.tag == "Order"
    assert root.findtext("Item") == "SYNTHETIC-WIDGET"
    assert root.find(f".//{{{_DS}}}Signature") is None


def test_whitespace_after_the_signature_does_not_cause_a_false_refusal() -> None:
    """The comparison must drop the signature the way the enveloped transform does, keeping its tail.

    A placeholder ``ds:Signature`` with trailing whitespace is how a pretty-printed partner document
    arrives; dropping the tail along with the element would refuse it.
    """
    body = (
        b'<Order><Item>SYNTHETIC-WIDGET</Item>\n  <ds:Signature Id="placeholder" xmlns:ds="'
        + _DS.encode()
        + b'"/>'
        b"\n</Order>"
    )
    result = _verify(_sign(body))
    assert result.verified, f"a tail after the signature caused a refusal: {result.reason}"


def test_a_comment_the_signature_covers_is_accepted() -> None:
    """Comments are refused only when the signature excludes them; a with-comments c14n covers them."""
    body = b"<Order><!-- synthetic note --><Item>SYNTHETIC-WIDGET</Item></Order>"
    result = _verify(_sign(body, c14n=_WITH_COMMENTS))
    assert result.verified, f"a signed comment was refused: {result.reason}"


# --- the refusals ------------------------------------------------------------------------------------


def test_a_signed_element_moved_under_a_new_root_is_not_trusted() -> None:
    """The item's case. The signed element keeps its own signature intact, but now sits under a new
    document element beside content the signer never saw. The signature still checks out, so only
    a coverage rule can refuse it."""
    signed = _sign(_BODY_WITH_ID)
    wrapped = b"<Batch>" + signed + b"<Order><Item>UNSIGNED-WIDGET</Item></Order></Batch>"
    _refused(_verify(wrapped))


def test_content_added_inside_the_signature_element_is_not_trusted() -> None:
    """A ``URI=""`` signature covers the whole document EXCEPT its own ``ds:Signature`` element, which
    the enveloped transform removes before digesting. A ``ds:Object`` added there is unsigned."""
    signed = _sign(_BODY)
    injected = signed.replace(
        b"</ds:Signature>", b"<ds:Object><Item>UNSIGNED-WIDGET</Item></ds:Object></ds:Signature>"
    )
    assert injected != signed
    _refused(_verify(injected))


def test_a_foreign_element_inside_key_info_is_not_trusted() -> None:
    """``ds:KeyInfo`` admits elements from other namespaces, and nothing signs them either."""
    signed = _sign(_BODY)
    injected = signed.replace(
        b"</ds:KeyInfo>", b'<p:Item xmlns:p="urn:example:partner">UNSIGNED</p:Item></ds:KeyInfo>'
    )
    assert injected != signed
    _refused(_verify(injected))


@pytest.mark.parametrize(
    ("anchor", "replacement"),
    [
        (b"<ds:KeyInfo>", b"<ds:KeyInfo>UNSIGNED-WIDGET"),
        (b"</ds:X509Data>", b"</ds:X509Data>UNSIGNED-WIDGET"),
        (b"<ds:KeyInfo>", b"<ds:KeyInfo><!-- UNSIGNED-WIDGET -->"),
        (b"<ds:KeyInfo>", b"<ds:KeyInfo><?unsigned UNSIGNED-WIDGET?>"),
        (b"<ds:KeyInfo>", "<ds:KeyInfo>  ".encode()),
        (
            b"</ds:KeyInfo>",
            b'<dsig11:Item xmlns:dsig11="http://www.w3.org/2009/xmldsig11#">UNSIGNED</dsig11:Item>'
            b"</ds:KeyInfo>",
        ),
        (b"<ds:SignedInfo>", b"<ds:SignedInfo><!-- UNSIGNED-WIDGET -->"),
    ],
    ids=[
        "text-in-key-info",
        "tail-after-a-child",
        "comment-in-key-info",
        "pi-in-key-info",
        "non-xml-space-in-key-info",
        "unknown-dsig11-element",
        "comment-in-signed-info",
    ],
)
def test_free_text_inside_key_info_is_not_trusted(anchor: bytes, replacement: bytes) -> None:
    """``ds:KeyInfo`` is mixed content in the DSig schema, so text can sit between its children."""
    signed = _sign(_BODY)
    injected = signed.replace(anchor, replacement)
    assert injected != signed
    _refused(_verify(injected))


@pytest.mark.parametrize(
    ("anchor", "replacement"),
    [
        (b"<ds:KeyInfo>", b"<ds:KeyInfo><ds:KeyName>partner</ds:KeyName>"),
        (b"<ds:KeyInfo>", b"<ds:KeyInfo>\n  "),
        (
            b"</ds:X509Data>",
            b"<ds:X509IssuerSerial><ds:X509IssuerName>CN=partner-signer</ds:X509IssuerName>"
            b"<ds:X509SerialNumber>1</ds:X509SerialNumber></ds:X509IssuerSerial>"
            b"<ds:X509SubjectName>CN=partner-signer</ds:X509SubjectName></ds:X509Data>",
        ),
    ],
    ids=["key-name", "pretty-printed", "issuer-serial-and-subject"],
)
def test_ordinary_key_info_shapes_still_verify(anchor: bytes, replacement: bytes) -> None:
    """POSITIVE CONTROL for the arm above: key data other signers emit must not be refused."""
    signed = _sign(_BODY)
    edited = signed.replace(anchor, replacement)
    assert edited != signed
    result = _verify(edited)
    assert result.verified, f"an ordinary KeyInfo shape was refused: {result.reason}"


def test_an_xml_declaration_is_not_a_node_outside_the_document_element() -> None:
    """POSITIVE CONTROL for the sibling rule below: a declaration is not a sibling of the root."""
    result = _verify(b'<?xml version="1.0" encoding="UTF-8"?>\n' + _sign(_BODY))
    assert result.verified, f"an XML declaration caused a refusal: {result.reason}"


def test_a_document_element_that_is_the_signature_is_not_trusted() -> None:
    """An enveloping signature keeps the signed content in a ``ds:Object``, never the whole document."""
    from lxml import etree
    from signxml import methods
    from signxml.signer import XMLSigner

    key_pem = _key().private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    body = etree.fromstring(_BODY)  # noqa: S320 - a synthetic literal
    signed = XMLSigner(method=methods.enveloping).sign(
        body, key=key_pem, cert=[_cert_pem().decode()]
    )
    _refused(_verify(bytes(etree.tostring(signed))))


def test_a_comment_the_signature_excludes_is_not_trusted() -> None:
    """The default c14n drops comments before digesting, so a comment added later is unsigned. It can
    split a text node, which changes what an element's ``.text`` reads."""
    signed = _sign(_BODY)
    injected = signed.replace(b"<Qty>1</Qty>", b"<Qty><!---->1</Qty>")
    assert injected != signed
    _refused(_verify(injected))


@pytest.mark.parametrize(
    "outside", [b"<!-- UNSIGNED-WIDGET -->", b"<?unsigned UNSIGNED-WIDGET?>"], ids=["comment", "pi"]
)
@pytest.mark.parametrize("where", ["before", "after"])
def test_a_node_outside_the_document_element_is_not_trusted(outside: bytes, where: str) -> None:
    """An enveloped signature covers the document element, never a sibling of it."""
    signed = _sign(_BODY)
    _refused(_verify(outside + signed if where == "before" else signed + outside))


def test_the_reason_carries_no_content() -> None:
    """A fixed category name, so no document text can reach a log."""
    assert sigmod.UNSIGNED_CONTENT.isalpha()
