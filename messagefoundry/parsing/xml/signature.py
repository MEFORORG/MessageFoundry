# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""XML Digital Signature (XML-DSig) verification for the XML codec (``signxml`` behind the ``[xml]``
extra, BACKLOG #31) — verifying an inbound signed XML/SOAP body's integrity & origin.

``signxml`` performs the cryptography (it pulls in ``cryptography`` + ``hashlib`` for the DSig digest /
signature primitives), so this module is recorded in the cryptographic-discovery inventory
(``scripts/security/crypto_inventory_check.py``) by its module path even though the import is lazy: the
crypto provenance is "XML-DSig signature verification via signxml".

The signed document is parsed through **our** hardened lxml parser
(:mod:`messagefoundry.parsing.xml.harden`), so an untrusted signed body still goes through the
XXE/DTD lockdown before any signature processing.

**PHI rule:** a verification failure is reported by *reason category* only (signxml's exception type,
or one of this module's fixed names such as :data:`WEAK_SIGNING_KEY`), never the document content.

Pure: no engine imports.
"""

from __future__ import annotations

import dataclasses
import hashlib  # noqa: F401 - crypto-inventory anchor: XML-DSig digests run via signxml/cryptography
from dataclasses import dataclass
from typing import Any

from messagefoundry.parsing.xml._deps import load_lxml, load_signxml
from messagefoundry.parsing.xml.errors import XmlError
from messagefoundry.parsing.xml.harden import parse_bytes

__all__ = [
    "UNREADABLE_SIGNING_KEY",
    "UNSIGNED_CONTENT",
    "WEAK_SIGNING_KEY",
    "XmlSignatureResult",
    "verify",
]


@dataclass(frozen=True)
class XmlSignatureResult:
    """The outcome of an XML-DSig verification.

    ``verified`` is True iff the signature is valid against the supplied certificate/CA, its key
    clears the strength floor, AND it covers the whole document (vault BACKLOG #2315). ``reason`` is a
    PHI-safe failure category when not (``None`` on success).

    ``signed_content`` is the content the signature covers, as the signer canonicalized it: the
    document without its ``ds:Signature`` element. It is ``None`` unless ``verified``. **Read the
    message from these bytes, not from the document you passed in.** A verified document matches
    them, but these bytes are what the cryptography actually checked.
    """

    verified: bool
    reason: str | None = None
    signed_content: bytes | None = None


def _approved_signature_config(signxml: Any) -> Any:
    """signxml's accept-set minus every algorithm built on a sub-254-bit digest (BACKLOG #1171).

    ``XMLVerifier.verify`` takes ``expect_config`` and this call passed NONE, so the library's own
    default decided which algorithms a partner's signature could use. Measured on the pinned version,
    that default admits **SHA-224 and SHA3-224** as digests and six signature methods built on them.
    The V11 appendix's general-use preamble disqualifies a sub-254-bit digest output for new designs
    in any collision-resistance-requiring application, and a signature is one.

    DERIVED BY SUBTRACTION FROM THE LIBRARY'S DEFAULT, not rebuilt. ``replace`` keeps every other
    field the pinned version ships -- ``require_x509``, ``expect_references``, the c14n method -- so a
    future signxml that hardens a default we never named is not silently reverted by this call. A
    hand-built config would freeze today's answer to questions this code is not trying to decide.

    SCOPE, STATED BECAUSE IT IS NARROWER THAN THE ITEM'S: only the digest-STRENGTH limb is applied
    here. #1171 also reads the appendix as disallowing RSA-PKCS#1-v1.5 and DSA outright, and both are
    in the default accept-set (``RSA_SHA256`` and its siblings are PKCS#1 v1.5; ``DSA_SHA256`` is
    present). That restriction is NOT applied, because it would refuse the most common XML-DSig
    signature in use and the appendix's text cannot be read from this checkout to confirm it. Applying
    a break-the-common-case restriction on a relayed reading of a standard is not a call this change
    makes.
    """
    default = signxml.SignatureConfiguration()
    weak = "224"
    return dataclasses.replace(
        default,
        digest_algorithms=frozenset(d for d in default.digest_algorithms if weak not in d.name),
        signature_methods=frozenset(m for m in default.signature_methods if weak not in m.name),
    )


#: The smallest RSA modulus whose signature ``verify`` will accept (BACKLOG #1166, ASVS 11.2.3).
#: 2048, not 3072, by owner ruling R6 (2026-09-23): a partner signing key is counterparty material,
#: and RSA-2048 is what healthcare partners and public CAs issue today. That is about 112 bits, so
#: this floor closes the unbounded case and does NOT meet the 128-bit verb; the cell stays a recorded
#: partial. The RSA number matches ``transports/direct.py``'s partner-key floor; Direct also refuses
#: EC curves outside an allow-list, and this module does not.
_MIN_RSA_BITS = 2048

#: Fixed, PHI-safe ``reason`` values. Each names a category, never key or document content.
WEAK_SIGNING_KEY = "WeakSigningKey"
UNREADABLE_SIGNING_KEY = "UnreadableSigningKey"
UNSIGNED_CONTENT = "UnsignedContent"


def _signing_key_refusal(result: Any) -> str | None:
    """Return a refusal reason if the key that verified ``result`` is below the floor, else ``None``.

    MEASURED BEFORE THIS CHECK EXISTED: an RSA-1024 signer returned ``verified=True`` on BOTH anchor
    paths -- pinned via ``x509_cert``, and chained to a partner CA via ``ca_pem_file``. signxml's
    chain verifier refuses a 1024-bit CA key, but it never inspects the LEAF key that actually signs.

    It reads the key signxml reports it USED (``VerifyResult.signature_key``), not the anchor the
    caller passed. On the ``ca_pem_file`` path the signing key comes from the document's own
    certificate chain, so the anchor alone cannot answer the question.

    RSA ONLY, deliberately. EC and DSA keys pass through unchanged. Measured 2026-09-28 on signxml
    5.1.0, a P-192 key and a 1024-bit DSA key both still verify; whether to floor them is a separate
    call this change does not make.

    A key this cannot read is REFUSED rather than passed, and so is a result that names no key at
    all: a floor that cannot see the key and returns success anyway would report success forever.
    """
    # Imported here, not at module top: importing the xml package must stay free until a verify
    # path runs (see the package docstring).
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    results = result if isinstance(result, list) else [result]
    if not results:
        return UNREADABLE_SIGNING_KEY
    for one in results:
        try:
            key = load_pem_public_key(one.signature_key)
        except (AttributeError, TypeError, ValueError, UnsupportedAlgorithm):
            return UNREADABLE_SIGNING_KEY
        if isinstance(key, rsa.RSAPublicKey) and key.key_size < _MIN_RSA_BITS:
            return WEAK_SIGNING_KEY
    return None


_DS_NS = "http://www.w3.org/2000/09/xmldsig#"
_DSIG11_NS = "http://www.w3.org/2009/xmldsig11#"
_KEY_INFO = f"{{{_DS_NS}}}KeyInfo"
#: The elements ``ds:KeyInfo`` may hold: the X.509, key-value and key-name forms of XML-DSig 1.0 and
#: 1.1. Named one by one because the schema checks an unknown element in either namespace loosely.
#: ``RetrievalMethod``, ``PGPData``, ``SPKIData`` and ``ECParameters`` are left out; signxml reads
#: none of them.
_KEY_INFO_ELEMENTS = frozenset(
    {
        _KEY_INFO,
        *(
            f"{{{_DS_NS}}}{name}"
            for name in (
                "KeyName",
                "MgmtData",
                "X509Data",
                "X509IssuerSerial",
                "X509IssuerName",
                "X509SerialNumber",
                "X509SKI",
                "X509SubjectName",
                "X509Certificate",
                "X509CRL",
                "KeyValue",
                "RSAKeyValue",
                "Modulus",
                "Exponent",
                "DSAKeyValue",
                "P",
                "Q",
                "G",
                "Y",
                "J",
                "Seed",
                "PgenCounter",
            )
        ),
        *(
            f"{{{_DSIG11_NS}}}{name}"
            for name in (
                "ECKeyValue",
                "NamedCurve",
                "PublicKey",
                "DEREncodedKeyValue",
                "KeyInfoReference",
                "X509Digest",
            )
        ),
    }
)
#: The attributes those elements define. Anything else could carry text a Handler might read.
_KEY_INFO_ATTRIBUTES = frozenset({"Id", "URI", "Algorithm"})
#: XML's own whitespace. ``str.strip()`` with no argument also strips Unicode spaces such as U+00A0.
_XML_SPACE = " \t\r\n"
_SIGNATURE = f"{{{_DS_NS}}}Signature"
#: The ``ds:Signature`` children a whole-document signature may carry. ``ds:Object`` is left out on
#: purpose: an enveloped signature has no use for one, and nothing signs what it holds.
_SIGNATURE_CHILDREN = frozenset(
    {f"{{{_DS_NS}}}SignedInfo", f"{{{_DS_NS}}}SignatureValue", _KEY_INFO}
)


def _drop_signature(signature: Any) -> None:
    """Remove ``signature`` from its parent and keep its tail text, as the enveloped transform does.

    A copy of ``signxml.util._remove_sig``, the removal the verifier runs, so the document side of
    the comparison drops exactly what the digest side dropped. Copied rather than imported because
    that name is private; keep the two in step. Dropping the tail too would refuse a pretty-printed
    document.
    """
    parent = signature.getparent()
    if signature.tail:
        previous = signature.getprevious()
        if previous is None:
            parent.text = (parent.text or "") + signature.tail
        else:
            previous.tail = (previous.tail or "") + signature.tail
    parent.remove(signature)


def _signature_holds_unsigned_content(signature: Any) -> bool:
    """True if the ``ds:Signature`` element carries anything a Handler could mistake for payload.

    The enveloped transform removes the whole element before digesting, so nothing inside it is
    signed except ``ds:SignedInfo``, which the signature value covers. The schema signxml enforces
    still admits a ``ds:Object`` of any content, and a ``ds:KeyInfo`` that holds foreign-namespace
    elements, unknown DSig-namespace elements, and free text between its children. So this allows
    only the three standard children. Inside ``ds:KeyInfo`` it allows only the named key elements
    and their attributes, and text only inside one with no children, such as a certificate or a key
    name. It refuses a comment or processing instruction anywhere in the element, because no
    signature covers one there.
    """

    def blank(text: str | None) -> bool:
        return not (text or "").strip(_XML_SPACE)

    if any(not isinstance(el.tag, str) for el in signature.iter()):
        return True
    for child in signature:
        if child.tag not in _SIGNATURE_CHILDREN:
            return True
        if child.tag != _KEY_INFO:
            continue
        for el in child.iter():
            if el.tag not in _KEY_INFO_ELEMENTS or not set(el.attrib) <= _KEY_INFO_ATTRIBUTES:
                return True
            if el is not child and not blank(el.tail):
                return True
            if (el is child or len(el)) and not blank(el.text):
                return True
    return False


def _coverage_refusal(root: Any, result: Any, location: str) -> str | None:
    """Return :data:`UNSIGNED_CONTENT` unless the signature covers the whole document (BACKLOG #2315).

    signxml checks that the REFERENCED content is intact, wherever it sits, and returns that content.
    It does not check that the reference is the document. A Handler that reads its own parse of the
    document after ``verified=True`` would therefore act on whatever surrounds the signed element.
    Returning ``signed_content`` alone would not stop a Handler that checks only ``verified``, so
    this REFUSES such a document as well.

    The accepted shape is one reference whose signed content equals the whole received document
    minus its ``ds:Signature``. That admits both shapes an enveloped signer emits, ``URI=""`` and
    ``URI="#id"`` naming the document element, without parsing the URI. Both sides are compared as
    exclusive C14N WITH comments. So an unused namespace declaration does not cause a false refusal,
    and a comment the signature excluded is refused: a comment can split a text node and change what
    an element's ``.text`` reads. For the same reason a comment or processing instruction before or
    after the document element is refused: no enveloped signature covers one. The ``ds:Signature``
    element is checked on its own, because the comparison removes it.

    It MUTATES ``root``: ``verify`` parsed that tree itself and reads nothing from it afterwards, and
    signxml worked on copies of it, so no copy is made here.
    """
    etree = load_lxml()

    # A list means more than one reference. The config keeps signxml's default of exactly one, so a
    # list never arrives from the real call; refusing it keeps this function closed if that changes.
    if isinstance(result, list) or result.signed_xml is None:
        return UNSIGNED_CONTENT
    # signxml also accepts a document element that IS the ds:Signature (an enveloping signature),
    # where the signed content sits in a ds:Object. That shape never covers the whole document.
    if root.tag == _SIGNATURE:
        return UNSIGNED_CONTENT
    if root.getprevious() is not None or root.getnext() is not None:
        return UNSIGNED_CONTENT
    # The lookup signxml's verifier ran, so this drops the element whose removal the digest assumed.
    signature = root.find(f"{location}ds:Signature", namespaces={"ds": _DS_NS})
    if signature is None or _signature_holds_unsigned_content(signature):
        return UNSIGNED_CONTENT
    _drop_signature(signature)

    def c14n(element: Any) -> bytes:
        return bytes(etree.tostring(element, method="c14n", exclusive=True, with_comments=True))

    if c14n(root) != c14n(result.signed_xml):
        return UNSIGNED_CONTENT
    return None


def verify(
    document: str | bytes,
    *,
    x509_cert: str | bytes | None = None,
    ca_pem_file: str | bytes | None = None,
) -> XmlSignatureResult:
    """Verify the enveloped XML-DSig signature on ``document``.

    A trust anchor is **required**: pass ``x509_cert`` to pin the expected signer certificate, **or**
    ``ca_pem_file`` to trust a partner CA. Calling with neither is refused with :class:`ValueError` —
    signxml's default would otherwise trust **any** signature whose embedded certificate chains to the
    host's system CA store, so anyone with a public domain-validated certificate could forge a
    signature this returns ``verified=True`` for (DELTA-03). Returns an :class:`XmlSignatureResult` (a
    failed verification is **data**, not an exception, so a Handler can route the message). A
    signature made with an RSA key under 2048 bits fails with ``reason`` :data:`WEAK_SIGNING_KEY`
    even when the cryptography checks out, and one whose key cannot be read fails with
    :data:`UNREADABLE_SIGNING_KEY` (BACKLOG #1166).

    **Only a signature over the whole document verifies** (vault BACKLOG #2315). A document holding
    anything the signature does not cover fails with :data:`UNSIGNED_CONTENT`: for example a signed
    element under a new document element, content inside the ``ds:Signature`` element, or a comment
    the signature excluded. On success, read the message from ``signed_content``. Raises
    :class:`ValueError` if no anchor is supplied,
    :class:`~messagefoundry.parsing.xml.errors.XmlError` if the input is unparseable, and
    :class:`RuntimeError` if the ``[xml]`` extra is absent."""
    if x509_cert is None and ca_pem_file is None:
        # Refuse origin-blind verification. Require the caller to pin the expected signer or a partner
        # CA rather than fall back to signxml's "trust anything the OS trusts" default (DELTA-03).
        raise ValueError(
            "verify() requires a trust anchor: pass x509_cert (the pinned signer certificate) or "
            "ca_pem_file (a trusted CA). Refusing to trust any system-CA-trusted certificate."
        )
    signxml = load_signxml()
    root = parse_bytes(document)
    verifier = signxml.XMLVerifier()
    config = _approved_signature_config(signxml)
    try:
        result = verifier.verify(
            root,
            x509_cert=x509_cert,
            ca_pem_file=ca_pem_file,
            expect_config=config,
        )
    except signxml.exceptions.InvalidSignature as exc:
        return XmlSignatureResult(verified=False, reason=type(exc).__name__)
    except signxml.exceptions.InvalidInput as exc:
        # No signature present / structurally unprocessable as DSig — a data error, route it.
        raise XmlError(
            f"document is not a verifiable XML-DSig payload: {type(exc).__name__}"
        ) from exc
    refusal = _signing_key_refusal(result) or _coverage_refusal(root, result, config.location)
    if refusal is not None:
        return XmlSignatureResult(verified=False, reason=refusal)
    return XmlSignatureResult(verified=True, signed_content=bytes(result.signed_data))
