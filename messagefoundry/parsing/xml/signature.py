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

**PHI rule:** a verification failure is reported by *reason category* only, never the document
content. A returned ``reason`` is the class name of the bad-signature exception signxml or
``cryptography`` raised, ``InvalidSignature`` or a subclass such as ``InvalidDigest``, or one of this
module's fixed names such as :data:`WEAK_SIGNING_KEY`. An
:class:`XmlError` for a signature the libraries cannot process names only the class of the exception
raised, which can come from signxml, lxml, ``cryptography`` or the standard library. The rule does
NOT cover a document that fails before signature processing: at least a document that is not
well-formed XML, and a ``str`` document UTF-8 cannot encode, raise errors that can carry document
content. :func:`verify` says what each carries.

Pure: no engine imports.
"""

from __future__ import annotations

import dataclasses
import functools
import hashlib  # noqa: F401 - crypto-inventory anchor: XML-DSig digests run via signxml/cryptography
import logging
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any

from messagefoundry.parsing.xml._deps import load_lxml, load_signxml
from messagefoundry.parsing.xml.errors import XmlError
from messagefoundry.parsing.xml.harden import parse_bytes

if TYPE_CHECKING:
    from cryptography.x509 import Certificate

_log = logging.getLogger(__name__)

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

    ``verified`` is True only if the signature is valid against the supplied certificate/CA, its key
    clears the strength floor, it covers the document outside the ``ds:Signature`` element as
    exclusive C14N with comments reads it, AND that element holds only ``ds:SignedInfo``,
    ``ds:SignatureValue`` and ``ds:KeyInfo``, with no comment or processing instruction and only the
    key data :func:`verify` admits (vault BACKLOG #2315, #5538). ``reason`` is a PHI-safe failure
    category when not (``None`` on success).

    ``signed_content`` is the content the signature covers, as the signer canonicalized it: the
    document without its ``ds:Signature`` element, and under an exclusive-C14N signer without any
    namespace declaration no element or attribute name uses. It is ``None`` unless ``verified``.
    These bytes are what the cryptography actually checked; :func:`verify` says why a Handler reads
    only them.
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
    makes. A DSA signature still fails, but on its KEY: :func:`_signing_key_refusal` refuses every
    DSA key (BACKLOG #1166), whatever this accept-set admits.
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
#: partial. The RSA number matches ``transports/direct.py``'s partner-key floor. That 112-bit
#: residual covers RSA only: EC keys are held to :data:`_APPROVED_EC_CURVES`, and DSA is refused.
_MIN_RSA_BITS = 2048

#: EC curves whose signature ``verify`` will accept (BACKLOG #1166, ASVS 11.2.3). All three are at or
#: above 128-bit security. Named positively, so a curve nobody considered is refused by construction.
#: Twin of ``_APPROVED_EC_CURVES`` in ``transports/direct.py``; keep the two sets equal. It is copied,
#: not imported, because ``parsing/`` is a pure leaf library and must not import ``transports/``.
#: The allowed key TYPES are twins too: both floors admit RSA, EC, Ed25519 and Ed448, and refuse
#: DSA and every other type (BACKLOG #3384). A test in ``tests/test_direct_transport.py`` pins all
#: three.
_APPROVED_EC_CURVES = frozenset({"secp256r1", "secp384r1", "secp521r1"})

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

    THE KEY TYPE IS ALLOW-LISTED, so a type nobody considered is refused rather than passed:

    - RSA passes at :data:`_MIN_RSA_BITS` or more.
    - EC passes only on a curve in :data:`_APPROVED_EC_CURVES`. Measured 2026-09-28 on signxml 5.1.0,
      a P-192 key verified before this check refused it.
    - Ed25519 and Ed448 pass: both meet the 128-bit floor. signxml 5.1.0 offers no EdDSA signature
      method, so neither reaches this check through a real signature today.
    - DSA, and every other type, is refused at any size. Measured the same day, a 1024-bit DSA key
      verified before this check refused it. DSA is not floored at 2048, because the accepted
      112-bit residual on :data:`_MIN_RSA_BITS` covers RSA only.

    A key this cannot read is REFUSED rather than passed, and so is a result that names no key at
    all: a floor that cannot see the key and returns success anyway would report success forever.
    """
    # Imported here, not at module top: importing the xml package must stay free until a verify
    # path runs (see the package docstring).
    from cryptography.exceptions import UnsupportedAlgorithm
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
    from cryptography.hazmat.primitives.serialization import load_pem_public_key

    results = result if isinstance(result, list) else [result]
    if not results:
        return UNREADABLE_SIGNING_KEY
    for one in results:
        try:
            key = load_pem_public_key(one.signature_key)
        except (AttributeError, TypeError, ValueError, UnsupportedAlgorithm):
            return UNREADABLE_SIGNING_KEY
        if isinstance(key, rsa.RSAPublicKey):
            strong = key.key_size >= _MIN_RSA_BITS
        elif isinstance(key, ec.EllipticCurvePublicKey):
            strong = key.curve.name in _APPROVED_EC_CURVES
        else:
            strong = isinstance(key, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey))
        if not strong:
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
    """True if the ``ds:Signature`` element carries unsigned content outside the admitted key data.

    The enveloped transform removes the whole element before digesting, so nothing inside it is
    signed except ``ds:SignedInfo``, which the signature value covers. The schema signxml enforces
    still admits a ``ds:Object`` of any content, and a ``ds:KeyInfo`` that holds foreign-namespace
    elements, unknown DSig-namespace elements, and free text between its children. So this allows
    only the three standard children. Inside ``ds:KeyInfo`` it allows only the named key elements
    and their attributes, and text only inside one with no children, such as a certificate or a key
    name. It refuses a comment or processing instruction anywhere in the element, because no
    signature covers one there.

    What it admits, leaf text included, is still unsigned; see :func:`verify`.
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
    """Return :data:`UNSIGNED_CONTENT` unless the signature covers the document (BACKLOG #2315).

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

    # Content outside the signed element can make the document impossible to canonicalize, such as
    # an element in a namespace with a relative URI. Coverage is then unshown, so refuse (BACKLOG #2816).
    try:
        if c14n(root) != c14n(result.signed_xml):
            return UNSIGNED_CONTENT
    except etree.C14NError:
        return UNSIGNED_CONTENT
    return None


@functools.cache
def _anchor_faults() -> tuple[type[Exception], ...]:
    """The exception types :func:`_read_anchor` reports as an anchor that cannot be read.

    pyOpenSSL is optional, so its error joins only when it imports; without it no pin can be a
    pyOpenSSL object, so nothing can raise that error. Its import can fail with more than
    :class:`ImportError`, such as an :class:`AttributeError` from a pyOpenSSL that does not match
    the installed ``cryptography``, so any failure there leaves its error out rather than escaping.
    """
    from cryptography.exceptions import UnsupportedAlgorithm

    faults: tuple[type[Exception], ...] = (
        ValueError,
        TypeError,
        AttributeError,
        UnsupportedAlgorithm,
    )
    try:
        from OpenSSL.crypto import Error as openssl_error
    except ImportError:
        return faults
    except Exception as exc:
        # Logged, with only the type, because a broken install is otherwise invisible.
        _log.warning(
            "pyOpenSSL failed to import (%s); its error is not an anchor fault", type(exc).__name__
        )
        return faults
    return (*faults, openssl_error)


def _read_anchor(
    signxml: Any, x509_cert: str | bytes | Certificate | None, ca_pem_file: str | bytes | None
) -> tuple[Any, Any]:
    """Read the anchor before signxml's call, whose errors :func:`verify` blames on the document,
    and refuse one that cannot be read as :func:`verify`'s docstring states. Returns ``(pinned
    certificate, None)`` or ``(None, CA store)``. Like signxml, it skips ``ca_pem_file`` when a
    certificate is pinned, and it reads that file through signxml's own loader;
    :func:`_verifier_type` hands the store to signxml's chain check. A pinned ``cryptography``
    certificate object is passed through, any object with ``to_cryptography()``, such as a
    pyOpenSSL one, is converted through it, and anything else is read as PEM text. A caught fault
    becomes a new :class:`ValueError` raised after the handler ends, so the fault is not chained.
    """
    # Imported here, not at module top, as in _signing_key_refusal.
    from cryptography import x509

    if x509_cert is None and ca_pem_file is None:
        # verify() refuses this first; kept closed so signxml never falls back to the system store.
        raise ValueError("a trust anchor is required")
    name = "x509_cert" if x509_cert is not None else "ca_pem_file"
    # Looked up outside the try, so a signxml without them is not blamed on the anchor.
    add_pem_header = signxml.util.add_pem_header
    chain_verifier = signxml.util.X509CertChainVerifier
    # Before the try: an except clause's expression runs only once a fault is in flight, so a
    # failure computing it there would replace that fault and chain onto it.
    faults = _anchor_faults()
    try:
        if x509_cert is not None:
            cert: Any = x509_cert
            if not isinstance(cert, x509.Certificate):
                to_cryptography = getattr(cert, "to_cryptography", None)
                if callable(to_cryptography):
                    cert = to_cryptography()
                else:
                    cert = x509.load_pem_x509_certificate(add_pem_header(cert))
            if not isinstance(cert, x509.Certificate):
                raise TypeError("not a certificate")
            # signxml reads the key inside its call, where a fault would be blamed on the document.
            cert.public_key()
            return cert, None
        if (isinstance(ca_pem_file, str) and "\0" in ca_pem_file) or (
            isinstance(ca_pem_file, bytes) and b"\0" in ca_pem_file
        ):
            # open() refuses such a path with ValueError, which would read as a file that does not
            # parse. No file has that path, so it is one that cannot be opened. OSError is not one
            # of the faults caught below, so it is raised as is.
            raise OSError("ca_pem_file cannot be opened: the path holds a NUL")
        return None, chain_verifier(ca_pem_file=ca_pem_file).store
    except faults as exc:
        fault = f"{name} cannot be read: {type(exc).__name__}"
    raise ValueError(fault)


@functools.cache
def _verifier_type(signxml: Any) -> Any:
    """signxml's ``XMLVerifier``, made to check a certificate chain against a CA store already read.

    signxml's chain verifier reads ``ca_pem_file`` again each time it checks a chain, inside the call
    whose errors :func:`verify` reports as the document's. A CA file deleted or rewritten after
    :func:`_read_anchor` read it would then surface as an :class:`XmlError`. This subclass builds the
    chain verifier signxml would, with its time and policies, and swaps in only the store
    :func:`_read_anchor` returned, so the call never opens the file. Built once per signxml module,
    because signxml loads lazily.
    """

    class _ReadChainVerifier(signxml.util.X509CertChainVerifier):  # type: ignore[misc]
        def __init__(self, store: Any, built: Any) -> None:
            # Every field signxml set, not a hand-kept list, so a field a later signxml adds is kept.
            self.__dict__.update(vars(built))
            self._read_store = store

        @property
        def store(self) -> Any:
            return self._read_store

    class _Verifier(signxml.XMLVerifier):  # type: ignore[misc]
        def __init__(self, ca_store: Any) -> None:
            super().__init__()
            self._ca_store = ca_store

        def get_cert_chain_verifier(self, *args: Any, **kwargs: Any) -> Any:
            # Passed through as given, so the override does not pin signxml's parameter list.
            built = super().get_cert_chain_verifier(*args, **kwargs)
            return _ReadChainVerifier(self._ca_store, built)

    return _Verifier


def verify(
    document: str | bytes,
    *,
    x509_cert: str | bytes | Certificate | None = None,
    ca_pem_file: str | bytes | None = None,
) -> XmlSignatureResult:
    """Verify the enveloped XML-DSig signature on ``document``.

    A trust anchor is **required**: pass ``x509_cert`` to pin the expected signer certificate, **or**
    ``ca_pem_file`` to trust a partner CA. Calling with neither is refused with :class:`ValueError` —
    signxml's default would otherwise trust **any** signature whose embedded certificate chains to the
    host's system CA store, so anyone with a public domain-validated certificate could forge a
    signature this returns ``verified=True`` for (DELTA-03). Returns an :class:`XmlSignatureResult` (a
    failed verification is **data**, not an exception, so a Handler can route the message). A
    signature whose key fails the floor in :func:`_signing_key_refusal` fails with ``reason``
    :data:`WEAK_SIGNING_KEY` even when the cryptography checks out. That includes at least an RSA key
    under 2048 bits, an EC key on a curve outside :data:`_APPROVED_EC_CURVES`, and any DSA key. One
    whose key cannot be read fails with :data:`UNREADABLE_SIGNING_KEY` (BACKLOG #1166).

    **Only a signature over everything outside its own ``ds:Signature`` element verifies** (vault
    BACKLOG #2315), as exclusive C14N with comments reads that content. A document holding content
    the signature does not cover outside that element fails with :data:`UNSIGNED_CONTENT`: for
    example a signed element under a new document element, or a comment the signature excluded.
    Exclusive C14N drops a namespace declaration that no element or attribute name uses, so under
    an exclusive-C14N signer such a declaration is unsigned anywhere in the document, including a
    prefix only a QName in content, such as an ``xsi:type`` value, resolves through. Inside
    ``ds:Signature``, no comment or processing instruction is admitted anywhere, and neither is any
    element, attribute or text that
    :func:`_signature_holds_unsigned_content` does not admit. Each of those is refused: with
    :data:`UNSIGNED_CONTENT` unless an earlier check refuses it first, such as the key floor, the
    cryptography, or signxml's own schema check, which raises :class:`XmlError` rather than
    returning a result.

    **``verified=True`` vouches for ``signed_content`` and nothing else, so read the message from
    ``signed_content``, never from your own parse of ``document``** (vault BACKLOG #5538, reviewed
    not-a-bug). Inside ``ds:Signature``, only ``ds:SignedInfo`` is signed, and a verified document
    may still carry unsigned content there. That includes at least:

    - free text in a ``ds:KeyInfo`` leaf, such as ``ds:KeyName``, ``ds:MgmtData`` or
      ``ds:X509SubjectName``, and on the pinned ``x509_cert`` path ``ds:X509Certificate``;
    - attributes the schema allows on ``ds:Signature`` and ``ds:SignatureValue``, which are not
      checked here: at least an ``Id`` on either, and an ``xsi:`` attribute such as
      ``xsi:schemaLocation`` on ``ds:SignatureValue``;
    - the ``Id``, ``URI`` and ``Algorithm`` attributes :data:`_KEY_INFO_ATTRIBUTES` admits on
      ``ds:KeyInfo`` and its descendants, wherever the schema defines one, such as the ``Id`` of
      ``ds:KeyInfo``, the ``URI`` of ``dsig11:KeyInfoReference`` or the ``Algorithm`` of
      ``dsig11:X509Digest``;
    - a namespace declaration, such as one on ``ds:KeyInfo``, whose URI is free text.

    An unsigned ``Id`` there may repeat an ``Id`` the payload carries, so a ``//*[@Id=...]`` lookup
    on your own parse can return an element nobody signed. The ``ds:KeyInfo`` leaves and their
    attributes are admitted on purpose, as a set, so that a signer emitting standard key data such
    as a key name or subject name is not refused; none of that content is in ``signed_content``. Do
    not take the signer's identity from ``ds:KeyInfo`` either, and do not treat a
    ``ds:X509Certificate`` there as checked: the anchor you pass is what checks the signer.

    Raises :class:`ValueError` if no anchor is supplied. When both are supplied, only ``x509_cert``
    is read and ``ca_pem_file`` is ignored, as signxml does (vault BACKLOG #6120), so a
    ``ca_pem_file`` that cannot be read beside a pin is not refused. The anchor that is used is read
    before the document, and one that cannot be read is refused there with at least these types:
    :class:`ValueError`, whose fixed message names only the anchor and the fault's type, with the
    fault on neither ``__cause__`` nor ``__context__``, such as for a pinned certificate that is not
    one, whose key cannot be loaded or whose pyOpenSSL conversion fails, a CA file holding no
    certificate, or a CA path the platform cannot encode or decode; and :class:`OSError` if
    ``ca_pem_file`` cannot be opened or read from, such as a missing file or a ``str`` or ``bytes``
    path holding a NUL. A fault of another type, such as one a pin's own ``to_cryptography()``
    raises, escapes as raised. Only reading is checked there: a pin whose key type signxml cannot
    verify with, such as Ed25519, or a CA certificate in the file whose key cannot be loaded, fails
    per document instead, as an ``XmlError`` or an ``InvalidCertificate`` result.
    Raises :class:`~messagefoundry.parsing.xml.errors.XmlError` if signxml or a library
    under it cannot process the signature, such as a schema-invalid or empty ``ds:SignatureValue``
    or key data it cannot read (vault BACKLOG #2816, #5372). That message names only the library's
    exception type, and the library's exception is on neither ``__cause__`` nor ``__context__``,
    because several quote the document.

    A document :func:`~messagefoundry.parsing.xml.harden.parse_bytes` cannot parse fails there
    instead, before any signature processing, and that path does NOT hold to the paragraph above.
    It raises at least these:

    - a document that declares a DOCTYPE: :class:`~messagefoundry.parsing.xml.errors.XmlSecurityError`
      with a fixed message;
    - a document that is not well-formed XML: :class:`~messagefoundry.parsing.xml.errors.XmlParseError`,
      whose message carries lxml's syntax-error text and which is chained from lxml's
      ``XMLSyntaxError``. That text can quote the document, such as an element or entity name or
      the bytes at the fault;
    - a ``str`` document that UTF-8 cannot encode, such as one holding a lone surrogate:
      :class:`UnicodeEncodeError`, which is NOT an :class:`XmlError`, and whose ``object``
      attribute holds the whole document.

    Raises :class:`RuntimeError` if the ``[xml]`` extra is absent."""
    if x509_cert is None and ca_pem_file is None:
        # Refuse origin-blind verification. Require the caller to pin the expected signer or a partner
        # CA rather than fall back to signxml's "trust anything the OS trusts" default (DELTA-03).
        raise ValueError(
            "verify() requires a trust anchor: pass x509_cert (the pinned signer certificate) or "
            "ca_pem_file (a trusted CA). Refusing to trust any system-CA-trusted certificate."
        )
    signxml = load_signxml()
    pinned, ca_store = _read_anchor(signxml, x509_cert, ca_pem_file)
    root = parse_bytes(document)
    verifier = signxml.XMLVerifier() if ca_store is None else _verifier_type(signxml)(ca_store)
    config = _approved_signature_config(signxml)
    from cryptography.exceptions import InvalidSignature as cryptography_invalid_signature

    try:
        result = verifier.verify(
            root,
            x509_cert=pinned,
            ca_pem_file=ca_pem_file,
            expect_config=config,
        )
    except cryptography_invalid_signature as exc:
        # The base class: signxml's own InvalidSignature derives from it, and one signxml branch
        # lets the raw cryptography one through. A bad signature stays data.
        return XmlSignatureResult(verified=False, reason=type(exc).__name__)
    except Exception as exc:
        # Broad on purpose, and it wraps ONLY the verifier call (Manager decision, batch 214). It
        # converts every library exception into a typed, body-free XmlError naming the type, and
        # swallows nothing, so it keeps CLAUDE.md section 6. Measured on signxml 5.2.0, malformed
        # signature content raises at least nine types from signxml, lxml, cryptography and
        # builtins, and several quote the document (BACKLOG #2816, #5372); a list of types was
        # shown to let the next unmeasured one escape with that text. A fault reading the anchor
        # does not land here: _read_anchor reads it first, and _verifier_type says why the CA file
        # is not read again. Raised after the handler ends, so the exception is on neither
        # __cause__ nor __context__ (BACKLOG #1796).
        fault = type(exc).__name__
    else:
        refusal = _signing_key_refusal(result) or _coverage_refusal(root, result, config.location)
        if refusal is not None:
            return XmlSignatureResult(verified=False, reason=refusal)
        return XmlSignatureResult(verified=True, signed_content=bytes(result.signed_data))
    raise XmlError(f"document is not a verifiable XML-DSig payload: {fault}")
