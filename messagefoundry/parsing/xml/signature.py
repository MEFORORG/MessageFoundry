# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""XML Digital Signature (XML-DSig) verification for the XML codec (``signxml`` behind the ``[xml]``
extra, BACKLOG #31) — verifying an inbound signed XML/SOAP body's integrity & origin.

``signxml`` performs the cryptography (it pulls in ``cryptography`` + ``hashlib`` for the DSig digest /
signature primitives), so this module is recorded in the cryptographic-discovery inventory
(``scripts/security/crypto_inventory_check.py``) by its module path even though the import is lazy: the
crypto provenance is "XML-DSig signature verification via signxml".

The signed document is parsed through **our** hardened lxml parser
(:mod:`messagefoundry.parsing.xml.harden`), so an untrusted signed body still goes through the
XXE/DTD lockdown before any signature processing.

**PHI rule:** a verification failure is reported by *reason category* only (signxml's exception type),
never the document content.

Pure: no engine imports.
"""

from __future__ import annotations

import dataclasses
import hashlib  # noqa: F401 - crypto-inventory anchor: XML-DSig digests run via signxml/cryptography
from dataclasses import dataclass
from typing import Any

from messagefoundry.parsing.xml._deps import load_signxml
from messagefoundry.parsing.xml.errors import XmlError
from messagefoundry.parsing.xml.harden import parse_bytes

__all__ = ["XmlSignatureResult", "verify"]


@dataclass(frozen=True)
class XmlSignatureResult:
    """The outcome of an XML-DSig verification. ``verified`` is True iff the signature is valid against
    the supplied certificate/CA; ``reason`` is a PHI-safe failure category when not (``None`` on
    success)."""

    verified: bool
    reason: str | None = None


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
    failed verification is **data**, not an exception, so a Handler can route the message). Raises
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
    try:
        verifier.verify(
            root,
            x509_cert=x509_cert,
            ca_pem_file=ca_pem_file,
            expect_config=_approved_signature_config(signxml),
        )
    except signxml.exceptions.InvalidSignature as exc:
        return XmlSignatureResult(verified=False, reason=type(exc).__name__)
    except signxml.exceptions.InvalidInput as exc:
        # No signature present / structurally unprocessable as DSig — a data error, route it.
        raise XmlError(
            f"document is not a verifiable XML-DSig payload: {type(exc).__name__}"
        ) from exc
    return XmlSignatureResult(verified=True)
