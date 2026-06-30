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

import hashlib  # noqa: F401 - crypto-inventory anchor: XML-DSig digests run via signxml/cryptography

from dataclasses import dataclass

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


def verify(
    document: str | bytes,
    *,
    x509_cert: str | bytes | None = None,
    ca_pem_file: str | bytes | None = None,
) -> XmlSignatureResult:
    """Verify the enveloped XML-DSig signature on ``document``.

    Pass ``x509_cert`` to pin the expected signer certificate, or ``ca_pem_file`` to trust a CA. Returns
    an :class:`XmlSignatureResult` (a failed verification is **data**, not an exception, so a Handler
    can route the message). Raises :class:`~messagefoundry.parsing.xml.errors.XmlError` if the input is
    unparseable, and :class:`RuntimeError` if the ``[xml]`` extra is absent."""
    signxml = load_signxml()
    root = parse_bytes(document)
    verifier = signxml.XMLVerifier()
    try:
        verifier.verify(root, x509_cert=x509_cert, ca_pem_file=ca_pem_file)
    except signxml.exceptions.InvalidSignature as exc:
        return XmlSignatureResult(verified=False, reason=type(exc).__name__)
    except signxml.exceptions.InvalidInput as exc:
        # No signature present / structurally unprocessable as DSig — a data error, route it.
        raise XmlError(
            f"document is not a verifiable XML-DSig payload: {type(exc).__name__}"
        ) from exc
    return XmlSignatureResult(verified=True)
