# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Exceptions for the XML/SOAP codec (BACKLOG #31).

Kept in their own module (mirroring :mod:`messagefoundry.parsing.x12.errors` /
:mod:`messagefoundry.parsing.fhir.errors`) so the message / schema / signature modules can raise them
without importing each other. All derive from :class:`ValueError`, so a Router/Handler that already
routes ``ValueError`` to the error/dead-letter path catches malformed / non-XML bodies without
special-casing XML — the count-and-log invariant holds for free.

**PHI rule (do not break):** these messages — and *any* codec log line — carry only routing-safe
locators (an XPath expression, an element tag/namespace, a schema assertion *name*), **never** the XML
element *content*. The full PHI-bearing body goes only to the secured store (CLAUDE.md §9).
"""

from __future__ import annotations

__all__ = [
    "XmlError",
    "XmlParseError",
    "XmlPathError",
    "XmlValidationError",
    "XmlSecurityError",
    "WsdlError",
    "WsdlSecurityError",
]


class XmlError(ValueError):
    """Base class for every XML codec error."""


class XmlParseError(XmlError):
    """The bytes are not well-formed XML (or could not be parsed by the hardened parser). The XML analog
    of :class:`~messagefoundry.parsing.x12.errors.X12PeekError` — a Router routes the message to the
    error/dead-letter path rather than guessing."""


class XmlPathError(XmlError):
    """An XPath expression is malformed, or a ``set`` targeted zero / multiple / non-element nodes. Its
    message names the *expression* only, never the matched content."""


class XmlValidationError(XmlError):
    """A well-formed document failed XSD schema validation. Its message is **PHI-safe**: it names the
    failing assertion / element *path* and *reason category* only — never the offending element value."""


class XmlSecurityError(XmlError):
    """A parse was refused because the document tripped a hardened-parser guard — an entity definition
    (DTD/DOCTYPE), an external entity reference, or a network/DTD fetch. The parser is locked down
    (``resolve_entities=False``, ``no_network=True``, ``load_dtd=False``, ``huge_tree=False``), so XXE /
    billion-laughs entity expansion / external-DTD SSRF are refused, not merely ignored. Raised so an
    operator sees *why* a payload was rejected rather than getting a silently-empty parse."""


class WsdlError(XmlError):
    """A WSDL document is malformed, not a WSDL, or an envelope could not be validated against it (BACKLOG
    #69, ADR 0122). A ``ValueError`` subclass (via :class:`XmlError`), so a Handler's ``except ValueError``
    routes it to the error/dead-letter path without special-casing. **PHI-safe**: names element QNames /
    reason categories only, never element content."""


class WsdlSecurityError(WsdlError):
    """A WSDL import could not be resolved without leaving the machine (ADR 0122). ``parse_wsdl`` refuses a
    ``wsdl:import`` / ``xsd:import`` / ``xsd:include`` whose ``location``/``schemaLocation`` points over the
    network (``http:``/``https:``/``ftp:``/a network-path ``//host`` reference) — the distinct WSDL-layer
    resolution seam the ``xmlschema`` ``allow="local"`` no-network config does **not** cover — so a crafted
    WSDL can't SSRF past the XSD lockdown. **PHI-safe**: names the URI *scheme* only, never the full URL."""
