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
