# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure XML/SOAP codec (BACKLOG #31) — a hardened, namespace-aware XPath read/set message model over
``lxml``, plus opt-in XSD schema validation and XML-DSig verification, mirroring the HL7
:mod:`messagefoundry.parsing` library and the X12 / FHIR / DICOM codecs.

It is **pure and side-effect-free** (no engine state) and imports nothing from
``messagefoundry.config`` / ``pipeline`` / ``store`` / ``transports`` — so the console may import it,
and a code-first Router/Handler calls it **on demand** against a
:class:`~messagefoundry.parsing.message.RawMessage` (an ``xml``-family ``content_type``, ADR 0004):
XML is **not** pushed through the engine pipeline as a bespoke object.

The heavy libraries live behind the optional ``[xml]`` extra (``lxml`` + ``xmlschema`` + ``signxml``),
loaded lazily via :mod:`messagefoundry.parsing.xml._deps`, so importing this package is free until a
parse/validate/verify path is called.

**Security:** ``defusedxml`` does **not** cover ``lxml`` (and ``defusedxml.lxml`` is deprecated), so the
lxml parser is hardened **directly** in :mod:`messagefoundry.parsing.xml.harden`
(``resolve_entities=False``, ``no_network=True``, ``load_dtd=False``, ``huge_tree=False`` + DOCTYPE
rejection) — XXE, billion-laughs entity expansion, and external-DTD SSRF are refused.
"""

from __future__ import annotations

from messagefoundry.parsing.xml.errors import (
    XmlError,
    XmlParseError,
    XmlPathError,
    XmlSecurityError,
    XmlValidationError,
)
from messagefoundry.parsing.xml.harden import hardened_parser, parse_bytes
from messagefoundry.parsing.xml.message import XmlMessage
from messagefoundry.parsing.xml.schema import XmlSchemaResult, validate_against
from messagefoundry.parsing.xml.signature import XmlSignatureResult, verify

__all__ = [
    "XmlMessage",
    "hardened_parser",
    "parse_bytes",
    "validate_against",
    "XmlSchemaResult",
    "verify",
    "XmlSignatureResult",
    "XmlError",
    "XmlParseError",
    "XmlPathError",
    "XmlValidationError",
    "XmlSecurityError",
]
