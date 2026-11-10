# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Opt-in XSD schema validation for the XML codec (``xmlschema`` behind the ``[xml]`` extra, BACKLOG
#31) — the XML analog of the X12 :func:`~messagefoundry.parsing.x12.validate.validate` strict tier.

A Handler calls :func:`validate_against` on demand against a local schema; **remote ``schemaLocation``
fetching is disabled** so a crafted document can't make the validator open a network connection (SSRF),
mirroring the no-network lockdown of :mod:`messagefoundry.parsing.xml.harden`. An inline schema opens
no other resource at all, and a schema given as a path opens files only from its own directory
(:func:`_build_schema` says how, and where that check is weaker than it looks).

**PHI rule:** a validation failure is reported with the failing element *path* and *reason category*
only (xmlschema's structural reason), never the offending element value.

Pure: no engine imports; the only network the validator could do (schema fetch) is disabled.
"""

from __future__ import annotations

import codecs
import os
from dataclasses import dataclass
from typing import Any

from messagefoundry.parsing.xml._deps import load_lxml, load_xmlschema
from messagefoundry.parsing.xml.errors import XmlValidationError
from messagefoundry.parsing.xml.harden import parse_bytes

__all__ = ["XmlSchemaResult", "validate_against"]


@dataclass(frozen=True)
class XmlSchemaResult:
    """The outcome of an XSD validation pass. ``valid`` is True iff the document conforms; ``reasons``
    is a tuple of **PHI-safe** failure summaries (failing element *path* + reason category), empty when
    valid."""

    valid: bool
    reasons: tuple[str, ...] = ()


#: Byte-order marks a bytes schema document may open with. No filesystem path starts with one, so a
#: bytes source carrying one is the XSD itself (BACKLOG #5537).
_BOMS = (
    codecs.BOM_UTF8,
    codecs.BOM_UTF16_LE,
    codecs.BOM_UTF16_BE,  # BOM_UTF32_LE starts with BOM_UTF16_LE, so it needs no entry
    codecs.BOM_UTF32_BE,
)


def _is_inline_xml(schema_source: str | bytes) -> bool:
    """True when ``schema_source`` is the XSD **document** rather than a path/URL to one.

    A leading byte-order mark counts as document text. Without that, a BOM-prefixed schema was read as
    a path: a ``str`` failed to load, and a ``bytes`` one skipped the hardened pre-parse below, so
    xmlschema parsed the raw text itself and expanded a DOCTYPE entity (BACKLOG #5537)."""
    if isinstance(schema_source, (bytes, bytearray)):
        return schema_source.startswith(_BOMS) or schema_source.lstrip()[:1] == b"<"
    return schema_source.removeprefix("\N{BYTE ORDER MARK}").lstrip()[:1] == "<"


def _build_schema(xmlschema_mod: Any, schema_source: str | bytes) -> Any:
    """Construct an ``xmlschema.XMLSchema`` that reads no resource beyond the schema it was given.

    An **inline** schema is parsed by :func:`~messagefoundry.parsing.xml.harden.parse_bytes` first, so
    the XSD goes through the same lockdown as every other document and xmlschema is handed an
    already-hardened tree instead of raw text (ASVS 1.5.3). Without that it parsed the source with its
    own **non-defused** ElementTree: an XSD carrying
    ``<!DOCTYPE xs:schema [<!ENTITY nm "patient">]>`` was parsed and its internal entity **expanded**,
    while ``parse_bytes`` refuses a DOCTYPE outright. The tree is then built under ``allow="none"``:
    a ``schemaLocation`` on an ``include``/``import``/``redefine``/``override`` is never opened, local
    or remote. An include or a redefine that needs one fails the build; an import whose location is
    refused is skipped with xmlschema's warning, so a type only it defines fails the build. An import
    of a namespace xmlschema already holds, such as the ``xml`` namespace, still resolves. Before
    BACKLOG #5537 this was ``allow="local"`` with no ``defuse``, and an inline schema's
    ``xs:include`` of a ``file:`` URL read that local file and expanded a DOCTYPE entity inside it.

    A schema given as a **path** cannot be pre-parsed; xmlschema opens it under ``allow="sandbox"``
    with ``base_url`` set to the schema's own directory, so it and its includes are read only from
    that directory or below it, never over the network. ``defuse="always"`` makes xmlschema refuse an
    entity declaration in each file it opens. The sandbox is xmlschema's own check, and it compares
    URL **string prefixes**: a sibling directory whose name starts with the schema directory's name
    (``schemas-old`` beside ``schemas``) is inside it as far as that check is concerned.
    """
    try:
        if _is_inline_xml(schema_source):
            return xmlschema_mod.XMLSchema(
                parse_bytes(schema_source), allow="none", defuse="always"
            )
        # Absolute, because xmlschema joins a relative source onto base_url.
        path = os.path.abspath(os.fsdecode(schema_source))
        return xmlschema_mod.XMLSchema(
            path, allow="sandbox", defuse="always", base_url=os.path.dirname(path)
        )
    except Exception as exc:  # xmlschema (and now harden) raise their own hierarchies
        # The exception TYPE names which gate refused it (XmlSecurityError = the XSD carried a
        # DOCTYPE) without quoting the schema text. Keeps validate_against's documented contract:
        # a schema that cannot be loaded is always XmlValidationError.
        raise XmlValidationError(f"could not load XSD schema: {type(exc).__name__}") from exc


def validate_against(document: str | bytes, schema_source: str | bytes) -> XmlSchemaResult:
    """Validate ``document`` against the XSD ``schema_source`` (a schema string/bytes or a local path).

    Returns an :class:`XmlSchemaResult`; a well-formed document that does not conform is returned as
    data, never raised, so a Handler can route the message and still see why. Raises
    :class:`~messagefoundry.parsing.xml.errors.XmlValidationError` when the schema itself can't be
    loaded, and :class:`RuntimeError` if the ``[xml]`` extra is absent. A ``document`` the hardened
    parser refuses is raised, not returned: :class:`~messagefoundry.parsing.xml.errors.XmlParseError`
    when it is not well-formed, and :class:`~messagefoundry.parsing.xml.errors.XmlSecurityError` when
    it declares a DOCTYPE. Both are :class:`ValueError`, so a Handler's ``except ValueError`` still
    routes the message to the error path; the refusal stays loud rather than reading as a schema
    mismatch (BACKLOG #5537)."""
    xmlschema_mod = load_xmlschema()
    etree = load_lxml()
    schema = _build_schema(xmlschema_mod, schema_source)
    # Parse the document through OUR hardened parser, then validate the resulting tree — so the
    # untrusted body still goes through the XXE/DTD lockdown, not xmlschema's own loader.
    root = parse_bytes(document)
    reasons: list[str] = []
    for error in schema.iter_errors(root):
        # PHI-safe: the element path + xmlschema's reason category (its 'reason' can embed the value,
        # so we use the validator/path + the error *type*, not the raw reason text).
        path = getattr(error, "path", None) or "/"
        reasons.append(f"{path}: {type(error).__name__}")
    _ = etree  # ensure the extra is present for callers that re-serialize after validating
    return XmlSchemaResult(valid=not reasons, reasons=tuple(reasons))
