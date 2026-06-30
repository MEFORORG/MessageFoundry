# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Opt-in XSD schema validation for the XML codec (``xmlschema`` behind the ``[xml]`` extra, BACKLOG
#31) — the XML analog of the X12 :func:`~messagefoundry.parsing.x12.validate.validate` strict tier.

A Handler calls :func:`validate_against` on demand against a local schema; **remote ``schemaLocation``
fetching is disabled** so a crafted document can't make the validator open a network connection (SSRF),
mirroring the no-network lockdown of :mod:`messagefoundry.parsing.xml.harden`.

**PHI rule:** a validation failure is reported with the failing element *path* and *reason category*
only (xmlschema's structural reason), never the offending element value.

Pure: no engine imports; the only network the validator could do (schema fetch) is disabled.
"""

from __future__ import annotations

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


def _build_schema(xmlschema_mod: Any, schema_source: str | bytes) -> Any:
    """Construct an ``xmlschema.XMLSchema`` with remote ``schemaLocation`` fetching disabled.

    ``allow="local"`` + ``base_url=None`` keep xmlschema from resolving any non-local schema reference
    over the network (no SSRF via an ``import``/``include``/``schemaLocation`` URL)."""
    try:
        return xmlschema_mod.XMLSchema(schema_source, allow="local", base_url=None)
    except Exception as exc:  # xmlschema raises its own hierarchy for a bad schema
        raise XmlValidationError(f"could not load XSD schema: {type(exc).__name__}") from exc


def validate_against(document: str | bytes, schema_source: str | bytes) -> XmlSchemaResult:
    """Validate ``document`` against the XSD ``schema_source`` (a schema string/bytes or a local path).

    Returns an :class:`XmlSchemaResult`; never raises on a *content* failure (it is returned as data so
    a Handler can route the message and still see why). Raises
    :class:`~messagefoundry.parsing.xml.errors.XmlValidationError` only when the schema itself can't be
    loaded, and :class:`RuntimeError` if the ``[xml]`` extra is absent."""
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
