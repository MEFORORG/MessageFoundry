# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The hardened lxml parser — the single place an ``lxml.etree.XMLParser`` is constructed for the XML
codec, locked down against XML attacks on **untrusted** inbound bodies (BACKLOG #31).

``defusedxml`` does **not** cover ``lxml`` (it patches the stdlib ``xml.*`` modules), and
``defusedxml.lxml`` is deprecated, so we harden the lxml parser **directly** here. Every parse in the
codec goes through :func:`hardened_parser`, so the lockdown can't be bypassed by a caller reaching for
lxml's permissive defaults.

Guards (all on by design — inbound HL7/XML is attacker-influenceable, CLAUDE.md §8):

* ``resolve_entities=False`` — custom entity references are **not** expanded → blocks classic XXE and
  billion-laughs entity-expansion DoS at the source.
* ``no_network=True`` — the parser never opens a network connection (no external-DTD / external-entity
  fetch → no SSRF via a crafted ``SYSTEM`` URL).
* ``load_dtd=False`` / ``dtd_validation=False`` — no DTD is loaded or processed.
* ``huge_tree=False`` — keep libxml2's built-in limits on tree size/depth (another expansion-DoS bound).
* ``DOCTYPE`` rejection — :func:`parse_bytes` additionally **rejects any document carrying a DOCTYPE**
  (``etree.DOCSTRING``/``DTD`` in the tree), so a payload can't smuggle entity *definitions* even
  though references wouldn't be resolved — defense in depth, mirroring defusedxml's ``forbid_dtd``.
"""

from __future__ import annotations

from typing import Any

from messagefoundry.parsing.xml._deps import load_lxml
from messagefoundry.parsing.xml.errors import XmlParseError, XmlSecurityError


def hardened_parser() -> Any:
    """A freshly-constructed, locked-down ``lxml.etree.XMLParser``.

    A new parser per call avoids any cross-document state and is cheap. Requires the ``[xml]`` extra
    (raises :class:`RuntimeError` if absent)."""
    etree = load_lxml()
    return etree.XMLParser(
        resolve_entities=False,
        no_network=True,
        load_dtd=False,
        dtd_validation=False,
        huge_tree=False,
        # Strip nothing implicitly; collapse no whitespace — preserve the document faithfully.
        remove_blank_text=False,
    )


def parse_bytes(data: bytes | str) -> Any:
    """Parse ``data`` into an lxml element tree with the hardened parser, refusing any DOCTYPE.

    Returns the root ``_Element``. Raises :class:`XmlSecurityError` if the document declares a DOCTYPE
    (a DTD/entity-definition carrier), and :class:`XmlParseError` if it is not well-formed XML.
    Requires the ``[xml]`` extra."""
    etree = load_lxml()
    if isinstance(data, str):
        payload: bytes = data.encode("utf-8")
    else:
        payload = bytes(data)
    parser = hardened_parser()
    try:
        root = etree.fromstring(payload, parser=parser)
    except etree.XMLSyntaxError as exc:
        # PHI-safe: lxml's message names a line/column + syntax category, not the element content.
        raise XmlParseError(f"not well-formed XML: {exc}") from exc
    # Defense in depth: refuse any DOCTYPE so entity *definitions* can't ride along (references are
    # already not resolved). getroottree().docinfo exposes the parsed DOCTYPE, if any.
    docinfo = root.getroottree().docinfo
    if docinfo is not None and (docinfo.doctype or docinfo.internalDTD or docinfo.externalDTD):
        raise XmlSecurityError(
            "refusing an XML document that declares a DOCTYPE/DTD (entity-definition carrier)"
        )
    return root
