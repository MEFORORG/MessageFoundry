# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Opt-in XSD schema validation + XML-DSig verification for the XML codec (BACKLOG #31) — the strict
tier behind the tolerant XmlMessage hot path."""

from __future__ import annotations

import pytest

pytest.importorskip("xmlschema")
pytest.importorskip("signxml")

from messagefoundry.parsing.xml import (  # noqa: E402 - after importorskip
    XmlError,
    XmlSchemaResult,
    validate_against,
    verify,
)

_XSD = """<?xml version="1.0"?>
<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">
  <xs:element name="patient">
    <xs:complexType>
      <xs:sequence>
        <xs:element name="id" type="xs:integer"/>
      </xs:sequence>
    </xs:complexType>
  </xs:element>
</xs:schema>"""


def test_schema_accepts_conforming_document() -> None:
    result = validate_against(b"<patient><id>42</id></patient>", _XSD)
    assert isinstance(result, XmlSchemaResult)
    assert result.valid is True
    assert result.reasons == ()


def test_schema_rejects_nonconforming_document() -> None:
    # id must be an integer; "abc" violates the type.
    result = validate_against(b"<patient><id>abc</id></patient>", _XSD)
    assert result.valid is False
    assert result.reasons
    # PHI guard: the offending value 'abc' must not appear in any surfaced reason.
    assert all("abc" not in r for r in result.reasons)


def test_schema_validates_through_hardened_parser() -> None:
    from messagefoundry.parsing.xml import XmlSecurityError

    xxe = (
        b'<?xml version="1.0"?>'
        b'<!DOCTYPE patient [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
        b"<patient><id>1</id></patient>"
    )
    with pytest.raises(XmlSecurityError):
        validate_against(xxe, _XSD)


def test_verify_rejects_unsigned_document() -> None:
    # A plain document carries no XML-DSig signature → not a verifiable payload (a data error, raised).
    with pytest.raises(XmlError):
        verify(b"<root>unsigned</root>")
