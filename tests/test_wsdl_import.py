# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""WSDL 1.1 import — pure SOAP operation/message type-tree + validate-against-WSDL (BACKLOG #69, ADR 0122).

Exercises the parse (operation/message tree + soapAction + resolved body-element QNames), envelope
validation against the embedded XSD (conformant / non-conformant / structural mismatch, PHI-safe reasons),
and the security lockdown (DOCTYPE refused via the hardened parser; a remote wsdl:import / xsd:import
refused no-network, scheme-only message). Skips cleanly if the [xml] extra is absent (like the sibling
XML-codec tests)."""

from __future__ import annotations

import pytest

pytest.importorskip("lxml")
pytest.importorskip("xmlschema")

from messagefoundry.parsing.xml import (  # noqa: E402 - after importorskip
    WsdlDefinition,
    WsdlError,
    WsdlSecurityError,
    XmlSecurityError,
    parse_wsdl,
)
from messagefoundry.parsing.xml.errors import XmlParseError  # noqa: E402

_NS = "http://example.org/eligibility"

WSDL = f"""<?xml version="1.0"?>
<wsdl:definitions
    xmlns:wsdl="http://schemas.xmlsoap.org/wsdl/"
    xmlns:soap="http://schemas.xmlsoap.org/wsdl/soap/"
    xmlns:xsd="http://www.w3.org/2001/XMLSchema"
    xmlns:tns="{_NS}"
    targetNamespace="{_NS}">
  <wsdl:types>
    <xsd:schema targetNamespace="{_NS}"
                elementFormDefault="qualified"
                xmlns:xsd="http://www.w3.org/2001/XMLSchema">
      <xsd:element name="CheckEligibility">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="memberId" type="xsd:string"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
      <xsd:element name="CheckEligibilityResponse">
        <xsd:complexType>
          <xsd:sequence>
            <xsd:element name="eligible" type="xsd:boolean"/>
          </xsd:sequence>
        </xsd:complexType>
      </xsd:element>
    </xsd:schema>
  </wsdl:types>
  <wsdl:message name="CheckEligibilityInput">
    <wsdl:part name="parameters" element="tns:CheckEligibility"/>
  </wsdl:message>
  <wsdl:message name="CheckEligibilityOutput">
    <wsdl:part name="parameters" element="tns:CheckEligibilityResponse"/>
  </wsdl:message>
  <wsdl:portType name="EligibilityPort">
    <wsdl:operation name="CheckEligibility">
      <wsdl:input message="tns:CheckEligibilityInput"/>
      <wsdl:output message="tns:CheckEligibilityOutput"/>
    </wsdl:operation>
  </wsdl:portType>
  <wsdl:binding name="EligibilityBinding" type="tns:EligibilityPort">
    <soap:binding style="document" transport="http://schemas.xmlsoap.org/soap/http"/>
    <wsdl:operation name="CheckEligibility">
      <soap:operation soapAction="http://example.org/eligibility/Check"/>
      <wsdl:input><soap:body use="literal"/></wsdl:input>
      <wsdl:output><soap:body use="literal"/></wsdl:output>
    </wsdl:operation>
  </wsdl:binding>
</wsdl:definitions>"""


def _envelope(body: str, *, env_ns: str = "http://schemas.xmlsoap.org/soap/envelope/") -> str:
    return f'<soap:Envelope xmlns:soap="{env_ns}"><soap:Body>{body}</soap:Body></soap:Envelope>'


_REQUEST_OK = _envelope(
    f'<CheckEligibility xmlns="{_NS}"><memberId>A123</memberId></CheckEligibility>'
)
_RESPONSE_OK = _envelope(
    f'<CheckEligibilityResponse xmlns="{_NS}"><eligible>true</eligible></CheckEligibilityResponse>'
)


# --- parse: operation / message tree ----------------------------------------


def test_parse_builds_operation_tree() -> None:
    d = parse_wsdl(WSDL)
    assert isinstance(d, WsdlDefinition)
    assert d.target_namespace == _NS
    op = d.operations["CheckEligibility"]
    assert op.soap_action == "http://example.org/eligibility/Check"
    assert op.input_element == f"{{{_NS}}}CheckEligibility"
    assert op.output_element == f"{{{_NS}}}CheckEligibilityResponse"


def test_parse_rejects_non_wsdl_root() -> None:
    with pytest.raises(WsdlError, match="not a WSDL"):
        parse_wsdl("<html><body>nope</body></html>")


def test_parse_rejects_malformed_xml() -> None:
    with pytest.raises(XmlParseError):
        parse_wsdl("<wsdl:definitions>unclosed")


# --- validate: conformant / non-conformant / mismatch -----------------------


def test_validate_request_conformant() -> None:
    d = parse_wsdl(WSDL)
    r = d.validate_request(_REQUEST_OK, "CheckEligibility")
    assert r.valid is True and r.reasons == ()


def test_validate_response_conformant() -> None:
    d = parse_wsdl(WSDL)
    assert d.validate_response(_RESPONSE_OK, "CheckEligibility").valid is True


def test_validate_request_non_conformant_has_phi_safe_reasons() -> None:
    d = parse_wsdl(WSDL)
    # memberId is required; an empty body element violates the schema.
    bad = _envelope(f'<CheckEligibility xmlns="{_NS}"></CheckEligibility>')
    r = d.validate_request(bad, "CheckEligibility")
    assert r.valid is False and r.reasons
    # PHI-safe: reasons name a path + category, never a member id value.
    assert "A123" not in " ".join(r.reasons)


def test_validate_structural_mismatch_wrong_body_element() -> None:
    d = parse_wsdl(WSDL)
    # The response element in a request slot → structural mismatch, PHI-safe (QNames only).
    r = d.validate_request(_RESPONSE_OK, "CheckEligibility")
    assert r.valid is False
    assert any("not the expected input element" in reason for reason in r.reasons)


def test_validate_soap12_envelope() -> None:
    d = parse_wsdl(WSDL)
    env12 = _envelope(
        f'<CheckEligibility xmlns="{_NS}"><memberId>Z9</memberId></CheckEligibility>',
        env_ns="http://www.w3.org/2003/05/soap-envelope",
    )
    assert d.validate_request(env12, "CheckEligibility").valid is True


def test_validate_unknown_operation_raises() -> None:
    d = parse_wsdl(WSDL)
    with pytest.raises(WsdlError, match="unknown WSDL operation"):
        d.validate_request(_REQUEST_OK, "NoSuchOp")


def test_validate_empty_body_is_invalid_not_crash() -> None:
    d = parse_wsdl(WSDL)
    r = d.validate_request(_envelope(""), "CheckEligibility")
    assert r.valid is False and any("Body" in reason for reason in r.reasons)


# --- security: hardened parse + no-network import lockdown -------------------


def test_wsdl_with_doctype_is_refused() -> None:
    doctype_wsdl = (
        '<?xml version="1.0"?>\n<!DOCTYPE wsdl:definitions [<!ENTITY x "y">]>\n'
        + WSDL.split("\n", 1)[1]
    )
    with pytest.raises(XmlSecurityError):
        parse_wsdl(doctype_wsdl)


def test_remote_wsdl_import_refused_no_network() -> None:
    wsdl = WSDL.replace(
        f'targetNamespace="{_NS}">',
        f'targetNamespace="{_NS}">\n'
        '  <wsdl:import namespace="urn:other" location="https://evil.example/secret.wsdl"/>',
    )
    with pytest.raises(WsdlSecurityError) as ei:
        parse_wsdl(wsdl)
    # PHI-safe: names the scheme, never the full URL / path.
    assert "https" in str(ei.value) and "secret.wsdl" not in str(ei.value)


def test_remote_xsd_import_refused_no_network() -> None:
    wsdl = WSDL.replace(
        '                xmlns:xsd="http://www.w3.org/2001/XMLSchema">',
        '                xmlns:xsd="http://www.w3.org/2001/XMLSchema">\n'
        '        <xsd:import namespace="urn:x" schemaLocation="http://evil.example/x.xsd"/>',
    )
    with pytest.raises(WsdlSecurityError) as ei:
        parse_wsdl(wsdl)
    assert "http" in str(ei.value) and "x.xsd" not in str(ei.value)


def test_local_relative_import_is_not_refused() -> None:
    # A bare relative import is not remote (not fetched, but not refused at parse) — it only fails closed
    # later if a validated type actually needs it. Here the operation still parses.
    wsdl = WSDL.replace(
        f'targetNamespace="{_NS}">',
        f'targetNamespace="{_NS}">\n  <wsdl:import namespace="urn:other" location="common.wsdl"/>',
    )
    d = parse_wsdl(wsdl)  # must NOT raise
    assert "CheckEligibility" in d.operations
