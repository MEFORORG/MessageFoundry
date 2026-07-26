# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Pure WSDL 1.1 import — a typed, read-only SOAP operation/message tree + validate-a-SOAP-envelope
against the WSDL's embedded XSD (BACKLOG #69, ADR 0122).

A partner's WSDL becomes a **machine-checkable contract**: :func:`parse_wsdl` walks a WSDL 1.1 document
into a frozen :class:`WsdlDefinition` (operations → message parts → resolved body-element QNames +
soapAction), and :meth:`WsdlDefinition.validate_request` / :meth:`WsdlDefinition.validate_response`
validate a SOAP envelope's body against the WSDL's **embedded** ``<wsdl:types>`` XSD.

**No zeep / no suds / no new dependency** — this uses only ``lxml`` (via the hardened parser) and
``xmlschema`` (via :func:`~messagefoundry.parsing.xml.schema.validate_against`), both already in the
``[xml]`` extra. It reuses the ADR 0015 SOAP transport's hand-built envelopes **unchanged**: a WSDL is
consulted to *check* an envelope, never to *drive* one (BACKLOG #70's synchronous WSCall stays declined).

**Security (CLAUDE.md §8):**

* The untrusted WSDL is parsed through :func:`~messagefoundry.parsing.xml.harden.parse_bytes`, so it gets
  the identical XXE / entity-expansion / external-DTD lockdown as every other body in the codec.
* Envelope validation rides :func:`~messagefoundry.parsing.xml.schema.validate_against`, whose
  ``xmlschema`` is built with remote fetching disabled (``allow="local"``, ``base_url=None``).
* The **distinct** ``wsdl:import`` / ``xsd:import`` / ``xsd:include`` resolution path — which
  ``xmlschema``'s ``allow="local"`` does **not** cover, because a ``wsdl:import`` is parsed by *this*
  code before any schema is built — is locked to **no-network**: a remote ``location``/``schemaLocation``
  is refused (:class:`~messagefoundry.parsing.xml.errors.WsdlSecurityError`), never dereferenced. A local
  import is not fetched either (a pure codec does no I/O); validation against a type reachable only via an
  unresolved import then fails closed through ``xmlschema``.

**PHI (CLAUDE.md §9):** every failure names element **QNames** / reason **categories** / URI **schemes**
only — never element content or a full URL. The PHI-bearing SOAP body goes only to the secured store.

Pure: no engine imports; no disk / network I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlsplit

from messagefoundry.parsing.xml._deps import load_lxml
from messagefoundry.parsing.xml.errors import WsdlError, WsdlSecurityError
from messagefoundry.parsing.xml.harden import parse_bytes
from messagefoundry.parsing.xml.schema import XmlSchemaResult, validate_against

__all__ = [
    "WsdlPart",
    "WsdlOperation",
    "WsdlDefinition",
    "parse_wsdl",
]

# WSDL 1.1 + SOAP binding + XSD namespaces (the fixed grammar namespaces, never PHI).
_WSDL_NS = "http://schemas.xmlsoap.org/wsdl/"
_SOAP11_BIND_NS = "http://schemas.xmlsoap.org/wsdl/soap/"
_SOAP12_BIND_NS = "http://schemas.xmlsoap.org/wsdl/soap12/"
_XSD_NS = "http://www.w3.org/2001/XMLSchema"

# SOAP *envelope* namespaces (1.1 and 1.2) — used to locate <soap:Body> in an instance envelope.
_SOAP11_ENV_NS = "http://schemas.xmlsoap.org/soap/envelope/"
_SOAP12_ENV_NS = "http://www.w3.org/2003/05/soap-envelope"


@dataclass(frozen=True)
class WsdlPart:
    """One ``<wsdl:part>`` of a message: its ``name`` plus the referenced global ``element`` QName
    (document/literal — the first-class case) and/or ``type`` QName (rpc/encoded — parsed best-effort).
    QNames are Clark notation ``{namespace}local``."""

    name: str
    element: str | None = None
    type: str | None = None


@dataclass(frozen=True)
class WsdlOperation:
    """A ``<wsdl:portType>`` operation, resolved to the SOAP body element for its request/response.

    ``input_element`` / ``output_element`` are the Clark-notation QName of the global element carried in
    the SOAP body (document/literal), or ``None`` (rpc/encoded, or an absent input/output). ``soap_action``
    is the binding's ``soapAction`` if present."""

    name: str
    soap_action: str | None = None
    input_element: str | None = None
    output_element: str | None = None


@dataclass(frozen=True)
class WsdlDefinition:
    """A parsed WSDL 1.1 document — a read-only operation/message contract tree.

    Construct via :func:`parse_wsdl`. Validate an instance envelope with :meth:`validate_request` /
    :meth:`validate_response`."""

    target_namespace: str | None
    operations: Mapping[str, WsdlOperation]
    # Embedded <wsdl:types> XSD schema(s), serialized to bytes, keyed by their targetNamespace (or "" for
    # a no-namespace schema). Private carriage for validate_against; not part of the public contract shape.
    _schemas: Mapping[str, bytes]

    def validate_request(self, envelope: str | bytes, operation: str) -> XmlSchemaResult:
        """Validate a request ``envelope``'s SOAP body against ``operation``'s input element (ADR 0122).

        Returns an :class:`~messagefoundry.parsing.xml.schema.XmlSchemaResult` (``valid`` + PHI-safe
        ``reasons``). Raises :class:`~messagefoundry.parsing.xml.errors.WsdlError` for an unknown operation
        or an operation with no resolvable document/literal input element (rpc/encoded not supported for
        validation)."""
        return self._validate(envelope, operation, direction="input")

    def validate_response(self, envelope: str | bytes, operation: str) -> XmlSchemaResult:
        """Validate a response ``envelope``'s SOAP body against ``operation``'s output element (ADR 0122).
        Mirror of :meth:`validate_request` for the reply."""
        return self._validate(envelope, operation, direction="output")

    def _validate(
        self, envelope: str | bytes, operation: str, *, direction: str
    ) -> XmlSchemaResult:
        op = self.operations.get(operation)
        if op is None:
            known = ", ".join(sorted(self.operations)) or "(none)"
            raise WsdlError(f"unknown WSDL operation {operation!r} (declared: {known})")
        expected = op.input_element if direction == "input" else op.output_element
        if expected is None:
            raise WsdlError(
                f"WSDL operation {operation!r} has no document/literal {direction} element to validate "
                "against (rpc/encoded style is not supported for validation)"
            )
        body_child = _soap_body_child(envelope)
        if body_child is None:
            return XmlSchemaResult(valid=False, reasons=("/: missing or empty SOAP Body",))
        actual = _clark(body_child)
        if actual != expected:
            # PHI-safe: names the QNames, never the element content.
            return XmlSchemaResult(
                valid=False,
                reasons=(f"{actual}: not the expected {direction} element {expected}",),
            )
        ns = _namespace_of(expected)
        schema = self._schemas.get(ns)
        if schema is None:
            raise WsdlError(
                f"WSDL has no embedded schema for namespace of {expected} "
                "(a split/imported contract must be inlined locally — no-network, ADR 0122)"
            )
        etree = load_lxml()
        child_bytes = bytes(etree.tostring(body_child, encoding="utf-8"))
        return validate_against(child_bytes, schema)


def parse_wsdl(data: str | bytes) -> WsdlDefinition:
    """Parse a WSDL 1.1 document into a :class:`WsdlDefinition` (BACKLOG #69, ADR 0122).

    Rides :func:`~messagefoundry.parsing.xml.harden.parse_bytes` (XXE/DTD/no-network lockdown). Refuses a
    remote ``wsdl:import`` / ``xsd:import`` / ``xsd:include``
    (:class:`~messagefoundry.parsing.xml.errors.WsdlSecurityError` — the no-network seam). Raises
    :class:`~messagefoundry.parsing.xml.errors.WsdlError` if the document is not a
    ``<wsdl:definitions>`` root, and :class:`RuntimeError` if the ``[xml]`` extra is absent."""
    root = parse_bytes(data)  # hardened parse; DOCTYPE refused
    if _clark(root) != f"{{{_WSDL_NS}}}definitions":
        raise WsdlError("not a WSDL 1.1 document (root is not {wsdl:}definitions)")
    _refuse_remote_imports(root)
    target_namespace = root.get("targetNamespace")
    schemas = _embedded_schemas(root)
    messages = _messages(root)
    operations = _operations(root, messages)
    return WsdlDefinition(
        target_namespace=target_namespace, operations=operations, _schemas=schemas
    )


# --- parsing helpers ---------------------------------------------------------


def _clark(elem: Any) -> str:
    """The element's tag already in Clark notation ``{namespace}local`` (lxml stores tags this way)."""
    return str(elem.tag)


def _namespace_of(clark: str) -> str:
    """The namespace URI from a Clark-notation QName (``{ns}local`` → ``ns``; ``local`` → ``""``)."""
    if clark.startswith("{"):
        return clark[1 : clark.index("}")]
    return ""


def _resolve_qname(prefixed: str | None, nsmap: Mapping[str | None, str]) -> str | None:
    """Resolve a ``prefix:local`` (or bare ``local``) attribute value to Clark ``{ns}local`` using the
    in-scope ``nsmap``. Returns ``None`` for an empty input; leaves an unresolvable prefix as-is-ish by
    treating it as no-namespace (a malformed WSDL fails closed later)."""
    if not prefixed:
        return None
    if ":" in prefixed:
        prefix, local = prefixed.split(":", 1)
    else:
        prefix, local = None, prefixed
    ns = nsmap.get(prefix)
    return f"{{{ns}}}{local}" if ns else local


def _is_remote_location(location: str | None) -> bool:
    """Whether an import ``location``/``schemaLocation`` points off-machine (a scheme like http/https/ftp/
    file, or a network-path ``//host`` reference). A bare relative path is not remote (not fetched, but not
    refused)."""
    if not location:
        return False
    parts = urlsplit(location.strip())
    return bool(parts.scheme) or bool(parts.netloc)


def _refuse_remote_imports(root: Any) -> None:
    """Lock the WSDL-layer resolution seam to no-network (ADR 0122): refuse any ``wsdl:import`` /
    ``xsd:import`` / ``xsd:include`` whose location is remote, so a crafted WSDL can't SSRF past the XSD
    lockdown. PHI-safe: the error names the URI scheme only, never the full URL."""
    for imp in root.iter(f"{{{_WSDL_NS}}}import"):
        if _is_remote_location(imp.get("location")):
            raise WsdlSecurityError(
                f"refusing a remote wsdl:import (scheme {_scheme(imp.get('location'))!r}) — imports are "
                "resolved no-network; inline the imported document locally"
            )
    for tag in (f"{{{_XSD_NS}}}import", f"{{{_XSD_NS}}}include", f"{{{_XSD_NS}}}redefine"):
        for imp in root.iter(tag):
            if _is_remote_location(imp.get("schemaLocation")):
                raise WsdlSecurityError(
                    f"refusing a remote schema import (scheme "
                    f"{_scheme(imp.get('schemaLocation'))!r}) — resolved no-network; inline it locally"
                )


def _scheme(location: str | None) -> str:
    """The URI scheme of a location (PHI-safe locator for an error) — ``""`` for a network-path ref."""
    if not location:
        return ""
    return urlsplit(location.strip()).scheme


def _embedded_schemas(root: Any) -> dict[str, bytes]:
    """Serialize each ``<xsd:schema>`` embedded in ``<wsdl:types>``, keyed by its targetNamespace (or
    ``""``). lxml's ``tostring`` of a sub-element carries the in-scope namespace declarations it uses, so
    each schema round-trips as a standalone document ``xmlschema`` can build."""
    etree = load_lxml()
    schemas: dict[str, bytes] = {}
    for types in root.iter(f"{{{_WSDL_NS}}}types"):
        for schema in types.iter(f"{{{_XSD_NS}}}schema"):
            tns = schema.get("targetNamespace") or ""
            schemas[tns] = bytes(etree.tostring(schema, encoding="utf-8"))
    return schemas


def _messages(root: Any) -> dict[str, list[WsdlPart]]:
    """Map ``<wsdl:message>`` name → its ordered parts (element/type resolved to Clark QNames)."""
    messages: dict[str, list[WsdlPart]] = {}
    for msg in root.iter(f"{{{_WSDL_NS}}}message"):
        name = msg.get("name")
        if not name:
            continue
        parts: list[WsdlPart] = []
        for part in msg.iterchildren(f"{{{_WSDL_NS}}}part"):
            parts.append(
                WsdlPart(
                    name=part.get("name") or "",
                    element=_resolve_qname(part.get("element"), part.nsmap),
                    type=_resolve_qname(part.get("type"), part.nsmap),
                )
            )
        messages[name] = parts
    return messages


def _local_name(prefixed: str | None) -> str | None:
    """The local part of a ``prefix:local`` message reference (a ``message=`` attribute names a
    ``<wsdl:message>`` by its unprefixed ``name``)."""
    if not prefixed:
        return None
    return prefixed.split(":", 1)[1] if ":" in prefixed else prefixed


def _body_element_for_message(
    message_ref: str | None, messages: Mapping[str, list[WsdlPart]]
) -> str | None:
    """The SOAP body element QName for a ``message=`` reference: the first part's ``element`` (document/
    literal). Returns ``None`` for an unknown message or an rpc/encoded (type-only) part."""
    name = _local_name(message_ref)
    if name is None:
        return None
    parts = messages.get(name)
    if not parts:
        return None
    return parts[0].element


def _soap_actions(root: Any) -> dict[str, str]:
    """Map operation name → binding ``soapAction`` (SOAP 1.1 or 1.2 binding), when declared."""
    actions: dict[str, str] = {}
    for binding in root.iter(f"{{{_WSDL_NS}}}binding"):
        for op in binding.iterchildren(f"{{{_WSDL_NS}}}operation"):
            op_name = op.get("name")
            if not op_name:
                continue
            for ns in (_SOAP11_BIND_NS, _SOAP12_BIND_NS):
                soap_op = op.find(f"{{{ns}}}operation")
                if soap_op is not None and soap_op.get("soapAction") is not None:
                    actions[op_name] = soap_op.get("soapAction") or ""
                    break
    return actions


def _operations(root: Any, messages: Mapping[str, list[WsdlPart]]) -> dict[str, WsdlOperation]:
    """Build the operation tree from every ``<wsdl:portType>``/``<wsdl:operation>``, resolving input/
    output body elements via the message table and soapAction via the binding."""
    actions = _soap_actions(root)
    operations: dict[str, WsdlOperation] = {}
    for port_type in root.iter(f"{{{_WSDL_NS}}}portType"):
        for op in port_type.iterchildren(f"{{{_WSDL_NS}}}operation"):
            name = op.get("name")
            if not name:
                continue
            in_el = op.find(f"{{{_WSDL_NS}}}input")
            out_el = op.find(f"{{{_WSDL_NS}}}output")
            operations[name] = WsdlOperation(
                name=name,
                soap_action=actions.get(name),
                input_element=_body_element_for_message(
                    in_el.get("message") if in_el is not None else None, messages
                ),
                output_element=_body_element_for_message(
                    out_el.get("message") if out_el is not None else None, messages
                ),
            )
    return operations


def _soap_body_child(envelope: str | bytes) -> Any | None:
    """The first element child of a SOAP (1.1 or 1.2) ``<Body>`` in ``envelope``, or ``None``. Parsed
    through the hardened parser (untrusted instance body)."""
    root = parse_bytes(envelope)
    for env_ns in (_SOAP11_ENV_NS, _SOAP12_ENV_NS):
        body = root.find(f"{{{env_ns}}}Body")
        if body is not None:
            for child in body:
                # skip comments / processing instructions — only element children
                if isinstance(child.tag, str):
                    return child
    return None
