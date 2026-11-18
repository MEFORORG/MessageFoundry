# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
* Envelope validation rides :func:`~messagefoundry.parsing.xml.schema.validate_against`. Each embedded
  schema reaches it as text, so ``xmlschema`` opens no file for it, local or remote, beyond its bundled
  copies of well-known namespaces (BACKLOG #5537).
* The **distinct** ``wsdl:import`` resolution path is not ``xmlschema``'s to govern, because a
  ``wsdl:import`` is read by *this* code before any schema is built. :func:`parse_wsdl` refuses a
  ``location``/``schemaLocation``, even an empty one, on a ``wsdl:import`` / ``xsd:import`` /
  ``xsd:include`` / ``xsd:redefine`` / ``xsd:override``, local or remote
  (:class:`~messagefoundry.parsing.xml.errors.WsdlSecurityError`, BACKLOG #5539). What the guard let
  through before, and what was opened, is recorded once, in ADR 0122's 2026-11-10 amendment. An
  ``xsd:import`` naming only a ``namespace`` stays legal. A type reachable only through it resolves
  to ``xmlschema``'s bundled copy where it bundles that namespace (XML-DSig, for one), and otherwise
  fails closed through ``xmlschema``.

**PHI (CLAUDE.md §9):** every failure names element **QNames** / reason **categories**, and a refused
location by its element and a well-known URI **scheme** or the kind of reference (``a local path``,
``a network path``) — never element content or any other text of the location. The PHI-bearing SOAP
body goes only to the secured store.

Pure: no engine imports and no network I/O. Parsing reads nothing from disk; validation reads only
``xmlschema``'s bundled schema files.
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
        ``reasons``). The result is invalid unless the root is a SOAP 1.1 or 1.2 ``Envelope`` holding
        an optional ``Header`` and then one ``Body``, and that ``Body`` holds exactly one element
        child, and none of the three holds character data directly (BACKLOG #5373). ``valid=True``
        says that one body element conforms to the schema; it does NOT cover at least header
        blocks, attributes and namespace declarations on the Envelope, Header or Body, or comments
        and processing instructions.

        Raises :class:`~messagefoundry.parsing.xml.errors.WsdlError` for an unknown operation
        or an operation with no resolvable document/literal input element (rpc/encoded not supported for
        validation). The envelope is parsed by
        :func:`~messagefoundry.parsing.xml.harden.parse_bytes`, which raises at least
        :class:`~messagefoundry.parsing.xml.errors.XmlParseError` for an envelope that is not
        well-formed, :class:`~messagefoundry.parsing.xml.errors.XmlSecurityError` for one that
        declares a DOCTYPE, and :class:`UnicodeEncodeError`, which is not an ``XmlError`` and
        carries the document, for a ``str`` that UTF-8 cannot encode, such as one holding a lone
        surrogate. :class:`RuntimeError` if the ``[xml]`` extra is absent."""
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
        body_child, refusal = _soap_body_child(envelope)
        if refusal is not None:
            return XmlSchemaResult(valid=False, reasons=(refusal,))
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
        # with_tail=False: the element alone, never the whitespace that follows it in the Body.
        child_bytes = bytes(etree.tostring(body_child, encoding="utf-8", with_tail=False))
        return validate_against(child_bytes, schema)


def parse_wsdl(data: str | bytes) -> WsdlDefinition:
    """Parse a WSDL 1.1 document into a :class:`WsdlDefinition` (BACKLOG #69, ADR 0122).

    Rides :func:`~messagefoundry.parsing.xml.harden.parse_bytes` (XXE/DTD/no-network lockdown). Refuses a
    ``wsdl:import`` / ``xsd:import`` / ``xsd:include`` / ``xsd:redefine`` / ``xsd:override`` carrying any
    location, local, remote or empty
    (:class:`~messagefoundry.parsing.xml.errors.WsdlSecurityError`, BACKLOG #5539). Raises
    :class:`~messagefoundry.parsing.xml.errors.WsdlError` if the document is not a
    ``<wsdl:definitions>`` root, and :class:`RuntimeError` if the ``[xml]`` extra is absent."""
    root = parse_bytes(data)  # hardened parse; DOCTYPE refused
    if _clark(root) != f"{{{_WSDL_NS}}}definitions":
        raise WsdlError("not a WSDL 1.1 document (root is not {wsdl:}definitions)")
    _refuse_imports(root)
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


#: At least these elements name another document to load, each with the attribute that names it. ADR
#: 0122 requires a split contract to be inlined, so a location on any of them is refused, local or
#: remote (BACKLOG #5539). ``xsd:override`` is XSD 1.1, in the same namespace; xmlschema honours it.
_LOCATION_ATTRS = (
    (f"{{{_WSDL_NS}}}import", "location", "wsdl:import"),
    (f"{{{_XSD_NS}}}import", "schemaLocation", "xsd:import"),
    (f"{{{_XSD_NS}}}include", "schemaLocation", "xsd:include"),
    (f"{{{_XSD_NS}}}redefine", "schemaLocation", "xsd:redefine"),
    (f"{{{_XSD_NS}}}override", "schemaLocation", "xsd:override"),
)


def _refuse_imports(root: Any) -> None:
    """Refuse any ``wsdl:import`` / ``xsd:import`` / ``xsd:include`` / ``xsd:redefine`` /
    ``xsd:override`` that carries a ``location``/``schemaLocation``, even an empty one (ADR 0122,
    BACKLOG #5539).

    Local locations are refused as well as remote ones; ADR 0122's 2026-11-10 amendment says why. An
    ``xsd:import`` that names only a ``namespace`` stays legal; it loads nothing of the author's.
    PHI-safe: the error names the element and :func:`_locator`'s description, never the location."""
    for tag, attr, label in _LOCATION_ATTRS:
        for elem in root.iter(tag):
            location = elem.get(attr)
            if location is not None:  # an empty one too: it resolves to the base, not to nothing
                raise WsdlSecurityError(
                    f"refusing a {label} with a {attr} ({_locator(location)}): a WSDL's imported "
                    "documents are never loaded, so inline the imported document"
                )


#: Schemes an error may name. Any other "scheme" is the text before a colon, which can be anything.
_NAMEABLE_SCHEMES = frozenset({"http", "https", "ftp", "ftps", "file"})


def _locator(location: str) -> str:
    """A PHI-safe description of a location for an error: a well-known URI scheme, or the kind of
    reference. Never any other text from the location."""
    text = location.strip()
    if not text:
        return "an empty location"
    slashed = text.replace("\\", "/")
    if slashed.lower().startswith(("//?/unc/", "//./unc/")):
        return "a network path"
    if slashed.startswith("//?/") and slashed[5:6] == ":" and slashed[4:5].isalpha():
        return "a local path"
    if slashed.startswith(("//./", "//?/")):
        return "a device path"
    if slashed.startswith("//"):
        return "a network path"
    if text[1:2] == ":" and text[:1].isalpha():  # a Windows drive, which urlsplit reads as a scheme
        return "a local path"
    try:
        scheme = urlsplit(text).scheme
    except ValueError:  # e.g. a bracketed host that is not an IP address
        return "an unparseable location"
    if not scheme:
        return "a local path"
    return f"scheme {scheme!r}" if scheme in _NAMEABLE_SCHEMES else "an unrecognised scheme"


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


#: XML's own whitespace (the S production). A bare str.strip() would also drop characters such as
#: U+00A0 and U+3000, which XML treats as character data.
_XML_SPACE = " \t\r\n"


def _holds_character_data(elem: Any) -> bool:
    """Whether ``elem`` holds text other than XML whitespace directly: before its first child, or
    after any child, comments and processing instructions included (CDATA is text here)."""
    return any(
        text is not None and text.strip(_XML_SPACE)
        for text in (elem.text, *(child.tail for child in elem))
    )


def _soap_body_child(envelope: str | bytes) -> tuple[Any, None] | tuple[None, str]:
    """``(element, None)`` for the single element child of the ``<Body>`` of a SOAP (1.1 or 1.2)
    ``envelope``, or ``(None, reason)`` with a PHI-safe reason when the envelope's structure fails
    one of the checks below. Parsed through the hardened parser (untrusted instance body).

    Checked: the root must be a SOAP ``Envelope`` whose element children are an optional
    ``Header`` and then one ``Body``, both in its own namespace; that ``Body`` must hold exactly one
    element child; and none of the Envelope, the Header or the Body may hold character data
    directly. The operation names one body element, so a sibling element or text beside it would
    otherwise reach the caller unvalidated under a valid result (BACKLOG #5373). That is stricter
    than SOAP 1.1, which allows elements after the ``Body``.

    NOT checked, so it can ride beside the validated element under a valid result, at least: the
    Header's element children (header blocks, which SOAP leaves open), attributes and namespace
    declarations on the Envelope, Header and Body, and comments and processing instructions
    anywhere, which are skipped. Reasons name
    only the SOAP grammar's own QNames and counts, never content."""
    root = parse_bytes(envelope)
    env_ns = next(
        (ns for ns in (_SOAP11_ENV_NS, _SOAP12_ENV_NS) if _clark(root) == f"{{{ns}}}Envelope"),
        None,
    )
    if env_ns is None:
        # The root's own name is the sender's text, so it is not echoed.
        return None, "/: root is not a SOAP 1.1 or 1.2 Envelope"
    header, body = f"{{{env_ns}}}Header", f"{{{env_ns}}}Body"
    names = [_clark(child) for child in root if isinstance(child.tag, str)]
    if body not in names:
        return None, "/: missing or empty SOAP Body"
    if names.count(body) > 1:
        return None, f"/Envelope: {names.count(body)} SOAP Body elements; expected exactly one"
    if names not in ([body], [header, body]):
        return None, "/Envelope: elements other than an optional Header followed by one Body"
    if _holds_character_data(root):
        return None, "/Envelope: character data beside the Header and Body"
    header_elem = root.find(header)
    if header_elem is not None and _holds_character_data(header_elem):
        return None, "/Envelope/Header: character data beside the header blocks"
    body_elem = root.find(body)
    # skip comments / processing instructions — only element children
    children = [child for child in body_elem if isinstance(child.tag, str)]
    if not children:
        return None, "/: missing or empty SOAP Body"
    if len(children) > 1:
        return None, f"/Envelope/Body: {len(children)} element children; expected exactly one"
    if _holds_character_data(body_elem):
        return None, "/Envelope/Body: character data beside the body element"
    return children[0], None
