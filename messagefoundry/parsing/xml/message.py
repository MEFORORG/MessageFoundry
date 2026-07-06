# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A mutable XML/SOAP message — read and set nodes by XPath, then namespace-aware re-encode (the HL7
:class:`~messagefoundry.parsing.message.Message` / X12 :class:`~messagefoundry.parsing.x12.message.X12Message`
analog for XML, BACKLOG #31).

Parsed through the **hardened** lxml parser (:mod:`messagefoundry.parsing.xml.harden`) so untrusted
inbound XML can't trigger XXE / entity-expansion / external-DTD fetches. A Handler calls this **on
demand** against a :class:`~messagefoundry.parsing.message.RawMessage` (``content_type`` is an
``xml``-family tag, ADR 0004) — XML is **not** pushed through the engine pipeline as a bespoke object.

XPath is namespace-aware: pass a ``namespaces=`` prefix→URI map and use those prefixes in expressions
(lxml requires a prefix for every namespaced element; a default ``xmlns`` still needs a bound prefix).

Pure: no I/O to disk/network, no engine imports.
"""

from __future__ import annotations

from typing import Any, Mapping

from messagefoundry.parsing.xml._deps import load_lxml
from messagefoundry.parsing.xml.errors import XmlError, XmlPathError
from messagefoundry.parsing.xml.harden import parse_bytes

__all__ = ["XmlMessage"]


class XmlMessage:
    """A parsed XML document you can read (``msg.get("//ns:Patient/ns:id/text()")``), mutate
    (``msg.set("//ns:Patient/ns:status", "active")``), and namespace-aware re-encode (``msg.encode()``).

    Construct via :meth:`parse`. ``namespaces`` (prefix→URI) is bound for every XPath call so
    expressions can address namespaced elements."""

    def __init__(self, root: Any, namespaces: Mapping[str, str] | None = None) -> None:
        self._root = root
        self._ns: dict[str, str] = dict(namespaces) if namespaces else {}

    @classmethod
    def parse(cls, raw: str | bytes, *, namespaces: Mapping[str, str] | None = None) -> XmlMessage:
        """Parse ``raw`` (str encoded UTF-8, or bytes) into a mutable model via the hardened parser.

        Raises :class:`~messagefoundry.parsing.xml.errors.XmlParseError` if not well-formed and
        :class:`~messagefoundry.parsing.xml.errors.XmlSecurityError` if it declares a DOCTYPE/DTD."""
        return cls(parse_bytes(raw), namespaces=namespaces)

    @property
    def namespaces(self) -> dict[str, str]:
        """The bound prefix→URI map used for every XPath evaluation."""
        return dict(self._ns)

    # --- read ----------------------------------------------------------------

    def _xpath(self, expression: str) -> list[Any]:
        etree = load_lxml()
        try:
            result = self._root.xpath(expression, namespaces=self._ns or None)
        except etree.XPathError as exc:
            # PHI-safe: names the expression, not the matched content.
            raise XmlPathError(f"invalid XPath {expression!r}: {exc}") from exc
        if isinstance(result, list):
            return result
        # A scalar XPath (e.g. count(), string()) — wrap so callers see a uniform list.
        return [result]

    def find(self, expression: str) -> list[Any]:
        """Every node/value matching ``expression`` (raw lxml nodes or scalar results). Use
        :meth:`get`/:meth:`get_all` for text extraction."""
        return self._xpath(expression)

    def _node_text(self, node: Any) -> str:
        # A scalar XPath result (bool/float/str) or an attribute/text node stringifies directly; an
        # element yields its concatenated text content.
        if isinstance(node, str):
            return node
        if isinstance(node, (bool, int, float)):
            return str(node)
        text = getattr(node, "text", None)
        if text is None and hasattr(node, "itertext"):
            return "".join(node.itertext())
        return text if text is not None else ""

    def get(self, expression: str) -> str | None:
        """Text of the **first** node matching ``expression``, or None if nothing matches. For an
        element, its direct text; for ``.../text()`` or ``@attr``, the string value."""
        nodes = self._xpath(expression)
        if not nodes:
            return None
        return self._node_text(nodes[0])

    def get_all(self, expression: str) -> list[str]:
        """Text of **every** node matching ``expression`` (empty list if none)."""
        return [self._node_text(node) for node in self._xpath(expression)]

    def exists(self, expression: str) -> bool:
        """True iff ``expression`` matches at least one node."""
        return bool(self._xpath(expression))

    # --- mutate --------------------------------------------------------------

    def set(self, expression: str, value: str) -> None:
        """Set the text content of the **single** element matching ``expression`` to ``value``.

        ``value`` is assigned as text (lxml escapes it on serialize, so it cannot inject markup).
        Raises :class:`~messagefoundry.parsing.xml.errors.XmlPathError` if the expression matches zero
        or more than one node, or matches a non-element (e.g. a ``text()``/attribute result — set those
        via :meth:`set_attribute`)."""
        nodes = self._xpath(expression)
        if len(nodes) != 1:
            raise XmlPathError(
                f"set requires exactly one matched element for {expression!r}, matched {len(nodes)}"
            )
        node = nodes[0]
        if not hasattr(node, "text") or isinstance(node, str):
            raise XmlPathError(f"set targets an element; {expression!r} matched a non-element node")
        node.text = value

    def set_attribute(self, expression: str, name: str, value: str) -> None:
        """Set attribute ``name`` to ``value`` on the **single** element matching ``expression``.
        Raises :class:`~messagefoundry.parsing.xml.errors.XmlPathError` if it doesn't match exactly one
        element."""
        nodes = self._xpath(expression)
        if len(nodes) != 1 or not hasattr(nodes[0], "set"):
            raise XmlPathError(
                f"set_attribute requires exactly one matched element for {expression!r}"
            )
        nodes[0].set(name, value)

    # --- encode --------------------------------------------------------------

    def encode(self, *, xml_declaration: bool = True, pretty: bool = False) -> bytes:
        """Serialize back to UTF-8 XML bytes (namespace prefixes preserved by lxml). ``pretty`` adds
        indentation; ``xml_declaration`` controls the leading ``<?xml ...?>``."""
        etree = load_lxml()
        try:
            return bytes(
                etree.tostring(
                    self._root,
                    encoding="utf-8",
                    xml_declaration=xml_declaration,
                    pretty_print=pretty,
                )
            )
        except (ValueError, TypeError) as exc:  # pragma: no cover - defensive
            raise XmlError(f"failed to serialize XML: {exc}") from exc

    def text(self, *, pretty: bool = False) -> str:
        """The serialized document as a ``str`` (UTF-8 decoded), without an XML declaration — handy for
        embedding into another message or logging *structure* (never PHI content at INFO+)."""
        return self.encode(xml_declaration=False, pretty=pretty).decode("utf-8")

    def __str__(self) -> str:
        return self.text()
