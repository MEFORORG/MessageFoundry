# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sanitize the SERVED copy of an SVG attachment to a tag and attribute allow-list (ASVS 1.3.4).

ADR 0105's 2026-09-28 amendment permits this, and bounds it: the attachment download route may serve
a sanitized copy of an SVG document, while owner ruling 3 still keeps the STORED OBX-5.5 value
verbatim. Nothing here touches the store. The one caller is the download route in ``api/app.py``, which
passes the bytes it has just decoded and serves what this module returns.

**What counts as SVG.** :func:`sanitize_if_svg` sanitizes when EITHER the stored label mentions ``svg``
OR the document's root element is ``svg``. The label is sender-influenced, so a control keyed on it
alone would let an SVG labelled ``text/xml`` or ``text/plain`` through untouched. The root check reads
only as far as the first start tag. A document whose prolog declares an entity is treated as SVG too,
because its root cannot be seen safely, and so it is refused below.

**What survives.** Only elements on :data:`_ALLOWED_ELEMENTS` (drawing, text, gradient, clip, mask,
marker and filter primitives) in the SVG namespace, carrying only attributes on :data:`_ALLOWED_ATTRS`.
Everything else is dropped with its whole subtree: at least ``script``, ``foreignObject``, ``style``,
``a``, ``image``, ``feImage``, every animation element and every foreign namespace. Every ``on*``
attribute goes because none is on the list. ``href`` and ``xlink:href`` survive only on the elements
that reference another part of the drawing, and only as a same-document ``#fragment``. An attribute
value is dropped if it holds a backslash (a CSS escape), a scheme such as ``javascript:`` or
``data:``, ``expression(``, or a ``url(`` that is not a ``#fragment`` reference.

**The ``style`` attribute is translated, never copied.** A declaration survives only when its property
is a presentation attribute on the list and its value passes the same check, and it is written out as
that attribute. Copying CSS through would need a CSS parser to vet it, and CSS escapes, comments and
``url()`` are the classic bypasses. Dropping ``style`` whole would lose the colours of most drawings
from common editors, which keep them there.

**Fail closed.** A document that is not well-formed XML, declares an entity, references an external
entity, has no ``svg`` root, or nests deeper than :data:`_MAX_DEPTH` raises :class:`SvgRejected`, and
the route serves nothing. Serving the original bytes instead would hand an unsanitized SVG to exactly
the case the parser could not vet: a browser's XML parser honours an internal DTD that defusedxml
refuses. A ``<!DOCTYPE>`` with no entity declarations is accepted, since common editors still write
the SVG 1.1 one, and the output never carries it.

Comments and processing instructions are dropped by the parser. The output is rebuilt from the parsed
tree by :func:`_serialize`, which escapes every text node and attribute value, so no markup from the
input reaches the output except through the allow-list.
"""

from __future__ import annotations

import re
from typing import Final
from xml.etree.ElementTree import (  # nosec B405 -- types only; every parse goes through defusedxml
    Element,
    ParseError,
)
from xml.sax.saxutils import escape  # nosec B406 -- output escaping only; nothing is parsed with it

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import DefusedXMLParser
from defusedxml.ElementTree import fromstring as _xml_fromstring

__all__ = ["SvgRejected", "may_be_svg", "sanitize_if_svg", "sanitize_svg"]

SVG_NS: Final = "http://www.w3.org/2000/svg"
XLINK_NS: Final = "http://www.w3.org/1999/xlink"
_XLINK_HREF: Final = f"{{{XLINK_NS}}}href"

#: The deepest element nesting the served copy may carry. A real drawing nests a few levels; a
#: pathological one would otherwise cost unbounded work, so a document past this is refused.
_MAX_DEPTH: Final = 256
#: Bytes that may precede an XML document's first ``<``: whitespace, and the NULs and byte-order marks
#: of the UTF-8, UTF-16 and UTF-32 encodings the parser detects on its own.
_XML_LEAD: Final = b" \t\r\n\x00\xef\xbb\xbf\xfe\xff"

#: SVG drawing elements that carry no script, no navigation and no external fetch of their own.
_ALLOWED_ELEMENTS: Final = frozenset(
    {
        "svg", "g", "defs", "symbol", "use", "switch", "title", "desc",
        "path", "rect", "circle", "ellipse", "line", "polyline", "polygon",
        "text", "tspan", "textPath",
        "linearGradient", "radialGradient", "stop", "pattern", "clipPath", "mask", "marker",
        "filter", "feBlend", "feColorMatrix", "feComponentTransfer", "feComposite",
        "feConvolveMatrix", "feDiffuseLighting", "feDisplacementMap", "feDistantLight",
        "feDropShadow", "feFlood", "feFuncA", "feFuncB", "feFuncG", "feFuncR",
        "feGaussianBlur", "feMerge", "feMergeNode", "feMorphology", "feOffset", "fePointLight",
        "feSpecularLighting", "feSpotLight", "feTile", "feTurbulence",
    }
)  # fmt: skip

#: The elements whose ``href`` points at another part of the same drawing.
_HREF_ELEMENTS: Final = frozenset(
    {"use", "linearGradient", "radialGradient", "pattern", "textPath", "filter"}
)

#: Presentation attributes. These are also the only properties a ``style`` declaration may set.
_PRESENTATION_ATTRS: Final = frozenset(
    {
        "alignment-baseline", "baseline-shift", "clip-path", "clip-rule", "color",
        "color-interpolation", "color-interpolation-filters", "direction", "display",
        "dominant-baseline", "fill", "fill-opacity", "fill-rule", "filter", "flood-color",
        "flood-opacity", "font-family", "font-size", "font-size-adjust", "font-stretch",
        "font-style", "font-variant", "font-weight", "image-rendering", "letter-spacing",
        "lighting-color", "marker-end", "marker-mid", "marker-start", "mask", "opacity",
        "overflow", "paint-order", "shape-rendering", "stop-color", "stop-opacity", "stroke",
        "stroke-dasharray", "stroke-dashoffset", "stroke-linecap", "stroke-linejoin",
        "stroke-miterlimit", "stroke-opacity", "stroke-width", "text-anchor", "text-decoration",
        "text-rendering", "transform", "transform-origin", "unicode-bidi", "vector-effect",
        "visibility", "white-space", "word-spacing", "writing-mode",
    }
)  # fmt: skip

#: Geometry and structure attributes. None of them takes a URL or a script.
_GEOMETRY_ATTRS: Final = frozenset(
    {
        "id", "class", "version", "viewBox", "preserveAspectRatio", "width", "height",
        "x", "y", "x1", "y1", "x2", "y2", "cx", "cy", "r", "rx", "ry", "fx", "fy", "fr",
        "d", "points", "pathLength", "dx", "dy", "rotate", "textLength", "lengthAdjust",
        "startOffset", "method", "spacing", "side", "offset", "systemLanguage",
        "gradientUnits", "gradientTransform", "spreadMethod",
        "patternUnits", "patternContentUnits", "patternTransform",
        "clipPathUnits", "maskUnits", "maskContentUnits",
        "markerWidth", "markerHeight", "markerUnits", "refX", "refY", "orient",
        "filterUnits", "primitiveUnits", "in", "in2", "result", "mode", "operator",
        "k1", "k2", "k3", "k4", "values", "type", "tableValues", "slope", "intercept",
        "amplitude", "exponent", "stdDeviation", "radius", "baseFrequency", "numOctaves",
        "seed", "stitchTiles", "scale", "xChannelSelector", "yChannelSelector", "order",
        "kernelMatrix", "divisor", "bias", "targetX", "targetY", "edgeMode", "preserveAlpha",
        "surfaceScale", "diffuseConstant", "specularConstant", "specularExponent",
        "kernelUnitLength", "azimuth", "elevation", "z", "pointsAtX", "pointsAtY",
        "pointsAtZ", "limitingConeAngle",
    }
)  # fmt: skip

_ALLOWED_ATTRS: Final = _PRESENTATION_ATTRS | _GEOMETRY_ATTRS

#: A same-document reference: ``#`` and an XML name, nothing else.
_FRAGMENT_RE: Final = re.compile(r"#[A-Za-z_][\w.:-]*")
#: A ``url(`` whose target is a same-document fragment, as it reads once whitespace is gone.
_FRAGMENT_URL_RE: Final = re.compile(r"""url\(['"]?#""")
#: Substrings no allow-listed attribute value needs, checked after whitespace and control characters
#: are removed and the value is case-folded, since browsers ignore both inside a scheme.
_FORBIDDEN_IN_VALUE: Final = ("javascript:", "vbscript:", "data:", "expression(", "@import")
#: Browsers ignore these inside a URL scheme, so they are removed before the scheme check.
_IGNORABLE_IN_VALUE_RE: Final = re.compile(r"[\s\x00-\x1f\x7f]+")
_IMPORTANT_RE: Final = re.compile(r"\s*!\s*important\s*$", re.IGNORECASE)


class SvgRejected(ValueError):
    """The document is SVG but could not be vetted, so no copy of it may be served."""


class _RootFound(Exception):
    """Raised from the sniff target at the first start tag; ``args[0]`` is its qualified name."""


class _RootTarget:
    """A parser target that stops the parse at the root element."""

    def start(self, tag: str, attrib: dict[str, str]) -> None:
        raise _RootFound(tag)


def _split(tag: str) -> tuple[str, str]:
    """``{ns}local`` as ``(ns, local)``; an unqualified name has the empty namespace."""
    if tag.startswith("{"):
        ns, _, local = tag[1:].partition("}")
        return ns, local
    return "", tag


def _root_is_svg(body: bytes) -> bool:
    """Whether the document's root element is ``svg``, reading no further than its start tag.

    Non-XML bytes (a PDF, a PNG) fail at the first byte and are not SVG. A prolog that declares an
    entity or references an external one counts as SVG, because the root cannot be read safely past
    it, and the sanitizer then refuses it."""
    parser = DefusedXMLParser(
        target=_RootTarget(), forbid_dtd=False, forbid_entities=True, forbid_external=True
    )
    try:
        parser.feed(body)
    except _RootFound as found:
        return _split(found.args[0])[1] == "svg"
    except DefusedXmlException:
        return True
    except ParseError:
        return False
    return False


def _safe_value(value: str) -> bool:
    """Whether an allow-listed attribute value is free of script, external references and escapes."""
    # Every rejected shape needs one of these characters, so path data and numbers skip the scan.
    if not any(ch in value for ch in ":(@\\"):
        return True
    if "\\" in value:
        return False
    folded = _IGNORABLE_IN_VALUE_RE.sub("", value).casefold()
    if any(bad in folded for bad in _FORBIDDEN_IN_VALUE):
        return False
    return "url(" not in _FRAGMENT_URL_RE.sub("", folded)


def _style_attrs(style: str) -> dict[str, str]:
    """The presentation attributes a ``style`` value sets, keeping only allow-listed, safe ones."""
    kept: dict[str, str] = {}
    for declaration in style.split(";"):
        prop, sep, value = declaration.partition(":")
        prop = prop.strip().casefold()
        value = _IMPORTANT_RE.sub("", value).strip()
        if sep and value and prop in _PRESENTATION_ATTRS and _safe_value(value):
            kept[prop] = value
    return kept


def _kept_attrs(elem: Element, local: str) -> dict[str, str]:
    """The attributes of ``elem`` that survive, keyed by their serialized name."""
    kept: dict[str, str] = {}
    for key, value in elem.attrib.items():
        if key in ("href", _XLINK_HREF):
            ref = value.strip()
            if local in _HREF_ELEMENTS and _FRAGMENT_RE.fullmatch(ref):
                kept["xlink:href" if key == _XLINK_HREF else "href"] = ref
        elif key in _ALLOWED_ATTRS and _safe_value(value):
            kept[key] = value
    # A style declaration outranks the presentation attribute it names, so it overwrites it here too.
    if style := elem.attrib.get("style"):
        kept.update(_style_attrs(style))
    return kept


def _attr(value: str) -> str:
    return escape(value, {'"': "&quot;", "\n": "&#10;", "\r": "&#13;", "\t": "&#9;"})


def _serialize(root: Element, ns: str) -> str:
    """Write the allow-listed part of the tree rooted at ``root``, whose elements live in ``ns``.

    Iterative rather than recursive, so a deep document cannot exhaust the interpreter's stack; the
    depth bound refuses it instead. Text and tails are kept, escaped, including those of a dropped
    element's neighbours, so a drawing's labels survive the removal of whatever sat beside them."""
    out: list[str] = ['<?xml version="1.0" encoding="UTF-8"?>\n']
    # Each item is an element to open at a depth, or a literal string already escaped.
    stack: list[tuple[Element, int] | str] = [(root, 0)]
    while stack:
        item = stack.pop()
        if isinstance(item, str):
            out.append(item)
            continue
        elem, depth = item
        if depth > _MAX_DEPTH:
            raise SvgRejected(f"SVG nests deeper than {_MAX_DEPTH} elements")
        local = _split(elem.tag)[1]
        attrs = _kept_attrs(elem, local)
        if depth == 0:
            attrs = {"xmlns": SVG_NS, "xmlns:xlink": XLINK_NS, **attrs}
        out.append(f"<{local}" + "".join(f' {k}="{_attr(v)}"' for k, v in attrs.items()) + ">")
        if elem.text:
            out.append(escape(elem.text))
        stack.append(f"</{local}>")
        for child in reversed(elem):
            # A child's tail is its parent's text that follows it, so it is kept even when the child
            # is dropped. Comments and processing instructions never reach the tree.
            if child.tail:
                stack.append(escape(child.tail))
            if not isinstance(child.tag, str):
                continue
            child_ns, child_local = _split(child.tag)
            if child_ns == ns and child_local in _ALLOWED_ELEMENTS:
                stack.append((child, depth + 1))
    return "".join(out)


def sanitize_svg(body: bytes) -> bytes:
    """The allow-listed copy of the SVG document ``body``, as UTF-8.

    Raises :class:`SvgRejected` when ``body`` is not a well-formed, entity-free document with an
    ``svg`` root in the SVG namespace or in none."""
    try:
        root = _xml_fromstring(body, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException) as exc:
        raise SvgRejected(
            f"SVG is not a well-formed, entity-free document: {type(exc).__name__}"
        ) from exc
    ns, local = _split(root.tag)
    if local != "svg" or ns not in (SVG_NS, ""):
        raise SvgRejected("document root is not an SVG svg element")
    return _serialize(root, ns).encode("utf-8")


def may_be_svg(label: str | None, body: bytes) -> bool:
    """A cheap, non-blocking pre-check: ``False`` means :func:`sanitize_if_svg` would return ``body``
    unchanged, so the caller can skip the thread hop for a PDF or an image."""
    return "svg" in (label or "").casefold() or body.lstrip(_XML_LEAD).startswith(b"<")


def sanitize_if_svg(label: str | None, body: bytes) -> bytes:
    """``body`` unchanged unless it is SVG by its label or its root, in which case the sanitized copy.

    Raises :class:`SvgRejected` for SVG that cannot be vetted. Blocking work: run it off the event loop."""
    if "svg" in (label or "").casefold() or _root_is_svg(body):
        return sanitize_svg(body)
    return body
