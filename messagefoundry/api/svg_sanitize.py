# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sanitize the SERVED copy of an SVG attachment to a tag and attribute allow-list (ASVS 1.3.4).

ADR 0105's 2026-09-28 amendment permits this, and bounds it: the attachment download route may serve
a sanitized copy of an SVG document, while owner ruling 3 still keeps the STORED OBX-5.5 value
verbatim. Nothing here touches the store. The one caller is the download route in ``api/app.py``, which
passes the bytes it has just decoded and serves what this module returns.

**The rules live in the ADR amendment, not here.** What counts as an SVG, what the allow-list keeps,
and what is refused are recorded once, in ADR 0105's 2026-09-28 amendment. These notes cover only how
the code meets them.

- Every string check is linear in its input. A value can be as large as the document, so a regex that
  backtracks on a long run of one character would stall the thread the route runs this on.
- The output is rebuilt from the parsed tree by :func:`_serialize`, which escapes every text node and
  attribute value, so no markup from the input reaches the output except through the allow-list.
  Comments and processing instructions never reach the tree.
- When the parser cannot reach a document's root, :func:`_first_element_name` finds it by scanning the
  bytes, skipping comments, processing instructions and declarations. So an SVG cannot escape the
  sanitizer by making the parser fail first, and an HTML page that merely embeds an ``<svg>`` is not
  mistaken for one.
"""

from __future__ import annotations

import re
from typing import Final
from xml.etree.ElementTree import (  # nosec B405 -- types only; every parse goes through defusedxml
    Element,
    ParseError,
)
from xml.sax.saxutils import escape  # nosec B406 -- output escaping only; nothing is parsed with it

from messagefoundry._vendor.defusedxml.common import DefusedXmlException
from messagefoundry._vendor.defusedxml.ElementTree import DefusedXMLParser
from messagefoundry._vendor.defusedxml.ElementTree import fromstring as _xml_fromstring

__all__ = ["SvgRejected", "may_be_svg", "sanitize_if_svg", "sanitize_svg"]

SVG_NS: Final = "http://www.w3.org/2000/svg"
XLINK_NS: Final = "http://www.w3.org/1999/xlink"
_XLINK_HREF: Final = f"{{{XLINK_NS}}}href"

#: The deepest element nesting the served copy may carry. A real drawing nests a few levels; a
#: pathological one would otherwise cost unbounded work, so a document past this is refused.
_MAX_DEPTH: Final = 256
#: The largest SVG the route will sanitize. Parsing and rebuilding cost about a second, and a dozen
#: times the document's size in memory, per 4 MB, so a larger one is refused rather than served raw.
_MAX_SVG_BYTES: Final = 32 * 1024 * 1024
#: The first byte that is not leading noise: the whitespace ``parsing/sniff.py`` strips, plus NUL and
#: the byte-order-mark bytes of UTF-8, UTF-16 and UTF-32, so a UTF-16 or UTF-32 SVG is still seen.
_FIRST_CONTENT_BYTE_RE: Final = re.compile(rb"[^ \t\r\n\x0b\x0c\x00\xef\xbb\xbf\xfe\xff]")
#: An element name after ``<``: every byte up to whitespace, ``/`` or ``>``. Bytes rather than a word
#: class, so a prefix in any encoding compatible with ASCII is taken whole.
_ELEMENT_NAME_RE: Final = re.compile(rb"[^\s/>]*")

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

#: The properties a ``style`` declaration may set. ``transform`` and ``transform-origin`` are left
#: out because their CSS grammar is not the attribute's.
_STYLE_PROPERTIES: Final = _PRESENTATION_ATTRS - {"transform", "transform-origin"}

#: A same-document reference: ``#`` and an XML name, nothing else.
_FRAGMENT_RE: Final = re.compile(r"#[A-Za-z_][\w.:-]*")
#: The functions an allow-listed value may call: colours, transforms, and ``url()`` (fragment only).
_ALLOWED_FUNCTIONS: Final = frozenset(
    {
        "", "url", "rgb", "rgba", "hsl", "hsla", "icc-color", "calc",
        "matrix", "translate", "scale", "rotate", "skewx", "skewy",
    }
)  # fmt: skip
#: A function call; group 1 is its name, and the match ends just after the parenthesis. The
#: look-behind lets a match start only where a name starts, so a long run of name characters with no
#: parenthesis is scanned once, not once per character.
_FUNCTION_RE: Final = re.compile(r"(?<![a-z0-9_-])([a-z0-9_-]*)\(")
#: Substrings no allow-listed attribute value needs. A scheme is refused even outside ``url()``.
_FORBIDDEN_IN_VALUE: Final = ("javascript:", "vbscript:", "data:", "@import")
#: Browsers ignore these inside a URL scheme, so they are removed before the checks.
_IGNORABLE_IN_VALUE_RE: Final = re.compile(r"[\s\x00-\x1f\x7f]+")
_IMPORTANT: Final = "important"


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


def _is_markup(body: bytes) -> bool:
    """Whether the first byte after any leading whitespace, NUL or byte-order mark is ``<``."""
    first = _FIRST_CONTENT_BYTE_RE.search(body)
    return first is not None and first.group() == b"<"


def _skip_declaration(data: bytes, i: int) -> int:
    """The index just past the ``<!...>`` declaration starting at ``i``, or -1 if it never closes.

    Tracks quotes and the internal subset's brackets, and skips comments inside the subset, so a ``>``
    or a quote inside an entity value or a comment does not end the declaration early."""
    depth, quote, j, n = 0, 0, i + 2, len(data)
    while j < n:
        c = data[j]
        if quote:
            if c == quote:
                quote = 0
        elif c in b"\"'":
            quote = c
        elif data.startswith(b"<!--", j):
            end = data.find(b"-->", j + 4)
            if end < 0:
                return -1
            j = end + 3
            continue
        elif c == ord("["):
            depth += 1
        elif c == ord("]"):
            depth -= 1
        elif c == ord(">") and depth <= 0:
            return j + 1
        j += 1
    return -1


def _first_element_name(data: bytes) -> bytes | None:
    """The first element name in ``data`` by a byte scan, or ``None`` if there is none.

    Used only when the parser cannot reach the root. Linear: every step moves forward."""
    i = 0
    while (i := data.find(b"<", i)) >= 0:
        if data.startswith(b"<?", i):
            end = data.find(b"?>", i + 2)
            i = -1 if end < 0 else end + 2
        elif data.startswith(b"<!--", i):
            end = data.find(b"-->", i + 4)
            i = -1 if end < 0 else end + 3
        elif data.startswith(b"<!", i):
            i = _skip_declaration(data, i)
        else:
            match = _ELEMENT_NAME_RE.match(data, i + 1)
            return match.group() if match else b""
        if i < 0:
            return None
    return None


def _root_is_svg(body: bytes) -> bool:
    """Whether the markup ``body`` is an SVG document, reading no further than its root start tag.

    When the parser cannot reach the root, :func:`_first_element_name` answers instead, since a
    browser may still read the document as SVG. That fallback compares case-insensitively."""
    parser = DefusedXMLParser(
        target=_RootTarget(), forbid_dtd=False, forbid_entities=True, forbid_external=True
    )
    try:
        parser.feed(body)
    except _RootFound as found:
        return _split(found.args[0])[1] == "svg"
    except (ParseError, DefusedXmlException, ValueError, LookupError):
        # ValueError and LookupError are pyexpat's answers to an encoding it does not support.
        name = _first_element_name(body.replace(b"\x00", b""))
        return name is not None and name.rpartition(b":")[2].lower() == b"svg"
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
    for call in _FUNCTION_RE.finditer(folded):
        name = call.group(1)
        if name not in _ALLOWED_FUNCTIONS:
            return False
        if name == "url":
            j = call.end()
            while j < len(folded) and folded[j] in "'\"":
                j += 1
            if not folded.startswith("#", j):
                return False
    return True


def _without_important(value: str) -> str:
    """``value`` stripped, less a trailing ``!important``. String operations, not a regex, so a long
    run of whitespace costs one pass."""
    value = value.strip()
    if value.casefold().endswith(_IMPORTANT):
        head = value[: -len(_IMPORTANT)].rstrip()
        if head.endswith("!"):
            return head[:-1].rstrip()
    return value


def _style_attrs(style: str) -> dict[str, str]:
    """The presentation attributes a ``style`` value sets, keeping only allow-listed, safe ones."""
    kept: dict[str, str] = {}
    for declaration in style.split(";"):
        prop, sep, value = declaration.partition(":")
        prop = prop.strip().casefold()
        value = _without_important(value)
        if sep and value and prop in _STYLE_PROPERTIES and _safe_value(value):
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

    Raises :class:`SvgRejected` when ``body`` is larger than :data:`_MAX_SVG_BYTES`, or is not a
    well-formed, entity-free document with an ``svg`` root in the SVG namespace or in none."""
    if len(body) > _MAX_SVG_BYTES:
        raise SvgRejected(f"SVG is larger than {_MAX_SVG_BYTES} bytes")
    # The parser's error can quote sender text (an entity name, a system id, an encoding label), so
    # only its type name is kept and the refusal is raised after the except ends: no caller's log
    # or traceback can reach the original through the chain (BACKLOG #2387, #1796).
    root: Element | None = None
    refused = "no root element"
    try:
        root = _xml_fromstring(body, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException, ValueError, LookupError) as exc:
        refused = type(exc).__name__
    if root is None:
        raise SvgRejected(f"SVG is not a well-formed, entity-free document: {refused}")
    ns, local = _split(root.tag)
    if local != "svg" or ns not in (SVG_NS, ""):
        raise SvgRejected("document root is not an SVG svg element")
    return _serialize(root, ns).encode("utf-8")


def may_be_svg(body: bytes) -> bool:
    """A cheap, non-blocking pre-check: ``False`` means :func:`sanitize_if_svg` would return ``body``
    unchanged whatever its label, so the caller can skip the thread hop for a PDF or an image. Only
    markup can be SVG: no SVG reader renders bytes that do not start with ``<``."""
    return _is_markup(body)


def sanitize_if_svg(label: str | None, body: bytes) -> bytes:
    """``body`` unchanged unless it is SVG, in which case the sanitized copy.

    Raises :class:`SvgRejected` for SVG that cannot be vetted. Blocking work: run it off the event
    loop."""
    if may_be_svg(body) and ("svg" in (label or "").casefold() or _root_is_svg(body)):
        return sanitize_svg(body)
    return body
