# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Sanitize the SERVED copy of an SVG attachment to a tag and attribute allow-list (ASVS 1.3.4).

ADR 0105's 2026-09-28 amendment permits this, and bounds it: the attachment download route may serve
a sanitized copy of an SVG document, while owner ruling 3 still keeps the STORED OBX-5.5 value
verbatim. Nothing here touches the store. The one caller is the download route in ``api/app.py``, which
passes the bytes it has just decoded and serves what this module returns. The ADR amendment is the
record of what this module keeps, drops and refuses; the notes below are about how.

**What counts as SVG.** Markup, meaning bytes whose first non-blank byte is ``<``, that EITHER carries a
label mentioning ``svg`` OR has an ``svg`` root element. The label is sender-influenced, so a check on it
alone would let an SVG labelled ``text/xml`` pass untouched. The root check reads only as far as the
first start tag. When the parser cannot reach the root (an unsupported or false encoding declaration,
an entity in the prolog, a syntax error), the first :data:`_SNIFF_HEAD` bytes are searched for an
``svg`` start tag instead, because a browser may still read that document as SVG. Bytes that are not
markup (a PDF, an image) are never SVG, whatever the label says: no SVG reader renders them. The one
exception is a gzip stream under an SVG label, which a viewer may inflate as SVGZ; it is refused.

**Values are checked for what they may call.** A value may call only the CSS and transform functions on
:data:`_ALLOWED_FUNCTIONS`, and ``url()`` only with a ``#fragment``. So ``image-set()``, ``src()`` and
any function added to CSS later are refused by default rather than by name.

**The ``style`` attribute is translated, never copied.** A declaration survives only when its property
is on :data:`_STYLE_PROPERTIES` and its value passes the same check, and it is written out as that
attribute. Copying CSS through would need a CSS parser to vet it. ``transform`` and
``transform-origin`` are left out because their CSS grammar (units such as ``45deg``) is not the
attribute's.

**Fail closed.** An SVG that is not well-formed, declares an entity, references an external entity,
has no ``svg`` root in the SVG namespace or in none, nests deeper than :data:`_MAX_DEPTH`, or is larger
than :data:`_MAX_SVG_BYTES` raises :class:`SvgRejected`, and the route serves nothing. Serving the
original bytes instead would hand an unvetted SVG to exactly the case the parser could not check: a
browser honours an internal DTD that defusedxml refuses. A ``<!DOCTYPE>`` with no entity declaration is
accepted, since common editors still write the SVG 1.1 one, and the output never carries it.

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
#: The largest SVG the route will sanitize. The work runs on the default thread pool the pipeline's
#: router and transform workers share, and costs a few seconds per 16 MB, so a larger SVG is refused
#: rather than allowed to stall message processing. A clinical drawing is far below this.
_MAX_SVG_BYTES: Final = 8 * 1024 * 1024
#: How far the markup test and the fallback ``svg`` search read into a document.
_SNIFF_HEAD: Final = 64 * 1024
#: Bytes that may precede an XML document's first ``<``: whitespace, and the NULs and byte-order marks
#: of the UTF-8, UTF-16 and UTF-32 encodings the parser detects on its own. Wider than the leading
#: noise ``parsing/sniff.py`` strips, on purpose: that check is about a UTF-8 body's first byte, and
#: this one must not miss a UTF-16 or UTF-32 SVG.
_XML_LEAD: Final = b" \t\r\n\x00\xef\xbb\xbf\xfe\xff"
#: An ``svg`` start tag, bare or prefixed, as the fallback search sees it once NULs are gone.
_SVG_START_TAG_RE: Final = re.compile(rb"<(?:[\w.-]+:)?svg[\s/>]", re.IGNORECASE)
_GZIP_MAGIC: Final = b"\x1f\x8b"

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
#: A function call; group 1 is its name, and the match ends just after the parenthesis.
_FUNCTION_RE: Final = re.compile(r"([a-z0-9_-]*)\(")
#: Substrings no allow-listed attribute value needs. A scheme is refused even outside ``url()``.
_FORBIDDEN_IN_VALUE: Final = ("javascript:", "vbscript:", "data:", "@import")
#: Browsers ignore these inside a URL scheme, so they are removed before the checks.
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


def _label_names_svg(label: str | None) -> bool:
    return "svg" in (label or "").casefold()


def _is_markup(body: bytes) -> bool:
    """Whether the first byte after any whitespace, NUL or byte-order mark is ``<``.

    Reads a bounded head, so a large image is not copied; it reads further only when that head is all
    leading bytes."""
    head = body[:_SNIFF_HEAD].lstrip(_XML_LEAD)
    if head:
        return head.startswith(b"<")
    return len(body) > _SNIFF_HEAD and body.lstrip(_XML_LEAD).startswith(b"<")


def _root_is_svg(body: bytes) -> bool:
    """Whether the markup ``body`` is an SVG document, reading no further than its root start tag.

    When the parser cannot reach the root, the answer comes from a search of the head for an ``svg``
    start tag, since a browser may still read the document as SVG."""
    parser = DefusedXMLParser(
        target=_RootTarget(), forbid_dtd=False, forbid_entities=True, forbid_external=True
    )
    try:
        parser.feed(body)
    except _RootFound as found:
        return _split(found.args[0])[1] == "svg"
    except (ParseError, DefusedXmlException, ValueError, LookupError):
        # ValueError and LookupError are pyexpat's answers to an encoding it does not support.
        return bool(_SVG_START_TAG_RE.search(body[:_SNIFF_HEAD].replace(b"\x00", b"")))
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
        if name == "url" and not folded[call.end() :].lstrip("'\"").startswith("#"):
            return False
    return True


def _style_attrs(style: str) -> dict[str, str]:
    """The presentation attributes a ``style`` value sets, keeping only allow-listed, safe ones."""
    kept: dict[str, str] = {}
    for declaration in style.split(";"):
        prop, sep, value = declaration.partition(":")
        prop = prop.strip().casefold()
        value = _IMPORTANT_RE.sub("", value).strip()
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
    try:
        root = _xml_fromstring(body, forbid_dtd=False, forbid_entities=True, forbid_external=True)
    except (ParseError, DefusedXmlException, ValueError, LookupError) as exc:
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
    if _label_names_svg(label) and body.startswith(_GZIP_MAGIC):
        return True
    return _is_markup(body)


def sanitize_if_svg(label: str | None, body: bytes) -> bytes:
    """``body`` unchanged unless it is SVG, in which case the sanitized copy.

    Raises :class:`SvgRejected` for SVG that cannot be vetted, including SVGZ under an SVG label.
    Blocking work: run it off the event loop."""
    if _label_names_svg(label) and body.startswith(_GZIP_MAGIC):
        raise SvgRejected("compressed SVG (SVGZ) is not sanitized")
    if _is_markup(body) and (_label_names_svg(label) or _root_is_svg(body)):
        return sanitize_svg(body)
    return body
