# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SVG served-copy sanitizer (ASVS 1.3.4, ADR 0105 amendment 2026-09-28, BACKLOG #2299).

Pure-function tests of ``messagefoundry.api.svg_sanitize``. The route-level tests, which pin that the
stored bytes stay verbatim, live in ``tests/test_attachment_download_api.py``.

Each hostile case is paired with a survivor, so a sanitizer that returned an empty ``<svg>`` for every
input would fail here: the drawing tests are the negative control.
"""

from __future__ import annotations

import re
from xml.etree.ElementTree import Element

import pytest
from defusedxml.ElementTree import fromstring

from messagefoundry.api.svg_sanitize import (
    SVG_NS,
    SvgRejected,
    may_be_svg,
    sanitize_if_svg,
    sanitize_svg,
)
from tests.test_xml_parser_consistency import HOSTILE

_DRAWING = (
    b'<?xml version="1.0" encoding="UTF-8"?>\n'
    b'<!DOCTYPE svg PUBLIC "-//W3C//DTD SVG 1.1//EN" '
    b'"http://www.w3.org/Graphics/SVG/1.1/DTD/svg11.dtd">\n'
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
    b'width="120" height="80" viewBox="0 0 120 80">'
    b"<!-- a comment --><title>Synthetic chart</title>"
    b'<defs><linearGradient id="g1"><stop offset="0" stop-color="#fff"/></linearGradient>'
    b'<symbol id="dot"><circle cx="5" cy="5" r="4"/></symbol></defs>'
    b'<g transform="translate(10,10)" style="fill: #336699; stroke:red !important; bogus: 1">'
    b'<rect x="0" y="0" width="50" height="20" fill="url(#g1)"/>'
    b'<path d="M0 30 L50 30"/><use xlink:href="#dot" x="60" y="0"/>'
    b'<text x="0" y="50">Label &amp; value</text></g></svg>'
)

_HOSTILE = (
    b'<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" '
    b'onload="alert(1)">'
    b"<script>alert(2)</script>"
    b'<foreignObject width="10" height="10"><div xmlns="http://www.w3.org/1999/xhtml">'
    b'<iframe src="javascript:alert(3)"/></div></foreignObject>'
    b'<a xlink:href="javascript:alert(4)"><rect width="5" height="5"/></a>'
    b'<use xlink:href="http://evil.example/x.svg#a"/>'
    b'<use href="data:image/svg+xml;base64,PHN2Zz4="/>'
    b'<image href="http://evil.example/track.png"/>'
    b'<rect width="1" height="1" onclick="alert(5)" fill="url(http://evil.example/f)"'
    b' stroke="java&#9;script:alert(6)" style="fill:url(//evil.example/x)"/>'
    b"<style>@import url(http://evil.example/s.css);</style>"
    b'<set attributeName="href" to="javascript:alert(7)"/>'
    b'<animate attributeName="onload" values="alert(8)"/>'
    b'<circle cx="1" cy="1" r="1" fill="\\75 rl(x)"/>'
    b'<?xml-stylesheet href="http://evil.example/s.css"?>'
    b"</svg>"
)


def _tree(data: bytes) -> Element:
    root: Element = fromstring(data, forbid_dtd=True, forbid_entities=True, forbid_external=True)
    return root


def _all_attrs(data: bytes) -> list[tuple[str, str, str]]:
    return [(el.tag, k, v) for el in _tree(data).iter() for k, v in el.attrib.items()]


def test_hostile_svg_loses_every_active_part() -> None:
    out = sanitize_svg(_HOSTILE)
    text = out.decode("utf-8").casefold()
    for needle in (
        "script",
        "foreignobject",
        "onload",
        "onclick",
        "iframe",
        "evil.example",
        "data:",
        "alert",
        "<a",
        "<image",
        "<style",
        "<set",
        "<animate",
        "xml-stylesheet",
        "\\",
    ):
        assert needle not in text, needle
    # The harmless rect still survives, stripped of its hostile attributes.
    tags = [el.tag for el in _tree(out).iter()]
    assert f"{{{SVG_NS}}}rect" in tags
    assert f"{{{SVG_NS}}}circle" in tags


def test_plain_drawing_keeps_its_shapes_text_and_internal_references() -> None:
    out = sanitize_svg(_DRAWING)
    root = _tree(out)
    tags = {el.tag.rpartition("}")[2] for el in root.iter()}
    expected = {"svg", "title", "defs", "linearGradient", "stop", "symbol", "circle", "g", "rect"}
    assert expected | {"path", "use", "text"} <= tags
    assert root.get("viewBox") == "0 0 120 80"
    attrs = _all_attrs(out)
    assert (f"{{{SVG_NS}}}rect", "fill", "url(#g1)") in attrs
    assert (f"{{{SVG_NS}}}use", "{http://www.w3.org/1999/xlink}href", "#dot") in attrs
    # style is translated into presentation attributes, dropping unknown properties and !important.
    g = next(el for el in root.iter() if el.tag == f"{{{SVG_NS}}}g")
    assert g.get("fill") == "#336699"
    assert g.get("stroke") == "red"
    assert g.get("style") is None and g.get("bogus") is None
    assert next(el for el in root.iter() if el.tag.endswith("text")).text == "Label & value"
    # The DOCTYPE and the comment are gone.
    assert b"DOCTYPE" not in out and b"comment" not in out


def test_sanitizing_is_idempotent() -> None:
    once = sanitize_svg(_DRAWING)
    assert sanitize_svg(once) == once


def test_unnamespaced_svg_root_is_accepted_and_given_the_svg_namespace() -> None:
    out = sanitize_svg(b'<svg width="2"><rect width="1"/><svg:rect xmlns:svg="urn:x"/></svg>')
    root = _tree(out)
    assert root.tag == f"{{{SVG_NS}}}svg"
    assert [el.tag for el in root] == [f"{{{SVG_NS}}}rect"]


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"<svg><rect></svg>", id="not-well-formed"),
        pytest.param(b"", id="empty"),
        pytest.param(b"synthetic text, not markup", id="not-xml"),
        pytest.param(b'<html xmlns="http://www.w3.org/1999/xhtml"/>', id="wrong-root"),
        pytest.param(b'<svg xmlns="urn:not-svg"/>', id="wrong-namespace"),
        pytest.param(
            b'<?xml version="1.0"?><!DOCTYPE svg [<!ENTITY a "aaaaaaaaaa">'
            b'<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
            b'<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">]>'
            b'<svg xmlns="http://www.w3.org/2000/svg"><text>&c;</text></svg>',
            id="entity-bomb",
        ),
        pytest.param(
            b'<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
            b'<svg xmlns="http://www.w3.org/2000/svg"><text>&x;</text></svg>',
            id="external-entity",
        ),
        pytest.param(
            b'<svg xmlns="http://www.w3.org/2000/svg">' + b"<g>" * 300 + b"</g>" * 300 + b"</svg>",
            id="too-deep",
        ),
    ],
)
def test_svg_that_cannot_be_vetted_is_rejected(data: bytes) -> None:
    with pytest.raises(SvgRejected):
        sanitize_svg(data)


def test_dtd_default_attributes_are_filtered_like_written_ones() -> None:
    # A DOCTYPE with no entity is accepted, but expat applies ATTLIST defaults to the tree; the
    # attribute allow-list must see them, or an onload could arrive through the DTD.
    out = sanitize_svg(
        b'<!DOCTYPE svg [<!ATTLIST svg onload CDATA "alert(1)">]>'
        b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1"/></svg>'
    )
    assert b"onload" not in out and b"alert" not in out
    assert b"<rect" in out


@pytest.mark.parametrize("label", ["image/svg+xml", "Image/SVG+XML", "image/svg", "text/x-svg"])
def test_a_label_naming_svg_triggers_the_sanitizer(label: str) -> None:
    assert b"script" not in sanitize_if_svg(label, _HOSTILE)
    with pytest.raises(SvgRejected):
        sanitize_if_svg(label, b"synthetic text, not markup")


@pytest.mark.parametrize("label", ["text/xml", "text/plain", "application/octet-stream", None])
def test_an_svg_root_triggers_the_sanitizer_whatever_the_label(label: str | None) -> None:
    assert b"script" not in sanitize_if_svg(label, _HOSTILE)
    assert b"script" not in sanitize_if_svg(label, _HOSTILE.decode().encode("utf-16"))


def test_a_prolog_entity_counts_as_svg_and_is_refused() -> None:
    with pytest.raises(SvgRejected):
        sanitize_if_svg("text/xml", b'<!DOCTYPE d [<!ENTITY a "b">]><doc>&a;</doc>')


@pytest.mark.parametrize(
    ("label", "data"),
    [
        ("application/pdf", b"%PDF-1.4\nsynthetic document <svg onload=x>\n%%EOF\n"),
        ("image/png", bytes.fromhex("89504e470d0a1a0a") + b"<svg/>"),
        ("text/plain", b"synthetic note mentioning <svg> in passing"),
        ("text/xml", b'<?xml version="1.0"?><ClinicalDocument><svg/></ClinicalDocument>'),
        ("application/json", b'{"svg": "<svg onload=x>"}'),
        ("text/plain", b""),
    ],
)
def test_non_svg_documents_are_returned_unchanged(label: str, data: bytes) -> None:
    assert sanitize_if_svg(label, data) is data


@pytest.mark.parametrize(
    ("label", "data", "expected"),
    [
        ("application/pdf", b"%PDF-1.4 <svg>", False),
        ("image/png", bytes.fromhex("89504e470d0a1a0a"), False),
        ("text/plain", b"", False),
        ("image/svg+xml", b"%PDF-1.4", True),
        ("text/xml", b"  <svg/>", True),
        ("text/xml", b"\xef\xbb\xbf<svg/>", True),
        ("text/xml", "<svg/>".encode("utf-16-be"), True),
        ("text/xml", "<svg/>".encode("utf-16"), True),
    ],
)
def test_the_pre_check_misses_no_markup_and_clears_binaries(
    label: str, data: bytes, expected: bool
) -> None:
    """``may_be_svg`` only lets the route skip the thread hop, so a ``False`` must never hide an SVG."""
    assert may_be_svg(label, data) is expected
    if not expected:
        assert sanitize_if_svg(label, data) is data


#: ASVS 1.5.3's shared hostile corpus (``tests/test_xml_parser_consistency.py``), with each document's
#: root renamed to ``svg`` so the sanitizer's root check cannot be what refuses it.
_HOSTILE_AS_SVG = {
    name: re.sub(r"(<!DOCTYPE |</?)(r|lolz)\b", r"\1svg", doc).encode("utf-8")
    for name, doc in HOSTILE.items()
}

#: The one corpus entry the sanitizer accepts, and why. Its DOCTYPE names an external DTD that expat
#: never fetches, and the output drops the DOCTYPE, so nothing it names can reach the served copy.
#: Common editors still write the SVG 1.1 DOCTYPE, which has this shape. Recorded here rather than
#: filtered out, so a change in the verdict is seen.
_ACCEPTED_BY_DESIGN = {"external-dtd-http"}


@pytest.mark.parametrize("name", sorted(_HOSTILE_AS_SVG))
def test_the_shared_hostile_xml_corpus_is_refused(name: str) -> None:
    document = _HOSTILE_AS_SVG[name]
    assert b"<svg" in document
    if name in _ACCEPTED_BY_DESIGN:
        out = sanitize_svg(document)
        assert b"DOCTYPE" not in out and b"203.0.113.10" not in out
    else:
        with pytest.raises(SvgRejected):
            sanitize_svg(document)
