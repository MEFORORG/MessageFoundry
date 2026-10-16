# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The SVG served-copy sanitizer (ASVS 1.3.4, ADR 0105 amendment 2026-09-28, BACKLOG #2299).

Pure-function tests of ``messagefoundry.api.svg_sanitize``. The route-level tests, which pin that the
stored bytes stay verbatim, live in ``tests/test_attachment_download_api.py``.

Each hostile case is paired with a survivor, so a sanitizer that returned an empty ``<svg>`` for every
input would fail here: the drawing tests are the negative control.
"""

from __future__ import annotations

import gzip
import re
import time
import zlib
from typing import Any
from xml.etree.ElementTree import Element

import pytest

from messagefoundry._vendor.defusedxml.ElementTree import fromstring
from messagefoundry.api import svg_sanitize
from messagefoundry.api.svg_sanitize import (
    SVG_NS,
    SvgRejected,
    may_be_svg,
    sanitize_if_svg,
    sanitize_svg,
)
from messagefoundry.parsing._bounded_inflate import bounded_inflate
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
        sanitize_if_svg(label, b"<svg><rect></svg>")


def test_an_svg_label_on_bytes_that_are_not_markup_changes_nothing() -> None:
    # Bytes that do not start with '<' and hold no svg start tag are not an SVG, so a mislabelled PDF
    # is left to the declared-type downgrade rather than refused.
    pdf = b"%PDF-1.4\nsynthetic document\n%%EOF\n"
    assert sanitize_if_svg("image/svg+xml", pdf) is pdf


def test_a_gzip_body_that_is_not_gzip_inside_is_refused() -> None:
    # The gzip magic and junk. zlib keeps no output from a call that raises, so nothing can be judged,
    # and a corrupt gzip is never served (BACKLOG #2391, the Lander's hold on PR 2158).
    gz = bytes.fromhex("1f8b0800") + b"synthetic"
    with pytest.raises(SvgRejected):
        sanitize_if_svg("image/svg+xml", gz)


# --- BACKLOG #2391: SVGZ ---------------------------------------------------------------------------


def _gz(data: bytes) -> bytes:
    return gzip.compress(data, mtime=0)


def _flip(data: bytes, at: int) -> bytes:
    """``data`` with the byte at ``at`` inverted."""
    out = bytearray(data)
    out[at] ^= 0xFF
    return bytes(out)


def test_the_corrupt_gzip_probes_really_fail_in_zlib() -> None:
    """Control for the refusal cases: each damaged body makes zlib raise, so the refusal is not
    vacuous, and the undamaged one inflates."""
    assert gzip.decompress(_gz(_HOSTILE)) == _HOSTILE
    for damaged in (_flip(_gz(_HOSTILE), -8), _flip(_gz(_HOSTILE), -1), _flip(_gz(_HOSTILE), 12)):
        with pytest.raises((OSError, EOFError, zlib.error)):
            gzip.decompress(damaged)


def test_damage_past_a_cleared_head_is_not_read() -> None:
    """The recorded trade, changed on purpose by BACKLOG #3257. A head whose first byte is not ``<``
    and which holds no ``svg`` start tag clears the body without reading the rest, so a large
    non-markup gzip damaged near its end is served as stored, and so is an ``svg`` tag past the
    head. What the head scan does not reach rests on the route's content-type allow-list. A tag
    inside the head is refused, damage or not: the docstring this replaces said a document whose
    first byte is not ``<`` could hide no SVG, and a browser reading it as HTML would show one."""
    filler = bytes(range(256)) * 2048
    body = _flip(_gz(b"%PDF-1.4 " + filler), -8)
    assert sanitize_if_svg("application/gzip", body) is body
    past_the_head = _flip(_gz(b"%PDF-1.4 " + filler + b"<svg onload=alert(1)>"), -8)
    assert sanitize_if_svg("application/gzip", past_the_head) is past_the_head
    with pytest.raises(SvgRejected, match="svg start tag"):
        sanitize_if_svg("application/gzip", _flip(_gz(b"%PDF-1.4 <svg onload=x>" + filler), -8))


@pytest.mark.parametrize(
    "label", ["image/svg+xml", "application/octet-stream", "application/gzip", None]
)
def test_svgz_is_inflated_sanitized_and_gzipped_again(label: str | None) -> None:
    """Ingress relabels gzip bytes under a ``+xml`` label, but the bytes stay gzip, so the label is not
    what decides. The root of the inflated document is."""
    out = sanitize_if_svg(label, _gz(_HOSTILE))
    assert out.startswith(b"\x1f\x8b")
    inner = gzip.decompress(out)
    assert inner == sanitize_svg(_HOSTILE)
    assert b"script" not in inner and b"<rect" in inner
    # mtime=0 makes the served copy a function of the document alone.
    assert sanitize_if_svg(label, _gz(_HOSTILE)) == out


@pytest.mark.parametrize(
    "inner",
    [
        pytest.param(b"%PDF-1.4\nsynthetic\n%%EOF\n", id="not-markup"),
        pytest.param(b'<?xml version="1.0"?><ClinicalDocument/>', id="markup-without-svg"),
        pytest.param(b"", id="empty"),
        pytest.param(_gz(_HOSTILE), id="gzip-in-gzip"),
    ],
)
def test_gzip_that_does_not_inflate_to_svg_is_unchanged(inner: bytes) -> None:
    """The control. A doubly-gzipped SVG is left alone: no SVG reader inflates twice."""
    body = _gz(inner)
    assert sanitize_if_svg("application/gzip", body) is body


@pytest.mark.parametrize(
    "body",
    [
        pytest.param(_gz(b"<svg><rect></svg>"), id="malformed-svg"),
        pytest.param(
            _gz(b'<html xmlns="http://www.w3.org/1999/xhtml"><svg/></html>'), id="embedded"
        ),
        pytest.param(_gz(_HOSTILE)[:-12], id="truncated"),
        pytest.param(_gz(_HOSTILE) + b"synthetic trailing junk", id="trailing-junk"),
        pytest.param(
            b"".join([_gz(b"<svg>")] + [_gz(b"<g/>")] * 16 + [_gz(b"</svg>")]), id="members"
        ),
        pytest.param(
            _gz(b" " * (33 * 1024 * 1024) + b'<svg onload="x"/>'), id="whitespace-past-the-bound"
        ),
        pytest.param(_flip(_gz(_HOSTILE), -8), id="bad-crc"),
        pytest.param(_flip(_gz(_HOSTILE), -1), id="bad-isize"),
        pytest.param(b"\x1f\x8b" + b"synthetic junk after the magic", id="junk-after-the-magic"),
        pytest.param(_flip(_gz(_HOSTILE), 12), id="corrupt-first-block"),
        pytest.param(
            _gz(b"<svg>") + _flip(_gz(b'<g onload="x"/></svg>'), -8), id="corrupt-later-member"
        ),
        pytest.param(_gz(b"<svg>") + b"\x00\x00" + _gz(b"</svg>"), id="nul-between-members"),
        pytest.param(_flip(_gz(b"%PDF-1.4 synthetic"), -8), id="bad-crc-on-a-non-svg-body"),
        pytest.param(bytes.fromhex("1f8b08"), id="header-cut-short"),
    ],
)
def test_gzip_markup_that_cannot_be_vetted_is_refused(body: bytes) -> None:
    with pytest.raises(SvgRejected):
        sanitize_if_svg("application/gzip", body)


def test_a_multi_member_svgz_is_vetted_as_one_document() -> None:
    """A gzip reader concatenates members, so a script split into a second member is still seen."""
    body = _gz(b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1"/>') + _gz(
        b"<script>alert(1)</script></svg>"
    )
    inner = gzip.decompress(sanitize_if_svg(None, body))
    assert b"script" not in inner and b"<rect" in inner
    # Trailing NUL padding, which some writers add, is not junk.
    assert gzip.decompress(sanitize_if_svg(None, body + b"\x00" * 64)) == inner


def test_a_gzip_bomb_is_bounded() -> None:
    """The inflate stops at the size bound, so a small body cannot cost gigabytes. Markup over the
    bound is refused; anything else over it is served as stored."""
    svg_bomb = _gz(b"<svg>" + b" " * (40 * 1024 * 1024))
    text_bomb = _gz(b"A" * (40 * 1024 * 1024))
    assert len(svg_bomb) < 100_000 and len(text_bomb) < 100_000
    started = time.perf_counter()
    with pytest.raises(SvgRejected):
        sanitize_if_svg("image/svg+xml", svg_bomb)
    assert sanitize_if_svg("image/svg+xml", text_bomb) is text_bomb
    assert time.perf_counter() - started < 10


def _spy_on_inflate(monkeypatch: pytest.MonkeyPatch) -> list[tuple[bool, int | None]]:
    """Record ``(keep_output, max_output_bytes)`` for each call the sanitizer makes to the shared
    inflate loop, in order, and let the call through."""
    calls: list[tuple[bool, int | None]] = []

    def spy(*args: Any, **kwargs: Any) -> Any:
        calls.append((kwargs["keep_output"], kwargs["max_output_bytes"]))
        return bounded_inflate(*args, **kwargs)

    monkeypatch.setattr(svg_sanitize, "bounded_inflate", spy)
    return calls


def test_svgz_over_the_bound_is_refused_before_any_output_is_kept(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """BACKLOG #1129. A trial pass that keeps nothing refuses markup over the bound, so the pass
    that keeps the document never runs for it. The ceiling it ran under is the bound."""
    calls = _spy_on_inflate(monkeypatch)
    with pytest.raises(SvgRejected, match="larger than the bound"):
        sanitize_if_svg("image/svg+xml", _gz(b"<svg>" + b" " * (40 * 1024 * 1024)))
    assert calls, "the sanitizer no longer inflates through the shared loop"
    assert not any(keep for keep, _ in calls)
    assert calls[-1] == (False, svg_sanitize._MAX_SVG_BYTES)


def test_svgz_at_the_bound_renders_and_one_over_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """The control for the refusal above: an SVGZ that inflates to exactly the bound is still
    sanitized and served, after a trial pass at the bound. The bounds are shrunk so the document is
    cheap to sanitize; the head stays smaller than the bound, as it is in production."""
    monkeypatch.setattr(svg_sanitize, "_GZIP_SNIFF_BYTES", 1024)
    monkeypatch.setattr(svg_sanitize, "_MAX_SVG_BYTES", 4096)
    head, tail = b'<svg xmlns="http://www.w3.org/2000/svg"><rect width="1"/>', b"</svg>"
    at_bound = head + b" " * (4096 - len(head) - len(tail)) + tail
    assert len(at_bound) == 4096
    calls = _spy_on_inflate(monkeypatch)
    out = sanitize_if_svg(None, _gz(at_bound))
    assert b"<rect" in gzip.decompress(out)
    assert calls == [(False, 1024), (False, 4096), (True, 4096)]

    calls.clear()
    with pytest.raises(SvgRejected, match="larger than the bound"):
        sanitize_if_svg(None, _gz(at_bound + b" "))
    assert calls == [(False, 1024), (False, 4096)]


def test_a_large_body_whose_head_is_only_noise_is_cleared_by_its_first_content_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The trial pass keeps no output, yet still sees the first byte past leading noise. A body that
    passes the bound but starts, past that noise, with a byte other than ``<`` is not markup and is
    served as stored, as it was before the trial pass, unless the head past that noise holds an
    ``svg`` start tag. Changed on purpose by BACKLOG #3257: the noise does not use up the head, so
    padding cannot push the tag out of the scan's reach."""
    monkeypatch.setattr(svg_sanitize, "_GZIP_SNIFF_BYTES", 1024)
    monkeypatch.setattr(svg_sanitize, "_MAX_SVG_BYTES", 4096)
    body = _gz(b" " * 2048 + b"%PDF-1.4 synthetic" + b"A" * 8192)
    assert sanitize_if_svg("application/gzip", body) is body
    tagged = _gz(b" " * 2048 + b"%PDF-1.4 synthetic <svg onload=x>" + b"A" * 8192)
    with pytest.raises(SvgRejected, match="svg start tag"):
        sanitize_if_svg("application/gzip", tagged)


# --- BACKLOG #2391: SVG below a root that is not svg -----------------------------------------------

_XHTML = b'<html xmlns="http://www.w3.org/1999/xhtml"><body>'
#: ``ESC ( B`` decodes to nothing in ISO-2022-JP, so a browser and Python's codec both read
#: ``<s ESC ( B vg`` as ``<svg``, while no byte scan sees the name.
_ISO2022_SVG = (
    b'<?xml version="1.0" encoding="ISO-2022-JP"?><s\x1b(Bvg xmlns="http://www.w3.org/2000/s\x1b(Bvg">'
    b"<script>alert(1)</script></s\x1b(Bvg>"
)


def test_the_iso_2022_jp_probe_really_decodes_to_svg() -> None:
    """Control for the refusal cases below: the bytes are an SVG once decoded."""
    assert "<svg" in _ISO2022_SVG.decode("iso2022_jp")
    assert b"<svg" not in _ISO2022_SVG


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(_XHTML + b'<svg xmlns="http://www.w3.org/2000/svg" onload="x"/></body></html>',
                     id="xhtml-inline-svg"),
        pytest.param(_XHTML + b"<svg/></body></html>", id="svg-named-in-the-xhtml-namespace"),
        pytest.param(b'<doc xmlns:s="http://www.w3.org/2000/svg"><s:script>x</s:script></doc>',
                     id="svg-namespace-without-an-svg-element"),
        pytest.param(b'<?xml version="1.0"?><ClinicalDocument><svg/></ClinicalDocument>', id="cda"),
        pytest.param(b"<html><body><svg onload=x></svg></body></html>", id="html"),
        pytest.param(b"<html><body><SVG onload=x></SVG><br></body></html>", id="html-upper-case"),
        pytest.param(b"<html><p><x:svg/><br></html>", id="html-prefixed"),
        pytest.param((_XHTML + b"<svg/></body></html>").decode().encode("utf-16"), id="utf-16"),
        pytest.param(b'<?xml version="1.0" encoding="Shift_JIS"?><doc><svg/></doc>',
                     id="unsupported-encoding"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY e "&#60;&#115;vg onload=\'x\'/>">]><doc>&e;</doc>',
                     id="entity-built-from-character-references"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY e "&#x3C;&#115;vg/>">]><doc>&e;</doc>',
                     id="entity-built-from-hex-references"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY e "<&#115;vg/>">]><doc>&e;</doc>',
                     id="entity-with-a-referenced-element-name"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY e "<svg/>">]><doc>&e;</doc>', id="entity-literal"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY n "x">]>'
                     b'<doc xmlns:s="&#104;ttp://www.w3.org/2000/svg"><s:rect/></doc>',
                     id="namespace-from-a-reference"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY a "<x:script xmlns:x=&#34;http://www.w3.org/2000/'
                     b'sv&#103;&#34;>x</x:script>">]>' + _XHTML + b"&a;</body></html>",
                     id="entity-with-a-quote-written-as-a-reference"),
        pytest.param(_XHTML + b'&nbsp;<x:script xmlns:x="http://www.w3.org/2000/sv&#103;"/>'
                     b"</body></html>", id="referenced-namespace-after-a-parse-error"),
        pytest.param(b'<!DOCTYPE h [<!ENTITY a "<x:script xmln&#115;:x=&#34;http://www.w3.org/2000/'
                     b'sv&#103;&#34;>x</x:script>">]>' + _XHTML + b"&a;</body></html>",
                     id="entity-with-a-referenced-xmlns-name"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY % p "x"><!ENTITY e "y">]><doc>&e;</doc>',
                     id="parameter-entity"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY e "&#38;#60;svg/>">]><doc>&e;</doc>',
                     id="entity-yielding-an-ampersand"),
        pytest.param(b"<html><body><!-- <svg onload=x> --><br></body></html>",
                     id="html-svg-in-a-comment-errs-toward-refusal"),
        pytest.param(_ISO2022_SVG, id="iso-2022-jp-svg-root"),
        pytest.param(b'<?xml version="1.0" encoding="ISO-2022-JP"?><r><s\x1b(Bvg xmlns="http://'
                     b'www.w3.org/2000/s\x1b(Bvg"><script>alert(1)</script></s\x1b(Bvg></r>',
                     id="iso-2022-jp-svg-below-another-root"),
        pytest.param(b'<!DOCTYPE r [<!ENTITY n "http&#58;//www.w3.org/2000/svg">'
                     b'<!ATTLIST script xmlns CDATA #FIXED "&n;">]><r><script>alert(1)</script></r>',
                     id="attlist-default-namespace-through-an-entity"),
        pytest.param(b'<?xml version="1.0" encoding="Shift_JIS"?><!DOCTYPE r [<!ATTLIST script xmlns'
                     b' CDATA #FIXED "http&#58;//www.w3.org/2000/svg">]><r><script>alert(1)</script></r>',
                     id="attlist-default-namespace-under-an-unsupported-encoding"),
        pytest.param(b"<html><body><!--><svg onload=alert(1)>--></body></html>",
                     id="html-empty-comment"),
        pytest.param(b"<html><body><![CDATA[><svg onload=alert(1)>]]></body></html>",
                     id="html-cdata"),
        pytest.param(b"<html><body><?x ><svg onload=alert(1)>?></body></html>",
                     id="html-processing-instruction"),
        pytest.param(b'<!DOCTYPE html SYSTEM "x><svg onload=alert(1)>"><html/>',
                     id="html-doctype-literal"),
    ],
)  # fmt: skip
def test_markup_carrying_svg_below_another_root_is_refused(data: bytes) -> None:
    """BACKLOG #2391. The parser decides where it can read the document; a byte scan decides where it
    cannot, and leans toward refusal. An entity is never expanded to find out."""
    assert may_be_svg(data)
    with pytest.raises(SvgRejected):
        sanitize_if_svg("application/xml", data)


@pytest.mark.parametrize(
    "data",
    [
        _XHTML + b"<p>a chart in svg format</p></body></html>",
        b"<doc>&lt;svg onload=x&gt;</doc>",
        b'<doc note="&lt;svg"/>',
        b"<html><body><p>systolic &#60; 120</p><br></body></html>",
        b'<!DOCTYPE d [<!ENTITY nbsp "&#160;">]><doc>a&nbsp;b</doc>',
        b"<doc><svgish/><x:svgs xmlns:x='urn:x'/></doc>",
        b"<html><body><code>xmlns=&quot;urn:x&quot;</code><br></body></html>",
        b"<!DOCTYPE d [<!ENTITY nbsp '&#160;'><!ENTITY co 'Synthetic &#169; Org'>]><doc>&co;</doc>",
        b'<html xmlns="http://www.w3.org/1999/xhtml" xmlns:svg="http://www.w3.org/2000/svg">'
        b"<body><p>report</p></body></html>",
        b"<html><body><p>see http://www.w3.org/2000/svg spec</p></body></html>",
        b'<doc xmlns:a="urn:x&#58;y"><a:note/></doc>',
    ],
)
def test_markup_without_svg_is_unchanged(data: bytes) -> None:
    """The control: text that names SVG, escaped markup, a ``&#60;`` in an HTML report, a text-only
    entity and element names that only start with ``svg`` are all served as stored."""
    assert sanitize_if_svg("application/xml", data) is data


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b"<html>" + b"<" * 400_000, id="many-angle-brackets"),
        pytest.param(b"<html><a" + b"b" * 400_000, id="long-name-no-colon"),
        pytest.param(b'<!ENTITY x "y"><html xmlns="' + b"a" * 400_000, id="long-xmlns-value"),
        pytest.param(b"<!ENTITY " * 50_000 + b"<html><x" + b":" * 400_000, id="many-colons"),
        pytest.param(b'<!ENTITY x "y"><html ' + b"xmlns" * 80_000, id="many-xmlns"),
        pytest.param(b'<!ENTITY x "y"><html ' + b"xmlns:" * 80_000, id="many-prefixed-xmlns"),
        pytest.param(b"<html " + b'xmlns="' * 80_000, id="many-quoted-xmlns"),
    ],
)
def test_the_embedded_svg_scan_is_linear(data: bytes) -> None:
    """The ``xmlns`` cases took minutes once: each match ran across every ``xmlns`` after it."""
    started = time.perf_counter()
    assert sanitize_if_svg("text/html", data) is data
    assert time.perf_counter() - started < 10


@pytest.mark.parametrize("compress", [False, True], ids=["plain", "gzip"])
def test_a_long_declaration_is_skipped_by_the_regex_engine(
    compress: bool, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The declaration scan stepped byte by byte in Python once. Through gzip this 32 KB body took
    4.7 s of CPU per download; it is now skipped between tokens in one regex search."""
    doc = b'<!DOCTYPE r [<!ENTITY a "x"> ' + b"a" * (32 * 1024 * 1024 - 100)
    body = gzip.compress(doc, mtime=0) if compress else doc
    steps: list[int] = []
    real = svg_sanitize._ScanBudget.spend

    def counting(self: svg_sanitize._ScanBudget) -> None:
        steps.append(1)
        real(self)

    monkeypatch.setattr(svg_sanitize._ScanBudget, "spend", counting)
    started = time.perf_counter()
    assert sanitize_if_svg("application/xml", body) is body
    # The steady assertion: a handful of tokens, not one step per byte. The clock is a loose backstop
    # (about 1 s here, against 5 s or more for the old loop).
    assert 0 < len(steps) < 20
    assert time.perf_counter() - started < 20


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b'<?xml version="1.0"?><ClinicalDocument><title>synthetic</title>'
                     b"</ClinicalDocument>", id="cda"),
        pytest.param(b"<html><body><p>a&nbsp;b</p><br></body></html>", id="html-nbsp"),
        pytest.param(b'<!DOCTYPE d [<!ENTITY nbsp "&#160;">]><doc>a&nbsp;b</doc>', id="entity-160"),
        pytest.param('<?xml version="1.0" encoding="Shift_JIS"?><doc>日本</doc>'.encode(
                     "shift_jis"), id="shift-jis-without-escape"),
        pytest.param(b'<?xml version="1.0" encoding="x-bogus"?><doc>synthetic</doc>', id="x-bogus"),
    ],
)  # fmt: skip
def test_ordinary_documents_on_both_paths_are_unchanged(data: bytes) -> None:
    """The no-false-refusal controls for the fail-closed fallback, pinned together."""
    assert sanitize_if_svg("application/xml", data) is data


def test_an_iso_2022_jp_document_is_refused_even_without_svg() -> None:
    """The recorded trade. pyexpat cannot read ISO-2022-JP, so it always reaches the byte scan, and
    Japanese text in it always carries the escape byte. It is refused rather than decoded."""
    doc = '<?xml version="1.0" encoding="ISO-2022-JP"?><r>日本</r>'.encode("iso2022_jp")
    assert b"\x1b" in doc
    with pytest.raises(SvgRejected):
        sanitize_if_svg("application/xml", doc)


def test_a_root_scan_that_runs_out_of_steps_is_refused() -> None:
    """Each bracket costs one step. Past the budget the root is unknown, so the document is treated
    as SVG and refused, never served unread."""
    doc = b'<!DOCTYPE r [<!ENTITY a "x">' + b"[]" * 200_000 + b"]><r/>"
    started = time.perf_counter()
    with pytest.raises(SvgRejected):
        sanitize_if_svg("application/xml", doc)
    assert time.perf_counter() - started < 3


@pytest.mark.parametrize("label", ["text/xml", "text/plain", "application/octet-stream", None])
def test_an_svg_root_triggers_the_sanitizer_whatever_the_label(label: str | None) -> None:
    assert b"script" not in sanitize_if_svg(label, _HOSTILE)
    assert b"script" not in sanitize_if_svg(label, _HOSTILE.decode().encode("utf-16"))


_SVG_ROOT = b'<svg xmlns="http://www.w3.org/2000/svg" onload="alert(1)"/>'
_PAD = b"A" * (70 * 1024)


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b'<!DOCTYPE d [<!ENTITY a "b">]>' + _SVG_ROOT, id="entity-in-the-prolog"),
        pytest.param(
            b'<?xml version="1.0" encoding="UTF-16"?>' + _SVG_ROOT, id="false-encoding-declaration"
        ),
        pytest.param(
            b'<?xml version="1.0" encoding="Shift_JIS"?>' + _SVG_ROOT, id="unsupported-encoding"
        ),
        pytest.param(
            b'<!DOCTYPE svg [<!ENTITY p "' + _PAD + b'">]>' + _SVG_ROOT, id="entity-padded-past-64k"
        ),
        pytest.param(
            b'<?xml version="1.0" encoding="Shift_JIS"?><!--' + _PAD + b"-->" + _SVG_ROOT,
            id="comment-padded-past-64k",
        ),
        pytest.param(
            b'<?xml version="1.0" encoding="Shift_JIS"?><!-- <html> -->' + _SVG_ROOT,
            id="decoy-element-in-a-comment",
        ),
        pytest.param(
            b"<!DOCTYPE s [<!ENTITY a \"it's > here\"><!-- don't -->]>" + _SVG_ROOT,
            id="quote-and-gt-inside-the-subset",
        ),
        pytest.param(
            '<!DOCTYPE s [<!ENTITY a "b">]><é:svg xmlns:é="http://www.w3.org/2000/svg"/>'.encode(),
            id="non-ascii-prefix",
        ),
    ],
)
def test_an_svg_whose_root_the_parser_cannot_reach_is_refused(data: bytes) -> None:
    """The byte scan finds the ``svg`` root a browser would still read, so the document is sanitized,
    and fails closed, rather than served untouched."""
    with pytest.raises(SvgRejected):
        sanitize_if_svg("text/xml", data)


@pytest.mark.parametrize(
    "data",
    [
        b'<!DOCTYPE d [<!ENTITY nbsp "&#160;">]><doc>a&nbsp;b</doc>',
        b'<?xml version="1.0" encoding="Shift_JIS"?><doc>synthetic</doc>',
        b'<?xml version="1.0" encoding="x-bogus"?><doc>synthetic</doc>',
        b'<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01 Transitional//EN">'
        b"<html lang=en><body><p>synthetic</p></body></html>",
    ],
)
def test_non_svg_markup_whose_root_the_parser_cannot_reach_is_unchanged(data: bytes) -> None:
    """An HTML page that EMBEDS an ``<svg>`` used to be here. Since BACKLOG #2391 it is refused; see
    ``test_markup_carrying_svg_below_another_root_is_refused``."""
    assert sanitize_if_svg("application/xml", data) is data


@pytest.mark.parametrize(
    ("markup", "survives"),
    [
        (b'<rect fill="rgb(1,2,3)"/>', b'fill="rgb(1,2,3)"'),
        (b"<rect fill=\"url( '#g' )\"/>", b"fill=\"url( '#g' )\""),
        (
            b'<rect transform="rotate(45) translate(1,2)"/>',
            b'transform="rotate(45) translate(1,2)"',
        ),
        (b'<rect style="fill: red ! IMPORTANT"/>', b'fill="red"'),
        (b"<rect mask=\"image-set('https://evil.example/t.png' 1x)\"/>", None),
        (b"<rect fill=\"src('https://evil.example/x')\"/>", None),
        (b'<rect fill="url(https://evil.example/x#a)"/>', None),
        (b'<rect fill="expression(alert(1))"/>', None),
        (b'<g transform="translate(1,1)" style="transform: rotate(45deg)"/>', b"translate(1,1)"),
    ],
)
def test_attribute_values_may_call_only_allow_listed_functions(
    markup: bytes, survives: bytes | None
) -> None:
    out = sanitize_svg(b'<svg xmlns="http://www.w3.org/2000/svg">' + markup + b"</svg>")
    assert b"evil.example" not in out and b"expression" not in out and b"deg" not in out
    if survives is not None:
        assert survives in out


@pytest.mark.parametrize(
    "markup",
    [
        pytest.param(b'<rect fill="' + b"a" * 400_000 + b':"/>', id="name-run-no-paren"),
        pytest.param(b'<rect style="fill:a' + b" " * 400_000 + b'b"/>', id="whitespace-run"),
        pytest.param(b'<rect fill="' + b"url(#a)" * 60_000 + b'"/>', id="many-url-calls"),
    ],
)
def test_value_checks_are_linear(markup: bytes) -> None:
    """Each shape backtracked or copied quadratically once; at these sizes that took minutes."""
    started = time.perf_counter()
    sanitize_svg(b'<svg xmlns="http://www.w3.org/2000/svg">' + markup + b"</svg>")
    assert time.perf_counter() - started < 10


def test_an_svg_over_the_size_bound_is_refused() -> None:
    big = b'<svg xmlns="http://www.w3.org/2000/svg">' + b" " * (32 * 1024 * 1024) + b"</svg>"
    with pytest.raises(SvgRejected):
        sanitize_svg(big)


@pytest.mark.parametrize(
    ("label", "data"),
    [
        (
            "application/pdf",
            b"%PDF-1.4\nsynthetic document << /Subtype /svg >> image/svg+xml\n%%EOF\n",
        ),
        ("image/png", bytes.fromhex("89504e470d0a1a0a") + b"<svgz/>"),
        ("text/plain", b"synthetic note mentioning an svg drawing in passing"),
        ("text/xml", b'<?xml version="1.0"?><ClinicalDocument><note/></ClinicalDocument>'),
        ("application/json", b'{"svg": "<svgs onload=x>"}'),
        ("text/plain", b""),
    ],
)
def test_non_svg_documents_are_returned_unchanged(label: str, data: bytes) -> None:
    """Changed on purpose by BACKLOG #3257. The PDF, PNG, text and JSON rows held a literal ``<svg``
    tag past leading text and pinned that it was served. They now hold near misses that are not an
    ``svg`` start tag; the tag itself is refused below."""
    assert sanitize_if_svg(label, data) is data


#: Synthetic bodies shaped like the binaries the download serves, with no ``svg`` start tag. Each
#: holds a ``<`` and the SVG namespace name or the word ``svg``, so a scan wider than the tag, or one
#: that refused any ``<``, would refuse them.
_PDF_SHAPED = (
    b"%PDF-1.7\n%\xe2\xe3\xcf\xd3\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n"
    b"2 0 obj\n<< /Type /Metadata /Subtype /XML >>\nstream\n"
    b'xmlns:svg="http://www.w3.org/2000/svg" synthetic image/svg+xml\nendstream\nendobj\n'
    + bytes(range(256)) * 64
    + b"\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
)
_PNG_SHAPED = (
    bytes.fromhex("89504e470d0a1a0a0000000d49484452000000010000000108060000001f15c489")
    + b"\x00\x00\x00\x19tEXtComment\x00synthetic <svgz> svg\x00"
    + bytes(range(256)) * 64
    + bytes.fromhex("0000000049454e44ae426082")
)
_DICOM_SHAPED = (
    b"\x00" * 128
    + b"DICM"
    + b"\x02\x00\x10\x00UI\x14\x001.2.840.10008.1.2.1\x00"
    + b"\x08\x00\x60\x00CS\x02\x00OT"
    + b"\x10\x00\x10\x00PN\x10\x00SYNTHETIC^SVG<\x00"
    + bytes(range(256)) * 64
)


@pytest.mark.parametrize(
    "data", [_PDF_SHAPED, _PNG_SHAPED, _DICOM_SHAPED], ids=["pdf", "png", "dicom"]
)
@pytest.mark.parametrize("label", ["image/svg+xml", "application/pdf", "application/octet-stream"])
def test_binaries_without_an_svg_tag_are_served_plain_and_gzipped(label: str, data: bytes) -> None:
    """The control for BACKLOG #3257's tag scan: a binary that is not markup and holds no ``svg``
    start tag is served as stored, plain or gzipped, whatever its label."""
    assert b"<" in data
    assert not svg_sanitize._is_markup(data)
    assert sanitize_if_svg(label, data) is data
    gz = _gz(data)
    assert sanitize_if_svg(label, gz) is gz


#: Leading Japanese text, then ``<s ESC ( B vg``, which an ISO-2022-JP decoder reads as ``<svg``.
_ISO2022_TEXT_THEN_SVG = b"note \x1b$B$3$s\x1b(B text <s\x1b(Bvg onload=alert(1)>"


def test_the_iso_2022_jp_text_probe_really_decodes_to_an_svg_tag() -> None:
    """Control for the escape case below: no byte scan sees the tag, the decoder does."""
    assert "<svg onload" in _ISO2022_TEXT_THEN_SVG.decode("iso2022_jp")
    assert not svg_sanitize._has_svg_tag(_ISO2022_TEXT_THEN_SVG)


def test_iso_2022_jp_text_with_a_lt_and_no_tag_is_served_plain_and_gzipped() -> None:
    """The control for the escape pass: real escape sequences and a ``<`` with no ``svg`` tag,
    which a browser would read as Japanese text, are served as stored."""
    data = "note: value < 5, svg drawing attached later".encode("iso2022_jp")
    data = "日本 ".encode("iso2022_jp") + data + " 語".encode("iso2022_jp")
    assert b"\x1b$B" in data and b"\x1b(B" in data and b"<" in data
    assert sanitize_if_svg("text/plain", data) is data
    gz = _gz(data)
    assert sanitize_if_svg("text/plain", gz) is gz


@pytest.mark.parametrize(
    "data",
    [
        pytest.param(b'synthetic text <svg onload="alert(1)"><rect/></svg>', id="text-then-svg"),
        pytest.param(b"%PDF-1.4\nsynthetic document <svg onload=x>\n%%EOF\n", id="pdf-then-svg"),
        pytest.param(bytes.fromhex("89504e470d0a1a0a") + b"<svg/>", id="png-then-svg"),
        pytest.param(b'{"svg": "<svg onload=x>"}', id="json-then-svg"),
        pytest.param(b"synthetic <SVG ONLOAD=x>", id="upper-case"),
        pytest.param(b"synthetic <x:svg onload=x>", id="prefixed"),
        pytest.param(b"synthetic\n<svg\nonload=x>", id="newline-after-the-name"),
        pytest.param(b"synthetic <svg", id="tag-at-the-end"),
        pytest.param("synthetic <svg onload=x>".encode("utf-16"), id="utf-16"),
        pytest.param(b"\x00" * 128 + b"DICM synthetic <svg onload=x>", id="dicom-then-svg"),
        pytest.param(_ISO2022_TEXT_THEN_SVG, id="iso-2022-jp-escape"),
    ],
)
@pytest.mark.parametrize("label", ["image/svg+xml", "text/html", "text/plain", None])
def test_an_svg_tag_past_leading_text_is_refused_plain_and_gzipped(
    label: str | None, data: bytes
) -> None:
    """BACKLOG #3257, the positive control. A body whose first byte past leading noise is not ``<``
    used to be served as stored even when it carried ``<svg onload=...>`` further on, under an SVG
    label too. It is refused now, plain and gzipped, and the pre-check sends it to the sanitizer."""
    assert not svg_sanitize._is_markup(data)
    assert may_be_svg(data)
    with pytest.raises(SvgRejected, match="svg start tag"):
        sanitize_if_svg(label, data)
    with pytest.raises(SvgRejected, match="svg start tag"):
        sanitize_if_svg(label, _gz(data))


def test_a_gzip_tag_scan_reads_the_head_from_the_first_content_byte(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The gzip head scan covers :data:`_GZIP_SNIFF_BYTES` from the first byte past leading noise,
    so leading whitespace does not shorten it: the head pass reads on to twice the head, and never
    to the bound (BACKLOG #1129). A tag that ends inside that window is refused, and one just past
    it is served, which is the recorded trade (BACKLOG #3257). A tag the window's end cuts is judged
    on what the window holds: ``<svg`` is refused as if the tag went on, ``<sv`` is past the head.
    The bounds are shrunk so the bodies stay small; the trade is the same at 64 KiB."""
    monkeypatch.setattr(svg_sanitize, "_GZIP_SNIFF_BYTES", 1024)
    lead = b" " * 900 + b"%PDF-1.4 "

    def at_the_end(tail: bytes, rest: bytes) -> bytes:
        """A body whose 1024-byte window past the noise ends with ``tail``, followed by ``rest``."""
        return _gz(lead + b"A" * (1024 - 9 - len(tail)) + tail + rest + b"A" * 4096)

    calls = _spy_on_inflate(monkeypatch)
    inside = at_the_end(b"<svg onload=", b"x>")
    with pytest.raises(SvgRejected, match="svg start tag"):
        sanitize_if_svg("application/gzip", inside)
    assert calls == [(False, 1024), (False, 2048)]
    calls.clear()
    outside = _gz(lead + b"A" * 1024 + b"<svg onload=x>" + b"A" * 4096)
    assert sanitize_if_svg("application/gzip", outside) is outside
    assert calls == [(False, 1024), (False, 2048)]
    with pytest.raises(SvgRejected, match="svg start tag"):
        sanitize_if_svg("application/gzip", at_the_end(b"<svg", b"z/>"))
    cut = at_the_end(b"<sv", b"g onload=x>")
    assert sanitize_if_svg("application/gzip", cut) is cut


def test_a_gzip_whose_content_starts_too_near_the_bound_is_refused(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A body that is only noise for the head is read up to the bound. If its first content byte
    lies so near the bound that no full head fits past it, the tag scan cannot see a full head, so
    the body is refused rather than cleared (BACKLOG #3257). The control starts its content early
    enough to leave a full head, and is served."""
    monkeypatch.setattr(svg_sanitize, "_GZIP_SNIFF_BYTES", 1024)
    monkeypatch.setattr(svg_sanitize, "_MAX_SVG_BYTES", 4096)
    near = _gz(b" " * 4000 + b"%PDF-1.4 " + b"A" * 8192)
    with pytest.raises(SvgRejected, match="before a full head"):
        sanitize_if_svg("application/gzip", near)
    room = _gz(b" " * 2048 + b"%PDF-1.4 " + b"A" * 8192)
    assert sanitize_if_svg("application/gzip", room) is room


@pytest.mark.parametrize(
    ("data", "expected"),
    [
        # Changed on purpose by BACKLOG #3257: this row was False, and the tag is now refused.
        (b"%PDF-1.4 <svg>", True),
        (b"%PDF-1.4 synthetic", False),
        (bytes.fromhex("89504e470d0a1a0a"), False),
        (b"", False),
        (bytes.fromhex("1f8b08"), True),  # gzip: SVGZ is inflated before it is judged
        (b"\x00" * 128 + b"DICM", False),
        (b"  <svg/>", True),
        (b"\x0c\x0b<svg/>", True),
        (b"\xef\xbb\xbf<svg/>", True),
        ("<svg/>".encode("utf-16-be"), True),
        ("<svg/>".encode("utf-16"), True),
    ],
)
def test_the_pre_check_misses_no_markup_and_clears_binaries(data: bytes, expected: bool) -> None:
    """``may_be_svg`` only lets the route skip the thread hop, so a ``False`` must never hide an SVG."""
    assert may_be_svg(data) is expected
    if not expected:
        assert sanitize_if_svg("image/svg+xml", data) is data


def test_the_pre_check_reads_past_any_amount_of_leading_whitespace() -> None:
    assert may_be_svg(b" " * (70 * 1024) + b"<svg/>")


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


_PLANTED = "SYNTHETICPLANTEDSVG"


@pytest.mark.parametrize(
    "doc",
    [
        f'<!DOCTYPE svg [<!ENTITY {_PLANTED} "x">]><svg/>'.encode(),
        f'<!DOCTYPE svg [<!ENTITY e SYSTEM "http://{_PLANTED}/">]><svg>&e;</svg>'.encode(),
        f'<?xml version="1.0" encoding="x-{_PLANTED}"?><svg/>'.encode(),
    ],
    ids=["entity-name", "system-id", "encoding-label"],
)
def test_a_refusal_keeps_the_parser_error_off_its_chain(doc: bytes) -> None:
    """The parser's error can quote sender text, so the refusal carries only its type name and
    neither chain link reaches it (BACKLOG #2387, #1796)."""
    with pytest.raises(SvgRejected) as caught:
        sanitize_svg(doc)
    assert caught.value.__cause__ is None
    assert caught.value.__context__ is None
    assert _PLANTED not in str(caught.value)
