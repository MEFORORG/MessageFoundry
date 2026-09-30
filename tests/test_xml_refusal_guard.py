# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Pin the XML refusal POLICY at each engine parse site, not just "the parse failed".

The engine parses untrusted XML in three places, and all three rely on defusedxml's refusal flags
(``forbid_dtd``, ``forbid_entities``, ``forbid_external``) rather than only on expat's amplification
limits:

* ``RawMessage.xml()`` in ``parsing/message.py`` -- an inbound XML payload, all three flags on.
* ``api/svg_sanitize.py`` -- the served copy of an SVG attachment, ``forbid_dtd`` OFF by design (ADR
  0105, 2026-09-28 amendment: a DOCTYPE with no entity declaration is accepted).
* ``corepoint_import.py`` -- an operator-supplied Corepoint export, all three flags on.

``tests/test_xml_parser_consistency.py`` already proves each surface refuses a hostile corpus, but it
counts ANY exception as a refusal. So a site that stopped refusing and fell over on something else
would still pass there. These tests assert WHICH refusal fired and that each site's own error path
turns it into a clean outcome.

**These tests name no XML library.** They read refusals by class name and reach the parser class
through the engine module that imports it. That is deliberate: they must pass unchanged whichever
package the engine imports defusedxml from, which is the proof a vendoring or a swap changed nothing.

Synthetic payloads only. The external-entity target is a path that does not exist, so nothing here
can reach a real resource even if a parser were misconfigured.
"""

from __future__ import annotations

import xml.etree.ElementTree as ET  # nosec B405 -- the unguarded CONTROL arm, fed only fixed strings
from pathlib import Path

import pytest

from messagefoundry.api import svg_sanitize
from messagefoundry.api.svg_sanitize import SvgRejected, sanitize_if_svg
from messagefoundry.config.models import ConnectorType, ContentType
from messagefoundry.config.wiring import ConnectionSpec, InboundConnection, Registry
from messagefoundry.corepoint_import import CorepointImportError, parse_any
from messagefoundry.parsing import Message, RawMessage
from messagefoundry.pipeline.dryrun import dry_run
from messagefoundry.store import MessageStatus

_SVG = 'xmlns="http://www.w3.org/2000/svg"'
_SVG_LABEL = "image/svg+xml"

#: The four shapes the brief names. Each has an ``svg`` root so the SVG site reaches its parser, and a
#: body the other two sites will parse as ordinary XML.
PAYLOADS: dict[str, str] = {
    # A DOCTYPE with nothing in it: no entity, no fetch. Only a site with forbid_dtd ON refuses it.
    "dtd": f'<!DOCTYPE svg SYSTEM "about:legacy-compat"><svg {_SVG}/>',
    "internal-entity": f'<!DOCTYPE svg [<!ENTITY a "expanded">]><svg {_SVG}>&a;</svg>',
    "external-entity": (
        '<!DOCTYPE svg [<!ENTITY x SYSTEM "file:///nonexistent/mefor-xxe-probe">]>'
        f"<svg {_SVG}>&x;</svg>"
    ),
    "billion-laughs": (
        '<!DOCTYPE svg [<!ENTITY l "lol">'
        '<!ENTITY l1 "&l;&l;&l;&l;&l;&l;&l;&l;&l;&l;">'
        '<!ENTITY l2 "&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;&l1;">'
        '<!ENTITY l3 "&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;&l2;">]>'
        f"<svg {_SVG}>&l3;</svg>"
    ),
}

#: With forbid_dtd ON, the DOCTYPE handler fires before any entity declaration is read, so every
#: payload is refused as a DTD. That ordering is the policy: nothing past the DOCTYPE is looked at.
_ALL_FLAGS_ON = dict.fromkeys(PAYLOADS, "DTDForbidden")

#: With forbid_dtd OFF (the SVG site), a bare DOCTYPE is accepted and an entity declaration is the
#: first thing refused, whether the entity is internal, external or recursive.
_SVG_EXPECTED: dict[str, str | None] = {
    "dtd": None,
    "internal-entity": "EntitiesForbidden",
    "external-entity": "EntitiesForbidden",
    "billion-laughs": "EntitiesForbidden",
}

_BENIGN = f'<svg {_SVG}><rect width="1" height="1"/></svg>'


# --- the control: these payloads are live against an unguarded parser ------------------------------


def test_control_stdlib_expands_the_internal_entity() -> None:
    """Without the refusal flags, CPython's own ElementTree EXPANDS a declared internal entity.

    This is the arm that proves the payloads discriminate, so a refusal below means the guard fired
    rather than the payload being inert. It also records why dropping to the stdlib parser would
    loosen the posture: expat's amplification limits do not refuse a small declared entity."""
    root = ET.fromstring(PAYLOADS["internal-entity"])  # noqa: S314  # nosec B314 -- control arm
    assert "".join(root.itertext()) == "expanded"


# --- site 1: RawMessage.xml() ----------------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_rawmessage_xml_refuses_with_the_policy_error(name: str) -> None:
    with pytest.raises(ValueError) as excinfo:  # the documented contract: a ValueError subclass
        RawMessage(PAYLOADS[name], "xml").xml()
    assert type(excinfo.value).__name__ == _ALL_FLAGS_ON[name]


def test_rawmessage_xml_accepts_the_benign_control() -> None:
    assert RawMessage(_BENIGN, "xml").xml().tag == "{http://www.w3.org/2000/svg}svg"


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_a_handler_hitting_the_refusal_records_error_and_sends_nothing(name: str) -> None:
    """The pipeline's error path: a Handler that calls ``xml()`` on a hostile body is ERROR, not a crash.

    Driven through ``dry_run``, which mirrors the engine's disposition logic without a store."""
    reg = Registry()
    reg.add_inbound(
        InboundConnection(
            name="IB_XML",
            spec=ConnectionSpec(ConnectorType.FILE, {}),
            router="r",
            content_type=ContentType.XML,
        )
    )

    def handle(msg: Message | RawMessage) -> None:
        assert isinstance(msg, RawMessage)
        msg.xml()

    reg.add_router("r", lambda _msg: ["h"])
    reg.add_handler("h", handle)

    result = dry_run(reg, PAYLOADS[name], inbound="IB_XML")

    assert result.disposition is MessageStatus.ERROR
    assert result.error is not None and _ALL_FLAGS_ON[name] in result.error
    assert not result.deliveries


# --- site 2: the SVG attachment sanitizer ----------------------------------------------------------


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_svg_sanitizer_refuses_every_entity_and_accepts_a_bare_doctype(name: str) -> None:
    """A refusal becomes :class:`SvgRejected`, which the download route answers with a 422."""
    expected = _SVG_EXPECTED[name]
    body = PAYLOADS[name].encode()
    if expected is None:
        # Pinned so a change to forbid_dtd here is a visible diff: ADR 0105 accepts this shape, and the
        # sanitizer drops the DOCTYPE from what it serves.
        served = sanitize_if_svg(_SVG_LABEL, body)
        assert b"DOCTYPE" not in served and b"<svg" in served
        return
    with pytest.raises(SvgRejected) as excinfo:
        sanitize_if_svg(_SVG_LABEL, body)
    assert type(excinfo.value.__cause__).__name__ == expected
    assert expected in str(excinfo.value)


@pytest.mark.parametrize("name", ["internal-entity", "external-entity", "billion-laughs"])
def test_svg_root_sniff_refuses_entities_without_a_label(name: str) -> None:
    """With no SVG label the root sniff decides, and it runs the same refusing parser first.

    The sniff falls back to a byte scan when its parse is refused, so the document is still seen as
    SVG and still refused by the sanitizer, never served raw."""
    with pytest.raises(SvgRejected):
        sanitize_if_svg(None, PAYLOADS[name].encode())


def test_forbid_external_refuses_an_external_reference_on_its_own() -> None:
    """The third flag, isolated. Every engine site also sets forbid_entities, which refuses the
    declaration first, so this is the only arm that shows forbid_external is live rather than inert.

    The parser class is taken from the engine module that uses it, so this names no library."""
    parser = svg_sanitize.DefusedXMLParser(  # type: ignore[attr-defined]  # not in its __all__
        target=ET.TreeBuilder(), forbid_dtd=False, forbid_entities=False, forbid_external=True
    )
    with pytest.raises(ValueError) as excinfo:
        parser.feed(PAYLOADS["external-entity"])
        parser.close()
    assert type(excinfo.value).__name__ == "ExternalReferenceForbidden"


# --- site 3: the Corepoint export import -----------------------------------------------------------


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_corepoint_import_refuses_with_the_policy_error(name: str) -> None:
    with pytest.raises(CorepointImportError, match="forbidden XML construct") as excinfo:
        parse_any(PAYLOADS[name])
    assert type(excinfo.value.__cause__).__name__ == _ALL_FLAGS_ON[name]


@pytest.mark.parametrize("name", sorted(PAYLOADS))
def test_corepoint_cli_reports_the_refusal_and_writes_nothing(
    name: str, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI's error path: a hostile export is a clean exit 1 with no module written."""
    from messagefoundry.__main__ import main

    export = tmp_path / "export.xml"
    export.write_text(PAYLOADS[name], encoding="utf-8")
    out = tmp_path / "out"

    assert main(["import", "corepoint", str(export), "--out", str(out)]) == 1
    assert _ALL_FLAGS_ON[name] in capsys.readouterr().err
    assert not out.exists() or not any(out.iterdir())
