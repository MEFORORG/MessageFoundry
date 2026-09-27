# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The shared redactor's label-anchored passes for FHIR JSON, DICOM tag dumps and XML (BACKLOG #1711).

Before these passes, ``messagefoundry.redaction`` only knew HL7 shapes: segments, field runs, date runs
and multi-token name runs. A structured payload hands it single tokens by construction, so a family
name in ``"family": "..."``, an MRN in ``<value value="..."/>`` or a patient id in a DICOM tag dump
walked through every pattern. The bundle and ``GET /logs/tail`` delegate to the same function, so they
leaked it too.

Each shape below is one fixture in the pattern ``tests/test_log_redaction_secret_domain.py`` uses:

* the planted values must be gone after the shared redactor, ``safe_text`` and the bundle's
  ``redact_log_line``;
* **a positive control**: with the shape's own pass disabled, the values it alone owns must LEAK.
  That is the only assertion that tells "this pass works" apart from "a neighbouring pass happened to
  cover it", which is how the bundle's bearer pattern once shipped redacting nothing (BACKLOG #1183);
* the label an operator needs to read (the key, the tag, the element name, an identifier's
  ``system``) must survive.

Negative controls pin ordinary operator text byte-identical, because a structural pass that eats
prose is a regression in every log line the engine writes. Every value is synthetic and invented here.
"""

from __future__ import annotations

import random
import re
import time
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

import pytest

from messagefoundry import redaction
from messagefoundry.redaction import redact, safe_text
from messagefoundry.support.redact import redact_log_line

#: Synthetic stand-ins. None is name-shaped to ``_NAME_RUN`` (no two adjacent capitalized tokens),
#: none is date-shaped and none carries two HL7 delimiters, so no HL7-era pass can reach any of them.
#: That is what makes each one a value only the new passes can earn.
FAMILY = "Zqxdoe"
GIVEN = "Janex"
MRN = "MRN4455667"
PHONE = "555-201-3344"
STREET = "4411 qorvelway"
CITY = "Zendaport"
DICOM_NAME = "Zqxdoe^Janex"
DICOM_ID = "PID9988776"
ISSUER = "Qorvelhosp"


@dataclass(frozen=True)
class Shape:
    """One structured shape: a text carrying PHI, the pass that must earn it, and what must survive."""

    name: str
    text: str
    #: Values the pass must remove, and which leak with the pass disabled (the positive control).
    owned: tuple[str, ...]
    #: The module function implementing the pass, disabled by the positive control.
    pass_name: str
    #: Substrings an operator needs that must survive the redaction.
    kept: tuple[str, ...] = ()


SHAPES = (
    Shape(
        "fhir-json-patient",
        '{"resourceType":"Patient","name":[{"use":"official","family":"Zqxdoe",'
        '"given":["Janex"]}],"identifier":[{"system":"urn:oid:2.16.840.1.113883.19.5",'
        '"value":"MRN4455667"}],"telecom":[{"system":"phone","value":"555-201-3344"}],'
        '"address":[{"line":["4411 qorvelway"],"city":"Zendaport"}]}',
        (FAMILY, GIVEN, MRN, PHONE, STREET, CITY),
        "_redact_json_fields",
        kept=('"resourceType":"Patient"', '"system":"urn:oid:2.16.840.1.113883.19.5"', '"family"'),
    ),
    Shape(
        "fhir-json-spaced",
        '{"resourceType": "Patient", "name": [{"family": "Zqxdoe", "given": ["Janex"]}], '
        '"identifier": [{"type": {"coding": [{"code": "MR"}]}, "value": "MRN4455667"}]}',
        (FAMILY, GIVEN, MRN),
        "_redact_json_fields",
        kept=('"code": "MR"', '"given"'),
    ),
    Shape(
        # A Router that raises with a parsed resource renders Python's repr, not JSON.
        "python-repr-resource",
        "ValueError: bad resource {'resourceType': 'Patient', 'name': [{'family': 'Zqxdoe', "
        "'given': ['Janex']}], 'identifier': [{'value': 'MRN4455667'}]}",
        (FAMILY, GIVEN, MRN),
        "_redact_json_fields",
        kept=("ValueError: bad resource", "'resourceType': 'Patient'"),
    ),
    Shape(
        # A scalar identifier, the shape a non-FHIR JSON payload uses.
        "json-scalar-identifier",
        '{"identifier": "MRN4455667", "status": "active"}',
        (MRN,),
        "_redact_json_fields",
        kept=('"status": "active"',),
    ),
    Shape(
        # The DICOM JSON model (PS3.18 F.2) keys an attribute by its tag.
        "dicom-json-model",
        '{"00100010": {"vr": "PN", "Value": [{"Alphabetic": "Zqxdoe^Janex"}]}, '
        '"00100020": {"vr": "LO", "Value": ["PID9988776"]}, '
        '"00080060": {"vr": "CS", "Value": ["CT"]}}',
        (DICOM_NAME, DICOM_ID),
        "_redact_json_fields",
        kept=('"00080060": {"vr": "CS", "Value": ["CT"]}',),
    ),
    Shape(
        "dcmdump-lines",
        "(0010,0010) PN [Zqxdoe^Janex]                          #  12, 1 PatientName\n"
        "(0010,0020) LO [PID9988776]                            #  10, 1 PatientID\n"
        "(0010,0021) LO [Qorvelhosp]                            #  10, 1 IssuerOfPatientID\n"
        "(0008,0060) CS [CT]                                    #   2, 1 Modality",
        (DICOM_NAME, DICOM_ID, ISSUER),
        "_redact_dicom_tags",
        kept=("(0010,0010)", "(0010,0020)", "(0008,0060) CS [CT]"),
    ),
    Shape(
        "pydicom-dataset-str",
        "(0010,0010) Patient's Name                      PN: 'Zqxdoe^Janex'\n"
        "(0010,0020) Patient ID                          LO: 'PID9988776'",
        (DICOM_NAME, DICOM_ID),
        "_redact_dicom_tags",
        kept=("(0010,0010)", "(0010,0020)"),
    ),
    Shape(
        # Several tags on one line, as a joined diagnostic renders them.
        "dicom-tags-one-line",
        "C-STORE rejected: (0010,0010) PN [Zqxdoe^Janex] (0010,0020) LO [PID9988776] "
        "(0008,0060) CS [CT]",
        (DICOM_NAME, DICOM_ID),
        "_redact_dicom_tags",
        kept=("C-STORE rejected:", "(0008,0060) CS [CT]"),
    ),
    Shape(
        "dicom-keyword-labels",
        "no match for PatientName=Zqxdoe^Janex PatientID=PID9988776 Modality=CT",
        (DICOM_NAME, DICOM_ID),
        "_redact_dicom_labels",
        kept=("no match for PatientName=", "PatientID=", "Modality=CT"),
    ),
    Shape(
        "dicom-keyword-dict-repr",
        "query {'PatientName': 'Zqxdoe^Janex', 'PatientID': 'PID9988776', 'Modality': 'CT'}",
        (DICOM_NAME, DICOM_ID),
        "_redact_dicom_labels",
        kept=("'Modality': 'CT'",),
    ),
    Shape(
        "fhir-xml-patient",
        '<Patient xmlns="http://hl7.org/fhir"><name><use value="official"/>'
        '<family value="Zqxdoe"/><given value="Janex"/></name>'
        '<identifier><system value="urn:oid:2.16.840.1.113883.19.5"/>'
        '<value value="MRN4455667"/></identifier>'
        '<telecom><system value="phone"/><value value="555-201-3344"/></telecom>'
        '<address><line value="4411 qorvelway"/><city value="Zendaport"/></address></Patient>',
        (FAMILY, GIVEN, MRN, PHONE, STREET, CITY),
        "_redact_xml_elements",
        kept=('<system value="urn:oid:2.16.840.1.113883.19.5"/>', "<family value=", "</Patient>"),
    ),
    Shape(
        # Text content and a namespace prefix, the shape a non-FHIR or CDA-like payload uses.
        "xml-text-content",
        "<pt:Patient><pt:name>\n  <pt:family>Zqxdoe</pt:family>\n  <pt:given>Janex</pt:given>\n"
        "</pt:name><pt:identifier>MRN4455667</pt:identifier></pt:Patient>",
        (FAMILY, GIVEN, MRN),
        "_redact_xml_elements",
        kept=("<pt:family>", "</pt:identifier>"),
    ),
)

#: Ordinary operator text each pass must leave byte-identical. Every entry carries a word from the
#: vocabulary in a shape that is NOT a structured payload, so a pass too greedy to tell the two apart
#: fails here. The first two are real engine strings: the provision-admin refusal hint in
#: ``api/app.py`` and the environments lookup error in ``ai`` policy loading.
NEGATIVE_CONTROLS = (
    "Create one at the host with `messagefoundry provision-admin --username <name> --email "
    "<address>`, pointed at this store (./messagefoundry.db) and the service's own config, "
    "then start again",
    "environment file environments/<name>.toml was not found",
    "the account's <name>@<domain> principal did not resolve",
    '{"logger": "messagefoundry.pipeline", "level": "INFO", "message": "delivered 3 rows"}',
    '{"connection": "IB_ACME_ADT", "status": "running", "queued": 4}',
    "(0008,0060) CS [CT]  # 2, 1 Modality",
    "(0020,000D) UI [1.2.840.10008.5.1.4.1.1.2]",
    "    name = ds.PatientName",
    "set the identifier and telecom mappings in the address book",
    # `name` and `address` are operator vocabulary too; a plain STRING under them is kept in JSON.
    'preset.create {"id": "p1", "name": "ED triage view", "replaced": false}',
    "validation error input_value={'name': 'IB_ACME_ADT', 'type': 'mllp'}",
    "connect failed {'address': '10.1.2.3', 'port': 2575}",
    # Two placeholders side by side: a child tag after a SPACE is not markup evidence.
    "Usage: tool <name> <address> then more words here",
    # A label that ends its line has no value; the next line is not its value.
    "PatientName:\nConnection IB_ACME_ADT started",
    '{"name":\nConnection IB_ACME_ADT started',
)


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: s.name)
def test_every_planted_value_is_gone_after_the_shared_redactor(shape: Shape) -> None:
    out = redact(shape.text)
    leaked = [value for value in shape.owned if value in out]
    assert not leaked, f"{shape.name}: {leaked} survived redact(): {out!r}"


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: s.name)
def test_every_planted_value_is_gone_from_a_stored_error(shape: Shape) -> None:
    out = safe_text(shape.text, limit=100_000)
    leaked = [value for value in shape.owned if value in out]
    assert not leaked, f"{shape.name}: {leaked} survived safe_text(): {out!r}"


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: s.name)
def test_every_planted_value_is_gone_from_the_bundle_and_log_tail(shape: Shape) -> None:
    """``redact_log_line`` is per LINE, so a multi-line shape is fed a line at a time, which is how
    the support bundle and ``GET /logs/tail`` see it."""
    out = "\n".join(redact_log_line(line) for line in shape.text.splitlines())
    leaked = [value for value in shape.owned if value in out]
    assert not leaked, f"{shape.name}: {leaked} survived redact_log_line(): {out!r}"


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: s.name)
def test_each_shape_leaks_when_its_own_pass_is_disabled(
    shape: Shape, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE POSITIVE CONTROL. Every owned value must survive with the shape's own pass switched off,
    so the green above is this pass's work and not a neighbour's."""
    monkeypatch.setattr(redaction, shape.pass_name, lambda text: text)
    out = redact(shape.text)
    covered = [value for value in shape.owned if value not in out]
    assert not covered, (
        f"{shape.name}: {covered} were redacted with {shape.pass_name} disabled, so another pass "
        f"covers them and this fixture cannot tell whether {shape.pass_name} works"
    )


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: s.name)
def test_the_labels_an_operator_reads_survive(shape: Shape) -> None:
    out = redact(shape.text)
    lost = [label for label in shape.kept if label not in out]
    assert not lost, f"{shape.name}: {lost} were eaten: {out!r}"


@pytest.mark.parametrize("shape", SHAPES, ids=lambda s: s.name)
def test_redact_stays_a_fixed_point_on_every_shape(shape: Shape) -> None:
    """``safe_text`` re-applies the redactor at the store chokepoint, and a record sent to two handlers
    is filtered twice, so a second pass must change nothing."""
    once = redact(shape.text)
    assert redact(once) == once


@pytest.mark.parametrize("line", NEGATIVE_CONTROLS)
def test_ordinary_operator_text_survives_byte_identical(line: str) -> None:
    assert redact(line) == line


def test_the_trailing_bound_note_survives_an_unterminated_structure() -> None:
    """A clamped string ends in the bound note on its own line. An unterminated structure runs to the
    end of the text by design (a cut inside it must not strand a fragment), and that must not take the
    note with it: the note is how a reader knows the text was cut."""
    note = redaction._clamp_marker(1234)
    for head in ('{"name": [{"family": "zqxa', "<family>zqxa", "(0010,0010) PN [zqxa"):
        out = redact(f"{head}\n{note}")
        assert out.endswith(f"\n{note}"), out
        assert "zqxa" not in out, out


def test_the_note_the_structured_passes_spare_is_the_note_the_clamp_writes() -> None:
    """The passes recognise the note by shape. If the note's wording moves, this reds rather than the
    note silently becoming redactable."""
    for dropped in (0, 7, 12_345_678, 2**63 - 1):
        note = redaction._clamp_marker(dropped)
        assert redaction._TRAILING_NOTES.search(f"head\n{note}") is not None


def test_a_note_lookalike_mid_text_ends_nothing() -> None:
    """Only a note at the very END is spared, so a peer that writes the literal into its payload
    cannot end a region early and walk the values after it through."""
    note = redaction._clamp_marker(5)
    out = redact(f'{{"given": [\n{note}\n"zqxa", "vornb"]}}')
    assert "zqxa" not in out and "vornb" not in out, out


# --- cost: each pass is linear in its input ---------------------------------

#: Inputs shaped to make each pass do the most work per character. The first two for each pass are
#: the ones a naive implementation is quadratic on: a region that runs to the end of the text from
#: every match, and a search that restarts from every match.
#: Each entry is ``(prefix, repeated unit)``; the prefix is what lets a unit that only matters inside
#: a region (``[``) enter one.
_HOSTILE = {
    "json-many-keys": ("", '"family": "a", '),
    "json-unterminated-keys": ("", '"name": ['),
    "json-deep": ('"name": ', '["a",'),
    "xml-prose-placeholders": ("", "<name> x "),
    "xml-prefixed-placeholders": ("", "<a:name> x "),
    "xml-open-evidenced": ("", "<name><a>b"),
    "xml-closed-elements": ("", "<family>a</family> "),
    "dicom-tags-one-line": ("", "(0010,0010) PN [a] "),
    "dicom-labels": ("", "PatientName=a "),
    "dicom-labels-unterminated-quote": ("", "PatientName='a "),
    # A start tag with a long run that is not a quoted attribute. The first draft stepped one
    # character at a time through it and re-read the run on every step: about 10 s per window.
    "xml-attribute-run": ("<name ", "a"),
    "xml-unquoted-attribute-run": ("<name data=", "Q"),
    "xml-child-attribute-run": ("<name>\n<b ", "a"),
}


def _hostile(shape: tuple[str, str], chars: int) -> str:
    prefix, unit = shape
    return (prefix + unit * (chars // len(unit) + 1))[:chars]


#: Hostile fixtures that carry nothing a pass should scrub, by design.
_NOTHING_TO_SCRUB = frozenset(
    {
        "xml-prose-placeholders",
        "xml-prefixed-placeholders",
        "xml-attribute-run",
        "xml-child-attribute-run",
    }
)


@pytest.mark.parametrize(("name", "shape"), list(_HOSTILE.items()), ids=list(_HOSTILE))
def test_every_hostile_fixture_reaches_a_structured_pass(
    name: str, shape: tuple[str, str], monkeypatch: pytest.MonkeyPatch
) -> None:
    """Non-vacuity for the two cost arms. A fixture no structured pass enters times the HL7 passes
    and nothing else: an earlier draft of this table prefixed every unit with a JSON key, and the
    XML units then became one bare JSON token that the XML pass never saw.

    Most fixtures must be CHANGED by a pass. The XML ones that carry nothing to scrub (placeholders,
    attribute runs) must change nothing, so for them the proof is that the tag walk ran at all."""
    text = _hostile(shape, 8 * 1024)
    if name not in _NOTHING_TO_SCRUB:
        assert redaction._redact_structured(text) != text
        return
    calls = 0
    walk = redaction._walk_xml_tag

    def counting(*args: Any) -> tuple[int, int, bool]:
        nonlocal calls
        calls += 1
        return walk(*args)

    monkeypatch.setattr(redaction, "_walk_xml_tag", counting)
    assert redaction._redact_structured(text) == text
    assert calls > 0, "the XML walk never ran, so this fixture times nothing of the XML pass"


def _best_of(work: Callable[[], object], reps: int = 3) -> float:
    best = float("inf")
    for _ in range(reps):
        start = time.perf_counter()
        work()
        best = min(best, time.perf_counter() - start)
    return best


@pytest.mark.parametrize("shape", list(_HOSTILE.values()), ids=list(_HOSTILE))
def test_each_pass_grows_linearly_in_its_input(shape: tuple[str, str]) -> None:
    """8x the input must cost well under 64x the time. A quadratic pass shows ~64x; a linear one ~8x.
    The ceiling of 24 is the one ``tests/test_log_redaction_secret_domain.py`` uses for the same
    question, and a ratio rather than an absolute budget keeps a slow runner from faking a red."""
    small, large = _hostile(shape, 8 * 1024), _hostile(shape, 64 * 1024)
    t_small = max(_best_of(lambda: redact(small)), 1e-4)
    t_large = _best_of(lambda: redact(large))
    assert t_large / t_small < 24, f"{t_large / t_small:.1f}x for 8x the input on {shape!r}"


@pytest.mark.parametrize("shape", list(_HOSTILE.values()), ids=list(_HOSTILE))
def test_a_full_window_of_hostile_structure_stays_affordable(shape: tuple[str, str]) -> None:
    """One window (the most any clamped caller hands the redactor) of the worst shape must stay well
    under a second on the event loop. Measured at about a tenth of this budget when written."""
    text = _hostile(shape, redaction._REDACT_WINDOW)
    assert _best_of(lambda: redact(text)) < 0.5


def _alternation(pattern: re.Pattern[str]) -> set[str]:
    """The literal vocabulary alternation spelled inside ``pattern``."""
    match = re.search(r"\((family\|[A-Za-z|]+)", pattern.pattern)
    assert match is not None, f"no vocabulary alternation in {pattern.pattern!r}"
    return set(match.group(1).split("|")) - {""}


@pytest.mark.parametrize(
    "name", ["_JSON_PHI_KEY", "_XML_PHI_ELEMENT", "_XML_PHI_END"], ids=lambda n: n
)
def test_each_spelled_out_vocabulary_matches_the_named_sets(name: str) -> None:
    """The patterns spell the vocabulary out as literals so the static ReDoS scan can read them
    (``tests/test_security_static.py``). This is what stops a spelling drifting from the sets the
    walks consult."""
    vocabulary = redaction._PHI_LEAF_KEYS | redaction._PHI_VALUE_KEYS
    assert _alternation(getattr(redaction, name)) == vocabulary


# --- what running the passes FIRST cost, and other findings from the first draft's review ---------

#: Inputs the HL7-era redactor already scrubbed. The first draft ran the structured passes before the
#: HL7 ones and each of these regressed: scrubbing a labelled value took away the delimiter or the
#: second name token an HL7 pass needed. Every value must stay gone.
_NEVER_LESS_THAN_BEFORE = (
    ('{"mrn":"MRN4455667^H","name":[{"family":"ZQX^D"}]}', "MRN4455667"),
    ('{"pid5":"ZQXDOE^JANEX","given":"J^K"}', "ZQXDOE"),
    ('Unexpected value for "name": Jane Doe', "Doe"),
    ('{"msg": "field \'name\': Jane Doe was invalid"}', "Doe"),
    ("PatientName=Doe Jane: no match found", "Jane"),
)


@pytest.mark.parametrize(("text", "value"), _NEVER_LESS_THAN_BEFORE)
def test_the_structured_passes_never_take_redaction_away(text: str, value: str) -> None:
    assert value not in redact(text), redact(text)


def test_a_bare_scrubbed_token_injects_no_quotes() -> None:
    """A scrubbed number or bare word becomes the bare placeholder, not a quoted one, so a JSON string
    holding a repr is not given stray quotes."""
    assert redact('{"birthDate": 19800505}') == '{"birthDate": [redacted]}'


def test_a_python_bytes_value_is_scrubbed_with_its_prefix_kept() -> None:
    out = redact("bad {'family': b'Zqxdoe', 'given': [b'Janex']}")
    assert FAMILY not in out and GIVEN not in out, out
    assert "b'[redacted]'" in out


def test_safe_text_is_idempotent_on_its_own_bound_note() -> None:
    """``safe_text`` is re-applied to its own output at the store chokepoint. When the answer ends
    inside an unterminated region, a second pass must not eat the note saying the text was cut."""
    once = safe_text('bad {"family": "zqxa ' + "q" * (redaction._REDACT_WINDOW + 10))
    assert "[redaction bound: dropped" in once, once
    assert safe_text(once) == once


def test_redact_is_a_fixed_point_over_random_structure() -> None:
    """A fuzz over the fragments the passes key on. The first draft broke the fixed point on an
    unterminated string ending in a lone backslash, which a second pass re-read as a different token
    stream; a reviewer found it in 200,000 random inputs. Seeded, so a red reproduces.

    The HL7 passes are not a fixed point on every input this alphabet builds -- a name run scrubbed
    on the first pass can leave a token carrying two delimiters for the second -- and that predates
    BACKLOG #1711. So the arm asks only about inputs the HL7 passes alone ARE a fixed point on, which
    is the property these passes must not take away. It is also why :func:`redact` repeats the
    structured passes: without the repeat this arm failed on its first run. Measured over 200,000
    inputs from this alphabet, no input needed more than 3 of the ``_STRUCTURED_ROUNDS`` rounds."""
    fragments = (
        '"name":',
        "'name':",
        '"value":',
        '"identifier":',
        "{",
        "}",
        "[",
        "]",
        ",",
        '"',
        "'",
        "\\",
        "\n",
        " ",
        "zq",
        "Zq Jx",
        "19800505",
        "<name>",
        "</name>",
        '<value value="',
        '"/>',
        "<identifier>",
        "</identifier>",
        "(0010,0010)",
        "(0008,0060)",
        " PN [",
        "PatientName=",
        "PatientID: ",
        "^",
        "|",
        "[redacted]",
        "b'",
        " [redaction bound: dropped 5 more chars unscanned]",
    )
    rng = random.Random(1711)
    known = "PN [: <\"'name':{'name'</identifier>\"[redacted]\\"
    checked = 0
    for case in [
        known,
        *("".join(rng.choices(fragments, k=rng.randint(1, 14))) for _ in range(20_000)),
    ]:
        baseline = redaction._redact_flat(case)
        if redaction._redact_flat(baseline) != baseline:
            continue
        once = redact(case)
        assert redact(once) == once, repr(case)
        checked += 1
    assert checked > 15_000, f"only {checked} inputs were eligible, so the fuzz measured little"


# --- second review round: shapes the first draft still let through ---------------------------------

#: Each is ``(text, a value that must be gone)``. All were measured leaking on the first revision.
_SECOND_ROUND_LEAKS = (
    # A tuple, a set and a date call are Python values the walk must enter, not end at.
    ("bad {'given': ('Janex', 'Qorv')}", GIVEN),
    ("bad {'given': frozenset({'Janex'})}", GIVEN),
    ("{'birthDate': datetime.date(1980, 5, 5)}", "1980"),
    # Prose running on after a key-shaped label.
    ('invalid "birthDate": 5 May 1980', "May"),
    # A comma inside an unquoted label value, and a multi-valued keyword.
    ("PatientName: Zqxdoe, Janex", GIVEN),
    ("{'PatientName': ['Zqxdoe^Janex', 'Qorv^Mil'], 'x': 1}", "Qorv^Mil"),
    # The f-string debug form and a logged attribute value.
    ("bad ds.PatientID='PID9988776'", DICOM_ID),
    ("query.PatientID: PID9988776", DICOM_ID),
    # An unquoted attribute value on a leaf element.
    ("<given value=Janex/>", GIVEN),
    # A KEPT attribute with no closer swallowed the next tag and its value.
    ('<identifier><system value="urn:x/><value value="MRN4455667"/></identifier>', MRN),
)


@pytest.mark.parametrize(("text", "value"), _SECOND_ROUND_LEAKS)
def test_second_round_shapes_do_not_leak(text: str, value: str) -> None:
    out = redact(text)
    assert value not in out, out
    assert redact(out) == out


def test_a_plain_string_name_in_json_is_a_stated_residual() -> None:
    """``name`` and ``address`` scrub a STRUCTURE only (``_PHI_STRUCTURE_ONLY_KEYS``), so an
    operator's ``{"name": "IB_ACME_ADT"}`` survives -- and so does a single-token patient name in
    non-FHIR JSON. Pinned so a change to that trade is deliberate. A FHIR ``name`` is an array or an
    object and is scrubbed (the fixtures above), and a two-token string is caught by the name run."""
    assert FAMILY in redact('{"name": "Zqxdoe"}')
    assert "Zqxdoe Janex" not in redact('{"name": "Zqxdoe Janex"}')


def _keyword_alternation(pattern: re.Pattern[str]) -> set[str]:
    match = re.search(r"\((?:\?:)?(PatientName\|[A-Za-z|]+)\)", pattern.pattern)
    assert match is not None, f"no keyword alternation in {pattern.pattern!r}"
    return set(match.group(1).split("|"))


def test_the_dicom_keyword_spellings_agree() -> None:
    """The keyword list is spelled in the label pattern and again in the value-end lookahead. If one
    gains a keyword the other lacks, a value runs over the next label or stops short of it."""
    assert _keyword_alternation(redaction._DICOM_PHI_LABEL) == _keyword_alternation(
        redaction._DICOM_LABEL_VALUE_END
    )


def test_the_dicom_json_tag_spellings_agree() -> None:
    tag = redaction._DICOM_JSON_PHI_TAG.pattern
    assert tag in redaction._JSON_PHI_KEY.pattern
