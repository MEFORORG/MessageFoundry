# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3318: a PHI label glued to an HL7 field run's token keeps its value scrubbed.

The field run replaces a whole whitespace-free token. When a PHI label sits in that token -- compact
JSON, compact XML, a query string, a comma -- the run took the label, and the part of its value past
the token's end was left for no pass to read. Before this fix, each shape below printed a synthetic
patient value on every log route here, and each paired control did not.

The fix masks that rest of the value in place (``redaction._glued_value``): main's answer, with
letters and digits replaced character for character. So the property this file holds, beside the
shapes, is that every route's output IS main's output masked that way: the same length, the same
whitespace and the same structure, which is what lets a cut, a later pass, a second handler or a
caller's text around the answer read it exactly as it reads main's. Two attempts before this one kept
the label instead, and text around the answer was read through the opener it left; the three shapes
that found it are pinned below as passing.

Every arm runs the filter chain ``_install_phi_filters`` installs, by the routes the engine uses.
Values are synthetic. The sibling for a CREDENTIAL label is BACKLOG #2968, pinned in
``tests/test_redaction_glued_credential_label.py``; this fix leaves those pins as they are."""

from __future__ import annotations

import json
import logging
import re
from collections.abc import Iterator
from contextlib import contextmanager
from string import ascii_letters, digits

import pytest

from messagefoundry import logging_setup, redaction
from messagefoundry.redaction import redact, safe_exc, safe_text
from messagefoundry.support.redact import redact_log_line


def _through_the_chain(text: str) -> str:
    """``text`` as a log message through the filters ``_install_phi_filters`` puts on a handler."""
    handler = logging.Handler()
    logging_setup._install_phi_filters(handler)
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert handler.filter(record)
    return record.getMessage()


def _log_paths(text: str) -> dict[str, str]:
    """``text`` by the log routes here, at least these."""
    return {
        "redact": redaction.redact(text),
        "redact twice": redaction.redact(redaction.redact(text)),
        "safe_exc then safe_text": safe_text(
            safe_exc(ValueError(text), limit=100_000), limit=100_000
        ),
        "once": _through_the_chain(text),
        "safe_text": _through_the_chain(safe_text(text, limit=100_000)),
        "safe_exc": _through_the_chain(safe_exc(ValueError(text), limit=100_000)),
        "two handlers": _through_the_chain(_through_the_chain(text)),
    }


def _paths_keeping(text: str, *values: str) -> list[str]:
    """Each ``path: value`` that a log route prints."""
    return [
        f"{path}: {value}"
        for path, out in _log_paths(text).items()
        for value in values
        if value in out
    ]


@contextmanager
def _rule_off() -> Iterator[None]:
    """The redactor as it was before BACKLOG #3318: every field run scrubbed as main scrubs it."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "_glued_value", lambda *args: None)
        yield


def _is_main_masked(out: str, main: str) -> bool:
    """Whether ``out`` is ``main`` with some letters and digits masked to their class, and nothing
    else changed."""
    return len(out) == len(main) and all(
        a == b or (b.isascii() and b.isalnum() and a == b.translate(redaction._SHAPE))
        for a, b in zip(out, main, strict=True)
    )


_COMPACT_JSON = json.dumps(
    {"url": "https://h.example/Patient?a=1&b=2&c=3", "name": "Zqxdoe Vandtjane"},
    separators=(",", ":"),
)

#: ``(shape, the synthetic value that printed before the fix)``: the four shapes of the record.
_SHAPES = {
    "compact-json": (_COMPACT_JSON, "Vandtjane"),
    "compact-xml": ("<PID.8>A^B^C</PID.8><name>Zqxdoe Vandtjane</name>", "Vandtjane"),
    "query-string": ("GET /Patient?a=1&b=2&mrn= 88123456 failed", "88123456"),
    "comma-glued": ("bad field A^B^C,PatientName: Zqxdoe", "Zqxdoe"),
}

_EACH_SHAPE = pytest.mark.parametrize(("text", "value"), list(_SHAPES.values()), ids=list(_SHAPES))
_EACH_SHAPE_TEXT = pytest.mark.parametrize(
    "text", [text for text, _ in _SHAPES.values()], ids=list(_SHAPES)
)

#: The paired controls, which scrubbed before the fix and still do.
_CONTROLS = {
    "default-json-dumps": (
        json.dumps({"url": "https://h.example/Patient?a=1&b=2&c=3", "name": "Zqxdoe Vandtjane"}),
        "Vandtjane",
    ),
    "json-with-no-run": ('{"url":"https://h.example/p","name":"Zqxdoe Vandtjane"}', "Vandtjane"),
    "xml-with-a-space": ("<PID.8>A^B^C</PID.8> <name>Zqxdoe Vandtjane</name>", "Vandtjane"),
    "xml-with-no-separators": ("<PID.8>ABC</PID.8><name>Zqxdoe Vandtjane</name>", "Vandtjane"),
}


@_EACH_SHAPE
def test_a_phi_label_glued_to_a_field_run_loses_its_value(text: str, value: str) -> None:
    assert not _paths_keeping(text, value)


@_EACH_SHAPE
def test_the_glued_label_rule_is_what_scrubs_it(text: str, value: str) -> None:
    """THE POSITIVE CONTROL: with the rule off, every route prints the value, so the green above is
    the rule's work and not a shape nothing reads."""
    with _rule_off():
        assert len(_paths_keeping(text, value)) == len(_log_paths(text))


@pytest.mark.parametrize(("text", "value"), list(_CONTROLS.values()), ids=list(_CONTROLS))
def test_the_paired_controls_scrub_with_the_rule_on_and_off(text: str, value: str) -> None:
    assert not _paths_keeping(text, value)
    with _rule_off():
        assert not _paths_keeping(text, value)


@_EACH_SHAPE_TEXT
def test_a_second_call_changes_nothing(text: str) -> None:
    once = redact(text)
    assert redact(once) == once


def test_the_value_is_masked_in_place() -> None:
    """The answer is main's, letters and digits masked to their class, so a reader still sees that a
    value was there and how it was laid out."""
    assert redact(_SHAPES["compact-xml"][0]) == "[redacted] Xxxxxxxxx</name>"
    assert redact(_SHAPES["query-string"][0]) == "GET [redacted] 00000000 failed"
    assert redact(_SHAPES["comma-glued"][0]) == "bad field [redacted] Xxxxxx"


@_EACH_SHAPE_TEXT
def test_every_route_answers_main_masked(text: str) -> None:
    after = _log_paths(text)
    with _rule_off():
        before = _log_paths(text)
    assert all(_is_main_masked(after[path], before[path]) for path in after)


# --- Guards: main's answer wherever a mask could be read differently -----------------------------


@pytest.mark.parametrize(
    ("text", "value"),
    [
        # A later label inside the rest: punctuation, so the rest is not masked.
        ('x|y|z"family":"Zq PatientID="4455667"', "4455667"),
        ("x|y|z,<family>Zq PatientID='4455667'</family>", "4455667"),
        ('x|y|z"family":"Zq 44 x 55 PatientID="44 55"', '"44 55"'),
        # A credential label inside the rest.
        ('x|y|z,"name":"q r password: "zq9hunter2z"', "zq9hunter2z"),
        ('x|y|z,"name":"q r token="zq9hunter2z"', "zq9hunter2z"),
        # A line break, which a second handler writes as visible text.
        (
            '"birthDate":"Zqxdoe Vandtjane\' x|y|z]"name":[{"family":"zqxdoe\n next 99887766',
            "99887766",
        ),
    ],
)
def test_a_rest_holding_punctuation_gets_main_answer(text: str, value: str) -> None:
    with _rule_off():
        main = redact(text)
        printed_by_main = set(_paths_keeping(text, value))
    assert redact(text) == main
    assert set(_paths_keeping(text, value)) <= printed_by_main


@pytest.mark.parametrize(
    "text",
    [
        "x|y|z<Qnsprefix:name>Vandtjane Smith</name>",  # a namespace prefix: not the vocabulary
        'x|y|z,"name":"Zq MRN 4455667"}',  # a gate word main's answer kept
        'x|y|z,"name":"Zq bearer Plantok"}',
        'x|y|z,"name":"Zq 19800505"}',  # a date, which main scrubs to a longer placeholder
        'x|y|z,"name":"Zq Vv": "x"}',  # a colon after the quote could make the word a key
        'x|y|z,"name":"Zq Vb"}',  # two letters glued to the quote can be a string prefix
        'nonnumeric port: \'u:pw@h\' x|y|z,"name":"Zq Vandtjane"}',  # the backstop's bounded tail
        "bad A^B^C,PatientName: Patient",  # at the text's end, the head of a keyword
    ],
)
def test_a_rest_a_pass_could_read_differently_gets_main_answer(text: str) -> None:
    with _rule_off():
        main = redact(text)
    assert redact(text) == main


def test_the_word_screen_is_what_guards_a_keyword_head(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL: masked, a ``Patient`` that ends the answer no longer joins a caller's
    ``Name: <value>``, which main's answer turned into a label."""

    def composed() -> str:
        return _through_the_chain(
            safe_exc(ValueError("bad A^B^C,PatientName: Patient")) + "Name: Plantsuf"
        )

    assert "Plantsuf" not in composed()
    monkeypatch.setattr(redaction, "_ANCHOR_PREFIXES", frozenset())
    assert "Plantsuf" in composed()


#: ``(text, the value a variant printed, the route)``: where the mask's length and class matter.
_MASK_CONTROLS = [
    ('{"name": A^B^C\'<given>Zqxdoe Plantone</name> Plantthree', "Plantthree", 40),
    ('bad x|y|z?MRN: PLANTUP PLANTUQ</name> "family": "Planttwelve" ok', "PLANTUQ", 100_000),
]


@pytest.mark.parametrize(("text", "value", "limit"), _MASK_CONTROLS)
def test_the_mask_keeps_main_length_and_class(
    text: str, value: str, limit: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    """THE POSITIVE CONTROL for the mask: taking the rest instead of masking it shortens the answer,
    so a limit keeps text main cut, and splits a name run main read whole. Masked, neither prints."""
    assert value not in safe_text(text, limit=limit)
    with _rule_off():
        assert value not in safe_text(text, limit=limit)
    monkeypatch.setattr(redaction, "_SHAPE", str.maketrans("", "", ascii_letters + digits))
    assert value in safe_text(text, limit=limit)


#: ``(an answer's input, text a caller glues straight after it, a value main hid)``: found by code
#: review round 1. Each printed on the head before that repair, and main hides each.
_GLUED_AFTER = {
    "segment-id head": (
        "bad A^B^C,PatientName: ZqMSH",
        "*^~\\&*A*B\rPID*1**DOEX$JANEX",
        "DOEX",
    ),
    "short segment-id head": ("bad A^B^C,PatientName: ZqM", "SH*^~\\&*A*B\rPID*1**DOEX", "DOEX"),
    "backstop opener head": (
        "bad A^B^C,PatientName: Zqnon",
        "numeric port: 'hunterpw@host'",
        "hunterpw",
    ),
    "digits before a stripped space": ("bad A^B^C,PatientName: 1980 ", "0505 retry", "0505"),
}


@pytest.mark.parametrize("name", list(_GLUED_AFTER))
def test_text_glued_after_an_answer_prints_nothing_main_hid(name: str) -> None:
    text, after, value = _GLUED_AFTER[name]
    assert value not in _through_the_chain(safe_exc(ValueError(text)) + after)
    with _rule_off():
        assert value not in _through_the_chain(safe_exc(ValueError(text)) + after)


def test_the_bundle_marker_head_is_refused() -> None:
    """The support bundle reads ``mfb64:v1:`` with no boundary before it."""
    line = _through_the_chain(safe_exc(ValueError("bad A^B^C,PatientName: mfb"))) + "64:v1:QUJDREVG"
    assert "QUJDREVG" not in redact_log_line(line)


def test_the_boundary_free_heads_are_what_guard_glued_text(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL: without the heads, a masked ``ZqMSH`` no longer declares the caller's
    delimiters, and the field it scrubbed prints."""
    text, after, value = _GLUED_AFTER["segment-id head"]
    monkeypatch.setattr(redaction, "_UNBOUNDED_HEADS", ())
    assert value in _through_the_chain(safe_exc(ValueError(text)) + after)


def test_a_segment_id_head_glued_to_its_quote_is_refused() -> None:
    """Found by the grammar differential after review round 2: a JSON log escapes the quote, and the
    plain answer's ``ZqMSH\\"]},\\`` then declares delimiters that a mask would not."""
    text = '{"name": A^B^C{"identifier":{"value":"Qa1 ZqMSH"]},"family":"Plantsix" Plantsixt'

    def tee() -> str:
        return _through_the_chain(json.dumps({"detail": safe_text(text)}, ensure_ascii=False))

    with _rule_off():
        main = tee()
    assert _is_main_masked(tee(), main)


def test_a_run_over_declared_delimiters_masks_a_glued_value() -> None:
    text = 'MSH*^~\\&*A*B\r x*y*z,"name":"Zqxdoe Vandtjane"}'
    assert "Vandtjane" not in redact(text)
    with _rule_off():
        assert "Vandtjane" in redact(text)


def test_a_top_level_value_key_is_not_masked() -> None:
    """``value`` is PHI only under ``identifier`` or ``telecom``, as the structured pass reads it."""
    text = 'bad x|y|z,"value":"Retry later please"} ok'
    with _rule_off():
        main = redact(text)
    assert redact(text) == main


def test_an_identifier_array_of_objects_masks_its_value() -> None:
    """FHIR writes ``identifier`` as an array of objects, so the ``value`` member sits two brackets
    in (code review round 2)."""
    text = 'x|y|z,"identifier":[{"value":"Zq 4455667"}]'
    assert "4455667" not in redact(text)
    with _rule_off():
        assert "4455667" in redact(text)


def test_a_short_unquoted_value_is_masked() -> None:
    assert redact("bad A^B^C,mrn= 12 x") == "bad [redacted] 00 x"


def test_a_clamped_record_still_gets_the_rule() -> None:
    text = _SHAPES["compact-json"][0] + " " + "w " * redaction._REDACT_WINDOW
    assert "Vandtjane" not in redaction.redact_untrusted(text)
    assert "Vandtjane" not in safe_text(text)


@pytest.mark.parametrize(
    "tag", ["(0010,0010)", "(0010, 1040)", "(0010,00ff)", "(0008,0060)", "(0010,ZZZZ)"]
)
def test_the_bare_label_tag_is_the_dicom_tag_in_group_0010(tag: str) -> None:
    whole = redaction._DICOM_TAG.fullmatch(tag)
    expected = whole is not None and whole.group(1) == "0010"
    assert (redaction._GLUED_BARE_LABEL.fullmatch(tag) is not None) is expected


def test_the_glued_labels_spell_the_structured_vocabulary() -> None:
    """The glued-label patterns spell the vocabulary out for the ReDoS scanner, so they are pinned to
    the sets the structured passes read: a key added there and missed here fails this."""
    vocabulary = redaction._PHI_LEAF_KEYS | redaction._PHI_VALUE_KEYS
    for key in vocabulary:
        assert redaction._GLUED_QUOTED_LABEL.search(f'"{key}":"')
    assert redaction._GLUED_QUOTED_LABEL.search('"identifier":{"value":"')
    for key in vocabulary:
        assert redaction._GLUED_XML_LABEL.fullmatch(f"<{key}>Zq")
        assert redaction._XML_PHI_ELEMENT.match(f"<{key}>")
    # And the other way: every word the patterns spell is one the structured passes read.
    for pattern in (redaction._GLUED_QUOTED_LABEL, redaction._GLUED_XML_LABEL):
        spelled = re.search(r"\(\?:([a-zA-Z|]+)\|0010|\(\?:([a-zA-Z|]+)\)>", pattern.pattern)
        assert spelled is not None
        assert set((spelled.group(1) or spelled.group(2)).split("|")) == vocabulary


def test_the_word_screen_holds_the_words_the_passes_spell() -> None:
    """Spot-checks that the screen read its sources: a DICOM keyword, a credential word, the MRN
    label, a JSON literal, the backstop's opener and a bundle scheme word, each with a head."""
    for word in ("patientname", "password", "bearer", "mrn", "true", "nonnumeric", "basic", "msh"):
        assert word in redaction._ANCHOR_PREFIXES
        assert word[:2] in redaction._ANCHOR_PREFIXES
    assert "vandtjane" not in redaction._ANCHOR_PREFIXES


# --- A small grammar sweep: every route answers main masked, around a caller's text too ----------

_RUNS = ("A^B^C", "x|y|z", "https://h.example/p?a=1&b=2&c=3")
_GLUE = ("", ",", ";", '"', "}", "]", ">", "&", "/", "=")
_LABELS = (
    '"name":"',
    "'family':'",
    '"given":["',
    '"identifier":{"value":"',
    "<name>",
    "<given",
    "PatientName:",
    "PatientID='",
    "mrn=",
    "MRN",
    "(0010,0010)",
)
_TAILS = ("", '"', '"}', "'}", "</name>", " tail", " PatientID=Plantpid1", " Plantone Planttwo")
_PLANTED = ("Zqxdoe", "Vandtjane", "Plantpid1", "Plantone", "Planttwo", "Plantsuf", "Plantpre")
#: Text a caller writes around an answer, at least these shapes: a structure opened before it, a
#: word a name run could join after it, and a quote that a kept opener would have paired.
_AROUND = (
    ("", ""),
    ("AE '<name>Qz': ", ""),
    ("", " Plantsuf x"),
    ("", " for peer O'Brien Plantsuf"),
    ("Plantpre ", " (on_frame({'family': 'Plantsuf'}))"),
)


def _sweep() -> Iterator[str]:
    for run in _RUNS:
        for glue in _GLUE:
            for label in _LABELS:
                for tail in _TAILS:
                    yield f"bad {run}{glue}{label}Zqxdoe Vandtjane{tail}"


def _sweep_routes(text: str) -> dict[str, str]:
    routes = _log_paths(text)
    for limit in (40, 80, 200):
        routes[f"safe_text {limit}"] = safe_text(text, limit=limit)
        routes[f"store after safe_exc {limit}"] = safe_text(safe_exc(ValueError(text), limit=limit))
    for before, after in _AROUND:
        routes[f"around {before!r} {after!r}"] = _through_the_chain(
            before + safe_exc(ValueError(text)) + after
        )
    return routes


def test_every_route_of_the_sweep_answers_main_masked() -> None:
    """Every text of the sweep, by every route, with the rule on and off: the output is main's,
    masked. That rules out any value main hid printing, by construction rather than by a list of
    values. It also counts the routes the rule fixed, so a sweep it never touched cannot pass."""
    broken: list[str] = []
    fixed = 0
    for text in _sweep():
        after = _sweep_routes(text)
        with _rule_off():
            before = _sweep_routes(text)
        for path, out in after.items():
            if not _is_main_masked(out, before[path]):
                broken.append(f"{path}: {text!r}")
            fixed += any(value in before[path] and value not in out for value in _PLANTED)
    assert not broken, broken[:10]
    assert fixed > 1000, fixed


# --- A cut falls at a different place in each answer (found against the previous attempt) -------
#
# The previous attempt's answer differed from main's in length, so one limit cut each at a different
# place, and the shorter answer kept text main's cut off. Each text below printed its value on that
# attempt and prints nothing on main.

#: ``(text, the synthetic value, limit)``: one ``safe_text`` cut at each of three limits.
_CUT_SHAPES = {
    "limit-40": (
        ',Plantone"00101040":"PatientID=\'"mrn": "https://h.example/Patient?a=1&b=2&c=3 ok<given>'
        'a&b&cOtherPatientIDs=|"family":"<: PatientName=\'name\':\'<name>"identifier":{"value":"',
        "Plantone",
        40,
    ),
    "limit-80": (
        '"1980-05-05 OtherPatientIDs=A^B^C(0008,0020)  4455667(0008,0020) x|y|z<ns:name>""'
        '<value value="<value value=" retryVandtjane=',
        "Vandtjane",
        80,
    ),
    "limit-120": (
        '{"00101040":"?a=1&b=2&<connection reset by peer while sendingOtherPatientIDs=  1980-05-05'
        '(0008,0020) "mrn: Zqxdoe></name>x"00100010":"00101040":"</name>Vandtjane',
        "Zqxdoe",
        120,
    ),
}
_EACH_CUT = pytest.mark.parametrize(
    ("text", "value", "limit"), list(_CUT_SHAPES.values()), ids=list(_CUT_SHAPES)
)

#: The store route at its real default: ``safe_exc`` at an emit site, then the store's
#: ``safe_text`` chokepoint over the result, both at the default limit of 200.
_STORE_TEXT = (
    'mrn="00100010": \'name\':\'mrn="00100010":4455667ok Plantone</name>A^B^C<family value="'
    'connection reset by peer while sendingVandtjane]<value value="IB_ACME_ADT4455667</name>'
    "OtherPatientIDs=="
)


def _stored(text: str) -> str:
    return safe_text(safe_exc(ValueError(text)))


@_EACH_CUT
def test_a_cut_answer_keeps_nothing_the_cut_old_answer_did_not(
    text: str, value: str, limit: int
) -> None:
    assert value not in safe_text(text, limit=limit)
    assert value not in safe_exc(ValueError(text), limit=limit)
    assert value not in _through_the_chain(safe_text(text, limit=limit))


def test_the_store_bound_keeps_nothing_the_old_answer_did_not() -> None:
    """Only the second cut is pinned: ``safe_exc`` alone prints this value on main too, a residual of
    the redactor that this item does not touch, and the store's cut drops it there."""
    assert redaction._DEFAULT_LIMIT == 200
    assert "4455667" not in _stored(_STORE_TEXT)


def test_the_cut_pins_print_nothing_with_the_rule_off_either() -> None:
    """Main parity: the redactor before BACKLOG #3318 printed none of these values."""
    with _rule_off():
        for text, value, limit in _CUT_SHAPES.values():
            assert value not in safe_text(text, limit=limit)
        assert "4455667" not in _stored(_STORE_TEXT)


# --- Consumers that change the answer before they redact it again (found against the previous
# attempt) ---------------------------------------------------------------------------------------
#
# Each printed its value on the previous attempt, by the real consumer named, and prints nothing on
# main: the support bundle's line scrubber, the JSON log formatter's escaping, the audit tee's
# ``json.dumps``, and a call site that appends its own words after an answer.

_ESCAPED_TEXT = 'A^B^C<given value="PatientID="q" Plantdd tail'
_LONG_TOKEN_TEXT = "GET /Patient?a=1&b=2&mrn= 4455/QZXRTVWBNMLKJHGFDSAPOIU failed"
_OPEN_TEXT = 'A^B^C<given value="PatientID="'


def _consumer_routes() -> dict[str, tuple[str, str]]:
    """``route: (output, the value it must not print)``, by the real consumers."""
    chained = _through_the_chain(_ESCAPED_TEXT)
    return {
        "audit tee": (
            _through_the_chain(
                json.dumps({"detail": safe_text(_ESCAPED_TEXT)}, ensure_ascii=False)
            ),
            "Plantdd",
        ),
        "json log then bundle": (
            redact_log_line(json.dumps({"message": chained}, ensure_ascii=False)),
            "Plantdd",
        ),
        "bundle line": (redact_log_line(_LONG_TOKEN_TEXT), "QZXRTVWBNMLKJHGFDSAPOIU"),
        "appended words": (
            _through_the_chain(f"delivery failed: {safe_exc(ValueError(_OPEN_TEXT))} for Sufxvalq"),
            "Sufxvalq",
        ),
    }


def test_no_consumer_prints_a_value_main_hid() -> None:
    printed = [route for route, (out, value) in _consumer_routes().items() if value in out]
    assert not printed
    with _rule_off():
        assert not [route for route, (out, value) in _consumer_routes().items() if value in out]


# --- Text a call site puts around an answer (found against the previous attempt) ----------------
#
# Each printed a value main hid, by a shipped log format, on the previous attempt: its kept opener
# left the answer's edge in a different parse state from main's, and the next pass read the caller's
# text through it. The mask leaves no opener, so these answer as main does.

_AROUND_AN_ANSWER = {
    # messagefoundry/last_resort.py: "last-resort: %s (%s)", with an asyncio callback repr.
    "appended-quoted-repr": (
        lambda: "last-resort: {} ({})".format(
            safe_exc(ValueError("x|y|z,'name':'Qzx")),
            "Exception in callback on_frame({'family': 'zqxdoe'})",
        ),
        "zqxdoe",
    ),
    # A peer name with an apostrophe after an answer whose open value closes at one.
    "appended-apostrophe": (
        lambda: "{} for peer O'Brien 4455 zqxpeer".format(
            safe_exc(ValueError("x|y|z\"'name':'4455667 PatientID=Plantpid1"))
        ),
        "zqxpeer",
    ),
    # messagefoundry/transports/dicom.py: a peer-chosen calling AE title before the answer.
    "prefix-element": (
        lambda: "DICOM C-STORE from {} (AE {!r}): object could not be decoded: {}".format(
            "10.0.0.5", "<name>Qz", safe_exc(ValueError("bad x|y|z<given Zq 4455667 zqxpeer"))
        ),
        "zqxpeer",
    ),
}


@pytest.mark.parametrize("name", list(_AROUND_AN_ANSWER))
def test_text_around_an_answer_prints_nothing_main_hid(name: str) -> None:
    compose, value = _AROUND_AN_ANSWER[name]
    assert value not in _through_the_chain(compose())


@pytest.mark.parametrize("name", list(_AROUND_AN_ANSWER))
def test_main_hid_the_value_around_an_answer(name: str) -> None:
    """The control for the pins above: main's redactor hides each value, so each pin is a value the
    previous attempt newly printed and not one main printed too."""
    compose, value = _AROUND_AN_ANSWER[name]
    with _rule_off():
        assert value not in _through_the_chain(compose())
