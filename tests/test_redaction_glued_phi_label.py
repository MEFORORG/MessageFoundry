# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #3318: a PHI label glued to an HL7 field run's token keeps its value scrubbed.

The field run replaces a whole whitespace-free token. When a PHI label sits in that token -- compact
JSON, compact XML, a query string, a comma -- the run took the label, and the part of its value past
the token's end was left for no pass to read. Before this fix, each shape below printed a synthetic
patient value on every log route here, and each paired control did not.

Every arm runs the filter chain ``_install_phi_filters`` installs, by the routes the engine uses:
straight to a handler, after ``safe_text`` or ``safe_exc``, and through two handlers. Values are
synthetic. The sibling for a CREDENTIAL label is BACKLOG #2968, pinned in
``tests/test_redaction_glued_credential_label.py``; this fix leaves those pins as they are."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from contextlib import contextmanager

import pytest

from messagefoundry import logging_setup, redaction
from messagefoundry.redaction import redact, safe_exc, safe_text

#: The routes that end in the credential filters.
_CHAIN_PATHS = ("once", "safe_text", "safe_exc", "two handlers")


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
        # Through the module attribute, so ``_rule_off`` reaches these two routes too.
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


def _paths_keeping(text: str, *values: str, paths: tuple[str, ...] = ()) -> list[str]:
    """Each ``path: value`` that a log route prints, on ``paths`` or on every route."""
    return [
        f"{path}: {value}"
        for path, out in _log_paths(text).items()
        for value in values
        if value in out and (not paths or path in paths)
    ]


@contextmanager
def _rule_off() -> Iterator[None]:
    """The redactor as it was before BACKLOG #3318: every route goes through ``redaction.redact``."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "redact", lambda text: redaction._redact_text(text, None))
        yield


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


@_EACH_SHAPE
def test_a_second_call_changes_nothing(text: str, value: str) -> None:
    del value
    once = redact(text)
    assert redact(once) == once


def test_the_label_is_kept_so_a_reader_sees_what_was_withheld() -> None:
    assert redact(_SHAPES["compact-xml"][0]) == "[redacted]<name>[redacted]</name>"
    assert redact(_SHAPES["query-string"][0]) == "GET [redacted]mrn= [redacted] failed"


# --- Guards: the answer without the rule is returned wherever the rule could print more --------


@pytest.mark.parametrize(
    ("text", "value"),
    [
        # A kept quote ends the leaf string early, and the next label's value is left behind it.
        ('x|y|z"family":"Zq PatientID="4455667"', "4455667"),
        ("x|y|z,<family>Zq PatientID='4455667'</family>", "4455667"),
    ],
)
def test_an_answer_that_keeps_a_new_word_is_not_used(text: str, value: str) -> None:
    assert not _paths_keeping(text, value)


def test_a_value_whose_words_print_elsewhere_is_still_caught() -> None:
    """Found by code review: a count of words passed this, because ``plain`` printed 44 and 55 in
    the prose the kept quote swallowed. The check reads runs in order, not words."""
    text = 'x|y|z"family":"Zq 44 x 55 PatientID="44 55"'
    assert redact(text) == redaction._redact_text(text, None)
    assert '"44 55"' not in redact(text)


def test_the_kept_text_check_is_what_guards_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL for the guards above: with the check passing everything, the value
    prints."""
    monkeypatch.setattr(redaction, "_keeps_only_what_plain_kept", lambda out, plain, labels: True)
    assert "4455667" in redact('x|y|z"family":"Zq PatientID="4455667"')
    assert '"44 55"' in redact('x|y|z"family":"Zq 44 x 55 PatientID="44 55"')


def test_a_record_over_the_window_still_gets_the_rule() -> None:
    """``clamp_untrusted`` joins its bound note with a line break. That break is this module's, not a
    peer's, so it does not take the rule off."""
    text = _SHAPES["compact-json"][0] + " " + "w " * redaction._REDACT_WINDOW
    assert "Vandtjane" not in redaction.redact_untrusted(text)


@pytest.mark.parametrize(
    "text",
    [
        'x|y|z,"name":"q r password: "zq9hunter2z"',
        'x|y|z,"name":"q r token="zq9hunter2z"',
        'x|y|z,"name":"q r a%2Cpassword: "zq9hunter2z"',
    ],
)
def test_a_text_holding_a_credential_shape_gets_the_answer_without_the_rule(text: str) -> None:
    """The credential filters run after this module, so a kept label must not take their label into
    its own value. A text that holds one gets exactly the answer the redactor gave before #3318."""
    assert redact(text) == redaction._redact_text(text, None)
    assert not _paths_keeping(text, "zq9hunter2z", paths=_CHAIN_PATHS)


def test_the_credential_screen_is_what_guards_it(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE POSITIVE CONTROL: with the screen off, the chain prints the credential. ``redact`` alone
    never scrubs one, so the chain is what is asserted on."""
    text = 'x|y|z,"name":"q r password: "zq9hunter2z"'
    assert "zq9hunter2z" not in _through_the_chain(text)
    monkeypatch.setattr(redaction, "_holds_a_credential_shape", lambda text: False)
    assert "zq9hunter2z" in _through_the_chain(text)


def test_a_text_with_a_line_break_gets_the_answer_without_the_rule() -> None:
    """The control-character filter writes a line break as visible text, so a second handler reads
    the text as one line. A kept quote there closed an earlier value that the line end had closed on
    the first call, and the second handler printed a value this redactor hid. Only that route is
    held: the others print the value with the rule off too."""
    text = '"birthDate":"Zqxdoe Vandtjane\' x|y|z]"name":[{"family":"zqxdoe\n next 99887766'
    assert redact(text) == redaction._redact_text(text, None)
    assert not _paths_keeping(text, "99887766", paths=("two handlers",))


def test_an_xml_label_with_a_namespace_prefix_is_not_kept() -> None:
    """The prefix is free text, so keeping it could print a word the run hid. Found by code review:
    the word check allowed every word of a kept label, the prefix's too."""
    text = "x|y|z<Qnsprefix:name>Vandtjane Smith</name>"
    assert redact(text) == redaction._redact_text(text, None)
    assert "Qnsprefix" not in redact(text)


def test_the_mrn_label_is_the_label_half_of_the_mrn_pass() -> None:
    """``_MRN_LABEL`` is group 1 of ``_MRN_LABELLED``, spelled again so it needs no value. Pinned so
    the two cannot drift apart."""
    assert redaction._MRN_LABELLED.pattern.startswith(redaction._MRN_LABEL.pattern)


@pytest.mark.parametrize(
    "tag", ["(0010,0010)", "(0010, 1040)", "(0010,00ff)", "(0008,0060)", "(0010,ZZZZ)"]
)
def test_the_patient_tag_is_the_dicom_tag_in_group_0010(tag: str) -> None:
    whole = redaction._DICOM_TAG.fullmatch(tag)
    expected = whole is not None and whole.group(1) == "0010"
    assert (redaction._PATIENT_DICOM_TAG.fullmatch(tag) is not None) is expected


# --- A small grammar sweep: no route prints a value the redactor before the rule hid ------------

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
_TAILS = ("", '"', "</name>", " tail", " PatientID=Plantpid1", " Plantone Planttwo")
_PLANTED = ("Zqxdoe", "Vandtjane", "Plantpid1", "Plantone", "Planttwo")


def _sweep() -> Iterator[str]:
    for run in _RUNS:
        for glue in _GLUE:
            for label in _LABELS:
                for tail in _TAILS:
                    yield f"bad {run}{glue}{label}Zqxdoe Vandtjane{tail}"


def test_no_route_prints_a_value_the_redactor_before_the_rule_hid() -> None:
    """Every text of the sweep, by every route, with the rule on and off. It also counts the texts
    the rule fixed, so a sweep the rule never touched cannot pass as evidence."""
    newly: list[str] = []
    fixed = 0
    for text in _sweep():
        after = _log_paths(text)
        with _rule_off():
            before = _log_paths(text)
        for path, out in after.items():
            printed = {value for value in _PLANTED if value in out}
            hidden = {value for value in _PLANTED if value not in before[path]}
            newly += [f"{path}: {value} in {text!r}" for value in printed & hidden]
            fixed += bool({value for value in _PLANTED if value in before[path]} - printed)
    assert not newly, newly[:10]
    assert fixed > 1000, fixed
