# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A stray JSON closer is read on the text as received (BACKLOG #5814, added item 2).

Two bypasses of the mismatched-closer rule that engine PR 3070's review named. A flat HL7 field-run
pass ran first and could consume an opener, so the closer after it looked matched to the JSON walk;
and a stray closer of the SAME kind as the open container ended the value early, which the walk cannot
tell from a real close. In both, a single-token value after the closer walked through ``redact``,
``safe_text`` and the bundle's ``redact_log_line`` on defaults. Every value here is synthetic.
"""

from __future__ import annotations

import ast
import functools
import logging
import random
import re
import time
from collections.abc import Callable
from pathlib import Path

import pytest

import messagefoundry.redaction as redaction
from messagefoundry.logging_setup import _shipped_filters
from messagefoundry.redaction import (
    _JSON_PHI_KEY,
    _JSON_STRUCTURE,
    _JSON_TOKEN,
    _stray_json_closer,
    redact,
    safe_text,
)
from messagefoundry.support.redact import redact_log_line

SECRET = "Qzorvex"
PLACEHOLDER = "[redacted]"

SCRUBBERS: list[Callable[[str], str]] = [redact, safe_text, redact_log_line]

STRAY = [
    # A field-run pass consumed the `[`, so the `)` read as matched.
    f'{{"identifier": [a|b|c ) , {{"value": "{SECRET}"}}]}}',
    # A same-kind stray closer ended the value early.
    f'{{"given": [Jane] {SECRET}]}}',
    f'{{"family": ["Doe"] ] {SECRET}}}',
    f'{{"identifier": [{{"value": "x"}}] ], "value": "{SECRET}"}}',
    f'x {{"name": [ "a" ] ] {SECRET}',
    f'[{{"family": ["Doe"] ] {SECRET}}}]',
]

#: Texts origin/main 4ad697da713 kept the PHI value of, each now the placeholder. A value straight
#: after a PHI value's container, with no delimiter between, makes the scrub raise
#: (``_json_value_runs_on``); a key's colon on the next line no longer disarms the check, and a
#: closer with nothing open after a key is stray.
RUN_ON = [
    f'"given": [Jane] {SECRET}]',  # no container open: the head was cut
    f'{{"given": [x] {SECRET}}}}}',  # the key's own container's kind
    f'can\'t map {{"given": [Jane] {SECRET}]}}',  # a string opened before the key
    f'{{"given": [Jane] {SECRET}\']}}',  # a quote in the value hides the closer
    f'{{"given": [Jane] {SECRET}"]}}',
    # A top-level key whose colon is on the next line.
    f'"telecom"\n: [a|b|c ) , {{"value": "{SECRET}"}}]',
    # One token after a closed PHI value, with no stray closer.
    f'{{"given": [x] {SECRET}}}',
    # An apostrophe before a same-kind stray closer.
    f'{{"given": [Jane] can\'t {SECRET}]}}',
    # A stray closer after the value, then the token.
    f'"given": [Jane] ] {SECRET}',
    # A PHI key nested in another PHI key's value.
    f'{{"identifier": [{{"value": ["x"] {SECRET}}}]}}',
    # Labels after the value: they go with the text, so no later pass reads one without its value.
    f'{{"given": [Jane] password= {SECRET}:8080}}',
    f'{{"given": [Jane] {SECRET}: 1}}',
    f'{{"given": [Jane] frozenset({{{SECRET}}})}}',
]

#: Some texts whose PHI value is kept: examples, not a complete list. Strict, so a change that
#: catches one turns this red.
MISSED = [
    # The key's own container closed by a same-kind stray closer, then another closer, then the token.
    f'{{"given": [x] }} }} {SECRET}',
    # A line break before the token. The walk starts at the key, so a line break after the key's
    # own container ends the value there, even inside an object opened before the key.
    f'{{"given": [x]\n {SECRET}}}',
    f'{{\n  "given": [x]\n  {SECRET}}}\n}}',
    # The key's own container closed, then a colon: the walk has returned before it.
    f'{{"given": [Jane]}}:{SECRET}}}',
    # A line break after the colon: the walk reads no value on the next line (as on origin/main).
    f'"telecom":\n[a|b|c ) , {{"value": "{SECRET}"}}]',
    f'{{"telecom":\n  [{{"value": "{SECRET}"}}]}}',
    # A member after a comma with no key: the walk reads it under the object's policy.
    f'{{"identifier": {{"value": ["x"], {SECRET}}}}}',
    # A closer of the enclosing object's kind, then the token, then a stray closer.
    f'{{"given": ["x"]}} {SECRET}}}',
    # A colon after a tuple, which can be a dict key.
    f'{{"given": (Jane): {SECRET}}}',
    # A token after a scalar value: the run-on rule reads only what follows a container.
    f'"family": "Doe" {SECRET}',
    # A field run, then a line break before the token: the line break ends a top-level value.
    f'"given": [a|b|c]\n {SECRET}',
    f'{{"given": [a|b|c]\n {SECRET}}}',
    # A string after the field run's placeholder: the read-on takes a bare token only.
    f'"given": a|b|c "{SECRET}"',
    # A token glued to a count note reads as a callable's name, which the walk keeps.
    f'"given": a|b|c {SECRET}\u2026(+12 chars)',
    # A comma ends the value, as it does with no field run (`"given": Doe, Jane`).
    f'"given": a|b|c x, {SECRET}',
    # A container after a scalar value, or after the field run's placeholder.
    f'"given": x [{SECRET}]',
    f'"given": a|b|c [{SECRET}]',
    # A line break after the token with more text following, a credential word in the run, and a
    # run longer than _PLAIN_RUN_TOKENS: the read-on leaves each as it was.
    f'"given": a|b|c {SECRET}\nnext line',
    f'"given": a|b|c bearer {SECRET}',
    f'"given": a|b|c {SECRET}' + " w" * 16,
    # A run that reaches a label or a quote: the read-on stops at the placeholder rather than take
    # a label another pass reads (`_placeholder_runs_on`).
    f"\"given\": a|b|c {SECRET} <given value='x'",
    f'"given": a|b|c {SECRET}"',
]

#: An UNBRACKETED field run, then a token, each kept on origin/main 4ad697da713 and on this
#: row's earlier heads. A field-run pass runs before the JSON walk and writes ``[redacted]`` for
#: the run, so the token after it read as no key's value (top level) or under the enclosing
#: object's policy (nested). The walk now reads on past that placeholder
#: (``_placeholder_runs_on``) and keeps a scrubbed container's policy after it
#: (``_policy_after_close``). Not a value the walk blanks whole: each keeps its keys.
FIELD_RUN = [
    f'"given": a|b|c {SECRET}',
    f'{{"given": a|b|c {SECRET}}}',
    f'{{"family": DOE^JANE^Q {SECRET}}}',
    f'{{"identifier": {{"value": a|b|c {SECRET}}}}}',
    f'"given": a|b|c Jane Doe {SECRET}',
    f'"given": a|b|c 1980-05-05 {SECRET}',
    f'"given": a|b|c 123-45-6789 {SECRET}',
    f'"given": a|b|c {SECRET}, Jane',
    f'{{"given": x a|b|c {SECRET}}}',
    f'"given": x a|b|c {SECRET}',
    f'"identifier": a|b|c {SECRET}',
    f'[{{"given": a|b|c {SECRET}}}]',
    f'{{"telecom": [{{"value": a|b|c {SECRET}}}]}}',
    f'"name": a|b|c {SECRET}',
    f'"address": a|b|c {SECRET}',
    f'{{"name": a|b|c {SECRET}}}',
    f'"given": a|b|c\t{SECRET}',
    f'"given":\ta|b|c {SECRET}',
    f'"given": a|b|c {SECRET}\n[redaction bound: dropped 12 more chars unscanned]',
    # The placeholder written by the text itself, top level and inside a searched object.
    f'"given": [redacted] {SECRET}',
    f'{{"identifier": {{"system": "x", "value": [redacted] {SECRET}}}}}',
]


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize("text", FIELD_RUN)
def test_a_token_after_a_field_run_is_hidden(scrub: Callable[[str], str], text: str) -> None:
    once = scrub(text)
    assert SECRET not in once and once != PLACEHOLDER, once
    assert scrub(once) == once


#: The FIELD_RUN texts 4ad697da713 hid the token of already, with its name passes. They are
#: pinned because the same change reaches them; every other FIELD_RUN text kept its token there.
FIELD_RUN_MAIN_HID = {
    f'"given": a|b|c Jane Doe {SECRET}',
    f'"given": a|b|c {SECRET}, Jane',
}
FIELD_RUN_MAIN_KEPT = [text for text in FIELD_RUN if text not in FIELD_RUN_MAIN_HID]


def test_the_main_hid_set_is_in_field_run() -> None:
    assert set(FIELD_RUN) >= FIELD_RUN_MAIN_HID


@pytest.mark.parametrize("text", FIELD_RUN_MAIN_KEPT)
def test_origin_main_kept_each_field_run_token(text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control: with this branch's rules off, each such text keeps its token."""
    _rules_off(monkeypatch)
    assert SECRET in redact(text)


#: Texts the differential against origin/main found printing words main's bounded answer had cut,
#: on earlier forms of the read-on: it wrote one placeholder for a long token, or for a run whose
#: label and value main scrubbed in two passes, so the answer was shorter and the bound cut later;
#: or it padded with spaces, which split a token the whole-token cut had dropped.
CUT_SHIFT = [
    "A^B^C['given': Pqwertypassword=password=<value value=\n[redaction bound: x]'name':"
    "Authorization: Bearer <value value=password=PID|1||Hunter2pw>\n1980-05-05Hunter2pw>"
    '"identifier": 10.1.2.3"telecom":Hunter2pwhttps://h:1/p</name>DOE^JANE^Q 1980-05-05Hunter2pwQzorvex',
    '"identifier": [redacted]A^B^C"system": MRN 123456\t123-45-6789(A^B^C"identifier": https://h:1/p'
    ' "name":\'given\': token="system": Doe, Jane"address": \tJane Doe"address": Authorization: Bearer'
    " >OtherPatientIDs=DOE^JANE>frozenset(\"0010ABCD\": MRN: 'given': ",
    f'"given": a|b|c 1980-05-05Hunter2pw{SECRET}',
    '"given": a|b|c MRN 123456',
    # Padding with spaces split a token main's whole-token cut dropped.
    'PatientName=\nDOE^JANE^Q \'"name":<value value=[redacted]1980-05-05Doe, Jane',
    '\\</name>"telecom":123-45-6789Hunter2pwQzorvex123-45-6789"telecom":MRN 123456',
    'a|b|cA^B^C"telecom":\tQzorvex\\"telecom"::\'name\':Jane DoeIB_ACME_ADTPatientName=Hunter2pw'
    "123-45-6789IB_ACME_ADT\n[redaction bound: x],\tpassword: ",
]


@pytest.mark.parametrize("text", [*FIELD_RUN, *CUT_SHIFT])
def test_the_read_on_never_shortens_the_answer(text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """A shorter answer lets a length bound keep text it cut before, so the read-on writes each
    token it scrubs at the token's own length at least (``_padded``). Each of these is at least
    as long as with this branch's rules off."""
    ours = redact(text)
    with monkeypatch.context() as patch:
        _rules_off(patch)
        theirs = redact(text)
    assert len(ours) >= len(theirs) or ours == PLACEHOLDER, (ours, theirs)


@pytest.mark.parametrize("limit", [60, 200])
@pytest.mark.parametrize("text", CUT_SHIFT)
def test_a_cut_shift_text_prints_no_word_the_rules_off_answer_hid(
    text: str, limit: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    ours = safe_text(text, limit=limit)
    with monkeypatch.context() as patch:
        _rules_off(patch)
        theirs = safe_text(text, limit=limit)
    assert not _words(ours) - _words(theirs) - _NOTE_WORDS, (ours, theirs)


#: Texts the read-on leaves as they were: a value after the placeholder that is not the field run's.
FIELD_RUN_KEPT = [
    ('"given": a|b|c\nstep 2 done', '"given": [redacted]\nstep 2 done'),
    ('{"given": a|b|c, "status": "ok"}', '{"given": [redacted] "status": "ok"}'),
    # A label after the placeholder is left for the credential passes.
    ('"given": a|b|c token=x', '"given": [redacted] token=x'),
    # A run longer than _PLAIN_RUN_TOKENS is not read on into.
    ('"given": a|b|c ' + "w " * 17, '"given": [redacted]' + " w" * 17),
    # Under name/address the first stage keeps a scalar, and the widened stage judges its shape.
    ('{"name": a|b|c 10.1.2.3}', '{"name": [redacted] 10.1.2.3}'),
    ('{"system": [redacted] ok}', '{"system": [redacted] ok}'),
    ('"given": ["x"]\u2026(+12 chars)', '"given": ["[redacted]"]\u2026(+12 chars)'),
    ('"given": a|b|c\u2026(+12 chars)', None),
]


#: Review round-9b28b256be: trailing whitespace the answer's strip removes, which a first call
#: read as more text and a second as the end, so the read-on took the value only on the second.
TRAILING_SPACE = [
    f'"given": a|b|c {SECRET}\u2028',
    f'"given": a|b|c {SECRET}\x0b',
    f'"given": a|b|c {SECRET}\x85',
    f'"given": a|b|c {SECRET}\u3000',
    f'{{"identifier": {{"value": a|b|c {SECRET}\n',
    f'{{"identifier": {{"value": a|b|c {SECRET}\n}}}}',
]


@pytest.mark.parametrize("text", TRAILING_SPACE)
def test_trailing_whitespace_reads_as_the_end_on_both_calls(text: str) -> None:
    once = safe_text(text)
    assert SECRET not in once, once
    assert safe_text(once) == once


def _log_chain(text: str) -> str:
    """``text`` through the filters a shipped log handler runs: the redactor, then the credential
    filters after it."""
    record = logging.LogRecord("b5814", logging.WARNING, __file__, 0, "%s", (text,), None)
    for log_filter in _shipped_filters():
        log_filter.filter(record)
    return record.getMessage()


#: Review round-9b28b256be: the shipped log chain printed each secret, because the read-on wrote
#: a credential label as the placeholder and left its separator and value on the next line, or
#: took a bare ``bearer`` the whole-text gate reads.
LOG_CHAIN = [
    '"given": a|b|c token\n= QzorvexSecret1',
    '"given": a|b|c bearer\nQzorvexSecret1',
    '"given": a|b|c password\n: QzorvexSecret1',
    '"given": a|b|c api_key\n=QzorvexSecret1',
    '"given": a|b|c session\n=QzorvexSecret1',
    '"given": a|b|c MEFOR_DB_PASSWORD\n= QzorvexSecret1',
    '{"given": a|b|c x api_key\n= QzorvexSecret1, "k": 1}',
    'ValueError: bad PID: "family": DOE^JANE^Q session\n= QzorvexSecret1',
    '"given": a|b|c bearer abcd1234, a%7Cb%7Cc;sslpassword=x qzorvexpw',
]


@pytest.mark.parametrize("text", LOG_CHAIN)
def test_the_log_chain_prints_no_credential(text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    ours = _log_chain(text)
    assert "QzorvexSecret1" not in ours and "qzorvexpw" not in ours, ours
    with monkeypatch.context() as patch:
        _rules_off(patch)
        theirs = _log_chain(text)
    assert not _words(ours) - _words(theirs) - _NOTE_WORDS, (ours, theirs)


def test_the_log_chain_differential(monkeypatch: pytest.MonkeyPatch) -> None:
    """The shipped log chain runs the redactor before the credential filters, which none of
    ``_DIFF_SCRUBBERS`` does, so it is compared here too, over this file's own fuzz."""
    texts = [t for t in [*LOG_CHAIN, *_differential_fuzz(1_500)] if _JSON_PHI_KEY.search(t)]
    ours = [[_log_chain(text)] for text in texts]
    with monkeypatch.context() as patch:
        _rules_off(patch)
        theirs = [[_log_chain(text)] for text in texts]
    leaks, changed = _words_main_hid(texts, ours, theirs)
    assert not leaks, leaks[:5]
    assert changed > 20, changed


@pytest.mark.parametrize(("text", "expected"), FIELD_RUN_KEPT)
def test_the_read_on_stops_where_the_value_ends(text: str, expected: str | None) -> None:
    once = safe_text(text)
    if expected is not None:
        assert once == expected
    assert safe_text(once) == once


@pytest.mark.parametrize(
    "text",
    [
        '{"resourceType": "OperationOutcome", "name": "IB_FHIR", "diagnostics": "'
        + "word " * 60
        + '"}',
        'config error: "name": IB_ACME_ADT - can\'t open the drop folder (permission denied)',
        "2026-11-26 10:00:00 WARNING {'name': 'IB_X', 'token=[REDACTED] failed",
    ],
)
def test_a_cut_or_quoted_string_after_a_key_keeps_its_diagnostic(text: str) -> None:
    """Review round 2's controls: a cut inside a string after a PHI key, an apostrophe in prose, and a
    support-bundle placeholder are not stray closers, so the text is not blanked whole, cut or not."""
    for limit in (200, 10_000):
        once = safe_text(text, limit=limit)
        assert once != PLACEHOLDER and safe_text(once, limit=limit) != PLACEHOLDER, once


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize("text", RUN_ON)
def test_a_value_run_on_after_a_phi_container_redacts_the_whole_text(
    scrub: Callable[[str], str], text: str
) -> None:
    assert scrub(text) == PLACEHOLDER


@pytest.mark.parametrize("text", RUN_ON)
def test_origin_main_kept_each_run_on_value(text: str, monkeypatch: pytest.MonkeyPatch) -> None:
    """Positive control: with this branch's rules off, each RUN_ON text keeps its value."""
    _rules_off(monkeypatch)
    assert SECRET in redact(text)


#: Texts the run-on rule leaves legible, each a fixed point of ``safe_text``: a placeholder a scrub
#: wrote before another value, and the count note after a closed value.
KEPT = [
    '{"identifier": {"value": x y}}',
    '"given": x y',
    '{"given": [x, "y"], "family": ("a") }',
    '{"given": ["x"]\u2026(+12 chars)',
    '{"telecom": [build(t) for t in tels], "x": 1}',
]


@pytest.mark.parametrize("text", KEPT)
def test_a_kept_text_is_legible_and_a_fixed_point(text: str) -> None:
    once = safe_text(text)
    assert once != PLACEHOLDER
    assert safe_text(once) == once


@pytest.mark.xfail(
    strict=True, raises=AssertionError, reason="KNOWN RESIDUAL of BACKLOG #5814: see MISSED"
)
@pytest.mark.parametrize("text", MISSED)
def test_a_documented_miss_still_keeps_the_value(text: str) -> None:
    assert SECRET not in redact(text)


def test_the_placeholder_keeps_the_bound_note() -> None:
    """The bound note is the only sign the text was cut, so the whole-text placeholder keeps it."""
    note = "\n[redaction bound: dropped 12 more chars unscanned]"
    assert redact(f'{{"given": [Jane] {SECRET}]}}' + note) == PLACEHOLDER + note


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize("text", STRAY)
def test_a_stray_closer_redacts_the_whole_text(scrub: Callable[[str], str], text: str) -> None:
    assert scrub(text) == PLACEHOLDER


@pytest.mark.parametrize("text", STRAY)
def test_the_rule_is_a_fixed_point_of_safe_text(text: str) -> None:
    once = safe_text(text)
    assert safe_text(once) == once


#: Negative controls, each read as before. Some other balanced texts are blanked whole
#: (KNOWN_COST).
BALANCED = [
    (
        '{"family": ["Zqxdoe"], "status": "ok (1)", "id": f(1, [2], {"a": 3})}',
        '{"family": ["[redacted]"], "status": "ok (1)", "id": f(1, [2], {"a": 3})}',
    ),
    ('{"family": "a ] b"}', '{"family": "[redacted]"}'),
    ('step 1) failed: {"family": "Zqxdoe"}', 'step 1) failed: {"family": "[redacted]"}'),
    ('{"family": "Zqxdoe"} then retry 2)', '{"family": "[redacted]"} then retry 2)'),
    ('"family": "Zqxdoe"\nstep 2) done', '"family": "[redacted]"\nstep 2) done'),
]


@pytest.mark.parametrize(("text", "expected"), BALANCED)
def test_a_matched_or_out_of_scope_closer_reads_as_before(text: str, expected: str) -> None:
    assert redact(text) == expected


#: A traceback whose frame line leaves a PHI-keyed dict unclosed, and whose later frame holds a
#: mismatched closer. The key's own container never closes, so the check stays armed to the end.
TRACEBACK = (
    "Traceback (most recent call last):\n"
    '  File "app.py", line 12, in deliver\n'
    f'    send({{"family": "{SECRET}", "mrn": 7\n'
    '  File "wire.py", line 40, in send\n'
    "    raise ValueError(]\n"
    "ValueError: bad frame\n"
)

#: Some texts blanked whole beyond the PHI value: examples, not a complete list.
KNOWN_COST = [
    TRACEBACK,
    # One line of a pretty-printed body, as the support bundle redacts it, line by line.
    f'    "family": "{SECRET}"}},',
    f'"name": "{SECRET}" stopped: code 3)',
    f'"telecom": [{{"system": "{SECRET}"}}] (2 entries)',
    f'{{"family": "{SECRET}", "note": [1}}}}',
    f'"family": "{SECRET}", "note": [1}}',
    f'"family": "{SECRET}" rejected by peer (see [ref) for details',
    f'{{"family": "x"}} x {{"given": "{SECRET}", "note": [1}}',
    f'"family": "{SECRET}"\u2028(see [ref)',
    f'"family": "{SECRET}" (see [ref\n\n}}',
    # Key-shaped text inside a string.
    f'{{"note": "x \'family\': {SECRET}", "a": [1}}}}',
    # Balanced, well-formed JSON: the result is read too, and a scrub left a stray closer there.
    f'{{"family": "{SECRET}", "id": ["a|b|c", 1]}}',
    # A closer with nothing open after a top-level key.
    f'"family": "{SECRET}" step 2) failed',
    # Prose after a PHI value's container on its line.
    f"connect failed for 'address': ('10.0.0.1', 2575) after {SECRET} tries",
    f'"family": ["{SECRET}"] failed to map',
    # Source lines of a rendered traceback that build JSON with a call or an attribute.
    f'    out = {{"name": names({SECRET}).upper() if pid else None}}',
    f'        "family": {SECRET}.family}})',
]


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize("text", KNOWN_COST)
def test_a_known_cost_blanks_the_whole_text(scrub: Callable[[str], str], text: str) -> None:
    """KNOWN COST, pinned so a change to it is deliberate. The direction is safe: more is hidden.
    Before BACKLOG #5814 each kept its text."""
    assert scrub(text) == PLACEHOLDER


def _reference_walk(text: str) -> bool:
    """The check's walk as it stood before the structure-only step (engine head 79a11bc4f2b), over
    every ``_JSON_TOKEN`` token, with the two rules BACKLOG #5814's run-on build added: a line
    break inside a key does not disarm it, and an armed closer with nothing open is stray. It reads
    the live ``_JSON_TOKEN`` and ``_JSON_PHI_KEY``, so it is that walk only while those two are
    unchanged. The shipped walk must give the same verdict."""
    return _token_walk(text, run_on=True)


def _token_walk(text: str, *, run_on: bool) -> bool:
    """The token walk; ``run_on=False`` is the walk origin/main 4ad697da713 shipped."""
    keys = [m.span() for m in _JSON_PHI_KEY.finditer(text)]
    if not keys:
        return False
    stack: list[str] = []
    armed: int | None = None
    key_end = 0
    next_key = 0
    pos = 0
    while pos < len(text):
        if armed is None and next_key == len(keys):
            return False
        match = _JSON_TOKEN.match(text, pos)
        assert match is not None
        while next_key < len(keys) and keys[next_key][0] <= match.start():
            armed = len(stack) if armed is None else min(armed, len(stack))
            key_end = keys[next_key][1] if run_on else 0
            next_key += 1
        pos = match.end()
        punct = match.group("punct")
        if punct is None:
            ws = match.group("ws")
            if armed == 0 and not stack and ws is not None:
                last = max(ws.rfind("\n"), ws.rfind("\r"))
                if last >= 0 and match.start() + last >= key_end:
                    armed = None
            continue
        if punct in "{[(":
            stack.append("}" if punct == "{" else "]" if punct == "[" else ")")
        elif punct in "}])":
            if armed is not None and ((stack and stack[-1] != punct) or (not stack and run_on)):
                return True
            if stack:
                stack.pop()
            if armed is not None and len(stack) < armed:
                armed = None
    return False


def _token_structure(text: str) -> str:
    """The brackets and whitespace line breaks the reference walk reads, from ``_JSON_TOKEN``."""
    out = []
    pos = 0
    while pos < len(text):
        match = _JSON_TOKEN.match(text, pos)
        assert match is not None
        if (punct := match.group("punct")) is not None and punct in "{}[]()":
            out.append(punct)
        elif (ws := match.group("ws")) is not None:
            out.extend(char for char in ws if char in "\r\n")
        pos = match.end()
    return "".join(out)


@functools.cache
def _redaction_suite_strings() -> tuple[str, ...]:
    """Every string literal in the redaction suites, the inputs and the expected outputs alike."""
    names = re.compile(r"redact|5814|5815|safe_exc|clamp|audit_offbox|quarantine")
    found: set[str] = set()
    for path in sorted(Path(__file__).parent.glob("test_*.py")):
        if names.search(path.name):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            found.update(
                node.value
                for node in ast.walk(tree)
                if isinstance(node, ast.Constant) and isinstance(node.value, str)
            )
    return tuple(sorted(found))


def _fuzz(count: int) -> list[str]:
    """Seeded texts drawn from what either walk reads: brackets, both quotes, a backslash, line
    breaks and other whitespace, string prefixes, characters neither treats as structure, PHI keys
    and filler."""
    rng = random.Random(5814)
    parts = ["{", "}", "[", "]", "(", ")", '"', "'", "\\", "\n", "\r", " ", "\t", "\x0b", "\x0c"]
    parts += ["\x1c", "\x1f", "\x85", "\u2028", "\u2029", "\u3000", ",", ":", "x", "b'", 'B"']
    parts += ['rb"', "`", "<", ">", '"""']
    parts += ['"family": ', "'given': ", '"name":', '"0010ABCD": ']
    return ["".join(rng.choices(parts, k=rng.randint(1, 40))) for _ in range(count)]


_STRUCTURE_FUZZ = 30_000
#: How much of the structure fuzz the differential reads (see its docstring).
_DIFFERENTIAL_SHARE = 4_000


def _cases() -> list[str]:
    """This file's cases and the suites' literals, then their ``redact`` results.

    Not cached: the results come from whatever ``redact`` is live, so a cache filled while a test
    had the rules patched off would hand that test's answers to every later test. The pure part,
    the literals, is cached in :func:`_redaction_suite_strings`."""
    texts = [*STRAY, *RUN_ON, *MISSED, *FIELD_RUN, *(text for text, _ in BALANCED), *KNOWN_COST]
    texts += _redaction_suite_strings()
    return texts + [redact(text) for text in texts]


def _corpus() -> list[str]:
    """:func:`_cases`, then the structure fuzz."""
    return [*_cases(), *_fuzz(_STRUCTURE_FUZZ)]


def test_the_structure_walk_matches_the_token_walk() -> None:
    """Over this file's cases, the redaction suites' literals, their ``redact`` results and a seeded
    fuzz, ``_JSON_STRUCTURE`` captures exactly the brackets and line breaks the token walk reads,
    and the check gives the token walk's verdict."""
    verdicts = {True: 0, False: 0}
    for text in _corpus():
        captured = "".join(m.group("char") or "" for m in _JSON_STRUCTURE.finditer(text))
        assert captured == _token_structure(text), text
        verdict = _reference_walk(text)
        assert _stray_json_closer(text) == verdict, text
        verdicts[verdict] += 1
    # Positive controls: the corpus reaches both verdicts often.
    assert verdicts[True] > 500 and verdicts[False] > 500, verdicts


def _rules_off(monkeypatch: pytest.MonkeyPatch) -> None:
    """Turn this branch's rules off, which leaves the scrubber origin/main 4ad697da713 shipped."""
    monkeypatch.setattr(redaction, "_json_value_runs_on", lambda *_a, **_k: False)
    monkeypatch.setattr(redaction, "_placeholder_runs_on", lambda *_a, **_k: None)
    monkeypatch.setattr(redaction, "_policy_after_close", lambda *a: a[-1])
    monkeypatch.setattr(redaction, "_runs_on_as_received", lambda _text: False)
    monkeypatch.setattr(
        redaction, "_stray_json_closer", lambda text: _token_walk(text, run_on=False)
    )


#: Leak cases an earlier attempt at this rule had (04102211b39, reverted in 71752f81d0d), and others
#: from its review: a credential label without a colon, an unclosed opener after the value, nested
#: keys, a token a colon follows, a callable, and an unclosed piece before later lines.
LEAK_PROBES = [
    f'"given": [Jane] password= {SECRET}pw:8080',
    f'{{"given": [Jane] password= {SECRET}pw:8080}}',
    f'"family": ["x"] token={SECRET}123 Authorization= Bearer {SECRET}987',
    f'"family": ["x"] (see [ref) {SECRET}',
    f'"family": ["x"] PatientID: {SECRET}',
    f'{{"family": ["x"] [ {SECRET}',
    f'"name": [a] "given": [b] {SECRET}',
    f'{{"given": [Jane] (\n{SECRET}\nline2 Pqwerty',
]


def _differential_fuzz(count: int) -> list[str]:
    """Seeded texts mixing PHI keys, brackets, credential and DICOM labels, field runs, the
    placeholder and the count note, so both scrubbers' rules meet one another."""
    rng = random.Random(58140)
    parts = ["{", "}", "[", "]", "(", ")", '"', "'", "\\", "\n", " ", " ", "\t", ",", ":"]
    parts += ['"family": ', "'given': ", '"name":', '"address": ', '"identifier": ', '"value": ']
    parts += ['"telecom":', '"0010ABCD": ', '"system": ', SECRET, "a|b|c", "x", "IB_ACME_ADT"]
    parts += ["password=", "password: ", "token=", "Authorization: Bearer ", "https://h:1/p"]
    parts += ["PatientID: ", "PatientName=", "MRN 123456", "DOE^JANE", "PID|1||", PLACEHOLDER]
    parts += ["\u2026(+3 chars)", "frozenset(", "date(", "1980-05-05", "Doe, Jane", "<given value="]
    parts += [" a|b|c ", "DOE^JANE^Q ", "123-45-6789", "\t", "x a|b|c "]
    parts += ["\n= ", "bearer ", "bearer\n", "\u2028", "\x0b", "\x85", " api_key", "session"]
    return ["".join(rng.choices(parts, k=rng.randint(1, 30))) for _ in range(count)]


_WORD = re.compile(r"[A-Za-z0-9]{3,}")
#: The words of the placeholder and of this module's notes, which a blanked answer may carry.
_NOTE_WORDS = set(_WORD.findall(PLACEHOLDER + redaction._clamp_marker(1) + redaction._COUNT_CLOSER))


_DIFF_SCRUBBERS: list[Callable[[str], str]] = [*SCRUBBERS, lambda text: safe_text(text, limit=60)]


def _answers(texts: list[str]) -> list[list[str]]:
    return [[scrub(text) for scrub in _DIFF_SCRUBBERS] for text in texts]


def _main_answers(texts: list[str], monkeypatch: pytest.MonkeyPatch) -> list[list[str]]:
    with monkeypatch.context() as patch:
        _rules_off(patch)
        return _answers(texts)


def _words_main_hid(
    texts: list[str], ours: list[list[str]], mains: list[list[str]]
) -> tuple[list[str], int]:
    """``(leaks, changed)``: each text with an answer that prints a word the rules-off answer hid,
    and how many answers differ at all."""
    leaks: list[str] = []
    changed = 0
    for text, mine, theirs in zip(texts, ours, mains, strict=True):
        for got, main in zip(mine, theirs, strict=True):
            if got != main:
                changed += 1
                if _words(got) - _words(main) - _NOTE_WORDS:
                    leaks.append(text)
    return leaks, changed


def _words(answer: str) -> set[str]:
    """The words of ``answer`` past its count notes and the log chain's escapes. A note's number
    counts what a cut dropped, so a scrub that hides more moves it, and it is not text the answer
    printed; an escape such as ``\\u0085`` is the chain's spelling of one character, which would
    otherwise join the word after it."""
    return set(_WORD.findall(_ESCAPE.sub(" ", redaction._COUNT_NOTE.sub("", answer))))


_ESCAPE = re.compile(r"\\(?:u[0-9a-fA-F]{4}|x[0-9a-fA-F]{2}|[nrt])")


def test_no_text_prints_a_word_the_rules_off_scrubber_hid(monkeypatch: pytest.MonkeyPatch) -> None:
    """THE CONTROL'S DIFFERENTIAL. Over the corpus, the leak probes and a seeded fuzz, no scrubber
    prints a word that the rules-off form (``_rules_off``) hid. That form is origin/main
    4ad697da713's scrubber only while ``_rules_off`` names every rule this branch added; the
    build's own run against origin/main's module, kept out of the suite because it needs git, is
    recorded in its commit message. Every rule here only turns a text into the placeholder, so
    this is the check that a later change keeps it that way.

    It reads every :func:`_cases` text but only the head of the structure fuzz, for time: most of
    that fuzz holds a PHI key, and scoring all of it through every scrubber twice costs a large
    share of the per-test timeout (measured 2026-11-27). That fuzz aims at the walk's brackets,
    which :func:`test_the_structure_walk_matches_the_token_walk` reads whole, and
    :func:`_differential_fuzz` is this test's own fuzz."""
    # Seeded and drawn in order, so this is the head of the structure fuzz.
    head = _fuzz(_DIFFERENTIAL_SHARE)
    texts = [*_cases(), *head, *LEAK_PROBES, *KEPT, *_differential_fuzz(4_000)]
    # Neither rule reads a text with no PHI key, so only those can differ.
    texts = [text for text in texts if _JSON_PHI_KEY.search(text)]
    leaks, changed = _words_main_hid(texts, _answers(texts), _main_answers(texts, monkeypatch))
    assert not leaks, leaks[:5]
    # Positive control: the rules changed many answers, so the comparison saw the two apart.
    assert changed > 200, changed


def test_the_differential_sees_a_leak(monkeypatch: pytest.MonkeyPatch) -> None:
    """Negative control: a scrubber that keeps the JSON values it should hide is caught."""
    texts = [f'{{"family": "{SECRET}", "a": 1}}']
    mains = _main_answers(texts, monkeypatch)
    monkeypatch.setattr(redaction, "_redact_json_fields", lambda text, **_k: text)
    leaks, _ = _words_main_hid(texts, _answers(texts), mains)
    assert set(leaks) == set(texts)


@pytest.mark.parametrize("text", LEAK_PROBES)
def test_a_leak_probe_keeps_no_secret(text: str) -> None:
    for scrub in SCRUBBERS:
        assert SECRET not in scrub(text), (scrub, text)


def test_the_count_note_pattern_reads_the_note_safe_text_writes() -> None:
    """``_COUNT_NOTE`` spells the note ``_held_back`` writes; this pins the two together."""
    cut = redaction._held_back("word " * 100, 40)
    note = redaction._COUNT_NOTE.search(cut)
    assert note is not None and note.end() == len(cut)


def test_a_run_of_count_notes_stays_linear() -> None:
    """Review round-7c41e93b2a: a skip loop over notes rescanned every later note at each closer,
    so a peer's run of notes was quadratic. One note is skipped now; this bounds the work."""
    text = '{"identifier": {"system": [1]' + "\u2026(+1 chars)" * 3_000 + "}}"
    start = time.perf_counter()
    safe_text(text)
    assert time.perf_counter() - start < 5.0


def test_the_count_note_after_a_closed_value_is_not_a_run_on() -> None:
    """``safe_text``'s count after a closed value is not a value, so a cut answer stays legible."""
    note = "\u2026(+12 chars)"
    assert redact('{"given": ["x"]' + note) == '{"given": ["[redacted]"]' + note
