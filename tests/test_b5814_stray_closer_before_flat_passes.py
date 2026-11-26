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
import random
import re
from collections.abc import Callable
from pathlib import Path

import pytest

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

#: Stray closers the check is documented to miss (``_stray_json_closer``'s docstring). Strict, so a
#: change that catches one turns this red and the docstring and changelog move with it.
MISSED = [
    f'"given": [Jane] {SECRET}]',  # no container open: the head was cut
    f'{{"given": [x] {SECRET}}}}}',  # the key's own container's kind
    f'can\'t map {{"given": [Jane] {SECRET}]}}',  # a string opened before the key
    f'{{"given": [Jane] {SECRET}\']}}',  # a quote in the value hides the closer
    f'{{"given": [Jane] {SECRET}"]}}',
    # A top-level key whose colon is on the next line: the walk disarms at that line break.
    f'"telecom"\n: [a|b|c ) , {{"value": "{SECRET}"}}]',
]


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


@pytest.mark.xfail(strict=True, reason="KNOWN RESIDUAL of BACKLOG #5814: see _stray_json_closer")
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


#: Negative controls: balanced JSON, a closer in a string, a closer in prose before the key, and a
#: closer in prose after the key's container closed are all read as before.
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

#: The check is not scoped to the PHI value: a malformed sibling, prose after a top-level key, and
#: a later key arming the walk again after the first key's container closed, then a malformed
#: sibling of that key; and a U+2028 line separator, which does not disarm a top-level key.
KNOWN_COST = [
    TRACEBACK,
    f'{{"family": "{SECRET}", "note": [1}}}}',
    f'"family": "{SECRET}", "note": [1}}',
    f'"family": "{SECRET}" rejected by peer (see [ref) for details',
    f'{{"family": "x"}} x {{"given": "{SECRET}", "note": [1}}',
    f'"family": "{SECRET}"\u2028(see [ref)',
]


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize("text", KNOWN_COST)
def test_a_known_cost_blanks_the_whole_text(scrub: Callable[[str], str], text: str) -> None:
    """KNOWN COST, pinned so a change to it is deliberate (``_stray_json_closer``'s docstring names
    it). The direction is safe: more is hidden. Before BACKLOG #5814 each kept its text."""
    assert scrub(text) == PLACEHOLDER


def _reference_walk(text: str) -> bool:
    """The check's walk as it stood before the structure-only step (engine head 79a11bc4f2b), over
    every ``_JSON_TOKEN`` token. It reads the live ``_JSON_TOKEN`` and ``_JSON_PHI_KEY``, so it is
    that walk only while those two are unchanged. The shipped walk must give the same verdict."""
    keys = [match.start() for match in _JSON_PHI_KEY.finditer(text)]
    if not keys:
        return False
    stack: list[str] = []
    armed: int | None = None
    next_key = 0
    pos = 0
    while pos < len(text):
        if armed is None and next_key == len(keys):
            return False
        match = _JSON_TOKEN.match(text, pos)
        assert match is not None
        while next_key < len(keys) and keys[next_key] <= match.start():
            armed = len(stack) if armed is None else min(armed, len(stack))
            next_key += 1
        pos = match.end()
        punct = match.group("punct")
        if punct is None:
            ws = match.group("ws")
            if armed == 0 and not stack and ws is not None and ("\n" in ws or "\r" in ws):
                armed = None
            continue
        if punct in "{[(":
            stack.append("}" if punct == "{" else "]" if punct == "[" else ")")
        elif punct in "}])":
            if stack and stack[-1] != punct and armed is not None:
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


def _redaction_suite_strings() -> list[str]:
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
    return sorted(found)


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


def _corpus() -> list[str]:
    """This file's cases and the suites' literals with their ``redact`` results, then the fuzz."""
    texts = [*STRAY, *MISSED, *(text for text, _ in BALANCED), *KNOWN_COST]
    texts += _redaction_suite_strings()
    return texts + [redact(text) for text in texts] + _fuzz(30_000)


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
