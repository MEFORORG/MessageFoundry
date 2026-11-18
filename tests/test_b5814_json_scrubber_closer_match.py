# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""A JSON value with a mismatched closer makes the whole text redacted (BACKLOG #5814).

Before the fix the scrubber's open-container stack popped on ANY of ``}``, ``]`` and ``)``, so a stray
closer of the wrong kind inside a PHI-keyed value ended the scrub early, and a single-token name after
it walked through ``redact``, ``safe_text`` and the bundle's ``redact_log_line`` on defaults. Every
value here is synthetic and invented for the test.
"""

from __future__ import annotations

import random
from collections.abc import Callable

import pytest

from messagefoundry.redaction import redact, safe_text
from messagefoundry.support.redact import redact_log_line

FAMILY = "Zqxdoe"
GIVEN = "Janex"
#: What :func:`redact` substitutes, here for the whole text.
PLACEHOLDER = "[redacted]"

SCRUBBERS: list[Callable[[str], str]] = [redact, safe_text, redact_log_line]

#: Texts whose JSON walk meets a closer of the wrong kind. Each was a leak shape on origin/main or on
#: an earlier head of this branch; every one is now the placeholder alone.
MISMATCHED = [
    # The two the label-keeping walks could not close: a later pass scrubbed text BEFORE the
    # mismatch from an anchor after it.
    'nonnumeric port: \'SECRETPW {"family": ["' + "A" * 300 + "\" ) @host'",
    '<given> Qmrnxq {"family": ["x" ) </given>',
    # A stray closer ended the scrub early.
    f'{{"family": ["{FAMILY}" ) "{GIVEN}"]}}',
    f'{{"family": ["{FAMILY}" }} "{GIVEN}"]}}',
    f'{{"family": {{"a": "{FAMILY}" ] , "b": "{GIVEN}"}}}}',
    f'{{"family": {{"a": "{FAMILY}" ) , "b": "{GIVEN}"}}}}',
    f'{{"family": f("{FAMILY}" ] , "{GIVEN}")}}',
    # A stray closer handed what followed to a frame or a later key that kept it.
    '{"identifier": {"system": [1, 2), "value": "Qmrnxq"}}',
    '{"identifier": [{"system": "x" ] "Qmrnxq"}]',
    '{"identifier": {"system": "x" ) , "value": "Qmrnxq"}}',
    '{"identifier": {"system": "x" ] , "value": "Qmrnxq"}}',
    '{"telecom": {"system": "phone" ] , "value": "Qmrnxq"}}',
    '{"identifier": {"type": {"text": "x" ] }, "value": "Qmrnxq"}}',
    f'{{"identifier": {{"system": [1, 2)}}, "family": "{FAMILY}", "birthDate": "Qmrnxq"}}',
    f'{{"telecom": [{{"use": f(]}}], "given": "{GIVEN}", "family": "{FAMILY}"}}',
    f'{{"identifier": [{{"system": "urn:x", "value": "1"}}}}, "name": [{{"text": "{FAMILY}"}}]}}',
    f"{{'identifier': ['x' }}, 'family': {{'{FAMILY}'}}}}",
    f'{{"identifier": {{"system": [["x" }}], "family": "{GIVEN}"}}}}',
    f'{{"telecom": {{"system": [("x" ]), "given": "{GIVEN}"}}}}',
    f'{{"identifier": {{"system": [["x" }}], "00100010": "{GIVEN}"}}}}',
    f'{{"name": {{"x" ] "family": "{GIVEN}": 1}}}}',
    f'{{"family": ["x" ) {GIVEN}(1)]}}',
    f'{{"identifier": {{"system": "x" ] , "{GIVEN}": 1}}}}',
    # A label inside the walk whose value lies past the walk's end.
    '{"family": ["x" ) PatientID: ] Qmrnxq',
    '{"family": ["x" ) PatientName=x ] Qmrnxq',
    '{"family": ["x" ) \'PatientID\': ] Qmrnxq',
    '{"family": ["x" ) (0010,0020) ] Qmrnxq',
    '{"family": ["x" ) (0010, 1040) ] Qmrnxq',
    '{"family": ["x" ) "(0010,0020) a" ] Qmrnxq',
    '{"family": ["x" ) <given>Qa ] Qmrnxq',
    '{"family": ["x" ) <ns:given>Qa ] Qmrnxq',
    '{"identifier": ["x" ) <name value=:]Qmrnxq',
    '{"family": ["x" ) <telecom value=:]Qmrnxq',
    '{"identifier": [{"system": {"a": "x" ] , "b": "PatientID=1" }}] Qmrnxq',
    '{"family": [["x" ) ) [[ ] PatientID: ]]] Qmrnxq',
    '{"family": [["x" ) ) [[ ] <given>Qa ]]] Qmrnxq',
    f'{{"family": ["x" ) {FAMILY}<given>{GIVEN}</given> {FAMILY}/PatientID=Qmrnxq ]',
    # A label before the walk whose value ended inside it.
    '<given>Zq {"family": [["x" ) </given> ]] Qmrnxq',
    '<given>Zq {"family": [["x" ) </given junk> ]] Qmrnxq',
    'PatientName=Zq {"family": [["x" ) PatientID=a;b ]] Qmrnxq',
    'PatientName=Zq {"family": [["x" ) "PatientID=a;b" ]] Qmrnxq',
    'PatientName=Zq {"family": [["x" ) <telecom value=1/> ]] Qmrnxq',
    '<given>Zq {"family": ["x" ) "family": ["</given>" ] ] Qmrnxq',
    'PatientName=Zq {"family": ["x" ) "given": "PatientID=a;b" ] Qmrnxq',
]


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize("text", MISMATCHED)
def test_a_mismatched_closer_redacts_the_whole_text(scrub: Callable[[str], str], text: str) -> None:
    assert scrub(text) == PLACEHOLDER


@pytest.mark.parametrize("text", MISMATCHED)
def test_the_whole_text_rule_is_a_fixed_point_of_safe_text(text: str) -> None:
    once = safe_text(text)
    assert safe_text(once) == once


@pytest.mark.parametrize("scrub", SCRUBBERS)
def test_a_matched_closer_leaves_ordinary_json_as_it_was(scrub: Callable[[str], str]) -> None:
    """Negative control: ordinary JSON is scrubbed as before, and text after a properly closed PHI
    value is outside it and stays as written."""
    text = f'{{"family": ["{FAMILY}"], "status": "Kept-{GIVEN}", "id": f(1, [2], {{"a": 3}})}}'
    out = scrub(text)
    assert FAMILY not in out
    assert out == '{"family": ["[redacted]"], "status": "Kept-Janex", "id": f(1, [2], {"a": 3})}'


def test_fuzz_stray_closers_never_end_a_never_closed_array() -> None:
    """A ``family`` array that is never closed by ``]`` holds every name after it, whatever stray
    ``)`` and ``}`` the peer puts between them. The result is also a fixed point of :func:`safe_text`,
    which the store chokepoint relies on."""
    rng = random.Random(5814)
    pieces = [f'"{FAMILY}"', f'"{GIVEN}"', ",", " ", ")", "}"]
    for _ in range(300):
        body = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 24)))
        text = f'{{"family": [{body}'
        for scrub in SCRUBBERS:
            out = scrub(text)
            assert FAMILY not in out and GIVEN not in out, (text, out)
        once = safe_text(text, limit=10_000)  # no cut: the cut note is a known exception
        assert safe_text(once, limit=10_000) == once, text


def test_fuzz_identifier_array_never_closed_scrubs_every_value() -> None:
    """An identifier's kept (INHERIT) objects meet stray closers too. While its array is never
    closed by ``]``, every ``value`` in it is scrubbed, whichever closer ends an object, and a fixed
    point holds."""
    rng = random.Random(58140)
    pieces = ['"system": "x"', '"value": "Qmrnxq"', ",", " ", ")", "}", "{"]
    for _ in range(300):
        body = "".join(rng.choice(pieces) for _ in range(rng.randint(1, 16)))
        text = f'{{"identifier": [{{{body}'
        for scrub in SCRUBBERS:
            out = scrub(text)
            assert "Qmrnxq" not in out, (text, out)
        once = safe_text(text, limit=10_000)  # no cut: the cut note is a known exception
        assert safe_text(once, limit=10_000) == once, text
