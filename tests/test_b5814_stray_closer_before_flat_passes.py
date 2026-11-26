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

from collections.abc import Callable

import pytest

from messagefoundry.redaction import redact, safe_text
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
