# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The JSON value scrubber ends a container only on the closer that opened it (BACKLOG #5814).

Before the fix its open-container stack popped on ANY of ``}``, ``]`` and ``)``, so a stray closer of
the wrong kind inside a PHI-keyed value ended the scrub early, and a single-token name after it walked
through ``redact``, ``safe_text`` and the bundle's ``redact_log_line`` on defaults. Every value here is
synthetic and invented for the test; none is name-, date- or HL7-shaped, so only the JSON pass can
earn its removal.
"""

from __future__ import annotations

import random
from collections.abc import Callable

import pytest

from messagefoundry.redaction import redact, safe_text
from messagefoundry.support.redact import redact_log_line

FAMILY = "Zqxdoe"
GIVEN = "Janex"

SCRUBBERS: list[Callable[[str], str]] = [redact, safe_text, redact_log_line]


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize(
    "text",
    [
        f'{{"family": ["{FAMILY}" ) "{GIVEN}"]}}',
        f'{{"family": ["{FAMILY}" }} "{GIVEN}"]}}',
        f'{{"family": {{"a": "{FAMILY}" ] , "b": "{GIVEN}"}}}}',
        f'{{"family": {{"a": "{FAMILY}" ) , "b": "{GIVEN}"}}}}',
        f'{{"family": f("{FAMILY}" ] , "{GIVEN}")}}',
    ],
)
def test_a_mismatched_closer_does_not_end_the_scrub(scrub: Callable[[str], str], text: str) -> None:
    out = scrub(text)
    assert FAMILY not in out
    assert GIVEN not in out
    assert '"family"' in out  # the key an operator reads survives


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize(
    "text",
    [
        # A frame that keeps what it holds (the INHERIT members of an identifier or telecom) and an
        # identifier array both rise to LEAF on a stray closer rather than ending or staying as they
        # were, so neither the identifier's own value nor a later key's value is kept.
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
    ],
)
def test_a_mismatched_closer_never_lowers_the_scrub_level(
    scrub: Callable[[str], str], text: str
) -> None:
    out = scrub(text)
    assert "Qmrnxq" not in out
    assert FAMILY not in out
    assert GIVEN not in out


@pytest.mark.parametrize("scrub", SCRUBBERS)
def test_a_matched_closer_still_ends_the_value(scrub: Callable[[str], str]) -> None:
    """Negative control: text after a properly closed PHI value is outside it and stays as written."""
    text = f'{{"family": ["{FAMILY}"], "status": "Kept-{GIVEN}"}}'
    out = scrub(text)
    assert FAMILY not in out
    assert f"Kept-{GIVEN}" in out


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
