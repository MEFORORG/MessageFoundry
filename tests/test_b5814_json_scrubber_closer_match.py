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
        # After a stray closer the walk scrubs every data token until its own frames close, so
        # neither an identifier's own value, nor a later key's value, nor a key or a callable name
        # in between is kept, whichever frame (INHERIT or not, nested or not) the closer landed in.
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
    ],
)
def test_a_mismatched_closer_hands_nothing_to_a_frame_that_keeps_it(
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


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize(
    "text",
    [
        # After the stray `)` the walk runs on to the array's own `]`, so `Qmrnxq` lies past it and
        # only the later pass that reads the label in between scrubs it. Scrubbing the label inside
        # the walk left `Qmrnxq` in view.
        '{"family": ["x" ) PatientID: ] Qmrnxq',  # a DICOM keyword label
        '{"family": ["x" ) PatientName=x ] Qmrnxq',  # the label and its value in one token
        '{"family": ["x" ) \'PatientID\': ] Qmrnxq',  # a quoted keyword, as a dict key
        '{"family": ["x" ) (0010,0020) ] Qmrnxq',  # a dump tag
        '{"family": ["x" ) (0010, 1040) ] Qmrnxq',  # a dump tag past element 00xx, widened
        '{"family": ["x" ) "(0010,0020) a" ] Qmrnxq',  # a dump tag inside a string
        '{"family": ["x" ) <given>Qa ] Qmrnxq',  # an XML start tag, its content opening at once
        '{"family": ["x" ) <ns:given>Qa ] Qmrnxq',  # a prefixed one
        '{"identifier": ["x" ) <name value=:]Qmrnxq',  # an XML attribute the element scrubs
        '{"family": ["x" ) <telecom value=:]Qmrnxq',  # `value`, the one a telecom scrubs
    ],
)
def test_a_label_inside_a_malformed_walk_still_anchors_the_pass_after_it(
    scrub: Callable[[str], str], text: str
) -> None:
    out = scrub(text)
    assert "Qmrnxq" not in out, out


@pytest.mark.parametrize("scrub", SCRUBBERS)
def test_the_label_is_kept_and_what_surrounds_it_in_the_token_is_not(
    scrub: Callable[[str], str],
) -> None:
    """The kept label is only the label: a name glued before it, or a value after it in the same
    token, is scrubbed with the rest of the walk."""
    out = scrub(f'{{"family": ["x" ) {FAMILY}<given>{GIVEN}</given> {FAMILY}/PatientID=Qmrnxq ]')
    assert FAMILY not in out and GIVEN not in out and "Qmrnxq" not in out, out
    assert "<given>" in out and "PatientID=" in out, out


@pytest.mark.parametrize("scrub", SCRUBBERS)
@pytest.mark.parametrize(
    "text",
    [
        # The walk before BACKLOG #5814 scrubbed these labels, since the stray `)` left it inside
        # the outer array. Kept, each would end a value a later pass scrubs before `Qmrnxq`: an end
        # tag closes the element, a `;` or a `Label=` ends a DICOM label's value.
        '<given>Zq {"family": [["x" ) </given> ]] Qmrnxq',
        '<given>Zq {"family": [["x" ) </given junk> ]] Qmrnxq',
        'PatientName=Zq {"family": [["x" ) PatientID=a;b ]] Qmrnxq',
        'PatientName=Zq {"family": [["x" ) "PatientID=a;b" ]] Qmrnxq',
        'PatientName=Zq {"family": [["x" ) <telecom value=1/> ]] Qmrnxq',
    ],
)
def test_a_label_the_older_walk_scrubbed_is_still_scrubbed(
    scrub: Callable[[str], str], text: str
) -> None:
    out = scrub(text)
    assert "Qmrnxq" not in out, out


#: Labels a later pass reads, each followed by the value it scrubs. ``{}`` is the secret.
_LABELLED = [
    "PatientID: {}",
    "PatientName={}",
    "PatientAddress: {}",
    "'PatientID': '{}'",
    "(0010,0020) {}",
    "(0010, 0010) {}",
    "(0010,2154) {}",
    "<given>{}</given>",
    "<family>{}",
    "<ns:name>{}</ns:name>",
    '<given value="{}"/>',
    '<identifier system="x" value="{}"/>',
]
#: A label and its value, split where the walk's own closers go.
_SPLIT_LABELLED = [
    ("PatientID: ", " {}"),
    ("PatientName=", " {}"),
    ("(0010,0020) ", " {}"),
    ("(0010, 1040) ", " {}"),
    ("<given>Qa", " {}</given>"),
    ("<name value=", "{}"),
]
_OPENERS = {"[": "]", "(": ")", '{"k": ': "}"}


def _labelled_case(rng: random.Random, serial: int) -> tuple[str, list[str]]:
    """A leaf value inside one to three containers that a stray closer leaves open, closed properly
    after, then more text. Every secret is either a data token inside the walk or the value a label
    holds, inside the walk or after it, so every one is a token some pass scrubs."""
    secrets: list[str] = []

    def secret() -> str:
        token = f"Qz{serial:04d}x{len(secrets):02d}k".replace("0", "q").replace("1", "w")
        secrets.append(token)
        return token

    openers = [rng.choice(list(_OPENERS)) for _ in range(rng.randint(1, 3))]
    closers = [_OPENERS[opener] for opener in reversed(openers)]
    stray = [closer for closer in "])}" if closer != closers[0]]
    parts = [f'{{"{rng.choice(["family", "given", "birthDate", "00100020"])}": ', *openers]
    for _ in range(rng.randint(1, 8)):
        roll = rng.random()
        if roll < 0.3:
            parts.append(rng.choice(stray))
        elif roll < 0.6:
            parts.append(rng.choice(_LABELLED).format(secret()))
        else:
            parts.append(rng.choice(['"{}"', "{}", "'{}'"]).format(secret()))
        parts.append(rng.choice([" ", ", ", " , "]))
    split = rng.choice([None, *_SPLIT_LABELLED])
    if split is not None:
        # The label inside the walk and its value past the walk's end, where only the pass that
        # reads the label scrubs it. One stray closer per container first, so the label lies past
        # the point where a walk that let any closer end a container returned.
        parts.extend(rng.choice(stray) for _ in openers)
        parts.extend((" ", split[0]))
    parts.extend(closers)
    if split is not None:
        parts.append(split[1].format(secret()))
    for index in range(rng.randint(0, 2)):
        # One label to a line after the first: a label's value runs to the line end, and one that
        # swallows the next label strands that label's value on origin/main as well.
        parts.append(rng.choice(["", "] ", ") ", "} "]))
        parts.insert(len(parts) - 1, " " if index == 0 else "\n")
        parts.append(rng.choice(_LABELLED).format(secret()))
    return "".join(parts), secrets


def test_fuzz_labels_in_and_after_an_outer_closed_malformed_walk() -> None:
    """Containers a stray closer leaves open, closed properly afterwards, with DICOM and XML labels
    inside the walk and after it. Asserting that no secret survives is a floor at least as high as
    origin/main's, whatever main's :func:`redact` removed of them, without importing main here.
    Measured against origin/main's module on 2026-11-18: of this seed's 400 cases main leaked a
    secret in 81, and in 0 did a secret main removed survive here. The result is also a fixed
    point of :func:`safe_text`."""
    rng = random.Random(58141)
    for serial in range(400):
        text, secrets = _labelled_case(rng, serial)
        for scrub in SCRUBBERS:
            out = scrub(text)
            assert not [token for token in secrets if token in out], (text, out)
        once = safe_text(text, limit=10_000)  # no cut: the cut note is a known exception
        assert safe_text(once, limit=10_000) == once, text
