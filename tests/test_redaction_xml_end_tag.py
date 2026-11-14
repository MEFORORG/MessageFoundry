# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5925: text inside a vocabulary element's malformed end tag no longer prints.

The XML element walk copied an end tag's remainder -- everything after the tag's name up to the next
``<`` or ``>`` -- into the output as it stood. So a synthetic value inside an end tag
(``</family Zqxdoe>``) or after one that never got its ``>`` (``</family Zqxdoe``) walked through
:func:`redaction.redact`. Values here are single synthetic tokens on purpose: a two-name run is taken
by the name pass whatever the XML pass does, and the arm would pass for the wrong reason."""

from __future__ import annotations

import logging
import random
from collections.abc import Callable, Iterator
from contextlib import contextmanager

import pytest

from messagefoundry import logging_setup, redaction, secretscrub
from messagefoundry.redaction import redact, safe_exc, safe_text
from messagefoundry.support.redact import redact_log_line

#: ``id: (text, the synthetic value inside or after the end tag, the end tag's name)``.
_MALFORMED = {
    "text-inside": ("<family>Smith</family Zqxdoe>", "Zqxdoe", "</family"),
    "no-bracket-at-end": ("<family>Smith</family Zqxdoe", "Zqxdoe", "</family"),
    "no-bracket-before-tag": ("<family>Smith</family Zqxdoe<given>x</given>", "Zqxdoe", "</family"),
    "nested-child": ("<name><given>Smith</given Zqxdoe></name>", "Zqxdoe", "</given"),
    "namespaced": ("<ns:family>Smith</ns:family Zqxdoe>", "Zqxdoe", "</ns:family"),
}


@pytest.mark.parametrize(
    ("text", "value", "end_tag"), list(_MALFORMED.values()), ids=list(_MALFORMED)
)
def test_a_malformed_end_tag_strands_nothing(text: str, value: str, end_tag: str) -> None:
    out = redact(text)
    assert value not in out, out
    assert end_tag in out, out  # the tag's name stays; only its remainder is masked
    assert redact(out) == out


def _through_the_chain(text: str) -> str:
    """``text`` as a log message through the filters ``_install_phi_filters`` puts on a handler."""
    handler = logging.Handler()
    logging_setup._install_phi_filters(handler)
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert handler.filter(record)
    return record.getMessage()


def _main_end_tag_rest(text: str, start: int, stop: int) -> str:
    """The end-tag rest as main copied it, vendored: main appended ``text[tag.start():pos]``, which
    is the tag itself (still appended) followed by exactly this."""
    return text[start:stop]


@contextmanager
def _main() -> Iterator[None]:
    """The redactor as it stood before #5925: every end-tag rest copied as it stood."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "_end_tag_rest", _main_end_tag_rest)
        yield


@pytest.mark.parametrize(
    ("text", "value", "end_tag"), list(_MALFORMED.values()), ids=list(_MALFORMED)
)
def test_main_printed_each_value(text: str, value: str, end_tag: str) -> None:
    """THE POSITIVE CONTROL: before #5925 every shape above printed its value, so the green above is
    the end-tag mask's work and not a pass that caught it anyway."""
    with _main():
        assert value in redact(text)


@pytest.mark.parametrize(
    ("text", "want"),
    [
        ("<family>Smith</family Zqxdoe>", "<family>[redacted]</family Xxxxxx>"),
        ("<family>Smith</family Zqxdoe", "<family>[redacted]</family Xxxxxx"),
        ("<family>Smith</family Zqx 4455>", "<family>[redacted]</family Xxx 0000>"),
        ("<family>Smith</family >", "<family>[redacted]</family >"),
        # The rest of a bracketless tag past its own line is copied as it stood.
        (
            "<family>Smith</family Zqxdoe\nretry 3 of 5 after 200 ms",
            "<family>[redacted]</family Xxxxxx\nretry 3 of 5 after 200 ms",
        ),
    ],
)
def test_the_rest_is_masked_in_place(text: str, want: str) -> None:
    """Masked character for character, as :data:`redaction._SHAPE` masks a glued value: the same
    length, whitespace and class, so a cut, a later pass or a caller's text reads it as main's."""
    assert redact(text) == want


#: Rests that stay as main left them, the stated residual: punctuation, a word a pass reads
#: literally, a date, a tab before the word, and a word on a later line inside the tag.
_KEPT = {
    "comma": "<family>Smith</family Zq, Zqxdoe>",
    "credential-label": "<family>Smith</family password: Zqxdoe>",
    "anchor-word": "<family>Smith</family Bearer Zqxdoe>",
    "date": "<family>Smith</family 1980-05-05 Zqxdoe>",
    "tab": "<family>Smith</family\tZqxdoe>",
    "later-line": "<family>Smith</family\nZqxdoe>",
}


@pytest.mark.parametrize("text", list(_KEPT.values()), ids=list(_KEPT))
def test_a_rest_a_pass_could_read_differently_stays_as_main_left_it(text: str) -> None:
    with _main():
        main = redaction._redact_xml_elements(text)
    assert redaction._redact_xml_elements(text) == main


def test_a_credential_label_in_the_rest_still_reaches_the_credential_filter() -> None:
    """The credential filters after :func:`redact` read the label, so a mask that took it would print
    the value after it: the rest stays, and the filter scrubs the value as on main."""
    out = secretscrub.scrub_credentials(redact("<family>Smith</family password: <s3cr3tvalue99>"))
    assert "s3cr3tvalue99" not in out


# --- THE GATE: a differential fuzz against main, composed joins included ------------------------
#
# A redaction change that REPLACES text with a placeholder cannot be shown to redact at least what
# main did: once a redacted fragment is joined to raw text and redacted again, a name run main would
# have formed across the join is gone and the joined value prints. The previous attempt at #5925
# passed a per-text differential and failed exactly there. So the fuzz below composes: for generated
# ``a`` and ``raw``, every route over ``redact(a) + raw`` (and ``a + raw``, and the log chain's
# output plus ``raw``) is compared with main's same route, value by value.

_VALUES = ("Zqxdoe", "Vandtjane", "Plantone", "Kplm7", "Qwerty12", "s3cr3tvalue99", "4455667")
_STARTS = (
    "<family>", "<given>", "<name>", "<name><given>", "<ns:family>", "<telecom>", "x <family>",
    "<family> ", '<identifier><system value="urn:x">', "<identifier><value>",
)  # fmt: skip
_CONTENT = ("Smith", "Smith Doe", "", "1980", "Doe\n", "A^B^C", "(0010,1000) Doe")
_ENDS = ("</family", "</given", "</other", "</ns:family", "</name", "</system", "</value")
_LABELS = (
    "password:", "password: ", "token=", "Bearer ", "Authorization: Bearer ", "MRN ", "MRN: ",
    "mrn=", '"name": "', "'family': '", "(0010,0010) ", "PatientName=", "PatientID: ", "id=",
    "api_key=", "MEFOR_DB_PASSWORD=", "nonnumeric port: '", "MSH|^~\\&|", "MSH*$~\\#*", "user:",
    "OtherPatientIDs=", "Patient Name ", "secret ", "mfb64:v1:",
)  # fmt: skip
_SEPARATORS = (
    " ", " ", "", "\t", "\n", "\r\n", "<", "<b>", ">", "> ", "</family>", "<given>", '"', "'", ",",
    ";", "&", "|", "^", "{", "}", "[", "]", "$", "*", "\\", ".", "-", "/", ":", "=", " for ",
)  # fmt: skip
_WORDS = ("Smith", "John", "retry", "after", "of", "Doe", "ms", "Zq", "for", "peer", "O'Brien")


def _fragment(rand: random.Random, *, element: bool) -> str:
    """Generated text: with ``element``, a vocabulary element and a malformed end tag first; then
    labels, words, values, separators and more end tags."""
    parts: list[str] = []
    if element:
        if rand.random() < 0.3:
            parts.append(rand.choice(_LABELS) + rand.choice(('"', "'", "{", "", " ")))
        parts += [rand.choice(_STARTS), rand.choice(_CONTENT), rand.choice(_ENDS)]
        parts.append(rand.choice((" ", " ", " ", "", "\t")))
    for _ in range(rand.randint(1, 7)):
        pick = rand.random()
        if pick < 0.3:
            parts.append(rand.choice(_SEPARATORS))
        elif pick < 0.45:
            parts.append(rand.choice(_LABELS))
        elif pick < 0.55:
            parts.append(rand.choice(_ENDS) + " ")
        elif pick < 0.75:
            parts.append(rand.choice(_WORDS) + rand.choice((" ", "")))
        else:
            parts.append(rand.choice(_VALUES) + rand.choice((" ", "", ">")))
    return "".join(parts)


def _routes(text: str) -> dict[str, str]:
    """``text`` by the routes a log line or a stored error takes, at least these."""
    chained = _through_the_chain(text)
    return {
        "redact": redact(text),
        "redact twice": redact(redact(text)),
        "chain": chained,
        "two handlers": _through_the_chain(chained),
        "credential filter": secretscrub.scrub_credentials(redact(text)),
        "bundle": redact_log_line(chained),
        "store": safe_text(safe_exc(ValueError(text))),
        "safe_text 60": safe_text(text, limit=60),
    }


def _composed(a: str, raw: str) -> dict[str, str]:
    """Every route over ``a`` alone and over ``a`` joined to ``raw`` three ways: raw, after one
    :func:`redact`, and after the log chain."""
    routes: dict[str, str] = {}
    for name, text in (
        ("a", a),
        ("a + raw", a + raw),
        ("redact(a) + raw", redact(a) + raw),
        ("chain(a) + raw", _through_the_chain(a) + raw),
        ("safe_exc(a) + raw", safe_exc(ValueError(a)) + raw),
    ):
        for route, out in _routes(text).items():
            routes[f"{name} by {route}"] = out
    return routes


def _differential(
    trials: int, seed: int, mask: Callable[[str, int, int], str] | None = None
) -> tuple[list[str], int, list[str]]:
    """``(leaks, gains, unmasked)`` over ``trials`` composed texts: each ``route: value`` the shipped
    redactor prints and main does not, how many it hides that main printed, and each route whose
    output is not main's with some letters and digits masked (:func:`_is_main_masked`). ``mask``
    replaces :func:`redaction._end_tag_rest`, for the control."""
    rand = random.Random(seed)  # seeded: a flaky PHI arm gets muted, so this one cannot flake
    leaks: list[str] = []
    unmasked: list[str] = []
    gains = 0
    for _ in range(trials):
        a = _fragment(rand, element=True)
        raw = _fragment(rand, element=rand.random() < 0.3)
        with _main():
            before = _composed(a, raw)
        with pytest.MonkeyPatch.context() as patch:
            if mask is not None:
                patch.setattr(redaction, "_end_tag_rest", mask)
            after = _composed(a, raw)
        for route, out in after.items():
            if not _is_main_masked(out, before[route]):
                unmasked.append(f"{route}: {a!r} + {raw!r}")
            for value in _VALUES:
                if value in out and value not in before[route]:
                    leaks.append(f"{route}: {value} in {a!r} + {raw!r}")
                elif value in before[route] and value not in out:
                    gains += 1
    return leaks, gains, unmasked


def _is_main_masked(out: str, main: str) -> bool:
    """Whether ``out`` is ``main`` with some letters and digits masked to their class, and nothing
    else changed: then no value main hid can print, by construction rather than by a value list."""
    return len(out) == len(main) and all(
        a == b or (b.isascii() and b.isalnum() and a == b.translate(redaction._SHAPE))
        for a, b in zip(out, main, strict=True)
    )


def _replace_rest(text: str, start: int, stop: int) -> str:
    """The CONTROL: a rest REPLACED by the placeholder wherever it holds a word, the design the
    previous attempt took. It is not class-preserving, so the fuzz must find it leaking."""
    rest = text[start:stop]
    return (
        f" {redaction._REDACTED}{'>' if rest.endswith('>') else ''}" if rest.strip(" >") else rest
    )


def test_the_end_tag_mask_redacts_at_least_what_main_did_through_composed_joins() -> None:
    """THE GATE for #5925: over generated vocabulary elements with malformed end tags, joined to raw
    text and redacted again by every route, every output is main's with some letters and digits
    masked, so no value main hid prints. The gain count shows the mask is exercised; the replacing
    control shows the corpus can produce the composed-join leak.

    Measured at 1,500 trials: 0 leaks, 0 unmasked routes and 7,856 values hidden that main printed,
    against 610 leaks on the control. 20,000 more trials over four other seeds, run by hand, also
    found 0 leaks. These are measurements of this corpus, not a proof for every input."""
    leaks, gains, unmasked = _differential(1_500, 5925)
    control, _, _ = _differential(1_500, 5925, mask=_replace_rest)
    assert control, "the replacing control leaked nothing, so the corpus cannot find the leak"
    assert gains, "the mask hid nothing main printed, so #5925 is not exercised"
    assert not leaks, leaks[:5]
    assert not unmasked, unmasked[:5]


def test_a_composed_join_adds_no_gap_main_did_not_have() -> None:
    """On vocabulary content, where ``redact(a + raw)`` hides a value and ``redact(redact(a) + raw)``
    prints it, main's ``redact(redact(a) + raw)`` printed it too: the mask adds no composed-join gap
    of its own. The gaps there are main's, counted so the arm is not vacuous; the residual pin below
    names their cause."""
    rand = random.Random(59250)
    regressions: list[str] = []
    gaps = 0
    for _ in range(1_500):
        a = _fragment(rand, element=True)
        raw = _fragment(rand, element=False)
        with _main():
            main_joined = redact(redact(a) + raw)
        whole, joined = redact(a + raw), redact(redact(a) + raw)
        for value in _VALUES:
            if value not in whole and value in joined:
                gaps += 1
                if value not in main_joined:
                    regressions.append(f"{value} in {a!r} + {raw!r}")
    assert gaps, "no composed-join gap at all, so the corpus does not reach the case"
    assert not regressions, regressions[:5]


def test_an_element_whose_text_was_redacted_reads_as_prose_on_a_second_call() -> None:
    """A STATED RESIDUAL, main's as well as this fix's. An element that no well-formed end tag closes
    is walked only on evidence, and ``[redacted]`` opening its text is not evidence, so a second
    call reads it as prose and an end-tag rest joined after it is not masked. The whole text masks
    it; the composed join prints it, on main too."""
    a, raw = "api_key={<given>1980</name Smith of ", "Kplm7>"
    assert "Kplm7" not in redact(a + raw)
    assert "Kplm7" in redact(redact(a) + raw)
    with _main():
        assert "Kplm7" in redact(redact(a) + raw)


def test_the_mask_is_a_fixed_point() -> None:
    rand = random.Random(925)
    for _ in range(2_000):
        once = redact(_fragment(rand, element=True))
        assert redact(once) == once, once
