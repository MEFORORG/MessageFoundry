# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5925: text inside a vocabulary element's malformed end tag is masked where the XML pass sees it.

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


def _main_end_tag_rest(text: str, start: int, stop: int, mask: bool) -> str:
    """The end-tag rest as main copied it, vendored: main appended ``text[tag.start():pos]``, which
    is the tag itself (still appended) followed by exactly this."""
    return text[start:stop]


@contextmanager
def _main() -> Iterator[None]:
    """The redactor as it stood before #5925: every end-tag rest copied as it stood, and a round
    ending only where the structured passes changed nothing. With no mask, that is
    :func:`redaction._masked_only` always False, so a fault in that gate cannot move this baseline
    with the redactor it is compared against (code review round 2)."""
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "_end_tag_rest", _main_end_tag_rest)
        patch.setattr(redaction, "_masked_only", _never_masked_only)
        yield


def _never_masked_only(text: str, flat: str, *, widened: bool) -> bool:
    """Main's round gate: no change is a mask alone, so only ``text == flat`` ends a round."""
    return False


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
        # Names ending in a letter a boundary-free word starts with, and short ones, are masked
        # inside a tag: nothing can join the last word before its ``>``.
        ("<family>Smith</family Johnson>", "<family>[redacted]</family Xxxxxxx>"),
        ("<given>Smith</given Li>", "<given>[redacted]</given Xx>"),
        # A vocabulary end tag outside a walked element: after the element closed, or with its start
        # tag cut away.
        (
            "<family>Smith</family></family Zqxdoe>",
            "<family>[redacted]</family></family Xxxxxx>",
        ),
        ("Smith</family Zqxdoe> tail", "Smith</family Xxxxxx> tail"),
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


#: Rests that stay as main left them, the stated residual, at least these: punctuation, a word a
#: pass reads literally, a credential word inside a longer word, a date, a tab or a non-ASCII letter,
#: a word on a later line inside the tag, and at the end of the text, a last word a caller's text
#: could complete (a digit, a boundary-free word's head, a camelCase credential label's head).
_KEPT = {
    "comma": "<family>Smith</family Zq, Zqxdoe>",
    "credential-label": "<family>Smith</family password: Zqxdoe>",
    "anchor-word": "<family>Smith</family Bearer Zqxdoe>",
    "camel-credential": "<family>Smith</family userPwd>",
    "date": "<family>Smith</family 1980-05-05 Zqxdoe>",
    "tab": "<family>Smith</family\tZqxdoe>",
    "tab-after": "<family>Smith</family Zqxdoe\t>",
    "non-ascii": "<family>Smith</family Zqxödoe>",
    "later-line": "<family>Smith</family\nZqxdoe>",
    "segment-id-head": "<family>Smith</family ZqMSH>",
    "end-digit": "<family>Smith</family Zqx 4455",
    "end-head": "<family>Smith</family Johnson",
    "end-camel-head": "<family>Smith</family zqxP",
    "end-camel-word": "<family>Smith</family userPwd",
}


@pytest.mark.parametrize("text", list(_KEPT.values()), ids=list(_KEPT))
def test_a_rest_a_pass_could_read_differently_stays_as_main_left_it(text: str) -> None:
    with _main():
        main = redaction._redact_xml_elements(text)
    assert redaction._redact_xml_elements(text) == main


def test_a_field_run_that_takes_the_end_tag_prints_the_rest_as_main_did() -> None:
    """A STATED RESIDUAL (code review round 3): the flat passes run before the XML pass, so a field
    run that takes the end tag's name leaves a rest no end tag owns, and it prints, as on main."""
    for text in ("a|b|<family>Smith</family Zqxdoe>", "<given>A^B^C</given Zqxdoe>"):
        with _main():
            main = redact(text)
        assert redact(text) == main
        assert "Zqxdoe" in main  # the residual, named so a fix to it is seen here


@pytest.mark.parametrize(
    ("a", "raw"),
    [
        ("<family>Smith</family password: ", "<s3cr3tvalue99>"),
        # Found by code review round 1: a camelCase label, whole or as a head a caller completes,
        # which the credential filter reads with no boundary in front (BACKLOG #5545).
        ("<family>Smith</family userPwd", "=s3cr3tvalue99"),
        ("<family>Smith</family clientSecret", "=s3cr3tvalue99"),
        ("<family>Smith</family zqxP", "assword: s3cr3tvalue99"),
        # Found by code review round 2: a lower-case head of a compound key word, which the filter
        # reads case-insensitively from a boundary.
        ("<family>Smith</family shared", "accesskey=s3cr3tvalue99"),
        ("<family>Smith</family zq master", "Key=s3cr3tvalue99"),
        ("<family>Smith</family acco", "untkey=s3cr3tvalue99"),
    ],
)
def test_a_credential_label_in_the_rest_still_reaches_the_credential_filter(
    a: str, raw: str
) -> None:
    """The credential filters after :func:`redact` read the label, so a mask that took it would print
    the value after it: the rest stays, and the filter scrubs the value as on main."""
    for text in (a + raw, redact(a) + raw):
        assert "s3cr3tvalue99" not in secretscrub.scrub_credentials(redact(text))
    with _main():
        assert "s3cr3tvalue99" not in secretscrub.scrub_credentials(redact(redact(a) + raw))


def test_the_camel_label_words_cover_the_credential_filter() -> None:
    """THE DRIFT PIN: :mod:`redaction` cannot import :mod:`secretscrub`, so it spells the camelCase
    label words; a word added there and not here fails this."""
    assert {word.lower() for word in secretscrub._CAMEL_WORDS} <= set(redaction._CAMEL_LABEL_WORDS)


def test_every_head_of_a_camel_label_word_is_refused_at_the_end() -> None:
    """Every head of every label word, whole or after a camelCase capital, refuses a last word that
    ends the text, since a caller's text could complete it into a label the filter reads."""
    for word in redaction._CAMEL_LABEL_WORDS:
        for end in range(1, len(word) + 1):
            head = word[:end]
            if not head.isalnum():  # a maskable rest holds letters and digits only
                continue
            assert redaction._ends_in_camel_head(f" {head}"), head
            assert redaction._ends_in_camel_head(f" zq{head[0].upper()}{head[1:]}"), head


class _CountingText(str):
    """A text that counts how often it is searched for the backstop's opener."""

    searches = 0

    def __contains__(self, item: object) -> bool:
        if item == redaction._USERINFO_OPENER:
            type(self).searches += 1
        return super().__contains__(item)  # type: ignore[operator]


@pytest.mark.parametrize(
    "unit", ["<name><a>b" + "</b Zq> x" * 500, "</name Zq> x" * 500], ids=["walked", "stray"]
)
def test_the_backstop_opener_is_tested_once_per_text(unit: str) -> None:
    """THE COST PIN (code review round 3): a scan of the whole text once per end tag was quadratic
    on a 64 KiB window. Counted, not timed, so it cannot pass on a fast runner."""
    _CountingText.searches = 0
    out = redaction._redact_xml_elements(_CountingText(unit))
    assert "Zq" not in out  # the end tags were reached, and masked
    assert _CountingText.searches == 1, _CountingText.searches


def test_a_text_holding_the_backstop_opener_keeps_every_rest() -> None:
    """Found by code review round 2: masking forced a round main did not run, the backstop reached
    further on the line a field run had shortened, and took the ``"name":`` key the widened stage
    needed, so the name value printed. The opener keeps every rest, as the glued-value mask does."""
    text = "nonnumeric port: 'pw " + "x|y|" * 70 + ' {"name": "Zq@host Kplm7"} </family Zqxdoe>'
    assert "Kplm7" not in redact(text)
    assert "Zqxdoe" in redact(text)
    cut = "nonnumeric port: 'pw Kplm7 " + "x|y|" * 70 + " tail@host' </family Zqxdoe> Qwerty12 rest"
    with _main():
        main = safe_text(cut, limit=60)
    assert safe_text(cut, limit=60) == main


# --- THE GATE: a differential fuzz against main, composed joins included ------------------------
#
# A redaction change that REPLACES text with a placeholder cannot be shown to redact at least what
# main did: once a redacted fragment is joined to raw text and redacted again, a name run main would
# have formed across the join is gone and the joined value prints. The previous attempt at #5925
# passed a per-text differential and failed exactly there. So the fuzz below composes: for generated
# ``a`` and ``raw``, every route over ``redact(a) + raw`` (and ``a + raw``, and the log chain's
# output plus ``raw``) is compared with main's same route, value by value.

#: Planted values: synthetic tokens, and surnames that end on a boundary-free word's head or are two
#: letters long, which the end-of-text rules refuse and the in-tag rules mask.
_VALUES = (
    "Zqxdoe", "Vandtjane", "Plantone", "Kplm7", "Qwerty12", "s3cr3tvalue99", "4455667", "Johnson",
    "Webb", "Kim", "Li",
)  # fmt: skip
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
    "OtherPatientIDs=", "Patient Name ", "secret ", "mfb64:v1:", "userPwd=", "clientSecret: ",
    "zqxP", "assword: ", "ZqMSH", "^~\\&|", "accessToken=", "shared", "accesskey=", "master",
    "Key=", "acco", "untkey=",
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
        if rand.random() < 0.05:  # the backstop's opener, with a tail a field run shortens
            parts.append("nonnumeric port: 'pw " + "x|y|" * 70 + ' {"name": "Zq@host Kplm7"} ')
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
        "safe_text": safe_text(text),
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


class _Tally:
    """One redactor's results against main's: each ``route: value`` it prints and main does not, how
    many it hides that main printed, and each route whose output is not main's with some letters and
    digits masked (:func:`_is_main_masked`)."""

    def __init__(self) -> None:
        self.leaks: list[str] = []
        self.unmasked: list[str] = []
        self.gains = 0

    def add(self, after: dict[str, str], before: dict[str, str], where: str) -> None:
        for route, out in after.items():
            if not _is_main_masked(out, before[route]):
                self.unmasked.append(f"{route}: {where}")
            for value in _VALUES:
                if value in out and value not in before[route]:
                    self.leaks.append(f"{route}: {value} in {where}")
                elif value in before[route] and value not in out:
                    self.gains += 1


def _differential(
    trials: int, seed: int, control: Callable[[str, int, int, bool], str]
) -> tuple[_Tally, _Tally]:
    """The shipped redactor's tally and ``control``'s, which replaces
    :func:`redaction._end_tag_rest`, over ``trials`` composed texts, each compared with main's
    answer for the same text, computed once."""
    rand = random.Random(seed)  # seeded: a flaky PHI arm gets muted, so this one cannot flake
    shipped, controlled = _Tally(), _Tally()
    for _ in range(trials):
        a = _fragment(rand, element=True)
        raw = _fragment(rand, element=rand.random() < 0.3)
        where = f"{a!r} + {raw!r}"
        with _main():
            before = _composed(a, raw)
        shipped.add(_composed(a, raw), before, where)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(redaction, "_end_tag_rest", control)
            controlled.add(_composed(a, raw), before, where)
    return shipped, controlled


def _is_main_masked(out: str, main: str) -> bool:
    """Whether ``out`` is ``main`` with some letters and digits masked to their class, and nothing
    else changed: then no value main hid can print, by construction rather than by a value list."""
    return len(out) == len(main) and all(
        a == b or (b.isascii() and b.isalnum() and a == b.translate(redaction._SHAPE))
        for a, b in zip(out, main, strict=True)
    )


def _replace_rest(text: str, start: int, stop: int, mask: bool) -> str:
    """The CONTROL: a rest REPLACED by the placeholder wherever it holds a word, the design the
    previous attempt took. It is not class-preserving, so the fuzz must find it leaking. It ignores
    ``mask``, so it reaches texts holding the backstop's opener too."""
    rest = text[start:stop]
    return (
        f" {redaction._REDACTED}{'>' if rest.endswith('>') else ''}" if rest.strip(" >") else rest
    )


def test_the_end_tag_mask_redacts_at_least_what_main_did_through_composed_joins() -> None:
    """THE GATE for #5925: over generated vocabulary elements with malformed end tags, joined to raw
    text and redacted again by every route, every output is main's with some letters and digits
    masked, so no value main hid prints. The gain count shows the mask is exercised; the replacing
    control shows the corpus can produce the composed-join leak.

    Measured at 1,500 trials: 0 leaks, 0 unmasked routes and 9,398 values hidden that main printed,
    against 1,526 leaks on the control, which ignores ``mask`` and so reaches texts holding the
    backstop's opener. 16,000 more trials over four other seeds, run by hand, also found 0 leaks and
    0 unmasked routes. The corpus holds the shapes code review found (camelCase credential labels
    and their heads, a segment id glued to a tag's ``>``, surnames the end-of-text rules refuse,
    the backstop's opener over a tail a field run shortens). With ``_end_tag_rest`` patched to
    ignore ``mask``, the same 1,500 trials found 203 leaks; with the head check narrowed to
    capitals they found none, so that shape rests on the pins above, not on this arm. These are
    measurements of this corpus, not a
    proof for every input."""
    shipped, control = _differential(1_500, 5925, _replace_rest)
    assert control.leaks, "the replacing control leaked nothing, so the corpus cannot find the leak"
    assert shipped.gains, "the mask hid nothing main printed, so #5925 is not exercised"
    assert not shipped.leaks, shipped.leaks[:5]
    assert not shipped.unmasked, shipped.unmasked[:5]


def test_a_composed_join_adds_no_gap_main_did_not_have() -> None:
    """On vocabulary content, where ``redact(a + raw)`` hides a value and ``redact(redact(a) + raw)``
    prints it, main's ``redact(redact(a) + raw)`` printed it too: the mask adds no composed-join gap
    of its own."""
    rand = random.Random(59250)
    regressions: list[str] = []
    for _ in range(1_500):
        a = _fragment(rand, element=True)
        raw = _fragment(rand, element=False)
        with _main():
            main_joined = redact(redact(a) + raw)
        whole, joined = redact(a + raw), redact(redact(a) + raw)
        for value in _VALUES:
            if value not in whole and value in joined and value not in main_joined:
                regressions.append(f"{value} in {a!r} + {raw!r}")
    assert not regressions, regressions[:5]


def test_an_end_tag_after_an_element_read_as_prose_is_masked_on_a_second_call() -> None:
    """Found by the composed-join arm: an element no well-formed end tag closes is walked only on
    evidence, and ``[redacted]`` opening its text is none, so a second call reads it as prose. The
    vocabulary end tag after it is masked as a stray one, so the composed join hides what the whole
    text hides, where main printed it."""
    a, raw = "api_key={<given>1980</name Smith of ", "Kplm7>"
    assert "Kplm7" not in redact(a + raw)
    assert "Kplm7" not in redact(redact(a) + raw)
    with _main():
        assert "Kplm7" in redact(redact(a) + raw)


#: Found by the Lander's differential at 552c25b49e: a vocabulary end tag with a maskable rest, then
#: a name pair glued to ``=PID|``. Main's first call leaves ``&[redacted]=PID|[redacted]``, and the
#: ``PID|`` it keeps takes a caller's text joined after it; a second round turns it into
#: ``[redacted]``. The mask counted as a change, so one call ran that second round and the joined
#: value printed.
_ROUND_STARTS = (
    "</given Doe>&Smith, Jones=PID|x",
    "</family Zqx>&Smith, Jones=PID|x",
    "</given Doe> &Smith, Jones=PID|x",
    "</family Zqx>  &Smith, Jones=PID|x",
    "</given Doe>\n&Smith, Jones=PID|x",
    "</family Zqx>\n&Smith, Jones=PID|x",
)
#: What a caller joins after it: prose, a date, a phone, quotes, markup and a comment.
_ROUND_JOINS = (
    " Qzhqpjzj",
    " peer Qzhqpjzj",
    " expected Qzhqpjzj got",
    " 19800102 Qzhqpjzj",
    " 1980-01-02 Qzhqpjzj",
    " 555-201-3344 Qzhqpjzj",
    " (555) 201-3344 Qzhqpjzj",
    ' "Qzhqpjzj"',
    " 'Qzhqpjzj'",
    " <b>Qzhqpjzj</b>",
    " <!-- Qzhqpjzj -->",
)


@pytest.mark.parametrize("raw", _ROUND_JOINS)
@pytest.mark.parametrize("a", _ROUND_STARTS)
def test_a_masked_rest_runs_no_round_main_did_not(a: str, raw: str) -> None:
    """A mask alone is not a change that sends the text round again: every route over ``a`` and
    ``a`` joined to ``raw`` is main's with some letters and digits masked, so the joined value is
    hidden wherever main hid it, ``redact(redact(a) + raw)`` and ``safe_text(safe_text(a) + raw)``
    first among them."""
    with _main():
        before = _composed(a, raw)
        main_twice = safe_text(safe_text(a) + raw)
    after = _composed(a, raw)
    assert "Qzhqpjzj" not in before["redact(a) + raw by redact"]  # the gap main does not have
    assert "Qzhqpjzj" not in safe_text(safe_text(a) + raw)
    assert _is_main_masked(safe_text(safe_text(a) + raw), main_twice)
    assert len(after) >= 45
    assert after.keys() == before.keys()
    unmasked = [route for route, out in after.items() if not _is_main_masked(out, before[route])]
    assert not unmasked, [(route, after[route], before[route]) for route in unmasked[:3]]
    assert any(out != before[route] for route, out in after.items())  # the mask ran
    # THE POSITIVE CONTROL: with a mask counted as a change again, as at 552c25b49e, this pair
    # prints the joined value where main hid it, so the green above is the round gate's work.
    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "_masked_only", _never_masked_only)
        assert "Qzhqpjzj" in redact(redact(a) + raw)


def test_a_scrub_that_keeps_length_and_class_still_runs_another_round() -> None:
    """THE EXACT CHECK (code review): ``[abcdefgh]`` and ``[redacted]`` have one length and one
    class layout, so the class comparison alone would read this real scrub, beside a masked rest,
    as masks only and end a round main ran again. The structured pass with every rest kept is what
    tells them apart."""
    flat = '{"name": "[abcdefgh]"} </family Zqx>'
    out = redaction._redact_structured(flat, widened=True)
    assert out == '{"name": "[redacted]"} </family Xxx>'
    assert out.translate(redaction._SHAPE) == flat.translate(redaction._SHAPE)
    assert not redaction._masked_only(out, flat, widened=True)
    masked_alone = redaction._redact_structured(flat, widened=False)
    assert masked_alone == '{"name": "[abcdefgh]"} </family Xxx>'
    assert redaction._masked_only(masked_alone, flat, widened=False)
    with _main():
        main = redact(flat)
    assert main == '{"name": "[redacted]"} </family Zqx>'
    assert _is_main_masked(redact(flat), main)


#: Shapes main's one call does not leave at a fixed point of its own passes, for the generated arm
#: below: a name pair glued to a segment id, and a JSON value whose scrub joins field-run halves.
_ROUND_PIECES = (
    "&Smith, Jones=PID|x", "&Doe, Webb=PID|", '{"family":"a b"}|q', "&Kim, Li=OBX|y",
    '{"given":"c d"}|',
)  # fmt: skip


def test_the_round_gate_holds_over_generated_joins() -> None:
    """The generated arm for the round gate (code review round 2): the gate above cannot see a
    round main did not run, since its corpus holds no text main's one call leaves short of a fixed
    point. Here each ``a`` ends on such a shape. Every route is main's with some letters and digits
    masked, and the control, the gate forced off as at 552c25b49e, leaks.

    Measured by hand at 1,500 trials on each of five seeds, this one among them: 0 leaks and 0
    unmasked routes, against 100 to 481 leaks on the control. A measurement of this corpus, not a
    proof."""
    rand = random.Random(59252)
    shipped, forced = _Tally(), _Tally()
    for _ in range(1_000):
        a = _fragment(rand, element=True) + rand.choice(("", " ", "  ", "\n", " x "))
        a += rand.choice(_ROUND_PIECES)
        raw = rand.choice((" ", "\n", "")) + _fragment(rand, element=rand.random() < 0.3)
        where = f"{a!r} + {raw!r}"
        with _main():
            before = _composed(a, raw)
        shipped.add(_composed(a, raw), before, where)
        with pytest.MonkeyPatch.context() as patch:
            patch.setattr(redaction, "_masked_only", _never_masked_only)
            forced.add(_composed(a, raw), before, where)
    assert forced.leaks, "the forced-off gate leaked nothing, so this corpus cannot see the defect"
    assert shipped.gains, "the mask hid nothing main printed, so the mask is not exercised"
    assert not shipped.leaks, shipped.leaks[:5]
    assert not shipped.unmasked, shipped.unmasked[:5]


def test_the_mask_is_a_fixed_point() -> None:
    rand = random.Random(925)
    for _ in range(2_000):
        once = redact(_fragment(rand, element=True))
        assert redact(once) == once, once
