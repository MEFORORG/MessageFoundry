# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""BACKLOG #5925 root fix: a value this module's bound note follows does not end the text.

The redactor keeps some values that end the text, because a caller's text glued after the answer
could complete a word another pass reads, and a mask would stop that pass. A value right before
the bound note a clamp writes was judged that way too, though the note's joiner and the note follow
it and nothing can be glued there. So a digit-bearing MRN, a credential opening with a digit, and
end-tag rests such as ``</family Kim`` printed whole in front of the note. Every value here is
synthetic."""

from __future__ import annotations

import inspect
import logging
import re
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from messagefoundry import logging_setup, redaction
from messagefoundry.redaction import redact, safe_exc, safe_text

_NOTE = redaction._clamp_marker(70_000)
_JOINERS = {"newline": "\n", "space": " "}

#: ``(text, its synthetic value)``: values the end-of-text rules kept right before a note.
_FIELD_RUN_VALUES = (
    ("a|b|mrn: 12345", "12345"),
    ("a|b|mrn: Zqx4", "Zqx4"),
    ("x^y^token= 4455abc", "4455abc"),
    ("a|b|password: 4455", "4455"),
    ("a|b|mrn: ZqMSH", "ZqMSH"),
)
_END_TAG_RESTS = (
    ("<family>Smith</family Zqx 4455", "4455"),
    ("<family>Smith</family zqxP", "zqxP"),
    ("<family>Smith</family Kim", "Kim"),
    ("</family Zqx 4455", "4455"),
    ("a|b|</family Zqx 4455", "4455"),
    ("a|b|</family Kim", "Kim"),
)


def _through_the_chain(text: str) -> str:
    """``text`` as a log message through the filters ``_install_phi_filters`` puts on a handler."""
    handler = logging.Handler()
    logging_setup._install_phi_filters(handler)
    record = logging.LogRecord("test", logging.ERROR, __file__, 1, "%s", (text,), None)
    assert handler.filter(record)
    return record.getMessage()


@contextmanager
def _main() -> Iterator[None]:
    """The redactor as it stood before the root fix: every bound note ignored by the end-of-text
    rules, only the last trailing note set aside, :func:`redaction._glued_value` as main had it
    (vendored, so a value before a space-joined note is judged on the whole text, as main judged
    it), and :func:`redaction.safe_text` redacting its head with no note after it."""
    maskable, end_tag = redaction._maskable_rest, redaction._end_tag_rest
    glued_end_tag = redaction._glued_end_tag_rest
    # On the code before the root fix the arm takes no `noted`; on it, `noted=False` is main's.
    end_tag_kwargs = (
        {"noted": False} if "noted" in inspect.signature(glued_end_tag).parameters else {}
    )

    def maskable_off(*args: Any, noted: bool = False, **kwargs: Any) -> str | None:
        return maskable(*args, **kwargs)

    def end_tag_off(*args: Any, noted: bool = False, **kwargs: Any) -> str:
        return end_tag(*args, **kwargs)

    def main_glued_value(
        text: str, body: str, run: re.Match[str], field_run: re.Pattern[str]
    ) -> str | None:
        token, end = run.group(), run.end()
        note_follows = len(body) < len(text) and text.startswith("\n", len(body))
        stop = redaction._glued_phi_value_end(text, body, token, end)
        if stop is not None:
            judged = body if note_follows and stop == len(body) else text
            rest = maskable(judged, end, stop, field_run, credential=False)
            if rest is not None:
                return rest
        rest = glued_end_tag(body, token, end, field_run, **end_tag_kwargs)
        if rest is not None:
            return rest
        if not redaction._ends_in_credential_label(token):
            return None
        bare = redaction._GLUED_BARE_VALUE.match(body, end)
        if bare is None:
            return None
        judged = body if note_follows and bare.end() == len(body) else text
        return maskable(judged, end, bare.end(), field_run, credential=True)

    def before_notes_off(head: str, *_: object) -> str:
        return redact(head)

    def last_note_only(text: str) -> str:
        note = redaction._TRAILING_NOTES.search(text)
        return text if note is None else text[: note.start()]

    with pytest.MonkeyPatch.context() as patch:
        patch.setattr(redaction, "_without_trailing_note", last_note_only)
        patch.setattr(redaction, "_glued_value", main_glued_value)
        patch.setattr(redaction, "_maskable_rest", maskable_off)
        patch.setattr(redaction, "_end_tag_rest", end_tag_off)
        patch.setattr(redaction, "_redact_before_notes", before_notes_off, raising=False)
        yield


def _is_main_masked(out: str, main: str) -> bool:
    """Whether ``out`` is ``main`` with some ASCII letters and digits masked to their class and
    nothing else changed, so no character main replaced is back in ``out``."""
    return len(out) == len(main) and all(
        a == b or (b.isascii() and b.isalnum() and a == b.translate(redaction._SHAPE))
        for a, b in zip(out, main, strict=True)
    )


@pytest.mark.parametrize("joiner", list(_JOINERS.values()), ids=list(_JOINERS))
@pytest.mark.parametrize(("text", "value"), _FIELD_RUN_VALUES + _END_TAG_RESTS)
def test_a_value_right_before_a_bound_note_is_masked(text: str, value: str, joiner: str) -> None:
    clamped = f"{text}{joiner}{_NOTE}"
    with _main():
        main = redact(clamped)
    out = redact(clamped)
    assert value not in out, out
    assert out.endswith(joiner + _NOTE)  # the note itself is kept as it was
    assert _is_main_masked(out, main)


@pytest.mark.parametrize(("text", "value"), _FIELD_RUN_VALUES[:4] + _END_TAG_RESTS[:2])
def test_the_log_chain_masks_a_value_its_clamp_left_last(text: str, value: str) -> None:
    """The handler chain clamps with a newline-joined note, then redacts. Only shapes the clamp's
    name walk keeps are used, so the route reaches the rule."""
    routed = text + " " + "q" * 70_000
    assert value in redaction.clamp_untrusted(routed)  # the premise: the clamp kept it last
    assert value not in _through_the_chain(routed)
    assert value not in redaction.redact_untrusted(routed)


@pytest.mark.parametrize(("text", "value"), _FIELD_RUN_VALUES[:4] + _END_TAG_RESTS[:2])
def test_safe_text_and_safe_exc_mask_a_value_their_bound_left_last(text: str, value: str) -> None:
    """:func:`redaction.safe_text` appends its space-joined note after it redacts, so before the
    root fix the redaction never saw it and judged the value as ending the text."""
    routed = text + " " + "q" * 70_000
    head, note = redaction.safe_text_bound(routed)
    assert note and head.rstrip().endswith(value)  # the premise: the bound left it last
    assert value not in safe_text(routed, limit=400)
    assert value not in safe_exc(ValueError(routed))


#: Suffixes after each text, for the differential: no note, each joiner, and whitespace before one.
_SUFFIXES = ("", "\n" + _NOTE, " " + _NOTE, "  \n" + _NOTE, " \n" + _NOTE, "\n\n" + _NOTE)
_CORPUS = tuple(text for text, _ in _FIELD_RUN_VALUES + _END_TAG_RESTS) + (
    "a|b|mrn: qw",
    "a|b|PatientID: Li",
    "x^y^secret: k7",
    "a|b|pwd: ZqMS",
    "<family>Smith</family ZqMSH",
    "<family>Smith</family Li",
    "<family>Smith</family Zqxdoe Vandt",
    "<family>Smith</family userPwd",
    "<family>Smith</family Zq, Zqxdoe",
    "<family>Smith</family Johnson",
    "<family>Smith</family shared",
    "a|b|</family zqxP",
    "a|b|</family ZqMSH",
    "a|b|<family>Smith</family Zqxdoe",
    '{"name": "Zqx Doe", "id": 4455}',
    "DOE, JANE 19800505",
    "nonnumeric port: 'Zqx 4455",
)


@pytest.mark.parametrize("suffix", _SUFFIXES, ids=lambda s: repr(s[:3]))
@pytest.mark.parametrize("text", _CORPUS)
def test_no_route_unmasks_what_main_masked(text: str, suffix: str) -> None:
    """Every route over the corpus answers main's answer with some letters and digits masked, so
    the root fix never prints a character main replaced. A measurement of this corpus."""
    routes: dict[str, Callable[[str], str]] = {
        "redact": redact,
        "redact twice": lambda t: redact(redact(t)),
        "safe_text": lambda t: safe_text(t, limit=4096),
        "safe_text padded": lambda t: safe_text(t + " " + "q" * 70_000, limit=4096),
        "chain padded": lambda t: _through_the_chain(t + " " + "q" * 70_000),
        "untrusted stacked": lambda t: redaction.redact_untrusted(f"{t}\n{_NOTE} " + "q" * 70_000),
    }
    for route, call in routes.items():
        with _main():
            main = call(text + suffix)
        out = call(text + suffix)
        assert _is_main_masked(out, main), (route, out, main)


@pytest.mark.parametrize("joiner", list(_JOINERS.values()), ids=list(_JOINERS))
def test_a_rest_ending_in_a_boundary_free_word_is_masked_before_a_note(joiner: str) -> None:
    """Code review round 1: behind a note the walk kept a last word ending in ``MSH`` where the
    field-run arm masked it. ``MSH`` needs a non-space separator after it, and the note's joiner is
    whitespace, so both arms mask it."""
    assert "ZqMSH" not in redact(f"<family>Smith</family ZqMSH{joiner}{_NOTE}")
    assert "ZqMSH" not in redact(f"a|b|mrn: ZqMSH{joiner}{_NOTE}")


def test_a_value_before_an_earlier_of_stacked_notes() -> None:
    """A text that already ends in a note, bounded again. ``safe_text`` reads the head alone, whose
    last note is set aside, so the value is masked. ``redact_untrusted`` stacks a second note on the
    text, the passes set aside only the last, and the value still prints, as on main: setting the
    run aside whole made a differential print a credential main masked, so it is a residual the
    changelog names."""
    text = f"a|b|mrn: 12345\n{_NOTE} " + "q" * 70_000
    assert "12345" not in safe_text(text)
    with _main():
        main = redaction.redact_untrusted(text)
    assert "12345" in main
    assert redaction.redact_untrusted(text) == main


def test_a_head_redacted_whole_is_not_redacted_twice(monkeypatch: pytest.MonkeyPatch) -> None:
    """Code review round 2: a mismatched JSON closer makes the answer the placeholder alone, which
    drops the note read after the head; reading the head again would only repeat that answer."""
    calls: list[int] = []
    real = redaction.redact

    def counting(text: str) -> str:
        calls.append(len(text))
        return real(text)

    monkeypatch.setattr(redaction, "redact", counting)
    head = "word " * 50 + '{"name": ["a"} '
    assert redaction._redact_before_notes(head) == redaction._REDACTED
    assert len(calls) == 1


def test_a_rest_with_no_note_after_it_keeps_the_end_of_text_rules() -> None:
    """Without a note, a rest ending the text is still one a caller can glue text onto."""
    assert "Kim" in redact("<family>Smith</family Kim")
    assert "4455" in redact("<family>Smith</family Zqx 4455")


# --- added items of the row ---------------------------------------------------------------------


def test_prose_naming_a_vocabulary_end_tag_is_masked() -> None:
    """Added item 2, the negative control the over-masking lacked: stray-tag masking changes prose
    that names a vocabulary end tag, kept by Manager decision because over-masking fails safe."""
    assert redact("expected </family but got") == "expected </family xxx xxx"
    assert redact("missing </name element") == "missing </name xxxxxxx"


def _alternation(pattern: re.Pattern[str]) -> set[str]:
    found = re.search(r"\(\?:(family\|[A-Za-z|]+)\)", pattern.pattern)
    assert found is not None, pattern.pattern
    return set(found.group(1).split("|"))


@pytest.mark.parametrize("name", ["_XML_PHI_END_OPEN", "_GLUED_XML_LABEL"])
def test_each_end_tag_vocabulary_copy_matches_the_named_sets(name: str) -> None:
    """Added item 5: these patterns spell the vocabulary out as a literal, which no drift pin
    checked against the sets the walks consult."""
    vocabulary = redaction._PHI_LEAF_KEYS | redaction._PHI_VALUE_KEYS
    assert _alternation(getattr(redaction, name)) == vocabulary


def test_the_line_break_rule_after_a_rest_is_pinned() -> None:
    """Added item 18: the ``later-line`` kept shape returns before the line-break rule, so nothing
    exercised it. A rest followed only by a line break is judged as glued to it: a longer word is
    masked, and a last word of two letters or fewer is kept (item 15's over-refusal)."""
    assert redact("<family>Smith</family Zqxdoe\n") == "<family>[redacted]</family Xxxxxx\n"
    assert redact("<family>Smith</family Li\n") == "<family>[redacted]</family Li\n"
