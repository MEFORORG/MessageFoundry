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
from collections import Counter
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from typing import Any

import pytest

from messagefoundry import logging_setup, redaction
from messagefoundry.redaction import redact, safe_exc, safe_text
from messagefoundry.verify_leaf import safe_detail_text

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
        text: str,
        body: str,
        run: re.Match[str],
        field_run: re.Pattern[str],
        *,
        noted: bool = False,
    ) -> tuple[str, str] | None:
        # Returns the arm's (rest, mask) pair, as the head's _glued_value does.
        token, end = run.group(), run.end()
        note_follows = len(body) < len(text) and text.startswith("\n", len(body))
        stop = redaction._glued_phi_value_end(text, body, token, end)
        if stop is not None:
            judged = body if note_follows and stop == len(body) else text
            rest = maskable(judged, end, stop, field_run, credential=False)
            if rest is not None:
                return rest, rest.translate(redaction._SHAPE)
        tag_rest = glued_end_tag(body, token, end, field_run, **end_tag_kwargs)
        if tag_rest is not None:
            return tag_rest
        if not redaction._ends_in_credential_label(token):
            return None
        bare = redaction._GLUED_BARE_VALUE.match(body, end)
        if bare is None:
            return None
        judged = body if note_follows and bare.end() == len(body) else text
        rest = maskable(judged, end, bare.end(), field_run, credential=True)
        return None if rest is None else (rest, rest.translate(redaction._SHAPE))

    def last_note_only(text: str) -> str:
        note = redaction._TRAILING_NOTES.search(text)
        return text if note is None else text[: note.start()]

    def main_bounded_head(head: str, note: str) -> str:
        # Main's safe_text head: redacted as it stood, no whitespace dropped, no note told.
        return redact(head).strip()

    with pytest.MonkeyPatch.context() as patch:
        if hasattr(redaction, "redact_bounded_head"):
            patch.setattr(redaction, "redact_bounded_head", main_bounded_head)
        patch.setattr(redaction, "_without_trailing_note", last_note_only)
        patch.setattr(redaction, "_glued_value", main_glued_value)
        patch.setattr(redaction, "_maskable_rest", maskable_off)
        patch.setattr(redaction, "_end_tag_rest", end_tag_off)
        # Main refused a rest ending the text whole; the glue-head mask (#5925 closing step 1) came
        # after the root fix this stand-in measures.
        if hasattr(redaction, "_mask_keeping_glue_head"):
            patch.setattr(redaction, "_mask_keeping_glue_head", lambda rest: None)
        yield


#: Routes whose dropped whitespace at the cut can switch a whole-text gate, such as the final
#: ``bearer`` one, toward more scrubbing, so their answer is not main's with masks alone.
_GATE_ROUTES = frozenset({"safe_text tab gap", "verify tab gap"})


def _hides_at_least_main(out: str, main: str) -> bool:
    """Whether every word ``out`` prints is a word ``main`` prints (counted), a shape mask, or holds
    the placeholder: so ``out`` prints nothing ``main`` hid."""
    left = Counter(main.split())
    for word in out.split():
        if left[word] > 0:
            left[word] -= 1
        elif redaction._REDACTED not in word and word.translate(redaction._SHAPE) != word:
            return False
    return True


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
def test_safe_text_masks_a_value_its_bound_left_last(text: str, value: str) -> None:
    """The root fix on the ``safe_text`` route: it redacts its head told, out of band, that its
    bound note follows, so a value the bound left last is masked as the clamp route masks it. Red
    on the code before: the value printed in front of the note. The answer is main's with letters
    and digits masked, nothing else changed."""
    routed = text + " " + "q" * 70_000
    with _main():
        main = safe_text(routed, limit=400)
    assert value in main  # the premise: main printed it
    out = safe_text(routed, limit=400)
    assert value not in out, out
    assert _is_main_masked(out, main), (out, main)


@pytest.mark.parametrize(("text", "value"), _FIELD_RUN_VALUES[:2] + _END_TAG_RESTS[:2])
def test_verify_detail_masks_a_value_its_clamp_left_last(text: str, value: str) -> None:
    """The same fix on ``verify_leaf.safe_detail_text``, which clamps and appends the note after its
    passes. Red on the code before: the value printed in front of the note."""
    from messagefoundry.verify_leaf import safe_detail_text

    routed = text + " " + "q" * 70_000
    with _main():
        main = safe_detail_text(routed, limit=400)
    assert value in main  # the premise: main printed it
    assert value not in safe_detail_text(routed, limit=400)


@pytest.mark.parametrize("gap", ["\t", " \t", "\t\t", "  "], ids=repr)
def test_safe_text_masks_a_value_whitespace_left_before_its_cut(gap: str) -> None:
    """The cut lands on the last whitespace, so a run of it can stay after the head's last value.
    That whitespace is dropped before the head is read, as the answer drops it anyway, so the value
    is still the one the note follows. Red on the code before: ``12345`` printed."""
    routed = "a|b|mrn: 12345" + gap + "q" * 70_000
    with _main():
        main = safe_text(routed)
    assert "12345" in main  # the premise
    out = safe_text(routed)
    assert "12345" not in out and _is_main_masked(out, main), (out, main)


def test_safe_exc_masks_it_through_safe_text() -> None:
    """``safe_exc`` renders a message through :func:`safe_text`, so it takes the fix with no change
    of its own. Red on the code before: the value printed."""
    routed = "a|b|mrn: 12345 " + "q" * 70_000
    with _main():
        main = safe_exc(ValueError(routed))
    assert "12345" in main  # the premise
    out = safe_exc(ValueError(routed))
    assert "12345" not in out and _is_main_masked(out, main), (out, main)


@pytest.mark.parametrize(
    "text", ["x%7Cy%7Cz bearer", "PID%7C123%7CDOE bearer", "PID%7C1%7C2 a|b|mrn: 12345 bearer"]
)
def test_an_encoded_run_before_a_final_scheme_word_is_redacted_as_main_redacted_it(
    text: str,
) -> None:
    """Code review round 3: a stand-in note read after ``safe_text``'s head put a line break after
    a final ``bearer``, which the credential gate read as a scheme, so the encoded field run printed
    where main redacted it."""
    routed = text + " " + "q" * 70_000
    with _main():
        main = safe_text(routed, limit=4096)
    out = safe_text(routed, limit=4096)
    assert "%7C" not in main  # the premise: main redacted the encoded run
    assert out == main


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
    # The inputs of this row's earlier regressions, so the safe_text fix is measured on them: the
    # round-3 scheme gate, the reverted PR 3093 rests, and a round main ran that a mask must not.
    "x%7Cy%7Cz bearer",
    "PID%7C123%7CDOE bearer",
    "PID%7C1%7C2 a|b|mrn: 12345 bearer",
    "a|b|</family Zqxdoe>",
    "a|b|</family Zqxdoe Vandt",
    "a|b|</family Li",
    "</given Doe>&Smith, Jones=PID|x",
    "user svcadmin Login Password: svcadmin",
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
        "safe_text padded twice": lambda t: safe_text(
            safe_text(t + " " + "q" * 70_000, limit=4096) + " " + "q" * 70_000, limit=4096
        ),
        "chain padded": lambda t: _through_the_chain(t + " " + "q" * 70_000),
        "untrusted stacked": lambda t: redaction.redact_untrusted(f"{t}\n{_NOTE} " + "q" * 70_000),
        # Round-1 review of this fix: whitespace at the cut, which the bounded head drops, and
        # the verify detail route, which takes the same head rule.
        "safe_text tab gap": lambda t: safe_text(t + " \t" + "q" * 70_000, limit=4096),
        "verify padded": lambda t: safe_detail_text(t + " " + "q" * 70_000, limit=4096),
        "verify tab gap": lambda t: safe_detail_text(t + "\t\t" + "q" * 70_000, limit=4096),
    }
    for route, call in routes.items():
        with _main():
            main = call(text + suffix)
        out = call(text + suffix)
        check = _hides_at_least_main if route in _GATE_ROUTES else _is_main_masked
        assert check(out, main), (route, out, main)


def test_whitespace_dropped_at_the_cut_switches_the_bearer_gate_toward_scrubbing() -> None:
    """Round-1 review of the safe_text fix: dropping the head's trailing whitespace changes
    ``_redact_unguarded``'s final-``bearer`` gate too, the gate a stand-in note once flipped the
    wrong way. Here it goes the safe way: main printed the encoded run, the bounded head scrubs it."""
    routed = "x%7Cy%7Cz bearer \t" + "q" * 70_000
    with _main():
        main = safe_text(routed)
    assert "%7C" in main  # the premise
    assert "%7C" not in safe_text(routed)


@pytest.mark.parametrize("joiner", list(_JOINERS.values()), ids=list(_JOINERS))
def test_a_rest_ending_in_a_boundary_free_word_is_masked_before_a_note(joiner: str) -> None:
    """Code review round 1: behind a note the walk kept a last word ending in ``MSH`` where the
    field-run arm masked it. ``MSH`` needs a non-space separator after it, and the note's joiner is
    whitespace, so both arms mask it."""
    assert "ZqMSH" not in redact(f"<family>Smith</family ZqMSH{joiner}{_NOTE}")
    assert "ZqMSH" not in redact(f"a|b|mrn: ZqMSH{joiner}{_NOTE}")


def test_a_value_before_an_earlier_of_stacked_notes() -> None:
    """A text that already ends in a note, bounded again. ``safe_text``'s head then ends in that
    note, which the passes set aside, so the value is masked. ``redact_untrusted`` stacks a second note on the
    text, the passes set aside only the last, and the value still prints, as on main: setting the
    run aside whole made a differential print a credential main masked, so it is a residual the
    changelog names."""
    text = f"a|b|mrn: 12345\n{_NOTE} " + "q" * 70_000
    assert "12345" not in safe_text(text)
    with _main():
        main = redaction.redact_untrusted(text)
    assert "12345" in main
    assert redaction.redact_untrusted(text) == main


def test_a_rest_with_no_note_after_it_keeps_the_end_of_text_rules() -> None:
    """Without a note, a rest ending the text is still one a caller can glue text onto: the end of
    its last word that glued text could complete is kept (BACKLOG #5925 closing step 1), and a
    last word holding a digit keeps the rest whole."""
    assert redact("<family>Smith</family Kim") == "<family>[redacted]</family Xxm"
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
    exercised it. A rest followed only by a line break is judged as ending the text, since an
    answer is stripped before a caller glues to it, so a last word of two letters is masked too.
    Before item 15 was fixed it was judged as glued to the line break and kept."""
    assert redact("<family>Smith</family Zqxdoe\n") == "<family>[redacted]</family Xxxxxx\n"
    assert redact("<family>Smith</family Li\n") == "<family>[redacted]</family Xx\n"
    assert redact("<family>Smith</family Li\r\n") == "<family>[redacted]</family Xx\r\n"


def test_the_audit_tee_detail_prints_no_value_the_cut_left_last() -> None:
    """Both of the tee's detail paths are told the note follows the head (BACKLOG #5925 closing
    step 5), so neither prints the value the cut left last. The C0-scrubbed path's head was read
    by the handler chain with no note, so its answer can still show that value; the line check
    then ships the detail hidden whole, with its note (``_bounded_detail``). Before step 5 this
    pinned main's answer, the scrubbed detail with ``12345`` in it."""
    import json

    from messagefoundry.store import audit_tee

    lines: list[str] = []

    class _Capture(logging.Handler):
        def emit(self, record: logging.LogRecord) -> None:
            lines.append(record.getMessage())

    handler = _Capture()
    logger = logging.getLogger("messagefoundry.audit")
    logger.addHandler(handler)
    try:
        audit_tee.emit_audit_tee(
            action="message.error",
            actor="svc",
            channel_id=None,
            detail="\x01 a|b|mrn: 12345 " + "q" * 70_000,
            ts=1.0,
            row_id=1,
            seq=1,
            row_hash="0" * 64,
        )
    finally:
        logger.removeHandler(handler)
    shipped = json.loads(lines[-1])["detail"]
    assert "12345" not in shipped, shipped
    assert shipped.endswith(" [redaction bound: dropped 70_001 more chars unscanned]"), shipped
