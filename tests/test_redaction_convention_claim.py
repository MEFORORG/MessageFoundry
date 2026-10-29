# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No document calls the exception-message convention THE control for a redaction residual (BACKLOG #3464).

The "never put PHI in an exception message" convention binds only the engine's own authors, in text
they write themselves. A diagnostic can quote text a remote peer wrote, which no convention of ours
binds, so "the convention remains the control" was false for peer text. It was said in ten places
across six files. docs/PHI.md section 7 now states the fact once, under *Who the exception-message
convention binds*, and the other places point there.

This pins the absence of the old claim, in the shapes the controls below hold, over ``docs/``,
``messagefoundry/``, ``tests/``, ``packaging/``, ``harness/`` and ``scripts/``. It is a lexical floor:
a paraphrase that never says "the control" passes it. It also pins that the statement the pointers
cite is still in section 7. A correction note may quote the old wording, with any double quotes
inside it made single: a match wholly inside a double-quoted span that opens right after ``read`` or
``said`` following a ``CORRECTED`` or ``Corrected`` marker, and closes just after the match, is a
quoted retraction, not the claim (:func:`_is_quoted_retraction`).
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCANNED = ("docs", "messagefoundry", "tests", "packaging", "harness", "scripts")
_SUFFIXES = frozenset({".md", ".py"})
_STATEMENT = "**Who the exception-message convention binds.**"

_CONTROL = r"\s+(?:remains|is)\s+(?:still\s+)?the\s+(?:only\s+)?\W{0,2}control\b"
#: The claim, as it read before BACKLOG #3464. Line breaks and comment or quote markers are folded
#: away first, so a claim wrapped across lines is still one sentence; up to four marks such as a
#: closing quote or Markdown emphasis may sit between the convention's name and the verb.
_CLAIM = re.compile(
    rf"exception\s+message\W{{0,4}}(?:\s+convention\W{{0,4}})?{_CONTROL}"
    rf"|the\s+convention\s+above\W{{0,4}}{_CONTROL}",
    re.IGNORECASE,
)
_LINE_MARKER = re.compile(r"^\s*(?:#:?|>)?\s*", re.MULTILINE)
#: A cheap first look on the raw text: ``\W+`` also spans a line break and its comment marker, so no
#: file that :data:`_CLAIM` would match after folding is skipped. Most files fail it and skip the fold.
_MAYBE = re.compile(r"the\W+(?:only\W+)?control", re.IGNORECASE)


def _folded(text: str) -> str:
    return " ".join(_LINE_MARKER.sub("", text).split())


#: How far back a correction marker may sit and still own a quoted claim: room for the marker, its
#: date or context and a lead-in such as ``this read``, never a whole paragraph.
_CORRECTED_REACH = 200
#: How far past the claim its retraction quote must close: room for a tail such as ``for both``.
_CLOSE_REACH = 40
#: The opening of a quoted retraction, read back from where the claim starts: a ``CORRECTED`` or
#: ``Corrected`` marker, then ``read`` or ``said`` (in any case) with a double quote opening RIGHT
#: AFTER the verb and still open at the claim. The marker is case-sensitive, so prose saying "the
#: corrected wording read" is not one; the letter guard before it, not its case, is what keeps
#: ``UNCORRECTED`` out. A quote opened anywhere else, such as the one around the convention's own
#: name in ``this said X; the "never put PHI ..." convention remains the control``, is not one.
_QUOTED_RETRACTION = re.compile(
    r"(?<![A-Za-z])(?:CORRECTED|Corrected)(?![a-z])"
    rf".{{0,{_CORRECTED_REACH}}}?"
    r"(?<![A-Za-z])(?i:read|said)(?![a-z])[\s:*_]*\"[^\"]*$"
)


def _is_quoted_retraction(folded: str, m: re.Match[str]) -> bool:
    """Whether the claim ``m`` sits wholly inside a retraction's quote.

    The quote must still be open at the claim's END (no double quote inside the match, which
    ``_CLAIM``'s ``\\W{0,4}`` would otherwise accept) and must close within :data:`_CLOSE_REACH`
    after it, so an unclosed quote cannot exempt a claim made in a later sentence. The opening is
    searched with ``pos``, not on a slice, so a window that cuts ``UNCORRECTED`` keeps its left
    context."""
    if '"' in m.group(0):
        return False
    close = folded.find('"', m.end())
    if close == -1 or close - m.end() > _CLOSE_REACH:
        return False
    lo = max(0, m.start() - _CORRECTED_REACH)
    return _QUOTED_RETRACTION.search(folded, lo, m.start()) is not None


def _claims(text: str) -> list[str]:
    if not _MAYBE.search(text):
        return []
    folded = _folded(text)
    return [m.group(0) for m in _CLAIM.finditer(folded) if not _is_quoted_retraction(folded, m)]


@pytest.mark.parametrize(
    "shipped",
    [
        # docs/PHI.md, the second residual
        "Neither is a completeness claim; the convention above remains the control for both.",
        # messagefoundry/redaction.py, a ``#:`` comment wrapped across two lines
        '#: takes no time; the "never put PHI in an exception message"\n#: convention remains the control.',
        # docs/CONFIGURATION.md, a blockquote with Markdown emphasis
        '> for which *"never put PHI in an exception message"*\n> remains the control. So',
        # tests/test_logging.py, a ``#`` comment
        '# the "never put PHI in an\n# exception message" convention is the control. Pin it.',
        # variants a reword could reach for
        'the "never put PHI in an exception message" convention is still the only control',
        'the "never put PHI in an exception message" convention** remains the **control**',
        # a claim near an unrelated correction is still the claim
        "**CORRECTED 2026-10-01:** this said the gate was per route. Neither is a completeness "
        "claim; the convention above remains the control for both.",
        'An UNCORRECTED fragment, read "x". The convention above remains the control for both.',
        # the convention's own opening quote is not a retraction quote (PR 2595 review); the
        # control is the dated CORRECTED note in test_the_scan_passes_other_prose
        'Corrected 2026-10-01: this said the gate was per route; the "never put PHI in an exception '
        'message" convention remains the control.',
        # a lowercase "corrected" in prose is no marker (PR 2595 review), dated or not; same control
        'the corrected wording read "the convention above remains the control for both".',
        'corrected 2026-10-28: this read "the convention above remains the control for both".',
        # the convention name's quote closed INSIDE the claim, right after the verb
        '**CORRECTED 2026-10-28:** this said "never put PHI in an exception message" is the control',
        # a retraction quote never closed by a double quote does not reach a later sentence
        '**CORRECTED 2026-10-28:** this read "per route”. Neither is a completeness claim; the '
        "convention above remains the control for both.",
    ],
)
def test_the_scan_finds_each_shipped_wording(shipped: str) -> None:
    assert _claims(shipped), shipped


def test_a_window_cut_through_uncorrected_is_no_marker() -> None:
    # Pad so the reach window opens two characters into "UNCORRECTED", at "CORRECTED".
    head = 'UNCORRECTED 2026-10-28: this read "'
    text = (
        head
        + "x" * (_CORRECTED_REACH + 1 - len(head))
        + ' the convention above remains the control"'
    )
    claim = text.index("the convention above")
    assert text[claim - _CORRECTED_REACH :].startswith("CORRECTED")
    assert _claims(text)
    # control: the same text with a real marker is a quoted retraction
    assert _claims(text.replace("UNCORRECTED", "--CORRECTED")) == []


@pytest.mark.parametrize(
    "prose",
    [
        'The "never put PHI in an exception message" convention covers it only in text the '
        "engine's own authors write.",
        "the SPDX header convention is the control here",  # another convention
        'the "never put PHI in an exception message" convention is the controller',
        # a retraction quoting the old claim verbatim
        '**CORRECTED 2026-10-28:** this read "the convention above remains the control for both".',
        '*Corrected 2026-10-01 (BACKLOG #2443 step 4):* this said "the convention above remains '
        'the control for both".',
        # the same, quoting the convention-name arm (inner quotes single, so the outer one stays open)
        "**CORRECTED 2026-10-28:** this said \"the 'never put PHI in an exception message' "
        'convention remains the control".',
        # the tree's other correction shapes: undated, a context in brackets, a capital verb,
        # underscore emphasis, and a quoted term before the verb
        '**CORRECTED:** this read "the convention above remains the control for both".',
        'CORRECTED (review of a87fcb2932): this comment said "the convention above remains the '
        'control for both".',
        '**CORRECTED 2026-10-28:** Read "the convention above remains the control for both".',
        '_Corrected 2026-10-01:_ this said "the convention above remains the control for both".',
        '**CORRECTED 2026-10-28:** this _read_ "the convention above remains the control for both".',
        '**CORRECTED 2026-10-28:** the "Who binds" note read "the convention above remains the '
        'control for both".',
    ],
)
def test_the_scan_passes_other_prose(prose: str) -> None:
    assert _claims(prose) == []


def _sources() -> list[Path]:
    me = Path(__file__).resolve()
    return sorted(
        path
        for top in _SCANNED
        for path in (_ROOT / top).rglob("*")
        if path.suffix in _SUFFIXES and path.is_file() and path.resolve() != me
    )


def test_no_document_names_the_convention_as_the_control() -> None:
    sources = _sources()
    # A moved root would scan nothing and pass; the floor catches an empty or wrong one.
    assert len(sources) > 500
    hits = {
        path.relative_to(_ROOT).as_posix(): found
        for path in sources
        if (found := _claims(path.read_text(encoding="utf-8")))
    }
    assert not hits, (
        f"{hits} -- the exception-message convention binds only the engine's own authors, never a "
        "remote peer; point at docs/PHI.md section 7, 'Who the exception-message convention binds'"
    )


def test_the_statement_the_pointers_cite_is_in_section_7() -> None:
    phi = (_ROOT / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert phi.count(_STATEMENT) == 1
    section_7 = phi.split("\n## 7.", 1)[1].split("\n## 8.", 1)[0]
    assert _STATEMENT in section_7
