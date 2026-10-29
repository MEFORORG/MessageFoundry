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
cite is still in section 7. A correction note may quote the old wording verbatim: a match inside a
quote that opens right after ``read`` or ``said`` in a dated ``CORRECTED`` note
(:data:`_QUOTED_RETRACTION`) is a quoted retraction, not the claim.
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


#: How far back a correction marker may sit and still own a quoted claim: room for the marker's
#: date and a lead-in such as ``this read``, never a whole paragraph.
_CORRECTED_REACH = 200
#: A quoted retraction, in the house shape ``**CORRECTED 2026-10-28:** this read "..."``: a
#: ``CORRECTED`` or ``Corrected`` marker with its date (case-sensitive, so prose saying "the corrected
#: wording read" is not one, and ``UNCORRECTED`` is not one either), then in the same sentence
#: ``read`` or ``said`` with the quote opening RIGHT AFTER the verb, still open where the claim
#: starts. A quote opened anywhere else, such as the one around the convention's own name in
#: ``this said X; the "never put PHI ..." convention remains the control``, does not exempt a claim.
_QUOTED_RETRACTION = re.compile(
    r"\b(?:CORRECTED|Corrected)[*_\s]*\d{4}-\d{2}-\d{2}\b[^.\"]*?\b(?:read|said)[\s:*_]*\"[^\"]*$"
)


def _claims(text: str) -> list[str]:
    if not _MAYBE.search(text):
        return []
    folded = _folded(text)
    return [
        m.group(0)
        for m in _CLAIM.finditer(folded)
        if not _QUOTED_RETRACTION.search(folded[max(0, m.start() - _CORRECTED_REACH) : m.start()])
    ]


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
        # a lowercase "corrected" in prose is no marker (PR 2595 review); same control
        'the corrected wording read "the convention above remains the control for both".',
    ],
)
def test_the_scan_finds_each_shipped_wording(shipped: str) -> None:
    assert _claims(shipped), shipped


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
