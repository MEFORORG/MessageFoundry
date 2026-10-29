# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No scanned file calls the exception-message convention THE control for a redaction residual (BACKLOG #3464).

The "never put PHI in an exception message" convention binds only the engine's own authors, in text
they write themselves. A diagnostic can quote text a remote peer wrote, which no convention of ours
binds, so "the convention remains the control" was false for peer text. It was said in ten places
across six files. docs/PHI.md section 7 now states the fact once, under *Who the exception-message
convention binds*, and the other places point there.

This pins the absence of the old claim, in the shapes the tests below hold, over ``docs/``,
``messagefoundry/``, ``tests/``, ``packaging/``, ``harness/`` and ``scripts/``. It is a lexical floor:
a paraphrase that never says "the control" passes it. It also pins that the statement the pointers
cite is still in section 7.

The guard cannot tell a claim from a retraction that quotes it, so it flags every match, and a note
recording that the claim was removed paraphrases it rather than quoting it. That is the trade
``tests/test_worktree_new_cleanup_advice.py`` makes for its own stale claim. PR 2595 tried two
exemptions for quoted retractions: a marker-reading rule, which failed open in at least the seven
shapes :data:`_HOLD_SHAPES` pins, and then an explicit allowlist, which no file in the tree needed.
Both were removed.
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


def _claims(text: str) -> list[str]:
    """Every claim in ``text``, in order, each as the folded words that matched."""
    if not _MAYBE.search(text):
        return []
    folded = " ".join(_LINE_MARKER.sub("", text).split())
    return [m.group(0) for m in _CLAIM.finditer(folded)]


def _sources(root: Path) -> list[Path]:
    me = Path(__file__).resolve()
    return sorted(
        path
        for top in _SCANNED
        for path in (root / top).rglob("*")
        if path.suffix in _SUFFIXES and path.is_file() and path.resolve() != me
    )


#: The shapes the marker-reading exemption let through on PR 2595, each measured exempt there and
#: named in the Lander's second hold. With no exemption, each is flagged.
_HOLD_SHAPES = {
    "a quote, then a later quote": '**CORRECTED 2026-10-28:** this read "per route"; it should read '
    '"the convention above remains the control for both".',
    "a later sentence": '**CORRECTED 2026-10-28:** this was per route. The fix said "the convention '
    'above remains the control for both".',
    "prose opening with Corrected": "Corrected ACK handling landed in 2026. The spec said "
    '"the convention above remains the control for both".',
    "NOT CORRECTED": 'NOT CORRECTED: this read "the convention above remains the control for both".',
    "CORRECTED-by-design": 'CORRECTED-by-design: this read "the convention above remains the '
    'control for both".',
    "CORRECTEDLY": 'CORRECTEDLY: this read "the convention above remains the control for both".',
    "a curly close, then a later quote": '**CORRECTED 2026-10-28:** this read "per route'
    "\N{RIGHT DOUBLE QUOTATION MARK}. The convention above remains the control for both; see "
    '"Who binds".',
}

#: Wordings the scan must flag: the shipped ones, variants a reword could reach for, and claims near
#: a correction marker, which were flagged before PR 2595 tried an exemption.
_MUST_FLAG = {
    "PHI.md, the second residual": "Neither is a completeness claim; the convention above remains "
    "the control for both.",
    "redaction.py, a #: comment wrapped across two lines": "#: takes no time; the "
    '"never put PHI in an exception message"\n#: convention remains the control.',
    "CONFIGURATION.md, a blockquote with emphasis": '> for which *"never put PHI in an exception '
    'message"*\n> remains the control. So',
    "test_logging.py, a # comment": '# the "never put PHI in an\n# exception message" convention '
    "is the control. Pin it.",
    "is still the only control": 'the "never put PHI in an exception message" convention is still '
    "the only control",
    "emphasis around the verb": 'the "never put PHI in an exception message" convention** remains '
    "the **control**",
    "after a CORRECTED marker": "**CORRECTED 2026-10-01:** this said the gate was per route. "
    "Neither is a completeness claim; the convention above remains the control for both.",
    "after UNCORRECTED": 'An UNCORRECTED fragment, read "x". The convention above remains the '
    "control for both.",
    "quoted after UNCORRECTED": 'UNCORRECTED 2026-10-28: this read "the convention above remains '
    'the control for both".',
    "the name's own quote after Corrected": "Corrected 2026-10-01: this said the gate was per "
    'route; the "never put PHI in an exception message" convention remains the control.',
    "quoted after lowercase corrected": 'the corrected wording read "the convention above remains '
    'the control for both".',
    "quoted after a lowercase marker": 'corrected 2026-10-28: this read "the convention above '
    'remains the control for both".',
    "the name quoted after CORRECTED": '**CORRECTED 2026-10-28:** this said "never put PHI in an '
    'exception message" is the control',
    "a curly close before the claim": '**CORRECTED 2026-10-28:** this read "per route'
    "\N{RIGHT DOUBLE QUOTATION MARK}. Neither is a completeness claim; the convention above "
    "remains the control for both.",
    **{f"hold shape: {name}": text for name, text in _HOLD_SHAPES.items()},
}


@pytest.mark.parametrize("name", sorted(_MUST_FLAG))
def test_the_scan_flags_each_wording(name: str) -> None:
    assert _claims(_MUST_FLAG[name]), name


def test_every_claim_in_a_text_is_reported_by_its_own_words() -> None:
    retraction = (
        'CORRECTED 2026-10-28: this read "the convention above remains the control for both".'
    )
    assert _claims(retraction + " The convention above remains the control.") == [
        "the convention above remains the control",
        "The convention above remains the control",
    ]
    assert len(_claims(retraction + "\n" + retraction)) == 2


@pytest.mark.parametrize(
    "prose",
    [
        'The "never put PHI in an exception message" convention covers it only in text the '
        "engine's own authors write.",
        "the SPDX header convention is the control here",  # another convention
        'the "never put PHI in an exception message" convention is the controller',
    ],
)
def test_the_scan_passes_other_prose(prose: str) -> None:
    assert _claims(prose) == []


def test_no_scanned_file_names_the_convention_as_the_control() -> None:
    sources = _sources(_ROOT)
    # A moved root would scan nothing and pass; the floor catches an empty or wrong one.
    assert len(sources) > 500, f"scanned only {len(sources)} files under {_ROOT}"
    hits = [
        f"{rel}: {claim!r}"
        for path in sources
        for rel in [path.relative_to(_ROOT).as_posix()]
        for claim in _claims(path.read_text(encoding="utf-8"))
    ]
    assert not hits, (
        "the old claim is back:\n  "
        + "\n  ".join(hits)
        + "\nThe exception-message convention binds only the engine's own authors, never a remote "
        "peer; point at docs/PHI.md section 7, 'Who the exception-message convention binds'. This "
        "guard cannot tell a quote from a claim, so to record the old claim, paraphrase it rather "
        "than quote it."
    )


def test_the_statement_the_pointers_cite_is_in_section_7() -> None:
    phi = (_ROOT / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert phi.count(_STATEMENT) == 1, (
        f"docs/PHI.md holds {_STATEMENT!r} {phi.count(_STATEMENT)} times"
    )
    section_7 = phi.split("\n## 7.", 1)[1].split("\n## 8.", 1)[0]
    assert _STATEMENT in section_7, f"{_STATEMENT!r} is no longer in docs/PHI.md section 7"
