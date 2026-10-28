# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No document calls the exception-message convention THE control for a redaction residual (BACKLOG #3464).

The "never put PHI in an exception message" convention binds only the people who write the engine, a
Router or a Handler. A diagnostic can quote text a remote peer wrote, and no convention of ours binds
that peer, so "the convention remains the control" was false for peer text. It was said in at least
ten places across five files. docs/PHI.md section 7 now states the fact once, under *Who the
exception-message convention binds*, and the other places point there.

This pins the absence of the old claim over ``docs/``, ``messagefoundry/`` and ``tests/``, with the
claim's own shipped wordings as the positive control, and pins that the statement the pointers cite
still exists. A future ``CORRECTED`` note quoting the old wording would trip it too; quote it with a
word changed instead.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCANNED = ("docs", "messagefoundry", "tests")
_SUFFIXES = frozenset({".md", ".py"})
_STATEMENT = "**Who the exception-message convention binds.**"

#: The claim, as it read before BACKLOG #3464, in each shape it took. Line breaks, comment markers and
#: Markdown emphasis are folded away first, so a claim wrapped across lines is still one sentence.
_CLAIM = re.compile(
    r"convention(?:\s+above)?\s+(?:remains|is)\s+the\s+control"
    r"|exception\s+message\W{0,4}\s+(?:remains|is)\s+the\s+control",
    re.IGNORECASE,
)
_LINE_MARKER = re.compile(r"^\s*(?:#:?|>)?\s*", re.MULTILINE)
#: A cheap first look on the raw text: ``\W+`` also spans a line break and its comment marker, so no
#: file that :data:`_CLAIM` would match after folding is skipped. Most files fail it and skip the fold.
_MAYBE = re.compile(r"the\W+control", re.IGNORECASE)


def _folded(text: str) -> str:
    return " ".join(_LINE_MARKER.sub("", text).split())


def _claims(text: str) -> list[str]:
    if not _MAYBE.search(text):
        return []
    return [m.group(0) for m in _CLAIM.finditer(_folded(text))]


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
    ],
)
def test_the_scan_finds_each_shipped_wording(shipped: str) -> None:
    assert _claims(shipped), shipped


def test_the_scan_passes_the_corrected_wording() -> None:
    corrected = (
        'The "never put PHI in an exception message" convention covers it only in text the '
        "engine's own authors write."
    )
    assert _claims(corrected) == []


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


def test_the_statement_the_pointers_cite_exists() -> None:
    phi = (_ROOT / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert phi.count(_STATEMENT) == 1
