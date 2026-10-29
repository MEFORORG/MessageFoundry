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
cite is still in section 7.

**Every match is flagged, whatever marker surrounds it.** A correction note that must quote the old
claim verbatim adds its own entry to :data:`_ALLOWED` in the same change, so a reviewer sees the
exemption beside the quote. An entry is a path and the exact quoted text, folded the way the scan
folds it. An entry whose text is no longer in its file, or holds no claim, fails
:func:`test_no_allowlist_entry_is_stale`. A marker-reading exemption was tried first and failed open
in at least seven shapes (PR 2595), which :func:`test_a_claim_is_flagged_whatever_marker_surrounds_it`
pins.
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

#: Real retractions that quote the old claim: ``(posix path from the repository root, exact quoted
#: text as folded)``. Empty: no file in the scanned trees quotes the claim today.
_ALLOWED: tuple[tuple[str, str], ...] = ()


def _folded(text: str) -> str:
    return " ".join(_LINE_MARKER.sub("", text).split())


def _claims(
    text: str, path: str = "", allowed: tuple[tuple[str, str], ...] = _ALLOWED
) -> list[str]:
    """Every claim in ``text``, less those wholly inside an allowlisted quote for ``path``."""
    if not _MAYBE.search(text):
        return []
    folded = _folded(text)
    spans = [
        (start, start + len(quote))
        for entry_path, quote in allowed
        if entry_path == path
        for start in (m.start() for m in re.finditer(re.escape(quote), folded))
    ]
    return [
        m.group(0)
        for m in _CLAIM.finditer(folded)
        if not any(lo <= m.start() and m.end() <= hi for lo, hi in spans)
    ]


def _stale(root: Path, allowed: tuple[tuple[str, str], ...]) -> list[tuple[str, str]]:
    """The entries whose quote is not in their file any more, or holds no claim to exempt."""
    stale = []
    for path, quote in allowed:
        target = root / path
        folded = _folded(target.read_text(encoding="utf-8")) if target.is_file() else ""
        if quote not in folded or not _CLAIM.search(quote):
            stale.append((path, quote))
    return stale


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
    ],
)
def test_the_scan_finds_each_shipped_wording(shipped: str) -> None:
    assert _claims(shipped), shipped


#: The shapes the marker-reading exemption at 09c971f14 let through (PR 2595 second hold), each
#: measured exempt there. With no marker reading, each is flagged.
_MARKER_SHAPES = {
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
    "a curly close, then a later quote": '**CORRECTED 2026-10-28:** this read "per route”. The '
    'convention above remains the control for both; see "Who binds".',
}


@pytest.mark.parametrize("shape", sorted(_MARKER_SHAPES))
def test_a_claim_is_flagged_whatever_marker_surrounds_it(shape: str) -> None:
    assert _claims(_MARKER_SHAPES[shape]), shape


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


_RETRACTION = (
    '**CORRECTED 2026-10-28:** this read "the convention above remains the control for both".'
)
_ENTRY = ("docs/EXAMPLE.md", 'this read "the convention above remains the control for both"')


def test_an_allowlisted_quote_passes_only_at_its_own_path() -> None:
    assert _claims(_RETRACTION, "docs/EXAMPLE.md", (_ENTRY,)) == []
    assert _claims(_RETRACTION, "docs/OTHER.md", (_ENTRY,))  # the same text elsewhere
    assert _claims(_RETRACTION, "docs/EXAMPLE.md", ())  # control: no entry, flagged
    # a second claim in the same file, outside the quote, is still flagged
    assert _claims(_RETRACTION + " The convention above remains the control.", _ENTRY[0], (_ENTRY,))


def test_an_allowlist_entry_gone_from_its_file_is_stale(tmp_path: Path) -> None:
    docs = tmp_path / "docs"
    docs.mkdir()
    (docs / "EXAMPLE.md").write_text(_RETRACTION + "\n", encoding="utf-8")
    assert _stale(tmp_path, (_ENTRY,)) == []  # control: present and holding a claim
    (docs / "EXAMPLE.md").write_text("reworded, no quote left\n", encoding="utf-8")
    assert _stale(tmp_path, (_ENTRY,)) == [_ENTRY]
    assert _stale(tmp_path, (("docs/GONE.md", _ENTRY[1]),)) == [("docs/GONE.md", _ENTRY[1])]
    no_claim = ("docs/EXAMPLE.md", "reworded")
    assert _stale(tmp_path, (no_claim,)) == [no_claim]  # present, but exempts nothing


def test_no_allowlist_entry_is_stale() -> None:
    assert _stale(_ROOT, _ALLOWED) == []


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
    hits = {}
    for path in sources:
        rel = path.relative_to(_ROOT).as_posix()
        if found := _claims(path.read_text(encoding="utf-8"), rel):
            hits[rel] = found
    assert not hits, (
        f"{hits} -- the exception-message convention binds only the engine's own authors, never a "
        "remote peer; point at docs/PHI.md section 7, 'Who the exception-message convention binds'. "
        "A correction that must quote the old claim verbatim adds an entry to _ALLOWED."
    )


def test_the_statement_the_pointers_cite_is_in_section_7() -> None:
    phi = (_ROOT / "docs" / "PHI.md").read_text(encoding="utf-8")
    assert phi.count(_STATEMENT) == 1
    section_7 = phi.split("\n## 7.", 1)[1].split("\n## 8.", 1)[0]
    assert _STATEMENT in section_7
