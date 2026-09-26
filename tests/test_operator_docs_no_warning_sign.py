# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The swept docs carry no warning sign (U+26A0) -- BACKLOG #1265, one slice at a time.

CLAUDE.md section 11 rules U+26A0 decoration rather than a sixth holdout (owner-ruled 2026-08-14)
and states the cost; BACKLOG #1265 is the filed migration. Two slices are pinned here:

- the five shipped operator docs, which have external readers and no machine-parsed neighbours;
- every top-level Markdown file in ``docs/adr/`` (the glob does not recurse), found by glob so a
  NEW ADR is covered too, less the files in ``_ADR_NOT_YET``. Each of those is held to a ceiling,
  so its population cannot grow while it waits, and a test fails the day it reaches zero, so it
  moves into the pinned set rather than sitting unguarded.

**That is not a claim they are glyph-free.** Other glyphs are a separate population and outside
#1265. At least ``docs/CONNECTIONS.md`` still carries 124 U+2705 and 18 U+274C in its
connector-parity table, and several swept ADRs still carry U+26D4 or U+2705. This guard says
nothing about them, and a reader must not take a green run here as covering them.

Two design choices are load-bearing.

**The positive control is planted here, not borrowed from the ledger.** The item records that the
first census of this population returned a FALSE ZERO off a broken shell escape, and only a
control caught it -- five zeros from a scanner that never matches look exactly like five clean
files. The obvious control when this guard was written was ``docs/BACKLOG.md``, which then carried
the glyph in the hundreds, but that population was scheduled for the last slice of #1265; a control
that a later, correct sweep drives to zero would then fail this test for the wrong reason. So the
control is a string planted in the test, which measures the same thing (the scanner detects the
glyph when it is present) and stays true after every other slice lands.

**It matches a literal needle rather than reusing either existing glyph class.** ``_BANNED`` in
``scripts/asvs/apply.py`` is the right instrument for a security record and the wrong one here: it
also bans arrows, and the five operator docs alone carried 168 of those legitimately.
``_GLYPH_RANGES`` in ``scripts/telemetry/rule_telemetry.py`` already excludes arrows for that
reason, but it grades session events rather than files and still fires on the 3 U+23F3 in
``CONNECTIONS.md``. Either would answer a question adjacent to the one asked (SDS-3.8).
"""

from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: The warning sign, and the variation selector that usually trailed it in this corpus. Both are
#: named rather than pasted so this source file stays pure ASCII: a literal glyph here would be
#: the thing under test, and it would also raise UnicodeEncodeError on a stock cp1252 console.
_GLYPH = "\N{WARNING SIGN}"
_VS16 = "\N{VARIATION SELECTOR-16}"

#: The item's own "defensible first slice": external readers, no machine-parsed neighbours.
_OPERATOR_DOCS = (
    "docs/SECURITY.md",
    "docs/PHI.md",
    "docs/INSTALL-GUIDE.md",
    "docs/DEPLOYMENT.md",
    "docs/CONNECTIONS.md",
)

#: Files the docs/adr/ slice skipped, mapped to the U+26A0 count each carried then. README.md was
#: skipped because open pull requests 1444, 1481 and 1579 were editing it on 2026-09-26. The count
#: is a ceiling: a file may fall below it, never rise above it. Sweep one, then delete it here --
#: ``test_not_yet_adr_still_carries_the_glyph`` fails until you do.
_ADR_NOT_YET = {
    "docs/adr/README.md": 6,
}


def _adr_slice() -> tuple[str, ...]:
    """Every ``docs/adr/*.md`` outside ``_ADR_NOT_YET``, repo-relative."""
    found = (p.relative_to(_ROOT).as_posix() for p in (_ROOT / "docs" / "adr").glob("*.md"))
    return tuple(sorted(p for p in found if p not in _ADR_NOT_YET))


#: Repo-relative paths, so a later slice extends this by adding one -- what remains of the
#: population is not all under docs/ (at least harness/ and engine source still carry some).
_SWEPT = _OPERATOR_DOCS + _adr_slice()


def _sites(text: str, needle: str) -> list[int]:
    """Return the 1-indexed lines of ``text`` carrying ``needle``."""
    return [n for n, line in enumerate(text.splitlines(), 1) if needle in line]


def test_the_scanner_finds_the_glyph_when_it_is_present() -> None:
    """Positive control: without this, a zero below proves nothing about the files."""
    planted = f"clean\n{_GLYPH}{_VS16} a caution\nclean\n{_GLYPH} another\n"
    assert _sites(planted, _GLYPH) == [2, 4]
    assert _sites(planted, _VS16) == [2]
    assert _sites("no glyph here\n", _GLYPH) == []


def test_the_adr_glob_finds_the_adrs() -> None:
    """Positive control for the glob: an empty slice would pass every parametrized case below."""
    adrs = _adr_slice()
    assert "docs/adr/0072-traced-dryrun-mode.md" in adrs
    assert len(adrs) > 100, f"the docs/adr/ glob found only {len(adrs)} files"


@pytest.mark.parametrize("path", sorted(_ADR_NOT_YET))
def test_not_yet_adr_still_carries_the_glyph(path: str) -> None:
    """An exclusion that outlives its reason is an unguarded file nobody notices."""
    count = (_ROOT / path).read_text(encoding="utf-8").count(_GLYPH)
    assert count > 0, (
        f"{path} no longer carries U+26A0. Remove it from _ADR_NOT_YET so the guard pins it."
    )
    assert count <= _ADR_NOT_YET[path], (
        f"{path} carries {count} U+26A0, above its ceiling of {_ADR_NOT_YET[path]}. It is waiting "
        "for its slice of BACKLOG #1265, not open to new ones: say the word instead."
    )


@pytest.mark.parametrize("path", _SWEPT)
def test_swept_doc_carries_no_warning_sign(path: str) -> None:
    text = (_ROOT / path).read_text(encoding="utf-8")
    assert _sites(text, _GLYPH) == [], (
        f"{path} carries U+26A0 on these lines. Say the word the sentence means "
        "-- WARNING, DO NOT, CAUTION or NOTE -- rather than restoring the glyph (BACKLOG #1265)."
    )


@pytest.mark.parametrize("path", _SWEPT)
def test_swept_doc_keeps_no_variation_selector(path: str) -> None:
    """A half-removal leaves U+FE0F behind, and an invisible codepoint reviews as clean."""
    text = (_ROOT / path).read_text(encoding="utf-8")
    assert _sites(text, _VS16) == [], (
        f"{path} carries a U+FE0F. Nearly every U+26A0 in this corpus was followed by one, so "
        "the likely cause is a half-removed glyph. If it follows a different emoji instead, that "
        "emoji is outside BACKLOG #1265: write the word, or drop the selector."
    )
