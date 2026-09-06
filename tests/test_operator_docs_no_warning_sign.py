# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The five shipped operator docs carry no warning sign (U+26A0) -- BACKLOG #1265, first slice.

CLAUDE.md section 11 rules U+26A0 decoration rather than a sixth holdout (owner-ruled 2026-08-14)
and states the cost; BACKLOG #1265 is the filed migration. These five files have external readers
and no machine-parsed neighbours, so they are the slice this guard pins.

**That is not a claim they are glyph-free.** ``docs/CONNECTIONS.md`` still carries 124 U+2705 and
18 U+274C in its connector-parity table. Those are a separate population and outside #1265; this
guard says nothing about them, and a reader must not take a green run here as covering them.

Two design choices are load-bearing.

**The positive control is planted here, not borrowed from the ledger.** The item records that the
first census of this population returned a FALSE ZERO off a broken shell escape, and only a
control caught it -- five zeros from a scanner that never matches look exactly like five clean
files. The obvious control is ``docs/BACKLOG.md``, which carries the glyph in the hundreds, but
that population is itself scheduled for the last slice of #1265; a control that a later, correct
sweep drives to zero would then fail this test for the wrong reason. So the control is a string
planted in the test, which measures the same thing (the scanner detects the glyph when it is
present) and stays true after every other slice lands.

**It matches a literal needle rather than reusing either existing glyph class.** ``_BANNED`` in
``scripts/asvs/apply.py`` is the right instrument for a security record and the wrong one here: it
also bans arrows, and these five documents carry 168 of those legitimately. ``_GLYPH_RANGES`` in
``scripts/telemetry/rule_telemetry.py`` already excludes arrows for that reason, but it grades
session events rather than files and still fires on the 3 U+23F3 in ``CONNECTIONS.md``. Either
would answer a question adjacent to the one asked (SDS-3.8).
"""

from __future__ import annotations

from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parent.parent

#: The warning sign, and the variation selector that always trailed it in this corpus. Both are
#: named rather than pasted so this source file stays pure ASCII: a literal glyph here would be
#: the thing under test, and it would also raise UnicodeEncodeError on a stock cp1252 console.
_GLYPH = "\N{WARNING SIGN}"
_VS16 = "\N{VARIATION SELECTOR-16}"

#: The item's own "defensible first slice": external readers, no machine-parsed neighbours. Paths
#: are repo-relative rather than bare names so a later slice extends this tuple by adding one --
#: what remains of the population is not all under docs/ (26 sit in harness/, 3 in engine source).
_SWEPT = (
    "docs/SECURITY.md",
    "docs/PHI.md",
    "docs/INSTALL-GUIDE.md",
    "docs/DEPLOYMENT.md",
    "docs/CONNECTIONS.md",
)


def _sites(text: str, needle: str) -> list[int]:
    """Return the 1-indexed lines of ``text`` carrying ``needle``."""
    return [n for n, line in enumerate(text.splitlines(), 1) if needle in line]


def test_the_scanner_finds_the_glyph_when_it_is_present() -> None:
    """Positive control: without this, a zero below proves nothing about the files."""
    planted = f"clean\n{_GLYPH}{_VS16} a caution\nclean\n{_GLYPH} another\n"
    assert _sites(planted, _GLYPH) == [2, 4]
    assert _sites(planted, _VS16) == [2]
    assert _sites("no glyph here\n", _GLYPH) == []


@pytest.mark.parametrize("path", _SWEPT)
def test_swept_operator_doc_carries_no_warning_sign(path: str) -> None:
    text = (_ROOT / path).read_text(encoding="utf-8")
    assert _sites(text, _GLYPH) == [], (
        f"{path} carries U+26A0 on these lines. Say the word the sentence means "
        "-- WARNING, DO NOT, CAUTION or NOTE -- rather than restoring the glyph (BACKLOG #1265)."
    )


@pytest.mark.parametrize("path", _SWEPT)
def test_swept_operator_doc_keeps_no_orphan_variation_selector(path: str) -> None:
    """A half-removal leaves U+FE0F behind, and an invisible codepoint reviews as clean."""
    text = (_ROOT / path).read_text(encoding="utf-8")
    assert _sites(text, _VS16) == [], (
        f"{path} carries a stray U+FE0F. Every U+26A0 in this corpus was followed by one, "
        "so removing the glyph alone leaves an invisible character behind."
    )
