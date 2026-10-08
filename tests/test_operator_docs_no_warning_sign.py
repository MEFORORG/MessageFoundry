# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The swept files carry no warning sign (U+26A0) -- BACKLOG #1265, one slice at a time.

CLAUDE.md section 11 rules U+26A0 decoration rather than a sixth holdout (owner-ruled 2026-08-14)
and states the cost; BACKLOG #1265 is the filed migration. Three slices are pinned here:

- the five shipped operator docs, which have external readers and no machine-parsed neighbours;
- every top-level Markdown file in ``docs/adr/`` (the glob does not recurse), found by glob so a
  NEW ADR is covered too;
- the live docs and the code comments and docstrings, under the owner ruling of 2026-09-30:
  "the sweep extends beyond docs/adr/ to live docs and code comments. Dated benchmark and status
  records are exempt and must be named as exempt. The CLA and license banners are reviewed
  separately, not in this sweep."

Every file that still carries the glyph is named in ``_HELD`` with a ceiling and a reason, or sits
under a dated-record prefix in ``_DATED_RECORDS``. ``test_no_unlisted_file_carries_the_warning_sign``
walks every tracked file, so a glyph added anywhere else fails, not only in a file listed here.

**That is not a claim the swept files are glyph-free.** Other glyphs are a separate population and
outside #1265. At least ``docs/CONNECTIONS.md`` still carries 124 U+2705 and 18 U+274C in its
connector-parity table, and several swept ADRs still carry U+26D4 or U+2705. This guard says
nothing about them, and a reader must not take a green run here as covering them.

Two design choices are load-bearing.

**The positive controls are planted or dated, never a file a later slice would clean.** The first
census of this population returned a FALSE ZERO off a broken shell escape, and only a control
caught it. So the scanner is proved on a string planted in this test, and the tree walk is proved
on a dated benchmark record that is exempt from the sweep and so stays non-zero.

**It matches a literal needle rather than reusing either existing glyph class.** ``_BANNED`` in
``scripts/asvs/apply.py`` is the right instrument for a security record and the wrong one here: it
also bans arrows, and the five operator docs alone carried 168 of those legitimately.
``GLYPH`` in ``scripts/quality/glyph_ranges.py``, which telemetry and the new-glyph hook share,
already excludes arrows for that reason. It judges new lines and session events rather than one
file's census, and it fires on far more than the warning sign: in ``CONNECTIONS.md`` alone it
matches the check marks, the cross marks and the 3 U+23F3. Either would answer a question adjacent to the one asked (SDS-3.8).
"""

from __future__ import annotations

import subprocess
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

#: The live-docs and code-comment slice (owner ruling 2026-09-30). Only files that reached zero
#: are listed; a file that kept a glyph on purpose is in ``_HELD`` instead.
_LIVE_SLICE = (
    "docs/AOAG-DEPLOYMENT.md",
    "docs/ASVS-ASSESSMENT-METHOD.md",
    "docs/CI-SELFHOSTED-RUNNER.md",
    "docs/CONFIGURATION.md",
    "docs/CONTAINER-EXPOSURE-EVALUATION.md",
    "docs/EARLY-ADOPTER-GUIDE.md",
    "docs/LEDGER-GATE.md",
    "docs/SERVICE.md",
    "docs/SESSION-MAIL.md",
    "docs/SYSTEM-REQUIREMENTS.md",
    "docs/THROUGHPUT.md",
    "harness/config/shardcert/_shape.py",
    "harness/load/enginepoll.py",
    "messagefoundry/api/_ui_seam.py",
    "messagefoundry/auth/totp.py",
    "messagefoundry/config/settings.py",
    "messagefoundry_webconsole/_external.py",
    "messagefoundry_webconsole/routes/oidc.py",
    "tests/test_dependabot_automerge_guardrails.py",
    "tests/test_docs_db_grants.py",
    "tests/test_security_doc_drift.py",
    "tests/test_totp_window.py",
    "tests/test_ui_oidc_interstitial_route.py",
)

#: Dated measurement and handoff records. Exempt by the 2026-09-30 ruling: they record what a run
#: said on its day, and rewriting one edits history rather than live guidance. Three carriers here
#: have no date in their NAME -- TUNING-BASELINE.md, shardcert-ceiling-ladder.md and
#: PLAN-ENGINE-ATTRIBUTION.md -- and are exempt as benchmark records that date themselves inside.
_DATED_RECORDS = ("docs/benchmarks/",)

_UI_STRING = (
    "the glyph is inside a user-visible string literal, not a comment, so changing it changes "
    "behaviour"
)

#: Every file outside ``_DATED_RECORDS`` that still carries U+26A0, mapped to the count it carried
#: when this slice landed and the reason it kept it. The count is a ceiling: a file may fall below
#: it, never rise above it. When one reaches zero, move it into a swept tuple and delete it here --
#: ``test_held_file_still_carries_the_glyph`` fails until you do.
_HELD: dict[str, tuple[int, str]] = {
    "CHANGELOG.md": (1, "dated release record"),
    "CLA.md": (1, "legal banner, reviewed separately by the owner"),
    "COMMERCIAL-LICENSE.md": (1, "licence banner, reviewed separately by the owner"),
    "tests/test_ledger_check.py": (
        2,
        "deliberate non-ASCII test data (NON_ASCII_BODY, a ROW title)",
    ),
    "ide/src/hl7Picker.ts": (1, _UI_STRING + " (the UNVERIFIED badge ADR 0072 quotes)"),
    "ide/src/liveDebug.ts": (1, _UI_STRING),
    "ide/src/stepsModel.ts": (1, _UI_STRING),
    "harness/load/shardcert_ladder.py": (3, _UI_STRING + " (printed report lines)"),
    "harness/load/shardcert.py": (1, _UI_STRING + " (a printed report line)"),
}

#: A dated record that must stay non-zero: the tree walk's positive control.
_TREE_CONTROL = "docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md"


def _adr_slice() -> tuple[str, ...]:
    """Every ``docs/adr/*.md``, repo-relative."""
    found = (p.relative_to(_ROOT).as_posix() for p in (_ROOT / "docs" / "adr").glob("*.md"))
    return tuple(sorted(found))


_SWEPT = _OPERATOR_DOCS + _adr_slice() + _LIVE_SLICE


def _sites(text: str, needle: str) -> list[int]:
    """Return the 1-indexed lines of ``text`` carrying ``needle``."""
    return [n for n, line in enumerate(text.splitlines(), 1) if needle in line]


def _tree_census() -> dict[str, int]:
    """U+26A0 count per tracked file that carries at least one.

    It counts the glyph's UTF-8 bytes rather than decoding, so a file with one stray non-UTF-8
    byte is still read rather than skipped along with its glyphs.
    """
    out = subprocess.run(  # nosec B603 B607 - fixed argv, no shell
        ["git", "-C", str(_ROOT), "ls-files", "-z"],
        capture_output=True,
        check=True,
        timeout=120,
    ).stdout.decode("utf-8")
    needle = _GLYPH.encode("utf-8")
    census: dict[str, int] = {}
    for rel in out.split("\0"):
        path = _ROOT / rel
        if not rel or not path.is_file():
            continue
        count = path.read_bytes().count(needle)
        if count:
            census[rel] = count
    return census


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
    assert "docs/adr/README.md" in adrs
    assert len(adrs) > 100, f"the docs/adr/ glob found only {len(adrs)} files"


def test_no_unlisted_file_carries_the_warning_sign() -> None:
    """Every tracked carrier is a dated record or named in ``_HELD``; nothing else may gain one."""
    census = _tree_census()
    assert census.get(_TREE_CONTROL, 0) > 0, (
        f"the tree walk found no U+26A0 in {_TREE_CONTROL}, an exempt dated record that carries "
        "it. The walk is broken, so its silence about every other file proves nothing."
    )
    # Cannot fail after the control above. It restates that control in the one form the
    # vacuous-absence lint reads as a guard; the control above is the real check.
    assert census, "the tree census is empty"
    unlisted = sorted(
        rel for rel in census if rel not in _HELD and not rel.startswith(_DATED_RECORDS)
    )
    assert unlisted == [], (
        f"these tracked files carry U+26A0 and are neither swept nor held: {unlisted}. Say the "
        "word the sentence means -- WARNING, DO NOT, CAUTION or NOTE (BACKLOG #1265)."
    )


@pytest.mark.parametrize("path", sorted(_HELD))
def test_held_file_still_carries_the_glyph(path: str) -> None:
    """An exemption that outlives its reason is an unguarded file nobody notices."""
    ceiling, reason = _HELD[path]
    count = (_ROOT / path).read_text(encoding="utf-8").count(_GLYPH)
    assert count > 0, (
        f"{path} no longer carries U+26A0 (held because: {reason}). Remove it from _HELD and "
        "add it to a swept tuple so the guard pins it."
    )
    assert count <= ceiling, (
        f"{path} carries {count} U+26A0, above its ceiling of {ceiling}. It is held because: "
        f"{reason}. That does not open it to new ones: say the word instead."
    )


def test_swept_and_held_do_not_overlap() -> None:
    """A path in both sets would be asserted clean and non-zero at once, and one arm must lie."""
    assert sorted(set(_SWEPT) & set(_HELD)) == []


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
