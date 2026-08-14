# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""No script under ``scripts/`` can abort on a stock Windows console (BACKLOG #1030).

THE DEFECT THIS REPLACES. Enforcement was per-file and hand-placed: ``tests/test_cli.py`` asserts one
STRING is cp1252-encodable, ``tests/test_announce_hook.py`` asserts one FILE is ASCII, and
``tests/test_session_mail.py`` names five mail scripts in a literal list. None generalises, so a glyph
reaching ``print()`` from any other script was caught only by a human reading the diff -- and the
class recurred at least three times.

WHAT IS GATED, AND WHY IT IS NOT BARE ENCODABILITY. The failure is a character reaching a stream that
can RAISE, not a character existing. ``sys.stdout`` carries ``errors='surrogateescape'``, which
round-trips only lone surrogates in DC80-DCFF; every other unencodable codepoint still raises.
``sys.stderr`` carries ``backslashreplace`` and never raises -- that asymmetry, not a strict/non-strict
split, is why the same text survives on stderr and aborts on stdout.

So a file may carry non-cp1252 characters IF IT HARDENS ITS OWN STDOUT. That is not an exemption list:
it is a property of the file, checked mechanically, and it is the actual remedy rather than a promise
about one. ``scripts/docs/backlog_status_check.py`` is exactly why the distinction is load-bearing --
its argparse description quotes the machine-parsed banner alphabet CLAUDE.md section 11 protects, and
remediation text that cannot show an author the character it wants added is not actionable. A gate
that could not express that would fire on correct code and be switched off.

THREE PROPERTIES THIS KEEPS, each of which the item names:

  * IT PRINTS WHAT IT SCANNED. A filtered scan that skips a file type reads as clean when it never
    looked. The inventory is asserted, not merely emitted, so a collapse to zero files fails here
    instead of passing silently.
  * IT READS THE WHOLE FILE, never line by line. ``str.splitlines()`` splits on U+2028 and U+2029 and
    consumes them, so a line-oriented scan is structurally blind to the two separators most likely to
    break a terminal.
  * IT NEVER SILENTLY DROPS A FILE. A file that will not decode as UTF-8 is a FAILURE, not a skip.

SCOPE, STATED RATHER THAN IMPLIED. ``scripts/**/*.py`` only. The engine already hardens both streams
at ``messagefoundry/__main__.py``, and the ``.ps1`` surface has no equivalent reconfigure, so
generalising to PowerShell is a different decision and is left to the existing per-file gates.
``docs/`` is deliberately out: ``docs/BACKLOG.md`` is a sanctioned holdout for that same alphabet.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"

#: The remedy, detected as a property of the file. A call that rebinds stdout's codec is the only
#: thing that actually stops the abort, which is why it -- and not a promissory comment -- is the
#: signal. Matched loosely on the call itself so a keyword reordering does not silently un-exempt.
_HARDENS_STDOUT = re.compile(r"stdout\s*\.\s*reconfigure\s*\(", re.MULTILINE)


def _python_scripts() -> list[Path]:
    return sorted(p for p in _SCRIPTS.rglob("*.py") if "__pycache__" not in p.parts)


def _unencodable(text: str) -> list[str]:
    """Distinct characters cp1252 cannot represent, in codepoint order.

    Whole-string, deliberately: see the module docstring on ``splitlines`` eating U+2028/U+2029.
    """
    bad: set[str] = set()
    for ch in set(text):
        try:
            ch.encode("cp1252")
        except UnicodeEncodeError:
            bad.add(ch)
    return sorted(bad)


def test_the_scan_actually_covers_something() -> None:
    """PRINT AND PIN WHAT WAS SCANNED. A scan whose file list collapses to nothing reports a clean
    result forever; this is the positive control that stops that being indistinguishable from green.
    """
    found = _python_scripts()
    print(f"scanned {len(found)} python files under scripts/")
    assert len(found) >= 25, (
        f"only {len(found)} files under scripts/ -- the walk is not finding them"
    )
    assert (_SCRIPTS / "docs" / "backlog_status_check.py") in found


def test_every_script_file_decodes_as_utf8() -> None:
    """A file that will not decode is a FAILURE, never a silent skip -- an undecodable file is the
    one most likely to carry the bytes this gate exists to find."""
    undecodable: list[str] = []
    for path in _python_scripts():
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            undecodable.append(f"{path.relative_to(_ROOT)}: {exc}")
    assert not undecodable, "not decodable as UTF-8:\n  " + "\n  ".join(undecodable)


def test_no_script_can_abort_a_cp1252_console() -> None:
    """The gate itself: a script may carry non-cp1252 characters only if it hardens its own stdout."""
    offenders: list[str] = []
    exempted: list[str] = []
    for path in _python_scripts():
        text = path.read_text(encoding="utf-8")
        bad = _unencodable(text)
        if not bad:
            continue
        rel = path.relative_to(_ROOT)
        shown = " ".join(f"U+{ord(c):04X}" for c in bad[:6])
        if _HARDENS_STDOUT.search(text):
            exempted.append(f"{rel} ({len(bad)} distinct: {shown})")
            continue
        offenders.append(
            f"{rel} carries {len(bad)} non-cp1252 character(s) [{shown}] and does NOT "
            f"reconfigure sys.stdout -- printing any of them aborts on a stock Windows console"
        )
    print(f"carrying non-cp1252 characters, hardened and therefore allowed: {exempted or 'none'}")
    assert not offenders, "\n  ".join(["scripts that can abort a cp1252 console:", *offenders])


# --- the detector's own controls, so a green above is evidence rather than a pattern that quietly
# --- stopped matching ----------------------------------------------------------------------------

#: Built with chr(), never literals. This file must stay cp1252-clean itself -- a gate whose own
#: test could abort the console it defends would be the joke version of this item -- and chr() also
#: keeps it inside CLAUDE.md section 11, naming a character without adopting one. Every entry has a
#: recorded failure behind it; none is hypothetical.
_BROKE_SOMETHING = [
    chr(0x2192),  # broke `messagefoundry --help` (the adr-analyze arrow)
    chr(0x2705),  # banner alphabet; broke this repo's own backlog gate --help
    chr(0x26D4),  # banner alphabet
    chr(0x1F522),  # banner alphabet; the documented cp1252 console crash
    chr(0x2194),  # crashed a scanner mid-scan this session, TRUNCATING its output
    chr(0x2028),  # line separator: invisible to any splitlines()-based scan
    chr(0x2029),  # paragraph separator: same
]


@pytest.mark.parametrize("ch", _BROKE_SOMETHING, ids=lambda c: f"U+{ord(c):04X}")
def test_the_detector_sees_every_character_that_has_actually_broken_something(ch: str) -> None:
    assert _unencodable(f"x{ch}y") == [ch]


def test_the_detector_does_not_fire_on_representable_text() -> None:
    """U+2014 and U+00A3 ARE cp1252-representable and must not be flagged. The item calls this out:
    a gate that fires on an em dash gets switched off within a day."""
    text = "plain ASCII, an em dash " + chr(0x2014) + ", and a pound sign " + chr(0x00A3)
    assert _unencodable(text) == []


def test_the_line_oriented_blindness_is_real_and_this_scan_avoids_it() -> None:
    """Demonstrates the mechanism instead of asserting it: ``splitlines()`` CONSUMES U+2028, so a
    line-oriented scan is structurally unable to see it. The whole-string scan does."""
    sep = chr(0x2028)
    text = "before" + sep + "after"
    assert sep not in "".join(text.splitlines()), "splitlines would have hidden it"
    assert _unencodable(text) == [sep]


def test_the_hardening_signal_is_detected_and_is_not_vacuous() -> None:
    """The exemption must be the REMEDY itself, not a promise about one."""
    assert _HARDENS_STDOUT.search('sys.stdout.reconfigure(encoding="utf-8", errors="replace")')
    assert _HARDENS_STDOUT.search("sys . stdout . reconfigure ( encoding='utf-8' )")
    assert not _HARDENS_STDOUT.search("# we should probably reconfigure stdout one day")
    assert not _HARDENS_STDOUT.search("sys.stderr.reconfigure(encoding='utf-8')")


def test_a_synthetic_offender_is_caught_and_a_hardened_one_is_not() -> None:
    """The gate proved in BOTH directions, on files it has never seen."""
    glyph = chr(0x2705)
    bare = f'print("{glyph} done")'
    hardened = 'import sys; sys.stdout.reconfigure(encoding="utf-8"); ' + bare
    assert _unencodable(bare) == [glyph]
    assert not _HARDENS_STDOUT.search(bare)
    assert _unencodable(hardened) == [glyph]
    assert _HARDENS_STDOUT.search(hardened)
