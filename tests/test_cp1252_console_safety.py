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

WHAT A SCRUBBING GATE WOULD DESTROY IN THIS REPOSITORY, MEASURED RATHER THAN IMAGINED. Besides the
banner alphabet, ``backlog_status_check.py`` carries one further non-cp1252 character: a lone U+FE0F
inside the banner regex, as ``[<class>]\\uFE0F?\\s``. That is an OPTIONAL VS-16, letting a banner be
written with or without the selector -- exactly the handling CLAUDE.md section 11 mandates for any
regex touching that alphabet. It is invisible at the point of use and looks like lint.

Delete it and the ``?`` binds to the CHARACTER CLASS instead. The pattern STILL COMPILES, so nothing
at author time objects. It then matches an indented continuation line (``^>\\s\\s``, which the ledger
is full of), ``b.group("emoji")`` returns ``None``, and the dispatch below it evaluates
``None in _CLOSED`` where ``_CLOSED`` is a ``str`` -- ``TypeError``, on any run that touches the real
ledger. Two failure modes, and the second is the dangerous one:

  * LOUDLY, TODAY -- every gate that calls ``parse_items`` dies, which is most of them.
  * SILENTLY, LATER -- the first banner authored WITH a selector stops matching. No banner carries
    one today, so nothing would catch that regression on the day it arrives.

That is the case for hardening the stream rather than scrubbing the file, and it is why the exemption
had to be expressible: one invisible character, removed by a well-meaning gate, takes out the reader
every ledger gate depends on.

NO COUNT IS PINNED IN THAT ARGUMENT, DELIBERATELY. The number of qualifying lines is ref-relative and
grows with every filed item, so a figure would be stale the moment it was written -- and re-reading
it would reproduce it, which reads as verification. That is the same hazard the banner in
``conftest.py`` refuses for the same reason. The mechanism above needs no number and is re-derivable
in one command on any ref.

THREE PROPERTIES THIS KEEPS, each of which the item names:

  * IT PRINTS WHAT IT SCANNED. A filtered scan that skips a file type reads as clean when it never
    looked. The inventory is asserted, not merely emitted, so a collapse to zero files fails here
    instead of passing silently.
  * IT READS THE WHOLE FILE, never line by line. ``str.splitlines()`` splits on U+2028 and U+2029 and
    consumes them, so a line-oriented scan is structurally blind to the two separators most likely to
    break a terminal.
  * IT NEVER SILENTLY DROPS A FILE. A file that will not decode as UTF-8 is a FAILURE, not a skip.

SCOPE, STATED RATHER THAN IMPLIED. ``scripts/**/*.py`` AND ``scripts/**/*.ps1``. The engine already
hardens both streams at ``messagefoundry/__main__.py``. ``docs/`` is deliberately out:
``docs/BACKLOG.md`` is a sanctioned holdout for that same alphabet.

THE POWERSHELL HALF WAS THE LARGER SURFACE AND WAS THE ONE STILL ON THE PER-FILE GATES THIS ITEM
NAMES AS THE DEFECT. Measured on this ref: **43 ``.ps1`` files against 37 ``.py``**, so the majority
of ``scripts/`` was ungated while this module's own thesis was that hand-placed gates decay. One of
the two per-file gates the item cites by name is a ``.ps1`` one (``tests/test_announce_hook.py``
asserts a single script is ASCII).

IT LANDS AS A RATCHET AT ZERO, AND THAT IS THE HONEST DESCRIPTION. Measured before writing it: **0 of
the 43 ``.ps1`` files carry a non-cp1252 character** -- with a positive control in the same run, the
detector finding 916 such characters across 29 distinct codepoints in ``docs/BACKLOG.md``, because a
census that returns zero everywhere is indistinguishable from a broken predicate and this repository
has produced exactly that false zero before. So this fixes no existing offender; it stops the class
recurring on the surface where it was least addressed.

THE POWERSHELL REMEDY IS A DIFFERENT CALL AND HAD TO BE, which is why the earlier scope note deferred
it. There is no ``sys.stdout.reconfigure`` in PowerShell; the equivalent property is rebinding the
console's output encoding, ``[Console]::OutputEncoding = [System.Text.Encoding]::UTF8``. That idiom is
already in this tree (``scripts/coord/overlap.ps1``, ``scripts/hooks/announce-session.ps1``), in both
cases wrapped in ``try {} catch {}`` because a redirected or headless host can refuse it -- so the
detector matches the ASSIGNMENT and does not require the try, which would make the signal a style
check rather than a capability one.

WHAT IS DELIBERATELY NOT GATED HERE: the DECODE direction. This module covers a script EMITTING a
character a cp1252 console cannot print, which aborts loudly. A tool that READS bytes through a cp1252
codec does not abort -- it returns a silent wrong answer, and a false zero is indistinguishable from a
clean result. That is the more dangerous half and it is untouched by this file; it is named in the
ledger item as an adjacent direction rather than filed as a number.
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


#: The PowerShell remedy, detected as a property of the file exactly as the Python one is. Rebinding
#: the console's output encoding is what actually stops the abort; a comment promising to is not. The
#: surrounding ``try {} catch {}`` both live sites use is deliberately NOT required -- a host that
#: refuses the assignment is a runtime condition, and requiring the wrapper would turn a capability
#: check into a style check.
_HARDENS_PS_CONSOLE = re.compile(
    r"\[Console\]\s*::\s*OutputEncoding\s*=", re.IGNORECASE | re.MULTILINE
)


def _python_scripts() -> list[Path]:
    return sorted(p for p in _SCRIPTS.rglob("*.py") if "__pycache__" not in p.parts)


def _powershell_scripts() -> list[Path]:
    return sorted(_SCRIPTS.rglob("*.ps1"))


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


# --- the PowerShell half (BACKLOG #1030 residual) --------------------------------------------------
# Same three properties as the Python half above, deliberately: print what was scanned, never silently
# drop an undecodable file, read whole files. The ONLY thing that differs is the remedy, because
# PowerShell has no stdout.reconfigure.


def test_the_powershell_scan_actually_covers_something() -> None:
    """The same positive control the Python walk carries, and it is not ceremony here either: this
    surface is the LARGER one (43 .ps1 against 37 .py when this landed), so a walk that collapses
    would hide more than the other one would."""
    found = _powershell_scripts()
    print(f"scanned {len(found)} powershell files under scripts/")
    assert len(found) >= 30, (
        f"only {len(found)} .ps1 files under scripts/ -- the walk is not finding them"
    )
    assert (_SCRIPTS / "coord" / "claim.ps1") in found


def test_every_powershell_script_decodes_as_utf8() -> None:
    """Undecodable is a FAILURE, never a skip -- same rule as the Python half, and the file most
    likely to carry the bytes this gate hunts is exactly the one that will not decode."""
    undecodable: list[str] = []
    for path in _powershell_scripts():
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            undecodable.append(f"{path.relative_to(_ROOT)}: {exc}")
    assert not undecodable, "not decodable as UTF-8:\n  " + "\n  ".join(undecodable)


def test_no_powershell_script_can_abort_a_cp1252_console() -> None:
    """THE GATE, PowerShell half. A script may carry non-cp1252 characters only if it rebinds the
    console's output encoding.

    A RATCHET AT ZERO WHEN IT LANDED, and saying so is the honest form: no .ps1 file carried such a
    character, so this caught nothing on arrival. It exists because the class has recurred at least
    three times on the Python side and the PowerShell surface was left on the per-file gates this
    module's own docstring names as the defect.
    """
    offenders: list[str] = []
    exempted: list[str] = []
    for path in _powershell_scripts():
        text = path.read_text(encoding="utf-8")
        bad = _unencodable(text)
        if not bad:
            continue
        rel = path.relative_to(_ROOT)
        shown = " ".join(f"U+{ord(c):04X}" for c in bad[:6])
        if _HARDENS_PS_CONSOLE.search(text):
            exempted.append(f"{rel} ({len(bad)} distinct: {shown})")
            continue
        offenders.append(
            f"{rel} carries {len(bad)} non-cp1252 character(s) [{shown}] and does NOT set "
            f"[Console]::OutputEncoding -- printing any of them aborts on a stock Windows console"
        )
    print(f"powershell carrying non-cp1252, hardened and therefore allowed: {exempted or 'none'}")
    assert not offenders, "\n  ".join(
        ["powershell scripts that can abort a cp1252 console:", *offenders]
    )


def test_the_powershell_hardening_signal_is_detected_and_is_not_vacuous() -> None:
    """The exemption must fire on the real idiom and must not fire on a promise to adopt it.

    THE LIVE FORM IS THE FIXTURE. Both sites in this tree wrap the assignment in ``try {} catch {}``
    because a redirected or headless host can refuse it; the detector matches the ASSIGNMENT without
    the wrapper, so a script that hardens unwrapped is still exempt and one that merely mentions the
    property is not.

    STATED RATHER THAN OVERCLAIMED: like its Python twin, this reads text, so a COMMENTED-OUT
    assignment would satisfy it. That is a known shared limitation of both halves, not a property
    this half is asserting away.
    """
    assert _HARDENS_PS_CONSOLE.search(
        "try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }"
    )
    assert _HARDENS_PS_CONSOLE.search("[console] :: OutputEncoding  =  $enc")  # spacing + case
    assert not _HARDENS_PS_CONSOLE.search("# we should set the console output encoding one day")
    assert not _HARDENS_PS_CONSOLE.search("Write-Output [Console]::OutputEncoding")  # a READ


def test_a_synthetic_powershell_offender_is_caught_and_a_hardened_one_is_not() -> None:
    """Both arms on manufactured input, so the gate is shown to discriminate without depending on the
    tree containing an offender -- which it does not, and should not have to."""
    glyph = chr(0x2192)
    bare = f'Write-Output "step {glyph} next"'
    hardened = (
        "try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }\n"
        f'Write-Output "step {glyph} next"'
    )
    assert _unencodable(bare) == [glyph]
    assert not _HARDENS_PS_CONSOLE.search(bare)
    assert _unencodable(hardened) == [glyph]
    assert _HARDENS_PS_CONSOLE.search(hardened)


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
