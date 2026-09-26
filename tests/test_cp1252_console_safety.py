# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Five gated surfaces cannot abort a stock Windows console (BACKLOG #1030).

The surfaces are named under SCOPE below, with the roots still outside them. This file was
scripts-only when it shipped, and widening it is the item's whole point, so the summary line
counts surfaces rather than naming one.

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
about one. It is checked in the PARSED code, never in the text (BACKLOG #1875): a textual check let a
file that merely mentioned the remedy in a comment or a string go unwatched, and it meant hardening a
file for real was indistinguishable from talking about it.

``scripts/docs/backlog_status_check.py`` was exactly why the distinction is load-bearing (it left with
the ledger, BACKLOG #1250) -- its argparse description quoted the machine-parsed banner alphabet, and
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

SCOPE, STATED RATHER THAN IMPLIED. Five surfaces and two predicates, in file order:
``scripts/**/*.py`` here and ``scripts/**/*.ps1`` next gate on ENCODABILITY; ``messagefoundry/`` in
the third section and ``harness/`` plus ``tests/`` in the fourth gate on REACHING a console. Which
predicate a surface gets is a measurement, not a preference, and the section that applies it
carries the count. The fourth section also names the roots that are still OUT, with their sizes.

``docs/`` IS DELIBERATELY OUT, AND ITS POSITIVE CONTROL DIED UNDER IT. ``docs/BACKLOG.md`` was both
a sanctioned holdout for the banner alphabet and this detector's control at 29 distinct non-cp1252
codepoints; the ledger left for the maintainer-internal repository (BACKLOG #1250) and the 23-line
stub that remains carries ZERO -- measured 2026-09-21, same instrument. Re-running the old control
now reproduces a false zero and reads as a clean tree. CLAUDE.md section 11 names the replacement
and it holds on the same run: ``docs/FEATURE-MAP.md`` at 10 distinct codepoints and
``docs/CONNECTIONS.md`` at 7. A detector that finds nothing anywhere is indistinguishable from a
clean tree, and this repository has produced a false zero on exactly this census before.
"""

from __future__ import annotations

import ast
import functools
import re
import tomllib
from pathlib import Path
from typing import NamedTuple

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_SCRIPTS = _ROOT / "scripts"

#: THE EXEMPTION IS A FACT ABOUT THE PARSED CODE, NEVER ABOUT THE TEXT (BACKLOG #1875). It used to be
#: a substring match, so any file that MENTIONED the remedy in a comment, a docstring or an unexecuted
#: string was exempt, and this very module was exempt by accident on its own assertion literals. A
#: gate whose scope a comment can change is a gate any edit can switch off without anybody noticing.
#:
#: The remedy is now one shared chokepoint, `messagefoundry.console_streams.harden_console_streams`,
#: and a file counts as hardened only if its syntax tree holds a real CALL to it, bound by a real
#: IMPORT from that module, as the FIRST statement of a module-level `main()`. A comment or a string
#: is not a Call node, and a local function that happens to share the name is not the import, so
#: neither can satisfy it. The position is part of the rule: a call in some other function (a test
#: that exercises the helper, say) or after the first print proves nothing about the stream the
#: file's output meets, and a module with no `main()` cannot know whether its caller hardened.
_CHOKEPOINT_MODULE = "messagefoundry.console_streams"
_CHOKEPOINT = "harden_console_streams"


def _chokepoint_names(tree: ast.Module) -> tuple[frozenset[str], frozenset[str]]:
    """(bare names, dotted module paths) through which this file can reach the chokepoint.

    A ``from messagefoundry.console_streams import harden_console_streams [as x]`` binds a bare
    name; an ``import messagefoundry.console_streams [as m]`` binds a module path whose attribute
    is then called. Two forms are refused and fail loud rather than being guessed at, because no
    file uses either today: a RELATIVE import, whose target depends on where the file sits, and
    ``from messagefoundry import console_streams``.
    """
    names: set[str] = set()
    modules: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            if node.level == 0 and node.module == _CHOKEPOINT_MODULE:
                names.update(a.asname or a.name for a in node.names if a.name == _CHOKEPOINT)
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name == _CHOKEPOINT_MODULE:
                    modules.add(a.asname or a.name)
    return frozenset(names), frozenset(modules)


def _first_statement_of_main(tree: ast.Module) -> ast.stmt | None:
    """The first statement of a module-level ``def main``, skipping a docstring; else None."""
    for node in tree.body:
        if isinstance(node, ast.FunctionDef) and node.name == "main":
            body = node.body
            if (
                body
                and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)
                and isinstance(body[0].value.value, str)
            ):
                body = body[1:]
            return body[0] if body else None
    return None


def _calls_the_chokepoint(tree: ast.Module) -> bool:
    """Does ``main()`` harden the streams through the shared helper before it does anything else?"""
    first = _first_statement_of_main(tree)
    if not (isinstance(first, ast.Expr) and isinstance(first.value, ast.Call)):
        return False
    names, modules = _chokepoint_names(tree)
    func = first.value.func
    if isinstance(func, ast.Name):
        return func.id in names
    return (
        isinstance(func, ast.Attribute)
        and func.attr == _CHOKEPOINT
        and ".".join(_dotted(func.value)) in modules
    )


def _reconfigures_stdout(tree: ast.AST) -> bool:
    """Is there a real ``<...>.stdout.reconfigure(encoding=... or errors=...)`` call?

    The scripts half's second form. Some gated scripts are stdlib-only by contract and cannot import
    the engine, so the scripts half also accepts the direct call, anywhere in the file, as the
    textual check it replaces did. It is still read from the tree, so a comment cannot fake it, and
    a call that sets neither keyword (``line_buffering=True``, say) changes no codec and does not
    count.
    """
    for node in ast.walk(tree):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "reconfigure"
            and _dotted(node.func.value)[-1:] == ["stdout"]
            and any(kw.arg in ("encoding", "errors") for kw in node.keywords)
        ):
            return True
    return False


def _script_hardens(text: str) -> bool:
    """The scripts half's exemption: the chokepoint, or a direct stdout reconfigure call.

    A file that will not parse is NOT hardened, so its characters are reported rather than excused.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return False
    return _calls_the_chokepoint(tree) or _reconfigures_stdout(tree)


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
    # A NAMED FILE, NOT JUST A COUNT: a walk can find 25 files and still miss the directory you care
    # about. This anchor was `docs/backlog_status_check.py` until the ledger left the repository
    # (BACKLOG #1250) and that script went with it; `docs/link_check.py` is its replacement in the
    # same directory, so the control still proves the walk reaches `scripts/docs/`.
    assert (_SCRIPTS / "docs" / "link_check.py") in found


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
        if _script_hardens(text):
            exempted.append(f"{rel} ({len(bad)} distinct: {shown})")
            continue
        offenders.append(
            f"{rel} carries {len(bad)} non-cp1252 character(s) [{shown}] and does NOT harden "
            f"its stdout (call {_CHOKEPOINT_MODULE}.{_CHOKEPOINT}, or sys.stdout.reconfigure in "
            f"a stdlib-only script) -- printing any of them aborts on a stock Windows console"
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
    assert _script_hardens('sys.stdout.reconfigure(encoding="utf-8", errors="replace")')
    assert _script_hardens("sys . stdout . reconfigure ( encoding='utf-8' )")
    assert not _script_hardens("# we should probably reconfigure stdout one day")
    assert not _script_hardens("sys.stderr.reconfigure(encoding='utf-8')")


def test_a_mention_of_the_remedy_is_not_the_remedy() -> None:
    """THE DEFECT BACKLOG #1875 NAMES, pinned. Every one of these satisfied the old substring match,
    because each contains ``stdout.reconfigure(`` as text. None of them executes it."""
    for mention in (
        "# sys.stdout.reconfigure(errors='replace') would fix this",
        '"""Call sys.stdout.reconfigure(encoding="utf-8") first."""',
        "HINT = \"sys.stdout.reconfigure(encoding='utf-8')\"",
        "print('try sys.stdout.reconfigure(errors=\"replace\")')",
        "# harden_console_streams() is called by the entry point",
    ):
        assert not _script_hardens(mention), mention


def test_a_synthetic_offender_is_caught_and_a_hardened_one_is_not() -> None:
    """The gate proved in BOTH directions, on files it has never seen."""
    glyph = chr(0x2705)
    bare = f'print("{glyph} done")'
    hardened = 'import sys; sys.stdout.reconfigure(encoding="utf-8"); ' + bare
    via_chokepoint = chr(10).join(
        [f"from {_CHOKEPOINT_MODULE} import {_CHOKEPOINT}", "def main():", f"    {_CHOKEPOINT}()"]
    ) + (chr(10) + "    " + bare)
    assert _unencodable(bare) == [glyph]
    assert not _script_hardens(bare)
    assert _unencodable(hardened) == [glyph]
    assert _script_hardens(hardened)
    assert _script_hardens(via_chokepoint)


# =================================================================================================
# THE POWERSHELL HALF (BACKLOG #1030). See ADR 0178 for the derivation.
#
# WHY THE LARGER SURFACE WAS THE UNGATED ONE. Measured 2026-08-28: 54 `.ps1` files under `scripts/`
# against 47 `.py`. The half this file already gated was the smaller one.
#
# THE CONTROL THAT SHOWED THE GAP, run before a line of this section was written: the SAME character
# (U+2192) planted in `scripts/asvs/apply.py` and in `scripts/coord/claim.ps1`, one gate, one run.
# The offenders list named the `.py` and did not contain the `.ps1`. With only the `.ps1` poisoned
# the suite was fully green.
#
# THE FAILURE MODE IS WORSE HERE, AND THAT IS MEASURED RATHER THAN ASSUMED. Python raises
# UnicodeEncodeError, which is catchable, loud, and leaves a traceback. PowerShell SUBSTITUTES.
# Driven through both real hosts with the console pinned to cp1252, every arm returned rc=0 and
# none raised: the character came back as `?`, or as three wrong characters, and the script
# reported success. A silent corruption is strictly harder to notice than a crash.
#
# TWO INDEPENDENT CHANNELS, WHERE PYTHON HAS ONE -- the hard part of this item, measured
# 2026-08-28 on WinPS 5.1.26100 and pwsh 7.6.5, console forced to cp1252 for every run:
#
#   host       source BOM   [Console]::OutputEncoding   decode   encode   character survives
#   WinPS 5.1  no           no                          BAD      ok       NO
#   WinPS 5.1  no           YES                         BAD      BAD      NO
#   WinPS 5.1  YES          no                          ok       BAD      NO   (substituted '?')
#   WinPS 5.1  YES          YES                         ok       ok       YES
#   pwsh 7.6   no           no                          ok       BAD      NO   (substituted '?')
#   pwsh 7.6   no           YES                         ok       ok       YES
#   pwsh 7.6   YES          no                          ok       BAD      NO
#   pwsh 7.6   YES          YES                         ok       ok       YES
#
# Source DECODING (WinPS 5.1 reads a BOM-less file as ANSI; pwsh 7 defaults to UTF-8) and output
# ENCODING (fixed by `[Console]::OutputEncoding`) are separate, and EITHER ALONE LEAVES THE
# CHARACTER DESTROYED. `sys.stdout.reconfigure` has no second channel to miss.
#
# AN EARLIER READING OF THIS EXEMPTION IS REFUTED ABOVE, WHICH IS WHY THE TABLE IS HERE. A prior
# unlanded attempt at this gate exempted any file assigning `[Console]::OutputEncoding`, on the
# reasoning that requiring more "would turn a capability check into a style check". Row 2 is that
# predicate's blind spot: on WinPS 5.1 a BOM-less hardened file is STILL BROKEN. The predicate is
# kept anyway, but as a HOST-CONDITIONAL claim rather than a universal one --
#
# THE HOST ASSUMPTION, STATED BECAUSE THE PREDICATE DEPENDS ON IT. This repository standardises on
# pwsh 7: measured 2026-08-28, 19 `pwsh` references across `.github/`, `.claude/`, `scripts/` and
# CLAUDE.md. Row 6 is therefore the governing row for ALMOST every script here, and on it the
# assignment alone IS sufficient. Under WinPS 5.1 it is not, and that caveat is load-bearing rather
# than decorative -- see the next block, where "almost" turns out to have a named exception.
#
# WHY A BOM IS NOT REQUIRED OF EVERY FILE. On the governing host a BOM is neither necessary (row 6
# survives without one) nor sufficient (row 7 fails with one). And 0 of 54 `.ps1` files carry one
# today, so requiring it everywhere would be a 54-file rewrite riding a zero-diff ratchet.
#
# BUT "NOTHING HERE RUNS WinPS 5.1" IS FALSE, AND THE FIRST VERSION OF THIS GATE ASSERTED IT.
# The claim was measured with a grep scoped to `.github/`, `.claude/`, `scripts/` and CLAUDE.md,
# which returned zero `powershell.exe` -- and that instrument answered a NARROWER question than the
# one being asked (SDS-3.8). Widening the scan to the engine finds the counterexample:
#
#   messagefoundry/service.py:270  ShellExecuteW(None, "runas", "powershell.exe", params, ...)
#
# `powershell.exe` is Windows PowerShell 5.1, NOT pwsh 7, and `params` runs
# `scripts/service/install-service.ps1` -- a file inside the surface this section gates. So exactly
# one gated script has a shipped WinPS 5.1 entry point, and on that host row 2 says the
# `[Console]::OutputEncoding` exemption is NOT SUFFICIENT.
#
# Left as prose, that would be a compensating control resting on a false premise, which CLAUDE.md
# section 11 (SDS-3.7) forbids outright. So it is closed in the predicate instead: for a script
# reachable under WinPS 5.1, the exemption additionally requires a UTF-8 BOM -- both channels, as
# rows 1-4 demand. Measured 2026-08-28 this changes nothing today (install-service.ps1 is BOM-less
# and unhardened but carries ZERO non-cp1252 characters, so it is clean on the encodability test and
# never reaches the exemption at all). It is armed for the day someone adds a glyph and "fixes" it
# with the one-line remedy that is correct everywhere else in this repository.
#
# A SIDE EFFECT THE PYTHON REMEDY DOES NOT HAVE, measured rather than reasoned about. Python's
# `reconfigure` rebinds one process's own wrapper. The PowerShell assignment mutates the SHARED
# console: a child was observed taking the code page from 1252 to 65001, and it STAYED 65001 after
# that child exited, while the parent's cached `[Console]::OutputEncoding` still reported 1252.
# The remedy is correct and is still the right one to require -- but it is not free, and a reader
# comparing the two surfaces should not assume the analogy is exact.
#
# THIS LANDS AS A RATCHET AT ZERO, NOT AS A REPAIR. Measured 2026-08-28: 0 of 54 `.ps1` files carry
# a non-cp1252 character, so this commit changes no script and fixes no live break. The zero is a
# MEASUREMENT, not a silent predicate -- the same detector, on the same run, reports 29 distinct
# codepoints in `docs/BACKLOG.md`. It is a regression gate for a class that has already recurred.
# =================================================================================================

#: The remedy, detected as a property of the file, exactly as the Python half does it. Matched
#: case-insensitively because PowerShell is case-insensitive and `[console]::outputencoding` is a
#: legal spelling of the same statement; a case-sensitive test would silently un-exempt a correct
#: file. Both in-tree forms are covered -- `[System.Text.Encoding]::UTF8` and
#: `[Text.UTF8Encoding]::new($false)` -- because the trailing expression is deliberately NOT
#: constrained: what matters is that the property is ASSIGNED, not which UTF-8 encoder is chosen.
#:
#: THE `=` IS THE WHOLE POINT AND IS REQUIRED. A READ (`[Console]::OutputEncoding.CodePage`, or a
#: comparison with `-eq`) hardens nothing, and a gate that accepted one would exempt files on the
#: strength of a mention. `$OutputEncoding` is deliberately NOT matched: it is a different variable
#: governing what is piped INTO native commands, not what reaches the console.
_HARDENS_PS_CONSOLE = re.compile(
    r"\[\s*(?:System\.)?Console\s*\]\s*::\s*OutputEncoding\s*=(?!=)", re.IGNORECASE
)


#: Scripts with a shipped Windows PowerShell 5.1 entry point, where the assignment ALONE is not
#: enough (row 2) and the exemption additionally requires a UTF-8 BOM. Kept as an explicit list
#: rather than inferred, because "who launches this file, and with which host" is not a property
#: the file itself carries. `test_the_winps_entry_point_is_still_real` re-derives the one entry
#: from the engine source on every run, so this cannot rot into a stale claim unnoticed.
_RUN_UNDER_WINDOWS_POWERSHELL = frozenset({"service/install-service.ps1"})


def _powershell_scripts() -> list[Path]:
    return sorted(_SCRIPTS.rglob("*.ps1"))


def _hardens_ps_console(path: Path, text: str, raw: bytes) -> bool:
    """Is this file's non-cp1252 content actually safe on the host that runs it?

    Both channels where both channels are reachable. For a pwsh-7-only script the output-encoding
    assignment is sufficient; for one launched by `powershell.exe` the source must ALSO carry a
    UTF-8 BOM, or WinPS 5.1 reads it as ANSI and the character is destroyed before it is printed.
    """
    if not _HARDENS_PS_CONSOLE.search(text):
        return False
    rel = path.relative_to(_SCRIPTS).as_posix()
    if rel in _RUN_UNDER_WINDOWS_POWERSHELL:
        return raw.startswith(b"\xef\xbb\xbf")
    return True


def test_the_powershell_scan_actually_covers_something() -> None:
    """PRINT AND PIN WHAT WAS SCANNED, for the reason the Python half states: a walk that collapses
    to nothing reports a clean result forever. `claim.ps1` is pinned by name because it is the file
    the pre-build control poisoned to prove this surface was invisible."""
    found = _powershell_scripts()
    print(f"scanned {len(found)} powershell files under scripts/")
    assert len(found) >= 45, (
        f"only {len(found)} .ps1 files under scripts/ -- the walk is not finding them"
    )
    assert (_SCRIPTS / "coord" / "claim.ps1") in found


def test_every_powershell_script_decodes_as_utf8() -> None:
    """A file that will not decode is a FAILURE, never a silent skip.

    Sharper on this surface than on the Python one: an undecodable `.ps1` is the exact artefact
    the WinPS-5.1 ANSI-decode row above produces, so treating it as a skip would hide the very
    failure this section was written to describe.
    """
    undecodable: list[str] = []
    for path in _powershell_scripts():
        try:
            path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            undecodable.append(f"{path.relative_to(_ROOT)}: {exc}")
    assert not undecodable, "not decodable as UTF-8:\n  " + "\n  ".join(undecodable)


def test_no_powershell_script_can_abort_a_cp1252_console() -> None:
    """The gate: a `.ps1` may carry non-cp1252 characters only if it hardens the console itself."""
    offenders: list[str] = []
    exempted: list[str] = []
    for path in _powershell_scripts():
        raw = path.read_bytes()
        text = raw.decode("utf-8")
        bad = _unencodable(text)
        if not bad:
            continue
        rel = path.relative_to(_ROOT)
        shown = " ".join(f"U+{ord(c):04X}" for c in bad[:6])
        if _hardens_ps_console(path, text, raw):
            exempted.append(f"{rel} ({len(bad)} distinct: {shown})")
            continue
        winps = path.relative_to(_SCRIPTS).as_posix() in _RUN_UNDER_WINDOWS_POWERSHELL
        extra = (
            " -- and because the engine launches it via powershell.exe (Windows PowerShell 5.1, "
            "messagefoundry/service.py), it ALSO needs a UTF-8 BOM: without one WinPS 5.1 reads "
            "the source as ANSI and destroys the character before it is ever printed"
            if winps
            else ""
        )
        offenders.append(
            f"{rel} carries {len(bad)} non-cp1252 character(s) [{shown}] and is not hardened "
            f"(assign [Console]::OutputEncoding) -- on a stock Windows console PowerShell "
            f"SUBSTITUTES the character and still exits 0, so the corruption is silent{extra}"
        )
    print(f"carrying non-cp1252 characters, hardened and therefore allowed: {exempted or 'none'}")
    assert not offenders, "\n  ".join(
        ["powershell scripts that can corrupt a cp1252 console:", *offenders]
    )


# --- the powershell detector's own controls ------------------------------------------------------


def test_the_winps_entry_point_is_still_real() -> None:
    """RE-DERIVE THE WinPS 5.1 LIST FROM THE ENGINE, never trust the constant.

    `_RUN_UNDER_WINDOWS_POWERSHELL` encodes a fact about a CALLER, which the called file cannot
    carry -- exactly the kind of claim that rots silently. This reads `service.py` and checks the
    two halves that make the entry point real: it launches `powershell.exe` (which is Windows
    PowerShell 5.1, NOT pwsh 7), and the script it launches is the one named in the constant.

    If service.py ever moves to `pwsh`, this fails and the constant should LOSE that entry -- the
    stricter rule would then be protecting a host nothing uses.
    """
    src = (_ROOT / "messagefoundry" / "service.py").read_text(encoding="utf-8")
    assert '"powershell.exe"' in src, (
        "service.py no longer launches powershell.exe -- if it moved to pwsh, drop the entry from "
        "_RUN_UNDER_WINDOWS_POWERSHELL, because the BOM requirement then guards nothing"
    )
    for rel in _RUN_UNDER_WINDOWS_POWERSHELL:
        assert (_SCRIPTS / rel).is_file(), f"{rel} is listed but does not exist"
        assert Path(rel).name in src, f"{rel} is listed but service.py does not launch it"


def test_the_winps_exemption_requires_both_channels() -> None:
    """The stricter arm, proved to DIFFER from the pwsh-7 arm on identical content.

    Same text, same glyph, same hardening line -- exempt as an ordinary script, NOT exempt as the
    one the engine runs under WinPS 5.1 unless the source also carries a BOM. If these two did not
    diverge, the WinPS rule would be a second name for the ordinary one.
    """
    glyph = chr(0x2192)
    text = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n" + f'Write-Host "{glyph}"'
    raw = text.encode("utf-8")
    with_bom = b"\xef\xbb\xbf" + raw

    ordinary = _SCRIPTS / "coord" / "claim.ps1"
    winps = _SCRIPTS / next(iter(_RUN_UNDER_WINDOWS_POWERSHELL))

    assert _hardens_ps_console(ordinary, text, raw), "pwsh-7 script: assignment alone suffices"
    assert not _hardens_ps_console(winps, text, raw), "WinPS script: a BOM-less file is NOT safe"
    assert _hardens_ps_console(winps, text, with_bom), "WinPS script: both channels together are"
    # And a BOM without the assignment is still not enough, in either place (rows 3 and 7).
    bare = f'Write-Host "{glyph}"'
    assert not _hardens_ps_console(winps, bare, b"\xef\xbb\xbf" + bare.encode("utf-8"))
    assert not _hardens_ps_console(ordinary, bare, b"\xef\xbb\xbf" + bare.encode("utf-8"))


def test_the_powershell_hardening_signal_matches_both_in_tree_spellings() -> None:
    """Proved against the real files, not a reconstruction, so a rewrite of either one fails here.

    Reading the shipped text also stops the regex being tuned to a form nobody uses.
    """
    for rel in ("coord/overlap.ps1", "coord/claim-adjudicate.ps1", "hooks/announce-session.ps1"):
        real = (_SCRIPTS / rel).read_text(encoding="utf-8")
        assert _HARDENS_PS_CONSOLE.search(real), f"{rel} assigns it and must be seen to"


def test_the_powershell_hardening_signal_is_not_vacuous() -> None:
    """The exemption must be the REMEDY, not a mention of one. A read, a comparison, a promissory
    comment and the unrelated `$OutputEncoding` variable must all fail to exempt."""
    assert _HARDENS_PS_CONSOLE.search("[Console]::OutputEncoding = [System.Text.Encoding]::UTF8")
    assert _HARDENS_PS_CONSOLE.search(
        "[Console]::OutputEncoding = [Text.UTF8Encoding]::new($false)"
    )
    assert _HARDENS_PS_CONSOLE.search("[System.Console]::OutputEncoding=[Text.Encoding]::UTF8")
    # PowerShell is case-insensitive; so is the signal.
    assert _HARDENS_PS_CONSOLE.search("[console]::outputencoding = [text.encoding]::utf8")
    # A READ hardens nothing.
    assert not _HARDENS_PS_CONSOLE.search("$cp = [Console]::OutputEncoding.CodePage")
    assert not _HARDENS_PS_CONSOLE.search("if ([Console]::OutputEncoding -eq $utf8) { }")
    assert not _HARDENS_PS_CONSOLE.search("# we should probably set [Console]::OutputEncoding")
    # A DIFFERENT variable: governs input to native commands, not console output.
    assert not _HARDENS_PS_CONSOLE.search("$OutputEncoding = [System.Text.Encoding]::UTF8")


def test_a_synthetic_powershell_offender_is_caught_and_a_hardened_one_is_not() -> None:
    """Both directions, on text the gate has never seen -- and note the hardened arm KEEPS the
    character. The remedy is hardening the stream, never scrubbing the source."""
    glyph = chr(0x2192)
    bare = f'Write-Host "depth {glyph} 3"'
    hardened = "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n" + bare
    assert _unencodable(bare) == [glyph]
    assert not _HARDENS_PS_CONSOLE.search(bare)
    assert _unencodable(hardened) == [glyph], "the character must survive the remedy"
    assert _HARDENS_PS_CONSOLE.search(hardened)


def test_the_powershell_detector_discriminates_on_encodability_not_on_ascii() -> None:
    """U+00E9 is non-ASCII but cp1252 encodes it at 0xE9, so it must NOT fire. A gate that
    degraded into an ASCII-only rule would fire on legitimately accented strings and be switched
    off; `scripts/hooks/announce-session.ps1` keeps an ASCII-only source by its own separate rule,
    and that is a per-file choice this class-wide gate must not silently generalise."""
    assert _unencodable("resume" + chr(0x00E9) + " and an em dash " + chr(0x2014)) == []
    assert _unencodable("arrow " + chr(0x2192)) == [chr(0x2192)]


# =================================================================================================
# THE ENGINE HALF (BACKLOG #1030, the Dispatcher's 2026-08-22 amendment).
#
# The amendment measured that this item's scope sentence -- "the surface is scripts/ rather than the
# engine" -- is backwards: 0 of 39 gated script files carried U+2192 against 134 of 267 engine files
# and 1,028 lines. It also said plainly that 1,028 is A POPULATION, NOT A DEFECT COUNT, because a
# character only bites if it REACHES a console, and that nobody had measured that subset.
#
# MEASURED 2026-08-27, and the subset is two orders of magnitude smaller. Of 1,647 non-cp1252
# characters across the engine's 267 files: 865 sit in comments (never evaluated), 759 in docstrings
# (which reach a console only through --help or help()), and 23 in evaluable string literals. Of
# those 23, exactly ONE is lexically inside a call that writes to a console.
#
# THAT MEASUREMENT DECIDES THE PREDICATE, WHICH THE ITEM NAMES AS THE OPEN DESIGN QUESTION --
# "whether to gate on encodability or on reaching an unguarded stream, since those give different
# answers for a file that reconfigures". Gating the engine on ENCODABILITY, the way the scripts half
# above is gated, fires 1,647 times and would be switched off the same day. Gating on REACH fires
# once. The scripts half keeps the wider predicate because it can afford to: measured on the same
# run, all 46 script files carry 12 such characters between them, in a single file that hardens
# itself. Two predicates, two surfaces, both stated rather than implied.
#
# WHY IT IS WORTH GATING WHEN NO SHIPPED PATH IS BROKEN TODAY. messagefoundry/__main__.py:main()
# reconfigures both streams, NSSM launches "messagefoundry serve", and uvicorn.run is called from
# inside __main__.py -- so every shipped entry point is hardened and the one live site is protected
# by the file it lives in. THE PROTECTION IS ONE FUNCTION CALL AWAY FROM ANY NEW ENTRY POINT, and
# nothing detects a new printed glyph. That is this item's whole thesis: enforcement that is
# hand-placed decays between sweeps.
# =================================================================================================

_ENGINE = _ROOT / "messagefoundry"


# THE REACH ROOTS ACCEPT ONE REMEDY: `_calls_the_chokepoint` (BACKLOG #1875). Before that item this
# was a substring test -- ``reconfigure(`` plus the word ``stdout`` anywhere in the file -- so a
# comment or a docstring exempted a file, and this module exempted itself on its own assertion
# literals. It also made hardening a file look exactly like removing it from the gate, which is why
# PR 1403 scrubbed ``harness/reconcile/__main__.py`` rather than hardening it.
#
# The three sites that hardened by hand (the engine CLI and two harness CLIs) now call the helper,
# so there is one chokepoint and one shape to recognise. The direct ``sys.stdout.reconfigure`` form
# is NOT accepted here, unlike the scripts half, because a second accepted shape is how a second,
# divergent hardening creeps back in. The cost falls on a test listed in tests/tooling_manifest.txt,
# which may not import the engine: it has no legal remedy but to print ASCII. That is the right one
# for a test anyway, which should not rebind the process streams pytest is capturing; it is what PR
# 1403 did for tests/test_benchmark_parser.py.


#: Logging method names. A record that cannot encode is NOT a crash -- logging catches the
#: UnicodeEncodeError in the handler, reports it on stderr and DROPS the record. So the failure mode
#: on this path is a silently missing log line, which is why a promissory comment will not do.
_LOG_METHODS = frozenset(
    {"debug", "info", "warning", "warn", "error", "exception", "critical", "log"}
)


@functools.cache
def _modules_under(root: Path) -> tuple[Path, ...]:
    """Every Python file under ``root``, recursively. Shared by all three reach surfaces.

    Cached, because the three tests per surface would otherwise re-walk the same tree; a TUPLE, so
    the cached result cannot be mutated out from under a sibling test that has not run yet.
    """
    return tuple(sorted(p for p in root.rglob("*.py") if "__pycache__" not in p.parts))


def _engine_modules() -> tuple[Path, ...]:
    return _modules_under(_ENGINE)


def _dotted(node: ast.expr) -> list[str]:
    """The dotted path of an attribute chain, outermost last. `self._log.warning` -> the 3 parts."""
    parts: list[str] = []
    while isinstance(node, ast.Attribute):
        parts.append(node.attr)
        node = node.value
    if isinstance(node, ast.Name):
        parts.append(node.id)
    return list(reversed(parts))


def _writes_to_a_console(call: ast.Call) -> bool:
    """Does this call put its arguments on stdout/stderr?

    Deliberately LEXICAL and deliberately narrow. It does not chase a string through a variable,
    so it under-reports by construction -- which is the right direction for a gate: every hit is
    real, and the cost of a miss is a character that was already only a risk.
    """
    func = call.func
    if isinstance(func, ast.Name) and func.id == "print":
        return True
    if not isinstance(func, ast.Attribute):
        return False
    parts = _dotted(func)
    if func.attr == "write" and len(parts) >= 2 and parts[-2] in ("stdout", "stderr"):
        return True
    # A logger is identified by its NAME rather than by its type, because the type is not available
    # to a static scan. `log`, `logger`, `self._log` and `logging` all match; `self.catalog.info()`
    # deliberately does not, because "catalog" is not a segment that equals a logger name.
    return func.attr in _LOG_METHODS and any(
        part.strip("_").lower() in ("log", "logger", "logging") for part in parts[:-1]
    )


def _printed_unencodable(text: str) -> list[tuple[int, str]]:
    """(line, character) for every non-cp1252 character inside a console-bound string literal.

    PER-CHARACTER VIA THE AST, NOT PER-LINE. A line-oriented version of this was written first and
    was wrong in a way that read as a clean result: on

        self._alert_leadership_lost("released")  # #145: clean step-down (inverse -> auto-resolve)

    a line scan sees a string token spanning the line and files the COMMENT's character as a live
    string. Measured on this repo, that inflated the engine's reach count from 15 to 31 and every
    inflated entry looked plausible in the dump. Only the argument subtree is walked here, so a
    comment and a docstring are out of scope by construction rather than by exclusion.
    """
    try:
        tree = ast.parse(text)
    except SyntaxError:  # a file that will not parse is caught by its own test below
        return []
    return _console_hits(tree)


def _console_hits(tree: ast.Module) -> list[tuple[int, str]]:
    """The tree-taking half of ``_printed_unencodable``, so a caller that has already parsed the
    file does not pay for a second parse. The controls below call the text-taking form."""
    hits: list[tuple[int, str]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not _writes_to_a_console(node):
            continue
        for arg in list(node.args) + [kw.value for kw in node.keywords]:
            for sub in ast.walk(arg):
                if isinstance(sub, ast.Constant) and isinstance(sub.value, str):
                    for ch in _unencodable(sub.value):
                        hits.append((sub.lineno, ch))
    return sorted(set(hits))


def test_the_engine_scan_actually_covers_something() -> None:
    """The same positive control the scripts half carries, for the same reason.

    It pins __main__.py by name because a `messagefoundry/**/*.py` git pathspec DROPS every
    top-level file -- measured on this repo: 240 files against 267 from three other spellings, and
    the 27 it loses include __main__.py, the one file whose hardening this whole scope rests on.
    """
    found = _engine_modules()
    print(f"scanned {len(found)} python files under messagefoundry/")
    assert len(found) >= 200, f"only {len(found)} engine files -- the walk is not finding them"
    assert (_ENGINE / "__main__.py") in found


class _RootScan(NamedTuple):
    """What one pass over a root found: the gate's two lists, plus the files it could not read."""

    offenders: tuple[str, ...]
    exempted: tuple[str, ...]
    unreadable: tuple[str, ...]


@functools.cache
def _scan_root(root: Path) -> _RootScan:
    """ONE read and ONE parse per file, shared by the two tests that consume this root.

    One implementation for all three reach surfaces. A second hand-written copy of this loop is how
    two roots end up disagreeing about what a hardened file is, and the disagreement is silent.

    Cached and returning tuples, because the gate test and the readability test below must stay
    SEPARATE -- a file that cannot be read is a named failure of its own, never folded into the
    gate's result -- while reading and parsing 1,200 files twice is pure waste. Measured 2026-09-21
    before this was shared: the two passes were most of this module's runtime.

    A file that fails to decode or parse lands in `unreadable` and contributes nothing to the other
    two lists. That is not a silent skip; the test that asserts on `unreadable` names it.
    """
    offenders: list[str] = []
    exempted: list[str] = []
    unreadable: list[str] = []
    for path in _modules_under(root):
        rel = path.relative_to(_ROOT)
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError as exc:
            unreadable.append(f"{rel}: not UTF-8: {exc}")
            continue
        try:
            tree = ast.parse(text)
        except SyntaxError as exc:
            unreadable.append(f"{rel}: will not parse: {exc}")
            continue
        hits = _console_hits(tree)
        if not hits:
            continue
        shown = ", ".join(f"line {ln} U+{ord(c):04X}" for ln, c in hits[:6])
        if _calls_the_chokepoint(tree):
            exempted.append(f"{rel} ({shown})")
            continue
        offenders.append(
            f"{rel} sends {len(hits)} non-cp1252 character(s) [{shown}] to a console and does "
            f"NOT call {_CHOKEPOINT_MODULE}.{_CHOKEPOINT} -- on a stock Windows console print() "
            f"aborts and a log record is DROPPED with only a stderr notice"
        )
    return _RootScan(tuple(offenders), tuple(exempted), tuple(unreadable))


def test_no_engine_module_puts_an_unencodable_character_on_a_console() -> None:
    """The engine gate: a console-bound literal stays cp1252-safe unless its file hardens stdout."""
    scan = _scan_root(_ENGINE)
    print(f"console-bound and hardened, therefore allowed: {list(scan.exempted) or 'none'}")
    assert not scan.offenders, "\n  ".join(
        ["engine modules that can lose or abort console output:", *scan.offenders]
    )


def test_every_engine_module_decodes_as_utf8_and_parses() -> None:
    """Never a silent skip, for both reasons: a file that will not decode is the likeliest to carry
    the bytes this gate hunts, and a file that will not parse would make _printed_unencodable return
    an empty list that is indistinguishable from a clean one."""
    broken = _scan_root(_ENGINE).unreadable
    assert not broken, "engine modules the scan could not read:\n  " + "\n  ".join(broken)


# --- the engine detector's own controls ----------------------------------------------------------


def test_the_engine_detector_catches_a_console_bound_glyph() -> None:
    """Caught in each of the three shapes that actually occur in this repo."""
    glyph = chr(0x2192)
    assert _printed_unencodable(f'print("a {glyph} b")') == [(1, glyph)]
    assert _printed_unencodable(f'sys.stdout.write("a {glyph} b")') == [(1, glyph)]
    assert _printed_unencodable(f'log.warning("depth %d{glyph}%d", a, b)') == [(1, glyph)]


def test_the_engine_detector_ignores_what_is_never_evaluated() -> None:
    """The precision that makes the gate survivable. These are the 1,624 characters a naive
    encodability scan over the engine would report, and every one of them is a false positive."""
    glyph = chr(0x2192)
    assert _printed_unencodable(f"x = 1  # a comment with {glyph} in it") == []
    assert _printed_unencodable(f'"""A module docstring with {glyph}."""\nx = 1') == []
    # A bare assignment is not a call, so it is out of scope by construction.
    assert _printed_unencodable(f'BOM_STRIP = "{glyph}"') == []
    # A literal bound to a name and never printed is out of scope: the scan is lexical by design.
    assert _printed_unencodable(f'name = f"{{a}} {glyph} b"') == []


def test_the_engine_detector_does_not_fire_on_representable_text() -> None:
    """An em dash and a pound sign ARE cp1252-representable. A gate that fires on an em dash gets
    switched off within a day, and this repo's prose uses both."""
    text = "an em dash " + chr(0x2014) + " and a pound " + chr(0x00A3)
    assert _printed_unencodable(f'print("{text}")') == []


def test_a_logger_is_matched_by_name_and_a_lookalike_is_not() -> None:
    """The logger heuristic proved in both directions, so its precision is evidence not assertion."""
    glyph = chr(0x2705)
    for good in ("log", "logger", "logging", "self._log", "self.logger"):
        assert _printed_unencodable(f'{good}.info("{glyph}")') == [(1, glyph)], good
    for other in ("self.catalog", "backlog", "dialog"):
        assert _printed_unencodable(f'{other}.info("{glyph}")') == [], other


def test_the_engine_gate_would_have_caught_the_alert_that_prompted_it() -> None:
    """The known-answer case, kept as a literal because the shipped line has since been fixed.

    Driven end to end on 2026-08-27 against the real LoggingAlertSink and a real cp1252 stream:
    an ASCII sibling method wrote 54 bytes, this format string wrote 105 bytes on a UTF-8 stream,
    and wrote ZERO on cp1252 while logging swallowed the UnicodeEncodeError. The alert announcing a
    backing-up lane was precisely the line that vanished.
    """
    shipped = (
        'log.warning("ALERT saturation: lane %r (%s) backlog RISING '
        + chr(0x2014)
        + " depth %d"
        + chr(0x2192)
        + '%d (+%.2f/s); ingest exceeding drain", name, stage, a, b, c)'
    )
    hits = _printed_unencodable(shipped)
    assert hits == [(1, chr(0x2192))], (
        f"expected only the arrow to be flagged, got {hits} -- the em dash in the same string is "
        f"cp1252-representable and must NOT be reported"
    )


def _tree(*lines: str) -> ast.Module:
    return ast.parse(chr(10).join(lines))


def _main(*body: str) -> tuple[str, ...]:
    """A module-level ``def main():`` with the given body lines, indented."""
    return ("def main():", *(f"    {line}" for line in body))


def test_the_engine_hardening_signal_sees_the_real_entry_points() -> None:
    """Proved against the real files rather than a reconstruction of them: the two entry points the
    reach gate exempts today must be seen to call the chokepoint."""
    for real in (_ENGINE / "__main__.py", _HARNESS / "__main__.py"):
        assert _calls_the_chokepoint(ast.parse(real.read_text(encoding="utf-8"))), real


def test_the_structural_exemption_accepts_only_a_real_imported_call() -> None:
    """BACKLOG #1875's second closing act: something a passing comment cannot satisfy.

    Every rejected case below is a way the old substring test could be satisfied, or a way a
    structural test could be fooled if it matched on the NAME alone or on the call's PRESENCE.
    """
    imp = f"from {_CHOKEPOINT_MODULE} import {_CHOKEPOINT}"
    call = f"{_CHOKEPOINT}(encoding='utf-8')"
    # Accepted: the real import and a real call first in main(), in each binding form.
    assert _calls_the_chokepoint(_tree(imp, *_main(call)))
    assert _calls_the_chokepoint(_tree(imp, *_main('"""Docstring."""', call)))
    assert _calls_the_chokepoint(
        _tree(f"from {_CHOKEPOINT_MODULE} import {_CHOKEPOINT} as harden", *_main("harden()"))
    )
    assert _calls_the_chokepoint(
        _tree(f"import {_CHOKEPOINT_MODULE}", *_main(f"{_CHOKEPOINT_MODULE}.{_CHOKEPOINT}()"))
    )
    assert _calls_the_chokepoint(
        _tree(f"import {_CHOKEPOINT_MODULE} as cs", *_main(f"cs.{_CHOKEPOINT}()"))
    )
    # Rejected: a mention in a comment, a docstring or a string, even beside the real import.
    assert not _calls_the_chokepoint(_tree(imp, *_main(f"# {call}", "pass")))
    assert not _calls_the_chokepoint(_tree(imp, *_main(f'"""Calls {call} on sys.stdout."""')))
    assert not _calls_the_chokepoint(_tree(imp, *_main(f'NOTE = "{call}"')))
    # Rejected: imported and never called.
    assert not _calls_the_chokepoint(_tree(imp, *_main("pass")))
    # Rejected: called, but not where it protects main()'s output -- after the first print, inside
    # a branch, in another function (a test exercising the helper), or at module level.
    assert not _calls_the_chokepoint(_tree(imp, *_main("print('x')", call)))
    assert not _calls_the_chokepoint(_tree(imp, *_main("if verbose:", f"    {call}")))
    assert not _calls_the_chokepoint(_tree(imp, "def test_it():", f"    {call}"))
    assert not _calls_the_chokepoint(_tree(imp, call))
    # Rejected: a local function that merely shares the name, with no import behind it.
    assert not _calls_the_chokepoint(_tree(f"def {_CHOKEPOINT}():", "    pass", *_main(call)))
    # Rejected: the right name imported from the wrong module.
    assert not _calls_the_chokepoint(_tree(f"from harness.util import {_CHOKEPOINT}", *_main(call)))
    # Rejected under the reach roots: the direct form, which only the scripts half accepts.
    assert not _calls_the_chokepoint(
        _tree("import sys", *_main("sys.stdout.reconfigure(errors='replace')"))
    )
    # The old textual signals, all of which used to exempt a file.
    assert not _calls_the_chokepoint(_tree("# we should probably reconfigure stdout one day"))
    assert not _calls_the_chokepoint(_tree("x = 'sys.stdout.reconfigure('  # stdout"))


def test_the_scripts_direct_form_must_set_a_codec_or_an_error_handler() -> None:
    """A reconfigure that sets neither keyword changes nothing about what the stream can encode."""
    assert _script_hardens("sys.stdout.reconfigure(errors='replace')")
    assert _script_hardens("sys.stdout.reconfigure(encoding='utf-8')")
    assert not _script_hardens("sys.stdout.reconfigure(line_buffering=True)")
    assert not _script_hardens("sys.stdout.reconfigure()")


# =================================================================================================
# THE TWO ROOTS THE THREE WALKS ABOVE LEFT UNWATCHED: harness/ and tests/ (BACKLOG #1030).
#
# THE ITEM'S COMPLAINT IS THAT THIS CLASS KEEPS RECURRING, and these were the two largest roots
# the three walks above never looked at. Measured 2026-09-21 at af3512fa7: 75 Python files under
# harness/ and 853 under tests/, 928 together, against 275 under messagefoundry/. They are not a
# tail case; they are most of the tree. Six smaller roots are still out, named at the foot of this
# block -- this paragraph is about size, not about completeness.
#
# THE SAME PREDICATE AS THE ENGINE HALF, AND THE FIGURES ARE THE WHOLE ARGUMENT. Both figures below
# are AT af3512fa7, this change's base, because that ref is where the choice was made. Gating these
# two roots on ENCODABILITY -- the predicate the scripts halves use -- fires 611 times there (137
# under harness/, 474 under tests/, distinct characters summed per file), which is the shape that
# gets a gate switched off within a week. Gating on REACH fires on THREE files of the 928, and one
# of the three is already exempt: harness/__main__.py reconfigures both streams in main(), so it
# passes on the property rather than on a list. The remaining two are fixed in this same change,
# which is why re-deriving the encodability figure on main AFTER this lands returns 610, not 611.
# The pair is quoted rather than the ratio because a reader has to be able to reproduce both ends.
#
# THE TWO DEFECTS ARE DIFFERENT AND ONLY ONE OF THEM ABORTS, which is worth stating because the
# quieter one is the one that ships. harness/reconcile/__main__.py prints its startup banner to
# sys.stderr, and stderr carries backslashreplace and never raises -- so on a stock cp1252 console
# the arrow is CORRUPTED rather than lost, and the operator reading that line to confirm the
# capture sink is up reads mojibake in the middle of a path. tests/test_benchmark_parser.py prints
# inside `capsys.disabled()`, which is the real stdout: that one RAISES UnicodeEncodeError and
# takes the test down.
#
# THAT SECOND FILE ALSO CARRIES A CHARACTER THIS GATE CANNOT SEE, AND IT IS FIXED BY HAND HERE. Its
# `skipif` reason is printed to real stdout by `pytest -rs`, and on a GIL build the reason is the
# ONLY thing that path prints -- the fixed print never executes, because the test is skipped. A
# `reason=` keyword is not print, not a std-stream write and not a logger, so `_writes_to_a_console`
# rejects it by construction. Widening the predicate to framework keywords that print
# (`skipif(reason=)`, `add_parser(help=)`, `ArgumentParser(description=)`) is a separate pass with
# its own trade-off; the character is removed here so this file does not keep a live console path
# the block above claims is closed.
#
# WHY A TEST TREE IS WORTH GATING WHEN NOTHING IN IT SHIPS. A test prints to the developer console
# this whole item is named for, and an abort there is indistinguishable from a real failure of the
# thing under test -- so it sends the reader after the wrong defect.
#
# ADDING tests/ PUTS THIS FILE INSIDE THE SCAN. When that landed (PR 1403) the walk could never FAIL
# on it, because this module satisfied the old TEXTUAL exemption by accident: its own assertion
# literals contained `sys.stdout.reconfigure(` and the word stdout. A glyph planted in a print() here
# was filed as exempt by the very gate it belongs to. BACKLOG #1875 made the exemption structural, so
# this module is now walked like any other file; `test_this_module_is_not_exempt_from_its_own_gate`
# below pins that, because this is the file in the repository that talks about hardening most.
#
# WHAT IS STILL OUT, AND THIS IS A FLOOR RATHER THAN A CENSUS. At least six roots hold Python this
# gate does not reach. Measured 2026-09-21, about 101 files: messagefoundry_webconsole/ (35 files),
# packaging/ (26), samples/ (18), tee/ (18), docker/ (2) and docs/ (2). All six measure ZERO
# console-bound hits today, which is a reason to leave them for a separate pass and NOT evidence
# that they are safe: a root with nothing to find is exactly the root that acquires the first one
# unwatched. Two deserve naming. packaging/ IS the second pytest collection root -- pyproject's
# `testpaths` names `packaging/messagefoundry-webconsole/tests` -- so the paragraph above about
# test trees applies to it in full, and it is out by scope rather than by argument. tee/ vendors
# messagefoundry/anon/ behind a CLI that prints to an operator console.
# =================================================================================================

_HARNESS = _ROOT / "harness"
_TESTS = _ROOT / "tests"

#: ``(label, root, floor, file pinned by name)``. The two halves catch opposite breakages, and the
#: FLOOR alone is not enough for either root here. A ``<root>/**/*.py`` git pathspec DROPS every
#: top-level file -- measured on the engine half above -- so each row pins the top-level file whose
#: loss would matter most: harness/__main__.py is the entry point whose hardening exempts it, and
#: this module is the one file whose disappearance from the walk would make every result below
#: meaningless.
#:
#: THE FLOOR CANNOT SEE THE OPPOSITE REGRESSION UNDER tests/, WHICH IS WHY IT IS NOT THE WHOLE
#: CONTROL. A walk that degraded from rglob to glob loses 61 of harness/'s 75 files and trips the
#: floor of 60; under tests/ it loses ONE of 853 and sails past any floor, and the pinned file is
#: itself top-level so that half clears too. Both halves would be blind on that row. The nested
#: assertion in the coverage test below is what discriminates there, and it can produce a different
#: answer: it goes red on exactly the degradation the floor cannot see.
_REACH_ROOTS: tuple[tuple[str, Path, int, str], ...] = (
    ("harness", _HARNESS, 60, "__main__.py"),
    ("tests", _TESTS, 700, "test_cp1252_console_safety.py"),
)

_REACH_ROOT_IDS = [label for label, _root, _floor, _pinned in _REACH_ROOTS]

#: ``(label, root)`` only, for the tests that use neither the floor nor the pin. Carrying all four
#: fields into them would read as though the floor and the pin participate in the gate itself.
_REACH_ROOT_PATHS = tuple((label, root) for label, root, _floor, _pinned in _REACH_ROOTS)


@pytest.mark.parametrize(("label", "root", "floor", "pinned"), _REACH_ROOTS, ids=_REACH_ROOT_IDS)
def test_the_harness_and_test_scans_actually_cover_something(
    label: str, root: Path, floor: int, pinned: str
) -> None:
    """PRINT AND PIN WHAT WAS SCANNED, the same positive control the three walks above carry.

    A scan whose file list collapses to nothing reports a clean result forever, and this repository
    has produced a false zero on exactly this census before.
    """
    found = _modules_under(root)
    nested = [p for p in found if len(p.relative_to(root).parts) > 1]
    print(f"scanned {len(found)} python files under {label}/, {len(nested)} of them nested")
    assert len(found) >= floor, (
        f"only {len(found)} files under {label}/ -- the walk is not finding them"
    )
    assert (root / pinned) in found, f"the walk under {label}/ lost its top-level {pinned}"
    # The floor is blind to this under tests/, where 852 of 853 files sit at the top level. If the
    # last nested file under a root is ever legitimately removed, this fails LOUDLY and points at
    # the control rather than reporting a clean tree it never walked.
    assert nested, (
        f"the walk under {label}/ found no file below the top level -- it has stopped recursing"
    )


@pytest.mark.parametrize(("label", "root"), _REACH_ROOT_PATHS, ids=_REACH_ROOT_IDS)
def test_no_harness_or_test_module_puts_an_unencodable_character_on_a_console(
    label: str, root: Path
) -> None:
    """The gate: a console-bound literal stays cp1252-safe unless its own file hardens stdout."""
    scan = _scan_root(root)
    print(
        f"{label}/: console-bound and hardened, therefore allowed: {list(scan.exempted) or 'none'}"
    )
    assert not scan.offenders, "\n  ".join(
        [f"modules under {label}/ that can lose or abort console output:", *scan.offenders]
    )


@pytest.mark.parametrize(("label", "root"), _REACH_ROOT_PATHS, ids=_REACH_ROOT_IDS)
def test_every_harness_and_test_module_decodes_as_utf8_and_parses(label: str, root: Path) -> None:
    """Never a silent skip. A file that will not parse makes ``_printed_unencodable`` return an
    empty list that is indistinguishable from a clean one, which is the false zero in miniature."""
    broken = _scan_root(root).unreadable
    assert not broken, f"modules under {label}/ the scan could not read:\n  " + "\n  ".join(broken)


def test_this_module_is_not_exempt_from_its_own_gate() -> None:
    """THE GATE MUST NOT EXEMPT ITSELF. Under the old textual exemption it did, on its own assertion
    literals (BACKLOG #1875). This file names the remedy dozens of times, in comments, docstrings and
    strings, and never performs it -- so it is the sharpest real-file control that a MENTION no
    longer exempts. Its non-cp1252 characters are built with chr(), which keeps it printable on the
    console it defends.

    Mutation: add a print with a literal U+2192 to this file. The walk above now goes red on it.
    """
    text = Path(__file__).resolve().read_text(encoding="utf-8")
    assert _CHOKEPOINT in text and "stdout.reconfigure(" in text, "the control lost its mentions"
    assert not _calls_the_chokepoint(ast.parse(text))
    assert not _script_hardens(text)
    assert _printed_unencodable(text) == []
    # The runtime control module goes further and really CALLS the helper, in its tests. Those
    # calls harden a fake stream, not the one its own prints meet, so it must not be exempt either.
    runtime = (_TESTS / "test_console_streams.py").read_text(encoding="utf-8")
    assert f"{_CHOKEPOINT}(" in runtime
    assert not _calls_the_chokepoint(ast.parse(runtime))


# --- the two-direction control, kept because an ASCII-only degradation reads as a clean tree ------

#: The two characters this extension ACTUALLY found, in the two files it found them in. Not a
#: hypothetical pair: U+2192 is the corrupted arrow in harness/reconcile/__main__.py and U+2265 is
#: the aborting one in tests/test_benchmark_parser.py. Built with chr() so this module stays
#: printable on the console it defends, and so it names a character without adopting one.
#:
#: U+2192 and U+2014 are also asserted individually by the engine half's own controls above. The
#: overlap is deliberate -- a two-direction control read as one block is what makes an ASCII-only
#: degradation obvious -- but if you change the detector, change BOTH sites: two controls that
#: disagree about the same character is worse than either alone.
_FOUND_BY_THIS_EXTENSION = (0x2192, 0x2265)

#: cp1252 encodes BOTH of these (0x97 and 0xE9). They are the other half of the control: a detector
#: that degraded from "cp1252 cannot represent it" into "it is not ASCII" stays green on the pair
#: above and starts firing on ordinary prose, and a gate that fires on an em dash or on an accented
#: name is switched off within a day. Without this direction, a broken scan and a clean scan look
#: identical.
_REPRESENTABLE_LOOKALIKES = (0x2014, 0x00E9)


@pytest.mark.parametrize("code_point", _FOUND_BY_THIS_EXTENSION, ids=lambda c: f"U+{c:04X}")
def test_the_reach_detector_flags_both_characters_this_extension_found(code_point: int) -> None:
    ch = chr(code_point)
    assert _printed_unencodable(f'print("a {ch} b")') == [(1, ch)], f"U+{code_point:04X}"


@pytest.mark.parametrize("code_point", _REPRESENTABLE_LOOKALIKES, ids=lambda c: f"U+{c:04X}")
def test_the_reach_detector_stays_silent_on_what_cp1252_can_represent(code_point: int) -> None:
    ch = chr(code_point)
    assert _printed_unencodable(f'print("a {ch} b")') == [], f"U+{code_point:04X}"


def test_the_extension_would_have_caught_both_sites_it_was_built_for() -> None:
    """The known-answer cases, kept as reconstructions because both shipped lines are fixed in this
    same change. Without them the gate's green says only that the tree is clean today, not that the
    detector can still see the shape that made it necessary.

    BOTH ARE REBUILT AS MULTI-LINE IMPLICIT f-STRING CONCATENATIONS, because that is what both real
    sites are and a single-line reconstruction would not exercise the shape it names. Neither
    reports line 1, so an AST walk that collapsed a JoinedStr onto its enclosing call would fail
    here.

    THE TWO REPORTED LINES DIFFER, AND THE REASON IS WORTH KNOWING BEFORE YOU READ A FAILURE. The
    detector reports the line a merged CONSTANT RUN begins on, which is not always the line the
    character sits on. Adjacent literal text flows across the fragment boundary: the banner's first
    fragment ends in a trailing space, that space and the arrow become one constant, and the run --
    so the reported line -- starts on the EARLIER fragment. A placeholder breaks the run, so the
    measure's ``{ratio:.2f}`` puts the following text in a fresh constant and the report lands on
    the character's own line. Both behaviours are reproduced below; measured 2026-09-21, and both
    match what the real pre-fix files returned.
    """
    nl = chr(10)
    banner = nl.join(
        [
            "print(",
            '    f"capture sink listening on {args.host}:{ports} "',
            '    f"' + chr(0x2192) + ' {args.out} (Ctrl-C to stop)",',
            "    file=sys.stderr,",
            ")",
        ]
    )
    # Line 2, not 3: the trailing space on line 2 and the arrow on line 3 are one constant.
    assert _printed_unencodable(banner) == [(2, chr(0x2192))]

    measure = nl.join(
        [
            "print(",
            '    f"[PARSE-15 AC-6 measure] workers={workers} "',
            '    f"single={single_rate:,.0f} msg/s multi={multi_rate:,.0f} msg/s "',
            '    f"scaling={ratio:.2f}x (gate ' + chr(0x2265) + '6x is operator-owned)"',
            ")",
        ]
    )
    # Line 4: the `{ratio:.2f}` placeholder starts a fresh constant on the character's own line.
    assert _printed_unencodable(measure) == [(4, chr(0x2265))]


# =================================================================================================
# THE RUNTIME HALF: EVERY CONSOLE ENTRY POINT HARDENS AT ONE CHOKEPOINT (BACKLOG #1875).
#
# Every walk above reads SOURCE. A runtime value is not source: an operator who passes
# `harness.reconcile capture --out` a path holding a character cp1252 cannot encode got that path
# echoed as backslash escapes on stderr, and no scan of any file can see the path. The only control
# that covers a value nobody wrote down is a hardened stream, so the decision this section records is
# WHERE that hardening lives: at one chokepoint, `messagefoundry.console_streams`, called from the top
# of every `__main__.py` under the two roots that ship console entry points. Placed file by file, it
# decayed; `harness/reconcile/__main__.py` was the one that never got it.
#
# The rule is keyed on `__main__.py` -- what `python -m <package>` runs -- and that is a FLOOR. A
# module with its own `if __name__ == "__main__":` block is out of scope here: at least
# `harness/load/ingress_probe.py`, `messagefoundry/generators/adt.py` and
# `messagefoundry/pipeline/_sandbox_worker.py` have one, and the last speaks a protocol over its
# pipes, where re-encoding the stream would change a wire format rather than harden a console.
# `tee/__main__.py` is outside both roots, like the rest of tee/.
#
# The runtime CONTROL, which drives the reconcile CLI with a non-cp1252 path under a cp1252 stream
# and asserts the bytes come back intact, is `tests/test_console_streams.py`.
# =================================================================================================

#: Entry points with no console, so the chokepoint has nothing to harden. Kept as an explicit list
#: because "is there a console" is a fact about how the file is LAUNCHED, which the file cannot
#: carry. `test_an_entry_point_without_a_console_is_still_a_gui_script` re-derives it from
#: pyproject.toml on every run. The tray is a `[project.gui-scripts]` entry, launched by
#: `pythonw`, where sys.stdout is None; it logs to a UTF-8 file, and ADR 0113 limits what it may
#: import.
_ENTRY_POINTS_WITHOUT_A_CONSOLE = frozenset({"messagefoundry/tray/__main__.py"})


def test_every_console_entry_point_hardens_at_the_chokepoint() -> None:
    found = {
        p.relative_to(_ROOT).as_posix(): p
        for root in (_ENGINE, _HARNESS)
        for p in _modules_under(root)
        if p.name == "__main__.py"
    }
    print(f"entry points scanned: {sorted(found)}")
    # PRINT AND PIN, as every walk in this module does: the file this item is named for, and a count
    # a degraded walk would fall under.
    assert "harness/reconcile/__main__.py" in found
    assert len(found) >= 5, f"only {len(found)} entry points found -- the walk is not finding them"
    unhardened = sorted(
        rel
        for rel, path in found.items()
        if rel not in _ENTRY_POINTS_WITHOUT_A_CONSOLE
        and not _calls_the_chokepoint(ast.parse(path.read_text(encoding="utf-8")))
    )
    assert not unhardened, (
        f"console entry points that do not call {_CHOKEPOINT_MODULE}.{_CHOKEPOINT}: {unhardened}. "
        f"A runtime value -- a path, a label, a message field -- reaches their output, and no "
        f"source scan can see it. Call the helper at the top of main()."
    )


def test_an_entry_point_without_a_console_is_still_a_gui_script() -> None:
    """RE-DERIVE THE EXCEPTION LIST, never trust the constant. If the tray ever becomes a console
    script, or moves, this fails and the entry should leave the list."""
    project = tomllib.loads((_ROOT / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    gui = {target.split(":", 1)[0] for target in project.get("gui-scripts", {}).values()}
    console = {target.split(":", 1)[0] for target in project.get("scripts", {}).values()}
    for rel in _ENTRY_POINTS_WITHOUT_A_CONSOLE:
        assert (_ROOT / rel).is_file(), f"{rel} is listed but does not exist"
        module = rel.removesuffix(".py").replace("/", ".")
        assert module in gui, f"{rel} is excused as console-less but is not a gui-script"
        assert module not in console, f"{rel} is excused as console-less but is a console script"
