# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A stray quote must not let a gated git command hide between two quoted words (BACKLOG #1229).

The gate blanks quoted spans before scanning, so a commit message cannot supply a verb. It used to do
that with two sequential regexes, DOUBLE QUOTES FIRST::

    $s = $s -replace '"[^"]*"', '""'
    $s = $s -replace "'[^']*'", "''"

Inside a SINGLE-quoted shell word a ``"`` is an ordinary literal, so a command like
``echo 'say "hi' ; <gated git command> ; echo 'bye" now'`` hands the shell two harmless arguments and
leaves the middle LIVE. The double-quote pass then pairs those two literal quotes ACROSS the live
command and deletes it, so no rule ever sees it and the gate ALLOWS.

THE ASYMMETRY IS THE PROOF AND IT IS WHY THIS WAS INVISIBLE FROM ONE SIDE. The mirrored shape -- a
stray apostrophe inside double-quoted words -- still DENIES, because the double-quote pass runs first
and consumes those spans before the single-quote pass can straddle. So the cause is the blanking
ORDER, not any command classifier, and a fix aimed at the classifiers would not have touched it.

Measured against the shipped hook before the fix: the marker survived blanking in the control and in
the mirrored shape, and was DELETED in the straddle shape. Both directions are asserted here, because
a test that only checked the broken shape would pass against a fix that simply blanked everything.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

# Built by concatenation rather than written inline. A test about quote handling must not itself
# depend on how this file's own string literals nest -- the first draft of this suite did, and the
# apostrophes it meant to embed arrived doubled, which silently changed the shape under test.
SQ = "'"
DQ = '"'


# Defined locally, matching the sibling command-parsing suite: these fixtures are not shared through a
# conftest, so importing the harness does not bring them along.
@pytest.fixture
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


def shell(command: str, cwd: Path) -> dict[str, object]:
    """A Bash tool payload, matching the sibling suites' harness."""
    return {
        "tool_name": "Bash",
        "tool_input": {"command": command},
        "cwd": str(cwd),
    }


# ONLY THE FIRST CASE DISCRIMINATES, and saying so is the point of this comment.
#
# Measured by restoring the original two-regex blanking: that plant reds the FIRST case and leaves the
# other two green. It takes a PAIR of stray double quotes to straddle -- one on each side of the gated
# command -- because the regex needs an opener and a closer to span across. A single stray quote has
# nothing to pair with and was never part of the defect.
#
# The two single-sided cases are kept deliberately, as BOUNDARY pins rather than as evidence: they
# record that one stray quote is harmless, so a future fix that over-blanks (deleting from a lone
# quote onwards) is caught here rather than in production. Left unlabelled they would read as three
# independent proofs of a fix that only one of them can see fail.
@pytest.mark.parametrize(
    "prefix,suffix",
    [
        # THE STRADDLE -- the defect. Two LITERAL double quotes, one inside each single-quoted word.
        (f"echo {SQ}say {DQ}hi{SQ} ; ", f" ; echo {SQ}bye{DQ} now{SQ}"),
        # Boundary: a single stray quote on the leading side only. Green before and after the fix.
        (f"echo {SQ}a{DQ}b{SQ} ; ", ""),
        # Boundary: ...and on the trailing side, so neither position is special-cased.
        ("", f" ; echo {SQ}c{DQ}d{SQ}"),
    ],
)
def test_a_straddling_quote_does_not_hide_a_gated_command(
    primary: Path, repos_file: Path, prefix: str, suffix: str
) -> None:
    """The gated command sits BETWEEN two literal quotes and must still be seen."""
    command = f"{prefix}git -C {primary} checkout main{suffix}"
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))


def test_the_mirrored_shape_still_denies(primary: Path, repos_file: Path) -> None:
    """The control that proves the fix did not simply invert the bug.

    This shape ALREADY denied before the fix, because the double-quote pass ran first. If a future
    change makes the single-quote pass run first instead, this is the test that catches it -- the
    defect would move rather than close, and the straddle test above would still be green.
    """
    command = f"echo {DQ}say {SQ}hi{DQ} ; git -C {primary} checkout main ; echo {DQ}bye{SQ} now{DQ}"
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))


def test_an_ordinary_quoted_commit_message_still_does_not_supply_a_verb(
    primary: Path, repos_file: Path
) -> None:
    """The reason blanking exists at all, kept green.

    `git commit -m "chore: clean up dead code"` was denied on `clean` before quoted spans were
    blanked. A scanner that stopped blanking -- the crudest way to pass the tests above -- would
    resurrect that false positive, so this is the other half of the boundary.
    """
    # run_gate returns the deny object, or None for ALLOW -- read from the harness rather than assumed.
    result = run_gate(
        shell(f"git commit -m {DQ}chore: clean up dead code{DQ}", cwd=primary), repos_file
    )
    assert result is None, (
        "a quoted commit message supplied a verb again -- quoted spans are no longer being blanked, "
        f"which is the false positive blanking exists to prevent. Deny object:\n{result}"
    )


@pytest.mark.parametrize(
    "tool,program,quote",
    [
        ("Bash", "echo", SQ),
        ("Bash", "echo", DQ),
        ("PowerShell", "Write-Output", SQ),
        # THE FOURTH CORNER, MISSING WHILE THE RECORD CLAIMED THERE WERE THREE. Both tools times both
        # quote characters is four. Measured ALLOW on origin/main and on this build, and it RUNS
        # (`111*3` -> 333). Its absence is the whole reason "fail-opens remaining: 3" got written down.
        ("PowerShell", "Write-Output", DQ),
    ],
)
def test_a_quoted_span_CROSSING_A_NEWLINE_is_a_known_open_straddle(
    primary: Path, repos_file: Path, tool: str, program: str, quote: str
) -> None:
    """A TRIPWIRE OVER BACKLOG #1429. It asserts ALLOW and that is NOT an endorsement.

    ``Get-ScannableSegments`` splits the command on newlines before any quoting is considered, so a
    quoted span that crosses a newline is not one span to the gate -- it is an unterminated quote on
    one line and a stray quote on the next. The middle line then carries ONE QUOTE FROM EACH
    surrounding span, those two pair ACROSS the gated command, and it is blanked. Same straddle this
    file exists for, reached through the line split instead of the pass order.

    Measured on the shipped gate, cwd inside the governed repo, with the middle statement pinned to
    whether it RUNS (``expr 111 \\* 3`` under bash and ``111*3`` under pwsh both print 333)::

        echo 'a<NL>b' ; git -C <governed> checkout main ; echo 'c<NL>d'    333    ALLOW
        echo "a<NL>b" ; git -C <governed> checkout main ; echo "c<NL>d"    333    ALLOW
        Write-Output 'a<NL>b' ; git -C <governed> ... ; Write-Output ...   333    ALLOW
        Write-Output "a<NL>b" ; git -C <governed> ... ; Write-Output ...   333    ALLOW

    ALL FOUR CORNERS ARE HERE, and the fourth is why this comment says so. The record carried three
    for a while -- both Bash rows and only the single-quoted PowerShell one -- and the missing
    double-quoted PowerShell row made "fail-opens remaining: 3" read as an enumeration when it was a
    floor. Re-measured 2026-09-03 against gate copies hash-verified byte-identical to origin/main and
    to this build: all four ALLOW on both, all four print 333. Treat the count as AT LEAST four.

    THE GATE'S OWN RESIDUAL LIST SAID THESE DENIED, and that claim is corrected in place there. It is
    pinned here rather than left in prose because a residual that lives only in a comment is one
    nobody notices closing -- and because the false claim is exactly what stopped anyone probing it.

    NOT FIXED IN THE CHANGE THAT ADDED THIS ROW: closing it means carrying quote state across the
    split, which changes what every rule sees on every multi-line command. That is a wider blast
    radius than the span-ownership fixes this file covers, so it is filed rather than half-done.

    WHEN THIS TEST REDS, that is the success signal: somebody closed BACKLOG #1429. Delete the row and
    invert #1429's banner; do not restore the ALLOW.
    """
    gated = (
        f"git -C {primary} checkout main" if tool == "Bash" else f"git -C {primary} reset --hard"
    )
    command = f"{program} {quote}a\nb{quote} ; {gated} ; {program} {quote}c\nd{quote}"
    assert (
        run_gate(
            {"tool_name": tool, "tool_input": {"command": command}, "cwd": str(primary)},
            repos_file,
        )
        is None
    ), (
        f"the multi-line {quote} span under {tool} now DENIES. That is progress -- BACKLOG #1429 is "
        "closed. Delete this row and invert the item's banner; do NOT restore the ALLOW."
    )
    # THE CONTROL, and it is what keeps the tripwire attached to the NEWLINE rather than to the whole
    # shape: the identical command with the span on one line DENIES, on the shipped gate and on this
    # one. Without it the row above would pass against a gate that had stopped seeing `git` entirely.
    one_line = f"{program} {quote}ab{quote} ; {gated} ; {program} {quote}cd{quote}"
    assert_denied(
        run_gate(
            {"tool_name": tool, "tool_input": {"command": one_line}, "cwd": str(primary)},
            repos_file,
        )
    )


def test_an_unterminated_quote_fails_closed(primary: Path, repos_file: Path) -> None:
    """An unpaired quote must leave the rest of the line VISIBLE, not swallow it.

    The old regexes required a closing quote, so an unpaired one never matched and the text stayed
    visible -- which fails CLOSED. A left-to-right scanner that consumed everything after a lone quote
    would fail OPEN, turning one stray character into a total bypass. That is a REGRESSION THE FIX
    COULD EASILY HAVE INTRODUCED, which is why it is pinned rather than assumed.
    """
    command = f"echo {SQ}oops ; git -C {primary} checkout main"
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))
