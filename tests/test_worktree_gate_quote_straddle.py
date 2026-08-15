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


def test_an_unterminated_quote_fails_closed(primary: Path, repos_file: Path) -> None:
    """An unpaired quote must leave the rest of the line VISIBLE, not swallow it.

    The old regexes required a closing quote, so an unpaired one never matched and the text stayed
    visible -- which fails CLOSED. A left-to-right scanner that consumed everything after a lone quote
    would fail OPEN, turning one stray character into a total bypass. That is a REGRESSION THE FIX
    COULD EASILY HAVE INTRODUCED, which is why it is pinned rather than assumed.
    """
    command = f"echo {SQ}oops ; git -C {primary} checkout main"
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))
