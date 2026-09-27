# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

import subprocess
from pathlib import Path

import pytest
from _bash_resolver import explain_returncode, require_bash

from tests._spawn_lock import run_single
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
        # quote characters is four. Its absence is why "fail-opens remaining: 3" got written down.
        ("PowerShell", "Write-Output", DQ),
    ],
)
def test_a_quoted_span_CROSSING_A_NEWLINE_is_a_known_open_straddle(
    primary: Path, repos_file: Path, tool: str, program: str, quote: str
) -> None:
    """THE TRIPWIRE OVER BACKLOG #1429, INVERTED: all four corners now DENY.

    The name is kept so the record that cites it still resolves; the assertion is the opposite of
    what it was. ``Get-ScannableSegments`` split the command on newlines before any quoting was
    considered, so a quoted span crossing a newline was an unterminated quote on one line and a stray
    quote on the next. The middle line carried ONE QUOTE FROM EACH surrounding span, those two paired
    ACROSS the gated command, and it was blanked. Measured on the gate before the fix, with the middle
    statement pinned to whether it RUNS (``expr 111 \\* 3`` under bash and ``111*3`` under pwsh both
    print 333)::

        echo 'a<NL>b' ; git -C <governed> checkout main ; echo 'c<NL>d'    333    was ALLOW
        echo "a<NL>b" ; git -C <governed> checkout main ; echo "c<NL>d"    333    was ALLOW
        Write-Output 'a<NL>b' ; git -C <governed> ... ; Write-Output ...   333    was ALLOW
        Write-Output "a<NL>b" ; git -C <governed> ... ; Write-Output ...   333    was ALLOW

    The fix is a SECOND VIEW over the command's logical lines, where a newline inside a quoted span
    does not end a line. **IF THIS REDS, the second view stopped reaching one of these corners. Do
    not restore the ALLOW.**
    """
    gated = (
        f"git -C {primary} checkout main" if tool == "Bash" else f"git -C {primary} reset --hard"
    )
    command = f"{program} {quote}a\nb{quote} ; {gated} ; {program} {quote}c\nd{quote}"
    assert_denied(
        run_gate(
            {"tool_name": tool, "tool_input": {"command": command}, "cwd": str(primary)},
            repos_file,
        )
    )
    # THE CONTROL: the identical command with the span on one line. It denied before the fix and
    # must still deny, so the row above stays attached to the NEWLINE rather than to the shape.
    one_line = f"{program} {quote}ab{quote} ; {gated} ; {program} {quote}cd{quote}"
    assert_denied(
        run_gate(
            {"tool_name": tool, "tool_input": {"command": one_line}, "cwd": str(primary)},
            repos_file,
        )
    )


#: The same straddle AFTER a construct whose quote the shell reads as data, or INSIDE code the
#: per-line view cannot see whole. Every row ALLOWED on the gate before #1429. The ``after_a_*`` rows
#: also ALLOW under a cross-line view that does not model the construct: the stray quote pairs with
#: the first span's opener, the pairing shifts by one, and the straddle comes back. So they make the
#: comment, block-comment, heredoc and here-string modelling load-bearing, each measured with that
#: one branch disabled. ``{G}`` is the gated command; every middle statement RUNS.
AFTER_A_CONSTRUCT = {
    "after_a_comment_bash": ("Bash", "# don't\necho 'a\nb' ; {G} ; echo 'c\nd'"),
    "after_a_comment_pwsh": (
        "PowerShell",
        "# don't\nWrite-Output 'a\nb' ; {G} ; Write-Output 'c\nd'",
    ),
    "after_a_heredoc_body": (
        "Bash",
        "cat <<'EOF' > n.txt\ndon't\nEOF\necho 'a\nb' ; {G} ; echo 'c\nd'",
    ),
    "after_a_here_string": (
        "PowerShell",
        "$m = @'\ndon't\n'@\nWrite-Output 'a\nb' ; {G} ; Write-Output 'c\nd'",
    ),
    "after_a_block_comment_pwsh": (
        "PowerShell",
        "<# don't\n#>\nWrite-Output 'a\nb' ; {G} ; Write-Output 'c\nd'",
    ),
    # The body of a heredoc fed to bash is CODE, so the straddle inside it runs too. This row does
    # NOT discriminate the heredoc modelling -- a plain quote carry reads the body the same way. It
    # pins that the body of an INTERPRETER's heredoc stays in the second view.
    "inside_a_heredoc_fed_to_bash": ("Bash", "bash <<'EOF'\necho 'a\nb' ; {G} ; echo 'c\nd'\nEOF"),
    # A substitution inside a double-quoted word, or an ANSI-C word, earlier on the SAME logical
    # line. An earlier draft could not model these and fell back to the per-line reading for the
    # whole line, so one harmless token anywhere on it restored the straddle.
    "after_a_substitution_in_a_double_quoted_word_bash": (
        "Bash",
        "echo \"$(true)\" ; echo 'a\nb' ; {G} ; echo 'c\nd'",
    ),
    "after_a_backtick_substitution_bash": (
        "Bash",
        "echo \"`true`\" ; echo 'a\nb' ; {G} ; echo 'c\nd'",
    ),
    "after_an_ansi_c_word_bash": ("Bash", "echo $'it\\'s' ; echo 'a\nb' ; {G} ; echo 'c\nd'"),
    "after_a_subexpression_pwsh": (
        "PowerShell",
        "Write-Output \"$(1)\" ; Write-Output 'a\nb' ; {G} ; Write-Output 'c\nd'",
    ),
    # A multi-line bash -c payload whose comment holds a stray quote. Only the payload's OWN
    # logical-line split, under the interpreter's convention, sees past the comment.
    "inside_a_multi_line_payload_after_a_comment": (
        "Bash",
        'bash -c \'# don"t\necho "a\nb" ; {G} ; echo "c\nd"\'',
    ),
}


@pytest.mark.parametrize("shape", sorted(AFTER_A_CONSTRUCT))
def test_the_straddle_is_seen_after_a_construct_that_holds_a_stray_quote(
    primary: Path, repos_file: Path, shape: str
) -> None:
    """BACKLOG #1429's must-trip half, past the shapes a naive quote carry would get wrong."""
    tool, template = AFTER_A_CONSTRUCT[shape]
    verb = "checkout main" if tool == "Bash" else "reset --hard"
    command = template.replace("{G}", f"git -C {primary} {verb}")
    assert_denied(
        run_gate(
            {"tool_name": tool, "tool_input": {"command": command}, "cwd": str(primary)},
            repos_file,
        )
    )


def test_the_straddles_after_a_construct_really_run_their_middle_statement(tmp_path: Path) -> None:
    """Each AFTER_A_CONSTRUCT row's gated slot is live code (SDS-3.8). No git command is run."""
    bash = require_bash(tmp_path)
    for shape, (tool, template) in sorted(AFTER_A_CONSTRUCT.items()):
        if tool == "Bash":
            proc = subprocess.run(
                [bash, "-c", template.replace("{G}", "expr 111 " + chr(92) + "* 3")],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=tmp_path,
            )
            why = explain_returncode(proc.returncode, shape)
        else:
            proc = run_single(
                [
                    "pwsh",
                    "-NoProfile",
                    "-NonInteractive",
                    "-Command",
                    template.replace("{G}", "111*3"),
                ],
                capture_output=True,
                text=True,
                timeout=120,
                cwd=tmp_path,
            )
            why = f"pwsh exited {proc.returncode}"
        assert "333" in proc.stdout, (
            f"{shape}: the middle statement did not run, so its DENY is over shell data. {why} "
            f"stdout={proc.stdout!r} stderr={proc.stderr!r}"
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
