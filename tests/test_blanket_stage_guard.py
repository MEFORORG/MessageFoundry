# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
r"""Tests for the blanket-git-stage PreToolUse guard (scripts/hooks/block-blanket-git-stage.ps1).

The guard stops one session sweeping another session's files into its commit: it denies
`git add -A/--all/-u/.`, `git commit -a/-am/--all` and `git commit` with a whole-tree pathspec,
and passes everything else silently.

THE CASE THESE TESTS EXIST FOR. The guard used to match the program name with `-cnotmatch`, so it
compared a SPELLING while Windows resolves an EXECUTABLE. `git`, `Git` and `GIT` all run the same
git.exe -- measured, all three print the same `git --version` under PowerShell and under Git Bash
-- so `Git add -A` staged the whole tree while `git add -A` was denied, and the only difference was
the capital letter. The program name is now matched case-insensitively.

ONLY THE PROGRAM NAME. The subcommand and flag tests stay case-SENSITIVE, and the allow-side cases
below pin that. Measured against real git: `git ADD .` returns "git: 'ADD' is not a git command",
`git add -a` returns "error: unknown switch `a'", and `git commit --ALL` returns "error: unknown
option `ALL'". Folding case there would deny commands git itself refuses to run.

THE OVER-DENY CLASS THIS FILE USED TO PIN IS NOW FIXED (BACKLOG #1341). The guard split on
`(\|\||&&|[;|&\n])`, which carried no quote or line state, so quoted text after a newline, `;`, `|`
or `&` landed at the front of a segment and was read there as a program name -- a heredoc writing a
doc, a commit message body, a `gh pr create --body`, a markdown table cell. Two non-prose commands
went the same way, `git log --all --grep commit` and `git grep -n add -- .`, because the subcommand
and flag tokens were matched ANYWHERE in a segment rather than at argv position. The guard now
blanks quoted spans and heredoc bodies before splitting, and resolves the subcommand past git's
global options. Those twelve payloads are still driven, under
`test_prose_and_read_only_commands_are_allowed`, with the opposite expectation.

AND THE PRICE OF THAT FIX IS PINNED HERE, NOT LEFT TO BE DISCOVERED (BACKLOG #1341). Blanking a
quoted span needs quote state, and this guard's has no escape handling and no end-of-input check,
so an apostrophe with no partner opens a span that runs to the end of the command and blanks the
real stage inside it. Eleven payloads were measured to stage a whole tree in a real shell and to be
ALLOWED by the committed guard; ten of them denied at its own parent. Eight are driven below as
`xfail(strict=True)` rows of MUST_STILL_DENY, so the fail-open is visible, is re-measured on every
run, and clears itself the moment somebody repairs the scanner.

WHY THE HISTORY IS KEPT RATHER THAN DELETED. The class was PRE-EXISTING and the case fix only
widened it from one spelling to all of them -- every case was driven in its lowercase spelling
first and already denied. That is what made the case fix landable while a known over-deny sat
beside it, and a future reader deciding whether a similar trade is acceptable needs the precedent,
not just the outcome.

THE ADD VOCABULARY IS A GENERATED FAMILY, NOT A LIST (BACKLOG #1340). Seven forms were filed; a
ground-truth pass measured at least 33 that really stage the whole tree, so patching literals would
have fixed almost nothing. The flag rule is generated from the option words per the method BACKLOG
#1097 settled, because a longer list has the same shape as the defect and decays the same way.
WHAT IS STILL NOT REACHED was measured under BACKLOG #1339 and is listed once, with what git did
for each form, in docs/BLANKET-STAGE-GUARD-FAIL-OPENS.md. That pass also closed the forms that
needed neither a quote-state parser nor a program-position test; they are driven below, each
beside a scoped control.

A MEASUREMENT THAT DID NOT ANSWER THIS QUESTION, recorded so it is not repeated. A scan of every
tracked file found 1 segment that already trips the guard and 0 that the case fix newly trips. The
arithmetic replicates and the population is wrong: the guard screens `tool_input.command`, while
every false deny above lives in text composed at call time -- a commit body, a heredoc, a PR body
-- which a scan of tracked file CONTENT cannot contain by construction. Only ten tracked segments
lead with a non-lowercase "Git" at all, so zero out of ten could never have separated "safe" from
"this corpus has almost none of the shape".

Each test drives the real hook as a subprocess with a real PreToolUse payload on stdin, so the
contract under test is the one Claude Code actually invokes.
"""

from __future__ import annotations

import functools
import json
import os
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

import pytest

# The deny ENVELOPE is one contract shared by every PreToolUse hook here, so its assertion has one
# home; tests/test_worktree_gate_git.py imports it from the same place.
from tests.test_worktree_gate import assert_denied

GUARD = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "block-blanket-git-stage.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def run_guard(payload: dict[str, Any] | str) -> dict[str, Any] | None:
    """Invoke the hook exactly as Claude Code does. Returns the deny object, or None for 'allow'."""
    raw = payload if isinstance(payload, str) else json.dumps(payload)
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(GUARD)],
        input=raw,
        capture_output=True,
        text=True,
        timeout=60,
    )
    # The guard is fail-OPEN: a non-zero exit would be a guardrail wedging git work, and an exit
    # code the harness ignores would leave the guard off with nobody the wiser.
    assert proc.returncode == 0, f"guard exited {proc.returncode}: {proc.stderr}"
    if not proc.stdout.strip():
        return None
    decision: dict[str, Any] = json.loads(proc.stdout)
    return decision


def bash(command: str, tool: str = "Bash") -> dict[str, Any]:
    # No cwd is threaded through: unlike the worktree gate, this guard never reads $j.cwd.
    return {
        "session_id": "s-1",
        "cwd": "C:/repo",
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


def assert_allowed(result: dict[str, Any] | None) -> None:
    assert result is None, f"expected ALLOW, got deny: {result}"


# ------------------------------------------------------------------ the case bypass, now closed

# Every spelling here RUNS on Windows and used to pass the guard untouched. The list is a FAMILY on
# purpose -- title case, all caps and mixed -- because a test pinning one spelling cannot see a fix
# that handles two.
CAPITALISED_DENY = [
    "Git add -A",
    "GIT add -A",
    "gIt add -A",
    "giT add .",
    "Git add --all",
    "GIT add -u",
    "Git commit -a",
    "GIT commit -am wip",
    "Git commit --all",
    "Git\tadd\t-A",
]


@pytest.mark.parametrize("command", CAPITALISED_DENY)
def test_a_capitalised_git_is_still_the_git_program(command: str) -> None:
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize("command", ["git add -A", "git commit -am wip"])
def test_the_lowercase_spelling_still_denies(command: str) -> None:
    """The floor. Widening the program match must not cost the coverage that already worked."""
    assert_denied(run_guard(bash(command)))


@pytest.mark.parametrize(
    "command",
    [
        "cd sub && Git add -A",
        "cd sub; GIT commit -am wip",
        "ls | Git add -A",
        "false || Git add --all",
    ],
)
def test_a_capitalised_git_after_a_shell_separator_denies(command: str) -> None:
    """Each shell-separated simple command is judged on its own, in every spelling."""
    assert_denied(run_guard(bash(command)))


def test_the_powershell_tool_is_guarded_too() -> None:
    assert_denied(run_guard(bash("Git add -A", tool="PowerShell")))


# ------------------------------------------------- the subcommand and the flags stay case-bound

CASE_BOUND_ALLOW = [
    "git ADD -A",
    "GIT ADD -A",
    "git COMMIT -am wip",
    "Git commit -AM wip",
    "git add --ALL",
    "git commit --ALL",
]


@pytest.mark.parametrize("command", CASE_BOUND_ALLOW)
def test_a_miscased_subcommand_or_flag_is_not_a_blanket_stage(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# --------------------------------------------------------------------------- the rest still runs

ORDINARY_ALLOW = [
    "git add README.md",
    "Git add README.md docs/X.md",
    "git commit -m 'a message'",
    "Git commit -m 'a message'",
    "git commit --amend",
    "Git commit --amend --no-edit",
    "git status",
    "gitk --all",
    "git-add -A",
    'echo "see Git add -A"',
]


@pytest.mark.parametrize("command", ORDINARY_ALLOW)
def test_ordinary_work_is_not_denied(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


def test_the_anchor_holds_so_a_word_ending_in_git_is_not_the_program() -> None:
    """`^` pins the match to the front of a split segment. Widening the CASE must not widen that."""
    assert_allowed(run_guard(bash("legit add -A")))
    assert_allowed(run_guard(bash("/usr/bin/legit add -A")))


# ------------------------------------------------------------------------------ the deny message


def test_the_flag_deny_names_the_flag_family_and_the_way_forward() -> None:
    """The message changed with BACKLOG #1340, and the change is the point.

    It used to read `-A/--all/-u/.` -- one sentence covering flags AND a pathspec. That told an
    operator who typed `:/` the problem was a flag, and it named neither `stage` nor `--update`,
    both of which now deny. The flag limb and the pathspec limb carry their own messages.
    """
    reason = assert_denied(run_guard(bash("GIT add -A")))
    assert "add/stage" in reason  # the synonym is real; the message must not hide it
    assert "--update" in reason
    assert "git add <path>" in reason  # a deny must say how to proceed, not just say no


def test_the_pathspec_deny_names_the_pathspec_not_a_flag() -> None:
    reason = assert_denied(run_guard(bash("git add :/")))
    assert "pathspec" in reason
    assert "git add <path>" in reason


def test_the_commit_deny_names_its_own_rule() -> None:
    reason = assert_denied(run_guard(bash("Git commit -am wip")))
    assert "-a/-am/--all" in reason


# ------------------------------------------------- the former over-deny class, FIXED (#1341)

# THESE SIX USED TO DENY AND NOW ALLOW. THE FLIP IS DELIBERATE (BACKLOG #1341).
#
# They were pinned as known-wrong so that whoever repaired the splitter would flip them on purpose
# instead of discovering them. This is that flip. Nothing here is a coverage reduction: each row
# asserts the SAME payload as before, with the opposite expectation, so the case is still driven
# and a regression that re-denies any of them fails this test.
#
# Two mechanisms, and the pairs separate them:
#   * rows 1-4 were segmentation. A separator inside a quoted span or a heredoc body split the
#     command, so prose landed at a segment front and was read as program position. The guard now
#     blanks quoted spans and heredoc bodies before splitting.
#   * rows 5-6 were argv position. `add` and `commit` were matched ANYWHERE in a segment, so a
#     read-only search whose ARGUMENT was the word `add` denied. The guard now resolves the
#     subcommand past git's global options and suppresses on a recognised read-only one.
#
# The capitalised/lowercase pairing is KEPT rather than collapsed. It is what shows the class was
# pre-existing and not created by the case fix, and it costs one extra driven payload per row.
FIXED_FORMER_OVER_DENY_PAIRS = [
    pytest.param(
        'git commit -m "fix\nGit add -A is blocked"',
        'git commit -m "fix\ngit add -A is blocked"',
        id="commit-message-body",
    ),
    pytest.param(
        "cat >> docs/X.md <<'EOF'\nGit add -A stages everything.\nEOF",
        "cat >> docs/X.md <<'EOF'\ngit add -A stages everything.\nEOF",
        id="heredoc-writing-a-doc",
    ),
    pytest.param(
        'echo "| Git add -A | denied |" >> docs/X.md',
        'echo "| git add -A | denied |" >> docs/X.md',
        id="single-line-split-on-pipe-inside-quotes",
    ),
    pytest.param(
        'git commit -m "wip; Git add -A was the trap"',
        'git commit -m "wip; git add -A was the trap"',
        id="single-line-split-on-semicolon-inside-quotes",
    ),
    pytest.param(
        "Git log --all --grep commit",
        "git log --all --grep commit",
        id="read-only-log-search",
    ),
    pytest.param(
        "Git grep -n add -- .",
        "git grep -n add -- .",
        id="read-only-content-search",
    ),
]


@pytest.mark.parametrize(("capitalised", "lowercase"), FIXED_FORMER_OVER_DENY_PAIRS)
def test_prose_and_read_only_commands_are_allowed(capitalised: str, lowercase: str) -> None:
    """Prose quoting a blanket-stage command, and read-only searches, must not be refused."""
    assert_allowed(run_guard(bash(capitalised)))
    assert_allowed(run_guard(bash(lowercase)))


# ------------------------------------------- the add vocabulary, closed as a family (#1340)

# EVERY ROW HERE WAS MEASURED TO REALLY STAGE THE WHOLE TREE, against real git 2.53.0.windows.2,
# in a throwaway repo, BEFORE being driven through the guard -- and every one was ALLOWED by the
# committed guard. An alleged bypass that does not actually stage anything is not a bypass, so the
# real-git step is what makes these rows evidence rather than assertion.
#
# The item named seven. The ground-truth pass measured at least 33 and stopped searching, not
# because the surface was exhausted. Patching seven literals would have fixed almost nothing --
# which is precisely why the flag rule below is GENERATED from the option words per BACKLOG #1097's
# settled method, rather than being a longer list.
NEWLY_DENIED_BLANKET_STAGES = [
    # the synonym, which alone defeated every flag row and the bare-dot row together
    "git stage -A",
    "git stage .",
    "git stage --all",
    "git stage :/",
    "git stage -Av",
    "git stage -u",
    "git stage --update",
    # the long-flag family, including git's unambiguous-abbreviation binding
    "git add --update",
    "git add --al",
    "git add --a",
    "git add --up",
    "git add --upd",
    "git add --no-ignore-removal",
    # single-dash clusters
    "git add -Av",
    "git add -vA",
    "git add -uv",
    # whole-tree pathspecs
    "git add :/",
    "git add ./",
    "git add ':(top)'",
    "git add -f :/",
    "git add --update :/",
    # the bare .exe spelling of the same executable
    "git.exe add -A",
    "git.exe commit -am wip",
]


@pytest.mark.parametrize("command", NEWLY_DENIED_BLANKET_STAGES)
def test_a_real_blanket_stage_is_denied_however_it_is_spelled(command: str) -> None:
    assert_denied(run_guard(bash(command)))


# THE NEGATIVE THAT BOUNDS THE FLAG FAMILY. Without these the next reader "simplifies" the
# case-sensitive `[Au]` cluster to `(?i)[au]` and the rule stops describing the family.
#
# `A`/`a` and `u`/`U` are FOUR DIFFERENT THINGS in this one command, and only two stage:
#   -a   is not a git add flag at all -- `git add -a` exits 129, `unknown switch 'a'`
#   -U   IS a real flag (--unified) and stages nothing
# Denying either buys zero protection and costs real work. Measured, not read off documentation.
CASE_BOUND_FLAG_ALLOW = [
    "git add -a",  # exit 129 in real git; denying it refuses what git already refuses
    "git add -na",  # same, clustered
    "git add -U 3 tracked.txt",  # --unified, a real flag that stages nothing
    "git add -p",  # patch mode, interactive and scoped
    "git add -n README.md",  # dry run on one path
    "git add -N newfile",  # intent-to-add, NOT --all despite the capital
]


@pytest.mark.parametrize("command", CASE_BOUND_FLAG_ALLOW)
def test_a_flag_that_is_not_a_blanket_stage_is_allowed(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# THE PATHSPEC LIMB'S OWN BOUND. A scoped path that merely CONTAINS a dot or a slash is ordinary
# work. The trailing boundary is the only thing separating these from the blanket forms above,
# which is why the pathspec limb cannot be fused into the flag rule.
SCOPED_PATHSPEC_ALLOW = [
    "git add ./src/x.py",
    "git add .gitignore",
    "git add src/.",
    "git add ./sub",
    "git add README.md",
]


@pytest.mark.parametrize("command", SCOPED_PATHSPEC_ALLOW)
def test_a_scoped_path_is_not_a_whole_tree_pathspec(command: str) -> None:
    assert_allowed(run_guard(bash(command)))


# ------------------------------------------------- the fix must not have bought a fail-open

# WHY THIS TEST EXISTS AND WHY IT IS NOT A FALSE-DENY CORPUS (BACKLOG #1229's reverted experiment).
#
# A program-position predicate was built for the sibling worktree_gate.ps1 and withdrawn six hours
# later. Its measurement was 93 rows of "does the shape that should allow, allow?" -- and A
# FALSE-DENY CORPUS CANNOT FIND A FAIL-OPEN BY CONSTRUCTION. It disclosed one fail-open and shipped
# at least ten more it never probed, because every row it drove asked the other question.
#
# The rows below are the other direction: shapes that MUST still be refused. On this guard a
# fail-open is the direction that loses coverage silently, so widening the allow side without this
# test is how the same mistake gets made on a second file.
#
# EIGHT OF THESE ROWS ARE `xfail(strict=True)`, AND THE MARKER IS THE FINDING (BACKLOG #1341).
# The quote-blanking pass that bought the allow side above tracks quote state with no escape
# handling and no end-of-input check, so it opens a span it never closes and blanks the real
# command that follows. The assertion on those rows is unchanged -- they still demand a DENY --
# because writing the current ALLOW down as a requirement is exactly the mistake BACKLOG #1086
# recorded: an attempt there put a live bypass in a must-ALLOW list, and anyone later restoring
# the deny would have red the suite and concluded they broke something.
#
# `strict` is what makes the marker self-clearing. Repairing `Hide-QuotedSpans` turns each row
# into an XPASS, which strict reports as a FAILURE, so the markers cannot be left behind to rot
# silently green -- the same construction `tests/test_fixture_outbox_reset.py` used for its
# pre-retirement pin.
#
# WHY THE REPAIR IS NOT IN THIS COMMIT. It is a quote-state parser change on a fail-open security
# gate, and the owner declined that shape across the sibling family (#1066/#1070/#1086/#1305/#1336)
# on 2026-08-25. The measurement is in the PR body; the short version is that the two limbs are not
# separable. Honouring backslash escapes ALONE flips `echo "C:\temp\" ; git add -A` -- an ordinary
# Windows path, measured to stage the whole tree under pwsh -- from DENY to ALLOW, because bash and
# PowerShell disagree about what a backslash is. One scanner cannot be right for both shells at
# once, which is the reason the family was declined rather than an argument for trying again.
_UNBALANCED_QUOTE = pytest.mark.xfail(
    strict=True,
    reason="BACKLOG #1341: an apostrophe with no closing quote leaves the scanner inside a span "
    "to end of input, so it blanks the stage that follows",
)
_ESCAPED_QUOTE = pytest.mark.xfail(
    strict=True,
    reason="BACKLOG #1341: an escaped quote closes a span the shell keeps open, so the scanner "
    "desynchronises and blanks the stage that follows",
)

MUST_STILL_DENY = [
    # The plain forms. If any of these ever allows, the guard is off.
    "git add -A",
    "git add --all",
    "git add -u",
    "git add .",
    "git commit -a",
    "git commit -am wip",
    "git commit --all",
    # A GLOBAL OPTION BEFORE THE SUBCOMMAND. This is the specific fail-open the subcommand
    # resolver could have introduced: if `-C` did not consume its value, the resolver would read
    # the PATH as the subcommand, fail to recognise it, and -- in a design where recognition were
    # required to keep the token -- allow. It must deny.
    "git -C /some/path add -A",
    "git -c user.name=x add -A",
    "git --git-dir=/tmp/x add -A",
    # An UNKNOWN global option must not become an escape hatch either. The resolver cannot know
    # whether it takes a value, so the subcommand resolves to something unrecognised -- which must
    # fall through to a deny, never to an allow.
    "git --some-future-option add -A",
    "git --some-future-option value add -A",
    # A read-only subcommand NAME appearing as an argument must not suppress a real stage.
    "git add -A -- log",
    "git add -A -- status",
    # Separators outside quotes still split, so a real stage after one is still caught.
    "echo hi && git add -A",
    "echo hi ; git add -A",
    "echo hi | git add -A",
    # A quoted argument elsewhere on the line must not hide a real stage outside the quotes.
    'git commit -m "message" && git add -A',
    # A heredoc that ENDS before the real command does not blank it.
    "cat <<'EOF' > f.txt\nsome body\nEOF\ngit add -A",
    # ---------------------------------------------------------- the quote-state class (#1341)
    #
    # EVERY ROW BELOW WAS MEASURED TO REALLY STAGE THE WHOLE TREE BEFORE BEING DRIVEN THROUGH THE
    # GUARD, in a throwaway repo carrying one modified tracked file and one untracked file, under
    # the real shell named in each comment. An alleged bypass that does not stage anything is not
    # a bypass, and this class needed that step more than most: the two payloads BACKLOG #1341
    # cites as its own evidence, `echo it's fine && git add -A` and `echo isn't ready ; git add
    # .`, DO flip the guard's verdict and run in NEITHER shell -- bash answers `unexpected EOF
    # while looking for matching '` and PowerShell answers ParserError. They are verdict moves,
    # not bypasses, so they are deliberately absent here.
    #
    # THE CONTROL COMES FIRST, and it is what makes the rest of the block mean anything. A comment
    # line followed by a real stage denies today. Only the apostrophe inside the comment changes
    # the verdict, so the apostrophe is the cause and the comment is not.
    "# no apostrophe here\ngit add -A",
    # UNBALANCED: a shell COMMENT carrying an apostrophe. Both shells run this and both stage.
    # This is the ordinary shape of the class -- no escaping trick, no unusual quoting, just an
    # English contraction in a comment above the command.
    pytest.param("# it's fine\ngit add -A", marks=_UNBALANCED_QUOTE, id="comment-apostrophe-add-A"),
    pytest.param(
        "# don't forget\ngit add .", marks=_UNBALANCED_QUOTE, id="comment-apostrophe-pathspec"
    ),
    pytest.param(
        "# that's it\ngit commit -am wip", marks=_UNBALANCED_QUOTE, id="comment-apostrophe-commit"
    ),
    # The synonym limb BACKLOG #1340 added never denied this shape at all: it is a fail-open the
    # quote repair introduced nothing into and closes nothing of, which is why it is pinned too.
    pytest.param(
        "# can't skip\ngit stage -A", marks=_UNBALANCED_QUOTE, id="comment-apostrophe-stage"
    ),
    # ESCAPED, bash spelling: a backslash-escaped double quote. bash stages; PowerShell refuses to
    # parse it, because a backslash is not a PowerShell escape.
    pytest.param(
        'echo "a \\" b" ; git add .', marks=_ESCAPED_QUOTE, id="bash-escaped-dquote-pathspec"
    ),
    pytest.param(
        'echo "a \\" b"\ngit add -A', marks=_ESCAPED_QUOTE, id="bash-escaped-dquote-newline"
    ),
    # A backslash-escaped APOSTROPHE outside any span. bash reads it as a literal character and
    # runs the stage; the guard reads it as a span opening and blanks the stage.
    pytest.param(
        "echo it\\'s fine && git add -A", marks=_ESCAPED_QUOTE, id="bash-escaped-apostrophe"
    ),
    # ESCAPED, PowerShell spelling: a BACKTICK-escaped double quote. PowerShell stages; bash
    # refuses to parse it. The pair is the argument against a single-shell repair -- the two
    # shells do not agree on which character escapes, and this guard screens both tools.
    pytest.param('echo "a `" b" && git add -A', marks=_ESCAPED_QUOTE, id="pwsh-escaped-dquote"),
]


@pytest.mark.parametrize("command", MUST_STILL_DENY)
def test_the_fix_did_not_buy_a_fail_open(command: str) -> None:
    assert_denied(run_guard(bash(command)))


def test_an_unrecognised_subcommand_falls_through_to_deny_not_allow() -> None:
    """The polarity rule, asserted directly rather than left to the rows above.

    Recognition may only ever SUPPRESS a deny. `zzz-not-a-subcommand` is not in the read-only
    list and never will be, so a command carrying it must still be judged by the staging
    predicates -- which deny. If this ever allows, the resolver has been rewritten so that failing
    to recognise something produces an allow, and that is the exact defect that killed the
    predicate in BACKLOG #1229.
    """
    assert_denied(run_guard(bash("git zzz-not-a-subcommand add -A")))


# ------------------------------------------- the measured fail-opens, step one (#1339)

# EVERY BLANKET ROW IN THIS SECTION WAS MEASURED FIRST: run under the shell its tool names, in a
# throwaway repository holding three modified tracked files at three depths and two untracked
# files, and seen to stage or commit all three tracked files. Every one was ALLOWED by the guard at
# the commit before this change. The full table, with what git did, is
# docs/BLANKET-STAGE-GUARD-FAIL-OPENS.md.
#
# EACH ROW IS A PAIR, AND THE SECOND HALF IS THE CONTROL. A deny test passes just as well against a
# guard that refuses every commit, so each blanket form is driven beside the nearest SCOPED form of
# the same shape, which must allow. If the rule were widened until it swallowed ordinary work, the
# control half fails; if the rule were removed, the blanket half fails.
_BS = "\\"
_BT = "`"

BLANKET_AND_SCOPED_CONTROL = [
    # git commit with a whole-tree pathspec: commits every tracked change, staged or not
    ("Bash", "git commit -m wip .", "git commit -m wip ./a.py"),
    ("Bash", "git commit -m wip -- :/", "git commit -m wip -- :/a.py"),
    ("Bash", "git commit -o . -m wip", "git commit -o a.py -m wip"),
    ("Bash", "git commit -i -m wip .", "git commit -i -m wip a.py"),
    ("Bash", "git commit -m wip ./", "git commit -m wip ./sub"),
    ("Bash", "git commit . -m wip", "git commit .gitignore -m wip"),
    ("Bash", "git commit --amend --no-edit .", "git commit --amend --no-edit"),
    ("PowerShell", "git -c user.name=x commit -m wip .", "git -c user.name=x commit -m wip a.py"),
    # the dot FAMILY: every path built only from single dots and separators is the current directory
    ("Bash", "git add ./.", "git add ./.gitignore"),
    ("Bash", "git add ././", "git add ./sub/"),
    ("Bash", "git add .//", "git add sub//"),
    ("PowerShell", f"git add .{_BS}", f"git add .{_BS}a.py"),
    ("PowerShell", f"git add .{_BS}.", f"git add sub{_BS}."),
    ("Bash", "git stage ./.", "git stage ./a.py"),
    ("Bash", "git add -- ./.", "git add -- ./a.py"),
    # a quoted flag reaches git as the flag
    ("Bash", 'git add "-A"', 'git add "-A.txt"'),
    ("PowerShell", "git add '--all'", "git add '--all.txt'"),
    # a redirect glued to the last argument
    ("Bash", "git add .>/dev/null", "git add .gitignore>/dev/null"),
    ("Bash", "git add -A>/dev/null", "git add a.py>/dev/null"),
    ("Bash", "git commit -m wip -a>/dev/null", "git commit -m wip a.py>/dev/null"),
    # a line continuation: one command to the shell, two lines to the old splitter
    ("Bash", f"git add {_BS}\n-A", f"git add {_BS}\n  a.py"),
    ("Bash", f"git {_BS}\nadd -A", f"git {_BS}\nadd a.py"),
    ("Bash", f"git add {_BS}\n.", f"git add {_BS}\n.gitignore"),
    ("Bash", f"git commit {_BS}\n-am wip", f"git commit {_BS}\n-m wip a.py"),
    ("Bash", f"git commit -m wip {_BS}\n.", f"git commit -m wip {_BS}\n  a.py"),
    # bash DELETES the backslash-newline, so it may sit inside a word
    ("Bash", f"git add -{_BS}\nA", f"git add -{_BS}\nN a.py"),
    ("Bash", f"git ad{_BS}\nd -A", f"git ad{_BS}\nd a.py"),
    ("Bash", f"gi{_BS}\nt add -A", f"gi{_BS}\nt add a.py"),
    ("PowerShell", f"git add {_BT}\n-A", f"git add {_BT}\n  a.py"),
    ("PowerShell", f"git {_BT}\nadd -A", f"git {_BT}\nadd a.py"),
    ("PowerShell", f"git commit {_BT}\n-am wip", f"git commit {_BT}\n-m wip a.py"),
]

# WHAT A BUILDER TYPES ALL DAY, PINNED AS ALLOW. A false deny on this guard is a defect: it is the
# friction that gets a control disarmed. Each row sits next to a rule above that could have caught
# it, and the comment names which.
MUST_STAY_ALLOWED = [
    # the commit pathspec rule reads the BLANKED view, so a dot inside a quoted message is not one
    ("Bash", 'git commit -m "msg" path/to/file.py'),
    ("PowerShell", 'git commit -m "msg" path/to/file.py'),
    ("Bash", 'git commit -m "add . to the list"'),
    ("PowerShell", "git commit -m 'add . to the list'"),
    ("Bash", "git commit -m 'one. two.' a.py"),
    ("Bash", 'git commit -m "wip" -- a.py sub/b.py'),
    ("Bash", "git commit -F .msg-file a.py"),
    ("Bash", "git commit --fixup :/pattern"),
    ("Bash", "git commit -m wip sub/."),
    ("Bash", "git commit --amend --no-edit"),
    ("Bash", 'git commit -m "line one\n\nline . two" a.py'),
    # ... and it reads only what FOLLOWS the word `commit`
    ("Bash", "git -C . commit -m wip a.py"),
    ("Bash", "git --work-tree . commit -m wip a.py"),
    # ... and not a trailing comment, nor a dot that belongs to a nested command
    ("Bash", "git commit -m wip a.py  # only a.py, not ."),
    ("Bash", "git commit -m 'fix' a.py # see ./"),
    ("Bash", "git push origin HEAD # commit ."),
    ("Bash", "git commit -m wip -- $(git ls-files -m . | head -3)"),
    ("PowerShell", "git commit -m wip (Join-Path . a.py)"),
    # ... and a quote beside `./` starts a quoted file name, it does not end the pathspec
    ("Bash", 'git commit -m wip ./"$f"'),
    ("Bash", "git commit -m wip -- $(git diff --cached --name-only -- .)"),
    # a path that merely STARTS with a dot, or climbs out, is scoped
    ("Bash", "git add path/to/file"),
    ("Bash", "git add ./a.py ../x.py"),
    ("Bash", "git add ../sibling/file.py"),
    ("Bash", "git add .github/workflows/ci.yml"),
    ("PowerShell", f"git add .{_BS}a.py"),
    # A RUN OF SLASHES MUST NOT HANG THE HOOK. A nested quantifier in the dot family backtracked
    # exponentially here. `test_a_run_of_slashes_does_not_hang_the_hook` holds the time bound.
    ("Bash", "git add ." + "/" * 40 + "x"),
    # `commit` as a whole TOKEN only: a ref that contains the word is not the subcommand
    ("Bash", "git checkout fix-commit -- a.py"),
    # read-only subcommands still suppress, whatever their pathspec
    ("Bash", "git log --all --grep commit"),
    ("Bash", "git diff -- ."),
    ("Bash", "git status ."),
    ("Bash", "git grep -n add -- ."),
    # quoted prose that names the denied commands
    ("Bash", 'gh pr create --title t --body "do not run git add -A or git commit -m wip ."'),
    ("PowerShell", "gh pr create --body 'git add -A; git commit -m wip .'"),
    ("Bash", "git commit -m 'fix (git add -A) note' a.py"),
    # a COMMENT that names them, in brackets or backticks
    ("Bash", f"# Do not run {_BT}git commit -a{_BT} here\ngit commit -m wip a.py"),
    ("PowerShell", f"# Do not run {_BT}git commit -a{_BT} here\ngit commit -m wip a.py"),
    ("Bash", "# stage explicit paths (git add -A is blocked)\ngit add a.py"),
    ("PowerShell", "# stage explicit paths (git add -A is blocked)\ngit add a.py"),
    ("Bash", "ls  # (git stage -A is blocked by the guard)"),
    ("Bash", f"git add a.py  # not {_BT}git add .{_BT}"),
    ("Bash", "git commit -m wip a.py  # (not -a)"),
    # PROSE THAT A SLIPPED QUOTE STATE EXPOSES. An apostrophe or an escaped quote puts the quote
    # tracking out of step and the message text shows. A rule that started a command after an
    # opening bracket, and one that joined the lines of a quoted span, each refused rows here;
    # both were withdrawn for it.
    ("PowerShell", "gh pr create --title t --body @'\nThe guard doesn't allow (git add -A).\n'@"),
    ("Bash", f'git commit -m "fix: the {_BS}"(git add -A){_BS}" case" a.py'),
    ("PowerShell", "git commit -m @'\nseat.ps1 doesn't accept -Declare without -Seat\n'@ a.py"),
    ("PowerShell", "git commit -m @'\nIt doesn't stage . any more\n'@ a.py"),
    ("Bash", "git add a.py  # don't forget b.py later\ngit commit -m wip\ngit push -u origin HEAD"),
    ("Bash", "git add docs/x.md   # don't add the rest\ngit status --short ."),
    ("Bash", "cmd=(git add -A)"),
    ("PowerShell", "$sb = { git add -A }"),
    (
        "PowerShell",
        f"gh pr create --title t --body @'\nThe guard doesn't allow {_BT}git add -A{_BT}.\n'@",
    ),
    # brackets that do NOT put a blanket stage at the front of a segment
    ("Bash", "git add src/{a,b}.py"),
    ("Bash", "git add ./{a,b}.py"),
    ("Bash", "(git add ./{a,b}.py)"),
    ("Bash", "git commit -m msg -- src/{a,b}.py"),
    ("Bash", "git show HEAD@{1}:a.py"),
    ("Bash", "git stash apply stash@{0}"),
    ("Bash", "(cd sub && git add b.py)"),
    ("Bash", "x=$(git rev-parse HEAD) && git add a.py"),
    ("Bash", "git commit -m $(cat msgfile) a.py"),
    ("PowerShell", "$h = (git rev-parse HEAD); git add a.py"),
    ("PowerShell", "git add (Get-ChildItem a.py).Name"),
    ("PowerShell", "$m = @{ a = 1 }; git add a.py"),
    ("PowerShell", "Write-Output (git status --short)"),
    # PowerShell one-liners whose tail holds a dash-word or a bare dot: `-ForegroundColor` holds
    # a `u`, `-Path` holds an `a`, and `Test-Path .` holds a dot. None of it is git's.
    (
        "PowerShell",
        'if ($LASTEXITCODE -eq 0) { git add a.py } else { Write-Host "failed" -ForegroundColor Red }',
    ),
    ("PowerShell", "& { git add a.py } -ErrorAction SilentlyContinue"),
    ("PowerShell", 'try { git commit -m "wip" a.py } finally { Remove-Item -Path msg.txt }'),
    ("PowerShell", "if (Test-Path a.py) { git add a.py } elseif (Test-Path . ) { 1 }"),
    ("PowerShell", '{ git add a.py } else { Write-Host "use -A next time" }'),
    # continuations that join ordinary work
    ("Bash", f"git add a.py {_BS}\n  sub/b.py"),
    ("Bash", f"git commit -m wip {_BS}\n  a.py"),
    ("Bash", f'gh pr create --title t {_BS}\n  --body "git add -A is denied"'),
    ("PowerShell", f"git commit -m 'line one' {_BT}\n  a.py"),
    # A BACKSLASH IS NOT A POWERSHELL CONTINUATION. `git add src\` and `git diff --stat .` are two
    # commands there, so the tool name must keep them apart; joined, they read as `git add ... .`.
    ("PowerShell", f"git add src{_BS}\ngit diff --stat ."),
    # an ESCAPED backslash before the newline continues nothing in bash either
    ("Bash", f"git add src{_BS}{_BS}\ngit diff --stat ."),
    # MEASURED: the bare flag stages nothing (git prints the empty-pathspec hint), so allowing it
    # costs nothing. `git add --renormalize .` is denied by the pathspec limb and always was.
    ("Bash", "git add --renormalize"),
    ("Bash", "git add --renormalize a.py"),
]

# THE JOINED VIEW IS ADDED BESIDE THE OLD ONE, AND THE FIRST ROW IS WHY. Each row denied before
# this change and must still deny:
#   * a shell comment does not continue, so the stage on the line after `# see C:\temp\` is real
#     (measured under bash: it stages the whole tree). Joining the two lines would hide it.
#   * an argument in brackets must not strand the flag that follows it.
#   * a nested quantifier in the dot family would hang the scan on a run of slashes, before it
#     reached the real stage after the `;`.
ADDED_NOT_REPLACED = [
    ("Bash", f"# see C:{_BS}temp{_BS}\ngit add -A"),
    ("Bash", "git add ${nothing} -A"),
    ("Bash", "git add $(cat list) -u"),
    ("PowerShell", "git add (Get-ChildItem) -A"),
    ("Bash", "git add ." + "/" * 40 + "x; git add -A"),
]

# THE MEASURED FAIL-OPENS THAT ARE STILL OPEN, IN TWO TABLES. Each row stages or commits the whole
# tree in a real shell and is ALLOWED. They are pinned the same way as the quote class above, and
# for the same reason: the assertion demands the DENY, `strict` turns a repair into a visible
# XPASS, and nobody can write today's ALLOW down as a requirement.
#
# WHY EACH IS STILL OPEN DIFFERS BY ROW, so read the page before assuming a row cannot be closed.
# Many need a quote-state parser or a program-position test, which are declined (BACKLOG #1341,
# #1229), or the working directory, which the guard cannot see. Some were closed by a wider
# reading that was then withdrawn. And some are plain reading mistakes that look closable and have
# not been tried: the bare carriage return, the heredoc word with a dash, the arithmetic shift,
# and the path that only needs normalising.
#
# WHICH TABLE A ROW SITS IN IS THE RECORD OF WHO ACCEPTED IT, so do not move a row without an
# owner answer to cite. docs/BLANKET-STAGE-GUARD-FAIL-OPENS.md carries the answers, the full
# tables and what git did for each form. The answers are reported by the Special seat; no other
# seat saw the dialogs. AT LEAST these.
_ACCEPTED = pytest.mark.xfail(
    strict=True,
    reason="BACKLOG #1339: measured to stage the whole tree and allowed; a fail-open the owner "
    "accepted, as reported in docs/BLANKET-STAGE-GUARD-FAIL-OPENS.md sections 2 and 3",
)

ACCEPTED_FAIL_OPENS = [
    # answer 2 (a), a word before git: needs a program-position test
    ("Bash", "if true; then git add -A; fi"),
    ("Bash", "for i in 1; do git add -A; done"),
    ("Bash", "true && ! git add -A"),
    ("Bash", "time git add -A"),
    ("Bash", "FOO=1 git add -A"),
    # answer 2 (b), the parent directory from a subfolder: whole tree or scoped, by a directory
    # the guard cannot see
    ("Bash", "cd sub && git add .."),
    ("Bash", "git -C sub add .."),
    ("Bash", "cd sub && git commit -m wip .."),
    # answer 2 (c), quoting the guard cannot read without quote state
    ("Bash", "git commit -m wip '.'"),
    ("PowerShell", "git commit '-a' -m wip"),
    ("Bash", 'git "add" -A'),
    ("Bash", '"git" add -A'),
    ("Bash", "git add $'-A'"),
    # answer 2 (d), the shell supplies the pathspec
    ("Bash", 'git add "$PWD"'),
    ("Bash", "git add ~+"),
    ("Bash", "git add {.,}"),
    ("PowerShell", "git add (Get-Location)"),
    # answer 2 (e), grouping and substitution: git is not at the front of a separator segment
    ("Bash", "(git add -A)"),
    ("Bash", "{ git add -A; }"),
    ("Bash", "echo $(git add -A)"),
    # ... except in this row, where it is. This one is allowed because the closing bracket is
    # glued to the flag; its control below has a space there and is denied.
    ("Bash", "(cd sub && git add -A)"),
    ("Bash", 'echo "$(git add -A)"'),
    ("Bash", "cat <<EOF\n$(git add -A)\nEOF"),
    ("PowerShell", "& { git add -A }"),
    ("PowerShell", "if ($true) { git add -A }"),
    # answer 3, form 1: an escaped quote that hides a bracket or a hash before the dot
    ("Bash", f'git commit -m "a {_BS}" (b {_BS}" c" .'),
    ("Bash", f'git commit -m "a {_BS}" #b {_BS}" c" .'),
    ("PowerShell", f'git commit -m "a {_BT}" (b {_BT}" c" .'),
    # answer 3, form 2: a PowerShell block comment before the dot
    ("PowerShell", "git commit -m wip <# note #> ."),
    # answer 3, form 3: a piped substitution followed by a dot
    ("Bash", "git commit -m $(echo wip | cat) ."),
    ("Bash", "git add $(echo a.txt | cat) ."),
    # answer 3, form 4: a stage on a line after a bash here-string, which the heredoc reader blanks
    ("Bash", "cat <<<x\ngit add -A"),
    ("Bash", "cat <<<x\ngit commit -m wip ."),
    ("Bash", 'read -r a b <<< "$line"\ngit commit -am wip'),
]

# NOT ACCEPTED BY ANY OWNER ANSWER. No line in the three answers describes these rows. The page
# lists them in section 5, with the nearest accepted line for each.
_NOT_ACCEPTED = pytest.mark.xfail(
    strict=True,
    reason="BACKLOG #1339: measured to stage the whole tree and allowed; under no owner answer, "
    "listed in docs/BLANKET-STAGE-GUARD-FAIL-OPENS.md section 5",
)

NOT_ACCEPTED_FAIL_OPENS = [
    # under no answer at all
    ("PowerShell", "Write-Host hi\rgit add -A"),
    ("Bash", "cat <<EOF-1\nx\nEOF-1\ngit add -A"),
    ("Bash", "echo $((1<<n))\ngit add -A"),
    ("Bash", "git diff | git apply --cached"),
    # next to an accepted line whose words do not fit
    ("Bash", ">/dev/null git add -A"),
    ("PowerShell", "<# note #> git add -A"),
    ("Bash", "git add sub/.."),
    ("PowerShell", "(git add -A)"),
    ("Bash", f'git add "-{_BS}\nA"'),
    ("Bash", 'echo "see <<EOF"\ngit add -A'),
    ("Bash", f"git commit -m fix{_BS}(x ."),
    ("Bash", "git commit -m $(echo wip | cat) :/"),
    ("Bash", "git commit -m $(echo wip | cat) -a"),
    ("Bash", "git commit -m `echo wip | cat` ."),
    ("Bash", "git commit -m $(true && echo wip) ."),
    ("Bash", "git commit -m $(cat <<'EOF'\nsubject\nEOF\n) ."),
    # a pathspec or flag after a message that spans lines
    ("Bash", 'git commit -m "subject\n\nbody" .'),
    ("PowerShell", "git commit -m 'subject\nbody' -a"),
    ("PowerShell", "git commit -m @'\nx\n'@ ."),
    # git supplies the command, or another git command does the staging
    ("Bash", "git -c alias.aa=add aa ."),
    ("Bash", "git ls-files -m | git update-index --stdin"),
]

# THE CONTROLS FOR THE TWO TABLES ABOVE. Each is the nearest form that the guard DOES deny, and
# each was measured to stage or commit the whole tree. Without them a row above could be allowed
# because the guard allows everything of that shape, not because of the one thing the row names.
STILL_OPEN_CONTROLS = [
    ("Bash", 'git commit -m "a (b c" .'),
    ("Bash", 'git commit -m "a #b c" .'),
    ("PowerShell", "git commit -m wip <#note#> ."),
    ("PowerShell", "git commit -m wip <# note #> -a"),
    ("Bash", "git commit -m $(echo wip) ."),
    ("Bash", "(cd sub && git add -A )"),
    ("Bash", "{ cd sub; git add -A; }"),
    ("Bash", f"git add -{_BS}\nA"),
    ("Bash", "cat <<<x; git add -A"),
    ("Bash", "cat <<EOF\nx\nEOF\ngit add -A"),
    ("Bash", "echo $((1 << 2))\ngit add -A"),
    ("PowerShell", '$m = @"\nx\n"@\ngit add -A'),
]

# HARMLESS COMMANDS THE GUARD REFUSES, PINNED THE SAME WAY. The assertion demands the ALLOW each is
# owed. The first six are the price of the commit pathspec rule; the last is older. AT LEAST
# these; the page lists more, with what git did for each.
_OVER_DENY = pytest.mark.xfail(
    strict=True,
    reason="BACKLOG #1339: a harmless command the guard refuses; listed in "
    "docs/BLANKET-STAGE-GUARD-FAIL-OPENS.md",
)

KNOWN_OVER_DENY = [
    ("Bash", "git commit -m . a.py"),
    ("Bash", "git stash push -m commit -- ."),
    ("Bash", "git commit --dry-run ."),
    ("Bash", "cd sub && git commit -m wip ."),
    ("Bash", "git -C sub commit -m wip ."),
    ("Bash", "git commit -m wip . ':!sub'"),
    ("Bash", "git add a.py  # not ."),
]

# ONE pwsh PROCESS FOR ALL THE TABLES ABOVE. Every other test in this file starts the hook the way
# Claude Code does, one process per payload, and that stays the contract under test. These tables
# are a few hundred payloads, so they are driven through one process that swaps the console
# streams and calls the same script file once per payload. `exit` in a script called with `&` ends
# that script only. `test_the_batch_driver_agrees_with_a_real_invocation` holds the two together.
_BATCH_DRIVER = """
$guard = $env:MEFOR_BLANKET_GUARD_UNDER_TEST
$payloads = [Console]::In.ReadToEnd() | ConvertFrom-Json
$realOut = [Console]::Out
$outputs = New-Object 'System.Collections.Generic.List[string]'
foreach ($p in $payloads) {
    $w = New-Object System.IO.StringWriter
    [Console]::SetIn((New-Object System.IO.StringReader ([string]$p)))
    [Console]::SetOut($w)
    try { & $guard } finally { [Console]::SetOut($realOut) }
    if ($LASTEXITCODE -ne 0) { throw "guard exited $LASTEXITCODE" }
    $outputs.Add($w.ToString())
}
[Console]::Out.Write((ConvertTo-Json -InputObject $outputs.ToArray() -Compress))
"""

_BATCHED: list[tuple[str, str]] = sorted(
    {(tool, blanket) for tool, blanket, _ in BLANKET_AND_SCOPED_CONTROL}
    | {(tool, scoped) for tool, _, scoped in BLANKET_AND_SCOPED_CONTROL}
    | set(MUST_STAY_ALLOWED)
    | set(ADDED_NOT_REPLACED)
    | set(ACCEPTED_FAIL_OPENS)
    | set(NOT_ACCEPTED_FAIL_OPENS)
    | set(STILL_OPEN_CONTROLS)
    | set(KNOWN_OVER_DENY)
)


@functools.cache
def _batched_verdicts() -> dict[tuple[str, str], dict[str, Any] | None]:
    payloads = [json.dumps(bash(command, tool=tool)) for tool, command in _BATCHED]
    with tempfile.TemporaryDirectory() as tmp:
        driver = Path(tmp) / "drive.ps1"
        driver.write_text(_BATCH_DRIVER, encoding="utf-8")
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(driver)],
            input=json.dumps(payloads),
            capture_output=True,
            text=True,
            timeout=600,
            env={**os.environ, "MEFOR_BLANKET_GUARD_UNDER_TEST": str(GUARD)},
        )
    assert proc.returncode == 0, f"batch driver exited {proc.returncode}: {proc.stderr}"
    outputs: list[str] = json.loads(proc.stdout)
    assert len(outputs) == len(_BATCHED)
    return {
        row: (json.loads(out) if out.strip() else None)
        for row, out in zip(_BATCHED, outputs, strict=True)
    }


def verdict(tool: str, command: str) -> dict[str, Any] | None:
    return _batched_verdicts()[(tool, command)]


def test_the_batch_driver_agrees_with_a_real_invocation() -> None:
    """The batch is a shortcut, so it is checked against the real thing: one deny, one allow, and
    one row from each new reading, each also run as its own process."""
    for row in [
        ("Bash", "git commit -m wip ."),
        ("Bash", "git commit -m wip ./a.py"),
        ("Bash", f"git add -{_BS}\nA"),
        ("PowerShell", f"git add {_BT}\n-A"),
        ("PowerShell", f"git add src{_BS}\ngit diff --stat ."),
    ]:
        assert verdict(*row) == run_guard(bash(row[1], tool=row[0])), row


@pytest.mark.parametrize(("tool", "blanket", "scoped"), BLANKET_AND_SCOPED_CONTROL)
def test_a_measured_blanket_form_denies_and_its_scoped_control_allows(
    tool: str, blanket: str, scoped: str
) -> None:
    assert_denied(verdict(tool, blanket))
    assert_allowed(verdict(tool, scoped))


def test_the_commit_pathspec_deny_names_the_pathspec_and_not_the_flag() -> None:
    reason = assert_denied(run_guard(bash("git commit -m wip .")))
    assert "git commit with a whole-tree pathspec" in reason
    assert "git add <path>" in reason


@pytest.mark.parametrize(("tool", "command"), MUST_STAY_ALLOWED)
def test_ordinary_work_next_to_the_new_rules_is_allowed(tool: str, command: str) -> None:
    assert_allowed(verdict(tool, command))


@pytest.mark.parametrize(("tool", "command"), ADDED_NOT_REPLACED)
def test_a_second_reading_only_ever_adds_a_deny(tool: str, command: str) -> None:
    assert_denied(verdict(tool, command))


def test_a_run_of_slashes_does_not_hang_the_hook() -> None:
    """Driven as its OWN process, so the timeout in run_guard is what fails it. The old dot-family
    pattern took minutes on this payload and never reached the real stage after the `;`."""
    assert_denied(run_guard(bash("git add ." + "/" * 40 + "x; git add -A")))


@pytest.mark.parametrize("continuation", [_BS, _BT])
def test_an_unknown_tool_gets_both_continuation_characters(continuation: str) -> None:
    """The tool name picks ONE character for a tool the guard knows. For any other name it must
    apply both, never neither: an unrecognised name may only add a deny. The scoped half is the
    control."""
    assert_denied(run_guard(bash(f"git add {continuation}\n-A", tool="SomeFutureTool")))
    assert_allowed(run_guard(bash(f"git add {continuation}\n  a.py", tool="SomeFutureTool")))


@pytest.mark.parametrize(
    ("tool", "command"), [pytest.param(*r, marks=_ACCEPTED) for r in ACCEPTED_FAIL_OPENS]
)
def test_an_accepted_fail_open_is_still_allowed(tool: str, command: str) -> None:
    assert_denied(verdict(tool, command))


@pytest.mark.parametrize(
    ("tool", "command"), [pytest.param(*r, marks=_NOT_ACCEPTED) for r in NOT_ACCEPTED_FAIL_OPENS]
)
def test_a_fail_open_nobody_accepted_is_still_allowed(tool: str, command: str) -> None:
    assert_denied(verdict(tool, command))


@pytest.mark.parametrize(("tool", "command"), STILL_OPEN_CONTROLS)
def test_the_nearest_form_to_a_fail_open_is_denied(tool: str, command: str) -> None:
    assert_denied(verdict(tool, command))


def test_no_row_is_both_accepted_and_not_accepted() -> None:
    """The two tables are a record of who accepted what, so a row in both says nothing."""
    assert not set(ACCEPTED_FAIL_OPENS) & set(NOT_ACCEPTED_FAIL_OPENS)


@pytest.mark.parametrize(
    ("tool", "command"), [pytest.param(*r, marks=_OVER_DENY) for r in KNOWN_OVER_DENY]
)
def test_a_known_over_deny_is_still_refused_and_should_not_be(tool: str, command: str) -> None:
    assert_allowed(verdict(tool, command))


# --------------------------------------------------------------------------------- still fail-open


@pytest.mark.parametrize(
    "raw",
    [
        "",
        "   ",
        "not json at all",
        "{}",
        "[]",
        '{"tool_input": {}}',
        '{"tool_name": "Bash"}',
        '{"tool_input": {"command": ""}}',
        '{"tool_input": {"command": null}}',
        '{"tool_input": {"script": "git add -A"}}',
        # A real blanket stage in a payload that is cut short, or has text after it. The guard
        # cannot read either, so the stage passes. This is accepted fail-open 5 on the page.
        '{"tool_name": "Bash", "tool_input": {"command": "git add -A"',
        '{"tool_name": "Bash", "tool_input": {"command": "git add -A"}} trailing',
    ],
)
def test_a_payload_the_guard_cannot_read_allows(raw: str) -> None:
    """A guardrail must never wedge all git work. Anything unreadable passes silently."""
    assert_allowed(run_guard(raw))


@pytest.mark.parametrize(
    "raw",
    [
        '{"tool_input": {"command": "git add -A"}}',
        '{"tool_name": "Bash", "tool_input": {"command": ["git", "add", "-A"]}}',
    ],
)
def test_an_odd_payload_the_guard_can_still_read_denies(raw: str) -> None:
    """The control for the test above: the allow there comes from the payload being unreadable,
    and not from the guard allowing every odd payload."""
    assert_denied(run_guard(raw))
