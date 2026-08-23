# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The gate matched a SPELLING and called it a program; Windows matches an EXECUTABLE (BACKLOG #1305).

``Git``, ``GIT``, ``gIt`` and ``GIT.EXE`` all resolve to the same ``git.exe`` and all RUN -- measured
directly on both tool paths, Git Bash 5.2.37 and pwsh 7. Every git test in the hook compared
case-SENSITIVELY, so exactly one of those spellings ever matched. Measured on ``origin/main`` from
inside a governed primary, one capital letter apart::

    git -C <governed> reset --hard    DENY        Git -C <governed> reset --hard    ALLOW

**IT WAS NEVER ONE RULE.** The item bounded its measurement at rule 3 and left rule 3b unsampled; all
four git rules carried the same defect, and rule 3c is the worst of them --
``Git -C <governed> config core.hooksPath /dev/null`` disarms the ledger, claim and secret-leak commit
gates for every worktree on the machine at once. Measured on ``origin/main``:

===== ================================== ===== ===== ==========
rule  guards                             git   Git   GIT.EXE
===== ================================== ===== ===== ==========
3     primary tree swap                  DENY  ALLOW ALLOW
3b    linked-worktree hijack             DENY  ALLOW ALLOW
3c    shared ``core.hooksPath`` disarm   DENY  ALLOW ALLOW
3d    ``worktree remove`` of another      DENY  ALLOW ALLOW
      session's tree
===== ================================== ===== ===== ==========

**THE ALLOW ROWS ARE THE POINT OF THIS FILE, NOT THE DENY ROWS.** The obvious edit -- match the token
case-insensitively -- is measured, costed and rejected: the shared token pattern leads with
``[\\s;&|('\"\\\\/]`` so an absolute program path matches, which means it also matches any PATH ARGUMENT
whose last component is ``git``. Widening by case alone reads ``cp -r "/c/backups/Git" restore`` as a
git command and the next ordinary word as its verb. That was built during BACKLOG #1229 and reverted at
a measured cost of twelve false denies. A false DENY here blocks ordinary developer commands, which is
what buys a gate uninstalled -- so every deny row below is paired with the argument-position row that
must still allow.

**AND THE FIX IS NOT THE REVERTED PREDICATE.** ``Test-GitProgramPosition`` (fb93c9ca, reverted in
c0d6cef8) used a position test to GATE the quoted-program emit, so every shape its wrapper list did not
know went from DENY to ALLOW -- two measured fail-opens that ``origin/main`` denies.
``ConvertTo-CanonicalGitProgram`` only ever rewrites CASE, and only on a token it has already placed in
program position, so it is the IDENTITY on every line that spells git in lowercase. Measured over the
matrix behind this file: 25 rows moved, every one ALLOW to DENY, none the other way. The two fail-opens
stay pinned in ``tests/test_worktree_gate_escaped_quote.py`` and are re-measured DENY here in their
capitalised spelling.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or shutil.which("git") is None,
    reason="needs pwsh (PowerShell 7) and git on PATH",
)

# Every spelling that RUNS git.exe on Windows. `gIt` is not decoration: it rules out a fix that only
# handles the two shapes a human would think to type.
RUNNING_SPELLINGS = ("Git", "GIT", "gIt", "Git.Exe", "GIT.EXE")
# The control that must accompany every deny row. If the lowercase spelling stops denying, the row
# above it proves nothing about case.
LOWERCASE = "git"

# The default Git for Windows install path contains a space, so the quoted form is the ORDINARY
# spelling of an absolute git invocation rather than an exotic one.
QUOTED_PROG = '"C:\\Program Files\\Git\\bin\\{leaf}"'


def git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(
        ["git", *args], cwd=str(cwd) if cwd else None, check=True, capture_output=True, text=True
    )


def shell(command: str, cwd: Path | str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A REAL governed primary plus a linked worktree, because rules 3b/3c/3d ask git itself.

    A string-matching rig reaches only rule 3, and rule 3b is precisely the path the item left
    unsampled -- so a rig that cannot run it would reproduce the item's own blind spot.
    """
    primary = tmp_path / "Repo"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    # A branch that exists and is checked out NOWHERE -- the "free" branch rule 3b protects against.
    git("branch", "claude/free-branch", cwd=primary)
    wt = tmp_path / "Repo-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, repos=repos, free="claude/free-branch")


# --- the four rules, every running spelling -------------------------------------------------------
#
# Each entry names the RULE and a fragment of that rule's own deny text, so a row cannot pass by being
# denied for an unrelated reason -- which is the failure mode of a suite that only asserts "DENY".


def _rule_cases(r: SimpleNamespace) -> list[tuple[str, str, str]]:
    return [
        ("3", "{g} -C " + str(r.primary) + " reset --hard", "working tree of the SHARED PRIMARY"),
        (
            "3",
            "{g} -C " + str(r.primary) + " checkout " + r.free,
            "working tree of the SHARED PRIMARY",
        ),
        ("3b", "{g} -C " + str(r.wt) + " checkout " + r.free, "would switch a LINKED WORKTREE"),
        (
            "3c",
            "{g} -C " + str(r.primary) + " config core.hooksPath /dev/null",
            "would change the SHARED git configuration",
        ),
        (
            "3d",
            "{g} -C " + str(r.primary) + " worktree remove " + str(r.wt),
            "that is NOT the tree",
        ),
    ]


@pytest.mark.parametrize("spelling", RUNNING_SPELLINGS)
def test_every_running_spelling_of_bare_git_is_DENIED_on_every_git_rule(
    repo: SimpleNamespace, spelling: str
) -> None:
    """The bypass itself, across all four git rules and both of the item's bounded/unbounded halves.

    RULE 3b IS THE ROW THE ITEM COULD NOT CLAIM. Its measurement stopped at ``reset --hard`` and
    ``checkout`` on the primary and it said so; 3b, 3c and 3d were sampled afterwards and every one
    behaved identically. Pinning them together is what stops the next reader assuming a single-rule
    defect from a single-rule test.
    """
    for rule, template, fragment in _rule_cases(repo):
        reason = assert_denied(
            run_gate(shell(template.format(g=spelling), repo.primary), repo.repos)
        )
        assert fragment in reason, (
            f"rule {rule}: {spelling!r} denied, but not by rule {rule} -- got {reason[:120]!r}. A row "
            "that denies for the wrong reason is not coverage."
        )
        # THE DISCRIMINATING CONTROL, varying the spelling ALONE: the lowercase form must deny by the
        # same rule. Without it the row above cannot tell a case fix from a gate that denies anything.
        control = assert_denied(
            run_gate(shell(template.format(g=LOWERCASE), repo.primary), repo.repos)
        )
        assert fragment in control


@pytest.mark.parametrize("tool", ["Bash", "PowerShell"])
def test_the_bypass_is_closed_on_BOTH_tool_paths(repo: SimpleNamespace, tool: str) -> None:
    """One matcher serves both tool names and they take different escape conventions.

    The premise was verified on each host separately rather than assumed from the other: ``Git`` and
    ``GIT.EXE`` run git.exe under Git Bash AND under pwsh 7.
    """
    for spelling in RUNNING_SPELLINGS:
        assert_denied(
            run_gate(
                shell(f"{spelling} -C {repo.primary} reset --hard", repo.primary, tool), repo.repos
            )
        )


# --- THE ALLOW HALF, and it is the more important one ---------------------------------------------


@pytest.mark.parametrize(
    "argument_shape",
    [
        "cp -r {q} restore",
        "mv {q} restore",
        "ls {q} restore",
        "rsync -a {q} restore",
        "7z a out.7z {q} restore",
        "echo {q} restore",
        "python --src {q} restore",
        "Copy-Item {q} restore",
        "Move-Item {q} restore",
        "tar -cf o.tar {q} clean",
        "du -sh {q} clean",
        "head -n 5 {q} merge",
        "docker run --rm -v {q} restore",
        # Shapes that put something structural left of the span: a redirect target, a command
        # substitution, a brace expansion, and an earlier quoted span. Each was a case the reverted
        # predicate had to reason about explicitly.
        "echo hi > {q} clean",
        "cp -r $(pwd) {q} clean",
        "cp -r ${BACKUP} {q} clean",
        'cp -r "/a/Git" {q} clean',
    ],
)
@pytest.mark.parametrize("quoting", ['"{p}"', "{p}", "'{p}'"])
def test_a_PATH_ARGUMENT_whose_leaf_spells_git_is_still_ALLOWED(
    repo: SimpleNamespace, argument_shape: str, quoting: str
) -> None:
    """THE ROW THAT CATCHES A FALSE-DENY REGRESSION, which is the failure that killed the last attempt.

    A directory whose last component happens to be ``Git``, followed by an ordinary word that happens
    to be a git verb, is not a git command. Match the token case-insensitively without a position test
    and all of these DENY -- the twelve measured shapes that got the BACKLOG #1229 widening reverted.

    THE CWD IS LOAD-BEARING AND A PREVIOUS VERSION OF THIS SHAPE GOT IT WRONG. Run from outside the
    governed repo, a bare ``git restore`` names no governed target and the row allows whatever the
    scanner emitted -- it would be measuring the target resolver, not the case fix. These run from
    INSIDE the primary, so program position is the only variable left.
    """
    quoted = quoting.replace("{p}", "/c/backups/Git")
    # `.replace` rather than `.format`: one row carries a literal `${BACKUP}` and str.format would read
    # those braces as a field name and raise, turning a probe into a collection error.
    shaped = argument_shape.replace("{q}", quoted)
    assert run_gate(shell(shaped, repo.primary), repo.repos) is None, (
        f"{shaped!r} DENIED. A path argument whose leaf spells `Git` is not a git invocation, and "
        "denying it stops legitimate work over a directory name -- this is the twelve-false-deny "
        "family that got the BACKLOG #1229 widening reverted (BACKLOG #1305)."
    )


def test_the_quote_scan_keeps_a_separator_INSIDE_a_quoted_word_from_starting_a_command(
    repo: SimpleNamespace,
) -> None:
    """A `;` inside a quoted word is data, so the word after it is not in program position.

    This is why the scan reads quotes rather than splitting on separators: without it, every commit
    message or echoed sentence containing ``; Git <verb>`` would deny.
    """
    for shaped in (
        f'echo "hello; Git -C {repo.primary} reset --hard"',
        f'git -C {repo.primary} commit -m "Git checkout was the culprit"',
        f"git -C {repo.primary} commit -m 'GIT reset --hard is what broke it'",
    ):
        assert run_gate(shell(shaped, repo.primary), repo.repos) is None, (
            f"{shaped!r} DENIED -- a capitalised git spelling inside a quoted argument is prose, not "
            "a dispatched program."
        )


def test_a_leaf_that_merely_STARTS_with_git_is_untouched(repo: SimpleNamespace) -> None:
    """The identity check is whole-leaf, not a prefix. `GitHub` and `Gitea` are not git."""
    for name in ("GitHub", "Gitea", "GitLab", "git-lfs"):
        assert (
            run_gate(shell(f'cp -r "/c/backups/{name}" restore', repo.primary), repo.repos) is None
        )
        assert (
            run_gate(shell(f"{name} -C {repo.primary} reset --hard", repo.primary), repo.repos)
            is None
        )


def test_a_case_variant_does_not_widen_which_VERBS_are_gated(repo: SimpleNamespace) -> None:
    """Only the PROGRAM spelling is case-insensitive. The verb half must stay case-SENSITIVE.

    Measured on git 2.53.0.windows.2: ``git RESET`` and ``git STATUS`` FAIL, so a gate that matched
    them would be denying commands that cannot run. Read verbs are not gated in either case.
    """
    for shaped in (
        f"Git -C {repo.primary} status",
        f"GIT -C {repo.primary} log --oneline",
        f"Git -C {repo.primary} RESET --hard",
        f"GIT -C {repo.primary} CHECKOUT main",
    ):
        assert run_gate(shell(shaped, repo.primary), repo.repos) is None, (
            f"{shaped!r} DENIED. Either a read verb became gated, or the verb match went "
            "case-insensitive -- and an uppercase verb does not run at all."
        )
    # THE CONTROL: the lowercase verb in the same slot, with the same capitalised program, denies.
    assert_denied(run_gate(shell(f"Git -C {repo.primary} reset --hard", repo.primary), repo.repos))


def test_an_UNGOVERNED_target_still_allows_every_spelling(repo: SimpleNamespace) -> None:
    """Without this the deny rows prove only that the gate denies capitalised git unconditionally."""
    outside = repo.primary.parent / "NotGoverned"
    for spelling in (LOWERCASE, *RUNNING_SPELLINGS):
        assert (
            run_gate(
                shell(f"{spelling} -C {outside} reset --hard", repo.primary.parent), repo.repos
            )
            is None
        )


# --- wrappers, interpreters and the quoted program ------------------------------------------------


@pytest.mark.parametrize(
    "template,tool,why",
    [
        ("sudo {g} -C {p} reset --hard", "Bash", "a wrapper dispatches the word after it"),
        ("env {g} -C {p} reset --hard", "Bash", "same, and env may carry assignments"),
        ("FOO=1 {g} -C {p} reset --hard", "Bash", "an assignment prefix is transparent"),
        ("timeout 5 {g} -C {p} reset --hard", "Bash", "a numeric operand is transparent"),
        ("sudo -u root {g} -C {p} reset --hard", "Bash", "an option's bare-word operand is too"),
        ("nice -n 10 {g} -C {p} reset --hard", "Bash", "option operand plus numeric"),
        ("echo x | {g} -C {p} reset --hard", "Bash", "a pipe starts a new command"),
        ("({g} -C {p} reset --hard)", "Bash", "so does a subshell"),
        ("cd {p} && {g} reset --hard", "Bash", "and so does &&, with the target from the cd"),
        (
            "find . -name x -exec {g} -C {p} reset --hard \\;",
            "Bash",
            "find dispatches behind -exec",
        ),
        ("bash -c '{g} -C {p} reset --hard'", "Bash", "an interpreter payload is a fresh command"),
        ("pwsh -Command '{g} -C {p} reset --hard'", "Bash", "on the other host too"),
        ("cmd /c {g} -C {p} reset --hard", "Bash", "a cmd switch is transparent"),
        (". {g} -C {p} reset --hard", "PowerShell", "PowerShell dot-source dispatches"),
        ("& {g} -C {p} reset --hard", "PowerShell", "so does the call operator"),
    ],
)
def test_a_case_variant_reached_through_a_wrapper_is_DENIED(
    repo: SimpleNamespace, template: str, tool: str, why: str
) -> None:
    """Program position survives the transparent words in front of it.

    ``dot-source`` and ``cmd /c`` are here for a second reason: they are the two shapes whose loss the
    reverted predicate was withdrawn over. They must deny in EVERY spelling, and a change that closes
    the case bypass by gating the emit reopens them.
    """
    shaped = template.format(g="GIT", p=repo.primary)
    assert_denied(run_gate(shell(shaped, repo.primary, tool), repo.repos)), why
    # The lowercase control, same slot: it denies on origin/main and must still deny here.
    assert_denied(
        run_gate(shell(template.format(g="git", p=repo.primary), repo.primary, tool), repo.repos)
    )


@pytest.mark.parametrize("leaf", ["git.exe", "GIT.EXE", "Git", "Git.exe", "GIT"])
@pytest.mark.parametrize(
    "template,tool",
    [
        ("{prog} -C {p} reset --hard", "Bash"),
        ("cmd /c {prog} -C {p} reset --hard", "Bash"),
        (". {prog} -C {p} reset --hard", "PowerShell"),
    ],
)
def test_a_QUOTED_absolute_git_program_is_DENIED_in_every_spelling(
    repo: SimpleNamespace, leaf: str, template: str, tool: str
) -> None:
    """The quoted-program residual, closed, plus the two fail-opens the revert exists to keep shut.

    ``tests/test_worktree_gate_escaped_quote.py`` used to pin the capitalised rows here as a KNOWN
    OPEN ALLOW, with "when this test reds, somebody closed the hole -- delete the row" in its own
    docstring. It reddened under BACKLOG #1305 and the row is deleted; this is where the DENY lives
    now. The lowercase rows are the ones the revert protected and they are unchanged.

    HOW IT CLOSED WITHOUT BUYING THE TWELVE: the canonicaliser runs on the line BEFORE the quoted-span
    scan, so a quoted ``GIT.EXE`` in PROGRAM position arrives already lowercased and the scan's emit --
    still case-sensitive, untouched -- keeps it. A quoted ``Git`` in ARGUMENT position is never
    rewritten and is still blanked wholesale.
    """
    shaped = template.format(prog=QUOTED_PROG.format(leaf=leaf), p=repo.primary)
    assert_denied(run_gate(shell(shaped, repo.primary, tool), repo.repos))
    # THE CONTROL that keeps this from degenerating into "the gate denies any `cmd /c`": the identical
    # line aimed at a path no repos file governs must ALLOW.
    ungoverned = template.format(
        prog=QUOTED_PROG.format(leaf=leaf), p=repo.primary.parent / "NotGoverned"
    )
    assert run_gate(shell(ungoverned, repo.primary.parent, tool), repo.repos) is None


# --- the residuals, pinned as OPEN so nobody over-reads the fix -----------------------------------


@pytest.mark.parametrize(
    "template,tool,why",
    [
        (
            "Set-Alias g git; g -C {p} reset --hard",
            "PowerShell",
            "an alias carries no evidence of what it names",
        ),
        (
            'g(){{ git "$@"; }}; g -C {p} reset --hard',
            "Bash",
            "nor does a shell function",
        ),
        (
            "cmd /Q/C GIT -C {p} reset --hard",
            "Bash",
            "a concatenated cmd switch run is not a single-component slash token",
        ),
        (
            "ssh box GIT -C {p} reset --hard",
            "Bash",
            "ssh's first operand is a host, so listing ssh as a wrapper would buy nothing",
        ),
    ],
)
def test_the_shapes_this_fix_does_NOT_close_are_pinned_as_KNOWN_OPEN(
    repo: SimpleNamespace, template: str, tool: str, why: str
) -> None:
    """A TRIPWIRE OVER WHAT THE FIX DOES NOT COVER. It asserts ALLOW and that is NOT an endorsement.

    The item's own warning is that "the next bypass is a trailing dot, a short path, a quoted absolute
    path, or an alias, and each one closes as its own item forever". Two of those four are closed here
    (a quoted absolute path in any case; a lowercase short path already denied) and a trailing dot was
    measured NOT to run on either host, so it is not a live bypass. The rows below are what is left,
    measured rather than guessed, so the fix cannot be read as closing them.

    THE FIRST TWO ARE UNREACHABLE FROM A LINE SCANNER at all: the name ``g`` carries no evidence. The
    last two are allowlist misses and could be closed by extending the scanner.

    WHEN A ROW REDS, that is the success signal -- somebody closed it. Delete the row; do not restore
    the ALLOW, and re-check that the argument-position family above still allows.
    """
    shaped = template.format(p=repo.primary)
    assert run_gate(shell(shaped, repo.primary, tool), repo.repos) is None, (
        f"{shaped!r} now DENIES ({why}). If you closed this deliberately, delete the row. Do NOT "
        "restore the ALLOW, and check the argument-position rows above still pass."
    )


def test_the_capitalised_bypass_is_not_confined_to_the_primary_tree_swap(
    repo: SimpleNamespace,
) -> None:
    """Rule 3c is the one worth naming separately, and its blast radius is the reason.

    ``config core.hooksPath`` changes no working tree, so no tree-swap test would ever reach it -- and
    all worktrees share one ``.git``, so setting it from ANY of them disarms the ledger, claim and
    secret-leak commit gates for every session on the machine at once. Run from a linked worktree,
    which is where a session normally stands.
    """
    denied = assert_denied(
        run_gate(
            shell(f"GIT -C {repo.primary} config core.hooksPath /dev/null", repo.wt), repo.repos
        )
    )
    assert "SHARED git configuration" in denied
    # An ordinary per-user config write is untouched in every spelling -- the rule is narrow by design
    # and a case fix must not widen which KEYS are gated.
    assert (
        run_gate(shell(f"GIT -C {repo.primary} config user.email t@e.com", repo.wt), repo.repos)
        is None
    )
