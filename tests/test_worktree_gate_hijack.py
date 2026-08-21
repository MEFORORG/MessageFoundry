# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Tests for rule 3b of the worktree gate: hijacking a LINKED WORKTREE onto an existing branch.

Rule 3 protects only the shared PRIMARY. Rule 3b protects every OTHER governed worktree from the one
move that actually happened here: a session with no worktree of its own ran `git checkout <a-branch>`
inside somebody else's worktree, yanking that session's files onto a different branch mid-task. git
permits it because its native guard only blocks a branch that is ALREADY checked out somewhere -- a
"free" branch can be grabbed by any worktree.

The rule is narrow: only a switch onto an EXISTING LOCAL BRANCH is denied. Creating a new branch
(-b/-c), restoring files (`--`/pathspec), and reset/rebase/merge of the worktree's OWN branch stay
allowed. Unlike rules 1-3 (which string-match paths and need no real repo), rule 3b asks git itself
whether the target is a governed linked worktree and whether the destination names a real branch, so
these tests build REAL repos + worktrees.
"""

from __future__ import annotations

import os
import shlex
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


def git(*args: str, cwd: Path | None = None) -> None:
    subprocess.run(
        ["git", *args],
        cwd=str(cwd) if cwd else None,
        check=True,
        capture_output=True,
        text=True,
    )


def shell(command: str, cwd: Path | str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


_REPO_ROOT = Path(__file__).resolve().parents[1]


def _make_repo(tmp_path: Path, leaf: str) -> SimpleNamespace:
    """A real GOVERNED primary + a linked worktree (on `wt-branch`) + a second branch to hijack onto.

    Layout:
        <tmp>/<leaf>             main worktree, branch `main`   (listed in repos.txt -> governed)
        <tmp>/<leaf>-wt          linked worktree, branch `wt-branch`
        branch `claude/other-branch` exists but is checked out NOWHERE -- the grabbable "free" branch.

    `leaf` is a parameter because one test needs a primary whose path contains a SPACE: that is what
    makes the `-File "<path>"` quoting in rule 3b's remediation load-bearing rather than cosmetic.

    The REAL scripts/worktree/new.ps1 and scripts/coord/lock.ps1 are copied in, so the `-File` path
    the gate prints resolves to the actual script under test rather than a stand-in. lock.ps1 anchors
    on `git -C $Repo rev-parse --git-common-dir`, so it uses THIS fixture's .git and touches nothing real.
    """
    primary = tmp_path / leaf
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    # Branches that exist but are checked out nowhere -- the exact shape of claude/asvs-handoff.
    git("branch", "claude/other-branch", cwd=primary)
    git("branch", "claude/second-branch", cwd=primary)
    wt = tmp_path / f"{leaf}-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)

    for rel in ("scripts/worktree/new.ps1", "scripts/coord/lock.ps1"):
        dst = primary / rel
        dst.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(_REPO_ROOT / rel, dst)

    # Per-leaf, so two fixtures in one tmp_path cannot clobber each other's allowlist -- an unlisted
    # root makes the gate fail OPEN, which would let a test pass for entirely the wrong reason.
    repos = tmp_path / f"repos-{leaf.replace(' ', '_')}.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    tip = subprocess.run(
        ["git", "rev-parse", "claude/other-branch"],
        cwd=str(primary),
        check=True,
        capture_output=True,
        text=True,
    ).stdout.strip()
    return SimpleNamespace(
        primary=primary,
        wt=wt,
        repos=repos,
        other="claude/other-branch",
        second="claude/second-branch",
        tip=tip,
        new_ps1=primary / "scripts/worktree/new.ps1",
    )


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    return _make_repo(tmp_path, "Primary")


def _run_emitted(line: str, tmp_path: Path) -> subprocess.CompletedProcess[str]:
    """Run a command the gate PRINTED, verbatim, and report how it actually exited.

    The `exit $LASTEXITCODE` is load-bearing, not tidiness: without it `pwsh -File` returns 0 even
    when the script it ran died with a parameter-binding error, so every assertion built on the exit
    code would be vacuously green. `test_the_emitted_command_harness_can_see_a_failure` is the control
    that keeps this honest -- if someone deletes the exit line, that control goes red rather than the
    real tests going quietly green.
    """
    script = tmp_path / "remediation.ps1"
    script.write_text(line + " -NoInstall\nexit $LASTEXITCODE\n", encoding="utf-8")
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(script)],
        capture_output=True,
        text=True,
        timeout=180,
    )


# ------------------------------------------------------------------ the hijack, in every spelling


def test_checkout_onto_existing_branch_in_a_linked_worktree_is_denied(
    repo: SimpleNamespace,
) -> None:
    reason = assert_denied(run_gate(shell(f"git checkout {repo.other}", cwd=repo.wt), repo.repos))
    assert "LINKED WORKTREE" in reason
    assert repo.other in reason
    assert "new.ps1" in reason  # must tell the model how to proceed, not just refuse


# --------------------------------------------------- the remediation must RUN, not merely be NAMED
#
# The test directly above is why this section exists. It asserts `"new.ps1" in reason` -- and its
# fixture branch is already `claude/other-branch` -- so it RENDERED the broken command and passed
# anyway, for the defect's whole life. A test that hard-coded the expected hint string would have been
# just as blind: the string was never wrong, the RECEIVING CONTRACT rejected it. So nothing about the
# string can be the assertion. These tests EXECUTE what the gate printed and assert on EFFECTS.


_WINDOWS_ONLY = pytest.mark.skipif(
    os.name != "nt",
    reason=(
        "new.ps1 resolves its repo root with Join-Path $PSScriptRoot '..\\..'; PowerShell on Linux "
        "treats the backslash as a literal filename character, so the script cannot locate itself "
        "there. Same gate as tests/test_worktree_prune_merged.py."
    ),
)


def _emitted_new_ps1_line(reason: str) -> str:
    lines = [ln.strip() for ln in reason.splitlines() if "new.ps1" in ln]
    assert len(lines) == 1, f"expected exactly one new.ps1 command to test, got {lines}\n{reason}"
    return lines[0]


@_WINDOWS_ONLY
def test_the_emitted_command_harness_can_see_a_failure(
    repo: SimpleNamespace, tmp_path: Path
) -> None:
    """CONTROL: prove `_run_emitted` reports a non-zero exit before trusting it to report zero.

    A green gate is evidence only if you have shown it can see the failing class. Measured: without
    the helper's `exit $LASTEXITCODE`, this returns 0 and every execution test below is vacuous.
    """
    line = _emitted_new_ps1_line(
        assert_denied(run_gate(shell(f"git checkout {repo.other}", cwd=repo.wt), repo.repos))
    )
    # Replace whatever -Name the gate chose with a value new.ps1 must refuse: a '/' makes it more than
    # one path component. Done by TOKEN INDEX, so this control neither knows nor restates the slug rule
    # -- and so it works identically before and after the fix.
    tokens = shlex.split(line, posix=False)
    assert "-Name" in tokens, tokens
    tokens[tokens.index("-Name") + 1] = "has/slash"
    broken = " ".join(tokens)
    assert broken != line, f"could not construct the negative case from: {line}"
    assert _run_emitted(broken, tmp_path).returncode != 0, (
        "the harness reported success for a command that must fail -- every execution assertion "
        "in this module is vacuous until this passes"
    )


@_WINDOWS_ONLY
@pytest.mark.parametrize("leaf", ["Primary", "Pri mary"])
def test_the_rule_3b_remediation_creates_a_sibling_worktree_on_the_real_branch(
    tmp_path: Path, leaf: str
) -> None:
    """Run the command rule 3b prints, verbatim, and assert what it actually did.

    Both leaves matter and each isolates one defect. `Primary` pins the -Name/-Branch split: against
    the unfixed gate it dies with "Cannot validate argument on parameter 'Name'". `Pri mary` pins the
    `-File "<path>"` quoting: an unquoted path with a space makes pwsh exit 64 before -Name is ever
    bound, so without this leaf the quoting is untested.

    The only token added to the emitted line is ` -NoInstall`, which skips the venv build (minutes of
    I/O) and touches no argument under test. Every token the gate emitted is executed exactly as
    emitted, in its emitted order and quoting -- PowerShell's own tokenizer is the receiving parser.
    """
    r = _make_repo(tmp_path, leaf)
    reason = assert_denied(run_gate(shell(f"git checkout {r.other}", cwd=r.wt), r.repos))
    line = _emitted_new_ps1_line(reason)

    proc = _run_emitted(line, tmp_path)
    assert proc.returncode == 0, (
        f"the gate printed a command that FAILS:\n{line}\n{proc.stdout}{proc.stderr}"
    )

    # Find what was created from git, never from a hard-coded slug.
    porcelain = subprocess.run(
        ["git", "worktree", "list", "--porcelain"],
        cwd=str(r.primary),
        check=True,
        capture_output=True,
        text=True,
    ).stdout
    paths = [
        Path(ln[len("worktree ") :].strip())
        for ln in porcelain.splitlines()
        if ln.startswith("worktree ")
    ]
    created = [p for p in paths if p.resolve() not in (r.primary.resolve(), r.wt.resolve())]
    assert len(created) == 1, f"expected exactly one new worktree, got {created}\n{porcelain}"
    made = created[0]

    # SAFETY FENCE, asserted before any other result is trusted: nothing outside tmp_path was touched.
    assert tmp_path.resolve() in made.resolve().parents, f"{made} escaped tmp_path"

    # SIBLING, not nested -- asserted both ways.
    assert made.resolve().parent == r.primary.resolve().parent
    assert r.primary.resolve() not in made.resolve().parents

    def _git(*args: str) -> str:
        return subprocess.run(
            ["git", *args], cwd=str(made), check=True, capture_output=True, text=True
        ).stdout.strip()

    # It REUSED the branch rather than forking a new one off origin/main. This is the quiet wrong
    # success a sanitized -Name would produce: same directory, same exit code, different branch.
    assert _git("rev-parse", "--abbrev-ref", "HEAD") == r.other
    assert _git("rev-parse", "HEAD") == r.tip

    # The drift-detector's marker must carry the BRANCH. A directory slug here mismatches the real
    # HEAD by construction and fires a false hijack warning at every SessionStart, forever.
    marker = Path(_git("rev-parse", "--absolute-git-dir")) / "mefor-home-branch"
    assert marker.read_text(encoding="utf-8").strip() == r.other


@pytest.mark.parametrize("verb", ["checkout", "switch"])
def test_a_branch_checked_out_elsewhere_is_left_to_gits_own_guard(
    repo: SimpleNamespace, verb: str
) -> None:
    """`main` is checked out in the primary, so git refuses this switch without us.

    Denying it anyway would print `new.ps1 -Branch main`, which dies with "already checked out at" --
    another command the receiving side rejects, for the most ordinary shape there is.
    """
    assert run_gate(shell(f"git {verb} main", cwd=repo.wt), repo.repos) is None


@pytest.mark.parametrize("verb", ["checkout", "switch"])
def test_ignore_other_worktrees_still_denies(repo: SimpleNamespace, verb: str) -> None:
    """The flag that turns git's native guard OFF must not inherit the pass given above.

    Measured, for BOTH verbs -- `--[no-]ignore-other-worktrees` is accepted by checkout and switch
    alike, so covering only one spelling would leave the hole open under the other word:

        git <verb> main                            -> fatal: 'main' is already used by worktree at ...
        git <verb> --ignore-other-worktrees main   -> Switched to branch 'main'

    That is worse than the case rule 3b was written for: a LIVE worktree loses its branch mid-task,
    rather than a free branch being grabbed. The general form of the bug is that deferring to a guard
    you do not own is sound only while that guard is switched on, and its own caller can switch it off.
    """
    reason = assert_denied(
        run_gate(shell(f"git {verb} --ignore-other-worktrees main", cwd=repo.wt), repo.repos)
    )
    assert "LINKED WORKTREE" in reason


def test_the_emitted_name_is_derived_from_the_branch(repo: SimpleNamespace) -> None:
    """Two different branches must yield two different directories.

    A gate that emitted a CONSTANT -Name would satisfy every other test here -- the worktree still
    lands in the right place on the right branch -- while making two concurrent denies collide on one
    directory, at which point the second session's remediation throws "Worktree path already exists".
    That is another printed command that cannot run, which is the class this change exists to close.
    """
    names = []
    for branch in (repo.other, repo.second):
        reason = assert_denied(run_gate(shell(f"git checkout {branch}", cwd=repo.wt), repo.repos))
        tokens = shlex.split(_emitted_new_ps1_line(reason), posix=False)
        assert "-Name" in tokens, tokens
        names.append(tokens[tokens.index("-Name") + 1])
    assert names[0] != names[1], f"both branches emitted the same -Name: {names}"


def test_the_emitted_name_is_always_one_new_ps1_accepts(repo: SimpleNamespace) -> None:
    """Totality guard that restates NO rule: both halves are read out of the sources themselves.

    The slug function is extracted from the gate via the PowerShell AST; the accept pattern is read
    off new.ps1's own ValidatePattern via Get-Command (which does not execute the body). Neither is
    hand-copied here, so this cannot drift out of agreement with what it guards.
    """
    gate = _REPO_ROOT / "scripts/hooks/worktree_gate.ps1"
    probe = r"""
param([string]$Gate, [string]$NewPs1)
$ast = [System.Management.Automation.Language.Parser]::ParseFile($Gate, [ref]$null, [ref]$null)
$fn = $ast.Find({
    param($n)
    $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConvertTo-WorktreeSlug'
}, $true)
if (-not $fn) { Write-Error 'ConvertTo-WorktreeSlug not found in the gate'; exit 2 }
. ([ScriptBlock]::Create($fn.Extent.Text))
$pat = ((Get-Command $NewPs1).Parameters['Name'].Attributes |
        Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] }).RegexPattern
if (-not $pat) { Write-Error 'no ValidatePattern on new.ps1 -Name'; exit 3 }
$inputs = @('claude/other-branch','a/b/c','---','///','...','.lock','-lead','trail.',"nl`n",
            [char]0x4E2D + [char]0x6587)
$inputs += @(git branch --format='%(refname:short)')
$bad = @()
foreach ($b in $inputs) {
    if (-not $b) { continue }
    $s = ConvertTo-WorktreeSlug $b
    if ($s -notmatch $pat) { $bad += "$b -> $s" }
}
if ($bad) { Write-Output ("NONCONFORMING: " + ($bad -join '; ')); exit 1 }
Write-Output "checked $($inputs.Count) inputs against $pat"
"""
    script = repo.primary / "totality.ps1"
    script.write_text(probe, encoding="utf-8")
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(script),
            "-Gate",
            str(gate),
            "-NewPs1",
            str(repo.new_ps1),
        ],
        cwd=str(_REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"{proc.stdout}{proc.stderr}"
    # Non-vacuity: a pass must mean "checked", not "found nothing to check".
    assert "checked" in proc.stdout, proc.stdout


def test_switch_onto_existing_branch_in_a_linked_worktree_is_denied(repo: SimpleNamespace) -> None:
    assert_denied(run_gate(shell(f"git switch {repo.other}", cwd=repo.wt), repo.repos))


def test_dash_C_into_a_linked_worktree_is_denied(repo: SimpleNamespace) -> None:
    """A session sitting elsewhere reaches into the worktree with -C -- a cwd-only check misses this."""
    assert_denied(
        run_gate(shell(f'git -C "{repo.wt}" checkout {repo.other}', cwd=repo.primary), repo.repos)
    )


def test_cd_into_a_linked_worktree_then_checkout_is_denied(repo: SimpleNamespace) -> None:
    assert_denied(
        run_gate(
            shell(f'cd "{repo.wt}" && git checkout {repo.other}', cwd=repo.primary), repo.repos
        )
    )


def test_git_exe_spelling_is_denied(repo: SimpleNamespace) -> None:
    assert_denied(run_gate(shell(f"git.exe checkout {repo.other}", cwd=repo.wt), repo.repos))


# ------------------------------------------------------------------ what MUST keep working


def test_creating_a_new_branch_in_place_is_allowed(repo: SimpleNamespace) -> None:
    """-b/-c create a brand-new branch nobody holds -- not a hijack of an in-flight one."""
    assert run_gate(shell("git checkout -b brand-new", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell("git switch -c brand-new2", cwd=repo.wt), repo.repos) is None


def test_restoring_a_file_is_allowed(repo: SimpleNamespace) -> None:
    """`git checkout -- <path>` (and `checkout <ref> -- <path>`) is a file restore, not a branch move."""
    assert run_gate(shell("git checkout -- seed.txt", cwd=repo.wt), repo.repos) is None
    assert (
        run_gate(shell(f"git checkout {repo.other} -- seed.txt", cwd=repo.wt), repo.repos) is None
    )


def test_reset_and_rebase_of_the_worktrees_own_branch_are_allowed(repo: SimpleNamespace) -> None:
    """A worktree owns its own history -- it just may not be pulled onto another in-flight branch."""
    assert run_gate(shell("git reset --hard HEAD", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell("git rebase main", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell("git merge main", cwd=repo.wt), repo.repos) is None


def test_checking_out_the_branch_already_on_is_allowed(repo: SimpleNamespace) -> None:
    """A no-op checkout of the branch you are already on must not be flagged."""
    assert run_gate(shell("git checkout wt-branch", cwd=repo.wt), repo.repos) is None


def test_checkout_of_a_nonexistent_branch_is_allowed(repo: SimpleNamespace) -> None:
    """Only an EXISTING local branch is a hijack target; a typo/new name is not (and git errors anyway)."""
    assert run_gate(shell("git checkout does-not-exist", cwd=repo.wt), repo.repos) is None


def test_reads_are_allowed_in_a_linked_worktree(repo: SimpleNamespace) -> None:
    assert run_gate(shell(f"git show {repo.other}:seed.txt", cwd=repo.wt), repo.repos) is None
    assert run_gate(shell(f"git diff HEAD..{repo.other}", cwd=repo.wt), repo.repos) is None


# ------------------------------------------------------------------ scope: primary vs linked vs alien


def test_the_same_move_in_the_primary_uses_rule_3_not_3b(repo: SimpleNamespace) -> None:
    """In the primary the message is the SHARED PRIMARY one (rule 3 owns it), never rule 3b's."""
    reason = assert_denied(
        run_gate(shell(f"git checkout {repo.other}", cwd=repo.primary), repo.repos)
    )
    assert "SHARED PRIMARY" in reason
    assert "LINKED WORKTREE" not in reason


def test_a_worktree_of_an_UNGOVERNED_repo_is_untouched(tmp_path: Path) -> None:
    """Rule 3b acts only when the worktree's MAIN tree is a governed primary -- an alien repo is free."""
    other = tmp_path / "Alien"
    git("init", "-b", "main", str(other))
    git("config", "user.email", "t@example.com", cwd=other)
    git("config", "user.name", "t", cwd=other)
    (other / "f.txt").write_text("x\n", encoding="utf-8")
    git("add", "-A", cwd=other)
    git("commit", "-m", "seed", cwd=other)
    git("branch", "some-branch", cwd=other)
    wt = tmp_path / "Alien-wt"
    git("worktree", "add", "-b", "wt", str(wt), cwd=other)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{tmp_path / 'SomethingGoverned'}\n", encoding="utf-8")  # NOT the alien repo
    assert run_gate(shell("git checkout some-branch", cwd=wt), repos) is None


# ------------------------------------------- a quoted path must not SHADOW the verb rule 3b judges
#
# BACKLOG #1229 residual, fourth round. Rule 3 records the FIRST verb-bearing segment it sees and
# revises that record only when a later segment resolves a GOVERNED target. Inside a linked worktree no
# segment ever does, so whatever line one carries is what rule 3b is handed -- and while
# Remove-QuotedSpans kept the git token of EVERY quoted span whose leaf was `git`, an ordinary
# `cp -r "/c/backups/Git" switch` looked exactly like a git command carrying a gated verb.
#
# The effect is the opposite of the false denies that motivated the position predicate, which is why it
# is pinned in this file and not beside them: the shadowing line ATE the hijack, and a real
# `git switch <free branch>` in somebody else's worktree came back ALLOW.


@pytest.mark.parametrize(
    "leaf",
    [
        "Git",  # the case-folded spelling the unconditional emit added
        "Git.exe",  # and the `.exe` spelling, which a predicate that short-circuits on it still leaks
    ],
)
@pytest.mark.parametrize(
    "shadow_verb",
    [
        "switch",  # the same verb as the hijack below
        "clean",  # any gated verb captures the record -- it need not be a hijack verb
    ],
)
def test_a_quoted_git_path_on_an_earlier_line_does_not_shadow_a_hijack(
    repo: SimpleNamespace, leaf: str, shadow_verb: str
) -> None:
    """MEASURED main=DENY, unconditional-emit=ALLOW, this build=DENY, over the real hook.

    The two parametrised axes are not thoroughness. ``leaf`` separates a position predicate that governs
    every spelling from one that short-circuits on ``.exe`` -- the latter closes the first row and
    leaves the second ALLOWing, which is exactly the shape a reader would call fixed. ``shadow_verb``
    proves the capture is of the RECORD and not of a matching verb pair.
    """
    command = f'cp -r "/c/backups/{leaf}" {shadow_verb}\ngit switch {repo.other}'
    reason = assert_denied(run_gate(shell(command, cwd=repo.wt), repo.repos))
    assert "LINKED WORKTREE" in reason, (
        "the deny must be rule 3b judging the hijack on line two, not some other rule objecting to "
        f"line one -- otherwise this test would stay green over the shadow. Reason was: {reason}"
    )


def test_the_shadow_probe_is_discriminating(repo: SimpleNamespace) -> None:
    """CONTROLS for the test above, and it needs three of them.

    Without these the shadow rows would pass against a gate that denied any two-line command, any
    command mentioning a directory called Git, or the hijack line on its own regardless of context.
    """
    # ONE: the hijack alone denies, so the ALLOW the shadow produced came from the ADDED line.
    assert_denied(run_gate(shell(f"git switch {repo.other}", cwd=repo.wt), repo.repos))
    # TWO: a leaf that does not end in a git token never emitted one, so it never shadowed -- and this
    # row denies under the unconditional emit too. It separates "the emit" from "an extra line".
    assert_denied(
        run_gate(
            shell(f'cp -r "/c/backups/GitHub" switch\ngit switch {repo.other}', cwd=repo.wt),
            repo.repos,
        )
    )
    # THREE: the line that used to shadow must not now deny ON ITS OWN. If it did, the rows above
    # would be green for the wrong reason -- a false deny standing in for a repaired fail-open.
    assert run_gate(shell('cp -r "/c/backups/Git" switch', cwd=repo.wt), repo.repos) is None


def test_a_SAME_LINE_semicolon_compound_still_shadows_and_is_NOT_fixed_here(
    repo: SimpleNamespace,
) -> None:
    """A KNOWN OPEN RESIDUAL, asserted as ALLOW, and NOT an endorsement -- read before acting on it.

    ``Get-ScannableSegments`` splits on NEWLINES only, so a ``;`` compound is ONE segment, and
    ``Test-WorktreeHijack`` strips a segment up to its FIRST gated verb. So the shadow survives on one
    line, with or without any quoted path::

        cp -r "/c/backups/Git" switch ; git switch <free branch>     ALLOW
        git -C <ungoverned> clean -fd  NEWLINE  git switch <branch>  ALLOW  (no quoting at all)

    Both ALLOW on origin/main as well, so neither is introduced by the position predicate and neither
    is closed by it. This row exists because a shadow test written on ONE LINE would pass vacuously --
    it would be measuring the segment splitter, not the emit -- and the next person to write one needs
    to see that stated rather than rediscover it.

    WHEN THIS TEST REDS, somebody fixed rule 3b's first-verb capture. Delete the row; do not restore
    the ALLOW.
    """
    same_line = f'cp -r "/c/backups/Git" switch ; git switch {repo.other}'
    assert run_gate(shell(same_line, cwd=repo.wt), repo.repos) is None, (
        "the same-line shadow now DENIES. If you fixed rule 3b's first-verb capture deliberately, "
        "that is the intended outcome -- delete this test. Do NOT restore the ALLOW."
    )
    # The quoting-free twin, which proves the residual is the SEGMENT SPLIT and the first-verb capture
    # rather than anything Remove-QuotedSpans does.
    unquoted = f"git -C {repo.primary.parent} clean -fd\ngit switch {repo.other}"
    assert run_gate(shell(unquoted, cwd=repo.wt), repo.repos) is None
