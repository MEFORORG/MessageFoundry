"""The gate's own enforcement surface, and the shared git config that arms the commit gates.

Two holes with a shared shape: the thing doing the enforcing was not itself protected.

**Rule 1a.** The installed hook and its allowlist live OUTSIDE every governed root, so ``Test-Governed``
returned ``$null`` for them and rule 1 allowed an ``Edit`` to either. One line written to the allowlist
disarms the gate for every session on the machine, permanently and silently. The previous answer was that
the kill switch is "deliberately NOT named in the deny message" -- obscurity over a file one ``ls`` away.

**Rule 3c.** ``config`` changes no working tree, so the tree-swap verb list never saw it. Its blast radius
is larger than any tree swap: every worktree shares one ``.git``, so ``git config core.hooksPath`` run in
any of them disables the ledger, claim and secret-leak commit gates for *all* of them at once, and nothing
reports that they stopped running.

Both rules are deliberately narrow, and half the tests below exist to keep them that way. A guard that
also blocks ordinary work gets routed around, and then it guards nothing.
"""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import assert_denied, edit, run_gate  # reuse the subprocess harness

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
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
def primary(tmp_path: Path) -> Path:
    return tmp_path / "Repo"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    """Stands in for ~/.claude/hooks/worktree-gate.repos.txt -- the real kill switch."""
    hooks = tmp_path / "hooks"
    hooks.mkdir()
    f = hooks / "worktree-gate.repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


# --------------------------------------------------------------- rule 1a: the gate's own surface


def test_writing_the_allowlist_is_denied(primary: Path, repos_file: Path) -> None:
    """The allowlist IS the kill switch: emptying it turns the gate off everywhere, immediately."""
    reason = assert_denied(run_gate(edit(repos_file, cwd=primary), repos_file))
    assert "kill switch" in reason
    assert "install-gate.ps1" in reason  # must point at the sanctioned route, not merely refuse


def test_writing_the_installed_gate_script_is_denied(primary: Path, repos_file: Path) -> None:
    installed = repos_file.parent / "worktree_gate.ps1"
    assert_denied(run_gate(edit(installed, cwd=primary), repos_file))


def test_rule_1a_fires_from_a_worktree_too(tmp_path: Path, repos_file: Path) -> None:
    """It keys on the TARGET, like every other write rule -- where the session sits is irrelevant."""
    assert_denied(run_gate(edit(repos_file, cwd=tmp_path / "Repo-alerts"), repos_file))


def test_a_neighbouring_file_in_the_same_directory_is_not_gate_surface(
    primary: Path, repos_file: Path
) -> None:
    """The rule matches two exact FILES, never their parent. Keying on the directory was wrong twice:
    the allowlist path is a parameter that can point anywhere (under test it lands in a temp dir, where a
    directory rule swallowed every unrelated path and failed seven tests), and the real ~/.claude/hooks/
    holds unrelated things this rule has no business governing."""
    assert run_gate(edit(repos_file.parent / "notes.md", cwd=primary), repos_file) is None
    assert run_gate(edit(repos_file.parent / "leases" / "x.json", cwd=primary), repos_file) is None


def test_the_repos_source_script_is_not_gate_surface(tmp_path: Path, repos_file: Path) -> None:
    """Editing the gate AT SOURCE is the sanctioned way to change a rule -- that is what the deny message
    tells you to do, so it must not itself be blocked."""
    src = tmp_path / "Repo-work" / "scripts" / "hooks" / "worktree_gate.ps1"
    assert run_gate(edit(src, cwd=tmp_path / "Repo-work"), repos_file) is None


def test_rule_1a_is_off_when_the_gate_is_off(primary: Path, tmp_path: Path) -> None:
    """The kill switch still wins. An empty allowlist means nothing is governed, including this rule."""
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing\n", encoding="utf-8")
    assert run_gate(edit(empty, cwd=primary), empty) is None


# --------------------------------------------------------------- rule 3c: the shared git config


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A REAL governed repo + a linked worktree. 3c asks git for the common dir, so it needs both."""
    if shutil.which("git") is None:
        pytest.skip("needs git on PATH")

    def git(*args: str, cwd: Path | None = None) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
        )

    primary = tmp_path / "Primary"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    wt = tmp_path / "Primary-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)
    # A SECOND registered worktree, used by the rule-3d rows as the session cwd. It matters that this
    # is a real worktree and not a bare directory: from outside any repository `git worktree remove`
    # exits "fatal: not a git repository", so a row driven from there pins the VERDICT and never the
    # CONSEQUENCE -- it would pass equally against a rule that could not reach the victim at all.
    other = tmp_path / "Primary-other"
    git("worktree", "add", "-b", "other-branch", str(other), cwd=primary)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, other=other, repos=repos)


@pytest.mark.parametrize(
    "command",
    [
        "git config core.hooksPath /dev/null",
        "git config --local core.hooksPath nowhere",
        "git config core.worktree ../elsewhere",
        "git config alias.ci 'commit --no-verify'",
        "git -c core.hooksPath=/dev/null commit -m x",
        "git config include.path ../evil",
    ],
)
def test_disarming_the_shared_config_is_denied_in_the_primary(
    repo: SimpleNamespace, command: str
) -> None:
    reason = assert_denied(run_gate(shell(command, cwd=repo.primary), repo.repos))
    assert "SHARED git configuration" in reason


def test_disarming_from_a_LINKED_WORKTREE_is_denied_too(repo: SimpleNamespace) -> None:
    """The crux. Test-Governed EXEMPTS a linked worktree, and for tree swaps that is right -- a worktree
    is not the primary. For config it is exactly wrong: the write lands in the SHARED config and harms
    every sibling. 3c asks git for the common dir instead of reusing that exemption."""
    reason = assert_denied(
        run_gate(shell("git config core.hooksPath /dev/null", cwd=repo.wt), repo.repos)
    )
    assert "SHARED git configuration" in reason


@pytest.mark.parametrize(
    "command",
    [
        "git config user.email me@example.com",
        "git config --get core.hooksPath",
        "git config --list",
        "git config --get-all remote.origin.fetch",
        "git config pull.rebase true",
        "git config --show-origin core.hooksPath",
    ],
)
def test_ordinary_and_read_only_config_is_untouched(repo: SimpleNamespace, command: str) -> None:
    """Narrowness is the feature. Reading the dangerous key is not setting it, and everything off the
    disarm list is ordinary repo setup that must not need a workaround."""
    assert run_gate(shell(command, cwd=repo.primary), repo.repos) is None


def test_config_in_an_ungoverned_repo_is_untouched(tmp_path: Path, repo: SimpleNamespace) -> None:
    other = tmp_path / "Unrelated"
    other.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(other)], check=True, capture_output=True)
    assert run_gate(shell("git config core.hooksPath /dev/null", cwd=other), repo.repos) is None


def test_a_non_repo_cwd_fails_open(tmp_path: Path, repo: SimpleNamespace) -> None:
    """`rev-parse --git-common-dir` fails outside a repo, and every git failure must ALLOW -- a guardrail
    that wedges on an unexpected shape gets uninstalled."""
    plain = tmp_path / "NotARepo"
    plain.mkdir()
    assert run_gate(shell("git config core.hooksPath /dev/null", cwd=plain), repo.repos) is None


# --------------------------------------------- rule 3c: the PATH TOKEN, not just the cwd (BACKLOG #1061)
#
# Every test above issues a BARE `git config` with no path token, so not one of them could fail on a
# path-token defect -- and one shipped: a RELATIVE target was allowed while the identical ABSOLUTE one was
# denied. What follows is at least the asymmetry set (BACKLOG #1000): a negative control has to fail for
# exactly the shapes its rule covers and keep passing for the shapes another layer catches, or it cannot
# tell you which layer is doing the work. Absolute denies before and after; relative denied only after;
# a linked-worktree target denies before AND after, which is what makes this a correction and not a
# widening. Each was confirmed FAILING/PASSING as stated against the pre-fix gate.


def test_an_ABSOLUTE_path_target_is_denied(repo: SimpleNamespace) -> None:
    """Control, one half of the pair. This spelling already denied, and it must go on denying -- without
    it the relative case below cannot distinguish "the fix works" from "the rule now denies everything"."""
    reason = assert_denied(
        run_gate(
            shell(f'git -C "{repo.primary}" config core.hooksPath /dev/null', cwd=repo.wt),
            repo.repos,
        )
    )
    assert "SHARED git configuration" in reason


@pytest.mark.parametrize(
    "command",
    [
        "git -C ../Primary config core.hooksPath /dev/null",
        "git -C ../Primary config core.worktree ../elsewhere",
        "git -C ../Primary -c core.hooksPath=/dev/null commit -m x",
        "cd ../Primary && git config core.hooksPath /dev/null",
        "cd ../Primary && git config alias.ci 'commit --no-verify'",
    ],
)
def test_a_RELATIVE_path_target_is_denied_too(repo: SimpleNamespace, command: str) -> None:
    """The defect (BACKLOG #1061). Same command, same target, different spelling -- and it was ALLOWED.

    `rev-parse --git-common-dir` answers relative to the TARGET, so from the primary it returns the bare
    string `.git`; the rule then canonicalised that against the target token AS WRITTEN, GetFullPath
    refused a non-fully-qualified base, and the empty result matched no governed root and fell through to
    allow. `../Primary` (or `../../..` from a nested worktree) is simply how a session names the repo root:
    no shell variable, no intent, and it disarms the ledger, claim and secret-leak commit gates for every
    worktree at once. Both spellings that reach the resolver are swept -- `-C` and the `cd <rel> &&`
    prefix -- because the rule reads whichever one produced the target."""
    reason = assert_denied(run_gate(shell(command, cwd=repo.wt), repo.repos))
    assert "SHARED git configuration" in reason


def test_a_LINKED_WORKTREE_target_keeps_denying(repo: SimpleNamespace) -> None:
    """Control, the other half: the fix must be a CORRECTION, not a widening.

    A linked worktree answers `--git-common-dir` with an ABSOLUTE path, so this case never went through
    the hole and denied on its own. If the two above start denying and this one stops, the rule has been
    rewritten rather than repaired. Stated with an ABSOLUTE target on purpose -- see the relative sibling
    below for why that distinction is load-bearing here."""
    reason = assert_denied(
        run_gate(
            shell(f'git -C "{repo.wt}" config core.hooksPath /dev/null', cwd=repo.primary),
            repo.repos,
        )
    )
    assert "SHARED git configuration" in reason


def test_a_relative_LINKED_WORKTREE_target_is_denied_as_well(repo: SimpleNamespace) -> None:
    """The second, quieter half of the same defect: `& git -C <relative>` resolved against THIS HOOK
    PROCESS's cwd, which is not the session's. `run_gate` passes no `cwd=`, so the hook inherits pytest's
    -- exactly the divergence a real session can also produce -- git exits 128 on the unresolvable path,
    and the `$LASTEXITCODE -ne 0` fail-open swallowed it. The verdict therefore depended on where the hook
    process happened to be started, which is the same unfalsifiable green the defect hid behind. Rooting
    the target against the session cwd before the `git -C` removes that dependence entirely."""
    reason = assert_denied(
        run_gate(
            shell("git -C ../Primary-wt config core.hooksPath /dev/null", cwd=repo.primary),
            repo.repos,
        )
    )
    assert "SHARED git configuration" in reason


@pytest.mark.parametrize(
    "command",
    [
        "git -C ../Primary config user.email me@example.com",
        "git -C ../Primary config --get core.hooksPath",
        "git -C ../Primary config --list",
    ],
)
def test_a_relative_target_does_not_widen_the_key_list(repo: SimpleNamespace, command: str) -> None:
    """Narrowness survives the fix. Resolving the path decides WHICH repo is being configured; it must not
    decide WHICH KEYS are refused. Ordinary setup and reads stay allowed in the new spelling too."""
    assert run_gate(shell(command, cwd=repo.wt), repo.repos) is None


def test_a_relative_target_in_an_UNGOVERNED_repo_is_untouched(
    tmp_path: Path, repo: SimpleNamespace
) -> None:
    """Resolving the path must not turn every relative target into a deny: an unrelated repo named
    relatively is still an unrelated repo."""
    other = tmp_path / "Unrelated"
    other.mkdir()
    subprocess.run(["git", "init", "-b", "main", str(other)], check=True, capture_output=True)
    assert (
        run_gate(
            shell("git -C ../Unrelated config core.hooksPath /dev/null", cwd=repo.wt), repo.repos
        )
        is None
    )


def test_a_relative_target_that_is_NOT_A_REPO_still_fails_open(
    tmp_path: Path, repo: SimpleNamespace
) -> None:
    """The git-failure contract, restated for the path token. `test_a_non_repo_cwd_fails_open` pins it for
    the cwd; the fix added a second failure condition beside it, so pin this one explicitly or the two
    become indistinguishable. Here git ANSWERS -- the resolved path is not a repository -- and an answer of
    "not a repo" must allow."""
    plain = tmp_path / "NotARepo"
    plain.mkdir()
    assert (
        run_gate(
            shell("git -C ../NotARepo config core.hooksPath /dev/null", cwd=repo.wt), repo.repos
        )
        is None
    )


def test_a_target_that_cannot_be_RESOLVED_fails_closed(repo: SimpleNamespace) -> None:
    """The other branch, and it must be the OPPOSITE one. A relative target rooted against a cwd that is
    itself not absolute cannot be resolved at all -- git has not been asked anything, so nothing has said
    this is or is not a governed repo. Treating that silence as "not governed" is precisely how the defect
    above shipped, so it denies. Pinned as its own test because the pair only means something if both
    branches are reachable and different: this one DENIES where the test above ALLOWS, on inputs that
    differ solely in whether the path could be resolved."""
    reason = assert_denied(
        run_gate(
            shell("git -C ../Primary config core.hooksPath /dev/null", cwd="relative/cwd"),
            repo.repos,
        )
    )
    assert "could not be resolved" in reason


# --------------------------------------------------------------- rule 3d: destroying another worktree


def test_removing_another_sessions_worktree_is_denied(repo: SimpleNamespace) -> None:
    """Every other rule protects a tree from being SWAPPED. This one protects it from being DELETED,
    which is strictly worse and was entirely unguarded: `git worktree remove` takes the directory and its
    branch with any uncommitted work in them, and the session using it finds out when its next read
    fails. The verb list could never have caught it -- `worktree remove` is two tokens where every other
    entry is one."""
    reason = assert_denied(
        run_gate(shell(f'git worktree remove "{repo.wt}"', cwd=repo.primary), repo.repos)
    )
    assert "prune-merged.ps1" in reason  # offer the maintenance path, do not merely refuse
    # It must NOT assert the tree belongs to another session (BACKLOG #1041). The rule has no occupancy
    # or authorship signal, so that was an unverified claim -- and it was FALSE for a caller acting on a
    # worktree nobody was using. Refusing without knowing is correct; saying you know is not.
    assert "ANOTHER SESSION" not in reason
    assert "NOT the tree" in reason
    assert "cannot tell" in reason


def test_removing_your_own_worktree_is_not_blamed_on_another_session(
    repo: SimpleNamespace,
) -> None:
    """BACKLOG #1041. Reproduced live before it was filed: a session standing in a linked worktree ran
    `git worktree remove <that same path>` and was told the tree belonged to ANOTHER SESSION, then sent
    to confirm with a colleague who does not exist.

    The old justification was that git refuses to remove the worktree you are standing in, so anything
    reaching git must be aimed elsewhere. A PreToolUse hook decides whether anything reaches git AT ALL,
    so that refusal never happens and the premise is never tested. The decision to deny is still right --
    only the reason was false."""
    reason = assert_denied(
        run_gate(shell(f'git worktree remove "{repo.wt}"', cwd=repo.wt), repo.repos)
    )
    assert "ANOTHER SESSION" not in reason
    assert "THE WORKTREE THIS SESSION IS RUNNING IN" in reason
    # The old remedy sent the reader to confirm the tree was not in use -- verifying a falsehood.
    assert "not in use" not in reason


def test_the_self_check_does_not_leak_into_the_sibling_case(repo: SimpleNamespace) -> None:
    """Non-vacuity for the pair above: the two branches must be reachable and DIFFERENT.

    A self-check that fired for every path would make the sibling deny unreachable and quietly stop
    protecting other sessions' trees -- the failure this rule exists to prevent."""
    own = assert_denied(
        run_gate(shell(f'git worktree remove "{repo.wt}"', cwd=repo.wt), repo.repos)
    )
    sibling = assert_denied(
        run_gate(shell(f'git worktree remove "{repo.wt}"', cwd=repo.primary), repo.repos)
    )
    assert own != sibling
    assert "THE WORKTREE THIS SESSION IS RUNNING IN" in own
    assert "THE WORKTREE THIS SESSION IS RUNNING IN" not in sibling


def test_force_removing_and_moving_are_denied_too(repo: SimpleNamespace) -> None:
    assert_denied(
        run_gate(shell(f'git worktree remove --force "{repo.wt}"', cwd=repo.primary), repo.repos)
    )
    assert_denied(
        run_gate(shell(f'git worktree move "{repo.wt}" ../elsewhere', cwd=repo.primary), repo.repos)
    )


def test_reading_the_worktree_list_is_untouched(repo: SimpleNamespace) -> None:
    """`worktree list` is how you find out whether one is in use -- the deny message recommends it, so it
    must not itself be blocked."""
    assert run_gate(shell("git worktree list", cwd=repo.primary), repo.repos) is None
    assert run_gate(shell("git worktree list --porcelain", cwd=repo.primary), repo.repos) is None


def test_adding_a_worktree_is_untouched(repo: SimpleNamespace, tmp_path: Path) -> None:
    """Creating one is the sanctioned path out of every other deny in this file."""
    assert (
        run_gate(
            shell(f"git worktree add {tmp_path / 'New'} -b newbranch", cwd=repo.primary), repo.repos
        )
        is None
    )


def test_removing_a_worktree_of_an_UNGOVERNED_repo_is_allowed(
    tmp_path: Path, repo: SimpleNamespace
) -> None:
    other = tmp_path / "Unrelated"
    subprocess.run(["git", "init", "-b", "main", str(other)], check=True, capture_output=True)
    subprocess.run(
        ["git", "-C", str(other), "config", "user.email", "t@e.com"],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        ["git", "-C", str(other), "config", "user.name", "t"], check=True, capture_output=True
    )
    (other / "s.txt").write_text("s", encoding="utf-8")
    subprocess.run(["git", "-C", str(other), "add", "-A"], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(other), "commit", "-m", "s"], check=True, capture_output=True)
    owt = tmp_path / "Unrelated-wt"
    subprocess.run(
        ["git", "-C", str(other), "worktree", "add", "-b", "b", str(owt)],
        check=True,
        capture_output=True,
    )
    assert run_gate(shell(f'git worktree remove "{owt}"', cwd=other), repo.repos) is None


def test_a_nonexistent_path_fails_open(repo: SimpleNamespace, tmp_path: Path) -> None:
    """git cannot classify a path that is not a worktree, and every git failure must ALLOW."""
    assert (
        run_gate(shell(f'git worktree remove "{tmp_path / "nope"}"', cwd=repo.primary), repo.repos)
        is None
    )


# ------------------------------------------------- rule 3d: WHICH path, and resolved against WHAT
#
# BACKLOG #1064. Two independent defects, and closing either alone leaves the other open.
#
#   A. THE VICTIM TOKEN IS PICKED BY A SPLIT THAT CANNOT READ QUOTES. `$after -split '\s+'` then
#      `.Trim('"', "'")`. A quoted path containing a space becomes two tokens, the first is taken,
#      the quotes are trimmed, `git -C` fails on the truncated path, and the rule falls through to
#      ALLOW. Quoting does not help, because the tokeniser never reads the quotes.
#
#   B. THE VICTIM IS RESOLVED AGAINST THE WRONG DIRECTORY. git resolves a relative path against the
#      EFFECTIVE working directory, which a `-C` flag or a prefix `cd` changes. Rule 3d resolved it
#      against the hook process's cwd; the rejected `g1064` attempt changed that to the SESSION cwd,
#      which is also wrong. Those two answers COINCIDE when the session cwd happens to sit at the
#      same depth under the same parent as the `-C` target -- which is the ordinary sibling-worktree
#      shape, so a rig built that way reports a broken fix as working. The same-depth row is kept
#      below and LABELLED BLIND for exactly that reason.
#
# Every case here carries a CONTROL that must hold. A control that does not hold undermines
# everything measured beside it, and the `g1064` attempt broke its own.


@pytest.fixture
def spaced_repo(tmp_path: Path) -> SimpleNamespace:
    """The same rig as :func:`repo`, differing in ONE character: a space in the repo's leaf name.

    A path with a space is ordinary on Windows. This defect is latent on this machine only because
    the primary checkout happens to have no space in its path, and "latent because of an accident of
    this machine's paths" is an unexercised precondition, not a mitigation.
    """
    if shutil.which("git") is None:
        pytest.skip("needs git on PATH")

    def git(*args: str, cwd: Path | None = None) -> None:
        subprocess.run(
            ["git", *args],
            cwd=str(cwd) if cwd else None,
            check=True,
            capture_output=True,
            text=True,
        )

    primary = tmp_path / "Pri mary"
    git("init", "-b", "main", str(primary))
    git("config", "user.email", "t@example.com", cwd=primary)
    git("config", "user.name", "t", cwd=primary)
    (primary / "seed.txt").write_text("seed\n", encoding="utf-8")
    git("add", "-A", cwd=primary)
    git("commit", "-m", "seed", cwd=primary)
    wt = tmp_path / "Pri mary-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    # THE SESSION CWD IS A SECOND REGISTERED WORKTREE, not a bare directory, so the command each row
    # models is one git would really execute. From a cwd outside any repository `git worktree remove`
    # exits "fatal: not a git repository", and a row driven from there pins the VERDICT while never
    # pinning the CONSEQUENCE -- it would pass just as happily against a rule that could not reach the
    # victim at all. From here the same command really would destroy the victim tree.
    foreign = tmp_path / "Pri mary-other"
    git("worktree", "add", "-b", "other-branch", str(foreign), cwd=primary)
    return SimpleNamespace(primary=primary, wt=wt, repos=repos, foreign=foreign)


@pytest.mark.parametrize(
    "spelling",
    [
        'git worktree remove "{wt}"',
        "git worktree remove '{wt}'",
        'git -C "{primary}" worktree remove "{wt}"',
        'git worktree move "{wt}" ../elsewhere',
    ],
)
def test_a_victim_path_containing_a_space_is_still_governed(
    spaced_repo: SimpleNamespace, spelling: str
) -> None:
    """DEFECT A. Measured before the fix: every one of these ALLOWed, and the identical rig with the
    space removed DENIED all of them -- so the space is the whole cause and nothing else varied."""
    command = spelling.format(wt=spaced_repo.wt, primary=spaced_repo.primary)
    assert_denied(run_gate(shell(command, cwd=spaced_repo.foreign), spaced_repo.repos))


@pytest.mark.parametrize(
    "spelling",
    [
        'git worktree remove "{wt}"',
        "git worktree remove '{wt}'",
        'git -C "{primary}" worktree remove "{wt}"',
        'git worktree move "{wt}" ../elsewhere',
    ],
)
def test_the_no_space_control_denies_the_same_spellings(
    repo: SimpleNamespace, tmp_path: Path, spelling: str
) -> None:
    """THE CONTROL for the test above, and it is the reason that one means anything.

    It is the same four spellings against a rig whose only difference is the absent space. If this
    ever reds, the test above is measuring something other than the space and its result must not be
    trusted."""
    foreign = repo.other
    command = spelling.format(wt=repo.wt, primary=repo.primary)
    assert_denied(run_gate(shell(command, cwd=foreign), repo.repos))


@pytest.fixture
def cwd_positions(tmp_path: Path) -> SimpleNamespace:
    """Three session cwds. Only two of them can discriminate a correct fix from a broken one."""
    same_depth = tmp_path / "SameDepth"
    deeper = tmp_path / "Elsewhere" / "deep" / "deeper"
    other_parent = tmp_path / "Other" / "branch"
    for p in (same_depth, deeper, other_parent):
        p.mkdir(parents=True, exist_ok=True)
    return SimpleNamespace(same_depth=same_depth, deeper=deeper, other_parent=other_parent)


@pytest.mark.parametrize("position", ["same_depth", "deeper", "other_parent"])
@pytest.mark.parametrize(
    "spelling",
    [
        'git -C "{primary}" worktree remove ../Primary-wt',
        'cd "{primary}" && git worktree remove ../Primary-wt',
    ],
)
def test_a_relative_victim_resolves_against_the_effective_directory(
    repo: SimpleNamespace, cwd_positions: SimpleNamespace, position: str, spelling: str
) -> None:
    """DEFECT B, and the parametrisation is the point.

    Both spellings move git's working directory -- one with `-C`, one with a prefix `cd` -- so
    `../Primary-wt` names the governed worktree in every row. The rule must therefore deny from ALL
    THREE session positions, because where the SESSION stands has nothing to do with where GIT will
    stand.

    ``same_depth`` is the BLIND row: there the session cwd and the `-C` target share a parent, so
    resolving against either gives the same answer and the row passes even on a gate that resolves
    against the wrong one. It is kept because it is the row that looks like a fix -- a rig built only
    from sibling worktrees, which is the ordinary shape here, would consist entirely of blind rows.
    ``deeper`` and ``other_parent`` are the rows that discriminate."""
    command = spelling.format(primary=repo.primary)
    cwd = getattr(cwd_positions, position)
    assert_denied(run_gate(shell(command, cwd=cwd), repo.repos))


@pytest.mark.parametrize("trailer", ['""', "''", '"', "'"])
def test_a_quote_glued_to_the_victim_path_does_not_disarm_the_rule(
    repo: SimpleNamespace, tmp_path: Path, trailer: str
) -> None:
    """A REGRESSION THIS LANE INTRODUCED AND THEN CLOSED. Pinned so it cannot come back.

    The quote-aware scan replaced a ``.Trim('"', "'")``, and its first bare alternative was
    ``[^\\s"'][^\\s]*`` -- a tail that ADMITS quote characters. So ``git worktree remove <path>""``
    carried the trailing quotes into the token, ``git -C`` failed on the malformed path, and the rule
    fell through to ALLOW: the exact fail-open the quote-awareness was added to close, reintroduced
    by the fix for it.

    Measured across three gate versions, which is what separates a regression from an inherited
    defect: main DENY, the parent commit DENY, and the fix-before-this-correction ALLOW. The whole
    gate suite was blind to it, which is why this is a row and not a comment.
    """
    foreign = repo.other
    assert_denied(
        run_gate(shell(f"git worktree remove {repo.wt}{trailer}", cwd=foreign), repo.repos)
    )


@pytest.mark.parametrize(
    "command",
    [
        'git worktree remove "--force" "{wt}"',
        "git worktree remove '--force' '{wt}'",
        'git worktree remove "-f" "{wt}"',
    ],
)
def test_a_QUOTED_flag_is_skipped_like_an_unquoted_one(
    repo: SimpleNamespace, tmp_path: Path, command: str
) -> None:
    """INHERITED, not a regression -- and the note claiming otherwise was itself the defect.

    The flag skip tested ``$m.Value``, the RAW match text. A quoted flag begins with the quote
    character, so ``"--force"`` was never skipped and became the victim path. It ALLOWed on main and
    on the parent too, so this closes a pre-existing hole rather than a regression -- but the fix's
    own comment said the scan had been "validated against the flag", and only the UNQUOTED spelling
    had been. The skip now tests the CAPTURED value.
    """
    foreign = repo.other
    assert_denied(run_gate(shell(command.format(wt=repo.wt), cwd=foreign), repo.repos))


def test_the_victim_is_folded_before_it_reaches_the_deny_reason(
    repo: SimpleNamespace, tmp_path: Path
) -> None:
    """PINS THE FOLD, which until now was asserted by review alone.

    A mutant setting ``$victimMsg = $victimRaw`` passed every test in this section AND the whole
    thirteen-file gate suite, so the fold was entirely unguarded. Get-SafeForMessage exists because a
    deny REASON is an instruction an agent acts on and it carries a literal command block: a tab or
    newline smuggled into an interpolated value can forge a second "Do this instead:" block that a
    model reading top-down reaches first.

    A newline cannot arrive here -- segments are split per line above -- so the reachable character is
    the TAB, and the quoted branch of the victim scan admits one where the old whitespace split could
    not.
    """
    foreign = repo.other
    # A quoted victim carrying a TAB, which resolves via `..` back to the real worktree so the rule
    # still fires and still interpolates the operator's spelling into the reason.
    victim = f"{repo.wt}\t/../{repo.wt.name}"
    reason = assert_denied(
        run_gate(shell(f'git worktree remove "{victim}"', cwd=foreign), repo.repos)
    )
    assert "\t" not in reason, (
        "the victim path reached the deny reason unfolded -- a tab survived. Route it through "
        "Get-SafeForMessage; a reason is an instruction, not a log line."
    )


@pytest.mark.parametrize(
    "command",
    [
        'p="{wt}"; git worktree remove "$p"',
        'p=../Primary-wt; git worktree remove "$p"',
    ],
)
def test_indirection_through_a_shell_variable_is_a_KNOWN_open_residual(
    repo: SimpleNamespace, tmp_path: Path, command: str
) -> None:
    """A PINNED RESIDUAL, asserting ALLOW, and that is NOT an endorsement.

    The victim token here is ``$p``. Its value is a runtime fact, and this hook inspects a tool
    ARGUMENT before anything runs -- no static resolver can follow it, and the gate's own .SYNOPSIS
    already says it is a guardrail rather than a security boundary. So this is a limit of the shape,
    not an oversight, and the #1064 fix does not close it.

    It is pinned because the alternative is silence, and silence reads as coverage. If this ever
    reds, somebody taught the gate to follow a variable: delete this test and the residual note in
    the gate. Do NOT restore the ALLOW."""
    foreign = repo.other
    assert run_gate(shell(command.format(wt=repo.wt), cwd=foreign), repo.repos) is None, (
        "indirection now DENIES. If that was deliberate, delete this test and the residual note in "
        "the gate; do not restore the ALLOW to make it pass."
    )
