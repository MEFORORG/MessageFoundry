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
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, repos=repos)


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
