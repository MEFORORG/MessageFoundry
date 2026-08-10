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

import json
import shutil
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest

from tests.test_worktree_gate import (  # reuse the subprocess harness
    GATE,
    assert_denied,
    edit,
    run_gate,
)

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

# The script under test must be THIS checkout's. ``GATE`` is imported from a sibling module, and pytest
# resolves ``tests.`` against whatever is first on ``sys.path`` -- which, when it is launched from one
# worktree with a test path in another, is the OTHER worktree's package. Measured during this file's own
# red-first A/B: every case then drove an untouched copy of the gate and reported a failure identical in
# shape to the defect being fixed. A manufactured red is worse than no measurement, because it is
# indistinguishable from a real one. Assert the instrument before trusting anything it says.
assert GATE.resolve().parents[2] == Path(__file__).resolve().parents[1], (
    f"the gate under test ({GATE}) does not belong to this checkout "
    f"({Path(__file__).resolve().parents[1]}) -- run pytest FROM the worktree you are measuring"
)


def shell(command: str, cwd: Path | str, tool: str = "Bash") -> dict[str, Any]:
    return {
        "session_id": "s-1",
        "cwd": str(cwd),
        "hook_event_name": "PreToolUse",
        "tool_name": tool,
        "tool_input": {"command": command},
    }


def run_gate_in(
    payload: dict[str, Any], repos_file: Path, hook_cwd: Path | str
) -> dict[str, Any] | None:
    """``run_gate``, with the HOOK PROCESS's own cwd pinned explicitly.

    ``run_gate`` passes no ``cwd=``, so the hook inherits pytest's -- an ambient value nobody states and
    which is not what production supplies. That is not a hypothetical nuisance: rules 3b and 3d resolve a
    relative token against the process cwd, so the same payload measures ALLOW or DENY depending on where
    the runner was launched, and one earlier finding in this cluster was retracted for exactly that.

    A green that depends on an unstated ambient value is not a green. Every case below that could be
    sensitive to it therefore says where the hook stands, and
    :func:`test_rule_3c_is_invariant_to_where_the_HOOK_PROCESS_stands` proves the invariance rather than
    assuming it, by re-running a deny and an allow under a deliberately hostile value.
    """
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(GATE),
            "-ReposFile",
            str(repos_file),
        ],
        input=json.dumps(payload),
        capture_output=True,
        text=True,
        timeout=120,
        cwd=str(hook_cwd),
    )
    assert proc.returncode == 0, f"gate exited {proc.returncode}: {proc.stderr}"
    if not proc.stdout.strip():
        return None
    decision: dict[str, Any] = json.loads(proc.stdout)
    return decision


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


# ------------------------------------- rule 3c: a target spelled through a JUNCTION (BACKLOG #1061)
#
# The filed relative-path spelling was closed by rooting the token against the session cwd. That fix
# cannot see a path ALIAS: `[IO.Path]::GetFullPath` does not traverse a reparse point, so a junction
# naming the primary rooted to a real-looking path that matched no governed root. The gate now asks git
# for the common dir ALREADY ABSOLUTE (`--path-format=absolute`), and git de-aliases it itself.
#
# Windows-only by construction -- a junction is a Windows object. Skipped elsewhere rather than faked,
# because a fake would test the fake.


@pytest.fixture
def junctions(repo: SimpleNamespace, tmp_path: Path) -> SimpleNamespace:
    """A junction onto the GOVERNED primary and one onto an UNGOVERNED repo -- the asymmetry pair."""
    if sys.platform != "win32":
        pytest.skip("junctions are a Windows object")
    other = tmp_path / "Unrelated"
    subprocess.run(["git", "init", "-b", "main", str(other)], check=True, capture_output=True)
    gov = tmp_path / "JunctionToPrimary"
    ung = tmp_path / "JunctionToUnrelated"
    for link, target in ((gov, repo.primary), (ung, other)):
        p = subprocess.run(
            ["cmd", "/c", "mklink", "/J", str(link), str(target)], capture_output=True, text=True
        )
        if p.returncode != 0 or not link.is_dir():
            pytest.skip(f"could not create a junction: {p.stdout.strip()} {p.stderr.strip()}")
        # Non-vacuity, and it earned its place: a junction that does not resolve makes the gate ALLOW,
        # which is the SAME observation as the defect. Without this, a broken fixture and an unfixed gate
        # are indistinguishable, and one of them is a false report. Assert the premise the case rests on
        # -- git itself sees the real repository through the link -- before any verdict is read from it.
        seen = subprocess.run(
            ["git", "-C", str(link), "rev-parse", "--path-format=absolute", "--git-common-dir"],
            capture_output=True,
            text=True,
        )
        assert seen.returncode == 0, f"git cannot read through the junction {link}: {seen.stderr}"
        assert Path(seen.stdout.strip()).parent.resolve() == target.resolve(), (
            f"the junction {link} does not resolve to {target}: git says {seen.stdout.strip()}"
        )
    return SimpleNamespace(governed=gov, ungoverned=ung)


def test_a_JUNCTION_spelled_target_is_denied(
    repo: SimpleNamespace, junctions: SimpleNamespace
) -> None:
    """The defect. Measured ALLOW on the pre-fix gate: `rev-parse --git-common-dir` answers the bare
    string `.git` from a main working tree, GetFullPath composed that onto the JUNCTION's path rather
    than the real one, and the result matched no governed root. Hook process stands in the linked
    worktree, which is where the payload says the session is."""
    result = run_gate_in(
        shell(f'git -C "{junctions.governed}" config core.hooksPath /dev/null', cwd=repo.wt),
        repo.repos,
        hook_cwd=repo.wt,
    )
    seen = subprocess.run(
        [
            "git",
            "-C",
            str(junctions.governed),
            "rev-parse",
            "--path-format=absolute",
            "--git-common-dir",
        ],
        capture_output=True,
        text=True,
    )
    assert result is not None, (
        "expected a DENY, got allow. Scanned:\n"
        f"  junction     : {junctions.governed}\n"
        f"  git says     : {seen.stdout.strip()!r} (rc={seen.returncode})\n"
        f"  allowlist    : {repo.repos.read_text(encoding='utf-8')!r}\n"
        f"  payload cwd  : {repo.wt}"
    )
    reason = assert_denied(result)
    assert "SHARED git configuration" in reason


def test_a_JUNCTION_to_an_UNGOVERNED_repo_is_still_allowed(
    repo: SimpleNamespace, junctions: SimpleNamespace
) -> None:
    """The other half, and the one that says this is a correction rather than "de-alias everything and
    deny". Asking git to resolve the alias must not make every junction governed."""
    assert (
        run_gate_in(
            shell(f'git -C "{junctions.ungoverned}" config core.hooksPath /dev/null', cwd=repo.wt),
            repo.repos,
            hook_cwd=repo.wt,
        )
        is None
    )


def test_rule_3c_is_invariant_to_where_the_HOOK_PROCESS_stands(
    repo: SimpleNamespace, tmp_path: Path
) -> None:
    """Non-vacuity for every cwd claim in this file: prove the invariance, do not assume it.

    Rule 3c roots its target against the PAYLOAD cwd before it shells out, so its verdict must not move
    when the hook process is started somewhere else. Both directions are re-run under a deliberately
    HOSTILE ambient value -- a directory that is not a repository and is not related to the rig -- so a
    green here cannot have been bought by the runner happening to stand in a helpful place."""
    hostile = tmp_path / "HostileAmbient"
    hostile.mkdir()
    deny = shell("git -C ../Primary config core.hooksPath /dev/null", cwd=repo.wt)
    allow = shell("git -C ../Primary config user.email me@example.com", cwd=repo.wt)
    for hook_cwd in (repo.wt, repo.primary, hostile):
        assert_denied(run_gate_in(deny, repo.repos, hook_cwd=hook_cwd))
        assert run_gate_in(allow, repo.repos, hook_cwd=hook_cwd) is None


# ------------------------------- rule 3c: one line is SEVERAL commands, and a SET of targets (#1065)
#
# The rule judged a whole line at once and then read candidate ``[0]`` of the target set. Three ordinary
# spellings walked through that, none of them needing intent:
#
#   * a ``-C`` belonging to a DIFFERENT command on the line became "the repository being configured".
#     ``-C HEAD`` is the reuse-that-commit's-message flag; ``git config alias.amend "commit -C HEAD"`` is
#     written on purpose by people with nothing to evade.
#   * a neighbouring READ armed the rule's own read exclusion for the write beside it.
#   * a ``--git-dir`` / ``--work-tree`` naming a governed repository sat in the TAIL of the candidate set
#     and was never looked at, although the resolver's contract says the caller must deny if ANY member
#     is governed and rule 3 had always done so.
#
# Fourteen deny cases, every one measured ALLOW on the committed gate first. The narrowness block below
# it is the other half: eleven cases that must stay ALLOW on both sides, plus the pre-existing denies
# which must keep denying, or this is a rewrite rather than a repair.

_DISARM = "core.hooksPath /nope"


@pytest.fixture
def ungoverned(tmp_path: Path) -> Path:
    """A real repository that is NOT on the allowlist. Half the cases here are about it staying that
    way: a rule that sees more targets must not therefore refuse more repositories."""
    other = tmp_path / "Unrelated"
    subprocess.run(["git", "init", "-b", "main", str(other)], check=True, capture_output=True)
    return other


def _nested_worktree(repo: SimpleNamespace) -> Path:
    """A worktree git NESTS under the primary (``.claude/worktrees/<name>``, the first-party mechanism).

    Built on demand rather than in the ``repo`` fixture: only a handful of cases need it, and every other
    test in this file would pay for it. It matters here because ``Test-Governed`` deliberately EXEMPTS
    this path shape -- and rule 3c must not inherit that exemption, since a nested worktree's config
    write lands in the same shared file as the primary's."""
    nested = repo.primary / ".claude" / "worktrees" / "nested"
    nested.parent.mkdir(parents=True, exist_ok=True)
    subprocess.run(
        ["git", "-C", str(repo.primary), "worktree", "add", "-b", "nested-b", str(nested)],
        check=True,
        capture_output=True,
    )
    return nested


@pytest.mark.parametrize(
    ("command", "cwd_key"),
    [
        (f"git commit -C HEAD && git config {_DISARM}", "primary"),
        (f"git config {_DISARM} && git commit -C HEAD", "primary"),
        (f"git config {_DISARM} ; git commit -C HEAD", "primary"),
        (f"git commit -C HEAD || git config {_DISARM}", "primary"),
        (f"git commit -C HEAD | git config {_DISARM}", "primary"),
        (f"git config --list && git config {_DISARM}", "primary"),
        (f"git config {_DISARM} && git config --list", "primary"),
        (f"git config --get core.hooksPath && git config {_DISARM}", "primary"),
        (f"git commit -C HEAD && git config {_DISARM}", "wt"),
        (f"git config --list && git config {_DISARM}", "nested"),
        ("git commit -C HEAD && git config alias.ci 'x'", "primary"),
        ("git commit -C HEAD && git -c core.hooksPath=/x commit -m y", "primary"),
        ("git --git-dir GOVERNED/.git config " + _DISARM, "other"),
        ("git --work-tree GOVERNED config " + _DISARM, "other"),
    ],
)
def test_a_disarm_beside_another_command_is_denied(
    repo: SimpleNamespace, ungoverned: Path, command: str, cwd_key: str
) -> None:
    """Every one of these was measured ALLOW on the committed gate. The hook process stands where the
    payload says the session does, which is what production supplies."""
    cwd = (
        _nested_worktree(repo)
        if cwd_key == "nested"
        else {"primary": repo.primary, "wt": repo.wt, "other": ungoverned}[cwd_key]
    )
    command = command.replace("GOVERNED", str(repo.primary))
    reason = assert_denied(run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd))
    assert "SHARED git configuration" in reason


@pytest.mark.parametrize(
    ("command", "cwd_key"),
    [
        ("git config --list", "primary"),
        ("git config --get core.hooksPath", "primary"),
        ("git commit -C HEAD", "primary"),
        ("git -C UNGOVERNED config " + _DISARM, "primary"),
        ("git -C ../Unrelated config " + _DISARM, "wt"),
        ("git config user.email a@b.c && git commit -m x", "primary"),
        (f"git config {_DISARM}", "other"),
        ("cd ../Unrelated && git config " + _DISARM, "primary"),
        ("git config --list && git config user.email a@b.c", "primary"),
        ('git commit -m "note about core.hooksPath and alias.x" ; git status', "primary"),
        ("git --git-dir UNGOVERNED/.git config " + _DISARM, "other"),
    ],
)
def test_splitting_the_line_does_not_widen_the_rule(
    repo: SimpleNamespace, ungoverned: Path, command: str, cwd_key: str
) -> None:
    """The narrowness half, and it is the half the previous four attempts at this rule failed.

    Judging each invocation separately and checking every candidate makes the rule see MORE; each of
    these proves it does not therefore deny more. All eleven are ALLOW on the committed gate and must
    stay ALLOW here -- a read on its own, a `-C` at an ungoverned repo, a disarm inside an ungoverned
    repo, a `cd` into one, and a commit message that merely mentions the keys."""
    cwd = {"primary": repo.primary, "wt": repo.wt, "other": ungoverned}[cwd_key]
    command = command.replace("UNGOVERNED", str(ungoverned))
    assert run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd) is None


@pytest.mark.parametrize(
    ("command", "cwd_key"),
    [
        (f"git config {_DISARM}", "primary"),
        (f"git config {_DISARM}", "wt"),
        ("git -C GOVERNED config " + _DISARM, "wt"),
        ("git -C ../Primary config " + _DISARM, "wt"),
        ("cd ../Primary && git config " + _DISARM, "wt"),
        ("git -c core.hooksPath=/dev/null commit -m x", "primary"),
        ("git config alias.ci 'commit --no-verify'", "primary"),
        ("git config include.path ../evil", "primary"),
    ],
)
def test_the_pre_existing_denies_survive_the_split(
    repo: SimpleNamespace, command: str, cwd_key: str
) -> None:
    """The regression guard. These eight DENY on the committed gate; if the split turned any of them into
    an allow, the rule would have been rewritten rather than repaired -- which is how every earlier
    attempt at this rule failed verification."""
    cwd = {"primary": repo.primary, "wt": repo.wt}[cwd_key]
    command = command.replace("GOVERNED", str(repo.primary))
    assert_denied(run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd))


# ------------------------- rule 3c: the argument reader, quotes and spaces included (BACKLOG #1066)
#
# Every path reader in the resolver was ``"?([^"\s]+)"?`` against the raw line: DOUBLE quotes only, and
# stopping at a SPACE. That is two fail-opens in one expression, and neither needs an unusual spelling --
# this file writes a single-quoted argument two lines from the case it is testing.
#
#   * a single-quoted token keeps its leading quote, so ``GetFullPath`` turns even an ABSOLUTE path into
#     a relative one and nothing matches a governed root;
#   * a governed root whose path contains a space is truncated away entirely.
#
# The option is now located in the length-preserving quote mask and its value read out of the raw text at
# the same offset. That also makes a ``-C`` inside a quoted VALUE inert, which closes the second spelling
# filed under #1065 -- the mask blanks it, so a config value carrying ``-C HEAD`` can no longer nominate
# HEAD as the repository being configured. The quoted-and-INERT case and the quoted-and-EXECUTED case
# stay distinct: an interpreter argument is recursed into by ``Get-ScannableSegments`` and comes back as
# its own unquoted line.


@pytest.fixture
def spaced_root(tmp_path: Path) -> SimpleNamespace:
    """A governed root whose path contains a SPACE.

    Named ``Zed Repo`` on purpose. With a root called ``Primary Two`` the truncated prefix
    ``<tmp>/Primary`` is ITSELF a governed root in this rig, so the case would deny for an accidental
    reason and read as the rule working. The fixture has to make the truncation actually miss."""
    root = tmp_path / "Zed Repo"
    subprocess.run(["git", "init", "-b", "main", str(root)], check=True, capture_output=True)
    repos = tmp_path / "spaced-repos.txt"
    repos.write_text(f"{root}\n", encoding="utf-8")
    return SimpleNamespace(root=root, repos=repos)


@pytest.mark.parametrize(
    ("command", "cwd_key"),
    [
        ("git -C '../Primary' config " + _DISARM, "wt"),
        ("git -C 'GOVERNED' config " + _DISARM, "wt"),
        ("cd '../Primary' && git config " + _DISARM, "wt"),
        ('git config core.hooksPath "/nope -C HEAD"', "primary"),
        ("git config core.hooksPath '/nope -C HEAD'", "primary"),
        ("git --git-dir 'GOVERNED/.git' config " + _DISARM, "other"),
        ('git --git-dir="GOVERNED/.git" config ' + _DISARM, "other"),
    ],
)
def test_a_quoted_target_is_read_rather_than_mangled(
    repo: SimpleNamespace, ungoverned: Path, command: str, cwd_key: str
) -> None:
    """All seven measured ALLOW on the committed gate. The last two of the first group are the
    value-embedded ``-C`` recorded under #1065: the flag sits INSIDE a quoted config value, git never
    sees it as a flag, and reading it as one made the rule inspect a repository the command never
    touches -- then allow, because that repository does not exist."""
    cwd = {"primary": repo.primary, "wt": repo.wt, "other": ungoverned}[cwd_key]
    command = command.replace("GOVERNED", str(repo.primary))
    reason = assert_denied(run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd))
    assert "SHARED git configuration" in reason


def test_a_governed_root_whose_path_has_a_SPACE_is_seen(spaced_root: SimpleNamespace) -> None:
    """The truncation half. `[^"\\s]+` stopped at the space, so this root was invisible in BOTH quoting
    styles -- measured ALLOW on the committed gate for each."""
    for quote in ('"', "'"):
        cmd = f"git -C {quote}{spaced_root.root}{quote} config {_DISARM}"
        cwd = spaced_root.root.parent
        reason = assert_denied(run_gate_in(shell(cmd, cwd=cwd), spaced_root.repos, hook_cwd=cwd))
        assert "SHARED git configuration" in reason


def test_the_spaced_root_still_allows_an_ordinary_key(spaced_root: SimpleNamespace) -> None:
    """Reading the path decides WHICH repository, never WHICH KEYS."""
    cmd = f'git -C "{spaced_root.root}" config user.email me@example.com'
    cwd = spaced_root.root.parent
    assert run_gate_in(shell(cmd, cwd=cwd), spaced_root.repos, hook_cwd=cwd) is None


@pytest.mark.parametrize(
    ("command", "cwd_key"),
    [
        ("git -C 'UNGOVERNED' config " + _DISARM, "primary"),
        ("cd '../Unrelated' && git config " + _DISARM, "primary"),
        ("git -C 'GOVERNED' config user.email a@b.c", "wt"),
        ('git commit -m "use -C HEAD to reuse a message"', "primary"),
        ("git config user.name 'Some One'", "primary"),
    ],
)
def test_reading_quoted_arguments_does_not_widen_the_rule(
    repo: SimpleNamespace, ungoverned: Path, command: str, cwd_key: str
) -> None:
    """Narrowness. A quoted token at an UNGOVERNED repo stays allowed, an ordinary key at a governed one
    stays allowed, a commit message that merely writes `-C HEAD` is still prose, and a quoted value with
    a space in it is still an ordinary config write."""
    cwd = {"primary": repo.primary, "wt": repo.wt}[cwd_key]
    command = command.replace("GOVERNED", str(repo.primary)).replace("UNGOVERNED", str(ungoverned))
    assert run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd) is None


# ------------------------------------------- rule 3c: a QUOTED disarm key was invisible (BACKLOG #1069)
#
# The key was matched against the scan string, which blanks every quoted span, so quoting the key erased
# it before the danger list ran. Quoting an argument is ordinary; the ``-c alias.*`` form MUST be quoted
# because its value contains a space.
#
# Matching the raw text instead is not the fix -- it refuses a commit message that quotes the rule's own
# name, a shape this workstream writes constantly. The key is now matched against a length-preserving
# mask that unmasks a span holding a SINGLE BARE WORD: prose has spaces and stays masked, a quoted key
# does not and is seen.


@pytest.mark.parametrize(
    "command",
    [
        'git -c "core.hooksPath=/dev/null" commit -m x',
        "git -c 'core.hooksPath=/dev/null' commit -m x",
        'git config "core.hooksPath" /dev/null',
        "git config 'core.hooksPath' '/dev/null'",
        'git config --add "core.hooksPath" /dev/null',
        'git -c "include.path=/evil" commit -m x',
    ],
)
def test_a_QUOTED_disarm_key_is_seen(repo: SimpleNamespace, command: str) -> None:
    """All six measured ALLOW on the committed gate, from the governed primary."""
    assert_denied(run_gate_in(shell(command, cwd=repo.primary), repo.repos, hook_cwd=repo.primary))


def test_a_QUOTED_disarm_key_is_seen_from_a_linked_worktree_too(repo: SimpleNamespace) -> None:
    """The blast radius is why this matters: a linked worktree's config write lands in the same shared
    file, so an invisible key there disarms every sibling as completely as one in the primary."""
    assert_denied(
        run_gate_in(
            shell('git config "core.worktree" ../x', cwd=repo.wt), repo.repos, hook_cwd=repo.wt
        )
    )


def test_a_QUOTED_MULTI_WORD_alias_value_is_still_invisible(repo: SimpleNamespace) -> None:
    """PINNED AS AN ALLOW, and it is the spelling that motivated the item.

    A quoted span WITH whitespace stays masked, so ``-c 'alias.<name>=<multi-word command>'`` is still
    not seen -- and because that value contains a space, quoting is its only writable spelling, so the
    whole class is open. Recorded as an assertion rather than prose so a later change cannot close it
    silently or claim it was never there.

    The consolation is measured, not assumed: the bare command such an alias exists to smuggle is
    ALLOWED by this gate anyway, and ``-c`` persists nothing (scope ``command``, in memory). Closing it
    wants a real argument tokeniser, and the one pass that built one acquired five fail-opens."""
    assert (
        run_gate_in(
            shell("git -c 'alias.ci=commit --no-verify' ci -m x", cwd=repo.primary),
            repo.repos,
            hook_cwd=repo.primary,
        )
        is None
    )


@pytest.mark.parametrize(
    "command",
    [
        'git commit -m "explain core.hooksPath handling"',
        'git commit -m "core.hooksPath"',
        'git commit -m "rename alias.ci to alias.cim"',
        'git log --grep "core.hooksPath"',
        'echo "core.hooksPath" > notes.md',
        'git config --get "core.hooksPath"',
    ],
)
def test_prose_that_quotes_the_key_is_still_prose(repo: SimpleNamespace, command: str) -> None:
    """The other half, and the reason the fix is a bare-word mask rather than "match the raw text".

    Every one of these is a thing this repository's own sessions write. A guard that refuses a commit
    message for naming the key it protects gets routed around, and then it protects nothing. Note the
    second case: a bare-word span IS unmasked, and it still allows -- because seeing the key is not the
    same as seeing a write, and no ``config`` subcommand or ``-c`` override precedes it here."""
    assert run_gate_in(shell(command, cwd=repo.primary), repo.repos, hook_cwd=repo.primary) is None


def test_a_quoted_key_in_an_UNGOVERNED_repo_is_untouched(
    repo: SimpleNamespace, ungoverned: Path
) -> None:
    """Seeing the key decides WHICH KEYS, never WHICH REPOSITORY."""
    assert (
        run_gate_in(
            shell('git config "core.hooksPath" /dev/null', cwd=ungoverned),
            repo.repos,
            hook_cwd=ungoverned,
        )
        is None
    )


def test_a_quoted_value_cannot_arm_the_READ_exclusion(repo: SimpleNamespace) -> None:
    """The mirror image, pinned so the fix cannot be widened into its own inverse.

    The read exclusion stays on the FULLY masked view. If it were read off the bare-word mask, a quoted
    VALUE of ``--get`` would excuse the write beside it -- the same defect as this item with the sign
    reversed. Denies on the committed gate and must go on denying."""
    assert_denied(
        run_gate_in(
            shell('git config core.hooksPath "--get"', cwd=repo.primary),
            repo.repos,
            hook_cwd=repo.primary,
        )
    )


# -------------------------------- rule 3c: the LOCAL ADMIN SHARE spelling of a root (BACKLOG #1071)
#
# Rule 3c makes git resolve path aliases for it, and that works for a junction, a ``\\?\`` prefix,
# drive-letter case, a trailing slash and ``/./``. It does NOT work for ``\\localhost\C$\...``: git
# echoes that spelling back unresolved, so the comparison against a governed root never matched and a
# disarm-key write through it was ALLOWED.
#
# The fix is a textual rewrite of the admin-share form to its drive-letter form, on BOTH sides of the
# comparison. Deliberately not a canonicaliser of our own: per-component link resolution inside a
# PreToolUse hook opens a handle per component and can block on a dead network path, and a guardrail
# that hangs the tool call gets uninstalled.


def _admin_share(path: Path) -> str:
    """``C:\\x\\y`` -> ``\\\\localhost\\C$\\x\\y``. Windows-only, and needs local administrator rights on
    the machine -- the fixture skips rather than pretends when the share is not reachable."""
    return "\\\\localhost\\" + str(path)[0] + "$" + str(path)[2:]


@pytest.fixture
def admin_share(repo: SimpleNamespace) -> str:
    if sys.platform != "win32":
        pytest.skip("the admin share is a Windows object")
    unc = _admin_share(repo.primary)
    if not Path(unc).is_dir():
        pytest.skip(f"the local admin share is not reachable: {unc}")
    return unc


def test_the_ADMIN_SHARE_spelling_of_a_governed_root_is_denied(
    repo: SimpleNamespace, admin_share: str
) -> None:
    """Measured ALLOW on the committed gate: git answers ``//localhost/C$/...`` for this target, and the
    prefix comparison against a drive-letter root cannot match it."""
    reason = assert_denied(
        run_gate_in(
            shell(f'git -C "{admin_share}" config {_DISARM}', cwd=repo.wt),
            repo.repos,
            hook_cwd=repo.wt,
        )
    )
    assert "SHARED git configuration" in reason


def test_the_ADMIN_SHARE_spelling_of_an_UNGOVERNED_repo_still_allows(
    repo: SimpleNamespace, ungoverned: Path, admin_share: str
) -> None:
    """The asymmetry. Rewriting the spelling must decide WHICH repository, not make every UNC path
    governed. ``admin_share`` is requested only for its skip conditions."""
    unc = _admin_share(ungoverned)
    assert (
        run_gate_in(
            shell(f'git -C "{unc}" config {_DISARM}', cwd=repo.wt), repo.repos, hook_cwd=repo.wt
        )
        is None
    )


def test_the_ADMIN_SHARE_spelling_does_not_widen_the_key_list(
    repo: SimpleNamespace, admin_share: str
) -> None:
    assert (
        run_gate_in(
            shell(f'git -C "{admin_share}" config user.email me@example.com', cwd=repo.wt),
            repo.repos,
            hook_cwd=repo.wt,
        )
        is None
    )


def test_an_ALLOWLIST_ENTRY_written_as_an_admin_share_still_governs(
    repo: SimpleNamespace, tmp_path: Path, admin_share: str
) -> None:
    """The MIRROR direction, which the item recorded as unmeasured.

    Rewriting only the candidate side would close the measured spelling and leave this one open: a root
    written in the UNC form would silently govern nothing when the target is spelled normally. Measured
    ALLOW on the committed gate; both sides go through the rewrite now."""
    repos = tmp_path / "unc-repos.txt"
    repos.write_text(admin_share + "\n", encoding="utf-8")
    reason = assert_denied(
        run_gate_in(
            shell(f'git -C "{repo.primary}" config {_DISARM}', cwd=repo.wt), repos, hook_cwd=repo.wt
        )
    )
    assert "SHARED git configuration" in reason


# ------------------------------------- rule 3c reads TEXT, and text has shapes (BACKLOG #1072)
#
# One of these is FIXED and the rest are PINNED AS MEASURED. A shape recorded as an assertion cannot be
# quietly closed or quietly widened; a shape described in prose can be both, and a deleted case is
# indistinguishable from one that never existed.

_BT = "`"


def test_a_BACKTICK_wrapped_disarm_is_denied(repo: SimpleNamespace) -> None:
    """The fixed one, and it is a single character. Backtick command substitution put a character before
    `git` that was not in the rule's leading class, so the token was not seen at all and the write was
    ALLOWED. Measured on the committed gate."""
    cmd = f"{_BT}git config {_DISARM}{_BT}"
    reason = assert_denied(
        run_gate_in(shell(cmd, cwd=repo.primary), repo.repos, hook_cwd=repo.primary)
    )
    assert "SHARED git configuration" in reason


@pytest.mark.parametrize(
    "wrapper",
    ["$(CMD)", "(CMD)", "{ CMD }", "exec CMD", "eval CMD", "timeout 5 CMD", "env CMD", "sudo CMD"],
)
def test_the_other_wrapper_spellings_were_already_denied(
    repo: SimpleNamespace, wrapper: str
) -> None:
    """The non-vacuity pair for the case above: these eight DENY on the committed gate and must go on
    denying, so the backtick fix reads as the one-character correction it is rather than as "wrappers
    started being handled". The wrapper story was never "wrappers no longer hide git"."""
    cmd = wrapper.replace("CMD", f"git config {_DISARM}")
    assert_denied(run_gate_in(shell(cmd, cwd=repo.primary), repo.repos, hook_cwd=repo.primary))


@pytest.mark.parametrize(
    ("command", "cwd_key"),
    [
        (f"{_BT}git config {_DISARM}{_BT}", "other"),
        (f"{_BT}git config user.email a@b.c{_BT}", "primary"),
        (f'git commit -m "run {_BT}git config core.hooksPath{_BT} later"', "primary"),
    ],
)
def test_the_backtick_class_does_not_widen_the_rule(
    repo: SimpleNamespace, ungoverned: Path, command: str, cwd_key: str
) -> None:
    """Seeing the token decides that a git command is PRESENT -- never which repository or which keys.
    The third case matters most: this repository's own prose writes backticked commands constantly."""
    cwd = {"primary": repo.primary, "other": ungoverned}[cwd_key]
    assert run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd) is None


@pytest.mark.parametrize(
    ("label", "command"),
    [
        ("newline-joined cd", "cd ../Unrelated\ngit config " + _DISARM),
        ("subshell cd", "(cd ../Unrelated && git config " + _DISARM + ")"),
        ("Push-Location", "Push-Location ../Unrelated; git config " + _DISARM),
        ("heredoc, line-leading body", "python - <<'PY'\ngit config " + _DISARM + "\nPY"),
        (
            "heredoc, non-line-leading body",
            "python - <<'PY'\ntext git config " + _DISARM + " x\nPY",
        ),
    ],
)
def test_these_text_shapes_are_pinned_as_DENY_and_are_NOT_fixed_here(
    repo: SimpleNamespace, ungoverned: Path, label: str, command: str
) -> None:
    """PINNED, NOT FIXED, and the pin is the deliverable.

    All five DENY on the committed gate and still DENY here, and for the first three that is an
    OVER-deny: the ``cd`` aims at an ungoverned sibling, the rule cannot follow it across a newline, a
    subshell or ``Push-Location``, and the session cwd stands. Toward an ungoverned sibling that is a
    false deny; the opposite topology would be the hole -- which is exactly why the bail-outs are
    conservative and must not be removed to make composition tidier.

    The two heredoc bodies are the same over-deny in a different shape: writing a disarm-key line into a
    file is not a config write, and the rule cannot tell. Reproduced live during this lane -- the
    installed gate refused a commit message that spelled one of these commands out.

    ``ungoverned`` is requested so ``../Unrelated`` exists; the verdict does not depend on it, which is
    the point."""
    assert_denied(run_gate_in(shell(command, cwd=repo.primary), repo.repos, hook_cwd=repo.primary))


# --------------------- rule 3c: a cd prefix COMPOSES with a relative -C, and the wording (BACKLOG #1085)
#
# The resolver PREFERRED ``-C`` and discarded a ``cd`` prefix; a real shell resolves a relative ``-C``
# against the POST-cd directory. That is the exact mirror of #1061 -- one root confusion, opposite sign.
# From a governed primary, ``cd ../Unrelated && git -C . config <disarm>`` DENIED and named the primary
# while the command configures the ungoverned sibling, so a session that read the refusal and believed
# it had been actively misinformed.
#
# These cases assert the DENY TEXT as well as the verdict. A test ending in a bare ``assert_denied``
# cannot see this defect at all: the verdict does not move for the wording half, and a round-4 mutant
# that reinstated a known-false sentence survived a fully green suite for exactly that reason.

_NAMES_A_REPO = "would change the SHARED git configuration of"
_NAMES_NOTHING = "could not work out WHICH repository"


def test_a_cd_to_an_UNGOVERNED_repo_then_a_relative_C_is_allowed(
    repo: SimpleNamespace, ungoverned: Path
) -> None:
    """The filed false deny, and the only case in this lane that moves a verdict from DENY to ALLOW.

    The write lands in ../Unrelated. It is not a governed repository, and refusing it while naming the
    primary was both wrong and misleading."""
    assert (
        run_gate_in(
            shell(f"cd ../Unrelated && git -C . config {_DISARM}", cwd=repo.primary),
            repo.repos,
            hook_cwd=repo.primary,
        )
        is None
    )
    assert ungoverned.is_dir()  # the fixture built the sibling this command names


@pytest.mark.parametrize(
    ("command", "cwd_key"),
    [
        ("cd ../Unrelated && git -C ../Primary config " + _DISARM, "primary"),
        ("cd ../Primary && git -C . config " + _DISARM, "other"),
        ("git -C UNGOVERNED -C ../Primary config " + _DISARM, "primary"),
    ],
)
def test_composition_still_reaches_a_governed_repo(
    repo: SimpleNamespace, ungoverned: Path, command: str, cwd_key: str
) -> None:
    """Composition is not a licence to stop looking. Two of these were ALLOW on the committed gate --
    the second because a `cd` was discarded, the third because only the FIRST `-C` was read although git
    processes repeated `-C` sequentially, each relative to the previous."""
    cwd = {"primary": repo.primary, "other": ungoverned}[cwd_key]
    command = command.replace("UNGOVERNED", str(ungoverned))
    reason = assert_denied(run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd))
    assert _NAMES_A_REPO in reason


@pytest.mark.parametrize(
    ("label", "command"),
    [
        ("subshell cd", "(cd ../Unrelated && git config " + _DISARM + ")"),
        ("Push-Location", "Push-Location ../Unrelated; git config " + _DISARM),
        ("two cds", "cd ../Unrelated && cd ../Primary && git config " + _DISARM),
        ("popd", "popd && git config " + _DISARM),
        ("newline-joined cd", "cd ../Unrelated\ngit config " + _DISARM),
    ],
)
def test_an_unfollowable_cd_refuses_WITHOUT_naming_a_repository(
    repo: SimpleNamespace, ungoverned: Path, label: str, command: str
) -> None:
    """The wording half, and it is the whole point of the item.

    Each of these changes directory in a shape whose destination is not in the text -- a subshell, a
    verb the resolver does not follow, more than one ``cd``, a stack pop, or a newline the line-based
    splitter cannot compose across. The verdict is unchanged (the fallback is the session cwd and it is
    governed), but the refusal must NOT assert that this repository's shared configuration would change.
    It did not establish that."""
    reason = assert_denied(
        run_gate_in(shell(command, cwd=repo.primary), repo.repos, hook_cwd=repo.primary)
    )
    assert _NAMES_NOTHING in reason
    assert _NAMES_A_REPO not in reason
    assert "FALLBACK, NOT A FINDING" in reason
    assert ungoverned.is_dir()


@pytest.mark.parametrize(
    ("label", "command"),
    [
        ("no directory change at all", "git config " + _DISARM),
        ("a cd AFTER the write", "git config " + _DISARM + " && cd ../Unrelated"),
        ("an ABSOLUTE -C after a subshell cd", '(cd ../Unrelated && git -C "GOVERNED" config DIS)'),
        ("a followable cd into the governed repo", "cd ../Primary && git config " + _DISARM),
    ],
)
def test_a_determined_target_is_still_named(
    repo: SimpleNamespace, ungoverned: Path, label: str, command: str
) -> None:
    """Non-vacuity for the pair above: the hedge must be reachable AND avoidable.

    If every refusal said "could not work out which repository", the message would carry no information
    and the fix would be a regression dressed as caution. Each of these DOES establish the target -- no
    directory change, a change that happens after the write, an absolute ``-C`` that makes the base
    irrelevant, or a ``cd`` the resolver can follow -- so each must still name the repository.

    The last case runs from the linked worktree so ``../Primary`` names the governed root."""
    command = command.replace("GOVERNED", str(repo.primary)).replace("DIS", _DISARM)
    cwd = repo.wt if command.startswith("cd ../Primary") else repo.primary
    reason = assert_denied(run_gate_in(shell(command, cwd=cwd), repo.repos, hook_cwd=cwd))
    assert _NAMES_A_REPO in reason
    assert _NAMES_NOTHING not in reason
    assert ungoverned.is_dir()


# ------------------------ rule 3c governs a REPOSITORY, not a path prefix (BACKLOG #1067)
#
# "Is this governed?" was an equality-or-slash-prefix test against the root's WORKING TREE path, so any
# repository living anywhere under a governed root inherited its governance -- including an independent
# clone vendored there, which shares nothing with it. The refusal then said every worktree of this
# repository shares one git directory, which is simply untrue of that repository, and a refusal that
# misdescribes what it blocked teaches people to route around the gate.
#
# The comparison is now against the root's own COMMON DIR. The pair that has to hold: a vendored
# independent repo ALLOWS, and a worktree nested under ``.claude/worktrees`` -- whose git dir really is
# the primary's -- keeps DENYING.


@pytest.fixture
def vendored(repo: SimpleNamespace) -> Path:
    """An INDEPENDENT repository living under the primary. Its top level is itself and its git dir is
    its own; it shares nothing with the primary but its path."""
    vend = repo.primary / "vendor" / "thirdparty"
    vend.mkdir(parents=True)
    subprocess.run(["git", "init", "-b", "main", str(vend)], check=True, capture_output=True)
    return vend


@pytest.fixture
def submodule(repo: SimpleNamespace, ungoverned: Path) -> Path:
    """A real git SUBMODULE of the primary. Its git dir lives under ``<primary>/.git/modules/``, which is
    why it must stay on the deny side: the identity-only fix would have flipped it silently, and whether
    that is right is its own decision rather than a side effect of this one."""
    subprocess.run(
        ["git", "-C", str(ungoverned), "commit", "--allow-empty", "-m", "seed"],
        check=True,
        capture_output=True,
        env=None,
    )
    p = subprocess.run(
        [
            "git",
            "-c",
            "protocol.file.allow=always",
            "-C",
            str(repo.primary),
            "submodule",
            "add",
            str(ungoverned).replace("\\", "/"),
            "sub",
        ],
        capture_output=True,
        text=True,
    )
    if p.returncode != 0:
        pytest.skip(f"could not add a local submodule: {p.stderr.strip()[:200]}")
    return repo.primary / "sub"


def test_a_VENDORED_independent_repo_under_the_primary_is_allowed(
    repo: SimpleNamespace, vendored: Path
) -> None:
    """The defect, from the vendored repo's own cwd. Measured DENY on the committed gate, with a message
    naming the PRIMARY."""
    assert (
        run_gate_in(shell(f"git config {_DISARM}", cwd=vendored), repo.repos, hook_cwd=vendored)
        is None
    )


def test_the_VENDORED_repo_is_allowed_by_an_absolute_path_token_too(
    repo: SimpleNamespace, vendored: Path
) -> None:
    """Same repository, named from outside. Also DENY on the committed gate -- the defect is in the
    governance predicate, so it does not care how the target was spelled."""
    assert (
        run_gate_in(
            shell(f'git -C "{vendored}" config {_DISARM}', cwd=repo.primary),
            repo.repos,
            hook_cwd=repo.primary,
        )
        is None
    )


def test_a_NESTED_claude_worktree_keeps_denying(repo: SimpleNamespace) -> None:
    """The other half of the pair, and the one that makes this a correction rather than a hole.

    A worktree under ``.claude/worktrees`` sits under the primary's path exactly like the vendored repo
    does -- but its common dir IS the primary's, so its config write really does land in the shared
    file. Path shape cannot tell those two apart; repository identity can."""
    nested = _nested_worktree(repo)
    reason = assert_denied(
        run_gate_in(shell(f"git config {_DISARM}", cwd=nested), repo.repos, hook_cwd=nested)
    )
    assert "SHARED git configuration" in reason


def test_a_SUBMODULE_of_the_primary_keeps_denying(repo: SimpleNamespace, submodule: Path) -> None:
    """The flip the item warned about, pinned so it cannot happen by accident.

    A submodule's git dir is ``<primary>/.git/modules/<name>``, so the equality-or-under test still
    catches it. The tempting identity-ONLY predicate would have turned every submodule config write from
    DENY to ALLOW as an invisible side effect of fixing the vendored case."""
    assert_denied(
        run_gate_in(
            shell(f'git -C "{submodule}" config {_DISARM}', cwd=repo.primary),
            repo.repos,
            hook_cwd=repo.primary,
        )
    )


def test_the_governed_primary_and_its_sibling_worktree_keep_denying(repo: SimpleNamespace) -> None:
    """The baseline pair. If these ever stop denying, the predicate has been rewritten rather than
    narrowed, which is the failure mode of every earlier attempt at this rule."""
    for cwd in (repo.primary, repo.wt):
        reason = assert_denied(
            run_gate_in(shell(f"git config {_DISARM}", cwd=cwd), repo.repos, hook_cwd=cwd)
        )
        assert "SHARED git configuration" in reason


def test_an_allowlist_root_that_is_not_a_repository_still_governs_by_prefix(
    tmp_path: Path, repo: SimpleNamespace
) -> None:
    """The fallback, stated rather than assumed. An allowlist entry may legitimately name a directory
    that merely CONTAINS checkouts; there is no repository there to take an identity from, so the path
    prefix is still the answer and the old behaviour is unchanged."""
    repos = tmp_path / "container-repos.txt"
    repos.write_text(f"{tmp_path}\n", encoding="utf-8")
    reason = assert_denied(
        run_gate_in(shell(f"git config {_DISARM}", cwd=repo.primary), repos, hook_cwd=repo.primary)
    )
    assert "SHARED git configuration" in reason


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
