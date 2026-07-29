"""Rule 3 must judge what a command DOES, not how its characters are arranged.

Every case here is a regression that an adversarial review found in the first version of the
quote-blanking and cd-resolving work, each verified as a DENY on main (db53fd45) that had become an ALLOW.
They are grouped by the wrong assumption that caused them:

* **Quoted does not mean inert.** The argument of ``pwsh -Command`` / ``bash -c`` / ``cmd /c`` is quoted,
  and it is *code that runs*. Blanking every quoted span to stop a commit message supplying a verb also
  erased the verb from an interpreter argument, so ``pwsh -NoProfile -Command "git reset --hard"`` in the
  primary was allowed -- in this repo's own house idiom, and exactly the route-around the deny text warns
  against. Interpreter arguments are recursed into instead of blanked.

* **A command is a sequence, not a bag of tokens.** Resolving ``cd`` from anywhere in the string made the
  rule order-blind: a ``cd`` *after* the git verb, or one already undone by ``popd``, redirected the target
  away from the tree the git call actually touched. Only the text *preceding* the invocation counts, and an
  ambiguous prefix falls back to the session cwd -- the deny-side default.

* **Redirecting files is not redirecting the repository.** ``--work-tree`` / ``GIT_WORK_TREE`` say where
  files land; ``GIT_DIR`` still resolves from the cwd, so the shared repo's HEAD and index still move. Read
  as a replacement target they made a one-token bypass of the whole rule. They are additional candidates
  now, never substitutes -- only ``-C`` relocates both.

* **A line break is not a statement break.** Splitting per line to stop prose supplying a verb also split
  a trailing-backslash continuation from its subcommand. Continuations are folded first.

The closing group pins the fixes these regressions came from, so a revert cannot trade one for the other.
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
def nested(primary: Path) -> Path:
    return primary / ".claude" / "worktrees" / "wt-1"


@pytest.fixture
def repos_file(tmp_path: Path, primary: Path) -> Path:
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


# --------------------------------------------------------- quoted does not mean inert


@pytest.mark.parametrize(
    "command",
    [
        'pwsh -NoProfile -Command "git reset --hard"',
        "pwsh -Command 'git checkout main'",
        'pwsh -c "git clean -xfd"',
        'bash -c "git rebase origin/main"',
        'bash -lc "git checkout main"',
        'sh -c "git stash"',
        'cmd /c "git checkout main"',
    ],
)
def test_a_git_verb_inside_an_interpreter_argument_is_still_a_git_verb(
    primary: Path, repos_file: Path, command: str
) -> None:
    """The quoted span an interpreter is handed EXECUTES. Blanking it made every one of these allow."""
    reason = assert_denied(run_gate(shell(command, cwd=primary), repos_file))
    assert "SHARED PRIMARY" in reason


@pytest.mark.parametrize(
    "template",
    [
        'sh -c "cd {p} && git reset --hard"',
        'bash -lc "cd {p} && git checkout main"',
        "pwsh -c 'git -C {p} checkout main'",
        'pwsh -Command "cd {p}; git clean -xfd"',
    ],
)
def test_an_interpreter_argument_naming_the_primary_is_denied_from_a_worktree(
    tmp_path: Path, primary: Path, repos_file: Path, template: str
) -> None:
    """Worse than the above: the primary is spelled out in full inside the quotes, and the early exit on
    'no verb found' meant the in-text path fallback was never even reached."""
    assert_denied(
        run_gate(shell(template.format(p=primary), cwd=tmp_path / "Repo-alerts"), repos_file)
    )


def test_a_remote_command_over_ssh_is_not_the_local_primary(
    primary: Path, repos_file: Path
) -> None:
    """The counter-case that keeps the recursion honest: `ssh box "git checkout main"` runs on another
    HOST. It denied on main and should not -- recursing into interpreter arguments must not sweep this
    back in, so `ssh` is deliberately not treated as an interpreter."""
    assert run_gate(shell('ssh box "git checkout main"', cwd=primary), repos_file) is None


# --------------------------------------------------------- a command is a sequence


@pytest.mark.parametrize(
    "command",
    [
        "git checkout main && cd ../Elsewhere",
        "git reset --hard ; cd ../Elsewhere",
        "pushd ../Elsewhere ; popd ; git reset --hard",
        "cd ../Elsewhere && cd . && git clean -xfd",
        "cd - ; git checkout main",
    ],
)
def test_a_cd_that_does_not_precede_the_git_call_cannot_exempt_it(
    primary: Path, repos_file: Path, command: str
) -> None:
    """A cd AFTER the verb, one undone by popd, or an ambiguous pair: none of them changes the tree the
    git call acted on. Reading cd from the whole string let each of these walk out of the primary."""
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))


def test_a_cd_that_does_precede_the_git_call_is_still_honoured(
    primary: Path, repos_file: Path
) -> None:
    """The fix must not simply ignore cd -- that would re-open the relative-path bypass it was added for,
    and re-introduce the false positive of denying work that left the primary first."""
    assert run_gate(shell("cd ../Elsewhere && git checkout main", cwd=primary), repos_file) is None


def test_a_dash_C_beats_a_preceding_cd(tmp_path: Path, primary: Path, repos_file: Path) -> None:
    """git acts on -C, never on the cd'd directory, when both appear."""
    sibling = tmp_path / "Repo-alerts"
    assert (
        run_gate(shell(f'cd {primary} && git -C "{sibling}" rebase main', cwd=primary), repos_file)
        is None
    )
    assert_denied(
        run_gate(
            shell(f'cd {sibling} && git -C "{primary}" checkout main', cwd=sibling), repos_file
        )
    )


# --------------------------------------------------------- files vs repository


@pytest.mark.parametrize(
    "command",
    [
        "git --work-tree=C:/Windows/Temp reset --hard",
        "git --work-tree C:/Windows/Temp checkout main",
        "GIT_WORK_TREE=C:/Windows/Temp git checkout main",
    ],
)
def test_redirecting_the_work_tree_does_not_exempt_the_repository(
    primary: Path, repos_file: Path, command: str
) -> None:
    """GIT_DIR still resolves from the cwd, so the SHARED repo's HEAD and index still move. Treating these
    as 'the tree the command acts on' turned one token into a bypass of the entire rule."""
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))


def test_a_work_tree_pointing_INTO_the_primary_is_denied_from_outside(
    tmp_path: Path, primary: Path, repos_file: Path
) -> None:
    """The other direction: the candidate set means a work-tree aimed at the primary denies even when the
    cwd is innocent."""
    assert_denied(
        run_gate(
            shell(f'git --work-tree="{primary}" checkout main', cwd=tmp_path / "Elsewhere"),
            repos_file,
        )
    )


# --------------------------------------------------------- a line break is not a statement break


@pytest.mark.parametrize("command", ["git \\\n  checkout main", "git `\n  reset --hard"])
def test_a_line_continuation_does_not_separate_git_from_its_verb(
    primary: Path, repos_file: Path, command: str
) -> None:
    """Splitting per line to stop prose supplying a verb also split `git \\` from its subcommand. Folding
    continuations first is safe because prose does not end a line with a continuation character."""
    assert_denied(run_gate(shell(command, cwd=primary), repos_file))


def test_folding_continuations_does_not_resurrect_the_prose_false_positive(
    primary: Path, repos_file: Path
) -> None:
    assert run_gate(shell("git status\necho about to merge stuff", cwd=primary), repos_file) is None


# --------------------------------------------------------- rule 3b sees the same commands


@pytest.fixture
def repo(tmp_path: Path) -> SimpleNamespace:
    """A real governed primary + a linked worktree + a free branch to hijack onto."""
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
    git("branch", "claude/other-branch", cwd=primary)
    wt = tmp_path / "Primary-wt"
    git("worktree", "add", "-b", "wt-branch", str(wt), cwd=primary)
    repos = tmp_path / "repos.txt"
    repos.write_text(f"{primary}\n", encoding="utf-8")
    return SimpleNamespace(primary=primary, wt=wt, repos=repos, other="claude/other-branch")


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
@pytest.mark.parametrize(
    "template",
    [
        'pwsh -Command "git checkout {b}"',
        "pwsh -c 'git checkout {b}'",
        'bash -c "git switch {b}"',
        'cmd /c "git checkout {b}"',
    ],
)
def test_the_worktree_hijack_is_caught_through_an_interpreter_argument(
    repo: SimpleNamespace, template: str
) -> None:
    """Rule 3b rides the same scan as rule 3, so the blanking regression disarmed it too: a session could
    hijack another session's worktree simply by wrapping the checkout in `pwsh -Command`."""
    reason = assert_denied(run_gate(shell(template.format(b=repo.other), cwd=repo.wt), repo.repos))
    assert "LINKED WORKTREE" in reason


# --------------------------------------------------------- the receipt log stays one-record-per-line


def test_a_crafted_path_cannot_forge_extra_log_records(primary: Path, repos_file: Path) -> None:
    """$Detail is composed from tool input. An embedded newline would let a crafted path write additional
    records into the log whose entire purpose is counting denials -- so the count could be inflated by the
    thing being counted."""
    target = str(primary / "a\nb\tc.py")
    payload = {
        "session_id": "s-1",
        "cwd": str(primary),
        "tool_name": "Edit",
        "tool_input": {"file_path": target},
    }
    assert_denied(run_gate(payload, repos_file))
    log = repos_file.parent / "worktree-gate.log"
    lines = [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]
    assert len(lines) == 1, f"one deny must write exactly one record, got {len(lines)}: {lines}"
    assert lines[0].startswith("2"), "the record must still begin with its timestamp"
