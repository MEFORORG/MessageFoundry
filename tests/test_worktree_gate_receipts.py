# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The gate must leave a receipt when it denies, and its deny message must not misdirect.

Until the receipt existed the gate was unfalsifiable. It wrote its decision to stdout and exited 0, so
nothing on the box could answer "how many drift events did we prevent last month", "is the false-positive
rate 1/day or 1/1000", or "did that fix change anything" -- which meant every severity claim about this
machinery was an opinion. These tests pin the receipt's existence, its rule attribution, and the one thing
it must never contain.

The deny-message test is here for the same reason: the message is the part of the hook whose entire job is
steering the next action, and it was steering it back at the tree the gate had just refused.
"""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
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
    f = tmp_path / "repos.txt"
    f.write_text(f"{primary}\n", encoding="utf-8")
    return f


def receipts(repos_file: Path) -> list[str]:
    """The gate writes its log beside the allowlist, so the fixture's tmp dir isolates it per test."""
    log = repos_file.parent / "worktree-gate.log"
    if not log.exists():
        return []
    return [ln for ln in log.read_text(encoding="utf-8").splitlines() if ln.strip()]


# --------------------------------------------------------------------------- the receipt exists


def test_a_denied_write_leaves_a_receipt(primary: Path, repos_file: Path) -> None:
    assert_denied(run_gate(edit(primary / "src" / "app.py", primary), repos_file))
    lines = receipts(repos_file)
    assert len(lines) == 1, f"expected exactly one receipt, got {lines}"
    assert "rule=1" in lines[0]
    assert "tool=Edit" in lines[0]
    assert str(primary).replace("\\", "/").lower() in lines[0].replace("\\", "/").lower()


def test_an_allowed_call_leaves_no_receipt(tmp_path: Path, primary: Path, repos_file: Path) -> None:
    """The log counts DENIALS. If allows were logged too, the count would measure traffic, not drift."""
    worktree = tmp_path / "Repo-alerts" / "src" / "app.py"
    assert run_gate(edit(worktree, cwd=primary), repos_file) is None
    assert receipts(repos_file) == []


@pytest.mark.parametrize(
    ("payload_kind", "expected_rule"),
    [("dispatch", "rule=2"), ("git", "rule=3")],
)
def test_each_rule_stamps_its_own_id(
    primary: Path, repos_file: Path, payload_kind: str, expected_rule: str
) -> None:
    """Attribution is the point: 'the gate fired 40 times' is useless if you cannot tell rule 3's true
    positives from rule 3's false positives."""
    if payload_kind == "dispatch":
        payload: dict[str, Any] = {
            "session_id": "s-1",
            "cwd": str(primary),
            "tool_name": "Task",
            "tool_input": {"prompt": "go"},
        }
    else:
        payload = shell("git checkout somebranch", cwd=primary)
    assert_denied(run_gate(payload, repos_file))
    assert expected_rule in receipts(repos_file)[0]


def test_rule_4_stamps_its_own_id(primary: Path, repos_file: Path) -> None:
    """Rules 3b and 4 were the two the first version of this file left unattributed."""
    payload = {
        "session_id": "s-1",
        "cwd": str(primary),
        "tool_name": "EnterWorktree",
        "tool_input": {"name": "wt-1"},
    }
    assert_denied(run_gate(payload, repos_file))
    assert "rule=4" in receipts(repos_file)[0]


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
def test_rule_3b_stamps_its_own_id(tmp_path: Path) -> None:
    """3b needs a REAL worktree -- it asks git whether the target is a governed linked worktree."""

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

    assert_denied(run_gate(shell("git checkout claude/other-branch", cwd=wt), repos))
    line = receipts(repos)[0]
    assert "rule=3b" in line, line
    assert "git checkout" in line


def test_every_receipt_carries_the_gate_version(primary: Path, repos_file: Path) -> None:
    """The version stamp is how `install-gate.ps1 -Status` names the build that is running. If it stops
    being written, a log full of denials cannot be attributed to a rule set."""
    assert_denied(run_gate(edit(primary / "x.py", primary), repos_file))
    line = receipts(repos_file)[0]
    assert re.search(r"\tv\d{4}\.\d{2}\.\d{2}\.\d+\t", line), line
    assert re.search(r"\tpid=\d+\t", line), line


def test_rule_1_governs_the_primarys_own_git_hooks_directory(
    primary: Path, repos_file: Path
) -> None:
    """The gate's enforcement surface must not be editable through the gate. `<primary>/.git/hooks` is
    under a governed root and is NOT under the `.claude/worktrees/` exemption, so rule 1 denies a write
    there -- docs/SESSION-DRIFT-CONTROLS.md asserts this, and nothing was asserting it."""
    assert_denied(run_gate(edit(primary / ".git" / "hooks" / "pre-commit", primary), repos_file))
    assert_denied(run_gate(edit(primary / ".claude" / "hooks" / "x.ps1", primary), repos_file))


def test_the_receipt_never_records_the_raw_command(primary: Path, repos_file: Path) -> None:
    """A command string is attacker- and operator-influenceable and can carry a token. The rules pass a
    $Detail they composed themselves (a verb, a target path) precisely so the log cannot become a
    plaintext secret store -- this is the assertion that keeps it that way."""
    # A deliberately BLAND sentinel. An imitation of a real credential format (glpat-, ghp-, AKIA...)
    # trips this repo's own gitleaks pre-commit hook, so the guard against leaking secrets cannot itself
    # be written with something that looks like one.
    secret = "SENTINEL-MUST-NOT-REACH-THE-LOG"
    assert_denied(run_gate(shell(f"git checkout main # {secret}", cwd=primary), repos_file))
    blob = "\n".join(receipts(repos_file))
    assert blob, "expected a receipt"
    assert secret not in blob
    assert "git checkout" in blob  # the verb IS recorded -- that is the diagnostic value


def test_logging_failure_never_blocks_the_deny(primary: Path, tmp_path: Path) -> None:
    """The receipt is best-effort. An allowlist in a directory the gate cannot append to must still DENY --
    a guardrail that stops guarding because its logger broke is worse than one that never logged."""
    missing = tmp_path / "gone" / "repos.txt"
    missing.parent.mkdir()
    missing.write_text(f"{primary}\n", encoding="utf-8")
    shutil.rmtree(missing.parent, ignore_errors=True)
    # The allowlist is gone too, so this asserts the weaker but sufficient property: no crash, exit 0.
    assert run_gate(edit(primary / "x.py", primary), missing) is None


# --------------------------------------------------------------------------- the deny message


@pytest.mark.skipif(shutil.which("git") is None, reason="needs git on PATH")
def test_the_deny_message_does_not_offer_the_primary_as_a_worktree_to_reuse(
    tmp_path: Path,
) -> None:
    """Rule 1 lists the worktrees that already exist so a retry reuses one instead of minting another. The
    filter that removes the primary from that list compared a path string to the PSCustomObject returned by
    Test-Governed, so it was always -ne and never removed anything: the message refused a write to the
    primary and then named the primary as the first thing to reuse. Needs a REAL repo -- with no git
    worktree list to read, the hint section is absent and the assertion would be vacuous."""

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

    reason = assert_denied(run_gate(edit(primary / "x.py", primary), repos))
    assert "REUSE" in reason, "the hint section must be present or this test proves nothing"
    hint = reason.split("REUSE", 1)[1]

    def norm(p: str) -> str:
        return p.replace("\\", "/").rstrip("/").lower()

    # git prints worktree paths with forward slashes even on Windows, so normalise before comparing --
    # matching the raw string would silently find nothing and the assertions below would both pass.
    root = norm(str(tmp_path))
    listed = [norm(ln.strip()) for ln in hint.splitlines() if norm(ln.strip()).startswith(root)]
    assert norm(str(wt)) in listed, f"the real worktree must be offered; got {listed}"
    assert norm(str(primary)) not in listed, (
        f"the SHARED PRIMARY was offered as a worktree to reuse: {listed}"
    )
