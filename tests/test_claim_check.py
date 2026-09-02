# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""The claim gate (BACKLOG #309): two sessions must not build the same backlog item in parallel.

Each test drives the REAL hook as a subprocess against a REAL throwaway git repo, with real staged files
and real claim records — the same shape as tests/test_worktree_gate.py. Nothing is monkeypatched, because
the thing under test is precisely how the hook reads git and the shared claim registry.

The gate is deliberately narrow, and most of these tests pin what it must NOT block: a docs-only commit, a
body-only mention, a commit with no BACKLOG token. A coordination gate that fires on those gets disabled
by the first person it annoys, and then it protects nothing.
"""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

_CHECK = Path(__file__).resolve().parents[1] / "scripts" / "hooks" / "claim_check.py"


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True)


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway repo with one committed file, so a later `git add` produces a real staged diff."""
    r = tmp_path / "repo"
    r.mkdir()
    _git(r, "init", "-q")
    _git(r, "config", "user.email", "t@example.invalid")
    _git(r, "config", "user.name", "T")
    (r / "seed.txt").write_text("seed\n", encoding="utf-8")
    _git(r, "add", "seed.txt")
    _git(r, "commit", "-q", "-m", "seed")
    (r / "docs").mkdir()
    (r / "docs" / "BACKLOG.md").write_text("# backlog\n", encoding="utf-8")
    (r / "code.py").write_text("x = 1\n", encoding="utf-8")
    return r


def _claims_dir(repo: Path) -> Path:
    common = subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--git-common-dir"],
        capture_output=True,
        text=True,
    ).stdout.strip()
    d = Path(common) / "mefor-coord" / "claims"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _toplevel(repo: Path) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), "rev-parse", "--path-format=absolute", "--show-toplevel"],
        capture_output=True,
        text=True,
    ).stdout.strip()


def _write_claim(repo: Path, key: str, *, worktree: str | None = None) -> None:
    """A claim record, written UTF-8 WITHOUT a BOM exactly as claim.ps1 writes it."""
    rec = {
        "key": key,
        "note": "test",
        "branch": "b",
        "worktree": worktree if worktree is not None else _toplevel(repo),
        "claimed": "2026-07-24T12:00:00.0000000-05:00",
    }
    (_claims_dir(repo) / f"{key}.json").write_bytes(
        json.dumps(rec, separators=(",", ":")).encode("utf-8")
    )


def _run(repo: Path, message: str) -> subprocess.CompletedProcess[str]:
    msg = repo / "COMMIT_MSG.tmp"
    msg.write_text(message, encoding="utf-8")
    return subprocess.run(
        [sys.executable, str(_CHECK), str(msg)],
        cwd=repo,
        capture_output=True,
        text=True,
    )


# ------------------------------------------------------------------- what it must not fail OPEN on


def test_a_git_read_failure_refuses_instead_of_passing_unchecked(
    repo: Path, tmp_path: Path
) -> None:
    """The gate must not be disarmed by the one condition it cannot detect.

    `_git` returned `.stdout` and never checked `returncode`, so a failed read returned "" --
    indistinguishable from a genuinely empty diff. That flowed to `_touches_code([])`, which is
    False BY DESIGN so a message-only `--amend` is never blocked, and the gate took its docs-only
    exit and PASSED a commit citing an unclaimed item, PRINTING NOTHING.

    Driven the way the defect actually arrives: the hook runs somewhere git cannot answer. Before
    the fix this returned 0.
    """
    msg = tmp_path / "COMMIT_MSG.tmp"
    msg.write_text("feat(x): build it (BACKLOG #42)", encoding="utf-8")
    outside = tmp_path / "not-a-repo"
    outside.mkdir()
    r = subprocess.run(
        [sys.executable, str(_CHECK), str(msg)], cwd=outside, capture_output=True, text=True
    )
    assert r.returncode == 1, f"the gate PASSED a commit it could not check: {r.stdout} {r.stderr}"
    assert "could not be read" in r.stderr
    assert "NOT checked" in r.stderr


def test_the_git_read_failure_test_has_a_working_control(repo: Path) -> None:
    """The negative above proves nothing unless the SAME command succeeds where git can answer.

    Without this, deleting the staged-diff read entirely would satisfy the test above while
    breaking every real check -- a refusal for the wrong reason reads identically to a refusal
    for the right one.
    """
    _git(repo, "add", "code.py")
    r = _run(repo, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 1
    assert "NOT CLAIMED" in r.stderr, "inside a real repo the refusal must be the CLAIM one"
    assert "could not be read" not in r.stderr, "git read fine here; the wrong refusal fired"


# --------------------------------------------------------------------------- what it must BLOCK


def test_unclaimed_item_with_code_is_blocked(repo: Path) -> None:
    _git(repo, "add", "code.py")
    r = _run(repo, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 1
    assert "NOT CLAIMED" in r.stderr
    assert "claim.ps1 -Take 42" in r.stderr  # the fix must be in the message, not just the refusal


def test_item_claimed_by_another_worktree_is_blocked(repo: Path) -> None:
    _write_claim(repo, "42", worktree="C:/somewhere/else")
    _git(repo, "add", "code.py")
    r = _run(repo, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 1
    assert "claimed by ANOTHER worktree" in r.stderr
    assert "C:/somewhere/else" in r.stderr  # name the holder, so the human can go talk to them


def test_paired_items_block_when_either_is_unclaimed(repo: Path) -> None:
    """`(BACKLOG #71, #72)` is the house form for a paired commit; the second item must not slip through."""
    _write_claim(repo, "71")
    _git(repo, "add", "code.py")
    r = _run(repo, "feat(x): pair (BACKLOG #71, #72)")
    assert r.returncode == 1
    assert "#72" in r.stderr
    assert "#71 is" not in r.stderr  # the claimed one is not reported


def test_a_corrupt_claim_reads_as_unclaimed_not_as_permission(repo: Path) -> None:
    """Fail CLOSED. A BOM (PowerShell's `-Encoding utf8` writes one) makes json.loads raise; that must ask
    for a claim, never silently pass. This exact BOM bit us on an ADR claim on 2026-07-24."""
    (_claims_dir(repo) / "42.json").write_bytes(
        b"\xef\xbb\xbf" + json.dumps({"worktree": _toplevel(repo)}).encode("utf-8")
    )
    _git(repo, "add", "code.py")
    r = _run(repo, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 1
    assert "NOT CLAIMED" in r.stderr


# --------------------------------------------------------------------------- what it must NOT block


def test_claimed_item_passes(repo: Path) -> None:
    _write_claim(repo, "42")
    _git(repo, "add", "code.py")
    assert _run(repo, "feat(x): build it (BACKLOG #42)").returncode == 0


def test_docs_only_commit_is_never_blocked(repo: Path) -> None:
    """Banner flips and ledger reconciles cite an item without building it — blocking them would make the
    gate fight exactly the bookkeeping that keeps the backlog honest."""
    _git(repo, "add", "docs/BACKLOG.md")
    assert _run(repo, "docs(backlog): flip banner (BACKLOG #42)").returncode == 0


def test_no_backlog_token_passes(repo: Path) -> None:
    _git(repo, "add", "code.py")
    assert _run(repo, "chore: tidy up").returncode == 0


def test_backlog_mentioned_only_in_the_body_passes(repo: Path) -> None:
    """A body routinely cites the item a commit supersedes or was found by. Only the SUBJECT declares what
    a commit implements, so only the subject is enforced."""
    _git(repo, "add", "code.py")
    msg = "fix(x): unrelated thing\n\nFound while working on BACKLOG #42.\n"
    assert _run(repo, msg).returncode == 0


def test_empty_diff_passes(repo: Path) -> None:
    """`git commit --amend` on a message alone stages nothing; that must not be blocked."""
    assert _run(repo, "feat(x): build it (BACKLOG #42)").returncode == 0


def test_missing_message_argument_is_a_no_op(repo: Path) -> None:
    """Not wired as a commit-msg hook -> do nothing, rather than guess at a message file."""
    r = subprocess.run([sys.executable, str(_CHECK)], cwd=repo, capture_output=True, text=True)
    assert r.returncode == 0


# ------------------------------------------------- BACKLOG #1345: location must not outrank extension
#
# `_DOC_PREFIXES` classifies by LOCATION, so before this fix a file DECLARED ITSELF documentation
# merely by sitting under one -- and `.github/` holds the CI workflows. A commit rewiring CI, citing
# an item, touching nothing else, was held to no claim at all. Rewiring CI is exactly the change two
# sessions collide on, which is the collision this gate exists to stop.


def test_a_ci_workflow_only_commit_is_HELD_to_the_claim_rule(repo: Path) -> None:
    """MUST BLOCK. `.github/` is a documentation prefix and a workflow is not a `.md`, so this
    commit was classified as documentation and waved through."""
    (repo / ".github" / "workflows").mkdir(parents=True)
    (repo / ".github" / "workflows" / "ci.yml").write_text("on: push\n", encoding="utf-8")
    _git(repo, "add", ".github/workflows/ci.yml")
    proc = _run(repo, "ci: rewire the gate (BACKLOG #42)")
    assert proc.returncode != 0, f"a CI-only commit escaped the claim rule:\n{proc.stdout}"


def test_an_executable_under_a_documentation_prefix_is_HELD(repo: Path) -> None:
    """MUST BLOCK. Two such files exist on the real tree today, under docs/benchmarks/results/."""
    (repo / "docs" / "bench").mkdir(parents=True)
    (repo / "docs" / "bench" / "microbench.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "docs/bench/microbench.py")
    proc = _run(repo, "perf: adjust the harness (BACKLOG #42)")
    assert proc.returncode != 0, f"a .py under docs/ escaped the claim rule:\n{proc.stdout}"


def test_the_extension_test_is_case_INSENSITIVE(repo: Path) -> None:
    """MUST BLOCK, and it did not until this arm was added.

    `_CODE_SUFFIXES` is all-lowercase, so a bare `endswith` classified `docs/Tool.PY` as documentation
    and waved it through -- the SAME FILE as `docs/tool.py`, which the arm above correctly blocks, told
    apart only by how its extension is spelled.

    THIS IS THE ORIGINAL DEFECT RESTATED AT THE SUFFIX. #1345's row names the shape it was closing --
    "a test on the SPELLING of a path standing in for a question about what the file IS" -- and the
    first fix moved that test from the prefix to the suffix without removing its dependence on
    spelling. Measured against the landed gate before this change: `docs/Tool.PY`, `docs/Tool.Py` and
    `.github/run.PS1` all read as documentation while their lowercase twins read as code."""
    (repo / "docs" / "bench").mkdir(parents=True)
    (repo / "docs" / "bench" / "Tool.PY").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "add", "docs/bench/Tool.PY")
    proc = _run(repo, "perf: adjust the harness (BACKLOG #42)")
    assert proc.returncode != 0, (
        f"an UPPERCASE .PY under docs/ escaped the claim rule while its lowercase twin does not:\n"
        f"{proc.stdout}"
    )


def test_a_markdown_only_commit_is_STILL_never_blocked(repo: Path) -> None:
    """MUST NOT BLOCK -- the twin, and the property the fix must not break.

    Banner flips and ledger reconciles cite an item without building it. A fix that made every
    docs/ path require a claim would have the gate fight the bookkeeping that keeps the backlog
    honest, which is a worse failure than the hole it closes."""
    _git(repo, "add", "docs/BACKLOG.md")
    assert _run(repo, "docs(backlog): flip banner (BACKLOG #42)").returncode == 0


def test_a_DATA_file_under_docs_is_still_documentation(repo: Path) -> None:
    """MUST NOT BLOCK. The live tree carries 61 .txt, 58 .json and 42 .csv under docs/ -- benchmark
    results and fixtures. The narrowing is to EXECUTABLE and CONFIG extensions, not to everything
    that is not markdown, because the wider rule would block a benchmark commit for no benefit."""
    (repo / "docs" / "bench").mkdir(parents=True)
    (repo / "docs" / "bench" / "results.csv").write_text("a,b\n1,2\n", encoding="utf-8")
    _git(repo, "add", "docs/bench/results.csv")
    assert _run(repo, "docs(bench): record results (BACKLOG #42)").returncode == 0


def test_the_live_tree_really_contains_files_this_guard_changes() -> None:
    """THE ANTI-VACUITY ARM. If no such file existed, every arm above would pass over a hypothetical
    and the guard would be protecting nothing -- indistinguishable, in a green run, from one that
    works."""
    root = Path(__file__).resolve().parents[1]
    listed = subprocess.run(
        ["git", "-C", str(root), "ls-files"], capture_output=True, text=True, check=True
    ).stdout.splitlines()
    assert listed, "git ls-files returned nothing -- this assertion cannot mean anything"

    reclassified = [
        p
        for p in listed
        if p.startswith((".github/", "docs/")) and p.endswith((".yml", ".yaml", ".py"))
    ]
    assert len(reclassified) >= 20, (
        f"only {len(reclassified)} file(s) sit under a documentation prefix with an executable or "
        "config extension; this guard was measured against 30"
    )
