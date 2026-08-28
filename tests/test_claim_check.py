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


# ------------------------------------- BACKLOG #1346: the registry the writer writes, not the reader's


def _second_repo(tmp_path: Path) -> Path:
    """A repository that is NOT the one claim.ps1 writes to -- the vault's shape, in miniature."""
    r = tmp_path / "other"
    r.mkdir()
    _git(r, "init", "-q", "-b", "main")
    _git(r, "config", "user.email", "t@example.com")
    _git(r, "config", "user.name", "t")
    (r / "seed.txt").write_text("s\n", encoding="utf-8")
    _git(r, "add", "-A")
    _git(r, "commit", "-q", "-m", "seed")
    (r / "code.py").write_text("x = 1\n", encoding="utf-8")
    return r


def test_a_repo_with_NO_registry_is_told_WHY_claiming_will_not_help(
    tmp_path: Path, repo: Path
) -> None:
    """BACKLOG #1346. THE ITEM.

    ``claim.ps1`` is anchored on its own location, so it always records against the ENGINE checkout.
    This hook resolved from the COMMITTING repository, so anywhere else it read a directory that does
    not exist and refused every code-touching commit citing an item -- with no spelling that could ever
    satisfy it. Measured on the live vault: ``mefor-coord/`` present with alloc, mail and test-slots,
    ``claims/`` absent, and its ``commit-msg`` hook does exec this file.

    The refusal must still happen. What must change is that it becomes ANSWERABLE.
    """
    other = _second_repo(tmp_path)
    _git(other, "add", "code.py")
    r = _run(other, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 1
    assert "The claim REGISTRY does not exist here" in r.stderr
    assert "mefor.claimsDir" in r.stderr, "the remedy must name the knob that fixes it"


def test_the_registry_note_is_APPENDED_not_substituted(tmp_path: Path, repo: Path) -> None:
    """The familiar advice must survive. An absent registry and an unclaimed item are NOT
    distinguishable from inside this hook -- a fresh engine checkout that has simply never had a claim
    written also has no directory, and there ``NOT CLAIMED, run claim.ps1`` is exactly right.

    A first version of this fix BRANCHED instead, replacing the message, and the existing
    ``test_unclaimed_item_with_code_is_blocked`` caught it. That test was right and this row records why.
    """
    other = _second_repo(tmp_path)
    _git(other, "add", "code.py")
    r = _run(other, "feat(x): build it (BACKLOG #42)")
    assert "NOT CLAIMED" in r.stderr, "the ordinary advice must not be replaced"
    assert "claim.ps1 -Take 42" in r.stderr
    assert "The claim REGISTRY does not exist here" in r.stderr


def test_the_registry_note_is_SILENT_when_the_registry_exists(repo: Path) -> None:
    """NARROWNESS. The note must appear only where it is true.

    Without this the line prints on every refusal in the engine, where it is false and where a reader
    who acts on it points a working repository at someone else's registry.
    """
    _claims_dir(repo)  # creates it
    _git(repo, "add", "code.py")
    r = _run(repo, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 1
    assert "NOT CLAIMED" in r.stderr
    assert "The claim REGISTRY does not exist here" not in r.stderr


def test_mefor_claimsDir_lets_one_registry_serve_a_second_repository(
    tmp_path: Path, repo: Path
) -> None:
    """The half that makes the gate SATISFIABLE, which is what the item asks for.

    A BACKLOG number is an ENGINE ledger number, so one registry serving both repositories is the
    correct shape rather than a workaround: two registries would let one item be claimed twice, in two
    places, with neither able to see the other.
    """
    other = _second_repo(tmp_path)
    shared = _claims_dir(repo)
    rec = {
        "key": "42",
        "note": "test",
        "branch": "b",
        "worktree": _toplevel(other),
        "claimed": "2026-07-24T12:00:00.0000000-05:00",
    }
    (shared / "42.json").write_bytes(json.dumps(rec, separators=(",", ":")).encode("utf-8"))
    _git(other, "config", "mefor.claimsDir", str(shared))
    _git(other, "add", "code.py")
    r = _run(other, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 0, (
        f"a claim held in the shared registry must satisfy the gate: {r.stderr}"
    )


def test_mefor_claimsDir_pointing_somewhere_UNCLAIMED_still_refuses(
    tmp_path: Path, repo: Path
) -> None:
    """The control without which the row above is satisfied by a knob that disables the gate.

    Naming a registry must not mean passing. It must mean LOOKING THERE.
    """
    other = _second_repo(tmp_path)
    shared = _claims_dir(repo)  # exists, but holds no claim for 42
    _git(other, "config", "mefor.claimsDir", str(shared))
    _git(other, "add", "code.py")
    r = _run(other, "feat(x): build it (BACKLOG #42)")
    assert r.returncode == 1
    assert "NOT CLAIMED" in r.stderr
    assert "The claim REGISTRY does not exist here" not in r.stderr, (
        "the registry exists; only the claim is missing"
    )


def test_a_docs_only_commit_is_STILL_never_blocked_with_no_registry(
    tmp_path: Path, repo: Path
) -> None:
    """The stand-down must run BEFORE any of this. An absent registry must not start blocking ledger
    and documentation work, which is the one thing this gate has always promised not to touch."""
    other = _second_repo(tmp_path)
    (other / "docs").mkdir()
    (other / "docs" / "BACKLOG.md").write_text("# backlog\n", encoding="utf-8")
    _git(other, "add", "docs/BACKLOG.md")
    r = _run(other, "docs(ledger): flip the banner (BACKLOG #42)")
    assert r.returncode == 0, f"a docs-only commit must never be blocked: {r.stderr}"
