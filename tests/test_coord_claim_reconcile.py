# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A stranded claim is released only on evidence, and the evidence has two halves.

``prune-merged.ps1`` releases the claims held by a worktree it removes (BACKLOG #345). It can do
that safely because of what it has already proven: it only removes a worktree that is merged AND
clean AND unoccupied, so the claim it drops guards nothing. Every other removal path -- a manual
``git worktree remove``, ``git worktree prune``, deleting the folder, bulk cleanup by explicit path
list -- strands the claim with no such proof, and ``claim.ps1 -Take`` then hard-blocks the key for
every future session.

``claim-reconcile.ps1`` sweeps for those, and the tests below exist to pin the asymmetry that makes
it safe. Measured on this repository 2026-08-16: 33 of 56 claims were held by worktrees that no
longer existed, and **17 of those sat on branches carrying unmerged commits** -- including the only
copy of a fix for a live fail-open in a shipped safety control. A sweep that released on "holder
gone" alone would have freed every one of them for a second session to rebuild.

So every releasing test below is paired with the case that would ALSO pass if the tool simply
released whatever it could not see -- a gone holder whose work is unmerged, a gone holder still
registered, a claim it could not read. Those must survive untouched, and the default path must write
nothing at all.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAIM = ROOT / "scripts" / "coord" / "claim.ps1"
RECONCILE = ROOT / "scripts" / "coord" / "claim-reconcile.ps1"
TIMEOUT = 90

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="claim-reconcile.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A sandbox carrying its OWN copies -- both scripts anchor on where they live (BACKLOG #1060)."""
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    shutil.copy2(CLAIM, r / "scripts" / "coord" / "claim.ps1")
    shutil.copy2(RECONCILE, r / "scripts" / "coord" / "claim-reconcile.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def claims_dir(repo: Path) -> Path:
    d = repo / ".git" / "mefor-coord" / "claims"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_claim(repo: Path, key: str, holder: Path | str, branch: str, note: str = "n") -> Path:
    """Write a claim file the way claim.ps1 writes one: UTF-8, no BOM, compact JSON."""
    p = claims_dir(repo) / f"{key}.json"
    p.write_bytes(
        json.dumps(
            {
                "key": key,
                "note": note,
                "branch": branch,
                "worktree": str(holder).replace("\\", "/"),
                "claimed": "2026-08-01T00:00:00.0000000-05:00",
            }
        ).encode("utf-8")
    )
    return p


def reconcile(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "claim-reconcile.ps1"),
            *args,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
    )


def verdicts(repo: Path, *args: str) -> dict[str, str]:
    proc = reconcile(repo, "-Json", *args)
    assert proc.returncode == 0, proc.stderr
    return {c["key"]: c["verdict"] for c in json.loads(proc.stdout)["claims"]}


def landed_branch(repo: Path, name: str) -> None:
    """A branch that carries nothing main lacks -- the shape of work that already merged."""
    git(repo, "branch", name, "main")


def unmerged_branch(repo: Path, name: str) -> None:
    """A branch with a commit of its own. This is what must never be released."""
    git(repo, "branch", name, "main")
    git(repo, "worktree", "add", "-q", str(repo.parent / f"wt-{name}"), name)
    wt = repo.parent / f"wt-{name}"
    (wt / "work.txt").write_text("real work", encoding="utf-8")
    git(wt, "add", "-A")
    git(wt, "commit", "-qm", "work that exists nowhere else")
    git(repo, "worktree", "remove", "--force", str(wt))


def test_a_gone_holder_whose_work_landed_is_releasable(repo: Path, tmp_path: Path) -> None:
    landed_branch(repo, "landed")
    write_claim(repo, "k-landed", tmp_path / "vanished", "landed")
    assert verdicts(repo)["k-landed"] == "RELEASABLE"


def test_a_gone_holder_whose_work_is_unmerged_is_held(repo: Path, tmp_path: Path) -> None:
    """The pairing that matters: same gone holder, different work state, opposite verdict."""
    unmerged_branch(repo, "unmerged")
    write_claim(repo, "k-unmerged", tmp_path / "vanished", "unmerged")
    assert verdicts(repo)["k-unmerged"] == "HOLD"


def test_a_present_holder_is_never_touched(repo: Path) -> None:
    landed_branch(repo, "present-work")
    write_claim(repo, "k-present", repo, "present-work")
    assert verdicts(repo)["k-present"] == "HELD"


def test_a_gone_holder_that_is_still_registered_is_not_released(repo: Path) -> None:
    """Half a removal is prune-merged's job: the registration is evidence it was never completed."""
    ghost = repo.parent / "ghost"
    git(repo, "worktree", "add", "-q", str(ghost), "-b", "ghost-branch")
    shutil.rmtree(ghost)  # directory gone, registration intact
    write_claim(repo, "k-ghost", ghost, "ghost-branch")
    assert verdicts(repo)["k-ghost"] == "STRANDED-REGISTERED"


def test_an_unreadable_claim_is_reported_and_never_released(repo: Path) -> None:
    (claims_dir(repo) / "k-broken.json").write_text("{not json", encoding="utf-8")
    assert verdicts(repo)["k-broken"] == "UNREADABLE"


def test_a_claim_naming_a_branch_that_exists_nowhere_is_unknown(repo: Path, tmp_path: Path) -> None:
    """Squash-merged-and-deleted and deleted-unmerged are indistinguishable here, so neither wins."""
    write_claim(repo, "k-noref", tmp_path / "vanished", "branch-that-never-was")
    assert verdicts(repo)["k-noref"] == "STRANDED-UNKNOWN"


def test_the_default_path_writes_nothing(repo: Path, tmp_path: Path) -> None:
    landed_branch(repo, "landed")
    p = write_claim(repo, "k-landed", tmp_path / "vanished", "landed")
    before = p.read_bytes()
    assert reconcile(repo).returncode == 0
    assert p.exists() and p.read_bytes() == before
    assert not (claims_dir(repo) / ".history").exists()


def test_apply_releases_only_the_releasable_and_records_each_one(
    repo: Path, tmp_path: Path
) -> None:
    landed_branch(repo, "landed")
    unmerged_branch(repo, "unmerged")
    releasable = write_claim(repo, "k-landed", tmp_path / "vanished", "landed")
    guarded = write_claim(repo, "k-unmerged", tmp_path / "vanished", "unmerged")

    proc = reconcile(repo, "-Apply")
    assert proc.returncode == 0, proc.stderr

    assert not releasable.exists(), "the releasable claim should be gone"
    assert guarded.exists(), "a claim guarding unmerged work must survive -Apply"

    history = (claims_dir(repo) / ".history").read_text(encoding="utf-8").strip().splitlines()
    records = [json.loads(line) for line in history]
    assert [r["key"] for r in records] == ["k-landed"]
    assert records[0]["event"] == "release"
    assert records[0]["force"] is True
    assert records[0]["prior_branch"] == "landed"


def _gh_stub(tmp_path: Path, payload: str) -> Path:
    """Stand-in for `gh`. Ignores its arguments and prints one canned JSON document."""
    stub = tmp_path / "gh-stub.ps1"
    stub.write_text(f"param()\n@'\n{payload}\n'@\n", encoding="utf-8")
    return stub


def test_a_squash_merged_branch_is_releasable_when_a_merged_pr_has_its_tip(
    repo: Path, tmp_path: Path
) -> None:
    """The third arm, and the reason it exists: a squash leaves NO commit in common.

    Measured on this repository: a branch squash-merged as PR #346 still carried 13 commits
    origin/main lacked, so the local test alone held all five of its claims forever.
    """
    unmerged_branch(repo, "squashed")
    tip = git(repo, "rev-parse", "squashed").strip()
    write_claim(repo, "k-squashed", tmp_path / "vanished", "squashed")
    stub = _gh_stub(
        tmp_path, f'[{{"number":346,"headRefOid":"{tip}","mergedAt":"2026-08-12T17:45:36Z"}}]'
    )

    out = verdicts(repo, "-GhCommand", str(stub))
    assert out["k-squashed"] == "RELEASABLE"


def test_a_merged_pr_at_a_DIFFERENT_tip_does_not_release(repo: Path, tmp_path: Path) -> None:
    """A PR proves some earlier state landed -- not the state this claim is guarding."""
    unmerged_branch(repo, "moved-on")
    write_claim(repo, "k-moved", tmp_path / "vanished", "moved-on")
    stub = _gh_stub(
        tmp_path,
        '[{"number":1,"headRefOid":"0000000000000000000000000000000000000000","mergedAt":"2026-08-01T00:00:00Z"}]',
    )

    assert verdicts(repo, "-GhCommand", str(stub))["k-moved"] == "HOLD"


def test_an_unreachable_probe_holds_rather_than_downgrading_to_unknown(
    repo: Path, tmp_path: Path
) -> None:
    unmerged_branch(repo, "unreachable")
    write_claim(repo, "k-unreachable", tmp_path / "vanished", "unreachable")
    assert verdicts(repo, "-NoPullRequests")["k-unreachable"] == "HOLD"
