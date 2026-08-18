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
# Deliberately BELOW pytest's own bound. addopts carries --timeout=60 and CI overrides per leg
# (60 on ubuntu, 120 on Windows), so a 90s guard fired first on Windows and never on ubuntu --
# live on one platform, decorative on the other, and silently so. A backstop is only worth
# having if it is the FIRST thing to fire, because then the failure says 'a pwsh spawn hung'
# instead of pytest's generic timeout. Measured worst case is ~1.3s per test.
TIMEOUT = 45

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


def live_worktree(repo: Path, name: str) -> str:
    """A worktree that stays: registered AND present, so its leaf name is a live reference."""
    path = repo.parent / name
    git(repo, "worktree", "add", "-q", str(path), "-b", f"{name}-branch")
    return name


def test_a_note_naming_a_LIVE_worktree_withdraws_the_release(repo: Path, tmp_path: Path) -> None:
    """Found by a peer on the real registry, and the three tests above cannot see it.

    Claim 1020's ``worktree`` field names a directory that is gone while its note pins the head of a
    DIFFERENT directory that is present and carries unmerged commits. Path matching is blind to that
    association. 1020 itself lands on HOLD only because its branch work is unmerged -- the dangerous
    shape is a claim whose branch HAS landed while its note points at live work elsewhere, which
    passes every other test here.
    """
    landed_branch(repo, "landed")
    leaf = live_worktree(repo, "sibling-alive")
    write_claim(
        repo, "k-note", tmp_path / "vanished", "landed", note=f"CHECKING {leaf} before release"
    )
    assert verdicts(repo)["k-note"] == "NOTE-POINTS-ELSEWHERE"


def test_a_note_pinning_a_sha_reachable_from_a_LIVE_worktree_withdraws(
    repo: Path, tmp_path: Path
) -> None:
    """The 1010 case, and the rule is LIVENESS rather than merged-ness."""
    leaf = live_worktree(repo, "still-working")
    wt = repo.parent / leaf
    (wt / "wip.txt").write_text("in progress", encoding="utf-8")
    git(wt, "add", "-A")
    git(wt, "commit", "-qm", "work in progress")
    sha = git(wt, "rev-parse", "HEAD").strip()

    landed_branch(repo, "landed")
    write_claim(repo, "k-live", tmp_path / "vanished", "landed", note=f"CHECKING {sha[:12]}")
    assert verdicts(repo)["k-live"] == "NOTE-POINTS-ELSEWHERE"


def test_a_note_pinning_a_sha_on_a_DEAD_branch_still_releases(repo: Path, tmp_path: Path) -> None:
    """The false positive that a peer's release of 11 claims exposed, on its first outing.

    The rule was once "the sha is not on origin/main". A squash leaves a branch's own commits off
    main forever, so a note citing its own work sha always looked like it pointed elsewhere: it
    blocked 1241 (its own squash-merged branch) and adr-0158-land (a branch that is on origin), both
    wrongly, while the case the guard exists for -- 1010, pinning a sha on a worktree that is ALIVE
    -- was the one it caught. Two false positives and one true one, and the difference is liveness.
    """
    unmerged_branch(repo, "dead-branch")  # committed, then its worktree removed
    sha = git(repo, "rev-parse", "dead-branch").strip()
    landed_branch(repo, "landed")
    write_claim(repo, "k-dead", tmp_path / "vanished", "landed", note=f"work was at {sha[:12]}")
    assert verdicts(repo)["k-dead"] == "RELEASABLE"


def test_an_ordinary_note_still_releases(repo: Path, tmp_path: Path) -> None:
    """The negative control: the guard must not swallow every releasable claim."""
    landed_branch(repo, "landed")
    write_claim(
        repo, "k-plain", tmp_path / "vanished", "landed", note="ROLE=builder2; tidy up docs"
    )
    assert verdicts(repo)["k-plain"] == "RELEASABLE"


def test_the_script_carries_no_control_characters() -> None:
    """An escape that collapses into a control byte is invisible in every normal view.

    2026-08-16: `\b` was written into a regex in claim-reconcile.ps1 as a literal backspace (0x08).
    The pattern then matched nothing, silently, and the debug line that appeared to prove it worked
    had the pattern retyped by hand -- so the instrument measured a different regex than the code
    ran. Nothing about the file looked wrong; `cat -A` was the only view that showed it.
    """
    text = RECONCILE.read_text(encoding="utf-8")
    bad = {hex(ord(c)) for c in text if ord(c) < 32 and c not in "\r\n\t"}
    assert not bad, f"control characters in claim-reconcile.ps1: {sorted(bad)}"


def test_a_branch_whose_files_match_the_LANDING_commit_is_releasable(
    repo: Path, tmp_path: Path
) -> None:
    """Arm four. Identical AT THE POINT IT LANDED, not identical to main today.

    Comparing a branch to current main holds work that landed: main moves on, the files are edited
    again, and a branch merged days ago stops matching. Measured on the live registry 2026-08-16 --
    claude/adr-0158-land had 0 of 2 files identical to main while the same blobs were identical to
    the squash commit that landed them, 400-plus commits back. Both true; only one answers the
    question. Found by the peer session running patch-id and blob identity side by side.

    The fixture is the real shape: a branch, a SEPARATE squash commit on main carrying the same
    content, and then main moving on so a comparison against its HEAD would say "did not land".
    """
    git(repo, "branch", "feature", "main")
    git(repo, "worktree", "add", "-q", str(repo.parent / "wt-feature"), "feature")
    wt = repo.parent / "wt-feature"
    (wt / "work.txt").write_text("the delivered work", encoding="utf-8")
    git(wt, "add", "-A")
    git(wt, "commit", "-qm", "the work, on the branch")
    git(repo, "worktree", "remove", "--force", str(wt))

    # the squash: a different commit on main with byte-identical content
    (repo / "work.txt").write_text("the delivered work", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "squash of the branch (#346)")
    landing = git(repo, "rev-parse", "HEAD").strip()

    # main moves on, and edits the same file, so today's blobs no longer match the branch
    (repo / "work.txt").write_text("the delivered work, since revised", encoding="utf-8")
    git(repo, "add", "-A")
    git(repo, "commit", "-qm", "main moves on and edits the same file")

    write_claim(repo, "k-landing", tmp_path / "vanished", "feature")
    stub = _gh_stub(
        tmp_path,
        '[{"number":346,"headRefOid":"0000000000000000000000000000000000000000",'
        f'"mergedAt":"2026-08-12T17:45:36Z","mergeCommit":{{"oid":"{landing}"}}}}]',
    )
    out = verdicts(repo, "-GhCommand", str(stub))
    assert out["k-landing"] == "RELEASABLE", out


def test_a_merged_pr_with_no_readable_landing_commit_holds(repo: Path, tmp_path: Path) -> None:
    """The negative control for arm four: a PR at another tip proves an earlier state landed."""
    unmerged_branch(repo, "other-tip")
    write_claim(repo, "k-other", tmp_path / "vanished", "other-tip")
    stub = _gh_stub(
        tmp_path,
        '[{"number":1,"headRefOid":"0000000000000000000000000000000000000000",'
        '"mergedAt":"2026-08-01T00:00:00Z","mergeCommit":{"oid":""}}]',
    )
    assert verdicts(repo, "-GhCommand", str(stub))["k-other"] == "HOLD"


def test_claims_dir_can_audit_a_set_that_is_not_the_live_registry(
    repo: Path, tmp_path: Path
) -> None:
    """Replaying the rules over ALREADY-RELEASED claims, reconstructed from the ledger.

    A release performed by another session cannot be cross-checked against the registry, because the
    claim files are gone by definition. Rebuilding them from claims/.history and pointing this tool
    at the copy is how one instrument checks another without a second implementation of the rules --
    and two implementations of one rule are two rules by the end of the week.
    """
    landed_branch(repo, "landed")
    audit = tmp_path / "reconstructed"
    audit.mkdir()
    (audit / "k-gone.json").write_bytes(
        json.dumps(
            {
                "key": "k-gone",
                "note": "reconstructed from a release record",
                "branch": "landed",
                "worktree": str(tmp_path / "vanished").replace("\\", "/"),
                "claimed": "2026-08-01T00:00:00.0000000-05:00",
            }
        ).encode("utf-8")
    )
    out = verdicts(repo, "-ClaimsDir", str(audit))
    assert out == {"k-gone": "RELEASABLE"}, out
