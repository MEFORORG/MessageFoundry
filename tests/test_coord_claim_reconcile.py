# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
import sys
import time
from collections.abc import Iterator
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CLAIM = ROOT / "scripts" / "coord" / "claim.ps1"
RECONCILE = ROOT / "scripts" / "coord" / "claim-reconcile.ps1"
# The holder-present arm dot-sources the shared occupancy fence, which dot-sources its own liveness
# helper. The sandbox carries copies of both, for the same anchoring reason as the two above.
FENCE = [
    ROOT / "scripts" / "coord" / "occupancy.ps1",
    ROOT / "scripts" / "coord" / "session-registry.ps1",
]
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
    for f in FENCE:
        shutil.copy2(f, r / "scripts" / "coord" / f.name)
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def claims_dir(repo: Path) -> Path:
    d = repo / ".git" / "mefor-coord" / "claims"
    d.mkdir(parents=True, exist_ok=True)
    return d


def write_claim(
    repo: Path,
    key: str,
    holder: Path | str,
    branch: str,
    note: str = "n",
    refreshed: str | None = None,
) -> Path:
    """Write a claim file the way claim.ps1 writes one: UTF-8, no BOM, compact JSON."""
    p = claims_dir(repo) / f"{key}.json"
    claim = {
        "key": key,
        "note": note,
        "branch": branch,
        "worktree": str(holder).replace("\\", "/"),
        "claimed": "2026-08-01T00:00:00.0000000-05:00",
    }
    if refreshed is not None:
        claim["refreshed"] = refreshed
    p.write_bytes(json.dumps(claim).encode("utf-8"))
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
    """A present holder on another branch than its claim names: no merge proof is even sought."""
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


# --- The holder-present arm (BACKLOG #1784) -------------------------------------------------------
# A claim whose holder worktree STILL EXISTS and whose pull request has merged. The row measured 16 of
# 35 claims held by a directory that still existed, four of them naming a merged pull request, and
# nothing released them. Every releasing test below is paired with the shape that must NOT release.
# Keys are numeric because only a numeric key can be named by a pull request, and naming is required.

MERGED_LATER = "2099-01-01T00:00:00Z"  # after the fixture claim's 2026-08-01 stamp
MERGED_EARLIER = "2020-01-01T00:00:00Z"  # before it


@pytest.fixture
def sleeper() -> Iterator[int]:
    """A pid the fence reads as LIVE. Function-scoped, for test_worktree_prune_merged.py's reason.

    The fence calls a record STALE when its process started well before the recorded ``startedAt``,
    so each test spawns its own process and stamps the record at the same moment.
    """
    proc = subprocess.Popen(
        [sys.executable, "-c", "import time; time.sleep(900)"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )
    try:
        yield proc.pid
    finally:
        proc.kill()
        proc.wait(timeout=30)


def fence_root(tmp_path: Path, pid: int | None, cwd: Path) -> Path:
    """A Claude config root holding at most one session record.

    With a record, the fence is AVAILABLE and places that session at ``cwd``. With none, the fence
    has examined nothing and reads UNAVAILABLE, which must hold the claim rather than clear it.
    """
    cfg = tmp_path / "cfg"
    (cfg / "sessions").mkdir(parents=True, exist_ok=True)
    if pid is not None:
        rec = {
            "pid": pid,
            "sessionId": "b1784000-0000",
            "cwd": str(cwd),
            "startedAt": int(time.time() * 1000),
            "version": "2.1.220",
            "kind": "interactive",
            "entrypoint": "claude-desktop",
        }
        (cfg / "sessions" / f"{pid}.json").write_text(json.dumps(rec), encoding="utf-8")
    return cfg


def present_holder(repo: Path, name: str) -> tuple[Path, str]:
    """A worktree that stays, on its own branch, with one commit main lacks -- the squash shape.

    Also gives the sandbox a GitHub-shaped origin, because the arm scopes every gh call with --repo
    and holds the claim when it cannot. The stub ignores the value; no network is touched.
    """
    if "origin" not in git(repo, "remote").split():
        git(repo, "remote", "add", "origin", "https://github.com/example/sandbox.git")
    wt = repo.parent / f"wt-{name}"
    git(repo, "worktree", "add", "-q", str(wt), "-b", name)
    (wt / f"{name}.txt").write_text("the delivered work", encoding="utf-8")
    git(wt, "add", "-A")
    git(wt, "commit", "-qm", "the work, on the branch")
    return wt, git(wt, "rev-parse", "HEAD").strip()


def gh_router(
    tmp_path: Path,
    head: str = "[]",
    search: str = "[]",
    view: str = "{}",
    fail: bool = False,
    on_head: str = "",
) -> Path:
    """A `gh` stand-in that answers the three calls the holder-present arm makes, by their shape.

    ``pr list --head`` gets ``head``, ``pr list --search`` gets ``search``, and ``pr view`` gets
    ``view``. ``fail`` makes every call exit 1, which is "could not ask". ``on_head`` is PowerShell
    run before the --head answer: a side effect that lands AFTER the scan's local checks, so a test
    can drive the -Apply re-check deterministically. Nothing reaches GitHub.
    """
    stub = tmp_path / "gh-router.ps1"
    body = (
        "$a = $args -join ' '\n"
        "if ($a -like 'pr view*') { $out = @'\n" + view + "\n'@ }\n"
        "elseif ($a -like '*--search*') { $out = @'\n" + search + "\n'@ }\n"
        "else {\n" + on_head + "\n$out = @'\n" + head + "\n'@ }\n"
        "$out\n"
    )
    if fail:
        body = "exit 1\n"
    stub.write_text(body, encoding="utf-8")
    return stub


def pr_at(
    tip: str,
    key: str,
    number: int = 1784,
    merged: str = MERGED_LATER,
    base: str = "main",
) -> list[dict[str, object]]:
    """One merged pull request, its head at ``tip``, naming ``#<key>`` the way PR titles do."""
    return [
        {
            "number": number,
            "headRefOid": tip,
            "mergedAt": merged,
            "baseRefName": base,
            "title": f"fix: the work (BACKLOG #{key})",
            "body": "",
        }
    ]


def present(
    repo: Path, cfg: Path, stub: Path, *extra: str
) -> tuple[dict[str, str], dict[str, str]]:
    proc = reconcile(repo, "-Json", "-GhCommand", str(stub), "-ConfigRoot", str(cfg), *extra)
    assert proc.returncode == 0, proc.stderr
    claims = json.loads(proc.stdout)["claims"]
    return {c["key"]: c["verdict"] for c in claims}, {c["key"]: c["why"] for c in claims}


def test_a_present_holder_whose_merged_pr_has_its_exact_tip_is_releasable(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """The squash case: the branch's commit is NOT on main, and a merged PR's head is this tip."""
    wt, tip = present_holder(repo, "squashed-here")
    write_claim(repo, "9101", wt, "squashed-here")
    cfg = fence_root(tmp_path, sleeper, repo)  # a live session, placed in the PRIMARY
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9101"))))
    assert verdict["9101"] == "RELEASABLE", why


def test_extra_commits_beyond_the_merged_pr_head_are_not_released(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """The negative control: the PR merged an EARLIER tip, and the holder has since committed more."""
    wt, merged_tip = present_holder(repo, "moved-on-here")
    (wt / "more.txt").write_text("work after the merge", encoding="utf-8")
    git(wt, "add", "-A")
    git(wt, "commit", "-qm", "unmerged follow-up")
    write_claim(repo, "9102", wt, "moved-on-here")
    cfg = fence_root(tmp_path, sleeper, repo)
    stub = gh_router(tmp_path, head=json.dumps(pr_at(merged_tip, "9102")))
    verdict, why = present(repo, cfg, stub)
    assert verdict["9102"] == "HELD", why


def test_a_brand_new_holder_contained_in_main_is_not_released(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """Containment is not evidence here: a claim taken a minute ago has zero commits too."""
    present_holder(repo, "unrelated")  # only for the origin remote
    wt = repo.parent / "wt-fresh"
    git(repo, "worktree", "add", "-q", str(wt), "-b", "fresh")
    write_claim(repo, "9103", wt, "fresh")
    cfg = fence_root(tmp_path, sleeper, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path))
    assert verdict["9103"] == "HELD", why


def test_a_holder_stacked_on_another_builders_merged_tip_is_not_released(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """A second worktree cut at builder one's tip carries a merged tip before any work of its own.

    Found by the code-review pass on this change: without the key test it read RELEASABLE.
    """
    _one, tip = present_holder(repo, "builder-one")
    stacked = repo.parent / "wt-builder-two"
    git(repo, "worktree", "add", "-q", str(stacked), "-b", "builder-two", tip)
    write_claim(repo, "9104", stacked, "builder-two")
    cfg = fence_root(tmp_path, sleeper, repo)
    stub = gh_router(
        tmp_path, search=json.dumps(pr_at(tip, "9100"))
    )  # names builder one's key only
    verdict, why = present(repo, cfg, stub)
    assert verdict["9104"] == "MERGED-HELD", why
    assert "does not name 'BACKLOG #9104'" in why["9104"]


def test_one_merged_pr_releases_only_the_key_it_names(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """One holder, two keys, one merged PR naming one of them. The other key guards unstarted work."""
    wt, tip = present_holder(repo, "two-keys")
    write_claim(repo, "9105", wt, "two-keys")
    write_claim(repo, "9106", wt, "two-keys")
    cfg = fence_root(tmp_path, sleeper, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9105"))))
    assert verdict["9105"] == "RELEASABLE", why
    assert verdict["9106"] == "MERGED-HELD", why


def test_a_free_text_key_is_never_released_on_a_merge(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    wt, tip = present_holder(repo, "free-text")
    write_claim(repo, "tidy-the-docs", wt, "free-text")
    cfg = fence_root(tmp_path, sleeper, repo)
    stub = gh_router(tmp_path, head=json.dumps(pr_at(tip, "tidy-the-docs")))
    verdict, why = present(repo, cfg, stub)
    assert verdict["tidy-the-docs"] == "HELD", why


@pytest.mark.parametrize("dirt", ["tracked", "untracked", "untracked-hidden-by-config"])
def test_a_dirty_holder_is_held_before_any_probe(
    repo: Path, tmp_path: Path, sleeper: int, dirt: str
) -> None:
    """Local disqualifiers run first. The hidden case sets status.showUntrackedFiles=no."""
    wt, tip = present_holder(repo, f"dirty-{dirt}")
    if dirt == "tracked":
        (wt / f"dirty-{dirt}.txt").write_text("edited after the merge", encoding="utf-8")
    else:
        (wt / "brand_new_module.py").write_text("# never committed\n", encoding="utf-8")
    if dirt == "untracked-hidden-by-config":
        git(repo, "config", "status.showUntrackedFiles", "no")
    write_claim(repo, "9107", wt, f"dirty-{dirt}")
    cfg = fence_root(tmp_path, sleeper, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9107"))))
    assert verdict["9107"] == "HELD", why
    assert "uncommitted change(s) or untracked file(s)" in why["9107"]


def test_an_occupied_holder_is_held(repo: Path, tmp_path: Path, sleeper: int) -> None:
    wt, tip = present_holder(repo, "occupied")
    write_claim(repo, "9108", wt, "occupied")
    cfg = fence_root(tmp_path, sleeper, wt)  # the live session is IN the holder
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9108"))))
    assert verdict["9108"] == "HELD", why
    assert "LIVE" in why["9108"]


def test_an_unavailable_fence_holds_rather_than_clears(repo: Path, tmp_path: Path) -> None:
    """No session record examined is "could not look", never "nobody is there"."""
    wt, tip = present_holder(repo, "blind")
    write_claim(repo, "9109", wt, "blind")
    cfg = fence_root(tmp_path, None, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9109"))))
    assert verdict["9109"] == "HELD", why
    assert "UNAVAILABLE" in why["9109"]


def test_a_locked_holder_is_held(repo: Path, tmp_path: Path, sleeper: int) -> None:
    wt, tip = present_holder(repo, "locked-here")
    git(repo, "worktree", "lock", "--reason", "in use", str(wt))
    write_claim(repo, "9110", wt, "locked-here")
    cfg = fence_root(tmp_path, sleeper, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9110"))))
    assert verdict["9110"] == "HELD", why
    assert "locked" in why["9110"]


def test_a_claim_taken_after_the_merge_is_merged_held(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """The tip proves what merged, and nothing about a claim somebody took afterwards."""
    wt, tip = present_holder(repo, "late-claim")
    write_claim(repo, "9111", wt, "late-claim")
    cfg = fence_root(tmp_path, sleeper, repo)
    stub = gh_router(tmp_path, head=json.dumps(pr_at(tip, "9111", merged=MERGED_EARLIER)))
    verdict, why = present(repo, cfg, stub)
    assert verdict["9111"] == "MERGED-HELD", why
    assert "after the merge" in why["9111"]


def test_a_claim_re_taken_after_the_merge_is_merged_held(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """claim.ps1 never moves `claimed` on a re-take; `refreshed` is the post-merge assertion."""
    wt, tip = present_holder(repo, "re-taken")
    write_claim(repo, "9112", wt, "re-taken", refreshed="2099-06-01T00:00:00.0000000+00:00")
    cfg = fence_root(tmp_path, sleeper, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9112"))))
    assert verdict["9112"] == "MERGED-HELD", why
    assert "refreshed" in why["9112"]


def test_a_pr_merged_into_another_base_does_not_release(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """A stacked PR merged into its parent branch says nothing about main."""
    wt, tip = present_holder(repo, "stacked-pr")
    write_claim(repo, "9113", wt, "stacked-pr")
    cfg = fence_root(tmp_path, sleeper, repo)
    stub = gh_router(tmp_path, head=json.dumps(pr_at(tip, "9113", base="parent-feature")))
    verdict, why = present(repo, cfg, stub)
    assert verdict["9113"] == "HELD", why


def test_a_probe_that_cannot_answer_holds(repo: Path, tmp_path: Path, sleeper: int) -> None:
    wt, _tip = present_holder(repo, "gh-down")
    write_claim(repo, "9114", wt, "gh-down")
    cfg = fence_root(tmp_path, sleeper, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path, fail=True))
    assert verdict["9114"] == "HELD", why
    assert "could NOT be established" in why["9114"]


def test_a_wave_pr_carrying_the_tip_as_one_of_its_commits_is_releasable(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """A Manager's wave PR merges several builder branches, so the tip is a commit, not the head."""
    wt, tip = present_holder(repo, "wave-builder")
    write_claim(repo, "9115", wt, "wave-builder")
    cfg = fence_root(tmp_path, sleeper, repo)
    wave_head = "1" * 40
    wave = pr_at(wave_head, "9115", number=1600)
    wave[0]["body"] = "Wave 147: BACKLOG #9115, BACKLOG #9116"
    wave[0]["title"] = "wave 147"
    stub = gh_router(
        tmp_path,
        head="[]",
        search=json.dumps(wave),
        view=json.dumps({"commits": [{"oid": "2" * 40}, {"oid": tip}, {"oid": wave_head}]}),
    )
    verdict, why = present(repo, cfg, stub)
    assert verdict["9115"] == "RELEASABLE", why
    assert "PR #1600" in why["9115"]


def test_a_search_hit_whose_commit_list_lacks_the_tip_does_not_release(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """The search only nominates. Without the full oid in the PR's own commits, nothing is proven."""
    wt, _tip = present_holder(repo, "wave-miss")
    write_claim(repo, "9117", wt, "wave-miss")
    cfg = fence_root(tmp_path, sleeper, repo)
    stub = gh_router(
        tmp_path,
        search=json.dumps(pr_at("1" * 40, "9117", number=1601)),
        view=json.dumps({"commits": [{"oid": "2" * 40}]}),
    )
    verdict, why = present(repo, cfg, stub)
    assert verdict["9117"] == "HELD", why


def test_a_note_naming_its_OWN_holder_does_not_withdraw_the_release(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """ELSEWHERE means another worktree, even one whose leaf is a substring of the holder's leaf."""
    live_worktree(repo, "wt-mgr")  # a live sibling whose leaf is inside the holder's leaf
    wt, tip = present_holder(repo, "mgr-b147")  # leaf: wt-mgr-b147
    write_claim(repo, "9118", wt, "mgr-b147", note=f"ROLE=builder in {wt.name} at {tip[:12]}")
    cfg = fence_root(tmp_path, sleeper, repo)
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr_at(tip, "9118"))))
    assert verdict["9118"] == "RELEASABLE", why


def test_apply_releases_a_finished_present_holder_and_leaves_the_worktree(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    done_wt, done_tip = present_holder(repo, "done-here")
    busy_wt, busy_tip = present_holder(repo, "busy-here")
    (busy_wt / "busy-here.txt").write_text("still editing", encoding="utf-8")
    done = write_claim(repo, "9119", done_wt, "done-here")
    busy = write_claim(repo, "9120", busy_wt, "busy-here")
    cfg = fence_root(tmp_path, sleeper, repo)
    both = pr_at(done_tip, "9119", number=1) + pr_at(busy_tip, "9120", number=2)
    stub = gh_router(tmp_path, head=json.dumps(both))
    proc = reconcile(repo, "-Apply", "-GhCommand", str(stub), "-ConfigRoot", str(cfg))
    assert proc.returncode == 0, proc.stderr

    assert not done.exists(), proc.stdout
    assert busy.exists(), "a dirty holder's claim must survive -Apply"
    assert done_wt.exists(), "releasing a claim must never touch the worktree itself"

    records = [
        json.loads(line)
        for line in (claims_dir(repo) / ".history").read_text(encoding="utf-8").splitlines()
    ]
    assert [r["key"] for r in records] == ["9119"]
    # -AsWorktree without -Force, so claim.ps1 re-tests ownership itself; the actor is invoked_from.
    assert records[0]["force"] is False
    assert records[0]["prior_branch"] == "done-here"
    assert Path(records[0]["released_by"]).resolve() == done_wt.resolve()
    assert Path(records[0]["invoked_from"]).resolve() == repo.resolve()


def test_apply_rechecks_a_holder_that_changed_after_the_scan(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """The re-check, driven by a gh stub whose --head answer first drops a new file in the holder.

    The scan's local checks run BEFORE that call, so the scan sees a clean holder and reads
    RELEASABLE. The -Apply re-check must then see the new file and keep the claim. The positive
    control in the same run is a second holder the side effect does not touch, which IS released.
    """
    moved_wt, moved_tip = present_holder(repo, "moved-after")
    still_wt, still_tip = present_holder(repo, "still-done")
    moved = write_claim(repo, "9121", moved_wt, "moved-after")
    still = write_claim(repo, "9122", still_wt, "still-done")
    cfg = fence_root(tmp_path, sleeper, repo)
    both = pr_at(moved_tip, "9121", number=1) + pr_at(still_tip, "9122", number=2)
    new_file = str(moved_wt / "arrived_after_the_scan.py").replace("'", "''")
    stub = gh_router(
        tmp_path,
        head=json.dumps(both),
        on_head=f"Set-Content -LiteralPath '{new_file}' -Value 'x'",
    )
    proc = reconcile(repo, "-Json", "-Apply", "-GhCommand", str(stub), "-ConfigRoot", str(cfg))
    assert proc.returncode == 0, proc.stderr
    out = {c["key"]: c for c in json.loads(proc.stdout)["claims"]}

    assert moved.exists(), "a holder that changed after the scan must keep its claim"
    assert out["9121"]["verdict"] == "MERGED-HELD", out["9121"]
    assert "changed since the scan" in out["9121"]["why"]
    assert not still.exists(), "the untouched holder is the positive control"
    assert out["9122"]["verdict"] == "RELEASABLE"
    assert out["9122"]["outcome"] == "released", "the JSON carries each release's outcome"


def test_a_bare_hash_number_does_not_name_the_key(repo: Path, tmp_path: Path, sleeper: int) -> None:
    """On the engine repository a bare `#N` is as often a pull request number as an item."""
    wt, tip = present_holder(repo, "bare-hash")
    write_claim(repo, "9123", wt, "bare-hash")
    cfg = fence_root(tmp_path, sleeper, repo)
    pr = pr_at(tip, "9123")
    pr[0]["title"] = "fix: the work, follows #9123"
    verdict, why = present(repo, cfg, gh_router(tmp_path, head=json.dumps(pr)))
    assert verdict["9123"] == "MERGED-HELD", why


def test_the_pr_that_names_the_key_counts_when_several_carry_the_tip(
    repo: Path, tmp_path: Path, sleeper: int
) -> None:
    """The builder's own PR names another item; the wave PR that also carries the tip names this one."""
    wt, tip = present_holder(repo, "two-prs")
    write_claim(repo, "9124", wt, "two-prs")
    cfg = fence_root(tmp_path, sleeper, repo)
    wave = pr_at("1" * 40, "9124", number=1700)
    stub = gh_router(
        tmp_path,
        head=json.dumps(pr_at(tip, "9000", number=1699)),
        search=json.dumps(wave),
        view=json.dumps({"commits": [{"oid": tip}, {"oid": "1" * 40}]}),
    )
    verdict, why = present(repo, cfg, stub)
    assert verdict["9124"] == "RELEASABLE", why
    assert "PR #1700" in why["9124"]


def test_a_note_naming_a_live_worktree_whose_name_extends_the_holders_still_withdraws(
    repo: Path, tmp_path: Path
) -> None:
    """The negative control for the whole-name match: gone `vanished`, live `vanished-2`."""
    landed_branch(repo, "landed")
    live_worktree(repo, "vanished-2")
    write_claim(
        repo, "k-prefix", tmp_path / "vanished", "landed", note="CHECKING vanished-2 before release"
    )
    assert verdicts(repo)["k-prefix"] == "NOTE-POINTS-ELSEWHERE"


def test_apply_with_claims_dir_is_refused(repo: Path, tmp_path: Path) -> None:
    """-ClaimsDir audits a copy; a release would delete the LIVE claim under the same key."""
    landed_branch(repo, "landed")
    live = write_claim(repo, "k-live-copy", tmp_path / "vanished", "landed")
    audit = tmp_path / "audit"
    audit.mkdir()
    shutil.copy2(live, audit / live.name)
    proc = reconcile(repo, "-Apply", "-ClaimsDir", str(audit))
    assert proc.returncode == 2, proc.stdout
    assert live.exists()
