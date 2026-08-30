# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A rescue ref must be verifiable WITHOUT the branch it names (BACKLOG #1349).

A rescue ref is consulted once, in the moment the original is already gone -- so it is the one
instrument whose failure surfaces only when it is too late to fix. The item's two controls are the
two tests this file exists for:

  1. a ref written for a branch that is then ADVANCED must fail a tip check
  2. a ref must be verifiable after the branch it names is GONE

**AND CONTROL 2 IS NOT SATISFIED BY A SINGLE VERDICT.** The first version of this suite asserted
only that a ref whose branch is gone comes back ``SELF-DESCRIBING``. Two materially different refs
-- one that held the tip, one captured SHORT of it -- then produced byte-identical rows, because
``-Anchor`` recorded ``was-tip`` and ``-Check`` never read it. That is the item's own defect
surviving inside its fix, in exactly the population the fix is for, so the branch-gone arm is now
driven with BOTH refs at once and the two are required to differ.

**EVERY VERDICT IS ASSERTED SEPARATELY AND THEY MUST DIFFER.** Against the live repository every
rescue ref that already exists reports ``UNVERIFIABLE`` -- correctly, because none carries
provenance -- and a suite that only saw that state could not tell a working classifier from one
that returns a constant. A uniform output is exactly the shape a dead instrument produces, so each
arm is driven to a DIFFERENT verdict here.

**THE FIXTURE IS A REAL REPOSITORY, NOT A MOCK.** The behaviour under test is git's -- annotated tag
dereference, ancestor arithmetic, a deleted branch -- and a fake would be asserting this file's own
model of git rather than git.

**VERIFYING A REVERT OF ``rescue.ps1`` USES THE BLOB ID, NEVER A FILE HASH.** ``core.autocrlf=true``
in this repository and no ``.gitattributes`` rule covers ``scripts/coord/*.ps1``, so ``git checkout
--`` writes the file back with CRLF while the committed blob is LF. A raw ``sha256`` of the working
copy therefore reads as drift against a file that is provably unchanged. ``git diff --exit-code``
and ``git hash-object --path <p> <p>`` answer the byte-identity question; a file digest answers an
adjacent one (SDS-3.8). This matters to anyone mutation-testing the script and restoring it between
cycles, which is how these tests were checked for discrimination.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

_ROOT = Path(__file__).resolve().parents[1]
_RESCUE = _ROOT / "scripts" / "coord" / "rescue.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)


def _git(*args: str, cwd: Path) -> str:
    return subprocess.run(
        ["git", *args], cwd=str(cwd), check=True, capture_output=True, text=True
    ).stdout.strip()


def _repo(path: Path) -> Path:
    """A checkout carrying scripts/coord/rescue.ps1 and one commit."""
    (path / "scripts" / "coord").mkdir(parents=True)
    shutil.copy2(_RESCUE, path / "scripts" / "coord" / "rescue.ps1")
    _git("init", "-b", "main", ".", cwd=path)
    _git("config", "user.email", "t@e.com", cwd=path)
    _git("config", "user.name", "t", cwd=path)
    (path / "a.txt").write_text("one\n", encoding="utf-8")
    _git("add", "-A", cwd=path)
    _git("commit", "-m", "first", "--no-verify", cwd=path)
    return path


def _run(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(repo / "scripts" / "coord" / "rescue.ps1"),
            *args,
        ],
        cwd=str(repo),
        capture_output=True,
        text=True,
        timeout=300,
    )


def _advance(repo: Path, text: str) -> str:
    (repo / "a.txt").write_text(text, encoding="utf-8")
    _git("commit", "-am", f"advance {text.strip()}", "--no-verify", cwd=repo)
    return _git("rev-parse", "HEAD", cwd=repo)


def _rows(repo: Path) -> dict[str, dict[str, Any]]:
    proc = _run(repo, "-Check", "-Json")
    assert proc.returncode == 0, proc.stderr or proc.stdout
    rows = json.loads(proc.stdout)["rows"]
    if isinstance(rows, dict):  # ConvertTo-Json collapses a single-element array
        rows = [rows]
    return {r["ref"]: r for r in rows}


def _verdicts(repo: Path) -> dict[str, str]:
    return {ref: row["verdict"] for ref, row in _rows(repo).items()}


def _declared_verdicts() -> set[str]:
    """Every verdict the script can assign, read from the script rather than from this file.

    The test this replaces asserted the cardinality of a set of five string literals it had just
    written down, which is a tautology: it passed against a ZERO-BYTE ``rescue.ps1``. It was also
    wrong about its subject, omitting ``DIVERGED``. Reading the inventory out of the source means a
    verdict added without a fixture to exercise it fails here instead of shipping untested.
    """
    declared = set(re.findall(r"\$verdict = '([A-Z-]+)'", _RESCUE.read_text(encoding="utf-8")))
    # The positive control on the scan itself: a regex that matches nothing would otherwise make
    # "the suite observed everything the script emits" trivially true.
    assert len(declared) >= 6, (
        f"the scan is broken -- it read {declared or 'nothing'} from a script"
    )
    return declared


def test_an_anchored_ref_holds_the_tip_and_says_so(tmp_path: Path) -> None:
    """The baseline, and the POSITIVE CONTROL for every other test in this file.

    Without this, an assertion that some other state is not ``TIP`` proves nothing -- a classifier
    that never returns ``TIP`` would satisfy it.
    """
    repo = _repo(tmp_path / "r")
    assert _run(repo, "-Anchor", "baseline").returncode == 0
    assert _verdicts(repo) == {"refs/tags/rescue/baseline": "TIP"}


def test_a_ref_whose_branch_ADVANCED_fails_the_tip_check(tmp_path: Path) -> None:
    """BACKLOG #1349 control 1, stated in the item verbatim.

    BEHIND is reported as a snapshot older than its branch and NOT as a defect: dated rescue refs are
    snapshots by design, and the argument that short refs are a writer defect was made and withdrawn
    by its author. What the reader needs is to be TOLD which it is, not to have it fixed.
    """
    repo = _repo(tmp_path / "r")
    _run(repo, "-Anchor", "before")
    _advance(repo, "two\n")
    _advance(repo, "three\n")

    assert _verdicts(repo) == {"refs/tags/rescue/before": "BEHIND"}

    proc = _run(repo, "-Check")
    assert "BEHIND" in proc.stdout
    assert "TIP" not in proc.stdout.replace("MULTIPLE", ""), "must not still claim the tip"


def test_a_ref_AHEAD_of_the_branch_it_names_is_DIVERGED(tmp_path: Path) -> None:
    """The item's SECOND named wrong recovery decision, and it was live but untested.

    "Concluding work is lost when a ref still holds commits the branch no longer has" is half the
    stated motivation for #1349, and ``DIVERGED`` is the arm that reports it. Mutating that literal
    to ``TIP`` left the whole suite green before this test existed, so the arm shipped unproven.

    The state is reached the way it happens in practice: a ref is anchored at a tip, then the branch
    is rewound under it by a reset or a force-push, leaving the ref holding commits the branch has
    dropped.
    """
    repo = _repo(tmp_path / "r")
    base = _git("rev-parse", "HEAD", cwd=repo)
    _git("checkout", "-b", "work", cwd=repo)
    _advance(repo, "two\n")
    _advance(repo, "three\n")
    _run(repo, "-Anchor", "before-the-rewind")
    _git("checkout", "main", cwd=repo)
    _git("update-ref", "refs/heads/work", base, cwd=repo)

    row = _rows(repo)["refs/tags/rescue/before-the-rewind"]
    assert row["verdict"] == "DIVERGED"
    assert row["detail"] == "0 behind / 2 ahead of work", "the counts are the recovery fact"
    assert "DIVERGED" in _run(repo, "-Check").stdout


def test_a_ref_SURVIVES_the_deletion_of_the_branch_it_names(tmp_path: Path) -> None:
    """BACKLOG #1349 control 2, and the one the whole item turns on.

    436 of 730 existing refs name a branch that is GONE, and those are precisely the ones a rescue
    ref is for -- so the measurement is possible exactly where it does not matter and impossible
    exactly where it does. A ref written by ``-Anchor`` stays checkable in that state, because it
    carries what it captured rather than depending on the branch to still be there.
    """
    repo = _repo(tmp_path / "r")
    _advance(repo, "two\n")
    _git("checkout", "-b", "doomed", cwd=repo)
    _advance(repo, "three\n")
    _run(repo, "-Anchor", "orphan")
    _git("checkout", "main", cwd=repo)
    _git("branch", "-D", "doomed", cwd=repo)

    assert _verdicts(repo) == {"refs/tags/rescue/orphan": "HELD-THE-TIP"}


def test_two_anchored_refs_on_a_DELETED_branch_do_not_read_alike(tmp_path: Path) -> None:
    """The item's defect, reproduced INSIDE the fix, in the population the fix is for.

    ``-Anchor`` records ``was-tip`` and the first ``-Check`` never read it: it matched only
    ``^branch:`` and ``^commit:``. So a ref that held the tip and a ref captured one commit short of
    it came back with the same verdict, the same detail string and the same colour once the branch
    was gone -- while the two TAGS disagreed. Captured and then discarded is worse than never
    captured, because the report then contradicts the evidence it was built from.

    Both refs are driven in ONE repository so the difference cannot come from anything but the
    recorded fact.
    """
    repo = _repo(tmp_path / "r")
    _git("checkout", "-b", "feat", cwd=repo)
    short = _advance(repo, "two\n")
    _advance(repo, "three\n")
    _run(repo, "-Anchor", "held-the-tip")
    _run(repo, "-Anchor", "short-by-one", "-Sha", short)
    _git("checkout", "main", cwd=repo)
    _git("branch", "-D", "feat", cwd=repo)

    rows = _rows(repo)
    held = rows["refs/tags/rescue/held-the-tip"]
    partial = rows["refs/tags/rescue/short-by-one"]

    assert held["verdict"] != partial["verdict"], "two different refs, one answer -- the item's bug"
    assert held["verdict"] == "HELD-THE-TIP"
    assert partial["verdict"] == "SHORT-AT-CAPTURE"
    assert held["wasTipAtCapture"] is True
    assert partial["wasTipAtCapture"] is False
    assert held["detail"] != partial["detail"]

    # The human report is the surface an operator actually reads, so it has to separate them too.
    out = _run(repo, "-Check").stdout
    assert "HELD-THE-TIP" in out
    assert "SHORT-AT-CAPTURE" in out
    assert "reaching for one of these gets less than the branch held" in out


def test_a_legacy_ref_with_no_provenance_is_UNVERIFIABLE_never_clean(tmp_path: Path) -> None:
    """The refs that already exist, and the reason the word matters.

    A check that cannot tell must not print the word that means it can -- the standard
    ``unbacked_check.ps1`` sets in this directory for reachability. An unverifiable ref is not a
    healthy one; it is one nothing here can speak about.
    """
    repo = _repo(tmp_path / "r")
    sha = _git("rev-parse", "HEAD", cwd=repo)
    _git("update-ref", "refs/rescue/hand-written", sha, cwd=repo)

    assert _verdicts(repo) == {"refs/rescue/hand-written": "UNVERIFIABLE"}
    assert "is NOT the same as healthy" in _run(repo, "-Check").stdout


def test_a_ref_MOVED_off_what_it_recorded_is_ALTERED(tmp_path: Path) -> None:
    """The self-check arm: provenance is only worth having if a disagreement is reported.

    This is what makes the recorded sha evidence rather than decoration -- without it, a ref could
    claim a capture it no longer holds and read as fine.

    **THE MESSAGE IS CARRIED FORWARD DELIBERATELY, and the first version of this test did not do
    that.** It re-pointed the tag with a plain ``git tag -f``, which writes a LIGHTWEIGHT tag and
    therefore destroys the annotation -- so the ref came back ``UNVERIFIABLE`` rather than
    ``ALTERED``, and it was right to. That is a real and separate behaviour worth stating: replacing
    an annotated rescue tag with a lightweight one discards the provenance silently, and the audit
    then reports that it cannot tell rather than that nothing happened.

    Exercising ALTERED needs the harder case -- a ref that still CLAIMS its capture while pointing
    somewhere else. Re-annotating with the original message is how that state is reached.
    """
    repo = _repo(tmp_path / "r")
    _run(repo, "-Anchor", "moved")
    message = _git("for-each-ref", "--format=%(contents)", "refs/tags/rescue/moved", cwd=repo)
    other = _advance(repo, "two\n")
    _git("tag", "-f", "-a", "rescue/moved", "-m", message, other, cwd=repo)

    assert _verdicts(repo) == {"refs/tags/rescue/moved": "ALTERED"}


def test_replacing_an_annotated_rescue_tag_with_a_LIGHTWEIGHT_one_loses_its_provenance(
    tmp_path: Path,
) -> None:
    """Found while writing the test above, and it is the honest half of that discovery.

    ``git tag -f <name> <sha>`` on an existing ANNOTATED tag does not move it -- it replaces it with
    a lightweight one, and the recorded capture goes with it. The audit degrades to ``UNVERIFIABLE``,
    which is correct: nothing readable remains. Pinned so that a future change which starts reporting
    such a ref as healthy has to argue with a test rather than slip through.
    """
    repo = _repo(tmp_path / "r")
    _run(repo, "-Anchor", "clobbered")
    other = _advance(repo, "two\n")
    _git("tag", "-f", "rescue/clobbered", other, cwd=repo)

    assert _verdicts(repo) == {"refs/tags/rescue/clobbered": "UNVERIFIABLE"}


def test_re_anchoring_an_EXISTING_name_is_refused_and_the_snapshot_survives(
    tmp_path: Path,
) -> None:
    """Overwriting a rescue ref destroys the one snapshot somebody is about to reach for.

    ``git tag -a`` refuses an existing name and the script turns that non-zero exit into a throw, so
    the behaviour is already right. It was untested, which is what makes a future change to silently
    force the tag a change nothing objects to -- and the object it would destroy is unrecoverable by
    construction, because a rescue ref is consulted only after the original is gone.
    """
    repo = _repo(tmp_path / "r")
    captured = _git("rev-parse", "HEAD", cwd=repo)
    assert _run(repo, "-Anchor", "keep").returncode == 0
    moved = _advance(repo, "two\n")
    assert moved != captured

    proc = _run(repo, "-Anchor", "keep")
    assert proc.returncode != 0, "re-anchoring an existing name must not overwrite the snapshot"
    assert _git("rev-parse", "refs/tags/rescue/keep^{commit}", cwd=repo) == captured
    assert _verdicts(repo) == {"refs/tags/rescue/keep": "BEHIND"}


def test_a_hostile_anchor_slug_writes_NO_ref(tmp_path: Path) -> None:
    """``-Anchor`` interpolates its argument into a ref name, so the traversal case is pinned.

    ``rescue/../../pwned`` would land outside the namespace the audit reads if git accepted it.
    It does not -- ``check-ref-format`` rejects a ``..`` component -- and the script propagates that
    refusal instead of continuing. Asserting on the REF SPACE rather than on the message means a
    future change that writes the ref through some other path still fails here.
    """
    repo = _repo(tmp_path / "r")
    proc = _run(repo, "-Anchor", "../../pwned")

    assert proc.returncode != 0
    assert "pwned" not in _git("for-each-ref", "--format=%(refname)", cwd=repo)


def test_the_suite_OBSERVES_every_verdict_the_script_can_emit(tmp_path: Path) -> None:
    """THE ANTI-VACUITY CHECK, rebuilt because the version it replaces could not fail.

    That version's entire body was ``expected = {five literals}; assert len(expected) == 5``. It
    never invoked the script, never imported it, took an unused ``tmp_path``, and passed against a
    ZERO-BYTE ``rescue.ps1``. It could only fail for an edit to its own literal -- and it carried an
    incomplete inventory besides, omitting ``DIVERGED`` from a classifier that emits it.

    This drives ONE repository into every state the classifier distinguishes, one ref per state, and
    checks the observed verdicts against the inventory read out of the script's own source. A
    constant classifier collapses the mapping; an arm added without a fixture leaves the two sets
    unequal.
    """
    repo = _repo(tmp_path / "r")
    base = _git("rev-parse", "HEAD", cwd=repo)

    # UNVERIFIABLE -- a hand-written ref carrying no provenance, which is what every ref that
    # predates -Anchor looks like.
    _git("update-ref", "refs/rescue/legacy", base, cwd=repo)

    # TIP -- a branch that does not move afterwards.
    _git("checkout", "-b", "stable", cwd=repo)
    _advance(repo, "stable-1\n")
    _run(repo, "-Anchor", "on-the-tip")

    # BEHIND -- anchored, then the branch advances past it.
    _git("checkout", "main", cwd=repo)
    _git("checkout", "-b", "moving", cwd=repo)
    _advance(repo, "moving-1\n")
    _run(repo, "-Anchor", "before-the-advance")
    _advance(repo, "moving-2\n")

    # DIVERGED -- anchored, then the branch is rewound under it.
    _git("checkout", "main", cwd=repo)
    _git("checkout", "-b", "rewound", cwd=repo)
    _advance(repo, "rewound-1\n")
    _advance(repo, "rewound-2\n")
    _run(repo, "-Anchor", "before-the-rewind")
    _git("checkout", "main", cwd=repo)
    _git("update-ref", "refs/heads/rewound", base, cwd=repo)

    # HELD-THE-TIP and SHORT-AT-CAPTURE -- two captures on one branch, then the branch is deleted.
    _git("checkout", "-b", "doomed", cwd=repo)
    short = _advance(repo, "doomed-1\n")
    _advance(repo, "doomed-2\n")
    _run(repo, "-Anchor", "doomed-tip")
    _run(repo, "-Anchor", "doomed-short", "-Sha", short)
    _git("checkout", "main", cwd=repo)
    _git("branch", "-D", "doomed", cwd=repo)

    # ALTERED -- still claims a capture it no longer points at.
    _git("checkout", "-b", "moved-under", cwd=repo)
    _advance(repo, "moved-1\n")
    _run(repo, "-Anchor", "moved")
    message = _git("for-each-ref", "--format=%(contents)", "refs/tags/rescue/moved", cwd=repo)
    elsewhere = _advance(repo, "moved-2\n")
    _git("tag", "-f", "-a", "rescue/moved", "-m", message, elsewhere, cwd=repo)

    # SELF-DESCRIBING -- provenance present but no was-tip recorded, and no such branch. The honest
    # verdict is that the ref speaks for itself and still cannot say whether it held the tip.
    _git(
        "tag",
        "-a",
        "rescue/no-was-tip",
        "-m",
        f"mefor-rescue-v1\ncommit: {base}\nbranch: vanished\n",
        base,
        cwd=repo,
    )

    observed = _verdicts(repo)
    assert observed == {
        "refs/rescue/legacy": "UNVERIFIABLE",
        "refs/tags/rescue/before-the-advance": "BEHIND",
        "refs/tags/rescue/before-the-rewind": "DIVERGED",
        "refs/tags/rescue/doomed-short": "SHORT-AT-CAPTURE",
        "refs/tags/rescue/doomed-tip": "HELD-THE-TIP",
        "refs/tags/rescue/moved": "ALTERED",
        "refs/tags/rescue/no-was-tip": "SELF-DESCRIBING",
        "refs/tags/rescue/on-the-tip": "TIP",
    }
    assert len(set(observed.values())) == len(observed), "one ref per verdict, so no two can agree"
    assert set(observed.values()) == _declared_verdicts(), (
        "the script can emit a verdict no fixture here reaches, or reaches one it cannot emit"
    )


def test_an_annotated_tag_reports_its_COMMIT_not_the_tag_object(tmp_path: Path) -> None:
    """``rev-parse`` on an annotated tag returns the TAG OBJECT, and the item flags it by name.

    Read naively, every annotated rescue ref would compare unequal to its branch tip for a reason
    with nothing to do with staleness -- a false BEHIND on a ref that holds the tip exactly. Four of
    the live 730 are annotated, and ``-Anchor`` writes annotated tags, so this is the normal case
    here rather than an edge one.
    """
    repo = _repo(tmp_path / "r")
    _run(repo, "-Anchor", "annotated")

    tag_object = _git("rev-parse", "refs/tags/rescue/annotated", cwd=repo)
    commit = _git("rev-parse", "refs/tags/rescue/annotated^{commit}", cwd=repo)
    assert tag_object != commit, "fixture is not annotated -- this test would prove nothing"

    rows = _rows(repo)
    assert rows["refs/tags/rescue/annotated"]["commit"] == commit, (
        "reported the tag object instead of the commit"
    )
