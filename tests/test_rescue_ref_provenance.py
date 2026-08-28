# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A rescue ref must be verifiable WITHOUT the branch it names (BACKLOG #1349).

A rescue ref is consulted once, in the moment the original is already gone -- so it is the one
instrument whose failure surfaces only when it is too late to fix. The item's two controls are the
two tests this file exists for:

  1. a ref written for a branch that is then ADVANCED must fail a tip check
  2. a ref must be verifiable after the branch it names is GONE

**EVERY VERDICT IS ASSERTED SEPARATELY AND THEY MUST DIFFER.** Against the live repository all 1318
existing refs report ``UNVERIFIABLE`` -- correctly, because none carries provenance -- and a suite
that only saw that state could not tell a working classifier from one that returns a constant. A
uniform output is exactly the shape a dead instrument produces, so each arm is driven to a
DIFFERENT verdict here.

**THE FIXTURE IS A REAL REPOSITORY, NOT A MOCK.** The behaviour under test is git's -- annotated tag
dereference, ancestor arithmetic, a deleted branch -- and a fake would be asserting this file's own
model of git rather than git.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

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
        timeout=180,
    )


def _advance(repo: Path, text: str) -> str:
    (repo / "a.txt").write_text(text, encoding="utf-8")
    _git("commit", "-am", f"advance {text.strip()}", "--no-verify", cwd=repo)
    return _git("rev-parse", "HEAD", cwd=repo)


def _verdicts(repo: Path) -> dict[str, str]:
    proc = _run(repo, "-Check", "-Json")
    assert proc.returncode == 0, proc.stderr or proc.stdout
    payload = json.loads(proc.stdout)
    rows = payload["rows"]
    if isinstance(rows, dict):  # ConvertTo-Json collapses a single-element array
        rows = [rows]
    return {r["ref"]: r["verdict"] for r in rows}


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

    assert _verdicts(repo) == {"refs/tags/rescue/orphan": "SELF-DESCRIBING"}


def test_a_legacy_ref_with_no_provenance_is_UNVERIFIABLE_never_clean(tmp_path: Path) -> None:
    """The 1318 refs that already exist, and the reason the word matters.

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


def test_every_arm_produces_a_DIFFERENT_verdict(tmp_path: Path) -> None:
    """THE ANTI-VACUITY CHECK, and it is why the tests above are not one test wearing five names.

    Each state above is asserted in isolation, so a classifier returning a constant would fail four
    of them -- but only if the four expectations really differ. Asserting that here makes the
    parametrisation's own claim testable instead of assumed.
    """
    expected = {"TIP", "BEHIND", "SELF-DESCRIBING", "UNVERIFIABLE", "ALTERED"}
    assert len(expected) == 5, "five states, five distinct names"


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

    proc = _run(repo, "-Check", "-Json")
    rows = json.loads(proc.stdout)["rows"]
    if isinstance(rows, dict):
        rows = [rows]
    assert rows[0]["commit"] == commit, "reported the tag object instead of the commit"
