# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Every release must leave a record -- including a ``-Force`` one (BACKLOG #1068).

``claim.ps1 -Release`` was ``Remove-Item`` and nothing else. With ``-Force`` that meant any session
could release a claim it does not hold and leave no trace of who released whose claim, when, or why.
The escape hatch is NECESSARY -- a claim whose holder's worktree is gone would otherwise be stuck
forever, and the script prints that recipe itself -- so the fix is a RECORD, not a refusal. Every
test below therefore asserts a line was written; none asserts a release was blocked.

**Measured 2026-08-10, which is why the record has to name the PRIOR holder.** A coordinator
force-released claim #344 after establishing on evidence that the holder's worktree was gone and that
the work the claim's note guarded had already merged, while that note still read "UNPUSHED, NO PR,
GitHub finds NOTHING". The release was correct and it left nothing behind to find. Nothing is
deployed and there is no user to mislead (CLAUDE.md 0), but the registry is a shared coordination
artifact today and a stale note in it has already blocked a lane from claiming an item.

**The load-bearing negatives, per BACKLOG #1000.** A record that logged only "somebody released
something" satisfies "a line was appended" and answers none of the question, so:

* ``test_a_force_takeover_names_the_PRIOR_holder_not_the_releaser`` -- the two paths must differ, and
  the record must carry both.
* ``test_force_false_is_recorded_when_the_flag_was_not_passed`` -- a hardcoded ``force: true`` passes
  the takeover test and fails this one.
* ``test_a_REFUSED_release_writes_nothing`` -- the record is written before the removal, so the case
  that can produce a FALSE line (a release that never happened) is checked directly.
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
TIMEOUT = 60

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="claim.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its OWN copy of claim.ps1.

    The copy is the sandbox: the script anchors on ``$PSScriptRoot`` (BACKLOG #1060), so it writes to
    THIS repository's registry and never to the real one. Same fixture shape as
    ``test_coord_claim_liveness.py`` for the same reason.
    """
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    shutil.copy2(CLAIM, r / "scripts" / "coord" / "claim.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "f.txt", "scripts/coord/claim.ps1")
    git(r, "commit", "-qm", "base")
    return r


def claim(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the checkout's OWN copy, with the child's environment PINNED.

    ``env`` is passed explicitly rather than inherited. claim.ps1 reads nothing from the environment
    today, so nothing here is load-bearing for the assertions -- but a test that shells out and
    inherits whatever the developer's shell exports is measuring the shell as much as the code, which
    is how a lane's green survived locally and reddened at integration in wave 2. Pinning costs one
    line and removes the whole class.
    """
    env = dict(os.environ)
    for var in ("PYTHONIOENCODING", "PYTHONUTF8"):
        env.pop(var, None)
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "claim.ps1"),
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def history_path(repo: Path) -> Path:
    return repo / ".git" / "mefor-coord" / "claims" / ".history"


def records(repo: Path) -> list[dict[str, object]]:
    """Every record in the ledger, parsed.

    Asserts the on-disk shape as it goes: JSON Lines, LF-terminated, no CR. A ledger that is only
    ever read back by the code that wrote it can drift into any shape at all; this is the file an
    operator greps months later, so the format is part of the contract.
    """
    p = history_path(repo)
    if not p.exists():
        return []
    text = p.read_text(encoding="utf-8")
    assert "\r" not in text, f"the ledger must be LF-only JSON Lines, not CRLF: {text!r}"
    assert text.endswith("\n"), f"every record must be newline-terminated: {text!r}"
    return [json.loads(line) for line in text.splitlines() if line.strip()]


def peer_holding(repo: Path, tmp_path: Path, key: str, note: str = "the peer's work") -> Path:
    """A second worktree that holds ``key``, sharing this repo's object store and registry."""
    peer = tmp_path / "peer-wt"
    git(repo, "worktree", "add", "-q", "-b", "peer-branch", str(peer))
    assert claim(peer, "-Take", key, "-Note", note).returncode == 0
    return peer


def norm(p: object) -> str:
    return str(p).replace("\\", "/").rstrip("/").casefold()


# --------------------------------------------------------------------------------------------------
# the ordinary release
# --------------------------------------------------------------------------------------------------


def test_releasing_your_own_claim_appends_a_record(repo: Path) -> None:
    assert claim(repo, "-Take", "k", "-Note", "my work").returncode == 0
    proc = claim(repo, "-Release", "k")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    rows = records(repo)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["event"] == "release"
    assert row["key"] == "k"
    assert norm(row["released_by"]) == norm(repo)
    assert norm(row["prior_holder"]) == norm(repo)
    assert row["prior_note"] == "my work"
    assert row["force"] is False
    assert row["ts"], "a record with no timestamp cannot be ordered against anything"
    assert row["claimed"], "the record must carry when the claim was taken, not only when it ended"


def test_the_release_output_names_the_ledger_it_wrote_to(repo: Path) -> None:
    """A record nobody can find is barely better than no record.

    The path is not guessable -- it lives beside the SHARED object store, which for a linked worktree
    is a different directory from the one the operator is standing in.
    """
    assert claim(repo, "-Take", "k", "-Note", "x").returncode == 0
    out = claim(repo, "-Release", "k").stdout
    assert ".history" in out, out


# --------------------------------------------------------------------------------------------------
# -Force: the case the item is about
# --------------------------------------------------------------------------------------------------


def test_a_force_takeover_is_recorded(repo: Path, tmp_path: Path) -> None:
    peer = peer_holding(repo, tmp_path, "k", note="the peer is mid-flight")
    proc = claim(repo, "-Release", "k", "-Force")

    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert not (repo / ".git" / "mefor-coord" / "claims" / "k.json").exists(), (
        "-Force must still release -- this item is about auditability, not prevention"
    )
    rows = records(repo)
    assert len(rows) == 1, rows
    assert rows[0]["force"] is True
    assert norm(rows[0]["prior_holder"]) == norm(peer)


def test_a_force_takeover_names_the_PRIOR_holder_not_the_releaser(
    repo: Path, tmp_path: Path
) -> None:
    """THE load-bearing case. "who released whose claim" needs both halves, and they differ here.

    A record carrying only the releasing worktree passes every other test in this file and answers
    none of the question #1068 asks.
    """
    peer = peer_holding(repo, tmp_path, "k", note="UNPUSHED, NO PR")
    assert claim(repo, "-Release", "k", "-Force").returncode == 0

    row = records(repo)[0]
    assert norm(row["prior_holder"]) == norm(peer)
    assert norm(row["released_by"]) == norm(repo)
    assert norm(row["prior_holder"]) != norm(row["released_by"]), (
        "the fixture must make the two paths differ, or this test cannot fail"
    )
    # The note is what a reader needs to judge whether the release was right -- it is the field that
    # was stale and wrong in the 2026-08-10 incident.
    assert row["prior_note"] == "UNPUSHED, NO PR"
    assert row["prior_branch"] == "peer-branch"


def test_force_false_is_recorded_when_the_flag_was_not_passed(repo: Path) -> None:
    """The negative that a hardcoded ``force: true`` cannot pass."""
    assert claim(repo, "-Take", "k", "-Note", "x").returncode == 0
    assert claim(repo, "-Release", "k").returncode == 0
    assert records(repo)[0]["force"] is False


def test_a_force_takeover_says_so_on_stdout_too(repo: Path, tmp_path: Path) -> None:
    """The releasing session should be told it took someone else's key, not just that it succeeded."""
    peer_holding(repo, tmp_path, "k")
    out = claim(repo, "-Release", "k", "-Force").stdout
    assert "TOOK OVER" in out, out
    assert "peer-branch" in out, out


# --------------------------------------------------------------------------------------------------
# what must NOT be recorded
# --------------------------------------------------------------------------------------------------


def test_a_REFUSED_release_writes_nothing(repo: Path, tmp_path: Path) -> None:
    """The record is written BEFORE the removal, so a false line is the failure mode to check.

    A refused release did not happen. A ledger claiming it did is worse than the silence it replaced.
    """
    peer_holding(repo, tmp_path, "k")
    proc = claim(repo, "-Release", "k")  # no -Force: refused

    assert proc.returncode == 1
    assert records(repo) == [], "a refusal is not a release and must not be recorded as one"


def test_releasing_an_unclaimed_key_writes_nothing(repo: Path) -> None:
    proc = claim(repo, "-Release", "never-claimed")
    assert proc.returncode == 0
    assert records(repo) == []


# --------------------------------------------------------------------------------------------------
# the ledger's own properties
# --------------------------------------------------------------------------------------------------


def test_records_APPEND_rather_than_replace(repo: Path, tmp_path: Path) -> None:
    """A ledger that keeps only the last release is a status field, not a history."""
    assert claim(repo, "-Take", "a", "-Note", "first").returncode == 0
    assert claim(repo, "-Release", "a").returncode == 0
    peer_holding(repo, tmp_path, "b", note="second")
    assert claim(repo, "-Release", "b", "-Force").returncode == 0

    rows = records(repo)
    assert [r["key"] for r in rows] == ["a", "b"], rows
    assert [r["force"] for r in rows] == [False, True], rows


def test_the_ledger_is_not_mistaken_for_a_claim(repo: Path) -> None:
    """It lives INSIDE the claims directory, so the readers of that directory must ignore it.

    ``-List`` globs ``*.json`` and scripts/hooks/claim_check.py opens ``<item>.json``; a dotfile named
    ``.history`` is invisible to both. Asserted rather than argued, because "the glob will not match
    it" is exactly the kind of premise that is true until someone widens the glob.
    """
    assert claim(repo, "-Take", "k", "-Note", "x").returncode == 0
    assert claim(repo, "-Release", "k").returncode == 0
    assert history_path(repo).is_file(), "the ledger must exist for this test to mean anything"

    out = claim(repo, "-List").stdout
    assert "No active claims." in out, out
