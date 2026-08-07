# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Re-taking a claim you already hold must actually refresh its note.

``scripts/coord/claim.ps1 -Take`` documented itself as idempotent -- "re-taking your own claim just
refreshes the note" -- and did not do it. A new ``-Note`` was accepted, reported as success, and
silently discarded.

That is worse than a plain failure. The note is the one field written deliberately to say what a
session is doing, and ``announce-session.ps1`` broadcasts it to every session joining the repo while
telling them to prefer it over the worktree name. Measured 2026-08-02: the ``announce-hook`` claim was
still announcing "NO PR OPENED -- honouring the #119 merge freeze" to every joining session hours
after both PRs had merged. A stale note presented as current intent is a coordination fault.

The workaround people reached for -- ``-Release`` then ``-Take`` -- drops the claim in between, which
re-opens the very race the claim exists to close. So the property under test is *refresh in place*:
the note changes and ``claimed`` does not, which is what proves the claim was never let go.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path
from typing import Any

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
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    # STAGE THE SCRIPT INSIDE THE FIXTURE, and commit it, because claim.ps1 anchors on its own location
    # rather than on the cwd (BACKLOG #1060). This is also what makes the sandbox STRUCTURAL: these
    # tests used to be scoped to a temp registry only by ambient cwd, so the moment the script stopped
    # consulting cwd they began writing REAL claims into this clone's shared registry -- measured, two
    # strays landed there on the first run after the fix. Committing it means a linked worktree of this
    # fixture carries its own copy, which is how `peer_holding` still gets a claim held by the peer.
    shutil.copy2(CLAIM, r / "scripts" / "coord" / "claim.ps1")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def claim(cwd: Path, *args: str) -> subprocess.CompletedProcess[str]:
    """Run the checkout's OWN copy -- the script scopes itself to where it LIVES, not to the cwd.

    ``cwd`` still names the worktree under test, but it does so by HOLDING that copy rather than by
    being the ambient directory, which is what a session invoking `scripts\\coord\\claim.ps1` does.
    """
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
        timeout=TIMEOUT,
        check=False,
    )


def claim_file(repo: Path, key: str) -> Path:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord" / "claims" / f"{key}.json"


def read_claim(repo: Path, key: str) -> dict[str, Any]:
    raw = claim_file(repo, key).read_bytes()
    # NO BOM. scripts/hooks/claim_check.py reads this with encoding="utf-8" and a BOM makes json.loads
    # raise -- which that gate swallows into "not claimed", silently disabling itself for this key.
    assert not raw.startswith(b"\xef\xbb\xbf"), "claim file must be UTF-8 without a BOM"
    parsed: dict[str, Any] = json.loads(raw.decode("utf-8"))
    return parsed


def test_retaking_your_own_claim_replaces_the_note(repo: Path) -> None:
    assert claim(repo, "-Take", "k", "-Note", "first").returncode == 0
    before = read_claim(repo, "k")

    proc = claim(repo, "-Take", "k", "-Note", "second -- the PR has merged")
    assert proc.returncode == 0, proc.stderr

    after = read_claim(repo, "k")
    assert after["note"] == "second -- the PR has merged"
    assert "REFRESHED" in proc.stdout, "it must not report success without saying what it did"
    # THE CLAIM WAS NEVER RELEASED. `claimed` is the claim's identity; if the refresh had gone through
    # release-then-retake, this would have moved -- and there would have been a window in between with
    # the key free for another session to take.
    # Byte-identical, not merely "still parses". ConvertFrom-Json coerces an ISO-8601 string into a
    # [datetime], so a naive rewrite emits the local short form -- lower precision, no UTC offset, and
    # culture-dependent on the way back in. It would still parse, so nothing would ever complain.
    assert after["claimed"] == before["claimed"]
    assert "T" in str(before["claimed"]), "the stamp under test must be the ISO-8601 form"
    assert after["refreshed"], "a refreshed note needs its own stamp, or readers cannot date it"


def test_a_fresh_claim_has_no_refreshed_stamp(repo: Path) -> None:
    """Absent, not zero. Readers fall back to ``claimed``; a fabricated stamp would date it wrong."""
    assert claim(repo, "-Take", "k", "-Note", "first").returncode == 0
    assert "refreshed" not in read_claim(repo, "k")


def test_retaking_without_a_note_leaves_the_note_alone(repo: Path) -> None:
    """Re-asserting a claim is a normal thing to do and must not blank out what it says."""
    assert claim(repo, "-Take", "k", "-Note", "the real work").returncode == 0
    proc = claim(repo, "-Take", "k")
    assert proc.returncode == 0
    assert read_claim(repo, "k")["note"] == "the real work"
    assert "the real work" in proc.stdout, "show the note, so a session can see it is stale"


def test_the_refresh_updates_the_branch_too(repo: Path) -> None:
    """A claim naming a branch nobody is on is another confidently-wrong coordination fact."""
    assert claim(repo, "-Take", "k", "-Note", "n").returncode == 0
    git(repo, "checkout", "-q", "-b", "moved-on")
    assert claim(repo, "-Take", "k", "-Note", "n2").returncode == 0
    assert read_claim(repo, "k")["branch"] == "moved-on"


def test_a_peers_claim_is_still_refused(repo: Path, tmp_path: Path) -> None:
    """THE REGRESSION GUARD. The refresh path must not become a way to rewrite someone else's note.

    Mutual exclusion is the whole point of this script; a fix for a stale note that let any session
    overwrite any other session's note would trade a stale fact for a forged one.
    """
    peer = tmp_path / "peer-wt"
    git(repo, "worktree", "add", "-q", "-b", "peer-branch", str(peer))
    assert claim(peer, "-Take", "k", "-Note", "the peer's work").returncode == 0

    proc = claim(repo, "-Take", "k", "-Note", "mine now")
    assert proc.returncode == 1, "taking a peer's key must fail"
    assert "BLOCKED" in proc.stdout
    assert read_claim(repo, "k")["note"] == "the peer's work", (
        "a refused take must not have written"
    )


def test_a_key_that_looks_like_a_date_survives_a_refresh(repo: Path) -> None:
    """A key is free text, and ConvertFrom-Json date-coerces anything ISO-8601 shaped.

    Round-tripping the stored key through [string] would rewrite "2026-08-01T00:00:00" as
    "08/01/2026 00:00:00" -- a record naming a key nobody typed, which -List reports and -Release
    cannot be spelled to match.
    """
    key = "2026-08-01T00:00:00"
    assert claim(repo, "-Take", key, "-Note", "first").returncode == 0
    assert claim(repo, "-Take", key, "-Note", "second").returncode == 0
    assert read_claim(repo, "2026-08-01t00-00-00")["key"] == key


def test_a_refresh_that_cannot_be_written_leaves_the_old_claim_intact(repo: Path) -> None:
    """Write-then-REPLACE, not truncate-in-place and not delete-then-rename.

    Two properties, and the second is the one that bites hardest:

    * A claim file caught mid-write does not fail loudly -- ``claim_check.py`` swallows a parse error
      into "not claimed" and stops enforcing that key. A crash during a refresh must leave the OLD note.
    * **The claim file's existence IS the lock.** The take path is an exclusive ``CreateNew``, so any
      instant the name does not exist is an instant another worktree can claim a key we hold.
      ``Move-Item -Force`` is delete-then-rename: measured on this box, 400 moves left the destination
      absent on 2,559 of 154,506 polls. ``[IO.File]::Move(.., overwrite)`` is MoveFileEx and never
      unlinked the name across 134,581 polls -- it fails transiently instead, which is the safe
      direction: the old note survives and the claim stays ours.
    """
    assert claim(repo, "-Take", "k", "-Note", "first").returncode == 0
    path = claim_file(repo, "k")
    # Hold the file open without sharing Delete: the replace cannot land, and the old bytes must survive.
    with open(path, "r+b") as held:
        held.read()
        proc = claim(repo, "-Take", "k", "-Note", "second")
        # The NAME must never have gone away, even while the refresh was failing.
        assert path.exists(), (
            "the claim file was unlinked -- a peer could take the key in that window"
        )
    assert proc.returncode != 0 or read_claim(repo, "k")["note"] in {"first", "second"}
    # Whatever happened, the file is still parseable -- that is the property the gate depends on.
    assert read_claim(repo, "k")["key"] == "k"
    # And nothing was orphaned: this directory is the claim registry, not a scratch space.
    assert not list(path.parent.glob("*.tmp")), "a failed refresh left a temp file behind"
