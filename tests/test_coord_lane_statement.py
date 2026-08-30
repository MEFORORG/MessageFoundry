# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""``lane.ps1``'s only-ever-advances guard must not fire on a stamp it wrote itself.

THE GUARD IS CORRECT AND ITS COMPARISON WAS NOT. ``statedUtc`` is written as
``2026-08-29T03:28:22Z`` and ``ConvertFrom-Json`` deserialises that into a ``[datetime]`` with
``Kind=Utc`` -- already right. Passing that object to ``[datetime]::Parse`` coerced it BACK TO A
STRING first (``"8/29/2026 3:28:22 AM"``), and that form carries no zone, so it re-parsed as
``Kind=Unspecified`` and the following ``.ToUniversalTime()`` added the local offset A SECOND TIME.

A stamp written 27 minutes earlier therefore read five hours in the FUTURE and the guard threw. **A
guard written to stop the value moving BACKWARDS moved it FORWARDS by the local offset**, so a seat
that stated its lane could not state it again until that offset had elapsed -- five hours here.

NOTHING SURFACED IT, which is why it wants a test rather than a comment. The Stop hook kept
prompting for a lane level, the command kept refusing, and from a reader's side a frozen lane is
indistinguishable from an unchanged one. It also reads, from the dispatcher's seat, as seats
ignoring the prompt.

TWO ARMS, AND THE SECOND IS THE ONE THAT MATTERS. Deleting the guard would make arm one pass. Arm
two fails unless a genuinely future stamp is still refused, so the pair pins the fix rather than its
absence.

THE FIX UNDER TEST IS NOT MINE. It is PROCESS-IMPROVEMENT's, at f2ebc2e80, which is the commit this
file is written against -- I measured the defect independently and wrote the arms. That fix also
covers a case a bare ``.ToUniversalTime()`` still gets wrong: on ``Kind=Unspecified`` .NET assumes
LOCAL and re-adds the offset, so it uses ``SpecifyKind(..., Utc)`` on the object path and an
invariant-culture ``AssumeUniversal`` parse on the legacy string path.

MEASURED, three states of the script. This is what makes the arms a discriminator rather than two
assertions that happen to hold together:

    lane.ps1 state              arm one (past)   arm two (future)   arms-disagree
    broken (origin/main)        FAIL             pass               FAIL
    the fix at f2ebc2e80        pass             pass               pass
    guard disarmed              pass             FAIL               FAIL

READ THE BROKEN ROW: it refuses BOTH directions. That is the manufactured-non-compliance shape --
the hook nags that a level is stale, the seat runs the command, the command refuses, and from
outside that is indistinguishable from a seat ignoring the prompt.

The script resolves its store from ``git rev-parse --git-common-dir``, so these run it inside a
throwaway repository -- no override parameter needed, and the real coordination directory is never
touched.
"""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

_SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "lane.ps1"


def _pwsh(repo: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-File", str(_SCRIPT), *args],
        capture_output=True,
        text=True,
        cwd=repo,
    )


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway git repo with one commit, so ``git rev-parse`` answers."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    for k, v in (("user.email", "t@t"), ("user.name", "t")):
        subprocess.run(["git", "-C", str(tmp_path), "config", k, v], check=True)
    (tmp_path / "seed.txt").write_text("seed\n", encoding="utf-8")
    subprocess.run(["git", "-C", str(tmp_path), "add", "seed.txt"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-qm", "seed"], check=True)
    return tmp_path


def _lane_record(repo: Path) -> Path:
    """The single record lane.ps1 wrote. Located rather than derived: the box key is the script's
    business, and a test that recomputed it would be asserting its own copy of that rule."""
    lanes = repo / ".git" / "mefor-coord" / "lanes"
    files = sorted(p for p in lanes.glob("*.json"))
    assert len(files) == 1, f"expected exactly one lane record, found {[p.name for p in files]}"
    return files[0]


def _restate(repo: Path, stamp: datetime) -> subprocess.CompletedProcess[str]:
    """Force ``statedUtc`` to ``stamp`` in the SAME wire form the script writes, then re-state."""
    rec_path = _lane_record(repo)
    rec = json.loads(rec_path.read_text(encoding="utf-8"))
    rec["statedUtc"] = stamp.strftime("%Y-%m-%dT%H:%M:%SZ")
    rec_path.write_text(json.dumps(rec), encoding="utf-8")
    return _pwsh(repo, "-Free", "2", "-InFlight", "2", "-Note", "restate")


def test_a_stamp_this_script_wrote_minutes_ago_does_not_read_as_the_future(repo: Path) -> None:
    """ARM ONE -- the defect. A recent past stamp must not block the next statement."""
    first = _pwsh(repo, "-Free", "1", "-InFlight", "3", "-Note", "first")
    assert first.returncode == 0, f"first statement failed: {first.stderr or first.stdout}"

    past = datetime.now(UTC) - timedelta(minutes=30)
    result = _restate(repo, past)

    assert result.returncode == 0, (
        "a statedUtc 30 minutes in the PAST was rejected as being in the future. The guard is "
        "comparing a UTC value against a local clock -- see this module's docstring. "
        f"stderr={result.stderr!r}"
    )
    assert "in the future" not in (result.stderr + result.stdout)


def test_a_genuinely_future_stamp_is_still_refused(repo: Path) -> None:
    """ARM TWO -- the must-not-fire control, and the reason arm one is not satisfied by deletion.

    Removing the guard entirely makes arm one pass. This one fails unless the guard still refuses a
    stamp that really is ahead of now, which is the property it was written for: statedUtc only ever
    advances, so a clock that jumped backwards must not silently rewind the gauge.
    """
    first = _pwsh(repo, "-Free", "1", "-InFlight", "3", "-Note", "first")
    assert first.returncode == 0, f"first statement failed: {first.stderr or first.stdout}"

    future = datetime.now(UTC) + timedelta(hours=6)
    result = _restate(repo, future)

    assert result.returncode != 0, "a statedUtc genuinely in the future was accepted"
    assert "in the future" in (result.stderr + result.stdout)


def test_the_two_arms_disagree(repo: Path) -> None:
    """The arms must produce DIFFERENT outcomes on the same code, or they are one case twice.

    Both arms drive the identical path with the identical record shape; only the SIGN of the offset
    differs. If a change ever made them agree -- both passing or both failing -- the pair would still
    look like two tests while testing one thing.
    """
    _pwsh(repo, "-Free", "1", "-InFlight", "3", "-Note", "first")
    past = _restate(repo, datetime.now(UTC) - timedelta(minutes=30))
    future = _restate(repo, datetime.now(UTC) + timedelta(hours=6))
    assert (past.returncode == 0) != (future.returncode == 0), (
        f"past rc={past.returncode} future rc={future.returncode} -- the two arms agree, so the "
        "guard is not discriminating on the sign of the offset at all"
    )
