# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""mail-watch.ps1 stands an older watcher down, and does so only on real evidence.

The hook arms on Stop -- every turn boundary -- then polls for ``MaxWaitSeconds``. With no guard a
session taking turns faster than 900s accumulates one watcher per turn, each holding a process for its
full deadline. Measured 2026-09-18: 15 alive across 7 sessions, two sessions holding 5 each, about
1.9 GB resident. None was stuck; the oldest was 902s against the 900s deadline, so the population was
BOUNDED and the ceiling was simply ``900s / turn_interval``.

The guard's failure direction is inverted relative to the rest of that script, and that is the part
worth pinning. Everywhere else a failure exits 0, because a missed rewake costs nothing. Here exiting
IS the action, so the same reflex would drop wakes on any unreadable or half-written claim file --
converting a memory cost into a correctness one. Hence: only a well-formed token that is not mine
stands a watcher down, and everything else keeps watching.

So every test below that asserts a stand-down is paired with one asserting a NON-stand-down on
malformed evidence. A guard that always exits would pass the first half alone, and it is the half
nobody notices is broken.
"""

from __future__ import annotations

import json
import re
import subprocess
from pathlib import Path

import pytest
from _session_mail_harness import (
    HOOKS,
    SELF_ID,
    mail_root,
    repo,
    requires_pwsh_on_windows,
)

__all__ = ["repo"]  # re-exported so pytest resolves the fixture in this module

pytestmark = requires_pwsh_on_windows

WATCH = HOOKS / "mail-watch.ps1"

# Long enough that a watcher which fails to stand down is still polling when we look, short enough that
# such a failure costs the suite seconds rather than the pytest timeout.
POLL = 1
MAX_WAIT = 25


def run_watch(
    repo_path: Path, session_id: str = SELF_ID, timeout: int = 40
) -> subprocess.CompletedProcess[str]:
    """Drive the real hook the way Claude Code does: the hook JSON on stdin."""
    payload = json.dumps({"cwd": str(repo_path), "session_id": session_id})
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(WATCH),
            "-MaxWaitSeconds",
            str(MAX_WAIT),
            "-PollSeconds",
            str(POLL),
        ],
        input=payload,
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def owner_file(repo_path: Path, session_id: str = SELF_ID) -> Path:
    return mail_root(repo_path) / "watch" / f"{session_id.lower()}.owner"


def test_a_watcher_publishes_a_wellformed_claim(repo: Path) -> None:  # noqa: F811
    """The claim must be parseable by the very regex the stand-down check uses, or nothing stands down."""
    run_watch(repo)
    f = owner_file(repo)
    assert f.is_file(), "no claim published -- every later assertion here would pass vacuously"

    token = f.read_text(encoding="utf-8")
    assert re.fullmatch(r"\d+ [0-9a-fA-F-]{36}", token), (
        f"claim not in the guarded shape: {token!r}"
    )

    # The shape is read out of the script rather than restated, so tightening one and not the other
    # cannot leave this test asserting a pattern the shipped guard no longer accepts.
    src = WATCH.read_text(encoding="utf-8")
    m = re.search(r"\$owner -match '(\^[^']+\$)'", src)
    assert m, "stand-down regex not found in mail-watch.ps1 -- this test's instrument is broken"
    assert re.fullmatch(m.group(1).replace("\\d", "[0-9]"), token)


def test_a_foreign_claim_stands_the_watcher_down_promptly(repo: Path) -> None:  # noqa: F811
    """The whole point: an older watcher exits well before its own deadline."""
    f = owner_file(repo)
    f.parent.mkdir(parents=True, exist_ok=True)
    f.write_text("99999 abcdef01-2345-6789-abcd-ef0123456789", encoding="utf-8")

    # A real watcher overwrites the claim with its own on startup, so to simulate the LOSER we let it
    # start and then replace the claim underneath it -- which is exactly what a newer watcher does.
    proc = subprocess.Popen(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(WATCH),
            "-MaxWaitSeconds",
            str(MAX_WAIT),
            "-PollSeconds",
            str(POLL),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdin is not None
    proc.stdin.write(json.dumps({"cwd": str(repo), "session_id": SELF_ID}))
    proc.stdin.close()

    # Let it publish its own claim, then take the claim away from it.
    deadline_for_claim = 15
    for _ in range(deadline_for_claim * 4):
        if f.is_file() and f.read_text(encoding="utf-8").startswith(str(proc.pid)):
            break
        if proc.poll() is not None:
            break
        __import__("time").sleep(0.25)
    f.write_text("99999 abcdef01-2345-6789-abcd-ef0123456789", encoding="utf-8")

    # It must notice within a poll or two -- NOT merely "before MAX_WAIT", which a broken guard also
    # satisfies by timing out.
    rc = proc.wait(timeout=MAX_WAIT - 5)
    assert rc == 0, f"stood down with exit {rc}; only 0 means 'no rewake'"


def test_a_malformed_claim_does_NOT_stand_the_watcher_down(repo: Path) -> None:  # noqa: F811
    """The paired arm. A torn or unreadable claim must leave the watcher running.

    Without this, a guard that exits on ANY non-matching content passes the test above and silently
    drops wakes whenever the claim file is mid-write.
    """
    f = owner_file(repo)
    f.parent.mkdir(parents=True, exist_ok=True)

    proc = subprocess.Popen(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(WATCH),
            "-MaxWaitSeconds",
            str(MAX_WAIT),
            "-PollSeconds",
            str(POLL),
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    assert proc.stdin is not None
    proc.stdin.write(json.dumps({"cwd": str(repo), "session_id": SELF_ID}))
    proc.stdin.close()

    for _ in range(60):
        if f.is_file() and f.read_text(encoding="utf-8").startswith(str(proc.pid)):
            break
        if proc.poll() is not None:
            break
        __import__("time").sleep(0.25)

    # A half-written claim: the right shape truncated. This is the realistic torn read.
    f.write_text("99999 abcdef01-2345", encoding="utf-8")

    with pytest.raises(subprocess.TimeoutExpired):
        proc.wait(timeout=POLL * 6)
    proc.kill()
    proc.wait(timeout=10)


def test_an_unmarkable_session_publishes_no_claim_and_keeps_watching(repo: Path) -> None:  # noqa: F811
    """``ConvertTo-SessionKey`` returns null for a non-session-id, and no path may be built from it.

    Falling back to a box-keyed claim would be worse than no guard: two sessions sharing a worktree
    would evict each other, trading a bounded process count for lost wakes.
    """
    run_watch(repo, session_id="not-a-session-id")
    watch_dir = mail_root(repo) / "watch"
    if watch_dir.exists():
        assert not any(watch_dir.iterdir()), "built a claim path from an unvalidated session id"


def test_the_claim_file_survives_the_watcher_that_wrote_it(repo: Path) -> None:  # noqa: F811
    """Deleting it on exit would release a claim the exiting process no longer holds."""
    run_watch(repo)
    assert owner_file(repo).is_file(), (
        "claim removed on exit -- the newer watcher would then see no file, keep running, "
        "and the turn after it would start a third"
    )
