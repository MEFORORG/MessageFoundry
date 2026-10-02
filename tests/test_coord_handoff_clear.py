# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``seat.ps1 -ClearHandoff`` clears a DEAD session's pointer to a deleted file, and nothing else.

Every other ``seat.ps1`` path writes the caller's own record. A seat that died pointing at a file
that was later deleted kept ``fleet.ps1``'s ``handoffPointersBroken`` stop raised for as long as the
record survived, because its own writer never runs again. Measured 2026-10-02: 2 of 6 pointers, one
of them in a box whose worktree no longer exists.

The switch writes under a seat that cannot object, so most of this file is refusals. The sandbox is
the one ``test_coord_handoff_pointer.py`` builds, and the liveness fence reads a FAKE home through
``USERPROFILE``, so no test here can see, or be vetoed by, a real session on the box.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import time
from pathlib import Path
from typing import Any

import pytest

from tests import test_coord_handoff_pointer as _pointer_tests
from tests.test_coord_handoff_pointer import (  # noqa: F401  (pytestmark is applied by name)
    TIMEOUT,
    git,
    pytestmark,
    seat,
    seats_dir,
)

# The sandbox fixture, bound by ASSIGNMENT: importing the name directly makes every `repo`
# argument below a shadowed import, and an aliased import is not registered as `repo` at all.
repo = _pointer_tests.repo

DEAD = "dead-sess-0001"


@pytest.fixture
def home(tmp_path: Path) -> Path:
    """A fake user profile whose only config root is ``.claude`` with an empty session registry."""
    h = tmp_path / "home"
    (h / ".claude" / "sessions").mkdir(parents=True)
    return h


def clear(
    cwd: Path, home: Path, box: str, session: str, caller: str = "caller-sess"
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["USERPROFILE"] = str(home)
    env["HOME"] = str(home)
    env["CLAUDE_CODE_SESSION_ID"] = caller
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "seat.ps1"),
            "-ClearHandoff",
            "-Box",
            box,
            "-SessionId",
            session,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def record_path(repo: Path, session: str = DEAD) -> Path:
    hits = list(seats_dir(repo).rglob(f"{session}.json"))
    assert len(hits) == 1, hits
    return hits[0]


def load(p: Path) -> dict[str, Any]:
    return json.loads(p.read_text(encoding="utf-8-sig"))


def declare_dangling(repo: Path, cwd: Path | None = None) -> Path:
    """Declare a pointer under the DEAD session, then delete the file. Returns the record path."""
    where = cwd or repo
    doc = where / "h.md"
    doc.write_text("handoff body", encoding="utf-8")
    seat(where, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc), session=DEAD)
    doc.unlink()
    return record_path(repo)


def register(home: Path, session: str, pid: int, started_ms: int) -> None:
    """A registry record in the shape Claude Code writes: pid, sessionId, startedAt in Unix ms."""
    (home / ".claude" / "sessions" / f"{pid}.json").write_text(
        json.dumps({"pid": pid, "sessionId": session, "startedAt": started_ms, "cwd": "x"}),
        encoding="utf-8",
    )


def field_differences(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    """Every way ``after`` differs from ``before`` outside the two fields a clear may touch."""
    touched = {"handoff", "handoffClears"}
    out: list[str] = []
    kb = [k for k in before if k not in touched]
    ka = [k for k in after if k not in touched]
    if kb != ka:
        out.append(f"key order: {kb} -> {ka}")
    for k in kb:
        if k in after and before[k] != after[k]:
            out.append(f"{k}: {before[k]!r} -> {after[k]!r}")
    return out


class TestClearsADeadPointer:
    def test_a_dead_pid_record_with_a_dangling_pointer_is_cleared(
        self, repo: Path, home: Path
    ) -> None:
        rp = declare_dangling(repo)
        prior = load(rp)["handoff"]
        # A pid that existed and has exited: the fence must read DEAD, not merely "not found".
        gone = subprocess.Popen([sys.executable, "-c", "pass"])
        gone.wait()
        register(home, DEAD, gone.pid, int(time.time() * 1000))

        proc = clear(repo, home, rp.parent.name, rp.stem)
        assert proc.returncode == 0, proc.stderr
        assert proc.stdout.startswith("cleared "), proc.stdout

        rec = load(rp)
        assert rec["handoff"] is None
        entry = rec["handoffClears"][-1]
        assert entry["fenceState"] == "DEAD", entry
        assert entry["priorPointer"] == prior, "the whole prior pointer must be kept"
        assert entry["clearedBySessionId"] == "caller-sess"
        assert entry["clearedByBox"] and entry["writerVersion"] and entry["clearedAt"]
        assert not (seats_dir(repo) / ".writer-errors.txt").exists(), "a clear is not an error"

    def test_a_clear_still_works_after_the_worktree_is_removed(
        self, repo: Path, home: Path, tmp_path: Path
    ) -> None:
        """The orphaned-manager case: the handoff lived in the worktree, and both are gone."""
        wt = tmp_path / "wt"
        git(repo, "worktree", "add", "-q", "-b", "side", str(wt))
        doc = wt / "h.md"
        doc.write_text("handoff body", encoding="utf-8")
        seat(wt, "-Declare", "-Seat", "manager", "-Goal", "g", "-Handoff", str(doc), session=DEAD)
        rp = record_path(repo)
        git(repo, "worktree", "remove", "--force", str(wt))
        assert not wt.exists()

        proc = clear(repo, home, rp.parent.name, rp.stem)
        assert proc.returncode == 0, proc.stderr
        assert load(rp)["handoff"] is None

    def test_every_other_field_and_the_key_order_survive(self, repo: Path, home: Path) -> None:
        """Dates in a format pwsh would rewrite if it parsed them, and `asOf`/`writes` untouched."""
        rp = declare_dangling(repo)
        rec = load(rp)
        rec["asOf"] = "2026-09-25T00:37:14.1234567+00:00"
        rec["lifecycleAt"] = "2026-09-25T00:37:14Z"
        rec["declaredAt"] = "09/25/2026 00:37:14"
        rec["notes"] = "café → ok"
        rp.write_text(json.dumps(rec, indent=2, ensure_ascii=False), encoding="utf-8")
        before = load(rp)

        proc = clear(repo, home, rp.parent.name, rp.stem)
        assert proc.returncode == 0, proc.stderr
        after = load(rp)

        assert field_differences(before, after) == []
        assert list(after)[-1] == "handoffClears", "the audit trail is appended, not interleaved"
        assert len(after["handoffClears"]) == 1

    def test_the_comparison_catches_a_planted_change(self, repo: Path, home: Path) -> None:
        """POSITIVE CONTROL. A comparison that cannot fail would pass the test above vacuously."""
        rp = declare_dangling(repo)
        before = load(rp)
        assert clear(repo, home, rp.parent.name, rp.stem).returncode == 0
        after = load(rp)
        assert field_differences(before, after) == []

        mutated = dict(after)
        mutated["asOf"] = "2099-01-01T00:00:00Z"
        assert any(d.startswith("asOf:") for d in field_differences(before, mutated))

        reordered = {"writes": after["writes"], **{k: v for k, v in after.items() if k != "writes"}}
        assert any(d.startswith("key order") for d in field_differences(before, reordered))


class TestRefuses:
    def _assert_refused(self, proc: subprocess.CompletedProcess[str], rp: Path, raw: str) -> None:
        assert proc.returncode == 1, (proc.returncode, proc.stdout, proc.stderr)
        assert "REFUSED" in proc.stderr, proc.stderr
        assert rp.read_text(encoding="utf-8-sig") == raw, "a refusal must not write"

    def test_a_live_session_is_refused(self, repo: Path, home: Path) -> None:
        rp = declare_dangling(repo)
        raw = rp.read_text(encoding="utf-8-sig")
        live = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(60)"])
        try:
            register(home, DEAD, live.pid, int(time.time() * 1000))
            proc = clear(repo, home, rp.parent.name, rp.stem)
        finally:
            live.kill()
            live.wait()
        self._assert_refused(proc, rp, raw)
        assert "LIVE" in proc.stderr, proc.stderr
        assert not (seats_dir(repo) / ".writer-errors.txt").exists(), "a refusal is not an error"

    def test_a_pointer_whose_file_still_exists_is_refused(self, repo: Path, home: Path) -> None:
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc), session=DEAD)
        doc.write_text("body grown, so the pointer has drifted", encoding="utf-8")
        rp = record_path(repo)
        raw = rp.read_text(encoding="utf-8-sig")
        proc = clear(repo, home, rp.parent.name, rp.stem)
        self._assert_refused(proc, rp, raw)
        assert "still exists" in proc.stderr

    def test_no_fence_is_refused(self, repo: Path, tmp_path: Path) -> None:
        rp = declare_dangling(repo)
        raw = rp.read_text(encoding="utf-8-sig")
        bare = tmp_path / "bare-home"
        bare.mkdir()
        proc = clear(repo, bare, rp.parent.name, rp.stem)
        self._assert_refused(proc, rp, raw)
        assert "fence is unavailable" in proc.stderr

    def test_a_record_with_no_session_id_is_refused(self, repo: Path, home: Path) -> None:
        rp = declare_dangling(repo)
        rec = load(rp)
        rec["sessionId"] = None
        rp.write_text(json.dumps(rec), encoding="utf-8")
        raw = rp.read_text(encoding="utf-8-sig")
        proc = clear(repo, home, rp.parent.name, rp.stem)
        self._assert_refused(proc, rp, raw)
        assert "no sessionId" in proc.stderr

    def test_a_record_with_no_pointer_and_a_missing_record_are_refused(
        self, repo: Path, home: Path
    ) -> None:
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", session=DEAD)
        rp = record_path(repo)
        raw = rp.read_text(encoding="utf-8-sig")
        proc = clear(repo, home, rp.parent.name, rp.stem)
        self._assert_refused(proc, rp, raw)
        assert "no handoff pointer" in proc.stderr

        missing = clear(repo, home, rp.parent.name, "no-such-session")
        assert missing.returncode == 1 and "no record" in missing.stderr, missing.stderr

    def test_a_relative_pointer_is_refused_as_unevaluated(self, repo: Path, home: Path) -> None:
        rp = declare_dangling(repo)
        rec = load(rp)
        rec["handoff"]["path"] = "relative/h.md"
        rp.write_text(json.dumps(rec), encoding="utf-8")
        raw = rp.read_text(encoding="utf-8-sig")
        proc = clear(repo, home, rp.parent.name, rp.stem)
        self._assert_refused(proc, rp, raw)
        assert "cannot be evaluated" in proc.stderr

    @pytest.mark.parametrize("box", ["..", ".writer-alive", "a/b", ""])
    def test_a_key_that_could_escape_the_seats_directory_is_refused(
        self, repo: Path, home: Path, box: str
    ) -> None:
        proc = clear(repo, home, box, DEAD)
        assert proc.returncode == 1, (proc.stdout, proc.stderr)
        assert "REFUSED" in proc.stderr or "-Box" in proc.stderr, proc.stderr
