# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""A handoff pointer must not keep reading as true after the file it names moves on.

``seat.ps1 -Declare -Handoff <path>`` records path, bytes, sha256 and pointedAt, and sets
``unresolved`` when the path is missing AT DECLARE TIME. Nothing ever re-read it. ``fleet.ps1``
printed ``READ THE HANDOFF: <path>`` and warned only on that one never-refreshed flag.

Measured 2026-08-22 across every seat record on disk -- 265 records, 3 pointers, and by the end of
the session ALL THREE WERE WRONG:

    nice-payne-4dcee0-26279d9a      6232 bytes recorded, file absent        DANGLING
    lander-5c09c3-6b54f797          6246 bytes recorded, 110001 on disk     DRIFTED
    vigorous-hugle-802758-63d534e1  4801 bytes recorded, 4801 on disk       resolves -> DRIFTED

The third is the one worth reading twice. It resolved cleanly when first measured and had drifted
twenty minutes later, because the seat that declared it was still appending to it. The pointer did
not decay through neglect over days; it went wrong while its own author was working.

**DRIFTED IS THE WORSE STATE, AND IT IS THE ONE NOTHING REPORTED.** A dangling pointer advertises
its own brokenness -- the reader opens nothing and knows immediately. A drifted pointer opens, so
the replacement seat believes it was handed the document that was pointed at. That is the stale
-anchor shape CLAUDE.md section 11 names: the evidence moved, and the citation kept resolving to
something.

Two ends, because neither covers the other:

* ``seat.ps1`` re-checks on every ``-Record``, which is the Stop hook, which runs per turn in every
  config root. That covers a LIVE seat.
* ``fleet.ps1`` recomputes at render. That covers a DEAD one -- and the dangling pointer above
  belongs to a box whose last turn ended three days earlier, so its writer was never going to run
  again. A dead seat cannot report its own decay.

The positive control runs first on purpose. If ``resolves`` cannot be produced in this sandbox then
every assertion below it is vacuous, and a suite that only ever asserts the failure states would
pass against a function that returns one constant.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COORD = ROOT / "scripts" / "coord"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 and fleet.ps1 need pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its OWN copies of the scripts under test.

    Both scripts anchor on where they LIVE, so copying them in is what keeps a stray record out of
    the real registry -- the sandbox lesson test_coord_claim_refresh.py records.
    """
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    for name in ("seat.ps1", "fleet.ps1", "mail-key.ps1", "session-registry.ps1"):
        shutil.copy2(COORD / name, r / "scripts" / "coord" / name)
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def seat(cwd: Path, *args: str, session: str = "sess-ptr") -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env.pop("CLAUDE_CODE_SESSION_ID", None)
    env["CLAUDE_CODE_SESSION_ID"] = session
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "seat.ps1"),
            *args,
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def seats_dir(repo: Path) -> Path:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    return Path(common) / "mefor-coord" / "seats"


def records(repo: Path) -> dict[str, dict]:
    return {
        p.stem: json.loads(p.read_text(encoding="utf-8"))
        for p in sorted(seats_dir(repo).rglob("*.json"))
    }


def pointer(repo: Path, session: str = "sess-ptr") -> dict:
    rec = records(repo)[session]
    h = rec.get("handoff")
    assert h is not None, f"no handoff pointer on the record: {sorted(rec)}"
    return h


class TestSeatReValidatesThePointer:
    def test_pointer_reports_resolves_when_intact(self, repo: Path) -> None:
        """POSITIVE CONTROL, AND IT RUNS FIRST.

        Everything below asserts a failure state. If this one cannot pass, a function hard-coded to
        return 'dangling' would satisfy the rest of the class.
        """
        doc = repo / "h.md"
        doc.write_text("handoff body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        seat(repo, "-Record")
        h = pointer(repo)
        assert h["state"] == "resolves", h
        assert h["bytesNow"] == doc.stat().st_size
        assert h["checkedAt"]

    def test_pointer_reports_dangling_after_the_file_goes(self, repo: Path) -> None:
        """The nice-payne case: declared true, then the 12:03 archive moved the file."""
        doc = repo / "h.md"
        doc.write_text("handoff body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        recorded = pointer(repo)
        doc.unlink()
        seat(repo, "-Record")
        h = pointer(repo)
        assert h["state"] == "dangling", h
        assert h["bytesNow"] is None
        # The declaration is EVIDENCE, not a cache to refresh. Repairing it would erase the drift
        # rather than report it.
        for field in ("path", "bytes", "sha256", "pointedAt"):
            assert h[field] == recorded[field], (
                f"{field} was rewritten: {recorded[field]} -> {h[field]}"
            )

    def test_pointer_reports_drifted_when_the_file_grows(self, repo: Path) -> None:
        """The lander case, at its real magnitude: 6,246 bytes recorded against 110,001 on disk."""
        doc = repo / "h.md"
        doc.write_text("x" * 6246, encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        assert pointer(repo)["bytes"] == 6246
        doc.write_text("x" * 110001, encoding="utf-8")
        seat(repo, "-Record")
        h = pointer(repo)
        assert h["state"] == "drifted", h
        assert h["bytes"] == 6246, "the recorded size must survive"
        assert h["bytesNow"] == 110001, "the live size must be reported beside it"

    def test_a_pointer_declared_broken_recovers_when_the_file_appears(self, repo: Path) -> None:
        """`unresolved` is a fact about DECLARE TIME and must not outrank what is true now."""
        doc = repo / "later.md"
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        assert pointer(repo)["unresolved"] is True
        doc.write_text("it exists now", encoding="utf-8")
        seat(repo, "-Record")
        h = pointer(repo)
        assert h["state"] == "resolves", h
        assert h["unresolved"] is True, "the historical fact stays; `state` carries the live one"

    def test_record_does_not_erase_the_declared_pointer(self, repo: Path) -> None:
        """The `Prior` plumbing. A -Record knows nothing about -Handoff and must not drop it."""
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        for _ in range(3):
            seat(repo, "-Record")
        h = pointer(repo)
        assert h["path"].endswith("h.md")
        assert h["sha256"], "the declared hash must survive a Record that never computes one"

    def test_seat_exits_zero_when_the_pointer_target_is_unreadable(self, repo: Path) -> None:
        """seat.ps1 rule 2: a writer that dies must not take the Stop hook down with it."""
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        # A path no filesystem call can evaluate, reached through the recorded value.
        rec_path = next(iter(seats_dir(repo).rglob("sess-ptr.json")))
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        rec["handoff"]["path"] = "\\\\?\\nonsense::|<>"
        rec_path.write_text(json.dumps(rec), encoding="utf-8")
        proc = seat(repo, "-Record")
        assert proc.returncode == 0, proc.stderr
        assert pointer(repo)["state"] in {"dangling", "unreadable"}, pointer(repo)


class TestFleetRecomputesRatherThanTrustingTheRecord:
    """The reader half. A dead seat's writer never runs again, so only the reader can catch it."""

    def _fleet_json(self, repo: Path) -> dict:
        proc = subprocess.run(
            [
                "pwsh",
                "-NoProfile",
                "-NonInteractive",
                "-File",
                str(repo / "scripts" / "coord" / "fleet.ps1"),
                "-Json",
            ],
            cwd=str(repo),
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        # Exit 2 means fenceAvailable=false, which is expected in a sandbox with no config root.
        assert proc.returncode in (0, 2), f"rc={proc.returncode} stderr={proc.stderr}"
        return json.loads(proc.stdout)

    def test_fleet_recomputes_rather_than_reading_the_stored_flag(self, repo: Path) -> None:
        """A record asserting the pointer is fine, against a file that is not there.

        This is the shape the live registry was in: `unresolved` was false or absent on all three
        pointers, and two of them were broken.
        """
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        rec_path = next(iter(seats_dir(repo).rglob("sess-ptr.json")))
        rec = json.loads(rec_path.read_text(encoding="utf-8"))
        rec["handoff"]["unresolved"] = False
        rec["handoff"].pop("state", None)  # a record written before this rung existed
        rec_path.write_text(json.dumps(rec), encoding="utf-8")
        doc.unlink()

        out = self._fleet_json(repo)
        assert out["receipt"]["handoffPointers"] == 1
        assert out["receipt"]["handoffPointersDangling"] == 1
        rows = [r for r in out["rows"] if r.get("HandoffState")]
        assert rows and rows[0]["HandoffState"] == "dangling", rows

    def test_two_records_in_one_box_report_records_and_seats_separately(self, repo: Path) -> None:
        """A remediated seat leaves TWO records naming one handoff, and the counts must diverge.

        Measured 2026-08-22 on the live registry: 5 pointers across 4 boxes, because a seat whose
        declaration landed in nosid.json re-declared under its session id and neither record was
        pruned. Counting records answers "how many rows carry a pointer". It is the wrong
        denominator for "how many seats would be sent somewhere broken", and it inflates the moment
        anybody fixes their own record -- so remediation would read as the problem getting worse.
        """
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        rec_path = next(iter(seats_dir(repo).rglob("sess-ptr.json")))
        # The shape the live registry is in: same box, second record, same pointer.
        (rec_path.parent / "nosid.json").write_text(
            rec_path.read_text(encoding="utf-8"), encoding="utf-8"
        )
        doc.unlink()

        out = self._fleet_json(repo)
        assert out["receipt"]["handoffPointers"] == 2, "two records carry a pointer"
        assert out["receipt"]["handoffPointerSeats"] == 1, "but they are ONE seat"
        stops = " ".join(out["receipt"]["stopConditions"])
        assert "across 1 seat(s)" in stops, stops
        assert "duplicate records" in stops, "the divergence must be named, not left to arithmetic"

    def test_one_record_per_seat_does_not_claim_duplicates(self, repo: Path) -> None:
        """NEGATIVE CONTROL. The duplicate warning must not fire when records and seats agree."""
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        doc.unlink()
        out = self._fleet_json(repo)
        assert out["receipt"]["handoffPointers"] == out["receipt"]["handoffPointerSeats"] == 1
        assert "duplicate records" not in " ".join(out["receipt"]["stopConditions"])

    def test_the_receipt_reports_a_ratio_not_a_bare_count(self, repo: Path) -> None:
        """A numerator alone cannot be read: 1 dangling is a crisis at 2 pointers and noise at 200.

        THE FIXTURE CHANGED FROM A DRIFTED POINTER TO A DANGLING ONE (BACKLOG #1372) AND THE
        ASSERTION THIS TEST EXISTS FOR DID NOT. Drift was only the cheapest way to make a stop
        condition appear; the property under test is the RATIO FORMAT. Since drift no longer feeds
        the roll-up, a drifted fixture now produces no stop at all and this would have been
        asserting the format of a string that is never emitted.
        """
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        doc.unlink()
        out = self._fleet_json(repo)
        assert out["receipt"]["handoffPointersDangling"] == 1
        stops = " ".join(out["receipt"]["stopConditions"])
        assert "handoffPointersBroken=1 of 1" in stops, stops

    def test_a_drifted_pointer_alone_raises_no_stop_condition(self, repo: Path) -> None:
        """THE RULED BEHAVIOUR (BACKLOG #1372), pinned so it cannot be reverted by accident.

        A pointer exists so a seat told to READ THE HANDOFF reaches the right document. When the
        file has been UPDATED they reach the CURRENT one -- misdescribing a byte count and
        misdirecting a reader are different harms, and only the second is brokenness.

        Measured before the change: all five drifted seats in the live store were the seats keeping
        their handoffs current under the PROTECT rung, one of them entering the state ninety seconds
        after repairing it, while the 22 pointers naming a file that does not exist sat flat and
        invisible inside an 81% roll-up.

        THE DRIFT IS STILL COUNTED AND STILL REPORTED -- this asserts that too, so the change cannot
        be mistaken for suppressing it.
        """
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        doc.write_text("body grown longer", encoding="utf-8")

        out = self._fleet_json(repo)
        assert out["receipt"]["handoffPointersDrifted"] == 1, "the drift must still be REPORTED"
        assert out["receipt"]["handoffPointersDangling"] == 0
        stops = out["receipt"]["stopConditions"]
        assert not [s for s in stops if "handoffPointers" in s], stops

    def test_an_intact_pointer_raises_no_stop_condition(self, repo: Path) -> None:
        """NEGATIVE CONTROL. A gate that fires on everything reports nothing."""
        doc = repo / "h.md"
        doc.write_text("body", encoding="utf-8")
        seat(repo, "-Declare", "-Seat", "lander", "-Goal", "g", "-Handoff", str(doc))
        out = self._fleet_json(repo)
        assert out["receipt"]["handoffPointersDangling"] == 0
        assert out["receipt"]["handoffPointersDrifted"] == 0
        assert not [s for s in out["receipt"]["stopConditions"] if "handoffPointers" in s]
