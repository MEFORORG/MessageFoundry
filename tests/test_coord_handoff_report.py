# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""Retiring a handoff must refuse before it moves, and moving must never lose bytes.

``handoff.ps1 -Report`` is read-only. ``-Retire`` is the only thing that moves, one entry at a time,
with four holds in the way. There is no ``-Delete`` and no bulk mode, and that is a design decision
rather than an omission: measured 2026-08-22 over the real directory, ownership cannot be recovered
after the fact. 23 of 37 entries carried no owner evidence at all, and the two independent
derivation instruments tried disagreed with each other while both sounded confident.

**Every refusal test is a PAIR.** Assert the refusal, then remove the cause and assert it moves. A
one-sided test passes against a script that refuses everything, which is the safest wrong answer and
would make the tool useless without failing anything. The unflagged-move test runs first for the
same reason -- if that cannot pass, every refusal below it is vacuous.

The holds, and what each was measured at on the day this was written:

    CITED                17 of 42   a sibling names it; moving it breaks a live-looking reference
    POINTED-AT            2 of 42   a seat record names it, so fleet.ps1 sends a seat there
    READS-AS-LIVE         5 of 42   undated name, instruction-shaped opening
    STALE-IN-A-LIVE-BOX   0 of 42   the harm a liveness fence structurally cannot see

The CITED hold is not hypothetical. ``2026-08-22-ROLES-HANDOVER-common-split.md`` names the 432 KB
``2026-08-22-ROLES-common-split-and-trap-retraction.patch`` beside it, so retiring the patch alone
leaves a handover document telling a reader to apply a file that is no longer there.
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
LIB = ("handoff.ps1", "box-activity.ps1", "session-registry.ps1", "occupancy.ps1", "mail-key.ps1")
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="handoff.ps1 needs pwsh on Windows",
)


@pytest.fixture
def sandbox(tmp_path: Path) -> Path:
    """Scripts and a coordination directory that are not the real ones.

    No test here touches the live mefor-coord. test_coord_seat_prompt.py records why: two stray
    claims once landed in the live registry because a test ran against the live tree.
    """
    box = tmp_path / "scripts" / "coord"
    box.mkdir(parents=True)
    for name in LIB:
        shutil.copy2(COORD / name, box / name)
    (tmp_path / "coord" / "handoffs").mkdir(parents=True)
    (tmp_path / "coord" / "seats").mkdir(parents=True)
    return tmp_path


def run(sandbox: Path, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(sandbox / "scripts" / "coord" / "handoff.ps1"),
            *args,
            "-CoordDir",
            str(sandbox / "coord"),
            "-ConfigRoot",
            str(sandbox / "noroot"),
        ],
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
    )


def put(sandbox: Path, name: str, body: str = "plain body, nothing imperative here\n") -> Path:
    f = sandbox / "coord" / "handoffs" / name
    f.write_text(body, encoding="utf-8")
    return f


def point_at(sandbox: Path, name: str) -> None:
    d = sandbox / "coord" / "seats" / "some-box-0000"
    d.mkdir(parents=True, exist_ok=True)
    (d / "sess.json").write_text(
        json.dumps({"handoff": {"path": str(sandbox / "coord" / "handoffs" / name), "bytes": 1}}),
        encoding="utf-8",
    )


def retired_dir(sandbox: Path) -> Path:
    hits = [p for p in (sandbox / "coord").glob("_retired-*") if p.is_dir()]
    assert len(hits) == 1, f"expected one retirement directory, found {hits}"
    return hits[0]


class TestRetireMovesWhatIsNotHeld:
    def test_retire_moves_an_unflagged_entry(self, sandbox: Path) -> None:
        """FIRST, AND IT MUST PASS. Every refusal below is vacuous if the tool never moves anything."""
        src = put(sandbox, "2026-08-13-old-note.md")
        proc = run(sandbox, "-Retire", "2026-08-13-old-note.md")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert not src.exists()
        assert (retired_dir(sandbox) / "handoffs" / "2026-08-13-old-note.md").is_file()

    def test_retire_never_deletes(self, sandbox: Path) -> None:
        """Byte-for-byte at the destination. A short copy reported as success is the one
        unrecoverable outcome this tool exists to avoid, so the move verifies before it removes."""
        body = "x" * 5000
        put(sandbox, "2026-08-13-old-note.md", body)
        run(sandbox, "-Retire", "2026-08-13-old-note.md")
        dest = retired_dir(sandbox) / "handoffs" / "2026-08-13-old-note.md"
        assert dest.read_text(encoding="utf-8") == body

    def test_the_manifest_lists_every_name(self, sandbox: Path) -> None:
        """The improvement on the 2026-08-22 precedent, whose README named a tarball and not the 224
        names inside it -- which is exactly why a dangling seat pointer could not be resolved."""
        put(sandbox, "2026-08-13-a.md")
        put(sandbox, "2026-08-13-b.md")
        run(sandbox, "-Retire", "2026-08-13-a.md")
        run(sandbox, "-Retire", "2026-08-13-b.md")
        rows = (retired_dir(sandbox) / "MANIFEST.tsv").read_text(encoding="utf-8")
        assert "2026-08-13-a.md" in rows
        assert "2026-08-13-b.md" in rows

    def test_readme_restore_command_round_trips(self, sandbox: Path) -> None:
        """The restore line is not decoration. Parse it out and run it."""
        put(sandbox, "2026-08-13-old-note.md", "body")
        run(sandbox, "-Retire", "2026-08-13-old-note.md")
        readme = (retired_dir(sandbox) / "README.md").read_text(encoding="utf-8")
        line = next(x for x in readme.splitlines() if x.strip().startswith("Restore:"))
        cmd = line.split("Restore:", 1)[1].strip().strip("`")
        proc = subprocess.run(
            ["pwsh", "-NoProfile", "-NonInteractive", "-Command", cmd],
            capture_output=True,
            text=True,
            timeout=TIMEOUT,
            check=False,
        )
        assert proc.returncode == 0, proc.stderr
        assert (sandbox / "coord" / "handoffs" / "2026-08-13-old-note.md").is_file()

    def test_a_retired_name_is_resolvable_afterwards(self, sandbox: Path) -> None:
        """Asking to retire something already retired must say where it went, not just say no."""
        put(sandbox, "2026-08-13-old-note.md")
        run(sandbox, "-Retire", "2026-08-13-old-note.md")
        proc = run(sandbox, "-Retire", "2026-08-13-old-note.md")
        assert proc.returncode == 0
        assert "ALREADY RETIRED" in proc.stdout
        assert "MANIFEST.tsv" in proc.stdout


class TestTheFourHolds:
    def test_retire_refuses_a_cited_entry(self, sandbox: Path) -> None:
        put(sandbox, "2026-08-13-target.md")
        put(sandbox, "2026-08-13-citer.md", "apply 2026-08-13-target.md before you start\n")
        proc = run(sandbox, "-Retire", "2026-08-13-target.md")
        assert proc.returncode == 1, proc.stdout
        assert "CITED" in proc.stdout
        assert (sandbox / "coord" / "handoffs" / "2026-08-13-target.md").exists()

    def test_and_it_moves_once_the_citation_is_gone(self, sandbox: Path) -> None:
        """PAIR. Without this, the refusal above passes against a script that refuses everything."""
        put(sandbox, "2026-08-13-target.md")
        citer = put(sandbox, "2026-08-13-citer.md", "apply 2026-08-13-target.md\n")
        citer.write_text("nothing named here\n", encoding="utf-8")
        assert run(sandbox, "-Retire", "2026-08-13-target.md").returncode == 0

    def test_retire_refuses_a_pointed_at_entry(self, sandbox: Path) -> None:
        put(sandbox, "2026-08-13-target.md")
        point_at(sandbox, "2026-08-13-target.md")
        proc = run(sandbox, "-Retire", "2026-08-13-target.md")
        assert proc.returncode == 1
        assert "POINTED-AT" in proc.stdout

    def test_and_it_moves_once_nothing_points_at_it(self, sandbox: Path) -> None:
        """PAIR."""
        put(sandbox, "2026-08-13-target.md")
        point_at(sandbox, "2026-08-13-somethingelse.md")
        assert run(sandbox, "-Retire", "2026-08-13-target.md").returncode == 0

    def test_retire_refuses_an_instruction_shaped_entry(self, sandbox: Path) -> None:
        """Undated name plus an imperative opening. This is the shape an arriving seat obeys."""
        put(sandbox, "RESUME-HERE.md", "# Resume here\n\nRead this first before you do anything.\n")
        proc = run(sandbox, "-Retire", "RESUME-HERE.md")
        assert proc.returncode == 1
        assert "READS-AS-LIVE" in proc.stdout

    def test_and_a_dated_name_with_the_same_body_moves(self, sandbox: Path) -> None:
        """PAIR, and it pins WHICH half of the predicate is doing the work.

        The date in the name is the convention's own signal that a document is a dated record rather
        than standing instruction. Same body, different name, opposite answer.
        """
        put(
            sandbox,
            "2026-08-13-RESUME.md",
            "# Resume here\n\nRead this first before you do anything.\n",
        )
        assert run(sandbox, "-Retire", "2026-08-13-RESUME.md").returncode == 0

    def test_an_imperative_deep_in_the_body_does_not_flag(self, sandbox: Path) -> None:
        """The over-flagging the first draft had. Calibrated: 5 hits at a 300-byte head, 10 at 4000.

        A document that says "pending" in paragraph nine is narrating, not instructing.
        """
        body = "# A report\n\n" + ("filler prose that instructs nobody. " * 200) + "\nstill open\n"
        put(sandbox, "SOME-REPORT.md", body)
        assert run(sandbox, "-Retire", "SOME-REPORT.md").returncode == 0

    def test_force_names_the_flag_it_overrode(self, sandbox: Path) -> None:
        """An override that does not say what it overrode is indistinguishable from no hold."""
        put(sandbox, "2026-08-13-target.md")
        put(sandbox, "2026-08-13-citer.md", "see 2026-08-13-target.md\n")
        proc = run(sandbox, "-Retire", "2026-08-13-target.md", "-Force")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        assert "FORCED OVER" in proc.stdout
        assert "CITED" in proc.stdout
        assert (
            "forced"
            in (retired_dir(sandbox) / "MANIFEST.tsv").read_text(encoding="utf-8").splitlines()[0]
        )

    def test_reads_as_live_entry_is_compressed_not_moved_loose(self, sandbox: Path) -> None:
        """A loose move relocates the harm rather than removing it.

        The precedent proves it: COORDINATOR-HANDOFF-LIVE.md, the file its own retirement README
        singles out as the worst offender, is sitting uncompressed in _retired-2026-08-22/ where it
        still reads exactly as it did before.
        """
        put(sandbox, "RESUME-HERE.md", "# Resume here\n\nRead this first.\n")
        proc = run(sandbox, "-Retire", "RESUME-HERE.md", "-Force")
        assert proc.returncode == 0, proc.stdout + proc.stderr
        dest = retired_dir(sandbox) / "handoffs"
        assert (dest / "RESUME-HERE.md.zip").is_file()
        assert not (dest / "RESUME-HERE.md").exists()


class TestReportTellsEmptyFromUnlooked:
    def test_report_distinguishes_nothing_found_from_nothing_looked(self, sandbox: Path) -> None:
        """Two states with opposite fixes that render identically without this branch."""
        empty = run(sandbox, "-Report")
        assert empty.returncode == 0
        assert "EMPTY" in empty.stdout
        assert "DOES NOT EXIST" not in empty.stdout

        shutil.rmtree(sandbox / "coord" / "handoffs")
        gone = run(sandbox, "-Report")
        assert gone.returncode == 0
        assert "DOES NOT EXIST" in gone.stdout
        assert "not the same as it being empty" in gone.stdout

    def test_report_prints_its_denominators_before_any_verdict(self, sandbox: Path) -> None:
        """fleet.ps1's receipt rule. A verdict with no denominator cannot be read."""
        put(sandbox, "2026-08-13-a.md")
        out = run(sandbox, "-Report").stdout
        head = out.splitlines()[:5]
        assert any("scanned" in x for x in head), head
        assert any("fence" in x for x in head), head
        assert any("holds" in x for x in head), head

    def test_report_moves_nothing(self, sandbox: Path) -> None:
        put(sandbox, "RESUME-HERE.md", "# Resume here\n\nRead this first.\n")
        put(sandbox, "2026-08-13-a.md")
        run(sandbox, "-Report")
        assert (sandbox / "coord" / "handoffs" / "RESUME-HERE.md").exists()
        assert (sandbox / "coord" / "handoffs" / "2026-08-13-a.md").exists()
        assert not list((sandbox / "coord").glob("_retired-*"))

    def test_json_carries_the_same_holds_as_the_text(self, sandbox: Path) -> None:
        put(sandbox, "2026-08-13-target.md")
        put(sandbox, "2026-08-13-citer.md", "see 2026-08-13-target.md\n")
        data = json.loads(run(sandbox, "-Json").stdout)
        assert data["receipt"]["cited"] == 1
        held = [e for e in data["entries"] if e["Flags"]]
        assert held and held[0]["Name"] == "2026-08-13-target.md"

    def test_the_marker_list_is_reported_as_a_floor(self, sandbox: Path) -> None:
        """Section 11: prefer "at least" to an enumeration. A closed-set claim here would be false."""
        put(sandbox, "2026-08-13-a.md")
        assert "A FLOOR, not a closed set" in run(sandbox, "-Report").stdout
