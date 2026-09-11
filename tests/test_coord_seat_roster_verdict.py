# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
"""`seat.ps1` wrote whatever `-Seat` it was handed, so one roster had two readers and one was blind.

THE FAILURE THESE TESTS PIN. `role-card-inject.ps1` resolves a seat against `docs/roles/seats.json`
and is LOUD about a retired label. `seat.ps1 -Declare` did not read the roster at all: it copied the
label into the record, and `fleet.ps1` then rendered it as a live seat. Both records were valid, so
nothing reported a problem -- the same hollow-record shape `test_coord_seat_session_key.py` pins one
field over.

MEASURED 2026-09-10, and reported by the session it happened to: it declared `-Seat manager` while
that label was not in the roster at all, and the script accepted it and wrote a record. With the
Console now RETIRED (BACKLOG #1529) the mirror case is the dangerous one -- `-Seat console` would be
recorded in silence while the card hook refuses the same label out loud, and substituting a Console
for a Manager is the exact error that retirement was written to stop.

IT WARNS AND RECORDS; IT DOES NOT GATE. That is the deliberate half. An undeclared seat renders as
UNDECLARED to every other session, so refusing a declaration trades a readable-but-odd record for NO
record, which is worse. `test_a_retired_declaration_is_still_recorded` is the arm that keeps anyone
from "fixing" this into a refusal.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SEAT = ROOT / "scripts" / "coord" / "seat.ps1"
MAILKEY = ROOT / "scripts" / "coord" / "mail-key.ps1"
SEATS = ROOT / "docs" / "roles" / "seats.json"
TIMEOUT = 120

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="seat.ps1 needs pwsh on Windows",
)


def git(repo: Path, *args: str) -> str:
    proc = subprocess.run(
        ["git", "-C", str(repo), *args], capture_output=True, text=True, timeout=TIMEOUT, check=True
    )
    return proc.stdout


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    """A throwaway checkout carrying its own copy of the script AND of the real roster.

    The roster is copied rather than hand-written, so these tests grade against the shipped
    `seats.json` and go red when the roster changes under them -- which is the point. A fixture
    roster would keep passing after the real one moved.
    """
    r = tmp_path / "repo"
    (r / "scripts" / "coord").mkdir(parents=True)
    (r / "docs" / "roles").mkdir(parents=True)
    subprocess.run(["git", "init", "-q", "-b", "main", str(r)], check=True, capture_output=True)
    git(r, "config", "user.email", "t@example.invalid")
    git(r, "config", "user.name", "t")
    shutil.copy2(SEAT, r / "scripts" / "coord" / "seat.ps1")
    shutil.copy2(MAILKEY, r / "scripts" / "coord" / "mail-key.ps1")
    shutil.copy2(SEATS, r / "docs" / "roles" / "seats.json")
    (r / "f.txt").write_text("x", encoding="utf-8")
    git(r, "add", "-A")
    git(r, "commit", "-qm", "base")
    return r


def declare(cwd: Path, seat_label: str) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    env["CLAUDE_CODE_SESSION_ID"] = "roster-verdict-probe"
    return subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(cwd / "scripts" / "coord" / "seat.ps1"),
            "-Declare",
            "-Seat",
            seat_label,
            "-Goal",
            "roster verdict probe",
        ],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=TIMEOUT,
        check=False,
        env=env,
    )


def record(repo: Path) -> dict[str, object]:
    common = git(repo, "rev-parse", "--path-format=absolute", "--git-common-dir").strip()
    found = sorted(Path(common).joinpath("mefor-coord", "seats").rglob("*.json"))
    assert len(found) == 1, f"expected exactly one record, got {[p.name for p in found]}"
    return json.loads(found[0].read_text(encoding="utf-8"))


def roster() -> dict:
    return json.loads(SEATS.read_text(encoding="utf-8"))


def test_a_live_seat_declares_silently(repo: Path) -> None:
    """The NEGATIVE ARM. A guard that fires on the correct input is worse than no guard."""
    proc = declare(repo, "manager")
    assert proc.returncode == 0, proc.stderr
    assert proc.stderr.strip() == "", (
        f"declaring a live seat said something, so the guard cannot be trusted on a retired one:\n"
        f"{proc.stderr}"
    )
    rec = record(repo)
    assert rec["seat"] == "manager"
    assert rec["seatCanonical"] == "manager"
    assert rec["seatRosterVerdict"] == "live"


def test_an_alias_declares_silently_and_records_its_canonical_seat(repo: Path) -> None:
    proc = declare(repo, "mgr")
    assert proc.returncode == 0, proc.stderr
    assert "WARNING" not in proc.stderr.upper(), proc.stderr
    rec = record(repo)
    assert rec["seat"] == "mgr", "the verbatim label must survive -- every reader keys on it"
    assert rec["seatCanonical"] == "manager"
    assert rec["seatRosterVerdict"] == "alias"


def test_a_retired_seat_warns_and_names_the_retirement(repo: Path) -> None:
    """The defect. `-Seat console` was recorded in silence while the card hook refused it loudly."""
    proc = declare(repo, "console")
    assert proc.returncode == 0, "a roster objection must not fail the declaration"
    err = proc.stderr
    assert "RETIRED SEAT" in err, f"declaring a retired seat said nothing:\n{err}"
    assert "MANAGER" in err, "the warning does not name the seat that replaces it"
    # Case-folded on purpose: the roster writes "is NOT a renamed Console", and a case-sensitive
    # match here would go red on a wording change that is not a defect.
    assert "not a renamed console" in err.lower(), (
        "the warning retires the label without denying the rename, which is the substitution "
        "error BACKLOG #1529 exists to stop"
    )
    for seat_name in roster()["live"]:
        assert seat_name in err, f"the warning does not list the live seat {seat_name!r}"
    assert record(repo)["seatRosterVerdict"] == "retired"


def test_a_retired_declaration_is_still_recorded(repo: Path) -> None:
    """The arm that stops anyone turning this into a refusal.

    No record is worse than an odd one: an undeclared seat renders as UNDECLARED to every other
    session, and a machine that invents a goal writes a record that looks declared and says nothing.
    """
    declare(repo, "console")
    rec = record(repo)
    assert rec["seat"] == "console", "the declaration was dropped instead of recorded"
    assert rec["seatSource"] == "declared"
    assert rec["goal"] == "roster verdict probe"
    assert rec["declaredAt"], "a recorded declaration must carry its date"


def test_every_console_spelling_warns_not_just_the_canonical_one(repo: Path) -> None:
    """`consul` is the spelling a typo produces, so it is the one that must not pass quietly."""
    proc = declare(repo, "consul")
    assert proc.returncode == 0, proc.stderr
    assert "RETIRED SEAT" in proc.stderr, proc.stderr
    assert record(repo)["seatRosterVerdict"] == "retired"


def test_a_korus_only_seat_says_it_is_a_roster_difference(repo: Path) -> None:
    proc = declare(repo, "reviewer")
    assert proc.returncode == 0, proc.stderr
    assert "NOT A SEAT IN THIS REPOSITORY" in proc.stderr, proc.stderr
    assert "not a typo and not a retirement" in proc.stderr
    assert record(repo)["seatRosterVerdict"] == "elsewhere"


def test_an_unmapped_label_warns_rather_than_rendering_as_a_real_seat(repo: Path) -> None:
    """The case the reporting session hit: a label in no map at all, recorded in silence."""
    proc = declare(repo, "wombat")
    assert proc.returncode == 0, proc.stderr
    assert "MATCHES NO SEAT" in proc.stderr, proc.stderr
    assert "fleet board" in proc.stderr, "the warning does not say what the bad record will do"
    rec = record(repo)
    assert rec["seatRosterVerdict"] == "unknown"
    assert rec["seatCanonical"] is None


def test_the_objection_goes_to_stderr_and_never_pollutes_stdout(repo: Path) -> None:
    """Measured 2026-09-10: `Write-Warning` renders to STDOUT on pwsh 7 here.

    That matters because `-Record` and `-Prompt` are hook paths, and seat.ps1 states they must not
    narrate into a session's context. A roster objection on stdout would do exactly that, and would
    also land in whatever parses the `wrote <path>` line. So the message goes to stderr explicitly.
    """
    proc = declare(repo, "console")
    assert "RETIRED SEAT" in proc.stderr, "the objection is not on stderr"
    assert "RETIRED SEAT" not in proc.stdout, (
        "the objection leaked onto stdout, which narrates into a session's context on the hook "
        "paths and pollutes the line callers parse"
    )
    assert proc.stdout.strip().startswith("wrote "), (
        f"stdout should carry only the record path, got: {proc.stdout!r}"
    )


def test_a_missing_roster_costs_no_declaration(repo: Path) -> None:
    """A roster this script cannot read must not cost a session its seat.

    This is the path every OTHER test would hide: with `seats.json` absent, every assertion above
    about silence still passes, so without this arm a broken roster read would look like a clean one.
    """
    (repo / "docs" / "roles" / "seats.json").unlink()
    proc = declare(repo, "console")
    assert proc.returncode == 0, proc.stderr
    assert "RETIRED SEAT" not in proc.stderr
    rec = record(repo)
    assert rec["seat"] == "console", "the declaration was lost when the roster went missing"
    assert rec["seatRosterVerdict"] == "no-roster", (
        "a missing roster must be recorded AS missing -- otherwise 'no objection' and 'nothing "
        "checked' are the same value, and the blind path is indistinguishable from the clean one"
    )


def test_the_script_reads_the_roster_at_all() -> None:
    """The instrument check. Every assertion above passes against a script that never opens it."""
    source = SEAT.read_text(encoding="utf-8")
    assert "docs/roles/seats.json" in source, (
        "seat.ps1 does not name the roster, so the verdict fields cannot be coming from it"
    )
