# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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


def test_the_shipped_roster_has_no_elsewhere_occupant() -> None:
    """The bucket emptied on 2026-09-16, so the verdict below needs an INJECTED occupant.

    Asserting the emptiness here is what keeps the next test honest. If the roster ever gains a
    real occupant this goes red, and whoever added it has to decide whether an injected probe still
    stands in for the real thing.
    """
    assert roster()["elsewhere"] == {}, (
        "the shipped roster gained an elsewhere occupant, so the probe below no longer represents it"
    )


def test_an_elsewhere_seat_says_it_is_a_roster_difference(repo: Path) -> None:
    """The bucket is empty, so this exercises seat.ps1's branch against an occupant it injects.

    Without the injection this branch has NO test: every assertion over an empty map passes while
    examining nothing. The probe also checks that the roster's own REASON reaches stderr, which the
    occupant-based version of this test never did -- a warning without the reason leaves the reader
    with a refusal and no roster fact.
    """
    seats_path = repo / "docs" / "roles" / "seats.json"
    data = json.loads(seats_path.read_text(encoding="utf-8"))
    assert data["elsewhere"] == {}, "the fixture roster already carries an occupant"
    reason = "A probe occupant, injected by this test and present in no shipped roster."
    data["elsewhere"] = {"probeseat": reason}
    seats_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    proc = declare(repo, "probeseat")
    assert proc.returncode == 0, proc.stderr
    assert "NOT A SEAT IN THIS REPOSITORY" in proc.stderr, proc.stderr
    assert "not a typo and not a retirement" in proc.stderr
    assert reason in proc.stderr, (
        "the warning dropped the roster's reason, so it reads as a refusal"
    )
    assert record(repo)["seatRosterVerdict"] == "elsewhere"


def test_the_probe_label_lands_in_unknown_without_the_injection(repo: Path) -> None:
    """The CONTROL. The same label must reach a DIFFERENT verdict when the bucket is untouched.

    Without this arm the test above proves only that seat.ps1 warns about something, not that the
    injection is what moved it from `unknown` to `elsewhere`.
    """
    proc = declare(repo, "probeseat")
    assert proc.returncode == 0, proc.stderr
    assert "MATCHES NO SEAT" in proc.stderr, proc.stderr
    assert record(repo)["seatRosterVerdict"] == "unknown"


def test_an_unmapped_label_warns_rather_than_rendering_as_a_real_seat(repo: Path) -> None:
    """The case the reporting session hit: a label in no map at all, recorded in silence."""
    proc = declare(repo, "wombat")
    assert proc.returncode == 0, proc.stderr
    assert "MATCHES NO SEAT" in proc.stderr, proc.stderr
    assert "fleet board" in proc.stderr, "the warning does not say what the bad record will do"
    rec = record(repo)
    assert rec["seatRosterVerdict"] == "unknown"
    assert rec["seatCanonical"] is None


@pytest.mark.parametrize("emptied", ["aliases", "retired", "elsewhere"])
def test_an_empty_roster_map_does_not_silence_the_objection(repo: Path, emptied: str) -> None:
    """MEASURED 2026-09-16, and it cost the whole warning.

    Under `Set-StrictMode -Version Latest`, `$map.PSObject.Properties.Name` THROWS on a map with no
    members. The resolver wraps its entire read in one catch, and that catch cannot tell an
    unreadable roster from a readable one holding an empty map -- so emptying `elsewhere` demoted
    EVERY verdict to `roster-unreadable`, and `MATCHES NO SEAT` stopped being printed at all. Exit
    code stayed 0 and stderr went empty, so nothing anywhere reported it.

    THE SHAPE, NOT THE INSTANCE. All three maps are read the same way, so all three are
    parameterized here: fixing only the map that happened to empty leaves the defect armed in the
    other two, waiting for the next roster edit.
    """
    seats_path = repo / "docs" / "roles" / "seats.json"
    data = json.loads(seats_path.read_text(encoding="utf-8"))
    data[emptied] = {}
    seats_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    proc = declare(repo, "wombat")
    assert proc.returncode == 0, proc.stderr
    assert "MATCHES NO SEAT" in proc.stderr, (
        f"emptying '{emptied}' silenced the objection entirely; stderr was {proc.stderr!r}"
    )
    assert record(repo)["seatRosterVerdict"] == "unknown", (
        f"emptying '{emptied}' demoted the verdict instead of resolving the label"
    )


def test_the_empty_map_probe_can_tell_a_silenced_run_from_a_healthy_one(repo: Path) -> None:
    """The POSITIVE CONTROL for the test above, which asserts a string is PRESENT.

    A roster the script genuinely cannot read produces exactly the failure signature that test
    guards against -- rc 0, empty stderr, verdict `roster-unreadable`. Reproducing it here proves
    the assertions above can actually distinguish the two states, rather than passing because
    `MATCHES NO SEAT` happens to appear whatever the roster holds.
    """
    (repo / "docs" / "roles" / "seats.json").write_text("{ not json", encoding="utf-8")
    proc = declare(repo, "wombat")
    assert proc.returncode == 0, "an unreadable roster must never cost a session its declaration"
    assert proc.stderr.strip() == "", proc.stderr
    assert record(repo)["seatRosterVerdict"] == "roster-unreadable"


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


# ------------------------------------------------------------------ the role-card marker
#
# WHY THESE ARMS EXIST. `seat.ps1` writes the fleet episode record and `role-card-inject.ps1` reads
# `.claude/seat.local.txt`. Nothing bridged them, so a session that declared its seat -- exactly what
# the SessionStart prompt asks every session to do -- got a record and no card, silently, at the next
# session start. Measured 2026-09-19: 165 of 171 worktrees on the development box carried no marker.

MARKER_REL = Path(".claude") / "seat.local.txt"
INJECTOR = ROOT / "scripts" / "hooks" / "role-card-inject.ps1"


def marker(repo: Path) -> str | None:
    p = repo / MARKER_REL
    return p.read_text(encoding="utf-8").strip() if p.exists() else None


def test_a_live_declaration_writes_the_role_card_marker(repo: Path) -> None:
    assert marker(repo) is None, "the fixture must start with no marker or this proves nothing"
    proc = declare(repo, "manager")
    assert proc.returncode == 0, proc.stderr
    assert marker(repo) == "manager"


def test_an_alias_declaration_writes_the_CANONICAL_marker(repo: Path) -> None:
    """`-Seat mgr` must leave `manager` behind, so the hook resolves it in one step next session."""
    declare(repo, "mgr")
    assert marker(repo) == "manager", (
        "the marker carries the canonical seat, not the typed label -- the record keeps the verbatim "
        "one, and these two fields answer different questions"
    )


@pytest.mark.parametrize("label", ["console", "zzqx9137nosuchseat"])
def test_a_declaration_that_resolves_to_no_live_seat_writes_no_marker(
    repo: Path, label: str
) -> None:
    """A retired or unmapped label already warns loudly. A marker would move that failure and hide it.

    The hook would refuse the same label at the NEXT session start, which is a quiet failure in a
    place nobody is watching -- so the loud CLI objection is the only report anyone gets.
    """
    proc = declare(repo, label)
    assert proc.returncode == 0, "a roster objection must not fail the declaration"
    assert proc.stderr.strip() != "", "the objection is the only report; it must still be made"
    assert marker(repo) is None, f"{label!r} resolves to no live seat, so it must leave no marker"


@pytest.mark.parametrize("label", ["console", "zzqx9137nosuchseat"])
def test_a_bad_declaration_does_not_clobber_a_GOOD_marker(repo: Path, label: str) -> None:
    """The dangerous half. Overwriting a working marker would take a card away from a live seat."""
    declare(repo, "manager")
    assert marker(repo) == "manager"
    declare(repo, label)
    assert marker(repo) == "manager", (
        f"declaring {label!r} overwrote a live seat's marker; the next session would get no card"
    )


def test_both_scripts_name_the_same_marker_path() -> None:
    """The bridge, pinned as text. A rename on either side reopens the gap with nothing reporting it.

    This is the anti-vacuity arm for the whole family above: those tests drive `seat.ps1` alone, so
    they would stay green if `role-card-inject.ps1` started reading somewhere else.
    """
    literal = ".claude/seat.local.txt"
    writer = SEAT.read_text(encoding="utf-8")
    reader = INJECTOR.read_text(encoding="utf-8")
    assert literal in writer, f"{SEAT.name} no longer writes {literal}"
    assert literal in reader, f"{INJECTOR.name} no longer reads {literal}"
