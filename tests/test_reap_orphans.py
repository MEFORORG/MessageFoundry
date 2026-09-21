# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Tests for the orphaned-MSYS-tool detector (``scripts/coord/reap-orphans.ps1``).

THE PROPERTY UNDER TEST IS THAT IT DOES NOT KILL. Report-only is the default, killing needs
``-Kill``, and a candidate holding a listening TCP port is skipped unless ``-Force`` is also given.
Two 19-hour ``http.server`` fixtures were live on 127.0.0.1:8787 and :8788 on the box this was
written for, and a default sweep that took them out would have destroyed work while claiming to
clean up after it.

WHY A KILLER HAS TO BE OPT-IN HERE. ``taskkill /IM python.exe`` is machine-wide and has already
killed three interpreters on this box, only one of which belonged to the session that ran it. So
the script kills by PID or not at all, and these tests drive the read-only paths that every run
takes before it gets anywhere near a kill.

THE CONTROL LINE IS TESTED BECAUSE ITS ABSENCE IS INVISIBLE. A scan that finds nothing and a scan
that could not look print the same empty candidate list. The control line is the only thing that
separates them, so a run that omits it is a broken instrument that reads as a clean box.

Most of these tests drive the real script as a subprocess. They never pass ``-Kill``.

THE SUBPROCESS TESTS ARE WINDOWS-ONLY, AND THE GATE IS PER-TEST RATHER THAN MODULE-WIDE. The
script reads the process table with ``Get-CimInstance Win32_Process``; CIM/WMI is a Windows
interface, so on the ubuntu CI leg -- where pwsh IS installed -- every run exits with
``could not read the process table``. Making the script cross-platform is not the fix: the leak it
detects is an MSYS-on-Windows defect, so a Linux process table has nothing to say about it.

But the module must not skip WHOLE on Linux, because the assertions that read the script's TEXT
need no process table and are the only thing guarding this script on the only Linux leg. A module
that skips entirely there is a guard that cannot fail there. So the source-level tests carry no
mark and run everywhere, and :data:`_needs_windows_process_table` gates only the tests that
actually spawn the script.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "reap-orphans.ps1"

# BOTH HALVES ARE LOAD-BEARING AND THEY FAIL DIFFERENTLY. With no pwsh on PATH the spawn raises
# FileNotFoundError and the script is never reached; off Windows it IS reached, and gets as far as
# the error quoted in the module docstring above.
#
# SPELLED LIKE ITS SIBLINGS ON PURPOSE. Measured over tests/: `os.name != "nt"` paired with this
# same pwsh check is 39 of the 42 tooling-tier gates, every test_coord_*.py among them, against 3
# for `sys.platform != "win32"` -- which is the engine tier's spelling. Identical semantics, so the
# only thing at stake is whether a later sweep over the tier's 39 hand-copied gates finds this one.
_needs_windows_process_table = pytest.mark.skipif(
    shutil.which("pwsh") is None or os.name != "nt",
    reason="reap-orphans.ps1 reads Win32_Process through CIM, so it needs pwsh on Windows",
)


def run_script(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(SCRIPT), *args],
        capture_output=True,
        text=True,
        timeout=180,
    )


# EACH SPAWN COSTS A FULL Win32_Process CIM READ, so the tests that interrogate one invocation
# share it. The runs that must NOT be shared are marked where they are: the age-floor pair needs
# two readings of the same box, and the dead-parent check needs the script to run INSIDE a bracket
# of two independent pid snapshots.
@pytest.fixture(scope="module")
def default_run() -> subprocess.CompletedProcess[str]:
    return run_script()


@pytest.fixture(scope="module")
def default_json() -> dict[str, Any]:
    proc = run_script("-Json")
    assert proc.returncode == 0, proc.stderr
    payload: dict[str, Any] = json.loads(proc.stdout)
    return payload


@_needs_windows_process_table
def test_a_default_run_reports_and_exits_clean(
    default_run: subprocess.CompletedProcess[str],
) -> None:
    assert default_run.returncode == 0, default_run.stderr
    assert "control:" in default_run.stdout


def test_the_report_only_banner_is_pinned_in_the_source_not_only_in_a_run() -> None:
    """THE RUN-CONDITIONAL VERSION OF THIS TEST WAS ENVIRONMENT-DEPENDENT, WHICH IS WHY IT MOVED.

    The banner only prints when the box happens to have orphans. A test guarded on that asserts
    nothing on a clean box -- and a critic measured exactly that, zero candidates -- so deleting
    "REPORT ONLY" from the script would have stayed green everywhere except on whichever machine
    happened to be dirty. A test that reds by luck gets deleted rather than fixed.

    Reading the source pins the contract deterministically. The run-side check below still drives
    the real output when there is any.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    assert "REPORT ONLY" in text
    assert "-Kill to terminate" in text


@_needs_windows_process_table
def test_the_default_run_says_it_is_report_only_when_it_found_something(
    default_run: subprocess.CompletedProcess[str],
) -> None:
    """The banner has to name the mode, because the table alone reads like a kill log.

    VACUOUS ON A CLEAN BOX, and that is stated rather than hidden: with no candidates the banner
    never prints and neither assertion runs. The deterministic half is the source check above.
    """
    if "Stranded MSYS tool processes" in default_run.stdout:
        assert "REPORT ONLY" in default_run.stdout
        assert "-Kill" in default_run.stdout


@_needs_windows_process_table
def test_the_control_line_carries_all_three_numbers(default_json: dict[str, Any]) -> None:
    """A zero with no control beside it cannot be told apart from a scan that never looked."""
    control = default_json["control"]
    for field in ("TotalProcesses", "MsysToolsAlive", "DeadParentAnyAge"):
        assert field in control, f"the control block lost {field}"
        assert isinstance(control[field], int)
    # THE INSTRUMENT CHECK. This test runs under pwsh, which the process table must contain, so a
    # total of zero means the CIM query returned nothing rather than that the box is empty.
    assert control["TotalProcesses"] > 0, "the process table read as empty; the scan is broken"
    assert control["KillRequested"] is False
    assert control["Killed"] == 0


@_needs_windows_process_table
def test_the_control_reports_high_handle_processes_the_image_list_cannot_name(
    default_json: dict[str, Any],
) -> None:
    """The image list is this script's blind spot, and the control has to say so in a number.

    A python.exe or rg.exe walking the registry mounts leaks handles identically and is on no
    image list, so a zero candidate count must not be readable as "nothing is leaking". The handle
    floor is reported beside the count, because a bare count means nothing without its threshold.

    COUNTED OVER THE WHOLE TABLE, not just the orphans -- so the bound here is the process total.
    A dead-parent-only count read zero during an incident, when the runaway's session is still
    alive, which is precisely when an operator runs this.
    """
    control = default_json["control"]
    assert isinstance(control["HighHandleAnyParent"], int)
    assert control["HandleFloor"] > 0
    assert control["HighHandleAnyParent"] <= control["TotalProcesses"]


def test_the_identity_fence_fields_are_pinned_in_the_source() -> None:
    """A pid alone does not name a process across time, and -Kill re-reads before it acts.

    The row has to carry what that recheck compares against -- the image name and the creation
    time -- or the fence has nothing to fence with and degrades into a bare pid kill.

    THIS IS THE DETERMINISTIC HALF, SPLIT OUT SO IT STILL RUNS WHERE THE SCRIPT CANNOT. It was one
    test with the row loop below, which meant the whole assertion died on the ubuntu leg together
    with the subprocess -- leaving the fence pinned on Windows only.

    IT MATCHES THE ASSIGNMENT, NOT THE BARE NAME, BECAUSE THE BARE NAME COULD NOT FAIL. `"Mutating"
    in text` is satisfied by `$skippedMutating` and `SkippedMutatingImage`, `"Handles"` by the
    `$r.Handles` column in the report, and `"StartedTicks"` by the `-Kill` recheck that READS it --
    so deleting the row field left all three green. Anchoring to `<Field> =` at the start of a line
    ties each assertion to the line that actually builds the row.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    for field in ("StartedTicks", "Handles", "Mutating"):
        assert re.search(rf"^\s*{field}\s*=", text, re.M), (
            f"the row no longer assigns {field}, so a kill cannot recheck it"
        )


@_needs_windows_process_table
def test_every_candidate_carries_the_identity_fence_a_kill_would_recheck() -> None:
    """The run-side half of the fence check: the fields are present AND the right types.

    THE ROW LOOP IS VACUOUS ON A BOX WITH NO ORPHANS, and an earlier docstring here claimed the
    zero floor made sure it was not -- a provenance claim the evidence did not support. Candidate
    counts at a zero floor were measured at 7, then 3, then 0 on the same machine within an hour.
    So the field names are pinned from the source in the test above, and this loop checks their
    TYPES whenever the box happens to supply rows.
    """
    proc = run_script("-Json", "-MinAgeMinutes", "0")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert "SkippedPidRecycled" in payload["control"]
    assert "SkippedMutatingImage" in payload["control"]
    for row in payload["candidates"]:
        assert isinstance(row["StartedTicks"], int), row
        assert isinstance(row["Handles"], int), row
        assert isinstance(row["Mutating"], bool), row
        assert row["Name"], row


def test_a_kill_would_refuse_the_images_that_write() -> None:
    """The safety argument is about OUTPUT, and a writer breaks it in a way no parent check sees.

    A stranded git.exe killed mid index-pack leaves .git/index.lock behind and wedges every later
    git call in that repository; sed -i and sort -o leave a truncated temp file. Those images are
    still REPORTED -- narrowing detection would hide the leak this script exists to find -- but
    -Kill alone must refuse them. Asserted from the source because no test here ever passes -Kill.

    IT READS THE $MUTATING LIST ITSELF, BECAUSE A WHOLE-FILE SEARCH COULD NOT FAIL. All six of
    these images are ALSO in the $Image default that decides what counts as an MSYS tool, so
    `image in text` stayed green with the entire $MUTATING block deleted -- which is the edit that
    makes every writer -Kill eligible. Scoping the search to the list that populates $MUTATING is
    what makes the deletion red.
    """
    text = SCRIPT.read_text(encoding="utf-8")
    listed = re.search(
        r"foreach \(\$n in @\(([^)]*)\)\)\s*\{\s*\n\s*\$MUTATING\[\$n\] = \$true", text
    )
    assert listed, "the $MUTATING list is gone, so -Kill no longer refuses any writer"
    for image in ("git.exe", "sed.exe", "sort.exe", "sh.exe", "bash.exe", "xargs.exe"):
        assert image in listed.group(1), f"{image} writes, but -Kill would no longer refuse it"
    assert "-Force to override" in text


@_needs_windows_process_table
def test_a_default_run_kills_nothing_whatever_it_found(default_json: dict[str, Any]) -> None:
    assert default_json["control"]["Killed"] == 0
    for row in default_json["candidates"]:
        assert row["Action"] == "reported", row


@_needs_windows_process_table
def test_every_candidate_really_has_a_dead_parent_and_is_old_enough() -> None:
    """The parent check IS the safety argument, so it is asserted rather than described.

    A dead parent means no session is left to consume the output. If a candidate ever appears
    whose parent is alive, the predicate has inverted and the script would be proposing to kill
    something a peer is still waiting on. (A dead parent is NOT on its own a promise that killing
    destroys nothing -- the writer case is the test above.)

    VACUOUS WHEN THE BOX HAS NO ORPHANS, like every row loop in this module. It is kept because it
    is the only thing that catches an inverted predicate, and a false PASS here is a report nobody
    acts on rather than a kill nobody wanted.

    THE CONTROL IS TAKEN TWICE, BEFORE AND AFTER, AND ONLY THE INTERSECTION COUNTS. A single read
    cannot separate "this parent is alive" from "this pid was recycled in the second since the
    script looked", and a flaky safety test gets deleted rather than fixed. A pid present in both
    reads was alive across the whole window, so the script calling it dead is a real inversion.
    """
    before = _live_pids()
    proc = run_script("-Json", "-MinAgeMinutes", "10")
    assert proc.returncode == 0, proc.stderr
    after = _live_pids()
    alive_throughout = before & after
    payload = json.loads(proc.stdout)
    for row in payload["candidates"]:
        assert row["ParentPid"] not in alive_throughout, f"candidate {row} has a LIVE parent"
        assert row["AgeMinutes"] >= 10, row


@_needs_windows_process_table
def test_raising_the_age_floor_can_only_shrink_the_candidate_set() -> None:
    """A monotonicity check, which is what catches an age comparison written the wrong way round.

    Measured, not reasoned: both runs read the same box seconds apart, so a floor of one day
    cannot select a process that a floor of ten minutes rejected.
    """
    low_proc = run_script("-Json", "-MinAgeMinutes", "10")
    high_proc = run_script("-Json", "-MinAgeMinutes", "1440")
    assert low_proc.returncode == 0, low_proc.stderr
    assert high_proc.returncode == 0, high_proc.stderr
    low = json.loads(low_proc.stdout)
    high = json.loads(high_proc.stdout)
    low_pids = {r["Pid"] for r in low["candidates"]}
    high_pids = {r["Pid"] for r in high["candidates"]}
    assert high_pids <= low_pids, f"a higher floor selected {high_pids - low_pids}"


@_needs_windows_process_table
def test_an_unknown_image_list_finds_nothing_and_still_prints_the_control() -> None:
    """A zero that is EXPECTED, paired with a control line that proves the scan ran.

    Without the pairing, a zero from a broken scan and a zero from an empty box are one
    observation. The total here must still be non-zero.
    """
    proc = run_script("-Json", "-Image", "no-such-image-9f3a.exe")
    assert proc.returncode == 0, proc.stderr
    payload = json.loads(proc.stdout)
    assert payload["candidates"] == []
    assert payload["control"]["MsysToolsAlive"] == 0
    assert payload["control"]["TotalProcesses"] > 0


@_needs_windows_process_table
def test_the_output_is_ascii_so_it_survives_a_cp1252_console(
    default_run: subprocess.CompletedProcess[str],
) -> None:
    """CLAUDE.md section 11. A glyph raises UnicodeEncodeError on a stock Windows console, which
    would kill the run mid-report -- and this script is read while the box is already struggling.

    WINDOWS-ONLY IS NOT A GAP HERE, because this covers only what the source cannot show. A glyph
    SPELLED in this script is caught on every leg by tests/test_cp1252_console_safety.py, which
    walks scripts/**/*.ps1 with no platform gate. What that cannot see is a non-ASCII value the
    script picks up at RUNTIME and prints -- a process name can carry one -- and seeing that needs
    a real process table. A source-level copy of the central rule was drafted here and dropped:
    that module's docstring names the per-file ASCII assert as the very pattern it replaced.
    """
    assert default_run.stdout.isascii(), "non-ASCII in the report"


def _live_pids() -> set[int]:
    out = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "(Get-CimInstance Win32_Process -Property ProcessId).ProcessId | ConvertTo-Json -AsArray",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert out.returncode == 0, out.stderr
    pids = json.loads(out.stdout)
    assert pids, "the control process table read as empty"
    return {int(p) for p in pids}
