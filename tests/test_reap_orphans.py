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

These tests drive the real script as a subprocess. They never pass ``-Kill``.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts" / "coord" / "reap-orphans.ps1"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
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


def test_a_default_run_reports_and_exits_clean(
    default_run: subprocess.CompletedProcess[str],
) -> None:
    assert default_run.returncode == 0, default_run.stderr
    assert "control:" in default_run.stdout


def test_the_default_run_says_it_is_report_only_when_it_found_something(
    default_run: subprocess.CompletedProcess[str],
) -> None:
    """The banner has to name the mode, because the table alone reads like a kill log."""
    if "Stranded MSYS tool processes" in default_run.stdout:
        assert "REPORT ONLY" in default_run.stdout
        assert "-Kill" in default_run.stdout


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


def test_the_control_reports_high_handle_processes_the_image_list_cannot_name(
    default_json: dict[str, Any],
) -> None:
    """The image list is this script's blind spot, and the control has to say so in a number.

    A python.exe or rg.exe walking the registry mounts leaks handles identically and is on no
    image list, so a zero candidate count must not be readable as "nothing is leaking". The handle
    floor is reported beside the count, because a bare count means nothing without its threshold.
    """
    control = default_json["control"]
    assert isinstance(control["DeadParentOverHandleFloor"], int)
    assert control["HandleFloor"] > 0
    assert control["DeadParentOverHandleFloor"] <= control["DeadParentAnyAge"]


def test_every_candidate_carries_the_identity_fence_a_kill_would_recheck() -> None:
    """A pid alone does not name a process across time, and -Kill re-reads before it acts.

    The row has to carry what that recheck compares against -- the image name and the creation
    time -- or the fence has nothing to fence with and degrades into a bare pid kill. Driven at a
    zero floor so the assertions see rows on an ordinary box rather than passing over an empty list.
    """
    payload = json.loads(run_script("-Json", "-MinAgeMinutes", "0").stdout)
    assert "SkippedPidRecycled" in payload["control"]
    for row in payload["candidates"]:
        assert isinstance(row["StartedTicks"], int), row
        assert isinstance(row["Handles"], int), row
        assert row["Name"], row


def test_a_default_run_kills_nothing_whatever_it_found(default_json: dict[str, Any]) -> None:
    assert default_json["control"]["Killed"] == 0
    for row in default_json["candidates"]:
        assert row["Action"] == "reported", row


def test_every_candidate_really_has_a_dead_parent_and_is_old_enough() -> None:
    """The parent check IS the safety argument, so it is asserted rather than described.

    A dead parent means no session is left to consume the output, so killing destroys no work
    product. If a candidate ever appears whose parent is alive, the predicate has inverted and the
    script would be proposing to kill something a peer is still waiting on.

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


def test_raising_the_age_floor_can_only_shrink_the_candidate_set() -> None:
    """A monotonicity check, which is what catches an age comparison written the wrong way round.

    Measured, not reasoned: both runs read the same box seconds apart, so a floor of one day
    cannot select a process that a floor of ten minutes rejected.
    """
    low = json.loads(run_script("-Json", "-MinAgeMinutes", "10").stdout)
    high = json.loads(run_script("-Json", "-MinAgeMinutes", "1440").stdout)
    low_pids = {r["Pid"] for r in low["candidates"]}
    high_pids = {r["Pid"] for r in high["candidates"]}
    assert high_pids <= low_pids, f"a higher floor selected {high_pids - low_pids}"


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


def test_the_output_is_ascii_so_it_survives_a_cp1252_console(
    default_run: subprocess.CompletedProcess[str],
) -> None:
    """CLAUDE.md section 11. A glyph raises UnicodeEncodeError on a stock Windows console, which
    would kill the run mid-report -- and this script is read while the box is already struggling."""
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
