# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""The daily-prune installer: the defaults that are load-bearing, and the guards that protect them.

``prune-merged.ps1`` shipped safe and nothing ever ran it. Measured 2026-09-18: 112 registered worktrees
against 5 live sessions, 38 GB under ``.claude/worktrees``. ``install-daily-prune.ps1`` schedules it, and
``run-daily-prune.ps1`` is what the schedule actually runs. Each property below fails silently, which is
why each one is pinned here rather than left to review.

**It must dry-run by default.** A scheduler that starts deleting worktrees the day it is installed gives
nobody a window to notice it is wrong about occupancy. Asserted in BOTH directions -- default lacks
``-Apply``, ``-Apply`` carries it -- because a test that only checks the default passes just as well
against a script that can never apply at all.

**It must agree with prune-merged.ps1 about which checkout is the primary.** ``prune-merged.ps1:236``
exits REFUSED when its ``-RepoRoot`` is not ``occupancy.ps1``'s ``PrimaryPath``. A scheduler that resolves
the primary its own way agrees by luck, and the day it stops agreeing the task logs REFUSED every night
forever with nothing pruned and nothing reporting that it is aimed wrong.

**It must not run as SYSTEM.** prune-merged's liveness fence reads each Claude config root's
``sessions/<pid>.json``. As SYSTEM those roots belong to a different profile, the fence reads nothing, and
a fence that cannot look vetoes nothing -- which silently converts the script's safest check into a no-op
while leaving every log line looking normal.

**What runs nightly must be a tracked file.** The task body was briefly a base64 ``-EncodedCommand`` built
from a here-string, so the only copy of the logging and exit-code logic lived inside a string: undiffable,
untestable, and unreadable from Task Scheduler without decoding a blob.

The ``CLAUDECODE`` guard is tested in paired arms: it must refuse under ``CLAUDECODE`` and must NOT refuse
without it. A guard that always throws is indistinguishable from one that works, and it is the one nobody
notices is broken.
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

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "scripts" / "worktree" / "install-daily-prune.ps1"
RUNNER = ROOT / "scripts" / "worktree" / "run-daily-prune.ps1"
PRUNE = ROOT / "scripts" / "worktree" / "prune-merged.ps1"

# A decoy name so nothing here can touch the real task, and one constant so a rename cannot leave two
# tests pointing at differently-spelled tasks that both happen not to exist.
PROBE_TASK_NAME = "MEFOR-Worktree-Prune-TestProbe"

pytestmark = pytest.mark.skipif(
    shutil.which("pwsh") is None, reason="pwsh (PowerShell 7) not on PATH"
)

# Named once. Applied to the tests that reach past the installer's Windows-only check; deliberately NOT a
# module-level mark, because the CLAUDECODE guard fires BEFORE that check and must be provable on any OS.
requires_windows = pytest.mark.skipif(
    os.name != "nt", reason="reaches the installer's Windows-only scheduled-task path"
)


def run(*args: str, claudecode: bool = False) -> subprocess.CompletedProcess[str]:
    """Drive the real installer. ``-Json`` never registers anything, so this touches no task store."""
    env = {**os.environ}
    if claudecode:
        env["CLAUDECODE"] = "1"
    else:
        env.pop("CLAUDECODE", None)
    return subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(INSTALLER), *args],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
    )


def plan(*args: str) -> dict[str, Any]:
    proc = run("-Json", *args)
    assert proc.returncode == 0, f"-Json failed: {proc.stderr}"
    parsed: dict[str, Any] = json.loads(proc.stdout)
    return parsed


@requires_windows
def test_dry_run_is_the_default_and_apply_is_opt_in() -> None:
    """Both directions. Either assertion alone passes against a script that can only do one of them."""
    default = plan()
    applied = plan("-Apply")

    assert "-Apply" not in default["argument"], (
        "the installed task must NOT remove anything by default"
    )
    assert default["mode"] == "DRYRUN"

    assert "-Apply" in applied["argument"], "-Apply must reach the scheduled task's command line"
    assert applied["mode"] == "APPLY"


@requires_windows
def test_it_agrees_with_prune_merged_about_the_primary_checkout() -> None:
    """The installer's primary must be the one prune-merged.ps1 would accept, not merely a valid repo."""
    p = plan()
    repo_root = Path(p["repoRoot"])

    assert ".claude" not in repo_root.parts, f"resolved a worktree, not the primary: {repo_root}"
    assert "worktrees" not in repo_root.parts, f"resolved a worktree, not the primary: {repo_root}"
    assert (repo_root / ".git").exists(), f"not a checkout: {repo_root}"

    # The authority, asked directly: occupancy.ps1's PrimaryPath is the value prune-merged.ps1:236
    # compares against. Anything else here would be a second opinion.
    probe = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f". '{ROOT / 'scripts' / 'coord' / 'occupancy.ps1'}'; "
            f"(Get-WorktreeOccupancy -Repo '{ROOT}').PrimaryPath",
        ],
        capture_output=True,
        text=True,
        timeout=120,
    )
    authority = probe.stdout.strip()
    assert authority, f"could not read PrimaryPath: {probe.stderr}"
    assert Path(authority) == repo_root, (
        f"installer says {repo_root}, occupancy.ps1 says {authority} -- "
        "prune-merged.ps1 would exit REFUSED every night"
    )


@requires_windows
def test_the_task_does_not_run_elevated_or_as_system() -> None:
    p = plan()
    assert p["runLevel"] == "Limited"
    assert p["logonType"] == "Interactive"
    assert "SYSTEM" not in p["userId"].upper(), "SYSTEM blinds prune-merged's liveness fence"


@requires_windows
def test_what_runs_nightly_is_a_tracked_file_not_manufactured_text() -> None:
    """Pins the fix for the base64 here-string: the task body must be a file on disk."""
    p = plan()

    assert "EncodedCommand" not in p["argument"], (
        "the task body must not be manufactured text -- it cannot be diffed, tested or read back"
    )
    runner = Path(p["runner"])
    assert f'-File "{runner}"' in p["argument"]
    assert runner.name == RUNNER.name
    assert runner.suffix == ".ps1"
    # Not `runner.is_file()`: run from a worktree before this change lands, the primary legitimately does
    # not have it yet. What must hold either way is that the plan does not LIE about which it is -- the
    # installer refuses to register on a false here, and that refusal is only as good as this field.
    assert p["runnerExists"] is runner.is_file()


@requires_windows
def test_the_scheduled_runner_lives_in_the_primary_not_the_calling_worktree() -> None:
    """A worktree is by construction a thing somebody deletes.

    Asserting the runner equals THIS file's sibling would pin the bug rather than the fix, because this
    test usually runs from a worktree too -- so the assertion is against the resolved primary instead.
    """
    p = plan()
    runner = Path(p["runner"])
    repo_root = Path(p["repoRoot"])

    assert runner.is_relative_to(repo_root), (
        f"scheduled runner {runner} is outside the primary {repo_root} -- "
        "the task would point at a path that disappears when the worktree is removed"
    )
    assert ".claude" not in runner.parts
    assert "worktrees" not in runner.parts


def test_the_exit_code_table_matches_prune_merged() -> None:
    """run-daily-prune.ps1 holds a SECOND copy of prune-merged.ps1's exit-code contract.

    Moving the logging inside that 1502-line safety-critical script is the deeper fix and belongs in its
    own change. Until then the copy is held shut here, so the duplication cannot drift silently -- which
    is the only thing that made it acceptable to write down twice.
    """
    prune_src = PRUNE.read_text(encoding="utf-8")
    runner_src = RUNNER.read_text(encoding="utf-8")

    declared = {
        int(m.group(2)) for m in re.finditer(r"^\$EXIT_(\w+)\s*=\s*(\d+)", prune_src, re.MULTILINE)
    }
    assert declared, (
        "found no $EXIT_* constants in prune-merged.ps1 -- this test's instrument is broken"
    )

    table = runner_src.split("$EXIT_MEANING = @{", 1)[1].split("}", 1)[0]
    covered = {int(m.group(1)) for m in re.finditer(r"^\s*(\d+)\s*=", table, re.MULTILINE)}

    assert covered == declared, (
        f"run-daily-prune.ps1 explains exit codes {sorted(covered)}, "
        f"prune-merged.ps1 defines {sorted(declared)}"
    )


@requires_windows
def test_json_registers_nothing() -> None:
    """A plan-only run must leave the task store untouched, under a name nothing else would claim."""
    p = plan("-TaskName", PROBE_TASK_NAME)
    assert p["taskName"] == PROBE_TASK_NAME

    probe = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$t = Get-ScheduledTask -TaskName '{PROBE_TASK_NAME}' -ErrorAction SilentlyContinue; "
            "if ($t) { 'FOUND' } else { 'ABSENT' }",
        ],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert probe.stdout.strip() == "ABSENT", "-Json must not register a task"


def test_the_claudecode_guard_discriminates() -> None:
    """Paired arms on ONE variable, with DISJOINT reds.

    Both arms pass ``-Uninstall`` -- the only non-``-Json`` path that reaches past the guard and still
    changes nothing on a machine where the task was never registered. So the ONLY thing varying is
    ``CLAUDECODE``, and the two arms must fail differently rather than one failing and one passing for
    an unrelated reason.
    """
    refused = run("-Uninstall", "-TaskName", PROBE_TASK_NAME, claudecode=True)
    assert refused.returncode != 0, "must refuse from inside Claude Code"
    assert "Refusing to run inside Claude Code" in (refused.stderr + refused.stdout)

    allowed = run("-Uninstall", "-TaskName", PROBE_TASK_NAME, claudecode=False)
    assert "Refusing to run inside Claude Code" not in (allowed.stderr + allowed.stdout), (
        "the guard fired without CLAUDECODE -- it does not discriminate, it always throws"
    )


@requires_windows
def test_json_is_exempt_from_the_guard() -> None:
    """A separate claim from the one above: ``-Json`` registers nothing, so it stays usable in-session."""
    allowed = run("-Json", claudecode=True)
    assert allowed.returncode == 0, (
        "-Json must stay usable inside Claude Code: it registers nothing"
    )
    assert "Refusing" not in allowed.stderr
