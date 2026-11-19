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
def test_the_finished_claude_worktrees_step_is_opt_in_and_forwarded() -> None:
    """Both directions, and it must not imply -Apply: without it the runner only reports."""
    default = plan()
    opted = plan("-RemoveFinishedClaudeWorktrees")
    both = plan("-Apply", "-RemoveFinishedClaudeWorktrees")

    assert "-RemoveFinishedClaudeWorktrees" not in default["argument"]
    assert default["removeFinishedClaudeWorktrees"] is False

    assert "-RemoveFinishedClaudeWorktrees" in opted["argument"]
    assert opted["removeFinishedClaudeWorktrees"] is True
    assert "-Apply" not in opted["argument"], "the opt-in step must not arm removal by itself"
    assert opted["mode"] == "DRYRUN"

    assert "-RemoveFinishedClaudeWorktrees" in both["argument"]
    assert "-Apply" in both["argument"]
    assert both["mode"] == "APPLY"

    # The plan says whether the primary's runner declares the switch, read from the file itself;
    # registration refuses on a false, so this field must not lie.
    runner = Path(opted["runner"])
    declares = runner.is_file() and "RemoveFinishedClaudeWorktrees" in runner.read_text(
        encoding="utf-8"
    )
    field = opted["runnerDeclaresRemoveFinishedClaudeWorktrees"]
    assert field is (declares if runner.is_file() else None)


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


@requires_windows
@pytest.mark.parametrize(("args", "hours"), [((), 4), (("-TimeLimitHours", "7"), 7)])
def test_the_time_limit_reaches_the_plan_and_sets_the_runners_stop(
    args: tuple[str, ...], hours: int
) -> None:
    """One hour never finished: measured 2026-11-18, the run was killed mid-list by the old fixed limit.

    The default is 4. The runner's own stop must sit inside the limit, or the task is killed before the
    runner writes its summary; and it must follow an explicit limit rather than stay at the default's.
    """
    p = plan(*args)
    assert p["timeLimitHours"] == hours
    stop = p["stopAfterMinutes"]
    assert (hours - 1) * 60 < stop < hours * 60, "the runner must stop shortly before the limit"
    assert f"-StopAfterMinutes {stop}" in p["argument"]


@requires_windows
@pytest.mark.parametrize("hours", ["0", "-1", "13"])
def test_a_time_limit_out_of_range_is_refused(hours: str) -> None:
    proc = run("-Json", "-TimeLimitHours", hours)
    assert proc.returncode != 0, f"-TimeLimitHours {hours} was accepted: {proc.stdout}"
    assert "TimeLimitHours" in proc.stderr
    assert not proc.stdout.strip(), "a refused value must print no plan"


def test_the_registration_uses_the_time_limit_the_plan_reports() -> None:
    """Registration cannot be driven from a test, so the one line that builds its settings is read.

    The plan is only a preview if the registration reads the same variable; the old literal one-hour
    limit is the drift this pins shut.
    """
    src = INSTALLER.read_text(encoding="utf-8")
    (settings,) = [line for line in src.splitlines() if "New-ScheduledTaskSettingsSet" in line]
    assert "-ExecutionTimeLimit (New-TimeSpan -Hours $TimeLimitHours)" in settings, settings


@requires_windows
def test_the_plan_says_whether_the_primarys_runner_declares_the_stop() -> None:
    """Registration refuses on a false here, since forwarding an undeclared parameter fails binding."""
    p = plan()
    runner = Path(p["runner"])
    field = p["runnerDeclaresStopAfterMinutes"]
    if not runner.is_file():
        assert field is None
    else:
        assert field is ("StopAfterMinutes" in runner.read_text(encoding="utf-8"))


# A prune-merged.ps1 stand-in that reports the credential-prompt variables it inherited.
PRUNE_STUB = (
    "param([string]$RepoRoot, [switch]$Apply, [double]$IdleHours)\n"
    '"stub prompt=$env:GIT_TERMINAL_PROMPT gcm=$env:GCM_INTERACTIVE"\n'
    "exit 0\n"
)


def run_copied_runner(
    tmp_path: Path, *args: str
) -> tuple[subprocess.CompletedProcess[str], str | None]:
    """Run a copy of the runner outside any repository, beside ``PRUNE_STUB``.

    Only the coord files the runner dot-sources without -RemoveFinishedClaudeWorktrees are copied.
    Returns the process and the log text (None when no log was written). Nothing here reaches the real
    repository: git discovery stops at ``tmp_path`` and no GIT_* variable is inherited.
    """
    scripts = tmp_path / "copy" / "scripts"
    (scripts / "coord").mkdir(parents=True)
    for name in ("occupancy.ps1", "session-registry.ps1"):
        shutil.copy2(ROOT / "scripts" / "coord" / name, scripts / "coord" / name)
    (scripts / "worktree").mkdir()
    shutil.copy2(RUNNER, scripts / "worktree" / RUNNER.name)
    (scripts / "worktree" / PRUNE.name).write_text(PRUNE_STUB, encoding="utf-8")
    log_dir = tmp_path / "logs"
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GCM_"))}
    env.pop("CLAUDECODE", None)
    env["GIT_CEILING_DIRECTORIES"] = str(tmp_path)
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-File",
            str(scripts / "worktree" / RUNNER.name),
            "-LogDir",
            str(log_dir),
            *args,
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    logs = list(log_dir.glob("prune-*.log"))
    return proc, (logs[0].read_text(encoding="utf-8") if logs else None)


@requires_windows
def test_an_unhandled_error_in_the_runner_still_writes_an_exit_line(tmp_path: Path) -> None:
    """A throw after the log directory exists used to end the run with nothing in the log.

    Run without -RepoRoot outside any repository, resolving the primary throws. Before the trap no log
    line was written at all; now the log must name the error and end with an exit line.
    """
    proc, text = run_copied_runner(tmp_path)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert text is not None, f"the error left no log line: {proc.stderr}"
    assert "STOPPED on an unhandled error: Not inside a git repository" in text, text
    assert re.search(r"^=== exit 1 \(FAILED", text.splitlines()[-1]), text


@requires_windows
def test_the_prune_run_cannot_wait_on_a_credential_prompt_and_is_bracketed(
    tmp_path: Path,
) -> None:
    """A scheduled run has nobody to answer a git credential prompt, so the child must not ask.

    A stub prune-merged.ps1 reports what it inherited. The markers either side of it are what tells a
    reader of a log that stops early whether it stopped inside that run.
    """
    proc, text = run_copied_runner(tmp_path, "-RepoRoot", str(tmp_path))
    assert proc.returncode == 0, proc.stdout + proc.stderr
    assert text is not None, proc.stderr
    lines = text.splitlines()
    assert "stub prompt=0 gcm=never" in lines, text
    stub_at = lines.index("stub prompt=0 gcm=never")
    assert lines[stub_at - 1] == "--- prune-merged.ps1 running ---", text
    assert re.match(r"--- prune-merged\.ps1 exit 0 at \d\d:\d\d:\d\d ---$", lines[stub_at + 1]), (
        text
    )
    assert re.match(r"=== exit 0 \(OK\) at \d\d:\d\d:\d\d ===$", lines[-1]), text
