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
import time
from pathlib import Path
from typing import Any

import psutil
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


def test_the_runners_own_exit_code_is_not_one_of_prune_merged() -> None:
    """The runner's deadline-stop code must mean only that.

    It replaces a 0 and nothing else, so its value need not rank against the others, but a value
    prune-merged.ps1 also returns would make a log's exit line ambiguous.
    """
    declared = {
        int(m.group(1))
        for m in re.finditer(
            r"^\$EXIT_\w+\s*=\s*(\d+)", PRUNE.read_text(encoding="utf-8"), re.MULTILINE
        )
    }
    found = re.search(r"^\$EXIT_DEADLINE = (\d+)", RUNNER.read_text(encoding="utf-8"), re.MULTILINE)
    assert found, "run-daily-prune.ps1 no longer declares $EXIT_DEADLINE"
    assert int(found.group(1)) not in declared, (found.group(1), sorted(declared))


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


def copy_runner(
    tmp_path: Path, prune_stub: str = PRUNE_STUB, extra: dict[str, str] | None = None
) -> tuple[Path, Path, dict[str, str]]:
    """Copy the runner outside any repository, beside ``prune_stub`` as its prune-merged.ps1.

    Only the coord files the runner dot-sources without -RemoveFinishedClaudeWorktrees are copied;
    ``extra`` writes further files beside the runner. Returns the runner's path, the log directory and
    the environment to run it under. Nothing here reaches the real repository: git discovery stops at
    ``tmp_path`` and no GIT_* variable is inherited.
    """
    scripts = tmp_path / "copy" / "scripts"
    (scripts / "coord").mkdir(parents=True)
    for name in ("occupancy.ps1", "session-registry.ps1"):
        shutil.copy2(ROOT / "scripts" / "coord" / name, scripts / "coord" / name)
    (scripts / "worktree").mkdir()
    shutil.copy2(RUNNER, scripts / "worktree" / RUNNER.name)
    (scripts / "worktree" / PRUNE.name).write_text(prune_stub, encoding="utf-8")
    for name, text in (extra or {}).items():
        (scripts / "worktree" / name).write_text(text, encoding="utf-8")
    env = {k: v for k, v in os.environ.items() if not k.startswith(("GIT_", "GCM_"))}
    env.pop("CLAUDECODE", None)
    env["GIT_CEILING_DIRECTORIES"] = str(tmp_path)
    return scripts / "worktree" / RUNNER.name, tmp_path / "logs", env


def read_log(log_dir: Path) -> str | None:
    logs = list(log_dir.glob("prune-*.log"))
    return logs[0].read_text(encoding="utf-8") if logs else None


def run_copied_runner(
    tmp_path: Path,
    *args: str,
    prune_stub: str = PRUNE_STUB,
    extra: dict[str, str] | None = None,
    env_extra: dict[str, str] | None = None,
) -> tuple[subprocess.CompletedProcess[str], str | None]:
    """Run a copy of the runner (see ``copy_runner``).

    Returns the process and the log text (None when no log was written).
    """
    runner, log_dir, env = copy_runner(tmp_path, prune_stub, extra)
    env.update(env_extra or {})
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(runner), "-LogDir", str(log_dir)]
        + list(args),
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    return proc, read_log(log_dir)


@requires_windows
def test_an_unhandled_error_in_the_runner_still_writes_an_exit_line(tmp_path: Path) -> None:
    """A throw after the log directory exists used to end the run with nothing in the log.

    Run without -RepoRoot outside any repository, resolving the primary throws. Before the trap no log
    line was written at all; now the log must name the error and its line, and end with an exit line.
    Nothing was attempted, so the code is 2, whose meaning promises that, not 1 ("attempted").
    """
    proc, text = run_copied_runner(tmp_path)
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert text is not None, f"the error left no log line: {proc.stderr}"
    assert "STOPPED on an unhandled error: Not inside a git repository" in text, text
    assert re.search(r"\(at .*run-daily-prune\.ps1:\d+\)", text), text
    assert re.search(r"^=== exit 2 \(REFUSED", text.splitlines()[-1]), text


# No deadline starts the prune child with `&`; a deadline starts it as a process waited on with a time
# limit. The tests that pin how the child is started run under both.
DEADLINES = pytest.mark.parametrize(
    "deadline", [[], ["-StopAfterMinutes", "10"]], ids=["no-deadline", "deadline"]
)


@requires_windows
@DEADLINES
def test_the_prune_run_cannot_wait_on_a_credential_prompt_and_is_bracketed(
    tmp_path: Path, deadline: list[str]
) -> None:
    """A scheduled run has nobody to answer a git credential prompt, so the child must not ask.

    A stub prune-merged.ps1 reports what it inherited. The markers either side of it are what tells a
    reader of a log that stops early whether it stopped inside that run.
    """
    proc, text = run_copied_runner(tmp_path, "-RepoRoot", str(tmp_path), *deadline)
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


# A stub that reports what it inherited into the file $env:T_STARTED names, then waits long enough to
# be stopped part way. A file, not the log: the runner's log holds the stub's lines until it returns.
SLOW_PRUNE_STUB = (
    "param([string]$RepoRoot, [switch]$Apply, [double]$IdleHours)\n"
    '"stub prompt=$env:GIT_TERMINAL_PROMPT gcm=$env:GCM_INTERACTIVE" | Set-Content $env:T_STARTED\n'
    "Start-Sleep -Seconds 30\n"
    "exit 0\n"
)


@requires_windows
@pytest.mark.parametrize(
    ("before", "after"),
    [
        ({}, "after prompt=[] gcm=[] exists=False,False"),
        (
            {"GIT_TERMINAL_PROMPT": "1", "GCM_INTERACTIVE": "always"},
            "after prompt=[1] gcm=[always] exists=True,True",
        ),
    ],
    ids=["unset-before", "set-before"],
)
def test_a_hand_run_stopped_part_way_leaves_the_shells_prompt_variables_alone(
    tmp_path: Path, before: dict[str, str], after: str
) -> None:
    """A stop part way must not leave the prompt variables changed in the operator's shell.

    A hand run with ``&`` shares the caller's process. Here one pwsh stands in for that shell: the
    runner runs in a second runspace of it and is stopped with a runspace Stop while the stub
    prune-merged.ps1 is still running. Restored only in Exit-Run, both variables stayed set; the
    runner's `finally` now removes each that was unset before and puts back each value that was set,
    and the child still saw both as the runner set them.
    """
    runner, log_dir, env = copy_runner(tmp_path, SLOW_PRUNE_STUB)
    started = tmp_path / "stub-started.txt"
    env.update(
        {
            "T_RUNNER": str(runner),
            "T_LOGDIR": str(log_dir),
            "T_REPO": str(tmp_path),
            "T_STARTED": str(started),
            **before,
        }
    )
    script = (
        "$ps = [powershell]::Create().AddScript("
        "'& $env:T_RUNNER -LogDir $env:T_LOGDIR -RepoRoot $env:T_REPO'); "
        "$null = $ps.BeginInvoke(); $sw = [Diagnostics.Stopwatch]::StartNew(); "
        "while ($sw.Elapsed.TotalSeconds -lt 60 -and -not (Test-Path -LiteralPath $env:T_STARTED)) "
        "{ Start-Sleep -Milliseconds 100 }; "
        "$ps.Stop(); "
        '"state=$($ps.InvocationStateInfo.State) '
        "after prompt=[$env:GIT_TERMINAL_PROMPT] gcm=[$env:GCM_INTERACTIVE] "
        'exists=$(Test-Path Env:\\GIT_TERMINAL_PROMPT),$(Test-Path Env:\\GCM_INTERACTIVE)"'
    )
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    assert started.is_file(), proc.stdout + proc.stderr
    assert started.read_text(encoding="utf-8").strip() == "stub prompt=0 gcm=never"
    assert "state=Stopped " in proc.stdout, f"the run must be stopped part way: {proc.stdout}"
    assert after in proc.stdout, proc.stdout + proc.stderr


# A prune-merged.ps1 stand-in that REFUSES the prune (exit 2, nothing attempted) and lists one finished
# tree for the -RemoveFinishedClaudeWorktrees step.
REFUSING_PRUNE_STUB = (
    "param([string]$RepoRoot, [switch]$Apply, [double]$IdleHours, [switch]$Json, [switch]$SkipGh)\n"
    "if ($Json) {\n"
    '  \'{"fence":{"idleHours":24},"counts":{"reportOnlyHeld":0},"reportOnly":['
    '{"path":"X:/r/.claude/worktrees/a","claudeManaged":true,"branch":"b","whyFinished":"w"}]}\'\n'
    "  exit 0\n"
    "}\n"
    '"stub refused"\n'
    "exit $(if ($env:T_PRUNE_EXIT) { [int]$env:T_PRUNE_EXIT } else { 2 })\n"
)

# A finished-worktree-removal.ps1 stand-in: every path comes back with the outcome $env:T_OUTCOME
# names, and with $env:T_THROW set the helper then throws, as an unexpected error part way would.
REMOVING_HELPER_STUB = (
    "function Assert-NoGitRedirect([string]$Who) { }\n"
    "function Invoke-FinishedWorktreeRemoval {\n"
    "  param([string]$Primary, [string[]]$Paths, [double]$IdleHours, [string[]]$Protect,"
    " [switch]$Apply, $StopAt)\n"
    "  foreach ($p in $Paths) {"
    " [pscustomobject]@{ Path = $p; Outcome = $env:T_OUTCOME; Reason = 'stub'; Command = 'stub' } }\n"
    "  if ($env:T_THROW) { throw 'stub failure after a row' }\n"
    "}\n"
)


@requires_windows
@pytest.mark.parametrize(
    ("apply", "outcome", "throw", "expected"),
    [
        (True, "REMOVED", False, 1),
        (True, "REMOVED", True, 1),
        (True, "FAILED", False, 1),
        (True, "FAILED", True, 1),
        (True, "DECLINED", False, 1),
        (True, "DECLINED", True, 1),
        (True, "ORPHANED", False, 3),
        (True, "ORPHANED", True, 3),
        # A tree the deadline left is a deadline stop, which never replaces the prune's 2.
        (True, "NOT-REACHED", False, 2),
        (True, "NOT-REACHED", True, 2),
        # Controls: nothing was attempted, so the prune's 2 stands.
        (True, "REFUSED", False, 2),
        (True, "REFUSED", True, 2),
        (False, "WOULD-REMOVE", False, 2),
        (False, "WOULD-REMOVE", True, 2),
    ],
)
def test_the_exit_code_says_nothing_was_attempted_only_when_that_is_true(
    tmp_path: Path, apply: bool, outcome: str, throw: bool, expected: int
) -> None:
    """2 promises nothing was attempted. A refused prune returns 2, but the step may then remove trees.

    Before, the normal end passed the prune's 2 through, and the trap's Max kept it; either way a run
    that removed a tree said it had attempted nothing. Now a REMOVED, FAILED or DECLINED row makes it 1,
    at the normal end and in the trap alike, and any other row leaves the 2.
    """
    proc, text = run_copied_runner(
        tmp_path,
        "-RepoRoot",
        str(tmp_path),
        *(["-Apply"] if apply else []),
        "-RemoveFinishedClaudeWorktrees",
        prune_stub=REFUSING_PRUNE_STUB,
        extra={"finished-worktree-removal.ps1": REMOVING_HELPER_STUB},
        env_extra={"T_OUTCOME": outcome, **({"T_THROW": "1"} if throw else {})},
    )
    assert text is not None, proc.stdout + proc.stderr
    assert "--- prune-merged.ps1 exit 2 at " in text, text
    assert f"{outcome:<12} X:/r/.claude/worktrees/a" in text, text
    if throw:
        assert "STOPPED on an unhandled error: stub failure after a row" in text, text
    assert proc.returncode == expected, proc.stdout + proc.stderr
    assert re.match(rf"=== exit {expected} \(", text.splitlines()[-1]), text


@requires_windows
@pytest.mark.parametrize(("throw", "expected"), [(False, 4), (True, 1)], ids=["clean", "throws"])
def test_a_tree_the_deadline_left_turns_only_a_clean_run_into_4(
    tmp_path: Path, throw: bool, expected: int
) -> None:
    """A deadline stop replaces a 0 and nothing else, an unhandled error after it included.

    The prune exits 0 and every tree comes back NOT-REACHED: the run exits 4, DEADLINE. With the helper
    then throwing, the trap's 1 is the code, since a real failure matters more than a partial run.
    """
    proc, text = run_copied_runner(
        tmp_path,
        "-RepoRoot",
        str(tmp_path),
        "-Apply",
        "-RemoveFinishedClaudeWorktrees",
        prune_stub=REFUSING_PRUNE_STUB,
        extra={"finished-worktree-removal.ps1": REMOVING_HELPER_STUB},
        env_extra={
            "T_OUTCOME": "NOT-REACHED",
            "T_PRUNE_EXIT": "0",
            **({"T_THROW": "1"} if throw else {}),
        },
    )
    assert text is not None, proc.stdout + proc.stderr
    assert "--- prune-merged.ps1 exit 0 at " in text, text
    assert "NOT-REACHED  X:/r/.claude/worktrees/a" in text, text
    assert proc.returncode == expected, proc.stdout + proc.stderr
    assert re.match(rf"=== exit {expected} \(", text.splitlines()[-1]), text


# A stub that reports the location it ran in and what its -RepoRoot resolved to.
WHERE_PRUNE_STUB = (
    "param([string]$RepoRoot, [switch]$Apply, [double]$IdleHours)\n"
    '"stub repo=$((Resolve-Path -LiteralPath $RepoRoot).ProviderPath)"\n'
    "exit 0\n"
)


@requires_windows
@DEADLINES
def test_a_relative_repo_root_resolves_against_the_callers_location(
    tmp_path: Path, deadline: list[str]
) -> None:
    """A hand run after Set-Location resolves -RepoRoot . where the caller stands, not where pwsh began.

    Without a deadline the prune child is started with `&`, which starts it in the caller's PowerShell
    location; with one, it is started as a process whose working directory is set to that location. A
    child started any other way can start in the process directory and prune a different repository.
    """
    runner, log_dir, env = copy_runner(tmp_path, WHERE_PRUNE_STUB)
    here = tmp_path / "here"
    here.mkdir()
    env.update({"T_RUNNER": str(runner), "T_LOGDIR": str(log_dir), "T_HERE": str(here)})
    proc = subprocess.run(
        [
            "pwsh",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "Set-Location -LiteralPath $env:T_HERE; & $env:T_RUNNER -LogDir $env:T_LOGDIR -RepoRoot . "
            + " ".join(deadline),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    text = read_log(log_dir)
    assert text is not None, proc.stdout + proc.stderr
    assert f"stub repo={here}" in text.splitlines(), text


# A prune-merged.ps1 stand-in that hangs, as one waiting on a git prompt would. It prints a line on each
# stream, starts a grandchild that holds the output pipes and writes its pid to $env:T_GRANDCHILD, then
# sleeps. With -Json and $env:T_LIST_ONLY set, only the listing run hangs; the prune run returns at once.
HANGING_PRUNE_STUB = (
    "param([string]$RepoRoot, [switch]$Apply, [double]$IdleHours, [switch]$Json, [switch]$SkipGh)\n"
    "if ($env:T_LIST_ONLY -and -not $Json) { 'stub prune done'; exit 0 }\n"
    "'stub before the hang'\n"
    "[Console]::Error.WriteLine('stub stderr before the hang')\n"
    "$g = Start-Process -FilePath (Get-Process -Id $PID).Path -NoNewWindow -PassThru"
    " -ArgumentList '-NoProfile', '-NonInteractive', '-Command', 'Start-Sleep -Seconds 40'\n"
    "Set-Content -LiteralPath $env:T_GRANDCHILD -Value $g.Id\n"
    "Start-Sleep -Seconds 40\n"
    "'stub after the hang'\n"
    "exit 0\n"
)

TIMED_OUT_LINE = re.compile(
    r"^--- prune-merged\.ps1 TIMED OUT after \d+\.\d min, killed at \d\d:\d\d:\d\d ---$",
    re.MULTILINE,
)


def _kill_if_alive(pid_file: Path, since: float) -> bool:
    """True when the grandchild the hanging stub started was still running. Kills it either way."""
    if not pid_file.is_file():
        return False
    try:
        child = psutil.Process(int(pid_file.read_text(encoding="utf-8").strip()))
        # A recycled pid names some other process; only a pwsh started after the test began is ours.
        if "pwsh" not in child.name().lower() or child.create_time() < since:
            return False
        child.kill()
    except psutil.Error:
        return False
    return True


@requires_windows
@pytest.mark.parametrize(
    ("step", "apply", "expected"),
    [(False, False, 4), (True, False, 4), (False, True, 1)],
    ids=["prune-only", "with-step", "apply"],
)
def test_a_prune_run_past_the_deadline_is_killed_with_its_tree_and_the_run_still_exits(
    tmp_path: Path, step: bool, apply: bool, expected: int
) -> None:
    """A hung prune-merged.ps1 used to run on into Task Scheduler's kill, which writes nothing.

    With a 12-second deadline the stub is killed with its grandchild, the log keeps what it printed
    before the hang, then the TIMED OUT line, any later step's SKIPPED line, and the exit line. A dry
    run exits 4, DEADLINE. An -Apply prune killed part way attempted something and did not finish, so
    it exits 1, as the trap does for one. On origin/main the child ran its full 40 seconds and exited 0.
    """
    grandchild = tmp_path / "grandchild.pid"
    since = time.time() - 1
    try:
        proc, text = run_copied_runner(
            tmp_path,
            "-RepoRoot",
            str(tmp_path),
            "-StopAfterMinutes",
            "0.2",
            *(["-RemoveFinishedClaudeWorktrees"] if step else []),
            *(["-Apply"] if apply else []),
            prune_stub=HANGING_PRUNE_STUB,
            extra={"finished-worktree-removal.ps1": REMOVING_HELPER_STUB} if step else None,
            env_extra={"T_GRANDCHILD": str(grandchild), "T_OUTCOME": "REMOVED"},
        )
    finally:
        grandchild_survived = _kill_if_alive(grandchild, since)
    assert text is not None, proc.stdout + proc.stderr
    assert grandchild.is_file(), f"the stub never reached its hang, so nothing was tested: {text}"
    assert not grandchild_survived, f"the kill missed the stub's own child: {text}"
    lines = text.splitlines()
    assert "stub before the hang" in lines, text
    assert "stub stderr before the hang" in lines, text
    assert "stub after the hang" not in lines, text
    assert TIMED_OUT_LINE.search(text), text
    assert "--- prune-merged.ps1 exit " not in text, text
    if step:
        assert (
            "=== finished .claude/worktrees: SKIPPED, prune-merged.ps1 was still running at the run's "
            "deadline (stopAfter="
        ) in text, text
        assert "listed finished:" not in text, text
    assert re.match(rf"=== exit {expected} \(.*\) at \d\d:\d\d:\d\d ===$", lines[-1]), text
    if expected == 4:
        assert lines[-1].startswith("=== exit 4 (DEADLINE -- "), text
    assert proc.returncode == expected, proc.stdout + proc.stderr
    assert not list((tmp_path / "logs").glob("prune-child-*")), "the logged output files were left"


@requires_windows
@pytest.mark.parametrize(("prune_exit", "expected"), [(0, 4), (2, 2)])
def test_a_listing_run_past_the_deadline_is_killed_and_the_step_is_skipped(
    tmp_path: Path, prune_exit: int, expected: int
) -> None:
    """The step's listing run is a second prune-merged.ps1 run, and the deadline bounds it too.

    The prune run returns at once; the listing run hangs and is killed. The step attempts no tree. The
    stop makes a clean prune's 0 into 4, and leaves a refused prune's 2 alone. On origin/main the
    listing ran 40 seconds.
    """
    grandchild = tmp_path / "grandchild.pid"
    since = time.time() - 1
    try:
        proc, text = run_copied_runner(
            tmp_path,
            "-RepoRoot",
            str(tmp_path),
            "-StopAfterMinutes",
            "0.2",
            "-Apply",
            "-RemoveFinishedClaudeWorktrees",
            prune_stub=HANGING_PRUNE_STUB.replace(
                "'stub prune done'; exit 0", f"'stub prune done'; exit {prune_exit}"
            ),
            extra={"finished-worktree-removal.ps1": REMOVING_HELPER_STUB},
            env_extra={"T_GRANDCHILD": str(grandchild), "T_OUTCOME": "REMOVED", "T_LIST_ONLY": "1"},
        )
    finally:
        grandchild_survived = _kill_if_alive(grandchild, since)
    assert text is not None, proc.stdout + proc.stderr
    assert grandchild.is_file(), f"the stub never reached its hang, so nothing was tested: {text}"
    assert not grandchild_survived, f"the kill missed the stub's own child: {text}"
    assert re.search(rf"^--- prune-merged\.ps1 exit {prune_exit} at ", text, re.MULTILINE), text
    assert "  stderr: stub stderr before the hang" in text, text
    assert TIMED_OUT_LINE.search(text), text
    assert (
        "=== finished .claude/worktrees: SKIPPED, the listing run was still running at the run's "
        "deadline"
    ) in text, text
    assert "REMOVED" not in text, text
    assert re.match(rf"=== exit {expected} \(", text.splitlines()[-1]), text
    assert proc.returncode == expected, proc.stdout + proc.stderr
    assert not list((tmp_path / "logs").glob("prune-child-*")), "the logged output files were left"


# The REFUSING stub's one finished row, with a line on stderr, which must be logged and kept out of the
# JSON whichever way the listing run was started, and 2,000 rows outside .claude/worktrees. Printed as
# prune-merged.ps1 prints it, multi-line JSON, so the listing parses only if every line keeps its place.
NOISY_LISTING_STUB = (
    "param([string]$RepoRoot, [switch]$Apply, [double]$IdleHours, [switch]$Json, [switch]$SkipGh)\n"
    "if ($Json) {\n"
    "  [Console]::Error.WriteLine('stub listing warning')\n"
    "  $rows = @([pscustomobject]@{ path = 'X:/r/.claude/worktrees/a'; claudeManaged = $true;"
    " branch = 'b'; whyFinished = 'w' })\n"
    '  $rows += 1..2000 | ForEach-Object { [pscustomobject]@{ path = "X:/r/other/$_";'
    " claudeManaged = $false; branch = \"o$_\"; whyFinished = 'w' } }\n"
    "  [pscustomobject]@{ fence = @{ idleHours = 24 }; counts = @{ reportOnlyHeld = 0 };"
    " reportOnly = $rows } | ConvertTo-Json -Depth 6\n"
    "  exit 0\n"
    "}\n"
    '"stub refused"\n'
    "exit 2\n"
)


@requires_windows
@DEADLINES
def test_a_listing_run_inside_the_deadline_is_read_as_before(
    tmp_path: Path, deadline: list[str]
) -> None:
    """Started either way, the listing's stdout is parsed and its stderr is logged, not parsed."""
    proc, text = run_copied_runner(
        tmp_path,
        "-RepoRoot",
        str(tmp_path),
        "-RemoveFinishedClaudeWorktrees",
        *deadline,
        prune_stub=NOISY_LISTING_STUB,
        extra={"finished-worktree-removal.ps1": REMOVING_HELPER_STUB},
        env_extra={"T_OUTCOME": "WOULD-REMOVE"},
    )
    assert text is not None, proc.stdout + proc.stderr
    assert "  stderr: stub listing warning" in text.splitlines(), text
    assert "WOULD-REMOVE X:/r/.claude/worktrees/a" in text, text
    assert "listed finished: 1 under .claude/worktrees; 2000 elsewhere" in text, text
    assert "TIMED OUT" not in text, text
    assert proc.returncode == 2, proc.stdout + proc.stderr
    assert re.match(r"=== exit 2 \(REFUSED", text.splitlines()[-1]), text
    assert not list((tmp_path / "logs").glob("prune-child-*")), "the logged output files were left"


# A stub that prints a line, records its pid in $env:T_STARTED, then waits long enough to be stopped.
STOPPABLE_PRUNE_STUB = (
    "param([string]$RepoRoot, [switch]$Apply, [double]$IdleHours)\n"
    "'stub printed before the stop'\n"
    "Set-Content -LiteralPath $env:T_STARTED -Value $PID\n"
    "Start-Sleep -Seconds 40\n"
    "exit 0\n"
)


@requires_windows
def test_a_hand_run_stopped_on_the_deadline_path_kills_the_child_and_keeps_its_output(
    tmp_path: Path,
) -> None:
    """A Stop part way through a bounded run must not leave the child running or lose its output.

    The runner runs in a second runspace and is stopped while the stub waits. The bounded run's
    finally kills the child, and the output file is kept, because its lines never reached the log.
    """
    runner, log_dir, env = copy_runner(tmp_path, STOPPABLE_PRUNE_STUB)
    started = tmp_path / "stub-started.txt"
    env.update(
        {
            "T_RUNNER": str(runner),
            "T_LOGDIR": str(log_dir),
            "T_REPO": str(tmp_path),
            "T_STARTED": str(started),
        }
    )
    script = (
        "$ps = [powershell]::Create().AddScript("
        "'& $env:T_RUNNER -LogDir $env:T_LOGDIR -RepoRoot $env:T_REPO -StopAfterMinutes 10'); "
        "$null = $ps.BeginInvoke(); $sw = [Diagnostics.Stopwatch]::StartNew(); "
        "while ($sw.Elapsed.TotalSeconds -lt 60 -and -not (Test-Path -LiteralPath $env:T_STARTED)) "
        "{ Start-Sleep -Milliseconds 100 }; "
        "Start-Sleep -Milliseconds 500; $ps.Stop(); "
        '"state=$($ps.InvocationStateInfo.State)"'
    )
    since = time.time() - 1
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-Command", script],
        capture_output=True,
        text=True,
        timeout=120,
        env=env,
        cwd=tmp_path,
        check=False,
    )
    try:
        assert started.is_file(), proc.stdout + proc.stderr
        assert "state=Stopped" in proc.stdout, proc.stdout + proc.stderr
        survived = _kill_if_alive(started, since)
        assert not survived, "the stopped run left its prune-merged.ps1 child running"
        kept = list(log_dir.glob("prune-child-*.out.txt"))
        assert kept, (
            f"the child's output was deleted before it was logged: {list(log_dir.iterdir())}"
        )
        assert "stub printed before the stop" in kept[0].read_text(encoding="utf-8"), kept
    finally:
        _kill_if_alive(started, since)
