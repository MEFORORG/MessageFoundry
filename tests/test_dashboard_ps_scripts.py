# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Static checks on the dashboard's PowerShell scripts: each parses, and the installer carries the
CLAUDE.md section 5 host circuit breaker as its first statement. Nothing here registers a task."""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

_DIR = Path(__file__).resolve().parents[1] / "scripts" / "dashboard"
SCRIPTS = ("build.ps1", "scheduled-refresh.ps1", "install-schedule.ps1")
GUARD = (
    "if ([Environment]::MachineName -ne 'MEFORDEV01') { & { $ErrorActionPreference = 'Stop'; "
    'throw "STOP     this must run on MEFORDEV01, but this is '
    '$([Environment]::MachineName); nothing ran" } }'
)

_PARSE = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
$first = @($ast.EndBlock.Statements)[0]
[pscustomobject]@{
    errors = @($errors | ForEach-Object { $_.Message })
    hasParam = [bool]$ast.ParamBlock
    first = if ($first) { $first.Extent.Text } else { '' }
} | ConvertTo-Json -Compress
"""


def _ps_literal(path: Path | str) -> str:
    return "'" + str(path).replace("'", "''") + "'"


def _parse(path: Path) -> dict[str, object]:
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh is not installed")
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, a checked-in script path
        # The path as a single-quoted PowerShell literal: text after -Command is not $args.
        [
            pwsh,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$path = {_ps_literal(path)}" + _PARSE,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        check=True,
    )
    parsed: dict[str, object] = json.loads(proc.stdout)
    return parsed


@pytest.mark.parametrize("name", SCRIPTS)
def test_script_parses(name: str) -> None:
    got = _parse(_DIR / name)
    assert got["errors"] == [], got["errors"]
    assert got["hasParam"]


def test_installer_guard_is_the_first_statement() -> None:
    got = _parse(_DIR / "install-schedule.ps1")
    assert got["first"] == GUARD


def test_installer_stores_no_password_and_reregisters() -> None:
    text = (_DIR / "install-schedule.ps1").read_text(encoding="utf-8")
    assert "-LogonType Interactive" in text
    assert "-Password" not in text
    assert "-Force | Out-Null" in text
    assert "-MultipleInstances IgnoreNew" in text
    assert "MEFOR Dashboard Refresh" in text


def test_scheduled_refresh_reads_no_work_tree() -> None:
    text = (_DIR / "scheduled-refresh.ps1").read_text(encoding="utf-8")
    # Only fetch, rev-parse and archive reach git; no checkout, reset, pull or worktree.
    for verb in ("checkout", "reset", "pull", "worktree", "switch"):
        assert f"'{verb}'" not in text
    assert "'archive'" in text
    assert "-I $render" in text


_TIMES = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
$fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'ConvertTo-TriggerTimes' }, $true)
Invoke-Expression $fn.Extent.Text
$r1 = ConvertTo-TriggerTimes @('07:00,19:00')
$r2 = ConvertTo-TriggerTimes @('7:05', ' 19:30 ')
$ok = @($r1 | ForEach-Object { $_.ToString('HH:mm') })
$ok2 = @($r2 | ForEach-Object { $_.ToString('HH:mm') })
$bad = try { ConvertTo-TriggerTimes @('07:00,noon'); '' } catch { $_.Exception.Message }
[pscustomobject]@{ ok = $ok; ok2 = $ok2; bad = $bad } | ConvertTo-Json -Compress
"""


def test_installer_splits_and_validates_times() -> None:
    # Only the parsing function is evaluated, lifted from the file's AST: nothing is registered.
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh is not installed")
    path = _DIR / "install-schedule.ps1"
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, a checked-in script path
        [
            pwsh,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$path = {_ps_literal(path)}" + _TIMES,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        check=True,
    )
    got = json.loads(proc.stdout)
    assert got["ok"] == ["07:00", "19:00"]
    assert got["ok2"] == ["07:05", "19:30"]
    assert "'noon' is not a 24-hour time" in got["bad"]


_SWEEP = r"""
$tokens = $null; $errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$tokens, [ref]$errors)
$fn = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Remove-StaleTemp' }, $true)
Invoke-Expression $fn.Extent.Text
# The sweep ages a directory by creation time, which Python cannot set; backdate the -old ones.
Get-ChildItem -LiteralPath $base -Directory -Filter '*-old' | ForEach-Object { $_.CreationTimeUtc = [DateTime]::UtcNow.AddYears(-20) }
$r = @(Remove-StaleTemp $base $prefix)
[pscustomobject]@{ result = $r } | ConvertTo-Json -Compress
"""


def _sweep(
    tmp_path: Path, script: str = "build.ps1", prefix: str = "mf-dashboard-build-"
) -> list[object]:
    # Only the sweep function is evaluated, lifted from the script's AST, against tmp_path.
    pwsh = shutil.which("pwsh")
    if pwsh is None:
        pytest.skip("pwsh is not installed")
    proc = subprocess.run(  # noqa: S603  # nosec B603 - fixed argv, a checked-in script path
        [
            pwsh,
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            f"$path = {_ps_literal(_DIR / script)}; $base = {_ps_literal(tmp_path)}; "
            f"$prefix = {_ps_literal(prefix)}" + _SWEEP,
        ],
        stdin=subprocess.DEVNULL,
        capture_output=True,
        encoding="utf-8",
        timeout=60,
        check=True,
    )
    # A list, so stray pipeline output from the function would show as a second element.
    result: list[object] = json.loads(proc.stdout)["result"]
    return result


def _stale_dir(tmp_path: Path, name: str) -> Path:
    old = tmp_path / name
    old.mkdir()
    (old / "metrics.json").write_text("{}", encoding="utf-8")
    return old


_WIN_ONLY = pytest.mark.skipif(
    sys.platform != "win32",
    reason="creation time is settable, and an open file blocks deletion, only on Windows",
)


@_WIN_ONLY
def test_build_sweep_removes_a_stale_directory(tmp_path: Path) -> None:
    old = _stale_dir(tmp_path, "mf-dashboard-build-old")
    fresh = tmp_path / "mf-dashboard-build-new"
    fresh.mkdir()
    assert _sweep(tmp_path) == [True]
    assert not old.exists()
    assert fresh.exists()  # a live run's directory is never swept


@_WIN_ONLY
def test_build_sweep_failure_is_reported(tmp_path: Path) -> None:
    old = _stale_dir(tmp_path, "mf-dashboard-build-old")
    (old / "other.json").write_text("{}", encoding="utf-8")
    # An open handle without FILE_SHARE_DELETE: Remove-Item cannot delete the file.
    with (old / "metrics.json").open(encoding="utf-8"):
        assert _sweep(tmp_path) == [False]
        # The first sweep removed other.json, which moved the directory's last-write time to now;
        # the next run must still see the leftover, so the sweep reads its creation time.
        os.utime(old)
        assert _sweep(tmp_path) == [False]
    assert old.exists()


def test_build_sweep_failure_fails_the_run() -> None:
    text = (_DIR / "build.ps1").read_text(encoding="utf-8")
    assert "$swept = Remove-StaleTemp $base 'mf-dashboard-build-'" in text
    assert "if (-not $swept -and $code -eq 0) { $code = 3 }" in text
    # The gate sits after the finally, right before the only exit that follows it.
    assert text.rindex("if (-not $swept") < text.rindex("exit $code")


def test_installer_keeps_the_runner_out_of_appdata() -> None:
    text = (_DIR / "install-schedule.ps1").read_text(encoding="utf-8")
    # The code after the help block, which names AppData only to say why it is avoided.
    code = text[text.index("[CmdletBinding") :]
    code = "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#"))
    assert "LOCALAPPDATA" not in code
    assert "'.mefor\\dashboard'" in code
    assert "[string]$RunnerDir" in code


def test_installer_pins_the_task_to_a_checked_sha() -> None:
    text = (_DIR / "install-schedule.ps1").read_text(encoding="utf-8")
    assert "PositionalBinding = $false" in text
    # The runner comes out of the pinned commit, never this work tree's copy.
    assert "Copy-Item -LiteralPath (Join-Path $PSScriptRoot" not in text
    assert "archive --format=tar" in text
    assert "^[0-9a-f]{40}$" in text
    # Only the resolved sha reaches the task's argument string, unquoted because it is hex.
    assert "-Ref $sha -EngineRepo" in text
    assert '-Ref `"$Ref`"' not in text


def test_runner_validates_ref_and_fetches_main_only() -> None:
    text = (_DIR / "scheduled-refresh.ps1").read_text(encoding="utf-8")
    assert "'+refs/heads/main:refs/remotes/origin/main'" in text
    assert "-NoFetch" in text
    assert "is neither a 40-hex commit nor origin/<branch>" in text
    assert "-like 'file://*'" in text


def test_refs_are_explicit_and_python_splits_on_commas() -> None:
    for name in ("install-schedule.ps1", "scheduled-refresh.ps1"):
        assert '"refs/remotes/$' in (_DIR / name).read_text(encoding="utf-8"), name
    for name in ("build.ps1", "scheduled-refresh.ps1"):
        assert "\"$_\" -split ','" in (_DIR / name).read_text(encoding="utf-8"), name
    build = (_DIR / "build.ps1").read_text(encoding="utf-8")
    assert "'mf-dashboard-build-'" in build and "'mf-dashboard-'" not in build


@_WIN_ONLY
def test_refresh_sweep_ages_by_creation_time(tmp_path: Path) -> None:
    old = _stale_dir(tmp_path, "mf-dashboard-src-old")
    fresh = _stale_dir(tmp_path, "mf-dashboard-src-new")
    # An old last-write time on a new directory: a last-write sweep would remove it.
    os.utime(fresh, (1_000_000.0, 1_000_000.0))
    assert _sweep(tmp_path, "scheduled-refresh.ps1", "mf-dashboard-src-") == []
    assert not old.exists()
    assert fresh.exists()


def test_both_ps_sweeps_age_by_creation_time() -> None:
    # A partial sweep moves the last-write time to now, so neither sweep may read it.
    for name in ("build.ps1", "scheduled-refresh.ps1"):
        text = (_DIR / name).read_text(encoding="utf-8")
        assert "$_.CreationTimeUtc -lt $cutoff" in text, name
        assert "LastWriteTimeUtc -lt" not in text, name


def test_a_failed_fetch_turns_a_clean_run_red() -> None:
    text = (_DIR / "scheduled-refresh.ps1").read_text(encoding="utf-8")
    assert "if ($code -eq 0 -and $fetchFailed) { $code = 3 }" in text
