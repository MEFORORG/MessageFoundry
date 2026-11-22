# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Static checks on the dashboard's PowerShell scripts: each parses, and the installer carries the
CLAUDE.md section 5 host circuit breaker as its first statement. Nothing here registers a task."""

from __future__ import annotations

import json
import shutil
import subprocess
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


def _ps_literal(path: Path) -> str:
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


def test_installer_keeps_the_runner_out_of_appdata() -> None:
    text = (_DIR / "install-schedule.ps1").read_text(encoding="utf-8")
    # The code after the help block, which names AppData only to say why it is avoided.
    code = text[text.index("[CmdletBinding()]") :]
    code = "\n".join(ln for ln in code.splitlines() if not ln.lstrip().startswith("#"))
    assert "LOCALAPPDATA" not in code
    assert "'.mefor\\dashboard'" in code
    assert "[string]$RunnerDir" in code
