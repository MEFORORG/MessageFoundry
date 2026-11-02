# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``measure-store-access.ps1`` reads each child's exit code from a handle it owns.

``Invoke-ChildProcess``'s comment says why ``Start-Process`` lost the code under Windows
PowerShell 5.1, and holds the measurement.

NOTHING IN CI RUNS THE WHOLE SCRIPT OUTSIDE THE HOSTED windows-service-smoke LEG: it installs a
service and must run elevated. So one half reads the script's AST and pins that no command it runs
is ``Start-Process``, by any spelling, and the other lifts ``Invoke-ChildProcess`` out of that AST
and runs it on fast-exiting children, never running the script. Both need a PowerShell host and skip
where there is none; the second runs under each host present, Windows PowerShell 5.1 included,
since that is the host the CI steps use.
"""

from __future__ import annotations

import json
import re
import shutil
import sys
import uuid
from pathlib import Path

import pytest

from tests._spawn_lock import run_single

_SCRIPT = (
    Path(__file__).resolve().parent.parent / "scripts" / "service" / "measure-store-access.ps1"
)
_RUNS = 10
# Below the per-test bound, so a hung launch surfaces as TimeoutExpired naming this test. The bound
# allows for run_single's wait on the shared spawn lock as well.
_LAUNCH_TIMEOUT_S = 60
_PER_TEST_TIMEOUT_S = 180

pytestmark = pytest.mark.timeout(_PER_TEST_TIMEOUT_S)


def _psq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run(host: str, tmp_path: Path, script: str) -> str:
    f = tmp_path / f"exitcode-{uuid.uuid4().hex}.ps1"
    # With a BOM, which Windows PowerShell 5.1 needs to read a non-ASCII path as UTF-8.
    f.write_text(script, encoding="utf-8-sig")
    # Windows PowerShell's default policy can refuse an unsigned -File; pwsh's does not.
    policy = ["-ExecutionPolicy", "Bypass"] if host == "powershell" else []
    proc = run_single(
        [host, "-NoProfile", "-NonInteractive", *policy, "-File", str(f)],
        capture_output=True,
        text=True,
        timeout=_LAUNCH_TIMEOUT_S,
        check=False,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    lines = proc.stdout.strip().splitlines()
    assert lines, f"harness exited 0 but printed nothing on stdout; stderr: {proc.stderr}"
    return lines[-1]


def _need(host: str) -> None:
    if shutil.which(host) is None:
        pytest.skip(f"SKIP (nothing run): {host} not on PATH")


#: Every command the parsed source runs whose name, module qualifier dropped, is Start-Process or
#: one of its built-in aliases, plus the number of Invoke-ChildProcess calls.
_COMMAND_CENSUS = """
$names = @($ast.FindAll({ $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
    ForEach-Object { $_.GetCommandName() } | Where-Object { $_ } | ForEach-Object { ($_ -split '\\\\')[-1] })
$started = @($names | Where-Object { $_ -in @('Start-Process', 'start', 'saps') })
$child = @($names | Where-Object { $_ -eq 'Invoke-ChildProcess' })
ConvertTo-Json -Compress -InputObject @{
    errors = @($errs).Count; started = $started.Count; child = $child.Count }
"""


def _census(tmp_path: Path, path: Path) -> dict[str, int]:
    script = f"""
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile({_psq(str(path))}, [ref]$null, [ref]$errs)
{_COMMAND_CENSUS}
"""
    census: dict[str, int] = json.loads(_run("pwsh", tmp_path, script))
    return census


def _assert_clean(census: dict[str, int]) -> None:
    # A parse error leaves a partial AST, on which a Start-Process further down would go uncounted.
    assert census["errors"] == 0, census
    assert census["started"] == 0, census
    # Both children the script starts: the probe, and protect-key.
    assert census["child"] >= 2, census


def test_no_command_in_the_script_is_start_process(tmp_path: Path) -> None:
    _need("pwsh")
    _assert_clean(_census(tmp_path, _SCRIPT))


def test_the_census_fails_a_copy_that_does_not_parse(tmp_path: Path) -> None:
    _need("pwsh")
    broken = tmp_path / "broken.ps1"
    broken.write_text(
        _SCRIPT.read_text(encoding="utf-8") + "\nfunction Broken {\n", encoding="utf-8-sig"
    )
    census = _census(tmp_path, broken)
    assert census["errors"] > 0, census
    with pytest.raises(AssertionError):
        _assert_clean(census)


def test_the_census_sees_each_spelling_and_not_a_string(tmp_path: Path) -> None:
    _need("pwsh")
    snippet = (
        "function f { return Start-Process -FilePath x -PassThru }\n"
        "$p = Microsoft.PowerShell.Management\\Start-Process x\n"
        "& start x; . saps x\n"
        "$s = @'\nstart = 1\n'@\n"
        "Start-Sleep 0; & $Nssm start svc\n"
    )
    script = f"""
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseInput({_psq(snippet)}, [ref]$null, [ref]$errs)
{_COMMAND_CENSUS}
"""
    census = json.loads(_run("pwsh", tmp_path, script))
    assert census["errors"] == 0, census
    assert census["started"] == 4, census


@pytest.mark.parametrize("host", ["pwsh", "powershell"])
def test_the_exit_code_is_read_on_every_fast_exiting_child(tmp_path: Path, host: str) -> None:
    _need(host)
    child = tmp_path / "child.py"
    child.write_text(
        "import os, sys\n"
        "print(os.environ.get('W3_INHERITED', 'missing'))\n"
        "sys.stderr.write('err-' + sys.argv[1])\n"
        "sys.exit(int(sys.argv[1]))\n",
        encoding="ascii",
    )
    script = f"""
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile({_psq(str(_SCRIPT))}, [ref]$null, [ref]$errs)
if (@($errs).Count) {{ throw "the script does not parse: $($errs[0])" }}
$def = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $args[0].Name -eq 'Invoke-ChildProcess' }}, $true)
if (-not $def) {{ throw 'missing function Invoke-ChildProcess' }}
. ([scriptblock]::Create($def.Extent.Text))
$env:W3_INHERITED = 'inherited-ok'
$rows = for ($i = 0; $i -lt {_RUNS}; $i++) {{
    $want = if ($i % 2) {{ 3 }} else {{ 0 }}
    $r = Invoke-ChildProcess -FilePath {_psq(sys.executable)} `
        -Arguments ('"' + {_psq(str(child))} + '" ' + $want) -WorkingDirectory {_psq(str(tmp_path))}
    New-Object PSObject -Property @{{
        want = $want; code = $r.Code; out = $r.Out.Trim(); err = $r.Err.Trim() }}
}}
ConvertTo-Json -InputObject @($rows) -Compress
"""
    rows = json.loads(_run(host, tmp_path, script))
    assert len(rows) == _RUNS
    for row in rows:
        assert row["code"] == row["want"], row
        assert row["out"] == "inherited-ok", row
        assert row["err"] == f"err-{row['want']}", row


def test_control_start_process_loses_the_code_that_process_start_keeps(tmp_path: Path) -> None:
    """The hazard the census guards, read on the host the CI steps use.

    Under Windows PowerShell 5.1, a parent held 300 ms between ``Start-Process -PassThru`` and its
    first handle read lost the exit code of a child that exited meanwhile, 20 times in 20 on a
    local box. ``Process.Start``, which ``Invoke-ChildProcess`` uses, keeps it under the same hold,
    and that half is asserted. The loss is a reading, not an assertion: another process holding a
    handle to the child (an endpoint scanner, say) keeps the code readable, so a host that shows no
    loss skips with its reading rather than going red on an environment.
    """
    if sys.platform != "win32":
        pytest.skip("SKIP (nothing run): Windows PowerShell 5.1 is a Windows host")
    _need("powershell")
    script = r"""
$ErrorActionPreference = 'Stop'
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$lost = 0; $kept = 0
for ($i = 0; $i -lt 5; $i++) {
    $p = Start-Process -FilePath $cmd -ArgumentList '/c exit 3' -NoNewWindow -PassThru
    Start-Sleep -Milliseconds 300
    $null = $p.Handle
    # Bounded: if the child's process id was reused during the hold, the handle names a stranger.
    if ($p.WaitForExit(5000) -and $null -eq $p.ExitCode) { $lost++ }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $cmd; $psi.Arguments = '/c exit 3'; $psi.UseShellExecute = $false
    $q = [System.Diagnostics.Process]::Start($psi)
    Start-Sleep -Milliseconds 300
    # Unbounded: $q owns its handle, so no stranger can stand in; _run's launch timeout bounds it.
    $q.WaitForExit()
    if ($q.ExitCode -eq 3) { $kept++ }
}
"lost=$lost kept=$kept"
"""
    reading = _run("powershell", tmp_path, script)
    found = re.fullmatch(r"lost=(\d+) kept=(\d+)", reading)
    assert found, reading
    assert int(found.group(2)) == 5, reading
    if int(found.group(1)) == 0:
        pytest.skip(f"SKIP (read, not asserted): Start-Process kept every code here: {reading}")
