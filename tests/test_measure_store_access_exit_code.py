# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``measure-store-access.ps1`` reads each child's exit code from a handle it owns.

``Invoke-ChildProcess``'s comment says why ``Start-Process`` lost the code under Windows
PowerShell 5.1, and holds the measurement.

NOTHING IN CI RUNS THE WHOLE SCRIPT OUTSIDE THE HOSTED windows-service-smoke LEG: it installs a
service and must run elevated. So the static half pins that no ``Start-Process`` call is left in the
script's code, and the behavioural half lifts ``Invoke-ChildProcess`` out of the script's own AST
and runs it on fast-exiting children, never running the script. It runs under each PowerShell host
present, Windows PowerShell 5.1 included, since that is the host the CI steps use.
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
#: A Start-Process call in command position, by its name or either built-in alias.
_START_PROCESS = re.compile(r"(?:^|[=(|;{])\s*(?:Start-Process|start|saps)(?![\w-])", re.I | re.M)


def _code_only(text: str) -> str:
    """The script with its block and line comments removed, which name Start-Process in prose."""
    text = re.sub(r"<#.*?#>", "", text, flags=re.DOTALL)
    return "\n".join(ln for ln in text.splitlines() if not ln.lstrip().startswith("#"))


def test_no_start_process_call_is_left_in_the_script() -> None:
    raw = _SCRIPT.read_text(encoding="utf-8")
    # Positive control: the comments do name it, so a stripper that removed nothing would show here.
    assert "Start-Process" in raw
    code = _code_only(raw)
    assert not _START_PROCESS.findall(code)
    assert "function Invoke-ChildProcess" in code
    # Both children the script starts: the probe, and protect-key.
    assert len(re.findall(r"\bInvoke-ChildProcess\s+-FilePath\b", code)) >= 2


def test_the_scan_sees_each_spelling_and_not_a_lookalike() -> None:
    for call in ("$p = Start-Process -FilePath $x", "  start $x -PassThru", "$p = (saps $x)"):
        assert _START_PROCESS.search(_code_only(call + "\n")), call
    for other in ("& $Nssm start $ServiceName", "Start-TheService 'x'", "Start-Sleep -Seconds 1"):
        assert not _START_PROCESS.search(other), other


def _psq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


@pytest.mark.parametrize("host", ["pwsh", "powershell"])
def test_the_exit_code_is_read_on_every_fast_exiting_child(tmp_path: Path, host: str) -> None:
    if shutil.which(host) is None:
        pytest.skip(f"SKIP (nothing run): {host} not on PATH")
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
$ast = [System.Management.Automation.Language.Parser]::ParseFile({_psq(str(_SCRIPT))}, [ref]$null, [ref]$null)
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
    f = tmp_path / f"exitcode-{uuid.uuid4().hex}.ps1"
    # With a BOM, which Windows PowerShell 5.1 needs to read a non-ASCII path as UTF-8.
    f.write_text(script, encoding="utf-8-sig")
    # Windows PowerShell's default policy can refuse an unsigned -File; pwsh's does not.
    policy = ["-ExecutionPolicy", "Bypass"] if host == "powershell" else []
    proc = run_single(
        [host, "-NoProfile", "-NonInteractive", *policy, "-File", str(f)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    rows = json.loads(proc.stdout.strip().splitlines()[-1])
    assert len(rows) == _RUNS
    for row in rows:
        assert row["code"] == row["want"], row
        assert row["out"] == "inherited-ok", row
        assert row["err"] == f"err-{row['want']}", row


def test_control_start_process_loses_the_code_that_process_start_keeps(tmp_path: Path) -> None:
    """The hazard the static pin guards, shown on the host the CI steps use.

    Under Windows PowerShell 5.1, a parent held 300 ms between ``Start-Process -PassThru`` and its
    first handle read loses the exit code of a child that exited meanwhile. ``Process.Start``, which
    ``Invoke-ChildProcess`` uses, keeps it under the same hold. The fast-child test above cannot show
    this, because without the hold the old path also read every code on this box. At least one loss
    in five is asked for, not five, since another process holding a handle keeps the code readable.
    """
    if sys.platform != "win32" or shutil.which("powershell") is None:
        pytest.skip("SKIP (nothing run): Windows PowerShell 5.1 is a Windows host")
    script = r"""
$ErrorActionPreference = 'Stop'
$cmd = Join-Path $env:SystemRoot 'System32\cmd.exe'
$lost = 0; $kept = 0
for ($i = 0; $i -lt 5; $i++) {
    $p = Start-Process -FilePath $cmd -ArgumentList '/c exit 3' -NoNewWindow -PassThru
    Start-Sleep -Milliseconds 300
    $null = $p.Handle
    $p.WaitForExit()
    if ($null -eq $p.ExitCode) { $lost++ }
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $cmd; $psi.Arguments = '/c exit 3'; $psi.UseShellExecute = $false
    $q = [System.Diagnostics.Process]::Start($psi)
    Start-Sleep -Milliseconds 300
    $q.WaitForExit()
    if ($q.ExitCode -eq 3) { $kept++ }
}
"lost=$lost kept=$kept"
"""
    f = tmp_path / f"control-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8-sig")
    proc = run_single(
        [
            "powershell",
            "-NoProfile",
            "-NonInteractive",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(f),
        ],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    found = re.search(r"lost=(\d+) kept=(\d+)", proc.stdout)
    assert found, proc.stdout
    assert int(found.group(1)) >= 1, proc.stdout
    assert int(found.group(2)) == 5, proc.stdout
