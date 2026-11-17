# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``measure-store-access.ps1`` counts only the ADR 0167 REFUSAL as a refused start.

``Wait-ForGateRefusal`` used to return on any log line carrying the gate's clause, "no enabled
Administrator". The skipped-gate warning and the warn-mode line carry that clause too, and an engine
that logs either goes on to start and serve, so the StartFirst arm could report a refusal for an
engine that served. Now a line must also carry the refusal's own words, through
``Test-GateRefusalLine``.

NOTHING HERE RUNS THE SCRIPT: it installs a service and must run elevated, which only the hosted
windows-service-smoke leg does. The test lifts the two phrase assignments and
``Test-GateRefusalLine`` out of the script's AST and calls the function on lines worded as the
engine words them. It pins that ``app.py`` still holds each line's prefix and the clause text after
it, as literals; it does not render the lines from ``app.py``. It needs ``pwsh`` and skips where
there is none.
"""

from __future__ import annotations

import json
import shutil
import uuid
from pathlib import Path

import pytest

from tests._spawn_lock import run_single

_ROOT = Path(__file__).resolve().parent.parent
_SCRIPT = _ROOT / "scripts" / "service" / "measure-store-access.ps1"
_APP = _ROOT / "messagefoundry" / "api" / "app.py"

#: The prefix each of the gate's three lines opens with in ``app.py``, and a line worded so.
_REFUSAL = (
    "refusing to start a PHI instance: ",
    "RuntimeError: refusing to start a PHI instance: no enabled Administrator exists in this store,"
    " so no enabled account holds the role that manages users and roles",
)
_SKIPPED = (
    "the engine is starting with the notice gate skipped: ",
    "WARNING messagefoundry.api.app: the engine is starting with the notice gate skipped: no enabled"
    " Administrator exists in this store, so no enabled account holds the role",
)
_WARN_MODE = (
    "PHI instance with no deliverable security-notice recipient: ",
    "WARNING messagefoundry.api.app: PHI instance with no deliverable security-notice recipient: no"
    " enabled Administrator has a notification address, so every out-of-band security notice",
)


def _psq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _judge(host: str, tmp_path: Path, lines: list[str]) -> dict[str, object]:
    if shutil.which(host) is None:
        pytest.skip(f"SKIP (nothing run): {host} not on PATH")
    script = f"""
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile({_psq(str(_SCRIPT))}, [ref]$null, [ref]$errs)
if (@($errs).Count) {{ throw "the script does not parse: $($errs[0])" }}
foreach ($var in @('GateRefusal', 'NoAdminRefusal', 'StartRefused')) {{
  $set = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
      $args[0].Left.Extent.Text -eq ('$' + $var) }}, $false)
  if (-not $set) {{ throw "missing assignment `${{var}}" }}
  . ([scriptblock]::Create($set.Extent.Text))
}}
$def = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $args[0].Name -eq 'Test-GateRefusalLine' }}, $true)
if (-not $def) {{ throw 'missing function Test-GateRefusalLine' }}
. ([scriptblock]::Create($def.Extent.Text))
$lines = {_psq(json.dumps(lines))} | ConvertFrom-Json
ConvertTo-Json -Compress -InputObject @{{
  refusal = @($lines | ForEach-Object {{ [bool](Test-GateRefusalLine $_) }})
  no_admin = @($lines | ForEach-Object {{ [bool](Test-GateRefusalLine $_ $NoAdminRefusal) }})
  clause = @($lines | ForEach-Object {{ $_ -match [regex]::Escape($GateRefusal) }}) }}
"""
    f = tmp_path / f"gate-{uuid.uuid4().hex}.ps1"
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
    result: dict[str, object] = json.loads(proc.stdout.strip().splitlines()[-1])
    return result


def test_the_engine_still_words_the_three_gate_lines_so() -> None:
    app = _APP.read_text(encoding="utf-8")
    for prefix, line in (_REFUSAL, _SKIPPED, _WARN_MODE):
        assert prefix in app, prefix
        assert prefix in line
    # The clauses the script matches on, as app.py spells the detail text after each prefix. The
    # no-Administrator detail is split across an f-string, so its two halves are pinned apart.
    assert '"no enabled Administrator{' in app
    assert '"exists in this store, so no enabled account holds the role "' in app
    assert (
        '"no enabled Administrator has a notification address, so every out-of-band security "'
        in app
    )


@pytest.mark.parametrize("host", ["pwsh", "powershell"])
def test_only_the_refusal_counts_as_a_refused_start(tmp_path: Path, host: str) -> None:
    got = _judge(host, tmp_path, [_REFUSAL[1], _SKIPPED[1], _WARN_MODE[1], "unrelated line"])
    assert got["refusal"] == [True, False, False, False], got
    # The narrower clause the StartFirstEndToEnd arm passes: the no-Administrator refusal only.
    assert got["no_admin"] == [True, False, False, False], got
    # The control: the clause the wait used to match alone is in both warning lines, so the old
    # criterion took an engine that went on to serve for a refused one.
    assert got["clause"] == [True, True, True, False], got
