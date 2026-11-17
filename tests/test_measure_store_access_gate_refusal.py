# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""``measure-store-access.ps1`` counts only the ADR 0167 REFUSAL as a refused start.

``Wait-ForGateRefusal`` used to return on any log line carrying the gate's clause, "no enabled
Administrator". The skipped-gate warning and the warn-mode line carry that clause too, and an engine
that logs either goes on to start and serve, so the StartFirst arm could report a refusal for an
engine that served. Now a line must also carry the refusal's own words, through
``Test-GateRefusalLine``.

NOTHING HERE RUNS THE SCRIPT: it installs a service and must run elevated, which only the hosted
windows-service-smoke leg does. The tests lift the phrase assignments and functions they need out
of the script's AST: they call ``Test-GateRefusalLine`` on lines worded as the engine words them,
and run ``Wait-ForGateRefusal`` against a stand-in log reader. They pin that ``app.py`` still holds
each line's prefix and the clause text after it, as literals; they do not render the lines from
``app.py``. They need ``pwsh`` or ``powershell`` and skip where it is missing.
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

#: The prefix each of the gate's lines opens with in ``app.py``, and a line worded so.
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
#: The gate's could-not-run warning (a Vault transit outage while the gate is not enforcing). It lets
#: the start go on, and it does not carry the clause the lines above share.
_COULD_NOT_RUN = (
    "the security-notice gate could not run: ",
    "WARNING messagefoundry.api.app: the security-notice gate could not run: the accounts could not"
    " be checked against their integrity seal because Vault transit did not answer",
)


def _psq(value: str) -> str:
    return "'" + value.replace("'", "''") + "'"


def _run(host: str, tmp_path: Path, script: str) -> dict[str, object]:
    if shutil.which(host) is None:
        pytest.skip(f"SKIP (nothing run): {host} not on PATH")
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


def _lift(variables: list[str], functions: list[str]) -> str:
    """PowerShell that dot-sources the named assignments and functions out of the script's AST."""
    names = ", ".join(_psq(v) for v in variables)
    funcs = ", ".join(_psq(f) for f in functions)
    return f"""
$ErrorActionPreference = 'Stop'
$errs = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile({_psq(str(_SCRIPT))}, [ref]$null, [ref]$errs)
if (@($errs).Count) {{ throw "the script does not parse: $($errs[0])" }}
foreach ($var in @({names})) {{
  $set = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] -and
      $args[0].Left.Extent.Text -eq ('$' + $var) }}, $false)
  if (-not $set) {{ throw "missing assignment `${{var}}" }}
  . ([scriptblock]::Create($set.Extent.Text))
}}
foreach ($name in @({funcs})) {{
  $def = $ast.Find({{ $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] -and
      $args[0].Name -eq $name }}, $true)
  if (-not $def) {{ throw "missing function $name" }}
  . ([scriptblock]::Create($def.Extent.Text))
}}
"""


def _judge(host: str, tmp_path: Path, lines: list[str]) -> dict[str, object]:
    script = _lift(
        ["GateRefusal", "NoAdminRefusal", "StartRefused", "GateLetStart"], ["Test-GateRefusalLine"]
    ) + (
        f"""
$lines = {_psq(json.dumps(lines))} | ConvertFrom-Json
ConvertTo-Json -Compress -InputObject @{{
  refusal = @($lines | ForEach-Object {{ [bool](Test-GateRefusalLine $_) }})
  no_admin = @($lines | ForEach-Object {{ [bool](Test-GateRefusalLine $_ $NoAdminRefusal) }})
  let_start = @($lines | ForEach-Object {{ $_ -match $GateLetStart }})
  clause = @($lines | ForEach-Object {{ $_ -match [regex]::Escape($GateRefusal) }}) }}
"""
    )
    return _run(host, tmp_path, script)


def _wait(host: str, tmp_path: Path, lines: list[str]) -> dict[str, object]:
    """Run the script's own ``Wait-ForGateRefusal`` with ``lines`` as the whole service log."""
    script = _lift(
        ["GateRefusal", "StartRefused", "GateLetStart"],
        ["Test-GateRefusalLine", "Wait-ForGateRefusal", "Get-Excerpt"],
    ) + (
        f"""
$script:LogLines = @({_psq(json.dumps(lines))} | ConvertFrom-Json)
$script:ReadingsSeen = New-Object System.Collections.ArrayList
function Update-OwnerSample([string]$Phase) {{ }}
function Get-LogMatches {{ param([string]$Pattern) @($script:LogLines | Select-String -Pattern $Pattern) }}
function Add-Reading([string]$Text) {{ [void]$script:ReadingsSeen.Add($Text) }}
$WaitSeconds = 2
$refused = [bool](Wait-ForGateRefusal 'the first start')
ConvertTo-Json -Compress -InputObject @{{
  refused = $refused; let_start_seen = [bool]$script:GateLetStartSeen
  readings = @($script:ReadingsSeen).Count }}
"""
    )
    return _run(host, tmp_path, script)


def test_the_engine_still_words_the_gate_lines_so() -> None:
    app = _APP.read_text(encoding="utf-8")
    for prefix, line in (_REFUSAL, _SKIPPED, _WARN_MODE, _COULD_NOT_RUN):
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
    # Another engine line that carries the clause and is not the gate's.
    census = (
        "WARNING messagefoundry.auth.service: no enabled Administrator can sign in without an"
        " outside identity service"
    )
    got = _judge(
        host,
        tmp_path,
        [_REFUSAL[1], _SKIPPED[1], _WARN_MODE[1], _COULD_NOT_RUN[1], census, "unrelated line"],
    )
    assert got["refusal"] == [True, False, False, False, False, False], got
    # The narrower clause the StartFirstEndToEnd arm passes: the no-Administrator refusal only.
    assert got["no_admin"] == [True, False, False, False, False, False], got
    # Only the gate's let-it-start lines end the wait early, not the census line.
    assert got["let_start"] == [False, True, True, True, False, False], got
    # The control: the clause the wait used to match alone is in the first two warning lines, so the
    # old criterion took an engine that went on to serve for a refused one. The could-not-run line
    # does not carry it.
    assert got["clause"] == [True, True, True, False, True, False], got


@pytest.mark.parametrize("host", ["pwsh", "powershell"])
@pytest.mark.parametrize(
    ("line", "refused", "let_start"),
    [
        (_REFUSAL[1], True, False),
        (_SKIPPED[1], False, True),
        (_WARN_MODE[1], False, True),
        # Without the clause, a let-start search confined to clause lines never sees this one: the
        # wait ran to its timeout and the failure named store access.
        (_COULD_NOT_RUN[1], False, True),
        ("unrelated line", False, False),
    ],
)
def test_the_wait_ends_on_each_gate_line(
    tmp_path: Path, host: str, line: str, refused: bool, let_start: bool
) -> None:
    got = _wait(host, tmp_path, [line])
    assert got["refused"] is refused, got
    assert got["let_start_seen"] is let_start, got
    # A let-start line is quoted in a reading, which the failure text points at.
    assert got["readings"] == (1 if let_start else 0), got


def test_a_first_start_the_gate_let_go_on_is_not_attributed_to_store_access() -> None:
    # Both first-start branches go through Add-FirstStartFailure, which names the cause only as the
    # control and restart branches do: the store-access attribution only when the gate did not let
    # the start go on.
    text = _SCRIPT.read_text(encoding="utf-8")
    calls = [ln.strip() for ln in text.splitlines()]
    assert calls.count("Add-FirstStartFailure") == 2
    failure = 'Add-Failure ("$ServiceIdentity $what within $WaitSeconds s on a fresh store. "'
    assert text.count(failure) == 1
    at = text.index(failure)
    assert text.rindex("function Add-FirstStartFailure", 0, at) > 0
    before = text[text.rindex("$cause = if", 0, at) : at]
    assert before.startswith("$cause = if ($script:GateLetStartSeen) {"), before
    assert "Get-Attribution" in before.split("else", 1)[1], before
    assert "Get-Attribution" not in text[at : text.index("\n", at)]
