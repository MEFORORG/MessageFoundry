# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""Static guards on the two mefor-net-helper service scripts (BACKLOG #1523, ADR 0056).

NOTHING IN CI RUNS THESE SCRIPTS. They need an elevated Windows session, a published helper binary
and an nssm.exe, so the first thing that reads them end to end is an operator on a cluster node. That
makes a few properties worth pinning from here, because the alternative to a guard is not a later
test -- it is nobody.

Three of the four are decisions that a later edit would flip without anything noticing:

1. **The installer carries no second NSSM pin.** install-service.ps1 owns the archive URL and its
   SHA-256, and ``test_service_install_manifest.py`` guards that one. A copy here would be a second
   thing to keep current, and a stale copy of a supply-chain pin is worse than no copy.
2. **The installer reads [cluster.vip] through the engine, not by parsing TOML.** That is the whole
   of #1523's constraint: the helper refuses any request naming values other than its .conf's, so
   the installer's three values and the engine's three values must be the same three values, and a
   parser here would be a second DEFINITION of the block rather than a second reader of it.
3. **The uninstaller does not release the address unless asked.** On the node holding the VIP, an
   unasked release drops a live address during an uninstall, and nothing takes it over.

The fourth is a plain syntax check, which is worth its line precisely because no CI leg runs them.
"""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import uuid
from pathlib import Path

import pytest

import messagefoundry.service as svc

_INSTALL_SERVICE = svc.install_script_path()
_DIR = _INSTALL_SERVICE.parent if _INSTALL_SERVICE is not None else None
_INSTALL = _DIR / "install-net-helper.ps1" if _DIR is not None else None
_UNINSTALL = _DIR / "uninstall-net-helper.ps1" if _DIR is not None else None

pytestmark = pytest.mark.skipif(
    _DIR is None,
    reason="scripts/service not locatable (off-repo / non-editable install)",
)


def _text(path: Path | None) -> str:
    assert path is not None  # narrowed by the module-level skipif
    return path.read_text(encoding="utf-8")


def _psq(value: str) -> str:
    """One PowerShell single-quoted literal. Backslashes are literal inside single quotes."""
    return "'" + value.replace("'", "''") + "'"


# ONE pwsh PROCESS FOR THE WHOLE FILE. This test imports the engine, so tests/tooling_manifest.txt
# correctly leaves it off the path-gated tooling tier and it runs on every engine leg of every code
# PR. Measured on this box: three spawns cost 1.16s of a 1.83s file, and ci.yml records a ~2.4x
# process-spawn tax on the Windows leg. Every check here is the same operation -- Parser::ParseFile
# over a file in scripts/service/ -- so one session-scoped run answers all of them at once, and each
# test still asserts its own property with its own message.
@pytest.fixture(scope="session")
def ast_report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, object]:
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    assert _DIR is not None and _UNINSTALL is not None
    script = f"""
$ErrorActionPreference = 'Stop'
$report = @{{}}

# ParseFile parses; it never runs the file.
$parse = @{{}}
foreach ($name in @('install-net-helper.ps1', 'uninstall-net-helper.ps1')) {{
  $path = Join-Path {_psq(str(_DIR))} $name
  $errs = $null
  $null = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$errs)
  $parse[$name] = @($errs | ForEach-Object {{ "$($_.Extent.StartLineNumber): $($_.Message)" }})
}}
$report['parse'] = $parse

# Every service-name parameter: the ValidatePattern literal it declares, and what its declaration
# ACTUALLY binds. The two are asked separately on purpose -- matching text is not a matching
# decision, and `param(...)` is the only thing that can answer the second question.
$names = @{{}}
foreach ($name in @('install-net-helper.ps1', 'uninstall-net-helper.ps1')) {{
  $path = Join-Path {_psq(str(_DIR))} $name
  $ast = [System.Management.Automation.Language.Parser]::ParseFile($path, [ref]$null, [ref]$null)
  foreach ($p in $ast.ParamBlock.Parameters) {{
    $pname = $p.Name.VariablePath.UserPath
    if ($pname -notmatch 'ServiceName$') {{ continue }}
    $attr = @($p.Attributes | Where-Object {{ $_.TypeName.Name -eq 'ValidatePattern' }})
    $row = @{{ pattern = $null }}
    if ($attr.Count -eq 1) {{ $row['pattern'] = $attr[0].PositionalArguments[0].Value }}
    # Bind the REAL declaration, lifted verbatim out of the script's own param block.
    foreach ($probe in @(
        @{{ key = 'spaced'; value = 'MessageFoundry Prod' }},
        @{{ key = 'quoted'; value = "MessageFoundry'" }})) {{
      $sb = [scriptblock]::Create("param($($p.Extent.Text))`n`$$pname")
      $splat = @{{ $pname = $probe.value }}
      try {{ $null = & $sb @splat; $row[$probe.key] = $true }}
      catch {{ $row[$probe.key] = $false }}
    }}
    $names["$name::$pname"] = $row
  }}
}}
$report['service_names'] = $names

$ast = [System.Management.Automation.Language.Parser]::ParseFile(
    {_psq(str(_UNINSTALL))}, [ref]$null, [ref]$null)
$defined = [bool]$ast.Find({{ $args[0] -is
    [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $args[0].Name -eq 'Invoke-HelperRelease' }}, $true)
$calls = @($ast.FindAll({{ $args[0] -is
    [System.Management.Automation.Language.CommandAst] -and
    $args[0].CommandElements.Count -gt 0 -and
    $args[0].CommandElements[0].Extent.Text -eq 'Invoke-HelperRelease' }}, $true))
$guarded = 0
foreach ($call in $calls) {{
  $node = $call
  $ok = $false
  while ($node) {{
    if ($node -is [System.Management.Automation.Language.IfStatementAst]) {{
      foreach ($clause in $node.Clauses) {{
        # THE CONDITION MUST BE THE BARE VARIABLE. A substring match would also accept
        # `if (-not $ReleaseAddress)`, which is the inverted form of the very default this pins.
        if ($clause.Item1.PipelineElements.Count -eq 1) {{
          $expr = $clause.Item1.PipelineElements[0].Expression
          if ($expr -is [System.Management.Automation.Language.VariableExpressionAst] -and
              $expr.VariablePath.UserPath -eq 'ReleaseAddress') {{ $ok = $true }}
        }}
      }}
    }}
    $node = $node.Parent
  }}
  if ($ok) {{ $guarded++ }}
}}
$report['release'] = @{{ defined = $defined; calls = $calls.Count; guarded = $guarded }}
$report | ConvertTo-Json -Depth 5 -Compress
"""
    f = tmp_path_factory.mktemp("netguard") / f"guard-{uuid.uuid4().hex}.ps1"
    f.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(f)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    parsed = json.loads(proc.stdout.strip().splitlines()[-1])
    assert isinstance(parsed, dict)
    return parsed


# A pinned NSSM release hash is 64 hex characters in a quoted literal. Matched case-insensitively so
# a re-pin written in lower case is still found.
_SHA256 = re.compile(r"""["'][0-9a-fA-F]{64}["']""")


def test_the_installer_carries_no_second_nssm_pin() -> None:
    install_service = _text(_INSTALL_SERVICE)
    # THE CONTROL FIRST. install-service.ps1 holds both, so a search that cannot find them there
    # proves nothing by finding none in the new script.
    assert "nssm.cc/release" in install_service, (
        "CONTROL FAILED: install-service.ps1 no longer holds the NSSM archive URL, so the search "
        "below is aimed at nothing -- re-aim this guard at wherever the pin moved"
    )
    assert _SHA256.search(install_service), (
        "CONTROL FAILED: install-service.ps1 no longer holds a 64-hex pin; re-aim this guard"
    )

    helper_installer = _text(_INSTALL)
    assert "nssm.cc/release" not in helper_installer, (
        "install-net-helper.ps1 names an NSSM download URL. The pin belongs in install-service.ps1 "
        "alone; a second copy goes stale quietly and a stale supply-chain pin is worse than none. "
        "Take -NssmPath, or find nssm on PATH."
    )
    found = _SHA256.search(helper_installer)
    assert found is None, (
        f"install-net-helper.ps1 carries what looks like a pinned hash ({found.group()}). "
        "See the previous assertion."
    )


def test_the_installer_reads_cluster_vip_through_the_engine() -> None:
    text = _text(_INSTALL)
    assert "cluster-vip" in text, (
        "install-net-helper.ps1 no longer runs `messagefoundry cluster-vip`. That subcommand exists "
        "for this one caller (BACKLOG #1523); if the read moved, move this guard with it."
    )
    # A TOML parse would need one of these. `messagefoundry.toml` appears only as the *name* of what
    # -ServiceConfig points at, which the CLI opens -- so the file name alone is not the tell; the
    # tell is a parser.
    for parser in ("ConvertFrom-Toml", "tomlkit", "tomllib", "Import-Toml", "[Toml]"):
        assert parser not in text, (
            f"install-net-helper.ps1 parses TOML ({parser}). The helper refuses any request naming "
            "values other than its .conf's, so the installer's address/interface/mask and the "
            "engine's must be the same values -- a parser here is a second definition of "
            "[cluster.vip], not a second reader of it (BACKLOG #1523)."
        )


def test_the_uninstaller_releases_the_address_only_when_asked(
    ast_report: dict[str, object],
) -> None:
    """The release call site must sit under an ``if ($ReleaseAddress)``, un-negated.

    READ THE AST, NOT THE TEXT. The script's own prose explains the decision and names both the
    switch and the function, so a string scan would find the explanation and report compliance. The
    harness walks up from each call to its enclosing ``if`` statements and requires the condition to
    be the BARE variable -- a substring test would also pass ``if (-not $ReleaseAddress)``, which is
    the inverted form of the very default this exists to pin.
    """
    release = ast_report["release"]
    assert isinstance(release, dict)
    assert release["defined"], (
        "CONTROL FAILED: Invoke-HelperRelease is not defined in uninstall-net-helper.ps1, so a "
        "zero call count below would mean nothing -- re-aim this guard"
    )
    calls, guarded = int(release["calls"]), int(release["guarded"])
    assert calls >= 1, (
        "CONTROL FAILED: no call to Invoke-HelperRelease was found, so 'all of them are guarded' "
        "would be vacuously true -- re-aim this guard"
    )
    assert guarded == calls, (
        f"{calls - guarded} of {calls} calls to Invoke-HelperRelease are not under a bare "
        "`if ($ReleaseAddress)`. Releasing by default drops a live address during an uninstall on "
        "the node that holds the VIP, and nothing takes it over -- the helper that would have "
        "re-bound it elsewhere is what is being removed."
    )


def test_both_scripts_take_the_same_service_names(ast_report: dict[str, object]) -> None:
    """Whatever the installer will accept as a service name, the uninstaller must accept too.

    ONE DEFINITION, ``messagefoundry/service.py``'s ``_SAFE_SERVICE_NAME``, and two literal copies of
    it in ``param()`` blocks. The copies cannot be dot-sourced away: a PowerShell attribute argument
    must be a compile-time constant, and ``[ValidatePattern($pattern)]`` is refused at parse with
    *"Attribute argument must be a constant or a script block"*. So the copies are pinned here
    instead, which is what makes them one definition rather than three.

    The pattern is there because both names are interpolated into a WQL filter, where a single quote
    ends the literal. A space cannot, and ``install-service.ps1`` puts no validation on its own
    ``-ServiceName`` -- so an engine installed as ``MessageFoundry Prod`` is a name the node really
    can carry. A tighter pattern on one side makes that helper installable and not removable, and it
    fails at parameter binding, before the script can explain itself.

    BOTH HALVES ARE ASKED. Equal text is not an equal decision, so the harness also BINDS each
    declaration verbatim; and "it accepts a space" would be equally true of a parameter with no
    validation at all, so the quote must still be refused.
    """
    rows = ast_report["service_names"]
    assert isinstance(rows, dict)
    expected = svc._SAFE_SERVICE_NAME.pattern
    assert set(rows) == {
        "install-net-helper.ps1::ServiceName",
        "install-net-helper.ps1::EngineServiceName",
        "uninstall-net-helper.ps1::ServiceName",
    }, (
        "CONTROL FAILED: the harness found a different set of service-name parameters than this "
        f"guard was aimed at ({sorted(rows)}) -- re-aim it, do not relax it"
    )
    for key, row in sorted(rows.items()):
        assert isinstance(row, dict)
        assert row["pattern"] == expected, (
            f"{key} validates against {row['pattern']!r}, not messagefoundry/service.py's "
            f"_SAFE_SERVICE_NAME ({expected!r}). Both scripts must take the same names: a helper "
            "installed under a name one of them rejects cannot be removed by the other."
        )
        assert row["spaced"] is True, (
            f"{key} refuses 'MessageFoundry Prod' at parameter binding. install-service.ps1 puts no "
            "validation on its own -ServiceName and a space is legal in a Windows service name."
        )
        assert row["quoted"] is False, (
            f"CONTROL FAILED: {key} accepts a single quote. The name is interpolated into a WQL "
            "filter, where a quote ends the literal -- and an unvalidated parameter would pass the "
            "space assertion above for the wrong reason."
        )


@pytest.mark.parametrize("name", ["install-net-helper.ps1", "uninstall-net-helper.ps1"])
def test_the_script_parses(ast_report: dict[str, object], name: str) -> None:
    # No CI leg runs either script, so a syntax error would first show up on an operator's node
    # mid-install. Parsing is not running: ParseFile never executes the file.
    parse = ast_report["parse"]
    assert isinstance(parse, dict)
    assert name in parse, f"CONTROL FAILED: the harness did not parse {name} -- re-aim this guard"
    assert parse[name] == [], f"{name} has parse errors:\n" + "\n".join(parse[name])
