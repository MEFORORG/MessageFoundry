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

import re
import shutil
import subprocess
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


def _pwsh(script: str, tmp_path: Path) -> str:
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    f = tmp_path / "net-helper-guard.ps1"
    f.write_text(script, encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(f)],
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, f"harness failed: {proc.stdout}\n{proc.stderr}"
    return proc.stdout.strip()


# A pinned NSSM release hash is 64 hex characters in a quoted literal. Matched case-insensitively so
# a re-pin written in lower case is still found.
_SHA256 = re.compile(r"""["'][0-9a-fA-F]{64}["']""")


def test_the_installer_carries_no_second_nssm_pin(tmp_path: Path) -> None:
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
        f"install-net-helper.ps1 carries what looks like a pinned hash ({found.group() if found else ''}). "
        "See the previous assertion."
    )


def test_the_installer_reads_cluster_vip_through_the_engine(tmp_path: Path) -> None:
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


def test_the_uninstaller_releases_the_address_only_when_asked(tmp_path: Path) -> None:
    """The release call site must sit under an ``if ($ReleaseAddress)``.

    READ THE AST, NOT THE TEXT. The script's own prose explains the decision and names both the
    switch and the function, so a string scan would find the explanation and report compliance.
    This walks up from the call to its enclosing ``if`` statements instead.
    """
    assert _UNINSTALL is not None
    src = str(_UNINSTALL).replace("'", "''")
    script = f"""
$ErrorActionPreference = 'Stop'
$ast = [System.Management.Automation.Language.Parser]::ParseFile('{src}', [ref]$null, [ref]$null)
$defn = $ast.Find({{ $args[0] -is
    [System.Management.Automation.Language.FunctionDefinitionAst] -and
    $args[0].Name -eq 'Invoke-HelperRelease' }}, $true)
if (-not $defn) {{ throw 'Invoke-HelperRelease is not defined' }}
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
        if ($clause.Item1.Extent.Text -match '\\$ReleaseAddress') {{ $ok = $true }}
      }}
    }}
    $node = $node.Parent
  }}
  if ($ok) {{ $guarded++ }}
}}
Write-Output "$($calls.Count) $guarded"
"""
    calls, guarded = (int(n) for n in _pwsh(script, tmp_path).split())
    assert calls >= 1, (
        "CONTROL FAILED: no call to Invoke-HelperRelease was found, so 'all of them are guarded' "
        "would be vacuously true -- re-aim this guard"
    )
    assert guarded == calls, (
        f"{calls - guarded} of {calls} calls to Invoke-HelperRelease are not under an "
        "`if ($ReleaseAddress)`. Releasing by default drops a live address during an uninstall on "
        "the node that holds the VIP, and nothing takes it over -- the helper that would have "
        "re-bound it elsewhere is what is being removed."
    )


@pytest.mark.parametrize("name", ["install-net-helper.ps1", "uninstall-net-helper.ps1"])
def test_the_script_parses(tmp_path: Path, name: str) -> None:
    # No CI leg runs either script, so a syntax error would first show up on an operator's node
    # mid-install. Parsing is not running: ParseFile never executes the file.
    assert _DIR is not None
    src = str(_DIR / name).replace("'", "''")
    script = f"""
$errs = $null
$null = [System.Management.Automation.Language.Parser]::ParseFile(
    '{src}', [ref]$null, [ref]$errs)
if ($errs) {{ $errs | ForEach-Object {{ Write-Output "$($_.Extent.StartLineNumber): $($_.Message)" }} }}
else {{ Write-Output 'clean' }}
"""
    assert _pwsh(script, tmp_path) == "clean"
