# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
"""No service script runs an nssm.exe it has not checked, from a folder the engine can write (#2364).

``install-service.ps1`` used to check NSSM's hash only when it downloaded the archive, and cached the
binary in ``<DataDir>\\bin``, where the engine's own account has modify rights. A copy from
``-NssmPath``, ``PATH`` or that cache ran unchecked, as administrator. A hash check alone would not
have been enough there: from that folder the engine could also plant a DLL beside the binary, or turn
the folder into a junction after the check. The helper installer checked neither ``nssm.exe`` nor
``mefor-net-helper.exe`` before starting the helper as LocalSystem.

What the scripts do now, and what this file pins:

1. **One pin, two identical copies.** ``install-service.ps1`` and ``install-net-helper.ps1`` share a
   byte-identical block: ``$NssmExeSha256`` (the win64 ``nssm.exe`` inside the pinned archive, which
   is NOT the archive's own ``$NssmSha256``), ``Get-FilePinProblem``, ``Get-BroadWriteHolders``,
   ``Get-ServiceImageProblem`` and ``Set-ServiceImage``.
2. **The engine installer keeps nssm.exe in an administrator-only folder,** ``-NssmDir``. It sets
   the ACL of every folder it creates there and of the file it copies in, checks every source against
   the pin before copying it in, and refuses when anyone else can write the file, its folder, or a
   folder above. The resolver is lifted out by PowerShell AST and run against stand-in files, with
   the ACL reading stubbed per path, because a test's temp folder is never administrator-only.
3. **The registration is pointed at the checked copy, quoted, and read back.** Both functions run
   against a stubbed registry and a stubbed ``Win32_Service.Change``.
4. **Each top level uses these in order**, read from the AST.
5. **The uninstallers run no nssm.exe at all.** The SCM stops the service and ``sc.exe`` removes it.

Every refusal has a positive control beside it: a check that refuses everything would pass a
refusal-only test. Everything runs in ONE pwsh process, because this file imports the engine and so
runs on every engine leg, where each spawn costs about a second.

WHAT THIS DOES NOT TEST: that ``$NssmExeSha256`` is the hash of the real binary, that
``Win32_Service.Change`` behaves as stubbed, and that the SCM starts a service registered from
``-NssmDir``. The download path checks the extracted binary against the pin, so a wrong pin fails
closed on the first download. The ``windows-service-smoke`` leg runs that download, that change and
that start.
"""

from __future__ import annotations

import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import uuid
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

import messagefoundry.service as svc

_INSTALL_SERVICE = svc.install_script_path()
_DIR = _INSTALL_SERVICE.parent if _INSTALL_SERVICE is not None else None

pytestmark = pytest.mark.skipif(
    _DIR is None,
    reason="scripts/service not locatable (off-repo / non-editable install)",
)

_WITH_BLOCK = ("install-service.ps1", "install-net-helper.ps1")
_WITHOUT_NSSM = ("uninstall-service.ps1", "uninstall-net-helper.ps1")
_BEGIN = "# BEGIN pinned-hash check"
_END = "# END pinned-hash check"
_PIN_RE = re.compile(r'^\$NssmExeSha256\s*=\s*"([^"]*)"', re.M)
_ARCHIVE_RE = re.compile(r'\$NssmSha256\s*=\s*"([^"]*)"')

# Stand-ins for nssm.exe. Never executed: every function under test only hashes or copies them.
_GOOD = b"stand-in for the pinned nssm.exe\n"
_BAD = b"stand-in for a planted nssm.exe\n"


def _path(name: str) -> Path:
    assert _DIR is not None  # narrowed by the module-level skipif
    return _DIR / name


def _text(name: str) -> str:
    return _path(name).read_text(encoding="utf-8").replace("\r\n", "\n")


def _block(name: str) -> str:
    text = _text(name)
    assert text.count(_BEGIN) == 1 and text.count(_END) == 1, (
        f"{name} must hold exactly one pinned-hash block, between '{_BEGIN}' and '{_END}'"
    )
    return text[text.index(_BEGIN) : text.index(_END) + len(_END)]


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest().upper()


def _psq(value: str) -> str:
    """One PowerShell single-quoted literal. Backslashes are literal inside single quotes."""
    return "'" + value.replace("'", "''") + "'"


# ------------------------------------------------------------------------------ the shared pin


def test_the_two_copies_of_the_block_are_identical() -> None:
    first, second = (_block(name) for name in _WITH_BLOCK)
    assert first == second, (
        "the pinned-hash block in install-net-helper.ps1 differs from install-service.ps1's. The two "
        "copies are one definition kept in two places; change both in the same commit."
    )


def test_the_pin_is_well_formed_and_is_not_the_archive_pin() -> None:
    found = _PIN_RE.findall(_block("install-service.ps1"))
    assert len(found) == 1, "CONTROL FAILED: the block holds no $NssmExeSha256 assignment"
    pin = found[0]
    assert re.fullmatch(r"[0-9A-F]{64}", pin), (
        f"$NssmExeSha256 must be 64 uppercase hex characters; got {pin!r}"
    )
    archive = _ARCHIVE_RE.search(_text("install-service.ps1"))
    assert archive is not None, "CONTROL FAILED: install-service.ps1 no longer pins the archive"
    assert pin != archive.group(1), (
        "$NssmExeSha256 equals $NssmSha256, the hash of the ZIP. A binary is never equal to its "
        "archive, so every copy of nssm.exe would be refused."
    )


def test_no_script_restates_the_pin_outside_the_block() -> None:
    pin = _PIN_RE.findall(_block("install-service.ps1"))[0].lower()
    for name in _WITH_BLOCK + _WITHOUT_NSSM:
        text = _text(name)
        outside = text.replace(_block(name), "") if name in _WITH_BLOCK else text
        assert pin not in outside.lower(), (
            f"{name} states the nssm.exe pin outside the shared block. A second spelling is not "
            "guarded by the drift test and goes stale quietly."
        )


# ------------------------------------------------------------------- one pwsh run for all of it

# Functions lifted out of each script. The block's functions are identical in both installers,
# which the drift test above pins, so taking them from one is taking them from both.
_FUNCTIONS = {
    "install-service.ps1": [
        "Get-FilePinProblem",
        "Get-ServiceImageProblem",
        "Set-ServiceImage",
        "Set-ServiceAccount",
        "Set-AdminOnlyAcl",
        "Get-NssmHomeProblem",
        "Resolve-Nssm",
        "Save-PinnedNssm",
    ],
    "install-net-helper.ps1": ["Resolve-AbsolutePath", "Resolve-HelperNssm"],
}

# Stubs, defined AFTER the lifted functions so they win. A test's temp folder is never
# administrator-only, so the ACL reading is set per path; icacls calls are recorded, not run; the
# download must never be reached; the registry and Win32_Service are whatever a case says they are.
_STUBS = """
  $broadFor = @{}
  function Get-BroadWriteHolders { param($Path) if ($broadFor.ContainsKey("$Path")) { $broadFor["$Path"] } }
  function Invoke-WebRequest { throw 'NETWORK TOUCHED' }
  $icaclsCalls = [Collections.Generic.List[string]]::new()
  function icacls { $icaclsCalls.Add(($args -join ' ')) }
  $registry = @{}
  $changeResult = 0
  $changeApplies = $true
  $changes = [Collections.Generic.List[string]]::new()
  $throwWith = ''
  $disabled = [Collections.Generic.List[string]]::new()
  function Set-Service { param($Name, $StartupType, $ErrorAction) $disabled.Add("$Name=$StartupType") }
  function Get-ItemProperty {
    param($LiteralPath, $Name, $ErrorAction)
    $svcName = Split-Path -Leaf $LiteralPath
    if (-not $registry.ContainsKey($svcName)) { throw "no such key: $LiteralPath" }
    [pscustomobject]$registry[$svcName]
  }
  function Get-CimInstance { @($registry.Keys | ForEach-Object { [pscustomobject]@{ Name = $_ } }) }
  function Invoke-CimMethod {
    param($InputObject, $MethodName, $Arguments, $ErrorAction)
    # Recorded at call time: Set-ServiceAccount empties its table in `finally`.
    $changes.Add("keys=$(@($Arguments.Keys | Sort-Object) -join ',');" +
      "pw=$($Arguments['StartPassword'])")
    if ($throwWith) { throw $throwWith }
    if ($changeApplies -and $changeResult -eq 0) {
      if ($Arguments.ContainsKey('PathName')) { $registry[$InputObject.Name].ImagePath = $Arguments.PathName }
      if ($Arguments.ContainsKey('StartName')) { $registry[$InputObject.Name].ObjectName = $Arguments.StartName }
    }
    [pscustomobject]@{ ReturnValue = $changeResult }
  }
"""

_CASES = r"""
  # --- Get-FilePinProblem
  Invoke-Case 'pin-good' 'path-none' { Get-FilePinProblem -Path $good -Expected $NssmExeSha256 }
  Invoke-Case 'pin-good-lower' 'path-none' {
    Get-FilePinProblem -Path $good -Expected $NssmExeSha256.ToLowerInvariant() }
  Invoke-Case 'pin-bad' 'path-none' { Get-FilePinProblem -Path $bad -Expected $NssmExeSha256 }
  Invoke-Case 'pin-missing' 'path-none' {
    Get-FilePinProblem -Path (Join-Path $root 'nope.exe') -Expected $NssmExeSha256 }
  # --- install-service.ps1 Resolve-Nssm, each case with a folder of its own
  Invoke-Case 'install-provided-good' 'path-bad' {
    Resolve-Nssm -Provided $good -NssmDir (Join-Path $root 'new/home-provided-good') }
  Invoke-Case 'install-provided-bad' 'path-good' {
    Resolve-Nssm -Provided $bad -NssmDir (Join-Path $root 'home-provided-bad') }
  Invoke-Case 'install-path-good' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-path-good') }
  # TEMP and TMP are cleared for this case: Linux pwsh sets neither, and CI run 36590581708 went red
  # on ubuntu when the download path joined onto a null $env:TEMP. Clearing them here reproduces
  # that on every host.
  $savedTemp = $env:TEMP; $savedTmp = $env:TMP
  $env:TEMP = $null; $env:TMP = $null
  Invoke-Case 'install-path-bad' 'path-bad' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-path-bad') }
  $env:TEMP = $savedTemp; $env:TMP = $savedTmp
  Invoke-Case 'install-home-good' 'path-bad' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-good') }
  Invoke-Case 'install-home-bad' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-bad') }
  Invoke-Case 'install-home-good-provided-bad' 'path-good' {
    Resolve-Nssm -Provided $bad -NssmDir (Join-Path $root 'home-good') }
  $broadFor[(Join-Path $root 'home-broad')] = @('BUILTIN\Users (Write)')
  Invoke-Case 'install-broad-folder' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-broad') }
  $broadFor = @{ "$root" = @('BUILTIN\Users (DeleteSubdirectoriesAndFiles)') }
  Invoke-Case 'install-broad-parent' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-under-broad') }
  $broadFor = @{ (Join-Path $root 'home-good/nssm.exe') = @('DOMAIN\op (FullControl)') }
  Invoke-Case 'install-broad-file' 'path-good' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-good') }
  $broadFor = @{}
  # --- install-net-helper.ps1 Resolve-HelperNssm
  Invoke-Case 'helper-provided-good' 'path-bad' { Resolve-HelperNssm -Provided $good }
  Invoke-Case 'helper-provided-bad' 'path-good' { Resolve-HelperNssm -Provided $bad }
  Invoke-Case 'helper-path-good' 'path-good' { Resolve-HelperNssm }
  Invoke-Case 'helper-path-bad' 'path-bad' { Resolve-HelperNssm }
  Invoke-Case 'helper-none' 'path-none' { Resolve-HelperNssm }
  # --- Get-ServiceImageProblem, over a stubbed registry
  $img = 'C:\Program Files\MessageFoundry\nssm\nssm.exe'
  foreach ($row in @(
      @{ key = 'image-quoted'; line = ('"' + $img + '"') },
      @{ key = 'image-quoted-args'; line = ('"' + $img + '" -x') },
      @{ key = 'image-unquoted'; line = $img },
      @{ key = 'image-other'; line = '"C:\ProgramData\MessageFoundry\bin\nssm.exe"' },
      @{ key = 'image-longer-name'; line = ('"' + $img + '.evil.exe"') })) {
    $registry = @{ Svc = @{ ImagePath = $row.line } }
    Invoke-Case $row.key 'path-none' { Get-ServiceImageProblem -ServiceName 'Svc' -Path $img }
  }
  $registry = @{ Other = @{ ImagePath = ('"' + $img + '"') } }
  Invoke-Case 'image-missing' 'path-none' { Get-ServiceImageProblem -ServiceName 'Svc' -Path $img }
  # --- Set-ServiceImage, over the same stubs
  $registry = @{ Svc = @{ ImagePath = $img } }; $changes.Clear()
  Invoke-Case 'set-unquoted' 'path-none' {
    Set-ServiceImage -ServiceName 'Svc' -Path $img; "$($changes.Count)|$($registry['Svc'].ImagePath)" }
  $registry = @{ Svc = @{ ImagePath = ('"' + $img + '"') } }; $changes.Clear()
  Invoke-Case 'set-already' 'path-none' { Set-ServiceImage -ServiceName 'Svc' -Path $img; "$($changes.Count)" }
  $registry = @{ Svc = @{ ImagePath = '"C:\ProgramData\MessageFoundry\bin\nssm.exe"' } }; $changeResult = 2
  Invoke-Case 'set-refused' 'path-none' { Set-ServiceImage -ServiceName 'Svc' -Path $img }
  $changeResult = 0; $changeApplies = $false
  Invoke-Case 'set-not-applied' 'path-none' { Set-ServiceImage -ServiceName 'Svc' -Path $img }
  $changeApplies = $true
  # --- Set-ServiceAccount, over the same stubs. The password is synthetic.
  $pw = ConvertTo-SecureString 'synthetic-pw-1573' -AsPlainText -Force
  function Invoke-AccountCase([string]$Key, [scriptblock]$Action) {
    $registry = @{ Svc = @{ ImagePath = '"x"'; ObjectName = 'LocalSystem' } }
    $changes.Clear(); $disabled.Clear()
    Invoke-Case $Key 'path-none' { & $Action; "stored=$($registry['Svc'].ObjectName)|$($changes -join '/')" }
    $res["$Key-disabled"] = @($disabled)
  }
  Invoke-AccountCase 'acct-virtual' { Set-ServiceAccount -ServiceName 'Svc' -Account 'NT SERVICE\Svc' }
  Invoke-AccountCase 'acct-localsystem' { Set-ServiceAccount -ServiceName 'Svc' -Account 'LocalSystem' }
  Invoke-AccountCase 'acct-password' {
    Set-ServiceAccount -ServiceName 'Svc' -Account 'DOMAIN\svc' -Password $pw }
  $changeResult = 2
  Invoke-AccountCase 'acct-refused' {
    Set-ServiceAccount -ServiceName 'Svc' -Account 'DOMAIN\svc' -Password $pw }
  $changeResult = 0; $throwWith = 'provider echoed synthetic-pw-1573 back'
  Invoke-AccountCase 'acct-throws' {
    Set-ServiceAccount -ServiceName 'Svc' -Account 'DOMAIN\svc' -Password $pw }
  $throwWith = 'provider failed'
  Invoke-AccountCase 'acct-throws-nopw' { Set-ServiceAccount -ServiceName 'Svc' -Account 'NT SERVICE\Svc' }
  $throwWith = ''; $changeApplies = $false
  Invoke-AccountCase 'acct-not-applied' { Set-ServiceAccount -ServiceName 'Svc' -Account 'NT SERVICE\Svc' }
  $changeApplies = $true
  Invoke-AccountCase 'acct-canonical' { Set-ServiceAccount -ServiceName 'Svc' -Account $env:USERNAME }
  # Where each resolver case left nssm.exe, and what it holds; and what was sent to icacls.
  $res['homes'] = @{}
  foreach ($d in @(Get-ChildItem -LiteralPath $root -Directory -Recurse -Filter 'home-*')) {
    $f = Join-Path $d.FullName 'nssm.exe'
    $res['homes'][$d.Name] = $(if (Test-Path -LiteralPath $f) {
      (Get-FileHash -Algorithm SHA256 -LiteralPath $f).Hash } else { '' })
  }
  $res['icacls'] = @($icaclsCalls)
"""

_AST_PROBES = """
  $ast = @{}
  foreach ($name in @('install-service.ps1', 'uninstall-service.ps1', 'install-net-helper.ps1',
                      'uninstall-net-helper.ps1')) {
    $tree = [System.Management.Automation.Language.Parser]::ParseFile(
      (Join-Path $scripts $name), [ref]$null, [ref]$null)
    $ast[$name] = @{
      commands = @($tree.FindAll({
          $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
        Where-Object { $_.CommandElements.Count -gt 0 } |
        ForEach-Object { @{ name = $_.GetCommandName(); first = $_.CommandElements[0].Extent.Text;
          text = $_.Extent.Text; offset = $_.Extent.StartOffset } })
      functions = @($tree.FindAll({
          $args[0] -is [System.Management.Automation.Language.FunctionDefinitionAst] }, $true) |
        ForEach-Object { @{ name = $_.Name; start = $_.Extent.StartOffset; end = $_.Extent.EndOffset } })
      params = @($tree.ParamBlock.Parameters | ForEach-Object { $_.Name.VariablePath.UserPath })
    }
  }
  $tree = [System.Management.Automation.Language.Parser]::ParseFile(
    (Join-Path $scripts 'install-net-helper.ps1'), [ref]$null, [ref]$null)
  $p = $tree.ParamBlock.Parameters | Where-Object { $_.Name.VariablePath.UserPath -eq 'HelperSha256' }
  $row = @{ declared = [bool]$p }
  if ($p) {
    $row['mandatory'] = [bool]($p.Attributes | Where-Object {
      $_.TypeName.Name -eq 'Parameter' -and $_.NamedArguments.ArgumentName -contains 'Mandatory' })
    foreach ($probe in @(
        @{ key = 'hex'; value = ('ab' * 32) },
        @{ key = 'short'; value = 'abc' },
        @{ key = 'nonhex'; value = ('zz' * 32) })) {
      $sb = [scriptblock]::Create("param($($p.Extent.Text))`n`$HelperSha256")
      $splat = @{ HelperSha256 = $probe.value }
      try { $null = & $sb @splat; $row[$probe.key] = $true } catch { $row[$probe.key] = $false }
    }
  }
  $ast['helper-param'] = $row
  $res['ast'] = $ast
"""


def _stand_in(directory: Path, data: bytes) -> None:
    """An nssm on a PATH directory: nssm.exe for Windows, an executable `nssm` elsewhere."""
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "nssm.exe").write_bytes(data)
    plain = directory / "nssm"
    plain.write_bytes(data)
    plain.chmod(plain.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture(scope="module")
def report(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    """Run every case, and read every top level, in ONE pwsh process."""
    if shutil.which("pwsh") is None:
        pytest.skip("SKIP (nothing run): pwsh not on PATH")
    root = tmp_path_factory.mktemp("nssmpin")
    for name, data in (("good", _GOOD), ("bad", _BAD), ("home-good", _GOOD), ("home-bad", _BAD)):
        (root / name).mkdir()
        (root / name / "nssm.exe").write_bytes(data)
    _stand_in(root / "path-good", _GOOD)
    _stand_in(root / "path-bad", _BAD)
    (root / "path-none").mkdir()

    lines = ["& {", "  $ErrorActionPreference = 'Stop'"]
    for script, names in _FUNCTIONS.items():
        lines += [
            f"  $tree = [System.Management.Automation.Language.Parser]::ParseFile("
            f"{_psq(str(_path(script)))}, [ref]$null, [ref]$null)",
            "  foreach ($n in @(" + ", ".join(_psq(n) for n in names) + ")) {",
            "    $fn = $tree.Find({ $args[0] -is "
            "[System.Management.Automation.Language.FunctionDefinitionAst] -and "
            "$args[0].Name -eq $n }, $true)",
            f'    if (-not $fn) {{ throw "not defined in {script}: $n" }}',
            "    . ([scriptblock]::Create($fn.Extent.Text))",
            "  }",
        ]
    lines += [
        _STUBS,
        # The pin is the stand-in's hash, so the positive controls have something to match.
        f"  $NssmExeSha256 = {_psq(_sha(_GOOD))}",
        f"  $root = {_psq(str(root))}",
        f"  $scripts = {_psq(str(_DIR))}",
        "  $res = @{}",
        "  function Invoke-Case([string]$Key, [string]$PathDir, [scriptblock]$Body) {",
        "    $env:PATH = Join-Path $root $PathDir",
        # The throw is turned into output INSIDE the redirection, so a case that warns and then
        # throws keeps its warnings.
        "    $out = @(& { try { & $Body } catch { [pscustomobject]@{ Threw = $_.Exception.Message } } } 3>&1)",
        "    $isWarn = { $_ -is [System.Management.Automation.WarningRecord] }",
        "    $thrown = @($out | Where-Object { $_.PSObject.Properties['Threw'] })",
        "    $warn = @($out | Where-Object $isWarn | ForEach-Object { $_.Message })",
        "    $val = @($out | Where-Object { -not (& $isWarn) -and -not $_.PSObject.Properties['Threw'] } |",
        '      ForEach-Object { "$_" })',
        "    $res[$Key] = @{ threw = [bool]$thrown.Count; value = ($val -join '|'); warnings = $warn;",
        "      error = $(if ($thrown.Count) { $thrown[0].Threw } else { '' }) }",
        "  }",
        "  $good = Join-Path $root 'good/nssm.exe'",
        "  $bad = Join-Path $root 'bad/nssm.exe'",
        _CASES,
        _AST_PROBES,
        "  $res | ConvertTo-Json -Depth 8 -Compress",
        "}",
    ]
    harness = root / f"harness-{uuid.uuid4().hex}.ps1"
    harness.write_text("\n".join(lines), encoding="utf-8")
    proc = subprocess.run(
        ["pwsh", "-NoProfile", "-NonInteractive", "-File", str(harness)],
        capture_output=True,
        text=True,
        timeout=180,
    )
    assert proc.returncode == 0, f"harness failed:\n{(proc.stderr + proc.stdout)[:3000]}"
    parsed = json.loads(proc.stdout.strip().splitlines()[-1])
    assert isinstance(parsed, dict)
    parsed["_root"] = str(root)
    return parsed


def _case(report: dict[str, Any], key: str) -> dict[str, Any]:
    assert key in report, f"CONTROL FAILED: the harness did not run case {key!r}"
    case = report[key]
    assert isinstance(case, dict)
    return case


def _names_both_hashes(message: str) -> None:
    assert _sha(_BAD) in message.upper(), f"the message does not name the actual hash: {message}"
    assert _sha(_GOOD) in message.upper(), f"the message does not name the pinned hash: {message}"


def _from(value: object, directory: str) -> bool:
    """Whether a resolved path is the nssm in ``directory`` (``good``, ``path-good``, ``home-x``)."""
    parent = Path(str(value)).parent
    return parent.parts[-len(Path(directory).parts) :] == Path(directory).parts


# ------------------------------------------------------------------------------------ the check


def test_the_check_passes_a_match_and_names_both_hashes_on_a_mismatch(
    report: dict[str, Any],
) -> None:
    assert _case(report, "pin-good")["value"] == "", "a matching file must pass (positive control)"
    assert _case(report, "pin-good-lower")["value"] == "", (
        "a lower-case expected hash must still match: -HelperSha256 accepts either case"
    )
    _names_both_hashes(str(_case(report, "pin-bad")["value"]))
    missing = str(_case(report, "pin-missing")["value"])
    assert "could not be hashed" in missing, f"an unreadable file must be a mismatch: {missing!r}"


# ------------------------------------------------------------- the engine installer's resolver


def test_the_installer_copies_a_matching_source_into_its_own_folder(report: dict[str, Any]) -> None:
    homes = report["homes"]
    for key, home in (
        ("install-provided-good", "home-provided-good"),
        ("install-path-good", "home-path-good"),
        ("install-home-good", "home-good"),
    ):
        case = _case(report, key)
        assert case["threw"] is False, f"{key} threw: {case['error']}"
        assert _from(case["value"], home), (
            f"{key} returned {case['value']!r}, not the copy in {home}"
        )
        assert homes[home] == _sha(_GOOD), f"{key}: the copy in {home} is not the checked bytes"


def test_the_installer_makes_what_it_creates_administrator_only(report: dict[str, Any]) -> None:
    calls = [str(c) for c in report["icacls"]]
    root = Path(report["_root"])
    for created in (root / "new", root / "new" / "home-provided-good"):
        assert any(
            c.startswith(str(created) + " /inheritance:r") and "*S-1-5-32-544:(OI)(CI)F" in c
            for c in calls
        ), f"the folder it created, {created}, was not given an administrator-only ACL: {calls}"
    copied = root / "new" / "home-provided-good" / "nssm.exe"
    assert f"{copied} /setowner *S-1-5-32-544" in calls, "the file it copied in keeps its creator"
    # CONTROL: a folder that already existed is the operator's, and is left alone.
    assert not any(c.startswith(str(root / "home-good") + " ") for c in calls), (
        "an existing folder's ACL was rewritten"
    )


def test_the_installer_refuses_a_named_or_installed_copy_that_does_not_match(
    report: dict[str, Any],
) -> None:
    homes = report["homes"]
    for key, needle in (
        ("install-provided-bad", "-NssmPath"),
        ("install-home-bad", "installed"),
        ("install-home-good-provided-bad", "-NssmPath"),
    ):
        case = _case(report, key)
        assert case["threw"] is True, f"{key}: a copy that fails the check must be refused"
        assert needle in str(case["error"]), f"{key}: {case['error']}"
        _names_both_hashes(str(case["error"]))
    assert homes["home-provided-bad"] == "", "a refused -NssmPath copy was still copied in"
    assert homes["home-bad"] == _sha(_BAD), "CONTROL FAILED: the tampered installed copy is gone"


def test_the_installer_skips_a_path_copy_that_does_not_match(report: dict[str, Any]) -> None:
    case = _case(report, "install-path-bad")
    # It went on to the download, which the stub refuses: proof the PATH copy was not used.
    assert case["threw"] is True and "NETWORK TOUCHED" in str(case["error"]), case
    warnings = case["warnings"]
    assert isinstance(warnings, list) and len(warnings) == 1, warnings
    assert "PATH" in warnings[0] and "-NssmPath" in warnings[0], warnings[0]
    _names_both_hashes(warnings[0])
    assert report["homes"]["home-path-bad"] == "", "the mismatched PATH copy was copied in"


@pytest.mark.parametrize(
    ("key", "home", "who"),
    [
        ("install-broad-folder", "home-broad", "BUILTIN\\Users (Write)"),
        ("install-broad-parent", "home-under-broad", "DeleteSubdirectoriesAndFiles"),
        ("install-broad-file", "home-good", "DOMAIN\\op"),
    ],
)
def test_the_installer_refuses_a_copy_others_can_replace(
    report: dict[str, Any], key: str, home: str, who: str
) -> None:
    """The folder, a folder above it, and the file itself each count."""
    case = _case(report, key)
    assert case["threw"] is True and "not administrator-only" in str(case["error"]), case
    assert who in str(case["error"]), "the refusal must name who can write there"
    if key != "install-broad-file":
        assert report["homes"][home] == "", "nssm.exe was copied in where others can write"


# ------------------------------------------------------------------------ the registration


def test_the_registration_must_start_the_checked_copy_quoted(report: dict[str, Any]) -> None:
    for key in ("image-quoted", "image-quoted-args"):
        assert _case(report, key)["value"] == "", f"positive control {key}: {_case(report, key)}"
    # Unquoted with a space is CWE-428: the SCM would try C:\Program.exe first.
    for key in ("image-unquoted", "image-other", "image-longer-name", "image-missing"):
        problem = str(_case(report, key)["value"])
        assert "is registered to start" in problem, f"{key} was accepted: {problem!r}"


def test_the_registration_is_pointed_at_the_checked_copy(report: dict[str, Any]) -> None:
    img = r"C:\Program Files\MessageFoundry\nssm\nssm.exe"
    fixed = _case(report, "set-unquoted")
    assert fixed["threw"] is False, fixed
    assert fixed["value"] == f'1|"{img}"', f"the unquoted registration was not quoted: {fixed}"
    same = _case(report, "set-already")
    assert same["threw"] is False and same["value"] == "0", f"a correct one was changed: {same}"
    refused = _case(report, "set-refused")
    assert refused["threw"] is True and "returned 2" in str(refused["error"]), refused
    lied = _case(report, "set-not-applied")
    assert lied["threw"] is True and "reported success" in str(lied["error"]), (
        f"a change that did not stick passed as done: {lied}"
    )


_PLANTED = "synthetic-pw-1573"


def test_the_run_as_account_is_set_through_the_scm(report: dict[str, Any]) -> None:
    """NSSM 2.24 refuses a virtual account (exit 6, CI run 36590581708), so the SCM sets it.

    The password argument follows ChangeServiceConfig: none at all for a virtual or managed account,
    an empty string for LocalSystem, the real one only where one was given.
    """
    virtual = _case(report, "acct-virtual")
    assert virtual["threw"] is False, virtual
    assert virtual["value"] == "stored=NT SERVICE\\Svc|keys=StartName;pw=", (
        f"a virtual account must be sent with no StartPassword at all: {virtual['value']}"
    )
    local = _case(report, "acct-localsystem")
    assert local["value"] == "stored=LocalSystem|keys=StartName,StartPassword;pw=", local
    given = _case(report, "acct-password")
    assert given["threw"] is False, given
    assert given["value"] == f"stored=DOMAIN\\svc|keys=StartName,StartPassword;pw={_PLANTED}", given
    lied = _case(report, "acct-not-applied")
    assert lied["threw"] is True and "although" in str(lied["error"]), lied
    nopw = _case(report, "acct-throws-nopw")
    assert nopw["threw"] is True and "provider failed" in str(nopw["error"]), (
        "with no password in play, the provider's own error is the useful part of the message"
    )
    # A failure disables the service; a success leaves it alone (the control).
    for key in ("acct-refused", "acct-throws", "acct-throws-nopw", "acct-not-applied"):
        assert report[f"{key}-disabled"] == ["Svc=Disabled"], (
            f"{key} left the service able to start"
        )
    for key in ("acct-virtual", "acct-localsystem", "acct-password"):
        assert report[f"{key}-disabled"] == [], f"{key} disabled a service it set correctly"


def test_a_bare_account_name_is_canonicalised(report: dict[str, Any]) -> None:
    """`nssm set ObjectName` turned a bare name into DOMAIN\\user; the SCM route must too."""
    case = _case(report, "acct-canonical")
    assert case["threw"] is False, case
    stored = str(case["value"]).split("|", 1)[0].removeprefix("stored=")
    if sys.platform == "win32":
        assert "\\" in stored, f"a bare local user name was sent as it was typed: {stored!r}"
    else:
        # No SAM to translate against; the name goes through as given, and nothing throws.
        assert "\\" not in stored, stored


def test_no_run_as_failure_message_carries_the_password(report: dict[str, Any]) -> None:
    """BACKLOG #1573, carried to the new call: a refusal and a throwing provider, both with a password."""
    refused = _case(report, "acct-refused")
    assert refused["threw"] is True and "returned 2" in str(refused["error"]), refused
    thrown = _case(report, "acct-throws")
    assert thrown["threw"] is True, thrown
    for case in (refused, thrown):
        assert _PLANTED not in str(case["error"]) and _PLANTED not in str(case["warnings"]), (
            f"the password reached a message: {case}"
        )


def test_the_helper_installer_refuses_every_copy_that_does_not_match(
    report: dict[str, Any],
) -> None:
    assert _from(_case(report, "helper-provided-good")["value"], "good"), "positive control"
    assert _from(_case(report, "helper-path-good")["value"], "path-good"), "positive control"
    for key in ("helper-provided-bad", "helper-path-bad"):
        case = _case(report, key)
        assert case["threw"] is True, f"{key}: a copy that fails the check must be refused"
        _names_both_hashes(str(case["error"]))
    none = _case(report, "helper-none")
    assert none["threw"] is True and "not found" in str(none["error"])


# ------------------------------------------------------------------ the top levels, in order


def _script(report: dict[str, Any], script: str) -> dict[str, Any]:
    facts = report["ast"][script]
    assert isinstance(facts, dict) and facts["commands"], (
        f"CONTROL FAILED: nothing read from {script}"
    )
    return facts


def _at(entries: list[dict[str, Any]], predicate: Callable[[dict[str, Any]], bool]) -> list[int]:
    hits = [int(e["offset"]) for e in entries if predicate(e)]
    assert hits, "CONTROL FAILED: the command this ordering check is aimed at is gone"
    return hits


def _named(name: str, *needles: str) -> Callable[[dict[str, Any]], bool]:
    return lambda c: c.get("name") == name and all(n in str(c["text"]) for n in needles)


def _top_level(facts: dict[str, Any]) -> Callable[[dict[str, Any]], bool]:
    """Outside every function body: the script's own statements."""
    spans = [(int(f["start"]), int(f["end"])) for f in facts["functions"]]
    return lambda c: not any(s <= int(c["offset"]) < e for s, e in spans)


def test_helper_sha256_is_required_and_must_be_a_sha256(report: dict[str, Any]) -> None:
    row = report["ast"]["helper-param"]
    assert row["declared"], "install-net-helper.ps1 no longer declares -HelperSha256"
    assert row["mandatory"], (
        "-HelperSha256 is not mandatory. A default or an optional check would start an unchecked "
        "binary as LocalSystem whenever the operator left it out."
    )
    assert row["hex"] is True, "positive control: a 64-hex value must bind"
    assert row["short"] is False and row["nonhex"] is False, (
        "-HelperSha256 accepts a value that is not a SHA-256, so a typo would reach the compare"
    )


def test_the_helper_binary_is_checked_before_anything_is_stopped(report: dict[str, Any]) -> None:
    commands = _script(report, "install-net-helper.ps1")["commands"]
    check = min(_at(commands, _named("Get-FilePinProblem", "$SourceExe", "$HelperSha256")))
    assert check < min(_at(commands, _named("Stop-Service"))), (
        "mefor-net-helper.exe is checked against -HelperSha256 only after the running helper is "
        "stopped. A wrong binary should cost a message, not a stopped helper."
    )
    assert check < min(_at(commands, _named("Copy-Item"))), "the check comes after the copy"


def test_the_helper_installer_checks_both_installed_copies(report: dict[str, Any]) -> None:
    facts = _script(report, "install-net-helper.ps1")
    commands = facts["commands"]
    last_copy = max(_at(commands, _named("Copy-Item")))
    first_nssm = min(_at(commands, _named("Invoke-HelperNssm")))
    for needles in (("$TargetExe", "$HelperSha256"), ("$TargetNssm", "$NssmExeSha256")):
        for at in _at(commands, _named("Get-FilePinProblem", *needles)):
            assert last_copy < at < first_nssm, (
                f"the installed copy {needles} is not checked between the last copy and the first "
                "nssm call, so the file the SCM starts as SYSTEM is not the file checked"
            )
    # A rejected copy is deleted, both binaries, and a failed deletion disables the registration.
    assert _at(commands, _named("Remove-Item", "$TargetExe", "$TargetNssm"))
    assert _at(commands, _named("Set-Service", "Disabled"))


def test_the_helper_installer_points_the_registration_before_the_start(
    report: dict[str, Any],
) -> None:
    commands = _script(report, "install-net-helper.ps1")["commands"]
    point = min(_at(commands, _named("Set-ServiceImage", "$TargetNssm")))
    last_set = max(_at(commands, _named("Invoke-HelperNssm", " set ")))
    start = min(_at(commands, _named("Invoke-HelperNssm", " start ")))
    assert last_set < point < start, "the registration is not read back before the helper starts"


def test_the_engine_installer_points_the_registration_before_configuring(
    report: dict[str, Any],
) -> None:
    facts = _script(report, "install-service.ps1")
    commands = facts["commands"]
    top = _top_level(facts)
    resolved = min(_at(commands, _named("Resolve-Nssm")))
    uses = _at(
        commands,
        lambda c: top(c) and c.get("name") in ("Invoke-Nssm", "Stop-ServiceAndConfirm"),
    )
    assert resolved < min(uses), "an nssm.exe runs before the checked copy is resolved"
    point = min(_at(commands, _named("Set-ServiceImage", "$NssmPath")))
    install = min(_at(commands, _named("Invoke-Nssm", "install $ServiceName")))
    first_set = min(_at(commands, _named("Invoke-Nssm", "set $ServiceName")))
    assert install < point < first_set, (
        "the registration is not pointed at the checked copy between the install and the first set"
    )
    assert _at(commands, _named("Set-Service", "Disabled")), (
        "a registration that could not be pointed at the checked copy is left able to start"
    )


@pytest.mark.parametrize("script", _WITH_BLOCK)
def test_no_installer_sets_the_account_through_nssm(report: dict[str, Any], script: str) -> None:
    commands = _script(report, script)["commands"]
    through_nssm = [
        c
        for c in commands
        if c.get("name") in ("Invoke-Nssm", "Invoke-HelperNssm") and "ObjectName" in str(c["text"])
    ]
    assert not through_nssm, f"{script} still runs `nssm set ObjectName`: {through_nssm}"
    assert _at(commands, _named("Set-ServiceAccount")), f"CONTROL FAILED: {script} sets no account"


@pytest.mark.parametrize("script", _WITHOUT_NSSM)
def test_the_uninstallers_run_no_nssm(report: dict[str, Any], script: str) -> None:
    facts = _script(report, script)
    assert "NssmPath" not in facts["params"], f"{script} still takes an nssm.exe to run"
    top = _top_level(facts)
    for c in facts["commands"]:
        first = str(c["first"])
        assert not (top(c) and first.startswith("$") and "nssm" in first.lower()), (
            f"{script} runs {first} at its top level: {c['text']!r}"
        )
    assert _at(facts["commands"], _named("sc.exe", "delete $ServiceName")), (
        f"CONTROL FAILED: {script} no longer removes the service with sc.exe"
    )
    if script == "uninstall-service.ps1":
        assert _at(facts["commands"], _named("Stop-ServiceAndConfirm", '-NssmPath ""')), (
            "uninstall-service.ps1 no longer stops the service through the SCM"
        )
