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
6. **The other runs of nssm use the copy the installer checked (#2442).** ``measure-store-access.ps1``
   and the CI workflows used to run whatever ``nssm`` was on ``PATH``, as administrator. On a hosted
   runner that is the Chocolatey copy the installer itself refuses on its hash. Both now run the
   ``nssm.exe`` in the ``-NssmDir`` they hand the installer.

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

import functools
import hashlib
import json
import re
import shutil
import stat
import subprocess
import sys
import uuid
import zipfile
from collections.abc import Callable
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
# install-service.ps1's top-level download settings, which the harness runs as written (#2504).
_DOWNLOAD_VARS = ("NssmUrl", "NssmMirrorUrls", "NssmSha256")

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
  # The network is refused unless a case serves a URL: $webFiles maps a URL to the file it returns,
  # $webErrors to the message it fails with. Every URL asked for is recorded, in order.
  $webFiles = @{}
  $webErrors = @{}
  $webCalls = [Collections.Generic.List[string]]::new()
  function Invoke-WebRequest {
    param($Uri, $OutFile, [switch]$UseBasicParsing)
    $webCalls.Add("$Uri")
    if ($webErrors.ContainsKey("$Uri")) { throw $webErrors["$Uri"] }
    if (-not $webFiles.ContainsKey("$Uri")) { throw 'NETWORK TOUCHED' }
    Copy-Item -LiteralPath $webFiles["$Uri"] -Destination $OutFile -Force
  }
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
  # The real download sources, in the order Save-PinnedNssm tries them.
  $res['sources'] = @(@($NssmUrl) + @($NssmMirrorUrls))
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
  $webCalls.Clear()
  Invoke-Case 'install-path-bad' 'path-bad' {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-path-bad') }
  $res['install-path-bad-calls'] = @($webCalls)
  $env:TEMP = $savedTemp; $env:TMP = $savedTmp
  # --- install-service.ps1 Save-PinnedNssm: the primary, then each mirror (#2504). Stand-in URLs and
  # a stand-in archive pin, so each case says exactly which source serves what.
  $primary = 'https://primary.invalid/nssm-2.24.zip'
  $mirrorA = 'https://mirror-a.invalid/nssm-2.24.zip'
  $mirrorB = 'https://mirror-b.invalid/nssm-2.24.zip'
  function Invoke-DownloadCase([string]$Key, [hashtable]$Files, [hashtable]$Errors, [scriptblock]$Action) {
    $webFiles = $Files; $webErrors = $Errors; $webCalls.Clear()
    $NssmUrl = $primary; $NssmMirrorUrls = @($mirrorA, $mirrorB); $NssmSha256 = $zipGoodSha
    $dest = Join-Path $root "dl-$Key/nssm.exe"
    New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dest) | Out-Null
    if (-not $Action) { $Action = { Save-PinnedNssm -Destination $dest } }
    Invoke-Case $Key 'path-none' $Action
    $res["$Key-calls"] = @($webCalls)
    $res["$Key-written"] = $(if (Test-Path -LiteralPath $dest) {
      (Get-FileHash -Algorithm SHA256 -LiteralPath $dest).Hash } else { '' })
  }
  $down = '(503) Server Unavailable'
  Invoke-DownloadCase 'dl-primary-good' @{ $primary = $zipGood } @{}
  Invoke-DownloadCase 'dl-primary-down' @{ $mirrorA = $zipGood } @{ $primary = $down }
  Invoke-DownloadCase 'dl-primary-tampered' @{ $primary = $zipBad; $mirrorA = $zipGood } @{}
  Invoke-DownloadCase 'dl-second-mirror' @{ $mirrorB = $zipGood } @{
    $primary = $down; $mirrorA = 'The operation has timed out.' }
  Invoke-DownloadCase 'dl-mirrors-tampered' @{ $mirrorA = $zipBad; $mirrorB = $zipBad } @{
    $primary = $down }
  Invoke-DownloadCase 'dl-all-down' @{} @{ $primary = $down; $mirrorA = $down; $mirrorB = $down }
  # The same, end to end through the resolver: what reaches -NssmDir.
  Invoke-DownloadCase 'install-download-mirror' @{ $mirrorA = $zipGood } @{ $primary = $down } {
    Resolve-Nssm -NssmDir (Join-Path $root 'home-download-mirror') }
  Invoke-DownloadCase 'install-download-tampered' @{ $mirrorA = $zipBad; $mirrorB = $zipBad } @{
    $primary = $down } { Resolve-Nssm -NssmDir (Join-Path $root 'home-download-tampered') }
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
  # The bare name comes from [Environment]::UserName, which asks the OS, NOT from $env:USERNAME: Linux
  # pwsh does not set that variable, and CI run 36610203607 went red on ubuntu when this case handed
  # Set-ServiceAccount an empty name. USERNAME is cleared around the case so that the variable
  # creeping back in fails on every host, not only on Linux.
  $savedUser = $env:USERNAME; $env:USERNAME = $null
  $bareName = [Environment]::UserName
  Invoke-AccountCase 'acct-canonical' { Set-ServiceAccount -ServiceName 'Svc' -Account $bareName }
  $env:USERNAME = $savedUser
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
                      'uninstall-net-helper.ps1', 'measure-store-access.ps1')) {
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
    if ($name -eq 'measure-store-access.ps1') {
      $ast[$name]['assigns'] = @($tree.FindAll({
          $args[0] -is [System.Management.Automation.Language.AssignmentStatementAst] }, $true) |
        ForEach-Object { @{ left = $_.Left.Extent.Text; right = $_.Right.Extent.Text } })
      # Every literal argument of every command, unquoted, so `Start-Process nssm` or `cmd /c nssm`
      # is seen wherever the name sits, not only in command position.
      $ast[$name]['words'] = @($tree.FindAll({
          $args[0] -is [System.Management.Automation.Language.CommandAst] }, $true) |
        ForEach-Object {
          $cmd = $_
          $cmd.CommandElements | Where-Object {
            $_ -is [System.Management.Automation.Language.StringConstantExpressionAst] -or
            $_ -is [System.Management.Automation.Language.ExpandableStringExpressionAst] } |
          ForEach-Object { @{ value = $_.Value; text = $cmd.Extent.Text } } })
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


def _archive(path: Path, win64: bytes) -> Path:
    """A stand-in NSSM release archive. Its win32 copy is always the planted bytes, so a download
    that took the wrong architecture's nssm.exe would fail the binary pin."""
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("nssm-2.24/win32/nssm.exe", _BAD)
        zf.writestr("nssm-2.24/win64/nssm.exe", win64)
    return path


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
    zip_good = _archive(root / "archive-good.zip", _GOOD)
    zip_bad = _archive(root / "archive-bad.zip", _BAD)

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
    # The download sources and the archive pin, run from install-service.ps1's own top-level
    # assignments, so a case that refuses the network sees the real list.
    lines += [
        "  $tree = [System.Management.Automation.Language.Parser]::ParseFile("
        f"{_psq(str(_path('install-service.ps1')))}, [ref]$null, [ref]$null)",
        "  foreach ($v in @(" + ", ".join(_psq(v) for v in _DOWNLOAD_VARS) + ")) {",
        "    $a = @($tree.EndBlock.Statements | Where-Object {",
        "      $_ -is [System.Management.Automation.Language.AssignmentStatementAst] -and",
        "      $_.Left.VariablePath.UserPath -eq $v })",
        '    if ($a.Count -ne 1) { throw "install-service.ps1 must assign $v once at top level" }',
        "    . ([scriptblock]::Create($a[0].Extent.Text))",
        "  }",
    ]
    lines += [
        _STUBS,
        # The pin is the stand-in's hash, so the positive controls have something to match.
        f"  $NssmExeSha256 = {_psq(_sha(_GOOD))}",
        f"  $zipGood = {_psq(str(zip_good))}",
        f"  $zipBad = {_psq(str(zip_bad))}",
        f"  $zipGoodSha = {_psq(_sha(zip_good.read_bytes()))}",
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
    assert isinstance(warnings, list), warnings
    # The download warns once per source it could not use; those are counted in the next test.
    on_path = [w for w in warnings if "Not using the nssm on PATH" in w]
    assert len(on_path) == 1, warnings
    assert "-NssmPath" in on_path[0], on_path[0]
    _names_both_hashes(on_path[0])
    assert report["homes"]["home-path-bad"] == "", "the mismatched PATH copy was copied in"


# ------------------------------------------------------------- the download and its mirrors (#2504)


def test_the_real_sources_are_https_with_nssm_cc_first_and_a_mirror_elsewhere(
    report: dict[str, Any],
) -> None:
    sources = report["sources"]
    assert isinstance(sources, list) and len(sources) >= 2, (
        f"install-service.ps1 should try nssm.cc and at least one mirror, so an nssm.cc outage does "
        f"not stop an install: {sources}"
    )
    assert all(isinstance(s, str) and s.startswith("https://") for s in sources), sources
    assert urlsplit(sources[0]).hostname == "nssm.cc", f"nssm.cc must be tried first: {sources}"
    assert len(set(sources)) == len(sources), f"a source is listed twice: {sources}"
    assert any(urlsplit(s).hostname != "nssm.cc" for s in sources[1:]), (
        f"every fallback is on nssm.cc, so an nssm.cc outage still stops an install: {sources}"
    )
    # With the network refused, every real source was asked, in order, and each failure warned.
    assert report["install-path-bad-calls"] == sources, report["install-path-bad-calls"]
    case = _case(report, "install-path-bad")
    for url in sources:
        assert url in str(case["error"]), f"the final refusal does not name {url}: {case['error']}"
        assert any(url in w for w in case["warnings"]), f"no warning names {url}"


_PRIMARY = "https://primary.invalid/nssm-2.24.zip"
_MIRROR_A = "https://mirror-a.invalid/nssm-2.24.zip"
_MIRROR_B = "https://mirror-b.invalid/nssm-2.24.zip"


@pytest.mark.parametrize(
    ("key", "calls"),
    [
        ("dl-primary-good", [_PRIMARY]),
        ("dl-primary-down", [_PRIMARY, _MIRROR_A]),
        ("dl-primary-tampered", [_PRIMARY, _MIRROR_A]),
        ("dl-second-mirror", [_PRIMARY, _MIRROR_A, _MIRROR_B]),
    ],
)
def test_the_first_source_that_matches_the_archive_pin_is_used(
    report: dict[str, Any], key: str, calls: list[str]
) -> None:
    """Positive controls: a source that is down, or serves other bytes, is skipped, and the search
    stops at the first archive that matches. The win64 copy is taken, not the win32 one."""
    case = _case(report, key)
    assert case["threw"] is False, case
    assert report[f"{key}-calls"] == calls, report[f"{key}-calls"]
    assert report[f"{key}-written"] == _sha(_GOOD), (
        f"{key}: the nssm.exe written is not the win64 copy from the matching archive"
    )
    assert len(case["warnings"]) == len(calls) - 1, case["warnings"]


def test_a_mirror_that_fails_the_archive_pin_is_refused(report: dict[str, Any]) -> None:
    case = _case(report, "dl-mirrors-tampered")
    assert case["threw"] is True, "an archive that fails the pin was accepted"
    assert report["dl-mirrors-tampered-calls"] == [_PRIMARY, _MIRROR_A, _MIRROR_B]
    assert report["dl-mirrors-tampered-written"] == "", "a refused archive's nssm.exe was written"
    error = str(case["error"])
    assert "every source" in error, error
    zip_bad = Path(str(report["_root"])) / "archive-bad.zip"
    zip_good = Path(str(report["_root"])) / "archive-good.zip"
    assert _sha(zip_bad.read_bytes()) in error.upper(), (
        f"the refusal does not name the hash: {error}"
    )
    assert _sha(zip_good.read_bytes()) in error.upper(), (
        f"the refusal does not name the pin: {error}"
    )
    assert "(503)" in error, f"the refusal does not say why the primary failed: {error}"


def test_no_source_reachable_writes_nothing_and_names_the_offline_route(
    report: dict[str, Any],
) -> None:
    case = _case(report, "dl-all-down")
    assert case["threw"] is True, case
    assert report["dl-all-down-calls"] == [_PRIMARY, _MIRROR_A, _MIRROR_B]
    assert report["dl-all-down-written"] == ""
    assert "-NssmPath" in str(case["error"]), case["error"]


def test_the_resolver_installs_from_a_mirror_and_refuses_a_tampered_one(
    report: dict[str, Any],
) -> None:
    good = _case(report, "install-download-mirror")
    assert good["threw"] is False, good
    assert _from(good["value"], "home-download-mirror"), good["value"]
    assert report["homes"]["home-download-mirror"] == _sha(_GOOD)
    bad = _case(report, "install-download-tampered")
    assert bad["threw"] is True and "every source" in str(bad["error"]), bad
    assert report["homes"]["home-download-tampered"] == "", "a tampered mirror reached -NssmDir"


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
    nssm_calls = [c for c in commands if c.get("name") in ("Invoke-Nssm", "Invoke-HelperNssm")]
    assert len(nssm_calls) >= 1, (
        f"CONTROL FAILED: {script} runs no nssm wrapper, so none is checked"
    )
    through_nssm = [c for c in nssm_calls if "ObjectName" in str(c["text"])]
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


# ------------------------------------------------- the runs of nssm outside the installers (#2442)

_MEASURE = "measure-store-access.ps1"
_SMOKE_JOB = "windows-service-smoke"
# The folder the smoke job hands install-service.ps1, and so the only nssm.exe it may run.
_SMOKE_DIR_VAR = "SMOKE_NSSM_DIR"
_CHECKED_PATH = '"$env:' + _SMOKE_DIR_VAR + '\\nssm.exe"'
_CHECKED_CALL = re.compile(re.escape(_CHECKED_PATH) + r"\s+(\w+)\s+MessageFoundry\b")
# The word nssm or nssm.exe, in any case. It does not match inside -NssmDir or SMOKE_NSSM_DIR.
_ANY_NSSM = re.compile(r"\bnssm(?:\.exe)?\b", re.I)
# A literal argument that is nssm, nssm.exe, or a path ending in either.
_NSSM_WORD = re.compile(r"(?:^|[\\/])nssm(?:\.exe)?$", re.I)
# Commands that look an nssm up, bind one to a variable, or run one from a string.
_LOOKUPS = {
    "get-command",
    "gcm",
    "where",
    "where.exe",
    "set-variable",
    "sv",
    "new-variable",
    "invoke-expression",
    "iex",
}
# $Nssm on the left of an assignment, in any case, scope, cast or brace spelling.
_NSSM_TARGET = re.compile(r"\$\{?(?:\w+:)?nssm\}?\s*$", re.I)


def _script_named(name: str, text: str) -> bool:
    """Whether ``text`` names the script ``name`` in any path spelling. uninstall-* is not install-*."""
    return re.search(r"(?<![\w-])" + re.escape(name), text, re.I) is not None


# A run step re-pointing the folder, in its own shell or for later steps through GITHUB_ENV.
_REPOINT = re.compile(_SMOKE_DIR_VAR + r"\s*=", re.I)


def _runs_unchecked_nssm(script: str) -> list[str]:
    """The lines of a workflow ``run:`` script that name an nssm other than the checked copy.

    Deliberately wider than "runs it": outside a line that starts as a comment, any mention of
    nssm but the checked path counts, so a quoted name, a literal path, ``Start-Process`` or
    ``cmd /c`` cannot slip past. So does a line that sets the checked folder's variable. A trailing
    comment that mentions nssm is reported too; that errs toward a false red.
    """
    return [
        line.strip()
        for line in script.splitlines()
        if not line.lstrip().startswith("#")
        and (_ANY_NSSM.search(line.replace(_CHECKED_PATH, "")) or _REPOINT.search(line))
    ]


def test_the_store_access_measurement_runs_only_the_installers_checked_nssm(
    report: dict[str, Any],
) -> None:
    facts = _script(report, _MEASURE)
    commands = facts["commands"]
    assert "NssmDir" in facts["params"], (
        f"{_MEASURE} takes no -NssmDir, so it cannot name the folder whose nssm.exe the installer "
        "checks"
    )
    # Compared lower-cased throughout: PowerShell variable names ignore case.
    unchecked = [
        str(c["text"])
        for c in commands
        if (str(c["first"]).lower() != "$nssm" and _ANY_NSSM.search(str(c["first"])))
        or (str(c.get("name")).lower() in _LOOKUPS and _ANY_NSSM.search(str(c["text"])))
    ] + [
        str(w["text"])
        for w in facts["words"]
        if _NSSM_WORD.search(str(w["value"]))
        and not str(w["text"]).lower().startswith("join-path $nssmdir")
    ]
    assert not unchecked, (
        f"{_MEASURE} runs, or looks up, an nssm other than the checked $Nssm: {unchecked}"
    )
    targets = [a for a in facts["assigns"] if _NSSM_TARGET.search(str(a["left"]))]
    assert len(targets) == 1, (
        f"$Nssm must be assigned once, to the nssm.exe in -NssmDir; it is assigned {targets}"
    )
    source = str(targets[0]["right"])
    assert "$NssmDir" in source and "nssm.exe" in source, (
        f"$Nssm must be the nssm.exe in -NssmDir and nothing else; it is assigned {source}"
    )
    runs = [
        c for c in commands if str(c["first"]).startswith("$") and "nssm" in str(c["first"]).lower()
    ]
    assert runs, f"CONTROL FAILED: {_MEASURE} no longer runs nssm at all"
    assert {str(c["first"]).lower() for c in runs} == {"$nssm"}, (
        f"{_MEASURE} runs an nssm held in another variable: {[c['text'] for c in runs]}"
    )
    installs = [c for c in commands if _script_named("install-service.ps1", str(c["first"]))]
    assert installs, f"CONTROL FAILED: {_MEASURE} no longer runs install-service.ps1"
    assert all("-NssmDir $NssmDir" in str(c["text"]) for c in installs), (
        f"{_MEASURE} does not hand the installer -NssmDir $NssmDir, so the installer checks a copy "
        "in one folder while this script runs the one in another"
    )


@pytest.mark.parametrize(
    "line",
    [
        "nssm stop MessageFoundry",
        "  nssm set MessageFoundry AppEnvironmentExtra `",
        "& nssm start MessageFoundry",
        "if ($up) { nssm.exe stop MessageFoundry }",
        "$n = (Get-Command nssm).Source",
        "$s = nssm status MessageFoundry",
        '& "nssm" stop MessageFoundry',
        "& 'nssm.exe' stop MessageFoundry",
        "Start-Process nssm -ArgumentList 'stop', 'MessageFoundry'",
        "cmd /c nssm stop MessageFoundry",
        "gcm NSSM",
        '& "C:\\ProgramData\\chocolatey\\bin\\nssm.exe" stop MessageFoundry',
        '& "$env:SMOKE_NSSM_DIR\\nssm.exe" stop MessageFoundry; nssm start MessageFoundry',
        "$env:SMOKE_NSSM_DIR = 'C:\\ProgramData\\chocolatey\\bin'",
        '"SMOKE_NSSM_DIR=C:\\ProgramData\\chocolatey\\bin" >> $env:GITHUB_ENV',
    ],
)
def test_the_unchecked_nssm_detector_fires(line: str) -> None:
    assert _runs_unchecked_nssm(line) == [line.strip()]


@pytest.mark.parametrize(
    "line",
    [
        '& "$env:SMOKE_NSSM_DIR\\nssm.exe" stop MessageFoundry',
        "# nssm start MessageFoundry",
        ".\\scripts\\service\\install-service.ps1 -NssmDir $env:SMOKE_NSSM_DIR",
        "Get-Service MessageFoundry",
    ],
)
def test_the_unchecked_nssm_detector_ignores_the_checked_copy_and_comments(line: str) -> None:
    assert _runs_unchecked_nssm(line) == []


@functools.cache
def _jobs(workflow: str) -> dict[str, dict[str, Any]]:
    # Imported here, not at module scope: a venv without PyYAML turns that module's import into a
    # skip, which at module scope would skip every installer test above along with these two.
    from tests._workflow_contexts import jobs_of

    return jobs_of(workflow)


def _steps(job: dict[str, Any]) -> list[dict[str, Any]]:
    return [s for s in job.get("steps") or [] if isinstance(s, dict)]


def _run_scripts(job: dict[str, Any]) -> list[str]:
    return [s["run"] for s in _steps(job) if isinstance(s.get("run"), str)]


def test_no_workflow_names_an_unchecked_nssm() -> None:
    from tests._workflow_contexts import WORKFLOWS

    runs = [
        (path.name, job_id, script)
        for path in sorted(WORKFLOWS.glob("*.y*ml"))
        for job_id, job in _jobs(path.name).items()
        for script in _run_scripts(job)
    ]
    assert runs, f"CONTROL FAILED: no workflow run: step was read under {WORKFLOWS}"
    assert any(job_id == _SMOKE_JOB for _, job_id, _ in runs), (
        f"CONTROL FAILED: the {_SMOKE_JOB} job was not read under {WORKFLOWS}"
    )
    offenders = [
        f"{name} {job_id}: {line}"
        for name, job_id, script in runs
        for line in _runs_unchecked_nssm(script)
    ]
    assert not offenders, (
        "a workflow runs an nssm other than the checked copy. On a hosted runner the one on PATH "
        f"is the Chocolatey copy the installer refuses on its hash: {offenders}"
    )


def test_the_service_smoke_runs_the_copy_it_had_the_installer_check() -> None:
    job = _jobs("ci.yml").get(_SMOKE_JOB)
    assert job, f"CONTROL FAILED: ci.yml has no {_SMOKE_JOB} job"
    assert (job.get("env") or {}).get(_SMOKE_DIR_VAR), (
        f"the {_SMOKE_JOB} job does not set {_SMOKE_DIR_VAR}"
    )
    overridden = [s.get("name") for s in _steps(job) if _SMOKE_DIR_VAR in (s.get("env") or {})]
    assert not overridden, (
        f"a step overrides {_SMOKE_DIR_VAR}, so it runs an nssm.exe from a folder the installer "
        f"never checked: {overridden}"
    )
    scripts = _run_scripts(job)
    handed = "-NssmDir $env:" + _SMOKE_DIR_VAR
    for script_name in ("install-service.ps1", _MEASURE):
        calls = [
            line
            for script in scripts
            for line in script.splitlines()
            if _script_named(script_name, line) and not line.lstrip().startswith("#")
        ]
        assert calls, f"CONTROL FAILED: the {_SMOKE_JOB} job no longer runs {script_name}"
        assert all(handed in line for line in calls), (
            f"a {script_name} run in {_SMOKE_JOB} does not pass {handed}, so it checks or runs an "
            f"nssm.exe in some other folder: {calls}"
        )
    verbs = {m.group(1) for script in scripts for m in _CHECKED_CALL.finditer(script)}
    assert verbs >= {"set", "start", "stop"}, (
        f"{_SMOKE_JOB} should set, start and stop the service through the checked copy; it does "
        f"{sorted(verbs)}"
    )


_CACHED_VAR = "SMOKE_NSSM_CACHED_EXE"
_SHA_PINNED = re.compile(r"^actions/cache/(restore|save)@[0-9a-f]{40}$")


def test_the_service_smoke_caches_nssm_only_through_the_installers_check() -> None:
    """A warm cache spares the smoke the NSSM download, and nssm.cc with it (#2504).

    The cached file reaches the service only as ``-NssmPath``, which the installer refuses unless it
    matches the pin. The key is the pin, read from the installer, so a new pin is a new key. The copy
    saved is the one the installer checked, and a merge-queue run saves nothing it could not share.
    """
    job = _jobs("ci.yml").get(_SMOKE_JOB)
    assert job, f"CONTROL FAILED: ci.yml has no {_SMOKE_JOB} job"
    assert (job.get("env") or {}).get(_CACHED_VAR), f"{_SMOKE_JOB} does not set {_CACHED_VAR}"
    steps = _steps(job)
    names = [str(s.get("name")) for s in steps]

    def index(predicate: Callable[[dict[str, Any]], bool], what: str) -> int:
        found = [i for i, s in enumerate(steps) if predicate(s)]
        assert len(found) == 1, f"{_SMOKE_JOB} should have exactly one {what} step: {names}"
        return found[0]

    def uses(kind: str) -> Callable[[dict[str, Any]], bool]:
        return lambda s: str(s.get("uses", "")).startswith(f"actions/cache/{kind}@")

    pin = index(lambda s: s.get("id") == "nssm-pin", "pin-reading")
    restore = index(uses("restore"), "cache restore")
    save = index(uses("save"), "cache save")
    install = index(
        lambda s: any(
            _script_named("install-service.ps1", line) and not line.lstrip().startswith("#")
            for line in str(s.get("run", "")).splitlines()
        ),
        "install-service.ps1",
    )
    assert pin < restore < install < save, f"the cache steps are out of order: {names}"
    assert "$NssmExeSha256" in str(steps[pin].get("run")), "the cache key is not read from the pin"

    for i in (restore, save):
        step = steps[i]
        assert _SHA_PINNED.match(str(step["uses"])), f"not pinned by commit SHA: {step['uses']}"
        with_ = step.get("with") or {}
        assert with_.get("path") == "${{ env." + _CACHED_VAR + " }}", with_
        assert "steps.nssm-pin.outputs.pin" in str(with_.get("key")), with_
        assert "restore-keys" not in with_, "a partial key match would restore some other binary"
    assert steps[restore]["with"]["key"] == steps[save]["with"]["key"]

    # The install hands the cached file over only as -NssmPath, so the installer checks it.
    run = str(steps[install]["run"])
    assert f"$cached['NssmPath'] = $env:{_CACHED_VAR}" in run, run
    assert "@cached" in run, "the install does not pass the cached copy on"
    assert sum(_CACHED_VAR in line for line in run.splitlines()) == 1, (
        f"the install step uses {_CACHED_VAR} other than as -NssmPath"
    )

    # What is saved is a copy of the nssm.exe the installer checked, and only off the queue.
    stage = [
        s
        for s in steps[install + 1 : save]
        if _CHECKED_PATH in str(s.get("run", "")) and _CACHED_VAR in str(s.get("run", ""))
    ]
    assert len(stage) == 1, f"no step copies the checked nssm.exe into the cache path: {names}"
    for step in (stage[0], steps[save]):
        condition = str(step.get("if", ""))
        assert "cache-hit != 'true'" in condition, condition
        assert "github.event_name != 'merge_group'" in condition, condition
