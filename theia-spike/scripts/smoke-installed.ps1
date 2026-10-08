# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#
# Spike S-3: install the built installer per-user into a temp folder, drive the installed app with
# Playwright (open a handler in Steps, edit, save), then uninstall and check the uninstall ran.
# It changes no system setting and no other user: the installer is per-user (HKCU, no elevation).
#
#   pwsh -NoProfile -File theia-spike\scripts\smoke-installed.ps1
#Requires -Version 7
[CmdletBinding()]
param(
    [string]$Installer,
    # The Playwright specs to run against the installed app. S-2b's walk runs here with
    # -Specs installed-smoke, analyst-routes-electron; the S-3 verdict stays the smoke test alone.
    [string[]]$Specs = @('installed-smoke')
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$spike = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$repo = (Resolve-Path (Join-Path $spike '..')).Path
$app = Join-Path $spike 'electron-app'
if (-not $Installer) {
    $Installer = (Get-ChildItem -LiteralPath (Join-Path $app 'dist') -Filter '*-unsigned-setup.exe' |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1).FullName
}
if (-not $Installer -or -not (Test-Path -LiteralPath $Installer -PathType Leaf)) {
    throw 'No installer found. Run scripts\build-installer.ps1 first.'
}

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("mf-s3-smoke-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$installDir = Join-Path $root 'app'
$workspace = Join-Path $root 'ws\config'
$evidence = Join-Path $app 'test-results'
New-Item -ItemType Directory -Force -Path $root, $evidence, (Split-Path $workspace) | Out-Null
Copy-Item -LiteralPath (Join-Path $repo 'samples\config') -Destination $workspace -Recurse

$uninstallKeys = 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Uninstall\*'
function Get-SpikeUninstallEntry {
    Get-ItemProperty -Path $uninstallKeys -ErrorAction SilentlyContinue |
        Where-Object { $_.PSObject.Properties['DisplayName'] -and $_.DisplayName -like 'MessageFoundry Steps Spike*' }
}

# 1. Install. NSIS takes /D as the LAST argument, unquoted.
$exe = Join-Path $installDir 'MessageFoundry Steps Spike.exe'
$uninstaller = Join-Path $installDir 'Uninstall MessageFoundry Steps Spike.exe'
$testExit = 1
$gone = $false
$entryGone = $false
try {
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = Start-Process -FilePath $Installer -ArgumentList '/S', "/D=$installDir" -Wait -PassThru
    Write-Host "Install exit code $($p.ExitCode) after $([int]$sw.Elapsed.TotalSeconds) s"
    if ($p.ExitCode -ne 0) { throw "The installer exited $($p.ExitCode)" }
    if (-not (Test-Path -LiteralPath $exe -PathType Leaf)) { throw "The installer did not create $exe" }
    $entry = Get-SpikeUninstallEntry
    Write-Host "HKCU uninstall entry: $(if ($entry) { $entry.DisplayName + ' -> ' + $entry.UninstallString } else { 'MISSING' })"
    $installedBytes = (Get-ChildItem -LiteralPath $installDir -Recurse -File | Measure-Object Length -Sum).Sum
    Write-Host ("Installed size: {0:N1} MiB" -f ($installedBytes / 1MB))

    # 2. Drive it.
    Push-Location $app
    try {
        $env:MF_S3_EXE = $exe
        $env:MF_S3_WORKSPACE = $workspace
        # `pwsh -File` hands "a,b" over as one string; split it so both calling forms work.
        $specList = @($Specs | ForEach-Object { $_ -split ',' } | Where-Object { $_ })
        npx playwright test @specList
        $testExit = $LASTEXITCODE
    } finally {
        Remove-Item Env:MF_S3_EXE, Env:MF_S3_WORKSPACE -ErrorAction SilentlyContinue
        Pop-Location
    }
    $log = Join-Path $env:APPDATA 'MessageFoundry Steps Spike\logs\launcher.log'
    if (Test-Path -LiteralPath $log) {
        Copy-Item -LiteralPath $log -Destination (Join-Path $evidence 'launcher.log') -Force
        Write-Host 'launcher.log (last 5 lines):'
        Get-Content -LiteralPath $log -Tail 5 | ForEach-Object { Write-Host "  $_" }
    }
} finally {
    # 3. Always uninstall, so a failed run leaves no app, HKCU entry or shortcut behind. The NSIS
    # uninstaller re-launches itself from TEMP, so wait for the app to disappear.
    if (Test-Path -LiteralPath $uninstaller) {
        Start-Process -FilePath $uninstaller -ArgumentList '/S' -Wait
        $deadline = (Get-Date).AddSeconds(90)
        while ((Test-Path -LiteralPath $exe) -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 500 }
    }
    $gone = -not (Test-Path -LiteralPath $exe)
    $entryGone = -not (Get-SpikeUninstallEntry)
    Write-Host "Uninstall: app removed=$gone, HKCU entry removed=$entryGone"
}

if ($testExit -ne 0) { throw "The Playwright smoke test failed (exit $testExit). Evidence: $evidence; workspace kept at $root" }
if (-not $gone -or -not $entryGone) { throw 'The uninstall did not complete.' }
Remove-Item -LiteralPath $root -Recurse -Force
Write-Host "Smoke test passed. Evidence: $evidence"
