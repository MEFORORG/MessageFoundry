# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#
# Spike S-2b: do the Node fuses close the redirect S-3 found, and does the S-2 walk still run with them
# on? It works on a TEMP COPY of dist\win-unpacked and never flips the built app or the installer.
#
#   pwsh -NoProfile -File theia-spike\scripts\measure-fuses.ps1 [-SkipWalk]
#
# 1. Reads the fuses on the copy, then probes ELECTRON_RUN_AS_NODE and NODE_OPTIONS (--require).
# 2. Flips RunAsNode, EnableNodeOptionsEnvironmentVariable and EnableNodeCliInspectArguments off.
# 3. Probes again, then tries Playwright's Electron launch (which needs --inspect), then runs S-2's
#    walk over CDP (--remote-debugging-port), which no fuse governs.
# A probe that redirects writes a marker file; a probe that does not starts the app, which is killed.
#Requires -Version 7
[CmdletBinding()]
param([switch]$SkipWalk)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

$spike = (Resolve-Path (Join-Path $PSScriptRoot '..')).Path
$app = Join-Path $spike 'electron-app'
$source = Join-Path $app 'dist\win-unpacked'
if (-not (Test-Path -LiteralPath $source)) { throw "No $source; run scripts\build-installer.ps1 first." }

$root = Join-Path ([System.IO.Path]::GetTempPath()) ("mf-s2b-fuses-" + [guid]::NewGuid().ToString('N').Substring(0, 8))
$copy = Join-Path $root 'app'
New-Item -ItemType Directory -Force -Path $root | Out-Null
Copy-Item -LiteralPath $source -Destination $copy -Recurse
$exe = Join-Path $copy 'MessageFoundry Steps Spike.exe'

function Stop-Tree([int]$Id) {
    & (Join-Path $env:SystemRoot 'System32\taskkill.exe') /PID $Id /T /F 2>$null | Out-Null
}

# Waits until no process runs from the copy, so the executable can be rewritten.
function Wait-Unlocked {
    $deadline = (Get-Date).AddSeconds(30)
    do {
        $live = @(Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($copy, [StringComparison]::OrdinalIgnoreCase) })
        foreach ($proc in $live) { Stop-Tree ([int]$proc.ProcessId) }
        if ($live.Count -eq 0) { return }
        Start-Sleep -Milliseconds 500
    } while ((Get-Date) -lt $deadline)
    throw "Processes still run from $copy"
}

# Runs the copy with one environment variable set and reports whether the marker appeared.
function Test-Redirect([string]$Label, [hashtable]$Env, [string[]]$Arguments) {
    $marker = Join-Path $root "$Label.marker"
    Remove-Item -LiteralPath $marker -ErrorAction SilentlyContinue
    $saved = @{}
    foreach ($k in $Env.Keys) { $saved[$k] = [Environment]::GetEnvironmentVariable($k); [Environment]::SetEnvironmentVariable($k, ($Env[$k] -replace '\{marker\}', ($marker -replace '\\', '/'))) }
    try {
        $stderr = Join-Path $root "$Label.stderr"
        $p = Start-Process -FilePath $exe -ArgumentList $Arguments -PassThru -WindowStyle Hidden -RedirectStandardError $stderr
        $deadline = (Get-Date).AddSeconds(20)
        while (-not (Test-Path -LiteralPath $marker) -and -not $p.HasExited -and (Get-Date) -lt $deadline) { Start-Sleep -Milliseconds 250 }
        $redirected = Test-Path -LiteralPath $marker
        $stillRunning = -not $p.HasExited
        Stop-Tree $p.Id
        Wait-Unlocked
        $exit = if ($stillRunning) { 'killed' } else { $p.ExitCode }
        $err = if (Test-Path -LiteralPath $stderr) { ((Get-Content -LiteralPath $stderr -Raw) ?? '').Trim() -replace '\s+', ' ' } else { '' }
    } finally {
        foreach ($k in $Env.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k]) }
    }
    Write-Host ("S2B-FUSE-PROBE {0}: redirected={1} app-started-instead={2} exit={3} stderr={4}" -f $Label, $redirected, ($stillRunning -and -not $redirected), $exit, $err.Substring(0, [Math]::Min(300, $err.Length)))
    return $redirected
}

$requireScript = Join-Path $root 'redirect.js'
Set-Content -LiteralPath $requireScript -Encoding utf8 -Value "require('fs').writeFileSync(process.env.MF_S2B_MARKER, 'redirected'); process.exit(0);"
$nodeOptions = '--require "' + ($requireScript -replace '\\', '/') + '"'

$results = [ordered]@{}
try {
    Write-Host "S2B-FUSES before: $(node (Join-Path $PSScriptRoot 'fuses.mjs') read $exe)"
    $results['before.RUN_AS_NODE'] = Test-Redirect 'before-run-as-node' @{ ELECTRON_RUN_AS_NODE = '1'; MF_S2B_MARKER = '{marker}' } @('-e', "require('fs').writeFileSync(process.env.MF_S2B_MARKER,'x')")
    $results['before.NODE_OPTIONS'] = Test-Redirect 'before-node-options' @{ NODE_OPTIONS = $nodeOptions; MF_S2B_MARKER = '{marker}' } @()

    # A probe whose BEFORE run did not redirect is a dead control: its AFTER result says nothing about
    # the fuse. The three fuses also flip together, so an AFTER result is credited to the set, not to
    # one fuse (with RunAsNode off, Theia's forked backend fails too).
    foreach ($k in @($results.Keys)) {
        if (-not $results[$k]) { Write-Host "S2B-FUSE-CONTROL $k did not redirect BEFORE the flip; its AFTER result is not evidence." }
    }
    Wait-Unlocked
    $flipped = node (Join-Path $PSScriptRoot 'fuses.mjs') flip $exe
    if ($LASTEXITCODE -ne 0) { throw "Flipping the fuses failed: $flipped" }
    Write-Host "S2B-FUSES after: $flipped"
    $results['after.RUN_AS_NODE'] = Test-Redirect 'after-run-as-node' @{ ELECTRON_RUN_AS_NODE = '1'; MF_S2B_MARKER = '{marker}' } @('-e', "require('fs').writeFileSync(process.env.MF_S2B_MARKER,'x')")
    $results['after.NODE_OPTIONS'] = Test-Redirect 'after-node-options' @{ NODE_OPTIONS = $nodeOptions; MF_S2B_MARKER = '{marker}' } @()

    if (-not $SkipWalk) {
        Push-Location $app
        try {
            # Playwright's Electron launch passes --inspect=0, which the fuse now refuses.
            $env:MF_S3_EXE = $exe
            npx playwright test analyst-routes-electron -g 'named route' --timeout 240000 2>&1 | Select-Object -Last 15 | ForEach-Object { Write-Host "  [electron-launch] $_" }
            $results['after.playwright-electron-launch'] = ($LASTEXITCODE -eq 0)
            Remove-Item Env:MF_S3_EXE -ErrorAction SilentlyContinue

            # The same walk over CDP, which no fuse governs. A process left by the failed launch would
            # hold the single-instance lock and make every CDP launch quit.
            Wait-Unlocked
            $env:MF_S2B_CDP_EXE = $exe
            npx playwright test analyst-routes-electron 2>&1 | ForEach-Object { Write-Host "  [cdp] $_" }
            $results['after.walk-over-cdp'] = ($LASTEXITCODE -eq 0)
        } finally {
            Remove-Item Env:MF_S3_EXE, Env:MF_S2B_CDP_EXE -ErrorAction SilentlyContinue
            Pop-Location
        }
    }
} finally {
    Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -and $_.ExecutablePath.StartsWith($copy, [StringComparison]::OrdinalIgnoreCase) } |
        ForEach-Object { Stop-Tree ([int]$_.ProcessId) }
    Start-Sleep -Seconds 2
    Remove-Item -LiteralPath $root -Recurse -Force -ErrorAction SilentlyContinue
}
Write-Host "S2B-FUSE-RESULTS $($results | ConvertTo-Json -Compress)"
