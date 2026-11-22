# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
Collect the project metrics and render the dashboard page, then print its file:/// URL.

.DESCRIPTION
Runs collect_metrics.py into a snapshot in a fresh temporary directory (under the user's TEMP,
outside every work tree), renders it with render_html.py into the dashboard directory, prints the
page's URL as the last line, and removes the temporary snapshot.

The page goes where render_html.py resolves it: -OutDir, else MEFOR_DASHBOARD_DIR, else
OneDrive\Desktop\MEFOR\dashboard when OneDrive\Desktop\MEFOR exists, else %USERPROFILE%\MEFOR\dashboard.

The dashboard directory is checked first (render_html.py --print-out-dir), so a refused directory
stops the run before anything is collected. The collector's own work directory is put inside this
script's temporary directory, and leftover mf-dashboard-build-* directories older than two hours, from a
run that was killed, are swept first.

Exit status: 0 when every metric was read; 3 when the page was written but a metric or part could
not be read (the collector's own 3), or the temporary directory, or a stale one from a killed run,
could not be removed; any other
non-zero when no page was written. A failed render
leaves the previous index.html in place, because render_html.py replaces it atomically.

.EXAMPLE
pwsh -NoProfile -File scripts\dashboard\build.ps1 -Weeks 8
#>
[CmdletBinding()]
param(
    [string]$Vault = 'D:/Code/MessageFoundry-vault',
    [ValidateRange(2, 104)][int]$Weeks = 8,
    [string]$OutDir = '',
    # The engine git checkout for the release distance. Empty: the checkout these scripts sit in,
    # which the collector works out for itself.
    [string]$EngineRepo = '',
    # The engine commit these scripts were git-archived from, when they are no checkout.
    [string]$ArchiveRef = '',
    # The interpreter as an argv prefix, for example 'py','-3.14'. Empty: py -3.14 when it runs,
    # else python on PATH.
    [string[]]$Python = @(),
    # The caller already fetched origin main in the vault and the engine checkout.
    [switch]$NoFetch
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Python([string[]]$Given) {
    # `pwsh -File` passes -Python py,-3.14 as ONE string, because it does not split arrays.
    $parts = @($Given | ForEach-Object { "$_" -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    if ($parts.Count -gt 0) { return , $parts }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.14 -c "pass" 2>$null
        if ($LASTEXITCODE -eq 0) { return , @('py', '-3.14') }
    }
    return , @('python')
}

function Remove-StaleTemp([string]$Base, [string]$Prefix) {
    # A run killed by the task's time limit skips its finally, so its private snapshot outlives
    # it. Two hours is past any live run. $false when one that should have gone is still there:
    # it holds a private snapshot and vault files, so the caller fails the run, as the collector
    # does for its own sweep.
    $cutoff = [DateTime]::UtcNow.AddHours(-2)
    $ok = $true
    foreach ($old in @(Get-ChildItem -LiteralPath $Base -Directory -Filter "$Prefix*" -ErrorAction SilentlyContinue |
            Where-Object { $_.LastWriteTimeUtc -lt $cutoff -and -not $_.LinkType })) {
        Remove-Item -LiteralPath $old.FullName -Recurse -Force -ErrorAction SilentlyContinue
        if (Test-Path -LiteralPath $old.FullName) {
            [Console]::Error.WriteLine("ERROR: could not sweep stale $($old.FullName)")
            $ok = $false
        }
    }
    return $ok
}

$py = Resolve-Python $Python
$exe = $py[0]
$prefix = @($py | Select-Object -Skip 1)
$render = Join-Path $PSScriptRoot 'render_html.py'
$outArgs = @()
if ($OutDir) { $outArgs = @('--out-dir', $OutDir) }

# The page directory is refused BEFORE collecting, so nothing private is gathered for a directory
# the page may not be written to.
$null = & $exe @prefix -I $render @outArgs --print-out-dir
if ($LASTEXITCODE -ne 0) {
    [Console]::Error.WriteLine("ERROR: the dashboard directory is refused; nothing collected")
    exit 1
}

$base = [IO.Path]::GetTempPath()
$swept = Remove-StaleTemp $base 'mf-dashboard-build-'
$tmp = Join-Path $base ('mf-dashboard-build-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$snapshot = Join-Path $tmp 'metrics.json'
$code = 0
try {
    # --work-dir: the collector's own private directory goes under this one, so one cleanup
    # covers both and TMP versus TMPDIR can never split them.
    $collectArgs = @('-I', (Join-Path $PSScriptRoot 'collect_metrics.py'), '--vault', $Vault,
        '--out', $snapshot, '--weeks', $Weeks, '--work-dir', $tmp)
    if ($EngineRepo) { $collectArgs += @('--engine-repo', $EngineRepo) }
    if ($ArchiveRef) { $collectArgs += @('--archive-ref', $ArchiveRef) }
    if ($NoFetch) { $collectArgs += @('--no-fetch') }
    & $exe @prefix @collectArgs
    $collected = $LASTEXITCODE
    if ($collected -ne 0 -and $collected -ne 3) {
        [Console]::Error.WriteLine("ERROR: collect_metrics.py exited $collected; no page written")
        $code = $collected
    } else {
        $url = & $exe @prefix -I $render $snapshot @outArgs
        $rendered = $LASTEXITCODE
        if ($rendered -ne 0) {
            [Console]::Error.WriteLine("ERROR: render_html.py exited $rendered; the previous page stands")
            $code = $rendered
        } else {
            $code = $collected
            Write-Output $url
        }
    }
} finally {
    # Our own temporary directory, made above; the snapshot in it is a private file, so a
    # directory that will not go fails the run.
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $tmp) {
        [Console]::Error.WriteLine("ERROR: could not remove temporary $tmp, which holds a private snapshot")
        if ($code -eq 0) { $code = 3 }
    }
}
# A stale directory that would not go fails a run that was otherwise clean, as above.
if (-not $swept -and $code -eq 0) { $code = 3 }
exit $code
