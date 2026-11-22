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

Exit status: 0 when every metric was read; 3 when the page was written but a metric or part could
not be read (the collector's own 3); any other non-zero when no page was written. A failed render
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
    [string[]]$Python = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Resolve-Python([string[]]$Given) {
    if ($Given.Count -gt 0) { return , $Given }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.14 -c "pass" 2>$null
        if ($LASTEXITCODE -eq 0) { return , @('py', '-3.14') }
    }
    return , @('python')
}

$py = Resolve-Python $Python
$exe = $py[0]
$prefix = @($py | Select-Object -Skip 1)
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('mf-dashboard-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $tmp | Out-Null
$snapshot = Join-Path $tmp 'metrics.json'
$code = 0
try {
    $collectArgs = @('-I', (Join-Path $PSScriptRoot 'collect_metrics.py'), '--vault', $Vault,
        '--out', $snapshot, '--weeks', $Weeks)
    if ($EngineRepo) { $collectArgs += @('--engine-repo', $EngineRepo) }
    if ($ArchiveRef) { $collectArgs += @('--archive-ref', $ArchiveRef) }
    & $exe @prefix @collectArgs
    $collected = $LASTEXITCODE
    if ($collected -ne 0 -and $collected -ne 3) {
        [Console]::Error.WriteLine("ERROR: collect_metrics.py exited $collected; no page written")
        $code = $collected
    } else {
        $renderArgs = @('-I', (Join-Path $PSScriptRoot 'render_html.py'), $snapshot)
        if ($OutDir) { $renderArgs += @('--out-dir', $OutDir) }
        $url = & $exe @prefix @renderArgs
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
    # Our own temporary directory, made above; the snapshot in it is a private file.
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $tmp) {
        [Console]::Error.WriteLine("WARNING: could not remove temporary $tmp")
    }
}
exit $code
