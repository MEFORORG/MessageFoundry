# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
Unattended dashboard refresh: build the page from a git archive of -Ref, never from a work tree.

.DESCRIPTION
Work trees come and go, so this runner reads none of them. It:

1. runs `git -C <EngineRepo> fetch origin` and `git -C <Vault> fetch origin`, which move only
   remote-tracking refs and never touch either work tree;
2. resolves -Ref to a commit and `git archive`s the scripts the build needs (scripts/dashboard,
   which it runs; scripts/asvs and scripts/ci, which the collector runs and imports) into a fresh
   directory under TEMP, outside every work tree;
3. runs that copy's build.ps1, so the page lands in the dashboard directory render_html.py
   resolves (MEFOR_DASHBOARD_DIR, else the OneDrive or profile default);
4. appends one line (UTC time, ref commit, exit code, URL) to build.log in that directory, keeping
   the last 200 lines, and removes the temporary directory.

A failure exits non-zero and leaves the previous index.html in place: the page is replaced
atomically, and only by a render that succeeded. Python runs with -I. gh uses the account's own
existing authentication; this script holds no secret and logs none.

.EXAMPLE
pwsh -NoProfile -File scheduled-refresh.ps1 -Ref origin/main
#>
[CmdletBinding()]
param(
    [string]$EngineRepo = 'D:\Code\MessageFoundry',
    [string]$Ref = 'origin/main',
    [string]$Vault = 'D:/Code/MessageFoundry-vault',
    [ValidateRange(2, 104)][int]$Weeks = 8,
    [string[]]$Python = @()
)
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

#: The engine paths the build reads from the archived copy. collect_metrics.py runs
#: scripts/asvs/scorecard.py and imports scripts/ci/check_stalled_prs.py, which imports
#: scripts/ci/_pr_checks.py.
$ArchivePaths = @('scripts/dashboard', 'scripts/asvs', 'scripts/ci')

function Invoke-Git([string[]]$GitArgs) {
    $out = & git @GitArgs
    if ($LASTEXITCODE -ne 0) { throw "git $($GitArgs -join ' ') exited $LASTEXITCODE" }
    return $out
}

function Resolve-Python([string[]]$Given) {
    if ($Given.Count -gt 0) { return , $Given }
    if (Get-Command py -ErrorAction SilentlyContinue) {
        & py -3.14 -c "pass" 2>$null
        if ($LASTEXITCODE -eq 0) { return , @('py', '-3.14') }
    }
    return , @('python')
}

function Write-BuildLog([string]$Dir, [string]$Line) {
    # Only into a directory a render already made: a run that never rendered must not create one
    # where the work-tree refusal was never asked.
    if (-not $Dir -or -not (Test-Path -LiteralPath $Dir -PathType Container)) {
        [Console]::Error.WriteLine("build.log not written (no dashboard directory): $Line")
        return
    }
    $log = Join-Path $Dir 'build.log'
    $lines = @()
    if (Test-Path -LiteralPath $log) { $lines = @(Get-Content -LiteralPath $log -Encoding utf8) }
    $lines = @($lines + $Line | Select-Object -Last 200)
    $tmpLog = "$log.$([guid]::NewGuid().ToString('N')).tmp"
    Set-Content -LiteralPath $tmpLog -Value $lines -Encoding utf8
    Move-Item -LiteralPath $tmpLog -Destination $log -Force
}

$py = Resolve-Python $Python
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('mf-dashboard-src-' + [guid]::NewGuid().ToString('N'))
$sha = 'unresolved'
$url = ''
$outDir = ''
$code = 1
try {
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Invoke-Git @('-C', $EngineRepo, 'fetch', '--quiet', 'origin') | Out-Null
    Invoke-Git @('-C', $Vault, 'fetch', '--quiet', 'origin') | Out-Null
    $sha = (Invoke-Git @('-C', $EngineRepo, 'rev-parse', '--verify', "$Ref^{commit}") | Select-Object -First 1).Trim()
    $tar = Join-Path $tmp 'src.tar'
    Invoke-Git (@('-C', $EngineRepo, 'archive', '--format=tar', '-o', $tar, $sha, '--') + $ArchivePaths) | Out-Null
    $src = Join-Path $tmp 'src'
    New-Item -ItemType Directory -Path $src | Out-Null
    $tarExe = Join-Path $env:SystemRoot 'System32\tar.exe'
    if (-not (Test-Path -LiteralPath $tarExe)) { $tarExe = 'tar' }
    & $tarExe -xf $tar -C $src
    if ($LASTEXITCODE -ne 0) { throw "tar -xf exited $LASTEXITCODE" }

    $render = Join-Path $src 'scripts\dashboard\render_html.py'
    $outDir = (& $py[0] @($py | Select-Object -Skip 1) -I $render --print-out-dir | Select-Object -Last 1)
    if ($LASTEXITCODE -ne 0) { throw "render_html.py --print-out-dir exited $LASTEXITCODE" }

    $build = Join-Path $src 'scripts\dashboard\build.ps1'
    $output = @(& $build -Vault $Vault -Weeks $Weeks -EngineRepo $EngineRepo -Python $py)
    $code = $LASTEXITCODE
    $output | ForEach-Object { Write-Output $_ }
    $url = @($output | Where-Object { "$_" -like 'file:///*' } | Select-Object -Last 1) -join ''
} catch {
    [Console]::Error.WriteLine("ERROR: $($_.Exception.Message)")
    $code = 1
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $tmp) {
        [Console]::Error.WriteLine("WARNING: could not remove temporary $tmp")
    }
}
$stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$shown = if ($url) { $url } else { 'none' }
Write-BuildLog $outDir "$stamp ref=$Ref sha=$sha exit=$code url=$shown"
exit $code
