# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
Unattended dashboard refresh: build the page from a git archive of -Ref, never from a work tree.

.DESCRIPTION
Work trees come and go, so this runner reads none of them. It:

1. runs `git -C <EngineRepo> fetch --no-tags origin`, which moves only remote-tracking refs and
   touches no work tree, then the same in the vault; a failed vault fetch is a warning, because the
   collector fetches the vault itself and confines that failure to the vault metrics;
2. resolves -Ref to a commit and `git archive`s all of scripts/ at it into a fresh directory under
   TEMP, outside every work tree, so a new import in the build needs no change here;
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
# Unattended: a credential prompt would wait, hidden, until the task's time limit killed it.
$env:GIT_TERMINAL_PROMPT = '0'
$env:GCM_INTERACTIVE = 'never'
# render_html.py prints its output path in UTF-8; read it back the same way.
try { [Console]::OutputEncoding = [Text.UTF8Encoding]::new($false) } catch { [Console]::Error.WriteLine("WARNING: console encoding unchanged: $($_.Exception.Message)") }

#: The engine paths the build reads from the archived copy: the whole of scripts/, so the list
#: never lags what collect_metrics.py runs and imports.
$ArchivePaths = @('scripts')

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

function Get-FallbackOutDir {
    # render_html.py owns this rule; this copy is used only when the run failed before the
    # archived render_html.py could be asked, so an early failure is still logged.
    if ($env:MEFOR_DASHBOARD_DIR) { return $env:MEFOR_DASHBOARD_DIR }
    $home_ = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
    $onedrive = Join-Path $home_ 'OneDrive\Desktop\MEFOR'
    if (Test-Path -LiteralPath $onedrive -PathType Container) { return (Join-Path $onedrive 'dashboard') }
    return (Join-Path $home_ 'MEFOR\dashboard')
}

function Write-BuildLog([string]$Dir, [string]$Line) {
    # Only beside a page a render published there, which needed the work-tree refusal to pass
    # at that time. This run's own refusal is not asked again: a directory that became part of a
    # work tree after a page was published there still gets this line.
    if (-not $Dir -or -not (Test-Path -LiteralPath (Join-Path $Dir 'index.html') -PathType Leaf)) {
        [Console]::Error.WriteLine("build.log not written (no published page in '$Dir'): $Line")
        return
    }
    $log = Join-Path $Dir 'build.log'
    $tmpLog = "$log.$([guid]::NewGuid().ToString('N')).tmp"
    try {
        $lines = @()
        if (Test-Path -LiteralPath $log) { $lines = @(Get-Content -LiteralPath $log -Encoding utf8) }
        $lines = @($lines + $Line | Select-Object -Last 200)
        Set-Content -LiteralPath $tmpLog -Value $lines -Encoding utf8
        Move-Item -LiteralPath $tmpLog -Destination $log -Force
    } catch {
        # A log that will not write (OneDrive holding the file) never changes the run's result.
        Remove-Item -LiteralPath $tmpLog -Force -ErrorAction SilentlyContinue
        [Console]::Error.WriteLine("WARNING: build.log not written: $($_.Exception.Message)")
    }
}

$py = Resolve-Python $Python
$tmp = Join-Path ([IO.Path]::GetTempPath()) ('mf-dashboard-src-' + [guid]::NewGuid().ToString('N'))
$sha = 'unresolved'
$url = ''
$outDir = ''
$code = 1
try {
    New-Item -ItemType Directory -Path $tmp | Out-Null
    Invoke-Git @('-C', $EngineRepo, 'fetch', '--quiet', '--no-tags', 'origin') | Out-Null
    try {
        Invoke-Git @('-C', $Vault, 'fetch', '--quiet', '--no-tags', 'origin') | Out-Null
    } catch {
        [Console]::Error.WriteLine("WARNING: vault fetch failed, the collector retries it: $($_.Exception.Message)")
    }
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
    $output = @(& $build -Vault $Vault -Weeks $Weeks -EngineRepo $EngineRepo -ArchiveRef $sha -Python $py)
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
if (-not $outDir) { $outDir = Get-FallbackOutDir }
$stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$shown = if ($url) { $url } else { 'none' }
Write-BuildLog $outDir "$stamp ref=$Ref sha=$sha exit=$code url=$shown"
exit $code
