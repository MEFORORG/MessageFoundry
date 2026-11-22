# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
Unattended dashboard refresh: build the page from a git archive of -Ref, never from a work tree.

.DESCRIPTION
Work trees come and go, so this runner reads none of them. It:

1. fetches main ONLY, once per repository per run (`fetch --no-tags origin
   +refs/heads/main:refs/remotes/origin/main`, in the engine checkout and then the vault), which
   moves only refs/remotes/origin/main and touches no work tree, and tells the collector not to
   fetch again; a failed fetch is an error: the run goes on with the refs already there, and a
   page that otherwise built clean exits 3, so stale numbers never pass as current;
2. checks -Ref (a 40-hex commit, or origin/<branch>, which must already be fetched), resolves it
   to a commit and `git archive`s all of scripts/ at it into a fresh directory under TEMP, outside
   every work tree, so a new import in the build needs no change here; leftover directories from
   a killed run, older than two hours, are swept first;
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
# -Ref reaches git and the build log: a 40-hex commit, or a remote branch name with no `..`.
if (-not ($Ref -cmatch '^[0-9a-f]{40}$' -or ($Ref -cmatch '^origin/[A-Za-z0-9._/-]+$' -and $Ref -notlike '*..*'))) {
    throw "-Ref '$Ref' is neither a 40-hex commit nor origin/<branch>"
}
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
    # A run killed by the task's time limit skips its finally. Two hours is past any live run.
    # build.ps1 holds the same sweep for its own prefix; this file must stand alone once installed.
    $cutoff = [DateTime]::UtcNow.AddHours(-2)
    Get-ChildItem -LiteralPath $Base -Directory -Filter "$Prefix*" -ErrorAction SilentlyContinue |
        Where-Object { $_.LastWriteTimeUtc -lt $cutoff -and -not $_.LinkType } |
        ForEach-Object {
            Remove-Item -LiteralPath $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
            if (Test-Path -LiteralPath $_.FullName) {
                [Console]::Error.WriteLine("ERROR: could not sweep stale $($_.FullName)")
            }
        }
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
    # Only beside a page a render published there, and never when this run's refusal fired. An
    # early failure, before the archived render_html.py could be asked, logs through the fallback
    # directory, whose refusal is then not asked.
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
$base = [IO.Path]::GetTempPath()
Remove-StaleTemp $base 'mf-dashboard-src-'
$tmp = Join-Path $base ('mf-dashboard-src-' + [guid]::NewGuid().ToString('N'))
$sha = 'unresolved'
$url = ''
$outDir = ''
$refused = $false
$fetchFailed = $false
$code = 1
try {
    New-Item -ItemType Directory -Path $tmp | Out-Null
    foreach ($repo in @($EngineRepo, $Vault)) {
        try {
            # A stalled transfer aborts after 60 s under 1 KB/s, not at the task's 30-minute kill.
            Invoke-Git @('-C', $repo, '-c', 'http.lowSpeedLimit=1000', '-c', 'http.lowSpeedTime=60',
                'fetch', '--quiet', '--no-tags', 'origin',
                '+refs/heads/main:refs/remotes/origin/main') | Out-Null
        } catch {
            # The run goes on with the refs already there, but it ends red: stale numbers published
            # under exit 0 would read as current.
            $fetchFailed = $true
            [Console]::Error.WriteLine("ERROR: fetch failed in $repo, using the refs already there: $($_.Exception.Message)")
        }
    }
    # Explicit, so a local branch or tag named origin/main cannot shadow the remote-tracking ref.
    $full = if ($Ref -like 'origin/*') { "refs/remotes/$Ref" } else { $Ref }
    $sha = "$(@(Invoke-Git @('-C', $EngineRepo, 'rev-parse', '--verify', "$full^{commit}")) | Select-Object -First 1)".Trim()
    if ($sha -cnotmatch '^[0-9a-f]{40}$') { throw "-Ref resolved to '$sha', not a commit" }
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
    if ($LASTEXITCODE -ne 0) {
        # Refused: nothing, the log included, is written into that directory.
        $refused = $true
        throw "render_html.py --print-out-dir exited $LASTEXITCODE (the dashboard directory is refused)"
    }

    $build = Join-Path $src 'scripts\dashboard\build.ps1'
    $output = @(& $build -Vault $Vault -Weeks $Weeks -EngineRepo $EngineRepo -ArchiveRef $sha -Python $py -NoFetch)
    $code = $LASTEXITCODE
    if ($code -eq 0 -and $fetchFailed) { $code = 3 }
    $output | ForEach-Object { Write-Output $_ }
    # file:///C:/... for a drive, file://server/share/... for a UNC path.
    $url = @($output | Where-Object { "$_" -like 'file://*' } | Select-Object -Last 1) -join ''
} catch {
    [Console]::Error.WriteLine("ERROR: $($_.Exception.Message)")
    $code = 1
} finally {
    Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $tmp) {
        [Console]::Error.WriteLine("WARNING: could not remove temporary $tmp")
    }
}
if ($refused) { $outDir = '' } elseif (-not $outDir) { $outDir = Get-FallbackOutDir }
$stamp = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')
$shown = if ($url) { $url } else { 'none' }
Write-BuildLog $outDir "$stamp ref=$Ref sha=$sha exit=$code url=$shown"
exit $code
