# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
Register (or, with -Uninstall, remove) the "MEFOR Dashboard Refresh" scheduled task.

.DESCRIPTION
The task runs scheduled-refresh.ps1 through `pwsh -NoProfile -File` at each of -Times, local time.

PINNED TO ONE COMMIT. -Ref (a 40-hex commit, or origin/<branch> as already fetched in -EngineRepo)
is resolved to its full commit sha here, and only that sha reaches the task: the runner is
extracted from that commit with `git archive`, never copied from the work tree this script sits
in, and the task passes `-Ref <sha>`, so each run starts from the scripts of that one commit. The
pin covers the engine code only: scripts/ at that commit, and the runner extracted from it. It does
not cover the vault code each run also executes, the ledger census archived from vault origin/main
as it stands at run time, unpinned and as the same user. That code can rewrite the installed runner
in -RunnerDir and the scripts extracted for the run, so the pin holds only while vault origin/main
is trusted as fully as the engine code; collect_metrics.py's docstring says what that code can do.
Nor does the pin prove the engine code was reviewed: pin a merged main commit for that.
To move the dashboard to newer code, run this again with the new -Ref.

The runner goes to -RunnerDir (default %USERPROFILE%\.mefor\dashboard), a path no work tree owns.
Not under AppData: run from a packaged (MSIX) app such as Claude Desktop, a write to %LOCALAPPDATA%
is virtualized into that package's LocalCache, which Task Scheduler never sees, so every run would
fail to find the runner (measured: pwsh exit 64). -RunnerDir is refused under AppData for the same
reason, and is made absolute, since the task starts in System32.

-Force re-registers, so running this again replaces the task rather than adding one. The task runs
only while the user is logged on (LogonType Interactive), so no password is stored. It starts when
available after a missed time, stops after 30 minutes, and skips a run while one is still going.

-Uninstall removes the task and the runner its action names.

.EXAMPLE
pwsh -NoProfile -File scripts\dashboard\install-schedule.ps1 -Times 07:00,19:00 -Ref origin/main
pwsh -NoProfile -File scripts\dashboard\install-schedule.ps1 -Uninstall
#>
[CmdletBinding(PositionalBinding = $false)]
param(
    # Each element may hold several comma-separated times: `pwsh -File` passes -Times 07:00,19:00
    # as ONE string, because it does not split arrays.
    [string[]]$Times = @('07:00', '19:00'),
    [string]$Ref = 'origin/main',
    [string]$EngineRepo = 'D:\Code\MessageFoundry',
    [string]$RunnerDir = '',
    [switch]$Uninstall
)
if ([Environment]::MachineName -ne 'MEFORDEV01') { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run on MEFORDEV01, but this is $([Environment]::MachineName); nothing ran" } }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = 'MEFOR Dashboard Refresh'
$RunnerName = 'scheduled-refresh.ps1'

function ConvertTo-TriggerTimes([string[]]$Given) {
    $out = @()
    foreach ($part in @($Given | ForEach-Object { "$_" -split ',' })) {
        $text = $part.Trim()
        if (-not $text) { continue }
        if ($text -notmatch '^([01]?[0-9]|2[0-3]):[0-5][0-9]$') {
            throw "-Times: '$text' is not a 24-hour time such as 07:00"
        }
        $parsed = [datetime]::ParseExact($text, 'H:mm', [Globalization.CultureInfo]::InvariantCulture)
        $out += $parsed
    }
    if ($out.Count -eq 0) { throw '-Times: no time given' }
    return , $out
}

function Resolve-AbsolutePath([string]$Path, [string]$Name) {
    $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path).TrimEnd('\')
    # The path goes inside quotes in the task's argument string: a quote would end it early.
    if ($full.Contains('"')) { throw "-${Name}: '$full' contains a quote" }
    return $full
}

function Get-RunnerDir {
    # Not AppData: see the help text. A packaged app's AppData writes never reach Task Scheduler.
    $home_ = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
    $dir = if ($RunnerDir) { $RunnerDir } else { Join-Path $home_ '.mefor\dashboard' }
    $full = Resolve-AbsolutePath $dir 'RunnerDir'
    if ($full -match '\\AppData(\\|$)') { throw "-RunnerDir: '$full' is under AppData, which a packaged app virtualizes" }
    return $full
}

function Resolve-PinnedSha([string]$Repo, [string]$Given) {
    if (-not ($Given -cmatch '^[0-9a-f]{40}$' -or ($Given -cmatch '^origin/[A-Za-z0-9._/-]+$' -and $Given -notlike '*..*'))) {
        throw "-Ref '$Given' is neither a 40-hex commit nor origin/<branch>"
    }
    # origin/<branch> names the remote-tracking ref explicitly: git's own lookup order would let a
    # local branch or tag named origin/main shadow it.
    $full = if ($Given -like 'origin/*') { "refs/remotes/$Given" } else { $Given }
    # Captured whole before any Select-Object, which can stop the pipeline before $LASTEXITCODE is set.
    $out = @(& git -C $Repo rev-parse --verify "$full^{commit}")
    if ($LASTEXITCODE -ne 0) { throw "-Ref '$Given' does not resolve in $Repo" }
    $sha = "$($out | Select-Object -First 1)".Trim()
    if ($sha -cnotmatch '^[0-9a-f]{40}$') { throw "-Ref '$Given' resolved to '$sha', not a commit" }
    return $sha
}

function Export-Runner([string]$Repo, [string]$Sha, [string]$Dest) {
    # From the pinned commit, never from this script's own work tree.
    $tmp = Join-Path ([IO.Path]::GetTempPath()) ('mf-dashboard-install-' + [guid]::NewGuid().ToString('N'))
    New-Item -ItemType Directory -Path $tmp | Out-Null
    try {
        $tar = Join-Path $tmp 'runner.tar'
        & git -C $Repo archive --format=tar -o $tar $Sha -- "scripts/dashboard/$RunnerName"
        if ($LASTEXITCODE -ne 0) { throw "git archive of $RunnerName at $Sha exited $LASTEXITCODE" }
        $tarExe = Join-Path $env:SystemRoot 'System32\tar.exe'
        if (-not (Test-Path -LiteralPath $tarExe)) { $tarExe = 'tar' }
        & $tarExe -xf $tar -C $tmp
        if ($LASTEXITCODE -ne 0) { throw "tar -xf exited $LASTEXITCODE" }
        New-Item -ItemType Directory -Path $Dest -Force | Out-Null
        Copy-Item -LiteralPath (Join-Path $tmp "scripts\dashboard\$RunnerName") -Destination (Join-Path $Dest $RunnerName) -Force
    } finally {
        Remove-Item -LiteralPath $tmp -Recurse -Force -ErrorAction SilentlyContinue
    }
}

if ($Uninstall) {
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $runner = ''
    if ($task) {
        # The runner the task actually named, whatever -RunnerDir this call was given.
        $named = [regex]::Match("$(@($task.Actions)[0].Arguments)", '-File "([^"]+)"')
        if ($named.Success) { $runner = $named.Groups[1].Value }
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output "removed task: $TaskName"
    } else {
        Write-Output "no task named: $TaskName"
        $runner = Join-Path (Get-RunnerDir) $RunnerName
    }
    if ($runner -and (Split-Path -Leaf $runner) -eq $RunnerName -and (Test-Path -LiteralPath $runner)) {
        Remove-Item -LiteralPath $runner -Force
        Write-Output "removed runner: $runner"
    }
} else {
    $at = ConvertTo-TriggerTimes $Times
    $repo = Resolve-AbsolutePath $EngineRepo 'EngineRepo'
    $sha = Resolve-PinnedSha $repo $Ref
    $dest = Get-RunnerDir
    $runner = Join-Path $dest $RunnerName
    Export-Runner $repo $sha $dest
    $pwsh = (Get-Command pwsh).Source
    # Only checked values reach this string: absolute quote-free paths and a 40-hex sha.
    $action = New-ScheduledTaskAction -Execute $pwsh `
        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -File `"$runner`" -Ref $sha -EngineRepo `"$repo`""
    $triggers = @($at | ForEach-Object { New-ScheduledTaskTrigger -Daily -At $_ })
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
    # Battery is no reason to skip a refresh: the defaults would never start a laptop's run.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
        -Principal $principal -Settings $settings -Force | Out-Null
    $shown = ($at | ForEach-Object { $_.ToString('HH:mm') }) -join ', '
    Write-Output "registered task: $TaskName at $shown local, runner $runner, pinned to $sha"
}
