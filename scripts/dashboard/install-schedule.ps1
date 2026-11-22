# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
Register (or, with -Uninstall, remove) the "MEFOR Dashboard Refresh" scheduled task.

.DESCRIPTION
The task runs scheduled-refresh.ps1 through `pwsh -NoProfile -File` at each of -Times, local time.
The runner is copied to -RunnerDir first (default %USERPROFILE%\.mefor\dashboard), so the task
points at a path no work tree owns. Not under AppData: run from a packaged (MSIX) app such as Claude
Desktop, a write to %LOCALAPPDATA% is virtualized into that package's LocalCache, which Task
Scheduler never sees, so every run would fail to find the runner (measured: pwsh exit 64). -Force re-registers, so running this again replaces the task rather than adding one.
The copy is frozen at install time: after scheduled-refresh.ps1 changes on main, run this again.
The build scripts themselves are not frozen; the runner archives them from -Ref on every run.

The task runs only while the user is logged on (LogonType Interactive), so no password is stored.
It starts when available after a missed time, stops after 30 minutes, and skips a run while one is
still going.

.EXAMPLE
pwsh -NoProfile -File scripts\dashboard\install-schedule.ps1
pwsh -NoProfile -File scripts\dashboard\install-schedule.ps1 -Times 07:00,19:00
pwsh -NoProfile -File scripts\dashboard\install-schedule.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    # Each element may hold several comma-separated times: `pwsh -File` passes -Times 07:00,19:00
    # as ONE string, because it does not split arrays.
    [string[]]$Times = @('07:00', '19:00'),
    [string]$Ref = 'origin/main',
    [string]$RunnerDir = '',
    [switch]$Uninstall
)
if ([Environment]::MachineName -ne 'MEFORDEV01') { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run on MEFORDEV01, but this is $([Environment]::MachineName); nothing ran" } }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = 'MEFOR Dashboard Refresh'
# Not AppData: see the help text. A packaged app's AppData writes never reach Task Scheduler.
$home_ = if ($env:USERPROFILE) { $env:USERPROFILE } else { $HOME }
$dest = if ($RunnerDir) { $RunnerDir } else { Join-Path $home_ '.mefor\dashboard' }
$runner = Join-Path $dest 'scheduled-refresh.ps1'

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

if ($Uninstall) {
    if (Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Output "removed task: $TaskName"
    } else {
        Write-Output "no task named: $TaskName"
    }
    if (Test-Path -LiteralPath $runner) {
        Remove-Item -LiteralPath $runner -Force
        Write-Output "removed runner: $runner"
    }
} else {
    $at = ConvertTo-TriggerTimes $Times
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'scheduled-refresh.ps1') -Destination $runner -Force
    $pwsh = (Get-Command pwsh).Source
    $action = New-ScheduledTaskAction -Execute $pwsh `
        -Argument "-NoProfile -NonInteractive -WindowStyle Hidden -File `"$runner`" -Ref `"$Ref`""
    $triggers = @($at | ForEach-Object { New-ScheduledTaskTrigger -Daily -At $_ })
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
    # Battery is no reason to skip a refresh: the defaults would never start a laptop's run.
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries `
        -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 30) `
        -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
        -Principal $principal -Settings $settings -Force | Out-Null
    $shown = ($at | ForEach-Object { $_.ToString('HH:mm') }) -join ', '
    Write-Output "registered task: $TaskName at $shown local, runner $runner, ref $Ref"
}
