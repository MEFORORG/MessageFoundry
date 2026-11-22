# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
Register (or, with -Uninstall, remove) the "MEFOR Dashboard Refresh" scheduled task.

.DESCRIPTION
The task runs scheduled-refresh.ps1 through `pwsh -NoProfile -File` at each of -Times, local time.
The runner is copied to %LOCALAPPDATA%\MEFOR\dashboard first, so the task points at a path no work
tree owns. -Force re-registers, so running this again replaces the task rather than adding one.

The task runs only while the user is logged on (LogonType Interactive), so no password is stored.
It starts when available after a missed time, stops after 30 minutes, and skips a run while one is
still going.

.EXAMPLE
pwsh -NoProfile -File scripts\dashboard\install-schedule.ps1
pwsh -NoProfile -File scripts\dashboard\install-schedule.ps1 -Uninstall
#>
[CmdletBinding()]
param(
    [string[]]$Times = @('07:00', '19:00'),
    [string]$Ref = 'origin/main',
    [switch]$Uninstall
)
if ([Environment]::MachineName -ne 'MEFORDEV01') { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run on MEFORDEV01, but this is $([Environment]::MachineName); nothing ran" } }
Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$TaskName = 'MEFOR Dashboard Refresh'
$dest = Join-Path $env:LOCALAPPDATA 'MEFOR\dashboard'
$runner = Join-Path $dest 'scheduled-refresh.ps1'

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
    New-Item -ItemType Directory -Path $dest -Force | Out-Null
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'scheduled-refresh.ps1') -Destination $runner -Force
    $pwsh = (Get-Command pwsh).Source
    $action = New-ScheduledTaskAction -Execute $pwsh `
        -Argument "-NoProfile -File `"$runner`" -Ref `"$Ref`""
    $triggers = @($Times | ForEach-Object { New-ScheduledTaskTrigger -Daily -At $_ })
    $principal = New-ScheduledTaskPrincipal -UserId "$env:USERDOMAIN\$env:USERNAME" -LogonType Interactive
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable `
        -ExecutionTimeLimit (New-TimeSpan -Minutes 30) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $triggers `
        -Principal $principal -Settings $settings -Force | Out-Null
    Write-Output "registered task: $TaskName at $($Times -join ', ') local, runner $runner, ref $Ref"
}
