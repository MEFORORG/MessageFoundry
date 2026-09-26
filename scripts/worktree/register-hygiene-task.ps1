# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Register, or with -Unregister remove, the Windows scheduled task that runs hygiene-report.ps1.

.DESCRIPTION
    Owner ruling 2026-09-26: a script on a schedule, Steward pattern, zero model calls, that reports
    worktree and hook hygiene and deletes nothing. hygiene-report.ps1 is that script; this one only
    manages the task. Modelled on install-daily-prune.ps1 here and korus
    scripts/wiki/register-cycle-task.ps1.

    THE TASK RUNS THE PRIMARY CHECKOUT'S COPY of hygiene-report.ps1, never this script's own. This is
    usually run from a worktree, and a worktree is a thing somebody deletes; a task pointed at it dies
    with it, and Task Scheduler's only complaint is a result code in a history nobody reads.

    IT RUNS AS YOU, INTERACTIVELY, AT RUN LEVEL LIMITED. The report reads the Claude session registry
    under your profile (the liveness fence) and calls gh with your login. As SYSTEM both are missing,
    the fence could not look, and nothing would ever be proposed. Nothing it does needs elevation.

    IT RUNS ON BATTERY, IN A HIDDEN WINDOW, AND STOPS AFTER ONE HOUR. A second start while one runs is
    ignored, and a start missed while the machine slept runs when it wakes.

    IT REFUSES TO REGISTER OR UNREGISTER INSIDE CLAUDE CODE. The task runs, unattended and repeatedly,
    a script from the primary checkout that any session can edit, and removing it stops the reports
    with nothing saying why. The owner does both from a plain terminal. -WhatIf changes nothing and is
    allowed anywhere; so is -Json without -Unregister.

.PARAMETER EveryHours
    Hours between runs. Default 6.

.PARAMETER At
    First start time, local, 24-hour "HH:mm". Default 00:20. Repeats every -EveryHours from then.

.PARAMETER WhatIf
    Print the plan and register nothing.

.PARAMETER Json
    Print the plan (or the -Unregister result) as JSON. With no -Unregister it registers nothing.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\register-hygiene-task.ps1 -WhatIf
    pwsh -NoProfile -File scripts\worktree\register-hygiene-task.ps1
    pwsh -NoProfile -File scripts\worktree\register-hygiene-task.ps1 -EveryHours 12
    pwsh -NoProfile -File scripts\worktree\register-hygiene-task.ps1 -Unregister
#>
[CmdletBinding()]
param(
    [ValidateRange(1, 168)][int]$EveryHours = 6,
    [string]$At = '00:20',
    [string]$TaskName = 'MEFOR-Worktree-Hygiene',
    # Passed through to hygiene-report.ps1 when set; otherwise it uses its own default.
    [string]$OutDir,
    [switch]$Unregister,
    [switch]$WhatIf,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'

function Stop-Register([string]$Message) {
    [Console]::Error.WriteLine("register-hygiene-task: $Message")
    exit 2
}

$atTime = [datetime]::MinValue
if (-not [datetime]::TryParseExact($At, 'HH:mm', [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::None, [ref]$atTime)) {
    Stop-Register "-At '$At' is not a 24-hour HH:mm time."
}

# --- -Unregister ----------------------------------------------------------------------------------
if ($Unregister) {
    # Removing the owner's task stops the reports with nothing saying why, so a session may not do it
    # either. -WhatIf changes nothing and stays allowed.
    if ($env:CLAUDECODE -eq '1' -and -not $WhatIf) {
        Stop-Register 'refusing to unregister inside Claude Code: the owner registered this task. Run it from a plain terminal, or add -WhatIf to see what would happen.'
    }
    $result = [ordered]@{ taskName = $TaskName; whatIf = [bool]$WhatIf; registered = $null; removed = $false }
    if (-not $IsWindows) { Stop-Register 'Windows only: -Unregister removes a Windows scheduled task.' }
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $result.registered = [bool]$existing
    if ($existing -and -not $WhatIf) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        $result.removed = $true
    }
    if ($Json) { $result | ConvertTo-Json -Depth 4 }
    elseif ($WhatIf) { Write-Output "-WhatIf: would remove task '$TaskName' (registered: $($result.registered))." }
    elseif ($result.removed) { Write-Output "Removed scheduled task '$TaskName'." }
    else { Write-Output "No scheduled task '$TaskName' to remove." }
    exit 0
}

# --- plan -----------------------------------------------------------------------------------------
# The primary from the same helper hygiene-report.ps1 and prune-merged.ps1 use (git's first
# `worktree list` entry), not the parent of the common dir, which agrees only in the usual layout.
. "$PSScriptRoot\..\coord\occupancy.ps1"
$occ = Get-WorktreeOccupancy -Repo $PSScriptRoot
if (-not $occ.RepoFound) { Stop-Register "not inside a git repository: $PSScriptRoot" }
$primary = $occ.PrimaryPath
$report = Join-Path $primary 'scripts/worktree/hygiene-report.ps1'
$reportExists = Test-Path -LiteralPath $report -PathType Leaf

# One definition of each value the task is built from, read by both the plan and the registration.
$runLevel = 'Limited'
$logonType = 'Interactive'
$timeLimitHours = 1
$userId = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
$executable = (Get-Process -Id $PID).Path

$window = if ($IsWindows) { '-WindowStyle Hidden ' } else { '' }
$argument = "-NoProfile -NonInteractive $window-ExecutionPolicy Bypass -File `"$report`""
if ($OutDir) {
    if ($OutDir.Contains('"')) { Stop-Register "-OutDir holds a double quote, which cannot pass through the task's command line." }
    # Absolute now: the task resolves a relative path against its working directory, the primary
    # checkout, and would scatter untracked report files there.
    $OutDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutDir)
    $argument += " -OutDir `"$($OutDir.TrimEnd('\'))`""
}

$plan = [ordered]@{
    taskName = $TaskName
    executable = $executable
    argument = $argument
    workingDirectory = $primary
    report = $report
    reportExists = $reportExists
    trigger = [ordered]@{ kind = 'repeating'; firstAt = $At; everyHours = $EveryHours }
    userId = $userId
    logonType = $logonType
    runLevel = $runLevel
    executionTimeLimitHours = $timeLimitHours
    multipleInstances = 'IgnoreNew'
    deletesAnything = $false
}

if ($WhatIf -or $Json) {
    if ($Json) { $plan | ConvertTo-Json -Depth 4 }
    else {
        Write-Output "-WhatIf: nothing was registered."
        Write-Output "Task '$TaskName': every $EveryHours h from $At local, as $userId ($logonType logon, run level $runLevel)."
        Write-Output "  runs: $executable $argument"
        Write-Output "  in:   $primary"
        if (-not $reportExists) { Write-Output "  MISSING: $report" }
    }
    exit 0
}

# --- register (idempotent: -Force replaces an existing definition) --------------------------------
if ($env:CLAUDECODE -eq '1') {
    Stop-Register 'refusing to register inside Claude Code: the task would run, unattended, a script any session can edit. Run this from a plain terminal. (-WhatIf and -Json register nothing and are allowed.)'
}
if (-not $IsWindows) { Stop-Register 'Windows only: this registers a Windows scheduled task.' }
if (-not $reportExists) {
    Stop-Register "hygiene-report.ps1 is not in the primary checkout: $report. If the change has not landed there yet, bring the primary to origin/main first."
}

try {
    $action = New-ScheduledTaskAction -Execute $executable -Argument $argument -WorkingDirectory $primary
    $trigger = New-ScheduledTaskTrigger -Once -At $At -RepetitionInterval (New-TimeSpan -Hours $EveryHours)
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType $logonType -RunLevel $runLevel
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Hours $timeLimitHours) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null
}
catch { Stop-Register "the task store refused: $($_.Exception.Message)" }

Write-Output "Registered '$TaskName': every $EveryHours h from $At local."
Write-Output "  runs: $report"
Write-Output "  It reports and deletes nothing. Read the latest report at <git common dir>\mefor-coord\hygiene\latest.md"
exit 0
