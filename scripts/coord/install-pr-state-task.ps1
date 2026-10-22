# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Register, or with -Uninstall remove, the scheduled task that runs pr_state.py every 2 minutes.

.DESCRIPTION
    pr_state.py does one poll of the open pull requests and the merge queue, and writes
    <git-common-dir>/mefor-coord/pr-state.json. Read-only fleet panes read that file and call no API.
    docs/WORKTREES.md, "A PR-state cache for read-only panes", says what the file holds.

    Modelled on scripts/worktree/register-hygiene-task.ps1, and on the MEFOR-Usage-Trend task on
    mefordev01, which runs pythonw.exe so no window opens.

    THE TASK RUNS THE PRIMARY CHECKOUT'S COPY of pr_state.py, never this script's own. A worktree is
    a thing somebody deletes, and a task aimed at one dies with it.

    IT RUNS AS YOU, INTERACTIVELY, AT RUN LEVEL LIMITED. gh reads its token from your keyring, which
    SYSTEM cannot see. It runs whether or not a Claude session is open; it needs you logged on to
    Windows. It runs under pythonw.exe, so no window opens, on battery too, and stops after ten
    minutes. A second start while one runs is ignored, and pr_state.py's own lock covers the rest.

    IT REFUSES TO REGISTER OR UNINSTALL INSIDE CLAUDE CODE. The task runs, unattended every 2
    minutes, a script from the primary checkout that any session can edit. The owner does both from a
    plain terminal. -WhatIf, and -Json without -Uninstall, change nothing and are allowed anywhere.

    THE HOST CHECK. -ExpectedHost names the machine this must run on. Registering or removing a task
    on the wrong PC is the mistake the check exists for, so both refuse without it. One poller per PC
    is the design, so the name is a parameter rather than one machine written in.

.PARAMETER ExpectedHost
    The machine this run is meant for, as [Environment]::MachineName prints it. Required unless
    -WhatIf or -Json is given.

.PARAMETER Python
    The pythonw.exe the task runs. Default: the first pythonw.exe on PATH. pr_state.py needs 3.11+.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-pr-state-task.ps1 -WhatIf
    pwsh -NoProfile -File scripts\coord\install-pr-state-task.ps1 -ExpectedHost MEFORDEV01
    pwsh -NoProfile -File scripts\coord\install-pr-state-task.ps1 -ExpectedHost MEFORDEV01 -Uninstall
#>
[CmdletBinding()]
param(
    [string]$ExpectedHost,
    [string]$Python,
    [ValidateRange(1, 60)][int]$EveryMinutes = 2,
    [string]$TaskName = 'MEFOR-PR-State',
    [switch]$Uninstall,
    [switch]$WhatIf,
    [switch]$Json
)

# Host circuit breaker (CLAUDE.md section 5, script form). Nothing above this line touches the machine.
if ($ExpectedHost -and [Environment]::MachineName -ne $ExpectedHost) { & { $ErrorActionPreference = 'Stop'; throw "STOP     this must run on $ExpectedHost, but this is $([Environment]::MachineName); nothing ran" } }

$ErrorActionPreference = 'Stop'

function Stop-Install([string]$Message) {
    [Console]::Error.WriteLine("install-pr-state-task: $Message")
    exit 2
}

$preview = $WhatIf -or ($Json -and -not $Uninstall)
if (-not $preview -and -not $ExpectedHost) {
    Stop-Install "pass -ExpectedHost <this machine's name> to register or remove the task. This machine is $([Environment]::MachineName)."
}
if (-not $preview -and $env:CLAUDECODE -eq '1') {
    Stop-Install 'refusing to change the task store inside Claude Code: the task would run, unattended, a script any session can edit. Run this from a plain terminal. (-WhatIf, and -Json without -Uninstall, change nothing and are allowed.)'
}
if (-not $IsWindows) { Stop-Install 'Windows only: this manages a Windows scheduled task.' }

# --- -Uninstall -----------------------------------------------------------------------------------
if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    $result = [ordered]@{ taskName = $TaskName; whatIf = [bool]$WhatIf; registered = [bool]$existing; removed = $false }
    if ($existing -and -not $WhatIf) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        $result.removed = $true
    }
    if ($Json) { $result | ConvertTo-Json -Depth 4 }
    elseif ($WhatIf) { Write-Output "-WhatIf: would remove task '$TaskName' (registered: $($result.registered))." }
    elseif ($result.removed) { Write-Output "Removed scheduled task '$TaskName'. The cache file stays; readers will see its fetchedAt age." }
    else { Write-Output "No scheduled task '$TaskName' to remove." }
    exit 0
}

# --- plan -----------------------------------------------------------------------------------------
. "$PSScriptRoot\occupancy.ps1"
$occ = Get-WorktreeOccupancy -Repo $PSScriptRoot
if (-not $occ.RepoFound) { Stop-Install "not inside a git repository: $PSScriptRoot" }
$primary = $occ.PrimaryPath
$poller = Join-Path $primary 'scripts/coord/pr_state.py'
$pollerExists = Test-Path -LiteralPath $poller -PathType Leaf

if (-not $Python) {
    $cmd = Get-Command pythonw.exe -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($cmd) { $Python = $cmd.Source }
}
$pythonExists = [bool]$Python -and (Test-Path -LiteralPath $Python -PathType Leaf)
# A venv or worktree interpreter dies with its directory, and the task would then fail with nothing
# saying so. pythonw reports nothing either, so check the version through its python.exe sibling.
$pythonProblem = $null
if ($pythonExists -and (Split-Path -Leaf $Python) -ne 'pythonw.exe') {
    $pythonProblem = "$Python is not pythonw.exe; any other interpreter opens a window every run"
} elseif ($pythonExists) {
    $full = [System.IO.Path]::GetFullPath($Python)
    if ($full -match '[\\/](\.venv|venv|\.claude[\\/]worktrees)[\\/]') {
        $pythonProblem = "$full is inside a venv or worktree; pass -Python with an installed interpreter's pythonw.exe"
    } else {
        $sibling = Join-Path (Split-Path -Parent $full) 'python.exe'
        $ok = if (Test-Path -LiteralPath $sibling -PathType Leaf) { (& $sibling -c 'import sys; print(sys.version_info >= (3, 11))' 2>$null) } else { $null }
        if ("$ok".Trim() -ne 'True') { $pythonProblem = "could not confirm Python 3.11+ for $full (via $sibling)" }
    }
}
$ghExists = [bool](Get-Command gh -CommandType Application -ErrorAction SilentlyContinue)

$runLevel = 'Limited'
$logonType = 'Interactive'
# Keep under pr_state.py's STALE_LOCK_SECONDS (15 min).
$timeLimitMinutes = 10
$userId = if ($env:USERDOMAIN) { "$env:USERDOMAIN\$env:USERNAME" } else { $env:USERNAME }
$coordDir = Join-Path (& git -C $primary rev-parse --path-format=absolute --git-common-dir).Trim() 'mefor-coord'
$cache = Join-Path $coordDir 'pr-state.json'
# --coord-dir spares the poller a git process, which would open a console window under pythonw.
$argument = "`"$poller`" --coord-dir `"$coordDir`""

$plan = [ordered]@{
    taskName = $TaskName
    host = [Environment]::MachineName
    executable = $Python
    executableExists = $pythonExists
    executableProblem = $pythonProblem
    argument = $argument
    workingDirectory = $primary
    poller = $poller
    pollerExists = $pollerExists
    ghOnPath = $ghExists
    cache = $cache
    trigger = [ordered]@{ kind = 'repeating'; everyMinutes = $EveryMinutes }
    userId = $userId
    logonType = $logonType
    runLevel = $runLevel
    executionTimeLimitMinutes = $timeLimitMinutes
    multipleInstances = 'IgnoreNew'
}

if ($preview) {
    if ($Json) { $plan | ConvertTo-Json -Depth 4 }
    else {
        Write-Output "-WhatIf: nothing was registered."
        Write-Output "Task '$TaskName' on $($plan.host): every $EveryMinutes min, as $userId ($logonType logon, run level $runLevel)."
        Write-Output "  runs:   $Python $argument"
        Write-Output "  in:     $primary"
        Write-Output "  writes: $cache"
        if (-not $pythonExists) { Write-Output "  MISSING: pythonw.exe (pass -Python)" }
        elseif ($pythonProblem) { Write-Output "  PROBLEM: $pythonProblem" }
        if (-not $pollerExists) { Write-Output "  MISSING: $poller (the change has not reached the primary checkout)" }
        if (-not $ghExists) { Write-Output "  MISSING: gh on PATH" }
    }
    exit 0
}

# --- register (idempotent: -Force replaces an existing definition) --------------------------------
if (-not $pythonExists) { Stop-Install "no pythonw.exe found; pass -Python <path to pythonw.exe>." }
if ($pythonProblem) { Stop-Install $pythonProblem }
if (-not $pollerExists) {
    Stop-Install "pr_state.py is not in the primary checkout: $poller. Bring the primary to origin/main first."
}

try {
    $action = New-ScheduledTaskAction -Execute $Python -Argument $argument -WorkingDirectory $primary
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval (New-TimeSpan -Minutes $EveryMinutes)
    $principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType $logonType -RunLevel $runLevel
    $settings = New-ScheduledTaskSettingsSet -StartWhenAvailable -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries `
        -ExecutionTimeLimit (New-TimeSpan -Minutes $timeLimitMinutes) -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings `
        -Description 'One poll of open PRs and the merge queue into mefor-coord/pr-state.json (scripts/coord/pr_state.py).' -Force | Out-Null
}
catch { Stop-Install "the task store refused: $($_.Exception.Message)" }

Write-Output "Registered '$TaskName' on $([Environment]::MachineName): every $EveryMinutes min."
Write-Output "  runs:   $poller"
Write-Output "  writes: $cache"
exit 0
