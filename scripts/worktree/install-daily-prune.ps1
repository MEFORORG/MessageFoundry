# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Register a daily Windows scheduled task that runs run-daily-prune.ps1 against the PRIMARY checkout.

.DESCRIPTION
    prune-merged.ps1 has existed and been safe for a long time. Nothing ever ran it on a schedule, so
    sibling worktrees accumulated: measured 2026-09-18, 112 registered worktrees against 5 live sessions
    and 38 GB under .claude/worktrees. This installer closes that gap and nothing else.

    IT DEFAULTS TO A DRY RUN, AND THAT DEFAULT IS LOAD-BEARING. The registered task runs WITHOUT -Apply,
    so it only ever writes a decision table to the log. You read a few days of logs, and only then re-run
    this installer with -Apply. A scheduler that starts destroying worktrees on the day it is installed
    gives nobody a chance to notice it is wrong about occupancy.

    IT REGISTERS A TRACKED SCRIPT, NOT MANUFACTURED TEXT. The task action is a plain -File call to
    run-daily-prune.ps1, so what runs nightly is a file you can diff, test and read out of Task Scheduler.
    This was briefly a base64 -EncodedCommand built from a here-string; run-daily-prune.ps1's header
    records why that was wrong.

    SCOPE IS THE SIBLING WORKTREES ONLY. prune-merged.ps1 excludes anything under a `.claude/worktrees/`
    path segment by design -- that is the population EnterWorktree relocates LIVE sessions into, and
    claude-code issue 92342 (open) is exactly that the harness's own cleanup does not fire for adopted
    worktrees. This installer does not widen that scope and must not be made to. Those 73 worktrees need
    their own occupancy fence, which is a different piece of work.

    THE TASK RUNS AS YOU, INTERACTIVELY, NOT AS SYSTEM. prune-merged.ps1's liveness fence reads each
    Claude config root's sessions/<pid>.json to decide what is occupied. As SYSTEM those roots are a
    different profile, the fence reads nothing, and a fence that cannot look is a fence that vetoes
    nothing. Registering this to run whether-or-not-logged-on would quietly convert the safest check in
    the script into a no-op, so it is deliberately registered -RunLevel Limited under the calling user.

.PARAMETER Apply
    Register the task to actually remove worktrees. Omit this -- the default -- and the task dry-runs and
    logs. Re-run the installer with -Apply once the logs look right; registration is idempotent.

.PARAMETER At
    Daily start time, 24h "HH:mm". Default 03:30, chosen to be outside any plausible working session --
    the recent-activity veto is measured in hours, so a run that lands mid-afternoon vetoes nearly
    everything and teaches you nothing.

.PARAMETER Json
    Emit the resolved plan and REGISTER NOTHING. This is what the tests assert against, so they never
    touch the machine's task store.

.EXAMPLE
    pwsh -File scripts\worktree\install-daily-prune.ps1              # dry-run task, 03:30 daily
    pwsh -File scripts\worktree\install-daily-prune.ps1 -Apply       # promote it to actually remove
    pwsh -File scripts\worktree\install-daily-prune.ps1 -Json        # show the plan, register nothing
    pwsh -File scripts\worktree\install-daily-prune.ps1 -Uninstall   # remove the task
#>
[CmdletBinding()]
param(
    # Register the task WITH -Apply. Default is a logging dry run; see the header.
    [switch]$Apply,
    # Daily start time, "HH:mm".
    [string]$At = '03:30',
    # Hours of inactivity before a worktree stops being treated as occupied. Passed straight through.
    # Left at prune-merged.ps1's own default when not set, rather than duplicated here: a second copy of
    # a safety default drifts, and the copy that drifts is the one nobody tests.
    [double]$IdleHours,
    # Print the resolved plan as JSON and register nothing.
    [switch]$Json,
    # Remove the task.
    [switch]$Uninstall,
    # Task name in the root task folder. Also what lets the tests target a decoy name.
    [string]$TaskName = 'MEFOR-Worktree-Prune',
    # Where the task writes its transcript. Outside the repo on purpose -- a log inside .git is invisible
    # to the operator and a log inside the tree is a commit waiting to happen.
    [string]$LogDir
)

$ErrorActionPreference = 'Stop'

# Same refusal its sibling installers carry, and for a stronger reason than either of them. This one
# registers a SCHEDULED TASK that runs, unattended and repeatedly, a script whose whole job is deleting
# worktrees -- from a copy of that script the calling session can freely edit. A session that can edit
# prune-merged.ps1 and then schedule it has arranged for its own edits to run later with no reviewer.
if ($env:CLAUDECODE -eq '1' -and -not $Json) {
    throw "Refusing to run inside Claude Code. This schedules prune-merged.ps1 -- a script that deletes worktrees -- to run unattended, from a checkout the calling session can edit. Run it from a plain pwsh terminal. (-Json is allowed: it registers nothing.)"
}

if (-not $IsWindows) { throw "Windows-only: this registers a Windows scheduled task." }

. "$PSScriptRoot\..\coord\occupancy.ps1"

# The primary comes from the SAME helper prune-merged.ps1 validates its own -RepoRoot against, so the
# scheduler and the script it schedules cannot disagree about which checkout is the primary. Deriving it
# independently (a --git-common-dir parent, say) agrees today by luck; when it stops agreeing,
# prune-merged.ps1:236 exits REFUSED and the task logs REFUSED every night forever with nothing pruned
# and nothing reporting that the scheduler is aimed wrong.
$occ = Get-WorktreeOccupancy -Repo $PSScriptRoot
if (-not $occ.RepoFound) { throw "Not inside a git repository: $PSScriptRoot" }
$repoRoot = $occ.PrimaryPath

# The PRIMARY's copy of the runner, never $PSScriptRoot's. This installer is usually run from a worktree,
# and a worktree is by construction a thing somebody deletes -- scheduling its copy registers a daily task
# pointed at a path that disappears, and Task Scheduler's only complaint is a nonzero result code in a
# history nobody reads. The task must outlive the checkout that installed it.
$runner = Join-Path $repoRoot 'scripts/worktree/run-daily-prune.ps1'
$runnerExists = Test-Path -LiteralPath $runner
# NOT a throw here. -Json is a preview, and a preview that refuses to render is useless exactly when you
# most want to look at it -- from a worktree whose change has not landed on the primary yet. The plan
# reports the miss as a field; registration below is what refuses.

if (-not $LogDir) {
    $base = if ($env:LOCALAPPDATA) { $env:LOCALAPPDATA } else { [Environment]::GetFolderPath('LocalApplicationData') }
    $LogDir = Join-Path $base 'MessageFoundry/worktree-prune'
}

$pwshExe = (Get-Process -Id $PID).Path
$mode    = if ($Apply) { 'APPLY' } else { 'DRYRUN' }

# ONE definition of every value the task is built from, read by both the plan and the registration below.
# The principal trio were separate literals until a mutation test caught it: flipping the registration to
# -RunLevel Highest left the -Json plan still reporting "Limited", so the plan asserted a privilege level
# the task did not have and every test reading the plan stayed green. A plan that is not derived from the
# thing it describes is not a preview, it is a second claim that drifts.
$runLevel  = 'Limited'      # never Highest: see the header on why SYSTEM/elevation blinds the fence
$logonType = 'Interactive'
$userId    = "$env:USERDOMAIN\$env:USERNAME"

# Quoted because a path with a space would otherwise split into two arguments and silently prune, or fail
# to prune, somewhere nobody is looking.
$taskArgument = "-NoProfile -NonInteractive -ExecutionPolicy Bypass -File `"$runner`" -LogDir `"$LogDir`" -Label `"$TaskName`""
if ($Apply) { $taskArgument += ' -Apply' }
if ($PSBoundParameters.ContainsKey('IdleHours')) { $taskArgument += " -IdleHours $IdleHours" }

$plan = [ordered]@{
    taskName   = $TaskName
    mode       = $mode
    repoRoot   = $repoRoot
    runner     = $runner
    runnerExists = $runnerExists
    argument   = $taskArgument
    at         = $At
    logDir     = $LogDir
    executable = $pwshExe
    runLevel   = $runLevel
    logonType  = $logonType
    userId     = $userId
}

if ($Json) { $plan | ConvertTo-Json -Depth 5; exit 0 }

# --- Uninstall -------------------------------------------------------------------------------------
if ($Uninstall) {
    $existing = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    if ($existing) {
        Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false
        Write-Host "Removed scheduled task '$TaskName'."
    } else {
        Write-Host "No scheduled task '$TaskName' to remove."
    }
    exit 0
}

# --- Register (idempotent: -Force replaces an existing definition) ----------------------------------
# Refuse here rather than at resolution time, so -Json above could still render the plan that shows this.
if (-not $runnerExists) {
    throw "run-daily-prune.ps1 is not in the primary checkout: $runner`nIf it exists in the worktree you are standing in, the change has not landed yet -- merge it before scheduling it. A task pointed at a worktree copy dies with that worktree."
}

$action    = New-ScheduledTaskAction -Execute $pwshExe -Argument $taskArgument -WorkingDirectory $repoRoot
$trigger   = New-ScheduledTaskTrigger -Daily -At $At
# Built from the SAME variables the -Json plan reports, so the preview cannot drift from the registration.
$principal = New-ScheduledTaskPrincipal -UserId $userId -LogonType $logonType -RunLevel $runLevel
# StartWhenAvailable so a machine that was asleep at 03:30 still runs it; ExecutionTimeLimit so a wedged
# run cannot sit holding the repo forever.
$settings  = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Hours 1) -MultipleInstances IgnoreNew

Register-ScheduledTask -TaskName $TaskName -Action $action -Trigger $trigger -Principal $principal -Settings $settings -Force | Out-Null

Write-Host "Registered '$TaskName': daily at $At, mode $mode."
Write-Host "  repo: $repoRoot"
Write-Host "  runs: $runner"
Write-Host "  logs: $LogDir"
if (-not $Apply) {
    Write-Host ""
    Write-Host "This task DRY RUNS. It will not remove anything." -ForegroundColor Yellow
    Write-Host "Read a few days of logs, then re-run this installer with -Apply."
}
