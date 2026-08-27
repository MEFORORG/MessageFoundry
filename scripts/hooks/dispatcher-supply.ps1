# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
# Stop hook: the DISPATCHER does not end a turn with the builders running dry.
#
# WHY THIS EXISTS. Owner-set 2026-08-26, as a correction to this seat. The dispatcher's MAJOR DUTY
# is keeping every builder lane supplied with 2 to 4 tasks that they execute as background
# workflows. The point is throughput against the backlog: the owner is buying session tokens, and
# an idle builder converts none of them into landed work. A dispatcher polishing its own status
# board while two lanes sit empty is spending the budget on the instrument instead of the work.
#
# THAT IS EXACTLY WHAT HAPPENED. Both builder lanes were idle for hours on 2026-08-26 -- one for
# about 28 hours -- while this seat measured, rendered and re-rendered a board. The owner noticed
# before the dispatcher did, twice.
#
# WHAT IT DOES. On every dispatcher Stop, count the queued tasks per builder lane and block the
# stop if any lane is below the floor. It does not choose work and it does not dispatch: it only
# refuses to let the seat go quiet with lanes empty.
#
# THE QUEUE IS A FILE PER LANE, one task per line, written by the dispatcher when it dispatches:
#     <coord>\queue\<lane>.tsv       status <TAB> item <TAB> one-line description
# Lines whose first field is `done` or `cancelled` do not count toward the floor. A missing file
# counts as ZERO, never as "unknown" -- an unreadable queue is an empty one for this purpose,
# because the failure it guards against is silence.
#
# THE WAYS OUT, and they are the same two the builder nudge honours, for the same reason:
#     a declared work freeze     <coord>\FREEZE
#     an owner stop instruction  <coord>\stop\ALL  or  <coord>\stop\dispatcher
# Plus the same safety valve: a Stop hook that always blocks is an infinite loop. After
# $MaxNudges blocks in $WindowMinutes it lets the stop through and says loudly that the hook is
# broken, because at that point it is.
#
# FAIL-OPEN ON EVERY ERROR. ASCII-only. No glyphs.

$ErrorActionPreference = 'SilentlyContinue'

$FloorPerLane  = 2
$TargetPerLane = 4
$MaxNudges     = 8
$WindowMinutes = 30

function Allow([string]$why) {
    if ($why) { Write-Output "[dispatcher-supply] allowing stop: $why" }
    exit 0
}

try {
    $common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { Allow 'not a git checkout' }
    $coord = Join-Path $common.Trim() 'mefor-coord'
    if (-not (Test-Path -LiteralPath $coord)) { Allow 'no coordination directory' }

    $top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $top) { Allow 'no worktree path' }
    $seat = Split-Path $top.Trim() -Leaf

    # Case-insensitive: the live fleet has carried four different casings in one render.
    if ($seat -notmatch '(?i)dispatcher') { Allow "seat '$seat' is not the dispatcher" }

    if (Test-Path -LiteralPath (Join-Path $coord 'FREEZE')) { Allow 'work freeze in effect' }
    foreach ($f in @('stop\ALL', "stop\$seat")) {
        if (Test-Path -LiteralPath (Join-Path $coord $f)) { Allow "owner stop flag $f" }
    }

    # --- which builder lanes are live? ---------------------------------------------------------
    # Derived from git's own worktree list, so a lane that has been removed stops being counted
    # without anyone editing this script.
    $lanes = @(
        (& git worktree list --porcelain 2>$null) |
        Where-Object { $_ -like 'worktree *' } |
        ForEach-Object { ($_ -split ' ', 2)[1].Trim().TrimEnd('\', '/') } |
        ForEach-Object { Split-Path $_ -Leaf } |
        Where-Object { $_ -match '(?i)^builder' } |
        Sort-Object -Unique
    )
    if (-not $lanes -or $lanes.Count -eq 0) { Allow 'no builder lanes exist' }

    # --- count each lane's open queue ----------------------------------------------------------
    $short = @()
    $report = @()
    foreach ($lane in $lanes) {
        $q = Join-Path $coord ("queue\" + $lane + ".tsv")
        $open = 0
        if (Test-Path -LiteralPath $q) {
            $open = @(Get-Content -LiteralPath $q -ErrorAction SilentlyContinue |
                Where-Object { $_.Trim() -and -not $_.StartsWith('#') } |
                Where-Object { ($_ -split "`t")[0].Trim().ToLower() -notin @('done', 'cancelled', 'status') }
            ).Count
        }
        $report += ("    {0,-24} {1} open" -f $lane, $open)
        if ($open -lt $FloorPerLane) { $short += "$lane ($open)" }
    }

    if ($short.Count -eq 0) {
        Allow ("every builder lane has at least $FloorPerLane queued`n" + ($report -join "`n"))
    }

    # --- safety valve --------------------------------------------------------------------------
    $state = Join-Path $coord 'nudge'
    if (-not (Test-Path -LiteralPath $state)) { New-Item -ItemType Directory -Path $state -Force | Out-Null }
    $log = Join-Path $state 'dispatcher-supply.log'
    $now = (Get-Date).ToUniversalTime()
    $recent = @()
    if (Test-Path -LiteralPath $log) {
        # $t MUST start as a DateTime -- with $null, [ref]$t is [ref][object] and TryParse throws,
        # which the catch below would swallow, silently disabling this guard. That exact bug shipped
        # in builder-nudge.ps1 earlier today and was caught only by testing the valve itself.
        $recent = @(Get-Content -LiteralPath $log -ErrorAction SilentlyContinue | ForEach-Object {
            $t = [DateTime]::MinValue
            if ([DateTime]::TryParse($_, [ref]$t)) { $t.ToUniversalTime() }
        } | Where-Object { $_ -and ($now - $_).TotalMinutes -lt $WindowMinutes })
    }
    if ($recent.Count -ge $MaxNudges) {
        Write-Output "[dispatcher-supply] SAFETY VALVE: blocked $($recent.Count) times in $WindowMinutes min and the queues are still short. THIS IS A DEFECT IN THE HOOK OR THE QUEUE FILES, not a supply problem. Letting the stop through."
        Remove-Item -LiteralPath $log -Force -ErrorAction SilentlyContinue
        exit 0
    }
    Add-Content -LiteralPath $log -Value $now.ToString('o') -ErrorAction SilentlyContinue

    $msg = @"
[dispatcher-supply] DO NOT STOP. BUILDER LANES ARE BELOW THE FLOOR.

    short: $($short -join ', ')

$($report -join "`n")

YOUR MAJOR DUTY IS SUPPLY, NOT REPORTING. Owner-set 2026-08-26. Every builder lane should hold
$FloorPerLane to $TargetPerLane tasks it can execute as BACKGROUND WORKFLOWS. The purpose is throughput
against the backlog: the owner is buying session tokens, and an idle lane converts none of them
into landed work. Measuring the fleet is not the job; keeping it fed is.

THIS HOOK EXISTS BECAUSE THIS SEAT GOT THAT WRONG. Both builder lanes sat idle for hours on
2026-08-26, one of them about 28 hours, while this seat rendered and re-rendered a status board.
The owner spotted it before the dispatcher did, twice.

DO THIS NOW:
  1. Pick work from the backlog. Prefer items that a builder can run as a background workflow
     without another decision -- an unresolved dependency turns a task into a question.
  2. Dispatch it to the lane, and tell the builder to run it as a background workflow.
  3. Record it, one line per task, or this hook cannot see it:

         <status>  <item>  <one-line description>       (TAB separated)
         $coord\queue\<lane>.tsv

     Mark a line `done` or `cancelled` when it closes. Those stop counting toward the floor.

DO NOT MANUFACTURE WORK TO SILENCE THIS. An empty backlog is a real answer -- but say it to the
owner rather than to a queue file. Padding the queue defeats the only thing this hook measures.

CHECK FOR A DOUBLE-DISPATCH BEFORE YOU SEND. Another seat put five tasks into these lanes on
2026-08-26 without knowing this seat had dispatched into the same lane minutes earlier, and one
item went to two builders at once. Read the lane's queue file first.

THE ONLY WAYS OUT ARE THE OWNER'S:
    a declared work freeze     $coord\FREEZE
    an owner stop instruction  $coord\stop\ALL   or   $coord\stop\$seat
"@
    [Console]::Error.WriteLine($msg)
    exit 2
}
catch {
    Write-Output "[dispatcher-supply] error, allowing stop: $($_.Exception.Message)"
    exit 0
}
