# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Run prune-merged.ps1 once, log the transcript and the meaning of its exit code, and rotate old logs.

.DESCRIPTION
    This is the body of the daily scheduled task that install-daily-prune.ps1 registers. It exists as a
    tracked file rather than as text the installer manufactures, and that is the whole point of it.

    It was a base64 `-EncodedCommand` string built from a here-string inside the installer. Three
    independent review passes flagged the same shape, and they were right about all of it: the only copy
    of this logic lived inside a string, so it could not be diffed, could not be tested, could not be read
    out of Task Scheduler without decoding a blob, and mixed build-time with run-time interpolation where
    a single missing backtick silently freezes a value at install time. Ten lines of untestable logic in
    the one component whose job is deciding whether deletions happened is a bad trade at any size.

    IT DOES NOT DECIDE ANYTHING ABOUT THE SIBLINGS. Every safety judgement on them stays in
    prune-merged.ps1: what is merged, what is occupied, what is locked, what gets removed. This script
    starts that one, records what it said, and passes its exit code back.

    -RemoveFinishedClaudeWorktrees ADDS ONE OPT-IN STEP, and it is the only thing here that can touch
    .claude/worktrees. prune-merged.ps1 still removes nothing there; it lists the trees there that look
    finished, under REPORT-ONLY. After the prune run, this step runs prune-merged.ps1 AGAIN with -Json,
    in the same invocation, and takes that fresh list -- never a table from an earlier run. It keeps the
    rows under a `.claude/worktrees/` path segment and hands them to finished-worktree-removal.ps1, which
    re-checks each one immediately before acting and removes it with a plain `git worktree remove`, never
    with --force. That file's header lists the re-checks. Each removed or refused path is logged with its
    reason, then a summary line with the counts and the drive's free space. A refusal is data, not a
    failure, and leaves the exit code alone. Without -Apply the step only logs WOULD-REMOVE. With
    -Apply it refuses to run inside Claude Code, the same refusal install-daily-prune.ps1 carries.

.PARAMETER RepoRoot
    The primary checkout to prune. Defaults to the value the shared liveness fence calls the primary --
    the SAME source prune-merged.ps1 checks its own -RepoRoot against -- so the two can never disagree.

.PARAMETER Apply
    Forwarded to prune-merged.ps1. Omitted, the run is a dry run that removes nothing. It also arms the
    -RemoveFinishedClaudeWorktrees step; without it, that step only reports.

.PARAMETER RemoveFinishedClaudeWorktrees
    Opt in to the .claude/worktrees step described above. Off by default.

.PARAMETER KeepLogs
    How many dated logs to keep. Older ones are deleted after each run.

.EXAMPLE
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs            # dry run, logged
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs -Apply     # actually prune
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs -RemoveFinishedClaudeWorktrees          # also list what it would remove
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs -Apply -RemoveFinishedClaudeWorktrees   # and remove it
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$Apply,
    [switch]$RemoveFinishedClaudeWorktrees,
    [double]$IdleHours,
    [Parameter(Mandatory)][string]$LogDir,
    [string]$Label = 'MEFOR-Worktree-Prune',
    [int]$KeepLogs = 30
)

$ErrorActionPreference = 'Stop'

# The same refusal install-daily-prune.ps1 carries, for the one combination that removes Claude-managed
# trees: a session that can run this from a checkout it can edit could remove other sessions'
# .claude/worktrees trees with no reviewer, and worktree_gate.ps1 deliberately gives sessions no route
# to that population. The dry run stays usable in-session.
if ($env:CLAUDECODE -eq '1' -and $Apply -and $RemoveFinishedClaudeWorktrees) {
    throw "Refusing -Apply -RemoveFinishedClaudeWorktrees inside Claude Code: it removes Claude-managed worktrees. Run it from a plain terminal, or from the scheduled task install-daily-prune.ps1 registers. (Without -Apply it only reports, and is allowed.)"
}

# prune-merged.ps1 reports its verdict through the exit code, so a non-zero exit is DATA here, not a
# failure to be turned into a throw. Same reason that script sets this; the reason survives the call.
$PSNativeCommandUseErrorActionPreference = $false

. "$PSScriptRoot\..\coord\occupancy.ps1"

# What each exit code MEANS. prune-merged.ps1 owns the contract -- it defines $EXIT_OK/$EXIT_FAILED/
# $EXIT_REFUSED/$EXIT_ORPHANED -- and this is a second copy of it, which is a real cost and is deliberate:
# moving the logging into that 1502-line safety-critical script is the deeper fix and belongs in its own
# change. The drift that copy invites is held shut by a test instead:
# tests/test_worktree_install_daily_prune.py::test_the_exit_code_table_matches_prune_merged parses the
# constants out of prune-merged.ps1 and fails if this table stops matching. A second definition nobody can
# silently desync is a smaller problem than an unreviewable one.
$EXIT_MEANING = @{
    0 = 'OK'
    1 = 'FAILED -- something was attempted and did not fully succeed'
    2 = 'REFUSED -- safety could not be established, nothing was attempted'
    3 = 'ORPHANED DIRECTORY -- a worktree is broken on disk right now; needs a human'
}

$prune = Join-Path $PSScriptRoot 'prune-merged.ps1'
if (-not (Test-Path -LiteralPath $prune)) { throw "prune-merged.ps1 not found beside this script: $prune" }

# Resolve the primary through the SAME helper prune-merged.ps1 validates against (occupancy.ps1's
# PrimaryPath, which is git's first `worktree list` entry). Resolving it any other way -- a
# --git-common-dir parent, say -- gives an answer that is right today by agreement rather than by
# construction, and the failure when they diverge is silent: prune-merged.ps1:236 exits REFUSED, the task
# logs REFUSED every night forever, and nothing anywhere reports that the scheduler is pointed wrong.
if (-not $RepoRoot) {
    $occ = Get-WorktreeOccupancy -Repo $PSScriptRoot
    if (-not $occ.RepoFound) { throw "Not inside a git repository: $PSScriptRoot" }
    $RepoRoot = $occ.PrimaryPath
}

$pruneArgs = @('-RepoRoot', $RepoRoot)
if ($Apply) { $pruneArgs += '-Apply' }
if ($PSBoundParameters.ContainsKey('IdleHours')) { $pruneArgs += @('-IdleHours', $IdleHours) }

$mode = if ($Apply) { 'APPLY' } else { 'DRYRUN' }

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$log = Join-Path $LogDir ("prune-" + (Get-Date -Format 'yyyy-MM-dd') + ".log")

"=== $Label $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') mode=$mode repo=$RepoRoot ===" | Add-Content -LiteralPath $log
& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $prune @pruneArgs *>&1 |
    Add-Content -LiteralPath $log
$code = $LASTEXITCODE

if ($RemoveFinishedClaudeWorktrees) {
    . (Join-Path $PSScriptRoot 'finished-worktree-removal.ps1')
    "--- finished .claude/worktrees: mode=$mode ---" | Add-Content -LiteralPath $log

    # A FRESH list, from a second prune-merged.ps1 run in this invocation, after the prune above. Always
    # a dry run (-Json without -Apply) and -SkipGh: the report-only set does not read merge signals.
    $listArgs = @('-RepoRoot', $RepoRoot, '-Json', '-SkipGh')
    if ($PSBoundParameters.ContainsKey('IdleHours')) { $listArgs += @('-IdleHours', $IdleHours) }
    $raw = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $prune @listArgs 2>&1)
    $listExit = $LASTEXITCODE
    $stderrLines = @($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] } | ForEach-Object { "  stderr: $_" })
    if ($stderrLines.Count -gt 0) { $stderrLines | Add-Content -LiteralPath $log }
    $listing = $null
    try { $listing = (@($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n") | ConvertFrom-Json -ErrorAction Stop }
    catch { "  could not parse the listing run's JSON (exit $listExit): $($_.Exception.Message)" | Add-Content -LiteralPath $log }

    if ($null -eq $listing -or $null -eq $listing.fence -or $null -eq $listing.fence.idleHours) {
        # Not a refusal of one tree but of the whole step. 2 promises nothing was removed, which holds
        # only on a dry run: under -Apply the prune above may already have removed siblings, so the
        # refusal is reported as 1, the same rule prune-merged.ps1 applies to its own refusals.
        "=== finished .claude/worktrees: SKIPPED, the finished list could not be read; no .claude/worktrees tree was attempted ===" | Add-Content -LiteralPath $log
        $code = [math]::Max($code, $(if ($Apply) { 1 } else { 2 }))
    }
    else {
        $finished = @($listing.reportOnly | Where-Object { $_.claudeManaged -eq $true })
        $outside = @($listing.reportOnly).Count - $finished.Count
        "  listed finished: $($finished.Count) under .claude/worktrees; $outside elsewhere, left alone; $($listing.counts.reportOnlyHeld) withheld by prune-merged.ps1 (listing exit $listExit)" |
            Add-Content -LiteralPath $log

        # Never the worktree this run executes from, nor the one the shell stands in. The scheduled task
        # runs from the primary, which is refused anyway; a hand run from a worktree must not remove it.
        $protect = @($PSScriptRoot, (Get-Location).Path) | ForEach-Object {
            $top = & git -C $_ rev-parse --show-toplevel 2>$null
            if ($LASTEXITCODE -eq 0 -and $top) { ([string]$top).Trim() }
        }
        # The helper returns each input path unchanged, so the raw path is the key.
        $why = @{}
        foreach ($f in $finished) { $why[$f.path] = $f }

        # Logged per row as the helper emits it, not after it returns: a run killed part way (the task's
        # one-hour limit, say) still leaves the record of every tree it already removed.
        $rows = @(Invoke-FinishedWorktreeRemoval -Primary $RepoRoot -Paths @($finished | ForEach-Object { $_.path }) `
                -IdleHours ([double]$listing.fence.idleHours) -Protect $protect -Apply:$Apply | ForEach-Object {
                $f = $why[$_.Path]
                $detail = if ($_.Outcome -in 'REMOVED', 'WOULD-REMOVE') { "$($_.Reason) [$($f.branch)]; listed because: $($f.whyFinished)" } else { $_.Reason }
                $lines = @("  {0,-12} {1} -- {2}" -f $_.Outcome, $_.Path, $detail)
                if ($_.Outcome -eq 'WOULD-REMOVE') { $lines += "               would run: $($_.Command)" }
                $lines | Add-Content -LiteralPath $log
                $_
            })

        $byOutcome = @{}
        foreach ($r in $rows) { $byOutcome[$r.Outcome] = 1 + [int]$byOutcome[$r.Outcome] }
        $n = { param($o) [int]$byOutcome[$o] }
        $free = 'unknown'
        try {
            $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($RepoRoot))
            $free = "{0:N1} GB free on {1}" -f ($drive.AvailableFreeSpace / 1GB), $drive.Name
        }
        catch [System.ArgumentException], [System.IO.IOException], [System.UnauthorizedAccessException] {
            $free = "free space unreadable: $($_.Exception.Message)"
        }
        "=== finished .claude/worktrees: mode=$mode listed=$($finished.Count) removed=$(& $n 'REMOVED') wouldRemove=$(& $n 'WOULD-REMOVE') refused=$(& $n 'REFUSED') declined=$(& $n 'DECLINED') failed=$(& $n 'FAILED') orphaned=$(& $n 'ORPHANED'); $free ===" |
            Add-Content -LiteralPath $log

        # Refusals leave the code alone, and so does git declining a tree every re-check passed: nothing
        # changed, and the DECLINED line is there to be read. A removal that failed is a failure, and a
        # deregistered tree still on disk is an orphan -- the same severity order prune-merged.ps1 uses.
        if ((& $n 'FAILED') -gt 0) { $code = [math]::Max($code, 1) }
        if ((& $n 'ORPHANED') -gt 0) { $code = [math]::Max($code, 3) }
    }
}

$meaning = if ($EXIT_MEANING.ContainsKey($code)) { $EXIT_MEANING[$code] } else { "UNKNOWN exit code $code" }
"=== exit $code ($meaning) ===" | Add-Content -LiteralPath $log

# Keep the log directory bounded. -ErrorAction SilentlyContinue because a log a human has open must not
# turn a successful prune into a failed task run.
Get-ChildItem -LiteralPath $LogDir -Filter 'prune-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip $KeepLogs |
    Remove-Item -Force -ErrorAction SilentlyContinue

exit $code
