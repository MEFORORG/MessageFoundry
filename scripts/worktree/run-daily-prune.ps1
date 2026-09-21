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

    IT DOES NOT DECIDE ANYTHING. Every safety judgement stays in prune-merged.ps1: what is merged, what is
    occupied, what is locked, what gets removed. This script starts that one, records what it said, and
    passes its exit code back unchanged.

.PARAMETER RepoRoot
    The primary checkout to prune. Defaults to the value the shared liveness fence calls the primary --
    the SAME source prune-merged.ps1 checks its own -RepoRoot against -- so the two can never disagree.

.PARAMETER Apply
    Forwarded to prune-merged.ps1. Omitted, the run is a dry run that removes nothing.

.PARAMETER KeepLogs
    How many dated logs to keep. Older ones are deleted after each run.

.EXAMPLE
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs            # dry run, logged
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs -Apply     # actually prune
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$Apply,
    [double]$IdleHours,
    [Parameter(Mandatory)][string]$LogDir,
    [string]$Label = 'MEFOR-Worktree-Prune',
    [int]$KeepLogs = 30
)

$ErrorActionPreference = 'Stop'
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

$meaning = if ($EXIT_MEANING.ContainsKey($code)) { $EXIT_MEANING[$code] } else { "UNKNOWN exit code $code" }
"=== exit $code ($meaning) ===" | Add-Content -LiteralPath $log

# Keep the log directory bounded. -ErrorAction SilentlyContinue because a log a human has open must not
# turn a successful prune into a failed task run.
Get-ChildItem -LiteralPath $LogDir -Filter 'prune-*.log' -ErrorAction SilentlyContinue |
    Sort-Object LastWriteTime -Descending |
    Select-Object -Skip $KeepLogs |
    Remove-Item -Force -ErrorAction SilentlyContinue

exit $code
