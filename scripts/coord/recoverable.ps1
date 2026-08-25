# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Answer whether this worktree's UNTRACKED files would actually be lost, which "untracked" does
    not tell you (BACKLOG #1298).

.DESCRIPTION
    The archive dialog warns that untracked files "will be permanently discarded". That reasons from
    "not in THIS WORKTREE'S INDEX" straight to "will be lost", and skips the only question that
    decides it: is the content somewhere else. It is an INDEX test presented as a LOSS test.

    THE TWO ARE DIFFERENT FOR AN ORDINARY AND CONSTANT REASON. A worktree whose base is behind `main`
    does not have the files that landed since it branched. Any copy of one of those files sitting in
    the tree is untracked THERE while being tracked on `main` -- so the file is fully recoverable and
    the warning is wrong. Every session branched behind `main` meets this, on every file that landed
    since, and the prompt arrives at exactly the moment a seat is trying to finish.

    REPRODUCED ON THIS REPOSITORY 2026-08-24, which is what establishes the mechanism rather than a
    coincidence. A worktree detached at 720f9436, one commit before `tests/test_ci_retry_native_crash.py`
    landed at 6e758a87, with `main`'s copy of that file placed in it:

        git status --porcelain   ->  ?? tests/test_ci_retry_native_crash.py
        worktree blob            ->  5498a64cad057ed729d7220591246f75f2d21f15
        origin/main blob         ->  5498a64cad057ed729d7220591246f75f2d21f15

    Identical. The dialog called that permanent loss.

.NOTES
    THE DIALOG IS THE CLAUDE CODE HARNESS AND IS NOT THIS REPOSITORY'S CODE. Nothing here can change
    its wording, and a change that tries has misread the item. This script exists so a human or a
    session can answer the question the dialog raises but cannot itself answer.

    ANYTHING THIS SCRIPT CANNOT READ IS REPORTED AT RISK, NEVER CLEAN. That is the same direction
    occupancy.ps1 states for its own fence -- an unplaceable record makes the whole fence unavailable,
    because the failure that cannot be attributed is exactly the one that might be destroyed. Here the
    cost of the two errors is not symmetric: a false AT RISK costs a look, a false RECOVERABLE costs
    the file.

    NOT FETCHING ERRS THE SAME WAY, WHICH IS WHY -NoFetch IS SAFE. A stale `origin/main` can only
    fail to contain something that has since landed, so it can only move a file from RECOVERABLE to
    AT RISK. It cannot invent a match. The ref actually compared against is printed with every run,
    because a verdict without the ref it was computed against is not a result.

.PARAMETER Worktree
    The worktree to examine. Defaults to the current one.

.PARAMETER Ref
    What to consider "somewhere else". Defaults to origin/main.

.PARAMETER NoFetch
    Skip the fetch. See the note above: this can only over-warn.

.PARAMETER Json
    Emit the rows as JSON instead of a table.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\recoverable.ps1
    pwsh -NoProfile -File scripts\coord\recoverable.ps1 -Worktree C:\path\to\wt -NoFetch
#>
[CmdletBinding()]
param(
    [string]$Worktree,
    [string]$Ref = "origin/main",
    [switch]$NoFetch,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'

# NOTE ON $LASTEXITCODE, since every git call below leans on it: a non-zero exit is a RESULT here,
# not an error. `cat-file -e` exits 1 for a path that is simply absent from the ref, which is one of
# the three verdicts. $ErrorActionPreference='Stop' does not turn a native exit code into a throw,
# so the calls are made directly and their exit code read immediately after.

if (-not $Worktree) { $Worktree = (Get-Location).Path }
if (-not (Test-Path -LiteralPath $Worktree)) { throw "no such worktree: $Worktree" }
$script:Root = (Resolve-Path -LiteralPath $Worktree).Path

$top = & git -C $script:Root rev-parse --show-toplevel 2>$null
if ($LASTEXITCODE -ne 0 -or -not $top) { throw "not inside a git worktree: $script:Root" }
$script:Root = $top

if (-not $NoFetch) {
    & git -C $script:Root fetch origin --quiet 2>$null | Out-Null
}

$refSha = & git -C $script:Root rev-parse --verify --quiet "$Ref" 2>$null
if (-not $refSha) {
    throw "cannot resolve $Ref in $script:Root -- refusing to judge anything against a ref that does not exist"
}

# --untracked-files=all, because the default collapses an untracked DIRECTORY to a single entry and
# every file beneath it would then go unexamined while the run still reported a clean verdict.
# -z, because a path may contain a space, and porcelain v1 QUOTES such paths rather than emitting
# them raw -- parsing the quoted form is a second, silently different unescaper.
$raw = & git -C $script:Root status --porcelain --untracked-files=all -z 2>$null
$entries = @()
if ($raw) { $entries = ($raw -split "`0") | Where-Object { $_ } }

$rows = @()
foreach ($e in $entries) {
    if ($e.Length -lt 4 -or $e.Substring(0, 2) -ne '??') { continue }
    $path = $e.Substring(3)

    $verdict = $null
    $detail = $null
    $wtHash = $null
    $refHash = $null

    & git -C $script:Root cat-file -e "${Ref}:${path}" 2>$null | Out-Null
    $onRef = ($LASTEXITCODE -eq 0)

    if (-not $onRef) {
        $verdict = 'AT-RISK'
        $detail = "absent from $Ref"
    }
    else {
        $refHash = & git -C $script:Root rev-parse "${Ref}:${path}" 2>$null
        $wtHash = & git -C $script:Root hash-object -- "$path" 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $wtHash -or -not $refHash) {
            # UNREADABLE COUNTS AS AT RISK. It is on the ref, so it is tempting to call it clean --
            # but we could not read the working copy, so we do not know it is the same content, and
            # the one thing we must never do is tell someone a file is safe when we could not look.
            $verdict = 'AT-RISK'
            $detail = 'UNREADABLE -- could not hash the working copy; treated as at risk, not as clean'
        }
        elseif ($wtHash -eq $refHash) {
            $verdict = 'RECOVERABLE'
            $detail = "identical to $Ref"
        }
        else {
            $verdict = 'AT-RISK'
            $detail = "on $Ref but MODIFIED here"
        }
    }

    $rows += [pscustomobject]@{
        Path        = $path
        Verdict     = $verdict
        Detail      = $detail
        WorktreeSha = $wtHash
        RefSha      = $refHash
    }
}

$atRisk = @($rows | Where-Object { $_.Verdict -eq 'AT-RISK' })
$recoverable = @($rows | Where-Object { $_.Verdict -eq 'RECOVERABLE' })

if ($Json) {
    [pscustomobject]@{
        Worktree    = $script:Root
        Ref         = $Ref
        RefSha      = $refSha
        Fetched     = (-not $NoFetch)
        Untracked   = $rows.Count
        AtRisk      = $atRisk.Count
        Recoverable = $recoverable.Count
        Rows        = $rows
    } | ConvertTo-Json -Depth 5
}
else {
    Write-Output "worktree : $script:Root"
    # THE REF IS PART OF THE MEASUREMENT, not decoration. A verdict quoted without the ref it was
    # computed against cannot be re-checked by whoever reads it.
    Write-Output "compared : $Ref at $refSha$(if ($NoFetch) { '  (NOT fetched -- can only over-warn)' })"
    Write-Output ""
    if ($rows.Count -eq 0) {
        Write-Output "no untracked files. Nothing for the archive warning to be about."
    }
    else {
        foreach ($r in ($rows | Sort-Object Verdict, Path)) {
            Write-Output ("{0,-12} {1}" -f $r.Verdict, $r.Path)
            Write-Output ("             {0}" -f $r.Detail)
        }
        Write-Output ""
        Write-Output ("untracked {0}: {1} AT-RISK, {2} recoverable." -f $rows.Count, $atRisk.Count, $recoverable.Count)
        if ($atRisk.Count -eq 0) {
            Write-Output "Every untracked file here is already on $Ref, byte for byte. The archive warning is wrong about all of them."
        }
        else {
            Write-Output "The AT-RISK rows are the only ones the archive warning actually describes. Commit or copy them first."
        }
    }
}

# Exit 1 when anything is at risk, so this can be used as a check and not only read by a human.
# Nothing at risk -- including the no-untracked-files case -- exits 0.
if ($atRisk.Count -gt 0) { exit 1 }
exit 0
