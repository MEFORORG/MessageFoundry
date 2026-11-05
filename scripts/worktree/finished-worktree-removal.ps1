# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Re-check, then remove, finished .claude/worktrees trees. Dot-source it; it defines one function.

.DESCRIPTION
    The body of run-daily-prune.ps1 -RemoveFinishedClaudeWorktrees, kept in its own file so the
    re-checks can be tested against trees prune-merged.ps1 would never list (a dirty one, a locked one)
    -- which is exactly the race these re-checks exist for: a tree that looked finished when the list
    was made and stopped looking finished before it was acted on.

    WHY THIS IS SEPARATE FROM prune-merged.ps1, WHICH STILL REMOVES NOTHING UNDER .claude/worktrees.
    That script's exclusion is deliberate: .claude/worktrees is where EnterWorktree relocates a LIVE
    session, and that tool once removed an occupied worktree with --force, deregistering it and then
    failing to delete the directory. This step takes the list prune-merged.ps1 already prints as
    "look finished" and acts on it only the way the owner did by hand on 2026-11-05 -- a plain
    `git worktree remove`, which git itself refuses on a locked tree or one holding a modified or
    untracked file -- and only after re-checking every gate again immediately before each removal.

    THE RE-CHECKS, per path. The first one that fails REFUSES that path and the run moves on; a refusal
    is data, not a failure. At least these:
      * -IdleHours is not under worktree-gates.ps1's floor (checked once, for every path);
      * the path has a `.claude/worktrees/` segment -- the only population this step is for;
      * it is not the primary checkout, not a worktree the caller runs from (-Protect), and does not
        contain one;
      * it is still a registered worktree of -Primary (a fresh `git worktree list --porcelain`), and
        git does not report it locked or prunable;
      * `git status --porcelain --untracked-files=all` exits 0 and prints nothing. IGNORED files, such
        as a .venv, do not count, and plain `git worktree remove` deletes them;
      * its private git metadata is idle beyond -IdleHours (the same reading prune-merged.ps1 decides
        with);
      * a detached tree's tip is still held by some ref, so removing it strands no commit;
      * LAST, so the window before the removal is as short as it can be: the liveness fence
        (scripts/coord/occupancy.ps1, read fresh) is available, still lists the tree unlocked, finds no
        live session in it or in a worktree nested inside it, and finds no other registered worktree
        inside it.
    Every gate is the shared copy in worktree-gates.ps1 or occupancy.ps1, never a re-implementation.

    THE REMOVAL IS `git -C <primary> worktree remove <path>`, WITH NO --force, EVER. There is no switch
    to add one. git's own refusal on a locked or dirty tree is then a last fence this step keeps.

    It never deletes a branch and never releases a coordination claim. prune-merged.ps1 lists no tree
    that holds a claim, and a branch survives `git worktree remove`, so the commits stay reachable.
#>

. "$PSScriptRoot\..\coord\occupancy.ps1"
. "$PSScriptRoot\worktree-gates.ps1"

# Why one path must not be removed now, or '' when every re-check passes. The checks run cheapest first
# and the fence last; see the header for the list and the reason for that order.
function Get-FinishedWorktreeRefusal {
    param([string]$Primary, [string]$Path, [double]$IdleHours, [string[]]$ProtectNorm)
    $norm = ConvertTo-Norm $Path
    if (-not (Test-ClaudeManagedPath $Path)) { return 'outside .claude/worktrees, which is the only population this step removes' }
    if ($norm -eq (ConvertTo-Norm $Primary)) { return 'the primary checkout' }
    $guarded = @($ProtectNorm | Where-Object { $_ -eq $norm -or $_.StartsWith("$norm/") })
    if ($guarded.Count -gt 0) { return "the worktree this run is executing from, or one containing it ($($guarded[0]))" }

    $wt = @(Get-RepoWorktrees $Primary | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm }) | Select-Object -First 1
    if (-not $wt) { return 'no longer a registered worktree' }
    if ($wt.Locked) { return $(if ($wt.LockReason) { "locked: $($wt.LockReason)" } else { 'locked' }) }
    if ($wt.Prunable) { return "git reports it prunable ($($wt.Prunable)); that needs a human" }

    $clean = Test-WorktreeClean -Path $Path -AllUntracked
    if (-not $clean.Clean) { return "not clean: $($clean.Reasons -join '; ')" }

    $act = Get-WorktreeActivity -Path $Path
    if ($null -eq $act) { return 'its git metadata activity could not be read' }
    if ($act -gt (Get-Date).AddHours(-1 * $IdleHours)) {
        return "recently active: git metadata touched $([math]::Round(((Get-Date) - $act).TotalHours, 1)) h ago, inside the $IdleHours h window"
    }

    if ($wt.Detached -or -not $wt.Branch) {
        $held = Get-TipHolders -Path $Path -Repo $Primary
        if ($null -eq $held) { return 'detached, and its tip or the refs holding it could not be read' }
        if ($held.Holders.Count -eq 0) { return 'detached, and no ref holds its tip, so removal would strand commits' }
    }

    # The fence, read FRESH for this path and last of all.
    $occ = Get-WorktreeOccupancy -Repo $Primary
    if (-not $occ.RepoFound) { return "could not list the worktrees of $Primary" }
    if ((ConvertTo-Norm $occ.PrimaryPath) -ne (ConvertTo-Norm $Primary)) { return "$Primary is not the primary checkout git reports ($($occ.PrimaryPath))" }
    $wt2 = @($occ.Worktrees | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm }) | Select-Object -First 1
    if (-not $wt2) { return 'no longer a registered worktree' }
    if ($wt2.Locked) { return $(if ($wt2.LockReason) { "locked: $($wt2.LockReason)" } else { 'locked' }) }
    if (-not $occ.Available) { return "the liveness fence is unavailable: $($occ.Detail)" }
    $occupants = @(Get-WorktreeOccupants -Occupancy $occ -Path $wt2.Path -IncludeNested)
    if ($occupants.Count -gt 0) { return "occupied: $(($occupants | ForEach-Object { "$($_.Short) $($_.State)" }) -join ', ')" }
    $nested = @(Get-NestedWorktrees -Occupancy $occ -Path $wt2.Path)
    if ($nested.Count -gt 0) { return "contains another registered worktree ($($nested[0].Path))" }
    return ''
}

<#
Returns one row per input path: Path, Outcome, Reason, Command.
    Outcome  WOULD-REMOVE  every re-check passed; a dry run, so nothing was removed
             REMOVED       git removed it: deregistered and the directory is gone
             REFUSED       a re-check failed, or git declined; nothing changed
             FAILED        git was asked and the end state is not what it reported
             ORPHANED      deregistered, but the directory is still on disk; needs a human
    Command  the exact removal command, run or (in a dry run) not run. Never carries --force.
#>
function Invoke-FinishedWorktreeRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Primary,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Paths,
        [Parameter(Mandatory)][double]$IdleHours,
        # Worktrees that must never be removed whatever they look like: the one the caller runs from.
        [string[]]$Protect = @(),
        [switch]$Apply
    )
    $ErrorActionPreference = 'Stop'
    $PSNativeCommandUseErrorActionPreference = $false

    $protectNorm = @($Protect | Where-Object { $_ } | ForEach-Object { ConvertTo-Norm $_ })
    # A window under the floor releases trees a measurement says are in use, and 0 turns the reading off
    # entirely. prune-merged.ps1 runs on with a warning there; a step that removes trees does not.
    $floorRefusal = if ($IdleHours -lt $IDLE_FLOOR_HOURS) {
        "-IdleHours $IdleHours is under the $IDLE_FLOOR_HOURS h floor, so idle cannot be established"
    }
    $rows = [System.Collections.Generic.List[object]]::new()

    foreach ($path in @($Paths | Where-Object { $_ })) {
        $row = [pscustomobject]@{ Path = $path; Outcome = 'REFUSED'; Reason = ''; Command = "git -C `"$Primary`" worktree remove `"$path`"" }
        $rows.Add($row)
        $refusal = if ($floorRefusal) { $floorRefusal } else {
            Get-FinishedWorktreeRefusal -Primary $Primary -Path $path -IdleHours $IdleHours -ProtectNorm $protectNorm
        }
        if ($refusal) { $row.Reason = $refusal; continue }
        if (-not $Apply) { $row.Outcome = 'WOULD-REMOVE'; $row.Reason = 'every re-check passed'; continue }

        # The one removal. Plain `worktree remove`: no --force, so git refuses a locked tree or one
        # holding a modified or untracked file even if every check above was somehow wrong.
        $gitOut = @(& git -C $Primary worktree remove $path 2>&1 | ForEach-Object { "$_" })
        $removeExit = $LASTEXITCODE
        $gitText = (($gitOut | Where-Object { $_ }) -join ' ').Trim()

        # Judge the END STATE, not the exit code alone: a removal that deregistered the tree and then
        # failed to delete the directory is the orphan this whole fence exists to prevent.
        $norm = ConvertTo-Norm $path
        $stillRegistered = @(Get-RepoWorktrees $Primary | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm }).Count -gt 0
        $dirExists = Test-Path -LiteralPath $path
        $row.Outcome, $row.Reason = if (-not $stillRegistered -and -not $dirExists -and $removeExit -eq 0) {
            'REMOVED', 'every re-check passed'
        }
        elseif ($stillRegistered -and $removeExit -ne 0) {
            'REFUSED', "git declined (exit $removeExit): $gitText"
        }
        elseif (-not $stillRegistered -and $dirExists) {
            'ORPHANED', "deregistered but the directory is still on disk (git exit $removeExit): $gitText"
        }
        else {
            'FAILED', "git exit $removeExit, registered=$stillRegistered, directory present=${dirExists}: $gitText"
        }
    }
    return $rows.ToArray()
}
