# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Move uncommitted work OUT of the shared primary checkout and into a fresh worktree + branch.

.DESCRIPTION
    The companion to the worktree gate (scripts\hooks\worktree_gate.ps1). A gate that stops you writing
    into the primary is infuriating if you are already half-way through a change there -- so this moves
    what you have, instead of asking you to redo it.

    It stashes the primary's uncommitted work (tracked AND untracked), creates a worktree branched off the
    primary's CURRENT commit -- not origin/main, so the stash applies cleanly -- and applies that stash
    there BY ITS COMMIT ID, then drops it.

    THE STASH STACK IS CLONE-WIDE: every worktree and every session on this clone pushes and pops the same
    one, so "the top entry" is not "my entry" (BACKLOG #5957). The push carries a unique tag, the entry's
    commit id is read back by that tag straight away, and everything after that names the id -- never
    stash@{0}, never a bare pop. A push that created no entry is refused before anything else runs, since
    the only entry a later step could find would be someone else's.

    The stash is the safety net: if the apply fails for any reason, the work is still in `git stash list`
    and this script prints the exact id to restore. Nothing is ever discarded.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\rescue.ps1 -Name alerts-fix
    pwsh -NoProfile -File scripts\worktree\rescue.ps1 -Name alerts-fix -NoInstall   # skip the venv build
#>
[CmdletBinding()]
param(
    # NOT Mandatory, ON PURPOSE: a call without -Name would prompt for it, which hangs a caller with
    # stdin open (tests/_no_prompt.py, vault BACKLOG #3627). The refusal is right after this param block.
    # \A..\z for the reason given in new.ps1's param block; keep all four copies identical.
    [ValidatePattern('\A[A-Za-z0-9._-]+\z')]
    [string]$Name,
    [switch]$NoInstall,
    [switch]$Sqlserver
)

$ErrorActionPreference = "Stop"

# No -Name: refuse by name, before anything is read or moved. See $Name.
if (-not $Name) { throw "rescue.ps1 needs -Name <slug> for the new worktree. Nothing was moved. Add -Name and re-run." }

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# THE PRIMARY, AND ONLY THE PRIMARY. This script anchors on its own path, so the copy inside a LINKED
# worktree would stash THAT worktree -- often another session's live work -- and name the new one
# "<linked-leaf>-<Name>". A linked worktree is already a legitimate place to write, so there is nothing to
# rescue it from; refuse and name the primary's copy instead. git-dir equals git-common-dir only in the
# main worktree.
$gitDir, $commonDir = @(& git -C $RepoRoot rev-parse --path-format=absolute --git-dir --git-common-dir)
if ($LASTEXITCODE -ne 0) { throw "Cannot read the repository at $RepoRoot (git rev-parse failed). Nothing was moved." }
if ($gitDir -ne $commonDir) {
    $mainLine = @(& git -C $RepoRoot worktree list --porcelain) | Where-Object { $_ -like 'worktree *' } | Select-Object -First 1
    $mainPath = if ($mainLine) { $mainLine.Substring(9) } else { '<the primary checkout>' }
    throw ("$RepoRoot is a LINKED worktree, not the primary checkout. rescue.ps1 moves work out of the " +
        "primary only; a linked worktree is already a safe place to work. Nothing was moved. To rescue the " +
        "primary, run its own copy: pwsh -NoProfile -File `"$mainPath\scripts\worktree\rescue.ps1`" -Name $Name")
}

$Parent   = Split-Path $RepoRoot -Parent
$Target   = Join-Path $Parent ("{0}-{1}" -f (Split-Path $RepoRoot -Leaf), $Name)

if (Test-Path $Target) { throw "Worktree path already exists: $Target  (pick another -Name, or just work in it)" }

$dirty = @(& git -C $RepoRoot status --porcelain)
# A failed status prints nothing, which would read as "clean" below and send the caller away with work left
# in the primary.
if ($LASTEXITCODE -ne 0) { throw "git status failed in $RepoRoot (exit $LASTEXITCODE). Nothing was moved." }
if ($dirty.Count -eq 0) {
    Write-Host "Nothing to rescue: $RepoRoot is clean." -ForegroundColor Yellow
    Write-Host "You want a plain new worktree instead:  scripts\worktree\new.ps1 -Name $Name"
    return
}

$sha = (& git -C $RepoRoot rev-parse HEAD).Trim()
Write-Host "Rescuing $($dirty.Count) change(s) from $RepoRoot (at $($sha.Substring(0,7)))..."
$dirty | Select-Object -First 12 | ForEach-Object { Write-Host "  $_" }
if ($dirty.Count -gt 12) { Write-Host "  ... and $($dirty.Count - 12) more" }

# Every entry on the clone-wide stack, as (commit id, reflog subject). Read fresh each time it is needed,
# because another session can push or drop between any two reads.
function Get-StashEntries {
    $lines = @(& git -C $RepoRoot stash list --format='%H%x09%gs')
    if ($LASTEXITCODE -ne 0) { throw "git stash list failed in $RepoRoot (exit $LASTEXITCODE)" }
    foreach ($line in $lines) {
        $tab = $line.IndexOf("`t")
        if ($tab -gt 0) { [pscustomobject]@{ Sha = $line.Substring(0, $tab); Subject = $line.Substring($tab + 1) } }
    }
}

# -u carries untracked files too; without it they would be left behind in the primary and silently
# duplicated once the worktree recreated them. The GUID makes the tag this run's alone, so the entry can be
# found by tag even when a concurrent push lands on top of it before the read-back.
$stashMsg = "rescue -> $Name [$([guid]::NewGuid().ToString('N'))]"
& git -C $RepoRoot stash push --include-untracked -m $stashMsg
$pushRc = $LASTEXITCODE
$ours = @(Get-StashEntries | Where-Object { $_.Subject.EndsWith(": $stashMsg", [StringComparison]::Ordinal) })
if ($ours.Count -eq 0 -and $pushRc -ne 0) {
    throw "git stash push failed (exit $pushRc) and created no entry -- nothing was moved."
} elseif ($ours.Count -eq 0) {
    # Exit 0 with no entry is real: git stash prints "No local changes to save" for a change it cannot
    # carry, such as edited content inside a nested repository that status still reports.
    throw ("git stash push created no entry although status reported $($dirty.Count) change(s) -- nothing " +
        "was moved. git stash cannot carry these changes (for example, edits inside a nested repository); " +
        "commit or move them by hand. The stash stack was not touched.")
}
$stashSha = $ours[0].Sha

$stashed = $true
try {
    # An entry exists, so a failed push still leaves the work in it; the finally block says how to restore.
    if ($pushRc -ne 0) { throw "git stash push failed (exit $pushRc) but recorded entry $stashSha" }

    # Branch the worktree off the primary's CURRENT commit so the stash applies without conflict. (new.ps1
    # would otherwise default to origin/main, which the primary is often many commits behind.)
    $newArgs = @("-NoProfile", "-File", (Join-Path $PSScriptRoot "new.ps1"), "-Name", $Name, "-Base", $sha)
    if ($NoInstall) { $newArgs += "-NoInstall" }
    if ($Sqlserver) { $newArgs += "-Sqlserver" }
    & pwsh @newArgs
    if ($LASTEXITCODE -ne 0) { throw "new.ps1 failed (exit $LASTEXITCODE)" }

    # APPLY BY ID, never pop: a pop takes whatever is on top of the shared stack now, and new.ps1 (fetch,
    # worktree add, venv build) is a window of minutes for another session to push on top of ours.
    & git -C $Target stash apply $stashSha
    if ($LASTEXITCODE -ne 0) { throw "git stash apply $stashSha failed in $Target (exit $LASTEXITCODE)" }
    $stashed = $false

    # The work is in the worktree now, so a failed drop only leaves a spare copy behind. Re-find the entry's
    # CURRENT position by id, then compare the stack before and after: a push or drop by another session
    # between the read and the drop shifts every index, and an entry dropped by mistake is stored straight back.
    $before = @(Get-StashEntries)
    $at = [array]::IndexOf([string[]]@($before | ForEach-Object Sha), $stashSha)
    if ($at -lt 0) {
        Write-Warning "Stash commit $stashSha is no longer on the stash list; nothing to drop."
    } else {
        & git -C $RepoRoot stash drop -q "stash@{$at}"
        if ($LASTEXITCODE -ne 0) {
            Write-Warning "Could not drop stash commit $stashSha (exit $LASTEXITCODE); it is a spare copy and safe to drop by hand."
        } else {
            $after = @(Get-StashEntries | ForEach-Object Sha)
            # Only while OUR entry survived did the drop take another one. If ours is gone, an entry missing
            # beside it was dropped by its own session, and storing it back would resurrect it.
            $lostSet = if ($after -contains $stashSha) { @($before | Where-Object { $_.Sha -ne $stashSha -and $after -notcontains $_.Sha }) } else { @() }
            foreach ($lost in $lostSet) {
                # store -m writes the reflog subject verbatim, so passing the read subject keeps it identical.
                & git -C $RepoRoot stash store -m $lost.Subject $lost.Sha
                Write-Warning "The stash list moved during the drop; entry $($lost.Sha) was dropped instead and has been stored back. Stash commit $stashSha may remain as a spare copy."
            }
        }
    }

    Write-Host ""
    Write-Host "Rescued into $Target (branch '$Name', off $($sha.Substring(0,7)))." -ForegroundColor Green
    Write-Host "The primary checkout is clean again. Continue there:"
    Write-Host "  cd `"$Target`""
    if (-not $NoInstall) { Write-Host "  .\.venv\Scripts\Activate.ps1" }
}
finally {
    if ($stashed) {
        Write-Warning "Rescue did not complete. YOUR WORK IS SAFE -- it is in the stash as commit $stashSha :"
        Write-Warning "    git -C `"$RepoRoot`" stash list        # look for: $stashMsg"
        Write-Warning "    git -C `"$RepoRoot`" stash apply $stashSha    # put it back in the primary (by id, never a bare pop)"
        Write-Warning "Nothing was discarded. Resolve the failure above, then retry or apply it by hand."
    }
}
