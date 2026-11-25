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
    there BY ITS COMMIT ID.

    THE STASH STACK IS CLONE-WIDE: every worktree and every session on this clone pushes and pops the same
    one, so "the top entry" is not "my entry" (BACKLOG #5957). The push carries a unique tag, the entry's
    commit id is read back by that tag straight away, anchored under a private ref
    (refs/worktree-rescue/<guid>, this run's own GUID, not the stash SHA), and taken off the shared stack at once; the apply names the id, never a
    bare pop. The one step that cannot name the id is that drop: git stash drop takes a POSITION, so the
    position is re-found by id and checked just before the drop, and any other session's entry a shifted
    position dropped anyway is stored back. A push that created no entry is refused before anything else
    runs, since the only entry a later step could find would be someone else's.

    The anchor is the safety net: if a later step fails, the work is still held under that ref and this
    script prints the exact commands to restore it. Changes git stash cannot carry at all (edits inside a
    nested repository) are never moved, and the script says so.

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

# $GIT_REDIRECT_NAMES and Get-GitConfigCarriers come from worktree-gates.ps1. remove.ps1 calls the same
# Get-GitConfigCarriers, but keeps its OWN literal copy of the redirect names (and of the two object-store
# names below), so those lists can drift apart; keep them in step by hand.
. "$PSScriptRoot\worktree-gates.ps1"

# An inherited GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR or GIT_INDEX_FILE points every `git -C $RepoRoot`
# below at another repository, tree or index, and would also pass a linked copy off as the primary. The
# two object-store names are refused as remove.ps1 -Discard refuses them, because this script WRITES
# objects (the stash commit), and a redirected store would park the only copy of the work outside the
# clone. Config carried in the environment steers every read below (for example status.showUntrackedFiles
# or a core.fsmonitor hook). Before any git call.
$refused = @(@($GIT_REDIRECT_NAMES) + @('GIT_OBJECT_DIRECTORY', 'GIT_ALTERNATE_OBJECT_DIRECTORIES') |
    Where-Object { [Environment]::GetEnvironmentVariable($_) }) + @(Get-GitConfigCarriers)
if ($refused.Count -gt 0) {
    throw "rescue.ps1 refuses: $($refused -join ', ') is set, so git could read or write another repository, tree, index, object store or config. Unset it and re-run. Nothing was moved."
}

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

# Where new.ps1 will put the tree: beside the main worktree as git records it (BACKLOG #1894), which
# can be spelled differently from $PSScriptRoot, for example through a junction.
$mainLine = @(& git -C $RepoRoot worktree list --porcelain) | Where-Object { $_ -like 'worktree *' } | Select-Object -First 1
if (-not $mainLine) { throw "Cannot find the main worktree of $RepoRoot. Nothing was moved." }
$MainRoot = [System.IO.Path]::GetFullPath($mainLine.Substring('worktree '.Length)).TrimEnd('\', '/')
$Parent   = Split-Path $MainRoot -Parent
$Target   = Join-Path $Parent ("{0}-{1}" -f (Split-Path $MainRoot -Leaf), $Name)

if (Test-Path $Target) { throw "Worktree path already exists: $Target  (pick another -Name, or just work in it)" }
# Everything new.ps1 would refuse or misread about the branch is refused HERE, before the primary is
# touched. It refuses a leading '-' and a name git's refname grammar rejects; and it REUSES an existing
# branch, ignoring -Base, so the work would land on that branch's old tip instead of the commit it came from.
if ($Name.StartsWith('-')) { throw "-Name may not start with '-': '$Name'. Nothing was moved." }
& git -C $RepoRoot check-ref-format --branch $Name *> $null
if ($LASTEXITCODE -ne 0) { throw "-Name '$Name' is not a valid git branch name. Nothing was moved." }
$existing = @(& git -C $RepoRoot branch --list $Name)
if ($LASTEXITCODE -ne 0) { throw "git branch --list failed (exit $LASTEXITCODE). Nothing was moved." }
if ($existing.Count -gt 0) {
    throw "A branch named '$Name' already exists, so the work would not land on the commit it came from. Pick another -Name. Nothing was moved."
}

# Explicit flags, so a config such as status.showUntrackedFiles=no or a submodule ignore setting cannot
# make a dirty primary read clean.
function Get-PrimaryStatus {
    $lines = @(& git -C $RepoRoot status --porcelain --untracked-files=all --ignore-submodules=none)
    # A failed status prints nothing, which would read as "clean" and send the caller away with work left.
    if ($LASTEXITCODE -ne 0) { throw "git status failed in $RepoRoot (exit $LASTEXITCODE)." }
    $lines
}

$dirty = @(Get-PrimaryStatus)
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
        $id, $subject = $line -split "`t", 2
        [pscustomobject]@{ Sha = $id; Subject = "$subject" }
    }
}

# Whether a stash commit is on the clone-wide list right now: $true, $false, or $null when the list cannot
# be read. The messages that re-read the list at the moment they speak are the end-of-run still-listed
# check, the failure-path advice in the finally block, and Write-OwnEntryState.
function Test-StashListed([string]$Id) {
    try { return (@(Get-StashEntries | Where-Object Sha -eq $Id).Count -gt 0) } catch { return $null }
}

# The command an operator pastes to drop a listed entry. git stash drop takes a POSITION, so the command
# re-finds it by SHA when it runs and checks that position still holds the SHA just before the drop. It is a
# PowerShell command. Unlike Remove-OwnStashEntry it does not read the dropped SHA back from git's output and
# does not store back another session's entry if a shifted position dropped it; like that function, it
# cannot close the gap between its position check and the drop itself.
function Get-DropBySha([string]$Id) {
    ("`$n = @(git -C `"$RepoRoot`" stash list --format=%H).IndexOf('$Id'); " +
        "if (`$n -ge 0 -and (git -C `"$RepoRoot`" rev-parse `"stash@{`$n}`") -eq '$Id') { git -C `"$RepoRoot`" stash drop `"stash@{`$n}`" } " +
        "else { Write-Host 'Not dropped: that SHA is not at the position just found. If git stash list no longer shows it, the entry is off the stack and nothing needs dropping; if it is listed, run this command again.' }")
}

# Say where this run's entry is after a drop that did not remove it. A shifted position means some other
# session moved the list, which may be a pop of THIS entry, so read the list again instead of assuming.
function Write-OwnEntryState([string]$Id, [string]$Anchor, [string]$Why) {
    $listed = Test-StashListed $Id
    if ($listed -eq $true) {
        Write-Warning "$Why. Stash commit $Id stays on the stash list as a spare copy (it is also held under $Anchor)."
    } elseif ($listed -eq $false) {
        Write-Warning ("$Why. Stash commit $Id is no longer on the stash list: another session took it off, most " +
            "likely by a bare pop that ALSO applied this work into that session's tree. It is still held under $Anchor.")
    } else {
        Write-Warning "$Why. The stash list could not be read again, so stash commit $Id may or may not still be listed; it is held under $Anchor."
    }
}

# Take this run's entry off the shared stack, by id. git stash drop takes a POSITION, which another
# session's push or drop can shift at any moment, so: re-find the position by id, confirm it still holds
# that id, run the drop under the C locale so its "Dropped ... (<id>)" line parses, and store back, under
# its own subject, any other entry a shifted position dropped. Warns, never throws: the work is anchored
# under a private ref by now, so a failure here leaves a spare copy, never a loss.
function Remove-OwnStashEntry([string]$Id, [string]$Anchor) {
    try {
        $listed = @(Get-StashEntries)
        $at = [array]::IndexOf([string[]]@($listed | ForEach-Object Sha), $Id)
        if ($at -lt 0) {
            Write-Warning ("Stash commit $Id was already taken off the stash list by another session, most likely " +
                "by a bare pop that ALSO applied this work into that session's tree. It is still held under $Anchor.")
            return
        }
        if ((& git -C $RepoRoot rev-parse "stash@{$at}") -ne $Id) {
            Write-OwnEntryState -Id $Id -Anchor $Anchor -Why "The stash list moved under this run, so the drop was not attempted"
            return
        }
        $savedLcAll = $env:LC_ALL
        $env:LC_ALL = 'C'
        try { $dropOut = (@(& git -C $RepoRoot stash drop "stash@{$at}") -join "`n"); $dropRc = $LASTEXITCODE }
        finally { $env:LC_ALL = $savedLcAll }
        $dropped = if ($dropOut -match '\(([0-9a-f]{40,64})\)') { $Matches[1] } else { $null }
        if ($dropRc -ne 0) {
            Write-OwnEntryState -Id $Id -Anchor $Anchor -Why "Could not drop stash commit $Id (exit $dropRc)"
        } elseif (-not $dropped) {
            Write-Warning "Could not read which entry the drop removed ($dropOut). Check git stash list against: $(@($listed | ForEach-Object { "$($_.Sha) $($_.Subject)" }) -join '; ')"
        } elseif ($dropped -ne $Id) {
            $subject = @($listed | Where-Object Sha -eq $dropped | ForEach-Object Subject | Select-Object -First 1)
            # An entry pushed after the read above is not in $listed, so read its real subject from the commit.
            $subject = if ($subject) { $subject[0] } else { "$(& git -C $RepoRoot log -1 --format=%s $dropped)".Trim() }
            if (-not $subject) { $subject = "restored by rescue.ps1 after a shifted drop" }
            & git -C $RepoRoot stash store -m $subject $dropped
            if ($LASTEXITCODE -eq 0) {
                Write-OwnEntryState -Id $Id -Anchor $Anchor -Why "The stash list moved during the drop; another session's entry $dropped was dropped and has been stored back (at the top)"
            } else {
                Write-Warning "The stash list moved during the drop and another session's entry was dropped; storing it back FAILED. Restore it with: git -C `"$RepoRoot`" stash store -m `"$subject`" $dropped"
                Write-OwnEntryState -Id $Id -Anchor $Anchor -Why "This run's own entry was not the one dropped"
            }
        }
    } catch {
        Write-Warning "Taking stash commit $Id off the stash list failed ($_); it may still be listed as a spare copy."
    }
}

# -u carries untracked files too; without it they would be left behind in the primary and silently
# duplicated once the worktree recreated them. The GUID makes the tag this run's alone, so the entry can be
# found by tag even when a concurrent push lands on top of it before the read-back.
$guid      = [guid]::NewGuid().ToString('N')
$stashMsg  = "rescue -> $Name [$guid]"
$anchorRef = "refs/worktree-rescue/$guid"
# Under the C locale, so the no-entry branch below can read git's "No local changes to save" and tell a
# push that created nothing from one whose entry another session popped. Echoed, so the caller still sees it.
$savedLcAll = $env:LC_ALL
$env:LC_ALL = 'C'
try { $pushOut = @(& git -C $RepoRoot stash push --include-untracked -m $stashMsg); $pushRc = $LASTEXITCODE }
finally { $env:LC_ALL = $savedLcAll }
$pushOut | ForEach-Object { Write-Host $_ }
try {
    $stashSha = @(Get-StashEntries | Where-Object { $_.Subject.EndsWith(": $stashMsg", [StringComparison]::Ordinal) } | ForEach-Object Sha) | Select-Object -First 1
} catch {
    throw "$_ -- after the stash push (exit $pushRc). If the primary is now clean, the work is in the stash under: $stashMsg"
}
if (-not $stashSha) {
    $now = @(Get-PrimaryStatus)
    if ($now.Count -eq 0) {
        # The changes are gone from the primary but no entry carries this run's tag. Either a concurrent
        # push (a second rescue, say) took them first, or this run's entry was popped before the read-back.
        throw ("The primary is now clean, but no stash entry carries this run's tag ($stashMsg). Another " +
            "session either stashed these changes first (look in: git -C `"$RepoRoot`" stash list, and, since " +
            "a concurrent rescue run anchors its entry there and drops it from that list, in: git -C " +
            "`"$RepoRoot`" for-each-ref refs/worktree-rescue/) or popped this run's entry before it could be " +
            "read, which applied it into that session's tree. Nothing more was moved.")
    }
    if ($pushRc -ne 0) { throw "git stash push failed (exit $pushRc) and no entry carrying this run's tag ($stashMsg) is listed; the primary still shows changes. Check git -C `"$RepoRoot`" stash list before retrying." }
    # Exit 0 with no entry is real: git stash prints "No local changes to save" for a change it cannot
    # carry, such as edited content inside a nested repository that status still reports.
    if (@($pushOut | Where-Object { $_ -match '^No local changes to save' }).Count -gt 0) {
        throw ("git stash push created no entry although status reported $($dirty.Count) change(s) -- nothing " +
            "was moved. git stash cannot carry these changes (for example, edits inside a nested repository); " +
            "commit or move them by hand. The stash stack was not touched.")
    }
    # Otherwise the push did not report 'No local changes to save' (all that was measured), so it most likely recorded an entry, and the primary is dirty again with no tagged entry listed:
    # another session popped it before the read-back, which applied it into whatever tree that session runs in.
    throw ("git stash push did not report 'No local changes to save', but no stash entry carries this run's tag ($stashMsg) " +
        "and the primary still shows $($now.Count) change(s). Another session most likely popped this run's " +
        "entry before it could be read, which applied it into that session's tree (the primary itself, if it " +
        "runs there). This run moved nothing further; check the primary, git -C `"$RepoRoot`" stash list, and " +
        "git -C `"$RepoRoot`" for-each-ref refs/worktree-rescue/ before retrying.")
}

# ANCHOR, then leave the shared stack at once. Held under a private ref, the work cannot be popped by
# another session during new.ps1 (fetch, worktree add, venv build: minutes), and dropping now, while the
# entry is almost certainly still on top, keeps the position race to milliseconds instead of minutes.
& git -C $RepoRoot update-ref $anchorRef $stashSha
if ($LASTEXITCODE -ne 0) {
    throw "Could not anchor stash commit $stashSha under $anchorRef (exit $LASTEXITCODE). The push put the work into a stash entry tagged: $stashMsg (SHA $stashSha). The stash list was not read again after this failure, so check git -C `"$RepoRoot`" stash list before assuming it is still there."
}

$stashed = $true
try {
    if ($pushRc -ne 0) {
        # The entry exists, but git stash stops cleaning the tree when a step fails, so the primary may still
        # hold part of the work. The entry stays listed; the finally block says how to restore.
        throw "git stash push failed (exit $pushRc) after recording $stashSha; the primary may be only partly cleaned"
    }
    Remove-OwnStashEntry -Id $stashSha -Anchor $anchorRef

    # Changes git stash could not carry (edits inside a nested repository) are still in the primary.
    $left = @(Get-PrimaryStatus)
    if ($left.Count -gt 0) {
        Write-Warning "These changes could not be stashed and are STILL in the primary; move them by hand:"
        $left | ForEach-Object { Write-Warning "  $_" }
    }

    # Branch the worktree off the primary's CURRENT commit so the stash applies without conflict. (new.ps1
    # would otherwise default to origin/main, which the primary is often many commits behind.)
    $newArgs = @("-NoProfile", "-File", (Join-Path $PSScriptRoot "new.ps1"), "-Name", $Name, "-Base", $sha)
    if ($NoInstall) { $newArgs += "-NoInstall" }
    if ($Sqlserver) { $newArgs += "-Sqlserver" }
    & pwsh @newArgs
    if ($LASTEXITCODE -ne 0) { throw "new.ps1 failed (exit $LASTEXITCODE)" }

    # BY ID, never a pop. --index keeps what was staged apart from what was not; the worktree sits on the
    # stash's own base commit, so it applies cleanly.
    & git -C $Target stash apply --index $stashSha
    if ($LASTEXITCODE -ne 0) { throw "git stash apply --index $stashSha failed in $Target (exit $LASTEXITCODE)" }
    $stashed = $false

    & git -C $RepoRoot update-ref -d $anchorRef $stashSha
    if ($LASTEXITCODE -ne 0) { Write-Warning "Could not delete the anchor $anchorRef (exit $LASTEXITCODE); it is a spare copy, safe to delete." }

    Write-Host ""
    Write-Host "Rescued into $Target (branch '$Name', off $($sha.Substring(0,7)))." -ForegroundColor Green
    if ($left.Count -eq 0) { Write-Host "The primary checkout is clean again." }
    # A drop that failed or found the list shifted leaves this run's entry listed; say so, now, by reading it.
    $stillListed = Test-StashListed $stashSha
    if ($stillListed -eq $true) {
        Write-Warning ("Stash commit $stashSha is still on the shared stash list, a spare copy of the work now in " +
            "$Target. Drop it by its position, re-found by SHA when the command runs:")
        Write-Warning "    $(Get-DropBySha $stashSha)"
    } elseif ($null -eq $stillListed) {
        Write-Warning "Could not re-read the stash list; stash commit $stashSha may still be listed. To drop it if so: $(Get-DropBySha $stashSha)"
    }
    Write-Host "Continue there:"
    Write-Host "  cd `"$Target`""
    if (-not $NoInstall) { Write-Host "  .\.venv\Scripts\Activate.ps1" }
}
finally {
    if ($stashed) {
        Write-Warning "Rescue did not complete. YOUR WORK IS SAFE -- it is stash commit $stashSha, held under $anchorRef :"
        Write-Warning "    git -C `"$RepoRoot`" stash apply --index $stashSha    # put it back (by id, never a bare pop)"
        Write-Warning "    git -C `"$RepoRoot`" update-ref -d $anchorRef          # then release the anchor"
        Write-Warning "If the primary still holds part of the work (a failed push), move that aside before the apply."
        if ((Test-StashListed $stashSha) -ne $false) {
            Write-Warning "It may also still be on the shared stash list; once it is restored, drop that entry, re-found by SHA:"
            Write-Warning "    $(Get-DropBySha $stashSha)"
        }
        Write-Warning "Nothing was discarded. Resolve the failure above, then retry or apply it by hand."
    }
}
