# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Remove a git worktree created by new.ps1 (and optionally its branch).

.DESCRIPTION
    Removes the sibling worktree directory <repo>-<Name>. Refuses if the worktree has uncommitted
    *tracked* changes (so you don't lose work) unless -Force; the untracked .venv / node_modules are
    expected and removed automatically.

    WHICH COPY YOU RUN DECIDES WHICH CHECKOUT IT SEARCHES. This anchors on $PSScriptRoot (or -RepoRoot),
    not on your cwd, so run the copy living in the checkout the worktree was created FROM -- which is
    not necessarily the primary, since new.ps1 anchors the same way and creates its worktree beside
    itself. By absolute path it works from any cwd outside the worktree being removed (git can't
    remove the worktree you're standing in). This header used to name the primary checkout
    unconditionally, which was false for every worktree created from a linked one; new.ps1 now prints
    the exact command with the root already filled in (BACKLOG #1078). See docs/WORKTREES.md.

    -Name is the DIRECTORY component only. -DeleteBranch deletes whichever branch that worktree
    actually has checked out, read from git -- not a branch named after the directory. Since new.ps1
    gained -Branch the two can differ.

    -RepoRoot exists so this script can be EXECUTION-TESTED. It used to derive its root from
    $PSScriptRoot alone, so the only repository a test could point it at was the real checkout --
    which no test may drive, because this script force-removes worktrees and force-deletes refs. The
    branch-delete path was therefore covered by review only, and it is the one place in
    scripts/worktree/ where being wrong loses commits reachable from no ref and no reflog. Same
    parameter, same reason, as prune-merged.ps1. See tests/test_worktree_remove.py.

.EXAMPLE
    .\remove.ps1 -Name alerts
    .\remove.ps1 -Name alerts -DeleteBranch
    .\remove.ps1 -Name alerts -Force        # discard uncommitted tracked changes too
#>
[CmdletBinding()]
param(
    # The worktree DIRECTORY component, not a branch -- removal is BY PATH below, so this finds a
    # worktree whose branch carries a '/' just fine, and -DeleteBranch reads the real branch from git.
    # \A..\z for the reason given in new.ps1's param block; keep all four copies identical.
    [Parameter(Mandatory = $true)]
    [ValidatePattern('\A[A-Za-z0-9._-]+\z')]
    [string]$Name,
    [switch]$Force,         # remove even with uncommitted tracked changes
    [switch]$DeleteBranch,  # also delete the local branch
    # Remove even when this worktree OWNS a ledger number whose item is not yet on origin/main
    # (BACKLOG #1293). DELIBERATELY NOT -Force: that one means "I accept losing uncommitted changes",
    # and one consent must not silently cover an unrelated, IRREVERSIBLE risk. A stranded allocation
    # cannot be re-keyed -- ownership is non-transferable -- so the number is burned and the PR
    # carrying it is unlandable BY ANYONE.
    [switch]$AllowOrphanedAllocations,
    # Repo to operate on. Defaults to this script's own checkout -- which is what makes an absolute-
    # path invocation from ANY cwd resolve the checkout that owns the worktree. Tests point it at a
    # fixture so the real logic is what gets exercised.
    [string]$RepoRoot
)

$ErrorActionPreference = "Stop"

if (-not $RepoRoot) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
elseif (-not (Test-Path -LiteralPath $RepoRoot)) { throw "RepoRoot does not exist: $RepoRoot" }
else { $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path }

$Parent = Split-Path $RepoRoot -Parent
$RepoName = Split-Path $RepoRoot -Leaf
$WorktreePath = Join-Path $Parent "$RepoName-$Name"

if (-not (Test-Path $WorktreePath)) { throw "No such worktree: $WorktreePath" }

# Guard against losing UNCOMMITTED tracked work. Note this does NOT see committed-but-unpushed
# commits -- `status --porcelain` is empty for a clean worktree holding them; -DeleteBranch's own
# containment check below is what covers those. Untracked entries (??) -- the .venv, node_modules,
# dev db -- are expected and don't block removal.
$tracked = & git -C $WorktreePath status --porcelain | Where-Object { $_ -notmatch '^\?\?' }
if ($tracked -and -not $Force) {
    Write-Host ($tracked -join "`n")
    throw "Worktree has uncommitted tracked changes. Commit/push them, or re-run with -Force."
}

# --- BACKLOG #1293: refuse to strand a ledger number ---------------------------
#
# `Checker.owns` (scripts/hooks/ledger_check.py) decides ownership by CASEFOLDED PATH-STRING
# EQUALITY against the worktree recorded at allocation time. There is no fallback for a recorded
# worktree that no longer exists, so once this directory is gone `owns()` returns false for EVERY
# session, forever. The number is burned and any PR that must re-introduce its heading is
# unlandable by anybody. PR #397 was stranded exactly this way.
#
# THE GATE IS NOT WRONG AND THIS DOES NOT WIDEN IT. It fails closed and is behaving correctly; the
# defect is that there is no route back. Recovery for ALREADY-stranded numbers is an open route
# decision (three candidates, none obviously right -- see the item). PREVENTION needs no such
# decision, which is why it is here and the recovery is not.
#
# WHY IT REFUSES RATHER THAN WARNS. A claim can be released after the fact; an allocation CANNOT be
# re-keyed, because ownership is documented non-transferable. There is no post-hoc fix, so the only
# moment this can be stopped is before the removal.
#
# CANNOT-TELL COUNTS AS AT-RISK. An unreadable allocation record might name this worktree, and an
# unreadable ledger read might hide a heading. Both refuse.
$allocDirRoot = ''
$commonDirPre = "$(& git -C $RepoRoot rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
if ($commonDirPre) { $allocDirRoot = Join-Path $commonDirPre 'mefor-coord/alloc' }

function Test-LedgerNumberOnMain([string]$Kind, [string]$Number) {
    <# $true on origin/main, $false absent, $null CANNOT TELL (which the caller treats as at-risk).

    `git show` on a missing path prints nothing and can exit 0 through a pipe, so EXISTENCE is
    probed with ls-tree and only then read -- the trap the fleet hit twice reading role playbooks. #>
    if ($Kind -eq 'adr') {
        $listed = & git -C $RepoRoot ls-tree -r --name-only 'origin/main' 'docs/adr/' 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $pad = $Number.PadLeft(4, '0')
        foreach ($n in @($listed)) { if ($n -match "/$pad-") { return $true } }
        return $false
    }
    foreach ($ledger in @('docs/BACKLOG.md', 'docs/archive/backlog/BACKLOG-CLOSED.md')) {
        $present = & git -C $RepoRoot ls-tree --name-only 'origin/main' $ledger 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if (-not $present) { continue }
        $body = & git -C $RepoRoot show "origin/main:$ledger" 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        foreach ($ln in @($body)) { if ($ln -match "^##\s+$([regex]::Escape($Number))\.") { return $true } }
    }
    return $false
}

if ($allocDirRoot -and (Test-Path -LiteralPath $allocDirRoot)) {
    . "$PSScriptRoot\..\coord\occupancy.ps1"
    $allocTarget = ConvertTo-Norm $WorktreePath
    $atRisk = @()
    $allocUnreadable = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $allocDirRoot -Filter *.json -File -Recurse -EA SilentlyContinue | Sort-Object FullName)) {
        $a = $null
        try { $a = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
        catch { $allocUnreadable += $f.Name; continue }
        if ((ConvertTo-Norm ([string]$a.worktree)) -ne $allocTarget) { continue }
        $onMain = Test-LedgerNumberOnMain ([string]$a.kind) ([string]$a.number)
        if ($onMain -ne $true) {
            $why = if ($null -eq $onMain) { 'COULD NOT CHECK origin/main' } else { 'not on origin/main' }
            $atRisk += "$([string]$a.kind) #$([string]$a.number) -- $why -- $([string]$a.title)"
        }
    }
    if (($atRisk.Count -gt 0 -or $allocUnreadable.Count -gt 0) -and -not $AllowOrphanedAllocations) {
        $lines = @("This worktree OWNS ledger number(s) whose item is not yet on origin/main.", "")
        foreach ($r in $atRisk) { $lines += "  $r" }
        if ($allocUnreadable.Count -gt 0) {
            $lines += "  $($allocUnreadable.Count) allocation record(s) could not be parsed, and an unreadable"
            $lines += "  record MIGHT name this worktree: $($allocUnreadable -join ', ')"
        }
        $lines += ""
        $lines += "Removing it BURNS those numbers. Ownership is a path-string comparison against this"
        $lines += "directory and is NON-TRANSFERABLE, so once it is gone ledger_check.owns() returns"
        $lines += "false for every session forever and any PR that must re-introduce the heading is"
        $lines += "unlandable BY ANYONE. This is not recoverable after the fact."
        $lines += ""
        $lines += "Do this instead:"
        $lines += "  land the item(s) first, so the heading is on origin/main and ownership stops mattering;"
        $lines += "  or, if you accept burning them, re-run with -AllowOrphanedAllocations."
        throw ($lines -join "`n")
    }
}

# The branch is a FACT ABOUT THE WORKTREE, not a function of its directory name -- since new.ps1 gained
# -Branch the two can differ, and `branch -D $Name` would then delete the WRONG branch (or fail and
# print a misleading warning). Read it FIRST: `worktree remove` destroys the per-worktree admin dir, and
# with it that worktree's HEAD reflog. Same posture prune-merged.ps1 has always used -- it sources the
# branch from git, never from the path.
$branch = ""
$tip = ""
if ($DeleteBranch) {
    $branch = "$(& git -C $WorktreePath rev-parse --abbrev-ref HEAD 2>$null)".Trim()
    if (-not $branch -or $branch -eq "HEAD") {
        throw ("Cannot resolve the branch checked out in $WorktreePath (detached HEAD?). Re-run " +
               "without -DeleteBranch, then delete the branch by name yourself.")
    }
    $tip = "$(& git -C $RepoRoot rev-parse $branch 2>$null)".Trim()
}

# --force is needed regardless: the untracked .venv makes git consider the worktree non-empty.
& git -C $RepoRoot worktree remove --force $WorktreePath
if ($LASTEXITCODE -ne 0) { throw "git worktree remove failed (exit $LASTEXITCODE)" }
& git -C $RepoRoot worktree prune

# --- BACKLOG #1295: release the claims this worktree held ---------------------
#
# `claim.ps1 -Release` is WORKTREE-SCOPED, so once the holder directory is gone NOBODY can release
# its keys normally and each one reads as actively-being-built forever. Measured 2026-08-19: 19 of
# 28 live claims were already orphaned exactly this way -- and THIS script, the sanctioned removal
# path, had no claim handling at all, so it was a source of them rather than a cure.
#
# AFTER THE REMOVAL, NEVER BEFORE. The removal is the event that orphans a claim. Releasing first
# and then failing to remove would hand a LIVE worktree's keys to another session, which is the
# duplicate build the registry exists to stop -- strictly worse than the orphan being fixed.
#
# MATCH ON THE FULL NORMALISED PATH AND NOTHING ELSE: no leaf name, no prefix, no StartsWith. Same
# rule Remove-ClaimsHeldBy states in prune-merged.ps1, for the same reason -- releasing a claim held
# by a DIFFERENT, living worktree is worse than the defect. `ConvertTo-Norm` is DOT-SOURCED rather
# than copied because it must agree with claim.ps1's writer; a fifth private copy of a path
# normaliser is exactly where that agreement breaks without anyone noticing.
#
# UNREADABLE IS NOT ABSENT. A claim file that will not parse MIGHT name this worktree, so it is
# reported and LEFT ALONE rather than deleted on a guess.
#
# REPORTS, NEVER THROWS. The worktree is already gone by this point; throwing here would report the
# whole removal as failed and invite a re-run of something that already succeeded.
try {
    . "$PSScriptRoot\..\coord\occupancy.ps1"
    $commonDir = "$(& git -C $RepoRoot rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
    $claimsDir = if ($commonDir) { Join-Path $commonDir 'mefor-coord/claims' } else { '' }
    if ($claimsDir -and (Test-Path -LiteralPath $claimsDir)) {
        $target = ConvertTo-Norm $WorktreePath
        $released = @()
        $unreadable = @()
        foreach ($f in @(Get-ChildItem -LiteralPath $claimsDir -Filter *.json -File -EA SilentlyContinue | Sort-Object Name)) {
            $c = $null
            try { $c = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
            catch { $unreadable += $f.Name; continue }
            if ((ConvertTo-Norm ([string]$c.worktree)) -ne $target) { continue }
            try {
                Remove-Item -LiteralPath $f.FullName -Force -EA Stop
                $released += [string]$c.key
            }
            catch {
                Write-Warning ("claim '$([string]$c.key)' was held by the removed worktree and could NOT be " +
                               "released: $($_.Exception.Message). Release it yourself: " +
                               "claim.ps1 -Release $([string]$c.key) -Force")
            }
        }
        if ($released.Count -gt 0) {
            Write-Host "Released $($released.Count) claim(s) held by the removed worktree: $($released -join ', ')"
        }
        if ($unreadable.Count -gt 0) {
            Write-Warning ("$($unreadable.Count) claim file(s) could not be parsed and were LEFT IN PLACE " +
                           "($($unreadable -join ', ')). One of them may name the removed worktree; an " +
                           "unreadable claim is not an absent one, so it is not deleted on a guess.")
        }
    }
}
catch {
    Write-Warning ("could not sweep claims for the removed worktree: $($_.Exception.Message). Any claim it " +
                   "held is now orphaned -- `claim.ps1 -Release` is worktree-scoped, so use -Force to clear it.")
}

if ($DeleteBranch) {
    # LOSSLESS-DELETE DISCIPLINE, as defined by prune-merged.ps1's Remove-BranchSafely: `-d` first, and
    # `-D` only after re-verifying at THAT MOMENT that the branch has nothing beyond the main ref.
    # It matters here more than anywhere: the removal above already took the per-worktree HEAD reflog,
    # and `branch -D` takes the ref AND the branch reflog, so an unmerged force-delete leaves the
    # commits reachable from no ref and no reflog. The tip is printed either way, so scrollback is the undo.
    Write-Host "Branch '$branch' is at $tip. Recover a deleted branch with: git -C `"$RepoRoot`" branch <name> $tip"
    & git -C $RepoRoot branch -d $branch 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $unique = "$(& git -C $RepoRoot rev-list --count "origin/main..$branch" 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $unique) {
            Write-Warning ("could not re-verify '$branch' against origin/main, so the branch was KEPT. " +
                           "Delete it yourself once you are sure: git branch -D $branch")
        }
        elseif ([int]$unique -ne 0) {
            Write-Warning ("$unique commit(s) on '$branch' are not on origin/main, so the branch was KEPT " +
                           "(the worktree is gone; the branch still holds them). Delete it yourself once " +
                           "you are sure: git branch -D $branch")
        }
        else {
            & git -C $RepoRoot branch -D $branch
            if ($LASTEXITCODE -ne 0) { Write-Warning "could not delete branch '$branch'. Delete manually if intended." }
        }
    }
}

Write-Host "Removed worktree '$WorktreePath'." -ForegroundColor Green
