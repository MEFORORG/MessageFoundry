<#
.SYNOPSIS
    Remove a git worktree created by new.ps1 (and optionally its branch).

.DESCRIPTION
    Removes the sibling worktree directory <repo>-<Name>. Refuses if the worktree has uncommitted
    *tracked* changes (so you don't lose work) unless -Force; the untracked .venv / node_modules are
    expected and removed automatically. Run from the MAIN checkout (git can't remove the worktree
    you're standing in). See docs/WORKTREES.md.

.EXAMPLE
    .\remove.ps1 -Name alerts
    .\remove.ps1 -Name alerts -DeleteBranch
    .\remove.ps1 -Name alerts -Force        # discard uncommitted tracked changes too
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Name,
    [switch]$Force,         # remove even with uncommitted tracked changes
    [switch]$DeleteBranch   # also delete the local branch
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Parent = Split-Path $RepoRoot -Parent
$RepoName = Split-Path $RepoRoot -Leaf
$WorktreePath = Join-Path $Parent "$RepoName-$Name"

if (-not (Test-Path $WorktreePath)) { throw "No such worktree: $WorktreePath" }

# Guard against losing committed-but-unpushed or modified tracked work. Untracked entries (??) —
# the .venv, node_modules, dev db — are expected and don't block removal.
$tracked = & git -C $WorktreePath status --porcelain | Where-Object { $_ -notmatch '^\?\?' }
if ($tracked -and -not $Force) {
    Write-Host ($tracked -join "`n")
    throw "Worktree has uncommitted tracked changes. Commit/push them, or re-run with -Force."
}

# --force is needed regardless: the untracked .venv makes git consider the worktree non-empty.
& git -C $RepoRoot worktree remove --force $WorktreePath
if ($LASTEXITCODE -ne 0) { throw "git worktree remove failed (exit $LASTEXITCODE)" }
& git -C $RepoRoot worktree prune

# RELEASE THE BIRTH PIN. new.ps1 takes a 6h pin on every worktree it creates, and nothing used to
# release it -- so a create/work/remove cycle inside that window left an UNEXPIRED pin naming a
# directory that no longer existed, which made prune-merged.ps1's whole occupancy fence unavailable
# for the rest of the 6h, for every session, with no override flag. (The reader now also ignores a pin
# whose path is gone; that is the safety net. This is the tidy-up, so the store does not only grow.)
# Best-effort by contract: a pin that will not delete must never fail a removal that already happened.
try {
    . "$PSScriptRoot\..\coord\pin.ps1"
    $released = Remove-WorktreePins -Path $WorktreePath -Repo $RepoRoot
    if ($released -gt 0) { Write-Host "Released $released pruner pin(s) on this worktree." -ForegroundColor DarkGray }
}
catch {
    Write-Host "NOTE: could not release the pruner pin(s) for '$WorktreePath' ($($_.Exception.Message)); they name a path that is gone, which the reader ignores." -ForegroundColor Yellow
}

if ($DeleteBranch) {
    & git -C $RepoRoot branch -D $Name
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not delete branch '$Name' (unmerged?). Delete manually if intended." }
}

Write-Host "Removed worktree '$WorktreePath'." -ForegroundColor Green
