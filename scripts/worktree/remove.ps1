<#
.SYNOPSIS
    Remove a git worktree created by new.ps1 (and optionally its branch).

.DESCRIPTION
    Removes the sibling worktree directory <repo>-<Name>. Refuses if the worktree has uncommitted
    *tracked* changes (so you don't lose work) unless -Force; the untracked .venv / node_modules are
    expected and removed automatically. Run from the MAIN checkout (git can't remove the worktree
    you're standing in). See docs/WORKTREES.md.

    -Name is the DIRECTORY component only. -DeleteBranch deletes whichever branch that worktree
    actually has checked out, read from git -- not a branch named after the directory. Since new.ps1
    gained -Branch the two can differ.

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
    [switch]$DeleteBranch   # also delete the local branch
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
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
