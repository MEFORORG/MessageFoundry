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

if ($DeleteBranch) {
    & git -C $RepoRoot branch -D $Name
    if ($LASTEXITCODE -ne 0) { Write-Warning "could not delete branch '$Name' (unmerged?). Delete manually if intended." }
}

Write-Host "Removed worktree '$WorktreePath'." -ForegroundColor Green
