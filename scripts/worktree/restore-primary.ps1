<#
.SYNOPSIS
    Re-attach the shared primary checkout to its home branch after a session left it detached or on the
    wrong branch.

.DESCRIPTION
    The primary checkout is the one directory several sessions stand in at once. When a session runs
    `git checkout <its-branch>` there -- or leaves HEAD detached -- every other session's files silently
    become a different commit's files. The worktree gate (scripts/hooks/worktree_gate.ps1) now DENIES the
    tree-swapping git verbs in the primary, so this script is the sanctioned way back: an agent may
    REPAIR the primary, but it may not hijack it.

    "Home branch" is, in order:
      1. `git config mefor.homeBranch`  (set it once if you want something other than the default)
      2. `main-current`, if that branch exists
      3. `main`

    It REFUSES if the primary's tree is dirty -- re-attaching would either carry someone's uncommitted
    work onto another branch or lose it. Move that work out first (scripts\worktree\rescue.ps1), or pass
    -Force to re-attach anyway (only safe when you know the changes are junk).

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\restore-primary.ps1
    pwsh -NoProfile -File scripts\worktree\restore-primary.ps1 -Branch main
    pwsh -NoProfile -File scripts\worktree\restore-primary.ps1 -WhatIf
#>
[CmdletBinding(SupportsShouldProcess = $true)]
param(
    # Override the home branch for this run.
    [string]$Branch,
    # Re-attach even if the primary's tree is dirty. The changes stay in the tree; they are not discarded.
    [switch]$Force
)

$ErrorActionPreference = "Stop"

# The PRIMARY is the first entry of `git worktree list` -- the main working tree, whichever worktree this
# script happens to be running from.
$primary = (& git worktree list --porcelain |
        Select-String -Pattern '^worktree (.+)$' |
        Select-Object -First 1).Matches[0].Groups[1].Value
if (-not $primary) { throw "Could not locate the primary checkout (is this a git repository?)." }
$primary = $primary -replace '/', '\'

$head = (& git -C $primary rev-parse --abbrev-ref HEAD).Trim()
$detached = ($head -eq "HEAD")

if (-not $Branch) {
    $Branch = (& git -C $primary config --get mefor.homeBranch)
    if (-not $Branch) {
        # A statement cannot live inside an `if (...)` condition in PowerShell -- run it, then test.
        & git -C $primary show-ref --verify --quiet refs/heads/main-current
        $Branch = if ($LASTEXITCODE -eq 0) { "main-current" } else { "main" }
    }
    $Branch = $Branch.Trim()
}

& git -C $primary show-ref --verify --quiet "refs/heads/$Branch"
if ($LASTEXITCODE -ne 0) {
    throw "Home branch '$Branch' does not exist in $primary. Create it (git branch $Branch origin/main) or pass -Branch."
}

Write-Host "primary : $primary"
Write-Host "HEAD    : $(if ($detached) { "DETACHED at $((& git -C $primary rev-parse --short HEAD).Trim())" } else { $head })"
Write-Host "home    : $Branch"

if ($head -eq $Branch) {
    Write-Host ""
    Write-Host "Nothing to do -- the primary is already on '$Branch'." -ForegroundColor Green
    return
}

$dirty = @(& git -C $primary status --porcelain)
if ($dirty.Count -gt 0 -and -not $Force) {
    Write-Host ""
    Write-Warning "The primary has $($dirty.Count) uncommitted change(s). Re-attaching would carry them onto '$Branch'."
    $dirty | Select-Object -First 8 | ForEach-Object { Write-Host "  $_" }
    Write-Host ""
    Write-Host "Move the work to a worktree of its own first (it is not discarded):"
    Write-Host "    pwsh -NoProfile -File scripts\worktree\rescue.ps1 -Name <short-task-name>"
    Write-Host "Or, if you know the changes are junk, re-run with -Force."
    throw "Refusing to re-attach a dirty primary checkout."
}

if ($PSCmdlet.ShouldProcess($primary, "git checkout $Branch")) {
    & git -C $primary checkout $Branch
    if ($LASTEXITCODE -ne 0) { throw "git checkout $Branch failed in $primary (exit $LASTEXITCODE)." }

    Write-Host ""
    Write-Host "Primary re-attached to '$Branch'." -ForegroundColor Green
    & git -C $primary status -sb | Select-Object -First 1
    Write-Host ""
    Write-Host "If it is behind, update it:  git -C `"$primary`" pull --ff-only"
}
