<#
.SYNOPSIS
    Move uncommitted work OUT of the shared primary checkout and into a fresh worktree + branch.

.DESCRIPTION
    The companion to the worktree gate (scripts\hooks\worktree_gate.ps1). A gate that stops you writing
    into the primary is infuriating if you are already half-way through a change there -- so this moves
    what you have, instead of asking you to redo it.

    It stashes the primary's uncommitted work (tracked AND untracked), creates a worktree branched off the
    primary's CURRENT commit -- not origin/main, so the stash applies cleanly -- and pops the stash there.

    The stash is the safety net: if the pop fails for any reason, the work is still in `git stash list`
    and this script tells you so rather than swallowing it. Nothing is ever discarded.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\rescue.ps1 -Name alerts-fix
    pwsh -NoProfile -File scripts\worktree\rescue.ps1 -Name alerts-fix -NoInstall   # skip the venv build
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Name,
    [switch]$NoInstall,
    [switch]$Sqlserver
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Parent   = Split-Path $RepoRoot -Parent
$Target   = Join-Path $Parent ("{0}-{1}" -f (Split-Path $RepoRoot -Leaf), $Name)

if (Test-Path $Target) { throw "Worktree path already exists: $Target  (pick another -Name, or just work in it)" }

$dirty = @(& git -C $RepoRoot status --porcelain)
if ($dirty.Count -eq 0) {
    Write-Host "Nothing to rescue: $RepoRoot is clean." -ForegroundColor Yellow
    Write-Host "You want a plain new worktree instead:  scripts\worktree\new.ps1 -Name $Name"
    return
}

$sha = (& git -C $RepoRoot rev-parse HEAD).Trim()
Write-Host "Rescuing $($dirty.Count) change(s) from $RepoRoot (at $($sha.Substring(0,7)))..."
$dirty | Select-Object -First 12 | ForEach-Object { Write-Host "  $_" }
if ($dirty.Count -gt 12) { Write-Host "  ... and $($dirty.Count - 12) more" }

# -u carries untracked files too; without it they would be left behind in the primary and silently
# duplicated once the worktree recreated them.
$stashMsg = "rescue -> $Name"
& git -C $RepoRoot stash push --include-untracked -m $stashMsg
if ($LASTEXITCODE -ne 0) { throw "git stash push failed (exit $LASTEXITCODE) -- nothing was moved." }

$stashed = $true
try {
    # Branch the worktree off the primary's CURRENT commit so the stash applies without conflict. (new.ps1
    # would otherwise default to origin/main, which the primary is often many commits behind.)
    $newArgs = @("-NoProfile", "-File", (Join-Path $PSScriptRoot "new.ps1"), "-Name", $Name, "-Base", $sha)
    if ($NoInstall) { $newArgs += "-NoInstall" }
    if ($Sqlserver) { $newArgs += "-Sqlserver" }
    & pwsh @newArgs
    if ($LASTEXITCODE -ne 0) { throw "new.ps1 failed (exit $LASTEXITCODE)" }

    & git -C $Target stash pop
    if ($LASTEXITCODE -ne 0) { throw "git stash pop failed in $Target (exit $LASTEXITCODE)" }
    $stashed = $false

    Write-Host ""
    Write-Host "Rescued into $Target (branch '$Name', off $($sha.Substring(0,7)))." -ForegroundColor Green
    Write-Host "The primary checkout is clean again. Continue there:"
    Write-Host "  cd `"$Target`""
    if (-not $NoInstall) { Write-Host "  .\.venv\Scripts\Activate.ps1" }
}
finally {
    if ($stashed) {
        Write-Warning "Rescue did not complete. YOUR WORK IS SAFE -- it is in the stash:"
        Write-Warning "    git -C `"$RepoRoot`" stash list        # look for: $stashMsg"
        Write-Warning "    git -C `"$RepoRoot`" stash pop         # put it back in the primary"
        Write-Warning "Nothing was discarded. Resolve the failure above, then retry or pop it by hand."
    }
}
