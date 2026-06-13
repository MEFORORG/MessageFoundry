<#
.SYNOPSIS
    Create an isolated git worktree (+ its own .venv) for a parallel MessageFoundry build session.

.DESCRIPTION
    Two parallel efforts (e.g. two Claude Code chats) can't safely build in the same working tree —
    one's branch switch / edits clobber the other. This adds a git worktree as a SIBLING directory
    (<repo>-<Name>) on its own branch, then bootstraps that worktree's own Python virtualenv so its
    tests/tools run against its own checkout. The worktree shares the same .git/history/remote, so
    the normal branch -> PR -> merge flow is unchanged.

    Run from anywhere (it locates the repo via this script's path). See docs/WORKTREES.md.

.EXAMPLE
    .\new.ps1 -Name alerts
    .\new.ps1 -Name sqltuning -Base main -Sqlserver -Ide
    .\new.ps1 -Name quicklook -NoInstall
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Name,
    [string]$Base = "main",
    [string]$Python = "python",
    [switch]$Sqlserver,   # also install the [sqlserver] extra
    [switch]$Ide,         # also run `npm install` for the VS Code extension
    [switch]$NoInstall    # create the worktree only; skip the venv bootstrap
)

$ErrorActionPreference = "Stop"

# Repo root is two levels up from scripts\worktree\.
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$Parent = Split-Path $RepoRoot -Parent
$RepoName = Split-Path $RepoRoot -Leaf
$WorktreePath = Join-Path $Parent "$RepoName-$Name"

if (Test-Path $WorktreePath) { throw "Worktree path already exists: $WorktreePath" }

# Reuse an existing branch if it's there, else create it from -Base.
$branchExists = & git -C $RepoRoot branch --list $Name
Write-Host "Creating worktree '$WorktreePath' on branch '$Name'..."
if ($branchExists) {
    & git -C $RepoRoot worktree add $WorktreePath $Name
} else {
    & git -C $RepoRoot worktree add $WorktreePath -b $Name $Base
}
if ($LASTEXITCODE -ne 0) { throw "git worktree add failed (exit $LASTEXITCODE)" }

function Show-NextSteps {
    Write-Host ""
    Write-Host "Worktree ready: $WorktreePath (branch '$Name')" -ForegroundColor Green
    Write-Host "Next steps:"
    Write-Host "  cd `"$WorktreePath`""
    if (-not $NoInstall) {
        Write-Host "  .\.venv\Scripts\Activate.ps1        # use this worktree's env"
    }
    if ($Ide) {
        Write-Host "  code --extensionDevelopmentPath=`"$WorktreePath\ide`" `"$WorktreePath\mefor.code-workspace`""
    }
    Write-Host "  # ... build/commit/push on branch '$Name'; open a PR as usual."
    Write-Host "  # When done (run from the MAIN checkout): scripts\worktree\remove.ps1 -Name $Name"
}

if ($NoInstall) {
    Write-Host "Skipped env bootstrap (-NoInstall). Create a venv before running tests."
    Show-NextSteps
    return
}

# --- bootstrap the worktree's own virtualenv ---------------------------------
# Per-worktree venv so the worktree's tests/tools resolve its OWN checkout (a shared venv with an
# editable install would import whichever checkout it was installed from).
$venv = Join-Path $WorktreePath ".venv"
$venvPy = Join-Path $venv "Scripts\python.exe"
$extras = if ($Sqlserver) { "dev,console,sqlserver" } else { "dev,console" }

Write-Host "Creating virtualenv + installing .[$extras] (this can take a minute)..."
& $Python -m venv $venv
if ($LASTEXITCODE -ne 0) { throw "venv creation failed (is '$Python' on PATH?)" }
& $venvPy -m pip install --upgrade pip | Out-Null

Push-Location $WorktreePath
try {
    & $venvPy -m pip install -e ".[$extras]"
    if ($LASTEXITCODE -ne 0) { throw "pip install -e .[$extras] failed (exit $LASTEXITCODE)" }
} finally {
    Pop-Location
}

if ($Ide) {
    $npm = Get-Command npm -ErrorAction SilentlyContinue
    if ($npm) {
        Write-Host "Installing IDE extension dependencies (npm)..."
        & npm --prefix (Join-Path $WorktreePath "ide") install
        if ($LASTEXITCODE -ne 0) { Write-Warning "npm install failed; set up ide/ manually." }
    } else {
        Write-Warning "npm not found on PATH; skipped IDE dependency install."
    }
}

Show-NextSteps
