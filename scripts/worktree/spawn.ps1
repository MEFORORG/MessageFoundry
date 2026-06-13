<#
.SYNOPSIS
    Create a parallel-session worktree (via new.ps1) AND open a new editor window in it - one step.

.DESCRIPTION
    Wraps scripts\worktree\new.ps1 (which does the git worktree + per-worktree .venv bootstrap),
    then opens a fresh VS Code window on the new worktree so you can start a second Claude Code chat
    there immediately. Same flags as new.ps1. See docs/WORKTREES.md.

    The whole point of worktrees is that each parallel session gets its OWN branch + files; remember
    to start the second chat in the window this opens, not back in the main checkout.

.EXAMPLE
    .\spawn.ps1 -Name alerts
    .\spawn.ps1 -Name alerts -Base feature/harness-engine-coverage -Ide
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [ValidatePattern('^[A-Za-z0-9._-]+$')]
    [string]$Name,
    [string]$Base = "main",
    [string]$Python = "python",
    [switch]$Sqlserver,
    [switch]$Ide,
    [switch]$NoInstall
)

$ErrorActionPreference = "Stop"

# Forward everything to new.ps1 (it owns the worktree + venv creation; it throws on failure, which
# stops us here before we try to open an editor on a worktree that wasn't created).
$newArgs = @{ Name = $Name; Base = $Base; Python = $Python }
if ($Sqlserver) { $newArgs.Sqlserver = $true }
if ($Ide) { $newArgs.Ide = $true }
if ($NoInstall) { $newArgs.NoInstall = $true }
& (Join-Path $PSScriptRoot 'new.ps1') @newArgs

# Recompute the worktree path the same way new.ps1 does (<repo-parent>\<repo-name>-<Name>).
$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$WorktreePath = Join-Path (Split-Path $RepoRoot -Parent) ((Split-Path $RepoRoot -Leaf) + "-$Name")

if (Get-Command code -ErrorAction SilentlyContinue) {
    Write-Host ""
    Write-Host "Opening a new VS Code window in $WorktreePath ..." -ForegroundColor Green
    & code $WorktreePath
    Write-Host "Start your second Claude Code chat IN THAT WINDOW - it's isolated on branch '$Name'." -ForegroundColor Green
} else {
    Write-Warning "'code' (the VS Code CLI) is not on PATH; open this folder yourself and start the second chat there:"
    Write-Host "  $WorktreePath"
}
