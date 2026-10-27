# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Name each worktree folder that was emptied in place, and the Claude Desktop log line that did it.

.DESCRIPTION
    BACKLOG #2525. A folder under `<primary>\.claude\worktrees\` with no `.git` and absent from
    `git worktree list` is what a Desktop GC's `git worktree remove --force` leaves when a session
    held the folder open. This lists each one, and beside it every Desktop log line that names it:
    `[reapUntrackedWorktreeDir] git worktree remove refused` with `failed to delete`, or
    `Git worktree remove failed, will try manual cleanup` with `Permission denied`.
    The rule lives in worktree-audit.ps1, Find-EmptiedWorktrees; hygiene-report.ps1 prints the same
    list in its section f. This is the on-demand form.

    READ-ONLY. It runs `git worktree list` and reads files. It deletes, moves and re-registers
    nothing. To recover a folder a session is still in, re-add the worktree at the same path on the
    same branch, then lock it by hand: re-declaring the seat does not, since -Declare only relabels
    an existing lock (docs/WORKTREES.md).

.PARAMETER RepoRoot
    Any checkout of the repository. Defaults to this script's own.

.PARAMETER LogRoot
    Directories holding Desktop `*.log` files. Defaults to every profile's logs directory.

.PARAMETER Json
    Print JSON instead of text.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\find-emptied-worktrees.ps1
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string[]]$LogRoot,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'
$PSNativeCommandUseErrorActionPreference = $false

. "$PSScriptRoot\..\coord\occupancy.ps1"
. "$PSScriptRoot\worktree-audit.ps1"

if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
$wts = @(Get-RepoWorktrees $RepoRoot)
if ($wts.Count -eq 0) {
    [Console]::Error.WriteLine("find-emptied-worktrees: git lists no worktree for $RepoRoot, so nothing was checked.")
    exit 2
}
# The first `worktree list` entry is the primary, the same authority occupancy.ps1 uses.
$primary = $wts[0].Path
$found = @(Find-EmptiedWorktrees -PrimaryPath $primary -Worktrees $wts -LogRoot $LogRoot)

if ($Json) {
    ConvertTo-Json -InputObject ([ordered]@{ primary = $primary; emptied = $found }) -Depth 6
    exit 0
}
if ($found.Count -eq 0) {
    Write-Output "No emptied worktree folder under $(Join-Path $primary '.claude\worktrees')."
    exit 0
}
Write-Output "$($found.Count) emptied worktree folder(s) under $(Join-Path $primary '.claude\worktrees'):"
foreach ($f in $found) {
    Write-Output ""
    Write-Output "$($f.Path)  ($($f.Entries) entr$(if ($f.Entries -eq 1) { 'y' } else { 'ies' }) left)"
    if ($f.LogLines.Count -eq 0) { Write-Output '  no Desktop log line names it (the logs rotate; this is not evidence either way)' }
    foreach ($l in $f.LogLines) { Write-Output "  $($l.File):$($l.LineNumber): $($l.Text)" }
}
exit 0
