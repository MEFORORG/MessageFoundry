# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    The one rule that names the work tree root a lane level is keyed on. Defines functions only.

.DESCRIPTION
    Dot-sourced by lane.ps1, the only writer of a lane level, and by scripts/hooks/lane-level.ps1,
    which reads it back. Both must key the same box, so the rule lives here once: lane.ps1 keyed on
    git's resolved root while the hook keyed on the current directory, and through a junction the two
    named different boxes, so a stated lane read as unstated every turn (BACKLOG #5486).
#>

# git writes UTF-8; PowerShell decodes a native command's output with [Console]::OutputEncoding,
# which is an OEM code page on a stock console, so a non-ASCII path segment would come back mangled
# and key a box nobody reads. Every git call here that reads a path runs inside this; the caller's
# encoding is put back afterwards. Get-CoordLocalRoot in coord-root.ps1, which reads
# --git-common-dir for Resolve-CoordSharedRoot, now reads git's stream as UTF-8 itself (BACKLOG #7571).
# A host with no console attached may refuse the setter (as alloc.ps1 and worktree/remove.ps1 note).
# The action then runs in the encoding it already has, rather than the refusal reaching the caller:
# the lane-level hook would otherwise read it as an unresolved root and print SKIPPED on every Stop
# (BACKLOG #5486). The refusal is reported on stderr, as alloc.ps1 reports its own, unless that
# encoding is UTF-8 already; a non-ASCII path may then come back mangled, and
# Resolve-LaneWorktreeRoot refuses a root that names no directory. Only an encoding that was
# actually switched is put back.
function Invoke-GitUtf8([scriptblock]$Action) {
    $saved = $null
    $switched = $false
    try {
        $saved = [Console]::OutputEncoding
        [Console]::OutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $switched = $true
    } catch {
        $why = $_.Exception.Message
        if (-not $saved -or $saved.CodePage -ne 65001) {
            try { [Console]::Error.WriteLine("lane-root.ps1: WARNING -- git's output could not be set to decode as UTF-8 ($why), so a path holding a non-ASCII character may come back mangled.") } catch { }
        }
    }
    try {
        & $Action
    } finally {
        if ($switched) { try { [Console]::OutputEncoding = $saved } catch { } }
    }
}

function Resolve-LaneWorktreeRoot([string]$From) {
    # Returns Path (the root to key on) or Error (why none can be named; the caller decides whether
    # that refuses, as in lane.ps1, or falls back, as in the read-only hook).
    $revParse = @()
    $revParseExit = -1
    try {
        $revParse = @(Invoke-GitUtf8 { & git -C $From -c core.quotePath=false rev-parse --path-format=absolute --show-toplevel --show-prefix 2>$null })
        $revParseExit = $LASTEXITCODE
    } catch {
        return [pscustomobject]@{ Path = $null; Error = "git could not be run in $From ($($_.Exception.Message))" }
    }
    $top = if ($revParse.Count -ge 1) { ([string]$revParse[0]).Trim() } else { '' }
    if ($revParseExit -ne 0 -or -not $top) {
        return [pscustomobject]@{ Path = $null; Error = "git could not name the work tree root for $From" }
    }
    $prefix = if ($revParse.Count -ge 2) { ([string]$revParse[1]).Trim().TrimEnd('/') } else { '' }
    # A removed worktree under the primary checkout (.claude/worktrees/<name> with no .git left) has
    # git walk up to the primary, so keying there would overwrite the primary's level. That container
    # is the population the worktree tooling names (scripts/worktree/find-emptied-worktrees.ps1). A
    # live worktree there is its own toplevel, so a directory in it that git places in the primary is
    # no live tree's, whether or not the primary ignores the container: it refuses without asking
    # check-ignore, whose answer could only let it through. Any other directory of a live tree,
    # ignored or not (such as .venv\Scripts), is still that tree's work and keys on its root.
    if ("$prefix/" -like '.claude/worktrees/*') {
        return [pscustomobject]@{ Path = $null; Error = "$From is under the worktree container of $top but is no worktree of its own (a removed worktree reads this way)" }
    }
    # A root that names no directory was decoded in some page other than UTF-8 (Invoke-GitUtf8 above),
    # and keying on it would write a level no reader computes, so it refuses instead.
    if (-not (Test-Path -LiteralPath $top -PathType Container)) {
        return [pscustomobject]@{ Path = $null; Error = "git named $top as the work tree root for $From, but no such directory exists (its output may have been decoded in a code page other than UTF-8)" }
    }
    # git's resolved root, the path claim.ps1 records and seat records carry, so a tree reached
    # through a junction keys the same lane and claim hash as its target.
    return [pscustomobject]@{ Path = [System.IO.Path]::GetFullPath($top); Error = $null }
}
