# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    The per-worktree gates a removal is judged by: idle, clean, tip held, Claude-managed. Dot-source it.

.DESCRIPTION
    ONE copy of each gate, shared by prune-merged.ps1 (its decision pass, its report-only pass and its
    -Apply re-check) and by finished-worktree-removal.ps1 (the re-check that run-daily-prune.ps1
    -RemoveFinishedClaudeWorktrees makes immediately before each removal). They moved here out of
    prune-merged.ps1, so the nightly removal judges a tree exactly the way the report that listed it
    did. Two copies of a safety check drift, and the copy that drifts is the one nobody tests.

    Defines in the caller's scope: $IDLE_FLOOR_HOURS, $ACTIVITY_MTIME_FILES, Get-ReflogLastEntry,
    Get-WorktreeActivity (occupancy signal 2; prune-merged.ps1's header says what it can and cannot
    see), Test-WorktreeClean, Get-TipHolders, Test-ClaudeManagedPath, Get-FlaggedFileCount,
    Get-WorkingTreeActivity, Get-WorktreeOnlyCommitCount, Read-CoordRecord, Get-ClaimedWorktreeIndex and Get-IgnoredCloneCount.
#>

# The floor under -IdleHours. Signal 2 has been measured at 10.4h on a worktree that was demonstrably
# occupied, so a window under this one releases trees that measurement says are in use.
$IDLE_FLOOR_HOURS = 12

#: Metadata whose MTIME is the activity reading. `logs/HEAD` is deliberately NOT in this list; it is
#: read by content instead, for the reason written out over Get-ReflogLastEntry.
$ACTIVITY_MTIME_FILES = @('index', 'HEAD', 'ORIG_HEAD', 'FETCH_HEAD', 'COMMIT_EDITMSG', 'MERGE_MSG')

function Get-ReflogLastEntry {
    param([string]$LogPath)
    # THE REFLOG IS READ BY CONTENT, NOT BY MTIME, AND THAT IS THE WHOLE POINT.
    #
    # A reflog line is:  <old-oid> <new-oid> <name> <<email>> <epoch> <tz>\t<message>
    # The epoch is stamped by the operation that APPENDED the entry. Nothing which rewrites the file
    # without appending to it can move that number. The file's mtime is exactly the opposite: it
    # moves for any write at all, including one that changes nothing.
    #
    # MEASURED 2026-08-18 on this repository. A `git gc` ran at 08:15:34-08:16:05 -- packed-refs
    # rewritten at 08:15:34, the packs at 08:16:02-08:16:05 -- and its reflog expiry rewrote every
    # reflog in place. **48 of 50** worktree `logs/HEAD` files came out carrying the IDENTICAL mtime
    # `2026-08-18 08:15:42`, to the second, while their contents were days older: one worktree's last
    # entry is `2026-08-14 12:55:35`, four days before its own mtime.
    #
    # Signal 2 took the newest mtime, so that single gc made EVERY worktree in the repository read
    # "recently active -- someone may be working here" for the next -IdleHours. On the run that found
    # it, 11 of 14 candidates were vetoed on that basis alone and the tool removed nothing. With 50
    # worktrees and 9 live sessions producing loose objects, gc is frequent enough that the veto can
    # sit permanently on -- and a veto that always fires carries no more information than one that
    # never fires, which is the failure class docs/adr/0158 names.
    #
    # Returns $null when there is no entry to read. The CALLER decides what that means, because "the
    # file is empty" and "the file would not parse" are not the same fact and must not act alike.
    try { $last = Get-Content -LiteralPath $LogPath -Tail 1 -ErrorAction Stop } catch { return $null }
    if (-not $last) { return $null }
    # Split at the tab FIRST, so a committer name containing '>' cannot be mistaken for the closing
    # bracket of the email. What remains ends with "<epoch> <tz>", and anchoring the match on that end
    # is what makes it exact rather than merely plausible.
    $head = ([string]$last -split "`t", 2)[0]
    $m = [regex]::Match($head, '(\d{9,11})\s+[+-]\d{4}\s*$')
    if (-not $m.Success) { return $null }
    try { return [DateTimeOffset]::FromUnixTimeSeconds([long]$m.Groups[1].Value).LocalDateTime }
    catch { return $null }
}

function Get-WorktreeActivity {
    param([string]$Path)
    # The worktree's PRIVATE git metadata only. Deliberately NOT the working files: a venv install or a
    # test run churns those, so their mtimes would veto everything forever and the veto would stop
    # meaning anything. The cost is that a session which only edits files and runs no git command is
    # invisible to this signal too -- stated in the header rather than papered over.
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $gitdir = & git -C $Path rev-parse --absolute-git-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $gitdir) { return $null }
    $gitdir = ([string]$gitdir).Trim()
    if (-not (Test-Path -LiteralPath $gitdir)) { return $null }
    $newest = $null
    foreach ($rel in $ACTIVITY_MTIME_FILES) {
        $f = Join-Path $gitdir $rel
        if (Test-Path -LiteralPath $f) {
            $t = (Get-Item -LiteralPath $f -Force).LastWriteTime
            if ($null -eq $newest -or $t -gt $newest) { $newest = $t }
        }
    }
    $log = Join-Path $gitdir 'logs/HEAD'
    if (Test-Path -LiteralPath $log) {
        $item = Get-Item -LiteralPath $log -Force
        $t = Get-ReflogLastEntry -LogPath $log
        if ($null -eq $t -and $item.Length -gt 0) {
            # Non-empty, and it would not parse. FALL BACK TO THE MTIME, which is the reading this
            # had before. A parse failure must never be the thing that makes a worktree look idle,
            # because idle is the direction that REMOVES one: a reflog shape this does not recognise
            # is a reason to keep vetoing, not a reason to stop.
            $t = $item.LastWriteTime
        }
        # A zero-length logs/HEAD contributes NOTHING, and that is not an error: every entry has
        # expired, so the reflog holds no evidence in either direction and the six mtimes above still
        # speak. Reading its mtime here would reinstate the exact bug this function exists to remove,
        # on the oldest worktrees in the repository -- which are the ones most likely to be prunable.
        if ($null -ne $t -and ($null -eq $newest -or $t -gt $newest)) { $newest = $t }
    }
    return $newest
}

# ONE cleanliness routine, called by the decision pass AND by the re-check immediately before removal.
# The re-check used to collapse "the directory vanished", "git status exited 128", "an untracked file
# appeared" and "somebody edited a tracked file" into the single string "no longer clean" -- discarding
# the distinction at the exact moment an operator most needs it, because something changed underneath a
# destructive run.
# FAILS CLOSED: an unreadable status (a moved-away or half-deleted worktree exits 128 with no output)
# used to be indistinguishable from "no changes" and pointed straight at destruction. So is a folder git
# could not open: git warns on stderr, skips it and still exits 0, so its contents are unknown.
# -AllUntracked adds `--untracked-files=all`, so an untracked file inside an untracked directory is
# counted as a file rather than folded into one directory line. The verdict is the same either way.
function Test-WorktreeClean {
    param([string]$Path, [switch]$AllUntracked)
    if (-not (Test-Path -LiteralPath $Path)) {
        return @{ Clean = $false; Reasons = @('directory is missing (already half-removed? investigate before pruning)') }
    }
    # Built as an explicit array. `$x = if (...) { @('--flag') }` unrolls to a bare STRING, and splatting
    # a string hands git one character per argument -- which git reads as pathspecs, matches nothing, and
    # reports clean. Measured while writing this: a dirty tree read clean.
    $statusArgs = @('-C', $Path, '--no-optional-locks', 'status', '--porcelain')
    if ($AllUntracked) { $statusArgs += '--untracked-files=all' }
    $raw = @(& git @statusArgs 2>&1)
    $statusExit = $LASTEXITCODE
    if ($statusExit -ne 0) {
        return @{ Clean = $false; Reasons = @("git status failed (exit $statusExit) -- cannot establish it is clean") }
    }
    $status = @($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] } | ForEach-Object { "$_" })
    $unopened = @($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] -and "$_" -match 'could not open' })
    $trackedChanges = @($status | Where-Object { $_ -notmatch '^\?\?' })
    $untracked = @($status | Where-Object { $_ -match '^\?\?' })
    $r = @()
    if ($unopened.Count -gt 0) { $r += "git could not open $($unopened.Count) folder(s), so their contents are unknown" }
    if ($trackedChanges.Count -gt 0) { $r += "dirty: $($trackedChanges.Count) uncommitted tracked change(s)" }
    # Untracked files are the one loss class with no recovery THROUGH GIT: not in the index, not in a
    # stash, not in the reflog. (--force also deletes IGNORED files -- .venv, a dev DB, a generated
    # corpus -- which git status never shows here; those are unrecoverable too, merely regenerable.)
    # `--force` suppresses git's own refusal on them, so this must not wave them through.
    if ($untracked.Count -gt 0) {
        $r += "$($untracked.Count) untracked file(s) present -- --force would delete them unrecoverably"
    }
    return @{ Clean = ($r.Count -eq 0); Reasons = $r }
}

# The refs of -Repo that contain the worktree's HEAD, for a DETACHED tree: once it is removed, its
# commits are reachable through nothing else, so an empty Holders list means removal strands them.
# Returns @{ Tip; Holders } or $null when either read fails -- unreadable is never "held".
function Get-TipHolders {
    param([string]$Path, [string]$Repo)
    $tip = (& git -C $Path rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $tip) { return $null }
    $tip = ([string]$tip).Trim()
    $holders = @(& git -C $Repo for-each-ref --contains $tip --format='%(refname)' 2>$null)
    if ($LASTEXITCODE -ne 0) { return $null }
    return @{ Tip = $tip; Holders = $holders }
}

# A `.claude/worktrees/` path segment: the population EnterWorktree relocates live sessions into, which
# prune-merged.ps1 never removes and only the opt-in nightly step may. A path SHAPE, so it holds whoever
# currently owns the tree and survives the containing worktree being deregistered.
function Test-ClaudeManagedPath([string]$Path) {
    return (($Path -replace '\\', '/') -match '(?i)/\.claude/worktrees/')
}

# Files flagged skip-worktree (`S`) or assume-unchanged (a lowercase tag) in `git ls-files -v`. git
# status does not show an edit to either, and neither does git's own check in `worktree remove`, so an
# edit there would go with the tree unseen. Returns the count, or -1 when it cannot be read.
function Get-FlaggedFileCount([string]$Path) {
    $lines = @(& git -C $Path ls-files -v 2>$null)
    if ($LASTEXITCODE -ne 0) { return -1 }
    return @($lines | Where-Object { $_ -cmatch '^([a-z]|S) ' }).Count
}

# The newest write to the WORKING TREE: the tree's own folder, each entry directly under it, and the
# files inside .pytest_cache and .ruff_cache (a test or lint run rewrites those in place, moving no
# top-level mtime), up to -CacheCap of them. The idle reading above sees only git metadata, so a session
# that edits files and runs no git command is invisible to it. Not every write moves one of these: a
# file edited in place two levels down moves none. $null when it cannot be read.
function Get-WorkingTreeActivity {
    param([string]$Path, [int]$CacheCap = 2000)
    try {
        $items = @(Get-Item -LiteralPath $Path -Force -ErrorAction Stop) + @(Get-ChildItem -LiteralPath $Path -Force -ErrorAction Stop)
        foreach ($cache in '.pytest_cache', '.ruff_cache') {
            $dir = Join-Path $Path $cache
            if (Test-Path -LiteralPath $dir -PathType Container) {
                $items += @(Get-ChildItem -LiteralPath $dir -Recurse -Force -File -ErrorAction Stop | Select-Object -First $CacheCap)
            }
        }
    }
    catch [System.Management.Automation.ItemNotFoundException], [System.IO.IOException], [System.UnauthorizedAccessException] {
        return $null
    }
    return ($items | Measure-Object -Property LastWriteTime -Maximum).Maximum
}

# Commits that only this worktree's own state holds: its HEAD reflog and its per-worktree refs
# (refs/worktree, refs/bisect, refs/rewritten). `git worktree remove` deletes both, so a commit no
# shared ref holds becomes unreachable. A commit the branch's OWN reflog holds (an amend, a reset, a
# rebase on that branch) survives the removal, because that reflog lives in the common dir, so it is not
# counted. Returns the count, or -1 when it cannot be read or there are more than -Cap candidates.
function Get-WorktreeOnlyCommitCount {
    param([string]$Path, [string]$Repo, [string]$Branch, [int]$Cap = 500)
    $reflog = @(& git -C $Path reflog show --format=%H HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) { return -1 }
    $own = @(& git -C $Path for-each-ref --format='%(objectname)' refs/worktree refs/bisect refs/rewritten 2>$null)
    if ($LASTEXITCODE -ne 0) { return -1 }
    $sha = { param($x) @($x | ForEach-Object { ([string]$_).Trim() } | Where-Object { $_ -match '^[0-9a-f]{40,64}$' } | Select-Object -Unique) }
    # @() around each, or one SHA unrolls to a bare string, and splatting a string hands git characters.
    $held = @(& $sha (@($reflog) + @($own)))
    if ($held.Count -eq 0) { return 0 }
    if ($held.Count -gt $Cap) { return -1 }
    # Fewer exclusions only make this stricter, so a branch reflog that cannot be read, or is longer
    # than the cap, is used as far as it goes.
    $kept = @()
    if ($Branch) { $kept = @(& $sha @(& git -C $Repo reflog show --format=%H "refs/heads/$Branch" 2>$null) | Select-Object -First $Cap) }
    $n = & git -C $Repo rev-list --count @held --not --branches --tags --remotes @kept 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $n) { return -1 }
    return [int]([string]$n).Trim()
}

# One claim or allocation record file, judged the way remove.ps1 judges it: ONE object per file with a
# non-blank string `worktree` is the only shape claim.ps1 and alloc.ps1 write, so anything else might
# hide a tree and is a Problem (cannot tell). Tombstone marks the ownerless record
# tombstone-retired-backlog-allocator.ps1 writes. A record another PC wrote still counts: the two PCs
# can share one path layout, so its path may name a tree here. Needs
# coord-root.ps1 (Read-CoordText) and occupancy.ps1 (ConvertTo-Norm) loaded by the caller.
function Read-CoordRecord([string]$File) {
    $out = @{ Record = $null; Holder = ''; Problem = ''; Tombstone = $false }
    # Deliberately broad: ANY failure to read is the cannot-tell verdict, recorded in Problem rather than
    # swallowed, and every caller refuses on it.
    try { $parsed = @(Read-CoordText $File | ConvertFrom-Json -EA Stop) }
    catch { $out.Problem = "unreadable: $($_.Exception.Message)"; return $out }
    if ($parsed.Count -ne 1 -or $parsed[0] -isnot [System.Management.Automation.PSCustomObject]) { $out.Problem = 'not one record'; return $out }
    $rec = $parsed[0]
    $out.Record = $rec
    if ($rec.tombstone -is [bool] -and $rec.tombstone -and [string]$rec.worktree -eq '' -and [string]$rec.branch -eq '') {
        $out.Tombstone = $true; $out.Problem = 'tombstone'; return $out
    }
    if ($rec.worktree -isnot [string] -or -not $rec.worktree.Trim()) { $out.Problem = 'no worktree string'; return $out }
    $out.Holder = ConvertTo-Norm $rec.worktree
    return $out
}

# Which worktrees hold a coordination claim, across every claims directory given. UNREADABLE IS NOT
# ABSENT: a claim file that will not parse or has the wrong shape might name any worktree, and so might
# a directory that exists and cannot be listed, so the caller must treat Unreadable as "every tree may
# be claimed". A directory that does not exist holds no claim.
function Get-ClaimedWorktreeIndex([string[]]$ClaimsDir) {
    $claimed = @{}
    $unreadable = $false
    foreach ($dir in @($ClaimsDir | Where-Object { $_ })) {
        if (-not (Test-Path -LiteralPath $dir)) { continue }
        try { $files = @(Get-ChildItem -LiteralPath $dir -Filter *.json -File -ErrorAction Stop) }
        catch [System.IO.IOException], [System.UnauthorizedAccessException] { $unreadable = $true; continue }
        foreach ($f in $files) {
            $r = Read-CoordRecord $f.FullName
            if ($r.Tombstone) { continue }
            if ($r.Problem) { $unreadable = $true; continue }
            $claimed[$r.Holder] = $true
        }
    }
    return @{ Claimed = $claimed; Unreadable = $unreadable }
}

# Git clones hidden inside IGNORED directories, where git status never looks and `git worktree remove`
# deletes without asking: pip's editable clones in .venv/src or venv/src, and packages in node_modules
# (one @scope level included). Their unpushed commits would go with the tree. Returns the count, or -1
# when a directory that exists cannot be listed. A clone deeper than that is not looked for.
function Get-IgnoredCloneCount([string]$Path) {
    $n = 0
    try {
        foreach ($base in '.venv/src', 'venv/src', 'node_modules') {
            $dir = Join-Path $Path $base
            if (-not (Test-Path -LiteralPath $dir -PathType Container)) { continue }
            foreach ($d in @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction Stop)) {
                if (Test-Path -LiteralPath (Join-Path $d.FullName '.git')) { $n++ }
                elseif ($base -eq 'node_modules' -and $d.Name.StartsWith('@')) {
                    foreach ($s in @(Get-ChildItem -LiteralPath $d.FullName -Directory -Force -ErrorAction Stop)) {
                        if (Test-Path -LiteralPath (Join-Path $s.FullName '.git')) { $n++ }
                    }
                }
            }
        }
    }
    catch [System.IO.IOException], [System.UnauthorizedAccessException] { return -1 }
    return $n
}
