# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Read-only worktree checks shared by hygiene-report.ps1 and the seat-lock writer: the seat-lock
    reason format, which seat locks name a session that is gone, and which worktree folders were
    emptied in place, with the Desktop log lines that emptied them.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own. It RUNS NO GIT VERB AT ALL and
    deletes nothing, because hygiene-report.ps1 dot-sources it and tests/test_worktree_hygiene_report.py
    holds everything that report dot-sources to the report's read-only rule. The writes that place and
    remove a seat lock live in seat-lock.ps1, which the report never loads.

    WHY SEAT WORKTREES ARE LOCKED (BACKLOG #2524). A Claude Desktop instance's worktree GC
    (`[reapUntrackedWorktreeDir]`) runs `git worktree remove --force` on another instance's worktree
    that looks quiet and clean. On Windows a folder that a live session holds open is then EMPTIED and
    deregistered, with the session still in it. What the evidence shows (the vault's
    docs/reviews/2026-09-30-b184-1917-worktree-emptying.md) is that the GC's reap path logged
    `(locked)` and kept a locked folder. Its manual-cleanup fallback is NOT shown to respect a lock,
    so the lock narrows the exposure and does not close it. prune-merged.ps1 and claim-reconcile.ps1
    keep a locked tree too. So a seat locks its worktree on arrival and unlocks it on a clean exit. A session that
    dies without unlocking leaves a tree nothing reclaims, which is what Get-StaleSeatLocks reports.

    THE REASON FORMAT IS `<seat> <session id>`, two tokens and nothing else. It is what the row named,
    and it is told apart from other holders' locks by its SHAPE: Claude Code's own lock on an
    `isolation: worktree` agent reads `claude agent <name> (pid <n>)`, and a hand-written lock is
    usually prose. The session token must be a session id as seat.ps1 keys it (a UUID, optionally
    `codex-` prefixed), so a two-word hand lock such as `manual hold` is never read as a seat lock and
    offered for unlocking. A session with no such id is never locked (seat-lock.ps1), because nothing
    could ever tell its lock apart from another's, release it, or report it.
#>

# A session id as seat.ps1's Get-SessionKey keys it: a UUID, `codex-` prefixed for a Codex seat.
$script:SeatLockSessionPattern = '(?:codex-)?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}'

function Test-SeatLockSessionKey([string]$SessionKey) {
    return ([string]$SessionKey) -match "\A(?:$script:SeatLockSessionPattern)\z"
}

function ConvertTo-SeatLockToken([string]$Text) {
    # One token, so the reason stays two. A seat label is one word in the roster; anything else is
    # flattened rather than refused, because a lock with an odd label still protects the tree.
    $t = ([string]$Text).Trim() -replace '[^A-Za-z0-9._-]', '-'
    return $t
}

function Format-SeatLockReason {
    param([string]$Seat, [string]$SessionKey)
    $s = ConvertTo-SeatLockToken $Seat
    if (-not $s) { $s = 'undeclared' }
    return "$s $(ConvertTo-SeatLockToken $SessionKey)"
}

function ConvertFrom-SeatLockReason {
    # The seat and session a lock reason names, or $null when the reason is not a seat lock.
    param([AllowEmptyString()][string]$Reason)
    $r = ([string]$Reason).Trim()
    if ($r -notmatch "\A(?<seat>[A-Za-z0-9._-]+) (?<sid>$script:SeatLockSessionPattern)\z") { return $null }
    return [pscustomobject]@{ Seat = $Matches['seat']; SessionKey = $Matches['sid'] }
}

function ConvertTo-SeatSessionKey([string]$SessionId) {
    # The key seat.ps1's Get-SessionKey files a session under, and so the token its lock reason
    # carries: `codex-` prefixed for a Codex seat, cleaned, cut at 80. Kept equal to that function.
    if (-not $SessionId) { return 'nosid' }
    $sid = if ($env:KORUS_AGENT -eq 'codex') { "codex-$SessionId" } else { $SessionId }
    $k = $sid -replace '[^A-Za-z0-9._-]', '-'
    if ($k.Length -gt 80) { $k = $k.Substring(0, 80) }
    return $k
}

function Get-SeatLockReading {
    <#
    .SYNOPSIS
        The ONE rule for whether a seat lock's session is gone: State, Detail and Gone.

    .DESCRIPTION
        Gone is DEAD, STALE, or no registry record. A session that exits cleanly drops its record, so a
        miss cannot tell an exited session from one that never registered; Detail says which reading
        it was. LIVE, UNVERIFIED and UNREADABLE are never gone. A Codex session is not in Claude's
        registry, so it cannot be fenced and never reads gone. The caller must have dot-sourced
        session-registry.ps1.

        A MISS IS GONE ONLY WHEN EVERY REGISTRY FILE PARSED. A file caught mid-write parses to nothing
        and the lookup skips it, and that file may be the very session asked about; seat.ps1's
        -ClearHandoff refuses on the same ground. -Unreadable takes that count from a caller that
        already read the registry, so a report over many locks reads it once.
    #>
    param([string]$SessionKey, [string[]]$ConfigRoot, [Nullable[int]]$Unreadable)
    # session-registry.ps1 reads `.sessionId`, `.pid` and `.startedAt` off records that may lack them.
    # Under a caller's StrictMode (seat.ps1 runs Latest) a missing one throws instead of reading null.
    Set-StrictMode -Off
    if ($SessionKey.StartsWith('codex-')) {
        return [pscustomobject]@{ State = 'CODEX'; Detail = "Claude's session registry cannot fence a Codex seat"; Gone = $false }
    }
    try { $l = Get-SessionLiveness -SessionId $SessionKey -ConfigRoot $ConfigRoot }
    catch { return [pscustomobject]@{ State = 'UNREADABLE'; Detail = "the liveness lookup failed: $($_.Exception.Message)"; Gone = $false } }
    if ((-not $l.Found) -and $l.State -eq 'UNKNOWN') {
        if ($null -eq $Unreadable) {
            try { $Unreadable = @(Get-SessionRecords -ConfigRoot $ConfigRoot -IncludeUnreadable | Where-Object { $_.Unreadable }).Count }
            catch { $Unreadable = 1 }
        }
        if ($Unreadable -gt 0) {
            return [pscustomobject]@{ State = 'UNREADABLE'; Detail = "no registry record, but $Unreadable registry file(s) could not be read, and one may be this session's"; Gone = $false }
        }
        return [pscustomobject]@{ State = 'NO RECORD'; Detail = 'no registry record: the session exited, or never registered'; Gone = $true }
    }
    return [pscustomobject]@{ State = $l.State; Detail = $l.Detail; Gone = ($l.State -in @('DEAD', 'STALE')) }
}

function Get-StaleSeatLocks {
    <#
    .SYNOPSIS
        Every seat lock among $Worktrees whose session is gone, with the fence's reading.

    .DESCRIPTION
        $Worktrees are rows as occupancy.ps1's Get-RepoWorktrees returns them (Path, Locked,
        LockReason). The caller must have dot-sourced session-registry.ps1.

        Gone is Get-SeatLockReading's rule. A LIVE, UNVERIFIED or UNREADABLE session is never listed:
        this feeds a report that proposes an unlock, and an unlock under a live seat re-opens the tree
        to the GC. A Codex lock is listed as CODEX: nothing here can tell whether it is gone, and
        nothing else would ever report one a crashed Codex seat left.
    #>
    param([object[]]$Worktrees, [string[]]$ConfigRoot)
    $out = [System.Collections.Generic.List[object]]::new()
    $seatLocks = @(foreach ($w in @($Worktrees | Where-Object { $_ -and $_.Locked })) {
            $p = ConvertFrom-SeatLockReason $w.LockReason
            if ($p) { [pscustomobject]@{ W = $w; P = $p } }
        })
    if ($seatLocks.Count -eq 0) { return @() }
    $unreadable = 1
    try { $unreadable = @(Get-SessionRecords -ConfigRoot $ConfigRoot -IncludeUnreadable | Where-Object { $_.Unreadable }).Count } catch { }
    foreach ($x in $seatLocks) {
        $w = $x.W; $p = $x.P
        $r = Get-SeatLockReading -SessionKey $p.SessionKey -ConfigRoot $ConfigRoot -Unreadable $unreadable
        if (-not ($r.Gone -or $r.State -eq 'CODEX')) { continue }
        $out.Add([pscustomobject]@{ Path = $w.Path; Reason = $w.LockReason; Seat = $p.Seat; SessionKey = $p.SessionKey; State = $r.State; Detail = $r.Detail })
    }
    return @($out)
}

# ---------------------------------------------------------------------------------------------
# Worktrees emptied in place (BACKLOG #2525).
# ---------------------------------------------------------------------------------------------
#
# The GC's `git worktree remove --force` on a folder a live session holds open fails on Windows with
# `Permission denied` AFTER it has deleted the files, the `.git` link and the registration. What is
# left is a folder under `.claude\worktrees\` that has no `.git` and that `git worktree list` does not
# carry. The app logs that as a refusal, in one of the two lines below, so the log line that emptied
# a folder can be named beside it. The evidence is the vault's
# docs/reviews/2026-09-30-b184-1917-worktree-emptying.md.

# Each failure line: a marker, and a second substring the same line must carry.
$script:EmptiedLogMarkers = @(
    @{ Marker = 'reapUntrackedWorktreeDir] git worktree remove refused'; Also = 'failed to delete' }
    @{ Marker = 'Git worktree remove failed, will try manual cleanup'; Also = 'Permission denied' }
)

function Get-DesktopLogFiles {
    <#
    .SYNOPSIS
        Every Claude Desktop log file: each profile's `%USERPROFILE%\.claude-desktop*\logs`, and the
        default profile's `%LOCALAPPDATA%\Claude\Logs` and older `%APPDATA%\Claude\logs`. -LogRoot
        replaces that list, for a test or another layout.
    #>
    param([string[]]$LogRoot)
    $roots = if ($LogRoot) { @($LogRoot) } else {
        @(Get-ChildItem -LiteralPath $env:USERPROFILE -Directory -Filter '.claude-desktop*' -Force -ErrorAction SilentlyContinue |
                ForEach-Object { Join-Path $_.FullName 'logs' })
        if ($env:LOCALAPPDATA) { Join-Path $env:LOCALAPPDATA 'Claude\Logs' }
        if ($env:APPDATA) { Join-Path $env:APPDATA 'Claude\logs' }
    }
    return @(foreach ($r in $roots) {
            if ($r -and (Test-Path -LiteralPath $r -PathType Container)) {
                Get-ChildItem -LiteralPath $r -File -Filter '*.log' -ErrorAction SilentlyContinue
            }
        })
}

function Find-EmptiedWorktrees {
    <#
    .SYNOPSIS
        Each folder under <PrimaryPath>\.claude\worktrees\ that has no `.git` and is not a registered
        worktree, with the Desktop log lines that name it. Reads only; runs no git.

    .DESCRIPTION
        $Worktrees are rows as occupancy.ps1's Get-RepoWorktrees returns them; the caller has
        dot-sourced occupancy.ps1. The logs are read only when there is a folder to explain, so a
        clean tree costs one directory listing.

        A folder with no log line is still reported. The logs rotate, and a folder can be left empty
        some other way; the absence of a line is not evidence the GC did not do it.
    #>
    param([string]$PrimaryPath, [object[]]$Worktrees, [string[]]$LogRoot)
    $dir = Join-Path $PrimaryPath '.claude\worktrees'
    if (-not (Test-Path -LiteralPath $dir -PathType Container)) { return @() }
    $registered = @{}
    foreach ($w in @($Worktrees)) { if ($w) { $registered[(ConvertTo-Norm $w.Path)] = $true } }
    # `.ccd-trash~*` is the Desktop's own tombstone for a tree it is deleting in the background; the
    # Desktop's predicate skips those names too.
    $emptied = @(Get-ChildItem -LiteralPath $dir -Directory -Force -ErrorAction SilentlyContinue | Where-Object {
            -not $_.Name.StartsWith('.ccd-trash~') -and
            -not (Test-Path -LiteralPath (Join-Path $_.FullName '.git')) -and -not $registered.ContainsKey((ConvertTo-Norm $_.FullName))
        })
    if ($emptied.Count -eq 0) { return @() }

    $hits = @()
    $files = @(Get-DesktopLogFiles -LogRoot $LogRoot)
    if ($files.Count -gt 0) {
        $markers = @($script:EmptiedLogMarkers | ForEach-Object { $_.Marker })
        $hits = @(Select-String -LiteralPath $files.FullName -SimpleMatch -Pattern $markers -ErrorAction SilentlyContinue |
                Where-Object { $l = $_.Line; @($script:EmptiedLogMarkers | Where-Object { $l.Contains($_.Marker) -and $l.Contains($_.Also) }).Count -gt 0 })
    }
    return @(foreach ($e in $emptied) {
            # The log spells a path with either slash. A name must end at the match, so `seat-a` does
            # not claim the line about `seat-ab`.
            $pat = [regex]::Escape((ConvertTo-Norm $e.FullName)) + '(?![A-Za-z0-9._-])'
            # A run of backslashes is one separator, so a JSON-escaped `D:\\Code\\x` matches too.
            $lines = @($hits | Where-Object { ($_.Line -replace '\\+', '/').ToLowerInvariant() -match $pat } | ForEach-Object {
                    [pscustomobject]@{ File = $_.Path; LineNumber = $_.LineNumber; Text = $_.Line.Trim() }
                })
            [pscustomobject]@{
                Path     = $e.FullName
                Entries  = @(Get-ChildItem -LiteralPath $e.FullName -Force -ErrorAction SilentlyContinue).Count
                LogLines = $lines
            }
        })
}
