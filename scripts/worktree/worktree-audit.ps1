# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Read-only worktree checks shared by hygiene-report.ps1 and the seat-lock writer: the seat-lock
    reason format, and which seat locks name a session that is gone.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own. It RUNS NO GIT VERB AT ALL and
    deletes nothing, because hygiene-report.ps1 dot-sources it and tests/test_worktree_hygiene_report.py
    holds everything that report dot-sources to the report's read-only rule. The writes that place and
    remove a seat lock live in seat-lock.ps1, which the report never loads.

    WHY SEAT WORKTREES ARE LOCKED (BACKLOG #2524). A Claude Desktop instance's worktree GC
    (`[reapUntrackedWorktreeDir]`) runs `git worktree remove --force` on another instance's worktree
    that looks quiet and clean. On Windows a folder that a live session holds open is then EMPTIED and
    deregistered, with the session still in it. That GC keeps any worktree whose admin directory holds
    a `locked` file, and so do prune-merged.ps1, claim-reconcile.ps1 and this repository's other
    reclaimers. So a seat locks its worktree on arrival and unlocks it on a clean exit. A session that
    dies without unlocking leaves a tree nothing reclaims, which is what Get-StaleSeatLocks reports.

    THE REASON FORMAT IS `<seat> <session id>`, two tokens and nothing else. It is what the row named,
    and it is told apart from other holders' locks by its SHAPE: Claude Code's own lock on an
    `isolation: worktree` agent reads `claude agent <name> (pid <n>)`, and a hand-written lock is
    usually prose. The session token must be a session id as seat.ps1 keys it (a UUID, optionally
    `codex-` prefixed) or the literal `nosid`, so a two-word hand lock such as `manual hold` is never
    read as a seat lock and offered for unlocking.
#>

# A session id as seat.ps1's Get-SessionKey keys it: a UUID, `codex-` prefixed for a Codex seat, or
# the literal it falls back to when no id is known.
$script:SeatLockSessionPattern = '(?:codex-)?[0-9A-Fa-f]{8}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{4}-[0-9A-Fa-f]{12}|nosid'

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
    $k = ConvertTo-SeatLockToken $SessionKey
    if (-not $k) { $k = 'nosid' }
    return "$s $k"
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
        it was. LIVE, UNVERIFIED and UNREADABLE are never gone. `nosid` names no session, and a Codex
        session is not in Claude's registry, so neither can be fenced and neither reads gone. The
        caller must have dot-sourced session-registry.ps1.
    #>
    param([string]$SessionKey, [string[]]$ConfigRoot)
    if ($SessionKey -eq 'nosid') {
        return [pscustomobject]@{ State = 'NO SESSION ID'; Detail = 'the lock names no session, so nothing can say whether its seat is alive'; Gone = $false }
    }
    if ($SessionKey.StartsWith('codex-')) {
        return [pscustomobject]@{ State = 'CODEX'; Detail = "Claude's session registry cannot fence a Codex seat"; Gone = $false }
    }
    try { $l = Get-SessionLiveness -SessionId $SessionKey -ConfigRoot $ConfigRoot }
    catch { return [pscustomobject]@{ State = 'UNREADABLE'; Detail = "the liveness lookup failed: $($_.Exception.Message)"; Gone = $false } }
    if ((-not $l.Found) -and $l.State -eq 'UNKNOWN') {
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
        to the GC. A `nosid` lock is listed too, because nothing will ever release it on its own; a
        Codex lock is not, because nothing here can tell that it is gone.
    #>
    param([object[]]$Worktrees, [string[]]$ConfigRoot)
    $out = [System.Collections.Generic.List[object]]::new()
    foreach ($w in @($Worktrees | Where-Object { $_ -and $_.Locked })) {
        $p = ConvertFrom-SeatLockReason $w.LockReason
        if (-not $p) { continue }
        $r = Get-SeatLockReading -SessionKey $p.SessionKey -ConfigRoot $ConfigRoot
        if (-not ($r.Gone -or $r.State -eq 'NO SESSION ID')) { continue }
        $out.Add([pscustomobject]@{ Path = $w.Path; Reason = $w.LockReason; Seat = $p.Seat; SessionKey = $p.SessionKey; State = $r.State; Detail = $r.Detail })
    }
    return @($out)
}
