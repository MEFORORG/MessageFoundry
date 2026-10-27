# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Lock a seat's worktree on arrival and unlock it on a clean exit (BACKLOG #2524).

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own. seat.ps1 calls
    Set-SeatWorktreeLock on the SessionStart -Prompt path and on -Declare. NOT on every Stop
    (-Record): that path runs the PRIMARY's seat.ps1 through the user-scope shim, so it would lock
    trees whose own branch predates the unlock hook and never unlock them, and it follows a `cd` into
    a sibling. Only the SessionEnd hook scripts/hooks/seat-unlock.ps1 calls
    Remove-SeatWorktreeLock: a seat that ran -Close is often still open, and an early unlock re-opens
    it to the GC.
    Why a lock at all, and the reason format, are in worktree-audit.ps1's header.

    NEITHER FUNCTION THROWS. Each returns an Action and a Detail, because both run inside hooks that
    must never fail a turn.

    WHAT EACH WILL NOT DO, and why:
      * Lock or unlock the PRIMARY checkout. Git refuses `worktree lock` on the main working tree, and
        no GC removes it anyway.
      * Lock for a session with no session id. Its lock could never be matched at exit or placed by
        a reader, so it would be permanent and unreported.
      * Run in a Claude Code cloud session. The VM's clone has no Desktop GC to fend off, and the
        refusal elsewhere in this repository is that such a session writes nothing for others.
      * Replace another holder's lock. Claude Code locks an `isolation: worktree` agent's tree while it
        is live (docs/SESSION-DRIFT-CONTROLS.md), and a person may lock one by hand. Those are kept, and
        the caller is told. The one exception is a SEAT lock whose session reads DEAD or STALE: a
        seat arriving in that tree takes it over, so its own exit can clear it.
        The takeover rewrites the `locked` file in place rather than unlocking and re-locking, so
        there is no moment in which the tree is unlocked.
      * Remove a lock this session did not place. Unlock removes only a seat lock naming this session
        id. A lock with any other reason, or another session's, stays.
#>

. "$PSScriptRoot\worktree-audit.ps1"
# ConvertTo-Norm, and the liveness fence Get-SeatLockReading reads. Both define functions only.
. "$PSScriptRoot\..\coord\occupancy.ps1"

function Get-WorktreeLockState {
    <#
    .SYNOPSIS
        Whether $Worktree is a linked worktree, where its admin directory is, and its lock.
        Linked is $false for the primary checkout and for a path git cannot read.
    #>
    param([string]$Worktree)
    $out = [pscustomobject]@{ Linked = $false; AdminDir = ''; Locked = $false; Reason = ''; Error = '' }
    try {
        # One call, two lines: the git dir, then the common dir. Equal means the primary checkout.
        $dirs = @(& git -C $Worktree rev-parse --path-format=absolute --git-dir --git-common-dir 2>$null)
        if ($LASTEXITCODE -ne 0 -or $dirs.Count -lt 2) { $out.Error = "git cannot read $Worktree"; return $out }
        $g = ([string]$dirs[0]).Trim()
        if ((ConvertTo-Norm $g) -eq (ConvertTo-Norm ([string]$dirs[1]).Trim())) { return $out }
        $out.Linked = $true
        $out.AdminDir = $g
        $f = Join-Path $g 'locked'
        if (Test-Path -LiteralPath $f -PathType Leaf) {
            $out.Locked = $true
            $out.Reason = ([string](Get-Content -LiteralPath $f -Raw -ErrorAction SilentlyContinue)).Trim()
        }
    }
    catch { $out.Error = $_.Exception.Message }
    return $out
}

function Set-SeatWorktreeLock {
    <#
    .SYNOPSIS
        Lock $Worktree for this seat. Idempotent. Actions include at least locked, relabelled,
        taken-over, kept-own, kept-foreign, skipped-primary, skipped-cloud, skipped-no-session-id and
        failed.
    #>
    param(
        [string]$Worktree, [string]$Seat, [string]$SessionKey, [string[]]$ConfigRoot,
        # Keep this session's existing lock as it reads, for a caller that does not know the seat.
        [switch]$KeepLabel
    )
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
        return [pscustomobject]@{ Action = 'skipped-cloud'; Detail = 'a cloud session has no Desktop worktree GC to fend off' }
    }
    # A lock this session's exit could not match, and no reader could place, is a permanent lock that
    # nothing reports. So a session with no session id (a hand run with none set) places none.
    if (-not (Test-SeatLockSessionKey $SessionKey)) {
        return [pscustomobject]@{ Action = 'skipped-no-session-id'; Detail = "'$SessionKey' is not a session id, so nothing could release or report this lock" }
    }
    $reason = Format-SeatLockReason -Seat $Seat -SessionKey $SessionKey
    $st = Get-WorktreeLockState $Worktree
    if ($st.Error) { return [pscustomobject]@{ Action = 'failed'; Detail = $st.Error } }
    if (-not $st.Linked) { return [pscustomobject]@{ Action = 'skipped-primary'; Detail = 'the primary checkout cannot be locked, and no GC removes it' } }

    if ($st.Locked) {
        if ($st.Reason -ceq $reason) { return [pscustomobject]@{ Action = 'kept-own'; Detail = $reason } }
        $held = ConvertFrom-SeatLockReason $st.Reason
        $action = ''
        if ($held -and $held.SessionKey -ceq $SessionKey) {
            if ($KeepLabel) { return [pscustomobject]@{ Action = 'kept-own'; Detail = $st.Reason } }
            $action = 'relabelled'
        }
        elseif ($held -and (Get-SeatLockReading -SessionKey $held.SessionKey -ConfigRoot $ConfigRoot).State -in @('DEAD', 'STALE')) {
            # A positive dead signal only. NO RECORD is gone enough to REPORT, but a live seat this
            # reader cannot see (a config root outside USERPROFILE) also reads that way, and taking
            # its lock would let the newcomer's exit unlock the tree under it.
            $action = 'taken-over'
        }
        if (-not $action) {
            return [pscustomobject]@{ Action = 'kept-foreign'; Detail = "already locked by another holder: $($st.Reason)" }
        }
        # In place, so the tree is never unlocked in between. Git writes the reason and a newline.
        $f = Join-Path $st.AdminDir 'locked'
        $tmp = "$f.$([guid]::NewGuid().ToString('n')).tmp"
        try {
            [System.IO.File]::WriteAllText($tmp, "$reason`n", [System.Text.UTF8Encoding]::new($false))
            [System.IO.File]::Move($tmp, $f, $true)
            return [pscustomobject]@{ Action = $action; Detail = "$reason (was: $($st.Reason))" }
        }
        catch {
            # No residue in git's admin directory.
            try { [System.IO.File]::Delete($tmp) } catch { }
            return [pscustomobject]@{ Action = 'failed'; Detail = "could not rewrite the lock: $($_.Exception.Message)" }
        }
    }

    $msg = & git -C $Worktree worktree lock --reason $reason $Worktree 2>&1
    $code = $LASTEXITCODE
    if ($code -eq 0) { return [pscustomobject]@{ Action = 'locked'; Detail = $reason } }
    # Another writer may have locked it between the read and the call. Read again before calling it a
    # failure, so a race reads as the lock it produced.
    $again = Get-WorktreeLockState $Worktree
    if ($again.Locked) {
        $a = if ($again.Reason -ceq $reason) { 'kept-own' } else { 'kept-foreign' }
        return [pscustomobject]@{ Action = $a; Detail = $again.Reason }
    }
    return [pscustomobject]@{ Action = 'failed'; Detail = "git worktree lock exited $($code): $(($msg | Out-String).Trim())" }
}

function Remove-SeatWorktreeLock {
    <#
    .SYNOPSIS
        Unlock $Worktree only if this session's seat lock holds it. Actions include at least unlocked, not-locked,
        kept-foreign, skipped-primary, skipped-cloud, failed.
    #>
    param([string]$Worktree, [string]$SessionKey)
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
        return [pscustomobject]@{ Action = 'skipped-cloud'; Detail = 'a cloud session places no lock' }
    }
    $st = Get-WorktreeLockState $Worktree
    if ($st.Error) { return [pscustomobject]@{ Action = 'failed'; Detail = $st.Error } }
    if (-not $st.Linked) { return [pscustomobject]@{ Action = 'skipped-primary'; Detail = 'the primary checkout carries no seat lock' } }
    if (-not $st.Locked) { return [pscustomobject]@{ Action = 'not-locked'; Detail = '' } }
    $held = ConvertFrom-SeatLockReason $st.Reason
    if (-not $held -or -not (Test-SeatLockSessionKey $SessionKey) -or $held.SessionKey -cne $SessionKey) {
        return [pscustomobject]@{ Action = 'kept-foreign'; Detail = "locked by another holder: $($st.Reason)" }
    }
    $msg = & git -C $Worktree worktree unlock $Worktree 2>&1
    if ($LASTEXITCODE -eq 0) { return [pscustomobject]@{ Action = 'unlocked'; Detail = $st.Reason } }
    return [pscustomobject]@{ Action = 'failed'; Detail = "git worktree unlock exited $($LASTEXITCODE): $(($msg | Out-String).Trim())" }
}
