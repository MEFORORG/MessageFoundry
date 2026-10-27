# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Lock a seat's worktree on arrival and unlock it on a clean exit (BACKLOG #2524).

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own. seat.ps1 calls
    Set-SeatWorktreeLock on -Declare and on the SessionStart -Prompt path, and Remove-SeatWorktreeLock
    on -Close. The SessionEnd hook scripts/hooks/seat-unlock.ps1 calls Remove-SeatWorktreeLock too.
    Why a lock at all, and the reason format, are in worktree-audit.ps1's header.

    NEITHER FUNCTION THROWS. Each returns an Action and a Detail, because both run inside hooks that
    must never fail a turn.

    WHAT EACH WILL NOT DO, and why:
      * Lock or unlock the PRIMARY checkout. Git refuses `worktree lock` on the main working tree, and
        no GC removes it anyway.
      * Run in a Claude Code cloud session. The VM's clone has no Desktop GC to fend off, and the
        refusal elsewhere in this repository is that such a session writes nothing for others.
      * Replace another holder's lock. Claude Code locks an `isolation: worktree` agent's tree while it
        is live (docs/SESSION-DRIFT-CONTROLS.md), and a person may lock one by hand. Those are kept, and
        the caller is told. The one exception is a SEAT lock whose session reads DEAD or STALE, or has
        no registry record: a seat arriving in that tree takes it over, so its own exit can clear it.
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
        Lock $Worktree for this seat. Idempotent. Actions: locked, relabelled, taken-over, kept-own,
        kept-foreign, skipped-primary, skipped-cloud, failed.
    #>
    param([string]$Worktree, [string]$Seat, [string]$SessionKey, [string[]]$ConfigRoot)
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
        return [pscustomobject]@{ Action = 'skipped-cloud'; Detail = 'a cloud session has no Desktop worktree GC to fend off' }
    }
    $reason = Format-SeatLockReason -Seat $Seat -SessionKey $SessionKey
    $mineKey = $reason.Split(' ')[1]
    $st = Get-WorktreeLockState $Worktree
    if ($st.Error) { return [pscustomobject]@{ Action = 'failed'; Detail = $st.Error } }
    if (-not $st.Linked) { return [pscustomobject]@{ Action = 'skipped-primary'; Detail = 'the primary checkout cannot be locked, and no GC removes it' } }

    if ($st.Locked) {
        if ($st.Reason -ceq $reason) { return [pscustomobject]@{ Action = 'kept-own'; Detail = $reason } }
        $held = ConvertFrom-SeatLockReason $st.Reason
        $action = ''
        # `nosid` is no identity, so two sessions without one never relabel each other's lock.
        if ($held -and $mineKey -ne 'nosid' -and $held.SessionKey -ceq $mineKey) { $action = 'relabelled' }
        elseif ($held -and (Get-SeatLockReading -SessionKey $held.SessionKey -ConfigRoot $ConfigRoot).Gone) { $action = 'taken-over' }
        if (-not $action) {
            return [pscustomobject]@{ Action = 'kept-foreign'; Detail = "already locked by another holder: $($st.Reason)" }
        }
        try {
            # In place, so the tree is never unlocked in between. Git writes the reason and a newline.
            $f = Join-Path $st.AdminDir 'locked'
            $tmp = "$f.$([guid]::NewGuid().ToString('n')).tmp"
            [System.IO.File]::WriteAllText($tmp, "$reason`n", [System.Text.UTF8Encoding]::new($false))
            [System.IO.File]::Move($tmp, $f, $true)
            return [pscustomobject]@{ Action = $action; Detail = "$reason (was: $($st.Reason))" }
        }
        catch { return [pscustomobject]@{ Action = 'failed'; Detail = "could not rewrite the lock: $($_.Exception.Message)" } }
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
        Unlock $Worktree only if this session's seat lock holds it. Actions: unlocked, not-locked,
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
    $key = ConvertTo-SeatLockToken $SessionKey
    # `nosid` is no identity: two sessions with no id would each own the other's lock.
    if (-not $held -or -not $key -or $key -eq 'nosid' -or $held.SessionKey -cne $key) {
        return [pscustomobject]@{ Action = 'kept-foreign'; Detail = "locked by another holder: $($st.Reason)" }
    }
    $msg = & git -C $Worktree worktree unlock $Worktree 2>&1
    if ($LASTEXITCODE -eq 0) { return [pscustomobject]@{ Action = 'unlocked'; Detail = $st.Reason } }
    return [pscustomobject]@{ Action = 'failed'; Detail = "git worktree unlock exited $($LASTEXITCODE): $(($msg | Out-String).Trim())" }
}
