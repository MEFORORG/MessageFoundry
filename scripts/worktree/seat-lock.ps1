# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Lock a seat's worktree on arrival and unlock it on a clean exit (BACKLOG #2524).

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own. seat.ps1 calls
    Set-SeatWorktreeLock on the SessionStart -Prompt path, which creates the lock, and on -Declare,
    which only relabels it (Set-SeatWorktreeLock's -Mode says why). NOT on every Stop
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
        the caller is told. The exceptions are SEAT locks only: one whose session reads DEAD or STALE
        is taken over by a seat arriving in that tree, and one is handed over to the new id on a
        SessionStart from /clear, /resume or /compact when no other live session is in the tree.
        Either way the new holder's exit clears it.
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

function Get-SeatLockSelfPids {
    # This hook's own process and its ancestors, one of which is the Claude process whose registry
    # record (<pid>.json) carries this session. The same walk as presence.ps1's Get-SelfPids, which
    # cannot be dot-sourced because that script runs on load. A failed read returns $PID alone, so
    # this session's own record then reads as a peer and the handover is refused: the safe side.
    $ppid = @{}
    try {
        Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -EA Stop |
            ForEach-Object { $ppid[[int]$_.ProcessId] = [int]$_.ParentProcessId }
    }
    catch { return @($PID) }
    $chain = @()
    $cur = $PID
    for ($i = 0; $i -lt 12 -and $cur -gt 0; $i++) {
        $chain += $cur
        $parent = $ppid[$cur]
        if (-not $parent -or $parent -le 0 -or $chain -contains $parent) { break }
        $cur = $parent
    }
    return $chain
}

function Get-SeatLockHandoverVeto {
    <#
    .SYNOPSIS
        '' when no OTHER live session occupies $Worktree, else why a handover must not happen.

    .DESCRIPTION
        The occupancy fence hygiene-report.ps1 reads (occupancy.ps1): a session is in the tree when
        its registry record's cwd places it there and its state is a veto state (LIVE, UNVERIFIED,
        UNREADABLE). This session is excluded by its new id, and by pid, since the old id's record is
        the same Claude process. An unavailable fence vetoes: a peer it cannot see is not ruled out.
    #>
    param([string]$Worktree, [string]$SessionKey, [string[]]$ConfigRoot)
    # occupancy.ps1 reads fields a record may lack. Under seat.ps1's StrictMode Latest that throws,
    # and the catch below would then veto every handover. Same reason as Get-SeatLockReading.
    Set-StrictMode -Off
    try {
        $occ =Get-WorktreeOccupancy -Repo $Worktree -ConfigRoot $ConfigRoot
        if (-not $occ.Available) { return "the liveness fence could not look ($($occ.Detail))" }
        $norm = ConvertTo-Norm $Worktree
        $root = ''
        foreach ($w in $occ.Worktrees) {
            $k = ConvertTo-Norm $w.Path
            if (($norm -eq $k -or $norm.StartsWith("$k/")) -and $k.Length -gt $root.Length) { $root = $k }
        }
        if (-not $root) { return "the liveness fence does not list $Worktree" }
        $self = @(Get-SeatLockSelfPids)
        $peers = @(Get-WorktreeOccupants -Occupancy $occ -Path $root |
                Where-Object { $_.SessionId -cne $SessionKey -and $self -notcontains $_.Pid })
        if ($peers.Count -gt 0) { return "another session is in this tree: $(($peers | ForEach-Object { "$($_.Short) $($_.State)" }) -join ', ')" }
        return ''
    }
    catch { return "the liveness fence failed: $($_.Exception.Message)" }
}

function Set-SeatWorktreeLock {
    <#
    .SYNOPSIS
        Lock $Worktree for this seat. Idempotent. Actions include at least locked, relabelled,
        handed-over, taken-over, kept-own, kept-foreign, not-locked, skipped-primary, skipped-cloud,
        skipped-no-session-id and failed.

    .DESCRIPTION
        -Mode says which caller this is:
          arrive    SessionStart from a startup. Creates the lock; takes over a DEAD or STALE seat's.
          handover  SessionStart from /clear, /resume or /compact. The process and its seat carry on
                    in this tree under a new id, and the old id's lock reads LIVE or NO RECORD, so
                    neither a takeover nor any exit would ever release it. So a seat lock here is
                    rewritten to this id, but only when Get-SeatLockHandoverVeto finds no OTHER live
                    session in the tree and the fence could look; otherwise it is kept. Another
                    holder's lock is always kept.
          relabel   -Declare. Rewrites only a lock this session already holds, and NEVER creates one:
                    the SessionStart that created it and the SessionEnd that releases it come from
                    the same settings file, while a -Declare can run where that file wires no
                    SessionEnd (a new-branch worktree under an older primary).
    #>
    param(
        [string]$Worktree, [string]$Seat, [string]$SessionKey, [string[]]$ConfigRoot,
        # Keep this session's existing lock as it reads, for a caller that does not know the seat.
        [switch]$KeepLabel,
        [ValidateSet('arrive', 'handover', 'relabel')][string]$Mode = 'arrive'
    )
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
        return [pscustomobject]@{ Action = 'skipped-cloud'; Detail = 'a cloud session has no Desktop worktree GC to fend off' }
    }
    # A lock this session's exit could not match, and no reader could place, is a permanent lock that
    # nothing reports. So a session with no session id (a hand run with none set) places none.
    if (-not (Test-SeatLockSessionKey $SessionKey)) {
        return [pscustomobject]@{ Action = 'skipped-no-session-id'; Detail = "'$SessionKey' is not a session id, so nothing could release or report this lock" }
    }
    $st = Get-WorktreeLockState $Worktree
    if ($st.Error) { return [pscustomobject]@{ Action = 'failed'; Detail = $st.Error } }
    if (-not $st.Linked) { return [pscustomobject]@{ Action = 'skipped-primary'; Detail = 'the primary checkout cannot be locked, and no GC removes it' } }
    $held = if ($st.Locked) { ConvertFrom-SeatLockReason $st.Reason } else { $null }
    # A handover keeps the seat the old id declared when this new id has declared none yet.
    if ($Mode -eq 'handover' -and $held -and ([string]::IsNullOrWhiteSpace($Seat) -or $Seat -eq 'undeclared')) { $Seat = $held.Seat }
    $reason = Format-SeatLockReason -Seat $Seat -SessionKey $SessionKey

    if ($Mode -eq 'relabel' -and -not ($held -and $held.SessionKey -ceq $SessionKey)) {
        if ($st.Locked) { return [pscustomobject]@{ Action = 'kept-foreign'; Detail = "locked by another holder: $($st.Reason)" } }
        return [pscustomobject]@{ Action = 'not-locked'; Detail = "no lock from this session's SessionStart to relabel, and a declaration never creates one" }
    }

    if ($st.Locked) {
        if ($st.Reason -ceq $reason) { return [pscustomobject]@{ Action = 'kept-own'; Detail = $reason } }
        $action = ''
        if ($held -and $held.SessionKey -ceq $SessionKey) {
            if ($KeepLabel) { return [pscustomobject]@{ Action = 'kept-own'; Detail = $st.Reason } }
            $action = 'relabelled'
        }
        elseif ($held -and $Mode -eq 'handover') {
            # Only this process's own old id may be handed over. In a shared tree the lock may be a
            # live peer's, and rewriting it would let this session's exit unlock the tree under it.
            $veto = Get-SeatLockHandoverVeto -Worktree $Worktree -SessionKey $SessionKey -ConfigRoot $ConfigRoot
            if ($veto) { return [pscustomobject]@{ Action = 'kept-foreign'; Detail = "not handed over, $($veto): $($st.Reason)" } }
            $action = 'handed-over'
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
        # By session, not by the whole reason: this session's own SessionStart and -Declare can race
        # with two different seat labels.
        $raced = ConvertFrom-SeatLockReason $again.Reason
        $a = if ($raced -and $raced.SessionKey -ceq $SessionKey) { 'kept-own' } else { 'kept-foreign' }
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
