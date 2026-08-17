# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Read the Claude Code session registry, and decide whether a session is actually alive.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own.

        . "$PSScriptRoot\session-registry.ps1"
        $l = Get-SessionLiveness -SessionId "1234abcd-..."
        if ($l.State -eq "LIVE") { ... }

    ONE COPY OF THE FENCE, ON PURPOSE. Both presence.ps1 (a roster) and sessions.ps1 (which MOVES a
    transcript, and must not do that under a running writer) need the same answer to "is this session
    alive". Two copies of a safety check drift, and the copy that drifts is the one nobody is testing.

    `<config-root>/sessions/<pid>.json` is the only registry containing EVERY surface -- the Desktop
    app's own session tooling enumerates just the sessions it spawned, so a VS Code session is absent
    from it entirely. Config roots are discovered dynamically because several logins can coexist
    (`~\.claude` plus any `~\.claude-account-N`) and a session is only visible to the login that owns it.

    WHY THIS IS NOT A PID CHECK. Pids get reused, and these records outlive their process. Claude Code
    ships a `procStart` field for exactly this fence, but it serialises as absent in practice and its
    guard returns true when it cannot tell -- i.e. it fails OPEN toward "still alive". So we read the
    process start time ourselves and require it to be consistent with the recorded session start: a
    process that started AFTER the session registered is a recycled pid, not that session.

    WHAT THE ANSWERS MEAN, AND WHAT THEY LICENSE:
      LIVE        pid resolves and its start time is consistent. Trustworthy.
      UNVERIFIED  pid resolves; the fence could not be evaluated. Treat as possibly-live.
      UNREADABLE  the record itself cannot be fenced (no pid, or one that is not a number). Treat as
                  possibly-live: a record being WRITTEN right now is exactly this shape, and a session
                  that just launched is the last thing that should read as absent.
      STALE       pid resolves but belongs to a different process. The session is gone.
      DEAD        no such pid.
      (Found=$false) no record at all -- it exited cleanly, or was never registered.

    ONLY THE POSITIVE ANSWER IS SAFE TO ACT ON. There is no heartbeat anywhere on this host and
    registry writes are event-driven, so nothing here can PROVE a session is gone -- only that it is
    present. A DEAD/STALE/not-found verdict must never by itself authorise a destructive action;
    combine it with an independent signal and let either one veto.

    THE RECORD CARRIES NO BRANCH, AND TWO ROSTERS DISAGREE ABOUT ONE. A session record holds exactly
    `cwd, entrypoint, kind, name, nameSource, peerProtocol, pid, procStart, sessionId, startedAt,
    version` -- there is no branch field and never has been. So any branch you see printed beside a
    session came from somewhere else, and the two sources answer DIFFERENT QUESTIONS while both being
    labelled "branch":

      presence.ps1 / occupancy.ps1   the WORKTREE's branch, read live from `git worktree list
                                     --porcelain` (occupancy.ps1, the `branch ` porcelain line). Current
                                     at the moment you asked. This is the one to trust for "what is that
                                     checkout on NOW".
      the session-list MCP tool      a SESSION attribute captured when the session registered. It does
                                     not track a later `git switch`, so it is the branch the session
                                     STARTED on.

    Measured 2026-08-06: for ONE checkout the two rosters reported two DIFFERENT branch names -- the
    live roster the branch that checkout had been switched onto, the session list the one it registered
    with. Neither was wrong; they were answering different questions. NEVER quote a branch from the
    session list as a checkout's current branch, and never treat a disagreement between the two as
    evidence that either roster is broken.

    RELATED TRAP IN THE SAME FAMILY: the session list also exposes an `isRunning` flag. It means "this
    session is currently EXECUTING A TURN", not "this session is alive" -- an idle session between turns
    reads false while being perfectly reachable. It is not a liveness fence and must not be used as one;
    that is what Get-SessionLiveness above is for, subject to the positive-answer-only rule.

    THIS IS THE SOURCE OF RECORD FOR THAT FIELD, so the measurement lives here rather than being
    restated in each consumer. Measured 2026-08-06 by sending and getting real replies, not inferred
    from the field: an `isRunning: false` peer was DELIVERED to and answered within one turn, while an
    `isRunning: true` peer returned "Message queued ... will be processed after the in-flight turn
    finishes". As a REACHABILITY test the field therefore reads BACKWARDS, and filtering on it drops
    exactly the peers most able to answer. announce-session.ps1 instructed every session to do that
    until BACKLOG #1077.

    AND IT IS NOT UNIFORM ACROSS SURFACES, which is why the safe reading is "not observable" rather
    than "idle": a VS Code session is never entered into the Desktop app's in-memory session map at
    all, so it is ABSENT rather than listed-and-quiet, and no value of `isRunning` describes it. The
    field reports what the Desktop app can observe, and reachability is decided by cwd, not by it.
#>

# Every config root that actually holds a session registry.
function Get-ClaudeConfigRoots {
    [CmdletBinding()]
    param([string[]]$ConfigRoot)
    if ($ConfigRoot) { return @($ConfigRoot | Where-Object { Test-Path $_ }) }
    return @(
        Get-ChildItem -Path $env:USERPROFILE -Directory -Filter ".claude*" -Force -EA SilentlyContinue |
            Where-Object { Test-Path (Join-Path $_.FullName "sessions") } |
            ForEach-Object { $_.FullName }
    )
}

# Every registry record, with the root it came from attached.
#
# -IncludeUnreadable also returns a row for every file that could NOT be parsed (Record = $null,
# Unreadable = $true). A caller about to destroy something needs those: a record that is half-written
# -- i.e. a session that launched a moment ago -- fails to parse, and DROPPING it silently turns an
# occupied worktree from SKIP into PRUNE while the receipt reports one fewer record than existed.
# It is off by default so the read-only roster callers keep the shape they already handle.
function Get-SessionRecords {
    [CmdletBinding()]
    param([string[]]$ConfigRoot, [switch]$IncludeUnreadable)
    $out = @()
    foreach ($root in (Get-ClaudeConfigRoots -ConfigRoot $ConfigRoot)) {
        foreach ($f in @(Get-ChildItem (Join-Path $root "sessions") -Filter *.json -EA SilentlyContinue)) {
            # A single malformed record must never take down a caller -- one of these runs in a
            # SessionStart hook, where a throw replaces the chat's whole starting context.
            $rec = $null
            $err = ''
            try { $rec = Get-Content $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { $err = $_.Exception.Message }
            if (-not $rec) {
                if (-not $err) { $err = 'the file parsed to nothing (empty, or being written right now)' }
                if ($IncludeUnreadable) {
                    $out += [pscustomobject]@{ Record = $null; Root = $root; File = $f.FullName; Unreadable = $true; Error = $err }
                }
                continue
            }
            $out += [pscustomobject]@{ Record = $rec; Root = $root; File = $f.FullName; Unreadable = $false; Error = '' }
        }
    }
    return $out
}

# The fence. See the header for why this is not just "is the pid alive".
function Test-RecordLiveness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][AllowNull()][object]$Record,
        # How far a process may have started BEFORE its session registered and still be the same run.
        # Generous: registration follows process start, but a cold start on a loaded box can lag.
        [int]$StartSkewMinutes = 15
    )
    if (-not $Record) { return @{ State = "UNREADABLE"; Detail = "no record to fence" } }
    # A record with NO pid cannot be fenced, so it is UNREADABLE, not DEAD. It used to report DEAD --
    # which is not a veto anywhere -- and a registry file caught mid-write has exactly this shape, so a
    # session that had just launched read as "nobody is there" to a caller about to delete its worktree.
    $procId = [int]$Record.pid
    if (-not $procId) { return @{ State = "UNREADABLE"; Detail = "no pid in record; it cannot be fenced" } }

    $proc = Get-Process -Id $procId -EA SilentlyContinue
    if (-not $proc) { return @{ State = "DEAD"; Detail = "pid $procId not running" } }

    $procStart = $null
    try { $procStart = $proc.StartTime } catch { }
    if (-not $procStart) {
        # Access can be denied for a process in another context. Report the uncertainty rather than
        # upgrading it to LIVE: an unverifiable fence is not a passed fence.
        return @{ State = "UNVERIFIED"; Detail = "pid $procId alive; start time unreadable" }
    }
    if ($null -eq $Record.startedAt) {
        return @{ State = "UNVERIFIED"; Detail = "pid $procId alive; record has no startedAt" }
    }

    $registered = [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$Record.startedAt).LocalDateTime
    # A process cannot have started after the session it hosts registered (small forward slop for
    # clock jitter). Started much later => this pid was recycled onto a different process.
    $delta = ($procStart - $registered).TotalMinutes
    if ($delta -gt 1) {
        return @{ State = "STALE"; Detail = "pid $procId reused (process started $([int]$delta)m after the session)" }
    }
    if ($delta -lt (-1 * $StartSkewMinutes)) {
        return @{ State = "STALE"; Detail = "pid $procId start precedes the session by $([int](-$delta))m" }
    }
    return @{ State = "LIVE"; Detail = "" }
}

# Look one session up by id (full or unique prefix) and fence it.
function Get-SessionLiveness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [string[]]$ConfigRoot,
        [int]$StartSkewMinutes = 15
    )
    $hit = @(Get-SessionRecords -ConfigRoot $ConfigRoot |
        Where-Object { $_.Record.sessionId -and ([string]$_.Record.sessionId).StartsWith($SessionId, 'OrdinalIgnoreCase') })

    if ($hit.Count -eq 0) {
        # Not registered. NOT proof it is gone -- a session that never registered looks identical to
        # one that exited cleanly, so callers must fall back to an independent signal.
        return @{ Found = $false; State = "UNKNOWN"; Detail = "no registry record"; Record = $null }
    }
    # More than one match on a prefix: fence them all and report the most-alive, because the caller is
    # about to decide whether it is safe to disturb something.
    # UNREADABLE ranks with the possibly-live states, not with the gone ones: it means the fence could
    # not be evaluated, and an unevaluated fence is not a passed fence.
    $rank = @{ "LIVE" = 0; "UNVERIFIED" = 1; "UNREADABLE" = 2; "STALE" = 3; "DEAD" = 4 }
    $best = $null
    foreach ($h in $hit) {
        $l = Test-RecordLiveness -Record $h.Record -StartSkewMinutes $StartSkewMinutes
        if (-not $best -or $rank[$l.State] -lt $rank[$best.State]) {
            $best = @{ Found = $true; State = $l.State; Detail = $l.Detail; Record = $h.Record }
        }
    }
    return $best
}
