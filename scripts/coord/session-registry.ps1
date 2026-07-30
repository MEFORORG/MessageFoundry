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
#>

# ONE path normaliser, at the bottom of the stack ON PURPOSE. The cwd matcher (occupancy.ps1) and the
# write-footprint scanner (footprint.ps1) must decide "is this path inside that worktree" identically:
# two copies of a safety comparison drift, and the copy that drifts is the one nobody is testing. It
# lives here because it is the only file both of them already depend on.
function ConvertTo-Norm([string]$p) {
    if (-not $p) { return "" }
    return ($p -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

# Every config root that holds something a caller can read.
#
# -MustContain IS PART OF THE SAFETY, NOT A CONVENIENCE. This used to admit a root only if it held a
# `sessions` directory, and footprint.ps1 -- which reads `projects`, not `sessions` -- reused it to
# find the transcript corpus. A root holding a full corpus and no session registry (an account swap
# mid-flight; this machine carries a .claude-swap-backup) was therefore dropped BEFORE anything
# counted it, so the scan reported RootsExamined = 1 with zero faults while an entire corpus root, and
# every write recorded in it, was invisible. The predicate must name the directory the CALLER actually
# reads. A root matching ANY of the named subdirectories is admitted -- over-admitting costs an empty
# enumeration, under-admitting loses a corpus silently.
function Get-ClaudeConfigRoots {
    [CmdletBinding()]
    param([string[]]$ConfigRoot, [string[]]$MustContain = @('sessions'))
    if ($ConfigRoot) { return @($ConfigRoot | Where-Object { Test-Path $_ }) }
    return @(
        Get-ChildItem -Path $env:USERPROFILE -Directory -Filter ".claude*" -Force -EA SilentlyContinue |
            Where-Object {
                $root = $_.FullName
                @($MustContain | Where-Object { Test-Path (Join-Path $root $_) }).Count -gt 0
            } |
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
