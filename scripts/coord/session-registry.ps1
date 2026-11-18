# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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
      (Found=$false) no record at all -- it exited cleanly, or was never registered. State is UNKNOWN,
                  or UNREADABLE when a LIVE or fresh record that names no session reaches the
                  worktree the caller names (Test-AnonymousRecordReaches says which do), so may
                  be this one. The same record
                  turns a matched DEAD or STALE into UNREADABLE. Get-AnonymousSessionRecords and Get-SessionLiveness say how.

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
#
# EVERY PATH HERE AND IN Get-SessionRecords IS READ LITERALLY (vault BACKLOG #2985). A -Path read takes
# its argument as a wildcard pattern: a backtick escapes, [ ] is a set, and * and ? match. So a root
# named .claude``x was read as its sibling .claude`x, and a record named [1].json as 1.json, and a
# remover that trusted the read cleared a tree a session was recorded in. -Filter stays: it is the one
# pattern meant as one, and the file system matches it without PowerShell's escapes.
function Get-ClaudeConfigRoots {
    [CmdletBinding()]
    param([string[]]$ConfigRoot)
    if ($ConfigRoot) { return @($ConfigRoot | Where-Object { Test-Path -LiteralPath $_ }) }
    # No profile names no root. -LiteralPath refuses a null path with a throw, where -Path listed
    # the current directory instead.
    if (-not $env:USERPROFILE) { return @() }
    return @(
        Get-ChildItem -LiteralPath $env:USERPROFILE -Directory -Filter ".claude*" -Force -EA SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "sessions") } |
            ForEach-Object { $_.FullName }
    )
}

# The config root -> login label mapping. It lives HERE, beside the root enumeration it interprets,
# rather than in presence.ps1 where it started: two callers now need it and a second copy of a mapping
# is the drift this file already exists to prevent for the liveness fence.
function Get-LoginLabel([string]$RootPath) {
    $leaf = Split-Path $RootPath -Leaf
    if ($leaf -ieq ".claude") { return "default" }
    return ($leaf -replace '^\.claude-account-', 'acct-') -replace '^\.claude-?', ''
}

# WHICH LOGIN AM I ON. Answered from the session's OWN registry record, which is the only place the
# answer actually lives, and deliberately NOT from any repo-scoped roster.
#
# WHY THIS EXISTS AT ALL. A roster is built from the worktrees of one repo, so a session whose cwd is
# not one of them can never appear in it. The announce hook used to infer its login from its own row
# in that roster and fall back to the literal 'default' when the row was absent. That fallback is a
# GUESS, and on a non-default root it inverts every login comparison downstream rather than degrading
# it. Registry records are enumerated across every root, so this answers for a session the roster
# cannot see -- and returns '' honestly when there is no record rather than inventing one.
#
# RETURNS AN OBJECT, NOT A BARE LABEL, and the second field is the whole reason. An empty Login means
# "not known", never a default, because a wrong login is worse than an absent one -- but "not known"
# has two causes that a caller must be able to tell apart:
#
#   Matched = 0   no record carries this id. Usually transient: a session announcing on its first
#                 prompt while its record is still being written resolves itself next prompt.
#   Matched > 1   two or more config roots each claim this id. NOT transient and NOT self-resolving:
#                 duplicate roots do not converge, so a caller that treats it as "try again later"
#                 waits forever.
#
# Collapsing both to '' cost a real defect: the announce hook reported "no registry record matched
# this session id" while two matched, sending an operator to look for a missing file that was in fact
# present twice -- the one place the cause was visible.
function Get-LoginForSession {
    [CmdletBinding()]
    # NOT Mandatory, and that is a correctness decision rather than laxity. A mandatory [string] REJECTS
    # the empty string and prompts, which in a non-interactive hook throws -- and the announce hook
    # catches broadly, so the throw became a silent exit 0 with no output and no receipt. Measured while
    # building this: it took out -SelfTest entirely, which passes no session id by construction. The
    # same shape is on record in mail-drain.ps1's header, where a mandatory parameter rejecting an empty
    # string stranded a message inside a bare catch. An absent id is a legitimate question here and its
    # answer is '' -- the caller decides what that means.
    param([string]$SessionId, [string[]]$ConfigRoot)
    if (-not $SessionId) { return [pscustomobject]@{ Login = ''; Matched = 0 } }
    # EXACTLY ONE match is the only answer worth acting on. More than one means the same id is
    # registered under two roots, which this function cannot adjudicate and must not pick a winner
    # for -- but it REPORTS the count, so the caller can say which of the two silences it is in.
    $hits = @(
        Get-SessionRecords -ConfigRoot $ConfigRoot |
            Where-Object { [string](Get-RecordField $_.Record 'sessionId') -ieq $SessionId }
    )
    $login = if ($hits.Count -eq 1) { Get-LoginLabel $hits[0].Root } else { '' }
    return [pscustomobject]@{ Login = $login; Matched = $hits.Count }
}

# One field of a registry record, or $null when the record lacks it. A bare `$rec.pid` throws under
# Set-StrictMode for a missing property, and these functions run in their caller's strict scope
# (at least seat.ps1 and fleet.ps1 set it). A record missing a field is what a file caught mid-write looks like,
# so the read must answer rather than throw (BACKLOG #5491).
function Get-RecordField($Record, [string]$Name) {
    if ($null -eq $Record) { return $null }
    if ($Record -is [System.Collections.IDictionary]) {
        if ($Record.Contains($Name)) { return $Record[$Name] }
        return $null
    }
    $p = $Record.PSObject.Properties[$Name]
    if ($p) { return $p.Value }
    return $null
}

# A record's startedAt as a UTC DateTime, or $null when it is missing, not a number, or out of
# FromUnixTimeMilliseconds's range. Parsed as a double and rounded, as the [int64] cast this replaced
# did, so a fractional value still counts; NaN fails both bounds. A future value is returned as it
# is: Test-RecordLiveness compares it with the process start and reads one outside the skew as
# UNVERIFIED, and the anonymous-record aging drops future values itself.
function Get-RecordStartedUtc($Record) {
    $ms = 0.0
    if (-not [double]::TryParse([string](Get-RecordField $Record 'startedAt'), [System.Globalization.NumberStyles]::Float,
            [cultureinfo]::InvariantCulture, [ref]$ms) -or
        -not ($ms -ge -62135596800000 -and $ms -le 253402300799999)) { return $null }
    return [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$ms).UtcDateTime
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
        # -Force lists hidden and system records too: a record skipped here is a session no caller sees.
        # A directory named *.json is listed too, and reads as unreadable below.
        foreach ($f in @(Get-ChildItem -LiteralPath (Join-Path $root "sessions") -Filter *.json -Force -EA SilentlyContinue)) {
            # A single malformed record must never take down a caller -- one of these runs in a
            # SessionStart hook, where a throw replaces the chat's whole starting context.
            $rec = $null
            $err = ''
            if ($f -is [System.IO.DirectoryInfo]) { $err = 'a directory, not a file, so it cannot be read as a record' }
            else {
                try { $rec = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { $err = $_.Exception.Message }
            }
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
    # Fields are read through Get-RecordField and parsed with TryParse, because a cast throws on a value
    # that is not a number (BACKLOG #5491).
    $procId = 0
    if (-not [int]::TryParse([string](Get-RecordField $Record 'pid'), [ref]$procId) -or $procId -eq 0) {
        return @{ State = "UNREADABLE"; Detail = "no usable pid in record; it cannot be fenced" }
    }

    $proc = Get-Process -Id $procId -EA SilentlyContinue
    if (-not $proc) { return @{ State = "DEAD"; Detail = "pid $procId not running" } }

    $procStart = $null
    try { $procStart = $proc.StartTime } catch { }
    if (-not $procStart) {
        # Access can be denied for a process in another context. Report the uncertainty rather than
        # upgrading it to LIVE: an unverifiable fence is not a passed fence.
        return @{ State = "UNVERIFIED"; Detail = "pid $procId alive; start time unreadable" }
    }
    $startedUtc = Get-RecordStartedUtc $Record
    if ($null -eq $startedUtc) {
        return @{ State = "UNVERIFIED"; Detail = "pid $procId alive; record has no usable startedAt" }
    }
    $registered = $startedUtc.ToLocalTime()

    # A process cannot have started after the session it hosts registered (small forward slop for
    # clock jitter). Started much later => this pid was recycled onto a different process.
    $delta = ($procStart - $registered).TotalMinutes
    if ($delta -gt 1) {
        return @{ State = "STALE"; Detail = "pid $procId reused (process started $([long]$delta)m after the session)" }
    }
    if ($delta -lt (-1 * $StartSkewMinutes)) {
        # A startedAt still in the future cannot be a registration that happened, so outside the skew
        # it is an unusable start, not evidence of a recycled pid: UNVERIFIED, never STALE. Inside a
        # widened skew it falls through to LIVE, as it always did (remove.ps1 widens it). The [long]
        # casts replaced [int] ones, which threw on a gap past Int32 minutes.
        if ($startedUtc -gt [DateTime]::UtcNow.AddMinutes(1)) {
            return @{ State = "UNVERIFIED"; Detail = "pid $procId alive; record's startedAt is in the future" }
        }
        return @{ State = "STALE"; Detail = "pid $procId start precedes the session by $([long](-$delta))m" }
    }
    return @{ State = "LIVE"; Detail = "" }
}

# A path in the one form the anonymous-record scoping compares: forward slashes turned back, a
# \\?\ or \\.\ prefix dropped (\\?\UNC\ back to \\), trailing separators and space dropped,
# lower-cased. Windows paths compare case-insensitively. `.` and `..` segments are NOT collapsed, so a
# cwd spelled `<tree>\..\<other>` still reads as inside <tree> and vetoes it. A subst drive, a
# junction or an 8.3 short name is NOT resolved, so such a spelling still compares unequal.
function ConvertTo-RegistryNormPath([string]$Path) {
    if (-not $Path) { return '' }
    $p = $Path.Trim() -replace '/', '\'
    if ($p -match '^\\\\[?.]\\UNC\\') { $p = '\\' + $p.Substring(8) }
    elseif ($p -match '^\\\\[?.]\\') { $p = $p.Substring(4) }
    return $p.TrimEnd('\').ToLowerInvariant()
}

# Records that name no session and whose own fence is not DEAD or STALE, each with Fresh and Cwd.
#
# WHY THEY MATTER (BACKLOG #5491). Such a record may be the session a caller asks about, caught
# mid-write, so a gone answer beside one is not a gone answer. Under StrictMode the lookup used to
# throw on it, which seat.ps1 refused on; skipping it silently would turn that refusal into a clear.
#
# WHICH ONES VETO (Fresh = $true). A LIVE one always does: its pid and start time say it is running,
# and it stops vetoing on its own when that process exits. A non-LIVE one (UNVERIFIED or UNREADABLE)
# vetoes only while fresh, or a record that never gains its session id would block every clear
# until someone deleted it. Its age is taken from the newer of its startedAt and its file's last
# write, a future value of either being ignored. A file that vanished between the listing and this
# read is the shape of one being replaced right now, so it ages 0 whatever its startedAt. The
# default of 24 hours is box-activity.ps1's FreshHours, which bounds its own veto over unparsed
# registry files: the same "may be this session mid-launch" shape. An older one is returned with
# Fresh = $false, for the caller to report.
#
# WHERE THEY VETO is Get-SessionLiveness's -Worktree: Cwd is the record's own cwd, normalized, or ''
# when it has none it can read.
function Get-AnonymousSessionRecords {
    [CmdletBinding()]
    param(
        [object[]]$Records,
        [double]$FreshHours = 24,
        [int]$StartSkewMinutes = 15,
        # The clock the ages are taken against, so a caller with its own -Now ages these records by
        # the same instant it ages everything else.
        # A Local-kind value is converted to UTC first, so it cannot age a fresh record out by the
        # local offset. An Unspecified one is taken as UTC, as box-activity.ps1 takes its own -Now.
        [datetime]$Now = [DateTime]::UtcNow
    )
    if ($Now.Kind -eq [DateTimeKind]::Local) { $Now = $Now.ToUniversalTime() }
    $out = @()
    foreach ($r in @($Records)) {
        if (-not $r.Record -or [string](Get-RecordField $r.Record 'sessionId')) { continue }
        $state = (Test-RecordLiveness -Record $r.Record -StartSkewMinutes $StartSkewMinutes).State
        if ($state -in @('DEAD', 'STALE')) { continue }
        $item = Get-Item -LiteralPath $r.File -Force -EA SilentlyContinue
        # A future value is judged against the wall clock, never -Now: a record written after the
        # caller took its clock is the freshest kind, and ages 0 rather than dropping out.
        $wall = [DateTime]::UtcNow.AddMinutes(1)
        $times = @((Get-RecordStartedUtc $r.Record), $(if ($item) { $item.LastWriteTimeUtc })) |
            Where-Object { $null -ne $_ -and $_ -le $wall }
        $ageH = if (-not $item) { 0 }
                elseif ($times) { [math]::Max(0, ($Now - ($times | Sort-Object -Descending | Select-Object -First 1)).TotalHours) }
                else { [double]::PositiveInfinity }
        $cwd = Get-RecordField $r.Record 'cwd'
        $out += [pscustomobject]@{
            File     = $r.File
            Cwd      = if ($cwd -is [string]) { ConvertTo-RegistryNormPath $cwd } else { '' }
            State    = $state
            AgeHours = $ageH
            Fresh    = ($state -eq 'LIVE') -or ($ageH -lt $FreshHours)
        }
    }
    return $out
}

# Does an anonymous record veto a lookup for -Worktree? Only when the two name one tree: the record's
# cwd is that worktree or inside it, or is a git checkout (it holds a .git entry) that the worktree
# sits under. That last case is a session started in the primary checkout, which can work in a
# worktree under it (BACKLOG #5491); a plain parent such as a home directory or a drive root does
# not reach. A record with no readable cwd, a cwd that is not fully qualified (it resolves against
# the session's own directory, which nothing here knows), or a lookup that names no worktree, cannot
# be placed, so it vetoes wherever it is asked (fail closed).
function Test-AnonymousRecordReaches {
    param($Anonymous, [string]$Worktree)
    $w = ConvertTo-RegistryNormPath $Worktree
    if (-not $Anonymous.Cwd -or -not $w) { return $true }
    $c = $Anonymous.Cwd
    # With the separator put back: normalizing turns a drive root `C:\` into `c:`, which alone is not
    # fully qualified.
    if (-not [System.IO.Path]::IsPathFullyQualified($c + '\')) { return $true }
    if (($c -eq $w) -or $c.StartsWith($w + '\', 'Ordinal')) { return $true }
    # A string, not Join-Path, which throws on a drive this process does not have.
    return $w.StartsWith($c + '\', 'Ordinal') -and (Test-Path -LiteralPath "$c\.git")
}

# Look one session up by id (full or unique prefix) and fence it.
#
# -Worktree names the tree the caller is about to act on (a seat's worktree, a transcript's birth
# cwd). Pass it whenever it is known: without it every fresh anonymous record on the box vetoes.
function Get-SessionLiveness {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$SessionId,
        [string[]]$ConfigRoot,
        # Unbounded by default, as the removal paths pass it (remove.ps1, prune-merged.ps1 and the
        # nightly removal give [int]::MaxValue to Get-WorktreeOccupancy), so a session those fences
        # read LIVE never reads STALE, and so gone, here.
        [int]$StartSkewMinutes = [int]::MaxValue,
        [double]$AnonymousFreshHours = 24,
        [string]$Worktree,
        # Passed to Get-AnonymousSessionRecords, which ages the anonymous records by it.
        [datetime]$Now = [DateTime]::UtcNow
    )
    $records = @(Get-SessionRecords -ConfigRoot $ConfigRoot)
    $hit = @($records |
        Where-Object { $sid = [string](Get-RecordField $_.Record 'sessionId'); $sid -and $sid.StartsWith($SessionId, 'OrdinalIgnoreCase') })

    # Fenced only when the answer would be gone, the one case the anonymous records can change.
    # Anonymous lists the vetoing records, so a caller can name the real reason for a refusal.
    $anonymousVeto = {
        $anon = @(Get-AnonymousSessionRecords -Records $records -FreshHours $AnonymousFreshHours -StartSkewMinutes $StartSkewMinutes -Now $Now)
        $veto = @($anon | Where-Object { $_.Fresh -and (Test-AnonymousRecordReaches $_ $Worktree) })
        if ($veto.Count -gt 0) {
            $named = @($veto | ForEach-Object { if ($_.Cwd) { "$($_.File) (cwd $($_.Cwd))" } else { "$($_.File) (no readable cwd)" } })
            return @{ Veto = $true; Anonymous = $veto; Note = "but $($veto.Count) record(s) that are LIVE or were written in the last ${AnonymousFreshHours}h name no session and may be it: $($named -join '; ')" }
        }
        $old = @($anon | Where-Object { -not $_.Fresh } | ForEach-Object { $_.File })
        if ($old.Count -gt 0) {
            return @{ Veto = $false; Anonymous = @(); Note = "; $($old.Count) older record(s) name no session and do not veto: $($old -join '; ')" }
        }
        return @{ Veto = $false; Anonymous = @(); Note = '' }
    }

    if ($hit.Count -eq 0) {
        $a = & $anonymousVeto
        if ($a.Veto) {
            return @{ Found = $false; State = "UNREADABLE"; Detail = "no record names this session, $($a.Note)"; Record = $null; Anonymous = $a.Anonymous }
        }
        # Not registered. NOT proof it is gone -- a session that never registered looks identical to
        # one that exited cleanly, so callers must fall back to an independent signal.
        return @{ Found = $false; State = "UNKNOWN"; Detail = "no registry record$($a.Note)"; Record = $null; Anonymous = @() }
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
            $best = @{ Found = $true; State = $l.State; Detail = $l.Detail; Record = $h.Record; Anonymous = @() }
        }
    }
    if ($best.State -in @('DEAD', 'STALE')) {
        $a = & $anonymousVeto
        if ($a.Veto) {
            $best.Detail = "its record reads $($best.State) ($($best.Detail)), $($a.Note)"
            $best.State = "UNREADABLE"
            $best.Anonymous = $a.Anonymous
        } elseif ($a.Note) {
            $best.Detail = "$($best.Detail)$($a.Note)"
        }
    }
    return $best
}

# Was this session started by the Desktop app's scheduled-task runner, rather than by a person?
#
# THE REGISTRY CANNOT SAY. Measured 2026-10-16: a scheduled run's record reads kind=interactive,
# entrypoint=claude-desktop and nameSource=user, exactly like a session a person opened, and its name
# is only the task's title. The TRANSCRIPT can: its first line is the queue entry that started the
# run, and for a scheduled run that entry's content opens with `<scheduled-task name="...`. A session
# a person started opens with their own first prompt instead.
#
# WHY IT MATTERS: a scheduled run is a peer nobody is in. Announcing to it costs that run a turn per
# message, and the run's own announcements cost every real peer one.
#
# FAILS TOWARD $false. Any miss (no transcript yet, unreadable, unparseable) answers "a person's
# session", which is what every caller assumed before this existed. Only a positive marker excludes.
function Test-ScheduledTaskSession {
    [CmdletBinding()]
    param(
        [string]$Root,
        [string]$SessionId
    )
    # The id becomes a file name, so it must be one: no separators, no wildcards.
    if (-not $Root -or -not $SessionId -or $SessionId -notmatch '^[A-Za-z0-9._-]+$') { return $false }
    # Search every project directory rather than encoding the cwd. Measured 2026-10-16: one scheduled
    # run's transcript sat under two project directories, one of which matched no encoding of its cwd.
    # Walk them explicitly: `Get-ChildItem projects\* -Filter` returned nothing for a transcript that
    # was there.
    # Listed once per root per process: presence asks once per session, and the listing does not change
    # between those calls.
    if (-not $script:ProjectDirsByRoot) { $script:ProjectDirsByRoot = @{} }
    if (-not $script:ProjectDirsByRoot.ContainsKey($Root)) {
        $script:ProjectDirsByRoot[$Root] = @(Get-ChildItem -LiteralPath (Join-Path $Root 'projects') -Directory -EA SilentlyContinue |
                ForEach-Object { $_.FullName })
    }
    $hits = @($script:ProjectDirsByRoot[$Root] |
        ForEach-Object { Join-Path $_ "$SessionId.jsonl" } |
        Where-Object { Test-Path -LiteralPath $_ -PathType Leaf })
    foreach ($f in $hits) {
        try {
            $first = Get-Content -LiteralPath $f -TotalCount 1 -EA Stop
            $rec = $first | ConvertFrom-Json -EA Stop
            # The queue entry is what was measured. A first `user` record carrying the same prompt is
            # accepted too, so a runner that skips the queue does not silently turn the flag off.
            $text = if ($rec.type -eq 'queue-operation') { $rec.content }
                    elseif ($rec.type -eq 'user' -and $rec.message.content -is [string]) { $rec.message.content }
                    else { $null }
            if ($text -is [string] -and $text.StartsWith('<scheduled-task ', 'Ordinal')) { return $true }
        } catch { continue }
    }
    return $false
}
