# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Write or read the AFK-autonomy decision log (ADR 0211; docs/AUTONOMY-PLAN.md section 4.1).

.DESCRIPTION
    -Log writes ONE record. It is spooled locally first and then posted to the vault's issue for
    its UTC day, so a network failure loses nothing: the record stays spooled, the script says so
    and exits 4, and the next -Log or -Flush posts it. -NoPost spools only and posts nothing; the
    tripwire hook uses it. It never probes a shared root, and it skips a seat registry it can tell
    is on a share: at least a UNC path, a drive letter Windows reports as a network drive, and a
    path whose kind cannot be told. It CANNOT tell a share mounted under `/`, or a junction or
    symlink that leads to a share; a registry there is read, and a dead server can hang that read.

    -List reads records by day (-Day, default today UTC, and -Days for a range ending there), and
    filters them by -Seat or -Item. It reads the vault and the local spool, and marks a record that
    is still only spooled. An incomplete read (a vault read that fails, or a spool read
    _decisionlog.ps1 Read-DecisionSpool calls incomplete) is said aloud and exits 4: an empty answer
    from an unread log would look like a quiet day.

    -Flush posts whatever is spooled, except a record another worker holds the lock of, such as a
    -Log whose gate is still running, which it leaves for the next -Log or -Flush. It prints
    `FLUSHED posted=N failed=N held=N skipped=N`: held is that wait, failed a record it could not
    read or post, and skipped a record whose lock it could not make; each is named on stderr. A
    failed or skipped record exits 4; a held one does not, since its holder is still at work.
    _decisionlog.ps1 says how the spool's lock and posted mark work (The spool).

    -Gate -Item <item> [-Seat <seat>] [-BuildsOn <id>] answers which path a Class B act may take
    (docs/AUTONOMY-PLAN.md R4 and 4.5-4.7). It prints one word as its only stdout line, the reasons
    on stderr, or an object under -Json:
        NO-REVIEW  exit 10  the gate's conditions hold. NECESSARY, NOT SUFFICIENT: plan R4 also
                            needs a single revert or PR close to undo the act, no Class C path
                            touched, and live state read this turn, which the gate cannot see.
                            The session checks those itself before acting without review.
        REVIEW     exit 11  take the adversarial-review path first.
        HALT       exit 12  do not act; defer. The cost rung is hit.
    NO-REVIEW needs all of: the kill switch reads exactly OFF (afk-kill.ps1 -Status); the seat's
    Class B is calibrated, by the digest's own arithmetic (_decisionlog.ps1 Get-DecisionCalibration);
    no decision on the item was reversed in the 60 days read; the reversal budget is open (plan 4.5:
    3 reversals fleet-wide or 2 of the seat's own decisions inside 24 hours close it for 24 hours);
    the chain is no deeper than two (plan 4.6, below); and the cost rung is not hit (plan 4.7).
    IT FAILS CLOSED. No exit code but 10 is NO-REVIEW, so a crash (1), a usage error (2) or anything
    else reads as no permission. A read that fails, a seat that cannot be named, and a cost reading
    that is UNKNOWN all answer REVIEW. HALT comes from the cost rung only, and is checked first; the
    Lander is exempt from it (korus roles/STEWARD.md 3e). The gate stops at the first condition that
    closes the no-review path before the log is read, so a REVIEW for a kill switch reads no log.
    Today no seat is calibrated, so it answers REVIEW (or HALT) for everyone. That is correct.

    THE CHAIN. -BuildsOn names the decisions this one builds on. Depth is the unsampled (unrated)
    Class B decisions on the same item reachable through those links, and never less than the
    unsampled Class B decisions on the item logged in the trailing 24 hours, because -BuildsOn is
    self-reported. More than two goes to review. A linked id the log does not hold fails closed.

    -LOG ENFORCES IT. A `decision` record of Class B with -Reviewed no is locked, spooled with `gate`
    PENDING, then the gate runs, skipping that record, and its answer replaces PENDING in the spooled
    copy before the lock is given up. So a gate that crashes or hangs loses no record; one left
    PENDING counts toward the chain floor. No flusher posts the record while this -Log runs, and
    once it has exited, the lock is stale and the record is posted as it stands. The record is posted whatever the answer. When the answer is not NO-REVIEW, -Log prints
    `GATE <word>` and why, and exits with the gate's code, 11 or 12, in place of 0 or 4: the act must not go ahead without review, and the
    LOGGED line still says whether the record was posted or is still spooled. Under -NoPost the gate
    reads no network, so it can answer HALT or REVIEW but never NO-REVIEW. -Log stops an act only
    when a session logs BEFORE it acts; the empower skill, as read on 2026-10-26, says to log each
    decision and not when, so a session following it should run -Gate first. At least these do not call -Gate: the spawn
    hooks, wait-pr.ps1 and the driver and empower skills, so none of them stops on the cost rung.

    KINDS. `decision` is one Class A to D decision. `tripwire` is a tripwire hit. `rating` is the
    owner's blind-sample verdict on a decision (-Ref, -Rating). `outcome` updates a decision's
    outcome later (-Ref, -Outcome), and `-Outcome reversed` is what the digest counts as a reversal:
    a revert, a reopen, a re-brief or an override.

    THE FIELDS ARE ADR 0211's SCHEMA. -Predicate takes `name=evidence` strings, the predicates this
    turn checked and what each read showed. -Confidence is the session's stated confidence, 0 to
    100; it is logged and never used as a gate (plan R4).

    SEVERAL PREDICATES OR ALTERNATIVES. `pwsh -File` cannot repeat a parameter or pass an array, so
    each -Predicate and -Alternative value is also split at newlines: one argument may carry
    several, one per line. Called in-process (`& decision.ps1`), an array works as well.

    The seat defaults to the one this session declared in the seat registry, found by its session
    id; the session id defaults to $env:CLAUDE_CODE_SESSION_ID. Only this worktree's two boxes and
    this host's records count, so a seat declared from another worktree is not found. A record that
    cannot be read names no seat. Under -NoPost a registry on a share (above) names no seat.

.EXAMPLE
    decision.ps1 -Log -Item 3905 -Class B -Recommendation 'split the fix into two PRs' `
      -Alternative 'one PR' -Predicate 'live-state=gh pr view 2460 read 17:02Z' `
      -Undo 'close the second PR' -Confidence 80

.EXAMPLE
    decision.ps1 -List -Day 2026-10-21 -Seat manager

.EXAMPLE
    decision.ps1 -Gate -Item 3905 -BuildsOn d20261026T101500123-a1b2c3
#>
param(
    [switch]$Log,
    [switch]$List,
    [switch]$Flush,
    [switch]$Gate,
    [string[]]$BuildsOn = @(),
    # The usage reader and the Steward's thresholds file the cost rung reads. Defaulted in the body
    # (usage.ps1 beside this script; <home>\.claude\mefor-usage\thresholds.json); tests name fixtures.
    [string]$UsageScript = '',
    [string]$ThresholdsFile = '',
    # How long the cost rung waits on the usage reader before it reads UNKNOWN. A test that holds
    # the reader open names a longer wait, so its checks do not race the default. Capped at five
    # minutes. No flusher posts the record while its -Log runs, however long the gate waits.
    [ValidateRange(1, 300)][int]$UsageTimeoutSeconds = 30,
    [ValidateSet('decision', 'tripwire', 'rating', 'outcome')][string]$Kind = 'decision',
    [string]$Item = '',
    [string]$Seat = '',
    [string]$Session = '',
    [ValidateSet('', 'A', 'B', 'C', 'D')][string]$Class = '',
    [string[]]$Predicate = @(),
    [string]$Recommendation = '',
    [string[]]$Alternative = @(),
    [string]$Undo = '',
    [ValidateRange(-1, 100)][int]$Confidence = -1,
    [ValidateSet('no', 'yes')][string]$Reviewed = 'no',
    [string]$ReviewedBy = '',
    [string]$Outcome = '',
    [string]$Ref = '',
    [ValidateSet('', 'agree', 'disagree')][string]$Rating = '',
    [string]$Note = '',
    [switch]$NoPost,
    [string]$Day = '',
    [ValidateRange(1, 100)][int]$Days = 1,
    [switch]$Json,
    [string]$Repo = 'MEFORORG/MessageFoundry-vault'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A CLAUDE CODE CLOUD SESSION REACHES NO OTHER SESSION THROUGH THIS SCRIPT: its spool is the VM's
# own clone, and the owner ruled that vault work stays local (plan section 9, question 3), so a
# cloud Builder's decisions are logged by its Manager. CLAUDE.md section 5, "A cloud session is a
# Builder in its own session"; tests/test_coord_cloud_refusal.py holds the copies equal.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('decision.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

$modes = @($Log, $List, $Flush, $Gate | Where-Object { $_ })
if ($modes.Count -ne 1) {
    [Console]::Error.WriteLine('decision.ps1: give exactly one of -Log, -List, -Flush or -Gate.')
    exit 2
}

. (Join-Path $PSScriptRoot '_decisionlog.ps1')
# seat.ps1's root resolver and box keys, so the seat lookup reads where seat.ps1 writes.
. (Join-Path $PSScriptRoot 'coord-root.ps1')
. (Join-Path $PSScriptRoot 'mail-key.ps1')
$coord = Get-DecisionCoordRoot
if (-not $UsageScript) { $UsageScript = Get-DecisionUsageScript }
if (-not $ThresholdsFile) { $ThresholdsFile = Get-DecisionThresholdsFile }

# The gate's exit codes. None is 0 or 4, so no other answer of this script reads as NO-REVIEW.
$GateCodes = @{ 'NO-REVIEW' = 10; 'REVIEW' = 11; 'HALT' = 12 }

function ConvertTo-SeatRecordInstant($Value) {
    # A record's asOf as a UTC instant, or MinValue when it is absent or will not parse. A bad sort
    # key ranks the record last; it never drops the seat the record names.
    # ConvertFrom-Json hands an ISO stamp back as a [datetime]. One with an offset arrives as Local and
    # converts; one with no offset arrives as Unspecified, and ToUniversalTime() would read that as
    # local time and shift it by the offset (the trap lane.ps1 documents at statedUtc). Such a stamp
    # is UTC, so its Kind is set, not converted.
    try {
        if ($null -eq $Value) { return [datetime]::MinValue }
        if ($Value -is [datetime]) {
            if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
            return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
        }
        $text = [string]$Value
        if (-not $text.Trim()) { return [datetime]::MinValue }
        return [datetime]::Parse($text, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    } catch {
        return [datetime]::MinValue
    }
}

function Test-SeatRootIsNetwork([string]$Path) {
    # True when $Path is at least one of: a UNC path, a drive letter DriveInfo reports as Network (a
    # local call), or a path whose kind cannot be told. NOT detected: a share mounted under `/`, and a
    # junction or symlink that leads to a share. Those read as local.
    if (Get-CoordUncHost -Path $Path) { return $true }
    try {
        $rootOf = [System.IO.Path]::GetPathRoot($Path)
        if (-not $rootOf) { return $true }
        if ($rootOf -match '\A[A-Za-z]:') {
            return ([System.IO.DriveInfo]::new($rootOf).DriveType -eq [System.IO.DriveType]::Network)
        }
        return $false
    } catch {
        return $true
    }
}

function Get-SeatCandidate([string]$File) {
    # One seat record as a candidate, or $null. A record that was read but is wrong skips that record
    # only: an empty `{}`, bad JSON, a non-object, no seat, or a `host` naming another machine.
    # A record that exists but cannot be READ throws to the caller, which then names no seat: it may
    # be the newer record, so the other box's older one is not the seat.
    if (-not [System.IO.File]::Exists($File) -and -not [System.IO.Directory]::Exists($File)) { return $null }
    # Read-CoordText retries an SMB sharing violation, then rethrows it, so an unreadable record still
    # throws to the caller as above.
    $text = Read-CoordText $File
    try {
        $r = $text | ConvertFrom-Json -ErrorAction Stop
        if ($r -isnot [System.Management.Automation.PSCustomObject]) { return $null }
        # A record in EITHER box that names another host is that PC's seat, here for at least these
        # reasons: copied, hand-made, a short-hash collision, or a mistyped coord-migrate.ps1
        # -SourceHost. lane.ps1 refuses the same shape at its own key. A record with no host was
        # written here.
        if (-not (Test-CoordRecordIsHere $r)) { return $null }
        $props = $r.PSObject.Properties
        $s = if ($props['seat'] -and $r.seat) { [string]$r.seat } else { '' }
        if (-not $s) { return $null }
        $declared = [bool]$props['seatSource'] -and ([string]$r.seatSource -eq 'declared')
        $at = if ($props['asOf']) { ConvertTo-SeatRecordInstant $r.asOf } else { [datetime]::MinValue }
        $n = 0
        if ($props['writes']) { try { $n = [int]$r.writes } catch { $n = 0 } }
        return [pscustomobject]@{ Seat = $s; Declared = $declared; At = $at; Writes = $n }
    } catch {
        return $null
    }
}

function Resolve-SeatFromRegistry([string]$Sid, [switch]$Offline) {
    # The seat this session declared, read where seat.ps1 writes it and picked by seat.ps1's rules.
    # The file name is seat.ps1's Get-SessionKey of the id (keep the two in step), sanitised so an id
    # cannot widen the match.
    #
    # WHERE. seats/ is a shared kind, so seat.ps1 writes it on the resolved shared root, and this reads
    # it there, resolved from the same worktree (this cwd's top level, as seat.ps1 resolves it). A
    # Codex seat's records stay on the local root. A root that does not resolve names no seat; it
    # never falls back to the local copy, which the other PC never sees.
    #
    # -Offline (-NoPost, the tripwire hook's path) resolves the root without the port-445 probe, and
    # skips a root Test-SeatRootIsNetwork flags; its comment says what that misses. A dead SMB server
    # can hang one file call for about a minute, far past the hook's budget. A tripwire record needs
    # no seat.
    #
    # WHICH BOX. Only this worktree's two boxes: the host-keyed one seat.ps1 writes, and the path-only
    # legacy one a session that declared before docs/COORD-SHARED-ROOT.md step 4 still has. A record
    # in either box stamped by another host is that PC's seat and is skipped.
    #
    # WHICH RECORD. A declared seat beats a derived one (seat.ps1: "declared wins, derived fills only a
    # vacuum"). Among equals the record written LAST wins, by its own asOf and then its write count,
    # which is how seat.ps1 picks its prior. Listing order decides nothing.
    #
    # This mirrors seat.ps1 rather than calling it: seat.ps1's prior picker is inline in its main body,
    # which writes, and it does not weigh seatSource, because it only carries a prior forward.
    if (-not $Sid) { return '' }
    if ($env:KORUS_AGENT -eq 'codex') { $Sid = "codex-$Sid" }
    $Sid = $Sid -replace '[^A-Za-z0-9._-]', '-'
    if ($Sid.Length -gt 80) { $Sid = $Sid.Substring(0, 80) }
    if ($Sid -match '^\.+$') { return '' }
    try {
        $top = & git -C (Get-Location).Path rev-parse --show-toplevel 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $top) { return '' }
        $wt = (Resolve-Path -LiteralPath ([string]$top).Trim() -ErrorAction Stop).Path
        $localRoot = Get-CoordLocalRoot -From $wt
        if ($env:KORUS_AGENT -eq 'codex') {
            $res = Resolve-CoordDir -From $wt -Kind 'codex-seats' -LocalRoot $localRoot
            $seats = $res.Path
        } else {
            $res = if ($Offline) {
                Get-CoordSharedRoot -From $wt -LocalRoot $localRoot
            } else {
                Resolve-CoordSharedRoot -From $wt -LocalRoot $localRoot
            }
            if ($Offline -and $res.Path -and $res.Source -ne 'local' -and (Test-SeatRootIsNetwork $res.Path)) {
                # The error stream, not [Console]::Error, so the tripwire hook's 2>$null silences it.
                Write-Error -ErrorAction Continue "decision.ps1: -NoPost reads no network, and the seat registry is on $($res.Path), so no seat was read from it."
                return ''
            }
            $seats = if ($res.Path) { Join-Path $res.Path 'seats' } else { $null }
        }
        if ($res.Error -or -not $seats) {
            [Console]::Error.WriteLine("decision.ps1: the seat registry did not resolve, so no seat was read from it: $($res.Error)")
            return ''
        }
        $best = $null
        foreach ($box in @((ConvertTo-BoxKey -Path $wt), (ConvertTo-LegacyBoxKey -Path $wt))) {
            $cand = Get-SeatCandidate (Join-Path (Join-Path $seats $box) "$Sid.json")
            if (-not $cand) { continue }
            if (-not $best) { $best = $cand; continue }
            if ($cand.Declared -ne $best.Declared) {
                if ($cand.Declared) { $best = $cand }
                continue
            }
            if ($cand.At -gt $best.At -or ($cand.At -eq $best.At -and $cand.Writes -gt $best.Writes)) { $best = $cand }
        }
        if ($best) { return $best.Seat }
        return ''
    } catch {
        # An I/O error on the registry (an SMB share dropping, or one record that cannot be read) costs
        # the default seat, not -Log.
        [Console]::Error.WriteLine("decision.ps1: the seat registry could not be read, so no seat was read from it: $($_.Exception.Message)")
        return ''
    }
}

function Write-Flushed($Result) {
    foreach ($e in @($Result.Errors) + @($Result.Skipped)) { [Console]::Error.WriteLine("decision.ps1: NOT POSTED, still spooled: $e") }
    foreach ($e in $Result.Held) { [Console]::Error.WriteLine("decision.ps1: HELD, still spooled: $e") }
    foreach ($e in $Result.Warnings) { [Console]::Error.WriteLine("decision.ps1: WARNING: $e") }
}

function New-GateAnswer([string]$Result, $Why) {
    return [pscustomobject]@{ Result = $Result; Reasons = @($Why) }
}

function Invoke-DecisionGate {
    <#
      The class B gate's answer, NO-REVIEW, REVIEW or HALT, with its reasons. The header lists the
      conditions. Checked cheapest first, and it stops at the first that closes the no-review path
      until the log is read; from there every condition is checked and every failure is named. Any
      throw inside is REVIEW. -ExcludeId is the record -Log spooled before asking, which must not
      count against itself.
    #>
    param([string]$Item, [string]$Seat, [string[]]$BuildsOn, [string]$UsageScript, [string]$ThresholdsFile, [switch]$Offline,
        [string]$ExcludeId = '')
    $why = [System.Collections.Generic.List[string]]::new()
    try {
        if (Test-DecisionLanderSeat $Seat) {
            $why.Add('cost rung: not read, because the Lander is exempt from the Steward''s states (korus roles/STEWARD.md 3e)')
        } else {
            $rung = Get-DecisionCostRung -UsageScript $UsageScript -ThresholdsFile $ThresholdsFile -TimeoutSeconds $UsageTimeoutSeconds
            $why.Add("cost rung $($rung.State): $($rung.Reason)")
            if ($rung.State -eq 'HIT') { return (New-GateAnswer 'HALT' $why) }
            if ($rung.State -ne 'OK') {
                # UNKNOWN is common (a Desktop session runs no statusLine), so it must not halt: that
                # would shut the gate for good. It cannot show the rung is clear either.
                $why.Add('an UNKNOWN cost reading cannot show the rung is clear, so this goes to review, not to a halt')
                return (New-GateAnswer 'REVIEW' $why)
            }
        }
        if (-not $Seat) {
            $why.Add('no seat was given or found in the seat registry, so its calibration and its reversal budget cannot be read')
            return (New-GateAnswer 'REVIEW' $why)
        }
        if ($Offline) {
            $why.Add('-NoPost reads no network, so the kill switch and the log were not read')
            return (New-GateAnswer 'REVIEW' $why)
        }
        $kill = Get-DecisionKillSwitch
        if ($kill -ne 'OFF') {
            $why.Add("kill switch reads '$kill', so every class is in ask-mode (ADR 0211)")
            return (New-GateAnswer 'REVIEW' $why)
        }
        $now = [DateTime]::UtcNow
        $today = $now.ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        # The digest's default window, plus the days the -BuildsOn ids name, plus tomorrow, where a
        # clock running ahead files a record near midnight: the budget and the chain floor count a
        # future-dated record as now. Read-DecisionLogForGate adds the days of reversed decisions
        # older than all of them.
        $window = @(Get-DecisionDayRange $today 60)
        $tomorrow = $now.AddDays(1).ToString('yyyy-MM-dd', [Globalization.CultureInfo]::InvariantCulture)
        $days = @(@($window) + $tomorrow + @($BuildsOn | ForEach-Object { Get-DecisionIdDay $_ }) | Select-Object -Unique)
        $res = Read-DecisionLogForGate -Repo $Repo -CoordRoot $coord -Days $days
        if (-not $res.Complete) {
            $why.Add("the decision log was not fully read, so no condition on it can be shown: $($res.Errors -join '; ')")
            return (New-GateAnswer 'REVIEW' $why)
        }
        $all = @($res.Records | Where-Object { [string]$_.id -ne $ExcludeId })
        $ratings = Get-DecisionLatest $all 'rating'
        $outcomes = Get-DecisionLatest $all 'outcome'
        $reversals = @(Get-DecisionReversals $all)
        $closed = $false

        # Calibration reads the window alone, so it is the digest's whatever else was read for joins.
        $cal = Get-DecisionCalibration -Ratings $ratings -Outcomes $outcomes -RecentDays @(Get-DecisionDayRange $today 14) -Decisions @($all | Where-Object {
                $_.kind -eq 'decision' -and [string]$_.seat -eq $Seat -and $_.class -eq 'B' -and $window -contains (Get-DecisionIdDay ([string]$_.id))
            })
        if (-not $cal.Calibrated) {
            $why.Add("calibration: $Seat's Class B is not calibrated ($($cal.Blind); 14-day reversal rate $($cal.RateText))")
            $closed = $true
        }
        foreach ($r in $reversals) {
            if ([string]$r.Item -eq $Item) {
                $why.Add("item: decision $($r.Ref) on item $Item was reversed")
                $closed = $true
            } elseif (-not $r.Item) {
                $why.Add("item: the reversal of $($r.Ref) refers to a decision the log does not hold and names no item, so it may be this item's")
                $closed = $true
            }
        }
        $fleet = Get-DecisionBudget -Reversals $reversals -Now $now
        if ($fleet.ClosedUntil) {
            $why.Add("reversal budget: three reversals fleet-wide inside 24 hours close the no-review path for everyone until $(Format-DecisionInstant $fleet.ClosedUntil)")
            $closed = $true
        }
        $own = Get-DecisionBudget -Reversals $reversals -Now $now -Seat $Seat
        if ($own.ClosedUntil) {
            $why.Add("reversal budget: two reversals of $Seat's decisions inside 24 hours close its no-review path until $(Format-DecisionInstant $own.ClosedUntil)")
            $closed = $true
        }
        $ch = Get-DecisionChain -Records $all -Item $Item -BuildsOn $BuildsOn -Now $now -Ratings $ratings
        if ($ch.Missing.Count) {
            $why.Add("chain: it builds on $($ch.Missing -join ', '), which the log read does not hold, so the depth cannot be counted")
            $closed = $true
        }
        if ($ch.Depth -gt 2) {
            $why.Add("chain: depth $($ch.Depth) on item $Item ($($ch.Walked) through -BuildsOn, $($ch.Floor) in the trailing 24 hours), and more than two goes to review")
            $closed = $true
        }
        if ($closed) { return (New-GateAnswer 'REVIEW' $why) }
        $why.Add("every condition holds: kill switch OFF, calibrated, no reversal on the item, budgets open, chain depth $($ch.Depth)")
        return (New-GateAnswer 'NO-REVIEW' $why)
    } catch {
        $why.Add("the gate failed, so it fails closed: $($_.Exception.Message)")
        return (New-GateAnswer 'REVIEW' $why)
    }
}

# -BuildsOn is split at newlines like -Predicate, and refused before anything is read or written.
$BuildsOn = @($BuildsOn | ForEach-Object { $_ -split '\r?\n' } | ForEach-Object { $_.Trim() } | Where-Object { $_ } | Select-Object -Unique)
foreach ($b in $BuildsOn) {
    if (-not (Get-DecisionIdDay $b)) {
        [Console]::Error.WriteLine("decision.ps1: -BuildsOn '$b' is not a decision id. Nothing was written.")
        exit 2
    }
}

if ($Gate) {
    if (-not $Item) { [Console]::Error.WriteLine('decision.ps1: -Gate needs -Item, the item the act is on.'); exit 2 }
    if (-not $Session) { $Session = [string]$env:CLAUDE_CODE_SESSION_ID }
    if (-not $Seat) { $Seat = Resolve-SeatFromRegistry $Session }
    $g = Invoke-DecisionGate -Item $Item -Seat $Seat -BuildsOn $BuildsOn -UsageScript $UsageScript -ThresholdsFile $ThresholdsFile
    if ($Json) {
        Write-Output (ConvertTo-Json -Depth 4 -InputObject ([ordered]@{
                    result = $g.Result; exit = $GateCodes[$g.Result]; item = $Item; seat = $Seat; buildsOn = @($BuildsOn); reasons = @($g.Reasons)
                }))
    } else {
        foreach ($r in $g.Reasons) { [Console]::Error.WriteLine("decision.ps1: gate: $r") }
        Write-Output $g.Result
    }
    exit $GateCodes[$g.Result]
}

if ($Flush) {
    $r = Send-DecisionSpool -Repo $Repo -CoordRoot $coord
    Write-Flushed $r
    Write-Output "FLUSHED posted=$($r.Posted) failed=$($r.Errors.Count) held=$($r.Held.Count) skipped=$($r.Skipped.Count)"
    exit ($(if ($r.Errors.Count -or $r.Skipped.Count) { 4 } else { 0 }))
}

if ($List) {
    try { $Day = Resolve-DecisionDay $Day } catch { [Console]::Error.WriteLine("decision.ps1: $($_.Exception.Message)"); exit 2 }
    $res = Read-DecisionLog -Repo $Repo -CoordRoot $coord -Days (Get-DecisionDayRange $Day $Days)
    $rows = @($res.Records | Where-Object {
            (-not $Seat -or [string]$_.seat -eq $Seat) -and (-not $Item -or [string]$_.item -eq $Item)
        })
    if ($Json) {
        Write-Output (ConvertTo-Json -InputObject $rows -Depth 8)
    } else {
        foreach ($r in $rows) {
            $flag = if ($r.posted) { '' } else { ' [spooled, not posted]' }
            $what = if ([string]$r.recommendation) { [string]$r.recommendation } else { [string]$r.note }
            if ($what.Length -gt 80) { $what = $what.Substring(0, 77) + '...' }
            Write-Output ("{0}  {1,-8} {2,-1} {3,-10} {4,-10} {5}{6}" -f $r.id, $r.kind, $r.class, $r.seat, $r.item, $what, $flag)
        }
        Write-Output "$($rows.Count) record(s)."
    }
    if (-not $res.Complete) {
        foreach ($e in $res.Errors) { [Console]::Error.WriteLine("decision.ps1: INCOMPLETE, the log was not fully read: $e") }
        exit 4
    }
    exit 0
}

# -Log. Refuse a record missing what its kind needs, before anything is written.
if (-not $Session) { $Session = [string]$env:CLAUDE_CODE_SESSION_ID }
if (-not $Seat) { $Seat = Resolve-SeatFromRegistry $Session -Offline:$NoPost }
$missing = switch ($Kind) {
    'decision' { @(@{ Item = $Item; Class = $Class; Recommendation = $Recommendation; Seat = $Seat }.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key) }
    'tripwire' { @(if (-not $Note) { 'Note' }) }
    'rating' { @(if (-not $Ref) { 'Ref' }; if (-not $Rating) { 'Rating' }) }
    'outcome' { @(if (-not $Ref) { 'Ref' }; if (-not $Outcome) { 'Outcome' }) }
}
if ($missing) {
    [Console]::Error.WriteLine("decision.ps1: a $Kind record needs $((@($missing) | Sort-Object) -join ', '). Nothing was written.")
    exit 2
}
if ($Ref -and -not (Get-DecisionIdDay $Ref)) {
    [Console]::Error.WriteLine("decision.ps1: -Ref '$Ref' is not a decision id. Nothing was written.")
    exit 2
}
if ($Reviewed -eq 'yes' -and -not $ReviewedBy) {
    [Console]::Error.WriteLine('decision.ps1: -Reviewed yes needs -ReviewedBy, the reviewer. Nothing was written.')
    exit 2
}

$Predicate = @($Predicate | ForEach-Object { $_ -split '\r?\n' } | Where-Object { $_.Trim() })
$Alternative = @($Alternative | ForEach-Object { $_ -split '\r?\n' } | Where-Object { $_.Trim() })
$preds = foreach ($p in $Predicate) {
    $at = $p.IndexOf('=')
    if ($at -lt 1) { [Console]::Error.WriteLine("decision.ps1: -Predicate '$p' is not name=evidence. Nothing was written."); exit 2 }
    [ordered]@{ name = $p.Substring(0, $at).Trim(); evidence = $p.Substring($at + 1).Trim() }
}
# Where the gate is enforced (plan 4.5-4.7): empower requires every Class B decision to be logged,
# so an unreviewed one meets the gate here. That stops the act only when the log comes before it
# (the header says so). The record is written whatever the answer.
$gated = $Kind -eq 'decision' -and $Class -eq 'B' -and $Reviewed -eq 'no'
$gateAnswer = $null
$cfg = [string]$env:CLAUDE_CONFIG_DIR
$record = [ordered]@{
    v              = 1
    id             = New-DecisionId
    ts             = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ', [Globalization.CultureInfo]::InvariantCulture)
    kind           = $Kind
    item           = $Item
    seat           = $Seat
    session        = $Session
    account        = $(if ($cfg) { Split-Path -Leaf $cfg } else { '' })
    host           = [Environment]::MachineName
    class          = $(if ($Kind -eq 'tripwire' -and -not $Class) { 'C' } else { $Class })
    predicates     = @($preds)
    recommendation = $Recommendation
    alternatives   = @($Alternative)
    undo           = $Undo
    confidence     = $(if ($Confidence -ge 0) { $Confidence } else { $null })
    reviewed       = $Reviewed
    reviewedBy     = $ReviewedBy
    outcome        = $(if ($Outcome) { $Outcome } elseif ($Kind -eq 'tripwire') { 'detected' } else { 'pending' })
    ref            = $Ref
    rating         = $Rating
    note           = $Note
    buildsOn       = @($BuildsOn)
    # PENDING until the gate answers, below. A record left PENDING (the gate crashed or hung, or a
    # flusher posted it first) counts toward the chain floor like any unsampled Class B decision.
    gate           = $(if ($gated) { 'PENDING' } else { '' })
}

function Complete-Log([string]$How, [int]$Code) {
    # The LOGGED line always; then the gate's word and, when it is not NO-REVIEW, why and its code.
    Write-Output "LOGGED $($record.id) $How"
    if ($gateAnswer) {
        Write-Output "GATE $($gateAnswer.Result)"
        if ($gateAnswer.Result -ne 'NO-REVIEW') {
            foreach ($w in $gateAnswer.Reasons) { [Console]::Error.WriteLine("decision.ps1: gate: $w") }
            exit $GateCodes[$gateAnswer.Result]
        }
    }
    exit $Code
}

# EVERY RECORD IS SPOOLED BEFORE ANYTHING ELSE RUNS, the gate included, so a gate that crashes or
# hangs cannot lose it. A gated record is locked first and stays locked until the gate's answer is
# written into it, so no flusher posts it PENDING while this -Log runs. The gate skips its own id.
if ($gated) {
    if (-not (Lock-DecisionSpool -CoordRoot $coord -Id $record.id)) { throw "the lock of the new record $($record.id) is already held" }
    try {
        Write-DecisionSpool -CoordRoot $coord -Record ([pscustomobject]$record)
        $gateAnswer = Invoke-DecisionGate -Item $Item -Seat $Seat -BuildsOn $BuildsOn -UsageScript $UsageScript `
            -ThresholdsFile $ThresholdsFile -Offline:$NoPost -ExcludeId $record.id
        $record.gate = $gateAnswer.Result
        # The gate has answered, so a failure to write the answer down must not hide it: the record
        # keeps PENDING, which counts toward the chain floor, and -Log still reports the answer.
        try { Update-DecisionSpool -CoordRoot $coord -Record ([pscustomobject]$record) }
        catch {
            [Console]::Error.WriteLine("decision.ps1: the gate answered $($gateAnswer.Result), but $($record.id) could not be rewritten (its new copy could not be written: $($_.Exception.Message)), so the record says gate PENDING.")
        }
    } finally {
        Unlock-DecisionSpool -CoordRoot $coord -Id $record.id
    }
} else {
    Write-DecisionSpool -CoordRoot $coord -Record ([pscustomobject]$record)
}
if ($NoPost) { Complete-Log 'spooled' 0 }
$r = Send-DecisionSpool -Repo $Repo -CoordRoot $coord
Write-Flushed $r
# Posted is this flush's post, or an earlier one's: the posted mark, or no spool file left.
if ($r.PostedIds -notcontains $record.id -and (Test-DecisionSpooled -CoordRoot $coord -Id $record.id)) {
    Complete-Log 'spooled' 4
}
Complete-Log 'posted' 0
