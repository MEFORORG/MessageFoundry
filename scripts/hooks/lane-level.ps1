# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Stop hook. In a builder session it nags that lane for its own level. In the dispatcher session
    it reports each lane's stated counts, and it never calls a lane full.

.DESCRIPTION
    THERE IS NO ITEM CEILING. The owner ruling of 2026-10-26 is stated once, in the header of
    scripts/coord/lane.ps1. This hook used to call a lane AT CAPACITY when it stated no free items,
    against a four-item ceiling, and went quiet when both lanes said so. Now no count it reads
    becomes a verdict that a lane is full or that briefing should stop, and it adds no usage
    throttle of its own. The one count-driven word left is IDLE, for a lane with nothing in flight.

    EVERY NUMBER IS A LANE'S OWN QUOTE. A missing file, an unreadable file, a stale number, a
    superseded number, a roster shortfall -- each is said aloud, never turned into a count.

    THE DISPATCHER WRITES NOTHING THIS HOOK READS. It never reads mail, receipts, dispatch traffic,
    or claim counts to derive occupancy.

    The failure it replaces, measured 2026-08-23: a lane held NINE claims while reporting ONE active
    item and THREE free slots. A claim-counting gauge would have reported both lanes full for the
    entire outage. Both numbers were honest -- only the lane knows which is which.

    IT READS THE WORKTREE THE HOOK INPUT NAMES, NOT THE ONE IT RUNS IN. The desktop app starts a
    worktree session's CLI with `--project-config-root <primary checkout>`. Measured 2026-10-12, a
    hook then runs with its directory, CLAUDE_PROJECT_DIR and `git rev-parse` all naming the PRIMARY.
    This hook tells a builder lane from the dispatcher by its worktree's name and branch, so from the
    primary it would answer for neither. Only the `cwd` field of the JSON on stdin names the worktree,
    so the hook moves there (scripts/hooks/_hookinput.ps1) before its first git call. Input with no
    `cwd` leaves it where it started, as before. After a `cd` it reads the worktree the session
    started in; _hookinput.ps1 says how. A `cwd` it cannot use, with no such worktree to fall back
    to, is reported as a `[lane]` line.
#>
[CmdletBinding()]
param([switch]$SelfTest)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Hardcoded on purpose: a lane with hooks off writes nothing and is invisible to DISCOVERY too, so a
# derived expectation could never notice its absence.
$EXPECTED_LANES = 2
$STALE_TURNS = 6
$STALE_MIN = 30
$LANE_PROMPT_TURNS = 3
$LANE_PROMPT_MIN = 15
$SEAT_DIR_FLOOR = 5

$script:Lines = @()
function Say([string]$t) { $script:Lines += $t }

function Emit {
    if ($script:Lines.Count -gt 0) {
        $text = ($script:Lines -join "`n")
        $p = [pscustomobject]@{ hookSpecificOutput = [pscustomobject]@{
            hookEventName = 'Stop'; additionalContext = $text } }
        [Console]::Out.Write(($p | ConvertTo-Json -Compress -Depth 6))
    }
    exit 0
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return Read-CoordText $Path | ConvertFrom-Json }
    catch { return 'UNREADABLE' }
}

function Get-AgeMin($utc) {
    if (-not $utc) { return $null }
    try { return [math]::Round(([datetime]::UtcNow - ([datetime]::Parse($utc)).ToUniversalTime()).TotalMinutes, 0) }
    catch { return $null }
}

function Format-Age($m) {
    if ($null -eq $m) { return 'never' }
    if ($m -lt 60) { return "${m}m" }
    return "$([math]::Floor($m / 60))h$($m % 60)m"
}

function Test-Has($rec, [string]$name) {
    return ($rec.PSObject.Properties.Name -contains $name)
}

function Get-LaneVerdict($rec, [string]$boxKey) {
    # One state word and one confidence word, or a single non-answer word. A readable level is IDLE
    # when nothing is in flight and STATED otherwise, whatever its numbers: no count makes a lane
    # full. A `capacity` field on an old record is not read, for the same reason.
    $o = [ordered]@{ box = $boxKey; occ = ''; conf = ''; free = $null; inflight = $null
                     ageMin = $null; turns = $null; note = '' }

    if ($null -eq $rec) { $o.occ = 'NO-RECORD'; return [pscustomobject]$o }
    if ($rec -is [string] -and $rec -eq 'UNREADABLE') { $o.occ = 'UNREADABLE'; return [pscustomobject]$o }

    $free = if (Test-Has $rec 'statedFree') { $rec.statedFree } else { $null }
    $inf = if (Test-Has $rec 'statedInFlight') { $rec.statedInFlight } else { $null }
    if (Test-Has $rec 'statedNote') { $o.note = [string]$rec.statedNote }
    if (Test-Has $rec 'turnsSinceStated') { $o.turns = [int]$rec.turnsSinceStated }
    $statedUtc = if (Test-Has $rec 'statedUtc') { $rec.statedUtc } else { $null }
    $o.ageMin = Get-AgeMin $statedUtc

    if (-not $statedUtc) {
        $pc = if (Test-Has $rec 'promptCount') { [int]$rec.promptCount } else { 0 }
        $o.occ = if ($pc -gt 0) { 'NEVER-STATED' } else { 'NO-RECORD' }
        return [pscustomobject]$o
    }
    if ($null -eq $free -or $null -eq $inf) { $o.occ = 'UNREADABLE'; return [pscustomobject]$o }

    $o.free = [int]$free
    $o.inflight = [int]$inf
    $o.occ = if ($o.inflight -eq 0) { 'IDLE' } else { 'STATED' }

    $tipMoved = (Test-Has $rec 'tipNow') -and (Test-Has $rec 'tipAtStated') -and
                $rec.tipNow -and $rec.tipAtStated -and ($rec.tipNow -ne $rec.tipAtStated)
    $claimMoved = (Test-Has $rec 'claimHashNow') -and (Test-Has $rec 'claimHashAtStated') -and
                  $rec.claimHashNow -and $rec.claimHashAtStated -and ($rec.claimHashNow -ne $rec.claimHashAtStated)

    if ($tipMoved -or $claimMoved) { $o.conf = 'SUPERSEDED' }
    elseif (($null -ne $o.turns -and $o.turns -gt $STALE_TURNS) -or
            ($null -ne $o.ageMin -and $o.ageMin -gt $STALE_MIN)) { $o.conf = 'STALE' }
    else { $o.conf = 'FRESH' }

    return [pscustomobject]$o
}

$BLIND = @'
  CANNOT SEE: whether the number is right, whether an item concluded since it was typed, or anything
  about a lane that writes no record. Every number above is a QUOTE from that lane, never a
  measurement, and never derived from claims. A number changes when the LANE RESTATES, not when you
  dispatch. There is no item ceiling, so no count above is a reason to stop briefing.
'@

if ($SelfTest) {
    $fail = @()
    function New-Rec($f, $i, $t1, $t2, $turns) {
        [pscustomobject]@{
            statedFree = $f; statedInFlight = $i
            statedUtc = ([datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ'))
            tipAtStated = $t1; tipNow = $t2; claimHashAtStated = 'a'; claimHashNow = 'a'
            turnsSinceStated = $turns; capacity = 4; statedNote = ''; promptCount = 1 }
    }

    $v = Get-LaneVerdict (New-Rec 3 1 'x' 'x' 0) 'b1'
    if ($v.occ -ne 'STATED' -or $v.free -ne 3 -or $v.inflight -ne 1) { $fail += "3 free / 1 in flight must be STATED 3/1, got $($v.occ) $($v.free)/$($v.inflight)" }

    # The retired ceiling's own case: an old record naming capacity 4, with 0 free and 4 in flight.
    $v = Get-LaneVerdict (New-Rec 0 4 'x' 'x' 0) 'b2'
    if ($v.occ -ne 'STATED' -or $v.conf -ne 'FRESH') { $fail += "0 free / 4 in flight must be STATED FRESH, never full, got $($v.occ)/$($v.conf)" }
    if ($v.PSObject.Properties.Name -contains 'cap') { $fail += 'a verdict must carry no capacity' }

    $v = Get-LaneVerdict $null 'b3'
    if ($v.occ -ne 'NO-RECORD') { $fail += 'a missing record must be NO-RECORD' }

    $v = Get-LaneVerdict 'UNREADABLE' 'b4'
    if ($v.occ -ne 'UNREADABLE') { $fail += 'an unreadable record must be UNREADABLE' }

    $v = Get-LaneVerdict (New-Rec 0 3 'aaa' 'bbb' 0) 'b5'
    if ($v.conf -ne 'SUPERSEDED') { $fail += "a moved tip must be SUPERSEDED, got $($v.conf)" }

    $v = Get-LaneVerdict (New-Rec 0 3 'x' 'x' 99) 'b6'
    if ($v.conf -ne 'STALE') { $fail += "99 turns must be STALE, got $($v.conf)" }

    $v = Get-LaneVerdict (New-Rec 2 $null 'x' 'x' 0) 'b7'
    if ($v.occ -ne 'UNREADABLE') { $fail += "a level with no in-flight count must be UNREADABLE, got $($v.occ)" }

    $v = Get-LaneVerdict (New-Rec 0 0 'x' 'x' 0) 'b8'
    if ($v.occ -ne 'IDLE') { $fail += "0 in flight must be IDLE, got $($v.occ)" }

    if ($fail.Count) { $fail | ForEach-Object { Write-Host "FAIL: $_" }; exit 1 }
    Write-Host 'lane-level self-test: 8 cases pass, and none of them can read a lane as full.'
    exit 0
}

# INTO THE SESSION'S OWN DIRECTORY, BEFORE THE FIRST GIT CALL. See the header. The self-test above
# never gets here, so it still reads no stdin. A missing helper is said aloud, like a bad `cwd`.
$cwdFault = ''
try {
    $hookInput = Join-Path $PSScriptRoot '_hookinput.ps1'
    if (-not (Test-Path -LiteralPath $hookInput -PathType Leaf)) { throw 'scripts/hooks/_hookinput.ps1 is missing beside this hook' }
    . $hookInput
    $cwdFault = (Enter-CcxHookSession -Text (Read-CcxHookInput)).Reason
} catch { $cwdFault = "the hook could not read its input ($($_.Exception.Message))" }
if ($cwdFault) {
    Say "[lane] COULD NOT READ THIS SESSION'S WORKTREE: $cwdFault. What follows describes $((Get-Location).Path), where this hook runs."
}

# SEATS AND LANES BOTH LIVE ON THE SHARED ROOT (docs/COORD-SHARED-ROOT.md), so coord-root.ps1 names
# both directories. It is required, and there is no second copy of its rules here: a local path read
# while a shared root is configured would show this PC's half of the fleet as all of it. This hook
# only reads, so a missing resolver or a root that does not answer is a note and no verdict, never a
# block and never a read of a local copy.
$seatsDir = $null
$lanesDir = $null
$laneFault = ''
$coordRootScript = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\coord-root.ps1'
if (-not (Test-Path -LiteralPath $coordRootScript -PathType Leaf)) {
    $laneFault = 'scripts/coord/coord-root.ps1 is missing'
} else {
    try {
        . $coordRootScript
        $sr = Resolve-CoordSharedRoot -From (Get-Location).Path
        if ($sr.Error) { $laneFault = $sr.Error }
        else {
            $seatsDir = Join-Path $sr.Path 'seats'
            $lanesDir = Join-Path $sr.Path 'lanes'
        }
    } catch { $laneFault = "coord-root.ps1 failed: $($_.Exception.Message)" }
}
if ($laneFault) {
    Say "[lane] SKIPPED: the coordination root did not resolve ($laneFault). NO VERDICT, and this is NOT"
    Say "  'both lanes are fine' -- nothing was examined."
    Emit
}
. (Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\mail-key.ps1')
function Read-LaneFor([string]$Worktree, [string]$HostName) {
    # A lane file is named by the box key, which hashes the host as well as the path (mail-key.ps1),
    # so the record at that key is this tree's. Failing that, the old path-only key, which a copy of
    # lane.ps1 older than the change still writes (it runs from each worktree's branch, while this
    # hook runs from the primary). Every PC at this path shares that old name, so a record there counts
    # only when its host is this tree's host. No host means this machine, as everywhere. When both
    # files are readable, the one with the fresher stated level wins: a `lane.ps1 -Asked` on the new
    # key writes no number and must not hide a level stated on the old one.
    $rec = Read-Json (Join-Path $lanesDir "$(ConvertTo-BoxKey -Path $Worktree -HostName $HostName).json")
    $old = Read-Json (Join-Path $lanesDir "$(ConvertTo-LegacyBoxKey -Path $Worktree).json")
    if ($null -ne $old -and $old -isnot [string]) {
        $oldHost = Get-CoordRecordHost $old
        if (-not $oldHost) { $oldHost = Get-CoordHost }
        if ($oldHost -ine $HostName) { $old = $null }
    }
    if ($null -eq $rec) { return $old }
    if ($null -eq $old -or $old -is [string] -or $rec -is [string]) { return $rec }
    $newAge = if (Test-Has $rec 'statedUtc') { Get-AgeMin $rec.statedUtc } else { $null }
    $oldAge = if (Test-Has $old 'statedUtc') { Get-AgeMin $old.statedUtc } else { $null }
    if ($null -ne $oldAge -and ($null -eq $newAge -or $oldAge -lt $newAge)) { return $old }
    return $rec
}
$cwd = (Get-Location).Path
$leaf = (Split-Path $cwd -Leaf)
$branch = (& git rev-parse --abbrev-ref HEAD 2>$null)

if ($leaf -match '^builder') {
    $rec = Read-LaneFor $cwd (Get-CoordHost)
    $need = ($null -eq $rec) -or ($rec -is [string])
    if (-not $need) {
        $t = if (Test-Has $rec 'turnsSinceStated') { [int]$rec.turnsSinceStated } else { 99 }
        $a = Get-AgeMin $rec.statedUtc
        $need = (-not $rec.statedUtc) -or ($t -ge $LANE_PROMPT_TURNS) -or ($null -ne $a -and $a -ge $LANE_PROMPT_MIN)
    }
    if ($need) {
        Say '[lane] Your lane level is unstated or stale. State it now, it takes five seconds:'
        Say '  pwsh -NoProfile -File scripts\coord\lane.ps1 -Free <n> -InFlight <n> -Note "<what is moving>"'
        Say '  FREE MEANS BY WORK, NOT BY CLAIMS. Built-and-awaiting-land is FREE. Blocked is FREE.'
        Say '  Parked on a condition is FREE. There is no item ceiling, so count no empty slots.'
        Say '  Nobody else can write this number for you.'
    }
    Emit
}

if (-not (($leaf -match '^dispatcher') -or ($branch -match 'dispatcher'))) { Emit }

if (-not (Test-Path -LiteralPath $seatsDir)) {
    Say '[lane] INSTRUMENT ERROR: seats\ is absent, so no lane could be discovered. NO VERDICT, and'
    Say '  this is NOT a pass -- nothing was examined.'
    Emit
}
$seatDirs = @(Get-ChildItem -LiteralPath $seatsDir -Directory -ErrorAction SilentlyContinue)
if ($seatDirs.Count -lt $SEAT_DIR_FLOOR) {
    Say "[lane] INSTRUMENT ERROR: seats\ resolved $($seatDirs.Count) record dirs against a floor of $SEAT_DIR_FLOOR,"
    Say "  so the coordination root did not resolve. NO VERDICT, and this is NOT 'both lanes are fine'."
    Emit
}

# PASS 1: each seat directory's newest record, keyed by the box its tree and host have now
# (mail-key.ps1), so the same path on two PCs is two lanes. A tree that crossed the box-key change has
# two directories, the old path-only one and the new one, and only the NEWER of the two speaks for it:
# filtering first would let a frozen, still-open legacy record stand in for a seat that has since
# closed or re-declared in its new box. seatBox is the directory the record was found in; the
# activity check reads its heartbeat there.
$cands = @()
foreach ($d in $seatDirs) {
    $newest = Get-ChildItem -LiteralPath $d.FullName -Filter *.json -File -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (-not $newest) { continue }
    $s = Read-Json $newest.FullName
    if ($null -eq $s -or $s -is [string]) { continue }
    $wt = if (Test-Has $s 'worktree') { [string]$s.worktree } else { '' }
    if (-not $wt) { continue }
    $laneHost = Get-CoordRecordHost $s
    if (-not $laneHost) { $laneHost = Get-CoordHost }
    # A worktree that does not normalise to a path names no key, and no lane.
    try { $laneBox = ConvertTo-BoxKey -Path $wt -HostName $laneHost } catch { continue }
    $cands += [pscustomobject]@{
        box = $laneBox; seatBox = $d.Name; worktree = $wt; host = $laneHost
        at = $newest.LastWriteTimeUtc; rec = $s
    }
}
$cands = @($cands | Sort-Object at -Descending | Group-Object box | ForEach-Object { $_.Group | Select-Object -First 1 })

# PASS 2: is that newest record a live builder lane?
$lanes = @()
foreach ($c in $cands) {
    $s = $c.rec
    $wt = $c.worktree
    $seat = if (Test-Has $s 'seat') { [string]$s.seat } else { '' }
    $life = if (Test-Has $s 'lifecycle') { [string]$s.lifecycle } else { '' }
    # MATCH ON THE DECLARED SEAT ONLY, NEVER ON THE WORKTREE NAME. Measured 2026-08-23: the CLEANER
    # was sitting in a worktree whose name begins `builder-handoff-seat`, so a name match calls it a
    # builder lane. A worktree name is a creation-time label and nothing keeps it true.
    if ($seat -notmatch '^\s*build') { continue }
    if ($life -eq 'closed') { continue }
    if (-not (Test-Path -LiteralPath $wt)) { continue }
    # RECENCY, and the roster count below is what makes this safe. A seat record is stamped every turn,
    # so a lane silent for hours is one nobody is dispatching to. Measured today the live lanes sat at
    # 0.1h and 0.2h and the next candidate at 10.2h -- a real gap, not a threshold fitted to noise.
    # If this ever DROPS a live lane, `discovered` falls below `expected` and the ROSTER DRIFT block
    # fires. Narrowing can therefore cost noise; it can never hide a lane silently.
    if (((([datetime]::UtcNow) - $c.at).TotalHours) -gt 6) { continue }
    $lanes += $c
}

# RETIRE THE DEAD ONES WITH A REAL LIVENESS CALL, NOT A NAME MATCH. Measured 2026-08-23 without this
# step: 12 "lanes" discovered against 2 live, every one printing three lines of NO-RECORD. That is the
# noise failure -- a gauge nobody reads is identical to one that is switched off.
#
# THE ASYMMETRY IS THE WHOLE POINT: a lane is dropped ONLY when the call is Evaluable AND says dead.
# When Evaluable is false the lane is KEPT and marked LIVENESS-UNKNOWN, which speaks. An unevaluated
# fence is not a passed fence, so doubt can shrink the noise but can never hide a lane silently.
$live = @()
$unknown = @()
try {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\box-activity.ps1')
    $deadline = [datetime]::UtcNow.AddSeconds(6)
    foreach ($l in $lanes) {
        if ([datetime]::UtcNow -gt $deadline) { $unknown += $l; continue }
        try {
            $a = Get-BoxActivity -BoxKey $l.seatBox -WorktreePath $l.worktree -SeatsDir $seatsDir
            if (-not $a.Evaluable) { $unknown += $l; $live += $l }
            elseif ($a.Veto) { $live += $l }
        } catch { $unknown += $l; $live += $l }
    }
} catch {
    # The helper itself did not load. Keep every candidate rather than silently narrowing.
    $live = $lanes; $unknown = $lanes
}
$lanes = @($live | Group-Object box | ForEach-Object { $_.Group | Select-Object -First 1 })
$unknownBoxes = @($unknown | ForEach-Object { $_.box })

$verdicts = @()
foreach ($l in $lanes) { $verdicts += Get-LaneVerdict (Read-LaneFor $l.worktree $l.host) $l.box }

$discovered = $verdicts.Count
$unknownLive = @($verdicts | Where-Object { $unknownBoxes -contains $_.box }).Count

# NO VERDICT OF FULLNESS, AND NO SILENCE BOUGHT BY ONE. There is no item ceiling (see the header), so
# the counts are reported as quoted and the hook speaks on every dispatcher turn.
Say "[lane] $discovered LANES, EACH NUMBER BY ITS OWN STATEMENT. There is no item ceiling."
foreach ($v in ($verdicts | Sort-Object box)) {
    $lbl = ("$($v.occ) $($v.conf)").Trim()
    $pad = '{0,-28} {1,-20}' -f $v.box, $lbl
    switch ($v.occ) {
        'NO-RECORD' {
            Say "  $pad never wrote a level, and its own hook never prompted it"
            Say ('  {0,-28} {1,-20} either. That points at the HOOK, not the lane. Nothing is' -f '', '')
            Say ('  {0,-28} {1,-20} known here, not even zero.' -f '', '') }
        'NEVER-STATED' {
            Say "  $pad prompted on its own turns and never answered. The hook runs"
            Say ('  {0,-28} {1,-20} there; the number is not coming. Ask the lane directly.' -f '', '') }
        'UNREADABLE' {
            Say "  $pad its level file did not parse. NO verdict for this lane, and"
            Say ('  {0,-28} {1,-20} this is NOT a pass.' -f '', '') }
        default {
            $n = if ($v.note) { " Note: `"$($v.note)`"" } else { '' }
            Say "  $pad $($v.inflight) in flight, $($v.free) free by work, stated $(Format-Age $v.ageMin) and $($v.turns) lane-turns ago.$n" }
    }
    if ($v.conf -eq 'SUPERSEDED') {
        Say ('  {0,-28} {1,-20} that lane has committed or changed claims since it stated' -f '', '')
        Say ('  {0,-28} {1,-20} that number, so the number is NOT current. Ask it.' -f '', '') }
    if ($v.conf -eq 'STALE') { Say ('  {0,-28} {1,-20} STALE: the number may no longer hold. Ask it.' -f '', '') }
    if ($unknownBoxes -contains $v.box) {
        Say ('  {0,-28} {1,-20} LIVENESS-UNKNOWN: too few activity signals could be read, so I' -f '', '')
        Say ('  {0,-28} {1,-20} cannot say this lane is alive. An unevaluated fence is not a' -f '', '')
        Say ('  {0,-28} {1,-20} passed one, and any level above may be from a session that is gone.' -f '', '') }
}
Say "  coverage: $discovered lanes discovered, at least $EXPECTED_LANES expected, $unknownLive with liveness unknown."
# A FLOOR, NOT A CAP. A shortfall is what a lane invisible to discovery looks like. More lanes than
# that is ordinary at full speed and says nothing about a missing one.
if ($discovered -lt $EXPECTED_LANES) {
    Say '  ROSTER DRIFT: a lane with every hook off writes no seat record and no level, so it is'
    Say "  invisible to discovery too. Do not read '$discovered of $discovered' as healthy."
}
Say $BLIND
Emit
