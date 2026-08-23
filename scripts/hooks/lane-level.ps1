# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Stop hook. In a builder session it nags that lane for its own free-slot count. In the dispatcher
    session it reports those counts and speaks whenever it cannot prove both lanes are full.

.DESCRIPTION
    THE STRUCTURAL PROPERTY, AND EVERYTHING ELSE IS DETAIL: every input is either a lane's own
    assertion of fullness, or an invalidator of one. NOTHING TURNS "UNKNOWN" INTO "FULL". A missing
    file, an unreadable file, a stale number, a superseded number, a roster shortfall -- all of them
    SPEAK. Silence is reachable only through a lane's own fresh statement.

    THAT IS WHY IT SURVIVES A DISPATCHER WITH NO DISCIPLINE: THE DISPATCHER WRITES NOTHING THIS HOOK
    READS. It never reads mail, receipts, dispatch traffic, or claim counts to derive occupancy.

    The failure it replaces, measured 2026-08-23: a lane held NINE claims while reporting ONE active
    item and THREE free slots. A claim-counting gauge would have reported both lanes full for the
    entire outage. Both numbers were honest -- only the lane knows which is which.
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
$SERIAL_MIN_INFLIGHT = 2
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

function Get-CoordRoot {
    $c = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $c) { return $null }
    return (Join-Path $c.Trim() 'mefor-coord')
}

function Read-Json([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    try { return Get-Content -LiteralPath $Path -Raw -Encoding UTF8 | ConvertFrom-Json }
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
    # One occupancy word and one confidence word, or a single non-answer word. `greenable` is the ONLY
    # thing the caller may use to stay quiet, and it is set in exactly one place.
    $o = [ordered]@{ box = $boxKey; occ = ''; conf = ''; free = $null; inflight = $null
                     cap = 4; ageMin = $null; turns = $null; note = ''; greenable = $false }

    if ($null -eq $rec) { $o.occ = 'NO-RECORD'; return [pscustomobject]$o }
    if ($rec -is [string] -and $rec -eq 'UNREADABLE') { $o.occ = 'UNREADABLE'; return [pscustomobject]$o }

    $free = if (Test-Has $rec 'statedFree') { $rec.statedFree } else { $null }
    $inf = if (Test-Has $rec 'statedInFlight') { $rec.statedInFlight } else { $null }
    if ((Test-Has $rec 'capacity') -and $rec.capacity) { $o.cap = [int]$rec.capacity }
    if (Test-Has $rec 'statedNote') { $o.note = [string]$rec.statedNote }
    if (Test-Has $rec 'turnsSinceStated') { $o.turns = [int]$rec.turnsSinceStated }
    $statedUtc = if (Test-Has $rec 'statedUtc') { $rec.statedUtc } else { $null }
    $o.ageMin = Get-AgeMin $statedUtc

    if (-not $statedUtc) {
        $pc = if (Test-Has $rec 'promptCount') { [int]$rec.promptCount } else { 0 }
        $o.occ = if ($pc -gt 0) { 'NEVER-STATED' } else { 'NO-RECORD' }
        return [pscustomobject]$o
    }
    if ($null -eq $free) { $o.occ = 'UNREADABLE'; return [pscustomobject]$o }

    $o.free = [int]$free
    if ($null -ne $inf) { $o.inflight = [int]$inf }

    if ($o.free -gt 0) {
        $o.occ = 'OPEN'
    } elseif ($null -eq $o.inflight) {
        $o.occ = 'UNREADABLE'; return [pscustomobject]$o
    } elseif ($o.inflight -lt $SERIAL_MIN_INFLIGHT) {
        $o.occ = 'SERIAL'
    } else {
        $o.occ = 'AT-CAPACITY'
    }

    $tipMoved = (Test-Has $rec 'tipNow') -and (Test-Has $rec 'tipAtStated') -and
                $rec.tipNow -and $rec.tipAtStated -and ($rec.tipNow -ne $rec.tipAtStated)
    $claimMoved = (Test-Has $rec 'claimHashNow') -and (Test-Has $rec 'claimHashAtStated') -and
                  $rec.claimHashNow -and $rec.claimHashAtStated -and ($rec.claimHashNow -ne $rec.claimHashAtStated)

    if ($tipMoved -or $claimMoved) { $o.conf = 'SUPERSEDED' }
    elseif (($null -ne $o.turns -and $o.turns -gt $STALE_TURNS) -or
            ($null -ne $o.ageMin -and $o.ageMin -gt $STALE_MIN)) { $o.conf = 'STALE' }
    else { $o.conf = 'FRESH' }

    $o.greenable = ($o.occ -eq 'AT-CAPACITY' -and $o.conf -eq 'FRESH')
    return [pscustomobject]$o
}

$BLIND = @'
  CANNOT SEE: whether the number is right, whether an item concluded since it was typed, whether a hold
  makes those slots undispatchable, or anything about a lane that writes no record. Every number above
  is a QUOTE from that lane, never a measurement, and never derived from claims. OPEN clears when the
  LANE RESTATES, not when you dispatch -- if you dispatched and OPEN persists, that lane has not taken
  a turn yet.
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
    if ($v.occ -ne 'OPEN') { $fail += "3 free must be OPEN, got $($v.occ)" }
    if ($v.greenable) { $fail += 'an OPEN lane must never be greenable' }

    $v = Get-LaneVerdict (New-Rec 0 3 'x' 'x' 0) 'b2'
    if (-not $v.greenable) { $fail += "0 free / 3 in flight fresh must be greenable, got $($v.occ)/$($v.conf)" }

    $v = Get-LaneVerdict $null 'b3'
    if ($v.occ -ne 'NO-RECORD' -or $v.greenable) { $fail += 'a missing record must be NO-RECORD and never greenable' }

    $v = Get-LaneVerdict 'UNREADABLE' 'b4'
    if ($v.occ -ne 'UNREADABLE' -or $v.greenable) { $fail += 'an unreadable record must never be greenable' }

    $v = Get-LaneVerdict (New-Rec 0 3 'aaa' 'bbb' 0) 'b5'
    if ($v.conf -ne 'SUPERSEDED' -or $v.greenable) { $fail += "a moved tip must be SUPERSEDED, got $($v.conf)" }

    $v = Get-LaneVerdict (New-Rec 0 3 'x' 'x' 99) 'b6'
    if ($v.conf -ne 'STALE' -or $v.greenable) { $fail += "99 turns must be STALE, got $($v.conf)" }

    $v = Get-LaneVerdict (New-Rec 0 1 'x' 'x' 0) 'b7'
    if ($v.occ -ne 'SERIAL' -or $v.greenable) { $fail += "0 free / 1 in flight must be SERIAL, got $($v.occ)" }

    if ($fail.Count) { $fail | ForEach-Object { Write-Host "FAIL: $_" }; exit 1 }
    Write-Host 'lane-level self-test: 7 assertions pass, 6 of them asserting a state that must NOT be greenable.'
    exit 0
}

$coord = Get-CoordRoot
if (-not $coord -or -not (Test-Path -LiteralPath $coord)) {
    Say '[lane] INSTRUMENT ERROR: the coordination root did not resolve. NO VERDICT BELOW, and this is'
    Say "  NOT 'both lanes are fine' -- nothing was examined."
    Emit
}
$seatsDir = Join-Path $coord 'seats'
$lanesDir = Join-Path $coord 'lanes'
$cwd = (Get-Location).Path
$leaf = (Split-Path $cwd -Leaf)
$branch = (& git rev-parse --abbrev-ref HEAD 2>$null)

if ($leaf -match '^builder') {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\mail-key.ps1')
    $bk = ConvertTo-BoxKey -Path $cwd
    $rec = Read-Json (Join-Path $lanesDir "$bk.json")
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
        Say '  Parked on a condition is FREE. Nobody else can write this number for you.'
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

$lanes = @()
foreach ($d in $seatDirs) {
    $newest = Get-ChildItem -LiteralPath $d.FullName -Filter *.json -File -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1
    if (-not $newest) { continue }
    $s = Read-Json $newest.FullName
    if ($null -eq $s -or $s -is [string]) { continue }
    $seat = if (Test-Has $s 'seat') { [string]$s.seat } else { '' }
    $wt = if (Test-Has $s 'worktree') { [string]$s.worktree } else { '' }
    $life = if (Test-Has $s 'lifecycle') { [string]$s.lifecycle } else { '' }
    # MATCH ON THE DECLARED SEAT ONLY, NEVER ON THE WORKTREE NAME. Measured 2026-08-23: the CLEANER
    # was sitting in a worktree whose name begins `builder-handoff-seat`, so a name match calls it a
    # builder lane. A worktree name is a creation-time label and nothing keeps it true.
    if ($seat -notmatch '^\s*build') { continue }
    if ($life -eq 'closed') { continue }
    if (-not $wt -or -not (Test-Path -LiteralPath $wt)) { continue }
    # RECENCY, and the roster count below is what makes this safe. A seat record is stamped every turn,
    # so a lane silent for hours is one nobody is dispatching to. Measured today the live lanes sat at
    # 0.1h and 0.2h and the next candidate at 10.2h -- a real gap, not a threshold fitted to noise.
    # If this ever DROPS a live lane, `discovered` falls below `expected` and the ROSTER DRIFT block
    # fires. Narrowing can therefore cost noise; it can never manufacture a green.
    if (((([datetime]::UtcNow) - $newest.LastWriteTimeUtc).TotalHours) -gt 6) { continue }
    $lanes += [pscustomobject]@{ box = $d.Name; worktree = $wt }
}
$lanes = @($lanes | Group-Object worktree | ForEach-Object { $_.Group | Select-Object -First 1 })

# RETIRE THE DEAD ONES WITH A REAL LIVENESS CALL, NOT A NAME MATCH. Measured 2026-08-23 without this
# step: 12 "lanes" discovered against 2 live, every one printing three lines of NO-RECORD. That is the
# noise failure -- a gauge nobody reads is identical to one that is switched off.
#
# THE ASYMMETRY IS THE WHOLE POINT: a lane is dropped ONLY when the call is Evaluable AND says dead.
# When Evaluable is false the lane is KEPT and marked LIVENESS-UNKNOWN, which speaks. An unevaluated
# fence is not a passed fence, so doubt can shrink the noise but can never manufacture a green.
$live = @()
$unknown = @()
try {
    . (Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\box-activity.ps1')
    $deadline = [datetime]::UtcNow.AddSeconds(6)
    foreach ($l in $lanes) {
        if ([datetime]::UtcNow -gt $deadline) { $unknown += $l; continue }
        try {
            $a = Get-BoxActivity -BoxKey $l.box -WorktreePath $l.worktree -SeatsDir $seatsDir
            if (-not $a.Evaluable) { $unknown += $l; $live += $l }
            elseif ($a.Veto) { $live += $l }
        } catch { $unknown += $l; $live += $l }
    }
} catch {
    # The helper itself did not load. Keep every candidate rather than silently narrowing.
    $live = $lanes; $unknown = $lanes
}
$lanes = @($live | Group-Object worktree | ForEach-Object { $_.Group | Select-Object -First 1 })
$unknownBoxes = @($unknown | ForEach-Object { $_.box })

$verdicts = @()
foreach ($l in $lanes) { $verdicts += Get-LaneVerdict (Read-Json (Join-Path $lanesDir "$($l.box).json")) $l.box }

$discovered = $verdicts.Count
$notGreen = @($verdicts | Where-Object { -not $_.greenable }).Count
$unknownLive = @($verdicts | Where-Object { $unknownBoxes -contains $_.box }).Count
# A lane whose liveness could not be evaluated blocks green even if it states itself full: the
# statement may be from a session that is gone.
$green = ($discovered -eq $EXPECTED_LANES) -and ($discovered -gt 0) -and ($notGreen -eq 0) -and ($unknownLive -eq 0)

if ($green) {
    $bits = ($verdicts | ForEach-Object {
        "$($_.box) $($_.free) free / $($_.inflight) in flight of $($_.cap) (stated $(Format-Age $_.ageMin) ago)" }) -join ' | '
    Say "[lane] BOTH LANES AT CAPACITY BY THEIR OWN STATEMENT: $bits. Quoted, not measured."
    Emit
}

$below = @($verdicts | Where-Object { $_.occ -ne 'AT-CAPACITY' }).Count
Say "[lane] $below of $discovered LANES BELOW CAPACITY BY THEIR OWN STATEMENT."
foreach ($v in ($verdicts | Sort-Object box)) {
    $lbl = ("$($v.occ) $($v.conf)").Trim()
    $pad = '{0,-28} {1,-20}' -f $v.box, $lbl
    switch ($v.occ) {
        'NO-RECORD' {
            Say "  $pad never wrote a level, and its own hook never prompted it"
            Say ('  {0,-28} {1,-20} either. That points at the HOOK, not the lane. Nothing is' -f '', '')
            Say ('  {0,-28} {1,-20} known here: not zero, and not full.' -f '', '') }
        'NEVER-STATED' {
            Say "  $pad prompted on its own turns and never answered. The hook runs"
            Say ('  {0,-28} {1,-20} there; the number is not coming. Ask the lane directly.' -f '', '') }
        'UNREADABLE' {
            Say "  $pad its level file did not parse. NO verdict for this lane, and"
            Say ('  {0,-28} {1,-20} this is NOT a pass.' -f '', '') }
        'SERIAL' {
            Say "  $pad $($v.free) free / $($v.inflight) in flight of $($v.cap), stated $(Format-Age $v.ageMin) ago."
            Say ('  {0,-28} {1,-20} OCCUPANCY CANNOT SEE A SERIAL LANE -- it reads as full.' -f '', '') }
        default {
            $n = if ($v.note) { " Note: `"$($v.note)`"" } else { '' }
            Say "  $pad $($v.free) free / $($v.inflight) in flight of $($v.cap), stated $(Format-Age $v.ageMin) and $($v.turns) lane-turns ago.$n" }
    }
    if ($v.conf -eq 'SUPERSEDED') {
        Say ('  {0,-28} {1,-20} that lane has committed or changed claims since it stated' -f '', '')
        Say ('  {0,-28} {1,-20} that number, so the number is NOT current. Ask it.' -f '', '') }
    if ($v.conf -eq 'STALE') { Say ('  {0,-28} {1,-20} STALE IS NOT FULL.' -f '', '') }
    if ($unknownBoxes -contains $v.box) {
        Say ('  {0,-28} {1,-20} LIVENESS-UNKNOWN: too few activity signals could be read, so I' -f '', '')
        Say ('  {0,-28} {1,-20} cannot say this lane is alive. An unevaluated fence is not a' -f '', '')
        Say ('  {0,-28} {1,-20} passed one, and any level above may be from a session that is gone.' -f '', '') }
}
Say "  coverage: $discovered lanes discovered, $EXPECTED_LANES expected, $unknownLive with liveness unknown."
if ($discovered -ne $EXPECTED_LANES) {
    Say '  ROSTER DRIFT: a lane with every hook off writes no seat record and no level, so it is'
    Say "  invisible to discovery too. Do not read '$discovered of $discovered' as healthy."
}
Say $BLIND
Emit
