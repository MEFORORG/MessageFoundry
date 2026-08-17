# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    What the account's plan limits are doing, and whether a session is about to be cut off.

.DESCRIPTION
    Reads what `usage-collect.ps1` publishes from the Claude Code statusLine (see that file for why the
    statusLine is the only source). Adds the two things a raw reading cannot give you: a BURN RATE, and
    the only question that actually matters operationally -- WILL THIS WINDOW RUN OUT BEFORE IT RESETS?

    A percentage on its own does not answer that. 80% with two hours left and nothing running is fine;
    45% with 30 minutes left and six sessions compiling is not.

    THREE HONESTY RULES, because a usage tool that is confidently wrong is worse than no usage tool --
    it converts "I should check" into "I already know".

      1. NO PERCENTAGE WITHOUT ITS AGE. Every number is printed with how long ago it was observed.
         Windows are aged INDEPENDENTLY, because they are published independently.
      2. REFUSE TO PROJECT ON STALE OR THIN DATA. Below two fresh samples in the current window, or past
         -MaxAgeMinutes, the answer is UNKNOWN. Not an extrapolation, not a last-known value dressed up
         as current.
      3. NAME WHAT IS NOT MEASURED -- AND DO NOT OVERSTATE IT EITHER. The model-scoped weekly bucket
         (the "Weekly / Fable" bar) and the plan tier are not in the statusLine payload. Opus and
         Sonnet are NOT gaps: they have no separate bucket and draw on "All models", which is the
         `seven_day` window read here, so Opus work is fully covered. An earlier draft warned about an
         invisible Opus bucket that does not exist -- a false blind spot is its own failure, because a
         session told its headroom is unknowable stops trusting a reading that was accurate.

    EXIT CODES, so a coordinator can branch without parsing prose:
        0  OK
        10 WARN     -- high, or projected to exhaust before reset with slack
        11 CRITICAL -- projected to exhaust before reset, or already at the ceiling
        20 UNKNOWN  -- no data, stale data, or not enough samples to say

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\usage.ps1
    pwsh -NoProfile -File scripts\coord\usage.ps1 -Json
#>
[CmdletBinding()]
param(
    [string]$StateDir = (Join-Path $env:USERPROFILE ".claude\mefor-usage"),
    # Machine-readable, for the coordinator.
    [switch]$Json,
    # Older than this and a reading is reported but NOT projected from.
    [int]$MaxAgeMinutes = 20,
    # Rate is measured over at most this much recent history.
    [int]$RateWindowMinutes = 90
)

$ErrorActionPreference = "SilentlyContinue"

$latestPath = Join-Path $StateDir "latest.json"
$histPath = Join-Path $StateDir "history.jsonl"

$doc = $null
try { $doc = Get-Content -LiteralPath $latestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { }

if (-not $doc) {
    $msg = "NO USAGE DATA. Nothing has published to $latestPath."
    $fix = "The statusLine collector is not installed or has not run yet. Install it (owner, plain terminal):`n    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1`nIt only runs in an INTERACTIVE session -- never under 'claude -p' or the SDK."
    if ($Json) { @{ state = "UNKNOWN"; reason = "no data"; path = $latestPath } | ConvertTo-Json -Compress | Write-Output }
    else { Write-Host ""; Write-Host $msg -ForegroundColor Yellow; Write-Host $fix; Write-Host "" }
    exit 20
}

$nowUtc = (Get-Date).ToUniversalTime()

function Get-AgeMinutes($v) {
    if (-not $v) { return $null }
    # DO NOT STRINGIFY THIS VALUE. ConvertFrom-Json has ALREADY coerced the ISO-8601 field into a
    # [datetime] with Kind=Utc (verified, not assumed). Rendering it back to a string drops the 'Z',
    # and re-parsing a Z-less string assumes LOCAL -- which added this machine's UTC-5 offset and
    # reported a reading taken 90 seconds earlier as 299 minutes in the FUTURE.
    #
    # The sign is what made it dangerous rather than merely wrong: a negative age passes an
    # `age -gt max` staleness test unconditionally, so the guard against a dead publisher would have
    # been disarmed on every non-UTC machine while still looking present. Same ConvertFrom-Json date
    # coercion that silently downgraded the stamp in claim.ps1; it is worth expecting now.
    $t = $null
    if ($v -is [datetime]) {
        $t = switch ($v.Kind) {
            ([System.DateTimeKind]::Utc) { $v }
            ([System.DateTimeKind]::Local) { $v.ToUniversalTime() }
            default { [datetime]::SpecifyKind($v, [System.DateTimeKind]::Utc) }  # we only ever write UTC
        }
    }
    elseif ($v -is [datetimeoffset]) { $t = $v.UtcDateTime }
    else { try { $t = [System.DateTimeOffset]::Parse([string]$v).UtcDateTime } catch { return $null } }
    return [math]::Round(($nowUtc - $t).TotalMinutes, 1)
}

# --- burn rate ------------------------------------------------------------------------------------
#
# ONLY WITHIN ONE WINDOW EPOCH. When a window resets, the percentage falls off a cliff (90 -> 0). A rate
# computed across that boundary is a large NEGATIVE number, which would read as "consumption has stopped"
# at the exact moment a fresh window starts being spent. Rows are therefore grouped by their reset epoch
# and only rows sharing the CURRENT epoch are used.
function Get-Rate([string]$Key, [string]$ResetKey, $CurrentResetEpoch) {
    if (-not (Test-Path -LiteralPath $histPath)) { return $null }
    $rows = @()
    try {
        foreach ($line in (Get-Content -LiteralPath $histPath -Tail 400 -ErrorAction Stop)) {
            try { $r = $line | ConvertFrom-Json -ErrorAction Stop } catch { continue }
            if ($null -eq $r.$Key) { continue }                       # carried-forward or absent: not an observation
            if ($CurrentResetEpoch -and ($r.$ResetKey -ne $CurrentResetEpoch)) { continue }  # a previous window
            $age = Get-AgeMinutes $r.at
            if ($null -eq $age -or $age -gt $RateWindowMinutes) { continue }
            $rows += [pscustomobject]@{ AgeMin = $age; Pct = [double]$r.$Key }
        }
    } catch { return $null }
    if ($rows.Count -lt 2) { return $null }                            # one point is a reading, not a rate
    $oldest = $rows | Sort-Object AgeMin -Descending | Select-Object -First 1
    $newest = $rows | Sort-Object AgeMin | Select-Object -First 1
    $spanH = ($oldest.AgeMin - $newest.AgeMin) / 60.0
    if ($spanH -le 0) { return $null }
    $delta = $newest.Pct - $oldest.Pct
    return [pscustomobject]@{
        PctPerHour = [math]::Round($delta / $spanH, 2)
        Samples    = $rows.Count
        SpanMin    = [math]::Round($oldest.AgeMin - $newest.AgeMin, 1)
    }
}

function Get-WindowReport($w, [string]$Label, [string]$Key, [string]$ResetKey) {
    if (-not $w) {
        return [ordered]@{ label = $Label; state = "UNKNOWN"; reason = "never published"; used_percentage = $null }
    }
    $age = Get-AgeMinutes $w.captured_at
    $pct = [double]$w.used_percentage
    $resetEpoch = $w.resets_at_epoch
    $minsToReset = $null
    if ($resetEpoch) {
        try { $minsToReset = [math]::Round(([System.DateTimeOffset]::FromUnixTimeSeconds([long]$resetEpoch) - [System.DateTimeOffset]::UtcNow).TotalMinutes, 0) } catch { }
    }

    $o = [ordered]@{
        label            = $Label
        used_percentage  = $pct
        reading_age_min  = $age
        resets_at        = $w.resets_at
        minutes_to_reset = $minsToReset
        rate_pct_per_hr  = $null
        projected_at_reset = $null
        minutes_to_empty = $null
        state            = "OK"
        reason           = ""
    }

    # RULE 2: stale readings are reported, never projected from.
    #
    # The lower bound is not defensive tidying. An age is a subtraction of two clocks, and any bug or skew
    # that makes it negative would pass an `age -gt max` test unconditionally -- the staleness guard would
    # then be permanently disarmed while looking present. Bound it BOTH ways so a nonsensical age is
    # reported as nonsense rather than silently accepted as fresh.
    if ($null -eq $age -or $age -gt $MaxAgeMinutes -or $age -lt -2) {
        $o.state = "UNKNOWN"
        $o.reason = if ($null -eq $age) { "reading is undateable" }
        elseif ($age -lt -2) { "reading is dated $([math]::Abs($age)) min in the FUTURE -- clock skew or a bad timestamp; refusing to trust it" }
        else { "reading is $age min old (max $MaxAgeMinutes) -- no live session is publishing" }
        return $o
    }

    $rate = Get-Rate -Key $Key -ResetKey $ResetKey -CurrentResetEpoch $resetEpoch
    if ($rate) {
        $o.rate_pct_per_hr = $rate.PctPerHour
        if ($null -ne $minsToReset -and $minsToReset -gt 0) {
            $o.projected_at_reset = [math]::Round([math]::Min(100.0, $pct + $rate.PctPerHour * ($minsToReset / 60.0)), 1)
        }
        if ($rate.PctPerHour -gt 0) {
            $o.minutes_to_empty = [math]::Round((100.0 - $pct) / $rate.PctPerHour * 60.0, 0)
        }
    }
    else {
        $o.reason = "not enough samples in this window for a rate"
    }

    # Bands. The question is not "is the number big" but "does it run out before it resets".
    if ($pct -ge 98) { $o.state = "CRITICAL"; $o.reason = "at the ceiling" }
    elseif ($null -ne $o.minutes_to_empty -and $null -ne $minsToReset -and $o.minutes_to_empty -lt $minsToReset) {
        $o.state = "CRITICAL"
        $o.reason = "projected to hit 100% in ~$($o.minutes_to_empty) min, $minsToReset min before this window resets"
    }
    elseif ($pct -ge 85) { $o.state = "WARN"; $o.reason = "high, but not projected to run out before reset" }
    elseif ($null -ne $o.projected_at_reset -and $o.projected_at_reset -ge 95) {
        $o.state = "WARN"; $o.reason = "projected to reach $($o.projected_at_reset)% by reset"
    }
    return $o
}

$five = Get-WindowReport $doc.five_hour "session (5h)" "five_hour" "five_reset"
$seven = Get-WindowReport $doc.seven_day "weekly (7d)" "seven_day" "seven_reset"

$rank = @{ "OK" = 0; "WARN" = 10; "CRITICAL" = 11; "UNKNOWN" = 20 }
$states = @($five.state, $seven.state)
# CRITICAL outranks UNKNOWN: a known emergency in one window is not softened by the other being unknown.
$overall = if ($states -contains "CRITICAL") { "CRITICAL" }
elseif ($states -contains "WARN") { "WARN" }
elseif ($states -contains "UNKNOWN") { "UNKNOWN" }
else { "OK" }

# RULE 3, and the guidance is an ACTION. This repo has already learned that "don't do X" is the wrong
# primitive when automation has X armed -- see docs/WORKTREES.md. "Commit and hand off" is something a
# session can DO; "be careful" is not.
$advice = switch ($overall) {
    "CRITICAL" { "COMMIT NOW and write your handoff. Assume you may be cut off mid-task. Do not start anything you cannot finish or hand over in the time above." }
    "WARN" { "Commit at your next logical stop and keep your handoff current, so a cutoff costs nothing." }
    "UNKNOWN" { "Treat headroom as UNKNOWN, not as fine. Commit at logical stops anyway; that is the behaviour that makes a cutoff survivable regardless of the number." }
    default { "Normal working. Commit at logical stops as usual." }
}

$blindSpot = "NOT MEASURED: the model-scoped weekly bucket (Fable) and the plan tier are absent from the statusLine payload. Opus and Sonnet are NOT gaps -- they have no separate bucket and count against the 7d all-models window above, so Opus work is fully covered here."

if ($Json) {
    [ordered]@{
        state        = $overall
        exit_code    = $rank[$overall]
        five_hour    = $five
        seven_day    = $seven
        advice       = $advice
        not_measured = $blindSpot
        published_by = $doc.published_by
        captured_at  = $doc.captured_at
    } | ConvertTo-Json -Depth 6 | Write-Output
    exit $rank[$overall]
}

function Show-Window($o) {
    if ($o.state -eq "UNKNOWN" -and $null -eq $o.used_percentage) {
        Write-Host ("  {0,-14} UNKNOWN -- {1}" -f $o.label, $o.reason) -ForegroundColor DarkGray
        return
    }
    $colour = switch ($o.state) { "CRITICAL" { "Red" } "WARN" { "Yellow" } "UNKNOWN" { "DarkGray" } default { "Green" } }
    $reset = if ($null -ne $o.minutes_to_reset) { "resets in {0}h{1:00}m" -f [int]($o.minutes_to_reset / 60), ($o.minutes_to_reset % 60) } else { "reset unknown" }
    Write-Host ("  {0,-14} {1,5:0.0}%  {2}   [seen {3} min ago]" -f $o.label, $o.used_percentage, $reset, $o.reading_age_min) -ForegroundColor $colour
    if ($null -ne $o.rate_pct_per_hr) {
        $proj = if ($null -ne $o.projected_at_reset) { ", ~{0}% by reset" -f $o.projected_at_reset } else { "" }
        Write-Host ("                 {0:+0.0;-0.0;0.0} %/hr{1}" -f $o.rate_pct_per_hr, $proj) -ForegroundColor DarkGray
    }
    if ($o.reason) { Write-Host ("                 {0}" -f $o.reason) -ForegroundColor DarkGray }
}

Write-Host ""
Write-Host "Claude account usage  --  $overall" -ForegroundColor $(switch ($overall) { "CRITICAL" { "Red" } "WARN" { "Yellow" } "UNKNOWN" { "DarkGray" } default { "Green" } })
Write-Host ""
Show-Window $five
Show-Window $seven
Write-Host ""
Write-Host "  $advice"
Write-Host ""
Write-Host "  $blindSpot" -ForegroundColor DarkGray
Write-Host ""
exit $rank[$overall]
