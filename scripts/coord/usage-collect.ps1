# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    statusLine command: publish the account's live plan-limit state where every session can read it.

.DESCRIPTION
    THE ONLY PLACE THE REAL NUMBERS ARRIVE. Claude Code hands `rate_limits` to a statusLine command's
    stdin and NOWHERE ELSE -- not SessionStart, not UserPromptSubmit, not Stop, not any other hook. So a
    coordinator cannot subscribe to quota state; it has to be COLLECTED here and written somewhere shared.
    That single fact is why this script exists and why it is a statusLine rather than a hook.

    ONE PUBLISHER, N READERS. The quota is ACCOUNT-WIDE: all sessions in every repo draw down the same
    5-hour and 7-day pools, so any ONE session's reading is the truth for all of them. Do not run a
    collector per session expecting to add them up -- summing double-counts the same shared pool. The
    output path is therefore user-level, not repo-level: the data is a property of the account, not of
    a checkout, and a repo-scoped copy would be a second truth that goes stale.

    WHAT IT CANNOT SEE, STATED HERE SO NOTHING DOWNSTREAM IMPLIES OTHERWISE. The statusLine payload
    carries `five_hour` and `seven_day` only. Absent: the MODEL-SCOPED weekly bucket (the "Weekly /
    Fable" bar in Settings > Usage) and the plan tier. The request to expose them was closed as
    not-planned.

    OPUS IS NOT ONE OF THE GAPS, and an earlier draft of this file said it was. Opus and Sonnet have no
    separate weekly bucket on this plan -- they draw on "All models", which IS the `seven_day` window
    published here. So for Opus work the coverage is complete, and a warning implying otherwise would
    make sessions distrust an accurate reading. Only a model with its OWN bar (Fable) is unmeasured.
    Corrected 2026-08-02 by the account holder against the actual Settings > Usage panel; the wrong
    version came from reading `seven_day_opus`/`seven_day_sonnet` in an undocumented endpoint's SCHEMA
    and assuming a field implies an active limit.

    NEVER THROWS, NEVER BLOCKS. A statusLine that errors or hangs degrades the session it is decorating,
    so every path is wrapped and the worst case is a bare line of text with no publish. Writes are
    temp-then-rename because Claude Code CANCELS an in-flight statusLine when a new one is triggered
    (300ms debounce) -- a truncating write would publish half a JSON document to every reader on the box.

.EXAMPLE
    Wire it (owner, from a plain terminal):
        pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1
    Read it (anyone):
        pwsh -NoProfile -File scripts\coord\usage.ps1
#>
[CmdletBinding()]
param(
    # Where to publish. User-level by default: the quota is account-wide, so this is not repo state.
    [string]$StateDir = (Join-Path $env:USERPROFILE ".claude\mefor-usage"),
    # Raw payload capture, for verifying the schema against a real session. Off by default: the payload
    # carries cwd and session ids, and this is a shared machine-level path.
    [switch]$CaptureRaw
)

# NO `$ErrorActionPreference = "Stop"`. This decorates a live session; a throw here is a worse outcome
# than a missing reading, every time.
$ErrorActionPreference = "SilentlyContinue"

function Write-AtomicText([string]$Path, [string]$Text) {
    # Temp-then-rename. [IO.File]::Move with overwrite is MoveFileEx(MOVEFILE_REPLACE_EXISTING), which
    # never unlinks the destination name -- measured on this box at 0 absent-polls across 134,581, versus
    # 2,559 for Move-Item -Force. Readers therefore never observe a missing or half-written file.
    $tmp = "$Path.$PID.tmp"
    [System.IO.File]::WriteAllBytes($tmp, [System.Text.Encoding]::UTF8.GetBytes($Text))
    foreach ($attempt in 1..3) {
        # Untyped catch: PowerShell wraps a .NET method's exception in MethodInvocationException, so a
        # typed catch here silently never matches and orphans the temp file.
        try { [System.IO.File]::Move($tmp, $Path, $true); return $true } catch { Start-Sleep -Milliseconds (15 * $attempt) }
    }
    Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
    return $false
}

function Format-Reset([object]$EpochSeconds) {
    if ($null -eq $EpochSeconds) { return $null }
    try { return [System.DateTimeOffset]::FromUnixTimeSeconds([long]$EpochSeconds).ToLocalTime().ToString("o") } catch { return $null }
}

$line = "mefor-usage"
try {
    if (-not [Console]::IsInputRedirected) { Write-Output $line; exit 0 }
    $raw = [Console]::In.ReadToEnd()
    $p = $null
    try { $p = $raw | ConvertFrom-Json -ErrorAction Stop } catch { }
    if (-not $p) { Write-Output "mefor-usage: unreadable statusline payload"; exit 0 }

    New-Item -ItemType Directory -Force -Path $StateDir | Out-Null
    if ($CaptureRaw) { Write-AtomicText (Join-Path $StateDir "raw-payload.json") $raw | Out-Null }

    $rl = $p.rate_limits
    $now = (Get-Date).ToUniversalTime().ToString("o")

    # ABSENT IS A VALUE. The docs are explicit that rate_limits "appears only for Claude.ai subscribers
    # (Pro/Max) after the first API response in the session" and that each window "may be independently
    # absent". So a missing window is recorded as null with a reason, never defaulted to 0 -- 0% used and
    # "not reported yet" are opposite facts and must not share a representation.
    function Get-Window($w) {
        if ($null -eq $w) { return $null }
        $pct = $w.used_percentage
        if ($null -eq $pct) { return $null }
        return [ordered]@{
            used_percentage = [double]$pct
            resets_at_epoch = $w.resets_at
            resets_at       = Format-Reset $w.resets_at
        }
    }

    $five = Get-Window $rl.five_hour
    $seven = Get-Window $rl.seven_day

    # Snapshotted BEFORE the carry-forward below, because HISTORY MUST RECORD ONLY WHAT WAS FRESHLY
    # OBSERVED. A carried-forward percentage written against a new timestamp tells the burn-rate
    # calculation that consumption had stopped -- the one lie that matters in a tool built to warn
    # about consumption.
    $freshFive = if ($five) { $five.used_percentage } else { $null }
    $freshSeven = if ($seven) { $seven.used_percentage } else { $null }

    # DO NOT CLOBBER A GOOD READING WITH AN EMPTY ONE.
    #
    # EVERY session runs this statusLine and they all publish to ONE shared file, so every session is a
    # publisher -- there is no privileged "collector". A session that has not yet had its first API
    # response carries no rate_limits at all, and a naive write blanks the account's only good reading
    # for all of them. Caught in test: a full 5h/7d reading was overwritten seconds later by a session
    # reporting neither.
    #
    # Per-window, not all-or-nothing, because the docs are explicit that the two windows are absent
    # INDEPENDENTLY. An absent window carries the previous value forward together with ITS OWN
    # captured_at, so staleness is tracked per window and a reader can never mistake a carried-over
    # number for a freshly observed one.
    $latestPath = Join-Path $StateDir "latest.json"
    $prevDoc = $null
    try { $prevDoc = Get-Content -LiteralPath $latestPath -Raw -ErrorAction SilentlyContinue | ConvertFrom-Json -ErrorAction Stop } catch { }

    if ($five) { $five.captured_at = $now } elseif ($prevDoc -and $prevDoc.five_hour) { $five = $prevDoc.five_hour }
    if ($seven) { $seven.captured_at = $now } elseif ($prevDoc -and $prevDoc.seven_day) { $seven = $prevDoc.seven_day }

    # Nothing observed and nothing remembered: publish NOTHING rather than a document full of nulls.
    if (-not $five -and -not $seven) { Write-Output "mefor-usage: no rate_limits yet"; exit 0 }

    $doc = [ordered]@{
        captured_at   = $now
        published_by  = [ordered]@{
            session_id = [string]$p.session_id
            version    = [string]$p.version
            cwd        = [string]$p.cwd
        }
        five_hour     = $five
        seven_day     = $seven
        # Named explicitly rather than omitted, so a reader cannot mistake "this build never collected
        # it" for "the account has none". Opus is deliberately NOT listed: it has no separate weekly
        # bucket and is covered by seven_day.
        unavailable   = @(
            "model_scoped_weekly (Fable) -- not present in the statusLine payload",
            "plan_tier -- not present in the statusLine payload"
        )
        source        = "claude-code statusLine rate_limits"
    }

    $json = ($doc | ConvertTo-Json -Depth 6)
    $ok = Write-AtomicText (Join-Path $StateDir "latest.json") $json

    # History drives burn rate. Append ONLY when a percentage actually moves: the statusline can fire many
    # times a minute, and a row per fire would be a large file describing a flat line.
    if ($ok -and ($null -ne $freshFive -or $null -ne $freshSeven)) {
        $histPath = Join-Path $StateDir "history.jsonl"
        $prev = $null
        try { $prev = (Get-Content -LiteralPath $histPath -Tail 1 -ErrorAction SilentlyContinue | ConvertFrom-Json) } catch { }
        # Append only when a FRESHLY OBSERVED percentage actually moves. The statusline can fire many
        # times a minute; a row per fire would be a large file describing a flat line, and rate over a
        # dense flat series is noise.
        $changed = $true
        if ($prev) {
            $samePct = (($null -eq $freshFive) -or ($prev.five_hour -eq $freshFive)) -and
                       (($null -eq $freshSeven) -or ($prev.seven_day -eq $freshSeven))
            if ($samePct) { $changed = $false }
        }
        if ($changed) {
            $row = [ordered]@{
                at          = $now
                five_hour   = $freshFive
                seven_day   = $freshSeven
                five_reset  = if ($rl.five_hour) { $rl.five_hour.resets_at } else { $null }
                seven_reset = if ($rl.seven_day) { $rl.seven_day.resets_at } else { $null }
            } | ConvertTo-Json -Compress
            Add-Content -LiteralPath $histPath -Value $row -Encoding UTF8
        }
    }

    # The human-facing line. Keep it short; this is a status bar, not a report.
    if ($five -or $seven) {
        $parts = @()
        if ($five) { $parts += ("5h {0:0}%" -f $five.used_percentage) }
        if ($seven) { $parts += ("7d {0:0}%" -f $seven.used_percentage) }
        $line = ($parts -join "  ")
        if ($five -and $five.resets_at_epoch) {
            $mins = [int](([System.DateTimeOffset]::FromUnixTimeSeconds([long]$five.resets_at_epoch) - [System.DateTimeOffset]::UtcNow).TotalMinutes)
            if ($mins -ge 0) { $line += ("  (resets {0}h{1:00}m)" -f [int]($mins / 60), ($mins % 60)) }
        }
    }
    else {
        # Distinguish "no quota data yet" from "quota fine". The first API response of a session has not
        # landed yet, or this is not a subscription account.
        $line = "mefor-usage: no rate_limits yet"
    }
}
catch {
    $line = "mefor-usage: collector error"
}

Write-Output $line
exit 0
