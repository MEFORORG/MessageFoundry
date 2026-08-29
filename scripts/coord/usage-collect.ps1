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

    ONE PUBLISHER, N READERS, PER ACCOUNT -- AND THE "PER ACCOUNT" IS THE HALF THAT WAS MISSING. This
    is the single place that premise is stated; everything else links here.

    The quota is ACCOUNT-WIDE: all sessions in every repo draw down the same 5-hour and 7-day pools, so
    any ONE session's reading is the truth for all sessions ON THAT ACCOUNT. Do not run a collector per
    session expecting to add them up -- summing double-counts the same shared pool. The output path is
    therefore not repo-level: the data is a property of the account, not of a checkout, and a
    repo-scoped copy would be a second truth that goes stale.

    IT IS NOT MACHINE-WIDE EITHER, and an earlier version of this file wrote as if it were. A box can
    run several Claude config roots at once, each pinned through CLAUDE_CONFIG_DIR, and A CONFIG ROOT
    HOLDS ONE CREDENTIAL SET AND THEREFORE ONE ANTHROPIC ACCOUNT. Measured on the box this was written
    for: five account roots, five different account emails, five separate pools. Publishing all of them
    to one user-level file is last-writer-wins across unrelated quotas, and the damage compounds -- the
    percentage flaps; the carry-forward below can leave five_hour from one account beside seven_day
    from another in one document; and usage.ps1's staleness guard never fires, because some OTHER
    account keeps the file warm. That last one is the worst: the guard looks present and is disarmed.

    SO THE PUBLISH PATH IS PER CONFIG ROOT: <config root>\mefor-usage. The rule lives once, in
    config-roots.ps1 (Get-UsageStateDir), and usage.ps1 derives its read path from the same function --
    so publisher and reader cannot drift apart. The filesystem is the partition key, which is why two
    roots cannot collide however CLAUDE_CONFIG_DIR is spelled.

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
    # Where to publish. NO DEFAULT HERE -- resolved in the body, because a param-block default cannot
    # call a function this script dot-sources (param() must be the first statement). That constraint is
    # a gift: computing it in the body is what lets collector, reader and installer share ONE
    # derivation instead of three string literals that agree by luck.
    #
    # The wired statusLine ALWAYS passes this explicitly, so the body's resolution is only ever reached
    # by a hand run or by a LEGACY wired command written before publish paths were per-root.
    [string]$StateDir,
    # Raw payload capture, for verifying the schema against a real session. Off by default: the payload
    # carries cwd and session ids.
    [switch]$CaptureRaw,
    # A parameter, not an environment read, for the test-safety reason config-roots.ps1 states:
    # [Environment]::GetFolderPath ignores a USERPROFILE override, so a callee that resolves home
    # itself cannot be redirected by a test.
    [string]$HomeDir = $(if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') })
)

# NO `$ErrorActionPreference = "Stop"`. This decorates a live session; a throw here is a worse outcome
# than a missing reading, every time.
$ErrorActionPreference = "SilentlyContinue"

# DOT-SOURCED GUARDED, WITH A LITERAL FALLBACK. This file decorates a live session and must survive a
# missing or broken sibling; a throw here is worse than any wrong path, every time. The fallback is a
# SECOND copy of a two-line rule, which is exactly the duplication SDS-3.5 warns about -- kept
# deliberately because "never throws" outranks "one definition" for a statusLine, and pinned by a test
# in tests/test_coord_usage.py so drift goes red rather than silent.
$HaveConfigRoots = $false
try { . (Join-Path $PSScriptRoot 'config-roots.ps1'); $HaveConfigRoots = $true } catch { }

# Loaded UNCONDITIONALLY, not only when $StateDir needs resolving: the wired statusLine always passes
# -StateDir, so a load inside that branch would leave the stamp helpers undefined on the one path that
# actually runs in production.
function Get-RootLabel([string]$Path) {
    if ([string]::IsNullOrWhiteSpace($Path)) { return $null }
    if ($HaveConfigRoots) { return (ConvertTo-NormalRootPath $Path) }
    try { return ([System.IO.Path]::GetFullPath($Path)).TrimEnd('\', '/') } catch { return $Path }
}

$ConfigRootEnv = if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR } else { $null }
if (-not $StateDir) {
    $root = $null
    if ($HaveConfigRoots) { $root = (Resolve-CurrentConfigRoot -HomeDir $HomeDir).Path }
    else { $root = if ($ConfigRootEnv) { $ConfigRootEnv } else { Join-Path $HomeDir '.claude' } }
    # AN UNVALIDATED PIN MUST NOT MANUFACTURE A CONFIG ROOT. New-Item -Force creates every missing
    # parent (measured: it created a .claude-account-99 as a side effect), so a typo'd or stale
    # CLAUDE_CONFIG_DIR would have a live session build a directory nothing can launch from -- the
    # exact input the installer refuses to create. Publishing nothing is a state this script already
    # handles quietly.
    if ($root -and (Test-Path -LiteralPath $root -PathType Container)) { $StateDir = Join-Path $root 'mefor-usage' }
}
if (-not $StateDir) { Write-Output "mefor-usage: no config root to publish to"; exit 0 }

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

    # THE LEAF ONLY, AGAINST A PARENT THAT ALREADY EXISTS. -Force creates every missing ancestor, so
    # without this guard an explicit -StateDir naming a root that is gone would have this script build
    # the whole chain. Same rule as the resolution above; stated here because the wired command reaches
    # this line without passing through it.
    if (-not (Test-Path -LiteralPath (Split-Path $StateDir -Parent) -PathType Container)) {
        Write-Output "mefor-usage: no config root to publish to"; exit 0
    }
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

    # THE ORIGIN TRAVELS WITH THE WINDOW, FOR THE SAME REASON captured_at DOES.
    #
    # A document-level stamp records who WROTE the file, not where the numbers in it came from, and the
    # carry-forward is exactly the hop that separates the two. Root A publishes into root B's directory
    # (a legacy or hand-copied command). B's next session fires before its first API response, carries
    # A's percentages forward, and rebuilds published_by with B -- so a document-level check compares B
    # against B, passes, and reports A's headroom as B's. The window kept its older captured_at and
    # would have been called stale eventually; it would never have been called FOREIGN.
    #
    # So a FRESHLY OBSERVED window is stamped here and a CARRIED one keeps whatever stamp it arrived
    # with. usage.ps1 applies the cross-root refusal per window as well as per document.
    $stampEnv = $(if ($ConfigRootEnv) { (Get-RootLabel $ConfigRootEnv) } else { "unset" })
    if ($five) { $five.captured_at = $now; $five.config_root_env = $stampEnv }
    elseif ($prevDoc -and $prevDoc.five_hour) { $five = $prevDoc.five_hour }
    if ($seven) { $seven.captured_at = $now; $seven.config_root_env = $stampEnv }
    elseif ($prevDoc -and $prevDoc.seven_day) { $seven = $prevDoc.seven_day }

    # Nothing observed and nothing remembered: publish NOTHING rather than a document full of nulls.
    if (-not $five -and -not $seven) { Write-Output "mefor-usage: no rate_limits yet"; exit 0 }

    $doc = [ordered]@{
        captured_at   = $now
        # WHERE THIS DOCUMENT CAME FROM, IN THREE FIELDS, BECAUSE ONE WOULD DETECT NOTHING.
        #
        # config_root is a LABEL derived from the write path, so it is always correct and can never be
        # a gate: a stamp derived from where we wrote agrees with where we wrote by construction. A
        # root mis-wired to publish into ANOTHER root's directory would land there stamped with that
        # other root, and every check would pass.
        #
        # config_root_env is THE DETECTOR: the ambient CLAUDE_CONFIG_DIR, read live, never derived from
        # the write path. usage.ps1 refuses a document whose config_root_env names a root other than
        # the one the document sits under -- which is the only comparison that can catch a mis-wire.
        #
        # "unset" IS A VALUE, distinct from absent. Absent means an older collector wrote this; unset
        # means this collector ran with no pin. usage.ps1 treats both as unverifiable provenance and
        # SAYS SO on every reading, rather than either lying about coverage or refusing correct data.
        # Whether CLAUDE_CONFIG_DIR even reaches a statusLine child process is UNMEASURED on this box;
        # if it does not, that line prints forever, which is the correct loud outcome.
        published_by  = [ordered]@{
            session_id      = [string]$p.session_id
            version         = [string]$p.version
            cwd             = [string]$p.cwd
            state_dir       = $StateDir
            config_root     = (Get-RootLabel (Split-Path $StateDir -Parent))
            config_root_env = $(if ($ConfigRootEnv) { (Get-RootLabel $ConfigRootEnv) } else { "unset" })
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
