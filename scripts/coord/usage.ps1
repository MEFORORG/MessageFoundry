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

    WHICH ACCOUNT'S NUMBERS. This root's. The publish path is per config root -- see usage-collect.ps1
    for why, stated once there -- so a bare invocation answers for the account THIS session booted
    against, not for the box. Use -AllRoots to see every root side by side.

    FOUR HONESTY RULES, because a usage tool that is confidently wrong is worse than no usage tool --
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
      4. REFUSE A READING FROM SOMEBODY ELSE'S ACCOUNT, AND SAY WHEN THAT CANNOT BE CHECKED. A document
         stamped with a config root other than the one it sits under is reported UNKNOWN, never as this
         session's headroom. A document carrying no stamp is read, and labelled UNVERIFIED -- absence
         of provenance and wrong provenance are different facts, and only one of them is an error.

    EXIT CODES, so a coordinator can branch without parsing prose:
        0  OK
        10 WARN     -- high, or projected to exhaust before reset with slack
        11 CRITICAL -- projected to exhaust before reset, or already at the ceiling
        20 UNKNOWN  -- no data, stale data, not enough samples, or a reading this root may not trust
    Every diagnostic state added for the per-root publish path is UNKNOWN/20: they distinguish WHICH
    FIX to apply, not how bad the situation is, and a coordinator branches on the four codes above.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\usage.ps1
    pwsh -NoProfile -File scripts\coord\usage.ps1 -Json
    pwsh -NoProfile -File scripts\coord\usage.ps1 -AllRoots
    # Peek at another root without leaving this session:
    pwsh -NoProfile -File scripts\coord\usage.ps1 -StateDir "$HOME\.claude-account-1\mefor-usage"
#>
[CmdletBinding()]
param(
    # NO DEFAULT. Resolved in the body from this session's own config root, because a param-block
    # default cannot call a function the script dot-sources (param() must be the first statement).
    # That constraint is a gift: computing it in the body is what lets reader, collector and installer
    # share ONE derivation instead of restating a literal that agrees by luck.
    [string]$StateDir,
    # Machine-readable, for the coordinator.
    [switch]$Json,
    # Older than this and a reading is reported but NOT projected from.
    [int]$MaxAgeMinutes = 20,
    # Rate is measured over at most this much recent history.
    [int]$RateWindowMinutes = 90,
    # One line per config root on this box. A SURVEY, NEVER A MERGE: these are different accounts with
    # different 5h and 7d pools, so summing, averaging or taking a worst-of across them would rebuild
    # the exact lie the per-root publish path removes.
    [switch]$AllRoots,
    # A parameter for the test-safety reason config-roots.ps1 states.
    [string]$HomeDir = $(if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') })
)

$script:GaveStateDir = $PSBoundParameters.ContainsKey('StateDir')

$ErrorActionPreference = "SilentlyContinue"

# THE READER NEEDS THIS GUARD MORE THAN THE COLLECTOR DOES, and SilentlyContinue is why. With the
# library missing, the dot-source failure is swallowed, Resolve-CurrentConfigRoot is not found
# (swallowed), $StateDir stays $null, Join-Path $null "latest.json" yields the EMPTY STRING, and this
# script would print "Nothing has published to ." and then diagnose `\settings.json` -- a confidently
# wrong answer, which is the one outcome the honesty rules above exist to prevent. The shipped param
# default could not fail this way; removing it introduces the hazard, so it is closed here.
$rootInfo = $null
$haveLib = $false
try {
    . (Join-Path $PSScriptRoot 'config-roots.ps1')
    $rootInfo = Resolve-CurrentConfigRoot -HomeDir $HomeDir
    $haveLib = $true
}
catch { }
# THE FLOOR IS THE LIBRARY, NOT THE PATH, and testing the path alone would leave a hole. An explicit
# -StateDir resolves the path without the library, but every downstream check -- Test-IsOurStatusLine,
# Get-WiredStateDir, Test-SameRoot -- comes from it, and under SilentlyContinue a missing function is
# swallowed rather than raised. That would produce a full, confidently wrong diagnosis. Refuse on the
# library, whatever the path.
if (-not $haveLib) {
    $reason = "cannot resolve this session's config root -- scripts\coord\config-roots.ps1 did not load"
    if ($Json) { @{ state = "UNKNOWN"; reason = $reason; path = $null } | ConvertTo-Json -Compress | Write-Output }
    else { Write-Host ""; Write-Host "UNKNOWN. $reason" -ForegroundColor Yellow; Write-Host "" }
    exit 20
}
if (-not $StateDir) { $StateDir = Get-UsageStateDir $rootInfo.Path }

$latestPath = Join-Path $StateDir "latest.json"
$histPath = Join-Path $StateDir "history.jsonl"

$doc = $null
try { $doc = Get-Content -LiteralPath $latestPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { }

# WHY THE READER DIAGNOSES AND THE INSTALLER CANNOT. The reader is the only half that runs INSIDE the
# pin, so it is the only one positioned to see which root a session really boots against. And because
# it already has to open this root's settings.json to answer at all, the wired command is in hand at
# no extra cost -- which is what lets it distinguish "not wired" from "wired to publish somewhere
# else", two states with completely different fixes that the old one-line message merged.
#
# EIGHT STATES. The old message named none of them: it said "not installed or has not run yet" and
# printed the bare installer command with no root -- so following the reader's own advice re-ran the
# exact invocation that produced the false INSTALLED claim in the first place.
function Get-StatusLineDiagnosis([string]$Root, [string]$ReadingFrom) {
    $settingsPath = Join-Path $Root "settings.json"
    # THE DIRECTORY ITSELF FIRST. A typo'd CLAUDE_CONFIG_DIR otherwise reads as "this root has no
    # settings.json", and the remedy printed for that state is an installer invocation the installer
    # REFUSES (it will not create a config root). The operator follows the advice, gets a refusal, and
    # nothing anywhere has named the actual fault.
    if (-not (Test-Path -LiteralPath $Root -PathType Container)) {
        return [ordered]@{
            settings_path   = $settingsPath
            state           = "NO_SUCH_ROOT"
            line            = "NO SUCH DIRECTORY -- the config root itself does not exist"
            remedy          = @("Nothing can be wired here, and the installer refuses to create a config root.",
                "Fix CLAUDE_CONFIG_DIR (or the launcher that sets it) to name a directory that exists.")
            wired_state_dir = $null
            wired_collector = $null
        }
    }
    $o = [ordered]@{
        settings_path = $settingsPath
        state         = "NOT_WIRED_NO_SETTINGS"
        line          = "NOT WIRED -- this root has no settings.json"
        remedy        = @("No session booting from this root can publish. Wire it (owner, plain terminal):",
            "  pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -ConfigDir `"$Root`"")
        wired_state_dir = $null
        wired_collector = $null
    }
    if (-not (Test-Path -LiteralPath $settingsPath)) { return $o }

    $settings = $null
    try { $settings = Get-Content -LiteralPath $settingsPath -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop }
    catch {
        $o.state = "SETTINGS_UNREADABLE"
        $o.line = "UNKNOWN -- settings.json is not valid JSON"
        $o.remedy = @("An unparseable settings.json silently disables EVERY setting in it, not just this one.",
            "Fix that first.")
        return $o
    }

    $cmd = [string]$settings.statusLine.command
    if ([string]::IsNullOrWhiteSpace($cmd)) {
        $o.state = "NOT_WIRED_NO_STATUSLINE"
        $o.line = "NOT WIRED -- settings.json carries no statusLine"
        return $o
    }
    if (-not (Test-IsOurStatusLine $cmd)) {
        $o.state = "FOREIGN_STATUSLINE"
        $o.line = "FOREIGN -- a statusLine that is not ours owns this root's status bar"
        $o.remedy = @("The collector never runs here, and the installer REFUSES to replace someone else's",
            "statusLine. Merge the two commands by hand, or remove theirs, then re-install.")
        return $o
    }

    $o.wired_state_dir = Get-WiredStateDir $cmd
    $o.wired_collector = Get-WiredCollectorPath $cmd
    $reinstall = @("Re-wire this root so the two agree:",
        "  pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -ConfigDir `"$Root`"")

    if ($null -eq $o.wired_state_dir) {
        $o.state = "WIRED_LEGACY"
        $o.line = "WIRED (ours) but the command carries no -StateDir -- written before publish paths were per-root. Where it publishes depends on the collector's own fallback at run time."
        $o.remedy = $reinstall
        return $o
    }
    if ($o.wired_collector -and -not (Test-Path -LiteralPath $o.wired_collector)) {
        $o.state = "WIRED_COLLECTOR_MISSING"
        $o.line = "WIRED (ours) but the collector it names is absent: $($o.wired_collector)"
        $o.remedy = @("The status bar shows 'mefor-usage: collector missing' and nothing publishes.",
            "Advance the primary checkout, or re-install to point at a collector that exists.")
        return $o
    }
    if (-not (Test-SameRoot $o.wired_state_dir $ReadingFrom)) {
        # THIS ARM IS THE POINT OF THE WHOLE DIAGNOSIS. Without it the reader tells the operator to
        # restart and wait, forever, with nothing anywhere saying the two halves disagree -- which is
        # the original defect relocated rather than fixed.
        $o.state = "WIRED_ELSEWHERE"
        $o.line = "WIRED (ours) but it publishes to $($o.wired_state_dir), and this session reads $ReadingFrom. WAITING WILL NOT FIX THIS."
        $o.remedy = $reinstall
        return $o
    }
    $o.state = "WIRED_HERE"
    $o.line = "WIRED (ours), and it is wired to publish where this reader is looking"
    $o.remedy = @("Settings are read at session START, so a session already running when it was wired still",
        "has none. Start a NEW session pinned to this root and give it about ten seconds. Interactive",
        "only -- it never runs under 'claude -p' or the SDK, so a headless coordinator can read this",
        "and can never publish it.")
    return $o
}

$readRoot = Split-Path $StateDir -Parent
$rootSource = if ($script:GaveStateDir) { "-StateDir" } elseif ($rootInfo) { $rootInfo.Source } else { "unknown" }

# DIAGNOSED ON EVERY RUN, NOT ONLY WHEN THERE IS NOTHING TO READ. An earlier version computed this
# inside the no-data branch, which made WIRED_ELSEWHERE -- the arm this diagnosis exists for --
# unreachable in the case where it misleads most: a root now wired to publish into a SIBLING still has
# its own older latest.json, so the reader served that stale percentage as current for twenty minutes
# and then said "no live session is publishing", which is also false. The session is publishing; it is
# publishing somewhere else, and nothing in the output said so.
$dx = Get-StatusLineDiagnosis $readRoot $StateDir

if (-not $doc) {
    if ($Json) {
        [ordered]@{
            state             = "UNKNOWN"
            reason            = "no data"
            path              = $latestPath
            config_root       = $readRoot
            config_root_source = $rootSource
            settings_path     = $dx.settings_path
            statusline_state  = $dx.state
            state_dir         = $StateDir
            wired_state_dir   = $dx.wired_state_dir
            wired_collector   = $dx.wired_collector
        } | ConvertTo-Json -Compress | Write-Output
    }
    else {
        Write-Host ""
        Write-Host "NO USAGE DATA. Nothing has published to $latestPath." -ForegroundColor Yellow
        Write-Host "  config root : $readRoot   (from $rootSource)"
        Write-Host "  settings    : $($dx.settings_path)"
        Write-Host "  statusLine  : $($dx.line)"
        Write-Host ""
        foreach ($l in $dx.remedy) { Write-Host "  $l" }
        Write-Host ""
        Write-Host "  This reads the FILE. A file that carries the statusLine is not the same as a statusLine that FIRED."
        Write-Host ""
    }
    exit 20
}

# RULE 4, THE REFUSAL. Compared against the READ-FROM root -- the root the document actually sits
# under -- and NOT against the reader's own root. Those are identical on the default path, but
# comparing against the reader's root would break the two invocations that exist precisely to look
# elsewhere: the documented single-root peek (-StateDir <other root>) and every row of the -AllRoots
# survey but one. It still catches the failure it exists for: a reader in A opens A's file, the stamp
# says B, B is not A, refuse.
#
# THE STAMP IT GATES ON IS config_root_env, NOT config_root. config_root is derived from the write
# path, so it agrees with the write path by construction and could never detect a mis-wire.
$stampEnv = [string]$doc.published_by.config_root_env
$provenance = "OK"
if ($stampEnv -and $stampEnv -ne "unset") {
    if (-not (Test-SameRoot $stampEnv $readRoot)) {
        $reason = "published from a DIFFERENT config root ($stampEnv); this document sits under $readRoot -- refusing to report another account's headroom as this session's"
        if ($Json) { [ordered]@{ state = "UNKNOWN"; reason = $reason; path = $latestPath; config_root = $readRoot; provenance = "FOREIGN" } | ConvertTo-Json -Compress | Write-Output }
        else { Write-Host ""; Write-Host "UNKNOWN. $reason" -ForegroundColor Yellow; Write-Host "" }
        exit 20
    }
}
else {
    # ABSENCE IS UNVERIFIABLE PROVENANCE, NOT WRONG PROVENANCE -- so the reading is used, and the fact
    # that the guard could not run is stated on every line of output rather than assumed away. It is
    # also what keeps every hand-written fixture and every pre-change document readable.
    $provenance = "UNVERIFIED"
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

# ONE DEFINITION of the per-window cross-root test. The single-root reader and the -AllRoots survey
# both call it, because two statements of one rule is exactly how the survey came to print a
# percentage that the reader four lines above had just refused.
function Test-WindowFromRoot($w, [string]$ReadRoot) {
    if (-not $w) { return $true }
    $e = [string]$w.config_root_env
    if (-not $e -or $e -eq "unset" -or -not $ReadRoot) { return $true }
    return [bool](Test-SameRoot $e $ReadRoot)
}

function Get-WindowReport($w, [string]$Label, [string]$Key, [string]$ResetKey, [string]$ReadRoot) {
    if (-not $w) {
        return [ordered]@{ label = $Label; state = "UNKNOWN"; reason = "never published"; used_percentage = $null }
    }
    # RULE 4, PER WINDOW. A window carries the config root that OBSERVED it, and the carry-forward keeps
    # that stamp rather than restamping -- so a percentage that came from another account is caught here
    # even when the document around it was written by this root. The document-level check cannot see
    # that hop: it compares the writer to the directory, and both are correct.
    $wEnv = [string]$w.config_root_env
    if (-not (Test-WindowFromRoot $w $ReadRoot)) {
        return [ordered]@{
            label           = $Label
            state           = "UNKNOWN"
            reason          = "this window was observed under a DIFFERENT config root ($wEnv) and carried into a document under $ReadRoot -- refusing to report another account's headroom"
            used_percentage = $null
        }
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
        # NO CAUSAL CLAIM. This used to read "-- no live session is publishing", which nothing here
        # checks and which is often false: a session may be publishing perfectly well, into another
        # root. The mis-wire warning printed above the numbers names that case; this line states the
        # age and stops.
        else { "reading is $age min old (max $MaxAgeMinutes)" }
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

$five = Get-WindowReport $doc.five_hour "session (5h)" "five_hour" "five_reset" $readRoot
$seven = Get-WindowReport $doc.seven_day "weekly (7d)" "seven_day" "seven_reset" $readRoot

$rank = @{ "OK" = 0; "WARN" = 10; "CRITICAL" = 11; "UNKNOWN" = 20 }
$states = @($five.state, $seven.state)
# CRITICAL outranks UNKNOWN: a known emergency in one window is not softened by the other being unknown.
# ONE LIST, READ TWICE. The warning printed below and the verdict computed here must name the same
# states, or the prose and the exit code describe different situations -- the two-instruments-
# disagreeing defect this whole change exists to remove, reproduced inside one script.
$dxUntrusted = @("WIRED_ELSEWHERE", "WIRED_LEGACY", "WIRED_COLLECTOR_MISSING", "FOREIGN_STATUSLINE",
    "NOT_WIRED_NO_SETTINGS", "NOT_WIRED_NO_STATUSLINE")

$overall = if ($states -contains "CRITICAL") { "CRITICAL" }
elseif ($states -contains "WARN") { "WARN" }
elseif ($states -contains "UNKNOWN") { "UNKNOWN" }
else { "OK" }

# A READING THIS ROOT MAY NOT TRUST IS UNKNOWN, which is what the exit-code contract promises. The
# diagnosis used to reach the prose only, so a root the script itself called mis-wired still exited 0
# and reported state=OK beside statusline_state=WIRED_ELSEWHERE in one document. An explicit -StateDir
# is exempt: there the operator named the directory, and the root above it need not be wired at all.
if (-not $script:GaveStateDir -and $overall -ne "CRITICAL" -and $dx.state -in $dxUntrusted) {
    $overall = "UNKNOWN"
}

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

# ONE LINE PER CONFIG ROOT, AND NOTHING COMPUTED ACROSS THEM. Each row is validated against ITS OWN
# root, which is why the refusal above compares to the read-from root rather than the reader's -- with
# the other comparison every row but this session's would render as a refusal.
function Get-RootSummary([string]$Root) {
    $sd = Get-UsageStateDir $Root
    $lp = Join-Path $sd "latest.json"
    $s = [ordered]@{ root = $Root; state_dir = $sd; published = $false; note = ""; five = $null; seven = $null; age_min = $null; stale = $false }
    $d = $null
    try { $d = Get-Content -LiteralPath $lp -Raw -ErrorAction Stop | ConvertFrom-Json -ErrorAction Stop } catch { }
    if (-not $d) {
        $dx = Get-StatusLineDiagnosis $Root $sd
        $s.note = "never published  [statusLine: $($dx.state)]"
        return $s
    }
    $env_ = [string]$d.published_by.config_root_env
    if ($env_ -and $env_ -ne "unset" -and -not (Test-SameRoot $env_ $Root)) {
        $s.note = "REFUSED -- stamped with a different config root ($env_)"
        return $s
    }
    $s.published = $true
    # THE SURVEY IS THE ONLY PLACE ACCOUNTS ARE COMPARED, so it is where the cross-root refusal
    # matters most -- and it was the one place it did not run. Checking only the DOCUMENT stamp passes
    # a carry-forward: the document was written by this root and sits under this root, while the
    # numbers inside came from another. Measured: the single-root reader refused both windows and the
    # survey four lines later printed them as this root's own.
    $fiveOurs = Test-WindowFromRoot $d.five_hour $Root
    $sevenOurs = Test-WindowFromRoot $d.seven_day $Root
    $s.five = if ($d.five_hour -and $fiveOurs) { [double]$d.five_hour.used_percentage } else { $null }
    $s.seven = if ($d.seven_day -and $sevenOurs) { [double]$d.seven_day.used_percentage } else { $null }
    # AGED BY ITS WINDOWS, NOT BY THE DOCUMENT. The collector rewrites the document stamp on EVERY
    # fire, including a pure carry-forward, so it dates the last fire and not the observation -- a
    # six-hour-old reading rendered as "[seen 0 min ago]". The OLDER of the two windows is the honest
    # single number for a row printing both. The @() wrapper is load-bearing: without it a single
    # surviving age arrives as a scalar and .Count is unreliable.
    $fa = if ($d.five_hour) { Get-AgeMinutes $d.five_hour.captured_at } else { $null }
    $sa = if ($d.seven_day) { Get-AgeMinutes $d.seven_day.captured_at } else { $null }
    $ages = @(@($fa, $sa) | Where-Object { $null -ne $_ })
    # The document stamp is the fallback only when no window carries one, which keeps pre-change
    # documents and hand-written fixtures readable.
    $s.age_min = if ($ages.Count) { ($ages | Measure-Object -Maximum).Maximum } else { Get-AgeMinutes $d.captured_at }
    $s.stale = ($null -eq $s.age_min) -or ($s.age_min -gt $MaxAgeMinutes)
    if (-not $fiveOurs -or -not $sevenOurs) {
        $s.note = "REFUSED -- a window here was observed under a DIFFERENT config root"
    }
    elseif (-not $env_ -or $env_ -eq "unset") { $s.note = "provenance UNVERIFIED" }
    return $s
}

$survey = $null
if ($AllRoots) {
    $survey = @()
    foreach ($r in @(Get-LaunchableConfigRoots -HomeDir $HomeDir)) { $survey += Get-RootSummary $r }
    if ($rootInfo -and -not ($survey | Where-Object { Test-SameRoot $_.root $readRoot })) {
        $survey += Get-RootSummary $readRoot
    }
}

if ($Json) {
    [ordered]@{
        state        = $overall
        exit_code    = $rank[$overall]
        five_hour    = $five
        seven_day    = $seven
        advice       = $advice
        not_measured = $blindSpot
        provenance   = $provenance
        statusline_state = $dx.state
        wired_state_dir = $dx.wired_state_dir
        config_root  = $readRoot
        config_root_source = $rootSource
        state_dir    = $StateDir
        roots        = $survey
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
# WHOSE NUMBERS THESE ARE, ON EVERY RUN. Five roots on this box are five different accounts with five
# separate pools, so a percentage with no root beside it is an unattributed number -- the same shape of
# omission as a percentage with no age.
Write-Host "  config root: $readRoot   (from $rootSource)" -ForegroundColor DarkGray
# A MIS-WIRE IS PRINTED ABOVE THE NUMBERS, not below them and not only when there are none. If this root
# publishes somewhere else, the percentages under this heading are a leftover, and saying so after the
# reader has already read them is too late to stop the wrong decision.
if ($dx.state -in $dxUntrusted) {
    Write-Host ""
    Write-Host "  WARNING -- the numbers below may be a leftover:" -ForegroundColor Yellow
    Write-Host "  $($dx.line)" -ForegroundColor Yellow
    foreach ($l in $dx.remedy) { Write-Host "  $l" -ForegroundColor DarkGray }
}
# CORRECTLY WIRED AND STILL NOT FRESH IS ITS OWN FAILURE, and it is the one actually seen on this box:
# every root wired, every collector present, and latest.json frozen for 47 minutes across nine live
# sessions. The mis-wire arm above cannot catch it -- a healthy root reports WIRED_HERE -- so without
# this it falls through to a bare "reading is N min old", which is the line a reader skims past. The
# earlier "-- no live session is publishing" at least signalled that something was wrong; deleting it
# as an unchecked causal claim was right, but it left this case with no signal at all.
#
# EVERY CLAUSE IS BACKED. "wired, and the collector it names exists" is what WIRED_HERE already tested
# (ownership, an extracted -StateDir matching this directory, and Test-Path on the collector). "nothing
# fresh" is the window states. The two CAUSES are offered as alternatives, never asserted, because
# nothing here can tell them apart.
# -and, NOT -or. With -or this fired on a document published 0.15 seconds earlier: a fresh five_hour
# beside a seven_day that has simply never been published leaves one window UNKNOWN, and the warning
# then claimed "nothing fresh has published here" over a reading taken moments ago. The claim is that
# NOTHING is fresh, so the test has to be that nothing is.
elseif ($dx.state -eq "WIRED_HERE" -and $five.state -eq "UNKNOWN" -and $seven.state -eq "UNKNOWN") {
    # THE COLLECTOR CLAUSE IS CONDITIONAL, because WIRED_HERE does not always mean one was checked: a
    # wired command carrying a -StateDir but no recognisable collector assignment yields a null
    # collector path, which skips the Test-Path guard entirely. Asserting it exists would be asserting
    # a check that never ran.
    $collClause = if ($dx.wired_collector) { " and the collector it names exists" } else { "" }
    Write-Host ""
    Write-Host "  WARNING -- this root is wired correctly$collClause," -ForegroundColor Yellow
    Write-Host "  yet nothing fresh has published here. Two causes, and this cannot tell them apart:" -ForegroundColor Yellow
    Write-Host "    - no session has STARTED here since it was wired (settings are read at session start), or" -ForegroundColor DarkGray
    Write-Host "    - the statusLine is configured but never runs. It is part of the terminal UI's render" -ForegroundColor DarkGray
    Write-Host "      tree, so check whether your client shows a status bar at all; a line beginning" -ForegroundColor DarkGray
    Write-Host "      'mefor-usage' there means it IS firing and the fault is elsewhere." -ForegroundColor DarkGray
}
Write-Host ""
Show-Window $five
Show-Window $seven
Write-Host ""
Write-Host "  $advice"
if ($provenance -eq "UNVERIFIED") {
    Write-Host ""
    Write-Host "  provenance: UNVERIFIED -- the publisher recorded no CLAUDE_CONFIG_DIR, so the cross-root guard could not run" -ForegroundColor DarkGray
}
Write-Host ""
Write-Host "  $blindSpot" -ForegroundColor DarkGray
if ($survey) {
    Write-Host ""
    Write-Host "  Config roots under $HomeDir matching the launcher name shape, plus this session's."
    Write-Host "  A survey -- nothing is summed across accounts:"
    foreach ($s in $survey) {
        $mark = if (Test-SameRoot $s.root $readRoot) { "  <- this session" } else { "" }
        if ($s.published) {
            $f = if ($null -ne $s.five) { "5h {0,3:0}%" -f $s.five } else { "5h   -" }
            $v = if ($null -ne $s.seven) { "7d {0,3:0}%" -f $s.seven } else { "7d   -" }
            # Two branches rather than a computed -ForegroundColor: passing $null to that parameter
            # throws ("Cannot convert null to type System.ConsoleColor"), measured.
            if ($s.stale) {
                Write-Host ("    {0,-46} {1}  {2}   [STALE -- oldest window seen {3} min ago, max {4}]{5}" -f $s.root, $f, $v, $s.age_min, $MaxAgeMinutes, $mark) -ForegroundColor DarkGray
            }
            else {
                Write-Host ("    {0,-46} {1}  {2}   [seen {3} min ago]{4}" -f $s.root, $f, $v, $s.age_min, $mark)
            }
            if ($s.note) { Write-Host ("    {0,-46} {1}" -f "", $s.note) -ForegroundColor DarkGray }
        }
        else {
            Write-Host ("    {0,-46} {1}{2}" -f $s.root, $s.note, $mark) -ForegroundColor DarkGray
        }
    }
    # ENUMERATED BY A DIFFERENT RULE, so the survey cannot confirm its own predicate. The rows above
    # come from an anchored, case-sensitive name shape; this pass finds every ~/.claude* directory
    # carrying a settings.json and names any the survey did not cover. Without it, a root spelled
    # `.Claude-Account-7` and burning quota would be absent from a list the operator reads as complete.
    foreach ($c in @(Get-ClaudeConfigCandidates -HomeDir $HomeDir)) {
        if ($survey | Where-Object { Test-SameRoot $_.root $c.FullName }) { continue }
        Write-Host ("    {0,-46} not surveyed -- carries a settings.json but is not a launcher-shaped root name" -f $c.Name) -ForegroundColor Yellow
    }
}
Write-Host ""
exit $rank[$overall]
