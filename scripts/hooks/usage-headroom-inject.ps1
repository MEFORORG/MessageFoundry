# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    PreToolUse hook: put the account's current pool headroom in front of a session at the instant it
    spawns a worker.

.DESCRIPTION
    THE WATCHER COULD ALREADY COMPUTE THIS AND HAD NO WAY TO SAY IT (BACKLOG #1406). The usage
    collector is a statusLine; it writes `latest.json` and appends `history.jsonl`, and four things
    read those files. None of them can interrupt a running session. So a finding sat in a file and
    reached nobody until somebody happened to look.

    THAT SPLITS THE WATCHER'S JOB IN TWO, AND ONLY ONE HALF NEEDS DELIVERY.

      Naming the account with headroom WORKS ALREADY. A session needs that fact at exactly one
      moment -- just before it spawns -- and it CONTROLS that moment. Pulling the file at the point
      of use is the right design, not a compromise.

      Warning that a pool is nearly spent DOES NOT. A warning has to arrive at a moment nobody
      controls, and nothing here can interrupt a turn in progress.

    This hook closes the first half properly rather than inventing a channel for the second. It fires
    on the spawn tools, reads what the collector already wrote, and hands the session the number at
    the one moment the number changes a decision.

    WHY NOT A POLLER, MEASURED. A session that waits and checks is the most expensive state in the
    system: 2,108 metered tokens per waiting minute on a three-minute heartbeat and 22,275 on a
    ten-minute sleep loop, against ZERO once a turn ends. Buying delivery with a poll costs more than
    the warning saves. This hook makes no model call, sleeps for nothing, and runs only when a spawn
    is about to happen.

    WHY IT READS THROUGH usage.ps1 RATHER THAN latest.json DIRECTLY. Two reasons, and the second is
    the load-bearing one.

      One definition. `usage.ps1` already owns the honesty rules -- age per window, the staleness
      refusal, the future-dated-reading refusal, and the cross-root provenance check. A second
      implementation here would drift from it, and the drift would show up as two tools disagreeing
      about the same pool.

      The provenance check is not optional. A box runs several config roots, each a different
      account with its own pools. A reading published under another root, or carried forward from
      one, must never be reported as this session's headroom. Re-deriving that rule badly is how a
      spawn decision gets made against somebody else's quota.

    `usage.ps1` makes no network call of its own -- it reads the same files -- so this adds a reader
    of the FILES and NOT a second reader of the usage endpoint. That distinction matters: the
    endpoint returns 429 PER ENDPOINT rather than per caller, proven inside one process, so the
    design wants exactly one caller and this is not it.

    AN ABSENT, STALE OR UNREADABLE SOURCE IS UNKNOWN -- NEVER ZERO, AND NEVER SILENCE. A confident
    number derived from a failed read is worse than no number: it converts "I should check" into "I
    already know". Every failure path below says what failed and prints UNKNOWN. The reader's own
    absence is included: an empty answer and a broken probe are byte-identical unless you test the
    source first, which is the same shape as `claude agents --json` returning an empty list and
    exit 0 against a config root that does not exist.

    EVERY NUMBER CARRIES ITS AGE. The collector publishes at statusLine granularity, so a reading can
    be up to about fifteen minutes old while still looking plausible. A percentage printed with no
    age beside it invites a decision on data that has already expired.

    IT NEVER BLOCKS. There is no deny path here at all. A separate gate decides whether a launch may
    proceed; this one only makes sure the session can see what it is about to spend. Every error
    exits 0.

    WIRING. PreToolUse in the tracked `.claude/settings.json`, matcher
    `^(Task|Agent|Workflow)$|spawn_task` -- the dispatch tools and nothing else. The cost is one pwsh
    spawn plus one child, roughly 0.7 s, which is nothing beside a dispatch and a standing tax if it
    were ever wired on `*`: measured 19.0 tool calls per turn on this repo's transcripts. The
    tool-name test below is a second, narrower filter, so a matcher widened later cannot quietly turn
    this into that tax.

    THE MATCHER MUST CARRY A REGEX CHARACTER, AND THAT IS NOT A STYLE CHOICE. Claude Code reads a
    matcher of only letters, digits, `_`, `-`, spaces, `,` and `|` as a list of EXACT tool names, and
    anything else as an unanchored JavaScript regex. This row shipped as
    `Task|Agent|Workflow|spawn_task`, which is the first form: it selected three tools and never
    `mcp__ccd_session__spawn_task`, because MCP names reach a matcher fully qualified and a bare
    `spawn_task` is not one. Nothing reported it -- a matcher that selects nothing looks exactly like
    a hook that ran and had nothing to say. The `^...$` anchors keep the three bare names exact so an
    unanchored `Task` cannot also take `TaskOutput`, and the trailing alternative stays unanchored on
    purpose, because it has to match a qualified name it does not spell out.
    `tests/test_claude_settings_contract.py` reads that row and evaluates it the way the client does,
    against the guard below, so the two cannot part again.

    A DESKTOP SESSION GETS A SECOND, LABELLED SOURCE (BACKLOG #1459; seat decision under owner
    delegation 2026-10-08, not an owner ruling). A Desktop or SDK session never runs a statusLine, so
    on a Desktop-only config root the statusLine reading stays UNKNOWN for good. When it is UNKNOWN for
    such a session, the hook also reads the Steward's out-of-repo `status.json` and prints it as its
    own block. Four rules keep it from passing as a statusLine reading:

      Its own label. Every line it prints says where it came from, and its verdict line never
      replaces the statusLine verdict above it.

      Its own age and TTL. Each entry records when the Steward read it (`ts`) and how long the
      Steward itself would serve it (`ttl`). Past that TTL the fallback is UNKNOWN, never projected
      from; the statusLine's $MaxAgeMinutes does not apply to it.

      The same subject as the statusLine. The Steward keys a pool by the login record's
      `oauthAccount.organizationUuid`, or `acct:<accountUuid>` without one (watch.py, main()). This
      config root's login record names the key, and an entry naming another account is refused.

      No grade. The Steward's `state` field is a severity label, not a stop order (korus
      roles/STEWARD.md 3b), and usage.ps1's thresholds were set for statusLine readings. The
      fallback prints the numbers with their age and leaves grading to the reader.

    The file lives outside git and the Steward owns it. A schema version this hook does not know is
    UNKNOWN rather than a guess.

.EXAMPLE
    Drive it by hand the way the harness drives it:
        '{"tool_name":"Task"}' | pwsh -NoProfile -File scripts\hooks\usage-headroom-inject.ps1
#>
[CmdletBinding()]
param(
    # The reader to consult. Parameterised so tests drive the REAL hook against a real reader and a
    # fixture, rather than re-implementing the rule -- and so the missing-reader path is reachable
    # without deleting anything.
    [string]$UsageScript = (Join-Path $PSScriptRoot "..\coord\usage.ps1"),
    # Handed straight to the reader. Left unset in production so the reader resolves THIS session's
    # config root; set by tests to a fixture directory.
    [string]$StateDir,
    # The stated staleness threshold. Passed through, so the prose below and the reader that decides
    # UNKNOWN cannot name two different numbers.
    [int]$MaxAgeMinutes = 20,
    # The Steward's cache, read as a labelled fallback (BACKLOG #1459). Unset in production, so the
    # path resolves the way the Steward's own watch.py resolves it; set by tests to a fixture.
    [string]$StewardStatusFile,
    # The login record that names this config root's pool. Unset in production; set by tests.
    [string]$LoginRecord
)

# No `Stop`: this hook informs, and a throw here would be a tool call broken by a decoration.
$ErrorActionPreference = "SilentlyContinue"

# The tools that start a worker. Held here rather than trusted to the matcher because a matcher is
# configuration and this file is not: wired on `*` by a future edit, the hook would otherwise pay its
# spawn cost on every tool call in the session.
$SPAWN_TOOLS = @("Task", "Agent", "Workflow")

# Fold a value that came out of a FILE before putting it in prose the model reads.
#
# The reason strings below interpolate `published_by.config_root_env`, which is JSON any process on
# the box can write. A value carrying newlines would render a second block inside this notice, and a
# model reading top-down reaches the forged one first -- the shape BACKLOG #1040 measured against the
# worktree gate. Line structure is the whole exposure inside a sentence, so line structure is what is
# neutralised; '$', ';' and '&' do nothing here and are left alone.
function Get-Folded([object]$Value, [int]$Max = 300) {
    if ($null -eq $Value) { return "" }
    $s = [string]$Value
    $s = $s -replace "`r`n", " " -replace "`r", " " -replace "`n", " "
    $s = $s -replace "\s+", " "
    $s = $s.Trim()
    if ($s.Length -gt $Max) { $s = $s.Substring(0, $Max) + " ..." }
    return $s
}

function Write-Context([string]$Text) {
    $payload = [pscustomobject]@{
        hookSpecificOutput = [pscustomobject]@{
            hookEventName     = "PreToolUse"
            additionalContext = $Text
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

$HEAD = "[usage headroom, read at the spawn point from the file the statusLine collector already " +
        "publishes. No API call was made and nothing polled; this is the file, at the one moment it " +
        "changes a decision.]"

$AGE_NOTE = "Ages are part of the reading. The collector publishes at statusLine granularity, so a " +
            "number can be up to about 15 min old and still look current; anything past $MaxAgeMinutes min " +
            "is reported UNKNOWN rather than projected from."

# WHY AN UNKNOWN WILL NOT CLEAR ON ITS OWN (BACKLOG #1459). A bare "UNKNOWN" hid two causes that
# waiting cannot fix, and a session told only "UNKNOWN" waits for a number that cannot arrive. ONE
# note, never both: their remedies conflict, and the wiring fault has to be fixed first.
#
#   A WIRING FAULT the reader named -- for one, PowerShell source that bash cannot parse, which the
#   reader used to call WIRED_HERE. Any state but WIRED_HERE is named here. That is deliberately
#   wider than the reader's $dxUntrusted, which decides whether a READING is trusted; this decides
#   whether a fault is worth naming beside an UNKNOWN, and every one of them is. Skipped under
#   -StateDir, mirroring the reader: the caller named a directory, and the root above it need not be
#   wired at all.
#
#   A CLIENT THAT NEVER RUNS A statusLine. The collector is a statusLine, and a statusLine runs only
#   in the terminal UI. Measured 2026-09-30 across six config roots: every latest.json write lined up
#   with a session whose transcript records entrypoint "cli", and none with the "claude-desktop"
#   sessions that carried nearly all the traffic -- one correctly wired root had Desktop sessions that
#   day and a reading four days old. install-usage-statusline.ps1 names the SDK as never running it
#   either. Only those clients are named; any other entrypoint, an unfamiliar one included, gets no
#   note rather than a guess.
#
# THE REMEDY IS LABELLED AN OWNER ACTION. It rewrites a config root's settings.json, outside git, and
# this text lands in the context of every session about to spawn, which must not read it as a task.
function Get-CauseNote($Doc) {
    $st = if ($Doc) { Get-Folded $Doc.statusline_state 60 } else { "" }
    if (-not $StateDir -and $st -and $st -ne "WIRED_HERE") {
        $out = @("  statusLine ($st): " + (Get-Folded $Doc.statusline_line))
        $rem = @(@($Doc.statusline_remedy) | ForEach-Object { Get-Folded $_ } | Where-Object { $_ })
        if ($rem.Count -gt 0) {
            $out += "  remedy, an OWNER action (it writes a config root outside git; do not run it yourself):"
            $out += @($rem | ForEach-Object { "    $_" })
        }
        return $out
    }
    if (Test-NoStatusLineClient) {
        return @("  publisher: this session's entrypoint is '$(Get-Entrypoint)', which never runs a statusLine, so " +
            "nothing this session does will refresh this file. Only an interactive terminal 'claude' " +
            "session pinned to this config root publishes it.")
    }
    return @()
}

function Get-Entrypoint { Get-Folded $env:CLAUDE_CODE_ENTRYPOINT 40 }

# Only these clients are named; any other entrypoint, an unfamiliar one included, is not.
function Test-NoStatusLineClient {
    $ep = Get-Entrypoint
    return ($ep -eq "claude-desktop" -or $ep -like "sdk-*")
}

# THE STEWARD'S status.json, AS A LABELLED FALLBACK (BACKLOG #1459; seat decision under owner
# delegation 2026-10-08, not an owner ruling). The header says why each refusal below exists. Returns
# the lines to print, or nothing when the fallback does not apply.
#
# UNDER -StateDir IT RUNS ONLY WHEN BOTH FILES ARE NAMED. A caller that named a state directory is a
# test or a by-hand probe, and falling through to the real ~/.claude files there would read a live
# account's numbers into a fixture run.
function Get-StewardFallback {
    if (-not (Test-NoStatusLineClient)) { return @() }
    if ($StateDir -and -not ($StewardStatusFile -and $LoginRecord)) { return @() }

    # WHERE THE STEWARD WRITES, resolved the way watch.py resolves it: MEFOR_USAGE_DIR, else the config
    # root's mefor-usage, else the copy beside watch.py when that directory holds no tooling. The
    # settings files invoke watch.py by absolute path under ~/.claude/mefor-usage (STEWARD.md 3c).
    $cfg = $env:CLAUDE_CONFIG_DIR
    $statusPath = $StewardStatusFile
    if (-not $statusPath) {
        $dir = $env:MEFOR_USAGE_DIR
        if (-not $dir) { $dir = Join-Path $(if ($cfg) { $cfg } else { Join-Path $HOME ".claude" }) "mefor-usage" }
        if (-not (Test-Path -LiteralPath (Join-Path $dir "usage-now.py"))) {
            $dir = Join-Path (Join-Path $HOME ".claude") "mefor-usage"
        }
        $statusPath = Join-Path $dir "status.json"
    }
    # watch.py's CLAUDE_JSON: the pinned root's .claude.json, or ~/.claude.json for the default root.
    $loginPath = $LoginRecord
    if (-not $loginPath) {
        $loginPath = if ($cfg) { Join-Path $cfg ".claude.json" } else { Join-Path $HOME ".claude.json" }
    }

    $lines = @("  fallback source: the Steward's status.json at " + (Get-Folded $statusPath) +
        ". This is NOT a statusLine reading. It carries its own age and the Steward's own TTL.")
    $unknown = {
        param([string]$Why)
        return $lines + "  fallback verdict: UNKNOWN -- $Why"
    }

    # -AsHashtable IS REQUIRED, NOT STYLE. A real .claude.json carries project keys that differ only by
    # case, and plain ConvertFrom-Json throws on them -- measured on this box's own login record, where
    # it made every root read "no readable login record".
    $login = $null
    try { $login = Get-Content -LiteralPath $loginPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { }
    if (-not $login) {
        return & $unknown ("no readable login record at " + (Get-Folded $loginPath) + ", so no pool can be named")
    }
    $org = Get-Folded $login.oauthAccount.organizationUuid 80
    $acct = Get-Folded $login.oauthAccount.accountUuid 80
    if (-not $org -and -not $acct) {
        return & $unknown "the login record names no account, so no pool can be named"
    }
    # watch.py's _cli_pool_selfcheck: a login record that disagrees with itself cannot name a pool.
    $billed = Get-Folded $login.cachedUsageUtilization.accountUuid 80
    if ($acct -and $billed -and $acct -ne $billed) {
        return & $unknown ("the login record disagrees with itself (oauthAccount names account " +
            $acct.Substring(0, [math]::Min(8, $acct.Length)) + ", cachedUsageUtilization names " +
            $billed.Substring(0, [math]::Min(8, $billed.Length)) + "), so it cannot name this pool")
    }
    $key = if ($org) { $org } else { "acct:$acct" }
    $pool = $key.Substring(0, [math]::Min(13, $key.Length))

    if (-not (Test-Path -LiteralPath $statusPath)) { return & $unknown "the Steward has never written this file" }
    $doc = $null
    try { $doc = Get-Content -LiteralPath $statusPath -Raw -ErrorAction Stop | ConvertFrom-Json -AsHashtable -ErrorAction Stop } catch { }
    if ($doc -isnot [System.Collections.IDictionary]) { return & $unknown "the file is present and nothing readable came out of it" }
    if ([string]$doc.version -ne "3") {
        return & $unknown ("its schema version is '" + (Get-Folded $doc.version 20) + "', and this hook reads only version 3")
    }
    $entry = $null
    if ($doc.pools -is [System.Collections.IDictionary]) { $entry = $doc.pools[$key] }
    if ($entry -isnot [System.Collections.IDictionary]) { return & $unknown "the Steward has no entry for pool $pool, the login this config root records" }

    # The key matched; the entry must agree. An entry naming another account is refused, not read.
    $entryOrg = Get-Folded $entry.org 80
    $entryAcct = Get-Folded $entry.account 80
    if (($org -and $entryOrg -and $entryOrg -ne $org) -or ($acct -and $entryAcct -and $entryAcct -ne $acct)) {
        return & $unknown "the entry under pool $pool names another account, so it was read and refused"
    }

    $ts = $entry.ts -as [double]
    $ttl = $entry.ttl -as [double]
    if ($null -eq $ts -or -not [double]::IsFinite($ts)) { return & $unknown "the entry for pool $pool carries no read time" }
    if ($null -eq $ttl -or -not [double]::IsFinite($ttl) -or $ttl -le 0) {
        return & $unknown "the entry for pool $pool carries no TTL, so its freshness cannot be judged"
    }
    $ageSec = [DateTimeOffset]::UtcNow.ToUnixTimeMilliseconds() / 1000.0 - $ts
    # usage.ps1's skew allowance, so the two sources refuse a future date at the same point.
    if ($ageSec -lt -120) { return & $unknown "the entry for pool $pool is dated in the FUTURE -- clock skew or a bad timestamp" }
    $ageSec = [math]::Max(0.0, $ageSec)
    $ageMin = "{0:0.0}" -f ($ageSec / 60)
    $ttlMin = "{0:0.#}" -f ($ttl / 60)
    if ($ageSec -gt $ttl) {
        return & $unknown ("the entry for pool $pool is $ageMin min old, past the Steward's own TTL of " +
            "$ttlMin min, so it is not projected from")
    }
    if ((Get-Folded $entry.kind 20) -ne "reading") {
        return & $unknown "the Steward's own entry for pool $pool is not a reading"
    }

    $lines += "  fallback verdict: READ, not graded here -- pool $pool, the login this config root records"
    foreach ($w in @(@("5-hour", "5h"), @("weekly", "7d"))) {
        $v = $entry.levels.($w[0]) -as [double]
        $label = "  steward {0,-3}" -f $w[1]
        if ($null -eq $v -or -not [double]::IsFinite($v)) {
            $lines += "$label UNKNOWN -- the Steward's entry carries no $($w[0]) reading"
            continue
        }
        $lines += "$label {0,5:0.0}% used   [read {1} min ago by the Steward; its TTL is {2} min]" -f $v, $ageMin, $ttlMin
    }
    return $lines
}

# UNKNOWN IS STILL AN INJECTION. Exiting quietly on a failed read would leave the session with no
# reading and no indication that a reading was attempted, which is the state this hook exists to end.
function Write-Unknown([string]$Detail, [string[]]$Extra = @()) {
    Write-Context (@(
            $HEAD
            "  verdict: UNKNOWN -- $Detail"
            $Extra
            "  UNKNOWN is not zero headroom and it is not full headroom. It is no measurement."
            "  Spawn on your own judgment, and expect a cutoff to be possible at any point."
            @(Get-StewardFallback)
        ) -join "`n")
}

# UNAVAILABLE IS NOT UNKNOWN, AND ROUTING IT THROUGH Write-Unknown WOULD BE A LIE IN THE SAFE-LOOKING
# DIRECTION. The line above says UNKNOWN "is no measurement" and tells the session to use its own
# judgment -- which is exactly the wrong instruction for an account that has no subscription, because
# the honest reading is a hard zero and there is no judgment call left to make. The reader's own
# distinction between exit 20 and 21 is preserved here rather than collapsed at the last hop.
function Write-Unavailable([string]$Reason, [string]$Account) {
    $lines = @($HEAD)
    if ($Account) { $lines += "  account: $Account" }
    $lines += @(
        "  verdict: UNAVAILABLE -- this account has no subscription. There is no pool to spend."
        "  reason: $Reason"
        "  This is a MEASUREMENT, not a gap: it is zero spendable capacity, not an unread number."
        "  Do not send work here, and do not read a quiet publish directory under it as spare capacity."
    )
    Write-Context ($lines -join "`n")
}

# --- which tool is this ---------------------------------------------------------------------------

$raw = ""
try { if ([Console]::IsInputRedirected) { $raw = [Console]::In.ReadToEnd() } } catch { $raw = "" }

$toolName = $null
if ($raw) {
    try {
        $p = $raw | ConvertFrom-Json -ErrorAction Stop
        if ($p.PSObject.Properties.Name -contains "tool_name") { $toolName = [string]$p.tool_name }
    }
    catch { }
}

# A NAME WE CAN READ DECIDES; A NAME WE CANNOT READ DOES NOT VETO. The matcher already selected this
# call, so an unparseable payload is not evidence that this is the wrong moment -- and treating it as
# one would disarm the hook silently, which is the failure mode being fixed rather than reproduced.
if ($toolName) {
    $isSpawn = ($SPAWN_TOOLS -contains $toolName) -or ($toolName -like "*spawn_task*")
    if (-not $isSpawn) { exit 0 }
}

# --- read what the collector wrote ----------------------------------------------------------------

if (-not (Test-Path -LiteralPath $UsageScript)) {
    Write-Unknown ("the usage reader is missing at " + (Get-Folded $UsageScript) +
        ", so nothing was read. This is a broken probe, not an all-clear.")
}

# Not $args: that name is automatic, and a script that writes to it is one refactor away from a
# binding surprise that is invisible at the call site.
$readerArgs = @("-NoProfile", "-NonInteractive", "-File", $UsageScript, "-Json", "-MaxAgeMinutes", $MaxAgeMinutes)
if ($StateDir) { $readerArgs += @("-StateDir", $StateDir) }

$out = $null
try { $out = & pwsh @readerArgs 2>$null }
catch {
    Write-Unknown ("the usage reader could not be run: " + (Get-Folded $_.Exception.Message))
}

# EMPTY STDOUT IS NOT A READING. The reader's contract is a JSON document on every path, including
# every failure, so nothing at all means it never produced a verdict -- a killed process, a broken
# copy, a refused invocation. Folding that into "no data" would report a probe that never ran as a
# pool that was measured.
$text = (@($out) -join "`n").Trim()
if (-not $text) {
    Write-Unknown "the usage reader produced no output at all, so nothing was measured"
}

$j = $null
try { $j = $text | ConvertFrom-Json -ErrorAction Stop } catch { }
if (-not $j) {
    Write-Unknown "the usage reader's output was not readable JSON, so nothing was measured"
}

# --- render ---------------------------------------------------------------------------------------

$state = Get-Folded $j.state
if (-not $state) { $state = "UNKNOWN" }

# BEFORE THE WINDOW CHECK BELOW, because an UNAVAILABLE document deliberately carries NO five_hour key
# -- so leaving this until after it would send every cancelled account down the "the reader returned no
# window readings" path and report a known zero as an unread number.
if ($state -eq "UNAVAILABLE") {
    $why = Get-Folded $j.reason
    if (-not $why) { $why = "no reason recorded" }
    Write-Unavailable $why (Get-Folded $j.config_root)
}

# WHICH FILE WAS ACTUALLY LOOKED AT. The reader reports `path` when it found nothing and `state_dir`
# when it found something; either way the session should be told where the number came from, because
# a per-root publish path means "the account" is a directory, not a global.
$latestPath = $null
if ($j.PSObject.Properties.Name -contains "path" -and $j.path) { $latestPath = [string]$j.path }
elseif ($j.PSObject.Properties.Name -contains "state_dir" -and $j.state_dir) {
    $latestPath = Join-Path ([string]$j.state_dir) "latest.json"
}
elseif ($StateDir) { $latestPath = Join-Path $StateDir "latest.json" }

# NO WINDOWS MEANS THE READER REFUSED THE WHOLE DOCUMENT -- nothing published, a foreign root, or a
# config root it could not resolve. Its own reason is the honest text; the source test below is what
# separates "nobody ever published" from "something is there and it did not survive the read".
if (-not ($j.PSObject.Properties.Name -contains "five_hour") -or -not $j.five_hour) {
    $why = Get-Folded $j.reason
    if (-not $why) { $why = "the reader returned no window readings" }
    # A REFUSAL IS NOT AN UNREADABLE FILE, and saying so would be a confidently wrong diagnosis of a
    # correctly working guard. The reader stamps a cross-root refusal FOREIGN, so that case is
    # separated on the stamp rather than on the wording of a sentence.
    $where = "the source path is unknown"
    if ($latestPath) {
        if ((Get-Folded $j.provenance) -eq "FOREIGN") {
            $where = "the source at " + (Get-Folded $latestPath) + " was read and refused"
        }
        elseif (Test-Path -LiteralPath $latestPath) {
            $where = "a file IS present at " + (Get-Folded $latestPath) + " and nothing readable came out of it"
        }
        else {
            $where = "nothing has ever published to " + (Get-Folded $latestPath)
        }
    }
    Write-Unknown "$why ($where)" @(Get-CauseNote $j)
}

function Format-Window($w, [string]$Short) {
    $label = "  {0,-3}" -f $Short
    if (-not $w) { return "$label UNKNOWN -- this window has never been published" }
    if ([string]$w.state -eq "UNKNOWN" -or $null -eq $w.used_percentage) {
        return "$label UNKNOWN -- " + (Get-Folded $w.reason)
    }
    # THE AGE IS NOT AN ORNAMENT ON THE PERCENTAGE, so it is printed in the same clause and never
    # dropped when it is null: an undated number is worth less than no number.
    $age = if ($null -ne $w.reading_age_min) { "read {0} min ago" -f $w.reading_age_min } else { "age UNKNOWN" }
    $line = "$label {0,5:0.0}% used   [{1}]" -f ([double]$w.used_percentage), $age
    if ($null -ne $w.minutes_to_reset -and [int]$w.minutes_to_reset -gt 0) {
        $m = [int]$w.minutes_to_reset
        $line += ("   resets in {0}h{1:00}m" -f [int]($m / 60), ($m % 60))
    }
    if ([string]$w.state -in @("WARN", "CRITICAL")) {
        $line += "   " + [string]$w.state + " -- " + (Get-Folded $w.reason 160)
    }
    return $line
}

$lines = @($HEAD)
$account = Get-Folded $j.config_root
if ($account) { $lines += "  account: $account" }
$lines += "  verdict: $state"
$lines += (Format-Window $j.five_hour "5h")
$lines += (Format-Window $j.seven_day "7d")

# PROVENANCE UNVERIFIED IS SAID OUT LOUD. The publisher recorded no CLAUDE_CONFIG_DIR, so the guard
# that keeps another account's headroom out of this reading could not run. That is a different fact
# from a failed guard, and only one of them is an error -- but a session spawning on the number is
# entitled to know which one it has.
if ((Get-Folded $j.provenance) -eq "UNVERIFIED") {
    $lines += "  provenance: UNVERIFIED -- the publisher recorded no config root, so the cross-account guard could not run"
}

# A READING THAT CAME BACK UNKNOWN GETS ITS CAUSE, for the same reason the no-window path does.
if ($state -eq "UNKNOWN") {
    $lines += @(Get-CauseNote $j)
}

$advice = Get-Folded $j.advice
if ($advice) { $lines += "  $advice" }
$lines += "  $AGE_NOTE"
# AFTER the age note, which is about the statusLine reading and does not apply to the fallback.
if ($state -eq "UNKNOWN") { $lines += @(Get-StewardFallback) }

Write-Context ($lines -join "`n")
