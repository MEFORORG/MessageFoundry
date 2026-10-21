# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Wait, in the background, until a pull request is merged, is closed, or has every check
    complete, with a hard floor on the polling interval and a hard ceiling on the total wait.

.DESCRIPTION
    This is the bounded wait helper of the AFK-autonomy plan, docs/AUTONOMY-PLAN.md section 6.2. A
    session runs it with run_in_background and is woken when it exits, so it can carry a PR to
    completion without the owner typing "resume", and without writing its own poll loop.

        pwsh -NoProfile -File scripts/coord/wait-pr.ps1 -Repo MEFORORG/MessageFoundry -Pr 2466 -Until merged

    -Until merged           exit 0 once the PR is merged. A PR closed WITHOUT merging can never meet
                            it, so that is exit 1, not a wait until the timeout.
    -Until closed           exit 0 once the PR is closed, merged or not.
    -Until checks-complete  exit 0 once every check run and every commit status on the PR's CURRENT
                            head has finished, whatever its conclusion, and every context branch
                            protection requires has reported. The final line counts the conclusions;
                            reading them is the caller's job.

    EXIT CODES: 0 the condition is met, 2 the wait timed out, 1 anything else (bad arguments, too
    little rate budget to start, a gh call that failed, a PR that can no longer meet the condition).
    Exit 2 is not exit 1 on purpose: a timeout means "still waiting, decide whether to wait again",
    an error means "this instrument did not work".

    ONE LINE PER STATE CHANGE. Each check computes a one-line state and prints it only when it
    differs from the last one printed, so a 60-minute wait on an unchanging PR prints two lines, not
    thirty. For merged and closed the line carries GitHub's mergeable_state, so a branch that went
    BEHIND while you waited shows up as a change (docs/WORKTREES.md, "If you poll for 'is it merged
    yet', watch for three outcomes, not two").

.NOTES
    THE BOUNDS ARE THE POINT. Every seat draws on ONE shared 5000-per-hour GitHub budget (the
    header of scripts/hooks/block-api-burn.ps1 says why). The interval is clamped UP to 120 s and the
    total DOWN to 60 minutes, so one wait is at most 31 checks. Each check is a conditional request:
    the ETag of the last 200 goes back as If-None-Match, and GitHub does not count a 304 against
    the primary rate limit. The 304 behaviour was measured 2026-10-21 with gh 2.102.0: `gh api -i`
    prints the 304 status line and headers to stdout, writes "gh: HTTP 304" to stderr, exits 1, and
    X-Ratelimit-Remaining did not move.

    THE STARTING BUDGET IS READ ONCE. `gh api rate_limit` is free and runs before anything else;
    fewer than 500 core requests left refuses the start with exit 1, because a wait is never urgent
    enough to drain the last of a budget every other seat shares.

    REST ONLY, NEVER `gh pr`. `gh pr` speaks GraphQL, which the cloud GitHub proxy refuses
    (CLAUDE.md section 5, "A cloud session is a Builder in its own session"), and GraphQL has no
    conditional requests. Everything here is `gh api` against REST paths, so it runs unchanged in
    pwsh 7 on Windows and on a Linux cloud VM.

    IT DOES NOT TRIP block-api-burn.ps1, READ 2026-10-21. That guard inspects the COMMAND LINE a
    session types. Its first test requires `gh` in command position (at the start, after a shell
    separator, or behind `bash -c` / `pwsh -Command` / `cmd /c`), and exits 0 with no decision when
    there is none. `pwsh -NoProfile -File scripts/coord/wait-pr.ps1 ...` has no `gh` token, so none
    of its three deny rules (`gh run watch`, `--watch`, a hand-rolled loop with a sleep) is reached.
    The guard cannot see inside this script. That is acceptable rather than a loophole only because
    of the bounds above: the guard exists to stop UNBOUNDED loops, and this one is capped at 31
    conditional reads. Its deny reasons do not name this script yet; that is a change to the hook,
    not made here. Chaining a plain `gh` call in front of it on one line is still allowed, because
    that line has no loop keyword and no `--watch`.

    WHAT checks-complete CANNOT SEE. A required context with no check run on the head yet is
    invisible to a list of the runs that exist (CLAUDE.md section 5, the Lander's safeguard 1). So
    the required set is read once, from classic protection and from rulesets, through the same two
    endpoints scripts/ci/required_contexts.py reads, and every name in it must have reported. When
    both name nothing (an unprotected base) the script says so in its output and falls back to "at
    least one check exists and none is still running", which can end early on a roll-up that has not
    started. A failed read is exit 1, never an empty set.

    THE DESKTOP'S PR MONITOR IS NOT A SUBSTITUTE, READ 2026-10-21 from its tool description: it
    watches the one PR bound to the session, wakes it on CI failures, conflicts and review comments,
    and cannot be told to wait for a merge, for checks to finish, or for another session's PR. It
    also does not exist in a cloud session.

    -GhCommand and -SleepCommand are test seams. The tests point them at a stub `gh` and at a
    sleeper that records the seconds instead of sleeping. -SleepCommand receives the already
    clamped interval, so the clamp is tested through it.
#>
[CmdletBinding()]
param(
    [Parameter(Mandatory)]
    [ValidatePattern('^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$')]
    [string]$Repo,

    [Parameter(Mandatory)]
    [ValidateRange(1, 2147483647)]
    [int]$Pr,

    [Parameter(Mandatory)]
    [ValidateSet('merged', 'closed', 'checks-complete')]
    [string]$Until,

    [int]$IntervalSeconds = 120,

    [ValidateRange(1, 2147483647)]
    [int]$MaxMinutes = 60,

    [string]$GhCommand = 'gh',

    [string]$SleepCommand = ''
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

$MinIntervalSeconds = 120
$MaxTotalMinutes = 60
$RateFloor = 500

$script:Etags = @{}
$script:Bodies = @{}
$script:Requests = 0
$script:NotModified = 0

function Say([string]$Message) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    # Console, not Write-Output: Say runs inside functions whose return value is their output.
    [Console]::Out.WriteLine("$stamp wait-pr $Repo#${Pr}: $Message")
}

function Fail([string]$Message) {
    [Console]::Error.WriteLine("wait-pr $Repo#${Pr}: error: $Message")
    exit 1
}

# One REST GET through `gh api -i`, conditional on the last ETag seen for the same path. Returns
# the parsed body; on a 304 returns the body cached with that ETag.
function Get-Rest {
    param([string]$Path, [switch]$Free)

    $ghArgs = @('api', '-i', '-H', 'Accept: application/vnd.github+json')
    if ($script:Etags.ContainsKey($Path)) {
        $ghArgs += @('-H', "If-None-Match: $($script:Etags[$Path])")
    }
    $ghArgs += $Path

    # gh exits 1 on a 304 and on every 4xx, and writes "gh: HTTP <code>" to stderr. The status line
    # on stdout is what decides, so the exit code and stderr are kept only for the error message.
    $eap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        $all = @(& $GhCommand @ghArgs 2>&1)
        $code = $LASTEXITCODE
    } finally {
        $ErrorActionPreference = $eap
    }
    if (-not $Free) { $script:Requests++ }
    $err = @($all | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] }) -join ' '
    $text = (@($all | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n") -replace "`r", ''

    if ($text -notmatch '^HTTP/\S+ (\d{3})') {
        Fail "gh api $Path printed no HTTP status line (exit $code). $err"
    }
    $status = [int]$Matches[1]
    $split = $text.IndexOf("`n`n")
    $head = if ($split -ge 0) { $text.Substring(0, $split) } else { $text }
    $body = if ($split -ge 0) { $text.Substring($split + 2).Trim() } else { '' }

    if ($status -eq 304) {
        if (-not $script:Bodies.ContainsKey($Path)) {
            Fail "gh api $Path answered 304 to a request that sent no ETag this script holds a body for."
        }
        $script:NotModified++
        return $script:Bodies[$Path]
    }
    if ($status -lt 200 -or $status -ge 300) { Fail "gh api $Path answered HTTP $status. $err" }
    if (-not $body) { Fail "gh api $Path answered HTTP $status with an empty body." }

    $parsed = $body | ConvertFrom-Json
    $etag = [regex]::Match($head, '(?im)^etag:[ \t]*(.+)$')
    if ($etag.Success) {
        $script:Etags[$Path] = $etag.Groups[1].Value.Trim()
        $script:Bodies[$Path] = $parsed
    }
    return $parsed
}

function Read-Pr { Get-Rest "repos/$Repo/pulls/$Pr" }

function Test-Merged($p) {
    $state = "state=$($p.state) merged=$($p.merged) mergeable_state=$($p.mergeable_state) head=$($p.head.sha)"
    if ($Until -eq 'closed') {
        $met = $p.state -eq 'closed'
    } else {
        $met = $p.merged -eq $true
        if (-not $met -and $p.state -eq 'closed') {
            Say $state
            Fail 'the PR was closed without merging, so -Until merged can no longer be met.'
        }
    }
    @{ Met = $met; State = $state; Summary = "head=$($p.head.sha)" }
}

function Test-Checks($p) {
    $sha = [string]$p.head.sha

    $runs = @()
    $page = 1
    do {
        $b = Get-Rest "repos/$Repo/commits/$sha/check-runs?per_page=100&page=$page"
        $batch = @($b.check_runs)
        $runs += $batch
        $page++
    } while ($batch.Count -gt 0 -and $runs.Count -lt [int]$b.total_count)
    $statuses = @((Get-Rest "repos/$Repo/commits/$sha/status?per_page=100").statuses)

    # One split per list, so "still running" and "has reported" cannot drift apart.
    $running = @()
    $pending = @()
    $reported = @()
    foreach ($run in $runs) {
        if ($run.status -eq 'completed') { $reported += [string]$run.name } else { $running += $run }
    }
    foreach ($s in $statuses) {
        if ($s.state -eq 'pending') { $pending += $s } else { $reported += [string]$s.context }
    }
    $missing = @($script:Required | Where-Object { $reported -notcontains $_ })

    $met = ($runs.Count + $statuses.Count) -gt 0 -and $running.Count -eq 0 -and
        $pending.Count -eq 0 -and $missing.Count -eq 0
    $state = "head=$sha runs=$($runs.Count - $running.Count)/$($runs.Count) completed, " +
        "statuses pending=$($pending.Count)/$($statuses.Count), required not reported=$($missing.Count)"
    $conclusions = @($runs | ForEach-Object { [string]$_.conclusion }) +
        @($statuses | ForEach-Object { [string]$_.state })
    $tally = ($conclusions | Group-Object | Sort-Object Name | ForEach-Object { "$($_.Count) $($_.Name)" }) -join ', '
    @{ Met = $met; State = $state; Summary = "head=$sha $tally" }
}

# The required set, from the same two endpoints scripts/ci/required_contexts.py reads: classic
# protection through `branches/{base}`, which needs no admin scope (unlike
# `.../protection/required_status_checks`), and every ruleset through `rules/branches/{base}`.
function Read-Required([string]$Base) {
    $branch = Get-Rest "repos/$Repo/branches/$Base"
    $classic = @()
    $protection = $branch.PSObject.Properties['protection']
    if ($protection -and $protection.Value) {
        $checks = $protection.Value.PSObject.Properties['required_status_checks']
        if ($checks -and $checks.Value -and $checks.Value.PSObject.Properties['contexts']) {
            $classic = @($checks.Value.contexts | ForEach-Object { [string]$_ })
        }
    }
    $ruleset = @(
        @(Get-Rest "repos/$Repo/rules/branches/$Base") |
            Where-Object { $_.type -eq 'required_status_checks' } |
            ForEach-Object { @($_.parameters.required_status_checks) } |
            ForEach-Object { [string]$_.context }
    )
    @($classic + $ruleset | Sort-Object -Unique)
}

try {
    if ($IntervalSeconds -lt $MinIntervalSeconds) {
        Say "interval raised from $IntervalSeconds s to the $MinIntervalSeconds s floor"
        $IntervalSeconds = $MinIntervalSeconds
    }
    if ($MaxMinutes -gt $MaxTotalMinutes) {
        Say "total wait lowered from $MaxMinutes min to the $MaxTotalMinutes min ceiling"
        $MaxMinutes = $MaxTotalMinutes
    }

    # rate_limit is not counted against the limit, so it is not counted here either.
    $limit = Get-Rest 'rate_limit' -Free
    $remaining = [int]$limit.resources.core.remaining
    if ($remaining -lt $RateFloor) {
        Fail "refusing to start: $remaining core requests remain, below the floor of $RateFloor that every seat shares."
    }
    Say "waiting until $Until, every $IntervalSeconds s for at most $MaxMinutes min ($remaining core requests remain)"

    $p = Read-Pr
    $script:Required = @()
    if ($Until -eq 'checks-complete') {
        $base = [string]$p.base.ref
        $script:Required = @(Read-Required $base)
        if ($script:Required.Count -eq 0) {
            Say "no required contexts found on $base; waiting on the visible checks only, which cannot see a check that has not started"
        } else {
            Say "required contexts on ${base}: $($script:Required.Count)"
        }
    }

    $maxSeconds = $MaxMinutes * 60
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $slept = 0
    $last = $null
    while ($true) {
        $r = if ($Until -eq 'checks-complete') { Test-Checks $p } else { Test-Merged $p }
        if ($r.State -ne $last) {
            Say $r.State
            $last = $r.State
        }
        $accounting = "$($script:Requests) requests, $($script:NotModified) of them 304 and not counted"
        if ($r.Met) {
            Say "met: $Until. $($r.Summary). $accounting"
            exit 0
        }
        # A recording sleeper takes no wall time, so the seconds slept count as elapsed too.
        $elapsed = [math]::Max($slept, $clock.Elapsed.TotalSeconds)
        if ($elapsed + $IntervalSeconds -gt $maxSeconds) {
            Say "timeout: $Until not met within $MaxMinutes min. $accounting"
            exit 2
        }
        if ($SleepCommand) { & $SleepCommand $IntervalSeconds } else { Start-Sleep -Seconds $IntervalSeconds }
        $slept += $IntervalSeconds
        $p = Read-Pr
    }
} catch {
    Fail "$($_.Exception.Message)"
}
