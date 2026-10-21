# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Wait, in the background, until a pull request is merged, is closed, or has every check
    complete, with a hard floor on the polling interval, a hard ceiling on the time it sleeps, and
    a timeout on every gh call.

.DESCRIPTION
    This is the bounded wait helper of the AFK-autonomy plan, section 6.2 of docs/AUTONOMY-PLAN.md
    (owner-approved 2026-10-21; on branch `autonomy-plan`, not yet on main, when this was written).
    A session runs it with run_in_background and is woken when it exits, so it can carry a PR to
    completion without the owner typing "resume", and without writing its own poll loop.

        pwsh -NoProfile -File scripts/coord/wait-pr.ps1 -Repo MEFORORG/MessageFoundry -Pr 2466 -Until merged

    -Until merged           exit 0 once the PR is merged. A PR read as closed WITHOUT merging on two
                            checks in a row is exit 1, not a wait until the timeout. One such read is
                            not enough, because closing and reopening is a common way to re-run CI.
                            An open PR whose `mergeable_state` reads `dirty` or `behind` on two checks
                            in a row of the same head SHA is exit 3, "needs a push" (see below).
    -Until closed           exit 0 once the PR is closed, merged or not.
    -Until checks-complete  exit 0 once every check run and every commit status on the PR's CURRENT
                            head has finished, whatever its conclusion, and every context its base
                            branch requires has reported. The final line counts the conclusions;
                            reading them is the caller's job.

    EXIT CODES: 0 the condition is met, 2 the wait timed out, 3 the PR needs a push before it can
    merge (-Until merged only), 1 anything else (bad arguments, too little rate budget to start, a
    gh call that failed, a PR that can no longer meet the condition). Exit 2 is not exit 1 on
    purpose: a timeout means "still waiting, decide whether to wait again", an error means "this
    instrument did not work". Exit 3 is neither: the instrument worked and waiting longer will not
    help, because someone has to update or rebase the branch first.

    ONE LINE PER STATE CHANGE. Each check computes a one-line state and prints it only when it
    differs from the last one printed, so a 60-minute wait on an unchanging PR prints a start line,
    one state line and a timeout line, not thirty-odd. For merged and closed the line carries
    GitHub's REST `mergeable_state`, in lower case (`behind`, `dirty`, `blocked`, `clean`), so a
    branch that went stale while you waited is in the output.

    NEEDS A PUSH IS EXIT 3, FOR -Until merged ONLY. docs/WORKTREES.md ("watch for three outcomes,
    not two") says a merge watcher must not sit out its whole budget on a PR that cannot merge
    without a push. So an open PR read as `dirty` or `behind` on two checks in a row of the SAME
    head SHA ends the wait with exit 3 and one line naming the state and the SHA. Two reads, because
    GitHub computes mergeability lazily and a transient value is common. An `unknown` or missing
    value, or a transient failure, counts for nothing and resets nothing; any other value, a closed
    read, or a new head SHA resets the count. For closed and checks-complete the state is printed
    and never acted on.

.NOTES
    THE BOUNDS ARE THE POINT. Every seat draws on ONE shared 5000-per-hour GitHub budget (the
    header of scripts/hooks/block-api-burn.ps1 says why). The interval is clamped UP to 120 s and the
    total DOWN to 60 minutes (and UP to one interval, so a wait always waits), so one wait is at
    most 31 checks. A check is one read of the PR for merged and closed, and at least three for
    checks-complete (the PR, each page of check runs, each page of commit statuses), plus at least
    two reads of the base's required contexts at the start and on a retarget. The first read of
    each path is unconditional and counted. Every later read of it is conditional: the ETag of the
    last 200 goes back as If-None-Match, and GitHub does not count a 304 against the primary rate
    limit, so an unchanging PR costs little after the first check. The 304
    behaviour was measured 2026-10-21 with gh 2.102.0: `gh api -i` prints the 304 status line and
    headers to stdout, writes "gh: HTTP 304" to stderr, exits 1, and X-Ratelimit-Remaining did not
    move.

    EVERY gh CALL HAS A 60 s TIMEOUT. gh sets none of its own, so each call runs as a child process
    that is killed, with its process tree, if it has not finished within 60 s. A killed call is a
    transient failure under the three-in-a-row rule below. The ceiling is on time SLEPT: intervals
    slept never exceed it, and the wall clock ends the wait at the first check that finishes past
    it. So a wait can run past its ceiling by at most one interval plus the reads of one check, and
    with the timeout each of those reads is bounded too.

    THE STARTING BUDGET IS READ ONCE. `gh api rate_limit` is free and runs before anything else;
    fewer than 500 core requests left refuses the start with exit 1, because a wait is never urgent
    enough to drain the last of a budget every other seat shares. Because it runs first, a gh that
    is missing or not logged in is exit 1 at once.

    ONE TRANSIENT FAILURE DOES NOT END THE WAIT. Inside the loop a 5xx, a 429, a call that printed
    no status line at all (a reset connection), or a call killed at its timeout becomes the state
    line and the next interval reads again. Three in a row is exit 1, because by then the failure
    is more likely a broken gh (logged out, removed) than a blip, and a timeout would misreport it
    as "still waiting". A 403 or 429 that says the rate budget is spent (X-Ratelimit-Remaining: 0)
    is exit 1 at once, with a message naming the budget: polling a spent budget every seat shares
    is the thing to stop. Any other 4xx is exit 1 too.

    REST ONLY, NEVER `gh pr`. `gh pr` speaks GraphQL, which the cloud GitHub proxy refuses
    (CLAUDE.md section 5, "A cloud session is a Builder in its own session"), and GraphQL has no
    conditional requests. Everything here is `gh api` against REST paths, so it runs unchanged in
    pwsh 7 on Windows and on a Linux cloud VM.

    IT DOES NOT TRIP block-api-burn.ps1, READ 2026-10-21. That guard inspects the COMMAND LINE a
    session types. Its first test requires `gh` in command position (at the start, after a shell
    separator, or behind `bash -c` / `pwsh -Command` / `cmd /c`), and exits 0 with no decision when
    there is none. `pwsh -NoProfile -File scripts/coord/wait-pr.ps1 ...` has no `gh` token, so none
    of its three deny rules (`gh run watch`, `--watch`, a hand-rolled loop with a sleep) is reached.
    The guard cannot see inside this script, and THE GUARD DOES NOT SANCTION IT: its loop rule
    denies bounded sleeping loops typed at the prompt too, and tells a session to read once per
    turn. What sanctions this one is the owner-approved plan (section 6.2 asks for exactly this
    helper, run in the background "so no hook change is needed") and the bounds above. Do not read
    it as licence to move any other loop into a .ps1 file. The guard's deny reasons do not name
    this script; that is a change to the hook, not made here. Chaining a plain `gh` call in front
    of it on one line is still allowed, because that line has no loop keyword and no `--watch`.

    WHAT checks-complete CANNOT SEE. A required context with no check run on the head yet is
    invisible to a list of the runs that exist (CLAUDE.md section 5, the Lander's safeguard 1). So
    the required set is read from classic protection and from rulesets, through the same two
    endpoints scripts/ci/required_contexts.py reads, and every name in it must have reported, matched
    case-sensitively so a near-miss name never satisfies it. It is read again if the PR's base
    changes, and a transient failure part-way through that read leaves it unread, to be read again
    next check. A protected base whose payload carries no contexts key is exit 1, never an empty
    set, which is that reader's rule too; an empty contexts list is a real empty answer. Only a
    base where both name nothing falls back, out loud, to "at least one check exists and none is
    still running", which can end early on a roll-up that has not started. THIS IS A COPY of that
    reader's rule in PowerShell, not a call to it, and it parts from it once on purpose: that
    reader refuses an unprotected branch, where a waiter can still wait on the visible checks.

    THE DESKTOP'S PR MONITOR IS NOT A SUBSTITUTE, READ 2026-10-21 from its tool description: it
    watches the one PR bound to the session, wakes it on CI failures, conflicts and review comments,
    and cannot be told to wait for a merge, for checks to finish, or for another session's PR. It
    also does not exist in a cloud session.

    TEST SEAMS. -GhCommand names the gh to run; a stand-in can only fake answers, never shorten a
    sleep. A .ps1 stand-in runs as its own child process under this pwsh, so it goes through the
    same timeout and kill as a real gh. -SleepCommand replaces Start-Sleep, which would remove the
    interval floor, and -GhTimeoutSeconds replaces the 60 s per-call timeout; both are refused
    unless MEFOR_WAIT_PR_TEST_SEAMS=1 is set in the environment. The tests set it, point the sleep
    at a sleeper that records the already clamped interval instead of sleeping, and shorten the
    timeout only where a stand-in hangs on purpose.
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

    [string]$SleepCommand = '',

    [ValidateRange(1, 3600)]
    [int]$GhTimeoutSeconds = 60
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
$script:ClosedUnmerged = 0
$script:StaleSha = $null
$script:StaleReads = 0
$script:Utf8 = [System.Text.UTF8Encoding]::new($false)

function Say([string]$Message) {
    $stamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
    # Console, not Write-Output: Say runs inside functions whose return value is their output.
    [Console]::Out.WriteLine("$stamp wait-pr $Repo#${Pr}: $Message")
}

function Fail([string]$Message) {
    [Console]::Error.WriteLine("wait-pr $Repo#${Pr}: error: $Message")
    exit 1
}

# A property of a parsed JSON object, or $null when the object does not carry it. StrictMode makes
# a plain `.name` on a missing property throw.
function Prop($Object, [string]$Name) {
    if ($null -eq $Object) { return $null }
    $p = $Object.PSObject.Properties[$Name]
    # The comma keeps an empty array an empty array instead of letting the pipeline drop it. So
    # assign the result before enumerating it: `@(Prop ...)` would wrap the array, not copy it.
    if ($p) { return , $p.Value } else { return $null }
}

# A ref name inside a REST path: `#`, `?` and `%` are legal in a branch name and would end the
# path; `/` stays, because the branches endpoints take a slashed name as it is.
function Esc([string]$Segment) { [uri]::EscapeDataString($Segment) -replace '%2F', '/' }

# Thrown for an answer that may change by waiting; the loop catches it, Fail is for the rest.
class TransientReadException : System.Exception {
    TransientReadException([string]$Message) : base($Message) {}
}

# The program and leading arguments that run -GhCommand as a child process. A .ps1 stand-in runs
# under this same pwsh, so the timeout and the kill below apply to it exactly as to a real gh.
function Resolve-Gh {
    $cmd = Get-Command $GhCommand -CommandType Application, ExternalScript -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if (-not $cmd) { Fail "cannot find gh as '$GhCommand'; is the GitHub CLI installed and on PATH?" }
    if ($cmd.CommandType -eq 'ExternalScript') {
        return @{ File = [Environment]::ProcessPath; Args = @('-NoProfile', '-NonInteractive', '-File', $cmd.Source) }
    }
    @{ File = $cmd.Source; Args = @() }
}

# One gh call as a child process, killed with its tree past -GhTimeoutSeconds. ArgumentList, not a
# command-line string, so a weak ETag (W/"...") keeps its quotes on Windows. Both streams are read
# asynchronously so a full stderr pipe cannot stall the child while stdout is drained.
function Invoke-Gh([string[]]$GhArgs) {
    $psi = [System.Diagnostics.ProcessStartInfo]::new($script:Gh.File)
    foreach ($a in $script:Gh.Args + $GhArgs) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = $script:Utf8
    $psi.StandardErrorEncoding = $script:Utf8
    # A gh that wants to prompt fails at once instead of sitting out the timeout.
    $psi.Environment['GH_PROMPT_DISABLED'] = '1'
    $proc = [System.Diagnostics.Process]::Start($psi)
    try {
        $proc.StandardInput.Close()
        $out = $proc.StandardOutput.ReadToEndAsync()
        $err = $proc.StandardError.ReadToEndAsync()
        $clock = [System.Diagnostics.Stopwatch]::StartNew()
        $ms = $GhTimeoutSeconds * 1000
        # EOF on both pipes is waited for under the same deadline: a grandchild holding a pipe open
        # would otherwise hang the read after gh itself exited.
        $finished = $proc.WaitForExit($ms) -and
            [System.Threading.Tasks.Task]::WaitAll([System.Threading.Tasks.Task[]]@($out, $err),
                [int][math]::Max(0, $ms - $clock.ElapsedMilliseconds))
        if (-not $finished) {
            try {
                $proc.Kill($true)
                [void]$proc.WaitForExit(5000)
            } catch [System.InvalidOperationException], [System.ComponentModel.Win32Exception], [System.AggregateException] {
                [Console]::Error.WriteLine("wait-pr $Repo#${Pr}: could not kill gh process $($proc.Id): $($_.Exception.Message)")
            }
            throw [TransientReadException]::new("gh api $($GhArgs[-1]) did not finish within $GhTimeoutSeconds s and was killed")
        }
        [pscustomobject]@{ Out = $out.Result; Err = $err.Result; Code = $proc.ExitCode }
    } finally {
        $proc.Dispose()
    }
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

    # Counted before the call: a call killed at its timeout may still have reached GitHub.
    if (-not $Free) { $script:Requests++ }
    # gh exits 1 on a 304 and on every 4xx, and writes "gh: HTTP <code>" to stderr. The status line
    # on stdout is what decides, so the exit code and stderr are kept only for the error message.
    $res = Invoke-Gh $ghArgs
    $code = $res.Code
    $err = @(($res.Err -split '\r?\n') | Where-Object { $_ }) -join ' '
    $text = $res.Out -replace "`r", ''

    if ($text -notmatch '^HTTP/\S+ (\d{3})') {
        throw [TransientReadException]::new("gh api $Path printed no HTTP status line (exit $code). $err")
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
        return , $script:Bodies[$Path]
    }
    if (($status -eq 403 -or $status -eq 429) -and $head -match '(?im)^x-ratelimit-remaining:[ \t]*0[ \t]*$') {
        Fail "gh api $Path answered HTTP $status with X-Ratelimit-Remaining 0: the rate budget every seat shares is spent, so this wait stops rather than poll it."
    }
    if ($status -ge 500 -or $status -eq 429) {
        throw [TransientReadException]::new("gh api $Path answered HTTP $status")
    }
    if ($status -lt 200 -or $status -ge 300) { Fail "gh api $Path answered HTTP $status. $err" }
    if (-not $body) { Fail "gh api $Path answered HTTP $status with an empty body." }

    # -NoEnumerate keeps a JSON array an array, even an empty one.
    $parsed = ConvertFrom-Json -InputObject $body -NoEnumerate
    $etag = [regex]::Match($head, '(?im)^etag:[ \t]*(.+)$')
    if ($etag.Success) {
        $script:Etags[$Path] = $etag.Groups[1].Value.Trim()
        $script:Bodies[$Path] = $parsed
    }
    return , $parsed
}

function Test-Merged($p) {
    $ms = [string](Prop $p 'mergeable_state')
    $sha = [string]$p.head.sha
    $state = "state=$($p.state) merged=$($p.merged) mergeable_state=$ms head=$sha"
    $needsPush = $null
    if ($Until -eq 'closed') {
        $met = $p.state -eq 'closed'
    } else {
        $met = $p.merged -eq $true
        if (-not $met -and $p.state -eq 'closed') { $script:ClosedUnmerged++ } else { $script:ClosedUnmerged = 0 }
        if ($script:ClosedUnmerged -ge 2) {
            Say $state
            Fail 'the PR was read as closed without merging on two checks in a row, so -Until merged will not be met.'
        }
        if ((Measure-NeedsPush $p.state $ms $sha) -ge 2) {
            $needsPush = "mergeable_state=$ms on two checks in a row of head $sha"
        }
    }
    @{ Met = $met; NeedsPush = $needsPush; State = $state; Summary = "head=$sha" }
}

# Counts reads of an open PR that cannot merge without a push, per head SHA, and returns the
# count. `unknown` and a missing value are GitHub still computing, so they neither count nor reset.
function Measure-NeedsPush([string]$State, [string]$Mergeable, [string]$Sha) {
    if ($Sha -cne $script:StaleSha) {
        $script:StaleSha = $Sha
        $script:StaleReads = 0
    }
    if ($State -ne 'open') {
        $script:StaleReads = 0
    } elseif ($Mergeable -eq 'dirty' -or $Mergeable -eq 'behind') {
        $script:StaleReads++
    } elseif ($Mergeable -and $Mergeable -ne 'unknown') {
        $script:StaleReads = 0
    }
    $script:StaleReads
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
    $statuses = @()
    $page = 1
    do {
        $b = Get-Rest "repos/$Repo/commits/$sha/status?per_page=100&page=$page"
        $list = Prop $b 'statuses'
        $batch = @($list)
        $statuses += $batch
        $page++
    } while ($batch.Count -gt 0 -and $statuses.Count -lt [int](Prop $b 'total_count'))

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
    $missing = @($script:Required | Where-Object { $reported -cnotcontains $_ })

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
    $branch = Get-Rest "repos/$Repo/branches/$(Esc $Base)"
    $classic = @()
    if ((Prop $branch 'protected') -eq $true) {
        $contexts = Prop (Prop (Prop $branch 'protection') 'required_status_checks') 'contexts'
        if ($null -eq $contexts) {
            Fail "base $Base is protected but its branch payload names no required_status_checks.contexts; that is not an empty required set."
        }
        $classic = @($contexts | ForEach-Object { [string]$_ })
    }
    $ruleset = @()
    $page = 1
    do {
        $rules = @(Get-Rest "repos/$Repo/rules/branches/$(Esc $Base)?per_page=100&page=$page" | ForEach-Object { $_ })
        $ruleset += @(
            $rules | Where-Object { (Prop $_ 'type') -eq 'required_status_checks' } |
                ForEach-Object { $checks = Prop (Prop $_ 'parameters') 'required_status_checks'; $checks } |
                ForEach-Object { [string](Prop $_ 'context') }
        )
        $page++
    } while ($rules.Count -ge 100)
    @($classic + $ruleset | Sort-Object -Unique -CaseSensitive)
}

try {
    # -SleepCommand would remove the interval floor and -GhTimeoutSeconds the per-call timeout.
    if ($env:MEFOR_WAIT_PR_TEST_SEAMS -ne '1') {
        $bound = $PSBoundParameters
        $seams = @('SleepCommand', 'GhTimeoutSeconds' | Where-Object { $bound.ContainsKey($_) })
        if ($seams) {
            Fail "$(($seams | ForEach-Object { "-$_ is a test seam" }) -join '; '); it needs MEFOR_WAIT_PR_TEST_SEAMS=1."
        }
    }
    $script:Gh = Resolve-Gh
    if ($IntervalSeconds -lt $MinIntervalSeconds) {
        Say "interval raised from $IntervalSeconds s to the $MinIntervalSeconds s floor"
        $IntervalSeconds = $MinIntervalSeconds
    }
    if ($IntervalSeconds -gt $MaxTotalMinutes * 60) {
        Say "interval lowered from $IntervalSeconds s to the $($MaxTotalMinutes * 60) s ceiling"
        $IntervalSeconds = $MaxTotalMinutes * 60
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

    $maxSeconds = $MaxMinutes * 60
    if ($maxSeconds -lt $IntervalSeconds) {
        Say "total wait raised from $MaxMinutes min to one interval, $IntervalSeconds s, so the wait waits at all"
        $maxSeconds = $IntervalSeconds
    }
    $clock = [System.Diagnostics.Stopwatch]::StartNew()
    $slept = 0
    $last = $null
    $base = $null
    $transients = 0
    $script:Required = @()
    while ($true) {
        try {
            $p = Get-Rest "repos/$Repo/pulls/$Pr"
            $prBase = [string]$p.base.ref
            if ($Until -eq 'checks-complete' -and $prBase -cne $base) {
                # $base moves only once the read has finished, so a read cut short is read again.
                $script:Required = @(Read-Required $prBase)
                $base = $prBase
                if ($script:Required.Count -eq 0) {
                    Say "no required contexts on $base; waiting on the visible checks only, which cannot see a check that has not started"
                } else {
                    Say "required contexts on ${base}: $($script:Required.Count)"
                }
            }
            $r = if ($Until -eq 'checks-complete') { Test-Checks $p } else { Test-Merged $p }
            $transients = 0
        } catch [TransientReadException] {
            $transients++
            if ($transients -ge 3) { Fail "three transient failures in a row, the last: $($_.Exception.Message)" }
            $r = @{ Met = $false; State = "transient, reading again next interval: $($_.Exception.Message)" }
        }
        if ($r.State -ne $last) {
            Say $r.State
            $last = $r.State
        }
        $accounting = "$($script:Requests) requests, $($script:NotModified) of them 304 and not counted"
        if ($r.Met) {
            Say "met: $Until. $($r.Summary). $accounting"
            exit 0
        }
        # Indexed, not dotted: only Test-Merged sets the key, and StrictMode throws on a missing one.
        if ($r['NeedsPush']) {
            Say "needs a push: $($r['NeedsPush']), so -Until merged will not be met without one. $accounting"
            exit 3
        }
        # Counted in intervals slept, so the last interval is waited too; the wall clock also ends
        # a wait whose reads, each cut off at its timeout, have added up past the ceiling.
        if ($slept + $IntervalSeconds -gt $maxSeconds -or $clock.Elapsed.TotalSeconds -gt $maxSeconds) {
            Say "timeout: $Until not met within $MaxMinutes min. $accounting"
            exit 2
        }
        if ($SleepCommand) { & $SleepCommand $IntervalSeconds } else { Start-Sleep -Seconds $IntervalSeconds }
        $slept += $IntervalSeconds
    }
} catch {
    Fail "$($_.Exception.Message)"
}
