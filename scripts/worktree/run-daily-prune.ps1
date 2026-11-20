# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Run prune-merged.ps1 once, log the transcript and the meaning of its exit code, and rotate old logs.

.DESCRIPTION
    This is the body of the daily scheduled task that install-daily-prune.ps1 registers. It exists as a
    tracked file rather than as text the installer manufactures, and that is the whole point of it.

    It was a base64 `-EncodedCommand` string built from a here-string inside the installer. Three
    independent review passes flagged the same shape, and they were right about all of it: the only copy
    of this logic lived inside a string, so it could not be diffed, could not be tested, could not be read
    out of Task Scheduler without decoding a blob, and mixed build-time with run-time interpolation where
    a single missing backtick silently freezes a value at install time. Ten lines of untestable logic in
    the one component whose job is deciding whether deletions happened is a bad trade at any size.

    IT DOES NOT DECIDE ANYTHING ABOUT THE SIBLINGS. Every safety judgement on them stays in
    prune-merged.ps1: what is merged, what is occupied, what is locked, what gets removed. This script
    starts that one, records what it said, and passes its exit code back, or 4 when the run stopped at
    its -StopAfterMinutes deadline.

    -RemoveFinishedClaudeWorktrees ADDS ONE OPT-IN STEP, and it is the only thing here that can touch
    .claude/worktrees. prune-merged.ps1 still removes nothing there; it lists the trees there that look
    finished, under REPORT-ONLY. After the prune run, this step runs prune-merged.ps1 AGAIN with -Json,
    in the same invocation, and takes that fresh list -- never a table from an earlier run. It keeps the
    rows under a `.claude/worktrees/` path segment and hands them to finished-worktree-removal.ps1, which
    re-checks each one immediately before acting and removes it with a plain `git worktree remove`, never
    with --force. That file's header lists the re-checks. Each removed or refused path is logged with its
    reason, then a summary line with the counts and the drive's free space. A refusal is data, not a
    failure, and leaves the exit code alone. Without -Apply the step only logs WOULD-REMOVE. With
    -Apply it refuses to run inside Claude Code, the same refusal install-daily-prune.ps1 carries. With
    the switch, a GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR or GIT_INDEX_FILE in the environment refuses the
    whole run before the prune starts, logged, with exit 2.

.PARAMETER RepoRoot
    The primary checkout to prune. Defaults to the value the shared liveness fence calls the primary --
    the SAME source prune-merged.ps1 checks its own -RepoRoot against -- so the two can never disagree.

.PARAMETER Apply
    Forwarded to prune-merged.ps1. Omitted, the run is a dry run that removes nothing. It also arms the
    -RemoveFinishedClaudeWorktrees step; without it, that step only reports.

.PARAMETER RemoveFinishedClaudeWorktrees
    Opt in to the .claude/worktrees step described above. Off by default.

.PARAMETER StopAfterMinutes
    Minutes after this run starts at which it stops. Optional; without it the run has no deadline of
    its own and starts both prune-merged.ps1 runs with `&`, unbounded. install-daily-prune.ps1 sets it
    inside the task's time limit; its header says why.

    With it, each prune-merged.ps1 run is a child process waited on for the time left to the deadline.
    One still running at the deadline is killed with its whole process tree, git included, and logged
    as `--- prune-merged.ps1 TIMED OUT after N min, killed at HH:mm:ss ---`, after what it printed.
    The kill is a hard one, the same Task Scheduler's limit would make, only earlier and logged. Under
    -Apply it can leave what the child was doing half done, and no later run is sure to report it: a
    worktree partly deleted before git deregistered it, a stale git lock file (index.lock,
    packed-refs.lock) in the primary that refuses later git commands until removed by hand, claims
    left behind, or a truncated orphan ledger. Past the deadline before the prune run, it is not
    started and the log says so.
    The .claude/worktrees step is skipped with one SKIPPED line when the prune run was not started or
    was killed, when the deadline passed before the listing run, or when the listing run was killed.
    Inside the step, past the deadline no further tree is started, and each one left is logged as
    NOT-REACHED (the next run lists them again). Every one of those stops still writes the exit line.
    A run that stopped at the deadline and earned no other code exits 4, DEADLINE; see $EXIT_DEADLINE
    below. Two deadline stops exit 1 instead: an -Apply prune run killed part way, the same rule the
    trap applies to an -Apply prune that started and did not exit, and a child the kill could not end,
    logged as `kill FAILED`, which may still be running.

.PARAMETER KeepLogs
    How many dated logs to keep. Older ones are deleted after each run.

.NOTES
    A kill from outside (Task Scheduler's time limit, a reboot) writes nothing; -StopAfterMinutes is
    there so the time limit is not reached.

    Exit codes: 0 to 3 are prune-merged.ps1's, passed through and explained by $EXIT_MEANING below. 4
    is this runner's own: the run stopped at its -StopAfterMinutes deadline, left work for the next
    run, and earned no other code. It replaces only a 0: a 1, 2 or 3 the run earned is the exit code
    even when the run also stopped at its deadline, and the log still records the stop.

.EXAMPLE
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs            # dry run, logged
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs -Apply     # actually prune
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs -RemoveFinishedClaudeWorktrees          # also list what it would remove
    pwsh -File scripts\worktree\run-daily-prune.ps1 -LogDir C:\logs -Apply -RemoveFinishedClaudeWorktrees   # and remove it
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [switch]$Apply,
    [switch]$RemoveFinishedClaudeWorktrees,
    [double]$IdleHours,
    [Parameter(Mandatory)][string]$LogDir,
    [string]$Label = 'MEFOR-Worktree-Prune',
    [int]$KeepLogs = 30,
    [ValidateRange(0.0001, 1440)][double]$StopAfterMinutes
)

$ErrorActionPreference = 'Stop'
# Set here so the trap below never reads a caller's variable of the same name.
$log = $null
$code = $null
$deadlineHit = $false
$pruneStarted = $false
# In UTC: Task Scheduler's limit counts elapsed time, and a local clock repeats an hour at the DST
# fall-back, which would put this deadline an hour past the kill.
$deadline = if ($PSBoundParameters.ContainsKey('StopAfterMinutes')) { [DateTime]::UtcNow.AddMinutes($StopAfterMinutes) } else { $null }

# The same refusal install-daily-prune.ps1 carries, for the one combination that removes Claude-managed
# trees: a session that can run this from a checkout it can edit could remove other sessions'
# .claude/worktrees trees with no reviewer, and worktree_gate.ps1 deliberately gives sessions no route
# to that population. The dry run stays usable in-session.
if ($env:CLAUDECODE -eq '1' -and $Apply -and $RemoveFinishedClaudeWorktrees) {
    throw "Refusing -Apply -RemoveFinishedClaudeWorktrees inside Claude Code: it removes Claude-managed worktrees. Run it from a plain terminal, or from the scheduled task install-daily-prune.ps1 registers. (Without -Apply it only reports, and is allowed.)"
}

# prune-merged.ps1 reports its verdict through the exit code, so a non-zero exit is DATA here, not a
# failure to be turned into a throw. Same reason that script sets this; the reason survives the call.
$PSNativeCommandUseErrorActionPreference = $false

. "$PSScriptRoot\..\coord\occupancy.ps1"

# What each exit code MEANS. prune-merged.ps1 owns the contract -- it defines $EXIT_OK/$EXIT_FAILED/
# $EXIT_REFUSED/$EXIT_ORPHANED -- and this is a second copy of it, which is a real cost and is deliberate:
# moving the logging into that 1502-line safety-critical script is the deeper fix and belongs in its own
# change. The drift that copy invites is held shut by a test instead:
# tests/test_worktree_install_daily_prune.py::test_the_exit_code_table_matches_prune_merged parses the
# constants out of prune-merged.ps1 and fails if this table stops matching. A second definition nobody can
# silently desync is a smaller problem than an unreviewable one.
$EXIT_MEANING = @{
    0 = 'OK'
    1 = 'FAILED -- something was attempted and did not fully succeed'
    2 = 'REFUSED -- safety could not be established, nothing was attempted'
    3 = 'ORPHANED DIRECTORY -- a worktree is broken on disk right now; needs a human'
}
# The runner's own code, kept out of the table above because prune-merged.ps1 never returns it. A
# deadline stop used to leave the code alone, which made a run that skipped work exit as if it had
# finished it. Exit-Run uses it only in place of a 0 (owner's Manager, 2026-11-19): a real failure
# matters more than a partial run, and deadline stops are expected most nights while a backlog drains.
# tests/test_worktree_install_daily_prune.py::test_the_runners_own_exit_code_is_not_one_of_prune_merged
# holds it apart from prune-merged.ps1's.
$EXIT_DEADLINE = 4
$EXIT_DEADLINE_MEANING = 'DEADLINE -- the run stopped at its -StopAfterMinutes deadline and left work for the next run; it earned no other code, and no killed run was an -Apply prune or survived its kill'

$prune = Join-Path $PSScriptRoot 'prune-merged.ps1'
if (-not (Test-Path -LiteralPath $prune)) { throw "prune-merged.ps1 not found beside this script: $prune" }

$mode = if ($Apply) { 'APPLY' } else { 'DRYRUN' }
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
$log = Join-Path $LogDir ("prune-" + (Get-Date -Format 'yyyy-MM-dd') + ".log")

# Writes the exit line (while the log can be written), trims the log directory, and exits.
function Exit-Run([int]$Code) {
    # Set by every deadline stop, before its log line, so a failed write still carries it here.
    if ($deadlineHit -and $Code -eq 0) { $Code = $EXIT_DEADLINE }
    $meaning = if ($Code -eq $EXIT_DEADLINE) { $EXIT_DEADLINE_MEANING } elseif ($EXIT_MEANING.ContainsKey($Code)) { $EXIT_MEANING[$Code] } else { "UNKNOWN exit code $Code" }
    try { "=== exit $Code ($meaning) at $(Get-Date -Format 'HH:mm:ss') ===" | Add-Content -LiteralPath $log }
    catch [System.Management.Automation.RuntimeException], [System.IO.IOException], [System.UnauthorizedAccessException] {
        Write-Error -Message "exit $Code ($meaning); the log could not take this line: $($_.Exception.Message)" -ErrorAction Continue
    }
    # Keep the log directory bounded. -ErrorAction SilentlyContinue because a log a human has open must
    # not turn a successful prune into a failed task run.
    Get-ChildItem -LiteralPath $LogDir -Filter 'prune-*.log' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending |
        Select-Object -Skip $KeepLogs |
        Remove-Item -Force -ErrorAction SilentlyContinue
    exit $Code
}

# Runs prune-merged.ps1 with $ChildArgs as a child process and waits on it until $deadline, which `&`
# cannot do. Used only when there is a deadline; without one the run keeps its `&` calls unchanged.
# Started the way `&` starts it: the same pwsh, on the same console, in the caller's location (so a
# relative -RepoRoot resolves the same), inheriting the environment, decoding output as `&` does.
#
# Its stdout and stderr go straight to two files beside the log, written by the child itself, so each
# keeps its own order, and a run killed from outside still leaves on disk what the child printed (in
# prune-child-<pid>.out.txt and .err.txt). Read back after the child ends and written to the log here:
# stdout's lines (with -LogStdout), then stderr's, each prefixed with $StderrPrefix. The files are deleted
# only once that write succeeded, so a throw or a Stop before it leaves them on disk instead. Returns
# the stdout lines for a caller that parses them. The one thing lost against `*>&1` is how the two
# streams interleaved. Lines collected from the
# process's own stream events came back out of order even within one stream (156 of 20,000 measured
# 2026-11-19), which scrambled the listing run's multi-line JSON.
#
# A child still running at the deadline is killed with its whole process tree, since a hung `git fetch`
# under it is the likely hang.
function Invoke-BoundedPrune([object[]]$ChildArgs, [switch]$LogStdout, [string]$StderrPrefix = '') {
    # Start-Process joins its arguments with spaces and quotes none, so quote each as the C runtime
    # splits them: a run of backslashes before a quote, or at the end, is doubled.
    $argLine = (@('-NoProfile', '-NonInteractive', '-ExecutionPolicy', 'Bypass', '-File', $prune) + $ChildArgs | ForEach-Object {
            $a = [string]$_
            if ($a -and $a -notmatch '[\s"]') { $a } else { '"' + ($a -replace '(\\*)"', '$1$1\"' -replace '(\\+)$', '$1$1') + '"' }
        }) -join ' '
    # Absolute: the FileStream below resolves a relative path against the process directory.
    $logDirFull = (Resolve-Path -LiteralPath $LogDir).ProviderPath
    # Unique per call: a descendant of an earlier run that still holds its file must not write into this one.
    $tag = "$PID-$([guid]::NewGuid().ToString('N'))"
    $out = Join-Path $logDirFull "prune-child-$tag.out.txt"
    $err = Join-Path $logDirFull "prune-child-$tag.err.txt"
    $p = $null
    $timedOut = $false
    $killedAt = $null
    $killFault = $null
    $stillRunning = $false
    $logged = $false
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    try {
        $p = Start-Process -FilePath (Get-Process -Id $PID).Path -ArgumentList $argLine -NoNewWindow -PassThru `
            -WorkingDirectory (Get-Location -PSProvider FileSystem).ProviderPath -RedirectStandardOutput $out -RedirectStandardError $err
        # Read once now: a Process from Start-Process that never had its handle read can report no exit code.
        $null = $p.Handle
        # In slices, so a Stop of this runspace (Ctrl+C, a host's Stop) is not held up until the child ends.
        while (-not $p.WaitForExit(250)) {
            if ([DateTime]::UtcNow -lt $deadline) { continue }
            $killedAt = Get-Date
            try { $p.Kill($true) }
            catch [System.InvalidOperationException], [System.ComponentModel.Win32Exception], [System.AggregateException], [System.NotSupportedException] {
                $killFault = $_.Exception.Message
            }
            # Bounded, so the run still reaches its exit line if the kill did not take.
            $null = $p.WaitForExit(15000)
            # A child that ended on its own between the last wait and the kill was not timed out, and its
            # exit code is real. TerminateProcess, which Kill uses on Windows, leaves -1. Windows only, as
            # the scheduled task is: elsewhere Kill sends SIGKILL, the code reads 137, and this would take
            # a killed child for one that exited.
            $stillRunning = -not $p.HasExited
            $timedOut = $stillRunning -or $p.ExitCode -eq -1
            break
        }
        $sw.Stop()
        $lines = @(foreach ($f in @(@{ Path = $out; Stderr = $false }, @{ Path = $err; Stderr = $true })) {
            if (-not (Test-Path -LiteralPath $f.Path)) { continue }
            # ReadWrite sharing: a descendant the kill missed may still hold the file open for writing.
            $fs = [System.IO.FileStream]::new($f.Path, 'Open', 'Read', 'ReadWrite, Delete')
            try {
                $reader = [System.IO.StreamReader]::new($fs, [Console]::OutputEncoding)
                while ($null -ne ($line = $reader.ReadLine())) { [pscustomobject]@{ Stderr = $f.Stderr; Text = $line } }
            }
            finally { $fs.Dispose() }
        })
        $toLog = @($lines | Where-Object { $_.Stderr -or $LogStdout } | ForEach-Object { if ($_.Stderr) { "$StderrPrefix$($_.Text)" } else { $_.Text } })
        if ($toLog.Count -gt 0) { $toLog | Add-Content -LiteralPath $log }
        $logged = $true
        [pscustomobject]@{
            TimedOut     = $timedOut
            StillRunning = $stillRunning
            Pid          = $p.Id
            ExitCode     = if ($timedOut) { $null } else { $p.ExitCode }
            Minutes      = $sw.Elapsed.TotalMinutes
            KilledAt     = $killedAt
            KillFault    = $killFault
            Stdout       = @($lines | Where-Object { -not $_.Stderr } | ForEach-Object { $_.Text })
        }
    }
    finally {
        # Reached on a throw or a runspace Stop too: never leave the child running behind the run.
        if ($null -ne $p -and -not $p.HasExited) {
            try { $p.Kill($true) }
            catch [System.InvalidOperationException], [System.ComponentModel.Win32Exception], [System.AggregateException], [System.NotSupportedException] {
                Write-Error -Message "could not kill prune-merged.ps1 (pid $($p.Id)): $($_.Exception.Message)" -ErrorAction Continue
            }
        }
        if ($null -ne $p) { $p.Dispose() }
        if ($logged) { Remove-Item -LiteralPath $out, $err -Force -ErrorAction SilentlyContinue }
    }
}

# A child the kill could not end may still be running, unobserved, so the run is a failure: at least 1.
function Set-KillFailedCode([pscustomobject]$Run) {
    if ($Run.KillFault -or $Run.StillRunning) { $script:code = [math]::Max([int]$script:code, 1) }
}

# The timed line a child still running at the deadline leaves, after whatever it printed. "killed" only
# when the kill took; otherwise it says the child may still be running. Invariant culture, so the minutes
# read the same under any locale.
function Write-TimedOut([pscustomobject]$Run) {
    $minutes = $Run.Minutes.ToString('0.0', [cultureinfo]::InvariantCulture)
    $at = $Run.KilledAt.ToString('HH:mm:ss')
    $what = if ($Run.KillFault -or $Run.StillRunning) {
        $fault = if ($Run.KillFault) { ": $($Run.KillFault)" } else { ': it had not exited 15 s later' }
        "kill FAILED at $at, so it may still be running (pid $($Run.Pid))$fault"
    }
    else { "killed at $at" }
    "--- prune-merged.ps1 TIMED OUT after $minutes min, $what ---" | Add-Content -LiteralPath $log
}

# A terminating error still leaves its reason and an exit line in the log, rather than only on a stderr
# nothing captures. A trap covers its whole scope, lines above it included, so a throw before the log
# path exists (the CLAUDECODE refusal) is passed on unchanged by `break`.
trap {
    if (-not $log) { break }
    $fault = "$($_.Exception.Message) (at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber))"
    try { "=== $Label $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') STOPPED on an unhandled error: $fault ===" | Add-Content -LiteralPath $log }
    catch [System.Management.Automation.RuntimeException], [System.IO.IOException], [System.UnauthorizedAccessException] {
        Write-Error -Message "the log could not take the STOPPED line either: $($_.Exception.Message)" -ErrorAction Continue
    }
    Write-Error -Message $fault -ErrorAction Continue
    # 2 promises nothing was removed: true before the prune started and on a dry run. Once an -Apply
    # prune has started, even if it has not exited, 1, the rule the step's own refusal follows. Never
    # below a code already set, which already carries every row the step handled (raised per row, below).
    Exit-Run ([math]::Max([int]$code, $(if (-not $pruneStarted -or -not $Apply) { 2 } else { 1 })))
}

# BEFORE ANYTHING ASKS GIT, the primary's resolution below included: the helper refuses these too, but
# by then the prune would already have run under them. Refused into the LOG, with exit 2 (nothing
# attempted), so a scheduled run that hits it leaves a line saying why rather than a bare exit code.
if ($RemoveFinishedClaudeWorktrees) {
    $stepFault = ''
    try { . (Join-Path $PSScriptRoot 'finished-worktree-removal.ps1') }
    catch { $stepFault = "the -RemoveFinishedClaudeWorktrees step's scripts could not be loaded (a defect, not a safety finding): $($_.Exception.Message)" }
    if (-not $stepFault) {
        try { Assert-NoGitRedirect 'run-daily-prune.ps1 -RemoveFinishedClaudeWorktrees' }
        catch { $stepFault = $_.Exception.Message }
    }
    if ($stepFault) {
        "=== $Label $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') mode=$mode REFUSED before the prune; nothing was attempted: $stepFault ===" |
            Add-Content -LiteralPath $log
        Write-Error -Message $stepFault -ErrorAction Continue
        Exit-Run 2
    }
}

# Resolve the primary through the SAME helper prune-merged.ps1 validates against (occupancy.ps1's
# PrimaryPath, which is git's first `worktree list` entry). Resolving it any other way -- a
# --git-common-dir parent, say -- gives an answer that is right today by agreement rather than by
# construction, and the failure when they diverge is silent: prune-merged.ps1:236 exits REFUSED, the task
# logs REFUSED every night forever, and nothing anywhere reports that the scheduler is pointed wrong.
if (-not $RepoRoot) {
    $occ = Get-WorktreeOccupancy -Repo $PSScriptRoot
    if (-not $occ.RepoFound) { throw "Not inside a git repository: $PSScriptRoot" }
    $RepoRoot = $occ.PrimaryPath
}

$pruneArgs = @('-RepoRoot', $RepoRoot)
if ($Apply) { $pruneArgs += '-Apply' }
if ($PSBoundParameters.ContainsKey('IdleHours')) { $pruneArgs += @('-IdleHours', $IdleHours) }

# A scheduled task has nobody to answer an HTTPS credential prompt, in a terminal or in Git Credential
# Manager's window, so make prune-merged.ps1's `git fetch` (and every git it starts, which inherit this)
# fail instead of waiting until the task's time limit kills the run. hygiene-report.ps1 sets the same
# two. An SSH origin's passphrase or host-key prompt is not covered. The 2026-11-17 log stops right
# after "Fetching origin (--prune)...", which a fetch waiting on a prompt would explain; that is not
# established. A hand run with `&` shares the caller's process, so the `finally` below puts both back
# as they were, as alloc.ps1 does. Measured: it runs on Exit-Run's `exit`, on a runspace Stop, and on a
# throw, where it runs BEFORE the trap, so the trap and its Exit-Run see the caller's values again.
$hadPromptEnv = @{}
foreach ($k in 'GIT_TERMINAL_PROMPT', 'GCM_INTERACTIVE') {
    $hadPromptEnv[$k] = if (Test-Path -LiteralPath "Env:\$k") { [Environment]::GetEnvironmentVariable($k) } else { $null }
    $hadPromptEnv["$k.exists"] = Test-Path -LiteralPath "Env:\$k"
}
try {
    $env:GIT_TERMINAL_PROMPT = '0'
    $env:GCM_INTERACTIVE = 'never'
    $deadlineText = if ($deadline) { " stopAfter=$($deadline.ToLocalTime().ToString('HH:mm:ss'))" } else { '' }
    "=== $Label $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss') mode=$mode repo=$RepoRoot$deadlineText ===" | Add-Content -LiteralPath $log
    # Why the run stopped short of its end, once it has; each stop below sets it and skips what follows.
    # A deadline stop sets $deadlineHit BEFORE its log line, as the rows raise the code before theirs.
    $stopReason = $null
    if ($deadline -and [DateTime]::UtcNow -ge $deadline) {
        $deadlineHit = $true
        "--- prune-merged.ps1 NOT STARTED, the run's deadline ($($deadlineText.Trim())) had passed ---" | Add-Content -LiteralPath $log
        $stopReason = "the run's deadline ($($deadlineText.Trim())) passed before the prune run"
    }
    else {
        # A marker on each side of the prune-merged.ps1 run, which prints nothing between its fetch line and
        # its table. A log that ends after the first marker, with no exit or TIMED OUT marker, was stopped
        # inside that run from outside.
        "--- prune-merged.ps1 running ---" | Add-Content -LiteralPath $log
        $pruneStarted = $true
        if ($deadline) {
            $run = Invoke-BoundedPrune $pruneArgs -LogStdout
            if ($run.TimedOut) {
                $deadlineHit = $true
                # An -Apply prune killed part way attempted something and did not finish: 1, as the trap
                # rules for an -Apply prune that started and did not exit. Set before the line, as the rows do.
                if ($Apply) { $code = [math]::Max([int]$code, 1) }
                Set-KillFailedCode $run
                Write-TimedOut $run
                $stopReason = "prune-merged.ps1 was still running at the run's deadline ($($deadlineText.Trim()))"
            }
            else { $code = $run.ExitCode }
        }
        else {
            & (Get-Process -Id $PID).Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $prune @pruneArgs *>&1 |
                Add-Content -LiteralPath $log
            $code = $LASTEXITCODE
        }
        if (-not $stopReason) { "--- prune-merged.ps1 exit $code at $(Get-Date -Format 'HH:mm:ss') ---" | Add-Content -LiteralPath $log }
    }

    if ($RemoveFinishedClaudeWorktrees) { "--- finished .claude/worktrees: mode=$mode ---" | Add-Content -LiteralPath $log }
    # Read before the listing run too, which is itself a full prune-merged.ps1 run: started past the deadline
    # it would be killed at once, and every row it listed would come back NOT-REACHED anyway.
    if ($RemoveFinishedClaudeWorktrees -and -not $stopReason -and $deadline -and [DateTime]::UtcNow -ge $deadline) {
        $deadlineHit = $true
        $stopReason = "the run's deadline ($($deadlineText.Trim())) passed before the listing run"
    }
    if ($RemoveFinishedClaudeWorktrees -and -not $stopReason) {
        # A FRESH list, from a second prune-merged.ps1 run in this invocation, after the prune above. Always
        # a dry run (-Json without -Apply) and -SkipGh: the report-only set does not read merge signals.
        $listArgs = @('-RepoRoot', $RepoRoot, '-Json', '-SkipGh')
        if ($PSBoundParameters.ContainsKey('IdleHours')) { $listArgs += @('-IdleHours', $IdleHours) }
        if ($deadline) {
            $run = Invoke-BoundedPrune $listArgs -StderrPrefix '  stderr: '
            $listExit = $run.ExitCode
            $listOut = $run.Stdout
        }
        else {
            $raw = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -ExecutionPolicy Bypass -File $prune @listArgs 2>&1)
            $listExit = $LASTEXITCODE
            $listOut = @($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] })
            $listErr = @($raw | Where-Object { $_ -is [System.Management.Automation.ErrorRecord] })
            if ($listErr.Count -gt 0) { $listErr | ForEach-Object { "  stderr: $_" } | Add-Content -LiteralPath $log }
        }
        if ($deadline -and $run.TimedOut) {
            $deadlineHit = $true
            Set-KillFailedCode $run
            Write-TimedOut $run
            $stopReason = "the listing run was still running at the run's deadline ($($deadlineText.Trim()))"
        }
    }

    # Every deadline stop has set $deadlineHit already; Exit-Run turns it into 4 where the code is still 0.
    if ($stopReason) {
        if ($RemoveFinishedClaudeWorktrees) {
            "=== finished .claude/worktrees: SKIPPED, $stopReason; no .claude/worktrees tree was attempted ===" | Add-Content -LiteralPath $log
        }
    }
    elseif ($RemoveFinishedClaudeWorktrees) {
        $listing = $null
        try { $listing = ($listOut -join "`n") | ConvertFrom-Json -ErrorAction Stop }
        catch { "  could not parse the listing run's JSON (exit $listExit): $($_.Exception.Message)" | Add-Content -LiteralPath $log }

        if ($null -eq $listing -or $null -eq $listing.fence -or $null -eq $listing.fence.idleHours) {
            # Not a refusal of one tree but of the whole step. 2 promises nothing was removed, which holds
            # only on a dry run: under -Apply the prune above may already have removed siblings, so the
            # refusal is reported as 1, the same rule prune-merged.ps1 applies to its own refusals.
            "=== finished .claude/worktrees: SKIPPED, the finished list could not be read; no .claude/worktrees tree was attempted ===" | Add-Content -LiteralPath $log
            $code = [math]::Max($code, $(if ($Apply) { 1 } else { 2 }))
        }
        else {
            $finished = @($listing.reportOnly | Where-Object { $_.claudeManaged -eq $true })
            $outside = @($listing.reportOnly).Count - $finished.Count
            "  listed finished: $($finished.Count) under .claude/worktrees; $outside elsewhere, left alone; $($listing.counts.reportOnlyHeld) withheld by prune-merged.ps1 (listing exit $listExit)" |
                Add-Content -LiteralPath $log

            # Never the worktree this run executes from, nor the one the shell stands in. The scheduled task
            # runs from the primary, which is refused anyway; a hand run from a worktree must not remove it.
            $protect = @($PSScriptRoot, (Get-Location).Path) | ForEach-Object {
                $top = & git -C $_ rev-parse --show-toplevel 2>$null
                if ($LASTEXITCODE -eq 0 -and $top) { ([string]$top).Trim() }
            }
            # The helper returns each input path unchanged, so the raw path is the key.
            $why = @{}
            foreach ($f in $finished) { $why[$f.path] = $f }

            # Logged per row as the helper emits it, not after it returns: a run killed part way still leaves
            # the record of every tree it already removed.
            $rows = @(Invoke-FinishedWorktreeRemoval -Primary $RepoRoot -Paths @($finished | ForEach-Object { $_.path }) `
                    -IdleHours ([double]$listing.fence.idleHours) -Protect $protect -Apply:$Apply -StopAt $deadline | ForEach-Object {
                    $f = $why[$_.Path]
                    $detail = if ($_.Outcome -in 'REMOVED', 'WOULD-REMOVE') { "$($_.Reason) [$($f.branch)]; listed because: $($f.whyFinished)" } else { $_.Reason }
                    # The code is raised here, per row and BEFORE the row's log line, so an error later in the
                    # run, a failed log write included, reaches the trap with it. A deregistered tree still on
                    # disk is an orphan, 3. A tree the deadline left marks a deadline stop. A 2 from the
                    # prune says nothing was attempted, which a REMOVED, FAILED or DECLINED row makes false,
                    # so 1. A failure is at least 1. Otherwise the code never goes lower, and a refusal
                    # changes nothing.
                    if ($_.Outcome -eq 'ORPHANED') { $script:code = [math]::Max([int]$script:code, 3) }
                    elseif ($_.Outcome -eq 'NOT-REACHED') { $script:deadlineHit = $true }
                    elseif ($_.Outcome -in 'REMOVED', 'FAILED', 'DECLINED') {
                        if ([int]$script:code -eq 2) { $script:code = 1 }
                        elseif ($_.Outcome -eq 'FAILED') { $script:code = [math]::Max([int]$script:code, 1) }
                    }
                    $lines = @("  {0,-12} {1} -- {2}" -f $_.Outcome, $_.Path, $detail)
                    if ($_.Outcome -eq 'WOULD-REMOVE') { $lines += "               would run: $($_.Command)" }
                    $lines | Add-Content -LiteralPath $log
                    $_
                })

            $byOutcome = @{}
            foreach ($r in $rows) { $byOutcome[$r.Outcome] = 1 + [int]$byOutcome[$r.Outcome] }
            $n = { param($o) [int]$byOutcome[$o] }
            $free = 'unknown'
            try {
                $drive = [System.IO.DriveInfo]::new([System.IO.Path]::GetPathRoot($RepoRoot))
                $free = "{0:N1} GB free on {1}" -f ($drive.AvailableFreeSpace / 1GB), $drive.Name
            }
            catch [System.ArgumentException], [System.IO.IOException], [System.UnauthorizedAccessException] {
                $free = "free space unreadable: $($_.Exception.Message)"
            }
            "=== finished .claude/worktrees: mode=$mode listed=$($finished.Count) removed=$(& $n 'REMOVED') wouldRemove=$(& $n 'WOULD-REMOVE') refused=$(& $n 'REFUSED') declined=$(& $n 'DECLINED') failed=$(& $n 'FAILED') orphaned=$(& $n 'ORPHANED') notReached=$(& $n 'NOT-REACHED'); $free ===" |
                Add-Content -LiteralPath $log
        }
    }

    Exit-Run $code
}
finally {
    foreach ($k in 'GIT_TERMINAL_PROMPT', 'GCM_INTERACTIVE') {
        if ($hadPromptEnv["$k.exists"]) { [Environment]::SetEnvironmentVariable($k, $hadPromptEnv[$k]) }
        else { Remove-Item -LiteralPath "Env:\$k" -ErrorAction SilentlyContinue }
    }
}
