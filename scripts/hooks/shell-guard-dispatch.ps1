# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    PreToolUse dispatcher: run several shell-call guards in ONE pwsh process, unchanged.

.DESCRIPTION
    WHY THIS EXISTS. Every Bash and PowerShell tool call used to start one pwsh per guard, and pwsh
    startup is most of the cost. Measured 2026-10-17 on mefordev01, a loaded box, with
    System.Diagnostics.Process.TotalProcessorTime over 15 sequential launches each: a bare
    `pwsh -NoProfile -Command exit` took a median 484 ms CPU, each guard's own launch 609-828 ms,
    so the three cost about 2,000 ms per tool call; this file running all three took 828-922 ms.

    THE GUARDS' CODE IS NOT EDITED, AND EACH STILL RUNS STANDALONE. The settings file passes each
    guard's path as an argument, in order. Each one is invoked with `&`, which gives it its own
    script scope, so its Set-StrictMode, $ErrorActionPreference and functions stay inside it --
    the two guards that both define Hide-QuotedSpans do not see each other's. A guard reads its
    payload from [Console]::In and writes its decision to [Console]::Out, so before each guard
    stdin is replaced with a fresh reader over the payload this file read once, and stdout with a
    buffer. `exit` inside a guard ends that guard's script, not this process (measured).

    ***SCOPE IS ISOLATED; THE PROCESS IS NOT.*** At least these are shared by every guard in the
    run, and none of the guards wired today touches them: the current location, environment
    variables, the Console encodings (setting [Console]::OutputEncoding rebuilds Console.Out, so
    the guard's writes would bypass the buffer), and [Environment]::Exit. A guard that needs any
    of them belongs in its own handler, not on this list.

    THIS SCRIPT SETS NO STRICT MODE AND NO ERROR PREFERENCE, ON PURPOSE. A child scope inherits
    both, and block-blanket-git-stage.ps1 runs with neither when it is its own process. Its own
    variables carry a `ShellGuard` prefix for the same reason: PowerShell scoping is dynamic, so a
    guard that read a name before assigning it would otherwise see this file's value.

    A DECISION IS A PreToolUse JSON OBJECT, NOT ANY OUTPUT. Claude Code reads a hook's stdout as a
    decision only when it parses as one, so a guard's stray text decided nothing when that guard
    was its own process. Here it must not decide anything either -- above all it must not end the
    run, or one guard's chatter would silence the guards after it. Pipeline output from a guard is
    discarded for the same reason.

    THE FIRST DENY WINS AND ENDS THE RUN, AND SO DOES A BLOCKING EXIT. The rest are not started,
    because a guard that ran long after a deny could push the hook past its timeout, and a hook
    that times out lets the command run -- an already-reached deny turned into an allow. The cost
    is that a command two guards would refuse shows one reason, and the retry shows the other.
    A guard's `exit 2` is read as Claude Code's blocking exit and passed on; its stderr already
    went to this process's stderr. An exit is told apart from a native command's code by `$?`:
    measured 2026-10-17, `$?` after `& script` is false only when the script ran `exit N` with N
    non-zero, and stays true after a git call that failed or a Write-Error. $LASTEXITCODE alone
    cannot tell them apart, and worktree_gate.ps1 runs git.
    A non-deny decision (`ask`, `allow`) is kept, the first one wins, and it is written once every
    guard has run.

    FAIL-OPEN PER GUARD, AND VISIBLE. A guard that throws, exits non-zero other than 2, or whose
    path does not exist contributes an allow, and the others still run. Each failure is written to
    stderr, and when no guard decided anything the run exits 1. That is the non-blocking hook
    error Claude Code showed for a separate guard process that failed to start or crashed, so a
    broken guard is still reported rather than silently off.

    `--user-hook=worktree_gate` RUNS THE GATE THE ACCOUNT INSTALLED, AND PROVES IT RAN, PER CALL.
    It names ~/.claude/hooks/worktree_gate.ps1, where scripts/worktree/install-gate.ps1 puts the
    gate, and runs it only when this account DELEGATES it: the account's settings.json
    ($env:CLAUDE_CONFIG_DIR, else ~/.claude) contains `shell-guard-proof`, which the installer
    writes into the account's own Bash|PowerShell entry. That entry still runs for every call, in
    parallel with this file. It stands down only when it finds, in
    <account>/shell-guard-proof/, a proof named by THIS call's tool_use_id, written after it started
    waiting, holding this session's id. This file writes that proof (`<tool_use_id>.ok`) only when
    the gate it ran for this payload finished normally with nothing on stdout -- a silent allow.
    Anything else (a decision, an exit, a throw, a missing gate) writes `<tool_use_id>.run`, which
    tells the entry to stop waiting and run the gate itself. So a missing, failing or slow copy of
    this file leaves the account's entry running the gate; install-gate.ps1 says how it waits.
    `<session id>.session` tells the entry that this session's dispatcher runs the gate at all, so
    a project without this file costs no wait. It is a hint, never a proof: forged or stale, it
    only makes the entry wait before running the gate. An account that does not delegate runs the
    gate itself, and this file skips it.

    ORDER IS THE SETTINGS FILE'S: THE WORKTREE GATE FIRST, THEN THE BOUNDED GUARD. The account's
    entry is waiting on the gate's proof, so the gate must not queue behind guards that could use
    up the wait. It parsed whatever it was given when it ran alone, so going first costs it
    nothing. block-blanket-git-stage.ps1 comes next: it refuses an over-long payload, which keeps a
    huge payload from the two guards after it that parse whatever they are given. That guard's own
    read stops at its cap, but THIS file reads all of stdin first, so on the wired path the read
    itself is not bounded; only the parse is. The timeout in settings.json is the guards' former
    per-guard timeouts summed, so a run in which every guard finishes inside its old budget still
    finishes inside this one.

    WIRING IS NOT ASSERTED HERE ON PURPOSE. Which guards run is a property of settings.json.
    ASCII-only on purpose (PS 5.1 ANSI-read lesson); run under pwsh 7 by the hook.
#>
param(
    [Parameter(ValueFromRemainingArguments = $true)]
    [string[]]$ShellGuardPaths
)

$ShellGuardStdout = [Console]::Out
try {
    $ShellGuardPayload = [Console]::In.ReadToEnd()
} catch {
    exit 0
}

function Write-ShellGuardFailure([string]$Path, [string]$Why) {
    [Console]::Error.WriteLine("shell-guard-dispatch: guard '$Path' failed open: $Why")
}

$ShellGuardHome = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
$ShellGuardAccount = if ($env:CLAUDE_CONFIG_DIR) { $env:CLAUDE_CONFIG_DIR } else { Join-Path $ShellGuardHome '.claude' }
$ShellGuardProofDir = Join-Path $ShellGuardAccount 'shell-guard-proof'
# The same patterns the account's bash entry uses, so both name the same files; a payload they read
# differently only costs the entry its wait.
$ShellGuardSession = if ($ShellGuardPayload -cmatch '"session_id"\s*:\s*"(?<v>[A-Za-z0-9-]{1,100})"') { $Matches['v'] } else { $null }
$ShellGuardCall = if ($ShellGuardPayload -cmatch '"tool_use_id"\s*:\s*"(?<v>[A-Za-z0-9_-]{1,100})"') { $Matches['v'] } else { $null }
# Scoping is dynamic, so a guard reading $Matches before its own first match would see ours.
$Matches = $null

function Write-ShellGuardProof([string]$Kind) {
    # Kind 'ok' stands the account's entry down for this call; 'run' tells it to run the gate now.
    if (-not $ShellGuardSession -or -not $ShellGuardCall) { return }
    try {
        $final = Join-Path $ShellGuardProofDir "$ShellGuardCall.$Kind"
        $part = "$final.$PID.tmp"
        # Written whole, then renamed, so the entry never reads a half-written proof.
        [System.IO.File]::WriteAllText($part, "$ShellGuardSession`n")
        [System.IO.File]::Move($part, $final)
    } catch {
        # No proof only costs the entry its own run of the gate.
        [Console]::Error.WriteLine("shell-guard-dispatch: could not write the gate's proof: $($_.Exception.Message)")
    }
}

function Clear-ShellGuardProofs {
    # Every call leaves files behind, so prune at most every 10 minutes: proofs and waits older
    # than that, and session hints older than 30 days. A session older than that only waits.
    try {
        $stamp = Join-Path $ShellGuardProofDir 'pruned'
        $calls = [DateTime]::UtcNow.AddMinutes(-10)
        # A missing stamp reads as 1601, so it prunes.
        if ([System.IO.File]::GetLastWriteTimeUtc($stamp) -gt $calls) { return }
        [System.IO.File]::WriteAllText($stamp, '')
        $sessions = [DateTime]::UtcNow.AddDays(-30)
        foreach ($f in [System.IO.Directory]::GetFiles($ShellGuardProofDir)) {
            $cutoff = if ($f.EndsWith('.session')) { $sessions } else { $calls }
            if ([System.IO.File]::GetLastWriteTimeUtc($f) -lt $cutoff) {
                try { [System.IO.File]::Delete($f) } catch { $null = $_ }
            }
        }
    } catch {
        $null = $_
    }
}

$ShellGuardFailed = $false
$ShellGuardKept = $null
# With no arguments the parameter is $null, and @($null) is one empty entry, not none.
foreach ($ShellGuardPath in @($ShellGuardPaths | Where-Object { $_ })) {
    # Non-null only for the gate: the proof its run leaves for the account's entry.
    $ShellGuardProof = $null
    if ($ShellGuardPath -ceq '--user-hook=worktree_gate') {
        $ShellGuardPath = Join-Path $ShellGuardHome '.claude/hooks/worktree_gate.ps1'
        $ShellGuardHint = if ($ShellGuardSession) { Join-Path $ShellGuardProofDir "$ShellGuardSession.session" } else { $null }
        $ShellGuardDelegated = $false
        try {
            $ShellGuardDelegated = [System.IO.File]::ReadAllText((Join-Path $ShellGuardAccount 'settings.json')).Contains('shell-guard-proof')
        } catch {
            # No readable account settings: nothing delegates, so the gate is not this run's.
            $null = $_
        }
        if (-not $ShellGuardDelegated) {
            # An entry still waiting on this session's hint is told to stop waiting.
            if ($ShellGuardHint -and (Test-Path -LiteralPath $ShellGuardHint)) {
                Write-ShellGuardProof 'run'
                try { [System.IO.File]::Delete($ShellGuardHint) } catch { $null = $_ }
            }
            continue
        }
        $ShellGuardProof = 'run'
        if ($ShellGuardHint) {
            try {
                $null = [System.IO.Directory]::CreateDirectory($ShellGuardProofDir)
                if (-not (Test-Path -LiteralPath $ShellGuardHint)) { [System.IO.File]::WriteAllText($ShellGuardHint, '') }
                Clear-ShellGuardProofs
            } catch {
                [Console]::Error.WriteLine("shell-guard-dispatch: could not record the session hint: $($_.Exception.Message)")
            }
        }
    } elseif ($ShellGuardPath.StartsWith('--')) {
        Write-ShellGuardFailure $ShellGuardPath 'unknown option'
        $ShellGuardFailed = $true
        continue
    }
    try {
        if (-not (Test-Path -LiteralPath $ShellGuardPath -PathType Leaf)) {
            Write-ShellGuardFailure $ShellGuardPath 'no such file'
            $ShellGuardFailed = $true
            continue
        }
        $ShellGuardBuffer = [System.IO.StringWriter]::new()
        $global:LASTEXITCODE = 0
        try {
            [Console]::SetIn([System.IO.StringReader]::new($ShellGuardPayload))
            [Console]::SetOut($ShellGuardBuffer)
            $null = & $ShellGuardPath
            $ShellGuardCompleted = $?
        } catch {
            Write-ShellGuardFailure $ShellGuardPath $_.Exception.Message
            $ShellGuardFailed = $true
            continue
        } finally {
            [Console]::SetOut($ShellGuardStdout)
        }
        if (-not $ShellGuardCompleted) {
            if ($LASTEXITCODE -eq 2) { exit 2 }
            Write-ShellGuardFailure $ShellGuardPath "exit code $LASTEXITCODE"
            $ShellGuardFailed = $true
            continue
        }
        $ShellGuardOutput = $ShellGuardBuffer.ToString()
        # A silent allow, and nothing else, is the gate's verdict the account's entry may stand on.
        if ($ShellGuardProof -and -not $ShellGuardOutput) { $ShellGuardProof = 'ok' }
    } finally {
        # Every way out of the gate's run -- continue, exit 2, a throw -- writes its proof first.
        if ($ShellGuardProof) { Write-ShellGuardProof $ShellGuardProof }
    }
    if (-not $ShellGuardOutput.Trim()) { continue }
    $ShellGuardVerdict = $null
    try {
        $ShellGuardParsed = $ShellGuardOutput | ConvertFrom-Json -ErrorAction Stop
        $ShellGuardVerdict = [string]$ShellGuardParsed.hookSpecificOutput.permissionDecision
    } catch {
        # Not JSON: it decided nothing as its own process either.
        continue
    }
    if ($ShellGuardVerdict -ceq 'deny') {
        $ShellGuardStdout.Write($ShellGuardOutput)
        $ShellGuardStdout.Flush()
        exit 0
    }
    if ($ShellGuardVerdict -and $null -eq $ShellGuardKept) { $ShellGuardKept = $ShellGuardOutput }
}
if ($null -ne $ShellGuardKept) {
    $ShellGuardStdout.Write($ShellGuardKept)
    $ShellGuardStdout.Flush()
    exit 0
}
if ($ShellGuardFailed) { exit 1 }
exit 0
