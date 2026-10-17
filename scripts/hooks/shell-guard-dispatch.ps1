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
    A guard that leaves $LASTEXITCODE at 2 is read as Claude Code's blocking exit and passed on;
    its stderr already went to this process's stderr. In-process, `exit 2` and a native command
    that exited 2 look the same, so a guard that runs one would block here where it allowed
    alone: a false deny, which is the visible direction. The guards wired today run none.
    A non-deny decision (`ask`, `allow`) is kept, the first one wins, and it is written once every
    guard has run.

    FAIL-OPEN PER GUARD, AND VISIBLE. A guard that throws, exits non-zero other than 2, or whose
    path does not exist contributes an allow, and the others still run. Each failure is written to
    stderr, and when no guard decided anything the run exits 1. That is the non-blocking hook
    error Claude Code showed for a separate guard process that failed to start or crashed, so a
    broken guard is still reported rather than silently off.

    ORDER IS THE SETTINGS FILE'S, AND THE BOUNDED GUARD GOES FIRST. block-blanket-git-stage.ps1
    refuses an over-long payload, so placing it first keeps a huge payload from reaching the two
    guards that parse whatever they are given. That guard's own read stops at its cap, but THIS
    file reads all of stdin first, so on the wired path the read itself is not bounded; only the
    parse is. The timeout in settings.json is the three guards' former per-guard timeouts summed,
    so a run in which every guard finishes inside its old budget still finishes inside this one.

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

$ShellGuardFailed = $false
$ShellGuardKept = $null
# With no arguments the parameter is $null, and @($null) is one empty entry, not none.
foreach ($ShellGuardPath in @($ShellGuardPaths | Where-Object { $_ })) {
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
    } catch {
        Write-ShellGuardFailure $ShellGuardPath $_.Exception.Message
        $ShellGuardFailed = $true
        continue
    } finally {
        [Console]::SetOut($ShellGuardStdout)
    }
    if ($LASTEXITCODE -eq 2) { exit 2 }
    if ($LASTEXITCODE -ne 0) {
        Write-ShellGuardFailure $ShellGuardPath "exit code $LASTEXITCODE"
        $ShellGuardFailed = $true
        continue
    }
    $ShellGuardOutput = $ShellGuardBuffer.ToString()
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
