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

    -ProjectGuards IS FOR ONE ACCOUNT-LEVEL HANDLER. With it, after the guards named on the command
    line, this file also runs the guards $env:CLAUDE_PROJECT_DIR's scripts/hooks/shell-guards.txt
    lists. That lets a single handler that names the installed worktree gate run the gate and the
    session repo's own guards in one process, in every repo the account opens; a repo with no
    manifest gets the gate alone. Which handler passes the switch is a property of the wiring, not
    of this file.

    WHY A LINE LIST, AND WHY THERE. Claude Code never reads the file, so declaring a guard in it
    cannot also start that guard in a second process, which a settings.json entry would. It is
    parsed on every shell tool call, so it is plain lines, the format of the gate's own
    worktree-gate.repos.txt, rather than JSON or TOML. It sits beside the guards it names because
    .gitignore tracks nothing under .claude/ but settings.json, and a worktree only receives
    tracked files.

    THE MANIFEST IS UNTRUSTED INPUT, because it is a file in a working tree any session can edit.
    It is read from $env:CLAUDE_PROJECT_DIR, the same root the project settings file's
    ${CLAUDE_PROJECT_DIR} placeholder used to resolve against. One repo-relative path per line;
    blank lines and lines starting with '#' are skipped. A line is run only if it is exactly
    `scripts/hooks/<name>.ps1` (lowercase directories, forward slashes, a name of letters, digits,
    '.', '_' and '-' that starts with a letter or digit), its full path still sits inside that
    repo's scripts/hooks/, and neither the file nor scripts/ nor scripts/hooks/ is a link or
    junction that could lead out of the repo. Anything else is refused and reported like a failed
    guard. A manifest over 16 KB is refused whole. With CLAUDE_PROJECT_DIR unset there is no repo
    to read, and the gate runs alone, silently, as it did before this file ran it.

    THE GUARDS' CODE IS NOT EDITED, AND EACH STILL RUNS STANDALONE. Each guard is invoked with
    `&`, which gives it its own script scope, so its Set-StrictMode, $ErrorActionPreference and
    functions stay inside it -- the two guards that both define Hide-QuotedSpans do not see each
    other's. A guard reads its payload from [Console]::In and writes its decision to
    [Console]::Out, so before each guard stdin is replaced with a fresh reader over the payload
    this file read once, and stdout with a buffer. `exit` inside a guard ends that guard's script,
    not this process (measured).

    ***SCOPE IS ISOLATED; THE PROCESS IS NOT.*** At least these are shared by every guard in the
    run, and none of the guards wired today touches them: the current location, environment
    variables, the Console encodings (setting [Console]::OutputEncoding rebuilds Console.Out, so
    the guard's writes would bypass the buffer), and [Environment]::Exit. A guard that needs any
    of them belongs in its own handler, not on this list.

    THIS SCRIPT SETS NO STRICT MODE AND NO ERROR PREFERENCE, ON PURPOSE. A child scope inherits
    both, and block-blanket-git-stage.ps1 runs with neither when it is its own process. Its own
    variables and functions carry a `ShellGuard` prefix for the same reason: PowerShell scoping is
    dynamic, so a guard that read a name before assigning it would otherwise see this file's value.

    A DECISION IS A PreToolUse JSON OBJECT, NOT ANY OUTPUT. Claude Code reads a hook's stdout as a
    decision only when it parses as one, so a guard's stray text decided nothing when that guard
    was its own process. Here it must not decide anything either -- above all it must not end the
    run, or one guard's chatter would silence the guards after it. Pipeline output from a guard is
    discarded for the same reason.

    THE FIRST DENY WINS AND ENDS THE RUN, AND SO DOES A BLOCKING EXIT. The rest are not started,
    because a guard that ran long after a deny could push the hook past its timeout, and a hook
    that times out lets the command run -- an already-reached deny turned into an allow. The cost
    is that a command two guards would refuse shows one reason, and the retry shows the other.
    A non-deny decision (`ask`, `allow`) is kept, the first one wins, and it is written once every
    guard has run.

    A GUARD'S EXIT CODE IS WHAT ITS OWN PROCESS WOULD HAVE EXITED WITH. That is $LASTEXITCODE only
    when the guard ended with a non-zero `exit`, which is when `$?` reads false after the call.
    A guard that returns, or falls off its end, leaves in $LASTEXITCODE whatever native command it
    ran last -- the worktree gate runs git, which exits 128 outside a repository -- while the same
    guard run alone exits 0. Measured 2026-10-17 over twelve shapes, among them `exit 0|1|2|128`,
    a bare `exit`, `return`, falling off the end after a failed git, a trailing Write-Error, and a
    native `cmd /c exit 2` as the last statement: `$?` was false for exactly the non-zero exits,
    and standalone exited non-zero for exactly those. Reading $LASTEXITCODE alone turned a fall-off after a failed git into a
    reported failure, and a native command that exited 2 into a false block.

    Exit 2 is Claude Code's blocking exit and is passed on; the guard's stderr already went to this
    process's stderr.

    FAIL-OPEN PER GUARD, AND VISIBLE. A guard that throws, exits non-zero other than 2, or whose
    path does not exist contributes an allow, and the others still run; so does a manifest line
    that is refused. Each failure is written to stderr, and when no guard decided anything the run
    exits 1. That is the non-blocking hook error Claude Code showed for a separate guard process
    that failed to start or crashed, so a broken guard is still reported rather than silently off.

    ORDER: THE NAMED GUARDS, THEN THE MANIFEST'S, EACH IN ITS OWN ORDER. A named gate runs first;
    it saw every payload as its own process too. block-blanket-git-stage.ps1 refuses an over-long
    payload, so the manifest lists it first, keeping a huge payload from the two guards after it
    that parse whatever they are given. That guard's own read stops at its cap, but THIS file
    reads all of stdin first, so on the wired path the read itself is not bounded; only the parse
    is. A handler's timeout should be its guards' former per-guard timeouts summed (15 seconds
    each), so a run in which every guard finishes inside its old budget still finishes inside it.

    ASCII-only on purpose (PS 5.1 ANSI-read lesson); run under pwsh 7 by the hook.
#>
param(
    # Also run the guards $env:CLAUDE_PROJECT_DIR's scripts/hooks/shell-guards.txt names, after the
    # named ones. The installed account-level handler passes it; nothing else needs to.
    [Alias('ProjectGuards')]
    [switch]$ShellGuardFromProject,
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

# The manifest's guards, as full paths, and one Problem per line it refuses. Its rules are the
# header's; it executes nothing.
function Read-ShellGuardManifest([string]$Root) {
    $manifest = Join-Path $Root 'scripts/hooks/shell-guards.txt'
    $file = [System.IO.FileInfo]::new($manifest)
    if (-not $file.Exists) { return }
    if ($file.Length -gt 16384) {
        return [pscustomobject]@{ Path = $null; Entry = $manifest; Problem = "manifest is $($file.Length) bytes, over the 16384-byte cap" }
    }
    $hooks = [System.IO.Path]::GetFullPath((Join-Path $Root 'scripts/hooks'))
    $prefix = $hooks.TrimEnd('\', '/') + [System.IO.Path]::DirectorySeparatorChar
    $linked = { param($info) $info.Exists -and ($info.Attributes -band [System.IO.FileAttributes]::ReparsePoint) }
    $dirLink = @(
        [System.IO.DirectoryInfo]::new((Join-Path $Root 'scripts'))
        [System.IO.DirectoryInfo]::new($hooks)
    ) | Where-Object { & $linked $_ } | Select-Object -First 1
    $n = 0
    foreach ($line in [System.IO.File]::ReadAllLines($manifest)) {
        $n++
        $entry = $line.Trim()
        if (-not $entry -or $entry.StartsWith('#')) { continue }
        $problem = $null
        $full = $null
        if ($entry -cnotmatch '\Ascripts/hooks/[A-Za-z0-9][A-Za-z0-9._-]*\.ps1\z') {
            $problem = "manifest line $n is not of the form scripts/hooks/<name>.ps1"
        } else {
            $full = [System.IO.Path]::GetFullPath((Join-Path $Root $entry))
            if (-not $full.StartsWith($prefix, [System.StringComparison]::OrdinalIgnoreCase)) {
                $problem = "manifest line $n resolves outside $hooks"
            } elseif ($dirLink) {
                $problem = "$($dirLink.FullName) is a link or junction, so manifest line $n may lead out of the repo"
            } elseif (& $linked ([System.IO.FileInfo]::new($full))) {
                $problem = "manifest line $n is a link or junction, so it may lead out of the repo"
            }
        }
        if ($problem) {
            [pscustomobject]@{ Path = $null; Entry = $entry; Problem = $problem }
        } else {
            [pscustomobject]@{ Path = $full; Entry = $entry; Problem = $null }
        }
    }
}

$ShellGuardFailed = $false
$ShellGuardList = [System.Collections.Generic.List[string]]::new()
# With no arguments the parameter is $null, and @($null) is one empty entry, not none.
foreach ($ShellGuardPath in @($ShellGuardPaths | Where-Object { $_ })) { $ShellGuardList.Add($ShellGuardPath) }

if ($ShellGuardFromProject -and $env:CLAUDE_PROJECT_DIR) {
    $ShellGuardRoot = $env:CLAUDE_PROJECT_DIR
    if (-not [System.IO.Path]::IsPathFullyQualified($ShellGuardRoot)) {
        Write-ShellGuardFailure 'scripts/hooks/shell-guards.txt' "CLAUDE_PROJECT_DIR is not a full path: $ShellGuardRoot"
        $ShellGuardFailed = $true
    } else {
        try {
            foreach ($ShellGuardEntry in @(Read-ShellGuardManifest $ShellGuardRoot)) {
                if ($ShellGuardEntry.Problem) {
                    Write-ShellGuardFailure $ShellGuardEntry.Entry $ShellGuardEntry.Problem
                    $ShellGuardFailed = $true
                } elseif (-not ($ShellGuardList -contains $ShellGuardEntry.Path)) {
                    $ShellGuardList.Add($ShellGuardEntry.Path)
                }
            }
        } catch {
            Write-ShellGuardFailure 'scripts/hooks/shell-guards.txt' "unreadable: $($_.Exception.Message)"
            $ShellGuardFailed = $true
        }
    }
}

$ShellGuardKept = $null
foreach ($ShellGuardPath in $ShellGuardList) {
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
        # Read on the very next line: any statement in between would reset it.
        $ShellGuardExitedClean = $?
        $ShellGuardExit = if ($ShellGuardExitedClean) { 0 } else { $LASTEXITCODE }
    } catch {
        Write-ShellGuardFailure $ShellGuardPath $_.Exception.Message
        $ShellGuardFailed = $true
        continue
    } finally {
        [Console]::SetOut($ShellGuardStdout)
    }
    if ($ShellGuardExit -eq 2) { exit 2 }
    if ($ShellGuardExit -ne 0) {
        Write-ShellGuardFailure $ShellGuardPath "exit code $ShellGuardExit"
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
