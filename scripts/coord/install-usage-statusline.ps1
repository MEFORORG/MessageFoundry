# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Wire usage-collect.ps1 as the Claude Code statusLine, so an account's plan limits get published.

.DESCRIPTION
    Run this ONCE per config root, from a plain terminal. It writes `statusLine` into that root's
    settings.json. See usage-collect.ps1 for why a statusLine is the only source.

    WHICH ROOT, AND WHY THAT IS THE WHOLE POINT. Claude Code reads settings from the root named by
    CLAUDE_CONFIG_DIR, falling back to ~/.claude. An earlier version of this script always wrote
    ~/.claude/settings.json and reported "INSTALLED (user level -- every session on this machine)". On
    a box whose launchers pin CLAUDE_CONFIG_DIR to ~/.claude-account-<N>, that claim was false: the
    statusLine never fired, nothing ever published, and usage.ps1 correctly reported the collector as
    not installed. An install success followed by a reader saying it was never installed -- two
    instruments disagreeing, with the wrong one louder and earlier.

    FIVE RULES DECIDE THE TARGET SET, FIRST MATCH WINS:
      1. -SettingsPath <file>...  exactly those files; each file's PARENT is its config root.
      2. -ConfigDir <dir>...      <dir>\settings.json for each.
      3. -AllRoots                every ~/.claude-account-<N> under -HomeDir, plus this session's
                                  pinned root if CLAUDE_CONFIG_DIR names one outside that set.
      4. CLAUDE_CONFIG_DIR set    that one root.
      5. otherwise                <HomeDir>\.claude.
    -AllRoots is OPT-IN and covers ACCOUNT roots only. It deliberately diverges from
    scripts/worktree/install-gate.ps1, which defaults to the whole set: a security gate fails by
    under-reach so it wires everything it can find, whereas this writes into several vendor-owned
    directories belonging to DIFFERENT Anthropic accounts, and the pin is the single-session correct
    target. -AllRoots also excludes ~/.claude, which this repo's coordination tooling treats as shared
    state; wire it deliberately with -ConfigDir "$HOME\.claude" if a bare `claude` run needs numbers.

    EACH ROOT IS WIRED TO PUBLISH UNDER ITSELF (<root>\mefor-usage), because a config root holds one
    credential set and therefore one Anthropic account, and separate accounts have separate 7-day
    pools. One shared file across roots is last-writer-wins across unrelated quotas. The rule
    lives once, in config-roots.ps1, and the reader derives its path from the same function -- so the
    two halves cannot drift into the disagreement described above.

    IT TAKES EFFECT IN NEWLY STARTED SESSIONS. Existing sessions keep the config they booted with, the
    same as the coordination hooks. And it only ever runs in an INTERACTIVE session: the statusLine is
    part of the TUI's render tree and never executes under `claude -p` or the SDK, so a headless
    coordinator can read what this publishes but can never publish it itself.

    WHY THE WIRED COMMAND POINTS AT AN ABSOLUTE PATH rather than resolving the repo per invocation: the
    statusLine runs on every assistant message behind a 300ms debounce, and a `git rev-parse` per fire
    is latency on the render path for a value that never changes. The trade is that moving or deleting
    the checkout breaks it -- so the wired command TESTS FOR THE SCRIPT and degrades to a quiet marker
    instead of erroring into the status bar on every message.

    refreshInterval is set because statusLine updates are EVENT-DRIVEN -- a new assistant message,
    /compact, a permission-mode change -- and go silent when a session is idle. Anthropic's own docs
    name "a coordinator waits on background subagents" as the case where that leaves you blind, which is
    exactly this repo's situation.

    EXIT CODES, so a coordinator can branch without parsing prose:
        0  every targeted root ended in the desired state
        3  PARTIAL -- at least one root reached it and at least one did not
        1  NOTHING WRITTEN -- roots were targeted and none reached the desired state
        2  COULD NOT START -- unusable arguments, a named root that does not exist, no roots resolved,
           or the collector missing. Nothing was examined.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -ConfigDir "$HOME\.claude-account-5"
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -AllRoots
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -Status
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -Uninstall
    # ONE PATH PER RUN under `pwsh -File`. It hands each argument over as a single string, so
    # `-ConfigDir A,B` binds as the one value "A,B" (measured), and it refuses a repeated -ConfigDir
    # (measured). Nothing splits it, deliberately: a Windows path may legally contain a comma. Several
    # paths at once need a pwsh session: & <script> -ConfigDir @('A', 'B').
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Uninstall,
    [switch]$Status,
    # Milliseconds. Minimum honoured by Claude Code is 1000, so a smaller value is refused rather than
    # written: the run's own "refreshInterval: <n> ms" summary would otherwise state a rate that never
    # applies (BACKLOG #7577).
    [int]$RefreshInterval = 10000,
    # LOWEST-LEVEL OVERRIDE, AND IT HAS NO DEFAULT ON PURPOSE. A default here is what made the
    # CLAUDE_CONFIG_DIR pin unreachable: a pin can only be consulted when nothing has already answered
    # the question, and a computed default answers it before the pin is ever read. Deleting the default
    # IS the fix; reading the pin is only what that makes possible.
    [string[]]$SettingsPath,
    # Config dir(s) to wire. Same [string[]] shape as scripts/worktree/install-gate.ps1.
    [string[]]$ConfigDir,
    # Wire every account config root under -HomeDir. Opt-in; see the .DESCRIPTION for why.
    [switch]$AllRoots,
    # Which collector to wire. Defaults to the PRIMARY checkout's copy, deliberately: a worktree is
    # disposable and a statusLine pointing into one dies with it. One absolute path is wired into every
    # root. Overridable so tests can drive the real installer against a fixture.
    [string]$CollectorPath,
    # THE HOME DIRECTORY IS A PARAMETER, NOT AN ENVIRONMENT READ, AND THAT IS A TEST-SAFETY RULE.
    # Measured: with USERPROFILE overridden to C:/fake/home a child pwsh still reported
    # [Environment]::GetFolderPath('UserProfile') = C:\Users\<user>. A callee that resolves home itself
    # cannot be redirected by a test, so one dropped environment variable would stand between the
    # -AllRoots test and enumerating -- and wiring -- the real account roots on this box.
    [string]$HomeDir = $(if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') })
)

# CAPTURED AT SCRIPT SCOPE, IMMEDIATELY, AND NEVER RE-TESTED INSIDE A FUNCTION. Measured on pwsh 7.6.5
# with `-File probe.ps1 -SettingsPath X`: at script scope ContainsKey('SettingsPath') is True; inside a
# function its own $PSBoundParameters is EMPTY, so the same test returns False for every caller. A
# resolver that tested it there would make rules 1 and 2 unreachable and silently fall through to the
# pin -- meaning `-SettingsPath <fixture>` from the test suite would be ignored and this script would
# write into the caller's live pinned root instead.
$script:GaveSettingsPath = $PSBoundParameters.ContainsKey('SettingsPath')
$script:GaveConfigDir = $PSBoundParameters.ContainsKey('ConfigDir')

$ErrorActionPreference = "Stop"

. (Join-Path $PSScriptRoot 'config-roots.ps1')
$MARKER = $script:UsageStatusLineMarker

# One stamp for the whole run, so every root's backup reads as one run's set. The old fixed
# ".bak-usage" name is retired: run this twice over five roots and every pre-install backup on the box
# holds post-install content, recovering nothing anywhere.
$BackupStamp = [DateTime]::Now.ToString('yyyyMMdd-HHmmss')

function Stop-Cannot([string]$Reason) {
    Write-Host ""
    Write-Host "CANNOT START: $Reason" -ForegroundColor Red
    Write-Host ""
    exit 2
}

# THE WIRED COMMAND IS READ BY WHICHEVER SHELL CLAUDE CODE PICKS, so every path baked into it has to
# mean the same thing in both. Both bash and pwsh expand $ and a backtick inside double quotes, both
# read \" as an escaped quote, and neither can carry a literal " in a path anyway -- so there is no
# spelling of those characters that survives the pair. Refuse at install time, in front of a human,
# rather than emit a command that fails silently in a status bar forever.
#
# A PRE-PASS OVER EVERY TARGET, NOT A CHECK INSIDE THE WRITE LOOP. Aborting halfway through -AllRoots
# would leave some roots on the new command and some on the old -- the mixed state the readers now have
# to tell apart -- so the run either wires all of its targets or writes nothing.
function Assert-ShellQuotable([string]$Path, [string]$What) {
    if ($Path -match '["$`]' -or $Path.EndsWith('\')) {
        Stop-Cannot ("$What cannot be quoted for both bash and pwsh: $Path" +
            "`n              It carries a double quote, a dollar sign, a backtick, or a trailing" +
            "`n              backslash. A statusLine has no shell key, so one string has to satisfy" +
            "`n              both shells. Move it somewhere plainer and re-run.")
    }
}

function Assert-RootExists([string]$Path, [string]$What) {
    if (Test-Path -LiteralPath $Path -PathType Container) { return }
    $msg = "$What does not exist: $Path"
    if ($Path -like '*,*') {
        $msg += "`n              (that string contains a comma -- `pwsh -File` passes it as ONE value;" +
        " run once per path, or use -AllRoots)"
    }
    Stop-Cannot $msg
}

# Read PER PATH, never once for the whole run. The previous version closed over a single script-scope
# $SettingsPath, which becomes actively dangerous the moment that parameter is [string[]]. Measured
# with @(existing.json, missing.json): `Test-Path -LiteralPath` returns "True False", `-not` on that is
# False so the guard PASSES, and Get-Content then throws on the missing one. With two files that both
# exist it is worse -- Get-Content -Raw returns them CONCATENATED and ConvertFrom-Json ACCEPTS the
# concatenation as an array of two objects, so one root would be judged by a silent merge of two files.
function Read-Settings([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return [ordered]@{} }
    # Fail loudly rather than overwrite: a settings file we cannot parse is one we must not rewrite,
    # because a bad write silently disables EVERY setting in it, not just this one.
    return ($raw | ConvertFrom-Json -AsHashtable)
}

function Write-SettingsFile([string]$Path, $Data) {
    # TWO SERIALISATION GUARDS, AND THE SECOND IS NOT IMPLIED BY THE FIRST. Measured with a 24-level
    # document: ConvertTo-Json -Depth 20 emits "Resulting JSON is truncated as serialization has
    # exceeded the set depth of 20" AND THE TRUNCATED TEXT STILL PARSES BACK CLEANLY, with the deep node
    # replaced by its type name as a string. So a parse-back check alone would let one -AllRoots run
    # quietly truncate up to five live account roots and count every one as written.
    $json = $Data | ConvertTo-Json -Depth 20 -WarningVariable depthWarning -WarningAction SilentlyContinue
    if ($depthWarning) { throw "serialising this file would have TRUNCATED it (nesting deeper than 20); left untouched" }
    try { $null = $json | ConvertFrom-Json } catch { throw "the generated settings JSON is invalid: $_" }
    # NO -ErrorAction SilentlyContinue on the backup. In a loop, a silent backup failure followed by a
    # successful destructive write is a per-root data loss the tally would count as a success.
    # RETURNS WHETHER IT BACKED ONE UP, because the caller prints that line. A root with no
    # settings.json has nothing to copy, and an -AllRoots run that printed a backup path for all five
    # would send an operator hunting for backups that were never taken -- a small lie of exactly the
    # kind this change exists to remove.
    # A FREE NAME, NOT A FIXED ONE, AND IT RETURNS WHERE THE COPY LANDED. $BackupStamp has
    # one-second resolution, so two runs inside the same second collide -- measured on a fixture: run
    # 1 wrote the original 55 bytes, run 2 started immediately after and overwrote that same file with
    # 771 bytes of run 1's POST-install content. The only pre-install copy was destroyed by the run
    # that claimed to be making one, which is worse than not backing up at all: the operator is told a
    # backup exists and it holds the wrong content.
    $backedTo = $null
    if (Test-Path -LiteralPath $Path) {
        $dest = "$Path.bak-usage-$BackupStamp"
        $n = 1
        while (Test-Path -LiteralPath $dest) { $dest = "$Path.bak-usage-$BackupStamp-$n"; $n++ }
        Copy-Item -LiteralPath $Path -Destination $dest -Force
        $backedTo = $dest
    }
    # TEMP-THEN-MOVE, the discipline account-availability.ps1 and the collector already use. Claude
    # Code reads this file at session start, and an in-place Set-Content truncates the live file first,
    # so a crash or a concurrent session start mid-write sees a partial file that disables every
    # setting in it (BACKLOG #7576). The encoding is UTF-8 WITHOUT a BOM, which is what Set-Content
    # -Encoding UTF8 wrote on pwsh 7; [Text.Encoding]::UTF8 would add one. $Path is absolute (the
    # target resolver makes it so), which matters because these .NET calls resolve a relative path
    # against the process directory, not $PWD.
    #
    # ONE File.Move WITH overwrite, NOT File.Replace. Replace is two renames (the old file aside, the
    # new one in), so a concurrent reader finds NO settings.json between them, and a part-way failure
    # can leave it gone. Move with overwrite is one MoveFileEx(MOVEFILE_REPLACE_EXISTING): a single
    # rename that swaps the directory entry, so a reader opens the old file or the new one, never
    # nothing, and a failed move leaves the old file where it was. A rename keeps the TEMP file's own
    # ACL and attributes, which are the directory's inherited ones (measured: a protected owner-only ACL
    # and Hidden were both lost to a bare Move), so Copy-SettingsSecurity puts the old file's onto the
    # temp file BEFORE the move, and no reader ever sees a widened settings.json.
    #
    # A LINKED FILE IS STILL WRITTEN IN PLACE. A move swaps the directory entry, so it would cut a
    # symbolic or hard link that the old Set-Content wrote through, leaving a standalone copy while the
    # shared file kept its old content. For a link, writing through matters more than atomicity, so that
    # case keeps the old behaviour rather than gaining a new failure. So does a file whose security
    # cannot be copied: installing it with a wider ACL would be worse than the in-place write it
    # replaced.
    #
    # A SHARING VIOLATION OR AN ACCESS DENIAL IS RETRIED, because a file just created is often held open
    # for a moment by a scanner, and a reader holding settings.json open without delete sharing refuses
    # the rename (measured: a Python reader's plain open() refused most renames in a tight loop). When
    # the retries run out, the in-place write runs instead: that reader never blocked the old write, so
    # refusing the install there would be worse than it was. A missing directory fails at once.
    $item = Get-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
    if ($item -and $item.LinkType) {
        Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
        return $backedTo
    }
    #
    # A FAILED SWAP MUST NEVER LEAVE NEITHER FILE (BACKLOG #7576). The move itself cannot leave
    # settings.json gone, but a concurrent deleter can, so a COMPLETE temp file is deleted only while
    # settings.json exists, and the failure report names every copy.
    $tmp = "$Path.$PID.tmp"
    $tmpComplete = $false
    $inPlaceWhy = $null
    try {
        [System.IO.File]::WriteAllText($tmp, $json + [Environment]::NewLine, [System.Text.UTF8Encoding]::new($false))
        $tmpComplete = $true
        if ($item) { $inPlaceWhy = Copy-SettingsSecurity $item $tmp }
        # No move when the security copy failed: the in-place write below runs instead.
        foreach ($attempt in $(if ($inPlaceWhy) { @() } else { 1..3 })) {
            # Untyped catch: a .NET method's exception arrives wrapped in MethodInvocationException.
            try {
                Invoke-SettingsSwap $tmp $Path ([bool]$item)
                break
            }
            catch {
                $hr = $_.Exception.GetBaseException().HResult
                $transient = $hr -eq -2147024864 -or $hr -eq -2147024891  # ERROR_SHARING_VIOLATION, ERROR_ACCESS_DENIED
                # A retry, or the in-place write, only while settings.json is still where it was.
                if (-not $transient -or ($item -and -not (Test-Path -LiteralPath $Path))) { throw }
                if ($attempt -eq 3) {
                    if (-not $item) { throw }
                    $inPlaceWhy = "the move was refused 3 times ($($_.Exception.GetBaseException().Message))"
                    break
                }
                Start-Sleep -Milliseconds (50 * $attempt)
            }
        }
    }
    catch {
        $why = $_.Exception.GetBaseException().Message
        if (-not $tmpComplete) { throw "settings.json was not touched: writing the new content to a temp file failed ($why)" }
        throw (Get-FailedSwapReport $Path $tmp ([bool]$item) $backedTo $why)
    }
    finally {
        # A temp file that was never completely written is never anyone's only copy.
        if (-not $tmpComplete -or (Test-Path -LiteralPath $Path)) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    if ($inPlaceWhy) {
        Write-Verbose "in-place write of ${Path}: $inPlaceWhy"
        Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    }
    return $backedTo
}

# THE OLD FILE'S OWNER, GROUP, DACL AND VISIBLE ATTRIBUTES, ONTO THE TEMP FILE. Returns $null on
# success, or why it could not, and the caller then writes in place. The DACL travels as SDDL, so its
# protection flag goes with it. Setting an owner other than this user needs a privilege the run may
# lack, which is one of the cases that falls back. ReadOnly is not copied: a move over a read-only file
# fails anyway, as the in-place write did.
function Copy-SettingsSecurity([System.IO.FileSystemInfo]$Item, [string]$Tmp) {
    try {
        if (Test-SwapFault $Item.FullName 'security-copy-fails') { throw "simulated security copy failure" }
        $sections = [System.Security.AccessControl.AccessControlSections]'Owner, Group, Access'
        $src = [System.IO.FileSystemAclExtensions]::GetAccessControl([System.IO.FileInfo]$Item.FullName, $sections)
        $dst = [System.Security.AccessControl.FileSecurity]::new()
        $dst.SetSecurityDescriptorSddlForm($src.GetSecurityDescriptorSddlForm($sections), $sections)
        [System.IO.FileSystemAclExtensions]::SetAccessControl([System.IO.FileInfo]$Tmp, $dst)
        $want = $Item.Attributes -band [System.IO.FileAttributes]'Hidden, System, Archive, NotContentIndexed'
        if ($want) { [System.IO.File]::SetAttributes($Tmp, $want) }
        return $null
    }
    catch { return "its security could not be copied onto the temp file ($($_.Exception.GetBaseException().Message))" }
}

# TEST SEAM, FENCED SO IT CANNOT REACH A REAL CONFIG ROOT. MEFOR_TEST_STATUSLINE_SWAP_FAULT names a
# failure to simulate, and it fires ONLY when ALL of these hold, so a value leaked into an operator's
# environment does nothing:
#   - MEFOR_TEST_STATUSLINE_SWAP_FAULT_DIR names a directory whose leaf starts 'mefor-swap-fault-',
#     a name no Claude config root (~/.claude*) carries;
#   - the settings file sits DIRECTLY in that directory;
#   - that directory is strictly inside an explicitly set, absolute TEMP. GetTempPath is not consulted:
#     with TMP and TEMP unset it falls back to USERPROFILE, the directory real roots live in.
# Modes: 'move-fails' throws where the move would run; 'move-fails-target-gone' first deletes the
# target, standing in for a concurrent deleter; 'security-copy-fails' fails the security copy.
function Test-SwapFault([string]$Path, [string]$Mode) {
    if ($env:MEFOR_TEST_STATUSLINE_SWAP_FAULT -cne $Mode) { return $false }
    $dir = $env:MEFOR_TEST_STATUSLINE_SWAP_FAULT_DIR
    $temp = $env:TEMP
    if (-not $dir -or -not $temp) { return $false }
    if (-not [System.IO.Path]::IsPathFullyQualified($dir) -or -not [System.IO.Path]::IsPathFullyQualified($temp)) { return $false }
    $ic = [System.StringComparison]::OrdinalIgnoreCase
    $dir = [System.IO.Path]::GetFullPath($dir).TrimEnd('\', '/')
    $temp = [System.IO.Path]::GetFullPath($temp).TrimEnd('\', '/')
    if (-not [System.IO.Path]::GetFileName($dir).StartsWith('mefor-swap-fault-', $ic)) { return $false }
    if (-not [string]::Equals([System.IO.Path]::GetDirectoryName([System.IO.Path]::GetFullPath($Path)), $dir, $ic)) { return $false }
    return $dir.StartsWith($temp + '\', $ic)
}

function Invoke-SettingsSwap([string]$Tmp, [string]$Path, [bool]$Exists) {
    if (Test-SwapFault $Path 'move-fails-target-gone') {
        Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
        throw [System.IO.IOException]::new("simulated move failure after a concurrent delete")
    }
    if (Test-SwapFault $Path 'move-fails') { throw [System.IO.IOException]::new("simulated move failure") }
    # Overwrite only a file this run saw: a root that had none must not clobber one a concurrent writer
    # created meanwhile.
    [System.IO.File]::Move($Tmp, $Path, $Exists)
}

# SAYS WHERE EVERY COPY IS. The returned text is the FAILED line's reason, so an operator reads the
# paths without opening a log. It never says what settings.json now HOLDS: a concurrent writer can have
# put anything there.
function Get-FailedSwapReport([string]$Path, [string]$Tmp, [bool]$Existed, [string]$BackedTo, [string]$Why) {
    $present = Test-Path -LiteralPath $Path
    $msg = if ($present) { "settings.json was not updated ($Why); the new content was not installed" }
    elseif ($Existed) { "settings.json is MISSING after a failed swap ($Why)" }
    else { "settings.json was not created ($Why)" }
    if (-not $present) {
        $msg += $(if (Test-Path -LiteralPath $Tmp) { ". The new content is in $Tmp" } else { ". The new content's temp file $Tmp is gone too" })
    }
    if ($BackedTo) { $msg += "; a copy of the previous content is in $BackedTo" }
    # Re-running first would read the missing file as empty and write a settings.json holding only
    # the statusLine, so the restore comes first.
    if (-not $present) { $msg += ". Rename one of them to $Path before running this installer again" }
    return "$msg."
}

# THREE-WAY, NOT TWO-WAY. A statusLine object present with a null or empty command is NONE, not
# FOREIGN: calling it FOREIGN would make this script refuse that root forever while printing a refusal
# line with nothing after the colon, and offer a remedy naming a command that does not exist.
function Get-Ownership($Settings) {
    $sl = $Settings['statusLine']
    if (-not $sl) { return 'NONE' }
    $cmd = [string]$sl['command']
    if ([string]::IsNullOrWhiteSpace($cmd)) { return 'NONE' }
    if (Test-IsOurStatusLine $cmd) { return 'OURS' }
    return 'FOREIGN'
}

function New-WiredCommand([string]$Collector, [string]$StateDir) {
    # ONE STRING, TWO SHELLS, AND THAT IS THE WHOLE CONSTRAINT ON THIS FUNCTION. A statusLine entry has
    # NO `shell` key -- its keys are exactly command/refreshInterval/type -- so unlike a hook it cannot
    # declare PowerShell, and Claude Code runs it under bash on any box where Git Bash is installed.
    # This used to emit PowerShell SOURCE, which bash cannot parse. Measured twice, by two sessions, on
    # the bytes taken straight out of a live settings.json: under bash, "syntax error near unexpected
    # token `{'" and exit 2, with pwsh never launched; under pwsh, exit 0 and a complete latest.json
    # published beside history.jsonl. So a root wired that way would publish nothing on a box with Git
    # Bash, and every reader downstream would report UNKNOWN with no instrument anywhere naming the
    # shell as the cause.
    #
    # WHAT THE SHELL-AGNOSTIC FORM COSTS, STATED RATHER THAN QUIETLY DROPPED: the inline Test-Path
    # guard is gone, because no single string expresses a conditional in both shells. A collector that
    # disappears AFTER wiring now surfaces whatever pwsh says about a -File it cannot open, in the
    # status bar, instead of the friendly "mefor-usage: collector missing" line. Two things still cover
    # that state -- this script refuses to wire a collector that is not there (the Test-Path before the
    # install loop), and usage.ps1 still diagnoses one that vanishes later as WIRED_COLLECTOR_MISSING.
    #
    # DOUBLE QUOTES ARE ONLY SAFE BECAUSE Assert-ShellQuotable RAN FIRST, over every path this run will
    # bake in. Both shells expand $ and a backtick inside double quotes, and both read a trailing
    # backslash as escaping the closing quote; a path carrying one would be mangled by both.
    return "# $MARKER`n" +
    "pwsh -NoProfile -NonInteractive -File `"$Collector`" -StateDir `"$StateDir`""
}

# --- resolve the target set, ONCE ------------------------------------------------------------------

if ($AllRoots -and ($script:GaveConfigDir -or $script:GaveSettingsPath)) {
    Stop-Cannot "-AllRoots cannot be combined with -ConfigDir / -SettingsPath -- pick one"
}
# BOUND-AND-EMPTY IS A USAGE ERROR, NOT "NOT GIVEN". Measured: `-ConfigDir @()` gives ContainsKey True
# with Count 0 and [bool] False, so a truthiness test would silently promote the caller to the next
# rule and wire a root they never named.
if ($script:GaveSettingsPath -and @($SettingsPath).Count -eq 0) { Stop-Cannot "-SettingsPath was given with no value" }
if ($script:GaveConfigDir -and @($ConfigDir).Count -eq 0) { Stop-Cannot "-ConfigDir was given with no value" }

# THE PATH ARGUMENTS ARE MADE ABSOLUTE AGAINST $PWD FIRST (BACKLOG #7577): at least -SettingsPath,
# -ConfigDir, -HomeDir and -CollectorPath. A relative CLAUDE_CONFIG_DIR pin is not, because it names no
# $PWD of its own. ConvertTo-NormalRootPath
# and the .NET file calls resolve a relative path against [Environment]::CurrentDirectory, which a
# Set-Location does not move, while Test-Path and Set-Content resolve it against $PWD. Called with `&`
# after a `cd`, the two differ, so a relative argument was checked in one directory and wired to
# another. GetUnresolvedProviderPathFromPSPath reads $PWD, expands no wildcard, and needs no file to
# exist. A bare file name also gets a real parent this way: Split-Path 'settings.json' -Parent is ''.
# On the install path, a drive that does not exist, or a $PWD on a non-filesystem drive such as HKCU:,
# is a usage error and answers exit 2 like any other, never a raw exception and exit 1. -Status and
# -Uninstall carry a gone path on instead; see the catch below.
function Resolve-ArgPath([string]$Path, [string]$What) {
    if ([string]::IsNullOrWhiteSpace($Path)) { Stop-Cannot "$What was given as an empty string" }
    $provider = $null; $drive = $null
    try { $full = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path, [ref]$provider, [ref]$drive) }
    catch {
        # AN AUDIT OR AN UNINSTALL GOES ON PAST A GONE ROOT, so one root on an unmapped drive does not
        # hide the rest. The raw path is NOT a reading of that root. For a -SettingsPath target both
        # modes test it with Test-PathRootReachable and report it UNKNOWN, never as absent. A gone
        # -ConfigDir still stops at Assert-RootExists with exit 2, and a gone -HomeDir under the default
        # rule still ends on a raw Join-Path error with exit 1, as it did before this resolver.
        if ($Status -or $Uninstall) { return $Path }
        Stop-Cannot "$What cannot be resolved to a file path: $Path ($($_.Exception.GetBaseException().Message))"
    }
    if ($provider.Name -ne 'FileSystem') { Stop-Cannot "$What does not name a file-system path: $Path (it resolved under $($provider.Name))" }
    return $full
}

# A MISSING FILE ON A MISSING DRIVE IS NOT AN ABSENT FILE. Test-Path answers False for both a deleted
# settings.json and one on a drive or share that is not there, and Read-Settings turns False into an
# empty document, so -Uninstall reported a root on an unmapped drive as NOT PRESENT and exited 0 -- a
# state no part of the run observed. A path whose root is not a reachable directory is UNKNOWN.
function Test-PathRootReachable([string]$Path) {
    $r = [System.IO.Path]::GetPathRoot($Path)
    return [bool]$r -and (Test-Path -LiteralPath $r -PathType Container)
}

# -HomeDir IS RESOLVED ONLY WHERE IT IS READ: -AllRoots, the default root, and the -Status audit. Its
# default is USERPROFILE, which can be empty or on an unmapped drive, and a -SettingsPath or
# -ConfigDir install never reads it, so resolving it up front refused an install that had no use for
# it. A blank one under -Status goes on unresolved, as it did before this resolver.
function Resolve-HomeDir {
    if ($Status -and [string]::IsNullOrWhiteSpace($script:HomeDir)) { return $script:HomeDir }
    return (Resolve-ArgPath $script:HomeDir "-HomeDir")
}

$targets = @()
$targetFrom = ""
if ($script:GaveSettingsPath) {
    $targetFrom = "-SettingsPath"
    $targets = @($SettingsPath | ForEach-Object {
            $s = Resolve-ArgPath $_ "-SettingsPath"
            [pscustomobject]@{ Settings = $s; Root = (ConvertTo-NormalRootPath (Split-Path $s -Parent)) }
        })
}
elseif ($script:GaveConfigDir) {
    $targetFrom = "-ConfigDir"
    $ConfigDir = @($ConfigDir | ForEach-Object { Resolve-ArgPath $_ "-ConfigDir" })
    foreach ($d in $ConfigDir) { Assert-RootExists $d "config dir" }
    $targets = @($ConfigDir | ForEach-Object {
            $r = ConvertTo-NormalRootPath $_
            [pscustomobject]@{ Settings = (Join-Path $r "settings.json"); Root = $r }
        })
}
elseif ($AllRoots) {
    $targetFrom = "-AllRoots"
    $HomeDir = Resolve-HomeDir
    $roots = @(Get-LaunchableConfigRoots -HomeDir $HomeDir -AccountsOnly)
    $addedOutside = $null
    if ($env:CLAUDE_CONFIG_DIR) {
        $pin = ConvertTo-NormalRootPath $env:CLAUDE_CONFIG_DIR
        Assert-RootExists $pin "CLAUDE_CONFIG_DIR names a directory that"
        if (-not ($roots | Where-Object { Test-SameRoot $_ $pin })) { $roots += $pin; $addedOutside = $pin }
    }
    if (@($roots).Count -eq 0) { Stop-Cannot "no account config root found under $HomeDir" }
    $targets = @($roots | ForEach-Object {
            $r = ConvertTo-NormalRootPath $_
            [pscustomobject]@{ Settings = (Join-Path $r "settings.json"); Root = $r }
        })
}
else {
    $HomeDir = Resolve-HomeDir
    $cur = Resolve-CurrentConfigRoot -HomeDir $HomeDir
    $targetFrom = $cur.Source
    Assert-RootExists $cur.Path $(if ($cur.Source -eq 'CLAUDE_CONFIG_DIR') { "CLAUDE_CONFIG_DIR names a directory that" } else { "config dir" })
    $targets = @([pscustomobject]@{ Settings = (Join-Path $cur.Path "settings.json"); Root = $cur.Path })
}

# --- Status ----------------------------------------------------------------------------------------
#
# AUDITING IS NOT INSTALLING, so -Status runs before the git-repository guard and before the
# collector-exists guard. Refusing an audit precisely when its answer -- "this root points at a
# collector that is gone" -- is the thing you needed is the wrong trade.

if ($Status) {
    Write-Host ""
    Write-Host "target from: $targetFrom"
    $ok = 0; $bad = 0
    foreach ($t in $targets) {
        Write-Host ""
        Write-Host "  $($t.Settings)"
        if (-not (Test-PathRootReachable $t.Settings)) {
            # Before every per-root line below: each one reads a path under that root, and the
            # publish-path line threw on a missing drive, ending the whole audit at this root.
            Write-Host "    statusLine    : UNKNOWN -- the drive or share this path is on is not reachable, so nothing under it was read" -ForegroundColor Yellow
            $bad++
            continue
        }
        $own = 'UNREADABLE'; $settings = $null
        try { $settings = Read-Settings $t.Settings; $own = Get-Ownership $settings } catch { }
        Write-Host "    statusLine    : $own"
        $wantState = Get-UsageStateDir $t.Root
        if ($own -eq 'OURS') {
            $cmd = [string]$settings['statusLine']['command']
            # READ BACK OUT OF THE WIRED COMMAND, NEVER RECOMPUTED. The previous version reported
            # "script exists" against a path THAT INVOCATION had just resolved from git, so a root
            # wired from a checkout since deleted still reported True. Across five roots wired at
            # different times from different checkouts, one recomputed line describes none of them.
            $wired = Get-WiredStateDir $cmd
            $coll = Get-WiredCollectorPath $cmd
            # A command bash cannot parse publishes nowhere, whatever path it names (BACKLOG #1459).
            # Said IN ADDITION to the path arms below, not instead of them: the path it names is
            # still a fact an operator may need, and a root can be PowerShell source AND elsewhere.
            $psSource = Test-IsPowerShellSourceStatusLine $cmd
            # A RELATIVE COLLECTOR runs from each session's working directory, so Test-Path from this
            # audit's $PWD cannot vouch for it (BACKLOG #7577). Such a root needs a re-install.
            $relColl = $coll -and -not [System.IO.Path]::IsPathFullyQualified($coll)
            if ($null -eq $wired) {
                Write-Host "    publishes to  : UNKNOWN (legacy command, no -StateDir -- the collector chooses at run time)"
                Write-Host "                    re-install this root to bake the path in: -ConfigDir `"$($t.Root)`""
                $bad++
            }
            elseif (-not (Test-SameRoot (Split-Path $wired -Parent) $t.Root)) {
                Write-Host "    publishes to  : $wired   -- ELSEWHERE; this root reads $wantState" -ForegroundColor Yellow
                $bad++
            }
            else {
                Write-Host "    publishes to  : $wired"
                if ($psSource -or $relColl) { $bad++ } else { $ok++ }
            }
            if ($psSource) {
                Write-Host "    but it cannot : the command is PowerShell source, and bash (which runs a statusLine) cannot parse it, so it publishes NOTHING" -ForegroundColor Yellow
                # The legacy arm above already printed the same re-install line; one is enough.
                if ($null -ne $wired) { Write-Host "                    re-install this root to replace it: -ConfigDir `"$($t.Root)`"" }
            }
            if ($relColl) {
                Write-Host "    collector     : $coll   -- RELATIVE; a session resolves it from its own directory, so it may name nothing" -ForegroundColor Yellow
                # One re-install line per root: the legacy and PowerShell-source arms may have printed it.
                if ($null -ne $wired -and -not $psSource) { Write-Host "                    re-install this root to wire an absolute path: -ConfigDir `"$($t.Root)`"" }
            }
            elseif ($coll) { Write-Host "    collector     : $coll   exists: $(Test-Path -LiteralPath $coll)" }
            else { Write-Host "    collector     : UNKNOWN (command shape not recognised)" }
        }
        elseif ($own -eq 'UNREADABLE') {
            # A CORRUPT settings.json IS NOT A CLEAN ONE. It may carry a working statusLine that this
            # audit cannot see, so reporting "carries none" would send an operator away from a stray
            # publisher rather than towards it.
            Write-Host "    publishes to  : UNKNOWN -- settings.json could not be parsed, so its wiring is unknown" -ForegroundColor Yellow
            $bad++
        }
        else {
            Write-Host "    publishes to  : nothing -- this root carries no statusLine of ours"
            $bad++
        }
        # WITHOUT THESE TWO LINES, a name-shaped root nobody has ever logged into renders byte-for-byte
        # like a root wired ten minutes ago that simply has not run a session yet. Two states, opposite
        # fixes, one rendering. They do NOT gate the write -- a fresh root still needs wiring, because
        # the first session it runs is exactly the one that would come up unpublishing.
        $hasCfg = Test-Path -LiteralPath (Join-Path $t.Root ".claude.json")
        $hasCred = Test-Path -LiteralPath (Join-Path $t.Root ".credentials.json")
        $markers = "    login markers : .claude.json $(if ($hasCfg) { 'yes' } else { 'no ' })  .credentials.json $(if ($hasCred) { 'yes' } else { 'no ' })"
        if (-not $hasCfg -and -not $hasCred) { $markers += "  -- no session has ever launched from this root" }
        Write-Host $markers
        # A RECEIPT, NOT A CONFIG READ, and now per root. Whether a settings file names the script says
        # nothing about whether it has ever run -- that distinction is the one this repo keeps paying for.
        $latest = Join-Path $wantState "latest.json"
        Write-Host "    has published : $(Test-Path -LiteralPath $latest)   ($latest)"
    }

    # THE INDEPENDENT AUDIT. Enumerated by a DIFFERENT rule from the one that chose the targets, so it
    # can contradict them. Without it -Status could only ever confirm this script's own predicate --
    # a validator satisfied by construction. It is also what makes the name predicate's deliberate
    # case-sensitivity loud instead of a silent under-reach.
    $HomeDir = Resolve-HomeDir
    $seen = @(Get-ClaudeConfigCandidates -HomeDir $HomeDir)
    Write-Host ""
    Write-Host "  audit: $($seen.Count) ~/.claude* dir(s) under $HomeDir carry a settings.json, enumerated"
    Write-Host "         independently of the target set above"
    if ($seen.Count -eq 0) {
        Write-Host "         NOTHING EXAMINED -- so this audit concluded nothing. That is not the same as 'no orphans'." -ForegroundColor Yellow
    }
    foreach ($d in $seen) {
        if ($targets | Where-Object { Test-SameRoot $_.Root $d.FullName }) { continue }
        $orphan = $false; $unreadable = $false
        try { $orphan = (Get-Ownership (Read-Settings (Join-Path $d.FullName "settings.json"))) -eq 'OURS' } catch { $unreadable = $true }
        if ($unreadable) { Write-Host "         UNREADABLE: $($d.Name) -- settings.json could not be parsed, ownership unknown" -ForegroundColor Yellow }
        elseif ($orphan) { Write-Host "         ORPHAN: $($d.Name) carries a mefor-usage statusLine and is not in the target set" -ForegroundColor Yellow }
        else { Write-Host "         not judged: $($d.Name) -- carries no statusLine of ours" }
    }
    Write-Host ""
    Write-Host "  This reads the FILE. A file that carries the statusLine is not the same as a statusLine that FIRED."
    Write-Host ""
    if ($bad -eq 0) { exit 0 }
    if ($ok -eq 0) { exit 1 }
    exit 3
}

# --- Uninstall -------------------------------------------------------------------------------------
#
# THE MIRROR-IMAGE LIE IS WORSE THAN THE INSTALL LIE, because the operator believes they turned
# something off. A single-root -Uninstall under a pin strips one root, prints REMOVED, exits 0 -- and
# leaves every other root still wired and still publishing.

if ($Uninstall) {
    $removed = 0; $absent = 0; $foreign = 0; $failed = 0; $wouldRemove = 0; $unknown = 0
    Write-Host ""
    foreach ($t in $targets) {
        if (-not (Test-PathRootReachable $t.Settings)) {
            Write-Host "  UNKNOWN      $($t.Settings)   -- its drive or share is not reachable; nothing was read or removed" -ForegroundColor Red
            $unknown++
            continue
        }
        try {
            $settings = Read-Settings $t.Settings
            switch (Get-Ownership $settings) {
                'OURS' {
                    # THE COUNTER GOES INSIDE THE GUARD. An earlier version incremented $removed
                    # outside it, so `-Uninstall -AllRoots -WhatIf` printed "removed: 5" and exited 0
                    # having removed nothing -- an operator dry-running before committing would read
                    # that as "the collector is off" while all five roots kept publishing. It is the
                    # same shape as the install claim this whole change deletes, and worse, because a
                    # person believes they turned something OFF.
                    if ($PSCmdlet.ShouldProcess($t.Settings, "remove the $MARKER statusLine")) {
                        $settings.Remove('statusLine')
                        $backedTo = Write-SettingsFile $t.Settings $settings
                        Write-Host ("  REMOVED      {0}{1}" -f $t.Settings, $(if ($backedTo) { "   backup $backedTo" } else { "" }))
                        $removed++
                    }
                    else {
                        Write-Host "  WOULD REMOVE $($t.Settings)"
                        $wouldRemove++
                    }
                }
                'FOREIGN' { Write-Host "  FOREIGN      $($t.Settings)   -- someone else's statusLine, left untouched"; $foreign++ }
                default { Write-Host "  NOT PRESENT  $($t.Settings)   -- no $MARKER statusLine here"; $absent++ }
            }
        }
        catch {
            Write-Host "  FAILED       $($t.Settings)   -- $($_.Exception.Message)" -ForegroundColor Red
            $failed++
        }
    }
    Write-Host ""
    Write-Host ("Roots examined: {0}   ({1})" -f $targets.Count, $targetFrom)
    Write-Host ("  removed: {0}   not present: {1}   foreign: {2}   failed: {3}   unknown: {4}   would remove: {5}" -f `
            $removed, $absent, $foreign, $failed, $unknown, $wouldRemove)
    Write-Host ""
    # An unreachable root is not a dry-run success either: nothing about it was read.
    if ($WhatIfPreference -and $unknown -eq 0) { exit 0 }
    if ($failed + $unknown -eq 0) { exit 0 }
    if ($removed + $absent + $foreign -eq 0) { exit 1 }
    exit 3
}

# --- Install ---------------------------------------------------------------------------------------

# Gated, so -Status and -Uninstall work outside a checkout. The primary checkout, not this worktree: a
# worktree is disposable and the statusLine outlives it.
if (-not $CollectorPath) {
    $common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { Stop-Cannot "not inside a git repository -- run this from the MessageFoundry checkout, or pass -CollectorPath" }
    $CollectorPath = Join-Path (Split-Path ($common.Trim()) -Parent) "scripts/coord/usage-collect.ps1"
}
# ABSOLUTE BEFORE IT IS CHECKED OR BAKED IN. A statusLine runs from the session's working directory,
# so a relative path that passed the Test-Path below would name nothing when it fires (BACKLOG #7577).
$CollectorPath = Resolve-ArgPath $CollectorPath "-CollectorPath"
if (-not (Test-Path -LiteralPath $CollectorPath)) {
    Stop-Cannot "collector not found at $CollectorPath. The primary checkout does not carry it yet -- merge the branch that adds it, or advance the primary, before installing."
}

# BEFORE THE FIRST WRITE. See Assert-ShellQuotable: the paths going into the command have to survive
# both bash and pwsh, and a partial run would leave the box in a mixed state.
Assert-ShellQuotable $CollectorPath "the collector path"
foreach ($t in $targets) { Assert-ShellQuotable (Get-UsageStateDir $t.Root) "the publish path for $($t.Root)" }
# IN THE BODY, NOT A [ValidateRange], and on the install path only: a binding failure exits 1 with
# pwsh's own text, and exit 1 here means "roots were targeted and none reached the desired state". A
# usage error is exit 2. -Status and -Uninstall never use the interval.
if ($RefreshInterval -lt 1000) {
    Stop-Cannot "-RefreshInterval $RefreshInterval is under 1000 ms, the minimum Claude Code honours"
}
# A -SettingsPath directory is checked HERE, on the install path only, and before any write: a missing
# directory found inside the write loop fails that one target after the others were written, the mixed
# state these pre-passes exist to prevent. -Status and -Uninstall still report on a deleted root.
if ($targetFrom -eq '-SettingsPath') {
    foreach ($t in $targets) { Assert-RootExists $t.Root "the directory of -SettingsPath $($t.Settings)" }
}

$wrote = 0; $rewired = 0; $unchanged = 0; $refusing = 0; $failed = 0; $would = 0
Write-Host ""
foreach ($t in $targets) {
    $stateDir = Get-UsageStateDir $t.Root
    $cmd = New-WiredCommand $CollectorPath $stateDir
    try {
        $settings = Read-Settings $t.Settings
        $own = Get-Ownership $settings
        if ($own -eq 'FOREIGN') {
            $first = (([string]$settings['statusLine']['command'] -split "`r?`n", 2)[0]).Trim()
            Write-Host "  REFUSING   $($t.Settings)  -- a statusLine that is not ours is already configured" -ForegroundColor Red
            Write-Host "             its first line: $first"
            Write-Host "             Silently replacing someone's status bar is not this script's call. Remove it"
            Write-Host "             yourself, or merge the two commands by hand, then re-run."
            $refusing++
            continue
        }

        $wasState = $null
        $wasColl = $null
        $isOurs = ($own -eq 'OURS')
        if ($isOurs) {
            $existing = [string]$settings['statusLine']['command']
            $wasState = Get-WiredStateDir $existing
            $wasColl = Get-WiredCollectorPath $existing
            # A NUMBER, NOT A CAST. [int]'abc' threw here, inside the try, so the root counted FAILED
            # on every run and a re-install could never repair it (BACKLOG #7577). A non-number is
            # simply not the wanted value, so the root is rewired.
            $ri = $settings['statusLine']['refreshInterval']
            $sameRi = ($ri -is [long] -or $ri -is [int]) -and $ri -eq $RefreshInterval
            if ($existing -ceq $cmd -and $sameRi) {
                Write-Host "  UNCHANGED  $($t.Settings)"
                Write-Host "             already carries exactly this command and refreshInterval; not rewritten, no backup taken"
                $unchanged++
                continue
            }
        }

        if (-not $PSCmdlet.ShouldProcess($t.Settings, "install the $MARKER statusLine")) {
            Write-Host "  WOULD WRITE $($t.Settings)"
            Write-Host "              would wire it to publish to $stateDir"
            $would++
            continue
        }

        $settings['statusLine'] = [ordered]@{
            type            = "command"
            command         = $cmd
            refreshInterval = $RefreshInterval
        }
        $backedTo = Write-SettingsFile $t.Settings $settings

        if ($isOurs) {
            # Printed separately from WROTE rather than folded into it: "we wired a root that had
            # nothing" and "we corrected a root that was publishing to the wrong account" are different
            # facts to an operator deciding whether a stray file needs cleaning up.
            #
            # AND THE REASON IS DERIVED, NOT ASSUMED. This branch is entered whenever the command is
            # not byte-identical, which is a WEAKER fact than any of the sentences below. An earlier
            # version printed "published somewhere else" unconditionally, and an operator's real run
            # produced a block reading "published somewhere else / was: <path> / now: <the same path>"
            # -- the publish path had not moved at all, the COLLECTOR had. A line that contradicts the
            # two lines under it is the same defect this whole change exists to remove.
            $wasPsSource = Test-IsPowerShellSourceStatusLine $existing
            $why = if (-not $wasState) {
                "carried no -StateDir, so the collector chose its own default at run time"
            }
            elseif (-not (Test-SameRoot $wasState $stateDir)) {
                "published somewhere else"
            }
            elseif ($wasColl -and $wasColl -ne $CollectorPath) {
                "named a different collector"
            }
            elseif ($wasPsSource) {
                "was PowerShell source, which bash cannot parse, so it published nothing"
            }
            else {
                "differed from this command in some other way (quoting, refreshInterval, or an unrecognised shape)"
            }
            Write-Host "  REWIRED    $($t.Settings)"
            Write-Host "             replaced a $MARKER statusLine that $why"
            Write-Host "             was: $(if ($wasState) { $wasState } else { '(no -StateDir -- the collector chose its own default)' })"
            Write-Host "             now: $stateDir"
            # PowerShell source is ALSO said when an earlier arm took the reason: the old command may
            # have named another path or collector as well, and the operator needs both facts (#1459).
            if ($wasPsSource -and $why -notlike "was PowerShell source*") {
                Write-Host "             the old command was also PowerShell source, which bash cannot parse, so it published nothing"
            }
            if ($wasColl -and $wasColl -ne $CollectorPath) {
                Write-Host "             collector was: $wasColl"
                Write-Host "             collector now: $CollectorPath"
            }
            $rewired++
        }
        else {
            $latest = Join-Path $stateDir "latest.json"
            # PRESENT TENSE IS NOT USED. "wired to publish to" is backed by "a settings key was
            # written"; "publishes to" would assert something no check here supports.
            Write-Host "  WROTE      $($t.Settings)"
            Write-Host "             wired to publish to $latest $(if (Test-Path -LiteralPath $latest) { '(a reading is already there)' } else { '(nothing has published there yet)' })"
            $wrote++
        }
        if ($backedTo) { Write-Host "             backup $backedTo" }
        else { Write-Host "             no backup taken -- this root had no settings.json to preserve" }
    }
    catch {
        Write-Host "  FAILED     $($t.Settings)  -- $($_.Exception.Message)" -ForegroundColor Red
        $failed++
    }
}

Write-Host ""
# THE POPULATION IS NAMED, not left as a bare count. "Roots examined: 5" alone reads as "all of them",
# which is the completeness claim that produced this whole change.
Write-Host ("Roots examined: {0}   ({1})" -f $targets.Count, $targetFrom)
# NO "skipped" COLUMN. An earlier draft carried one for "the backup threw so the write was never
# attempted", but the catch below reports that as FAILED, so nothing could ever increment it. A tally
# column that is structurally always zero reads as "nothing was skipped" -- a claim about the run
# rather than a fact about the code, which is the shape of overclaim this whole change removes.
Write-Host ("  wrote: {0}   rewired: {1}   unchanged: {2}   refusing: {3}   failed: {4}   would write: {5}" -f `
        $wrote, $rewired, $unchanged, $refusing, $failed, $would)
if ($AllRoots -and $addedOutside) {
    Write-Host "  added: $addedOutside (this session's CLAUDE_CONFIG_DIR, outside $HomeDir)"
}
Write-Host "  collector      : $CollectorPath   (one copy, shared by every root above)"
Write-Host "  refreshInterval: $RefreshInterval ms"
Write-Host ""
Write-Host "  Takes effect in NEWLY STARTED sessions; existing ones keep the config they booted with."
Write-Host "  A root listed above is a root whose settings FILE now carries the statusLine. That is not the"
Write-Host "  same as a statusLine that FIRED -- confirm with a session started under that root."
Write-Host "  Interactive only -- it never runs under 'claude -p' or the SDK."
Write-Host "  Read a root's numbers from a session pinned to it:"
Write-Host "    pwsh -NoProfile -File scripts\coord\usage.ps1"
Write-Host ""

# A DRY RUN MUST NOT REPORT FAILURE. Under -WhatIf ShouldProcess returns false for every root, so a
# purely tally-driven rule would return 1 -- while the shipped script exits 0. $WhatIfPreference is
# True inside the script under -WhatIf (measured) and is the test.
if ($WhatIfPreference) { exit 0 }
$desired = $wrote + $rewired + $unchanged
if ($desired -eq $targets.Count) { exit 0 }
if ($desired -eq 0) { exit 1 }
exit 3
