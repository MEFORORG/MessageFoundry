# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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
    credential set and therefore one Anthropic account, and separate accounts have separate 5-hour and
    7-day pools. One shared file across roots is last-writer-wins across unrelated quotas. The rule
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
    # ONE -ConfigDir PER VALUE. `pwsh -File` hands each argument over as a single string, so
    # `-ConfigDir A,B` binds as the one value "A,B" (measured). Nothing splits it, deliberately: a
    # Windows path may legally contain a comma.
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Uninstall,
    [switch]$Status,
    # Milliseconds. Minimum honoured by Claude Code is 1000.
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

function Assert-RootExists([string]$Path, [string]$What) {
    if (Test-Path -LiteralPath $Path -PathType Container) { return }
    $msg = "$What does not exist: $Path"
    if ($Path -like '*,*') {
        $msg += "`n              (that string contains a comma -- `pwsh -File` passes it as ONE value;" +
        " repeat -ConfigDir per path, or use -AllRoots)"
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
    Set-Content -LiteralPath $Path -Value $json -Encoding UTF8
    return $backedTo
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
    # The guard is inline so a missing script degrades to a marker rather than erroring into the status
    # bar on every single message -- a statusLine that shouts an exception is worse than one that says
    # nothing. $d is a VARIABLE at the call site, not an interpolation, which is what makes a state dir
    # containing spaces safe.
    return "# $MARKER`n" +
    "`$s = '$($Collector -replace "'", "''")'; " +
    "`$d = '$($StateDir  -replace "'", "''")'; " +
    "if (Test-Path -LiteralPath `$s) { & pwsh -NoProfile -File `$s -StateDir `$d } " +
    "else { Write-Output '${MARKER}: collector missing' }"
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

$targets = @()
$targetFrom = ""
if ($script:GaveSettingsPath) {
    $targetFrom = "-SettingsPath"
    $targets = @($SettingsPath | ForEach-Object {
            [pscustomobject]@{ Settings = $_; Root = (ConvertTo-NormalRootPath (Split-Path $_ -Parent)) }
        })
}
elseif ($script:GaveConfigDir) {
    $targetFrom = "-ConfigDir"
    foreach ($d in $ConfigDir) { Assert-RootExists $d "config dir" }
    $targets = @($ConfigDir | ForEach-Object {
            $r = ConvertTo-NormalRootPath $_
            [pscustomobject]@{ Settings = (Join-Path $r "settings.json"); Root = $r }
        })
}
elseif ($AllRoots) {
    $targetFrom = "-AllRoots"
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
                $ok++
            }
            if ($coll) { Write-Host "    collector     : $coll   exists: $(Test-Path -LiteralPath $coll)" }
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
    $removed = 0; $absent = 0; $foreign = 0; $failed = 0; $wouldRemove = 0
    Write-Host ""
    foreach ($t in $targets) {
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
    Write-Host ("  removed: {0}   not present: {1}   foreign: {2}   failed: {3}   would remove: {4}" -f `
            $removed, $absent, $foreign, $failed, $wouldRemove)
    Write-Host ""
    if ($WhatIfPreference) { exit 0 }
    if ($failed -eq 0) { exit 0 }
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
if (-not (Test-Path -LiteralPath $CollectorPath)) {
    Stop-Cannot "collector not found at $CollectorPath. The primary checkout does not carry it yet -- merge the branch that adds it, or advance the primary, before installing."
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
        $isOurs = ($own -eq 'OURS')
        if ($isOurs) {
            $existing = [string]$settings['statusLine']['command']
            $wasState = Get-WiredStateDir $existing
            if ($existing -ceq $cmd -and [int]$settings['statusLine']['refreshInterval'] -eq $RefreshInterval) {
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
            Write-Host "  REWIRED    $($t.Settings)"
            Write-Host "             replaced a $MARKER statusLine that published somewhere else"
            Write-Host "             was: $(if ($wasState) { $wasState } else { '(no -StateDir -- the collector chose its own default)' })"
            Write-Host "             now: $stateDir"
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
