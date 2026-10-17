# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Install (or remove) the worktree gate -- a PreToolUse hook that stops sessions BUILDING in the
    shared primary checkout, and hijacking a linked worktree onto another session's branch.

.DESCRIPTION
    Copies scripts\hooks\worktree_gate.ps1 to a shared USER-scope location (%USERPROFILE%\.claude\hooks\)
    and registers it as a PreToolUse hook in the settings.json of EVERY Claude config dir this box uses:
    ~/.claude (the Desktop app) AND each ~/.claude-account-N (the VS Code launchers that set
    CLAUDE_CONFIG_DIR). Override the set with -ConfigDir.

    WHY EVERY CONFIG DIR. The gate used to wire only ~/.claude, which left every ~/.claude-account-N
    session UNGATED -- and those are where the parallel VS Code chats run. A session running under an
    ungoverned account checked its own branch out inside another session's linked worktree (a hijack that
    silently swapped that session's files mid-task); the gate that would have blocked it was simply not
    installed there. This mirrors what install-selfheal.ps1 already does: wire all of them.

    WHY USER SCOPE, and why an installed COPY:

      * Reach. A hook in the project's .claude\settings.json is git-tracked, so it lives on ONE branch and
        does not exist in the other worktrees until each of them merges it. A user-scope hook governs every
        session on the machine the moment it is written. Hook definitions from the user, project and local
        scopes are unioned, so this ADDS to the repo's existing guards rather than replacing them.

      * Survivability. The command must not point into a working tree. The primary checkout is routinely
        on a detached HEAD or an old commit; a hook whose script path lives there vanishes on a checkout,
        and a hook whose script is missing exits non-zero-but-not-2 -- which means the tool call RUNS
        ANYWAY, silently. The gate would be off in every session and nothing would say so. So we install a
        copy outside every tree (once, shared, referenced by absolute path from each account) and re-copy
        it on each install.

    The gate only governs the checkouts listed in worktree-gate.repos.txt. That file IS the kill switch:
    -Uninstall removes it (and the hook entries from every config dir).

    THE ALLOWLIST IS MERGED, NEVER REPLACED (BACKLOG #1375). A run ADDS the roots it names and keeps
    every root already there. It used to overwrite the file with just this run's repos, and a bare run
    resolves to exactly ONE repo -- so on a box governing two checkouts, re-installing dropped one.

    AND THE DROPPED ROOT GOES UNGOVERNED IN SILENCE -- NOT by tripping the kill switch. A bare install
    writes ONE root, never zero, so the gate's zero-root exit never fires on this path and the gate
    stays fully on for the root that survived. The dropped root is simply ABSENT from the list: no rule
    matches a path inside it, the hook exits 0 printing nothing, and writes into that checkout quietly
    stop being denied. There is no empty file to notice and no message anywhere.

    To stop governing one root without turning the gate off, name it: -Uninstall -Repo "<path>".

    THE SOURCE IS CHECKED AGAINST origin/main, NOT ONLY AGAINST ITSELF (BACKLOG #1878). The bytes this
    installs come from the checkout it runs in. An install REFUSES when that checkout's gate differs
    from the gate at -UpstreamRef (origin/main by default), or when that ref cannot be read; pass
    -AllowStaleSource for a deliberate offline install, rollback or test. -Status grades the installed
    gate against the same ref, so a stale install run from a stale tree no longer reads IN SYNC. The
    script never fetches: the ref is as fresh as this checkout's last fetch.

    Run from a PLAIN TERMINAL, not from inside Claude Code -- a session that can install its own gate can
    uninstall it. The script refuses when $env:CLAUDECODE is set.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Repo C:\Users\me\Code\Probe   # govern a test repo
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -ConfigDir C:\Users\me\.claude-account-3
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall -Repo C:\Users\me\Code\Probe  # stop governing ONE
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Status
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -AllowStaleSource   # deliberately install a gate not on origin/main
#>
[CmdletBinding()]
param(
    # Primary checkout(s) to govern -- ADDED to the allowlist, never replacing it. Defaults to this
    # repo's main worktree. With -Uninstall it means the opposite: stop governing exactly these roots
    # and leave everything else alone.
    [string[]]$Repo,
    [switch]$Uninstall,
    [switch]$Status,
    # Do not gate Task/Agent/Workflow dispatch from the primary (writes are still gated).
    [switch]$NoDispatchGate,
    # Gate the EnterWorktree tool (rule 4), which relocates a LIVE session into a worktree.
    #
    # OPT-IN, and deliberately OFF by default. Rule 4 has never been installed, and turning it on as a
    # SIDE EFFECT of installing an unrelated fix would be a trap: with rules 2 and 4 both live, a session
    # started in the primary has no in-session path to isolation at all -- it can neither dispatch a
    # subagent nor relocate itself, so it must be restarted elsewhere by a human. That is a hard stop on
    # workflow-by-default from the directory sessions naturally open in, and it is a decision the owner
    # makes on purpose (docs/WORKTREES.md), not one that rides along with a regex fix.
    #
    # It also duplicates a guard the vendor now ships: since v2.1.206 EnterWorktree into a path OUTSIDE
    # .claude/worktrees/ raises a confirmation prompt that no permission rule can suppress, and since
    # v2.1.198 the transcript follows the session's cwd BOTH ways, so relocation re-files a chat rather
    # than losing it. See docs/SESSION-DRIFT-CONTROLS.md.
    [switch]$EnterWorktreeGate,
    # Config dirs to wire the hook into. Default: ~/.claude plus every existing ~/.claude-account-*.
    [string[]]$ConfigDir,
    # The ref whose gate counts as CURRENT (BACKLOG #1878). -Status grades the installed gate against
    # it as well as against this checkout, and an install refuses when this checkout's gate differs
    # from it. Read as last fetched: this script never fetches. A name with a slash means the
    # remote-tracking ref (refs/remotes/<name>), never a local branch of that name; pass a full
    # refs/... name for anything else. It may not start with '-', so git can never read it as an option.
    [ValidatePattern('\A[^-]')]
    [string]$UpstreamRef = "origin/main",
    # Install this checkout's gate even though it differs from -UpstreamRef's, or -UpstreamRef cannot
    # be read. For a deliberate offline install, a rollback to an older gate, or a test of an unmerged
    # gate change. Nothing else.
    [switch]$AllowStaleSource
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path

# The gate SCRIPT + its allowlist live ONCE, shared, under ~/.claude\hooks -- referenced by absolute path
# from every config dir's settings.json, so a single copy (and a single kill switch) governs all accounts.
# Null-safely: $env:USERPROFILE is Windows-only and NULL elsewhere, where Join-Path throws a
# parameter-binding error instead of returning a path. Same idiom as its sibling scripts.
$HomeDir   = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
$HooksDir  = Join-Path $HomeDir ".claude/hooks"
$GateDst   = Join-Path $HooksDir "worktree_gate.ps1"
$ReposFile = Join-Path $HooksDir "worktree-gate.repos.txt"

# Marker so we can find (and remove) exactly the entries we added, without disturbing other hooks.
$Marker = "worktree_gate.ps1"

# The NAME shape of a launcher config dir, and the ONLY thing this script wires. ~/.claude is the Desktop
# app; every VS Code launcher on this box points CLAUDE_CONFIG_DIR at ~/.claude-account-<N> with N decimal
# -- not inferred from a directory listing but from how the launchers BUILD the path
# (~/claude-launchers/Launch-Claude-{1..4}.ps1 assign a literal `.claude-account-<N>`). A suffix after the
# number is therefore not an account, because nothing can launch from one.
#
# ANCHORED, and the anchors are the entire predicate (BACKLOG #1024). The old filter was
# `-Filter ".claude-account-*"`, which matches any name merely BEGINNING with `.claude-account-`.
# Measured 2026-08-04: `~/.claude-account-2.lock` IS a directory, so the filter matched it and this
# installer wrote gate wiring into it on every run -- into a dir with no `.claude.json`, no
# `.credentials.json` and no sessions, i.e. one nothing has ever launched from.
#
# THIS IS THE WRITER. The Python reader (tests/test_gate_installed_parity.py) used the same unanchored
# glob and read that wiring back as evidence the wiring was correct; the two agreed because both were
# wrong the same way. #199 anchored the reader as `\A\.claude-account-\d+\Z`; this is the matching half,
# so the predicate is now the same on both sides.
#
# `\z`, NOT `\Z`. Python's `\Z` is the absolute end of the string; .NET's `\Z` also matches BEFORE a
# trailing newline, and .NET's `\z` is the one that means what Python's `\Z` means. Spelling it `\Z` here
# would look like the reader and mean something slightly wider.
#
# Case-SENSITIVE, matching the reader. `-Filter` is case-insensitive on Windows, so a `.Claude-Account-2`
# would reach this predicate and be rejected -- leaving that dir unwired. That direction is deliberate:
# the -Status audit below enumerates independently of this predicate and reports any such dir by name,
# which is a louder outcome than silently wiring something the reader would refuse to judge.
$LauncherName = [regex]'\A\.claude-account-\d+\z'

# Every ~/.claude* directory carrying a settings.json, WITHOUT judging what it is. Deliberately wider than
# the wire set: it is the -Status audit's independent population, and it must not be selected by the same
# predicate whose correctness it exists to check.
function Get-ConfigCandidates([string]$Root) {
    @(
        Get-ChildItem -LiteralPath $Root -Directory -Filter ".claude*" -Force -ErrorAction SilentlyContinue |
            Where-Object { Test-Path -LiteralPath (Join-Path $_.FullName "settings.json") -PathType Leaf }
    )
}

# Config dirs to wire. Default: ~/.claude + every existing ~/.claude-account-<N> (the VS Code launchers).
#
# -Force IS LOAD-BEARING AND ITS ABSENCE IS INVISIBLE ON WINDOWS. Get-ChildItem omits hidden entries
# without it. On Windows a dot-prefixed directory carries no hidden ATTRIBUTE, so every ~/.claude-account-N
# enumerates either way and the omission cannot be reproduced locally. On Linux the dot prefix IS the
# hidden convention, so this glob returns NOTHING and the wire set collapses to the single explicit
# ~/.claude candidate on the line above -- which is not a glob and so survives. That is precisely the
# shape CI reported on the ubuntu leg (writer wired ['.claude']; the reader, anchored by #199, judged
# ['.claude', '.claude-account-1', '.claude-account-42']), and it is why the parity test caught here what
# no Windows run could. Get-ConfigCandidates above already passes -Force for the same reason; the two
# enumerations must agree, and a difference between them is the exact defect #1024 exists to close.
if (-not $ConfigDir -or $ConfigDir.Count -eq 0) {
    $cands = @( (Join-Path $HomeDir ".claude") )
    $cands += @(
        Get-ChildItem -LiteralPath $HomeDir -Directory -Filter ".claude-account-*" -Force -ErrorAction SilentlyContinue |
            Where-Object { $LauncherName.IsMatch($_.Name) } |
            ForEach-Object { $_.FullName }
    )
    $ConfigDir = @($cands | Where-Object { Test-Path -LiteralPath $_ -PathType Container })
}

function Read-Settings([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $Path -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return [ordered]@{} }
    try { return ($raw | ConvertFrom-Json -AsHashtable) }
    catch { throw "$Path is not valid JSON -- fix it by hand before installing (it is live config for every session)." }
}

function Write-Settings([string]$Path, $Data) {
    # Two sessions installing at once could interleave a read-modify-write and leave INVALID JSON, which
    # would break hooks in every session on the machine at once. Serialize to a temp file, parse it back
    # to prove it is valid, keep a backup, then move it into place in one atomic operation. Done PER FILE,
    # so a failure wiring one config dir can never corrupt another.
    $json = $Data | ConvertTo-Json -Depth 20
    $null = $json | ConvertFrom-Json      # throws before we touch the real file
    $tmp = "$Path.tmp-$PID"
    Set-Content -LiteralPath $tmp -Value $json -Encoding utf8
    if (Test-Path -LiteralPath $Path) { Copy-Item -LiteralPath $Path "$Path.bak" -Force }
    Move-Item -LiteralPath $tmp -Destination $Path -Force
}

function Remove-GateHooks($Data) {
    if (-not $Data.hooks -or -not $Data.hooks.PreToolUse) { return $Data }
    $kept = @(
        $Data.hooks.PreToolUse | Where-Object {
            $entry = $_
            -not (@($entry.hooks) | Where-Object { "$($_.command)" -like "*$Marker*" })
        }
    )
    if ($kept.Count -gt 0) { $Data.hooks.PreToolUse = $kept }
    else { $null = $Data.hooks.Remove("PreToolUse") }
    return $Data
}

# Tool names reachable through a PreToolUse entry whose command names the gate. ONE reader, used by both
# the wire-set scan and the independent audit below -- two copies would drift, and the copy that drifts is
# the one that decides whether an orphan is reported.
function Get-WiredMatchers([string]$SettingsPath) {
    $wired = [System.Collections.Generic.HashSet[string]]::new()
    $s = Read-Settings $SettingsPath
    foreach ($e in @($s.hooks.PreToolUse)) {
        if (@($e.hooks) | Where-Object { "$($_.command)" -like "*$Marker*" }) {
            foreach ($t in "$($e.matcher)".Split("|")) { if ($t) { $null = $wired.Add($t) } }
        }
    }
    # THE COMMA IS LOAD-BEARING -- do not delete it. A bare `return $wired` UNROLLS the set into the
    # pipeline and no caller ever sees a HashSet: zero matchers arrive as $null, ONE arrives as a
    # [String] whose .Contains() is a SUBSTRING test rather than set membership, and two or more as
    # [Object[]]. The one-element arm is the dangerous one because it is silent -- exit code 0 and a
    # clean wrong answer -- while the empty arm at least crashes the caller below.
    #
    # Stated once here and made EXECUTABLE, not restated, in tests/test_install_gate_wiring.py: the
    # three tests named for the substring, empty and audit arms each fail on a bare return.
    return ,$wired
}

function Get-GateVersion([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $m = [regex]::Match((Get-Content -LiteralPath $Path -Raw), '\$GateVersion\s*=\s*"([^"]+)"')
    if ($m.Success) { $m.Groups[1].Value } else { "(unstamped)" }
}

function Get-GateHash([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    # A CONTENT hash, not a byte hash -- the same basis tests\test_gate_installed_parity.py uses, so the
    # two instruments print the SAME digest and cannot disagree about one file.
    #
    # Get-FileHash is byte-exact, and that made every Windows checkout read as *** STALE *** in red: git's
    # clean filter stores LF, core.autocrlf=true checks out CRLF, and the install below is a Copy-Item,
    # which translates nothing -- so the installed copy carries whatever form the checkout that installed
    # it had. Measured 2026-08-04, the two differed by 805 line endings and NOTHING else, while
    # `git status` called the file clean. A false STALE is not a harmless false alarm here: the remedy it
    # printed is a re-install, and re-installing from a checkout older than the installed gate DOWNGRADES
    # this machine-global file for every session on the box.
    #
    # Folded on BYTES (drop the CR of each CRLF pair) rather than by decoding to text: the file need not
    # be valid UTF-8, and a decode/re-encode round trip could move a BOM or a lone high byte and change
    # the digest for a reason that has nothing to do with content.
    #
    # Latin-1 is the one encoding that is still a byte fold: it maps each byte 0-255 to exactly one char
    # and back, with no BOM and no replacement character, so the Replace below drops exactly the CR of
    # each CRLF pair and nothing else. It replaced a per-byte interpreted loop that took about 3 s on
    # the 260 KB gate, which mattered once #1878 made -Status hash three copies instead of two.
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $latin1 = [System.Text.Encoding]::Latin1
    $folded = $latin1.GetBytes($latin1.GetString($bytes).Replace("`r`n", "`n"))
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        (($sha.ComputeHash($folded) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
    } finally {
        $sha.Dispose()
    }
}

# Every tool a gate script branches on. -Status calls this on the INSTALLED copy, deliberately: the
# question it answers is "which rules does the gate that is RUNNING have, and are they all wired", and the
# source's rule set is not evidence for either. That is the whole point of the audit -- rule 4 was in the
# source, declared by this installer, and covered by tests, while the running gate had never heard of it.
#
# THE COMMA ON BOTH EXIT PATHS IS LOAD-BEARING, for the reason Get-WiredMatchers above already
# states in full -- read it there rather than here. The short form: a bare return UNROLLS, so a
# zero-tool corpus arrives as $null and a ONE-tool corpus as a [String] whose .Contains() is a
# substring test wearing set membership. Callers must NOT re-wrap in @(); doing so re-hides the
# defect behind the caller's own grace, which is what BACKLOG #1291 is about.
function Get-HandledTools([string]$Path) {
    if (-not (Test-Path -LiteralPath $Path)) { return ,@() }
    $text = Get-Content -LiteralPath $Path -Raw
    $tools = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($m in [regex]::Matches($text, '\$tool\s+-(?:not)?in\s+@\(([^)]*)\)')) {
        foreach ($q in [regex]::Matches($m.Groups[1].Value, '"([^"]+)"')) { $null = $tools.Add($q.Groups[1].Value) }
    }
    ,@($tools)
}

# ------------------------------------------------------------------------------- upstream provenance
# THE DEFECT THESE CLOSE (BACKLOG #1878). The install copied its bytes from the checkout the script ran
# in, and -Status graded the installed gate against that SAME checkout. So an install from a stale tree
# shipped a stale gate to every config dir on the box, and -Status run from that tree then read
# IN SYNC. Measured 2026-09-21: a primary 66 commits behind origin/main reported IN SYNC while a worktree
# at origin/main reported STALE against the same installed file.
#
# So both paths now also read one fixed reference: the gate blob at -UpstreamRef (origin/main by
# default). The script NEVER fetches. The ref is as fresh as the last fetch in this checkout, and every
# line that prints it says so.
#
# PARAMETER-FED and reading no script-scope variable, for the reason the allowlist functions below give:
# the install path refuses inside Claude Code, so the tests lift these out and run them on a fixture.

# The gate as it stands at $Ref, plus how far this checkout's HEAD sits from it.
#
# Available is $true only when the blob was read and hashed. Otherwise Reason says why, and every
# caller must treat that as UNVERIFIED -- never as a match.
#
# THE HASH IS Get-GateHash, ON PURPOSE. The blob is written to a temp file and hashed by the same
# function that hashes the installed copy and the working file, so all three digests share one
# line-ending fold and can only differ in content. The blob is read as raw BYTES through a process
# stream: PowerShell's native-command pipeline would decode it as text first.
#
# Never throws. -Status must never fail, and a missing ref is a reading, not an error.
function Get-UpstreamGate {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$RepoRoot,
        [Parameter(Mandatory)][string]$Ref,
        [string]$RelPath = "scripts/hooks/worktree_gate.ps1"
    )

    $out = [ordered]@{ Ref = $Ref; Available = $false; Sha = $null; Behind = $null; Ahead = $null; Reason = $null }
    $tmp = $null
    try {
        # The PATH-resolved executable, used for EVERY call below. A bare "git" in ProcessStartInfo goes
        # through the Windows CreateProcess search, which tries the current directory before PATH, so a
        # git.exe sitting in the folder the operator ran from would answer the currency check.
        $gitExe = @(Get-Command git -CommandType Application -ErrorAction SilentlyContinue)[0].Source
        if (-not $gitExe) {
            $out.Reason = "git is not on PATH"
            return [pscustomobject]$out
        }
        # WHICH REF, WITHOUT ASKING git TO GUESS. A short name like origin/main resolves to
        # refs/heads/origin/main FIRST when such a local branch exists, and refs are shared by every
        # worktree. So a name with a slash is read as a REMOTE-TRACKING ref and nothing else; a full
        # refs/... name is taken as written; a name with no slash (a SHA, HEAD, a local branch) is
        # left to git. No separate rev-parse: a git start costs over a second on a large Windows
        # checkout, and a cat-file of a missing ref already says so.
        $gitRef = if ($Ref -like "refs/*" -or $Ref -notlike "*/*") { $Ref } else { "refs/remotes/$Ref" }

        $tmp = [System.IO.Path]::GetTempFileName()
        $psi = [System.Diagnostics.ProcessStartInfo]::new($gitExe)
        foreach ($a in @("-C", $RepoRoot, "cat-file", "blob", "${gitRef}:$RelPath")) { $psi.ArgumentList.Add($a) }
        $psi.UseShellExecute = $false
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        # "Never fetches" has to hold in a partial clone too, where cat-file would otherwise fetch a
        # missing blob from the promisor remote and could sit on a credential prompt. A closed stdin and
        # no terminal prompt make any such attempt fail fast instead of hanging -Status.
        $psi.RedirectStandardInput = $true
        $psi.Environment["GIT_NO_LAZY_FETCH"] = "1"
        $psi.Environment["GIT_TERMINAL_PROMPT"] = "0"
        $p = [System.Diagnostics.Process]::Start($psi)
        try {
            $p.StandardInput.Close()
            $errText = $p.StandardError.ReadToEndAsync()
            $fs = [System.IO.File]::Create($tmp)
            try { $p.StandardOutput.BaseStream.CopyTo($fs) } finally { $fs.Dispose() }
            $p.WaitForExit()
            if ($p.ExitCode -ne 0) {
                $out.Reason = "${gitRef}:$RelPath does not resolve here: never fetched, or not a git checkout (git: $("$($errText.Result)".Trim()))"
                return [pscustomobject]$out
            }
        } finally {
            $p.Dispose()
        }
        $out.Sha = Get-GateHash $tmp

        # Left is HEAD's side (ahead), right is the ref's side (behind). An unborn HEAD leaves both
        # $null, which callers print as unknown rather than as zero.
        $counts = & $gitExe -C $RepoRoot rev-list --left-right --count "HEAD...$gitRef" 2>$null
        if ($LASTEXITCODE -eq 0 -and "$counts" -match '\A\s*(\d+)\s+(\d+)\s*\z') {
            $out.Ahead  = [int]$Matches[1]
            $out.Behind = [int]$Matches[2]
        }
        $out.Available = $true
    } catch {
        $out.Available = $false
        $out.Sha = $null
        $out.Reason = "reading $Ref failed: $($_.Exception.Message)"
    } finally {
        if ($tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    }
    [pscustomobject]$out
}

# One sentence for where this checkout sits against the ref. -ContentDiffers is for callers that
# already know the two gates differ: then a behind-count of zero is not a contradiction, it means this
# checkout carries a gate change the ref does not. Without that knowledge the note would be false.
function Format-UpstreamPosition {
    param($Upstream, [switch]$ContentDiffers)
    if ($null -eq $Upstream.Behind) { return "this checkout's position against $($Upstream.Ref) could not be read" }
    $s = "this checkout is $($Upstream.Behind) commit(s) behind $($Upstream.Ref) and $($Upstream.Ahead) ahead"
    if ($ContentDiffers -and $Upstream.Behind -eq 0) {
        $s += " (so it carries a gate change $($Upstream.Ref) does not: a commit of its own or an uncommitted edit)"
    }
    $s
}

# Why an install from this checkout must not go ahead silently, or $null when it may.
#
# $null in exactly one case: this checkout's gate has the same content as the ref's. An unreadable ref
# is a refusal too. "Could not check" is not "checked and current", and an install that proceeds on
# it is the same unverified machine-global write this function exists to stop.
#
# A MISSING SOURCE is refused here as well, and -AllowStaleSource cannot pass it (the caller checks
# presence separately). Left to the Copy-Item, it failed only AFTER the allowlist write, so the run
# changed the box and then threw with no refusal text.
function Get-StaleSourceRefusal {
    [CmdletBinding()]
    param(
        [string]$SourcePath,
        [string]$SourceSha,
        [Parameter(Mandatory)]$Upstream
    )

    if (-not $SourceSha) {
        return "Refusing to install: this checkout has no gate at $SourcePath, so there is nothing to install. Nothing on this box has been changed."
    }
    if ($Upstream.Available -and $Upstream.Sha -eq $SourceSha) { return $null }

    $short = { param($h) if ($h) { $h.Substring(0, 12).ToLowerInvariant() } else { "(none)" } }
    $ref = $Upstream.Ref
    $head = if ($Upstream.Available) {
        @(
            "Refusing to install: this checkout's gate is not the one on $ref."
            "  this checkout : $SourcePath  sha $(& $short $SourceSha)"
            "  upstream      : $ref  sha $(& $short $Upstream.Sha)  (as last fetched; this script never fetches)"
            "  position      : $(Format-UpstreamPosition $Upstream -ContentDiffers)"
            "Installing would put THIS checkout's gate in place for every session on this box. Bring this"
            "checkout up to $ref and re-run, or run the installer from a checkout that is at $ref."
        )
    } else {
        @(
            "Refusing to install: $ref could not be read ($($Upstream.Reason)),"
            "so nothing shows that this checkout's gate is current."
            "  this checkout : $SourcePath  sha $(& $short $SourceSha)"
            "Fetch $ref in this checkout, or name a readable ref with -UpstreamRef, and re-run."
        )
    }
    (@($head) + @(
            "If you MEAN to install this tree anyway -- an offline box whose $ref is itself behind, a"
            "deliberate rollback to an older gate (the downgrade -Status's STALE warning describes), or a"
            "test of an unmerged gate change -- re-run with -AllowStaleSource. The switch exists for those"
            "cases alone. Nothing on this box has been changed."
        )) -join [Environment]::NewLine
}

# --------------------------------------------------------------------------------------- allowlist
# THE DEFECT THESE CLOSE (BACKLOG #1375). The install path used to write the allowlist with a bare
# Set-Content of only THIS run's resolved repos, and nothing between the parameter block and that write
# ever read the file back. A bare run resolves to exactly ONE repo -- the main worktree, via
# `git worktree list` -- so on a box whose allowlist named two roots (measured live on this machine: the
# engine checkout AND the vault clone) a bare re-install DROPPED one.
#
# And the dropped root goes UNGOVERNED SILENTLY. Say the mechanism exactly, because the plausible one is
# wrong and was written here first: this is NOT the zero-root kill switch firing. A bare install writes
# ONE root, never zero, so `if ($roots.Count -eq 0) { exit 0 }` in the gate never runs on this path, and
# the gate keeps governing the root that survived just as strictly as before.
#
# The dropped root is simply ABSENT from the list the gate loads. Test-Governed answers $null for every
# path inside it, so no rule matches, the hook exits 0 with no output, and writes into that checkout stop
# being denied. That is the shape this repo keeps finding -- a clean exit code over a wrong answer -- and
# it is worse than the kill switch, not milder: the kill switch leaves an empty file somebody can notice,
# whereas this leaves a plausible-looking allowlist that is quietly one root short.
#
# EVERYTHING BELOW IS PARAMETER-FED and reads no script-scope variable ($ReposFile, $HooksDir, $Repo).
# That is not tidiness, it is the only way any of this gets verified: install-gate.ps1 REFUSES to run
# inside Claude Code (the throw below), so no session can exercise the install path at all. The tests in
# tests/test_install_gate_allowlist_merge.py lift these four functions out by AST and run them in
# isolation under `Set-StrictMode -Version Latest`, so a future edit that reaches for a script variable
# THROWS in the extracted copy instead of quietly yielding $null.

# The comparison key for ONE allowlist line: case-insensitive, slash-direction-insensitive, trailing
# separator ignored.
#
# String.Replace, not the -replace operator: `-replace '\'` is a lone escape and an invalid regex.
#
# DELIBERATELY NOT the gate's Get-ComparablePath (scripts/hooks/worktree_gate.ps1), which calls
# GetFullPath first. This one must not: it runs over lines naming checkouts that may be GONE, or on a
# drive this run cannot see, and resolving them could throw and take the install down -- or fold two
# lines together on evidence that is not there.
#
# The omission is ONE-DIRECTIONAL, and that is the whole safety argument. Skipping GetFullPath can only
# make this key FINER than the gate's, never coarser. Finer writes a harmless duplicate line; COARSER
# silently drops a root, which is the defect above -- and in -Remove mode it un-governs a root THE
# OPERATOR DID NOT NAME, which is that same defect through a different door. Measured: `C:\A\..\B` folds
# to `c:/b` under the gate and stays `c:/a/../b` here.
#
# THAT IS TRUE OF THE OMISSION, AND IT WAS NOT TRUE OF THE FUNCTION -- which is a different sentence, and
# the difference cost a measured counterexample. Coarseness can enter at any step, not only at the one
# being argued about, and it entered at the TrimEnd, which is why the TrimEnd below is conditional. Bare,
# it erases the separator that tells a drive ROOT from a drive-RELATIVE path, so `C:\` and `C:` both keyed
# `c:` -- installer-COARSER, the direction the paragraph above rules out. They are not the same place:
# the gate resolves `C:\` to the root of drive C and `C:` to the CURRENT DIRECTORY on drive C (measured
# 2026-08-29: `c:` against `c:/users/<you>/...`). So the separator goes back on when trimming it would
# leave a bare drive spec, and `C:` keeps a key of its own.
#
# THE DOMAIN IS TRIMMED LINES. Every caller trims before it compares -- Merge-GovernedRoots trims each
# existing line and each incoming value, Write-GovernedRoots trims each line it reads back, and the gate
# trims each line before Get-ComparablePath -- so a leading-space spelling is not a pair either
# normalizer is ever asked about, and the corpus below says so rather than leaving it implied.
#
# tests/test_install_gate_allowlist_merge.py pins the direction by EXTRACTING both normalizers and
# asserting installer-same implies gate-same, over a corpus that CARRIES the drive-root pair -- so the
# exception above is a counterexample the corpus contains, not a sentence beside it. Extraction, not
# restatement, because a restated predicate is a third predicate.
function Get-RootKey([string]$Value) {
    $v = $Value.Trim().Replace('\', '/')
    $k = $v.TrimEnd('/')
    if ($k.Length -lt $v.Length -and $k -match '\A[A-Za-z]:\z') { $k = "$k/" }
    $k.ToLowerInvariant()
}

# Fold the roots this run names INTO the list already on the box, and report what changed.
#
# Returns Lines (what to write), Roots (what will be governed), Added, Dropped, Missing, Duplicated.
# Every property is wrapped in @() so a one-element result stays an array through ConvertTo-Json.
#
# EXISTING LINES ARE KEPT VERBATIM -- comments, blanks, spelling, file order. This installer does not
# tidy lines it was not asked to touch, and that rule buys three things at once: a hand-written comment
# beside a root survives, a re-run is byte-identical so a diff shows only real change, and the contract
# stays one sentence. Nothing resolves, validates or stats an existing line either: a root is often
# removed precisely BECAUSE its checkout is gone.
#
# FIRST SPELLING WINS. An existing line is never rewritten to the incoming spelling -- the gate quotes
# the operator's spelling back in its deny messages, so recasing a path changes what a reader sees for
# no reason.
#
# TWO EXISTING LINES NAMING ONE ROOT ARE BOTH KEPT and reported in Duplicated. Collapsing them removes
# no governance, so it is not this defect; keeping them costs the gate one string compare.
#
# DEDUP APPLIES TO Incoming ONLY -- against the existing keys and against itself, so `-Repo a,a` writes
# one line. (PowerShell binds a comma-separated argument to a [string[]] parameter as two elements, so
# `-Repo a,b` really does govern two repos.)
#
# The header is emitted ONLY when Existing is empty. On a merge the existing header survives verbatim.
function Merge-GovernedRoots {
    [CmdletBinding()]
    param(
        [string[]]$Existing = @(),
        [string[]]$Incoming = @(),
        # Removal mode: drop every existing line whose key an Incoming value names, keep everything else.
        [switch]$Remove
    )

    $lines      = [System.Collections.Generic.List[string]]::new()
    $roots      = [System.Collections.Generic.List[string]]::new()
    $added      = [System.Collections.Generic.List[string]]::new()
    $dropped    = [System.Collections.Generic.List[string]]::new()
    $missing    = [System.Collections.Generic.List[string]]::new()
    $duplicated = [System.Collections.Generic.List[string]]::new()

    $incomingKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($i in @($Incoming)) {
        $t = "$i".Trim()
        if ($t) { $null = $incomingKeys.Add((Get-RootKey $t)) }
    }
    $matched = [System.Collections.Generic.HashSet[string]]::new()
    $kept    = [System.Collections.Generic.HashSet[string]]::new()

    if (-not $Remove -and @($Existing).Count -eq 0) {
        $lines.Add("# Primary checkouts governed by the worktree gate (scripts\hooks\worktree_gate.ps1).")
        $lines.Add("# Writes INTO these trees are denied; a linked worktree may not be switched onto an existing branch.")
        $lines.Add("# Deleting this file turns the gate OFF everywhere, immediately.")
        $lines.Add("# install-gate.ps1 MERGES this list: a run ADDS the roots it names and keeps every root already here.")
        $lines.Add("# To stop governing one:  install-gate.ps1 -Uninstall -Repo `"<path>`"")
    }

    # A ROOT is a line that is non-blank after Trim() and does not start with '#'. Comments and blanks
    # are Lines but never Roots -- the same reading the gate itself uses.
    foreach ($line in @($Existing)) {
        $text = "$line"
        $t = $text.Trim()
        if (-not $t -or $t.StartsWith('#')) { $lines.Add($text); continue }
        $key = Get-RootKey $t
        if ($Remove -and $incomingKeys.Contains($key)) {
            $null = $matched.Add($key)
            $dropped.Add($t)
            continue
        }
        $lines.Add($text)
        $roots.Add($t)
        if (-not $kept.Add($key)) { $duplicated.Add($t) }
    }

    if ($Remove) {
        $reported = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($i in @($Incoming)) {
            $t = "$i".Trim()
            if (-not $t) { continue }
            $key = Get-RootKey $t
            if ($matched.Contains($key)) { continue }
            if ($reported.Add($key)) { $missing.Add($t) }
        }
    } else {
        foreach ($i in @($Incoming)) {
            $t = "$i".Trim()
            if (-not $t) { continue }
            if (-not $kept.Add((Get-RootKey $t))) { continue }
            $lines.Add($t)
            $roots.Add($t)
            $added.Add($t)
        }
    }

    [pscustomobject]@{
        Lines      = @($lines)
        Roots      = @($roots)
        Added      = @($added)
        Dropped    = @($dropped)
        Missing    = @($missing)
        Duplicated = @($duplicated)
    }
}

# Announce what the allowlist now says. A pure printer -- it takes the path as a parameter precisely so
# a test can call it without the install path, and every string a merge or a narrowing prints lives here.
function Show-AllowlistResult {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)]$Result,
        [Parameter(Mandatory)][string]$Path,
        [string]$BackupPath,
        # Removal mode: this run took roots AWAY, which is a change of posture and is reported loudly.
        [switch]$Narrowed,
        # The allowlist existed and named NO root, so the gate governed nothing until this run.
        [switch]$WasOff,
        # There was no allowlist at all before this run.
        [switch]$Created
    )

    $addedKeys = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($a in @($Result.Added)) { $null = $addedKeys.Add((Get-RootKey $a)) }

    # COUNT DISTINCT ROOTS, NOT LINES. Two lines naming one root are both kept on purpose (see
    # Merge-GovernedRoots), so a line count over-reports -- "2 root(s)" for one governed tree. This is
    # the one line an operator reads to confirm nothing was lost, so it must not claim more governance
    # than the box has. It could never hide a DROP in either direction; it could only overstate.
    $distinct = {
        param($values)
        $keys = [System.Collections.Generic.HashSet[string]]::new()
        foreach ($v in @($values)) { $null = $keys.Add((Get-RootKey $v)) }
        $keys.Count
    }

    if ($Narrowed) {
        $n = & $distinct $Result.Dropped
        $m = & $distinct $Result.Roots
        Write-Host "Worktree gate: allowlist NARROWED -- $n root(s) REMOVED, $m still governed." -ForegroundColor Yellow
        foreach ($d in @($Result.Dropped)) { Write-Host "  removed   : $d" }
        Write-Host "              This root is UNGOVERNED the instant the file is written: writes into it stop being"
        Write-Host "              denied, and nothing else reports that."
        foreach ($r in @($Result.Roots)) { Write-Host "  governing : $r" }
        Write-Host "  allowlist : $Path"
        if ($BackupPath) { Write-Host "  backup    : $BackupPath  (the allowlist as it was BEFORE this run)" }
        if ($m -eq 0) {
            Write-Host "  WARNING   : the allowlist now names NO root, so the gate governs NOTHING and every session on" -ForegroundColor Yellow
            Write-Host "              this box is ungated. That is the same state as -Uninstall, reached one root at a time." -ForegroundColor Yellow
        }
        Write-Host "  The hook wiring, the installed gate and every other root are untouched."
        return
    }

    # No per-run MERGED/UNCHANGED banner. A line that appears on every run is one readers learn to skip
    # -- this script already makes that argument about its own output, up in the -Status block -- so the
    # count rides on the allowlist line that was going to be printed anyway.
    $counts = "$(& $distinct $Result.Roots) root(s); $(& $distinct $Result.Added) added by this run"
    $suffix = if ($Created) { " -- allowlist CREATED" } else { "" }
    Write-Host "  allowlist : $Path  ($counts)$suffix"
    foreach ($r in @($Result.Roots)) {
        $mark = if ($addedKeys.Contains((Get-RootKey $r))) { "  (ADDED by this run)" } else { "" }
        Write-Host "  governing : $r$mark"
    }
    if (@($Result.Duplicated).Count -gt 0) {
        Write-Host "  note      : $(@($Result.Duplicated).Count) line(s) name a root already listed above. Every line is kept -- this installer does not tidy lines it was not asked to touch."
    }
    if ($WasOff) {
        Write-Host "  WAS OFF   : the allowlist named NO root before this run, so the gate governed NOTHING on this" -ForegroundColor Yellow
        Write-Host "              box. This run turns it on." -ForegroundColor Yellow
    }
}

# THE ONE WRITER of the allowlist. Mirrors Write-Settings above, which already proves the idiom here.
#
# 1. Back up UNCONDITIONALLY, immediately before every write. The thriftier "only when the content
#    changed" rule is what makes a .bak read as a recovery point two changes back; copying every time
#    costs nothing and makes the backup exactly one write old BY CONSTRUCTION.
# 2. Build the whole file in memory, write it to a temp file, then Move-Item over the target. That also
#    closes a corruption path a naive Add-Content would open: a file whose last line lacks a trailing
#    newline would get the next root concatenated onto it.
# 3. Read it back and assert every intended root is there. WHAT THAT CATCHES, EXACTLY: a write that did
#    not land. The file on disk does not carry the roots this run intended, so the run refuses instead of
#    printing them as governed.
#
#    WHAT IT DOES NOT CATCH, and an earlier wording here claimed it did: two installers that both READ
#    before either WRITES. Each merge is right about the content it read, each write lands, and each
#    read-back passes -- and the second write silently drops the root the first one added. Nothing here
#    compares the file against the content the merge was computed from, so that lost update is invisible
#    to this check. It NARROWS the race; it does not close it, and it does not make every lost update
#    loud. tests/test_install_gate_allowlist_merge.py RUNS the surviving case rather than describing it.
#
# WRITE-ONLY, AND THAT IS A SECURITY PROPERTY. Nothing reads the .bak back: not this installer, not the
# gate. Gate rule 1a protects the allowlist and the gate script by EXACT FILENAME and explicitly refuses
# to key on the parent directory, so a sibling worktree-gate.repos.txt.bak is NOT protected and a session
# could write to it. That is harmless only while it is inert; the moment anything reads it, it becomes a
# route around rule 1a. tests/test_install_gate_allowlist_merge.py pins that it stays unread -- by
# following the VALUE through the variables that carry it, not by looking for the string ".bak", which
# one local alias defeats.
#
# THE .bak OUTLIVES THE ALLOWLIST, on purpose. A full -Uninstall backs the file up and then deletes it,
# so the sibling stays behind in a directory the gate no longer protects -- it is the only recovery from
# the largest data loss this script performs. It also means a .bak can be OLDER than the allowlist beside
# it: a later install creates a fresh file and takes no backup, having had nothing to back up. Read it as
# a recovery copy, never as a record of the previous run.
#
# Returns the backup path, or $null when there was no file to back up.
function Write-GovernedRoots {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Path,
        [string[]]$Lines = @()
    )

    $bak = $null
    if (Test-Path -LiteralPath $Path) {
        $bak = "$Path.bak"
        Copy-Item -LiteralPath $Path -Destination $bak -Force
    }

    $tmp = "$Path.tmp-$PID"
    Set-Content -LiteralPath $tmp -Value @($Lines) -Encoding utf8
    Move-Item -LiteralPath $tmp -Destination $Path -Force

    $seen = [System.Collections.Generic.HashSet[string]]::new()
    foreach ($b in @(Get-Content -LiteralPath $Path -ErrorAction Stop)) {
        $t = "$b".Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        $null = $seen.Add((Get-RootKey $t))
    }
    # THE REFUSAL SPEAKS FOR THE WHOLE RUN, so its claim about the rest of the box has to be kept true by
    # the CALL SITES rather than asserted here. It used to say "Nothing else was changed", which was
    # false on the install path: the gate copy ran FIRST, so a refusal left this box carrying a refreshed
    # machine-global gate -- and, on a first install, no hook wiring at all -- while the operator read
    # that nothing had changed. The install path now writes the allowlist BEFORE it copies the gate and
    # before it wires any config dir, and tests/test_install_gate_allowlist_merge.py pins that order.
    foreach ($l in @($Lines)) {
        $t = "$l".Trim()
        if (-not $t -or $t.StartsWith('#')) { continue }
        if (-not $seen.Contains((Get-RootKey $t))) {
            $recover = if ($bak) { "The allowlist as it was immediately before this write is in $bak." }
                       else { "There was no allowlist before this write, so there is no backup." }
            throw "WROTE $Path but reading it back does not show $t. Another install probably ran at the same time, so this run's roots may be missing from the file. Neither the gate script nor the hook wiring has been written yet. $recover Read $Path, then re-run this command."
        }
    }
    return $bak
}

# ------------------------------------------------------------------------------------------ status
# NB this branch runs BEFORE the CLAUDECODE refusal below, deliberately. Auditing is not installing, and
# a session that cannot see whether the gate is current has no way to notice the exact failure that let
# rule 4 sit unshipped for five days while every test reported it present. Installing stays a human act.
if ($Status) {
    $srcGate = Join-Path $RepoRoot "scripts\hooks\worktree_gate.ps1"
    $iVer = Get-GateVersion $GateDst ; $sVer = Get-GateVersion $srcGate
    $iSha = Get-GateHash    $GateDst ; $sSha = Get-GateHash    $srcGate

    # Print the SHA alongside the version. The version is a hand-bumped label and can disagree with
    # reality -- it did: three rules shipped without a bump, so both lines read the same version directly
    # above a STALE verdict. Showing the hash makes agreement VISIBLE instead of asserted.
    #
    # That incident taught "when the version and the hash disagree, believe the hash", and on 2026-08-04
    # this box produced the exact inverse: both lines read v2026.07.29.2, the byte hashes differed, and
    # the VERSION was the one telling the truth -- the digests differed only in line endings. Neither
    # number is authoritative on its own. The hash is now a CONTENT hash (Get-GateHash), which is what
    # makes the pair meaningful: a disagreement between them is now a real disagreement.
    #
    # Lowercased: the digest is returned uppercase, and every other hash a reader sees here (git, the
    # parity test's output) is lowercase. Two spellings of the same digest invite a false "these differ".
    $shortSha = { param($h) if ($h) { " sha $($h.Substring(0, 12).ToLowerInvariant())" } else { "" } }
    Write-Host "installed   : $(if ($iSha) { "$GateDst  v$iVer$(& $shortSha $iSha)" } else { 'NOT installed' })"
    Write-Host "source      : $(if ($sSha) { "$srcGate  v$sVer$(& $shortSha $sSha)" } else { 'NOT FOUND' })"

    # THE THIRD READING, AND THE ONLY ONE NOT TAKEN FROM THIS CHECKOUT (BACKLOG #1878). The two lines
    # above both came from wherever this script was invoked, so a stale install run from a stale tree
    # graded itself IN SYNC. The ref is a fixed yardstick that does not move with the invoking checkout.
    $up = Get-UpstreamGate -RepoRoot $RepoRoot -Ref $UpstreamRef
    if ($up.Available) {
        Write-Host "upstream    : $($up.Ref):scripts/hooks/worktree_gate.ps1 $(& $shortSha $up.Sha)  (as last fetched; this script never fetches)"
        Write-Host "              $(Format-UpstreamPosition $up)"
    } else {
        Write-Host "upstream    : $($up.Ref) UNREADABLE -- $($up.Reason)" -ForegroundColor Yellow
    }

    if ($iSha -and $sSha) {
        if ($iSha -eq $sSha -and $up.Available -and $up.Sha -eq $iSha) {
            Write-Host "parity      : IN SYNC -- identical CONTENT to this checkout AND to $($up.Ref) (line endings are folded out, not compared)." -ForegroundColor Green
        } elseif ($iSha -eq $sSha -and $up.Available) {
            # The false green this row exists to remove. Both lines above agree, and both are behind.
            Write-Host "parity      : *** NOT CURRENT *** the running gate matches THIS CHECKOUT, and this checkout's gate" -ForegroundColor Red
            Write-Host "              differs from $($up.Ref)'s. Agreement between two copies from one stale tree is not currency."
            Write-Host "                installed and this checkout :$(& $shortSha $iSha)"
            Write-Host "                $($up.Ref) :$(& $shortSha $up.Sha)"
            Write-Host "              $(Format-UpstreamPosition $up -ContentDiffers)."
            Write-Host "              Bring a checkout up to $($up.Ref) and run -Status from THERE before installing anything." -ForegroundColor Yellow
            Write-Host "              If this box deliberately runs an older or unmerged gate, this verdict is expected."
        } elseif ($iSha -eq $sSha) {
            # Not green. A match with this checkout says nothing about currency when the ref cannot be read.
            Write-Host "parity      : UNVERIFIED -- the running gate matches this checkout, but $($up.Ref) could not be read," -ForegroundColor Yellow
            Write-Host "              so nothing here shows that this checkout is current. Fetch $($up.Ref) and re-run."
        } elseif ($up.Available -and $up.Sha -eq $iSha) {
            # The false RED of the same defect: graded against this checkout alone, a current gate run
            # from a stale tree read as STALE, under text telling the reader to replace it.
            Write-Host "parity      : CURRENT -- the running gate has the same CONTENT as $($up.Ref)." -ForegroundColor Green
            Write-Host "              THIS CHECKOUT's gate differs from both, so do NOT install from it." -ForegroundColor Yellow
            Write-Host "              $(Format-UpstreamPosition $up -ContentDiffers)."
        } else {
            Write-Host "parity      : *** STALE *** the running gate's CONTENT differs from this checkout's." -ForegroundColor Red
            # The ref answers the question the warning below asks, where it can be read, so it goes
            # first.
            $which = if (-not $up.Available) { "cannot say which copy is current: $($up.Ref) is unreadable" }
                     elseif ($up.Sha -eq $sSha) { "$($up.Ref) matches THIS CHECKOUT, so the INSTALLED gate is the copy that differs (older, or an unmerged gate installed with -AllowStaleSource)" }
                     else { "$($up.Ref) matches NEITHER copy" }
            Write-Host "              upstream : $which." -ForegroundColor Yellow
            Write-Host "              This is a difference in rules or logic -- CRLF vs LF cannot produce it."
            Write-Host "              Until the installed copy is replaced, rules added or removed in source have"
            Write-Host "              no effect, and the tests still pass."
            Write-Host "              WORK OUT WHICH COPY IS OLDER FIRST. Installing from a checkout older than the"
            Write-Host "              installed gate DOWNGRADES it for every session on this box:" -ForegroundColor Yellow
            Write-Host "                git log --oneline -5 -- scripts/hooks/worktree_gate.ps1"
            Write-Host "              Re-run this installer only once THIS checkout is confirmed the newer of the two."
        }
    }

    # ONE reading of "what is a root", borrowed from the merge rather than spelled again here: a line
    # that is non-blank after Trim() and does not start with '#'. This block used to carry a THIRD,
    # disagreeing definition -- it tested StartsWith('#') on the UNTRIMMED line, so an INDENTED comment
    # printed as a governed root. That was unreachable only while the installer regenerated the file on
    # every run; the merge now PRESERVES an operator's indented comment by design, which made a latent
    # disagreement live. -Status is also the only allowlist audit a session is allowed to run, so it is
    # the one reader that must not say a comment is being governed.
    if (Test-Path -LiteralPath $ReposFile) {
        $governed = @((Merge-GovernedRoots -Existing @(Get-Content -LiteralPath $ReposFile)).Roots)
        if ($governed.Count -gt 0) {
            Write-Host "governing   :"
            foreach ($g in $governed) { Write-Host "              $g" }
        } else {
            # An allowlist that exists and names no root is the gate switched OFF, and it printed as a
            # bare "governing   :" with nothing under it -- which reads as a rendering glitch, not as a
            # box with no governance.
            Write-Host "governing   : nothing (the allowlist names no root -> gate is OFF)"
        }
    } else {
        Write-Host "governing   : nothing (no allowlist -> gate is OFF)"
    }

    # Compare the wired matchers against the rules the INSTALLED script actually implements -- an
    # expectation, not a count. A count of "3" is not information unless you know whether 3 is right.
    $handled = Get-HandledTools $GateDst
    foreach ($cd in $ConfigDir) {
        $sp = Join-Path $cd "settings.json"
        $wired = Get-WiredMatchers $sp
        # Rules that are deliberately unwired are reported as such, never as UNWIRED. A status line that
        # cries wolf about a known-and-intended state is one a reader learns to skip, which is how a real
        # UNWIRED would go unnoticed -- the exact failure this whole block exists to surface.
        $optIn   = @("EnterWorktree")
        $absent  = @($handled | Where-Object { -not $wired.Contains($_) })
        $missing = @($absent  | Where-Object { $optIn -notcontains $_ } | Sort-Object)
        $offByChoice = @($absent | Where-Object { $optIn -contains $_ } | Sort-Object)
        $stray   = @($wired   | Where-Object { $handled -notcontains $_ } | Sort-Object)
        Write-Host "wiring      : $sp"
        Write-Host "              matched  : $(@($wired | Sort-Object) -join ', ')"
        if ($offByChoice) {
            Write-Host "              opt-in   : $($offByChoice -join ', ')  <- off by default, add -EnterWorktreeGate to enable"
        }
        if ($missing) {
            Write-Host "              UNWIRED  : $($missing -join ', ')  <- implemented but NEVER FIRES" -ForegroundColor Yellow
        }
        if ($stray) {
            Write-Host "              stray    : $($stray -join ', ')  <- matched but the script ignores it" -ForegroundColor Yellow
        }
    }

    # --- INDEPENDENT AUDIT: break the writer-validates-its-own-writing loop (BACKLOG #1024) ----------
    # Everything above scans $ConfigDir, which is the set this script WRITES. On its own that can only
    # ever confirm the installer's own output: if the discovery predicate is wrong, the writer creates
    # the wiring and the reader reads it back as evidence, and the two agree because they are the same
    # predicate. That is a validator satisfied by construction (ADR 0158), and it is not hypothetical --
    # measured 2026-08-04, ~/.claude-account-2.lock held three gate matchers this installer had put
    # there under the unanchored glob, and the Python reader counted them as correct wiring.
    #
    # So enumerate from a DIFFERENT starting point: every ~/.claude* directory that carries a
    # settings.json, judged by name AFTERWARDS rather than selected by name up front. The names are
    # printed whether or not anything is wrong, because a count that got smaller looks like an
    # improvement and only the names say what stopped being looked at.
    #
    # Reported, never fixed. Anchoring the writer means -Uninstall no longer reaches an orphan either,
    # so the remedy has to be a command a human runs deliberately -- and which dir is a stale artifact
    # versus a config root this box really uses is the owner's call, not this script's.
    $judged = @($ConfigDir | ForEach-Object {
            try { (Resolve-Path -LiteralPath $_ -ErrorAction Stop).Path } catch { $_ }
        })
    $seen = @(Get-ConfigCandidates $HomeDir)
    Write-Host ""
    Write-Host "audit       : $($seen.Count) ~/.claude* dir(s) with a settings.json, enumerated independently"
    Write-Host "              of the wire set above (so this cannot agree with the writer by construction)"
    Write-Host "              found    : $(@($seen | ForEach-Object { $_.Name } | Sort-Object) -join ', ')"

    $orphans = @()
    $notJudged = @($seen | Where-Object { $judged -notcontains $_.FullName })
    foreach ($d in $notJudged) {
        $why = if ($d.Name -ieq ".claude" -or $LauncherName.IsMatch($d.Name)) {
            "outside the -ConfigDir set given on the command line"
        } else {
            "not a launcher name"
        }
        # An unreadable settings.json must not take -Status down over a directory nobody asked about,
        # and must not read as "no wiring here" either. Say which it was.
        #
        # $null MEANS "Read-Settings THREW", and nothing else -- which is true only because
        # Get-WiredMatchers returns its set without unrolling (see the comma there). Remove it and
        # $null also means "valid JSON, zero gate matchers", so this branch defames a readable dir and
        # the "carries no gate wiring" arm below becomes unreachable.
        $wired = $null
        try { $wired = Get-WiredMatchers (Join-Path $d.FullName "settings.json") } catch { $wired = $null }
        if ($null -eq $wired) {
            Write-Host "              UNREADABLE: $($d.Name)  <- settings.json is not valid JSON; its wiring is unknown" -ForegroundColor Yellow
        } elseif ($wired.Count -gt 0) {
            $orphans += $d
            Write-Host "              ORPHAN GATE WIRING in $($d.Name) ($why)" -ForegroundColor Yellow
            Write-Host "                matched: $(@($wired | Sort-Object) -join ', ')"
            Write-Host "                This installer will neither refresh nor remove it. Remove it deliberately:"
            Write-Host "                  install-gate.ps1 -Uninstall -ConfigDir `"$($d.FullName)`""
        } else {
            Write-Host "              not judged: $($d.Name) ($why) -- carries no gate wiring"
        }
    }
    # "I found nothing" and "I found things and they are all fine" are different sentences, and only the
    # second is reassurance. Collapsing them is the failure this whole audit exists to remove, so an
    # empty population says NOTHING WAS EXAMINED rather than borrowing the clean verdict below it.
    if ($seen.Count -eq 0) {
        Write-Host "              NOTHING EXAMINED -- no ~/.claude* dir under $HomeDir carries a settings.json," -ForegroundColor Yellow
        Write-Host "              so this audit concluded nothing. That is not the same as 'no orphans'."
    }
    elseif ($notJudged.Count -eq 0) {
        Write-Host "              every dir found is in the wire set above; nothing is unjudged"
    }
    elseif ($orphans.Count -eq 0) {
        Write-Host "              no unjudged dir carries gate wiring"
    }

    Write-Host ""
    Write-Host "scanned $($ConfigDir.Count) config dir(s) against $(@($handled).Count) implemented rule(s)."
    return
}

if ($env:CLAUDECODE -eq "1") {
    throw "Refusing to run inside Claude Code. A session that can install this gate can also remove it. Run from a plain pwsh terminal. (-Status is allowed from a session: auditing is not installing.)"
}

# --------------------------------------------------------------------------------------- uninstall
if ($Uninstall) {
    # -Uninstall -Repo <path> NARROWS the allowlist: it stops governing the named roots and touches
    # NOTHING else -- not the hook wiring, not the installed gate, not the other roots.
    #
    # This is a DELIBERATE narrowing of an existing combination, not a new parameter. The branch below
    # never read $Repo, and the $Repo default is computed after it returns, so today `-Uninstall -Repo X`
    # performs a FULL uninstall while the operator believes they scoped it -- and bare -Uninstall cannot
    # fall in here, because it has no $Repo at all. Giving the combination the meaning it already looks
    # like turns a silent misreading into the thing on the label. It also matches the -Uninstall
    # -ConfigDir idiom the -Status audit already prints as a remedy.
    if ($Repo -and $Repo.Count -gt 0) {
        # An absent allowlist THROWS here: there is nothing to narrow, and that is not the same as
        # narrowing to nothing.
        $existing = @(Get-Content -LiteralPath $ReposFile -ErrorAction Stop)

        # No Resolve-Path -ErrorAction Stop and no "Not a git checkout" throw: you remove a root
        # BECAUSE the checkout is gone. Resolve only so a relative spelling like `.` works, and fall
        # back to the literal string when it does not resolve.
        $wanted = @(foreach ($r in $Repo) {
                $p = Resolve-Path -LiteralPath $r -ErrorAction SilentlyContinue
                if ($p) { $p.Path } else { $r }
            })

        $result = Merge-GovernedRoots -Existing $existing -Incoming $wanted -Remove

        # ANY unmatched value refuses the WHOLE removal and writes nothing. A partial removal leaves the
        # operator's model of which roots are governed wrong, which is the exact class of defect this
        # change exists to remove; retyping the command costs nothing.
        if ($result.Missing.Count -gt 0) {
            $detail = @(
                @($result.Missing) | ForEach-Object { "  no match  : $_" }
                @($result.Roots)   | ForEach-Object { "  governing : $_" }
            )
            throw (@(
                    "-Uninstall -Repo named $($result.Missing.Count) value(s) the allowlist does not carry, so NOTHING was removed and nothing"
                    "was written. Matching ignores case and slash direction."
                    $detail
                ) -join [Environment]::NewLine)
        }

        $bak = Write-GovernedRoots -Path $ReposFile -Lines $result.Lines
        Show-AllowlistResult -Result $result -Path $ReposFile -BackupPath $bak -Narrowed
        return
    }

    foreach ($cd in $ConfigDir) {
        $sp = Join-Path $cd "settings.json"
        if (-not (Test-Path -LiteralPath $sp)) { continue }
        Write-Settings $sp (Remove-GateHooks (Read-Settings $sp))
    }
    # The largest data loss this script performs, and until now it left nothing behind. Same one-write-old
    # backup every other write here takes.
    if (Test-Path -LiteralPath $ReposFile) { Copy-Item -LiteralPath $ReposFile -Destination "$ReposFile.bak" -Force }
    Remove-Item -LiteralPath $ReposFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GateDst   -Force -ErrorAction SilentlyContinue
    Write-Host "Worktree gate REMOVED from $($ConfigDir.Count) config dir(s). Sessions are no longer gated (takes effect immediately)." -ForegroundColor Yellow
    return
}

# ----------------------------------------------------------------------------------------- install
if (-not $Repo -or $Repo.Count -eq 0) {
    # Default to the MAIN worktree, not to wherever this script happens to be running from. You will
    # usually install from a worktree (that is the whole point of the gate), and governing that worktree
    # instead of the primary would be exactly backwards.
    $main = (& git -C $RepoRoot worktree list --porcelain 2>$null |
                Select-String -Pattern '^worktree (.+)$' |
                Select-Object -First 1).Matches[0].Groups[1].Value
    $Repo = @(if ($main) { $main } else { $RepoRoot })
}

$resolved = foreach ($r in $Repo) {
    $p = (Resolve-Path -LiteralPath $r -ErrorAction Stop).Path
    if (-not (Test-Path -LiteralPath (Join-Path $p ".git"))) { throw "Not a git checkout: $p" }
    $p
}

# REFUSE A STALE SOURCE BEFORE ANYTHING ON THIS BOX CHANGES (BACKLOG #1878). This run copies its gate
# from THIS checkout into a machine-global file every session runs. A checkout behind -UpstreamRef
# would ship an old gate to every config dir, and -Status run from the same checkout would then find
# nothing wrong. So compare against the ref first, and refuse unless the operator says they mean it.
# It sits above the allowlist write so a refusal leaves the box exactly as it was.
$sourceGate = Join-Path $RepoRoot "scripts\hooks\worktree_gate.ps1"
$checkedSha = Get-GateHash $sourceGate
$upstream = Get-UpstreamGate -RepoRoot $RepoRoot -Ref $UpstreamRef
$staleRefusal = Get-StaleSourceRefusal -SourcePath $sourceGate -SourceSha $checkedSha -Upstream $upstream
if ($staleRefusal) {
    # A missing source is not a currency question, so the override does not reach it.
    if (-not $AllowStaleSource -or -not $checkedSha) { throw $staleRefusal }
    Write-Host "WARNING: installing a gate that is not the one on $UpstreamRef, because -AllowStaleSource was given." -ForegroundColor Yellow
    Write-Host "         -Status will not grade this install IN SYNC against $UpstreamRef while the two differ."
    Write-Host "         $(if ($upstream.Available) { Format-UpstreamPosition $upstream -ContentDiffers } else { "$UpstreamRef is unreadable: $($upstream.Reason)" })"
} elseif ($UpstreamRef -ne "origin/main") {
    # A passing check against a ref the operator chose is only as good as that choice, and
    # `-UpstreamRef HEAD` would pass any committed tree. Say which yardstick was used.
    Write-Host "NOTE: the source was checked against -UpstreamRef $UpstreamRef, not the default origin/main." -ForegroundColor Yellow
}

New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null

# READ AND MERGE BEFORE ANYTHING ON THIS BOX CHANGES. An allowlist this run cannot read must stop the
# install while the machine is still exactly as it was -- reading after the gate copy below would leave a
# refreshed gate sitting behind a refusal.
#
# -ErrorAction Stop, never SilentlyContinue: a read that fails quietly turns an unreadable allowlist into
# an EMPTY one, which re-creates the dropped-root defect through the back door. A file that is simply
# absent is the fresh-box case and is not an error.
$allowlistExisted = Test-Path -LiteralPath $ReposFile
$existing = if ($allowlistExisted) { @(Get-Content -LiteralPath $ReposFile -ErrorAction Stop) } else { @() }
$wasOff = $allowlistExisted -and ((Merge-GovernedRoots -Existing $existing).Roots.Count -eq 0)
$result = Merge-GovernedRoots -Existing $existing -Incoming $resolved

# WRITE THE ALLOWLIST BEFORE ANYTHING MACHINE-GLOBAL CHANGES -- the same argument as the read above, one
# step later. Write-GovernedRoots can REFUSE (its read-back), and its refusal tells the operator that
# neither the gate script nor the hook wiring has been written yet. Copying the gate first made that
# sentence false: a refusal left this box carrying a refreshed machine-global gate and, on a first
# install, no matchers at all. Nothing between here and the copy needs the installed gate to exist --
# $command below is a string.
$bak = Write-GovernedRoots -Path $ReposFile -Lines $result.Lines

# BACK UP THE GATE BEFORE OVERWRITING IT. The allowlist writer has done this since #1375; the GATE
# SCRIPT never did, and the near-miss is why: `Write-Settings` backs up settings.json, and reading
# `Copy-Item ... .bak` in this file makes the absence here easy to read as presence. It is not the
# same file.
$GateSrc = Join-Path $RepoRoot "scripts\hooks\worktree_gate.ps1"
$gateBak = $null
if (Test-Path -LiteralPath $GateDst) {
    $gateBak = "$GateDst.bak"
    Copy-Item -LiteralPath $GateDst -Destination $gateBak -Force
}

Copy-Item -LiteralPath $GateSrc -Destination $GateDst -Force

# STAMP THE INSTALLED COPY WITH THE INSTALL TIME, AND THIS IS THE LOAD-BEARING HALF OF #1247.
#
# Copy-Item carries the SOURCE file's LastWriteTime, so the installed gate inherited a timestamp from
# whichever checkout it was copied from -- routinely days old, and older still on a fresh clone.
# Measured 2026-08-29: a source back-dated six days produced an installed copy reporting the same
# six-day-old time, seconds after the copy ran.
#
# AN INHERITED MTIME IS WORSE THAN A MISSING ONE BECAUSE IT READS AS EVIDENCE. A correct stale-gate
# report was retracted on the strength of this timestamp -- "nothing wrote it today" -- and the
# retraction propagated. A file with no mtime would have been questioned; a file with a confident
# wrong one was believed.
#
# The mtime now answers the question people actually ask it: WHEN WAS THIS INSTALLED. It deliberately
# does NOT answer "is this current", which is a content question -- `-Status` compares hashes for that,
# and the two must not be conflated.
$installedAtUtc = [DateTime]::UtcNow
(Get-Item -LiteralPath $GateDst).LastWriteTimeUtc = $installedAtUtc

# A RECEIPT, AND AN HONEST NOTE ABOUT WHAT IT IS WORTH. Nothing recorded that an install happened, so
# there was no way to ask who installed this gate, from which tree, or at which commit.
#
# TRUST LEVEL, STATED BECAUSE THE ALTERNATIVE IS ANOTHER CONFIDENT WRONG ANSWER: gate rule 1a protects
# ~/.claude/hooks/ by EXACT FILENAME and refuses to key on the parent directory, so this sibling is NOT
# protected and a session can write it. Read it as a convenience record, never as attestation. The hash
# it carries is checkable against the file; the rest is a claim by whoever last ran the installer.
$receipt = [ordered]@{
    installedAtUtc = $installedAtUtc.ToString('o')
    sourcePath     = $GateSrc
    sourceRepo     = $RepoRoot
    gateVersion    = (Get-GateVersion $GateDst)
    gateSha256     = (Get-GateHash $GateDst)
    configDirs     = @($ConfigDir)
    # BACKLOG #1878: what the source was checked against, so a later NOT CURRENT can be told apart
    # from a deliberate -AllowStaleSource install.
    upstreamRef        = $UpstreamRef
    upstreamGateSha256 = $upstream.Sha
    allowStaleSource   = [bool]$AllowStaleSource
    note           ='Convenience record written by install-gate.ps1. NOT protected by the gate and NOT attestation.'
} | ConvertTo-Json -Depth 4
Set-Content -LiteralPath "$GateDst.receipt.json" -Value $receipt -Encoding utf8

# The stale-source check hashed the source before the allowlist write; the copy read it again just
# now. If the working file changed in between, what was installed is not what was checked. The gate
# is already in place, and throwing here would leave the wiring half-written, so say it loudly.
if ((Get-GateHash $GateDst) -ne $checkedSha) {
    Write-Host "WARNING: the gate changed on disk between the currency check and the copy, so the installed gate" -ForegroundColor Yellow
    Write-Host "         is NOT the one that was checked against $UpstreamRef. Run -Status, then re-install." -ForegroundColor Yellow
}

$command = "pwsh -NoProfile -File `"$GateDst`""

# One matcher per rule in scripts/hooks/worktree_gate.ps1. A rule the hook implements but that is not
# matched here NEVER FIRES -- the hook is simply not invoked for that tool, and nothing says so. Rule 3
# shipped in exactly that state. tests/test_install_gate_wiring.py now asserts that every tool the script
# branches on appears in this list, so the two cannot drift apart again. (Rule 3b -- worktree hijack --
# rides the same Bash|PowerShell matcher as rule 3, so it needs no new tool here.)
$matchers = @(
    "Write|Edit|MultiEdit|NotebookEdit"   # rule 1 -- writes INTO the primary's tree
    "Bash|PowerShell"                     # rules 3 + 3b -- git verbs that swap the primary / hijack a worktree
)
if (-not $NoDispatchGate) {
    $matchers += "Task|Agent|Workflow"    # rule 2 -- subagent dispatch FROM the primary
}
if ($EnterWorktreeGate) {
    $matchers += "EnterWorktree"          # rule 4 -- OPT-IN, see the parameter's note for why
}

$entries = foreach ($m in $matchers) {
    [ordered]@{
        matcher = $m
        hooks   = @([ordered]@{
            type          = "command"
            command       = $command
            timeout       = 15
            statusMessage = "Checking worktree gate"
        })
    }
}

# Wire (idempotently) into every target config dir. Each file is read-modified-written independently with
# its own backup/validate/rollback, so a failure on one account cannot corrupt another.
foreach ($cd in $ConfigDir) {
    $sp = Join-Path $cd "settings.json"
    $data = Remove-GateHooks (Read-Settings $sp)   # idempotent: drop our old entries, then re-add
    if (-not $data.hooks)            { $data.hooks = [ordered]@{} }
    if (-not $data.hooks.PreToolUse) { $data.hooks.PreToolUse = @() }
    $data.hooks.PreToolUse = @($data.hooks.PreToolUse) + @($entries)
    Write-Settings $sp $data
    Write-Host "  wired : $sp"
}

Write-Host ""
Write-Host "Worktree gate INSTALLED into $($ConfigDir.Count) config dir(s) (every session, no restart)." -ForegroundColor Green
Write-Host "  gate      : $GateDst"
Write-Host "  installed : $($installedAtUtc.ToString('yyyy-MM-dd HH:mm:ss')) UTC  (receipt: $GateDst.receipt.json)"
# Not `$resolved | ForEach-Object`: that prints what THIS run named, which under-reports what the box
# governs the moment the allowlist carries a root this run did not name -- which is the whole point.
Show-AllowlistResult -Result $result -Path $ReposFile -BackupPath $bak -WasOff:$wasOff -Created:(-not $allowlistExisted)
Write-Host "  matchers  : $($matchers -join '  +  ')"
Write-Host ""
Write-Host "Writes into a governed tree are DENIED; a linked worktree may not be switched onto an existing branch."
Write-Host "To turn it off:          pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall"
Write-Host "To stop governing ONE:   pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall -Repo `"<path>`""
Write-Host "                         This installer MERGES the allowlist: a run adds the roots it names and"
Write-Host "                         never drops one it did not name."
