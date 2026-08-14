# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

    Run from a PLAIN TERMINAL, not from inside Claude Code -- a session that can install its own gate can
    uninstall it. The script refuses when $env:CLAUDECODE is set.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Repo C:\Users\me\Code\Probe   # govern a test repo
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -ConfigDir C:\Users\me\.claude-account-3
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Status
#>
[CmdletBinding()]
param(
    # Primary checkout(s) to govern. Defaults to this repo's root.
    [string[]]$Repo,
    [switch]$Uninstall,
    [switch]$Status,
    # Proceed even when the installed gate's content does not match its own install receipt (BACKLOG
    # #1247). A mismatch means something wrote this machine-global file outside this installer, so the
    # default is to STOP and ask rather than overwrite the evidence. Required only for that one case:
    # a gate with no receipt at all is the normal pre-#1247 state and installs without this.
    [switch]$OverwriteUnverifiedGate,
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
    [string[]]$ConfigDir
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

# Install-receipt helpers (BACKLOG #1247). A separate file because it must be dot-sourceable by a
# test; this script cannot be, since loading it performs a machine-global install.
. (Join-Path $PSScriptRoot "_gate_receipt.ps1")
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
    $bytes = [System.IO.File]::ReadAllBytes($Path)
    $out = [System.Collections.Generic.List[byte]]::new($bytes.Length)
    for ($i = 0; $i -lt $bytes.Length; $i++) {
        if ($bytes[$i] -eq 13 -and ($i + 1) -lt $bytes.Length -and $bytes[$i + 1] -eq 10) { continue }
        $out.Add($bytes[$i])
    }
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try {
        (($sha.ComputeHash($out.ToArray()) | ForEach-Object { $_.ToString('x2') }) -join '').ToUpperInvariant()
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
    if ($iSha -and $sSha) {
        if ($iSha -eq $sSha) {
            Write-Host "parity      : IN SYNC -- identical CONTENT (line endings are folded out, not compared)." -ForegroundColor Green
        } else {
            Write-Host "parity      : *** STALE *** the running gate's CONTENT differs from this checkout's." -ForegroundColor Red
            Write-Host "              This is a difference in rules or logic -- CRLF vs LF cannot produce it."
            Write-Host "              Until the installed copy is replaced, rules added or removed in source have"
            Write-Host "              no effect, and the tests still pass."
            Write-Host "              WORK OUT WHICH COPY IS OLDER FIRST. Installing from a checkout older than the"
            Write-Host "              installed gate DOWNGRADES it for every session on this box:" -ForegroundColor Yellow
            Write-Host "                git log --oneline -5 -- scripts/hooks/worktree_gate.ps1"
            Write-Host "              Re-run this installer only once THIS checkout is confirmed the newer of the two."
        }
    }

    if (Test-Path -LiteralPath $ReposFile) {
        Write-Host "governing   :"
        Get-Content -LiteralPath $ReposFile | Where-Object { $_ -and -not $_.StartsWith('#') } |
            ForEach-Object { Write-Host "              $_" }
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
    foreach ($cd in $ConfigDir) {
        $sp = Join-Path $cd "settings.json"
        if (-not (Test-Path -LiteralPath $sp)) { continue }
        Write-Settings $sp (Remove-GateHooks (Read-Settings $sp))
    }
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

New-Item -ItemType Directory -Force -Path $HooksDir | Out-Null

# BACKLOG #1247 -- this write used to be a bare Copy-Item over a MACHINE-GLOBAL safety control, with
# no backup, no receipt and no log line. When the installed gate's content changed on this box while
# three sessions ran against it, nothing could say who wrote it. The four steps below exist so that
# question is answerable next time, and so an unexpected change STOPS the install instead of being
# silently overwritten -- an overwrite destroys the only evidence that anything happened.
$srcGateFile = Join-Path $RepoRoot "scripts\hooks\worktree_gate.ps1"
$provenance  = Get-GateProvenance $GateDst ${function:Get-GateHash}
$replacedSha = if (Test-Path -LiteralPath $GateDst) { Get-GateHash $GateDst } else { $null }

if ($provenance -eq "MODIFIED" -and -not $OverwriteUnverifiedGate) {
    $r = Read-GateReceipt $GateDst
    throw @"
REFUSING TO OVERWRITE: the installed gate does not match its own install receipt.

  gate            : $GateDst
  installed now   : $replacedSha
  receipt records : $($r.installed_content_sha256)
  receipt written : $($r.written_at_utc) by $($r.installed_by_repo)

Something wrote this file outside this installer. Overwriting would destroy the only evidence of
what it was. Inspect it first; then re-run with -OverwriteUnverifiedGate to proceed deliberately.

DO NOT trust the file's timestamp to decide -- Copy-Item carries the SOURCE's LastWriteTime, so the
installed gate's mtime reflects whichever checkout installed it and not when it was written here.
"@
}
if ($provenance -eq "UNRECORDED") {
    Write-Warning "installed gate has no install receipt (installed before BACKLOG #1247, or written by something else). Recording its hash as replaced: $replacedSha"
}

$backup = Backup-GateBeforeWrite $GateDst
Copy-Item -LiteralPath $srcGateFile -Destination $GateDst -Force
$receiptPath = Write-GateReceipt -GatePath $GateDst -SourcePath $srcGateFile -RepoRoot $RepoRoot `
    -HashFn ${function:Get-GateHash} -ReplacedSha $replacedSha -ReplacedProvenance $provenance -BackupPath $backup

@(
    "# Primary checkouts governed by the worktree gate (scripts\hooks\worktree_gate.ps1)."
    "# Writes INTO these trees are denied; a linked worktree may not be switched onto an existing branch."
    "# Deleting this file turns the gate OFF everywhere, immediately."
    $resolved
) | Set-Content -LiteralPath $ReposFile -Encoding utf8

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
Write-Host "  allowlist : $ReposFile"
$resolved | ForEach-Object { Write-Host "  governing : $_" }
Write-Host "  matchers  : $($matchers -join '  +  ')"
Write-Host ""
Write-Host "Writes into a governed tree are DENIED; a linked worktree may not be switched onto an existing branch."
Write-Host "To turn it off:  pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall"
