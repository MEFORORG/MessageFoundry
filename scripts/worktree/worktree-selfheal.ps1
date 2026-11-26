# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    SessionStart backstop: heal the shared PRIMARY checkout when Claude Desktop's per-session
    auto-worktree half-fails on Windows and flips the primary's HEAD onto the session's branch,
    leaving an empty "ghost" stub worktree. See AI memory mf-tengu-worktree-halffail and
    anthropics/claude-code#76590.

.DESCRIPTION
    Installed at USER scope as a SessionStart hook by install-selfheal.ps1, which wires the one
    config dir it is given per run -- ~/.claude (the Desktop app) or a .claude-account-N (the
    CLAUDE_CONFIG_DIR VS Code launchers); it has no loop over every config dir
    (docs/SESSION-DRIFT-CONTROLS.md, B10). In each config dir it was run for, it fires at the start of
    every session, INCLUDING a ghost stub
    session whose cwd is an unregistered .claude/worktrees/<name> dir that resolves up to the
    primary -- a case a PROJECT-scoped hook can never see (the stub has no project .claude/).

    For each governed primary (from the shared allowlist), if its HEAD is on another branch than the
    home branch (a detached HEAD is left alone) AND `git status --porcelain` printed nothing for it, it runs `git checkout <home branch>`
    on it itself rather than calling restore-primary.ps1 (step 1 below says why). If THIS session is
    sitting in a stub worktree, it injects a heads-up telling the model to spin up a real worktree
    with new.ps1 before editing.

    FAILS OPEN on every error path (exit 0, no output). A backstop that wedges session startup gets
    ripped out, and then it protects nothing. The critical action (repairing the primary) is a side
    effect that does not depend on the additionalContext output shape being recognized.

    Off switch: the hook no-ops when the allowlist it reads names no root. It reads the gate's
    ~/.claude/hooks/worktree-gate.repos.txt whenever that file exists, even empty, and the legacy
    ~/.claude-hooks/worktree-gate.repos.txt only when it does not. So deleting the gate's file turns
    this hook off only where no legacy file lists a root; where one does, the hook stays armed on it.
    docs/SESSION-DRIFT-CONTROLS.md G8 is the source of record for the two files.
#>
param(
    # Shared allowlist of primary checkouts to guard (one absolute path per line, '#' comments).
    # When passed, absent or empty => the backstop is OFF. When not passed, the file is chosen below,
    # and the Off switch paragraph above says when that leaves the backstop on.
    #
    # ONE allowlist, shared with the PreToolUse gate. There used to be two -- the gate read
    # ~/.claude/hooks/worktree-gate.repos.txt and this backstop read ~/.claude-hooks/worktree-gate.repos.txt
    # -- with one installer rewriting its own unconditionally and the other seeding the second only if
    # absent. Nothing kept them in sync: adding a governed repo through the gate installer never reached
    # the backstop, and `install-gate.ps1 -Uninstall` left this hook armed and still willing to run
    # `git checkout` on the primary long after the gate was gone. They agreed only by luck.
    #
    # The legacy path is still read as a FALLBACK, because this script is installed as a copy: this
    # copy, on a box whose only allowlist is the legacy one, keeps the backstop on. Whichever file exists
    # wins, gate location first. It does NOT cover the reverse skew: once the gate's file exists the
    # legacy one is never read, so a root only the legacy file lists loses the backstop with no message,
    # and an older installed copy reads only the legacy file whatever this one does
    # (docs/SESSION-DRIFT-CONTROLS.md, G8).
    [string]$ReposFile
)

if (-not $ReposFile) {
    # Null-safely: $env:USERPROFILE is Windows-only and is NULL elsewhere, where Join-Path then throws a
    # parameter-binding error rather than returning a path. Honour the env var when set (tests and account
    # swaps override it) and fall back to the .NET accessor, which resolves $HOME on Unix.
    $homeDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
    $shared = Join-Path $homeDir '.claude/hooks/worktree-gate.repos.txt'
    $legacy = Join-Path $homeDir '.claude-hooks/worktree-gate.repos.txt'
    $ReposFile = if (Test-Path -LiteralPath $shared) { $shared } else { $legacy }
}

$ErrorActionPreference = 'SilentlyContinue'

function Emit-Context([string]$Message) {
    # SessionStart context injection. If the shape is not recognized it is simply ignored -- the
    # primary repair above has already happened regardless, so this is best-effort guidance only.
    [Console]::Out.Write((@{
                hookSpecificOutput = @{
                    hookEventName     = 'SessionStart'
                    additionalContext = $Message
                }
            } | ConvertTo-Json -Compress -Depth 6))
}

function Norm([string]$p) { if (-not $p) { return '' } ; ($p -replace '\\', '/').TrimEnd('/').ToLowerInvariant() }

# --- read the SessionStart payload (only for cwd); fail open if unreadable -------------------------
$cwd = ''
try { $j = [Console]::In.ReadToEnd() | ConvertFrom-Json; $cwd = [string]$j.cwd } catch { }

# --- governed primaries (shared allowlist). No file / no entries => nothing to do -----------------
$roots = @(
    Get-Content -LiteralPath $ReposFile -ErrorAction SilentlyContinue |
        Where-Object { $_ -and -not $_.TrimStart().StartsWith('#') } |
        ForEach-Object { $_.Trim() }
)
if ($roots.Count -eq 0) { exit 0 }

$notes = @()
foreach ($root in $roots) {
    if (-not (Test-Path -LiteralPath $root)) { continue }

    # Home branch, in order: git config mefor.homeBranch -> main-current (if it exists) -> main.
    # NB: use $homeBranch, NOT $home -- $HOME is a read-only PowerShell automatic variable
    # (the user profile dir) and PS var names are case-insensitive, so writing $home silently fails.
    $homeBranch = (& git -C $root config --get mefor.homeBranch)
    if (-not $homeBranch) {
        & git -C $root show-ref --verify --quiet refs/heads/main-current
        $homeBranch = if ($LASTEXITCODE -eq 0) { 'main-current' } else { 'main' }
    }
    $homeBranch = "$homeBranch".Trim()

    $head = "$(& git -C $root rev-parse --abbrev-ref HEAD 2>$null)".Trim()
    $dirty = @(& git -C $root status --porcelain 2>$null)

    # 1) Primary drifted off home AND clean -> un-flip it. This mirrors restore-primary.ps1's core
    #    action but scopes git explicitly with -C: that script auto-detects "the primary" from the
    #    ambient cwd, which a hook process does not reliably have. We already verified a clean tree
    #    and a real (non-detached) drift above, so this is the same safe branch switch it would do.
    if ($head -and $head -ne $homeBranch -and $head -ne 'HEAD' -and $dirty.Count -eq 0) {
        & git -C $root checkout $homeBranch 2>$null
        if ($LASTEXITCODE -eq 0) {
            $notes += "Auto-repaired the shared primary ($root): HEAD had drifted to '$head'; restored to '$homeBranch'. This was a half-failed Desktop auto-worktree (anthropics/claude-code#76590)."
        }
    }

    # 2) Is THIS session sitting in a ghost stub under this primary's .claude/worktrees/?
    $rc = Norm $root
    $c = Norm $cwd
    if ($c -and $c.StartsWith("$rc/.claude/worktrees/")) {
        # A real linked worktree has a .git FILE; a half-failed stub does not.
        if (-not (Test-Path -LiteralPath (Join-Path $cwd '.git'))) {
            $notes += "This session's working dir is a GHOST stub ($cwd) left by a half-failed auto-worktree (anthropics/claude-code#76590): it has no .git pointer, is not in ``git worktree list``, and git here resolves to the shared primary, not an isolated worktree. Before ANY edits, create a real worktree and work there by ABSOLUTE path:`n    pwsh -NoProfile -File $root\scripts\worktree\new.ps1 -Name <short-task>`nDo not build in this stub."
        }
    }
}

# 3) Record THIS session's own LINKED worktree's current branch as its home branch. This step once
#    warned when the branch had been SWITCHED (the worktree hijack, which gate rule 3b blocks); since the
#    2026-08-26 ruling below it detects nothing and warns about nothing. It never switches a linked
#    worktree under the session that is using it.
if ($cwd -and (Test-Path -LiteralPath $cwd)) {
    # A linked worktree's private git dir is <repo>/.git/worktrees/<id>/; the main worktree's is <repo>/.git.
    # Only a linked worktree can be hijacked away from an assigned branch, so act only on those.
    $gitDir = "$(& git -C $cwd rev-parse --absolute-git-dir 2>$null)".Trim()
    if ($gitDir -match '[/\\]worktrees[/\\]') {
        # Only if this worktree's repo is a governed primary (its MAIN worktree is in the allowlist).
        $mainWt = ''
        $ml = @(& git -C $cwd worktree list --porcelain 2>$null) |
            Where-Object { $_ -match '^worktree ' } | Select-Object -First 1
        if ($ml) { $mainWt = Norm ($ml -replace '^worktree\s+', '') }
        $governed = $false
        foreach ($r in $roots) { if ((Norm $r) -eq $mainWt) { $governed = $true; break } }
        if ($governed) {
            $homeFile = Join-Path $gitDir 'mefor-home-branch'
            $wtHead = "$(& git -C $cwd rev-parse --abbrev-ref HEAD 2>$null)".Trim()
            # Owner ruling 2026-08-26: RE-TASKING A POOLED WORKTREE IS SANCTIONED, so the record
            # FOLLOWS the current branch instead of reporting a hijack.
            #
            # The prior shape wrote this file only when ABSENT, so it held the first branch a
            # directory ever had and mismatched forever after any normal re-task. Claude Desktop's
            # WorktreePool releases and re-takes these directories on new branches as ordinary
            # lifecycle -- measured, with desktop-log receipts -- so every legitimate re-point read
            # as an attack. All three live worktrees were mismatched when this was ruled.
            #
            # It also PRINTED a remedy: git switch <home>. The hook never mutated anything, which is
            # what its old comment claimed -- but it INSTRUCTED a mutation that would swap a running
            # session onto a stale abandoned branch mid-task. Warn-only is a property of the hook,
            # not of the outcome.
            #
            # HIJACK DETECTION IS DELIBERATELY GIVEN UP HERE. "The branch changed" cannot separate an
            # attack from the pool doing its job, and the false positives had already trained every
            # seat to dismiss the warning -- so it was protecting nothing while carrying a sharp edge.
            # Restoring detection needs a different signal, not a stricter version of this one.
            if ($wtHead -and $wtHead -ne 'HEAD') {
                Set-Content -LiteralPath $homeFile -Value $wtHead -Encoding utf8 -ErrorAction SilentlyContinue
            }
        }
    }
}

if ($notes.Count -gt 0) { Emit-Context ($notes -join "`n`n") }
exit 0
