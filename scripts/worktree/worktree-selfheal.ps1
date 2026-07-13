# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
#Requires -Version 7
<#
.SYNOPSIS
    SessionStart backstop: heal the shared PRIMARY checkout when Claude Desktop's per-session
    auto-worktree half-fails on Windows and flips the primary's HEAD onto the session's branch,
    leaving an empty "ghost" stub worktree. See AI memory mf-tengu-worktree-halffail and
    anthropics/claude-code#76590.

.DESCRIPTION
    Installed at USER scope as a SessionStart hook into EVERY Claude config dir a session can use
    on this box -- ~/.claude (the Desktop app) and each .claude-account-N (the CLAUDE_CONFIG_DIR
    VS Code launchers). It therefore fires at the start of every session, INCLUDING a ghost stub
    session whose cwd is an unregistered .claude/worktrees/<name> dir that resolves up to the
    primary -- a case a PROJECT-scoped hook can never see (the stub has no project .claude/).

    For each governed primary (from the shared allowlist), if its HEAD has drifted off the home
    branch AND its tree is clean, it invokes the repo's own restore-primary.ps1 to un-flip it
    (that script refuses a dirty tree, so uncommitted work is never lost). If THIS session is
    sitting in a stub worktree, it injects a heads-up telling the model to spin up a real worktree
    with new.ps1 before editing.

    FAILS OPEN on every error path (exit 0, no output). A backstop that wedges session startup gets
    ripped out, and then it protects nothing. The critical action (repairing the primary) is a side
    effect that does not depend on the additionalContext output shape being recognized.

    Kill switch: delete the shared allowlist (worktree-gate.repos.txt) -> the hook no-ops everywhere.
#>
param(
    # Shared allowlist of primary checkouts to guard (one absolute path per line, '#' comments).
    # Absent or empty => the backstop is OFF. Kept OUTSIDE any per-account config dir so it is
    # account-agnostic and survives an account swap.
    [string]$ReposFile = (Join-Path $env:USERPROFILE '.claude-hooks\worktree-gate.repos.txt')
)

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

if ($notes.Count -gt 0) { Emit-Context ($notes -join "`n`n") }
exit 0
