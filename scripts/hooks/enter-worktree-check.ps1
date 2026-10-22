# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    PreToolUse hook for EnterWorktree: show scripts/worktree/enter-check.ps1's SAFE or UNSAFE
    verdict in the owner's permission prompt (ADR 0212).

.DESCRIPTION
    The harness asks "Allow Claude to use EnterWorktree?" when a session enters a worktree outside
    `.claude/worktrees/`, unless the session runs under bypassPermissions. This hook runs the check
    and puts its verdict in that prompt, so the owner sees it before answering. Where the harness
    would not prompt, it says nothing, so it never adds a prompt.

    IT NEVER ALLOWS AND NEVER DENIES. Its one decision is `ask`, whose reason the harness shows the
    user in the permission prompt. This script and the check run from `${CLAUDE_PROJECT_DIR}`, a
    tree sessions can edit (the session's own, or, for a desktop-app worktree session, the shared
    primary checkout), so a session could change what they print; an `allow` from them would be a
    session approving itself. ADR 0212 records why an allow is deferred until it comes from an
    installed copy outside every session-writable tree.

    On SAFE: `ask`, with a reason that starts `enter-check: SAFE`. On UNSAFE: `ask`, with a reason
    that starts `enter-check: UNSAFE` and gives the first reasons, folded onto one line and
    bounded. On anything else it returns NO decision, and the prompt, if any, shows unannotated:
    this machine's OFF file, a missing or failing check, a verdict it does not recognise, a path
    under `.claude/worktrees/`, a `permission_mode` of bypassPermissions or none, or an input
    naming no `path` (EnterWorktree with `name` creates a new worktree, which this hook does not
    judge).

    TO SILENCE IT: per machine with the OFF file, or permanently, as scripts/worktree/enter-check.ps1's
    header says (ADR 0212 records the same two).

    -FleetRepos, -FleetRemotes and -TempRoot are passed through to enter-check.ps1 for tests. The
    settings entry passes none, so the defaults apply.
#>
param(
    [string[]]$FleetRepos,
    [string[]]$FleetRemotes,
    [string]$TempRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Ask([string]$Reason) {
    # The only decision this hook writes, fixed here rather than passed in.
    $out = @{ hookSpecificOutput = @{ hookEventName = 'PreToolUse'; permissionDecision = 'ask'; permissionDecisionReason = $Reason } }
    [Console]::Out.Write(($out | ConvertTo-Json -Compress -Depth 4))
}

function Get-PromptText([string]$Text, [int]$Max) {
    # Shown in the owner's prompt: one line, no control or format character (a bidi override can
    # reorder what the owner reads), and bounded.
    $t = (($Text -replace '\p{C}', ' ') -replace '\s+', ' ').Trim()
    if ($t.Length -gt $Max) { $t = $t.Substring(0, $Max - 3) + '...' }
    return $t
}

try {
    . (Join-Path $PSScriptRoot '_hookinput.ps1')
    $text = Read-CcxHookInput
    if ([string]::IsNullOrWhiteSpace($text)) { exit 0 }
    $hook = $text | ConvertFrom-Json -ErrorAction Stop
    if ($hook -isnot [pscustomobject]) { exit 0 }
    $props = $hook.PSObject.Properties
    # The verdict is for this one tool, whatever matcher a settings file wires the hook under.
    if (-not $props['tool_name'] -or [string]$props['tool_name'].Value -cne 'EnterWorktree') { exit 0 }
    $toolInput = if ($props['tool_input']) { $props['tool_input'].Value } else { $null }
    if ($toolInput -isnot [pscustomobject] -or -not $toolInput.PSObject.Properties['path']) { exit 0 }
    # Only `path` is judged, so an input carrying anything else gets no verdict.
    if (@($toolInput.PSObject.Properties | Where-Object { $_.Name -cne 'path' }).Count) { exit 0 }
    $path = [string]$toolInput.PSObject.Properties['path'].Value
    $sid = if ($props['session_id']) { [string]$props['session_id'].Value } else { '' }
    $cwd = Get-CcxHookPayloadCwd -Payload $hook
    if ([string]::IsNullOrWhiteSpace($path) -or -not $cwd.Cwd) { exit 0 }

    # Annotate only a prompt the harness shows anyway; an `ask` anywhere else ADDS a prompt, and
    # in a run nobody answers, a prompt is a refusal. docs/SESSION-DRIFT-CONTROLS.md records the
    # harness's rule: it asks for a path outside `.claude/worktrees/`, by design not inside it, and
    # never under bypassPermissions. A mode the input does not name is not assumed to prompt.
    $mode = if ($props['permission_mode']) { [string]$props['permission_mode'].Value } else { '' }
    if (-not $mode -or $mode -ceq 'bypassPermissions') { exit 0 }
    $segs = @($path.Split([char[]]@('\', '/'), [System.StringSplitOptions]::RemoveEmptyEntries))
    for ($i = 0; $i + 1 -lt $segs.Count; $i++) {
        if ($segs[$i] -ieq '.claude' -and $segs[$i + 1] -ieq 'worktrees') { exit 0 }
    }

    $transcript = if ($props['transcript_path']) { [string]$props['transcript_path'].Value } else { '' }
    $check = @{ Path = $path; SessionId = $sid; SessionCwd = $cwd.Cwd; TranscriptPath = $transcript }
    if ($FleetRepos) { $check['FleetRepos'] = $FleetRepos }
    if ($FleetRemotes) { $check['FleetRemotes'] = $FleetRemotes }
    if ($TempRoot) { $check['TempRoot'] = $TempRoot }
    $lines = @(& (Join-Path (Split-Path -Parent $PSScriptRoot) 'worktree/enter-check.ps1') @check 2>$null)
    $code = $LASTEXITCODE
    $verdict = if ($lines.Count) { [string]$lines[0] } else { '' }

    if ($code -eq 0 -and $verdict -ceq 'SAFE') {
        Write-Ask ('enter-check: SAFE -- a linked fleet worktree in this session''s own scratchpad, at an ' +
            'unmodified commit of the remote''s main, entered from outside any primary checkout. Advisory: ' +
            'the check runs from the session''s own tree (ADR 0212)')
        exit 0
    }
    if ($code -eq 1 -and $verdict -ceq 'UNSAFE') {
        # At most three reasons of at most 300 characters each: the check's reasons lead with
        # absolute paths, and a tighter cap cut off the part that says why.
        $why = @($lines | Select-Object -Skip 1 -First 3 | ForEach-Object { Get-PromptText ([string]$_) 300 } | Where-Object { $_ }) -join '; '
        if (-not $why) { $why = 'no reason printed' }
        Write-Ask "enter-check: UNSAFE -- $why (ADR 0212)"
        exit 0
    }
    # OFF (exit 2), or output that is not a verdict: no decision, so the prompt shows unannotated.
    exit 0
}
catch {
    # No decision on any fault: the owner's prompt shows. Said on stderr, never as a decision.
    [Console]::Error.WriteLine("enter-worktree-check: no decision ($($_.Exception.Message))")
    exit 0
}
