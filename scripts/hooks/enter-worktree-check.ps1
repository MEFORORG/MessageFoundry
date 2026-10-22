# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    PreToolUse hook for EnterWorktree: auto-allow entering a worktree only when
    scripts/worktree/enter-check.ps1 says SAFE (ADR 0212).

.DESCRIPTION
    The owner was shown "Allow Claude to use EnterWorktree?" each time a session entered a
    throwaway worktree it had made under its own scratchpad. This hook answers that prompt for the
    one case enter-check.ps1 proves safe, and changes nothing else.

    IT NEVER DENIES. On SAFE it returns permissionDecision `allow`. On UNSAFE, on any error, or
    when the input names no `path` (EnterWorktree with `name` creates a new worktree, which this
    hook does not judge), it returns NO decision, so the normal prompt shows. On UNSAFE it adds
    `additionalContext` saying why the call was not auto-allowed.

    A deny from another hook wins over this allow: the opt-in `-EnterWorktreeGate` matcher of
    scripts/hooks/worktree_gate.ps1, when installed, denies under its rule 4, and that is intended.
    This hook does not change the workspace-trust prompt either.

    TO DISABLE IT: fleet-wide, per machine, or permanently, as scripts/worktree/enter-check.ps1's
    header says (ADR 0212 records the same three).

    -FleetRepos, -FleetRemotes and -TempRoot are passed through to enter-check.ps1 for tests. The settings entry
    passes neither, so the defaults apply; whoever can edit that entry's arguments can already
    edit the permission rules beside it.
#>
param(
    [string[]]$FleetRepos,
    [string[]]$FleetRemotes,
    [string]$TempRoot
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-HookOutput([hashtable]$Specific) {
    $Specific['hookEventName'] = 'PreToolUse'
    [Console]::Out.Write((@{ hookSpecificOutput = $Specific } | ConvertTo-Json -Compress -Depth 4))
}

try {
    . (Join-Path $PSScriptRoot '_hookinput.ps1')
    $text = Read-CcxHookInput
    if ([string]::IsNullOrWhiteSpace($text)) { exit 0 }
    $hook = $text | ConvertFrom-Json -ErrorAction Stop
    if ($hook -isnot [pscustomobject]) { exit 0 }
    $props = $hook.PSObject.Properties
    # The allow is for this one tool, whatever matcher a settings file wires the hook under.
    if (-not $props['tool_name'] -or [string]$props['tool_name'].Value -cne 'EnterWorktree') { exit 0 }
    $toolInput = if ($props['tool_input']) { $props['tool_input'].Value } else { $null }
    if ($toolInput -isnot [pscustomobject] -or -not $toolInput.PSObject.Properties['path']) { exit 0 }
    $path = [string]$toolInput.PSObject.Properties['path'].Value
    $sid = if ($props['session_id']) { [string]$props['session_id'].Value } else { '' }
    $cwd = Get-CcxHookPayloadCwd -Payload $hook
    if ([string]::IsNullOrWhiteSpace($path) -or -not $cwd.Cwd) { exit 0 }

    $transcript = if ($props['transcript_path']) { [string]$props['transcript_path'].Value } else { '' }
    $check = @{ Path = $path; SessionId = $sid; SessionCwd = $cwd.Cwd; TranscriptPath = $transcript }
    if ($FleetRepos) { $check['FleetRepos'] = $FleetRepos }
    if ($FleetRemotes) { $check['FleetRemotes'] = $FleetRemotes }
    if ($TempRoot) { $check['TempRoot'] = $TempRoot }
    $lines = @(& (Join-Path (Split-Path -Parent $PSScriptRoot) 'worktree/enter-check.ps1') @check 2>$null)
    $code = $LASTEXITCODE
    $verdict = if ($lines.Count) { [string]$lines[0] } else { '' }

    if ($code -eq 0 -and $verdict -ceq 'SAFE') {
        Write-HookOutput @{
            permissionDecision       = 'allow'
            permissionDecisionReason = 'enter-check.ps1: SAFE -- a linked worktree in this session''s own scratchpad, with origin/main''s .claude/, and the kill switch OFF (ADR 0212)'
        }
        exit 0
    }
    $why = (@($lines | Select-Object -Skip 1) | ForEach-Object { ([string]$_).Trim() }) -join ' '
    Write-HookOutput @{
        additionalContext = "enter-worktree-check (ADR 0212) did not auto-allow this EnterWorktree call, so the owner is asked as usual. enter-check.ps1 printed: $verdict $why"
    }
    exit 0
}
catch {
    # No decision on any fault: the owner's prompt shows. Said on stderr, never as a decision.
    [Console]::Error.WriteLine("enter-worktree-check: no decision ($($_.Exception.Message))")
    exit 0
}
