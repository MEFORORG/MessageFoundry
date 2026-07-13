# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Wire the worktree-selfheal SessionStart backstop into ONE Claude Code config dir's settings.json.

.DESCRIPTION
    Idempotent. MERGES (never clobbers) a SessionStart hook that runs the shared worktree-selfheal.ps1;
    existing hooks and top-level keys are preserved. Backs up settings.json, validates the written JSON,
    and rolls back on any failure.

    Run once per config dir a session can use. On this box (a subscription-swap setup) that is:
      ~/.claude                (the Desktop app; CLAUDE_CONFIG_DIR unset)
      ~/.claude-account-1/2/3  (the VS Code launchers, which set CLAUDE_CONFIG_DIR)
    The hook SCRIPT lives once at a shared, account-agnostic path (~/.claude-hooks) referenced by all of
    them, so only the wiring is per-dir. See worktree-selfheal.ps1 and AI memory mf-tengu-worktree-halffail.

.EXAMPLE
    pwsh -File scripts\worktree\install-selfheal.ps1 -ConfigDir C:\Users\Scott\.claude
#>
param(
    [Parameter(Mandatory)][string]$ConfigDir,
    [string]$HookPath = (Join-Path $env:USERPROFILE '.claude-hooks\worktree-selfheal.ps1')
)
$ErrorActionPreference = 'Stop'
if (-not (Test-Path -LiteralPath $ConfigDir)) { throw "Config dir not found: $ConfigDir" }
$settingsPath = Join-Path $ConfigDir 'settings.json'

# --- Ensure the shared, account-agnostic hook script + allowlist exist (idempotent) ---------------
# One script copy, referenced by every config dir's wiring, so an account swap can't drop it.
$sharedDir = Split-Path -Parent $HookPath
New-Item -ItemType Directory -Force -Path $sharedDir | Out-Null
$canonical = Join-Path $PSScriptRoot 'worktree-selfheal.ps1'
if (Test-Path -LiteralPath $canonical) { Copy-Item -LiteralPath $canonical -Destination $HookPath -Force }
elseif (-not (Test-Path -LiteralPath $HookPath)) { throw "worktree-selfheal.ps1 not found beside this installer or at $HookPath." }
$reposFile = Join-Path $sharedDir 'worktree-gate.repos.txt'
if (-not (Test-Path -LiteralPath $reposFile)) {
    # Seed from the worktree gate's existing allowlist if present; else a commented template.
    $gateRepos = Join-Path $env:USERPROFILE '.claude\hooks\worktree-gate.repos.txt'
    if (Test-Path -LiteralPath $gateRepos) { Copy-Item -LiteralPath $gateRepos -Destination $reposFile -Force }
    else { Set-Content -LiteralPath $reposFile -Encoding utf8 -Value '# Primaries guarded by the SessionStart backstop. One absolute path per line. Delete to disable.' }
}

$raw = if (Test-Path -LiteralPath $settingsPath) { Get-Content -LiteralPath $settingsPath -Raw } else { '{}' }
$cfg = $raw | ConvertFrom-Json
if ($null -eq $cfg) { $cfg = [pscustomobject]@{} }

# Ensure .hooks exists.
if (-not ($cfg.PSObject.Properties.Name -contains 'hooks') -or $null -eq $cfg.hooks) {
    $cfg | Add-Member -NotePropertyName 'hooks' -NotePropertyValue ([pscustomobject]@{}) -Force
}

# Existing SessionStart groups (preserve them).
$groups = @()
if (($cfg.hooks.PSObject.Properties.Name -contains 'SessionStart') -and $cfg.hooks.SessionStart) {
    $groups = @($cfg.hooks.SessionStart)
}

# Idempotency: bail if any SessionStart hook already runs our script.
foreach ($g in $groups) {
    foreach ($h in @($g.hooks)) {
        if ("$($h.command)" -match 'worktree-selfheal') {
            Write-Host "[$ConfigDir] already wired -- no change."
            return
        }
    }
}

# Append our group.
$entry = [pscustomobject]@{
    hooks = @([pscustomobject]@{
            type          = 'command'
            command       = "pwsh -NoProfile -File `"$HookPath`""
            timeout       = 30
            statusMessage = 'Worktree self-heal'
        })
}
$groups = @($groups) + $entry
$cfg.hooks | Add-Member -NotePropertyName 'SessionStart' -NotePropertyValue $groups -Force

# Backup -> write -> validate -> roll back on failure.
if (Test-Path -LiteralPath $settingsPath) {
    Copy-Item -LiteralPath $settingsPath -Destination "$settingsPath.bak-selfheal" -Force
}
$json = $cfg | ConvertTo-Json -Depth 40
Set-Content -LiteralPath $settingsPath -Value $json -Encoding utf8
try {
    $null = Get-Content -LiteralPath $settingsPath -Raw | ConvertFrom-Json
    Write-Host "[$ConfigDir] wired + valid JSON."
} catch {
    if (Test-Path -LiteralPath "$settingsPath.bak-selfheal") {
        Copy-Item -LiteralPath "$settingsPath.bak-selfheal" -Destination $settingsPath -Force
    }
    throw "[$ConfigDir] produced invalid JSON; rolled back. $_"
}
