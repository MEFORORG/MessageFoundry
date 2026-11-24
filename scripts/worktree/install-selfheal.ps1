# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Wire the worktree-selfheal SessionStart backstop into ONE Claude Code config dir's settings.json.

.DESCRIPTION
    Idempotent. MERGES (never clobbers) a SessionStart hook that runs the shared worktree-selfheal.ps1;
    existing hooks and top-level keys are preserved. Validates the new JSON before writing, backs up
    settings.json, and replaces it in one move from a temp file beside it, so it is never written in place.
    It does not create the allowlist; install-gate.ps1 owns that.

    Run once per config dir a session can use. On this box (a subscription-swap setup) that is:
      ~/.claude                (the Desktop app; CLAUDE_CONFIG_DIR unset)
      ~/.claude-account-1/2/3  (the VS Code launchers, which set CLAUDE_CONFIG_DIR)
    The hook SCRIPT lives once at a shared, account-agnostic path (~/.claude-hooks) referenced by all of
    them, so only the wiring is per-dir. See worktree-selfheal.ps1 and AI memory mf-tengu-worktree-halffail.

.EXAMPLE
    pwsh -File scripts\worktree\install-selfheal.ps1 -ConfigDir C:\Users\<you>\.claude
#>
param(
    [Parameter(Mandatory)][string]$ConfigDir,
    # NO DEFAULT HERE, deliberately. Parameter defaults are evaluated during BINDING, before the first
    # line of the body -- so a default that throws preempts the CLAUDECODE guard below and the script
    # dies with an unrelated error instead of refusing. That is exactly what happened: the default was
    # `Join-Path $env:USERPROFILE ...`, and off Windows $env:USERPROFILE is NULL, so on Linux CI the
    # installer crashed with "Cannot bind argument to parameter 'Path' because it is null" and the
    # refusal never ran. A guard is only a guard if nothing can run ahead of it.
    [string]$HookPath
)
$ErrorActionPreference = 'Stop'

# Its sibling install-gate.ps1 has refused to run inside Claude Code since it shipped; this installer
# never did, and it is the MORE privileged of the two. It wires a user-scope SessionStart hook that runs
# `git checkout` on the shared primary unattended, and its canonical source is $PSScriptRoot -- the copy
# in the calling session's own worktree, which that session may freely edit. The higher-privilege
# component was the less protected one.
if ($env:CLAUDECODE -eq '1') {
    throw "Refusing to run inside Claude Code. This installs a user-scope hook that repairs the shared primary unattended, from a script the calling session can edit. Run it from a plain pwsh terminal."
}

# Home directory, null-safely. $env:USERPROFILE is Windows-only and is NULL elsewhere; honour it when set
# (tests and account swaps rely on overriding it) and fall back to the .NET accessor, which resolves $HOME
# on Unix. Every script in this family uses the same idiom -- see worktree-selfheal.ps1 and install-gate.ps1.
$homeDir = if ($env:USERPROFILE) { $env:USERPROFILE } else { [Environment]::GetFolderPath('UserProfile') }
if (-not $HookPath) { $HookPath = Join-Path $homeDir '.claude-hooks/worktree-selfheal.ps1' }

# The path goes into a double-quoted shell command below. A `$` or backtick there would be expanded by
# whichever shell runs the hook, and a double quote would end the argument, so the wired command would
# name a different file. Refuse rather than escape on a guess about which shell that is.
if ($HookPath -match '[$`"]') {
    throw "Refusing a HookPath containing a dollar sign, backtick or double quote: $HookPath"
}

if (-not (Test-Path -LiteralPath $ConfigDir)) { throw "Config dir not found: $ConfigDir" }
$settingsPath = Join-Path $ConfigDir 'settings.json'

# --- Ensure the shared, account-agnostic hook script exists (idempotent) --------------------------
# One script copy, referenced by every config dir's wiring, so an account swap can't drop it.
$sharedDir = Split-Path -Parent $HookPath
New-Item -ItemType Directory -Force -Path $sharedDir | Out-Null
$canonical = Join-Path $PSScriptRoot 'worktree-selfheal.ps1'
if (Test-Path -LiteralPath $canonical) { Copy-Item -LiteralPath $canonical -Destination $HookPath -Force }
elseif (-not (Test-Path -LiteralPath $HookPath)) { throw "worktree-selfheal.ps1 not found beside this installer or at $HookPath." }

# The allowlist is NOT created here. The backstop reads the gate's ~/.claude/hooks/worktree-gate.repos.txt
# first and ~/.claude-hooks/worktree-gate.repos.txt only as a legacy fallback (worktree-selfheal.ps1). A
# copy seeded into the legacy place would outlive `install-gate.ps1 -Uninstall` and keep the backstop
# running `git checkout` on the primary after the gate's allowlist was gone. install-gate.ps1 owns the one
# allowlist. An existing legacy file is left as it is.
$gateRepos = Join-Path $homeDir '.claude/hooks/worktree-gate.repos.txt'
$legacyRepos = Join-Path $sharedDir 'worktree-gate.repos.txt'
if (-not (Test-Path -LiteralPath $gateRepos)) {
    if (Test-Path -LiteralPath $legacyRepos) {
        Write-Host "[$ConfigDir] note: $gateRepos is absent, so the backstop reads the legacy $legacyRepos. install-gate.ps1 writes the gate's allowlist; delete the legacy file to stop that fallback."
    } else {
        Write-Host "[$ConfigDir] note: $gateRepos is absent, so the backstop guards nothing until install-gate.ps1 writes it."
    }
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
        # An exec-form hook names the script in args rather than command; it is the same wiring.
        if ("$($h.command) $(@($h.args) -join ' ')" -match 'worktree-selfheal') {
            Write-Host "[$ConfigDir] already wired -- no change."
            return
        }
    }
}

# Append our group.
$entry = [pscustomobject]@{
    hooks = @([pscustomobject]@{
            type          = 'command'
            command       = "pwsh -NoProfile -NonInteractive -File `"$HookPath`""
            timeout       = 30
            statusMessage = 'Worktree self-heal'
        })
}
$groups = @($groups) + $entry
$cfg.hooks | Add-Member -NotePropertyName 'SessionStart' -NotePropertyValue $groups -Force

# Validate -> backup -> write a temp file beside the live one -> one replace. Other sessions read
# settings.json at any moment, so it is never written in place: a reader sees the old file or the new
# one, never a truncated one. Invalid JSON leaves the live file untouched and exits non-zero.
$json = $cfg | ConvertTo-Json -Depth 40
try {
    $null = $json | ConvertFrom-Json
} catch {
    throw "[$ConfigDir] produced invalid JSON; settings.json left untouched. $_"
}
if (Test-Path -LiteralPath $settingsPath) {
    Copy-Item -LiteralPath $settingsPath -Destination "$settingsPath.bak-selfheal" -Force
}
# .NET resolves relative paths against the process directory, not the PowerShell location, so both
# paths are made absolute first. File.Move with overwrite is one rename that replaces the target;
# Move-Item -Force is not, on Windows it can delete the target first and leave a window with no file.
$liveAbs = (Resolve-Path -LiteralPath $ConfigDir).ProviderPath
$tmp = Join-Path $liveAbs ("settings.json.tmp-selfheal-{0}" -f [guid]::NewGuid().ToString('N'))
try {
    [IO.File]::WriteAllText($tmp, $json, [Text.UTF8Encoding]::new($false))
    [IO.File]::Move($tmp, (Join-Path $liveAbs 'settings.json'), $true)
} finally {
    if (Test-Path -LiteralPath $tmp) { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
}
Write-Host "[$ConfigDir] wired + valid JSON."
