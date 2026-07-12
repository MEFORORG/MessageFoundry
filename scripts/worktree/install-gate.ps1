<#
.SYNOPSIS
    Install (or remove) the worktree gate -- a PreToolUse hook that stops sessions BUILDING in the
    shared primary checkout.

.DESCRIPTION
    Copies scripts\hooks\worktree_gate.ps1 to the USER scope (%USERPROFILE%\.claude\hooks\) and registers
    it in %USERPROFILE%\.claude\settings.json.

    WHY USER SCOPE, and why an installed COPY:

      * Reach. A hook in the project's .claude\settings.json is git-tracked, so it lives on ONE branch and
        does not exist in the other worktrees until each of them merges it. A user-scope hook governs every
        session on the machine the moment it is written. Hook definitions from the user, project and local
        scopes are unioned, so this ADDS to the repo's existing guards rather than replacing them.

      * Survivability. The command must not point into a working tree. The primary checkout is routinely
        on a detached HEAD or an old commit; a hook whose script path lives there vanishes on a checkout,
        and a hook whose script is missing exits non-zero-but-not-2 -- which means the tool call RUNS
        ANYWAY, silently. The gate would be off in every session and nothing would say so. So we install a
        copy outside every tree and re-copy it on each install.

    The gate only governs the checkouts listed in worktree-gate.repos.txt. That file IS the kill switch:
    -Uninstall removes it (and the hook entries).

    Run from a PLAIN TERMINAL, not from inside Claude Code -- a session that can install its own gate can
    uninstall it. The script refuses when $env:CLAUDECODE is set.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Repo C:\Users\me\Code\Probe   # govern a test repo
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall
    pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Status
#>
[CmdletBinding()]
param(
    # Primary checkout(s) to govern. Defaults to this repo's root.
    [string[]]$Repo,
    [switch]$Uninstall,
    [switch]$Status,
    # Do not gate Task/Agent/Workflow dispatch from the primary (writes are still gated).
    [switch]$NoDispatchGate
)

$ErrorActionPreference = "Stop"

if ($env:CLAUDECODE -eq "1") {
    throw "Refusing to run inside Claude Code. A session that can install this gate can also remove it. Run from a plain pwsh terminal."
}

$RepoRoot  = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$ClaudeDir = Join-Path $env:USERPROFILE ".claude"
$HooksDir  = Join-Path $ClaudeDir "hooks"
$Settings  = Join-Path $ClaudeDir "settings.json"
$GateDst   = Join-Path $HooksDir "worktree_gate.ps1"
$ReposFile = Join-Path $HooksDir "worktree-gate.repos.txt"

# Marker so we can find (and remove) exactly the entries we added, without disturbing other hooks.
$Marker = "worktree_gate.ps1"

function Read-Settings {
    if (-not (Test-Path -LiteralPath $Settings)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $Settings -Raw
    if ([string]::IsNullOrWhiteSpace($raw)) { return [ordered]@{} }
    try { return ($raw | ConvertFrom-Json -AsHashtable) }
    catch { throw "$Settings is not valid JSON -- fix it by hand before installing (it is live config for every session)." }
}

function Write-Settings($Data) {
    # Two sessions installing at once could interleave a read-modify-write and leave INVALID JSON, which
    # would break hooks in every session on the machine at once. Serialize to a temp file, parse it back
    # to prove it is valid, keep a backup, then move it into place in one atomic operation.
    $json = $Data | ConvertTo-Json -Depth 20
    $null = $json | ConvertFrom-Json      # throws before we touch the real file
    $tmp = "$Settings.tmp-$PID"
    Set-Content -LiteralPath $tmp -Value $json -Encoding utf8
    if (Test-Path -LiteralPath $Settings) { Copy-Item -LiteralPath $Settings "$Settings.bak" -Force }
    Move-Item -LiteralPath $tmp -Destination $Settings -Force
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

# ------------------------------------------------------------------------------------------ status
if ($Status) {
    $installed = Test-Path -LiteralPath $GateDst
    Write-Host "gate script : $(if ($installed) { "installed -> $GateDst" } else { 'NOT installed' })"
    if (Test-Path -LiteralPath $ReposFile) {
        Write-Host "governing   :"
        Get-Content -LiteralPath $ReposFile | Where-Object { $_ -and -not $_.StartsWith('#') } |
            ForEach-Object { Write-Host "              $_" }
    } else {
        Write-Host "governing   : nothing (no allowlist -> gate is OFF)"
    }
    $s = Read-Settings
    $n = @($s.hooks.PreToolUse | Where-Object { @($_.hooks) | Where-Object { "$($_.command)" -like "*$Marker*" } }).Count
    Write-Host "hook entries: $n registered in $Settings"
    return
}

# --------------------------------------------------------------------------------------- uninstall
if ($Uninstall) {
    $data = Remove-GateHooks (Read-Settings)
    Write-Settings $data
    Remove-Item -LiteralPath $ReposFile -Force -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $GateDst   -Force -ErrorAction SilentlyContinue
    Write-Host "Worktree gate REMOVED. Sessions are no longer gated (takes effect immediately)." -ForegroundColor Yellow
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
Copy-Item -LiteralPath (Join-Path $RepoRoot "scripts\hooks\worktree_gate.ps1") -Destination $GateDst -Force

@(
    "# Primary checkouts governed by the worktree gate (scripts\hooks\worktree_gate.ps1)."
    "# Writes INTO these trees are denied; writes into their linked worktrees are allowed."
    "# Deleting this file turns the gate OFF everywhere, immediately."
    $resolved
) | Set-Content -LiteralPath $ReposFile -Encoding utf8

$command = "pwsh -NoProfile -File `"$GateDst`""
$data    = Remove-GateHooks (Read-Settings)      # idempotent: drop our old entries, then re-add
if (-not $data.hooks)             { $data.hooks = [ordered]@{} }
if (-not $data.hooks.PreToolUse)  { $data.hooks.PreToolUse = @() }

# One matcher per rule in scripts/hooks/worktree_gate.ps1. A rule the hook implements but that is not
# matched here NEVER FIRES -- the hook is simply not invoked for that tool, and nothing says so. Rule 3
# shipped in exactly that state. tests/test_install_gate_wiring.py now asserts that every tool the script
# branches on appears in this list, so the two cannot drift apart again.
$matchers = @(
    "Write|Edit|MultiEdit|NotebookEdit"   # rule 1 -- writes INTO the primary's tree
    "Bash|PowerShell"                     # rule 3 -- git verbs that swap the primary's tree
)
if (-not $NoDispatchGate) {
    $matchers += "Task|Agent|Workflow"    # rule 2 -- subagent dispatch FROM the primary
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
$data.hooks.PreToolUse = @($data.hooks.PreToolUse) + @($entries)
Write-Settings $data

Write-Host ""
Write-Host "Worktree gate INSTALLED (user scope -- every session, every worktree, no restart)." -ForegroundColor Green
Write-Host "  gate      : $GateDst"
Write-Host "  allowlist : $ReposFile"
$resolved | ForEach-Object { Write-Host "  governing : $_" }
Write-Host "  matchers  : $($matchers -join '  +  ')"
Write-Host ""
Write-Host "Writes into a governed tree are DENIED; writes into its linked worktrees are allowed."
Write-Host "To turn it off:  pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall"
