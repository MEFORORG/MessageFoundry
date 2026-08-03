<#
.SYNOPSIS
    Wire usage-collect.ps1 as the Claude Code statusLine, so the account's plan limits get published.

.DESCRIPTION
    Run this ONCE, from a plain terminal. It writes `statusLine` into the USER-level
    ~/.claude/settings.json, so every session on this machine publishes -- and reads -- the same
    account-wide quota state. See usage-collect.ps1 for why the statusLine is the only source.

    IT TAKES EFFECT IN NEWLY STARTED SESSIONS. Existing sessions keep the config they booted with, the
    same as the coordination hooks. And it only ever runs in an INTERACTIVE session: the statusLine is
    part of the TUI's render tree and never executes under `claude -p` or the SDK, so a headless
    coordinator can read what this publishes but can never publish it itself.

    WHY IT POINTS AT AN ABSOLUTE PATH rather than resolving the repo per invocation: the statusLine runs
    on every assistant message behind a 300ms debounce, and a `git rev-parse` per fire is latency on the
    render path for a value that never changes. The trade is that moving or deleting the checkout breaks
    it -- so the wired command TESTS FOR THE SCRIPT and degrades to a quiet marker instead of erroring
    into the status bar on every message.

    refreshInterval is set because statusLine updates are EVENT-DRIVEN -- a new assistant message,
    /compact, a permission-mode change -- and go silent when a session is idle. Anthropic's own docs
    name "a coordinator waits on background subagents" as the case where that leaves you blind, which is
    exactly this repo's situation.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -Status
    pwsh -NoProfile -File scripts\coord\install-usage-statusline.ps1 -Uninstall
#>
[CmdletBinding(SupportsShouldProcess)]
param(
    [switch]$Uninstall,
    [switch]$Status,
    # Milliseconds. Minimum honoured by Claude Code is 1000.
    [int]$RefreshInterval = 10000,
    [string]$SettingsPath = (Join-Path $env:USERPROFILE ".claude\settings.json"),
    # Which collector to wire. Defaults to the PRIMARY checkout's copy, deliberately: a worktree is
    # disposable and a user-level statusLine pointing into one dies with it. Overridable so tests can
    # drive the real installer against a fixture instead of asserting a copy of its rules.
    [string]$CollectorPath
)

$ErrorActionPreference = "Stop"
$MARKER = "mefor-usage"

# The primary checkout, not this worktree: a worktree is disposable and the statusLine outlives it.
$common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $common) { throw "Not inside a git repository -- run this from the MessageFoundry checkout." }
$primary = Split-Path ($common.Trim()) -Parent
$script = if ($CollectorPath) { $CollectorPath } else { Join-Path $primary "scripts/coord/usage-collect.ps1" }

function Get-Settings {
    if (-not (Test-Path -LiteralPath $SettingsPath)) { return [ordered]@{} }
    $raw = Get-Content -LiteralPath $SettingsPath -Raw
    if (-not $raw.Trim()) { return [ordered]@{} }
    return ($raw | ConvertFrom-Json -AsHashtable)
}

if ($Status) {
    $s = Get-Settings
    $sl = $s['statusLine']
    Write-Host ""
    if (-not $sl) { Write-Host "statusLine: NOT CONFIGURED" -ForegroundColor Yellow }
    else {
        $isOurs = ([string]$sl['command']) -like "*$MARKER*"
        Write-Host ("statusLine: CONFIGURED" + $(if ($isOurs) { " (ours)" } else { " (SOMEONE ELSE'S -- install would replace it)" })) -ForegroundColor $(if ($isOurs) { "Green" } else { "Yellow" })
        Write-Host "  command        : $($sl['command'])"
        Write-Host "  refreshInterval: $($sl['refreshInterval'])"
    }
    Write-Host "  script exists  : $(Test-Path -LiteralPath $script)  ($script)"
    $latest = Join-Path $env:USERPROFILE ".claude\mefor-usage\latest.json"
    # A RECEIPT, NOT A CONFIG READ. Whether the settings file names the script says nothing about
    # whether it has ever run -- that distinction is the one this repo keeps paying for.
    Write-Host "  has published  : $(Test-Path -LiteralPath $latest)  ($latest)" -ForegroundColor $(if (Test-Path -LiteralPath $latest) { "Green" } else { "Yellow" })
    Write-Host ""
    exit 0
}

$settings = Get-Settings

if ($Uninstall) {
    if ($settings['statusLine'] -and ([string]$settings['statusLine']['command']) -like "*$MARKER*") {
        $settings.Remove('statusLine')
        if ($PSCmdlet.ShouldProcess($SettingsPath, "remove the mefor-usage statusLine")) {
            Copy-Item -LiteralPath $SettingsPath -Destination "$SettingsPath.bak-usage" -Force -ErrorAction SilentlyContinue
            ($settings | ConvertTo-Json -Depth 20) | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
            Write-Host "statusLine REMOVED from $SettingsPath" -ForegroundColor Yellow
        }
    }
    else { Write-Host "Nothing to remove: the statusLine is absent or is not ours." -ForegroundColor Yellow }
    exit 0
}

if (-not (Test-Path -LiteralPath $script)) {
    throw "Collector not found at $script. The primary checkout ($primary) does not carry it yet -- merge the branch that adds it, or advance the primary, before installing."
}

if ($settings['statusLine'] -and ([string]$settings['statusLine']['command']) -notlike "*$MARKER*") {
    Write-Host ""
    Write-Host "REFUSING: a statusLine is already configured and it is not ours." -ForegroundColor Red
    Write-Host "  command: $($settings['statusLine']['command'])"
    Write-Host ""
    Write-Host "Silently replacing someone's status bar is not this script's call. Remove it yourself, or"
    Write-Host "merge the two commands by hand, then re-run."
    exit 1
}

# The guard is inline so a missing script degrades to a marker rather than erroring into the status bar
# on every single message -- a statusLine that shouts an exception is worse than one that says nothing.
$cmd = "# $MARKER`n" +
"`$s = '$($script -replace "'", "''")'; if (Test-Path -LiteralPath `$s) { & pwsh -NoProfile -File `$s } else { Write-Output '${MARKER}: collector missing' }"

$settings['statusLine'] = [ordered]@{
    type            = "command"
    command         = $cmd
    refreshInterval = $RefreshInterval
}

if ($PSCmdlet.ShouldProcess($SettingsPath, "install the mefor-usage statusLine")) {
    if (Test-Path -LiteralPath $SettingsPath) { Copy-Item -LiteralPath $SettingsPath -Destination "$SettingsPath.bak-usage" -Force }
    $json = $settings | ConvertTo-Json -Depth 20
    # Never leave the file unparseable: a broken settings.json degrades every session on this machine.
    try { $null = $json | ConvertFrom-Json } catch { throw "Refusing to write: generated settings JSON is invalid. $_" }
    $json | Set-Content -LiteralPath $SettingsPath -Encoding UTF8
    Write-Host ""
    Write-Host "statusLine INSTALLED (user level -- every session on this machine)" -ForegroundColor Green
    Write-Host "  collector      : $script"
    Write-Host "  refreshInterval: $RefreshInterval ms"
    Write-Host "  publishes to   : $(Join-Path $env:USERPROFILE '.claude\mefor-usage\latest.json')"
    Write-Host "  backup         : $SettingsPath.bak-usage"
    Write-Host ""
    Write-Host "  Takes effect in NEWLY STARTED sessions. Interactive only -- never under 'claude -p'."
    Write-Host "  Then read it with:  pwsh -NoProfile -File scripts\coord\usage.ps1"
    Write-Host ""
}
