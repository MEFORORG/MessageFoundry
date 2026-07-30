<#
.SYNOPSIS
    PreToolUse gate: refuse to edit a file another LIVE session is already changing.

.DESCRIPTION
    Worktrees stop two sessions from overwriting each other's bytes. They do NOT stop two sessions
    from editing the same file in parallel and discovering it at merge -- by which point both have
    built on divergent assumptions and someone's work is thrown away. This gate turns that from a
    merge-time surprise into an edit-time refusal, which is the only point where it is still cheap.

    NOTHING TO OPT INTO. It reads git state and the session registry, both by-products of working
    normally. That is the whole design: `claim.ps1` has existed for some time and has been used
    exactly ZERO times, because a coordination step you must remember is one you will skip. A guard
    that needs cooperation to work does not work.

    ONLY LIVE SESSIONS BLOCK. A dormant worktree with changes cannot be racing you -- its owner is not
    typing -- so it is reported and allowed. Blocking on dormant worktrees would deny edits to every
    file any abandoned branch ever touched, and a gate that cries wolf gets uninstalled.

    FAILS OPEN, DELIBERATELY. Any error -- unparseable payload, no git, no registry, a broken overlap
    script -- exits 0 and allows the edit. This gate prevents rework; it must never be the reason a
    session cannot work. That is the opposite of the worktree gate's posture (which protects the
    shared tree and should fail closed), and the difference is intentional.

    Wired on Edit|Write|MultiEdit|NotebookEdit. The overlap map is cached, so the common case is a
    cache read, not a git walk across every worktree.
#>
[CmdletBinding()]
param(
    # Overlap script to consult. Parameterised so tests drive the REAL gate against a fixture rather
    # than re-implementing its rule -- a test that asserts a copy of the rule proves nothing.
    [string]$OverlapScript = (Join-Path $PSScriptRoot "..\coord\overlap.ps1"),
    # Emit the decision and skip reading stdin (tests).
    [string]$PathOverride
)

# No $ErrorActionPreference = Stop: this gate fails OPEN, and a throw would be a deny-by-crash.
$ErrorActionPreference = "SilentlyContinue"

function Deny([string]$Reason) {
    # The hookSpecificOutput wrapper is MANDATORY -- a bare permissionDecision is silently ignored,
    # which would leave this looking installed while permitting everything.
    $payload = @{
        hookSpecificOutput = @{
            hookEventName            = "PreToolUse"
            permissionDecision       = "deny"
            permissionDecisionReason = $Reason
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

$target = $PathOverride
if (-not $target) {
    if (-not [Console]::IsInputRedirected) { exit 0 }
    try { $hook = [Console]::In.ReadToEnd() | ConvertFrom-Json } catch { exit 0 }
    if (-not $hook) { exit 0 }
    $target = [string]$hook.tool_input.file_path
    # NotebookEdit and some variants name the path differently; absence just means nothing to check.
    if (-not $target) { $target = [string]$hook.tool_input.notebook_path }
}
if (-not $target) { exit 0 }

if (-not (Test-Path -LiteralPath $OverlapScript)) { exit 0 }

$rows = @()
try {
    $raw = & pwsh -NoProfile -NonInteractive -File $OverlapScript -File $target -Json 2>$null
    if ($raw) { $rows = @($raw | ConvertFrom-Json) }
} catch { exit 0 }
if (-not $rows -or $rows.Count -eq 0) { exit 0 }

$live = @($rows | Where-Object { $_.Live })
if ($live.Count -eq 0) { exit 0 }   # dormant only: worth knowing, not worth blocking

$leaf = Split-Path $target -Leaf
$lines = @("$leaf is already being changed by another LIVE session -- editing it now means one of you loses work at merge.", "")
foreach ($r in $live) {
    $lines += "  $($r.Short) ($($r.Surface)) in $($r.Worktree) [$($r.Branch)]"
    foreach ($w in @($r.Work | Select-Object -First 2)) { $lines += "      building: $w" }
}
$lines += ""
$lines += "Before overriding: that session may already be doing what you are about to do."
$lines += "  see everything in flight :  pwsh -NoProfile -File scripts\coord\overlap.ps1"
$lines += "  who is live              :  pwsh -NoProfile -File scripts\coord\presence.ps1"
$lines += "If you genuinely need this file, coordinate first -- or edit a different one."

Deny ($lines -join "`n")
