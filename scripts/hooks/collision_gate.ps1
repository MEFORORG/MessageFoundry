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

# DENY ONLY ON AN UNCOMMITTED EDIT IN A LIVE WORKTREE. `Files` is the union of what a branch COMMITTED
# and what is dirty in its tree, so a session that committed a file, went clean and finished still
# appears here -- and a committed file stays until the branch LANDS. Reported 2026-08-01 with a repro:
# a session committed a file, confirmed in writing it was done, and the peer it handed off to was still
# refused. While PRs cannot merge, "until it lands" is indefinite, so the blocked set only ever grows.
# That is this gate's own stated failure mode -- "a gate that cries wolf gets uninstalled".
#
# MatchedDirty is the narrower predicate and it is exactly the question being asked: is someone editing
# this file NOW. A row lacking the property (a stale overlap cache written before this change) is
# treated as dirty, so the gate degrades to its previous over-blocking behaviour rather than silently
# permitting a real collision -- over-block is safe, under-block is a silent collision.
$editing = @($live | Where-Object { $null -eq $_.PSObject.Properties['MatchedDirty'] -or $_.MatchedDirty })
if ($editing.Count -eq 0) {
    # Committed-and-clean in every live worktree: report it, do not block. The peer may well have
    # already done what you are about to do, which is worth knowing and not worth refusing over.
    $names = (@($live | ForEach-Object { "$($_.Short) [$($_.Branch)]" }) -join ', ')
    [Console]::Out.Write((@{
                hookSpecificOutput = @{
                    hookEventName     = "PreToolUse"
                    additionalContext = "[collision] $(Split-Path $target -Leaf) was already CHANGED AND COMMITTED on another live session's branch ($names), whose tree is now clean. Not blocking -- but that work may overlap yours, so check its commits before you duplicate or revert it."
                }
            } | ConvertTo-Json -Compress -Depth 6))
    exit 0
}

$leaf = Split-Path $target -Leaf
$lines = @("$leaf has UNCOMMITTED changes in another LIVE session's worktree -- editing it now means one of you loses work at merge.", "")
foreach ($r in $editing) {
    $lines += "  $($r.Short) ($($r.Surface)) in $($r.Worktree) [$($r.Branch)]"
    foreach ($w in @($r.Work | Select-Object -First 2)) { $lines += "      building: $w" }
}
$lines += ""
$lines += "Before overriding: that session may already be doing what you are about to do."
$lines += "  see everything in flight :  pwsh -NoProfile -File scripts\coord\overlap.ps1"
$lines += "  who is live              :  pwsh -NoProfile -File scripts\coord\presence.ps1"
$lines += "If you genuinely need this file, coordinate first -- or edit a different one."

Deny ($lines -join "`n")
