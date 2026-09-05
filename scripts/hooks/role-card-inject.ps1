# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Inject this worktree's role card at session start.

.DESCRIPTION
    A SessionStart hook. It reads the seat this WORKTREE holds, finds that seat's card under
    docs/roles/, and hands it to the starting session.

    WHY THIS EXISTS. A session is told its role in its first message. That works for the
    conversation and dies with it. Measured 2026-09-05 across the live seats directory:

        subagent boxes            25 records,  25 carry a role  (100%)
        worktree sessions        968 records, 145 carry a role  (14%)
        worktree, last 7 days    380 records,  49 carry a role  (12%)

    Subagents reach 100% because the Agent tool writes the seat mechanically. Worktree sessions
    sit at 12% because a person says it out loud. The gap is not effort; it is who writes it. The
    same records held 46 distinct strings for a six-seat roster, including eight spellings of
    Builder, so the label is normalised through docs/roles/seats.json rather than trusted.

    IT NEVER GUESSES. Resolution stops at silence, never at a derived label:

        1. .claude/seat in the worktree root
        2. $env:MEFOR_SEAT
        3. nothing -- print the command that sets it, inject no card

    A branch or directory name is deliberately NOT a rung. CLAUDE.md section 5 records that a
    worktree name is a creation-time label nothing keeps current, and that one is known to
    describe work its session never did. A wrong card injected at CLAUDE.md weight is worse than
    no card, so the silent path is the safe one. tests/test_role_cards.py pins that negative.

    THIS HOOK MUST NEVER FAIL THE TURN. It exits 0 on every path, exactly as seat-record.ps1 and
    seat-declare-prompt.ps1 do. A hook that can break a session is a worse fault than an
    undeclared seat, and this one runs in every worktree of a repo with a live fleet in it.

.NOTES
    Wired at SessionStart beside seat-declare-prompt.ps1. That hook asks for the GOAL, which no
    machine can write; this one supplies the ROLE, which one can. They are complements.
#>

[CmdletBinding()]
param(
    # The worktree to read. Normally derived from the invocation directory; the parameter exists
    # so the tests can drive a tmp_path without a real session.
    [string]$Worktree
)

$ErrorActionPreference = 'Continue'

# Everything below is wrapped. See the header: this hook never fails a turn.
try {
    if (-not $Worktree) { $Worktree = (Get-Location).Path }
    $repo = Split-Path (Split-Path $PSScriptRoot -Parent) -Parent
    $rolesDir = Join-Path $repo 'docs\roles'
    $seatsJson = Join-Path $rolesDir 'seats.json'

    $setCmd = "Set-Content .claude\seat '<seat>'"

    if (-not (Test-Path -LiteralPath $seatsJson)) {
        Write-Output "[role] docs/roles/seats.json is missing from this checkout -- no card injected."
        exit 0
    }
    $seats = Get-Content -LiteralPath $seatsJson -Raw -Encoding UTF8 | ConvertFrom-Json

    # --- Resolve the seat. Rungs in order; each falls through only on an EMPTY result. ---------
    $raw = ''
    $source = ''

    $marker = Join-Path $Worktree '.claude\seat'
    if (Test-Path -LiteralPath $marker) {
        $raw = (Get-Content -LiteralPath $marker -Raw -Encoding UTF8)
        $source = '.claude/seat'
    }
    if (-not $raw.Trim() -and $env:MEFOR_SEAT) {
        $raw = $env:MEFOR_SEAT
        $source = 'MEFOR_SEAT'
    }

    # Strip control characters before matching, so a mangled marker resolves to nothing rather
    # than throwing. It is one line of a file anybody can edit by hand.
    $key = ($raw -replace '[^\x20-\x7E]', '').Trim().ToLowerInvariant()

    if (-not $key) {
        Write-Output @"
[role] This worktree has no seat, so no role card was injected. Set one and every session here
       gets that seat's rules at session start:

           $setCmd

       Seats: $($seats.seats -join ', ')
"@
        exit 0
    }

    # --- Retired seats are named, never resolved. -----------------------------------------------
    $retiredNames = $seats.retired.PSObject.Properties.Name
    if ($retiredNames -contains $key) {
        $why = $seats.retired.$key
        Write-Output "[role] This worktree's seat is '$key', which is retired -- $why. No card injected. Set a live seat with: $setCmd"
        exit 0
    }

    # --- Normalise the spelling. An unmapped string resolves to nothing. -------------------------
    $aliasNames = $seats.aliases.PSObject.Properties.Name
    if ($aliasNames -notcontains $key) {
        Write-Output "[role] '$key' (from $source) is not a known seat, so no card was injected. Seats: $($seats.seats -join ', ')"
        exit 0
    }
    $seat = $seats.aliases.$key

    $card = Join-Path $rolesDir "$seat.card.md"
    if (-not (Test-Path -LiteralPath $card)) {
        Write-Output "[role] seat '$seat' resolved, but docs/roles/$seat.card.md is missing from this checkout."
        exit 0
    }
    $text = Get-Content -LiteralPath $card -Raw -Encoding UTF8

    # --- Leave a copy a COMPACTED session can re-read. ------------------------------------------
    # .claude/ is git-ignored by contents, so this can never dirty the tree. Best effort only:
    # a read-only or absent directory must not cost the injection.
    try {
        $dotClaude = Join-Path $Worktree '.claude'
        if (-not (Test-Path -LiteralPath $dotClaude)) {
            New-Item -ItemType Directory -Path $dotClaude -Force | Out-Null
        }
        Set-Content -LiteralPath (Join-Path $dotClaude 'ROLE.md') -Value $text -Encoding UTF8
    } catch { }

    # --- Emit. -----------------------------------------------------------------------------------
    # additionalContext is the form that renders at CLAUDE.md weight. Plain stdout is the proven
    # fallback -- seat-declare-prompt.ps1 has always reached sessions that way -- so a harness
    # that ignores the JSON still delivers the card, just framed as hook output.
    $payload = [ordered]@{
        hookSpecificOutput = [ordered]@{
            hookEventName    = 'SessionStart'
            additionalContext = $text
        }
    }
    Write-Output ($payload | ConvertTo-Json -Depth 5 -Compress)
} catch {
    # Deliberately swallowed. See the header: this hook never fails a turn.
    Write-Output "[role] role card injection could not run: $($_.Exception.Message)"
}

exit 0
