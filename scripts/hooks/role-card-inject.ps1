# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
#Requires -Version 7.0
<#
.SYNOPSIS
    SessionStart hook. Injects this worktree's role card, or stays silent.

.DESCRIPTION
    WHAT THIS EXISTS FOR. A session is told its seat in its first message. That instruction is an
    ordinary user turn: it competes with everything else in the context and it does not survive a
    compaction. This hook binds the seat to the WORKTREE instead. Sessions come and go inside a
    worktree; the marker survives a crash, a compaction, an account switch and a respawn.

    RESOLUTION ORDER, HIGHEST FIRST.

      1. .claude/seat.local.txt in the worktree root
      2. $env:KORUS_SEAT
      3. Nothing. No card is injected and the command that sets the marker is printed.

    IT NEVER GUESSES FROM A BRANCH OR DIRECTORY NAME, and that omission is deliberate rather than
    unfinished. A worktree name is a creation-time label that nothing keeps current. This
    repository has one right now whose name describes a question its session answered in the first
    two minutes. A card is injected at the weight of the working agreement, so a WRONG card
    outranks the thing the session should have been reading. Silence costs one printed line; a
    wrong card costs a session that confidently follows another seat's rules.
    `TheHookNeverGuessesASeat` in tests/test_role_cards.py pins both the behaviour and the absence
    of any branch read in this source.

    IT NEVER FAILS A TURN. Every path exits 0, as the other hooks here do. A hook that can break a
    session is a worse fault than an undeclared seat, and this one runs in every worktree.

    WHY THE MARKER CANNOT RIDE INTO A COMMIT. This repository's .gitignore carries `/.claude/*`
    with ONE negation, `!/.claude/settings.json`, and the comment above that negation warns that a
    second one would expose nested checkouts carrying `.venv` and the local database. So the marker
    and the injected copy are ignored by the wildcard, and NOTHING here should be added to make
    them so. Measured with `git check-ignore -v`, and pinned by `TheMarkerCannotRideIntoACommit`.

    THE IGNORE RULE IS INVERTED FROM KORUS, where this hook came from. There `.claude/` is
    deliberately TRACKED and machine-local files are named `.local.`. Do not carry that reasoning
    across; the outcome matches and the reason does not.

.PARAMETER WorktreeRoot
    The worktree to resolve the seat for. Defaults to the current directory. Tests pass a
    temporary root; a real session never passes this.
#>

[CmdletBinding()]
param(
    [string] $WorktreeRoot = $PWD.Path
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# The hook reads stdin because the harness sends a JSON payload. Nothing here needs it, but a hook
# that leaves stdin unread can make the caller block on the write.
try { $null = [Console]::In.ReadToEnd() } catch { }

$MarkerRelPath = '.claude/seat.local.txt'
$RoleCopyRelPath = '.claude/ROLE.local.md'

function Write-Note {
    param([string] $Text)
    # Plain stdout. See "the one thing not proven" in docs/ROLE-CARDS.md: whether a hook wired in
    # a project's own settings can emit hookSpecificOutput.additionalContext is UNTESTED here, and
    # plain stdout is the shape this repository has actually exercised at SessionStart.
    Write-Output $Text
}

try {
    $repoRoot = Split-Path -Parent (Split-Path -Parent $PSScriptRoot)
    $seatsPath = Join-Path $repoRoot 'docs/roles/seats.json'

    if (-not (Test-Path -LiteralPath $seatsPath)) {
        Write-Note "[role-card] No roster at docs/roles/seats.json, so no card was injected."
        exit 0
    }

    $seats = Get-Content -LiteralPath $seatsPath -Raw | ConvertFrom-Json

    # ---------------------------------------------------------------- resolve the declared label
    $raw = $null
    $source = $null

    $markerPath = Join-Path $WorktreeRoot $MarkerRelPath
    if (Test-Path -LiteralPath $markerPath) {
        $raw = (Get-Content -LiteralPath $markerPath -Raw -ErrorAction SilentlyContinue)
        $source = $MarkerRelPath
    }

    if ([string]::IsNullOrWhiteSpace($raw) -and $env:KORUS_SEAT) {
        $raw = $env:KORUS_SEAT
        $source = '$env:KORUS_SEAT'
    }

    if ([string]::IsNullOrWhiteSpace($raw)) {
        Write-Note @"
[role-card] NO SEAT IS DECLARED FOR THIS WORKTREE, so no role card was injected.

This is silence, not a failure. Nothing guessed a seat from the branch or directory name, because
a worktree label is a creation-time string that nothing keeps current, and a wrong card would be
injected at the weight of CLAUDE.md.

Set one, from the worktree root, and it survives every later session here:

    Set-Content $MarkerRelPath 'builder'

Live seats: $($seats.live -join ', ').
"@
        exit 0
    }

    $label = $raw.Trim().ToLowerInvariant()

    # ------------------------------------------------------------------------ normalise the label
    $canonical = $null
    if ($seats.live -contains $label) {
        $canonical = $label
    }
    elseif ($seats.aliases.PSObject.Properties.Name -contains $label) {
        $canonical = $seats.aliases.$label
    }

    # ------------------------------------------------------------- a retired seat says so, loudly
    if (-not $canonical -and ($seats.retired.PSObject.Properties.Name -contains $label)) {
        Write-Note @"
[role-card] '$label' IS A RETIRED SEAT. No card was injected.

$($seats.retired.$label)

Its playbook stays in korus at `origin/main:roles/retired/` as the record of what the seat did. A
document that routes work through it is stale. Set a live seat in ${source}:

    Set-Content $MarkerRelPath '<seat>'

Live seats: $($seats.live -join ', ').
"@
        exit 0
    }

    # ------------------------------------------- a seat that is live in korus but not in this table
    $elsewhere = $null
    if ($seats.PSObject.Properties.Name -contains 'elsewhere') {
        if ($seats.elsewhere.PSObject.Properties.Name -contains $label) {
            $elsewhere = $seats.elsewhere.$label
        }
    }
    if (-not $canonical -and $elsewhere) {
        Write-Note @"
[role-card] '$label' IS NOT A SEAT IN THIS REPOSITORY. No card was injected.

$elsewhere

This is a roster difference, not a typo and not a retirement. CLAUDE.md section 5 governs the
roster here, and it is shorter than korus's. Set a seat from this table in ${source}:

    Set-Content $MarkerRelPath '<seat>'

Live seats: $($seats.live -join ', ').
"@
        exit 0
    }

    if (-not $canonical) {
        Write-Note @"
[role-card] '$label' (from $source) MATCHES NO SEAT, so no card was injected and nothing was
guessed. An unmapped label resolves to nothing on purpose.

Live seats: $($seats.live -join ', ').
If '$label' is a spelling of one of those, add it to the aliases map in docs/roles/seats.json.
"@
        exit 0
    }

    # ------------------------------------------------------------------------------ read the card
    $cardPath = Join-Path $repoRoot "docs/roles/$canonical.card.md"
    if (-not (Test-Path -LiteralPath $cardPath)) {
        Write-Note "[role-card] Seat '$canonical' resolved, but docs/roles/$canonical.card.md is missing. No card was injected."
        exit 0
    }

    $card = Get-Content -LiteralPath $cardPath -Raw

    # The cap is enforced by the test suite as well. It is re-checked here so a card edited in a
    # worktree that has not run the tests cannot quietly cost every session on the machine.
    $maxBytes = 6 * 1024
    if ([System.Text.Encoding]::UTF8.GetByteCount($card) -gt $maxBytes) {
        Write-Note "[role-card] docs/roles/$canonical.card.md is over the $maxBytes-byte cap, so it was NOT injected. Trim it, or the seat runs without its card."
        exit 0
    }

    # ------------------------------------------- leave a copy a compacted session can re-read
    try {
        $copyPath = Join-Path $WorktreeRoot $RoleCopyRelPath
        $copyDir = Split-Path -Parent $copyPath
        if (-not (Test-Path -LiteralPath $copyDir)) {
            $null = New-Item -ItemType Directory -Path $copyDir -Force
        }
        Set-Content -LiteralPath $copyPath -Value $card -Encoding utf8NoBOM
    }
    catch {
        # Writing the copy is a convenience. Failing it must not cost the session its card.
        Write-Note "[role-card] Could not write $RoleCopyRelPath ($($_.Exception.Message)). The card below is still in effect."
    }

    Write-Note @"
[role-card] SEAT: $canonical (resolved from $source)

The card below carries the rules for this seat. It is a SUMMARY: CLAUDE.md's seat table governs and
the long playbook is named at the end of the card. A copy is at $RoleCopyRelPath, so it can be
re-read after a compaction.

$card
"@
    exit 0
}
catch {
    # Never fail a turn. An undeclared seat is a smaller fault than a session that cannot start.
    Write-Output "[role-card] The role-card hook failed and was skipped: $($_.Exception.Message)"
    exit 0
}
