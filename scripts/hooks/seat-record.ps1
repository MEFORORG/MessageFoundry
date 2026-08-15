# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Stop hook: record this session's episode so a replacement seat under another account can pick the
    work up. Thin by design -- it forwards stdin to scripts/coord/seat.ps1 and gets out of the way.

.DESCRIPTION
    WIRED TO Stop ONLY, and that is a measured choice rather than a default. Stop already pays a pwsh
    spawn for the mail drain, and install-coordination.ps1 measured roughly 366 ms per spawn against
    about 19 tool calls per turn. A second UserPromptSubmit hook would be a standing tax on every
    prompt for a path exercised at account-switch frequency -- days apart, not seconds. Stop fires at
    every turn end, so the record's asOf is still bounded by the seat's last COMPLETED turn.

    THE TURN IT IS WRITTEN IN IS THE TURN IT CANNOT SEE. A Stop hook runs at the end of a turn, so a
    turn killed mid-flight leaves no record of itself, and the blind spot is always the NEWEST turn --
    which is exactly what a replacement most needs. This is why fleet.ps1 re-reads the predecessor
    worktree's ACTUAL git status at render time rather than trusting the recorded one, and renders any
    disagreement as stranded work. The hook cannot close this gap; the reader has to.

    THIS HOOK MUST NEVER FAIL THE TURN. It exits 0 unconditionally. seat.ps1 already records its own
    failures to seats/.writer-errors.txt and exits 0 for the same reason, so a broken writer leaves a
    trail without taking the session's Stop handler down with it.

    NO OUTPUT ON THE SUCCESS PATH. Stop-hook output is shown to the model, and a line printed at every
    single turn end is noise that trains the reader to skip the whole channel -- including the turn it
    finally says something that matters.
#>
[CmdletBinding()]
param([string]$CommonDir)

# Deliberately NOT 'Stop'. A throw here would surface as a failed Stop hook every turn.
$ErrorActionPreference = 'Continue'

try {
    # Read stdin ONCE and pass it on. The payload carries session_id, and without it seat.ps1 keys the
    # record on the literal string 'nosid' -- correct, but it collapses every unidentified session in
    # a worktree into one record, so the payload is worth forwarding carefully.
    $payload = ''
    if ([Console]::IsInputRedirected) { $payload = [Console]::In.ReadToEnd() }

    $seat = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\seat.ps1'
    if (-not (Test-Path -LiteralPath $seat)) {
        # Resolving to nothing is the failure mode this whole layer exists to make visible, so say so
        # rather than exiting quietly. A wired hook that resolves nothing is byte-identical to a
        # healthy one with nothing to do.
        Write-Output "[seat] scripts/coord/seat.ps1 is missing from this checkout -- the seat recorder is wired but resolving nothing."
        exit 0
    }

    if ($payload) {
        $payload | & pwsh -NoProfile -File $seat -Record 2>&1 | Out-Null
    } else {
        & pwsh -NoProfile -File $seat -Record 2>&1 | Out-Null
    }
} catch {
    # Last resort. seat.ps1 owns the error log; if we could not even reach it there is nowhere better
    # than stderr, and the turn still ends cleanly.
    Write-Error "[seat] recorder failed: $($_.Exception.Message)" -EA Continue
}

exit 0
