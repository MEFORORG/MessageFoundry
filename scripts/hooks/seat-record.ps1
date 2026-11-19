# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Stop hook: record this session's episode so a replacement seat under another account can pick the
    work up. Thin by design -- it resolves the session's worktree with scripts/hooks/_hookinput.ps1,
    forwards stdin to scripts/coord/seat.ps1 with that worktree named, and gets out of the way.

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
    $seat = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\seat.ps1'
    if (-not (Test-Path -LiteralPath $seat)) {
        # Resolving to nothing is the failure mode this whole layer exists to make visible, so say so
        # rather than exiting quietly. A wired hook that resolves nothing is byte-identical to a
        # healthy one with nothing to do.
        Write-Output "[seat] scripts/coord/seat.ps1 is missing from this checkout -- the seat recorder is wired but resolving nothing."
        exit 0
    }

    # WHICH WORKTREE THE RECORD IS FOR comes from the shared session-pin rules in _hookinput.ps1, never
    # from the payload's raw cwd. That cwd is where the session is NOW, so after a `cd` into a sibling
    # worktree or another repository it would put this session's record there. Tested for first: a
    # dot-source of a missing file is not reliably a throw, and its absence is a fault to say aloud.
    $hookInput = Join-Path $PSScriptRoot '_hookinput.ps1'
    if (-not (Test-Path -LiteralPath $hookInput -PathType Leaf)) {
        Write-Output "[seat] scripts/hooks/_hookinput.ps1 is missing beside this hook, so it cannot tell which worktree this session is in; nothing was recorded."
        exit 0
    }
    . $hookInput
    # Read stdin ONCE and pass it on. The payload carries session_id, and without it seat.ps1 keys the
    # record on the literal string 'nosid' -- correct, but it collapses every unidentified session in
    # a worktree into one record, so the payload is worth forwarding carefully.
    $payload = Read-CcxHookInput
    $session = Enter-CcxHookSession -Text $payload -ReadOnly
    if ($session.Reason) {
        # The only worktree left to record is the one this hook started in, the PRIMARY under the
        # desktop app, and a record there would say this session sits in the primary.
        Write-Output "[seat] could not read this session's worktree: $($session.Reason). Nothing was recorded for this turn."
        exit 0
    }
    # Named explicitly, so seat.ps1 never falls back to the payload's cwd as its hint.
    $worktree = if ($session.Dir) { [string]$session.Dir } else { (Get-Location).ProviderPath }

    # The running pwsh by full path, not a PATH lookup: a launch error must not be discarded with the
    # recorder's output, because a recorder that never ran is the failure this layer exists to show.
    $pwsh = if ($PSVersionTable.PSEdition -eq 'Core') { [Environment]::ProcessPath } else { '' }
    if (-not $pwsh) { $pwsh = (Get-Command pwsh -CommandType Application -ErrorAction Stop | Select-Object -First 1).Source }
    $recorderArgs = @('-NoProfile', '-File', $seat, '-Record', '-Worktree', $worktree)
    # Cleared first, so a launch that never sets it reads as no exit code rather than an earlier one.
    $global:LASTEXITCODE = $null
    $out = if ($payload) { $payload | & $pwsh @recorderArgs 2>&1 } else { & $pwsh @recorderArgs 2>&1 }
    # seat.ps1 -Record exits 0 on every route it controls, so any other code, or none, means it never
    # ran as written: pwsh refused the file, or it could not start.
    $code = $global:LASTEXITCODE
    if ($code -ne 0) {
        $detail = (@($out) | ForEach-Object { [string]$_ } | Where-Object { $_.Trim() } | Select-Object -Last 3) -join ' | '
        $exited = if ($null -eq $code) { 'did not start' } else { "exited $code" }
        Write-Output "[seat] the seat recorder $exited, so this turn was not recorded. $detail"
    }
} catch {
    # Last resort. seat.ps1 owns the error log; if we could not even reach it, say so on stdout, where
    # this hook's other notices go, and the turn still ends cleanly.
    Write-Output "[seat] recorder failed: $($_.Exception.Message)"
}

exit 0
