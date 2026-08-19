# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Ask a starting seat to declare what it is for, and record that it was asked.

.DESCRIPTION
    A SessionStart hook. Thin by design -- it stamps the episode record through
    scripts/coord/seat.ps1 -Prompt and writes ONE line the joining session will read.

    WHY THIS EXISTS. seat.ps1 has carried -Declare -Seat -Goal since it was written, and the
    mechanical half of the record has always worked: a Stop hook fires -Record and every episode
    carries writes, touchedPaths, dirty, unpushed and tip. The declared half did not.

        Measured 2026-08-18 across the live seats directory:
            22 episode records
             1 carried a goal
             1 carried a seat
            22 read lifecycle:open, 0 closed

    So the fleet could always answer "is this seat alive and writing" and could never answer "what
    is it trying to do" -- which is the question a person actually asks. An instrument nobody feeds
    is not a instrument; it is a schema.

    WHAT THIS HOOK CANNOT DO, stated here so nobody expects it later. IT CANNOT WRITE A GOAL. A goal
    is intent, and a machine that invents one produces a record that looks declared and says nothing
    -- the hollow-record failure this repo already refuses for auto-generated ADRs. The hook asks;
    the seat answers or does not.

    WHAT IT CAN GUARANTEE is that the silence is legible. Before this, "no goal" covered two
    different states with opposite fixes:

        never asked      -> the fleet has no declaration habit; fix the setup
        asked, ignored   -> this seat chose not to; fix the seat

    goalPromptedAt separates them. That is the whole contribution, and it is the same rule the
    presence source follows one directory over: a negative is not an absence until you can show the
    question was put.

    THIS HOOK MUST NEVER FAIL THE TURN. It exits 0 unconditionally, on every path, exactly as
    seat-record.ps1 does. A hook that can break a session is a worse fault than an undeclared seat,
    and this one runs in every worktree of a repo with a live fleet in it.

.NOTES
    Wired at SessionStart. Emits at most one line so it cannot crowd a session's context.
#>

[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

try {
    # Read stdin if a payload is there. SessionStart delivers session_id, and without it seat.ps1
    # keys the record by a fallback rather than by the session that is actually starting.
    $raw = ''
    try {
        if (-not [Console]::IsInputRedirected) { $raw = '' }
        else { $raw = [Console]::In.ReadToEnd() }
    } catch { $raw = '' }

    $sessionId = ''
    $sessionName = ''
    if ($raw) {
        try {
            $payload = $raw | ConvertFrom-Json -ErrorAction Stop
            foreach ($f in 'session_id', 'sessionId') {
                if ($payload.PSObject.Properties.Name -contains $f -and $payload.$f) {
                    $sessionId = [string]$payload.$f; break
                }
            }
            foreach ($f in 'name', 'session_name') {
                if ($payload.PSObject.Properties.Name -contains $f -and $payload.$f) {
                    $sessionName = [string]$payload.$f; break
                }
            }
        } catch { }
    }

    $seat = Join-Path (Split-Path $PSScriptRoot -Parent) 'coord\seat.ps1'
    if (-not (Test-Path -LiteralPath $seat)) {
        Write-Output "[seat] scripts/coord/seat.ps1 is missing from this checkout -- the declaration prompt is wired and resolving nothing."
        exit 0
    }

    # A derived label is passed ONLY when the payload named the session. seat.ps1 records it as
    # derived:caller and will not let it overwrite a declaration, so passing it can never launder a
    # guess into a stated intent.
    $args = @('-NoProfile', '-File', $seat, '-Prompt')
    if ($sessionId) { $args += @('-SessionId', $sessionId) }
    if ($sessionName) { $args += @('-DerivedSeat', $sessionName) }

    $out = & pwsh @args 2>&1
    $null = $out   # seat.ps1 owns its own error log; -Prompt is deliberately silent

    Write-Output @"
[seat] Declare what this seat is for before starting work -- one command, and it is what the fleet
       board reads. A seat with no goal renders as UNDECLARED to every other session:

           pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <role> -Goal "<one line>"

       Optional on the same call: -Done "<what finished looks like>" -OutOfScope "<what you will not touch>"
"@
} catch {
    # Deliberately swallowed. See the header: this hook never fails a turn.
    Write-Output "[seat] declaration prompt could not run: $($_.Exception.Message)"
}

exit 0
