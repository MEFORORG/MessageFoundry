# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    A SessionEnd hook: release the worktree lock this session placed on arrival (BACKLOG #2524).

.DESCRIPTION
    seat.ps1 locks a seat's worktree at SessionStart and on -Declare, with the reason
    `<seat> <session id>`; scripts/worktree/worktree-audit.ps1 says why. This hook is the clean-exit
    half. It unlocks only a seat lock that names THIS session's id, so Claude Code's own lock on an
    agent worktree, a hand-placed lock, and another live seat's lock all stay.

    A session that dies without reaching this hook leaves its lock, and the tree is then kept by every
    reclaimer. hygiene-report.ps1 lists those locks, under "Seat locks whose session is gone".

    IT ANSWERS FOR THE SESSION'S OWN WORKTREE, NOT THE ONE IT STARTED IN. Under the desktop app a hook
    starts in the primary checkout; _hookinput.ps1 resolves the session's worktree from the pin its
    SessionStart wrote, or the input's `cwd`. It reads the pin and never writes one.

    IT NEVER FAILS AND NEVER SPEAKS. It exits 0 on every path and prints nothing, because a session
    that is ending has no turn left to read a line. A failed unlock leaves the lock, which
    hygiene-report.ps1 then lists like any other left behind.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Continue'

try {
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') { exit 0 }
    . (Join-Path $PSScriptRoot '_hookinput.ps1')
    $raw = Read-CcxHookInput
    $s = Resolve-CcxHookSession -Text $raw -ReadOnly
    if (-not $s.SessionId) { exit 0 }
    # /clear and /resume end a session id while the process, and its seat, go on in the same tree.
    # The lock stays and keeps protecting the tree; the SessionStart that follows hands it over to the
    # new id (seat.ps1 -Prompt -Source), whose own exit then releases it.
    if ($s.Payload -and $s.Payload.PSObject.Properties['reason'] -and [string]$s.Payload.reason -in @('clear', 'resume')) { exit 0 }
    # The pinned worktree first. With no pin (a session since /clear), the input's own `cwd`: the
    # helper refuses to answer for an unpinned linked worktree, but an unlock removes only a lock
    # naming THIS session id, so following the `cwd` cannot release anyone else's.
    $root = $s.Root
    if (-not $root -and $s.Payload -and $s.Payload.PSObject.Properties['cwd']) {
        $p = Get-CcxHookPayloadCwd -Payload $s.Payload
        if ($p.Cwd) { $root = Get-CcxWorktreeRoot $p.Cwd }
    }
    if (-not $root) { $root = Get-CcxWorktreeRoot (Get-Location).ProviderPath }
    if (-not $root) { exit 0 }
    . (Join-Path (Split-Path -Parent $PSScriptRoot) 'worktree\seat-lock.ps1')
    $null = Remove-SeatWorktreeLock -Worktree $root -SessionKey (ConvertTo-SeatSessionKey $s.SessionId)
}
catch { }

exit 0
