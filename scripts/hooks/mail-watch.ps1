# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Hook (asyncRewake): wake this session the moment mail arrives, instead of at the next turn boundary.

.DESCRIPTION
    The URGENT tier. scripts/hooks/mail-drain.ps1 delivers at SessionStart and Stop, which is the right
    default and costs one process per turn. This delivers MID-TURN, on the SENDER's clock, for the case
    where waiting for the recipient to finish what it is doing is the whole problem.

    HOW IT WORKS, AND THIS IS A MEASURED MECHANISM, NOT AN INFERRED ONE.
    Claude Code's command-hook schema carries `asyncRewake`: "If true, hook runs in background and wakes
    the model on exit code 2 (blocking error). Implies async." On exit 2 the hook's output is injected
    into the RUNNING session as a system reminder. Verified end-to-end on 2026-08-05 against v2.1.221:
    a probe hook armed at SessionStart, exiting 2 after two seconds, produced the token in the
    assistant's own output and a post_turn_summary reading "<token> arrived; processing". So the model
    genuinely receives it mid-turn.

    THE TRAP THAT MAKES THIS SILENTLY NOT WORK, AND IT COST A FULL DEBUG CYCLE TO FIND.
    The rewake fires on exit code 2 and ONLY on exit code 2. When the hook command is a nested
    PowerShell invocation, the outer shell does NOT propagate the inner script's exit code -- it reports
    1. Measured: the identical probe reported `exit_code: 1, outcome: error` and the payload was logged
    as a hook error and DISCARDED, versus `exit_code: 2` and a real injection once the command appended
    `; exit $LASTEXITCODE`. The failure is completely silent from the session's side: the hook ran, the
    output was captured, nothing arrived. THE INSTALLER MUST EMIT THAT SUFFIX -- see
    scripts/coord/install-coordination.ps1.

    ALSO SET `async: true` ALONGSIDE `asyncRewake: true`. The "implies async" claim is conditional. The
    binary gates backgrounding on `isInteractive || hasStreamingInput`, so in a NON-interactive run
    (claude -p) `asyncRewake` alone falls through to the synchronous path and this script would block
    the session for its full timeout. Setting `async` forces the background branch unconditionally while
    still carrying the rewake fields.

    IT IS ONE-SHOT, AND THAT IS A REAL LIMITATION, STATED RATHER THAN PAPERED OVER.
    The rewake belongs to the process CLAUDE CODE ITSELF SPAWNED and is tracking by hook id. A watcher
    that re-spawned itself would produce a grandchild whose exit code no one is listening to, so
    self-re-arming does not work and is not attempted. After one delivery this watcher is done, and the
    session falls back to the Stop/SessionStart drain until the next arming event. Re-arming is
    therefore a hook's job, not this script's.

    IT DOES NOT DUPLICATE THE DRAIN. It waits for mail, then runs mail-drain.ps1 and rewakes with that
    output. One definition of consume-and-receipt, not two -- if this rendered its own copy, the two
    would drift and the copy that drifts is the one nobody tests.

    WHAT IT WAITS FOR IS "MAIL THIS SESSION HAS NOT BEEN SHOWN", NOT "A NON-EMPTY INBOX". Those were the
    same condition until the drain stopped consuming at SessionStart. Now a shown message STAYS in the
    inbox until the session's turn boundary, so a non-empty inbox is the steady state and the old test
    fired on it repeatedly -- a blocking mid-turn rewake carrying "Nothing is being shown to you". The
    shown-marker under box/<key>/shown/ is what distinguishes them, and reading it is not rendering:
    delivery still happens in exactly one place.

    FAIL OPEN. Any error exits 0, which means "no rewake" and costs nothing.
#>
[CmdletBinding()]
param(
    # How long to wait for mail before giving up quietly. Must stay comfortably under the hook's
    # configured timeout: a watcher killed at timeout is indistinguishable from one that found nothing.
    [int]$MaxWaitSeconds = 900,
    [int]$PollSeconds = 3
)

$ErrorActionPreference = 'SilentlyContinue'

try {
    $stdinRaw = ''
    if ([Console]::IsInputRedirected) { $stdinRaw = [Console]::In.ReadToEnd() }
    $hook = $null
    try { $hook = $stdinRaw | ConvertFrom-Json } catch { }
    if (-not $hook) { exit 0 }

    $cwd = if ($hook.cwd) { [string]$hook.cwd } else { (Get-Location).Path }

    $common = & git -C $cwd rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $common) { exit 0 }
    $root = Join-Path $common.Trim() 'mefor-coord/mail'

    # mail-claim.ps1 dot-sources mail-key.ps1, so this takes both halves of the contract at once and
    # cannot end up holding only the box key. What is needed from it is the SHOWN-MARKER name shape.
    . "$PSScriptRoot\..\coord\mail-claim.ps1"
    $key = ConvertTo-BoxKey -Path $cwd
    $inboxDir = Join-Path $root "box/$key/inbox"
    $shownDir = Join-Path $root "box/$key/shown"
    # Validated before any path is built from it, exactly as the drain does; $null means UNMARKABLE.
    $sessionKey = ConvertTo-SessionKey -SessionId ([string]$hook.session_id)

    $deadline = [DateTime]::UtcNow.AddSeconds($MaxWaitSeconds)
    while ([DateTime]::UtcNow -lt $deadline) {
        # The OFF switch is checked every pass, not once at arm time: it exists to reach sessions that
        # are ALREADY running, and a watcher armed an hour ago is exactly such a session.
        if (Test-Path -LiteralPath (Join-Path $root 'OFF')) { exit 0 }

        if (Test-Path -LiteralPath $inboxDir) {
            # "MAIL THIS SESSION HAS NOT BEEN SHOWN", NOT "THE INBOX IS NON-EMPTY". Those were the same
            # question until the drain stopped consuming at SessionStart: mail it shows now STAYS in the
            # inbox until the session's next turn boundary, so a non-empty inbox is the steady state
            # rather than the arrival signal. Measured against the earlier form: a re-armed watcher fired
            # immediately on held mail, ran the drain, got its zero-delivery injection, and rewoke the
            # session MID-TURN with "Nothing is being shown to you" -- a blocking interruption carrying
            # no content, repeatable for as long as the mail sat there.
            #
            # This is not a second copy of the drain's delivery logic: it asks only "is there anything
            # new for me", and the drain remains the one place a message is rendered, receipted and
            # consumed. An UNMARKABLE session falls back to the inbox test, which is the old behaviour
            # and the old cost -- the drain has already told that session it cannot record displays for
            # it, and a one-shot watcher fires at most once anyway.
            $pending = @(Get-ChildItem -LiteralPath $inboxDir -Filter *.json -File -EA SilentlyContinue |
                Where-Object {
                    if (-not $sessionKey) { return $true }
                    $p = Split-MailFileName -Name $_.Name
                    if (-not $p) { return $false }   # a name we did not mint; the drain will not show it
                    # Test-FilePresent, not File.Exists -- this channel's one probe, for the reason its
                    # header gives. Its failure direction here is an extra wake, never a missed one.
                    -not (Test-FilePresent -Path (Join-Path $shownDir "$($p.Stem)--$sessionKey.marker"))
                })
            if ($pending.Count -gt 0) {
                # Hand the same stdin straight through, so the drain resolves the identical box, applies
                # the identical session filter, and writes the identical receipt.
                $out = ($stdinRaw | & pwsh -NoProfile -File (Join-Path $PSScriptRoot 'mail-drain.ps1') 2>$null)
                if (-not $out) { exit 0 }   # drain found nothing deliverable (expired, or filtered); stay quiet

                $text = $null
                try { $text = ($out | ConvertFrom-Json).hookSpecificOutput.additionalContext } catch { }
                if (-not $text) { exit 0 }

                # stderr, then exit 2. That pair IS the delivery.
                [Console]::Error.WriteLine($text)
                exit 2
            }
        }
        Start-Sleep -Seconds $PollSeconds
    }
}
catch {
    exit 0
}
exit 0
