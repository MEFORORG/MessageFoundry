# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    SessionStart and UserPromptSubmit hook: when this seat holds claims on a batch's rows and the
    runbook workbook reads FREE for that batch, or names someone else, put the read_batch.py --take
    command in the session's context. It never blocks.

.DESCRIPTION
    WHY IT EXISTS. Owner decision 2026-11-27, in a Manager's chat ("Stop hook + Lander"). A session
    that picks up a batch through a handoff, /carry-on or a respawn never reads the /batch skill's
    instruction to run read_batch.py --take, so the owner's runbook dashboard reads FREE for a batch
    somebody holds. This hook is the half that tells the session; the work is done by
    runbook_take_prompt.py beside it, whose header says what it reads and whose claims count.

    WHY THESE EVENTS AND NOT STOP. The owner's aim is to prompt the session itself. On Stop, only a
    block decision puts text in front of the model, and a systemMessage reaches the user alone.
    SessionStart and UserPromptSubmit add a hook's exit-0 output to the model's context without
    blocking (scripts/hooks/precompact-reprime.ps1 records the event list). SessionStart is the one
    that catches a respawn or a /carry-on seat; UserPromptSubmit catches a claim taken mid-session.
    The helper's per-batch cooldown keeps a prompt from repeating what an earlier one said.

    IT NEVER BLOCKS AND NEVER FAILS. Every path exits 0, and it never prints a `decision`. The only
    stdout is one {"hookSpecificOutput":{"hookEventName":...,"additionalContext":...}} object, the
    shape mail-drain.ps1 emits on these events. Any other event prints nothing.

    FAIL QUIET. No workbook, no openpyxl interpreter, no claims, a locked or unreadable file, a
    helper that runs past $HelperTimeoutMs, or output that is not that one object: nothing on
    stdout. The reason, where there is one, goes to stderr, which Claude Code keeps in its debug log
    at exit 0, so a hook that is always quiet for a fault can still be told from a healthy one.

    WHICH WORKTREE. The session's own, as _hookinput.ps1 resolves it from the hook input, and
    nothing else: never the hook's working directory, which names the PRIMARY under the desktop app,
    and never a `cwd` the resolver refused. A session that has `cd`-ed into a sibling worktree or
    another repository would otherwise be told to take the sibling's batch, so a refusal is quiet.

    OVERRIDES, for a machine laid out differently: MEFOR_RUNBOOK_PYTHON (an interpreter with
    openpyxl), MEFOR_RUNBOOK_WORKBOOK (the .xlsx), MEFOR_RUNBOOK_READ_BATCH (the read_batch.py the
    printed command names). Opt out with MEFOR_RUNBOOK_PROMPT = 'off'.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

# Well inside the installer row's 20 s timeout: pwsh start-up and the input read come before it.
$HelperTimeoutMs = 12000

function Write-Reason([string]$Text) {
    try { [Console]::Error.WriteLine("runbook-take-prompt: $Text") } catch { }
}

try {
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') { exit 0 }
    if (([string]$env:MEFOR_RUNBOOK_PROMPT).Trim().ToLowerInvariant() -eq 'off') { exit 0 }
    . (Join-Path $PSScriptRoot '_hookinput.ps1')
    $raw = Read-CcxHookInput
    $session = Resolve-CcxHookSession -Text $raw -ReadOnly
    $sessionId = [string]$session.SessionId
    # \z, not $: $ also matches before a final newline.
    if ($sessionId -cnotmatch '\A[A-Za-z0-9_-]{1,100}\z') { exit 0 }
    # Only the two events whose output reaches the model without blocking; see the header.
    $event = [string]$session.Event
    if ($event -cnotin @('SessionStart', 'UserPromptSubmit')) { exit 0 }

    # The resolver's answer only; the header's WHICH WORKTREE says why there is no fallback.
    $root = $session.Root
    if ($session.Reason) { Write-Reason "no worktree to answer for: $($session.Reason)"; exit 0 }
    if (-not $root) { exit 0 }

    $home_ = [Environment]::GetFolderPath('UserProfile')
    $py = [string]$env:MEFOR_RUNBOOK_PYTHON
    if (-not $py) { $py = Join-Path $home_ '.claude-tools\py\Scripts\python.exe' }
    if (-not (Test-Path -LiteralPath $py -PathType Leaf)) { Write-Reason "no interpreter at $py"; exit 0 }
    $workbook = [string]$env:MEFOR_RUNBOOK_WORKBOOK
    if (-not $workbook) { $workbook = Join-Path $home_ 'OneDrive\Desktop\MEFOR\MEFOR-backlog-runbook.xlsx' }
    if (-not (Test-Path -LiteralPath $workbook -PathType Leaf)) { exit 0 }

    # The read_batch.py beside this account's /batch skill. With CLAUDE_CONFIG_DIR set, that root's
    # copy or nothing: another root's copy is another account's, and the /batch SKILL.md forbids it
    # because the copies drift. Unset, the default root's copy, else a placeholder.
    $readBatch = [string]$env:MEFOR_RUNBOOK_READ_BATCH
    if (-not $readBatch) {
        $cfg = [string]$env:CLAUDE_CONFIG_DIR
        if ($cfg) {
            $readBatch = Join-Path $cfg 'skills\batch\read_batch.py'
            if (-not (Test-Path -LiteralPath $readBatch -PathType Leaf)) { Write-Reason "no read_batch.py under $cfg"; exit 0 }
        }
        else {
            $readBatch = Join-Path $home_ '.claude\skills\batch\read_batch.py'
            if (-not (Test-Path -LiteralPath $readBatch -PathType Leaf)) { $readBatch = '<account skills dir>\batch\read_batch.py' }
        }
    }

    # The seat marker seat.ps1 -Declare writes, read in wiki-write-prompt.ps1's Get-Seat order: the
    # Codex state path when set, else .claude/, else $env:KORUS_SEAT. A plain label or nothing.
    $seat = ''
    try {
        $rel = if ($env:KORUS_AGENT -eq 'codex' -and $env:KORUS_STATE_REL) { "$env:KORUS_STATE_REL/seat.local.txt" } else { '.claude/seat.local.txt' }
        $marker = Join-Path $root $rel
        if (Test-Path -LiteralPath $marker -PathType Leaf) { $seat = [string](Get-Content -LiteralPath $marker -Raw) }
    }
    catch { }
    if (-not $seat.Trim()) { $seat = [string]$env:KORUS_SEAT }
    $seat = $seat.Trim().ToLowerInvariant()
    if ($seat -notmatch '^[a-z][a-z0-9-]{0,39}$') { $seat = '' }

    $psi = [System.Diagnostics.ProcessStartInfo]::new($py)
    foreach ($a in @(
            '-I', (Join-Path $PSScriptRoot 'runbook_take_prompt.py'),
            '--worktree', $root, '--session', $sessionId, '--seat', $seat,
            '--workbook', $workbook, '--python', $py, '--read-batch', $readBatch)) {
        $psi.ArgumentList.Add([string]$a)
    }
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
    $proc = [System.Diagnostics.Process]::Start($psi)
    $proc.StandardInput.Close()
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    if (-not $proc.WaitForExit($HelperTimeoutMs)) {
        try { $proc.Kill($true) } catch { }
        Write-Reason "the helper ran past $HelperTimeoutMs ms and was stopped"
        exit 0
    }
    $err = [string]$errTask.Result
    if ($err.Trim()) { try { [Console]::Error.WriteLine($err.Trim()) } catch { } }
    $out = [string]$outTask.Result
    if (-not $out.Trim()) { exit 0 }

    # Relay only the one object the helper is allowed to print.
    $obj = $out | ConvertFrom-Json -AsHashtable
    if ($obj -isnot [hashtable] -or $obj.Count -ne 1 -or $obj['additionalContext'] -isnot [string]) {
        Write-Reason 'the helper printed something other than one additionalContext object'
        exit 0
    }
    # The shape mail-drain.ps1 emits on these events. No decision key: nothing here blocks.
    $json = [ordered]@{
        hookSpecificOutput = [ordered]@{ hookEventName = $event; additionalContext = $obj['additionalContext'] }
    } | ConvertTo-Json -Compress -Depth 4 -EscapeHandling EscapeNonAscii
    [Console]::Out.Write($json)
}
catch {
    Write-Reason "nothing printed: $($_.Exception.Message)"
    exit 0
}
exit 0
