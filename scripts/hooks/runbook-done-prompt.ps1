# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    PostToolUse hook on Bash and PowerShell: when a command has just opened a pull request that
    names a runbook batch, put the read_batch.py --done command in the session's context. It never
    blocks.

.DESCRIPTION
    WHY IT EXISTS. Owner instruction 2026-11-28, in a Manager's chat: nothing reminded a session to
    run `read_batch.py --done NN --state "PR OPEN"` when it opened a batch's pull request, so the
    owner's runbook dashboard went stale. runbook-take-prompt.ps1 covers the --take half; this covers
    the --done half. The work is done by runbook_done_prompt.py beside it, whose header says what it
    matches and what it prints.

    WHY PostToolUse. That is the event that sees both the command and its result, so a create that
    failed says nothing. A PostToolUse hook's plain stdout does not reach the model; the one object
    it prints, {"hookSpecificOutput":{"hookEventName":"PostToolUse","additionalContext":...}}, does.
    That is the shape mail-drain.ps1 emits on its events.

    IT NEVER BLOCKS AND NEVER FAILS. Every path exits 0, and it never prints a `decision`.

    FAST ON EVERY OTHER COMMAND. It runs after every Bash and PowerShell call, so it reads the input
    and stops at once unless the text holds "pr create" or "/pulls". Only then does it start Python.
    The shim's own pwsh start is the cost every call still pays.

    FAIL QUIET. No interpreter, a helper that runs past $HelperTimeoutMs, input it cannot read, or
    helper output that is not the one object: nothing on stdout. A reason goes to stderr, which Claude
    Code keeps in its debug log at exit 0.

    WHICH WORKTREE. The session's own, as _hookinput.ps1 resolves it. When it refuses the `cwd`, the
    helper still reads the command, but reads no body file and no claims, since it cannot tell whose
    worktree they are in.

    IT READS NO WORKBOOK AND MAKES NO NETWORK OR gh CALL, and it writes no file.

    OVERRIDES: MEFOR_RUNBOOK_PYTHON (the interpreter, shared with runbook-take-prompt.ps1),
    MEFOR_RUNBOOK_READ_BATCH (the read_batch.py the printed command names). Opt out with
    MEFOR_RUNBOOK_PROMPT = 'off', the same switch as runbook-take-prompt.ps1.
#>
[CmdletBinding()]
param()

$ErrorActionPreference = 'Stop'

$HelperTimeoutMs = 8000

function Write-Reason([string]$Text) {
    try { [Console]::Error.WriteLine("runbook-done-prompt: $Text") } catch { }
}

try {
    # The workbook and read_batch.py live on the owner's machine; a cloud session has neither.
    if ($env:CLAUDE_CODE_REMOTE -eq 'true') { exit 0 }
    if (([string]$env:MEFOR_RUNBOOK_PROMPT).Trim().ToLowerInvariant() -eq 'off') { exit 0 }
    . (Join-Path $PSScriptRoot '_hookinput.ps1')
    $raw = Read-CcxHookInput
    # The cheap gate. JSON escapes nothing in these two strings, so the raw text is enough.
    if ($raw -notmatch '(?i)pr\s+create|/pulls') { exit 0 }

    $session = Resolve-CcxHookSession -Text $raw -ReadOnly
    if ([string]$session.Event -cne 'PostToolUse') { exit 0 }
    $sessionId = [string]$session.SessionId
    if ($sessionId -cnotmatch '\A[A-Za-z0-9_-]{1,100}\z') { $sessionId = '' }
    $root = ''
    if ($session.Reason) { Write-Reason "reading no body file or claims: $($session.Reason)" }
    elseif ($session.Root) { $root = [string]$session.Root }

    $home_ = [Environment]::GetFolderPath('UserProfile')
    $py = [string]$env:MEFOR_RUNBOOK_PYTHON
    if (-not $py) { $py = Join-Path $home_ '.claude-tools\py\Scripts\python.exe' }
    if (-not (Test-Path -LiteralPath $py -PathType Leaf)) {
        $cmd = Get-Command python -CommandType Application -EA SilentlyContinue | Select-Object -First 1
        if (-not $cmd) { Write-Reason "no interpreter at $py and none on PATH"; exit 0 }
        $runPy = [string]$cmd.Source
    }
    else { $runPy = $py }

    $readBatch = [string]$env:MEFOR_RUNBOOK_READ_BATCH
    if (-not $readBatch) {
        $cfg = [string]$env:CLAUDE_CONFIG_DIR
        if (-not $cfg) { $cfg = Join-Path $home_ '.claude' }
        $readBatch = Join-Path $cfg 'skills\batch\read_batch.py'
        if (-not (Test-Path -LiteralPath $readBatch -PathType Leaf)) { $readBatch = '<account skills dir>\batch\read_batch.py' }
    }

    $psi = [System.Diagnostics.ProcessStartInfo]::new($runPy)
    foreach ($a in @(
            '-I', (Join-Path $PSScriptRoot 'runbook_done_prompt.py'),
            '--worktree', $root, '--session', $sessionId,
            '--python', $py, '--read-batch', $readBatch,
            '--temp-dir', [System.IO.Path]::GetTempPath())) {
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
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $errTask = $proc.StandardError.ReadToEndAsync()
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($raw)
    try { $proc.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length) } catch { }
    try { $proc.StandardInput.Close() } catch { }
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
    # No decision key: nothing here blocks.
    $json = [ordered]@{
        hookSpecificOutput = [ordered]@{ hookEventName = 'PostToolUse'; additionalContext = $obj['additionalContext'] }
    } | ConvertTo-Json -Compress -Depth 4 -EscapeHandling EscapeNonAscii
    [Console]::Out.Write($json)
}
catch {
    Write-Reason "nothing printed: $($_.Exception.Message)"
    exit 0
}
exit 0
