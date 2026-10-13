# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Shared by the harness hooks: read the hook input, and find the session's own directory in it.

.DESCRIPTION
    WHY THIS EXISTS. The desktop app starts a worktree session's CLI with
    `--project-config-root <primary checkout>`. Measured 2026-10-12: under that flag a hook runs with
    its working directory, `$env:CLAUDE_PROJECT_DIR` and `git rev-parse --show-toplevel` all naming
    the PRIMARY. Only the `cwd` field of the JSON on stdin names the worktree the session is in.

    Across MessageFoundry worktree transcripts, session-context.ps1 printed "This chat's worktree:
    <primary>" 410 times against 48 for a worktree. Every hook that asks git, `$PWD` or
    CLAUDE_PROJECT_DIR where it is gets the same wrong answer.

    So a hook reads its input with Read-CcxHookInput and then does ONE of two things:

      * Enter-CcxHookCwd moves the hook into the session's directory, so every later git call, every
        `$PWD` read and every child script answers for the session. Use it where the hook asks git.
      * Get-CcxHookWorktree returns the worktree root without calling git. Use it where the hook only
        needs a path, such as a file under `.claude/`.

    NO CWD IS NOT A FAULT. A payload with no `cwd` (an older harness, a hand-run test) leaves the
    hook where it started, which is the old behaviour. A payload that NAMES a cwd the hook cannot use
    is a fault, and both functions return the reason so the caller can say it aloud. Falling back in
    silence is the defect this file exists to fix.

    Dot-source it. It defines functions only and has no side effect on load.
#>

function Read-CcxHookInput {
    <#
      .SYNOPSIS
        The hook input on stdin as text, or '' when there is none.

      .DESCRIPTION
        Read as UTF-8 BYTES, not through [Console]::In. That reader decodes with the console code
        page, which mangles a non-ASCII `cwd` and sends the hook quietly back to its own directory.

        Guarded on IsInputRedirected, so a hook run by hand from a terminal does not wait for input.

        AND BOUNDED IN TIME. IsInputRedirected is True from an agent shell with no pipe at all
        (announce-session.ps1 measured it), and a caller that leaves stdin open would hang an
        unbounded read. The harness writes its JSON and closes the pipe, so it never meets the bound.
    #>
    param([int] $TimeoutMs = 2000)
    try {
        if (-not [Console]::IsInputRedirected) { return '' }
        $reader = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false))
        $read = $reader.ReadToEndAsync()
        if ($read.Wait($TimeoutMs)) { return $read.Result }
        return ''
    }
    catch { return '' }
}

function Get-CcxHookPayloadCwd {
    <#
      .SYNOPSIS
        What the hook input says about its directory: Named, Cwd and Reason.

      .DESCRIPTION
        Named is $false when the input names no cwd at all, which is not a fault. Cwd is the resolved
        directory when it exists. Reason says why a named cwd could not be used.
    #>
    param([string] $Text)
    $out = [pscustomobject]@{ Named = $false; Cwd = $null; Reason = '' }
    if ([string]::IsNullOrWhiteSpace($Text)) { return $out }
    try { $payload = $Text | ConvertFrom-Json -ErrorAction Stop } catch { return $out }
    if ($null -eq $payload -or $payload -isnot [pscustomobject] -or -not $payload.PSObject.Properties['cwd']) { return $out }
    $dir = [string]$payload.cwd
    if ([string]::IsNullOrWhiteSpace($dir)) { return $out }
    $out.Named = $true
    try {
        if (-not (Test-Path -LiteralPath $dir -PathType Container)) {
            $out.Reason = "the hook input names cwd $dir, which does not exist"
            return $out
        }
        $out.Cwd = (Resolve-Path -LiteralPath $dir -ErrorAction Stop).ProviderPath
    }
    catch { $out.Reason = "the hook input names cwd $dir, which could not be resolved ($($_.Exception.Message))" }
    return $out
}

function Get-CcxHookWorktree {
    <#
      .SYNOPSIS
        The worktree root the hook input's `cwd` sits in: Named, Root and Reason.

      .DESCRIPTION
        Walks up from `cwd` to the first directory holding `.git`: a FILE in a linked worktree, a
        DIRECTORY in a primary checkout. It calls no git, so it costs nothing on a hot path.
    #>
    param([string] $Text)
    $p = Get-CcxHookPayloadCwd -Text $Text
    $out = [pscustomobject]@{ Named = $p.Named; Root = $null; Reason = $p.Reason }
    if (-not $p.Cwd) { return $out }
    $at = $p.Cwd
    while ($at) {
        if (Test-Path -LiteralPath (Join-Path $at '.git')) { $out.Root = $at; return $out }
        $parent = Split-Path -Parent $at
        if (-not $parent -or $parent -eq $at) { break }
        $at = $parent
    }
    $out.Reason = "the hook input names cwd $($p.Cwd), which is inside no checkout"
    return $out
}

function Enter-CcxHookCwd {
    <#
      .SYNOPSIS
        Move into the directory the hook input names. Returns '' or the reason it could not.

      .DESCRIPTION
        Moves into `cwd` itself, not a root walked up from it, so git resolves the worktree exactly
        as it would in the session. A hook that keys anything on `$PWD` then keys it on the session.

        PowerShell starts native children in the current location, so a git call or a child pwsh
        launched after this answers for the session too.

        '' means the hook is where it should be, or the input named no cwd and the hook stays put.
    #>
    param([string] $Text)
    $p = Get-CcxHookPayloadCwd -Text $Text
    if (-not $p.Cwd) { return $p.Reason }
    try { Set-Location -LiteralPath $p.Cwd -ErrorAction Stop }
    catch { return "the hook could not enter cwd $($p.Cwd) ($($_.Exception.Message))" }
    return ''
}
