# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Shared by the harness hooks: read the hook input, and find the session's own directory in it.

.DESCRIPTION
    WHY THIS EXISTS. The desktop app starts a worktree session's CLI with
    `--project-config-root <primary checkout>`. Measured 2026-10-12 in a fixture launched with that
    flag (korus#220 records it): a hook runs with its working directory, `$env:CLAUDE_PROJECT_DIR`
    and `git rev-parse --show-toplevel` all naming the PRIMARY. Only the `cwd` field of the JSON on
    stdin names the worktree the session is in.

    Seen live 2026-10-13: this repository's announce hook told a session in a worktree to announce
    itself as "<primary> (main)". Every hook that asks git, `$PWD` or CLAUDE_PROJECT_DIR where it is
    gets the same wrong answer.

    THE CWD IS WHERE THE SESSION IS NOW, NOT WHERE IT STARTED. A session that runs `cd` moves its
    `cwd`, and a hook that followed it would answer for whatever directory the session stands in: a
    sibling's mail box, a sibling's announcement, another repository's steering note. So the `cwd` is
    trusted only as far as two checks allow (the Lander's verdict on korus#223):

      * SAME REPOSITORY. The `cwd` must sit in a worktree whose git common dir is the common dir of
        the checkout the hook started in. A `cwd` in another repository, in no checkout, or under a
        `.git` that names no real git dir is not used.
      * THE SESSION'S OWN WORKTREE. The first hook a session runs, normally SessionStart, PINS the
        worktree its `cwd` names, keyed by session id, under <common dir>/mefor-coord/session-root/.
        A later `cwd` in a different worktree is a `cd`, and the hook answers for the pinned one.

    A `cwd` that fails either check falls back to the pin. With no pin to fall back to, it is a fault.

    So a hook reads its input with Read-CcxHookInput and then does ONE of two things:

      * Enter-CcxHookSession moves the hook into the session's directory, so every later git call,
        every `$PWD` read and every child script answers for the session. Use it where the hook asks
        git.
      * Resolve-CcxHookSession returns the same answer without moving. Use it where the hook only
        needs a path, such as a file under `.claude/`.

    Neither spawns git. The common dir is read from the `.git` file and the git dir's `commondir`,
    as git itself reads them, because steer-inject runs before every tool call.

    NO CWD IS NOT A FAULT. A payload with no `cwd` (an older harness, a hand-run test) leaves the
    hook where it started, which is the old behaviour. A payload that NAMES a cwd the hook cannot use,
    with no pin to fall back to, is a fault, and both functions return the reason so the caller can
    say it aloud. Falling back in silence is the defect this file exists to fix.

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
        A read that does meet it says so on stderr, so "no input" and "input still open" differ. It
        also sets $script:CcxHookInputTimedOut, and Resolve-CcxHookSession then reports a fault rather
        than "no cwd": a hook that fell back in silence would answer for the primary.
    #>
    param([int] $TimeoutMs = 2000)
    $script:CcxHookInputTimedOut = $false
    try {
        if (-not [Console]::IsInputRedirected) { return '' }
        $reader = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false))
        $read = $reader.ReadToEndAsync()
        if ($read.Wait($TimeoutMs)) { return $read.Result }
        [Console]::Error.WriteLine("[hook-input] stdin was still open after $TimeoutMs ms, so the hook read no input and answers for $($PWD.Path).")
        $script:CcxHookInputTimedOut = $true
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

        -Payload takes input already parsed, so a caller holding one does not parse it twice.
    #>
    param([string] $Text, [object] $Payload)
    $out = [pscustomobject]@{ Named = $false; Cwd = $null; Reason = '' }
    $payload = $Payload
    if ($null -eq $payload) {
        if ([string]::IsNullOrWhiteSpace($Text)) { return $out }
        try { $payload = $Text | ConvertFrom-Json -ErrorAction Stop } catch { return $out }
    }
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

function Get-CcxShortHash {
    # The first four bytes of SHA-256 over UTF-8 text, as eight hex digits: a fixed-length file-name key.
    param([string] $Text)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $bytes = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) }
    finally { $sha.Dispose() }
    return -join ($bytes[0..3] | ForEach-Object { $_.ToString('x2') })
}

function Test-CcxSayOnce {
    <#
      .SYNOPSIS
        $true when a throttled notice should be said now, and stamps it. One stamp per $Key.

      .DESCRIPTION
        A stamp younger than $Minutes keeps the notice quiet. A stamp dated in the future does not,
        or clock skew would silence it forever. A stamp that cannot be read or written answers $true:
        noise is the safe failure of a silencer.
    #>
    param([string] $Key, [string] $Dir, [int] $Minutes = 30)
    try {
        $stamp = Join-Path $Dir "$(Get-CcxShortHash $Key).stamp"
        $prev = Get-Item -LiteralPath $stamp -ErrorAction SilentlyContinue
        if ($prev) {
            $mins = ((Get-Date) - $prev.LastWriteTime).TotalMinutes
            if ($mins -ge 0 -and $mins -lt $Minutes) { return $false }
        }
        New-Item -ItemType Directory -Force -Path $Dir -ErrorAction Stop | Out-Null
        Set-Content -LiteralPath $stamp -Value ((Get-Date).ToString('o')) -Encoding ascii -ErrorAction Stop
    } catch { }
    return $true
}

function ConvertTo-CcxNormPath {
    # A full path with no trailing separator, so two spellings of one directory compare equal. A drive
    # root keeps its separator, because `C:` alone means the current directory on C.
    param([string] $Path)
    if ([string]::IsNullOrWhiteSpace($Path)) { return '' }
    try { $full = [System.IO.Path]::GetFullPath($Path) } catch { return '' }
    $trimmed = $full.TrimEnd('\', '/')
    if (-not $trimmed -or $trimmed -match '^[A-Za-z]:$') { return $full }
    return $trimmed
}

function Test-CcxSamePath {
    param([string] $A, [string] $B)
    $na = ConvertTo-CcxNormPath $A
    $nb = ConvertTo-CcxNormPath $B
    if (-not $na -or -not $nb) { return $false }
    $mode = if ($IsWindows) { [System.StringComparison]::OrdinalIgnoreCase } else { [System.StringComparison]::Ordinal }
    return [string]::Equals($na, $nb, $mode)
}

function Get-CcxWorktreeRoot {
    <#
      .SYNOPSIS
        The first directory at or above $Path that holds `.git`, or $null. Calls no git.

      .DESCRIPTION
        `.git` is a FILE in a linked worktree and a DIRECTORY in a primary checkout. $Path need not
        exist, so a file about to be created still finds the worktree it will land in.
    #>
    param([string] $Path)
    $at = ConvertTo-CcxNormPath $Path
    while ($at) {
        if (Test-Path -LiteralPath (Join-Path $at '.git')) { return $at }
        $parent = Split-Path -Parent $at
        if (-not $parent -or $parent -eq $at) { break }
        $at = $parent
    }
    return $null
}

function Get-CcxGitCommonDir {
    <#
      .SYNOPSIS
        The git common dir of the worktree rooted at $Root, or $null. Calls no git.

      .DESCRIPTION
        Read the way git reads it. `.git` is the git dir, or a file whose `gitdir:` line names it. The
        git dir's `commondir` file, when present, names the common dir relative to the git dir. A git
        dir with no HEAD is not one, so an empty `.git` file or a stray `.git` directory gives $null.
    #>
    param([string] $Root)
    try {
        if (-not $Root) { return $null }
        $dotGit = Join-Path $Root '.git'
        if (Test-Path -LiteralPath $dotGit -PathType Container) { $gitDir = $dotGit }
        elseif (Test-Path -LiteralPath $dotGit -PathType Leaf) {
            $line = [string](Get-Content -LiteralPath $dotGit -TotalCount 1 -ErrorAction Stop)
            if ($line -notmatch '^gitdir:\s*(.+?)\s*$') { return $null }
            $gitDir = $Matches[1]
            if (-not [System.IO.Path]::IsPathRooted($gitDir)) { $gitDir = Join-Path $Root $gitDir }
        }
        else { return $null }
        if (-not (Test-Path -LiteralPath (Join-Path $gitDir 'HEAD') -PathType Leaf)) { return $null }
        $common = $gitDir
        $pointer = Join-Path $gitDir 'commondir'
        if (Test-Path -LiteralPath $pointer -PathType Leaf) {
            $c = ([string](Get-Content -LiteralPath $pointer -TotalCount 1 -ErrorAction Stop)).Trim()
            if ($c) {
                if (-not [System.IO.Path]::IsPathRooted($c)) { $c = Join-Path $gitDir $c }
                $common = $c
            }
        }
        $norm = ConvertTo-CcxNormPath $common
        if (-not $norm -or -not (Test-Path -LiteralPath $norm -PathType Container)) { return $null }
        return $norm
    }
    catch { return $null }
}

function Resolve-CcxHookSession {
    <#
      .SYNOPSIS
        Which directory this hook should answer for. Moves nothing.

      .DESCRIPTION
        Returns Named, Dir, Root, Reason, Note, SessionId, Event and Payload, from ONE parse.

          Dir     the directory to answer for, or $null to stay where the hook started.
          Root    the worktree root Dir sits in; $null with Dir.
          Reason  set only when the input NAMED a cwd and Dir is $null: the fault to say aloud.
          Note    set when Dir is the pinned worktree and not the `cwd`: why the `cwd` was not used.
          Pinned  the worktree the session started in, when a pin records it; otherwise $null.

        The header gives the two checks and the pin. $StartDir is where the hook started, and its
        repository is the one this hook serves. A hook started outside every checkout has no
        repository to compare with and nowhere to keep a pin, so it takes any usable `cwd`, as before.
    #>
    param(
        [string] $Text,
        [string] $StartDir = (Get-Location).ProviderPath,
        # Read the pin, never write it. For a hook that promises to write nowhere but its own store
        # (mail-drain) or runs before every tool call (steer-inject); the SessionStart hooks write it.
        [switch] $ReadOnly,
        # A `cwd` that exists but sits in no checkout is answered for as it is, with no Root, rather
        # than as a fault. For mail-drain, whose -AnchorRepo case is exactly that.
        [switch] $AllowOutside
    )
    $out = [pscustomobject]@{
        Named = $false; Dir = $null; Root = $null; Reason = ''; Note = ''
        SessionId = ''; Event = ''; Payload = $null; Pinned = $null
    }
    # Stdin still open at the bound is not "no cwd": falling back in silence would answer for where
    # the hook started, the primary under the desktop app.
    if ([string]::IsNullOrWhiteSpace($Text) -and $script:CcxHookInputTimedOut) {
        $out.Named = $true
        $out.Reason = 'the hook input was still open when the hook stopped waiting for it, so it names no cwd'
        return $out
    }
    if (-not [string]::IsNullOrWhiteSpace($Text)) {
        try { $out.Payload = $Text | ConvertFrom-Json -ErrorAction Stop } catch { $out.Payload = $null }
    }
    # Through PSObject.Properties, because a caller under Set-StrictMode throws on a missing member.
    $source = ''
    if ($out.Payload -is [pscustomobject]) {
        $props = $out.Payload.PSObject.Properties
        if ($props['session_id']) { $out.SessionId = [string]$props['session_id'].Value }
        if ($props['hook_event_name']) { $out.Event = [string]$props['hook_event_name'].Value }
        if ($props['source']) { $source = [string]$props['source'].Value }
    }

    $p = Get-CcxHookPayloadCwd -Payload $out.Payload
    $out.Named = $p.Named
    if (-not $p.Named) { return $out }

    $startCommon = Get-CcxGitCommonDir (Get-CcxWorktreeRoot $StartDir)

    # The candidate: the `cwd`, if it sits in a real worktree of the repository this hook serves.
    $why = $p.Reason
    $root = $null
    $outside = $false
    if (-not $why) {
        $root = Get-CcxWorktreeRoot $p.Cwd
        if (-not $root) {
            $outside = $true
            $why = "the hook input names cwd $($p.Cwd), which is inside no checkout"
        }
        else {
            $common = Get-CcxGitCommonDir $root
            if (-not $common) { $why = "the hook input names cwd $($p.Cwd), whose .git names no git directory" }
            elseif ($startCommon -and -not (Test-CcxSamePath $common $startCommon)) {
                $why = "the hook input names cwd $($p.Cwd), which is in another repository"
            }
        }
        if ($why) { $root = $null }
    }

    # The pin: the worktree this session started in. Only where there is a repository to keep it in
    # and a session id to key it by. A pin naming a worktree of another repository, or one since
    # removed, is ignored.
    $pinFile = ''
    $pinned = $null
    if ($startCommon -and $out.SessionId) {
        $pinFile = Join-Path $startCommon "mefor-coord/session-root/$(Get-CcxShortHash $out.SessionId)"
        try {
            if (Test-Path -LiteralPath $pinFile -PathType Leaf) {
                $saved = ([string](Get-Content -LiteralPath $pinFile -TotalCount 1 -ErrorAction Stop)).Trim()
                $savedCommon = Get-CcxGitCommonDir $saved
                if ($savedCommon -and (Test-CcxSamePath $savedCommon $startCommon)) { $pinned = ConvertTo-CcxNormPath $saved }
            }
        } catch { $pinned = $null }
    }

    # A SessionStart that STARTS the process (startup, resume, or no source given) names where the
    # session starts, so it writes the pin. A SessionStart from /clear or /compact fires wherever a
    # `cd` left the cwd, and so does every other event: those write a pin only where none exists, for
    # a session that predates the pin or whose SessionStart did not run.
    $launch = ($out.Event -eq 'SessionStart') -and ($source -notin @('clear', 'compact'))
    if (-not $ReadOnly -and $root -and $pinFile -and ($launch -or -not $pinned)) {
        try {
            $pinDir = Split-Path -Parent $pinFile
            New-Item -ItemType Directory -Force -Path $pinDir -ErrorAction Stop | Out-Null
            # Written beside the pin and renamed over it, so a hook reading at the same moment sees
            # the old pin or the new one, never a truncated file.
            $tmp = "$pinFile.$PID.tmp"
            Set-Content -LiteralPath $tmp -Value $root -Encoding utf8 -ErrorAction Stop
            Move-Item -LiteralPath $tmp -Destination $pinFile -Force -ErrorAction Stop
            $pinned = $root
            # One small file per session ever started, so SessionStart sweeps those a month old.
            if ($out.Event -eq 'SessionStart') {
                $cutoff = (Get-Date).AddDays(-30)
                Get-ChildItem -LiteralPath $pinDir -File -ErrorAction SilentlyContinue |
                    Where-Object { $_.LastWriteTime -lt $cutoff } |
                    Remove-Item -Force -ErrorAction SilentlyContinue
            }
        } catch { }
    }

    $out.Pinned = $pinned
    if ($root -and (-not $pinned -or (Test-CcxSamePath $root $pinned))) {
        $out.Dir = $p.Cwd
        $out.Root = $root
        return $out
    }
    if ($pinned) {
        $out.Dir = $pinned
        $out.Root = $pinned
        $out.Note = if ($why) { "$why; this hook answers for $pinned, the worktree the session started in" }
                    else { "the hook input names cwd $($p.Cwd), outside the worktree the session started in; this hook answers for $pinned" }
        return $out
    }
    # Checked AFTER the pin, so a pinned session that ran `cd` into a scratch directory keeps its own
    # worktree; only a session with nothing pinned is answered for where it stands.
    if ($outside -and $AllowOutside) {
        $out.Dir = $p.Cwd
        return $out
    }
    $out.Reason = $why
    return $out
}

function Enter-CcxHookSession {
    <#
      .SYNOPSIS
        Resolve-CcxHookSession, then move into its Dir. Returns the resolution.

      .DESCRIPTION
        PowerShell starts native children in the current location, so a git call or a child pwsh
        launched after this answers for the session too. A Dir it cannot enter becomes the Reason.
    #>
    param([string] $Text, [switch] $ReadOnly)
    $s = Resolve-CcxHookSession -Text $Text -ReadOnly:$ReadOnly
    if ($s.Dir) {
        try { Set-Location -LiteralPath $s.Dir -ErrorAction Stop }
        catch {
            $s.Reason = "the hook could not enter $($s.Dir) ($($_.Exception.Message))"
            $s.Dir = $null
            $s.Root = $null
            $s.Note = ''
        }
    }
    return $s
}
