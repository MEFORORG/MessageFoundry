# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Shared by the harness hooks: read the hook input, and find the session's own worktree in it.

.DESCRIPTION
    ONE DESIGN, TWO COPIES. korus and the MessageFoundry engine each ship this file. Below the license
    lines the two copies are byte-identical; change both together.

    WHY THIS EXISTS. The desktop app starts a worktree session's CLI with
    `--project-config-root <primary checkout>`. Measured 2026-10-12 in a fixture launched with that
    flag (korus#220 records it): a hook runs with its working directory, `$env:CLAUDE_PROJECT_DIR`
    and `git rev-parse --show-toplevel` all naming the PRIMARY. Only the `cwd` field of the JSON on
    stdin names the worktree the session is in.

    THE CWD IS WHERE THE SESSION IS NOW, NOT WHERE IT STARTED. A session that runs `cd` moves its
    `cwd`. A hook that followed it would read a sibling's steering note, show a sibling's mail, or
    announce as the sibling. So this file is the ONE place the rule lives, and docs link here:

      1. SAME REPOSITORY. A `cwd` is a candidate only when its worktree's git common dir is the one
         of the checkout the hook started in (the START checkout). Another repository, no checkout,
         or a `.git` that names no real git dir is refused.
      2. A LAUNCH IS TRUSTED. A SessionStart from a startup or a resume (or with no source) fires
         where the session was launched, so its candidate `cwd` is the session's worktree, and it
         PINS it: <common dir>/ccx-session-root/<hash of the session id>.
      3. LATER EVENTS ANSWER FOR THE PIN. A `cwd` inside the pinned worktree is used as it is. One
         anywhere else is a `cd`, and the hook answers for the pinned worktree instead.
      4. WITH NO PIN, ONLY THE START CHECKOUT. An unpinned session's `cwd` is used only when it sits
         in the start checkout's own worktree. Anywhere else (a sibling, or the session's own linked
         worktree under the desktop app) is refused with a Reason, and the hook stays in the start
         checkout and says so. It never answers for a sibling it cannot tell from its own.
      5. /CLEAR AND /COMPACT NEVER PIN. Their SessionStart fires wherever a `cd` left the shell, and
         /clear mints a new session id (announce-session.ps1 records it), so a pin written there
         could name a sibling. Such a session follows rule 4 until its next startup or resume. That
         costs the desktop-app worktree session its own answers after a /clear, and it is the safe
         side: loud and wrong-checkout-free, never quietly the sibling.

    WHO MAY WRITE A PIN. Only a hook that is not -ReadOnly, and only in a clone that opted in: the
    clone holds `ccx.config.json` at its primary checkout or at the start checkout, or this file
    itself lives in a worktree of that clone (the repository ships the hook). So a user-scope copy
    leaves no file in an unrelated repository. Reading a pin needs no opt-in.

    A PIN IS REPLACED ATOMICALLY. It is written to a unique temp file beside it and moved over it
    with [System.IO.File]::Move(..., $true), which replaces in one rename on the same volume, so a
    reader sees the old pin or the new one and never none. Readers open it sharing delete, so a
    reader never blocks the rename. A move that keeps failing deletes the old pin rather than keep
    it, so the session falls to rule 4, never to the previous run's worktree. Temp files older than
    ten minutes and pins older than thirty days are pruned at each pin write.

    NO CWD IS NOT A FAULT. A payload with no `cwd` (an older harness, a hand-run test) leaves the
    hook where it started. Stdin still open at the read's bound IS one, because nothing says it
    would have named no `cwd`. A refused `cwd` is a fault too, and both entry points return the
    Reason so the caller can say it aloud. Falling back in silence is the defect this file exists
    to fix.

    A hook reads its input with Read-CcxHookInput and then does ONE of two things:

      * Enter-CcxHookSession moves the hook into the session's directory, so every later git call,
        every `$PWD` read and every child script answers for the session. Use it where the hook
        asks git.
      * Resolve-CcxHookSession returns the same answer without moving. Use it where the hook only
        needs a path, such as a file under `.claude/`.

    Neither spawns git. The common dir is read from the `.git` file and the git dir's `commondir`,
    as git itself reads them, because steer-inject runs before every tool call.

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
        A read that does meet it says so on stderr and sets $script:CcxHookInputTimedOut, and
        Resolve-CcxHookSession then reports a fault rather than "no cwd".
    #>
    param([int] $TimeoutMs = 2000)
    $script:CcxHookInputTimedOut = $false
    try {
        if (-not [Console]::IsInputRedirected) { return '' }
        $reader = [System.IO.StreamReader]::new([Console]::OpenStandardInput(), [System.Text.UTF8Encoding]::new($false))
        $read = $reader.ReadToEndAsync()
        if ($read.Wait($TimeoutMs)) { return $read.Result }
        [Console]::Error.WriteLine("[hook-input] stdin was still open after $TimeoutMs ms, so the hook read no input.")
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
    # The first $Bytes bytes of SHA-256 over UTF-8 text, as hex: a fixed-length file-name key.
    param([string] $Text, [int] $Bytes = 4)
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $hash = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($Text)) }
    finally { $sha.Dispose() }
    return -join ($hash[0..($Bytes - 1)] | ForEach-Object { $_.ToString('x2') })
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

function Read-CcxSessionPin {
    # The first line of a pin, or $null. Opened sharing delete, so a writer's rename over it never
    # waits on this reader.
    param([string] $Path)
    try {
        $share = [System.IO.FileShare]::ReadWrite -bor [System.IO.FileShare]::Delete
        $fs = [System.IO.FileStream]::new($Path, [System.IO.FileMode]::Open, [System.IO.FileAccess]::Read, $share)
        $reader = [System.IO.StreamReader]::new($fs, [System.Text.UTF8Encoding]::new($false))
        try { return ([string]$reader.ReadLine()).Trim() }
        finally { $reader.Dispose() }
    }
    catch { return $null }
}

function Write-CcxSessionPin {
    <#
      .SYNOPSIS
        Replace the pin at $Path with $Root in one rename. Returns $true when the pin names $Root.

      .DESCRIPTION
        The header says why. A move that keeps failing removes the old pin and tries once more, so
        a pin whose own state blocked the rename (read-only, say) is still replaced. A pin that
        already names $Root counts as written: a concurrent SessionStart hook put it there, and
        deleting it would leave the session with none. Any other failure leaves no pin, never the
        old one. Pruning runs apart from the write, so a prune that throws cannot undo a pin.
    #>
    param([string] $Path, [string] $Root)
    $dir = Split-Path -Parent $Path
    $tmp = Join-Path $dir ('{0}.{1}.{2}.tmp' -f (Split-Path -Leaf $Path), $PID, [guid]::NewGuid().ToString('N').Substring(0, 8))
    $written = $false
    try {
        New-Item -ItemType Directory -Force -Path $dir -ErrorAction Stop | Out-Null
        [System.IO.File]::WriteAllText($tmp, $Root, [System.Text.UTF8Encoding]::new($false))
        foreach ($attempt in 1..8) {
            try { [System.IO.File]::Move($tmp, $Path, $true); $written = $true; break }
            catch { Start-Sleep -Milliseconds 25 }
        }
        if (-not $written -and -not (Test-CcxSamePath (Read-CcxSessionPin $Path) $Root)) {
            Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
            try { [System.IO.File]::Move($tmp, $Path, $true); $written = $true } catch { }
        }
    }
    catch { }
    finally { Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue }
    if (-not $written) {
        if (Test-CcxSamePath (Read-CcxSessionPin $Path) $Root) { $written = $true }
        # Never keep the previous run's pin: with none, the session falls to rule 4 of the header.
        else { Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue }
    }
    try {
        # Pruned here because a pin is written about once per session. A temp file ten minutes old
        # belongs to no live writer; a pin thirty days old to no live session.
        $now = Get-Date
        Get-ChildItem -LiteralPath $dir -File -ErrorAction SilentlyContinue |
            Where-Object { ($_.Name -like '*.tmp' -and $_.LastWriteTime -lt $now.AddMinutes(-10)) -or
                           ($_.Name -notlike '*.tmp' -and $_.LastWriteTime -lt $now.AddDays(-30)) } |
            Remove-Item -Force -ErrorAction SilentlyContinue
    }
    catch { }
    return $written
}

function Test-CcxPinOptIn {
    # Whether a pin may be written in the clone whose start checkout is $StartRoot. See the header.
    param([string] $StartRoot, [string] $StartCommon)
    if (Test-Path -LiteralPath (Join-Path $StartRoot 'ccx.config.json') -PathType Leaf) { return $true }
    if ((Split-Path -Leaf $StartCommon) -eq '.git' -and
        (Test-Path -LiteralPath (Join-Path (Split-Path -Parent $StartCommon) 'ccx.config.json') -PathType Leaf)) { return $true }
    $own = Get-CcxGitCommonDir (Get-CcxWorktreeRoot $PSScriptRoot)
    return [bool]($own -and (Test-CcxSamePath $own $StartCommon))
}

function Resolve-CcxHookSession {
    <#
      .SYNOPSIS
        Which directory this hook should answer for. Moves nothing.

      .DESCRIPTION
        Returns these, from ONE parse of the input. The header gives the rules.

          Dir        the directory to answer for, or $null to stay where the hook started.
          Root       the worktree root Dir sits in; $null with Dir, or for a -AllowOutside answer.
          Source     'cwd', 'pin', or 'start' when Dir is $null.
          Reason     set when the input NAMED a cwd and this refused it: the fault to say aloud.
          Note       set when Dir is the pinned worktree and not the `cwd`: why the `cwd` was not used.
          Pinned     the worktree the pin records after this call, or $null.
          Named, SessionId, Event, Payload  what the input said.

        A hook started outside every checkout has no repository to check a `cwd` against and nowhere
        to pin. It stays where it started, in silence, unless the `cwd` does not exist (a Reason) or
        -AllowOutside takes a `cwd` that sits in no checkout.
    #>
    param(
        [string] $Text,
        [string] $StartDir = (Get-Location).ProviderPath,
        # Read the pin, never write it. For a hook that runs before every tool call, promises to write
        # nowhere but its own store, or is a diagnostic run.
        [switch] $ReadOnly,
        # An unpinned session's `cwd` that sits in no checkout is answered for as it is, with no Root,
        # rather than as a fault. For mail-drain, whose -AnchorRepo case is exactly that.
        [switch] $AllowOutside
    )
    $out = [pscustomobject]@{
        Named = $false; Dir = $null; Root = $null; Source = 'start'; Reason = ''; Note = ''
        SessionId = ''; Event = ''; Payload = $null; Pinned = $null
    }
    $timedOut = [bool](Get-Variable -Name CcxHookInputTimedOut -Scope Script -ValueOnly -ErrorAction Ignore)
    if ([string]::IsNullOrWhiteSpace($Text) -and $timedOut) {
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

    $startRoot = Get-CcxWorktreeRoot $StartDir
    $startCommon = Get-CcxGitCommonDir $startRoot
    if (-not $startCommon) {
        # No repository to check against and nowhere to pin. A `cwd` in some checkout is not this
        # session's own (it launched in none), so the hook stays put, in silence, as it did before
        # it read any `cwd`. A missing `cwd` is still a fault, and -AllowOutside still takes one
        # that sits in no checkout.
        if ($p.Reason) { $out.Reason = $p.Reason }
        elseif ($p.Cwd -and $AllowOutside -and -not (Get-CcxWorktreeRoot $p.Cwd)) { $out.Dir = $p.Cwd; $out.Source = 'cwd' }
        return $out
    }

    $launch = ($out.Event -eq 'SessionStart') -and ($source -notin @('clear', 'compact'))
    $pinFile = ''
    if ($out.SessionId) { $pinFile = Join-Path $startCommon "ccx-session-root/$(Get-CcxShortHash $out.SessionId -Bytes 8)" }

    # The pin, read only where it decides: a launch replaces it below. A pin naming no worktree root
    # of this repository (removed since, or forged to point elsewhere) is not this session's answer.
    $pinned = $null
    if ($pinFile -and -not $launch) {
        $saved = Read-CcxSessionPin $pinFile
        if ($saved -and (Test-CcxSamePath (Get-CcxWorktreeRoot $saved) $saved)) {
            $savedCommon = Get-CcxGitCommonDir $saved
            if ($savedCommon -and (Test-CcxSamePath $savedCommon $startCommon)) { $pinned = ConvertTo-CcxNormPath $saved }
        }
    }

    # The candidate: the `cwd`, if it sits in a real worktree of this repository (rule 1).
    $why = $p.Reason
    $root = $null
    $outside = $false
    if ($p.Cwd) {
        $root = Get-CcxWorktreeRoot $p.Cwd
        if (-not $root) {
            $outside = $true
            $why = "the hook input names cwd $($p.Cwd), which is inside no checkout"
        }
        else {
            # A root already checked (the pin's, or the start checkout's) needs no second read.
            $common = if ((Test-CcxSamePath $root $pinned) -or (Test-CcxSamePath $root $startRoot)) { $startCommon }
                      else { Get-CcxGitCommonDir $root }
            if (-not $common) { $why = "the hook input names cwd $($p.Cwd), whose .git names no git directory" }
            elseif (-not (Test-CcxSamePath $common $startCommon)) { $why = "the hook input names cwd $($p.Cwd), which is in another repository" }
        }
        if ($why) { $root = $null }
    }

    # Rule 2. A launch that does not write a pin removes any it finds: a refused or unnamed `cwd`,
    # or a clone no longer opted in. The previous run's would otherwise answer, in silence, for
    # every later event. Removing writes no new file, so it needs no opt-in.
    if ($launch -and $pinFile -and -not $ReadOnly) {
        if ($root -and (Test-CcxPinOptIn $startRoot $startCommon)) {
            if (Write-CcxSessionPin -Path $pinFile -Root $root) { $pinned = $root }
        }
        else { Remove-Item -LiteralPath $pinFile -Force -ErrorAction SilentlyContinue }
    }
    $out.Pinned = $pinned

    if (-not $p.Named) { return $out }
    $own = if ($pinned) { $pinned } else { $startRoot }
    if ($root -and ($launch -or (Test-CcxSamePath $root $own))) {
        $out.Dir = $p.Cwd; $out.Root = $root; $out.Source = 'cwd'
        return $out
    }
    if ($pinned) {
        $out.Dir = $pinned; $out.Root = $pinned; $out.Source = 'pin'
        $out.Note = if ($why) { "$why; this hook answers for $pinned, the worktree the session started in" }
                    else { "the hook input names cwd $($p.Cwd), outside the worktree the session started in; this hook answers for $pinned" }
        return $out
    }
    if ($outside -and $AllowOutside) {
        $out.Dir = $p.Cwd; $out.Source = 'cwd'
        return $out
    }
    $out.Reason = if ($why) { $why }
                  else { "no pin records that this session started in $root, so the hook stays in $startRoot rather than follow the hook input's cwd $($p.Cwd)" }
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
            $s.Source = 'start'
            $s.Note = ''
        }
    }
    return $s
}
