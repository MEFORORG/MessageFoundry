# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Definitions only: where fleet coordination state lives. Dot-source it; it does nothing on its own.

.DESCRIPTION
    WHY THIS FILE EXISTS. Until 2026-10 every coordination script built `<git-common-dir>/mefor-coord`
    by hand, about 36 copies of one expression. That put the seat registry, mail and claims under ONE
    clone on ONE PC, so a session on a second PC could neither see nor be seen. Measured 2026-10-21: a
    Manager on the second PC published its seat id and mail path on a pull request, and neither existed
    on this PC. docs/COORD-SHARED-ROOT.md is the design; this file is its one definition of "where".

    TWO ROOTS.
      LOCAL   <git-common-dir>/mefor-coord, always. Caches, per-session receipts, this machine's leases.
      SHARED  The cross-PC store. Resolved in this order, first hit wins:
                1. $env:MEFOR_COORD_ROOT, when set and not blank. For tests, one session, or a rollback.
                   Do NOT set it user-wide: it then applies to every repository, korus and the vault too.
                2. `shared_root = '<path>'` in <LOCAL>/root.toml. Per clone and inside .git, so each PC
                   names its own UNC path and nothing can commit it.
                3. LOCAL itself. With nothing configured, behaviour is exactly what it was before.

    WHICH KIND IS SHARED is $script:CoordSharedKinds, named once. Everything else is local. The class
    table in docs/COORD-SHARED-ROOT.md says why each kind falls where it does.

    root.toml TAKES A TOML LITERAL STRING ONLY (single quotes). A UNC path in a basic string ("...")
    means something else in TOML, because `\\` there is an escape. Rather than half-implement TOML, a
    value in any other form is a configuration ERROR, never a silent fallback to LOCAL: a fallback
    would split the fleet into two registries that each believe they are the only one.

    REACHABILITY. A dead SMB server does not answer "no"; it hangs a file call for up to the client's
    session timeout (60 s measured). Test-CoordRoot answers fast instead: a TCP connect to port 445
    with a short timeout, before any file call. A DOWN verdict is cached in <LOCAL>/coord-root-down.json
    for 60 s, so a dead share costs one timeout per minute per clone, not one per hook process.

    CONSTRAINTS, the same four config-roots.ps1 states, because hooks dot-source this:
      1. NO top-level param() block.
      2. NO assignment to a preference variable.
      3. NO I/O and NO pipeline output at load time.
      4. NEVER THROWS from a resolver function. Errors come back in the result's Error field. The two
         file helpers below are the one exception, by design: each stands in for a .NET call that
         throws, so after its retries it rethrows that call's own exception for the caller's catch.

    SMB SHARING VIOLATIONS. Measured on the share 2026-10-21: replacing a file by rename while another
    process read it failed 2 of 50 times with "Access to the path is denied.", and 56 of about 2,500
    reads failed with a sharing violation. Both clear in milliseconds. Move-CoordFileReplace and
    Read-CoordText retry exactly those, briefly and boundedly; a missing file is never retried. A
    writer must not use `Move-Item -Force` instead: it is delete-then-rename, so a reader can find the
    name missing in between.
    Its Python twin is scripts/coord/coord_root.py; tests/test_coord_root.py holds both to one answer.

.EXAMPLE
    . (Join-Path $PSScriptRoot 'coord-root.ps1')
    $r = Resolve-CoordDir -From $repo -Kind 'claims'
    if ($r.Error) { throw $r.Error }
#>

# The kinds that cross PCs. One list; the Python twin carries the same one and a test compares them.
$script:CoordSharedKinds = @('seats', 'mail', 'claims', 'alloc', 'handoffs', 'wiki', 'lanes', 'owner-log')

$script:CoordRootEnv = 'MEFOR_COORD_ROOT'
$script:CoordRootFile = 'root.toml'
$script:CoordDownFile = 'coord-root-down.json'
$script:CoordDownTtlSeconds = 60
$script:CoordProbeTimeoutMs = 1500

# The SMB retry: 8 tries, sleeping 25 ms and doubling, each sleep capped at 250 ms, so about 1.1 s in
# all. The Python twin carries the same numbers.
$script:CoordRetryTries = 8
$script:CoordRetryFirstMs = 25
$script:CoordRetryMaxSleepMs = 250
# ERROR_SHARING_VIOLATION and ERROR_LOCK_VIOLATION, as HRESULTs.
$script:CoordSharingHResults = @([int]0x80070020, [int]0x80070021)

# A TOML literal string, and nothing else, on a `shared_root` key. An optional trailing comment.
# ASCII space and tab only, never \s: .NET's \s and Python's differ on \x1c-\x1f and \x85, and the twins
# must give one answer.
$script:CoordRootLine = [regex]"\A[ \t]*shared_root[ \t]*=[ \t]*'([^']*)'[ \t]*(#.*)?\z"
$script:CoordBlankLine = [regex]'\A[ \t]*(#.*)?\z'
$script:CoordWs = [char[]]@(' ', "`t", "`r", "`n")

function ConvertFrom-CoordRootBytes {
    # UTF-16 with a BOM, UTF-8 with or without one, STRICTLY: Windows PowerShell 5.1 writes UTF-16 with
    # `>`, and an ANSI file with a non-ASCII path must be an error on both twins, not a guess on one.
    param([byte[]]$Raw)
    if ($Raw.Length -ge 2 -and (($Raw[0] -eq 0xFF -and $Raw[1] -eq 0xFE) -or ($Raw[0] -eq 0xFE -and $Raw[1] -eq 0xFF))) {
        $enc = if ($Raw[0] -eq 0xFF) { [System.Text.UnicodeEncoding]::new($false, $true, $true) } else { [System.Text.UnicodeEncoding]::new($true, $true, $true) }
        return $enc.GetString($Raw, 2, $Raw.Length - 2)
    }
    $start = 0
    if ($Raw.Length -ge 3 -and $Raw[0] -eq 0xEF -and $Raw[1] -eq 0xBB -and $Raw[2] -eq 0xBF) { $start = 3 }
    return [System.Text.UTF8Encoding]::new($false, $true).GetString($Raw, $start, $Raw.Length - $start)
}

function Get-CoordLocalRoot {
    # <git-common-dir>/mefor-coord for the repository at $From, or $null when git cannot say.
    # --path-format=absolute is not optional: the bare form is relative to the caller's cwd.
    param([string]$From)
    try {
        $gitArgs = @()
        if ($From) { $gitArgs = @('-C', $From) }
        $common = & git @gitArgs rev-parse --path-format=absolute --git-common-dir 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $common) { return $null }
        return (Join-Path ([string]$common).Trim() 'mefor-coord')
    } catch { return $null }
}

function Get-CoordSharedRoot {
    # Returns @{ Path; Source = 'env'|'file'|'local'; Error }. Path is $null only when Error is set.
    # No probe; Resolve-CoordSharedRoot adds one. A caller that already holds <common>/mefor-coord
    # passes it as -LocalRoot, and no git process is spawned.
    param([string]$From, [string]$LocalRoot)
    $envValue = [string][Environment]::GetEnvironmentVariable($script:CoordRootEnv)
    $envValue = $envValue.Trim($script:CoordWs)
    if ($envValue) {
        if (-not (Test-CoordAbsolutePath $envValue)) {
            return @{ Path = $null; Source = 'env'; Error = "$($script:CoordRootEnv) is not an absolute path: $envValue" }
        }
        return @{ Path = $envValue; Source = 'env'; Error = $null }
    }
    $local = if ($LocalRoot) { $LocalRoot } else { Get-CoordLocalRoot -From $From }
    if (-not $local) {
        return @{ Path = $null; Source = 'local'; Error = "git could not name the common dir for '$From'" }
    }
    $file = Join-Path $local $script:CoordRootFile
    $text = $null
    try {
        if (-not (Test-Path -LiteralPath $file)) {
            return @{ Path = $local; Source = 'local'; Error = $null }
        }
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) {
            return @{ Path = $null; Source = 'file'; Error = "$file exists but is not a file" }
        }
        $raw = [System.IO.File]::ReadAllBytes($file)
    } catch {
        return @{ Path = $null; Source = 'file'; Error = "$file could not be read: $($_.Exception.Message)" }
    }
    try { $text = ConvertFrom-CoordRootBytes -Raw $raw } catch {
        return @{ Path = $null; Source = 'file'; Error = "$file is not UTF-8 or UTF-16 with a byte-order mark" }
    }
    # EVERY line is checked, not the first: a second shared_root, or junk after a valid one, is an error.
    $found = $null
    foreach ($line in ($text -split "`r`n|`n|`r")) {
        if ($script:CoordBlankLine.IsMatch($line)) { continue }
        $m = $script:CoordRootLine.Match($line)
        if (-not $m.Success -or -not $m.Groups[1].Value.Trim($script:CoordWs)) {
            return @{ Path = $null; Source = 'file'; Error = "$file has a line that is not shared_root = '<path>' (single quotes): $line" }
        }
        if ($null -ne $found) {
            return @{ Path = $null; Source = 'file'; Error = "$file names shared_root more than once" }
        }
        $found = $m.Groups[1].Value.Trim($script:CoordWs)
    }
    if ($null -eq $found) { return @{ Path = $null; Source = 'file'; Error = "$file names no shared_root" } }
    if (-not (Test-CoordAbsolutePath $found)) {
        return @{ Path = $null; Source = 'file'; Error = "$file names a shared_root that is not an absolute path: $found" }
    }
    return @{ Path = $found; Source = 'file'; Error = $null }
}

function Test-CoordAbsolutePath {
    # A drive-rooted or UNC path, or (off Windows) a leading slash. A relative root resolves against
    # each process's own cwd, which puts two sessions on two registries; `C:share` and `\share` are
    # relative on Windows too. The Python twin carries the same pattern.
    param([string]$Path)
    return ($Path -cmatch '\A(?:[A-Za-z]:[\\/]|[\\/]{2}[^\\/]+[\\/][^\\/]+|/(?![\\/]))')
}

function Test-CoordSharedKind {
    param([string]$Kind)
    return ($script:CoordSharedKinds -contains $Kind)
}

function Get-CoordUncHost {
    # The server name of a \\server\share path, or $null for anything else.
    param([string]$Path)
    if ($Path -match '\A[\\/]{2}([^\\/]+)[\\/]') { return $Matches[1] }
    return $null
}

function Test-CoordRoot {
    # Returns @{ Ok; Error }. Fast on a dead server; see the header for why.
    param([string]$Path, [string]$LocalRoot)
    if (-not $Path) { return @{ Ok = $false; Error = 'no path' } }
    $server = Get-CoordUncHost -Path $Path
    if ($server) {
        $down = if ($LocalRoot) { Join-Path $LocalRoot $script:CoordDownFile } else { $null }
        # The verdict is about ONE root. A cache written for another root, or stamped in the future by a
        # skewed clock or a copied file, is ignored rather than trusted.
        try {
            if ($down -and (Test-Path -LiteralPath $down -PathType Leaf)) {
                $age = ([DateTime]::UtcNow - (Get-Item -LiteralPath $down).LastWriteTimeUtc).TotalSeconds
                $cached = ([System.IO.File]::ReadAllText($down) | ConvertFrom-Json -ErrorAction Stop).root
                if ($cached -ceq $Path -and $age -ge 0 -and $age -lt $script:CoordDownTtlSeconds) {
                    return @{ Ok = $false; Error = "shared root $Path was unreachable $([int]$age) s ago (cached in $down)" }
                }
            }
        } catch { }
        $reached = $false
        $client = [System.Net.Sockets.TcpClient]::new()
        try {
            $reached = $client.ConnectAsync($server, 445).Wait($script:CoordProbeTimeoutMs) -and $client.Connected
        } catch { $reached = $false } finally { $client.Dispose() }
        if (-not $reached) {
            try {
                if ($down) {
                    New-Item -ItemType Directory -Force -Path $LocalRoot | Out-Null
                    [System.IO.File]::WriteAllText($down, (@{ root = $Path; at = [DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress))
                }
            } catch { }
            return @{ Ok = $false; Error = "shared root $Path is unreachable: no answer from ${server}:445 within $($script:CoordProbeTimeoutMs) ms" }
        }
    }
    try {
        if (Test-Path -LiteralPath $Path -PathType Container -ErrorAction Stop) { return @{ Ok = $true; Error = $null } }
        return @{ Ok = $false; Error = "shared root $Path does not exist or is not a directory" }
    } catch {
        return @{ Ok = $false; Error = "shared root $Path cannot be read: $($_.Exception.Message)" }
    }
}

function Resolve-CoordSharedRoot {
    # The shared root itself, probed. Returns @{ Path; Source; Error }. A caller that needs several
    # shared kinds resolves once and joins each kind onto Path, rather than paying one probe per kind.
    param([string]$From, [string]$LocalRoot)
    $local = if ($LocalRoot) { $LocalRoot } else { Get-CoordLocalRoot -From $From }
    $root = Get-CoordSharedRoot -From $From -LocalRoot $local
    if ($root.Error) { return $root }
    if ($root.Source -ne 'local') {
        $probe = Test-CoordRoot -Path $root.Path -LocalRoot $local
        if (-not $probe.Ok) { return @{ Path = $null; Source = $root.Source; Error = $probe.Error } }
    }
    return $root
}

function Resolve-CoordDir {
    # The directory for one kind of coordination state. Returns @{ Path; Shared; Source; Error }.
    # A shared kind on a configured root is probed; a caller that writes exclusive state (a claim, an
    # allocation) refuses on Error. A caller that only reads may skip with a note. Neither may fall
    # back to LOCAL for a shared kind.
    # $Kind is not Mandatory: under -NonInteractive a missing Mandatory parameter THROWS at binding,
    # and this file never throws (header, constraint 4).
    param([string]$From, [string]$Kind, [string]$LocalRoot)
    if (-not $Kind) { return @{ Path = $null; Shared = $false; Source = 'local'; Error = 'Resolve-CoordDir needs -Kind' } }
    $local = if ($LocalRoot) { $LocalRoot } else { Get-CoordLocalRoot -From $From }
    if (-not (Test-CoordSharedKind -Kind $Kind)) {
        if (-not $local) { return @{ Path = $null; Shared = $false; Source = 'local'; Error = "git could not name the common dir for '$From'" } }
        return @{ Path = (Join-Path $local $Kind); Shared = $false; Source = 'local'; Error = $null }
    }
    $root = Resolve-CoordSharedRoot -From $From -LocalRoot $local
    if ($root.Error) { return @{ Path = $null; Shared = $true; Source = $root.Source; Error = $root.Error } }
    return @{ Path = (Join-Path $root.Path $Kind); Shared = $true; Source = $root.Source; Error = $null }
}

function Get-CoordHost {
    # The name every shared record carries, so a reader on another PC can tell it is not checkable here.
    return [Environment]::MachineName
}

# What a host field that is present but not a string reads as. It never equals a machine name, so the
# record is NOT CHECKABLE HERE: only an ABSENT field means legacy, and guessing "this machine" for a
# malformed one would let this disk judge, and reap, another PC's record. The Python twin matches.
$script:CoordUnreadableHost = '<unreadable host>'

function Get-CoordRecordHost {
    # The host a record names, trimmed; '' when it names none; the unreadable marker when it is not text.
    param($Record)
    if ($null -eq $Record) { return '' }
    $h = $null
    if ($Record -is [System.Collections.IDictionary]) {
        if ($Record.Contains('host')) { $h = $Record['host'] }
    } else {
        $p = $Record.PSObject.Properties['host']
        if ($p) { $h = $p.Value }
    }
    if ($null -eq $h) { return '' }
    if ($h -isnot [string]) { return $script:CoordUnreadableHost }
    return $h.Trim($script:CoordWs)
}

function Test-CoordRecordIsHere {
    # True when a record is this machine's to judge: it names no host, or names this one.
    param($Record)
    $h = Get-CoordRecordHost $Record
    return (-not $h) -or ($h -ieq (Get-CoordHost))
}

function Get-CoordInnerException {
    # PowerShell wraps an exception a .NET method throws in a MethodInvocationException.
    param($Exception)
    if ($Exception -is [System.Management.Automation.MethodInvocationException] -and $Exception.InnerException) {
        return $Exception.InnerException
    }
    return $Exception
}

function Test-CoordTransientIoError {
    # True for the errors an SMB share raises while another process holds the file: a sharing or lock
    # violation, and (for a rename only) access denied. A missing file or directory is never transient.
    param($Exception, [switch]$AllowAccessDenied)
    $e = Get-CoordInnerException $Exception
    if ($e -is [System.IO.FileNotFoundException] -or $e -is [System.IO.DirectoryNotFoundException]) { return $false }
    if ($AllowAccessDenied -and $e -is [System.UnauthorizedAccessException]) { return $true }
    return ($e -is [System.IO.IOException] -and $script:CoordSharingHResults -contains $e.HResult)
}

function Invoke-CoordIoRetry {
    # Runs $Action, retrying the transient errors above with a short bounded backoff. When the tries run
    # out, or the error is not transient, it rethrows the .NET exception itself, so a caller's typed
    # catch still matches.
    param([scriptblock]$Action, [switch]$AllowAccessDenied)
    $sleep = $script:CoordRetryFirstMs
    for ($try = 1; ; $try++) {
        try { return (& $Action) } catch {
            $ex = Get-CoordInnerException $_.Exception
            if ($try -ge $script:CoordRetryTries -or -not (Test-CoordTransientIoError $ex -AllowAccessDenied:$AllowAccessDenied)) { throw $ex }
        }
        Start-Sleep -Milliseconds $sleep
        $sleep = [Math]::Min($sleep * 2, $script:CoordRetryMaxSleepMs)
    }
}

function ConvertTo-CoordFullPath {
    # .NET resolves a relative path against the process cwd, not against PowerShell's location.
    param([string]$Path)
    if ([System.IO.Path]::IsPathRooted($Path)) { return $Path }
    return (Join-Path (Get-Location -PSProvider FileSystem).ProviderPath $Path)
}

function Move-CoordFileReplace {
    # Renames $Source onto $Destination in one step, retrying a sharing violation or access denied.
    # -NoOverwrite keeps an existing destination and throws IOException, which is never retried.
    param([string]$Source, [string]$Destination, [switch]$NoOverwrite)
    $src = ConvertTo-CoordFullPath $Source
    $dst = ConvertTo-CoordFullPath $Destination
    $overwrite = -not $NoOverwrite
    Invoke-CoordIoRetry -AllowAccessDenied -Action { [System.IO.File]::Move($src, $dst, $overwrite) }
}

function Read-CoordText {
    # A file's whole text, retrying a sharing violation. A missing file throws FileNotFoundException at
    # once, so a caller's "missing" path is unchanged. An empty file emits nothing, exactly as
    # `Get-Content -Raw` does, so a pipeline into ConvertFrom-Json behaves as it did before.
    # -Encoding defaults to UTF-8 with byte-order-mark detection, as ReadAllText does.
    param([string]$Path, [System.Text.Encoding]$Encoding)
    $full = ConvertTo-CoordFullPath $Path
    $enc = if ($Encoding) { $Encoding } else { [System.Text.Encoding]::UTF8 }
    $text = Invoke-CoordIoRetry -Action { [System.IO.File]::ReadAllText($full, $enc) }
    if ($text.Length -eq 0) { return }
    return $text
}
