# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Copy one PC's live coordination records onto the shared root, stamping each with the host that
    wrote it. Dry-run unless -Apply.

.DESCRIPTION
    WHY THIS EXISTS. docs/COORD-SHARED-ROOT.md, Migration steps 6 and 10. A record with no `host`
    field is read as "this machine's" (coord-root.ps1, Test-CoordRecordIsHere). That is true only on
    the PC that wrote it. Copied to the share unstamped, a claim from one PC would be judged by the
    other PC's disk, read as HOLDER GONE, and could be reaped. So every copied JSON record that has
    no `host` field gets `host = <SourceHost>` on the way over. A record that has one keeps it.

    A RECORD IT CANNOT STAMP SAFELY IS NOT CLEAN. At least these are copied as they are, listed under
    UNSTAMPED, and make the run exit 3: a `.json` file that is not a readable JSON object; a `host`
    that is present but null or blank, which the readers also take to mean "this machine"; and a host
    key in another case, such as `Host`, where adding `host` would give the record two keys that
    ConvertFrom-Json refuses to read. Each needs a person, not a guess.

    THE WIKI INBOX IS COPIED BUT NEVER STAMPED. No reader judges a wiki event by host, and korus's
    compile compares an inbox event's bytes with its landed copy, so a stamped event would halt it.

    WHAT IT COPIES. Only the shared kinds coord-root.ps1 names ($script:CoordSharedKinds), each from
    <Source>/<kind> to <Target>/<kind>. At least these are never copied, at any depth: `_retired-*`,
    `*.BACKUP-*` and `backups` (retired and backup trees), `tmp` and `*.tmp` (a writer's half-made
    file), `*.lock`, names ending `cache` or `.cache`, and reparse points (a junction is not
    followed). The local kinds (announce, overlap-cache, test-slots and the rest) are not walked at
    all, because they are not in the list.

    IT NEVER OVERWRITES. A target file with the same name is a CONFLICT, reported and left alone. A
    target file whose bytes equal what this would write is PRESENT, so a second run is a no-op rather
    than a wall of conflicts. Each write goes to a temp name and is renamed without overwrite, so a
    file that appears on the target between the check and the write is a conflict too.

    LEDGERS AND SINGLETONS ARE NOT MERGED. Both PCs hold at least these under the same name:
    claims/.history, owner-log/*, seats/.pool-epoch, seats/.writer-alive/* and wiki/query-log/*. One
    absent from the target is copied. One present with other content is listed under NOT MERGED and
    left alone, without counting as a conflict, so routine noise does not bury a real double claim.
    Appending one ledger to the other is a person's job.

    ALLOCATIONS. A number under alloc/<kind>/<n>.json present on both sides with different content is
    a COLLISION: two PCs issued the same number. It is reported for the owner to rule on and never
    resolved here. alloc/backlog belongs to the retired backlog allocator
    (tombstone-retired-backlog-allocator.ps1). Its records and its tombstone are not live numbers, so
    they get their own heading and are not copied unless -IncludeRetiredBacklog. Leave the LOCAL
    alloc/backlog in place after the migration: a stale pre-retirement allocator reads only that path.

    THE WRONG HOST IS CAUGHT WHEN IT CAN BE. Without -SourceHost the stamp is this machine. If any
    record in -Source already names a different host, -Source is probably another PC's copy, so the
    run lists those hosts under FOREIGN HOSTS and exits 3. Pass -SourceHost to say which PC wrote it.

    TIMES. Each copy keeps its source's last-write time, as `robocopy /COPY:DT` would, because seat
    liveness reads it.

    NEVER RUN THIS AGAINST LIVE STATE WITHOUT THE OWNER. Pointing -Target at the share is migration
    step 6, which is the owner's to schedule. Tests use temp directories only.

.PARAMETER Source
    The coordination directory to copy from, for example this clone's <git-common-dir>/mefor-coord.

.PARAMETER Target
    The shared root to copy into, for example \\Nucbox01\Shared\mefor-coord. It must already exist
    (migration step 1 creates it). A UNC target is probed first, so a dead server fails in seconds.

.PARAMETER SourceHost
    The host to stamp on records that have no host field. Defaults to this machine (Get-CoordHost).
    Pass it when -Source is another PC's copy.

.PARAMETER Apply
    Write. Without it nothing is written anywhere.

.PARAMETER IncludeRetiredBacklog
    Also copy alloc/backlog. Off by default; see ALLOCATIONS above.

.PARAMETER Json
    Print one machine-readable JSON summary instead of the report.

.NOTES
    Exit codes:
      0  clean.
      1  at least one read or write failed. Wins over 3, because the report is then incomplete.
      2  bad arguments: a missing or non-directory -Source, a -Target that is missing, unreachable or
         not a directory, or nested roots. Nothing was read past the arguments.
      3  at least one CONFLICT, COLLISION, UNSTAMPED record or FOREIGN HOST. With -Apply every other
         file was still copied. Also the cloud-session refusal, which prints only its one stderr line.
      4  coord-root.ps1 is missing, so the shared kinds cannot be named.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\coord-migrate.ps1 -Source D:\old\mefor-coord -Target E:\probe\mefor-coord
    pwsh -NoProfile -File scripts\coord\coord-migrate.ps1 -Source D:\old\mefor-coord -Target E:\probe\mefor-coord -SourceHost MEFORDEV01 -Apply -Json
#>
[CmdletBinding()]
param(
    # None is Mandatory: a Mandatory prompt hangs a caller whose stdin stays open (tests/_no_prompt.py).
    # Missing values are refused below, after the cloud refusal.
    [string]$Source,
    [string]$Target,
    [string]$SourceHost,
    [switch]$Apply,
    [switch]$IncludeRetiredBacklog,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'

# A CLAUDE CODE CLOUD SESSION REACHES NO OTHER SESSION THROUGH THIS SCRIPT: its --git-common-dir is
# the VM's own clone, and the share is not on its network. CLAUDE.md section 5, "A cloud session is a
# Builder in its own session"; tests/test_coord_cloud_refusal.py holds the copies equal.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('coord-migrate.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

$coordRootScript = Join-Path $PSScriptRoot 'coord-root.ps1'
if (-not (Test-Path -LiteralPath $coordRootScript -PathType Leaf)) {
    [Console]::Error.WriteLine("coord-migrate.ps1: REFUSED -- $coordRootScript is missing, so the shared kinds cannot be named and nothing was read or written.")
    exit 4
}
. $coordRootScript

function Stop-Usage([string]$Message) {
    [Console]::Error.WriteLine("coord-migrate.ps1: $Message")
    exit 2
}

function Get-FullPath([string]$Path) {
    # Against PowerShell's location, not the process cwd that [IO.Path]::GetFullPath uses: the two
    # differ after Set-Location in an interactive shell.
    $p = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Path)
    return [System.IO.Path]::TrimEndingDirectorySeparator([System.IO.Path]::GetFullPath($p))
}

function Get-InnerException($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    if ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
    return $ex
}

if (-not $Source) { Stop-Usage 'needs -Source <dir>.' }
if (-not $Target -or -not $Target.Trim()) { Stop-Usage 'needs -Target <dir>.' }
$srcRoot = Get-FullPath $Source
$dstRoot = Get-FullPath $Target
if (-not (Test-Path -LiteralPath $srcRoot -PathType Container)) { Stop-Usage "-Source '$srcRoot' is not a directory." }
$sep = [System.IO.Path]::DirectorySeparatorChar
# Nested roots would copy the target into itself, or read back what this run just wrote.
if ($srcRoot -ieq $dstRoot -or $dstRoot.StartsWith("$srcRoot$sep", [StringComparison]::OrdinalIgnoreCase) -or
    $srcRoot.StartsWith("$dstRoot$sep", [StringComparison]::OrdinalIgnoreCase)) {
    Stop-Usage "-Source and -Target must not be the same directory or nested: '$srcRoot', '$dstRoot'."
}
# A missing or dead target would make every file read "would copy" with no collisions: a dry run
# that is clean because it compared against nothing. Test-CoordRoot answers fast on a dead server.
$probe = Test-CoordRoot -Path $dstRoot
if (-not $probe.Ok) { Stop-Usage "-Target is not usable: $($probe.Error)" }
$stampGiven = [bool]($SourceHost -and $SourceHost.Trim())
$stampHost = if ($stampGiven) { $SourceHost.Trim() } else { Get-CoordHost }

# Why each excluded name is excluded is in the header. Matched against every path segment.
function Get-SkipReason([string]$Name) {
    if ($Name -like '_retired-*') { return 'retired tree' }
    if ($Name -like '*.BACKUP-*' -or $Name -eq 'backups') { return 'backup' }
    if ($Name -eq 'tmp' -or $Name -like '*.tmp') { return 'temp file' }
    if ($Name -like '*.lock') { return 'lock' }
    if ($Name -like '*cache' -or $Name -like '*.cache') { return 'cache' }
    return $null
}

function Test-LedgerPath([string]$RelFull) {
    # The files both PCs hold under one name; see LEDGERS AND SINGLETONS in the header.
    return ($RelFull -ceq 'claims/.history' -or $RelFull -like 'owner-log/*' -or $RelFull -ceq 'seats/.pool-epoch' -or
        $RelFull -like 'seats/.writer-alive/*' -or $RelFull -like 'wiki/query-log/*')
}

$utf8Strict = [System.Text.UTF8Encoding]::new($false, $true)
$JsonKind = [System.Text.Json.JsonValueKind]

function Get-PlannedBytes([byte[]]$Raw) {
    # Returns @{ Bytes; Stamped; HostKept; KeptHost; Unstamped }. A JSON object with no host field
    # gets one, inserted as text right after its opening brace: re-serialising would reformat the
    # record, and ConvertFrom-Json turns ISO date strings into DateTime values that serialise back
    # differently. Unstamped is the reason a record could not be stamped safely, or $null.
    $result = @{ Bytes = $Raw; Stamped = $false; HostKept = $false; KeptHost = $null; Unstamped = $null }
    $bom = ($Raw.Length -ge 3 -and $Raw[0] -eq 0xEF -and $Raw[1] -eq 0xBB -and $Raw[2] -eq 0xBF)
    $start = if ($bom) { 3 } else { 0 }
    try {
        $text = $utf8Strict.GetString($Raw, $start, $Raw.Length - $start)
        $doc = [System.Text.Json.JsonDocument]::Parse($text)
    } catch {
        $result.Unstamped = 'not a readable JSON object (strict UTF-8 JSON)'
        return $result
    }
    try {
        if ($doc.RootElement.ValueKind -ne $JsonKind::Object) {
            $result.Unstamped = 'not a JSON object'
            return $result
        }
        $props = @($doc.RootElement.EnumerateObject())
        # Exact case, as the Python twin reads it (record.get("host")).
        $exact = @($props | Where-Object { $_.Name -ceq 'host' })
        if ($exact.Count -gt 0) {
            $v = $exact[-1].Value
            if ($v.ValueKind -eq $JsonKind::Null -or ($v.ValueKind -eq $JsonKind::String -and -not $v.GetString().Trim())) {
                # The readers take a null or blank host to mean "this machine", the hazard itself.
                $result.Unstamped = 'host is present but null or blank'
                return $result
            }
            $result.HostKept = $true
            # A non-string host reads as unreadable, never as a machine, so it is safe and names nobody.
            if ($v.ValueKind -eq $JsonKind::String) { $result.KeptHost = $v.GetString().Trim() }
            return $result
        }
        if (@($props | Where-Object { $_.Name -ieq 'host' }).Count -gt 0) {
            $result.Unstamped = 'a host key in another case; adding host would give it two keys ConvertFrom-Json refuses'
            return $result
        }
        $brace = $text.IndexOf('{')
        $field = '"host":' + ([string]$stampHost | ConvertTo-Json -Compress)
        if ($props.Count -gt 0) { $field += ',' }
        $stamped = $text.Substring(0, $brace + 1) + $field + $text.Substring($brace + 1)
        $check = [System.Text.Json.JsonDocument]::Parse($stamped)
        $check.Dispose()
        $body = $utf8Strict.GetBytes($stamped)
        if ($bom) { $body = [byte[]](@(0xEF, 0xBB, 0xBF) + $body) }
        $result.Bytes = [byte[]]$body
        $result.Stamped = $true
        return $result
    } finally { $doc.Dispose() }
}

function Test-SameBytes([byte[]]$A, [byte[]]$B) {
    if ($A.Length -ne $B.Length) { return $false }
    return [System.Linq.Enumerable]::SequenceEqual($A, $B)
}

function Get-Files([string]$Dir, [string]$Rel, [System.Collections.Generic.List[object]]$Skipped) {
    # Every regular file under $Dir, as relative paths, skipping excluded names and reparse points.
    $out = [System.Collections.Generic.List[string]]::new()
    foreach ($item in @(Get-ChildItem -LiteralPath $Dir -Force -ErrorAction Stop)) {
        $relPath = if ($Rel) { "$Rel/$($item.Name)" } else { $item.Name }
        $reason = Get-SkipReason $item.Name
        if (-not $reason -and ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) { $reason = 'reparse point' }
        if ($reason) {
            $Skipped.Add([pscustomobject]@{ path = $relPath; reason = $reason })
            continue
        }
        if ($item.PSIsContainer) {
            foreach ($f in (Get-Files $item.FullName $relPath $Skipped)) { $out.Add($f) }
        } else {
            $out.Add($relPath)
        }
    }
    return , $out
}

$kinds = [System.Collections.Generic.List[object]]::new()
$conflicts = [System.Collections.Generic.List[string]]::new()
$collisions = [System.Collections.Generic.List[string]]::new()
$notMerged = [System.Collections.Generic.List[string]]::new()
$errors = [System.Collections.Generic.List[string]]::new()
$skippedAll = [System.Collections.Generic.List[object]]::new()
$unstamped = [System.Collections.Generic.List[object]]::new()
$foreign = [System.Collections.Generic.SortedSet[string]]::new([StringComparer]::OrdinalIgnoreCase)
$backlog = [ordered]@{ records = 0; tombstones = 0; included = [bool]$IncludeRetiredBacklog }
$verbatim = @{ Bytes = $null; Stamped = $false; HostKept = $false; KeptHost = $null; Unstamped = $null }

foreach ($kind in $script:CoordSharedKinds) {
    $row = [ordered]@{ kind = $kind; copy = 0; stamped = 0; hostKept = 0; present = 0; skipped = 0; conflicts = 0; collisions = 0; notMerged = 0 }
    $kinds.Add($row)
    $srcKind = Join-Path $srcRoot $kind
    if (-not (Test-Path -LiteralPath $srcKind -PathType Container)) { continue }
    $skipped = [System.Collections.Generic.List[object]]::new()
    try { $files = Get-Files $srcKind '' $skipped } catch {
        $errors.Add("$kind/: could not be listed: $($_.Exception.Message)")
        continue
    }
    foreach ($s in $skipped) { $skippedAll.Add([pscustomobject]@{ path = "$kind/$($s.path)"; reason = $s.reason }) }
    $row.skipped = $skipped.Count

    foreach ($rel in $files) {
        $relFull = "$kind/$rel"
        $parts = $rel -split '/'
        $isBacklog = ($kind -eq 'alloc' -and $parts[0] -eq 'backlog')
        $srcFile = Join-Path $srcKind ($parts -join $sep)
        $dstFile = Join-Path (Join-Path $dstRoot $kind) ($parts -join $sep)
        try { $raw = [System.IO.File]::ReadAllBytes($srcFile) } catch {
            $errors.Add("${relFull}: could not be read: $($_.Exception.Message)")
            continue
        }
        if ($isBacklog) {
            $backlog.records++
            # The same test tombstone-retired-backlog-allocator.ps1 applies (Test-IsTombstone).
            try {
                $c = $utf8Strict.GetString($raw).TrimStart([char]0xFEFF) | ConvertFrom-Json -ErrorAction Stop
                if ($null -ne $c -and ($c.PSObject.Properties.Name -contains 'tombstone') -and ($c.tombstone -eq $true)) {
                    $backlog.tombstones++
                }
            } catch { }
            if (-not $IncludeRetiredBacklog) { continue }
        }
        $plan = $verbatim.Clone()
        $plan.Bytes = $raw
        if ($rel -like '*.json' -and $kind -ne 'wiki') { $plan = Get-PlannedBytes $raw }
        if ($plan.KeptHost -and -not $stampGiven -and $plan.KeptHost -ine $stampHost) { [void]$foreign.Add($plan.KeptHost) }

        if (Test-Path -LiteralPath $dstFile) {
            try { $have = [System.IO.File]::ReadAllBytes($dstFile) } catch {
                $errors.Add("${relFull}: the target copy could not be read: $($_.Exception.Message)")
                continue
            }
            if (Test-SameBytes $have $plan.Bytes) { $row.present++; continue }
            # A number two PCs both issued. Not alloc/backlog: those are not live numbers.
            $isNumber = ($kind -eq 'alloc' -and -not $isBacklog -and $parts.Count -eq 2 -and $parts[1] -match '\A\d+\.json\z')
            if ($isNumber) { $row.collisions++; $collisions.Add($relFull) }
            elseif (Test-LedgerPath $relFull) { $row.notMerged++; $notMerged.Add($relFull) }
            else { $row.conflicts++; $conflicts.Add($relFull) }
            continue
        }

        if ($Apply) {
            $tmp = "$dstFile.migrate-$([guid]::NewGuid().ToString('N')).tmp"
            try {
                New-Item -ItemType Directory -Force -Path (Split-Path -Parent $dstFile) | Out-Null
                [System.IO.File]::WriteAllBytes($tmp, [byte[]]$plan.Bytes)
                [System.IO.File]::SetLastWriteTimeUtc($tmp, [System.IO.File]::GetLastWriteTimeUtc($srcFile))
                # No overwrite: a file that appeared since the check above fails the move, and is a conflict.
                [System.IO.File]::Move($tmp, $dstFile, $false)
            } catch {
                $ex = Get-InnerException $_
                Remove-Item -LiteralPath $tmp -Force -ErrorAction SilentlyContinue
                # ERROR_FILE_EXISTS (80) or ERROR_ALREADY_EXISTS (183), from the error itself: a
                # second look at the share could answer from a stale client cache.
                if ($ex -is [System.IO.IOException] -and (($ex.HResult -band 0xFFFF) -in 80, 183)) {
                    $row.conflicts++; $conflicts.Add($relFull)
                } else {
                    $errors.Add("${relFull}: could not be written: $($ex.Message)")
                }
                continue
            }
        }
        $row.copy++
        if ($plan.Stamped) { $row.stamped++ }
        if ($plan.HostKept) { $row.hostKept++ }
        if ($plan.Unstamped) { $unstamped.Add([pscustomobject]@{ path = $relFull; reason = $plan.Unstamped }) }
    }
}

$dirty = $conflicts.Count -or $collisions.Count -or $unstamped.Count -or $foreign.Count
$exit = if ($errors.Count) { 1 } elseif ($dirty) { 3 } else { 0 }
$mode = if ($Apply) { 'apply' } else { 'dry-run' }

if ($Json) {
    [ordered]@{
        mode = $mode; source = $srcRoot; target = $dstRoot; sourceHost = $stampHost
        kinds = @($kinds); conflicts = @($conflicts); collisions = @($collisions); notMerged = @($notMerged)
        unstamped = @($unstamped); foreignHosts = @($foreign); retiredBacklog = $backlog
        skipped = @($skippedAll); errors = @($errors); exit = $exit
    } | ConvertTo-Json -Depth 6
    exit $exit
}

function Write-List([string]$Heading, $Items) {
    if (-not @($Items).Count) { return }
    Write-Host ''
    Write-Host "$Heading ($(@($Items).Count)):"
    foreach ($i in $Items) { Write-Host "  $i" }
}

$verb = if ($Apply) { 'copied' } else { 'would copy' }
Write-Host "coord-migrate ($mode): $srcRoot -> $dstRoot, stamping host = $stampHost"
Write-Host ''
$fmt = '{0,-10} {1,10} {2,8} {3,9} {4,8} {5,8} {6,9} {7,10} {8,10}'
Write-Host ($fmt -f 'kind', $verb, 'stamped', 'host kept', 'present', 'skipped', 'conflicts', 'collisions', 'not merged')
foreach ($r in $kinds) {
    Write-Host ($fmt -f $r.kind, $r.copy, $r.stamped, $r.hostKept, $r.present, $r.skipped, $r.conflicts, $r.collisions, $r.notMerged)
}
Write-Host ''
$bl = if ($IncludeRetiredBacklog) { 'included in the counts above' } else { 'NOT copied; pass -IncludeRetiredBacklog to copy them' }
Write-Host "RETIRED BACKLOG ALLOCATIONS (alloc/backlog): $($backlog.records) record(s), $($backlog.tombstones) tombstone(s) -- $bl."
Write-List 'COLLISIONS -- the same number issued on both sides, for the owner to rule on' $collisions
Write-List 'CONFLICTS -- a different file of the same name is already on the target, left alone' $conflicts
Write-List 'UNSTAMPED -- copied as it is, and still read as "this machine" on every PC; fix by hand' ($unstamped | ForEach-Object { "$($_.path): $($_.reason)" })
Write-List "FOREIGN HOSTS -- records in -Source name these hosts, not $stampHost; pass -SourceHost" $foreign
Write-List 'NOT MERGED -- a ledger or singleton both sides hold; the target copy was kept' $notMerged
Write-List 'ERRORS' $errors
if (-not $Apply) {
    Write-Host ''
    Write-Host 'Dry run: nothing was written. Pass -Apply to copy.'
}
exit $exit
