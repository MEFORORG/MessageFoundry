# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Record THIS lane's own counts of items in flight and items free by work. The only writer of a
    lane level.

.DESCRIPTION
    A builder lane states how many items it is working and how many it holds without working them.
    Nothing else in the fleet may write those numbers -- not a Manager, not a hook, not an inference
    from claims.

    THERE IS NO ITEM CEILING (owner ruling 2026-10-26). The four-item lane ceiling, and the
    -Capacity parameter that defaulted to it, are retired: Builders and Managers work at full speed,
    and usage is governed only by the Steward's holds and the korus Workflow gate. Nothing this
    script records is a cap, a slot count or a reason to stop briefing or building. Do not add a
    capacity back, and do not add a usage throttle here; usage is the Steward's.

    THERE IS NO -Lane AND NO -BoxKey PARAMETER, AND ADDING ONE DEFEATS THE WHOLE DESIGN. The box key is
    derived from $PWD, so a session can only ever state its OWN level. The failure this replaces is a
    gauge that reported both lanes full while one sat idle, because it counted CLAIMS: measured
    2026-08-23, one lane held nine claims and reported one active item and three free slots. Both
    numbers were honest. Only the lane knows which is which.

    FREE MEANS BY WORK, NOT BY CLAIMS. Built-and-awaiting-land is FREE. Blocked is FREE. Parked on a
    condition is FREE. A claim you are not currently able to progress is FREE work wearing an
    occupied label, and that mislabelling is the outage. With no ceiling there are no empty slots,
    so -Free counts exactly those held items and nothing else.
#>
[CmdletBinding(DefaultParameterSetName = 'State')]
param(
    # NEITHER IS Mandatory, ON PURPOSE: a bare call, or one giving a single number, binds this default
    # set without both, and a Mandatory prompt there hangs a caller with stdin open
    # (tests/_no_prompt.py, vault BACKLOG #3627). The refusal follows this param block, after the
    # cloud refusal.
    [Parameter(ParameterSetName = 'State')][ValidateRange(0, 99)][int]$Free,
    [Parameter(ParameterSetName = 'State')][ValidateRange(0, 99)][int]$InFlight,
    [Parameter(ParameterSetName = 'State')][string]$Note = '',
    # Stamp that a dispatcher asked. Carries NO number.
    [Parameter(ParameterSetName = 'Asked', Mandatory)][switch]$Asked,
    [Parameter(ParameterSetName = 'Show', Mandatory)][switch]$Show
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A CLAUDE CODE CLOUD SESSION REACHES NO OTHER SESSION THROUGH THIS SCRIPT: its --git-common-dir is
# the VM's own clone, so a write would "succeed" where nobody reads. CLAUDE.md section 5, "A cloud
# session is a Builder in its own session"; tests/test_coord_cloud_refusal.py holds the copies equal.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('lane.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

# A level needs both numbers: refuse by name, before anything is read or written. See $Free. Bound,
# not truthy, because 0 is a real answer for either.
if ($PSCmdlet.ParameterSetName -eq 'State' -and
    -not ($PSBoundParameters.ContainsKey('Free') -and $PSBoundParameters.ContainsKey('InFlight'))) {
    throw "A lane level needs both -Free and -InFlight (or use -Asked or -Show). Nothing was written."
}

. (Join-Path $PSScriptRoot 'mail-key.ps1')

# coord-root.ps1 is required; without it this refuses rather than guess (docs/COORD-SHARED-ROOT.md).
$coordRootScript = Join-Path $PSScriptRoot 'coord-root.ps1'
if (-not (Test-Path -LiteralPath $coordRootScript -PathType Leaf)) {
    [Console]::Error.WriteLine("lane.ps1: REFUSED -- $coordRootScript is missing, so the coordination root cannot be resolved and nothing was written.")
    exit 2
}
. $coordRootScript
$thisHost = Get-CoordHost

# Both kinds this writes or reads are fleet-wide, so both are resolved before anything is written,
# and an error refuses rather than writing a level into a local copy nobody else reads.
$sharedResolved = Resolve-CoordSharedRoot -From (Get-Location).Path
if ($sharedResolved.Error) {
    [Console]::Error.WriteLine("lane.ps1: REFUSED -- the coordination root could not be resolved, so nothing was written: $($sharedResolved.Error)")
    exit 2
}
$claimsDirShared = Join-Path $sharedResolved.Path 'claims'

function Get-ClaimHash([string]$Worktree) {
    # Hash of the claim KEYS this worktree holds. Used ONLY to invalidate a stated number when the
    # claim set moves -- never to derive one. The test runs one way: it can make a number stale, and
    # it can never make a stale number look fresh.
    $dir = $claimsDirShared
    if (-not (Test-Path -LiteralPath $dir)) { return '' }
    $want = $Worktree.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'
    $keys = @()
    foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter *.json -Recurse -File -ErrorAction SilentlyContinue)) {
        try { $d = Read-CoordText $f.FullName | ConvertFrom-Json } catch { continue }
        $w = ''
        if ($d.PSObject.Properties.Name -contains 'worktree' -and $d.worktree) { $w = [string]$d.worktree }
        if (-not $w) { continue }
        $w = $w.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'
        if ($w -ne $want) { continue }
        # The same path on another PC is another tree (docs/COORD-SHARED-ROOT.md). No host is this one.
        if (-not (Test-CoordRecordIsHere $d)) { continue }
        $keys += $f.BaseName
    }
    if ($keys.Count -eq 0) { return 'none' }
    $joined = ($keys | Sort-Object) -join '|'
    $sha = [System.Security.Cryptography.SHA256]::Create()
    try { $b = $sha.ComputeHash([System.Text.Encoding]::UTF8.GetBytes($joined)) } finally { $sha.Dispose() }
    return (-join ($b[0..7] | ForEach-Object { $_.ToString('x2') }))
}

$worktree = (Get-Location).Path
$boxKey   = ConvertTo-BoxKey -Path $worktree
$lanesDir = Join-Path $sharedResolved.Path 'lanes'
$tmpDir   = Join-Path $lanesDir '.tmp'
$file     = Join-Path $lanesDir "$boxKey.json"

$rec = $null
$recFault = $null
if (Test-Path -LiteralPath $file) {
    try {
        $rec = Read-CoordText $file | ConvertFrom-Json -NoEnumerate
        # An empty file, or JSON that is not an object (0, null, "", [], 1, [1, 2]), is not a lane
        # record, and nor is {}: an object with no fields records nothing to judge or keep.
        if ($rec -isnot [System.Management.Automation.PSCustomObject]) {
            $recFault = 'it is not a JSON object'
        } elseif (@($rec.PSObject.Properties).Count -eq 0) {
            $recFault = 'it is an empty JSON object'
        }
    }
    catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] { $rec = $null }
    catch { $recFault = $_.Exception.Message }
}
# FAIL CLOSED. The host refusal below needs the record read, so a record file that exists but cannot
# be read, parsed, or taken as a record must not be taken as no record and replaced. Only a missing
# file means no record. A record with fields but no `host` is still this machine's, as below.
# -Show reads it again on its own.
if (-not $Show -and $recFault) {
    [Console]::Error.WriteLine("lane.ps1: REFUSED -- the lane record at $file exists but could not be read ($recFault). Nothing was written. Read it with -Show; if it is damaged rather than busy, move it out of $lanesDir by hand and state this lane's level again.")
    exit 2
}
# The box key hashes this host as well as the path (mail-key.ps1), so another PC's lane at the same
# path writes its own file, not this one. A record under the old path-only key is not
# read: lane-level.ps1 asks for a fresh level after 15 minutes anyway, so a restatement replaces it.
# A record at THIS key that still names another host got here at least by a copy, by hand, by a
# collision on the short hash, or by a mistyped coord-migrate.ps1 -SourceHost. Taking it over would overwrite that lane's stated level with this one's, so a write refuses
# and says so; -Show only reads, so it prints the record as it is. A record with no `host` was
# written here, as every record before the field was.
if (-not $Show -and $rec -and -not (Test-CoordRecordIsHere $rec)) {
    [Console]::Error.WriteLine("lane.ps1: REFUSED -- $file is the lane record of $(Get-CoordRecordHost $rec), not of this machine ($thisHost). Nothing was written. Read it with -Show; if it is a stray copy rather than that machine's live lane, move it out of $lanesDir by hand and state this lane's level again.")
    exit 2
}
if (-not $rec) {
    $rec = [pscustomobject]@{
        v = 1; boxKey = $boxKey; worktree = $worktree
        statedFree = $null; statedInFlight = $null; statedUtc = $null
        statedBySessionId = $null; statedNote = ''
        tipAtStated = ''; claimHashAtStated = ''; turnsSinceStated = 0
        tipNow = ''; claimHashNow = ''; lastTurnUtc = $null
        promptedUtc = $null; promptCount = 0; askedByDispatcherUtc = $null
    }
}

if ($Show) {
    # -SHOW IS A STRICT READ. Its callers may hold only read access to the root, so it creates no
    # directory and writes no file. (The resolver's down cache is the one exception, and it lives in
    # this clone's own .git, never on the root.) It prints what ONE read of the record found, so the
    # record and its `absent` reason cannot come from two reads that a restatement landed between.
    # The read above keeps no reason, which is why this one stands alone. A found record prints as it
    # is; otherwise the blank record above prints with `absent` saying why, so an unstated lane never
    # reads as a stated one.
    $shown = $null
    $absent = $null
    try {
        $shown = Read-CoordText $file | ConvertFrom-Json -NoEnumerate
        if ($shown -isnot [System.Management.Automation.PSCustomObject]) {
            $absent = "the lane record at $file is not a JSON object"
        }
    } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
        $absent = if (Test-Path -LiteralPath $lanesDir -PathType Container) { "no lane record at $file" }
                  else { "no lanes directory found at $lanesDir, so this root holds no lane record" }
    } catch {
        $absent = "the lane record at $file could not be read: $($_.Exception.Message)"
    }
    if ($absent) {
        # A FRESH blank record, never $rec: $rec may hold what the earlier read found, so a restatement
        # between the two reads would print a stated level beside an `absent` reason. The fields
        # match the blank record above; fold the two together once that read keeps its reason.
        $shown = [pscustomobject]@{
            v = 1; boxKey = $boxKey; worktree = $worktree
            statedFree = $null; statedInFlight = $null; statedUtc = $null
            statedBySessionId = $null; statedNote = ''
            tipAtStated = ''; claimHashAtStated = ''; turnsSinceStated = 0
            tipNow = ''; claimHashNow = ''; lastTurnUtc = $null
            promptedUtc = $null; promptCount = 0; askedByDispatcherUtc = $null
            absent = $absent
        }
    }
    $shown | ConvertTo-Json -Depth 5
    exit 0
}

# Made here, on the write path only, so -Show above creates nothing.
New-Item -ItemType Directory -Force -Path $lanesDir, $tmpDir | Out-Null

$nowUtc = [datetime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ssZ')

if ($Asked) {
    $rec.askedByDispatcherUtc = $nowUtc
} else {
    # statedUtc only ever advances.
    if ($rec.statedUtc) {
        try {
            # COMPARE THE VALUE, DO NOT RE-PARSE IT. ConvertFrom-Json already returns this as a
            # [datetime] with Kind=Utc. [datetime]::Parse() on a DateTime stringifies it to reach the
            # string overload, THE STRING CARRIES NO KIND, and the result comes back Unspecified --
            # so ToUniversalTime() then applies the local offset a SECOND time and a stamp minutes
            # old reads as hours in the future. This guard exists to stop a stamp moving BACKWARDS
            # and instead moved it FORWARD by the offset, which made every restate throw:
            # measured 2026-08-29, a lane could not restate its level for the whole window.
            # A CONVERSION THAT LOOKS LIKE A NO-OP AND DESTROYS THE ONE PROPERTY THAT MADE THE VALUE
            # CORRECT. The string branch is kept for records written before Kind was preserved.
            $existing = if ($rec.statedUtc -is [datetime]) {
                if ($rec.statedUtc.Kind -eq 'Local') { $rec.statedUtc.ToUniversalTime() }
                else { [datetime]::SpecifyKind($rec.statedUtc, [System.DateTimeKind]::Utc) }
            } else {
                [datetime]::Parse([string]$rec.statedUtc, [cultureinfo]::InvariantCulture,
                    [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor
                    [System.Globalization.DateTimeStyles]::AssumeUniversal)
            }
            if ($existing -gt [datetime]::UtcNow) {
                throw "existing statedUtc $($rec.statedUtc) is in the future; refusing to move it backwards"
            }
        } catch [System.FormatException] { }
    }
    $tip = (& git rev-parse HEAD 2>$null)
    if ($LASTEXITCODE -ne 0) { $tip = '' } else { $tip = $tip.Trim() }

    $rec.statedFree        = $Free
    $rec.statedInFlight    = $InFlight
    $rec.statedUtc         = $nowUtc
    $rec.statedBySessionId = $env:CLAUDE_CODE_SESSION_ID
    $rec.statedNote        = $Note
    $rec.tipAtStated       = $tip
    $rec.claimHashAtStated = (Get-ClaimHash -Worktree $worktree)
    $rec.turnsSinceStated  = 0
    $rec.tipNow            = $tip
    $rec.claimHashNow      = $rec.claimHashAtStated
}
$rec.worktree = $worktree
$rec.boxKey   = $boxKey
# A record written before the ceiling was retired carries `capacity`, 4 by default. Drop it on the
# next write, so no stored lane level still names a cap for a reader to apply.
$rec.PSObject.Properties.Remove('capacity')
# docs/COORD-SHARED-ROOT.md: a reader on another PC must be able to tell this lane is not its own.
$rec | Add-Member -NotePropertyName host -NotePropertyValue $thisHost -Force

$tmp = Join-Path $tmpDir ("$boxKey." + [guid]::NewGuid().ToString('n') + '.json')
($rec | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $tmp -Encoding UTF8 -NoNewline
# One atomic rename, retried on an SMB sharing violation (coord-root.ps1). Not Move-Item -Force,
# which deletes first, so the lane hook could read the level as missing.
Move-CoordFileReplace -Source $tmp -Destination $file -ReplaceReadOnly

if ($Asked) {
    Write-Host "lane: recorded that a dispatcher asked. No number written."
} else {
    Write-Host "lane: $boxKey -- $Free free / $InFlight in flight, stated $nowUtc"
    if (-not $Note) { Write-Host "      (no note. A note is what makes the number auditable later.)" }
}
exit 0
