# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    See what is in the handoffs directory, and retire one entry at a time with four refusals in the
    way. Read-only except for -Retire, which MOVES and never deletes.

.DESCRIPTION
    WHY THIS EXISTS. `.git/mefor-coord/handoffs/` grows without bound and nothing can prune it.
    Measured 2026-08-22: 41 entries, all written that day, after a MANUAL cleanup at 12:03 tarred 224
    older ones away. The archived names spanned six days, so the rate is roughly 35 a day.

    THE HARM IS NOT DISK. It is that a stale document reads as a live instruction to an arriving
    seat. The 12:03 retirement README says so in its own words -- it singles out `RESUME-HERE.md`,
    `HOLD-149-defects.md`, `UNPUSHED-WORK-LEDGER.md` and a file literally named
    `COORDINATOR-HANDOFF-LIVE.md` whose text claims to be "only what is TRUE RIGHT NOW" and was last
    written two weeks earlier.

    WHY THIS TOOL DOES NOT SWEEP. Ownership cannot be recovered after the fact. Measured the same
    day over the real directory, with the matcher's positive and negative controls both passing:

        exactly one owner derivable   11 of 37   (29 percent)
        ambiguous                      3
        NO owner evidence at all      23 of 37   (62 percent)

    A first pass claimed 14 unique. Seven were false, because the primary checkout's worktree
    basename is literally `messagefoundry`, so any document mentioning the project matched it. A
    second, independent instrument run by another reviewer disagreed with this one AND with itself:
    all six `2026-08-22-DISPATCHER-*` files matched a box whose writer last ran four days before the
    files were written. TWO INSTRUMENTS, BOTH CONFIDENT, BOTH WRONG, DISAGREEING WITH EACH OTHER.

    So `-Report` prints hints and never acts on them, and `-Retire` is a human decision, one entry at
    a time. A machine that invents an owner produces a record that looks owned and says nothing --
    the hollow-record failure `seat.ps1`'s own header refuses for goals.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\handoff.ps1 -Report

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\handoff.ps1 -Retire 2026-08-13-old-note.md
#>
[CmdletBinding(DefaultParameterSetName = 'Report')]
param(
    # Print the box directory this worktree should write into, creating it if absent.
    [Parameter(ParameterSetName = 'Where', Mandatory)][switch]$Where,

    [Parameter(ParameterSetName = 'Report')][switch]$Report,
    [Parameter(ParameterSetName = 'Report')][switch]$Json,

    # Move ONE entry to _retired-<date>/. Refuses on any hold unless -Force.
    [Parameter(ParameterSetName = 'Retire', Mandatory)][string]$Retire,
    [Parameter(ParameterSetName = 'Retire')][switch]$Force,

    # Overridable so tests exercise the real logic against a fixture instead of the live directory.
    [string]$CoordDir,
    [string[]]$ConfigRoot,
    [string]$RepoHint,
    # Hours. Matches box-activity.ps1's default; see its comment on why it is generous.
    [double]$FreshHours = 24
)

$ErrorActionPreference = 'Stop'
. "$PSScriptRoot\mail-key.ps1"
. "$PSScriptRoot\box-activity.ps1"

# ------------------------------------------------------------------------------------------------
# Location.
# ------------------------------------------------------------------------------------------------

function Resolve-CoordDir {
    param([string]$Override)
    if ($Override) { return $Override }
    $common = & git @( if ($RepoHint) { @('-C', $RepoHint) } else { @() } ) rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $common) {
        throw "Not inside a git worktree: refusing to guess where the coordination state lives."
    }
    return (Join-Path $common.Trim() 'mefor-coord')
}

$coord = Resolve-CoordDir -Override $CoordDir
$handoffs = Join-Path $coord 'handoffs'
$seatsDir = Join-Path $coord 'seats'

# ------------------------------------------------------------------------------------------------
# -Where.
# ------------------------------------------------------------------------------------------------

if ($Where) {
    $wt = & git @( if ($RepoHint) { @('-C', $RepoHint) } else { @() } ) rev-parse --show-toplevel 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $wt) { throw "Not inside a git worktree." }
    # ConvertTo-BoxKey is mail-key.ps1's, dot-sourced, never inlined. ONE definition of a box key --
    # a second copy is the drift CLAUDE.md section 11 forbids, and the copy nobody tests is the one
    # that breaks.
    $box = ConvertTo-BoxKey -Path $wt.Trim()
    $dir = Join-Path $handoffs $box
    if (-not (Test-Path -LiteralPath $dir)) { New-Item -ItemType Directory -Path $dir -Force | Out-Null }
    Write-Output $dir
    exit 0
}

# ------------------------------------------------------------------------------------------------
# Read the directory.
# ------------------------------------------------------------------------------------------------

$now = [datetime]::UtcNow

$entries = @()
if (Test-Path -LiteralPath $handoffs) {
    foreach ($i in @(Get-ChildItem -LiteralPath $handoffs -Force -EA SilentlyContinue)) {
        $isDir = $i.PSIsContainer
        $bytes = if ($isDir) {
            (Get-ChildItem -LiteralPath $i.FullName -Recurse -File -EA SilentlyContinue |
                Measure-Object -Property Length -Sum).Sum
        } else { $i.Length }
        $entries += [pscustomobject]@{
            Name    = $i.Name
            Path    = $i.FullName
            IsDir   = $isDir
            Bytes   = [long]($bytes | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
            AgeH    = [math]::Round(($now - $i.LastWriteTimeUtc).TotalHours, 2)
            Head    = ''
            Text    = ''
            Flags   = @()
            Box     = $null
        }
    }
}

# TWO WINDOWS, BECAUSE THEY ANSWER TWO DIFFERENT QUESTIONS. Reading one buffer for both is how the
# first draft of this file over-flagged, and it is SDS-3.8 in miniature: the instrument worked and
# the question was wrong.
#
#   Head (HEAD_BYTES) -- "does this OPEN with an instruction". A standing instruction lives in the
#   title and the first line or two. Calibrated against the real 12 undated entries: the flag count
#   is 5 at 200, 300 and 500 bytes and climbs to 7 at 1000 and 10 at 4000. The extra five at 4000 are
#   narration deep in a body -- a document that mentions "pending" in paragraph nine is not
#   instructing anybody. A plateau across 200-500 is the evidence that 300 is not a knife-edge pick.
#
#   Text (full) -- "does this NAME another entry". A citation is just as load-bearing on the last
#   line as the first, so this one cannot be windowed at all.
$HEAD_BYTES = 300
$TEXT_CAP = 4MB
$textCapped = 0
foreach ($e in $entries) {
    if ($e.IsDir) { continue }
    try {
        $fs = [System.IO.File]::OpenRead($e.Path)
        try {
            $want = [int][math]::Min([long]$TEXT_CAP, $fs.Length)
            $buf = New-Object byte[] $want
            $n = $fs.Read($buf, 0, $want)
            $e.Text = [System.Text.Encoding]::UTF8.GetString($buf, 0, $n)
            $e.Head = $e.Text.Substring(0, [math]::Min($HEAD_BYTES, $e.Text.Length))
        } finally { $fs.Dispose() }
    } catch { $e.Text = ''; $e.Head = '' }
    # A cap nobody logs reads as full coverage. The receipt carries this count for the same reason
    # fleet.ps1 prints its denominators.
    if ($e.Bytes -gt $TEXT_CAP) { $textCapped++ }
}

# ------------------------------------------------------------------------------------------------
# The four holds. Each is a REFUSAL, so a false positive costs a -Force and a false negative costs a
# broken reference -- the asymmetry is deliberate and every predicate errs toward holding.
# ------------------------------------------------------------------------------------------------

# CITED: another entry names this one. Measured 2026-08-22: 16 citation edges, 15 of 38 entries
# cited by a sibling. The concrete case that forced this hold --
# 2026-08-22-ROLES-HANDOVER-common-split.md names the 432 KB
# 2026-08-22-ROLES-common-split-and-trap-retraction.patch beside it, so moving the patch alone
# leaves a handover document instructing a reader to apply a file that is no longer there.
$byName = @{}
foreach ($e in $entries) { $byName[$e.Name] = $e }
foreach ($e in $entries) {
    if (-not $e.Text) { continue }
    foreach ($other in $entries) {
        if ($other.Name -eq $e.Name) { continue }
        if ($e.Text.Contains($other.Name)) {
            if ($other.Flags -notcontains 'CITED') { $other.Flags += 'CITED' }
        }
    }
}

# POINTED-AT: a seat record's handoff pointer names it.
$pointed = @{}
if (Test-Path -LiteralPath $seatsDir) {
    foreach ($f in @(Get-ChildItem -LiteralPath $seatsDir -Recurse -Filter *.json -File -EA SilentlyContinue)) {
        try { $rec = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
        catch { continue }
        if ($rec.handoff -and $rec.handoff.path) { $pointed[(Split-Path ([string]$rec.handoff.path) -Leaf)] = $true }
    }
}
foreach ($e in $entries) { if ($pointed.ContainsKey($e.Name)) { $e.Flags += 'POINTED-AT' } }

# READS-AS-LIVE: an undated name whose head gives an instruction. This is M2's harm, and it is
# identifiable BY SHAPE with no owner derivation at all -- which is why it survives while every
# ownership instrument failed.
#
# THE MARKER LIST IS A FLOOR, NOT A CLOSED SET. Section 11's "prefer at least to an enumeration"
# applies: these are the shapes present in the three entries that carry the flag today
# (LIAISON-QUEUE-POINTER.md, README-NAMING.md, STEWARD-resume-96c816.py), and a fourth shape will
# exist. The flag is a HOLD, so missing one costs a document that retires without a second look and
# adding one costs a -Force. -Report prints the count so the floor is visible rather than implied.
$liveMarkers = @(
    'READ TH', 'READ IT', 'RESUME', 'START HERE', 'DO NOT', 'REFUSE',
    'NEXT STEP', 'TODO', 'PENDING', 'UNPUSHED', 'IS NOT IN THIS', 'THE RULE LIVES',
    'RIGHT NOW', 'STILL OPEN', 'HOLD '
)
foreach ($e in $entries) {
    if ($e.IsDir) { continue }
    # A date in the NAME is the convention's own signal that the document is a dated record rather
    # than standing instruction. README-NAMING.md, added to this directory the same day, requires it.
    if ($e.Name -match '\d{4}-\d{2}-\d{2}') { continue }
    $headUpper = $e.Head.ToUpperInvariant()
    if (@($liveMarkers | Where-Object { $headUpper.Contains($_) }).Count -gt 0) {
        $e.Flags += 'READS-AS-LIVE'
    }
}

# STALE-IN-A-LIVE-BOX: a box directory's own HANDOFF.md older than the box's newest activity by more
# than FreshHours. This is the harm a liveness fence structurally CANNOT see -- the box is live, so
# every fence says do not touch, while the document inside it went stale a day ago. Zero today,
# because no box directories exist until the naming contract lands.
foreach ($e in $entries) {
    if (-not $e.IsDir) { continue }
    $e.Box = $e.Name
    $doc = Join-Path $e.Path 'HANDOFF.md'
    if (-not (Test-Path -LiteralPath $doc -PathType Leaf)) { continue }
    $act = Get-BoxActivity -BoxKey $e.Name -WorktreePath '' -SeatsDir $seatsDir -ConfigRoot $ConfigRoot -RepoHint $RepoHint -FreshHours $FreshHours -Now $now
    $docAgeH = [math]::Round(($now - (Get-Item -LiteralPath $doc).LastWriteTimeUtc).TotalHours, 2)
    if ($null -ne $act.WriterAliveAgeH -and ($docAgeH - $act.WriterAliveAgeH) -gt $FreshHours) {
        $e.Flags += 'STALE-IN-A-LIVE-BOX'
    }
}

# ------------------------------------------------------------------------------------------------
# Denominators. PRINTED BEFORE ANY VERDICT, following fleet.ps1's receipt: a reader must be able to
# tell "nothing found" from "nothing looked", and those render identically without these lines.
# ------------------------------------------------------------------------------------------------

$dirs = @($entries | Where-Object { $_.IsDir })
$files = @($entries | Where-Object { -not $_.IsDir })
$totalBytes = ($entries | Measure-Object -Property Bytes -Sum).Sum
$rootsSeen = @(Get-ClaudeConfigRoots -ConfigRoot $ConfigRoot)
$flagged = @($entries | Where-Object { $_.Flags.Count -gt 0 })

$receipt = [ordered]@{
    renderedAtUtc  = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    handoffsDir    = $handoffs
    dirExists      = (Test-Path -LiteralPath $handoffs)
    entries        = $entries.Count
    files          = $files.Count
    boxDirectories = $dirs.Count
    bytes          = [long]($totalBytes | ForEach-Object { if ($null -eq $_) { 0 } else { $_ } })
    configRoots    = $rootsSeen.Count
    fenceAvailable = ($rootsSeen.Count -gt 0)
    seatRecords    = @(if (Test-Path -LiteralPath $seatsDir) { Get-ChildItem -LiteralPath $seatsDir -Recurse -Filter *.json -File -EA SilentlyContinue } else { @() }).Count
    cited          = @($entries | Where-Object { $_.Flags -contains 'CITED' }).Count
    pointedAt      = @($entries | Where-Object { $_.Flags -contains 'POINTED-AT' }).Count
    readsAsLive    = @($entries | Where-Object { $_.Flags -contains 'READS-AS-LIVE' }).Count
    staleInLiveBox = @($entries | Where-Object { $_.Flags -contains 'STALE-IN-A-LIVE-BOX' }).Count
    heldTotal      = $flagged.Count
    liveMarkerCount = $liveMarkers.Count
    headBytes       = $HEAD_BYTES
    textCapped      = $textCapped
}

# ------------------------------------------------------------------------------------------------
# -Retire.
# ------------------------------------------------------------------------------------------------

if ($PSCmdlet.ParameterSetName -eq 'Retire') {
    $target = $entries | Where-Object { $_.Name -eq $Retire } | Select-Object -First 1
    if (-not $target) {
        # Resolve against every manifest before saying no. The 12:03 precedent tarred 224 names away
        # and its README lists only the tarball, which is exactly why the dangling seat pointer could
        # not be resolved against it.
        $found = @()
        foreach ($m in @(Get-ChildItem -LiteralPath $coord -Recurse -Filter MANIFEST.tsv -File -EA SilentlyContinue)) {
            foreach ($line in @(Get-Content -LiteralPath $m.FullName -EA SilentlyContinue)) {
                if ($line -like "*`t$Retire`t*" -or $line -like "*`t$Retire") { $found += $m.FullName }
            }
        }
        if ($found.Count -gt 0) {
            Write-Output "ALREADY RETIRED: $Retire"
            $found | Select-Object -Unique | ForEach-Object { Write-Output "  listed in $_" }
            exit 0
        }
        Write-Error "handoff.ps1: no entry named '$Retire' in $handoffs, and no manifest records retiring one."
        exit 2
    }

    if ($target.Flags.Count -gt 0 -and -not $Force) {
        Write-Output "REFUSED: $($target.Name)"
        foreach ($f in $target.Flags) {
            $why = switch ($f) {
                'CITED' { 'another entry in this directory names it; moving it breaks a reference that still reads as working' }
                'POINTED-AT' { 'a seat record names it, so fleet.ps1 would send a replacement seat to it' }
                'READS-AS-LIVE' { 'undated name and an instruction-shaped head; this is the shape that gets obeyed by an arriving seat' }
                'STALE-IN-A-LIVE-BOX' { 'the box is active but this document is not; a liveness fence cannot see this and will keep saying do not touch' }
                default { 'held' }
            }
            Write-Output "  $f -- $why"
        }
        Write-Output ""
        Write-Output "Re-run with -Force to override. It will name the flag it overrode."
        exit 1
    }

    $stamp = $now.ToString('yyyy-MM-dd')
    $destDir = Join-Path (Join-Path $coord "_retired-$stamp") 'handoffs'
    if (-not (Test-Path -LiteralPath $destDir)) { New-Item -ItemType Directory -Path $destDir -Force | Out-Null }

    $compress = ($target.Flags -contains 'READS-AS-LIVE') -and -not $target.IsDir
    $srcBytes = $target.Bytes
    if ($compress) {
        # COMPRESSED, NOT MOVED LOOSE. A loose move relocates the harm instead of removing it, and the
        # precedent proves it: COORDINATOR-HANDOFF-LIVE.md, the file its own retirement README singles
        # out as the worst offender, is sitting uncompressed in _retired-2026-08-22/ right now, where
        # it still reads exactly as it did before.
        $dest = Join-Path $destDir "$($target.Name).tar.gz"
        tar -czf $dest -C (Split-Path $target.Path -Parent) $target.Name
        if ($LASTEXITCODE -ne 0) { throw "tar failed for $($target.Name); nothing was moved." }
        if (-not (Test-Path -LiteralPath $dest)) { throw "archive not created for $($target.Name); nothing was moved." }
        Remove-Item -LiteralPath $target.Path -Force
    } else {
        $dest = Join-Path $destDir $target.Name
        if (Test-Path -LiteralPath $dest) { throw "destination already exists: $dest -- refusing to overwrite." }
        Copy-Item -LiteralPath $target.Path -Destination $dest -Recurse -Force
        # VERIFY BEFORE REMOVING. A move that reported success over a short copy would be the one
        # unrecoverable outcome this whole tool exists to avoid.
        $destBytes = if ($target.IsDir) {
            (Get-ChildItem -LiteralPath $dest -Recurse -File -EA SilentlyContinue | Measure-Object -Property Length -Sum).Sum
        } else { (Get-Item -LiteralPath $dest).Length }
        if ([long]$destBytes -ne [long]$srcBytes) {
            Remove-Item -LiteralPath $dest -Recurse -Force -EA SilentlyContinue
            throw "copy verified WRONG for $($target.Name): $srcBytes bytes in, $destBytes out. Source untouched."
        }
        Remove-Item -LiteralPath $target.Path -Recurse -Force
    }

    $manifest = Join-Path (Join-Path $coord "_retired-$stamp") 'MANIFEST.tsv'
    if (-not (Test-Path -LiteralPath $manifest)) {
        Add-Content -LiteralPath $manifest -Encoding utf8 -Value "retiredAtUtc`tname`tbytes`tflags`tforced`tdestination"
    }
    # DOUBLE quotes, and that is the whole point. A single-quoted PowerShell string does no escape
    # processing, so '`t' is a literal backtick followed by 't' and the file is not a TSV at all.
    # The header two lines up used double quotes and the rows did not, so the two disagreed inside
    # one file -- caught by the round-trip test looking a name back up and not finding it.
    $row = "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $now.ToString('yyyy-MM-ddTHH:mm:ssZ'), $target.Name, $srcBytes,
        (($target.Flags -join ',') -replace '^$', 'none'), ([string]$Force.IsPresent), $dest
    Add-Content -LiteralPath $manifest -Encoding utf8 -Value $row

    $readme = Join-Path (Join-Path $coord "_retired-$stamp") 'README.md'
    if (-not (Test-Path -LiteralPath $readme)) {
        Add-Content -LiteralPath $readme -Encoding utf8 -Value @"
# Retired coordination state, $stamp

NOTHING HERE WAS DELETED. Everything was MOVED, and restoring is a move back.
Every name is listed in MANIFEST.tsv beside this file -- that is the improvement on the
2026-08-22 retirement, whose README named a tarball and not the 224 names inside it, which
is why a dangling seat pointer could not be resolved against it.

## Retired entries
"@
    }
    $restore = if ($compress) {
        "tar -xzf `"$dest`" -C `"$handoffs`""
    } else {
        "Move-Item -LiteralPath `"$dest`" -Destination `"$handoffs`""
    }
    Add-Content -LiteralPath $readme -Encoding utf8 -Value @"

- **$($target.Name)** ($srcBytes bytes, retired $($now.ToString('yyyy-MM-ddTHH:mm:ssZ'))$(if ($target.Flags.Count) { ", flags: $($target.Flags -join ', ')" })$(if ($Force) { ", FORCED" }))
  Restore: ``$restore``
"@

    Write-Output "RETIRED: $($target.Name) -> $dest"
    if ($Force -and $target.Flags.Count -gt 0) {
        Write-Output "FORCED OVER: $($target.Flags -join ', ')"
    }
    Write-Output "Manifest: $manifest"
    Write-Output "Restore : $restore"
    exit 0
}

# ------------------------------------------------------------------------------------------------
# -Report.
# ------------------------------------------------------------------------------------------------

if ($Json) {
    [ordered]@{
        receipt = $receipt
        entries = @($entries | Select-Object Name, Bytes, AgeH, IsDir, @{n = 'Flags'; e = { @($_.Flags) } })
    } | ConvertTo-Json -Depth 6
    exit 0
}

$out = @()
$out += "handoffs   $handoffs"
if (-not $receipt.dirExists) {
    # "Nothing found" and "nothing looked" must not render the same. This is the branch that keeps
    # them apart, and it says which one it is in its first four words.
    $out += "THE DIRECTORY DOES NOT EXIST. Nothing was scanned. This is not the same as it being empty."
    $out -join "`n"
    exit 0
}
$out += ("scanned    {0} entries ({1} files, {2} box directories), {3:N0} bytes" -f $receipt.entries, $receipt.files, $receipt.boxDirectories, $receipt.bytes)
$out += ("fence      {0} ({1} config roots, {2} seat records)" -f $(if ($receipt.fenceAvailable) { 'AVAILABLE' } else { 'UNAVAILABLE -- every activity verdict below is a guess' }), $receipt.configRoots, $receipt.seatRecords)
$out += ("holds      {0} entries held: {1} cited, {2} pointed-at, {3} reads-as-live, {4} stale-in-a-live-box" -f $receipt.heldTotal, $receipt.cited, $receipt.pointedAt, $receipt.readsAsLive, $receipt.staleInLiveBox)
$out += ("markers    reads-as-live tested against {0} shapes -- A FLOOR, not a closed set" -f $receipt.liveMarkerCount)
$out += ""
if ($receipt.entries -eq 0) {
    $out += "The directory is EMPTY. Scanned and found nothing, which is different from the line above."
    $out -join "`n"
    exit 0
}
foreach ($e in ($entries | Sort-Object -Property @{e = { $_.Flags.Count }; Descending = $true }, Name)) {
    $kind = if ($e.IsDir) { 'dir ' } else { 'file' }
    $out += ("{0}  {1,10:N0} B  {2,7:N1}h  {3}" -f $kind, $e.Bytes, $e.AgeH, $e.Name)
    if ($e.Flags.Count -gt 0) { $out += ("                                HOLD: {0}" -f ($e.Flags -join ', ')) }
}
$out += ""
$out += "Nothing above was moved. -Report never moves anything."
$out += "To retire one:  handoff.ps1 -Retire <name>     (it refuses on any HOLD; -Force names what it overrode)"
$out -join "`n"
