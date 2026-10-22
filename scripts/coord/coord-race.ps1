# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Race exclusive file creation against another PC on one shared directory, then judge the result.

.DESCRIPTION
    WHY THIS EXISTS. docs/COORD-SHARED-ROOT.md, Migration steps 2 and 4, and "What MEFORDEV01
    measured". Claims and allocations rely on CreateNew failing when the file exists. MEFORDEV01 ran
    that race with two processes on ONE client, and it held. The part no single-client test sees is
    two clients' caches. So this runs one process on EACH PC against the same directory on the share.

    RACE MODE. Each PC runs this with its own -Tag and the same -StartAtUtc. It waits until that
    time, then tries CreateNew on slot-1 to slot-<Slots> in -Dir, writing its tag into each slot it
    wins. It writes what it won to <Dir>/result-<Tag>.json. It refuses to start when any slot file or
    its own result file is already there, because a stale slot reads as a loss for both sides. Clock
    skew between the PCs shifts the start; keep it well under the race's length, or the two do not
    overlap and the run proves nothing. The result records each side's actual start time.

    COMPARE MODE (-Compare). Reads every result-*.json in -Dir and reports, per slot: a DOUBLE WINNER
    (two results claim it), an EMPTY SLOT (no result claims it), and a MISMATCH (the slot file's
    content is not the tag that claims it). Exactly one winner per slot, with matching content, is the
    pass.

    NEVER POINT THIS AT A LIVE REGISTRY. -Dir is a probe directory of its own, made fresh per run.
    Running it on the share is the owner's call (migration step 2).

.PARAMETER Dir
    The probe directory. It must exist.

.PARAMETER Tag
    This side's name, for example the PC's name. Letters, digits, dot, dash and underscore only.

.PARAMETER StartAtUtc
    The shared start time, as an ISO 8601 time with an offset or a Z, for example
    2026-10-22T15:00:00Z. Refused if more than an hour away.

.PARAMETER Slots
    How many slots to race. Default 100.

.PARAMETER Compare
    Judge the result files in -Dir instead of racing.

.PARAMETER Json
    With -Compare, print one machine-readable JSON summary instead of the report.

.NOTES
    Exit codes:
      0  race: finished and wrote its result. Compare: every slot has one winner with matching content.
      1  race: at least one slot failed for a reason other than "it exists", such as access denied.
         The result file still records it.
      2  bad arguments, a stale slot or result in -Dir, or (compare) fewer than two result files.
      3  compare: a double winner, an empty slot or a content mismatch. Also the cloud-session
         refusal, which prints only its one stderr line.

.EXAMPLE
    # On each PC, the same time, a different tag:
    pwsh -NoProfile -File scripts\coord\coord-race.ps1 -Dir \\server\share\race-1 -Tag ALIENWARE -StartAtUtc 2026-10-22T15:00:00Z
    # Then, from either PC:
    pwsh -NoProfile -File scripts\coord\coord-race.ps1 -Compare -Dir \\server\share\race-1
#>
[CmdletBinding()]
param(
    # None is Mandatory: a Mandatory prompt hangs a caller whose stdin stays open (tests/_no_prompt.py).
    # Missing values are refused below, after the cloud refusal.
    [string]$Dir,
    [string]$Tag,
    [string]$StartAtUtc,
    [int]$Slots = 100,
    [switch]$Compare,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'

# A CLAUDE CODE CLOUD SESSION REACHES NO OTHER SESSION THROUGH THIS SCRIPT: its --git-common-dir is
# the VM's own clone, and the share is not on its network. CLAUDE.md section 5, "A cloud session is a
# Builder in its own session"; tests/test_coord_cloud_refusal.py holds the copies equal.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('coord-race.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

function Stop-Usage([string]$Message) {
    [Console]::Error.WriteLine("coord-race.ps1: $Message")
    exit 2
}

if (-not $Dir) { Stop-Usage 'needs -Dir <probe dir>.' }
if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { Stop-Usage "-Dir '$Dir' is not a directory." }
$Dir = [System.IO.Path]::GetFullPath($Dir)
$slotPattern = [regex]'\Aslot-(\d+)\z'

if ($Compare) {
    $results = @(Get-ChildItem -LiteralPath $Dir -Filter 'result-*.json' -File)
    if ($results.Count -lt 2) { Stop-Usage "found $($results.Count) result file(s) in '$Dir'; a race needs two." }
    $claims = @{}
    $sides = [System.Collections.Generic.List[object]]::new()
    $maxSlots = 0
    foreach ($f in $results) {
        try { $r = [System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json -ErrorAction Stop }
        catch { Stop-Usage "$($f.Name) is not readable JSON: $($_.Exception.Message)" }
        if (-not $r.tag -or $null -eq $r.won) { Stop-Usage "$($f.Name) has no tag or no won list." }
        $tagName = [string]$r.tag
        if ([int]$r.slots -gt $maxSlots) { $maxSlots = [int]$r.slots }
        $won = @($r.won | ForEach-Object { [int]$_ })
        foreach ($n in $won) {
            if (-not $claims.ContainsKey($n)) { $claims[$n] = [System.Collections.Generic.List[string]]::new() }
            $claims[$n].Add($tagName)
        }
        $sides.Add([ordered]@{ tag = $tagName; host = [string]$r.host; slots = [int]$r.slots; won = $won.Count; errors = @($r.errors).Count; startedAtUtc = [string]$r.startedAtUtc })
    }
    # The slot files too: one with no claimant is as wrong as a claimed slot with no file.
    foreach ($s in @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $slotPattern.IsMatch($_.Name) })) {
        $n = [int]$slotPattern.Match($s.Name).Groups[1].Value
        if ($n -gt $maxSlots) { $maxSlots = $n }
    }
    $double = [System.Collections.Generic.List[object]]::new()
    $empty = [System.Collections.Generic.List[int]]::new()
    $mismatch = [System.Collections.Generic.List[object]]::new()
    for ($n = 1; $n -le $maxSlots; $n++) {
        $file = Join-Path $Dir "slot-$n"
        $content = $null
        if (Test-Path -LiteralPath $file -PathType Leaf) { $content = ([System.IO.File]::ReadAllText($file)).Trim() }
        # @() around the whole if: an if's output unrolls, so one claimant would come back a bare string.
        $who = @(if ($claims.ContainsKey($n)) { $claims[$n] })
        if ($who.Count -gt 1) { $double.Add([ordered]@{ slot = $n; tags = $who; content = $content }); continue }
        if ($who.Count -eq 0) { $empty.Add($n); continue }
        if ($content -cne $who[0]) { $mismatch.Add([ordered]@{ slot = $n; claimedBy = $who[0]; content = $content }) }
    }
    $exit = if ($double.Count -or $empty.Count -or $mismatch.Count) { 3 } else { 0 }
    if ($Json) {
        [ordered]@{
            dir = $Dir; slots = $maxSlots; sides = @($sides)
            doubleWinners = @($double); emptySlots = @($empty); mismatches = @($mismatch); exit = $exit
        } | ConvertTo-Json -Depth 5
        exit $exit
    }
    Write-Host "coord-race compare: $Dir, $maxSlots slot(s)"
    foreach ($s in $sides) {
        Write-Host ("  {0} on {1}: won {2} of {3}, {4} error(s), started {5}" -f $s.tag, $s.host, $s.won, $s.slots, $s.errors, $s.startedAtUtc)
    }
    Write-Host "  double winners: $($double.Count)"
    foreach ($d in $double) { Write-Host "    slot-$($d.slot): $($d.tags -join ', ') (file says '$($d.content)')" }
    Write-Host "  empty slots: $($empty.Count)"
    if ($empty.Count) { Write-Host "    $(($empty | ForEach-Object { "slot-$_" }) -join ', ')" }
    Write-Host "  content mismatches: $($mismatch.Count)"
    foreach ($m in $mismatch) { Write-Host "    slot-$($m.slot): claimed by $($m.claimedBy), file says '$($m.content)'" }
    Write-Host $(if ($exit -eq 0) { 'PASS: every slot has exactly one winner, and its file names that winner.' } else { 'FAIL: exclusive create did not hold on this directory.' })
    exit $exit
}

if (-not $Tag -or $Tag -notmatch '\A[A-Za-z0-9._-]+\z') { Stop-Usage 'needs -Tag <name>: letters, digits, dot, dash and underscore only.' }
if (-not $StartAtUtc) { Stop-Usage 'needs -StartAtUtc <ISO 8601 time>, the same on every side.' }
if ($Slots -lt 1 -or $Slots -gt 100000) { Stop-Usage '-Slots must be between 1 and 100000.' }
$start = [DateTimeOffset]::MinValue
# An offset or a Z is required: a bare local time means a different instant on each PC.
if ($StartAtUtc -notmatch '(Z|[+-]\d\d:?\d\d)\z' -or
    -not [DateTimeOffset]::TryParse($StartAtUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$start)) {
    Stop-Usage "-StartAtUtc '$StartAtUtc' is not an ISO 8601 time with an offset or a Z."
}
$wait = $start.UtcDateTime - [DateTime]::UtcNow
if ($wait.TotalHours -gt 1) { Stop-Usage "-StartAtUtc is $([int]$wait.TotalMinutes) minutes away; an hour is the limit." }

$resultFile = Join-Path $Dir "result-$Tag.json"
if (Test-Path -LiteralPath $resultFile) { Stop-Usage "$resultFile already exists; race in a fresh directory." }
$stale = @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $slotPattern.IsMatch($_.Name) })
if ($stale.Count) { Stop-Usage "'$Dir' already holds $($stale.Count) slot file(s); race in a fresh directory." }

# Sleep most of the wait, then spin, so both sides leave the gate within a millisecond or two of it.
while ($true) {
    $left = ($start.UtcDateTime - [DateTime]::UtcNow).TotalMilliseconds
    if ($left -le 0) { break }
    if ($left -gt 50) { Start-Sleep -Milliseconds ([int][Math]::Min($left - 30, 1000)) } else { [System.Threading.Thread]::SpinWait(1000) }
}
$startedAt = [DateTime]::UtcNow

$tagBytes = [System.Text.Encoding]::UTF8.GetBytes($Tag)
$won = [System.Collections.Generic.List[int]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$lost = 0
for ($n = 1; $n -le $Slots; $n++) {
    $path = Join-Path $Dir "slot-$n"
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
        try { $fs.Write($tagBytes, 0, $tagBytes.Length) } finally { $fs.Dispose() }
        $won.Add($n)
    } catch [System.IO.IOException] {
        # The file exists: the other side won it. That is the expected loss, not an error.
        if (Test-Path -LiteralPath $path) { $lost++ }
        else { $errors.Add([ordered]@{ slot = $n; error = $_.Exception.Message }) }
    } catch {
        $errors.Add([ordered]@{ slot = $n; error = $_.Exception.Message })
    }
}
$finishedAt = [DateTime]::UtcNow

$result = [ordered]@{
    tag = $Tag; host = [Environment]::MachineName; slots = $Slots
    startAtUtc = $start.UtcDateTime.ToString('o'); startedAtUtc = $startedAt.ToString('o'); finishedAtUtc = $finishedAt.ToString('o')
    won = @($won); lost = $lost; errors = @($errors)
} | ConvertTo-Json -Depth 4
$fsr = [System.IO.File]::Open($resultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
try {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($result)
    $fsr.Write($bytes, 0, $bytes.Length)
} finally { $fsr.Dispose() }

Write-Host "coord-race ${Tag}: won $($won.Count), lost $lost, $($errors.Count) error(s), of $Slots slot(s). Result: $resultFile"
exit $(if ($errors.Count) { 1 } else { 0 })
