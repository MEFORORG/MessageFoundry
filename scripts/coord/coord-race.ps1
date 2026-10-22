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

    RACE MODE. Each PC runs this with its own -Tag and the same -StartAtUtc. It tries CreateNew on
    slot-1 to slot-<Slots> in -Dir, writing its tag into each slot it wins, and records what it won in
    <Dir>/result-<Tag>.json. It refuses to start when any slot file or its own result file is already
    there, because a stale slot reads as a loss for both sides.

    EACH SLOT HAS ITS OWN GATE, WITH JITTER. Slot n opens at StartAtUtc + (n-1)*GapMs, plus a random
    delay below GapMs drawn per slot and per side. Walking the slots back to back would not race: the
    side that loses slot 1 pays an error and falls behind, and from then on it only ever finds files
    the other side already made. The gates keep the two sides level, and the jitter makes some slots
    arrive within one round trip of each other even when the two clocks differ by a few
    milliseconds. GapMs 0 walks back to back.

    COMPARE MODE (-Compare). Reads every result-*.json in -Dir and reports, per slot: a DOUBLE WINNER
    (two results claim it), an EMPTY SLOT (no result claims it), and a MISMATCH (the slot file's
    content is not the tag that claims it). It also checks that the run was a race at all. At least:
    every side had the same start time and slot count, none started more than max(GapMs, 20) ms
    late by its own clock, none recorded an error, the time windows overlap, and every side won at
    least one slot. A run that fails those proves nothing either way.

    NEVER POINT THIS AT A LIVE REGISTRY. -Dir is a probe directory of its own, made fresh per run.
    Running it on the share is the owner's call (migration step 2).

.PARAMETER Dir
    The probe directory. It must exist.

.PARAMETER Tag
    This side's name, for example the PC's name. Letters, digits, dot, dash and underscore only.

.PARAMETER StartAtUtc
    The shared start time, as an ISO 8601 time with an offset or a Z, for example
    2026-10-22T15:00:00Z. Refused if more than an hour ahead or more than two seconds past.

.PARAMETER Slots
    How many slots to race. Default 100.

.PARAMETER GapMs
    Milliseconds between slot gates, and the width of each slot's jitter. Default 20, so 100 slots
    take about two seconds.

.PARAMETER Compare
    Judge the result files in -Dir instead of racing.

.PARAMETER Json
    With -Compare, print one machine-readable JSON summary instead of the report.

.NOTES
    Exit codes:
      0  race: finished and wrote its result. Compare: a valid race, and every slot has one winner
         with matching content.
      1  race: at least one slot failed for a reason other than "it exists", such as access denied.
         The result file still records it.
      2  bad arguments, a stale slot or result in -Dir, or (compare) fewer than two result files, or
         a run that was not a valid race, or pwsh older than 7.5.
      3  compare: a double winner; or an empty slot or a content mismatch when no side recorded an
         error, since an error explains both. Wins over 2. Also the cloud-session refusal, which
         prints only its one stderr line.

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
    [int]$GapMs = 20,
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

function Get-InnerException($ErrorRecord) {
    $ex = $ErrorRecord.Exception
    if ($ex -is [System.Management.Automation.MethodInvocationException] -and $ex.InnerException) { $ex = $ex.InnerException }
    return $ex
}

if (-not $Dir) { Stop-Usage 'needs -Dir <probe dir>.' }
# Against PowerShell's location, not the process cwd that [IO.Path]::GetFullPath uses.
$Dir = [System.IO.Path]::GetFullPath($ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($Dir))
if (-not (Test-Path -LiteralPath $Dir -PathType Container)) { Stop-Usage "-Dir '$Dir' is not a directory." }
$slotPattern = [regex]'\Aslot-(\d+)\z'

if ($Compare) {
    # -DateKind below arrived in pwsh 7.5; on 7.4 every result would read as unreadable JSON.
    if ($PSVersionTable.PSVersion -lt [version]'7.5') { Stop-Usage "-Compare needs pwsh 7.5 or later; this is $($PSVersionTable.PSVersion)." }
    $results = @(Get-ChildItem -LiteralPath $Dir -Filter 'result-*.json' -File)
    if ($results.Count -lt 2) { Stop-Usage "found $($results.Count) result file(s) in '$Dir'; a race needs two." }
    $claims = @{}
    $sides = [System.Collections.Generic.List[object]]::new()
    $maxSlots = 0
    foreach ($f in $results) {
        # -DateKind String: the default turns the ISO times into DateTime and drops their milliseconds
        # on the way back to text, and the overlap check below needs them.
        try { $r = [System.IO.File]::ReadAllText($f.FullName) | ConvertFrom-Json -DateKind String -ErrorAction Stop }
        catch { Stop-Usage "$($f.Name) is not readable JSON: $($_.Exception.Message)" }
        if (-not $r.tag -or $null -eq $r.won) { Stop-Usage "$($f.Name) has no tag or no won list." }
        $tagName = [string]$r.tag
        if ([int]$r.slots -gt $maxSlots) { $maxSlots = [int]$r.slots }
        $won = @($r.won | ForEach-Object { [int]$_ })
        foreach ($n in $won) {
            if (-not $claims.ContainsKey($n)) { $claims[$n] = [System.Collections.Generic.List[string]]::new() }
            $claims[$n].Add($tagName)
        }
        $sides.Add([ordered]@{
                tag = $tagName; host = [string]$r.host; slots = [int]$r.slots; won = $won.Count; errors = @($r.errors).Count
                startAtUtc = [string]$r.startAtUtc; startedAtUtc = [string]$r.startedAtUtc; finishedAtUtc = [string]$r.finishedAtUtc
                gapMs = [int]$r.gapMs
            })
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

    # Was it a race at all? Each check names a way a run can pass while measuring nothing.
    $invalid = [System.Collections.Generic.List[string]]::new()
    if (@($sides | ForEach-Object { $_.slots } | Sort-Object -Unique).Count -gt 1) { $invalid.Add('the sides raced different slot counts') }
    foreach ($s in $sides) {
        if ($s.errors) { $invalid.Add("$($s.tag) recorded $($s.errors) error(s)") }
        if ($s.won -eq 0) { $invalid.Add("$($s.tag) won no slot, so the two may never have overlapped") }
    }
    if (@($sides | ForEach-Object { $_.startAtUtc } | Sort-Object -Unique).Count -gt 1) { $invalid.Add('the sides were given different start times') }
    $starts = @(); $ends = @()
    $inv = [Globalization.CultureInfo]::InvariantCulture
    $utc = [Globalization.DateTimeStyles]::AssumeUniversal
    foreach ($s in $sides) {
        $a = [DateTimeOffset]::MinValue; $b = [DateTimeOffset]::MinValue; $t = [DateTimeOffset]::MinValue
        $ok = [DateTimeOffset]::TryParse($s.startedAtUtc, $inv, $utc, [ref]$a) -and [DateTimeOffset]::TryParse($s.finishedAtUtc, $inv, $utc, [ref]$b)
        if (-not $ok) { $invalid.Add("$($s.tag) has no readable start and finish time"); continue }
        $starts += $a; $ends += $b
        # A late side runs straight through every gate already past, and those slots are not raced.
        # Measured on that side's own clock, so skew between the PCs does not enter.
        $limit = [Math]::Max($s.gapMs, 20)
        if ([DateTimeOffset]::TryParse($s.startAtUtc, $inv, $utc, [ref]$t) -and ($a - $t).TotalMilliseconds -gt $limit) {
            $invalid.Add("$($s.tag) started $([int]($a - $t).TotalMilliseconds) ms late, past the $limit ms limit")
        }
    }
    if ($starts.Count -eq $sides.Count -and @($starts | Sort-Object)[-1] -ge @($ends | Sort-Object)[0]) {
        $invalid.Add('the time windows do not overlap: one side finished before another started')
    }

    # A double winner is a FAIL whatever else happened. An empty slot or a mismatch is one only when
    # no side recorded an error: an access-denied or a dropped session explains both, and then
    # exclusive create was never tested.
    $sideErrors = @($sides | Where-Object { $_.errors }).Count
    $exit = if ($double.Count -or (($empty.Count -or $mismatch.Count) -and -not $sideErrors)) { 3 } elseif ($invalid.Count -or $empty.Count -or $mismatch.Count) { 2 } else { 0 }
    if ($Json) {
        [ordered]@{
            dir = $Dir; slots = $maxSlots; sides = @($sides)
            doubleWinners = @($double); emptySlots = @($empty); mismatches = @($mismatch); invalid = @($invalid); exit = $exit
        } | ConvertTo-Json -Depth 5
        exit $exit
    }
    Write-Host "coord-race compare: $Dir, $maxSlots slot(s)"
    foreach ($s in $sides) {
        Write-Host ("  {0} on {1}: won {2} of {3}, {4} error(s), {5} to {6}" -f $s.tag, $s.host, $s.won, $s.slots, $s.errors, $s.startedAtUtc, $s.finishedAtUtc)
    }
    Write-Host "  double winners: $($double.Count)"
    foreach ($d in $double) { Write-Host "    slot-$($d.slot): $($d.tags -join ', ') (file says '$($d.content)')" }
    Write-Host "  empty slots: $($empty.Count)"
    if ($empty.Count) { Write-Host "    $(($empty | ForEach-Object { "slot-$_" }) -join ', ')" }
    Write-Host "  content mismatches: $($mismatch.Count)"
    foreach ($m in $mismatch) { Write-Host "    slot-$($m.slot): claimed by $($m.claimedBy), file says '$($m.content)'" }
    Write-Host "  not a valid race: $($invalid.Count)"
    foreach ($i in $invalid) { Write-Host "    $i" }
    $verdict = switch ($exit) {
        0 { 'PASS: a valid race, and every slot has exactly one winner whose tag is in its file.' }
        2 { 'NO VERDICT: the run was not a valid race, so it shows nothing about exclusive create. Race again.' }
        default { 'FAIL: exclusive create did not hold on this directory.' }
    }
    Write-Host $verdict
    exit $exit
}

if (-not $Tag -or $Tag -notmatch '\A[A-Za-z0-9._-]+\z') { Stop-Usage 'needs -Tag <name>: letters, digits, dot, dash and underscore only.' }
if (-not $StartAtUtc) { Stop-Usage 'needs -StartAtUtc <ISO 8601 time>, the same on every side.' }
if ($Slots -lt 1 -or $Slots -gt 100000) { Stop-Usage '-Slots must be between 1 and 100000.' }
if ($GapMs -lt 0 -or $GapMs -gt 1000) { Stop-Usage '-GapMs must be between 0 and 1000.' }
$maxRaceMs = 10 * 60 * 1000
if ([long]$Slots * $GapMs -gt $maxRaceMs) { Stop-Usage '-Slots times -GapMs is over ten minutes.' }
$start = [DateTimeOffset]::MinValue
# An offset or a Z is required: a bare local time means a different instant on each PC.
if ($StartAtUtc -notmatch '(Z|[+-]\d\d:?\d\d)\z' -or
    -not [DateTimeOffset]::TryParse($StartAtUtc, [Globalization.CultureInfo]::InvariantCulture, [Globalization.DateTimeStyles]::None, [ref]$start)) {
    Stop-Usage "-StartAtUtc '$StartAtUtc' is not an ISO 8601 time with an offset or a Z."
}
$wait = $start.UtcDateTime - [DateTime]::UtcNow
if ($wait.TotalHours -gt 1) { Stop-Usage "-StartAtUtc is $([int]$wait.TotalMinutes) minutes away; an hour is the limit." }
# A late side would start alone and win nothing, or everything: no race.
if ($wait.TotalSeconds -lt -2) { Stop-Usage "-StartAtUtc is $([int](-$wait.TotalSeconds)) s in the past; pick a time both sides can make." }

$resultFile = Join-Path $Dir "result-$Tag.json"
if (Test-Path -LiteralPath $resultFile) { Stop-Usage "$resultFile already exists; race in a fresh directory." }
$stale = @(Get-ChildItem -LiteralPath $Dir -File | Where-Object { $slotPattern.IsMatch($_.Name) })
if ($stale.Count) { Stop-Usage "'$Dir' already holds $($stale.Count) slot file(s); race in a fresh directory." }

function Wait-Until([DateTime]$Utc) {
    # Sleep most of the wait, then spin, so both sides leave each gate within a millisecond or two.
    while ($true) {
        $left = ($Utc - [DateTime]::UtcNow).TotalMilliseconds
        if ($left -le 0) { return }
        if ($left -gt 30) { Start-Sleep -Milliseconds ([int][Math]::Min($left - 15, 1000)) } else { [System.Threading.Thread]::SpinWait(1000) }
    }
}

Wait-Until $start.UtcDateTime
$startedAt = [DateTime]::UtcNow

$tagBytes = [System.Text.Encoding]::UTF8.GetBytes($Tag)
$rng = [System.Random]::new()
$won = [System.Collections.Generic.List[int]]::new()
$errors = [System.Collections.Generic.List[object]]::new()
$lost = 0
for ($n = 1; $n -le $Slots; $n++) {
    if ($GapMs -gt 0) { Wait-Until $start.UtcDateTime.AddMilliseconds(($n - 1) * $GapMs + $rng.NextDouble() * $GapMs) }
    $path = Join-Path $Dir "slot-$n"
    $fs = $null
    try {
        $fs = [System.IO.File]::Open($path, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
    } catch {
        $ex = Get-InnerException $_
        # ERROR_FILE_EXISTS (80) or ERROR_ALREADY_EXISTS (183): the other side won it, the expected
        # loss. Read from the error itself, because a second look could answer from a stale cache.
        if ($ex -is [System.IO.IOException] -and (($ex.HResult -band 0xFFFF) -in 80, 183)) { $lost++ }
        else { $errors.Add([ordered]@{ slot = $n; error = $ex.Message }) }
        continue
    }
    # Won. A failed write after that is this side's I/O error, never a loss: the slot is ours.
    $won.Add($n)
    # Flush inside the try: Write only fills a buffer, so the real write happens at the flush.
    try { $fs.Write($tagBytes, 0, $tagBytes.Length); $fs.Flush() } catch {
        $errors.Add([ordered]@{ slot = $n; error = "won, but the tag write failed: $((Get-InnerException $_).Message)" })
    } finally { try { $fs.Dispose() } catch { } }
}
$finishedAt = [DateTime]::UtcNow

$result = [ordered]@{
    tag = $Tag; host = [Environment]::MachineName; slots = $Slots; gapMs = $GapMs
    startAtUtc = $start.UtcDateTime.ToString('o'); startedAtUtc = $startedAt.ToString('o'); finishedAtUtc = $finishedAt.ToString('o')
    won = @($won); lost = $lost; errors = @($errors)
} | ConvertTo-Json -Depth 4
try {
    $fsr = [System.IO.File]::Open($resultFile, [System.IO.FileMode]::CreateNew, [System.IO.FileAccess]::Write, [System.IO.FileShare]::None)
} catch {
    # Most likely a second side whose tag differs only in case: the file system folds them together.
    Stop-Usage "could not create $resultFile, so this side's result is lost: $((Get-InnerException $_).Message). Is another side's tag the same name in a different case?"
}
try {
    $bytes = [System.Text.UTF8Encoding]::new($false).GetBytes($result)
    $fsr.Write($bytes, 0, $bytes.Length)
} finally { $fsr.Dispose() }

Write-Host "coord-race ${Tag}: won $($won.Count), lost $lost, $($errors.Count) error(s), of $Slots slot(s). Result: $resultFile"
exit $(if ($errors.Count) { 1 } else { 0 })
