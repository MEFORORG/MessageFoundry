# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Write the retirement tombstone into this clone's shared BACKLOG allocation registry, so a stale
    pre-retirement copy of alloc.ps1 issues an absurd number instead of one the vault already uses.

.DESCRIPTION
    THE PROBLEM (BACKLOG #1829). `11a3934c1` retired the engine backlog allocator by narrowing
    scripts/coord/alloc.ps1 to `[ValidateSet("adr")]`. That protects only a checkout which HAS the new
    file. A worktree whose tree predates 2026-09-13 still carries the old script, and it still runs:
    measured 2026-09-19, a tree at `4c68c28eb` issued #1770 and #1771, which the vault ledger already
    held. The old floor is a maximum over ledger text (gone from this repository), refs, and this
    clone's registry -- so with the ledger term empty it falls back to the registry, whose maximum
    trails the vault's.

    WHY THE REGISTRY AND NOT THE SCRIPT. Nothing at head can change what an old copy of a file does.
    What an old copy DOES share with head is the registry: every pre-retirement revision of alloc.ps1
    takes its floor as a maximum over `<git-common-dir>/mefor-coord/alloc/backlog/*.json`, parsing each
    file's BASE NAME as the number. So one record numbered far above any real ledger number moves every
    stale copy's floor above it. The next number it issues then collides with nothing, and it reads
    as wrong on sight: `ALLOCATED BACKLOG #1000001`.

    WHAT THIS DOES NOT DO. It does not make a stale copy REFUSE; it makes the stale copy's number
    harmless and conspicuous. (Two early revisions, 8e6e7fa37 and 03f1fbd73, already refuse a backlog
    allocation on their own; the tombstone does not change that.) It covers only the clone whose
    registry it is written into, so a second engine clone needs its own run.

    ONE SHARED-REGISTRY CASE IT CANNOT TELL APART. The engine clone also fetches the vault as a second
    remote. A vault checkout made as a worktree OF THIS CLONE would share this registry, and the vault's
    live allocator there would be lifted to #1000001 too. Allocate vault numbers from the vault's own
    clone, which has its own registry and never sees this record.

    THE RECORD IS INERT TO EVERY OTHER READER, and that is by its shape. `worktree` and `branch` are
    empty. Every reader of this registry keys on `worktree` and skips a record whose value is empty or
    does not match: remove.ps1's orphan guard, seat.ps1's allocation list, precompact-reprime.ps1,
    alloc.ps1 -List, and ledger_check.py's owns(), which also returns False on an empty branch. So no
    session is ever told it holds this number, and no removal is refused over it.

    IT REFUSES A CLONE WHOSE OWN ALLOCATOR IS STILL LIVE. The vault clone's alloc.ps1 still accepts
    `-Kind backlog` and is where backlog numbers are allocated now. A tombstone there would push its
    real allocator to #1000001 and break the ledger it serves. So this reads the target clone's
    `origin/main:scripts/coord/alloc.ps1` and writes only when that copy's `-Kind` set does not include
    `backlog`. A copy it cannot read counts as live.

    Idempotent. A second run finds the record and changes nothing. The record is written to a temp file
    and moved into place, so no reader ever sees a half-written one. An EMPTY record at that path is
    replaced rather than refused, because remove.ps1 refuses every removal over an unreadable record.

.PARAMETER GitCommonDir
    The shared git directory whose registry receives the record. Defaults to the clone this script
    sits in. A linked worktree's own git dir is resolved to the common dir. Tests point it at a fixture.

.PARAMETER Check
    Report whether the tombstone is present, and write nothing. Exit 0 when present, 1 when absent,
    2 when something else holds that number.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\tombstone-retired-backlog-allocator.ps1 -Check
    pwsh -NoProfile -File scripts\coord\tombstone-retired-backlog-allocator.ps1
#>
[CmdletBinding()]
param(
    [string]$GitCommonDir,
    [switch]$Check
)

$ErrorActionPreference = "Stop"

# Far above any real ledger number, and a round one so it reads as deliberate. The vault ledger was
# under #1900 when this was written; it would take a thousand years at the current rate to reach this.
$TombstoneNumber = 1000000

if (-not $GitCommonDir) {
    $GitCommonDir = (& git -C $PSScriptRoot rev-parse --path-format=absolute --git-common-dir 2>$null)
    if (-not $GitCommonDir) { throw "scripts/coord/ is not inside a git repository: $PSScriptRoot" }
}
if (-not (Test-Path -LiteralPath $GitCommonDir.Trim() -PathType Container)) {
    throw "-GitCommonDir '$GitCommonDir' is not a directory."
}
# Normalise to the COMMON dir. A linked worktree's own git dir (.git/worktrees/<name>) is a directory
# too, and a record written under it is one no allocator reads -- while this script said WROTE.
$resolved = (& git --git-dir=$($GitCommonDir.Trim()) rev-parse --path-format=absolute --git-common-dir 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $resolved) { throw "-GitCommonDir '$GitCommonDir' is not a git directory." }
$GitCommonDir = $resolved.Trim()

$registry = Join-Path $GitCommonDir "mefor-coord/alloc/backlog"
$file = Join-Path $registry "$TombstoneNumber.json"

function Test-IsTombstone([string]$Path) {
    try { $c = Get-Content -LiteralPath $Path -Raw -EA Stop | ConvertFrom-Json -EA Stop }
    catch { return $false }
    if ($null -eq $c) { return $false }
    return ($c.PSObject.Properties.Name -contains 'tombstone') -and ($c.tombstone -eq $true)
}

if ($Check) {
    if (-not (Test-Path -LiteralPath $file)) {
        Write-Host "ABSENT: $file"
        exit 1
    }
    if (Test-IsTombstone $file) {
        Write-Host "PRESENT: $file"
        exit 0
    }
    Write-Host "OCCUPIED BY SOMETHING ELSE: $file"
    exit 2
}

# The guard that keeps this away from the vault. Read the clone's PUBLISHED allocator rather than any
# worktree's copy: a worktree can be stale in either direction, and origin/main is what every fresh
# checkout of this clone will run.
$published = & git --git-dir=$GitCommonDir show "origin/main:scripts/coord/alloc.ps1" 2>$null
if ($LASTEXITCODE -ne 0 -or -not $published) {
    throw ("Cannot read origin/main:scripts/coord/alloc.ps1 in $GitCommonDir, so this cannot tell whether " +
        "the clone's own backlog allocator is retired. Refusing: a tombstone in a clone with a LIVE " +
        "backlog allocator breaks that allocator.")
}
$m = [regex]::Match(($published -join "`n"), '\[ValidateSet\(([^)]*)\)\]\s*\[string\]\$Kind')
if (-not $m.Success) {
    throw "Cannot find the -Kind ValidateSet in origin/main:scripts/coord/alloc.ps1 in $GitCommonDir. Refusing."
}
if ($m.Groups[1].Value -match 'backlog') {
    throw ("origin/main:scripts/coord/alloc.ps1 in $GitCommonDir still accepts -Kind backlog, so this clone's " +
        "backlog allocator is LIVE. A tombstone here would push it to #$($TombstoneNumber + 1). Refusing.")
}

New-Item -ItemType Directory -Force -Path $registry | Out-Null

if (Test-Path -LiteralPath $file) {
    if (Test-IsTombstone $file) {
        Write-Host "ALREADY PRESENT, nothing written: $file"
        exit 0
    }
    if ((Get-Item -LiteralPath $file).Length -ne 0) {
        throw "$file exists and is NOT the tombstone. Refusing to overwrite an allocation record."
    }
    # Empty: a crashed write. Nothing is lost by replacing it, and leaving it makes remove.ps1 refuse
    # every worktree removal in the clone.
    Remove-Item -LiteralPath $file
}

$record = [ordered]@{
    number    = "$TombstoneNumber"
    kind      = "backlog"
    title     = ("RETIRED ALLOCATOR TOMBSTONE (BACKLOG #1829). The engine backlog allocator was retired in " +
        "11a3934c1 (BACKLOG #1250, #1754). This record lifts a stale pre-retirement alloc.ps1 above every " +
        "real number. Allocate backlog numbers in the MessageFoundry-vault clone instead.")
    branch    = ""
    worktree  = ""
    claimed   = (Get-Date).ToString("o")
    tombstone = $true
} | ConvertTo-Json -Compress

# Write beside it, then move into place. File.Move without overwrite fails when the target exists, so a
# concurrent second run loses cleanly and then finds a COMPLETE record, and no reader ever sees a
# partial one. The temp name does not end in .json, so no reader globbing *.json can pick it up.
$temp = Join-Path $registry ".tombstone-$([System.Guid]::NewGuid().ToString('N')).tmp"
[System.IO.File]::WriteAllText($temp, $record, [System.Text.UTF8Encoding]::new($false))
try {
    [System.IO.File]::Move($temp, $file)
} catch [System.IO.IOException] {
    Remove-Item -LiteralPath $temp -EA SilentlyContinue
    if (Test-IsTombstone $file) {
        Write-Host "ALREADY PRESENT, nothing written: $file"
        exit 0
    }
    throw
}

Write-Host "WROTE TOMBSTONE: $file"
Write-Host "  A pre-retirement alloc.ps1 in any worktree of this clone now issues #$($TombstoneNumber + 1) or above."
exit 0
