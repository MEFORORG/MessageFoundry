# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Record THIS lane's own free-slot count. The only writer of a lane level.

.DESCRIPTION
    A builder lane states how many of its slots are free BY WORK. Nothing else in the fleet may write
    that number -- not the dispatcher, not a hook, not an inference from claims.

    THERE IS NO -Lane AND NO -BoxKey PARAMETER, AND ADDING ONE DEFEATS THE WHOLE DESIGN. The box key is
    derived from $PWD, so a session can only ever state its OWN level. The failure this replaces is a
    gauge that reported both lanes full while one sat idle, because it counted CLAIMS: measured
    2026-08-23, one lane held nine claims and reported one active item and three free slots. Both
    numbers were honest. Only the lane knows which is which.

    FREE MEANS BY WORK, NOT BY CLAIMS. Built-and-awaiting-land is FREE. Blocked is FREE. Parked on a
    condition is FREE. A claim you are not currently able to progress is a FREE slot wearing an
    occupied label, and that mislabelling is the outage.
#>
[CmdletBinding(DefaultParameterSetName = 'State')]
param(
    [Parameter(ParameterSetName = 'State', Mandatory)][ValidateRange(0, 99)][int]$Free,
    [Parameter(ParameterSetName = 'State', Mandatory)][ValidateRange(0, 99)][int]$InFlight,
    [Parameter(ParameterSetName = 'State')][string]$Note = '',
    [Parameter(ParameterSetName = 'State')][ValidateRange(1, 99)][int]$Capacity = 4,
    # Stamp that a dispatcher asked. Carries NO number and cannot produce an at-capacity reading.
    [Parameter(ParameterSetName = 'Asked', Mandatory)][switch]$Asked,
    [Parameter(ParameterSetName = 'Show', Mandatory)][switch]$Show
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. (Join-Path $PSScriptRoot 'mail-key.ps1')

function Get-CoordRoot {
    $c = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $c) { throw 'not inside a git repository' }
    return (Join-Path $c.Trim() 'mefor-coord')
}

function Get-ClaimHash([string]$Worktree) {
    # Hash of the claim KEYS this worktree holds. Used ONLY to invalidate a stated number when the
    # claim set moves -- never to derive one. The test runs one way: it can make a number stale, and
    # it can never make a stale number look fresh.
    $coord = Get-CoordRoot
    $dir = Join-Path $coord 'claims'
    if (-not (Test-Path -LiteralPath $dir)) { return '' }
    $want = $Worktree.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'
    $keys = @()
    foreach ($f in (Get-ChildItem -LiteralPath $dir -Filter *.json -Recurse -File -ErrorAction SilentlyContinue)) {
        try { $d = Get-Content -LiteralPath $f.FullName -Raw -Encoding UTF8 | ConvertFrom-Json } catch { continue }
        $w = ''
        if ($d.PSObject.Properties.Name -contains 'worktree' -and $d.worktree) { $w = [string]$d.worktree }
        if (-not $w) { continue }
        $w = $w.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\'
        if ($w -ne $want) { continue }
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
$coord    = Get-CoordRoot
$lanesDir = Join-Path $coord 'lanes'
$tmpDir   = Join-Path $lanesDir '.tmp'
$file     = Join-Path $lanesDir "$boxKey.json"

New-Item -ItemType Directory -Force -Path $lanesDir, $tmpDir | Out-Null

$rec = $null
if (Test-Path -LiteralPath $file) {
    try { $rec = Get-Content -LiteralPath $file -Raw -Encoding UTF8 | ConvertFrom-Json } catch { $rec = $null }
}
if (-not $rec) {
    $rec = [pscustomobject]@{
        v = 1; boxKey = $boxKey; worktree = $worktree; capacity = $Capacity
        statedFree = $null; statedInFlight = $null; statedUtc = $null
        statedBySessionId = $null; statedNote = ''
        tipAtStated = ''; claimHashAtStated = ''; turnsSinceStated = 0
        tipNow = ''; claimHashNow = ''; lastTurnUtc = $null
        promptedUtc = $null; promptCount = 0; askedByDispatcherUtc = $null
    }
}

if ($Show) {
    $rec | ConvertTo-Json -Depth 5
    exit 0
}

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

    $rec.capacity          = $Capacity
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

$tmp = Join-Path $tmpDir ("$boxKey." + [guid]::NewGuid().ToString('n') + '.json')
($rec | ConvertTo-Json -Depth 5) | Set-Content -LiteralPath $tmp -Encoding UTF8 -NoNewline
Move-Item -LiteralPath $tmp -Destination $file -Force

if ($Asked) {
    Write-Host "lane: recorded that a dispatcher asked. No number written."
} else {
    Write-Host "lane: $boxKey -- $Free free / $InFlight in flight of $($rec.capacity), stated $nowUtc"
    if (-not $Note) { Write-Host "      (no note. A note is what makes the number auditable later.)" }
}
exit 0
