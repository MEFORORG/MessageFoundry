# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Write or read the AFK-autonomy decision log (ADR 0211; docs/AUTONOMY-PLAN.md section 4.1).

.DESCRIPTION
    -Log writes ONE record. It is spooled locally first and then posted to the vault's issue for
    its UTC day, so a network failure loses nothing: the record stays spooled, the script says so
    and exits 4, and the next -Log or -Flush posts it. -NoPost spools only, with no network; the
    tripwire hook uses it.

    -List reads records by day (-Day, default today UTC, and -Days for a range ending there), and
    filters them by -Seat or -Item. It reads the vault and the local spool, and marks a record that
    is still only spooled. A vault that cannot be read is said aloud and exits 4: an empty answer
    from an unread log would look like a quiet day.

    -Flush posts whatever is spooled.

    KINDS. `decision` is one Class A to D decision. `tripwire` is a tripwire hit. `rating` is the
    owner's blind-sample verdict on a decision (-Ref, -Rating). `outcome` updates a decision's
    outcome later (-Ref, -Outcome), and `-Outcome reversed` is what the digest counts as a reversal:
    a revert, a reopen, a re-brief or an override.

    THE FIELDS ARE ADR 0211's SCHEMA. -Predicate takes `name=evidence` strings, the predicates this
    turn checked and what each read showed. -Confidence is the session's stated confidence, 0 to
    100; it is logged and never used as a gate (plan R4).

    SEVERAL PREDICATES OR ALTERNATIVES. `pwsh -File` cannot repeat a parameter or pass an array, so
    each -Predicate and -Alternative value is also split at newlines: one argument may carry
    several, one per line. Called in-process (`& decision.ps1`), an array works as well.

    The seat defaults to the one this session declared in the seat registry, found by its session
    id; the session id defaults to $env:CLAUDE_CODE_SESSION_ID.

.EXAMPLE
    decision.ps1 -Log -Item 3905 -Class B -Recommendation 'split the fix into two PRs' `
      -Alternative 'one PR' -Predicate 'live-state=gh pr view 2460 read 17:02Z' `
      -Undo 'close the second PR' -Confidence 80

.EXAMPLE
    decision.ps1 -List -Day 2026-10-21 -Seat manager
#>
param(
    [switch]$Log,
    [switch]$List,
    [switch]$Flush,
    [ValidateSet('decision', 'tripwire', 'rating', 'outcome')][string]$Kind = 'decision',
    [string]$Item = '',
    [string]$Seat = '',
    [string]$Session = '',
    [ValidateSet('', 'A', 'B', 'C', 'D')][string]$Class = '',
    [string[]]$Predicate = @(),
    [string]$Recommendation = '',
    [string[]]$Alternative = @(),
    [string]$Undo = '',
    [ValidateRange(-1, 100)][int]$Confidence = -1,
    [ValidateSet('no', 'yes')][string]$Reviewed = 'no',
    [string]$ReviewedBy = '',
    [string]$Outcome = '',
    [string]$Ref = '',
    [ValidateSet('', 'agree', 'disagree')][string]$Rating = '',
    [string]$Note = '',
    [switch]$NoPost,
    [string]$Day = '',
    [ValidateRange(1, 100)][int]$Days = 1,
    [switch]$Json,
    [string]$Repo = 'MEFORORG/MessageFoundry-vault'
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# A CLAUDE CODE CLOUD SESSION REACHES NO OTHER SESSION THROUGH THIS SCRIPT: its spool is the VM's
# own clone, and the owner ruled that vault work stays local (plan section 9, question 3), so a
# cloud Builder's decisions are logged by its Manager. CLAUDE.md section 5, "A cloud session is a
# Builder in its own session"; tests/test_coord_cloud_refusal.py holds the copies equal.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('decision.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

$modes = @($Log, $List, $Flush | Where-Object { $_ })
if ($modes.Count -ne 1) {
    [Console]::Error.WriteLine('decision.ps1: give exactly one of -Log, -List or -Flush.')
    exit 2
}

. (Join-Path $PSScriptRoot '_decisionlog.ps1')
$coord = Get-DecisionCoordRoot

function Resolve-SeatFromRegistry([string]$Sid) {
    # The seat this session declared: <coord>/seats/<box>/<key>.json, where the key is seat.ps1's
    # Get-SessionKey of the id (keep the two in step). Sanitised to a file name, so an id cannot
    # widen the match.
    if (-not $Sid) { return '' }
    if ($env:KORUS_AGENT -eq 'codex') { $Sid = "codex-$Sid" }
    $Sid = $Sid -replace '[^A-Za-z0-9._-]', '-'
    if ($Sid.Length -gt 80) { $Sid = $Sid.Substring(0, 80) }
    if ($Sid -match '^\.+$') { return '' }
    # seat.ps1 keeps a Codex session's records in their own directory.
    $seats = Join-Path $coord $(if ($env:KORUS_AGENT -eq 'codex') { 'codex-seats' } else { 'seats' })
    if (-not [System.IO.Directory]::Exists($seats)) { return '' }
    # ONE SESSION CAN HAVE A RECORD IN TWO BOXES. Since the box key hashes the host as well as the
    # path (docs/COORD-SHARED-ROOT.md, step 4), a session that declared before that change keeps a
    # frozen record under the path-only key, and seat.ps1 writes on under the host-keyed one. The
    # directory listing order says nothing about which is current, so take the record written LAST,
    # by its own asOf and then its write count: the rule seat.ps1 uses to pick its prior.
    $best = $null
    foreach ($box in [System.IO.Directory]::EnumerateDirectories($seats)) {
        $f = Join-Path $box "$Sid.json"
        if (-not [System.IO.File]::Exists($f)) { continue }
        try {
            $r = [System.IO.File]::ReadAllText($f) | ConvertFrom-Json
            $s = if ($r.PSObject.Properties.Name -contains 'seat') { [string]$r.seat } else { '' }
            if (-not $s) { continue }
            $at = [datetime]::MinValue
            if ($r.PSObject.Properties.Name -contains 'asOf' -and $r.asOf) {
                $at = if ($r.asOf -is [datetime]) { $r.asOf.ToUniversalTime() }
                      else { [datetime]::Parse([string]$r.asOf, [cultureinfo]::InvariantCulture,
                              [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal) }
            }
            $n = if ($r.PSObject.Properties.Name -contains 'writes') { [int]$r.writes } else { 0 }
        } catch {
            # An unreadable record names no seat; another box may still hold a readable one.
            continue
        }
        if (-not $best -or $at -gt $best.At -or ($at -eq $best.At -and $n -gt $best.Writes)) {
            $best = [pscustomobject]@{ Seat = $s; At = $at; Writes = $n }
        }
    }
    if ($best) { return $best.Seat }
    return ''
}

function Write-Flushed($Result) {
    foreach ($e in $Result.Errors) { [Console]::Error.WriteLine("decision.ps1: NOT POSTED, still spooled: $e") }
}

if ($Flush) {
    $r = Send-DecisionSpool -Repo $Repo -CoordRoot $coord
    Write-Flushed $r
    Write-Output "FLUSHED posted=$($r.Posted) failed=$($r.Errors.Count)"
    exit ($(if ($r.Errors.Count) { 4 } else { 0 }))
}

if ($List) {
    try { $Day = Resolve-DecisionDay $Day } catch { [Console]::Error.WriteLine("decision.ps1: $($_.Exception.Message)"); exit 2 }
    $res = Read-DecisionLog -Repo $Repo -CoordRoot $coord -Days (Get-DecisionDayRange $Day $Days)
    $rows = @($res.Records | Where-Object {
            (-not $Seat -or [string]$_.seat -eq $Seat) -and (-not $Item -or [string]$_.item -eq $Item)
        })
    if ($Json) {
        Write-Output (ConvertTo-Json -InputObject $rows -Depth 8)
    } else {
        foreach ($r in $rows) {
            $flag = if ($r.posted) { '' } else { ' [spooled, not posted]' }
            $what = if ([string]$r.recommendation) { [string]$r.recommendation } else { [string]$r.note }
            if ($what.Length -gt 80) { $what = $what.Substring(0, 77) + '...' }
            Write-Output ("{0}  {1,-8} {2,-1} {3,-10} {4,-10} {5}{6}" -f $r.id, $r.kind, $r.class, $r.seat, $r.item, $what, $flag)
        }
        Write-Output "$($rows.Count) record(s)."
    }
    if (-not $res.Complete) {
        foreach ($e in $res.Errors) { [Console]::Error.WriteLine("decision.ps1: INCOMPLETE, the vault log was not read: $e") }
        exit 4
    }
    exit 0
}

# -Log. Refuse a record missing what its kind needs, before anything is written.
if (-not $Session) { $Session = [string]$env:CLAUDE_CODE_SESSION_ID }
if (-not $Seat) { $Seat = Resolve-SeatFromRegistry $Session }
$missing = switch ($Kind) {
    'decision' { @(@{ Item = $Item; Class = $Class; Recommendation = $Recommendation; Seat = $Seat }.GetEnumerator() | Where-Object { -not $_.Value } | ForEach-Object Key) }
    'tripwire' { @(if (-not $Note) { 'Note' }) }
    'rating' { @(if (-not $Ref) { 'Ref' }; if (-not $Rating) { 'Rating' }) }
    'outcome' { @(if (-not $Ref) { 'Ref' }; if (-not $Outcome) { 'Outcome' }) }
}
if ($missing) {
    [Console]::Error.WriteLine("decision.ps1: a $Kind record needs $((@($missing) | Sort-Object) -join ', '). Nothing was written.")
    exit 2
}
if ($Ref -and -not (Get-DecisionIdDay $Ref)) {
    [Console]::Error.WriteLine("decision.ps1: -Ref '$Ref' is not a decision id. Nothing was written.")
    exit 2
}
if ($Reviewed -eq 'yes' -and -not $ReviewedBy) {
    [Console]::Error.WriteLine('decision.ps1: -Reviewed yes needs -ReviewedBy, the reviewer. Nothing was written.')
    exit 2
}

$Predicate = @($Predicate | ForEach-Object { $_ -split '\r?\n' } | Where-Object { $_.Trim() })
$Alternative = @($Alternative | ForEach-Object { $_ -split '\r?\n' } | Where-Object { $_.Trim() })
$preds = foreach ($p in $Predicate) {
    $at = $p.IndexOf('=')
    if ($at -lt 1) { [Console]::Error.WriteLine("decision.ps1: -Predicate '$p' is not name=evidence. Nothing was written."); exit 2 }
    [ordered]@{ name = $p.Substring(0, $at).Trim(); evidence = $p.Substring($at + 1).Trim() }
}
$cfg = [string]$env:CLAUDE_CONFIG_DIR
$record = [ordered]@{
    v              = 1
    id             = New-DecisionId
    ts             = [DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
    kind           = $Kind
    item           = $Item
    seat           = $Seat
    session        = $Session
    account        = $(if ($cfg) { Split-Path -Leaf $cfg } else { '' })
    host           = [Environment]::MachineName
    class          = $(if ($Kind -eq 'tripwire' -and -not $Class) { 'C' } else { $Class })
    predicates     = @($preds)
    recommendation = $Recommendation
    alternatives   = @($Alternative)
    undo           = $Undo
    confidence     = $(if ($Confidence -ge 0) { $Confidence } else { $null })
    reviewed       = $Reviewed
    reviewedBy     = $ReviewedBy
    outcome        = $(if ($Outcome) { $Outcome } elseif ($Kind -eq 'tripwire') { 'detected' } else { 'pending' })
    ref            = $Ref
    rating         = $Rating
    note           = $Note
}
Write-DecisionSpool -CoordRoot $coord -Record ([pscustomobject]$record)
if ($NoPost) {
    Write-Output "LOGGED $($record.id) spooled"
    exit 0
}
$r = Send-DecisionSpool -Repo $Repo -CoordRoot $coord
Write-Flushed $r
# Still spooled is <id>.json, or a <id>.json.<pid>.posting claim another flusher holds.
$spool = Get-DecisionSpoolDir $coord
if ([System.IO.Directory]::Exists($spool) -and @([System.IO.Directory]::EnumerateFiles($spool, "$($record.id).json*")).Count) {
    Write-Output "LOGGED $($record.id) spooled"
    exit 4
}
Write-Output "LOGGED $($record.id) posted"
exit 0
