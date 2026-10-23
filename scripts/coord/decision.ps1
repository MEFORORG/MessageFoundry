# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Write or read the AFK-autonomy decision log (ADR 0211; docs/AUTONOMY-PLAN.md section 4.1).

.DESCRIPTION
    -Log writes ONE record. It is spooled locally first and then posted to the vault's issue for
    its UTC day, so a network failure loses nothing: the record stays spooled, the script says so
    and exits 4, and the next -Log or -Flush posts it. -NoPost spools only, with no network; the
    tripwire hook uses it. Its default seat comes from the seat registry only when the registry is
    on this machine: it never probes a shared root, and never reads one on a share.

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
# seat.ps1's root resolver and box keys, so the seat lookup reads where seat.ps1 writes.
. (Join-Path $PSScriptRoot 'coord-root.ps1')
. (Join-Path $PSScriptRoot 'mail-key.ps1')
$coord = Get-DecisionCoordRoot

function ConvertTo-SeatRecordInstant($Value) {
    # A record's asOf as a UTC instant, or MinValue when it is absent or will not parse. A bad sort
    # key ranks the record last; it never drops the seat the record names.
    # ConvertFrom-Json hands an ISO stamp back as a [datetime]. One with an offset arrives as Local and
    # converts; one with no offset arrives as Unspecified, and ToUniversalTime() would read that as
    # local time and shift it by the offset (the trap lane.ps1 documents at statedUtc). Such a stamp
    # is UTC, so its Kind is set, not converted.
    try {
        if ($null -eq $Value) { return [datetime]::MinValue }
        if ($Value -is [datetime]) {
            if ($Value.Kind -eq [System.DateTimeKind]::Local) { return $Value.ToUniversalTime() }
            return [datetime]::SpecifyKind($Value, [System.DateTimeKind]::Utc)
        }
        $text = [string]$Value
        if (-not $text.Trim()) { return [datetime]::MinValue }
        return [datetime]::Parse($text, [cultureinfo]::InvariantCulture,
            [System.Globalization.DateTimeStyles]::AdjustToUniversal -bor [System.Globalization.DateTimeStyles]::AssumeUniversal)
    } catch {
        return [datetime]::MinValue
    }
}

function Test-SeatRootIsNetwork([string]$Path) {
    # True when reading $Path could reach another machine: a UNC path, or a drive letter mapped to a
    # share. DriveInfo asks Windows how the letter is mapped, a local call. A path whose kind cannot
    # be told counts as network, so the offline lookup skips it rather than risk a hang.
    if (Get-CoordUncHost -Path $Path) { return $true }
    try {
        $rootOf = [System.IO.Path]::GetPathRoot($Path)
        if (-not $rootOf) { return $true }
        if ($rootOf -match '\A[A-Za-z]:') {
            return ([System.IO.DriveInfo]::new($rootOf).DriveType -eq [System.IO.DriveType]::Network)
        }
        return $false
    } catch {
        return $true
    }
}

function Get-SeatCandidate([string]$File) {
    # One seat record as a candidate, or $null. Anything wrong with a record skips that record only:
    # an empty `{}`, bad JSON, a non-object, no seat, or a `host` naming another machine.
    try {
        if (-not [System.IO.File]::Exists($File)) { return $null }
        $r = [System.IO.File]::ReadAllText($File) | ConvertFrom-Json -ErrorAction Stop
        if ($r -isnot [System.Management.Automation.PSCustomObject]) { return $null }
        # A record in EITHER box that names another host is that PC's seat, copied or hand-made here;
        # lane.ps1 refuses the same shape at its own key. A record with no host was written here.
        if (-not (Test-CoordRecordIsHere $r)) { return $null }
        $props = $r.PSObject.Properties
        $s = if ($props['seat'] -and $r.seat) { [string]$r.seat } else { '' }
        if (-not $s) { return $null }
        $declared = [bool]$props['seatSource'] -and ([string]$r.seatSource -eq 'declared')
        $at = if ($props['asOf']) { ConvertTo-SeatRecordInstant $r.asOf } else { [datetime]::MinValue }
        $n = 0
        if ($props['writes']) { try { $n = [int]$r.writes } catch { $n = 0 } }
        return [pscustomobject]@{ Seat = $s; Declared = $declared; At = $at; Writes = $n }
    } catch {
        return $null
    }
}

function Resolve-SeatFromRegistry([string]$Sid, [switch]$Offline) {
    # The seat this session declared, read where seat.ps1 writes it and picked by seat.ps1's rules.
    # The file name is seat.ps1's Get-SessionKey of the id (keep the two in step), sanitised so an id
    # cannot widen the match.
    #
    # WHERE. seats/ is a shared kind, so seat.ps1 writes it on the resolved shared root, and this reads
    # it there, resolved from the same worktree (this cwd's top level, as seat.ps1 resolves it). A
    # Codex seat's records stay on the local root. A root that does not resolve names no seat; it
    # never falls back to the local copy, which the other PC never sees.
    #
    # -Offline (-NoPost, the tripwire hook's path) NEVER TOUCHES THE NETWORK. It resolves the root
    # without the port-445 probe, and reads it only when it is on this machine. A root on a share
    # names no seat there: a dead SMB server can hang one file call for about a minute, far past the
    # hook's budget. A tripwire record needs no seat.
    #
    # WHICH BOX. Only this worktree's two boxes: the host-keyed one seat.ps1 writes, and the path-only
    # legacy one a session that declared before docs/COORD-SHARED-ROOT.md step 4 still has. A record
    # in either box stamped by another host is that PC's seat and is skipped.
    #
    # WHICH RECORD. A declared seat beats a derived one (seat.ps1: "declared wins, derived fills only a
    # vacuum"). Among equals the record written LAST wins, by its own asOf and then its write count,
    # which is how seat.ps1 picks its prior. Listing order decides nothing.
    #
    # This mirrors seat.ps1 rather than calling it: seat.ps1's prior picker is inline in its main body,
    # which writes, and it does not weigh seatSource, because it only carries a prior forward.
    if (-not $Sid) { return '' }
    if ($env:KORUS_AGENT -eq 'codex') { $Sid = "codex-$Sid" }
    $Sid = $Sid -replace '[^A-Za-z0-9._-]', '-'
    if ($Sid.Length -gt 80) { $Sid = $Sid.Substring(0, 80) }
    if ($Sid -match '^\.+$') { return '' }
    try {
        $top = & git -C (Get-Location).Path rev-parse --show-toplevel 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $top) { return '' }
        $wt = (Resolve-Path -LiteralPath ([string]$top).Trim() -ErrorAction Stop).Path
        $localRoot = Get-CoordLocalRoot -From $wt
        if ($env:KORUS_AGENT -eq 'codex') {
            $res = Resolve-CoordDir -From $wt -Kind 'codex-seats' -LocalRoot $localRoot
            $seats = $res.Path
        } else {
            $res = if ($Offline) {
                Get-CoordSharedRoot -From $wt -LocalRoot $localRoot
            } else {
                Resolve-CoordSharedRoot -From $wt -LocalRoot $localRoot
            }
            if ($Offline -and $res.Path -and $res.Source -ne 'local' -and (Test-SeatRootIsNetwork $res.Path)) {
                [Console]::Error.WriteLine("decision.ps1: -NoPost reads no network, and the seat registry is on $($res.Path), so no seat was read from it.")
                return ''
            }
            $seats = if ($res.Path) { Join-Path $res.Path 'seats' } else { $null }
        }
        if ($res.Error -or -not $seats) {
            [Console]::Error.WriteLine("decision.ps1: the seat registry did not resolve, so no seat was read from it: $($res.Error)")
            return ''
        }
        $best = $null
        foreach ($box in @((ConvertTo-BoxKey -Path $wt), (ConvertTo-LegacyBoxKey -Path $wt))) {
            $cand = Get-SeatCandidate (Join-Path (Join-Path $seats $box) "$Sid.json")
            if (-not $cand) { continue }
            if (-not $best) { $best = $cand; continue }
            if ($cand.Declared -ne $best.Declared) {
                if ($cand.Declared) { $best = $cand }
                continue
            }
            if ($cand.At -gt $best.At -or ($cand.At -eq $best.At -and $cand.Writes -gt $best.Writes)) { $best = $cand }
        }
        if ($best) { return $best.Seat }
        return ''
    } catch {
        # An I/O error on the registry (an SMB share dropping, say) costs the default seat, not -Log.
        [Console]::Error.WriteLine("decision.ps1: the seat registry could not be read, so no seat was read from it: $($_.Exception.Message)")
        return ''
    }
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
if (-not $Seat) { $Seat = Resolve-SeatFromRegistry $Session -Offline:$NoPost }
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
