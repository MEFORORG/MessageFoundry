# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Project the fleet from the episode records seat.ps1 wrote -- the roster a session under a
    DIFFERENT account reads to reconstitute a replacement fleet after an account switch.

.DESCRIPTION
    PURE READER over <git-common-dir>/mefor-coord/seats/. It writes nothing except the render
    artifacts named below, and it holds NO liveness opinion of its own: the fence is
    session-registry.ps1's, dot-sourced. claim.ps1 already accreted a private Get-HolderLiveness
    beside the fence that six other files route through, and a second definition of a safety check
    is how the copy nobody tests becomes the copy in use.

        fleet.ps1 -Text            # roster, receipt first
        fleet.ps1 -Text -All       # do not fold stale rows
        fleet.ps1 -Json            # machine-readable
        fleet.ps1 -Chip <boxKey> <sessionKey>   # the standalone briefing for one spawn_task call

    WHY THE RECEIPT COMES BEFORE THE ROSTER, AND WHY IT CAN REFUSE.

    An empty roster and a dead writer produce THE SAME OUTPUT. So do a healthy quiet fleet and a
    fleet whose hooks were silently disabled by disableAllHooks, org policy or workspace trust. The
    reader of this output is, by construction, the person least equipped to notice -- they are
    reading it because they lost the context that would have told them. So the receipt states what
    was EXAMINED, not merely what was found, and any of the STOP conditions below suppresses the
    manifest rather than rendering a confident empty answer.

    THE DENOMINATOR IS THE POINT. Joining records to the fence tells you nothing about a session
    that produced NO record -- it is not missing, it does not exist. `liveSessionsWithoutRecord`
    supplies the missing denominator by starting from the FENCE and subtracting, so a dead writer
    shows up as a positive count instead of as silence.

    EVERY VERDICT IS COMPUTED AT READ TIME AND NONE IS STORED. A stored verdict is read after the
    world moved. Measured on this repo the same day: one unchanged commit carried three SHAs across
    rebases within minutes, and a "contains current origin/main: YES" check was already false twenty
    minutes after it was taken. So this renders facts with the time they were taken, and re-derives
    every judgement from the tree in front of it.

    WHY A SHA IS NEVER AN IDENTIFIER HERE. Work is named by BRANCH plus change; a commit id appears
    only as "as of HH:MMZ". A ruling or a briefing citing a bare SHA becomes unresolvable the moment
    its branch rebases, and this project has watched exactly that happen.

    ANCESTRY IS NOT CONTENT. "Is my commit an ancestor of main" and "is my content in main" are
    different questions, and squash-merge makes them disagree as a matter of course -- 51 of the last
    100 main commits carry a (#N) squash suffix. The landed probe therefore compares CONTENT over a
    pathspec derived from the record's own mergeBase, and an empty pathspec is UNCHECKABLE, never
    AGREES.
#>
[CmdletBinding()]
param(
    [switch]$Text,
    [switch]$Json,
    [switch]$All,
    # Bring back every SUPERSEDED record -- the older episodes of a box, one row each. Off by
    # default because one busy worktree otherwise occupies a third of the roster; never DELETED,
    # because a superseded record is evidence and the count is always printed. -All implies this.
    # AFFECTS THE TEXT ROSTER ONLY. -Json emits every row regardless and always did: a machine
    # consumer should receive the full set and apply its own rule, and silently shrinking its input
    # to suit a human's screen is how a downstream tool starts reporting a smaller fleet.
    [switch]$History,
    [switch]$Chip,
    [string]$BoxKey,
    [string]$SessionKey,
    [int]$FoldDays = 7,
    [string]$RepoHint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\session-registry.ps1"
. "$PSScriptRoot\mail-key.ps1"

function Invoke-Git {
    param([string]$Dir, [string[]]$GitArgs)
    try {
        $out = & git -C $Dir @GitArgs 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if ($null -eq $out) { return '' }
        return ($out -join "`n").Trim()
    } catch { return $null }
}

$repo = if ($RepoHint) { $RepoHint } else { (Get-Location).Path }
$common = Invoke-Git -Dir $repo -GitArgs @('rev-parse', '--path-format=absolute', '--git-common-dir')
if (-not $common) {
    Write-Error "fleet.ps1: not inside a git repository (or git failed). Cannot locate the seats layer."
    exit 2
}
$coord = Join-Path $common 'mefor-coord'
$seatsDir = Join-Path $coord 'seats'
$primary = Split-Path $common -Parent

# ---------------------------------------------------------------------------------------------
# Gather. Records first, then the fence, then the denominator.
# ---------------------------------------------------------------------------------------------

$records = @()
$unreadableRecords = 0
if (Test-Path -LiteralPath $seatsDir) {
    foreach ($d in @(Get-ChildItem -LiteralPath $seatsDir -Directory -EA SilentlyContinue |
                     Where-Object { $_.Name -notlike '.*' })) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -Filter *.json -EA SilentlyContinue)) {
            try {
                $j = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop
                $records += [pscustomobject]@{ Rec = $j; File = $f.FullName; Box = $d.Name }
            } catch {
                # A record being written RIGHT NOW has exactly this shape. Counted, never dropped:
                # dropping turns an occupied seat into an absent one in the receipt's own numbers.
                $unreadableRecords++
            }
        }
    }
}

# The fence. Its availability is a FACT IN THE RECEIPT, not an assumption.
$fenceAvailable = $true
$sessionRows = @()
$rootsExamined = 0
try {
    $roots = @(Get-ClaudeConfigRoots)
    $rootsExamined = $roots.Count
    $sessionRows = @(Get-SessionRecords -IncludeUnreadable)
    if ($rootsExamined -eq 0) { $fenceAvailable = $false }
} catch {
    $fenceAvailable = $false
}

function Get-NormPath([string]$p) {
    if (-not $p) { return '' }
    return ($p.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\')
}

# Worktrees of THIS clone, so the denominator is scoped to this repo rather than to the whole box.
$repoWorktrees = @()
$wtOut = Invoke-Git -Dir $repo -GitArgs @('worktree', 'list', '--porcelain')
if ($wtOut) {
    foreach ($line in ($wtOut -split "`n")) {
        if ($line -match '^worktree\s+(.+)$') { $repoWorktrees += (Get-NormPath $Matches[1]) }
    }
}

# LIVE sessions sitting in this repo's worktrees. This is the denominator: a session here that has
# produced no record is EVIDENCE THE WRITER IS DEAD, not evidence the fleet is idle.
$liveInRepo = @()
foreach ($row in $sessionRows) {
    if (-not $row.Record) { continue }
    $cwd = $null
    if ($row.Record.PSObject.Properties.Name -contains 'cwd') { $cwd = Get-NormPath ([string]$row.Record.cwd) }
    if (-not $cwd -or $repoWorktrees -notcontains $cwd) { continue }
    $l = Test-RecordLiveness -Record $row.Record
    if ($l.State -eq 'LIVE') {
        $liveInRepo += [pscustomobject]@{
            SessionId = [string]$row.Record.sessionId
            Cwd       = $cwd
            Box       = (ConvertTo-BoxKey -Path ([string]$row.Record.cwd))
            Root      = $row.Root
        }
    }
}

$recordedSessionIds = @($records | ForEach-Object { [string]$_.Rec.sessionId } | Where-Object { $_ })
$liveWithoutRecord = @($liveInRepo | Where-Object { $recordedSessionIds -notcontains $_.SessionId })

# Writer heartbeat. "Installed", "resolvable" and "actually ran" are three different sentences and
# the first alone answers the neighbouring question.
$heartbeats = @()
$aliveDir = Join-Path $seatsDir '.writer-alive'
if (Test-Path -LiteralPath $aliveDir) {
    $heartbeats = @(Get-ChildItem -LiteralPath $aliveDir -Filter *.txt -EA SilentlyContinue)
}
$writerErrors = 0
$errFile = Join-Path $seatsDir '.writer-errors.txt'
if (Test-Path -LiteralPath $errFile) {
    $writerErrors = @(Get-Content -LiteralPath $errFile -EA SilentlyContinue).Count
}

# origin/main's own age. Every landed verdict is computed against this ref, and the ref moves ONLY on
# fetch. A landed verdict against a stale ref is the dangerous direction: this repo carries reverts,
# and against a stale cached main a reverted change reads as "already landed" -- i.e. deliberately
# reverted work would be recorded as done.
$originMainSha = Invoke-Git -Dir $repo -GitArgs @('rev-parse', 'origin/main')
$originMainAgeMinutes = $null
$fetchHead = Join-Path $common 'refs\remotes\origin\main'
if (Test-Path -LiteralPath $fetchHead) {
    $originMainAgeMinutes = [int]((Get-Date).ToUniversalTime() - (Get-Item -LiteralPath $fetchHead).LastWriteTimeUtc).TotalMinutes
}

# ---------------------------------------------------------------------------------------------
# Classify. Every state is derived here and none is read from a record.
# ---------------------------------------------------------------------------------------------

$now = [DateTime]::UtcNow

# NOT [string]$iso. MEASURED: ConvertFrom-Json parses "2026-08-14T20:24:29Z" into a [DateTime] with
# Kind=Utc, and casting THAT to string yields "08/14/2026 20:24:29" -- the Z is GONE. Parsing the
# result treats it as LOCAL, silently adding the UTC offset, and this box reported ages five hours in
# the FUTURE. The pattern was correct throughout; the TYPE was not what the code assumed, which is
# why re-reading the parse call finds nothing and dumping the type finds it immediately.
function Get-AgeHoursExact($iso) {
    # UNROUNDED, and it exists because ordering and display need different resolutions. Anything
    # that COMPARES two records must call this; anything that PRINTS an age wants the rounded one.
    if (-not $iso) { return $null }
    try {
        $utc = if ($iso -is [DateTime]) {
            if ($iso.Kind -eq [DateTimeKind]::Utc) { $iso } else { $iso.ToUniversalTime() }
        } else {
            [DateTimeOffset]::Parse([string]$iso, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime
        }
        return ($now - $utc).TotalHours
    } catch { return $null }
}

function Get-AgeHours($iso) {
    # The DISPLAY age. One decimal is a 6-minute bucket, which is fine to read and wrong to sort on.
    $e = Get-AgeHoursExact $iso
    if ($null -eq $e) { return $null }
    return [Math]::Round($e, 1)
}

$rows = @()
foreach ($r in $records) {
    $rec = $r.Rec
    $wt = if ($rec.PSObject.Properties.Name -contains 'worktree') { [string]$rec.worktree } else { '' }
    $sid = if ($rec.PSObject.Properties.Name -contains 'sessionId') { [string]$rec.sessionId } else { $null }

    # Fence state, positive answers only. There is no heartbeat on this host and registry writes are
    # event-driven, so nothing here can PROVE a session is gone -- only that it is present.
    $fence = 'UNKNOWN'
    if ($fenceAvailable -and $sid) {
        try { $fence = (Get-SessionLiveness -SessionId $sid).State } catch { $fence = 'UNKNOWN' }
    }

    $lifecycle = if ($rec.PSObject.Properties.Name -contains 'lifecycle') { [string]$rec.lifecycle } else { 'open' }
    $ageH = Get-AgeHours $rec.asOf

    # SUPERSEDED: a newer record in the same box, or a later record naming this one as predecessor.
    #
    # ORDER ON THE EXACT AGE, NEVER THE DISPLAYED ONE. This compared the ROUNDED age until
    # 2026-08-22, and one decimal is a 6-minute bucket -- so two records written inside the same
    # bucket tied, no strict `-lt` could order them, and BOTH survived as live roster rows.
    # Measured in messagefoundry-096b5d29 the day it was found: 21:17:32Z and 21:16:52Z, forty
    # seconds and two distinct records apart, both rounding to 0.1, both rendered.
    #
    # It is the defect this whole roster keeps producing in new places -- an instrument whose
    # resolution does not match the question. A 6-minute bucket is the right precision to READ and
    # the wrong precision to SORT, and the two uses had been sharing one function.
    # AND THE ORDER MUST BE TOTAL, not merely finer. asOf is stamped to the SECOND, so moving the
    # comparison off the rounded age shrank the tie window from 6 minutes to 1 second without
    # closing it -- two records written inside one second still tie, and a tie means NEITHER
    # supersedes the other, so both survive. That is the original defect at a smaller scale, and it
    # showed up as a test that passed alone and failed under load, which is the worst way to find it.
    #
    # The file name breaks the tie. It is arbitrary and it is DETERMINISTIC, which is the property
    # that matters: exactly one record in a tied pair survives, the same one on every render. It
    # does not claim to know which was written first -- at equal timestamps nothing here can.
    $exactAge = Get-AgeHoursExact $rec.asOf
    $superseded = $false
    foreach ($o in $records) {
        if ($o.File -eq $r.File) { continue }
        if ($o.Box -ne $r.Box) { continue }
        $oAge = Get-AgeHoursExact $o.Rec.asOf
        if ($null -eq $oAge -or $null -eq $exactAge) { continue }
        if ($oAge -lt $exactAge) { $superseded = $true }
        elseif ($oAge -eq $exactAge -and [string]::CompareOrdinal([string]$o.File, [string]$r.File) -gt 0) { $superseded = $true }
    }

    $state = switch ($true) {
        { $lifecycle -eq 'closed' }                    { 'CLOSED'; break }
        { $lifecycle -eq 'handed' }                    { 'HANDED'; break }
        { $superseded }                                { 'SUPERSEDED'; break }
        { $fence -eq 'LIVE' }                          { 'RUNNING'; break }
        { $fence -in @('UNVERIFIED', 'UNREADABLE') }   { 'POSSIBLY RUNNING'; break }
        { -not $fenceAvailable }                       { 'UNKNOWN-NO-FENCE'; break }
        default                                        { 'INTERRUPTED' }
    }
    if ($state -eq 'INTERRUPTED' -and $null -ne $ageH -and $ageH -gt ($FoldDays * 24)) {
        $state = 'ORPHANED-STALE'
    }

    # WRITER-STALE: the record's own clock versus the harness transcript's. A per-session record's
    # age stops tracking activity the moment the writer stops, and the two must not be conflated.
    $writerStale = ($null -ne $ageH -and $ageH -gt 1 -and $state -in @('RUNNING', 'POSSIBLY RUNNING'))

    $declared = $null
    if (($rec.PSObject.Properties.Name -contains 'seat') -and $rec.seat) { $declared = [string]$rec.seat }

    $rows += [pscustomobject]@{
        Box         = $r.Box
        SessionKey  = if ($rec.PSObject.Properties.Name -contains 'sessionKey') { [string]$rec.sessionKey } else { '' }
        Seat        = $declared
        State       = $state
        Fence       = $fence
        AgeHours    = $ageH
        # THE FACT, kept apart from the STATE LABEL that sometimes hides it. The state switch tests
        # lifecycle first, so a CLOSED or HANDED record is never LABELLED 'SUPERSEDED' even when a
        # newer record exists in its box -- and both labels are worth keeping, because "somebody
        # closed this" and "a newer episode exists" are different things a reader wants.
        #
        # Folding has to key on this boolean rather than on the label, or exactly the records a
        # remediating seat just closed stay on the roster forever. Measured 2026-08-22: four boxes
        # rendered two rows each for that reason, every one of them an orphan its seat had just
        # closed on purpose.
        Superseded  = $superseded
        # WHICH seat.ps1 wrote this record, as that writer measured itself. Read, never recomputed:
        # the question is what the writer was running AT THE TIME, and re-deriving it here would
        # answer today's question about a past write -- which is the exact substitution that
        # invented a phantom cause on 2026-08-22 and cost three sessions an evening.
        #
        # Absent on every record written before the field existed, and rendered as nothing rather
        # than as 'current'. A missing measurement is not a passing one.
        WriterScript = if (($rec.PSObject.Properties.Name -contains 'writerScript') -and $rec.writerScript) {
            [string]$rec.writerScript.state
        } else { $null }
        WriterStale = $writerStale
        Branch      = if ($rec.PSObject.Properties.Name -contains 'branch') { [string]$rec.branch } else { $null }
        Worktree    = $wt
        Epoch       = if ($rec.PSObject.Properties.Name -contains 'poolEpoch') { [int]$rec.poolEpoch } else { $null }
        Rec         = $rec
        File        = $r.File
    }
}

# ---------------------------------------------------------------------------------------------
# The receipt, and the STOP conditions it can fire.
# ---------------------------------------------------------------------------------------------

$stops = @()
if (-not $fenceAvailable) { $stops += 'fenceAvailable=false -- no config root with a sessions/ directory was found; every state below would be a guess' }
if ($liveWithoutRecord.Count -gt 0) { $stops += "liveSessionsWithoutRecord=$($liveWithoutRecord.Count) -- the writer is not running in every live seat, so this roster is INCOMPLETE by that many" }
if ($records.Count -eq 0 -and $heartbeats.Count -eq 0) { $stops += 'recordsExamined=0 AND writerHeartbeatIn=0 -- indistinguishable from a writer that was never installed' }
if ($null -ne $originMainAgeMinutes -and $originMainAgeMinutes -gt 60) { $stops += "originMainAgeMinutes=$originMainAgeMinutes -- origin/main has not been fetched recently; landed verdicts would be computed against a stale ref" }

# POINTER CENSUS, resolved here rather than trusted from the records. Printed as a RATIO because the
# numerator alone cannot be read: "1 dangling" is a crisis at 2 pointers and noise at 200. Measured
# 2026-08-22 the ratio was 2 broken of 3 recorded against 262 records -- the denominator is the part
# that says the mechanism is unused, and the numerator is the part that says the few uses are wrong.
$ptrTotal = 0; $ptrDangling = 0; $ptrDrifted = 0; $ptrUnreadable = 0
$ptrBoxes = @{}
foreach ($o in $records) {
    $h = $o.Rec.handoff
    if (-not ($h -and $h.path)) { continue }
    $ptrTotal++
    # BOXES AS WELL AS RECORDS, because ONE SEAT CAN HOLD SEVERAL RECORDS AND THE COUNTS DIVERGE.
    # A seat whose declaration landed in nosid.json and then re-declared under its session id leaves
    # BOTH records in place, each carrying the same pointer -- measured 2026-08-22, 5 pointers across
    # 4 boxes, with one box holding two records naming one file. Counting records answers "how many
    # rows carry a pointer", which is right for the per-row render below. It is the WRONG denominator
    # for "how many seats would be sent somewhere broken", and it inflates the moment anyone
    # remediates. Both are printed so a reader can see 5-across-4 rather than inferring 5 seats.
    $ptrBoxes[$o.Box] = $true
    try {
        if (-not (Test-Path -LiteralPath ([string]$h.path) -PathType Leaf)) { $ptrDangling++ }
        elseif ($null -ne $h.bytes -and [long]$h.bytes -ne (Get-Item -LiteralPath ([string]$h.path) -EA Stop).Length) { $ptrDrifted++ }
    } catch { $ptrUnreadable++ }
}
if ($ptrDangling -gt 0 -or $ptrDrifted -gt 0) {
    $spread = if ($ptrBoxes.Count -ne $ptrTotal) { " across $($ptrBoxes.Count) seat(s) -- records exceed seats, so at least one seat holds duplicate records" } else { " across $($ptrBoxes.Count) seat(s)" }
    $stops += "handoffPointersBroken=$($ptrDangling + $ptrDrifted) of $ptrTotal$spread -- a seat told to READ THE HANDOFF would be sent to a file that is missing or is no longer the one that was pointed at"
}

$receipt = [ordered]@{
    renderedAtUtc             = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    seatsDir                  = $seatsDir
    rootsExamined             = $rootsExamined
    fenceAvailable            = $fenceAvailable
    recordsExamined           = $records.Count
    recordsUnreadable         = $unreadableRecords
    liveSessionsInRepo        = $liveInRepo.Count
    liveSessionsWithoutRecord = $liveWithoutRecord.Count
    writerHeartbeatIn         = $heartbeats.Count
    writerErrorLines          = $writerErrors
    repoWorktrees             = $repoWorktrees.Count
    originMainSha             = $originMainSha
    originMainAgeMinutes      = $originMainAgeMinutes
    handoffPointers           = $ptrTotal
    handoffPointerSeats       = $ptrBoxes.Count
    handoffPointersDangling   = $ptrDangling
    handoffPointersDrifted    = $ptrDrifted
    handoffPointersUnreadable = $ptrUnreadable
    stopConditions            = @($stops)
}

# ---------------------------------------------------------------------------------------------
# Render.
# ---------------------------------------------------------------------------------------------

if ($Chip) {
    $row = $rows | Where-Object { $_.Box -eq $BoxKey -and $_.SessionKey -eq $SessionKey } | Select-Object -First 1
    if (-not $row) { Write-Error "fleet.ps1: no record for $BoxKey/$SessionKey"; exit 2 }
    $rec = $row.Rec
    $lines = @()
    $lines += "You are a REPLACEMENT SEAT. The session that held this work is gone. You inherit NOTHING"
    $lines += "from it except what is written below. Everything here was measured at $($rec.asOf) and the"
    $lines += "world has moved since -- RE-VERIFY BEFORE YOU ACT, do not trust a line because it is specific."
    $lines += ""
    $lines += "PREDECESSOR CHECKOUT: $($rec.worktree)"
    $lines += "BRANCH: $($row.Branch)   (identified by NAME, never by a commit id -- a rebase reissues the id)"
    if ($rec.tip) { $lines += "ITS TIP WAS: $($rec.tip)  AS OF $($rec.asOf). Resolve the branch yourself; do not use this id as an identifier." }
    $lines += ""
    if ($rec.seat) { $lines += "SEAT: $($rec.seat)" } else { $lines += "SEAT: NOT DECLARED. The predecessor never declared one; do not invent a role." }
    if ($rec.goal) { $lines += "GOAL AS DECLARED: $($rec.goal)" } else { $lines += "GOAL: NOT DECLARED." }
    if ($rec.done) { $lines += "DONE MEANS: $($rec.done)" }
    if ($rec.outOfScope) { $lines += "OUT OF SCOPE: $($rec.outOfScope)" }
    $lines += ""
    $lines += "FIRST ACTIONS, IN THIS ORDER, BEFORE ANY BUILDING:"
    $lines += "  1. Look at the predecessor checkout. Uncommitted work there is the ONLY thing that truly dies:"
    $lines += "     git -C `"$($rec.worktree)`" status --porcelain"
    $lines += "     git -C `"$($rec.worktree)`" log --oneline origin/main..HEAD"
    if ($rec.stashSha) {
        $lines += "     A stash commit was captured at record time, covering TRACKED edits only: $($rec.stashSha)"
        $lines += "     Recover with: git -C `"$($rec.worktree)`" checkout $($rec.stashSha) -- ."
    }
    # The loudest thing in the whole briefing, because it is the only category that is GONE if the
    # checkout is removed. `git stash create` has no -u, so an untracked file is held by no git
    # object anywhere -- not in a stash, not in a commit, not on a remote.
    $untracked = @()
    if (($rec.PSObject.Properties.Name -contains 'dirty') -and $rec.dirty -and
        ($rec.dirty.PSObject.Properties.Name -contains 'untracked')) {
        $untracked = @($rec.dirty.untracked)
    }
    if ($untracked.Count -gt 0) {
        $lines += ""
        $lines += "     *** $($untracked.Count) UNTRACKED FILE(S) EXIST ONLY IN THAT WORKING DIRECTORY. ***"
        $lines += "     NO GIT OBJECT HOLDS THEM -- not the stash above, not a commit, not a remote."
        $lines += "     COPY THEM BEFORE ANYTHING ELSE. If that checkout is removed they are gone:"
        foreach ($u in ($untracked | Select-Object -First 40)) { $lines += "       $u" }
        if ($untracked.Count -gt 40) { $lines += "       ... and $($untracked.Count - 40) more" }
    }
    $lines += "  2. git fetch origin FIRST, then decide whether the work already landed. Compare CONTENT, not"
    $lines += "     ancestry -- squash-merge makes 'commits ahead' and 'content ahead' disagree routinely:"
    if ($rec.touchedPaths -and @($rec.touchedPaths).Count -gt 0) {
        $lines += "       git diff --name-only origin/main $($row.Branch) -- " + (@($rec.touchedPaths) -join ' ')
        $lines += "     Empty output means the content is already on main. DO NOT REBUILD IT."
    } else {
        $lines += "       (no touched paths were recorded, so this check is UNCHECKABLE here -- derive the"
        $lines += "        pathspec yourself from the branch's merge-base before concluding anything)"
    }
    $lines += "  3. Re-check claims and allocations BEFORE taking any. This briefing was written at generate"
    $lines += "     time and you are reading it at click time; a hold may have been declared in between."
    $ownClaims = @($rec.claims | Where-Object { $_.attribution -eq 'this-episode' })
    $inhClaims = @($rec.claims | Where-Object { $_.attribution -ne 'this-episode' })
    if ($ownClaims.Count -gt 0) { $lines += "     CLAIMS HELD BY THE PREDECESSOR EPISODE: " + (($ownClaims | ForEach-Object { $_.key }) -join ', ') }
    else { $lines += "     CLAIMS HELD BY THE PREDECESSOR EPISODE: none" }
    if ($inhClaims.Count -gt 0) {
        $lines += "     ALSO PRESENT IN THAT WORKTREE BUT FROM EARLIER OCCUPANTS -- NOT YOURS, DO NOT REHOME:"
        $lines += "       " + (($inhClaims | ForEach-Object { $_.key }) -join ', ')
    }
    $ownAlloc = @($rec.allocations | Where-Object { $_.attribution -eq 'this-episode' })
    $inhAlloc = @($rec.allocations | Where-Object { $_.attribution -ne 'this-episode' })
    if ($ownAlloc.Count -gt 0) { $lines += "     LEDGER NUMBERS ALLOCATED BY THIS EPISODE: " + (($ownAlloc | ForEach-Object { "$($_.kind) #$($_.number)" }) -join ', ') }
    else { $lines += "     LEDGER NUMBERS ALLOCATED BY THIS EPISODE: none" }
    if ($inhAlloc.Count -gt 0) {
        $lines += "     $($inhAlloc.Count) MORE are allocated to that worktree PATH by earlier occupants."
        $lines += "     THEY ARE NOT YOURS. Do not rehome them and do not cite them."
    }
    if ($rec.handoff -and $rec.handoff.path) {
        $lines += ""
        $lines += "  4. READ THE HANDOFF: $($rec.handoff.path)"
        # RESOLVED HERE, AT RENDER, NOT READ OUT OF THE RECORD. seat.ps1 re-checks the pointer on
        # every Stop, which covers a LIVE seat -- but the pointer most likely to be wrong belongs to
        # a seat that will never run again, and a dead seat's writer cannot report its own decay.
        # Measured 2026-08-22: the one DANGLING pointer on disk belongs to nice-payne-4dcee0, whose
        # last turn ended 2026-08-19. Only a reader was ever going to catch it.
        $hp = [string]$rec.handoff.path
        $live = $null
        try { if (Test-Path -LiteralPath $hp -PathType Leaf) { $live = (Get-Item -LiteralPath $hp -EA Stop).Length } }
        catch { $live = $null }
        $wasBytes = $rec.handoff.bytes
        if ($null -eq $live) {
            $lines += "     WARNING: THAT FILE IS NOT THERE NOW. Treat it as a lead, not a document."
        }
        elseif ($null -ne $wasBytes -and [long]$wasBytes -ne [long]$live) {
            # Named separately because it is the failure that does NOT announce itself: the path
            # opens, so nothing looks wrong, and the reader believes they were handed the document
            # that was pointed at.
            $lines += "     WARNING: THAT FILE HAS CHANGED SINCE IT WAS POINTED AT -- $wasBytes bytes recorded, $live now."
            $lines += "     It still opens, so nothing else will tell you. Read it as current work, not as a settled handoff."
        }
    }
    $lines += ""
    $lines += "  5. Declare yourself so the NEXT switch reads fresh state rather than backfilling:"
    $lines += "     pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <seat> -Predecessor $($row.Box)/$($row.SessionKey) -Goal `"...`""
    $lines += ""
    $lines += "ACCOUNT BOUNDARY -- these do NOT cross and must not be inherited: usage figures, project"
    $lines += "memory, artifact capabilities, workflow caches, and the realtime send channel. Read your own."
    $lines -join "`n"
    exit 0
}

if ($Json) {
    [ordered]@{
        receipt = $receipt
        # Handoff* are computed here, not read from the record: -Json is what another tool consumes,
        # and a consumer that got the recorded flag would inherit the same never-re-checked value the
        # human render stopped trusting above.
        rows    = @($rows | Select-Object Box, SessionKey, Seat, State, Fence, AgeHours, Superseded, WriterScript, WriterStale, Branch, Worktree, Epoch,
            @{n = 'HandoffPath'; e = { if ($_.Rec.handoff) { [string]$_.Rec.handoff.path } else { $null } } },
            @{n = 'HandoffState'; e = {
                    $h = $_.Rec.handoff
                    if (-not ($h -and $h.path)) { return $null }
                    try {
                        if (-not (Test-Path -LiteralPath ([string]$h.path) -PathType Leaf)) { return 'dangling' }
                        if ($null -ne $h.bytes -and [long]$h.bytes -ne (Get-Item -LiteralPath ([string]$h.path) -EA Stop).Length) { return 'drifted' }
                        return 'resolves'
                    } catch { return 'unreadable' }
                }
            })
    } | ConvertTo-Json -Depth 8
    $code = if ($fenceAvailable) { 0 } else { 2 }
exit $code
}

# Default: text.
"FLEET CONTINUITY ROSTER"
"rendered $($receipt.renderedAtUtc)"
""
"RECEIPT -- what was EXAMINED, not merely what was found:"
foreach ($k in $receipt.Keys) {
    if ($k -eq 'stopConditions') { continue }
    "  {0,-26} {1}" -f $k, $receipt[$k]
}
""
if ($stops.Count -gt 0) {
    "STOP CONDITIONS FIRED -- $($stops.Count). DO NOT TREAT THE ROSTER BELOW AS COMPLETE:"
    foreach ($s in $stops) { "  - $s" }
    ""
} else {
    "NO STOP CONDITIONS. The roster below is as complete as this instrument can establish."
    ""
}

# TWO FOLDS, COUNTED SEPARATELY, because they answer different questions and a reader who is
# surprised by a missing row needs to know WHICH rule took it.
#
# WHY SUPERSEDED IS FOLDED AT ALL. The state has been computed correctly since it was written --
# measured 2026-08-22 on the busiest box, messagefoundry-096b5d29: 104 records, 102 SUPERSEDED, 1
# INTERRUPTED, 1 CLOSED. Every one of those 102 was rendered as its own roster line, so ONE
# worktree occupied 104 of the roster's 279 rows. Nothing was wrong with the classification; it
# just was not used. A reader asking "who holds this worktree and what are they doing" cannot
# answer it from 104 lines, and that is the only question this roster exists to answer.
#
# FOLDED, NOT DROPPED, AND THAT IS THE WHOLE DESIGN. A superseded record is evidence -- a seat is
# deliberately holding a nosid record tonight BECAUSE it evidences a defect, and a roster that
# silently discarded superseded rows would erase exactly that class of proof. So the count is
# always printed and -History always brings them back.
$showHistory = $History -or $All
$shown = $rows
if (-not $All) { $shown = $shown | Where-Object { $_.State -ne 'ORPHANED-STALE' } }
if (-not $showHistory) { $shown = $shown | Where-Object { -not $_.Superseded } }
$shown = @($shown)
$foldedStale = @($rows | Where-Object { $_.State -eq 'ORPHANED-STALE' }).Count
$foldedSuperseded = @($rows | Where-Object { $_.Superseded }).Count
$folded = @($rows).Count - @($shown).Count

if (@($rows).Count -eq 0) {
    "NO EPISODE RECORDS EXIST. That is NOT the same as 'no seats were working' -- see the receipt above."
} else {
    "{0,-30} {1,-14} {2,-18} {3,-7} {4}" -f 'BOX', 'SEAT', 'STATE', 'AGE_H', 'BRANCH'
    foreach ($row in ($shown | Sort-Object State, Box)) {
        $seat = if ($row.Seat) { $row.Seat } else { 'NOT-DECLARED' }
        $mark = if ($row.WriterStale) { ' [WRITER-STALE]' } else { '' }
        # A DIFFERENT WORD ON PURPOSE. WRITER-STALE above means THE RECORD IS OLD; this means THE
        # SCRIPT IS OLD. Two facts about two objects, and one token carrying both is the failure
        # CLAUDE.md section 11 describes. Only out-of-date is marked -- 'modified' is the ordinary
        # state of a maintainer's own checkout and flagging it would train readers to ignore this.
        if ($row.WriterScript -eq 'out-of-date') { $mark += ' [SCRIPT-OUT-OF-DATE]' }
        "{0,-30} {1,-14} {2,-18} {3,-7} {4}{5}" -f $row.Box, $seat, $row.State, $row.AgeHours, $row.Branch, $mark
    }
}
if ($folded -gt 0) {
    ""
    # Named separately on purpose. "12 rows folded" tells a reader something is missing and not
    # which rule removed it, and the two rules have different remedies.
    if (-not $All -and $foldedStale -gt 0) {
        "$foldedStale row(s) folded as ORPHANED-STALE (older than $FoldDays days). Show with -All."
    }
    if (-not $showHistory -and $foldedSuperseded -gt 0) {
        "$foldedSuperseded row(s) folded as SUPERSEDED (an older episode of a box that has a newer record). Show with -History."
    }
}

""
"RESPAWN POPULATION (INTERRUPTED, HANDED): " + @($rows | Where-Object { $_.State -in @('INTERRUPTED', 'HANDED') }).Count
"  Never respawned: RUNNING, POSSIBLY RUNNING, SUPERSEDED, CLOSED."
"  Briefing for one row:  fleet.ps1 -Chip -BoxKey <box> -SessionKey <key>"

$code = if ($fenceAvailable) { 0 } else { 2 }
exit $code

