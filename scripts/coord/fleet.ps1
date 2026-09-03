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

# HOW FRESH IS THE origin/main EVERY LANDED VERDICT IS JUDGED AGAINST? A landed verdict against a
# stale ref is the dangerous direction: this repo carries reverts, and against a stale cached main a
# reverted change reads as "already landed" -- i.e. deliberately reverted work recorded as done. A
# remote-tracking ref is only ever refreshed by a fetch, so the age of the ref IS the age of the last
# fetch, and the fetch is the thing to time.
#
# READ THE FETCH CLOCK, NOT THE REF FILE (BACKLOG #1374). This stated fetch recency and stat'ed
# `refs/remotes/origin/main`, whose mtime moves when the REF MOVES and not when a fetch happened.
# They are two clocks. Measured on this repo 2026-08-28: `.git/FETCH_HEAD` at 18:02:16.769 against
# the loose ref at 18:01:24.059 -- a fetch landed 52 seconds AFTER the ref last moved and left the
# ref untouched. Reproduced from an empty sandbox 2026-09-03: a fetch against an unmoved remote
# writes FETCH_HEAD and creates no loose ref at all, so a fleet that fetched seconds ago fired the
# stop and printed DO NOT TREAT THE ROSTER BELOW AS COMPLETE about a fetch that was fresh.
#
# AND THE LOOSE REF WAS NOT EVEN THE COMMON CASE, WHICH IS THE HALF THAT RENDERED HEALTHY. Measured
# 2026-09-03: `git clone` packs `refs/remotes/origin/main` into `packed-refs` and writes NO loose
# ref, and `git pack-refs --all` puts any clone in that state. With nothing to stat the value stayed
# null, the old `-ne $null` guard meant the stop could not fire, and an absent warning renders
# identically to a healthy one. So the unmeasurable case is now a STOP in its own right: this
# instrument must never be silent about being blind.
#
# FETCH_HEAD IS PER-WORKTREE AND THE REMOTE-TRACKING REF IS SHARED, so read the whole clone.
# Measured 2026-09-03: a fetch run inside a linked worktree writes `<git-dir>/FETCH_HEAD` and leaves
# `<common>/FETCH_HEAD` untouched, while `refs/remotes/origin/main` is common to the clone. Every
# seat here works in a linked worktree, so reading only the common dir would report the PRIMARY's
# last fetch. The question is "when was this clone's shared origin/main last refreshed", and any
# worktree's fetch refreshes it -- so the answer is the NEWEST clock in the clone.
#
# THE SAME CONCLUSION WAS REACHED INDEPENDENTLY IN THIS REPO, and the reasoning lives there rather
# than being restated here: `_remote_knowledge()` in scripts/asvs/scorecard.py reads FETCH_HEAD,
# probes more than one git dir, takes the newest, and treats "no clock" as a loud NEVER-FETCHED. It
# probes only the CURRENT worktree's git dir plus the common one, which is right for a tool judging
# ONE tree; this renders a roster for the whole clone, so it sweeps every worktree.
#
# DO NOT "FIX" THIS BACK TO THE REFLOG. It is the obvious-looking alternative -- it survives
# `pack-refs` and is not per-worktree -- and it is the SAME WRONG CLOCK, because a reflog records ref
# MOVEMENTS. Measured on this repo 2026-09-03: the newest `origin/main` reflog entry and
# `.git/FETCH_HEAD` differ by 1000 seconds, the fetch being the newer. `git for-each-ref` is out for
# the same reason: it exposes the upstream COMMIT's date, which here preceded the ref update by 11
# minutes. No git plumbing reports a fetch time, so the file mtime is the only clock on offer.
#
# STATED LIMITS, all three in the same direction a reader needs to know about:
#   1. `git ls-remote origin main` would answer the real question directly ("is my cached ref
#      current?") in about 0.7 seconds, measured. DECLINED: this script is a PURE READER a stranded
#      session runs to reconstitute a fleet, so it must work offline and unauthenticated. A network
#      round-trip per render buys accuracy by adding the failure mode the instrument exists to
#      survive. The clock is therefore a PROXY, deliberately.
#   2. FETCH_HEAD says "a fetch happened", not "origin/main was refreshed". `git fetch origin
#      refs/pull/N/head`, or a fetch of a different remote, bumps this clock while leaving
#      origin/main untouched -- so this can read FRESH while the ref is stale, which is the
#      dangerous direction. The file's own first line names the ref and remote fetched, so closing
#      it is possible and is not attempted here.
#   3. `git fetch --no-write-fetch-head` refreshes the ref and writes no clock at all, so it reads
#      as no fetch ever. That one fails LOUD, via the unmeasurable stop, which is the safe direction.
$originMainSha = Invoke-Git -Dir $repo -GitArgs @('rev-parse', 'origin/main')

# The clone's worktrees, enumerated a SECOND way and on purpose: `$repoWorktrees` above lists WORKING
# TREE paths from `git worktree list`, and getting a git dir out of one costs a git child process
# each. The admin directories under `<common>/worktrees` are the git dirs, already.
$fetchClockPaths = @(Join-Path $common 'FETCH_HEAD')
$worktreeGitDirs = Join-Path $common 'worktrees'
if (Test-Path -LiteralPath $worktreeGitDirs) {
    foreach ($d in @(Get-ChildItem -LiteralPath $worktreeGitDirs -Directory -EA SilentlyContinue)) {
        $fetchClockPaths += (Join-Path $d.FullName 'FETCH_HEAD')
    }
}

$lastFetchAgeMinutes = $null
# NEVER NULL, because this is the line a reader scans past. A blank value beside a null age is how
# the blind case passed for a healthy one; a sentence saying it could not be measured cannot.
$lastFetchClock = 'UNMEASURABLE -- no FETCH_HEAD in this clone (see stop conditions)'
# -LiteralPath, not a glob: a checkout path may contain [ or ], and -Path would treat it as a
# wildcard and silently match nothing. Missing and unreadable both fall out as no item.
$newestFetch = @($fetchClockPaths |
        ForEach-Object { Get-Item -LiteralPath $_ -EA SilentlyContinue } |
        Sort-Object LastWriteTimeUtc -Descending |
        Select-Object -First 1)
if ($newestFetch.Count -eq 1) {
    $lastFetchAgeMinutes = [int]((Get-Date).ToUniversalTime() - $newestFetch[0].LastWriteTimeUtc).TotalMinutes
    $lastFetchClock = $newestFetch[0].FullName
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
function Get-AgeHours($iso) {
    if (-not $iso) { return $null }
    try {
        $utc = if ($iso -is [DateTime]) {
            if ($iso.Kind -eq [DateTimeKind]::Utc) { $iso } else { $iso.ToUniversalTime() }
        } else {
            [DateTimeOffset]::Parse([string]$iso, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime
        }
        return [Math]::Round(($now - $utc).TotalHours, 1)
    } catch { return $null }
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
    $superseded = $false
    foreach ($o in $records) {
        if ($o.File -eq $r.File) { continue }
        if ($o.Box -ne $r.Box) { continue }
        $oAge = Get-AgeHours $o.Rec.asOf
        if ($null -ne $oAge -and $null -ne $ageH -and $oAge -lt $ageH) { $superseded = $true }
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
# BOTH DIRECTIONS FIRE, and the null one is the reason this rung exists (BACKLOG #1374). The old
# guard was `-ne $null -and -gt 60`, so the one state where the instrument knows nothing was the one
# state it said nothing about.
if ($null -eq $lastFetchAgeMinutes) {
    $stops += 'lastFetchAgeMinutes=UNMEASURABLE -- no FETCH_HEAD exists anywhere in this clone, so this instrument CANNOT tell a fetch made seconds ago from one never made, and every landed verdict below is computed against an origin/main of UNKNOWN age. A fresh clone reads this way on purpose: `git clone` writes no FETCH_HEAD. Run `git fetch origin` -- it both refreshes the ref and makes this field measurable'
} elseif ($lastFetchAgeMinutes -gt 60) {
    $stops += "lastFetchAgeMinutes=$lastFetchAgeMinutes -- the last fetch anywhere in this clone was $lastFetchAgeMinutes minutes ago; landed verdicts would be computed against a stale origin/main"
}

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
# BACKLOG #1372: A DRIFTED POINTER IS NOT A BROKEN ONE, so it no longer feeds this stop.
# A pointer exists so a seat told to READ THE HANDOFF reaches the right document. When the file
# has been UPDATED they reach the CURRENT one -- misdescribing a byte count and misdirecting a
# reader are different harms, and only the second is brokenness.
#
# MEASURED, and the numbers are why this changed rather than an opinion about it. Two readings 81
# minutes apart, 2026-08-27:
#
#     07:51Z -> 09:12Z      gone 22 -> 22 (FLAT)    drifted 2 -> 5    clean 5 -> 6
#
# All five drifted seats were the seats keeping their handoffs current under the 96% PROTECT rung,
# which demands exactly that every few minutes; one was measured entering the state NINETY SECONDS
# after repairing it. So the alarm population grows as the fleet behaves correctly, while the 22
# pointers that name a file which does not exist -- the number a reader actually needs -- sat
# unchanged and invisible inside an 81% roll-up.
#
# THE AUTHOR'S ARGUMENT IN seat.ps1 IS NOT OVERTURNED AND NOTHING HERE ERASES DRIFT. Recorded
# values are still never repaired, `handoffPointersDrifted` is still counted and still rendered
# below. What changed is only what the STOP CONDITION aggregates.
#
# Ruled 2026-08-27 by the Liaison under the owner's standing AFK authority, with their own conflict
# declared and the decision logged to the owner-item ledger for overturn. Both obvious deciders --
# they and this builder -- are among the drifted seats, which is recorded rather than worked around.
if ($ptrDangling -gt 0) {
    $spread = if ($ptrBoxes.Count -ne $ptrTotal) { " across $($ptrBoxes.Count) seat(s) -- records exceed seats, so at least one seat holds duplicate records" } else { " across $($ptrBoxes.Count) seat(s)" }
    $stops += "handoffPointersBroken=$ptrDangling of $ptrTotal$spread -- a seat told to READ THE HANDOFF would be sent to a file that is MISSING (drifted pointers are counted separately as handoffPointersDrifted and are NOT broken -- see BACKLOG #1372)"
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
    # NAMED FOR THE CLOCK IT READS. The predecessor key `originMainAgeMinutes` claimed fetch recency
    # and timed the ref file instead; nothing outside docs/BACKLOG.md ever read it by name (checked
    # against this repo and the vault's origin/main, with `fleet.ps1` itself as the positive
    # control), so it was renamed rather than doubled. A consumer pinned to the old key now finds no
    # key at all, which is the honest failure -- the alternative was a familiar name that keeps
    # answering the wrong question.
    lastFetchAgeMinutes       = $lastFetchAgeMinutes
    lastFetchClock            = $lastFetchClock
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
        rows    = @($rows | Select-Object Box, SessionKey, Seat, State, Fence, AgeHours, WriterStale, Branch, Worktree, Epoch,
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
    # A NULL MUST NOT RENDER AS WHITESPACE. `-f` formats $null as the empty string, so a field this
    # instrument could not measure printed as a blank column and read exactly like a quiet, healthy
    # one -- the same failure BACKLOG #1374 is about, on whichever field happens to be null next.
    # `originMainSha` is null in any checkout with no `origin` remote and was rendering that way.
    # This is the generic backstop; a field whose null needs a REMEDY still carries its own sentence
    # (`lastFetchClock`), because "(null)" cannot tell anyone to run `git fetch origin`.
    $v = if ($null -eq $receipt[$k]) { '(null)' } else { $receipt[$k] }
    "  {0,-26} {1}" -f $k, $v
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

$shown = if ($All) { $rows } else { $rows | Where-Object { $_.State -ne 'ORPHANED-STALE' } }
$folded = @($rows).Count - @($shown).Count

if (@($rows).Count -eq 0) {
    "NO EPISODE RECORDS EXIST. That is NOT the same as 'no seats were working' -- see the receipt above."
} else {
    "{0,-30} {1,-14} {2,-18} {3,-7} {4}" -f 'BOX', 'SEAT', 'STATE', 'AGE_H', 'BRANCH'
    foreach ($row in ($shown | Sort-Object State, Box)) {
        $seat = if ($row.Seat) { $row.Seat } else { 'NOT-DECLARED' }
        $mark = if ($row.WriterStale) { ' [WRITER-STALE]' } else { '' }
        "{0,-30} {1,-14} {2,-18} {3,-7} {4}{5}" -f $row.Box, $seat, $row.State, $row.AgeHours, $row.Branch, $mark
    }
}
if ($folded -gt 0) { ""; "$folded row(s) folded as ORPHANED-STALE (older than $FoldDays days). Show with -All." }

""
"RESPAWN POPULATION (INTERRUPTED, HANDED): " + @($rows | Where-Object { $_.State -in @('INTERRUPTED', 'HANDED') }).Count
"  Never respawned: RUNNING, POSSIBLY RUNNING, SUPERSEDED, CLOSED."
"  Briefing for one row:  fleet.ps1 -Chip -BoxKey <box> -SessionKey <key>"

$code = if ($fenceAvailable) { 0 } else { 2 }
exit $code

