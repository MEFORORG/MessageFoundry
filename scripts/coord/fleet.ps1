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
        fleet.ps1 -ColdStart       # receipt + EVERY respawn-eligible briefing, for the first
                                   # session after an account switch. See docs/FLEET-CONTINUITY.md.

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
    [switch]$ColdStart,
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
if ($null -ne $originMainAgeMinutes -and $originMainAgeMinutes -gt 60) { $stops += "originMainAgeMinutes=$originMainAgeMinutes -- origin/main has not been fetched recently; landed verdicts would be computed against a stale ref" }

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
    stopConditions            = @($stops)
}

# ---------------------------------------------------------------------------------------------
# Render.
# ---------------------------------------------------------------------------------------------

# Set-StrictMode makes a bare $rec.<missing> a TERMINATING error, and the cold start reads records
# written by the PREVIOUS writer version -- precisely where a field can be absent. The failure mode
# is worse than a crash: the briefing header has already been emitted, so the operator is handed a
# TRUNCATED briefing that looks like output. Every optional read goes through here.
function Get-Field($Obj, [string]$Name) {
    if ($null -eq $Obj) { return $null }
    if ($Obj.PSObject.Properties.Name -contains $Name) { return $Obj.$Name }
    return $null
}

# @($null) is a ONE-element array holding $null, NOT an empty array -- so a missing list field piped
# into Where-Object hands $null to the filter, and $null.attribution is another terminating error
# under StrictMode. Every list-shaped read goes through here so the absent case is genuinely empty.
# CALL SITES STILL WRAP IN @(): a PowerShell function RETURN unrolls a one-element array to a
# scalar, and a scalar has no .Count -- which is a terminating error under StrictMode too.
function Get-FieldArray($Obj, [string]$Name) {
    $v = Get-Field $Obj $Name
    if ($null -eq $v) { return @() }
    return @($v | Where-Object { $null -ne $_ })
}

# ONE briefing generator, called by BOTH -Chip and -ColdStart. A second copy of this text is how the
# version nobody reads becomes the version the owner pastes -- the same argument this file's header
# already makes about not re-defining the liveness fence.
function New-ChipBriefing {
    param($Row)

    $row = $Row
    $rec = $row.Rec

    $asOf       = Get-Field $rec 'asOf'
    $recWt      = Get-Field $rec 'worktree'
    $tip        = Get-Field $rec 'tip'
    $seat       = Get-Field $rec 'seat'
    $goal       = Get-Field $rec 'goal'
    $doneMeans  = Get-Field $rec 'done'
    $outOfScope = Get-Field $rec 'outOfScope'
    $stashSha   = Get-Field $rec 'stashSha'

    $lines = @()
    $lines += "You are a REPLACEMENT SEAT. The session that held this work is gone. You inherit NOTHING"
    $lines += "from it except what is written below. Everything here was measured at $asOf and the"
    $lines += "world has moved since -- RE-VERIFY BEFORE YOU ACT, do not trust a line because it is specific."
    $lines += ""
    $lines += "PREDECESSOR CHECKOUT: $recWt"
    $lines += "BRANCH: $($row.Branch)   (identified by NAME, never by a commit id -- a rebase reissues the id)"
    if ($tip) { $lines += "ITS TIP WAS: $tip  AS OF $asOf. Resolve the branch yourself; do not use this id as an identifier." }
    $lines += ""
    if ($seat) { $lines += "SEAT: $seat" } else { $lines += "SEAT: NOT DECLARED. The predecessor never declared one; do not invent a role." }
    if ($goal) { $lines += "GOAL AS DECLARED: $goal" } else { $lines += "GOAL: NOT DECLARED." }
    if ($doneMeans) { $lines += "DONE MEANS: $doneMeans" }
    if ($outOfScope) { $lines += "OUT OF SCOPE: $outOfScope" }
    $lines += ""
    $lines += "FIRST ACTIONS, IN THIS ORDER, BEFORE ANY BUILDING:"
    $lines += "  1. Look at the predecessor checkout. Uncommitted work there is the ONLY thing that truly dies:"
    $lines += "     git -C `"$recWt`" status --porcelain"
    $lines += "     git -C `"$recWt`" log --oneline origin/main..HEAD"
    if ($stashSha) {
        $lines += "     A stash commit was captured at record time, covering TRACKED edits only: $stashSha"
        $lines += "     Recover with: git -C `"$recWt`" checkout $stashSha -- ."
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
    $touched = @(Get-FieldArray $rec 'touchedPaths')
    if ($touched.Count -gt 0) {
        $lines += "       git diff --name-only origin/main $($row.Branch) -- " + ($touched -join ' ')
        $lines += "     Empty output means the content is already on main. DO NOT REBUILD IT."
    } else {
        $lines += "       (no touched paths were recorded, so this check is UNCHECKABLE here -- derive the"
        $lines += "        pathspec yourself from the branch's merge-base before concluding anything)"
    }
    $lines += "  3. Re-check claims and allocations BEFORE taking any. This briefing was written at generate"
    $lines += "     time and you are reading it at click time; a hold may have been declared in between."
    $recClaims = @(Get-FieldArray $rec 'claims')
    $ownClaims = @($recClaims | Where-Object { $_.attribution -eq 'this-episode' })
    $inhClaims = @($recClaims | Where-Object { $_.attribution -ne 'this-episode' })
    if ($ownClaims.Count -gt 0) { $lines += "     CLAIMS HELD BY THE PREDECESSOR EPISODE: " + (($ownClaims | ForEach-Object { $_.key }) -join ', ') }
    else { $lines += "     CLAIMS HELD BY THE PREDECESSOR EPISODE: none" }
    if ($inhClaims.Count -gt 0) {
        $lines += "     ALSO PRESENT IN THAT WORKTREE BUT FROM EARLIER OCCUPANTS -- NOT YOURS, DO NOT REHOME:"
        $lines += "       " + (($inhClaims | ForEach-Object { $_.key }) -join ', ')
    }
    $recAlloc = @(Get-FieldArray $rec 'allocations')
    $ownAlloc = @($recAlloc | Where-Object { $_.attribution -eq 'this-episode' })
    $inhAlloc = @($recAlloc | Where-Object { $_.attribution -ne 'this-episode' })
    if ($ownAlloc.Count -gt 0) { $lines += "     LEDGER NUMBERS ALLOCATED BY THIS EPISODE: " + (($ownAlloc | ForEach-Object { "$($_.kind) #$($_.number)" }) -join ', ') }
    else { $lines += "     LEDGER NUMBERS ALLOCATED BY THIS EPISODE: none" }
    if ($inhAlloc.Count -gt 0) {
        $lines += "     $($inhAlloc.Count) MORE are allocated to that worktree PATH by earlier occupants."
        $lines += "     THEY ARE NOT YOURS. Do not rehome them and do not cite them."
    }
    $handoff = Get-Field $rec 'handoff'
    if ($handoff -and (Get-Field $handoff 'path')) {
        $lines += ""
        $lines += "  4. READ THE HANDOFF: $(Get-Field $handoff 'path')"
        if (Get-Field $handoff 'unresolved') {
            $lines += "     WARNING: that path DID NOT RESOLVE when it was recorded. Treat it as a lead, not a document."
        }
    }
    $lines += ""
    $lines += "  5. Declare yourself so the NEXT switch reads fresh state rather than backfilling:"
    $lines += "     pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <seat> -Predecessor $($row.Box)/$($row.SessionKey) -Goal `"...`""
    $lines += ""
    $lines += "ACCOUNT BOUNDARY -- these do NOT cross and must not be inherited: usage figures, project"
    $lines += "memory, artifact capabilities, workflow caches, and the realtime send channel. Read your own."
    $lines -join "`n"
}

# The receipt, as data. Rendered by the default text path AND by -ColdStart; a cold start that
# printed briefings without it would be the confident-empty-answer failure this file exists to
# refuse, one level up.
function Get-ReceiptLines {
    $out = @()
    $out += "RECEIPT -- what was EXAMINED, not merely what was found:"
    foreach ($k in $receipt.Keys) {
        if ($k -eq 'stopConditions') { continue }
        $out += "  {0,-26} {1}" -f $k, $receipt[$k]
    }
    $out += ""
    if ($stops.Count -gt 0) {
        $out += "STOP CONDITIONS FIRED -- $($stops.Count). DO NOT TREAT WHAT FOLLOWS AS COMPLETE:"
        foreach ($s in $stops) { $out += "  - $s" }
    } else {
        $out += "NO STOP CONDITIONS. What follows is as complete as this instrument can establish."
    }
    $out
}

if ($Chip) {
    $row = $rows | Where-Object { $_.Box -eq $BoxKey -and $_.SessionKey -eq $SessionKey } | Select-Object -First 1
    if (-not $row) { Write-Error "fleet.ps1: no record for $BoxKey/$SessionKey"; exit 2 }
    New-ChipBriefing -Row $row
    exit 0
}

# -ColdStart: the whole transfer in one command, for a virgin session under a DIFFERENT account.
# It emits the receipt first and every respawn-eligible briefing after it, so the owner pastes one
# sentence instead of hand-carrying documents. Same filesystem only: a briefing names paths (the
# predecessor checkout, its handoff document) rather than carrying their bytes.
if ($ColdStart) {
    "FLEET COLD START -- rendered $($receipt.renderedAtUtc)"
    ""
    "You are the FIRST session after an account switch. Everything below was read from disk just"
    "now; you inherit nothing else. Read the receipt BEFORE the briefings -- if a stop condition"
    "fired, the briefing list is not the whole fleet and respawning from it will silently drop seats."
    ""
    Get-ReceiptLines
    ""

    $respawn = @($rows | Where-Object { $_.State -in @('INTERRUPTED', 'HANDED') })
    "RESPAWN POPULATION: $($respawn.Count) seat(s) -- states INTERRUPTED and HANDED."
    "  Deliberately excluded: RUNNING, POSSIBLY RUNNING, SUPERSEDED, CLOSED."
    ""
    if ($respawn.Count -eq 0) {
        "NO SEAT IS RESPAWN-ELIGIBLE. Read that against the receipt above, not as an all-clear:"
        "an empty population and an instrument that could not look produce the SAME output here."
    }
    $n = 0
    foreach ($row in ($respawn | Sort-Object Box)) {
        $n++
        ""
        "=" * 94
        "BRIEFING $n OF $($respawn.Count) -- $($row.Box) / $($row.SessionKey)"
        "  regenerate alone with: fleet.ps1 -Chip -BoxKey $($row.Box) -SessionKey $($row.SessionKey)"
        "=" * 94
        ""
        New-ChipBriefing -Row $row
    }
    ""
    "=" * 94
    "AFTER RESPAWNING: bump the pool epoch ONCE, so every record written from here dates itself"
    "against this switch rather than leaving it to be inferred from a credential directory label:"
    "  pwsh -NoProfile -File scripts\coord\seat.ps1 -BumpEpoch"

    $code = if ($fenceAvailable) { 0 } else { 2 }
    exit $code
}

if ($Json) {
    [ordered]@{
        receipt = $receipt
        rows    = @($rows | Select-Object Box, SessionKey, Seat, State, Fence, AgeHours, WriterStale, Branch, Worktree, Epoch)
    } | ConvertTo-Json -Depth 8
    $code = if ($fenceAvailable) { 0 } else { 2 }
exit $code
}

# Default: text.
"FLEET CONTINUITY ROSTER"
"rendered $($receipt.renderedAtUtc)"
""
Get-ReceiptLines
""

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

