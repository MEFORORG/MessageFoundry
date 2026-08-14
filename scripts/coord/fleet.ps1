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
        fleet.ps1 -Detail -BoxKey <box> -SessionKey <key>   # one seat's EVIDENCE, for a human

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

    SCOPE, RULED 2026-08-14 AND NOT TO BE MISREAD. The project''s anti-registry thesis STANDS: a
    hand-maintained seat registry remains rejected. What was granted is a NARROW exception for records
    NOBODY WRITES BY HAND, on the ground that the status board''s unit of record is a work key whose
    output has no sessions array and therefore structurally cannot answer "which sessions were running
    and what was each doing". The VOLUNTARY half is demoted for the second ruled reason -- declaration
    decays, measured at 8.8 to 31 percent adoption -- so nothing here may DEPEND on a seat having
    declared anything. The chip GENERATOR is also out of scope: the owner composes chips by hand,
    because a paste-ready briefing authored at queue time and executed at click time goes stale
    silently, which happened live on this project the day this was written.

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
    [switch]$Detail,
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

# -Detail: the EVIDENCE for one seat, for a human who is composing a spawn_task chip BY HAND.
#
# OWNER RULING 2026-08-14: the chip GENERATOR is out of scope. This is not that, and the difference
# is not cosmetic. A generated briefing is a paste-ready artifact authored at queue time and executed
# at click time -- true when written, false when run, and it carries no marker saying which. That
# hazard fired live on this project the same day. A hand-composed chip cannot go stale silently,
# because a human wrote each line knowing when they wrote it.
#
# So this prints FACTS WITH THEIR AGE and the COMMANDS TO RE-CHECK THEM. It is deliberately not
# phrased as a prompt, and it does not address a future session.
if ($Detail) {
    $row = $rows | Where-Object { $_.Box -eq $BoxKey -and $_.SessionKey -eq $SessionKey } | Select-Object -First 1
    if (-not $row) { Write-Error "fleet.ps1: no record for $BoxKey/$SessionKey"; exit 2 }
    $rec = $row.Rec
    $ageTxt = if ($null -ne $row.AgeHours) { "$($row.AgeHours)h old" } else { "age unknown" }

    "SEAT EVIDENCE -- $($row.Box)/$($row.SessionKey)"
    "This is EVIDENCE for you to read, not a briefing to paste. Compose the chip yourself."
    "Every line below was recorded $ageTxt and may have expired since. Re-check commands are given."
    ""
    "STATE (computed now): $($row.State)   fence=$($row.Fence)"
    "CHECKOUT: $($rec.worktree)"
    "BRANCH:   $($row.Branch)"
    "  Work is named by BRANCH. A commit id is not an identifier here -- a rebase reissues it."
    if ($rec.tip) { "  tip was $($rec.tip) as of the record; resolve the branch yourself." }
    ""
    "WHAT THIS SEAT ACTUALLY DID -- involuntary evidence, written as a side effect of working:"
    $commits = @()
    if (($rec.PSObject.Properties.Name -contains 'commits') -and $rec.commits) { $commits = @($rec.commits) }
    if ($commits.Count -gt 0) {
        foreach ($c in $commits) { "  $c" }
    } else {
        "  no commits since the merge-base were recorded"
    }
    $touched = @()
    if (($rec.PSObject.Properties.Name -contains 'touchedPaths') -and $rec.touchedPaths) { $touched = @($rec.touchedPaths) }
    if ($touched.Count -gt 0) {
        "  touched $($touched.Count) path(s): " + (($touched | Select-Object -First 15) -join ', ')
    }
    ""
    "WORK AT RISK -- check this FIRST, it is the only category that cannot be recovered elsewhere:"
    $untracked = @()
    if (($rec.PSObject.Properties.Name -contains 'dirty') -and $rec.dirty -and
        ($rec.dirty.PSObject.Properties.Name -contains 'untracked')) { $untracked = @($rec.dirty.untracked) }
    if ($untracked.Count -gt 0) {
        "  $($untracked.Count) UNTRACKED file(s) -- HELD BY NO GIT OBJECT. Not in the stash, not in a"
        "  commit, not on a remote. If that checkout is removed they are gone:"
        foreach ($u in ($untracked | Select-Object -First 40)) { "    $u" }
    } else { "  no untracked files were recorded" }
    if ($rec.stashSha) { "  stash commit (TRACKED edits only): $($rec.stashSha)" }
    if (($rec.PSObject.Properties.Name -contains 'stashCovers')) { "  stash covers: $($rec.stashCovers)" }
    if ($rec.unpushed) { "  unpushed commits vs $($rec.unpushed.base): $($rec.unpushed.count)" }
    else { "  unpushed: NO-UPSTREAM (nobody has looked; this is not the same as zero)" }
    ""
    "RE-CHECK BEFORE YOU ACT ON ANY OF THE ABOVE:"
    "  git fetch origin"
    "  git -C `"$($rec.worktree)`" status --porcelain"
    "  git -C `"$($rec.worktree)`" log --oneline origin/main..HEAD"
    if ($touched.Count -gt 0) {
        "  git diff --name-only origin/main $($row.Branch) -- " + (($touched | Select-Object -First 15) -join ' ')
        "    Empty output means the CONTENT is already on main. Ancestry answers a different question:"
        "    squash-merge routinely makes commits-ahead and content-ahead disagree."
    } else {
        "  landed check is UNCHECKABLE -- no touched paths recorded, so derive the pathspec from the"
        "  branch's own merge-base rather than diffing the whole tree."
    }
    ""
    "LEDGER AND CLAIMS -- attribution matters, the path outlives its occupant:"
    $ownC = @($rec.claims | Where-Object { $_.attribution -eq 'this-episode' })
    $inhC = @($rec.claims | Where-Object { $_.attribution -ne 'this-episode' })
    "  claims by THIS episode:      " + $(if ($ownC.Count) { (($ownC | ForEach-Object { $_.key }) -join ', ') } else { 'none' })
    if ($inhC.Count) { "  present but from EARLIER occupants of that path (NOT this seat's): " + (($inhC | ForEach-Object { $_.key }) -join ', ') }
    $ownA = @($rec.allocations | Where-Object { $_.attribution -eq 'this-episode' })
    $inhA = @($rec.allocations | Where-Object { $_.attribution -ne 'this-episode' })
    "  ledger numbers by THIS episode: " + $(if ($ownA.Count) { (($ownA | ForEach-Object { "$($_.kind) #$($_.number)" }) -join ', ') } else { 'none' })
    if ($inhA.Count) { "  $($inhA.Count) more allocated to that PATH by earlier occupants -- not this seat's, do not rehome or cite" }
    ""
    "DECLARED INTENT -- VOLUNTARY, UNVERIFIED, AND OFTEN ABSENT BY DESIGN."
    "  Measured adoption of voluntary declaration on this project: 8.8 to 31 percent. Treat anything"
    "  here as a hint that was true when someone typed it, never as the record. The evidence above is"
    "  the record."
    if ($rec.seat) { "  seat:        $($rec.seat)" } else { "  seat:        not declared" }
    if ($rec.goal) { "  goal:        $($rec.goal)" }
    if ($rec.done) { "  done means:  $($rec.done)" }
    if ($rec.outOfScope) { "  out of scope: $($rec.outOfScope)" }
    if ($rec.handoff -and $rec.handoff.path) {
        "  handoff:     $($rec.handoff.path)"
        if (($rec.handoff.PSObject.Properties.Name -contains 'unresolved') -and $rec.handoff.unresolved) {
            "               WARNING: that path DID NOT RESOLVE when recorded. A lead, not a document."
        }
    }
    ""
    "ACCOUNT BOUNDARY -- do NOT carry these across: usage figures, project memory, artifact"
    "capabilities, workflow caches, the realtime send channel. Read your own."
    exit 0
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
"  Briefing for one row:  fleet.ps1 -Detail -BoxKey <box> -SessionKey <key>"

$code = if ($fenceAvailable) { 0 } else { 2 }
exit $code


