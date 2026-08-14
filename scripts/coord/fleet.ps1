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
        fleet.ps1 -Detail -BoxKey <box> -SessionKey <session>   # one seat's EVIDENCE, for a human

    Both -Detail arguments are COLUMNS OF THE TEXT ROSTER, and -SessionKey takes a unique prefix of
    one. That is a correctness property, not a convenience: an instruction whose argument appears on
    no rendered surface cannot be followed, and several sessions in one checkout otherwise render
    indistinguishably. An ambiguous prefix is refused by name; it is never resolved to the first hit.

    ONLY A POSITIVE FENCE ANSWER OUTRANKS ANYTHING. The state switch puts fence=LIVE FIRST, above every
    recorded or computed label, because it is the only line measured against the world as it is now.
    Anything placed above it can MASK a running session, and two things did: a per-path SUPERSEDED rule
    and a `lifecycle` written by the demoted voluntary half. Symmetrically, INTERRUPTED requires the
    fence to have ANSWERED that the session is not registered -- a fence that was never evaluated (no
    session id in the record, or a throw) is POSSIBLY RUNNING and is counted in the receipt, because an
    unevaluated fence is not a passed fence.

    WHY THE RECEIPT COMES BEFORE THE ROSTER, AND WHY IT CAN REFUSE.

    An empty roster and a dead writer produce THE SAME OUTPUT. So do a healthy quiet fleet and a
    fleet whose hooks were silently disabled by disableAllHooks, org policy or workspace trust. The
    reader of this output is, by construction, the person least equipped to notice -- they are
    reading it because they lost the context that would have told them. So the receipt states what
    was EXAMINED, not merely what was found, and any of the STOP conditions below suppresses the
    manifest rather than rendering a confident empty answer.

    EVERY RECEIPT FIELD IS EITHER A STOP OPERAND OR THE INSTRUMENT FOR ONE, AND A PRINTED FIELD THAT
    IS NEITHER IS A DECORATION. Measured on the shipped file against a throwaway repo: `recordsUnreadable`
    and `writerErrorLines` were both PRINTED and both entered NO stop condition, so a seats layer with an
    unreadable record, and a seat whose writer had just failed and said so in
    seats/.writer-errors.txt, each rendered under "NO STOP CONDITIONS. The roster below is as complete
    as this instrument can establish." That is this module's one job failing in the one place it exists
    to hold. The rule now runs both ways: nothing is printed that no stop reads, and nothing is a stop
    operand that the receipt does not print.

    A COUNT OF FILES IS NOT A MEASUREMENT OF FRESHNESS. Three fields were counting existence where the
    question was recency, and all three could therefore only ever go UP:
      * `writerHeartbeatIn` counted files in seats/.writer-alive/ and never read the UTC timestamp
        seat.ps1 writes INSIDE each one, so proof-of-life could never go stale or fall.
      * `liveSessionsWithoutRecord` asked only whether a record EXISTS for a live session, so one
        record ever written satisfied the denominator forever -- a writer that recorded turn 1 and
        then died was byte-identical to one recording every turn.
      * `writerErrorLines` counts an APPEND-ONLY log, so it can never fall by construction, and a stop
        keyed on the total would fire forever after the first ever failure. The operand is therefore
        the RECENT count. A channel that fires when nothing is wrong trains its reader to skip it, and
        this file already paid for that lesson once (see CRYING WOLF below).
    So every staleness verdict here is measured against -FreshMinutes, and that bound is itself a
    receipt field, because a number is not checkable without the instrument that produced it (SDS-3.8).

    A FENCE THAT IS PRESENT IS NOT A FENCE THAT CAN SEE. `rootsExamined` and `fenceAvailable` test that
    a config root holds a sessions/ DIRECTORY -- an existence test on a folder. An EMPTY sessions/
    directory passes it, and then every record with a session id gets the fence's ordinary
    NOT-REGISTERED answer and lands on INTERRUPTED, which is the most destructive verdict available and
    the one that puts a row in the respawn population. MEASURED: with a genuinely LIVE session in the
    repo and its registry record removed, the seat rendered INTERRUPTED under "NO STOP CONDITIONS",
    and rendered RUNNING in the same run with the record restored. So the number of session records
    actually READ is now a receipt field and a stop operand of its own.

    AND THE FIX IS A STOP, NOT A RECLASSIFICATION. Mapping the blind fence's answers to POSSIBLY
    RUNNING would drive the RESPAWN POPULATION TO ZERO -- NOT-REGISTERED is also the fence's ordinary
    answer for the entire dead population -- and manufacture the confidently-empty roster this module
    exists to prevent. That exact fix was proposed once for the UNKNOWN token and rejected for that
    reason. A stop suppresses the CLAIM OF COMPLETENESS while still rendering every row; a
    reclassification would delete the rows from the answer.

    THE DENOMINATOR IS THE POINT. Joining records to the fence tells you nothing about a session
    that produced NO record -- it is not missing, it does not exist. `liveSessionsWithoutRecord`
    supplies the missing denominator by starting from the FENCE and subtracting, so a dead writer
    shows up as a positive count instead of as silence. It is scoped to this clone's worktrees, and
    the scoping test is EXACT-MATCH-OR-DESCENDANT: a session whose cwd is a subdirectory of a
    worktree is still that worktree's session, and dropping it silently shrinks the denominator to
    the point where it stops discriminating. MEASURED THE SAME NIGHT: presence.ps1 counted 13 live
    sessions where a second instrument reached 10, and the checkout that had just been worked in was
    among those the second could not see. The separator is not optional in that test -- a bare
    StartsWith makes "MessageFoundry-ledger" a child of "MessageFoundry".

    A CRASH IS THE INVERSE OF A STOP, NOT A STRONGER ONE. A stop suppresses the claim of completeness
    and still renders the evidence; an unhandled exception suppresses the evidence and renders
    nothing. Under `Set-StrictMode -Version Latest` a MISSING PROPERTY THROWS, so every record field
    is read through Get-RecField and the classification of one record is wrapped: one malformed file
    must cost ONE ROW, never the receipt. MEASURED on the shipped file: a one-line `{"a":1}`, a
    whitespace-only file and a ZERO-BYTE file dropped into any box directory each produced exit 1, a
    bare PropertyNotFoundException, and no receipt, no denominator, no stop conditions and no roster
    at all.

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
    # Opt OUT of redaction on -Json. Named, so the unsafe form is deliberate rather than the default.
    [switch]$Raw,
    [switch]$All,
    [switch]$Detail,
    [string]$BoxKey,
    [string]$SessionKey,
    [int]$FoldDays = 7,
    # THE ONE STALENESS BOUND, shared by every "is this still being written" verdict below and printed
    # in the receipt beside them. One knob rather than three, because a reader who widens it has to be
    # able to see, in one place, everything they just widened.
    [int]$FreshMinutes = 120,
    [string]$RepoHint
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\session-registry.ps1"
. "$PSScriptRoot\mail-key.ps1"

function Invoke-Git {
    # $null means git REFUSED (non-zero exit); '' means it succeeded and said nothing. Callers that
    # test object existence depend on that distinction, so do not collapse the two.
    param([string]$Dir, [string[]]$GitArgs)
    try {
        $out = & git -C $Dir @GitArgs 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        if ($null -eq $out) { return '' }
        return ($out -join "`n").Trim()
    } catch { return $null }
}

# EVERY RECORD FIELD IS READ THROUGH THIS, and the reason is in the header: under
# `Set-StrictMode -Version Latest` a missing property THROWS instead of yielding $null. Measured on the
# shipped file, `$rec.sessionId` over a box directory containing one `{"a":1}` took the whole reader
# down with a PropertyNotFoundException before the receipt was built -- the failure mode that most
# needs a receipt produced none. The registry half of this class was closed in an earlier pass (the
# fence call is wrapped and `cwd` is presence-checked); the SEATS half -- the files this layer writes
# itself -- was still open, and it is the half a half-finished write lands in.
#
# ABSENT AND NULL COLLAPSE TO THE DEFAULT ON PURPOSE. A record carrying `"sessionId": null` (the
# documented `nosid` path) and one missing the key entirely are the same fact to every reader here.
function Get-RecField {
    param($Object, [string]$Name, $Default = $null)
    if ($null -eq $Object) { return $Default }
    try {
        if ($Object.PSObject.Properties.Name -contains $Name) {
            $v = $Object.$Name
            if ($null -ne $v) { return $v }
        }
    } catch { }
    return $Default
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
# Time. Defined before the gather because the gather now MEASURES ages rather than counting files.
# ---------------------------------------------------------------------------------------------

$now = [DateTime]::UtcNow

# NOT [string]$iso. MEASURED: ConvertFrom-Json parses "2026-08-14T20:24:29Z" into a [DateTime] with
# Kind=Utc, and casting THAT to string yields "08/14/2026 20:24:29" -- the Z is GONE. Parsing the
# result treats it as LOCAL, silently adding the UTC offset, and this box reported ages five hours in
# the FUTURE. The pattern was correct throughout; the TYPE was not what the code assumed, which is
# why re-reading the parse call finds nothing and dumping the type finds it immediately.
#
# MINUTES IS THE PRIMITIVE AND HOURS IS DERIVED FROM IT. Get-AgeHours rounds to 0.1h, i.e. six
# minutes, which is coarser than every freshness bound in this file; a staleness verdict computed off
# the rounded value would be answering a neighbouring question (SDS-3.8).
function Get-AgeMinutes($iso) {
    if (-not $iso) { return $null }
    try {
        $utc = if ($iso -is [DateTime]) {
            if ($iso.Kind -eq [DateTimeKind]::Utc) { $iso } else { $iso.ToUniversalTime() }
        } else {
            [DateTimeOffset]::Parse([string]$iso, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime
        }
        return ($now - $utc).TotalMinutes
    } catch { return $null }
}

function Get-AgeHours($iso) {
    $m = Get-AgeMinutes $iso
    if ($null -eq $m) { return $null }
    return [Math]::Round($m / 60, 1)
}

# ---------------------------------------------------------------------------------------------
# Gather. Records first, then the fence, then the denominator.
# ---------------------------------------------------------------------------------------------

$records = @()
$unreadableRecords = 0
if (Test-Path -LiteralPath $seatsDir) {
    foreach ($d in @(Get-ChildItem -LiteralPath $seatsDir -Directory -EA SilentlyContinue |
                     Where-Object { $_.Name -notlike '.*' })) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -Filter *.json -EA SilentlyContinue)) {
            $j = $null
            try { $j = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
            catch {
                # A record being written RIGHT NOW has exactly this shape. Counted, never dropped:
                # dropping turns an occupied seat into an absent one in the receipt's own numbers.
                $j = $null
            }
            # A PARSE THAT DID NOT THROW IS NOT A RECORD. MEASURED: a ZERO-BYTE file and a
            # whitespace-only file both come back from `Get-Content -Raw` as '' rather than $null, and
            # ConvertFrom-Json accepts '' and returns $null WITHOUT raising -- so the catch above never
            # saw them, a $null went into $records, and the reader died on it two sections later with
            # no receipt. The test is on the BASE object because [pscustomobject] matches any value
            # wrapped in a PSObject: measured, `5 -is [pscustomobject]` and `"hi" -is [pscustomobject]`
            # are both TRUE, so the obvious test would have admitted a bare JSON scalar as a seat.
            if ($null -eq $j -or -not ($j.PSObject.BaseObject -is [System.Management.Automation.PSCustomObject])) {
                $unreadableRecords++
                continue
            }
            $records += [pscustomobject]@{ Rec = $j; File = $f.FullName; Box = $d.Name }
        }
    }
}

# The fence. Its availability is a FACT IN THE RECEIPT, not an assumption -- and PRESENT and ABLE TO
# SEE are two facts, so they are two fields.
#
# `rootsExamined`/`fenceAvailable` are STRUCTURE: Get-ClaudeConfigRoots keeps a root only if it holds a
# sessions/ DIRECTORY, which is an existence test on a folder. An EMPTY sessions/ passes it, and then
# every fenced record gets the fence's ordinary Found=$false and lands on INTERRUPTED -- the most
# destructive verdict available and the one that fills the respawn population. MEASURED against a
# throwaway repo with a controlled config root: one genuinely LIVE session rendered RUNNING with its
# registry record present and INTERRUPTED with the sessions/ directory emptied, both runs reporting
# rootsExamined=1, fenceAvailable=true and "NO STOP CONDITIONS".
#
# So `fenceSessionRecordsRead` is the MEASUREMENT -- how many registry records the fence actually
# parsed -- and it is what `fenceCanSee` and the stop below are keyed on. It does NOT feed the
# classifier: see the header for why turning a blind fence into POSSIBLY RUNNING would zero the
# respawn population and manufacture the very roster this module exists to prevent.
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
# -IncludeUnreadable returns a row with Record=$null for a registry file that would not parse -- a
# session that launched a moment ago is exactly that shape. Those are a hole in the denominator, not
# an absence, so they are counted rather than dropped.
$fenceRecordsUnreadable = @($sessionRows | Where-Object { -not $_.Record }).Count
$fenceRecordsRead = @($sessionRows).Count - $fenceRecordsUnreadable
$fenceCanSee = ($fenceAvailable -and $fenceRecordsRead -gt 0)

function Get-NormPath([string]$p) {
    if (-not $p) { return '' }
    return ($p.Trim().TrimEnd('\', '/').ToLowerInvariant() -replace '/', '\')
}

# EXACT MATCH OR DESCENDANT, AND THE SEPARATOR IS NOT OPTIONAL.
#
# The denominator asks "is this live session sitting in one of this clone's worktrees", and a session
# whose cwd is a SUBDIRECTORY of a worktree is still that worktree's session. Exact path equality
# dropped every one of them, which shrinks the denominator exactly where it is supposed to
# discriminate. MEASURED THE SAME NIGHT ON THIS BOX: presence.ps1 counted 13 live sessions where a
# second instrument reached 10, and the checkout that had just been worked in was among the three the
# second could not see.
#
# The appended separator is the whole defence: a bare StartsWith makes "...\MessageFoundry-ledger" a
# child of "...\MessageFoundry", and this project has TWO files carrying that scar (occupancy.ps1:227
# appends it; install-git-hooks.ps1:186 documents the sibling-worktree miss it caused).
#
# LONGEST MATCH WINS, or a worktree nested inside another -- which is this project's own layout,
# .claude\worktrees\<name> under the primary -- folds into its parent and gets attributed to a
# checkout it is nowhere near.
function Resolve-WorktreeFor([string]$NormCwd, [string[]]$Worktrees) {
    $best = $null
    foreach ($w in $Worktrees) {
        if (-not $w) { continue }
        if ($NormCwd -eq $w -or $NormCwd.StartsWith("$w\", [StringComparison]::Ordinal)) {
            if (-not $best -or $w.Length -gt $best.Length) { $best = $w }
        }
    }
    return $best
}

# Worktrees of THIS clone, so the denominator is scoped to this repo rather than to the whole box.
# Its AVAILABILITY is a fact in the receipt for the same reason the fence's is: an empty list and a
# git that would not answer produce the same denominator, and one of them means the denominator is
# not being computed at all.
$repoWorktrees = @()
$wtOut = Invoke-Git -Dir $repo -GitArgs @('worktree', 'list', '--porcelain')
$worktreeListAvailable = [bool]$wtOut
if ($wtOut) {
    foreach ($line in ($wtOut -split "`n")) {
        if ($line -match '^worktree\s+(.+)$') { $repoWorktrees += (Get-NormPath $Matches[1]) }
    }
}

# NEWEST RECORD PER SESSION, AS AN AGE. "A record exists" and "the writer is still recording this
# seat" are different sentences, and the denominator below needs the second one: one record ever
# written satisfied the first forever, so a writer that recorded turn 1 and then died was
# byte-identical to one recording every turn. A session can hold a record in more than one box (it
# only has to cd), so the NEWEST wins.
#
# A record whose asOf will not parse keeps a $null age, which is treated below as NOT fresh. That is
# the safe direction: it fires a stop that says the roster may be short, rather than certifying a
# record whose age nothing could establish.
$recordAgeBySession = @{}
foreach ($r in $records) {
    $sid = [string](Get-RecField $r.Rec 'sessionId' '')
    if (-not $sid) { continue }
    $m = Get-AgeMinutes (Get-RecField $r.Rec 'asOf')
    if (-not $recordAgeBySession.ContainsKey($sid)) { $recordAgeBySession[$sid] = $m }
    elseif ($null -ne $m -and ($null -eq $recordAgeBySession[$sid] -or $m -lt $recordAgeBySession[$sid])) {
        $recordAgeBySession[$sid] = $m
    }
}

# Writer heartbeat. "Installed", "resolvable" and "actually ran" are three different sentences and
# the first alone answers the neighbouring question.
#
# THE TIMESTAMP INSIDE THE FILE IS THE MEASUREMENT; COUNTING THE FILES IS NOT. seat.ps1 rule 3 writes
# a UTC instant into seats/.writer-alive/<boxKey>.txt on EVERY invocation including no-op ones, and
# this used to count the files and never open them -- so proof-of-life could only ever go UP, and a
# writer disabled months ago (disableAllHooks, org policy, workspace trust: all silent) read exactly
# like one that ran a second ago. The file's own mtime is a FALLBACK, never the primary: it answers
# "when was this file last written", which is the same sentence only while nothing else touches it.
$heartbeats = @()
$heartbeatAgeByBox = @{}
$aliveDir = Join-Path $seatsDir '.writer-alive'
if (Test-Path -LiteralPath $aliveDir) {
    $heartbeats = @(Get-ChildItem -LiteralPath $aliveDir -Filter *.txt -EA SilentlyContinue)
}
foreach ($h in $heartbeats) {
    $stamp = $null
    try { $stamp = (Get-Content -LiteralPath $h.FullName -Raw -EA Stop) } catch { }
    $age = Get-AgeMinutes ([string]$stamp).Trim()
    if ($null -eq $age) { $age = ($now - $h.LastWriteTimeUtc).TotalMinutes }
    # A PowerShell hashtable is case-insensitive on string keys by default, which is what this lookup
    # needs: ConvertTo-BoxKey's slug half preserves the case of the directory leaf, so a key minted
    # here from a normalised (lower-cased) path would otherwise miss the writer's own file.
    $heartbeatAgeByBox[[System.IO.Path]::GetFileNameWithoutExtension($h.Name)] = $age
}
$heartbeatNewestAge = $null
if ($heartbeatAgeByBox.Count -gt 0) {
    $heartbeatNewestAge = [int][Math]::Round((($heartbeatAgeByBox.Values | Measure-Object -Minimum).Minimum))
}

# The writer's own failure log. seat.ps1 rule 2 appends one line per failure and still exits 0, so
# this file is the ONLY trace of a seat that is provably not being recorded.
#
# THE OPERAND IS THE RECENT COUNT, NOT THE TOTAL, and that is a correctness choice rather than a
# softening. The log is APPEND-ONLY and nothing truncates it, so a stop keyed on the total would fire
# for ever after the first failure this repo ever had -- and a channel that fires when nothing is
# wrong trains its reader to skip it, which is the CRYING WOLF failure this file already paid for
# once on origin/main staleness. The total is still printed, so the history is not hidden.
# An UNPARSABLE line counts as recent: failing toward firing the stop suppresses a completeness claim,
# and the other direction hides a writer that is failing right now.
$writerErrors = 0
$writerErrorsRecent = 0
$writerErrorNewestAge = $null
$errFile = Join-Path $seatsDir '.writer-errors.txt'
if (Test-Path -LiteralPath $errFile) {
    $errLines = @(Get-Content -LiteralPath $errFile -EA SilentlyContinue | Where-Object { $_ -and $_.Trim() })
    $writerErrors = $errLines.Count
    foreach ($ln in $errLines) {
        # seat.ps1 writes "<iso utc>`t<host>`t<stage>`t<message>".
        $age = Get-AgeMinutes (($ln -split "`t")[0])
        if ($null -eq $age -or $age -le $FreshMinutes) { $writerErrorsRecent++ }
        if ($null -ne $age -and ($null -eq $writerErrorNewestAge -or $age -lt $writerErrorNewestAge)) {
            $writerErrorNewestAge = $age
        }
    }
}

# LIVE sessions sitting in this repo's worktrees. This is the denominator: a session here that has
# produced no record -- or no RECENT record -- is EVIDENCE THE WRITER IS DEAD, not evidence the fleet
# is idle.
$liveInRepo = @()
$registryUnfenceable = 0
foreach ($row in $sessionRows) {
    if (-not $row.Record) { continue }
    $cwd = Get-NormPath ([string](Get-RecField $row.Record 'cwd' ''))
    if (-not $cwd) { continue }
    $wtMatch = Resolve-WorktreeFor -NormCwd $cwd -Worktrees $repoWorktrees
    if (-not $wtMatch) { continue }
    # ONE malformed registry file must degrade ONE row, never the whole receipt. MEASURED on this
    # file: a registry record carrying a non-numeric startedAt threw out of Test-RecordLiveness here
    # -- this call sat outside any try -- and fleet.ps1 exited 1 having printed no receipt, no
    # denominator, no stop conditions and no roster, only a stack trace. A registry file caught
    # mid-write is exactly that shape, so the failure arrives at the moment a session is launching.
    # That is this module's own worst outcome delivered as a crash: the reader is by construction the
    # person least able to tell a broken instrument from an idle fleet. Counted, never swallowed.
    $l = $null
    try { $l = Test-RecordLiveness -Record $row.Record } catch { $registryUnfenceable++; continue }
    if ($l.State -ne 'LIVE') { continue }

    $sid = [string](Get-RecField $row.Record 'sessionId' '')
    $hasRecord = ($sid -and $recordAgeBySession.ContainsKey($sid))
    $recAge = if ($hasRecord) { $recordAgeBySession[$sid] } else { $null }
    # The box is minted from the MATCHED WORKTREE ROOT, not from the session's cwd: seat.ps1 keys the
    # record on `git rev-parse --show-toplevel`, so a cwd one directory down would mint a box key that
    # matches nothing this layer ever wrote.
    $boxKey = ConvertTo-BoxKey -Path $wtMatch
    $hbAge = if ($heartbeatAgeByBox.ContainsKey($boxKey)) { $heartbeatAgeByBox[$boxKey] } else { $null }
    $liveInRepo += [pscustomobject]@{
        SessionId           = $sid
        Cwd                 = $cwd
        Worktree            = $wtMatch
        Box                 = $boxKey
        Root                = $row.Root
        HasRecord           = [bool]$hasRecord
        RecordAgeMinutes    = $recAge
        RecordFresh         = ($hasRecord -and $null -ne $recAge -and $recAge -le $FreshMinutes)
        HeartbeatAgeMinutes = $hbAge
        HeartbeatFresh      = ($null -ne $hbAge -and $hbAge -le $FreshMinutes)
    }
}

$liveWithoutRecord = @($liveInRepo | Where-Object { -not $_.HasRecord })
$liveWithStaleRecord = @($liveInRepo | Where-Object { $_.HasRecord -and -not $_.RecordFresh })
# The heartbeat separates "the writer is not running here" from "the writer runs and its write
# failed": a fresh heartbeat beside a stale record is the second, and .writer-errors.txt says why.
$liveWithoutFreshHeartbeat = @($liveInRepo | Where-Object { -not $_.HeartbeatFresh })

# origin/main's own age. Every landed verdict is computed against this ref, and the local copy of it
# only refreshes on FETCH. A landed verdict against a stale ref is the dangerous direction: this repo
# carries reverts, and against a stale cached main a reverted change reads as "already landed" --
# i.e. deliberately reverted work would be recorded as done.
#
# ASK THE QUESTION YOU MEAN (SDS-3.8). The question is "how long since anyone refreshed this clone's
# copy of origin/main", and the instrument has to answer THAT sentence rather than a neighbouring one.
# Stat'ing refs/remotes/origin/main answers "when did the ref last MOVE", and that is wrong in BOTH
# directions -- both MEASURED on a throwaway clone:
#   BLIND    the loose file does not exist while the ref is PACKED, which is the state of every fresh
#            clone and of any repo after `git gc` / `git pack-refs`. The age came back null, and a
#            null age skipped the stop condition silently, so an ordinary `git pack-refs --all`
#            disarmed the check while `originMainSha` kept printing a healthy-looking value beside it.
#   CRYING   when the file does exist, a fetch that confirms origin/main is UNCHANGED completes
#   WOLF     without touching it. The check fired "has not been fetched recently" SECONDS after a
#            verified-current fetch, which on a quiet solo repo is the normal state -- and a channel
#            that fires when nothing is wrong trains its reader to skip it.
#
# FETCH_HEAD is the file git rewrites on EVERY fetch whether or not any ref moved, so it answers the
# question asked. It is PER-WORKTREE (measured: a fetch from a linked worktree left <common>/FETCH_HEAD
# untouched and wrote <common>/worktrees/<name>/FETCH_HEAD), while refs/remotes is shared by the whole
# clone -- so the answer is the NEWEST FETCH_HEAD anywhere in the clone, not this worktree's. The SHA
# still comes from `git rev-parse`, which is packed-ref aware and was never the broken half.
$originMainSha = Invoke-Git -Dir $repo -GitArgs @('rev-parse', 'origin/main')
$originMainAgeMinutes = $null
# NOT $null, and not blank. A blank age beside a populated sha reads as a pass; this has to say which.
$originMainAgeSource = 'UNCHECKABLE -- no FETCH_HEAD anywhere in this clone; nobody has fetched here since it was created'
$fetchHeads = @()
foreach ($p in @((Join-Path $common 'FETCH_HEAD')) + @(Get-ChildItem -LiteralPath (Join-Path $common 'worktrees') -Directory -EA SilentlyContinue |
                 ForEach-Object { Join-Path $_.FullName 'FETCH_HEAD' })) {
    if (Test-Path -LiteralPath $p) { $fetchHeads += (Get-Item -LiteralPath $p) }
}
if ($fetchHeads.Count -gt 0) {
    $newest = ($fetchHeads | Sort-Object LastWriteTimeUtc -Descending | Select-Object -First 1)
    $originMainAgeMinutes = [int]((Get-Date).ToUniversalTime() - $newest.LastWriteTimeUtc).TotalMinutes
    $originMainAgeSource = "FETCH_HEAD mtime (newest of $($fetchHeads.Count) in this clone)"
}

# ---------------------------------------------------------------------------------------------
# Classify. Every state is derived here and none is read from a record.
# ---------------------------------------------------------------------------------------------

$rows = @()
$unclassifiableRecords = 0
foreach ($r in $records) {
  # ONE RECORD, ONE ROW, AND A THROW COSTS THE ROW RATHER THAN THE RECEIPT. Every field below is read
  # through Get-RecField, so this catch should be unreachable -- it is here because "should be
  # unreachable" is exactly what the shipped file assumed about the record shape, and an unhandled
  # exception is the INVERSE of a stop: it suppresses the evidence and renders nothing. Two live
  # throws remain reachable even so and neither is a field read: Test-Path on a junk worktree string,
  # and casting a non-numeric poolEpoch. The row is still emitted, visibly unusable and out of the
  # respawn population, and the count is a stop operand.
  try {
    $rec = $r.Rec
    $wt = [string](Get-RecField $rec 'worktree' '')
    $sid = [string](Get-RecField $rec 'sessionId' '')
    if (-not $sid) { $sid = $null }

    # Fence state, positive answers only. There is no heartbeat on this host and registry writes are
    # event-driven, so nothing here can PROVE a session is gone -- only that it is present.
    #
    # FOUR OUTCOMES, FOUR TOKENS. These used to collapse into one literal 'UNKNOWN', and that single
    # token had no arm in the switch below, so all four fell through to `default { 'INTERRUPTED' }` --
    # the most destructive verdict available, and the one that puts a row in the respawn population.
    # They are NOT the same answer and must not share a name:
    #   NO-FENCE        no config root holds a sessions/ directory; nothing was asked of anything.
    #   NOT-FENCEABLE   the RECORD carries no sessionId, so it can never be fenced. This is the
    #                   documented `nosid` outcome of the plain hook path, i.e. reachable by design.
    #   FENCE-ERROR     the fence THREW. A registry file caught mid-write is exactly this, and a
    #                   session that just launched is the last thing that should read as absent.
    #   NOT-REGISTERED  the fence answered, and answered Found=$false. THIS is the ordinary gone case,
    #                   and it is the whole population this roster exists to enumerate.
    # Only the last one licenses INTERRUPTED. Ranking the first three with the possibly-live states is
    # session-registry.ps1's own contract -- "an unevaluated fence is not a passed fence", "ONLY THE
    # POSITIVE ANSWER IS SAFE TO ACT ON" -- and mapping them all to POSSIBLY RUNNING without splitting
    # NOT-REGISTERED out would have been the opposite defect: it would classify every dead seat as
    # possibly-live, drive the respawn population to zero, and manufacture the confidently-empty roster
    # this module was built to prevent. The split is what lets both halves be right.
    $fence =
        if (-not $fenceAvailable) { 'NO-FENCE' }
        elseif (-not $sid) { 'NOT-FENCEABLE' }
        else {
            try {
                $l = Get-SessionLiveness -SessionId $sid
                if ($l.Found) { [string]$l.State } else { 'NOT-REGISTERED' }
            } catch { 'FENCE-ERROR' }
        }

    $lifecycle = [string](Get-RecField $rec 'lifecycle' 'open')
    $ageH = Get-AgeHours (Get-RecField $rec 'asOf')

    # DOES THE CHECKOUT STILL EXIST? One Test-Path, and the reader already re-derives everything else.
    # The project's own cleanup (scripts/worktree/remove.ps1, prune-merged.ps1) calls
    # `git worktree remove --force` and neither touches mefor-coord/seats, so the record outlives the
    # checkout BY CONSTRUCTION. Rendered without this, a vanished checkout is byte-identical to a live
    # one and stays in the respawn population, while -Detail prints "WORK AT RISK ... if that checkout
    # is removed they are gone" over files that went with the directory -- a warning written in the
    # conditional for a condition that already holds.
    # Test-Path itself throws on a path holding characters the filesystem API rejects, and a record's
    # worktree is a string read off disk. A path that cannot even be tested is not a checkout anyone
    # can respawn into, so the throw resolves to GONE rather than to a dead reader.
    $checkoutExists = $false
    if ($wt) { try { $checkoutExists = Test-Path -LiteralPath $wt -PathType Container } catch { $checkoutExists = $false } }
    $checkoutGone = ($wt -and -not $checkoutExists)
    # Git no longer LISTS the path, but a directory is still sitting there: a different fact, so it
    # gets a different name. Untracked files there are still recoverable, so this must not become a
    # state. Gated on the list being available at all, or a git that would not answer would flag
    # every row.
    $checkoutUnlisted = ($wt -and -not $checkoutGone -and $worktreeListAvailable -and
                         ($repoWorktrees -notcontains (Get-NormPath $wt)))

    # SUPERSEDED means "a LATER RECORD OF THIS SEAT replaced this one", and it is the only meaning the
    # never-respawn list can carry. It used to be computed per BOX -- and the box IS the worktree
    # (ConvertTo-BoxKey hashes the normalised path), while records are keyed per (worktree, SESSION).
    # So every other session that had ever recorded in that checkout retired the older ones: a
    # successor, a concurrent VS Code seat, a shared checkout. MEASURED: with three sessions in one
    # box, a seat holding the only copy of an untracked file AND a seat the fence reported LIVE both
    # rendered SUPERSEDED under "NO STOP CONDITIONS", and the same LIVE session id alone in its own box
    # rendered RUNNING in the same run. Supersession within ONE session is already expressed by the
    # record file being overwritten, so a cross-file rule keyed on the path had nothing left to mean.
    # The `predecessor` link is the one cross-file statement that IS about sessions, and it is written
    # by the seat itself. It is voluntary, so nothing DEPENDS on it: absent a link nothing is
    # superseded, every row stays visible, and the failure direction is showing more rather than less.
    $superseded = $false
    $myKey = [string](Get-RecField $rec 'sessionKey' '')
    foreach ($o in $records) {
        if ($o.File -eq $r.File) { continue }
        $p = Get-RecField $o.Rec 'predecessor'
        if (-not $p) { continue }
        $pBox = [string](Get-RecField $p 'boxKey' '')
        $pKey = [string](Get-RecField $p 'sessionKey' '')
        if (-not $pBox -or -not $pKey) { continue }
        if (($pBox -eq $r.Box) -and $myKey -and ($pKey -eq $myKey)) { $superseded = $true }
    }

    # ORDER IS THE FIX, NOT JUST THE ARMS. The POSITIVE fence answer goes FIRST, because it is the one
    # answer measured against the world as it is right now; everything below it is a label recorded in
    # the past. Any computed or declared label placed above it can MASK a running session, and both
    # kinds did: SUPERSEDED masked fence=LIVE, and `lifecycle` is written by the demoted voluntary half
    # -- a live seat that ran `-Close -Handback` renders HANDED, which is IN the respawn population, so
    # a stale declaration would put a second session into an occupied worktree. RUNNING and CLOSED are
    # both on the never-respawn list, so nothing is lost by preferring the measured fact.
    $state = switch ($true) {
        { $fence -eq 'LIVE' }                                    { 'RUNNING'; break }
        { $fence -in @('UNVERIFIED', 'UNREADABLE') }             { 'POSSIBLY RUNNING'; break }
        { $fence -in @('NOT-FENCEABLE', 'FENCE-ERROR') }         { 'POSSIBLY RUNNING'; break }
        { $fence -eq 'NO-FENCE' }                                { 'UNKNOWN-NO-FENCE'; break }
        # Also a fact measured against the world as it is now, so it outranks every recorded label:
        # there is nothing to respawn INTO and nothing left to rescue from that working directory.
        # Visible in the roster, out of the respawn population. In particular it must sit ABOVE
        # `handed`, which IS in the population and would otherwise hand a replacement a dead path.
        { $checkoutGone }                                        { 'CHECKOUT-GONE'; break }
        { $lifecycle -eq 'closed' }                              { 'CLOSED'; break }
        { $lifecycle -eq 'handed' }                              { 'HANDED'; break }
        { $superseded }                                          { 'SUPERSEDED'; break }
        default                                                  { 'INTERRUPTED' }
    }
    if ($state -eq 'INTERRUPTED' -and $null -ne $ageH -and $ageH -gt ($FoldDays * 24)) {
        $state = 'ORPHANED-STALE'
    }

    # WRITER-STALE: the record's own clock versus the harness transcript's. A per-session record's
    # age stops tracking activity the moment the writer stops, and the two must not be conflated.
    $writerStale = ($null -ne $ageH -and $ageH -gt 1 -and $state -in @('RUNNING', 'POSSIBLY RUNNING'))

    $declared = [string](Get-RecField $rec 'seat' '')
    if (-not $declared) { $declared = $null }

    # `[int]` on a value read off disk throws for anything non-numeric, so the cast is gated rather
    # than trusted. An epoch that will not parse renders as absent, which is what it is.
    $epoch = $null
    $epochRaw = Get-RecField $rec 'poolEpoch'
    if ($null -ne $epochRaw -and "$epochRaw" -match '\A[0-9]+\z') { $epoch = [int]$epochRaw }

    $rows += [pscustomobject]@{
        Box              = $r.Box
        SessionKey       = $myKey
        Seat             = $declared
        State            = $state
        Fence            = $fence
        AgeHours         = $ageH
        WriterStale      = $writerStale
        CheckoutGone     = [bool]$checkoutGone
        CheckoutUnlisted = [bool]$checkoutUnlisted
        Branch           = [string](Get-RecField $rec 'branch' '')
        Worktree         = $wt
        Epoch            = $epoch
        Rec              = $rec
        File             = $r.File
    }
  } catch {
    # THE ROW SURVIVES ITS OWN RECORD. Rendering nothing here would delete a seat from the answer;
    # rendering a row that says so keeps the checkout visible, keeps it OUT of the respawn population
    # (nothing about it was established), and the stop condition keyed on this count tells the reader
    # the roster is short by exactly this much and which file to open.
    $unclassifiableRecords++
    $rows += [pscustomobject]@{
        Box              = $r.Box
        SessionKey       = ''
        Seat             = $null
        State            = 'RECORD-UNUSABLE'
        Fence            = 'RECORD-UNUSABLE'
        AgeHours         = $null
        WriterStale      = $false
        CheckoutGone     = $false
        CheckoutUnlisted = $false
        Branch           = $null
        Worktree         = ''
        Epoch            = $null
        Rec              = $r.Rec
        File             = $r.File
    }
  }
}

# Records sharing ONE checkout. This is what the per-box SUPERSEDED rule was really reacting to, and
# hiding rows was the wrong answer to it: they are DIFFERENT sessions with different work. Reported as
# a count so the reader sees the collision risk instead of a silently shortened list -- one checkout
# takes ONE seat, so N rows in a box is at most one respawn, not N.
$boxesWithSeveral = @($rows | Group-Object Box | Where-Object { $_.Count -gt 1 })

# ---------------------------------------------------------------------------------------------
# The receipt, and the STOP conditions it can fire.
# ---------------------------------------------------------------------------------------------

$recordsUnfenceable = @($rows | Where-Object { $_.Fence -in @('NOT-FENCEABLE', 'FENCE-ERROR') }).Count
$recordsCheckoutGone = @($rows | Where-Object { $_.CheckoutGone }).Count

# THE STOP SET IS THE RECEIPT, READ BACK. Every operand below is a field printed above it, and every
# field printed above is read by something here -- see the header: a printed field that no stop reads
# is a decoration, and this file shipped with two of them.
$stops = @()
if (-not $fenceAvailable) { $stops += 'fenceAvailable=false -- no config root with a sessions/ directory was found; every state below would be a guess' }
# PRESENT IS NOT THE SAME AS ABLE TO SEE. With a sessions/ directory that holds nothing readable, the
# fence answers NOT-REGISTERED for every record and INTERRUPTED is MANUFACTURED rather than measured --
# including for seats that are running right now. This suppresses the completeness claim rather than
# reclassifying the rows, because reclassifying them would empty the respawn population instead.
elseif (-not $fenceCanSee) { $stops += "fenceSessionRecordsRead=0 over rootsExamined=$rootsExamined -- the fence is PRESENT but read no session records at all, so every NOT-REGISTERED verdict below (and every INTERRUPTED derived from one) was measured against an EMPTY registry" }
if ($fenceRecordsUnreadable -gt 0) { $stops += "fenceSessionRecordsUnreadable=$fenceRecordsUnreadable -- that many registry files would not parse, so the live denominator is short by up to that many; a session that launched a moment ago has exactly that shape" }
if (-not $worktreeListAvailable) { $stops += 'worktreeListAvailable=false -- git would not list this clone''s worktrees, so liveSessionsWithoutRecord below is computed against an EMPTY denominator and cannot fire' }
if ($liveWithoutRecord.Count -gt 0) { $stops += "liveSessionsWithoutRecord=$($liveWithoutRecord.Count) -- the writer is not running in every live seat, so this roster is INCOMPLETE by that many" }
# THE RECENCY HALF OF THE SAME DENOMINATOR. Existence alone was satisfied for ever by one record
# written once, so a writer that recorded turn 1 and then died reported as healthy.
if ($liveWithStaleRecord.Count -gt 0) { $stops += "liveSessionsWithStaleRecord=$($liveWithStaleRecord.Count) -- that many live seats have a record OLDER than $FreshMinutes minutes (or one whose age will not parse); the writer recorded them once and has not since, so what the roster says about them is out of date by an unknown amount" }
if ($liveWithoutFreshHeartbeat.Count -gt 0) { $stops += "liveSessionsWithStaleWriterHeartbeat=$($liveWithoutFreshHeartbeat.Count) -- that many live seats have no writer heartbeat inside $FreshMinutes minutes, so the Stop hook is not firing there at all (disableAllHooks, org policy and workspace trust all disable it SILENTLY)" }
if ($registryUnfenceable -gt 0) { $stops += "registryRecordsUnfenceable=$registryUnfenceable -- that many session records in this repo's worktrees could not be fenced at all, so the live denominator is short by up to that many" }
if ($records.Count -eq 0 -and $heartbeats.Count -eq 0) { $stops += 'recordsExamined=0 AND writerHeartbeatIn=0 -- indistinguishable from a writer that was never installed' }
# A RECORD THAT WOULD NOT PARSE IS A SEAT THIS ROSTER CANNOT DESCRIBE. It was already counted and
# already printed; it just entered no stop, so a seats layer where EVERY record was unreadable
# rendered as a confident empty roster. One of these may simply be mid-write -- that is a re-run, not
# a reason to leave the claim of completeness standing.
if ($unreadableRecords -gt 0) { $stops += "recordsUnreadable=$unreadableRecords -- that many files in the seats layer are not readable records (malformed, empty, or being written this instant), so the roster is short by up to that many" }
if ($unclassifiableRecords -gt 0) { $stops += "recordsUnclassifiable=$unclassifiableRecords -- that many records parsed but could not be classified; they are rendered as RECORD-UNUSABLE and nothing about them was established" }
# A record with no sessionId is STRUCTURALLY unfenceable rather than merely quiet, and it is reachable
# by design (the plain hook path with no session_id on stdin writes exactly one). Its liveness column
# is not a measurement, so the roster is incomplete by that many whatever state is rendered.
if ($recordsUnfenceable -gt 0) { $stops += "recordsUnfenceable=$recordsUnfenceable -- that many records carry no session id or threw in the fence, so their liveness is UNMEASURED, not quiet" }
# THE WRITER SAYING IT FAILED. seat.ps1 exits 0 on every failure by design (rule 2), so this log is the
# only place a seat that is provably not being recorded shows up at all. Keyed on the RECENT count for
# the reason given where it is computed: the log never shrinks.
if ($writerErrorsRecent -gt 0) {
    $newestTxt = if ($null -ne $writerErrorNewestAge) { "newest $([int]$writerErrorNewestAge)m ago" } else { 'newest of unknown age' }
    $stops += "writerErrorLinesRecent=$writerErrorsRecent of writerErrorLines=$writerErrors ($newestTxt) -- the writer FAILED that many times inside $FreshMinutes minutes and still exited 0; read $errFile. Any seat it failed on is missing or stale below"
}
# UNCHECKABLE is its own stop. Silence beside a populated originMainSha reads as a pass, and that is
# precisely the blind direction: landed verdicts computed against a cached main of unknown age.
if ($null -eq $originMainAgeMinutes) { $stops += "originMainAgeMinutes is $originMainAgeSource -- landed verdicts below would be computed against a cached origin/main of UNKNOWN age" }
elseif ($originMainAgeMinutes -gt 60) { $stops += "originMainAgeMinutes=$originMainAgeMinutes (source: $originMainAgeSource) -- nobody has fetched in this clone recently; landed verdicts would be computed against a stale ref" }

$receipt = [ordered]@{
    renderedAtUtc              = $now.ToString('yyyy-MM-ddTHH:mm:ssZ')
    seatsDir                   = $seatsDir
    # SDS-3.8 again: every staleness verdict below is a comparison against THIS number, so a reader
    # cannot check any of them without seeing it.
    freshWithinMinutes         = $FreshMinutes
    rootsExamined              = $rootsExamined
    fenceAvailable             = $fenceAvailable
    fenceSessionRecordsRead    = $fenceRecordsRead
    fenceSessionRecordsUnreadable = $fenceRecordsUnreadable
    fenceCanSee                = $fenceCanSee
    recordsExamined            = $records.Count
    recordsUnreadable          = $unreadableRecords
    recordsUnclassifiable      = $unclassifiableRecords
    recordsUnfenceable         = $recordsUnfenceable
    recordsCheckoutGone        = $recordsCheckoutGone
    liveSessionsInRepo         = $liveInRepo.Count
    liveSessionsWithoutRecord  = $liveWithoutRecord.Count
    liveSessionsWithStaleRecord = $liveWithStaleRecord.Count
    liveSessionsWithStaleWriterHeartbeat = $liveWithoutFreshHeartbeat.Count
    registryRecordsUnfenceable = $registryUnfenceable
    writerHeartbeatIn          = $heartbeats.Count
    # The AGE of the newest heartbeat, not just how many files there are. Null means no heartbeat file
    # exists at all, which is a different sentence from "one exists and is old".
    writerHeartbeatNewestAgeMinutes = $heartbeatNewestAge
    writerErrorLines           = $writerErrors
    writerErrorLinesRecent     = $writerErrorsRecent
    worktreeListAvailable      = $worktreeListAvailable
    repoWorktrees              = $repoWorktrees.Count
    checkoutsWithSeveralRecords = $boxesWithSeveral.Count
    originMainSha              = $originMainSha
    originMainAgeMinutes       = $originMainAgeMinutes
    # SDS-3.8: the number is useless without the instrument that produced it. A reader has to be able
    # to check that the tool answers the question they are asking it, and 'UNCHECKABLE' has to be a
    # value they can SEE rather than a blank they interpret.
    originMainAgeSource        = $originMainAgeSource
    stopConditions             = @($stops)
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
    # PREFIX MATCH ON THE SESSION KEY, the way Get-SessionLiveness already resolves a session id. The
    # roster prints a truncated key (a full one is 36 characters and would push the branch off a
    # terminal), so an exact-match-only lookup would demand an identifier no rendered surface shows.
    # AMBIGUITY IS A LOUD REFUSAL, never a Select-Object -First 1: picking one of two seats silently is
    # how a reader gets a confident briefing about the wrong session.
    $hits = @($rows | Where-Object {
        $_.Box -eq $BoxKey -and ($_.SessionKey -eq $SessionKey -or
            ($SessionKey -and $_.SessionKey.StartsWith($SessionKey, [StringComparison]::OrdinalIgnoreCase)))
    })
    if ($hits.Count -eq 0) {
        $inBox = @($rows | Where-Object { $_.Box -eq $BoxKey })
        if ($inBox.Count -eq 0) {
            Write-Error "fleet.ps1: no record for box '$BoxKey'. Boxes present: $((@($rows | Select-Object -ExpandProperty Box -Unique)) -join ', ')"
        } else {
            Write-Error "fleet.ps1: no record for $BoxKey/$SessionKey. Session keys in that box: $((@($inBox | Select-Object -ExpandProperty SessionKey)) -join ', ')"
        }
        exit 2
    }
    if ($hits.Count -gt 1) {
        Write-Error "fleet.ps1: '$SessionKey' is AMBIGUOUS in $BoxKey -- it matches $($hits.Count) records: $((@($hits | Select-Object -ExpandProperty SessionKey)) -join ', '). Give more of the key."
        exit 2
    }
    $row = $hits[0]
    $rec = $row.Rec
    $ageTxt = if ($null -ne $row.AgeHours) { "$($row.AgeHours)h old" } else { "age unknown" }

    "SEAT EVIDENCE -- $($row.Box)/$($row.SessionKey)"
    "This is EVIDENCE for you to read, not a briefing to paste. Compose the chip yourself."
    "Every line below was recorded $ageTxt and may have expired since. Re-check commands are given."
    ""
    "STATE (computed now): $($row.State)   fence=$($row.Fence)"
    if ($row.CheckoutGone) {
        "CHECKOUT: $($row.Worktree)"
        "  THAT DIRECTORY NO LONGER EXISTS -- checked just now. The record outlives the checkout by"
        "  construction: the project's own cleanup runs 'git worktree remove --force' and does not"
        "  touch this layer. Everything below that lived only in the working directory is ALREADY GONE,"
        "  not at risk. What survives is what git holds: pushed commits, and the stash object if it"
        "  still resolves. Every re-check command rooted at that path will fail, and that is expected."
    } else {
        "CHECKOUT: $($row.Worktree)"
        if ($row.CheckoutUnlisted) {
            "  The directory is there, but 'git worktree list' does not name it -- it is a leftover"
            "  directory rather than a registered worktree of this clone. Files in it are still readable."
        }
    }
    "BRANCH:   $($row.Branch)"
    "  Work is named by BRANCH. A commit id is not an identifier here -- a rebase reissues it."
    $tip = Get-RecField $rec 'tip'
    if ($tip) { "  tip was $tip as of the record; resolve the branch yourself." }
    ""
    "WHAT THIS SEAT ACTUALLY DID -- involuntary evidence, written as a side effect of working:"
    $commits = @(Get-RecField $rec 'commits' @())
    if ($commits.Count -gt 0) {
        foreach ($c in $commits) { "  $c" }
    } else {
        "  no commits since the merge-base were recorded"
    }
    $touched = @(Get-RecField $rec 'touchedPaths' @())
    if ($touched.Count -gt 0) {
        # A LIST THAT IS SHORTER THAN ITS OWN COUNT MUST SAY SO. This used to print "touched 19
        # path(s):" and then list 15 with no ellipsis and no "showing first N".
        $head = @($touched | Select-Object -First 15)
        $more = if ($touched.Count -gt $head.Count) { " ... and $($touched.Count - $head.Count) more (SHOWING $($head.Count) OF $($touched.Count))" } else { '' }
        "  touched $($touched.Count) path(s): " + ($head -join ', ') + $more
    }
    ""
    if ($row.CheckoutGone) {
        "WORK THAT WAS AT RISK -- THE CHECKOUT IS GONE, so this is a post-mortem, not a rescue list:"
    } else {
        "WORK AT RISK -- check this FIRST, it is the only category that cannot be recovered elsewhere:"
    }
    $untracked = @(Get-RecField (Get-RecField $rec 'dirty') 'untracked' @())
    if ($untracked.Count -gt 0) {
        if ($row.CheckoutGone) {
            "  $($untracked.Count) UNTRACKED file(s) were held by NO GIT OBJECT, and the directory that"
            "  held them has been removed. THEY ARE ALREADY GONE -- there is nothing here to rescue and"
            "  no command below will find them. Recorded so the loss is known rather than discovered:"
        } else {
            "  $($untracked.Count) UNTRACKED file(s) -- HELD BY NO GIT OBJECT. Not in the stash, not in a"
            "  commit, not on a remote. If that checkout is removed they are gone:"
        }
        foreach ($u in ($untracked | Select-Object -First 40)) { "    $u" }
        if ($untracked.Count -gt 40) { "    ... and $($untracked.Count - 40) more (SHOWING 40 OF $($untracked.Count))" }
    } else { "  no untracked files were recorded" }
    # THE STASH HANDLE IS TESTED, NOT PRINTED. `git stash create` writes no ref and no reflog entry, so
    # the object it names is unreachable from the moment it exists; seat.ps1 now ANCHORS it under
    # refs/mefor-seat/<box>/<session> and records that ref, and this is the reader half of that fix.
    # MEASURED before it: `git gc --prune=now` deleted the recorded stash and the next -Detail printed
    # the same sha in the same words -- a pruned handle and a live one were byte-identical, under a
    # heading that tells the reader the tracked half is the recoverable one.
    #
    # THE PROBE RUNS IN THIS CLONE, NOT IN THE RECORD'S CHECKOUT. Every worktree of a clone shares one
    # object store, and the recorded checkout may be CHECKOUT-GONE -- which is exactly when a reader
    # most needs to know whether the object survived it.
    $stashSha = [string](Get-RecField $rec 'stashSha' '')
    $stashRef = [string](Get-RecField $rec 'stashRef' '')
    $stashObjectGone = $false
    if ($stashSha) {
        $objSha = Invoke-Git -Dir $repo -GitArgs @('rev-parse', '--verify', '--quiet', "$stashSha^{commit}")
        $stashObjectGone = (-not $objSha)
        $refSha = if ($stashRef) { Invoke-Git -Dir $repo -GitArgs @('rev-parse', '--verify', '--quiet', $stashRef) } else { $null }
        if (-not $objSha) {
            "  stash commit (TRACKED edits only): $stashSha"
            "    THAT OBJECT NO LONGER RESOLVES -- checked just now with 'git rev-parse --verify' in this"
            "    clone. gc has pruned it. Those tracked edits are NOT recoverable from this handle; what"
            "    is left is whatever was committed or pushed. This is a post-mortem line, not a rescue one."
        } elseif ($refSha -and $refSha -eq $stashSha) {
            "  stash commit (TRACKED edits only): $stashSha"
            "    Verified just now: the object resolves AND $stashRef still holds it, so gc cannot take it."
            "    Recover with:  git -C `"$($row.Worktree)`" stash apply $stashSha"
        } else {
            "  stash commit (TRACKED edits only): $stashSha"
            $where = if (-not $stashRef) { 'the record names no anchoring ref (written by an older writer)' }
                     elseif (-not $refSha) { "its anchor $stashRef is GONE" }
                     else { "its anchor $stashRef now points at $refSha instead" }
            "    The object still resolves, but $where -- so nothing holds it and the next gc in this"
            "    clone can delete it without a word. Recover or re-anchor it NOW:"
            "    git -C `"$($row.Worktree)`" stash apply $stashSha"
        }
    }
    # `stashCovers` is the WRITER's word for what the stash held when it was made. Printed bare under a
    # "no longer resolves" verdict it reads as a live promise of recovery, which is the exact
    # over-promise this block exists to stop, so the reader's own measurement qualifies it.
    $stashCovers = Get-RecField $rec 'stashCovers'
    if ($null -ne $stashCovers) {
        if ($stashObjectGone) { "  stash covers: $stashCovers -- AS RECORDED; the object backing it is gone (above)" }
        else { "  stash covers: $stashCovers" }
    }
    $unpushed = Get-RecField $rec 'unpushed'
    if ($unpushed) { "  unpushed commits vs $(Get-RecField $unpushed 'base' '?'): $(Get-RecField $unpushed 'count' '?')" }
    else { "  unpushed: NO-UPSTREAM (nobody has looked; this is not the same as zero)" }
    ""
    "RE-CHECK BEFORE YOU ACT ON ANY OF THE ABOVE:"
    "  git fetch origin"
    "  git -C `"$($row.Worktree)`" status --porcelain"
    "  git -C `"$($row.Worktree)`" log --oneline origin/main..HEAD"
    if ($touched.Count -gt 0) {
        # THE PATHSPEC IS READ FROM THE RECORD, NOT PASTED INTO THE COMMAND. The pasted form was
        # wrong twice over and both mechanisms yield the SAME observable -- git exits 0 with empty
        # output, which the sentence below defines as "already on main":
        #   TRUNCATION  the emitted pathspec stopped at 15 entries with no marker. MEASURED on a
        #               19-path branch whose first 15 had squash-landed: the emitted command returned
        #               nothing, rc=0, while the same query over all 19 named three unlanded modules
        #               and a new file. A reader following the printed instruction drops live work.
        #   QUOTING     the paths were joined on a bare space, so "b/my notes.md" became two
        #               pathspecs that match nothing. MEASURED: unquoted -> empty, rc=0; quoted ->
        #               "b/my notes.md". A completely unlanded single-path branch reports as landed.
        # Splatting an array to a native command passes each element as ONE argument, so quoting and
        # spaces are handled by the shell rather than by string concatenation here, and the command's
        # LENGTH no longer scales with the path count -- which is what made truncation tempting.
        "  `$p = (Get-Content -Raw `"$($row.File)`" | ConvertFrom-Json).touchedPaths"
        "  git -C `"$($row.Worktree)`" diff --name-only origin/main $($row.Branch) -- @p"
        "    That reads all $($touched.Count) recorded path(s) from the record itself, so the pathspec"
        "    cannot be short and cannot be split on a space. ONLY THEN does empty output mean the"
        "    CONTENT is already on main. Ancestry answers a different question: squash-merge routinely"
        "    makes commits-ahead and content-ahead disagree."
        if ($null -eq $originMainAgeMinutes) {
            "    CAUTION: origin/main's freshness is UNCHECKABLE in this clone ($originMainAgeSource),"
            "    so run the fetch above FIRST or this verdict is against a cached ref of unknown age."
        }
    } else {
        "  landed check is UNCHECKABLE -- no touched paths recorded, so derive the pathspec from the"
        "  branch's own merge-base rather than diffing the whole tree."
    }
    ""
    "LEDGER AND CLAIMS -- attribution matters, the path outlives its occupant:"
    # Get-RecField INSIDE the filters as well: these elements come from a JSON array on disk, so a
    # claim written by an older writer, or one caught mid-write, need not carry `attribution` -- and
    # under strict mode reading the absent property throws out of the whole -Detail render.
    $claims = @(Get-RecField $rec 'claims' @())
    $ownC = @($claims | Where-Object { (Get-RecField $_ 'attribution') -eq 'this-episode' })
    $inhC = @($claims | Where-Object { (Get-RecField $_ 'attribution') -ne 'this-episode' })
    "  claims by THIS episode:      " + $(if ($ownC.Count) { (($ownC | ForEach-Object { Get-RecField $_ 'key' '?' }) -join ', ') } else { 'none' })
    if ($inhC.Count) { "  present but from EARLIER occupants of that path (NOT this seat's): " + (($inhC | ForEach-Object { Get-RecField $_ 'key' '?' }) -join ', ') }
    $allocs = @(Get-RecField $rec 'allocations' @())
    $ownA = @($allocs | Where-Object { (Get-RecField $_ 'attribution') -eq 'this-episode' })
    $inhA = @($allocs | Where-Object { (Get-RecField $_ 'attribution') -ne 'this-episode' })
    "  ledger numbers by THIS episode: " + $(if ($ownA.Count) { (($ownA | ForEach-Object { "$(Get-RecField $_ 'kind' '?') #$(Get-RecField $_ 'number' '?')" }) -join ', ') } else { 'none' })
    if ($inhA.Count) { "  $($inhA.Count) more allocated to that PATH by earlier occupants -- not this seat's, do not rehome or cite" }
    ""
    "DECLARED INTENT -- VOLUNTARY, UNVERIFIED, AND OFTEN ABSENT BY DESIGN."
    "  Measured adoption of voluntary declaration on this project: 8.8 to 31 percent. Treat anything"
    "  here as a hint that was true when someone typed it, never as the record. The evidence above is"
    "  the record."
    $decSeat = Get-RecField $rec 'seat'
    $decGoal = Get-RecField $rec 'goal'
    $decDone = Get-RecField $rec 'done'
    $decScope = Get-RecField $rec 'outOfScope'
    $decHandoff = Get-RecField $rec 'handoff'
    if ($decSeat) { "  seat:        $decSeat" } else { "  seat:        not declared" }
    if ($decGoal) { "  goal:        $decGoal" }
    if ($decDone) { "  done means:  $decDone" }
    if ($decScope) { "  out of scope: $decScope" }
    if ($decHandoff -and (Get-RecField $decHandoff 'path')) {
        "  handoff:     $(Get-RecField $decHandoff 'path')"
        if (Get-RecField $decHandoff 'unresolved') {
            "               WARNING: that path DID NOT RESOLVE when recorded. A lead, not a document."
        }
    }
    ""
    "ACCOUNT BOUNDARY -- do NOT carry these across: usage figures, project memory, artifact"
    "capabilities, workflow caches, the realtime send channel. Read your own."
    exit 0
}

# REDACTION IS THE DEFAULT ON -Json, and -Raw is the opt-out.
#
# Owner decision D1 governs coordination state that leaves the terminal: absolute home paths and
# free-text notes are stripped. -Json is the mode most likely to be piped somewhere -- a file, a
# ticket, an artifact -- and a default that has to be remembered is not a control. So the safe form
# is what you get for free and the unsafe form has to be asked for by name.
#
# It replaces the USER PROFILE PREFIX rather than pattern-matching a username: a regex for a name is
# a needle that goes stale the moment the box changes hands, and this has to fail toward redacting.
# The worktree LEAF survives, because a reader needs to tell two checkouts apart, and the leaf is a
# branch-ish label rather than a home path.
function Protect-HomePath([string]$p) {
    if (-not $p) { return $p }
    $home_ = $env:USERPROFILE
    if ($home_ -and $p.StartsWith($home_, [StringComparison]::OrdinalIgnoreCase)) {
        return '~' + $p.Substring($home_.Length)
    }
    return $p
}

if ($Json) {
    $outRows = @($rows | Select-Object Box, SessionKey, Seat, State, Fence, AgeHours, WriterStale, CheckoutGone, CheckoutUnlisted, Branch, Worktree, Epoch)
    # THE DENOMINATOR'S OWN ROWS, not just its count. A machine reader that sees
    # liveSessionsWithoutRecord=3 and cannot name the three has been told the roster is incomplete
    # without being told where. These are the seats the roster CANNOT describe, so they are rendered
    # beside the ones it can.
    $outLive = @($liveInRepo | Where-Object { -not $_.RecordFresh } | ForEach-Object {
        [pscustomobject]@{
            SessionId           = $_.SessionId
            Box                 = $_.Box
            Worktree            = $_.Worktree
            HasRecord           = $_.HasRecord
            RecordAgeMinutes    = $(if ($null -ne $_.RecordAgeMinutes) { [int]$_.RecordAgeMinutes } else { $null })
            HeartbeatAgeMinutes = $(if ($null -ne $_.HeartbeatAgeMinutes) { [int]$_.HeartbeatAgeMinutes } else { $null })
        }
    })
    $outReceipt = $receipt
    if (-not $Raw) {
        $outReceipt = [ordered]@{}
        foreach ($k in $receipt.Keys) {
            # ASSIGN THE VALUE, DO NOT ASSIGN THE OUTPUT OF AN `if`. A statement's output stream
            # UNROLLS an array, so an EMPTY one contributes zero objects and the assignment lands
            # $null. MEASURED here, on the one field where it matters most: `-Json -Raw` emitted
            # "stopConditions": [] while `-Json` -- the DEFAULT, and the form most likely to be piped
            # somewhere -- emitted "stopConditions": null for the same run, purely because it went
            # through this loop. A machine reader then cannot tell "no stop conditions" from "this
            # instrument does not report stop conditions", which is this module's own defect class
            # (and PowerShell's `@($null).Count -eq 1` makes the miscount agree with a plausible
            # wrong answer, as it did once already in this layer).
            $v = $receipt[$k]
            if ($k -eq 'seatsDir') { $v = Protect-HomePath ([string]$v) }
            $outReceipt[$k] = $v
        }
        foreach ($r in $outRows) { $r.Worktree = Protect-HomePath ([string]$r.Worktree) }
        foreach ($r in $outLive) { $r.Worktree = Protect-HomePath ([string]$r.Worktree) }
    }
    [ordered]@{
        redacted = (-not $Raw)
        receipt  = $outReceipt
        rows     = $outRows
        liveSessionsNotDescribed = $outLive
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
    "  {0,-38} {1}" -f $k, $receipt[$k]
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

# THE DENOMINATOR, NAMED. A count in the receipt says the roster is short; this says by WHICH seats,
# which is what a reader can actually act on. These are live sessions the FENCE can see sitting in
# this clone's worktrees whose record is missing or stale -- so they are absent from, or out of date
# in, the roster below, and nothing in that roster hints at them.
$liveNotDescribed = @($liveInRepo | Where-Object { -not $_.RecordFresh })
if ($liveNotDescribed.Count -gt 0) {
    "LIVE SESSIONS THIS ROSTER CANNOT DESCRIBE -- $($liveNotDescribed.Count). The fence sees them; the writer did not:"
    foreach ($s in $liveNotDescribed) {
        $sid = if ($s.SessionId) { $s.SessionId } else { '(no session id)' }
        if ($sid.Length -gt 12) { $sid = $sid.Substring(0, 12) }
        $why = if (-not $s.HasRecord) { 'NO RECORD AT ALL' }
               elseif ($null -eq $s.RecordAgeMinutes) { 'record present, its age WILL NOT PARSE' }
               else { "newest record is $([int]$s.RecordAgeMinutes)m old (bound $FreshMinutes m)" }
        $hb = if ($null -eq $s.HeartbeatAgeMinutes) { 'no writer heartbeat for that checkout' } else { "writer heartbeat $([int]$s.HeartbeatAgeMinutes)m old" }
        "  {0,-13} {1}" -f $sid, $s.Worktree
        "                {0}; {1}" -f $why, $hb
    }
    ""
}

$shown = if ($All) { $rows } else { $rows | Where-Object { $_.State -ne 'ORPHANED-STALE' } }
$folded = @($rows).Count - @($shown).Count

if (@($rows).Count -eq 0) {
    "NO EPISODE RECORDS EXIST. That is NOT the same as 'no seats were working' -- see the receipt above."
} else {
    # THE SESSION COLUMN IS NOT DECORATION. The footer's own next step takes -SessionKey, and this is
    # the default surface, written for a human who lost their context. Without it, several sessions in
    # one checkout render BYTE-IDENTICALLY apart from state and age -- same box, same NOT-DECLARED,
    # same branch -- so the reader can see the rows, cannot address any of them, and the natural
    # recovery of guessing the box key twice returns "no record for <box>/". A 12-character prefix is
    # enough because -Detail resolves a prefix and refuses an ambiguous one out loud. Rows are grouped
    # by BOX, so sessions sharing a checkout sit together instead of being scattered by state.
    "{0,-30} {1,-13} {2,-14} {3,-18} {4,-7} {5}" -f 'BOX', 'SESSION', 'SEAT', 'STATE', 'AGE_H', 'BRANCH'
    foreach ($row in ($shown | Sort-Object Box, State, AgeHours)) {
        $seat = if ($row.Seat) { $row.Seat } else { 'NOT-DECLARED' }
        $sk = if ($row.SessionKey) { $row.SessionKey } else { '(no-key)' }
        if ($sk.Length -gt 12) { $sk = $sk.Substring(0, 12) }
        $mark = ''
        if ($row.WriterStale) { $mark += ' [WRITER-STALE]' }
        if ($row.CheckoutUnlisted) { $mark += ' [CHECKOUT-UNLISTED]' }
        "{0,-30} {1,-13} {2,-14} {3,-18} {4,-7} {5}{6}" -f $row.Box, $sk, $seat, $row.State, $row.AgeHours, $row.Branch, $mark
    }
}
if ($folded -gt 0) { ""; "$folded row(s) folded as ORPHANED-STALE (older than $FoldDays days). Show with -All." }
if ($boxesWithSeveral.Count -gt 0) {
    ""
    "$($boxesWithSeveral.Count) checkout(s) hold MORE THAN ONE record -- these are DIFFERENT sessions that"
    "occupied the same directory, not older snapshots of one seat, so each row is its own work. But a"
    "checkout takes ONE seat at a time: read them all, respawn at most one per checkout."
    foreach ($g in $boxesWithSeveral) { "  $($g.Name): $($g.Count) records" }
}

""
"RESPAWN POPULATION (INTERRUPTED, HANDED): " + @($rows | Where-Object { $_.State -in @('INTERRUPTED', 'HANDED') }).Count
"  Never respawned: RUNNING, POSSIBLY RUNNING, SUPERSEDED, CLOSED, CHECKOUT-GONE, UNKNOWN-NO-FENCE,"
"  RECORD-UNUSABLE."
"  POSSIBLY RUNNING now also covers a record that could not be fenced at all (no session id, or the"
"  fence threw). An unevaluated fence is not a passed fence, and the receipt counts them."
"  RECORD-UNUSABLE is a file this reader could not turn into a row: nothing about that seat was"
"  established, so it is neither respawned nor written off -- open the record and decide by hand."
"  Briefing for one row:  fleet.ps1 -Detail -BoxKey <box> -SessionKey <session>"
"  (both columns are printed above; the SESSION prefix shown is enough, and an ambiguous one is"
"  refused by name rather than resolved to the first match.)"

$code = if ($fenceAvailable) { 0 } else { 2 }
exit $code


