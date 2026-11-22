# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Project the fleet from the episode records seat.ps1 wrote -- the roster a session under a
    DIFFERENT account reads to reconstitute a replacement fleet after an account switch.

.DESCRIPTION
    PURE READER over <shared root>/seats/ (coord-root.ps1; <git-common-dir>/mefor-coord/seats/ when
    nothing is configured). It writes nothing except the render
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

    A RECORD FROM ANOTHER PC IS NEVER JUDGED HERE. On a shared root the registry holds seats from
    every PC, and both of this reader's liveness inputs -- the session-registry fence and the handoff
    file on disk -- are per-PC. A seat running on the other PC has no session here and its paths do
    not exist here, so judging it would read a live seat as INTERRUPTED and invite a respawn of work
    still running. Such a record renders as ON <HOST> and is excluded from the respawn population and
    the pointer census. A record with no `host` predates the field and is this PC's
    (docs/COORD-SHARED-ROOT.md, "The bug a plain path change would ship").
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

# A CLAUDE CODE CLOUD SESSION REACHES NO OTHER SESSION THROUGH THIS SCRIPT: its --git-common-dir is
# the VM's own clone, so a read finds nothing there and the empty answer looks clean. CLAUDE.md
# section 5, "A cloud session is a Builder in its own session"; tests/test_coord_cloud_refusal.py
# holds the copies equal.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('fleet.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s .git/mefor-coord reaches no other session, so nothing was read or recorded.')
    exit 3
}

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

. "$PSScriptRoot\session-registry.ps1"
. "$PSScriptRoot\mail-key.ps1"
. "$PSScriptRoot\coord-root.ps1"

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
# seats/ is a SHARED kind. A root that does not answer is a refusal, never a quiet read of the local
# copy: that copy is the one the other PC never writes, so it would render as a complete, smaller fleet.
$seatsRes = Resolve-CoordDir -From $repo -Kind 'seats' -LocalRoot (Join-Path ([string]$common).Trim() 'mefor-coord')
if ($seatsRes.Error) {
    # stderr directly, not Write-Error: under this file's 'Stop' preference Write-Error throws and the
    # exit code would be 1 instead of the 2 this refusal documents.
    [Console]::Error.WriteLine("fleet.ps1: the shared seat registry did not resolve, so nothing was read: $($seatsRes.Error)")
    exit 2
}
$seatsDir = $seatsRes.Path
$primary = Split-Path $common -Parent
$thisHost = Get-CoordHost

# ---------------------------------------------------------------------------------------------
# Gather. Records first, then the fence, then the denominator.
# ---------------------------------------------------------------------------------------------

$records = @()
$unreadableRecordFiles = @()
if (Test-Path -LiteralPath $seatsDir) {
    foreach ($d in @(Get-ChildItem -LiteralPath $seatsDir -Directory -EA SilentlyContinue |
                     Where-Object { $_.Name -notlike '.*' })) {
        foreach ($f in @(Get-ChildItem -LiteralPath $d.FullName -Filter *.json -File -EA SilentlyContinue)) {
            try {
                $j = Read-CoordText $f.FullName -AllowAccessDenied | ConvertFrom-Json -EA Stop
                $records += [pscustomobject]@{ Rec = $j; File = $f.FullName; Box = $d.Name }
            } catch [System.IO.FileNotFoundException], [System.IO.DirectoryNotFoundException] {
                # Deleted between the listing and the read: a file that is gone holds no seat. Only
                # the read's own not-found says so; a later Test-Path could not tell a vanished file
                # from one whose read failed for another reason and then moved. A seats directory that
                # is itself gone (a dropped share) is not a deleted record: every read after it would
                # be skipped and the roster would come out smaller, so that counts as unreadable.
                if (-not (Test-Path -LiteralPath $seatsDir -PathType Container)) { $unreadableRecordFiles += $f.FullName }
                continue
            } catch {
                # Counted, never dropped: dropping turns an occupied seat into an absent one in the
                # receipt's own numbers. seat.ps1 writes a record by one atomic rename and the read
                # retries a sharing violation and, with -AllowAccessDenied, the access denied Windows
                # gives a file deleted but not yet gone, so a record that still fails is not busy.
                # It fires a stop below: an unread record may be a seat the roster cannot show.
                $unreadableRecordFiles += $f.FullName
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

# The registry's own normalizer, so the denominator and the anonymous-record veto read one cwd the
# same way.
function Get-NormPath([string]$p) { return (ConvertTo-RegistryNormPath $p) }

# Worktrees of THIS clone, so the denominator is scoped to this repo rather than to the whole box.
$repoWorktrees = @()
$wtOut = Invoke-Git -Dir $repo -GitArgs @('worktree', 'list', '--porcelain')
if ($wtOut) {
    foreach ($line in ($wtOut -split "`n")) {
        if ($line -match '^worktree\s+(.+)$') { $repoWorktrees += (Get-NormPath $Matches[1]) }
    }
}

# The worktree of this repo that holds a normalised cwd, or $null, so a session in a subdirectory
# counts in the denominator (BACKLOG #5485). It walks up the cwd's ancestors to the nearest worktree
# (the innermost, where worktrees nest), so the boundary is a separator and `repo-other` is not inside
# `repo`. Both sides are lower-cased by ConvertTo-RegistryNormPath. A directory with its own .git
# between the cwd and that worktree is another repository's tree, so the cwd is not this repo's.
$repoWorktreeSet = [System.Collections.Generic.HashSet[string]]::new([string[]]@($repoWorktrees | Where-Object { $_ }), [System.StringComparer]::Ordinal)
function Get-ContainingRepoWorktree([string]$Cwd) {
    $below = @()
    $p = $Cwd
    while ($p) {
        if ($repoWorktreeSet.Contains($p)) {
            foreach ($b in $below) { if (Test-Path -LiteralPath "$b\.git") { return $null } }
            return $p
        }
        $below += $p
        $cut = $p.LastIndexOf('\')
        $p = if ($cut -gt 0) { $p.Substring(0, $cut) } else { '' }
    }
    return $null
}

# LIVE sessions sitting in this repo's worktrees. This is the denominator: a session here that has
# produced no record is EVIDENCE THE WRITER IS DEAD, not evidence the fleet is idle.
$liveInRepo = @()
foreach ($row in $sessionRows) {
    if (-not $row.Record) { continue }
    # Read through Get-RecordField: a registry file holding `{}` parses to an object with no
    # properties, and `.PSObject.Properties.Name` on it throws under StrictMode (BACKLOG #5491).
    $rawCwd = [string](Get-RecordField $row.Record 'cwd')
    $cwd = Get-NormPath $rawCwd
    $holder = Get-ContainingRepoWorktree $cwd
    if (-not $holder) { continue }
    # A record that names no session is still a live session here, whatever its age, so it counts,
    # and it counts in liveWithoutRecord below too: no seat record can be matched to it, so the
    # roster is incomplete by it until it names its session.
    $liveSid = [string](Get-RecordField $row.Record 'sessionId')
    # The same unbounded start skew as the seat lookup below, so the two count one session alike.
    $l = Test-RecordLiveness -Record $row.Record -StartSkewMinutes ([int]::MaxValue)
    if ($l.State -eq 'LIVE') {
        $liveInRepo += [pscustomobject]@{
            SessionId = $liveSid
            Cwd       = $cwd
            # The worktree's box, not the cwd's: a subdirectory names a box no seat writes.
            Box       = (ConvertTo-BoxKey -Path $holder)
            Root      = $row.Root
        }
    }
}

# Registry records that name no session and are LIVE or fresh (session-registry.ps1,
# Get-AnonymousSessionRecords). A seat whose own lookup would read gone, and whose worktree such a
# record reaches (Test-AnonymousRecordReaches), reads POSSIBLY RUNNING through its own fence below,
# because each seat's lookup passes its worktree. One with no readable cwd cannot be
# placed, and a failed scan cannot be trusted, so either suppresses the roster and exits non-zero:
# respawn.ps1 stops on a fleet run that prints no JSON.
$anonymousLive = @()
$anonymousNoCwd = @()
$anonymousReadError = ''
try {
    $fresh = @(Get-AnonymousSessionRecords -Records $sessionRows -StartSkewMinutes ([int]::MaxValue) | Where-Object { $_.Fresh })
    $anonymousLive = @($fresh | ForEach-Object { $_.File })
    $anonymousNoCwd = @($fresh | Where-Object { -not $_.Cwd } | ForEach-Object { $_.File })
} catch {
    # The failure is the catch itself, never its message: an exception with an empty message must
    # still read as a failed scan (BACKLOG #5491).
    $anonymousReadError = [string]$_.Exception.Message
    if (-not $anonymousReadError) { $anonymousReadError = "$($_.Exception.GetType().FullName), with no message" }
}

$recordedSessionIds = @($records | ForEach-Object { [string](Get-RecordField $_.Rec 'sessionId') } | Where-Object { $_ })
$liveWithoutRecord = @($liveInRepo | Where-Object { -not $_.SessionId -or $recordedSessionIds -notcontains $_.SessionId })

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
# STATED LIMITS, both in the same direction a reader needs to know about:
#   1. `git ls-remote origin main` would answer the real question directly ("is my cached ref
#      current?") in about 0.7 seconds, measured. DECLINED: this script is a PURE READER a stranded
#      session runs to reconstitute a fleet, so it must work offline and unauthenticated. A network
#      round-trip per render buys accuracy by adding the failure mode the instrument exists to
#      survive. The clock is therefore a PROXY, deliberately.
#   2. `git fetch --no-write-fetch-head` refreshes the ref and writes no clock at all, so it reads
#      as no fetch ever. That one fails LOUD, via the unmeasurable stop, which is the safe direction.
#
# A CLOCK ONLY COUNTS IF IT NAMES origin's main (BACKLOG #1374 -- the limit that WAS stated here and
# is now closed). "A fetch happened" is not "origin/main was refreshed": `git fetch origin
# refs/pull/N/head`, or a fetch of another remote, bumps the mtime and leaves the ref alone. That
# reads FRESH against a stale ref, which is the dangerous direction. FETCH_HEAD answers this itself,
# because it records WHAT was fetched, one line per ref, as <sha> TAB <flag> TAB <description>:
#
#     <sha>              branch 'main' of https://github.com/MEFORORG/MessageFoundry
#     <sha> not-for-merge branch 'feature' of https://github.com/MEFORORG/MessageFoundry
#     <sha>              'refs/pull/7/head' of https://github.com/MEFORORG/MessageFoundry
#
# Measured in a sandbox 2026-09-04, one fetch form per run: `git fetch origin`, `git fetch origin
# main` and `git fetch origin refs/heads/main` ALL write `branch 'main' of <url>`, so matching that
# one line form covers a refspec given by short name or by full ref. `git fetch origin
# refs/pull/7/head` writes `'refs/pull/7/head' of <url>` -- no `branch` prefix and no mention of
# main. That is the case that used to read fresh.
#
# THE FILE IS REWRITTEN AND NOT APPENDED, so an older main line cannot be relied on to linger.
# Measured the same day: `git fetch origin main` followed by `git fetch origin refs/pull/7/head`
# left a ONE-LINE FETCH_HEAD naming only the pull ref, six seconds newer, main line gone.
#
# THE URL IS WRITTEN WITHOUT ITS `.git` SUFFIX, so a literal compare against the configured remote
# never matches. Measured: `git remote get-url origin` returned `.../remote.git` while FETCH_HEAD in
# that same clone said `.../remote`. Both sides are normalised below. The match is on a NORMALISED
# URL rather than on the remote NAME because FETCH_HEAD records the url and never the name.
#
# WHEN NOTHING QUALIFIES THIS GOES NULL rather than falling back to the newest clock. The fallback
# is the tempting line to write and it would restore the exact defect -- a pull-ref fetch reporting
# itself as origin/main's freshness. The two roads to null say DIFFERENT things and get DIFFERENT
# stops: no clock at all, versus clocks that all fetched something else. "No FETCH_HEAD exists
# anywhere in this clone" is a FALSE SENTENCE in the second case, and a reader who just ran a fetch
# would disbelieve the instrument that said it.
$mainBranch = 'main'
$originMainSha = Invoke-Git -Dir $repo -GitArgs @('rev-parse', "origin/$mainBranch")

# Both sides of the url compare go through this. Trailing separators and the `.git` suffix differ
# between what git CONFIGURES and what git WRITES, and nothing else is touched: an ssh alias and an
# https url for one repo are genuinely not comparable, and forcing them to look it would invent a
# match this instrument cannot support.
function ConvertTo-ComparableUrl([string]$u) {
    if (-not $u) { return '' }
    $s = ($u.Trim() -replace '\\', '/').TrimEnd('/')
    if ($s.EndsWith('.git', [System.StringComparison]::OrdinalIgnoreCase)) {
        $s = $s.Substring(0, $s.Length - 4)
    }
    return $s.TrimEnd('/').ToLowerInvariant()
}

# Does this FETCH_HEAD record a fetch that refreshed origin's main? The description is the THIRD
# tab-separated field, rejoined rather than indexed at [2] so a description carrying a tab cannot
# silently truncate the url being compared. An unreadable or half-written file answers "no
# evidence", which is the safe direction: it withholds the clock rather than inventing one.
function Test-FetchHeadNamesOriginMain([string]$Path, [string]$Branch, [string]$Url) {
    if (-not $Url) { return $false }
    $wanted = "branch '$Branch' of "
    try { $lines = @(Get-Content -LiteralPath $Path -EA Stop) } catch { return $false }
    foreach ($line in $lines) {
        $parts = $line -split "`t"
        if ($parts.Count -lt 3) { continue }
        $desc = ($parts[2..($parts.Count - 1)] -join "`t").Trim()
        if (-not $desc.StartsWith($wanted, [System.StringComparison]::Ordinal)) { continue }
        if ((ConvertTo-ComparableUrl $desc.Substring($wanted.Length)) -eq $Url) { return $true }
    }
    return $false
}

$originUrl = ConvertTo-ComparableUrl (Invoke-Git -Dir $repo -GitArgs @('remote', 'get-url', 'origin'))

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

$originMainFetchAgeMinutes = $null
# NEVER NULL, because this is the line a reader scans past. A blank value beside a null age is how
# the blind case passed for a healthy one; a sentence saying it could not be measured cannot.
$originMainFetchClock = 'UNMEASURABLE -- no FETCH_HEAD in this clone (see stop conditions)'
$originMainFetchStop = 'originMainFetchAgeMinutes=UNMEASURABLE -- no FETCH_HEAD exists anywhere in this clone, so this instrument CANNOT tell a fetch made seconds ago from one never made, and every landed verdict below is computed against an origin/main of UNKNOWN age. A fresh clone reads this way on purpose: `git clone` writes no FETCH_HEAD. Run `git fetch origin` -- it both refreshes the ref and makes this field measurable'
# -LiteralPath, not a glob: a checkout path may contain [ or ], and -Path would treat it as a
# wildcard and silently match nothing. Missing and unreadable both fall out as no item.
$allClocks = @($fetchClockPaths |
        ForEach-Object { Get-Item -LiteralPath $_ -EA SilentlyContinue } |
        Sort-Object LastWriteTimeUtc -Descending)
# Sorted newest-first, so the FIRST qualifying file is the newest qualifying file and the loop can
# stop there. It also means an unreadable newest clock falls through to the next one rather than
# ending the search.
$mainClock = $null
foreach ($c in $allClocks) {
    if (Test-FetchHeadNamesOriginMain $c.FullName $mainBranch $originUrl) { $mainClock = $c; break }
}
if ($null -ne $mainClock) {
    $originMainFetchAgeMinutes = [int]((Get-Date).ToUniversalTime() - $mainClock.LastWriteTimeUtc).TotalMinutes
    $originMainFetchClock = $mainClock.FullName
    $originMainFetchStop = $null
} elseif ($allClocks.Count -ge 1) {
    # The newly-closed blind spot, and it needs its OWN sentence. Telling this reader that no
    # FETCH_HEAD exists would be false on its face -- they can see the files -- and an instrument
    # caught in an obvious lie stops being read at all.
    $originMainFetchClock = "UNMEASURABLE -- $($allClocks.Count) FETCH_HEAD file(s) here, none naming origin/$mainBranch (newest: $($allClocks[0].FullName))"
    $originMainFetchStop = "originMainFetchAgeMinutes=UNMEASURABLE -- $($allClocks.Count) FETCH_HEAD file(s) exist in this clone and NOT ONE records a fetch of origin/$mainBranch. Every one of them fetched something else (a pull ref, a different remote), which bumps the clock and leaves origin/$mainBranch untouched -- so the cached ref is of UNKNOWN age no matter how recently this clone fetched. Run ``git fetch origin`` to refresh the ref and make this field measurable"
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
function Get-RecordInstantUtc($iso) {
    if (-not $iso) { return $null }
    try {
        if ($iso -is [DateTime]) {
            # A stamp with no offset parses to Kind=Unspecified, and ToUniversalTime would read it as
            # local. UTC, as the string branch below assumes.
            if ($iso.Kind -eq [DateTimeKind]::Unspecified) { return [DateTime]::SpecifyKind($iso, [DateTimeKind]::Utc) }
            return $iso.ToUniversalTime()
        }
        return [DateTimeOffset]::Parse([string]$iso, [cultureinfo]::InvariantCulture, [System.Globalization.DateTimeStyles]::AssumeUniversal -bor [System.Globalization.DateTimeStyles]::AdjustToUniversal).UtcDateTime
    } catch { return $null }
}

# For display and the fold only. Two records can share a rounded age, so ordering them reads
# Get-RecordInstantUtc instead (BACKLOG #5872).
function Get-AgeHours($utc) {
    if ($null -eq $utc) { return $null }
    return [Math]::Round(($now - $utc).TotalHours, 1)
}

# EACH RECORD'S TREE: the box its worktree and host key to now (docs/COORD-SHARED-ROOT.md, step 4).
# A record in the old path-only box of that worktree belongs to the same tree as one in the new box,
# because one session crosses the change with a record in each: seat.ps1 writes the new box only,
# while an older copy of it may still write the old one. Anything else keeps its own box.
$legacyKeyOf = @{}
foreach ($r in $records) {
    $tree = $r.Box
    # Get-RecordField, not `.PSObject.Properties.Name`: a seat record holding `{}` has no properties,
    # and that read throws under StrictMode, as the registry loops above say (BACKLOG #5491).
    $w = [string](Get-RecordField $r.Rec 'worktree')
    # A worktree that does not normalise to a path names no key; that record keeps its own box.
    try {
        if ($w -and -not $legacyKeyOf.ContainsKey($w)) { $legacyKeyOf[$w] = ConvertTo-LegacyBoxKey -Path $w }
        if ($w -and $r.Box -ceq $legacyKeyOf[$w]) {
            $tree = ConvertTo-BoxKey -Path $w -HostName (Get-CoordRecordHost $r.Rec)
        }
    } catch { $tree = $r.Box }
    $sk = [string](Get-RecordField $r.Rec 'sessionKey')
    $r | Add-Member -NotePropertyName Tree -NotePropertyValue $tree -Force
    $r | Add-Member -NotePropertyName SessionKey -NotePropertyValue $sk -Force
    $asOfUtc = Get-RecordInstantUtc (Get-RecordField $r.Rec 'asOf')
    $r | Add-Member -NotePropertyName AsOfUtc -NotePropertyValue $asOfUtc -Force
    # The session's latest instant and lifecycle; a newer legacy copy overrides them below.
    $r | Add-Member -NotePropertyName OrderUtc -NotePropertyValue $asOfUtc -Force
    $r | Add-Member -NotePropertyName LifecycleRec -NotePropertyValue $r.Rec -Force
    # A record is filed under its session key, so the file stem names a record missing the field.
    # 'nosid' is shared by every writer with no session id, so it identifies no one session.
    $identity = if ($sk) { $sk } else { [IO.Path]::GetFileNameWithoutExtension($r.File) }
    $r | Add-Member -NotePropertyName SessionIdentity -NotePropertyValue $(if ($identity -cne 'nosid') { "$tree|$identity" }) -Force
}
# Legacy-box records whose OWN SESSION has a record in the new box. The pointer census below skips
# them: the seat repairs its pointer in the new record. An older seat.ps1 may still write one, so
# the new-box record takes the instant and lifecycle of a newer copy. A different session's legacy
# record is still counted, because -ClearHandoff can still reach it.
$frozenLegacy = @{}
$newBoxRecords = [System.Collections.Generic.Dictionary[string, object]]::new([System.StringComparer]::Ordinal)
foreach ($r in $records) {
    if ($r.SessionIdentity -and $r.Box -ceq $r.Tree) { $newBoxRecords[$r.SessionIdentity] = $r }
}
foreach ($r in $records) {
    if (-not $r.SessionIdentity -or $r.Box -ceq $r.Tree -or -not $newBoxRecords.ContainsKey($r.SessionIdentity)) { continue }
    $frozenLegacy[$r.File] = $true
    $current = $newBoxRecords[$r.SessionIdentity]
    if ($null -ne $r.AsOfUtc -and ($null -eq $current.AsOfUtc -or $r.AsOfUtc -gt $current.AsOfUtc)) {
        $current.OrderUtc = $r.AsOfUtc
        $current.LifecycleRec = $r.Rec
    }
}

$rows = @()
# Seat lookups that threw. Each such seat reads POSSIBLY RUNNING, and the receipt says why.
$lookupFailures = @()
# Seat records that name no session or no worktree. Each reads POSSIBLY RUNNING unless it is
# closed, and the receipt names the file.
$incompleteRecords = @()
foreach ($r in $records) {
    $rec = $r.Rec
    # This loop reads seat-record fields through Get-RecordField, which answers `{}` under StrictMode
    # where `.PSObject.Properties.Name` throws (BACKLOG #5491), as the -Chip briefing below does.
    $wt = [string](Get-RecordField $rec 'worktree')
    $sid = [string](Get-RecordField $rec 'sessionId')
    # A record that names no session or no worktree (`{}`, `null`, or one missing either field) cannot
    # be fenced, so it reads POSSIBLY RUNNING (CLOSED when it says so), never INTERRUPTED, and on
    # this PC its fence reads UNREADABLE: nothing here can tell its session is gone, and -Chip would brief a replacement into
    # no checkout.
    $incomplete = (-not $sid) -or (-not $wt)

    # Fence state, positive answers only. There is no heartbeat on this host and registry writes are
    # event-driven, so nothing here can PROVE a session is gone -- only that it is present.
    # The fence is this PC's session registry, so it is never asked about another PC's record.
    $isHere = Test-CoordRecordIsHere $rec
    $fence = if ($isHere) { 'UNKNOWN' } else { 'NOT-CHECKABLE-HERE' }
    # The fence matches on session id alone, so a live session may have left this record's worktree.
    $liveInTree = $false
    if ($incomplete) {
        if ($isHere) { $fence = 'UNREADABLE' }
        $incompleteRecords += $r.File
    }
    elseif ($isHere -and $fenceAvailable) {
        # The seat's worktree scopes the anonymous-record veto: a fresh record naming no session in
        # THIS worktree may be this seat relaunched, so it reads POSSIBLY RUNNING, never INTERRUPTED,
        # while one in another worktree leaves this seat's own verdict alone.
        # A lookup that throws is an unevaluated fence, not a gone session: UNREADABLE reads POSSIBLY
        # RUNNING, where UNKNOWN read INTERRUPTED and invited a respawn (BACKLOG #5491).
        # The removal paths' unbounded start skew (remove.ps1, prune-merged.ps1 and the nightly removal
        # pass [int]::MaxValue to Get-WorktreeOccupancy), so a session the removal fence reads LIVE
        # never reads STALE, and so INTERRUPTED, here.
        try {
            $liveness = Get-SessionLiveness -SessionId $sid -Worktree $wt -StartSkewMinutes ([int]::MaxValue)
            $fence = $liveness.State
            if ($fence -eq 'LIVE') {
                $holder = Get-ContainingRepoWorktree (Get-NormPath ([string](Get-RecordField $liveness.Record 'cwd')))
                $liveInTree = [bool]$holder -and $holder -ceq (Get-NormPath $wt)
            }
        }
        catch {
            $fence = 'UNREADABLE'
            $lookupFailures += "$($r.File): $($_.Exception.GetType().Name) $($_.Exception.Message)"
        }
    }

    $lifecycleValue = Get-RecordField $r.LifecycleRec 'lifecycle'
    $lifecycle = if ($null -ne $lifecycleValue) { [string]$lifecycleValue } else { 'open' }
    $ageH = Get-AgeHours $r.OrderUtc

    # SUPERSEDED: a newer record of the same tree (above). Without the tree, a session that crossed
    # the box-key change reads as two seats. A frozen legacy copy is superseded outright, whichever
    # is newer; its new-box record speaks for the session at the later of their two instants, so the
    # copy itself supersedes nothing.
    # The compare reads instants, not Get-AgeHours's 0.1 h buckets (BACKLOG #5872). asOf has
    # one-second resolution, so an exact tie supersedes neither: breaking it could hide a crashed
    # seat from the respawn population.
    $superseded = $false
    foreach ($o in $records) {
        if ($o.File -eq $r.File) { continue }
        if ($o.Tree -cne $r.Tree) { continue }
        if ($frozenLegacy.ContainsKey($o.File)) { continue }
        if ($null -ne $o.OrderUtc -and $null -ne $r.OrderUtc -and $o.OrderUtc -gt $r.OrderUtc) { $superseded = $true }
    }

    $state = switch ($true) {
        { $lifecycle -eq 'closed' }                    { 'CLOSED'; break }
        # Ahead of HANDED, which respawn.ps1 respawns, and of ON <HOST>, which -Chip still briefs: an
        # incomplete record names no checkout to brief.
        { $incomplete }                                { 'POSSIBLY RUNNING'; break }
        # Ahead of HANDED and LIVE: both of a session's records would read alike, and only the new-box
        # record may speak for it, or one session shows twice.
        { $frozenLegacy.ContainsKey($r.File) }         { 'SUPERSEDED'; break }
        { $lifecycle -eq 'handed' }                    { 'HANDED'; break }
        # A newer record in this tree does not end a session still live in this tree.
        { $superseded -and -not $liveInTree }          { 'SUPERSEDED'; break }
        { -not $isHere }                               { "ON $((Get-CoordRecordHost $rec).ToUpperInvariant())"; break }
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
    if (Get-RecordField $rec 'seat') { $declared = [string](Get-RecordField $rec 'seat') }

    $rows += [pscustomobject]@{
        Box         = $r.Box
        SessionKey  = [string](Get-RecordField $rec 'sessionKey')
        Seat        = $declared
        State       = $state
        Fence       = $fence
        AgeHours    = $ageH
        WriterStale = $writerStale
        Branch      = if ($null -ne (Get-RecordField $rec 'branch')) { [string](Get-RecordField $rec 'branch') } else { $null }
        Worktree    = $wt
        Host        = Get-CoordRecordHost $rec
        IsHere      = $isHere
        Epoch       = if ($null -ne (Get-RecordField $rec 'poolEpoch')) { [int](Get-RecordField $rec 'poolEpoch') } else { $null }
        Rec         = $rec
        File        = $r.File
    }
}

# ---------------------------------------------------------------------------------------------
# The receipt, and the STOP conditions it can fire.
# ---------------------------------------------------------------------------------------------

$stops = @()
if ($unreadableRecordFiles.Count -gt 0) { $stops += "recordsUnreadable=$($unreadableRecordFiles.Count) -- these seat record(s) could not be read or parsed, so a seat they hold may be absent from the roster below and it may be INCOMPLETE by them. Causes include at least a damaged record, an unreachable share and an access denial: read each first, and move it out of the seats directory by hand only if it is damaged: $($unreadableRecordFiles -join '; ')" }
if (-not $fenceAvailable) { $stops += 'fenceAvailable=false -- no config root with a sessions/ directory was found; every state below would be a guess' }
if ($anonymousReadError) { $stops += "anonymousLiveRecords=UNREAD -- the scan for registry records that name no session failed ($anonymousReadError), so a relaunched seat could read INTERRUPTED below" }
if ($anonymousNoCwd.Count -gt 0) { $stops += "anonymousLiveRecordsWithNoCwd=$($anonymousNoCwd.Count) -- registry record(s) name no session, are live or freshly written, and name no readable cwd ($($anonymousNoCwd -join '; ')), so no seat can be told apart from a relaunch of it" }
if ($liveWithoutRecord.Count -gt 0) { $stops += "liveSessionsWithoutRecord=$($liveWithoutRecord.Count) -- live session(s) in this repo's worktrees match no seat record (the writer is not running there, or the registry record names no session yet), so this roster is INCOMPLETE by that many" }
if ($incompleteRecords.Count -gt 0) { $stops += "seatRecordsIncomplete=$($incompleteRecords.Count) -- these seat records name no session or no worktree, so they cannot be fenced; each reads POSSIBLY RUNNING unless closed, and -Chip writes no briefing for it: $($incompleteRecords -join '; ')" }
if ($lookupFailures.Count -gt 0) { $stops +="seatLookupsFailed=$($lookupFailures.Count) -- the liveness lookup threw for these seat records, which read POSSIBLY RUNNING because the fence could not be evaluated: $($lookupFailures -join '; ')" }
if ($records.Count -eq 0 -and $heartbeats.Count -eq 0) { $stops += 'recordsExamined=0 AND writerHeartbeatIn=0 -- indistinguishable from a writer that was never installed' }
# BOTH DIRECTIONS FIRE, and the null one is the reason this rung exists (BACKLOG #1374). The old
# guard was `-ne $null -and -gt 60`, so the one state where the instrument knows nothing was the one
# state it said nothing about.
if ($null -eq $originMainFetchAgeMinutes) {
    # Which of the two blind states this is was decided where the clocks were read, because that is
    # the only place that still knows. Both are UNMEASURABLE; they differ in what to DO about it.
    $stops += $originMainFetchStop
} elseif ($originMainFetchAgeMinutes -gt 60) {
    $stops += "originMainFetchAgeMinutes=$originMainFetchAgeMinutes -- the newest fetch of origin/$mainBranch anywhere in this clone was $originMainFetchAgeMinutes minutes ago; landed verdicts would be computed against a stale origin/$mainBranch"
}

# POINTER CENSUS, resolved here rather than trusted from the records. Printed as a RATIO because the
# numerator alone cannot be read: "1 dangling" is a crisis at 2 pointers and noise at 200. Measured
# 2026-08-22 the ratio was 2 broken of 3 recorded against 262 records -- the denominator is the part
# that says the mechanism is unused, and the numerator is the part that says the few uses are wrong.
$ptrTotal = 0; $ptrDangling = 0; $ptrDrifted = 0; $ptrUnreadable = 0; $ptrOtherHost = 0
$ptrBoxes = @{}
foreach ($o in $records) {
    # Through Get-RecordField: a seat record or a handoff holding `{}` has no such property, and a
    # bare read throws under StrictMode (BACKLOG #5491).
    $h = Get-RecordField $o.Rec 'handoff'
    $hPath = [string](Get-RecordField $h 'path')
    $hBytes = Get-RecordField $h 'bytes'
    if (-not $hPath) { continue }
    # Another PC's pointer names a path on that PC. Test-Path here would call it dangling and fire the
    # stop below for a document that resolves where it was written, so it is counted apart.
    if (-not (Test-CoordRecordIsHere $o.Rec)) { $ptrOtherHost++; continue }
    # A frozen legacy copy of a live seat's record; its pointer is the newer record's to answer for.
    if ($frozenLegacy.ContainsKey($o.File)) { continue }
    $ptrTotal++
    # BOXES AS WELL AS RECORDS, because ONE SEAT CAN HOLD SEVERAL RECORDS AND THE COUNTS DIVERGE.
    # A seat whose declaration landed in nosid.json and then re-declared under its session id leaves
    # BOTH records in place, each carrying the same pointer -- measured 2026-08-22, 5 pointers across
    # 4 boxes, with one box holding two records naming one file. Counting records answers "how many
    # rows carry a pointer", which is right for the per-row render below. It is the WRONG denominator
    # for "how many seats would be sent somewhere broken", and it inflates the moment anyone
    # remediates. Both are printed so a reader can see 5-across-4 rather than inferring 5 seats.
    $ptrBoxes[$o.Tree] = $true
    try {
        if (-not (Test-Path -LiteralPath $hPath -PathType Leaf)) { $ptrDangling++ }
        elseif ($null -ne $hBytes -and [long]$hBytes -ne (Get-Item -LiteralPath $hPath -EA Stop).Length) { $ptrDrifted++ }
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
    thisHost                  = $thisHost
    recordsOtherHost          = @($rows | Where-Object { -not $_.IsHere }).Count
    rootsExamined             = $rootsExamined
    fenceAvailable            = $fenceAvailable
    recordsExamined           = $records.Count
    recordsUnreadable         = $unreadableRecordFiles.Count
    seatRecordsIncomplete     = $incompleteRecords.Count
    liveSessionsInRepo        = $liveInRepo.Count
    liveSessionsWithoutRecord = $liveWithoutRecord.Count
    # Null, not 0, when the scan failed: an unmeasured count must not read as none.
    anonymousLiveRecords      = if ($anonymousReadError) { $null } else { $anonymousLive.Count }
    anonymousLiveRecordFiles  = if ($anonymousReadError) { "the scan failed: $anonymousReadError" } elseif ($anonymousLive.Count) { $anonymousLive -join '; ' } else { 'none' }
    writerHeartbeatIn        = $heartbeats.Count
    writerErrorLines          = $writerErrors
    repoWorktrees             = $repoWorktrees.Count
    originMainSha             = $originMainSha
    # NAMED FOR THE QUESTION IT ANSWERS, and it has now been renamed TWICE for the same reason, so
    # the rule is worth stating plainly: this key must say origin/main, because that is the ref the
    # verdicts below are computed against.
    #   `originMainAgeMinutes` (first) claimed fetch recency and timed the REF FILE.
    #   `lastFetchAgeMinutes` (second) timed a real fetch, but ANY fetch. It was literally accurate
    #   and still wrong in the case that matters: with a pull-ref fetch one minute old beside a main
    #   fetch three hours old, the honest value of THIS field is 180, which the name `lastFetch`
    #   contradicts. A name that fights its own value is how this item started.
    # Nothing outside docs/BACKLOG.md and this script's own test ever read either key by name --
    # checked with `originMainSha` as the positive control that the search could see the files -- so
    # each was renamed rather than doubled. A consumer pinned to an old key now finds no key at all,
    # which is the honest failure.
    originMainFetchAgeMinutes = $originMainFetchAgeMinutes
    originMainFetchClock      = $originMainFetchClock
    handoffPointers           = $ptrTotal
    handoffPointerSeats       = $ptrBoxes.Count
    handoffPointersDangling   = $ptrDangling
    handoffPointersDrifted    = $ptrDrifted
    handoffPointersUnreadable = $ptrUnreadable
    handoffPointersOtherHost  = $ptrOtherHost
    stopConditions            = @($stops)
}

# ---------------------------------------------------------------------------------------------
# Render.
# ---------------------------------------------------------------------------------------------

# ROSTER SUPPRESSED, exit 4, for the two conditions under which no seat can be told apart from a
# relaunch of itself. Nothing goes to stdout in any mode, so -Chip writes no replacement briefing and
# respawn.ps1, which stops on a fleet run with no parseable JSON, sends nobody. The stops go to stderr.
if ($anonymousReadError -or $anonymousNoCwd.Count -gt 0) {
    [Console]::Error.WriteLine('fleet.ps1: ROSTER SUPPRESSED (exit 4). A confident roster here could send a replacement seat into a worktree a live session holds:')
    foreach ($s in $stops) { [Console]::Error.WriteLine("  - $s") }
    exit 4
}

if ($Chip) {
    $row = $rows | Where-Object { $_.Box -eq $BoxKey -and $_.SessionKey -eq $SessionKey } | Select-Object -First 1
    if (-not $row) { Write-Error "fleet.ps1: no record for $BoxKey/$SessionKey"; exit 2 }
    # No briefing, so no `git -C ""` command, for a record that names no session or no worktree.
    # stderr directly: under this file's 'Stop' preference Write-Error throws, and the exit code
    # would be 1, not 2.
    if ($incompleteRecords -contains $row.File) {
        [Console]::Error.WriteLine("fleet.ps1: no briefing for $BoxKey/$SessionKey -- its seat record names no session or no worktree, so it cannot be fenced: $($row.File)")
        exit 2
    }
    $rec = $row.Rec
    # Every field is read through Get-RecordField: a seat record missing one has no such property,
    # and a bare read throws under this script's StrictMode Latest (BACKLOG #5491).
    $asOf = Get-RecordField $rec 'asOf'
    $recWt = [string](Get-RecordField $rec 'worktree')
    $tip = Get-RecordField $rec 'tip'
    $seatName = Get-RecordField $rec 'seat'
    $goal = Get-RecordField $rec 'goal'
    $done = Get-RecordField $rec 'done'
    $outOfScope = Get-RecordField $rec 'outOfScope'
    $stashSha = Get-RecordField $rec 'stashSha'
    $touchedPaths = Get-RecordField $rec 'touchedPaths'
    $handoff = Get-RecordField $rec 'handoff'
    $hp = [string](Get-RecordField $handoff 'path')
    $lines = @()
    $lines += "You are a REPLACEMENT SEAT. The session that held this work is gone. You inherit NOTHING"
    $lines += "from it except what is written below. Everything here was measured at $asOf and the"
    $lines += "world has moved since -- RE-VERIFY BEFORE YOU ACT, do not trust a line because it is specific."
    $lines += ""
    $lines += "PREDECESSOR CHECKOUT: $recWt"
    if (-not $row.IsHere) {
        $lines += "RECORDED ON $($row.Host.ToUpperInvariant()), NOT THIS PC ($thisHost). That checkout and any handoff path"
        $lines += "below are on that PC, and nothing here could check them. Run the git steps there."
    }
    $lines += "BRANCH: $($row.Branch)   (identified by NAME, never by a commit id -- a rebase reissues the id)"
    if ($tip) { $lines += "ITS TIP WAS: $tip  AS OF $asOf. Resolve the branch yourself; do not use this id as an identifier." }
    $lines += ""
    if ($seatName) { $lines += "SEAT: $seatName" } else { $lines += "SEAT: NOT DECLARED. The predecessor never declared one; do not invent a role." }
    if ($goal) { $lines += "GOAL AS DECLARED: $goal" } else { $lines += "GOAL: NOT DECLARED." }
    if ($done) { $lines += "DONE MEANS: $done" }
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
    $untracked = @(Get-RecordField (Get-RecordField $rec 'dirty') 'untracked' | Where-Object { $null -ne $_ })
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
    if ($touchedPaths -and @($touchedPaths).Count -gt 0) {
        $lines += "       git diff --name-only origin/main $($row.Branch) -- " + (@($touchedPaths) -join ' ')
        $lines += "     Empty output means the content is already on main. DO NOT REBUILD IT."
    } else {
        $lines += "       (no touched paths were recorded, so this check is UNCHECKABLE here -- derive the"
        $lines += "        pathspec yourself from the branch's merge-base before concluding anything)"
    }
    $lines += "  3. Re-check claims and allocations BEFORE taking any. This briefing was written at generate"
    $lines += "     time and you are reading it at click time; a hold may have been declared in between."
    $claims = @(Get-RecordField $rec 'claims' | Where-Object { $null -ne $_ })
    $ownClaims = @($claims | Where-Object { (Get-RecordField $_ 'attribution') -eq 'this-episode' })
    $inhClaims = @($claims | Where-Object { (Get-RecordField $_ 'attribution') -ne 'this-episode' })
    if ($ownClaims.Count -gt 0) { $lines += "     CLAIMS HELD BY THE PREDECESSOR EPISODE: " + (($ownClaims | ForEach-Object { Get-RecordField $_ 'key' }) -join ', ') }
    else { $lines += "     CLAIMS HELD BY THE PREDECESSOR EPISODE: none" }
    if ($inhClaims.Count -gt 0) {
        $lines += "     ALSO PRESENT IN THAT WORKTREE BUT FROM EARLIER OCCUPANTS -- NOT YOURS, DO NOT REHOME:"
        $lines += "       " + (($inhClaims | ForEach-Object { Get-RecordField $_ 'key' }) -join ', ')
    }
    $allocs = @(Get-RecordField $rec 'allocations' | Where-Object { $null -ne $_ })
    $ownAlloc = @($allocs | Where-Object { (Get-RecordField $_ 'attribution') -eq 'this-episode' })
    $inhAlloc = @($allocs | Where-Object { (Get-RecordField $_ 'attribution') -ne 'this-episode' })
    if ($ownAlloc.Count -gt 0) { $lines += "     LEDGER NUMBERS ALLOCATED BY THIS EPISODE: " + (($ownAlloc | ForEach-Object { "$(Get-RecordField $_ 'kind') #$(Get-RecordField $_ 'number')" }) -join ', ') }
    else { $lines += "     LEDGER NUMBERS ALLOCATED BY THIS EPISODE: none" }
    if ($inhAlloc.Count -gt 0) {
        $lines += "     $($inhAlloc.Count) MORE are allocated to that worktree PATH by earlier occupants."
        $lines += "     THEY ARE NOT YOURS. Do not rehome them and do not cite them."
    }
    if ($hp) {
        $lines += ""
        $lines += "  4. READ THE HANDOFF: $hp"
        # RESOLVED HERE, AT RENDER, NOT READ OUT OF THE RECORD. seat.ps1 re-checks the pointer on
        # every Stop, which covers a LIVE seat -- but the pointer most likely to be wrong belongs to
        # a seat that will never run again, and a dead seat's writer cannot report its own decay.
        # Measured 2026-08-22: the one DANGLING pointer on disk belongs to nice-payne-4dcee0, whose
        # last turn ended 2026-08-19. Only a reader was ever going to catch it.
        $live = $null
        try { if ($row.IsHere -and (Test-Path -LiteralPath $hp -PathType Leaf)) { $live = (Get-Item -LiteralPath $hp -EA Stop).Length } }
        catch { $live = $null }
        $wasBytes = Get-RecordField $handoff 'bytes'
        if (-not $row.IsHere) {
            $lines += "     NOT CHECKED: that path is on $($row.Host). Open it there."
        }
        elseif ($null -eq $live) {
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
        rows    = @($rows | Select-Object Box, SessionKey, Seat, State, Fence, AgeHours, WriterStale, Branch, Worktree, Host, Epoch,
            @{n = 'HandoffPath'; e = { $h = Get-RecordField $_.Rec 'handoff'; if ($h) { [string](Get-RecordField $h 'path') } else { $null } } },
            @{n = 'HandoffState'; e = {
                    $h = Get-RecordField $_.Rec 'handoff'
                    $hPath = [string](Get-RecordField $h 'path')
                    $hBytes = Get-RecordField $h 'bytes'
                    if (-not $hPath) { return $null }
                    if (-not $_.IsHere) { return 'not-checkable-here' }
                    try {
                        if (-not (Test-Path -LiteralPath $hPath -PathType Leaf)) { return 'dangling' }
                        if ($null -ne $hBytes -and [long]$hBytes -ne (Get-Item -LiteralPath $hPath -EA Stop).Length) { return 'drifted' }
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
    # (`originMainFetchClock`), because "(null)" cannot tell anyone to run `git fetch origin`.
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
"  Never respawned: RUNNING, POSSIBLY RUNNING, SUPERSEDED, CLOSED, ON <HOST> (another PC's seat)."
"  Briefing for one row:  fleet.ps1 -Chip -BoxKey <box> -SessionKey <key>"

$code = if ($fenceAvailable) { 0 } else { 2 }
exit $code

