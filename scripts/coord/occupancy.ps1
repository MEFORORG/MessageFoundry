<#
.SYNOPSIS
    Which worktree is each live session sitting in -- the shared occupancy matcher.

.DESCRIPTION
    Dot-source this; it defines functions and does nothing on its own.

        . "$PSScriptRoot\occupancy.ps1"
        $occ = Get-WorktreeOccupancy -Repo $RepoRoot -ConfigRoot $ConfigRoot
        if (-not $occ.Available) { <refuse to do anything destructive> }
        $who = Get-WorktreeOccupants -Occupancy $occ -Path $candidate   # veto-worthy rows only

    ONE COPY OF THE MATCHER, ON PURPOSE. presence.ps1 (a read-only roster) and prune-merged.ps1 (which
    DELETES a worktree and its branch) must answer "is somebody in this checkout" identically. Two
    copies of a safety check drift, and the copy that drifts is the one nobody is testing -- so the
    matcher lives here and the liveness fence itself lives one level down in session-registry.ps1.

    AVAILABILITY IS PART OF THE ANSWER, NOT AN ABSENCE OF ONE.
    ---------------------------------------------------------
    "The fence ran and nobody is here" and "the fence could not look" produce the SAME empty row set,
    so an empty list must never be read as a green light. This returns a RECEIPT alongside the rows --
    RootsExamined / RecordsExamined / RecordsUnplaceable -- and sets Available only when there was
    something to examine: at least one config root holding a session registry, at least one readable
    record in it, AND no record that could not be PLACED. A caller about to destroy something must gate
    on Available, print the receipt, and refuse when it is false. Count what you EXAMINED, not what you
    found.

    AN UNPLACEABLE RECORD MAKES THE WHOLE FENCE UNAVAILABLE. Two shapes qualify -- a file that will not
    parse, and a record that parses but carries no cwd -- and BOTH used to be dropped on the floor by a
    silent `continue`, so they appeared in no count at all. Neither can be attributed to, or cleared
    from, any particular worktree: it could be a session sitting in the very tree the caller is about to
    delete. A file caught HALF-WRITTEN is exactly this shape, which makes it the signature of a session
    that launched seconds ago. Refusing the whole run is the only answer that cannot destroy one; the
    remedy is to look at the named file and re-run.

    RecordsExamined and RecordsUnplaceable deliberately OVERLAP: the first counts what parsed, the
    second counts what cannot be placed, and a cwd-less record is both.

    ONLY A POSITIVE ANSWER IS TRUSTWORTHY (see session-registry.ps1). There is no heartbeat on this
    host, so nothing here can prove a session is GONE. Occupancy may therefore only ever VETO an
    action; a DEAD/STALE/absent verdict must never by itself authorise one.

    THREE SOURCES, COMPOSED. Each is opt-in, has its own receipt, and tags its own rows:
      * the recorded cwd (this file) -- where a session was LAUNCHED;
      * -IncludeFootprints (footprint.ps1) -- where a session has actually WRITTEN;
      * -IncludePins (pin.ps1) -- where a HUMAN has declared they are working, which is the only one
        that can see a writer who is not a Claude tool call at all.
    Availability is ANDed (any source failing to look refuses the whole run) and vetoes are ORed (any
    source seeing somebody stops the removal); reasons only ever append. Each source keeps its OWN
    examined/found counters, so nobody can read coverage from one as coverage from another -- the
    specific way a multi-signal fence quietly collapses into one.

    WHAT THE CWD SOURCE CANNOT SEE -- state this wherever it is consumed:
      * A session that writes into a worktree BY ABSOLUTE PATH from somewhere else. Records carry the
        cwd a session was launched in and nothing ever rewrites it, so a workflow that fans subagents
        into N sibling worktrees is represented by ONE record carrying ONE cwd. Measured 2026-07-30 on
        this repo: of the writes landing in a `<primary>-<slug>` sibling, 88.9% came from a session
        whose recorded cwd was a different checkout, and this source placed a session inside ZERO of the
        four siblings that then existed -- including the one a live session was demonstrably building
        in. That is what -IncludeFootprints exists for; this source alone is not enough.
      * A cwd recorded as a UNC path (\\host\C$\...) or an 8.3 short path: the match is a string
        compare on the normalised path, and neither spelling normalises to the worktree's own. (The
        footprint source resolves through .git instead and does not share this blind spot.)
      * A session that never registered at all.
    It DOES see VS Code sessions -- <config-root>/sessions/<pid>.json is the only registry carrying
    every surface (the Desktop app's own session tooling lists just what it spawned). The match is
    purely path-based, so the launching surface is irrelevant to it.

    NESTED WORKTREES. `EnterWorktree`/new.ps1 put worktrees at <checkout>/.claude/worktrees/<slug>, so
    a worktree can live INSIDE another one. Get-WorktreeOccupancy attributes a session to the LONGEST
    matching worktree, which is right for a roster (report the innermost checkout) and wrong for a
    destructive caller: a session in the nested tree does not then veto its ANCESTOR, whose --force
    removal deletes the nested tree with it. Get-WorktreeOccupants -IncludeNested folds descendants in
    for that reason, and Get-NestedWorktrees lists them so a caller can refuse outright.
#>

# The liveness fence, shared with presence.ps1 and sessions.ps1. (footprint.ps1 dot-sources it too;
# PowerShell re-sourcing is idempotent, and the shared ConvertTo-Norm comes from it.)
. "$PSScriptRoot\session-registry.ps1"
# The write-footprint source, used only under -IncludeFootprints.
. "$PSScriptRoot\footprint.ps1"
# Declared occupancy (a human said so), used only under -IncludePins.
. "$PSScriptRoot\pin.ps1"

# States that must VETO a destructive action: the session is live, or we could not tell that it isn't.
# DEAD/STALE are deliberately absent -- they are not a veto, and they are not permission either.
# UNREGISTERED is only ever produced by the footprint source (a session that wrote here and has no
# registry record); it vetoes for the same reason UNREADABLE does -- the fence could not be evaluated,
# and an unevaluated fence is not a passed fence. PINNED comes from the pin source and is a
# DECLARATION rather than a liveness verdict -- kept as its own state so a reader cannot mistake a
# human saying "I am working here" for a process that was fenced.
$script:OccupancyVetoStates = @('LIVE', 'UNVERIFIED', 'UNREADABLE', 'UNREGISTERED', 'PINNED')

function Test-OccupancyVeto {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$State)
    return ($script:OccupancyVetoStates -contains $State)
}

# ConvertTo-Norm now lives in session-registry.ps1, dot-sourced above: footprint.ps1 has to answer "is
# this path inside that worktree" exactly as this file does, and the only way to guarantee that is one
# copy at the bottom of the stack.

# Every worktree sharing one .git. Keyed on the worktree SET rather than a single path, because the
# whole point is seeing siblings, not just yourself.
function Get-RepoWorktrees([string]$RepoHint) {
    $gitArgs = @()
    if ($RepoHint) { $gitArgs = @("-C", $RepoHint) }
    $porcelain = & git @gitArgs worktree list --porcelain 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $porcelain) { return @() }
    $out = @()
    $cur = $null
    foreach ($line in $porcelain) {
        if ($line -like "worktree *") {
            $cur = [pscustomobject]@{
                Path = $line.Substring(9).Trim(); Branch = ""
                Bare = $false; Detached = $false; Locked = $false; LockReason = ""; Prunable = ""
            }
            $out += $cur
        }
        elseif ($line -like "branch *" -and $cur) {
            $cur.Branch = ($line.Substring(7).Trim() -replace '^refs/heads/', '')
        }
        elseif ($line -like "detached*" -and $cur) {
            $cur.Branch = "(detached)"
            $cur.Detached = $true
        }
        elseif ($line -eq "bare" -and $cur) { $cur.Bare = $true }
        # `locked` and `locked <reason>` are git's OWN occupancy flag, and the one thing a single
        # `worktree remove --force` will not override. Dropping it on the floor (as the parser here
        # used to) means a worktree that explicitly said "in use" is still attempted.
        elseif ($line -like "locked*" -and $cur) {
            $cur.Locked = $true
            if ($line.Length -gt 7) { $cur.LockReason = $line.Substring(7).Trim() }
        }
        elseif ($line -like "prunable*" -and $cur) {
            $cur.Prunable = if ($line.Length -gt 9) { $line.Substring(9).Trim() } else { "prunable" }
        }
    }
    return $out
}

<#
Map every session record onto the worktree it was launched in, fenced for liveness, with a receipt.

Returns a pscustomobject:
    RepoFound        [bool]   the -Repo hint resolved to a git repo at all
    Available        [bool]   BOTH sources had something to examine (see the header)
    Detail           [string] why it is unavailable, '' when it is available
    RootsExamined     [int]    config roots holding a sessions registry
    RecordsExamined   [int]    records that PARSED across those roots
    RecordsUnplaceable[int]    records that will not parse or carry no cwd -- any at all => Available false
    UnplaceableFiles  [array]  each one's path and why, so the operator can go and look
    Worktrees         [array]  every worktree of this .git (Path/Branch/Locked/LockReason/...)
    PrimaryPath       [string] the trunk checkout (git reports it first)
    Sessions          [array]  veto-worthy rows from BOTH sources, each tagged with its Source
                               ('cwd' or 'footprint'). The cwd rows are one per record placed by its
                               recorded cwd; the footprint rows are one per (session, worktree) pair
                               with a write inside the window.
    FootprintsIncluded[bool]   whether the second source ran at all
    Footprint         [object] its full receipt (see footprint.ps1), or $null
#>
function Get-WorktreeOccupancy {
    [CmdletBinding()]
    param(
        [string]$Repo,
        [string[]]$ConfigRoot,
        [int]$StartSkewMinutes = 15,
        # Add the write-footprint source. Off by default: the read-only roster callers want "where is
        # each session sitting", and one of them runs in a SessionStart hook where a corpus scan is
        # both the wrong question and the wrong cost. Anything DESTRUCTIVE must pass it.
        [switch]$IncludeFootprints,
        [double]$FootprintHours = 36,
        # Add declared occupancy (pin.ps1). Off by default for the same reason as above.
        [switch]$IncludePins
    )

    $worktrees = @(Get-RepoWorktrees $Repo)
    if ($worktrees.Count -eq 0) {
        return [pscustomobject]@{
            RepoFound = $false; Available = $false
            Detail = 'not inside a git repository -- nothing to scope occupancy to'
            RootsExamined = 0; RecordsExamined = 0; RecordsUnplaceable = 0; UnplaceableFiles = @()
            Worktrees = @(); PrimaryPath = ''; Sessions = @()
            FootprintsIncluded = [bool]$IncludeFootprints; Footprint = $null
            PinsIncluded = [bool]$IncludePins; PinSet = $null
        }
    }

    $wtIndex = @{}
    foreach ($w in $worktrees) { $wtIndex[(ConvertTo-Norm $w.Path)] = $w }
    # The primary (trunk) checkout is the first entry git reports.
    $primaryPath = $worktrees[0].Path
    $primaryNorm = ConvertTo-Norm $primaryPath

    $roots = @()
    $all = @()
    try {
        $roots = @(Get-ClaudeConfigRoots -ConfigRoot $ConfigRoot)
        # ONE enumeration, faults included: reading the directory twice would let a record appear
        # between the passes and be counted in neither.
        $all = @(Get-SessionRecords -ConfigRoot $ConfigRoot -IncludeUnreadable)
    }
    catch {
        # An unreadable registry is an unavailable fence, never an empty one.
        return [pscustomobject]@{
            RepoFound = $true; Available = $false
            Detail = "session registry unreadable: $($_.Exception.Message)"
            RootsExamined = $roots.Count; RecordsExamined = 0; RecordsUnplaceable = 0; UnplaceableFiles = @()
            Worktrees = $worktrees; PrimaryPath = $primaryPath; Sessions = @()
            FootprintsIncluded = [bool]$IncludeFootprints; Footprint = $null
            PinsIncluded = [bool]$IncludePins; PinSet = $null
        }
    }
    $records = @($all | Where-Object { -not $_.Unreadable })
    # UNPLACEABLE, which is a superset of unparseable: a record that parses but carries no cwd cannot be
    # attributed to -- or ruled out of -- any worktree either, and it used to be dropped by a bare
    # `continue`. The two counters deliberately overlap: RecordsExamined counts what PARSED,
    # RecordsUnplaceable counts what cannot be PLACED, and a cwd-less record is both.
    $faults = @($all | Where-Object { $_.Unreadable } |
            ForEach-Object { [pscustomobject]@{ File = $_.File; Why = "unparseable: $($_.Error)" } })
    $placeable = @()
    foreach ($e in $records) {
        if (-not $e.Record.cwd) {
            $faults += [pscustomobject]@{ File = $e.File; Why = 'no cwd in the record, so it cannot be placed in any worktree' }
        }
        else { $placeable += $e }
    }

    $available = $false
    $detail = ''
    if ($roots.Count -eq 0) {
        $detail = 'no Claude config root with a session registry was found (looked for <userprofile>\.claude*\sessions)'
    }
    elseif ($faults.Count -gt 0) {
        # See the header: an unplaceable record could name ANY worktree, so it clears none of them, and
        # a half-written file is what a session that just launched looks like.
        $detail = "$($faults.Count) session record(s) could not be placed, so the roster is incomplete and no worktree can be cleared: $(($faults | ForEach-Object { "$($_.File) ($($_.Why))" }) -join '; ')"
    }
    elseif ($records.Count -eq 0) {
        $detail = "$($roots.Count) config root(s) examined, but not one readable session record in them"
    }
    else { $available = $true }

    $sessions = @()
    foreach ($entry in $placeable) {
        $rec = $entry.Record

        # Scope: cwd inside one of this repo's worktrees. Exact match on the worktree root, or a
        # descendant of it -- a session cd'd into a subdirectory is still that worktree's session.
        # LONGEST match wins, or a nested worktree (.claude/worktrees/x) folds into the primary and
        # gets reported as colliding in a checkout it is nowhere near.
        $cwdNorm = ConvertTo-Norm $rec.cwd
        $match = $null
        foreach ($k in $wtIndex.Keys) {
            if ($cwdNorm -eq $k -or $cwdNorm.StartsWith("$k/")) {
                if (-not $match -or $k.Length -gt (ConvertTo-Norm $match.Path).Length) { $match = $wtIndex[$k] }
            }
        }
        if (-not $match) { continue }

        # A record we cannot even evaluate (e.g. a non-numeric pid, which throws in the fence) must
        # VETO, not vanish and not crash the caller. UNREADABLE is in the veto set for that reason.
        $live = $null
        try { $live = Test-RecordLiveness -Record $rec -StartSkewMinutes $StartSkewMinutes }
        catch { $live = @{ State = "UNREADABLE"; Detail = "record could not be fenced: $($_.Exception.Message)" } }

        $matchNorm = ConvertTo-Norm $match.Path
        $sid = [string]$rec.sessionId
        # A non-numeric pid is exactly the record that throws above; keep it reportable rather than
        # letting the cast take the whole caller down.
        $recPid = 0
        try { $recPid = [int]$rec.pid } catch { $recPid = 0 }
        $sessions += [pscustomobject]@{
            # Which SOURCE placed this row. The two are never merged into one number anywhere: a fence
            # that reports a single "vetoed N" cannot show that one of its signals has gone to zero.
            Source       = 'cwd'
            State        = $live.State
            Detail       = $live.Detail
            SessionId    = $sid
            Short        = if ($sid) { $sid.Substring(0, [Math]::Min(8, $sid.Length)) } else { "?" }
            Pid          = $recPid
            Cwd          = [string]$rec.cwd
            Entrypoint   = [string]$rec.entrypoint
            Kind         = [string]$rec.kind
            Root         = $entry.Root
            StartedAt    = if ($null -ne $rec.startedAt) { [DateTimeOffset]::FromUnixTimeMilliseconds([int64]$rec.startedAt).LocalDateTime.ToString("o") } else { "" }
            WorktreePath = $match.Path
            Worktree     = if ($matchNorm -eq $primaryNorm) { "primary" } else { Split-Path $match.Path -Leaf }
            IsPrimary    = ($matchNorm -eq $primaryNorm)
            Branch       = $match.Branch
            # Footprint-only columns, present on every row so the two shapes are interchangeable.
            Writes       = 0
            LastWriteAt  = ''
            CrossTree    = $false
            PlacedBy     = 'cwd'
        }
    }

    # --- Source 2: where sessions have actually WRITTEN ------------------------------------------
    # ANDed on availability, ORed on vetoes, reasons appended. A source that could not look refuses the
    # whole run; a source that looked and saw nobody adds nothing and says so in its own receipt.
    $fp = $null
    if ($IncludeFootprints) {
        try {
            $fp = Get-WorktreeFootprints -Worktrees $worktrees -ConfigRoot $ConfigRoot `
                -WindowHours $FootprintHours -StartSkewMinutes $StartSkewMinutes
        }
        catch {
            # An exception in the scanner is "could not look", never "nobody is here".
            $fp = [pscustomobject]@{
                Available = $false
                Detail = "the write-footprint scan threw: $($_.Exception.GetType().Name)"
                Note = ''; WindowHours = $FootprintHours
                RootsExamined = 0; RootsWithCorpus = 0
                TranscriptsFound = 0; TranscriptsInWindow = 0; TranscriptsWithNeedle = 0
                BytesScanned = [long]0; LinesScanned = 0; LinesParsed = 0; PathBlocksExamined = 0
                WritesExamined = 0; WritesOutsideWindow = 0; WritesUndated = 0
                WritesPlaced = 0; WritesUnplaced = 0
                PlacedByPrefix = 0; PlacedByGitdir = 0; GitdirProbes = 0; GitdirUnresolvable = 0
                SidechainFiles = 0; SidechainLines = 0; SidechainPathBlocks = 0
                CrossTreeWrites = 0; Faults = @(); Footprints = @()
            }
        }
        $sessions += @($fp.Footprints)
        if (-not $fp.Available) {
            $available = $false
            $detail = if ($detail) { "$detail; write-footprint source: $($fp.Detail)" } else { "write-footprint source: $($fp.Detail)" }
        }
    }

    # --- Source 3: declared occupancy -------------------------------------------------------------
    # The only source that can see a writer who is not a Claude tool call at all.
    $pins = $null
    if ($IncludePins) {
        try { $pins = Get-WorktreePins -Worktrees $worktrees -Repo $Repo }
        catch {
            $pins = [pscustomobject]@{
                Available = $false
                Detail = "the pin store read threw: $($_.Exception.GetType().Name)"
                Note = ''; Dir = ''
                PinsExamined = 0; PinsUnreadable = 0; PinsExpired = 0; PinsUnplaceable = 0
                Faults = @(); Pins = @()
            }
        }
        $sessions += @($pins.Pins)
        if (-not $pins.Available) {
            $available = $false
            $detail = if ($detail) { "$detail; pin source: $($pins.Detail)" } else { "pin source: $($pins.Detail)" }
        }
    }

    return [pscustomobject]@{
        RepoFound = $true; Available = $available; Detail = $detail
        RootsExamined = $roots.Count; RecordsExamined = $records.Count
        RecordsUnplaceable = $faults.Count
        UnplaceableFiles = @($faults | ForEach-Object { "$($_.File) -- $($_.Why)" })
        Worktrees = $worktrees; PrimaryPath = $primaryPath; Sessions = @($sessions)
        FootprintsIncluded = [bool]$IncludeFootprints; Footprint = $fp
        PinsIncluded = [bool]$IncludePins; PinSet = $pins
    }
}

# The rows that must VETO an action against $Path. Veto-worthy states only; DEAD/STALE are dropped
# here so no caller can mistake them for permission.
#
# -IncludeNested also returns sessions attributed to a worktree nested INSIDE $Path. A roster wants the
# innermost attribution (that is where the session actually is); anything about to delete $Path wants
# the ancestor vetoed too, because `worktree remove --force` on a parent takes the nested tree with it
# and leaves it registered-but-gone -- the exact orphan state this whole fence exists to prevent.
function Get-WorktreeOccupants {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Occupancy,
        [Parameter(Mandatory)][string]$Path,
        [switch]$IncludeNested
    )
    $norm = ConvertTo-Norm $Path
    return @($Occupancy.Sessions | Where-Object {
            $wt = ConvertTo-Norm $_.WorktreePath
            (Test-OccupancyVeto $_.State) -and
            ($wt -eq $norm -or ($IncludeNested -and $wt.StartsWith("$norm/")))
        })
}

# Registered worktrees living INSIDE $Path (excluding $Path itself). A worktree that contains another
# one is never safe to remove: git deletes the parent's tree, the nested checkout goes with it, and the
# nested worktree stays registered while its directory no longer exists.
function Get-NestedWorktrees {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Occupancy,
        [Parameter(Mandatory)][string]$Path
    )
    $norm = ConvertTo-Norm $Path
    return @($Occupancy.Worktrees | Where-Object {
            $p = ConvertTo-Norm $_.Path
            $p -ne $norm -and $p.StartsWith("$norm/")
        })
}

# The inverse: registered worktrees that CONTAIN $Path. A caller enumerating candidates by name prefix
# needs this, because `<primary>-pins/.claude/worktrees/x` also starts with `<primary>-` and so passed a
# prefix test as a candidate in its own right -- the nested tree being, by construction, where a live
# session was just relocated to. Nesting under the PRIMARY was excluded only by the accident that
# `<primary>/` is not `<primary>-`.
function Get-ContainingWorktrees {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][object]$Occupancy,
        [Parameter(Mandatory)][string]$Path
    )
    $norm = ConvertTo-Norm $Path
    return @($Occupancy.Worktrees | Where-Object {
            $p = ConvertTo-Norm $_.Path
            $p -ne $norm -and $norm.StartsWith("$p/")
        })
}
