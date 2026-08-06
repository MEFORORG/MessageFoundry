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

    WHAT IT CANNOT SEE -- state this wherever it is consumed:
      * A session that writes into a worktree BY ABSOLUTE PATH from somewhere else. Records carry the
        cwd a session was launched in, and measurement on this repo says 29% of writes come from a
        session sitting in the primary and land in a sibling worktree. Those are invisible here, so a
        cwd-keyed fence alone is not sufficient protection for a destructive action. Measured
        2026-07-30 on this repo: 5 live sessions, 9 worktrees, and ZERO of the four `<primary>-<slug>`
        siblings drew a veto -- including the one a session was demonstrably building in. A caller that
        destroys things needs a second, non-cwd signal; this one alone is not enough.
      * A cwd recorded as a UNC path (\\host\C$\...) or an 8.3 short path: the match is a string
        compare on the normalised path, and neither spelling normalises to the worktree's own.
      * A session that never registered at all.
    It DOES see VS Code sessions -- <config-root>/sessions/<pid>.json is the only registry carrying
    every surface (the Desktop app's own session tooling lists just what it spawned). The match is
    purely path-based, so the launching surface is irrelevant to it.

    NESTED WORKTREES. `EnterWorktree` puts worktrees at <checkout>/.claude/worktrees/<slug> (new.ps1
    makes SIBLINGS, <repo-parent>/<repo-name>-<Name>), so
    a worktree can live INSIDE another one. Get-WorktreeOccupancy attributes a session to the LONGEST
    matching worktree, which is right for a roster (report the innermost checkout) and wrong for a
    destructive caller: a session in the nested tree does not then veto its ANCESTOR, whose --force
    removal deletes the nested tree with it. Get-WorktreeOccupants -IncludeNested folds descendants in
    for that reason, and Get-NestedWorktrees lists them so a caller can refuse outright.
#>

# The liveness fence, shared with presence.ps1 and sessions.ps1.
. "$PSScriptRoot\session-registry.ps1"

# States that must VETO a destructive action: the session is live, or we could not tell that it isn't.
# DEAD/STALE are deliberately absent -- they are not a veto, and they are not permission either.
$script:OccupancyVetoStates = @('LIVE', 'UNVERIFIED', 'UNREADABLE')

function Test-OccupancyVeto {
    [CmdletBinding()]
    param([Parameter(Mandatory)][AllowEmptyString()][string]$State)
    return ($script:OccupancyVetoStates -contains $State)
}

function ConvertTo-Norm([string]$p) {
    if (-not $p) { return "" }
    return ($p -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

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
    Available        [bool]   the fence had something to examine (see the header)
    Detail           [string] why it is unavailable, '' when it is available
    RootsExamined     [int]    config roots holding a sessions registry
    RecordsExamined   [int]    records that PARSED across those roots
    RecordsUnplaceable[int]    records that will not parse or carry no cwd -- any at all => Available false
    UnplaceableFiles  [array]  each one's path and why, so the operator can go and look
    Worktrees         [array]  every worktree of this .git (Path/Branch/Locked/LockReason/...)
    PrimaryPath       [string] the trunk checkout (git reports it first)
    Sessions          [array]  one row per record whose cwd falls inside one of those worktrees
#>
function Get-WorktreeOccupancy {
    [CmdletBinding()]
    param(
        [string]$Repo,
        [string[]]$ConfigRoot,
        [int]$StartSkewMinutes = 15
    )

    $worktrees = @(Get-RepoWorktrees $Repo)
    if ($worktrees.Count -eq 0) {
        return [pscustomobject]@{
            RepoFound = $false; Available = $false
            Detail = 'not inside a git repository -- nothing to scope occupancy to'
            RootsExamined = 0; RecordsExamined = 0; RecordsUnplaceable = 0; UnplaceableFiles = @()
            Worktrees = @(); PrimaryPath = ''; Sessions = @()
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
        }
    }

    return [pscustomobject]@{
        RepoFound = $true; Available = $available; Detail = $detail
        RootsExamined = $roots.Count; RecordsExamined = $records.Count
        RecordsUnplaceable = $faults.Count
        UnplaceableFiles = @($faults | ForEach-Object { "$($_.File) -- $($_.Why)" })
        Worktrees = $worktrees; PrimaryPath = $primaryPath; Sessions = @($sessions)
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
