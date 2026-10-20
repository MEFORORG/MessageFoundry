# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Who is ACTUALLY live in this repo right now -- across every Claude Code surface, including VS Code.

.DESCRIPTION
    `claim.ps1` answers "what is being built"; this answers "who is here". They are different failures:
    a claim tells you work is taken, presence tells you whether the session that took it still exists.

    WHY THIS EXISTS RATHER THAN THE OBVIOUS ALTERNATIVES
    ----------------------------------------------------
    The Claude Desktop app's session tooling (its `list_sessions` MCP tool) enumerates an in-memory map
    of sessions THE DESKTOP APP ITSELF SPAWNED. A session launched by the VS Code extension is never
    entered into it -- not filtered out, never registered -- so it is invisible to that tool and cannot
    be addressed by it. Verified 2026-07-29: a live VS Code session sharing the DEFAULT config root was
    absent from `list_sessions` while its sibling desktop sessions were listed. It is not a login split.

    `<config-root>/sessions/<pid>.json` is the only registry that contains every surface. This script
    reads that, so a VS Code session in the primary checkout shows up next to desktop sessions in
    worktrees. Config roots are discovered dynamically (~\.claude plus any ~\.claude-account-N), because
    several logins can be in play on one machine and a session is only visible to the login that owns it.

    LIVENESS IS A FENCE, NOT A PID CHECK
    ------------------------------------
    A bare `is pid alive` check is wrong: PIDs are reused, and these files outlive their process (a
    session that dies uncleanly leaves its file behind -- measured, 2 of 3 IDE lock files on this host
    named dead processes, the oldest by 6.5 days). Claude Code's own registry carries a `procStart` field
    for exactly this fence, but on this host it serialises as absent, so the shipped guard passes
    unconditionally. We therefore compute process start time OURSELVES and require it to be consistent
    with the recorded session start. A reused PID hosts a process that started AFTER the session
    registered, and that is what STALE means below.

    A session is reported LIVE only when its pid resolves AND that process's start time is consistent.
    Anything else is STALE (pid reused or file orphaned) or DEAD (no such pid).

    READ-ONLY. This script never writes, never deletes a registry file, and never contacts another
    session. It is a roster, not a channel.

    The cwd -> worktree matcher and the availability receipt live in occupancy.ps1, shared with
    prune-merged.ps1 (which DELETES a worktree, so it must reach the same verdict this roster does).
    This script only labels and renders what that returns.

    -FLEET, AND WHAT IT STILL CANNOT PROVE
    --------------------------------------
    The default roster is scoped to ONE repository family, so a seat working another repo is absent
    from it, and that absence reads as "that seat is not running". -Fleet scans every repository the
    session records name, plus the caller's own, and joins the results.

    A -Fleet roster that lacks a seat does NOT prove the seat absent. At least these stay unlisted:
      * a session whose cwd lies outside git. It names no repository to scan.
      * a session whose cwd is gone, with no checkout above it. A gone sibling worktree such as
        <primary>-<slug> is this shape. Its repository is scanned only if something else names it.
      * a session on another machine. No form of this roster can see it.
    The caller's own repository is always scanned, so its fence still reports the shapes
    occupancy.ps1 names: a gone sibling worktree named <primary>-<slug>, and a deregistered checkout
    still on disk. A gone checkout of it elsewhere is in neither shape and goes unreported. A named
    repository that cannot be scanned makes the roster UNAVAILABLE rather than dropping out of it.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\presence.ps1
    pwsh -NoProfile -File scripts\coord\presence.ps1 -All        # include stale/dead entries
    pwsh -NoProfile -File scripts\coord\presence.ps1 -Json       # machine-readable
    pwsh -NoProfile -File scripts\coord\presence.ps1 -Fleet      # every repository the records name
#>
[CmdletBinding()]
param(
    # Config roots to scan. Defaults to every ~\.claude* directory (Desktop + each CLI/VS Code login).
    # Tests point this at a fixture directory, so the real discovery logic is what gets exercised.
    [string[]]$ConfigRoot,
    # Show STALE and DEAD entries too. Default lists only sessions that are actually live.
    [switch]$All,
    # Emit JSON instead of a table.
    [switch]$Json,
    # Repo to scope to. Defaults to the current worktree's repo family (all worktrees sharing one .git).
    [string]$Repo,
    # Scan every repository the session records name, not just this one. See the -Fleet note in the
    # description for what a -Fleet roster still cannot prove.
    [switch]$Fleet,
    # Treat this pid as "me" so the roster can mark the calling session. Defaults to auto-detection by
    # ancestry (see Get-SelfPids) -- 0 means "work it out", which is what every real invocation wants.
    [int]$SelfPid = 0,
    # How far a process may have started BEFORE its session registered and still be the same run.
    # Generous: registration follows process start, but a cold start on a loaded box can lag.
    [int]$StartSkewMinutes = 15
)

# A CLAUDE CODE CLOUD SESSION SEES NO OTHER SESSION THROUGH THIS SCRIPT: the config roots it scans are
# the VM's own, so the roster lists nobody else and that empty answer looks like an empty repo. CLAUDE.md
# section 5, "A cloud session is a Builder in its own session"; tests/test_coord_cloud_refusal.py
# holds the line.
if ($env:CLAUDE_CODE_REMOTE -eq 'true') {
    [Console]::Error.WriteLine('presence.ps1: refused in a Claude Code cloud session (CLAUDE_CODE_REMOTE=true). This VM''s Claude config roots list no other session, so nothing was read.')
    exit 3
}

$ErrorActionPreference = "Stop"

# --- Registry access, the liveness fence, and the cwd -> worktree matcher ------------------------
# All shared: sessions.ps1 needs the SAME answer to "is this session alive" before it moves a
# transcript, and prune-merged.ps1 needs the SAME answer to "is anybody in this checkout" before it
# DELETES one. Two copies of a safety check drift, and the copy that drifts is the one nobody tests.
. "$PSScriptRoot\occupancy.ps1"

# Get-LoginLabel now lives in session-registry.ps1, reached through the occupancy.ps1 dot-source above.
# It moved because the announce hook needs the same mapping and a second copy would drift.

# The surface a session was launched from. This is the field that makes VS Code sessions visible at all,
# so it is reported verbatim when it is something we do not recognise rather than folded into "other".
function Get-SurfaceLabel([string]$Entrypoint) {
    switch -Regex ($Entrypoint) {
        '^claude-desktop$' { return "desktop" }
        '^claude-vscode$' { return "vscode" }
        '^$' { return "?" }
        default { return $Entrypoint -replace '^claude-', '' }
    }
}

# --- Which of these sessions is the caller ------------------------------------------------------
# NOT $PID: this script runs as a pwsh child (often a grandchild, via a hook), so its own pid never
# appears in the registry. The session that invoked us is an ANCESTOR, so walk the parent chain and
# treat every pid on it as "self". Getting this wrong is not cosmetic -- a roster that cannot tell you
# from a sibling is one you will act on as though someone else were in your own worktree.
function Get-SelfPids([int]$Override) {
    if ($Override -gt 0) { return @($Override) }
    # ONE CIM query for the whole process table, not one per ancestor: this runs on every SessionStart,
    # and a dozen round-trips is the difference between a hook you notice and one you don't.
    $ppid = @{}
    try {
        Get-CimInstance Win32_Process -Property ProcessId, ParentProcessId -EA Stop |
            ForEach-Object { $ppid[[int]$_.ProcessId] = [int]$_.ParentProcessId }
    } catch { return @($PID) }

    $chain = @()
    $cur = $PID
    # Bounded: a runaway or cyclic parent chain must not hang a SessionStart hook.
    for ($i = 0; $i -lt 12 -and $cur -gt 0; $i++) {
        $chain += $cur
        $parent = $ppid[$cur]
        if (-not $parent -or $parent -le 0 -or $chain -contains $parent) { break }
        $cur = $parent
    }
    return $chain
}

# --- Which repositories -Fleet scans ----------------------------------------------------------
# One -Repo hint per distinct git common dir, with the caller's repository seeded first.
#
# THE SEED IS THE ENGINE'S DEPARTURE FROM KORUS efd7b428db. Korus scanned the caller's repository
# only when no record named any repository. A record whose cwd is gone often names no repository on
# disk. So when a repository's only record was gone, korus never scanned it. The third unplaceable
# shape in occupancy.ps1 then could not fire, and -Fleet called the fence available. Seeding the
# caller's repository keeps that fault visible for the repository the caller works in.
#
# The .git pointer is read first, because it costs no process and survives deregistration; rev-parse
# runs only where the pointer says nothing. Results are memoised by cwd.
#
# Returns Hints (common dir -> hint), OwnFound, and Unreadable (record files that did not parse).
function Get-FleetRepoHints([string]$OwnRepo, [string[]]$Roots, [hashtable]$Memo = @{}) {
    $hints = [ordered]@{}
    $own = Get-RepoCommonDir $OwnRepo
    if ($own) { $hints[$own] = $OwnRepo }
    $unreadable = @()
    $records = @()
    $readError = ''
    try { $records = @(Get-SessionRecords -ConfigRoot $Roots -IncludeUnreadable) }
    catch { $readError = $_.Exception.Message }
    $memo = $Memo
    foreach ($rec in $records) {
        if ($rec.Unreadable) { $unreadable += $rec.File; continue }
        # Get-SessionRecords returns a WRAPPER (Root, File, Record, ...), so the session's fields
        # live under .Record. Reading .cwd off the wrapper is null for every record, and korus
        # measured that collapsing -Fleet to one repository.
        $cwd = [string]$rec.Record.cwd
        if (-not $cwd) { continue }
        if (-not $memo.ContainsKey($cwd)) {
            # A cwd on a drive that no longer exists makes Join-Path throw. It names no repository.
            $common = ''
            try {
                $common = Get-OwningGitCommonDir $cwd
                if (-not $common -and (Test-Path -LiteralPath $cwd)) { $common = Get-RepoCommonDir $cwd }
            }
            catch { $common = '' }
            $memo[$cwd] = $common
        }
        $common = $memo[$cwd]
        # The common dir itself is the hint. git runs inside a git directory, and the common dir
        # still exists when the session's checkout does not.
        if ($common -and -not $hints.Contains($common)) { $hints[$common] = $common }
    }
    return [pscustomobject]@{
        Hints = $hints; OwnFound = [bool]$own; Unreadable = $unreadable; ReadError = $readError; Memo = $memo
    }
}

# One repository's scan, turned into a failed scan rather than a throw or a silent drop. Either of
# those would leave the joined fence reading available on a repository it never read.
function Get-FleetScan([string]$Common, [string]$Hint) {
    try {
        $one = Get-WorktreeOccupancy -Repo $Hint -ConfigRoot $ConfigRoot -StartSkewMinutes $StartSkewMinutes
        if ($one.RepoFound) { return $one }
        $why = "git could not list the worktrees of $Common, so that repository was not scanned"
    }
    catch { $why = "the scan of $Common failed: $($_.Exception.Message)" }
    return [pscustomobject]@{
        RepoFound = $false; Available = $false; Detail = $why
        RootsExamined = 0; RecordsExamined = 0; UnplaceableFiles = @(); PrimaryPath = ''; Sessions = @()
    }
}

# --- Collect ------------------------------------------------------------------------------------
# EVERY REPO, OR ONE. -Fleet calls Get-WorktreeOccupancy once per repository and joins the results.
# That keeps ONE definition of 'live' and 'unplaceable', which prune-merged.ps1 and sessions.ps1
# depend on. Any repository that cannot account for its records makes the joined fence unavailable.
$scopeLabel = 'this repo'
$ownPrimary = ''
if ($Fleet) {
    $plan = Get-FleetRepoHints -OwnRepo $Repo -Roots $ConfigRoot
    $scans = @($plan.Hints.Keys | ForEach-Object { Get-FleetScan -Common $_ -Hint $plan.Hints[$_] })
    $found = @($scans | Where-Object { $_.RepoFound })
    if ($plan.OwnFound) { $ownPrimary = $scans[0].PrimaryPath }
    $unplaceable = @($found | ForEach-Object { $_.UnplaceableFiles } | Select-Object -Unique)

    $problems = @()
    # A -Repo the caller named, and git cannot resolve, is a repository this roster never read.
    if ($plan.ReadError) {
        $problems += "the session registry could not be read to choose repositories: $($plan.ReadError)"
    }
    if ($Repo -and -not $plan.OwnFound) {
        $problems += "the repository named by -Repo ($Repo) could not be resolved, so it was not scanned"
    }
    # A record that did not parse named no repository when they were chosen. If the scans still saw
    # it unparseable they already fault it; one that parsed by then may name a repository not scanned.
    $healed = @($plan.Unreadable | Where-Object {
            $f = $_
            -not @($unplaceable | Where-Object { $_.StartsWith("$f -- ") }).Count
        })
    if ($healed.Count -gt 0) {
        $problems += "$($healed.Count) record(s) parsed only after repositories were chosen, so their repositories may be unscanned: $($healed -join '; ')"
    }
    # Each scan re-reads the registry. A record that appears in between names a repository nobody
    # chose, so choose again and compare. The memo from the first pass keeps the second one cheap.
    $late = @((Get-FleetRepoHints -OwnRepo $Repo -Roots $ConfigRoot -Memo $plan.Memo).Hints.Keys |
            Where-Object { -not $plan.Hints.Contains($_) })
    if ($late.Count -gt 0) {
        $problems += "a session record naming another repository appeared during the scan: $($late -join '; ')"
    }
    if ($unplaceable.Count -gt 0) {
        $problems += "$($unplaceable.Count) session record(s) could not be placed, so the roster is incomplete: $($unplaceable -join '; ')"
    }
    # Failed scans and scans unavailable for a reason other than an unplaceable record.
    $problems += @($scans | Where-Object { -not $_.Available -and @($_.UnplaceableFiles).Count -eq 0 } |
            ForEach-Object { $_.Detail } | Select-Object -Unique)

    # A session inside a repository nested in another's checkout is placed by both scans. Keep the
    # more specific placement, the longer worktree path. The occurrence index keeps two identical
    # records within one scan apart, since every scan walks the registry in the same order.
    $byRecord = [ordered]@{}
    foreach ($scan in $found) {
        $seenHere = @{}
        foreach ($s in $scan.Sessions) {
            $base = "$($s.Root)|$($s.SessionId)|$($s.Pid)|$($s.Cwd)"
            $n = [int]$seenHere[$base]
            $seenHere[$base] = $n + 1
            $key = "$base|$n"
            $s | Add-Member -NotePropertyName Repo -NotePropertyValue $scan.PrimaryPath -Force
            $prev = $byRecord[$key]
            if (-not $prev -or $s.WorktreePath.Length -gt $prev.WorktreePath.Length) { $byRecord[$key] = $s }
        }
    }
    $occ = [pscustomobject]@{
        # Any repository attempted counts, so a failed scan reaches the UNAVAILABLE receipt with its
        # reason rather than the generic "not inside a git repository".
        RepoFound       = ($scans.Count -gt 0)
        Available       = ($found.Count -gt 0 -and $problems.Count -eq 0)
        Detail          = ($problems -join '; ')
        # Every scan reads the same registry, so the max is the honest single figure.
        RootsExamined   = [int]($found | Measure-Object -Property RootsExamined -Maximum).Maximum
        RecordsExamined = [int]($found | Measure-Object -Property RecordsExamined -Maximum).Maximum
        Sessions        = @($byRecord.Values)
    }
    $noun = if ($scans.Count -eq 1) { 'repository' } else { 'repositories' }
    $scopeLabel = "the FLEET of $($scans.Count) $noun"
}
else {
    $occ = Get-WorktreeOccupancy -Repo $Repo -ConfigRoot $ConfigRoot -StartSkewMinutes $StartSkewMinutes
    $ownPrimary = $occ.PrimaryPath
}

# EVERY HUMAN RUN STATES WHAT ITS ROSTER CANNOT PROVE, the empty one included, since "nobody is
# here" is the reading a narrow roster most often corrupts. The default is scoped to one repository.
# -Fleet is wider, and a seat missing from it is still not proven absent.
function Write-ScopeWarning {
    Write-Host ""
    if ($Fleet) {
        Write-Host "  A seat missing from this roster is NOT proven absent. At least these are not listed:" -ForegroundColor Yellow
        Write-Host "  sessions whose cwd is outside git or gone with no checkout above it, and sessions on another machine." -ForegroundColor Yellow
        return
    }
    Write-Host "  SCOPED TO THIS REPOSITORY. A seat working another repo is not listed above." -ForegroundColor Yellow
    Write-Host "  Before writing that any seat is absent:  pwsh -NoProfile -File scripts\coord\presence.ps1 -Fleet" -ForegroundColor Yellow
}

if (-not $occ.RepoFound) {
    # THE STDERR RECEIPT BELONGS HERE TOO, and its absence was a hole in the control this script
    # already documents. The -Json block further down emits an UNAVAILABLE receipt so that "the fence
    # could not look" stops rendering as an indistinguishable `[]` -- but THIS path returned the same
    # empty array with no receipt at all, so one of the two ways of being unable to look stayed
    # silent on exactly the channel a machine consumer reads. A caller that correctly checks stderr
    # for the receipt would still read "not a git repository" as "nobody is live".
    if ($Json) {
        [Console]::Error.WriteLine("presence: roster UNAVAILABLE -- not inside a git repository, so there is nothing to scope presence to. An empty list here is NOT 'nobody is live'.")
        "[]" | Write-Output
    }
    else { Write-Host "Not inside a git repository -- nothing to scope presence to." }
    exit 0
}

$selfPids = Get-SelfPids $SelfPid

$rows = @()
foreach ($s in $occ.Sessions) {
    $repoOf = if ($s.PSObject.Properties['Repo']) { $s.Repo } else { $ownPrimary }
    $rows += [pscustomobject]@{
        State     = $s.State
        Detail    = $s.Detail
        Surface   = Get-SurfaceLabel $s.Entrypoint
        Login     = Get-LoginLabel $s.Root
        SessionId = $s.SessionId
        Short     = $s.Short
        Pid       = $s.Pid
        Cwd       = $s.Cwd
        Worktree  = $s.Worktree
        # The repository's primary checkout. Under -Fleet it is what tells two repos' rows apart.
        Repo      = $repoOf
        IsOwnRepo = ((ConvertTo-Norm $repoOf) -eq (ConvertTo-Norm $ownPrimary))
        IsPrimary = $s.IsPrimary
        Branch    = $s.Branch
        Kind      = $s.Kind
        # Kind cannot tell a scheduled-task run from a person's session; the transcript can. Only read
        # for a row the default view keeps, since the filter below drops the rest.
        Scheduled = if ($All -or (Test-OccupancyVeto $s.State)) {
            Test-ScheduledTaskSession -Root $s.Root -SessionId $s.SessionId
        } else { $false }
        IsSelf    = ($selfPids -contains [int]$s.Pid)
        StartedAt = $s.StartedAt
    }
}

$order = @{ "LIVE" = 0; "UNVERIFIED" = 1; "UNREADABLE" = 1; "STALE" = 2; "DEAD" = 3 }
$rows = @($rows | Sort-Object @{ E = { $order[$_.State] } }, @{ E = { $_.Worktree } })
# Anything that is live, or that we could not prove ISN'T, stays in the default view: an unverifiable
# fence is not a passed fence.
if (-not $All) { $rows = @($rows | Where-Object { Test-OccupancyVeto $_.State }) }

if ($Json) {
    # The receipt goes to STDERR, deliberately: stdout stays a pure JSON array so every existing
    # consumer keeps working, but "the fence could not look" no longer renders as an indistinguishable
    # `[]`. Without this, session-context.ps1's banner reports an unavailable fence as "nobody else is
    # here" -- a green light derived from nothing having been measured.
    if (-not $occ.Available) {
        [Console]::Error.WriteLine("presence: roster UNAVAILABLE -- $($occ.Detail). $($occ.RootsExamined) config root(s), $($occ.RecordsExamined) record(s) examined. An empty list here is NOT 'nobody is live'.")
    }
    # -Depth so nested pscustomobjects survive; -AsArray so a single row is still a JSON list and a
    # caller can index it without special-casing.
    ($rows | ConvertTo-Json -Depth 4 -AsArray) | Write-Output
    exit 0
}

if ($rows.Count -eq 0) {
    # "Nobody is here" and "I could not look" produce the same empty list, so say which one it is.
    if (-not $occ.Available) {
        Write-Host "Roster UNAVAILABLE -- $($occ.Detail)." -ForegroundColor Yellow
        Write-Host "  This is NOT 'nobody is live'. An empty list from a fence that could not look proves nothing." -ForegroundColor Yellow
    }
    else {
        Write-Host "No live sessions found in $scopeLabel." -ForegroundColor DarkGray
        Write-Host "  (fence: $($occ.RootsExamined) config root(s), $($occ.RecordsExamined) record(s) examined.)" -ForegroundColor DarkGray
    }
    Write-Host "(Add -All to include stale/dead registry entries.)" -ForegroundColor DarkGray
    Write-ScopeWarning
    exit 0
}

Write-Host ""
# A PARTIAL ROSTER MUST NOT RENDER AS A COMPLETE ONE. Under -Fleet one repository's unplaceable record
# sits beside another's live rows, so a non-empty table is no evidence that the fence could look.
if (-not $occ.Available) {
    Write-Host "Roster INCOMPLETE -- $($occ.Detail)." -ForegroundColor Yellow
    Write-Host "  What follows is what could be placed. There may be sessions it does not show." -ForegroundColor Yellow
}
Write-Host "Live Claude sessions in $scopeLabel ($($rows.Count)):"
# NAME EVERY COLUMN (BACKLOG #1098). The leading token is an 8-hex REGISTRY SESSION ID and reads exactly
# like an abbreviated commit SHA: session-context.ps1's banner, which points readers here, prints a real
# one in the same shape (`git worktree list` = path, sha, branch). Unlabelled, a reader resolves it
# against git and gets an error at best, the wrong tree if the prefix happens to resolve. A header row
# rather than a per-row word because this is a fixed-width table -- the header governs every row, which
# is the property the item asks for.
Write-Host ("  {0,-8} {1,-7} {2,-34} {3}" -f "sess-id", "surface", "worktree", "branch")
foreach ($r in $rows) {
    $me = if ($r.IsSelf) { "  <-- THIS session" } else { "" }
    # Only the caller's own primary is the SHARED PRIMARY; another repo's trunk is no collision here.
    $shared = $r.IsPrimary -and $r.IsOwnRepo -and -not $r.IsSelf
    $warn = if ($shared) { "  [in the SHARED PRIMARY]" } else { "" }
    $state = if ($r.State -eq "LIVE") { "" } else { "  [$($r.State): $($r.Detail)]" }
    $where = if ($Fleet -and $r.Repo) { "$(Split-Path $r.Repo -Leaf)/$($r.Worktree)" } else { $r.Worktree }
    Write-Host ("  {0,-8} {1,-7} {2,-34} {3}" -f $r.Short, $r.Surface, $where, $r.Branch)
    if ($me -or $warn -or $state) { Write-Host ("           {0}{1}{2}" -f $me.TrimStart(), $warn, $state) }
}
Write-Host ""
Write-Host "  See what they are building:  pwsh -NoProfile -File scripts\coord\claim.ps1 -List"
Write-ScopeWarning
Write-Host ""
exit 0
