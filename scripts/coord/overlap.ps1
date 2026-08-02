<#
.SYNOPSIS
    What every OTHER session in this repo is changing right now -- files and stated work.

.DESCRIPTION
    presence.ps1 answers "who is here". This answers "what are they touching", which is the question
    that actually prevents a collision. Two sessions in separate worktrees are isolated on disk and
    still collide: they edit the same file and one of them rebases onto a surprise, or -- the case that
    actually cost this project rework -- they build the SAME FIX in DIFFERENT files, produce zero merge
    conflicts, and both PRs go green (three sessions, one npm advisory, two PRs closed as duplicates).

    So two independent signals, because they catch different failures:

      FILES  -- per worktree: committed changes vs origin/main, plus the uncommitted working tree.
                Catches concurrent edits. Exact, cheap, no cooperation required.
      WORK   -- per session: the subjects of its task list (~/.claude/tasks/<sessionId>/*.json).
                Catches duplicate EFFORT on different files. Free: sessions write these anyway, so
                nobody has to remember to declare anything.

    NOBODY HAS TO OPT IN. Every input here is a by-product of working normally -- git state and a task
    list a session already keeps. That is deliberate: claim.ps1 has existed for a while and has been
    used exactly zero times, because a coordination step you must remember is a coordination step you
    will skip. Anything built on voluntary declaration decays to nothing.

    LIVE vs DORMANT. A worktree whose session is live is a CONCURRENT collision -- someone is editing
    it now. A worktree with changes but no live session is still worth knowing about (the work may
    already be done), but it cannot be racing you. Callers are expected to treat these differently:
    block on live, mention dormant.

    CACHED, because the git walk costs ~1.5s across a dozen worktrees and a PreToolUse hook runs on
    every single edit. The cache is a plain last-write-wins file: a stale-by-seconds view of who is
    editing what is fine, and two sessions refreshing at once cost a duplicate walk, not corruption.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\overlap.ps1                       # human summary
    pwsh -NoProfile -File scripts\coord\overlap.ps1 -Json                 # machine-readable
    pwsh -NoProfile -File scripts\coord\overlap.ps1 -File messagefoundry\api\app.py
    pwsh -NoProfile -File scripts\coord\overlap.ps1 -Refresh              # ignore the cache
#>
[CmdletBinding()]
param(
    # Ask about ONE path: who else is changing it. Repo-relative or absolute. Exit 0 with no output
    # when nobody is -- the fast path a hook takes on nearly every edit.
    [string]$File,
    # Emit JSON.
    [switch]$Json,
    # Ignore the cache and re-walk.
    [switch]$Refresh,
    # How long a cached walk stays usable.
    [int]$CacheSeconds = 60,
    # Repo to inspect. Defaults to the current worktree's repo family.
    [string]$Repo,
    # Config roots for the session registry (tests point this at a fixture).
    [string[]]$ConfigRoot,
    # Where task lists live. Separate param so tests can supply their own.
    [string]$TasksDir = (Join-Path $env:USERPROFILE ".claude\tasks")
)

$ErrorActionPreference = "Stop"
. "$PSScriptRoot\session-registry.ps1"

# Emit UTF-8 explicitly. The default console encoding mangles non-ASCII in task subjects (a Unicode
# arrow came through as a raw 0x1A), which turns valid output into JSON a consumer cannot parse.
try { [Console]::OutputEncoding = [System.Text.Encoding]::UTF8 } catch { }

function ConvertTo-Norm([string]$p) {
    if (-not $p) { return "" }
    return ($p -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

$gitArgs = @(); if ($Repo) { $gitArgs = @("-C", $Repo) }
$common = (& git @gitArgs rev-parse --path-format=absolute --git-common-dir 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $common) {
    if ($Json) { "[]" | Write-Output }
    exit 0
}
$common = $common.Trim()
$myRoot = (& git @gitArgs rev-parse --path-format=absolute --show-toplevel 2>$null)
$myRootNorm = ConvertTo-Norm $myRoot

$cacheFile = Join-Path $common "mefor-coord/overlap-cache.json"

function Get-WorktreeList {
    $out = @(); $cur = $null
    foreach ($line in (& git @gitArgs worktree list --porcelain 2>$null)) {
        if ($line -like "worktree *") {
            $cur = [pscustomobject]@{ Path = $line.Substring(9).Trim(); Branch = "" }
            $out += $cur
        }
        elseif ($line -like "branch *" -and $cur) { $cur.Branch = ($line.Substring(7).Trim() -replace '^refs/heads/', '') }
        elseif ($line -like "detached*" -and $cur) { $cur.Branch = "(detached)" }
    }
    return $out
}

# The subjects a session has declared it is working on. Free signal: TaskCreate writes these anyway.
# in_progress first -- that is what it is doing NOW, which is what a sibling needs to know.
function Get-SessionWork([string]$SessionId) {
    if (-not $SessionId) { return @() }
    $dir = @(Get-ChildItem $TasksDir -Directory -Filter "$SessionId*" -EA SilentlyContinue | Select-Object -First 1)
    if (-not $dir) { return @() }
    $items = @()
    foreach ($f in @(Get-ChildItem $dir[0].FullName -Filter *.json -EA SilentlyContinue)) {
        try { $t = Get-Content $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
        if ($t.status -eq "completed") { continue }
        # Another session's free text: sanitise before it reaches our JSON or a hook's deny message.
        # Control characters here are usually a mangled Unicode arrow rather than anything hostile,
        # but they corrupt the JSON a consumer has to parse, and this is untrusted input either way.
        $subject = ([string]$t.subject) -replace '[\p{C}]', ' '
        $subject = ($subject -replace '\s+', ' ').Trim()
        if ($subject.Length -gt 100) { $subject = $subject.Substring(0, 97) + "..." }
        $items += [pscustomobject]@{ Subject = $subject; Status = [string]$t.status }
    }
    return @($items | Sort-Object @{ E = { if ($_.Status -eq "in_progress") { 0 } else { 1 } } })
}

function Build-Map {
    $sessionsByCwd = @{}
    foreach ($e in (Get-SessionRecords -ConfigRoot $ConfigRoot)) {
        if (-not $e.Record.cwd) { continue }
        $l = Test-RecordLiveness -Record $e.Record
        # Only a POSITIVE liveness answer counts as "someone is here". A dead/stale verdict is never
        # trustworthy on this host (no heartbeat), but it also cannot hurt us here: the worst case is
        # we report a worktree as dormant when its owner is actually around, and dormant still shows.
        if ($l.State -ne "LIVE" -and $l.State -ne "UNVERIFIED") { continue }
        $k = ConvertTo-Norm $e.Record.cwd
        $sessionsByCwd[$k] = $e.Record
    }

    $rows = @()
    foreach ($w in (Get-WorktreeList)) {
        $norm = ConvertTo-Norm $w.Path
        if ($norm -eq $myRootNorm) { continue }   # not a collision with yourself
        if (-not (Test-Path -LiteralPath $w.Path)) { continue }

        # Committed work on this branch, plus whatever is uncommitted in its tree.
        #
        # NEITHER diff form is correct alone, and each is wrong in the opposite direction:
        #   three-dot (origin/main...HEAD) = what the BRANCH AUTHORED. Required, because two-dot alone
        #     blames a merely-behind branch for every file main has moved underneath it.
        #   two-dot   (origin/main..HEAD)  = what still DIFFERS from main. Required, because the repo
        #     SQUASH-merges ("title (#NN)"): the squashed commit never becomes an ancestor of the
        #     branch, so the merge-base never advances and three-dot keeps crediting a landed branch
        #     with its files FOREVER. Its session then blocks that file set until someone prunes the
        #     worktree.
        # The INTERSECTION is what the branch authored AND has not yet landed. It self-clears on
        # squash, rebase and merge-commit alike. Measured 2026-07-30: two landed branches claimed 8
        # and 4 files under three-dot and 0 under the intersection, while every branch with real
        # outstanding work was unchanged (101/101, 21/21, 11/11).
        $files = @()
        $authored = @(& git -C $w.Path diff --name-only origin/main...HEAD 2>$null)
        if ($LASTEXITCODE -eq 0) {
            $outstanding = @(& git -C $w.Path diff --name-only origin/main..HEAD 2>$null)
            if ($LASTEXITCODE -eq 0) {
                # Fall back to the authored set if the two-dot diff fails, so a git hiccup
                # over-blocks (safe) rather than under-blocks (silent collisions).
                $still = [System.Collections.Generic.HashSet[string]]::new(
                    [string[]]$outstanding, [System.StringComparer]::Ordinal)
                $files += @($authored | Where-Object { $still.Contains($_) })
            }
            else { $files += $authored }
        }
        # --no-optional-locks: a plain `git status` REWRITES the index of the repo it inspects, and this
        # walks every peer worktree -- so merely asking "what is in flight" would mutate other sessions'
        # checkouts. Read-only is mandatory for an observer.
        $dirty = @(& git -C $w.Path --no-optional-locks status --porcelain 2>$null |
            Where-Object { $_.Length -gt 3 } | ForEach-Object { $_.Substring(3).Trim('"') })
        $dirty = @($dirty | Where-Object { $_ } | Sort-Object -Unique)
        $files += $dirty
        $files = @($files | Where-Object { $_ } | Sort-Object -Unique)

        # A session sitting anywhere INSIDE the worktree owns it, not just one whose cwd is the root.
        $sess = $null
        foreach ($k in $sessionsByCwd.Keys) {
            if ($k -eq $norm -or $k.StartsWith("$norm/")) { $sess = $sessionsByCwd[$k]; break }
        }
        if ($files.Count -eq 0 -and -not $sess) { continue }

        $rows += [pscustomobject]@{
            Worktree  = Split-Path $w.Path -Leaf
            Path      = $w.Path
            Branch    = $w.Branch
            Live      = [bool]$sess
            SessionId = if ($sess) { [string]$sess.sessionId } else { "" }
            Short     = if ($sess -and $sess.sessionId) { ([string]$sess.sessionId).Substring(0, 8) } else { "" }
            Surface   = if ($sess) { ([string]$sess.entrypoint) -replace '^claude-', '' } else { "" }
            Files     = $files
            # Files is the UNION of committed-and-unlanded and working-tree. A caller that must
            # distinguish "someone is typing in this file right now" from "this branch authored it and
            # is done" cannot do it from Files -- and this script's own contract (see LIVE vs DORMANT
            # above) tells callers to treat signals differently, which was not honourable until now.
            # Reported 2026-08-01: a session that had COMMITTED a file, gone clean, and said in writing
            # it was finished still blocked every other session from that file, because a committed
            # file stays in Files until the branch lands -- and while PRs cannot merge, that is forever.
            Dirty     = $dirty
            Work      = @(Get-SessionWork $(if ($sess) { [string]$sess.sessionId } else { "" }) | ForEach-Object { $_.Subject })
        }
    }
    return $rows
}

# --- cache -------------------------------------------------------------------------------------
$map = $null
if (-not $Refresh -and (Test-Path -LiteralPath $cacheFile)) {
    try {
        $c = Get-Content $cacheFile -Raw -EA Stop | ConvertFrom-Json -EA Stop
        $age = ((Get-Date) - [datetime]::Parse($c.at)).TotalSeconds
        # Bound BOTH ways: a cache stamped in the future (clock skew, or a file copied between boxes)
        # would otherwise look eternally fresh and pin a stale map forever.
        if ($age -ge 0 -and $age -lt $CacheSeconds -and $c.root -eq $myRootNorm) { $map = @($c.rows) }
    } catch { $map = $null }
}
if ($null -eq $map) {
    $map = Build-Map
    try {
        New-Item -ItemType Directory -Force -Path (Split-Path $cacheFile) | Out-Null
        # Last-write-wins on purpose: a duplicate walk is the only cost of a race, and a lock on the
        # hot path of every edit would be worse than the thing it protects.
        @{ at = (Get-Date).ToString("o"); root = $myRootNorm; rows = $map } |
            ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cacheFile -Encoding UTF8
    } catch { }   # a cache we cannot write is a slow hook, not a broken one
}

# --- single-file query (the hook's fast path) ----------------------------------------------------
if ($File) {
    $q = $File
    if ([System.IO.Path]::IsPathRooted($q)) {
        $qn = ConvertTo-Norm $q
        $rn = "$myRootNorm/"
        if ($qn.StartsWith($rn)) { $q = $qn.Substring($rn.Length) } else { $q = $qn }
    }
    $q = ConvertTo-Norm $q
    $hits = @()
    foreach ($r in $map) {
        if (@($r.Files | ForEach-Object { ConvertTo-Norm $_ }) -contains $q) {
            # Tell the caller WHICH signal matched. Without this a consumer sees only "this row
            # mentions your file" and must treat a finished, committed branch identically to a session
            # with unsaved edits open in front of it.
            $r | Add-Member -NotePropertyName MatchedDirty `
                -NotePropertyValue (@($r.Dirty | ForEach-Object { ConvertTo-Norm $_ }) -contains $q) -Force
            $hits += $r
        }
    }
    if ($Json) { ($hits | ConvertTo-Json -Depth 6 -AsArray) | Write-Output; exit 0 }
    foreach ($h in $hits) {
        $state = if ($h.Live) { "LIVE $($h.Surface) session $($h.Short)" } else { "dormant worktree" }
        Write-Host "  $File is also changed by $state in $($h.Worktree) [$($h.Branch)]"
    }
    exit 0
}

if ($Json) { ($map | ConvertTo-Json -Depth 6 -AsArray) | Write-Output; exit 0 }

if (@($map).Count -eq 0) { Write-Host "No other worktree has changes."; exit 0 }
Write-Host ""
foreach ($r in $map) {
    $who = if ($r.Live) { "LIVE $($r.Surface) $($r.Short)" } else { "dormant" }
    Write-Host ("{0,-38} {1,-38} {2}" -f $r.Worktree, $r.Branch, $who)
    foreach ($w in @($r.Work | Select-Object -First 3)) { Write-Host "    building: $w" }
    Write-Host ("    {0} changed file(s)" -f @($r.Files).Count)
}
Write-Host ""
