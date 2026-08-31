# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
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

      FILES  -- per worktree: committed changes vs origin/main that the CALLER does not already have,
                plus the uncommitted working tree. Catches concurrent edits. Exact, cheap, no
                cooperation required.

                RELATIVE TO WHOEVER ASKED, and that is not a detail a consumer can ignore. The
                committed half is narrowed by the querying worktree's own HEAD, so the same peer
                yields a different Files for a different caller, and a peer whose only committed work
                the caller already has can drop out of the map entirely. A count taken from it is
                "files this peer changed beyond mine", never "files this peer changed". The
                uncommitted half is absolute -- see the third intersect term in Build-Map for why the
                narrowing stops there.
      WORK   -- per session: the subjects of its task list, plus the goal its seat record declares.
                Catches duplicate EFFORT on different files.

                TWO SOURCES, BECAUSE THE FIRST ONE DIED AND NOBODY NOTICED. This read only
                ~/.claude/tasks/<sessionId>/*.json, which failed three ways at once, all measured
                2026-08-30 on this box:

                  1. ONE ROOT OF SIX. A box runs several Claude config roots (~/.claude plus one
                     ~/.claude-account-<N> per account), and a session's task list lives under the root
                     it BOOTED from. Both live sessions were on .claude-account-2. Reading a hardcoded
                     ~/.claude saw none of them, and would have seen at best a sixth of the fleet.
                  2. THE DIRECTORY NAME CHANGED. Task directories used to be the full session UUID;
                     they are now `session-<first 8 of the id>`. The `<SessionId>*` glob cannot match
                     that shape, so no directory written after the change is reachable at all.
                  3. THE STORE IS DEAD. 209 task files exist across all six roots and the newest is
                     dated 2026-08-22. Every one of the 21 directories created since carries zero task
                     files. Nothing writes them any more.

                Legs 1 and 2 are repaired below, because a store that comes back must be read
                correctly. Leg 3 is why there is a second source: the SEAT RECORD written to
                <git-common-dir>/mefor-coord/seats/ by seat.ps1's Stop hook, which is keyed by session
                id, carries the seat's declared goal, and was being written seconds before this was
                measured.

    THE COST OF ALL THIS WAS SILENCE, so the census below is not decoration. A live run over 136 rows
    returned a work signal on ZERO of them, for over a week, and looked exactly like a fleet with
    nothing to say. Every run now prints what it read -- stores, files, seat records, and the age of
    the newest task file measured against the newest seat record -- so "the store I read is empty"
    cannot render as "nobody is working". The seat store is the positive control: if it is being
    written and the task store is not, the fleet is demonstrably not quiet.

    NOBODY HAS TO OPT IN for the FILES signal, which is a by-product of working normally. The task half
    of WORK was free the same way and is now dead; the seat half needs a declaration, which CLAUDE.md
    requires and a SessionStart hook prompts for. That is a real weakness -- claim.ps1 has existed for
    a while and has been used exactly zero times, because a coordination step you must remember is a
    coordination step you will skip -- so an undeclared seat contributes nothing here and the census
    says how many sessions answered out of how many were asked.

    LIVE vs DORMANT. A worktree whose session is live is a CONCURRENT collision -- someone is editing
    it now. A worktree with changes but no live session is still worth knowing about (the work may
    already be done), but it cannot be racing you. Callers are expected to treat these differently:
    block on live, mention dormant.

    CACHED, because the walk is not cheap and a PreToolUse hook runs it on every single edit. The cost
    is PROCESS COUNT -- one git per term per worktree -- so it scales with how many worktrees exist,
    not with how much work they contain. MEASURED 2026-08-22 at 73 worktrees: 11.4s before the
    caller-relative term, 14.6s with it evaluated per peer, 12.0s with it gated on one up-front
    `for-each-ref`. RE-MEASURED 2026-08-30 at 162 worktrees, after the count more than doubled: 582 git
    spawns, 28.9s of git time, ~50ms per call of which ~34ms is bare process startup. The whole walk
    took 26.1s against the gate's 16s budget and bailed on all five runs.

    THREE THINGS KEEP IT UNDER BUDGET, attacking that number from different sides:

      PARALLEL  -- the per-worktree body runs in runspaces (-ParallelLimit, default 16). No two
                   worktrees share state, so wall time collapses to the throughput of git rather than
                   the sum of its startups. Measured 2026-08-30: 28.9s serial, 3.98s at 16 ways.
      MEMOISED  -- the three committed-half diffs are pure functions of three commit ids (origin/main,
                   the peer's HEAD, the caller's HEAD), so the answer is CONTENT-ADDRESSED and cannot
                   go stale. The peer's HEAD arrives free in `worktree list --porcelain`, which this
                   script already runs. A hit skips three of the four git spawns. Measured: 3.98s cold,
                   1.17s warm. This is the term that keeps the walk flat as worktrees accumulate, and
                   accumulating is what they measurably do.
      BUDGETED  -- see -TimeBudgetSeconds, for whatever is left once both of the above are spent.

    RE-MEASURE AFTER TOUCHING THIS LOOP, and do not answer a slow walk by raising the budget. It sits
    under a harness timeout this script does not control, and a hook that blocks an edit for 20s is
    worse than no hook at all.

    The WHOLE-MAP cache is a plain last-write-wins file: a stale-by-seconds view of who is editing what
    is fine, and two sessions refreshing at once cost a duplicate walk, not corruption. It is keyed on
    the querying worktree's root AND HEAD, because Files depends on both. The term memo beside it is
    keyed on content rather than time, so it has no freshness window and needs none.

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
    # Where task lists live. ONE PER CONFIG ROOT, and unset means "derive them", which is the whole
    # repair: the old default was the single literal ~/.claude\tasks, so a session booted from any
    # ~/.claude-account-<N> could not be seen at all. Derived from Get-ClaudeConfigRoots below rather
    # than from a second enumerator here -- two copies of "what is a config root" drift, and this
    # directory has paid for that mistake more than once (see config-roots.ps1's header).
    #
    # Still a parameter, and now an ARRAY, so a test can point it at a fixture store. A single string
    # binds to a one-element array, which is why the existing callers that pass one path still work.
    [string[]]$TasksDir,
    # ABANDON THE WALK AND EXIT 3 if it has not finished within this many seconds. 0 = unbounded,
    # which is the right default for a human at a prompt: a slow answer beats no answer.
    #
    # It exists for the HOOK, which has the opposite need. collision_gate.ps1 spawns this script under
    # a harness timeout it does not control; when that timeout fires the hook process is killed, so it
    # emits nothing -- and empty stdout from a PreToolUse hook is byte-identical to "checked, nobody
    # else is touching this file". That is the silent all-clear the gate's own docstring says it was
    # rewritten to eliminate, and the ONE failure path it cannot narrate, because it is not running
    # any more when it happens. Bailing out UNDER the harness budget converts it into an exit code the
    # gate is already wired to report.
    #
    # A PARTIAL MAP IS RETURNED, AND EVERY ROW OF IT SAYS SO. This script used to withhold one, on the
    # reasoning that half a walk under-reports and an under-report here is a silent collision. The
    # first half of that is true; the conclusion does not follow. Discarding the rows does not make the
    # walk complete -- it throws away the peers the walk DID find, so a real collision sitting in the
    # walked half was dropped and the edit allowed. That is the same silent collision by a longer
    # route, and it is what shipped: measured 2026-08-30, five of five runs bailed and returned nothing
    # while 162 worktrees went unreported.
    #
    # So the rows survive, each stamped Partial, Walked and Total, and exit 3 still reports that the
    # walk did not cover everything. A consumer may use a partial map ONLY to add a warning, never to
    # conclude all-clear. collision_gate.ps1 does exactly that: it can still deny on one, and every
    # path that would ALLOW on one goes through its unresolved notice instead of exiting quietly.
    #
    # ZERO ROWS PRINTS NOTHING, not `[]`. That keeps `[]` meaning one thing only: a COMPLETE walk that
    # found nobody. A partial walk must never be able to render as the all-clear.
    #
    # Still no cache write on an overrun. Caching an under-report would pin it for the whole window.
    #
    # Fractional, so a test can pin the bail deterministically instead of racing a one-second floor.
    [double]$TimeBudgetSeconds = 0,
    # How many worktrees to inspect at once. The walk is one git process per term per worktree and no
    # two worktrees share anything, so this is the lever that turns process startup from a sum into a
    # throughput figure. Measured 2026-08-30 across 162 worktrees: 28.9s at 1, 3.98s at 16, no further
    # gain at 32. 1 or less runs the same body serially, which is what the tests pin against.
    [int]$ParallelLimit = 16
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

# One emitter for every -Json exit, so no path can print nothing. See the note at the -File query below.
#
# The null filter is load-bearing, not defensive tidying. `Build-Map` returning no rows yields
# AutomationNull, which PARAMETER BINDING converts to a real $null on the way in -- and `@($null).Count`
# is 1, so the zero-rows guard was dead in exactly the case it was written for and the whole-map query
# emitted `[null]`: a phantom row, strictly worse than the nothing it replaced. Caught by adversarial
# review after the -File path had been verified by hand; the two call sites do not fail alike.
function Write-JsonArray($Rows) {
    $r = @($Rows | Where-Object { $null -ne $_ })
    # A PARTIAL WALK WITH NOTHING TO SHOW PRINTS NOTHING, so `[]` keeps meaning exactly one thing: a
    # COMPLETE walk that found nobody. Every other rule here depends on that staying true. Rows from a
    # partial walk carry their own Partial stamp and are safe to print; zero rows carry no stamp, so
    # printing them as `[]` would render an unfinished walk as the all-clear.
    if ($script:MapPartial -and $r.Count -eq 0) { return }
    if ($r.Count -eq 0) { Write-Output "[]"; return }
    Write-Output ($r | ConvertTo-Json -Depth 6 -AsArray)
}

# Declared before any path can read it. A cache HIT skips Build-Map entirely, and an unset $script:
# variable would leave the partial test reading $null on the one path that is definitely complete.
$script:MapPartial = $false

$gitArgs = @(); if ($Repo) { $gitArgs = @("-C", $Repo) }
$common = (& git @gitArgs rev-parse --path-format=absolute --git-common-dir 2>$null)
if ($LASTEXITCODE -ne 0 -or -not $common) {
    if ($Json) { "[]" | Write-Output }
    exit 0
}
$common = $common.Trim()
$myRoot = (& git @gitArgs rev-parse --path-format=absolute --show-toplevel 2>$null)
$myRootNorm = ConvertTo-Norm $myRoot

# --- where the WORK signal reads from ------------------------------------------------------------
# One tasks store per config root, derived from the SAME enumerator the session registry uses, so the
# two cannot disagree about which roots exist. -TasksDir overrides for tests.
$script:TaskStores = @(
    if ($TasksDir) { $TasksDir }
    else { @(Get-ClaudeConfigRoots -ConfigRoot $ConfigRoot) | ForEach-Object { Join-Path $_ 'tasks' } }
)
# The seat layer, spelled the way fleet.ps1, handoff.ps1 and lane-level.ps1 already spell it.
$script:SeatsDir = Join-Path $common 'mefor-coord\seats'

# EVERY COUNT THIS SCRIPT PRINTS ABOUT THE WORK SIGNAL, in one place, so no line can claim a number
# the walk did not produce. Carried through the cache too -- a cached map that re-derived these would
# report a survey it never ran.
$script:Census = [ordered]@{
    Surveyed         = $false
    StoresConfigured = @($script:TaskStores).Count
    StoresPresent    = 0
    TaskFiles        = 0
    TaskNewest       = $null
    SeatRecords      = 0
    SeatNewest       = $null
    Asked            = 0
    AnsweredTasks    = 0
    AnsweredSeat     = 0
}

# THE QUERYING WORKTREE'S OWN HEAD, used below to stop crediting a peer with a commit the caller wrote.
# Empty when it cannot be resolved, and every use is guarded on that -- see the note at the third
# intersect term for why the failure direction has to be "report more", not "report less".
#
# `-q --verify` and NOT a bare `rev-parse HEAD`. On an unborn branch the bare form prints the literal
# string "HEAD" on stdout while exiting 128, so a caller that tested the output instead of the exit code
# would anchor a diff on the word HEAD. Measured: `-q --verify` exits 1 and prints nothing.
$myHead = ""
$headOut = (& git @gitArgs rev-parse -q --verify HEAD 2>$null)
if ($LASTEXITCODE -eq 0 -and $headOut) { $myHead = ([string]$headOut).Trim() }

# WHICH BRANCHES INHERITED MY UNLANDED WORK -- computed ONCE for the whole walk, because the third
# intersect term below is only ever non-trivial for a peer that holds one of my commits.
#
# THE COST IS PROCESS COUNT, and that is measured rather than assumed. This walk spawns one git per
# term per worktree; on this box at 73 worktrees each one costs ~49 ms, so a term evaluated per peer is
# ~3.5 s added to a script the PreToolUse gate runs on every Edit and Write, under a harness timeout of
# 20 s. Asking the question once instead costs ONE `rev-list` plus ONE `for-each-ref --contains`
# (measured 130 ms against 639 refs) and answered it for 72 of 73 worktrees here.
#
# THE OLDEST unlanded commit, not all of them. Along a linear branch, containing any of my commits
# implies containing the oldest, so one ref query settles it. A branch of mine carrying a merge could
# in principle hand a peer a newer commit without the oldest; that peer is then NOT matched, keeps
# today's wider set, and is over-reported -- the same direction every other fallback here takes.
#
# $null means "could not tell" (no HEAD, no origin/main, a git error) and restores the per-peer diff.
# An EMPTY set is a different answer and a real one: I have nothing unlanded, so no peer can have
# inherited anything of mine and the term cannot narrow any row.
$inheritors = $null
if ($myHead) {
    $mine = @(& git @gitArgs rev-list origin/main..$myHead 2>$null)
    if ($LASTEXITCODE -eq 0) {
        if ($mine.Count -eq 0) {
            $inheritors = [System.Collections.Generic.HashSet[string]]::new(
                [string[]]@(), [System.StringComparer]::Ordinal)
        }
        else {
            $refs = @(& git @gitArgs for-each-ref --format='%(refname:short)' --contains $mine[-1] refs/heads 2>$null)
            if ($LASTEXITCODE -eq 0) {
                $inheritors = [System.Collections.Generic.HashSet[string]]::new(
                    [string[]]$refs, [System.StringComparer]::Ordinal)
            }
        }
    }
}

$cacheFile = Join-Path $common "mefor-coord/overlap-cache.json"
$termCacheFile = Join-Path $common "mefor-coord/overlap-terms.json"

# THE ANCHOR EVERY COMMITTED-HALF TERM IS MEASURED AGAINST, resolved once so it can go in the memo key.
# Empty means "could not tell", which disables the memo entirely and leaves every term computed the
# long way -- slow, and the same answer. The memo must never be consulted on a key that omits an input.
$originMain = ""
$omOut = (& git @gitArgs rev-parse -q --verify origin/main 2>$null)
if ($LASTEXITCODE -eq 0 -and $omOut) { $originMain = ([string]$omOut).Trim() }

# THE TERM MEMO: key -> the committed half of Files for one worktree.
#
# CONTENT-ADDRESSED, NOT TIME-ADDRESSED, and that distinction is the whole safety argument. All three
# diffs below are commit-to-commit (no working tree is read), so each is a pure function of the commit
# ids in its key. Two fixed commits have one merge base forever, because the object graph only grows.
# A key that matches therefore guarantees a byte-identical answer, so this cache has no staleness
# window to get wrong -- unlike the whole-map cache beneath it, which trades freshness for speed.
#
# The dirty half is deliberately NOT in here. `git status` reads the working tree, and a peer typing
# into a file touches neither HEAD nor the index -- so nothing cheap changes when the one signal this
# gate exists for does. Memoising it on any key we can afford to compute would miss exactly the
# collision it is meant to catch, which is why the status spawn stays on every worktree every walk.
$termCache = @{}
try {
    if (Test-Path -LiteralPath $termCacheFile) {
        $tc = Get-Content $termCacheFile -Raw -EA Stop | ConvertFrom-Json -EA Stop
        foreach ($p in $tc.PSObject.Properties) { $termCache[$p.Name] = @($p.Value) }
    }
} catch { $termCache = @{} }   # unreadable memo is a slow walk, not a wrong one

# KEEP THE `HEAD` LINE. This one command already reports every worktree's checked-out commit, and the
# parser used to drop it on the floor -- then the walk spawned a git per worktree to ask questions that
# are pure functions of exactly that commit id. Reading it here is what makes the term memo possible,
# and it costs nothing: the process is already running for the paths and branches.
#
# Empty Head is tolerated (an unborn checkout, or a git too old to print the line). It disables the
# memo for that worktree and the terms are computed the long way, which is slow and correct.
function Get-WorktreeList {
    $out = @(); $cur = $null
    foreach ($line in (& git @gitArgs worktree list --porcelain 2>$null)) {
        if ($line -like "worktree *") {
            $cur = [pscustomobject]@{ Path = $line.Substring(9).Trim(); Branch = ""; Head = "" }
            $out += $cur
        }
        elseif ($line -like "HEAD *" -and $cur) { $cur.Head = $line.Substring(5).Trim() }
        elseif ($line -like "branch *" -and $cur) { $cur.Branch = ($line.Substring(7).Trim() -replace '^refs/heads/', '') }
        elseif ($line -like "detached*" -and $cur) { $cur.Branch = "(detached)" }
    }
    return $out
}

# Another session's free text reaches our JSON, a hook's deny message and this console. Sanitise once,
# here, so no caller has to remember. Control characters are usually a mangled Unicode arrow rather
# than anything hostile, but they corrupt the JSON a consumer has to parse, and it is untrusted input
# either way.
function Format-Subject([string]$Text) {
    $s = ($Text -replace '[\p{C}]', ' ')
    $s = ($s -replace '\s+', ' ').Trim()
    if ($s.Length -gt 100) { $s = $s.Substring(0, 97) + "..." }
    return $s
}

# WHAT THE STORES HOLD, irrespective of any session -- the measurement that separates "this store is
# empty" from "the fleet is quiet". Run once, and only when a live session has actually been asked,
# because the walk it hangs off is already close to the collision gate's budget.
#
# BOTH HALVES, ALWAYS, even when the first one answers. Surveying the seat layer only on a task-list
# miss was the obvious saving and it broke the census: a fleet whose sessions all kept task lists got
# "0 seat record(s)" printed at it, which is a false statement about a store that was never opened,
# and it disarmed the staleness control below in exactly the case where the two ages must be compared.
# Caught by tests/test_coord_overlap_work_signal.py, not by reading this code.
function Get-StoreSurvey {
    if ($script:Census.Surveyed) { return }
    $script:Census.Surveyed = $true
    foreach ($store in $script:TaskStores) {
        if (-not (Test-Path -LiteralPath $store)) { continue }
        $script:Census.StoresPresent++
        foreach ($f in @(Get-ChildItem -LiteralPath $store -Recurse -Filter *.json -EA SilentlyContinue)) {
            $script:Census.TaskFiles++
            if ($null -eq $script:Census.TaskNewest -or $f.LastWriteTime -gt $script:Census.TaskNewest) {
                $script:Census.TaskNewest = $f.LastWriteTime
            }
        }
    }
    Get-SeatIndex | Out-Null
}

# The seat records, indexed by session id. Built once per walk, from Get-StoreSurvey above, so it is
# paid only when a live session was actually asked.
#
# A FULL SCAN AND NOT A LOOKUP, because the file is named by the session KEY, not the session id, and
# deriving that key here would be a second copy of seat.ps1's rule. Measured 2026-08-30: 692 records
# in 0.57s, which is affordable against a walk that costs tens of seconds and is paid once.
$script:SeatIndex = $null
function Get-SeatIndex {
    if ($null -ne $script:SeatIndex) { return $script:SeatIndex }
    $script:SeatIndex = @{}
    foreach ($f in @(Get-ChildItem -LiteralPath $script:SeatsDir -Recurse -Filter *.json -EA SilentlyContinue)) {
        # One malformed record must never take the walk down; a record caught mid-write has this shape.
        try { $r = Get-Content $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
        if (-not $r.sessionId) { continue }
        $script:Census.SeatRecords++
        if ($null -eq $script:Census.SeatNewest -or $f.LastWriteTime -gt $script:Census.SeatNewest) {
            $script:Census.SeatNewest = $f.LastWriteTime
        }
        # Last write wins on a duplicate id: the newer record is the one describing this run.
        $k = [string]$r.sessionId
        if (-not $script:SeatIndex.ContainsKey($k) -or $f.LastWriteTime -gt $script:SeatIndex[$k].At) {
            $script:SeatIndex[$k] = [pscustomobject]@{ Record = $r; At = $f.LastWriteTime }
        }
    }
    return $script:SeatIndex
}

# What a session says it is working on. in_progress first -- that is what it is doing NOW, which is
# what a sibling needs to know -- then the declared goal, which is a whole-session statement rather
# than a step.
function Get-SessionWork([string]$SessionId) {
    if (-not $SessionId) { return @() }
    $script:Census.Asked++
    Get-StoreSurvey
    $items = @()

    # BOTH DIRECTORY SHAPES. The full id was the old name; `session-<first 8>` is what the writer uses
    # now. Neither pattern can match the other's directories, so there is no double count.
    $short = $SessionId.Substring(0, [Math]::Min(8, $SessionId.Length))
    foreach ($store in $script:TaskStores) {
        foreach ($pattern in @("$SessionId*", "session-$short")) {
            foreach ($dir in @(Get-ChildItem -LiteralPath $store -Directory -Filter $pattern -EA SilentlyContinue)) {
                foreach ($f in @(Get-ChildItem -LiteralPath $dir.FullName -Filter *.json -EA SilentlyContinue)) {
                    try { $t = Get-Content $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
                    if ($t.status -eq "completed") { continue }
                    $items += [pscustomobject]@{
                        Subject = (Format-Subject ([string]$t.subject))
                        Status  = [string]$t.status
                        Source  = "task"
                    }
                }
            }
        }
    }
    if ($items.Count -gt 0) { $script:Census.AnsweredTasks++ }

    # The seat declaration. Only consulted when the task list said nothing, so a session keeping a live
    # task list still reports the finer-grained answer.
    if ($items.Count -eq 0) {
        $seat = (Get-SeatIndex)[$SessionId]
        if ($seat -and $seat.Record.goal) {
            $goal = Format-Subject ([string]$seat.Record.goal)
            if ($goal) {
                $script:Census.AnsweredSeat++
                $items += [pscustomobject]@{ Subject = $goal; Status = "declared"; Source = "seat" }
            }
        }
    }
    return @($items | Sort-Object @{ E = { if ($_.Status -eq "in_progress") { 0 } else { 1 } } })
}

# THE LINE THAT MAKES A DEAD STORE LOOK DIFFERENT FROM A QUIET FLEET. Every branch names what was read
# and where; none of them can print a bare zero and stop.
function Format-Census($C) {
    if (-not $C.Surveyed) {
        return "work signal: no live session to ask, so the task stores and the seat layer were not read."
    }
    # "task(s)", never "task file(s)". tests/test_coord_overlap_attribution.py selects the changed-file
    # line by searching every line for the substring "file(s)", so a census that spelled the unit out
    # would be picked up as a file count and asserted against a rule written for a different sentence.
    $ages = "newest task " + $(if ($C.TaskNewest) { ([datetime]$C.TaskNewest).ToString("yyyy-MM-dd HH:mm") } else { "none" }) +
            ", newest seat record " + $(if ($C.SeatNewest) { ([datetime]$C.SeatNewest).ToString("yyyy-MM-dd HH:mm") } else { "none" })
    $lines = @(
        "work signal: read $($C.TaskFiles) task(s) across $($C.StoresPresent) of $($C.StoresConfigured) task store(s) " +
        "and $($C.SeatRecords) seat record(s); $ages."
        "  asked $($C.Asked) live session(s): $($C.AnsweredTasks) answered from a task list, $($C.AnsweredSeat) from a seat declaration."
    )
    if ($C.StoresPresent -eq 0) {
        $lines += "  NO TASK STORE EXISTS under any config root, so the task half of this signal read nothing at all."
    }
    elseif ($C.TaskFiles -eq 0) {
        $lines += "  THE TASK STORE IS EMPTY. It holds no task for anyone, which is not the same fact as nobody working."
    }
    # THE POSITIVE CONTROL. The seat layer is written by a Stop hook on every session, so a seat record
    # newer than the newest task file by more than a day proves the fleet is active and this store is
    # not being written. Without the comparison an old task store and an idle box read identically.
    elseif ($C.SeatNewest -and $C.TaskNewest -and (([datetime]$C.SeatNewest) - ([datetime]$C.TaskNewest)).TotalDays -gt 1) {
        $days = [int]((([datetime]$C.SeatNewest) - ([datetime]$C.TaskNewest)).TotalDays)
        $lines += "  THE TASK STORE IS STALE: its newest task is $days day(s) older than the newest seat record, " +
                  "so sessions are running and nothing is writing task lists."
    }
    return ($lines -join "`n")
}

# STDERR UNDER -Json, and that is the only channel available. stdout under -Json is a JSON array with
# exactly one consumer contract -- collision_gate.ps1 treats anything that is not parseable as "the
# check did not happen" -- so a census line on stdout would break the gate outright, and a census
# object appended to the array would be a phantom row for anything that counts. The gate discards our
# stderr (`2>$null`), so this costs it nothing and still reaches a human running the same command.
function Write-CensusToStderr {
    [System.Console]::Error.WriteLine((Format-Census $script:Census))
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
        # A FENCED session outranks an unfenceable one for the same directory. UNVERIFIED is the shape a
        # crashed session's record takes once its pid is recycled -- alive, but nothing proves it is the
        # same run -- so letting one displace a genuinely LIVE record would report a ghost's id and branch
        # for a worktree somebody is really sitting in. Last-write-wins had no opinion about which it kept.
        $rank = if ($l.State -eq "LIVE") { 0 } else { 1 }
        if ($sessionsByCwd.ContainsKey($k) -and $sessionsByCwd[$k].Rank -le $rank) { continue }
        $sessionsByCwd[$k] = [pscustomobject]@{ Record = $e.Record; Rank = $rank }
    }

    $worktrees = @(Get-WorktreeList)

    # ATTRIBUTE A SESSION TO THE MOST SPECIFIC WORKTREE CONTAINING IT, not to the first one that matches.
    #
    # Linked worktrees live UNDER the primary checkout (.../MessageFoundry/.claude/worktrees/<name>), so
    # every linked worktree's path is ALSO a prefix match for the primary's row. The old rule walked the
    # session table and broke on the first hit, so the primary row was handed whichever linked-worktree
    # session the hashtable happened to enumerate first -- reporting the primary checkout as LIVE, on a
    # branch nobody was on, "building" a peer's task list. Hashtable order is not stable, so the wrong
    # answer was also a different wrong answer each run, which is why it read as noise rather than a bug.
    #
    # Longest prefix wins is the only rule that survives nesting: a session in .../worktrees/foo matches
    # both the primary and foo, and foo is the one it is actually sitting in.
    $ownerByWorktree = @{}
    foreach ($k in @($sessionsByCwd.Keys | Sort-Object)) {
        $best = $null
        foreach ($w in $worktrees) {
            $wn = ConvertTo-Norm $w.Path
            if ($k -eq $wn -or $k.StartsWith("$wn/")) {
                if ($null -eq $best -or $wn.Length -gt $best.Length) { $best = $wn }
            }
        }
        # Two sessions inside one worktree: the fenced one wins, then first by sorted cwd -- so the
        # answer is the same every run, and a ghost never displaces a session that is really there.
        if ($best) {
            $cur = $ownerByWorktree[$best]
            if ($null -eq $cur -or $sessionsByCwd[$k].Rank -lt $cur.Rank) { $ownerByWorktree[$best] = $sessionsByCwd[$k] }
        }
    }

    $script:WalkAbandoned = $false   # declared, not left to $null: the caller reads it unconditionally
    $script:WalkedCount = 0
    $script:WorktreeCount = 0

    # PLAN THE WALK BEFORE RUNNING ANY OF IT. Everything that needs this script's own scope -- the
    # caller's HEAD, the inheritor set, the memo -- is resolved into a flat job list here, so the body
    # below can run in a runspace that shares none of it.
    $jobs = @()
    foreach ($w in $worktrees) {
        $norm = ConvertTo-Norm $w.Path
        if ($norm -eq $myRootNorm) { continue }   # not a collision with yourself
        if (-not (Test-Path -LiteralPath $w.Path)) { continue }

        # $inheritors GATES THE SPAWN, not the answer. A peer holding none of my unlanded commits
        # cannot be narrowed by the third term below, so running that diff for it buys a guaranteed
        # no-op at ~50 ms on the hot path of every edit -- see the note where $inheritors is built.
        # Every branch of this guard that is uncertain runs the diff.
        $mayHaveMine = ($null -eq $inheritors) -or (-not $w.Branch) -or
            ($w.Branch -eq "(detached)") -or $inheritors.Contains($w.Branch)

        # EVERY INPUT THE COMMITTED HALF READS GOES IN THE KEY, or the memo answers a question it was
        # not asked. Those inputs are exactly three commit ids plus the one flag that decides whether
        # the third diff runs at all. Any of them unknown yields an empty key, which means "compute it".
        $key = ""
        if ($originMain -and $w.Head -and $myHead) {
            $key = "$originMain|$($w.Head)|$myHead|$(if ($mayHaveMine) { 1 } else { 0 })"
        }
        $jobs += [pscustomobject]@{
            Path = $w.Path; Branch = $w.Branch; Norm = $norm; Key = $key
            Memo = $(if ($key -and $termCache.ContainsKey($key)) { @($termCache[$key]) } else { $null })
            MyHead = $myHead; MayHaveMine = $mayHaveMine
        }
    }
    $script:WorktreeCount = $jobs.Count

    # THE DEADLINE IS ABSOLUTE, not a stopwatch reading, because the workers do not share one. Each
    # checks it before spending anything, so the walk stops on a whole number of worktrees and overshoot
    # is bounded by the slowest single worktree already in flight rather than by the whole remainder.
    $deadline = $null
    if ($TimeBudgetSeconds -gt 0) { $deadline = [datetime]::UtcNow.AddSeconds($TimeBudgetSeconds) }

    # ONE DEFINITION OF THE PER-WORKTREE BODY, run either across runspaces or straight through.
    #
    # Held as TEXT and rebuilt at the call site on purpose. A live ScriptBlock keeps an affinity to the
    # runspace that created it, so handing one to a parallel worker either throws or quietly executes
    # back on the parent thread -- which would serialise the walk while still looking parallel. Rebuild
    # from source and each worker gets its own. The text is this file's own literal, never input.
    $walkBodyText = {
        param($Job, $Deadline)
        # Not "Stop": this body catches its own failures and reports them as an unwalked worktree, and
        # a terminating error in one runspace would instead delete that worktree from the map silently.
        $ErrorActionPreference = "SilentlyContinue"
        $r = [pscustomobject]@{
            Path = $Job.Path; Committed = @(); Dirty = @(); Memoizable = $false; Skipped = $false
        }
        try {
            if ($Deadline -and [datetime]::UtcNow -ge $Deadline) { $r.Skipped = $true; return $r }

            # THE COMMITTED HALF: what this branch authored, has not landed, and the caller does not
            # already have. Three git spawns, or none at all on a memo hit.
            #
            # NEITHER diff form is correct alone, and each is wrong in the opposite direction:
            #   three-dot (origin/main...HEAD) = what the BRANCH AUTHORED. Required, because two-dot
            #     alone blames a merely-behind branch for every file main has moved underneath it.
            #   two-dot   (origin/main..HEAD)  = what still DIFFERS from main. Required, because the
            #     repo SQUASH-merges ("title (#NN)"): the squashed commit never becomes an ancestor of
            #     the branch, so the merge-base never advances and three-dot keeps crediting a landed
            #     branch with its files FOREVER. Its session then blocks that file set until someone
            #     prunes the worktree.
            # The INTERSECTION is what the branch authored AND has not yet landed. It self-clears on
            # squash, rebase and merge-commit alike. Measured 2026-07-30: two landed branches claimed 8
            # and 4 files under three-dot and 0 under the intersection, while every branch with real
            # outstanding work was unchanged (101/101, 21/21, 11/11).
            if ($null -ne $Job.Memo) { $r.Committed = @($Job.Memo) }
            else {
                $files = @()
                $ok = $true
                $authored = @(& git -C $Job.Path diff --name-only origin/main...HEAD 2>$null)
                if ($LASTEXITCODE -ne 0) { $ok = $false }
                # An EMPTY authored set makes both remaining terms dead: an intersection with nothing is
                # nothing, and the third term can only shrink it further. Skipping them is not a
                # heuristic or a sampling trade -- it is the same answer for two fewer git processes,
                # and process count is what this walk costs. Measured 2026-08-30: 33 of 162 worktrees.
                if ($ok -and $authored.Count -gt 0) {
                    $outstanding = @(& git -C $Job.Path diff --name-only origin/main..HEAD 2>$null)
                    if ($LASTEXITCODE -eq 0) {
                        $still = [System.Collections.Generic.HashSet[string]]::new(
                            [string[]]$outstanding, [System.StringComparer]::Ordinal)
                        $files += @($authored | Where-Object { $still.Contains($_) })
                    }
                    else {
                        # Fall back to the authored set if the two-dot diff fails, so a git hiccup
                        # over-blocks (safe) rather than under-blocks (silent collisions).
                        $files += $authored
                        $ok = $false
                    }

                    # AND A THIRD TERM: what the peer changed BEYOND WHAT I ALREADY HAVE.
                    #
                    # Both anchors above are origin/main, evaluated inside the peer's worktree, so
                    # neither knows anything about the session asking. A commit the CALLER authored,
                    # which the peer inherited by being cut from the caller's branch, is credited to the
                    # peer -- indistinguishable from work the peer did. Measured 2026-08-22: the gate
                    # told a session that handoff.ps1 had been "CHANGED AND COMMITTED" on a peer's
                    # branch and to check its commits. The peer had never touched the file in a commit
                    # it owned; the one commit that authored it was the reader's. So the reader went
                    # looking for a peer's conflicting commit, found only their own, and could only read
                    # that as the gate being broken -- which is how a gate stops being read, and then
                    # gets uninstalled.
                    #
                    # Three-dot, so it resolves the merge base and asks the ANCESTRY question. A tree
                    # diff (`<myHEAD> <peerHEAD>`, two arguments) is a different sentence and fails BOTH
                    # ways here: it still flags the inherited file, because our trees genuinely differ
                    # in it once I commit again, AND it credits the peer with files only I have touched.
                    #
                    # ADDED, never substituted. Re-anchoring either term above on $myHead would suppress
                    # this false positive and silently restore the squash-merge one: the two-dot term
                    # only self-clears a landed branch because it is measured against origin/main, where
                    # the squashed commit actually is. tests/test_coord_overlap_signals.py pins both.
                    #
                    # DEGRADES BY OVER-REPORTING. No $myHead, or a diff that fails, drops the term and
                    # leaves the wider set -- the same choice the two-dot fallback makes, for the same
                    # reason: an over-report is loud and annoying, an under-report is a silent collision.
                    if ($Job.MyHead -and $files.Count -gt 0 -and $Job.MayHaveMine) {
                        $beyondMine = @(& git -C $Job.Path diff --name-only "$($Job.MyHead)...HEAD" 2>$null)
                        if ($LASTEXITCODE -eq 0) {
                            $theirs = [System.Collections.Generic.HashSet[string]]::new(
                                [string[]]$beyondMine, [System.StringComparer]::Ordinal)
                            $files = @($files | Where-Object { $theirs.Contains($_) })
                        }
                        else { $ok = $false }
                    }
                }
                # ONLY A CLEAN RUN IS MEMOISABLE. The key names commit ids and never expires, so an
                # entry written from a degraded run would be replayed as the exact answer forever.
                $r.Committed = @($files)
                $r.Memoizable = $ok
            }

            # --no-optional-locks: a plain `git status` REWRITES the index of the repo it inspects, and
            # this walks every peer worktree -- so merely asking "what is in flight" would mutate other
            # sessions' checkouts. Read-only is mandatory for an observer.
            #
            # RUN EVERY WALK, NEVER MEMOISED. See the note on $termCache: a working-tree edit moves
            # nothing cheap, so this spawn is the price of the signal the gate actually blocks on.
            $dirty = @(& git -C $Job.Path --no-optional-locks status --porcelain 2>$null |
                Where-Object { $_.Length -gt 3 } | ForEach-Object { $_.Substring(3).Trim('"') })
            $r.Dirty = @($dirty | Where-Object { $_ } | Sort-Object -Unique)
        } catch { $r.Skipped = $true }
        return $r
    }.ToString()


    $results = @()
    if ($jobs.Count -gt 0) {
        if ($ParallelLimit -gt 1) {
            $results = @($jobs | ForEach-Object -ThrottleLimit $ParallelLimit -Parallel {
                    $sb = [scriptblock]::Create($using:walkBodyText)
                    & $sb $_ $using:deadline
                })
        }
        else {
            $sb = [scriptblock]::Create($walkBodyText)
            $results = @($jobs | ForEach-Object { & $sb $_ $deadline })
        }
    }

    # REASSEMBLE IN JOB ORDER. Parallel results arrive in completion order, and a map whose rows shuffle
    # between runs reads as churn to anyone diffing two of them.
    $byPath = @{}
    foreach ($x in $results) { if ($x) { $byPath[$x.Path] = $x } }

    $rows = @()
    $fresh = @{}
    foreach ($w in $jobs) {
        $res = $byPath[$w.Path]
        # A worktree that was never reached, or whose body failed, leaves the map INCOMPLETE -- which is
        # the same condition as an overrun and is reported the same way. Dropping it quietly would be
        # the under-report this script exists to prevent.
        if ($null -eq $res -or $res.Skipped) { $script:WalkAbandoned = $true; continue }
        $script:WalkedCount++
        if ($res.Memoizable -and $w.Key) { $fresh[$w.Key] = @($res.Committed) }

        $norm = $w.Norm
        $files = @($res.Committed)
        $dirty = @($res.Dirty)
        $files += $dirty
        $files = @($files | Where-Object { $_ } | Sort-Object -Unique)

        # A session sitting anywhere INSIDE the worktree owns it, not just one whose cwd is the root --
        # resolved above, against every worktree at once, because "inside" is ambiguous when they nest.
        $sess = if ($ownerByWorktree.ContainsKey($norm)) { $ownerByWorktree[$norm].Record } else { $null }
        if ($files.Count -eq 0 -and -not $sess) { continue }

        # Resolved ONCE per row, not twice inside the object literal. Get-SessionWork counts what it
        # read into the census, so calling it a second time for the source column would double every
        # number the census reports.
        $work = @(Get-SessionWork $(if ($sess) { [string]$sess.sessionId } else { "" }))

        $rows += [pscustomobject]@{
            Worktree  = Split-Path $w.Path -Leaf
            Path      = $w.Path
            Branch    = $w.Branch
            Live      = [bool]$sess
            SessionId = if ($sess) { [string]$sess.sessionId } else { "" }
            Short     = if ($sess -and $sess.sessionId) { ([string]$sess.sessionId).Substring(0, 8) } else { "" }
            Surface   = if ($sess) { ([string]$sess.entrypoint) -replace '^claude-', '' } else { "" }
            Files     = $files
            # Files is the UNION of (committed-and-unlanded MINUS what the caller already has) and
            # working-tree, so the committed half is RELATIVE TO WHOEVER ASKED -- see the FILES entry
            # in the header. A caller that must distinguish "someone is typing in this file right now"
            # from "this branch authored it and is done" cannot do it from Files -- and this script's
            # own contract (see LIVE vs DORMANT above) tells callers to treat signals differently,
            # which was not honourable until now.
            # Reported 2026-08-01: a session that had COMMITTED a file, gone clean, and said in writing
            # it was finished still blocked every other session from that file, because a committed
            # file stays in Files until the branch lands -- and while PRs cannot merge, that is forever.
            Dirty     = $dirty
            # Work stays a plain string array: collision_gate.ps1 renders it straight into a deny
            # message, and a shape change there would be a silent break in the one consumer that
            # matters. WorkSource is the parallel array saying where each entry came from, added
            # rather than folded into the text so the strings themselves are unchanged.
            Work       = @($work | ForEach-Object { $_.Subject })
            WorkSource = @($work | ForEach-Object { $_.Source })
        }
    }

    # PRUNE TO WHAT THIS WALK COULD STILL USE. Keys carry commit ids, so a worktree that moved leaves
    # its old entry unreachable forever; keeping only the keys this walk planned bounds the file at the
    # worktree count instead of growing it once per commit anybody makes.
    #
    # WRITTEN EVEN AFTER AN OVERRUN, unlike the whole-map cache. Every entry is content-addressed, so a
    # partial walk contributes exact answers for the worktrees it reached and carries the rest forward
    # untouched. There is no under-report to pin, which is the only reason the other cache is withheld.
    try {
        $keep = @{}
        foreach ($w in $jobs) {
            if (-not $w.Key) { continue }
            if ($fresh.ContainsKey($w.Key)) { $keep[$w.Key] = $fresh[$w.Key] }
            elseif ($termCache.ContainsKey($w.Key)) { $keep[$w.Key] = $termCache[$w.Key] }
        }
        New-Item -ItemType Directory -Force -Path (Split-Path $termCacheFile) | Out-Null
        $keep | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $termCacheFile -Encoding UTF8
    } catch { }   # a memo we cannot write is a slow walk, not a broken one

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
        #
        # KEYED ON $myHead AS WELL AS $myRootNorm, because Files now depends on it. Root alone was NOT
        # already sufficient, which is worth stating because it looks like it should be: the root is
        # what identifies the querying worktree, but the third intersect term above is a function of
        # that worktree's HEAD, and HEAD moves under a fixed root every time the caller commits. Left
        # out, the map would be answered from a walk computed at the previous HEAD for the rest of the
        # window. That errs toward over-reporting (an older HEAD yields a merge base no newer, so the
        # term is no smaller), so it is not a collision risk -- but a cache whose value depends on an
        # input its key does not name is a cache that lies, and the fix is one field. A cache written
        # before this field existed reads back as $null, misses, and re-walks once.
        if ($age -ge 0 -and $age -lt $CacheSeconds -and $c.root -eq $myRootNorm -and
            [string]$c.head -eq $myHead) {
            $map = @($c.rows)
            # CARRIED, NEVER RE-DERIVED. The census counts what the WALK read, and a cache hit does no
            # reading at all -- so recomputing it here would print zeros beside rows that do carry work,
            # which is the exact "empty store reads as quiet fleet" confusion this census exists to end.
            # A cache written before this field existed reads back null and the census says so.
            if ($c.census) { foreach ($k in @($script:Census.Keys)) { if ($null -ne $c.census.$k) { $script:Census[$k] = $c.census.$k } } }
        }
    } catch { $map = $null }
}
if ($null -eq $map) {
    # @() for the SAME reason Write-JsonArray filters nulls, at the other end of the same round trip.
    # A bare `$map = Build-Map` survives in process -- assignment preserves AutomationNull, so the
    # zero-rows guard below still fires -- but it serializes into the cache as `"rows": null`, and the
    # next run reads that back as `@($null)`, a ONE-element array holding $null. Count is then 1, the
    # guard does not fire, and the table prints a phantom occupant. The hook arms this constantly:
    # collision_gate.ps1 runs `overlap.ps1 -File ... -Json` on every gated edit and the cache is written
    # before the -File early exit, so any bare `overlap.ps1` inside $CacheSeconds inherits it.
    $map = @(Build-Map)
    $script:MapPartial = [bool]$script:WalkAbandoned
    # OVERRAN THE BUDGET: keep the rows, stamp every one of them, exit 3, and DO NOT CACHE. The rows are
    # what the walk actually established and throwing them away cannot make the walk complete -- it only
    # loses the collisions it did find. The cache is the one thing withheld, because a stored
    # under-report would answer every query for the whole window as though the walk had finished.
    if ($script:MapPartial) {
        foreach ($r in $map) {
            $r | Add-Member -NotePropertyName Partial -NotePropertyValue $true -Force
            $r | Add-Member -NotePropertyName Walked -NotePropertyValue $script:WalkedCount -Force
            $r | Add-Member -NotePropertyName Total -NotePropertyValue $script:WorktreeCount -Force
        }
    }
    else {
        try {
            New-Item -ItemType Directory -Force -Path (Split-Path $cacheFile) | Out-Null
            # Last-write-wins on purpose: a duplicate walk is the only cost of a race, and a lock on the
            # hot path of every edit would be worse than the thing it protects.
            #
            # `census` rides along because a cache HIT prints one too. Without it a warm run would show
            # the rows and silently drop the work signal, which is the reading this field exists to give.
            @{ at = (Get-Date).ToString("o"); root = $myRootNorm; head = $myHead; rows = $map
               census = $script:Census } |
                ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $cacheFile -Encoding UTF8
        } catch { }   # a cache we cannot write is a slow hook, not a broken one
    }
}

# EXIT 3 SURVIVES EVERY OUTPUT PATH BELOW. The rows are a warning, never a verdict, and the exit code is
# what says so -- so no branch may reach `exit 0` on a partial walk just because it printed something.
function Exit-Overlap { if ($script:MapPartial) { exit 3 }; exit 0 }

# THE HUMAN HAS NO EXIT CODE. A person reads the table, not $LASTEXITCODE, so for them the whole signal
# has to be in the text -- and it goes FIRST, because a reader who finds what they were looking for in
# the rows below stops reading. It states the coverage rather than just the word "partial": "walked 40
# of 162" is a fact someone can act on, where "incomplete" invites them to assume it was nearly done.
#
# IT ALSO GOES ABOVE THE CENSUS, and the order is deliberate. The census reports what the work signal
# read; the banner reports that the WALK ITSELF did not finish. A reader who takes the census as the
# scope of the run would read a partial walk as a complete one with little to say.
function Write-PartialBanner {
    if (-not $script:MapPartial) { return }
    Write-Host ""
    Write-Host "PARTIAL MAP -- walked $($script:WalkedCount) of $($script:WorktreeCount) worktrees before running out of time."
    Write-Host "The rest were NOT checked. Nothing below is an all-clear: a peer in an unwalked worktree"
    Write-Host "cannot appear here at all. Re-run with -TimeBudgetSeconds 0 for the complete answer."
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
    # ALWAYS EMIT AN ARRAY. `@() | ConvertTo-Json -AsArray` sends ZERO objects down the pipeline, so
    # ConvertTo-Json never runs and the script prints NOTHING -- despite -AsArray, which only shapes
    # output that exists. "Nobody else is in this file" therefore looked identical on stdout to "this
    # script died before it could answer", and a consumer had no way to tell an all-clear from a
    # failure. (-InputObject is not the fix: with -AsArray it double-wraps to [[]].) Measured
    # 2026-08-02 against the real script.
    if ($Json) { Write-CensusToStderr; (Write-JsonArray $hits); Exit-Overlap }
    Write-PartialBanner
    Write-Host (Format-Census $script:Census)
    foreach ($h in $hits) {
        $state = if ($h.Live) { "LIVE $($h.Surface) session $($h.Short)" } else { "dormant worktree" }
        Write-Host "  $File is also changed by $state in $($h.Worktree) [$($h.Branch)]"
    }
    Exit-Overlap
}

if ($Json) { Write-CensusToStderr; (Write-JsonArray $map); Exit-Overlap }

Write-PartialBanner
# "No other worktree has changes" IS A FINDING, and only a complete walk is entitled to state it. After
# an overrun the banner above has already said the opposite, so this line must not follow it.
if (@($map).Count -eq 0) {
    # The census goes ABOVE the all-clear, because this is exactly the line a dead work signal hides
    # behind: "no other worktree has changes" is a claim about git, and a reader takes it as a claim
    # about the fleet unless the sentence before it says what was actually read.
    Write-Host (Format-Census $script:Census)
    if (-not $script:MapPartial) { Write-Host "No other worktree has changes." }
    Exit-Overlap
}
Write-Host ""
Write-Host (Format-Census $script:Census)
foreach ($r in $map) {
    # "session" here too (BACKLOG #1310). Unlabelled, this column ends in an 8-hex token and the column
    # beside it is a branch name -- the shape of an abbreviated commit hash, and read as one on
    # 2026-08-22 when the collision gate re-rendered the same value into prose.
    #
    # The word goes on the ROW here because these rows are NOT uniform: a dormant peer prints just
    # "dormant" in this column, so a header could not govern every row. presence.ps1 carries the same
    # value in a table whose rows ARE uniform and labels it from a header instead (BACKLOG #1098).
    # Both are right for their own table; neither is the general rule.
    $who = if ($r.Live) { "LIVE $($r.Surface) session $($r.Short)" } else { "dormant" }
    Write-Host ("{0,-38} {1,-38} {2}" -f $r.Worktree, $r.Branch, $who)
    # The SOURCE is named on every line. "building: X" from a live task list and "building: X" from a
    # goal declared hours ago are different claims about how current X is, and a reader deciding
    # whether to interrupt someone needs to know which one they are looking at.
    for ($i = 0; $i -lt [Math]::Min(3, @($r.Work).Count); $i++) {
        $src = if (@($r.WorkSource)[$i]) { @($r.WorkSource)[$i] } else { "task" }
        Write-Host ("    building ({0}): {1}" -f $src, @($r.Work)[$i])
    }
    # "beyond yours", not "changed": the committed half of Files is narrowed by the querying HEAD, so
    # this count is relative to the caller. See the FILES entry in the header.
    Write-Host ("    {0} changed file(s) beyond yours" -f @($r.Files).Count)
}
Write-Host ""
