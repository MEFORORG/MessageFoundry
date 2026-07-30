<#
.SYNOPSIS
    Prune sibling git worktrees that are merged, clean, AND unoccupied.

.DESCRIPTION
    Automates the recurring cleanup so finished worktrees don't pile up.

    THE RULE IS:  prune = merged AND clean AND NOT occupied.
    Occupancy is a VETO ONLY. It can stop a removal; it can never authorise one. There is no heartbeat
    anywhere on this host, so nothing here can PROVE a session is gone -- a DEAD/STALE/absent verdict is
    the absence of a veto, not a permission. When the fence cannot look at all, nothing is pruned.

    Enumerates the <repo>-<name> sibling worktrees that new.ps1 creates and removes each one that is ALL
    of:

      (a) merged     -- no commits beyond origin/main, OR a merged PR whose head is this exact tip, OR
                        its OWN upstream branch is gone (squash-merged + remote-deleted),
      (b) clean      -- no uncommitted tracked changes AND no untracked files (see below),
      (c) unlocked   -- `git worktree lock` is git's own "in use" flag and this script honours it,
      (d) unoccupied -- no live Claude session is sitting in it OR in a worktree nested inside it, its
                        git metadata has not been touched within -IdleHours, and it does not contain
                        another registered worktree.

    "SIBLING" IS NOT A PREFIX MATCH. The candidate set used to be every registered worktree whose path
    starts with `<primary>-`, which silently includes `<primary>-pins/.claude/worktrees/x` -- a
    CLAUDE-MANAGED nested worktree, the exact place EnterWorktree relocates a live session to, and the
    one population this header promised never to touch. Nested trees under the PRIMARY escaped only by
    the accident that `<primary>/` is not `<primary>-`. Now anything living inside another registered
    worktree, and anything with a `.claude/worktrees/` path segment, is excluded outright and listed as
    a non-candidate. -Name cannot reach them either.

    THIS TOOL DESTROYS OTHER SESSIONS' WORK IF IT IS WRONG. It removed an occupied worktree once:
    `git worktree remove --force` deleted the .git pointer, deregistered the tree, then failed to
    delete the directory, leaving a folder git no longer recognised -- the session working there had
    every subsequent git command fail. So the bias here is fixed and not negotiable: a false SKIP is a
    minor annoyance, a false PRUNE destroys a session. Every check that cannot reach a confident
    answer SKIPs. Nothing is ever traded for tidiness.

    OCCUPANCY IS NOT IMPLIED BY CLEAN+MERGED. A session can sit in a worktree with nothing
    uncommitted -- a brand-new worktree has zero commits, so it is "an ancestor of origin/main" and
    perfectly clean from the second it is created, which is exactly the state that got destroyed. THREE
    independent occupancy signals are therefore required, and any one of them vetoes:

      1. THE LIVENESS FENCE (scripts/coord/occupancy.ps1, shared with presence.ps1). Reads
         <config-root>/sessions/<pid>.json, maps each session's recorded cwd onto a worktree, and
         fences it on pid + process start time. Only LIVE / UNVERIFIED / UNREADABLE veto, for the
         veto-only reason above. A session in a NESTED worktree vetoes its ancestor too.
      2. RECENT ACTIVITY (-IdleHours, default 36). Newest mtime of the worktree's PRIVATE git metadata
         (index, HEAD, logs/HEAD, ...). Does not depend on a recorded cwd. If it cannot be read, that
         is a veto too. Confirm a specific worktree past this veto with -Name <slug>; -Name never
         overrides signals 1 or 3, a nested worktree, or a lock.
      3. THE WRITE FOOTPRINT (scripts/coord/footprint.ps1, -FootprintHours, default 36). Reads Claude
         Code's own transcripts and places a session by where it actually WROTE, which is the question
         signal 1 was never able to answer. It exists because signal 1 was measured contributing
         NOTHING to this tool's decisions: of the writes landing in a `<primary>-<slug>` sibling on
         this repo, 88.9% came from a session whose recorded cwd was a different checkout, and signal 1
         placed a session inside 0 of the 4 siblings that existed when it was measured. Measured after
         (2026-07-30, real repo, 7 candidates): signal 1 = 1 of 7, signal 3 = 6 of 7, and the five it
         adds include three worktrees a session that is LIVE RIGHT NOW had written 257 times between
         them from a cwd of the PRIMARY, plus one being written into from a checkout of an entirely
         different repository. Like signal 1 it can only veto, and -Name cannot override it.
         WHAT THAT NUMBER IS AND IS NOT, because it is a placement count and reads like a protection
         delta: at the DEFAULT windows, every candidate signal 3 covered had also had its git metadata
         touched more recently than its last tool-call write, so signal 3's veto set was a strict
         SUBSET of signal 2's and the unattended default-flag run behaved identically without it. That
         is an empirical fact about one afternoon, not a structural one -- a session editing files
         without running a git command is seen by signal 3 and not by signal 2 -- but the measured
         value of signal 3 today is concentrated where signal 2 is off or narrowed: -Name, a reduced
         -IdleHours, and the per-candidate re-check during -Apply.

    WHAT THE FENCE CANNOT SEE (printed on every run, because a fence believed to be wider than it is
    is worse than no fence):
      * a write by anything that is not a Claude tool call -- a human editing in an editor, an
        autosave, a plain terminal, a process spawned by a tool call and still running after it
        returned. Those appear in no transcript, so signal 3 is blind to them and signal 2 sees them
        only if they touch git metadata;
      * a file written BY a shell command: the transcript records the command string, not a resolved
        path list, and this deliberately does not try to parse one out of it;
      * a session that never registered AND never wrote through a tool call;
      * a session whose writes fall outside -FootprintHours while its git metadata is outside
        -IdleHours: both windows have to be open for either to see it.
    A cwd recorded as a UNC (\\host\C$\...) or 8.3 short path still defeats signal 1's string compare,
    but signal 3 resolves a written path through .git and does not share that blind spot.
    It DOES see VS Code sessions: the file registry carries every surface, and the match is purely
    path-based (the Desktop app's own session tooling only lists what it spawned).

    FENCE UNAVAILABLE => NOTHING IS PRUNED, LOUDLY (exit 2). "The fence found nobody" and "the fence
    could not look" are the same empty answer, so availability is checked explicitly and ANDed across
    both record-based sources: at least one config root with a session registry, at least one readable
    record, NO record that failed to parse (an unparseable record's cwd is unknowable, so it cannot be
    cleared from any candidate -- and a file caught half-written is precisely what a session that
    launched a second ago looks like), and no transcript fault behind signal 3 (an unreadable
    transcript, a torn line, or its canary reporting that the format has moved). When it is unavailable
    every candidate becomes SKIP and the run exits non-zero rather than silently pruning unfenced. The
    fence is re-read IN FULL before EACH removal -- every source, per candidate, not once for the loop
    -- so a session that arrives during an earlier removal still stops the later ones; it used to be
    read once, which left the only signal with measured coverage stale for candidates 2..N while the
    36 h metadata guess was the fresh one. There is deliberately no override flag.

    A SIGNAL THAT SAW NOTHING SAYS SO, RATHER THAN REPORTING A BARE ZERO. "0 candidates vetoed" reads
    as "nobody is anywhere" and sends an operator to -Name; "3 of 5 candidates have no footprint, so
    for those this signal contributed nothing" is the same number and the opposite instruction. Both
    per-signal veto counts and the count of candidates no signal covered are on every run.

    EVERYTHING THAT NARROWS THE FENCE IS DECLARED IN RED, on the run and in the JSON receipt --
    -IdleHours 0, an -IdleHours below the 12h floor (an occupied worktree has been measured at 10.4h,
    so anything under that releases trees that measurement says are in use), an explicit -ConfigRoot,
    a FAILED fetch (merge decisions then rest on stale refs), a gh PR probe that errored, and every
    -Name-confirmed worktree. -Name is the one worth spelling out: it is -IdleHours 0 scoped to one
    tree, and since signal 1 has been measured vetoing 0 of 4 real siblings, `-Apply -Name <slug>` can
    leave a candidate with no working occupancy signal at all. It stays available because there are
    legitimate uses, but it is never silent -- an operator who believes they are fenced when they are
    not is worse off than one who knows they aren't.

    OUTCOMES, NOT INTENTIONS. The summary counts what actually happened -- removed / failed / skipped,
    branches deleted / kept -- because a destructive tool that over-reports what it destroyed is
    actively misleading (it used to print the count of candidates it INTENDED to remove). A removal is
    only counted as removed once the directory is verified gone and deregistered. A failed removal is
    diagnosed on the spot: git deregisters a worktree even when it cannot finish deleting the files, so
    this reports whether the directory, its .git pointer and its registration survived, and prints the
    recovery recipe for the orphaned case. `git worktree prune` is never run -- it deregisters ANY
    worktree whose directory is momentarily missing, including the .claude/worktrees ones this script
    must never touch, and it would finish the destruction a failed removal left half done.

    AN ORPHAN OUTLIVES THE RUN THAT MADE IT, SO IT IS REMEMBERED. Once git has deregistered a worktree
    it is no longer in `git worktree list`, so it drops out of the candidate set and the NEXT run
    reported a green all-clear over a directory this script had broken -- the recovery recipe existed
    only in the first run's scrollback. Every orphan is now recorded in <git-common-dir>/
    prune-merged-orphans.json and re-reported, with the recipe, on every subsequent run until the
    directory is gone or re-registered. A directory that still carries a .git FILE pointing into this
    repo's worktree admin area while git no longer lists it is reported the same way, ledger or not.

    EXIT CODES, highest severity wins: 0 nothing wrong; 1 something was attempted and failed without
    destroying anything; 2 REFUSED -- nothing was attempted because safety could not be established
    (bad cwd, unavailable fence, a -Name that matched nothing); 3 ORPHANED -- a directory is broken on
    disk right now and needs the recovery recipe. 3 outranks 2 because damage on disk outranks a
    refusal to act.

    A BRANCH IS NEVER FORCE-DELETED ON A STALE VERDICT. `git branch -d` refuses a branch merged only
    into origin/main when the local main lags, so `-D` used to be the ROUTINE path and git's last
    protection was overridden every time. Now: `-d` first, and `-D` only after re-verifying, at that
    moment, that `origin/main..<branch>` is empty -- i.e. every commit on it is already reachable from
    origin/main and the delete cannot lose anything. Otherwise the BRANCH IS KEPT and reported. A stale
    ref costs nothing; a destroyed commit costs a session.

    DRY-RUN by default: prints the decision table and does nothing. -Apply re-evaluates everything
    from scratch in the same run and acts on THAT table, never on a table you read a minute ago.

    NEVER touches: the primary checkout, the .claude/worktrees Claude-managed worktrees, the Temp
    scratchpad worktrees, detached worktrees, or the separate sibling REPOS living beside this one.
    Must be run FROM the primary checkout; it refuses loudly anywhere else rather than reporting
    "nothing to consider". See docs/WORKTREES.md.

.EXAMPLE
    scripts\worktree\prune-merged.ps1                      # dry run: the decision table, no action
    scripts\worktree\prune-merged.ps1 -Fetch               # dry run, refreshing origin/* first
    scripts\worktree\prune-merged.ps1 -Apply               # remove the ones that pass every check
    scripts\worktree\prune-merged.ps1 -Apply -Name pins    # also confirm past the activity veto
    scripts\worktree\prune-merged.ps1 -Apply -SkipFetch    # offline / faster
    scripts\worktree\prune-merged.ps1 -Json                # machine-readable decisions + receipt
#>
[CmdletBinding()]
param(
    # Actually remove. Default is a dry run.
    [switch]$Apply,
    # Skip the `git fetch --prune` even under -Apply (offline / speed). Stale refs decide the merge test.
    [switch]$SkipFetch,
    # Fetch during a DRY RUN too. Off by default: fetch --prune rewrites remote-tracking refs, which is
    # what turns an upstream into [gone] -- a "safe, does nothing" preview should not enlarge the next
    # apply's blast radius.
    [switch]$Fetch,
    # Restrict to these worktrees (slug `<repo>-<name>` or bare `<name>`), and confirm them past the
    # recent-activity veto. Never overrides the liveness fence, a nested worktree, or a worktree lock.
    [string[]]$Name,
    # Don't ask gh about merged PRs (offline, or no gh).
    [switch]$SkipGh,
    # Emit JSON: the same decision objects the table renders, plus the fence receipt and the counts.
    [switch]$Json,
    # Repo to operate on. Defaults to this script's own checkout; tests point it at a fixture so the
    # real logic is what gets exercised.
    [string]$RepoRoot,
    # Config roots for the liveness fence. Defaults to every <userprofile>\.claude* registry. Setting it
    # explicitly REPLACES the real registry, so the run is reported as reduced-assurance.
    [string[]]$ConfigRoot,
    # A worktree whose git metadata was touched more recently than this is treated as occupied. Default
    # 36h: longer than any plausible working day, because this is the only signal that sees a session
    # writing in by absolute path, and it was once measured within 1.6h of expiring on two OCCUPIED
    # worktrees. 0 turns signal 2 OFF and the run says so in red -- and so does anything under the 12h
    # floor, because only the literal 0 used to be declared: `-IdleHours 0.5`, typed for "half an hour",
    # released every worktree on this repo and printed no warning at all.
    [double]$IdleHours = 36,
    # How far back the write-footprint source (signal 3) reads the transcript corpus. Separate from
    # -IdleHours on purpose: -IdleHours 0 is a declared way to turn the crude metadata heuristic off,
    # and it must not take the signal with actual measured coverage down with it. A footprint that
    # cannot be fenced against a live pid vetoes until it ages out of THIS window, so shortening it
    # releases worktrees whose last writer cannot be proven gone.
    [double]$FootprintHours = 36,
    # Liveness fence tolerance, passed through to the shared fence.
    [int]$StartSkewMinutes = 15,
    # The ref a branch must be merged into.
    [string]$MainRef = 'origin/main'
)

$ErrorActionPreference = "Stop"
# This script decides what to destroy from git EXIT CODES (a non-zero `rev-list`, `branch -d`, or
# `worktree remove` is data, not a failure). Never let a native non-zero exit turn into a throw.
$PSNativeCommandUseErrorActionPreference = $false

# The cwd -> worktree matcher, the liveness fence, and the availability receipt. One copy, shared with
# presence.ps1: two copies of a safety check drift, and the copy that drifts is the untested one.
. "$PSScriptRoot\..\coord\occupancy.ps1"

$EXIT_OK = 0
$EXIT_FAILED = 1   # something was attempted and did not fully succeed
$EXIT_REFUSED = 2  # nothing was attempted, because safety could not be established
$EXIT_ORPHANED = 3 # a directory is broken on disk right now (this run, or one before it)

# The MOST SEVERE outcome decides the code, and severity is the numeric order above. A run that
# refuses AND leaves an orphan must report the orphan: a refusal costs the operator a re-run, a broken
# directory costs a session every git command it tries.
$exit = $EXIT_OK
function Set-Exit([int]$Code) { if ($Code -gt $script:exit) { $script:exit = $Code } }

# The floor under -IdleHours. Signal 2 has been measured at 10.4h on a worktree that was demonstrably
# occupied, so a window under this one releases trees that measurement says are in use.
$IDLE_FLOOR_HOURS = 12
# The same floor under -FootprintHours, and it exists for the same measured reason: `-IdleHours 0.5`,
# typed for "half an hour", released every worktree on this repo and printed no warning at all -- and
# the new knob shipped with exactly that hole. Measured on the real repo: `-FootprintHours 0.5` took
# signal 3 from 5 vetoes to 2 with an EMPTY reducedAssurance, while the -Name banner in the same run
# asserted "signals 1 and 3 still apply". Only the literal 0 and a negative value were ever declared.
$FOOTPRINT_FLOOR_HOURS = 12

function Write-Note([string]$Text, [string]$Colour = 'DarkGray') {
    if (-not $Json) { Write-Host $Text -ForegroundColor $Colour }
}

# --- Resolve and validate where we are ----------------------------------------------------------
if (-not $RepoRoot) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
elseif (-not (Test-Path -LiteralPath $RepoRoot)) { throw "RepoRoot does not exist: $RepoRoot" }
else { $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path }

# A negative -IdleHours puts the cut-off in the FUTURE, so `$activity -gt $idleCut` can never fire and
# signal 2 is silently dead. Refuse rather than run with a disarmed veto that still looks armed.
if ($IdleHours -lt 0) {
    if ($Json) { @{ error = 'IdleHours must be >= 0'; idleHours = $IdleHours; exitCode = $EXIT_REFUSED } | ConvertTo-Json -Depth 4 | Write-Output }
    else { Write-Host "REFUSED: -IdleHours $IdleHours is negative, which would disarm the activity veto while appearing to set it." -ForegroundColor Red }
    exit $EXIT_REFUSED
}

if ($FootprintHours -lt 0) {
    if ($Json) { @{ error = 'FootprintHours must be >= 0'; footprintHours = $FootprintHours; exitCode = $EXIT_REFUSED } | ConvertTo-Json -Depth 4 | Write-Output }
    else { Write-Host "REFUSED: -FootprintHours $FootprintHours is negative, which would put the window in the future and disarm signal 3 while appearing to set it." -ForegroundColor Red }
    exit $EXIT_REFUSED
}

$occ = Get-WorktreeOccupancy -Repo $RepoRoot -ConfigRoot $ConfigRoot -StartSkewMinutes $StartSkewMinutes `
    -IncludeFootprints -FootprintHours $FootprintHours -IncludePins

if (-not $occ.RepoFound) {
    if ($Json) { @{ error = 'not a git repository'; repoRoot = $RepoRoot; exitCode = $EXIT_REFUSED } | ConvertTo-Json -Depth 4 | Write-Output }
    else { Write-Host "REFUSED: $RepoRoot is not inside a git repository." -ForegroundColor Red }
    exit $EXIT_REFUSED
}

# Run from the primary, and say so when you are not. The old script silently found no `<self>-*`
# siblings from inside a worktree and printed a green "nothing to consider", which reads exactly like
# "everything is tidy".
if ((ConvertTo-Norm $RepoRoot) -ne (ConvertTo-Norm $occ.PrimaryPath)) {
    if ($Json) {
        @{ error = 'not the primary checkout'; repoRoot = $RepoRoot; primary = $occ.PrimaryPath; exitCode = $EXIT_REFUSED } |
            ConvertTo-Json -Depth 4 | Write-Output
    }
    else {
        Write-Host "REFUSED: this is a linked worktree, not the primary checkout." -ForegroundColor Red
        Write-Host "  here:    $RepoRoot" -ForegroundColor Red
        Write-Host "  primary: $($occ.PrimaryPath)" -ForegroundColor Red
        Write-Host "  Sibling worktrees are named after the PRIMARY, so from here the candidate set is" -ForegroundColor Red
        Write-Host "  empty for the wrong reason. Re-run it from the primary." -ForegroundColor Red
    }
    exit $EXIT_REFUSED
}

$RepoRootFwd = ($RepoRoot -replace '\\', '/')
$RepoLeaf = Split-Path $RepoRoot -Leaf
# The extra sources' own receipts. Read here, before the reduced-assurance notices are assembled:
# they were assigned further down and every notice about them evaluated against $null.
$fp = $occ.Footprint
$pinSet = $occ.PinSet

# Anything that narrows what the two occupancy signals can see. Named on the run and in the JSON, so a
# reduced fence is never mistaken for a full one.
$activityVeto = ($IdleHours -gt 0)
$reducedAssurance = @()
if (-not $activityVeto) {
    $reducedAssurance += 'activity veto DISABLED (-IdleHours 0): signal 2 is OFF, so a session that touched git metadata but wrote nothing through a tool call is invisible to this run'
}
elseif ($IdleHours -lt $IDLE_FLOOR_HOURS) {
    # Only the literal 0 used to be declared. Everything between 0 and the floor disarmed signal 2 just
    # as effectively and printed nothing.
    $reducedAssurance += "activity window NARROWED to $IdleHours h (floor $IDLE_FLOOR_HOURS h): an OCCUPIED worktree has been measured at 10.4 h idle, so signal 2 will release trees somebody is in"
}
if ($ConfigRoot) {
    $reducedAssurance += "liveness fence scoped to an explicit -ConfigRoot ($($ConfigRoot -join ', ')): the machine's real session registry was NOT consulted"
}
# Signal 3's window, declared on exactly the same terms as signal 2's. A footprint that cannot be
# fenced against a live pid vetoes until it ages out of THIS window, so narrowing it releases
# worktrees whose last writer cannot be proven gone.
$footprintVetoOn = ($FootprintHours -gt 0)
if (-not $footprintVetoOn) {
    $reducedAssurance += 'write footprint DISABLED (-FootprintHours 0): signal 3 is OFF, so a session writing into a worktree by absolute path from another checkout is invisible to this run'
}
elseif ($FootprintHours -lt $FOOTPRINT_FLOOR_HOURS) {
    $reducedAssurance += "footprint window NARROWED to $FootprintHours h (floor $FOOTPRINT_FLOOR_HOURS h): signal 3 will release a worktree whose last tool-call write is older than that, and it is the only signal with measured coverage of a cross-checkout writer"
}
# How signal 3 must be DESCRIBED elsewhere in this run. The -Name banner below used to assert
# "signals 1 and 3 still apply" unconditionally, which is false the moment another flag has narrowed
# or disabled signal 3 -- and the only warning an operator saw was that false one.
$sig3State =
if (-not $footprintVetoOn) { 'signal 3 is OFF (-FootprintHours 0)' }
elseif ($FootprintHours -lt $FOOTPRINT_FLOOR_HOURS) { "signal 3 is NARROWED to $FootprintHours h" }
else { 'signal 3 still applies' }

# --- Refresh refs (see -Fetch) -------------------------------------------------------------------
$fetched = $false
$fetchDetail = ''
if ($SkipFetch) { $fetchDetail = 'skipped (-SkipFetch): merge decisions use whatever refs are on disk' }
elseif (-not ($Apply -or $Fetch)) { $fetchDetail = 'skipped (dry run): pass -Fetch to refresh origin/* first' }
else {
    Write-Note "Fetching origin (--prune)..."
    & git -C $RepoRoot fetch origin --prune --quiet 2>$null
    if ($LASTEXITCODE -eq 0) { $fetched = $true; $fetchDetail = 'origin fetched (--prune)' }
    else {
        $fetchDetail = "FETCH FAILED (exit $LASTEXITCODE): merge decisions are being made against stale refs"
        # Its own text says the merge decisions rest on stale refs, which IS reduced assurance. It used
        # to render in the same dark grey as "-SkipGh", below the notice an operator actually reads.
        $reducedAssurance += $fetchDetail
    }
}

# --- Merge signal --------------------------------------------------------------------------------
function Get-GitHubSlug([string]$Repo) {
    $url = & git -C $Repo remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $url) { return $null }
    if ($url -match '^(?:https?://[^/@]*@?[^/]*github\.com/|git@github\.com:|ssh://git@github\.com/)(?<o>[^/]+)/(?<r>[^/]+?)(?:\.git)?/?$') {
        return "$($Matches['o'])/$($Matches['r'])"
    }
    return $null
}

$ghSlug = if ($SkipGh) { $null } else { Get-GitHubSlug $RepoRoot }
$hasGh = (-not $SkipGh) -and $ghSlug -and [bool](Get-Command gh -ErrorAction SilentlyContinue)
# The receipt is written AFTER the probes, from what they actually answered. It used to be decided up
# front from "gh is installed and origin is GitHub", so an unauthenticated, rate-limited, offline or
# unauthorised gh produced "PR probe scoped to <slug>" on a run where every probe errored -- the same
# defect class (a receipt asserting a check that never ran) this script was rewritten to remove.
$ghAttempts = 0
$ghFailures = 0
$ghFirstError = ''

# Is `origin/main..<branch>` empty right now? Used twice: once as the cheap merge signal, and again
# immediately before a branch delete, so a verdict formed seconds earlier can never authorise -D.
function Test-ContainedInMain {
    param([string]$Branch)
    $n = (& git -C $RepoRoot rev-list --count "$MainRef..refs/heads/$Branch" 2>$null)
    if ($LASTEXITCODE -ne 0) { return @{ Ok = $false; Unique = -1 } }
    return @{ Ok = $true; Unique = [int]$n }
}

# A branch with exactly one reflog entry ("branch: Created from ...") never advanced. That is NOT the
# same thing as merged, even though both look like "0 commits beyond origin/main" -- and the never-used
# case is precisely the state of the worktree that got destroyed.
function Test-BranchNeverUsed {
    param([string]$Branch)
    $log = @(& git -C $RepoRoot reflog show --format='%gs' "refs/heads/$Branch" 2>$null)
    if ($LASTEXITCODE -ne 0) { return $false }
    return ($log.Count -eq 1 -and $log[0] -match '^branch: Created from')
}

function Test-Merged {
    param([string]$Branch)
    $notes = @()
    $tip = (& git -C $RepoRoot rev-parse --verify --quiet "refs/heads/$Branch^{commit}" 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $tip) {
        return @{ Merged = $false; Reason = "branch $Branch has no resolvable tip"; Unique = -1; Notes = $notes; NeverUsed = $false }
    }
    $tip = $tip.Trim()

    # 1) Nothing beyond origin/main. Cheap, offline, and true by construction for a brand-new
    #    worktree -- which is why (d) occupancy exists.
    $c = Test-ContainedInMain -Branch $Branch
    if (-not $c.Ok) {
        return @{ Merged = $false; Reason = "cannot compare against $MainRef (does it exist?)"; Unique = -1; Notes = $notes; NeverUsed = $false }
    }
    $uniq = $c.Unique
    if ($uniq -eq 0) {
        if (Test-BranchNeverUsed -Branch $Branch) {
            return @{
                Merged = $true; Unique = 0; Notes = $notes; NeverUsed = $true
                Reason = "never used: 0 commits and the branch never advanced (nothing was merged FROM here)"
            }
        }
        return @{ Merged = $true; Reason = "no commits beyond $MainRef"; Unique = 0; Notes = $notes; NeverUsed = $false }
    }

    # 2) A merged PR -- but only when its head is THIS EXACT TIP. `--head <branch>` matches by NAME, so
    #    a branch continued after its PR merged (or a name reused from an earlier life) otherwise reads
    #    as merged and gets its later commits force-deleted. Repo-scoped: gh resolves the repo from the
    #    CALLER'S cwd otherwise, so launching this by absolute path from another checkout would answer
    #    from that repo's merged PRs.
    #    `--json number,headRefOid` is ONE argv entry. A space after the comma makes PowerShell pass
    #    three, gh rejects the third, and this whole block silently never ran (it didn't, for a while)
    #    while the receipt still claimed a PR probe was scoped. Keep the comma tight.
    if ($hasGh) {
        $script:ghAttempts++
        $raw = & gh pr list --repo $ghSlug --head $Branch --state merged --json number,headRefOid --limit 20 2>&1
        $ghExit = $LASTEXITCODE
        # 2>&1 folds stderr in as ErrorRecords; keep them out of the JSON but keep them as the reason.
        $ghText = (@($raw | Where-Object { $_ -isnot [System.Management.Automation.ErrorRecord] }) -join "`n").Trim()
        if ($ghExit -ne 0) {
            $script:ghFailures++
            $why = (@($raw) -join ' ').Trim()
            if (-not $script:ghFirstError) { $script:ghFirstError = if ($why) { $why } else { "gh exited $ghExit" } }
            $notes += "the merged-PR probe FAILED for this branch (gh exited $ghExit), so only the local merge signals were available"
        }
        if ($ghExit -eq 0 -and $ghText) {
            $prs = $null
            try { $prs = @($ghText | ConvertFrom-Json) } catch { $prs = @() }
            $exact = @($prs | Where-Object { $_.headRefOid -eq $tip })
            if ($exact.Count -gt 0) {
                return @{ Merged = $true; Reason = "PR #$($exact[0].number) merged at this exact tip"; Unique = $uniq; Notes = $notes; NeverUsed = $false }
            }
            if ($prs.Count -gt 0) {
                $notes += "a merged PR (#$($prs[0].number)) exists for the branch NAME '$Branch', but its head was $($prs[0].headRefOid.Substring(0,8)) and this branch is at $($tip.Substring(0,8)) -- the branch moved on after that merge"
            }
        }
    }

    # 3) Upstream gone: the remote branch was deleted, the usual squash-merge + auto-delete shape. Only
    #    when the upstream is the branch's OWN remote branch -- `new.ps1 -Base origin/<parent>` leaves a
    #    child branch pointing at the PARENT's upstream, so a merged parent makes a never-pushed child
    #    report [gone] and its commits would go with the branch.
    #    `gone` means THE REMOTE REF IS ABSENT, never `merged`: a branch whose PR was CLOSED, or that was
    #    deleted with `push --delete`, reports exactly this. So it is a signal to remove the WORKTREE, and
    #    never a licence to delete the branch -- which is why the branch delete re-verifies containment
    #    in origin/main on its own and keeps the branch when it cannot.
    $refInfo = (& git -C $RepoRoot for-each-ref --format '%(upstream:short)|%(upstream:track)|%(upstream:remotename)' "refs/heads/$Branch" 2>$null)
    if ($LASTEXITCODE -eq 0 -and $refInfo) {
        $parts = ([string]$refInfo).Split('|')
        $upShort = $parts[0]
        $upTrack = if ($parts.Count -gt 1) { $parts[1] } else { '' }
        $upRemote = if ($parts.Count -gt 2) { $parts[2] } else { '' }
        if ($upTrack -match 'gone') {
            if ($upShort -eq "$upRemote/$Branch") {
                return @{
                    Merged = $true
                    Reason = "upstream $upShort is gone (squash-merged + remote-deleted); the branch is KEPT because $uniq commit(s) are not on $MainRef"
                    Unique = $uniq; Notes = $notes; NeverUsed = $false
                }
            }
            $notes += "upstream $upShort is gone, but it belongs to ANOTHER branch (this worktree was branched off it) -- not a merge signal"
        }
    }
    return @{ Merged = $false; Reason = 'no merge signal'; Unique = $uniq; Notes = $notes; NeverUsed = $false }
}

# --- Occupancy signal 2: recent activity, which does not depend on a recorded cwd ----------------
function Get-WorktreeActivity {
    param([string]$Path)
    # The worktree's PRIVATE git metadata only. Deliberately NOT the working files: a venv install or a
    # test run churns those, so their mtimes would veto everything forever and the veto would stop
    # meaning anything. The cost is that a session which only edits files and runs no git command is
    # invisible to this signal too -- stated in the header rather than papered over.
    if (-not (Test-Path -LiteralPath $Path)) { return $null }
    $gitdir = & git -C $Path rev-parse --absolute-git-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $gitdir) { return $null }
    $gitdir = ([string]$gitdir).Trim()
    if (-not (Test-Path -LiteralPath $gitdir)) { return $null }
    $newest = $null
    foreach ($rel in @('index', 'HEAD', 'ORIG_HEAD', 'FETCH_HEAD', 'COMMIT_EDITMSG', 'MERGE_MSG', 'logs/HEAD')) {
        $f = Join-Path $gitdir $rel
        if (Test-Path -LiteralPath $f) {
            $t = (Get-Item -LiteralPath $f -Force).LastWriteTime
            if ($null -eq $newest -or $t -gt $newest) { $newest = $t }
        }
    }
    return $newest
}

# --- Candidate set -------------------------------------------------------------------------------
# Literal prefix, NOT -like: `-like` treats [ ] in a path as a character class, so a repo living under
# a bracketed directory silently matches nothing (and every "was not pruned" assertion would pass
# vacuously).
$prefixed = @($occ.Worktrees | Where-Object {
        ($_.Path -replace '\\', '/').StartsWith("$RepoRootFwd-", [StringComparison]::OrdinalIgnoreCase)
    })

# Everything the prefix caught but that must never be a candidate -- said out loud rather than leaving
# the operator to wonder whether it was considered at all.
$siblings = @()
$excluded = @()
foreach ($w in $prefixed) {
    $fwd = ($w.Path -replace '\\', '/')
    # A worktree INSIDE another registered worktree is not a sibling of anything. `<primary>-pins/
    # .claude/worktrees/x` passes the prefix test, and removing it destroys the Claude-managed checkout
    # a live session was relocated into -- while the parent, protected by Get-NestedWorktrees, watches.
    $containers = @(Get-ContainingWorktrees -Occupancy $occ -Path $w.Path)
    if ($containers.Count -gt 0) {
        $excluded += [pscustomobject]@{ Wt = $w; Why = "nested inside $(Split-Path $containers[-1].Path -Leaf)" }
    }
    # Belt and braces, and it survives the containing worktree being deregistered: this path shape is
    # Claude-managed by construction, whoever currently owns it.
    elseif ($fwd -match '(?i)/\.claude/worktrees/') {
        $excluded += [pscustomobject]@{ Wt = $w; Why = 'Claude-managed (.claude/worktrees)' }
    }
    elseif ($w.Detached -or $w.Bare -or -not $w.Branch) {
        $excluded += [pscustomobject]@{ Wt = $w; Why = 'detached/bare' }
    }
    else { $siblings += $w }
}

$namedMisses = @()
if ($Name) {
    $wanted = @($Name | ForEach-Object { $_.Trim() } | Where-Object { $_ })
    $matchesName = {
        param($leaf)
        foreach ($n in $wanted) { if ($leaf -ieq $n -or $leaf -ieq "$RepoLeaf-$n") { return $true } }
        return $false
    }
    $siblings = @($siblings | Where-Object { & $matchesName (Split-Path $_.Path -Leaf) })
    foreach ($n in $wanted) {
        $hit = @($siblings | Where-Object { (Split-Path $_.Path -Leaf) -ieq $n -or (Split-Path $_.Path -Leaf) -ieq "$RepoLeaf-$n" })
        if ($hit.Count -eq 0) { $namedMisses += $n }
    }
}

# --- One decision pass; two renderers ------------------------------------------------------------
$idleCut = (Get-Date).AddHours(-1 * $IdleHours)

# ONE cleanliness routine, called by the decision pass AND by the re-check immediately before removal.
# The re-check used to collapse "the directory vanished", "git status exited 128", "an untracked file
# appeared" and "somebody edited a tracked file" into the single string "no longer clean" -- discarding
# the distinction at the exact moment an operator most needs it, because something changed underneath a
# destructive run.
# FAILS CLOSED: an unreadable status (a moved-away or half-deleted worktree exits 128 with no output)
# used to be indistinguishable from "no changes" and pointed straight at destruction.
function Test-WorktreeClean {
    param([string]$Path)
    if (-not (Test-Path -LiteralPath $Path)) {
        return @{ Clean = $false; Reasons = @('directory is missing (already half-removed? investigate before pruning)') }
    }
    $status = @(& git -C $Path --no-optional-locks status --porcelain 2>$null)
    $statusExit = $LASTEXITCODE
    if ($statusExit -ne 0) {
        return @{ Clean = $false; Reasons = @("git status failed (exit $statusExit) -- cannot establish it is clean") }
    }
    $trackedChanges = @($status | Where-Object { $_ -notmatch '^\?\?' })
    $untracked = @($status | Where-Object { $_ -match '^\?\?' })
    $r = @()
    if ($trackedChanges.Count -gt 0) { $r += "dirty: $($trackedChanges.Count) uncommitted tracked change(s)" }
    # Untracked files are the one loss class with no recovery THROUGH GIT: not in the index, not in a
    # stash, not in the reflog. (--force also deletes IGNORED files -- .venv, a dev DB, a generated
    # corpus -- which git status never shows here; those are unrecoverable too, merely regenerable.)
    # `--force` suppresses git's own refusal on them, so this must not wave them through.
    if ($untracked.Count -gt 0) {
        $r += "$($untracked.Count) untracked file(s) present -- --force would delete them unrecoverably"
    }
    return @{ Clean = ($r.Count -eq 0); Reasons = $r }
}

# The reported shape of an occupant. Shared with the -Apply re-check, which must WRITE BACK the
# occupants it finds: a re-check veto used to leave `Occupants: []` on the one candidate the fence
# actually stopped, so the run that signal 1 saved reported signal 1 as having contributed nothing.
function ConvertTo-OccupantRows([object[]]$Rows) {
    return @($Rows | ForEach-Object {
            [pscustomobject]@{
                Short = $_.Short; State = $_.State; Surface = $_.Entrypoint; Cwd = $_.Cwd; Worktree = $_.Worktree
                # WHICH SIGNAL saw it, and (for a footprint) how much it saw. A merged occupant list
                # cannot show that one of the two sources has gone to zero, which is the whole reason
                # the second one was built.
                Source = $_.Source; Writes = $_.Writes; LastWriteAt = $_.LastWriteAt; CrossTree = $_.CrossTree
            }
        })
}

function Get-Decision {
    param([object]$Wt, [bool]$Confirmed)
    $leaf = Split-Path $Wt.Path -Leaf
    $reasons = @()
    $notes = @()

    # EVERY LOCAL DISQUALIFIER IS EVALUATED BEFORE THE MERGE TEST. The merge test can cost a gh round
    # trip per candidate, and that time is the window in which a session can arrive; spending it on a
    # worktree that is already occupied both widens the window and answers a question nobody asked.

    # Lock: git's own occupancy flag, and the one thing a single --force will not override.
    if ($Wt.Locked) {
        $why = if ($Wt.LockReason) { ": $($Wt.LockReason)" } else { '' }
        $reasons += "locked by git$why"
    }

    # Occupancy 1: the liveness fence. Unavailable is a REFUSAL, never an empty answer. -IncludeNested
    # because removing a parent takes the nested checkout with it, so a session in the nested tree must
    # veto the ancestor as well.
    # Signals 1 AND 3 both arrive here: Get-WorktreeOccupants returns the veto-worthy rows of both
    # sources, each tagged with the one that produced it. They are reported separately -- a single
    # "occupied by N" cannot show that one source contributed nothing.
    $occupants = @()
    if ($occ.Available) {
        $occupants = @(Get-WorktreeOccupants -Occupancy $occ -Path $Wt.Path -IncludeNested)
        if ($occupants.Count -gt 0) {
            $who = ($occupants | ForEach-Object {
                    $where = if ((ConvertTo-Norm $_.WorktreePath) -eq (ConvertTo-Norm $Wt.Path)) { '' } else { " in nested $($_.Worktree)" }
                    if ($_.Source -eq 'footprint') {
                        $from = if ($_.CrossTree) { " writing in from $($_.Cwd)" } else { '' }
                        "$($_.Short) [$($_.State)] $($_.Writes) write(s)$from$where"
                    }
                    elseif ($_.Source -eq 'pin') { "$($_.Short) [PINNED] $($_.Reason)$where" }
                    else { "$($_.Short) [$($_.State)]$where" }
                }) -join ', '
            $bySignal = @()
            $n1 = @($occupants | Where-Object { $_.Source -eq 'cwd' }).Count
            $n3 = @($occupants | Where-Object { $_.Source -eq 'footprint' }).Count
            $n4 = @($occupants | Where-Object { $_.Source -eq 'pin' }).Count
            if ($n1) { $bySignal += "$n1 by recorded cwd" }
            if ($n3) { $bySignal += "$n3 by write footprint" }
            if ($n4) { $bySignal += "$n4 by an operator pin" }
            $reasons += "occupied by $($occupants.Count) session(s) ($($bySignal -join ', ')): $who"
        }
    }

    # A worktree that CONTAINS another registered worktree is never safe to --force-remove, occupied or
    # not: git deletes the parent tree, the nested checkout goes with it, and the nested worktree stays
    # registered with no directory -- the orphan state this whole script exists to avoid causing.
    $nested = @(Get-NestedWorktrees -Occupancy $occ -Path $Wt.Path)
    if ($nested.Count -gt 0) {
        $names = (($nested | ForEach-Object { Split-Path $_.Path -Leaf }) -join ', ')
        $reasons += "contains $($nested.Count) nested registered worktree(s) ($names) -- removing this would orphan them"
    }

    if (-not $occ.Available) {
        $reasons += "liveness fence unavailable -- $($occ.Detail)"
    }

    $c = Test-WorktreeClean -Path $Wt.Path
    $clean = [bool]$c.Clean
    $reasons += @($c.Reasons)

    # Occupancy 2: recent activity. The signal that does not need a recorded cwd, and the only one that
    # saw the sessions signal 1 missed.
    $activity = Get-WorktreeActivity -Path $Wt.Path
    $activityAge = $null
    if ($null -eq $activity) {
        $reasons += 'activity unknown (git metadata unreadable) -- cannot establish nobody is in it'
    }
    elseif (-not $activityVeto) {
        $activityAge = [math]::Round(((Get-Date) - $activity).TotalHours, 2)
        $notes += "activity veto OFF (-IdleHours 0); this worktree was touched $activityAge h ago"
    }
    else {
        $activityAge = [math]::Round(((Get-Date) - $activity).TotalHours, 2)
        if ($activity -gt $idleCut) {
            if ($Confirmed) {
                $notes += "recent activity ($activityAge h ago) overridden by -Name"
            }
            else {
                $reasons += "recently active ($activityAge h ago, < $IdleHours h) -- someone may be working here by absolute path; confirm with -Name $leaf"
            }
        }
    }

    # Merge signal LAST -- only worth the gh round trip when nothing local already disqualifies it.
    $merged = $null
    $mergeReason = 'not evaluated (already disqualified)'
    $unique = -1
    $neverUsed = $false
    if ($reasons.Count -eq 0) {
        $m = Test-Merged -Branch $Wt.Branch
        $merged = [bool]$m.Merged
        $mergeReason = [string]$m.Reason
        $unique = [int]$m.Unique
        $neverUsed = [bool]$m.NeverUsed
        $notes += @($m.Notes)
        if (-not $merged) { $reasons += "not merged ($mergeReason)" }
    }

    return [pscustomobject]@{
        Leaf         = $leaf
        Path         = $Wt.Path
        Branch       = $Wt.Branch
        Decision     = if ($reasons.Count -eq 0) { 'PRUNE' } else { 'SKIP' }
        Reasons      = @($reasons)
        Reason       = if ($reasons.Count -eq 0) { $mergeReason } else { $reasons[0] }
        Notes        = @($notes)
        Clean        = $clean
        # $null, not $false, when the test never ran: a machine consumer reads `false` as "checked, and
        # it is not merged", which is a different claim from "never asked".
        Merged       = $merged
        MergeReason  = $mergeReason
        NeverUsed    = $neverUsed
        UniqueCommits = $unique
        Locked       = [bool]$Wt.Locked
        NestedWorktrees = @($nested | ForEach-Object { Split-Path $_.Path -Leaf })
        Occupants    = @(ConvertTo-OccupantRows $occupants)
        ActivityAgeHours = $activityAge
        Confirmed    = [bool]$Confirmed
        Outcome      = 'not attempted'
        OutcomeDetail = ''
        # NOT 'kept': every skipped candidate then claimed a decision nobody made, and the JSON said 7
        # branches were kept on a run whose summary said 0. 'kept' is now only ever set by a keep.
        BranchOutcome = 'not attempted'
        BranchDetail  = ''
    }
}

$confirmedLeaves = @()
if ($Name) { $confirmedLeaves = @($siblings | ForEach-Object { Split-Path $_.Path -Leaf }) }

$decisions = @()
foreach ($s in $siblings) {
    $leaf = Split-Path $s.Path -Leaf
    $decisions += Get-Decision -Wt $s -Confirmed ($confirmedLeaves -contains $leaf)
}
$prunable = @($decisions | Where-Object { $_.Decision -eq 'PRUNE' })

# -Name is the loudest thing an operator can do to the fence: it is -IdleHours 0 scoped to one tree,
# and signal 1 has been measured vetoing 0 of 4 real siblings. It used to produce only a grey `note:`
# line, while the flag it is equivalent to got a red banner.
$confirmedActually = @($decisions | Where-Object { $_.Confirmed } | ForEach-Object { $_.Leaf })
if ($confirmedActually.Count -gt 0) {
    $reducedAssurance += "activity veto OVERRIDDEN by -Name for: $($confirmedActually -join ', ') -- signal 2 is off for those (signal 1 applies and $sig3State; -Name cannot reach either)"
}
# A source that could not see anything is reduced assurance, not a clean bill of health. BOTH extra
# sources: signal 4's note ("no pin has ever been taken in this repo") used to render only in yellow
# one indent down, while signal 3's was promoted -- so the signal measuring 0 BY CONSTRUCTION was the
# quieter of the two.
if ($fp -and $fp.Available -and $fp.Note) {
    $reducedAssurance += "write-footprint source contributed nothing: $($fp.Note)"
}
if ($pinSet -and $pinSet.Available -and $pinSet.Note) {
    $reducedAssurance += "operator-pin source contributed nothing: $($pinSet.Note)"
}

# The gh receipt, written from what the probes ANSWERED (see Test-Merged).
$ghDetail =
if ($SkipGh) { 'PR probe skipped (-SkipGh)' }
elseif (-not $ghSlug) { 'PR probe skipped: origin is not a GitHub remote' }
elseif (-not $hasGh) { 'PR probe skipped: gh is not installed' }
elseif ($ghAttempts -eq 0) { "PR probe available ($ghSlug) but no candidate reached the merge test" }
elseif ($ghFailures -eq 0) { "PR probe scoped to ${ghSlug}: $ghAttempts candidate(s) probed" }
else { "PR probe scoped to $ghSlug FAILED on $ghFailures of $ghAttempts candidate(s): $ghFirstError" }
if ($ghFailures -gt 0) {
    $reducedAssurance += "the merged-PR probe FAILED on $ghFailures of $ghAttempts candidate(s): the exact-tip merge signal was unavailable for them ($ghFirstError)"
}

# --- The fence receipt: count what was EXAMINED, not what was found ------------------------------
# Sessions, not ROWS: signal 3 emits one row per (session, worktree) pair, so a session writing into
# three worktrees would otherwise be counted as three live sessions.
$liveInRepo = @($occ.Sessions | Where-Object { Test-OccupancyVeto $_.State } |
        ForEach-Object { $_.SessionId } | Select-Object -Unique).Count
# What each source actually CONTRIBUTED here, which is not the same as how many sessions it saw, and
# never merged into one number: signal 1's honest figure on this repo has been 0 of 4 while three of
# those worktrees were occupied in fact, and a combined count would have hidden exactly that.
# Recomputed AFTER the apply loop, because a re-check veto is a contribution too.
function Measure-SignalVetoes([object[]]$Decisions, [string]$Source) {
    return @($Decisions | Where-Object { @($_.Occupants | Where-Object { $_.Source -eq $Source }).Count -gt 0 }).Count
}
$fenceVetoedAtDecision = @($decisions | Where-Object { $_.Occupants.Count -gt 0 }).Count
$fenceVetoed = $fenceVetoedAtDecision
$cwdVetoed = Measure-SignalVetoes $decisions 'cwd'
$footprintVetoed = Measure-SignalVetoes $decisions 'footprint'
$pinVetoed = Measure-SignalVetoes $decisions 'pin'
# The number an operator must see instead of a bare zero: candidates this signal had nothing to say
# about, which is not the same claim as "nobody was there".
$withoutFootprint = @($decisions | Where-Object { @($_.Occupants | Where-Object { $_.Source -eq 'footprint' }).Count -eq 0 }).Count
$blindSpots = @(
    'a write by anything that is not a Claude tool call (an editor, an autosave, a plain terminal, a process still running after its tool call returned)',
    'a file written BY a shell command -- the transcript records the command string, not a resolved path list',
    'a session that never registered AND never wrote through a tool call',
    'a session whose writes are outside -FootprintHours while its git metadata is outside -IdleHours',
    # The two residuals the fixed canaries still cannot reach. Named here rather than left in a script
    # header, because this list is what an operator actually reads before deciding to trust the fence.
    'a transcript torn mid-write on its FIRST write into a brand-new worktree, in a file that has never named this repo family -- counted (linesUnparseableElsewhere), not refused; that worktree is covered by signal 4 and by fresh git metadata instead',
    'a vendor release that renames the write tools AND moves the path keys at the same time -- canary 1 catches the second, canary 4 the first, and neither catches both together; what is left is the footprint note saying no write placed'
)

if (-not $Json) {
    Write-Host ""
    if ($occ.Available) {
        Write-Host ("Occupancy fence: {0} config root(s), {1} record(s) examined, {2} live session(s) in this repo family." -f
            $occ.RootsExamined, $occ.RecordsExamined, $liveInRepo) -ForegroundColor DarkCyan
        Write-Host ("  Signal 1 (recorded cwd)     placed a session inside {0} of {1} candidate(s)." -f
            $cwdVetoed, $decisions.Count) -ForegroundColor DarkCyan
        if ($fp) {
            Write-Host ("  Signal 3 (write footprint) placed a session inside {0} of {1} candidate(s)." -f
                $footprintVetoed, $decisions.Count) -ForegroundColor DarkCyan
            Write-Host ("    scanned {0} transcript(s) across {1} corpus root(s); {2} in the last {3} h, {4} mentioning this repo; {5:n0} line(s) parsed, {6} write(s) examined, {7} placed in a worktree here, {8} elsewhere ({9} of the placed came from a session sitting in another checkout)." -f
                $fp.TranscriptsFound, $fp.RootsWithCorpus, $fp.TranscriptsInWindow, $fp.WindowHours,
                $fp.TranscriptsWithNeedle, $fp.LinesParsed, $fp.WritesExamined, $fp.WritesPlaced,
                $fp.WritesUnplaced, $fp.CrossTreeWrites) -ForegroundColor DarkGray
            # The allow-list, and what was actually observed against it. Canary 4 fires only when the
            # intersection is EMPTY; a PARTIAL rename (one tool renamed, the rest intact) leaves it
            # green, so the vocabulary has to be legible rather than merely asserted.
            Write-Host ("    write tools recognised: {0} of {1}; {2} distinct tool name(s) seen over {3:n0} path-tool block(s). Placement: {4} by path, {5} through .git ({6} director(ies) probed)." -f
                (@($fp.WriteToolNamesSeen) -join '/'), (@($fp.WriteToolsAllowList) -join '/'),
                @($fp.ToolNamesSeen).Count, $fp.PathToolBlocks,
                $fp.PlacedByPrefix, $fp.PlacedByGitdir, $fp.GitdirProbes) -ForegroundColor DarkGray
            if ($fp.LinesUnparseableElsewhere -gt 0) {
                Write-Host ("    {0} unparseable line(s) in transcripts with no connection to this repo family -- counted, not refused (a machine-wide scan cannot fault on every session that is mid-append)." -f
                    $fp.LinesUnparseableElsewhere) -ForegroundColor DarkGray
            }
            if ($fp.Note) { Write-Host "    $($fp.Note)" -ForegroundColor Yellow }
            # NEVER a bare zero. "0 vetoed" reads as "nobody is anywhere" and sends an operator to
            # -Name; this is the same number with the honest meaning attached.
            if ($withoutFootprint -gt 0 -and $decisions.Count -gt 0) {
                Write-Host ("    {0} of {1} candidate(s) have NO footprint at all -- for those this signal contributed nothing, which is not the same as nobody being there." -f
                    $withoutFootprint, $decisions.Count) -ForegroundColor Yellow
            }
        }
        if ($pinSet) {
            Write-Host ("  Signal 4 (operator pin)    placed a declaration on {0} of {1} candidate(s); {2} pin(s) examined, {3} expired." -f
                $pinVetoed, $decisions.Count, $pinSet.PinsExamined, $pinSet.PinsExpired) -ForegroundColor DarkCyan
            Write-Host "    It is the only signal that sees a writer who is not a Claude tool call -- an editor, an autosave, a plain terminal." -ForegroundColor DarkGray
            if ($pinSet.Note) { Write-Host "    $($pinSet.Note)" -ForegroundColor Yellow }
        }
    }
    else {
        Write-Host "Occupancy fence UNAVAILABLE -- $($occ.Detail)." -ForegroundColor Red
        Write-Host "  That is NOT 'nobody is live'. Nothing will be pruned." -ForegroundColor Red
    }
    Write-Host "  It DOES see VS Code sessions (the match is path-based, not surface-based). It CANNOT see:" -ForegroundColor DarkGray
    foreach ($b in $blindSpots) { Write-Host "    - $b" -ForegroundColor DarkGray }
    if ($activityVeto) {
        Write-Host ("  Which is why git metadata touched within {0}h also counts as occupied." -f $IdleHours) -ForegroundColor DarkGray
    }
    foreach ($r in $reducedAssurance) { Write-Host "  REDUCED ASSURANCE: $r" -ForegroundColor Red }
    Write-Host "  refs: $fetchDetail" -ForegroundColor DarkGray
    Write-Host "  merge: $ghDetail" -ForegroundColor DarkGray

    Write-Host ""
    Write-Host ("{0,-42} {1,-30} {2}" -f 'WORKTREE', 'BRANCH', 'DECISION')
    Write-Host ("{0,-42} {1,-30} {2}" -f ('-' * 40), ('-' * 28), ('-' * 40))
    foreach ($d in $decisions) {
        $text = if ($d.Decision -eq 'PRUNE') { "PRUNE - $($d.Reason)" } else { "SKIP  - $($d.Reason)" }
        $colour = if ($d.Decision -eq 'PRUNE') { 'Yellow' } else { 'Gray' }
        Write-Host ("{0,-42} {1,-30} {2}" -f $d.Leaf, $d.Branch, $text) -ForegroundColor $colour
        foreach ($r in @($d.Reasons | Select-Object -Skip 1)) { Write-Host ("{0,-42} {1,-30} also: {2}" -f '', '', $r) -ForegroundColor DarkGray }
        foreach ($n in $d.Notes) { Write-Host ("{0,-42} {1,-30} note: {2}" -f '', '', $n) -ForegroundColor DarkGray }
    }
    if ($decisions.Count -eq 0) {
        Write-Host "  (no candidates)" -ForegroundColor DarkGray
    }
    foreach ($e in $excluded) {
        Write-Host ("{0,-42} {1,-30} not a candidate ({2})" -f (Split-Path $e.Wt.Path -Leaf), $e.Wt.Branch, $e.Why) -ForegroundColor DarkGray
    }
    foreach ($n in $namedMisses) {
        Write-Host "  -Name '$n' matched no PRUNABLE sibling worktree (it may be nested, detached, or not exist)." -ForegroundColor Yellow
    }
}

# --- Orphans this script left behind on an EARLIER run -------------------------------------------
# Once git deregisters a worktree it leaves `git worktree list` and therefore the candidate set, so the
# next run printed a green all-clear over a directory this script had broken and the recovery recipe
# survived only in the first run's scrollback. Two independent detectors, because either can be true
# alone: a ledger written at the moment of the failure, and a directory still carrying a .git FILE that
# points into this repo's worktree admin area while git no longer lists it.
$gitCommonDir = ''
$cd = & git -C $RepoRoot rev-parse --path-format=absolute --git-common-dir 2>$null
if ($LASTEXITCODE -eq 0 -and $cd) { $gitCommonDir = ([string]$cd).Trim() }
$ledgerPath = if ($gitCommonDir) { Join-Path $gitCommonDir 'prune-merged-orphans.json' } else { '' }

function Read-OrphanLedger {
    if (-not $ledgerPath -or -not (Test-Path -LiteralPath $ledgerPath)) { return @() }
    try { return @(Get-Content -LiteralPath $ledgerPath -Raw -EA Stop | ConvertFrom-Json -EA Stop) }
    catch { return @() }
}

# Still broken RIGHT NOW: on disk, and not registered. An entry that was repaired (re-added) or fully
# deleted clears itself, so the ledger cannot nag about a state that no longer exists.
function Get-LiveOrphans([object[]]$Ledger) {
    $registered = @{}
    foreach ($w in @(Get-RepoWorktrees $RepoRoot)) { $registered[(ConvertTo-Norm $w.Path)] = $true }
    $seen = @{}
    $out = @()
    foreach ($e in $Ledger) {
        $p = [string]$e.path
        if (-not $p) { continue }
        $n = ConvertTo-Norm $p
        if ($registered.ContainsKey($n) -or -not (Test-Path -LiteralPath $p)) { continue }
        if ($seen.ContainsKey($n)) { continue }
        $seen[$n] = $true
        $out += [pscustomobject]@{ Path = $p; Leaf = (Split-Path $p -Leaf); Branch = [string]$e.branch; At = [string]$e.at; Why = 'a previous run of this script failed to finish removing it' }
    }
    # The ledger-free detector: an unregistered sibling directory whose .git pointer still names this
    # repo. Deliberately NOT "any unregistered <repo>-* directory" -- an unrelated folder sharing the
    # prefix is not an orphan, and a destructive tool that cries wolf gets ignored.
    $parent = Split-Path $RepoRoot -Parent
    foreach ($dir in @(Get-ChildItem -LiteralPath $parent -Directory -Force -EA SilentlyContinue |
            Where-Object { $_.Name.StartsWith("$RepoLeaf-", [StringComparison]::OrdinalIgnoreCase) })) {
        $n = ConvertTo-Norm $dir.FullName
        if ($registered.ContainsKey($n) -or $seen.ContainsKey($n)) { continue }
        $dotgit = Join-Path $dir.FullName '.git'
        if (-not (Test-Path -LiteralPath $dotgit -PathType Leaf)) { continue }
        $txt = ''
        try { $txt = Get-Content -LiteralPath $dotgit -Raw -EA Stop } catch { continue }
        if ($txt -notmatch 'gitdir:\s*(.+)') { continue }
        $target = ConvertTo-Norm ($Matches[1].Trim())
        if (-not $gitCommonDir -or -not $target.StartsWith((ConvertTo-Norm $gitCommonDir) + '/')) { continue }
        $seen[$n] = $true
        $out += [pscustomobject]@{ Path = $dir.FullName; Leaf = $dir.Name; Branch = ''; At = ''; Why = 'it still points into this repo''s worktree admin directory, but git no longer lists it' }
    }
    return $out
}

$ledger = @(Read-OrphanLedger)
# Scanned BEFORE the apply loop, so this run's own orphans are reported as this run's, not as history.
$priorOrphans = @(Get-LiveOrphans $ledger)

# --- Apply ---------------------------------------------------------------------------------------
$removed = 0; $failed = 0; $branchesDeleted = 0; $branchesKept = 0; $orphaned = 0
$newOrphans = @()
if (-not $occ.Available) { Set-Exit $EXIT_REFUSED }
if ($priorOrphans.Count -gt 0) { Set-Exit $EXIT_ORPHANED }

# Delete the branch only when the delete is provably lossless AT THIS MOMENT. `-d` refuses a branch
# merged only into origin/main whenever the local main lags (it usually does), so `-D` was the routine
# path and git's own last protection was being overridden every time -- including on a verdict formed
# before a session pushed two more commits onto the branch. Re-verify containment here, after the
# removal, or keep the branch: a stale ref costs nothing.
function Remove-BranchSafely {
    param([object]$Decision)
    & git -C $RepoRoot branch -d $Decision.Branch 2>$null | Out-Null
    if ($LASTEXITCODE -eq 0) { return @{ Outcome = 'deleted'; Detail = '' } }

    $c = Test-ContainedInMain -Branch $Decision.Branch
    if (-not $c.Ok) {
        return @{ Outcome = 'kept'; Detail = "could not re-verify containment in $MainRef, so the branch was kept" }
    }
    if ($c.Unique -ne 0) {
        return @{
            Outcome = 'kept'
            Detail = "$($c.Unique) commit(s) are not on $MainRef, so the branch was KEPT (delete it yourself once you are sure: git branch -D $($Decision.Branch))"
        }
    }
    $out = @(& git -C $RepoRoot branch -D $Decision.Branch 2>&1)
    if ($LASTEXITCODE -eq 0) {
        return @{ Outcome = 'force-deleted'; Detail = "re-verified: 0 commits beyond $MainRef, so nothing was lost" }
    }
    return @{ Outcome = 'kept'; Detail = ($out -join ' ').Trim() }
}

$occ2 = $null
if ($Apply -and $prunable.Count -gt 0) {
    Write-Note ""
    foreach ($d in $prunable) {
        if (-not $Json) { Write-Host "Removing $($d.Leaf) [$($d.Branch)]..." -ForegroundColor Cyan }

        # PER CANDIDATE, NOT ONCE FOR THE LOOP. This read used to sit ABOVE the foreach, so signals 1,
        # 3 and 4 were frozen at the moment the first removal began and only signal 2 -- the crude 36 h
        # metadata guess -- was re-read per candidate. The branch's own arithmetic inverts that: signal
        # 3 is the one with measured coverage, and it was the stale one for candidates 2..N. Measured:
        # a LIVE session's write into the SECOND candidate, landing during the FIRST removal, was
        # invisible (vetoedByFootprint 0, fence.available true) and the directory was destroyed; the
        # identical footprint present before the run started produced a SKIP. Signal 2 cannot cover it
        # -- a transcript write touches no git metadata, which is the entire gap signal 3 exists for.
        # It costs a corpus scan per candidate (~7 s on this repo). That is the correct trade for a
        # tool whose failure mode is destroying another session's work.
        $occ2 = Get-WorktreeOccupancy -Repo $RepoRoot -ConfigRoot $ConfigRoot -StartSkewMinutes $StartSkewMinutes `
            -IncludeFootprints -FootprintHours $FootprintHours -IncludePins

        # Re-check the things that can change under us in seconds.
        if (-not $occ2.Available) {
            $d.Outcome = 'skipped'
            $d.OutcomeDetail = "re-check: fence became unavailable ($($occ2.Detail))"
            Set-Exit $EXIT_REFUSED
            Write-Note "  SKIPPED: $($d.OutcomeDetail)" 'Yellow'
            continue
        }
        $now = @(Get-WorktreeOccupants -Occupancy $occ2 -Path $d.Path -IncludeNested)
        if ($now.Count -gt 0) {
            $d.Outcome = 'skipped'
            $d.OutcomeDetail = "re-check: a session arrived ($(($now | ForEach-Object { $_.Short }) -join ', '))"
            # WRITE IT BACK. Without this the candidate the fence just saved still reports `Occupants:
            # []`, and the receipt's "vetoed by signal 1" figure -- the number that exists precisely so
            # "the fence ran" cannot imply "the fence covered it" -- under-reports the save to zero.
            $d.Occupants = @(ConvertTo-OccupantRows $now)
            Write-Note "  SKIPPED: $($d.OutcomeDetail)" 'Yellow'
            continue
        }
        $nestedNow = @(Get-NestedWorktrees -Occupancy $occ2 -Path $d.Path)
        if ($nestedNow.Count -gt 0) {
            $d.Outcome = 'skipped'
            $d.OutcomeDetail = "re-check: a nested worktree appeared ($((($nestedNow | ForEach-Object { Split-Path $_.Path -Leaf }) -join ', ')))"
            Write-Note "  SKIPPED: $($d.OutcomeDetail)" 'Yellow'
            continue
        }
        # Signal 2, re-read. It was the ONE signal missing from this block, and it is the only one with
        # measured coverage of the class of worktree this tool prunes (signal 1 vetoed 0 of 4 real
        # siblings). The window is a gh round trip per candidate -- measured at 0.56s -- plus every
        # removal before this one, which is exactly the interval the re-check exists to close.
        if ($activityVeto -and -not $d.Confirmed) {
            $a2 = Get-WorktreeActivity -Path $d.Path
            $cut2 = (Get-Date).AddHours(-1 * $IdleHours)
            if ($null -eq $a2) {
                $d.Outcome = 'skipped'
                $d.OutcomeDetail = 're-check: activity became unreadable -- cannot establish nobody is in it'
                Write-Note "  SKIPPED: $($d.OutcomeDetail)" 'Yellow'
                continue
            }
            if ($a2 -gt $cut2) {
                $d.Outcome = 'skipped'
                $d.OutcomeDetail = "re-check: git metadata was touched $([math]::Round(((Get-Date) - $a2).TotalHours, 2)) h ago, inside the $IdleHours h window"
                Write-Note "  SKIPPED: $($d.OutcomeDetail)" 'Yellow'
                continue
            }
        }
        # Same routine the decision pass used, so the reason survives: this used to flatten a vanished
        # directory, an exit-128 status, an untracked file and a real edit into "no longer clean".
        $c2 = Test-WorktreeClean -Path $d.Path
        if (-not $c2.Clean) {
            $d.Outcome = 'skipped'
            $d.OutcomeDetail = "re-check: $($c2.Reasons -join '; ')"
            Write-Note "  SKIPPED: $($d.OutcomeDetail)" 'Yellow'
            continue
        }

        # --force suppresses git's refusal on untracked/modified files -- the exact refusal that would
        # have prevented the incident -- so it is only ever reached after this script has established
        # the tree is clean itself. (It is NOT needed for the ignored .venv: git's own check ignores
        # ignored files, contrary to the comment that used to live here. It also does not override a
        # lock; that needs -f -f, which this script never passes.)
        $out = @(& git -C $RepoRoot worktree remove --force $d.Path 2>&1)
        $removeExit = $LASTEXITCODE
        $err = ($out -join ' ').Trim()
        $dirExists = Test-Path -LiteralPath $d.Path
        $ptrExists = $dirExists -and (Test-Path -LiteralPath (Join-Path $d.Path '.git'))
        $stillRegistered = @(Get-RepoWorktrees $RepoRoot | Where-Object { (ConvertTo-Norm $_.Path) -eq (ConvertTo-Norm $d.Path) }).Count -gt 0

        # OUTCOME, NOT EXIT CODE. Exit 0 is git's claim; the directory being gone and deregistered is
        # the fact. Only the fact is counted as removed.
        if ($removeExit -eq 0 -and -not $dirExists -and -not $stillRegistered) {
            $removed++
            $d.Outcome = 'removed'
            $b = Remove-BranchSafely -Decision $d
            $d.BranchOutcome = $b.Outcome
            $d.BranchDetail = $b.Detail
            if ($b.Outcome -eq 'kept') {
                $branchesKept++
                Write-Note "  removed; branch '$($d.Branch)' KEPT: $($b.Detail)" 'Yellow'
            }
            else {
                $branchesDeleted++
                Write-Note "  removed; branch $($b.Outcome).$(if ($b.Detail) { " $($b.Detail)" })" 'Green'
            }
        }
        elseif ($removeExit -eq 0) {
            # git said it worked and it did not. Do NOT touch the branch on an unverified removal.
            $failed++
            Set-Exit $EXIT_FAILED
            $d.Outcome = 'failed'
            # A DELIBERATE keep, so it is counted as one. The failure paths used to leave the branch
            # alone and say so in prose while the summary reported "0 kept".
            $d.BranchOutcome = 'kept'
            $d.BranchDetail = 'the removal could not be verified, so the branch was left alone'
            $branchesKept++
            $d.OutcomeDetail = "git reported success but the directory $(if ($dirExists) { 'still exists' } else { 'is gone' }) and it is $(if ($stillRegistered) { 'STILL REGISTERED' } else { 'deregistered' }); branch '$($d.Branch)' was left alone"
            Write-Note "  FAILED: $($d.OutcomeDetail)" 'Red'
        }
        else {
            # A NON-ZERO EXIT DOES NOT MEAN NOTHING HAPPENED. git deletes the .git pointer and
            # deregisters the worktree before it walks the tree, and it deregisters even when that walk
            # fails ("no going back from here"). Diagnose what actually survived.
            $failed++
            Set-Exit $EXIT_FAILED
            $d.BranchOutcome = 'kept'
            $d.BranchDetail = 'the removal failed, so the branch was left alone'
            $branchesKept++
            $fileCount = 0
            if ($dirExists) {
                $probe = @(Get-ChildItem -LiteralPath $d.Path -Recurse -File -Force -EA SilentlyContinue | Select-Object -First 501)
                $fileCount = $probe.Count
            }
            $fileText = if ($fileCount -gt 500) { '500+' } else { "$fileCount" }

            if (-not $dirExists) {
                $d.Outcome = 'failed'
                $d.OutcomeDetail = "git exited $removeExit ($err) but the directory is gone; branch '$($d.Branch)' was left alone"
                Write-Note "  FAILED (exit $removeExit): $err" 'Red'
                Write-Note "  The directory is gone but git reported an error, so the branch was NOT deleted." 'Yellow'
            }
            elseif (-not $ptrExists -or -not $stillRegistered) {
                $orphaned++
                Set-Exit $EXIT_ORPHANED
                $d.Outcome = 'orphaned'
                # Remembered on disk: git has deregistered it, so it will not be in the candidate set of
                # any future run and nothing else would ever mention it again.
                $newOrphans += [pscustomobject]@{ path = $d.Path; branch = $d.Branch; at = (Get-Date).ToString('o'); detail = $err }
                $ptrText = if ($ptrExists) { 'intact' } else { 'DELETED' }
                $d.OutcomeDetail = "ORPHANED: .git pointer $ptrText, $fileText file(s) left, registered=$stillRegistered ($err)"
                Write-Note "  FAILED (exit $removeExit): $err" 'Red'
                Write-Note "  ORPHANED -- this is the state that nearly cost a session its work:" 'Red'
                Write-Note "    directory:      still on disk ($fileText file(s) remain)" 'Red'
                Write-Note "    .git pointer:   $(if ($ptrExists) { 'intact' } else { 'DELETED -- git no longer recognises this directory' })" 'Red'
                Write-Note "    registration:   $(if ($stillRegistered) { 'still listed by git worktree list' } else { 'DEREGISTERED' })" 'Red'
                Write-Note "    Any session working there will now see 'fatal: not a git repository'." 'Red'
                if ($ptrExists) {
                    Write-Note "    Try 'git -C ""$RepoRoot"" worktree repair ""$($d.Path)""' FIRST -- the .git file survived, so" 'Red'
                    Write-Note "    the registration may be re-creatable in place. If that fails, use the move-aside recipe:" 'Red'
                }
                else {
                    Write-Note "    'git worktree repair' cannot fix it (the .git file it needs is gone) and" 'Red'
                    Write-Note "    'git worktree add --force' refuses (the directory already exists). Recover it:" 'Red'
                }
                Write-Note "      1. close anything holding files open in it (an editor, a shell sitting in it)" 'Red'
                Write-Note "      2. Move-Item '$($d.Path)' '$($d.Path).salvage'" 'Red'
                Write-Note "      3. git -C '$RepoRoot' worktree add '$($d.Path)' '$($d.Branch)'" 'Red'
                Write-Note "      4. copy anything you need out of '$($d.Path).salvage' (stashes are safe -- they live in the shared .git)" 'Red'
                Write-Note "    The branch was NOT deleted, and 'git worktree prune' was NOT run." 'Red'
            }
            else {
                $d.Outcome = 'failed'
                $d.OutcomeDetail = "nothing destroyed: directory, .git pointer and registration intact ($err)"
                Write-Note "  FAILED (exit $removeExit): $err" 'Red'
                Write-Note "  Nothing was destroyed: the directory, its .git pointer and its registration are intact." 'Yellow'
            }
        }
    }
}
elseif ($Apply) {
    Write-Note "" ; Write-Note "Nothing to prune." 'Green'
}

$skipped = @($decisions | Where-Object { $_.Decision -eq 'SKIP' -or $_.Outcome -eq 'skipped' }).Count
# Now that the apply loop has run, count what the fence ACTUALLY stopped -- including the re-check
# saves, and still split by source so neither can be read as coverage the other provided.
$fenceVetoed = @($decisions | Where-Object { $_.Occupants.Count -gt 0 }).Count
$cwdVetoed = Measure-SignalVetoes $decisions 'cwd'
$footprintVetoed = Measure-SignalVetoes $decisions 'footprint'
$pinVetoed = Measure-SignalVetoes $decisions 'pin'
$withoutFootprint = @($decisions | Where-Object { @($_.Occupants | Where-Object { $_.Source -eq 'footprint' }).Count -eq 0 }).Count
if (-not $Json -and $fenceVetoed -gt $fenceVetoedAtDecision) {
    Write-Host ("  The fence vetoed {0} further candidate(s) during the removal pass (total {1} of {2}: {3} by recorded cwd, {4} by write footprint)." -f
        ($fenceVetoed - $fenceVetoedAtDecision), $fenceVetoed, $decisions.Count, $cwdVetoed, $footprintVetoed) -ForegroundColor DarkCyan
}

# -Name asked for something that does not exist, so the operator's instruction was NOT carried out. It
# used to print one yellow line and exit 0 with a green summary -- the same "green no-op" shape as the
# wrong-cwd case this script now refuses outright.
if ($namedMisses.Count -gt 0) { Set-Exit $(if ($removed -gt 0) { $EXIT_FAILED } else { $EXIT_REFUSED }) }

# Persist the orphan ledger: what is still broken, plus anything this run broke. Written only under
# -Apply -- a dry run reports the same state without touching anything.
$ledgerOut = @()
foreach ($o in $priorOrphans) { $ledgerOut += [pscustomobject]@{ path = $o.Path; branch = $o.Branch; at = $o.At; detail = $o.Why } }
$ledgerOut += $newOrphans
$ledgerNote = ''
if ($Apply -and $ledgerPath) {
    try {
        if ($ledgerOut.Count -gt 0) { ($ledgerOut | ConvertTo-Json -Depth 4 -AsArray) | Set-Content -LiteralPath $ledgerPath -Encoding utf8 }
        elseif (Test-Path -LiteralPath $ledgerPath) { Remove-Item -LiteralPath $ledgerPath -Force }
    }
    catch { $ledgerNote = "could not write the orphan ledger at ${ledgerPath}: $($_.Exception.Message)" }
}

# --- Report --------------------------------------------------------------------------------------
if ($Json) {
    [pscustomobject]@{
        repoRoot = $RepoRoot
        apply    = [bool]$Apply
        fence    = [pscustomobject]@{
            # FAIL-CLOSED HEADLINE: false if the fence was unavailable at EITHER read. It used to report
            # the decision-pass verdict only, so a fence that died mid-run produced `available: true`
            # next to `exitCode: 2` with no field to reconcile them.
            available          = ([bool]$occ.Available -and ($null -eq $occ2 -or [bool]$occ2.Available))
            availableAtDecision = [bool]$occ.Available
            availableAtApply   = if ($null -eq $occ2) { $null } else { [bool]$occ2.Available }
            detail             = $occ.Detail
            detailAtApply      = if ($null -eq $occ2) { '' } else { [string]$occ2.Detail }
            rootsExamined      = $occ.RootsExamined
            recordsExamined    = $occ.RecordsExamined
            recordsUnplaceable = $occ.RecordsUnplaceable
            unplaceableFiles   = @($occ.UnplaceableFiles)
            liveInRepo         = $liveInRepo
            vetoedCandidates   = $fenceVetoed
            vetoedCandidatesAtDecision = $fenceVetoedAtDecision
            # PER SOURCE, never only the total: the total cannot show that one signal has gone to zero,
            # and one of them measurably had.
            vetoedByCwd        = $cwdVetoed
            vetoedByFootprint  = $footprintVetoed
            vetoedByPin        = $pinVetoed
            candidatesWithoutFootprint = $withoutFootprint
            pins               = if ($null -eq $pinSet) { $null } else {
                [pscustomobject]@{
                    available   = [bool]$pinSet.Available
                    detail      = [string]$pinSet.Detail
                    note        = [string]$pinSet.Note
                    dir         = [string]$pinSet.Dir
                    examined    = $pinSet.PinsExamined
                    unreadable  = $pinSet.PinsUnreadable
                    expired     = $pinSet.PinsExpired
                    gone        = $pinSet.PinsGone
                    unplaceable = $pinSet.PinsUnplaceable
                    faults      = @($pinSet.Faults)
                }
            }
            blindSpots         = $blindSpots
            idleHours          = $IdleHours
            footprintHours     = $FootprintHours
            activityVeto       = $activityVeto
            footprint          = if ($null -eq $fp) { $null } else {
                [pscustomobject]@{
                    available            = [bool]$fp.Available
                    detail               = [string]$fp.Detail
                    note                 = [string]$fp.Note
                    windowHours          = $fp.WindowHours
                    rootsExamined        = $fp.RootsExamined
                    rootsWithCorpus      = $fp.RootsWithCorpus
                    transcriptsFound     = $fp.TranscriptsFound
                    transcriptsInWindow  = $fp.TranscriptsInWindow
                    transcriptsVanished  = $fp.TranscriptsVanished
                    transcriptsWithNeedle = $fp.TranscriptsWithNeedle
                    bytesScanned         = $fp.BytesScanned
                    linesScanned         = $fp.LinesScanned
                    linesParsed          = $fp.LinesParsed
                    linesUnparseableElsewhere = $fp.LinesUnparseableElsewhere
                    pathToolBlocks       = $fp.PathToolBlocks
                    pathBlocksExamined   = $fp.PathBlocksExamined
                    toolNamesSeen        = @($fp.ToolNamesSeen)
                    writeToolsAllowList  = @($fp.WriteToolsAllowList)
                    writeToolNamesSeen   = @($fp.WriteToolNamesSeen)
                    writesExamined       = $fp.WritesExamined
                    writesOutsideWindow  = $fp.WritesOutsideWindow
                    writesUndated        = $fp.WritesUndated
                    writesPlaced         = $fp.WritesPlaced
                    writesUnplaced       = $fp.WritesUnplaced
                    placedByPrefix       = $fp.PlacedByPrefix
                    placedByGitdir       = $fp.PlacedByGitdir
                    gitdirProbes         = $fp.GitdirProbes
                    sidechainFiles       = $fp.SidechainFiles
                    sidechainLines       = $fp.SidechainLines
                    sidechainPathToolBlocks = $fp.SidechainPathToolBlocks
                    sidechainPathBlocks  = $fp.SidechainPathBlocks
                    crossTreeWrites      = $fp.CrossTreeWrites
                    faults               = @($fp.Faults)
                }
            }
            reducedAssurance   = @($reducedAssurance)
        }
        refs     = $fetchDetail
        fetched  = $fetched
        gh       = $ghDetail
        ghProbes = [pscustomobject]@{ attempted = $ghAttempts; failed = $ghFailures; firstError = $ghFirstError }
        candidates = @($decisions)
        excluded = @($excluded | ForEach-Object { [pscustomobject]@{ leaf = (Split-Path $_.Wt.Path -Leaf); reason = $_.Why } })
        namedMisses = @($namedMisses)
        orphansFromEarlierRuns = @($priorOrphans | ForEach-Object { [pscustomobject]@{ leaf = $_.Leaf; path = $_.Path; branch = $_.Branch; why = $_.Why } })
        ledger   = [pscustomobject]@{ path = $ledgerPath; persisted = ($Apply -and -not $ledgerNote); note = $ledgerNote }
        counts   = [pscustomobject]@{
            candidates      = $decisions.Count
            prunable        = $prunable.Count
            removed         = $removed
            # `orphaned` is a SUBSET of `failed`, not a sibling of it: removed+failed+skipped covers
            # every candidate exactly once. failedNonOrphan is spelled out so a consumer cannot reach
            # the wrong total by adding all four.
            failed          = $failed
            failedNonOrphan = ($failed - $orphaned)
            orphaned        = $orphaned
            orphansFromEarlierRuns = $priorOrphans.Count
            skipped         = $skipped
            branchesDeleted = $branchesDeleted
            branchesKept    = $branchesKept
        }
        exitCode = $exit
    } | ConvertTo-Json -Depth 6 | Write-Output
    exit $exit
}

Write-Host ""
if (-not $Apply) {
    if ($prunable.Count -eq 0) {
        Write-Host "DRY RUN - nothing would be removed ($($decisions.Count) candidate(s) examined, all skipped)." -ForegroundColor Green
    }
    else {
        Write-Host "DRY RUN - $($prunable.Count) of $($decisions.Count) candidate(s) would be removed. Re-run with -Apply to act." -ForegroundColor Yellow
        Write-Host "  -Apply re-evaluates everything itself; it never acts on the table you read a minute ago." -ForegroundColor DarkGray
    }
}
else {
    # Outcomes, not intentions. Coloured by the EXIT CODE, not by $failed: a run where the fence died
    # and every removal was refused has failed 0 and used to print that line in green next to exit 2.
    $orphanText = if ($orphaned) { " ($orphaned ORPHANED, counted inside failed)" } else { "" }
    Write-Host "Done. removed $removed, failed $failed$orphanText, skipped $skipped of $($decisions.Count) candidate(s)." -ForegroundColor $(if ($exit -eq $EXIT_OK) { 'Green' } else { 'Red' })
    Write-Host "  branches: $branchesDeleted deleted, $branchesKept kept." -ForegroundColor DarkGray
}

# Orphans from an EARLIER run. Git no longer lists them, so nothing else in this report would.
if ($priorOrphans.Count -gt 0) {
    Write-Host ""
    Write-Host "$($priorOrphans.Count) ORPHANED director(ies) from an earlier run are still broken on disk:" -ForegroundColor Red
    foreach ($o in $priorOrphans) {
        Write-Host "  $($o.Leaf)  --  $($o.Why)" -ForegroundColor Red
        Write-Host "    Any session working there sees 'fatal: not a git repository'. Recover it:" -ForegroundColor Red
        Write-Host "      1. close anything holding files open in it (an editor, a shell sitting in it)" -ForegroundColor Red
        Write-Host "      2. Move-Item '$($o.Path)' '$($o.Path).salvage'" -ForegroundColor Red
        Write-Host "      3. git -C '$RepoRoot' worktree add '$($o.Path)'$(if ($o.Branch) { " '$($o.Branch)'" })" -ForegroundColor Red
        Write-Host "      4. copy anything you need out of '$($o.Path).salvage'" -ForegroundColor Red
    }
    if (-not $Apply) { Write-Host "  (this list is re-derived every run; it clears itself once the directory is gone or re-registered)" -ForegroundColor DarkGray }
}
if ($ledgerNote) { Write-Host "  NOTE: $ledgerNote" -ForegroundColor Yellow }

foreach ($r in $reducedAssurance) { Write-Host "  REDUCED ASSURANCE: $r" -ForegroundColor Red }
if ($exit -eq $EXIT_REFUSED) {
    if (-not $occ.Available -or ($null -ne $occ2 -and -not $occ2.Available)) {
        Write-Host "  Exit 2: the occupancy fence was unavailable, so nothing was eligible. Fix the fence, don't bypass it." -ForegroundColor Red
        if ($null -ne $occ2 -and -not $occ2.Available) {
            Write-Host "    It was available when the table was built and gone by the time of the removal: $($occ2.Detail)" -ForegroundColor Red
        }
    }
    if ($namedMisses.Count -gt 0) {
        Write-Host "  Exit 2: -Name named $($namedMisses -join ', '), which matched no prunable sibling, so what you asked for did not happen." -ForegroundColor Red
    }
}
elseif ($exit -eq $EXIT_ORPHANED) {
    Write-Host "  Exit 3: a directory is broken on disk RIGHT NOW. It is not a failed no-op -- follow the recipe above." -ForegroundColor Red
}
exit $exit
