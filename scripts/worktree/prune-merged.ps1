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

    THIS TOOL DESTROYS OTHER SESSIONS' WORK IF IT IS WRONG. It removed an occupied worktree once:
    `git worktree remove --force` deleted the .git pointer, deregistered the tree, then failed to
    delete the directory, leaving a folder git no longer recognised -- the session working there had
    every subsequent git command fail. So the bias here is fixed and not negotiable: a false SKIP is a
    minor annoyance, a false PRUNE destroys a session. Every check that cannot reach a confident
    answer SKIPs. Nothing is ever traded for tidiness.

    OCCUPANCY IS NOT IMPLIED BY CLEAN+MERGED. A session can sit in a worktree with nothing
    uncommitted -- a brand-new worktree has zero commits, so it is "an ancestor of origin/main" and
    perfectly clean from the second it is created, which is exactly the state that got destroyed. Two
    independent occupancy signals are therefore required, and either one vetoes:

      1. THE LIVENESS FENCE (scripts/coord/occupancy.ps1, shared with presence.ps1). Reads
         <config-root>/sessions/<pid>.json, maps each session's recorded cwd onto a worktree, and
         fences it on pid + process start time. Only LIVE / UNVERIFIED / UNREADABLE veto, for the
         veto-only reason above. A session in a NESTED worktree vetoes its ancestor too.
      2. RECENT ACTIVITY (-IdleHours, default 36). Newest mtime of the worktree's PRIVATE git metadata
         (index, HEAD, logs/HEAD, ...). This is the signal that does NOT depend on a recorded cwd, and
         it is what covers the fence's biggest blind spot -- so it is not a nicety, it is the load-
         bearing one for the class of worktree this tool actually prunes. If it cannot be read, that is
         a veto too. Confirm a specific worktree past this veto with -Name <slug>; -Name never
         overrides signal 1, a nested worktree, or a lock.

    WHAT THE FENCE CANNOT SEE (printed on every run, because a fence believed to be wider than it is
    is worse than no fence):
      * a session that writes into this worktree BY ABSOLUTE PATH from somewhere else -- measured on
        this repo, 29% of writes come from a session sitting in the primary and land in a sibling.
        Measured again 2026-07-30: 5 live sessions, 9 worktrees, and signal 1 vetoed NONE of the four
        `<primary>-<slug>` siblings, including one a session was demonstrably building in. Signal 2 is
        what stood between that session and this script;
      * a cwd recorded as a UNC (\\host\C$\...) or 8.3 short path -- the match is a normalised string
        compare, and neither spelling normalises to the worktree's own path;
      * a session that never registered;
      * a session that only Writes/Edits files and runs no git command: it touches none of the seven
        metadata files, so signal 2 goes quiet on it as well.
    It DOES see VS Code sessions: the file registry carries every surface, and the match is purely
    path-based (the Desktop app's own session tooling only lists what it spawned).

    FENCE UNAVAILABLE => NOTHING IS PRUNED, LOUDLY (exit 2). "The fence found nobody" and "the fence
    could not look" are the same empty answer, so availability is checked explicitly: at least one
    config root with a session registry, and at least one readable record. When it is unavailable
    every candidate becomes SKIP and the run exits non-zero rather than silently pruning unfenced.
    There is deliberately no override flag. -IdleHours 0 and an explicit -ConfigRoot each REDUCE
    assurance rather than bypassing it silently: both are named in red on the run and in the JSON
    receipt, because an operator who believes they are fenced when they are not is worse off than one
    who knows they aren't.

    OUTCOMES, NOT INTENTIONS. The summary counts what actually happened -- removed / failed / skipped,
    branches deleted / kept -- because a destructive tool that over-reports what it destroyed is
    actively misleading (it used to print the count of candidates it INTENDED to remove). A removal is
    only counted as removed once the directory is verified gone and deregistered. A failed removal is
    diagnosed on the spot: git deregisters a worktree even when it cannot finish deleting the files, so
    this reports whether the directory, its .git pointer and its registration survived, and prints the
    recovery recipe for the orphaned case. `git worktree prune` is never run -- it deregisters ANY
    worktree whose directory is momentarily missing, including the .claude/worktrees ones this script
    must never touch, and it would finish the destruction a failed removal left half done.

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
    # worktrees. 0 turns signal 2 OFF and the run says so in red.
    [double]$IdleHours = 36,
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

$occ = Get-WorktreeOccupancy -Repo $RepoRoot -ConfigRoot $ConfigRoot -StartSkewMinutes $StartSkewMinutes

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

# Anything that narrows what the two occupancy signals can see. Named on the run and in the JSON, so a
# reduced fence is never mistaken for a full one.
$activityVeto = ($IdleHours -gt 0)
$reducedAssurance = @()
if (-not $activityVeto) {
    $reducedAssurance += 'activity veto DISABLED (-IdleHours 0): signal 2 is OFF, so a session writing in by absolute path is invisible to this run'
}
if ($ConfigRoot) {
    $reducedAssurance += "liveness fence scoped to an explicit -ConfigRoot ($($ConfigRoot -join ', ')): the machine's real session registry was NOT consulted"
}

# --- Refresh refs (see -Fetch) -------------------------------------------------------------------
$fetched = $false
$fetchDetail = ''
if ($SkipFetch) { $fetchDetail = 'skipped (-SkipFetch): merge decisions use whatever refs are on disk' }
elseif (-not ($Apply -or $Fetch)) { $fetchDetail = 'skipped (dry run): pass -Fetch to refresh origin/* first' }
else {
    Write-Note "Fetching origin (--prune)..."
    & git -C $RepoRoot fetch origin --prune --quiet 2>$null
    if ($LASTEXITCODE -eq 0) { $fetched = $true; $fetchDetail = 'origin fetched (--prune)' }
    else { $fetchDetail = "FETCH FAILED (exit $LASTEXITCODE): merge decisions are being made against stale refs" }
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
$ghDetail =
if ($SkipGh) { 'PR probe skipped (-SkipGh)' }
elseif (-not $ghSlug) { 'PR probe skipped: origin is not a GitHub remote' }
elseif (-not $hasGh) { 'PR probe skipped: gh is not installed' }
else { "PR probe scoped to $ghSlug" }

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
        $raw = & gh pr list --repo $ghSlug --head $Branch --state merged --json number,headRefOid --limit 20 2>$null
        if ($LASTEXITCODE -eq 0 -and $raw) {
            $prs = $null
            try { $prs = @($raw | ConvertFrom-Json) } catch { $prs = @() }
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
$siblings = @($occ.Worktrees | Where-Object {
        ($_.Path -replace '\\', '/').StartsWith("$RepoRootFwd-", [StringComparison]::OrdinalIgnoreCase) -and
        $_.Branch -and -not $_.Bare -and -not $_.Detached
    })

# Detached and bare siblings are never candidates, but say so rather than leaving the operator to
# wonder whether they were considered at all.
$excluded = @($occ.Worktrees | Where-Object {
        ($_.Path -replace '\\', '/').StartsWith("$RepoRootFwd-", [StringComparison]::OrdinalIgnoreCase) -and
        ($_.Detached -or $_.Bare -or -not $_.Branch)
    })

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
    $occupants = @()
    if ($occ.Available) {
        $occupants = @(Get-WorktreeOccupants -Occupancy $occ -Path $Wt.Path -IncludeNested)
        if ($occupants.Count -gt 0) {
            $who = ($occupants | ForEach-Object {
                    $where = if ((ConvertTo-Norm $_.WorktreePath) -eq (ConvertTo-Norm $Wt.Path)) { '' } else { " in nested $($_.Worktree)" }
                    "$($_.Short) [$($_.State)]$where"
                }) -join ', '
            $reasons += "occupied by $($occupants.Count) session(s): $who"
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

    # Clean. FAILS CLOSED: an unreadable status (a moved-away or half-deleted worktree exits 128 with
    # no output) used to be indistinguishable from "no changes" and pointed straight at destruction.
    $clean = $false
    if (-not (Test-Path -LiteralPath $Wt.Path)) {
        $reasons += 'directory is missing (already half-removed? investigate before pruning)'
    }
    else {
        $status = @(& git -C $Wt.Path --no-optional-locks status --porcelain 2>$null)
        $statusExit = $LASTEXITCODE
        if ($statusExit -ne 0) {
            $reasons += "git status failed (exit $statusExit) -- cannot establish it is clean"
        }
        else {
            $trackedChanges = @($status | Where-Object { $_ -notmatch '^\?\?' })
            $untracked = @($status | Where-Object { $_ -match '^\?\?' })
            if ($trackedChanges.Count -gt 0) {
                $reasons += "dirty: $($trackedChanges.Count) uncommitted tracked change(s)"
            }
            # Untracked (NOT ignored -- .venv/node_modules never appear here) files are the one loss
            # class with no recovery: not in the index, not in a stash, not in the reflog. `--force`
            # suppresses git's own refusal on them, so this must not wave them through.
            if ($untracked.Count -gt 0) {
                $reasons += "$($untracked.Count) untracked file(s) present -- --force would delete them unrecoverably"
            }
            $clean = ($trackedChanges.Count -eq 0 -and $untracked.Count -eq 0)
        }
    }

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
        Occupants    = @($occupants | ForEach-Object { [pscustomobject]@{ Short = $_.Short; State = $_.State; Surface = $_.Entrypoint; Cwd = $_.Cwd; Worktree = $_.Worktree } })
        ActivityAgeHours = $activityAge
        Confirmed    = [bool]$Confirmed
        Outcome      = 'not attempted'
        OutcomeDetail = ''
        BranchOutcome = 'kept'
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

# --- The fence receipt: count what was EXAMINED, not what was found ------------------------------
$liveInRepo = @($occ.Sessions | Where-Object { Test-OccupancyVeto $_.State }).Count
# What signal 1 actually CONTRIBUTED here, which is not the same as how many sessions it saw. On this
# repo the honest number has been 0 of 4 while three of those worktrees were occupied in fact.
$fenceVetoed = @($decisions | Where-Object { $_.Occupants.Count -gt 0 }).Count
$blindSpots = @(
    'a session writing into a worktree by absolute path from elsewhere (29% of writes on this repo)',
    'a cwd recorded as a UNC or 8.3 short path',
    'a session that never registered',
    'a session that only edits files and runs no git command (invisible to signal 2 as well)'
)

if (-not $Json) {
    Write-Host ""
    if ($occ.Available) {
        Write-Host ("Occupancy fence: {0} config root(s), {1} record(s) examined, {2} live session(s) in this repo family." -f
            $occ.RootsExamined, $occ.RecordsExamined, $liveInRepo) -ForegroundColor DarkCyan
        Write-Host ("  Sessions it placed INSIDE a candidate: {0} of {1} candidate(s) vetoed by signal 1." -f
            $fenceVetoed, $decisions.Count) -ForegroundColor DarkCyan
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
        Write-Host ("{0,-42} {1,-30} not a candidate (detached/bare)" -f (Split-Path $e.Path -Leaf), $e.Branch) -ForegroundColor DarkGray
    }
    foreach ($n in $namedMisses) {
        Write-Host "  -Name '$n' matched no sibling worktree." -ForegroundColor Yellow
    }
}

# --- Apply ---------------------------------------------------------------------------------------
$removed = 0; $failed = 0; $branchesDeleted = 0; $branchesKept = 0; $orphaned = 0
$exit = $EXIT_OK
if (-not $occ.Available) { $exit = $EXIT_REFUSED }

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

if ($Apply -and $prunable.Count -gt 0) {
    # Re-read occupancy immediately before acting: the decision pass above costs a gh round trip per
    # candidate, and a session can arrive inside that window.
    $occ2 = Get-WorktreeOccupancy -Repo $RepoRoot -ConfigRoot $ConfigRoot -StartSkewMinutes $StartSkewMinutes
    Write-Note ""
    foreach ($d in $prunable) {
        if (-not $Json) { Write-Host "Removing $($d.Leaf) [$($d.Branch)]..." -ForegroundColor Cyan }

        # Re-check the things that can change under us in seconds.
        if (-not $occ2.Available) {
            $d.Outcome = 'skipped'
            $d.OutcomeDetail = "re-check: fence became unavailable ($($occ2.Detail))"
            $exit = $EXIT_REFUSED
            Write-Note "  SKIPPED: $($d.OutcomeDetail)" 'Yellow'
            continue
        }
        $now = @(Get-WorktreeOccupants -Occupancy $occ2 -Path $d.Path -IncludeNested)
        if ($now.Count -gt 0) {
            $d.Outcome = 'skipped'
            $d.OutcomeDetail = "re-check: a session arrived ($(($now | ForEach-Object { $_.Short }) -join ', '))"
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
        $recheck = @(& git -C $d.Path --no-optional-locks status --porcelain 2>$null)
        if ($LASTEXITCODE -ne 0 -or $recheck.Count -gt 0) {
            $d.Outcome = 'skipped'
            $d.OutcomeDetail = 're-check: no longer clean'
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
            $exit = $EXIT_FAILED
            $d.Outcome = 'failed'
            $d.OutcomeDetail = "git reported success but the directory $(if ($dirExists) { 'still exists' } else { 'is gone' }) and it is $(if ($stillRegistered) { 'STILL REGISTERED' } else { 'deregistered' }); branch '$($d.Branch)' was left alone"
            Write-Note "  FAILED: $($d.OutcomeDetail)" 'Red'
        }
        else {
            # A NON-ZERO EXIT DOES NOT MEAN NOTHING HAPPENED. git deletes the .git pointer and
            # deregisters the worktree before it walks the tree, and it deregisters even when that walk
            # fails ("no going back from here"). Diagnose what actually survived.
            $failed++
            $exit = $EXIT_FAILED
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
                $d.Outcome = 'orphaned'
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

# --- Report --------------------------------------------------------------------------------------
if ($Json) {
    [pscustomobject]@{
        repoRoot = $RepoRoot
        apply    = [bool]$Apply
        fence    = [pscustomobject]@{
            available          = [bool]$occ.Available
            detail             = $occ.Detail
            rootsExamined      = $occ.RootsExamined
            recordsExamined    = $occ.RecordsExamined
            liveInRepo         = $liveInRepo
            vetoedCandidates   = $fenceVetoed
            blindSpots         = $blindSpots
            idleHours          = $IdleHours
            activityVeto       = $activityVeto
            reducedAssurance   = @($reducedAssurance)
        }
        refs     = $fetchDetail
        fetched  = $fetched
        gh       = $ghDetail
        candidates = @($decisions)
        excluded = @($excluded | ForEach-Object { [pscustomobject]@{ leaf = (Split-Path $_.Path -Leaf); reason = 'detached/bare' } })
        namedMisses = @($namedMisses)
        counts   = [pscustomobject]@{
            candidates      = $decisions.Count
            prunable        = $prunable.Count
            removed         = $removed
            failed          = $failed
            orphaned        = $orphaned
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
    # Outcomes, not intentions.
    $orphanText = if ($orphaned) { " ($orphaned ORPHANED)" } else { "" }
    Write-Host "Done. removed $removed, failed $failed$orphanText, skipped $skipped of $($decisions.Count) candidate(s)." -ForegroundColor $(if ($failed) { 'Red' } else { 'Green' })
    Write-Host "  branches: $branchesDeleted deleted, $branchesKept kept." -ForegroundColor DarkGray
}
foreach ($r in $reducedAssurance) { Write-Host "  REDUCED ASSURANCE: $r" -ForegroundColor Red }
if (-not $occ.Available) {
    Write-Host "  Exit 2: the occupancy fence was unavailable, so nothing was eligible. Fix the fence, don't bypass it." -ForegroundColor Red
}
exit $exit
