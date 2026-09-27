# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Write a read-only hygiene report: the primary checkout, every worktree, installed-hook drift, and a
    proposed cleanup list for the owner to approve in one go.

.DESCRIPTION
    Owner ruling 2026-09-26. The Lander flags the hygiene its own merges leave, and a scheduled script
    with zero model calls writes this report. NOTHING IS DELETED AUTOMATICALLY. This script never
    removes, prunes, resets, checks out, cleans, switches or pushes anything. The cleanup list it
    writes is text for the owner, and the script runs none of it.

    tests/test_worktree_hygiene_report.py pins that by parsing this file: every `git` invocation must
    use a verb from a read-only allowlist, and no delete cmdlet may appear. Keep every git call LITERAL
    (`git -C $x status ...`), never a splatted verb, or that scan cannot see what runs.

    WHAT IT WRITES ON PURPOSE: refs and FETCH_HEAD from the `git fetch origin main` in each clone, and
    the report files in -OutDir. The fetch passes --no-auto-maintenance, so it cannot start a
    `gc --auto` (which would expire reflogs and prune worktree records), and never --prune, so it
    deletes no ref. Status passes --no-optional-locks, so it does not rewrite any worktree's index.
    That last one matters beyond tidiness: prune-merged.ps1 reads the index mtime as recent activity,
    so a report that touched every index every six hours would veto every prune.

    WHAT IT REPORTS, per clone (the engine's primary checkout, plus -ExtraRoot):
      a. The primary checkout: branch, uncommitted files, and ahead/behind origin/main after a fetch.
         In a SHALLOW clone those counts are a FLOOR, never a distance: commits past the shallow
         boundary are not on disk to be counted. With no merge base visible, it prints no count.
      b. Every registered worktree: path, branch, whether the directory still exists, last commit date,
         uncommitted count, and whether its branch MERGED.
      c. Installed-hook drift, read by running that clone's own scripts\coord\install-git-hooks.ps1
         -Status. Nothing here re-implements that check; this only picks out the lines worth reading.
      d. A proposed cleanup list, and a separate NEEDS A HUMAN LOOK list.

    "MERGED" COMES FROM GITHUB, ONE BULK CALL PER CLONE PER RUN. This repository squash-merges, so
    `merge-base --is-ancestor` cannot see a landing, and the clone is shallow as well. One
    `gh pr list --state merged` call per clone returns every merged head name and head SHA, and one
    `git ls-remote --heads origin` says which remote branches still exist. There is never an API call
    per worktree: the fleet shares one GitHub API budget. When gh is missing or fails, every merge
    status reads UNKNOWN and nothing is proposed for removal. It never guesses. Only a same-repository
    PR into -MainBranch counts; a fork PR whose head name collides, or a PR stacked onto another
    branch, does not.

    WHAT "MERGED" CANNOT SEE. A branch merged INSIDE another pull request -- a Builder branch a Manager
    folded into one wave PR -- has no merged PR under its own name, so it reads NOT MERGED here. That
    is the safe direction: it is left alone, never proposed.

    A MERGED WORKTREE IS PROPOSED FOR REMOVAL ONLY WHEN ALL OF THESE HOLD, and otherwise goes to NEEDS
    A HUMAN LOOK with the reasons:
      * its tip IS the head of a merged PR. A name match alone is not enough: a branch that kept
        moving after its PR merged carries work that PR did not land;
      * that PR merged more than -HoldHours ago;
      * none of its commit date, its private git files and its last reflog entry moved within
        -IdleHours (the recent-activity signal prune-merged.ps1 also relies on, read the same way
        but without that tool's floor);
      * `git status --porcelain --untracked-files=normal` is empty. An untracked `.venv` alone goes to
        a human, because removing it needs --force, and --force also turns off git's own refusal of a
        tree somebody has started editing since this report ran;
      * it is not locked, contains no other registered worktree, and the shared liveness fence
        (scripts\coord\occupancy.ps1, the one prune-merged.ps1 uses) could look and found no session
        in it or in a worktree nested inside it. A DEAD record there holds it too: once the tree is
        gone that record is unplaceable, and occupancy.ps1 then keeps the fence unavailable.

    THE FENCE SEES A SESSION BY THE CWD IT LAUNCHED IN. A session writing into a worktree by absolute
    path from somewhere else, or relocated into it after launch, is invisible to it. The activity
    window is what covers that case, and only while the session runs git there. The owner reads the
    list before running it, and `git worktree remove` without --force still refuses a tree with
    uncommitted changes on its own.

    WHY THIS IS NOT prune-merged.ps1 -Json. That tool decides for the `<repo>-<name>` siblings only and
    excludes `.claude/worktrees` by design. This report covers every registered worktree of each clone
    and only proposes. Its predicate is deliberately stricter on the merge (the exact tip) and has no
    reflog read; a prune-merged fix to occupancy lands here through occupancy.ps1, which both share.

    COST IS BOUNDED. One `git status` per existing worktree, run with -Throttle in parallel, plus a
    fixed handful of calls per clone. No network call is made per worktree.

    OUTPUT. `hygiene-<yyyy-MM-dd>.md` and `.json` in -OutDir, one pair per day (a later run the same day
    replaces it), plus `latest.md` and `latest.json`. Nothing here deletes old reports.

.PARAMETER RepoRoot
    Any checkout of the engine repository. The report is always about its PRIMARY checkout. Defaults to
    this script's own repository.

.PARAMETER ExtraRoot
    Other clones to scan the same way. Defaults to the `<primary>-vault` sibling beside the primary,
    when that directory is a clone of its own.

.PARAMETER NoExtraRoots
    Scan the engine clone only.

.PARAMETER OutDir
    Where the report goes. Defaults to `<git common dir>/mefor-coord/hygiene/`, which is untracked and
    shared by every worktree.

.PARAMETER Gh
    The gh command to call. Defaults to $env:MEFOR_HYGIENE_GH, else `gh`. Tests point it at a fake.

.PARAMETER GhRepo
    owner/repo for the engine clone's merged-PR call. Defaults to what `origin` names.

.PARAMETER IdleHours
    A merged worktree whose commit date, index or HEAD moved within this many hours is held for a human.
    Default 72, prune-merged.ps1's default. 0 turns the hold off.

.PARAMETER ConfigRoot
    Claude config roots for the liveness fence. Defaults to every <userprofile>\.claude* registry.

.EXAMPLE
    pwsh -NoProfile -File scripts\worktree\hygiene-report.ps1
    pwsh -NoProfile -File scripts\worktree\hygiene-report.ps1 -SkipFetch -NoExtraRoots
#>
[CmdletBinding()]
param(
    [string]$RepoRoot,
    [string[]]$ExtraRoot,
    [switch]$NoExtraRoots,
    [string]$OutDir,
    [string]$Gh,
    [string]$GhRepo,
    [switch]$SkipGh,
    [switch]$SkipFetch,
    [string]$MainBranch = 'main',
    [int]$PrLimit = 3000,
    [double]$HoldHours = 24,
    [double]$IdleHours = 72,
    [int]$Throttle = 8,
    [string[]]$ConfigRoot
)

$ErrorActionPreference = 'Stop'
# A non-zero git or gh exit is DATA here (a missing remote, a failed fetch), never a throw.
$PSNativeCommandUseErrorActionPreference = $false
# A scheduled task has nobody to answer a credential prompt, in a terminal or in Git Credential
# Manager's window; fail the fetch instead of hanging until the task's time limit kills the run.
$env:GIT_TERMINAL_PROMPT = '0'
$env:GCM_INTERACTIVE = 'never'

. "$PSScriptRoot\..\coord\occupancy.ps1"

if (-not $Gh) { $Gh = if ($env:MEFOR_HYGIENE_GH) { $env:MEFOR_HYGIENE_GH } else { 'gh' } }
if (-not $RepoRoot) { $RepoRoot = $PSScriptRoot }
if (-not (Test-Path -LiteralPath $RepoRoot)) {
    [Console]::Error.WriteLine("hygiene-report: -RepoRoot does not exist: $RepoRoot")
    exit 2
}
# A negative window puts the cut-off in the future and silently disarms the check.
if ($IdleHours -lt 0 -or $HoldHours -lt 0) {
    [Console]::Error.WriteLine("hygiene-report: -IdleHours and -HoldHours must be 0 or more.")
    exit 2
}

# Which clone a path belongs to, identified by its git common directory.
function Get-CommonDir([string]$Path) {
    $common = git -C $Path rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $common) { return '' }
    return ([string]$common).Trim()
}

$engineCommon = Get-CommonDir $RepoRoot
if (-not $engineCommon) {
    [Console]::Error.WriteLine("hygiene-report: not inside a git repository: $RepoRoot")
    exit 2
}
if (-not $OutDir) { $OutDir = Join-Path $engineCommon 'mefor-coord/hygiene' }
$lastRun = Join-Path $OutDir 'last-run.txt'

# A run that dies leaves latest.md holding the previous run's content. Say so beside it, so a stale
# report is not read as a current one.
trap {
    try {
        New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
        Set-Content -LiteralPath $lastRun -Encoding utf8NoBOM -Value "FAILED $((Get-Date).ToString('o')): $($_.Exception.Message). latest.md is from an earlier run."
    }
    catch { [Console]::Error.WriteLine("hygiene-report: could not record the failure: $($_.Exception.Message)") }
    [Console]::Error.WriteLine("hygiene-report: FAILED: $($_.Exception.Message)")
    exit 1
}

$roots = @([pscustomobject]@{ Hint = $RepoRoot; Common = $engineCommon; Role = 'engine'; GhRepo = $GhRepo })
if (-not $NoExtraRoots) {
    if (-not $PSBoundParameters.ContainsKey('ExtraRoot')) {
        # The sibling beside the primary checkout. The primary is the first `worktree list` entry, the
        # same authority occupancy.ps1 and prune-merged.ps1 use.
        $enginePrimary = (Get-WorktreeOccupancy -Repo $RepoRoot -ConfigRoot $ConfigRoot).PrimaryPath
        $sib = Join-Path (Split-Path $enginePrimary -Parent) ((Split-Path $enginePrimary -Leaf) + '-vault')
        $ExtraRoot = @(if (Test-Path -LiteralPath (Join-Path $sib '.git') -PathType Container) { $sib })
    }
    foreach ($x in @($ExtraRoot | Where-Object { $_ })) {
        $xc = Get-CommonDir $x
        if (-not $xc -or (ConvertTo-Norm $xc) -eq (ConvertTo-Norm $engineCommon)) { continue }
        $roots += [pscustomobject]@{ Hint = $x; Common = $xc; Role = 'extra'; GhRepo = '' }
    }
}

function Get-GitHubSlug([string]$Repo) {
    $url = git -C $Repo remote get-url origin 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $url) { return '' }
    if ([string]$url -match '^(?:https?://(?:[^/@]*@)?github\.com/|git@github\.com:|ssh://git@github\.com/)(?<o>[^/]+)/(?<r>[^/]+?)(?:\.git)?/*$') {
        return "$($Matches['o'])/$($Matches['r'])"
    }
    return ''
}

# Branch names are case-sensitive in git and on GitHub; a PowerShell hashtable is not.
function New-OrdinalMap { return [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal) }

# ConvertFrom-Json turns an ISO timestamp into a [datetime], and casting that to [string] gives a
# culture-formatted local time with no offset. Normalise both shapes to one DateTimeOffset.
function ConvertTo-Instant($Value) {
    if ($null -eq $Value -or '' -eq $Value) { return $null }
    if ($Value -is [DateTimeOffset]) { return $Value }
    if ($Value -is [datetime]) { return [DateTimeOffset]$Value }
    return [DateTimeOffset]::Parse([string]$Value, [cultureinfo]::InvariantCulture)
}

# Newest sign of git use in a linked worktree's PRIVATE admin dir, read from the filesystem: the .git
# FILE names that dir. No git call, so it cannot move what it measures. The files are the ones
# prune-merged.ps1 reads. The reflog is read by the timestamp in its LAST ENTRY, never by mtime,
# because a `git gc` rewrites every reflog in place (prune-merged.ps1's header has the measurement).
function Get-PrivateGitActivity([string]$Worktree) {
    $dot = Join-Path $Worktree '.git'
    if (-not (Test-Path -LiteralPath $dot -PathType Leaf)) { return $null }
    $txt = ''
    try { $txt = Get-Content -LiteralPath $dot -Raw -ErrorAction Stop } catch { return $null }
    if (-not ($txt -match 'gitdir:\s*(\S.*)')) { return $null }
    $gitdir = $Matches[1].Trim()
    if (-not [System.IO.Path]::IsPathRooted($gitdir)) { $gitdir = Join-Path $Worktree $gitdir }
    $newest = $null
    foreach ($name in @('index', 'HEAD', 'ORIG_HEAD', 'FETCH_HEAD', 'COMMIT_EDITMSG', 'MERGE_MSG')) {
        $f = Join-Path $gitdir $name
        if (Test-Path -LiteralPath $f -PathType Leaf) {
            $t = [DateTimeOffset](Get-Item -LiteralPath $f).LastWriteTimeUtc
            if (-not $newest -or $t -gt $newest) { $newest = $t }
        }
    }
    $reflog = Join-Path $gitdir 'logs/HEAD'
    if (Test-Path -LiteralPath $reflog -PathType Leaf) {
        $last = Get-Content -LiteralPath $reflog -Tail 1 -ErrorAction SilentlyContinue
        # `<old> <new> <name> <<email>> <unix-seconds> <tz>\t<message>`
        if ($last -and ([string]$last -match '>\s+(\d{9,})\s+[+-]\d{4}')) {
            $t = [DateTimeOffset]::FromUnixTimeSeconds([int64]$Matches[1])
            if (-not $newest -or $t -gt $newest) { $newest = $t }
        }
    }
    return $newest
}

function Get-CloneReport($R) {
    # The liveness fence first: it also parses `worktree list` (with HEAD) and names the primary, so
    # this report reads the same worktree set and the same primary as prune-merged.ps1.
    $occ = Get-WorktreeOccupancy -Repo $R.Hint -ConfigRoot $ConfigRoot
    $root = $occ.PrimaryPath
    $rep = [ordered]@{ root = $root; role = $R.Role; commonDir = $R.Common }
    $rep.fence = [ordered]@{
        available = [bool]$occ.Available; detail = $occ.Detail
        rootsExamined = $occ.RootsExamined; recordsExamined = $occ.RecordsExamined
    }

    # --- a. the primary checkout ---------------------------------------------------------------
    $branch = git -C $root rev-parse --abbrev-ref HEAD 2>$null
    $pStatus = @(git -C $root --no-optional-locks status --porcelain --untracked-files=normal 2>$null)
    $pStatusExit = $LASTEXITCODE
    $fetch = [ordered]@{ attempted = $false; ok = $false; detail = '' }
    if ($SkipFetch) { $fetch.detail = 'skipped (-SkipFetch): counts use the refs already on disk' }
    else {
        $fetch.attempted = $true
        git -C $root fetch --quiet --no-auto-maintenance origin $MainBranch 2>$null
        $fetch.ok = ($LASTEXITCODE -eq 0)
        $fetch.detail = if ($fetch.ok) { "fetched origin $MainBranch" } else { "FETCH FAILED (exit $LASTEXITCODE): counts use stale refs" }
    }
    $upstream = "origin/$MainBranch"
    $shallow = ([string](git -C $root rev-parse --is-shallow-repository 2>$null)).Trim() -eq 'true'
    $ahead = $null; $behind = $null; $abDetail = ''
    $haveBase = $true
    if ($shallow) {
        # With the shared history cut off, rev-list counts ALL of one side's local history, which is
        # an overcount rather than a floor. Only count when a merge base is on disk.
        git -C $root merge-base HEAD $upstream 2>$null | Out-Null
        $haveBase = ($LASTEXITCODE -eq 0)
        if (-not $haveBase) { $abDetail = "no merge base with $upstream is visible in this shallow clone, so ahead/behind cannot be counted" }
    }
    if ($haveBase) {
        $ab = git -C $root rev-list --left-right --count "HEAD...$upstream" 2>$null
        if ($LASTEXITCODE -eq 0 -and [string]$ab -match '^\s*(\d+)\s+(\d+)\s*$') {
            $ahead = [int]$Matches[1]; $behind = [int]$Matches[2]
        }
        else { $abDetail = "could not count: $upstream is not resolvable here" }
    }
    $hookSrcBehind = @()
    $hookSrcNote = ''
    if ($null -eq $behind) { $hookSrcNote = "could not tell whether hook sources changed on $upstream since this checkout's HEAD: $abDetail" }
    elseif ($behind -gt 0) {
        # Three dots: what changed on main SINCE the merge base, not what this checkout changed itself.
        $hookSrcBehind = @(git -C $root diff --name-only "HEAD...$upstream" -- scripts/hooks .pre-commit-config.yaml scripts/coord/install-git-hooks.ps1 2>$null)
    }
    $rep.primary = [ordered]@{
        path = $root; branch = ([string]$branch).Trim()
        uncommittedCount = if ($pStatusExit -eq 0) { $pStatus.Count } else { $null }
        uncommittedFiles = @($pStatus)
        fetch = $fetch; shallow = $shallow
        ahead = $ahead; behind = $behind; countIsFloor = $shallow; countDetail = $abDetail
    }

    # --- merge signal: one gh call and one ls-remote per clone ----------------------------------
    $slug = if ($R.GhRepo) { $R.GhRepo } else { Get-GitHubSlug $root }
    $ghInfo = [ordered]@{ available = $false; repo = $slug; detail = ''; mergedCount = 0; windowFull = $false }
    $merged = New-OrdinalMap
    if ($SkipGh) { $ghInfo.detail = 'skipped (-SkipGh): merge status UNKNOWN' }
    elseif (-not $slug) { $ghInfo.detail = 'origin is not a GitHub remote and no -GhRepo was given: merge status UNKNOWN' }
    elseif (-not (Get-Command $Gh -ErrorAction SilentlyContinue)) { $ghInfo.detail = "gh is unavailable ('$Gh' not found): merge status UNKNOWN" }
    else {
        $raw = $null
        # A .ps1 gh that never calls `exit` leaves $LASTEXITCODE at whatever git set last.
        $global:LASTEXITCODE = 0
        try { $raw = & $Gh pr list --repo $slug --state merged --limit $PrLimit --json 'headRefName,headRefOid,number,mergedAt,baseRefName,isCrossRepository' 2>$null }
        catch { $ghInfo.detail = "gh threw: $($_.Exception.Message): merge status UNKNOWN" }
        if (-not $ghInfo.detail) {
            if ($LASTEXITCODE -ne 0) { $ghInfo.detail = "gh exited $($LASTEXITCODE): merge status UNKNOWN" }
            else {
                try {
                    $prs = @(($raw -join "`n") | ConvertFrom-Json)
                    foreach ($pr in $prs) {
                        # A fork's head name can collide with ours, and a PR stacked onto another
                        # branch did not land on main.
                        if ($pr.isCrossRepository -or [string]$pr.baseRefName -cne $MainBranch) { continue }
                        $name = [string]$pr.headRefName
                        if (-not $merged.ContainsKey($name)) { $merged[$name] = [System.Collections.Generic.List[object]]::new() }
                        $merged[$name].Add($pr)
                    }
                    $ghInfo.available = $true
                    $ghInfo.mergedCount = $prs.Count
                    $ghInfo.windowFull = ($prs.Count -ge $PrLimit)
                    $ghInfo.detail = "$($prs.Count) merged PRs read from $slug" + $(if ($ghInfo.windowFull) { " -- the -PrLimit $PrLimit window is FULL, so an older merge reads NOT MERGED" } else { '' })
                }
                catch { $ghInfo.detail = "gh output did not parse as JSON: merge status UNKNOWN" }
            }
        }
    }
    $rep.gh = $ghInfo

    $remote = New-OrdinalMap
    $lsOut = @(git -C $root ls-remote --heads origin 2>$null)
    $lsOk = ($LASTEXITCODE -eq 0)
    foreach ($l in $lsOut) { if ($l -match '^([0-9a-f]+)\s+refs/heads/(.+)$') { $remote[$Matches[2]] = $Matches[1] } }
    $rep.remoteBranches = [ordered]@{ available = $lsOk; count = $remote.Count }

    # --- b. every worktree ---------------------------------------------------------------------
    $primaryNorm = ConvertTo-Norm $root
    $others = @($occ.Worktrees | Where-Object { (ConvertTo-Norm $_.Path) -ne $primaryNorm -and -not $_.Bare })
    $exists = @{}
    foreach ($e in $others) { $exists[(ConvertTo-Norm $e.Path)] = (Test-Path -LiteralPath $e.Path -PathType Container) }

    # Last commit date for every HEAD in ONE call.
    $dates = @{}
    $heads = @($others | Where-Object { $_.Head } | ForEach-Object { $_.Head } | Select-Object -Unique)
    if ($heads.Count -gt 0) {
        $logOut = @($heads | git -C $root log --no-walk=unsorted --ignore-missing --stdin --format='%H %cI' 2>$null)
        foreach ($l in $logOut) { if ($l -match '^([0-9a-f]+) (\S+)$') { $dates[$Matches[1]] = $Matches[2] } }
    }

    # One `git status` per existing worktree, in parallel. The only per-worktree call this makes.
    $status = @{}
    $existing = @($others | Where-Object { $exists[(ConvertTo-Norm $_.Path)] } | ForEach-Object { $_.Path })
    if ($existing.Count -gt 0) {
        $results = $existing | ForEach-Object -ThrottleLimit $Throttle -Parallel {
            $lines = @(git -C $_ --no-optional-locks status --porcelain --untracked-files=normal 2>$null)
            [pscustomobject]@{ Path = $_; Exit = $LASTEXITCODE; Lines = $lines }
        }
        foreach ($res in $results) { $status[(ConvertTo-Norm $res.Path)] = $res }
    }

    $now = [DateTimeOffset]::Now
    $rows = [System.Collections.Generic.List[object]]::new()
    foreach ($e in $others) {
        $norm = ConvertTo-Norm $e.Path
        $isThere = $exists[$norm]
        $st = $status[$norm]
        $lines = if ($st) { @($st.Lines) } else { @() }
        $uncommitted = if ($st -and $st.Exit -eq 0) { $lines.Count } else { $null }
        $hasBranch = $e.Branch -and -not $e.Detached
        $shortHead = $e.Head.Substring(0, [Math]::Min(12, $e.Head.Length))

        $mergeState = 'UNKNOWN'; $mergedPr = $null; $mergedAt = $null; $atTip = $false
        $remoteSha = if ($hasBranch -and $remote.ContainsKey($e.Branch)) { [string]$remote[$e.Branch] } else { $null }
        if (-not $hasBranch) { $mergeState = 'NO BRANCH' }
        elseif ($ghInfo.available) {
            if ($merged.ContainsKey($e.Branch)) {
                $mergeState = 'MERGED'
                $prs = @($merged[$e.Branch] | Sort-Object { ConvertTo-Instant $_.mergedAt } -Descending)
                $tipPrs = @($prs | Where-Object { [string]$_.headRefOid -ceq $e.Head })
                $atTip = ($tipPrs.Count -gt 0)
                $pick = if ($atTip) { $tipPrs[0] } else { $prs[0] }
                $mergedPr = [int]$pick.number
                $mergedAt = ConvertTo-Instant $pick.mergedAt
            }
            else { $mergeState = 'NOT MERGED' }
        }
        $pushed = if ($hasBranch -and $e.Head) { ($atTip -or ($remoteSha -ceq $e.Head)) } else { $null }

        $verdict = 'KEEP'; $reasons = [System.Collections.Generic.List[string]]::new(); $command = ''
        if (-not $isThere) {
            $verdict = 'MISSING'
            $reasons.Add('registered, but the directory is gone')
        }
        elseif ($mergeState -eq 'MERGED') {
            # Single quotes, so a `$` or backtick in a path is not expanded when this is pasted into
            # PowerShell. A single quote inside a path is doubled, which is PowerShell's own escape.
            $plain = "git -C '$($root -replace "'", "''")' worktree remove '$($e.Path -replace "'", "''")'"
            if ($null -eq $uncommitted) { $reasons.Add("git status failed (exit $($st.Exit)), so its work cannot be read") }
            elseif ($uncommitted -gt 0) {
                if ($lines | Where-Object { $_ -notmatch '^\?\? "?\.venv/?"?$' }) { $reasons.Add("$uncommitted uncommitted file(s)") }
                else { $reasons.Add("only an untracked .venv is listed. Removing it needs --force, which also turns off git's refusal of a tree someone has edited since: $plain --force") }
            }
            if (-not $atTip) {
                if ($remoteSha -ceq $e.Head) { $reasons.Add("tip $shortHead is origin/$($e.Branch) but not the head of merged PR $mergedPr, so it carries commits that PR did not land") }
                else { $reasons.Add("tip $shortHead is on no merged PR head and is not origin/$($e.Branch): unpushed, or behind its remote") }
            }
            if ($e.Locked) { $reasons.Add("locked$(if ($e.LockReason) { ": $($e.LockReason)" })") }
            $nested = @(Get-NestedWorktrees -Occupancy $occ -Path $e.Path)
            if ($nested.Count -gt 0) { $reasons.Add("contains $($nested.Count) other registered worktree(s); removing it would take them too") }
            if (-not $occ.Available) { $reasons.Add("the liveness fence could not look: $($occ.Detail)") }
            else {
                $occupants = @(Get-WorktreeOccupants -Occupancy $occ -Path $e.Path -IncludeNested)
                if ($occupants.Count -gt 0) { $reasons.Add("a session is in it: $(($occupants | ForEach-Object { "$($_.Short) $($_.State)" }) -join ', ')") }
                else {
                    # A DEAD record is no veto, but once the directory is gone its cwd names a checkout git
                    # no longer lists. occupancy.ps1 then calls it unplaceable, and the fence stays
                    # unavailable on every later run -- for this clone and, by the name prefix, others.
                    $norm2 = ConvertTo-Norm $e.Path
                    $records = @($occ.Sessions | Where-Object { $w = ConvertTo-Norm $_.WorktreePath; $w -eq $norm2 -or $w.StartsWith("$norm2/") })
                    if ($records.Count -gt 0) { $reasons.Add("a $($records[0].State) session record ($($records[0].Short)) names it; removing the tree would leave that record unplaceable and switch the liveness fence off until the record is gone") }
                }
            }
            if ($mergedAt) {
                $age = ($now - $mergedAt).TotalHours
                if ($age -lt $HoldHours) { $reasons.Add(("merged {0:N1} h ago, inside the {1} h hold: its session may still be there" -f $age, $HoldHours)) }
            }
            if ($IdleHours -gt 0) {
                $touched = @(Get-PrivateGitActivity $e.Path)
                if ($e.Head -and $dates.ContainsKey($e.Head)) { $touched += ConvertTo-Instant $dates[$e.Head] }
                $newest = $touched | Where-Object { $_ } | Sort-Object -Descending | Select-Object -First 1
                if ($newest) {
                    $idle = ($now - $newest).TotalHours
                    if ($idle -lt $IdleHours) { $reasons.Add(("git activity {0:N1} h ago, inside the {1} h idle window: a session may still be working there" -f $idle, $IdleHours)) }
                }
            }
            if ($reasons.Count -gt 0) { $verdict = 'HUMAN' }
            else { $verdict = 'REMOVE'; $command = $plain }
        }
        elseif ($mergeState -eq 'UNKNOWN') { $verdict = 'UNKNOWN' }

        $rows.Add([ordered]@{
                path = $e.Path; branch = if ($hasBranch) { $e.Branch } else { '' }; detached = [bool]$e.Detached
                exists = $isThere; prunable = [bool]$e.Prunable; locked = $e.Locked
                lastCommit = if ($e.Head -and $dates.ContainsKey($e.Head)) { $dates[$e.Head] } else { $null }
                uncommitted = $uncommitted
                uncommittedSample = @(if ($verdict -eq 'HUMAN') { $lines | Select-Object -First 20 })
                merge = $mergeState; mergedPr = $mergedPr; mergedAt = if ($mergedAt) { $mergedAt.ToString('o') } else { $null }
                pushed = $pushed; remoteBranchExists = [bool]$remoteSha
                verdict = $verdict; reasons = @($reasons); command = $command
            })
    }
    $rep.worktrees = @($rows)
    $rep.cleanup = [ordered]@{
        remove = @($rows | Where-Object { $_.verdict -eq 'REMOVE' })
        human  = @($rows | Where-Object { $_.verdict -eq 'HUMAN' })
        missing = @($rows | Where-Object { $_.verdict -eq 'MISSING' })
    }
    $reconcile = Join-Path $root 'scripts/coord/claim-reconcile.ps1'
    $rep.claimReconcile = if (Test-Path -LiteralPath $reconcile -PathType Leaf) { "pwsh -NoProfile -File `"$reconcile`"" } else { '' }

    # --- c. hook drift, read by the clone's own installer --------------------------------------
    $installer = Join-Path $root 'scripts/coord/install-git-hooks.ps1'
    $hooks = [ordered]@{ installer = $installer; ran = $false; exitCode = $null; flagged = @(); output = @(); hookSourcesBehindMain = @($hookSrcBehind); hookSourcesNote = $hookSrcNote; rearm = '' }
    if (Test-Path -LiteralPath $installer -PathType Leaf) {
        # -Status is the read-only mode. The engine installer's bare invocation INSTALLS, so -Status
        # is never optional here.
        $out = @(& (Get-Process -Id $PID).Path -NoProfile -NonInteractive -File $installer -Status 2>&1 | ForEach-Object { [string]$_ })
        $hooks.ran = $true
        $hooks.exitCode = $LASTEXITCODE
        $hooks.output = $out
        # A keyword pick of the installer's own capitalised warnings. Case-SENSITIVE, so ordinary
        # lower-case prose ("not installed in this .venv") is not read as drift. It can miss a warning
        # worded some new way, which is why the full output is always kept beside it.
        # The one lower-case form kept is a hook's own status line (`commit-msg : not installed`).
        $hooks.flagged = @($out | Where-Object { $_ -cmatch 'STALE|NOT INSTALLED|NOT ARMED|DOES NOT EXIST|DISAGREE|UNRESOLVABLE|NOTHING DECLARED|NOT the primary|NOT ours|POINTED AT THE PUBLIC|LINTS DIFFERENTLY|FAILS OPEN|LEGACY|NOT the ledger gate|^\s*(commit-msg|pre-commit|pre-push|post-commit|post-merge)\s*:\s*not installed' })
        # The two clones' installers differ: the vault's bare invocation is a dry run and needs -Arm.
        $arm = if (Select-String -LiteralPath $installer -Pattern '\[switch\]\s*\$Arm\b' -Quiet) { ' -Arm' } else { '' }
        $hooks.rearm = "pwsh -NoProfile -File `"$installer`"$arm"
    }
    $rep.hooks = $hooks
    return $rep
}

$generated = Get-Date
$report = [ordered]@{
    tool = 'scripts/worktree/hygiene-report.ps1'
    generatedAt = $generated.ToString('o')
    readOnly = 'This report ran no destructive command. Every command in it is for the owner to run.'
    holdHours = $HoldHours
    idleHours = $IdleHours
    clones = @(foreach ($r in $roots) { Get-CloneReport $r })
}

# --- render --------------------------------------------------------------------------------------
function Format-Count($n) { if ($null -eq $n) { 'unknown' } else { [string]$n } }

$md = [System.Collections.Generic.List[string]]::new()
$md.Add("# Worktree hygiene report")
$md.Add("")
$md.Add("**Generated $($report.generatedAt)** by ``$($report.tool)``. Every reading below is as of that time, so it says nothing about a merge that landed later.")
$md.Add("")
$md.Add("This report is read-only: it deleted nothing, and it runs none of the commands below.")
foreach ($c in $report.clones) {
    $p = $c.primary
    $md.Add("")
    $md.Add("## $($c.role) clone: ``$($c.root)``")
    $md.Add("")
    $md.Add("### a. Primary checkout")
    $md.Add("")
    $md.Add("- Branch: ``$($p.branch)``")
    $md.Add("- Uncommitted files: $(Format-Count $p.uncommittedCount)")
    foreach ($f in $p.uncommittedFiles) { $md.Add("  - ``$f``") }
    $md.Add("- Fetch: $($p.fetch.detail)")
    if ($null -eq $p.ahead) { $md.Add("- Ahead/behind origin/${MainBranch}: $($p.countDetail)") }
    elseif ($p.countIsFloor) { $md.Add("- Ahead/behind origin/${MainBranch}: at least $($p.ahead) ahead, at least $($p.behind) behind. This clone is SHALLOW, so both counts are a floor, not a distance.") }
    else { $md.Add("- Ahead/behind origin/${MainBranch}: $($p.ahead) ahead, $($p.behind) behind.") }

    $md.Add("")
    $md.Add("### b. Worktrees ($($c.worktrees.Count), primary excluded)")
    $md.Add("")
    $md.Add("- Merge signal: $($c.gh.detail)")
    $md.Add("- Remote branches: $(if ($c.remoteBranches.available) { "$($c.remoteBranches.count) read from origin" } else { 'ls-remote FAILED, so pushed status rests on merged PR heads alone' })")
    $md.Add("- Liveness fence: $(if ($c.fence.available) { "available ($($c.fence.recordsExamined) records in $($c.fence.rootsExamined) config roots)" } else { "UNAVAILABLE -- $($c.fence.detail). Nothing is proposed for removal while it cannot look." })")
    $md.Add("")
    $md.Add("| Path | Branch | Exists | Last commit | Uncommitted | Merge | Pushed | Verdict |")
    $md.Add("| --- | --- | --- | --- | --- | --- | --- | --- |")
    foreach ($w in ($c.worktrees | Sort-Object { $_.verdict }, { $_.path })) {
        $br = if ($w.detached) { '(detached)' } else { $w.branch }
        $mg = if ($w.mergedPr) { "$($w.merge) PR $($w.mergedPr)" } else { $w.merge }
        $md.Add("| ``$($w.path)`` | ``$br`` | $(if ($w.exists) { 'yes' } else { 'NO' }) | $(if ($w.lastCommit) { $w.lastCommit } else { 'unknown' }) | $(Format-Count $w.uncommitted) | $mg | $(if ($null -eq $w.pushed) { 'unknown' } elseif ($w.pushed) { 'yes' } else { 'NO' }) | $($w.verdict) |")
    }

    $h = $c.hooks
    $md.Add("")
    $md.Add("### c. Installed-hook drift")
    $md.Add("")
    if (-not $h.ran) { $md.Add("No installer at ``$($h.installer)``, so hook drift was not measured for this clone.") }
    else {
        $md.Add("Read by ``$($h.installer) -Status`` (exit $($h.exitCode)). It compares the installed hooks with THIS checkout's working tree, not with origin/$MainBranch.")
        $md.Add("")
        if ($h.flagged.Count -gt 0) {
            $md.Add("**$($h.flagged.Count) line(s) flag drift or a gap:**")
            $md.Add("")
            foreach ($l in $h.flagged) { $md.Add("- ``$($l.Trim())``") }
        }
        else { $md.Add("No line matched the drift keywords. That is a keyword pick, so read the full output before concluding the hooks are current.") }
        $md.Add("")
        $md.Add("<details><summary>Full -Status output</summary>")
        $md.Add("")
        $md.Add('```')
        foreach ($l in $h.output) { $md.Add($l) }
        $md.Add('```')
        $md.Add("")
        $md.Add("</details>")
    }
    if ($h.hookSourcesNote) {
        $md.Add("")
        $md.Add("**Hook sources against origin/${MainBranch}:** $($h.hookSourcesNote)")
    }
    if ($h.hookSourcesBehindMain.Count -gt 0) {
        $md.Add("")
        $md.Add("**Hook sources changed on origin/$MainBranch since this checkout's merge base**, so the -Status comparison above is against a stale source:")
        $md.Add("")
        foreach ($f in $h.hookSourcesBehindMain) { $md.Add("- ``$f``") }
    }
    if ($h.rearm) {
        $md.Add("")
        $md.Add("Re-arm from a PLAIN terminal, after this checkout is at origin/$MainBranch. Arming from an older checkout downgrades the hooks for every worktree of this clone.")
        $md.Add("")
        $md.Add('```powershell')
        $md.Add($h.rearm)
        $md.Add('```')
    }

    $md.Add("")
    $md.Add("### d. Proposed cleanup (for the owner to approve; nothing here has run)")
    $md.Add("")
    if ($c.cleanup.remove.Count -eq 0) { $md.Add("No worktree passes every check, so nothing is proposed.") }
    else {
        $md.Add("Each of these sits at the exact head of a merged PR, older than $HoldHours h. None has files ``git status`` lists, a lock, a nested worktree, or a session record the fence can see.")
        $md.Add($(if ($IdleHours -gt 0) { "None shows git activity in the last $IdleHours h." } else { "**The activity window is OFF (-IdleHours 0), so recent git activity was not checked.**" }))
        $md.Add("``git worktree remove`` also deletes gitignored files: a ``.venv`` and caches, but also any local ``.env`` or store file. Run them from a plain terminal:")
        $md.Add("")
        $md.Add('```powershell')
        foreach ($w in $c.cleanup.remove) { $md.Add($w.command) }
        $md.Add('```')
        if ($c.claimReconcile) {
            $md.Add("")
            $md.Add("Afterwards, release the claims those worktrees held. Run it without -Apply first; see docs/WORKTREES.md:")
            $md.Add("")
            $md.Add('```powershell')
            $md.Add($c.claimReconcile)
            $md.Add('```')
        }
    }
    $md.Add("")
    $md.Add("#### NEEDS A HUMAN LOOK ($($c.cleanup.human.Count))")
    $md.Add("")
    if ($c.cleanup.human.Count -eq 0) { $md.Add("None.") }
    foreach ($w in $c.cleanup.human) {
        $md.Add("- ``$($w.path)`` (``$($w.branch)``, $($w.merge) PR $($w.mergedPr)): $($w.reasons -join '; ')")
        foreach ($f in $w.uncommittedSample) { $md.Add("  - ``$f``") }
    }
    if ($c.cleanup.missing.Count -gt 0) {
        $md.Add("")
        $md.Add("#### Registered, directory missing ($($c.cleanup.missing.Count))")
        $md.Add("")
        $md.Add("``git worktree prune`` would deregister these, and also any OTHER worktree whose directory is briefly missing at that moment. Decide per entry.")
        $md.Add("")
        foreach ($w in $c.cleanup.missing) { $md.Add("- ``$($w.path)`` (``$($w.branch)``)") }
    }
}

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$stamp = $generated.ToString('yyyy-MM-dd')
$mdText = ($md -join "`n") + "`n"
$jsonText = $report | ConvertTo-Json -Depth 8 -Compress
$files = @(
    @{ Path = (Join-Path $OutDir "hygiene-$stamp.md"); Text = $mdText }
    @{ Path = (Join-Path $OutDir "hygiene-$stamp.json"); Text = $jsonText }
    @{ Path = (Join-Path $OutDir 'latest.md'); Text = $mdText }
    @{ Path = (Join-Path $OutDir 'latest.json'); Text = $jsonText }
)
foreach ($f in $files) { Set-Content -LiteralPath $f.Path -Value $f.Text -Encoding utf8NoBOM -NoNewline }
Set-Content -LiteralPath $lastRun -Encoding utf8NoBOM -Value "OK $($report.generatedAt)"

foreach ($c in $report.clones) {
    Write-Output ("{0}: {1} worktrees, {2} proposed for removal, {3} need a human look, {4} hook line(s) flagged" -f `
            $c.root, $c.worktrees.Count, $c.cleanup.remove.Count, $c.cleanup.human.Count, $c.hooks.flagged.Count)
}
Write-Output "Report written: $(Join-Path $OutDir "hygiene-$stamp.md")"
Write-Output "           and: $(Join-Path $OutDir "hygiene-$stamp.json")"
Write-Output "        latest: $(Join-Path $OutDir 'latest.md')"
exit 0
