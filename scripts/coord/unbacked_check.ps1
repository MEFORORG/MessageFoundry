# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Report commits that exist on NO remote -- the "correct but unpublished" gap that nothing else
    measures.

.DESCRIPTION
    Uncommitted work has `git status`. Unmerged work has the pull request list. COMMITTED-BUT-UNPUSHED
    work has neither: it looks finished from inside the worktree holding it and is invisible from
    everywhere else, and git never raises a signal about it -- git conflicts on concurrent edits,
    never on a correct-but-unpublished divergence. This script is that missing instrument.

    MEASURE PER REF, NEVER PER HEAD. This is the whole reason the script exists in this shape, and it
    is written down because the mistake was made here, not imagined:

        git rev-list --count HEAD --not --remotes       # per worktree, over checked-out tips

    returned 0 for every repository and worktree on this machine on 2026-08-16, and was reported as
    "nothing single-copy anywhere". Re-measured per REF, the same machine held 802 unbacked commits
    across 239 branches -- 227 of them in this repository alone. The first command answers "does any
    CHECKED-OUT TIP have unbacked commits". It was read as "is any work unbacked". A branch that no
    worktree currently has checked out is invisible to it, and that is the normal state of most
    branches. See CLAUDE.md section 11, SDS-3.8: confirm your instrument answers the question you
    asked, not one adjacent to it.

    COVERAGE IS A FIRST-CLASS OUTPUT, not a nicety. This script always prints how many refs across how
    many repositories it examined, including when it finds nothing. A check that emits "no unbacked
    work" without "over 547 refs in 4 repositories" is worse than no check, because it manufactures
    confidence -- a run that examined zero refs and a run that examined everything print the same
    reassuring line. The acceptance criterion is stated in
    .git/mefor-coord/handoffs/2026-08-15-DISPATCHER-claims-do-not-replicate.md.

    A REPOSITORY WITH NO REMOTE IS THE MAXIMUM CASE, NOT A SKIP. `--not --remotes` against a repo with
    zero remotes excludes nothing, so every commit counts as unbacked -- which is correct, and is
    exactly the state that had a 46-commit project existing on one disk until it was given a remote.
    Such repos are reported as NO-REMOTE rather than folded into a count, because the remedy differs:
    the others need a push, this one needs a remote to push to.

    CONFIGURED IS NOT REACHABLE, AND THE DIFFERENCE IS A FALSE NEGATIVE. `--not --remotes` excludes
    everything reachable from `refs/remotes/*`, and those are LOCAL COPIES of what a server once
    advertised. If the server is gone, they still exclude -- so the check reports a repository as
    fully backed up when its backing store does not answer. Measured while writing this script: a
    repository whose origin is a Gitea on localhost that no longer runs reported
    "0 unbacked commits" across 7 refs. Every one of those commits exists on exactly one disk.

    So reachability is probed by default, once per remote, and reported as a SEPARATE AXIS rather
    than folded into the commit count. A repository with remotes configured and none reachable is
    reported as UNVERIFIABLE, not as clean: the honest statement is "this check cannot tell", and a
    check that cannot tell must not print the word that means it can. Use -SkipReachability to
    suppress the probe; the output then says reachability was not checked.

    WHAT THIS DOES NOT MEASURE. Uncommitted and untracked work (use `git status`), and whether a
    remote-tracking ref is up to date with what the server has now (run `git fetch --prune` first if
    that matters). Reachability from ANY remote-tracking ref counts as backed, including a rescue
    tag -- durable is not the same as landed, and this measures durability only.

.PARAMETER Path
    One or more repository roots. Defaults to the repository containing this script.

.PARAMETER Json
    Emit a machine-readable object instead of text, for a board or dashboard to consume.

.PARAMETER Quiet
    Suppress per-ref detail; print only the coverage line and the totals.

.PARAMETER SkipReachability
    Do not contact any remote. Faster, and STRICTLY WEAKER -- see the note below on why reachability
    is checked by default. When set, the output says so rather than quietly meaning something else.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\unbacked_check.ps1

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\unbacked_check.ps1 -Path C:\a\repo,C:\another\repo -Json

.OUTPUTS
    Exit code 0 when every ref is backed by at least one remote-tracking ref; 1 when any is not.
    Exit code 2 means the check could not run and therefore reports nothing -- never success.
#>
[CmdletBinding()]
param(
    [string[]]$Path,
    [switch]$Json,
    [switch]$Quiet,
    [switch]$SkipReachability
)

$ErrorActionPreference = "Stop"

if (-not $Path -or $Path.Count -eq 0) {
    $root = (& git -C $PSScriptRoot rev-parse --show-toplevel 2>$null)
    if (-not $root) { Write-Error "Not inside a git repository, and no -Path given."; exit 2 }
    $Path = @($root)
}

# `pwsh -File script.ps1 -Path a,b,c` hands the whole comma list over as ONE string -- -File does not
# parse arrays the way -Command does. Splitting here means the documented invocation works either way
# rather than failing with "Path does not exist: 'a','b','c'", which is what it did.
$Path = @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().Trim("'").Trim('"') } | Where-Object { $_ })

$repos = @()
$totalRefs = 0
$totalUnbacked = 0
$totalCommits = 0

foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) {
        Write-Error "Path does not exist: $p"
        exit 2
    }
    $inside = (& git -C $p rev-parse --is-inside-work-tree 2>$null)
    if ($inside -ne "true") {
        Write-Error "Not a git repository: $p"
        exit 2
    }

    $remotes = @(& git -C $p remote 2>$null)

    # Probe each remote ONCE. `ls-remote --exit-code` contacts the server and changes nothing locally,
    # which is what makes it safe to run from an audit. This is the axis that distinguishes "backed
    # up" from "excluded by a local copy of a store that no longer answers".
    $reachable = @()
    $unreachable = @()
    if (-not $SkipReachability) {
        foreach ($rem in $remotes) {
            & git -C $p ls-remote --exit-code --quiet $rem HEAD 2>$null | Out-Null
            if ($LASTEXITCODE -eq 0) { $reachable += $rem } else { $unreachable += $rem }
        }
    }

    $refs = @(& git -C $p for-each-ref --format='%(refname)' refs/heads 2>$null)
    $findings = @()

    foreach ($ref in $refs) {
        # --not --remotes excludes everything reachable from any remote-tracking ref. With no remotes
        # configured it excludes nothing, so the count is the branch's entire history -- correct, and
        # the reason the NO-REMOTE case is reported separately below rather than silently inflating a
        # total that would then read as ordinary unpushed work.
        $n = (& git -C $p rev-list --count $ref --not --remotes 2>$null)
        if ($n -and [int]$n -gt 0) {
            $findings += [pscustomobject]@{
                Ref     = ($ref -replace '^refs/heads/', '')
                Commits = [int]$n
            }
        }
    }

    $sum = ($findings | Measure-Object -Property Commits -Sum).Sum
    if (-not $sum) { $sum = 0 }

    $repos += [pscustomobject]@{
        Repo                = $p
        HasRemote           = ($remotes.Count -gt 0)
        RemotesConfigured   = $remotes.Count
        RemotesReachable    = $reachable.Count
        RemotesUnreachable  = $unreachable
        ReachabilityChecked = (-not $SkipReachability)
        # UNVERIFIABLE: remotes exist, none answered. Every "backed" verdict in this repo then rests
        # on local copies of a store that is not there, so the commit count below understates by an
        # unknown amount and must not be read as clean.
        Unverifiable        = (($remotes.Count -gt 0) -and (-not $SkipReachability) -and ($reachable.Count -eq 0))
        RefsScanned         = $refs.Count
        Unbacked            = $findings.Count
        Commits             = $sum
        Findings            = $findings
    }
    $totalRefs += $refs.Count
    $totalUnbacked += $findings.Count
    $totalCommits += $sum
}

if ($Json) {
    $unverifiableCount = @($repos | Where-Object { $_.Unverifiable }).Count
    [pscustomobject]@{
        RepositoriesScanned  = $repos.Count
        RefsScanned          = $totalRefs
        BranchesUnbacked     = $totalUnbacked
        CommitsUnbacked      = $totalCommits
        RepositoriesUnverifiable = $unverifiableCount
        ReachabilityChecked  = (-not $SkipReachability)
        Repositories         = $repos
    } | ConvertTo-Json -Depth 6
    # Unverifiable must fail too. A consumer that keys only on CommitsUnbacked would read a dead
    # remote as a clean result, which is the defect this axis exists to expose.
    exit ([int](($totalUnbacked -gt 0) -or ($unverifiableCount -gt 0)))
}

$unverifiableRepos = @($repos | Where-Object { $_.Unverifiable })

foreach ($r in $repos) {
    if (-not $r.HasRemote) {
        Write-Host "NO-REMOTE     $($r.Repo)" -ForegroundColor Red
        Write-Host "              $($r.Commits) commits across $($r.RefsScanned) refs exist on this disk only." -ForegroundColor Red
        Write-Host "              This repository has no remote at all, so nothing here is a push away from" -ForegroundColor Red
        Write-Host "              safety -- it needs a remote first. A bundle is interim cover, not a remote." -ForegroundColor Red
        continue
    }
    if ($r.Unverifiable) {
        Write-Host "UNVERIFIABLE  $($r.Repo)" -ForegroundColor Red
        Write-Host "              $($r.RemotesConfigured) remote(s) configured, NONE reachable: $($r.RemotesUnreachable -join ', ')" -ForegroundColor Red
        Write-Host "              This check reports $($r.Commits) unbacked across $($r.RefsScanned) refs, and that number" -ForegroundColor Red
        Write-Host "              is a FLOOR, not an answer. Everything it counted as backed was excluded by" -ForegroundColor Red
        Write-Host "              refs/remotes/* -- local copies of a store that did not answer. Restore the" -ForegroundColor Red
        Write-Host "              remote, re-point it, or bundle the repository and treat it as unbacked." -ForegroundColor Red
        continue
    }
    if ($r.Unbacked -eq 0) { continue }
    Write-Host "UNBACKED      $($r.Repo)" -ForegroundColor Yellow
    if (-not $Quiet) {
        foreach ($f in ($r.Findings | Sort-Object Commits -Descending)) {
            Write-Host ("              {0,-55} {1}" -f $f.Ref, $f.Commits)
        }
    }
}

# COVERAGE FIRST, ALWAYS, INCLUDING ON A CLEAN RUN. See the DESCRIPTION: a bare "clean" cannot be
# distinguished from a run that examined nothing.
Write-Host ""
Write-Host "coverage : $totalRefs refs across $($repos.Count) repositor$(if ($repos.Count -eq 1) { 'y' } else { 'ies' })"
if ($SkipReachability) {
    Write-Host "           reachability NOT checked (-SkipReachability) -- a dead remote reads as backed" -ForegroundColor Yellow
} else {
    $reach = ($repos | Measure-Object -Property RemotesReachable -Sum).Sum
    $conf = ($repos | Measure-Object -Property RemotesConfigured -Sum).Sum
    Write-Host "           $reach of $conf configured remote(s) answered"
}
if ($unverifiableRepos.Count -gt 0) {
    Write-Host "result   : UNVERIFIABLE in $($unverifiableRepos.Count) repositor$(if ($unverifiableRepos.Count -eq 1) { 'y' } else { 'ies' }) -- see above. Not reporting clean." -ForegroundColor Red
    exit 1
}
if ($totalUnbacked -eq 0) {
    Write-Host "result   : 0 unbacked commits" -ForegroundColor Green
    exit 0
}
Write-Host "result   : $totalCommits commits on $totalUnbacked branches exist on no remote" -ForegroundColor Yellow
Write-Host ""
Write-Host "Remedy, which buys durability without publication or review:"
Write-Host "  git config mefor.durabilityRemote <private-remote>   # once, per repository"
Write-Host "  git push --force <private-remote> <branch>:refs/tags/rescue/branch/<branch>"
Write-Host "Verify the remote is private BEFORE nominating it:  gh repo view <owner>/<repo> --json visibility"
exit 1
