# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
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

    A BRANCH SCAN CANNOT SEE A DETACHED HEAD, AND THAT IS THE THIRD FALSE NEGATIVE THIS SCRIPT HAS
    SHIPPED. Scanning `refs/heads` answers "does any BRANCH carry unbacked commits". A worktree with a
    detached HEAD is on no branch, so it is structurally invisible to that scan -- and detached is not
    an edge case here: measured 2026-08-16, 23 of one repository's 44 registered worktrees were
    detached, and 11 of them carried 30 commits that existed on no remote while this script reported
    zero. So every worktree HEAD is checked as well, and a detached one is reported against its
    PATH, because it has no branch name to report against.

    The pattern across all three defects is the same and worth stating once: each earlier version
    answered a question adjacent to the one a reader would ask. Per HEAD instead of per ref; per
    local ref instead of per reachable remote; per branch instead of per checkout. The fix each time
    was to widen what "everything" means, which is why the coverage line now counts refs AND
    worktrees rather than a single number that hides which of the two it meant.

    THE WORKTREE COUNT INCLUDES THE PRIMARY CHECKOUT, because `git worktree list` registers it as
    one. Stated because it is a silent off-by-one in exactly the reconciliation this script invites:
    two people counting "how many worktrees" will differ by one and each will believe the other has
    found something. Checking it is correct -- the primary can carry unbacked commits like any other
    checkout -- so the fix is to say so, not to subtract it.

    WHY THIS CHECK AND NOT A CLAIM SWEEP. This project also has a coordination registry that records
    which checkout holds which work, and it is tempting to reconcile from there instead. It does not
    cover this: measured 2026-08-16, a worktree created by `scripts/worktree/new.ps1` carried a
    committed-but-unpushed commit and NO claim named it, because that script does not take one. A
    claim-based sweep is therefore blind to precisely the worktree most worth finding -- one holding
    work nobody has registered. This check reads git, not the registry, and is unaffected.

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

    The same holds for ONE dead remote among live ones, and for tracking refs left behind by a remote
    no longer configured. The repository is then not UNVERIFIABLE, so only the remotes that answered
    may exclude a commit; a branch held by the dead remote alone is counted as unbacked, and the
    remotes that did not answer are named (BACKLOG #5502).

    A RELATED PRACTICE, because this check is how the need surfaces. Prose that CITES a commit which
    will deliberately never land -- a trial branch, a refuted experiment, a rejected approach -- makes
    a merged file depend on a sha this check would otherwise be the only thing protecting. Measured
    2026-08-16: `.github/workflows/ci.yml` line 994 on origin/main cites a worker-count trial "at
    2bb733915", that branch was deliberately deleted from the public remote, and `git ls-remote
    origin` returns zero matches for the sha. Three refs hold it -- one local branch and two rescue
    refs. A single `git branch -D` would leave a merged citation resolving to nothing.

    So when citing work that will not land, name a REF-INDEPENDENT identifier beside the sha -- a CI
    run id, a PR number, an artefact url -- something whose retention does not depend on a git ref.
    The citation then degrades gracefully: lose the sha and the evidence is still reachable. The sha
    is precisely the half this tool exists to rescue, which is why it is the wrong half to rely on
    alone.

    UNCOMMITTED WORK IS REPORTED, NOT COUNTED, AND THE DISTINCTION IS THE POINT. Nothing here can
    make an uncommitted change durable -- a post-commit hook needs a commit, and this check measures
    commits. But printing "0 unbacked commits" while a checkout holds unpushed EDITS is the same
    manufactured confidence this script exists to prevent: measured 2026-08-16, the primary checkout
    carried 43 uncommitted insertions in `scripts/coord/mail.ps1` while every commit-based
    instrument on the machine read clean. It was found by a person reading `git status`, not by any
    of them.

    So dirty checkouts are surfaced on their own line and deliberately do NOT change the exit code:
    uncommitted work is a normal state of a working tree, and failing on it would train an operator
    to ignore the result. The severity difference is real -- an unbacked commit is recoverable from
    the reflog, an uncommitted edit is not recoverable from anything -- which is the argument for
    showing it, not for treating it as an error.

    WHAT THIS DOES NOT MEASURE. Whether an uncommitted change is worth keeping, and whether a
    remote-tracking ref still names the commit the server has now: a branch the server rewound is
    trusted at its old tip (run `git fetch --prune` first if that matters). Reachability from a
    TRUSTED remote's tracking refs counts as backed, including a rescue tag fetched there -- durable
    is not the same as landed, and this measures durability only. A remote is trusted when it
    answered the probe with at least one branch or tag, and of its tracking refs only those its
    fetch refspecs map back to a branch or tag it advertised (a tracking ref whose branch was deleted
    there backs nothing), plus, unchecked, those a refspec maps to a source outside refs/heads/ and
    refs/tags/, which the probe does not list. With -SkipReachability, or when none answered
    (UNVERIFIABLE), every non-symref remote-tracking ref that peels to a commit present here still
    excludes (one whose object is missing backs nothing); in the UNVERIFIABLE case no patch-id match is read
    from them, so a squash-landed branch counts in that floor.

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
    Exit code 0 when every ref is backed by at least one trusted remote-tracking ref; 1 when any is not.
    Exit code 2 means the check could not run, or could not run completely -- never success. That
    includes a git listing or rev-list that failed partway (reported as UNVERIFIABLE). Such a run
    still lists the unbacked items it did measure, in text and in the JSON, except that whenever a
    listing the exclusion set is built from failed (the remotes, a trusted remote's refspecs or
    tracking refs, the remote-tracking refs, or the object check on them), the text prints "a git
    listing failed for <labels>; per-branch counts are not shown" instead of the per-branch list.
    The JSON lists the items either way.
#>
#Requires -Version 7
[CmdletBinding()]
param(
    [string[]]$Path,
    [switch]$Json,
    [switch]$Quiet,
    [switch]$SkipReachability
)

$ErrorActionPreference = "Stop"

# Invoke-Git starts this exact file. Resolved once through PowerShell command discovery, which never
# runs a binary from the current directory; a bare 'git' handed to ProcessStartInfo would let Windows
# search pwsh's own folder and the current directory before PATH.
$gitExe = @(Get-Command git -CommandType Application -ErrorAction SilentlyContinue)[0].Source
# Could-not-run messages go to stderr directly: Write-Error under Stop would end the script with
# exit 1, "unbacked found", before the exit 2 that means "could not run" (see .OUTPUTS).
if (-not $gitExe) { [Console]::Error.WriteLine("git is not on PATH."); exit 2 }

if (-not $Path -or $Path.Count -eq 0) {
    $root = (& $gitExe -C $PSScriptRoot rev-parse --show-toplevel 2>$null)
    if (-not $root) { [Console]::Error.WriteLine("Not inside a git repository, and no -Path given."); exit 2 }
    $Path = @($root)
}

# `pwsh -File script.ps1 -Path a,b,c` hands the whole comma list over as ONE string -- -File does not
# parse arrays the way -Command does. Splitting here means the documented invocation works either way
# rather than failing with "Path does not exist: 'a','b','c'", which is what it did.
$Path = @($Path | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().Trim("'").Trim('"') } | Where-Object { $_ })

# CONTENT-DURABILITY CLASSIFICATION (BACKLOG #1299).
#
# `--not --remotes` answers "does this COMMIT OBJECT exist on a remote". A reader runs this script to
# ask "is any WORK at risk of being lost". Those two questions diverge on two ROUTINE mechanisms, and
# measured 2026-08-23 on this machine EVERY alarm was a divergence: 8 of 8 unbacked commits were
# content-durable. The remedy the script printed would have force-pushed rescue tags for work already
# on `main`.
#
#   (1) SQUASH-MERGE orphans the original. `main` gets a NEW sha, so a branch still pointing at the
#       pre-squash commit references an object on no remote while its content is fully landed. Every
#       merged PR left behind by `gh pr checkout` is in this class.
#   (2) A LOCAL `merge <remote> into <branch>` creates a merge commit that is itself new, while both
#       its parents are already backed and it contributes no content of its own.
#
# WHY THE PARENT TEST ALONE IS NOT SOUND, and this is the half a naive fix gets wrong: a merge whose
# parents are both backed CAN still carry content that exists nowhere else -- a hand-resolved conflict
# lives in neither parent. So arm (2) additionally requires the commit's tree to equal the tree an
# AUTOMATIC merge of those parents produces. Identical means the merge is re-derivable and nothing is
# lost with it; different means somebody resolved something by hand and that resolution IS the work.
# Measured on the 6 merge commits live here: all 6 identical, so all 6 are genuinely re-derivable.
#
# The classification only ever moves a commit from AT-RISK to DURABLE. A commit that fails both arms
# is reported exactly as before, so this cannot mask the case the script exists for.
#
# At least these git calls go through here: the remote and ref listings, symbolic-ref, cat-file,
# merge-base, cherry, the worktree listing, and every rev-list that asks "what is unbacked". Others
# use `& $gitExe`, the same file. It
# starts git directly rather than through a PowerShell pipeline, for three measured reasons:
#   - stdin is written as ONE pre-joined string. Piping a few thousand lines object by object cost
#     710 ms a call on a synthetic 3000-ref repository, against 222 ms for the old `--not --remotes`
#     glob and 45 ms for this.
#   - output is decoded as UTF-8. PowerShell decodes native output with the console code page, so a
#     non-ASCII branch name came back garbled and every rev-list fed that name failed.
#   - the exit code travels with the output. Ok is false when git failed, and a caller must never
#     read a failed run's empty output as "nothing unbacked" (BACKLOG #5502).
function Invoke-Git {
    param([string]$Repo, [string[]]$GitArgs, [string]$StdinText)
    $psi = [System.Diagnostics.ProcessStartInfo]::new($gitExe)
    $psi.ArgumentList.Add('-C')
    $psi.ArgumentList.Add($Repo)
    foreach ($a in $GitArgs) { $psi.ArgumentList.Add($a) }
    $psi.UseShellExecute = $false
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
    $proc = [System.Diagnostics.Process]::Start($psi)
    $outTask = $proc.StandardOutput.ReadToEndAsync()
    $null = $proc.StandardError.ReadToEndAsync()
    # git can exit before reading its stdin -- a repository or worktree removed mid-run -- and the
    # write then fails on a closed pipe. That is this call failing, never the whole run crashing.
    $writeFailed = $false
    try {
        if ($StdinText) { $proc.StandardInput.Write($StdinText) }
        $proc.StandardInput.Close()
    } catch [System.IO.IOException] {
        $writeFailed = $true
    }
    $proc.WaitForExit()
    $lines = @($outTask.Result -split "`r?`n" | Where-Object { $_ })
    return [pscustomobject]@{ Ok = ((-not $writeFailed) -and $proc.ExitCode -eq 0); Lines = $lines; ExitCode = $(if ($writeFailed) { -1 } else { $proc.ExitCode }) }
}

# The full refnames a remote's fetch refspecs map $Name back to, or none. Negative refspecs and ones
# with no destination map nothing. A refspec carries at most one '*' on each side.
function Get-RefspecSource {
    param([string]$Name, [string[]]$Refspecs)
    foreach ($spec in $Refspecs) {
        $s = $spec.TrimStart('+')
        if ($s.StartsWith('^') -or -not $s.Contains(':')) { continue }
        $src, $dst = $s -split ':', 2
        $star = $dst.IndexOf('*')
        if ($star -lt 0) {
            # A short source names a branch or a tag, as git resolves it.
            if ($dst -ceq $Name -and -not $src.Contains('*')) {
                if ($src.StartsWith('refs/', [StringComparison]::Ordinal)) { $src } else { "refs/heads/$src"; "refs/tags/$src" }
            }
            continue
        }
        $pre = $dst.Substring(0, $star)
        $post = $dst.Substring($star + 1)
        if ($Name.Length -gt $pre.Length + $post.Length -and
            $Name.StartsWith($pre, [StringComparison]::Ordinal) -and $Name.EndsWith($post, [StringComparison]::Ordinal) -and
            $src.Contains('*')) {
            $src.Replace('*', $Name.Substring($pre.Length, $Name.Length - $pre.Length - $post.Length))
        }
    }
}

# The trusted exclusion set arrives as '^<object id>' lines on stdin ($ExcludeText, joined once per
# repository): object ids rather than refnames, so a ref pruned by a concurrent fetch, or one whose
# name does not survive a round trip, cannot make rev-list die mid-run.
function Invoke-RevList {
    param([string]$Repo, [string[]]$RevArgs, [string[]]$NotArgs, [string]$ExcludeText)
    return Invoke-Git -Repo $Repo -GitArgs (@('rev-list', '--stdin') + @($RevArgs) + @($NotArgs)) -StdinText $ExcludeText
}

# A remote's own tracking refs, as Name and Oid: full refnames under refs/remotes/<name>/, with
# symrefs dropped (a symref's target, if it is trusted, is listed in its own right; a symref pointing
# outside would smuggle that ref in) and a nested remote's namespace (<name>/<other>) left to that
# remote. Ok is false when the listing failed, which the caller reports rather than reading as "no
# refs".
#
# With -Advertised (the branch and tag names the remote answered with), a tracking ref is kept only
# when the remote's fetch refspecs map it back to one of those names, or to a source outside
# refs/heads/ and refs/tags/ that the probe cannot see: one whose source branch was deleted on the
# remote is a stale local copy and backs nothing (BACKLOG #5502). Stale counts them.
# The object id is not compared, so a branch the remote rewound is still trusted at its old tip.
function Get-RemoteOwnRefs {
    param([string]$Repo, [string]$Remote, [string[]]$AllRemotes, $Advertised, [string[]]$Refspecs)
    $nested = @($AllRemotes | Where-Object { $_.StartsWith("$Remote/", [StringComparison]::Ordinal) })
    $res = Invoke-Git -Repo $Repo -GitArgs @('for-each-ref', '--format=%(objectname) %(refname) %(symref)', "refs/remotes/$Remote")
    $own = [System.Collections.Generic.List[object]]::new()
    $stale = 0
    foreach ($line in $res.Lines) {
        $oid, $name, $sym = $line -split ' ', 3
        if ($sym) { continue }
        if (-not $name.StartsWith("refs/remotes/$Remote/", [StringComparison]::Ordinal)) { continue }
        if ($nested | Where-Object { $name.StartsWith("refs/remotes/$_/", [StringComparison]::Ordinal) }) { continue }
        if ($null -ne $Advertised) {
            # The probe lists branches and tags only, so a source outside refs/heads/ and refs/tags/
            # (a pull ref, a rescue namespace) cannot be checked and stays trusted, as before.
            $sources = @(Get-RefspecSource -Name $name -Refspecs $Refspecs)
            $checkable = @($sources | Where-Object { $_.StartsWith('refs/heads/', [StringComparison]::Ordinal) -or $_.StartsWith('refs/tags/', [StringComparison]::Ordinal) })
            $uncheckable = $sources.Count -gt $checkable.Count
            if (-not $uncheckable -and -not ($checkable | Where-Object { $Advertised.Contains($_) })) {
                $stale++
                continue
            }
        }
        $own.Add([pscustomobject]@{ Name = $name; Oid = $oid })
    }
    return [pscustomobject]@{ Ok = $res.Ok; Refs = $own; Stale = $stale }
}

# $Landed maps each commit the caller's `git cherry` runs marked '-' to the upstream that marked it.
# $NotArgs and $ExcludeText are the caller's exclusion set, so a parent counts as backed only by a
# remote this run trusts (see $excludeText and $upstreamCandidates below, BACKLOG #5502).
function Test-CommitContentDurable {
    param([string]$Repo, [string]$Commit, [hashtable]$Landed, [string[]]$NotArgs, [string]$ExcludeText)

    # Arm 1: patch-id already upstream. `git cherry` marks '-' when an equivalent patch exists on the
    # upstream ref, which is precisely the squash/rebase-landed case a sha comparison cannot see.
    if ($Landed.ContainsKey($Commit)) {
        return [pscustomobject]@{ Durable = $true; Why = "patch already on $($Landed[$Commit] -replace '^refs/remotes/', '') (squash/rebase-landed)" }
    }

    # Arm 2: a re-derivable merge over backed parents.
    $line = (& $gitExe -C $Repo rev-list --parents -n1 $Commit 2>$null)
    if (-not $line) { return [pscustomobject]@{ Durable = $false; Why = $null } }
    $parents = @(($line -split '\s+') | Select-Object -Skip 1)
    if ($parents.Count -lt 2) { return [pscustomobject]@{ Durable = $false; Why = $null } }

    foreach ($par in $parents) {
        $res = Invoke-RevList -Repo $Repo -RevArgs @('--count', $par) -NotArgs $NotArgs -ExcludeText $ExcludeText
        if (-not $res.Ok -or -not $res.Lines -or [int]$res.Lines[0] -gt 0) {
            return [pscustomobject]@{ Durable = $false; Why = $null }   # a parent is unbacked, or unknown
        }
    }
    $actual = (& $gitExe -C $Repo rev-parse "$Commit^{tree}" 2>$null)
    $auto = (& $gitExe -C $Repo merge-tree --write-tree $parents[0] $parents[1] 2>$null | Select-Object -First 1)
    if ($actual -and $auto -and $actual -eq $auto) {
        return [pscustomobject]@{ Durable = $true; Why = 'merge over backed parents, tree identical to the automatic merge' }
    }
    return [pscustomobject]@{ Durable = $false; Why = $null }
}

$repos = @()
$totalRefs = 0
$totalWorktrees = 0
$totalUnbacked = 0
$totalCommits = 0
$totalDetached = 0
$totalDirty = 0
$totalDurable = 0
$durableFindings = @()

foreach ($p in $Path) {
    if (-not (Test-Path -LiteralPath $p)) {
        [Console]::Error.WriteLine("Path does not exist: $p")
        exit 2
    }
    # ABSOLUTE, ONCE, BEFORE ANY GIT CALL. `& git -C .` resolves against PowerShell's location, and
    # Invoke-Git's process resolves against the process directory, which a Set-Location does not
    # move; with a relative path the two halves of a run would read different repositories.
    $p = (Resolve-Path -LiteralPath $p).ProviderPath
    $inside = (& $gitExe -C $p rev-parse --is-inside-work-tree 2>$null)
    if ($inside -ne "true") {
        [Console]::Error.WriteLine("Not a git repository: $p")
        exit 2
    }

    # Every place a listing or a rev-list failed. A failed scan prints nothing, and nothing must not
    # read as zero: one such failure makes the repository UNVERIFIABLE and the run exit 2.
    $scanFailed = @()

    # Read through Invoke-Git, UTF-8, so remote names compare equal to the refnames listed the same way.
    # A failed listing is a failed scan, never "no remote" (BACKLOG #5502).
    $remoteList = Invoke-Git -Repo $p -GitArgs @('remote')
    if (-not $remoteList.Ok) { $scanFailed += '(remote listing)' }
    $remotes = @($remoteList.Lines)

    # Probe each remote ONCE. `ls-remote --exit-code` contacts the server and changes nothing locally,
    # which is what makes it safe to run from an audit. This is the axis that distinguishes "backed
    # up" from "excluded by a local copy of a store that no longer answers".
    $reachable = @()
    $unreachable = @()
    $emptyRemotes = @()
    # Per answering remote, the branch and tag names it advertised: Get-RemoteOwnRefs trusts only the
    # tracking refs that map back to one of them.
    $advertised = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    if (-not $SkipReachability) {
        foreach ($rem in $remotes) {
            # A remote answers when it advertises a branch or tag. Only those two namespaces are
            # listed, so a large remote's pull refs never are: a bare repository whose HEAD names a
            # branch nobody pushed still holds branches, and a durability store may hold only rescue
            # tags. Exit 2 means it answered with neither -- an empty or recreated store, which backs
            # nothing, so it is untrusted and reported apart from one that did not answer. A remote
            # holding only other refs reads empty too.
            $probe = Invoke-Git -Repo $p -GitArgs @('ls-remote', '--exit-code', '--heads', '--tags', $rem)
            if ($probe.ExitCode -eq 0) {
                $reachable += $rem
                $names = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
                foreach ($l in $probe.Lines) {
                    $n = ($l -split "`t", 2)[1]
                    if ($n -and -not $n.EndsWith('^{}')) { [void]$names.Add($n) }
                }
                $advertised[$rem] = $names
            } else {
                $unreachable += $rem
                if ($probe.ExitCode -eq 2) { $emptyRemotes += $rem }
            }
        }
    }

    # TRUST ONLY WHAT ANSWERED (BACKLOG #5502). A bare `--not --remotes` lets every tracking ref
    # exclude commits -- a remote that did not answer, or a namespace left by a remote no longer
    # configured -- so with one live remote the repository is not UNVERIFIABLE and a branch held only
    # by a dead store read as backed. So once any remote answered, only the answering remotes' OWN
    # tracking refs exclude, passed as explicit object ids (Get-RemoteOwnRefs, Invoke-RevList): no
    # glob, so neither a symref pointing outside the namespace nor a nested remote's namespace rides
    # along. When reachability was skipped (documented as weaker) or none answered, every
    # non-symref tracking ref excludes, as the bare form did: that repository is reported
    # UNVERIFIABLE, whose count is stated as a floor. With no remote configured nothing excludes,
    # orphan tracking refs included. Names are compared case-sensitively, as git compares them.
    #
    # Each answering remote's own refs are listed once, filtered to the ones its fetch refspecs map
    # back to a name it advertised, and reused for the exclusion set and the candidates.
    $ownRefs = [System.Collections.Generic.Dictionary[string, object]]::new([StringComparer]::Ordinal)
    $staleRefs = 0
    foreach ($r in $remotes) {
        if (-not $SkipReachability -and $reachable -cnotcontains $r) { continue }
        $adv = $null
        $specs = @()
        if (-not $SkipReachability) {
            $adv = $advertised[$r]
            # Exit 1 is "no such key": a remote with no fetch refspec maps no tracking ref back.
            $specRes = Invoke-Git -Repo $p -GitArgs @('config', '--get-all', "remote.$r.fetch")
            if (-not $specRes.Ok -and $specRes.ExitCode -ne 1) { $scanFailed += "(fetch refspecs of $r)" }
            $specs = @($specRes.Lines)
        }
        $listing = Get-RemoteOwnRefs -Repo $p -Remote $r -AllRemotes $remotes -Advertised $adv -Refspecs $specs
        if (-not $listing.Ok) { $scanFailed += "(tracking refs of $r)" }
        $ownRefs[$r] = $listing.Refs
        $staleRefs += $listing.Stale
    }
    # The exclusion set, as object ids. Once a remote answered, the trusted remotes' own refs; with
    # -SkipReachability, or with remotes and none answering (UNVERIFIABLE, a floor), every non-symref
    # ref under refs/remotes, which is what a bare `--not --remotes` read, minus a symref's outside
    # target. With no remote configured nothing excludes.
    $notArgs = @()
    $excludeText = ''
    $oids = [System.Collections.Generic.HashSet[string]]::new([StringComparer]::Ordinal)
    if ($reachable.Count -gt 0) {
        foreach ($r in $reachable) { foreach ($x in $ownRefs[$r]) { [void]$oids.Add($x.Oid) } }
    } elseif ($remotes.Count -gt 0) {
        $all = Invoke-Git -Repo $p -GitArgs @('for-each-ref', '--format=%(objectname) %(symref)', 'refs/remotes')
        if (-not $all.Ok) { $scanFailed += '(remote-tracking ref listing)' }
        foreach ($line in $all.Lines) {
            $oid, $sym = $line -split ' ', 2
            if (-not $sym) { [void]$oids.Add($oid) }
        }
    }
    # A tracking ref naming a missing object, or a tag whose target commit is missing, backs nothing,
    # and handing its id to rev-list would kill every scan. One cat-file call peels each id to its
    # commit and drops those that do not resolve; a missing BRANCH tip or a hole in history still
    # fails its own rev-list and reads UNVERIFIABLE.
    if ($oids.Count -gt 0) {
        $check = Invoke-Git -Repo $p -GitArgs @('cat-file', '--batch-check=%(objectname) %(objecttype)') -StdinText ((@($oids | ForEach-Object { "$_^{commit}" }) -join "`n") + "`n")
        if (-not $check.Ok) { $scanFailed += '(tracking ref object check)' }
        # Only a resolved commit is kept: an unresolvable name prints "<name> missing" (or another
        # word), never an id and the type.
        $present = @($check.Lines | Where-Object { $_ -match '^[0-9a-f]{40,64} commit$' } | ForEach-Object { ($_ -split ' ', 2)[0] })
        $excludeText = (($present | ForEach-Object { "^$_" }) -join "`n") + "`n"
    }
    # Tracking refs under no configured remote: no longer trusted once any remote answered, and
    # counted so the output can say they were ignored.
    $orphanRefs = 0
    if ($reachable.Count -gt 0) {
        $listing = Invoke-Git -Repo $p -GitArgs @('for-each-ref', '--format=%(refname)', 'refs/remotes')
        if (-not $listing.Ok) { $scanFailed += '(tracking ref listing)' }
        $orphanRefs = @($listing.Lines | Where-Object {
            $rn = $_
            -not ($remotes | Where-Object { $rn.StartsWith("refs/remotes/$_/", [StringComparison]::Ordinal) })
        }).Count
    }
    # The patch-id arm reads the default branches of the TRUSTED remotes: for each, every one of its
    # refs/remotes/<r>/HEAD target, main and master that is one of that remote's own refs. Membership
    # in Get-RemoteOwnRefs is the existence test, so a dangling HEAD falls back, a HEAD target outside
    # the namespace or in a nested remote's is refused, and a local branch or tag NAMED like a
    # tracking ref never stands in (rev-parse would resolve one). Without -SkipReachability a trusted
    # remote is one that answered, so with none answering (UNVERIFIABLE) the arm is off. Origin is
    # listed first only so it names the upstream in the reclassification line; the ref loop reads
    # every candidate. Each candidate carries its object id, which is what git is handed.
    $trustedNames = if ($SkipReachability) { $remotes } else { $reachable }
    $ordered = @($trustedNames | Where-Object { $_ -ceq 'origin' }) + @($trustedNames | Where-Object { $_ -cne 'origin' })
    $upstreamCandidates = [System.Collections.Generic.List[object]]::new()
    foreach ($r in $ordered) {
        $own = $ownRefs[$r]
        $head = (Invoke-Git -Repo $p -GitArgs @('symbolic-ref', '--quiet', "refs/remotes/$r/HEAD")).Lines | Select-Object -First 1
        foreach ($n in @($head, "refs/remotes/$r/main", "refs/remotes/$r/master")) {
            if (-not $n -or ($upstreamCandidates | Where-Object { $_.Name -ceq $n })) { continue }
            $hit = $own | Where-Object { $_.Name -ceq $n } | Select-Object -First 1
            if ($hit) { $upstreamCandidates.Add($hit) }
        }
    }
    # RELATED HISTORY, DECIDED ONCE PER CANDIDATE: against a main that shares no history with this
    # repository -- another project fetched as a durability remote -- `git cherry` compares the whole
    # of both, and a diff that happens to be identical there would mark an unbacked commit landed. A
    # candidate `git merge-base` cannot join to the checkout's HEAD is dropped for the whole run; one
    # call per candidate, not one per ref. Each ref is checked against the kept candidates again
    # below, so an orphan branch is not compared with a main that only HEAD shares history with.
    $upstreamCandidates = @($upstreamCandidates | Where-Object {
        (Invoke-Git -Repo $p -GitArgs @('merge-base', $_.Oid, 'HEAD')).Ok
    })

    # Branches as a snapshot of object ids: a branch deleted by another session after this listing is
    # still scanned from its id rather than failing, and a non-ASCII name is only ever displayed.
    $heads = Invoke-Git -Repo $p -GitArgs @('for-each-ref', '--format=%(objectname) %(refname)', 'refs/heads')
    if (-not $heads.Ok) { $scanFailed += '(branch listing)' }
    $refs = @($heads.Lines | ForEach-Object {
        $oid, $name = $_ -split ' ', 2
        [pscustomobject]@{ Oid = $oid; Name = $name }
    })
    $findings = @()
    $atRiskOids = @()

    # DETACHED WORKTREE HEADS. A worktree checked out on a branch is already covered by the ref scan
    # above; one with a detached HEAD is on no branch and no ref scan can reach it. Enumerate the
    # checkouts themselves so "everything" means every place a commit can be sitting, not every
    # branch. Reported against the worktree PATH because there is no branch name to report.
    # Read as UTF-8 through Invoke-Git: decoded with the console code page, a non-ASCII worktree path
    # came back garbled, failed Test-Path below and was skipped silently (BACKLOG #5502).
    $wtHeads = @()
    $wtList = Invoke-Git -Repo $p -GitArgs @('worktree', 'list', '--porcelain')
    if (-not $wtList.Ok) { $scanFailed += '(worktree listing)' }
    foreach ($line in $wtList.Lines) {
        if ($line -match '^worktree (.+)$') { $wtHeads += $Matches[1] }
    }
    $detached = @()
    $detachedOids = @()
    $detachedUnresolved = 0
    $dirty = @()
    foreach ($wp in $wtHeads) {
        $native = $wp -replace '/', '\'
        if (-not (Test-Path -LiteralPath $native)) { continue }
        # Reported, never counted -- see the DESCRIPTION. An uncommitted edit cannot be made durable
        # by anything here, and is the one loss no reflog recovers, so silence about it is the
        # dangerous option.
        $st = @(& $gitExe -C $native status --porcelain 2>$null)
        if ($st.Count -gt 0) {
            $dirty += [pscustomobject]@{
                Worktree = $native
                Tracked  = @($st | Where-Object { $_ -notmatch '^\?\?' }).Count
                Untracked = @($st | Where-Object { $_ -match '^\?\?' }).Count
            }
        }
        # symbolic-ref fails on a detached HEAD; that failure IS the test.
        & $gitExe -C $native symbolic-ref --quiet HEAD 2>$null | Out-Null
        if ($LASTEXITCODE -eq 0) { continue }
        $res = Invoke-RevList -Repo $native -RevArgs @('--count', 'HEAD') -NotArgs $notArgs -ExcludeText $excludeText
        if (-not $res.Ok) {
            # A worktree removed by another session mid-run holds nothing at risk here; skip it.
            if (Test-Path -LiteralPath $native) { $scanFailed += "(detached) $native" }
            continue
        }
        $dn = $res.Lines | Select-Object -First 1
        if ($dn -and [int]$dn -gt 0) {
            $full = (Invoke-Git -Repo $native -GitArgs @('rev-parse', 'HEAD')).Lines | Select-Object -First 1
            if ($full -match '^[0-9a-f]{40,64}$') { $detachedOids += $full } else { $detachedUnresolved += [int]$dn }
            $detached += [pscustomobject]@{
                Worktree = $native
                Head     = (& $gitExe -C $native rev-parse --short HEAD 2>$null)
                Commits  = [int]$dn
            }
        }
    }

    foreach ($ref in $refs) {
        # The exclusion set excludes everything reachable from a trusted remote-tracking ref. With no
        # remotes configured it excludes nothing, so the count is the branch's entire history --
        # correct, and the reason the NO-REMOTE case is reported separately below rather than silently
        # inflating a total that would then read as ordinary unpushed work.
        $refName = $ref.Name -replace '^refs/heads/', ''
        $res = Invoke-RevList -Repo $p -RevArgs @($ref.Oid) -NotArgs $notArgs -ExcludeText $excludeText
        if (-not $res.Ok) { $scanFailed += $refName; continue }
        $unbacked = $res.Lines
        $n = $unbacked.Count
        if ($n -gt 0) {
            # CLASSIFY BEFORE ALARMING (BACKLOG #1299). Only when EVERY unbacked commit on this ref is
            # content-durable does the ref stop being a finding -- one commit that fails both arms
            # keeps the whole ref in the at-risk report, because the point is not to lose that one.
            # ONE `git cherry` PER REF, read line by line (BACKLOG #5493). It lists every commit in
            # upstream..ref, so a per-commit call whose FIRST line was taken as that commit's verdict
            # read the OLDEST commit's mark, and one landed commit at the base of a branch cleared
            # every unpushed commit on top of it.
            # SHARED HISTORY FIRST: against a main this ref shares no history with -- another project
            # fetched as a durability remote, or an orphan branch -- cherry compares the whole of
            # both, and a diff that happens to be identical there would mark an unbacked commit
            # landed. So the candidate list holds only histories related to HEAD (decided once,
            # above), and of those a candidate `git merge-base` cannot join to THIS ref is skipped
            # too. EVERY candidate left is read: a squash that landed on a second answering remote
            # is as durable as one on origin.
            $landed = @{}
            foreach ($u in $upstreamCandidates) {
                if (-not (Invoke-Git -Repo $p -GitArgs @('merge-base', $u.Oid, $ref.Oid)).Ok) { continue }
                foreach ($cl in (Invoke-Git -Repo $p -GitArgs @('cherry', $u.Oid, $ref.Oid)).Lines) {
                    if ($cl -match '^- ([0-9a-f]+)$' -and -not $landed.ContainsKey($Matches[1])) { $landed[$Matches[1]] = $u.Name }
                }
            }
            $why = $null
            $allDurable = $true
            foreach ($c in $unbacked) {
                $v = Test-CommitContentDurable -Repo $p -Commit $c -Landed $landed -NotArgs $notArgs -ExcludeText $excludeText
                if (-not $v.Durable) { $allDurable = $false; break }
                if (-not $why) { $why = $v.Why }
            }
            if ($allDurable) {
                $durableFindings += [pscustomobject]@{
                    Repo    = $p
                    Ref     = $refName
                    Commits = [int]$n
                    Why     = $why
                }
                $totalDurable += [int]$n
                continue
            }
            $findings += [pscustomobject]@{
                Ref     = $refName
                Commits = [int]$n
            }
            $atRiskOids += $ref.Oid
        }
    }

    # Branch AND detached-HEAD commits, so this repository's figure agrees with CommitsUnbacked and
    # the NO-REMOTE and UNVERIFIABLE lines do not leave out a detached checkout's work (BACKLOG #6489
    # item 1). The detached share is the distinct commits no at-risk branch already counts: a HEAD
    # detached on a branch's history would otherwise count that history twice. If that count cannot
    # be read, each detached HEAD's own count is added instead -- too high, never too low -- and the
    # failure is a failed scan like any other. Every id goes on stdin, so the command line does not
    # grow with the worktree count, and no blank line is written: rev-list --stdin stops reading there.
    $detachedSum = $detachedUnresolved
    if ($detachedOids.Count -gt 0) {
        $stdinLines = @($excludeText -split "`n" | Where-Object { $_ }) + @($atRiskOids | ForEach-Object { "^$_" }) + @($detachedOids)
        $res = Invoke-RevList -Repo $p -RevArgs @('--count') -NotArgs $notArgs -ExcludeText (($stdinLines -join "`n") + "`n")
        if ($res.Ok -and $res.Lines) {
            $detachedSum += [int]$res.Lines[0]
        } else {
            $scanFailed += '(detached commit count)'
            $detachedSum = [int](($detached | Measure-Object -Property Commits -Sum).Sum)
        }
    }
    $sum = [int](($findings | Measure-Object -Property Commits -Sum).Sum) + $detachedSum

    $repos += [pscustomobject]@{
        Repo                = $p
        # Null, not false or 0, when `git remote` failed: an unread listing is not "no remote".
        HasRemote           = $(if ($remoteList.Ok) { $remotes.Count -gt 0 } else { $null })
        RemotesConfigured   = $(if ($remoteList.Ok) { $remotes.Count } else { $null })
        RemotesReachable    = $reachable.Count
        RemotesUnreachable  = $unreachable
        RemotesEmpty        = $emptyRemotes
        OrphanTrackingRefs  = $orphanRefs
        StaleTrackingRefs   = $staleRefs
        ReachabilityChecked = (-not $SkipReachability)
        # UNVERIFIABLE: remotes exist, none answered. Every "backed" verdict in this repo then rests
        # on local copies of a store that is not there, so the commit count below understates by an
        # unknown amount and must not be read as clean. A failed rev-list is the same verdict for a
        # different reason: the scan itself could not run, so its silence is not a zero.
        ScanFailed          = $scanFailed
        Unverifiable        = ((($remotes.Count -gt 0) -and (-not $SkipReachability) -and ($reachable.Count -eq 0)) -or ($scanFailed.Count -gt 0))
        RefsScanned         = $refs.Count
        WorktreesScanned    = $wtHeads.Count
        Unbacked            = $findings.Count
        Commits             = $sum
        Findings            = $findings
        DetachedUnbacked    = $detached
        DirtyCheckouts      = $dirty
    }
    $totalRefs += $refs.Count
    $totalWorktrees += $wtHeads.Count
    $totalUnbacked += $findings.Count
    $totalCommits += $sum
    $totalDetached += $detached.Count
    $totalDirty += $dirty.Count
}

if ($Json) {
    $unverifiableCount = @($repos | Where-Object { $_.Unverifiable }).Count
    [pscustomobject]@{
        RepositoriesScanned  = $repos.Count
        RefsScanned          = $totalRefs
        WorktreesScanned     = $totalWorktrees
        BranchesUnbacked     = $totalUnbacked
        DetachedWorktreesUnbacked = $totalDetached
        CommitsUnbacked      = $totalCommits
        RepositoriesUnverifiable = $unverifiableCount
        ReachabilityChecked  = (-not $SkipReachability)
        Repositories         = $repos
    } | ConvertTo-Json -Depth 6
    # Unverifiable and detached must both fail too. A consumer keying only on CommitsUnbacked would
    # read a dead remote as clean; one keying only on BranchesUnbacked would miss every detached
    # checkout, which is how 30 commits went unreported. A failed scan exits 2, "could not run", so a
    # consumer can tell a broken measurement from work that needs a rescue push.
    if (@($repos | Where-Object { $_.ScanFailed.Count -gt 0 }).Count -gt 0) { exit 2 }
    exit ([int](($totalUnbacked -gt 0) -or ($unverifiableCount -gt 0) -or ($totalDetached -gt 0)))
}

$unverifiableRepos = @($repos | Where-Object { $_.Unverifiable })
$scanFailedRepos = @($repos | Where-Object { $_.ScanFailed.Count -gt 0 })

foreach ($r in $repos) {
    if ($r.ScanFailed.Count -gt 0) {
        Write-Host "UNVERIFIABLE  $($r.Repo)" -ForegroundColor Red
        Write-Host "              git FAILED for: $($r.ScanFailed -join ', ')" -ForegroundColor Red
        Write-Host "              A failed scan prints nothing, and nothing is not zero: this repository" -ForegroundColor Red
        Write-Host "              could not be fully measured. Run git fsck there; a missing object is the usual cause." -ForegroundColor Red
        # What DID scan is still shown: a failure on one ref must not hide the at-risk work found
        # on the others. The JSON carries the same items under Findings and DetachedUnbacked. When
        # a trusted-refs listing or the object check failed, in any mode, the per-branch list is
        # withheld.
        $listingFailed = @($r.ScanFailed | Where-Object {
                $_ -like '(tracking refs of *' -or $_ -like '(fetch refspecs of *' -or
                $_ -in @('(tracking ref object check)', '(remote-tracking ref listing)', '(remote listing)')
            })
        if ($listingFailed.Count -gt 0) {
            Write-Host "              a git listing failed for $($listingFailed -join ', '); per-branch counts are not shown" -ForegroundColor Red
        } elseif ($r.Unbacked -gt 0 -or $r.DetachedUnbacked.Count -gt 0) {
            Write-Host "              measured before or beside the failure, on no remote:" -ForegroundColor Yellow
            if (-not $Quiet) {
                foreach ($f in ($r.Findings | Sort-Object Commits -Descending)) {
                    Write-Host ("              {0,-55} {1}" -f $f.Ref, $f.Commits)
                }
                foreach ($f in ($r.DetachedUnbacked | Sort-Object Commits -Descending)) {
                    Write-Host ("              {0,-55} {1}" -f "(detached) $($f.Worktree) @ $($f.Head)", $f.Commits) -ForegroundColor Yellow
                }
            }
        }
        continue
    }
    if (-not $r.HasRemote) {
        Write-Host "NO-REMOTE     $($r.Repo)" -ForegroundColor Red
        Write-Host "              $($r.Commits) commits across $($r.RefsScanned) refs$(if ($r.DetachedUnbacked.Count -gt 0) { " and $($r.DetachedUnbacked.Count) detached checkout(s)" }) exist on this disk only." -ForegroundColor Red
        Write-Host "              This repository has no remote at all, so nothing here is a push away from" -ForegroundColor Red
        Write-Host "              safety -- it needs a remote first. A bundle is interim cover, not a remote." -ForegroundColor Red
        continue
    }
    if ($r.Unverifiable) {
        Write-Host "UNVERIFIABLE  $($r.Repo)" -ForegroundColor Red
        Write-Host "              $($r.RemotesConfigured) remote(s) configured, NONE reachable: $($r.RemotesUnreachable -join ', ')" -ForegroundColor Red
        if ($r.RemotesEmpty.Count -gt 0) {
            Write-Host "              of those, answered with no refs (an empty store): $($r.RemotesEmpty -join ', ')" -ForegroundColor Red
        }
        Write-Host "              This check reports $($r.Commits) unbacked across $($r.RefsScanned) refs$(if ($r.DetachedUnbacked.Count -gt 0) { " and $($r.DetachedUnbacked.Count) detached checkout(s)" }), and that number" -ForegroundColor Red
        Write-Host "              is a FLOOR, not an answer. Everything it counted as backed was excluded by" -ForegroundColor Red
        Write-Host "              refs/remotes/* -- local copies of a store that did not answer. Restore the" -ForegroundColor Red
        Write-Host "              remote, re-point it, or bundle the repository and treat it as unbacked." -ForegroundColor Red
        continue
    }
    if ($r.Unbacked -eq 0 -and $r.DetachedUnbacked.Count -eq 0) { continue }
    Write-Host "UNBACKED      $($r.Repo)" -ForegroundColor Yellow
    if (-not $Quiet) {
        foreach ($f in ($r.Findings | Sort-Object Commits -Descending)) {
            Write-Host ("              {0,-55} {1}" -f $f.Ref, $f.Commits)
        }
        # Reported against the path, and labelled, because a reader scanning for a branch name will
        # not find one -- that absence is the whole reason a ref scan missed it.
        foreach ($f in ($r.DetachedUnbacked | Sort-Object Commits -Descending)) {
            Write-Host ("              {0,-55} {1}" -f "(detached) $($f.Worktree) @ $($f.Head)", $f.Commits) -ForegroundColor Yellow
        }
    }
}

# COVERAGE FIRST, ALWAYS, INCLUDING ON A CLEAN RUN. See the DESCRIPTION: a bare "clean" cannot be
# distinguished from a run that examined nothing.
Write-Host ""
# Refs AND worktrees, never one number. A single count hides which of the two it meant, and the
# gap between them is exactly where 30 commits hid on 2026-08-16.
Write-Host "coverage : $totalRefs refs and $totalWorktrees worktree checkouts (incl. primary) across $($repos.Count) repositor$(if ($repos.Count -eq 1) { 'y' } else { 'ies' })"
if ($SkipReachability) {
    Write-Host "           reachability NOT checked (-SkipReachability) -- a dead remote reads as backed" -ForegroundColor Yellow
} else {
    $reach = ($repos | Measure-Object -Property RemotesReachable -Sum).Sum
    $conf = ($repos | Measure-Object -Property RemotesConfigured -Sum).Sum
    # Measure-Object sums a null as 0, and a failed `git remote` is not zero remotes.
    if ($repos | Where-Object { $null -eq $_.RemotesConfigured }) { $conf = "$conf or more (git remote failed)" }
    Write-Host "           $reach of $conf configured remote(s) answered$(if ($repos | Where-Object { $_.RemotesEmpty.Count -gt 0 }) { ' (a remote that answered with no refs is not counted)' })"
    # Named, because a branch held only by one of these reads as "exist on no remote" above, and
    # the remedy for that is restoring the remote, not a rescue push.
    foreach ($r in ($repos | Where-Object { $_.RemotesReachable -gt 0 -and $_.RemotesUnreachable.Count -gt 0 })) {
        $silent = @($r.RemotesUnreachable | Where-Object { $r.RemotesEmpty -cnotcontains $_ })
        if ($silent.Count -gt 0) {
            Write-Host "           not trusted, did not answer: $($silent -join ', ') in $($r.Repo) -- a branch held only there counts as unbacked; restore or re-point it" -ForegroundColor Yellow
        }
        if ($r.RemotesEmpty.Count -gt 0) {
            Write-Host "           not trusted, answered with no refs: $($r.RemotesEmpty -join ', ') in $($r.Repo) -- an empty store backs nothing" -ForegroundColor Yellow
        }
    }
    foreach ($r in ($repos | Where-Object { $_.OrphanTrackingRefs -gt 0 })) {
        Write-Host "           not trusted, no configured remote: $($r.OrphanTrackingRefs) tracking ref(s) in $($r.Repo) -- a branch held only there counts as unbacked" -ForegroundColor Yellow
    }
    foreach ($r in ($repos | Where-Object { $_.StaleTrackingRefs -gt 0 })) {
        Write-Host "           not trusted, no longer advertised by their remote: $($r.StaleTrackingRefs) tracking ref(s) in $($r.Repo) -- a branch held only there counts as unbacked; git fetch --prune clears them" -ForegroundColor Yellow
    }
}
if ($unverifiableRepos.Count -gt 0) {
    Write-Host "result   : UNVERIFIABLE in $($unverifiableRepos.Count) repositor$(if ($unverifiableRepos.Count -eq 1) { 'y' } else { 'ies' }) -- see above. Not reporting clean." -ForegroundColor Red
    # Exit 2 when a scan could not run (see .OUTPUTS); 1 when it ran against remotes that did not answer.
    if ($scanFailedRepos.Count -gt 0) { exit 2 }
    exit 1
}
# Printed BEFORE the result line, and on every run, so "0 unbacked commits" can never be read alone.
# Deliberately not part of the exit code: see the DESCRIPTION.
if ($totalDirty -gt 0) {
    Write-Host "uncommitted: $totalDirty checkout$(if ($totalDirty -ne 1) { 's' }) hold uncommitted changes -- NOT durable, and nothing here can make them so" -ForegroundColor Yellow
    if (-not $Quiet) {
        foreach ($r in $repos) {
            foreach ($x in $r.DirtyCheckouts) {
                Write-Host ("             {0,-55} {1} tracked, {2} untracked" -f $x.Worktree, $x.Tracked, $x.Untracked)
            }
        }
    }
}
# RECLASSIFIED, ALWAYS PRINTED (BACKLOG #1299). Shown on a clean run too: a reader who sees only
# "0 unbacked" cannot tell whether the classification examined anything, and a silent reclassification
# is how a real alarm would get suppressed without anyone noticing the mechanism existed.
if ($totalDurable -gt 0) {
    Write-Host "durable  : $totalDurable commit$(if ($totalDurable -ne 1) { 's' }) on $($durableFindings.Count) ref$(if ($durableFindings.Count -ne 1) { 's' }) exist on no remote but their CONTENT is not at risk" -ForegroundColor DarkGray
    if (-not $Quiet) {
        foreach ($d in $durableFindings) {
            Write-Host ("             {0,-42} {1}" -f $d.Ref, $d.Why) -ForegroundColor DarkGray
        }
    }
}
if ($totalUnbacked -eq 0 -and $totalDetached -eq 0) {
    Write-Host "result   : 0 unbacked commits$(if ($totalDirty -gt 0) { ' (but see uncommitted, above)' })" -ForegroundColor Green
    exit 0
}
$where = @()
if ($totalUnbacked -gt 0) { $where += "$totalUnbacked branch$(if ($totalUnbacked -ne 1) { 'es' })" }
if ($totalDetached -gt 0) { $where += "$totalDetached detached worktree$(if ($totalDetached -ne 1) { 's' })" }
Write-Host "result   : $totalCommits commits on $($where -join ' and ') exist on no remote" -ForegroundColor Yellow
Write-Host ""
Write-Host "Remedy, which buys durability without publication or review:"
Write-Host "  git config mefor.durabilityRemote <private-remote>   # once, per repository"
Write-Host "  pwsh -NoProfile -File scripts\coord\rescue.ps1 -Anchor <name>   # IN the checkout holding the work"
Write-Host "  git push --force <private-remote> refs/tags/rescue/<name>"
Write-Host "Verify the remote is private BEFORE nominating it:  gh repo view <owner>/<repo> --json visibility"
# THE -Anchor STEP IS THE REMEDY, NOT DECORATION (BACKLOG #1349). This block used to print a bare
# `git push --force <remote> <branch>:refs/tags/rescue/branch/<branch>`, so an operator who followed
# the tool's own advice wrote a ref recording NOTHING about what it captured. That ref can then only
# be graded against a branch that still exists -- which is precisely the population a rescue ref was
# never needed for. Measured 2026-09-03 in this checkout: rescue.ps1 -Check examined 1671 refs and
# returned UNVERIFIABLE for all 1671, every one of them written by a bare push like the one this
# script was printing. -Anchor writes an annotated tag whose message carries the commit, the branch
# and whether it was that branch's head at the instant of capture, and -Check reads that back after
# the branch is gone.
Write-Host ""
Write-Host "-Anchor is what makes the ref readable LATER: it records the commit, the branch and"
Write-Host "whether the capture was that branch's head. A bare push records none of that, and a"
Write-Host "rescue ref is read once -- after the branch it names is already gone. Audit what you"
Write-Host "have with:  pwsh -NoProfile -File scripts\coord\rescue.ps1 -Check"
exit 1
