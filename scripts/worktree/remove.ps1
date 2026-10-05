# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Remove one git worktree of this clone, or list every one of them.

.DESCRIPTION
    THREE WAYS IN.

      -Name <n>   The sibling worktree new.ps1 made for <n>, at <repo>-<n> beside the checkout THIS
                  COPY lives in. Unchanged by the routes below. It can also delete the branch.
      -Path <p>   Any registered linked worktree of this clone that is not under .claude/worktrees: a
                  harness scratchpad, a hand-made directory, a sibling. This is the CHECKED route, and
                  it is the one the worktree gate's rule 3d names (vault BACKLOG #1017). It removes
                  the directory and never the branch: it does not take -DeleteBranch.
      -List       Read-only. Every registered linked worktree, its class, and which route reaches it.

    WHAT -Path REFUSES, WHATEVER -Force SAYS:
      * any run with GIT_DIR, GIT_WORK_TREE, GIT_COMMON_DIR or GIT_INDEX_FILE set, since each makes
        `git -C <path>` answer for a different checkout;
      * a path component ending in a dot or a space, which Windows drops, so it names another directory;
      * anything that is not a registered linked worktree of this clone, compared on its full path as
        git records it. The primary, another repository's worktree, a plain directory, and a junction,
        subst or 8.3 spelling of a real target are all refused;
      * the target you are standing in, and a target that holds the copy of this script being run;
      * a target under a .claude/worktrees path segment. That is where the Claude Code harness puts
        its worktrees, and a subagent started with `isolation: worktree` is recorded under its
        PARENT's directory, so the occupancy check below would read its tree as empty (BACKLOG
        #1038, Manager decision batch 184). A sibling new.ps1 made beside a linked worktree also
        sits there; the copy of this script in that worktree still removes it by -Name;
      * a target that CONTAINS another registered worktree, since the removal would delete that
        checkout too and leave it registered with no directory;
      * a target git has locked, which is git's own in-use flag;
      * a DETACHED target whose HEAD commit is held by no ref, and a target whose HEAD reflog or own
        per-worktree refs (refs/worktree, refs/bisect, refs/rewritten) hold a commit no shared ref
        holds. The removal deletes that reflog and those refs, so nothing would reach the commits;
      * a target the session registry records a session in, or any target at all when the registry
        cannot be read (scripts/coord/occupancy.ps1 says why an unreadable fence must refuse). A
        registry that was read and holds no record at all clears the target. This fence sees only
        the directory a session was launched in, never where it writes.

    WHAT -Force OVERRIDES ON -Path: uncommitted tracked changes, untracked files, ignored files, and
    files flagged skip-worktree or assume-unchanged. Without -Force every one of those refuses, with
    ONE exception: an IGNORED directory named .venv, node_modules, __pycache__, .pytest_cache,
    .mypy_cache or .ruff_cache goes with the worktree. An UNTRACKED directory of those names refuses.
    -Force is the operator's switch. A session runs -Path without it, and a refusal is final for a
    session: it reports what was refused and why, and stops.

    WHAT ONLY -AllowOrphanedAllocations OVERRIDES, on both removal routes: a target that owns a
    ledger number (alloc.ps1) whose item is not on origin/main, or an allocation record that cannot
    be read. It is the operator's switch too.

    WHAT -Path DOES NOT READ. A commit that only a branch's own reflog holds is untouched, because
    the branch stays. Work a session wrote into the target by absolute path from another directory
    is seen only if it left the tree dirty.

    -Name KEEPS ITS OLD RULES, and none of the -Path refusals above apply to it except the detached
    HEAD one: tracked changes refuse without -Force, untracked files go with the worktree, there is
    no occupancy check, and it runs `git worktree prune` afterwards. -Path runs no blanket prune,
    because that also drops OTHER worktrees' registrations.

    WHICH COPY YOU RUN DECIDES WHAT -Name SEARCHES. -Name anchors on $PSScriptRoot (or -RepoRoot), not
    on your cwd, so run the copy living in the checkout the worktree was created FROM -- which is
    not necessarily the primary, since new.ps1 anchors the same way and creates its worktree beside
    itself. By absolute path it works from any cwd outside the worktree being removed. new.ps1 prints
    the exact command with the root already filled in (BACKLOG #1078). -Path and -List read the
    clone's whole worktree list, so every copy gives the same answer. See docs/WORKTREES.md.

    -Name is the DIRECTORY component only. -DeleteBranch deletes whichever branch that worktree
    actually has checked out, read from git -- not a branch named after the directory. Since new.ps1
    gained -Branch the two can differ.

    -RepoRoot exists so this script can be EXECUTION-TESTED. It used to derive its root from
    $PSScriptRoot alone, so the only repository a test could point it at was the real checkout --
    which no test may drive, because this script force-removes worktrees and force-deletes refs. The
    branch-delete path was therefore covered by review only, and it is the one place in
    scripts/worktree/ where being wrong loses commits reachable from no ref and no reflog. Same
    parameter, same reason, as prune-merged.ps1. See tests/test_worktree_remove.py and
    tests/test_worktree_remove_path.py.

.EXAMPLE
    .\remove.ps1 -Name alerts
    .\remove.ps1 -Name alerts -DeleteBranch
    .\remove.ps1 -Name alerts -Force        # discard uncommitted tracked changes too
    .\remove.ps1 -List
    .\remove.ps1 -Path C:\Users\me\AppData\Local\Temp\claude\x\y\scratchpad\wt
#>
[CmdletBinding(DefaultParameterSetName = 'ByName')]
param(
    # The worktree DIRECTORY component, not a branch -- removal is BY PATH below, so this finds a
    # worktree whose branch carries a '/' just fine, and -DeleteBranch reads the real branch from git.
    # \A..\z for the reason given in new.ps1's param block; keep all four copies identical.
    [Parameter(Mandatory = $true, ParameterSetName = 'ByName')]
    [ValidatePattern('\A[A-Za-z0-9._-]+\z')]
    [string]$Name,

    # Any registered linked worktree of this clone, by its path. The header lists what it refuses.
    [Parameter(Mandatory = $true, ParameterSetName = 'ByPath')]
    [ValidateNotNullOrEmpty()]
    [string]$Path,

    [Parameter(Mandatory = $true, ParameterSetName = 'List')]
    [switch]$List,

    # Remove even with uncommitted changes; the header says what it covers on each route.
    [Parameter(ParameterSetName = 'ByName')]
    [Parameter(ParameterSetName = 'ByPath')]
    [switch]$Force,

    # Also delete the local branch. -Name ONLY, ON PURPOSE: -Path reaches checkouts this session did
    # not make, so "it removes the directory, never the branch" has to hold by construction there.
    [Parameter(ParameterSetName = 'ByName')]
    [switch]$DeleteBranch,

    # Remove even when this worktree OWNS a ledger number whose item is not yet on origin/main
    # (BACKLOG #1293). DELIBERATELY NOT -Force: that one means "I accept losing uncommitted changes",
    # and one consent must not silently cover an unrelated, IRREVERSIBLE risk. A stranded allocation
    # cannot be re-keyed -- ownership is non-transferable -- so the number is burned and the PR
    # carrying it is unlandable BY ANYONE.
    [Parameter(ParameterSetName = 'ByName')]
    [Parameter(ParameterSetName = 'ByPath')]
    [switch]$AllowOrphanedAllocations,

    # Repo to operate on. Defaults to this script's own checkout -- which is what makes an absolute-
    # path invocation from ANY cwd resolve the checkout that owns the worktree. Tests point it at a
    # fixture so the real logic is what gets exercised.
    [string]$RepoRoot
)

$ErrorActionPreference = "Stop"

$byPath = $PSCmdlet.ParameterSetName -eq 'ByPath'
$listing = $PSCmdlet.ParameterSetName -eq 'List'

if ($byPath -or $listing) {
    # Refused rather than cleared: a script run as `.\remove.ps1` shares the caller's process, so
    # clearing them would change the operator's shell. Each one makes `git -C <path>` answer for a
    # checkout other than the one named.
    $gitRedirects = @('GIT_DIR', 'GIT_WORK_TREE', 'GIT_COMMON_DIR', 'GIT_INDEX_FILE') |
        Where-Object { [Environment]::GetEnvironmentVariable($_) }
    if ($gitRedirects) {
        throw ("$($gitRedirects -join ', ') is set, so git would answer for a different checkout than " +
            "the one named. Unset it and re-run. Nothing was removed.")
    }
}

if (-not $RepoRoot) { $RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path }
elseif (-not (Test-Path -LiteralPath $RepoRoot)) { throw "RepoRoot does not exist: $RepoRoot" }
else { $RepoRoot = (Resolve-Path -LiteralPath $RepoRoot).Path }

$Parent = Split-Path $RepoRoot -Parent
$RepoName = Split-Path $RepoRoot -Leaf

# Refs that do not keep a commit alive for long, so they never count as holding one. refs/stash moves
# with any session's next stash; the others are cleared by prefetch, bisect reset, a finished rebase
# or a filter-branch cleanup. Each --exclude binds to the --glob after it.
$transientRefExcludes = @('--exclude=refs/stash', '--exclude=refs/prefetch/*', '--exclude=refs/bisect/*',
    '--exclude=refs/rewritten/*', '--exclude=refs/original/*')

# A path with a .claude/worktrees segment, on a ConvertTo-Norm value. prune-merged.ps1 excludes the
# same population outright, for the same reason.
$managedSegment = '/\.claude/worktrees(/|\z)'

$PrimaryRoot = ''
$registered = @()
$linked = @()
if ($byPath -or $listing) {
    # Get-RepoWorktrees, ConvertTo-Norm, Get-NestedWorktrees and the occupancy fence.
    . "$PSScriptRoot\..\coord\occupancy.ps1"
    # Every registered worktree, primary first. FAIL CLOSED: an unreadable list is the same empty
    # answer as a clone with none, and must never read as permission.
    $registered = @(Get-RepoWorktrees $RepoRoot)
    if ($registered.Count -eq 0) {
        throw "Could not list the registered worktrees of '$RepoRoot'. Nothing was removed."
    }
    $PrimaryRoot = $registered[0].Path
    $linked = @($registered | Select-Object -Skip 1)
}

if ($listing) {
    # The class is where a worktree sits; the route is what reaches it. A sibling is a sibling of THE
    # CHECKOUT THIS COPY LIVES IN, because that is the only place this copy's -Name looks.
    Write-Host "Primary: $PrimaryRoot   this copy: $RepoRoot   linked worktrees: $($linked.Count)"
    $siblingPrefix = (ConvertTo-Norm (Join-Path $Parent $RepoName)) + '-'
    $counts = @{ sibling = 0; managed = 0; other = 0 }
    $byNameCount = 0
    $byPathCount = 0
    foreach ($w in $linked) {
        $norm = ConvertTo-Norm $w.Path
        $leafName = ''
        if ($norm.StartsWith($siblingPrefix)) {
            $rest = (Split-Path $w.Path -Leaf).Substring($RepoName.Length + 1)
            if (-not $norm.Substring($siblingPrefix.Length).Contains('/') -and $rest -match '\A[A-Za-z0-9._-]+\z') {
                $leafName = $rest
            }
        }
        $isManaged = $norm -match $managedSegment
        $class = if ($leafName) { 'sibling' } elseif ($isManaged) { 'managed' } else { 'other' }
        $counts[$class]++
        $routes = @()
        if ($leafName) { $routes += '-Name'; $byNameCount++ }
        if (-not $isManaged) { $routes += '-Path'; $byPathCount++ }
        $how = if ($routes) { $routes -join ',' } else { 'none' }
        $flags = @()
        if ($w.Locked) { $flags += 'locked' }
        if ($w.Prunable) { $flags += 'prunable' }
        $branch = if ($w.Branch) { $w.Branch } else { '?' }
        $flagText = if ($flags) { "  [$($flags -join ', ')]" } else { '' }
        # The column after the route is the ARGUMENT -Name takes, or '-'. It is never the branch, which
        # can differ from the directory, so `-Name <branch>` would reach a different worktree.
        $arg = if ($leafName) { $leafName } else { '-' }
        Write-Host ("{0,-8} {1,-11} {2,-24} {3,-30} {4}{5}" -f $class, $how, $arg, $branch, $w.Path, $flagText)
    }
    Write-Host "Columns: class, route(s), -Name argument ('-' for none), branch, path."
    Write-Host ("sibling {0}, managed {1}, other {2}. -Name reaches {3} of {4} and -Path reaches {5}." -f
        $counts.sibling, $counts.managed, $counts.other, $byNameCount, $linked.Count, $byPathCount)
    Write-Host ("A 'managed' row is under .claude/worktrees. -Path never removes one; the header of this " +
        "script says why.")
    return
}

if ($byPath) {
    # A COMPONENT ENDING IN A DOT OR A SPACE NAMES A DIFFERENT DIRECTORY: Windows drops both, and
    # GetFullPath, Test-Path and git all follow it.
    $parts = @($Path -split '[\\/]' | Where-Object { $_ -and $_ -ne '.' -and $_ -ne '..' })
    if (@($parts | Where-Object { $_ -match '[. ]\z' }).Count -gt 0) {
        throw ("A path component ends in a dot or a space, which Windows drops, so it would name a " +
            "different directory. Nothing was removed.")
    }
    $WorktreePath = [System.IO.Path]::GetFullPath($Path, $PWD.ProviderPath).TrimEnd('\', '/')
    if (-not (Test-Path -LiteralPath $WorktreePath)) { throw "No such worktree: $WorktreePath" }

    $there = ConvertTo-Norm $WorktreePath
    if ($there -eq (ConvertTo-Norm $PrimaryRoot)) {
        throw "'$WorktreePath' is the primary checkout. This script never removes it. Nothing was removed."
    }
    # EXACT full-path equality against git's own list, and exactly one hit. A junction, subst or 8.3
    # spelling of a real worktree is a different string, so it is refused here rather than followed.
    $entry = @($linked | Where-Object { (ConvertTo-Norm $_.Path) -eq $there })
    if ($entry.Count -ne 1) {
        Write-Host "REFUSED: '$WorktreePath' is not a registered linked worktree of $PrimaryRoot." -ForegroundColor Red
        Write-Host "List them with:  scripts\worktree\remove.ps1 -List" -ForegroundColor Red
        throw "Not a registered worktree. Nothing was removed."
    }
    $entry = $entry[0]

    $here = ConvertTo-Norm $PWD.ProviderPath
    if ($here -eq $there -or $here.StartsWith("$there/")) {
        throw "You are standing inside '$WorktreePath'. Run this from another checkout. Nothing was removed."
    }
    # The copy being run would be deleted part-way through its own run. The gate names the PRIMARY's
    # copy for this reason.
    $scriptDir = ConvertTo-Norm $PSScriptRoot
    if ($scriptDir -eq $there -or $scriptDir.StartsWith("$there/")) {
        throw ("This copy of remove.ps1 lives inside '$WorktreePath'. Run the copy in the primary " +
            "checkout ($PrimaryRoot). Nothing was removed.")
    }

    # NOT REACHED, ON PURPOSE (BACKLOG #1038, Manager decision batch 184). The occupancy fence below
    # reads the directory a session was LAUNCHED in. A subagent under `isolation: worktree` is
    # recorded under its parent's directory (measured: 0 occupants for a live subagent's tree), and
    # its tree is one of these. A fence that fails open on a population is worse than no route to it.
    if ($there -match $managedSegment) {
        Write-Host "REFUSED: '$WorktreePath' is under .claude/worktrees, where the Claude Code harness puts its worktrees." -ForegroundColor Red
        Write-Host ("-Path never removes one: a subagent's tree there is recorded under its parent's directory, " +
            "so the occupancy check would read it as empty.") -ForegroundColor Red
        Write-Host ("If new.ps1 made it as a sibling of a linked worktree, the copy of remove.ps1 in THAT " +
            "worktree removes it by -Name. Otherwise removing it is the user's decision.") -ForegroundColor Red
        throw "Target is under .claude/worktrees. Nothing was removed."
    }

    # A worktree nested inside the target goes with it and stays registered with no directory. Remove
    # the nested ones first, deepest first. Not overridable: -Force means "discard changes", nothing else.
    $nestedTrees = @(Get-NestedWorktrees -Occupancy ([pscustomobject]@{ Worktrees = $registered }) -Path $WorktreePath)
    if ($nestedTrees.Count -gt 0) {
        Write-Host "REFUSED: '$WorktreePath' contains $($nestedTrees.Count) other registered worktree(s):" -ForegroundColor Red
        $nestedTrees | ForEach-Object { Write-Host "  $($_.Path)" -ForegroundColor Red }
        throw "Target contains another registered worktree. Remove those first. Nothing was removed."
    }

    # `locked` is git's own occupancy flag. A single --force would fail on it anyway; saying so here
    # names the reason instead of an exit code.
    if ($entry.Locked) {
        $lockWhy = if ($entry.LockReason) { " ($($entry.LockReason))" } else { '' }
        throw "'$WorktreePath' is locked$lockWhy. That is git's own in-use flag. Nothing was removed."
    }
}
else {
    $WorktreePath = Join-Path $Parent "$RepoName-$Name"
    if (-not (Test-Path $WorktreePath)) { throw "No such worktree: $WorktreePath" }
}

# Every git call that is not aimed at the target itself. On -Path it is the primary, so nothing here
# stands in a checkout that is about to go.
$GitRoot = if ($byPath) { $PrimaryRoot } else { $RepoRoot }

# A DETACHED HEAD WHOSE COMMIT NO REF HOLDS is lost with the worktree: removal deletes the HEAD reflog
# too, so nothing reaches it afterwards. -Force does not override it -- -Force means
# "discard changes", nothing else. The shape is the vault remove.ps1's (vault PR 2125). Refs are read
# with --glob=refs/*, not --all, which would add this worktree's own HEAD and so never find anything
# at risk.
& git -C $WorktreePath symbolic-ref -q HEAD *> $null
if ($LASTEXITCODE -ne 0) {
    $head = "$(& git -C $WorktreePath rev-parse --verify --quiet HEAD 2>$null)".Trim()
    if ($LASTEXITCODE -ne 0 -or -not $head) {
        throw "Could not read the detached HEAD of '$WorktreePath'. Nothing was removed."
    }
    $unheld = "$(& git -C $GitRoot rev-list --count $head --not @transientRefExcludes --glob=refs/* 2>$null)".Trim()
    if ($LASTEXITCODE -ne 0 -or $unheld -notmatch '^\d+$') {
        throw "Could not tell whether the detached HEAD $head is held by a ref. Nothing was removed."
    }
    if ([int]$unheld -gt 0) {
        Write-Host "Keep them first, for example:  git -C `"$GitRoot`" branch <name> $head" -ForegroundColor Red
        throw ("'$WorktreePath' is detached at $head, and $unheld commit(s) there are held by no ref. " +
               "Removing it would leave them in no ref and no reflog. Nothing was removed.")
    }
}

if ($byPath) {
    # THE HEAD REFLOG GOES WITH THE WORKTREE, and the check above reads only the commit HEAD is on now.
    # A commit made on a detached HEAD before switching back to a branch is held by that reflog alone.
    # The vault copy documents this as a gap; this route refuses it, because it reaches checkouts the
    # caller did not make. -Force does not override it. A commit a branch's own reflog still holds,
    # an amended one for example, is counted here too: this cannot tell the two apart, so it refuses.
    $logTips = @(& git -C $WorktreePath reflog show --format=%H HEAD 2>$null |
            Where-Object { $_ -match '\A[0-9a-f]{40,64}\z' })
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read the HEAD reflog of '$WorktreePath' (exit $LASTEXITCODE). Nothing was removed."
    }
    # THE TREE'S OWN PER-WORKTREE REFS GO WITH IT TOO. refs/worktree/*, refs/bisect/* and
    # refs/rewritten/* live in this worktree's admin directory, and the primary's `--glob=refs/*` below
    # reads the PRIMARY's copies of those namespaces, never this tree's. So what they point at is
    # checked the same way as the reflog. Read from INSIDE the target, which is the only place they
    # resolve.
    $ownRefTips = @(& git -C $WorktreePath for-each-ref '--format=%(objectname)' refs/worktree/ refs/bisect/ refs/rewritten/ 2>$null |
            Where-Object { $_ -match '\A[0-9a-f]{40,64}\z' })
    if ($LASTEXITCODE -ne 0) {
        throw "Could not read the per-worktree refs of '$WorktreePath' (exit $LASTEXITCODE). Nothing was removed."
    }
    $logTips = @(@($logTips) + @($ownRefTips) | Sort-Object -Unique)
    # The tips ride on one command line, which has a length limit. Past it, refuse rather than sample.
    if ($logTips.Count -gt 400) {
        throw ("The HEAD reflog and per-worktree refs of '$WorktreePath' name $($logTips.Count) commits, " +
            "more than this route checks. Nothing was removed.")
    }
    if ($logTips.Count -gt 0) {
        $looseCommits = @(& git -C $GitRoot rev-list @logTips --not @transientRefExcludes --glob=refs/* 2>$null)
        if ($LASTEXITCODE -ne 0) {
            throw ("Could not tell whether a ref holds the commits in the HEAD reflog and per-worktree " +
                "refs of '$WorktreePath'. Nothing was removed.")
        }
        if ($looseCommits.Count -gt 0) {
            Write-Host ("REFUSED: the HEAD reflog or a per-worktree ref of '$WorktreePath' holds " +
                "$($looseCommits.Count) commit(s) that no shared ref holds:") -ForegroundColor Red
            $looseCommits | Select-Object -First 5 | ForEach-Object { Write-Host "  $_" -ForegroundColor Red }
            Write-Host "Keep one with:  git -C `"$GitRoot`" branch <name> <commit>" -ForegroundColor Red
            throw "Removing it would delete that reflog and leave those commits in no ref. Nothing was removed."
        }
    }

    # The occupancy fence. The registry is found under $env:USERPROFILE, which is how the tests point
    # it at a fixture.
    #
    # UNREADABLE REFUSES; READABLE AND EMPTY CLEARS (Manager decision, batch 184, ported from the
    # vault copy). occupancy.ps1 reports Available false in both cases. An unreadable registry,
    # meaning no registry at all, a record that cannot be placed, or an enumeration that failed, could
    # hide a session in the target. A registry that was read and holds no record at all is what every
    # session exiting cleanly leaves, and nobody is recorded in the target.
    #
    # THE REGISTRY IS LISTED A SECOND TIME, INDEPENDENTLY, AND ON EVERY RUN. The enumeration beneath
    # the receipt lists with -ErrorAction SilentlyContinue, and Get-ClaudeConfigRoots drops a root
    # whose `sessions` Test-Path is false, which is also what access-denied returns. So a root it could
    # not read reads as a root with nothing in it. This listing walks every .claude* directory under
    # USERPROFILE with -ErrorAction Stop: any error refuses, and a different root count refuses,
    # because the two reads then disagree.
    $occ = Get-WorktreeOccupancy -Repo $PrimaryRoot
    $listedRoots = 0
    $listedRecords = 0
    $listingError = ''
    try {
        if (-not $env:USERPROFILE) { throw 'USERPROFILE is not set' }
        foreach ($d in @(Get-ChildItem -LiteralPath $env:USERPROFILE -Directory -Filter '.claude*' -Force -ErrorAction Stop)) {
            $kids = @(Get-ChildItem -LiteralPath $d.FullName -Force -ErrorAction Stop)
            if (-not ($kids | Where-Object { $_.PSIsContainer -and $_.Name -eq 'sessions' })) { continue }
            $listedRoots++
            $listedRecords += @(Get-ChildItem -LiteralPath (Join-Path $d.FullName 'sessions') -Filter *.json -File -Force -ErrorAction Stop).Count
        }
    }
    catch { $listingError = $_.Exception.Message }
    if ($listingError -or ($listedRoots -ne $occ.RootsExamined)) {
        $why = if ($listingError) { $listingError } else {
            "the receipt examined $($occ.RootsExamined) registry root(s) and a second listing found $listedRoots" }
        Write-Host "REFUSED: the session registry could not be listed consistently: $why." -ForegroundColor Red
        throw "Occupancy unknown. Nothing was removed."
    }
    # Readable and empty: both reads found no record in any root, and nothing failed to parse.
    $readableEmpty = (-not $occ.Available) -and $occ.RegistryRead -and $occ.RootsExamined -gt 0 -and
        $occ.RecordsUnplaceable -eq 0 -and $occ.RecordsExamined -eq 0 -and $listedRecords -eq 0
    if (-not $occ.Available -and -not $readableEmpty) {
        Write-Host ("REFUSED: the session registry could not clear '$WorktreePath': $($occ.Detail) " +
            "(roots $($occ.RootsExamined), records $($occ.RecordsExamined), unplaceable $($occ.RecordsUnplaceable)).") -ForegroundColor Red
        throw "Occupancy unknown. Nothing was removed."
    }
    $who = @(Get-WorktreeOccupants -Occupancy $occ -Path $WorktreePath -IncludeNested)
    if ($who.Count -gt 0) {
        Write-Host "REFUSED: $($who.Count) session(s) are recorded in '$WorktreePath':" -ForegroundColor Red
        $who | ForEach-Object { Write-Host "  $($_.State) $($_.Short) pid $($_.Pid) cwd $($_.Cwd)" -ForegroundColor Red }
        throw "Target is occupied. Nothing was removed."
    }

    # EVERYTHING GIT WOULD DELETE IS SHOWN, whatever status.showUntrackedFiles says: tracked changes,
    # untracked files and ignored files all refuse without -Force. A -Path target is often another
    # session's checkout, so nothing goes on a guess about what is disposable.
    #
    # THE ONE EXCEPTION is an IGNORED DIRECTORY with one of six names, which every tree that ran a
    # test or built an environment carries. Git prints an ignored directory as `!! <path>/`, so the
    # pattern needs both the `!!` and the trailing slash: an untracked directory of the same name is
    # `??` and refuses, and so does an ignored FILE of that name. Case-sensitive on purpose. A path git
    # had to quote ends in a quote, not a slash, and so refuses.
    $exemptIgnored = '\A!! (?:.*/)?(?:\.venv|node_modules|__pycache__|\.pytest_cache|\.mypy_cache|\.ruff_cache)/\z'
    $statusLines = @(& git -C $WorktreePath --no-optional-locks status --porcelain --ignored --untracked-files=normal 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "git status failed in '$WorktreePath' (exit $LASTEXITCODE), so its changes are unknown. Nothing was removed."
    }
    $pending = @($statusLines | Where-Object { $_ -and $_ -cnotmatch $exemptIgnored })
    # git status does not look at a file flagged skip-worktree (S) or assume-unchanged (lower case), so
    # an edit to one is invisible above. Count every flagged file as pending: nothing here can tell an
    # edited one from an untouched one without reading it.
    $flagged = @(& git -C $WorktreePath ls-files -v 2>$null | Where-Object { $_ -cmatch '^(S|[a-z]) ' })
    if ($LASTEXITCODE -ne 0) {
        throw "git ls-files failed in '$WorktreePath' (exit $LASTEXITCODE). Nothing was removed."
    }
    $pending += @($flagged | ForEach-Object { "flagged $($_.Substring(2))" })
    if ($pending.Count -gt 0 -and -not $Force) {
        $pending | Select-Object -First 20 | ForEach-Object { Write-Host $_ }
        if ($pending.Count -gt 20) { Write-Host "... and $($pending.Count - 20) more" }
        $what = 'uncommitted changes, untracked files, or ignored files outside the cache directories this route tolerates'
        if ($flagged.Count -gt 0) { $what += ', or files flagged skip-worktree or assume-unchanged' }
        throw ("Worktree has $what. Commit and push what matters. -Force discards the rest, and it is " +
            "the operator's switch. Nothing was removed.")
    }
}
else {
    # Guard against losing UNCOMMITTED tracked work. Note this does NOT see committed-but-unpushed
    # commits -- `status --porcelain` is empty for a clean worktree holding them; -DeleteBranch's own
    # containment check below is what covers those. Untracked entries (??) -- the .venv, node_modules,
    # dev db -- are expected and don't block removal.
    # The exit code is read BEFORE the filter: a git that cannot read this worktree (a corrupt index, say)
    # prints nothing, and nothing read as "no changes" here would hand `worktree remove --force` the very
    # edits this guard exists for. -Force does not override it (BACKLOG #1038).
    $status = @(& git -C $WorktreePath status --porcelain 2>$null)
    if ($LASTEXITCODE -ne 0) {
        throw "git status failed in '$WorktreePath' (exit $LASTEXITCODE), so its changes are unknown. Nothing was removed."
    }
    $tracked = $status | Where-Object { $_ -notmatch '^\?\?' }
    if ($tracked -and -not $Force) {
        Write-Host ($tracked -join "`n")
        throw "Worktree has uncommitted tracked changes. Commit/push them, or re-run with -Force."
    }
}

# --- BACKLOG #1293: refuse to strand a ledger number ---------------------------
#
# `Checker.owns` (scripts/hooks/ledger_check.py) decides ownership by CASEFOLDED PATH-STRING
# EQUALITY against the worktree recorded at allocation time. There is no fallback for a recorded
# worktree that no longer exists, so once this directory is gone `owns()` returns false for EVERY
# session, forever. The number is burned and any PR that must re-introduce its heading is
# unlandable by anybody. PR #397 was stranded exactly this way.
#
# THE GATE IS NOT WRONG AND THIS DOES NOT WIDEN IT. It fails closed and is behaving correctly; the
# defect is that there is no route back. Recovery for ALREADY-stranded numbers is an open route
# decision (three candidates, none obviously right -- see the item). PREVENTION needs no such
# decision, which is why it is here and the recovery is not.
#
# WHY IT REFUSES RATHER THAN WARNS. A claim can be released after the fact; an allocation CANNOT be
# re-keyed, because ownership is documented non-transferable. There is no post-hoc fix, so the only
# moment this can be stopped is before the removal.
#
# CANNOT-TELL COUNTS AS AT-RISK. An unreadable allocation record might name this worktree, and an
# unreadable ledger read might hide a heading. Both refuse.
$allocDirRoot = ''
$commonDirPre = "$(& git -C $GitRoot rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
if ($commonDirPre) { $allocDirRoot = Join-Path $commonDirPre 'mefor-coord/alloc' }

function Test-LedgerNumberOnMain([string]$Kind, [string]$Number) {
    <# $true on origin/main, $false absent, $null CANNOT TELL (which the caller treats as at-risk).

    `git show` on a missing path prints nothing and can exit 0 through a pipe, so EXISTENCE is
    probed with ls-tree and only then read -- the trap the fleet hit twice reading role playbooks. #>
    if ($Kind -eq 'adr') {
        $listed = & git -C $GitRoot ls-tree -r --name-only 'origin/main' 'docs/adr/' 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        $pad = $Number.PadLeft(4, '0')
        foreach ($n in @($listed)) { if ($n -match "/$pad-") { return $true } }
        return $false
    }
    # A BACKLOG NUMBER CANNOT BE ANSWERED FROM THIS REPOSITORY ANY MORE (BACKLOG #1250).
    # The ledger moved to the maintainer-internal repo, so there is nothing here to read.
    #
    # $null is this function's own CANNOT TELL, and the caller already treats it as at-risk.
    # $false would be worse than wrong: it asserts the number is ABSENT from main, which is a
    # claim no evidence in this clone supports, and it would let a worktree holding a live
    # backlog claim be removed quietly.
    return $null
}

if ($allocDirRoot -and (Test-Path -LiteralPath $allocDirRoot)) {
    . "$PSScriptRoot\..\coord\occupancy.ps1"
    # Both spellings git gives this worktree: the path as resolved here, and `rev-parse
    # --show-toplevel` run inside it, which is the one alloc.ps1 records and owns() compares against.
    $allocOwners = @{ (ConvertTo-Norm $WorktreePath) = $true }
    $allocTop = "$(& git -C $WorktreePath rev-parse --path-format=absolute --show-toplevel 2>$null)".Trim()
    if ($LASTEXITCODE -eq 0 -and $allocTop) { $allocOwners[(ConvertTo-Norm $allocTop)] = $true }
    $atRisk = @()
    $allocUnreadable = @()
    foreach ($f in @(Get-ChildItem -LiteralPath $allocDirRoot -Filter *.json -File -Recurse -EA SilentlyContinue | Sort-Object FullName)) {
        $a = $null
        try { $a = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
        catch { $allocUnreadable += $f.Name; continue }
        if (-not $allocOwners.ContainsKey((ConvertTo-Norm ([string]$a.worktree)))) { continue }
        $onMain = Test-LedgerNumberOnMain ([string]$a.kind) ([string]$a.number)
        if ($onMain -ne $true) {
            $why = if ($null -eq $onMain) { 'COULD NOT CHECK origin/main' } else { 'not on origin/main' }
            $atRisk += "$([string]$a.kind) #$([string]$a.number) -- $why -- $([string]$a.title)"
        }
    }
    if (($atRisk.Count -gt 0 -or $allocUnreadable.Count -gt 0) -and -not $AllowOrphanedAllocations) {
        $lines = @("This worktree OWNS ledger number(s) whose item is not yet on origin/main.", "")
        foreach ($r in $atRisk) { $lines += "  $r" }
        if ($allocUnreadable.Count -gt 0) {
            $lines += "  $($allocUnreadable.Count) allocation record(s) could not be parsed, and an unreadable"
            $lines += "  record MIGHT name this worktree: $($allocUnreadable -join ', ')"
        }
        $lines += ""
        $lines += "Removing it BURNS those numbers. Ownership is a path-string comparison against this"
        $lines += "directory and is NON-TRANSFERABLE, so once it is gone ledger_check.owns() returns"
        $lines += "false for every session forever and any PR that must re-introduce the heading is"
        $lines += "unlandable BY ANYONE. This is not recoverable after the fact."
        $lines += ""
        $lines += "Do this instead:"
        $lines += "  land the item(s) first, so the heading is on origin/main and ownership stops mattering;"
        $lines += "  or, if you accept burning them, re-run with -AllowOrphanedAllocations."
        throw ($lines -join "`n")
    }
}

# The branch is a FACT ABOUT THE WORKTREE, not a function of its directory name -- since new.ps1 gained
# -Branch the two can differ, and `branch -D $Name` would then delete the WRONG branch (or fail and
# print a misleading warning). Read it FIRST: `worktree remove` destroys the per-worktree admin dir, and
# with it that worktree's HEAD reflog. Same posture prune-merged.ps1 has always used -- it sources the
# branch from git, never from the path.
$branch = ""
$tip = ""
if ($DeleteBranch) {
    $branch = "$(& git -C $WorktreePath rev-parse --abbrev-ref HEAD 2>$null)".Trim()
    if (-not $branch -or $branch -eq "HEAD") {
        throw ("Cannot resolve the branch checked out in $WorktreePath (detached HEAD?). Re-run " +
               "without -DeleteBranch, then delete the branch by name yourself.")
    }
    $tip = "$(& git -C $RepoRoot rev-parse $branch 2>$null)".Trim()
}
# Read before the removal, only to say afterwards which branch was left alone.
$keptBranch = if ($byPath -and -not $entry.Detached) { [string]$entry.Branch } else { '' }

# -Name passes --force regardless: an untracked .venv makes git consider the worktree non-empty, and
# that route lets untracked files go.
# -Path WITHOUT -Force PASSES NO --force, so git makes its own check at the moment it deletes: it
# refuses a tree with modified or untracked files. That closes the gap between the status read above
# and the removal, for those two kinds. Git's check does not list ignored files, so the tolerated
# cache directories still go, and so would an ignored file written in that gap.
$removeArgs = @('worktree', 'remove')
if (-not $byPath -or $Force) { $removeArgs += '--force' }
& git -C $GitRoot @removeArgs $WorktreePath
if ($LASTEXITCODE -ne 0) {
    $code = $LASTEXITCODE
    if ($byPath) {
        # git drops the registration even when it cannot delete the whole tree, for example because
        # another process holds a file open there. Say so: the leftover is no longer a worktree, so
        # no route here can reach it again.
        $after = @(Get-RepoWorktrees $PrimaryRoot)
        if ($after.Count -gt 0 -and -not ($after | Where-Object { (ConvertTo-Norm $_.Path) -eq $there }) -and
            (Test-Path -LiteralPath $WorktreePath)) {
            Write-Host ("WARNING: git dropped the registration of '$WorktreePath' but could not delete all of it; " +
                "something may hold a file open there. What is left is no longer a worktree. Delete it by " +
                "hand once nothing uses it. Its claims were NOT released.") -ForegroundColor Yellow
        }
    }
    throw "git worktree remove failed (exit $code)"
}
# -Name only. `git worktree remove` already dropped the target's registration, and a blanket prune
# also drops OTHER worktrees' registrations, with the HEAD reflog each one holds. The -Name route
# keeps the prune it has always run; the -Path route, which is new, does not start one.
if (-not $byPath) { & git -C $RepoRoot worktree prune }

# --- BACKLOG #1295: release the claims this worktree held ---------------------
#
# `claim.ps1 -Release` is WORKTREE-SCOPED, so once the holder directory is gone NOBODY can release
# its keys normally and each one reads as actively-being-built forever. Measured 2026-08-19: 19 of
# 28 live claims were already orphaned exactly this way -- and THIS script, the sanctioned removal
# path, had no claim handling at all, so it was a source of them rather than a cure.
#
# AFTER THE REMOVAL, NEVER BEFORE. The removal is the event that orphans a claim. Releasing first
# and then failing to remove would hand a LIVE worktree's keys to another session, which is the
# duplicate build the registry exists to stop -- strictly worse than the orphan being fixed.
#
# MATCH ON THE FULL NORMALISED PATH AND NOTHING ELSE: no leaf name, no prefix, no StartsWith. Same
# rule Remove-ClaimsHeldBy states in prune-merged.ps1, for the same reason -- releasing a claim held
# by a DIFFERENT, living worktree is worse than the defect. `ConvertTo-Norm` is DOT-SOURCED rather
# than copied because it must agree with claim.ps1's writer; a fifth private copy of a path
# normaliser is exactly where that agreement breaks without anyone noticing.
#
# UNREADABLE IS NOT ABSENT. A claim file that will not parse MIGHT name this worktree, so it is
# reported and LEFT ALONE rather than deleted on a guess.
#
# REPORTS, NEVER THROWS. The worktree is already gone by this point; throwing here would report the
# whole removal as failed and invite a re-run of something that already succeeded.
try {
    . "$PSScriptRoot\..\coord\occupancy.ps1"
    $commonDir = "$(& git -C $GitRoot rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
    $claimsDir = if ($commonDir) { Join-Path $commonDir 'mefor-coord/claims' } else { '' }
    if ($claimsDir -and (Test-Path -LiteralPath $claimsDir)) {
        $target = ConvertTo-Norm $WorktreePath
        $released = @()
        $unreadable = @()
        foreach ($f in @(Get-ChildItem -LiteralPath $claimsDir -Filter *.json -File -EA SilentlyContinue | Sort-Object Name)) {
            $c = $null
            try { $c = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
            catch { $unreadable += $f.Name; continue }
            if ((ConvertTo-Norm ([string]$c.worktree)) -ne $target) { continue }
            try {
                Remove-Item -LiteralPath $f.FullName -Force -EA Stop
                $released += [string]$c.key
            }
            catch {
                Write-Warning ("claim '$([string]$c.key)' was held by the removed worktree and could NOT be " +
                               "released: $($_.Exception.Message). Release it yourself: " +
                               "claim.ps1 -Release $([string]$c.key) -Force")
            }
        }
        if ($released.Count -gt 0) {
            Write-Host "Released $($released.Count) claim(s) held by the removed worktree: $($released -join ', ')"
        }
        if ($unreadable.Count -gt 0) {
            Write-Warning ("$($unreadable.Count) claim file(s) could not be parsed and were LEFT IN PLACE " +
                           "($($unreadable -join ', ')). One of them may name the removed worktree; an " +
                           "unreadable claim is not an absent one, so it is not deleted on a guess.")
        }
    }
}
catch {
    Write-Warning ("could not sweep claims for the removed worktree: $($_.Exception.Message). Any claim it " +
                   "held is now orphaned -- `claim.ps1 -Release` is worktree-scoped, so use -Force to clear it.")
}

if ($DeleteBranch) {
    # LOSSLESS-DELETE DISCIPLINE, as defined by prune-merged.ps1's Remove-BranchSafely: `-d` first, and
    # `-D` only after re-verifying at THAT MOMENT that the branch has nothing beyond the main ref.
    # It matters here more than anywhere: the removal above already took the per-worktree HEAD reflog,
    # and `branch -D` takes the ref AND the branch reflog, so an unmerged force-delete leaves the
    # commits reachable from no ref and no reflog. The tip is printed either way, so scrollback is the undo.
    Write-Host "Branch '$branch' is at $tip. Recover a deleted branch with: git -C `"$RepoRoot`" branch <name> $tip"
    & git -C $RepoRoot branch -d $branch 2>$null | Out-Null
    if ($LASTEXITCODE -ne 0) {
        $unique = "$(& git -C $RepoRoot rev-list --count "origin/main..$branch" 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $unique) {
            Write-Warning ("could not re-verify '$branch' against origin/main, so the branch was KEPT. " +
                           "Delete it yourself once you are sure: git branch -D $branch")
        }
        elseif ([int]$unique -ne 0) {
            Write-Warning ("$unique commit(s) on '$branch' are not on origin/main, so the branch was KEPT " +
                           "(the worktree is gone; the branch still holds them). Delete it yourself once " +
                           "you are sure: git branch -D $branch")
        }
        else {
            & git -C $RepoRoot branch -D $branch
            if ($LASTEXITCODE -ne 0) { Write-Warning "could not delete branch '$branch'. Delete manually if intended." }
        }
    }
}

Write-Host "Removed worktree '$WorktreePath'." -ForegroundColor Green
if ($keptBranch) { Write-Host "Branch '$keptBranch' was not touched." }
