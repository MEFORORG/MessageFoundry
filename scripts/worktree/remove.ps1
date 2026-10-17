# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
# Windows PowerShell 5.1 has no two-argument GetFullPath and fails part-way with an error that names
# neither the cause nor the fix, and before pwsh 7.2 $ErrorActionPreference = "Stop" also turns a git
# warning on stderr into a terminating error, part-way through a removal. This stops both hosts
# before anything runs, with a message that does say why.
#Requires -Version 7.2
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
        the directory a session was launched in, never where it writes, so on its own it is blind
        to a subagent's tree. The refusals in the next list are the signals that are not;
      * every refusal in the next list, which -Name shares.

    WHAT BOTH REMOVAL ROUTES REFUSE, WHATEVER -Force SAYS (-Name since vault BACKLOG #2988):
      * a target that still holds a work claim (claim.ps1), or any target when a claim file cannot
        be read, parses to something other than one record, or names no worktree. The registry is
        found the way claim.ps1 finds it, mefor.claimsRoot included;
      * a target whose own git directory was written to in the last six hours: a commit, a checkout,
        a merge or a fetch. Nothing here can tell whether what did that has finished;
      * a target whose working tree was written to in the last six hours: its top directory, any
        entry directly under it, or anything in .pytest_cache or .ruff_cache. A worker that only
        reads files and runs tests leaves no git trace, but a FINISHED test run rewrites
        .pytest_cache (vault BACKLOG #2985, part B item 1). A run still in progress has written
        nothing there yet, so this does not see one.

    WHAT -Force OVERRIDES ON -Path: uncommitted tracked changes, untracked files, ignored files, and
    files flagged skip-worktree or assume-unchanged. Without -Force every one of those refuses, with
    ONE exception: an IGNORED directory named .venv, node_modules, __pycache__, .pytest_cache,
    .mypy_cache or .ruff_cache goes with the worktree. An UNTRACKED directory of those names refuses,
    and so does one that is a junction or a symlink.
    -Force is the operator's switch. A session runs -Path without it, and a refusal is final for a
    session: it reports what was refused and why, and stops.

    WHAT ONLY -AllowOrphanedAllocations OVERRIDES, on both removal routes: a target that owns a
    ledger number (alloc.ps1) whose item is not on origin/main, or an allocation record that cannot
    be read. It is the operator's switch too.

    WHAT -Path DOES NOT READ. A commit that only a branch's own reflog holds is untouched, because
    the branch stays. Work a session wrote into the target by absolute path from another directory
    is seen only if it left the tree dirty, or wrote where the activity signal below reads.

    -Name KEEPS ITS OLD RULES OTHERWISE. Of the -Path-only refusals it shares only the detached HEAD
    one: tracked changes refuse without -Force, untracked files go with the worktree, there is no
    occupancy check, and it runs `git worktree prune` afterwards. -Path runs no blanket prune,
    because that also drops OTHER worktrees' registrations.

    NEITHER ROUTE RELEASES A CLAIM. The work has to land, or the claim be released with
    claim.ps1 -Release, which records the release in the claims .history file, first. Both routes
    refuse a claimed tree, so after a removal no claim should name it. One taken in the moment between the check and the removal is reported, never deleted:
    claim.ps1 -Release -Force is the release that leaves a record.

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
    # Position 0, and -RepoRoot position 1, are what this script bound before it had parameter sets:
    # `remove.ps1 alerts` must keep working.
    [Parameter(Mandatory = $true, Position = 0, ParameterSetName = 'ByName')]
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
    [Parameter(Position = 1)]
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

# A path with a .claude/worktrees segment ANYWHERE in it, on a ConvertTo-Norm value. prune-merged.ps1
# excludes this population too, for the same reason; its own test needs a trailing slash and is asked
# only of the primary's siblings, so the two are not the same expression. This one is the wider.
$managedSegment = '/\.claude/worktrees(/|\z)'

$PrimaryRoot = ''
$registered = @()
$linked = @()
# Get-RepoWorktrees, ConvertTo-Norm, Get-NestedWorktrees and the occupancy fence. Every route uses
# ConvertTo-Norm, because it must agree with claim.ps1's writer.
. "$PSScriptRoot\..\coord\occupancy.ps1"
if ($byPath -or $listing) {
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
    # -Name's own pattern, read off the parameter rather than written out a fifth time.
    $namePattern = ($MyInvocation.MyCommand.Parameters['Name'].Attributes |
            Where-Object { $_ -is [System.Management.Automation.ValidatePatternAttribute] }).RegexPattern
    $counts = @{ sibling = 0; managed = 0; other = 0 }
    $byPathCount = 0
    foreach ($w in $linked) {
        $norm = ConvertTo-Norm $w.Path
        $leafName = ''
        # The no-further-slash test comes FIRST: only then is the leaf the whole remainder, and only
        # then is it long enough to cut. A tree below a sibling has a short leaf of its own.
        if ($norm.StartsWith($siblingPrefix) -and -not $norm.Substring($siblingPrefix.Length).Contains('/')) {
            $rest = (Split-Path $w.Path -Leaf).Substring($RepoName.Length + 1)
            if ($namePattern -and $rest -match $namePattern) { $leafName = $rest }
        }
        $isManaged = $norm -match $managedSegment
        $class = if ($leafName) { 'sibling' } elseif ($isManaged) { 'managed' } else { 'other' }
        $counts[$class]++
        $routes = @()
        if ($leafName) { $routes += '-Name' }
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
        $counts.sibling, $counts.managed, $counts.other, $counts.sibling, $linked.Count, $byPathCount)
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
    # A worktree registered INSIDE the target goes with it, and a harness tree under the target's own
    # .claude/worktrees is one: a session launched in the target puts its subagents there. Refused as
    # on -Path, and for the same reason not overridable.
    $nameRegistered = @(Get-RepoWorktrees $RepoRoot)
    if ($nameRegistered.Count -eq 0) {
        throw "Could not list the registered worktrees of '$RepoRoot'. Nothing was removed."
    }
    $nestedTrees = @(Get-NestedWorktrees -Occupancy ([pscustomobject]@{ Worktrees = $nameRegistered }) -Path $WorktreePath)
    if ($nestedTrees.Count -gt 0) {
        Write-Host "REFUSED: '$WorktreePath' contains $($nestedTrees.Count) other registered worktree(s):" -ForegroundColor Red
        $nestedTrees | ForEach-Object { Write-Host "  $($_.Path)" -ForegroundColor Red }
        throw "Target contains another registered worktree. Remove those first. Nothing was removed."
    }
}

# Every git call that is not aimed at the target itself. On -Path it is the primary, so nothing here
# stands in a checkout that is about to go.
$GitRoot = if ($byPath) { $PrimaryRoot } else { $RepoRoot }

# THE SPELLINGS A RECORD MAY NAME THIS WORKTREE BY, computed once and used by every check that
# matches a record to this tree: the claim refusal, the allocation guard, and the claim report after
# the removal. So no two of them can disagree about which tree this is. Both routes match the
# resolved path and `rev-parse --show-toplevel` run inside the tree, which is the spelling alloc.ps1
# and claim.ps1 record. It has to be read now: after the removal there is no tree to ask.
# A JUNCTION ALIAS OF THE TREE IS NOT MATCHED (vault BACKLOG #2985, part B item 2): claim.ps1 records
# the toplevel git prints, so no route found writes one.
# MATCH ON THE FULL NORMALISED PATH AND NOTHING ELSE: no leaf name, no prefix, no StartsWith. A record
# of a DIFFERENT, living worktree must never be taken for this one.
$ownTop = "$(& git -C $WorktreePath rev-parse --path-format=absolute --show-toplevel 2>$null)".Trim()
if ($LASTEXITCODE -ne 0) { $ownTop = '' }
$targetNorms = @(@($WorktreePath, $ownTop) | Where-Object { $_ } | ForEach-Object { ConvertTo-Norm $_ } | Sort-Object -Unique)

# Test-Path answers $false for a path it may not read, so access-denied would read as "absent" and an
# unreadable claims directory as "no claims" (vault BACKLOG #2985, item 15). This answers $false only
# for a path that is not there, and throws for anything else.
function Test-PresentOrThrow([string]$LiteralPath, [string]$What) {
    try {
        $null = Get-Item -LiteralPath $LiteralPath -Force -ErrorAction Stop
        return $true
    }
    catch [System.Management.Automation.ItemNotFoundException] { return $false }
    catch { throw "Could not tell whether $What exists ($($_.Exception.Message)). Nothing was removed." }
}

# THE SAME TRAP ONE LEVEL DOWN. `Get-ChildItem -ErrorAction Stop` on a directory this user may not
# LIST returns nothing and does not throw (measured on pwsh 7, a directory denied list rights), so an
# unlistable claims directory read as "no claims". This enumerates through .NET, which throws, and
# turns that into a refusal. Every entry is listed, a link included, but a recursive walk never
# descends into a linked directory, so it never leaves the tree. Hidden and system entries are kept,
# which .NET's own default would drop. -Max stops the walk one entry past it, so a cap bounds the work
# and not only the answer. The enumerable is walked by foreach directly: assigning it to a variable
# through an `if` would make PowerShell read it all first.
function Get-EntriesOrThrow([string]$Dir, [string]$What, [string]$Filter = '*', [switch]$Recurse, [switch]$FilesOnly,
    [int]$Max = [int]::MaxValue) {
    $opts = [System.IO.EnumerationOptions]::new()
    $opts.IgnoreInaccessible = $false
    $opts.AttributesToSkip = [System.IO.FileAttributes]0
    $found = [System.Collections.Generic.List[System.IO.FileSystemInfo]]::new()
    $pending = [System.Collections.Generic.Stack[string]]::new()
    $pending.Push($Dir)
    try {
        while ($pending.Count -gt 0 -and $found.Count -le $Max) {
            $here = $pending.Pop()
            foreach ($e in [System.IO.DirectoryInfo]::new($here).EnumerateFileSystemInfos('*', $opts)) {
                $isDir = $e -is [System.IO.DirectoryInfo]
                if ($Recurse -and $isDir -and -not ($e.Attributes -band [System.IO.FileAttributes]::ReparsePoint)) {
                    $pending.Push($e.FullName)
                }
                if ($FilesOnly -and $isDir) { continue }
                if ($Filter -ne '*' -and $e.Name -notlike $Filter) { continue }
                $found.Add($e)
                if ($found.Count -gt $Max) { break }
            }
        }
    }
    catch { throw "Could not list $What under '$Dir' ($($_.Exception.Message)), so $What are unknown. Nothing was removed." }
    return $found.ToArray()
}

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
    # USERPROFILE through Get-EntriesOrThrow: any error refuses, and a different root count refuses,
    # because the two reads then disagree. NOT Get-ChildItem -ErrorAction Stop, which lists a
    # directory this user may not read as empty and does not throw (vault BACKLOG #2985, item 15).
    $occ = Get-WorktreeOccupancy -Repo $PrimaryRoot
    $listedRoots = 0
    $listedRecords = 0
    $listingError = ''
    try {
        if (-not $env:USERPROFILE) { throw 'USERPROFILE is not set' }
        $homes = Get-EntriesOrThrow $env:USERPROFILE 'config roots' '.claude*'
        foreach ($d in @($homes | Where-Object { $_ -is [System.IO.DirectoryInfo] })) {
            $kids = Get-EntriesOrThrow $d.FullName 'registry entries'
            if (-not ($kids | Where-Object { $_ -is [System.IO.DirectoryInfo] -and $_.Name -eq 'sessions' })) { continue }
            $listedRoots++
            $listedRecords += @(Get-EntriesOrThrow (Join-Path $d.FullName 'sessions') 'session records' '*.json' -FilesOnly).Count
        }
    }
    # Never empty, so an exception with no message cannot read as a clean listing.
    catch { $listingError = "the second listing failed: $($_.Exception.Message)" }
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
}

# --- IN-USE SIGNALS THAT DO NOT DEPEND ON WHERE A SESSION WAS LAUNCHED, ON BOTH ROUTES -------------
#
# THE -Path FENCE ABOVE IS BLIND TO MOST OF WHAT THIS SCRIPT REACHES, and that was measured, not
# feared. It reads the directory a session was LAUNCHED in. A subagent Builder is recorded under its
# parent's directory, and so is any session that works in a tree by absolute path. Read off this
# machine's live registry on 2026-10-05: of 18 live records, 17 sat under .claude/worktrees and 1
# in the primary. NONE sat in any of the 158 trees -Path reaches, while nine sibling trees of a
# running batch held 14 claims and fresh git state. With the fence alone, six of those nine
# would have been removed under their Builders. (Found by the Lander's review of PR 2014.)
#
# -Name HAD NONE OF THESE (vault BACKLOG #2988). A session can run it, and a sibling that held a
# claim and untracked work was removed with exit 0. So the signals below run on both routes. Neither
# is overridable by -Force, which means "discard changes" and nothing else. An operator who must
# remove such a tree now uses git from a plain terminal.
#
# SIGNAL ONE: A WORK CLAIM. claim.ps1 records the worktree that took a key, whoever launched the
# session. A tree that still holds a claim is work in flight: a Builder's claim on built work
# stays until the Lander releases it at landing.
# CANNOT-TELL REFUSES: a claim file that will not parse might name this tree.
#
# THE REGISTRY IS FOUND THE WAY claim.ps1 FINDS IT (vault BACKLOG #2985, part B item 3). claim.ps1
# reads mefor.claimsRoot in the tree that holds the claim, which for a claim naming this target is
# the target, and follows it ONE hop to that repository's common dir. Reading only this clone's
# own registry would be blind to every claim once the setting is made. The clone's own registry is
# read AS WELL: a claim taken before the setting was made, or by an older claim.ps1, is there.
function Get-TargetClaimsDirs {
    $setting = "$(& git -C $WorktreePath config --get mefor.claimsRoot 2>$null)".Trim()
    # Exit 1 is "not set". Anything else is a config git could not read, which could hide the key.
    $code = $LASTEXITCODE
    if ($code -ne 0 -and $code -ne 1) {
        throw "git could not read mefor.claimsRoot in '$WorktreePath' (exit $code), so claims are unknown. Nothing was removed."
    }
    $own = "$(& git -C $WorktreePath rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
    if ($LASTEXITCODE -ne 0 -or -not $own) {
        throw "git could not name the common git dir of '$WorktreePath', so claims are unknown. Nothing was removed."
    }
    $dirs = @(Join-Path $own 'mefor-coord/claims')
    if ($code -eq 0 -and $setting) {
        # claim.ps1 hands the value to git as it stands, so a relative one resolves against the
        # caller's shell. Nothing here can tell which shell that was.
        if (-not [System.IO.Path]::IsPathFullyQualified($setting)) {
            throw ("mefor.claimsRoot in '$WorktreePath' is the relative path '$setting', which claim.ps1 resolves " +
                "against its caller's directory. Claims are unknown. Nothing was removed.")
        }
        $rootTop = "$(& git -C $setting rev-parse --path-format=absolute --show-toplevel 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $rootTop) {
            throw ("mefor.claimsRoot in '$WorktreePath' names '$setting', which is not a git repository, so " +
                "claims are unknown. Nothing was removed.")
        }
        $common = "$(& git -C $rootTop rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $common) {
            throw "git could not name the common git dir of '$rootTop', so claims are unknown. Nothing was removed."
        }
        $dirs += Join-Path $common 'mefor-coord/claims'
    }
    return @($dirs | Sort-Object -Unique { ConvertTo-Norm $_ })
}

# Every claim file in every registry this target's claims can be in, or none.
function Read-TargetClaims {
    foreach ($d in $claimsDirs) {
        if (Test-PresentOrThrow $d 'the claims directory') { Read-ClaimFiles $d }
    }
}

# One claim or allocation record file: Record is the parsed object, Holder the normalised worktree it
# names, or '' with Problem saying why it cannot be matched. ONE record per file, with a non-blank
# string worktree, is the only shape claim.ps1 and alloc.ps1 write; any other shape might hide this
# tree, so it is a cannot-tell (vault BACKLOG #2985, item 16).
function Read-RecordFile([System.IO.FileSystemInfo]$File) {
    $c = $null
    $problem = ''
    try { $c = Get-Content -LiteralPath $File.FullName -Raw -ErrorAction Stop | ConvertFrom-Json -NoEnumerate -ErrorAction Stop }
    catch { $problem = 'does not parse' }
    if (-not $problem) {
        if ($c -isnot [System.Management.Automation.PSCustomObject]) { $problem = 'is not one JSON object' }
        elseif ($c.worktree -isnot [string] -or [string]::IsNullOrWhiteSpace($c.worktree)) { $problem = 'names no worktree' }
    }
    if ($problem) { return [pscustomobject]@{ Name = $File.Name; Record = $null; Holder = ''; Problem = $problem } }
    [pscustomobject]@{ Name = $File.Name; Record = $c; Holder = (ConvertTo-Norm $c.worktree); Problem = '' }
}

function Read-ClaimFiles([string]$Dir) {
    foreach ($f in @(Get-EntriesOrThrow $Dir 'claims' '*.json' -FilesOnly | Sort-Object Name)) {
        $r = Read-RecordFile $f
        $r | Add-Member -NotePropertyName Key -NotePropertyValue $(if ($r.Record) { [string]$r.Record.key } else { '' }) -PassThru
    }
}

$claimsDirs = @(Get-TargetClaimsDirs)
$claimFiles = @(Read-TargetClaims)
if ($claimFiles.Count -gt 0) {
    $heldKeys = @($claimFiles | Where-Object { $_.Holder -and $targetNorms -contains $_.Holder } | ForEach-Object { $_.Key })
    $claimsUnreadable = @($claimFiles | Where-Object { $_.Problem })
    if ($heldKeys.Count -gt 0 -or $claimsUnreadable.Count -gt 0) {
        if ($heldKeys.Count -gt 0) {
            Write-Host ("REFUSED: '$WorktreePath' still holds $($heldKeys.Count) work claim(s): " +
                "$($heldKeys -join ', ').") -ForegroundColor Red
            Write-Host ("A held claim means the work is in flight or has not landed. It is released from " +
                "that worktree with claim.ps1 -Release, or by the Lander when the work lands.") -ForegroundColor Red
        }
        foreach ($u in $claimsUnreadable) {
            Write-Host "REFUSED: claim file $($u.Name) $($u.Problem), so it might name this worktree." -ForegroundColor Red
        }
        throw "Target still holds a work claim, or a claim file could not be matched. Nothing was removed."
    }
}

# SIGNAL TWO: RECENT ACTIVITY. Six hours is a judgement, not a measurement: long enough to cover a
# Builder between its last commit and the end of its checks, short enough that yesterday's trees are
# reachable. A clock that makes the newest write look like the future reads as recent, and refuses.
#
# IN THE TREE'S OWN GIT DIRECTORY: every commit, checkout, merge and fetch rewrites a file there. The
# index is left out on purpose: a read-only `git status` can rewrite it, and a staged change leaves
# the tree dirty anyway. Also left out: `gitdir` and `commondir`. They are pointers, not activity, and
# git's own source rewrites the `gitdir` pointer when a linked tree older than a day is merely
# opened. The checks above open this tree, so counting that file would make every old tree look
# written-to just now. git 2.55.0.windows.5 was not seen to do it; another version may.
$quietHours = 6
$ownGitDir = "$(& git -C $WorktreePath rev-parse --absolute-git-dir 2>$null)".Trim()
if ($LASTEXITCODE -ne 0 -or -not $ownGitDir) {
    throw "Could not find the git directory of '$WorktreePath', so its last activity is unknown. Nothing was removed."
}
$stateFiles = @(Get-EntriesOrThrow $ownGitDir 'git state files' -FilesOnly |
        Where-Object { $_.Name -notlike 'index*' -and $_.Name -notin @('gitdir', 'commondir') })
$headLog = Join-Path $ownGitDir 'logs/HEAD'
if (Test-PresentOrThrow $headLog 'the HEAD reflog') { $stateFiles += Get-Item -LiteralPath $headLog -Force -ErrorAction Stop }
if ($stateFiles.Count -eq 0) {
    throw "The git directory of '$WorktreePath' holds no state file to date. Nothing was removed."
}

# IN THE WORKING TREE (vault BACKLOG #2985, part B item 1). A worker whose claim names a DIFFERENT
# tree, in a reused tree, that has only read files and run tests leaves no git trace at all. What it
# does leave: pytest rewrites .pytest_cache on every run, and anything created or deleted directly
# under the root changes the root's own write time. So the root, every entry directly under it, and
# everything in the two small caches are read. The worktree's `.git` file is a pointer, like `gitdir`.
# A cache too big to read to the end cannot be dated, so it refuses rather than samples.
$treeCacheCap = 5000
$treeFiles = @(Get-Item -LiteralPath $WorktreePath -Force -ErrorAction Stop)
$treeFiles += @(Get-EntriesOrThrow $WorktreePath 'working-tree entries' | Where-Object { $_.Name -ne '.git' })
foreach ($cacheName in @('.pytest_cache', '.ruff_cache')) {
    $cache = $treeFiles | Where-Object { $_.Name -eq $cacheName -and $_ -is [System.IO.DirectoryInfo] -and
        -not ($_.Attributes -band [System.IO.FileAttributes]::ReparsePoint) } | Select-Object -First 1
    if (-not $cache) { continue }
    $inCache = @(Get-EntriesOrThrow $cache.FullName 'cache entries' -Recurse -Max $treeCacheCap)
    if ($inCache.Count -gt $treeCacheCap) {
        throw ("'$($cache.FullName)' holds more than $treeCacheCap entries, more than this script dates, so the " +
            "tree's last activity is unknown. Nothing was removed.")
    }
    $treeFiles += $inCache
}

foreach ($signal in @(
        @{ Files = $stateFiles; Where = 'git last wrote to'; What = 'Something committed, checked out or fetched there recently' },
        @{ Files = $treeFiles; Where = 'a file was last written in the working tree of'; What = 'Something wrote files there recently, a test run for one' })) {
    $newest = $null
    foreach ($f in $signal.Files) { if (-not $newest -or $f.LastWriteTimeUtc -gt $newest.LastWriteTimeUtc) { $newest = $f } }
    $quietFor = [DateTime]::UtcNow - $newest.LastWriteTimeUtc
    if ($quietFor.TotalHours -lt $quietHours) {
        Write-Host ("REFUSED: $($signal.Where) '$WorktreePath' $([int][Math]::Max(0, $quietFor.TotalMinutes)) " +
            "minute(s) ago ($($newest.Name)), inside the $quietHours-hour quiet period.") -ForegroundColor Red
        Write-Host ("$($signal.What), and no check here can tell whether it has finished.") -ForegroundColor Red
        throw "Target was active recently. Nothing was removed."
    }
}

if ($byPath) {
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
    # A TOLERATED NAME IS NOT ENOUGH: THE DIRECTORY MUST BE A REAL ONE, INSIDE THE TREE. A junction or
    # symlink named `node_modules` points at a directory somewhere else, so it is not this tree's
    # cache to throw away. A tolerated directory that is a reparse point, or that cannot be read,
    # goes back on the pending list. This reads the named directory only, not what is inside it.
    # MEASURED on git 2.55.0.windows.5, and recorded so the reason is not overstated: git does NOT
    # delete through a junction. In four cases the outside content survived. What git does do is
    # drop the registration, exit 0 and leave the directory behind, which this guard prevents for a
    # top-level junction. A junction INSIDE a tolerated directory still ends that way; the script
    # then reports the leftover and exits 1, after the removal.
    foreach ($line in @($statusLines | Where-Object { $_ -cmatch $exemptIgnored })) {
        $rel = $line.Substring(3).TrimEnd('/')
        $isRealDirectory = $false
        try {
            $item = Get-Item -LiteralPath (Join-Path $WorktreePath $rel) -Force -ErrorAction Stop
            $isRealDirectory = $item.PSIsContainer -and
                -not ($item.Attributes -band [System.IO.FileAttributes]::ReparsePoint)
        }
        catch { $isRealDirectory = $false }
        if (-not $isRealDirectory) { $pending += "$line  (a link, or unreadable: not a plain directory)" }
    }
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
#
# BOTH ROUTES FAIL CLOSED on a common dir git cannot name and on an alloc directory that cannot be
# listed. -Name used to read both as "no records found" (vault BACKLOG #2985, item 11, and #2988).
$commonDirPre = "$(& git -C $GitRoot rev-parse --path-format=absolute --git-common-dir 2>$null)".Trim()
if ($LASTEXITCODE -ne 0 -or -not $commonDirPre) {
    throw "git could not name the common git dir of '$GitRoot', so allocations are unknown. Nothing was removed."
}
$allocDirRoot = Join-Path $commonDirPre 'mefor-coord/alloc'

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

if (Test-PresentOrThrow $allocDirRoot 'the allocation directory') {
    $atRisk = @()
    $allocUnreadable = @()
    foreach ($f in @(Get-EntriesOrThrow $allocDirRoot 'allocations' '*.json' -Recurse -FilesOnly | Sort-Object FullName)) {
        $r = Read-RecordFile $f
        if ($r.Problem) { $allocUnreadable += "$($f.Name) ($($r.Problem))"; continue }
        if ($targetNorms -notcontains $r.Holder) { continue }
        $a = $r.Record
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
            $lines += "  $($allocUnreadable.Count) allocation record(s) could not be matched, and an unreadable"
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
$removeCode = $LASTEXITCODE
# git can drop the registration and leave files behind, on either exit code. On a failure, because
# another process holds a file open and git had already deleted the rest and dropped the
# registration (vault BACKLOG #2985, item 19): that order is git's own, and nothing here can make it
# atomic. On exit 0, when a junction inside the tree stops the delete (item 8, measured on git
# 2.55.0.windows.5 with one inside node_modules; nothing outside the tree was deleted). Either way
# the leftover is no longer a worktree, so no route here can reach it again, and the run says so
# rather than reporting a clean removal.
# Not Test-Path, which reads a directory it may not see as gone.
try { $leftover = Test-PresentOrThrow $WorktreePath 'the removed directory' } catch { $leftover = $true }
if ($removeCode -ne 0) {
    $after = @(Get-RepoWorktrees $GitRoot)
    if ($leftover -and $after.Count -gt 0 -and -not ($after | Where-Object { $targetNorms -contains (ConvertTo-Norm $_.Path) })) {
        Write-Host ("WARNING: git dropped the registration of '$WorktreePath' but could not delete all of it; " +
            "something may hold a file open there. What is left is no longer a worktree. Delete it by " +
            "hand once nothing uses it.") -ForegroundColor Yellow
    }
    throw "git worktree remove failed (exit $removeCode)"
}
# -Name only. `git worktree remove` already dropped the target's registration, and a blanket prune
# also drops OTHER worktrees' registrations, with the HEAD reflog each one holds. The -Name route
# keeps the prune it has always run; the -Path route, which is new, does not start one.
if (-not $byPath) { & git -C $RepoRoot worktree prune }

# --- A CLAIM TAKEN AFTER THE CHECK: reported, never released (vault BACKLOG #2988) -----------------
#
# Both routes refused any claim on this tree before the removal, so this finds one only if it was
# taken in the moment between that check and the removal. That is a LIVE session's claim, and its
# tree is now gone. Deleting the file here would release it with no line in the claims .history
# file, which is what this script used to do (BACKLOG #1295, #1068). So it is reported, and the
# release is left to claim.ps1 -Release -Force, which records who released whose claim.
#
# REPORTS, NEVER THROWS. The worktree is already gone by this point; throwing here would report the
# whole removal as failed and invite a re-run of something that already succeeded.
try {
    $late = @(Read-TargetClaims | Where-Object { $_.Problem -or ($targetNorms -contains $_.Holder) })
    foreach ($c in $late) {
        if ($c.Problem) {
            Write-Warning "claim file $($c.Name) $($c.Problem) and was left in place; it may name the removed worktree."
        }
        else {
            # Quoted, because a key is free text and a bare one with a space would not bind.
            $quotedKey = "'" + ($c.Key -replace "'", "''") + "'"
            Write-Warning ("claim $quotedKey was taken in the removed worktree after this run checked it. It was " +
                "left in place. Release it with: claim.ps1 -Release $quotedKey -Force")
        }
    }
}
catch {
    Write-Warning "could not re-read claims after the removal: $($_.Exception.Message)"
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

if ($leftover) {
    Write-Host ("WARNING: git dropped the registration of '$WorktreePath' and exited 0, but the directory is " +
        "still there. What is left is no longer a worktree; a junction inside it is one known cause. Look " +
        "at it, then delete it by hand.") -ForegroundColor Yellow
}
else { Write-Host "Removed worktree '$WorktreePath'." -ForegroundColor Green }
if ($keptBranch) {
    Write-Host "Branch '$keptBranch' was not touched."
    # Said out loud because the tree was the visible sign of this work: commits on no remote now
    # live on the local branch alone. A note, never a refusal, and never a reason to fail a removal
    # that has already happened.
    $localOnly = "$(& git -C $GitRoot rev-list --count "refs/heads/$keptBranch" --not --remotes 2>$null)".Trim()
    if ($LASTEXITCODE -eq 0 -and $localOnly -match '\A\d+\z' -and [int]$localOnly -gt 0) {
        Write-Host ("NOTE: $localOnly commit(s) on '$keptBranch' are on no remote-tracking ref, as of the last " +
            "fetch. They are kept on the local branch.")
    }
}
# Exit 1 rather than 0, so a caller does not read a half-done removal as a clean one.
if ($leftover) { exit 1 }
