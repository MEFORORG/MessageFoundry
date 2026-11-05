# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
#Requires -Version 7
<#
.SYNOPSIS
    Re-check, then remove, finished .claude/worktrees trees. Dot-source it; it defines one function.

.DESCRIPTION
    The body of run-daily-prune.ps1 -RemoveFinishedClaudeWorktrees, kept in its own file so the
    re-checks can be tested against trees prune-merged.ps1 would never list (a dirty one, a locked one)
    -- which is exactly the race these re-checks exist for: a tree that looked finished when the list
    was made and stopped looking finished before it was acted on.

    THIS STEP OVERRIDES BACKLOG #1038's DECLINE, ON THE OWNER'S EXPLICIT REQUEST OF 2026-11-05. #1038
    (Manager decision, batch 184) gave .claude/worktrees no scripted deletion route, because the liveness
    fence cannot see an `isolation: worktree` subagent and a route whose check fails open on a population
    is worse than none. The owner asked for this route anyway. What stands in for the fence on that
    population is listed under WHAT THESE DO NOT SEE below, with the residual it leaves.

    THIS HEADER IS THE ONE STATEMENT OF THE RE-CHECK LIST. docs/WORKTREES.md links here rather than
    restating it (SDS-3.5); change the list here.

    WHY THIS IS SEPARATE FROM prune-merged.ps1, WHICH STILL REMOVES NOTHING UNDER .claude/worktrees.
    That script's exclusion is deliberate: .claude/worktrees is where EnterWorktree relocates a LIVE
    session, and that tool once removed an occupied worktree with --force, deregistering it and then
    failing to delete the directory. This step takes the list prune-merged.ps1 already prints as
    "look finished" and acts on it only the way the owner did by hand on 2026-11-05 -- a plain
    `git worktree remove`, which git itself refuses on a locked tree or one holding a modified or
    untracked file -- and only after re-checking every gate again immediately before each removal.

    THE RE-CHECKS, per path. The first one that fails REFUSES that path and the run moves on; a refusal
    is data, not a failure. At least these:
      * -IdleHours is a finite number not under worktree-gates.ps1's floor, and this clone's
        coordination root resolves (both checked once, for every path);
      * the path has a `.claude/worktrees/` segment -- the only population this step is for;
      * it is not the primary checkout, not a worktree the caller runs from (-Protect), and does not
        contain one;
      * it is still a registered worktree of -Primary (a fresh `git worktree list --porcelain` that
        must read), and git does not report it locked or prunable;
      * no file in it is flagged skip-worktree or assume-unchanged, whose edits git status cannot see;
      * `git status --porcelain --untracked-files=all`, run with LC_ALL=C so its warning text is
        untranslated, exits 0, prints nothing, and warns of no folder it could not open;
      * its private git metadata, and its working tree (the top level, plus the files in .pytest_cache
        and .ruff_cache), are both idle beyond -IdleHours;
      * no rebase, am, cherry-pick, merge, revert or bisect is in progress in its own git dir;
      * every IGNORED entry git lists is a regenerable cache directory, by the list remove.ps1 -Path
        tolerates ($REGENERABLE_IGNORED_PATTERN in worktree-gates.ps1, which names them), and a plain
        directory, so a .env, a *.db store or a build output beside them refuses the tree;
      * a walk of the whole working tree, ignored directories included, finds no nested git checkout (an
        entry named .git), no link of any kind, and inside a cache directory no file named like data
        ($CACHE_DATA_NAME_PATTERN); a folder it cannot list refuses;
      * no commit is held only by its own HEAD reflog or per-worktree refs, which the removal deletes (a
        commit the branch's own reflog holds survives, so it does not count; a detached tip is covered);
      * it owns no allocation (alloc.ps1) whose item is not provably on origin/main, matched by the path
        `git worktree list` gives or the toplevel git prints inside it;
      * no coordination claim names it by either spelling, in this clone's registry or the one its
        mefor.claimsRoot names, and every claim file and directory there could be read;
      * LAST, so the window before the removal is as short as it can be: the liveness fence
        (scripts/coord/occupancy.ps1, read fresh) is available, still lists the tree unlocked, finds no
        registered session launched in it or in a worktree nested inside it, and finds no other
        registered worktree inside it.
    Every gate is the shared copy in worktree-gates.ps1 or occupancy.ps1 where one exists. The claim and
    allocation readers list through Test-PresentOrThrow and Get-EntriesOrThrow, the readers remove.ps1
    uses (both now in worktree-gates.ps1), and a registry directory reads as absent only while the
    folder holding it is there, so a coordination root that is unreachable, or drops mid-run, refuses
    rather than reading as empty; the record parsing follows remove.ps1's rules, cannot-tell refusing,
    without sharing its code.

    WHAT THESE DO NOT SEE, said rather than implied. The fence reads the directory a session was
    LAUNCHED in, and a subagent under `isolation: worktree` is recorded under its parent's directory, so
    the fence alone fails open on this population (docs/WORKTREES.md, *What -Path does not reach*). What
    covers that case is the rest: the harness locks a live agent's worktree (observed 2026-11-05, reason
    "claude agent <id> (pid <n>)"), and a session working there moves the git metadata or the watched
    working-tree mtimes within -IdleHours (72 h by default). THE RESIDUAL: a session that holds no lock,
    runs no git command and writes none of those for that long is not seen, and its tree can be removed
    under it. Its committed work survives through refs (the branch is never deleted, and a commit only
    the tree's own reflog holds refuses the tree); what it had not committed was already refused by the
    clean check. THE IGNORED CACHES ARE DELETED WITH THE TREE, the .venv included, and what is inside
    one is not read beyond the walk's denylist: a data file there under any other name goes with it.
    A PROCESS OUTSIDE CLAUDE that holds files in the tree (a python.exe from its .venv, an engine started
    there) is not looked for: git deletes what it can, fails on the held file, and the row ends ORPHANED
    for a human. A tree a killed run left half-deleted reads REFUSED (prunable or not clean) on later
    nights rather than raising the code.
    -Apply refuses inside Claude Code, here and in run-daily-prune.ps1.
    THE REMOVAL IS `git -C <primary> worktree remove <path>`, WITH NO --force, EVER. There is no switch
    to add one. git's own refusal on a locked or dirty tree is then a last fence this step keeps.

    It never deletes a branch and never releases a coordination claim. A tree that ends ORPHANED
    (deregistered, directory still on disk) is added to prune-merged.ps1's orphan ledger, so every later
    prune-merged.ps1 run re-reports it and exits 3 until a human clears it.
#>

. "$PSScriptRoot\..\coord\occupancy.ps1"
. "$PSScriptRoot\..\coord\coord-root.ps1"
. "$PSScriptRoot\worktree-gates.ps1"

# Allocation records (alloc.ps1) naming the tree, by any of -Norms, whose item is not provably on
# origin/main. Removing the tree does not burn such a number outright: ledger_check.py's owns() falls
# back to the recorded BRANCH once the recorded path is gone, and this step never deletes a branch. But
# ownership then rests on that branch alone, and a later branch deletion (prune-merged.ps1's, or a
# hand's) strands the number with nothing reporting it. remove.ps1 refuses the same case (BACKLOG #1293).
# CANNOT-TELL IS AT-RISK: an unreadable record or registry, a backlog number (no longer answerable from
# this repo), or an origin/main that cannot be listed all refuse. Returns '' or the refusal.
function Get-AllocationRefusal {
    param([string]$Primary, [string[]]$Norms, [string]$AllocDir)
    # Through the throwing readers, so an unreachable registry refuses rather than reading as empty.
    try {
        if (-not (Test-RegistryPresentOrThrow $AllocDir 'the allocation directory')) { return '' }
        $files = @(Get-EntriesOrThrow $AllocDir 'allocations' '*.json' -Recurse -FilesOnly)
    }
    catch { return "the allocation registry could not be read, so an allocation may name it: $($_.Exception.Message)" }
    $atRisk = @()
    foreach ($f in $files) {
        $r = Read-CoordRecord $f.FullName
        if ($r.Tombstone) { continue }
        if ($r.Problem) { return "allocation record $($f.Name) cannot be read ($($r.Problem)), and it might name this tree" }
        if ($Norms -notcontains $r.Holder) { continue }
        $kind = [string]$r.Record.kind
        $number = [string]$r.Record.number
        $onMain = $null
        # A number that is not all digits cannot name an ADR file, so it stays cannot-tell. Escaped
        # anyway, so the record's text is never read as a pattern.
        if ($kind -eq 'adr' -and $number -match '\A\d+\z') {
            $pad = [regex]::Escape($number.PadLeft(4, '0'))
            $listed = @(& git -C $Primary ls-tree -r --name-only origin/main docs/adr/ 2>$null)
            if ($LASTEXITCODE -eq 0) { $onMain = [bool]@($listed | Where-Object { $_ -match "/$pad-" }).Count }
        }
        if ($onMain -ne $true) { $atRisk += "$kind #$number" }
    }
    if ($atRisk.Count -gt 0) { return "it owns allocation(s) not provably on origin/main ($($atRisk -join ', ')); removing it would leave them owned through the branch alone" }
    return ''
}

# The claims directories a claim naming this tree can be in: this clone's registry, plus the one hop
# claim.ps1 follows when the tree sets mefor.claimsRoot. Returns @{ Dirs; Error }.
function Get-TreeClaimsDirs {
    param([string]$Path, [string]$OwnClaimsDir)
    $setting = "$(& git -C $Path config --get mefor.claimsRoot 2>$null)".Trim()
    $code = $LASTEXITCODE
    # Exit 1 is "not set". Anything else is a config git could not read, which could hide the key.
    if ($code -ne 0 -and $code -ne 1) { return @{ Dirs = @(); Error = "git could not read mefor.claimsRoot (exit $code)" } }
    $dirs = @($OwnClaimsDir)
    if ($code -eq 0 -and $setting) {
        if (-not [System.IO.Path]::IsPathFullyQualified($setting)) { return @{ Dirs = @(); Error = "mefor.claimsRoot is the relative path '$setting'" } }
        $top = "$(& git -C $setting rev-parse --path-format=absolute --show-toplevel 2>$null)".Trim()
        if ($LASTEXITCODE -ne 0 -or -not $top) { return @{ Dirs = @(); Error = "mefor.claimsRoot names '$setting', which is not a git repository" } }
        $hop = Resolve-CoordDir -From $top -Kind 'claims'
        if ($hop.Error) { return @{ Dirs = @(); Error = "the claim registry of '$top' could not be resolved ($($hop.Error))" } }
        $dirs += $hop.Path
    }
    return @{ Dirs = $dirs; Error = '' }
}

# Why one path must not be removed now, or '' when every re-check passes. The checks run cheapest first
# and the fence last; the header lists them and says why that order.
function Get-FinishedWorktreeRefusal {
    param([string]$Primary, [string]$Path, [double]$IdleHours, [string[]]$ProtectNorm, [string]$OwnClaimsDir, [string]$AllocDir)
    $norm = ConvertTo-Norm $Path
    if (-not (Test-ClaudeManagedPath $Path)) { return 'outside .claude/worktrees, which is the only population this step removes' }
    if ($norm -eq (ConvertTo-Norm $Primary)) { return 'the primary checkout' }
    $guarded = @($ProtectNorm | Where-Object { $_ -eq $norm -or $_.StartsWith("$norm/") })
    if ($guarded.Count -gt 0) { return "the worktree this run is executing from, or one containing it ($($guarded[0]))" }

    # The primary is always listed, so an empty list is a failed read, never "not registered".
    $all = @(Get-RepoWorktrees $Primary)
    if ($all.Count -eq 0) { return "could not list the worktrees of $Primary" }
    $wt = @($all | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm }) | Select-Object -First 1
    if (-not $wt) { return 'no longer a registered worktree' }
    if ($wt.Locked) { return $(if ($wt.LockReason) { "locked: $($wt.LockReason)" } else { 'locked' }) }
    if ($wt.Prunable) { return "git reports it prunable ($($wt.Prunable)); that needs a human" }

    $flagged = Get-FlaggedFileCount $Path
    if ($flagged -ne 0) { return $(if ($flagged -lt 0) { 'its flagged files could not be read' } else { "$flagged file(s) flagged skip-worktree or assume-unchanged, whose edits git status cannot see" }) }
    $clean = Test-WorktreeClean -Path $Path -AllUntracked
    if (-not $clean.Clean) { return "not clean: $($clean.Reasons -join '; ')" }

    $cut = (Get-Date).AddHours(-1 * $IdleHours)
    $act = Get-WorktreeActivity -Path $Path
    if ($null -eq $act) { return 'its git metadata activity could not be read' }
    if ($act -gt $cut) { return "recently active: git metadata touched $([math]::Round(((Get-Date) - $act).TotalHours, 1)) h ago, inside the $IdleHours h window" }
    $wact = Get-WorkingTreeActivity -Path $Path
    if ($null -eq $wact) { return 'its working-tree activity could not be read' }
    if ($wact -gt $cut) { return "recently active: the working tree was written $([math]::Round(((Get-Date) - $wact).TotalHours, 1)) h ago, inside the $IdleHours h window" }

    # After the idle readings, which are cheap: these cost a second git status and a whole-tree walk.
    $ops = Get-InProgressOperation $Path
    if ($null -eq $ops) { return 'its git dir could not be read for an operation in progress' }
    if ($ops.Count -gt 0) { return "an operation is in progress in its git dir ($($ops -join ', ')), whose state the removal deletes" }
    $ignored = Get-UnsafeIgnoredEntries $Path
    if ($null -eq $ignored) { return 'its ignored files could not be listed' }
    if ($ignored.Count -gt 0) { return "$($ignored.Count) ignored entr(ies) that are not a regenerable cache, which the removal would delete (first: $($ignored[0]))" }
    try { $hazard = Get-NestedHazard $Path } catch { return $_.Exception.Message }
    if ($hazard) { return "it holds $hazard, which git status does not read into" }

    # Covers a detached tip too: `reflog show HEAD` prints the current HEAD even when the log is empty.
    $branch = if ($wt.Detached) { '' } else { [string]$wt.Branch }
    $only = Get-WorktreeOnlyCommitCount -Path $Path -Repo $Primary -Branch $branch
    if ($only -ne 0) { return $(if ($only -lt 0) { 'the commits its HEAD reflog and own refs hold could not be checked' } else { "$only commit(s) held only by its HEAD reflog or its own refs, which the removal deletes" }) }

    # A record may name the tree by either spelling remove.ps1 matches: the path `git worktree list`
    # gives, or the toplevel git prints inside it, which is what claim.ps1 and alloc.ps1 record.
    $top = "$(& git -C $Path rev-parse --path-format=absolute --show-toplevel 2>$null)".Trim()
    if ($LASTEXITCODE -ne 0 -or -not $top) { return 'git could not name its toplevel, so a record naming it by that spelling cannot be matched' }
    $norms = @(@($norm, (ConvertTo-Norm $top)) | Sort-Object -Unique)
    $alloc = Get-AllocationRefusal -Primary $Primary -Norms $norms -AllocDir $AllocDir
    if ($alloc) { return $alloc }
    $dirs = Get-TreeClaimsDirs -Path $Path -OwnClaimsDir $OwnClaimsDir
    if ($dirs.Error) { return "claims are unknown: $($dirs.Error)" }
    $claims = Get-ClaimedWorktreeIndex $dirs.Dirs -RequireParent
    if ($claims.Unreadable) { return 'a claim file or directory could not be read, so any tree may be claimed' }
    if (@($norms | Where-Object { $claims.Claimed.ContainsKey($_) }).Count -gt 0) { return 'a coordination claim names it' }

    # The fence, read FRESH for this path and last of all.
    $occ = Get-WorktreeOccupancy -Repo $Primary
    if (-not $occ.RepoFound) { return "could not list the worktrees of $Primary" }
    if ((ConvertTo-Norm $occ.PrimaryPath) -ne (ConvertTo-Norm $Primary)) { return "$Primary is not the primary checkout git reports ($($occ.PrimaryPath))" }
    $wt2 = @($occ.Worktrees | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm }) | Select-Object -First 1
    if (-not $wt2) { return 'no longer a registered worktree' }
    if ($wt2.Locked) { return $(if ($wt2.LockReason) { "locked: $($wt2.LockReason)" } else { 'locked' }) }
    if (-not $occ.Available) { return "the liveness fence is unavailable: $($occ.Detail)" }
    $occupants = @(Get-WorktreeOccupants -Occupancy $occ -Path $wt2.Path -IncludeNested)
    if ($occupants.Count -gt 0) { return "occupied: $(($occupants | ForEach-Object { "$($_.Short) $($_.State)" }) -join ', ')" }
    $nested = @(Get-NestedWorktrees -Occupancy $occ -Path $wt2.Path)
    if ($nested.Count -gt 0) { return "contains another registered worktree ($($nested[0].Path))" }
    return ''
}

# Record an ORPHANED tree in prune-merged.ps1's orphan ledger, in the shape that script writes, so its
# next run re-reports it. Returns '' or why it could not.
function Add-OrphanLedgerEntry {
    param([string]$Primary, [string]$Path, [string]$Branch, [string]$Detail)
    $cd = & git -C $Primary rev-parse --path-format=absolute --git-common-dir 2>$null
    if ($LASTEXITCODE -ne 0 -or -not $cd) { return 'git could not name the common dir, so the orphan ledger was not written' }
    $ledger = Join-Path ([string]$cd).Trim() 'prune-merged-orphans.json'
    try {
        $entries = @()
        if (Test-Path -LiteralPath $ledger) { $entries = @(Get-Content -LiteralPath $ledger -Raw -EA Stop | ConvertFrom-Json -EA Stop) }
        $entries += [pscustomobject]@{ path = $Path; branch = $Branch; at = (Get-Date).ToString('o'); detail = $Detail }
        ($entries | ConvertTo-Json -Depth 4 -AsArray) | Set-Content -LiteralPath $ledger -Encoding utf8
        return ''
    }
    catch [System.IO.IOException], [System.UnauthorizedAccessException], [System.ArgumentException] {
        return "the orphan ledger at $ledger could not be written: $($_.Exception.Message)"
    }
}

<#
Emits one row per input path, AS EACH PATH IS DECIDED, so a caller logging from the pipeline keeps the
record of every removal already made even if the run is killed part way. Row: Path, Outcome, Reason,
Command.
    Outcome  WOULD-REMOVE  every re-check passed; a dry run, so nothing was removed
             REMOVED       git removed it: deregistered and the directory is gone
             REFUSED       a re-check failed or could not complete; nothing was attempted
             DECLINED      every re-check passed and git still refused; nothing changed, but a gate here
                           disagrees with git, which is worth reading
             FAILED        the removal was attempted and the end state is not what git reported, or
                           cannot be re-read
             ORPHANED      deregistered, but the directory is still on disk; needs a human
    Command  the exact removal command, run or (in a dry run) not run. Never carries --force.
#>
function Invoke-FinishedWorktreeRemoval {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory)][string]$Primary,
        [Parameter(Mandatory)][AllowEmptyCollection()][string[]]$Paths,
        [Parameter(Mandatory)][double]$IdleHours,
        # Worktrees that must never be removed whatever they look like: the one the caller runs from.
        [string[]]$Protect = @(),
        [switch]$Apply
    )
    $ErrorActionPreference = 'Stop'
    $PSNativeCommandUseErrorActionPreference = $false
    # Here as well as in run-daily-prune.ps1, so dot-sourcing this file is no way around it.
    if ($Apply -and $env:CLAUDECODE -eq '1') {
        throw 'Refusing Invoke-FinishedWorktreeRemoval -Apply inside Claude Code: it removes Claude-managed worktrees. The dry run is allowed.'
    }

    $protectNorm = @($Protect | Where-Object { $_ } | ForEach-Object { ConvertTo-Norm $_ })
    # Refusals that hold for every path, decided once. A window under the floor releases trees a
    # measurement says are in use, 0 turns the reading off, and NaN compares false both ways, so the
    # test is written to fail closed. prune-merged.ps1 runs on with a warning there; this does not.
    $allRefusal = ''
    if (-not [double]::IsFinite($IdleHours) -or -not ($IdleHours -ge $IDLE_FLOOR_HOURS)) {
        $allRefusal = "-IdleHours $IdleHours is not a number at or over the $IDLE_FLOOR_HOURS h floor, so idle cannot be established"
    }
    # This clone's shared coordination root names both registries; an error leaves claims and
    # allocations unknown, which refuses everything.
    $ownClaimsDir = ''
    $allocDir = ''
    if (-not $allRefusal) {
        $root = Resolve-CoordSharedRoot -From $Primary
        if ($root.Error) { $allRefusal = "the coordination root could not be resolved, so claims and allocations are unknown: $($root.Error)" }
        else {
            $ownClaimsDir = Join-Path $root.Path 'claims'
            $allocDir = Join-Path $root.Path 'alloc'
        }
    }

    foreach ($path in @($Paths | Where-Object { $_ })) {
        $row = [pscustomobject]@{ Path = $path; Outcome = 'REFUSED'; Reason = ''; Command = "git -C `"$Primary`" worktree remove `"$path`"" }
        try {
            $refusal = if ($allRefusal) { $allRefusal } else {
                Get-FinishedWorktreeRefusal -Primary $Primary -Path $path -IdleHours $IdleHours -ProtectNorm $protectNorm `
                    -OwnClaimsDir $ownClaimsDir -AllocDir $allocDir
            }
            if ($refusal) { $row.Reason = $refusal }
            elseif (-not $Apply) { $row.Outcome = 'WOULD-REMOVE'; $row.Reason = 'every re-check passed' }
            else { Invoke-OneRemoval -Primary $Primary -Row $row }
        }
        catch [System.Management.Automation.RuntimeException], [System.IO.IOException], [System.UnauthorizedAccessException] {
            # Before git was asked, a throw is a check that could not complete: nothing was attempted.
            # While the end state is being read, it is a failure, because that state is no longer known.
            # Once a verdict on the end state is in (ORPHANED, say), a later throw must not relabel it:
            # an orphan re-read as REFUSED would drop the exit code 3 that makes a human look.
            if ($row.Outcome -eq 'ATTEMPTING') { $row.Outcome = 'FAILED'; $row.Reason = "the removal was attempted and then a read threw: $($_.Exception.Message)" }
            elseif ($row.Outcome -eq 'REFUSED') { $row.Reason = "a check could not complete: $($_.Exception.Message)" }
            else { $row.Reason = "$($row.Reason); then an error: $($_.Exception.Message)" }
        }
        $row
    }
}

function Invoke-OneRemoval {
    param([string]$Primary, [object]$Row)
    $path = $Row.Path
    $norm = ConvertTo-Norm $path
    $wt = @(Get-RepoWorktrees $Primary | Where-Object { (ConvertTo-Norm $_.Path) -eq $norm }) | Select-Object -First 1
    # '' for a detached tree: the ledger's recovery recipe re-adds a BRANCH, and '(detached)' is not one.
    $branch = if ($wt -and -not $wt.Detached) { [string]$wt.Branch } else { '' }

    # The one removal. Plain `worktree remove`: no --force, so git refuses a locked tree or one holding a
    # modified or untracked file even if every check above was somehow wrong.
    $Row.Outcome = 'ATTEMPTING'
    $gitOut = @(& git -C $Primary worktree remove $path 2>&1 | ForEach-Object { "$_" })
    $removeExit = $LASTEXITCODE
    $gitText = (($gitOut | Where-Object { $_ }) -join ' ').Trim()

    # Judge the END STATE, not the exit code alone: a removal that deregistered the tree and then failed
    # to delete the directory is the orphan this whole fence exists to prevent. An unreadable list is
    # not "deregistered", so it is read with its own exit code rather than through Get-RepoWorktrees.
    $listing = @(& git -C $Primary worktree list --porcelain 2>$null)
    $listOk = ($LASTEXITCODE -eq 0 -and $listing.Count -gt 0)
    $stillRegistered = @($listing | Where-Object { $_ -like 'worktree *' -and (ConvertTo-Norm $_.Substring(9).Trim()) -eq $norm }).Count -gt 0
    $dirExists = Test-Path -LiteralPath $path
    if (-not $listOk) {
        $Row.Outcome = 'FAILED'
        $Row.Reason = "git exit $removeExit, and the worktree list could not be re-read; directory present=${dirExists}: $gitText"
    }
    elseif (-not $stillRegistered -and -not $dirExists -and $removeExit -eq 0) {
        $Row.Outcome = 'REMOVED'; $Row.Reason = 'every re-check passed'
    }
    elseif ($stillRegistered -and $dirExists -and $removeExit -ne 0) {
        $Row.Outcome = 'DECLINED'; $Row.Reason = "git declined (exit $removeExit): $gitText"
    }
    elseif (-not $stillRegistered -and $dirExists) {
        $Row.Outcome = 'ORPHANED'
        $Row.Reason = "deregistered but the directory is still on disk (git exit $removeExit): $gitText"
        # Deliberately broad: whatever the ledger write throws, the verdict above stands and the error
        # is logged with it. The runner still exits 3 on the row.
        try { $note = Add-OrphanLedgerEntry -Primary $Primary -Path $path -Branch $branch -Detail $Row.Reason }
        catch { $note = "the orphan ledger was not written: $($_.Exception.Message)" }
        if ($note) { $Row.Reason += "; $note" }
    }
    else {
        $Row.Outcome = 'FAILED'
        $Row.Reason = "git exit $removeExit, registered=$stillRegistered, directory present=${dirExists}: $gitText"
    }
}
