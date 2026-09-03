# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Write a rescue ref that can be verified WITHOUT the branch it names, and audit the ones already
    written (BACKLOG #1349).

.DESCRIPTION
    A rescue ref is consulted once, in the moment the original is already gone. That is the whole
    hazard: it is the one instrument whose failure surfaces only when it is too late to fix.

    THE DEFECT IS NOT THAT REFS GO STALE. Dated rescue tags are SNAPSHOTS BY DESIGN -- nothing
    re-takes them, so a tag older than its branch is working as intended, not broken. The argument
    that short refs are a writer defect was made and WITHDRAWN by its author: 374 of 730 tags holding
    a tip is also exactly what mostly-dormant branches look like, which is a correlation read as
    intent. This script does not "fix" staleness and must not be changed to.

    THE DEFECT IS THAT A READER CANNOT TELL. Reaching for a ref that is 75 commits short, or
    concluding work is lost when another namespace holds its tip, are both wrong RECOVERY decisions,
    and nothing today reports either.

    AND THE MEASUREMENT IS POSSIBLE EXACTLY WHERE IT DOES NOT MATTER. A rescue ref can only be
    compared against a branch that still exists -- but 436 of 730 name a branch that is GONE, and
    those are precisely the ones a rescue ref is FOR. Worse, all 730 dated tags carry a date-scoped
    label rather than a branch name, so zero of them can be censused by name at all. The one
    confirmed short instance was findable only because its branch happened to survive alongside it.

    SO THE FIX IS AT WRITE TIME, AND IT IS THE ONLY PLACE IT CAN BE. `-Anchor` writes an ANNOTATED
    tag whose message records the branch, the sha and the instant it captured. That makes the ref
    self-describing: a later reader can ask "was this the tip when it was written, and is it still
    the object it claims" without needing the branch to exist. Nothing can retrofit the refs already
    written -- the information was never captured -- and `-Check` says so about them rather than
    guessing.

    AND `-Check` MUST READ WHAT `-Anchor` RECORDED, WHICH THE FIRST VERSION DID NOT. It matched only
    `branch:` and `commit:`, so once the branch was gone a ref that HELD THE TIP and a ref captured
    SHORT of it produced the same verdict, the same detail and the same colour -- in exactly the
    population this script exists for, while the two tags plainly disagreed. Captured and then
    discarded is worse than never captured, because the report then contradicts its own evidence.
    The branch-gone arm therefore reports HELD-THE-TIP or SHORT-AT-CAPTURE, and keeps the bare
    SELF-DESCRIBING verdict only for a ref whose message carries no `was-tip` line to read.

    UNVERIFIABLE IS NOT CLEAN, and that distinction is the entire point of the report. A ref whose
    branch is gone and which carries no recorded provenance gets UNVERIFIABLE, never OK. The honest
    statement is "this check cannot tell", and a check that cannot tell must not print the word that
    means it can -- the standard `unbacked_check.ps1` already sets in this directory, for the same
    reason one level over.

    COVERAGE IS A FIRST-CLASS OUTPUT. Every run prints how many refs it examined and across which
    namespaces, including when it finds nothing wrong. A run that examined zero refs and a run that
    examined everything otherwise print the same reassuring line.

    ANNOTATED TAGS DEREFERENCE, AND THE NAIVE READ IS WRONG. `rev-parse <tag>` on an annotated tag
    returns the TAG OBJECT, not the commit it points at, so a comparison against a branch tip fails
    for a reason that has nothing to do with staleness. Every commit id here comes from
    `%(*objectname)` where it exists and `%(objectname)` otherwise.

    AND THE AUDIT READS THREE KINDS OF NAMESPACE, NOT TWO, BECAUSE THE LARGEST ONE WAS MISSING.
    Measured 2026-09-03: this checkout holds 266 refs under `refs/rescue`, 1405 under
    `refs/tags/rescue` -- and 1505 under `refs/remotes/private/rescuetags`, which the first version
    of this script never looked at. That namespace exists because `remote.private.fetch` carries
    `+refs/tags/rescue/*:refs/remotes/private/rescuetags/*`, so ONE server-side tag arrives under a
    SECOND local name. `git tag -l 'rescue/*'` cannot see it, which is how two readers each verified
    a real object with an instrument structurally blind to the other's.

    THE TWO KINDS ARE DIFFERENT MECHANISMS AND ARE REPORTED AS SUCH. A `refs/tags/rescue/*` ref is a
    SNAPSHOT: nothing re-takes it, so a ref behind its branch is behind it forever. A
    `refs/remotes/<remote>/rescuetags/*` ref is PUSH-UPDATED: the durability hook force-moves it on
    every commit, so a ref behind its branch may merely be LAGGING and the next commit fixes it. One
    reflog on such a ref shows six updates. Grading those two at one severity is the naming collapse
    this whole item is about, so `mechanism` is a first-class field here and the report splits on it.

    THE SOFTENING APPLIES ONLY WHILE THE BRANCH IS ALIVE. A push-updated ref whose branch is GONE
    gets no further pushes, so its staleness is as permanent as a tag's. Mechanism therefore changes
    the wording of BEHIND and DIVERGED and deliberately changes nothing about the branch-gone arms.

    THE COUNTS OVERLAP ON PURPOSE. A tag and its remote-tracking mirror are two names for what may or
    may not be one object, and 15 percent of the pairs measured for this item DISAGREED. Deduplicating
    them would delete the finding.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\rescue.ps1 -Anchor my-lane-before-rebase
    pwsh -NoProfile -File scripts\coord\rescue.ps1 -Check
    pwsh -NoProfile -File scripts\coord\rescue.ps1 -Check -Json
#>
[CmdletBinding(DefaultParameterSetName = 'Check')]
param(
    # Write a rescue ref under refs/rescue/<slug>, capturing HEAD unless -Sha says otherwise.
    [Parameter(ParameterSetName = 'Anchor', Mandatory)][string]$Anchor,
    # The commit to capture. Defaults to HEAD.
    [Parameter(ParameterSetName = 'Anchor')][string]$Sha,
    # Audit every rescue ref reachable from this repository.
    [Parameter(ParameterSetName = 'Check', Mandatory = $false)][switch]$Check,
    [switch]$Json
)

$ErrorActionPreference = 'Stop'

# Anchored on the SCRIPT, not the cwd, for the reason alloc.ps1 states once (BACKLOG #1060): an
# absolute -File invocation from another worktree must act on the checkout the script lives in.
$repo = (& git -C $PSScriptRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
if (-not $repo) { throw "scripts/coord/ is not inside a git repository: $PSScriptRoot" }
$repo = $repo.Trim()

#: The marker that makes a ref self-describing. Grepped for by -Check, so it is defined once.
$PROVENANCE = 'mefor-rescue-v1'

#: Field and record separators for the ONE-PASS read below. Control characters rather than any
#: printable delimiter, because a tag message is free text and could contain a pipe or a tab.
$FS = [char]0x1F
$RS = [char]0x1E

#: The two mechanisms a rescue ref can be written by, and the difference decides how loudly a
#: behind-its-branch ref should read. Named once here so no call site spells them differently.
$SNAPSHOT = 'snapshot'
$PUSH_UPDATED = 'push-updated'

function Get-RescueNamespaces {
    <#
    EVERY NAMESPACE A RESCUE REF LANDS IN, WITH THE MECHANISM THAT WRITES IT.

    The remote-tracking prefixes are derived from `git remote` rather than hardcoded, because the
    remote's NAME is an operator's choice: this checkout calls it `private`, and nothing makes that
    universal. Enumerating remotes costs one spawn and removes the guess.

    A prefix that matches nothing is kept and reported as zero. That is the coverage rule this
    directory already sets: a run that examined nothing and a run that examined everything must not
    print the same reassuring line, and a namespace silently dropped for being empty is exactly how
    a reader loses the ability to tell.
    #>
    $ns = [ordered]@{}
    $ns['refs/rescue'] = $SNAPSHOT
    $ns['refs/tags/rescue'] = $SNAPSHOT
    foreach ($remote in (& git -C $repo remote)) {
        $r = "$remote".Trim()
        if (-not $r) { continue }
        # `rescuetags` is what remote.<r>.fetch remaps refs/tags/rescue/* into here; `rescue` covers
        # a mirror of the refs/rescue subtree under the same remote.
        $ns["refs/remotes/$r/rescuetags"] = $PUSH_UPDATED
        $ns["refs/remotes/$r/rescue"] = $PUSH_UPDATED
    }
    return $ns
}

function Get-RescueRecords {
    <#
    ONE `for-each-ref` FOR THE WHOLE AUDIT, AND THE REASON IS MEASURED. The first version of this
    script asked git for the commit, then the contents, per ref. That is three process spawns per
    ref; across the ref population counted below it exceeded a two-minute budget and had to be
    backgrounded. Windows process creation is the cost, not git.

    A PREFIX PATTERN IS THE CORRECT ENUMERATION AND A GLOB IS NOT, AND THIS IS THE ONE PLACE THE
    COUNTS ARE STATED. `refs/rescue` as a pattern matches the entire subtree; `refs/rescue/*` matches
    ONE path segment. Measured on this repository 2026-08-28: `refs/rescue` 206 against
    `refs/rescue/*` 73, plus `refs/tags/rescue` 1131, for 1337 across the two prefixes read here. 73
    is the dangerous kind of wrong -- small, plausible, and it reads as an answer. TREAT THESE AS A
    DATED SAMPLE, NEVER A CONSTANT: the total rose by four within the minutes it took to correct this
    comment, and the figure it replaced had been restated elsewhere in the file with a different
    value. What does not drift is that the glob under-reports the same subtree by roughly two thirds.

    `%(*objectname)` is populated ONLY for an annotated tag; for a lightweight ref it is empty and
    `%(objectname)` is already the commit. Taking both and picking is why an annotated tag does not
    silently compare its TAG OBJECT against a branch tip.
    #>
    param([System.Collections.Specialized.OrderedDictionary]$Namespaces)

    $prefixes = @($Namespaces.Keys)
    $fmt = "%(refname)$FS%(objectname)$FS%(*objectname)$FS%(contents)$RS"
    $raw = (& git -C $repo for-each-ref --format=$fmt $prefixes) -join "`n"
    foreach ($rec in ($raw -split [regex]::Escape($RS))) {
        if (-not $rec.Trim()) { continue }
        $f = $rec -split [regex]::Escape($FS)
        if ($f.Count -lt 3) { continue }
        $commit = if ($f[2].Trim()) { $f[2].Trim() } else { $f[1].Trim() }
        $ref = $f[0].Trim()
        # Longest match is not needed: no prefix here is a prefix of another. `refs/rescue` and
        # `refs/remotes/<r>/rescue` are disjoint subtrees, and git's own prefix rule stops at a
        # slash, so `refs/rescue` never claims `refs/rescuetags`.
        $namespace = $null
        foreach ($p in $prefixes) {
            if ($ref -eq $p -or $ref.StartsWith("$p/")) { $namespace = $p; break }
        }
        [pscustomobject]@{
            ref       = $ref
            commit    = $commit
            contents  = if ($f.Count -ge 4) { $f[3] } else { '' }
            namespace = $namespace
            mechanism = if ($namespace) { $Namespaces[$namespace] } else { 'unknown' }
        }
    }
}

function Get-LocalBranchTips {
    # Read every branch tip ONCE into a lookup, for the same spawn-cost reason. A per-ref
    # `rev-parse --verify refs/heads/<name>` would reintroduce exactly the cost just removed.
    $map = @{}
    foreach ($line in (& git -C $repo for-each-ref --format="%(refname:short)$FS%(objectname)" refs/heads)) {
        $p = $line -split [regex]::Escape($FS)
        if ($p.Count -ge 2) { $map[$p[0].Trim()] = $p[1].Trim() }
    }
    return $map
}

if ($PSCmdlet.ParameterSetName -eq 'Anchor') {
    $target = if ($Sha) { $Sha } else { 'HEAD' }
    $commit = (& git -C $repo rev-parse --verify "$target^{commit}" 2>$null)
    if (-not $commit) { throw "not a commit: $target" }
    $commit = $commit.Trim()

    # The branch is recorded as a LABEL, never as the thing verification depends on. A detached HEAD
    # has none, and that is a normal state here -- 23 of 44 worktrees were detached when
    # unbacked_check.ps1 was written -- so it is reported rather than treated as an error.
    $branch = (& git -C $repo rev-parse --abbrev-ref HEAD 2>$null)
    if ($branch) { $branch = $branch.Trim() }
    if (-not $branch -or $branch -eq 'HEAD') { $branch = '(detached)' }

    # WAS IT THE TIP AT WRITE TIME? Recorded as a fact about this instant, not asserted as a promise
    # about the future. A snapshot that was the tip when taken and is short a week later is working
    # exactly as designed; what a reader needs is to know WHICH it is.
    $tipOf = if ($branch -ne '(detached)') { (& git -C $repo rev-parse --verify "$branch^{commit}" 2>$null) } else { $null }
    $wasTip = if ($tipOf) { ($tipOf.Trim() -eq $commit) } else { $false }

    $stamp = (Get-Date).ToUniversalTime().ToString('o')
    $message = @(
        $PROVENANCE
        "commit: $commit"
        "branch: $branch"
        "was-tip: $wasTip"
        "captured: $stamp"
        "worktree: $repo"
    ) -join "`n"

    $ref = "rescue/$Anchor"
    & git -C $repo tag -a $ref -m $message $commit
    if ($LASTEXITCODE -ne 0) { throw "could not write tag $ref" }

    Write-Host "ANCHORED $ref -> $($commit.Substring(0,9))" -ForegroundColor Green
    Write-Host "  branch  : $branch"
    Write-Host "  was tip : $wasTip"
    Write-Host "  captured: $stamp"
    if (-not $wasTip) {
        Write-Host "  NOTE: this commit was NOT the tip of $branch when captured. That is recorded," -ForegroundColor Yellow
        Write-Host "        so a later reader is told rather than left to infer it." -ForegroundColor Yellow
    }
    exit 0
}

# ---------------------------------------------------------------------------------------------
# -Check
# ---------------------------------------------------------------------------------------------
$namespaces = Get-RescueNamespaces
$records = @(Get-RescueRecords -Namespaces $namespaces)
$tips = Get-LocalBranchTips
$rows = @()

foreach ($rec in $records) {
    $r = $rec.ref
    $commit = $rec.commit
    $body = $rec.contents
    $mechanism = $rec.mechanism
    $selfDescribing = $body -match [regex]::Escape($PROVENANCE)

    $recordedBranch = $null
    $recordedCommit = $null
    $recordedWasTip = $null
    if ($selfDescribing) {
        if ($body -match '(?m)^branch:\s*(.+)$') { $recordedBranch = $Matches[1].Trim() }
        if ($body -match '(?m)^commit:\s*([0-9a-f]{7,40})') { $recordedCommit = $Matches[1].Trim() }
        # READ WHAT -Anchor RECORDED. This line is the entire reason the branch-gone population is
        # readable at all; matching only branch and commit made a tip capture and a short capture
        # render identically, which is the item's own defect reproduced inside its fix. Left as
        # $null when the message carries no was-tip line, because "not recorded" and "recorded
        # False" are different answers and must not collapse into one.
        if ($body -match '(?m)^was-tip:\s*(True|False)\s*$') {
            $recordedWasTip = ($Matches[1] -eq 'True')
        }
    }

    # A self-describing ref is checked against ITSELF first. This is the arm that works when the
    # branch is gone, which is the population the whole item is about.
    $intact = $null
    if ($recordedCommit) { $intact = ($recordedCommit -eq $commit) }

    $branchName = $recordedBranch
    $verdict = 'UNVERIFIABLE'
    $detail = 'no recorded provenance and no branch to compare against'

    if ($intact -eq $false) {
        $verdict = 'ALTERED'
        $detail = "records $($recordedCommit.Substring(0,9)) but points at $($commit.Substring(0,9))"
    }
    elseif ($branchName -and $branchName -ne '(detached)' -and $tips.ContainsKey($branchName)) {
        $tip = $tips[$branchName]
        if ($tip -eq $commit) { $verdict = 'TIP'; $detail = "holds the tip of $branchName" }
        else {
            # Only reached for a self-describing ref whose branch still exists -- a small subset, so
            # the per-ref rev-list cost here is bounded rather than paid 1318 times.
            # $LASTEXITCODE IS READ HERE BECAUSE `2>$null` MAKES A FAILURE LOOK LIKE AN ANSWER.
            # `git rev-list --count` exits 128 with EMPTY stdout when it cannot resolve a range --
            # measured, not assumed. Without this guard $ahead is empty, `$ahead -eq '0'` is FALSE,
            # and control falls to the else branch, which reports DIVERGED with blank counts. That
            # turns a loud "I CANNOT ANSWER THAT" into the most alarming verdict this script emits,
            # about a ref that may be perfectly sound. It is the same collapse the was-tip comment
            # above refuses: "not recorded" and "recorded False" are different answers.
            #
            # Reachability, stated honestly and NARROWED after a measurement: both operands normally
            # resolve, since $commit is the ref's own target and $tip comes from a local branch this
            # clone just enumerated. So this is a GUARD, not a fix for a failure seen in the wild.
            # It needs the OBJECT to be absent from the clone doing the asking, which in practice
            # means a partial, shallow or otherwise incomplete clone.
            #
            # AN EARLIER VERSION OF THIS COMMENT ALSO BLAMED THE REFSPEC THAT REMAPS
            # +refs/tags/rescue/* INTO refs/remotes/private/rescuetags/*. THAT WAS WRONG AND THE
            # DISTINCTION IS WORTH KEEPING: a remap changes the NAME a ref is reachable under, not
            # whether the OBJECT is present -- `git cat-file -t` on such a commit returns `commit`,
            # measured. So a remap makes `git tag --contains` return zero for work that IS tagged,
            # which is a real and separate hazard, and it does NOT make rev-list fail here.
            # Two different failures that both feel like "the ref is missing".
            $behind = (& git -C $repo rev-list --count "$commit..$tip" 2>$null)
            $behindOk = ($LASTEXITCODE -eq 0)
            $ahead = (& git -C $repo rev-list --count "$tip..$commit" 2>$null)
            $aheadOk = ($LASTEXITCODE -eq 0)
            if (-not $behindOk -or -not $aheadOk) {
                $verdict = 'UNVERIFIABLE'
                $detail = "git could not compare against $branchName in this clone -- a statement about THIS CLONE, not about the ref"
            }
            elseif ($ahead -eq '0') {
                $verdict = 'BEHIND'
                # MECHANISM CHANGES THE SENTENCE, NEVER THE VERDICT. A snapshot behind its branch is
                # behind it forever, because nothing re-takes it. A push-updated ref behind its
                # branch is a different fact -- the hook force-moves it on the next commit -- and
                # reporting the two in identical words is the collapse this item exists to name.
                $detail = if ($mechanism -eq $PUSH_UPDATED) {
                    "$behind commit(s) short of $branchName -- re-pushed as the branch moves, so this may merely be LAGGING"
                }
                else {
                    "$behind commit(s) short of $branchName -- a snapshot older than its branch, NOT a defect"
                }
            }
            else {
                $verdict = 'DIVERGED'
                $detail = if ($mechanism -eq $PUSH_UPDATED) {
                    "$behind behind / $ahead ahead of $branchName -- re-pushed, so the behind half may merely be LAGGING"
                }
                else {
                    "$behind behind / $ahead ahead of $branchName"
                }
            }
        }
    }
    elseif ($selfDescribing) {
        # THE CASE THE ITEM EXISTS FOR. The branch is gone, so no comparison is possible -- but the
        # ref carries what it captured, and WHICH of these three it is drives opposite recovery
        # decisions. Reporting them under one name is the failure that made this arm worthless.
        if ($recordedWasTip -eq $true) {
            $verdict = 'HELD-THE-TIP'
            $detail = "branch $branchName is gone; ref is intact and WAS its tip when captured"
        }
        elseif ($recordedWasTip -eq $false) {
            $verdict = 'SHORT-AT-CAPTURE'
            $detail = "branch $branchName is gone; ref is intact but was NOT its tip when captured -- a partial snapshot"
        }
        else {
            $verdict = 'SELF-DESCRIBING'
            $detail = "branch $branchName is gone; ref is intact but recorded no was-tip, so whether it held the tip cannot be told"
        }
    }

    $rows += [pscustomobject]@{
        ref = $r; commit = $commit; verdict = $verdict
        namespace = $rec.namespace; mechanism = $mechanism
        selfDescribing = [bool]$selfDescribing; wasTipAtCapture = $recordedWasTip; detail = $detail
    }
}

#: Coverage, per namespace, including the ones that matched nothing. Built before the JSON branch so
#: both outputs report the same thing.
$coverage = @()
foreach ($p in $namespaces.Keys) {
    $coverage += [pscustomobject]@{
        namespace = $p
        mechanism = $namespaces[$p]
        count     = @($rows | Where-Object namespace -eq $p).Count
    }
}

if ($Json) {
    [pscustomobject]@{
        examined   = $rows.Count
        repo       = $repo
        namespaces = $coverage
        rows       = $rows
    } | ConvertTo-Json -Depth 5
    exit 0
}

$byVerdict = $rows | Group-Object verdict | Sort-Object Name

Write-Host ""
Write-Host "RESCUE REF AUDIT -- $repo"
Write-Host "EXAMINED $($rows.Count) ref(s) across $($coverage.Count) namespace(s):"
foreach ($c in $coverage) {
    Write-Host ("  {0,6}  {1,-13} {2}" -f $c.count, $c.mechanism, $c.namespace)
}
Write-Host "  $SNAPSHOT      = a one-time capture. Nothing re-takes it, so staleness here is PERMANENT."
Write-Host "  $PUSH_UPDATED  = force-moved by the durability hook, so a ref behind a LIVE branch may"
Write-Host "                 merely be lagging. Once that branch is gone, nothing pushes again and"
Write-Host "                 the two mechanisms are equally final."
Write-Host "  The counts OVERLAP by construction: remote.<remote>.fetch remaps refs/tags/rescue/*"
Write-Host "  into refs/remotes/<remote>/rescuetags/*, so one server-side object arrives under a"
Write-Host "  second local name. They are not deduplicated -- the two names disagreeing is the"
Write-Host "  finding, and folding them together would delete it."
if ($rows.Count -eq 0) {
    Write-Host "  Zero refs examined. That is a fact about this repository, not a clean bill." -ForegroundColor Yellow
}
Write-Host ("{0,-16} {1,10} {2,13}" -f 'verdict', $SNAPSHOT, $PUSH_UPDATED)
foreach ($g in $byVerdict) {
    # SHORT-AT-CAPTURE is Gray with BEHIND, not Green with TIP: both are snapshots older than their
    # branch and neither is a defect, but neither is the outcome a reader hopes for either. Bare
    # SELF-DESCRIBING falls through to Yellow deliberately -- it is the arm that cannot tell.
    $colour = switch ($g.Name) {
        'TIP' { 'Green' }
        'HELD-THE-TIP' { 'Green' }
        'BEHIND' { 'Gray' }
        'SHORT-AT-CAPTURE' { 'Gray' }
        'ALTERED' { 'Red' }
        default { 'Yellow' }
    }
    $snap = @($g.Group | Where-Object mechanism -eq $SNAPSHOT).Count
    $pushed = @($g.Group | Where-Object mechanism -eq $PUSH_UPDATED).Count
    Write-Host ("{0,-16} {1,10} {2,13}" -f $g.Name, $snap, $pushed) -ForegroundColor $colour
}

$unknown = @($rows | Where-Object mechanism -eq 'unknown').Count
if ($unknown -gt 0) {
    # Cannot happen while every ref comes from an enumerated prefix, and is printed anyway: a row
    # whose mechanism is unclassified would otherwise render as 0 and 0 and read as nothing at all.
    Write-Host ""
    Write-Host "$unknown ref(s) matched no known namespace and are MISSING from the split above." -ForegroundColor Red
}

$laggingBehind = @($rows | Where-Object { $_.verdict -eq 'BEHIND' -and $_.mechanism -eq $PUSH_UPDATED }).Count
if ($laggingBehind -gt 0) {
    Write-Host ""
    Write-Host "$laggingBehind push-updated ref(s) sit behind a branch that still exists." -ForegroundColor Gray
    Write-Host "  Read this one QUIETLY. The durability hook force-moves these on the next commit, so" -ForegroundColor Gray
    Write-Host "  behind here is usually lag, not loss -- one such ref's reflog shows six updates. It is" -ForegroundColor Gray
    Write-Host "  NOT the same finding as a snapshot behind its branch, which never catches up." -ForegroundColor Gray
}

$short = @($rows | Where-Object verdict -eq 'SHORT-AT-CAPTURE').Count
if ($short -gt 0) {
    Write-Host ""
    Write-Host "$short ref(s) were SHORT of their branch when captured, and that branch is now gone." -ForegroundColor Yellow
    Write-Host "  That is not a defect -- a rescue ref is a snapshot by design -- but it is the fact a" -ForegroundColor Yellow
    Write-Host "  recovery decision turns on: reaching for one of these gets less than the branch held." -ForegroundColor Yellow
    Write-Host "  Nothing can compare them against anything now, so the recorded answer is the only one." -ForegroundColor Yellow
}

$unverifiable = @($rows | Where-Object verdict -eq 'UNVERIFIABLE')
if ($unverifiable.Count -gt 0) {
    $uSnap = @($unverifiable | Where-Object mechanism -eq $SNAPSHOT).Count
    $uPush = @($unverifiable | Where-Object mechanism -eq $PUSH_UPDATED).Count
    Write-Host ""
    Write-Host "$($unverifiable.Count) ref(s) are UNVERIFIABLE, which is NOT the same as healthy." -ForegroundColor Yellow
    Write-Host "  They carry no recorded provenance and name no branch that still exists, so nothing" -ForegroundColor Yellow
    Write-Host "  here can say what they hold." -ForegroundColor Yellow
    Write-Host "  $uSnap of them are $SNAPSHOT refs. Those CANNOT be retrofitted -- the information was" -ForegroundColor Yellow
    Write-Host "    never captured and nothing re-takes a snapshot. Write new ones with -Anchor." -ForegroundColor Yellow
    Write-Host "  $uPush of them are $PUSH_UPDATED refs, and this half HEALS ITSELF. The durability hook" -ForegroundColor Yellow
    Write-Host "    now pushes an annotated tag object carrying the same provenance, so each of these" -ForegroundColor Yellow
    Write-Host "    becomes readable on the next commit to the branch it tracks. A branch with no" -ForegroundColor Yellow
    Write-Host "    further commits keeps its unverifiable ref, so the count falls with activity, not" -ForegroundColor Yellow
    Write-Host "    with time." -ForegroundColor Yellow
}
exit 0
