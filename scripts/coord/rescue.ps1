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
    $fmt = "%(refname)$FS%(objectname)$FS%(*objectname)$FS%(contents)$RS"
    $raw = (& git -C $repo for-each-ref --format=$fmt refs/rescue refs/tags/rescue) -join "`n"
    foreach ($rec in ($raw -split [regex]::Escape($RS))) {
        if (-not $rec.Trim()) { continue }
        $f = $rec -split [regex]::Escape($FS)
        if ($f.Count -lt 3) { continue }
        $commit = if ($f[2].Trim()) { $f[2].Trim() } else { $f[1].Trim() }
        [pscustomobject]@{
            ref      = $f[0].Trim()
            commit   = $commit
            contents = if ($f.Count -ge 4) { $f[3] } else { '' }
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
$records = @(Get-RescueRecords)
$tips = Get-LocalBranchTips
$rows = @()

foreach ($rec in $records) {
    $r = $rec.ref
    $commit = $rec.commit
    $body = $rec.contents
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
            $behind = (& git -C $repo rev-list --count "$commit..$tip" 2>$null)
            $ahead = (& git -C $repo rev-list --count "$tip..$commit" 2>$null)
            if ($ahead -eq '0') {
                $verdict = 'BEHIND'
                $detail = "$behind commit(s) short of $branchName -- a snapshot older than its branch, NOT a defect"
            }
            else {
                $verdict = 'DIVERGED'
                $detail = "$behind behind / $ahead ahead of $branchName"
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
        selfDescribing = [bool]$selfDescribing; wasTipAtCapture = $recordedWasTip; detail = $detail
    }
}

if ($Json) {
    [pscustomobject]@{
        examined = $rows.Count
        repo     = $repo
        rows     = $rows
    } | ConvertTo-Json -Depth 5
    exit 0
}

$byVerdict = $rows | Group-Object verdict | Sort-Object Name

Write-Host ""
Write-Host "RESCUE REF AUDIT -- $repo"
Write-Host "EXAMINED $($rows.Count) ref(s) across refs/rescue/ and refs/tags/rescue/."
if ($rows.Count -eq 0) {
    Write-Host "  Zero refs examined. That is a fact about this repository, not a clean bill." -ForegroundColor Yellow
}
Write-Host ""
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
    Write-Host ("{0,-16} {1}" -f $g.Name, $g.Count) -ForegroundColor $colour
}

$short = @($rows | Where-Object verdict -eq 'SHORT-AT-CAPTURE').Count
if ($short -gt 0) {
    Write-Host ""
    Write-Host "$short ref(s) were SHORT of their branch when captured, and that branch is now gone." -ForegroundColor Yellow
    Write-Host "  That is not a defect -- a rescue ref is a snapshot by design -- but it is the fact a" -ForegroundColor Yellow
    Write-Host "  recovery decision turns on: reaching for one of these gets less than the branch held." -ForegroundColor Yellow
    Write-Host "  Nothing can compare them against anything now, so the recorded answer is the only one." -ForegroundColor Yellow
}

$unverifiable = @($rows | Where-Object verdict -eq 'UNVERIFIABLE').Count
if ($unverifiable -gt 0) {
    Write-Host ""
    Write-Host "$unverifiable ref(s) are UNVERIFIABLE, which is NOT the same as healthy." -ForegroundColor Yellow
    Write-Host "  They carry no recorded provenance and name no branch that still exists, so nothing" -ForegroundColor Yellow
    Write-Host "  here can say what they hold. They predate -Anchor and cannot be retrofitted: the" -ForegroundColor Yellow
    Write-Host "  information was never captured. Refs written by -Anchor stay verifiable after their" -ForegroundColor Yellow
    Write-Host "  branch is deleted, which is the case a rescue ref exists for." -ForegroundColor Yellow
}
exit 0
