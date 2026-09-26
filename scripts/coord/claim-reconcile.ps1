# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    Find work claims whose work demonstrably landed -- whether the holder worktree is gone, or still
    present with its pull request merged -- and release ONLY those. Reports by default; changes
    nothing without -Apply.

.DESCRIPTION
    `prune-merged.ps1` already releases the claims held by a worktree IT removes (BACKLOG #345), and
    that reasoning is untouched here. This exists because that is ONE removal path and there are
    several: `git worktree remove` run by hand, `git worktree prune`, deleting the directory in
    Explorer, and bulk cleanup by explicit path list. Every one of those strands the claim, and
    `claim.ps1 -Take` hard-blocks on a claim file that exists -- so the key becomes unclaimable by
    every future session until a human happens to run `-Release <key> -Force`.

    Measured 2026-08-16 on this repository: 33 of 56 claims were held by worktrees that no longer
    existed on disk, across 11 locations, the oldest 14 days old.

    WHY THIS IS STRICTER THAN THE RELEASE INSIDE prune-merged, AND MUST BE.

    prune-merged can release safely because of what it has already proven before it gets there: it
    only ever removes a worktree that is merged AND clean AND unoccupied. The claim it drops is
    guarding nothing, by construction.

    This sweep has no such precondition. It meets claims whose holder is gone for reasons nobody
    recorded, and on this repository 17 of those 33 sat on branches carrying unmerged commits --
    including a fix for a live fail-open in a shipped safety control. Releasing on "holder gone"
    alone would have freed every one of them for another session to rebuild. So a release here needs
    BOTH halves:

        (a) the holder is gone AND deregistered  -- prune-merged's evidence rule, unchanged, and
        (b) the work is provably on origin/main  -- this file's addition.

    Anything that fails either half is REPORTED and never touched. Anything that cannot be
    established is reported as UNKNOWN and never touched: the false positive here hands a key to a
    second session and invites the duplicate build the registry exists to stop, which is strictly
    worse than a stale line in a file.

    THIS IS NOT AN EXPIRING CLAIM. Nothing here reads a clock. claim.ps1's argument that an
    auto-expiring claim silently re-opens the race it exists to prevent is correct and is why age is
    not an input: a claim whose holder is merely quiet is invisible to this tool.

    THE LEDGER IS NOT REIMPLEMENTED. Releases shell out to `claim.ps1 -Release <key> -Force`, which
    owns the .history format, writes the record BEFORE removing the file, and refuses the release if
    the record cannot be written (BACKLOG #1068). A second writer of that file would be a second
    definition of it.

    WHAT THIS CANNOT SEE, because a control trusted past its reach is worse than no control.

    It answers one question -- "can this be released on evidence?" -- and it is deliberately weaker
    than a human reading each case. Measured against a 14-agent hand investigation of the same 33
    stranded claims on 2026-08-16: that pass judged 16 releasable, this tool judges 3. Every one of
    its 3 is inside the 16; the other 13 need evidence this cannot gather:

      * work that landed under a DIFFERENT head -- #1097's fix merged as PR #343 from
        `claude/1097-1064-gate-family`, not from the `g1097` the claim names;
      * a squash whose PR head OID no longer equals the branch tip, because the branch took a later
        merge from main -- true of five claims sharing one squash-merged seat branch here;
      * content-level equivalence -- byte-identical blobs on both sides, which is how the hand pass
        proved several of these and is not a rule that survives being automated.

    So a HOLD from this tool means "not provable here", NOT "unmerged". It never means the reverse.
    Read the report as a floor on what is safe to release and never as a ceiling on what has landed.

    THE HOLDER-PRESENT ARM (BACKLOG #1784). Everything above is about a holder that is GONE. The
    commoner stale claim is the other shape: the holder worktree still exists and its pull request has
    merged, because a session ends when its pull request opens and nothing downstream reads the merge.
    That row measured it on 2026-09-16: 16 of 35 claims were held by a directory that still existed,
    and four of those named a pull request that had already merged. Each one read as live work.

    Such a claim is RELEASABLE only when ALL of these hold, and every one is checked. The local
    ones run first, so a holder that is plainly still in use costs no GitHub call:

      * the holder is a registered worktree of this repository, on the branch the claim names;
      * the claim's key is numeric, because only a numeric key can be named by a pull request;
      * the holder has no uncommitted change and no untracked file, whatever status.showUntrackedFiles
        says, and is not locked (`git worktree lock`);
      * the occupancy fence (occupancy.ps1) is AVAILABLE and places no live or unverifiable session in
        the holder or in a worktree nested inside it. The fence can only veto, never authorise;
      * a pull request MERGED INTO main carries the holder's exact tip -- as its head, or, for a
        Manager's wave pull request that merged several builder branches, as one of its commits. The
        search only finds candidates; the proof is that pull request's own commit list, matched on the
        full oid. A squash leaves no ancestry on main, so this is the only merge evidence this arm
        accepts. A pull request merged into any other base proves nothing about main;
      * that pull request names the claim's key in the house form, `BACKLOG #<key>`, where any `#N`
        after a BACKLOG token on the same line counts (claim_check.py reads commit subjects the same
        way). A bare `#N` is not enough: on the engine repository it is as often a pull request number.
        A tip is evidence about a branch, and a branch is not the unit a claim is about. One worktree
        can hold several keys, and a worktree stacked on another builder's tip carries that builder's
        merged tip before it does any work of its own. When several merged pull requests carry the
        tip, the one naming the key is the one that counts;
      * the claim was taken, and last re-taken with a note (`refreshed`), BEFORE that pull request
        merged. A claim asserted afterwards guards later work, and the tip proves nothing about it.
        Every instant is a recorded one; no clock is read.

    CONTAINMENT IN origin/main IS DELIBERATELY NOT EVIDENCE HERE. A brand-new worktree has zero
    commits, so it is "contained in main" and clean from the second it is created -- exactly the
    state of a claim taken a minute ago for work not yet started. prune-merged's header records the
    same trap. A holder with merge proof that fails the naming or ordering condition is MERGED-HELD,
    with its reasons, and is never touched. Any other holder stays HELD and unlisted, as before.

    -Apply RE-CHECKS A PRESENT HOLDER just before it releases one, because unlike a gone holder it can
    still move. The re-check runs every local condition again against a re-read claim file, a fresh
    worktree list and a fresh fence, reusing only the merge evidence. The release itself then goes
    through `claim.ps1 -Release <key> -AsWorktree <holder>` WITHOUT -Force, so claim.ps1 re-tests that
    the holder still owns the key in its own process, immediately before it removes the file. The
    release record therefore reads like the holder's own release, with force false; `invoked_from`
    names the tree this ran from. Releases happen BEFORE the report is printed, so every releasable row
    carries its outcome and the report never names a release that did not happen.

    WHAT THIS ARM CANNOT SEE, stated because a control trusted past its reach is worse than none:

      * A MANAGER'S SUBAGENT BUILDERS, which are how most work here is done. A subagent has no session
        record of its own. The only record is its Manager's, whose cwd is the Manager's worktree, so a
        builder's worktree always reads UNOCCUPIED to the fence. What protects a running builder is the
        rest of the list: before its pull request merges it has no merge proof, and once it edits
        anything its tree is dirty.
      * A session re-asserting a claim after the merge with a bare `claim.ps1 -Take <key>`. On a key it
        already holds, claim.ps1 writes nothing unless a -Note is given, so no stamp records it.
      * A MULTI-SLICE ITEM. A pull request that lands one slice of an item names the item's key, so a
        claim held for the rest of that item reads as finished. The item's ledger banner is what
        protects the remaining slices, as it is for every closed claim.
      * A pull request that names the key only to say it was NOT done ("dropped BACKLOG #N").

    In each case the release costs a key, never work: the merge proof says every commit the holder
    carries is already merged.

.EXAMPLE
    pwsh -NoProfile -File scripts\coord\claim-reconcile.ps1
    pwsh -NoProfile -File scripts\coord\claim-reconcile.ps1 -Json
    pwsh -NoProfile -File scripts\coord\claim-reconcile.ps1 -Apply
#>
[CmdletBinding()]
param(
    # Release the claims classified RELEASABLE. Without it this tool writes nothing at all.
    [switch]$Apply,
    # Machine-readable output for a caller that wants to act on the classification.
    [switch]$Json,
    # Skip the GitHub probe. Without it a squash-merged branch reads as unmerged forever, because a
    # squash leaves NO commit in common: measured here, a branch squash-merged as PR #346 still
    # carries 13 commits origin/main lacks, and its five claims all read HOLD on the local test alone.
    [switch]$NoPullRequests,
    # The probe itself, injectable so a test can stub it -- the pattern test_announce_hook.py uses
    # for presence.ps1. Must accept `pr list --head <branch> --state merged --json ...` and, for the
    # holder-present arm, `pr list --repo --base --head|--search`, and `pr view <n> --repo --json commits`.
    [string]$GhCommand = "gh",
    # Audit a set of claims that is not the live registry. Exists for one job: replaying these rules
    # over claims that have ALREADY been released, reconstructed from claims/.history, so a release
    # somebody else performed can be cross-checked by a different instrument without writing a second
    # copy of these rules. A second implementation of a rule is two rules by the end of the week.
    [string]$ClaimsDir = "",
    # Scope the occupancy fence to these Claude config roots instead of every one under the user
    # profile. It exists for tests; a live run leaves it unset so the real session registry is read.
    [string[]]$ConfigRoot
)

$ErrorActionPreference = "Stop"

# -ClaimsDir exists to AUDIT a reconstructed copy, and a release always lands in the LIVE registry,
# because claim.ps1 resolves its own. Together they would judge one file and delete another.
if ($Apply -and $ClaimsDir) {
    Write-Host "REFUSED: -Apply with -ClaimsDir. -ClaimsDir audits a copy; a release would delete the LIVE claim with the same key." -ForegroundColor Red
    exit 2
}

# Anchored on the SCRIPT, not the caller's directory -- the reasoning is written out at the head of
# alloc.ps1 and claim.ps1, and it applies identically: this must resolve the repo it belongs to even
# when invoked by absolute path from another worktree.
$repo = (& git -C $PSScriptRoot rev-parse --path-format=absolute --show-toplevel 2>$null)
if (-not $repo) { throw "scripts/coord/ is not inside a git repository: $PSScriptRoot" }
$repo = $repo.Trim()
$common = (& git -C $repo rev-parse --path-format=absolute --git-common-dir).Trim()
$claimsDir = if ($ClaimsDir) { $ClaimsDir } else { Join-Path $common "mefor-coord/claims" }
$claimTool = Join-Path $PSScriptRoot "claim.ps1"

function ConvertTo-Norm([string]$Path) {
    if (-not $Path) { return "" }
    ($Path -replace '\\', '/').TrimEnd('/').ToLowerInvariant()
}

# The occupancy fence, for the holder-present arm only. ONE copy of the matcher, shared with
# presence.ps1 and prune-merged.ps1; occupancy.ps1 says why a second copy is the one that drifts. It
# defines a ConvertTo-Norm identical to the one above. Loaded at script scope because functions
# sourced inside a function do not survive it. If it cannot load, the fence reads UNAVAILABLE, and
# that holds every holder-present claim rather than clearing one.
$occupancyTool = Join-Path $PSScriptRoot "occupancy.ps1"
$occupancyLoadError = ""
if (Test-Path -LiteralPath $occupancyTool) {
    try { . $occupancyTool } catch { $occupancyLoadError = "occupancy.ps1 failed to load: $($_.Exception.Message)" }
}
else { $occupancyLoadError = "occupancy.ps1 is not beside this script" }

if (-not (Test-Path -LiteralPath $claimsDir)) {
    # NEVER LOOKED is not CLEAN -- the same rule prune-merged applies to this directory. A tidy
    # report over a directory that was never read is the silence this tool exists to remove.
    if ($Json) { [pscustomobject]@{ scanned = $false; claims = @() } | ConvertTo-Json -Depth 5 }
    else { Write-Host "No claims directory at $claimsDir -- nothing was scanned." -ForegroundColor Yellow }
    exit 0
}

# The REGISTERED worktrees, which is a different set from the directories that exist. `git worktree
# list` reports registrations: a deleted directory can still be listed until somebody prunes it, and
# a claim pointing at one of those is NOT safe to release -- the registration is the evidence that
# the removal was never completed, and completing it is prune-merged's job, not this tool's.
#
# `git worktree lock` is git's own "in use" flag. prune-merged honours it, and so does the
# holder-present arm: a locked holder is never released on a merge, however clean it looks.
function Read-WorktreeRegistry {
    $reg = @{}; $lock = @{}; $last = ""
    foreach ($line in (& git -C $repo worktree list --porcelain)) {
        if ($line -like 'worktree *') { $last = ConvertTo-Norm $line.Substring(9); $reg[$last] = $true }
        elseif ($last -and ($line -eq 'locked' -or $line -like 'locked *')) { $lock[$last] = $true }
    }
    return @{ Registered = $reg; Locked = $lock }
}
$wtRegistry = Read-WorktreeRegistry
$registered = $wtRegistry.Registered
$locked = $wtRegistry.Locked

# origin/main is the reference, never local main. Measured 2026-08-16: local main was 24 commits
# behind origin/main on this clone, and every "not merged" verdict taken against it would have been
# wrong in the direction that keeps a claim alive -- safe here, but wrong, and the same habit read
# the other way releases work that has not landed.
$mainRef = if ((& git -C $repo rev-parse --verify --quiet "origin/main")) { "origin/main" } else { "main" }

# THE THIRD ARM, and prune-merged.ps1 already has it: "a merged PR whose head is this exact tip".
# Requiring the EXACT tip is the point. A merged PR whose head has since moved proves that some
# earlier state landed, which is not the state the claim is guarding, and releasing on it would be
# the confident-wrong answer this tool exists to avoid. A near miss is reported, never released.
$ghAvailable = $false
if (-not $NoPullRequests) {
    $ghAvailable = [bool](Get-Command $GhCommand -ErrorAction SilentlyContinue)
}
function Test-LandedByPullRequest {
    param([string]$Branch, [string]$Tip)
    if (-not $ghAvailable) { return $null }
    try {
        $raw = & $GhCommand pr list --head $Branch --state merged --json number,headRefOid,mergedAt,mergeCommit --limit 5 2>$null
        if ($LASTEXITCODE -ne 0 -or -not $raw) { return $null }
        $prs = @($raw | ConvertFrom-Json)
        foreach ($pr in $prs) {
            if ($pr.headRefOid -and $Tip -and $pr.headRefOid -eq $Tip) {
                return [pscustomobject]@{ Number = $pr.number; MergedAt = $pr.mergedAt; ExactTip = $true; Landing = "" }
            }
        }
        # No PR at this exact tip. Return the most recent merged one anyway, carrying its LANDING
        # commit: the tip may have moved after the merge (a later merge from main is the common
        # cause), and the landing commit is what the fourth arm compares against.
        if ($prs.Count) {
            $best = $prs[0]
            return [pscustomobject]@{ Number = $best.number; MergedAt = $best.mergedAt
                ExactTip = $false; Landing = [string]$best.mergeCommit.oid }
        }
        return $false
    }
    catch { return $null }   # could not ask; NOT the same as "no PR", and must not read like it
}

# ConvertFrom-Json coerces an ISO-8601 string into a [datetime] (claim.ps1's ConvertTo-Stamp records
# the same trap), so a claim's stamps and a PR's `mergedAt` can each arrive in either shape. Compare
# them as offsets, never as local wall-clock text. $null means unreadable, and the caller holds on it.
function ConvertTo-Instant($Value) {
    if ($Value -is [datetimeoffset]) { return $Value }
    if ($Value -is [datetime]) { return [datetimeoffset]$Value }
    $parsed = [datetimeoffset]::MinValue
    if ($Value -and [datetimeoffset]::TryParse([string]$Value, [Globalization.CultureInfo]::InvariantCulture,
            [Globalization.DateTimeStyles]::AssumeUniversal, [ref]$parsed)) { return $parsed }
    return $null
}

function ConvertFrom-GhJson($Raw) {
    if (-not $Raw) { return @() }
    return @((@($Raw) -join "`n") | ConvertFrom-Json)
}

# The holder-present arm scopes every GitHub call with --repo. Without it gh answers from the caller's
# cwd or its default-repo setting, and this script is run by absolute path from other checkouts -- the
# vault shares engine history and has pull requests of its own. prune-merged.ps1 scopes the same way
# for the same reason. No GitHub origin means the question cannot be asked, and the claim is held.
$ghRepo = ""
$originUrl = (& git -C $repo remote get-url origin 2>$null)
if ($originUrl -and ([string]$originUrl) -match '^(?:https?://[^/@]*@?[^/]*github\.com/|git@github\.com:|ssh://git@github\.com/)(?<o>[^/]+)/(?<r>[^/]+?)(?:\.git)?/?$') {
    $ghRepo = "$($Matches['o'])/$($Matches['r'])"
}
# The base a pull request must have merged INTO for its merge to say anything about $mainRef.
$baseBranch = $mainRef -replace '^origin/', ''

function New-PrEvidence($Pr, [string]$As) {
    [pscustomobject]@{ Number = $Pr.number; MergedAt = $Pr.mergedAt; As = $As; Text = "$($Pr.title)`n$($Pr.body)" }
}

# Does the pull request name this claim's key in the house form? claim_check.py's reading of a commit
# subject, applied per line: a BACKLOG token, then any `#N` after it on the same line, so
# "(BACKLOG #1927, #1928)" names both. A bare `#N` does not count -- on the engine repository it is as
# often a pull request number. A free-text key can never be named, and returns $false.
function Test-PullRequestNamesKey([string]$Key, [string]$Text) {
    if ($Key -notmatch '^\d+$' -or -not $Text) { return $false }
    foreach ($line in ($Text -split "`n")) {
        $m = [regex]::Match($line, '(?i)(?<![A-Za-z0-9_])BACKLOG(?![A-Za-z0-9_])')
        if (-not $m.Success) { continue }
        foreach ($item in [regex]::Matches($line.Substring($m.Index), '#([0-9]{1,5})(?![0-9A-Za-z_])')) {
            if ($item.Groups[1].Value -eq $Key) { return $true }
        }
    }
    return $false
}

# Which pull request MERGED INTO main carries this exact tip, preferring one that names the key.
# The same three-way answer Test-LandedByPullRequest gives, for the same reason: a row is evidence,
# $false is "asked, and found none", and $null is "could not ask", which must never read like the
# second. When some candidate could not be read and none that could names the key, the answer is
# $null: the unread one might have named it.
function Find-MergedPullRequestCarrying {
    param([string]$Branch, [string]$Tip, [string]$Key)
    if (-not $ghAvailable -or -not $ghRepo -or -not $Tip) { return $null }
    $fields = "number,headRefOid,mergedAt,baseRefName,title,body"
    $carrying = @()
    $unasked = $false
    try {
        $raw = & $GhCommand pr list --repo $ghRepo --head $Branch --base $baseBranch --state merged --json $fields --limit 20 2>$null
        if ($LASTEXITCODE -ne 0) { return $null }
        foreach ($pr in @(ConvertFrom-GhJson $raw)) {
            if ($pr.baseRefName -eq $baseBranch -and $pr.headRefOid -eq $Tip) { $carrying += New-PrEvidence $pr "its head" }
        }
        $named = @($carrying | Where-Object { Test-PullRequestNamesKey -Key $Key -Text $_.Text }) | Select-Object -First 1
        if ($named) { return $named }
        # A Manager cuts one pull request per wave from several builder branches (CLAUDE.md section
        # 5), so a builder's tip is one of that pull request's commits and never its head, and a
        # --head lookup by the builder's branch finds nothing. The search only finds candidates. The
        # proof is the candidate's own commit list, matched on the full oid.
        $raw = & $GhCommand pr list --repo $ghRepo --base $baseBranch --state merged --search $Tip --json $fields --limit 5 2>$null
        if ($LASTEXITCODE -ne 0) { $unasked = $true; $raw = $null }
        foreach ($pr in @(ConvertFrom-GhJson $raw)) {
            if ($pr.baseRefName -ne $baseBranch) { continue }
            if (@($carrying | Where-Object { $_.Number -eq $pr.number }).Count) { continue }
            if ($pr.headRefOid -eq $Tip) { $carrying += New-PrEvidence $pr "its head"; continue }
            $view = & $GhCommand pr view $pr.number --repo $ghRepo --json commits 2>$null
            if ($LASTEXITCODE -ne 0 -or -not $view) { $unasked = $true; continue }
            $oids = @(@(ConvertFrom-GhJson $view) | ForEach-Object { $_.commits } | ForEach-Object { [string]$_.oid })
            if ($oids -contains $Tip) { $carrying += New-PrEvidence $pr "one of its $($oids.Count) commits" }
        }
    }
    catch { return $null }
    $named = @($carrying | Where-Object { Test-PullRequestNamesKey -Key $Key -Text $_.Text }) | Select-Object -First 1
    if ($named) { return $named }
    if ($unasked) { return $null }
    if ($carrying.Count) { return $carrying[0] }
    return $false
}

# The fence, read once per scan and read AGAIN by each -Apply re-check (Reset-Fence), because the
# re-check exists to see a session that arrived after the scan.
$script:fence = $null
function Get-Fence {
    if ($null -ne $script:fence) { return $script:fence }
    if ($occupancyLoadError) {
        $script:fence = [pscustomobject]@{ Available = $false; Detail = $occupancyLoadError }
    }
    else {
        try { $script:fence = Get-WorktreeOccupancy -Repo $repo -ConfigRoot $ConfigRoot }
        catch { $script:fence = [pscustomobject]@{ Available = $false; Detail = "the fence threw: $($_.Exception.Message)" } }
    }
    return $script:fence
}
function Reset-Fence { $script:fence = $null }

# Untracked files count. They are the one kind of work git holds nowhere else, and a new module a
# session has not yet added is exactly what a claim guards. --untracked-files=all makes that true
# whatever status.showUntrackedFiles is set to. Fails closed: an unreadable status is never "clean".
function Get-HolderDirt([string]$Path) {
    $status = @(& git -C $Path --no-optional-locks status --porcelain --untracked-files=all 2>$null)
    if ($LASTEXITCODE -ne 0) { return "git status failed in the holder (exit $LASTEXITCODE), so it cannot be shown clean" }
    if ($status.Count) { return "the holder has $($status.Count) uncommitted change(s) or untracked file(s)" }
    return ""
}

# The holder-present arm (BACKLOG #1784). The header lists its conditions in this order and says why
# containment in main is not one of them. ONE predicate, used by the scan and by the -Apply re-check,
# so the two cannot disagree. -KnownPr is the re-check's: it reuses the scan's merge evidence rather
# than asking GitHub again, and re-runs everything local.
function Get-PresentHolderVerdict {
    param([object]$Claim, [string]$Key, [string]$Holder, [string]$Branch, [object]$KnownPr = $null)
    $v = [ordered]@{ verdict = "HELD"; why = "holder directory exists"; tip = ""; pr = $null }
    if (-not $registered.ContainsKey($Holder)) {
        $v.why = "holder directory exists but is not a registered worktree of this repository"
        return $v
    }
    if (-not $Branch) { $v.why = "holder directory exists; the claim records no branch"; return $v }
    $current = (& git -C $Holder symbolic-ref --quiet --short HEAD 2>$null)
    $current = if ($current) { ([string]$current).Trim() } else { "" }
    if ($current -ne $Branch) {
        $on = if ($current) { "'$current'" } else { "a detached HEAD" }
        $v.why = "holder directory exists and is on $on, not the claimed '$Branch'"
        return $v
    }
    if ($Key -notmatch '^\d+$') {
        $v.why = "holder directory exists; a free-text key cannot be named by a pull request, so no merge can release it"
        return $v
    }
    $dirt = Get-HolderDirt $Holder
    if ($dirt) { $v.why = "holder directory exists and is in use: $dirt"; return $v }
    if ($locked.ContainsKey($Holder)) { $v.why = "holder directory exists and is locked (git worktree lock)"; return $v }
    $fence = Get-Fence
    if (-not $fence.Available) {
        $v.why = "holder directory exists; the occupancy fence is UNAVAILABLE ($($fence.Detail)), so a session in it cannot be ruled out"
        return $v
    }
    $in = @(Get-WorktreeOccupants -Occupancy $fence -Path $Holder -IncludeNested)
    if ($in.Count) {
        $v.why = "holder directory exists and $($in.Count) session(s) are placed in it or a worktree nested in it ($(@($in | ForEach-Object { $_.State }) -join ', '))"
        return $v
    }
    if ($NoPullRequests -and -not $KnownPr) { $v.why = "holder directory exists; merge probe skipped (-NoPullRequests)"; return $v }
    $tip = (& git -C $Holder rev-parse --verify --quiet HEAD 2>$null)
    if (-not $tip) { $v.why = "holder directory exists; its HEAD could not be read"; return $v }
    $tip = ([string]$tip).Trim()

    $pr = if ($KnownPr) { $KnownPr } else { Find-MergedPullRequestCarrying -Branch $Branch -Tip $tip -Key $Key }
    if ($null -eq $pr) {
        $v.why = "holder directory exists; whether a PR merged into $baseBranch carries its tip could NOT be established"
        return $v
    }
    if ($pr -isnot [pscustomobject]) {
        $v.why = "holder directory exists; found no PR merged into $baseBranch carrying its tip $($tip.Substring(0, 9))"
        return $v
    }

    $blocks = @()
    if (-not (Test-PullRequestNamesKey -Key $Key -Text $pr.Text)) {
        $blocks += "PR #$($pr.Number) does not name 'BACKLOG #$Key', so nothing ties this claim to that work"
    }
    $mergedAt = ConvertTo-Instant $pr.MergedAt
    foreach ($field in @("claimed", "refreshed")) {
        $raw = $Claim.$field
        if ($field -eq "refreshed" -and -not $raw) { continue }   # never re-taken with a note
        $at = ConvertTo-Instant $raw
        if ($null -eq $at -or $null -eq $mergedAt) {
            $blocks += "the claim's '$field' cannot be ordered against the merge, because a timestamp is unreadable"
        }
        elseif ($at -ge $mergedAt) {
            $blocks += "the claim was $field $($at.ToString('o')), after the merge, so it guards later work"
        }
    }
    $when = if ($mergedAt) { $mergedAt.UtcDateTime.ToString("yyyy-MM-ddTHH:mm:ssZ") } else { [string]$pr.MergedAt }
    $proof = "PR #$($pr.Number) merged into $baseBranch $when carrying this tip ($($tip.Substring(0, 9))) as $($pr.As)"
    if ($blocks.Count) {
        $v.verdict = "MERGED-HELD"
        $v.why = "$proof, but: $($blocks -join '; ')"
    }
    else {
        $v.verdict = "RELEASABLE"
        $v.why = "holder present but finished: $proof and naming BACKLOG #$Key; claimed before the merge; clean, unlocked, no session placed in it"
        $v.tip = $tip
        $v.pr = $pr
    }
    return $v
}

# The -Apply re-check for a holder-present row. Returns "" when the row still stands, otherwise why it
# does not. It re-reads the claim file (another holder, or a new claim under the same key), refreshes
# the worktree list and the fence, and runs the same predicate as the scan with the scan's evidence.
function Test-StillReleasable([object]$Row) {
    $file = $Row.claimFile
    if (-not (Test-Path -LiteralPath $file)) { return "the claim file is gone" }
    try { $c = Get-Content -LiteralPath $file -Raw -EA Stop | ConvertFrom-Json -EA Stop }
    catch { return "the claim file no longer parses" }
    if ((ConvertTo-Norm ([string]$c.worktree)) -ne $Row.holder) { return "the claim is now held by another worktree" }
    $fresh = Read-WorktreeRegistry
    $script:registered = $fresh.Registered
    $script:locked = $fresh.Locked
    Reset-Fence
    $v = Get-PresentHolderVerdict -Claim $c -Key $Row.key -Holder $Row.holder -Branch ([string]$c.branch) -KnownPr $script:prByKey[$Row.key]
    if ($v.verdict -ne "RELEASABLE") { return $v.why }
    if ($v.tip -ne $Row.tip) { return "the holder's tip moved" }
    return ""
}

$rows = @()
$script:prByKey = @{}
foreach ($f in @(Get-ChildItem -LiteralPath $claimsDir -Filter *.json -File -EA SilentlyContinue | Sort-Object Name)) {
    $verdict = "UNKNOWN"; $why = ""; $key = $f.BaseName; $holder = ""; $branch = ""

    try { $c = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop }
    catch {
        # An unreadable claim belongs to the registry, not to any worktree. It is reported and never
        # released: we could not read whose it is, and claim_check.py reads a malformed claim as
        # UNCLAIMED, so the key is already ungated -- deleting the file would hide that, not fix it.
        $rows += [pscustomobject]@{ key = $key; holder = ""; branch = ""; note = ""; verdict = "UNREADABLE"; why = $_.Exception.Message }
        continue
    }

    $key = if ($c.key) { [string]$c.key } else { $f.BaseName }
    $holder = ConvertTo-Norm ([string]$c.worktree)
    $branch = [string]$c.branch
    $note = [string]$c.note

    if (-not $holder) {
        $rows += [pscustomobject]@{ key = $key; holder = ""; branch = $branch; note = $note; verdict = "UNKNOWN"; why = "claim names no worktree" }
        continue
    }
    if (Test-Path -LiteralPath $holder) {
        $v = Get-PresentHolderVerdict -Claim $c -Key $key -Holder $holder -Branch $branch
        $row = [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = $v.verdict; why = $v.why }
        # What the -Apply re-check re-reads, because this holder can still move. The pull request
        # evidence stays out of the JSON: it is an input to the re-check, not a finding.
        if ($v.tip) {
            $row | Add-Member -NotePropertyName tip -NotePropertyValue $v.tip
            $row | Add-Member -NotePropertyName claimFile -NotePropertyValue $f.FullName
            $script:prByKey[$key] = $v.pr
        }
        $rows += $row
        continue
    }
    if ($registered.ContainsKey($holder)) {
        # Gone from disk but still registered: half a removal. prune-merged completes it and releases
        # the claim as it goes; doing it here would race that and skip its merged/clean proof.
        $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "STRANDED-REGISTERED"
            why = "directory gone but the worktree is still registered -- run prune-merged.ps1, which releases as it removes" }
        continue
    }

    # Holder gone AND deregistered. Now the second half: did the work land?
    if (-not $branch) {
        $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = ""; verdict = "STRANDED-UNKNOWN"
            why = "claim records no branch, so nothing can be proven about its work" }
        continue
    }

    $ref = $null
    foreach ($cand in @($branch, "origin/$branch")) {
        if (& git -C $repo rev-parse --verify --quiet $cand) { $ref = $cand; break }
    }
    if (-not $ref) {
        # The branch is gone everywhere. That is consistent with a squash-merge plus remote deletion,
        # and equally with somebody deleting unmerged work. Both look identical from here, so this is
        # reported rather than released -- the whole point of the tool is to not guess.
        $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "STRANDED-UNKNOWN"
            why = "branch '$branch' exists neither locally nor on origin -- squash-merged or deleted, and those are indistinguishable here" }
        continue
    }

    & git -C $repo merge-base --is-ancestor $ref $mainRef 2>$null
    $contained = ($LASTEXITCODE -eq 0)
    $ahead = [int](& git -C $repo rev-list --count "$mainRef..$ref")

    if ($contained -or $ahead -eq 0) {
        $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "RELEASABLE"
            why = "holder gone and deregistered; '$branch' carries no commit that $mainRef lacks" }
    }
    else {
        $tip = (& git -C $repo rev-parse $ref 2>$null)
        $pr = Test-LandedByPullRequest -Branch $branch -Tip ($tip ? $tip.Trim() : "")
        if ($pr -is [pscustomobject] -and $pr.ExactTip) {
            $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "RELEASABLE"
                why = "holder gone and deregistered; PR #$($pr.Number) merged $($pr.MergedAt) with head at this exact tip -- squashed, so the $ahead commit(s) are the same work" }
        }
        elseif ($pr -is [pscustomobject] -and -not $pr.ExactTip -and $pr.Landing) {
            # ARM FOUR: identical AT THE POINT IT LANDED, not identical to main today.
            #
            # Comparing a branch's files to current origin/main is wrong in the direction that HOLDS
            # work that landed: main moves on, the files get edited again, and a branch merged four
            # days ago stops matching. Measured 2026-08-16 on claude/adr-0158-land -- 0 of 2 files
            # identical to main, while the same blobs are identical to the squash commit 10af48bb
            # that landed them, 400-plus commits back. Both facts are true; only one answers the
            # question. Found by the peer session that measured patch-id and blob identity side by
            # side, and it is the trap underneath the squash trap.
            $landing = $pr.Landing
            $base = (& git -C $repo merge-base $ref $landing 2>$null)
            $touched = @()
            if ($base) { $touched = @(& git -C $repo diff --name-only ($base.Trim()) $ref 2>$null) }
            $identical = $touched.Count -gt 0
            foreach ($f in $touched) {
                $a = (& git -C $repo rev-parse --quiet --verify "${ref}:$f" 2>$null)
                $b = (& git -C $repo rev-parse --quiet --verify "${landing}:$f" 2>$null)
                if (-not $a -or -not $b -or $a -ne $b) { $identical = $false; break }
            }
            if ($identical) {
                $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "RELEASABLE"
                    why = "holder gone and deregistered; PR #$($pr.Number) landed at $($landing.Substring(0,9)) and all $($touched.Count) file(s) this branch touched are byte-identical there" }
            }
            else {
                $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "HOLD"
                    why = "$ahead commit(s) not on $mainRef; PR #$($pr.Number) merged but this tip is not its head and the branch files differ from the landing commit" }
            }
        }
        elseif ($pr -is [pscustomobject]) {
            # A merged PR exists for this head, its tip does not match, and no landing commit could
            # be resolved. That proves an earlier state landed and nothing about this one.
            $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "HOLD"
                why = "$ahead commit(s) on '$branch' not on $mainRef; PR #$($pr.Number) merged at a different tip and its landing commit could not be read" }
        }
        elseif ($null -eq $pr -and -not $NoPullRequests) {
            # HOLD, not UNKNOWN. The local evidence already proves work exists here; a probe that
            # could not run only means the verdict cannot be UPGRADED to releasable. Downgrading a
            # proven hold to "could not tell" would lose the one fact we do have.
            $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "HOLD"
                why = "$ahead commit(s) on '$branch' are not on $mainRef; PR state could NOT be established, so a squash-merge cannot be ruled out either" }
        }
        else {
            $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "HOLD"
                why = "$ahead commit(s) on '$branch' are not on $mainRef and no merged PR has this tip -- releasing invites a rebuild of work that exists" }
        }
    }
}


# --- A note can pin work the `worktree` field does not name (found by a peer, 2026-08-16) --------
# Claim 1020 is the live example: its worktree field names a directory that is gone, while its NOTE
# reads "CHECKING w3-l2-auth-policy a46f7a83" and pins the exact head of a DIFFERENT directory that
# is present and carries 4 unmerged commits. Path matching cannot see that association, and neither
# can the three tests above -- 1020 only lands on HOLD because its branch work is unmerged.
#
# The dangerous shape is the other one: a claim whose named holder is gone AND whose branch work HAS
# landed, while its note points at live work somewhere else. That passes all three tests and would be
# released wrongly. So a releasable verdict is withdrawn when its note names a live worktree or a
# commit that origin/main does not contain. This is a REPORT, not a release: the tool cannot read
# intent out of free text and does not try to (FR-009's reasoning, one repository over).
$liveTrees = @()
foreach ($w in $registered.Keys) {
    if (-not (Test-Path -LiteralPath $w)) { continue }
    $head = (& git -C $w rev-parse --verify --quiet HEAD 2>$null)
    $liveTrees += [pscustomobject]@{ Norm = $w; Leaf = (Split-Path $w -Leaf); Head = $(if ($head) { ([string]$head).Trim() } else { "" }) }
}
foreach ($r in @($rows | Where-Object { $_.verdict -eq "RELEASABLE" -and $_.note })) {
    # ELSEWHERE means another worktree. A holder-present claim's own directory is live by definition,
    # and its note routinely names that directory or pins its own work -- the claim describing itself.
    # Without this, every holder-present release whose note did either would be withdrawn.
    $others = @($liveTrees | Where-Object { $_.Norm -ne $r.holder })
    $n = $r.note.ToLowerInvariant()
    # A WHOLE name, not a substring. A substring test reads a note naming `mgr-b147` as naming a live
    # `mgr` too, and the fix of deleting the holder's own name first then hid a live `vanished-2` from
    # a note about gone holder `vanished`. Worktree names here are one another's prefixes by
    # construction, so the boundary is a letter, digit, underscore or hyphen.
    $leaf = @($others | ForEach-Object { $_.Leaf.ToLowerInvariant() } | Where-Object {
            $_ -and [regex]::IsMatch($n, '(?<![A-Za-z0-9_-])' + [regex]::Escape($_) + '(?![A-Za-z0-9_-])')
        }) | Select-Object -First 1
    if ($leaf) {
        $r.verdict = "NOTE-POINTS-ELSEWHERE"
        $r.why = "would be releasable, but its note names '$leaf', a worktree that EXISTS -- read the note before releasing"
        continue
    }
    # No word-boundary anchors, deliberately. This regex is a FILTER and `git rev-parse` below is
    # the gate, so a sloppy match costs one cheap lookup and a tight one cost a literal backspace
    # byte: an earlier edit wrote a backslash-b word boundary into this pattern as a literal 0x08,
    # it matched nothing, and the debug line that "proved" it worked had the pattern retyped by
    # hand -- measuring a different regex than the code ran. The suite now refuses control bytes here.
    foreach ($m in [regex]::Matches($r.note, '[0-9a-f]{7,40}')) {
        $sha = $m.Value
        if (-not (& git -C $repo rev-parse --verify --quiet "$sha^{commit}")) { continue }
        # Already on main? Then it is a reference point, not live work. Notes routinely cite the base
        # they branched from ("based origin/main c5c4108b"), and a base is an ancestor of every live
        # worktree by construction -- so liveness alone flagged 1241 and adr-0158-land on their own
        # base commits. Both halves are needed: NOT on main, and reachable from something alive.
        & git -C $repo merge-base --is-ancestor $sha $mainRef 2>$null
        if ($LASTEXITCODE -eq 0) { continue }
        # REACHABLE FROM LIVE WORK, not merely absent from main. "Not on origin/main" was the first
        # rule here and it was wrong in the common case: a squash leaves the branch's own commits off
        # main forever, so a note citing its own work sha ALWAYS looked like it pointed elsewhere.
        # Measured 2026-08-16 against a peer's release of 11 claims: that rule blocked 1241
        # (3525deca, its own squash-merged branch, no live worktree) and adr-0158-land (0fdc326e, a
        # branch that is on origin), both wrongly -- while the case it exists for, 1010, pins
        # a sha on a branch whose worktree IS alive -- was the one it caught. Two false positives and
        # one true one, and the difference between them is liveness rather than merged-ness.
        foreach ($live in $others) {
            if (-not $live.Head) { continue }
            & git -C $repo merge-base --is-ancestor $sha $live.Head 2>$null
            if ($LASTEXITCODE -eq 0) {
                $r.verdict = "NOTE-POINTS-ELSEWHERE"
                $r.why = "would be releasable, but its note pins $sha, which is reachable from $($live.Leaf) -- a worktree that EXISTS"
                break
            }
        }
        if ($r.verdict -eq "NOTE-POINTS-ELSEWHERE") { break }
    }
}

# -Apply releases BEFORE the report is printed, so each releasable row carries its outcome and the
# report never names a release that did not happen. A holder-present row is re-checked first.
if ($Apply) {
    foreach ($r in @($rows | Where-Object { $_.verdict -eq "RELEASABLE" })) {
        $releaseArgs = @("-Release", $r.key, "-Force")
        if ($r.PSObject.Properties['tip']) {
            $changed = Test-StillReleasable $r
            if ($changed) {
                $r.verdict = "MERGED-HELD"
                $r.why = "$($r.why) -- but changed since the scan, so it was not released: $changed"
                continue
            }
            # -AsWorktree and NO -Force: claim.ps1 re-tests that the holder still owns the key, in its
            # own process, just before it removes the file. -Force would delete whatever claim sits
            # under the key by then, including one somebody else took a moment ago.
            $releaseArgs = @("-Release", $r.key, "-AsWorktree", $r.holder)
        }
        # The ledger writer stays in one place. A gone holder's release needs -Force, because it is
        # held by a worktree that is not this one, which is the condition that defines that set.
        & pwsh -NoProfile -File $claimTool @releaseArgs | Out-Null
        $outcome = if ($LASTEXITCODE -eq 0) { "released" } else { "release FAILED -- claim untouched" }
        $r | Add-Member -NotePropertyName outcome -NotePropertyValue $outcome -Force
    }
}

$releasable = @($rows | Where-Object { $_.verdict -eq "RELEASABLE" })
$hold = @($rows | Where-Object { $_.verdict -eq "HOLD" })
$unknown = @($rows | Where-Object { $_.verdict -in @("STRANDED-UNKNOWN", "STRANDED-REGISTERED", "UNKNOWN", "UNREADABLE", "NOTE-POINTS-ELSEWHERE", "MERGED-HELD") })

if ($Json) {
    [pscustomobject]@{
        scanned    = $true
        reference  = $mainRef
        applied    = [bool]$Apply
        counts     = [pscustomobject]@{
            total = $rows.Count; held = @($rows | Where-Object { $_.verdict -eq "HELD" }).Count
            releasable = $releasable.Count; hold = $hold.Count; unresolved = $unknown.Count
        }
        claims     = $rows
    } | ConvertTo-Json -Depth 5
}
else {
    Write-Host ""
    # The count names its POPULATION and its FILTER. It printed "(N claims)" over a report that
    # silently omits every HELD row, so the header said 30 while the registry held 48 and the JSON
    # said 48 -- a count without its filter, which is the defect this repository keeps finding and
    # the one FR-015 exists for one repository over.
    $shown = $releasable.Count + $hold.Count + $unknown.Count
    Write-Host "Claim reconciliation against $mainRef -- $shown of $($rows.Count) claims shown; $($rows.Count - $shown) held by a directory that still exists and are not listed"
    Write-Host ""
    foreach ($group in @(
            @{ n = "RELEASABLE -- work is on $mainRef (holder gone and deregistered, or holder present and finished)"; v = $releasable; c = "Green" },
            @{ n = "HOLD -- holder gone, but the branch carries work that is NOT on $mainRef"; v = $hold; c = "Red" },
            @{ n = "UNRESOLVED -- reported, never released"; v = $unknown; c = "Yellow" })) {
        if (-not $group.v.Count) { continue }
        Write-Host "  $($group.n) [$($group.v.Count)]" -ForegroundColor $group.c
        foreach ($r in $group.v) {
            $done = if ($r.PSObject.Properties['outcome']) { " [$($r.outcome)]" } else { "" }
            Write-Host ("      {0,-26} {1}{2}" -f $r.key, $r.why, $done)
        }
        Write-Host ""
    }
    if (-not $Apply -and $releasable.Count) {
        Write-Host "  Nothing was changed. Re-run with -Apply to release the $($releasable.Count) above." -ForegroundColor Cyan
        Write-Host ""
    }
}
exit 0
