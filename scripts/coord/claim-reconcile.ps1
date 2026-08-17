# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    Find work claims whose holder worktree no longer exists, and release ONLY the ones whose work
    demonstrably landed. Reports by default; changes nothing without -Apply.

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
    # for presence.ps1. Must accept: <cmd> pr list --head <branch> --state merged --json ...
    [string]$GhCommand = "gh",
    # Audit a set of claims that is not the live registry. Exists for one job: replaying these rules
    # over claims that have ALREADY been released, reconstructed from claims/.history, so a release
    # somebody else performed can be cross-checked by a different instrument without writing a second
    # copy of these rules. A second implementation of a rule is two rules by the end of the week.
    [string]$ClaimsDir = ""
)

$ErrorActionPreference = "Stop"

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
$registered = @{}
foreach ($line in (& git -C $repo worktree list --porcelain)) {
    if ($line -like 'worktree *') { $registered[(ConvertTo-Norm $line.Substring(9))] = $true }
}

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

$rows = @()
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
        $rows += [pscustomobject]@{ key = $key; holder = $holder; branch = $branch; note = $note; verdict = "HELD"; why = "holder directory exists" }
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
$liveLeaves = @()
$liveHeads = @{}
foreach ($w in $registered.Keys) {
    if (-not (Test-Path -LiteralPath $w)) { continue }
    $liveLeaves += (Split-Path $w -Leaf).ToLowerInvariant()
    $head = (& git -C $w rev-parse --verify --quiet HEAD 2>$null)
    if ($head) { $liveHeads[$head.Trim()] = (Split-Path $w -Leaf) }
}
foreach ($r in @($rows | Where-Object { $_.verdict -eq "RELEASABLE" -and $_.note })) {
    $n = $r.note.ToLowerInvariant()
    $leaf = @($liveLeaves | Where-Object { $_ -and $n.Contains($_) }) | Select-Object -First 1
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
        foreach ($live in $liveHeads.Keys) {
            & git -C $repo merge-base --is-ancestor $sha $live 2>$null
            if ($LASTEXITCODE -eq 0) {
                $r.verdict = "NOTE-POINTS-ELSEWHERE"
                $r.why = "would be releasable, but its note pins $sha, which is reachable from $($liveHeads[$live]) -- a worktree that EXISTS"
                break
            }
        }
        if ($r.verdict -eq "NOTE-POINTS-ELSEWHERE") { break }
    }
}

$releasable = @($rows | Where-Object { $_.verdict -eq "RELEASABLE" })
$hold = @($rows | Where-Object { $_.verdict -eq "HOLD" })
$unknown = @($rows | Where-Object { $_.verdict -in @("STRANDED-UNKNOWN", "STRANDED-REGISTERED", "UNKNOWN", "UNREADABLE", "NOTE-POINTS-ELSEWHERE") })

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
            @{ n = "RELEASABLE -- holder gone, deregistered, work is on $mainRef"; v = $releasable; c = "Green" },
            @{ n = "HOLD -- holder gone, but the branch carries work that is NOT on $mainRef"; v = $hold; c = "Red" },
            @{ n = "UNRESOLVED -- reported, never released"; v = $unknown; c = "Yellow" })) {
        if (-not $group.v.Count) { continue }
        Write-Host "  $($group.n) [$($group.v.Count)]" -ForegroundColor $group.c
        foreach ($r in $group.v) { Write-Host ("      {0,-26} {1}" -f $r.key, $r.why) }
        Write-Host ""
    }
    if (-not $Apply -and $releasable.Count) {
        Write-Host "  Nothing was changed. Re-run with -Apply to release the $($releasable.Count) above." -ForegroundColor Cyan
        Write-Host ""
    }
}

if (-not $Apply) { exit 0 }

foreach ($r in $releasable) {
    # The ledger writer stays in one place. -Force is required because every one of these is held by
    # a worktree that is not this one, which is the condition that defines the set.
    & pwsh -NoProfile -File $claimTool -Release $r.key -Force | Out-Null
    if ($LASTEXITCODE -ne 0) { Write-Host "  release FAILED for '$($r.key)' -- claim untouched" -ForegroundColor Red }
    else { Write-Host "  released $($r.key)" -ForegroundColor Green }
}
exit 0
