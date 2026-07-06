<#
.SYNOPSIS
    Prune sibling git worktrees whose PR is merged AND working tree is clean.

.DESCRIPTION
    Automates the recurring cleanup so finished worktrees don't pile up. Enumerates the
    <repo>-<name> sibling worktrees that new.ps1 creates, and for each that is BOTH:
      (a) clean   — no uncommitted *tracked* changes (the untracked .venv / node_modules are fine), and
      (b) merged  — its PR is merged (via gh), OR its tip is an ancestor of origin/main, OR its
                    upstream branch is gone (the remote branch was deleted, i.e. squash-merged),
    it removes the worktree and deletes the now-merged local branch.

    DRY-RUN by default: prints a table of PRUNE / SKIP decisions and does nothing. Pass -Apply to act.

    NEVER touches: the primary checkout, the current worktree, the .claude/worktrees Claude-managed
    worktrees, the Temp-scratchpad worktrees, or the separate sibling REPOS living beside this one
    (the public mirror, any config repos, the website, unrelated projects) — those aren't worktrees of
    this .git, so they never appear in `git worktree list`. Run from the MAIN checkout (git can't
    remove the worktree you're standing in). See docs/WORKTREES.md and AI memory: mf-worktree-hygiene.

.EXAMPLE
    scripts\worktree\prune-merged.ps1              # dry run: show which merged+clean siblings would go
    scripts\worktree\prune-merged.ps1 -Apply       # actually remove them + delete the merged branches
    scripts\worktree\prune-merged.ps1 -Apply -SkipFetch   # skip the network fetch (offline / faster)
#>
[CmdletBinding()]
param(
    [switch]$Apply,       # actually remove; default is a dry run
    [switch]$SkipFetch    # skip the `git fetch --prune` (offline / speed)
)

$ErrorActionPreference = "Stop"

$RepoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..\..")).Path
$RepoRootFwd = ($RepoRoot -replace '\\', '/')

# Refresh origin/main and mark deleted remote branches [gone], so squash-merged branches are detected.
if (-not $SkipFetch) {
    Write-Host "Fetching origin (--prune)..." -ForegroundColor DarkGray
    & git -C $RepoRoot fetch origin --prune --quiet
}

$hasGh = [bool](Get-Command gh -ErrorAction SilentlyContinue)

# Enumerate linked worktrees via porcelain (robust to spaces in paths).
$porcelain = & git -C $RepoRoot worktree list --porcelain
$entries = @()
$cur = $null
foreach ($line in $porcelain) {
    if ($line -match '^worktree (.+)$') {
        if ($cur) { $entries += [pscustomobject]$cur }
        $cur = @{ Path = $Matches[1]; Branch = $null; Bare = $false; Detached = $false }
    }
    elseif ($line -match '^branch refs/heads/(.+)$') { $cur.Branch = $Matches[1] }
    elseif ($line -eq 'bare') { $cur.Bare = $true }
    elseif ($line -eq 'detached') { $cur.Detached = $true }
}
if ($cur) { $entries += [pscustomobject]$cur }

# Keep only the <repo>-<name> siblings new.ps1 makes; this naturally drops the primary/current
# checkout, the .claude/worktrees and Temp worktrees, and anything detached/bare.
$siblings = @($entries | Where-Object {
        (($_.Path -replace '\\', '/') -like "$RepoRootFwd-*") -and $_.Branch -and -not $_.Bare -and -not $_.Detached
    })

if ($siblings.Count -eq 0) {
    Write-Host "No <repo>-<name> sibling worktrees to consider." -ForegroundColor Green
    return
}

function Test-Merged {
    param([string]$Branch)
    # 1) A merged PR is the strongest signal (catches squash-merges) — use gh when available.
    if ($hasGh) {
        $n = & gh pr list --head $Branch --state merged --json number --jq 'length' 2>$null
        if ($LASTEXITCODE -eq 0 -and $n -and ([int]$n) -gt 0) { return @{ Merged = $true; Reason = 'PR merged' } }
    }
    # 2) Tip is an ancestor of origin/main (plain merge / fast-forward).
    & git -C $RepoRoot merge-base --is-ancestor "refs/heads/$Branch" origin/main 2>$null
    if ($LASTEXITCODE -eq 0) { return @{ Merged = $true; Reason = 'ancestor of origin/main' } }
    # 3) Upstream gone: the remote branch was deleted (typical after a squash-merge + auto-delete).
    $track = (& git -C $RepoRoot for-each-ref --format '%(upstream:track)' "refs/heads/$Branch" 2>$null)
    if ($track -match 'gone') { return @{ Merged = $true; Reason = 'upstream gone (merged + remote-deleted)' } }
    return @{ Merged = $false; Reason = 'no merge signal' }
}

Write-Host ""
Write-Host ("{0,-42} {1,-34} {2}" -f 'WORKTREE', 'BRANCH', 'DECISION')
Write-Host ("{0,-42} {1,-34} {2}" -f ('-' * 40), ('-' * 32), ('-' * 24))

$toRemove = @()
foreach ($s in $siblings) {
    # Clean = no tracked changes. Untracked entries (??) — .venv, node_modules, dev db — are expected.
    $tracked = & git -C $s.Path status --porcelain 2>$null | Where-Object { $_ -notmatch '^\?\?' }
    $clean = -not $tracked
    $m = Test-Merged -Branch $s.Branch

    if (-not $clean) { $decision = 'SKIP  - dirty (uncommitted tracked changes)' }
    elseif (-not $m.Merged) { $decision = "SKIP  - not merged ($($m.Reason))" }
    else { $decision = "PRUNE - $($m.Reason)"; $toRemove += $s }

    Write-Host ("{0,-42} {1,-34} {2}" -f (Split-Path $s.Path -Leaf), $s.Branch, $decision)
}

if ($toRemove.Count -eq 0) {
    Write-Host "`nNothing to prune." -ForegroundColor Green
    return
}

if (-not $Apply) {
    Write-Host "`nDRY RUN - $($toRemove.Count) worktree(s) would be removed. Re-run with -Apply to act." -ForegroundColor Yellow
    return
}

Write-Host ""
foreach ($s in $toRemove) {
    $leaf = Split-Path $s.Path -Leaf
    Write-Host "Removing $leaf [$($s.Branch)]..." -ForegroundColor Cyan
    # --force is needed regardless: the untracked .venv makes git consider the worktree non-empty.
    & git -C $RepoRoot worktree remove --force $s.Path
    if ($LASTEXITCODE -ne 0) { Write-Warning "  worktree remove failed for $leaf; leaving its branch alone."; continue }
    # -d first (safe); fall back to -D since we've already confirmed the branch is merged.
    & git -C $RepoRoot branch -d $s.Branch 2>$null
    if ($LASTEXITCODE -ne 0) { & git -C $RepoRoot branch -D $s.Branch }
}
& git -C $RepoRoot worktree prune

Write-Host "`nDone. Pruned $($toRemove.Count) merged + clean worktree(s)." -ForegroundColor Green
