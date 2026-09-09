# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
# PreCompact hook: put back the facts a compaction destroys.
#
# WHAT A COMPACTION TAKES. The seat, the goal, the brief, which ledger numbers this worktree holds,
# and whether the work is pushed. All of that lives in the conversation, and a compaction summarises
# the conversation. The SessionStart hook (seat-declare-prompt.ps1) asks for a declaration exactly
# once, at session start, and never fires again -- so after a compaction the seat is undeclared IN
# CONTEXT even though it declared perfectly well an hour ago, and it has no idea it is holding an
# unfiled allocation that burns if the worktree is removed.
#
# WHY IT READS RATHER THAN ASKS. At SessionStart the right move is to ask, because nothing is known
# yet and a machine that invents a goal writes a record that looks declared and says nothing. At
# PreCompact the declaration usually ALREADY EXISTS on disk; the compaction is about to drop it from
# context, not from the record. So this hook reads the record back. That is a restatement of a
# stated intent, not an invented one, and the distinction is the same one seat-declare-prompt.ps1
# draws in its own header. Adopted from gastown, which registers its `prime --hook` primer on
# SessionStart AND PreCompact for this reason (BACKLOG #1453).
#
# LEGIBLE SILENCE. If no declaration is found, this hook says so rather than saying nothing, and
# repeats the declare command. "Never declared" and "declared, then compacted away" have opposite
# fixes and must not both render as blank.
#
# THIS HOOK MUST NEVER FAIL THE TURN. It exits 0 on every path.
#
# WIRING IS NOT ASSERTED HERE ON PURPOSE. Whether this script is referenced by a PreCompact matcher
# is a property of settings.json, not of this file.
# See docs/WORKTREES.md.

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

function Write-Context {
    param([string]$Text)
    $payload = [pscustomobject]@{
        hookSpecificOutput = [pscustomobject]@{
            hookEventName     = 'PreCompact'
            additionalContext = $Text
        }
    }
    [Console]::Out.Write(($payload | ConvertTo-Json -Compress -Depth 6))
}

try {
    $common = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
    if ($LASTEXITCODE -ne 0 -or -not $common) { exit 0 }
    $common = $common.Trim()
    $coord = Join-Path $common 'mefor-coord'
    if (-not (Test-Path -LiteralPath $coord)) { exit 0 }

    $top = (& git rev-parse --path-format=absolute --show-toplevel 2>$null)
    if (-not $top) { exit 0 }
    $top = $top.Trim()
    $topNorm = ($top -replace '/', '\').TrimEnd('\')

    $lines = @()

    # Read the branch BEFORE the declaration block: it is the discriminator that decides whether a
    # record found by path actually belongs to this session, not just a fact reported at the end.
    $branchNow = (& git rev-parse --abbrev-ref HEAD 2>$null)
    if ($branchNow) { $branchNow = $branchNow.Trim() }

    # ---- the declaration -------------------------------------------------------------------
    # Newest record for THIS worktree that actually carries a goal. Records are per-episode, so a
    # box can hold many and only some are declared; taking the newest DECLARED one is what restores
    # intent rather than the most recent heartbeat.
    $seatsDir = Join-Path $coord 'seats'
    $declared = $null
    if (Test-Path -LiteralPath $seatsDir) {
        $cands = Get-ChildItem -LiteralPath $seatsDir -Recurse -Filter '*.json' -File -EA SilentlyContinue |
                 Sort-Object LastWriteTimeUtc -Descending
        foreach ($f in $cands) {
            try { $j = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
            $wt = [string]$j.worktree
            if (-not $wt) { continue }
            if (($wt -replace '/', '\').TrimEnd('\') -ne $topNorm) { continue }
            if ($j.PSObject.Properties['goal'] -and $j.goal) { $declared = $j; break }
        }
    }

    if ($declared) {
        # A worktree OUTLIVES the session that declared in it -- directories here get re-used, and a
        # record matched on path alone can be a previous occupant's intent wearing this tree's name.
        # Restoring that as if it were current is worse than restoring nothing, because a stale goal
        # is actionable and reads as authoritative. The branch is the discriminator the fleet already
        # uses for exactly this ("the directory was re-used"), so check it before trusting the goal.
        $declBranch = if ($declared.PSObject.Properties['branch']) { [string]$declared.branch } else { '' }
        $stale = $declBranch -and $branchNow -and ($declBranch -ne $branchNow)

        $age = ''
        if ($declared.PSObject.Properties['declaredAt'] -and $declared.declaredAt) {
            $parsed = [datetime]::MinValue
            if ([datetime]::TryParse([string]$declared.declaredAt, [ref]$parsed)) {
                $days = [math]::Round(((Get-Date) - $parsed).TotalDays, 1)
                $age = " ($days days old)"
            }
        }

        if ($stale) {
            $lines += "SEAT: a declaration exists for this DIRECTORY but it is probably NOT YOURS."
            $lines += "It was declared on branch '$declBranch'$age; this session is on '$branchNow'."
            $lines += "Worktrees get re-used, so treat the following as a previous occupant's intent"
            $lines += "and re-declare rather than adopting it:"
            $lines += "    seat: $($declared.seat)"
            $lines += "    goal: $($declared.goal)"
            $lines += '    pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <role> -Goal "<one line>"'
        } else {
            $lines += "SEAT: $($declared.seat)"
            $lines += "GOAL: $($declared.goal)"
            if ($declared.PSObject.Properties['done'] -and $declared.done) { $lines += "DONE WHEN: $($declared.done)" }
            if ($declared.PSObject.Properties['outOfScope'] -and $declared.outOfScope) { $lines += "OUT OF SCOPE: $($declared.outOfScope)" }
            if ($age) { $lines += "declared at $($declared.declaredAt)$age" }
        }
    } else {
        $lines += "SEAT: not declared. Nothing on disk carries a goal for this worktree, so this is the"
        $lines += "'never asked or never answered' case, NOT a goal lost to compaction. Declare one:"
        $lines += '    pwsh -NoProfile -File scripts\coord\seat.ps1 -Declare -Seat <role> -Goal "<one line>"'
    }

    # ---- ledger numbers this worktree holds ------------------------------------------------
    # This is the fact with a permanent cost attached. An allocated-but-unfiled number burns if the
    # worktree is removed, and after a compaction nobody in the session remembers holding one.
    $allocDir = Join-Path $coord 'alloc'
    $held = @()
    if (Test-Path -LiteralPath $allocDir) {
        foreach ($f in (Get-ChildItem -LiteralPath $allocDir -Recurse -Filter '*.json' -File -EA SilentlyContinue)) {
            try { $a = Get-Content -LiteralPath $f.FullName -Raw -EA Stop | ConvertFrom-Json -EA Stop } catch { continue }
            $aw = [string]$a.worktree
            if (-not $aw) { continue }
            # EXACT match, never a prefix. Sibling worktrees in this repo are named as extensions of
            # each other (...-cfbf59 and ...-cfbf59-connscale-ci-claim), so a prefix test claims another
            # tree's numbers as your own.
            if (($aw -replace '/', '\').TrimEnd('\') -ne $topNorm) { continue }
            $held += "#$($a.number) ($($a.kind)) $($a.title)"
        }
    }
    if ($held.Count -gt 0) {
        $lines += ''
        $lines += "LEDGER NUMBERS THIS WORKTREE HOLDS -- these burn permanently if the tree is removed"
        $lines += "with raw git rather than scripts/worktree/remove.ps1:"
        foreach ($h in $held) { $lines += "    $h" }
    }

    # ---- is the work safe ------------------------------------------------------------------
    $dirty = @(& git status --porcelain 2>$null | Where-Object { $_ }).Count
    $unpushed = (& git rev-list --count HEAD --not --remotes --tags 2>$null)
    $lines += ''
    $lines += "BRANCH: $($branchNow) -- $dirty uncommitted file(s), $unpushed commit(s) on no remote or tag."
    if ([int]($unpushed | ForEach-Object { $_ }) -gt 0 -or $dirty -gt 0) {
        $lines += "Commit and push before the context gets any tighter. An unpushed branch is lost work."
    }

    Write-Context ("[precompact] Restoring what this compaction is about to drop.`n" + ($lines -join "`n"))
    exit 0
} catch {
    # Deliberately swallowed. This hook never fails a turn.
    exit 0
}
