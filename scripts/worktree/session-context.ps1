# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors
<#
.SYNOPSIS
    SessionStart hook: surface git-worktree coordination to a Claude Code chat.

.DESCRIPTION
    Wired as a SessionStart hook in .claude/settings.json. Whatever this prints to stdout is injected
    into the chat's starting context, so a new window starts already knowing the rules for working
    alongside sibling sessions.

    Parallel-session coordination, printed ONLY when 2+ worktrees share this .git, i.e. when
    parallel build sessions are actually in play and could collide. It also:
      - warns a session that lands in the SHARED PRIMARY (trunk) checkout to branch into its
        own worktree before editing (owner often forgets to say so); and
      - nudges cleanup by counting the <repo>-<name> siblings, pointing at prune-merged.ps1
        so finished worktrees don't pile up.
    See docs/WORKTREES.md and AI memory: mf-worktree-hygiene.

    IT READS THE WORKTREE THE HOOK INPUT NAMES, NOT THE ONE IT RUNS IN. The desktop app starts a
    worktree session's CLI with `--project-config-root <primary checkout>`. Measured 2026-10-12, this
    hook then ran with its directory, CLAUDE_PROJECT_DIR and `git rev-parse` all naming the PRIMARY,
    so it named the primary as a worktree session's own and told it it sat in the shared trunk.

    Only the `cwd` field of the JSON on stdin names the session's worktree. So the hook moves there
    (scripts/hooks/_hookinput.ps1) before its first git call, and presence.ps1, overlap.ps1 and every
    git call below answer for the session. Input with no `cwd` leaves it where it started, as before.
    _hookinput.ps1 holds the rules for which worktree that is. Where they answer with the pinned
    worktree rather than the `cwd`, the banner says so. A `cwd` they refuse, or a helper that is
    missing, becomes the banner's first line, and the banner then describes the checkout the hook
    runs in.
#>
$ErrorActionPreference = "SilentlyContinue"

$lines = @()

# Into the session's own directory BEFORE any git call. Under SilentlyContinue a dot-source of a
# missing file does not throw, so the helper is tested for first and its absence is said aloud.
$cwdFault = ''
$hookInput = Join-Path $PSScriptRoot '../hooks/_hookinput.ps1'
try {
    if (-not (Test-Path -LiteralPath $hookInput -PathType Leaf)) { throw "scripts/hooks/_hookinput.ps1 is missing beside this hook" }
    . $hookInput
    $session = Enter-CcxHookSession -Text (Read-CcxHookInput)
    $cwdFault = $session.Reason
    if ($session.Note) { $lines += "[session-context] $($session.Note)." }
} catch { $cwdFault = "the hook could not read its input ($($_.Exception.Message))" }
if ($cwdFault) {
    $lines += "[session-context] COULD NOT READ THIS SESSION'S WORKTREE: $cwdFault. Everything below describes $((Get-Location).Path), where this hook runs, which may not be your worktree."
}

# Add parallel-session coordination only when 2+ worktrees share this .git (real collision risk).
$root = (& git rev-parse --show-toplevel 2>$null)
if ($root) {
    $wt = @(& git worktree list 2>$null)
    if ($wt.Count -gt 1) {
        $branch = (& git branch --show-current 2>$null)
        # Primary (trunk) checkout vs a linked worktree: the primary's git-dir IS the common dir. A
        # match on 'worktrees' in the git-dir misreads a primary that sits under a directory of that
        # name, once the hook runs from a subdirectory and git prints the path in full.
        $gitDir = (& git rev-parse --path-format=absolute --git-dir 2>$null)
        $commonDir = (& git rev-parse --path-format=absolute --git-common-dir 2>$null)
        # A git that does not answer leaves this UNKNOWN, never "linked": a primary read as a linked
        # worktree loses the warning below, which is the one line this banner most needs to say.
        $isPrimary = $null
        if ($gitDir -and $commonDir) {
            $isPrimary = ("$gitDir".Trim().TrimEnd('/') -ieq "$commonDir".Trim().TrimEnd('/'))
        }

        $lines += ""
        $lines += "[PARALLEL SESSION ($($wt.Count) worktrees active)]"
        $lines += "This chat's worktree: $root  (branch: $branch)"

        if ($null -eq $isPrimary) {
            $lines += ""
            $lines += "  >>> git did not say whether this is the SHARED PRIMARY checkout or your own worktree."
            $lines += "  >>> If it is the primary, create and work in your OWN worktree before substantive edits."
        }

        # Loudest, first: if this session sits in the SHARED trunk, tell it to branch into its own worktree.
        if ($isPrimary) {
            $lines += ""
            $lines += "  >>> You are in the SHARED PRIMARY checkout, where parallel sessions collide."
            $lines += "  >>> Before any substantive edits, create and work in your OWN worktree:"
            $lines += "  >>>     scripts\worktree\new.ps1 -Name <short-task-name>"
            $lines += "  >>> (A trivial one-off read/edit here is fine; anything you'll iterate on gets a worktree.)"
        }

        # HIGH SIGNAL FIRST, AND EVERY LIST CAPPED. The harness injects a hook's output whole only while
        # it is small; past that it saves the output to a file and injects a short preview of the head.
        # Measured 2026-10-22 on a box with 471 worktrees and 155 claims: 128,001 bytes, of which the
        # model saw only the head of the full worktree list, so the peers and claims below never reached
        # it. So the worktree list is now a count and this session's own row, printed last, and each list
        # below names the command that shows the rest. tests/test_session_context_presence.py pins the
        # byte budget.
        $peerCap = 10
        $busyCap = 3
        $claimCap = 10
        $staleHours = 12

        # WHO IS ACTUALLY HERE. The worktree count is the set of checkouts, not the set of live
        # sessions -- most worktrees usually have nobody in them, and the one collision that matters
        # (someone editing the shared primary right now) is invisible from it. presence.ps1 is the only
        # roster that spans surfaces: the Desktop app's own session tooling never registers a session it
        # did not spawn, so a VS Code session working in this repo does not appear in it at all.
        $presence = Join-Path $PSScriptRoot "..\coord\presence.ps1"
        if (Test-Path $presence) {
            $peers = @()
            # A SessionStart hook must never fail loudly: whatever this prints IS the chat's starting
            # context, so a throw here would replace the coordination banner with a stack trace.
            try { $peers = @(& $presence -Json | ConvertFrom-Json) } catch { $peers = @() }

            $others = @($peers | Where-Object { -not $_.IsSelf })
            if ($others.Count -gt 0) {
                $lines += ""
                $lines += "LIVE sessions in this repo right now ($($others.Count) besides you):"
                # LABEL THE ID IN EVERY ROW (BACKLOG #1098). Bare, the 8-hex token reads as an
                # abbreviated commit SHA -- and it reads that way for a concrete reason, not a vague
                # one: the `git worktree list` row this banner prints for your own worktree puts a REAL
                # abbreviated SHA in exactly this shape, before a bracketed branch. It is a registry session id, resolves
                # to no git object, and a session that compared "is that worktree ahead of mine"
                # against it got an error at best and the wrong tree if the prefix happened to resolve.
                # The word goes on the ROW, not in a legend, so the column cannot mean one thing in one
                # row and something else in the next.
                foreach ($p in @($others | Select-Object -First $peerCap)) {
                    $where = if ($p.IsPrimary) { "the SHARED PRIMARY" } else { $p.Worktree }
                    $flag = if ($p.State -ne "LIVE") { "  [$($p.State)]" } else { "" }
                    $lines += "  session $($p.Short)  $($p.Surface)  in $where  [$($p.Branch)]$flag"
                }
                $roster = "pwsh -NoProfile -File scripts\coord\presence.ps1 -All"
                if ($others.Count -gt $peerCap) {
                    $lines += "  +$($others.Count - $peerCap) more (run: $roster)"
                }
                # The two notes below test EVERY peer, not only the rows shown, so a capped row still
                # raises its hazard.
                # The surfaces differ in what can reach them, and that changes how you coordinate.
                if (@($others | Where-Object { $_.Surface -ne "desktop" }).Count -gt 0) {
                    $lines += "  NOTE: a non-desktop (e.g. VS Code) session is live. It cannot be reached by"
                    $lines += "        session messaging -- coordinate through a claim or the PR, not a message."
                }
                if (@($others | Where-Object { $_.IsPrimary }).Count -gt 0) {
                    $lines += "  WARNING: a session is working in the SHARED PRIMARY checkout. Anything you do"
                    $lines += "           there can collide with it -- stay in this worktree."
                }
                if ($others.Count -le $peerCap) { $lines += "  Full roster:  $roster" }
            }

            # WHAT they are building, not just where they are. The roster above prevents you editing
            # the same FILE; this is the only thing that prevents you building the same THING. That is
            # the collision that actually cost this project rework -- three sessions independently
            # fixing one npm advisory, in DIFFERENT files, so nothing file-shaped could have caught it.
            # Sourced from each session's own task list, so no one has to declare anything.
            $overlap = Join-Path $PSScriptRoot "..\coord\overlap.ps1"
            if (Test-Path $overlap) {
                $inflight = @()
                try { $inflight = @(& $overlap -Json | ConvertFrom-Json) } catch { $inflight = @() }
                $busy = @($inflight | Where-Object { $_.Live -and (@($_.Work).Count -gt 0 -or @($_.Files).Count -gt 0) })
                if ($busy.Count -gt 0) {
                    $lines += ""
                    $lines += "WHAT THEY ARE BUILDING -- check before you start, so you don't build it twice:"
                    foreach ($b in @($busy | Select-Object -First $busyCap)) {
                        # Same id, same banner, same label -- see the note on the roster rows above.
                        #
                        # "beyond yours" is not decoration. overlap.ps1's Files narrows its committed
                        # half against the HEAD of whoever asked, so this count is relative to THIS
                        # session and a bare "changed" would overstate what the peer did.
                        $lines += "  session $($b.Short) [$($b.Branch)] -- $(@($b.Files).Count) file(s) changed beyond yours"
                        if (@($b.Work).Count) { $lines += "      $(@($b.Work)[0])" }
                    }
                    if ($busy.Count -gt $busyCap) { $lines += "  +$($busy.Count - $busyCap) more" }
                    $lines += "  Everything in flight:  pwsh -NoProfile -File scripts\coord\overlap.ps1"
                }
            }
        }

        # BACKLOG #309: what the OTHER sessions are building, before you start building it too. The commit-msg
        # claim gate only enforces NUMBERED items; this banner is the whole mechanism for ad-hoc work -- and
        # ad-hoc work is what actually collided (three sessions, one npm advisory, two duplicate PRs).
        #
        # The registry may sit on the shared root (docs/COORD-SHARED-ROOT.md), so coord-root.ps1 names it.
        # This banner only reads: a root that does not answer is one line saying so, never a local guess
        # shown as the fleet's claims.
        $claimDir = $null
        $claimFault = ''
        $coordRootScript = Join-Path $PSScriptRoot '..\coord\coord-root.ps1'
        if (Test-Path -LiteralPath $coordRootScript -PathType Leaf) {
            try {
                . $coordRootScript
                $knownLocal = if ($commonDir) { Join-Path "$commonDir".Trim() 'mefor-coord' } else { '' }
                $resolvedClaims = Resolve-CoordDir -From (Get-Location).Path -Kind 'claims' -LocalRoot $knownLocal
                if ($resolvedClaims.Error) { $claimFault = $resolvedClaims.Error } else { $claimDir = $resolvedClaims.Path }
            } catch { $claimFault = "coord-root.ps1 failed: $($_.Exception.Message)" }
        } else {
            $claimFault = "$coordRootScript is missing"
        }
        if ($claimFault) {
            $lines += ""
            $lines += "Active work claims: NOT READ -- the claim registry did not resolve ($claimFault)."
        }
        $claimFiles = @(if ($claimDir) { Get-ChildItem $claimDir -Filter *.json -EA SilentlyContinue | Sort-Object Name })
        if ($claimFiles.Count -gt 0) {
            $meNorm = ($root -replace '\\', '/').TrimEnd('/')
            # Only the fresh claims are listed, newest first. A stale one still holds its key, and the
            # commit-msg claim gate still enforces it; claim.ps1 -List shows every one.
            $staleCount = 0
            $now = Get-Date
            $fresh = @(foreach ($cf in $claimFiles) {
                try { $c = Get-Content $cf.FullName -Raw | ConvertFrom-Json } catch { continue }
                # An unreadable date is never called stale, as before: it sorts last instead.
                $age = [double]::MaxValue
                try { $age = ($now - [datetime]::Parse($c.claimed)).TotalHours } catch { }
                if ($age -ne [double]::MaxValue -and $age -ge $staleHours) { $staleCount++; continue }
                [pscustomobject]@{ Claim = $c; Age = $age }
            })
            $lines += ""
            $lines += "Active work claims ($($fresh.Count) fresh, $staleCount stale over ${staleHours}h not shown) -- do NOT start one held by another session:"
            foreach ($f in @($fresh | Sort-Object Age | Select-Object -First $claimCap)) {
                $c = $f.Claim
                $heldNorm = ($c.worktree -replace '\\', '/').TrimEnd('/')
                # A claim from another machine names that machine's path, so it is never THIS session.
                $here = Test-CoordRecordIsHere $c
                $who = if ($here -and $heldNorm -ieq $meNorm) { "THIS session" } elseif ($here) { $c.worktree } else { "$($c.worktree) on $(Get-CoordRecordHost $c)" }
                $note = "$($c.note)"
                if ($note.Length -gt 80) { $note = $note.Substring(0, 77) + '...' }
                $lines += "  $($c.key) -- $note  (held by $who [$($c.branch)])"
            }
            if ($fresh.Count -gt $claimCap) { $lines += "  +$($fresh.Count - $claimCap) more fresh" }
            $lines += "  Every claim:  pwsh -NoProfile -File scripts\coord\claim.ps1 -List"
            $lines += "  Claim yours first:  scripts\coord\claim.ps1 -Take <key> -Note `"<what>`""
        }

        # The checkouts, last and short: a count and this session's own row. `git worktree list` prints
        # every one, and at 471 of them that list alone pushed everything above out of the preview.
        $rootFwd = ($root -replace '\\', '/')
        $ownRow = $wt | Where-Object { ($_ -replace '\\', '/') -like "$rootFwd *" } | Select-Object -First 1
        $lines += ""
        $lines += "Worktrees sharing this .git: $($wt.Count)  (all of them: git worktree list)"
        # git pads the path column to the longest path of them all, so the padding is squeezed out.
        if ($ownRow) { $lines += "  yours:  $($ownRow -replace '\s{2,}', '  ')" }

        # Nudge cleanup: count the <repo>-<name> siblings new.ps1 creates, so finished ones don't pile up.
        $siblingCount = @($wt | Where-Object { ($_ -replace '\\', '/') -like "$rootFwd-*" }).Count
        if ($siblingCount -ge 1) {
            $lines += "  [cleanup] $siblingCount sibling worktree(s) exist. Prune the finished (merged + clean) ones:"
            $lines += "       scripts\worktree\prune-merged.ps1        (dry-run; add -Apply to remove)"
        }

        $lines += ""
        $lines += "Coordination rules for parallel sessions (see docs/WORKTREES.md):"
        $lines += "  - Keep ALL changes on this worktree's branch ('$branch'); never edit files in a sibling worktree."
        $lines += "  - Use THIS worktree's .venv (.\.venv\Scripts\Activate.ps1), or you silently test the wrong code."
        $lines += "  - The AI project memory (~/.claude/.../memory) is SHARED, last write wins: do not write it"
        $lines += "    unless the user confirms this session owns memory updates."
    }
}

# The backstop behind the row caps: row counts do not bound bytes, since a long path, branch or task
# line can still grow a row. The sections run in priority order, so past the budget the tail goes and
# one line says so; the head, which holds the hazards, always survives.
$byteBudget = 4000
$out = ($lines -join "`n")
if ([Text.Encoding]::UTF8.GetByteCount($out) -gt $byteBudget) {
    $kept = @()
    $used = 0
    foreach ($l in $lines) {
        $n = [Text.Encoding]::UTF8.GetByteCount($l) + 1
        # Room for the closing line below, so the cut banner still ends under the budget.
        if ($used + $n -gt $byteBudget - 200) { break }
        $kept += $l
        $used += $n
    }
    $kept += "[session-context] cut the last $($lines.Count - $kept.Count) line(s) to fit the budget. Full lists: scripts\coord\presence.ps1 -All, scripts\coord\claim.ps1 -List, git worktree list"
    $out = ($kept -join "`n")
}
$out | Write-Output
