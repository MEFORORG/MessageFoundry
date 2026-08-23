# SPDX-License-Identifier: AGPL-3.0-or-later
# Copyright (C) 2026 MessageFoundry Organization and contributors
<#
.SYNOPSIS
    SessionStart hook: surface project working-defaults + git-worktree coordination to a Claude Code chat.

.DESCRIPTION
    Wired as a SessionStart hook in .claude/settings.json. Whatever this prints to stdout is injected
    into the chat's starting context, so a new window starts already knowing the project's preferences
    and the rules for working alongside sibling sessions.

    Two parts:
      1. Ultracode preference — printed EVERY session. Ultracode is session-only and a memory can't
         auto-enable it (recalled memories are background context), so we surface the preference here
         deterministically every time. See AI memory: mf-ultracode-preference.
      2. Parallel-session coordination — printed ONLY when 2+ worktrees share this .git, i.e. when
         parallel build sessions are actually in play and could collide. This part also:
           - warns a session that lands in the SHARED PRIMARY (trunk) checkout to branch into its
             own worktree before editing (owner often forgets to say so); and
           - nudges cleanup by counting the <repo>-<name> siblings, pointing at prune-merged.ps1
             so finished worktrees don't pile up.
         See docs/WORKTREES.md and AI memory: mf-worktree-hygiene.
#>
$ErrorActionPreference = "SilentlyContinue"

$lines = @()

# (1) Always surface the project's working default so every new window keeps it top-of-mind.
#
# THIS BLOCK MUST NOT IMPLY A STATE, and the disclaimer must stay louder than the advice. It prints
# UNCONDITIONALLY, so anything a reader concludes about the current state from seeing it was concluded
# from a constant.
#
# The previous wording ended "so enable it for this session (include 'ultracode' in your prompt) when
# you want it" -- which reads as "it is off right now, here is how to turn it on". Measured 2026-08-14:
# a session read exactly that, observed no "Ultracode is on" system-reminder, concluded ultracode was
# OFF, and told the owner so -- while the indicator in the app's input bar said it was ON. It then
# declined to run a Workflow and asked the owner to re-enable something already enabled.
#
# The defect is a null with no mechanism, in both directions at once: the ABSENCE of a confirming
# signal is not evidence of the negative, and the PRESENCE of an unconditional one is not evidence of
# anything. A message that prints either way cannot discriminate between the states it describes.
$lines += "[MessageFoundry] This project prefers Ultracode (multi-agent workflow-by-default) for"
$lines += "substantive tasks."
$lines += "THIS NOTICE PRINTS EVERY SESSION AND TELLS YOU NOTHING ABOUT WHETHER ULTRACODE IS ON RIGHT NOW."
$lines += "It is a standing preference, not a state reading. Do NOT conclude ultracode is off because you"
$lines += "see this, and do NOT conclude it from the absence of an 'Ultracode is on' reminder. A message"
$lines += "that prints either way carries no information about the state, in either direction."
$lines += "WHAT ACTUALLY REPORTS THE STATE: an 'Ultracode is on' system-reminder when one is present, and"
$lines += "the Ultracode indicator in the app's input bar. If you can see neither and the answer would"
$lines += "change what you do, ASK. Do not infer it, and do not tell the owner it is off."
$lines += "Ultracode is session-only and no memory or config can auto-enable it, so when it genuinely is"
$lines += "off the way on is the owner including 'ultracode' in a prompt."
$lines += "Offer to run a Workflow proactively for non-trivial work; don't auto-run one without the opt-in."

# (2) Add parallel-session coordination only when 2+ worktrees share this .git (real collision risk).
$root = (& git rev-parse --show-toplevel 2>$null)
if ($root) {
    $wt = @(& git worktree list 2>$null)
    if ($wt.Count -gt 1) {
        $branch = (& git branch --show-current 2>$null)
        # Primary (trunk) checkout vs a linked worktree: a linked worktree's git-dir is under .git/worktrees/.
        $gitDir = (& git rev-parse --git-dir 2>$null)
        $isPrimary = ($gitDir -notmatch 'worktrees')

        $lines += ""
        $lines += "[PARALLEL SESSION ($($wt.Count) worktrees active)]"
        $lines += "This chat's worktree: $root  (branch: $branch)"

        # Loudest, first: if this session sits in the SHARED trunk, tell it to branch into its own worktree.
        if ($isPrimary) {
            $lines += ""
            $lines += "  >>> You are in the SHARED PRIMARY checkout, where parallel sessions collide."
            $lines += "  >>> Before any substantive edits, create and work in your OWN worktree:"
            $lines += "  >>>     scripts\worktree\new.ps1 -Name <short-task-name>"
            $lines += "  >>> (A trivial one-off read/edit here is fine; anything you'll iterate on gets a worktree.)"
        }

        $lines += ""
        $lines += "All worktrees sharing this .git/history/remote:"
        $wt | ForEach-Object { $lines += "  $_" }

        # WHO IS ACTUALLY HERE. The worktree list above is the set of checkouts, not the set of live
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
                # one: the `git worktree list` block a few lines above puts a REAL abbreviated SHA in
                # exactly this shape, before a bracketed branch. It is a registry session id, resolves
                # to no git object, and a session that compared "is that worktree ahead of mine"
                # against it got an error at best and the wrong tree if the prefix happened to resolve.
                # The word goes on the ROW, not in a legend, so the column cannot mean one thing in one
                # row and something else in the next.
                foreach ($p in $others) {
                    $where = if ($p.IsPrimary) { "the SHARED PRIMARY" } else { $p.Worktree }
                    $flag = if ($p.State -ne "LIVE") { "  [$($p.State)]" } else { "" }
                    $lines += "  session $($p.Short)  $($p.Surface)  in $where  [$($p.Branch)]$flag"
                }
                # The surfaces differ in what can reach them, and that changes how you coordinate.
                if (@($others | Where-Object { $_.Surface -ne "desktop" }).Count -gt 0) {
                    $lines += "  NOTE: a non-desktop (e.g. VS Code) session is live. It cannot be reached by"
                    $lines += "        session messaging -- coordinate through a claim or the PR, not a message."
                }
                if (@($others | Where-Object { $_.IsPrimary }).Count -gt 0) {
                    $lines += "  WARNING: a session is working in the SHARED PRIMARY checkout. Anything you do"
                    $lines += "           there can collide with it -- stay in this worktree."
                }
                $lines += "  Full roster:  pwsh -NoProfile -File scripts\coord\presence.ps1 -All"
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
                    foreach ($b in $busy) {
                        # Same id, same banner, same label -- see the note on the roster rows above.
                        #
                        # "beyond yours" is not decoration. overlap.ps1's Files narrows its committed
                        # half against the HEAD of whoever asked, so this count is relative to THIS
                        # session and a bare "changed" would overstate what the peer did.
                        $lines += "  session $($b.Short) [$($b.Branch)] -- $(@($b.Files).Count) file(s) changed beyond yours"
                        foreach ($w in @($b.Work | Select-Object -First 3)) { $lines += "      $w" }
                    }
                    $lines += "  Everything in flight:  pwsh -NoProfile -File scripts\coord\overlap.ps1"
                }
            }
        }

        # Nudge cleanup: count the <repo>-<name> siblings new.ps1 creates, so finished ones don't pile up.
        $rootFwd = ($root -replace '\\', '/')
        $siblingCount = @($wt | Where-Object { ($_ -replace '\\', '/') -like "$rootFwd-*" }).Count
        if ($siblingCount -ge 1) {
            $lines += ""
            $lines += "  [cleanup] $siblingCount sibling worktree(s) exist. Prune the finished (merged + clean) ones:"
            $lines += "       scripts\worktree\prune-merged.ps1        (dry-run; add -Apply to remove)"
        }

        # BACKLOG #309: what the OTHER sessions are building, before you start building it too. The commit-msg
        # claim gate only enforces NUMBERED items; this banner is the whole mechanism for ad-hoc work -- and
        # ad-hoc work is what actually collided (three sessions, one npm advisory, two duplicate PRs).
        $claimDir = Join-Path (& git rev-parse --path-format=absolute --git-common-dir 2>$null).Trim() "mefor-coord/claims"
        $claimFiles = @(Get-ChildItem $claimDir -Filter *.json -EA SilentlyContinue | Sort-Object Name)
        if ($claimFiles.Count -gt 0) {
            $meNorm = ($root -replace '\\', '/').TrimEnd('/')
            $lines += ""
            $lines += "Active work claims ($($claimFiles.Count)) -- do NOT start one held by another session:"
            foreach ($cf in $claimFiles) {
                try { $c = Get-Content $cf.FullName -Raw | ConvertFrom-Json } catch { continue }
                $heldNorm = ($c.worktree -replace '\\', '/').TrimEnd('/')
                $who = if ($heldNorm -ieq $meNorm) { "THIS session" } else { $c.worktree }
                $stale = ""
                try {
                    $hrs = ((Get-Date) - [datetime]::Parse($c.claimed)).TotalHours
                    if ($hrs -ge 12) { $stale = "  [stale ~$([int]$hrs)h]" }
                } catch { }
                $lines += "  $($c.key) -- $($c.note)"
                $lines += "      held by $who [$($c.branch)]$stale"
            }
            $lines += "  Claim yours first:  scripts\coord\claim.ps1 -Take <key> -Note `"<what>`""
        }

        $lines += ""
        $lines += "Coordination rules for parallel sessions (see docs/WORKTREES.md):"
        $lines += "  - Keep ALL changes on this worktree's branch ('$branch'); never edit files in a sibling worktree."
        $lines += "  - Use THIS worktree's .venv (.\.venv\Scripts\Activate.ps1), not the main checkout's, or you'll"
        $lines += "    silently test the wrong code."
        $lines += "  - The AI project memory (~/.claude/.../memory) is SHARED across all sessions: reads are fine,"
        $lines += "    but only ONE session should write at a time (last write wins). Do not write project memory"
        $lines += "    unless the user confirms this session owns memory updates."
    }
}

($lines -join "`n") | Write-Output
