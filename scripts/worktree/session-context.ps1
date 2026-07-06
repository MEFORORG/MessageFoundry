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
$lines += "[MessageFoundry] This project prefers Ultracode (multi-agent workflow-by-default) for"
$lines += "substantive tasks. Ultracode is session-only — it can't be auto-enabled from a memory or"
$lines += "config, so enable it for this session (include 'ultracode' in your prompt) when you want it."
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

        # Nudge cleanup: count the <repo>-<name> siblings new.ps1 creates, so finished ones don't pile up.
        $rootFwd = ($root -replace '\\', '/')
        $siblingCount = @($wt | Where-Object { ($_ -replace '\\', '/') -like "$rootFwd-*" }).Count
        if ($siblingCount -ge 1) {
            $lines += ""
            $lines += "  [cleanup] $siblingCount sibling worktree(s) exist. Prune the finished (merged + clean) ones:"
            $lines += "       scripts\worktree\prune-merged.ps1        (dry-run; add -Apply to remove)"
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
