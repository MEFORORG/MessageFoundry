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
         parallel build sessions are actually in play and could collide. See docs/WORKTREES.md.
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
        $lines += ""
        $lines += "[PARALLEL SESSION ($($wt.Count) worktrees active)]"
        $lines += "This chat's worktree: $root  (branch: $branch)"
        $lines += "All worktrees sharing this .git/history/remote:"
        $wt | ForEach-Object { $lines += "  $_" }
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
