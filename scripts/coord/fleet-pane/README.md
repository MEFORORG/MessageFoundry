# fleet-pane

A Claude Code mod that adds `/fleet`: a pane beside the chat with the fleet's state. It is
read-only and makes no model call. It reads the coordination scripts in this folder's parent, in
the checkout the session runs in.

| Section | Source | Read every |
|---|---|---|
| Live seats | `presence.ps1 -Json` | 60 s |
| Open PRs and merge queue | `<git common dir>/mefor-coord/pr-state.json`, written by `pr_state.py` | 30 s |
| Usage | `usage.ps1 -Json -StateDir <config root>/mefor-usage` | 120 s |
| This lane | `lane.ps1 -Show` | 120 s |

Each section shows its own age. A failed read says so in red and keeps the last good data beside
it, so a broken read never looks like an empty list. The timers skip all work while the pane is not
placed. The pane never calls GitHub: the PR section reads the cache the `MEFOR-PR-State` scheduled
task writes, under the reader rules in `docs/WORKTREES.md`, "A PR-state cache for read-only panes".

Usage often reads UNKNOWN in a desktop session, because desktop sessions never run the statusLine
that publishes the reading. The pane shows that with the reading's age rather than hiding it.

## Install

Load it for one session, from a terminal:

```powershell
claude --plugin-dir D:/Code/MessageFoundry/scripts/coord/fleet-pane
```

For desktop sessions, name the folder in `CLAUDE_CODE_PLUGIN_DIRS` in the `env` block of
`~/.claude/settings.json`. Point it at the primary checkout, which tracks `main`. Then type `/fleet`.

## Check it

```powershell
claude plugin validate scripts/coord/fleet-pane
claude plugin test scripts/coord/fleet-pane
```

Once a session has loaded the mod, `.claude-plugin/types/` holds the API types (git-ignored), and
`tsc -p scripts/coord/fleet-pane` type-checks it. `tests/test_fleet_pane_guard.py` checks in CI that
the module never reaches `$.model`, `$.agent`, `$.prompt.submit` or `$.tool.register`.
