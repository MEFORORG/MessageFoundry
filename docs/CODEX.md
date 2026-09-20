# Codex reads the current Claude Code tooling

`CLAUDE.md` is the repo authority for both agents. `AGENTS.md` points there.
The skill bodies under `.claude/skills/` are authoritative too. Codex's
`.agents/skills/` entries contain pointers, not copies of those procedures.
Read linked resources relative to the Claude skill's directory.
User-level sources come from `$CLAUDE_CONFIG_DIR/skills` when set, otherwise
`~/.claude/skills`. This follows junctions into `.claude-shared-skills` too.
Repo skill names take precedence over user-level names.

## Hooks follow Claude's repo settings

`.codex/config.toml` registers a transport for Codex lifecycle events.
`scripts/codex/bridge.py` reads `.claude/settings.json` on **each event**.
Matching command hooks run from their current source paths, with their arguments
and timeouts. Removing or changing a source handler affects the next call.
The bridge combines context and keeps a denial over an allowance.

Codex calls shell hooks `Bash`, including PowerShell commands. The bridge also
matches Claude's `PowerShell` name. Patch calls match `apply_patch`, `Edit`, and
`Write`. A future hook that needs Claude-specific input fields still needs an
adapter; alias matching alone cannot translate an edit payload.

New event types appear as unmapped at startup. Unsupported handler types and
failed commands report errors. The bridge does not silently claim they ran.
Command-only hooks use PowerShell on Windows and `sh` elsewhere; structured
`command` and `args` avoid shell parsing. Hook chains have a 90-second outer limit.

Only repo settings are imported. Claude's user settings, local settings, account
credentials, permission grants, plugins, and status line remain Claude-owned.
Codex retains its own sandbox and approval rules. Claude permission patterns are
not a Codex enforcement layer. The restrictions in `CLAUDE.md` still govern work.

## Start a Codex session

1. Open this checkout, or a worktree carrying these changes, in Codex.
2. Trust the project and review its hooks when Codex prompts.
3. Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 doctor` to check source paths.

Use this worktree's `.venv` and the current setup instructions in
`docs/WORKTREES.md`. The launcher uses `.venv/Scripts/python.exe` on Windows and
`.venv/bin/python` elsewhere. It does not install packages or change Python.
The sandbox may require approval to launch the base Python installation.

Hook trust is a Codex setting. Writing the repo config does not grant trust or
prove that a running session loaded it. Start a new session after setup.
See the [official hook documentation](https://learn.chatgpt.com/docs/hooks).

## Run the existing scripts

Use the existing scripts directly for development checks. Read their current
arguments and gates in `CLAUDE.md`, `pyproject.toml`, `.pre-commit-config.yaml`,
and `docs/WORKTREES.md`. The adapter does not replace those commands or gates.

For seat declarations and other identity-sensitive scripts, use the transport:

```powershell
pwsh -NoProfile -File scripts/codex/invoke.ps1 run scripts/coord/seat.ps1 -Declare -Seat special -Goal "The owner's assigned task"
```

The transport uses `CODEX_THREAD_ID`. If that variable is absent, pass
`--session-id <id-from-the-startup-hook>` after `run`. It never guesses a session
from Claude's files. An absent identity is an error.

The shared seat writer prefixes Codex record IDs with `codex-`. Codex role markers
and role-card copies live under `.codex/sessions/<encoded-session-id>/`.
Seat records live under `<git-common-dir>/mefor-coord/codex-seats/`, separate
from Claude's `seats/` inventory. The writer's logic still comes from `seat.ps1`.
Claude keeps its `.claude/` paths. Compaction recovery separates their records.
The bridge sets its compatibility environment only for child processes.

Claude account usage and Claude process discovery do not measure Codex.
Use native Codex usage and task tools for those questions. A Codex seat record
does not prove that Claude's fleet process scanner can track its liveness.
Do not use Claude's account-switch or pool-epoch commands for a Codex account.

## Keep pointers current

Run `pwsh -NoProfile -File scripts/codex/invoke.ps1 sync-skills` after adding or
renaming Claude skills. This refreshes discovery metadata and pointer files.
Add `--include-user-skills` to include user-level skills such as `seat`.
It leaves unrelated Codex skills alone and reports removed source skills.
Existing pointers read current skill bodies whenever invoked.
The one-time `sync-skills --migrate-copies` option replaces old copied skills and
backs them up under `.codex/migration-backup/`. Normal refreshes never use it.

When a skill asks for the current session's title or transcript, use native Codex
task tools and `CODEX_THREAD_ID`. Do not substitute Claude's files. If Codex cannot
resolve a required identity, report the missing fact instead of choosing a seat.

For `seat`, keep the current source's roster, question, and readback procedure.
In Codex, `$seat` is the explicit invocation of the source's `/seat` skill.
Translate `AskUserQuestion` to Codex's user-input tool. The source's marker step
targets the directory returned by `scripts/codex/invoke.ps1 state-dir`, never
`.claude/seat.local.txt`. Create that directory when needed. The shared declaration
writer also writes the Codex marker when called through the transport.
Run the source's card-injection command through `invoke.ps1 run` too.
Use `--session-id` with `state-dir` when `CODEX_THREAD_ID` is absent.

Source changes that alter a hook's payload contract require adapter tests.
Run `tests/test_codex_bridge.py` with the existing seat, role-card, and compaction
tests before claiming compatibility. Do not replace Claude source procedures
with a second Codex implementation.
