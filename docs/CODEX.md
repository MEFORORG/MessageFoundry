# Codex reads the current Claude Code tooling

`CLAUDE.md` is the repo authority for both agents. `AGENTS.md` points there.
The skill bodies under `.claude/skills/` are authoritative too. Codex's
`.agents/skills/` entries contain pointers, not copies of those procedures.
Read linked resources relative to the Claude skill's directory.
User-level sources come from `$CLAUDE_CONFIG_DIR/skills` when set, otherwise
`~/.claude/skills`. This follows junctions into `.claude-shared-skills` too.
Repo skill names take precedence over user-level names.
Git ignores `.claude/skills/`, so a repo skill exists only in the checkout that holds it.
Every pointer therefore finds its source at run time through `source-skill`.
A link into that folder would break in every other clone.

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

New event types appear as unmapped at startup. The bridge does not silently
claim a failed hook ran.

### Who decides a block

Only a hook blocks. As in Claude Code, a hook's exit 2 blocks. So does a hook
that sets `"onFailure": "block"` when it fails: a non-zero exit, a timeout, a
command that cannot start, a defect of its own such as an unsupported handler
type or shell, or a defect in its group, such as a matcher that is not a valid
regex, that keeps it from running. Any other hook failure is a
non-blocking error. The bridge reports it on stderr and as a `systemMessage`,
naming the hook, ignores that hook's output, and runs the remaining hooks. A JSON
`permissionDecision` deny from a hook is a decision, not a failure, and is passed
on as before.

A bridge fault never blocks, on any event. A fault is anything that keeps the
bridge from running the hooks: settings that cannot be parsed, a missing session
id, a payload that cannot be read as UTF-8 JSON, a payload whose
`hook_event_name` differs from the registered event in more than case, or any
other exception. The bridge reports it on stderr and as a `systemMessage`, and
keeps any decision already gathered, such as an earlier hook's deny. A defect is
judged where it belongs. A hook's own defect is reported and that hook skipped;
the hooks before it have already run, and the hooks after it still run. A defect
in a group, such as its matcher, is reported and that group skipped, and the
groups after it still run.

A launcher that cannot run the bridge never blocks either. In hook mode the
bridge exits 0 to proceed or 10 to block, and `invoke.ps1` turns 10 into 2. Any
other outcome is no decision: another bridge exit, including the 2 that Python
and argparse exit with, a missing `.venv`, or a checkout `git` cannot find. On a
call that names `hook` as its subcommand, as every registered command does, no
decision is reported and maps to a non-blocking exit 1 on every event, never to
2, and never to 0 once `pwsh` has started, except that a help flag prints usage
and exits 0. `invoke.ps1` ends its process with
its code, and the command line passes it on, because `pwsh -Command` would
report an exit 2 as 1. This is tested with PowerShell, `cmd` and `sh` as the
outer shell. Codex's documentation does not say which shell runs a hook command.
When `pwsh` itself cannot start, nothing reports it: the line would exit 0 under
Windows PowerShell 5.1, which proceeds as if every hook passed, 9009 under `cmd`
and 127 under `sh`; this is reasoned, not measured.

At origin/main before this change, no exit-2 block reached Codex: `pwsh -Command`
reported the bridge's exit 2 as 1. A hook's JSON `permissionDecision` deny was
unaffected. **A future guard that must block when it fails sets
`"onFailure": "block"`.** That holds only once the bridge runs and reads the
settings: a launcher with no decision, or a bridge fault, never blocks.

The bridge differs from Claude Code in at least three ways. It runs an event's
hooks one after another, where Claude Code runs them in parallel. Exit 2 stops
the remaining hooks, and the bridge exits 10 on every event, which `invoke.ps1`
turns into 2, including events where Claude Code only shows the hook's stderr.
Hook chains have a 90-second outer limit, so the timeouts of a long chain add up
against it.

Command-only hooks use the shell they name. With none, they use bash, as Claude
Code does: Git Bash on Windows, else PowerShell there when Git Bash is missing.
Structured `command` and `args` avoid shell parsing. A command-only PowerShell
hook blocks by `exit 2`, as under Claude Code, whose hooks reference blocks a
PowerShell hook with an explicit `exit 2`. The bridge runs it under
`pwsh -Command` and takes the exit code unchanged, so a final native program's
exit 2 does not block unless the hook ends with `exit $LASTEXITCODE`. The bridge
puts one line before the hook, turning `$PSNativeCommandUseErrorActionPreference`
off, so a hook that must open with `param()`, a `using` statement or a named
block fails to parse and cannot block.

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
