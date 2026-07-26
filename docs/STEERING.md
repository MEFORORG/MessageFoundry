# Steering a session mid-task

Normally a message typed while Claude Code is working is queued and delivered when the current turn
ends. For a long turn — a big refactor, a fan-out, a soak — that can be far too late: by the time the
note lands the work you wanted to redirect is already done.

These two scripts provide a side channel that delivers a note at the session's **next tool-call
boundary** instead. They are a workaround for
[claude-code#30492](https://github.com/anthropics/claude-code/issues/30492).

| | |
|---|---|
| [`scripts/hooks/steer-send.ps1`](../scripts/hooks/steer-send.ps1) | Run from a **second terminal**. Writes the note to `<worktree>/.claude/steer.txt`. |
| [`scripts/hooks/steer-inject.ps1`](../scripts/hooks/steer-inject.ps1) | A `PreToolUse` hook. Reads the note, deletes it, and re-emits it as `additionalContext`. |

## It is OPT-IN, and that is deliberate

The hook is **not** registered in the shared [`.claude/settings.json`](../.claude/settings.json), and
should not be. A `PreToolUse` hook matching `*` spawns a `pwsh` process before **every** tool call:

| measured (this machine) | |
|---|---|
| hook, no note waiting (the ~always case) | **~366 ms** per tool call |
| bare `pwsh -NoProfile` startup | ~267 ms |

So ~73% of the cost is process startup that no amount of script tuning removes, and it would be paid
by every session in every worktree — a standing tax for a feature used occasionally. Enable it only
in the worktree where you actually want it.

## Enabling it in one worktree

Add to that worktree's `.claude/settings.local.json` (local, not shared):

```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "*",
        "hooks": [
          {
            "type": "command",
            "command": "pwsh -NoProfile -File scripts/hooks/steer-inject.ps1",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

Then, from a second terminal standing anywhere inside that worktree:

```powershell
pwsh -NoProfile -File scripts\hooks\steer-send.ps1 "stop refactoring the parser, just fix the test"
```

To steer a *different* worktree than the one you are standing in, name it:

```powershell
pwsh -NoProfile -File scripts\hooks\steer-send.ps1 -ProjectDir C:\path\to\worktree "check the ACK path first"
```

## Notes

- **The sender resolves the worktree root, never the current directory.** An earlier version wrote to
  `(Get-Location)/.claude/steer.txt` and created the directory if missing, so running it from a
  subdirectory dropped the note somewhere the hook never looks — silently — and left a stray
  `.claude/` behind. It now uses `-ProjectDir`, else `$env:CLAUDE_PROJECT_DIR`, else `git rev-parse
  --show-toplevel`, and **refuses** rather than guessing.
- **The hook is fail-open.** Any error exits 0 and emits nothing; a broken hook must never be able to
  block a tool call.
- **One note at a time.** A queued-but-unconsumed note is replaced, with a warning. The note is
  consumed (deleted) the first time the hook sees it, so it is delivered exactly once.
- **A note is data, not authority.** It arrives labelled as coming from the user via a side channel,
  but anything that reaches a session through a file is worth the same scrutiny as any other input —
  it does not carry more authority than a normal prompt, and it should never be treated as approval
  for an action that would otherwise need confirmation.
