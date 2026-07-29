# Parallel build sessions with git worktrees

Two efforts working in the **same** checkout collide: a `git checkout` or file edit in one changes the
files under the other, and their commits/index race. That's fine for two sessions that are only
*reading or planning*, but not for two that are **building at once** (e.g. two Claude Code chats).

The fix is a **git worktree** per session — a second working directory on its own branch that shares
the same `.git` history and remote. Each worktree has independent files, branch, and (here) its own
Python virtualenv, so builds and tests don't interfere. Commits and pushes still go to the same
remote, so the normal **branch → PR → merge** flow is unchanged.

## Create one

```powershell
# from anywhere in the repo:
scripts\worktree\new.ps1 -Name alerts
```

This first runs `git fetch origin`, then creates a **sibling** directory `..\MessageFoundry-alerts` on
a new branch `alerts` (off `origin/main`, the freshly fetched remote tip — so a stale local `main`
can't seed it), then bootstraps `..\MessageFoundry-alerts\.venv` with `pip install -e ".[dev,harness]"`.
Options:

- `-Base <ref>` — branch off something other than `origin/main`. If you point it at a local branch
  that lags its upstream, you get a loud warning (it would start the worktree from stale code).
- `-Sqlserver` — also install the `[sqlserver]` extra.
- `-Ide` — also `npm install` the VS Code extension, and print the EDH launch command.
- `-NoInstall` — create the worktree only (skip the venv); set one up yourself before testing.
- `-Python <exe>` — interpreter used to create the venv (default `python`).

Then work in it independently:

```powershell
cd ..\MessageFoundry-alerts
.\.venv\Scripts\Activate.ps1
# build / commit / push on branch 'alerts'; open a PR as usual
```

Point a second Claude Code chat (or VS Code window / EDH) at that directory and the two sessions build
in parallel without touching each other's files.

> **One-step shortcut:** `scripts\worktree\spawn.ps1 -Name alerts` runs `new.ps1` **and** opens a VS Code
> window on the new worktree, so you just start the second chat in that window. Same flags as `new.ps1`.

## Remove one

Run from the **main** checkout (git can't remove the worktree you're standing in):

```powershell
scripts\worktree\remove.ps1 -Name alerts            # refuses if there are uncommitted tracked changes
scripts\worktree\remove.ps1 -Name alerts -DeleteBranch
scripts\worktree\remove.ps1 -Name alerts -Force     # discard uncommitted tracked changes too
```

The untracked `.venv` / `node_modules` are expected and removed automatically; only uncommitted
**tracked** changes block removal (unless `-Force`).

## What's isolated vs shared

| Isolated per worktree | Shared across worktrees |
|---|---|
| Working files, branch, git index | `.git` object store / history |
| `.venv` (per-worktree, **not** shared) | The remote (`origin`) — all branches/PRs |
| `.mefor/` dev DB, generated corpus, `ide/node_modules` | — |

**Heads-up — the AI project memory is shared.** `~/.claude/.../memory/` (the `MEMORY.md` index +
`mf-*.md` files) lives outside the repo and is shared by all sessions. Reads are fine; if two chats
**write** memory at the same time the last write wins, so coordinate memory updates (or let one chat
own them).

## Automatic coordination context (SessionStart hook)

You don't have to brief each new chat by hand. A `SessionStart` hook
([../scripts/worktree/session-context.ps1](../scripts/worktree/session-context.ps1), wired in
[`../.claude/settings.json`](../.claude/settings.json)) injects context into every new Claude Code
window. It always prints the project's Ultracode working-default reminder, and **when 2+ worktrees
share this `.git`** it appends the parallel-session block: which worktree/branch this chat owns, the
full worktree list, and the shared-memory write rule above. With a single worktree it prints only the
working-default line.

**Who is actually live — `presence.ps1`.** The worktree list above is the set of *checkouts*, not the
set of *sessions*: most worktrees usually have nobody in them, and the collision that matters — someone
editing the shared primary right now — is invisible from it. The banner therefore also lists **live
sessions**, from [../scripts/coord/presence.ps1](../scripts/coord/presence.ps1). Run it directly any time:

```powershell
pwsh -NoProfile -File scripts\coord\presence.ps1        # live sessions in this repo
pwsh -NoProfile -File scripts\coord\presence.ps1 -All   # include stale/dead registry entries
```

Two things make it worth having over the Desktop app's own session list:

- **It sees VS Code sessions.** The Desktop app's `list_sessions` enumerates an in-memory map of
  sessions *the app itself spawned*; a session launched by the VS Code extension is never entered into
  it — not filtered out, never registered — so it is invisible there and cannot be messaged. Verified
  against a live VS Code session sharing the **default** config root, so this is not a per-login split.
  `<config-root>/sessions/<pid>.json` is the only registry carrying every surface, and that is what
  `presence.ps1` reads (discovering config roots dynamically, since several logins can coexist).
- **Liveness is fenced, not a pid check.** PIDs get reused and those records outlive their process, so
  it compares each process's real start time against the recorded session start. Claude Code ships a
  `procStart` field for exactly this, but here it serialises as absent and its guard passes
  unconditionally — a bare pid check reports a recycled pid as a live session.

It is **read-only**: a roster, not a channel. It never writes a registry file and never contacts another
session. Note the corollary of having no heartbeat anywhere on this host: a `DEAD`/`STALE` verdict is a
hint for a human, and must never by itself authorise a destructive action such as reclaiming a claim.

**Creating a worktree is serialised.** `git worktree add -b <name> <base>` writes `.git/config`, so two
sessions creating worktrees at once race `.git/config.lock` — on Windows that surfaces as `could not
lock config file .git/config: File exists`, leaving orphaned branches behind. `new.ps1` wraps that call
in a cross-session mutex ([../scripts/coord/lock.ps1](../scripts/coord/lock.ps1)), which uses the same
atomic exclusive-create as `claim.ps1`. It **retries and never steals**: on timeout it fails loudly and
names the holder, because breaking a lock you cannot prove is abandoned re-opens the very race it exists
to close — and on this host there is no reliable liveness signal to prove it with.

**Cross-session staging guard.** A `PreToolUse` hook (same `settings.json`,
[../scripts/hooks/block-blanket-git-stage.ps1](../scripts/hooks/block-blanket-git-stage.ps1)) refuses
blanket `git add -A`/`.`/`-u`/`--all` and `git commit -a`/`-am`/`--all` in **every** session, so even two
chats in the *same* tree can't sweep each other's files into one commit — stage explicit paths instead.
Review or disable it via `/hooks`.

Because new worktrees branch off `origin/main`, the hook + script reach a new worktree only once
they're committed to `main` (and fetched). `.claude/settings.json` is tracked (shared across worktrees);
`.claude/settings.local.json` stays git-ignored (machine-local).

## The worktree gate (enforcement, not a reminder)

> Full write-up, with the measurements and the backout procedure: [WORKTREE-GATE.md](WORKTREE-GATE.md).
> The whole estate as one system — every control's LIVE/INERT status, an audit of the gaps, and the
> ultracode question: [SESSION-DRIFT-CONTROLS.md](SESSION-DRIFT-CONTROLS.md).

The `SessionStart` banner above **asks** you to work in a worktree. Measurement says asking doesn't work:
across 30 days, 166 sessions ran with their cwd in the shared primary, and **44% of all their file writes
landed in the primary's tree**. The gate makes it mechanical.

```powershell
# once, from a PLAIN terminal (not inside Claude Code):
pwsh -NoProfile -File scripts\worktree\install-gate.ps1
pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Status
pwsh -NoProfile -File scripts\worktree\install-gate.ps1 -Uninstall   # kill switch, takes effect at once
```

[`install-gate.ps1`](../scripts/worktree/install-gate.ps1) copies
[`scripts/hooks/worktree_gate.ps1`](../scripts/hooks/worktree_gate.ps1) into `~/.claude/hooks/` and
registers it as a `PreToolUse` hook in the **user-scope** `~/.claude/settings.json`. It denies:

1. a **`Write`/`Edit`/`MultiEdit`/`NotebookEdit` whose target path is inside the primary's working tree**;
2. a **`Task`/`Agent`/`Workflow` dispatch made from the primary** — a subagent inherits the parent's cwd,
   can't create a worktree for itself, and its blocked edits don't reliably surface back to the parent, so
   a fan-out from the primary would *appear* to succeed while writing nothing.
3. an **`EnterWorktree` tool call**, which relocates a **live** session into a worktree — that re-files the
   session's chat transcript under the worktree's slug, so the conversation drops out of the session list of
   the window it was born in (nothing is deleted; the window just stops looking there). Open a **fresh**
   session directly on the worktree instead. Any session already relocated and gone missing is recoverable —
   see the recovery tool below. (Fail-open like the rest: an unrecognised payload never wedges the tool call.)

Reads are never gated: asking a question or planning in the primary stays frictionless. Only building is
blocked.

> **Rule 3 ships INERT — activating it is a deliberate, separate decision.** The live hook is a *copy* at
> `~/.claude/hooks/worktree_gate.ps1`; `install-gate.ps1` is what overwrites it. Merging this rule changes
> nothing until that script is re-run, which is why the code can land ahead of the call.
>
> Weigh it with rules 2 and 3 together before you activate. Rule 2 denies a fan-out **from** the primary and
> rule 3 denies relocating **into** a worktree, so with both live a primary-resident session has **no
> in-session path to a subagent at all** — it must be *started* in a worktree. That is the safe pattern, but
> it is a hard stop rather than a nudge, and it makes workflow-by-default impossible from the directory
> sessions naturally open in.
>
> The counter-case is that `EnterWorktree` → dispatch → `ExitWorktree keep` is genuinely safe: the transcript
> follows the cwd **both** ways, so a relocated session is only lost if it *ends* while still inside. Rule 3
> cannot know you will exit properly — but `sessions.ps1` below now makes that outcome **recoverable**, which
> is the thing that was missing when ten sessions were stranded and the rule was first designed. Ship the
> cure, then decide whether you still want the prohibition.

### Recovering a relocated session — `sessions.ps1`

If a session was relocated into a worktree before rule 3 existed (or by a plain terminal, which the gate
never governs) and vanished from its window's list, [`sessions.ps1`](../scripts/worktree/sessions.ps1) finds
and rescues it. It scans **every** login on the box (`~\.claude` plus each `~\.claude-account-*`) and reads
only the head of each transcript, so it is fast and read-only by default:

```powershell
pwsh -NoProfile -File scripts\worktree\sessions.ps1                 # every session for this repo, newest first
pwsh -NoProfile -File scripts\worktree\sessions.ps1 -Relocated      # only the ones that moved (missing from a window)
pwsh -NoProfile -File scripts\worktree\sessions.ps1 -Id <prefix>    # detail for one session
pwsh -NoProfile -File scripts\worktree\sessions.ps1 -Rehome <prefix> -WhatIf  # preview the move, touch nothing
pwsh -NoProfile -File scripts\worktree\sessions.ps1 -Rehome <prefix>          # put it back in the primary's session list
```

`-Rehome` is the one destructive action: it moves the transcript (and its sidecar dir) back under the
**primary's** slug so it reappears in the main window's session list. A bare invocation only ever **lists** —
it never moves anything — and `-Rehome` refuses on a session that still looks live (written within
`-MinIdleMinutes`, default 10; override with `-Force`) and honours `-WhatIf` for a no-op preview.

**It keys on the write's target path, never on the session's cwd.** In that same 30-day window, **29% of
writes came from a session sitting in the primary but landed inside a sibling worktree by absolute
path** — already correct. A cwd-keyed gate would have denied every one of them. So a session may stay
where it is and simply write into its worktree; there is no need to `cd`, relocate, or restart.

Already dirty in the primary when the gate stops you? Don't redo the work — move it:

```powershell
pwsh -NoProfile -File scripts\worktree\rescue.ps1 -Name <task>
```

[`rescue.ps1`](../scripts/worktree/rescue.ps1) stashes the primary's changes (tracked *and* untracked),
creates a worktree branched off the primary's **current commit** so the stash applies cleanly, and pops it
there. If any step fails the work stays in `git stash list` and the script says so — nothing is discarded.

Two deliberate limits. The gate lives in **user scope** because a hook committed to the project's
`.claude/settings.json` sits on one branch and doesn't exist in the other worktrees until each merges it —
and because a hook whose script path lives inside a working tree vanishes on a checkout, after which the
tool call *runs anyway, silently*. And it is a **guardrail, not a security boundary**: it inspects tool
arguments, so a file written by a shell command isn't seen. It stops the accidental primary edit — the "I
forgot to spin up a worktree" case — which is the one that actually happens.

## Why a venv per worktree

A fresh worktree has no `.venv` (it's git-ignored, exists only in the checkout it was created in). A
*shared* venv with `pip install -e .` is bound to **one** source path, so it would import that
checkout's code no matter which worktree you run from — silently testing the wrong code. A
per-worktree venv keeps each session honest. The cost is disk + ~a minute of install (pip's cache
makes repeats fast).
