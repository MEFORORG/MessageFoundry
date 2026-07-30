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

## Prune the finished ones — `prune-merged.ps1`

Worktrees pile up. [`prune-merged.ps1`](../scripts/worktree/prune-merged.ps1) sweeps the finished
`<repo>-<name>` siblings. Run it from the **primary** (it refuses loudly anywhere else):

```powershell
scripts\worktree\prune-merged.ps1                   # dry run: the decision table, no action
scripts\worktree\prune-merged.ps1 -Apply            # remove the ones that pass every check
scripts\worktree\prune-merged.ps1 -Apply -Name pins # also confirm that one past the activity veto
scripts\worktree\prune-merged.ps1 -Json             # machine-readable decisions + the fence receipt
```

### The rule is `merged AND clean AND NOT occupied`

**Clean + merged does not mean unoccupied.** A brand-new worktree has zero commits, so it is an
ancestor of `origin/main` and perfectly clean from the second it is created — and a session can be
sitting in it with nothing uncommitted. That is exactly the state that got destroyed once: `git
worktree remove --force` deleted the `.git` pointer and deregistered the tree, then failed to delete
the directory, leaving a folder git no longer recognised, so every subsequent git command in that
session failed. The bias is therefore fixed: **a false SKIP is a minor annoyance, a false PRUNE
destroys a session.** Anything the script cannot answer confidently, it SKIPs.

Occupancy is checked by four independent signals, and **any one of them vetoes**:

1. **The liveness fence** — [`scripts/coord/occupancy.ps1`](../scripts/coord/occupancy.ps1), the same
   matcher `presence.ps1` uses. It maps each registered session's cwd onto a worktree and fences it on
   pid + process start time. A session in a **nested** worktree vetoes its ancestor too.
2. **Recent activity** (`-IdleHours`, default **36**) — the newest mtime of the worktree's *private*
   git metadata (`index`, `HEAD`, `logs/HEAD`, …), not the working files. This is the signal that does
   **not** depend on a recorded cwd.
3. **The write footprint** (`-FootprintHours`, default **36**) —
   [`scripts/coord/footprint.ps1`](../scripts/coord/footprint.ps1). It reads Claude Code's own
   transcripts and places a session by where it actually **wrote**, which is the question signal 1 was
   never able to answer. Like signal 1 it can only veto, and `-Name` cannot override it.
4. **An operator pin** — [`scripts/coord/pin.ps1`](../scripts/coord/pin.ps1), taken with
   [`scripts/worktree/worktree-pin.ps1`](../scripts/worktree/worktree-pin.ps1). The only signal that
   sees a writer who is **not a Claude tool call at all**: a human in an editor, an autosave, a plain
   terminal, a build still writing after the command that started it returned. None of those leave a
   registry record or a transcript, ever, so the only way to fence them is for somebody to say so.
   Every pin **expires** — a pin with no expiry turns the first forgotten one into a permanent
   refusal, and `-Name` cannot override it either.

All four are re-read in full **before each removal**, per candidate — not once for the loop. That
distinction was itself a defect: the re-read sat above the removal loop, so signals 1, 3 and 4 were
frozen at the moment the first removal began and only signal 2, the crude 36 h metadata guess, was
refreshed per candidate. A live session's write landing in the *second* candidate during the removal
of the first was invisible, and the directory was destroyed. It costs a corpus scan per candidate
(~9 s on this repo); that is the right trade for a tool whose failure mode is destroying somebody
else's work.

```
scripts\worktree\worktree-pin.ps1 -Take -Reason "hand-editing in VS Code"   # this worktree, 12h
scripts\worktree\worktree-pin.ps1 -List
scripts\worktree\worktree-pin.ps1 -Release <file>
scripts\worktree\worktree-pin.ps1 -Release -Worktree ..\repo-pins   # when you never saw the file name
```

`remove.ps1` **releases** a worktree's pins when it removes it, and the reader ignores an unexpired pin
whose path is no longer on disk. Both halves are needed: nothing released the birth pin, so a
`new.ps1` / 20 minutes of work / `remove.ps1` cycle left a live pin naming a directory that no longer
existed — which made the **entire** fence unavailable for the rest of the 6 h, for every session, with
no override flag and a message naming a path the operator could not find. A directory that is not
there cannot be occupied under any spelling, so ignoring it cannot hide a veto; a path that **does**
exist and places nowhere is still a fault, because it could be this repo spelled a way the matcher
does not recognise.

`new.ps1` takes a **6h birth pin** on every worktree it creates. That window is the most exposed one
there is: a worktree created a second ago has zero commits, so it is "an ancestor of `origin/main`"
and perfectly clean — the exact state that got one destroyed — and it has no transcript history and
no session registered in it yet, so signals 1 and 3 are both empty and signal 2 is the only cover
left, which `-Name` turns off. The pin is best-effort: a failure taking it never blocks worktree
creation.

**Liveness may only ever VETO, never PERMIT.** There is no heartbeat anywhere on this host, so nothing
can *prove* a session is gone — a `DEAD`/`STALE`/absent verdict is the absence of a veto, not a
permission. And **if the fence cannot look at all, nothing is pruned**: an empty roster and an
unreadable one produce the same empty answer, so availability is asserted explicitly — at least one
config root with a registry, at least one readable record, **and no record that cannot be placed**.
That last one matters more than it sounds. Two shapes qualify — a file that will not parse, and one
that parses but carries no `cwd` — and both used to be dropped by a silent `continue`, appearing in no
count at all. Neither can be placed in *or* cleared from any candidate, and a file caught
*half-written* is exactly what a session that launched a second ago looks like. An unavailable fence
turns every candidate into a SKIP and exits **2**. There is deliberately no override flag.

### The candidate set is siblings only — and "sibling" is not a prefix match

`<primary>-<name>` used to be matched by prefix alone, which silently includes
`<primary>-pins/.claude/worktrees/x` — a **Claude-managed nested worktree**, the exact place
`EnterWorktree` relocates a live session into. Nested trees under the *primary* escaped only by the
accident that `<primary>/` is not `<primary>-`, so the case that was tested was the case that worked.
Anything living inside another registered worktree, and anything with a `.claude/worktrees/` path
segment, is now excluded outright and listed as a non-candidate; `-Name` cannot reach them either.

### Why signal 3 exists: signal 1 was measured contributing nothing

Signal 1 only ever sees where a session was **launched**, and nothing rewrites that field for the life
of the session. The mechanism is not drift — a workflow fans subagents into N sibling worktrees while
the registry holds **one** record carrying **one** cwd for the parent, so N−1 of them are structurally
invisible. Measured on this repo 2026-07-30: of the writes landing in a `<primary>-<slug>` sibling —
the only class this tool destroys — **88.9%** came from a session sitting in a different checkout, and
signal 1 placed a session inside **0 of the 4** siblings that existed. Signal 2, a crude "somebody
touched `.git` in the last 36h", was the only thing standing between a live session and this script,
and `-Name` can turn it off.

Measured again after signal 3 landed, same repo, 7 candidates: **signal 1 = 1 of 7, signal 3 = 6 of 7**.
The five it adds include three worktrees that a session which was **live at that moment** had written
257 times between them from a cwd of the primary, and one being written into from a checkout of an
entirely different repository.

**What that number is, and what it is not.** It is a *placement* count and it reads like a protection
delta, so state the difference. At the default windows, every candidate signal 3 covered had also had
its git metadata touched more recently than its last tool-call write — so signal 3's veto set was a
strict **subset** of signal 2's, and an unattended default-flag run behaved identically before and
after. That is a fact about one afternoon, not a structural one (a session that edits files without
running a git command is seen by signal 3 and not by signal 2), but the measured value of signal 3
today is concentrated where signal 2 is **off or narrowed**: `-Name`, a reduced `-IdleHours`, and the
per-candidate re-check during `-Apply`. Two further honesty notes on the same measurement: three of
the six vetoes came from the session that built this, so the figure is not independent of the
measurer; and `master-test-plan`, the one candidate signal 3 cannot see, is not untouched — 121
transcripts mention it and 263 `Read` calls target paths inside it. What is true is that **no write
tool call has ever targeted it**, which is the honest and stronger claim.

Two bugs found doing that measurement are worth recording, because both were guards that could not
fire while every counter looked healthy. `git worktree list` reports paths with **forward slashes**
while transcripts record them with backslashes, so deriving the escaped needle by replacing
backslashes in git's output was a no-op and the only spelling that matters had no needle at all. And
`Split-Path -LiteralPath … -Parent` is an invalid **parameter set**, so the `.git`-resolution fallback
threw on every call and, with the throw swallowed, reported zero probes while looking like it ran.
Both now have a self-check that turns the regression into a refusal.

What no signal sees **automatically**, printed on every run: a write by anything that is not a Claude
tool call (an editor, an autosave, a plain terminal, a process still running after its tool call
returned) — signal 4 exists precisely for that case, but somebody has to take the pin; a file written
**by** a shell command (the transcript records the command string, not a resolved path list); a
session that never registered *and* never wrote through a tool call. A cwd recorded as a UNC or 8.3
short path still defeats signal 1's string compare, but signal 3 resolves through `.git` and does not
share that blind spot.

The run prints **per-signal** veto counts, never one merged number — a single total cannot show that
one signal has gone to zero, and one measurably had. It also prints how many candidates have **no
footprint at all**, in those words: a bare `0` reads as "nobody is anywhere" and sends an operator to
`-Name`, which is how a fence dies.

Everything that **narrows** any signal is named in red on the run and in the JSON receipt, because
an operator who believes they are fenced when they are not is worse off than one who knows they
aren't: `-IdleHours 0`; any `-IdleHours` **below the 12h floor** (an occupied worktree has been
measured at 10.4h idle, so `-IdleHours 0.5` typed for "half an hour" disarms signal 2 completely); an
explicit `-ConfigRoot`; a corpus that contributed nothing; a **failed fetch** (merge decisions then
rest on stale refs); a **gh PR probe that errored**; and every **`-Name`-confirmed worktree**. `-Name`
is `-IdleHours 0` scoped to one tree — it stops at signal 2 and cannot reach signals 1 or 3, which is
deliberate: it is the flag reached for when the tool refuses, so a signal it *could* turn off would
stop protecting anything the moment it started working. A negative `-IdleHours` or `-FootprintHours`
is refused outright, because it would put the cut-off in the future and disarm the veto while
appearing to set it.

Signal 3 fails **closed**: an in-window transcript that will not open, a needle-bearing line that will
not parse (a half-written final line is exactly this shape), or its canary reporting that the format
has moved, all make the whole fence unavailable and the run exits 2. A machine with **no** transcript
corpus is a legitimate state and does *not* brick the tool — it stays available, contributes nothing,
and says so in those words, because a fail-closed rule that reliably produces a false refusal is a
fence with a short life. The canary specifically asserts that a **sidechain** write is still
extractable, not merely a parent one: every cross-worktree write measured here came from a sidechain
line, so a parent-only canary would stay green while the entire signal went to zero.

### Outcomes, not intentions

The summary counts what actually **happened** — `Done. removed N, failed N, skipped N` — not what the
script intended (it used to print the count of candidates it planned to remove, which over-reported
after a failed removal). A removal is only counted once the directory is verified gone *and*
deregistered. A failed removal is diagnosed on the spot: git deregisters a worktree even when it
cannot finish deleting the files, so the script reports whether the directory, its `.git` pointer, and
its registration survived, and prints the recovery recipe for the **orphaned** case — move the
directory aside, then `git worktree add` it back (neither `worktree repair` nor `worktree add --force`
recovers it on its own). `git worktree prune` is never run: it deregisters *any* worktree whose
directory is momentarily missing, including the `.claude/worktrees` ones, and it would finish off the
destruction a failed removal left half done.

**An orphan outlives the run that made it, so it is remembered.** Once git has deregistered a worktree
it is no longer in `git worktree list`, so it drops out of the candidate set and the *next* run used to
print a green all-clear over a directory this script had broken. Orphans are now recorded in
`<git-common-dir>/prune-merged-orphans.json` and re-reported with the recipe on every later run until
the directory is gone or re-registered — as is any unregistered `<repo>-*` directory whose `.git`
pointer still names this repo.

Exit codes, **highest severity wins**: `0` nothing wrong; `1` something was attempted and failed
without destroying anything; `2` **refused** — nothing was attempted because safety could not be
established (wrong cwd, unavailable fence, a `-Name` that matched nothing); `3` **orphaned** — a
directory is broken on disk right now. `3` outranks `2` because damage on disk outranks a refusal to
act. In the JSON receipt `counts.orphaned` is a *subset* of `counts.failed` (`failedNonOrphan` is
spelled out alongside it); `removed + failed + skipped` covers every candidate exactly once.

**A branch is never force-deleted on a stale verdict.** `git branch -d` refuses a branch merged only
into `origin/main` whenever the local `main` lags — which it usually does — so `-D` used to be the
routine path and git's last protection was overridden every time. Now `-d` is tried first, and `-D`
only after re-verifying *at that moment* that `origin/main..<branch>` is empty. Otherwise the branch is
**kept** and reported. A stale ref costs nothing; a destroyed commit costs a session.

Tests: [`tests/test_worktree_prune_merged.py`](../tests/test_worktree_prune_merged.py) drives the real
script against a synthetic repo family. Tests assert the *decision and the reason* rather than survival
— a script that has lost its primary fence still leaves the directory intact, because the `-Apply`
re-check catches it, so a survival-only assertion proves nothing — and carry a positive control in the
same invocation wherever one is possible (a refusal test refuses the whole run by design). The
`-Apply` re-check itself is driven by a **gh shim on PATH** whose merge probe performs a side effect —
a session arrives, the fence dies, the metadata is touched — before answering, which reproduces the
race deterministically with no threads and no sleeps.

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

The fence itself lives in [../scripts/coord/session-registry.ps1](../scripts/coord/session-registry.ps1)
and is shared with `sessions.ps1` — one copy on purpose, because two copies of a safety check drift and
the one that drifts is the one nobody is testing.

**`sessions.ps1 -Rehome` no longer trusts transcript mtime alone.** Moving a transcript out from under a
running session corrupts it *and* relocates a live session — the exact injury `sessions.ps1` exists to
repair. Its old guard used file mtime, which is **not** a liveness signal here: subagent and workflow
output is filed under `<sessionId>/subagents/`, so a session running a long workflow barely touches its
own transcript. Measured on this host: a verifiably-live session sat **32 minutes** idle by mtime — three
times the 10-minute `-MinIdleMinutes` default — while its process was alive and fenced. The guard now
consults the registry *and* mtime, and **refuses if either says live**, because nothing here can prove a
session is gone; only the positive answer is trustworthy.

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
