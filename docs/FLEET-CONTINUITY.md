# Fleet continuity: moving the fleet to another account

When an account runs out of usage, the fleet is closed and one fresh session is opened under a
different Claude account. That session inherits nothing: no context, no project memory, no realtime
channel to anything that was running. This is how it picks the fleet back up without anyone
hand-carrying documents.

## The one sentence

Open one session under the new account, in this repository, and paste:

```bash
pwsh -NoProfile -File scripts/coord/fleet.ps1 -ColdStart
```

That is the whole transfer. It prints a receipt, then one complete standalone briefing per
respawn-eligible seat, each of which can be handed straight to a `spawn_task` call.

## What it emits, in order

1. **The receipt, before anything else** -- what was EXAMINED, not merely what was found:
   config roots read, records read, live sessions seen, live sessions with no record, writer
   heartbeat, writer error lines. If a stop condition fired, it says so and tells you the briefing
   list is not the whole fleet.
2. **The respawn population** -- seats in state `INTERRUPTED` or `HANDED`. `RUNNING`,
   `POSSIBLY RUNNING`, `SUPERSEDED` and `CLOSED` are deliberately excluded and never respawned.
3. **One briefing per seat**, numbered, each naming the predecessor's checkout, its branch by name,
   its claims and ledger allocations, its handoff document, and -- loudest of all -- any untracked
   files, which are the only category held by no git object anywhere.
4. **The epoch bump**, to run once after respawning.

Each briefing carries the command to regenerate it alone, so a single seat can be re-emitted later
without re-running the whole thing.

## Why the receipt comes first, and why it can refuse

An empty roster and a dead writer produce the same output. So do a healthy quiet fleet and one whose
hooks were silently disabled by `disableAllHooks`, by org policy, or by workspace trust. The person
reading this output is, by construction, the one least able to tell those apart -- they are reading
it because they lost the context that would have told them.

So a cold start that found nothing says so against the receipt rather than reporting an all-clear,
and `liveSessionsWithoutRecord` supplies the missing denominator by starting from the liveness fence
and subtracting, so a dead writer appears as a positive count instead of as silence.

## Constraints, stated because they are easy to assume away

- **Same filesystem only.** A briefing names paths -- the predecessor checkout, its handoff document
  -- rather than carrying their bytes. Nothing under `.git/mefor-coord` is version controlled, so it
  does not travel with a clone or a push. Moving to a different machine needs an export bundle,
  which is not built.
- **These do not cross an account boundary and must not be inherited:** usage figures, project
  memory, artifact capabilities, workflow caches, and the realtime send channel. Read your own.
- **Nothing detects the switch.** It is an owner act. `seat.ps1 -BumpEpoch` records it so that
  "written before the switch" becomes a stored fact rather than an inference from a credential
  directory label; no collector triggers it.
- **A briefing is a measurement with a timestamp, not current state.** It was generated before it
  was read, and this repository has watched one unchanged commit carry three different SHAs across
  rebases inside a few minutes. Re-verify before acting; never treat a commit id in a briefing as an
  identifier.

## Where the state comes from

`scripts/coord/seat.ps1` writes one episode record per (worktree, session) as a `Stop` hook, at
`<git-common-dir>/mefor-coord/seats/<boxKey>/<sessionKey>.json`. It needs no discipline from anyone
-- it derives what it can from git and the harness payload, and `-Declare` adds intent on top and is
expected to be missing.

`scripts/coord/fleet.ps1` is a pure reader over those records. It stores nothing, and it holds no
liveness opinion of its own: the fence is `session-registry.ps1`'s, dot-sourced rather than copied.
Every verdict is computed at read time, because a stored verdict is read after the world moved.
