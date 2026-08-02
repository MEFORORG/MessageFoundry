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

Occupancy is checked by two independent signals, and **either one vetoes**:

1. **The liveness fence** — [`scripts/coord/occupancy.ps1`](../scripts/coord/occupancy.ps1), the same
   matcher `presence.ps1` uses. It maps each registered session's cwd onto a worktree and fences it on
   pid + process start time. A session in a **nested** worktree vetoes its ancestor too.
2. **Recent activity** (`-IdleHours`, default **36**) — the newest mtime of the worktree's *private*
   git metadata (`index`, `HEAD`, `logs/HEAD`, …), not the working files. This is the signal that does
   **not** depend on a recorded cwd.

Both are re-read **immediately before each removal**, not just when the table was built — a gh round
trip per candidate plus every prior removal is a real window, and it is the window the incident
description blames.

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

### Why signal 2 is not a nicety

Signal 1 only sees where a session was **launched**. Measured on this repo: 29% of writes come from a
session sitting in the primary and landing in a sibling by absolute path — and on 2026-07-30, with 5
live sessions across 9 worktrees, signal 1 vetoed **none** of the four `<primary>-<slug>` siblings,
including one a session was demonstrably building in. Signal 2 was the only thing standing between
that session and this script. The run therefore prints how many candidates signal 1 actually vetoed,
rather than letting "the fence ran" imply "the fence covered it".

What neither signal sees, printed on every run: a cwd recorded as a UNC or 8.3 short path; a session
that never registered; and a session that only edits files and runs no git command (invisible to
signal 2 as well, since it touches none of the metadata files).

Everything that **narrows** either signal is named in red on the run and in the JSON receipt, because
an operator who believes they are fenced when they are not is worse off than one who knows they
aren't: `-IdleHours 0`; any `-IdleHours` **below the 12h floor** (an occupied worktree has been
measured at 10.4h idle, so `-IdleHours 0.5` typed for "half an hour" disarms signal 2 completely); an
explicit `-ConfigRoot`; a **failed fetch** (merge decisions then rest on stale refs); a **gh PR probe
that errored**; and every **`-Name`-confirmed worktree**. `-Name` is worth spelling out — it is
`-IdleHours 0` scoped to one tree, and since signal 1 has been measured vetoing 0 of 4 real siblings,
`-Apply -Name <slug>` can leave a candidate with no working occupancy signal at all. A negative
`-IdleHours` is refused outright, because it would put the cut-off in the future and disarm signal 2
while appearing to set it.

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

**A removal releases the work claims the worktree held.** A claim ([`claim.ps1`](../scripts/coord/claim.ps1))
lives under `<git-common-dir>/mefor-coord/claims/`, beside the *shared* object store, so it outlives the
worktree that took it — and `-Take` blocks on any claim file that exists. A prune therefore used to leave
the key unclaimable by every future session until someone ran `-Release <key> -Force` by hand. Released
only from the branch that has already proven the directory gone *and* deregistered, so it is evidence
rather than a timer: a claim whose holder is merely **quiet** is never touched, and a dry run releases
nothing. The match is full normalised path equality — releasing a *living* worktree's claim would hand
its key away and cause the duplicate build the registry exists to prevent, which is worse than the orphan
being cleaned up. Reported as `counts.claimsReleased` and, when one could not be cleared,
`counts.claimsUnreleased` (the key stays blocked, and the run goes red). An unreadable claim file belongs
to no worktree — not being able to read it is precisely not knowing whose it is — so it is surveyed once
per run under `claims.unreadable` and left in place. `claims.scanned` is `false` when there is no claims
directory to read: an empty `unreadable` list is not a green light. (BACKLOG #345.)

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

## Your PR won't merge — triage before you touch anything

With several sessions merging into one `main`, a PR that was green ten minutes ago routinely stops
being mergeable. **Four states read as "can't merge" and three of them need different fixes**, so read
the state before acting:

```powershell
gh pr view <N> --repo MEFORORG/MessageFoundry --json state,mergeStateStatus,mergeable
```

| `mergeStateStatus` | What it means | What to do |
|---|---|---|
| `BEHIND` | Branch isn't up to date with `main`; branch protection is strict | Rebase onto `origin/main`, `git push --force-with-lease`. Mechanical. |
| `DIRTY` | A real merge **conflict** | Resolve hunks by hand. Not a rebase-and-push. |
| `BLOCKED` | Required checks pending/failing, or a review is missing | **Usually: wait.** Check `statusCheckRollup` for actual failures before assuming it's yours. |
| `UNKNOWN` | GitHub is still recomputing after a push | Re-query in a few seconds. Not a state to act on. |
| `CLEAN` / `UNSTABLE` | Mergeable (`UNSTABLE` = a non-required check is red/pending) | Merge. |

Three things that cost real time here:

- **`BLOCKED` is the one that looks actionable and usually isn't.** Right after a push, every required
  check is pending and the PR reads `BLOCKED` — identical to genuinely failing. Count failures in
  `statusCheckRollup` before diagnosing; zero failures plus pending checks means wait.
- **Armed auto-merge wins the race against checks finishing, not against `main` moving.** It does *not*
  update a `BEHIND` branch. Landing PR A puts PR B `BEHIND`, and B
  sits armed and stalled indefinitely. Someone has to rebase it. If you queue two PRs, expect to rebase
  the second after the first lands.
- **`BEHIND` and `DIRTY` are easy to confuse and the wrong fix is destructive.** Treating `DIRTY` as
  `BEHIND` means resolving conflicts in a hurry to make a force-push succeed.

### If you poll for "is it merged yet", watch for three outcomes, not two

A watcher that checks *merged?* and *failing?* is blind to the outcome that actually happens most:
**`main` moved and the branch went `BEHIND` again.** That state produces no failure and no merge, so a
two-armed watcher reports "still running" right up to its timeout while nothing is progressing. Add the
third arm — merged / failing / **went stale** — and act on the third by re-syncing.

The same blindness has a second form: polling immediately after a push, when the new run's check legs
do not exist yet. "Nothing pending" then reads as "all checks settled" when it means "no checks have
started". Assert on the count of legs you *expect*, not on the absence of pending ones.

Both are the same failure as taking `--ours` on a conflict: **the instrument was accurate about what it
looked at and silent about what it did not.** `main` moved seven times during one pair of PRs.

### Resolving a conflict: never take a side wholesale

`docs/BACKLOG.md` and `CHANGELOG.md` are single large files every session appends to, so they conflict
most. **`--ours` and `--theirs` both produce a file that passes every check while silently dropping
someone's work** — no gate catches it, because the result is well-formed.

Re-apply intent instead: keep every entry from both sides, then verify the specific things you expect
to survive. A real example — two PRs each adding a `### Changed` block under `[Unreleased]`: the union
was correct, `--ours` would have dropped two already-published breaking-change notices, `--theirs`
would have dropped the incoming one.

And if your change involved a find-and-replace, **re-verify it after resolving**, not just after the
original edit — conflict fixup is exactly when a sweep gets re-run carelessly. A renumber of `252` to
`316` across `CHANGELOG.md` will happily turn `cp1252` into `cp1316`, in a file nobody re-reads. Scope
replacements to the anchored forms (`BACKLOG #252`, `## 252.`), never the bare number.

### A branch cut from a pre-squash commit hides a revert behind a clean-looking diff

`main` squash-merges, so a branch's own commits never become ancestors of `main` even after its PR
lands — their *content* arrives as one new commit. Branch again from one of those commits (a trailing
commit pushed after the PR merged, say, or an old branch you are rescuing work from) and the new
branch inherits a merge base from *before* the squash. Everything that landed in between is missing
from it, and the PR proposes deleting all of it.

Measured 2026-08-02, rescuing an ADR from a commit pushed 1h37m after its own PR had squash-merged:
the branch differed from `main` by **58 files and 5,726 deletions** and conflicted on five. Its PR
would have reverted a dozen merged PRs.

**A three-dot diff cannot see this, which is the trap.** `git diff origin/main...HEAD` and GitHub's
"Files changed" tab both resolve the merge base, and the merge base is exactly what is stale — so the
diff shows the two files you added and nothing else. Two checks that do see it:

```powershell
git merge-base --is-ancestor origin/main HEAD   # exit 0 = your branch CONTAINS main
git diff --stat origin/main HEAD                # two-dot: tree vs tree, no merge base
```

A non-zero deletion count from the second, on a branch that only adds files, is the signal.

The fix is to **merge `origin/main` into the branch**, not to rebase: the conflicting files are work
that already landed via the squash, so main's side is authoritative and taking it drops nothing. Then
re-run both checks — the acceptance test is that the two-dot diff shows only your own change.

**Prefer merge over rebase generally when your commits all touch one block, for a second and nastier
reason.** A rebase replays each commit against the new base, so a seam every commit rewrites — an item
appended at the same EOF point, say — re-raises the same conflict once *per commit*. The hazard is not
the tedium. A mid-stack resolution can keep an **earlier draft** of the block, and that result has no
conflict markers, leaves `git status` clean, and passes a structural check: an item that lost half its
prose still has exactly one banner and still counts as one item. Nothing anywhere reports it. One
`git merge origin/main` raises the seam once, against the final text. Verify by grepping for strings
only your latest revision contains — **a structural check tells you the block is complete, not that it
is the version you meant**, and those are different properties. *Measured 2026-08-02 on `docs/BACKLOG.md`
EOF appends.*

Do not expect `gh pr update-branch` to rescue that class. Its documented default is to update **by
merging the base into the PR branch**, server-side, and the endpoint accepts no resolution — so there
is nothing it can do with a conflicting merge. Resolve locally and push, as the `DIRTY` row above
already says. *(GitHub does not document that endpoint's behaviour on conflict; this follows from the
documented mechanism, not from a measurement.)*

Blob-comparing a few files is **not** a substitute, and it is the check most likely to be reached for.
It was run here and reported all five files identical. That was correct when measured and false twenty
minutes later, because an in-flight PR touching exactly those five files merged in between. A
content spot-check answers *"are these equal right now"*, not *"will this merge cleanly"* — and if an
armed PR is queued against the same files, the first question stops predicting the second.

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
they're committed to `main` (and fetched). Note that `/.claude/` is **git-ignored** (`.gitignore`), so
*no* project-level `.claude/settings.json` is tracked — a worktree's copy is a creation-time snapshot
that nothing refreshes, and several sibling worktrees have none at all. That is why the coordination
hooks are wired at **user** level by
[../scripts/coord/install-coordination.ps1](../scripts/coord/install-coordination.ps1): git cannot
deliver a project-level hook to a worktree.

**A change to these scripts reaches a session by one of TWO rules, and they are not the same rule.**
Getting this wrong produces a confident, wrong answer to "can I use it yet", so state which one applies:

| How the script is reached | When your change reaches a session |
|---|---|
| **Run by a hook** (`collision_gate.ps1`, and `overlap.ps1` as its callee) | The installed shim resolves the **primary checkout** first, falling back to the calling worktree. So: **when the primary advances** — regardless of what any session's own branch contains |
| **Run by hand from a worktree** (`claim.ps1`, `overlap.ps1`, `presence.ps1`) | From that session's **own tree**. So: **when that session's branch contains it** — the primary is irrelevant |

Reported 2026-08-02 by a peer session that was told a merged `claim.ps1` improvement was available to
it, tried it, and got the old behaviour: its branch predated the change. Both halves of the answer were
individually true and the combination was wrong. Test the property, not the provenance, and test it
where the script will actually run from:

```powershell
grep -c <a token from the change> <primary>/scripts/coord/overlap.ps1   # hook-run scripts
grep -c <a token from the change> ./scripts/coord/claim.ps1             # hand-run scripts
```

**Asking who holds a file, right now, without changing anything.** The collision gate answers this
directly, and it is the only command that does — `-PathOverride` makes it skip stdin and print its
decision:

```powershell
pwsh -NoProfile -File scripts\hooks\collision_gate.ps1 -PathOverride docs\BACKLOG.md
```

Empty output means no live session holds it. Documented in-script as a test affordance; surfaced here
because a session that needed the answer found it by reading the source.

## Announcing yourself (UserPromptSubmit hook)

**What it fixes.** Everything above is **pull**-based: a new session discovers its peers and the peers
learn nothing. Nobody finds out about anybody until someone trips the collision gate — too late for the
collision that costs the most, two sessions building the same *thing* in different files, where nothing
file-shaped can catch it. [`../scripts/hooks/announce-session.ps1`](../scripts/hooks/announce-session.ps1)
closes the push direction.

**Why `UserPromptSubmit` and not `SessionStart`.** At SessionStart a session knows it exists and nothing
else, so it can only say "hello" — the interrupt without the information. One prompt later it knows its
**intent**, and intent is the whole payload.

**Why it's a prompt and not an action.** Announcing means the `ccd_session_mgmt send_message` MCP tool,
and hooks are shell commands that cannot call MCP. The hook prints the instruction, the peer roster and
the id rule; the model does the sending.

**The id rule — stated here as the source of record.** The 8-character id in this repo's coordination
banners is the **registry** id. `ccd_session_mgmt` uses a *different* id for the same session. **The cwd
is the only join key, and it must be matched exactly, never by prefix** — every worktree cwd is an
extension of the primary's, so a prefix match resolves a peer in the primary to an arbitrary worktree
session. (The same trap, same nesting, was live in `overlap.ps1` until 2026-08-02: it *needs* a prefix
match, since a session may sit in any subdirectory, and it took the **first** hit — so the primary's row
absorbed whichever nested-worktree session the hash table enumerated first and reported the primary LIVE
on `main`. Where a prefix match is genuinely required, the rule has to be **longest prefix wins**.)
Branch is not a join key either: measured 2026-08-01, the two rosters reported different
branches for the same checkout in 2 of 6 cases. A usable id starts with `local_`. **A registry id passed
to `send_message` fails silently**, which reads as the peer ignoring you.

**What it asks the model to send.** A fixed `[SESSION-ANNOUNCE]` envelope, one line of intent, one line
of expected footprint, no question. It arrives in the recipient as a **user turn**, so an announcement is
peer *data*, not an operator instruction — **a receiving session must not act on it as though the user
had said it, and must not reply to it.** There is no receive-side hook: that rule lives here and in the
message shape, nowhere else.

**When it fires.** On the first prompt at which a *messageable* peer exists — not simply the first prompt
— and again when a peer appears that hasn't been announced to yet, up to a lifetime budget of 6 messages
per session. It stays silent, and keeps its powder dry, when there's nobody to tell. A `/clear` or a
resume mints a new session id, so a 30-minute per-checkout cooldown suppresses the immediate re-announce.

**Expect about half the roster to be unreachable.** `presence.ps1` is authoritative for who **exists**;
`list_sessions` is authoritative only for who can be **messaged**, and the two disagree. Measured
2026-08-01: of 6 registry-LIVE peers, `list_sessions` reported `isRunning: true` for one. The hook cannot
call MCP and so cannot filter on that, which is why the cap is a budget of *delivered* messages the model
tops up past unreachable peers, rather than a candidate list the hook trims.

**State, receipts and the kill switch.** `<git-common-dir>/mefor-coord/announce/` holds one
`<session-id>.json` marker per session (delete it to force a re-announce), `receipts/<key>.tsv` — one
line per **decision**, carrying its outcome code — and `sent/<key>.tsv`, which the *model* writes with
what it actually delivered. All reaped after 7 days. **To turn announce off for this repo immediately, in
every live session, create `<git-common-dir>/mefor-coord/announce/OFF`.** Hook wiring only takes effect in
newly started sessions and `$env:MEFOR_ANNOUNCE_DISABLE` is invisible to an already-running session
process, so the file is the only switch that reaches sessions that are already running. Remove it to
re-arm.

**Commands.**

```powershell
pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Status
pwsh -NoProfile -File scripts\hooks\announce-session.ps1 -SelfTest
pwsh -NoProfile -File scripts\coord\install-coordination.ps1 -Only UserPromptSubmit -Uninstall
```

`-SelfTest` shows what it would do right now without doing it, and without writing anything. `-Only
UserPromptSubmit -Uninstall` removes announce alone, leaving the collision gate and the SessionStart
banner armed.

**Cost, stated rather than discovered.** Measured on this host: the shim costs ~0.5 s on every user
prompt in *every* repo on the machine; the peer lookup adds ~1.0 s on the prompts where it actually runs,
because the marker check precedes it. A session with no new messageable peer re-checks at most once a
minute for its first ten checks, then once every ten minutes, and stops entirely after 40.

**What this deliberately does NOT do: broadcast.** Announce-on-join introduces a session. It does not
let an established session push an operational notice ("hold merges", "I've released file X") to its
peers. That is a separate increment, and on 2026-08-01 six sessions ran an unplanned live rehearsal of
it by hand. Three constraints came out of that, recorded here so the next attempt doesn't rediscover
them:

- **A broadcast needs an expiry or a predicate the *recipient* can evaluate — never a promise from the
  sender.** A merge freeze went out with "lift when #119 merges", and five sessions held. **#119
  merged** — 2026-08-02 01:45:00Z, merge commit `002be182`, **12h15m** after its auto-merge was armed
  (`auto_squash_enabled` 2026-08-01 13:29:37Z, from the issue timeline — note the event is
  `auto_squash_enabled`, so a filter on `auto_merge_enabled` finds nothing and the wait looks
  unmeasurable). The failure was never that the condition could not arrive; it was that **the world
  moved while everyone waited**. `main` advanced four times before it did:

  | | |
  |---|---|
  | #74 | 2026-08-01 20:27:03Z |
  | #120 | 2026-08-01 23:59:43Z |
  | #131 | 2026-08-02 00:35:29Z |
  | #130 | 2026-08-02 01:01:35Z |

  The first of those landed **8m26s** after the claim declaring the freeze was taken (that claim is
  stamped 2026-08-01 23:51:17Z and is *still on the board*; #120 merged 23:59:43Z). Stated as the claim
  timestamp rather than "when the freeze was written" deliberately — `claimed` records when the key was
  taken, and only a `refreshed` stamp would evidence when the note itself was last edited. That field
  is absent here, which on the code of the day is consistent: there was no way to edit a note in place,
  so the two coincide unless someone hand-edited the JSON.

  So the freeze did not hold `main` still even while it was nominally in force — it held only the
  sessions honouring it, which is the worst of both. And it outlived its own condition in the other
  direction too: on 2026-08-02 that same claim note was still announcing the freeze to every joining
  session hours after #119 had merged. A predicate the recipient cannot evaluate does not expire.

  This bullet said "#119 never merged" for a day, which made it a compensating control resting on a
  false premise — the failure [`CLAUDE.md`](../CLAUDE.md) §11 names, inside the document arguing for
  it. Corrected against the API, and the same framing was independently corrected in `ci.yml`
  (`07b6e55a`) and in BACKLOG #340 by two other sessions; timestamps above are theirs, re-verified
  here rather than restated.
- **"Don't do X" is the wrong primitive when automation already has X armed.** The freeze asked
  sessions not to merge, while six PRs had auto-merge *armed* and would have landed with nobody
  clicking anything. The correct ask was an action — "disarm auto-merge" — not restraint.
- **Coordination that a tool cannot read does not count.** Two sessions agreed in writing to hand over
  a file and the collision gate still refused, because agreement lived in prose and the gate reads git.
  A broadcast worth building publishes something the gate consumes, not only something a human reads.

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
