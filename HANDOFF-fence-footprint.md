# Handoff — worktree occupancy fence, write-footprint signal

**Stopped:** 2026-07-30 ~14:50, mid-run, by request. Nothing is lost; nothing is pushed.
**Branch:** `fence-footprint` @ `a7c5199a` — working tree **clean**, 9 commits, **UNVERIFIED**.
**Worktree:** the `MessageFoundry-fence-footprint` sibling checkout

---

## The problem this was solving

`scripts/worktree/prune-merged.ps1` decides whether a worktree is safe to delete. Its occupancy
fence had two signals:

- **signal 1** — the liveness fence: places a session inside a worktree by matching the session's
  recorded **cwd** against registered worktree paths;
- **signal 2** — git-metadata activity within `-IdleHours` (default 36h).

Measured on this repo on 2026-07-30 with 4 live sessions, **signal 1 placed sessions inside 0 of 4
candidates.** It contributed nothing. Signal 2 — a crude "somebody touched `.git` recently" guess —
was the only thing standing between a live session and a destructive removal.

The reason is that **a session's cwd is not where it writes.** The canonical case is the session
that commissioned this work: cwd was the primary checkout while it spent three hours writing,
testing and committing inside `MessageFoundry-prunefix`. The fence would have called prunefix
unoccupied.

## What got built (9 commits, on top of PR #74)

New **signal 3**: a per-session write footprint, plus a worktree "pin". Two new files
(`scripts/coord/footprint.ps1` ~800 lines, `scripts/coord/pin.ps1` ~296) and a third
(`scripts/worktree/worktree-pin.ps1`). ~2,000 lines net across coord + worktree scripts, docs and
tests.

```
a7c5199a  test+docs: the junction test passed because its fixture leaked the needle through cwd
6d01dbb3  fix: -Apply froze the one signal with coverage and refreshed only the guess
61c2aafd  fix: the birth pin outlived the worktree it named and took the whole fence down with it
851847b6  fix: a corpus scanner it does not use could silently empty the SessionStart roster
cd21ebdd  fix: the funnel in front of the placement made the .git fallback unreachable
c6d0a27d  feat: nothing in the fence could see a human, and a brand-new worktree had no cover
4d5461a2  test+docs: prove the write footprint by mutation, not by passing
e1453c9d  fix: the only occupancy signal that protected a prunable worktree was a 36h guess
aeb36faa  fix: occupancy placed a session where it LAUNCHED, never where it wrote   ← the core fix
```

Two findings worth keeping regardless of whether the code survives:

- **The fence could not see a human at all.** The session registry only knows about Claude
  sessions. You, working in a worktree, were invisible to signal 1 — and a freshly-created
  worktree has no git activity yet, so signal 2 gave it no cover either. New worktrees were the
  least protected, not the most.
- **Fail-closed applied carelessly is its own outage.** `61c2aafd` — a stale "birth pin" naming a
  worktree that no longer existed made the *entire* fence unavailable, permanently. A safety guard
  that bricks itself is one people switch off.

`docs/WORKTREES.md:151` carries the reasoning under *"Why signal 3 exists: signal 1 was measured
contributing nothing"*, including a note at `:204` that `-IdleHours 0.5`, typed meaning "half an
hour", silently disarms signal 2 completely.

## ⚠️ What is NOT done — read this before trusting any of it

**The deliverable was the measurement, and it was never produced.** The run was killed during the
final Measure phase. So:

1. **No before/after receipt exists.** Whether signal 3 actually places real sessions inside real
   worktrees on this repo is **unknown**. The whole premise of the task was that a green test suite
   over synthetic fixtures does not count as evidence — and a green test suite is all there is.
2. **The verification bar was never run to completion by me.** No confirmed ruff / mypy / pytest
   counts. Assume nothing passes until you have run it.
3. **The adversarial findings were partially applied.** Commits `cd21ebdd` through `a7c5199a` read
   like Refute-phase fixes landing, but there is no triage record saying which findings were fixed
   and which were judged not real. That record does not exist.
4. `a7c5199a` says a test *"passed because its fixture leaked the needle through cwd"* — i.e. at
   least one test in this branch was green for the wrong reason and was caught. Assume there are
   others that were not.

## ⚠️ Branch topology — the trap

`fence-footprint` is **stacked on `prunefix`**, not on `main`. It contains all of PR #74 plus a
merge of main (`39cc939c`). That was the right call — both edit the same fence code — but:

**PR #74 squash-merges.** After it lands, `main` gets one commit containing prunefix's content
while this branch still has the four originals. A plain `git rebase main` will try to replay
changes already present and conflict.

Use this instead, replaying only what is above prunefix's tip:

```
git rebase --onto main d806aa1d fence-footprint
```

## To resume

The workflow script is preserved and resumable — unchanged agents replay from cache:

```
Workflow({
  scriptPath: "<claude-projects-dir>/workflows/scripts/fence-write-footprint-wf_53264ea5-4be.js",
  resumeFromRunId: "wf_53264ea5-4be"
})
```

where `<claude-projects-dir>` is this worktree's session directory under
`~/.claude/projects/`, session `c0d9ffa7-5010-4538-8b0c-e037ce76d344`.

Per-agent returns, including the recon and the design judgement, are in that same directory under
`subagents/workflows/wf_53264ea5-4be/journal.jsonl`. **Read that before diagnosing anything** —
do not assume cached results are non-empty.

If resuming, the first thing to do is the thing that never happened: **run the fence dry-run
against the real repo and get the after-number.** If it is still 0 of N, the 2,000 lines are not
worth landing, and that is a legitimate outcome to discover.

**Safety, unchanged:** never `-Apply` against the real repo — sessions are live in it and `-Apply`
destroys worktrees. Dry run only; `-Apply` exclusively against synthetic fixtures.

## Left running deliberately

**PR #74** (`prunefix` — the original prune-merged fix) is open, auto-merge armed, 32 checks
passing, none failing. That work **is** verified: I mutation-tested both load-bearing guards
myself, and confirmed the shipped script said `PRUNE` on `MessageFoundry-pins` where the fixed one
says `SKIP - recently active (13.52 h)`. It keeps going `BEHIND` because other sessions merge
faster than it updates. It is independent of everything above and safe to let land — say so if
you would rather it did not.
