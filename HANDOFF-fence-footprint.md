# Handoff — worktree occupancy fence, write-footprint signal

**Stopped:** 2026-07-30 ~14:50, mid-run, by request. Nothing is lost; nothing is pushed.
**Branch:** `fence-footprint` @ `b6c4fb7d` — 12 commits above prunefix's tip (`d806aa1d`), plus an
**uncommitted** canary-4 fix and its tests in the working tree (see Status item 5). The `a7c5199a`
this line used to pin is stale.
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

## Status — the measurement now exists; here is what it says, and what is still not done

**The deliverable was the measurement, and it has now been produced.** The original run was killed
during the final Measure phase, which is why this section used to say no before/after receipt
existed. That is no longer true, and it also contradicted `prune-merged.ps1`, whose header had
already recorded an after-number. Measured **2026-07-30**, real repo, dry run only, by the follow-up
session working this same checkout — deliberately *not* by the session that built signal 3, because
the 7-candidate figure in the docstring was taken by its own author and is not independent of it:

1. **The after-number, on 10 real candidates.** **Signal 1 placed a session inside 1 of 10; signal 3
   placed one inside 9 of 10**, on **164 cross-tree writes** — writes that landed in a worktree from
   a session whose recorded cwd was somewhere else. The premise survives contact with real data, not
   just with fixtures. It was not 0 of N, which was the outcome that would have made the branch not
   worth landing.
2. **The protection delta, isolated.** Re-run with signal 2 disarmed (`-IdleHours 0` — the `-Name`
   case, and the case an operator reaches for precisely when the tool refuses), the **pre-branch code
   decided PRUNE on 4 worktrees that live sessions were actively writing into. This branch decides
   SKIP on all 4.** Both runs were **dry runs** — `-Apply` is never pointed at the real repo, and
   `git worktree list` still shows all 10 siblings — so the 4 is a decision that would have been
   acted on, not damage that was done. That is the number the whole exercise was for. At *default* flags the two behave identically: signal 3's
   veto set was a strict subset of signal 2's, and the docstring says so in those words. The value is
   concentrated where signal 2 is off or narrowed, and this is that measurement.
3. **Corpus scale behind those runs.** 779 in-window transcripts over 36h; the receipt reads
   `pathToolBlocks=9229, pathBlocksExamined=9107, writeToolNamesSeen=[Edit, Write]`. Every
   path-bearing tool name in the corpus is classified except `EnterWorktree` (13 blocks).
4. **The verification bar, as recorded on 2026-07-30 on this branch:** `ruff check . && ruff format
   --check .` clean, and `python -m pytest tests/test_worktree_prune_merged.py -q` green apart from
   one pre-existing, environment-dependent failure noted below (venv at `.venv\Scripts\python.exe`).
   Re-run both before landing — the suite takes ~10 minutes, and a recorded count is not a run you
   watched.
5. **Canary 4's own false positive is fixed, in the working tree and not yet committed.** As shipped,
   `footprint.ps1`'s fourth canary faulted whenever a window held path-bearing tool calls but no
   *write* tool call — which is the signature of the tool-rename regression it exists to catch **and**
   the signature of an ordinary quiet window, and those are not separable by tool name. When it fired,
   the whole fence went UNAVAILABLE, every candidate became SKIP and the run exited 2, with no
   override flag: the exact failure shape canary 1 had already been rewritten to remove. Replaying it
   hourly over 1,109h of real history (13,315 transcripts, 4 config roots) fired it once, at
   2026-06-22T18Z, against a corpus where 87% of transcripts contain no write block at all. It is now
   split on *positive* evidence — a new negative allow-list `$FootprintKnownNonWriteTools` and a
   counter `PathBlocksUnclassified`. A path-bearing tool name **neither** list claims still hard-faults
   (a renamed write tool lands there by construction); zero writes with every name accounted for is a
   loud non-blocking note on the existing REDUCED ASSURANCE channel. The new fault set is a strict
   subset of the old one, so this cannot invent a refusal. Three regression tests pin it:
   `test_a_READ_ONLY_window_does_not_brick_the_pruner`,
   `test_an_ENTERWORKTREE_only_window_does_not_brick_the_pruner`, and
   `test_an_UNCLASSIFIED_path_bearing_tool_name_is_a_fault` — the last of which proves the refusal
   through the corpus rather than by mutating the file under test.

Still open, and still worth distrusting:

- **`test_a_broken_roster_does_not_silently_empty_the_coordination_banner` fails on this host, and
  fails identically on the pristine branch tip.** Its control leg shells out to the *real*
  `scripts/coord/session-context.ps1` in the real repo and asserts the banner does **not** say
  `PEER ROSTER UNAVAILABLE`; on a machine where `presence.ps1` currently produces no output, it does.
  That is a test coupled to live machine state, not a regression in the fence — but it is a red test
  in the suite and it needs either a stubbed roster or a skip guard before this branch lands.
- **The adversarial findings were partially applied.** Commits `cd21ebdd` through `a7c5199a` read
  like Refute-phase fixes landing, but there is no triage record saying which findings were fixed and
  which were judged not real. That record still does not exist.
- `a7c5199a` says a test *"passed because its fixture leaked the needle through cwd"* — i.e. at least
  one test in this branch was green for the wrong reason and was caught. Assume there are others that
  were not.
- **Spun out, deliberately not smuggled into the canary-4 fix:** whether `EnterWorktree` should count
  as a WRITE tool (and therefore veto a worktree in its own right) is a real and larger question. It
  is currently listed as provably-non-writing on its declared schema, which changes no behaviour.
  Also still owed: one re-run of the 1,109 h hourly replay against the *patched* predicate, recording
  `pathBlocksUnclassified` per hour. The suppression claim is presently an inference from the 36 h
  vocabulary census rather than from the replay, and that gap is cheap to close now the counter exists
  and is in both the console line and the JSON receipt.

## ⚠️ Branch topology — the trap

`fence-footprint` is **stacked on `prunefix`**, not on `main`. It contains all of PR #74 plus a
merge of main (`39cc939c`). That was the right call — both edit the same fence code — but:

**PR #74 squash-merges.** After it lands, `main` gets one commit containing prunefix's content
while this branch still has the four originals. A plain `git rebase main` will try to replay
changes already present and conflict.

Use this instead — fetch first, and rebase onto the **remote** main, replaying only what is above
prunefix's tip:

```
git fetch origin && git rebase --onto origin/main d806aa1d fence-footprint
```

The command this handoff originally carried, `git rebase --onto main d806aa1d fence-footprint`, is
wrong twice. **It targets the local `main`**, which at the time this was written lagged `origin/main`
by two commits, so the rebase would have quietly rebuilt the branch on a stale base and left it
behind what everyone else is merging into — a local ref is not the integration branch, and nothing in
the command refreshes it. **And its replay set, `d806aa1d..fence-footprint`, still contains
`1d6ea162`** ("ci: surface a failing nightly", #72), which is already in `main` — it reached this
branch through the merge `39cc939c` — so the rebase would try to replay a change that is already
present and conflict, which is the exact failure the `--onto` was chosen to avoid. Fetching and
naming `origin/main` fixes both at once: the base is current, and `1d6ea162` is recognised as already
upstream and dropped instead of replayed.

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

The dry run against the real repo — the thing that never happened, and the gate on whether the
~2,000 lines were worth landing — **has since been run**; the after-number and the `-IdleHours 0`
delta are in the Status section above. What is left to resume is the missing triage record, the
host-coupled roster test, and the two spun-out items, not the measurement.

**Safety, unchanged:** never `-Apply` against the real repo — sessions are live in it and `-Apply`
destroys worktrees. Dry run only; `-Apply` exclusively against synthetic fixtures.

## Left running deliberately

**PR #74** (`prunefix` — the original prune-merged fix) is open, auto-merge armed, 32 checks
passing, none failing. That work **is** verified: I mutation-tested both load-bearing guards
myself, and confirmed the shipped script said `PRUNE` on `MessageFoundry-pins` where the fixed one
says `SKIP - recently active (13.52 h)`. It keeps going `BEHIND` because other sessions merge
faster than it updates. It is independent of everything above and safe to let land — say so if
you would rather it did not.
