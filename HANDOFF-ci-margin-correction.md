# HANDOFF — ci-margin-correction

Written 2026-08-02 ~04:00Z, winding down at the owner's stop-work instruction (relayed via another
session; usage cap). Claim key: `ci-margin-correction`.

**If you read one line:** the cap raise in #131 was correct and is unchanged. Its *justification* was
wrong in every row, and #138 fixes it. Don't re-litigate the decision; don't trust the old numbers.

---

## 1. STATE

| | |
|---|---|
| Branch | `claude/ci-margin-correction` @ `8e71fcdf`, pushed, **0 behind main** |
| PR | **#138**, OPEN, auto-merge **ARMED** (squash) |
| CI | **2 failures** — see BLOCKED ON |
| Uncommitted | none (this file is the only addition) |

The worktree carrying this branch has a *different* recorded HOME branch, so a session-start hook will
warn about a possible worktree-hijack. That is expected: the branch was created here deliberately
because the previous one had been squash-merged and could not fast-forward.

---

## 2. DONE (landed on main)

| SHA | What |
|---|---|
| `f7e12695` | #74 — prune-merged worktree destruction fix (was stalled since 2026-07-30) |
| `28d186b5` | #131 — Windows step cap 26→36, job 30→40; stall detector; BACKLOG #340 + #344 |
| `002be182` | #119 — ADR 0154 increment B (I updated its branch when its owner went idle mid-task) |

**Shipped in #131 and still current:**
- `scripts/ci/check_stalled_prs.py` + `.github/workflows/stalled-prs.yml` — daily, **advisory by
  placement, must never become required** (it reports on *other* PRs; a stall on one would block
  another).
- Signature: `state=OPEN AND mergeStateStatus=BEHIND AND failing=0 AND pending=0`. Matches `BEHIND`
  **only** — `BLOCKED` is excluded deliberately, because `BLOCKED` self-resolves and `BEHIND` cannot
  clear without external action. Verified against all four states.

---

## 3. IN FLIGHT — PR #138

Corrects #131's own justification. **The 36:00 step decision is unchanged and remains correct.**

Measured over **all 101 CI runs created 2026-08-01** (`gh api --paginate`), timing each leg's
`Tests (pytest)` **step**, filtering on the **step's own** conclusion:

```
leg              #131 claimed   TRUE      n     old cap   true margin
ubuntu-latest    12:27          12:31     57    19:00     1.518x
windows-2022     18:39          21:34     52    26:00     1.206x
windows-2025     24:35          25:51     49    26:00     1.006x   <- NINE SECONDS
```

Also raises `job_timeout` on all three legs, because the job cap was the binding constraint and
**nobody was watching it**:

```
leg       step + web-console(max) + overhead   old job      new job
ubuntu    19:00 + 1:58 + 0:41 = 21:39          22:00 +21s   26:00 +4:21 (1.20x)
W22/W25   36:00 + 3:27 + 0:41 = 40:08          40:00  -8s   46:00 +5:52 (1.15x)
```

---

## 4. BLOCKED ON

**#138 CI: `sql server (store + connector) 2022` FAILED, which fails `CI gate`.**

```
tests/test_sqlserver_store.py::test_cipher_invocations_upsert_is_atomic_and_additive
pyodbc.OperationalError: ('HYT00', ... 'Query timeout expired (0) (SQLExecDirectW)')
1 failed, 148 passed in 60.19s
```

**Do not call this a flake without proving it.** This repo's two famous "flakes" were a livelock and a
test that was right. What is known: #138's diff is `.github/workflows/ci.yml` only — the matrix values
for the ubuntu/W22/W25 `test` legs and the comment above `Tests (pytest)`. The sqlserver leg is a
separate job whose timeouts I did not touch. So a causal path from this diff to that failure is not
obvious, but **it has not been ruled out**. Next step: re-run the single job and check whether it
reproduces, and compare against the same test on `main`.

Note the failure is itself a fixed wall-clock bound expiring (a *query* timeout) — i.e. plausibly
another BACKLOG #344 instance, in a third place.

**Who clears it:** whoever picks this up. #138 is armed, so it lands by itself once the leg is green.

---

## 5. RETRACTIONS — things I asserted that were wrong

Four of mine. All were caught by a peer measuring, **none by me re-reading**.

1. **"The collision gate never self-clears after a squash merge."** FALSE. `overlap.ps1` intersects
   three-dot with two-dot; `git diff A..B` compares trees, so once content is in main the two-dot set
   empties and the intersection clears. `collision_gate.ps1:70` *delegates* to `overlap.ps1`, so it
   inherits this by construction. I read a three-dot diff and stopped.
2. **"#131's own run proves the raised cap applied."** It did apply — but the run does not show it.
   Its step ran 24:22, under both 26:00 and 36:00. Durations cannot discriminate. **The matrix the run
   echoes into its own log can** (`"job_timeout":40,"step_timeout":36`), and it was there the whole
   time. Read the configuration; don't infer it from behaviour consistent with several configurations.
3. **"#119 died in a race between the step cap and the job cap"** (`26:07 + 3:18 + 0:41 = 30:06`).
   FALSE — arithmetic over an impossible state. A step kill ends the job and skips what follows;
   the killed run shows `Web console tests: completed/SKIPPED` and a 27:15 job against a 30:00 cap.
   #119 was killed by the step cap alone and its attribution was correct.
4. **"The primary checkout is serving a stale collision gate."** FALSE — I hashed a **CRLF working
   file against an LF blob**. Normalised, they are identical. I was one command from `git pull`-ing a
   shared checkout used by every session, on the strength of this.

---

## 6. TRAPS — each is a fact plus its measurement

**T1. `step_timeout` gates TWO steps, and the job must cover their sum.**
`ci.yml` applies `timeout-minutes: ${{ matrix.step_timeout }}` to both `Tests (pytest)` and
`Web console tests (pytest)`. So a job can hold 2 × `step_timeout` of gated work that `step_timeout`
cannot bound. **This is not theoretical** — run `30724385719` (main @ `8f01cef8`):
```
Tests (pytest)              25:51  SUCCESS     <- 9s under the 26:00 cap
Web console tests (pytest)         CANCELLED
JOB                         30:13  CANCELLED   <- job_timeout 30 fired
```
A **green** first step, then an unattributed job kill during the second. It cannot happen when a step
is *killed*; only when the first step **passes** near its budget. The real fix is to stop the two
steps sharing a budget — a 3:27 suite has no business holding 36:00 (BACKLOG #344).

**T2. Filtering a pool by JOB conclusion while measuring STEP durations removes the tightest cases by
construction.** A step near `step_timeout` is exactly the one that pushes its job into `job_timeout`,
so the job is cancelled while the step concluded success. **Five such rows existed on 2026-08-01 and
they include the maximum.** This is what produced #131's wrong table. Measure the step; filter on the
step.

**T3. A default `gh run list` page is 20 rows.** #131's "11 passing runs" was a tool-truncated sample
reported as though it had been chosen — 20 of 101. Enumerate with `gh api --paginate`.

**T4. Job durations are NOT step durations.** The job runs several minutes longer (setup **plus the
second pytest step**) and is capped separately. `c53f752b`'s JOB ran 28:41 and PASSED against job cap
30 / step cap 26. **Four sessions made this error tonight**, one of them immediately after writing the
correction about it. Rule: quote step figures from the step's own `started_at`/`completed_at` — never
by subtracting setup from a job total, never from elapsed wall-clock mid-run.

**T5. To compare a working file against a git object, hash it WITH git.**
`git hash-object <file>` and `git rev-parse <ref>:<path>` agree; `sha256sum` does not, because
`core.autocrlf` means the working file is CRLF and the blob is LF. Retraction 4 above.

**T6. Sizing a cap by ratio-against-one-run is the wrong criterion.** windows-2025's step spread on
identical code is **5:26** (20:41 … 26:07 across seven observations). The rule that matters is
**headroom > observed spread**, not a multiple of a point estimate. Against 26:00 the headroom over
the true max was *negative*; #119's death was arithmetic, not luck.

**T7. `check_stalled_prs.py` uses `gh pr list --limit 100`.** Past 100 open PRs the remainder is
invisible and the receipt prints `scanned 100` — true, and reading as complete. Not biting at ~15 open
PRs; unguarded regardless. My own instance of *a rule quantified over what is present cannot notice
what is missing*.

---

## 7. Adjacent, not mine

- **BACKLOG #340** (merge queue) — the ADR-0154 session is adding measured evidence after #137 lands:
  #132 took **four full CI cycles to land, none from a failure** (~80 min runner time for a change
  correct on the first pass). Their caveat belongs with it: tonight's queue *did* resolve without a
  queue, via hand coordination, so a queue is a **convenience, not a correctness fix**.
- **BACKLOG #344** still restates #138's superseded figures (`24:35`, `1.06x`, `11 runs`, `1.45x`).
  **That edit is not done** — it was blocked on live sessions holding `docs/BACKLOG.md`. Do it.
- **ADR 0158** ("Silent controls") is the announce session's, drafted not committed. ADR **0157** is
  the HA session's *demotion safety* — I mis-routed taxonomy material to 0157 for hours; it is 0158.
- **The collision-gate fix (#133) needs the PRIMARY checkout advanced before it is in force.**
  Check with `grep -c MatchedDirty <primary>/scripts/hooks/collision_gate.ps1` — non-zero means live.
  Merged ≠ deployed, and nothing reports the gap.
