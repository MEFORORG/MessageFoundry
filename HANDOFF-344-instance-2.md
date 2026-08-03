# HANDOFF — BACKLOG #344 instance 2 (paused 2026-08-02)

> **This work is UNPUSHED. There is no PR and no remote branch.** A resumer checking GitHub will
> find nothing and may conclude #344 instance 2 was never fixed. It was. It lives in exactly one
> place:
>
> **HEAD `66443098`, 4 commits ahead of `origin/main`, working tree clean.** You are reading this
> from the branch itself; `git branch --show-current` names it. The branch name is deliberately
> not written here — the leak guard matches worktree/branch slugs by shape, because a slug is
> whatever the task was called and this repo is public. It is recorded, with the worktree path,
> in `.git/mefor-coord/HANDOFF-344-instance-2.md` (never published).
>
> `git rev-parse --verify origin/<this-branch>` → *"Needed a single revision"*. That is not an
> error; it is the confirmation that nothing was pushed.

Paused on the owner's instruction, relayed by the coordinator session. Nothing is half-done: the
four commits are coherent and independently verified. **Push / PR / merge were never taken — they
route to the owner, and pausing is not a reason to push.**

---

## 1. What was wrong, and what the mechanism actually is

`tests/test_stage_dispatcher.py`'s ADR 0070 tests failed intermittently on the **SQL Server leg
only** — a bare `assert await _wait_until(...)` → `assert False` with *zero* logic assertions
failing. Two occurrences in 21 days, ~0.4%/test over ~479 observations.

**It was never the 8.0s bound.** Do not raise it. The test passes in max 0.204s on green SQL Server
jobs and 0.576s at worst across 241 runs — the bound is 14–39× the worst passing run, and both
failures sit ~7× beyond the *entire* passing distribution. A gap, not a tail. Past ~31s a raise
would convert a real 30-second store hang into a silent PASS.

The actual chain — **proven by forcing it on a live SQL Server, not inferred**:

1. `claim_fifo_heads` ([`store/sqlserver.py`](messagefoundry/store/sqlserver.py)) runs under
   `SET LOCK_TIMEOUT 0`, so a momentarily contended head raises **native error 1222** instantly.
2. The store **catches 1222 and returns a normal EMPTY result** (the `_is_lock_timeout` branch).
   This is deliberate — the ADR 0114 "never-block" yield — and is logged **only at DEBUG**, which
   is why nothing ever reported it.
3. The dispatcher's EMPTY branch takes **T12**: `phase = IDLE`, **no timer armed**.
4. In production the periodic sweep re-readies such a lane. The ADR 0070 tests set
   `sweep_interval=_HUGE_SWEEP` (3600) with an **empty `lane_provider`** *on purpose*, so IDLE is
   **terminal** there and the lane can never be re-claimed. The poll then cannot succeed at any
   budget.

**This is a test-rig gap, not an engine defect.** Production's backstop is intact. Do **not** "fix"
T12 by arming a timer on every EMPTY — that re-introduces the exact spin ADR 0070's fix-A backoff
exists to collapse.

### The reproduction recipe (the expensive part — the scratch harnesses were deleted)

Deterministic, ~4s, on a live SQL Server. Drive ADR 0070 test 1 to its first PARKED, then from a
**second pooled connection** take a conflicting lock on the head row and hold it across the
post-unpark re-claim:

```
cur = await blocker.cursor()
await cur.execute("UPDATE queue SET last_error = last_error WHERE stage=? AND channel_id=?",
                  (Stage.INGRESS.value, lane))     # NOT committed -> holds an X lock
pu = d.park_until(lane); mc.advance((pu - mc.now) + 0.5); await _settle()
```

Observed, and this is the signature to match:

```
[1] after fault 1:  phase=PARKED  park_until=1001.0  empty_claims=(0, 0, 0)
[2] after unpark into a LOCKED head:
        phase=IDLE  park_until=None  armed_timers={}  empty_claims=(1, 0, 1)
[3] after releasing the lock: recovered=False phase=IDLE      <- TERMINAL, not merely slow
[4] after mark_ready(lane, woken=False): PARKED, streak=2      <- the fix works
```

Step [3] is the clause that proves *terminal* rather than *slow*; no timeout reasoning reaches it.

**A second, quieter route exists** and produces the identical observable: the batch claim's lock
probe runs `WITH (UPDLOCK, ROWLOCK, READPAST)`, so a contended head is *skipped* and the head-pin
step drops the whole lane — with **no log line at all**. Both routes read `(1,0,1)`, so the counters
cannot separate them. That is a limit of the instrument, not doubt about the mechanism.

**Postgres is NOT immune.** It uses `FOR UPDATE SKIP LOCKED` — the same head-of-line skip. Its 119
observations at ~0.4% expect ~0.5 events and exonerate nothing. Only **SQLite's** 0/1,105 is
structural. Read the symptom as *server-backed store*, not "SQL Server only".

### A THIRD source of the 1222 — and it refines the wording above (BACKLOG #348 / ADR 0159)

Added 2026-08-02 from the #348 session, which reached the same 1222 from the opposite end. **Their
measurement, my verification of the mechanism in our source:**

`CancelledError` derives from `BaseException`, so the store's `except Exception: await
conn.rollback()` idiom **never runs its rollback on a cancellation** — and `aioodbc`'s
`Pool.release()` returns the connection to the free deque with no rollback or reset. Verified here:
`store/sqlserver.py` has **90** rollback sites guarded by `except Exception` and **zero** using
`except BaseException` or a `finally`. They measured the consequence on a live container —
cancelling `release_claimed` left 7 KEY X locks on `queue` (`reschedule_claimed` 7, `mark_done` 9,
`enqueue_ingress` 11), against 0 for a `claim_fifo_heads` control — after which a real
`claim_fifo_heads` returned EMPTY-all and a raw writer got 1222.

**Why this matters to the text above:** §1 and the commit message for the fix reason from
*momentary* contention — a live producer holding a head lock in flight. A connection poisoned this
way holds its locks **for as long as it sits unclaimed in the pool's free deque**, so the 1222 can
repeat across successive sweep ticks instead of clearing on the next one. The chain into T12 and the
terminal IDLE is identical; only the *duration and origin* of the contention differ.

**It does not change this branch's conclusion** — production still recovers via the sweep, so
"test-rig gap, not an engine defect" stands, and that session explicitly declined to escalate its
severity on the strength of this finding. But: **if you ever see a 1222 that cannot be attributed to
a live producer, look here first.** Cross-referenced by ledger number (#348 / ADR 0159), not by SHA,
because that work is also unpushed.

---

## 2. What was changed (4 commits)

> **If you cite one SHA, cite `58f8f134` — that is THE FIX.** `66443098` and the HEAD commit are a
> banner edit and this note; they touch **no code**. This was already mis-relayed once between
> sessions (HEAD was circulated as "the fix"), so name the commit, not the tip.

| SHA | What |
|---|---|
| `58f8f134` | **THE FIX** + ledger: `_wait_until` raises on expiry with a full diagnostic; `_wait_lane` sweep stand-in; #344 instance 2 → RESOLVED |
| `e42f0ae3` | Three corrections from adversarial review (see below) |
| `7e430e82` | Merge `origin/main` (`dc0da097`, #148's #345/#346) — verified by **content**, both directions |
| `66443098` | Banner rewritten to land with its body; no instance count |

**Two halves of the fix**, both in `tests/test_stage_dispatcher.py`:

1. **`_wait_until` now RAISES** `_WaitTimeout` on expiry (BACKLOG #344 proposal 6) carrying lane
   phase, park deadline, infra streak, lane-task liveness/exception, the store row's status and
   `next_attempt_at`, the clock, and `empty_claims` — plus a one-line **VERDICT** naming which
   hypothesis the reading proves. All ~60 bare-assert call sites convert for free; two that
   legitimately tolerate a timeout pass `required=False`; one that carried a message passes `note=`.
2. **`_wait_lane`** stands in for the disabled sweep: a lane found in terminal IDLE is re-readied
   via `mark_ready(lane, woken=False)`, **counted, capped at `_MAX_SWEEP_STANDINS = 1`, and
   `warnings.warn`-loud**. Past the cap it raises, calling it a contention regression. Disabled when
   IDLE is itself the target phase. Measured: 12 consecutive full-file SQL Server runs produced
   **zero** stand-ins, so the cap of 1 has margin.

The `e42f0ae3` corrections, all verified in source before being written: `empty_claims` alone is
**not** a complete discriminator (`== 0` covers ≥3 stuck states that only the *phase* separates, so
the verdict reads both); the READPAST second route; and Postgres not being structurally immune. It
also fixed a shadowing bug from the first commit — a `for lane in ...` loop rebinding the `lane`
**parameter**, which would have named a stale lane with two live dispatchers.

---

## 3. Verification already done — do not redo it blind

- `ruff format --check`, `ruff check`, **`mypy --strict`** — all clean on the changed file.
- `scripts/docs/backlog_status_check.py` — **green at 270 items**.
- Full `tests/test_stage_dispatcher.py`: **76 passed / 38 skipped** on a live SQL Server 2022
  container *and* on a live Postgres 16; **38 passed** sqlite-only (the default CI leg).
- **Falsification (the load-bearing check):** with `_MAX_SWEEP_STANDINS` forced to 0, the same
  injected EMPTY reproduces the original failure — now carrying the full diagnostic instead of a
  bare `assert False`. A guard that passes against unpatched code measures nothing.

### Rebuilding the DB rigs (mine were torn down)

Both containers were **removed** at the end of the session; the shared `mefor-mssql` / `mefor-pg-ci`
were left alone. To re-verify:

```
scripts\dev\sqlserver-docker.ps1 -ContainerName mefor-mssql-<lane> -Volume mefor-mssql-<lane>-data -Port <free>
docker run -d --name mefor-pg-<lane> -e POSTGRES_PASSWORD=mefor -e POSTGRES_DB=messagefoundry -p <free>:5432 postgres:16
```

- ⚠️ **A native `MSSQLSERVER` service owns `127.0.0.1:1434` on this box.** Docker had 1433; I used
  **14330** for mine. Always check the owner first, then sanity-check `SELECT @@VERSION` matches the
  image you started — a wrong-server connect reports a misleading login failure and nothing names it.
- ⚠️ **The two backends share ONE `MEFOR_STORE_*` config.** They cannot run in the same pytest
  invocation; run them as separate legs, as CI does. Clear `MEFOR_*` between legs.
- Local pytest **silently skips** both server legs without `MEFOR_TEST_SQLSERVER` /
  `MEFOR_TEST_POSTGRES` — a green local run proves nothing about them.
- ⚠️ **An isolated repro loop will not reproduce this.** 800 iterations of the two tests alone
  returned 800/800 green: running them in isolation is the one configuration that cannot generate
  lock contention. It *did* appear unforced in a **full-file** run. Force it (§1) rather than sample.

---

## 4. Open threads a resumer must not rediscover

**(a) One known conflict with PR #138** (OPEN, auto-merge ARMED, CI-BLOCKED at pause).
`git merge-tree --write-tree HEAD <pr-138-branch>` → **exactly one hunk, `docs/BACKLOG.md:~8328`,
the status banner only.**

**Agreement reached with that session** (peer-to-peer, before the coordinator's remit; the
coordinator has also recorded it — it otherwise lived only in two paused sessions' heads):

> **#138 lands first. Then merge and take *this branch's* banner, keeping #138's two corrected
> sentences in the `*Instance 2, RE-DIAGNOSED*` paragraph.**

Rationale: a banner is a claim about the body beneath it, so it must land in the same commit as the
body it describes. #138's banner is true of main-after-#138; mine is true of main-after-this-branch.
**This branch's banner deliberately carries no instance count**, so it stays true in either order —
the agreed order is *preferable, not load-bearing*. Do not panic about ordering, and do **not**
restore a tally: instance 3 and proposal 5 exist only on #138's branch, so naming them here would
describe a body that is not present if this branch lands first.

Use `git merge-tree --write-tree A B` to re-check — no worktree, no dirty state, no abort to recover
from. It caught this after both sessions had verified the region they were told about and both
concluded the merge was clean.

**(b) The ledger claim is HELD and must stay held.** Number **344**, scoped to the **fix in
`tests/` only** — #138 holds the `ci.yml`/ledger half. Both notes say so. Do not release it: the
work is real, unlanded and unpushed, and the claim is the only thing marking that territory.

**(c) Out of scope, already filed as a task chip:** a swallowed 1222 increments the same counter as
a genuinely idle poll, so an operator cannot distinguish contention from no-work. The yield itself
is by design (ADR 0114) and must **not** be changed — this is about making it countable.

---

## 5. Not done

- **Push, PR, merge** — the owner's call, deliberately not taken.
- The #138 banner reconcile (§4a), which cannot happen until #138 lands.
