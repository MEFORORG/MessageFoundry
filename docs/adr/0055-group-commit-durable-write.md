# 0055 — Group-commit for the staged queue — the durable-write ceiling-mover

> # ⛔ SUPERSEDED / WITHDRAWN (2026-07-12) — by [ADR 0099](0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md)
> **DO NOT BUILD THIS. The "build authorized now as a no-regret lever" line below is REVOKED.**
>
> This ADR was never withdrawn when it should have been. **[ADR 0069](0069-durable-write-throughput-lever.md)
> (2026-07-03) measured its central premise and refuted it** — *"durable-write is **not** the throughput wall"* — and
> the two ADRs then sat side by side, both `Proposed`, contradicting each other for nine days. Whoever read this one
> first would have built the wrong thing.
>
> **Two independent reasons it is dead:**
> 1. **The premise is measured false.** The store absorbs **~27–29k commits/s**; demand at the *full* 45M/day target
>    is **~2,416 commits/s** — the commit tier is **~9% utilised**. You cannot buy throughput by consuming less of a
>    resource you are barely touching.
> 2. **The mechanism breaks a hard invariant, on PHI.** `DELAYED_DURABILITY` returns from `COMMIT` *before* the log
>    block is flushed — so `enqueue_ingress` commits, the listener **ACKs**, the sender drops its copy, and a power
>    failure loses up to 60 KB of unflushed log. **An ACKed message that does not exist.** CLAUDE.md §2 is explicit:
>    the inbound is ACKed *"only after the raw message is durably committed to the ingress stage."*
>
> **Do not enable `DELAYED_DURABILITY` on the store, ever.** The surviving Phase-4 mechanism is
> [ADR 0057](0057-inline-step-a-fast-path.md) inline stage-fusion — a *different* mechanism — and it is itself gated
> behind a pre-registered measurement (ADR 0099 §Decision 4). This ADR is retained for the record only.

- **Status:** **Proposed** (2026-06-29) — design; the build is **authorized now as a no-regret lever** by
  [ADR 0051](0051-corepoint-throughput-parity-strategy.md)'s delayed-hardware adjustment, with its relative
  fsync/msg delta **proxy-measured on the 265KF** (consumer floor). The *absolute* throughput claim still
  waits on the enterprise / spec-matched-cloud measurement.
- **Date:** 2026-06-29
- **Related:** [0051](0051-corepoint-throughput-parity-strategy.md) (parity strategy — group-commit is its
  named #1 durable-write lever) · [0001](0001-staged-pipeline-architecture.md) (staged queue / ACK-on-receipt)
  · [0005](0005-transform-accessible-state.md) (the read-through state caches) · [0037](0037-multi-process-sharding-l3.md)
  (sharding — composes per shard) · [CLAUDE.md](../../CLAUDE.md) §2 (reliability + count-and-log invariants)
  · BACKLOG #64 · `docs/research/db-commit-wall-backend-survey.md` (gitignored)
- **Correction (2026-06-30):** the `commit_delay`/`commit_siblings` "native group-commit" referenced
  below is a **PostgreSQL-ONLY** GUC. **SQL Server has no durability-neutral group-commit knob** — its
  only commit-coalescing control is `DELAYED_DURABILITY`, which *relaxes* durability (it could ACK a
  crash-erasable message) and is therefore **rejected** for the PHI store. So the "server-DB native
  group-commit" path here is Postgres-only; SQL Server's scale path is the concurrent pool + sharding
  ([ADR 0037](0037-multi-process-sharding-l3.md)), not a native GUC. **As built (#660) the committer is
  SQLite-only**; Postgres `commit_delay` adoption remains a future **gated, off-by-default** increment,
  measurement-deferred until sharding supplies enough concurrent in-flight commits to coalesce.

---

## Context

By the incumbent's own account the **durable-write / DB tier is the throughput battleground** (ADR 0051:
Corepoint names *"the speed of the disk of the DB server's data drive"* the leading driver, qualified at
**9,200 8 KB-random-write IOPS**). MessageFoundry commits **~7 transactions/msg** through the staged queue
(`db-write-amplification-levers`), and **group-commit is the one unbuilt lever that moves the commit ceiling**
— every other lever cuts *bytes* (carriage/pruning), not *fsyncs*. So this is the highest-leverage
durable-write change.

Group-commit must preserve the standing invariants, quoted verbatim ([CLAUDE.md](../../CLAUDE.md) §2):

> **Reliability invariant:** … At-least-once now relies on a re-run re-deriving identical output, so
> **routers and transforms must be pure** … outbound connections must still be **idempotent**.

> **Count-and-log invariant:** **every received message is persisted before the ACK** … nothing is
> accepted-and-dropped.

**The mechanism is backend-dependent — and that distinction is the whole design** (always frame SQLite
alongside the server DBs):

- **SQLite (single writer).** One `aiosqlite` writer connection serialized by one `asyncio.Lock`
  (`store.py`). The DB never sees concurrent transactions, so a **native** group-commit GUC is N/A. The lever
  is an **app-side committer coroutine** that holds the txn open across N already-prepared mutations, then one
  durable sync.
- **PostgreSQL / SQL Server (concurrent pool).** These backends use a **connection pool + per-message locks**
  (`postgres.py` `pg_advisory_xact_lock`; `sqlserver.py` RCSI + `sp_getapplock`) — they *can* see concurrent
  transactions. So the **sharp catch** (deep-research 2026-06-28): the server's **native** group-commit
  (`commit_delay`/`commit_siblings`) only coalesces txns that are **concurrently in flight** — it buys ~0
  unless the **engine submits writes concurrently**. The single-writer-lock serialization inherited from
  SQLite would starve it. **So the first thing this ADR must resolve is a code fact: do the server backends
  serialize writes behind one lock, or run a concurrent write pool?** That decides app-side-committer
  vs. native-GUC-plus-concurrent-submission. (WS4 of ADR 0053 found the server backends use pools + per-msg
  locks, i.e. concurrent-capable — to be confirmed against the write path here.)

## Decision

**Add group-commit to the staged queue to cut fsyncs/msg while preserving at-least-once, the claim
poison-guard, and ACK-on-receipt — via a backend-appropriate mechanism.** Core design (verified, from the
`group-commit-design` workflow):

**App-side committer coroutine (the SQLite lever; the fallback for any single-writer server path).** A
dedicated committer per store coalesces N already-prepared mutations into **one** `commit()` under the writer
lock — the single writer holds the txn open across N members, then one durable sync. A **group rollback
rejects every member's future** → each caller re-runs; this is a *coordinated* version of the crash-re-run
the system already tolerates, **licensed by the existing idempotent INFLIGHT-guarded handoffs**.

- **GROUPED:** `enqueue_ingress`, `route_handoff`, `transform_handoff`, `mark_done`,
  `complete_with_response`, `dead_letter_now`, `mark_failed`.
- **STANDALONE — immediate commit, never grouped:**
  - **`claim_next_fifo` / `claim_ready`** (Hazard A) — the `attempts+1` **poison-guard** MUST stay
    durable-before-work; it may flush early but must **never share a rollback fate** with post-claim work,
    else an infinite crash-loop / FIFO head-of-line block.
  - `write_reference_snapshot`; `record_audit` (the hash-chain).
- **Hazard B (ACK timing):** the inbound ACK **waits on the ingress member's future** (resolved *after* the
  group commit) — never ACK data a crash could lose. Count-and-log invariant intact.
- **The cache-publish gotcha (the adversarial-pass catch):** the read-through caches
  (`_state_cache`/`_reference_cache`) are published **post-commit, outside the lock, from the mutator's own
  stack frame**. A committer coroutine **cannot** publish them. **Fix:** each member publishes its cache
  delta **only on its own future's success** (rollback → future rejected → frame unwinds → publish skipped),
  using the immutable-swap discipline. Plus a **bounded cross-lane stale-read window** for global ADR-0005
  state (lane A can't see lane B's writes until the batch commits) — **documented and bounded**, or excluded.
- **Mechanical:** `mark_done` runs on aiosqlite's *implicit* txn today → refactor to statements-only so the
  committer owns `BEGIN`.
- **Config:** `[store].group_commit_window_ms` + a flush-count threshold; the **win is large under
  `synchronous=FULL`** (fsync amortization) and **muted under the default NORMAL** (trims txn/WAL/lock
  overhead, not fsyncs).

**Server-DB path (PG / SQL Server), resolved by the code fact above:** *if* the write path runs a concurrent
pool, prefer **concurrent submission + the DB's native group-commit** (`commit_delay`) over the app-side
committer — the engine ensures enough in-flight commits for the server to coalesce. *If* it serializes behind
one lock, the app-side committer applies as for SQLite. Either way the invariant treatment (poison-guard
standalone, ACK-on-ingress-future, cache-publish-on-success) is identical.

## Acceptance Criteria

- **AC-1** — IF a group commit rolls back, THEN **every** member's future SHALL be rejected and each caller
  SHALL re-run (no member is silently dropped or partially applied). → `tests/test_group_commit.py::test_group_rollback_reruns_all`
- **AC-2** — THE SYSTEM SHALL never group `claim_next_fifo`/`claim_ready`: the `attempts+1` poison-guard
  commits **standalone, before** the claimed work, and never shares a rollback fate with it. →
  `tests/test_group_commit.py::test_claim_poisonguard_standalone`
- **AC-3** — WHEN ACK-on-receipt is in effect, THE SYSTEM SHALL release the inbound ACK only **after** the
  ingress member's group commit is durable (count-and-log intact). → `tests/test_group_commit.py::test_ack_waits_for_durable_ingress`
- **AC-4** — A member SHALL publish its `_state_cache`/`_reference_cache` delta **only on its own commit
  success**; a rolled-back member SHALL publish nothing. → `tests/test_group_commit.py::test_cache_publish_only_on_success`
- **AC-5** — WHILE group-commit is enabled, the staged-pipeline + cluster invariant suites (per-channel FIFO,
  at-least-once, single-finalizer) SHALL pass unchanged. → `tests/test_staged_pipeline.py` + `tests/test_invariants*`
- **AC-6 (measurement)** — group-commit SHALL show a **measured fsync/msg (and commit-latency) reduction**
  on the proxy harness under `synchronous=FULL`, on **storage configured for representative fsync** (native
  DB, or a Docker **named volume on the NVMe** with `fio --fsync=1` latency verified ≈ native `diskspd` — per
  ADR 0051's methodology; a Windows bind-mount is invalid). → `harness/load/` + `docs/benchmarks/group-commit.md`

## Options considered

1. **App-side committer coroutine (SQLite + any single-writer path) + concurrent-submission/native-GUC for a
   concurrent server pool — this.** **CHOSEN.** Fits the actual write model per backend; preserves the
   single-writer model and the invariants; the rollback-reject-rerun reuses the crash-re-run the system
   already tolerates.
2. **Native server GUC only (`commit_delay`).** Rejected as the *general* answer — it coalesces only
   concurrently-in-flight txns; under single-writer-lock serialization it buys ~0 and the ~1.74× pgbench
   figure (10 concurrent clients) won't transfer. Viable **only** on the concurrent-pool path, and even then
   needs concurrent submission.
3. **Do nothing.** Rejected — group-commit is the named #1 durable-write lever; every other lever cuts bytes,
   not fsyncs.

## Consequences

**Positive** — cuts fsyncs/msg (the commit ceiling-mover) while preserving every invariant; reuses the
existing idempotent-re-run licence; config-gated (`group_commit_window_ms`), off = today's behaviour; composes
per shard (ADR 0037).

**Negative / risks** — it touches the **most invariant-dense code** (the staged-handoff transactions + the
finalizer); it revisits the read-through-cache publish + cross-lane state visibility (the documented gotchas);
the win is **`synchronous=FULL`-dependent** (muted under NORMAL); and the **server-DB applicability** hinges
on the single-lock-vs-pool fact that must be resolved first. The absolute throughput number stays unproven
until the enterprise / cloud measurement.

**Out of scope** — the absolute enterprise-ceiling run (ADR 0051 / #40); the lean-writes/carriage levers
(#62/#63/#47); multi-DB split.

## To resolve on acceptance

- [ ] **The code fact:** does `store/postgres.py` + `store/sqlserver.py` serialize writes behind one lock or
  run a concurrent write pool? (Decides app-side-committer vs. native-GUC + concurrent-submission for the
  server backends.)
- [ ] The proxy-measurement on the 265KF (fsyncs/sec + commit latency on one shard at volume) under
  `synchronous=FULL`, with the **storage methodology verified** (native or named-volume + `fio` check).
- [ ] The bounded cross-lane stale-read window for ADR-0005 global state — documented or excluded.
- [ ] Config defaults: `group_commit_window_ms` + flush threshold; ship **off** by default (opt-in) until the
  absolute measurement.
