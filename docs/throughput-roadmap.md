<!--
Throughput roadmap + multisession build plan toward 45M msg/day (521 msg/s).
Consolidated 2026-06-30 after the diagnosis SETTLED: three independent methods (code-hunt, wait-stats,
in-flight instrumentation) agree the wall is the per-lane 7-deep serial commit round-trip chain.
Planning/decision record, not a benchmark report.
-->

# Throughput Roadmap & Multisession Build Plan (toward 45M msg/day)

**Status:** planning/decision record · **Date:** 2026-06-30 · diagnosis **settled** · **plan REVISED
2026-06-30 (connection-scale)** · **B8 RAN 2026-06-30 — single-store ceiling ≈23,600 commits/s, the store
is NOT the wall; see the B8 result below.**

---

## 2026-06-30 — B8 RESULT: the store is NOT the wall (supersedes the SAN-bound plateau/cap + "connections-per-store" framing)

**B8 ran** on AWS **i4i.2xlarge local Nitro SSD** — a stand-in for on-prem local NVMe; the whole point was
to escape the Azure SAN proxy. Flush validated **real** (avg durable commit **170 µs**, WRITELOG 141 µs —
not a faked sub-30 µs ack). **Single-store commit ceiling ≈ 23,600 commits/s** (localhost, synthetic
autocommit loader, 8-vCPU box; peak at 16 threads, single-thread 3,855).

**This resolves the first of the REVISION's two unmeasured numbers and reframes the plan:**
- **≈6.5× the ~3,647 commits/s target** (521 msg/s × 7 commits/msg for 45M/day) — **one unified store
  carries the whole aggregate with headroom, at *7* commits/msg**, before B1–B3's cut even counts. The
  "B8 must count the post-cut commits to know if one store holds it" question below is moot: it holds it
  comfortably either way.
- **≈83× the Azure SAN ~284 cap.** The **~284 cap and the "lanes plateau ~100–140 on a single store"
  finding in the diagnosis below were a SAN / network-storage artifact, not a store limit.** Delete
  "need 2–3 stores / a partitioned queue for write capacity" from the plan — **1 unified store, decided.**
  Store-partitioning (ADR 0039) stays shelved now for **write capacity too**, not only search/reporting;
  channel-sharding drops to a **read-side / monitoring** concern.
- **The connection-scale / lane levers are UNBLOCKED with real store headroom.** Lane parallelism
  (B5 executor split, pool sizing, any within-store lane multiplication) won't hit a store wall on local
  NVMe — the store absorbs ~23.6k commits/s. **Expect the ~100 plateau to LIFT far past it against a
  single store**; the ceiling moves to the **engine's serial-per-inbound commit chain + CPU**, exactly
  where the diagnosis put it. **Commit-depth collapse (B1–B3, DONE) stays the primary lever**; lane
  parallelism now has real store headroom behind it.

**Still pending (the second unmeasured number):** B8 was localhost + a synthetic autocommit loader (NOT
the full 7-commit pipeline) on a small 8-vCPU box (real ceiling likely higher). The **prod-faithful
per-interface number** — the real engine driving the 7-commit pipeline over the LAN — is the **"04" run,
gated on cutting the build (v0.2.12/.13) + the B11 harness**. When the build is cut, redeploy the proven
~15-min AWS rig for the engine-box run. Result + kit: `mf-b8-nvme-bench-rig` memory + `OneDrive\Desktop\
MEFOR\aws-bench`.

> B8 SUPERSEDES, in the diagnosis + lever table below: the "~100–140 plateau on a single store", the
> "~284 SAN cap" **as a store limit**, and the "connections-per-store ~1.75× / 1 vs 2–3 stores" framing.
> The 7-deep commit-chain diagnosis and B1–B3's primacy are UNCHANGED (they are engine-side). Read
> [`throughput-build-plan.md`](throughput-build-plan.md) for the re-sequenced next step.

---

## 2026-06-30 REVISION — connection-scale target (supersedes "multiply lanes" / order-group sharding)

**Two owner decisions reframe the whole plan, and they simplify it.** (1) A feed = a channel = ONE
strictly-ordered serial lane, **never split** by any key — so **order-group sharding (B4) is DELETED**.
(2) **Federation is the customer's responsibility**: a mega chain MUST break a hot source (e.g. ADT) into
multiple inbound interfaces by hospital/region, so no single inbound ever carries a consolidated firehose.

**The real target is the Corepoint spec: 1,500 connections** at ~45M msg/day aggregate = **~0.35 msg/s
average per connection** (521 msg/s aggregate). The hottest real feed measured (a mid-size hospital's ADT feed) is
1.76 msg/s; a serial lane does 42–200 msg/s. **Per-lane speed has ~100× headroom and is never the
binding constraint.** The diagnosis below (the 7-deep commit chain) still holds — but it is now an
**aggregate-commit** lever, not a lane-speed one: cutting ~7→~4–5 commits/msg (B1–B3, **DONE + verified
on SQL Server + Postgres**) raises **connections-per-store ~1.75×** (a SAN-class single store ≈ holds the
whole 521 msg/s target — *if* the post-cut count is ~4; ~397 msg/s if it's ~5, so B8 must count it).

**So the problem is CONNECTION-SCALE + AGGREGATE-COMMIT, not lane speed.** The work is: running ~1,500
mostly-idle lanes efficiently · total commits/s on one shared store · node/store distribution.

**Verdict: PLAUSIBLE, not yet proven.** On paper: **1 engine node (8–16 cores) + 1 unified server DB**
(Postgres/SQL Server — **SQLite non-viable at this tier**, ~680 single-writer handoffs/s) on enterprise
storage, + 1 active-passive standby. Store-partitioning (ADR 0039) stays **shelved** — funding-tier
customers reject the fragmented search/reporting/audit it causes. But the verdict rests on **two
unmeasured numbers** — the on-prem NVMe concurrent-commit ceiling (decides 1 vs 2–3 stores) and the
1,500-connection resource footprint (**no harness exists**) — and **three defaults sized for tens of
connections, not 1,500**: the off-loop executor (~12–32 threads; there is **no** `set_default_executor`
in the codebase), `pool_size=5` for the whole engine, and the 0.25 s idle-poll backstop.

**The #1 connection-scale problem (sized by the review):** the per-stage wake events are **engine-wide
singletons** — one message `set()`s the routed-work event and wakes **all ~1,500** router workers
(thundering herd), each doing an empty `claim_next_fifo`. Removing the 0.25 s timer only converts a
time-driven empty-claim storm into an event-driven one; the real fix is **per-lane wake events** — and
that storm hits the **same** shared-store ceiling that is the aggregate wall, so idle-economy and
store-commit are one contention point at scale. This makes B12 a structural change, not a timer tweak.

**Revised lever set** (full table + sequence: [`throughput-build-plan.md`](throughput-build-plan.md)):
**DELETED** B4 (order-group sharding). **NEW** B11 connection-scale harness (the prerequisite — does not
exist today), B12 per-lane idle-economy (per-lane wake events), B13 `pool_size` right-sizing, B14
accept-cap default. **REFRAMED** B5 (sized + **split** off-loop executor) + B6 (shared ingest sub-pool,
not per-listener) toward 1,500 lanes; B8 = the gating NVMe-ceiling + connections-per-node curve. B10 =
the B3 index migration so the cut lands on **upgraded** DBs. **B11 + B8 are hard prerequisites — nothing
downstream is provable until they run.** Reliability at 1,500 lanes additionally needs: failover
cold-start stampede control (~3,000 workers re-armed at once), finalizer contention sizing on one store,
O(connections) monitoring cardinality caps, and ~0.5–1.3 TB/day store growth (per-connection retention +
lean-write become **mandatory**). Doc fix: reconcile `SYSTEM-REQUIREMENTS.md` (it wrongly says
multi-process sharding is "not built" — ADR 0037 shipped it).

> Everything below this line is the **original diagnosis + the now-superseded "cut the chain, then
> multiply lanes" plan**. The **diagnosis (the 7-deep commit chain) is still valid and is why B1–B3
> matter**; the **"multiply lanes" strategy and TIER 2 order-group sharding (B4) are superseded** by this
> revision. Read the diagnosis for *why*; read `throughput-build-plan.md` for *what's next*.

## Provenance & how to read this

- The bottleneck is **settled by three independent, converging methods**: a 10-agent code-hunt of the
  per-message path, the SQL Server `sys.dm_os_wait_stats` diagnostic, and an in-flight-concurrency
  instrumented bench run. All three land on the same wall.
- **CPU is not the wall — measured, not assumed.** A direct profile of the hot path (peek + `route_only`
  + `transform_one` + AES-GCM) on the real generated corpus (434–909 B, median ~748 B) gives ~0.27 ms/msg
  on real Azure silicon (~0.68 ms dev box); the engine box sat **96 % idle** at the throughput ceiling.
- The source bench artifacts (`RESULTS-*.md`, `ANALYSIS-*.md`, `*-RESULTS-*.md`,
  `HANDOFF-azure-bench-FINAL`) are **operator-local** (bench-only credentials) and **not** in the repo.
- **S0 (doc corrections)** — step-b "3"→~7 commits/msg + the `settings.py`/ADR 0055 `commit_delay`
  Postgres-only scoping — **already landed in this PR (#665, commit 1).**

---

## The settled diagnosis — what the wall is, and what it is not

**The wall is the per-lane single-worker 7-deep serial commit round-trip chain.** Each inbound is three
serial stage-workers (`_router_worker` → `_transform_worker` → `_delivery_worker`), and a single message
walks **~7 sequential committed remote round-trips**, each gated on the prior stage's commit becoming
visible: `enqueue_ingress` → claim+`route_handoff` → claim+`transform_handoff` → claim+`mark_done`. The
claims cannot fuse with their handoffs because the pure `route_only`/`transform_one` run **off the loop**
(`asyncio.to_thread`) between them.

**The numbers:** single-lane **~50 msg/s = ~20 ms/msg = ~7 × ~2.84 ms/round-trip**. Lane sharding helps
but is **sub-linear** (1→4 lanes = ~2×, plateaus ~100–140 on a single store). The box is **96 % idle** at
the plateau — it is *waiting* on serial round-trips, not computing.

**How we know (three methods):**
- **Code-hunt** eliminated every engine-internal serializer with `file:line` grounding — pool-acquire
  lock, the shared executor/GIL (pyodbc releases the GIL for the ~2 ms SQL wait; on-loop CPU is ~130 µs/msg
  ⇒ a ~7,700 msg/s ceiling, 77× the plateau), the finalizer (`sp_getapplock` keyed per-message), the
  `claim_next_fifo` locks (lane-scoped), `_audit_lock`/state caches.
- **Wait-stats** ruled out the DB: `ix_queue_ready` page-latch 3 ms (negligible); `WRITELOG` dominated raw
  ms but forcing `DELAYED_DURABILITY = FORCED` did **not** lift the plateau; disk far below its ceiling.
- **In-flight instrumentation** ruled out the pool (the runs used `pool_size=40`; `pool_busy` ~12/24 ≪ 40)
  and proved the chain: at 4 lanes, raising the executor 12→64 changed throughput by **~0**.

**Ruled out — do not re-chase:** disk · `ix_queue_ready` page-latch · the log · the connection pool ·
CPU/GIL. **One measured secondary:** the default 12-thread `ThreadPoolExecutor` throttles *above* 4 lanes
(24 workers > 12 threads → 64 threads lifts the 8-lane knee ~100→~140) — a thread-count tax, not the
primary wall.

**Fixed constraints carried into the build:**
- **~7 durable commits/message** at fan-out 1 (the figure for commit-tier modeling).
- **CPU is not the wall** (~0.27–0.68 ms/msg; ~3.6 ms even at an 11.5 KB body) — so cores are not the gate.
- **Store choice is settled — do not reopen it.** SQL-vs-SQLite collapses to **~parity at the shipped
  NORMAL default** (the old "3–4×" was a `synchronous=FULL` artifact); SQL Server's real edge is the
  concurrency/HA a single-lane bench doesn't exercise. **SQLite is structurally unshardable** (one
  process-wide `asyncio.Lock`, `store.py:799`).
- **Azure SAN-proxy caps ~284 msg/s** even perfectly parallel at 7 commits/msg — **on-prem PLP NVMe is
  mandatory for any absolute prod-sizing number.** (Cutting commits/msg raises this cap proportionally.)

---

## PART 1 — What to build + the improvement model

### Strategy: cut the chain first, then multiply lanes

The per-lane wall is the **depth** of the serial round-trip chain, so the highest-leverage move is to
**reduce round-trips per message** — that raises single-lane throughput *and* every sharded lane. Lane
sharding only *multiplies* the per-lane rate, sub-linearly; it is worth far more once each lane is cheaper.

### Ranked levers (settled)

| # | Lever | Effect | Verdict | Top guardrail |
|---|---|---|---|---|
| **1** | **Collapse the commit depth** — extend the existing combined `handoff` (ingress→outbound in one txn, `sqlserver.py:1259`, no-transform path) to fuse the producer handoffs where no off-loop work intervenes, and cut the standalone `claim_next_fifo` round-trips | **PRIMARY.** Cuts ~7 → ~3–5 RTs/msg ⇒ raises single-lane (~50 → ~70–115) *and* every lane | **build first** | Reliability-core: each fused step stays a single committed txn; preserve at-least-once, ACK-on-receipt (ingress durable before ACK), the `attempts+1` poison-guard, per-lane FIFO, finalizer sole authority. ADR + adversarial-invariant tests. |
| **2** | **Batch-claim TOP(N)** on the FIFO claim path (3 of the 7 commits are claims) | Amortizes the claim RTs across N rows; **pairs with #1** | **build-with-guardrail** | INGRESS + ROUTED lanes ONLY (outbound skip-and-complete stays atomic); backing-off head BLOCKS the batch; limit=1 byte-identity parity. |
| **3** | **Drop the per-insert `SELECT MAX(created_at)` FIFO-clamp round-trip** (seq-only ordering) | An extra server RT per produced row — its removal is a *direct* chain-depth cut | **build-with-guardrail** | ORDER-BY-key change (`seq`), **not** a deletion, behind `[store].fifo_clamp`; clock-skew FIFO test; own the un-clamped-`created_at` metric (queue_buildup detector). |
| **4** | **Inbound order-group lane sharding** (K router/transform pairs per inbound; deterministic `shard_key`) | **SECONDARY** — real but sub-linear (~2× plateau); only worthwhile *after* the chain is cut | **build-with-guardrail** | Per-order-group FIFO; same-key→same-shard; finalizer-under-K; **reject shards>1 on SQLite**; size pool **and** executor with K. |
| **5** | **Executor sizing / split** (give aioodbc its own pool, or raise the default) | Small secondary **above 4 lanes** (measured ~100→140); SQL-Server-only (asyncpg has no executor) | **build-with-guardrail** | Preserve the EF-6 no-MARS single-active-statement + cursor-close-before-release. |
| **6** | **Dedicated ingest lane** (reserved server conn / SQLite priority-gate) | Robustness/no-drop, not throughput — eliminates silent intake socket-shed | **build-with-guardrail** | SQLite = bounded-fair priority-gate on `:799`, never a 2nd writer; `[inbound].max_ingress_depth` TCP-backpressure. |
| **7** | **SQLite `synchronous=NORMAL` baseline** (measurement + `db_status()` observability) | Sizes the honest shipped-default SQLite number; not a throughput win | **build-with-guardrail** | Report a band; surface `synchronous`; document the durability relaxation. |
| — | **PG `commit_delay`** | ~1.00× at sustained sharded rates (commits rarely bunch) | **defer (gated, off, last)** | PG-only GUC; re-test only if batch-claim re-bunches commits. |
| — | `DELAYED_DURABILITY` · extend the SQLite committer to servers · READPAST in the FIFO claim · `shard_key`-as-index-lead · pool tuning | — | **REJECT / N/A** | durability / by-design / per-lane FIFO (#285) / page-latch refuted / pool ran 40. |

### Improvement model (honest)

- **Single-lane is the lever.** Today ~50 msg/s = 7 RTs. Collapsing to ~4 RTs and batch-claiming the
  claims lifts single-lane toward ~85–115 msg/s — and *every* sharded lane with it.
- **Aggregate = single-lane × the (sub-linear) lane multiplier**, then bounded by the executor (size it)
  and ultimately the store's concurrent-commit ceiling.
- **Ceilings:** Azure SAN caps ~284 msg/s at 7 commits/msg (proportionally higher with fewer commits);
  **on-prem PLP NVMe is the only path to an absolute 521 number**; SQLite never reaches it (structural lock).
- The store decision stands (parity at the default ⇒ SQL Server for its concurrency/HA, not single-instance throughput).

### Reliability constraints (apply to every reliability-core lever)

At-least-once (each stage handoff a single committed txn; a crash re-runs idempotently); ACK-on-receipt
(the ingress commit lands before the AA); pure routers/transforms (re-run re-derives identical output);
finalizer = sole disposition authority; strict per-lane / per-order-group FIFO. **Collapse-commit-depth is
the sharpest:** fusing stages moves crash-recovery boundaries, so the ADR must prove no fused path can
drop the poison-guard, double-deliver on re-run, or ACK a message a crash could erase.

---

## PART 2 — Multisession Build Plan

**House rules (every session):** branch + PR (no direct `main`); gate on **CI, not reviewers** (solo dev,
admin bypass); **OMIT the `Co-Authored-By` trailer** (CLA bot); never commit creds/PHI/customer data — scan
the staged diff; reliability-core changes need an **ADR + adversarial-invariant tests**; vet+lock any new
dep; run the **FULL** pytest suite (leak-gate 3-place-token lesson), `QT_QPA_PLATFORM=offscreen` for console
legs. Worktree per session: `scripts/worktree/new.ps1 -Name <X> -NoInstall`. Bench creds/IPs are
operator-local (gitignored) — never committed/mirrored.

**Per-session gate (baseline):** `ruff check .` + `ruff format --check .` + `mypy messagefoundry` (strict)
+ `pytest` (full, offscreen Qt) — plus the specific new invariant test named, plus any measurement gate.

### Sequence (re-ranked around the settled diagnosis)

```
S0  docs corrections ............................. DONE (PR #665)
        │
   TIER 1 — cut the chain (the primary throughput fix; reliability-core; serialize on store files)
   B1  collapse the commit depth  ──►  B2  batch-claim TOP(N)  ──►  B3  drop the SELECT MAX clamp RT
        │
   TIER 2 — multiply + protect (after the chain is cheaper)
   B4  order-group lane sharding (secondary)  ─┬─►  B5  executor sizing/split (SQL Server, >4 lanes)
                                               └─►  B6  dedicated ingest lane (robustness)
        │
   TIER 3 — measure + baselines (independent / deferred)
   B7  SQLite NORMAL baseline    B8  measurement (post-fix re-measure + on-prem NVMe + prod corpus)    B9  PG commit_delay (deferred, last)
```

### TIER 1 — cut the chain

**B1 — Collapse the commit depth (PRIMARY; ADR required; effort L; reliability-core)**
- **OWNS:** `store/sqlserver.py` (extend the combined `handoff` at `:1259` beyond the no-transform path;
  the producer-handoff fusion + claim-RT reduction), `store/postgres.py` (mirror), `store/base.py` (any
  new combined primitive on the Store protocol), `pipeline/wiring_runner.py` (drive the fused path where a
  message has no slow off-loop work), `config/settings.py` (a gate flag, default OFF until proven),
  **new `docs/adr/00NN-collapse-commit-depth.md`**.
- **Gate:** (1) **at-least-once under a crash at every fused boundary** (kill between sub-steps; re-run
  produces identical output, no dup outbound row, no lost message); (2) **ACK-on-receipt preserved** (the
  ingress durability point is unchanged — never ACK a fused-but-uncommitted message); (3) poison-guard
  still durable-before-work; (4) **byte-identity at flag-OFF** (the fused path is opt-in, default path
  unchanged); (5) per-lane FIFO + finalizer-sole-authority under the fused path. SQL Server + Postgres CI
  legs PR-blocking.
- **Guardrail:** default OFF; the fusion is bounded to paths with **no intervening off-loop work** (the
  pure route/transform can't be inside an open txn holding a row lock across `to_thread`); measure
  RTs/msg before/after.
- **PR boundary:** one "feat: collapse commit depth (combined handoff extension, default off)".
- **Parallelism:** **leads the store-file chain.** SERIALIZE B1 → B2 → B3 → B4 on `store/*.py` + `wiring_runner.py`.

**B2 — Batch-claim TOP(N) (ADR required; effort M)**
- **OWNS:** `store/base.py` (new `claim_next_fifo_batch` — do not change `claim_next_fifo`),
  `store/store.py`+`store/sqlserver.py`+`store/postgres.py` (impls), `pipeline/wiring_runner.py` (drain a
  batch in lane order), `config/settings.py` (`[store].fifo_claim_batch=1` default-OFF + max-age),
  **new `docs/adr/0057-batch-claim-fifo.md`**.
- **Gate:** (1) FIFO-under-batch (interleaved lane, batch=8, strict seq order, a backing-off head BLOCKS
  the batch — contiguous-due-prefix); (2) crash-mid-batch replay (`reset_stale_inflight` re-pends the rest,
  idempotent, no dup outbound); (3) limit=1 byte-identity parity; (4) SQL Server no-READPAST regression (#285).
- **Guardrail:** INGRESS + ROUTED lanes ONLY — do NOT batch the outbound/delivery lane. Bound N small
  (4–16) + time-bound; watch RCSI version-store in soak.
- **Parallelism:** SERIALIZE after B1 (`wiring_runner.py` + store files).

**B3 — Seq-only FIFO ordering: drop the `SELECT MAX(created_at)` clamp RT (ADR required; effort M; reliability-core)**
- **OWNS:** `store/sqlserver.py` (`_fifo_created_at` + call sites; claim ORDER BY), `store/postgres.py`
  (clamp + call sites), `config/settings.py` (`[store].fifo_clamp`), **new `docs/adr/00NN-fifo-claim-ordering-by-seq.md`**.
- **Gate:** (A) clock-skew FIFO test (a later insert with a *smaller* raw `created_at` still claims in
  insertion order) — all backends; (B) multi-lane interleave; (C) crash-replay seq-determinism. SQL Server
  + Postgres CI legs PR-blocking.
- **Guardrail:** ORDER-BY-key change (not deletion), behind `[store].fifo_clamp = "seq"|"created_at"`
  (default `"seq"`). Own the un-clamped-`created_at` metric (the `pending_depth`/queue_buildup detector).
- **Parallelism:** SERIALIZE after B2 on the store files. (Removes one of the per-message RTs — a direct
  chain-depth cut, hence Tier 1.)

### TIER 2 — multiply + protect

**B4 — Inbound order-group lane sharding (SECONDARY; ADR required; effort L)**
- **OWNS:** `pipeline/wiring_runner.py` (`_router_workers`/`_transform_workers` → `dict[str, list[Task]]`;
  shard-index spawn/ensure/on-done; listener `shard_key` compute), `config/wiring.py`
  (`InboundConnection.partition_key` + `shards`), `config/settings.py` (`[inbound].default_shards`),
  `parsing/peek.py` (default HL7 PID-3/MSH-4 key extractor), the three store files (`shard_key` column +
  migration + `claim_next_fifo AND shard_key=?` + index lead-column), `api/models.py` (per-shard depth),
  **new `docs/adr/00NN-order-group-lane-sharding.md`**.
- **Gate:** (1) sharded per-order-group FIFO (2-MRN interleave; slow transform on A doesn't delay B);
  (2) same-key→same-shard across restart; (3) crash-mid-pipeline-in-one-shard replay; (4) finalizer-under-K
  (fan-out-2 routed rows in different shards — no premature PROCESSED); (5) A40-class cross-key serialization
  shard; (6) reload K-change refused-or-redrained, no row stranded; (7) SQLite no-op parity (shards=4 ≡
  shards=1); (8) legacy migration to `shard_key DEFAULT 0`.
- **Guardrail:** K-change = quiesce-drain-to-empty (no re-stamp). shards=1 default = byte-identical. Reject
  shards>1 on SQLite. Size pool **and** executor with K (B5). Gate behind a K=1-vs-K=2 microbench — if
  overlap < ~1.4×, ship K=1 default. **Set expectation: sub-linear (~2× on one store); the chain cut (Tier 1)
  is what makes each lane worth multiplying.**
- **Parallelism:** the wide-collision session — SERIALIZE on `wiring_runner.py` + all store files after B3.

**B5 — Executor sizing / split (SQL Server; ADR required; effort M)**
- **OWNS:** a dedicated `ThreadPoolExecutor` for aioodbc (at `sqlserver.py:393`) separate from a sized CPU
  executor for the `route_only`/`transform_one` `to_thread` calls; `config/settings.py`
  (`[store].odbc_executor_threads`, `[pipeline].cpu_executor_threads`); **new ADR**; a startup guard that
  neither is the stock default. **SQL-Server-only** (asyncpg has none).
- **Gate:** under K-lane load the DB and CPU work no longer share threads (assert distinct executors); EF-6
  no-MARS + cursor-close-before-release preserved; byte-identical FIFO/disposition at K=1.
- **Scope note:** measured as a **modest secondary** (~100→140 at 8 lanes) — a thread-count fix, not the
  primary wall. Build it to unblock >4-lane sharding, not as a standalone throughput play.
- **Parallelism:** SERIALIZE after B4 on `sqlserver.py` + `wiring_runner.py`.

**B6 — Dedicated ingest lane (robustness; ADR required; effort M)**
- **OWNS:** `store/store.py` (replace `:799` lock with a bounded-fair priority gate; ingest acquires HIGH),
  `store/sqlserver.py`+`store/postgres.py` (reserved 1-conn ingest pool), `pipeline/wiring_runner.py`
  (listener `max_ingress_depth`), `transports/mllp.py` (pause-recv backpressure), `config/settings.py` +
  `config/models.py`, **new ADR**.
- **Gate:** intake-never-sheds-under-delivery-stall; per-lane FIFO under the gate; ACK-after-durable on the
  reserved conn; `reset_stale_inflight` recovers reserved-conn ingress rows; `max_ingress_depth` engages TCP
  flow-control (drops nothing); **starvation-bound test** (sustained ingest can't indefinitely block workers).
- **Guardrail:** sell as ROBUSTNESS, not throughput. SQLite = bounded-fair priority-gate, never a 2nd writer.
- **Parallelism:** SERIALIZE on `store.py` + `wiring_runner.py` against B4/B5.

### TIER 3 — measure + baselines

**B7 — SQLite `synchronous=NORMAL` baseline (measurement + observability; independent)**
- **OWNS:** `store/store.py` (`db_status()` + `DbStatus` — add read-only `synchronous` field), `api/models.py`,
  `api/app.py`, `harness/load/enginepoll.py`+`report.py`, `console/status.py` (cosmetic).
- **Gate:** durability-mode-PARITY test (NORMAL vs FULL: byte-identical FIFO order, outbound rows, terminal
  disposition); MEASUREMENT: run the harness FULL then NORMAL on the same box, report a band, label MEASURED.
- **Guardrail:** report a band; document the NORMAL durability relaxation. Additive `store.py` touch —
  land early so it doesn't collide with the Tier-1 store-file chain.

**B8 — Measurement: post-fix re-measure + on-prem NVMe + prod corpus (no code)**
- **OWNS:** gitignored bench profiles; results into `docs/benchmarks/` (drift-reconciled vs origin/main).
- **Depends on:** B1–B3 (re-measure single-lane RTs/msg + the lane curve after the chain is cut); then B4.
- **Runs:** (1) confirm collapse+batch cut single-lane RTs (target ~7 → ~4) and lift single-lane + the lane
  curve; (2) **on-prem PLP NVMe** for the absolute 521 number (Azure SAN caps ~284); (3) **prod-sized
  (~11.5 KB) corpus** (still unrun — the bench used ~750 B); (4) fix the per-stage dwell query (`ts` is a
  string — cast before diffing).

**B9 — PG `commit_delay` (deferred, LAST; effort M)**
- **OWNS:** `store/postgres.py` (`SET commit_delay`/`commit_siblings`, re-applied on reconnect),
  `config/settings.py` (`pg_commit_delay_us=0`), `docs/CONFIGURATION.md`.
- **Depends on:** B8 — only if it shows commits bunching (e.g. batch-claim re-bunched them). REJECT on SQL
  Server (warn-and-ignore). Ships OFF.

---

### File-collision matrix (what must serialize)

| File | Sessions | Sequencing |
|---|---|---|
| **`store/sqlserver.py`** | B1, B2, B3, B4, B5, B6 | **SERIALIZE:** B1 → B2 → B3 → B4 → B5 → B6 |
| **`store/postgres.py`** | B1, B2, B3, B4, B6, B9 | **SERIALIZE:** B1 → B2 → B3 → B4 → B6; B9 independent |
| **`store/store.py`** | B1 (opt), B2, B4, B6, B7 | **SERIALIZE:** B7 (additive, first) → B1/B2 → B4 → B6 |
| **`pipeline/wiring_runner.py`** | B1, B2, B4, B5, B6 | **SERIALIZE:** B1 → B2 → B4 → B5 → B6 |
| **`config/settings.py`** | B1–B6, B9 | distinct keys, mostly mergeable — coordinate |

**Parallel-safe:** B7 (additive observability) and B8 (measurement, no code) run alongside anything. The
**Tier-1 store-file chain (B1 → B2 → B3) is strictly serial** and is the critical path.

### First session to start

**B1 — collapse the commit depth.** It is the primary lever (it raises single-lane *and* every future
sharded lane), it leads the serial store-file chain, and it is the hardest reliability-core change, so it
sets the invariant-test scaffolding the rest reuse. Land **B7** (the additive `synchronous` field +
SQLite-NORMAL baseline) in parallel for the honest default-config number. Carry one framing into B1: the
wall is **chain depth**, not cores or the store — so success is measured as **RTs/msg cut** (target ~7 → ~4)
and single-lane msg/s up, with lane sharding (B4) the secondary multiplier that follows.
