<!--
Multisession EXECUTION plan for the remaining throughput build. Companion to throughput-roadmap.md
(diagnosis + the 2026-06-30 connection-scale revision). This is the operational layer — order,
parallelism, method, coordination. Created 2026-06-30; REVISED 2026-06-30 (connection-scale).
-->

# Multisession Build Plan — remaining throughput work

**Companion to** [`throughput-roadmap.md`](throughput-roadmap.md) (the diagnosis + the **2026-06-30
connection-scale revision**, which this table implements). This is the **execution layer**: order,
parallelism, method, coordination.

## 2026-07-02 (later) — WS-C RESULT: the connection-scale claim storm (a THIRD wall) + the fix program

The 1,500-lane campaign found the wall that binds at CONNECTION scale regardless of volume: the
staged pipeline runs **one claim loop per (lane × stage)** — ~4,500 at 1,500 lanes — and their
`UPDLOCK` claims saturate the **store box** (92% CPU with **zero** messages in flight; `LCK_M_U`
convoy 40–70 ms; heavy `PAGELATCH_EX`). The claims are correct index seeks — this is lock/latch
contention from concurrency, and `poll_interval` / `pool_size` / B12-alone are all **inert** (A/B'd).
Distinct from the WS-B engine-CPU wall (which binds throughput per box at low lane counts): the
claim storm binds **lane count per store**. A secondary wall was measured behind it: outbound
**connect-per-delivery** exhausts ephemeral ports at ~525 msg/s (TIME_WAIT > the default Windows
range; ~18.6k connect-failure dead-letters) — host tuning is documented in
[`SERVICE.md`](SERVICE.md) §High-delivery-rate TCP tuning; connection reuse is the durable fix.

**The fix program** (operator-approved; plan: operator-local
`MULTISESSION-PLAN-claim-storm-2026-07-02.md`):
- **Phase-0 (the WS-1 PR):** with `per_lane_wake` ON, the idle backstop backs off
  0.25 s → 30 s (ADR 0061 amendment) — kills the IDLE storm (bench: store waits → ~0 at rest).
  At-least-once holds because every deferred-work path now self-wakes: `mark_failed` returns
  `next_attempt_at` and the delivery worker arms a per-lane retry timer; the clustered lease
  reclaim nudges `notify_work`; startup recovery precedes worker spawn. Bench-proven INSUFFICIENT
  under load — the loaded claim convoy persists →
- **Phase-1 (IN DESIGN — the throughput fix):** shared per-stage claimers — collapse O(lanes) claim
  loops to O(stages) pooled claimers over a new FIFO-safe head-per-lane store primitive (EMPTY on a
  producer-locked head, NEVER READPAST-skip within a lane — the #285 trap) + an in-process per-lane
  serializer, behind `[pipeline].claim_mode`. **DONE — ADR 0066; `pooled` is the default since #744
  (2026-07-03), `per_lane` the byte-identical opt-out.**
- **Also queued:** persistent outbound MLLP (removes connect-per-delivery — triple-motivated by the
  CPU profile, the delivery ceiling, and the port exhaustion); `DeliveryError` now carries the OS
  errno (#730). **Phase-2** (hash-partitioned queue *table* under the pooled claimer — one database,
  never a split store) stays a contingency, only if a residual `PAGELATCH` ceiling shows on the
  post-Phase-1 rate-walk.

**Interim deployment guidance:** until Phase-1 lands, size deployments to **≲ a few hundred lanes
per store** (the storm scales with lane count, not volume); `per_lane_wake=ON` + the Phase-0
backstop give idle lanes near-zero store cost.

## 2026-07-02 — WS-B RESULT (the multi-engine store gate): store EXONERATED; the wall is engine-box per-message CPU

The WS-B campaign (`harness multishard`: N `serve` engines against ONE shared SQL Server store)
initially returned *STORE_IS_CEILING / WRITELOG* and an ADR 0063 escalation. That verdict **did not
survive adversarial review** (two review passes + a fully de-confounded re-run; the whole arc is
preserved in the operator-local WS_B_REPORT.md). The settled, five-way-confirmed result:

- **The store is NOT the ceiling.** A driver-free commit-storm on the store box peaked **~29,000
  commits/s** — ≥11× what the engines demanded (~2,600) — with group commit batching 1.6→22.9
  commits/flush and the log device idle (0.19–0.27 ms/write). A `DELAYED_DURABILITY=FORCED` A/B
  (diagnostic only — it stays rejected for production) cut WRITELOG waits **75×** and bought **zero**
  throughput. **ADR 0063 (no split store) stays CLOSED — now with positive evidence.**
- **The wall is engine-side per-message CPU**: during the collapse the engine processes ran 65%
  mean / 81% peak of an 8-vCPU box while the load drivers used 5.8%; a split-driver re-run (two
  orchestrator processes on provably disjoint lanes) still collapsed, eliminating the harness. The
  engine-side mechanism is **not yet decomposed** (parse vs asyncio vs ODBC marshal vs AES vs applock
  orchestration) — that decomposition picks the next lever.
- **Clean numbers: ~193 msg/s intake per engine; two engines on one 8-vCPU box = 383 msg/s,
  near-linear.** The collapsed 429/279/285 figures are offered-overshoot artifacts — never cite them.
  **Caveat:** every measured *delivered* rate in the campaign was throttled by a **per-sink-process
  ceiling (~100–140 msg/s per driver/sink process)** — delivery scaled with sink processes, not
  engines — so the sustained end-to-end per-box rate is **unmeasured**. The 1500-shape test below must
  provision **≥5–6 sink processes** and target **delivered ≈ offered with bounded in-pipeline**.
- **Retroactive taint:** a single harness process has a measured **~457 msg/s ACK ceiling**, which
  confounds every earlier run offered above it through one process — including the hi-N
  **"≥~48 interfaces/engine wall"** (its 384-pass / 576-fail boundary brackets the ceiling). Re-measure
  with split drivers (`--engine-index-base`, #711) before citing an interfaces-per-engine limit.
  ADR 0062's pool inverted-U is **not** affected (its failures occur below the ceiling, dose-responsive).
- **Fixed along the way:** N≥4 co-start (was a convoy; now routine at N=16) via serialized harness
  spawn (#698) + the **ADR 0064** schema-init content-hash fast-path + index-seekable
  `reset_stale_inflight` (#703); honest hold-bracketed harness rates (#698); split-driver support (#711).
- **The scale story this settles:** ONE unified store + N engine **boxes** (ADR 0037) + per-message-CPU
  cuts (B2's fewer commits, free-threading ADR 0053, hot-path reduction). Rough **intake** sizing:
  ~1.5–2 8-vCPU-box-equivalents for the 521 msg/s tier; end-to-end sizing TBD. **Prerequisite before
  any N-concurrently-active engines on one store:** ownership-scoped startup recovery (today's
  unconditional `reset_stale_inflight` would steal a live sibling's in-flight rows — design plan
  exists, build gated on the 1500-shape box count).
  - **Scope correction (2026-07-06, from a code map): this is TWO entangled reliability-core builds, not a
    one-file patch.** (A) Scoping the reset to a shard's owned inbound `channel_id`s cleanly recovers
    ingress/routed/response/PT rows. But (B) **outbound rows are the gap** — they carry the *source*
    inbound's `channel_id` while the delivery lane keys on `destination_name` and is **shared across
    shards**, so a naive `channel_id` filter either **dups** a sibling's in-flight send or **strands** a row
    INFLIGHT forever (SQL Server has no lease sweep). [ADR 0063](adr/0063-no-split-store-unified-store-for-sharding.md)
    §45-50 names the missing piece — a **single-delivery-consumer-per-outbound-lane** ownership primitive
    (or a shard-stable outbound `owner` stamp: SS writes `owner=NULL`; PG's `owner` is `pid+uuid`, *not*
    restart-stable). MVP = **A + B**; estimate ~2–4 weeks + a **new overlapping-destination failover test**
    (today's `harness/load/multishard.py` deliberately uses disjoint names, sidestepping the exact overlap).
    Full build spec: the operator handoff `SHARDING-OWNERSHIP-SCOPED-RECOVERY-HANDOFF-2026-07-06.md`.

**NEXT (priority order):** (a) the **1500-SHAPE test** — hundreds of connections @ ~0.35–1 msg/s,
~521 aggregate, B1/B2 ON (+B12 as the confirm-at-scale arm), a dedicated load-gen box, ≥5–6 sink
processes, per-box CPU captured → the real per-box ceiling + box count; (b) ~~decompose engine
per-message CPU~~ **DONE same-day, twice-measured and converged** (a py-spy `--gil` leaf-frame
profile on the SQL Server rig + an independent SQLite in-process study — both operator-local
artifacts): **~76% of the engine's GIL-holding CPU is orchestration plumbing** — asyncio +
cross-thread future marshaling 41%, thread-pool executor 25.8%, locks 9.1% — vs ~24% actual work
(SQL 11.7, MLLP 5.1, HL7 parse 4.6, pipeline 2.3, **crypto ~0**). The cost is the
**blocking-DB-driver-in-a-thread-pool round-trip per store op** (identical shape on aioodbc AND
aiosqlite — ODBC itself is exonerated), so the **top levers are: (1) B2 + fewer stage ops per
message; (2) batch multiple SQL statements per executor hop; (3) free-threading (ADR 0053), which
directly attacks the dominant cost; (4) persistent outbound MLLP connections** (today's outbound
opens a TCP connection per delivered message — `mllp.py` documents persistence as future work; a
real delivery-ceiling lever, owner decision). **B12 per-lane wake was A/B'd on the rig at dense AND
idle shapes: no measurable CPU or throughput change** (empty claims release the GIL during the
network wait) — it stays default-OFF and drops out of the CPU lever ranking (re-confirm only at
full 1,500-lane scale). B5 (executor split) is likely subsumed by (2)/(3) — re-evaluate after the
1500-shape run. Platform note: the asyncio overhead was measured on the Windows ProactorEventLoop;
re-profile on the production platform before final box sizing; (c) a clean 4-engine no-loss point
(offer ~450–500, not 780); (d) ownership-scoped recovery (gated on (a)).

## Where we are (2026-06-30)
- **Target reframed to the Corepoint spec: ~1,500 connections @ ~521 msg/s aggregate** (~0.35 msg/s
  average/connection). **Per-lane speed has ~100× headroom and is not the constraint**; the problem is
  **connection-scale + aggregate-commit** (see the roadmap revision).
- **DONE + verified on real SQL Server + Postgres:** B1 (inline fast-path 7→5 commits/msg), B2
  (batch-claim), B3 (seq-only FIFO, ~3 fewer round-trips/msg), B7 (SQLite NORMAL baseline + `db_status`),
  and **#672** (the server-DB CI legs now gate every lever's backend tests; the #285 locking test was
  repaired). The **chain-cut is complete** — it now serves the **aggregate-commit** axis (raises
  connections-per-store ~1.75×).
- **B4 (order-group sharding) is DELETED** (owner decision: feeds stay one ordered lane; customers
  federate hot sources). Do not resurrect.
- **DONE this session:** **B11** connection-scale harness (#675) and **B10** rename-based FIFO index
  migration (ADR 0060, #676) — both merged, real-CI-green on all backends.
- **B8 RAN 2026-06-30 → the store is NOT the wall.** Single-store commit ceiling ≈ **23,600 commits/s** on
  local NVMe (AWS i4i, flush real @170 µs) — **≈6.5× the ~3,647 commits/s (45M/day) target, ≈83× the Azure
  SAN ~284 cap.** **1 unified store is DECIDED** (no 2–3 stores / partitioned queue for write capacity;
  ADR 0039 shelved for write capacity too). The SAN "~100–140 plateau / ~284 cap" were storage artifacts,
  not store limits. **The connection-scale + lane levers below (B13/B12/B5/B6) are now unblocked with real
  store headroom** — the ceiling moves to the **engine serial-per-inbound chain + CPU**, where B1–B3 (DONE)
  already act. See the roadmap's B8 RESULT block.
- **Verdict: store side PROVEN (1 store holds 45M/day with headroom); the 1,500-connection footprint is
  still unproven.** The remaining gate is the **prod-faithful per-interface number** — the real engine
  driving the 7-commit pipeline over the LAN (the **"04" run**), which needs the **cut build (v0.2.12/.13)**
  + B11. B8 was localhost/synthetic on a small 8-vCPU box (real ceiling likely higher).

## Items

| ID | What | Status | Depends on | Note |
|---|---|---|---|---|
| **B1** | inline fast-path (7→5 commits/msg) | ✅ DONE | — | aggregate-commit lever (connections-per-store) |
| **B2** | batch-claim `TOP(N)` | ✅ DONE | — | fewer claim round-trips; helps the idle+active claim load |
| **B3** | seq-only FIFO (drop `SELECT MAX` clamp) | ✅ DONE | — | biggest chain cut; needs **B10** to land on upgraded DBs |
| **B7** | SQLite NORMAL baseline + `db_status` | ✅ DONE | — | baseline; SQLite stays non-viable at the 1,500-conn tier |
| **B4** | ~~order-group lane sharding~~ | ❌ **DELETED** | — | owner decision: no intra-feed split; federation handles hot sources |
| **B11** | connection-scale harness (500/1k/1.5k lanes) | ✅ **DONE** (#675) | — | `harness/load/connscale/` + additive engine instrumentation. Measures executor saturation, store-pool wait, idle-poll RT/s, FD/socket, reload + ACK latency vs connection count. |
| **B8** | single-store commit ceiling (bench) | ✅ **DONE** 2026-06-30 | — | **≈23,600 commits/s** on local NVMe (AWS i4i) → **store is NOT the wall; 1 unified store DECIDED** (≈6.5× target, ≈83× SAN). SAN ~100/~284 were storage artifacts. **Still pending: the prod-faithful per-interface "04" run** (real engine over LAN) — gated on the **cut build (v0.2.12/.13)**; redeploy the ~15-min AWS rig. |
| **B12** | per-lane wake events | ✅ **DONE** (ADR 0061) | B11 | **#1 connection-scale fix.** Wake events WERE engine-wide singletons → one message woke all ~1,500 router workers (thundering herd). Now a committed message wakes **only its own (stage, lane) worker** via a strict get-or-create per-lane Event registry. **DEFAULT-OFF** + byte-identical when off; the 0.25 s poll backstop + FIFO claim are untouched (a missed wake self-heals). Measurable via B11's `wake_fanout_per_s → ~0`. |
| **B13** | server-DB `pool_size` right-sizing | ✅ **DONE** (ADR 0062) | B11 | Default `pool_size` raised **5 → 40** — the measured **inverted-U optimum** (helps to ~40; over-provisioning past it is CATASTROPHIC — shared-instance WRITELOG/applock contention, not CPU). NOT "bigger for 1500": that's a **sharding** problem. ~~Residual per-engine wall at ≥~48 interfaces~~ — **WITHDRAWN pending re-measure** (2026-07-02: those runs were offered above the single-harness-process ~457/s ACK ceiling; re-run with split drivers, #711). The inverted-U itself is unaffected (measured below the ceiling). Server-DB only; tunable; explicit configs unchanged. |
| **B5** | off-loop executor sizing + **split** | ⬜ TODO | B11/B8 | No `set_default_executor` today → route_only + transform_one share Python's default pool (~12–32 threads) engine-wide. Install explicit **split** pools (routing vs larger transform), sized to cores+connections; isolate the 30 s `db_lookup` thread-pin so it can't starve routing+transform. |
| **B6** | shared **ingest sub-pool** / writer path | ⬜ TODO | B11/B13 | Give pre-ACK intake its own commit path so ACK-on-receipt latency doesn't queue behind the worker-claim + idle-poll storm. **Shared sub-pool carved from B13's pool — NOT per-listener** (1,500 dedicated conns is infeasible). |
| **B14** | per-listener accept-cap default | ⬜ TODO | B11 | `DEFAULT_MAX_CONNECTIONS=256` × 1,500 listeners = 384k socket ceiling. Lower the default (most HL7 partners hold 1–4), keep the per-connection override. |
| **B10** | rename-based FIFO index migration | ✅ **DONE** (ADR 0060, #676) | B3 | renames to `ix_queue_fifo_*_seq` + idempotent on-open DROP-old/CREATE-new on all 3 backends, so B3's cut lands on **upgraded** DBs. |
| **B9** | Postgres `commit_delay` (group-commit) | ⏸ DEFERRED | B8 | only meaningful once B8 shows durable-write-bound AND the store presents concurrent in-flight txns (see the single-writer-vs-pool open question). |
| **T8** | backend-parametric test/measurement | ⬜ TODO | — | run every connection-scale + commit result across SQLite/SQL Server/Postgres. |

## Execution sequence

```
DONE:     B11 connscale harness (#675) + B10 index migration (#676) + B8 store ceiling (~23,600 commits/s)
          + the "04" per-interface run (2026-07-01: one strict-FIFO MLLP interface ~60 msg/s e2e,
          serial-lane-latency-bound -- per-interface BOUNDED BY DESIGN; feeds federate) + B12 per-lane
          wake (ADR 0061) + B13 pool 40 (ADR 0062) + WS-B multi-engine gate RESOLVED (2026-07-02, above:
          store EXONERATED with ~11x headroom; wall = engine-box per-message CPU; ADR 0064 open-path
          fixes; #698/#703/#711 instruments).
GATE:     the 1500-SHAPE test (see the 2026-07-02 block above) -> the real per-box ceiling + box count.
          Sizes B5/B6/B14 AND the ownership-scoped-recovery decision.
THEN:     engine per-message CPU decomposition -> pick the top lever (B5 executor split / ADR 0053
          free-threading / hot-path cuts)  ->  B5  ->  B6 ingest sub-pool  ->  B14 accept-cap
LATER:    B9 (only if a de-confounded run shows durable-write-bound) ; T8 backend-parametric
RELIABILITY-AT-SCALE (fold into the above): ownership-scoped reset_stale_inflight (PREREQUISITE for any
          N-active engines on one store; = scoped-reset + the ADR 0063 single-consumer-per-outbound-lane
          primitive — a reliability-core A+B build, NOT a one-file patch; see the "Scope correction" above)
          · failover cold-start stampede control · finalizer contention
          sizing · O(connections) monitoring-cardinality caps · ~0.5-1.3 TB/day store growth ->
          per-connection retention + lean-write become MANDATORY.
DOC:      SYSTEM-REQUIREMENTS.md multi-process-sharding wording reconciled 2026-07-02 (supervise is
          BUILT, ADR 0037/0063; N-active-on-one-store awaits ownership-scoped recovery).
```

**The store is no longer a gate** — B8 proved one store absorbs ~23,600 commits/s (~6.5× the 45M/day
target), so the connection-scale levers (B13/B12/B5/B6/B14) are unblocked; size them against B11's curves
+ the **"04" engine-over-LAN run** (still needed before a near-1,500-connection deployment claim). The
defaults (executor ~12–32, 0.25 s poll; `pool_size` raised to 40 by B13/ADR 0062) are still largely for *tens* of connections — that is the
remaining engine-side work.

## Per-session method (the proven loop)
1. **Ultracode design+verify Workflow** → ADR + plan + invariant-test matrix (map → designs → adversarial
   verifiers → synthesize → critic).
2. **Worktree off `origin/main`** + venv (`[dev,harness,sqlserver,postgres]`).
3. **Implement** default-OFF / byte-identical-when-OFF where it touches the reliability core.
4. **Adversarial-invariant tests** across SQLite + SQL Server + Postgres; **append new backend tests to
   the `ci.yml` throughput-lever step on BOTH server-DB legs** (the #672 gate).
5. **PR → CI gate (both server-DB legs) → merge.** Omit the `Co-Authored-By` trailer; run the FULL
   pytest suite (leak-gate 3-place token); never commit creds/PHI; bench artifacts stay operator-local.

## Deployment shape (gate on B8/B11 before publishing)
- **1 engine node** (8–16 cores) + **1 unified server DB** (Postgres/SQL Server on enterprise storage) +
  1 active-passive standby. **SQLite non-viable** at this tier; viable to ~low-hundreds of connections
  (idle-poll-bound, **expressed in connection count, not msg/s** — the poll storm hits the single-writer
  lock as f(connections) before throughput does). Store-partitioning (ADR 0039) stays shelved.
- **Federation rule (state in the deployment guide):** the customer caps per-interface volume; a mega
  chain splits a hot source (ADT) by hospital/region/service-line into multiple inbound connections, each
  well under one lane's ceiling. The engine guarantees strict per-lane FIFO + at-least-once per interface;
  scale beyond one lane for a logical source is the customer federating it, never the engine splitting it.
- **Smaller tiers collapse cleanly:** community hospital (~1M/day) = 1 node + 1 store (SQLite ok up to a
  connection-count cap); mid-IDN (~5–15M/day) = 1 node + 1 server DB.
