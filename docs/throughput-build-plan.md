<!--
Multisession EXECUTION plan for the remaining throughput build. Companion to throughput-roadmap.md
(diagnosis + the 2026-06-30 connection-scale revision). This is the operational layer — order,
parallelism, method, coordination. Created 2026-06-30; REVISED 2026-06-30 (connection-scale).
-->

# Multisession Build Plan — remaining throughput work

**Companion to** [`throughput-roadmap.md`](throughput-roadmap.md) (the diagnosis + the **2026-06-30
connection-scale revision**, which this table implements). This is the **execution layer**: order,
parallelism, method, coordination.

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
| **B13** | server-DB `pool_size` right-sizing | ⬜ TODO | B11 | `pool_size=5` for the whole engine (settings.py) → catastrophic for ~3,000 workers. Raise to tens–low-hundreds, sized to connection count; startup validation. Near one-line, outsized impact. |
| **B5** | off-loop executor sizing + **split** | ⬜ TODO | B11/B8 | No `set_default_executor` today → route_only + transform_one share Python's default pool (~12–32 threads) engine-wide. Install explicit **split** pools (routing vs larger transform), sized to cores+connections; isolate the 30 s `db_lookup` thread-pin so it can't starve routing+transform. |
| **B6** | shared **ingest sub-pool** / writer path | ⬜ TODO | B11/B13 | Give pre-ACK intake its own commit path so ACK-on-receipt latency doesn't queue behind the worker-claim + idle-poll storm. **Shared sub-pool carved from B13's pool — NOT per-listener** (1,500 dedicated conns is infeasible). |
| **B14** | per-listener accept-cap default | ⬜ TODO | B11 | `DEFAULT_MAX_CONNECTIONS=256` × 1,500 listeners = 384k socket ceiling. Lower the default (most HL7 partners hold 1–4), keep the per-connection override. |
| **B10** | rename-based FIFO index migration | ✅ **DONE** (ADR 0060, #676) | B3 | renames to `ix_queue_fifo_*_seq` + idempotent on-open DROP-old/CREATE-new on all 3 backends, so B3's cut lands on **upgraded** DBs. |
| **B9** | Postgres `commit_delay` (group-commit) | ⏸ DEFERRED | B8 | only meaningful once B8 shows durable-write-bound AND the store presents concurrent in-flight txns (see the single-writer-vs-pool open question). |
| **T8** | backend-parametric test/measurement | ⬜ TODO | — | run every connection-scale + commit result across SQLite/SQL Server/Postgres. |

## Execution sequence

```
DONE:     B11 connection-scale harness (#675) + B10 index migration (ADR 0060, #676) + B8 single-store
          commit-ceiling bench -> store is NOT the wall; 1 unified store DECIDED (~23,600 commits/s).
GATE:     the "04" prod-faithful per-interface run -- real engine over LAN driving the 7-commit pipeline
          -- gated on the CUT BUILD (v0.2.12/.13). Redeploy the ~15-min AWS rig. This sizes B13/B12/B5/B6/
          B14 against the real engine (B8 already proved the store won't be the wall).
THEN:     B13 pool right-size  ->  B12 per-lane wake events  ->  B5 executor split  ->  B6 ingest sub-pool
          ->  B14 accept-cap            (each sized by B11's curves; B12 is the structural one)
LATER:    B9 (only if the 04 run shows durable-write-bound + concurrent in-flight txns) ; T8 backend-parametric
RELIABILITY-AT-SCALE (fold into the above): failover cold-start stampede control (~3,000 workers re-armed
          at once) · finalizer contention sizing on one store · O(connections) monitoring-cardinality
          caps · ~0.5-1.3 TB/day store growth -> per-connection retention + lean-write become MANDATORY.
DOC:      reconcile SYSTEM-REQUIREMENTS.md (it wrongly says multi-process sharding isn't built; ADR 0037
          shipped it) before publishing node/store deployment guidance.
```

**The store is no longer a gate** — B8 proved one store absorbs ~23,600 commits/s (~6.5× the 45M/day
target), so the connection-scale levers (B13/B12/B5/B6/B14) are unblocked; size them against B11's curves
+ the **"04" engine-over-LAN run** (still needed before a near-1,500-connection deployment claim). The
defaults (executor ~12–32, `pool_size=5`, 0.25 s poll) are still for *tens* of connections — that is the
remaining engine-side work.

## Per-session method (the proven loop)
1. **Ultracode design+verify Workflow** → ADR + plan + invariant-test matrix (map → designs → adversarial
   verifiers → synthesize → critic).
2. **Worktree off `origin/main`** + venv (`[dev,console,sqlserver,postgres]`).
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
