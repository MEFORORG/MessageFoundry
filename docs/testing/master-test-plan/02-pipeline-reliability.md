[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 1. Pipeline & Reliability Core

**ID prefix:** `PIPE` · **Surface:** engine (+ CI infra for the never-executed legs; one manual browser/harness row)
· **Primary risk:** a silent break in the durable staged queue — a lost, duplicated, mis-ordered, or never-terminal message — on code paths whose only live-backend proof runs in no CI leg.

### 1.1 Scope & objectives

This chapter owns the engine's **reliability core**: the durable staged queue and everything that
guarantees a received message is counted, logged, and eventually terminal exactly once per
destination.

In scope:

- The **3 + 1 stage** queue — `ingress → routed → outbound`, plus the optional `Stage.RESPONSE`
  re-ingress token ([`store/store.py:330-357`](../../../messagefoundry/store/store.py)).
- **ACK-on-receipt**: AA is built only after `enqueue_ingress` durably commits
  ([`pipeline/wiring_runner.py:3717-3745`](../../../messagefoundry/pipeline/wiring_runner.py)), and the
  four pre-ACK failure classes that still **NAK synchronously** (decode `AR` :3497, NUL `AR` :3523,
  strict-validate `AE` :3660, streaming-detach `AE` :3699).
- **Transactional stage handoff** — `route_handoff` / `transform_handoff` / the Step-A combined
  `handoff` / `ingress_handoff` ([`store/base.py:289-366`, `:703-726`](../../../messagefoundry/store/base.py)) —
  and the at-least-once re-run invariant that rests on them.
- **Crash recovery**: `reset_stale_inflight` across every stage, and its ownership-scoped form
  (`OwnedLanes`, ADR 0073) for **engine shards** over one unified store
  ([`pipeline/engine.py:809-874`](../../../messagefoundry/pipeline/engine.py)).
- The **disposition finalizer as sole authority** and the seven-member `MessageStatus` set
  (`RECEIVED / ROUTED / UNROUTED / PROCESSED / FILTERED / ERROR / NOT_DEPLOYED`,
  [`store/store.py:311-319`](../../../messagefoundry/store/store.py)).
- **Seq-only per-lane FIFO** (ADR 0059), the claim family (`claim_next_fifo`,
  `claim_next_fifo_batch` ADR 0058, `claim_fifo_heads` + `list_fifo_lanes` ADR 0066,
  `release_claimed` / `reschedule_claimed` ADR 0070), pooled `StageDispatcher` (**the shipped
  default**, `claim_mode="pooled"`) and its `per_lane` opt-out.
- **Retry / backoff / dead-letter / bulk replay / resend / re-ingress**, the H2 `delivered_keys`
  idempotency ledger, and the ADR 0082 batch twins.
- **Startup connection fault isolation** (ADR 0031) and the `CONTINUE` / `STOP` internal-error policy
  at both the router and transform phases.
- **Purity of Routers/Handlers** and the two sanctioned non-pure carve-outs — `db_lookup`
  (ADR 0010) and `fhir_lookup` (ADR 0043).
- **Dry-run** (`route_only` / `transform_one` / `route_message` / `dry_run`), traced dry-run
  (ADR 0072), snapshot parity, and the `accepts=` router-stage predicate seam (ADR 0084).
- The **guard-rail posture of withdrawn levers** that remain operator-reachable: the ADR 0057 inline
  fast path (terminated by ADR 0107) and the ADR 0055 group-commit window.

Explicitly **NOT** in scope here — cited, not restated:

| Out of scope | Owned by |
|---|---|
| Per-feature six-dimension coverage audit of every pipeline/store mechanism | `docs/testing/FEATURE-COVERAGE-PLAN.md` §9 `[FCP:STORE-1..22]` and §12 `[FCP:PIPE-1..19]` |
| Windows Server 2025 host/service-identity behaviour: NSSM crash recovery (`W25:S2.5`), dead-letter+replay walkthrough (`W25:S3.5`), independent draining (`W25:S3.6`), real-host throughput & failover **time** (`W25:S4.x`) | `docs/testing/WIN2025-TEST-PLAN.md` — which at `:38`, `:71`, `:76` explicitly **disowns** engine internals (staged pipeline, per-lane FIFO, store parity) as CI-owned |
| Throughput/bench methodology, the 20-profile catalog, backend comparison, ADR 0101 pre-registered falsifiers | `docs/LOAD-TESTING.md`, `docs/THROUGHPUT.md`, `docs/throughput-{roadmap,build-plan}.md`, `docs/benchmarks/` |
| Crypto root-of-trust / KeyProvider seam (`FCP:CRIT-1`) | Crypto chapter; coverage plan P0 |
| Active-passive leader election, cluster coordinator, DR backup/restore | HA/cluster and DR chapters (coverage plan §HA/§DR) |
| HL7 peek/parse/strict-validate semantics themselves | Parsing chapter (this chapter only asserts *which* of them NAK) |
| Transports/connector behaviour (MLLP framing, File, DICOM, X12) | Transports chapter |
| Mutation-coverage and diff-coverage advisory gates | `docs/quality-gates/HANDOFF-mutation-coverage.md` (drafted, not built) |

**ID disambiguation.** This chapter's IDs are **zero-padded** (`PIPE-01`…) and are *not* the coverage
plan's unpadded `PIPE-1..19`. Per the plan-wide convention, **every foreign ID carries its document
prefix**: `FCP:` for a `docs/testing/FEATURE-COVERAGE-PLAN.md` id, `W25:` for a
`docs/testing/WIN2025-TEST-PLAN.md` test id. A bare `PIPE-nn` in this chapter always means **this
chapter's own row**. This chapter's area = `{FCP:PIPE-1..19}` ∪
`{FCP:STORE-2,3,4,5,6,7,8,9,10,11,13,16,17,18,21}`. See open question 1.

---

### 1.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_staged_pipeline.py` (42 tests, SQLite) | Ingress row + `RECEIVED` before ACK; handoff atomicity / idempotency / rollback; `route_handoff` + `transform_handoff`; finalizer precedence incl. not-premature-with-a-pending-sibling; `ROUTED→FILTERED` collapse; `reset_stale_inflight` all-stages + scoped; `ack_after=delivered` refused at wiring **and** at engine start; legacy outbox migration; write-amplification footprint |
| `tests/test_sqlserver_store.py` (~93, `MEFOR_TEST_SQLSERVER`; CI `ci.yml:549-569`) | Server-DB parity for the staged flow, handoff idempotency, `transform_handoff` crash, finalizer-not-premature across sibling handlers, and the `FCP:STORE-4` runner-level ACK-on-receipt + post-ingress-failure-does-NOT-NAK pair at `:2890-2940` |
| `tests/test_postgres_store.py` (~101, `MEFOR_TEST_POSTGRES`; CI `ci.yml:771-785`) | Postgres parity for the same set, the `FCP:STORE-4` ACK/no-NAK twin at `:2839`, and the lease-aware scoped-reset primitive (sibling lease preserved) |
| `tests/test_wiring_engine.py` (54) | Worker behaviour end-to-end: unrouted/filtered, unknown-handler dead-letter at ingress, retry-then-succeed, exhausted-retries → dead-letter, permanent-reject fail-fast, `CONTINUE`/`STOP` at ingress + transform, stage-aware buildup/stall/saturation alerts, outbound stop/resume FIFO drain, leadership requeue, PHI-free error logging |
| `tests/test_seq_only_fifo.py` (8, backend-parametrized) + `tests/test_fifo_ordering.py` (6) | Seq-only per-lane FIFO; order under a backward clock; outbound + response fan-in commit order; rowid reuse; backing-off head blocks the lane; contiguous-due cutoff; replay/reset preserve seq position; H2 dup-head skip-and-advance with no reorder |
| `tests/test_batch_claim_fifo.py` (9) + `_locking.py` (18) + `_worker.py` (2) | ADR 0058 contiguous-due prefix truncation; backing-off head ⇒ empty batch; crash-mid-batch tail recovered **in order**; attempts bumped in the claim commit; undecryptable interior dead-lettered with the tail surviving; locked-head **BLOCKS** (the no-`SKIP LOCKED` trap the repo tracks as **`#285`** (above the published #231 baseline), cited at `ci.yml:817` and `docs/adr/0066-pooled-stage-claimers.md:18`, `:24`, `:87`, `:99`) |
| `tests/test_claim_fifo_heads.py` (18) + `tests/test_stage_dispatcher.py` (37) | ADR 0066 pooled claim semantics + the dispatcher state machine: prefix order, park/unpark, slot-budget exactness, 200-lane busy soak, sweep/rearm, ADR 0070 T17 cases 1-9, pause/resume slot conservation |
| `tests/test_pooled_runner.py` (3) + `tests/test_pooled_rider.py` | The ADR 0066 default-flip sentinel (`claim_mode` unset ⇒ pooled dispatchers; the flip is recorded at `docs/adr/0066-pooled-stage-claimers.md:3`, `:7` and tracked as **`#744`** / PR #765) and the opt-out sentinel (explicit `per_lane` constructs **zero** pooled objects), plus a pooled SQLite end-to-end smoke |
| `tests/test_per_lane_wake.py` (11) + `tests/test_idle_backstop_retry_wake.py` (5) | ADR 0061 targeted wake registry; default-OFF singleton parity; a producer wakes only its own lane; multi-message FIFO under per-lane wake; the long-idle retry backstop |
| `tests/test_reingress.py` (22) | ADR 0013 Inc 2: `Stage.RESPONSE` lane keying, reset recovery, the finalizer seeing the pending response row, loopback wiring guards, exactly-once `ingress_handoff`, depth-cap dead-letter, corrupt-ref no-loop, end-to-end response worker, `response_get` after retention purge |
| `tests/test_passthrough.py` (25) + `tests/test_passthrough_graph.py` | ADR 0038 internal PT connector + child-message re-ingress in the same `transform_handoff` transaction |
| `tests/test_not_deployed.py` (26) + 5 cases each in `test_sqlserver_store.py` / `test_postgres_store.py` | ADR 0111: declined Sends recorded as `not_deployed` events in the **same** handoff txn; the finalizer emitting `NOT_DEPLOYED` rather than `FILTERED` for an all-declined message |
| `tests/test_startup_fault_isolation.py` (7) | ADR 0031: duplicate-port loser isolated, reserved-API-port inbound isolated, failed outbound isolated → retries → recovers, File `validate_directory` isolate vs defer, valid graph starts clean, `/connections` reports degraded |
| `tests/test_inline_fast_path.py` (11; also on real SS + PG via `ci.yml:690` / `:820`) | ADR 0057 gates: off ⇒ split path; multi-handler / filtering / state-op / lookup-graph all fall back; internal-error policy; crash-after-claim pure re-run; post-commit idempotent no-op; the G6 finite-attempts ceiling on the inline path |
| `tests/test_crit2_inline_doc_drift.py` (4) | `InboundConnection.inline` and the `inbound()` factory both default `False`; the live `_router_worker` really does call `store.handoff(` (doc-drift tripwire) |
| `tests/test_replay_purity.py` (7) | `RouteOutcome` value-equality replay harness: a pure Handler is byte-identical; a pinned `current_ingest_time` is pure; module-global / wall-clock / `uuid4` / impure-router all **diverge** — the harness has teeth |
| `messagefoundry/checks.py:863-945` (`handler-security`, ADR 0144) via `messagefoundry check` | Advisory static `impure-transform` rule scoped to `@router`/`@handler` bodies (wall clock / `random` / `uuid4`), plus `phi-to-log`, `unsafe-db-lookup`, `ambient-authority`, `unvetted-import`; `--strict-handler-security` promotes to blocking |
| `tests/test_accepts_seam.py` (25) | ADR 0084: decline before a routed row exists; all-declined → `UNROUTED` (incl. the fused twin); a predicate raise is a content error; sandbox/tracer parity; purity across a replay; thread-safety; and the three static-validation negatives — **closes `FCP:PIPE-9`** |
| `tests/test_db_lookup.py` (24) + `test_db_lookup_live_runner.py` (4) + `test_fhir_lookup.py` (48) | Carve-out semantics: raises with no active runner; dry-run raises; FHIR router-phase raises (`:545`); write/multi-statement rejected; egress allow-list; PHI-free errors; live-runner substitute / gated-drop → `FILTERED` / error + timeout dead-letter **after** the ACK |
| `tests/test_dryrun.py` (23) + `test_dryrun_trace.py` (17) + `test_dryrun_snapshot_parity.py` (4) | Dry-run route/transform/self-smoke; traced mode byte-identical + prev-tracer restore + redaction-by-default; snapshot parity with the live path |
| `tests/test_ownership_scoped_reset.py` (7) + `test_shard_lane_ownership.py` (10) + `test_shard_recovery_engine.py` (9) + `test_sharding.py` (32) | ADR 0073/0063 **engine-shard** lane ownership, scoped-reset semantics, in-process engine-shard recovery, and the unified-store guard refusing >1 SQLite engine shard — all in the default SQLite pytest leg |
| `tests/test_group_commit.py` (19) | ACK waits for a durable ingress; the claim never enrols in the committer; group rollback re-runs all; per-lane FIFO + single finalizer + at-least-once idempotent handoff hold under group-commit; default window 0 constructs no committer |
| `tests/test_adr0075_batch_{golden_sql,backend_gate,error_attribution}.py` + `test_adr0075_rt_count_gate.py` | **Offline** golden-SQL text, provable no-op on Postgres/SQLite, per-statement error attribution, round-trip counts for the DEFAULT-ON statement-batching lever — these **do** run in the default pytest leg |
| `tests/test_adr0114_claim_{flags,fold,proc,prepared}.py` | All three ADR 0114 sub-lever flags default OFF; env coercion; the AC-6 sentinel that non-SQL-Server backends never reference them; byte-identical OFF batch text; fold/guard exception + cancellation matrix; proc-body golden pins; prepared-cursor lifecycle |
| `tests/test_txn_per_message_cost_model.py` (12, default leg) | The ADR 0051 `3 + 2H + 2N` model composed from real `SqlServerStore` methods over a recording connection: `route_handoff` commits once regardless of H, `transform_handoff` once regardless of N, and `fifo_claim_batch` collapses `2H → H+1` (not to 1) |
| `.github/workflows/ci.yml:660-701` (SQL Server) / `:805-830` (Postgres) — "throughput-lever backend invariants" | Runs `test_inline_fast_path`, `test_batch_claim_{fifo,worker,locking}`, `test_claim_fifo_heads`, `test_seq_only_fifo`, `test_fifo_index_migration`, `test_per_lane_wake`, `test_stage_dispatcher`, `test_pooled_rider` against **real** SQL Server **and** real Postgres |
| `ci.yml:635-658` / `:787-803` — failover-LOAD legs + `tests/_failover_load_support.py:88-127` | `test_load_failover_{sqlserver,postgres}.py` under the **pooled** default: promotion, no acknowledged loss, drained pipeline, `lane_inversions == 0` with `lanes_observed >= 2`, single leader, bounded dup rate — closes **`FCP:STORE-7`**'s "pooled failover unmeasured" |
| `ci.yml:878-956` (load smoke, SQLite) and the SQL Server twin | End-to-end zero-loss fan-out + drain-to-zero at smoke size on both backends, nightly + `workflow_dispatch`; the SS leg caught the routed-stage `handler_name`-drop regression the in-process tests missed |
| `ci.yml:702-723` / `:855-877` — RTE capture / re-ingress leg (`tests/test_x12_rte.py`) | The connector→runner half of capture → `Stage.RESPONSE` → loopback re-ingress on real SQL Server and real Postgres |
| `harness/config/coverage.py` + `harness/scenarios.py:41-63` | The disposition-coverage graph: A01/A04/A08 fan-out `PROCESSED`, other ADT single-send, A02 `FILTERED`, A03 `ERROR`, non-ADT `UNROUTED`, strict-inbound `ERROR`, plus independent draining and dead-letter/replay |
| `harness/load/` (runner, governor, correlator, sink, failover, multishard, shardcert, shardcert_ladder, connscale) + 20 profiles in `harness/load/profiles/` | Load/soak/spike/fan-out/write-amp profiles, correlation-sink true-E2E no-loss reconciliation, per-lane FIFO inversion counting (`failover.py:657`), failover orchestration, the ADR 0073 N-active shardcert bench (local-correctness half) |
| `docs/CONNECTIONS.md:1592-1640` | The operator-facing claim-mode contract: pooled default rationale, `per_lane` opt-out, caveat (a) no inbound de-dup so exactly-once degrades under load, caveat (b) failover covered but recovery **time** host-dependent |

**Done — do not re-plan.** The following are closed and must not reappear as new work in this
chapter or any downstream one:

1. **Stage-handoff atomicity, idempotency and rollback** on all three backends. `test_staged_pipeline`
   owns SQLite; `test_sqlserver_store` / `test_postgres_store` own server-DB parity and both run in CI.
2. **Seq-only per-lane FIFO and the whole claim family** — single, batch, and pooled — on all three
   backends, including the locked-head-BLOCKS inversion (`#285` — the no-`SKIP LOCKED` trap,
   `ci.yml:817` / ADR 0066 §mandate `:18`). The
   `throughput-lever backend invariants` legs execute these against real SQL Server and real Postgres today.
3. **Pooled-mode failover under load.** `FCP:STORE-7` is stale: `ci.yml:635-658` / `:787-803`
   run `test_load_failover_{sqlserver,postgres}` with the harness setting **no** `claim_mode`, i.e.
   under the pooled default, and hard-gate zero acknowledged loss + `lane_inversions == 0`.
4. **Postgres 2-engine crash-and-restart recovery.** `FCP:STORE-10`'s "not built" is stale —
   `tests/test_shard_recovery_postgres.py` exists (4 tests). Its problem is that it **runs nowhere**
   (PIPE-01), not that it is missing.
5. **`accepts=` static fail-closed validation** — `FCP:PIPE-9` is closed by
   `test_accepts_seam.py` (the three static-validation negatives).
6. **Purity replay-equality harness** — `FCP:PIPE-14`'s replay half is closed by
   `test_replay_purity.py` + the `impure-transform` advisory lint. What remains open is the
   *runtime/estate* detector (PIPE-25 below), not the harness.
7. **`FCP:STORE-4` cross-backend ACK-on-receipt + no-post-ACK-NAK** — closed by
   `test_sqlserver_store.py:2890-2940` and `test_postgres_store.py:2839`. What is missing is only the
   general/SQLite twin (PIPE-04).
8. **Coverage-plan citation errata:** `FCP:STORE-3`/`FCP:STORE-4` cite `test_consistency`, which is
   `tests/test_consistency.py` — **HL7 cross-field consistency primitives**, not pipeline consistency.
   Correct the citation; do not build against it.

---

### 1.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| Six `MEFOR_TEST_*`-gated pipeline suites (~36 tests) are named in **no** workflow step | A live regression in `batch_handoff_statements` (DEFAULT-ON, SQL-Server-only, restructures the route/transform handoff DML) or in ownership-scoped **engine-shard** recovery ships green | Silent data loss, wrong disposition, or **duplicate PHI deliveries across engine shards** on the production-scale backend | **No.** `ci.yml:424-428`'s own comment says the path gate "MUST list every file the sqlserver/postgres steps run"; these are in neither the steps nor the gate regex | **P0** |
| No poison-crash attempts ceiling on the **default split** ingress/routed path | A hard abort with no Python exception (C-extension segfault, OOM kill) inside `route_only`/`transform_one`/handoff is caught by neither the internal-error policy nor the ADR 0070 T17 handler; `reset_stale_inflight` re-pends the head, the lane re-runs, the process dies again | Lane head-of-line blocked **forever** across NSSM/supervisor restarts; nothing dead-letters; every message behind it stops flowing. The G6 ceiling exists only inside `if inline:` (`wiring_runner.py:4475-4496`), and its own comment at `:4479-4480` states no ingress/routed path enforces `max_attempts` on the split path. `supervisor.py:22` lists "restart backoff / crash-loop breaker" as deferred | **No** — the ADR 0087 sandbox that would contain it is default OFF, and no test drives a hard abort on the split path | **P0** |
| `W25:S3.4` / `W25:S2.7` and `harness/config/coverage.py:17` assert an **AE NAK** for a post-ACK Handler raise | Under ACK-on-receipt the AA fires at the ingress commit (`wiring_runner.py:3726-3745`) before the Router or Handler runs; a Handler raise **cannot** NAK | A human running `W25:S3.4` either fails a correct system or records a NAK that never happened. `harness/scenarios.py:63` already expects only disposition `error`, so the docs contradict both the code and the harness they instruct the tester to run — on the single most partner-visible behaviour change in ADR 0001 | **No** — the docs *are* the detector, and they are wrong | **P0** |
| No live end-to-end committed-transactions-per-message ceiling in CI | An accidental extra handoff commit doubles `committed_txns/msg` | Passes every test; surfaces only as a production capacity shortfall. ADR 0051 sizes capacity on `3 + 2H + 2N`; the counters already exist (`store/base.py:220-234`, surfaced at `api/app.py:4142-4143`) | Partly — `test_txn_per_message_cost_model.py` pins the **model** over a recording connection, not the **live** counter through a real runner | P1 |
| A refactor hoists the lookup-runner `ExitStack` to wrap `route_only` | Routers silently gain live `db_lookup` access; the at-least-once re-run invariant breaks and an unbudgeted live DB read lands on the routing hot path for every message | Non-pure Routers ⇒ duplicate/divergent downstream side effects on every crash re-run | **No** for `db_lookup` — the FHIR twin exists (`test_fhir_lookup.py:545`); the db_lookup side has only "no active runner" (`test_db_lookup.py:104`) and "dry-run raises" (`:310`). The guarantee is *positional* (`wiring_runner.py:5027-5031`), not structural | P1 |
| `delivered_keys` carries no "hashes + ids only, never a body or PHI" assertion | A widened `delivery_key` or an added column carrying a body fragment or MRN lands PHI **unencrypted at rest** — the ledger is deliberately outside the `_cipher` seam (`store/store.py:1356-1357`) | Unencrypted PHI at rest, exactly the class `FCP:STORE-19`/`FCP:STORE-20`'s redaction bar exists to prevent | **No** — the schema comment claims it; nothing tests it | P1 |
| Live single-box N-active **engine-shard** certification runs nowhere | `test_shard_cert_sqlserver.py` (2) and `harness/load/shardcert.py` are in no workflow; `test_shardcert_{two_box,multiproc,ladder_two_box}.py` do run but their own docstrings say every network collaborator is faked | A cross-engine-shard head-steal or a mis-owned outbound lane shows as duplicate or stranded PHI deliveries only in production, on the declared scaling axis | Partly (wiring + in-process lane arithmetic only) | P1 |
| Bulk dead-letter replay under concurrent intake is unsoaked | `replay_dead` re-pends rows into lanes a delivery worker is actively draining | A replayed message could land ahead of live traffic on the same destination — an A08 update before its A01. Clinically wrong ordering | **No** — `tests/test_api.py:309-353` covers the route and its filters, nothing drives replay under load (`FCP:STORE-16`'s own note) | P2 |
| `[transform] inline=True` and `group_commit_window_ms > 0` remain plain operator-settable knobs against explicit DO-NOT-ENABLE rulings | Inline changes the disposition path (`store/base.py:306-311` warns `handoff` must never be called with empty deliveries or the message is **non-terminal forever**); group-commit moves the ACK durability boundary | Operator-induced reliability regression with no warning, no `check` finding, no runtime guard rail | Partly — `test_crit2_inline_doc_drift.py` pins the *default*, nothing warns on an explicit flip; group-commit has none | P2 |
| `per_lane` claim mode rots | The documented byte-identical escape hatch (`docs/CONNECTIONS.md:1605`) fails exactly when someone reaches for it during a pooled incident | An operator loses the fallback mid-incident | **No** — the default `pytest -q` suite runs everything under pooled (`wiring_runner.py:632`); `per_lane` has a construction sentinel but no end-to-end parity run | P2 |
| FIFO covering index / recovery predicate silently unadopted by the planner | A per-lane FIFO claim degrades to a scan | Correctness holds, so no test fails; the symptom is a throughput cliff only the off-repo bench rigs see, after a release | **No** — `test_fifo_index_migration.py` (6) proves the rename-based migration ran, not planner adoption (`FCP:STORE-9`/`FCP:STORE-13` residual) | P2 |
| ADRs 0055/0058/0059/0060/0061/0114 statuses disagree with shipped code; `FEATURE-MAP.md` §4 omits ~12 shipped mechanisms and lists only 6 dispositions | A reviewer reading "Proposed" on seq-only FIFO concludes the ordering key is still `created_at` — precisely the mental model that produces an ordering regression | Wrong design-of-record; a future test author sizes pipeline risk off a stale map | **No** — `tests/test_feature_map_claims.py` guards only ASVS score tuples and private/superseded links | P2 |
| `pipeline/supervisor.py:7,:14,:23` documents one SQLite db file per **engine shard** and calls a shared single-db mode deferred | Contradicts ADR 0063 and the module's own `require_unified_store` call at `:154` | An operator provisions split stores, hits a confusing hard refusal at startup, or reasons about recovery/FIFO under the wrong store topology — blurring exactly the *engine shard* vs *database shard* distinction | **No** | P2 |

---

### 1.4 Test matrix

The matrix enumerates **work this chapter commissions or schedules** — new tests, new CI legs, doc
errata with a tripwire, and the manual/host rows this area needs signed off. Coverage listed in §1.2
is regression that already runs; it is not repeated here.

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion;
**only T rows count toward the release gate**. **C** = *Characterisation* — produces a recorded
measurement, finding or dated decision with no threshold yet; legitimate work, but it **cannot
fail**, so it never gates a release (it becomes a T row the day its threshold is recorded).
**A** = *Assurance* — an external engagement; blocking only for an off-loopback / production-exposure
release, advisory otherwise, and excluded from the ordinary P0 count.

This chapter has **59 rows: 53 T, 6 C (PIPE-38, 46, 54, 55, 56, 57), 0 A.** Of the T rows,
**13 are P0** (PIPE-01, 02, 03, 04, 05, 06, 08, 09, 11, 14, 35, 39, 48) — two of those (PIPE-35,
PIPE-39) are **pointer rows** whose work is owned by another chapter (SEC-01, PERF-10) and are
discharged by that chapter's evidence, not by separate work here.

**Pointer rows.** Where a deliverable is duplicated across chapters, the owner keeps the full row and
this chapter carries a one-line pointer (Method `—`, Cls `T`, Pri matching the owner). This chapter
points at **SEC-01** (PIPE-35, P0 to match) and **PERF-10** (PIPE-39, P0 to match), and at the
consolidated **MIG FEATURE-MAP drift-guard row** (PIPE-36, PIPE-37) — those two keep this chapter's
own P1/P2 assessment until the consolidated MIG row's priority is fixed. Conversely this chapter
**owns** engine-shard *recovery correctness* (PIPE-01 / PIPE-14) — PERF-07 / PERF-09 point here for
it, and the engine-shard **cert ladder** deliberately does not live here (PERF-10). A pointer row is
discharged by the owner's evidence; it scopes no work in this chapter and adds no effort to §1.6.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| PIPE-01 | Wire the six never-executed server-DB pipeline suites into CI | Cross-backend | CI-leg | container-CI | x2 | T | P0 | **Owner row for engine-shard *recovery correctness* — PERF-07 / PERF-09 point here and scope no separate work.** `ci.yml`'s sqlserver-store step additionally runs `test_adr0075_batch_sqlserver.py` (11), `test_shard_recovery_sqlserver.py` (4), `test_adr0114_claim_proc_live.py` (6), `test_sqlserver_sync_handoff.py` (9), `test_shard_cert_sqlserver.py` (2); the postgres-store step additionally runs `test_shard_recovery_postgres.py` (4). Leg log shows **36 passed, 0 skipped** for the added files |
| PIPE-02 | Meta-test: every `MEFOR_TEST_{SQLSERVER,POSTGRES}`-gated test file is named by ≥1 workflow step | Functional | pytest | dev-PC | n/a | T | P0 | New `tests/test_serverdb_ci_coverage.py` scans `tests/*.py` for the skipif marker and `.github/workflows/*.yml` for the filename; it **fails today** naming all six files and **passes** after PIPE-01. A newly-added gated file with no workflow mention fails the build |
| PIPE-03 | The `serverdb` path-gate alternation admits every file the SS/PG steps run | Functional | pytest | dev-PC | n/a | T | P0 | Same meta-test asserts each filename run by an SS/PG step matches the `tests/test_(...)` alternation in the `serverdb` change-detection regex at `ci.yml:434` (whose own comment at `:424-428` requires exactly this); today `adr0075_batch_sqlserver`, `shard_recovery_*`, `adr0114_claim_proc_live`, `sqlserver_sync_handoff`, `shard_cert_sqlserver` do not match |
| PIPE-04 | MLLP Handler raise ⇒ exactly one `AA` frame and zero NAK frames | Negative/Security | pytest | dev-PC | SQLite | T | P0 | New case in `tests/test_staged_pipeline.py`: with a Handler that raises, the captured wire frames contain exactly 1 ACK, its MSA-1 == `AA`; the message reaches disposition `ERROR`; **no** `AE`/`AR` frame is ever written. (SS/PG twins already exist at `test_sqlserver_store.py:2924`, `test_postgres_store.py:2839`) |
| PIPE-05 | WIN2025-TEST-PLAN errata: post-ACK failures do not NAK | Compat | manual | dev-PC | n/a | T | P0 | Lines ~`:478`, `:486`, `:528`, `:561`, `:1245` no longer assert `AE/AR` for ADT^A03. `W25:S3.4` PASS reads "`AA` at receipt, then disposition `error`, **no NAK**"; `W25:S2.7`'s *malformed / wrong-version* case keeps its `AR`/`AE` (pre-ACK) and is textually separated from the A03 case; the `W25:S3.4` row's "ties S2.7" note distinguishes the two |
| PIPE-06 | `harness/config/coverage.py` disposition-table errata + doc-drift tripwire | Compat | pytest | dev-PC | n/a | T | P0 | The A03 row of the module docstring reads `ERROR (AA already sent; no NAK)`; the strict-inbound row keeps `ERROR (AE NAK)`. A new tripwire in `tests/test_crit2_inline_doc_drift.py` (or a sibling) fails if the string `AE NAK` reappears on the A03 row |
| PIPE-07 | The five pre-ACK failure classes still NAK synchronously and write **zero** ingress rows | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Parametrized over decode-error, embedded NUL, unparseable body, strict-validate failure, streaming-detach failure: exactly one NAK with the code the source specifies (`AR`/`AR`/`AR`/`AE`/`AE`, `wiring_runner.py:3497/3523/3660/3699`), one `ERROR` message row, `pending_depth(stage='ingress') == (0, None)`, listener still accepting a healthy message afterwards |
| PIPE-08 | Hard-abort inside off-loop `route_only` on the **default split** ingress lane is bounded | HA/Resilience | pytest | dev-PC | SQLite | T | P0 | New `tests/test_split_path_poison_bound.py`: seed one ingress row; run the engine in a child process whose route step calls `os.abort()`; restart `max_attempts + 1` times. Terminal state is **either** the row `DEAD` with a recorded error **or** the lane `STOPPED` with a `connection_stopped` alert; `attempts` strictly increases per pass; a second, healthy message seeded behind it reaches `PROCESSED` after the bound trips |
| PIPE-09 | Same hard-abort bound on the **routed** (transform) lane | HA/Resilience | pytest | dev-PC | SQLite | T | P0 | Same file, `Stage.ROUTED` head: bounded within `max_attempts` restarts; sibling routed rows for the same message are unaffected and their message never finalizes prematurely |
| PIPE-10 | Supervisor crash-loop breaker | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | `messagefoundry supervise` with a child that exits immediately: after K restarts inside a window the supervisor stops relaunching, logs at ERROR, and emits an alert; it does **not** spin. Closes the "restart backoff / crash-loop breaker" deferral at `pipeline/supervisor.py:22` |
| PIPE-11 | ADR 0075 statement batching ON vs OFF produces identical rows and dispositions on live SQL Server | Cross-backend | pytest | container-CI | x2 (SS) | T | P0 | Within `test_adr0075_batch_sqlserver.py` (once PIPE-01 runs it): for H=2, N=3, the ingress/routed/outbound row sets, `handler_name` values, `not_deployed` events and final disposition are byte-equal between `batch_handoff_statements=True` (default) and `False`; `committed_txns` per message is identical in both arms |
| PIPE-12 | Live end-to-end `committed_txns` / `body_copies` per-message ceiling | Performance | pytest | dev-PC | SQLite + x2 | T | P1 | New module (or an extension of `tests/test_txn_per_message_cost_model.py`) drives H×N through a **real** store handle behind a `RegistryRunner` and asserts `store.committed_txns / messages == 3 + 2H + 2N` and `body_copies / messages == 2 + H + N` for (H,N) ∈ {(1,1),(2,1),(1,3),(2,3)}. Postgres asserted at 0 (documented un-wired) rather than skipped silently |
| PIPE-13 | `per_lane` opt-out end-to-end parity arm | HA/Resilience | CI-leg | container-CI | SQLite | T | P2 | A nightly matrix arm sets `MEFOR_PIPELINE_CLAIM_MODE=per_lane` and runs `test_wiring_engine`, `test_staged_pipeline`, `test_seq_only_fifo`, `test_reingress`, `test_not_deployed`; the pass set is identical to the pooled arm (same test ids, zero failures, zero new skips) |
| PIPE-14 | Ownership-scoped recovery never re-pends a **live sibling engine shard's** in-flight rows — real server DBs | HA/Resilience | pytest | container-CI | x2 | T | P0 | **Owner row for engine-shard *recovery correctness* (with PIPE-01) — PERF-07 / PERF-09 point here.** `test_shard_recovery_{sqlserver,postgres}.py` execute in CI (PIPE-01): engine shard A restarts while engine shard B holds in-flight rows; after A's `reset_stale_inflight(owned=…)`, B's rows are still `inflight` with their lease intact, A's rows are `pending`, and the full fan-out drains exactly-once with `lane_inversions == 0`. The *cert ladder* half (`test_shard_cert_sqlserver.py`, single-delivery-consumer-per-lane, sizing) is **not** here — **PERF-10** owns it and PIPE-39 points at it |
| PIPE-15 | `require_unified_store` refusal on the `supervise` path + docstring correction | Negative/Security | pytest | dev-PC | SQLite | T | P2 | `messagefoundry supervise` on a config declaring 2 engine-shard ids with a SQLite backend exits non-zero with a message naming the unified-store requirement (ADR 0063); a doc tripwire asserts `pipeline/supervisor.py`'s docstring no longer claims `<stem>_<id>.db` per **engine shard** nor calls a shared single-db mode "deferred" |
| PIPE-16 | `NOT_DEPLOYED` is reachable end-to-end through the runner on all three backends | Functional | pytest | container-CI | x3 | T | P2 | An all-declined message finalizes `NOT_DEPLOYED` (not `FILTERED`) driven through a real `RegistryRunner` on SQLite plus the existing SS/PG store-suite cases; `/messages` and `/stats` report the seventh disposition |
| PIPE-17 | Finalizer is never premature with a pending `Stage.RESPONSE` row on server DBs | HA/Resilience | pytest | container-CI | x2 | T | P2 | Origin message with one delivered outbound row and one outstanding response work-row stays non-terminal; it finalizes only after `ingress_handoff` consumes the work-row. (SQLite half exists in `test_reingress.py`) |
| PIPE-18 | Bulk `replay_dead` under sustained concurrent intake preserves per-lane order | HA/Resilience | pytest | dev-PC | SQLite | T | P2 | Seed N dead rows on one outbound lane; start sustained intake into the same lane; call `replay_dead(destination_name=…)`; on drain, `lane_inversions == 0` measured on delivery seq, every message terminal **exactly once**, and no replayed row is delivered ahead of a live row enqueued before it |
| PIPE-19 | `replay_dead` two-person approval gate holds under the same load | Negative/Security | pytest | dev-PC | SQLite | T | P2 | With `[approvals].enabled`, `POST /dead-letters/replay` returns 202 + a pending id and re-pends **zero** rows until a second approver releases it; the audit record names both principals |
| PIPE-20 | `delivered_keys` contains no body substring and no PID field value | PHI | pytest | container-CI | x3 | T | P1 | Drive a delivery with a synthetic PHI-bearing body (generated, never real); assert every column value of every `delivered_keys` row contains no substring ≥8 chars of the body and none of the PID-3/PID-5/PID-7 values; assert the column set is exactly `(delivery_key, outbox_id, message_id, destination_name, delivery_seq, delivered_at)` so a widened schema fails |
| PIPE-21 | `resend_log` carries the same ids-only bar | PHI | pytest | dev-PC | SQLite | T | P2 | Same assertion shape against `resend_log` (also deliberately outside the `_cipher` seam, `store/store.py:1370-1380`) |
| PIPE-22 | A Router calling `db_lookup` raises and dead-letters | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Mirror `test_fhir_lookup.py:545` in `tests/test_db_lookup.py`: with a `DatabaseLookup` declared (so the executor exists), a `@router` calling `db_lookup` drives `_process_ingress_item` to a `DbLookupError` ⇒ dead-letter under `CONTINUE`; the message never routes. Fails if the lookup `ExitStack` is ever hoisted to wrap `route_only` |
| PIPE-23 | Both carve-outs remain unavailable in dry-run and in the sandbox | Negative/Security | pytest | dev-PC | n/a | T | P2 | `dryrun` and `dryrun --trace json` both raise for `db_lookup` and `fhir_lookup`; with `[sandbox].mode="subprocess"` both fail closed with `SandboxError` matching "db_lookup/fhir_lookup is forbidden" |
| PIPE-24 | `fhir_lookup` is GET-only and egress-gated at the connector boundary | Negative/Security | pytest | dev-PC | n/a | T | P2 | A non-GET verb and a host outside `[egress].allowed_http` are both refused before any socket is opened; the error text is PHI-free (already partly covered by `test_fhir_lookup.py` — extend, do not duplicate) |
| PIPE-25 | Runtime replay-equality probe over the shipped sample + harness configs | Functional | acceptance-probe | dev-PC | SQLite | T | P2 | A new opt-in `check --replay-equality` re-runs every `@router`/`@handler` in `--config` twice over a synthetic corpus and diffs `RouteOutcome` (reusing `assert_replay_stable` from `tests/test_replay_purity.py`); exit 0 for `samples/config` and `harness/config`, exit non-zero with the offending symbol named for a deliberately-impure fixture |
| PIPE-26 | Widen the `impure-transform` AST rule to file/socket writes inside decorated bodies | Negative/Security | pytest | dev-PC | n/a | T | P2 | `messagefoundry check --json` reports `impure-transform` for `open(..., "w")`, `Path.write_*`, `socket`, and `requests`/`httpx` calls inside a `@router`/`@handler` body; a clean estate reports none; `--strict-handler-security` makes it blocking |
| PIPE-27 | `inline=True` raises an advisory `check` finding citing ADR 0107 | Negative/Security | pytest | dev-PC | n/a | T | P2 | `messagefoundry check --json` on a config with an inbound declaring `inline=True` emits a finding naming ADR 0107 and the DO-NOT-PROMOTE ruling; a config without it emits none. (Owner may instead choose a hard wiring refusal — see open question 4) |
| PIPE-28 | `group_commit_window_ms > 0` raises an advisory `check` finding citing ADR 0055 | Negative/Security | pytest | dev-PC | n/a | T | P2 | Same shape against the service setting; the finding names ADR 0055's withdrawal and the ACK-durability-boundary consequence |
| PIPE-29 | `handoff` is never reachable with empty deliveries | Negative/Security | pytest | dev-PC | SQLite | T | P1 | A filtering Handler on an `inline=True` inbound provably takes the split path (guardrail G2); a direct `handoff(deliveries=())` call is refused or asserted against, so the "non-terminal forever" hazard at `store/base.py:306-311` cannot be reached from config |
| PIPE-30 | SQLite `EXPLAIN QUERY PLAN` proves the seq-trailing FIFO covering index is seeked | Performance | pytest | dev-PC | SQLite | T | P2 | The plan for the per-lane FIFO claim shows `SEARCH … USING INDEX <fifo index>` and contains no `SCAN`; the plan for `reset_stale_inflight`'s `(status, stage)` predicate likewise seeks |
| PIPE-31 | SQL Server / Postgres planner adoption of the same two predicates | Performance | pytest | container-CI | x2 | T | P2 | Gated legs assert an index seek (SS showplan / PG `EXPLAIN`) for the claim and the recovery predicate; a seq scan fails the test with the plan text attached |
| PIPE-32 | Traced dry-run installs its tracer on the thread that actually runs `transform_one` | Functional | pytest | dev-PC | n/a | T | P2 | The trace records frames whose `thread_ident` equals the off-loop worker's, not the loop thread's; the previous tracer is restored on that thread afterwards. Closes `FCP:PIPE-7` |
| PIPE-33 | Sandbox forbidden-import deny list is exercised beyond `socket` | Negative/Security | pytest | dev-PC | n/a | T | P2 | Parametrized over `ssl`, `messagefoundry.store`, `messagefoundry.transports`, `messagefoundry.api`, and the crypto module: each raises `SandboxError` naming the module, the worker survives, and a pre-cached module is purged so the guard re-triggers. Closes `FCP:PIPE-12` |
| PIPE-34 | POSIX `RLIMIT_AS` / `RLIMIT_CPU` backstop fires | Negative/Security | pytest | dev-PC | n/a | T | P2 | On Linux, a Handler allocating past `[sandbox].mem_mb` or burning past `cpu_seconds` is reaped by the child's own rlimit (`_sandbox_worker.py:58-73`) before the parent's `wall_seconds`; `skipif` on Windows with a recorded reason |
| PIPE-35 | **Pointer.** ADR-status-vs-code hygiene guard (a `Proposed` ADR may not have its declared module shipped; today 0058, 0059, 0060, 0061 and 0114 would flag, with a reasoned exemption register for design-only records such as 0051 / 0107) | Compat | — | dev-PC | n/a | T | P0 | Covered by SEC-01; no separate work scoped. The pipeline-ADR cases above are supplied to SEC-01's exemption register as input, not built here |
| PIPE-36 | **Pointer.** `FEATURE-MAP.md` §4 disposition parity — every `MessageStatus` member appears in §4's disposition line (today `NOT_DEPLOYED`, `store/store.py:319`, does not; `FEATURE-MAP.md:80` lists six) | Compat | — | dev-PC | n/a | T | P1 | Covered by the consolidated MIG FEATURE-MAP drift-guard row (MIG-28 and its consolidation); no separate work scoped. This chapter supplies the seven-member `MessageStatus` set as the assertion's input |
| PIPE-37 | **Pointer.** `FEATURE-MAP.md` §4 mechanism coverage — §4 names every Accepted-and-built ADR in {0001, 0013, 0031, 0038, 0057, 0058, 0059, 0060, 0061, 0064, 0066, 0070, 0071, 0073, 0075, 0082, 0104, 0111}; ~12 shipped mechanisms are absent today, including the **shipped default** pooled claim mode | Compat | — | dev-PC | n/a | T | P2 | Covered by the consolidated MIG FEATURE-MAP drift-guard row (MIG-28 and its consolidation); no separate work scoped. Whether the mechanism half can be blocking at all still turns on open question 8 |
| PIPE-38 | Reconcile the five stale coverage-plan rows | Compat | manual | dev-PC | n/a | C | P2 | **Characterisation — an editorial re-grade of another document's rows, with no pass/fail of its own.** `FCP:STORE-4`, `FCP:STORE-7`, `FCP:STORE-10`, `FCP:PIPE-9` and `FCP:PIPE-14` are re-graded in `docs/testing/FEATURE-COVERAGE-PLAN.md` against the evidence in §1.2, and the `FCP:STORE-3`/`FCP:STORE-4` `test_consistency` mis-citation is corrected; the plan remains the per-feature owner. Outcome is a dated set of re-graded rows — **records a decision, cannot fail, does not gate the release**. It becomes a T row only if the re-grade is later pinned by a drift test |
| PIPE-39 | **Pointer.** Live single-box N-active **engine-shard** cert ladder — `tests/test_shard_cert_sqlserver.py` (2) named by a CI step and collected>0, one delivery consumer per outbound lane across engine shards, sizing reported not gated | HA/Resilience | — | container-CI | x2 (SS) | T | P0 | Covered by PERF-10; no separate work scoped. The cert ladder is a performance/certification concern, so PERF owns it; this chapter keeps only engine-shard *recovery correctness* (PIPE-01 / PIPE-14). The workflow edit that names the file is the same one PIPE-01 makes |
| PIPE-40 | Multi-process N-active engine-shard fleet on a real server DB | HA/Resilience | external | cloud | x2 | T | P1 | On the AWS two-box rig: 4 `serve --shard` processes over ONE unified store, sustained synthetic load; correlation sink reconciles **zero** lost messages, per-lane FIFO inversions == 0, no cross-engine-shard head-steal (each outbound lane has exactly one consumer), and the sizing number recorded against ADR 0073's ~450-500 msg/s target |
| PIPE-41 | ADR 0114 sub-lever live legs execute (all still default OFF) | Cross-backend | pytest | container-CI | x2 (SS) | T | P1 | `test_adr0114_claim_proc_live.py` (6) runs in CI (PIPE-01) and passes with the procs installed; the flags stay `False` in `settings.py` and the AC-6 sentinel still proves non-SQL-Server backends never reference them |
| PIPE-42 | `test_sqlserver_sync_handoff.py` executes | Cross-backend | pytest | container-CI | x2 (SS) | T | P1 | Its 9 tests run and pass in the sqlserver-store leg (PIPE-01); they gate the ADR 0071 sync-handoff pool that `fuse_thread_hops` rides, which remains default OFF (NO-GO promote gate) |
| PIPE-43 | `fuse_thread_hops` stays OFF and is a provable no-op off SQL Server | Functional | pytest | dev-PC | n/a | T | P2 | `settings.pipeline.fuse_thread_hops is False` by default; on SQLite and Postgres the flag set True logs "ignored" and the dispatch path is byte-identical (extend `tests/test_adr0071_dispatch_wiring.py`) |
| PIPE-44 | Batch claim at `fifo_claim_batch > 1` preserves order under a crash mid-batch on live server DBs | HA/Resilience | pytest | container-CI | x2 | T | P2 | Already run by the throughput-lever legs for the primitives; add the runner-level case — kill the worker after row 2 of a 8-row prefix; the surviving `inflight` tail is recovered **in order** by `reset_stale_inflight`, no row is skipped, no `attempts` inflation on untouched rows |
| PIPE-45 | Stage-aware queue-buildup / stall alerts fire per stage under a wedged lane | Functional | pytest | dev-PC | SQLite | T | P2 | With the ingress lane STOPPED, `queue_buildup` names `stage='ingress'` and the lane; `/stats` `in_pipeline` (`api/app.py:4134`) is non-zero and does **not** read as drained |
| PIPE-46 | Operator-visible stall is legible in the web console | Usability | browser | browser-matrix | SQLite | C | P2 | With a router lane STOPPED by the `STOP` internal-error policy, `/ui` Live shows the message non-terminal, Dead Letters is empty, the connection event log shows `connection_stopped`, and the queue-depth gauge is rising — a human reads it as **stalled**, not drained |
| PIPE-47 | Startup fault isolation under the real service identity | HA/Resilience | manual | W2025-box | x3 | T | P2 | Covered structurally by `test_startup_fault_isolation.py`; on-box the only new signal is that an inbound failing to bind under the NSSM service account degrades (status `degraded` on `/connections`) rather than killing the service. Run once per backend during the WIN2025 pass; **do not** re-run the seven CI cases |
| PIPE-48 | NSSM hard-kill crash recovery with pending outbound rows | HA/Resilience | manual | W2025-box | x3 | T | P0 | **Owned by `W25:S2.5`** (`docs/testing/WIN2025-TEST-PLAN.md`) — cited, not re-specified. Recorded here as a release gate for this area: kill the engine PID with pending outbound rows, restart the service, confirm drain with no loss and no manual replay. `verify`'s `smoke.live` cannot self-check this (WIN2025 `:200`/`:335`) |
| PIPE-49 | Dead-letter → bulk replay with the destination DOWN vs UP-but-NAKing | HA/Resilience | manual | W2025-box | SQLite | T | P1 | **Owned by `W25:S3.5`** — the two cases must be labelled separately; the headless `--scenario dead_letter` gate is only valid with **nothing** listening on 2576 |
| PIPE-50 | Independent outbound draining under GUI fault injection | HA/Resilience | harness | W2025-box | SQLite | T | P1 | **Owned by `W25:S3.6`** — harness Receive tab set to fail/close so the MLLP echo dead-letters while the file archive succeeds for the same A01 fan-out |
| PIPE-51 | Headless disposition walk against the corrected expectations | Functional | harness | dev-PC | x3 | T | P1 | `python -m harness --scenario {processed,filtered,unrouted,error,dead_letter} --engine http://127.0.0.1:8765 --token <T>` each exit 0 against `harness/config`; the `error` run is recorded as **AA-then-ERROR**, not AE NAK (PIPE-05/06) |
| PIPE-52 | Load-smoke zero-loss + drain-to-zero stays green after the PIPE-01/PIPE-08 changes | Performance | load-harness | container-CI | SQLite + x2 (SS) | T | P1 | `ci.yml:878-956` and its SQL Server twin remain green: zero message loss from the correlation sink, all SLOs met, exit 0; `lane_inversions == 0` |
| PIPE-53 | Failover-LOAD legs stay green under the pooled default | HA/Resilience | load-harness | container-CI | x2 | T | P1 | `test_load_failover_{sqlserver,postgres}` continue to gate: promotion, no acknowledged loss, drained pipeline, `lane_inversions == 0` with `lanes_observed >= 2`, single live leader, bounded dup rate |
| PIPE-54 | Real-partner MLLP resend-timeout characterization (CONNECTIONS.md caveat (a)) | Compat | manual | AD-lab | n/a | C | P2 | Measure ACK latency at target load against a partner's resend window; record the margin. There is **no inbound de-duplication**, so a partner resend ingests as a fresh message — document the measured headroom, do not claim exactly-once |
| PIPE-55 | `pyodbc` native-crash retry does not mask a pipeline regression | Compat | manual | container-CI | x2 (SS) | C | P2 | `scripts/ci/retry-native-crash.sh` masks only exit 139/134. A human reviews any leg that retried: a repeated crash on the same test id is escalated as a real finding, not absorbed (upstream `pyodbc#1459`) |
| PIPE-56 | ADR 0101 pre-registered falsifier for any ADR 0114 default flip | Performance | external | cloud | x2 (SS) | C | P2 | Before any sub-lever default flips: decision rule fixed in writing before the run, manipulation check on `committed_txns`, a same-session OFF control, stated null and regression bands, human adjudication recorded. No flip without a passed, archived gate |
| PIPE-57 | Mutation-score the finalizer and the runner's stage-handoff paths | Functional | CI-leg | container-CI | SQLite | C | P2 | Once `docs/quality-gates/HANDOFF-mutation-coverage.md` gate #6 is built, its **first** target is `pipeline/wiring_runner.py` (`_process_ingress_item`, `_apply_*_internal_error`) and `store/store.py`'s `_maybe_finalize_sync`; report a surviving-mutant list advisory-only in the first release |
| PIPE-58 | Purge/retention never strands a non-terminal message | Functional | pytest | dev-PC | SQLite | T | P2 | A retention purge running while a message has one delivered and one in-flight routed row leaves the message non-terminal and the finalizer still able to resolve it (or dead-letters it explicitly) — never a silently orphaned row |
| PIPE-59 | **Memory exhaustion (OOM kill) mid-drain of a lane** — a distinct recovery path from `os.abort()` | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | `os.abort()` (PIPE-08/09) still unwinds the C runtime; an OOM kill is an **uncatchable** SIGKILL / Windows job-object commit-limit termination with no flush and a possibly torn WAL frame, so it exercises a different recovery path and must be injected separately. In `tests/test_split_path_poison_bound.py`: run the engine child under a hard memory cap (Linux cgroup v2 `memory.max` or `RLIMIT_AS`; Windows job object `JOB_OBJECT_LIMIT_PROCESS_MEMORY`) and have a Handler allocate past it while an outbound lane is mid-drain with in-flight rows. On restart: `reset_stale_inflight` re-pends **exactly** the killed process's in-flight rows and no sibling's; no `delivered_keys` duplicate for a delivery committed before the kill; no queue row skipped; `attempts` increments exactly once per pass and the PIPE-08 bound trips on the same schedule (an OOM kill is counted like an abort, not free); the recorded exit signature is the OOM one (137 / `0xC0000017`-class). If the platform cannot enforce a hard cap the case **`skipif`s with a recorded reason** — it must never pass vacuously |

---

### 1.5 Detailed scenarios

#### S-PIPE-A — PIPE-08 / PIPE-09: bound the split-path poison crash

**Why narrative:** this is a *hard abort*, not an exception. It cannot be simulated with
`raise` — the whole point is that no Python handler runs. It is also semantically load-bearing:
dead-lettering here means dead-lettering a message that was **never successfully processed**, which
needs an owner ruling (open question 3) before the assertion is written one way or the other.

**Preconditions**

- Clean SQLite store in the scratch dir (never the user's `messagefoundry.db`).
- `[pipeline].claim_mode` left unset (pooled default) — this is the *default* path being tested.
- `[transform] inline` left `False` on every inbound (the ADR 0057 G6 ceiling must **not** be the
  thing under test).
- A `[delivery]` retry policy with a **finite** `max_attempts` (e.g. 5).
- Synthetic corpus only: `python -m messagefoundry generate --code ADT --trigger A01 --count 3`
  written to the scratch dir. Never redirect generate/dryrun output into the repo.

**Steps**

1. Author a fixture config in the scratch dir with one MLLP inbound, one Router, one Handler, one
   `simulate`/file outbound. The Handler reads a control file; when it contains `abort`, it calls
   `os.abort()`.
2. Start the engine as a **child process** (`python -m messagefoundry serve --config <scratch>/cfg
   --db <scratch>/pipe08.db --env dev`). Wait for the inbound to bind.
3. Send one synthetic ADT^A01 over MLLP. Assert the sender receives **AA** (ACK-on-receipt) before
   the crash.
4. The child aborts. Record its exit code (SIGABRT / 0xC0000409-class on Windows).
5. Relaunch the child. Repeat steps 3-4 until `max_attempts + 1` passes have occurred.
6. Seed a **second**, healthy synthetic message behind the poison row before the final relaunch.

**Observation point**

`sqlite3 <scratch>/pipe08.db` (read-only) — the `queue` row for the poison message: `status`,
`attempts`, `stage`; the `messages` row disposition; the alert sink capture for
`connection_stopped`; and the second message's disposition.

**Expected result**

Exactly one of the two authorized terminal shapes, per the owner ruling:

- **(a) bounded dead-letter** — poison row `status='dead'`, message disposition `ERROR`,
  `attempts == max_attempts`, and the second message reaches `PROCESSED`; **or**
- **(b) bounded STOP** — lane STOPPED with a `connection_stopped` alert, poison row still
  `pending`, and the operator is told; the second message stays queued (head-of-line blocking is
  *intentional* in this shape and must be visible in `/stats` `in_pipeline`).

What must **not** happen: unbounded restart with monotonically-growing `attempts` and no alert —
today's behaviour.

**Cleanup / rollback**

Kill any surviving child; delete the scratch db + WAL/SHM; remove the control file. Nothing is
written under the repo. Repeat with `Stage.ROUTED` as the abort point for PIPE-09.

---

#### S-PIPE-B — PIPE-01/02/03: land the six never-executed suites without a false green

**Why narrative:** appending filenames to a workflow step is trivial; proving they actually *ran*
(rather than self-skipped) is the whole value, and a wrong `serverdb` path-gate silently re-hides
them on PRs.

**Preconditions**

- A branch off `main`; owner approval before any push (outward-facing).
- SQL Server 2025 + Postgres service containers available on the hosted runner (already configured
  at `ci.yml:549-569` / `:771-785`).

**Steps**

1. Append to the sqlserver-store leg's throughput-lever step (`ci.yml:690`):
   `tests/test_adr0075_batch_sqlserver.py`, `tests/test_shard_recovery_sqlserver.py`,
   `tests/test_adr0114_claim_proc_live.py`, `tests/test_sqlserver_sync_handoff.py`,
   `tests/test_shard_cert_sqlserver.py`. Keep the `scripts/ci/retry-native-crash.sh` wrapper.
2. Append `tests/test_shard_recovery_postgres.py` to the Postgres throughput-lever step
   (`ci.yml:820`).
3. Extend the `serverdb` path-gate alternation at `ci.yml:434` with
   `adr0075_batch|adr0114_claim|shard_recovery|shard_cert|sqlserver_sync_handoff`.
4. Add `tests/test_serverdb_ci_coverage.py` (PIPE-02/PIPE-03). Run it locally first and confirm it
   **fails** before the workflow edit and **passes** after — a meta-test that cannot fail is worthless.
5. Trigger the legs on the branch: `gh workflow run ci.yml --ref <branch>`.

**Observation point**

The leg logs. Grep each added filename for `passed` and assert `0 skipped` for it — a
`MEFOR_TEST_*` misconfiguration shows as a **skip**, which is exactly the false green this row exists
to kill.

**Expected result**

36 additional tests execute and pass; the meta-test is green; a deliberately-removed filename makes
the meta-test fail with that filename in the message.

**Cleanup / rollback**

If a newly-executed suite fails, do **not** re-remove it from the leg — that recreates the gap. File
the failure and, if it must be temporarily quarantined, mark it `xfail(strict=True)` with an issue
link so the meta-test still sees the file named.

---

#### S-PIPE-C — PIPE-05 / PIPE-06 / PIPE-51: the AE-NAK errata

**Why narrative:** it spans three artifacts (a frozen-ish campaign plan, a harness config docstring,
and a scenario run) and the *correct* half must survive — the strict-inbound and malformed cases
genuinely do NAK.

**Preconditions**

- Confirm the code fact first, do not take it on trust:
  `messagefoundry/pipeline/wiring_runner.py:3717-3745` (AA after `enqueue_ingress`) and
  `:3660-3681` (AE for a strict-validate failure, **before** any ingress row).
- Engine serving `harness/config` on 2575 / 2577.

**Steps**

1. Send a synthetic ADT^A03 to **2575** (tolerant inbound, Handler raises). Capture the wire frames.
2. Send a wrong-version message to **2577** (`IB_Coverage_Strict`). Capture the wire frames.
3. Edit `docs/testing/WIN2025-TEST-PLAN.md` rows `W25:S2.7` step 1 and `W25:S3.4` (both the table row and the
   Appendix index row at `:1245`), and the scenario-facts bullet at `:528` so the A03 case reads
   *"AA at receipt, then disposition `error`, no NAK"* and the malformed/wrong-version case keeps its
   `AR`/`AE`.
4. Edit `harness/config/coverage.py`'s docstring table: the `ADT^A03` row loses `(AE NAK)`; the
   *"anything malformed / wrong ver."* row keeps it.
5. Add the doc-drift tripwire (PIPE-06) and the wire-frame assertion (PIPE-04).

**Observation point**

Step 1's capture must contain exactly one frame with `MSA|AA`. Step 2's must contain exactly one
frame with `MSA|AE`. If step 1 shows an AE, stop — the code has changed and this chapter's premise
needs re-grounding.

**Expected result**

Both captures as above; both docs corrected; both tripwires green; `--scenario error` still exits 0
(it already asserts only disposition `error`, `harness/scenarios.py:63`).

**Cleanup / rollback**

None (documentation + tests). If the owner declares WIN2025-TEST-PLAN frozen for its current
campaign (open question 9), file the errata as a dated addendum block at the head of Section 3
instead of editing the rows in place — but the `coverage.py` fix and the pytest pin land regardless.

---

#### S-PIPE-D — PIPE-18: bulk replay under concurrent intake

**Why narrative:** the hazard is a *timing* interaction between `replay_dead`'s re-pend and a live
delivery worker's claim on the same lane; a naive test that replays into an idle lane proves nothing.

**Preconditions**

- Scratch SQLite store; one inbound, one Handler, one outbound whose destination is a controllable
  sink (harness Receive or a `simulate` outbound with an injectable fail switch).
- Synthetic ADT corpus.

**Steps**

1. With the sink **down**, send M=20 synthetic messages; let their outbound rows exhaust retries to
   `dead`. Record their `seq` values.
2. Bring the sink **up**.
3. Start sustained intake (harness load runner at smoke rate, or a loop of MLLP sends) into the same
   inbound so the same outbound lane is continuously draining.
4. While intake is running, call `POST /dead-letters/replay` scoped to that destination (or
   `store.replay_dead(destination_name=…)` in-process).
5. Stop intake; wait for drain-to-zero.

**Observation point**

The delivery order recorded at the sink, correlated by control id — the harness correlator, or the
`response`/`delivered_keys` rows ordered by `delivery_seq`.

**Expected result**

`lane_inversions == 0` measured over the whole run; every message terminal exactly once (no
`delivered_keys` duplicate, no still-`pending` row); no replayed message delivered ahead of a live
message that was enqueued to that lane **before** the replay call.

**Cleanup / rollback**

Delete the scratch store. If inversions are non-zero, capture the ordered `(seq, delivery_seq,
control_id)` triples — metrics/metadata only, **no message bodies** — and file against the
`replay_dead` re-pend path.

---

#### S-PIPE-E — PIPE-20: prove `delivered_keys` holds no PHI

**Why narrative:** the ledger is deliberately stored **in the clear**, outside the `_cipher` seam.
The test must be written so that *widening the schema* fails it, not just so that today's columns pass.

**Preconditions**

- Synthetic PHI-shaped body from `messagefoundry generate` with distinctive, greppable field values
  (a synthetic MRN, a synthetic surname). Never a real feed. Do not commit the corpus.
- Run on all three backends (SQLite locally; SS/PG in the gated legs).

**Steps**

1. Drive one message end-to-end to a delivered outbound row.
2. Read every column of every `delivered_keys` row for that message.
3. Assert: no cell contains any substring ≥8 characters of the raw body; no cell equals or contains
   the synthetic MRN, surname, or DOB; the column name set equals the six documented columns exactly.
4. Repeat for `resend_log` (PIPE-21) after a `resend_to`.

**Observation point**

Direct store read (`sqlite3` / `sqlcmd` / `psql`) inside the test — not the API, which redacts.

**Expected result**

All assertions hold; adding a hypothetical `body_fragment` column to the schema makes step 3 fail.

**Cleanup / rollback**

Drop the test schema/DB. **Never** print the ledger rows or the body to the test log on failure —
emit column *names* and a boolean match map only.

---

#### S-PIPE-F — PIPE-40: N-active engine-shard fleet on the AWS rig

**Why narrative:** every in-repo shardcert test fakes its network collaborators and says so in its
docstring. This is the only place the declared scaling axis is proven for real, and it is
destructive/expensive enough to need an explicit runbook.

**Preconditions**

- AWS two-box rig (m7i.4xlarge engine / i4i.2xlarge store, per the ADR 0107 P0 record); the campaign
  packet lives off-repo under `MEFOR/aws-bench/`.
- ONE unified store (SQL Server or Postgres) — **not** one store per engine shard (that would be a
  *database shard*, ADR 0039 L5, shelved). `require_unified_store`
  must be satisfiable.
- **Scrub the environment first:** the harness merges the launching shell's env as the base of the
  child env (`harness/load/shardcert.py:1559`), so any stale `MEFOR_PIPELINE_*` export silently
  reconfigures every arm invisibly. `env | grep MEFOR_` must be empty except the intended store vars.
- Do **not** set `--claim-mode per_lane`.

**Steps**

1. Provision the unified store; confirm RCSI is ON for SQL Server (pooled mode fails closed
   otherwise unless `require_rcsi_for_pooled=false`).
2. Launch 4 `serve --shard <id>` processes partitioned by connection.
3. Run the shardcert bench with the correlation sink enabled, at the target rate.
4. Mid-run, SIGKILL one engine shard; restart it. Confirm scoped recovery re-pends only its own lanes.
5. Drain to zero.

**Observation point**

The correlation sink's reconciliation report (sent vs received vs unmatched), per-lane inversion
count, the surviving engine shards' `in_pipeline` gauge during the kill, and the store's `queue` table
grouped by lane and owner.

**Expected result**

Zero lost messages; `lane_inversions == 0`; every outbound lane consumed by exactly one engine shard
(no cross-engine-shard head-steal); the restarted engine shard's rows recovered and drained; sizing number recorded
against ADR 0073's ~450-500 msg/s target as **reported, not gated**.

**Cleanup / rollback**

Terminate all four processes, drop the bench database, tear down the rig instances. Archive the JSON
report to the off-repo campaign packet — **metrics only**, no bodies.

---

### 1.6 Automation disposition

| Bucket | Items | Artifact | Effort |
|---|---|---|---|
| New pytest module | PIPE-02, PIPE-03 | `tests/test_serverdb_ci_coverage.py` — scan `tests/*.py` skipif markers vs `.github/workflows/*.yml` steps **and** the `serverdb` path-gate regex | S |
| New pytest module | PIPE-08, PIPE-09, PIPE-59 | `tests/test_split_path_poison_bound.py` — subprocess fault-injection harness for the ingress and routed lanes: `os.abort()` (PIPE-08/09) **and** a hard memory cap driving an uncatchable OOM kill mid-drain (PIPE-59) | M |
| New pytest module | PIPE-20, PIPE-21 | `tests/test_ledger_phi_safety.py` — `delivered_keys` + `resend_log` ids-only assertions, backend-parametrized | S |
| New pytest module | PIPE-30, PIPE-31 | `tests/test_fifo_index_plan.py` — SQLite `EXPLAIN QUERY PLAN` in the default leg; SS showplan / PG `EXPLAIN` behind the existing `MEFOR_TEST_*` gates | M |
| Pointer — no work here | PIPE-35 | ADR-status-vs-code hygiene is built once, by **SEC-01**. This chapter contributes the pipeline ADR cases (0058/0059/0060/0061/0114) and the design-only exemptions (0051, 0107) as input | — |
| Extend existing | PIPE-04, PIPE-07, PIPE-29, PIPE-58 | `tests/test_staged_pipeline.py` | S |
| Extend existing | PIPE-22, PIPE-23 | `tests/test_db_lookup.py` (mirror `test_fhir_lookup.py:545`) | S |
| Extend existing | PIPE-24 | `tests/test_fhir_lookup.py` | S |
| Extend existing | PIPE-06, PIPE-15, PIPE-27, PIPE-28 | `tests/test_crit2_inline_doc_drift.py` (doc-drift tripwires) + `messagefoundry/checks.py` (two new advisory findings) | M |
| Extend existing | PIPE-12 | `tests/test_txn_per_message_cost_model.py` — add the live-runner counter ceiling beside the recording-connection model | M |
| Extend existing | PIPE-16, PIPE-17, PIPE-44 | `tests/test_not_deployed.py`, `tests/test_reingress.py`, `tests/test_batch_claim_worker.py` | S |
| Extend existing | PIPE-18, PIPE-19 | `tests/test_api.py` (replay route) + a new soak case beside `tests/test_fifo_ordering.py` | M |
| Extend existing | PIPE-32, PIPE-33, PIPE-34 | `tests/test_dryrun_trace.py`, `tests/test_sandbox.py` | M |
| Pointer — no work here | PIPE-36, PIPE-37 | The `tests/test_feature_map_claims.py` extension is a **single consolidated MIG row**; this chapter supplies the `MessageStatus` set and the built-ADR list as its input | — |
| Extend existing | PIPE-43 | `tests/test_adr0071_dispatch_wiring.py` | S |
| Extend existing | PIPE-45 | `tests/test_wiring_engine.py` (alert emit points) | S |
| Extend existing | PIPE-10 | `tests/test_supervisor.py` + a crash-loop breaker in `pipeline/supervisor.py` | M |
| New CI leg / workflow edit | PIPE-01, PIPE-11, PIPE-14, PIPE-41, PIPE-42 (the same edit also lands the file **PERF-10** owns, which PIPE-39 points at) | `.github/workflows/ci.yml` — append six files to the two server-DB steps; widen the `serverdb` path gate at `:434` | S |
| New CI leg | PIPE-13 | Nightly matrix arm with `MEFOR_PIPELINE_CLAIM_MODE=per_lane` over the four core pipeline suites | S |
| New CI leg (deferred) | PIPE-57 | Mutation gate #6 targeted first at `wiring_runner.py` + the finalizer; blocked on `docs/quality-gates/HANDOFF-mutation-coverage.md` §1 (needs a working venv) | L |
| New probe capability | PIPE-25 | `messagefoundry check --replay-equality` — opt-in, re-runs each shipped Router/Handler twice over a synthetic corpus and diffs `RouteOutcome` (reuse `assert_replay_stable`) | M |
| Extend lint | PIPE-26 | Widen `checks.py`'s `impure-transform` rule to file/socket/HTTP writes inside decorated bodies | M |
| Harness / bench | PIPE-40, PIPE-56 | Existing `harness/load/shardcert.py` + the off-repo AWS campaign packet; no new harness code, an operating runbook | M |
| Stays manual — and why | PIPE-05 (a human must adjudicate frozen-campaign errata), PIPE-38 (re-grading another plan's rows is editorial), PIPE-47/48/49/50 (real NSSM service identity + a desktop session for GUI fault injection — structurally out of CI's reach, WIN2025-owned), PIPE-46 (a human eyeball is the assertion: "does a stalled lane *read* as stalled"), PIPE-54 (needs a real partner's resend window), PIPE-55 (deciding when a retry pattern is a real regression is judgment) | — | S–M each |
| Browser | PIPE-46 | `/ui` Live + Dead Letters + connection event log; no automation proposed (a legibility judgment, not an assertion) | S |

**Rough totals:** 4 new pytest modules (S/M), ~12 extensions to existing modules (mostly S), 2
workflow edits (S), 1 nightly arm (S), 1 new CLI probe mode (M), 1 deferred mutation leg (L), 8
manual/host rows already owned by WIN2025 or requiring human judgment, and 4 pointer rows
(PIPE-35, 36, 37, 39) that commission **no** work here.

---

### 1.7 Environment, data & prerequisites

**Hosts and runners**

- **dev-PC** — Windows 11 + Python 3.14 + `uv`, project installed with the
  `dev,harness,fhir,dicom,x12,xml,webauthn` extras plus `packaging/messagefoundry-webconsole`
  (per `docs/quality-gates/HANDOFF-mutation-coverage.md` §1). PySide6 with
  `QT_QPA_PLATFORM=offscreen` for headless harness/Qt tests.
- **container-CI** — the hosted Linux runners already configured in `ci.yml`.
- **W2025-box** — the self-hosted Windows Server 2025 runner `WIN-NAFGLU5SH1J`
  (`.github/workflows/selfhosted-win2025-sql.yml`), which today runs only `test_sqlserver_store`,
  `test_sqlserver_coordinator` and `test_database_connector_integration`.
- **cloud** — the AWS two-box bench rig (m7i.4xlarge engine / i4i.2xlarge store) for PIPE-40 and
  PIPE-56 only. **Must be procured/scheduled** — it was occupied during the last coverage-plan P4 pass.

**Services and drivers**

- SQL Server 2025 service container + Microsoft ODBC Driver 18 + `sqlcmd`;
  `MEFOR_TEST_SQLSERVER=1` with `MEFOR_STORE_*` and `MEFOR_ALLOW_INSECURE_TLS=1` for the container's
  self-signed cert. RCSI must be ON (pooled mode fails closed at startup unless
  `require_rcsi_for_pooled=false`).
- PostgreSQL service container; `MEFOR_TEST_POSTGRES=1` with `MEFOR_STORE_*` and
  `MEFOR_STORE_ENCRYPT=false` + `MEFOR_ALLOW_INSECURE_TLS=1` (plaintext container), `asyncpg` via the
  `postgres` extra.
- NSSM plus a dedicated Windows service account holding `db_ddladmin` / `db_datawriter` /
  `db_datareader` — the service identity's DB access is provably distinct from the interactive
  admin's (`W25:S1.3` false-green note). A DPAPI-protected store key must be minted **as the
  service identity**; an admin-minted key file is undecryptable by LocalSystem / LOCAL SERVICE and
  fail-closes under `require_encryption`.

**Ports**

MLLP inbounds 2575 (tolerant), 2576 (harness Receive sink), 2577 (strict); engine API 8765; load sink
band from `MEFOR_LOAD_SINK_PORT` (default 2700); the 1,500-connection estate shape uses inbound band
3000-4499; the shardcert harness defaults `--inbound-base 20000`, `--sink-base 40000`,
`--api-base 9000`. All must be free before a run.

**Accounts and tokens**

A bearer token for headless harness runs against an auth-on engine (`--token`), or
`MEFOR_SECURITY_REQUIRE_SIGN_IN=false` for the failover orchestrator, which spawns its own nodes.
For PIPE-19, an `[approvals]`-enabled instance with two distinct principals.

**Data — synthetic only**

- Corpus from `messagefoundry generate` (git-ignored). **Never** a real PHI feed.
- `dryrun` / `generate` / `--show-phi` stdout may contain full bodies — never redirect it to a
  committed file, a ticket, or a CI log.
- Reports and matrices carry **metrics and metadata only, never message bodies** (PIPE-18 and
  PIPE-20 failure captures are explicitly constrained to ids/column names/boolean match maps).

**Scratch**

Writable scratch for SQLite WAL-growth measurement; `harness_io/in` and `harness_io/out` for the File
round-trip legs. All PIPE scratch stores live outside the repo tree.

**Environment hygiene (bench rows)**

Before any PIPE-40 / PIPE-56 run, `env | grep MEFOR_` must show only the intended store vars — the
shardcert harness merges the launching shell's environment as the base of every child engine's env,
so a stale `MEFOR_PIPELINE_*` export silently reconfigures every arm and appears in no report.

---

### 1.8 Exit criteria

This area is signed off for release when **all** of the following are true and evidenced:

1. **CI reachability.** The six previously-unexecuted server-DB suites run in `ci.yml` and report
   **36 passed / 0 skipped** on a full run of both server-DB legs. `tests/test_serverdb_ci_coverage.py`
   is green and demonstrably fails when a gated file is removed from the workflow (PIPE-01/02/03).
2. **Poison bound.** PIPE-08 and PIPE-09 are green under the owner's chosen terminal shape
   (bounded dead-letter or bounded STOP), with the ruling recorded in an ADR or BACKLOG entry.
   No configuration exists in which a hard abort on the default split path re-runs unbounded.
3. **ACK contract truthful everywhere.** PIPE-04 green; PIPE-05 and PIPE-06 landed; the doc-drift
   tripwire fails if `AE NAK` reappears on the A03 row; `--scenario error` exits 0 and is recorded as
   AA-then-ERROR in the WIN2025 result set.
4. **Zero P0 rows open.** All **thirteen** P0 rows — PIPE-01, 02, 03, 04, 05, 06, 08, 09, 11, 14,
   **35**, **39**, 48 — are PASS or formally dispositioned with an owner-signed compensating control.
   Two of the thirteen (PIPE-35, PIPE-39) are **pointer rows**: they are discharged by SEC-01's and
   PERF-10's evidence respectively, not by separate work in this chapter. The eleven remaining are
   this chapter's own. All thirteen are class **T**; the six class-**C** rows (PIPE-38, 46, 54, 55,
   56, 57) do **not** gate this release, and there are no class-**A** rows in this area.
5. **PHI bar.** PIPE-20 green on all three backends; PIPE-21 green on SQLite. No test in this chapter
   logged a message body — verified by a grep of the CI logs for the synthetic MRN/surname tokens
   returning zero hits.
6. **Purity.** PIPE-22 green (a Router calling `db_lookup` raises); `messagefoundry check` reports
   zero `impure-transform` findings for `samples/config` and `harness/config`; PIPE-25's
   `--replay-equality` probe exits 0 for both.
7. **Cost model.** PIPE-12 green: live `committed_txns / msg == 3 + 2H + 2N` on SQLite and SQL Server
   across the four (H,N) shapes. Any deviation is either fixed or ADR-recorded with a new formula.
8. **Cross-backend.** Every P0/P1 matrix row marked `x2` or `x3` has executed on the named backends —
   not skipped. A skipped gated leg is a **fail**, not a pass.
9. **Engine-shard axis.** Recovery correctness green here (PIPE-01 / PIPE-14); the cert ladder green
   under **PERF-10**, which PIPE-39 points at. PIPE-40 either green on the AWS rig with the sizing
   number archived, **or** the owner has explicitly withheld N-active certification for v0.1 (open
   question 7) and `docs/FEATURE-MAP.md` says so. PIPE-59's OOM-kill recovery is green or
   platform-`skipif`'d with a recorded reason.
10. **Load/failover unregressed.** PIPE-52 and PIPE-53 green after all changes: zero acknowledged
    loss, `lane_inversions == 0`, drain-to-zero, single live leader, bounded dup rate.
11. **Host rows.** `W25:S2.5` (PIPE-48), `W25:S3.5` (PIPE-49) and `W25:S3.6` (PIPE-50) closed in the
    WIN2025 result set under the real NSSM service identity, per backend.
12. **Documentation of record consistent.** The MIG drift-guard row is green with `NOT_DEPLOYED`
    present in FEATURE-MAP §4 (discharging PIPE-36); SEC-01's status-hygiene guard is green or its
    exemption register owner-approved (discharging PIPE-35); `pipeline/supervisor.py`'s docstring
    matches ADR 0063 (PIPE-15). PIPE-38 is class **C** — its five re-graded `FCP:` rows are recorded,
    not gated.
13. **Guard rails.** PIPE-27 and PIPE-28 resolved one way or the other — either the advisory `check`
    findings ship, or the owner has ruled a hard wiring refusal and it is tested.
14. **No open P0/P1 finding** raised during execution remains unassigned; every P2 deferral carries a
    BACKLOG number.

---

### 1.9 Open questions

1. **ID namespace.** This chapter's prefix `PIPE` collides with `FEATURE-COVERAGE-PLAN.md` §12's
   `[FCP:PIPE-1..19]`, while this area's scope also spans that document's §9 `[FCP:STORE-*]`. This
   chapter uses **zero-padded** `PIPE-01…` and declares its area as `{FCP:PIPE-1..19} ∪
   {FCP:STORE-2,3,4,5,6,7,8,9,10,11,13,16,17,18,21}`. Per the plan-wide convention a bare `PIPE-nn`
   is always this chapter's row and every foreign id carries `FCP:` or `W25:`.
   *Confirm, or assign a distinct prefix.*
   **Blocks:** cross-referencing between the two documents; any traceability matrix built on top.

2. **Are the six never-executed server-DB test files an oversight or a deliberate cost decision?**
   If deliberate, what compensating control covers `batch_handoff_statements`, which is **DEFAULT-ON**,
   SQL-Server-only, reliability-core, and restructures the route/transform handoff DML?
   **Blocks:** PIPE-01, and by dependency PIPE-11, PIPE-14, PIPE-39, PIPE-41, PIPE-42.

3. **Is a poison-crash attempts ceiling on the DEFAULT split ingress/routed path authorized?**
   It changes semantics — a message would be dead-lettered without ever having been successfully
   processed. The alternative is a bounded STOP (head-of-line blocking, operator alerted). This needs
   an owner ruling, not just a test.
   **Blocks:** PIPE-08, PIPE-09; the assertion cannot be written until the terminal shape is chosen.

4. **Should `inline=True` be hard-refused at wiring** given ADR 0107's permanent DO-NOT-PROMOTE, or
   stay operator-settable with an advisory `check` finding?
   **Blocks:** PIPE-27 (advisory finding vs `WiringError`).

5. **ADR 0055 is WITHDRAWN but `_GroupCommitter` (`store/store.py:144`) and `group_commit_window_ms`
   (`settings.py:285`) remain live with 19 guarding tests.** Remove the code, or keep it and re-status
   the ADR as "built, default-off, do-not-enable"?
   **Blocks:** PIPE-28, and whether `tests/test_group_commit.py` (19) stays in the suite.

6. **Is `claim_mode = "per_lane"` a supported release configuration?** `docs/CONNECTIONS.md:1605`
   presents it as the byte-identical opt-out. If supported, it warrants the nightly parity arm; if it
   is now dev/diagnostic only, the docs should say so and the arm is unnecessary.
   **Blocks:** PIPE-13, and the wording of the CONNECTIONS.md contract.

7. **What is the v0.1 acceptance bar for N-active engine-shard certification?** Is the local
   shardcert bench (PIPE-39) sufficient, or must the AWS 4-engine no-loss plus sizing run (PIPE-40) be
   green before release?
   **Blocks:** exit criterion 9; whether the AWS rig must be procured for this release.

8. **Should `FEATURE-MAP.md` §4 list the throughput levers and their default states** (pooled,
   `batch_handoff_statements`, `per_lane_wake`, `fifo_claim_batch`, the ADR 0114 flags), or is the map
   deliberately a user-facing capability view that omits tuning flags? The answer decides whether the
   ~12 map/code disagreements are defects or by design.
   **Blocks:** PIPE-37 (whether it can be a blocking assertion at all). PIPE-36 (`NOT_DEPLOYED`
   missing from a six-item disposition list) is a defect either way.

9. **Who owns correcting the `W25:S2.7` / `W25:S3.4` "A03 → AE NAK" rows** — is that plan frozen
   for its current campaign, or can this chapter issue errata against it in place?
   **Blocks:** the form of PIPE-05 (in-place edit vs dated addendum). The `coverage.py` fix and the
   pytest pin proceed regardless.

10. **Should ADR status be CI-enforced against code** (0058/0059/0060/0061 are built but carry
    `Status: Proposed`; 0114 is Proposed with five test files and three live flags)? If so, which ADRs
    are legitimately design-only and belong on the allow-list?
    **Blocks:** PIPE-35.

11. **Is an in-CI `committed_txns`-per-message ceiling acceptable as a hard gate** — it would fail a
    PR that adds a commit — or must it stay advisory like the complexity/clone gates in
    `quality-advisory.yml`?
    **Blocks:** PIPE-12's severity and its workflow placement.

12. **Should the deferred mutation-coverage gate** (`docs/quality-gates/HANDOFF-mutation-coverage.md`)
    be targeted first at `pipeline/wiring_runner.py` and the store finalizer paths, given they are the
    highest-consequence code and already carry dense tests that mutation scoring could meaningfully
    grade?
    **Blocks:** PIPE-57's scope and priority.
