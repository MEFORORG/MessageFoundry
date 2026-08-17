[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 16. Performance, Throughput, Scale & Capacity

**ID prefix:** `PERF` · **Surface:** engine + CLI + infra (load harness, `serve --shard`/`supervise`, store backends, CI)
· **Primary risk:** every published throughput ceiling is produced by a verdict with no filling / backlog-slope term and no engine-vs-rig attribution, so a number that over-reports sustainable capacity by 3–5.5x can be signed off, printed in the sizing tiers, and used to size a hospital cutover.

---

### 16.1 Scope & objectives

**In scope.** The measurement instruments and the scale claims they feed:

- The `--load` harness end to end — profile schema (`harness/load/profile.py`), rate governor
  (`harness/load/governor.py`), correlation sink (`harness/load/sink.py`), engine poller
  (`harness/load/enginepoll.py`), no-loss reconcile + SLO verdict + baseline diff
  (`harness/load/report.py`), and the 19 shipped profiles under `harness/load/profiles/`.
- The scale rigs: `--connscale` (`harness/load/connscale/`), `--estate`
  (`harness/load/estate/`), `harness multishard` (`harness/load/multishard.py`),
  `harness shardcert` + the ascending rate ladder (`harness/load/shardcert.py`,
  `harness/load/shardcert_ladder.py`), and `--failover` (`harness/load/failover.py`).
- Engine sharding as a *measured* topology: `serve --shard` / `messagefoundry supervise`
  (`messagefoundry/pipeline/sharding.py`, `messagefoundry/pipeline/supervisor.py`), the no-split-store
  rule (ADR 0063 `require_unified_store`), ownership-scoped recovery + one delivery consumer per
  outbound lane (ADR 0073).
- The throughput lever set and its **default pinning**: `[store].group_commit_window_ms` (ADR 0055,
  withdrawn by ADR 0099), `[store].fifo_claim_batch` (ADR 0058), `[transform].inline` (ADR 0057 /
  0107 do-not-promote), `[pipeline].fuse_thread_hops` (ADR 0071 NO-GO), `[pipeline].per_lane_wake`
  (ADR 0061), `[pipeline].batch_handoff_statements` (ADR 0075, default-ON),
  `[pipeline].claim_mode="pooled"` (ADR 0066, default), `[store].pool_size=40` (ADR 0062), and the
  ADR 0114 SQL-Server-only claim sub-levers.
- Per-backend throughput and the published baselines: `docs/benchmarks/TUNING-BASELINE.md`,
  `docs/benchmarks/results/`, `.github/workflows/benchmark.yml`, and the sizing tiers in
  `docs/SYSTEM-REQUIREMENTS.md`.
- Long-run health: soak RSS / handle / connection-leak detection, retention & purge concurrent with
  load (ADR 0137 `max_pass_seconds`), and the saturation detector
  (`messagefoundry/pipeline/saturation.py`).
- The capacity story: ADR 0051 (Corepoint parity, measure-first phase complete), ADR 0052 (45M/day +
  1,500 connections), ADR 0074 (adopter capacity estimator — **build-gated**), ADR 0101 (falsifier
  discipline), ADR 0141 (copies/msg as the sizing proxy, bytes/msg refused).

**Explicitly NOT in scope here — owned elsewhere, cited not restated:**

| Area | Owner |
|---|---|
| Real-host throughput on the Windows Server 2025 box: per-DB baseline, closed-loop ceiling, spike, transform wall, fan-out write amplification, soak, sustained overload, malformed-under-load, Windows failover recovery time, DB restart/service bounce under load | `docs/testing/WIN2025-TEST-PLAN.md` §4 (`W25:S4.1`–`W25:S4.10`, §4.0 opens at line 644, `W25:S4.10` opens at line 985 and runs to ~line 1050) + the per-row validity gate at line 1042 |
| Failover-under-load x3 server DBs; throughput baseline under the load harness x3 | `docs/testing/WIN2025-TEST-MATRIX.md` rows `W25:G3` (line 92), `W25:H1` (line 100) |
| 45M/day as a tracked capability measurement; 1,500-connection reference baseline; falsifier CI smoke; capacity-estimator build decision | `docs/testing/FEATURE-COVERAGE-PLAN.md` §P5 (lines 271–299) — `FCP:SCALE-19`, `FCP:SCALE-18`, `FCP:SCALE-15`, `FCP:SCALE-16` |
| Dormant-lever dispositions (group-commit withdrawn, inline default-OFF doc drift, cp314t eval, L5 declined) | `docs/testing/FEATURE-COVERAGE-PLAN.md` §P7 (lines 402–408) — `FCP:STOREF-14`, `FCP:CRIT-2`, `FCP:SCALE-7`, `FCP:SCALE-17` |
| Persistent outbound MLLP throughput / TIME_WAIT regression | `docs/testing/FEATURE-COVERAGE-PLAN.md` `FCP:MLLP-8` (lines 596, 615) |
| Parser benchmark harness (single-thread throughput, builtins-vs-python-hl7 agreement, thread-pool determinism) | `tests/test_benchmark_parser.py` — `FCP:PARSE-15`, **closed** |
| Operator-facing harness contract (channels, exit codes, reconcile semantics, backend comparison, estate calibration, known limitations) | `docs/LOAD-TESTING.md` |

**Objectives.** (1) Make every published rate carry a *falsifiable* verdict — a filling term, an
estimand label, and an engine-vs-rig attribution. (2) Give the only built multicore topology (engine
shards over one unified store) real automated execution. (3) Make a throughput or latency regression
capable of failing something. (4) Prove the long-run and under-load-maintenance paths the soak exists
to cover actually leave evidence. (5) Stop the published sizing guidance from contradicting the
measured record.

---

### 16.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_load_runner.py` (PR gate, `pytest.mark.timeout(120)`) | Serves `harness/config/load` on a temp SQLite store, drives a tiny profile through `run_load` end to end, asserts no-loss + exit 0, the preflight failure path, and CLI dispatch |
| `.github/workflows/ci.yml` job `load-test` (nightly cron + dispatch) | `python -m harness --load smoke` against a real served engine under the secure PHI posture (runtime-minted `MEFOR_STORE_ENCRYPTION_KEY`, bounded retention, deny-by-default egress); zero-loss + all SLOs; metrics-only report uploaded |
| `.github/workflows/ci.yml` job `load-test-sqlserver` (matrix 2022/2025) | The same zero-loss fan-out path driven through the real SQL Server store with `smoke-sqlserver` |
| `tests/test_load_report.py`, `test_load_metrics.py`, `test_load_sender.py`, `test_load_sink.py`, `test_load_corpus.py` | Reconcile arithmetic, SLO composition, DDSketch percentile accuracy, pipelined MLLP sender, correlation sink, synthetic corpus build, metrics-only JSON (no PHI), CSV formula-injection neutralisation |
| `tests/test_load_profile.py`, `tests/test_load_config.py` | Profile schema fails loud on a typo'd key; shipped profiles and the load config carry no real partner/site/host tokens |
| `tests/test_load_failover_postgres.py` + `test_load_failover_sqlserver.py` as steps in `postgres store` (ci.yml:803) and `sql server (store + connector)` (ci.yml:658) | Two-node SIGKILL-under-load on real server DBs: no acknowledged loss, no split-brain, bounded dups, promotion observed, per-lane FIFO 0 inversions |
| `tests/test_load_failover_unit.py`, `tests/_failover_load_support.py` | Failover orchestrator logic offline — lease timing invariants, kill fraction, verdict composition |
| `tests/test_connscale_smoke.py`; `tests/test_connscale_postgres.py` at `MEFOR_STORE_POOL_SIZE=4` (ci.yml:853) | In-process connection-scale N=12→24 on SQLite (no-loss, FD + empty-claim monotonicity, executor shim, reload probe); pool-acquire-wait wall on a real server DB with a forced tiny pool |
| `tests/test_connscale_{profile,config,report,driver,cpu_probe,compare,batch,fuse,fuse_replay}.py` | Profile parsing, report shape, driver pacing, the BACKLOG #220 same-PID-set CPU fold, A/B compare, batch/fuse arm wiring |
| `tests/test_estate_{driver,profile,shape}.py` | Event-rate calibration (hubs driven slower than simples), the rate identity, fraction/fan-out bounds, heterogeneous graph shape — **unit level only** |
| `tests/test_multishard_smoke.py` | Two real `serve` subprocesses on ONE SQLite store: orchestration mechanics + no cross-engine lane steal (`foreign_rows == 0`) |
| `tests/test_sharding.py` (32 tests) | Engine-shard-tag normalisation, `shard_ids` discovery, `filter_registry_for_shard` carry-through, `require_unified_store` fail-closed |
| `tests/test_shard_recovery_engine.py`, `tests/test_shard_lane_ownership.py` | ADR 0073 engine seams: ownership-scoped recovery, reload refusal on a changed engine-shard universe (in-process SQLite) |
| `tests/test_supervisor.py` | Engine-shard db/port derivation, argv composition, one child per engine shard, restart-on-crash, terminate→kill escalation (against `_FakeProcess`) |
| `tests/test_shardcert_{config,ladder,ladder_cli,ladder_two_box,multiproc,partitioned,partitioned_fanout,two_box}.py`, `tests/test_harness_invariants.py` | Ladder climb/stop logic, rung classification, drive-shortfall vs backpressure attribution, the A4b cross-observer INCONCLUSIVE guard (`shardcert_ladder.py:870`), multi-process drive handshakes |
| CI step "throughput-lever backend invariants" on real SQL Server (ci.yml:660–700) and real Postgres (ci.yml:805–830) | `test_inline_fast_path`, `test_batch_claim_{fifo,worker,locking}`, `test_claim_fifo_heads`, `test_seq_only_fifo`, `test_fifo_index_migration`, `test_per_lane_wake`, `test_stage_dispatcher`, `test_pooled_rider` execute against both server backends |
| `tests/test_group_commit.py`; `tests/test_inline_fast_path.py` + `tests/test_crit2_inline_doc_drift.py` | ADR 0055 AC-1..AC-5 with the committer ON, plus the off-by-default gate; split-path behaviour with `inline` OFF plus the two default/doc tripwires |
| `tests/test_adr0075_batch_{golden_sql,sqlserver,backend_gate,error_attribution}.py`; `tests/test_adr0114_claim_{flags,fold,prepared,proc,proc_live}.py`; `tests/test_adr0071_fused_callables_sqlserver.py` | Per-hop statement batching holds commits/msg at 2.000 and is a provable no-op on PG/SQLite with error attribution preserved; claim sub-levers are SS-only no-ops elsewhere; fused-callable correctness |
| `tests/test_txn_per_message_cost_model.py` (12 tests); `tests/test_bytes_per_message_amplification.py` (8 tests) | Pins txn/msg = 3 + 2H + 2N against the real `SqlServerStore` over a recording connection, and body-copy amplification 2 + H + N — the currency ADR 0051's capacity argument rests on and the analytical counterpart of ADR 0141's copies/msg proxy |
| `tests/test_benchmark_parser.py` (6 tests) | `FCP:PARSE-15`: single-thread parser throughput, builtins-vs-python-hl7 agreement, thread-pool determinism, conservative floor guard |
| `tests/test_saturation.py`; `tests/test_host_metrics.py`; `tests/test_enginepoll_aggregate.py` | Rising-backlog derivative fires on sustained growth and not on bursty-but-draining; `messagefoundry_host_cpu_percent` / `_process_resident_memory_bytes` render in the Prometheus exposition; the poller sums read/written/backlog/in_pipeline across every engine-shard API in a `supervise` fleet |
| `tests/test_retention.py`, `tests/test_per_connection_retention.py` | Body purge, window overrides, dead-payload retention at the store level (idle) |
| `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md`; `docs/benchmarks/results/` (7 dated dirs) | The adversarially-verified measurement record — C1–C7 + P0 falsifier verdicts, the retraction list, §5 "why the measurement programme kept failing". **Correcting the recon:** the C4–C7 raw handbacks *are* committed (`results/2026-07-12-throughput-c4-c7/`, with per-cell JSON + CPU/DMV CSVs), so P0 is not the only auditable campaign |
| `harness/load/shardcert.py:1755` `CEILING_GATE_VERSION = 2`, `:1758` `_is_ceiling`, `:1893` `fill_ratio`, `:1915` `filling` | **Correcting the recon:** a filling / latency-divergence term *does* exist and *is* live on the **co-located** shardcert ladder, with `_FILLING_RATIO = 1.5`, a `_FILLING_MIN_SAMPLES = 30` abstain floor, a warm-up drop, and a versioned gate stamp |

**DONE — do not re-plan.** The load harness's *mechanics* are well covered: reconcile arithmetic,
percentile accuracy, PHI-safety of the report, CSV injection, profile schema strictness, the
customer-token leak guard, failover-under-load on both server DBs, the connection-scale rig at small
N, the A4b cross-observer guard, the txn/msg and copies/msg cost models, and every throughput lever's
*behavioural* correctness on all three backends. The parser benchmark (`FCP:PARSE-15`) and the API DoS
bounds (`FCP:API-18`) are closed by FEATURE-COVERAGE-PLAN §P5. WIN2025 §4 owns every real-host number.
Nothing below re-tests any of that; the rows below attack the **verdict**, the **attribution**, the
**execution surface**, and the **published claim**.

---

### 16.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| The `--load` sustainable-rate verdict has no filling / backlog-slope term | A phase whose in-flight backlog grows through the whole hold passes `zero_loss` + eventual drain and reads as sustained. `report.py:503 _run_slos` checks only zero-loss, drain seconds, dead letters, dup rate — no slope, no latency divergence | Every published `--load` ceiling; every adopter sizing run; a cutover sized 3–5.5x over capacity drops clinical messages | **No.** The gate exists only on the co-located shardcert path (`shardcert.py:1758`); `shardcert_ladder.py:1092` documents its own absence on the two-box path in capitals | **P0** |
| `/stats` poller-zero contamination | `enginepoll.py:556 await_drain` declares drained on `backlog == 0 and queue_depth == 0 and in_pipeline == 0` plus two equal `read`/`written` samples. A zeroed or frozen `/stats` under exactly the overload the gate exists for satisfies all four | A saturating, lossy run reports PASS and drained | No staleness precondition anywhere | **P0** |
| Engine sharding has zero CI execution | No workflow file contains the string `shard`. `tests/test_supervisor.py` drives `_FakeProcess`, never a real subprocess. `tests/test_shard_recovery_sqlserver.py`, `test_shard_recovery_postgres.py`, `test_shard_cert_sqlserver.py` are `MEFOR_TEST_*`-gated **and** named by no CI step, so they execute nowhere | ADR 0073 ownership-scoped recovery and single-delivery-consumer-per-lane are what keep per-lane FIFO and at-least-once correct on the only built multicore topology. A regression yields duplicate delivery, cross-engine-shard FIFO inversion, or permanently stranded rows | No | **P0** |
| Published sizing contradicts the measured record and itself | `docs/SYSTEM-REQUIREMENTS.md:195-198` offers tiers to "~500 – low-thousands msg/s / ~40M+/day"; the publishable measured figure is ~72 ev/s (`FCP:SCALE-19`, FEATURE-COVERAGE-PLAN:286, 7.23x short). The same file says multi-process scale-out "**is built**" (:163) and "a **future direction, not built**" (:213, :234) | The document an adopter sizes hardware from. Order-of-magnitude over-claim + a self-contradiction about whether the scale-out path exists | No doc-vs-measurement guard exists; `tests/test_feature_map_claims.py` checks only the ASVS score, private-path links and superseded docs | **P0** |
| The one published multi-process scale-out number was measured on a now-forbidden topology | `docs/benchmarks/TUNING-BASELINE.md:150` records the η ≈ 0.85 / E_core ≈ 42 msg/s **engine-sharding** result on the store line "**per-shard SQLite** (one store file per shard — **no shared DB**, no shared-DB commit contention by design)" (quoted verbatim from the source table), measured 2026-06-27. ADR 0063 (2026-07-01) and `sharding.py:81 require_unified_store` now **refuse** >1 engine shard on any non-server backend | The only published **engine-sharding** speedup — the shape adopters are told to multiply by their own `E_core` — is not reproducible with the shipped code, and it was measured with the shared-store contention deliberately absent | No | **P0** |
| No throughput/latency regression gate anywhere | `.github/workflows/benchmark.yml` is `workflow_dispatch`-only, and each run wraps the harness in `set +e` … `set -e` so **even the harness's own SLO exit code is discarded**. Numbers are hand-transcribed into TUNING-BASELINE. `--baseline`/`--tolerance` exist (`report.py:753`) but are invoked by no workflow. `docs/CI-QUALITY.md` has no perf section | A 5x throughput or p99 regression from a claim-path, store or connector change merges green and is found on the next manual rig run | No | **P1** |
| The published "reference performance floor" is enforced nowhere | TUNING-BASELINE:29 states the floor "≥ 200 msg/s sustained · ACK p99 ≤ 50 ms · e2e p99 ≤ 5 s". `harness/load/profiles/reference.toml` `[load.slo]` carries only `max_error_rate`, `max_dead_letters`, `zero_loss` — deliberately, but nothing else asserts the floor either | A release can clear the two-tier gate's performance tier by assertion rather than measurement | No | **P1** |
| No "harness-was-the-limit" boolean in the report | `deferred_backpressure` / `deferred_schedule` exist (`metrics.py:199-202`, written at `governor.py:51,58,86,123`) but `PhaseReport` and `_counters_dict` (`report.py:726`) emit only the total. Only shardcert has the attribution (`RungFidelity.DRIVE_SHORTFALL`) | `docs/LOAD-TESTING.md:296` and `W25:S4.2` (:755) / `W25:S4.7` (:907) / the validity gate (:1042) all require this flag FALSE before a ceiling counts — as written those acceptance steps are **unexecutable**, and a sender-bound number can be published as an engine ceiling | No | **P1** |
| Soak cannot detect a leak | `EngineSample` (`enginepoll.py:67-144`) has no RSS or handle field; `FdSampler` (`connscale/probe.py:73`) exists only under connscale/estate. `W25:S4.6`'s PASS condition "engine process RSS does not creep" is eyeballed in Task Manager | An 8 h soak leaves no committed trace of a slow leak — the soak cannot detect the failure it exists for | No | **P1** |
| Retention/purge under sustained load untested | `tests/test_retention.py` drives the store directly; nothing runs `RetentionRunner` concurrently with a load profile. ADR 0137's `max_pass_seconds` defaults to `0.0` (uncapped, `settings.py:1566`) with no under-load proof | An uncapped purge/VACUUM pass overlapping the next window contends with the claim path and stalls intake — a silent throughput collapse with no failing test | No | **P1** |
| The unconfirmed-send excusal can go vacuous | `report.py:598-601` documents it: once `unconfirmed_budget >= sent` the `max()` forgives a 100%-dead ACK path, and the independent intake floor cannot catch it (its signature is a high `read` with no ACKs) — "known gap, deliberately not fixed here" | A total ACK-path regression — the accepted-and-dropped failure the count-and-log invariant forbids — passes `zero_loss` on a small run, and the **small run is the CI gate** | Partially: `over_budget` fires only when the fraction arm dominates | **P1** |
| Overload / spike / write-amp / transform-wall profiles never run automatically | `spike-burst.toml`, `sustained-overload.toml`, `writeamp.toml`, `malformed-load.toml` are on-demand data files; no CI leg names any of them | A backpressure regression (intake past capacity, a spike that never drains, a fan-out that cannot drain) is invisible until a manual run — and these are the profiles that prove graceful degradation instead of loss | No | **P1** |
| No default-pinning guard for the perf flags | Only `inline` has a default tripwire (`tests/test_crit2_inline_doc_drift.py`). `fifo_claim_batch`, `fuse_thread_hops`, `per_lane_wake`, `fifo_claim_fold_reset/proc/prepared`, `group_commit_window_ms`, `batch_handoff_statements`, `claim_mode`, `pool_size` have behaviour tests but no default assertions (group-commit has one, `tests/test_group_commit.py`) | A silent default flip enables an un-benched or explicitly withdrawn lever on the staged-queue hot path. ADR 0114 requires a per-flag §8 bench gate; ADR 0055's committer is withdrawn but its code is live | Partial | **P1** |
| No latency-percentile regression gate | ACK/e2e p50/p95/p99 are computed per phase and compared to nothing without `--baseline`. The `messagefoundry_delivery_latency_seconds` histogram (`api/metrics.py:426`) carries no perf assertion | Latency is the operator-visible symptom of most perf regressions — ADR 0075 was justified on a −18% ACK p99, not throughput | No | **P1** |
| No knee-finder, no per-step gate | `grep -rn "knee" harness/` returns only TOML comments; `reference.toml:53-55` concedes the per-step e2e is "reported, not pass/failed". Step selection is a human eyeball | The published ceiling is an expert judgement call, not a reproducible measurement — exactly the expertise ADR 0074 promised to remove | No | **P1** |
| The reported estimand is intake ACK rate, not delivery | `report.py:411` `achieved = acked / rec.wall_seconds`; shardcert's ceiling term is `achieved_intake < offered * (1 - _INTAKE_TOL)`, explicitly "**Deliberately not** `delivered < offered`" (`shardcert.py:1766`) | The exact conflation STEP-4 Arm 0 forced a retraction over (26/s intake against ~16 msg/s delivery). Any number quoted without its estimand over-reports what reaches the partner | No | **P1** |
| Measured ceilings are instant-partner ceilings and nothing says so | `harness/load/sink.py:3-11` — the sink *is* the destination and "immediately ACKs AA. Speed is the contract". `docs/THROUGHPUT.md:239` names partner RTT as usually the biggest reduction (2.5x in its own worked example). No partner-RTT input, field or caveat exists | Sizing from an instant-partner number over-provisions throughput by roughly the partner's RTT factor | No | **P1** |
| multishard shared-store zero-loss is not asserted anywhere automated | `tests/test_multishard_smoke.py:16-22` explicitly excludes it as a single-writer-SQLite artifact; the real server-DB gate is operator-only | N engines on ONE unified store is the ADR 0063 topology the whole scale story rests on; its end-to-end no-loss property has no automated proof on any backend | No | **P1** |
| The estate runner has no end-to-end test | No file calls `harness.load.estate.runner.run_estate` (`runner.py:75`); no workflow invokes `--estate`, though `docs/LOAD-TESTING.md:242` and `profiles/README.md` advertise `estate-smoke` as a hermetic CI smoke | The 1,500-connection demo (ADR 0052 AC-2, BACKLOG #216) breaks only in front of an evaluator | No | **P1** |
| `connscale-smoke` / `estate-smoke` never run through the CLI | No workflow contains `--connscale` or `--estate`; `tests/test_connscale_smoke.py:15` nonetheless asserts the N=50/100 profile is "run via the `--connscale` CLI in CI" | Arg plumbing, port-window allocation and report writing are unexercised, and a docstring states a false coverage claim a reviewer will believe | No | **P2** |
| Group-commit code is live under a withdrawn ADR | `settings.py:285 group_commit_window_ms = 0.0` with a live committer at `store/store.py` and a full passing AC suite, while ADR 0055 is WITHDRAWN by ADR 0099 and its premise measured false | An operator enabling it on a PHI store bypasses a withdrawal grounded in a measured-false premise for zero measured gain; the passing AC suite reads as endorsement | Default only (`tests/test_group_commit.py`) | **P2** |
| `max_error_rate` suppressed below `_RATE_SLO_MIN_SENT` | `report.py:430,470-483` — a documented scope gap: an error flood confined to a sub-floor MEASURED phase inside a large multi-phase run is gated by neither the phase rate SLO nor the run-level reconcile | A profile with a short measured phase in which every message errors still exits 0 | Documented, not guarded | **P2** |
| No profile lint | A `.toml` can declare measured phases with no conformance SLOs (`writeamp`, `malformed-load` rely on the operator reading the report). Nothing checks a gate-class profile carries `zero_loss` plus a drain bound | A gate profile silently degraded to reporting-only passes every run, and the CI legs key off profile names | No | **P2** |
| Report JSON carries no host/environment stamp | `RunReport.to_json_dict` (`report.py:153`) emits schema, profile, engine URL, totals, phases, engine_side, no_loss, slo, notes — no host/CPU/OS/python/commit/backend-version. `benchmark.yml` writes a separate `env-<backend>.txt` sidecar | `--baseline` will happily diff runs from unlike hosts — a false regression, or worse a false all-clear on a faster runner. The provenance failure ADR 0101 exists to prevent | No | **P2** |
| No engine-side per-process CPU attribution on `--load` / shardcert | The BACKLOG #208 residual is off-repo; `connscale/probe.py` has the per-PID probe but the `--load` poller does not | Four store-side falsifiers returned negative and the wall is UNNAMED specifically because the engine box was never attributed. Every future limiting-factor label is a guess — the error class ADR 0101 forbids | No | **P2** |
| cp314t canary is too narrow | `.github/workflows/freethread-smoke.yml` runs only `tests/test_parsing.py` + `tests/test_wiring.py` under 3.14t, weekly, never on PR — while ADR 0053 names free-threading the committed unified-store scale path | The tripwire cannot detect a free-threading regression in the code that would have to be thread-safe (store, claim path, executors) | Partial (GIL-off assertion + non-vacuous verdict step are solid) | **P2** |
| "Aggregate = Σ per-interface ceilings" is measured-false but still required by an ADR | Corrected inline at `docs/THROUGHPUT.md:264-275` (16 lanes at 5.44/s against a 60/s per-lane ceiling ⇒ ~11x over-report) yet still required by ADR 0074 §Decision 1 / AC-2 | Any future capacity tool or sizing doc that sums interfaces over-reports by roughly an order of magnitude | No | **P2** |
| `supervise --db` help and the supervisor module docstring still describe per-engine-shard SQLite files | `messagefoundry/__main__.py:129` "each shard gets `<stem>_<shard>.db`" and `supervisor.py:7` "each with its own SQLite db file" (both quoted verbatim from source); `_shard_db_path` still derives them — while `require_unified_store` refuses that very topology | An operator reads the CLI help, believes per-engine-shard SQLite is supported, and hits a startup refusal (best case) or reasons about a store layout that cannot exist | No | **P2** |
| The saturation alert is never asserted under real overload | `tests/test_saturation.py` is a pure table test | It is the operator's only pre-ceiling warning; if it fails to fire under real overload the first signal is a full queue | No | **P2** |
| ADR 0074 amendment cross-links are dead | It cites `0107-inline-transaction-fusion.md` and `0101-publishable-performance-numbers.md`; the real files are `0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md` and `0101-pre-registered-falsifier-discipline-for-performance-measurement.md` | The two ADRs that gate the capacity-estimator build are unreachable from the amendment that gates it | No | **P2** |

---

### 16.4 Test matrix

**Row class (`Cls`).** **T** = a falsifiable test with an observable pass criterion — **only T rows count
toward the release gate**. **C** = characterisation: it produces a recorded measurement, finding or dated
owner decision but has no threshold yet, so it cannot fail and must never gate a release; a C row becomes
a T row the day its threshold is recorded. **A** = an external assurance engagement, blocking only for an
off-loopback / production-exposure release.

**This chapter has 66 rows: 60 T, 6 C, 0 A.** The 6 C rows are PERF-14, PERF-31, PERF-49, PERF-52,
PERF-62 and PERF-63 — every one of them publishes a number or a finding with no threshold behind it.
**15 of the T rows are P0** (PERF-01…PERF-13, PERF-45, PERF-46); the sixteenth P0-priority row, PERF-14,
is a C and therefore cannot gate. Three T rows — **PERF-07, PERF-09, PERF-56** — are **pointer rows**:
the deliverable is owned by another chapter, they scope no separate work here, and they close when the
owning row closes.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| PERF-01 | Filling term added to the `--load` run verdict: a synthetic phase whose in-flight backlog grows monotonically through the hold must FAIL | Performance | pytest | any | n/a | T | P0 | A `filling` (or `backlog_slope`) `SloCheck` appears in `RunReport.slos`; with a fabricated `EnginePoller` whose `in_pipeline` rises monotonically across the measured phase, `result_ok is False` and `exit_code == 1`; with a flat trace it passes; with fewer than the minimum samples the check is emitted with `observed == "abstain"` and does not fail the run |
| PERF-02 | Filling term added to the two-box `classify_rung`, replacing the documented absence at `shardcert_ladder.py:1092` | Performance | pytest | any | n/a | T | P0 | `classify_rung` accepts an in-hold latency-growth or backlog-slope input; a rung with `no_loss=True, engine_ok=True` and a growth signal above the bar returns `RungVerdict.COLLAPSED` (or a new `FILLING` verdict), not `SUSTAINED`; with the signal absent it returns `INCONCLUSIVE`, never `SUSTAINED`; `CEILING_GATE_VERSION` is bumped in the same commit |
| PERF-03 | Drain-clearance can no longer stand alone as a sustain criterion: bound D relative to H, or drop it | Performance | pytest | any | n/a | T | P0 | A synthetic rung with hold H and drain window D where `R <= C*(1+D/H)` and backlog grew all hold classifies as a ceiling; a profile-load-time check rejects `drain_timeout_s > k * (sum of measured phase durations)` for a gate-class profile, with k recorded in the profile schema |
| PERF-04 | `/stats` staleness precondition: a poller sample whose fields are all zero (or unchanged for N consecutive ticks while the client is still sending) must not satisfy `await_drain` | Negative/Security | pytest | any | n/a | T | P0 | With a fake `EngineClient` returning all-zero `/stats` while `Counters.sent` climbs, `await_drain` returns `None` (timeout) rather than a drain time; `build_report` records the run as INCONCLUSIVE, not PASS; sink-side `sink_received` is the primary loss authority in the emitted `no_loss.detail` |
| PERF-05 | Poller-zero rung classification: an engine half that reports zeros must yield INCONCLUSIVE, never a bracketed ceiling | Negative/Security | pytest | any | n/a | T | P0 | A synthetic `ShardCertStepRecord` / rung payload with zeroed engine counters and non-zero sink counters classifies `INCONCLUSIVE`; the existing A4b guard (`observers_inconclusive`, `shardcert_ladder.py:870`) is extended or a sibling zero-guard is added, and a regression test pins both |
| PERF-06 | Real 2-engine-shard `supervise` smoke on a server DB: two live `serve --shard` subprocesses over ONE unified store, driven by `--load` with `--skip-preflight` + `--shard-engine` | HA/Resilience | CI-leg | container-CI | x2 | T | P0 | Two child PIDs observed; each engine shard's `/connections` reports only its own tagged inbounds; the aggregated poller sums both; `zero_loss` true, `in_pipeline` reaches 0 on both engine shards, `max_dup_rate` within the profile bound, 0 per-lane FIFO inversions; the leg fails if either child exits non-zero |
| PERF-07 | **Pointer.** Engine-shard recovery correctness on a server DB (`tests/test_shard_recovery_sqlserver.py`, `tests/test_shard_recovery_postgres.py` named by a CI step, collected>0) | HA/Resilience | — | container-CI | x2 | T | P0 | Covered by PIPE-01 / PIPE-14; no separate work scoped |
| PERF-08 | Supervisor drives a real subprocess at least once (not only `_FakeProcess`) | HA/Resilience | pytest | any | SQLite | T | P0 | A single-engine-shard `supervise` spawns one real `python -m messagefoundry serve --shard …`, the child answers `/health`, a SIGTERM/terminate path stops it inside the grace, and a killed child is relaunched exactly once; asserted against the OS process, not a stub |
| PERF-09 | **Pointer.** Ownership-scoped recovery under a real 2-engine-shard restart on a server DB: a restarting engine shard re-pends only its own lanes | HA/Resilience | — | container-CI | x2 | T | P0 | Covered by PIPE-01 / PIPE-14; no separate work scoped |
| PERF-10 | **Owner: the engine-shard cert ladder + single-delivery-consumer-per-lane.** `tests/test_shard_cert_sqlserver.py` is named by a CI step, and one delivery consumer per outbound lane holds across engine shards under load | HA/Resilience | CI-leg | container-CI | x2 | T | P0 | `tests/test_shard_cert_sqlserver.py` appears in the `sql server (store + connector)` job's pytest list and a green run shows collected>0 (no silent skip); for every outbound lane, deliveries observed at the correlation sink arrive from exactly one engine shard's worker for the whole run; `owner_shard_of_destination` is stable across both processes; duplicate deliveries stay within `max_dup_rate`. **PIPE-39 points here — no cert-ladder work is scoped there** |
| PERF-11 | Doc-guard: `docs/SYSTEM-REQUIREMENTS.md` may not say multi-process scale-out both "is built" and "not built" | Functional | pytest | any | n/a | T | P0 | A pytest scans the file; the phrases "future direction, not built" and "is built" must not both apply to multi-process **engine sharding**; the test fails on today's content (lines 163, 213, 234) and passes after the owner edit |
| PERF-12 | Doc-guard: every sizing tier in `docs/SYSTEM-REQUIREMENTS.md` is either linked to a committed measurement artifact under `docs/benchmarks/results/` or carries an explicit UNVALIDATED label | Functional | pytest | any | n/a | T | P0 | Each tier row contains either a relative link resolving to an existing file under `docs/benchmarks/` or the literal token `UNVALIDATED`; the test fails on today's "~500 – low-thousands msg/s / ~40M+/day" row (line 198) |
| PERF-13 | Doc-guard: the published **engine-sharding** speedup carries its topology, and its topology is one the engine still permits | Functional | pytest | any | n/a | T | P0 | The `TUNING-BASELINE.md` multi-process section either (a) states in-row that per-engine-shard SQLite is REFUSED by `require_unified_store` for >1 engine shard and the figure is therefore historical, or (b) is replaced by a unified-store measurement; a test asserts the section does not present a per-engine-shard-SQLite η as current sizing guidance |
| PERF-14 | Re-measure the **engine-sharding** speedup on the ADR 0063 topology (K engine shards, ONE server DB) | Performance | harness | W2025-box | x2 | C | P0 | **Characterisation — publishes a number, no threshold.** `harness multishard --engines 1,2,4 --store sqlserver` (and postgres) produces an aggregate-vs-K table; the derived η is published with the store host, pool size, and `claim_mode` stamped, and a K at which zero-loss fails is recorded as the ceiling rather than dropped. Becomes a T row the day the owner records a minimum acceptable η (16.9 Q4) |
| PERF-15 | `benchmark.yml` stops discarding the harness exit code | Functional | CI-leg | container-CI | x3 | T | P1 | The `set +e` / `set -e` wrapper around `python -m harness --load reference` is removed or replaced with an explicit capture that re-raises; a deliberately failing profile makes the job red |
| PERF-16 | Nightly reference baseline diff with a committed per-runner-class baseline | Performance | CI-leg | container-CI | x3 | T | P1 | A nightly job runs `--load reference --baseline docs/benchmarks/baselines/<runner-class>-<backend>.json --tolerance <t>`; a synthetic 5x-slower baseline injection makes the job red; the job is skipped (not passed) when no baseline exists for the runner class |
| PERF-17 | Environment stamp embedded in the report, and `--baseline` refuses a mismatched stamp | Functional | pytest | any | n/a | T | P1 | `RunReport.to_json_dict()` gains an `environment` block (host CPU model, core count, OS, python version, engine git commit, store backend + server version, `pool_size`, `claim_mode`); `compare_to_baseline` returns a hard "environment mismatch — comparison refused" entry when the stamps differ on any pinned key, and a normal diff when they match; `SCHEMA_VERSION` bumped to 4 |
| PERF-18 | p99 latency folded into the baseline diff and gated | Performance | CI-leg | container-CI | x3 | T | P1 | `compare_to_baseline` already flags e2e p99; the nightly job additionally flags **ACK** p99 above `baseline*(1+tolerance)` and fails the job; a synthetic 3x p99 baseline makes it red while throughput is held flat |
| PERF-19 | "Harness-was-the-limit" boolean plumbed into `PhaseReport`, `_counters_dict`, JSON and CSV | Functional | pytest | any | n/a | T | P1 | `deferred_backpressure` and `deferred_schedule` appear per phase and in `totals`; a derived boolean `rig_was_the_limit` is true iff `deferred_schedule` dominates and `deferred_backpressure` is small; synthetic engine-bound counters yield false, rig-bound counters yield true, and all-zero deferrals yield `null` (not measured) rather than false |
| PERF-20 | The `W25:S4.2` / `W25:S4.7` acceptance steps become executable against the new flag | Performance | manual | W2025-box | x3 | T | P1 | Running `sustained-overload` per `W25:S4.7` produces a report in which `rig_was_the_limit` is a printed field; the operator's PASS/FAIL is read off it, not inferred. The measurement itself stays owned by WIN2025 §4 |
| PERF-21 | Estimand labelling: every published rate names what it counts, plus a deliveries/s headline | Functional | pytest | any | n/a | T | P1 | `achieved_msg_s` gains a sibling `achieved_estimand: "acked_per_wall_second"`; a `delivered_per_s` figure derived from `sink_received` (fan-out aware) is emitted per phase and in `overall`; the console render prints both with their labels; a test pins that no rate key exists without an estimand key |
| PERF-22 | Partner-RTT: injectable sink ACK delay and a `partner_rtt_ms` field stamped on every report | Performance | pytest | any | n/a | T | P1 | `CorrelationSink` accepts an ACK delay (default 0); the profile schema accepts `partner_rtt_ms`; the report always carries the value (0 rendered as "instant partner — not a real-partner ceiling"); a run at 25 ms shows measurably lower `delivered_per_s` than the same profile at 0 |
| PERF-23 | Knee-finder + per-step verdict over a rate ladder | Performance | pytest | any | n/a | T | P1 | A pure function takes the list of `PhaseReport`s from a rate-step profile and returns the highest step where achieved ≥ offered*(1−tol) AND e2e p99 stayed within a bounded multiple of the lowest step's, plus the step where it broke; a synthetic ladder with a known knee at r150 returns r100 as the ceiling and r150 as the break; a ladder with no knee returns "no knee within the ladder" rather than the top step |
| PERF-24 | The unconfirmed-send excusal cannot go vacuous: bound the connection-count floor arm | Negative/Security | pytest | any | n/a | T | P1 | A synthetic run where every send times out (`timeouts == sent`) and `unconfirmed_budget >= sent` FAILS `zero_loss` with a detail naming the dead ACK path; the existing de-flake case (14 stranded of 90, budget 4) still passes; the floor arm is clamped so `excused <= sent` in every branch |
| PERF-25 | Nightly `spike-burst` + `sustained-overload` at CI-feasible rates | HA/Resilience | CI-leg | container-CI | SQLite | T | P1 | Both profiles (rates scaled down via a CI variant) run nightly; PASS requires `zero_loss`, final `backlog == 0`, `in_pipeline == 0` within `max_drain_seconds`; **no** throughput floor is asserted; a deliberately stalled outbound makes the leg red |
| PERF-26 | Nightly `writeamp` at a small fan-out sweep, asserting drain and copies/msg | Cross-backend | CI-leg | container-CI | x3 | T | P1 | `MEFOR_LOAD_FANOUT` in {1, 4} produces reports whose `copies_per_message` differs by backend as documented in ADR 0141 (SQLite dedups an identical fan-out to 1 copy; SQL Server writes N) and whose `zero_loss` and drain hold; the leg fails if `copies_per_message` is `null` on a backend that wires the counter |
| PERF-27 | Soak instrumentation: RSS + handle count on the `--load` poller | Performance | pytest | any | n/a | T | P1 | `EngineSample` gains `handles` and `working_set_bytes` (reusing `connscale/probe.py FdSampler`); `EngineSummary` reports first-decile vs last-decile RSS and handle slope; both are `null` when unreadable, never 0; a synthetic monotonically-rising RSS series produces a positive slope and a flat series produces ~0 |
| PERF-28 | Soak SLO on RSS/handle slope | Performance | pytest | any | n/a | T | P1 | A new `max_rss_growth_bytes_per_hour` / `max_handle_growth_per_hour` SLO is accepted by the profile schema and emitted as `SloCheck`s; a synthetic leaking series fails, a flat one passes, and an unmeasured series abstains (check emitted with `observed == "not measured"`, run not failed) |
| PERF-29 | **Owner: purge-under-load measurement.** Retention running concurrently with sustained load: no throughput decay across purge passes | Performance | harness | dev-PC | x3 | T | P1 | A soak variant with retention enabled and a short purge interval; achieved msg/s in the last purge window is **≥ 0.85x** the first purge window's (a >15% decay FAILS the row); `zero_loss` holds; the run records ≥2 `RetentionPass` events. **STORE-18 points here** — purge/retention *correctness* stays owned by the STORE chapter, the *under-load measurement* is owned here and no separate work is scoped there |
| PERF-30 | ADR 0137 `max_pass_seconds` cap proven under load | Functional | pytest | any | SQLite | T | P1 | With a large purgeable backlog and a short `max_pass_seconds`, a pass returns `RetentionPass.capped is True`, its last-run marker is unadvanced, and the next scheduled pass resumes; with `max_pass_seconds == 0` the same workload returns `capped is False` |
| PERF-31 | **Owner: purge-under-load measurement.** Retention/purge does not stall intake: claim-path contention bound | Performance | harness | dev-PC | x2 | C | P1 | **Characterisation — the ACK p99 multiple has no agreed bar yet.** During an uncapped purge pass concurrent with load, the ACK p99 inside the purge window is measured against the pre-purge window and the ratio published; if it is material the finding is recorded and the `max_pass_seconds` default is re-opened as an owner decision (16.9 Q6). **STORE-18 points here.** Becomes a T row the day the owner records the maximum acceptable in-purge ACK p99 multiple |
| PERF-32 | Perf-flag default table test, keyed to the authorising ADR | Functional | pytest | any | n/a | T | P1 | One table test pins `group_commit_window_ms == 0.0` (ADR 0055 withdrawn), `fifo_claim_batch == 1` (ADR 0058), `fifo_claim_fold_reset/proc/prepared == False` (ADR 0114), `inline == False` (ADR 0057/0107), `fuse_thread_hops == False` (ADR 0071), `per_lane_wake == False` (ADR 0061), `batch_handoff_statements == True` (ADR 0075), `claim_mode == "pooled"` (ADR 0066), `pool_size == 40` (ADR 0062); each row names its ADR file and the test fails if that file is missing |
| PERF-33 | Withdrawn-lever startup warning: enabling `group_commit_window_ms > 0` logs a WITHDRAWN notice | Functional | pytest | any | SQLite | T | P2 | Constructing the store with a non-zero window emits a WARNING naming ADR 0055 as withdrawn by ADR 0099 and stating the premise is measured-false; the setting still functions (no behaviour change) unless the owner chooses removal (see 16.9 Q6) |
| PERF-34 | multishard shared-store zero-loss on a real server DB | HA/Resilience | CI-leg | container-CI | x2 | T | P1 | `harness multishard --engines 2 --store postgres` (and sqlserver) against the existing service containers: `zero_loss` asserted, `foreign_rows == 0`, `in_pipeline == 0` at drain on every engine; the SQLite single-writer carve-out at `tests/test_multishard_smoke.py:16-22` stays documented and unchanged |
| PERF-35 | In-process `run_estate` smoke at small N | Functional | pytest | any | SQLite | T | P1 | A test mirroring `tests/test_connscale_smoke.py` calls `harness.load.estate.runner.run_estate` with the `estate-smoke` profile at reduced N; N connections spin, the event-rate identity holds (hubs driven slower than simples), the no-loss reconcile passes, and the report populates FD/CPU/RSS peaks |
| PERF-36 | `--estate estate-smoke` and `--connscale connscale-smoke` executed through the real CLI in a nightly leg | Functional | CI-leg | container-CI | SQLite | T | P2 | Both CLI paths run to exit 0 nightly; the JSON report is written to the named path; the port-window allocation succeeds inside the runner's ephemeral range; the false coverage claim at `tests/test_connscale_smoke.py:15` is corrected in the same change |
| PERF-37 | Profile lint: gate-class profiles must carry `zero_loss` and a drain bound and ≥1 measured phase | Functional | pytest | any | n/a | T | P2 | A table test over every `harness/load/profiles/*.toml` (and the connscale/estate profiles) asserts each profile named by a CI leg carries `[load.slo].zero_loss = true`, a `max_drain_seconds`, and at least one `measured` phase; a profile that would silently become reporting-only fails the test |
| PERF-38 | Sub-floor measured phase is a load-time error, or every shipped profile clears the floor | Negative/Security | pytest | any | n/a | T | P2 | Either `load_profile_text` rejects a `measured` phase whose expected `sent` is below `_RATE_SLO_MIN_SENT` (200) when the profile declares `max_error_rate`, or a table test proves no shipped profile has one; a hand-built profile with a 50-message measured error-flood phase must not exit 0 |
| PERF-39 | Aggregate composition guard: no reported aggregate may exceed the measured concurrent run | Functional | pytest | any | n/a | T | P2 | Any aggregate the harness or a future capacity tool reports is `min(measured concurrent, Σ per-interface)`; a synthetic case with 16 lanes at 5.44/s measured and a 60/s per-lane ceiling reports 87/s, never 960/s; ADR 0074 §Decision 1 / AC-2 is corrected in the same change |
| PERF-40 | Per-process CPU attribution on the `--load` poller, with an explicit abstain | Performance | pytest | any | n/a | T | P2 | The `--load` report carries engine-subtree CPU-seconds and derived utilisation (reusing the `#220` same-PID-set fold at `connscale/probe.py:57-70`); when the PID set changes mid-window or the probe is unreadable the report emits `limiting_factor: "unattributed"` rather than a forced taxonomy pick |
| PERF-41 | Saturation alert asserted during a real overload run and silent during spike recovery | HA/Resilience | harness | dev-PC | SQLite | T | P2 | During the `sustained-overload` measured phase at least one saturation alert is emitted with `growth_per_second > 0`; during `spike-burst`'s recovery phase none is emitted; both read from the engine's alert stream, not from the pure detector |
| PERF-42 | Per-backend reference comparison run, three backends, one commit | Cross-backend | CI-leg | container-CI | x3 | T | P1 | `benchmark.yml` produces a `reference` report per backend at the same commit, each with the PERF-17 environment stamp; the transcription into TUNING-BASELINE names the artifact path; a backend whose run did not reach the top rate is recorded as "ladder incomplete", never as a ceiling |
| PERF-43 | SQL Server per-hop statement batching keeps commits/msg at 2.000 under a real load run | Cross-backend | CI-leg | container-CI | x2 | T | P1 | On the `load test (smoke, sqlserver)` leg, `txn_per_message_measured` from the report matches the analytical `3 + 2H + 2N` model for that profile's H and N within tolerance; on Postgres/SQLite the figure is `null` ("not measured") and the report says so rather than printing 0.0 |
| PERF-44 | `copies_per_message` never renders as a bytes figure and always names its backend | PHI | pytest | any | n/a | T | P2 | The console line and JSON both carry `copies_per_message_unit == "body copies (NOT bytes)"` and `copies_per_message_backend`; a test asserts no key matching `bytes_per_message` exists anywhere in the report schema (ADR 0141's refusal is enforced, not just documented) |
| PERF-45 | Report and CSV remain metrics-only under every new field added by PERF-17/19/21/22/27 | PHI | pytest | any | n/a | T | P0 | The existing `test_json_is_metrics_only_no_phi` is extended to the new blocks; no message body, control id, patient identifier, partner name or real hostname appears; the host stamp records CPU model / OS / core count but not the machine name unless the operator opts in |
| PERF-46 | `--load` reports written by any CI leg are metrics-only and safe to upload | PHI | CI-leg | container-CI | x3 | T | P0 | Every uploaded artifact under `out/load/` passes the publish forbidden-content guard; no `dryrun`/`generate` output is redirected into an artifact, ticket or log by any perf leg |
| PERF-47 | `require_unified_store` fail-closed proven end to end via the real CLI, not only the unit | HA/Resilience | pytest | any | SQLite | T | P1 | `messagefoundry supervise --config <2-engine-shard config> --db ./x.db` on a SQLite backend exits non-zero with the ADR 0063 message; no `x_a.db` / `x_b.db` file is created on disk; a single-engine-shard config keeps the bare `--db` path and starts |
| PERF-48 | `supervise` CLI help and the supervisor docstring no longer promise per-engine-shard SQLite | Functional | pytest | any | n/a | T | P2 | A doc-drift guard asserts neither `messagefoundry/__main__.py:129`'s `supervise --db` help nor `messagefoundry/pipeline/supervisor.py:7`'s module docstring describes a per-engine-shard store as the supported multi-engine-shard shape without naming the ADR 0063 refusal |
| PERF-49 | Reload under connection scale: the O(connections) quiesce-and-swap stays bounded | Performance | harness | dev-PC | x2 | C | P2 | **Characterisation — publishes a curve, no threshold.** The connscale reload probe (`probe.py time_reload`) records the reload round-trip at N = 500/1000/1500; the growth exponent and whether the round-trip fits inside the profile's drain window are published, and a superlinear curve is recorded as a finding. Becomes a T row the day the owner records a maximum acceptable reload round-trip at N = 1500 |
| PERF-50 | 1,500-connection connscale sweep on a server DB without fd/socket/worker exhaustion (ADR 0052 AC-2) | Performance | harness | W2025-box | x2 | T | P1 | `python -m harness --connscale connscale` at counts 500/1000/1500: `zero_loss` at every N, FD/handle count and empty-claims/sec monotone in N, no `EMFILE`/`WSAENOBUFS` in the engine log, pool acquire-wait p99 recorded per N. Owned as `FCP:SCALE-18` by FEATURE-COVERAGE-PLAN §P5 (rig-deferred, :285/:299) — this row is the execution record, not a new plan |
| PERF-51 | 1,500-connection estate demo at the calibrated event rate | Performance | harness | W2025-box | x2 | T | P2 | `python -m harness --estate estate-demo` with `store_backend` overridden to a server DB: 1,500 connections spin inside the `[3000, 4499]` port window, aggregate event rate converges within tolerance of `per_conn_event_rate * count`, `zero_loss` holds. **Blocked on owner sign-off of `simple_fraction = 0.72` and `hub_fanout = 3`** (16.9 Q2) |
| PERF-52 | 45M/day tracked measurement recorded against a repeatable command | Performance | external | cloud | x2 | C | P2 | **Characterisation — records a number and a gap, no threshold.** The shardcert ladder is run to its highest sustained rung with the PERF-02 filling term active; the resulting events/s is recorded against `TARGET_EVENTS_PER_S = 520.833` (`shardcert_ladder.py:101`) with the gap stated. Owned as `FCP:SCALE-19` by FEATURE-COVERAGE-PLAN §P5 (:286, :294 — explicitly "no in-repo pass/fail") — record, do not re-plan. Becomes a T row only if ADR 0052 AC-1 is re-ratified as a gating target (16.9 Q9) |
| PERF-53 | Per-engine-shard headroom sanity: adding an engine shard must not reduce the fleet aggregate | Performance | harness | cloud | x2 | T | P2 | Across K in {1, 2, 4} engine shards at a fixed offered rate per engine shard, aggregate **delivered**/s at K=2 and K=4 is **≥ 0.95x** the K=1 aggregate (a drop below that FAILS the row — it is not averaged away); each K holds `zero_loss` and `foreign_rows == 0`. A failure is diagnosed with pool acquire-wait and store DMV evidence, and the diagnosis does not excuse it |
| PERF-54 | cp314t canary widened toward the pure engine surface | Compat | CI-leg | container-CI | n/a | T | P2 | The weekly `freethread-smoke` job additionally runs the store, claim-path and pipeline test subsets that import no compiled-heavy extra; `sys._is_gil_enabled()` is still asserted false; the non-vacuous verdict step still fails a zero-collection run. ADR 0053's Phase-1 spike disposition stays owned by `FCP:SCALE-7` (FEATURE-COVERAGE-PLAN §P7, :377) |
| PERF-55 | Free-threading does not silently change a lever default or a claim-path invariant | Compat | CI-leg | container-CI | SQLite | T | P2 | Under 3.14t the PERF-32 default table test and the pooled/stage-dispatcher invariant tests pass unchanged; a divergence is reported as a free-threading finding, not a test flake |
| PERF-56 | **Pointer.** `docs/FEATURE-MAP.md` gains rows for **engine sharding**, `supervise`, connscale, estate, free-threading and capacity, and no row may be marked planned while a shipped-and-published counterpart exists (today: "Published throughput numbers + tuning baseline" is marked planned at `docs/FEATURE-MAP.md:158` although `TUNING-BASELINE.md` was published 2026-06-16) | Functional | — | any | n/a | T | P1 | Covered by the MIG chapter's consolidated FEATURE-MAP drift-guard row (the single row extending `tests/test_feature_map_claims.py`); no separate work scoped. The six perf-surface claims above are supplied to MIG as required content |
| PERF-57 | ADR 0074's amendment cross-links resolve | Functional | pytest | any | n/a | T | P2 | The existing ledger/link check covers `docs/adr/0074-adopter-capacity-estimator.md`; the two dead targets (`0107-inline-transaction-fusion.md` at :123, `0101-publishable-performance-numbers.md` at :146) are corrected to the real filenames (`0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md`, `0101-pre-registered-falsifier-discipline-for-performance-measurement.md`) and the check is green |
| PERF-58 | `docs/CI-QUALITY.md` gains a performance section describing what perf CI does and does not gate | Functional | pytest | any | n/a | T | P2 | The file names the nightly perf legs, states which are gating and which are reported-only, and links the baseline directory; a doc test asserts the section exists and names every perf workflow file present in `.github/workflows/` |
| PERF-59 | Capacity-estimator guard layer (ADR 0074 AC-1/3/5/6) buildable and tested independently of the gated measurement layer | Functional | pytest | any | x3 | T | P2 | If the owner authorises the guard layer (16.9 Q10): a run against a non-isolated store is refused; SQLite-derived knob rankings are never presented as server-transferable; a poller-zero or sink-capped run returns INCONCLUSIVE, not a number. No live throughput figure is produced. Owned as `FCP:SCALE-16` by FEATURE-COVERAGE-PLAN §P5 (:289, build-gated at :387) |
| PERF-60 | The reference performance floor is asserted somewhere, or explicitly relabelled | Performance | pytest | any | x3 | T | P1 | Either the nightly reference leg asserts TUNING-BASELINE's stated floor (≥200 msg/s sustained, ACK p99 ≤ 50 ms, e2e p99 ≤ 5 s) on a named runner class, or `TUNING-BASELINE.md:29` is edited to say the floor is a documentary sanity bar with no automated enforcement; a doc test pins whichever is chosen |
| PERF-61 | Outbound batch aggregation (ADR 0082) does not regress per-lane FIFO or zero-loss at fan-out | Cross-backend | pytest | any | x2 | T | P2 | With batch aggregation active at fan-out ≥ 8, per-lane first-arrival order at the correlation sink shows 0 inversions and `zero_loss` holds; the batch size actually used is reported so a silently-degraded batch of 1 is visible |
| PERF-62 | Windows failover recovery time under load is reported, never gated | HA/Resilience | manual | W2025-box | x2 | C | P2 | **Characterisation — the recovery *time* is recorded without a threshold.** The `--failover` run on the box records recovery time, promotion time, dropped-acked, duplicates and per-lane inversions; the correctness assertions (dropped-acked = 0, duplicates within `max_dup_rate`, inversions = 0) are already gated by the existing `test_load_failover_{postgres,sqlserver}.py` CI steps, so nothing new here can fail. Measurement owned by `W25:S4.9` — this row records the reporting contract only. Becomes a T row the day the owner records a maximum acceptable Windows recovery time |
| PERF-63 | Transform-cost wall sweep executed and recorded | Performance | manual | W2025-box | x3 | C | P2 | **Characterisation — publishes a curve, no threshold.** `MEFOR_LOAD_TRANSFORM=slow` with `MEFOR_LOAD_TRANSFORM_MS` over 1/2/5/10, restarting `serve` per point; the achieved rate vs transform cost curve is recorded with the estimand label from PERF-21. Owned by `W25:S4.4` — execution record only |
| PERF-64 | 8-hour soak on SQL Server with the PERF-27 instrumentation active | Performance | manual | W2025-box | x2 | T | P1 | The committed report carries first-vs-last-decile RSS and handle slopes, DB/WAL growth and dead-letter count; both slopes are inside the PERF-28 SLOs, `zero_loss` holds, and the last hour's achieved msg/s is **≥ 0.90x** the first hour's; the PASS/FAIL is read from the report, not from Task Manager. Scope owned by `W25:S4.6` (owner-resolved A1) — this row exists only because the instrumentation it depends on is new work |
| PERF-65 | **Multi-day soak spanning a local midnight and a DST transition** — the boundary case the 8 h run structurally cannot reach | Performance | manual | W2025-box | x2 | T | P1 | A ≥72 h continuous `--load` soak on a server DB whose window contains **at least one local midnight and one DST transition** (either a real transition, or the box TZ set to a zone whose transition falls inside the window — the TZ used is stamped in the PERF-17 environment block). PASS requires: `zero_loss`; RSS/handle slopes inside the PERF-28 SLOs across the whole window (not just per-day); achieved msg/s in the final 6 h **≥ 0.90x** the first 6 h; **exactly one** retention pass per configured interval across the DST step with `RetentionPass` start timestamps strictly monotone in UTC (no skipped and no double-run pass at the repeated/absent local hour); no log-rotation or metrics gap at either midnight; no session/token or lease expiry mis-computed across the transition. **Owned here** — the STORE chapter parks the multi-day soak as "stays manual" without giving it a row, and this row is that row |
| PERF-66 | **Systematic race detection on the contended claim paths** — repetition, not one-shot spot checks | HA/Resilience | CI-leg | container-CI | x3 | T | P1 | A nightly leg re-runs the contended async claim/handoff suites (`tests/test_batch_claim_fifo.py`, `test_batch_claim_worker.py`, `test_batch_claim_locking.py`, `test_claim_fifo_heads.py`, `test_pooled_rider.py`, `test_pooled_runner.py`, `test_per_lane_wake.py`, `test_stage_dispatcher.py`, `test_claim_phase_timing.py`) **N ≥ 50 times each** — via `pytest-repeat`'s `--count` (verified real, added to the `[dev]` extra in `pyproject.toml` and re-locked per §7, never ad-hoc installed) or an equivalent in-test repetition loop — under randomised test order with the seed printed and recorded. PASS = **zero** failures across all N repetitions on all three backends; a single failure at any repetition reds the leg and is quarantined with its seed and repetition index, never re-run to green. `pytest-rerunfailures` (already a dependency) is **disabled** on this leg so a flake cannot self-heal; the leg fails on a zero-collection run |

---

### 16.5 Detailed scenarios

#### S-PERF-A — Real 2-engine-shard `supervise` smoke over ONE unified store (PERF-06, PERF-10; the recovery extension in step 7 is executed under PIPE-01 / PIPE-14, which own it)

**Why narrative.** Three processes, two port bands, one store, and a mid-run kill. Run wrong
(per-engine-shard DBs, a single `--engine` without `--skip-preflight`, or a sink port inside the
inbound band) it either refuses to start or silently measures one engine shard.

**Preconditions.** A Postgres 16 or SQL Server 2022+ instance reachable from the runner, RCSI on for
SQL Server, `pip install -e ".[dev,postgres]"` (or `[dev,sqlserver]`). A config directory whose
inbound Connections carry two distinct engine-shard (`shard`) tags. `MEFOR_STORE_ENCRYPTION_KEY` minted at runtime,
never a committed literal. Store must be an isolated throwaway database — never a production store
(ADR 0074 hard requirement 1).

**Steps.**
1. Export the store env: `MEFOR_STORE_BACKEND=postgres`, `MEFOR_STORE_SERVER`, `MEFOR_STORE_PORT`,
   `MEFOR_STORE_DATABASE`, `MEFOR_STORE_USERNAME`, `MEFOR_STORE_PASSWORD`, plus
   `MEFOR_SECURITY_REQUIRE_SIGN_IN=false` for the poller and `MEFOR_EGRESS_ALLOWED_MLLP=127.0.0.1`
   for the loopback sink.
2. Mint the key:
   `export MEFOR_STORE_ENCRYPTION_KEY="$(python -c 'import base64, os; print(base64.b64encode(os.urandom(32)).decode())')"`.
3. Start the fleet: `python -m messagefoundry supervise --config <two-engine-shard-config> --base-port
   8765 --env dev`. Two children appear; engine-shard APIs land on 8765 and 8766 in sorted
   engine-shard order.
4. Confirm the topology before driving: `GET /connections` on 8765 lists only engine shard A's
   inbounds and on 8766 only engine shard B's. If either lists the other's, stop — the engine-shard
   tags are wrong.
5. Drive: `python -m harness --load smoke --engine http://127.0.0.1:8765
   --shard-engine http://127.0.0.1:8766 --skip-preflight --sink-port 2700
   --report-json out/load/supervise-2shard.json`. Every engine shard's `MEFOR_LOAD_SINK_PORT` must
   equal `--sink-port` so the one correlation sink aggregates both.
6. **Observation point (PERF-06):** the report's `no_loss` block. `engine_read` and `engine_written`
   are cluster sums (`enginepoll.py` de-dupes the primary URL, so passing 8765 twice cannot
   double-count). `zero_loss` must be true and `backlog == 0`.
7. **Recovery extension (owned by PIPE-01 / PIPE-14 — PERF-09 is a pointer to them):** repeat, and at
   ~50% into the measured phase `kill -9` the engine shard B child. The supervisor relaunches it.
   Observation point: query the store for rows whose owning engine shard is A and whose status moved
   `inflight → pending` during B's restart window — the count must be 0. Every B-owned in-flight row
   must be re-pended and eventually delivered.
8. **PERF-10 extension:** from the sink's per-connection arrival log, group deliveries by outbound
   lane. Each lane's deliveries must all be attributable to one engine shard for the whole run, and
   first-arrival order per lane must be monotone (0 inversions).

**Expected result.** Exit 0; `zero_loss` true; `in_pipeline == 0` on both engine-shard APIs at drain;
`at_least_once_redeliveries` within the profile's `max_dup_rate`; 0 cross-engine-shard FIFO
inversions; 0 A-owned rows re-pended by B's restart.

**Cleanup.** `kill` the supervisor (it terminates then kills children after the grace); drop the
throwaway database; delete `out/load/` if the run touched anything beyond metrics. No `.db` files
should exist — if `<stem>_a.db` / `<stem>_b.db` appear, that is PERF-47 failing.

---

#### S-PERF-B — Falsifying the filling term (PERF-01, PERF-02, PERF-03)

**Why narrative.** This is the P0 that retroactively invalidates published ceilings. The test must be
built to **fail on today's code** first, or it proves nothing.

**Preconditions.** No live engine — this is a pure unit exercise over `harness/load/report.py` and
`harness/load/shardcert_ladder.py`, plus one optional live confirmation.

**Steps.**
1. Build a synthetic `EnginePoller` double whose `samples` carry a monotonically rising `in_pipeline`
   across the measured phase (e.g. 0 → 5,000 over the hold) and whose final sample, taken after the
   generous drain window, reads `in_pipeline == 0`, `backlog == 0`.
2. Build matching `Counters` with `sent == acked`, `timeouts == 0`, `sink_received >= written`, so
   the reconcile passes cleanly.
3. Call `build_report` with a profile whose `[load.slo]` sets `zero_loss = true` and a generous
   `max_drain_seconds`. **Today this returns `result_ok is True`** — assert that first, as the
   red-baseline the fix must flip.
4. Add the filling term to `_run_slos` (a backlog-slope over the measured phase, or the shardcert
   `fill_ratio` shape reused: second-half median e2e vs first-half, with the
   `_FILLING_MIN_SAMPLES`-style abstain floor at `shardcert.py:817`). Re-run: `result_ok is False`,
   `exit_code == 1`, and the failing `SloCheck` names the slope.
5. Repeat with a flat `in_pipeline` trace — must still pass. Repeat with 5 samples — must abstain
   (check emitted, run not failed), never silently pass as steady.
6. For PERF-02, drive `classify_rung` with `no_loss=True, engine_ok=True, lane_inversions=0` plus a
   growth signal. Today it returns `SUSTAINED` (the docstring at `shardcert_ladder.py:1092` says so in
   capitals). After the change it must not.
7. **Live confirmation (optional, dev-PC, SQLite):** serve `harness/config/load`, run a hand-built
   profile at a rate ~2x the box's observed knee with a hold of 60 s and `drain_timeout_s = 600`.
   Today this exits 0. After the change it must exit 1 with the filling check named.

**Observation point.** `RunReport.slos` and the console `SLOs:` block; the `CEILING_GATE_VERSION`
stamp in the ladder JSON.

**Expected result.** A filling rung fails. A steady rung passes. A thin-data rung abstains.
`CEILING_GATE_VERSION` is bumped so a reader cannot compare a pre-change ceiling to a post-change one.

**Cleanup.** None (pure). If the live confirmation ran, delete the temp `.db` and the report; note
that any previously published ceiling measured without this term must be re-labelled (16.9 Q12).

---

#### S-PERF-C — Poller-zero contamination (PERF-04, PERF-05)

**Why narrative.** The failure mode is invisible by construction: the instrument reports the
all-clear value under exactly the condition it exists to detect.

**Preconditions.** Pure unit test against `harness/load/enginepoll.py`.

**Steps.**
1. Build a fake `EngineClient` whose `stats()` returns `in_pipeline = 0` and an empty
   `outbox_by_status`, whose `connections()` returns rows with `read = 0`, `written = 0`,
   `queue_depth = 0`, and whose `status()` returns a stable `db.size_bytes` — i.e. the shape a
   saturated or half-dead `/stats` produces.
2. Drive `EnginePoller.await_drain(timeout=5, interval=0.1)` while a `Counters` object shows `sent`
   climbing and `sink_received` far below `sent`. **Today `await_drain` returns a drain time**
   (`stable` is satisfied because `read` and `written` are both unchanged at 0, and all three depth
   gauges are 0). Assert that as the red baseline.
3. Add the staleness precondition: a sample is only eligible to satisfy drain if the cluster's
   cumulative `read` has advanced at least once since the baseline **and** the client's `sent` is
   non-zero, or if `uptime_s` advanced across samples while all counters stayed at zero for fewer than
   N ticks. Re-run: `await_drain` returns `None`.
4. Assert `build_report` then records the run as failing/inconclusive with `no_loss.detail` naming
   the sink-side counters as the primary loss authority, not the poller.
5. For PERF-05, feed a rung payload with zeroed engine counters and non-zero sink counts into
   `classify_rung` and assert `INCONCLUSIVE`.

**Observation point.** The return value of `await_drain`; `RunReport.no_loss.detail`; the rung
verdict enum.

**Expected result.** A zeroed engine can never produce a drained, zero-loss PASS.

**Cleanup.** None.

---

#### S-PERF-D — Vacuous unconfirmed-send excusal (PERF-24)

**Why narrative.** `report.py:598-601` names this gap in its own comment and declines to fix it
because a naive fix re-opens a historic de-flake. The test must protect both properties at once.

**Preconditions.** Pure unit test over `harness/load/report.py::_reconcile`.

**Steps.**
1. Case A (the regression that must FAIL): `sent = 100`, `timeouts = 100`, `read = 0`,
   `sink_received = 0`, `unconfirmed_budget = 100` (a small run where the connection-count floor
   dominates). Today `budget = max(100, 50) = 100`, `over_budget` is False, `excused = 100`,
   `read_short = 0`, and the intake floor `sent // 2 - read = 50 > 0` — so `floor_ok` is False and
   this one already fails. Re-run with `unconfirmed_budget = 100` and `read = 60` (a high read with
   no ACKs, the signature the comment names): the floor passes, `read_short = 100 - 100 - 60 < 0`
   passes, and the run reads zero-loss. **That is the case that must flip to FAIL.**
2. Case B (the de-flake that must still PASS): `sent = 90`, `timeouts = 14`, `read = 76`,
   `unconfirmed_budget = 4`. Must remain `ok is True`.
3. Case C (clamp): `timeouts = 150` with `sent = 100`. `excused` must clamp to `sent`; the bound must
   never degrade to `read >= 0`.
4. Implement: bound the floor arm of the budget (e.g. `budget = min(max(unconfirmed_budget, sent //
   2), sent - 1)` plus an explicit "ACK path dead" arm when `acked == 0 and sent > 0`), then re-run
   all three cases.

**Observation point.** `NoLoss.ok` and `NoLoss.detail`.

**Expected result.** A 100%-dead ACK path fails `zero_loss` at every run size, including the CI
smoke size; the historic de-flake case still passes.

**Cleanup.** None. Re-run `tests/test_load_runner.py` and the `load-test` nightly leg once before
merging — this touches the CI gate's own predicate.

---

#### S-PERF-E — Soak leak instrumentation and its SLO (PERF-27, PERF-28, PERF-64, PERF-65)

**Why narrative.** Multi-hour, destructive of disk, and the thing it measures only shows up in the
last decile.

**Preconditions.** For the unit half: none. For the live half: the W2025 box, SQL Server 2022+,
ODBC 18, disk headroom for 8 h of store + log growth, and the engine under the NSSM service identity
if coordinating with the production-posture story (`W25:S4.6` owns that decision). For the PERF-65
multi-day arm: ≥72 h of uninterrupted box time, disk headroom for three days of store + log growth,
and either a real DST transition inside the window or the box TZ set to a zone whose transition is.

**Steps.**
1. Unit half: extend `EngineSample` with `handles` and `working_set_bytes` sourced from
   `harness/load/connscale/probe.py::FdSampler` (already psutil-free, already subtree-aware, already
   carries the `#220` same-PID-set CPU fold). Feed a synthetic monotonically rising series and assert
   the first-vs-last-decile slope is positive; feed a flat series and assert ~0; feed an all-`None`
   series and assert the report says "not measured", never 0.
2. Add `max_rss_growth_bytes_per_hour` and `max_handle_growth_per_hour` to the `Slo` dataclass and
   `_run_slos`. Assert a leaking series fails and a flat one passes.
3. Live half: clone `harness/load/profiles/soak.toml`, raise the single `kind = "soak"` phase's
   `duration_s` to `28800`. **Preflight the clone** by loading it before the overnight run.
4. Run from the box: `python -m harness --load <clone.toml> --engine http://127.0.0.1:8765
   --db-backend sqlserver --report-json C:\srv\mefor\reports\load\soak-mssql.json --report-csv …`.
5. **Observation point.** The report's new RSS/handle slope fields and the two new `SloCheck`s — not
   Task Manager. Also `db_growth_bytes`, `dead_letters`, and the CSV's per-phase `achieved_msg_s`
   trend.
6. **Multi-day arm (PERF-65).** Clone again with `duration_s = 259200` (72 h) and start it so the
   window contains a local midnight **and** a DST transition (set the box TZ to a zone whose
   transition falls inside the window if no real one is due; stamp the TZ in the environment block).
   Leave retention enabled at a short interval so ≥1 pass falls on each side of the transition.
   Observation points beyond step 5: the `RetentionPass` start timestamps (strictly monotone in UTC,
   exactly one per configured interval across the repeated/absent local hour — no skip, no
   double-run), the log-rotation and `/metrics` scrape continuity at each midnight, and any
   lease/session/token expiry computed across the transition.

**Expected result.** Exit 0; `zero_loss`; `backlog == 0`; `dead_letters == 0` for well-formed
traffic; RSS and handle slopes within the SLO; last-hour throughput ≥ 0.90x the first hour's (final
6 h vs first 6 h on the 72 h arm). A leak now leaves a committed number, and a scheduler that
mis-handles the DST step reds the run instead of being discovered in production.

**Cleanup.** Drop the throwaway database and its transaction log; delete the store file and WAL if
SQLite; keep the JSON/CSV (metrics-only) as the soak artifact. Never run this against a production
store.

---

#### S-PERF-F — Retention/purge concurrent with sustained load (PERF-29, PERF-30, PERF-31)

**Why narrative.** Two schedulers contending for the same store. The failure is a throughput cliff
inside a window nobody is watching, and the default (`max_pass_seconds = 0.0`) is uncapped.

**Preconditions.** A server DB (the SQLite single-writer case is informative but not the production
shape). Retention enabled with a short interval and a short body-retention window so purges have real
work. Synthetic corpus only.

**Steps.**
1. Pre-seed the store by running a short high-fan-out load so there are purgeable bodies.
2. Configure `MEFOR_SECURITY_DELETE_MESSAGE_BODIES_AFTER_DAYS` and the retention interval so at least
   two purge passes fall inside the load window; leave `max_pass_seconds = 0` (the shipped default)
   for arm A.
3. Run a soak-shaped profile for long enough to span ≥2 purge passes, capturing the per-second rate
   series.
4. **Observation point.** `achieved_msg_s` in the last purge window vs the first; ACK p99 inside a
   purge window vs outside it; the retention runner's emitted pass records.
5. Arm B: repeat with a short `max_pass_seconds`. Assert at least one `RetentionPass.capped is True`,
   that the pass's last-run marker did not advance, and that the next pass resumed.
6. If arm A shows a material ACK p99 or throughput excursion inside a purge window, record it as a
   finding and re-open the uncapped default as an owner decision.

**Expected result.** Throughput and ACK p99 stay within tolerance across purge passes in at least one
of the two arms; the capped arm demonstrably caps and resumes.

**Cleanup.** Drop the throwaway store. Retention config is env-only, so nothing persists.

---

#### S-PERF-G — Re-measuring the engine-sharding speedup on the topology the engine actually permits (PERF-13, PERF-14)

**Why narrative.** The published η ≈ 0.85 was measured on per-engine-shard SQLite (`TUNING-BASELINE.md:150`)
five days before ADR 0063 made that topology illegal. Re-running it correctly is the only way the
number becomes true, and the run has to be driven from a box that is not itself the limit.

**Preconditions.** A server DB on its own host (co-locating it makes the store the measured wall). At
least 5–6 correlation-sink processes, or `--sink-ports` wide enough — a single local sink caps around
135–144 delivered msg/s and would otherwise be the measured wall. An isolated throwaway database.
The PERF-01/02 filling term merged, or the run is not publishable.

**Steps.**
1. `harness multishard --engines 1,2,4 --count <C> --per-conn-rate <R> --hold-seconds 60
   --store sqlserver --report-json out/multishard-ss.json` with `MEFOR_STORE_*` pointing at the
   server DB. Note `--db` is SQLite-only and must be omitted here.
2. Keep the per-engine offered rate fixed across K so the sweep answers "does adding an engine buy
   throughput", not "does raising the rate".
3. **Observation point.** Aggregate delivered/s per K (not intake — see PERF-21), zero-loss per K,
   `foreign_rows == 0` per K, pool acquire-wait p95/p99 per K (the discriminator between a claim wall
   and a pool bind, per the tripwire block at `enginepoll.py:191-214`), and the store's own wait
   stats if DBA access is available.
4. Derive η from delivered/s, not from acked/s, and publish it with the store host, pool size,
   `claim_mode`, and the sink-process count stamped alongside.
5. Edit `TUNING-BASELINE.md`: either replace the per-engine-shard-SQLite table or annotate it as historical
   and refused-by-`require_unified_store`.

**Expected result.** A unified-store η with its topology stated, or an honest finding that aggregate
does not scale with K on one store — which is itself the answer ADR 0063's scale story needs.

**Cleanup.** Drop the throwaway database; archive the metrics-only JSON under
`docs/benchmarks/results/<date>-multishard-unified/`.

---

#### S-PERF-H — Nightly overload and spike legs at CI-feasible rates (PERF-25)

**Why narrative.** Easy to run wrong: at CI rates the shipped `rate_start = 4000` overload phase just
saturates the runner's own NIC and loopback stack, and the leg then measures the runner.

**Preconditions.** A CI variant of each profile (do not edit the box-facing originals — WIN2025
Appendix D owns those numbers). SQLite store, hermetic, auth off, the secure PHI posture the existing
`load-test` leg already provisions.

**Steps.**
1. Add `spike-burst-ci.toml` and `sustained-overload-ci.toml` with the same **shape** (warmup →
   spike/overload → recovery/drain) and rates scaled to roughly 3–5x the runner's observed knee, not
   the box's.
2. Wire them into the existing nightly `load-test` job as extra steps against the same served engine,
   or as a sibling job so a failure is attributable.
3. **Observation point.** For each: `zero_loss`, final `backlog == 0`, `in_pipeline == 0` within
   `max_drain_seconds`, and the PERF-19 `rig_was_the_limit` boolean.
4. Assert **no** throughput floor. If `rig_was_the_limit` is true, the leg reports INCONCLUSIVE rather
   than PASS or FAIL — a runner-bound overload proves nothing about backpressure.
5. Negative check during development: stall one outbound destination and confirm the leg goes red on
   the drain bound.

**Expected result.** A backpressure regression (intake accepted past pipeline capacity, or a spike
that never drains) turns the nightly red. A slow runner turns it INCONCLUSIVE, not red.

**Cleanup.** The job already deletes its temp store; reports upload as metrics-only artifacts.

---

### 16.6 Automation disposition

**New pytest modules (name them).**

| Module | Covers | Effort |
|---|---|---|
| `tests/test_load_filling_gate.py` | PERF-01, PERF-03 — the filling/backlog-slope SLO on the `--load` verdict, abstain floor, red baseline | M |
| `tests/test_shardcert_filling_two_box.py` | PERF-02 — the filling term in `classify_rung` + `CEILING_GATE_VERSION` bump | M |
| `tests/test_enginepoll_staleness.py` | PERF-04, PERF-05 — poller-zero precondition, drain refusal, INCONCLUSIVE rung | M |
| `tests/test_load_report_environment_stamp.py` | PERF-17 — environment block, `SCHEMA_VERSION` 4, baseline mismatch refusal | S |
| `tests/test_load_report_attribution.py` | PERF-19, PERF-21, PERF-40 — deferred cause split in the report, estimand labels, deliveries/s, unattributed abstain | M |
| `tests/test_load_partner_rtt.py` | PERF-22 — injectable sink ACK delay + `partner_rtt_ms` stamping | S |
| `tests/test_load_knee_finder.py` | PERF-23 — knee-finder and per-step verdict over a synthetic ladder | M |
| `tests/test_load_soak_leak_slo.py` | PERF-27, PERF-28 — RSS/handle slope fields and their SLOs | M |
| `tests/test_perf_flag_defaults.py` | PERF-32 — the ADR-keyed default table test | S |
| `tests/test_load_profile_lint.py` | PERF-37, PERF-38 — gate-class profile requirements, sub-floor measured phase | S |
| `tests/test_estate_smoke.py` | PERF-35 — in-process `run_estate` at small N | M |
| `tests/test_supervise_real_subprocess.py` | PERF-08, PERF-47, PERF-48 — one real child, fail-closed CLI refusal, no per-engine-shard files, help-text drift | M |
| `tests/test_perf_doc_claims.py` | PERF-11, PERF-12, PERF-13, PERF-57, PERF-58, PERF-60 — sizing-tier provenance, built/not-built contradiction, engine-sharding-topology caveat, ADR 0074 links, CI-QUALITY perf section | M |
| `tests/test_retention_under_load.py` | PERF-30 — capped pass, unadvanced marker, resume | M |
| `tests/test_aggregate_composition_guard.py` | PERF-39 — min(measured concurrent, Σ per-interface) | S |

**Extends an existing module.**

| Existing module | Addition | Effort |
|---|---|---|
| `tests/test_load_report.py` | PERF-24 (three reconcile cases), PERF-44 (no bytes/msg key), PERF-45 (metrics-only over the new blocks) | S |
| `tests/test_feature_map_claims.py` | **No work here — PERF-56 is a pointer.** The MIG chapter owns the single consolidated FEATURE-MAP drift-guard row; this chapter only supplies the required content (engine sharding / `supervise` / connscale / estate / free-threading / capacity rows, and the `docs/FEATURE-MAP.md:158` planned-vs-published contradiction) | — |
| `tests/test_group_commit.py` | PERF-33 — the withdrawn-lever startup warning | S |
| `tests/test_saturation.py` (or a live sibling) | PERF-41 — alert emitted under real overload, silent in spike recovery | M |
| `tests/test_connscale_smoke.py` | PERF-36 — correct the false "run via the `--connscale` CLI in CI" docstring claim | S |
| `tests/test_outbound_batch.py` | PERF-61 — per-lane FIFO + zero-loss at fan-out with batch aggregation, reported batch size | M |

**New / changed CI legs.**

| Leg | Content | Effort |
|---|---|---|
| `ci.yml` job `supervise-engine-shard-smoke` (nightly + dispatch, PG and SS service containers) | PERF-06, PERF-10 — real 2-engine-shard fleet, kill-and-restart, ownership + FIFO assertions (the kill-and-restart *recovery correctness* assertions are owned by PIPE-01 / PIPE-14; this leg is the fleet that hosts them) | L |
| Steps appended to `sql server (store + connector)` and `postgres store` | PERF-10 — name `tests/test_shard_cert_sqlserver.py` so it actually executes. The two `test_shard_recovery_{sqlserver,postgres}.py` suites are wired by PIPE-01 / PIPE-14, not here (PERF-07 / PERF-09 are pointers) | S |
| `ci.yml` job `multishard-serverdb` (nightly) | PERF-34 — shared-store zero-loss on PG and SS | M |
| `ci.yml` extensions to `load-test` | PERF-25 (spike/overload CI variants), PERF-26 (writeamp at small fan-out), PERF-36 (`--connscale`/`--estate` CLI smokes) | M |
| `benchmark.yml` rework | PERF-15 (stop discarding the exit code), PERF-16 (baseline diff), PERF-18 (p99 gate), PERF-42 (per-backend at one commit), PERF-60 (floor decision) | L |
| `freethread-smoke.yml` widening | PERF-54, PERF-55 — engine subset under 3.14t, default table test under 3.14t | M |
| `ci.yml` job `claim-race-repeat` (nightly, x3 backends) | PERF-66 — the nine contended claim/handoff suites re-run N ≥ 50x under randomised order with a recorded seed, `pytest-rerunfailures` disabled, zero-collection fails the leg | M |

**New harness/probe capability.**

| Capability | Where | Effort |
|---|---|---|
| Filling / backlog-slope term on the `--load` verdict and the two-box rung classifier | `harness/load/report.py`, `harness/load/shardcert_ladder.py` | M |
| `/stats` staleness precondition | `harness/load/enginepoll.py` | S |
| Deferred-cause split + `rig_was_the_limit` in `PhaseReport`/JSON/CSV | `harness/load/report.py` | S |
| Estimand labels + deliveries/s headline | `harness/load/report.py` | M |
| Injectable sink ACK delay + `partner_rtt_ms` | `harness/load/sink.py`, `harness/load/profile.py`, `harness/load/report.py` | M |
| RSS/handle sampling on the `--load` poller (reuse `connscale/probe.py::FdSampler`) | `harness/load/enginepoll.py`, `harness/load/report.py` | M |
| Per-process CPU attribution + explicit `unattributed` abstain | `harness/load/enginepoll.py`, `harness/load/report.py` | M |
| Environment stamp + baseline stamp-match refusal | `harness/load/report.py` | S |
| Knee-finder + per-step verdict | new `harness/load/knee.py` | M |
| CI variants of the spike/overload profiles | `harness/load/profiles/` | S |
| A 72 h soak profile variant for the midnight/DST arm (PERF-65) | `harness/load/profiles/` (clone of `soak.toml`, `duration_s = 259200`) | S |
| `pytest-repeat` added to the `[dev]` extra + `uv lock` / `uv export` re-run (PERF-66) — verified real, never an ad-hoc install | `pyproject.toml`, `uv.lock`, `requirements.lock` | S |

**Stays manual, and why.** Everything in WIN2025 §4 that needs the real box: the per-DB baseline and
closed-loop ceiling on Windows Server 2025 under the NSSM service identity with real ODBC 18 and real
disk/NIC (CI structurally cannot produce it); the transform-cost wall sweep (a `serve` restart per
point); the fan-out write-amplification sweep at fan-out 1/10/50/100 with on-disk growth read via
`.db`/`-wal` size, `sp_spaceused`, `pg_database_size`; the 8 h SQL Server soak plus 1 h each on SQLite
and PostgreSQL, **and the ≥72 h midnight/DST soak (PERF-65) — owned by this chapter, not by STORE,
which parks the multi-day case as "stays manual" without a row**; the sustained-overload run driven
from the box so the dev-PC NIC cannot be the limit;
malformed/oversized/mid-frame injection under load (the corpus generator only emits hl7apy-conformant
messages, so the bad input comes from the PySide6 harness Compose/Send fault tabs on a desktop
session); Windows failover recovery *time*; store-service restart and NSSM bounce mid-load. Also
manual: the AWS two-box/three-box campaigns under ADR 0101 falsifier discipline, the 1,500-connection
connscale sweep and the estate demo (multi-minute, ~1,500-port budget, server-DB store), store-side
DMV attribution (LCK_M_U, PAGELATCH_EX, WRITELOG, SQL CPU%) and py-spy per-process splits, cp314t
bench figures for ADR 0054 AC-6, enterprise-hardware `E_core` and sustained durable-write IOPS
(BACKLOG #40), and the transcription/re-baseline decision for `TUNING-BASELINE.md`.

---

### 16.7 Environment, data & prerequisites

**Hosts and runners.**
- **W2025-box** (`WIN-NAFGLU5SH1J`): Windows Server 2025, NSSM, a dedicated AD service account or
  gMSA, and a desktop session for the PySide6 harness GUI (needed only for the malformed-under-load
  injection). Disk headroom for an 8 h soak's store + log growth — and for the ≥72 h midnight/DST
  soak (PERF-65) — and for high-fan-out write amplification.
- **container-CI**: GitHub-hosted `ubuntu-latest` (SQLite, PG 16, SQL Server 2022/2025 service
  containers) plus `windows-2022`/`windows-2025` where a Windows path is load-bearing. Nightly-cron
  minutes for the heavy legs. The self-hosted `mefor-win2025-sql` runner
  (`.github/workflows/selfhosted-win2025-sql.yml`) is dispatch-only and currently runs only the store
  / coordinator / DATABASE-connector suites — it is a candidate host for PERF-06/PERF-10 on real
  hardware but must stay dispatch-only (public repo; fork PRs must never reach it).
- **cloud**: the AWS bench rig — `m7i.4xlarge` engine box + `i4i.2xlarge` store box (local Nitro NVMe)
  + a separate load-generator box.
- **dev-PC**: unit-level and short live runs only; never a source of a published ceiling.

**Services, drivers, accounts.**
- SQL Server 2022 and 2025 (real instance for the box; service containers for CI), ODBC Driver 18,
  `sqlcmd`, RCSI enabled, `db_ddladmin` + `db_datawriter` + `db_datareader` grants.
- PostgreSQL 16/17 (real instance + service container).
- DBA-level DMV / perf-counter / wait-stats access on the store box for attribution runs
  (PERF-14, PERF-53).
- Project extras: `[dev]`, `[sqlserver]`, `[postgres]`, plus `[otel]` for the `/metrics` exporter.
  PERF-66 adds `pytest-repeat` to `[dev]` (declared in `pyproject.toml` and re-locked, per §7).
- Free-threaded CPython 3.14t plus cp314t wheels for pydantic-core, cryptography, argon2-cffi/cffi
  (PERF-54/55).

**Capacity of the rig itself (these are measurement prerequisites, not nice-to-haves).**
- **At least 5–6 correlation-sink processes** (or `--sink-ports` widened accordingly): a single local
  sink caps around 135–144 delivered msg/s and becomes the measured wall.
- A large contiguous ephemeral port budget: `estate-demo` occupies `[3000, 4499]`; connscale spins
  500/1000/1500 inbound listeners; the multishard sweep uses `--inbound-base`/`--sink-base`/
  `--api-base` bands with `--stride >= --count`.
- Two drive processes with disjoint `--engine-index-base` bands when the target aggregate exceeds one
  orchestrator process's own ~457 msg/s ACK ceiling.

**Data — synthetic only, always.**
- Corpora come from `messagefoundry generate` / `harness/load/corpus.py` (hl7apy-conformant triggers
  only) or the ADR 0030 anon framework. **No real PHI in any load run, ever.**
- Reports are metrics/metadata only — never message bodies or control-id lists. Every new field added
  by PERF-17/19/21/22/27 is covered by the extended metrics-only guard (PERF-45).
- `dryrun` / `generate` stdout can contain full bodies: never redirect it into a committed file, a
  ticket, or a CI log.

**Secrets and store hygiene.**
- `MEFOR_STORE_ENCRYPTION_KEY` is minted at runtime (32 random bytes, base64) in every leg that serves
  under the PHI posture — never a committed literal.
- **Every capacity/perf run uses an isolated, throwaway store.** Never the production store (ADR 0074
  hard requirement 1; the count-and-log invariant means a perf run's rows are real rows).
- Store passwords come from the runner's machine environment or CI secrets, never from this plan, the
  workflows, or a profile.

**Must be procured or stood up.**
1. A committed baseline directory `docs/benchmarks/baselines/<runner-class>-<backend>.json` and the
   convention for what a "runner class" is (PERF-16/17).
2. A unified-store multishard rig slot (store on its own host) for PERF-14 — the current published
   engine-sharding number cannot be reproduced without it.
3. Owner sign-off on the estate shape constants before PERF-51 can run.
4. A decision on whether the self-hosted W2025 runner takes the real-hardware engine-shard legs.
5. A ≥72 h uninterrupted booking of the W2025 box, plus the chosen DST-bearing time zone, for PERF-65.

---

### 16.8 Exit criteria

This area is signed off for release when **all** of the following hold:

1. **Every P0 T row (PERF-01 … PERF-13, PERF-45, PERF-46) is green or has a written owner waiver
   naming the risk it accepts.** No P0 may be closed by "not observed". PERF-07 and PERF-09 are
   pointer rows and close when PIPE-01 / PIPE-14 close. **PERF-14 is a C row and cannot gate** — it
   closes by publishing its number, not by passing.
2. **The filling term is live on both verdict paths** — the `--load` run verdict and the two-box
   `classify_rung` — with `CEILING_GATE_VERSION` bumped, an abstain path for thin data, and a red
   baseline test proving it fails a synthetic filling rung. Every ceiling published before the term
   existed is either re-measured or annotated as measured-without-the-filling-gate.
3. **A poller-zeroed run cannot report PASS or drained** on any path, proven by unit test.
4. **Engine sharding executes in CI**: at least one nightly leg spawns ≥2 real `serve --shard`
   subprocesses over one unified server-DB store, asserts zero-loss, ownership-scoped recovery across a
   mid-run kill, single-consumer-per-lane, and 0 per-lane FIFO inversions; and the three
   `MEFOR_TEST_*`-gated engine-shard suites are named by a CI step with collected>0 —
   `test_shard_cert_sqlserver.py` via PERF-10 here, `test_shard_recovery_{sqlserver,postgres}.py` via
   PIPE-01 / PIPE-14.
5. **`docs/SYSTEM-REQUIREMENTS.md` no longer contradicts itself or the measured record** — the
   built/not-built statement about multi-process scale-out is single-valued, and every sizing tier is
   either linked to a committed artifact or labelled UNVALIDATED. A pytest enforces both.
6. **The published engine-sharding speedup carries a topology that the engine permits** — either
   re-measured on the unified store or annotated as historical/refused, enforced by a doc guard.
7. **A throughput or latency regression can fail something**: `benchmark.yml` no longer discards the
   harness exit code, and a nightly reference run diffs against a committed per-runner-class baseline
   with an environment-stamp match, covering achieved rate, ACK p99 and e2e p99. A synthetic 5x
   regression demonstrably turns it red.
8. **Every published rate names its estimand**, a deliveries/s headline exists beside the intake rate,
   and `partner_rtt_ms` is stamped on every report (0 rendered as "instant partner").
9. **`rig_was_the_limit` exists as a report field**, so `W25:S4.2` / `W25:S4.7` / the §4 validity gate
   are executable as written.
10. **The soak leaves evidence**: RSS and handle slopes are in the committed report with SLOs, and one
    ≥2 h soak per server backend has been run with them active. **The ≥72 h midnight/DST soak
    (PERF-65) has run once** on a server backend with a clean retention-pass ledger across the
    transition, or carries a written owner waiver naming the boundary risk it accepts.
11. **Retention under load has a result** — either "no decay across purge passes at the shipped
    uncapped default" or a recorded finding plus an owner decision on the `max_pass_seconds` default.
12. **The perf-flag default table test passes**, pinning all nine flags to their shipped defaults with
    each keyed to its authorising ADR file.
13. **No gate-class profile lacks `zero_loss` + a drain bound + a measured phase**, enforced by lint.
    **The contended claim/handoff suites have run N ≥ 50x green under randomised order** on all three
    backends (PERF-66), with the seed recorded and no rerun-to-green.
14. **`docs/FEATURE-MAP.md` has rows for engine sharding, `supervise`, connscale, estate,
    free-threading and capacity**, and the drift guard forbids a planned marker on a
    shipped-and-published capability — closed by the MIG chapter's consolidated FEATURE-MAP row, to
    which PERF-56 points.
15. **All perf artifacts are metrics-only** and pass the publish forbidden-content guard; no perf run
    in this cycle touched a non-throwaway store or non-synthetic data.
16. **Open questions Q1–Q6 in 16.9 are answered in writing**; Q7–Q12 may remain open only with a
    recorded owner disposition attached to the release note.

---

### 16.9 Open questions

1. **Does the filling term ship before the next published number, and who signs the retraction?**
   Adding it retroactively invalidates ceilings measured without it — including the ~16 msg/s STEP-4
   plateau (`shardcert_ladder.py:1092` says so explicitly). *Blocks:* PERF-01, PERF-02, PERF-14,
   PERF-52, and any re-publication of `TUNING-BASELINE.md`.
2. **Sign-off on `estate-demo`'s `simple_fraction = 0.72` and `hub_fanout = 3`.** The profile marks
   both OWNER-CONFIRM; the 1,500-connection demo cannot be honestly run or published until the shape
   constants have recorded provenance. *Blocks:* PERF-51 and the ADR 0052 AC-2 demonstration.
3. **Are the SYSTEM-REQUIREMENTS sizing tiers re-derived from measurement or relabelled UNVALIDATED —
   and who owns fixing the built/not-built self-contradiction inside that same file?** *Blocks:*
   PERF-11, PERF-12, and any adopter sizing conversation.
4. **Is the published η ≈ 0.85 / `E_core` ≈ 42 engine-sharding result retracted, annotated as
   historical, or re-measured on the unified store?** It was measured on per-engine-shard SQLite, which
   `require_unified_store` now refuses. *Blocks:* PERF-13, PERF-14, and the multi-process sizing
   guidance in `TUNING-BASELINE.md` and `docs/SYSTEM-REQUIREMENTS.md`.
5. **Does `benchmark.yml` become a gating regression check with committed per-runner-class baselines,
   or stay report-only?** Today it is dispatch-only *and* discards the harness exit code, so no perf
   regression can fail anything. *Blocks:* PERF-15, PERF-16, PERF-18, PERF-42, PERF-60.
6. **Is `[store].group_commit_window_ms` removed from the shipped surface now ADR 0055 is withdrawn,
   or retained as dormant code with a startup warning?** *Blocks:* PERF-33 and the `FCP:STOREF-14`
   disposition in FEATURE-COVERAGE-PLAN §P7 (:362, :402). Also carries the `max_pass_seconds` default
   decision that turns PERF-31 from a C row into a T row.
7. **Is `supervise` multi-process engine sharding a SUPPORTED production topology yet?**
   `docs/SYSTEM-REQUIREMENTS.md:170-176` gates it on "the clean 4-engine no-loss bench (sustained, zero
   loss, per-lane FIFO)". Has that run, and where is the evidence? *Blocks:* PERF-06 scope (smoke vs
   certification), PERF-14, and whether the tiers may cite it at all.
8. **What is the release rule when the conformance tier passes but the performance tier sits an order
   of magnitude below the published sizing table?** `TUNING-BASELINE.md`'s two-tier gate says the
   performance figure is "recorded, never silently lowered" — does that still hold at a 7.23x gap?
   *Blocks:* the exit criterion for any release that quotes a throughput number.
9. **Does ADR 0052 AC-1/AC-2 remain a committed capability target** given four negative store-side
   falsifiers (ADR 0098) and a closed transaction-reduction path (ADR 0107), or is the target
   re-scoped? *Blocks:* PERF-52, PERF-53, and the framing of `FCP:SCALE-19`.
10. **Is ADR 0074's capacity estimator to be built at all, and against which revised gate and
    estimand?** The amendment gates the *measurement* layer on owner re-ratification; the fail-closed
    *guard* layer (AC-1/3/5/6) is buildable now. *Blocks:* PERF-59 and `FCP:SCALE-16`.
11. **Which box owns the recurring load runs now that BACKLOG #86 declined a self-hosted Actions leg —
    and at what cadence?** Should the 1,500-connection connscale/estate axes get a reduced-N nightly CI
    variant, or stay entirely operator-owned? *Blocks:* PERF-36, PERF-50, PERF-51, PERF-65
    scheduling (PERF-65 alone books the box for ≥72 h).
12. **Should the self-hosted `mefor-win2025-sql` runner take the real-hardware engine-shard legs
    (PERF-06/PERF-10, and the PIPE-01/PIPE-14 recovery suites PERF-07/PERF-09 point at)?** It is
    dispatch-only by security design and never required; adding perf legs
    to it changes nothing about that posture but does change who has to have the VM up. *Blocks:* the
    PERF-06 environment choice.
