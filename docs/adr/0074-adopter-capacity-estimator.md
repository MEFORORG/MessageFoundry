# ADR 0074 — Adopter-run capacity estimator: productize the harness rate-walk + zero-loss reconcile as a supported sizing command

**Status:** Accepted (2026-07-07) — owner ratified; build to follow (BACKLOG #96)
**Deciders:** owner (ratifies) + throughput working group
**Related:** BACKLOG **#96** (the item this ADR drafts), the **built** load harness [`harness/load/`](../../harness/load/) + [`docs/LOAD-TESTING.md`](../LOAD-TESTING.md) + [`docs/THROUGHPUT.md`](../THROUGHPUT.md) (the sizing method §7 this productizes); ADR 0069 (durable-write is not the wall — engine feed concurrency is; the ~97–107 msg/s pooled ceiling + store-exoneration figures), ADR 0066 (pooled stage claimers; the claim-storm limiting factor + the SQLite-vs-server knob divergence), ADR 0037/0063 (engine sharding on ONE unified store), ADR 0053 (free-threading path), ADR 0030 (anonymization / PHI-free datasets), ADR 0017 (consumer deployment model — the adopter the tester serves), ADR 0052 (enterprise scale target); BACKLOG **#28**/**#29** (the developer/benchmark harness runs), **#40** (enterprise-hardware CI leg), **#93** (the passive runtime overload-alert counterpart), **#64** (throughput-performance roadmap), **#74** (host CPU/mem sampling). Throughput-campaign evidence folded into #96 via PR #768.
**Code references** are `origin/main` tip at authoring; module paths are stable, line numbers approximate — locate exactly at implementation time. This ADR supersedes nothing.

---

## Context

An adopter deploying the engine on their own box (the ADR 0017 pinned-wheel + org-config pattern) needs to answer one concrete pre-cutover question: **"does *my* deployed box — this hardware, this store backend, this config — carry my ~36 msg/s hospital feed with headroom?"** Today that answer is a manual exercise: stand up the dev load harness, hand-drive it, and read [`benchmarks/TUNING-BASELINE.md`](../benchmarks/TUNING-BASELINE.md) by eye — expertise an adopter doesn't have and shouldn't need.

Capacity is **not a single portable number**. Every real throughput wall this project found was found by **measurement on specific hardware**, not by reading code: the per-box engine ceiling (~193 msg/s intake, engine-CPU-bound — BACKLOG #96 evidence, `ENGINE_CPU_PROFILE.md`), the ~97–107 msg/s sustained/peak ceiling at the 1,500-lane SQL-Server pooled shape ([ADR 0069](0069-durable-write-throughput-lever.md) §Context), the connection-scale claim-storm ([ADR 0066](0066-pooled-stage-claimers.md)), and the ~60 msg/s single strictly-ordered MLLP interface e2e bound ([`docs/THROUGHPUT.md`](../THROUGHPUT.md) §8). [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §8 states the principle in the doc itself: *"every published msg/s figure is hardware- and workload-dependent … treat all such numbers as starting points for your own measurement, not as guarantees."* An adopter reproducing that measurement **on their own box** is the only trustworthy sizing.

The forcing constraints are the CLAUDE.md invariants a capacity run must not violate. **Count-and-log** (CLAUDE.md §2, verbatim): *"every received message is persisted before the ACK … so inbound counts still reflect the true received volume and nothing is accepted-and-dropped."* A capacity run generates thousands of real store writes; run against the live store it would **inflate the true inbound counts** and leave synthetic rows in production. And the **PHI rule** (CLAUDE.md §9, verbatim): *"CLI `dryrun`/`generate` output can contain full message bodies … never run them against real PHI"* — a load run drives synthetic traffic and must stay synthetic-only, never real PHI.

## Decision

**Productize the existing harness rate-walk + zero-loss-reconcile methodology as a first-class, adopter-run capacity estimator** (a `messagefoundry capacity` subcommand — final name a to-resolve item) that drives controlled synthetic load through the **real** engine + store + config and reports:

1. an **estimated sustainable throughput per inbound interface** *and* an engine-wide aggregate (the sum across interfaces, never a single-feed number — the per-interface bound is by design, CLAUDE.md §12 / [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §7);
2. the **limiting factor** — a backend-aware label (engine-CPU-bound / claim-contention / pool-saturated / delivery-bound / host-TCP), not a bare number; and
3. **provision-at-≤50%-of-measured-ceiling** headroom guidance — size the deployment to run at no more than half the clean no-loss knee, leaving burst headroom (ADT traffic peaks at ~2.7× its daily average — [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §6; the exact fraction is a to-resolve item).

**Method (reuse, don't reinvent).** It packages the **built** machinery under [`harness/load/`](../../harness/load/) as a supported capability:

- a **stepped rate-walk** — a sequence of fixed-rate open-loop holds ([`harness/load/governor.py`](../../harness/load/governor.py) `RateGovernor._run_open`, token-bucket paced) climbing toward the saturation knee, where `in_pipeline` / backlog rises faster than drain (the #93 signal), reporting the **last step that drained cleanly with no loss** rather than a raw saturating peak;
- the **fast correlation sink** ([`harness/load/sink.py`](../../harness/load/sink.py) `CorrelationSink` + [`correlator.py`](../../harness/load/correlator.py)) for **true end-to-end** latency (p50/p95/p99), separate from intake ACK latency;
- the **drain gauge + no-loss reconcile** ([`harness/load/runner.py`](../../harness/load/runner.py) `sample_until_reconciled`, [`enginepoll.py`](../../harness/load/enginepoll.py)) — read ≥ confirmed-sent, sink-received ≥ written, pipeline empty — as the **only** success gate, so a reported ceiling is a *no-loss* ceiling;
- the **preflight** ([`runner.py`](../../harness/load/runner.py) `_preflight`) proving the target inbound ports are actually served before measuring.

**What it must NOT break:** it must not violate count-and-log against the live store (hence the isolated-store hard requirement below), must never carry real PHI, must not present a single blended throughput number (intake and delivery are separate walls), and must not present SQLite-derived knob rankings as if they transfer to a server backend.

## Hard requirements

1. **Isolated, throwaway store — refuse to run otherwise.** The estimator MUST run against a dedicated ephemeral/temp store (or a clearly-marked isolated namespace) and MUST **refuse to start** if pointed at a non-isolated / production store — never leaving synthetic rows in, or skewing the counts of, the live message store. This is the count-and-log invariant made operational: a capacity run's writes are test writes and must never enter the production inbound tally.
2. **Synthetic PHI-free payloads only.** Drive from the conformant generators ([`messagefoundry/generators/`](../../messagefoundry/generators/)) / the anon framework ([ADR 0030](0030-anonymization-test-harness-tee.md)) — never real PHI, and (per CLAUDE.md §9) never redirect the run's output to a committed file, ticket, or CI log.
3. **Backend-aware limiting-factor labels — the B12 lesson.** The named factor MUST be store-backend-aware. SQLite knob rankings do **not** transfer to server backends: B12 / per-lane-wake looked like a large win on **SQLite** (a call-count artifact) but had **no benefit on SQL Server** ([ADR 0066](0066-pooled-stage-claimers.md); BACKLOG #96 evidence). The tester MUST NOT carry a SQLite-derived ranking onto a server backend, and MUST NOT emit a single fixed "commit-bound" label — on a server deployment the per-box ceiling is **engine-CPU-bound** and the connection-scale wall is a **claim-storm** (contention), while store *commit* throughput carries large headroom (below).
4. **Explicit harness-ceiling caveats — label the limiting factor, don't over-claim a single-box number.** The measurement rig has its own ceilings that the tester MUST detect and disclose so it reports *where* the wall is rather than over-claiming:
   - a single driver process tops out at **~450 msg/s ACK** ([`docs/THROUGHPUT.md`](../THROUGHPUT.md) §8 intake ≈ 450/s; the harness single-driver attribution ceiling) — an intake number at that level may be measuring the driver, not the engine;
   - a local correlation sink caps at **~135–144 msg/s delivered per sink process** (BACKLOG #96), so an under-provisioned run (too few sinks — need ≥5–6, success = delivered ≈ offered) measures the sink, not the config;
   - the `/stats` poller can return **0 under overload** (poller-zero contamination — BACKLOG #96), so the tester MUST default to a **sub-ceiling rate-walk** (report the clean no-loss knee) and treat a single saturating hold as a stress check, not the capacity number.

## v1 scope

**v1 = rate-walk + backend-aware limiting-factor labels + per-interface & aggregate no-loss ceiling + headroom guidance.** That is the whole first cut. Fuller per-stage diagnostics — store-side DMV probes (`LCK_M_U`/`PAGELATCH_EX`/`WRITELOG`), py-spy engine CPU splits, per-process CPU attribution, io2-vs-NVMe storage A/Bs, N-engine multishard drivers — stay **future**. They belong to the developer benchmark campaign (#28/#29/#40) and would drift this adopter tool toward a general bench platform; v1 is deliberately minimal to avoid that scope creep. The prior-art artifacts for the deeper diagnostics (the off-repo `aws-bench/` toolbox named in BACKLOG #96) are the future-work source, not v1 dependencies.

## Grounding — known floors v1 must reproduce within tolerance

These are the measured/authoritative floors a v1 run **must reproduce within tolerance on comparable hardware** (the tester's own self-check — if it can't recover these on a known-comparable box, it is mis-measuring):

| Floor | Value | Source |
|---|---|---|
| Single strictly-ordered MLLP interface, e2e delivery | **~60 msg/s** (instant partner; serial-by-design per-interface bound) | [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §8; [ADR 0069](0069-durable-write-throughput-lever.md) |
| Intake (ACK-on-receipt), single driver | **~450 msg/s** (accept-and-persist, not delivery) | [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §8 |
| Per-engine intake ceiling (server backend) | **~193 msg/s**, engine-CPU-bound (N=1=193/s, N=2=383/s) | BACKLOG #96 evidence; `ENGINE_CPU_PROFILE.md` |
| Sustained / peak at the 1,500-lane SS pooled shape | **~97 / ~107 msg/s** | [ADR 0069](0069-durable-write-throughput-lever.md) §Context; [`benchmarks/adr0066-pooled-claimer-744.md`](../benchmarks/adr0066-pooled-claimer-744.md) |
| Store commit ceiling (store exonerated) | **~23,600–27,000 commits/s** (large headroom over the ~750/s pipeline feed) | [ADR 0069](0069-durable-write-throughput-lever.md); [`benchmarks/results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt`](../benchmarks/results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt) |
| Local correlation sink cap | **~135–144 msg/s per sink process** (need ≥5–6 sinks) | BACKLOG #96 |
| Single-hospital reference demand | **~36 msg/s** | Project sizing record (operator throughput matrix; off-repo — see *To resolve* item) |

> ⚠️ **Do not read the `N=1 = 193/s, N=2 = 383/s` pair as a shard-scaling law.** It is an **intake-only** measurement at **fan-out 1**. It says nothing about how the *delivery* path scales with engine-shard count on a shared store — the pooled outbound **claim query** is the measured wall there, not intake ([`benchmarks/outbound-claim-wall.md`](../benchmarks/outbound-claim-wall.md)). Whether per-shard capacity holds as `N` grows is **unmeasured**: it is BACKLOG **#218** (a 2-point probe) and **#215** (the full curve). The estimator must publish the adopter's own measured numbers and never extrapolate this pair.

These floors are also the tester's **limiting-factor discriminators**: intake near ~450/s ⇒ suspect the driver; delivery near a per-sink multiple ⇒ suspect the sinks; a server per-box plateau near ~193/s ⇒ engine-CPU-bound; a plateau that pooled claim mode lifts ⇒ claim-storm.

## Acceptance Criteria

> EARS form; each links (`→`) to the test/fixture that will verify it once the build is authorized. Placeholders until code exists — resolve on acceptance.

- **AC-1** — WHEN the estimator is pointed at a store that is not an isolated/ephemeral store, THE SYSTEM SHALL refuse to run (fail-closed) and emit an actionable error, never writing to the live store.
  → `tests/test_capacity_estimator.py::test_refuses_non_isolated_store`
- **AC-2** — WHEN a run completes, THE SYSTEM SHALL report the per-interface no-loss ceiling, the engine-wide aggregate, and a backend-aware limiting-factor label — never a single blended throughput number.
  → `tests/test_capacity_estimator.py::test_reports_per_interface_and_limiting_factor`
- **AC-3** — WHILE running on a SQLite store, THE SYSTEM SHALL NOT present SQLite-only knob rankings (e.g. per-lane-wake / B12) as server-transferable tuning levers.
  → `tests/test_capacity_estimator.py::test_backend_aware_labels`
- **AC-4** — IF the `/stats` poller returns zeros under saturation, THEN THE SYSTEM SHALL fall back to the sub-ceiling clean no-loss knee rather than reporting the saturating rate.
  → `tests/test_capacity_estimator.py::test_poller_zero_falls_back_to_knee`
- **AC-5** — THE SYSTEM SHALL drive only synthetic PHI-free payloads (generators / ADR 0030 anon), never real message bodies.
  → `tests/test_capacity_estimator.py::test_synthetic_only_payloads`
- **AC-6** — WHEN the sink provisioning is below the delivered rate (too few sinks), THE SYSTEM SHALL flag sink-capping so the run is not mistaken for an engine ceiling.
  → `tests/test_capacity_estimator.py::test_flags_sink_capping`

## Consequences

**Positive** — Sizing becomes a **supported operation** an adopter self-serves before a cutover, on their own hardware, without CI access or harness expertise; the #93 runtime overload-alert threshold gains a per-deployment capacity baseline to calibrate against; it reuses proven, adversarially-verified machinery ([`harness/load/`](../../harness/load/)) rather than a parallel measurement path; the isolated-store + synthetic-only requirements keep count-and-log and PHI invariants intact.

**Negative / risks** — The estimator ships as a supported surface, so its numbers carry an implicit promise; the harness-ceiling caveats (§Hard requirements 4) are load-bearing — an under-provisioned or poller-contaminated run can mislead if the caveats aren't enforced. Backend-aware labeling adds real complexity (the B12/SQLite trap must be encoded, not left to the operator). Reusing dev harness internals as a supported product surface pins a stability contract on modules that were previously dev-only — those seams now need change discipline.

**Out of scope (v1)** — store-side DMV probes, py-spy engine-CPU / per-process attribution, storage-tier A/Bs, N-engine multishard drivers (future, from the #96 `aws-bench/` toolbox); the developer/benchmark baseline runs (#28/#29) and the enterprise-hardware CI leg (#40); the passive runtime overload watcher (#93 — the pairing counterpart, separate item).

## Alternatives considered

| Alternative | Verdict | Why |
|---|---|---|
| **Productize the harness rate-walk + zero-loss reconcile** (this ADR) | **Chosen** | Capacity is hardware/store/config-specific; the only trustworthy sizing is a measurement on the adopter's own box, and the machinery already exists |
| Ship nothing; publish a **static sizing table** | Rejected | Capacity is hardware- and workload-dependent — [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §8 says so explicitly; a static number would mislead the exact adopters who most need a real answer |
| Point adopters at the **dev load harness + TUNING-BASELINE** (status quo) | Rejected | Requires harness expertise + a hand-built synthetic SUT config; not self-serve, and easy to misread (single-driver / sink-cap / poller-zero traps) |
| A **general benchmark platform** (all diagnostics up front) | Rejected for v1 | Scope creep toward a bench platform; v1 stays the minimal adopter estimator, deeper diagnostics deferred |
| Reuse the **#40 enterprise-hardware CI leg** | Rejected | That's a project baseline on project hardware; #96 is the adopter-run inverse on *their* hardware without CI access |

## To resolve on acceptance

- [ ] Final subcommand name (`messagefoundry capacity` vs `setup-test` vs other) and CLI surface (flags for target config, isolated-store path, sink count, rate-walk bounds).
- [ ] The exact headroom fraction to recommend (the "≤50% of measured ceiling" default — tie to the ADT ~2.7× peak factor or make it configurable).
- [ ] The precise isolated-store detection/refusal mechanism (temp DB vs marked namespace; how "non-isolated / production" is detected fail-closed across SQLite / Postgres / SQL Server backends).
- [ ] The limiting-factor label taxonomy and the exact engine/host signals each maps to (reusing #64/#74/#93 signals; which are v1 vs future).
- [ ] Confirm the single-hospital **~36 msg/s** reference demand's canonical citation — it currently lives in the off-repo operator throughput matrix, not an in-repo artifact; either land an in-repo reference or cite the sizing record explicitly.
- [ ] Whether v1 reports msg/day alongside msg/s (peak-aware, per [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §6) or msg/s only.

## References

- BACKLOG **#96** — the item + the 2026-07 throughput-campaign evidence (folded in via PR #768).
- [`harness/load/`](../../harness/load/) — `runner.py` (orchestration + `sample_until_reconciled` no-loss reconcile), `governor.py` (rate-walk), `sink.py`/`correlator.py` (e2e correlation), `enginepoll.py` (drain gauge). [`docs/LOAD-TESTING.md`](../LOAD-TESTING.md).
- [`docs/THROUGHPUT.md`](../THROUGHPUT.md) §6–§8 — the sizing method + reference lab measurements + caveats this productizes.
- [ADR 0069](0069-durable-write-throughput-lever.md) (feed-concurrency wall + store exoneration), [ADR 0066](0066-pooled-stage-claimers.md) (claim-storm + SQLite-vs-server knob divergence), [ADR 0030](0030-anonymization-test-harness-tee.md) (PHI-free data), [ADR 0017](0017-consumer-deployment-model.md) (the adopter), [ADR 0052](0052-enterprise-scale-target.md) (the scale target).
