# ADR 0074 — Adopter-run capacity estimator: productize the harness rate-walk + zero-loss reconcile as a supported sizing command

**Status:** Accepted (2026-07-07) — owner ratified. ⛔ **BUILD GATED (2026-07-14)** — a validity re-check against the STEP-4 Arm-0 findings found the ADR's **premise and hard requirements still hold**, but its **measurement method is materially stale and one part is unsafe to productize as written**: the "no-loss reconcile" it names as *the only success gate* is the very gate Arm 0 proved **over-reports** (a filling rung passes it while E2E latency runs away). **Do not build the measurement layer until the owner re-ratifies the revised gate + estimand** — see the [Amendment](#amendment-2026-07-14--validity-re-check-vs-step-4-arm-0-build-gated) below. (The fail-closed **guard** layer — AC-1/3/5/6 — is unaffected and remains buildable.)
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


---

## Amendment (2026-07-14) — validity re-check vs STEP-4 Arm 0 (BUILD GATED)

> **Trigger:** the STEP-4 Arm 0 findings (2026-07-13, adversarially verified) plus [ADR 0107](0107-inline-transaction-fusion.md) landed after this ADR was ratified (2026-07-07). This amendment re-checks ADR 0074 against them and against the shipped `harness/load/` code. It **does not supersede** the ADR; it gates the build of its measurement layer and corrects its Grounding section.

### Verdict

**The premise, the hard requirements, and the fail-closed guard layer still hold. The measurement method does not.**

This ADR names the drain gauge + no-loss reconcile as **"the *only* success gate, so a reported ceiling is a *no-loss* ceiling"** (§Method). STEP-4 Arm 0 proved that gate **over-reports**: a rung whose in-flight backlog grows through the entire hold passes it (E2E climbed **455 ms → 50,672 ms** while no-loss *and* eventual-drain both PASSED — it drained only *because the offer stopped*). The code says so about itself, unprompted:

> `harness/load/shardcert_ladder.py:1044-1054` — **"NO FILLING TERM — and that is a KNOWN GAP** … A rung can be lossless-and-drained yet still have been FILLING … **Every two-box ceiling — including the ~16 msg/s STEP-4 plateau — is therefore measured WITHOUT the filling gate**, and may over-report the sustainable rate by counting a still-filling rung as SUSTAINED."

Five further defects are **independent of the filling gap** and each errs in the same (unsafe) direction — over-reporting capacity to a hospital sizing a cutover. **Do not build the measurement layer until the owner re-ratifies the revised gate + estimand.** The guard layer (AC-1 / AC-3 / AC-5 / AC-6) is untouched and remains buildable.

---

### Confirmed blockers (verified against the code, not inferred)

**B1 — The named success gate over-reports, and the ADR has no safety net against it.**
`sample_until_reconciled` (`harness/load/enginepoll.py:162-199`) settles on `read >= sent - timeouts ∧ sink_received >= written ∧ in_pipeline == 0` — **every term evaluated after the offer stops**. Nothing observes in-hold backlog growth. The rung classifier does not abstain; it returns `SUSTAINED`. **No AC and no Grounding row of this ADR contains a latency, filling, or backlog-slope term** — every floor is a throughput floor. The ADR's own safety net does not contain the defect. (§Method *does* gesture at a filling-aware knee — "where `in_pipeline` / backlog rises faster than drain (the #93 signal)" — but the next bullet then declares no-loss the **only** gate, and the module cited for that knee, `governor.py::RateGovernor._run_open`, is a bare token-bucket with zero occurrences of `in_pipeline`/backlog/knee. The ADR is internally inconsistent and **the inconsistency resolves toward the unsafe reading**.)

**B2 — Drain-clearance is defeasible by construction: the gate admits 3–5.5× the true sustainable rate.**
With offer *R* > true capacity *C* over hold *H*, backlog (R−C)·H drains at *C*, so the rung passes iff **R ≤ C·(1 + D/H)**. STEP-4 ran `--hold-seconds 120 --drain-timeout 240` ⇒ **R ≤ 3C**. The shipped ladder defaults are `hold_seconds=20.0` / `drain_timeout=90.0` (`shardcert.py:711,715`) ⇒ **R ≤ 5.5C**. **The ≤50% headroom rule cannot absorb this** — half of a 3–5.5× over-report still provisions at **1.5–2.75× capacity**. Either require D ≪ H, or drop drain-clearance as a sustain criterion and rely on a filling term.

**B3 — The estimand is intake acceptance, not delivery — the exact conflation Arm 0 retracted.**
The step-reading rule is "the highest step where **achieved ≈ offered**", and `achieved = acked / rec.wall_seconds` (`harness/load/report.py:333, :361`) — an **ACK** rate. `_is_ceiling`'s second term is `achieved_intake < offered * (1 - _INTAKE_TOL)` (`shardcert.py:1061`), explicitly *"Deliberately **not** `delivered < offered`"*. Arm 0 retracted **"engine sustains 26"** precisely because 26/s was ingress acceptance against ~16 msg/s delivery. Per [ADR 0101](0101-publishable-performance-numbers.md), the reported figure MUST state its estimand or be quoted in **deliveries/s**. This defect lives in the ADR's *named* path — it is not fixable by switching paths.

**B4 — The engine-wide aggregate is defined as a *sum across interfaces*; that composition rule is measured-false.**
§Decision item 1 and AC-2 require "an engine-wide aggregate (**the sum across interfaces**)". The repo refutes it on the shipped default shape: `docs/benchmarks/THROUGHPUT-STATUS-2026-07-10.md:352-355` — *"(a)'s 87 delivered/s across 16 lanes is **5.44/s per lane** — far below (c)'s 60/s per-lane ceiling. Those lanes are starved **upstream** by a **store-side** wall."* Summing per-interface ceilings predicts 16 × 60 = 960/s against a **measured 87/s — an ~11× over-report**. Arm 0 corroborates: at the plateau, outbound lane occupancy is ~46% of a ~277 deliveries/s structural per-lane cap. **The aggregate MUST be a measured concurrent multi-interface run**, reported as `min(measured concurrent aggregate, Σ per-interface)` — never composed. `docs/THROUGHPUT.md:260`, the ADR's cited authority for the sum rule, needs the same correction.

**B5 — The measured ceiling is an *instant-partner* ceiling, and the ADR never says so.**
`harness/load/sink.py:3-11` — the CorrelationSink *"**is** the engine's outbound destination … and **immediately ACKs `AA`**. Speed is the contract."* Every outbound is redirected to it, and delivery *must* go to it because the reconcile is `sink_received >= written`. But `docs/THROUGHPUT.md:239` sizing step 2 is *"**Apply your partner's real acknowledgement time … This is usually the biggest reduction**"* — §2's worked example shows a 25 ms partner ACK cutting an interface from ~60 to ~24 msg/s (**2.5×**). ADR 0074 has **no partner-RTT input, no partner-RTT reported field, and no caveat**, while promising to answer *"does **my** box carry **my** feed"*. This over-report is orthogonal to B1 and survives every filling fix.

**B6 — AC-4 is circular: the poller-zero failure mode *satisfies* the gate.**
BACKLOG #96 is specific about which fields die: *"the engine `/stats` poller returns **0** for `engine_read`/`delivered`/**`in_pipeline`**/`pool.idle` under overload, so **the exact pass criteria go unmeasured in the runs that most need them**."* Now read the gate — `enginepoll.py:304`: `if cur.backlog == 0 and cur.queue_depth == 0 and cur.in_pipeline == 0 and stable:` → drained, where `stable` is `cur.read == prev.read and cur.written == prev.written`. **Two consecutively zeroed samples are trivially "stable"**, so an overloaded rung reads as *drained in one poll interval*. And §Method's knee is read from **the same zeroed fields**. AC-4 therefore instructs the tool to fall back to a knee derived from the signal that just died. (Memory-trap #1 — *a check that cannot fail in the regime it exists for* — compounded by trap #4.) **A `/stats` health/staleness detector must be a hard precondition; a poller-zeroed rung is INCONCLUSIVE, not "fallen back"; the independent sink-side counters must be the primary loss/backlog authority.**

**B7 — "Reuse, don't reinvent" is false for the two pieces that matter: there is no knee-finder and no per-step gate.**
`grep -rn "knee" harness/` returns **only TOML comments — zero code**. `harness/load/profiles/reference.toml:53-55` concedes the per-step e2e is *"the **SIGNAL used to read the knee (reported, not pass/failed)**"* — i.e. **step selection is a human eyeball today**, the exact expertise §Context exists to remove. Worse, `[load.slo] zero_loss = true` is a **whole-run** verdict taken after a cooldown *designed* to "drain whatever backlog the post-knee steps built" — it is structurally incapable of *ranking or rejecting an individual step*, and by construction **passes a run that climbed past the knee**. The only automated rung classifier in the repo is `shardcert_ladder.classify_rung` — a module this ADR never names, on a two-box path, carrying its own known filling gap. **v1 must BUILD the knee-finder + a per-step gate**; the Method premise ("packages the **built** machinery") and any effort estimate resting on it do not hold.

**B8 — The mandatory limiting-factor label is unsatisfiable as v1 is scoped.**
BACKLOG #96, verbatim: *"**store-side DMVs** (`LCK_M_U`, `PAGELATCH_EX`, `WRITELOG`, SQL CPU%) — these, **not** engine counters, **named the actual wall in both WS-B and WS-C, so an engine-only tester would mis-diagnose**."* §v1 scope puts store-side DMVs, py-spy splits and **per-process CPU attribution** out of v1, while §Decision item 2 / AC-2 / HR-3 *require* a backend-aware label. Irreconcilable. Compounding: (i) the project's own attribution policy forbids a bottleneck claim without client isolation + per-process CPU + nonzero collectors — v1 has none; (ii) an adopter running on **their own box** is structurally **co-located**, which `shardcert.py:2202-2203` says invalidates attribution; (iii) the taxonomy is a **closed set with no abstain**, yet the only wall the project has localized on the shipped default is *"**store-side — but UNNAMED**"* — a label the taxonomy cannot express. **A classifier with no "unattributed" outcome will confabulate one of five wrong answers.**

**B9 — HR-3, a *hard requirement*, commits the very B12 error it forbids, and hard-codes a withdrawn attribution.**
HR-3 forbids one fixed label while **mandating two others**. (a) The **~193 msg/s "per-engine intake ceiling (server backend)"** has provenance `dests=1`, **SQLite**, **ACK only, no delivery** (`THROUGHPUT-STATUS:262, :347`) — carrying a SQLite-derived figure onto a server backend is exactly what HR-3/AC-3 prohibit. (b) **"Claim-storm" is WITHDRAWN**: *"the inference 'therefore the claim is the wall' is **WITHDRAWN** — C4 put the claim at **#2**…, C6 found no convoy"* (`:258`); and the pooled-vs-`per_lane` sign **inverts** at high fan-out (`per_lane` sustains ≥28 ingress/s where the shipped `pooled` default collapses at 16). (c) The delivery path is **not CPU-bound at all**: engine CPU was *"only 5–10% of 16 cores … a **software pacing/serialization** limit"*. **HR-3 keeps only its NEGATIVE rule; every positive attribution is deleted, and the discriminator sentence under the Grounding table goes with it.**

**B10 — The Grounding table cannot serve as a self-check.**
(i) The ~193/s row is mislabeled "(server backend)" — see B9. (ii) The **~450 msg/s** row is recast as *"the harness single-driver attribution ceiling"* when its **only cited source attributes it to the ENGINE** (`THROUGHPUT.md:275`), and no 450/s driver cap exists anywhere in `harness/load/*.py` or `docs/LOAD-TESTING.md` — so *"intake near ~450/s ⇒ suspect the driver"* would flag a **correct** measurement as a rig artifact, and it sits **2.3× away from the 193/s intake row with no rule for choosing between them**. (iii) **"~107 peak"** is a **burst-drain rung** — peak in-pipeline **8,782**, ACK p99 **4.6 s** (`benchmarks/adr0066-pooled-claimer-744.md:83`) — which a corrected sustain gate must **FAIL**; requiring the tester to reproduce it **institutionalizes over-reporting**. Only the ~97 row (backlog 553, ACK p99 0.44 s) is bounded. (iv) **`ENGINE_CPU_PROFILE.md` does not exist in the tree** — it is an off-repo `aws-bench/` artifact that §v1 scope itself calls *"the future-work source, **not v1 dependencies**"*, while §Grounding makes reproducing floors sourced from it a mandatory v1 self-check. (v) *"reproduce within tolerance"* names **no tolerance** and pins **none** of the axes these numbers are functions of (fan-out, claim mode, shard count, backend, partner RTT, gate used).

**B11 — The ≤50% rule's base rate is unstated, and its 2.7× justification is internally inconsistent.**
If the halved rate is the **daily average**, the peak hour lands at 0.5 × 2.7 = **135% of the ceiling** — underwater. Absorbing a 2.7× burst needs **≤ 1/2.7 ≈ 37%**. `THROUGHPUT.md:240` resolves it the safe way (apply the burst factor **first**, so the operating rate is already the peak and the 50% is pure extra margin) — but this ADR never says which rate it halves, and by offering 2.7× as the **justification** for 50% it invites the unsafe reading.

**B12 — The report has no latency term at all; a utilization fraction can never certify an SLA.**
§Method collects true E2E p50/p95/p99 via the CorrelationSink — and then the three reported outputs and **every** acceptance criterion contain **no latency, no p95, no SLA**. The tool measures the knee and throws it away. A utilization fraction bounds latency **amplification** (~1/(1−ρ)), never **absolute** latency — with a slow partner ACK inflating baseline E2E (B5), even ρ = 0.5 can breach a sub-second SLA. **The fix is cheap: the data is already gathered.**

**B13 — The sink-cap remedy has no implementation in the ADR's named path, and AC-6 has no INCONCLUSIVE outcome.**
`harness/load/runner.py:59-65` constructs **one** `CorrelationSink` with `ports=tuple(sink_port + i for i in range(sink_ports))` — those are *ports inside one process*, and the ~135–144 msg/s cap is **per sink *process***. In the path §Method names, the cap **cannot be relieved at all**. Multi-*process* sinks exist only in `shardcert.py`'s drive, which this ADR never mentions, and it fails loud when `sink_count > dests` — so the **~36 msg/s single-hospital adopter with 1–2 outbound destinations can provision at most 1–2 sink processes**, hard-capping the *measurable* delivered rate with no remedy.

**B14 — Downstream artifacts carry the stale text and would ship the gate holes even if only this ADR is amended.**
`docs/adr/README.md:104` (stale status; repeats "poller-zero ⇒ sub-ceiling knee" and "~135–144/s per sink" as settled guidance); `docs/testing/FEATURE-COVERAGE-PLAN.md:298, :1237` — **SCALE-16** directs building *"poller-zero knee **AC-4**"* first, as *"correctness/PHI-safety assertions **independent of any live number**"*: **AC-4 is not independent of a live number — it is circular (B6)**; `docs/BACKLOG.md:4077-4079` (the HR-4 source text); `docs/THROUGHPUT.md:260` (the aggregate-is-the-sum rule).

---

### Corrections to the audit (recorded so the record stays honest)

**The Grounding floors are NOT stale, and Arm 0 does NOT contradict them.** Arm 0's shape is `dests=8`, fan-out-to-**all**-8, 4 shards, pooled ⇒ *"~16 msg/s ≈ **128 outbound-deliveries/s** (16.122 × 8)"*. The ADR's "~97 / ~107 msg/s at the 1,500-lane SS pooled shape" is a **fan-out-1 delivered** rate — the source table's column is literally `deliv/s`. Normalized to delivery events, **Arm 0 (128/s) sits slightly *above* the floor, on the same rig class. Same wall, same order, no conflict.** The ~60 msg/s single-lane bound was **never tested** by Arm 0 (lane occupancy ~46% of a ~277 deliveries/s cap — the lanes are starved upstream), and `THROUGHPUT-STATUS §4` **already reconciles** these numbers. Do not carry "stale floors" into the gate; it would wrongly discredit valid measurements. The table's problem is **provenance + its derived discriminator line** (B9/B10) — an editorial and method correction, not a refutation of the measurements.

**"The table mixes estimands" is overstated.** It labels every estimand in-row, and AC-2 already forbids a blended number. The estimand defect that is real lives in the **method** (`achieved = acked/wall`, B3), not in the table.

**"≤50%-of-ceiling is the WRONG estimand — size on the latency knee instead" is overstated, and its direction is backwards.** 0.5 × 16 msg/s = **8 msg/s**; the latency knee is **~12 msg/s**. **8 < 12** — against a *correctly measured* ceiling the 50% rule is **stricter than the knee** and already forbids the 12–16/s multi-second queueing regime. It is **INCOMPLETE, not wrong**: a no-loss ceiling fraction is the right answer to the loss/burst question this ADR asks, and the latency knee alone says nothing about loss or burst absorption. **Size on the MIN of both** — do not swap. The rule's true fragility is that its margin is parasitic on the ceiling being real: the 8-vs-12 gap tolerates at most a **1.5×** over-report, and the retracted *"engine sustains 26"* was a **1.6×** over-report that actually happened. **The defect is in the ceiling estimator (B1/B2/B3), not in the 50% fraction.**

**S_lane (#1036) is NOT a validated safer estimator, and the build gate must not be lifted on it.** What survives: the instrument is real and shipped (`messagefoundry/pipeline/phase_timing.py:246-429`, lever `MEFOR_PIPELINE_LANE_EPISODE_TIMING`), it measures service time **directly** (no Little's law), and being engine-side it side-steps the harness's own driver/sink/poller-zero ceilings. What does not: **(i)** `1/S_lane` is an **UPPER BOUND by its own specification** — it excludes lane **DWELL** (ready-deque wait + the 0.25 s sweep wake gap, measured at +50–58 ms elsewhere); the dwell instrument is **unbuilt**. **(ii)** The `utilization` term that *"makes the negative branch falsifiable"* is `occupied_s / (elapsed × lanes)` — **load-dependent by construction**, so a deliberately sub-saturation run lands systematically on the pre-registered branch *"REFUTES: the lanes do not bind"*. The safety property being sold is purchased by discarding the term that keeps the number honest. **(iii)** A **sibling service-time reciprocal has already over-predicted this engine's ceiling by 2.2–2.6×** (λ_max ≈ 34.7–41.0 msg/s vs ~16/s measured) — the exact direction that makes a hospital sizing tool unsafe. **(iv)** It emits **one blended line per STAGE, never per lane** (a lane key is a `destination_name` — PHI), so it **structurally cannot deliver this ADR's per-interface number**. **(v)** It sees **no loss**, cannot see the pooled-claimer or engine-CPU bounds, and is **pooled-mode only**. **(vi)** It has produced **zero measurements** (Arm 1 cancelled; the minimal run unstarted; the observer-effect control never run; the published procedure even names the **wrong env lever**). Correct next step: run the minimal S_lane experiment **across a rate ladder** as a **parallel track** — a candidate cross-check, never a gate-lifter.

**Nit:** `sample_until_reconciled` lives in `enginepoll.py:162`, not `runner.py` (which imports it). Every other named path still exists — `governor.py::RateGovernor._run_open`, `sink.py::CorrelationSink` + `correlator.py`, `enginepoll.py`, `runner.py::_preflight`.

---

### What still holds

| Part | Status |
|---|---|
| **The premise (§Context)** — capacity is not a portable number; every real wall was found by measurement on specific hardware | **HOLDS, strengthened.** Arm 0 and ADR 0107 are two more walls found only by measurement. |
| **HR-1 / AC-1** — isolated, throwaway store; refuse to run otherwise | **HOLDS. Buildable now.** Count-and-log made operational; untouched by every finding. |
| **HR-2 / AC-5** — synthetic, PHI-free payloads only | **HOLDS. Buildable now.** CLAUDE.md §9 + ADR 0030; untouched. |
| **HR-3's *negative* rule + AC-3** — SQLite knob rankings do not transfer to a server backend | **HOLDS, and matters more now** — see B9, where the ADR breaks its own rule. Keep the prohibition; delete the positive labels bundled with it. |
| **"Never a single blended number — intake and delivery are separate walls"** (§Method, AC-2) | **HOLDS, vindicated.** Arm 0's retraction of "engine sustains 26" *is* this error. The ADR states the right rule; its method then violates it (B3). |
| **HR-4's *existence*** — the rig has its own ceilings; detect and disclose them | **HOLDS as a principle.** The specific ceilings need repair (B6, B13), but "label *where* the wall is rather than over-claim" is correct, and is what STEP-4's gate architecture independently converged on. |
| **Store commit ceiling / store exoneration** (~23,600–27,000 commits/s) | **HOLDS, independently re-confirmed.** ADR 0107 killed the transaction lever *because* commit cost is not the wall — an adversarial second confirmation. **The one Grounding row with clean, in-repo, still-current provenance.** (It exonerates commit *bandwidth*, not the store tier generally.) |
| **The `N=1=193 / N=2=383` caveat block** | **HOLDS — the ADR's best paragraph.** "Intake-only, fan-out 1, unmeasured (#218/#215), never extrapolate." **This is the template every other Grounding row must be rewritten to**: {estimand, fan-out D, claim mode, shard count N, backend, partner RTT, gate used}. |
| **The Alternatives table** | **HOLDS.** All four rejections survive; the findings attack the *method*, not the choice. |
| **v1's exclusion of bench-platform diagnostics** | **HOLDS as a scope judgment** — but it now collides with AC-2 (B8). Resolve by **shrinking the claim** (abstain-capable label), not by growing v1 into a bench platform. |
| **The "To resolve" list** | **HOLDS** — every item still open; items 2 (headroom fraction) and 5 (~36 msg/s citation) are now **load-bearing**, not cosmetic. |
| **The fail-closed GUARD layer as a whole** (AC-1, AC-3, AC-5, AC-6-with-INCONCLUSIVE) | **HOLDS and is buildable today**, independent of any live number. **AC-2 and AC-4 are not** — AC-2 rests on a broken estimand + a false composition rule; AC-4 is circular. |

---

### Required changes before the measurement layer is built

1. **Demote the reconcile** from "the **only** success gate" to a **NECESSARY-BUT-NOT-SUFFICIENT correctness gate**, and **add a filling/stationarity term** to the sustain bar. A rung is SUSTAINED only if it is no-loss **AND non-filling**. Where the term cannot be computed the tool MUST report **INCONCLUSIVE** — never a silent `filling=False` beside a printed number. (`_FILLING_RATIO = 1.5` is **inherited and provisional**, calibrated store-side on a *different* quantity; re-calibrate before an adopter-facing tool quotes a fill_ratio-gated ceiling.)
2. **Bound the drain window** (D ≪ H) or drop drain-clearance as a sustain criterion — otherwise the gate is defeasible by an operator-chosen number (B2).
3. **Fix the estimand**: define the ceiling on **DELIVERY**, not `achieved ≈ offered` (intake). Add **ADR 0101** to *Related*, plus an AC: *every reported figure states its estimand, and every limiting-factor label names the signal that could have refuted it.*
4. **Measure the aggregate**; never compose it. Report `min(measured concurrent aggregate, Σ per-interface)`, and correct `docs/THROUGHPUT.md:260`.
5. **Handle partner RTT**: take `--partner-ack-ms` and inject it at the sink, **or** report the figure as an explicit **instant-partner upper bound** with a mandatory THROUGHPUT.md §7 step-2 derating.
6. **Rewrite AC-4** (poller-zero): a `/stats` staleness detector is a **hard precondition**; a zeroed rung is **INCONCLUSIVE**; sink-side counters are the primary loss/backlog authority.
7. **Rewrite AC-6** (sink-cap) with an **INCONCLUSIVE** outcome, and state that the ADR's named path (`runner.py`) cannot add sink **processes** at all.
8. **Make the limiting-factor label abstain-capable** (add `unattributed`), or grow v1's signals — but the ADR currently mandates the label while forbidding the evidence.
9. **State which rate the ≤50% halves** (average ⇒ ≤37%; peak ⇒ drop 2.7× from the justification).
10. **Add a latency/SLA output**: `--sla`, report the highest rung meeting it, size on `min(headroom_fraction × no_loss_ceiling, knee(SLA))`.
11. **Restate the Grounding table** row-by-row in the `N=1/N=2` caveat style; correct the 193 row to SQLite/intake-only; delete or re-source the 450 "driver ceiling"; drop the claim-storm discriminator; **drop "~107 peak" as a reproduction target**; state a numeric tolerance; resolve or remove the `ENGINE_CPU_PROFILE.md` citation.
12. **Add AC-7**: *WHEN a rung is lossless and eventually drains but its in-hold E2E latency is rising (filling), THE SYSTEM SHALL NOT report that rung as sustainable, and SHALL report the highest NON-FILLING rung as the ceiling.*
13. **Amend the downstream artifacts** (`docs/adr/README.md:104`, `FEATURE-COVERAGE-PLAN` SCALE-16, `BACKLOG` #96, `THROUGHPUT.md:260`) in the same change, or the gate holes ship regardless of what this ADR says.
14. **Re-price v1.** The knee-finder and per-step gate **do not exist** — "reuse, don't reinvent" does not hold for the two load-bearing pieces.
