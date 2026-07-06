# ADR 0069 — Durable-write is not the throughput wall; the lever is engine feed concurrency

**Status:** Proposed (2026-07-03)
**Deciders:** throughput working group
**Related:** ADR 0066 (pooled stage claimers), ADR 0055 (group-commit / durable-write), ADR 0001 (staged pipeline), ADR 0037 / ADR 0063 (sharding on a unified store), ADR 0053 (free-threading); [`docs/throughput-roadmap.md`](../throughput-roadmap.md), [`docs/throughput-build-plan.md`](../throughput-build-plan.md)

---

## Context

Pooled claiming (ADR 0066) removes the empty-claim contention that made the per-lane default collapse at high fan-out; the 2026-07-03 at-scale campaign ([`docs/benchmarks/adr0066-pooled-claimer-744.md`](../benchmarks/adr0066-pooled-claimer-744.md)) proved it — at 1,500 interfaces `per_lane` **breaches zero-loss** while `pooled` holds it, at a pool-independent ceiling of **~97 msg/s sustained / ~107 peak**.

The campaign labelled that ceiling **"store-write-bound"** (identical at `pool_size` 40 and 128, `pool_wait` pegged at the cap). This ADR records that **that label was wrong**, corrects it with a direct measurement, and settles the resulting question: *is a durable-write-tier lever — app-side group-commit, faster log storage, a bigger pool — worth building?* The answer is **no**; the wall is the engine-side pipeline **feed**, not the store.

## The decisive measurement — a commit-storm on the campaign's own store box

Prior work (B8, [`docs/throughput-roadmap.md`](../throughput-roadmap.md)) measured a single-store commit ceiling of **~23,600 commits/s** on an AWS **i4i.2xlarge** local Nitro SSD (durable commit ~170 µs, WRITELOG ~141 µs). That was a *different* run; this ADR did not rely on transferring it. Instead a driver-free commit-storm was run **on the campaign's own store box** — raw ODBC `INSERT`+`COMMIT` loops, one heap table per thread so the transaction log is the only shared resource ([`results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt`](../benchmarks/results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt)):

| threads | commits/s | avg log write | dominant wait |
|---:|---:|---:|---|
| 1 | 1,671 | 0.10 ms | WRITELOG |
| 8 | 10,201 | 0.14 ms | WRITELOG |
| 32 | 23,577 | 0.17 ms | WRITELOG |
| 128 | **27,178** | 0.25 ms | WRITELOG |

**Raw store ceiling ≈ 27,000 commits/s** at 128 threads, log writes sub-millisecond throughout, and the store coalesces log flushes unaided (~19:1 at 128 threads — but only ~1.5–2.3:1 at the 16–32 concurrency the pipeline actually runs). This is a **zero-contention upper bound** — per-thread heap tables, tiny rows, no shared-index maintenance and no `UPDLOCK` claim convoy — so the real pipeline (which writes a shared, indexed queue and contends on the very claim path named below) tops out *under* it; read the precise "36×" as a ceiling, not usable headroom. The staged pipeline issues only **~750 commits/s** at its ~107 msg/s ceiling (~7 commits/message). The conclusion survives a large discount: even a heavily-discounted store ceiling dwarfs ~750/s, and it is independently corroborated by pool-independence (below) and the roadmap's 96%-idle serial-round-trip diagnosis. **The store is not the bottleneck; the pipeline under-feeds it.** (B8 independently put the same instance class at ~23,600 commits/s.)

Why `pool_wait` was pegged despite that headroom: workers queue on the contended shared-queue **claim path**, not on durable-write capacity. Store CPU burns on the empty-claim `UPDLOCK` convoy (cf. WS-C, "~92% store CPU at zero messages"). **Same symptom (store CPU saturated), different root cause (claim contention, not commit throughput), different fix (engine concurrency, not storage).**

## Why each durable-write-tier lever buys ~0 (measured, not argued)

- **App-side group-commit (server backends):** group-commit amortizes the *fsync*. But the durable commit is only ~170 µs — **~6% of the ~2.84 ms serial round-trip** the roadmap identifies as the wall (the other ~94% is network + query + claim) — and the store has commit-rate headroom besides, so there is nothing to amortize that moves the needle. This is distinct from cutting the **number** of round-trips per message (a *latency* lever — Decision 2/3): group-commit does **not** reduce round-trip count (the engine still issues the same `COMMIT`s), so it cannot be what closes the feed gap. ADR 0055's native-knob rulings stand independently: SQL Server `DELAYED_DURABILITY` **rejected** (relaxes durability — could ACK a crash-erasable PHI message), PostgreSQL `commit_delay` **deferred** (durability-neutral but only coalesces concurrently-in-flight txns; ~1.00× predicted).
- **Faster log storage:** the commit-storm measured log writes at **0.10–0.25 ms** on local Nitro NVMe (`commit_storm.txt`) — already the fastest local tier (network-attached EBS such as io2 Block Express is *slower*, not faster). Storage is not the constraint; a proposed io2-vs-NVMe A/B was therefore not run.
- **Bigger connection pool:** `pool_size` 40 vs 128 gave the *identical* ~107 msg/s ceiling.

## Decision

1. **Do not build any durable-write-tier throughput lever** — app-side server group-commit, faster log storage, or a larger pool. Each is measured to buy ~0 against this workload. Reaffirm ADR 0055's `DELAYED_DURABILITY` rejection and `commit_delay` deferral.

2. **The throughput lever is engine-side pipeline-feed concurrency / claim depth** — close the ~36× feed gap so the pipeline can drive thousands of commits/s into a store that absorbs ~27k. This ADR does not re-decide the specifics (owned by the roadmap / build-plan); it directs effort there:
   - **Pooled claim mode (ADR 0066, #744)** — removes the empty-claim convoy; the first concurrency lever. *Flip pending the campaign evidence + rider gate.*
   - **Higher stage concurrency** — build a **shared per-stage claimer** (its own ADR to follow) plus executor sizing (build-plan B5), so more messages are in flight against the store's headroom. This is the decided next build after the pooled flip.
   - **Engine per-message CPU** — in the higher-concurrency regime the wall becomes engine CPU (build-plan: cross-thread future marshaling ~41%, thread-pool executor ~25.8%); levers are the executor split (B5), batching SQL statements per executor hop, and free-threading (ADR 0053).

3. **Commit amplification is a SECONDARY lever, and largely blocked — not spent.** B1 (inline fast-path 7→5), B2 (batch-claim), B3 (seq-only) all shipped, yet the campaign still commits **~7×/message** (750/107): B1's 7→5 is the **no-transform** fast path (default-OFF / inapplicable to the campaign's transform-bearing handlers), and B3 dropped a `SELECT` read round-trip, not a `COMMIT`. Further reduction for transform-bearing messages is **invariant-blocked** — `route_only`/`transform_one` run *off the loop* between a claim and its handoff, so claims cannot fuse with handoffs, and the poison-guard claim must stay standalone (below). So ~7 is close to a floor here; commit amplification ranks **below** concurrency because the reachable reduction is small, not because it is already banked.

## Correction to the record

This supersedes two earlier framings: the campaign write-up's **"store-write-bound"** (corrected here to *claim-contention-bound, with 36× store headroom*), and the roadmap's **"#1 lever = collapse the commit depth"** — that lever (B1) has **shipped**; the roadmap recommendation predates its own completion. The write-up and its `environment.txt` are updated alongside this ADR.

## Invariants any claim / concurrency work must preserve

- **ACK-on-receipt** — inbound ACKed only after the raw message is durably committed to the ingress stage. *(CLAUDE.md §2; ADR 0001 §3.)*
- **Per-handoff atomicity** — each stage handoff a single committed transaction (`claim → produce-next → complete`), idempotent on re-run. *(ADR 0001 §2.)*
- **Poison-guard stays standalone** — the `claim` (`attempts+1`) must never share a rollback fate with post-claim work. *(ADR 0055 AC-2 + the claim ADRs; note ADR 0001's original design showed `attempts+1` fused into the handoff txn — the standalone requirement is the later refinement.)*
- **Finalizer sole authority**, in-transaction, and **no durability relaxation**. *(CLAUDE.md §2.)*

## Consequences

- **Positive:** no effort spent on store-tier levers the measurements prove are no-ops; effort concentrates where the ceiling actually moves (engine feed concurrency); the reliability core is fenced by an explicit invariant list.
- **Negative / risk:** the engine-concurrency levers (shared claimer, executor split, free-threading) touch the reliability-critical pipeline and warrant their own ADRs + adversarial-invariant tests; free-threading carries the ADR 0053 caveats.
- **Scope:** the ~9 M/day campaign figure is a *single, standalone, best-case-storage* number, **not** enterprise (45 M/day) capacity — that remains a DB-tier / horizontal-scale question (ADR 0037/0063) *plus* this feed fix. Under a sync availability group with a **co-located (sub-ms RTT) replica**, per-commit replica-ack latency lowers the store's rate but leaves it well above ~750/s, so the feed stays the wall — and because the feed is itself serial-round-trip-bound, that added latency slows the *feed* too, which only strengthens the conclusion. (This AOAG extrapolation is the one point here not directly measured; cross-region sync replication is a separate misconfiguration, out of scope.)

## Alternatives considered

| Alternative | Verdict | Why (measured) |
|---|---|---|
| App-side server group-commit | **Rejected** | Fsync is ~6% of the round-trip + store has commit headroom; and it doesn't cut round-trip count |
| SQL Server `DELAYED_DURABILITY` | **Rejected** | Relaxes durability (crash-erasable ACK) — ADR 0055 |
| PostgreSQL `commit_delay` | **Deferred** | Durability-neutral but ~1.00× predicted; needs concurrent bunching — ADR 0055 / B9 |
| Faster / dedicated log storage | **Rejected** | Already sub-ms on the fastest tier (Nitro NVMe); storage isn't the wall |
| Bigger connection pool | **Rejected** | 40 vs 128 → identical ~107 msg/s |
| Further commit-depth collapse | **Mostly done / blocked** | B1–B3 shipped; residual is invariant-blocked (off-loop claim↔handoff, standalone poison-guard) |
| **Engine feed concurrency** (pooled + shared claimer + engine-CPU) | **Chosen** | Where the ~36× headroom is reclaimed; owned by roadmap/build-plan |
| Horizontal scale (engine+store pairs / sharding) | **Complementary** | The path beyond one store (ADR 0037/0063); orthogonal |

## References

- [`docs/benchmarks/results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt`](../benchmarks/results/2026-07-03-adr0066-pooled-atscale/commit_storm.txt) — the decisive commit-storm (~27k commits/s zero-contention ceiling; large store headroom over the ~750/s feed).
- [`docs/benchmarks/adr0066-pooled-claimer-744.md`](../benchmarks/adr0066-pooled-claimer-744.md) — the at-scale campaign (pool-independence; ~750 commits/s pipeline feed).
- [`docs/throughput-roadmap.md`](../throughput-roadmap.md) (B8 store ceiling; the serial round-trip diagnosis: ~2.84 ms/round-trip vs ~170 µs fsync) and [`docs/throughput-build-plan.md`](../throughput-build-plan.md) (B1–B3 chain-cut DONE; engine per-message CPU as the current wall; B5/B6).
- ADR 0055 (group-commit; native-knob rulings), ADR 0066 (pooled claimers), ADR 0001 (staged-pipeline invariants).
