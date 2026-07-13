# HANDOFF for dev — C6-LIVE (convoy decomposition) + the combined C5/C6 conclusion

**Date:** 2026-07-12 · **From:** AWS bench (route onward via operator) · **Run:** c6-wait-decomposition
**Engine build:** `98bec81` (pinned = C3/C4/C5). **No engine patch** — C6 changed no code.
**Engine-box deviation (record it):** ran on **m7i.4xlarge (16 vCPU)**, CHANGED from C4's m7i.2xlarge (upsized for C5, kept for C6). Store box i4i.2xlarge, unchanged (`n_sched=8`).

## C6 verdict
**AMBIGUOUS — STRUCTURAL**, on both pre-registered contrasts (they agree). The N=8 and N=16 collapses are **NOT
blocked on a resource convoy.** The §3(a) convoy floor (≥5 sessions suspended on one `resource_description`, or a
blocking chain ≥2 deep, in ≥50% of samples) was met in **0/72 samples on every arm**; across all 288 samples the
largest suspended group ever seen was **2**, max chain depth **1**. The waiters that exist are scattered `mfbench`
USER pages (db_id 5, a different page each sample — not a hot page) + `CXSYNC_PORT` parallelism. No VOID (never a
tempdb `2:1:*` catalog page — feature held).

- **Not WAIT-BOUND** (no lock chain, no shared-latch/page convoy). **Not SPILL** (no `RESOURCE_SEMAPHORE`/spill
  convoy → the C4 `list_fifo_lanes` intrinsic-vs-spill residual does NOT resolve to spill). **Not CPU-BOUND** —
  runnable climbs to 52 on 8 schedulers and `SOS_SCHEDULER_YIELD` is huge, but §4 makes that **context**, and
  CPU-BOUND is precluded by the offline 64.4% reconciliation.
- **Discipline note:** `WRITELOG` is rank-1 in the fenced, exclusion-set-filtered wait delta of **every** arm —
  including the 100%-delivered N=4 floor. That is the proof a wait's *rank* cannot name a wall; the convoy
  instrument correctly named nothing. (This corrects the C5 §6 misread — see `REVIEW_C5_handback §2`.)

## What C5 + C6 together conclude (the actionable takeaway)
- **C5:** per-shard ceiling `R ∈ [2,3) < 3.62` → **N-sizing is insufficient on its own.**
- **C6:** the collapse is **aggregate/structural, not a nameable convoy** → **not fixable by a contention fix or a
  single-query CPU rewrite.**
- **Therefore the path is the `txn/event` levers** — Phase-3 `accepts=` (batch accept), Phase-4 group-commit /
  batch-fusion / topology — **not** more shards, **not** a lock-granularity fix, **not** a claim/dispatch query
  rewrite. These are co-requisites, not follow-ons, to reach 45M/day.

## Package contents
- `HANDBACK_C6-LIVE_2026-07-12.md` — full handback (§6 format: feature proof, per-arm table, both convoy contrasts,
  the guardrails, adversarial pass).
- `c6-n4x2/`, `c6-n8x2/`, `c6-n8x3/`, `c6-n16x2/` — per arm: throughput report, `c6_convoy_*.json` (convoy summary),
  `c6_samples_*.json` (raw per-sample: waiting-rows, group sizes, runnable), CPU telemetry.
- Sampler source: `c6_convoy_sample.py` (the §3(a)/(b)/(c) instrument — grouping, floor, fence, exclusion set).

Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.
