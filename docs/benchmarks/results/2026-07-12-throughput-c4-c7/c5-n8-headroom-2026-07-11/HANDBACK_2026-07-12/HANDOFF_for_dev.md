# HANDOFF for dev — C5 (per-shard ceiling R at N=8, latch-free)

**Date:** 2026-07-12 · **From:** AWS bench (route onward via operator) · **Run:** c5-n8-headroom
**Engine build under test:** `98bec81` (pinned = C3/C4). **No engine patch** — C5 is a measurement run, it changed no code.
**Rev 2026-07-12b:** the §6 wait-mechanism claim was STRUCK after coordinator review — see below.

## Verdict
**R ∈ [2, 3) → N-SIZING INSUFFICIENT** (latch-free, as the code ships; independent of any claim rewrite — C4 = WITHHELD).
At N=8, pooled, latch-free: **2/shard sustains** (100% delivered, backlog slope +1.9); **3/shard collapses — reproduced twice**
(~50% delivered, slope +108/+111, ~85k stranded). R < 3.62, so even a fully cleared N=16 misses 520.83 ev/s.
**Decisive, not deferred** (engine = m7i.4xlarge): engine `max_core` ~38% and load-gen <8% are **both cool** at the collapse,
so the §3.2 carve-out does NOT fire — a fail with neither box saturated reads straight as a design verdict.

## What this means for dev
The N-sizing path is not sufficient on its own. The txn/event levers — Phase-3 `accepts=` (batch accept) and Phase-4
group-commit — move from follow-ons to **mandatory co-requisites** to reach 45M/day. Re-plan before building on N-sizing alone.
(These levers have their own independent justification; C5 does not, and cannot, provide wait-level evidence for a specific one.)

## On the N=8 wall — C5 does NOT name it (mechanism claim STRUCK)
An earlier draft of this handoff called the collapse a "serialization/write-path signature (`SOS_SCHEDULER_YIELD` +
`LOGMGR`/`CHECKPOINT`)." **That is retracted — it was backwards.** `LOGMGR_QUEUE`/`CHECKPOINT_QUEUE` are **idle background
waits** (both on the standard benign-exclusion set); in C5's own data they sit in a cluster of ≈800,000 ms waits over an
800 s window = threads asleep the whole run. The write-path wait that would matter — `WRITELOG` — is **absent**, as are
`PAGEIOLATCH_*`, `LCK_*`, `RESOURCE_SEMAPHORE*`. The only non-benign, reproduced signal is `SOS_SCHEDULER_YIELD`
(~826k/834k tasks) = **CPU pressure**. Root cause of the misread: the wait dump was a raw top-N, never filtered through the
exclusion set (the "rank-1 by default" trap). **C5 measures `R` only; naming the N=8 wall is the C6 convoy instrument's job.**

## Package contents
- `HANDBACK_C5_2026-07-12.md` — full handback (§8 format: feature-active proof, per-arm table, R + slope, verdict, adversarial pass).
- `c5-a/`, `c5-b/`, `c5-b2/` — per-arm report JSON + telemetry (`cpu_soak.csv`, `loadgen_cpu_soak.csv`, `storedmv_soak.txt`, `storepage_soak.txt`).
  - c5-a = 2/shard sanity PASS · c5-b = 3/shard collapse · c5-b2 = 3/shard collapse (reproduction).

Read-only DMV / public catalog names only; no secrets, IPs, hostnames, ports, or PHI.
