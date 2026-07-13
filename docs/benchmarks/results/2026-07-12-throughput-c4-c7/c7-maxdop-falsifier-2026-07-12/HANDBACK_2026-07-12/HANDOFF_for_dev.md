# HANDOFF for dev — C7 (MAXDOP falsifier) + where the C5→C7 arc lands

**Date:** 2026-07-12 · **From:** AWS bench (route onward via operator) · **Run:** c7-maxdop-falsifier
**Engine build:** `98bec81` (pinned). **No engine patch** — C7 is a config A/B (DB-scoped MAXDOP), reverted after.
**Boxes:** engine m7i.4xlarge, store i4i.2xlarge (`n_sched=8`), feature ON.

## C7 verdict — hypothesis KILLED, parallelism EXONERATED
Tested whether the store's ceiling was partly self-inflicted intra-query parallelism (C6's `CXSYNC_PORT` grew 34×,
the fastest-growing real wait). **It is not.** Forcing serial plans (DB-scoped `MAXDOP=1`, cache cleared —
manipulation check PASSED: `CXSYNC_PORT` 135,361 → 0):
- **N=8@3 got WORSE** — 49.4% → **20.6%** delivered, slope +115 → +155, store CPU driven to 89% for *less* output.
  → **§6 "parallelism was HELPING."**
- **N=8@2 (healthy rung) BROKE** — 100% PASS → **75.7% FAIL** under MAXDOP=1. → **the config is broadly harmful.**

So `CXSYNC_PORT`'s growth was a **collapse EFFECT, not a cause** (the C4 `list_fifo_lanes` / effect-vs-cause trap).
**Actionable:** do **NOT** set MAXDOP=1 on the store — it is load-bearing here and removing it hurts. The store's
current parallelism config (instance MAXDOP=8 ≈ effective 0 on 8 schedulers, CTFP=5) was **reverted intact**.

## Where C5 + C6 + C7 land (the combined conclusion for dev)
- **C5:** per-shard `R ∈ [2,3) < 3.62` → N-sizing insufficient alone.
- **C6:** the collapse is aggregate/structural, **not a resource convoy** (not a lock/latch/spill fix).
- **C7:** it is **not** an intra-query-parallelism config default either (MAXDOP=1 makes it worse).
- **⇒ The path is the `txn/event` levers** — Phase-3 `accepts=` (batch accept), Phase-4 group-commit / batch-fusion.
  Three cheaper "fixes" (more shards, a contention fix, a config default) have each been falsified. Group-commit /
  reducing txn-per-event is what's left standing.

## Package contents
- `HANDBACK_C7_2026-07-12.md` — full handback (§9: feature proof, settings-as-found, manipulation check, per-arm table, verdict).
- `c7-base/`, `c7-dop1/`, `c7-dop1-pass/` — throughput report + `c6_convoy_*.json` (fenced filtered wait delta incl. `CXSYNC_PORT`) + CPU telemetry.

Read-only DMV + one reverted DB-scoped config; public catalog names only; no secrets, IPs, hostnames, ports, or PHI.
