# HANDOFF — **P0: does inline stage-fusion move throughput, or is the Phase-4 premise dead?**

**Date:** 2026-07-12 · **Gates** [ADR 0099](../adr/0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md) /
[ADR 0057](../adr/0057-inline-step-a-fast-path.md) · **Discipline:** [ADR 0101](../adr/0101-pre-registered-falsifier-discipline-for-performance-measurement.md)
**Zero production code.** Harness + config only. This run **authorizes or kills** the entire Phase-4 build.
Read-only rig work + one harness patch (~20 lines). Public DMV/catalog names only; no secrets, IPs, hostnames, PHI.

---

## 0. What this settles, and the trap that would fake the answer

The store-side search is closed ([ADR 0098](../adr/0098-store-side-scaling-levers-are-exhausted-transaction-amortization-is-the-only-path-to-45m-day.md)):
N-sizing insufficient (C5), no convoy (C6), parallelism load-bearing (C7). The **one** surviving lever is reducing
**committed transactions per event** — and its shipped instance, **inline stage-fusion (ADR 0057), is already in the
tree and has never been enabled in a rig run.** P0 measures whether turning it on moves sustained throughput.

**But the Phase-4 premise itself — "per-message transaction count is the constraint" — has never been tested. P0 tests
that too (arm E), and that is the most valuable thing here.** C6 found no convoy and no single blocker, so it is
entirely possible the wall is per-**message**, not per-**transaction**, in which case fusion buys nothing.

### ⛔ THE DISARMED-ARM TRAP — read before touching the rig
The obvious experiment — *"flip `inline=True` and re-run the C5 ladder"* — **is null by construction and would kill the
angle on a fabricated result:**

- The fusion gate is **`if inline and len(names) == 1:`** — verified at
  [`wiring_runner.py:3712`](../../messagefoundry/pipeline/wiring_runner.py#L3712).
- The shardcert default shape is **`H = D = dests = 8`** — verified at
  [`harness/config/shardcert/_shape.py`](../../harness/config/shardcert/_shape.py) (`H` and `D` both default to `dests`).

**At H=8, `len(names) == 1` is NEVER true. Zero messages fuse. The ON arm is byte-identical to OFF, the contrast reads
~0%, and the angle dies on an experiment that never engaged.** This is the exact **B1–B10 disarmed-arm defect class** (a
fixed constant bounding a parameter-scaled interval → a fabricated verdict). **P0 runs at `H = D = 1`, where the gate can
fire.** The manipulation check (§4) exists to prove it fired.

---

## 1. PRE-FLIGHT (blocking)

1. **Engine box back at m7i.4xlarge (16 vCPU).** P0 is A/B'd for comparability against the C5/C6/C7 baseline, which is a
   **16-vCPU** baseline — a same-session contrast across a rig change is not valid. Store box i4i.2xlarge (unchanged,
   `n_sched=8`). *(If the box was downsized to 2x while idle, upsize before the first arm.)*
2. **Feature ON, verified:** `SELECT SERVERPROPERTY('IsTempdbMetadataMemoryOptimized')` = **1** — same store config as
   C5/C6/C7, else the A/B baseline shifts.
3. **Pin the engine build.** Same build across all arms; state it in the handback. Do **not** `git pull` mid-run.
4. **Apply the harness patch (§4) BEFORE the first arm** — recording `committed_txns` per arm is the manipulation check,
   not an optional extra. Without it the run cannot be validated and does not count.
5. Everything else as C5/C6/C7: pooled, `--drain-timeout 150` (do NOT raise past ~300 s — B7), 900 s soaks, gate on
   **`result`**, never `exit_code`.

## 2. THE ARMS — one session, same rig, same rungs, shape `H = D = 1`

Set the shape with the existing env knobs: `MEFOR_SHARDCERT_HANDLERS=1`, `MEFOR_SHARDCERT_DELIVERING=1`,
`MEFOR_SHARDCERT_DESTS=1`. **`batch_handoff_statements`** has an existing harness A/B env knob —
**`MEFOR_PIPELINE_BATCH_HANDOFF_STATEMENTS=false`** for OFF (arms A/B); unset = the shipped default **True** (arms C/D)
(`settings.py:950`, wired through `serve` at `__main__.py:1752`; read once at engine construction — set per subprocess).
**`inline`** is a per-inbound **factory param** (`inbound(..., inline=...)`) that the cert graph does **not** set yet —
add a one-line env-driven `inline=` to the `inbound()` call at `harness/config/shardcert/graph.py:145` (harness config,
not engine code). Every other `_inline_ok` gate is already satisfied. **See `HANDOFF_dev_to_bench_P0_answers.md` Q1/Q2
for the exact edits.**

| arm | shape | `inline` | `batch_handoff_statements` | purpose |
|---|---|---|---|---|
| **A — control** | H=1 D=1 | OFF | **OFF** | Same-session OFF baseline at the fusible shape. |
| **B — treatment** | H=1 D=1 | **ON** | **OFF** | ⭐ **The clean fusion contrast (PRIMARY).** |
| **C — deployed control** | H=1 D=1 | OFF | ON (shipped) | What production runs today. |
| **D — deployed treatment** | H=1 D=1 | **ON** | ON | The as-shipped number (confound named, §3). |
| **E — premise check** | **H∈{1,2,4,8}, D=1**, no-op transforms | OFF | ON | ⭐ **Zero-code test of the Phase-4 premise itself (§5).** |

**Primary contrast = B vs A** (both unbatched — an apples-to-apples fusion-vs-split test). **C/D are the as-shipped
delta**, reported with the confound below. Run **≥3 replicates** per arm; report the median and the arm-to-arm noise floor.

## 3. THE DE-CONFOUND (this would rig the result if ignored)
`handoff` (the fused primitive) has **no `batch_handoff_statements` dispatch** — it goes straight to `_acquire()` — while
`route_handoff` and `transform_handoff` (the split path) dispatch to the ADR 0075 batched twins, and
`batch_handoff_statements` **defaults True**. Separately, a fused inbound is **excluded from the ADR 0071 B5 sync path**
(`_fusion_active` is SQL-Server-only). **So a naive `inline=True` flip compares fusion-minus-two-existing-optimisations
against split-with-both** — not fusion-vs-split. That is why arms A/B are both **unbatched** (the clean contrast) and
arms C/D carry the confound explicitly in the writeup. Do not report D−C as "the fusion gain."

## 4. MANIPULATION CHECK — MANDATORY; it decides whether the run counts at all

`SqlServerStore.committed_txns` ([`sqlserver.py:1046`](../../messagefoundry/store/sqlserver.py#L1046), incremented in
`_commit`) is on `/stats` and is **already polled and summed across shards** by `harness/load/enginepoll.py` — shardcert
just never records it (it reports the *modelled* `3 + 2H + 2D` instead). **The patch (~20 lines): record
`Δcommitted_txns` per arm and divide by delivered messages.**

- **Predicted:** measured `committed_txns/msg` drops by **≥ 0.9** from arm A to arm B (the `transform_handoff` commit +
  the whole ROUTED claim-episode stream disappear).
- **No separate fallback counter — and do NOT add one** (that would be engine production code). The cert workload is
  **homogeneous** (every message hits the identical handler → one clean delivery), so fusion is **all-or-nothing**:
  either every message fuses or none do. Partial fallback is unreachable, so **`committed_txns/msg` is the sole arming
  proof.** *(Confirmed against the bench pre-flight, 2026-07-12 — see `HANDOFF_dev_to_bench_P0_answers.md` Q3.)*
- **If the txn/msg drop is < 0.9, the arm was DISARMED → the run is VOID, NOT a refutation.** Fix the shape, re-run.

## 5. ARM E — the premise check (the highest-information experiment here)
Hold **D=1** (so `events/msg = 2` is **constant**) and sweep **H ∈ {1,2,4,8}** with **no-op transforms** on the
**existing, unmodified split path**. `T_ded = 4 + H`, so txn/msg climbs **5 → 12** while events/msg stays fixed. This
isolates the per-message transaction term with **zero code**.

- **FLAT sustained events/s across H=1..8 → the premise is REFUTED.** Per-message txn count is not the constraint; F2's
  entire value (removing the `2H` term) is zero. **Stop, write the ADR that closes Phase 4, go find the real wall.**
  This verdict **dominates arm B** — a flat E kills the angle even if B looks positive.
- **FALLING with H → weak support only, and we say so.** H also adds routed rows, routed lanes and a little CPU, so a
  fall is **ambiguous** (not clean evidence for the txn term). **A flat result is a clean kill; a falling one is not a
  clean win.** Stated up front so nobody over-reads it. *(Two results already retracted for over-reading. Not a third.)*

## 6. HARD GATES (non-negotiable, every arm)
- **FIFO:** `lane_inversions == 0` **and** `lane_repeats == 0` on sink-socket truth, with the `lanes_observed >= 2`
  non-vacuity guard. Gate on **`result`**; quote only a rung that delivered **100%**. **Never** quote
  `ceiling.sustained_events_per_s` from a collapsed arm (it is populated even on a collapsed arm — the B1–B10 trap).
- **No loss:** `acked_not_delivered == 0` under the two-node SIGKILL-under-load harness, with the kill injected **inside
  the fused unit** (between the ingress claim and the `handoff` commit) — the fused path's crash window is new surface.
- **Attribution** (`mf-bench-attribution-policy`): client isolation, `max_core%` on **both** boxes, verified-nonzero
  collectors. No bottleneck claim without them.

## 7. DECISION RULE (pre-registered — fixed before the run; not movable afterward)
Metric: **`sustained_events_per_s`, arm B vs arm A**, at the **last 100%-delivered rung** AND at the **collapse rung**.
Manipulation check passed; FIFO + loss gates green; median of ≥3 replicates with the noise floor stated.

| B vs A | verdict | action |
|---|---|---|
| **≥ +8%** | **PROCEED** | Build F1 → F2 → F3. At H=1 fusion removes only 1 of 5 dedicated commits; F2 removes 8 of 12 at H=8 + the whole ROUTED stage — so +8% at the *weakest* shape is a defensible lower bound. |
| **+3% … +8%** | **INCONCLUSIVE — HALT + REPORT** | Inside ADR 0071 B5's measured band (+6.5/+9.3/+10.0%), which was a **NO-GO to promote**. Do not auto-build. Owner decides whether F2's large permanent 3-backend surface is worth a B5-sized number. |
| **−3% … +3% (NULL BAND)** | **ABANDON THE ANGLE** | The wall is per-**message**, not per-**transaction**. Do not build F2/F3. Write the ADR closing Phase 4; record `txn/event` as a **measured dead end**. *(F1 may still ship on its own merit — one pure-overhead txn off the ACK critical path.)* |
| **< −3% (REGRESSION)** | **ABANDON + ESCALATE** | **C7-shaped:** concurrency removal hurts. F2/F3 remove *more* concurrency, so they hurt more. This is itself a finding — stage-level overlap is load-bearing, which reframes the search. |
| **Arm E FLAT across H=1..8** | **ABANDON — dominates every other result** | The premise is refuted with zero production code. |

The **regression band is pre-registered deliberately** — the plan's original one-sided kill criterion (*"≥15% or dead"*)
could not see the harm this intervention could plausibly do. C7 proved that harm is real.

## 8. Do NOT
- Do **not** run at the default `H=8` shape — the fusion gate never fires (§0). `H=D=1`.
- Do **not** report a run whose `committed_txns/msg` drop is `< 0.9` (arm A→B) as a refutation — it is **VOID** (§4).
- Do **not** report `D − C` as "the fusion gain" — it carries the batching + B5 confound (§3).
- Do **not** over-read a *falling* arm E as premise-confirmed — only a **flat** E is a clean verdict (§5).
- Do **not** raise `--drain-timeout` past ~300 s (B7). Gate on `result`, never `exit_code`. Do **not** quote
  `ceiling.sustained_events_per_s` from a collapsed arm.
- Do **not** write engine production code — P0 is harness + config only.

## 9. What to send back (`HANDBACK_P0_<date>.md`)
1. Engine build + box (m7i.4xlarge / i4i.2xlarge / feature=1). The harness patch diff (the txn recorder).
2. **The manipulation check FIRST:** `committed_txns/msg` for arms A and B, and the A→B drop. If `< 0.9`, the run is
   VOID — say so and stop.
3. Per-arm table: `sustained_events_per_s` (last 100%-delivered rung + collapse rung), delivered %, `committed_txns/msg`,
   `inline_fallbacks`, FIFO (inversions/repeats), store CPU%, `max_core%` (both boxes), replicate count + noise floor.
4. **Arm E:** `sustained_events_per_s` vs H∈{1,2,4,8}. FLAT or FALLING? (Flat = premise refuted, dominates.)
5. **The §7 verdict** — PROCEED / INCONCLUSIVE / NULL (abandon) / REGRESSION (abandon+escalate) / E-flat (abandon) —
   B vs A, phrased against the pre-registered bands.
6. One-line read: **is the Phase-4 premise alive** — does cutting transactions per event move sustained throughput, or
   is the wall per-message?

## 10. Sources
- The full design + why the other three Phase-4 angles were killed: [`PLAN-PHASE4-GROUP-COMMIT.md`](PLAN-PHASE4-GROUP-COMMIT.md).
- The lever's status + the ledger reconciliation: [ADR 0099](../adr/0099-phase-4-group-commit-amortize-the-per-event-transaction-cost.md),
  [ADR 0057](../adr/0057-inline-step-a-fast-path.md).
- The measurement discipline: [ADR 0101](../adr/0101-pre-registered-falsifier-discipline-for-performance-measurement.md).
- The baseline this A/B's against: `results/2026-07-12-throughput-c4-c7/c5-n8-headroom-2026-07-11/`.
- **Line numbers are current-worktree** (the public mirror lags); the facts, not the lines, are load-bearing and were
  re-verified 2026-07-12.
