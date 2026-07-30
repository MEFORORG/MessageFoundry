# Archived throughput plans

> ## ⛔ Historical. Do not read anything in this folder as the live plan.

Five throughput planning notes were retired here after
[ADR 0107](../../adr/0107-phase-4-is-closed-transaction-reduction-is-a-measured-dead-end.md) (2026-07-13) closed
Phase 4: **`txn/event` reduction is a MEASURED dead end.** A pre-registered falsifier cut committed transactions
per message **28.5%** (10.47 → 7.49) and moved sustained throughput **−0.56%** — inside the null band — and its
arm E bounded the coupling at an elasticity of **−0.115**: *"No transaction-reduction mechanism — fusion,
group-commit, or any other — can close a 5.79× gap."* The shipped instance,
[ADR 0057](../../adr/0057-inline-step-a-fast-path.md) inline stage-fusion, is **⛔ DO NOT PROMOTE** and stays
default-OFF permanently. Every lever these plans sequence has since shipped, been declined, or been deferred.

**They are kept verbatim because they are the record of WHY the lever was closed** — the diagnosis, the ranked
levers, the pre-registered decision rules, and the angles that lost. Deleting them would leave the closure
unexplained and invite someone to re-derive the same dead end on a modelled argument. Each document carries a
⛔ banner at the top naming exactly what in it is superseded and what still stands; the bodies below those
banners are unedited.

| Document | What it was |
|---|---|
| [`THROUGHPUT-IMPROVEMENTS.md`](THROUGHPUT-IMPROVEMENTS.md) | The engineering note — the two axes (durable-write vs Python core), and the Corepoint-anchored path to parity in §5. |
| [`throughput-roadmap.md`](throughput-roadmap.md) | The 2026-06-30 diagnosis (the per-lane serial commit round-trip chain) plus the ranked lever set. |
| [`throughput-build-plan.md`](throughput-build-plan.md) | The multisession execution layer for that roadmap — order, parallelism, method, coordination. |
| [`THROUGHPUT-EXECUTION-PLAN.md`](THROUGHPUT-EXECUTION-PLAN.md) | The 2026-07-10 risk-first plan toward 520.83 events/s across ~1,500 connections, with the Phase-F lever table. |
| [`PLAN-PHASE4-GROUP-COMMIT.md`](PLAN-PHASE4-GROUP-COMMIT.md) | The Phase-4 implementation plan whose own pre-registered decision rule (§7.6) fired **ABANDON**. |

**Where the live numbers are.** Measured throughput lives in
[`../../benchmarks/TUNING-BASELINE.md`](../../benchmarks/TUNING-BASELINE.md), which is canonical. The audit these
plans execute against is
[`../../benchmarks/THROUGHPUT-STATUS-2026-07-10.md`](../../benchmarks/THROUGHPUT-STATUS-2026-07-10.md), and the raw
P0 artifacts are under
[`../../benchmarks/results/2026-07-13-p0-inline-fusion/`](../../benchmarks/results/2026-07-13-p0-inline-fusion/).
The 45M-messages/day figure of [ADR 0052](../../adr/0052-enterprise-scale-target.md) is a **target**, never a
demonstrated capability.
