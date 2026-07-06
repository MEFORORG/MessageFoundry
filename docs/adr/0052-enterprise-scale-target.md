# 0052 — Commit to the enterprise scale tier as a product target

- **Status:** **Accepted** (2026-06-29) — owner decision; a committed capability target, not a claim it is met today.
- **Date:** 2026-06-29
- **Related:** [0053](0053-free-threaded-multicore-engine.md) (free-threaded multi-core engine — the committed
  path to this target) · [0051](0051-corepoint-throughput-parity-strategy.md) (measure-first durable-write /
  lean-write parity levers — the storage/IOPS half) · [0037](0037-multi-process-sharding-l3.md) (L3 sharding —
  the fallback scale path) · [0039](0039-database-tier-sharding-l5.md) (L5 DB-tier sharding) ·
  [CLAUDE.md](../../CLAUDE.md) §2 (asyncio concurrency model; reliability + count-and-log invariants) ·
  BACKLOG #28/#29 (load/throughput harness), #40 (enterprise-hardware CI leg), #64 (parity roadmap) ·
  [DUAL_LICENSING_PLAN.md](../DUAL_LICENSING_PLAN.md)

---

## Context

The commercial model is an **open-source AGPL engine + a commercial dual-license** whose maintenance
funding base is **one large or two medium customers** ([DUAL_LICENSING_PLAN.md](../DUAL_LICENSING_PLAN.md)).
Those customers sit at the **enterprise scale tier** — large IDNs / consolidated health systems — not the
single-community-hospital tier. A product that cannot demonstrate enterprise capability cannot win the
customers that fund the project. **Owner decision (2026-06-29): the enterprise market is in-scope and is no
longer demand-gated** — stop re-litigating whether to serve it.

The forcing architectural fact is the concurrency model. Per [CLAUDE.md](../../CLAUDE.md) §2 (verbatim):

> **Concurrency = asyncio** (not Qt threads): one listener + a **router worker** + a **transform
> worker** per inbound connection, one delivery worker per outbound connection, listeners/pollers/
> retry-timers as asyncio tasks supervised by the `RegistryRunner` so a crash in one is isolated.

A single asyncio event loop runs all Python bytecode (peek, routing, transforms, validation) on **one
core**. So an enterprise volume forces a scaling choice: **across processes** = sharding (ADR 0037/0039),
which *fragments the store* (K databases → fragmented search/reporting/audit), or **within one process** =
multi-core on one unified store (free-threading, ADR 0053). This ADR commits the **requirement**; ADR 0053
commits the **path**.

For scale anchoring: a single large community hospital runs on the order of ~1M msgs/day;
**45M/day ≈ a very large IDN** — the top of single-engine sizing, and exactly the volume of the qualified
Corepoint 45M/day Required-System spec that ADR 0051 is anchored on (9,200 8 KB-random-write IOPS, ~11 KB/msg,
20+16 cores, multi-DB + AlwaysOn AG).

## Decision

**MessageFoundry SHALL be able to support up to 45,000,000 messages/day, 1,500 connections, and a remote
production database**, on a qualified enterprise configuration — as a committed product target. The
enterprise market is **in-scope and not demand-gated**.

- This is a **capability target / requirement**, not a claim the target is met today (a single asyncio loop
  is one core; the unified-store path to 45M/day is ADR 0053, with ADR 0037/0039 sharding as fallback and
  ADR 0051's durable-write levers as the storage/IOPS half).
- It changes **no** runtime behaviour by itself — it sets the numeric bar the scaling ADRs must
  collectively reach.
- The target must be reached **with the invariants intact** — per-channel FIFO, at-least-once delivery,
  count-and-log disposition, and **unified-store observability** (the fragmented-store caveat of sharding is
  the reason ADR 0053 is the *preferred* path, not sharding).

## Acceptance Criteria

> Capability targets; several verifying runs are future (the enterprise-hardware load run #40, a
> connection-scale harness). The **decision** (commit the target) is Accepted now; the criteria define the
> bar, not a precondition for the commitment. `adr-analyze` will flag the unresolved `→` links until built.

- **AC-1** — THE SYSTEM SHALL sustain up to 45M messages/day on a qualified enterprise configuration
  (remote server DB) with per-channel FIFO + at-least-once preserved.
  → `harness/load/` + `docs/benchmarks/` (enterprise-hardware run pending — BACKLOG #40 / #28 / #29)
- **AC-2** — THE SYSTEM SHALL support up to 1,500 concurrent connections without per-connection-worker
  exhaustion (fd/socket/worker-task limits).
  → connection-scale test (to build; new BACKLOG item)
- **AC-3** — WHERE the deployment uses a remote production database, THE SYSTEM SHALL run the full staged
  pipeline (`ingress → routed → outbound`) with the store finalizer as the single disposition authority.
  → `tests/` Postgres + SQL Server store suites

## Options considered

1. **Commit the enterprise tier as a target now (this).** **CHOSEN** — the funding base is here; early
   commitment is the cheapest time to put the supporting architecture in (timing argument, see ADR 0053);
   demand-gating it indefinitely starves the funding model.
2. **Demand-gate the enterprise market (build only on a signed deal).** Rejected — the prior framing; it
   gates a foundational capability on a sales event, and per the project's demonstrated velocity the core
   work is small and cheapest now.
3. **Cap the product at the small/mid-hospital tier (~1–5M/day).** Rejected — forfeits the commercial
   funding base (one large / two medium customers sit above this tier).

## Consequences

**Positive** — a single authoritative "the enterprise tier is committed" artifact (ends the recurring
"is the market worth it" debate); the scaling ADRs now have a concrete numeric bar; the commercial pitch can
*demonstrate* enterprise capability, not promise it.

**Negative / risks** — the target is **not met today** on a unified store (single loop = one core); reaching
it depends on ADR 0053 (or the ADR 0037/0039 sharding fallback) **plus** ADR 0051's durable-write levers; the
**1,500-connection axis is unvalidated** and is its own work (not implied by the msg/day number); the
enterprise-hardware measurement (#40) is pending, so the real single-engine ceiling is still estimated.

**Out of scope** — *how* to reach the target (ADR 0053 free-threading / ADR 0037–0039 sharding / ADR 0051
durable-write); the 45M/day storage + IOPS footprint (ADR 0051); the 1,500-connection scaling design.

## To resolve on acceptance

- [x] The market commitment — resolved by owner decision 2026-06-29.
- [ ] Connection-scale (1,500) validation harness — does not exist; track as a new BACKLOG item.
- [ ] Enterprise-hardware load run to measure the real single-engine ceiling vs the 45M target (#40 / #28 / #29).
