# 0039 — Database-tier sharding (L5) — per-shard store on K HA clusters + read-offload

- **Status:** **Proposed** (2026-06-27) — **design approved; build deferred ("shelved").** The owner
  has approved the *direction*; the build is deliberately **not** started and **activates only when a
  measured DB-commit wall exists** (the Step-0 / L0 hardware test pins the bottleneck on DB commit
  latency / WAL fsync / log flush, not on a headline number). Design landed in PR #588; no engine code
  is built for L5 yet.
- **Date:** 2026-06-27
- **Related:** [docs/design/dbshard.md](../design/dbshard.md) (full options analysis) · ADR 0037
  (L3 process sharding — L5 generalizes its per-subprocess store) · ADR 0001 (staged pipeline — the
  single-transaction handoffs L5 must not span across DBs) · [CLAUDE.md](../../CLAUDE.md) §2 (store /
  reliability invariant)

---

## Context

ADR 0037 (L3 process sharding) already gives each engine subprocess its **own SQLite db file**, so on
the SQLite-per-shard MVP there is **no shared-DB write contention at all** — L3 is about CPU. Production
estates, however, consolidate onto a **shared Postgres / SQL Server HA cluster** (for HA, central
backup, one operational surface). There, a message costs `~(2 + 2·fan-out)` durable commits (≈42 at
fan-out 20), and *every* shard's writes land on **one DB cluster** — which can saturate (the
**durable-write wall**) while CPU still has headroom across the shards.

L5's forcing problem is the **database write tier**, not the process count. It must let the engine fleet
write to **more than one DB cluster** (aggregate ceiling `K × one-cluster-ceiling` instead of `1×`)
**without** breaking the reliability invariant —

> Every subsequent stage **handoff** … is a **single committed transaction** … the store **finalizer is
> its single authority** (it alone sees every stage's rows …)

— i.e. **nothing may span two DBs in one transaction**, and a message's every stage must live on one
store. It is the **last** lever to reach for: apply only after a server-DB backend is in use, L1/L2
retention/store-once/group-commit are measured, and Step-0 pins the wall on DB commits with co-location
on one cluster already maxed.

## Decision

**L5 = a per-shard logical database, co-located on K HA clusters (the design's Option A), paired with
read-offload to a replica (Option C) as the cheaper-first valve, on top of the single-shared-cluster
baseline (Option D) which stays the default until a *measured* DB-commit wall fires.** This generalizes
L3's existing per-subprocess store from "one SQLite file per subprocess" to "a per-shard `[store]` block
on any backend, co-hosted on K clusters."

- **Per-shard store, co-located on K clusters.** Each L3 shard keeps its own `[store]` target; multiple
  shard databases are co-hosted on **one** HA cluster (Postgres+Patroni multi-db; SQL Server multi-AG
  with per-shard listeners). You split onto a **second** cluster only when one cluster's *measured* write
  ceiling is exceeded — **K (clusters) is decoupled from N (shards)** (the cost lever).
- **Read-offload as the cheap valve.** The store already runs reads on a dedicated read-only WAL pool;
  on a server backend that generalizes to a physical **read replica** (Postgres streaming replica /
  SQL Server readable secondary). The disposition-finalizing **write path never reads a replica**.
- **The one engine change is per-shard store configuration.** Let a shard carry its own `StoreSettings`
  so the supervisor hands each subprocess a distinct store target; the single-base default
  (`<stem>_<shard>.db`) stays **byte-identical**. No `store/*.py` change — each backend is unchanged;
  only which settings instance each subprocess opens. The rest is deployment topology + the existing
  Console/IDE control plane (cross-shard search fans out across the K stores).

This must **not** break the staged-pipeline transactions: each shard remains the *whole* existing
pipeline (ingress→routed→outbound, single-transaction handoffs, finalizer-as-sole-authority) against
**its own** store; nothing spans two DBs in one transaction.

## Options considered

1. **Option A — per-shard DB co-located on K HA clusters, + Option C read-offload, on the Option D
   single-cluster baseline (this).** **CHOSEN.** Reuses L3's invariant verbatim (a connection → one
   shard → one store); preserves at-least-once, FIFO and the finalizer per shard; K decoupled from N is
   the cost lever; read-offload buys write headroom on the existing cluster first.
2. **Option B — an engine-internal store *router* multiplexing one process across several backends.**
   **Rejected** — a write-path multiplexer either needs cross-DB transactions (none exist) or, to keep a
   message's stages on one backend, degenerates to "Option A done worse" (same partition inside one
   GIL-bound process, plus a bespoke multiplexer in the hottest reliability-critical seam). It is
   per-message-keyed DB routing wearing a store hat.
3. **Option C alone — read/write split only.** A *complement*, not the answer: it offloads reads but
   does **not** raise the *write* ceiling the L5 trigger targets.
4. **Option D — one cluster, scaled vertically + co-located only.** The **correct default** until the
   gating questions hold; L5 is the planned *exit* from Option D, not a replacement.

## Consequences

**Positive** — aggregate write ceiling becomes `Σ cluster ceilings`; share-nothing fault isolation
extends to the DB tier (a shard DB's saturation/outage is its own blast radius); per-channel FIFO,
at-least-once and the single-finalizer are untouched (each shard is the whole pipeline against its own
store); the cost lever K is decoupled from N; **no new authoring concept** — DB sharding is an ops
decision (which `[store]` a shard targets), invisible to Routers/Handlers and to the L3 `shard` tag.

**Negative / risks** — cross-shard reads (search, aggregate dashboards) span K databases and move to the
Console/IDE control plane; replica lag makes some monitoring reads slightly stale (never the write
path); operating K clusters adds backup/restore/patch surface.

**Explicit non-goals (what NOT to build)** — **no** per-message-key / facility-key / per-MRN DB sharding
(fans one source across DBs, breaks FIFO + the finalizer's authority); **no** active-active (#396 stays
deleted — each shard's store is active-passive); **no** cross-DB / distributed transaction; **no**
engine-internal write-path store-router (Option B); **no** making L5 a default (it is reserve capacity).

## To resolve on acceptance

> Open questions to settle before this flips from `Proposed` to `Accepted` and the build starts — and
> before any second cluster is provisioned. See [docs/design/dbshard.md](../design/dbshard.md) §7.

- [ ] Per-shard store config shape: a full `[store]`-per-shard block, or a thin `[shards.<id>.store]`
  overlay onto one base `[store]`?
- [ ] Co-location default: ship docs assuming Postgres+Patroni as the recommended K-cluster backend
  (with SQL Server AGs as the alternative), or stay backend-neutral?
- [ ] Read-replica scope: is read-offload-to-a-replica in L5's scope, or carved into its own item
  (it introduces replica-lag semantics)?
- [ ] Cross-shard search ownership: confirm it lands wholly in the Console fleet lane (L5 only publishes
  which store each shard uses; no engine-side cross-DB query).
- [ ] Activation trigger: confirm the measured-wall checklist (server-DB backend + L1/L2 applied +
  Step-0 pins the DB-commit wall + co-location maxed) is the agreed gate before provisioning a second
  cluster.
