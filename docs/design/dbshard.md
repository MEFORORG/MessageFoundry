# L5 DB sharding — scaling the database tier

Status: design proposal (no code). Promote to a numbered ADR on approval — do **not** assign an ADR
number here (numbers collide across worktrees).

This is the design for **L5 "DB sharding"** in the throughput plan
(`MEFOR-MAX-THROUGHPUT-PLAN.md` §3, row L5; capacity stage **S3** in §4.2). It is a *capacity lever
built ahead and activated only when a measured wall demands it* — not a default deployment shape.

---

## 1. Problem statement — and the line vs. L3

### What L3 already does (so L5 does not re-do it)

L3 (built: `pipeline/sharding.py` + `pipeline/supervisor.py`, `docs/design/multiproc.md`) is
**process sharding**. It runs N engine **subprocesses**, each owning a *disjoint* set of inbound
connections (tagged `shard="a"`), to escape the single-core GIL ceiling on routing/transform. As a
side effect of "share-nothing per subprocess," **L3 already gives each subprocess its own SQLite db
file** (`<stem>_<shard>.db`). So in the SQLite-per-shard MVP, every process shard is *also* a
separate database file — there is no shared-DB write contention at all.

**L3 is about CPU.** Its unit is the *feed (connection)*; it answers "routing/transform is pinned at
one core." It distributes db files only incidentally, because each OS process conveniently owns its
own SQLite file.

### What L5 is actually about

L5 is about the **database write tier**, not the process count. It fires under a *different measured
wall*: the **durable-write wall** (`MEFOR-MAX-THROUGHPUT-PLAN.md` §8) — commits/second against a
single store/DB server. A message costs `~(2 + 2·fan-out)` durable commits (≈42 at fan-out 20), and
on a **shared server-DB backend** (Postgres or SQL Server, which production estates use for HA — not
SQLite) *every* shard's writes land on **one DB cluster**. Past some volume × fan-out, the DB
saturates even though CPU has headroom.

L5's job: **let the engine fleet write to more than one DB cluster**, so the aggregate commit
ceiling is `K × one-cluster-ceiling` instead of `1×`. It does **not** re-partition connections (L3/L4
own that) and it does **not** change FIFO, the staged pipeline, or the authoring contracts.

### When is L5 actually needed? (the gating questions, in order)

L5 is the **last** lever to reach for. Walk the ladder:

1. **Are you on a server-DB backend at all?** On the SQLite-per-shard MVP there is **no shared-DB
   wall** — each L3 subprocess already has its own file. L5 is moot; you are done. L5 only exists for
   deployments that consolidated onto a shared Postgres/SQL Server cluster (for HA, central backup,
   one operational surface).
2. **Has L1 + L2 been applied?** Mandatory retention/pruning (L1), store-once-deliver-many (L2b), and
   group-commit (L2c) all *lower commits/second on the existing single cluster*. They must be in
   place and measured before concluding the DB is the wall — they often move it on their own.
3. **Did Step-0 (L0) actually pin the wall on the DB?** §8 is explicit: a drastic lever fires only on
   a *measured* wall, never a headline number. The trigger for L5 is: a **saturated** deployment
   whose flamegraph/wait-analysis shows the bottleneck is **DB commit latency / WAL fsync / log
   flush** — CPU has headroom across the shards, but the one DB cluster is at its commit ceiling.
4. **Is co-location (one cluster, many shard DBs) already maxed?** L5's *first* move is not "more
   clusters" — it is to co-host the per-shard databases on **K HA clusters**, K set by the write
   ceiling, not the shard count (the plan's §6 cost lever). You add a *second* cluster only when one
   cluster's measured write ceiling is exceeded by the co-hosted shard DBs.

If all four hold, L5 is warranted: **split the shard databases across more than one DB cluster.**

---

## 2. Options

Four concrete shapes, with trade-offs. They are not all mutually exclusive (the recommendation
combines two).

### Option A — Per-shard database, co-located on K HA clusters (the plan's "fleet" shape)

Each L3/L4 shard keeps its **own logical database** (its own `[store]` connection target). But
"N shards" does **not** mean "N clusters": multiple shard databases are **co-hosted on one HA
cluster** — a Postgres+Patroni cluster holding several databases, or a SQL Server WSFC/AOAG holding
several availability groups (separate listeners per shard for independent failover, or one AG for
coupled failover). You split onto a **second** cluster only when the measured write ceiling of the
first is exceeded.

The engine change is small and already half-present: each shard subprocess gets its **own
`StoreSettings`** (its own `server`/`database`, or its own SQLite `path`) instead of all shards
sharing one. Sharding the DB then *is* L3's existing per-subprocess store, generalized from
"`<stem>_<shard>.db` on SQLite" to "a per-shard `[store]` block on any backend."

- **+** Share-nothing at the DB tier too: a shard's DB saturation/outage is its own blast radius;
  removes the shared-DB ceiling cleanly; aggregate ceiling = `Σ cluster ceilings`.
- **+** Reuses L3's invariant exactly — a connection lives in one shard → one DB; per-channel FIFO
  and at-least-once are untouched (each shard is the *whole* existing reliable pipeline against its
  own store).
- **+** Customer cost lever: K (clusters) is decoupled from N (shards); license/operate K clusters,
  not N. Postgres+Patroni = zero DB licensing; SQL Server Basic AGs cover an active-passive store on
  Standard edition.
- **−** Cross-shard reads (search, aggregate dashboards) now span K databases — pushed to the
  Console/IDE control plane (cross-shard search already on the fleet lane's backlog).
- **−** Shared enterprise outbound sinks (the few EHR-adjacent destinations every feed hits) become
  the *delivery-side* ceiling, not the store — orthogonal to L5, handled by pooling / a delivery
  shard.

### Option B — A store **router** in front of one Store handle (engine-internal multiplexing)

Keep a single engine process (or a single L3 subprocess) but give it a `Store` *router* that fans
each operation to one of several underlying `Store` backends, choosing by a stable key (e.g.
`channel_id`). The router implements the `Store` protocol (`store/base.py`) and delegates.

- **+** No supervisor/topology change; could shard the DB without multiplying processes.
- **−** **Breaks the staged-pipeline transaction invariant.** The finalizer is the *single
  authority* and must see *every* stage's rows for a message in one store; the `handoff`/
  `route_handoff`/`transform_handoff` primitives are **single committed transactions** spanning
  ingress→routed→outbound rows. A router that put a message's stages on different backends would
  need cross-DB transactions (none exist) or would fracture at-least-once and the finalizer's
  authority. Keeping *all* of one message's rows on one backend means the router key must be
  per-message-stable (e.g. `channel_id`) — at which point it is **just Option A done worse** (same
  partition, but inside one process, re-introducing the GIL/CPU ceiling L3 exists to remove, and a
  bespoke multiplexer to maintain).
- **−** A new, subtle, high-blast-radius seam in the hottest, most reliability-critical code.
- **Verdict:** rejected as a primary mechanism. Per-message-keyed DB routing is the rejected
  "per-key sharding" wearing a store hat.

### Option C — Read/write split (offload reads, not writes)

The wall L5 targets is **writes** (commits/s). But read load (Console lists, message detail,
cross-shard search, dashboards, audit) also hits the DB. This option offloads *reads* to a
**read-only replica / a dedicated read connection tier**, freeing the primary for writes.

The store already has the foundation: a **dedicated read-only WAL connection pool**
(`store/store.py`, "lockfree-reads") runs every read (`list_messages`, `stats`, `db_status`,
`delivery_latency_histogram`, …) on its own connections without taking the write lock. The decided
read-connection strategy (project memory) is "reads → dedicated read-only pool, not write-lock
serialization." On a server-DB backend this generalizes to a **physical read replica**: point the
read pool at a Postgres streaming-replica / SQL Server readable secondary while writes go to the
primary.

- **+** Builds directly on an existing, shipped seam — no transaction-model change (reads are
  already off the write path).
- **+** Relieves the primary of *all* read pressure, buying write headroom *without* adding a write
  cluster — often enough to defer Option A.
- **−** Does **not** raise the *write* ceiling — if the measured wall is genuinely commits/s
  (the L5 trigger), reads-offloaded-only postpones but doesn't remove it.
- **−** Replica lag → cross-shard search and "did my message land" reads can be slightly stale;
  acceptable for monitoring, **not** for the disposition-finalizing write path (which never reads a
  replica).
- **Verdict:** a *complement*, not the L5 answer. It is the cheap first thing to try at the
  read-heavy edge, and it pairs with Option A.

### Option D — Single shared cluster, scaled vertically + co-located only (no DB sharding)

Stay on one HA cluster; absorb growth with bigger DB hardware (NVMe-PLP, more log throughput), RCSI
(SQL Server), L1/L2/L2c, and read-offload (Option C). This is the **"don't do L5 yet"** baseline.

- **+** Simplest operationally — one cluster, one backup/restore/monitor surface, no cross-shard
  reads.
- **−** A single cluster has a hard commit ceiling; vertical scaling and the L2 levers move it but do
  not remove it. When the measured write wall is hit and these are exhausted, you are out of moves
  *except* L5.
- **Verdict:** this is the **correct state until the four gating questions in §1 all hold.** L5 is
  the planned exit from Option D, not a replacement for it.

---

## 3. Recommended approach

**Option A (per-shard DB, co-located on K HA clusters), paired with Option C (read-offload) as the
cheaper-first complement — and Option D as the default until the measured wall fires.**

Rationale, against the hard constraints:

- **It reuses L3's invariant verbatim.** A connection lives in one shard; a shard owns one store. L5
  is exactly L3's existing per-subprocess store, **generalized** from "one SQLite file per
  subprocess" to "a per-shard `[store]` block on any backend, co-hosted on K clusters." No new
  partition concept reaches the interface admin — they still only tag a connection with a `shard`
  (the L3 surface). **DB sharding is an ops/deployment concern (which `[store]` a shard points at),
  not an authoring one.**
- **It honors every prior decision:** no per-message-key / facility-key / per-MRN sharding (that
  fans one source across DBs and breaks per-channel FIFO + at-least-once — Option B is its disguise,
  rejected); no active-active (#396 stays deleted — each shard is the existing **active-passive**
  store, share-nothing); customer-choice co-location (K decoupled from N) is the cost lever; "two
  distinct HA copies of MEFOR unified in the console + IDE" is exactly the per-shard-store-plus-
  control-plane shape.
- **It preserves the reliability model untouched.** Each shard remains the *whole* existing staged
  pipeline (ingress→routed→outbound, single-transaction handoffs, finalizer-as-sole-authority)
  against *its own* store. Nothing spans two DBs in one transaction — so at-least-once, replay,
  dead-lettering, and the finalizer's single-authority all hold per shard, unchanged.
- **Read-offload (C) is the cheap pressure valve.** Because reads already run on the dedicated
  read-only pool, pointing that pool at a replica buys write headroom on the *existing* cluster
  first — often deferring the need to add a second cluster at all.

The minimal engine surface this needs: **a per-shard `[store]` configuration** so two shards can
target two different clusters. Today the supervisor derives each SQLite path from one base
(`<stem>_<shard>.db`); L5 generalizes that to "a shard *may* carry its own store block" while leaving
the single-base default byte-identical. That is the whole engine-side change — the rest is
deployment topology + the Console/IDE control plane (already on the fleet lane).

---

## 4. Rough incremental build plan

Build the lever; *activate* per deployment only on a measured wall.

1. **Per-shard store config (the one engine change).** Let a shard carry its own `StoreSettings` (a
   `[store]`-per-shard or a `[shards.<id>.store]` overlay) so the supervisor hands each subprocess a
   distinct store target. Default = today's single-base derivation → **byte-identical** when no shard
   declares its own store. Validate: each shard resolves to exactly one store; a shard's outbounds
   may live on a *different* shard's store only via the explicit "replicated enterprise sink"
   declaration (the fleet lane's partition-coherence check), never implicitly.
   *(Owns: the `config/` shard-store surface + `supervisor.py` wiring. No `store/*.py` change — each
   backend is unchanged; only which settings instance each subprocess opens.)*
2. **K-cluster co-location docs + sizing.** Document co-hosting M shard databases on K HA clusters
   (Postgres+Patroni multi-db; SQL Server multi-AG with per-shard listeners), with the sizing formula
   `K ≈ Σ(rate × (2 + 2·fan-out)) ÷ one-cluster-commit-ceiling` from the capacity model. No code —
   `docs/CONNECTIONS.md` / a clustering/deployment guide.
3. **Read-offload to a replica (Option C activation).** Extend the read-only pool's target so it
   *may* point at a Postgres streaming replica / SQL Server readable secondary (the read pool seam
   already exists; this is a connection-target config + a "reads may be slightly stale" doc note).
   The disposition-finalizing write path never reads the replica.
4. **Control-plane wiring (depends on Console + IDE fleet lanes).** Cross-shard search fans out across
   the K stores; per-shard drill-down; the IDE's per-route shard assignment + partition-coherence
   validation already cover "a route's graph lives on one shard; shared sinks are explicit." L5 only
   needs to surface *which store* each shard uses in the shard registry.
5. **Activation runbook.** "You add a second cluster when *Y*" — the measured-wall checklist from §1,
   plus a backup/restore/patch-across-K-clusters automation note.

Each step is reversible and additive; nothing changes the authoring contracts or the staged-pipeline
transactions.

---

## 5. What NOT to build (explicit non-goals)

- **No per-message-key / facility-key / per-MRN DB sharding.** Routing a *message* to a DB by a field
  value is the rejected partition: it fans one source across DBs, breaks per-channel FIFO, and
  fractures at-least-once + the finalizer's single authority. The unit stays the **connection** (via
  the L3 `shard` tag), never the message. (Option B is this in store clothing — rejected.)
- **No active-active.** Each shard's store is the existing **active-passive** HA store (#396 stays
  deleted). L5 adds DB *partitions*, never a second concurrently-writing copy of the same data.
- **No cross-DB / distributed transaction.** The staged-pipeline handoffs are single committed
  transactions in *one* store; L5 never spans two DBs in one transaction. A message's every stage
  lives on one shard's store, full stop.
- **No engine-internal store-router multiplexer on the write path** (Option B). It either needs
  cross-DB transactions (don't exist) or degenerates to Option A done worse (same partition, inside
  one GIL-bound process).
- **No new authoring concept for the interface admin.** DB sharding is a deployment/ops decision
  (which `[store]` a shard targets), invisible to Routers/Handlers and to the `shard` tag the admin
  already sets.
- **No making L5 a default.** It is reserve capacity. SQLite-per-shard (L3 MVP) and single-shared-
  cluster (Option D) remain the norm; L5 activates only when §1's four gating questions all hold and
  Step-0 pins the wall on DB commits.

---

## 6. Decision (ADR-style — promote to a numbered ADR on approval)

**Context.** L3 already gives each engine subprocess its own SQLite file, so the SQLite-per-shard MVP
has no shared-DB wall. Production estates consolidate onto a shared Postgres/SQL Server HA cluster
(for HA + central ops), where every shard's `~(2+2·fan-out)` commits land on one cluster — which can
saturate (the durable-write wall) while CPU has headroom. Prior decisions reject per-key sharding and
active-active, and prefer customer-choice co-location (K clusters ≠ N shards) with the fleet unified
in the Console + IDE.

**Decision.** L5 = **per-shard logical database, co-located on K HA clusters** (Option A), generalizing
L3's existing per-subprocess store from "one SQLite file" to "a per-shard `[store]` block on any
backend," **paired with read-offload to a replica** (Option C) as the cheaper-first valve, on top of
the single-shared-cluster baseline (Option D) which remains the default until a *measured* DB-commit
wall fires. The only engine change is **per-shard store configuration**; the rest is deployment
topology + the existing Console/IDE control plane.

**Consequences.** Aggregate write ceiling becomes `Σ cluster ceilings`; share-nothing fault isolation
extends to the DB tier; per-channel FIFO, at-least-once, and the finalizer's single authority are
untouched (each shard is the whole existing pipeline against its own store). Cross-shard reads
(search, aggregate views) move to the control plane. The cost lever K is decoupled from N. No new
authoring concept; DB sharding stays an ops decision.

**Status.** Proposed. Promote to a numbered ADR on owner approval (do not assign a number in a
worktree — they collide). Activation is gated on Step-0 (L0) pinning the wall on DB commits.

---

## 7. Open questions for the owner

1. **Per-shard store config shape:** a full `[store]`-per-shard block, or a thin `[shards.<id>.store]`
   overlay onto one base `[store]` (overriding only `server`/`database`/`path`)? The overlay keeps the
   common case terse; the full block is more explicit.
2. **Co-location default:** ship docs assuming Postgres+Patroni (zero-licensing, best throughput) as
   the recommended K-cluster backend, with SQL Server AGs as the alternative — or stay backend-neutral?
3. **Read replica scope:** is read-offload-to-a-replica (Option C step 3) in L5's scope, or carved
   into its own item? It builds on the shipped read pool but introduces replica-lag semantics worth a
   separate decision.
4. **Cross-shard search ownership:** confirm cross-shard search lands wholly in the Console fleet lane
   (L5 only publishes which store each shard uses), with no engine-side cross-DB query.
5. **Activation trigger wording:** confirm the §1 measured-wall checklist (server-DB backend +
   L1/L2 applied + Step-0 pins DB-commit wall + co-location maxed) is the agreed gate before any
   second cluster is provisioned.
