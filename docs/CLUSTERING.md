# Running a cluster (active-passive HA)

> **Status: built (Track B).** Single-node operation is the default and is byte-identical whether or
> not this feature exists — a cluster is opt-in via `[cluster].enabled = true` on a server-DB store
> (PostgreSQL **or** SQL Server).
> Clustering is the **active-passive** (leader/standby failover) HA model — the supported HA mode.
> The horizontal **active-active** scale-out path (the graph running concurrently on every node) was
> **dropped (2026-06-18) and its code removed**; it is not a planned milestone.
> Design records: the cluster ADRs [0005](adr/0005-transform-accessible-state.md) /
> [0006](adr/0006-external-data-lookups.md) (the converged data) and
> [ADR 0008](adr/0008-cluster-observability-api.md) (the observability API below). Code:
> [`pipeline/cluster.py`](../messagefoundry/pipeline/cluster.py) (PostgreSQL) +
> [`pipeline/cluster_sqlserver.py`](../messagefoundry/pipeline/cluster_sqlserver.py) (SQL Server).

MessageFoundry provides HA by running **N identical engine processes against ONE shared server database**
(PostgreSQL or SQL Server) in an **active-passive** (one leader, the rest warm standbys) model. There is
no separate broker: the
durable staged queue, the row leases, leader election, and the config/state convergence all live in the
shared database. Single-node stays the no-op default; turning on `[cluster]` makes the nodes coordinate
so exactly one — the leader — runs the graph and a standby takes over on failure.

## Requirements

A clustered deployment **requires** (enforced at config load):

- `[cluster].enabled = true`
- `[store].backend = "postgres"` **or** `"sqlserver"` — SQLite is single-file/single-node; the cluster
  needs the shared `nodes` table + row leases a server DB provides. Both backends run the same
  active-passive leadership lease (`pipeline/cluster.py` for Postgres, `pipeline/cluster_sqlserver.py`
  for SQL Server).
- `[store].pool_size >= 2` — a clustered node drives concurrent background work against the pool (the
  membership/lease-renewal maintenance loop + the leader reclaim sweep + the per-stage workers), so it
  needs headroom over the store's working connections (prefer `>= 3`).

Every node points at the **same** server database (same `[store]` server/database/schema) and runs
the **same** config dir.

```toml
# messagefoundry.toml — identical on every node (the DB password comes from MEFOR_STORE_PASSWORD)
[store]
backend   = "postgres"   # or "sqlserver"
server    = "db.internal"
database  = "messagefoundry"
username  = "mefor"
pool_size = 40         # default (ADR 0062); >= 2 under [cluster]

[cluster]
enabled = true
# node_id is auto-derived (host:pid:hex, reusing the store's lease owner-id) — pin it only for a
# stable identity across restarts or in tests.
heartbeat_seconds    = 10.0
node_timeout_seconds = 30.0   # a node is "dead" when last_seen is older than this; must be > heartbeat
# How often the leader runs the RECURRING background expired-lease reclaim sweep (the active-passive
# background lease-reclaim). It does NOT gate failover speed: on promotion the new leader recovers the
# prior leader's stranded rows immediately (owner-scoped, lease-blind; #293), so [store].lease_ttl_seconds
# (the per-row lease TTL, default 60s) is the background-sweep ceiling, NOT the failover-recovery driver.
reclaim_interval_seconds = 30.0
# Leadership lease (active-passive self-fencing). Timing invariant enforced at load:
#   heartbeat_seconds < leader_fence_timeout_seconds < leader_lease_ttl_seconds
leader_lease_ttl_seconds      = 30.0  # a standby acquires leadership only once the lease has expired
leader_fence_timeout_seconds  = 20.0  # a leader that can't renew within this self-fences (split-brain guard)
# --- Leader preference (ADR 0096) — per-node; default (0.0, true) = unweighted first-lease-wins ------
# acquire_delay_seconds: seconds this node waits PAST the lease-expiry time before it may take over an
#   EXPIRED lease (handicap). A preferred site keeps 0.0; a warm remote-DR node sets a positive value so
#   a preferred node wins the routine take-over race. NEVER delays a renewal by the current leader, and
#   only ever makes a node claim LATER — so it can't open a two-leader window. Governs take-over of an
#   EXPIRED lease only; the very first election on an empty table is a plain race.
acquire_delay_seconds = 0.0
# promotable: false = this node may NEVER become leader (never inserts/takes-over/renews the lease); a
#   node that somehow already leads steps down cleanly on its next tick. Use it for a warm, passive DR
#   engine. At least ONE promotable node MUST exist, or no node ever acquires the lease and the graph
#   never drains (an all-non-promotable cluster is a misconfiguration).
promotable = true
```

> **Warm DR:** run a remote DR-site engine as a **non-promotable cluster member**
> (`promotable = false`) — NOT as a `[dr].activate` box. Combining `[dr].activate` with `[cluster]` is
> refused at config load (the DR run-profile gates which connections start, not lease acquisition, so a
> lease-contending DR box could win leadership and drive the primary store cross-WAN).

Start the same `serve` command on each host/process — e.g.:

```
python -m messagefoundry serve --service-config messagefoundry.toml --config ./config
```

(For a local DEV Postgres, `scripts/dev/postgres.ps1` sets the `MEFOR_STORE_*` connection env and
`MEFOR_ALLOW_INSECURE_TLS=1` for a loopback, no-TLS database — DEV convenience only.)

## What each node does

MessageFoundry runs **active-passive** (the Corepoint/Rhapsody model): the **leader (primary)** runs
the whole message graph; every other node is a **warm standby** that contends for leadership only. The
cluster coordinates the parts that must not double-run or interleave:

- **Active-passive graph gating (Workstream A1).** The wired graph — **all** listeners (MLLP/TCP/File/
  …) **and** the router/transform/delivery workers — runs **only on the leader**. A standby binds no
  listeners and runs no workers; it stays warm (membership heartbeat + cache convergence) and brings the
  graph up the moment it acquires leadership, and tears it down if it loses leadership. The graph
  supervisor polls leadership on a short interval so a demotion/fence **promptly** stops a node
  accepting new inbound work and initiating new processing. (The hard guarantee against *concurrent
  double-processing of a given row* is the **self-fencing leadership lease** + the leader-gated graph:
  the graph runs only on the leader, and a partitioned/slow old leader self-fences and lets its
  leadership lease **expire** before a standby can acquire leadership. Read that as *the old leader has
  stopped calling itself leader*, **not** as *the old leader has stopped* — fencing flips an in-memory
  flag; the listeners and any in-flight sends wind down on their own schedule, which nothing budgets
  against the fence-to-expiry margin. A promoted node can therefore briefly overlap a predecessor that
  is still finishing a send. That is bounded to duplicate delivery, which at-least-once permits and
  idempotent outbounds absorb — it is not a route to losing or stranding a message. The store's **row
  leases** are the additional backstop for the *recurring background* reclaim sweep, which only takes
  rows whose lease has **expired**.) Clients
  reconnect to whichever node is currently primary via a **floating VIP / load-balancer health check**
  (see the deployment doc). On promotion the new leader recovers the prior leader's stranded in-flight
  rows immediately — an *owner-scoped, lease-blind* on-promotion recovery (it re-pends only rows owned by
  *another* instance, never its own), so failover delivery resumes at once instead of waiting out the
  per-row lease TTL (`[store].lease_ttl_seconds`, default 60s — previously the dominant ~60s Postgres
  failover-recovery delay; #293). This is safe under the self-fencing guarantee above; the *recurring
  background* sweep stays lease-gated.
- **Leader election (self-fencing lease).** Exactly one node holds the `leader_lease` row and is the
  **leader**. The leader renews the lease every `heartbeat_seconds` (to `DB_now + leader_lease_ttl_seconds`,
  measured on the database's own clock, so node clock skew doesn't affect who may hold it); a standby
  acquires only once that lease has **expired**. A leader that cannot renew within
  `leader_fence_timeout_seconds` (< the TTL) **self-fences** — it stops *reporting itself* leader before
  the lease can expire and a standby acquire it (the split-brain guard). Two caveats if you tune these
  down from the shipped `10 / 20 / 30`: the usable margin is smaller than `ttl - fence`, because the
  fence baseline is taken after the renew round trip returns while the expiry is stamped on the database
  clock at statement execution, and detection lands up to one fence tick late; and the config validator
  checks the *ordering* `heartbeat < fence < ttl` only, never that any margin survives. On a clean stop
  the leader expires its lease so a standby takes over at once.
- **Store-checked leader epoch (fencing token).** The self-fence above is *temporal* — it relies on a
  paused/partitioned old leader noticing it has fallen behind and demoting itself before the lease TTL
  elapses. As a **second, durable** backstop the `leader_lease` row also carries a monotonic
  `leader_epoch` that is **bumped only on a fresh acquire** (a standby taking over) — never on a renew —
  so a node that took over holds a strictly *greater* epoch than the leader it superseded. On promotion
  the engine reads the held epoch from the coordinator and pushes it into the store
  (`Store.set_leader_epoch`); every FIFO claim then validates, **inside the single claim transaction**,
  that the held epoch is still current (`held >= leader_lease.leader_epoch`). A superseded ex-leader that
  resumes after an unusually long pause — past even the temporal fence — therefore claims **0 rows**: its
  held epoch is now older than the live leader's, so the claim's `UPDATE` matches nothing and it delivers
  nothing. The current leader's held epoch equals the lease epoch, so it claims normally; per-lane FIFO is
  unaffected (the guard only ever *rejects* a stale claim, never reorders a valid one). This is a
  **server-DB-only** safeguard (Postgres / SQL Server); SQLite is a single active node, so its
  `set_leader_epoch` is a no-op and the claim is byte-identical. **Scope:** the guard is attached to the
  claim and to nothing else — it stops a superseded ex-leader *claiming*, not *writing*. Disposition
  writes (done / failed / dead-letter) resolve their row by id with no epoch check, so an ex-leader that
  is still finishing a send can still record that row's outcome. The migration that adds the column is
  additive (`ADD COLUMN IF NOT EXISTS` / a guarded `ALTER`, run under the DDL lock), so an in-place
  upgrade of a live cluster is safe; the column back-fills to `0` and the first fresh acquire after the
  upgrade bumps it to `1`.
- **Leader-gated WRITE singletons.** Retention purges and the lease-reclaim sweep run **only on the
  leader**, so they never double-execute.
- **Leader-gated poll-source intake.** Only the leader polls a **shared** external resource (a watched
  directory / DB-poll table / remote dir). Under active-passive the standby doesn't run the graph at
  all, so this is belt-and-suspenders (the poll loop is also internally leader-gated).
- **Per-lane FIFO survives failover.** Because the graph runs on the **leader only**, per-lane FIFO is
  naturally serialized by that single processor. Across a failover, the ordinary FIFO claim
  (`claim_next_fifo`) reclaims a crashed/fenced prior leader's **stranded head** — this lane's
  expired-lease in-flight row, in the same transaction before the head SELECT — so the stranded row
  blocks the lane and a later row can never deliver ahead of it. (This replaced the dropped active-active
  per-lane lease mechanism.)
- **Reference / config / transform-state convergence.** The leader materializes each reference set from
  its source and followers read-through the shared snapshot; an operator config reload on one node bumps
  a shared version token and every other node reloads its own config dir to converge; transform-state
  writes propagate the same way via a per-namespace version token.

## Observability — `/cluster/status` and `/cluster/nodes`

Two read-only endpoints on the engine API expose membership and leadership. Both require
`Permission.MONITORING_READ` (held by VIEWER and up — no PHI, no new permission) and are reachable via
the console or any API client. They cost a cheap in-memory read (`/cluster/status`) or a single
`nodes`-table read (`/cluster/nodes`).

### `GET /cluster/status` — this node's posture

```json
{
  "node_id": "node-a:4812:1f9c2a7b",
  "clustered": true,
  "is_leader": false,
  "role": "standby",
  "config_version": 7
}
```

`role` is the active-passive role for operators / a load-balancer health check: `"primary"` when this
node is the leader (it runs the graph), `"standby"` when it is a warm follower (no listeners bound, no
workers running), or `"single-node"` when not clustered. Single-node (no cluster) reports `clustered:
false`, `is_leader: true`, `role: "single-node"`, `config_version: 0`:

```json
{ "node_id": "host:1234:ab12cd34", "clustered": false, "is_leader": true,
  "role": "single-node", "config_version": 0 }
```

### `GET /cluster/nodes` — all nodes + the derived leader

`leader_node_id` is the derived leader: among rows still carrying the leader flag, the freshest one
whose `last_seen` falls within `node_timeout_seconds`. At most one node is ever reported.

**It is not authoritative, and it is clock-sensitive — use `lease_owner` instead when it matters.**
The freshness test compares the *reading* node's wall clock against a `last_seen` written by the
*beating* node's wall clock, with an upper bound only. A row stamped by a node whose clock runs ahead
has a negative age, passes the test, and — being the largest `last_seen` — wins the pick. So a
crashed ex-leader whose clock ran fast can be reported here as leader while `lease_owner` on the same
response correctly names the live successor. The lease governs who processes; this field does not.
Note also that the web console's "cluster has no leader" health check keys off this field being
absent, so a skew-frozen row can keep it populated and mask a genuinely leaderless cluster.

Two-node cluster:

```json
{
  "nodes": [
    { "node_id": "node-a:4812:1f9c2a7b", "host": "node-a", "pid": 4812,
      "status": "active", "started_at": 1750000000.0, "last_seen": 1750000123.4, "is_leader": true,
      "acquire_delay_seconds": 0.0, "promotable": true },
    { "node_id": "node-b:5210:7c3e9d10", "host": "node-b", "pid": 5210,
      "status": "active", "started_at": 1750000005.0, "last_seen": 1750000124.1, "is_leader": false,
      "acquire_delay_seconds": 15.0, "promotable": false }
  ],
  "leader_node_id": "node-a:4812:1f9c2a7b",
  "lease_owner": "node-a:4812:1f9c2a7b",
  "lease_expires_at": 1750000153.4
}
```

`lease_owner` / `lease_expires_at` are the **authoritative** leadership-lease state read from the
`leader_lease` row: who holds the self-fencing lease and the DB-clock epoch at which it expires (the
instant a standby could acquire if the leader stops renewing). `lease_owner` normally equals
`leader_node_id` (the heartbeat-flag-derived leader); a brief divergence during failover is expected —
the lease is the source of truth for who may process. Each node also reports its **leader-preference
config** (ADR 0096): `acquire_delay_seconds` (its take-over-of-expired handicap; `0.0` = none) and
`promotable` (`false` = a non-promotable standby that can never become leader) — so an operator can SEE
which nodes are handicapped or passive across the cluster. Single node (synthetic self-entry — no heartbeat
history, so `started_at`/`last_seen` are `null`; permanently leader, so `lease_expires_at` is `null`):

```json
{
  "nodes": [
    { "node_id": "host:1234:ab12cd34", "host": "host", "pid": 1234,
      "status": "active", "started_at": null, "last_seen": null, "is_leader": true,
      "acquire_delay_seconds": 0.0, "promotable": true }
  ],
  "leader_node_id": "host:1234:ab12cd34",
  "lease_owner": "host:1234:ab12cd34",
  "lease_expires_at": null
}
```

A cleanly stopped node leaves a `status: "left"` tombstone (and its leader flag cleared); a crashed
node's row goes stale (its `last_seen` stops advancing) and the freshness filter stops counting it as
the leader. `leader_node_id` is always **at most one** node — during a failover window (an old leader's
flag not yet cleared while the new leader's flag is already set) the freshest still-beating node wins.
That the winner is the *live* node holds only while node clocks agree; a fast-clocked crashed node can
win the pick (see `GET /cluster/nodes` above). Never two leaders; not necessarily the right one.

`/cluster/status` is the **per-node authoritative** leadership signal (it reads that node's own
in-memory lock gate); `/cluster/nodes` derives leadership from the heartbeat flag and so can lag it by
up to one `heartbeat_seconds` interval. So immediately after a clean failover the freshly-promoted node
can report `is_leader: true` on `/cluster/status` for one beat before `/cluster/nodes` folds its flag in
and surfaces it as `leader_node_id` — a transient `leader_node_id: null` there is the one-tick fold-in
lag, not a lost-leader incident.

## Deployment topology (active-passive)

```
                      ┌──────────────── floating VIP / load balancer ────────────────┐
   MLLP/TCP senders ──▶  health check = TCP connect to the listener port              │
   (partners)         │  (only the PRIMARY binds it, so the VIP always lands on it)   │
                      └───────────────┬───────────────────────────┬──────────────────┘
                                      │ bound (primary)            │ NOT bound (standby)
                              ┌───────▼────────┐           ┌───────▼────────┐
                              │  node A         │           │  node B         │
                              │  PRIMARY        │           │  STANDBY (warm) │
                              │  graph running  │           │  no listeners   │
                              │  (leader lease) │           │  contends only  │
                              └───────┬─────────┘           └───────┬─────────┘
                                      └──────────┬───────────────────┘
                                        shared server DB (the lease + queue)
                                        DB-tier HA: PG replication / SQL Server Always On
```

**One primary processes; the rest are warm standbys.** All nodes point at the **same** server DB and run
the **same** config dir; the `leader_lease` row elects exactly one primary, which alone binds listeners
and runs workers (A standby binds nothing). DB-tier high availability (a replica / failover) is
**delegated to the database** (PostgreSQL streaming replication, SQL Server Always On) — MessageFoundry
does not replicate the store itself.

### Client reconnect — a floating VIP / LB health check is REQUIRED

Like Rhapsody/Corepoint, clients reach "the engine" through a **floating VIP or load balancer**, not a
fixed node — so a failover is transparent to senders (modulo a reconnect):

> **Planned alternative — engine-managed VIP (Windows-only).** [ADR 0056](adr/0056-engine-managed-vip-failover.md)
> proposes an **opt-in** mode where the **engine itself** owns the VIP (no external LB/VRRP/WSFC), moving it
> in lockstep with the leadership lease. It is **Windows-only** and **not yet built**. Until it ships — and
> on **Linux/containerized** deployments, which it does **not** cover — use the external floating VIP / LB
> described here, which stays the **cross-platform** default and the recommended posture for the strictest
> split-brain guarantee.
>
> **What HAS shipped from that ADR is only the control plane** — `POST /cluster/stepdown` (below), which
> moves *leadership*. It moves no address: with the external VIP / LB the address follows on its own,
> because the health check stops passing on the node that just released the lease.

- **MLLP / TCP inbound (per listener).** Use a VIP per inbound port whose health check is a **TCP
  connect to that port**. Because only the **primary** binds the port (the active-passive graph gating),
  the check passes only on the primary, so the VIP routes inbound traffic to it automatically; on
  failover the new primary binds the port, the old one's closes, and the VIP follows. MLLP senders see
  a connection drop and reconnect through the VIP — make partners **reconnect on drop** (standard MLLP
  client behavior).
- **Engine API edge (console / IDE).** The API is a control/read plane over the shared DB and is up on
  **every** node, so an API VIP can health-check the unauthenticated **`GET /health`** (liveness). To
  pin operations to the primary, read **`GET /cluster/status`** → `role` (`"primary"` / `"standby"`),
  or **`GET /cluster/nodes`** → `leader_node_id` + `lease_owner` (the console surfaces the live primary).

### Failover is not instantaneous

There is a promotion window, as in Rhapsody (minutes-class) — quantify it from the Workstream-D failover
benchmark, don't assume zero-downtime:

- **Clean stop** (graceful shutdown): the leaving primary **expires its lease**, so a standby acquires on
  its next heartbeat — failover is prompt (≈ one `heartbeat_seconds`). A **planned switchover** that
  leaves the node running takes the same path, without the shutdown — see `POST /cluster/stepdown` below.
- **Crash / partition**: the primary's lease **ages out**, so a standby acquires after up to
  `leader_lease_ttl_seconds`. A partitioned old primary **self-fences** within
  `leader_fence_timeout_seconds` (< the TTL), so it stops *reporting itself* leader before the standby
  takes over. It does not necessarily stop *working* by then: fencing sets a flag, and tearing the graph
  down (each inbound stopped in turn, each with its own shutdown grace) is not budgeted against the
  remaining margin. Expect a brief overlap in which the old primary finishes sends already in flight.
- During the window, in-flight rows are protected by the **row leases** (a standby reclaims only
  *expired* leases); the new primary runs an owner-scoped recovery **once on promotion** to recover the
  dead primary's in-flight rows promptly (and the ordinary FIFO claim reclaims a stranded lane head, so
  order survives). At-least-once delivery + idempotent re-runs mean a row interrupted mid-delivery is
  re-delivered after its lease expires (so downstream connections must stay idempotent).

### Planned failover — `POST /cluster/stepdown`

Ask the current primary to hand over on purpose, before you patch or reboot it, instead of pulling the
service out from under a live feed. The node **releases its leadership lease and keeps running**, demoted
to standby: a standby acquires the expired lease on its next heartbeat and promotes its graph, and the
node you drained stays up, heartbeating, ready to take leadership back later.

```
POST /cluster/stepdown        # body: {}, or {"force": true} to drain the last promotable node
{ "node_id": "node-a:4812:1f9c2a7b", "was_leader": true, "released_at": 1758000000.5,
  "new_leader_eligible": true, "force": false }
```

- **Permission:** `cluster:control`, a dedicated capability held by **Administrator only** and never
  assignable to a custom role. Behind `require_step_up`, so the caller also passes the per-actor
  admin-write pacing floor, the TOTP MFA gate and the credential-recency window.
- **`was_leader` is what the release returned**, not a reading taken before it. A fence or a lost-lease
  tick can move leadership in between, so a "was this node the leader?" check made first could report a
  failover that released nothing. The same returned value is what the audit row records.
- **Statuses:** `400` when the deployment is **not clustered** — `[cluster]` disabled, or a store with no
  cluster coordinator — so there is no lease to release; `412` when no other node could take the lease
  (next bullet); `409` when this node is not the leader — resolve the leader from `GET /cluster/nodes`
  and call it there; `403` on a missing permission, a stale step-up or an unsatisfied second factor;
  `503` when the engine is not started, when the membership read fails, or when the drain could not be
  achieved (see the `503` bullets below).
- **A `412` means nothing else could take over.** Before it touches leadership, the node reads cluster
  membership once. It looks for another node that is `active`, `promotable`, and has heartbeated within
  `node_timeout_seconds`, the same freshness test `GET /cluster/nodes` uses to name a leader and
  reports for each node as `fresh`. If it
  finds none, stepping down would leave no node able to take the lease, so it refuses and changes
  nothing. That covers a clustered install running one node, and one whose only sibling is
  `promotable = false` or has stopped heartbeating. The check is a snapshot: a sibling that dies just
  after it still counted.
- **`force` drains the node anyway, and waives nothing else.** Send `{"force": true}` to step down the
  last promotable node on purpose. It does not turn a `400` or a `409` into a success. **It does not keep
  the node drained, either.** If no other node takes the lease, the drained node renews it on its first
  tick after the two-heartbeat pause described below. To keep leader work stopped for a whole
  maintenance window, stop the service.
- **`new_leader_eligible` is what that one membership read found:** whether another promotable node had
  a fresh heartbeat. On a `200` it is `false` only when you sent `force`. It names no successor, because
  at the moment of release no standby has taken the lease yet.
- **A `503` reading `members-unreadable` means the membership read failed.** The node did not start the
  stepdown, so nothing was released or demoted. `force` does not skip this read. Retry, and if it
  repeats, look at the store connection.
- **A `503` reading `lock-timeout` means nothing happened at all.** The node's leadership lock was still
  held when `leader_fence_timeout_seconds` ran out, so no lease row was read or written and nothing was
  demoted. This one says nothing about who leads: the endpoint takes no leader check before the
  release, so it can come back from a node that leads nothing — which is why it does not tell you
  leadership is where you left it either. Do not start maintenance. Retry, and if it repeats, look at
  the store connection.
- **A `503` reading `release-unconfirmed` means the node HAS already stood down — and the outcome is
  genuinely unknown.** It has cleared its leadership flag, and this call stopped it claiming for two
  `heartbeat_seconds`. What it could not confirm is whether the write expiring its lease row
  committed, because a lost response to a committed `UPDATE` is indistinguishable here from an
  `UPDATE` that never ran. **It does not tell you a teardown just started**: a retry of an owed write
  finds the node already demoted, and the demotion edge fires only on the call that demotes it.
  - **The node is NOT quiescent when this `503` arrives, and no status code will tell you it is.** The
    demotion edge only wakes the graph supervisor; the teardown itself runs on that other task
    afterwards.
  - **The listeners stop early in that teardown, not at the end of it.** The source stop is the last of
    the three BOUNDED demote phases — each takes its own share of the demotion budget, so the shares
    are bounded and their sum is not the budget — and MLLP, TCP, HTTP and X12 each close their accept
    socket in the synchronous prologue of their own `stop()`, so they stop taking new connections
    before the unbounded phases (connector close, executor shutdown, sandbox close) are reached at
    all. **That buys less than it sounds like.** A source that overruns its share is abandoned rather
    than cancelled; DICOM releases its port inside exactly the call that gets abandoned, so a DICOM
    listener can still hold its port; established connections drain in the background; and a message
    already inside a handler still finishes its commit and its ACK, which count-and-log requires.
    Confirm quiescence with `GET /cluster/nodes` plus the connection view before you touch the node.
  - **If it committed**, a standby acquires on its next heartbeat and the failover is proceeding
    normally, whatever the error page says.
  - **If it did not**, the lease is still live and still owned by a node that has given up leadership,
    so on a first deployment nothing carries the feeds until that node renews itself back in when its
    pause ends — a partitioned pool during a stepdown is the way into that window.
  - **A retry re-sends the write, and answers `409` for as long as this node is not the leader.** The
    first call cleared this node's in-memory leader flag before it wrote, so every later call reports
    `was_leader=false`, which the endpoint turns into `409`. That holds whatever the lease row says:
    the row is not what decides the status code here. A retry reaches the write only after the
    membership read and the `412` check let it through, so while the store is still failing it
    answers `members-unreadable` and re-sends nothing.
  - **Only a maintenance tick can make this node leader again, and retrying prevents one.** The flag is
    set in exactly one place, when a tick's claim succeeds. A tick cannot claim while the stepdown
    pause holds — it returns not-held at the pause gate before touching the database — and **each retry
    that re-sends an owed write re-arms that pause for another two `heartbeat_seconds`**. So retrying
    promptly holds this node in `409` indefinitely, by never letting a tick through. **The remedy is to
    wait, not to retry.**
  - **Once the pause lapses, the next tick settles it.** If the lease row still names the drained node,
    the renew arm — `owner = me`, which carries no expiry test — matches, the node becomes leader
    again, and a stepdown issued *after that* answers `200`. If a standby acquired instead, the row
    names the standby and its lease is live, so the renew arm cannot match and the take-over arm needs
    an expiry that has not passed; the drained node stays a follower and `409` is permanent.
    **That `409` is the failover having worked, not a wrong-node answer.** Do not take the generic
    `409` remedy here and step down whoever `GET /cluster/nodes` now names as leader: that is the
    healthy successor, and draining it undoes the failover you just achieved.
  - Either way, read `GET /cluster/nodes` and confirm `lease_owner` has moved. That, not the status
    code, is what tells you it is safe to start maintenance.
- **Audited** as `cluster_stepdown` in the hash-chained audit log, with the acting user and
  `{node_id, was_leader, released_at, new_leader_eligible, force}` — cluster metadata only, never
  message content. A forced drain of the last node therefore reads `force: true` with
  `new_leader_eligible: false`. **Every call the handler completes is audited under that name, the
  `409` included**, so count drains by `was_leader` rather than by the action name. A `409` writes a
  row reading `was_leader: false, released_at: null`, and that row IS the refusal — which is why the
  `409` needs no separate denied row. The refusals the handler reaches before it can return (`400`,
  `412` and all three `503`s) write `cluster_stepdown_denied` instead, carrying the reason —
  `not-clustered`, `no-promotable-sibling`, `members-unreadable`, `lock-timeout` or
  `release-unconfirmed` — so no two of them read as one condition. That denied row is best-effort: a
  `members-unreadable` or `release-unconfirmed` comes from a store that has just failed, so the endpoint
  keeps the `503` and its remedy rather than losing both to an audit write that could not land either
  way.
- **Who leads next is not reported.** `new_leader_eligible` says only that some node could. At the
  instant of release no standby has acquired yet, so poll `GET /cluster/nodes` and watch `lease_owner`
  move rather than expecting the call to name a successor.

**In-flight work is not drained first.** Stepdown releases leadership; it does not quiesce the graph.
Rows already claimed on the old primary are recovered by the new one through the ordinary lease/reclaim
path, so plan the switchover the same way you plan a restart.

**The drained node stands down briefly before it contends again.** For two `heartbeat_seconds` after a
stepdown it declines to claim or renew, so a sibling wins the expired lease rather than the node you
just drained renewing itself straight back. On a cluster with no other promotable node that window is
leaderless, which is why such a call is refused with `412` unless you send `force`.

**Two known limits, so you can plan around them rather than discover them.** A sibling whose
`acquire_delay_seconds` is longer than two heartbeats is still handicapped out when the pause ends, and
the node you drained then reclaims its own lease ([BACKLOG #1507](BACKLOG.md)). And a node that has
already **self-fenced** cannot be drained at all: it holds no leadership to release, so the call answers
`409` while `GET /cluster/nodes` still shows it as the lease owner until the lease ages out
([BACKLOG #1508](BACKLOG.md)). In that state the node has given up leadership, but do not read that as
quiet: fencing sets a flag and wakes the graph teardown, which then runs on another task, so expect the
same brief overlap a crash failover gets (above). Wait out `leader_lease_ttl_seconds` rather than
retrying the stepdown.

### Tune the lease timings to your network

The defaults (`heartbeat_seconds=10`, `leader_fence_timeout_seconds=20`, `leader_lease_ttl_seconds=30`)
trade a ~30 s crash-failover for ample margin. Lower all three proportionally (keeping
`heartbeat < fence < ttl`) for faster failover at the cost of less tolerance for a slow DB / GC pause.

**The validator enforces the ordering, not a margin.** `heartbeat < fence < ttl` is checked at config
load; nothing checks that any usable time survives between the fence firing and the lease expiring. The
real margin is `ttl - fence` *minus* the renew round trip (the fence baseline is taken after the renew
returns, while the expiry is stamped on the database clock at statement execution) *minus* up to one
fence tick of detection lag — and graph teardown then has to fit in what remains. Tightening these
proportionally keeps the ordering legal while shrinking that budget toward zero, and the failure mode
is a longer overlap between an old and a new primary, not a config error. Keep headroom on a
synchronous-commit or cross-AZ database.

Because the **leadership** lease is evaluated on the **database's** clock, node clock skew does not
affect who may hold leadership. At least two other things *are* node-wall-clock and therefore skew-
sensitive: the **row** leases (see below) and the `nodes.last_seen` heartbeat behind the derived
`leader_node_id`. Do not read that pairing as exhaustive.

## Operational assumptions (honor these)

1. **Clock sync (NTP).** Keep node clocks synced to well within `[store].lease_ttl_seconds`. Row leases
   are wall-clock, so skew mistimes a lease expiry across nodes. Skew also corrupts the derived
   `leader_node_id` on `GET /cluster/nodes`, where a fast-clocked node wins the freshness pick even
   after it dies — and that field is what the console's "cluster has no leader" check keys off, so
   unchecked skew can mask a leaderless cluster. Leadership itself is unaffected (it is evaluated on the
   database clock); this is an operability assumption, not a correctness one.
2. **Identical config on every node.** Each node loads the graph (Connections / Routers / Handlers) from
   its **own** config dir; convergence coordinates the reload *version*, not the files. Deploy the same
   config dir to all nodes.
3. **Coordinated config changes.** Apply a config change as a **coordinated (not rolling) restart**, so
   nodes don't run divergent graphs across the change window.

## Related

- [ADR 0008](adr/0008-cluster-observability-api.md) — the observability API design.
- [docs/adr/](adr/) — the cluster ADRs and the staged-pipeline / store architecture they build on.
- [docs/CONFIGURATION.md](CONFIGURATION.md) — the full `[store]` / `[cluster]` settings catalog.
