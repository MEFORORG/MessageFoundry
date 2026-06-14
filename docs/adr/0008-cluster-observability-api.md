# ADR 0008 — Read-only cluster observability API (`/cluster/status` + `/cluster/nodes`)

- **Status:** Proposed (2026-06-14) — drafted on the owner's go; ratified-on-build. Closes the last
  Track B scale-out step: the coordination built in Steps 3–6b had no operator-visible surface.
- **Built:** Yes — shipped with this ADR (Track B Step 7).
- **Decision in one line:** expose cluster membership, leadership, and config-sync **read-only** over
  the engine HTTP API as two endpoints — **`/cluster/status`** (this node's posture) and
  **`/cluster/nodes`** (all nodes) — both gated by the existing `Permission.MONITORING_READ`; and
  retire the cluster "experimental" banner (one-time WARNING → one-time INFO).
- **Related:** the cluster ADRs [0005](0005-transform-accessible-state.md) /
  [0006](0006-external-data-lookups.md) (the data the coordinator converges),
  [`pipeline/cluster.py`](../../messagefoundry/pipeline/cluster.py) (the coordinator + the new
  `ClusterMember` / `cluster_members()`), [`api/app.py`](../../messagefoundry/api/app.py) (the
  endpoints, modeled on `/status`), [`docs/CLUSTERING.md`](../CLUSTERING.md) (the operator guide),
  [CLAUDE.md](../../CLAUDE.md) §2 (engine/console split; the API is the only external surface).

## Context

Track B built horizontal scale-out incrementally: leader election (Step 4), leader-gated WRITE
singletons + poll-source intake (Step 4b), per-lane FIFO ownership (Step 5), and cross-node
reference / config-reload / transform-state convergence (Steps 6/6b). All of it runs **invisibly** —
the coordinator's state (who is leader, which nodes are alive, what config version the cluster is on)
lives in cached in-memory gates and a Postgres `nodes` table that no API exposes. An operator running
N engine processes against one Postgres has no way to answer "which node is the leader?", "are all my
nodes heartbeating?", or "have the nodes converged to the same config version?" without querying the
database by hand.

Leadership is the awkward case. It is a **session-level advisory lock** held on a dedicated pooled
connection — the lock *is* the leadership, and it is recorded nowhere durable. The `is_leader()` gate
is each node's own cached view of whether it holds the lock; a node cannot cheaply observe another
node's lock from SQL. So a cluster-wide "who is leader?" needs a value each node **writes down**.

## Decision

### Two read-only endpoints, modeled on `/status`

Both follow the `/status` template exactly: `@app.get(..., response_model=...)` with
`engine: Engine = Depends(_get_engine)` and `_user: Identity = Depends(require(Permission.MONITORING_READ))`.

- **`GET /cluster/status` → `ClusterStatus`** — this node's posture from the cheap in-memory
  coordinator gates, **no DB round-trip**: `node_id`, `clustered` (`is_clustered()`), `is_leader`
  (`is_leader()`), `config_version` (`config_version_cached()`).
- **`GET /cluster/nodes` → `ClusterNodeList`** — one `ClusterNode` per known node (id, host, pid,
  status, `started_at`, `last_seen`, `is_leader`) plus the single derived `leader_node_id`. One DB read
  on a real cluster (the shared `nodes` table); none single-node.

The coordinator returns a plain frozen `ClusterMember` dataclass (no API/Pydantic import — the
coordinator stays free of FastAPI per the dependency direction in CLAUDE.md §4); the API maps it to the
`ClusterNode` Pydantic model at the boundary. The new models are console-importable the same way
`SystemStatus` is (defined in `api/models.py`, importable without pulling FastAPI in).

### Permission — reuse `MONITORING_READ`, add no new permission

Cluster membership/leadership is operational read-only telemetry, the same class as `/status` and
`/stats`. It carries **no PHI**. So it reuses `Permission.MONITORING_READ` (held by VIEWER and up) —
no new permission, no roles migration. Fail-closed under enabled auth (401 with no/invalid token, 403
without the permission) exactly like the other monitoring reads.

### Leader identity — a `nodes.is_leader` heartbeat flag + freshness derivation

Because leadership is a session advisory lock recorded nowhere else, each `DbCoordinator` **folds its
own current leadership into a new `is_leader BOOLEAN` column on its existing heartbeat UPDATE** — zero
extra writes, it rides the beat that already runs. `cluster_members()` then reads the table and derives
**at most one** leader, always a *live* one, by combining a **freshness filter** (`last_seen` within
`node_timeout_seconds`) with a **single-freshest** tiebreak — among the rows whose flag is set and that
are still fresh, only the one with the largest `last_seen` is reported as leader:

- A node's heartbeat lags the election by at most one tick (the loop beats *before* the leadership
  maintenance), which is fine for an observability endpoint.
- A **clean shutdown** clears the flag immediately (the mark-left UPDATE sets `is_leader=false`).
- A **hard crash** leaves the flag stale — and the freshness filter discards it once `last_seen` ages
  past the timeout, so a long-dead ex-leader's lingering `is_leader=true` is never reported as the live
  leader.
- During a **failover window** the freshness filter alone is not enough: a just-crashed ex-leader's row
  can still be *fresh* (its `last_seen` is recent but frozen at the crash instant) at the same moment a
  newly-promoted follower has already folded its own `is_leader=true` in — two fresh, flagged rows. The
  single-freshest tiebreak collapses that overlap to the node whose `last_seen` keeps advancing (the
  live leader), so `/cluster/nodes` never shows two leaders and `leader_node_id` is never the dead node.
  This is the key correctness property: the derived leader is always a single *live* node.

A pre-Step-7 `nodes` table (a cluster upgraded in place) is migrated idempotently under the same DDL
advisory lock: `ALTER TABLE nodes ADD COLUMN IF NOT EXISTS is_leader ...`. The
`NullCoordinator` synthesizes a single self-entry (single node, always leader, no DB), so
`/cluster/nodes` is byte-identical in shape on one node and on a cluster.

### Experimental → complete

With the observability API the scale-out feature set is complete, so the one-time cluster-enabled
banner becomes an **INFO** (renamed `_log_cluster_enabled_once`) that states the feature set is built
and summarizes the operational assumptions operators must honor (below), pointing at
`docs/CLUSTERING.md`. The `[cluster]` docstring and `cluster.py` docs no longer call the **cluster**
feature experimental. (The separate SQL-Server-backend and DATABASE-connector "experimental" notes are
unrelated and unchanged.)

## Operational assumptions (called out so operators honor them)

1. **Clock sync (NTP).** Lane leases and row leases are wall-clock; skew between nodes can mis-time a
   lease expiry. Keep node clocks reasonably synced.
2. **Homogeneous config.** All nodes must run **identical config dirs** — the graph, routers, and
   handlers are loaded from each node's own dir; convergence coordinates the *reload version*, not the
   files themselves.
3. **Coordinated config changes.** Apply config changes via a **coordinated (not rolling) restart** so
   nodes don't run divergent graphs across the change window.

## Consequences

- Operators can see membership, the live leader, and the cluster config version over the same localhost
  API the console already uses — no hand SQL.
- One new column (`is_leader`) on `nodes`, written on the existing heartbeat (no new write path); one
  read per `/cluster/nodes` call.
- The coordinator gains a `cluster_members()` contract method (and the `ClusterMember` dataclass) but
  stays free of any API import.

## Alternatives rejected

- **A `/cluster/lanes` endpoint** (per-lane ownership). Owner-declined for this step: the owns-lane
  cache is an eventually-consistent hint, not the correctness gate, and adds surface without a current
  operator need. Membership + leadership + config-version cover the asked-for visibility.
- **A dedicated `cluster:read` permission.** Rejected — the data is non-PHI operational telemetry in
  the same class as `/status`; a new permission would force a roles migration for no security gain.
- **Deriving leadership from the advisory lock at request time** (e.g. `pg_locks`). Brittle and
  backend-internal (matching a node to a lock by classid/key), and still wouldn't survive a crashed
  leader cleanly. The written-down flag + freshness filter is simpler and crash-correct.
- **A push/WebSocket cluster feed.** Out of scope; membership changes are infrequent and a poll of two
  cheap endpoints is sufficient. The existing `/ws/stats` stays the live-metrics channel.
