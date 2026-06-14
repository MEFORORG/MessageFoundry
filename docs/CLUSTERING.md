# Running a cluster (horizontal scale-out)

> **Status: built (Track B).** Single-node operation is the default and is byte-identical whether or
> not this feature exists — a cluster is opt-in via `[cluster].enabled = true` on a Postgres store.
> Design records: the cluster ADRs [0005](adr/0005-transform-accessible-state.md) /
> [0006](adr/0006-external-data-lookups.md) (the converged data) and
> [ADR 0008](adr/0008-cluster-observability-api.md) (the observability API below). Code:
> [`pipeline/cluster.py`](../messagefoundry/pipeline/cluster.py).

MessageFoundry scales out by running **N identical engine processes against ONE shared PostgreSQL**.
There is no separate broker: the durable staged queue, the row/lane leases, leader election, and the
config/state convergence all live in the shared database. Single-node stays the no-op default; turning
on `[cluster]` makes the nodes coordinate.

## Requirements

A clustered deployment **requires** (enforced at config load):

- `[cluster].enabled = true`
- `[store].backend = "postgres"` — SQLite is single-file/single-node; the cluster needs the shared
  `nodes` table + row/lane leases Postgres provides.
- `[store].pool_size >= 2` — the leader holds **one** dedicated pooled connection for the lifetime of
  its leadership advisory lock, so it needs headroom over the store's working connections.

Every node points at the **same** Postgres database (same `[store]` server/database/schema) and runs
the **same** config dir.

```toml
# messagefoundry.toml — identical on every node (the DB password comes from MEFOR_STORE_PASSWORD)
[store]
backend   = "postgres"
server    = "db.internal"
database  = "messagefoundry"
username  = "mefor"
pool_size = 5          # >= 2

[cluster]
enabled = true
# node_id is auto-derived (host:pid:hex, reusing the store's lease owner-id) — pin it only for a
# stable identity across restarts or in tests.
heartbeat_seconds    = 10.0
node_timeout_seconds = 30.0   # a node is "dead" when last_seen is older than this; must be > heartbeat
reclaim_interval_seconds = 30.0
```

Start the same `serve` command on each host/process — e.g.:

```
python -m messagefoundry serve --service-config messagefoundry.toml --config ./config
```

(For a local DEV Postgres, `scripts/dev/postgres.ps1` sets the `MEFOR_STORE_*` connection env and
`MEFOR_ALLOW_INSECURE_TLS=1` for a loopback, no-TLS database — DEV convenience only.)

## What each node does

All nodes receive over their **listen** sources (MLLP/TCP) and drain outbound deliveries; the cluster
coordinates the parts that must not double-run or interleave:

- **Leader election.** Exactly one node holds a session-level Postgres advisory lock and is the
  **leader**. If the leader stops or its connection drops, a follower takes over on its next tick.
- **Leader-gated WRITE singletons.** Retention purges and the lease-reclaim sweep run **only on the
  leader**, so they never double-execute.
- **Leader-gated poll-source intake.** Only the leader polls a **shared** external resource (a watched
  directory / DB-poll table / remote dir), so a shared source is ingested by exactly one node. Listen
  sources (each node's own MLLP/TCP endpoint) run on every node.
- **Per-lane FIFO across nodes.** A FIFO lane (stage:destination) is leased to a single node at
  claim time, so strict per-lane order holds across nodes with zero reorder window.
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
  "config_version": 7
}
```

Single-node (no cluster) reports `clustered: false`, `is_leader: true`, `config_version: 0`:

```json
{ "node_id": "host:1234:ab12cd34", "clustered": false, "is_leader": true, "config_version": 0 }
```

### `GET /cluster/nodes` — all nodes + the derived leader

`leader_node_id` is the single **live** leader; a crashed ex-leader whose row still carries the leader
flag is filtered out by a freshness check (`last_seen` within `node_timeout_seconds`), so it is never
reported as the leader.

Two-node cluster:

```json
{
  "nodes": [
    { "node_id": "node-a:4812:1f9c2a7b", "host": "node-a", "pid": 4812,
      "status": "active", "started_at": 1750000000.0, "last_seen": 1750000123.4, "is_leader": true },
    { "node_id": "node-b:5210:7c3e9d10", "host": "node-b", "pid": 5210,
      "status": "active", "started_at": 1750000005.0, "last_seen": 1750000124.1, "is_leader": false }
  ],
  "leader_node_id": "node-a:4812:1f9c2a7b"
}
```

Single node (synthetic self-entry — no heartbeat history, so `started_at`/`last_seen` are `null`):

```json
{
  "nodes": [
    { "node_id": "host:1234:ab12cd34", "host": "host", "pid": 1234,
      "status": "active", "started_at": null, "last_seen": null, "is_leader": true }
  ],
  "leader_node_id": "host:1234:ab12cd34"
}
```

A cleanly stopped node leaves a `status: "left"` tombstone (and its leader flag cleared); a crashed
node's row goes stale (its `last_seen` stops advancing) and the freshness filter stops counting it as
the leader. `leader_node_id` is always **at most one** node — during a failover window (an old leader's
flag not yet cleared while the new leader's flag is already set) the freshest still-beating node wins,
so the array never shows two leaders and never names a dead node.

`/cluster/status` is the **per-node authoritative** leadership signal (it reads that node's own
in-memory lock gate); `/cluster/nodes` derives leadership from the heartbeat flag and so can lag it by
up to one `heartbeat_seconds` interval. So immediately after a clean failover the freshly-promoted node
can report `is_leader: true` on `/cluster/status` for one beat before `/cluster/nodes` folds its flag in
and surfaces it as `leader_node_id` — a transient `leader_node_id: null` there is the one-tick fold-in
lag, not a lost-leader incident.

## Operational assumptions (honor these)

1. **Clock sync (NTP).** Lane and row leases are wall-clock — keep node clocks reasonably synced so a
   lease expiry isn't mistimed across nodes.
2. **Identical config on every node.** Each node loads the graph (Connections / Routers / Handlers) from
   its **own** config dir; convergence coordinates the reload *version*, not the files. Deploy the same
   config dir to all nodes.
3. **Coordinated config changes.** Apply a config change as a **coordinated (not rolling) restart**, so
   nodes don't run divergent graphs across the change window.

## Related

- [ADR 0008](adr/0008-cluster-observability-api.md) — the observability API design.
- [docs/adr/](adr/) — the cluster ADRs and the staged-pipeline / store architecture they build on.
- [docs/CONFIGURATION.md](CONFIGURATION.md) — the full `[store]` / `[cluster]` settings catalog.
