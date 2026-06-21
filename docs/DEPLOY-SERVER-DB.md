# MessageFoundry — Server-DB Deployment (PostgreSQL & SQL Server)

**Status: skeleton (2026-06-15) — structure + guidance are final; backend-specific bootstrap snippets
are filled in as the Gate #3 staging runs confirm them.** How to run the engine on a **production
server database** (PostgreSQL or SQL Server) instead of the single-node SQLite default. For the network
exposure / TLS posture of every channel, see [`DEPLOYMENT.md`](DEPLOYMENT.md); for the full settings
reference, [`CONFIGURATION.md`](CONFIGURATION.md); for clustering, [`CLUSTERING.md`](CLUSTERING.md).

---

## Scope & the greenfield-only rule

v0.1 supports **new** server-DB deployments only. There is **no in-place data migration** from SQLite
to a server DB: an operator **drains the SQLite store** (lets the pipeline empty — `in_pipeline → 0` on
`/stats`) and cuts over to a fresh server-DB store. Plan the cutover as a quiet-window switch, not a
copy. (A migration tool is out of scope for v0.1.)

Both server backends are **production-supported** (no "experimental" label):

- **PostgreSQL** — full staged pipeline, advisory-lock concurrency, row leases; backs active-passive HA.
- **SQL Server** — full staged pipeline + query/response capture; **active-passive too** — the
  leader-gate + self-fence keep a single active processor.

---

## 1. Connection settings

Configure `[store]` in the service settings (full reference: [`CONFIGURATION.md`](CONFIGURATION.md)
`[store]`). The essentials:

- `[store].type` — `postgres` or `sqlserver` (vs the default `sqlite`).
- The connection target (host/port/database/auth) — supply secrets via `MEFOR_*` env, never the file.
- `[store].encrypt` (default **true**) + `[store].trust_server_certificate` (default **false**) —
  encrypt the DB connection; only weaken with `MEFOR_ALLOW_INSECURE_TLS` on a trusted lab segment.
- `[store].pool_size` — see *Pool sizing* below.

> _Filled by staging:_ a minimal `[store]` block for each backend (Postgres DSN; SQL Server ODBC).

---

## 2. Schema bootstrap & evolution

- **Bootstrap on open:** the store creates its tables on `open()` if absent — no separate migration
  step to run. Point the engine at an empty database (and a login that may create objects on first run,
  or pre-create the schema from the documented DDL).
- **Schema-evolution policy:** schema changes are **idempotent additive DDL applied on open** (new
  columns/indexes added if missing; nothing destructive). An engine upgrade that adds a column brings it
  in on the next start. Because v0.1 is greenfield-only, there is no cross-version data backfill to plan.
- **SQL Server specifics:** RCSI (`READ_COMMITTED_SNAPSHOT`) is enabled at open (with a DBA-fallback
  warning if the login can't `ALTER DATABASE`); pre-enable it if your security policy forbids that grant.

> _Filled by staging:_ the exact bootstrap login privileges + the pre-create DDL per backend.

---

## 3. Pool sizing

- **Single node:** `[store].pool_size ≥ 3` recommended. Each stage handoff is a committed round-trip and
  the per-stage workers (router, transform, per-outbound delivery) run concurrently against the pool — a
  pool of 1 serializes them against intake.
- **Clustered (active-passive):** `pool_size ≥ 2` is **required** (a cross-section validator refuses a
  smaller pool when `[cluster].enabled`), `≥ 3` recommended — a clustered node also drives the
  membership / lease-renewal maintenance loop against the pool.

---

## 4. High availability (active-passive)

Engine HA in v0.1 is **active-passive**: exactly one node (the leader) binds listeners and processes the
graph; a standby stays warm and takes over on failure. Full design + operations: [`CLUSTERING.md`](CLUSTERING.md).

- **Engine tier (MessageFoundry):** set `[cluster].enabled` on a server-DB store. Leadership is a
  **self-fencing lease** in the shared DB (DB-clock TTL + a no-DB fence watchdog); only the leader
  processes, so there is no split-brain double-processing. `GET /cluster/status` + `/cluster/nodes`
  expose role/lease/roster.
- **DB tier:** database HA — PostgreSQL replication / SQL Server **Always On** — is **delegated to your
  DB administrators**, not built by MessageFoundry. The engine cluster rides the shared store connection,
  so its availability follows the DB tier's.
- **Front it with a floating VIP / load balancer** pointed at the active node's listeners (the standby
  refuses new inbound work until it is promoted). Inbound TLS posture per [`DEPLOYMENT.md`](DEPLOYMENT.md).

> _Filled by the Gate #3 failover run:_ the measured recovery/promotion time + the
> kill-primary-mid-load characteristics (see [`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)).

---

## 5. Pre-flight checklist

- [ ] `[store].type` set to `postgres`/`sqlserver`; connection + auth via `MEFOR_*` env.
- [ ] `[store].encrypt = true` (and **not** `MEFOR_ALLOW_INSECURE_TLS`) for any PHI deployment.
- [ ] `[store].pool_size ≥ 3` (≥ 2 hard-required in cluster mode).
- [ ] Bootstrap login can create the schema on first open, **or** the schema is pre-created.
- [ ] SQL Server: RCSI enabled (auto, or pre-enabled by a DBA).
- [ ] Source store drained (`in_pipeline → 0`) before cutover — greenfield, no in-place migration.
- [ ] (HA) `[cluster].enabled`; DB-tier replication/Always On configured by DBAs; VIP/LB in front.
- [ ] Off-loopback exposure reviewed against [`DEPLOYMENT.md`](DEPLOYMENT.md) (TLS on every channel).

---

*Companion: [`CONFIGURATION.md`](CONFIGURATION.md) (`[store]`/`[cluster]`), [`CLUSTERING.md`](CLUSTERING.md)
(HA topology + failover), [`DEPLOYMENT.md`](DEPLOYMENT.md) (channel × TLS), and the v0.1 plan
([`releases/v0.1-EXECUTION-PLAN.md`](releases/v0.1-EXECUTION-PLAN.md)).*
