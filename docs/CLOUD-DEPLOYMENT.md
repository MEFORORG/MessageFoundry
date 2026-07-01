<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# Cloud / Kubernetes deployment — managed Postgres, MLLP L4 load balancing, edge relay

This is the operator guide for running MessageFoundry as a **multi-node active-passive HA** deployment
on a cloud Kubernetes platform (EKS / AKS / GKE / vanilla k8s) or a cloud container service. It packages
the **already-built** active-passive HA (see [`CLUSTERING.md`](CLUSTERING.md) — the authoritative HA
reference) into a copyable target, per [ADR 0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md).

For the **PHI / HIPAA cloud architecture** (BAA, KMS, PrivateLink, region pinning), read its companion
[`CLOUD-PHI-HIPAA.md`](CLOUD-PHI-HIPAA.md). For the per-channel TLS posture and bind guards, read
[`DEPLOYMENT.md`](DEPLOYMENT.md). For the container image itself, read [`../docker/README.md`](../docker/README.md).

> **On-prem-first.** MessageFoundry's identity is on-premises ([ADR 0017](adr/0017-consumer-deployment-model.md)
> Decision 8: every instance runs inside the adopter's trusted network). Cloud is a **credible,
> demand-gated fast-follow**, not a hosted SaaS — there is no MessageFoundry-operated multi-tenant
> offering, and this guide never asks you to put PHI on a public endpoint. The cloud you deploy into is
> **your** cloud account, inside **your** trusted network boundary (private subnets, your VPC).

---

## 0. Pick your shape first

| Shape | Store | Replicas | When | Manifest |
|---|---|---|---|---|
| **POC / on-prem edge** | SQLite on a PVC | 1 | A trial, a lab, a small single-site edge relay | [`docker/k8s/statefulset.yaml`](../docker/k8s/statefulset.yaml) |
| **Cloud / k8s HA (this doc)** | **managed Postgres** | 3 (1 leader + 2 warm standbys) | A production multi-node deployment that must survive a node/pod loss | [`docker/k8s/ha-postgres.yaml`](../docker/k8s/ha-postgres.yaml) |
| **On-prem enterprise HA** | SQL Server (Always On AG) | N | An enterprise already standardized on SQL Server | doc variant — see [§2.3](#23-sql-server-always-on-ag-on-prem-enterprise-variant) |

**SQLite / single-node is POC or on-prem-edge ONLY for multi-node cloud.** It physically cannot back HA:
a SQLite store on a `ReadWriteOnce` PVC binds the workload to **one** writer (one node can mount RWO), and
the `[cluster]` validator ([`config/settings.py`](../messagefoundry/config/settings.py)) **refuses to
start** if `[cluster].enabled` is set without `[store].backend ∈ {postgres, sqlserver}` and
`[store].pool_size >= 2`. So an HA manifest cannot silently degrade to a single SQLite writer — it fails
loud at config load ([ADR 0047 AC-2](adr/0047-cloud-kubernetes-ha-deployment-packaging.md)).

---

## 1. The HA model in one paragraph (the LB recipe rests on it)

MessageFoundry HA is **active-passive**: N identical engine processes point at **one shared server DB**;
exactly one — the **leader**, elected by a self-fencing lease in that DB — runs the wired graph. The
engine **graph supervisor** ([`pipeline/engine.py`](../messagefoundry/pipeline/engine.py) `_start_graph`
/ `_reconcile_graph` / `_graph_supervisor_loop`) starts the `RegistryRunner` — **listeners and workers** —
**only while this node holds leadership**, and tears it down on demotion/fence. A standby therefore **binds
nothing**: its MLLP/TCP listener port is **closed**. That single fact is what lets a dumb L4 load balancer
follow failover with **zero engine VIP code** — a TCP-connect health check to the listener port passes only
on the leader. (This is *not* the per-source `leader_gate`, which a LISTEN source deliberately ignores; it
is the supervisor one level up. See [`CLUSTERING.md`](CLUSTERING.md) §"Active-passive graph gating".)

Active-**active** (a second concurrent writer) is **dropped and its code removed** (#396). HA here is
*failover*, never two live writers. To scale one partner's **intake**, use L3 parallel-lane / order-group
sharding ([ADR 0037](adr/0037-multi-process-sharding-l3.md)) — never a second replica of that listener.

---

## 2. The store: lead with managed Postgres

Cloud k8s HA leads with a **managed PostgreSQL** backend — Amazon RDS / Aurora PostgreSQL, Google Cloud
SQL for PostgreSQL, or Azure Database for PostgreSQL — matching the Mirth/IRIS shape (external Postgres,
not an embedded DB). The managed service owns **DB-tier HA** (Multi-AZ / regional replicas / failover);
MessageFoundry does **not** replicate the store itself — it rides the shared connection, so its
availability follows the DB tier's ([`CLUSTERING.md`](CLUSTERING.md) "DB-tier HA is delegated to the
database").

### 2.1 Required `[store]` / `[cluster]` settings

Set these identically on every replica (env-var form shown; the manifest injects them). Every name below
is verified against [`config/settings.py`](../messagefoundry/config/settings.py):

| Env var | `[…]` setting | Value | Why |
|---|---|---|---|
| `MEFOR_STORE_BACKEND` | `[store].backend` | `postgres` | SQLite is **refused** under `[cluster]` |
| `MEFOR_STORE_SERVER` | `[store].server` | your managed-PG endpoint | the RDS/Cloud SQL/Azure DB host |
| `MEFOR_STORE_PORT` | `[store].port` | `5432` | Postgres default (left at the 1433 default, the validator maps it to 5432 for `postgres`) |
| `MEFOR_STORE_DATABASE` | `[store].database` | `messagefoundry` | the database name |
| `MEFOR_STORE_USERNAME` | `[store].username` | `mefor` | the login |
| `MEFOR_STORE_PASSWORD` | `[store].password` | *(secret)* | **env/secret only** — never the config file |
| `MEFOR_STORE_POOL_SIZE` | `[store].pool_size` | `40` | default 40, the inverted-U optimum — don't set higher ([ADR 0062](adr/0062-default-store-pool-size.md)); `>= 2` under `[cluster]`. **Budget:** `engines × pool_size` hit one managed-PG `max_connections` (~2 engines at 40/100) — raise it, add a pooler, or size down; never split the store ([DEPLOY-SERVER-DB.md](DEPLOY-SERVER-DB.md) §3) |
| `MEFOR_CLUSTER_ENABLED` | `[cluster].enabled` | `true` | turns on the leader lease + graph gating |
| `MEFOR_STORE_REQUIRE_ENCRYPTION` | `[store].require_encryption` | `true` | fail-closed: refuse to start keyless (PHI at rest) |
| `MEFOR_STORE_ENCRYPTION_KEY` | `[store].encryption_key` | *(secret)* | base64 32 bytes — `messagefoundry gen-key` |

`[store].encrypt` defaults **true** and `[store].trust_server_certificate` defaults **false**, so the DB
connection is TLS-verified out of the box. Give the managed Postgres a **CA-trusted** server cert (the
provider's default RDS/Cloud SQL/Azure CA chains to a public root, or pin a private CA via
`[store].ssl_root_cert` — **Postgres only**, see [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §5). **Do not
set `MEFOR_ALLOW_INSECURE_TLS`** in a real deployment — it disables TLS verification across every transport.

### 2.2 Lease timings vs. failover speed

The defaults trade a ~30s crash-failover for margin: `heartbeat_seconds=10`,
`leader_fence_timeout_seconds=20`, `leader_lease_ttl_seconds=30` (invariant
`heartbeat < fence < ttl`, enforced at load). A **clean** stop (rolling restart, node drain) expires the
lease at once, so a standby takes over in ≈ one heartbeat; a **crash/partition** ages the lease out, up to
`leader_lease_ttl_seconds`. Failover is **not instantaneous** — set partner expectations accordingly.
Lower all three proportionally for faster failover at the cost of less tolerance for a slow DB / GC pause;
if you do, **lower the pod grace period in lockstep but keep it `> leader_lease_ttl_seconds`** (see §4).

### 2.3 SQL Server (Always On AG) — on-prem enterprise variant

Both server backends are HA-eligible. For an enterprise already on SQL Server, run the **same** cluster
mechanism against a SQL Server store with **Always On Availability Groups** for the DB tier. This is an
**on-prem doc variant**, not a second shipped manifest — to adapt `ha-postgres.yaml`:

- `MEFOR_STORE_BACKEND=sqlserver`, point `MEFOR_STORE_*` at the AG listener, `MEFOR_STORE_PORT=1433`.
- Use the **`messagefoundry:sqlserver`** image (it adds the OS-level MS ODBC Driver 18); the slim default
  has no ODBC.
- SQL Server (ODBC Driver 18) has **no** connection-string CA-file keyword — trust the DB CA via the host
  **machine trust store**, not `ssl_root_cert` (which is rejected for `sqlserver`). See
  [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §5.
- Everything else (the leader lease, graph gating, the LB recipe below) is identical — both backends run
  the same active-passive coordinator.

---

## 3. MLLP exposure — an operator-built L4 load balancer that follows failover

Off-cluster MLLP partners reach "the engine" through an **operator-built L4 load balancer** (an NLB), not
a fixed pod. MessageFoundry does **not** ship a load balancer — you stand it up — but the design makes the
VIP follow failover **passively**, with no engine VIP code.

### 3.1 The recipe

- **One L4 NLB listener per MLLP port.** MLLP is long-lived raw TCP, so it is L4 (TCP) load balancing —
  **not** an L7/HTTP ingress (see the prohibitions below).
- **A primary-only health check.** Because the graph supervisor binds the inbound listener **only on the
  leader**, a standby's listener port is **closed**. So:
  - **Default (zero-dependency): a TCP-connect health check** to the MLLP listener port. It succeeds only
    on the primary (the standbys refuse the connection), so the LB routes inbound traffic to the primary
    and follows it across a failover automatically.
  - **For L7-capable LBs: `GET /cluster/status` and require `role == "primary"`** (equivalently
    `is_leader == true`) on the engine API. This is the explicit, unambiguous probe where the LB can read
    HTTP — the API is up on **every** node, so a plain `/health` would *not* distinguish primary from
    standby; you must read `role`/`is_leader`. **Caveat — `/cluster/status` is authenticated.** It is gated
    by the `monitoring:read` permission (`Depends(require(Permission.MONITORING_READ))` in
    [`api/app.py`](../messagefoundry/api/app.py)), so an unauthenticated LB health probe gets `401/403` on
    **every** node (the leader included) and the LB would mark all backends unhealthy and black-hole MLLP.
    To use it, the LB must **inject a static bearer token / session header** into the probe (mint a
    least-privilege `monitoring:read` token; rotate it) — and **many L4 LBs cannot send auth headers at
    all**. If your LB cannot authenticate the probe, use the **TCP-connect-to-2575** default above (it needs
    no auth and works on any L4 LB); there is **no** tokenless primary-only HTTP endpoint to point an
    unauthenticated L7 check at. The `/health` liveness endpoint *is* tokenless, but it is 200 on every node
    and so cannot select the primary.
- **Health-check interval ABOVE the graph-reconcile interval.** The engine reconciles graph leadership on
  a short interval (`engine._graph_reconcile_interval`, ~1s — derived from the lease timings). Set the LB
  health-check interval **comfortably above** it (e.g. **10s**) so the VIP does **not flap** during the
  brief start/stop window of a leadership transition.
- **Drain in-flight frames.** Set the LB's deregistration delay (AWS NLB: `deregistration_delay`, ~60s) so
  a failing-over target finishes in-flight MLLP frames before it is removed. Set the LB **idle timeout
  above** the socket keepalive so a quiet-but-live MLLP connection is not reaped.
- **Partners reconnect on drop.** MLLP/TCP senders see a connection drop on failover and reconnect through
  the VIP — standard MLLP client behavior; require it of partners.

The `ha-postgres.yaml` manifest carries an AWS-NLB annotation block (commented) wiring exactly this:
`aws-load-balancer-type: external`, `healthcheck-protocol: TCP`, `healthcheck-port: 2575`,
`healthcheck-interval: 10`, and `deregistration_delay.timeout_seconds=60`.

### 3.2 Two hard prohibitions for MLLP

- **NO L7 / HTTP ingress for MLLP.** MLLP is a long-lived raw-TCP framing (start/end blocks), not
  request/response HTTP. An L7 ingress controller (ALB / nginx-ingress / Gateway API HTTPRoute) cannot
  carry it. Use an **L4** NLB. (The API plane *can* sit behind an L7 ingress — only the MLLP data plane
  cannot.)
- **NO HorizontalPodAutoscaler for MLLP.** HA replicas are for **failover**, not for spreading one
  partner's load. Only the leader processes (active-passive); sticky long-lived MLLP senders do not
  rebalance across replicas; and autoscaling conflicts with **per-channel FIFO / single-writer-per-lane**.
  Scale **intake** with L3 parallel-lane / order-group sharding ([ADR 0037](adr/0037-multi-process-sharding-l3.md)),
  never by replicating a partner's inbound listener.

### 3.3 The API plane

The engine API (console / IDE / monitoring) is a control/read plane over the shared DB and is up on
**every** node, so an API VIP can health-check the unauthenticated **`GET /health`** for liveness, or pin
operations to the primary via **`GET /cluster/status`** (`role`) / **`GET /cluster/nodes`**
(`leader_node_id`, `lease_owner`). **Both `/cluster/*` endpoints require `monitoring:read`** (see §3.1) — a
caller (LB probe or operator tooling) must present a `monitoring:read` token; only `/health` is tokenless.
Unlike MLLP, the API may sit behind an L7 ingress (it is HTTP).

---

## 4. Pod lifecycle — grace, PDB, rolling updates

The reference manifest ([`ha-postgres.yaml`](../docker/k8s/ha-postgres.yaml)) sets:

- **`terminationGracePeriodSeconds: 40`** — long enough for a drained **leader** to release its lease and
  finish `engine.stop()`'s ordered teardown before SIGKILL. The formula the manifest comment carries:

  ```
  grace >= leader_lease_ttl_seconds            (default 30s)
         + ~10s graph-quiesce
         + ~5s  PER MLLP listener (drained SERIALLY — additive)
         + store-close/flush margin
  ```

  The single-node `statefulset.yaml` already ships `40` (30s lease TTL + a light graph); the HA manifest
  **carries that forward** as the reconciled default for a small graph. **Raise it** for many-MLLP-listener
  graphs: `40 + 5*(listeners-1)`. It must always stay **`> leader_lease_ttl_seconds`**, or a drained leader
  is SIGKILLed still holding its lease (delaying failover by the whole TTL).
- **A `PodDisruptionBudget` with `maxUnavailable: 1`** — a voluntary disruption (node drain, rollout) may
  evict at most one replica at a time, so the cluster never drops below 2 live nodes (one leader + one warm
  standby). Combined with the rolling-update `maxUnavailable: 0` / `maxSurge: 1`, a config rollout replaces
  pods one at a time without dropping the floor ([ADR 0047 AC-4](adr/0047-cloud-kubernetes-ha-deployment-packaging.md)).
- **No readinessProbe.** `/health` is tokenless and answers before startup completes, and there is no
  unauthenticated readiness endpoint — a readinessProbe on `/health` would mark a pod Ready prematurely.
  A standby is intentionally "Ready": it must be a warm failover target. Primary-vs-standby routing is the
  **LB health check's** job (TCP-connect to the MLLP port), not a k8s probe's.

> **Coordinated, not divergent, config changes.** The manifest ships `strategy: RollingUpdate`, which is
> the right shape for changes that **do not** alter the baked config/graph (e.g. a base-image bump that
> keeps `/config` byte-identical). But a **config/graph change** (a new config-baked image) applied as a
> rolling update runs a **mixed-version window** — old leader + new standbys — which is the **divergent-graph**
> window [`CLUSTERING.md`](CLUSTERING.md) "Operational assumptions" item 3 says to avoid. A rolling replace is
> always **split-brain-safe** (single-leader lease + fence token = one writer), but for a config/graph change
> do a **coordinated** restart instead: scale the Deployment to `0` then back to `3` (or otherwise avoid a
> mixed-version leader window) so no two nodes run divergent graphs. `kubectl rollout restart` is **also**
> rolling and is **not** a substitute. Cert note: **API TLS cert rotation needs a pod restart** (uvicorn
> builds the TLS context once; only MLLP certs hot-reload on `/config/reload`) — fold the cert-renewal into
> your runbook.

---

## 5. Hybrid edge-relay topology (the realistic on-prem-adopter cloud path)

The strongest objection to cloud for HL7 is **connectivity**, not compliance: every MLLP message would
cross a WAN to an on-prem EHR, and MLLP has no native TLS. The industry answer — and MessageFoundry's
recommended cloud path — is **hybrid**: terminate MLLP **near the EHR** and forward it over a **private
encrypted link** to the cloud engine.

```
  on-prem hospital network                      private encrypted link            your cloud VPC
  ┌──────────────────────────┐                 (site-to-site VPN /              ┌───────────────────────┐
  │  EHR / lab / PACS         │  MLLP (LAN)     AWS Direct Connect /            │  cloud engine (HA)     │
  │  (sends HL7 v2)           │ ───────────▶    Azure ExpressRoute)            │  replicas: 3 + managed │
  └──────────────────────────┘                                                 │  Postgres (this doc)   │
            │                          ┌───────────────────────────────┐       └───────────┬───────────┘
            └─ MLLP terminated here ──▶│  EDGE RELAY (same engine image)│ ──── outbound ───▶│
               (inbound MLLP())        │  staged store = WAN BUFFER     │   MLLP/TCP over    │
                                       │  inbound MLLP → outbound MLLP  │   the private link │
                                       └───────────────────────────────┘                    │
```

**The edge relay is the SAME engine image — no new code** (ADR 0047 ratification). It is just an
on-prem MessageFoundry instance (the container image, or the Windows-service install) whose graph is:
an **inbound `MLLP()`** that receives the EHR feed on the LAN → a Router/Handler → an **outbound `MLLP()`
or `TCP()`** that forwards to the cloud engine over the private link. It reuses the existing **outbound
MLLP/TCP connectors** verbatim.

**Why the staged store is the selling point.** The relay's **at-least-once staged store** ([ADR
0001](adr/0001-staged-pipeline-architecture.md)) is the **WAN buffer**: a WAN blip queues outbound rows in
the relay's durable store and **drains on reconnect** — nothing is dropped (the count-and-log invariant
holds end to end). The same property protects the cloud engine's inbound. This sidesteps the real cloud
objection (a WAN-crossing, TLS-less MLLP feed) **without changing the engine**:

- MLLP stays on the **LAN** (loopback-or-segment near the EHR), so it never crosses the WAN in cleartext.
- The relay→cloud hop rides the **private encrypted link** (VPN / Direct Connect / ExpressRoute) — and you
  can additionally run the relay's outbound MLLP with `tls=True` (MLLP-over-TLS) for defense in depth.
- A WAN outage is a **buffered queue**, not lost messages.

The edge relay can be a **single node** (POC/edge SQLite is fine — its job is buffering, and DB-tier HA
lives at the cloud engine), or itself an HA pair on-prem if the edge must survive a node loss. Its
durability (the WAN buffer) requires the store volume to **persist** like any at-least-once store.

---

## 6. Off-box log forwarding — NOT in this manifest

The built `[logging]` off-box forwarder (`[logging].forward_*` → syslog/SIEM) is **plaintext** today:
`SyslogProtocol` has UDP/TCP variants but **no TLS** ([`config/settings.py`](../messagefoundry/config/settings.py)).
Enabling it from an ephemeral cloud pod would put PHI-adjacent log metadata on the wire in cleartext, so it
is **deliberately omitted** from the HA manifest and is **not** turned on here. **Do not "flip it on" as-is.**
Before any prod-HA enablement, pair it with a **TLS-forwarding sidecar / TLS collector** (or rely on the
container runtime's log driver to a TLS-terminating collector). This is an open follow-up, tracked in ADR
0047's "To resolve" — not a step in this runbook.

---

## 7. Quick start (managed Postgres, k8s)

1. **Provision a managed Postgres** (RDS / Cloud SQL / Azure DB) in a **private subnet**, Multi-AZ, with
   KMS at-rest encryption and a CA-trusted server cert. Create the `messagefoundry` database + a `mefor`
   login that may create objects on first open (the store bootstraps its schema on `open()`).
2. **Build a config-baked image** (`FROM messagefoundry:<version>; COPY --chown=10001:10001 config /config`)
   and push it to your private registry.
3. **Create the Secret** ([`docker/k8s/secret.example.yaml`](../docker/k8s/secret.example.yaml)) with
   `store-encryption-key`, `store-password`, and the API TLS cert/key (and optional `api-tls-key-password`).
4. **Apply** [`docker/k8s/ha-postgres.yaml`](../docker/k8s/ha-postgres.yaml) with `image:` set to your baked
   image and `MEFOR_STORE_SERVER` set to the managed-PG endpoint.
5. **Stand up the L4 NLB** (one listener per MLLP port, primary-only TCP-connect health check at a ~10s
   interval, deregistration delay ~60s) per [§3](#3-mllp-exposure--an-operator-built-l4-load-balancer-that-follows-failover).
6. **Verify HA:** `GET /cluster/nodes` shows 3 nodes + one `leader_node_id`; delete the leader pod and
   confirm a standby is promoted (`/cluster/status` `role` flips to `primary`) and the NLB VIP follows.
7. **Read [`CLOUD-PHI-HIPAA.md`](CLOUD-PHI-HIPAA.md)** and complete the BAA / KMS / PrivateLink posture
   before any PHI flows.

---

## Related

- [`CLUSTERING.md`](CLUSTERING.md) — the authoritative active-passive HA design + failover behavior.
- [`CLOUD-PHI-HIPAA.md`](CLOUD-PHI-HIPAA.md) — the cloud HIPAA secure-architecture posture (BAA, KMS, PrivateLink).
- [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) — server-DB store setup, pool sizing, DB-CA trust + rotation.
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — per-channel bind/TLS posture and the off-loopback exposure gates.
- [`../docker/README.md`](../docker/README.md) — the container image, the single-node manifest, and the compose `ha` profile.
- [ADR 0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md) — the decision this guide implements.
