<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# MessageFoundry — SQL Server Always On (AOAG) Deployment Guide (Windows)

This guide shows how to architect a **two-data-center, high-availability MessageFoundry
deployment** on Windows Server, using a **SQL Server Always On Availability Group** as the store.
The topology has four parts: a primary data center at the hospital, a remote offsite DR data
center, an active + standby engine VM pair (MessageFoundry's built-in active-passive clustering),
and an AOAG behind the store connection. It is written for the **DBAs who administer the AG** and
the **Windows / virtualization admins** who place the VMs. This is the on-prem "SQL Server
(Always On AG)" variant ratified in
[ADR 0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md) and sketched in
[`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md) §2.3, now realized for Windows Server VMs.

**Windows Server + SQL Server only.** This document does not cover PostgreSQL HA (streaming
replication, managed-PG failover); see [`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md) for that path.

---

## 1. Who this is for & what this doc does not repeat

This guide assumes the database tier is an Availability Group. It focuses on the decisions unique
to that choice: where the VMs go, which replicas commit synchronously, and how MessageFoundry's
failover interacts with the AG's. It does not duplicate the companion documents — each owns its
own area:

- [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) — `[store]` settings, pool sizing, schema
  bootstrap, DB-CA trust / certificate rotation, the greenfield-only rule. (It is still marked
  *skeleton* for the exact bootstrap login privileges, so link to it rather than guessing.)
- [`CLUSTERING.md`](CLUSTERING.md) — the authoritative engine-HA reference: leader lease,
  graph gating, epoch fencing, `/cluster/*` endpoints, lease-timing tuning.
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — network exposure, per-channel TLS posture, the VIP/LB
  requirement.
- [`SERVICE.md`](SERVICE.md) / [`INSTALL-GUIDE.md`](INSTALL-GUIDE.md) — NSSM service install,
  service accounts, DPAPI key files, log/config ACLs on each engine VM.
- [`EARLY-ADOPTER-GUIDE.md`](EARLY-ADOPTER-GUIDE.md) §14 — step-by-step cluster stand-up
  (per-node services, `[cluster]` TOML, NTP, `/cluster/nodes` verification).

**Division of labor (keep it explicit).** DB-tier HA is **delegated to the DBAs**, and the AG is
that delegation fulfilled; MessageFoundry never replicates the store itself
([`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §4, [`CLUSTERING.md`](CLUSTERING.md)). Engine-tier
HA is MessageFoundry's built-in active-passive cluster. These are **separate failover axes**, and
this document composes them. Engine HA is always failover, never two live writers: active-active
was dropped and its code deleted (#396).

---

## 2. Reference architecture

```
                        HL7 / MLLP senders
                               |
                    VIP / L4 load balancer (operator-built)
          TCP-connect health check per MLLP port -- passes ONLY on the
          engine that holds leadership (a standby binds no listeners)
                               |
 ============= PRIMARY DC (hospital) =============       ======== DR DC (offsite) ========
 |                                               |       |                               |
 |  Host A          Host B                       |       |  Host E                       |
 |  +---------+     +---------+                  |       |  +---------+                  |
 |  |Engine VM|     |Engine VM|                  |       |  |DR Engine|                  |
 |  |#1 ACTIVE|     |#2 active|                  |       |  |VM       |                  |
 |  |(leader) |     |-eligible|                  |       |  |SERVICE  |                  |
 |  |         |     |STANDBY  |                  |       |  |STOPPED  |                  |
 |  |         |     |         |                  |       |  |(cold)   |                  |
 |  +----+----+     +----+----+                  |       |  +----+----+                  |
 |       |               |                       |       |       :                       |
 |       +-------+-------+                       |       |       :                       |
 |               | TDS/TLS to AG listener        |       |       :                       |
 |  Host C          Host D                       |       |  Host F                       |
 |  +---------+     +---------+                  |       |  +---------+                  |
 |  |SQL VM   |     |SQL VM   |                  |       |  |SQL VM   |                  |
 |  |AG R1    |     |AG R2    |                  |       |  |AG R3    |                  |
 |  |primary  |     |SYNC +   |                  |       |  |ASYNC    |                  |
 |  |SYNC +   |     |AUTO f/o |                  |       |  |forced   |                  |
 |  |AUTO f/o |     |         |                  |       |  |f/o only |                  |
 |  +---------+     +---------+                  |       |  +---------+                  |
 |  all engines point [store].server here        |       |                               |
 |                                               |       |                               |
 =================================================       =================================

   Async log send: primary R1/R2  ------ over the WAN ------>  R3  (forced failover only).
   The DR-engine connector is dotted ( : ): its NSSM service is STOPPED in steady state and
   started only per the section 6 DR runbook -- promoted with the database as a site unit.

 WSFC quorum: primary-DC nodes vote, DR node gets ZERO votes; witness = CLOUD WITNESS
 (or a file share witness at a THIRD site -- never inside either data center).
```

The commit topology reduces to one rule: **synchronous commit stays inside the hospital DC**
(R1 + R2, with automatic failover), while **the DR replica is asynchronous** (forced failover
only). The WAN never sits in the commit path; §3 works through the arithmetic for why.

### Placement & anti-affinity

| VM | Placement rule | Enforcement | Negotiable? |
|---|---|---|---|
| SQL AG R1 + R2 | **Never on the same hypervisor host** (N+1 hosts for the WSFC nodes) | VMware: DRS VM-VM anti-affinity (mandated by Broadcom's WSFC-on-vSphere KBs: 313230 for vSphere 7.x / 313472 for 8.x / 404711 for 9.x). Hyper-V: `AntiAffinityClassNames` + `ClusterEnforcedAntiAffinity=1` / SCVMM availability set | **No** — this is the non-negotiable rule |
| Engine VM #1 (hospital, active) | Separate host from **both** local AG replicas, same cluster/leaf (10/25GbE) | Mutual anti-affinity across engine + R1 + R2 (needs ≥ 3 hosts + HA spare capacity) | With only 2 hosts: accept the engine sharing a host with whichever replica is currently *secondary* |
| Engine VM #2 (hospital, active-eligible) | Separate host from **both** local AG replicas *and* from engine #1, same cluster/leaf — so a single engine-host loss stays an **in-hospital** engine failover, not a cross-WAN or site event | Extend the mutual anti-affinity set to both engines + R1 + R2 | With only 2–3 hosts: at minimum keep it off engine #1's host; a shared engine host is exactly the failure domain §3.3 warns about |
| Engine VM (DR) | DR DC, separate host from R3 where possible; **service stopped in steady state (cold)** — promoted **with the database** as a site unit, not an independent engine-failover target | Soft rule | Yes |
| Quorum witness | Cloud witness, or file share witness at a third site | — | No witness in either DC alone |

Anti-affinity rules are **VM-to-VM, not role-aware**. You cannot express "engine ≠ current AG
primary," because the primary role floats on failover. The robust form is mutual anti-affinity
across the engine and *both* local replicas. Do **not** co-locate the engine VM with the SQL
primary to chase latency: §3.3 shows the saving is noise while the shared failure domain is real.

Running a **single hospital engine** (dropping engine #2) is an explicitly **degraded** variant, not
the baseline. With only one active-eligible engine in the hospital DC, any engine-host failure has
nowhere local to promote to, so it immediately escalates to either a **cross-WAN active engine**
(the DR engine winning the lease — paying the §3.3 commit multiplier on every message) or a **full
DR site event** (the §9 sender-cutover cost). Keep the second hospital engine unless you have
consciously accepted that escalation.

---

## 3. Why commit latency drives the design

### 3.1 MessageFoundry's write profile

The staged pipeline makes **~7 durable commits per message** at the default single-handler,
single-destination fan-out. Those commits are the pre-ACK ingress commit; a claim + handoff
commit pair at each of the two producer boundaries (ingress→routed, then routed→outbound); and a
delivery claim + `mark_done` pair on the outbound stage, where `mark_done` also runs the finalizer
inside its single commit. That totals 1 + 2 + 2 + 2 = ~7. The general formula is **3 + 2H + 2N**
for H handlers and N destinations, so a fan-out of 2 is 9. See
[`benchmarks/step-b-write-amplification.md`](benchmarks/step-b-write-amplification.md),
[ADR 0051](adr/0051-corepoint-throughput-parity-strategy.md), and
[ADR 0055](adr/0055-group-commit-durable-write.md). An inline fast-path that cuts 7 → 5 exists,
but it is **default-off**: it is a per-inbound `inline=True` opt-in on `inbound()`, with no
service-level `[transform]` setting ([ADR 0057](adr/0057-inline-step-a-fast-path.md)). Plan around
~7.

Those ~7 commits run **serially per message within an ordered lane** (a strictly-FIFO interface),
so the commit round-trip governs per-lane throughput:

```
per-lane msg/s  ≈  1000 / (commit_chain_depth × per-commit round-trip ms)
                ≈  1000 / (7 × RTT_ms)
```

The documented anchor works out to ~7 × 2.84 ms ≈ 20 ms/message ≈ **50 msg/s per ordered
lane** on a LAN-attached SQL Server ([`throughput-roadmap.md`](throughput-roadmap.md)). Three
distinct ceilings apply, and you should not conflate them:

- **Per ordered lane:** the commit round-trip chain binds (measured; the box sits ~96% idle at
  the single-lane plateau). Every millisecond added to the commit path lands **~7× in every
  message**.
- **Per engine box (aggregate, many lanes):** engine CPU binds
  ([`throughput-build-plan.md`](throughput-build-plan.md)).
- **Commit-tier IOPS:** headroom on decent hardware (~23,600 commits/s measured on local NVMe —
  11–36× above what the engine drove).

A sync-commit AG replica adds its **hardening round trip to every one of those ~7 commits**. That
is exactly why the decisive architectural choice below is *which replica is synchronous*, not
*which hypervisor host the engine shares*. An app-side group-commit experiment attacks the same
term from the other side: coalescing commits measured ~3.5× more commits/s. That work is
design-stage **for the server-DB backends**; the shipped `[store].group_commit_window_ms`
([ADR 0055](adr/0055-group-commit-durable-write.md)) is SQLite-only and ignored on SQL Server.

### 3.2 The latency budget

The table below lists verified typical ranges at steady state on healthy hosts:

| Path segment | Typical added latency |
|---|---|
| VM ↔ VM, **same hypervisor host** (vSwitch) | ~30–100 µs RTT |
| VM ↔ VM, **separate hosts, same 10/25GbE leaf** (default virtual stack) | ~100–300 µs RTT (SR-IOV / latency tuning can push < 100 µs) |
| Local **enterprise NVMe (power-loss-protected)** log flush | ~30–100 µs (SQL-observed WRITELOG ~0.03–0.3 ms — it includes log-writer queueing, not just device time) |
| **Mid-tier SAN** log write | ~300–1,000+ µs |
| **Sync-commit ack, local replica** on the same leaf | ~0.5–2 ms typical per commit (~0.3 ms best-case; spikes under log-send bursts) |
| Fiber propagation | ~5 µs/km **one-way** ≈ ~1 ms **RTT** per 100 km |
| Metro / DR link RTT | ~0.5–2 ms dark-fiber metro; ~1–10+ ms leased/routed circuits (measure the link — routed paths exceed map distance) |
| Deep C-state (C6) core wake | ~100–170 µs added to the tail (see §7.4) |

All of these figures sit 1–2 orders of magnitude below the ~10–15 ms/transfer storage latency
that Microsoft treats as SQL Server problem territory. This budget is therefore an *optimization*
exercise, and the ~7 commits/message multiplier is what makes it worth optimizing.

### 3.3 The same-hypervisor question, answered

**Q: Should the engine VM sit on the same hypervisor host as the SQL primary to shave latency?
A: No.**

- The saving is only **~50–150 µs per round trip** (same-host ~30–100 µs vs cross-host
  ~100–300 µs), on a commit path that runs ~0.5–1.5 ms end-to-end with a local sync replica. That
  is realistically **~5–15%** of a path dominated by the log flush plus the sync-replica hardening
  ack. Best case, ~7 round trips × ~0.15 ms ≈ **~1 ms per message**.
- It creates a **shared failure domain**: one host failure then takes out the engine *and* the AG
  primary at once, converting two independent, automatically-recovered failures into a single
  compound one.
- Compare the lever that actually matters. Putting the WAN in the commit path — synchronous commit
  to the DR replica — at a 5 ms link RTT adds **≥ ~35 ms serialized per message** (7 × 5 ms is a
  floor, since each commit also pays the remote log harden). That is ~35× the best-case
  co-location saving, and it would cut the ~50 msg/s ordered-lane anchor to roughly ~18 msg/s.
  State the penalty precisely: it is a per-message *latency* cost and a single-stream throughput
  cap, because concurrent lanes still overlap on a server DB.

**Prescription.** Put the engine and SQL VMs on **separate hosts in the same cluster/leaf**
(10/25GbE), apply anti-affinity per §2, and spend the engineering attention on **AOAG commit
topology (§4)**: sync local, async to DR.

---

## 4. AOAG configuration for MessageFoundry

**Prerequisites.** Settle these at design time, before anything below:

- **SQL Server 2022 or 2025, Enterprise Edition.** The three-replica topology in §4.1 — two
  synchronous replicas with automatic failover, plus an async DR replica — is **impossible on
  Standard Edition**. Standard's Basic Availability Groups cap at **two replicas and one
  database per AG**, which would force a different design. Enterprise versus Standard is a very
  large per-core cost delta, so put it in the project budget first (licensing detail in §10).
  MessageFoundry supports SQL Server **2022 and 2025** only; 2019 is not supported.
- **Windows Server 2022/2025 on the SQL VMs** (§7.4 states the engine-VM OS). All WSFC nodes, in
  both DCs, must join the **same AD domain**.
- **A writable domain controller + DNS server reachable from the DR site.** The §6 DR runbook
  depends on it. Forced quorum, the SQL service accounts, and the listener's DNS re-registration
  (§4.5) all quietly assume AD/DNS survives the loss of the primary DC.

### 4.1 Replica modes & failover settings

| Replica | Site | Availability mode | Failover mode | Purpose |
|---|---|---|---|---|
| R1 | Primary DC | Synchronous commit | Automatic | Normal primary |
| R2 | Primary DC | Synchronous commit | Automatic | Local HA — automatic failover target |
| R3 | DR DC | **Asynchronous commit** | Manual (**forced only**) | Disaster recovery |

This is Microsoft's documented reference pattern. Synchronous commit with automatic failover works
best when message latency between local nodes is low. Asynchronous commit is the DR solution for
replicas "distributed over considerable distances," and keeping the DR site async avoids the
performance degradation of inter-site latency. Note the precision: an async secondary supports
**only forced failover** (with possible data loss). There is no "planned manual" failover to R3
without first flipping it synchronous and letting it catch up.

Pin the automatic-failover preconditions in the runbook. Both R1 and R2 must set
`SYNCHRONOUS_COMMIT` and `FAILOVER_MODE = AUTOMATIC`, the secondary must be in the `SYNCHRONIZED`
state, and WSFC quorum must be healthy. Default health detection is **instance-level**, so enable
database-level health detection (`DB_FAILOVER = ON`) as well, letting a damaged or offline database
trigger failover too. The default timeouts bound detection (`HEALTH_CHECK_TIMEOUT` 30 s, AG lease
20 s, session timeout 10 s). Total RTO = detection + redo-queue drain + overhead, which runs to
tens of seconds for a healthy synchronized secondary and is unbounded if the redo queue is deep. By
default WSFC allows at most n−1 AG failovers per 6-hour period before the resource stays failed;
raise "Maximum Failures in the Specified Period" (Azure guidance uses 6), or at least know the
limit exists.

This design has **no synchronous replica at the DR site, ever**. If anyone proposes one, apply the
sizing rule: every millisecond of DR-link RTT costs ~7 ms of latency per message on every ordered
lane (§3.1).

### 4.2 `REQUIRED_SYNCHRONIZED_SECONDARIES_TO_COMMIT`

Leave it at the default **0**:

```sql
ALTER AVAILABILITY GROUP [MEFOR_AG]
SET (REQUIRED_SYNCHRONIZED_SECONDARIES_TO_COMMIT = 0);
```

- **At 0:** if the sync secondary stops responding, the primary marks it `NOT SYNCHRONIZING`
  (replica `DISCONNECTED` / `NOT_HEALTHY`) after the session timeout (default 10 s) and **keeps
  committing**. The AG then "runs exposed" rather than halting: no automatic failover, and RPO
  temporarily > 0 locally.
- **At 1:** commits on the primary **fail** whenever the sync secondary is unavailable. For
  MessageFoundry that means intake stops ACKing entirely (the pre-ACK ingress commit fails) and
  every stage stalls; you have traded a redundancy gap for a full interface-engine outage. Senders
  queue and retry under MLLP, so the value 0 is the right posture for a message engine: degrade,
  alert, and restore redundancy.
- **A merely *slow* (still-connected) sync secondary does not trigger the degrade.** Every commit
  waits for its hardening ack (`HADR_SYNC_COMMIT` waits), so a sick-but-alive R2 silently slows
  *every* message by ~7× its added latency. Monitor `HADR_SYNC_COMMIT` (§8) and be ready to flip
  R2 to async while it is remediated.

### 4.3 Quorum & witness

- Prefer a **cloud witness** (Microsoft's recommendation, explicitly supported for stretched
  multi-site clusters and non-shared-storage SQL Always On). Otherwise use a **file share witness
  at a third site**, physically separate from both DCs. Always configure a witness, and let dynamic
  quorum manage the votes.
- Keep an **odd number of votes, minimum three, and give DR-site nodes zero votes**. A DR node
  must never be able to cost the primary site its quorum across a flaky WAN. Set the vote with
  `(Get-ClusterNode "<DR-node>").NodeWeight = 0`, and verify with
  `Get-ClusterNode | ft Name, NodeWeight, State`.
- **Total primary-site loss.** The surviving DR node cannot form quorum on its own. The documented
  sequence is to **force quorum** on the DR node first, then perform a **forced AG failover**; see
  the runbook in §6.

### 4.4 Database prerequisites (what the store needs from the DBA)

The engine bootstraps its **schema, never the database**. There is no `CREATE DATABASE` in the
store; the connection string pins `DATABASE=` and expects the database to exist already. Stand the
database up in this order:

1. **`CREATE DATABASE [mefor]` on R1** (the name must match `[store].database`; the engine will
   not create it).
2. **`SET RECOVERY FULL`**, then pre-enable **RCSI** and `ALLOW_SNAPSHOT_ISOLATION` before first
   engine start (detail in the checklist below).
3. **Take the initial full backup**; a database must have one before it can join an AG.
4. **Add the database to the AG** (automatic seeding or backup/restore) and confirm it reports
   `SYNCHRONIZED` on R2.
5. **First engine start.** The idempotent schema DDL runs on the primary and replicates to the
   secondaries through the AG.

The checklist behind those steps:

- [ ] **Greenfield database.** There is no in-place migration from SQLite; drain and cut over
      ([`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) "greenfield-only"). The schema is created on
      first `open()` as idempotent DDL, so either grant the engine login create rights for the
      first run or pre-create the schema. The exact bootstrap privileges are still a
      *filled-by-staging* item in that doc. Until it is filled in, use this known-good interim
      posture: grant the engine login **`db_owner` on the `mefor` database only** (no server-level
      roles) for the first run, then after schema creation you may reduce toward
      `db_datareader` + `db_datawriter` + `EXECUTE`, validated in staging. With RCSI and
      `ALLOW_SNAPSHOT_ISOLATION` pre-set per step 2 above, the engine login never needs
      `ALTER DATABASE` rights.
- [ ] **Pre-enable RCSI on the primary before first engine start:**
      `ALTER DATABASE [mefor] SET READ_COMMITTED_SNAPSHOT ON WITH ROLLBACK IMMEDIATE;`
      (the database name must match `[store].database`). The store auto-enables RCSI at open if the
      login can `ALTER DATABASE`, and **degrades to a warning** if it cannot, which leaves the
      claim/finalize paths more deadlock-prone under load. A typical low-privilege AG login cannot
      do this, and `WITH ROLLBACK IMMEDIATE` kicks other sessions, so run it once, deliberately, as
      a DBA. Do the same for `ALLOW_SNAPSHOT_ISOLATION ON` (an online change).
- [ ] **FULL recovery model.** This is an AG membership requirement; the store itself does not
      require it. At ~7 commits/message the log-generation rate is material, so size the
      **log-backup cadence** (which also controls log truncation) against measured message volume.
- [ ] **Expect `sp_getapplock` (APPLOCK) waits** under load. The per-message finalizer and
      schema-init serialize on transaction-scoped applocks by design. No extra grant is needed.
- [ ] **Provision the engine login on all three replicas.** Logins are instance-level and do
      **not** replicate with the AG. Decide which `[store].auth` mode the engine uses
      (`sql` / `integrated` / `entra`, per [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md)). For SQL
      auth, create the login on R2/R3 **with the same SID as on R1**
      (via `CREATE LOGIN ... WITH SID = ...`, or `sp_help_revlogin` / dbatools `Copy-DbaLogin`) so
      the `mefor` database user does not orphan on failover. For Windows/Entra auth, grant the
      account on every instance. **Verify by connecting to each replica directly with the engine's
      credentials**, and make that check part of the pre-go-live failover drill; if it is missed,
      the very first failover to R2 leaves the engine in a login-failed retry loop.
- [ ] **Login grants.** The store reads only `sys.databases` and `sys.database_files` for status
      display, so it has no `VIEW SERVER STATE` dependency of its own. Still, validate the real
      low-privilege login in staging: MessageFoundry's CI runs the SQL Server leg as `sa`, so a
      green build does not prove a locked-down production login works. Missing grants surface as
      errors 297/300 only in production.
- [ ] **ODBC Driver 18** must be installed on every engine host. The driver name is hardcoded in
      the store's connection string; there is no override.
- [ ] **Connection budget.** `[store].pool_size` defaults to **40 per engine** (the measured
      optimum; do not raise it, [ADR 0062](adr/0062-default-store-pool-size.md)), plus a
      ~20-connection warm burst on start or promotion. This topology has **three engines — two
      hospital + one DR** — so the naive reservation is `3 × 40 + warm`. But only **one engine leads
      at a time**, and the **DR engine runs cold** (§5.1, service stopped), so it draws **0 in steady
      state**. Size for the **promotion overlap** — a new leader pre-warming while the old leader's
      ~40 have not yet closed — which peaks near `2 × 40 + ~20 ≈ 100`, not `3 × 40 = 120`. Until the
      shared-claimer work lands, keep it to **no more than a few hundred configured connections per
      store** ([`SYSTEM-REQUIREMENTS.md`](SYSTEM-REQUIREMENTS.md)).
- [ ] **Commit-bound, high-interface engines.** `[store].fifo_claim_batch = 8` (range 8–16,
      [ADR 0058](adr/0058-batch-claim-fifo-prefix.md)) amortizes the claim commit on backlogged
      lanes. It is the relevant lever here precisely because the sync replica raises per-commit
      cost.
- [ ] **Encryption.** At-rest protection is application-level AES-GCM inside the store, so there is
      **no TDE requirement**. TDE and encrypted backups remain optional DBA-side additions.
- [ ] **Backups are yours.** The engine deliberately has no backup path on this backend;
      `BACKUP DATABASE` and AG-integrated backups are DBA-delegated, and the store raises if asked.

### 4.5 Listener configuration — and a current MessageFoundry limitation

Every engine points `[store].server` at the **AG listener DNS name** (port 1433; put a
non-default listener port in `[store].port`). One limitation matters to every DBA planning a
cross-subnet listener:

> **MessageFoundry cannot emit `MultiSubnetFailover=Yes` today.** The store's ODBC connection
> string is a fixed keyword list ([`../messagefoundry/store/sqlserver.py`](../messagefoundry/store/sqlserver.py)
> `connection_string()`), there is no passthrough for arbitrary ODBC keywords, and the settings
> layer rejects the characters you would need to smuggle one in. Without that keyword, a
> cross-subnet failover can leave the driver dialing the stale subnet's IP until the TCP/login
> timeout. `[store].connect_timeout` (default 15 s) bounds each attempt, and ODBC 18's default TNIR
> softens but does not eliminate the penalty. `ApplicationIntent=ReadOnly` exists only on the
> separate `db_lookup` connector ([`../messagefoundry/transports/database.py`](../messagefoundry/transports/database.py));
> the store connection has no AG-aware keywords at all. Adding an opt-in `MultiSubnetFailover`
> setting has been assessed as a small `[store]` plus `connection_string()` change, tracked as
> [backlog #100](BACKLOG.md#100-multisubnetfailoveryes-opt-in-for-the-sql-server-store-connection-p2).
> Until it ships, configure the listener DNS-side as below.

**The Microsoft-documented workaround for clients that can't set `MultiSubnetFailover`** makes the
listener register only the active subnet's IP, with a short DNS TTL:

```powershell
Get-ClusterResource "MEFOR_AG_listener" | Set-ClusterParameter RegisterAllProvidersIP 0
Get-ClusterResource "MEFOR_AG_listener" | Set-ClusterParameter HostRecordTTL 300
# Apply per Microsoft's listener-configuration doc. The AG resource depends on the
# listener, so stopping the listener takes the AG resource offline with it — a brief
# DB outage for the engine; schedule it like a §5.2 short planned DB blip.
Stop-ClusterResource "MEFOR_AG_listener"
Start-ClusterResource "MEFOR_AG_listener"
Start-ClusterGroup "MEFOR_AG"
```

`RegisterAllProvidersIP=0` publishes one A-record (the online IP) instead of every subnet's IP,
and `HostRecordTTL 300` cuts client DNS caching from the 1,200 s default to 5 minutes. The
trade-off is that cross-subnet failover client recovery then depends on DNS TTL expiry plus
cross-site DNS/AD replication. Plan and **drill** the cross-DC connect path (§5.4), and keep DNS
replication to the DR site fast.

### 4.6 Listener TLS certificate

The engine connects with `Encrypt=yes` and **verifies** the server certificate. Setting
`[store].trust_server_certificate = true` or `encrypt = false` is **refused at startup**, unless
the break-glass `MEFOR_ALLOW_INSECURE_TLS` is set (never in production, because of PHI). This has
three consequences for the AG:

- ODBC Driver 18 validates against the **Windows machine trust store** (`LocalMachine\Root`), and
  there is no CA-file keyword. Import the DB CA on **every engine VM in both DCs**
  ([`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §5, `scripts/service/import-db-ca.ps1`).
- The engine offers no hostname-override keyword, so the certificate presented after failover must
  be valid for **exactly the listener DNS name** in `[store].server`. Every replica that can host
  the primary, including the DR replica, **must carry the listener DNS name in its certificate
  SAN** and chain to the trusted CA. Verify this *before* the first failover drill, not during the
  disaster.
- CA rotation is make-before-break on every connecting host in both DCs
  ([`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) §5.3). Pin the CA, never the leaf.

---

## 5. Engine placement & how MessageFoundry clustering composes with the AG

### 5.1 Two engines, one listener

Run the engine as a Windows service (NSSM, [`SERVICE.md`](SERVICE.md)) on **each** engine VM — the
two hospital engines and the DR engine. Give each an **identical config dir** and set
`[cluster].enabled = true` ([`CLUSTERING.md`](CLUSTERING.md)):

- Every engine points `[store].server` at the **AG listener**. Leadership is a self-fencing lease row
  in the shared DB, renewed on the **DB server's clock**, so node clock skew does not affect
  leadership. Run NTP everywhere anyway, since the row-level machinery uses wall clocks.
- Only the **leader** binds listeners and runs workers. A non-leader **binds nothing**; its only
  traffic is a small DB heartbeat every `heartbeat_seconds` (membership update, lease MERGE, and
  config-version read). **That WAN blessing is about the heartbeat, not the message path.** The
  heartbeat is genuinely happy to run across the WAN from the DR DC and never touches messages — but
  the lease knows nothing about geography. If the DR-DC engine is *running* and it **wins the lease**
  (because both hospital engines were unreachable at renewal time), it becomes a **cross-WAN active
  engine**: every one of its ~7 commits/message now crosses the WAN to the AG primary (§3.3), and
  there is **no automatic fail-back** to the hospital once an engine there returns — leadership stays
  put until you deliberately move it (the §6 *Failback* runbook). Leader-site preference is **not yet
  built** ([backlog #101](BACKLOG.md#101-leader-site-preference), unbuilt today — exactly like the
  engine-managed VIP of [ADR 0056](adr/0056-engine-managed-vip-failover.md)). The standing guidance
  still applies to the heartbeat: *tune the lease timings to your network*.
- **Run the DR engine cold.** So the DR engine cannot silently win the lease during a transient
  hospital-side blip and drag every commit across the WAN, keep its **NSSM service stopped in steady
  state**. It is promoted **with the database** as a site unit — started only as a **gated step in
  the §6 full-site-loss runbook**, never on its own — and **before you start it, run the
  identical-config check** below (a divergent DR config dead-letters rows on promotion). This cold
  posture is the deliberate counterpart to the cross-WAN-leadership hazard above; the two hospital
  engines, both warm and active-eligible, are what actually cover in-hospital engine failover.
- Timing defaults (`[…]` = `[cluster]`, with the invariant `heartbeat < fence < ttl` enforced at
  config load): `heartbeat_seconds = 10`, `leader_fence_timeout_seconds = 20`,
  `leader_lease_ttl_seconds = 30`, `node_timeout_seconds = 30`. `[store].pool_size ≥ 2` is
  required (≥ 3 recommended; the default 40 stands).
- Config changes are **coordinated restarts, not rolling**, and in this topology that spans both
  DCs. A divergent DR-node config is not cosmetic. The promotion-time dead-letter sweep is keyed
  off the promoting node's registry, so a stale DR config could dead-letter rows for destinations
  it does not know.
- Per-VM one-offs: each engine VM needs its own DPAPI-protected store-key provisioning, because
  DPAPI is machine-bound and a copied key file is useless. The `MEFOR_STORE_ENCRYPTION_KEY` env
  route is the alternative ([`SERVICE.md`](SERVICE.md)).

Engine failover and AG failover are **separate axes**. Measured functional engine failover
(promotion plus the on-promotion `reset_stale_inflight`) is **~7 s on SQL Server**
([`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)); AG failover is the DB-tier
event the engine *rides through* (§5.3). One note for scope hygiene: an engine standby plus an
async AG replica in the DR DC is **tier-2 HA stretched across sites**, not the separate cold/warm
tier-3 DR standby of [ADR 0048](adr/0048-third-tier-disaster-recovery-standby.md). That ADR
nevertheless concedes that a warm Always On DR replica gives near-zero RPO where the estate
supports it, which is exactly this design.

### 5.2 What actually happens during a DB outage (10 s vs 60 s, defaults)

Start with the invariant that no timing setting changes: **the shared DB *is* the staged queue.**
A DB outage always pauses processing for at least its own duration, because ingress commits (and
therefore ACKs), claims, handoffs, and deliveries all fail and retry until the DB is back. The
lease timings only decide whether **leadership and the listeners additionally bounce**. Workers
never die on store errors; they log, back off ~1 s, and retry forever. A failed ingress commit
drops the MLLP client's connection with **no ACK**, so the sender keeps the message and nothing is
accepted-and-dropped.

**~10 s outage (a clean local AG failover), fast-failing connections.** At most one lease-renew
attempt fails, and the next succeeds within 20 s of the last good renew, so there is **no
self-fence, no leadership change, and the listeners stay bound**. Senders see ~10 s of dropped
connections and missing ACKs, then retransmit. Know the real margin, though. The fence fires when
`now − last_successful_renew > leader_fence_timeout_seconds` (20 s), and renews are only
*attempted* every `heartbeat_seconds` (10 s), so the **guaranteed** no-fence tolerance is only
`fence − heartbeat ≈ 10 s`; phase alignment stretches it to just under 20 s. A 15 s AG failover
**may or may not fence**, depending on phase. Connects that *hang* rather than fail instantly eat
the margin further, since each heartbeat step can block up to `[store].connect_timeout` (15 s).

**~60 s outage.** The leader **self-fences ~10–21 s in** (phase-dependent; logged as WARNING
`SELF-FENCED`). Within ≤ 1 s the graph supervisor unbinds **all listeners** and stops workers, so
the MLLP VIP has no healthy backend and senders get connection-refused and queue at their end. The
lease expires on the DB clock, but *nobody can acquire it while the DB is down*, so the cluster
sits leaderless. When the DB returns (~t = 60), the first lease MERGE wins within ≤ 1 heartbeat:
the fenced ex-leader may **re-acquire its own lease** (epoch unchanged), or a standby may acquire
the expired lease (epoch + 1). Because that is a race, a 60 s outage always causes a **fence and
listener bounce, but not necessarily a leadership change**. The winner then brings the graph up:
epoch push, on-promotion `reset_stale_inflight`, sweeps, pool pre-warm, and listener bind. Total
resume ≈ outage + up to ~11 s + bring-up. No data is lost either way, since at-least-once and
durable ingress-before-ACK both hold; downstream systems must tolerate re-delivery.

**Sizing rule (use this, not folklore).** Make `leader_fence_timeout_seconds − heartbeat_seconds`
comfortably exceed the **worst observed AG failover time** at your site. For example,
`heartbeat 10 / fence 30 / ttl 45` guarantees ≥ 20 s of DB-outage tolerance before a fence, at the
cost of a slower crash-failover of the engine itself. Keep the load-enforced
`heartbeat < fence < ttl` ordering.

### 5.3 After an AG failover — engine reconnection, honestly

- **The engine has no reconnect logic of its own.** Recovery of severed pooled connections is
  delegated to the aioodbc pool and ODBC Driver 18 defaults; the DSN sets no `ConnectRetryCount`
  or `ConnectRetryInterval`, and neither is configurable today. The workers' retry loops paper
  over this in practice, and a per-statement `command_timeout` (default 30 s) bounds any hung
  statement. Even so, treat automatic pool recovery as **driver-dependent behavior to drill**, not
  a documented guarantee.
- **Stranded in-flight rows.** A row claimed just before the outage whose follow-up commit failed
  stays `INFLIGHT` (up to ~one row per active lane × `fifo_claim_batch`). Lanes are *not* blocked,
  because claims skip that row, but the message waits out of FIFO position until the recovery path
  runs. On SQL Server, `reset_stale_inflight` runs at **engine start** (single-node) or on
  **leader promotion** (clustered); there is **no periodic in-process sweep**. The runbook
  consequence: after any AG failover, check for stuck in-flight messages (§8), and if any are
  present, **restart the active engine service**. The clean stop releases the lease immediately,
  the standby promotes in ≈ one heartbeat, and on-promotion recovery re-pends every stranded row.
- SQL Server clustering has **no per-row leases**; `[store].lease_ttl_seconds` (60 s) is a
  PostgreSQL mechanism and is ignored here. On this backend, failover recovery was never gated on
  that TTL. Promotion runs an immediate, unconditional `reset_stale_inflight`, which is safe
  because the prior leader fenced and its lease expired first.

### 5.4 Inbound MLLP VIP / LB

MessageFoundry **designs for, but does not ship,** the floating VIP / L4 load balancer
([`DEPLOYMENT.md`](DEPLOYMENT.md), [`CLUSTERING.md`](CLUSTERING.md)). An engine-managed VIP is
**proposed only, with no code** ([ADR 0056](adr/0056-engine-managed-vip-failover.md)), so never
design as if the engine moves an IP. Stand up keepalived, HAProxy, F5, or an NLB with:

- **One VIP per inbound MLLP port, with the health check a TCP connect to that port.** Only the
  leader binds it, so the check passes only on the active engine and the VIP follows engine
  failover passively, including a failover to the DR-DC standby.
- **L7 alternative.** Probe `GET /cluster/status` and require `role == "primary"`. This needs a
  least-privilege `monitoring:read` bearer token injected by the LB, because unauthenticated probes
  get 401/403 on *every* node and black-hole traffic. Mint one by creating a dedicated local
  service account with a `monitoring:read`-bearing role and using its bearer token
  ([`SECURITY.md`](SECURITY.md), "Roles & permissions" / "Sessions"). The tokenless `/health`
  returns 200 on every node and **cannot** select the primary; there is no tokenless primary-only
  endpoint.
- **Set the probe interval comfortably above the ~1 s graph-reconcile interval** (e.g. 10 s) so
  the VIP does not flap during a leadership transition.
- **Partners must reconnect on drop.** This is standard MLLP client behavior; make it a
  requirement.

**Decide at design time where the VIP itself lives**, because it determines what §6's DR step
means. Three patterns are viable:

- **Global LB / GSLB spanning both DCs** (GSLB, DNS-based failover, or a stretched LB tier) runs
  the TCP health check against the engines in both sites. In principle a failover to the DR-DC
  engine is then followed automatically: the DR engine binds and its check goes green. **With the
  cold-DR posture (§5.1) that "automatic" follow still is not hands-off** — the DR engine's service
  is stopped in steady state, so nothing goes green until the §6 runbook *starts* it; the GSLB then
  follows. It also requires an LB tier that itself survives the primary DC. Do not treat DR follow
  as unconditionally desirable: a warm DR engine that the health check follows on a *transient*
  hospital blip is a cross-WAN active engine (§5.1/§3.3), which is why the DR engine is kept cold.
- **Route Health Injection (RHI) — a routed variant of the external VIP, for the cross-site case.**
  Instead of a stretched LB appliance, advertise the MLLP VIP as a **/32 host route** into the
  network from whichever site is active, gated by the **same leader-only TCP health check**: the
  hospital site injects the /32 only while a hospital engine holds leadership and **withdraws the
  hospital /32 on failover**; the DR site advertises the same /32 **only on deliberate DR
  activation**, never automatically. This gives VIP mobility across DCs without a shared appliance,
  but it inherits the §5.1 hazard — an *automatic* follow-to-DR is **not unconditionally
  desirable**, because a DR engine that wins the lease over a transient blip becomes a cross-WAN
  active engine (§3.3). Treat DR /32 advertisement as a runbook action paired with the §6 *Failback*
  step that withdraws it again, not a hands-off failover. Drive it from the same leader-only TCP
  connect (or the `monitoring:read`-gated `/cluster/status` probe) as the VIP health check.
- **Per-DC VIPs plus a pre-agreed sender cutover.** A conventional F5/HAProxy pair living in the
  primary DC **dies with the site**, so "repoint senders" then means changing every sending
  system's MLLP destination to the DR VIP. Maintain a **sender cutover list with owners and
  contacts** as a DR prerequisite, and drill it.

Document which pattern you chose; the §6 runbook's sender-repoint step executes it.

---

## 6. Failure modes & runbook

| Failure | Automatic behavior | Operator action |
|---|---|---|
| **Hypervisor host holding the SQL primary dies** | AG fails over automatically to the local sync secondary. Detection is bounded by the 20–30 s default timeouts plus redo drain, and runs longer if you raised the WSFC thresholds (§7.3), so substitute your own numbers. The engine rides the outage per §5.2, likely a self-fence and listener bounce that self-heals. Anti-affinity guarantees the engine and the other replica were elsewhere. | Verify `/cluster/nodes` and AG dashboard; check for stuck in-flight (§5.3) and restart the active engine service if any; restore host → replica rejoins and catches up. |
| **Hypervisor host holding the active engine dies** | A non-leader acquires the lease after ≤ `leader_lease_ttl_seconds` (30 s) — the **surviving hospital engine or the DR engine, whichever renews first**, since leader-site preference is unbuilt (§5.1); on-promotion recovery re-pends the dead node's in-flight rows (~7 s measured functional failover). VIP/route follows via the TCP health check. Hypervisor HA also restarts the dead VM (minutes, crash-consistent) — it comes back as a non-leader. DB untouched. | **Verify which engine won** (`/cluster/nodes`). With a second hospital engine present, promotion should stay in-hospital — confirm it did. **If the DR engine took the lease while the AG primary is still hospital-local, you now have a cross-WAN active engine** (§5.1/§3.3): execute **engine failback** — clean-restart the DR engine service so a hospital engine re-acquires (§6 *Failback*), then stop the DR engine cold again (§5.1). Confirm the VIP/route followed and dispositions are flowing. |
| **Planned local AG failover (patching)** | Planned manual failover between R1↔R2, no data loss. Engine sees a short DB outage — §5.2's 10 s case if quick. | Schedule in a quiet window; afterwards check stuck in-flight; drill this quarterly (it doubles as the §5.3 reconnect drill). |
| **Local sync secondary lost** (host/storage) | After the ~10 s session timeout the primary marks it `NOT SYNCHRONIZING` and keeps committing (`REQUIRED_SYNCHRONIZED_SECONDARIES_TO_COMMIT = 0`). **Running exposed:** no local automatic failover until it's back and resynchronized. | Alert + restore redundancy promptly. If it's *slow* rather than dead, commits are waiting on it (`HADR_SYNC_COMMIT`) — consider flipping it async while remediating. |
| **Both local DB replicas lost, engines alive** (partial site loss — storage/rack; R1 *and* R2 gone, the hospital engines still up) | No automatic failover: with both sync replicas gone the AG has no synchronized local target, and R3 is async (no auto-failover). Ingress commits fail, so the engines stop ACKing and run their store-error retry loops (§5.2); nothing is accepted-and-dropped. | Do **not** let the engines thrash a half-dead AG. In order: **(1) stop the engine services** (both hospital engines) to quiesce commit retries; **(2) force the AG** to R3 (`FORCE_FAILOVER_ALLOW_DATA_LOSS`, forcing quorum first per §4.3/§6 if quorum was lost); **(3) verify via `/cluster/nodes`** that exactly one engine holds the lease, then start it against the now-DR primary — accepting this is cross-WAN operation (§9). RPO per the §6 forced-failover loss statement. |
| **WAN / DR link down** | No commit impact (async). The primary's log **send queue grows** = your RPO growing; log can't truncate past what R3 needs indefinitely — watch log space. | Alert on `log_send_queue_size`; fix the link; the async replica catches up on its own. |
| **Full primary-site loss** | Nothing automatic — by design (DR node has zero quorum votes). | The runbook below. |

### Full-site-loss runbook (DR activation)

> **Prerequisite (verify in the quarterly drill, not at 3am).** You need a **writable domain
> controller + DNS server at the DR site** (§4 prerequisites). Forced quorum (step 1), the SQL
> service accounts (step 2), and the listener's DNS re-registration (step 4) all assume AD/DNS
> survived the primary DC.

1. **Force quorum** on the DR WSFC node, following Microsoft's forced-quorum procedure. Run
   `Stop-ClusterNode -Name "<DR-node>"`, then `Start-ClusterNode -Name "<DR-node>" -FixQuorum`
   (alternative: `net.exe start clussvc /forcequorum`), then restore its vote with
   `(Get-ClusterNode "<DR-node>").NodeWeight = 1`. Bring any other surviving nodes up one at a
   time, heed the split-brain warnings, and reassess votes.
2. **Forced AG failover** on R3: `ALTER AVAILABILITY GROUP [MEFOR_AG] FORCE_FAILOVER_ALLOW_DATA_LOSS;`.
   Forced failover requires quorum, which is why step 1 comes first.
3. **Resume** the replica databases. After a forced failover, every remaining secondary database
   is `SUSPENDED` and must be manually resumed, including the old primary when it returns. Log
   truncation is delayed while any secondary is suspended, which risks disk growth.
4. **Verify the listener before touching the engine.** Confirm the listener resource is online on
   R3's node, then **from the DR engine VM** run `Resolve-DnsName <listener>` and confirm it
   returns the **DR subnet's IP**. If it is stale, check the cluster name object's DNS registration
   against the DR-site DNS server, then run `ipconfig /flushdns` on the engine VM. §4.5's
   `RegisterAllProvidersIP=0` workaround makes client recovery depend entirely on this
   re-registration; until it happens, the DR engine silently keeps dialing the dead primary
   subnet's IP. Include this resolution check in the §4.5 cross-DC connect drill.
5. **Start the DR engine service.** In steady state the DR engine runs **cold** (§5.1), so it is
   *not* already competing for the lease — **start its NSSM service now**, after (a) confirming the
   listener resolves to the DR subnet (step 4) and (b) running the **identical-config check** (§5.1)
   so promotion does not dead-letter rows. On start it acquires the lease within ≈ one heartbeat and
   on-promotion `reset_stale_inflight` re-pends in-flight rows. Repoint senders per the §5.4 pattern:
   a global LB / GSLB follows automatically via the health check *once the service is up*; per-DC
   VIPs execute the sender cutover list; with RHI, **advertise the DR /32** now.
6. **Verify the hospital-side /32 was withdrawn.** If the hospital site advertised the MLLP VIP as a
   /32 (the §5.4 RHI variant) or answered on a per-DC VIP, confirm that route/VIP is **gone** now
   that the site is down — a lingering hospital /32 (e.g. still injected by a surviving edge device
   whose leader health check can no longer be satisfied) would black-hole or split senders across a
   dead site and the live DR one. With RHI the withdrawal is automatic on health-check failure;
   **verify it**, and only then rely on the DR /32. The §6 *Failback* runbook reverses this —
   withdraw the DR /32 and restore the hospital advertisement.
7. **Notify sending systems** to drain their retry queues, and expect at-least-once re-delivery
   downstream.

### Failback (after a DR activation or a 90-day DR test)

**Routine case first — an engine-only failover, DB still hospital-local.** The most common failback
is *not* a DR event at all: an engine-host blip or a transient store hiccup let a **misplaced
engine** (the #2 hospital engine, or worse the DR engine) win the lease while the AG primary never
left the hospital. Nothing on the SQL side moved, so there is nothing to resync — **just move
leadership back**: confirm the configs are identical (§5.1), then **cleanly restart the misplaced
engine service**. Its clean stop releases the lease immediately and the intended engine promotes in
≈ one heartbeat (§5.3). If the misplaced engine was the **DR** engine, **stop it cold again**
afterward (§5.1). Use this whenever §6's active-engine-death row flags a cross-WAN leader; the full
SQL + engine sequence below applies only after an actual DR *database* activation.

**SQL side.** Microsoft's forced-failover doc covers the sequence. In outline: rejoin and resume
the old primary-DC replicas, let R1/R2 catch up, flip R1 synchronous and wait for `SYNCHRONIZED`,
perform a planned failover back to R1, then restore the §4.1 mode table (R3 back to async) and the
§4.3 vote assignment and witness (undoing the forced-quorum `NodeWeight` changes). **But do not
treat the RESUME as free.** Resuming a suspended database **discards whatever the old primary held
that R3 never received** — and while the forced failover *accepted* that loss in principle, on a
**misdiagnosed partition** (the hospital DB was healthy; the WAN merely blinked) the discarded
lineage can contain **ACKed clinical messages the senders will never resend** (§6's RPO statement).
So **before you RESUME** the old primary:

- **Quantify the divergence** while the old primary is still readable: compare its last-committed
  LSN / `last_commit_time` against R3's, and check the ingress/audit tables for rows R3 never saw.
- **If that gap is non-trivial, snapshot first.** Take a **database snapshot** (or a full backup /
  file copy) of the old primary *before* rejoining it, so the divergent lineage stays recoverable
  for manual reconciliation into the new primary. Only then rejoin and resume.
- Treat a **large or unexpected** gap as a signal you may have failed over on a false alarm —
  reconcile before you discard; do not rubber-stamp the loss.

**Engine side.** Leadership does **not** auto-fail-back to the primary DC, so walk it back:

1. Confirm the two engine configs are **identical** before promoting (§5.1; a divergent config can
   dead-letter rows on promotion).
2. **Cleanly restart the DR engine service.** The clean stop releases the lease immediately, and
   the primary-DC standby promotes in ≈ one heartbeat. This is §5.3's recovery mechanism, used
   deliberately as the failback lever.
3. Verify the primary-DC node reports `role == "primary"` on `/cluster/nodes`, and that the
   listener DNS has flipped back to the primary subnet (the step-4 `Resolve-DnsName` check, run
   from the primary-DC engine VM).
4. Check for stuck `INFLIGHT` rows (§5.3) and confirm dispositions are flowing.
5. Repoint senders back (reverse of the §5.4 cutover, if per-DC VIPs).

### The RPO statement — be honest about it

MessageFoundry ACKs a message **only after it is durably committed to the ingress stage**
(ACK-on-receipt, per [`ARCHITECTURE.md`](ARCHITECTURE.md) and the count-and-log invariant).
"Durably committed" means committed **on the AG primary**. A forced failover to the async DR
replica discards *all* committed-but-unreplicated state: fresh ingress rows, in-pipeline
routed/outbound rows, delivered-markers, and audit rows. The at-least-once machinery repairs most
of that on re-run. The one loss it **cannot** repair is this: **a message ACKed at ingress but not
yet shipped to R3 is gone, and the sender, having been told AA, will never resend it.** That is the
deliberate, industry-standard tradeoff of async DR. The alternative, synchronous commit to the DR
site, puts the WAN's RTT into all ~7 commits of *every* message, all day, every day (§3.3). Accept
a small, *measured* RPO at DR instead:

- **Your RPO gauge is the send queue.** Read `log_send_queue_size` in
  `sys.dm_hadr_database_replica_states` (queried **on the primary**), or the AG dashboard's
  "Estimated Data Loss." Microsoft's simpler check compares `last_commit_time` between primary and
  secondary in the same DMV.
- **Monitor it continuously, *before* the disaster.** During quorum loss or after forced quorum,
  those columns report NULL, so potential loss cannot be assessed at disaster time. Microsoft's
  example alert is a job that runs every minute and compares the `last_commit_time` gap against
  your RPO target (e.g. 5 minutes).

---

## 7. VM & host configuration checklist

### 7.1 VMware (vSphere)

Sources: VMware's *Architecting Microsoft SQL Server on VMware vSphere* (the guide Microsoft's own
SQL virtualization support policy points to), plus Broadcom's WSFC-on-vSphere guidelines (KB 313230
for vSphere 7.x, KB 313472 for 8.x, KB 404711 for 9.x; use your release's article).

- [ ] **100% memory reservation** on the SQL VMs. This eliminates ballooning and swap, and note
      that it also constrains vMotion admission and drops the VM swap file. Allow no host memory
      overcommit for this cluster.
- [ ] **Lock Pages in Memory** for the SQL service account on tier-1 SQL VMs, paired with the full
      reservation and `max server memory`. Never do this on overcommitted hosts.
- [ ] **PVSCSI (or vNVMe on all-flash) controllers**, with multiple adapters. Put OS, data, and
      transaction log on **separate controllers/VMDKs**, and place the log VMDK on the
      lowest-latency tier (§7.4).
- [ ] **VMXNET3** vNIC, with RSS enabled in the guest (`netsh int tcp set global rss=enabled` plus
      the adapter driver property).
- [ ] **DRS VM-VM anti-affinity** per §2. It is mandatory for the AG replica pair (the
      WSFC-on-vSphere KBs above never allow two WSFC nodes on one host, and require N+1 hosts), and
      recommended as mutual anti-affinity across the engine and both replicas. **vSphere HA honors
      VM-VM anti-affinity during failover restarts only if the HA advanced option
      `das.respectVmVmAntiAffinityRules` is set, so set it.** HA will then refuse a restart that
      would violate the rule, reporting insufficient resources. Without it, an HA restart can land
      both AG replicas on one host, and DRS corrects placement only afterwards.
- [ ] **Snapshots.** Avoid them on SQL/AG VMs, and never use the "snapshot memory" option. If a
      backup product must use them, keep them quiesced and off-peak only, because the create/remove
      stun windows under heavy I/O are real.
- [ ] **vMotion of AG/WSFC nodes is supported.** It requires a 10GbE+ vMotion network; pair it with
      the WSFC heartbeat relaxation in §7.3.

### 7.2 Hyper-V

- [ ] **Static memory** for SQL VMs. Dynamic Memory is *supported*, but it silently disables
      virtual NUMA (a VM with Dynamic Memory has one vNUMA node), which cripples large SQL VMs.
      vSphere has the same trap: CPU Hot-Add disables vNUMA.
- [ ] **Anti-affinity.** Set `AntiAffinityClassNames` on the VM cluster groups (or use an SCVMM
      availability set). It is **soft by default**, so set `ClusterEnforcedAntiAffinity = 1` for
      hard enforcement. Caveat: in a 2-node cluster with one node down, the second VM will not
      start.
- [ ] **Checkpoints.** Set `CheckpointType = ProductionOnly`, because standard/memory-state
      checkpoints are inconsistent with SQL support. Avoid routine checkpointing of SQL/AG VMs
      entirely, and **never apply (revert) a checkpoint on an AG replica or WSFC node**; reverting a
      replica in time breaks the AG.
- [ ] **VMQ / vRSS** on 10GbE+ NICs. VMQ only engages at ≥ 10 Gb, and the "disable VMQ" folklore
      stems from buggy 1 GbE drivers.
- [ ] **Hyper-V Replica is NOT supported for VMs running Availability Groups.** It is forbidden as
      a DR shortcut here; AG replication to R3 *is* the DR mechanism for the SQL tier.

### 7.3 WSFC heartbeat relaxation (live migration + cross-site)

Live-migrating a WSFC/AG node stuns it briefly. Current Microsoft guidance is to keep the 1 s
heartbeat *delay* and raise the *thresholds*:

```powershell
(Get-Cluster).SameSubnetDelay      = 1000   # ms (default)
(Get-Cluster).SameSubnetThreshold  = 40     # WS2019/2022 default 20
(Get-Cluster).CrossSubnetDelay     = 1000
(Get-Cluster).CrossSubnetThreshold = 40
(Get-Cluster).RouteHistoryLength   = 80     # 2 x the threshold
```

Keep the AG lease consistent with the cluster tuning: **AG lease timeout <
2 × SameSubnetThreshold × SameSubnetDelay**. Start at 40 s and do not exceed 80 s with the 40/1 s
values above. For I/O-intensive windows, including VM-snapshot backups, Microsoft's relaxed AG
monitoring set is `HEALTH_CHECK_TIMEOUT 60000`, `FAILURE_CONDITION_LEVEL 2`, session timeout 20 s,
and max failures in period 6.

**These thresholds trade detection speed for stability, so re-derive the engine's timings to
match.** Raising `SameSubnetThreshold` to 40 lengthens WSFC node-death detection to
~`SameSubnetThreshold × SameSubnetDelay` (~40 s with the values above), which lengthens every
automatic AG failover. Re-derive the §5.2 sizing rule afterwards, keeping `fence − heartbeat`
comfortably above the new worst-case failover (e.g. `heartbeat 10 / fence 60 / ttl 90`), and
substitute your chosen thresholds into §6's expected-detection numbers. Otherwise every SQL-host
death self-fences the engine and bounces the listeners.

### 7.4 Storage, power, network

- [ ] **Put transaction log volumes on the lowest-latency durable tier you have.** Enterprise
      power-loss-protected NVMe class (~30–100 µs flush) beats mid-tier SAN (~300–1,000+ µs) by up
      to an order of magnitude, and MessageFoundry pays that difference ~7× per message. Both sync
      replicas need it, because the *secondary's* log flush is in every commit's path (§4.1).
- [ ] **Power.** Set BIOS to "OS Control" (or static high performance), the hypervisor power policy
      to High Performance, and the Windows High Performance plan on hosts *and* guests. Disable deep
      C-states (C6/C1E) on latency-critical hosts: a C6 wake is ~100–170 µs, a 1–3× multiplier on
      the commit path's fast segments. Note that *idle* systems are where C-state jitter is worst,
      so a quiet-hours latency spot-check does not flatter the config.
- [ ] **Jumbo frames.** They are worthwhile on the vMotion, iSCSI, backup, and AG-replication (WAN
      log-send) networks, but marginal for the engine↔SQL TDS path, and a mismatched MTU anywhere
      in the path is worse than not enabling them. Do not enable them on the client path just for
      MessageFoundry.
- [ ] **Right-size vCPU within a pNUMA node.** Crossing NUMA unnecessarily costs measurable
      performance on both stacks.
- [ ] Engine VMs: Windows Server 2022/2025, NSSM service per [`SERVICE.md`](SERVICE.md), AV
      exclusions per [`ANTIVIRUS-FIREWALL.md`](ANTIVIRUS-FIREWALL.md), NTP everywhere.

---

## 8. Monitoring

| Layer | What | Alert on |
|---|---|---|
| AG — RPO | `log_send_queue_size` (per secondary DB, `sys.dm_hadr_database_replica_states`, query on the primary); dashboard "Estimated Data Loss"; `last_commit_time` gap primary↔R3 | Gap > your RPO target (e.g. 5 min), checked every minute — continuously, not just in drills (§6: NULL during quorum loss) |
| AG — RTO | `redo_queue_size` / redo rate on R2 (drives failover duration) | Redo queue growing under steady load |
| AG — commit health | `HADR_SYNC_COMMIT` wait average; `synchronization_health` | Sustained multi-ms `HADR_SYNC_COMMIT` (a slow-but-alive R2 taxes every message ~7×, §4.2); any replica not `HEALTHY` |
| WSFC — quorum & witness | Cluster node state; quorum/witness resource online state (`Get-ClusterQuorum`; cluster events 1069, 1177, 1573); witness reachability | Witness offline (a silently dead witness converts the next node loss into quorum loss — exactly what §4.3 designs against); any node down > threshold. Cloud-witness storage keys rotate — track them as an expiring credential |
| Engine — cluster | `GET /cluster/status` per node (role; per-node authoritative), `GET /cluster/nodes` (lease owner/expiry — the source of truth; a one-tick `leader_node_id: null` during failover is normal fold-in lag). Both need `monitoring:read`. | No node reporting `primary` beyond ~`leader_lease_ttl_seconds`; a leadership change whose **new leader is not the engine co-located with the AG primary** (the compound cross-site condition — see the next row) |
| Engine ↔ AG — site correlation | Map the `/cluster/nodes` lease-owner host → its DC, and the AG **primary** replica's host → its DC (`sys.dm_hadr_availability_replica_states` joined to `sys.availability_replicas`); alert when the two sites differ | **Leader site ≠ AG-primary site, sustained beyond ~1 `leader_lease_ttl_seconds`** — this is the cross-WAN active-engine condition (§5.1/§3.3): a hospital-local AG primary with a DR-DC engine leader (or the reverse) means every ~7 commits/message are crossing the WAN. Execute engine failback (§6). A one-tick mismatch during a failover is normal — alert only when it *persists* past the TTL |
| Engine — logs | The `SELF-FENCED` WARNING; store-error retry logs | Any self-fence outside a known DB event |
| Engine — pipeline | `/stats` `in_pipeline`; message dispositions + AlertSink ([`ARCHITECTURE.md`](ARCHITECTURE.md)) | `in_pipeline` not draining after a DB event; messages stuck `INFLIGHT` post-failover (§5.3 — trigger the engine-restart recovery); `ERROR`/dead-letter spikes |
| VIP / LB | Backend health (TCP probe per §5.4) | Zero healthy backends > probe interval × 2 |

---

## 9. Sizing reality check

A ~445-bed hospital generates on the order of **1.1–1.4 M messages/day**, or **13–16 msg/s on
average** — an illustrative estimate from profiled production ADT feeds, not a published repo
figure. At the documented 2.7× busiest-hour burst factor ([`THROUGHPUT.md`](THROUGHPUT.md)), that
peaks at roughly **35–44 msg/s**. Compare that against the repo's measured figures
([`THROUGHPUT.md`](THROUGHPUT.md) §8, [`SYSTEM-REQUIREMENTS.md`](SYSTEM-REQUIREMENTS.md),
[`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md)):

- **One strictly-ordered MLLP interface** measures ~50–60 msg/s end-to-end against a LAN-attached
  server DB with a fast-ACKing partner. A *single lane* covers this hospital's peak hour, and real
  deployments split feeds across several interfaces anyway.
- **One engine's intake** (ACK-on-receipt) measures ~450 msg/s. The whole load sits in the
  *lowest* documented sizing tier ("Pilot/light: up to ~50 msg/s / ~1–4 M/day").

So a single active engine is comfortable at hospital scale, with three caveats that can eat the
margin:

1. **Partner ACK latency dominates a lane.** A partner that takes 50 ms to ACK caps one ordered
   lane at ~15 msg/s regardless of your hardware, so split feeds.
2. **Commit-path latency multiplies ~7×** (§3), and **these single-lane numbers assume the engine
   leader is co-located with the AG primary.** An under-provisioned or cross-DC DB (a documented
   ~30 deliveries/s single-stream remote-SQL-Server case) can drag a lane below the hospital peak.
   A **cross-WAN active engine** (§5.1) — a DR engine that won the lease while the AG primary is
   still hospital-local — **invalidates every figure above**, because each of the ~7 commits then
   crosses the WAN; the numbers hold only while leader and AG primary share a site. Keep the sync
   replica local, the log tier fast, and leadership co-located with the primary.
3. **Configured-connection count**, not message volume, is the current per-store scaling bound.
   Keep it to a few hundred connections per store for now
   ([`SYSTEM-REQUIREMENTS.md`](SYSTEM-REQUIREMENTS.md)).

---

## 10. Licensing note

Start with the edition itself. This three-replica topology **requires Enterprise Edition** (see the
§4 prerequisites: Standard's Basic AGs cap at two replicas and one database per AG). What follows is
about the *core licenses* on that edition.

With Software Assurance or subscription licenses, SQL Server permits **free passive failover
replicas**: one for HA (the licensing guide's HA replica is the synchronous one), one for DR (the
asynchronous one), plus one DR replica in Azure. So the §2 topology — a licensed primary, a passive
local sync secondary, and a passive DR async secondary — needs **only the primary's core
licenses**. "Passive" permits DBCC checks, log and full **backups**, and resource monitoring. A
secondary that is *readable* (read-intent routing, reporting) forfeits the benefit and must be
licensed, which is also why this guide never routes reads at the secondaries. Brief DR tests every
90 days are allowed. These terms quote the SQL Server 2022 Licensing Guide, pp. 25–26, so
**confirm with your licensing rep**, and re-check the SQL Server 2025 guide if deploying 2025.

---

## 11. References

**Repo:** [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) · [`CLUSTERING.md`](CLUSTERING.md) ·
[`DEPLOYMENT.md`](DEPLOYMENT.md) · [`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md) §2.3 ·
[`CONFIGURATION.md`](CONFIGURATION.md) · [`SERVICE.md`](SERVICE.md) ·
[`SYSTEM-REQUIREMENTS.md`](SYSTEM-REQUIREMENTS.md) · [`THROUGHPUT.md`](THROUGHPUT.md) ·
[`throughput-roadmap.md`](throughput-roadmap.md) ·
[`benchmarks/step-b-write-amplification.md`](benchmarks/step-b-write-amplification.md) ·
[`benchmarks/TUNING-BASELINE.md`](benchmarks/TUNING-BASELINE.md) ·
[`EARLY-ADOPTER-GUIDE.md`](EARLY-ADOPTER-GUIDE.md) §14 · ADRs
[0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md),
[0048](adr/0048-third-tier-disaster-recovery-standby.md),
[0051](adr/0051-corepoint-throughput-parity-strategy.md),
[0055](adr/0055-group-commit-durable-write.md),
[0056](adr/0056-engine-managed-vip-failover.md),
[0057](adr/0057-inline-step-a-fast-path.md),
[0058](adr/0058-batch-claim-fifo-prefix.md),
[0062](adr/0062-default-store-pool-size.md),
[0063](adr/0063-no-split-store-unified-store-for-sharding.md) · code:
[`../messagefoundry/store/sqlserver.py`](../messagefoundry/store/sqlserver.py),
[`../messagefoundry/config/settings.py`](../messagefoundry/config/settings.py).

**Microsoft Learn:**
[Availability modes](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/availability-modes-always-on-availability-groups)
(the local-sync / remote-async reference topology + the "distributed over considerable distances"
DR statement) ·
[HA/DR for SQL Server on Azure VMs](https://learn.microsoft.com/en-us/azure/azure-sql/virtual-machines/windows/business-continuity-high-availability-disaster-recovery-hadr-overview)
("use asynchronous commit instead of synchronous commit" for remote replicas) ·
[Failover and failover modes](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/failover-and-failover-modes-always-on-availability-groups) ·
[Forced manual failover](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/perform-a-forced-manual-failover-of-an-availability-group-sql-server) ·
[Monitor performance for AGs (RPO/RTO math)](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/monitor-performance-for-always-on-availability-groups) ·
[Lease / health-check timeouts](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/availability-group-lease-healthcheck-timeout) ·
[Listener configuration (RegisterAllProvidersIP / HostRecordTTL)](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/create-or-configure-an-availability-group-listener-sql-server) ·
[Listeners & client connectivity](https://learn.microsoft.com/en-us/sql/database-engine/availability-groups/windows/listeners-client-connectivity-application-failover) ·
[ODBC DSN / connection-string keywords](https://learn.microsoft.com/en-us/sql/connect/odbc/dsn-connection-string-attribute) ·
[WSFC disaster recovery through forced quorum](https://learn.microsoft.com/en-us/sql/sql-server/failover-clusters/windows/wsfc-disaster-recovery-through-forced-quorum-sql-server) ·
[Deploy a cloud witness](https://learn.microsoft.com/en-us/windows-server/failover-clustering/deploy-cloud-witness) ·
[HADR cluster best practices (heartbeats, quorum votes)](https://learn.microsoft.com/en-us/azure/azure-sql/virtual-machines/windows/hadr-cluster-best-practices) ·
[SQL Server virtualization support policy](https://learn.microsoft.com/en-us/troubleshoot/sql/database-engine/install/windows/support-policy-hardware-virtualization-product) ·
[SQL Server 2022 Licensing Guide (PDF)](https://download.microsoft.com/download/9/3/d/93d32de6-f268-45ed-ba25-2f9a6756b6af/SQL_Server_2022_Licensing_guide.pdf) ·
VMware, *Architecting Microsoft SQL Server on VMware vSphere* ·
Broadcom WSFC-on-vSphere guideline KBs: 313230 (vSphere 7.x) / 313472 (8.x) / 404711 (9.x).

---

*Companion: [`DEPLOY-SERVER-DB.md`](DEPLOY-SERVER-DB.md) (store settings + TLS trust),
[`CLUSTERING.md`](CLUSTERING.md) (engine HA), [`DEPLOYMENT.md`](DEPLOYMENT.md) (network/TLS
posture), [`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md) §2.3 (the ratified AOAG variant this doc
realizes).*
