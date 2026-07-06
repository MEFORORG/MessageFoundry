# ADR 0047 — Cloud / Kubernetes HA deployment packaging (the container fast-follow follow-ons)

- **Status:** Accepted (2026-06-28 — ratified; open items resolved in 'Ratification decisions' below)  <!-- Proposed (no code yet) → Accepted (build may start) → Superseded by NNNN / Rejected -->
- **Date:** 2026-06-28
- **ADR-index note:** the number `0047` is the project owner's assignment for this work (it is the slot
  [ADR 0048](0048-third-tier-disaster-recovery-standby.md) §1 calls *"reserved elsewhere — engine-managed
  VIP failover"*). This ADR claims it for **deployment packaging**, and draws the boundary explicitly: it
  packages an **operator-assembled** L4 load balancer whose VIP *follows* failover via a primary-only
  health check — it does **not** build an engine that *manipulates* a VIP. Any future engine-managed VIP
  is a distinct, deferred item (see *Out of scope* and *To resolve on acceptance*).
- **Related:** [BACKLOG #41](../BACKLOG.md) (this) · the ratifying research
  [`research/cloud-deployment-research-2026-06.md`](../research/cloud-deployment-research-2026-06.md) ·
  [ADR 0017](0017-consumer-deployment-model.md) (consumer deployment model, container fast-follow, PR #480) ·
  [ADR 0037](0037-multi-process-sharding-l3.md) (L3 process sharding — the CPU-scaling lever, **not** an HA
  lever) · [ADR 0039](0039-database-tier-sharding-l5.md) (L5 DB-tier sharding — the DB-write lever) ·
  [ADR 0048](0048-third-tier-disaster-recovery-standby.md) (DR standby — the loss-of-site lever) ·
  [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §0 (exposed-gate / TLS-required bind) ·
  shipped active-passive HA — the **graph supervisor** that binds listeners on the leader only
  ([`pipeline/engine.py`](../../messagefoundry/pipeline/engine.py) `_start_graph`/`_stop_graph`/
  `_graph_supervisor_loop`), the coordinator (`pipeline/cluster.py`, `pipeline/cluster_sqlserver.py`),
  `/cluster/*`, and [`docs/CLUSTERING.md`](../CLUSTERING.md) (the authoritative shipped-HA reference) ·
  [`docs/CONTAINER-EXPOSURE-EVALUATION.md`](../CONTAINER-EXPOSURE-EVALUATION.md) (Topology A vs B) ·
  [CLAUDE.md](../../CLAUDE.md) §1–§2 (the invariants quoted below)

---

## Context

The engine container shipped in PR #480 (ADR 0017 fast-follow): a non-root, OCI-compliant Linux image
(slim + `-sqlserver`), a Topology-A `compose.yaml`, and a **single-node** k8s `StatefulSet`. The
cloud-readiness research ([`research/cloud-deployment-research-2026-06.md`](../research/cloud-deployment-research-2026-06.md))
graded three tiers: **(a)** run-on-any-platform (ECS/Fargate/AKS/GKE) and **(b)** single-node-with-PVC
are **done and shipped**; **(c)** multi-node HA is *"code-complete, no assembly kit."* The active-passive
HA mechanism is fully built in the engine — externalized Postgres/SQL Server stores, a self-fencing
leader lease (`DbCoordinator`/`SqlServerCoordinator`), the engine-level graph supervisor that runs the
wired graph (listeners + workers) **only on the leader**, `/cluster/status` + `/cluster/nodes` — but
**nothing to copy**: both shipped manifests are hard `replicas: 1`, there is no multi-replica manifest,
no Postgres service in compose, no load-balancer wiring, and no cloud PHI doc. The gap is **packaging,
not capability**.

The forcing problem this ADR records: **turn the single-node container into a real cloud / Kubernetes HA
deployment target** — a copyable HA reference, cloud docs that lead with the right backend, MLLP load
balancing that actually follows failover, the realistic on-prem-adopter hybrid topology, and a cloud PHI
posture — **without** redesigning the engine and **without** violating the standing invariants
([CLAUDE.md](../../CLAUDE.md), quoted verbatim):

> **Reliability invariant (do not break):** the transactional **staged queue on SQLite (WAL)** gives
> at-least-once delivery, retries, replay, and dead-lettering *without* a separate broker. … At-least-once
> now relies on a re-run re-deriving identical output, so **routers and transforms must be pure** … outbound
> connections must still be **idempotent**.

> **Count-and-log invariant (do not break):** **every received message is persisted before the ACK** …
> so inbound counts still reflect the true received volume and nothing is accepted-and-dropped.

> **Dependency direction is one-way:** `pipeline/ transports/ parsing/ store/ config/` never import `api/`
> or `console/`.

And bounded by the standing scale-out posture (CLAUDE.md §2, ADR 0037 Option 3, ADR 0039 non-goals):
**active-active scale-out is DROPPED and its code removed (#396)** — each store stays **active-passive,
share-nothing**. HA here means *one* active writer with a warm standby, never two concurrent writers of
the same data. FIFO per channel and **single-writer-per-lane** mean a sticky, long-lived MLLP sender must
**not** be rebalanced across replicas. And the identity is **on-prem-first** (ADR 0017 Decision 8: every
instance runs inside the adopter's trusted network) — this ADR makes cloud a *credible, demand-gated
fast-follow*, it does **not** chase a hosted SaaS.

**How "only the leader binds listeners" is actually enforced (load-bearing; the LB recipe rests on it).**
The guarantee does **not** come from the per-source `leader_gate`: a LISTEN source (MLLP/TCP/X12/DICOM/HTTP)
**deliberately ignores** that gate and would bind on every node
([`transports/mllp.py`](../../messagefoundry/transports/mllp.py) `start()`: *"leader_gate is ignored: a
listen source runs on every node"*; `wiring_runner.py`: *"LISTEN sources (MLLP/TCP) accept-and-ignore it"*).
The gate only suppresses **POLL** sources (a shared dir / DB table / remote dir). The single-binder property
is enforced one level up by the **engine graph supervisor**
([`pipeline/engine.py`](../../messagefoundry/pipeline/engine.py) `_start_graph` / `_stop_graph` /
`_reconcile_graph` / `_graph_supervisor_loop`): in CLUSTERED mode the `RegistryRunner` — listeners **and**
workers — is started only while this node holds leadership and is torn down on demotion/fence, so **a
standby never starts its runner and therefore binds no listener**. `cluster.py` states it canonically:
*"listen sources (MLLP/TCP) ignore it and run on every node, but only the leader binds them (the graph runs
on the leader only)."* `docs/CLUSTERING.md` (§"Active-passive graph gating", and the deployment-topology
diagram: *"only the PRIMARY binds it, so the VIP always lands on it"*) is the authoritative, **correct**
statement of this and is the reference the cloud docs build on — the prior draft of this ADR mis-attributed
the seam to `leader_gate`/`wiring_runner.py`; this ADR cites the graph supervisor instead.

**One material correction vs. the research.** The research (dated 2026-06-22) listed a *"startup TLS guard
for raw-TCP/X12 listeners"* as an unbuilt gap (its item #6). That guard has **since been built** —
`check_tcp_tls_exposure` (raw-TCP **and** X12) landed in **PR #558 on 2026-06-26**
([`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py), wired at the source-build
seam alongside `check_mllp_tls_exposure` / `check_dimse_tls_exposure` / `check_http_tls_exposure`). So this
ADR's code item is **not a net-new guard**; it is **ratifying the already-shipped guard and rewriting the
now-stale "no guard" comments** in `docker/compose.yaml`, `docker/k8s/statefulset.yaml`, `docker/README.md`,
and the research itself. The decision below records that honestly rather than re-specifying built code.

## Decision

**Ratify the cloud research into a decision: package the shipped, code-complete active-passive HA into a
copyable cloud/Kubernetes target — a multi-replica reference manifest, Postgres-led cloud docs, primary-only
L4 MLLP load balancing, a hybrid edge-relay template, and a cloud PHI doc — plus a one-line correction
that the raw-TCP/X12 TLS guard already exists.** This is **packaging + docs**, demand-gated (build when a
real cloud/k8s adopter materializes); it must change **no engine reliability behavior**, must **not**
reintroduce active-active, and must **not** add a "channel"/"route" grouping element.

The six deliverables:

1. **Multi-replica HA reference manifest (the highest-leverage gap).** A Postgres-backed example —
   `replicas: 3`, `[cluster].enabled = true`, a `PodDisruptionBudget` with `maxUnavailable: 1`, and a
   `terminationGracePeriodSeconds` kept **longer than `leader_lease_ttl_seconds`** so a drained leader
   releases its lease before SIGKILL (the single-node `statefulset.yaml` already ships `40` against the
   `30s` default lease TTL — this is **carried forward and parameterized**, not introduced) — wired against
   the **built** coordinator + graph supervisor (`pipeline/cluster.py`, `pipeline/engine.py`,
   `/cluster/status`). All three replicas run identical config dirs (ADR 0017 same-commit-everywhere); the
   **graph supervisor** ensures exactly one replica (the leader) starts its `RegistryRunner` and binds the
   listeners, so the standbys are warm and **bind nothing**. Add a **Postgres service to `compose.yaml`** so
   the same HA shape runs locally.

2. **Cloud docs led by managed Postgres; SQLite framed POC/edge-only.** The cloud-deployment doc leads with
   a **managed Postgres** backend (Amazon RDS / Cloud SQL / Azure Database for PostgreSQL) for k8s HA —
   matching the Mirth/IRIS shape — because the **built `[cluster]` validator
   (`config/settings.py`) refuses SQLite and requires `[store].backend ∈ {postgres, sqlserver}` with
   `pool_size ≥ 2`** when `[cluster].enabled`, and a SQLite store on a `ReadWriteOnce` PVC *physically*
   binds a `StatefulSet` to one writer. SQLite / single-node is documented as **POC / on-prem-edge only**.
   SQL Server stays the on-prem enterprise backend (both server backends are HA-eligible; lead Postgres in
   the cloud docs, keep SQL Server first-class for on-prem).

3. **MLLP exposure via an operator-built L4 load balancer that follows failover.** Document **one L4 NLB
   listener per MLLP port** with a **health check that passes only on the primary**. Because the graph
   supervisor binds the inbound listener **only on the leader**, a standby's listener port is **closed** —
   so a **TCP-connect health check** to that port fails on standbys and the VIP **follows failover
   automatically without any engine VIP code**. (Where the LB supports L7 checks against the API,
   `GET /cluster/status` with `role == "primary"` / `is_leader == true` is the explicit, unambiguous probe —
   noted as the alternative for LBs that can read it; the TCP-connect probe is the zero-dependency default.
   **Caveat documented in the cloud guide:** `/cluster/status` is gated by `monitoring:read`, so an L7
   probe must inject a bearer token and many L4 LBs cannot — the TCP-connect default needs no auth, and
   there is no tokenless primary-only endpoint.)
   The health-check **interval must exceed the graph reconcile interval** (`engine._graph_reconcile_interval`,
   ~1s) so the VIP does not flap during the brief start/stop reconcile window of a leadership transition.
   Document the AWS-NLB specifics: idle timeout **>** the socket keepalive; drain in-flight frames via
   `deregistration_delay`. Two hard prohibitions, stated explicitly in the doc and manifest comments:
   - **NO L7/HTTP ingress for MLLP** — MLLP is long-lived raw TCP, not request/response HTTP.
   - **NO HPA for MLLP** — sticky long-lived senders won't rebalance, and autoscaling replicas conflicts
     with **FIFO / single-writer-per-lane**. Scale intake via **L3 parallel-lane / order-group sharding
     (ADR 0037)**, *never* by replicating a partner's inbound listener. (HA replicas are for *failover*,
     not for spreading one partner's load.)

4. **Hybrid edge-relay topology template (the realistic on-prem-adopter cloud path).** A template where
   **MLLP is terminated near the EHR** (an edge relay on the hospital network) and forwarded over a
   **private encrypted link** (site-to-site VPN / AWS Direct Connect / Azure ExpressRoute) to a cloud
   engine — with the **staged at-least-once store as the WAN buffer** (the existing reliability invariant
   *is* the selling point: a WAN blip queues in the staged store and drains on reconnect, nothing dropped,
   per count-and-log). This sidesteps the real cloud objection — every MLLP message crossing a WAN to an
   on-prem EHR, MLLP having no native TLS — without changing the engine.

5. **Cloud PHI / HIPAA secure-architecture doc.** A doc codifying the adopter-execution posture (these are
   *process*, the engine guards are already built): a CSP **BAA** + **HIPAA-eligible services only**;
   **KMS-backed at-rest** (RDS/EBS CMEK) layered with the engine's own AES-256-GCM store encryption, made
   **fail-closed** by setting `[store].require_encryption = true` (the TOML boolean at
   `config/settings.py`; `serve` refuses to start keyless — `__main__.py`) with the key supplied via the
   `MEFOR_STORE_ENCRYPTION_KEY` env var (or `[store].encryption_key_file`); region pinning; **private
   subnets + PrivateLink**; and **no public MLLP ingress** (edge-relay or private-link only). It reaffirms
   ADR 0017 Decision 8 (every instance inside the trusted network) for the cloud case and anticipates the
   2025 HIPAA Security Rule NPRM encryption/segmentation/inventory floor *(not finalized as of 2026-06;
   medium confidence)*. **Every env-var/setting name in the doc must be verified against
   `config/settings.py` before publishing.** Specifically: `MEFOR_STORE_REQUIRE_ENCRYPTION=true` IS a real
   env var (it maps to `[store].require_encryption`), but a prior draft implied that boolean **alone**
   encrypts at rest — it does not; it only forces a **keyless-start refusal**. The two controls that must
   both be set are `[store].require_encryption=true` AND the key (`MEFOR_STORE_ENCRYPTION_KEY` or
   `[store].encryption_key_file`).

6. **The raw-TCP/X12 startup TLS guard — ratify-as-built + rewrite stale comments (not net-new code).**
   `check_tcp_tls_exposure` (raw-TCP and X12, a sibling of `check_mllp_tls_exposure`) **already ships**
   (PR #558, 2026-06-26) and is wired into the source-build path. The work here is to **rewrite the stale
   comment blocks** in `docker/compose.yaml`, `docker/k8s/statefulset.yaml`, and `docker/README.md` — both
   halves of each block: drop *"those listeners have NO startup transport guard"* **and** correct the
   contrasting clause *"MLLP and the DICOM C-STORE SCP are guarded"* to the **complete set** (MLLP, DICOM
   C-STORE SCP, HTTP, **raw-TCP, and X12** are all exposed-gated — a non-loopback bind without TLS is
   refused at start), plus fix the same gap in the research note. **Off-box log forwarding is a separate
   open item, not flipped on here:** the built `[logging]` syslog forwarder is **plaintext** (UDP/TCP only;
   `SyslogProtocol` has **no TLS variant** — `config/settings.py`), so enabling it from a cloud/ephemeral-pod
   posture would put PHI-adjacent log metadata on the wire in cleartext. Any prod-HA enablement is gated on
   pairing it with a TLS-forwarding sidecar / TLS collector (tracked in *To resolve*). Note for operators:
   **API TLS cert rotation needs a pod restart** (uvicorn builds the TLS context once; only MLLP certs
   hot-reload on `/config/reload`) — fold it into the rolling-renewal runbook.

**What this must not break:** no change to the staged-pipeline transactions, at-least-once, the
single-finalizer, per-channel FIFO, or count-and-log; **no second concurrent writer** (active-active stays
deleted); **no "channel"/"route" grouping element** (replicas/lanes are not a graph-bundling object); the
one-way dependency rule holds (manifests/docs touch no engine package; the only code touched is doc-comment
text in `docker/` and the already-wired guard, which lives in `pipeline/` and imports nothing upward).

## Acceptance Criteria

> Mostly **artifact** criteria (this is packaging + docs); the behavioural criteria are the already-built
> graph-supervisor binding and the already-built guard, asserted as regression locks. The manifest-lint
> CI leg referenced by AC-4/AC-5 does **not** exist yet — it ships **as part of this work** (see
> *To resolve*), so those two criteria are verified by a *to-build* artifact gate, not an existing one.

- **AC-1** — WHILE a node holds cluster leadership it SHALL run the wired graph and bind the inbound
  listeners, and WHILE a node is a standby it SHALL run no listeners and bind nothing — so exactly one
  (leader) replica is bound at a time and a standby takes over on leader loss within ≈ one heartbeat
  (clean stop) to `leader_lease_ttl_seconds` (crash). *(This is the property the primary-only LB health
  check depends on — it is enforced by the engine graph supervisor, not the per-source leader_gate.)*
  → `tests/test_cluster_graph_gating.py::test_clustered_follower_does_not_start_the_graph`,
  `tests/test_cluster_graph_gating.py::test_clustered_leader_starts_the_graph_at_startup`,
  `tests/test_cluster_graph_gating.py::test_reconcile_starts_on_promotion_and_stops_on_demotion`
- **AC-2** — IF `[cluster].enabled` is set with a SQLite (or non-server) `[store].backend` or
  `pool_size < 2`, THEN THE SYSTEM SHALL refuse to start with a config-load error (the manifest cannot
  silently degrade HA to a single SQLite writer).
  → `tests/test_settings.py::test_cluster_enabled_requires_server_db_backend` (existing `[cluster]` cross-section validator)
- **AC-3** — WHEN an inbound raw-TCP or X12 listener binds a non-loopback host without TLS and without
  `--allow-insecure-bind`, THE SYSTEM SHALL refuse to start (cleartext-PHI exposed-gate), parity with the
  MLLP/DICOM/HTTP guards.
  → `tests/test_listener_tls_exposure.py::test_non_loopback_plaintext_refused` (the `check_tcp_tls_exposure` guard shipped in PR #558)
- **AC-4** — THE multi-replica manifest SHALL **preserve** `terminationGracePeriodSeconds` **>**
  `leader_lease_ttl_seconds` (the single-node manifest already sets `40` against the `30s` default) **and
  add** a `PodDisruptionBudget` `maxUnavailable: 1`, so a voluntary disruption drains and releases the
  leader lease before SIGKILL and never takes the quorum below one live writer.
  → manifest review + a **new** `kubeconform`/policy-lint CI leg shipped with this work (to-build; no pytest)
- **AC-5** — THE cloud docs SHALL state, for MLLP, **one L4 NLB listener per port with a primary-only health
  check** (TCP-connect to the listener port, or `GET /cluster/status` `role==primary`) and an explicit
  **"no L7/HTTP ingress, no HPA for MLLP"** prohibition; AND the stale guard-comment blocks in
  `docker/compose.yaml`, `docker/k8s/statefulset.yaml`, **and `docker/README.md`** SHALL be rewritten so no
  occurrence still claims raw-TCP/X12 are unguarded or contrasts them as unguarded against MLLP/DICOM.
  → doc/manifest review (artifact assertion; same new manifest-lint CI leg as AC-4)

## Options considered

1. **Package the built active-passive HA into a copyable cloud/k8s target (this) — manifest + Postgres-led
   docs + primary-only L4 LB + edge-relay template + cloud PHI doc, all demand-gated.** **CHOSEN.** Closes
   the *packaging* gap that the research identified as the only thing between MEFOR and Mirth/IRIS parity,
   without touching the reliability core; honors active-passive, FIFO/single-writer, and on-prem-first;
   the WAN-buffering edge relay turns the staged store into the cloud selling point.
2. **Ship a hosted SaaS / managed offering.** **Rejected** — a different business; every incumbent is
   converging there (Corepoint-as-a-Service, IRIS Cloud, Redox), and MEFOR's near-term wedge is exactly
   self-host control + no per-communication-point licensing *against* those managed services. The research's
   explicit recommendation: invest *moderately*, do **not** chase SaaS now.
3. **A first-party Kubernetes Operator / CRD (the IRIS `IrisCluster` bar).** **Rejected (deferred)** — a
   plain manifest + docs reaches Mirth-Helm parity at a fraction of the cost; a bespoke Operator is
   speculative build ahead of a single validating cloud feed, the exact trap this item is demand-gated to
   avoid. Revisit only if a real k8s adopter needs it.
4. **Active-active scale-out (N concurrent writers) for cloud throughput.** **Rejected / stays deleted
   (#396).** It violates the active-passive store invariant and per-channel FIFO; cloud HA is *failover*,
   and intake scale is the L3 sharding lever (ADR 0037), never a second live writer.
5. **An engine-managed VIP (the engine actively reassigns the floating IP on failover).** **Rejected for
   this ADR (out of scope; the boundary).** The cloud-native answer is **passive**: because the graph
   supervisor binds the listener **only on the leader**, the LB's primary-only health check already makes
   the VIP follow the leader, with **zero** engine VIP code. An engine that manipulates a VIP is the
   separate "engine-managed VIP failover" item the 0048 index note reserved — left to a future ADR if a
   non-LB (e.g. bare-metal keepalived) topology ever demands it.

## Consequences

**Positive** — reaches Mirth/IRIS container-HA parity on **packaging** (the capability is already built);
gives adopters a copy-paste HA manifest + a Postgres-led cloud path + an MLLP-LB recipe that follows
failover with no engine changes; the edge-relay template makes the staged at-least-once store a concrete
WAN-buffering selling point; the cloud PHI doc de-risks adopter compliance; and it all stays demand-gated,
so nothing is built ahead of a real adopter. The container investment pays off for on-prem/single-node
regardless of how far the cloud path goes.

**Negative / risks** — failover is **not instantaneous** (clean stop ≈ one heartbeat; crash up to
`leader_lease_ttl_seconds`, ~30s default) — the manifest and docs must set that expectation. The
`terminationGracePeriodSeconds` > lease-TTL guard must be **carried forward** (the single-node manifest
already holds it at `40` vs `30s`) or a drained leader is SIGKILLed holding its lease. The LB health-check
interval must exceed the graph reconcile interval (~1s) or the VIP can flap across a leadership transition.
Managed-Postgres HA + KMS + PrivateLink push real cost/ops onto the adopter (mitigant: SQLite single-node
and the edge relay stay valid lighter paths). Manifests can drift from the engine's settings/validators
(mitigant: AC-1/AC-2/AC-3 lock the behavior in pytest; AC-4/AC-5 lint the artifacts in the **new** CI leg).
The Mirth competitive facts in the research are **medium-confidence** (the Mirth research agent failed
mid-run) — verify current NextGen Helm/Docker specifics before leaning on the parity claim.

**Out of scope** — a hosted SaaS / managed offering; a first-party k8s Operator / CRD; **engine-managed VIP
failover** (the passive primary-only-health-check LB is the chosen mechanism; an engine that manipulates a
VIP is a separate reserved item); active-active / a second concurrent writer (#396, deleted); an inbound
**DICOMweb / HTTP web-service receiver** as a public cloud ingress (a distinct not-yet-built auth/TLS
surface, ADR 0023 territory); **TLS off-box log forwarding** (the built forwarder is plaintext — a TLS
syslog variant or a TLS sidecar/collector is a separate item); DB-tier write-scaling (L5 / ADR 0039) and
loss-of-site DR (ADR 0048) — those are separate levers this ADR only references. This ADR ships **no new
engine reliability code**; the raw-TCP/X12 guard is ratified-as-built, not re-implemented.

## To resolve on acceptance

> The **clarify** step: settle these before this flips to `Accepted` and any manifest/doc is authored.

- [ ] **ADR-number collision (gating).** [ADR 0048](0048-third-tier-disaster-recovery-standby.md) §1 records
  `0047` as *"reserved elsewhere — engine-managed VIP failover."* Confirm with the owner that `0047` is
  reassigned to **this** (deployment packaging) and that the reserved engine-managed-VIP work, if it ever
  happens, takes a **new** number — then, in the same change, update the `docs/adr/README.md` index and the
  0048 cross-reference so the reserved-slot note doesn't dangle.
- [ ] **Lead backend for the HA reference manifest:** ship the canonical example on **managed Postgres**
  (RDS/Cloud SQL/Azure DB) only, or ship a SQL Server (Always On AG) variant alongside it for on-prem
  enterprise adopters? (The validator accepts both; the question is which the *shipped* manifest demonstrates.)
- [ ] **`terminationGracePeriodSeconds` value:** the single-node manifest ships `40` (> the `30s` default
  `leader_lease_ttl`). Confirm the multi-replica default relative to the lease TTL **and** the per-MLLP-listener
  serial drain (≈5s each, additive) — i.e. pin the exact `grace = f(lease_ttl, listener_count)` formula the
  manifest comment should carry, reconciled with the existing `40`.
- [ ] **LB health-check probe + interval:** ratify TCP-connect-to-listener-port as the default primary-only
  probe (vs `GET /cluster/status` `role==primary` for L7-capable LBs), and pin the health-check interval
  **above** `engine._graph_reconcile_interval` (~1s) so the VIP doesn't flap during a leadership reconcile.
- [ ] **Edge-relay implementation:** is the edge relay just the **same engine image** run on-prem (MLLP in →
  forward out over the private link), or a documented thinner relay profile? Confirm it reuses the existing
  outbound MLLP/TCP connectors with no new code.
- [ ] **HIPAA NPRM dependency:** the cloud PHI doc anticipates the 2025 Security Rule NPRM
  encryption/segmentation/inventory floor — confirm we publish against the **current** Security Rule and
  flag the NPRM as anticipated-not-final (it was unfinalized as of 2026-06), so the doc doesn't assert an
  unenacted requirement.
- [ ] **Off-box log forwarding hop:** the built `[logging]` syslog forward is **plaintext** today
  (`SyslogProtocol` is UDP/TCP only — no TLS variant). Decide the prod-posture HA path: pair it with a
  TLS-forwarding sidecar / TLS collector before any enablement, **or** keep off-box forwarding out of the
  cloud manifest entirely — but do **not** instruct operators to "flip it on" as-is (cleartext PHI-adjacent
  metadata on the wire).
- [ ] **Manifest-lint CI leg:** confirm the new `kubeconform`/policy-lint job (the verifier named by
  AC-4/AC-5) ships with this work and is wired into CI — there is no such leg today.


---

## Ratification decisions (2026-06-28)

Owner delegated the open items ("you sort it out / do what is best"); resolved as:

- **Slot 0047 confirmed for this deployment-packaging work.** The earlier "engine-managed VIP failover" reservation on 0047 is **dissolved**: the VIP *follows* failover via the operator-assembled **passive** primary-only-health-check LB — the engine never manipulates a VIP. ADR 0048's fence rests on this.
- **Reference HA manifest leads with managed Postgres** (RDS / Cloud SQL / Azure DB). SQL Server Always On AG is an on-prem **doc variant**, not a second shipped manifest.
- **LB probe:** TCP-connect, **primary-only**, as the default; `GET /cluster/status` (role==primary) for L7-capable LBs. The health-check interval is pinned **above** the graph-reconcile interval (~1s) to avoid VIP flap during a leadership reconcile.
- **`terminationGracePeriodSeconds` ≥ `leader_lease_ttl` + serial-drain + margin** (reconcile with the existing single-node `40`).
- **Edge-relay = the same engine image** (reuse the outbound MLLP/TCP connectors) — **no new code**.
- **Cloud PHI doc** is published against the **current** HIPAA Security Rule; the 2025 NPRM floor is flagged as anticipated-not-final.
- **Off-box syslog stays OUT of the cloud manifest as-is** — `[logging]` syslog forwarding is plaintext; pair it with a TLS sidecar/collector before any enablement. Operators are **not** told to "flip it on" (no cleartext PHI-adjacent metadata on the wire).
- **A kubeconform / policy-lint CI leg ships with the build lane** (the verifier AC-4/AC-5 name).
