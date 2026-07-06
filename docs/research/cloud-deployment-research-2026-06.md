<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# Cloud / Kubernetes deployment — research & decision notes

**Recorded 2026-06-22.** Captured after the container fast-follow (ADR 0017) shipped (PR #480:
slim + `-sqlserver` engine images, compose, single-node k8s StatefulSet). This is the saved basis for
[`BACKLOG.md`](../BACKLOG.md) **#41** — read it if/when a cloud or Kubernetes adopter materializes.

> **Provenance / confidence.** Point-in-time, AI-assisted research synthesis (multi-agent web research +
> a codebase assessment) — **not** a vendor benchmark or a committed plan. The dedicated *Mirth* research
> agent failed mid-run (API overload), so **Mirth-specific facts came from the broader engine research and
> are medium-confidence**; verify Mirth's current Helm/Docker specifics against NextGen's docs before
> relying on them. Competitor facts are dated and marked with confidence inline.

---

## 1. Direct answer — does the shipped container support cloud deployment?

**Yes, with one caveat that matters.** The image is a clean, non-root, OCI-compliant Linux container with
a working k8s StatefulSet, in-process TLS, fail-closed PHI guards, and a CI-proven build + graceful drain.
It runs on any cloud container service today (ECS/Fargate, AKS, GKE, vanilla k8s).

**Caveat:** what ships is **single-node by construction** — the default image is SQLite-on-a-ReadWriteOnce
PVC and both shipped manifests are hard `replicas: 1`. The multi-node HA story (external server DB +
leader election) is **fully built in the engine** but has **no shipped manifest**, so cloud HA today is
"code-complete, operator assembles it," not "deploy-and-go."

## 2. Cloud-readiness by tier

| Tier | What it is | Status |
|---|---|---|
| **(a) Run on a cloud container platform** | Pull + run on ECS/Fargate/AKS/GKE/k8s | **Supported** (slim image, non-root uid 10001, tini PID 1, `/health` HEALTHCHECK, read-only-rootfs-ready; CI `docker-smoke` proves build → MLLP → PROCESSED → graceful stop) |
| **(b) Single-node cloud instance** | One pod, durable PVC, TLS, PHI guards on | **Supported + shipped** (`docker/k8s/statefulset.yaml`: StatefulSet + PVC + Services + Secret; hardened securityContext, liveness probe, lease-aware grace) |
| **(c) Multi-node HA / scale-out** | N pods, external server DB, leader election, LB/VIP follows failover | **Code-complete, NOT shipped as a manifest** — Postgres/SQL Server staged backends + self-fencing leader election (`DbCoordinator`/`SqlServerCoordinator`, `/cluster/status`) are real; a validator enforces `[cluster].enabled` ⇒ server DB. **No example manifest / LB to copy.** |

Net: **(a) and (b) done; (c) is "all the parts, no assembly kit."**

## 3. Competitor comparison

- **Corepoint** (Best-in-KLAS incumbent): Windows + .NET/IIS + required SQL Server; containers uncommon
  *(medium)*. Cloud answer is a **vendor-managed AWS SaaS** ("Corepoint as a Service") *(high)*, not a
  customer-run container. MEFOR wins decisively on container-friendliness + no-Windows/no-per-comm-point license.
- **Mirth Connect** *(medium)*: official Docker images + Helm; run as a StatefulSet pointed at **external
  PostgreSQL** (not embedded Derby). **This is exactly MEFOR's intended multi-node shape — they ship the
  chart, we don't yet.**
- **InterSystems IRIS for Health** *(high)*: most container-mature — official images, durable `%SYS`
  volume, a **first-party Kubernetes Operator (IrisCluster CRD)**. The "k8s-native HA" parity bar.
- **Rhapsody** *(medium)*: VM active/passive with **shared iSCSI + Pacemaker/Corosync + STONITH fencing**,
  ~3-min failover. **MEFOR is architecturally better here** — a self-fencing DB lease needs **no shared
  disk and no STONITH**.

**Overall:** MEFOR's externalized-DB + leader-election design is the modern, correct one — lighter than
Corepoint/Rhapsody, aligned with Mirth/IRIS. The gap is **packaging**, not capability.

## 4. Concrete gaps to truly support cloud (ranked)

1. **(important) No multi-replica HA reference manifest.** Ship a Postgres-backed `replicas: 3` example
   (`[cluster].enabled=true`, PodDisruptionBudget `maxUnavailable: 1`, lease-TTL-aware grace, probe
   wiring) + a compose with a Postgres service. Highest leverage — reaches Mirth/IRIS parity. The code
   works; there is just nothing to copy.
2. **(important) Default config can't scale.** SQLite + ReadWriteOnce PVC physically blocks multiple
   replicas (`settings.py` refuses SQLite under `[cluster]`). Cloud docs must lead with **managed Postgres**
   (RDS / Cloud SQL / Azure DB for PostgreSQL) and frame SQLite/single-node as POC/on-prem-edge only.
   Lead with **Postgres** for k8s (matches Mirth/IRIS); SQL Server stays the on-prem enterprise backend.
3. **(important) MLLP exposure needs an operator-built L4 LB / floating VIP.** Only the primary binds
   inbound ports → one **L4 NLB listener per MLLP port with a TCP-connect health check that passes only on
   the primary**, so the VIP follows failover. Document AWS-NLB specifics (idle timeout > socket keepalive;
   `deregistration_delay` to drain in-flight frames). **Explicitly: do NOT use an L7/HTTP ingress and do
   NOT use HPA for MLLP** — sticky long-lived senders won't rebalance and it conflicts with FIFO /
   single-writer-per-lane. Scale via parallel lanes / order-group sharding, never by replicating a
   partner's inbound listener.
4. **(important) Failover is not instantaneous — set expectations.** Clean stop ≈ 1 heartbeat; crash up to
   `leader_lease_ttl_seconds` (~30s default). Pin `terminationGracePeriodSeconds` so a drained leader
   releases the lease before SIGKILL (lease TTL vs grace must interact sanely).
5. **(nice-to-have) Off-box log/audit shipping is built but off-by-default + the syslog hop is plaintext.**
   Ephemeral pods mean local logs vanish — provide a reference TLS-forwarding sidecar/agent and flip it on
   in the prod-posture HA manifest. Also: **API TLS cert rotation needs a pod restart** (uvicorn builds the
   context once; only MLLP certs hot-reload on `/config/reload`) — note it for rolling renewals. ~~And add a
   **startup TLS guard for raw-TCP/X12** listeners (today unguarded, unlike MLLP/DICOM/API).~~
   **[CORRECTION 2026-06-28 — ADR 0047]:** the raw-TCP/X12 startup TLS guard has since **shipped**
   (`check_tcp_tls_exposure`, PR #558, 2026-06-26): a non-loopback raw-TCP/X12 listener is now refused at
   start, parity with MLLP/DICOM/HTTP. This item is **done**, not a gap.

**PHI/cloud posture is largely process, not code.** Loopback default, off-loopback bind guards, in-process
TLS, MLLP-over-TLS, AES-256-GCM at-rest (`MEFOR_STORE_ENCRYPTION_KEY` + fail-closed `REQUIRE_ENCRYPTION`),
TOTP MFA gate on exposed prod PHI, and deny-by-default egress are all built and default to the prod posture
in the manifests. The remaining work is adopter execution: CSP **BAA** + HIPAA-eligible services only,
KMS-backed at-rest (RDS/EBS CMEK), region pinning, private subnets + PrivateLink, no public MLLP ingress.

## 5. Strategic framing — is cloud actually the goal?

The strongest objection to cloud for HL7 **isn't compliance — it's connectivity/latency**: every MLLP
message would cross a WAN to an on-prem EHR, and MLLP has no native TLS (must be tunneled). The industry
answer is **hybrid: an edge relay near the EHR terminating MLLP locally and forwarding over a private
encrypted link (VPN / Direct Connect / ExpressRoute) to a cloud engine** — and MEFOR's **staged
at-least-once store is precisely the WAN-buffering selling point** for that.

**Recommendation: invest *moderately* — make cloud a credible fast-follow via the hybrid/edge topology;
do NOT chase a hosted SaaS now.**

- **Don't** build a hosted SaaS yet — every incumbent is converging there (Corepoint-as-a-Service, IRIS
  Cloud, Redox), but that's a different business; MEFOR's near-term wedge is self-host control + no
  per-comm-point licensing against those managed services.
- **Do** keep cloud a credible deployment target (ADR-0017 adopter model). Container-readiness is now
  **table stakes** in evals (IRIS/Mirth/Aidbox ship images + charts); we're ~90% there.
- **The container already pays off regardless of how far we push cloud:** reproducible/immutable/hardened
  deploys, a footprint that out-simplifies Windows-bound Corepoint, CI-proven build + graceful drain, the
  WAN-buffering edge-relay story, and the foundation for any future managed offering. None of it is wasted
  even if no instance ever runs in the cloud.

External one-liner: *"open-source Python healthcare integration engine — on-prem-first, container-ready,
k8s-capable, hybrid-cloud via edge relay, no Windows, no per-comm-point license."*

## 6. Recommended next steps (if/when picked up)

1. **Multi-replica HA reference manifest** (Postgres-backed `replicas: 3`, `[cluster].enabled`,
   PodDisruptionBudget, lease-TTL-aware grace) + a Postgres compose service. *Closes the #1 gap.*
2. **Cloud deployment ADR + adopter doc** codifying: external server DB (lead Postgres) + L4-NLB-per-MLLP
   with primary-only health check + leader-gated single-writer, and the explicit "no HTTP ingress / no HPA
   for MLLP" warnings.
3. **Hybrid edge-relay topology template** (MLLP terminated near the EHR, forwarded over a private link),
   positioning the staged store as the WAN-buffer.
4. **Cloud PHI/HIPAA secure-architecture doc** (BAA, HIPAA-eligible services, KMS at-rest, region pinning,
   private subnets/PrivateLink, no public MLLP) — anticipate the 2025 HIPAA Security Rule NPRM
   encryption/segmentation/inventory floor *(not finalized as of 2026-06, medium confidence)*.
5. ~~**Startup TLS guard for raw-TCP/X12/DICOM** (parallel to `check_mllp_tls_exposure`)~~ **— DONE, see the
   CORRECTION at §4 item 5: `check_tcp_tls_exposure` (raw-TCP/X12) shipped in PR #558 and the DICOM SCP guard
   (`check_dimse_tls_exposure`) was already built.** Off-box log forwarding is **NOT** flipped on in the HA
   manifest (ADR 0047): the `[logging]` syslog forwarder is plaintext (no TLS variant), so it must be paired
   with a TLS sidecar/collector before any enablement — it is deliberately left out of the cloud manifest.

**Relevant code/docs:** `docker/Dockerfile`, `docker/k8s/statefulset.yaml`, `docker/compose.yaml`,
`docs/DEPLOYMENT.md`, `docs/CLUSTERING.md`, `docs/CONTAINER-EXPOSURE-EVALUATION.md`,
`messagefoundry/store/postgres.py`, `messagefoundry/store/sqlserver.py`,
`messagefoundry/pipeline/cluster.py`, `messagefoundry/pipeline/cluster_sqlserver.py`,
`messagefoundry/config/settings.py`.
