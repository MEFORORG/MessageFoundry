<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# Cloud PHI / HIPAA secure-architecture posture

This codifies the **adopter-execution** posture for running MessageFoundry in a cloud account that carries
PHI ([ADR 0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md), deliverable 5). The engine's own
guards — fail-closed off-loopback bind gates, in-process API/MLLP TLS, AES-256-GCM at-rest, TOTP MFA,
deny-by-default egress, full audit — are **already built** ([`docs/PHI.md`](PHI.md),
[`docs/SECURITY.md`](SECURITY.md), [`docs/DEPLOYMENT.md`](DEPLOYMENT.md)). What this doc adds is the
**cloud-infrastructure process** the adopter owns: a BAA, HIPAA-eligible services, KMS at-rest, region
pinning, private networking, and no public MLLP ingress.

> **Standards baseline.** This doc is written against the **currently in-force HIPAA Security Rule** (45
> CFR Part 164, Subpart C — §164.308 administrative, §164.310 physical, §164.312 technical safeguards). A
> **2025 NPRM** proposed a stricter floor (mandatory encryption, network segmentation, asset inventory,
> removing "addressable" flexibility). As of this writing **that NPRM is anticipated, not final** — treat
> everything tagged *(NPRM-anticipated)* below as forward guidance, not an enacted requirement. Confirm the
> rule's status when you deploy.

---

## 0. The trust boundary still applies in the cloud

MessageFoundry is **on-prem-first** ([ADR 0017](adr/0017-consumer-deployment-model.md) Decision 8): every
instance runs **inside the adopter's trusted network**. In the cloud, "your trusted network" is **your VPC
in your cloud account** — private subnets, your perimeter controls — **not** a public endpoint and **not** a
MessageFoundry-operated multi-tenant SaaS (there is none). This reaffirms the on-prem trust boundary for the
cloud case: nothing PHI-bearing is ever placed directly on the public internet.

The cloud deployment is the multi-node HA shape in [`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md). This doc is
the compliance overlay on top of it.

---

## 1. Business Associate Agreement (BAA) — the gate

- **Execute a BAA with the cloud service provider** before any ePHI lands. AWS, Azure, and Google Cloud all
  offer one; without it the CSP is not a permitted business associate for PHI.
- **Use only HIPAA-eligible services.** A signed BAA covers a **specific list** of services per provider —
  not the whole catalog. Every service in the PHI path (compute, the managed DB, load balancers, KMS,
  logging, secrets) **must** be on that provider's HIPAA-eligible list. Check it explicitly; do not assume
  a service is in scope.
- **Flow the BAA down.** Your BAA with the covered entity / your customers must align with the CSP BAA.

---

## 2. Encryption at rest — KMS CMEK layered with the engine cipher

PHI at rest is protected in **two layers**, and the engine layer is made **fail-closed**:

1. **Infrastructure layer (the CSP, under a customer-managed KMS key):** enable **KMS CMEK** (customer
   master / customer-managed key) on:
   - the **managed Postgres** store (RDS / Aurora / Cloud SQL / Azure DB at-rest encryption),
   - any **block storage** (EBS / persistent disks) and **backups / snapshots**,
   - the **Secret** store (see §4).
   Prefer a **customer-managed** key (CMEK) over the provider-default key, so you own key rotation and can
   revoke. *(NPRM-anticipated: encryption at rest becomes mandatory rather than "addressable.")*
2. **Application layer (the engine):** MessageFoundry **also** encrypts PHI columns with **AES-256-GCM** in
   the store, independent of the DB's at-rest encryption, so a DB-file or backup exposure does not yield
   cleartext PHI. Make it **fail-closed**:
   - `[store].require_encryption = true` (env `MEFOR_STORE_REQUIRE_ENCRYPTION=true`) — `serve` **refuses to
     start** without a key, in any environment ([`config/settings.py`](../messagefoundry/config/settings.py),
     [`__main__.py`](../messagefoundry/__main__.py)).
   - Supply the key via **`MEFOR_STORE_ENCRYPTION_KEY`** (base64 of 32 random bytes —
     `messagefoundry gen-key`), sourced from the secret store (§4); **or** via
     `[store].encryption_key_file` (a path, e.g. a mounted secret file). These two — `require_encryption`
     and `MEFOR_STORE_ENCRYPTION_KEY` / `encryption_key_file` — are the **real** controls. (`MEFOR_STORE_REQUIRE_ENCRYPTION=true`
     IS a real env var — it maps to `[store].require_encryption` — but it does **not** encrypt anything on its
     own: it only forces a **keyless-start refusal**. You must **also** supply the key var. Earlier drafts
     implied the boolean alone sufficed; the boolean **and** the key var are both required, names verified
     against `config/settings.py`.)
   - Rotate the engine key with `messagefoundry rotate-key` (retired keys via `encryption_keys_retired`).

---

## 3. Encryption in transit — no PHI on the wire in cleartext

- **API / WSS:** in-process TLS (`MEFOR_API_TLS_CERT_FILE` / `MEFOR_API_TLS_KEY_FILE`), or an upstream
  TLS terminator (`tls_terminated_upstream` + `trusted_proxies`). A non-loopback API bind without TLS is
  **refused at startup**.
- **MLLP data plane:** **MLLP-over-TLS** (`tls=True` per connection). A non-loopback MLLP listener without
  TLS is **refused at wiring time** (`check_mllp_tls_exposure`). For partners that cross a WAN, prefer the
  **edge-relay** topology ([`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md) §5) so MLLP stays on the LAN and
  the WAN hop rides a private encrypted link.
- **raw-TCP / X12:** **plaintext-only** (no TLS option), and **exposed-gated** since PR #558 —
  `check_tcp_tls_exposure` **refuses** a non-loopback raw-TCP/X12 bind at startup, parity with the
  MLLP/DICOM/HTTP guards. Keep them loopback-bound, OS-firewalled/segmented, or behind a TLS-terminating
  TCP proxy. **Do not** publish them publicly.
- **Store DB connection:** `[store].encrypt = true` (default) + `[store].trust_server_certificate = false`
  (default) — TLS-verified to the managed Postgres. Give the DB a CA-trusted cert; **never** set
  `MEFOR_ALLOW_INSECURE_TLS` in production.

---

## 4. Secrets — the CSP secret store, KMS-wrapped

- Inject `MEFOR_STORE_ENCRYPTION_KEY`, `MEFOR_STORE_PASSWORD`, `MEFOR_API_TLS_KEY_PASSWORD`, and the TLS
  cert/key from the **cloud secret manager** (AWS Secrets Manager / Azure Key Vault / Google Secret
  Manager) or a k8s `Secret` whose backing store is KMS-encrypted — **never** plain manifest values or
  image layers. On k8s, inject via `secretKeyRef` (the manifests do this); enable **KMS envelope
  encryption** for etcd Secrets.
- A future external-KMS key provider seam exists (`[store].key_provider` = `aws_kms` | `azure_kv` |
  `gcp_kms` | `vault` | `pkcs11`) but is **not built yet** (it fails closed if selected). Today, source the
  key from the secret manager into `MEFOR_STORE_ENCRYPTION_KEY`.

---

## 5. Network architecture — private subnets, PrivateLink, no public MLLP

- **Private subnets only** for the engine pods and the managed DB. The DB is **never** publicly reachable.
- **PrivateLink / private endpoints** for the managed-DB and secret-manager connections, so that traffic
  never traverses the public internet even within the provider.
- **No public MLLP ingress.** MLLP is never exposed on a public load balancer. Partners reach it via:
  - the **edge-relay** topology (MLLP terminated on-prem near the EHR, forwarded over a private encrypted
    link — the recommended path), or
  - an **internal** L4 NLB reachable only from your private network / VPN (`aws-load-balancer-scheme:
    internal`), never `internet-facing`.
- **Segment the management plane** (console/IDE → API) from the data plane; keep the API off general-user
  VLANs. *(NPRM-anticipated: explicit network segmentation between systems handling ePHI.)*
- **Region pinning.** Pin every PHI-handling service to an **approved region** (data residency): the
  managed DB, compute, KMS keys, backups, and secret store all in-region. Disable cross-region replication
  to unapproved regions; KMS keys are regional — keep them in the pinned region.

---

## 6. Identity, access, audit

- **Authentication required + MFA.** `MEFOR_AUTH_ENABLED=true`; `MEFOR_AUTH_REQUIRE_MFA=true` for local
  Administrator accounts on an exposed PHI bind (the startup gate **refuses** a production-PHI off-loopback
  bind with local admins and `require_mfa=false`). AD/Entra MFA stays delegated to your IdP.
- **Deny-by-default egress.** `MEFOR_EGRESS_DENY_BY_DEFAULT=true` + the `MEFOR_EGRESS_ALLOWED_*` lists, so a
  transform can only send to approved destinations — a fail-closed exfiltration guard.
- **Full audit, off-box to your SIEM.** Every PHI access (raw view, summary) is audited with the acting
  user ([`docs/SECURITY.md`](SECURITY.md)). Ship audit + operational logs to your SIEM — but note the
  off-box **syslog forwarder is plaintext** ([§7](#7-known-residuals)); front it with a TLS-forwarding
  collector before enabling. Cloud-native: the container log driver to a TLS-terminating collector is the
  cleaner path for ephemeral pods.
- **Least-privilege IAM** for the pods (the DB login, the secret-manager reads, the KMS decrypt grant) —
  scope each to exactly what it needs.

---

## 7. Known residuals

- **Off-box syslog is plaintext (not enabled in the cloud manifest).** `SyslogProtocol` has no TLS variant
  ([`config/settings.py`](../messagefoundry/config/settings.py)), so `[logging].forward_*` is deliberately
  **omitted** from the HA manifest and is **not** flipped on by this guide. Pair it with a TLS
  sidecar/collector before any enablement — do not put PHI-adjacent log metadata on the wire in cleartext.
- **In-engine TLS revocation is delegated** ([ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md)).
  For enforced OCSP/CRL revocation, terminate with an **OCSP-must-staple** proxy (Topology B).
- **API cert rotation needs a pod restart** (uvicorn builds the TLS context once; MLLP certs hot-reload on
  `/config/reload`). Plan a rolling restart for API-cert renewal.
- **DB-tier HA is the managed service's job.** MessageFoundry rides the shared store connection; its
  availability follows the DB tier's (Multi-AZ / replication / Always On). Back up + restore-test the DB.

---

## 8. Pre-flight checklist (PHI cloud deployment)

- [ ] **BAA signed** with the CSP; every PHI-path service is on the provider's **HIPAA-eligible list**.
- [ ] **KMS CMEK** on the managed DB, block storage, backups/snapshots, and the secret store.
- [ ] Engine at-rest fail-closed: `MEFOR_STORE_REQUIRE_ENCRYPTION=true` **and** `MEFOR_STORE_ENCRYPTION_KEY`
      (or `[store].encryption_key_file`) supplied from the secret manager.
- [ ] **TLS in transit** everywhere: API TLS, MLLP-over-TLS (or edge-relay), DB `encrypt=true` /
      `trust_server_certificate=false`; **`MEFOR_ALLOW_INSECURE_TLS` is NOT set**.
- [ ] raw-TCP/X12 are loopback/segmented (the gate refuses a public bind) — none published publicly.
- [ ] **Private subnets + PrivateLink**; DB not publicly reachable; **no public MLLP ingress** (edge-relay
      or internal NLB only).
- [ ] **Region-pinned**: DB, compute, KMS keys, backups, secrets all in the approved region.
- [ ] **Auth + MFA** on; **deny-by-default egress** with populated allow-lists.
- [ ] **Audit + logs to the SIEM** via a **TLS** collector (NOT the plaintext syslog forwarder as-is).
- [ ] Least-privilege IAM for the pods (DB / secrets / KMS-decrypt grants scoped tight).
- [ ] *(NPRM-anticipated, forward-looking)* mandatory encryption, network segmentation, and an asset
      inventory documented — confirm whether the 2025 Security Rule NPRM has been finalized at deploy time.

---

## Related

- [`PHI.md`](PHI.md) — the full PHI map, threat model, redaction, retention/encryption roadmap.
- [`SECURITY.md`](SECURITY.md) — authn/RBAC, MFA, audit.
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — per-channel bind/TLS posture and the off-loopback gates.
- [`CLOUD-DEPLOYMENT.md`](CLOUD-DEPLOYMENT.md) — the cloud/k8s HA deployment this overlays.
- [ADR 0047](adr/0047-cloud-kubernetes-ha-deployment-packaging.md) — the decision; [ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md) — transport security.
