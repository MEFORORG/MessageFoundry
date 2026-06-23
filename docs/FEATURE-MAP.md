# MessageFoundry — Feature Map

A capability catalog across every area of the engine, with status. The companion **execution**
view (workstreams, gates, sequencing for the next release) is the
[v0.1 Release Plan](releases/v0.1-PLAN.md); this is the **capability** view.

**Status legend**

| Mark | Meaning |
|------|---------|
| ✅ | **Shipped** — on `main` today |
| 🔬 | **Shipped but experimental** — present, not yet production-labeled |
| 🔨 | **v0.1** — planned for the `0.1.0` release ([plan](releases/v0.1-PLAN.md)) |
| ⏭️ | **0.2+** — deferred (see the plan's *Out of scope*) |
| 🧭 | **Later** — on the long-term vision, not yet scheduled |

**Core model (shipped):** a code-first message graph wired *by name* — an inbound **Connection**
names a **Router** (`@router`), which forwards to one or more **Handlers** (`@handler`, filter →
transform), which `Send` to outbound Connections. No enclosing "channel" object; the configuration
*is* the graph, version-controlled as Python. Connection *transport config* may also live in
`connections.toml` (ADR 0007). Engine = headless asyncio FastAPI service; PySide6 console + VS Code
IDE are separate surfaces over the localhost API.

---

## 1. Ingestion & Transports (Connections)

| Feature | Status | Notes |
|---------|:--:|-------|
| MLLP source + destination | ✅ | Correct `0x0B…0x1C0x0D` framing, ACK/NAK, configurable ack mode |
| File source + destination | ✅ | Poll source is leader-gated in cluster mode |
| RemoteFile — SFTP / FTP / FTPS | ✅ | `[sftp]` extra (paramiko); FTP/FTPS via stdlib |
| TCP source + destination | ✅ | Generic byte-stream framing |
| DATABASE destination + DB-IN poll source | ✅ | Production (aioodbc/SQL Server); live round-trip CI-tested (#233) |
| REST destination | ✅ | ADR 0003 |
| SOAP destination | ✅ | ADR 0003 |
| FHIR REST destination | ✅ | ADR 0022 (#20) — R4B default (R5/STU3); create/update/transaction + 3 conditional knobs; reuses rest.py |
| Payload-agnostic ingress (`content_type` / `RawMessage`) | ✅ | ADR 0004 — non-HL7 bodies skip HL7 parsing |
| X12 EDI raw-TCP connector (ISA/IEA-framed) | ✅ | ADR 0012 — `X12()` source/destination; pairs with the `parsing/x12` codec (§3) |
| DICOM C-STORE SCP source (inbound DIMSE) | ✅ | ADR 0025 Phase 1 (#439) — `DICOM()` inbound C-STORE listener over `pynetdicom`, off-loop + commit-before-SUCCESS; `[dicom]` extra; `content_type=dicom` → `RawMessage` |
| DICOM C-STORE SCU + C-ECHO destination (outbound DIMSE) | ✅ | ADR 0025 Phase 2 (#478) — `DICOM()` outbound forward over `pynetdicom`, off-loop association; status→retry classification (context-rejected/unencodable/hard-refusal → dead-letter); `test_connection` = C-ECHO; DICOM-over-TLS client |
| DICOMweb STOW-RS destination (outbound HTTP) | ✅ | ADR 0025 Phase 2 (#478) — `DICOMweb()` store/send; stdlib sibling of `rest.py` (no new dep), `multipart/related` framing + `dicom+json` classification; `allowed_http` egress gate. Exceeds Mirth/Corepoint (neither ships DICOMweb) |
| DICOM — MWL / Query-Retrieve / DICOMweb retrieval / inbound STOW-RS / pixel data | ⛔ | Out of scope (ADR 0025): MWL owner-declined; C-FIND/C-MOVE/C-GET + QIDO/WADO + inbound STOW-RS receiver (needs ADR 0023) + pixel data all not built |
| MLLP-over-TLS | ✅ | Gate #4 (WP-13b) |
| REST-IN / SOAP-IN / FHIR-IN inbound HTTP-listener sources | ⏭️ | Destinations exist; inbound listeners deferred (FHIR server facade → ADR 0023) |
| MLLP persistent connection pooling | ⏭️ | Throughput optimization |

## 2. Routing & Handling (code-first)

| Feature | Status | Notes |
|---------|:--:|-------|
| `@router` / `@handler` / `Send` + `Registry` / `RegistryRunner` | ✅ | The wiring surface |
| `inbound()` / `outbound()` factories | ✅ | Same factories desugar `connections.toml` |
| `Message` (parsed HL7) + `RawMessage` (non-HL7) | ✅ | Handed to routers/handlers per content type |
| Reference sets (read-only lookup) | ✅ | ADR 0006 (#190) |
| `DatabaseRef` / live read-only external lookups in transforms | ✅ | ADR 0005/0006 (#191); owner-sanctioned hot-path read |
| `current_environment()` | ✅ | #192 |
| Dry-run (`dryrun`) | ✅ | Before/after diff; used by the IDE Test Bench |

## 3. Parsing & Validation

| Feature | Status | Notes |
|---------|:--:|-------|
| python-hl7 tolerant peek (hot path) | ✅ | Routing/filtering |
| hl7apy strict validation (opt-in per inbound) | ✅ | `validation.strict`; slow path, off routing |
| Parse-tree model + viewer | ✅ | Console + IDE render it |
| MSH-driven encoding-character awareness | ✅ | No hardcoded separators |
| FHIR codec (`parsing/fhir`: FhirPeek + FhirResource) | ✅ | ADR 0022 (#20) — `[fhir]` extra; JSON; R4B/R5/STU3; FHIRPath; pure/console-importable |
| X12 EDI tolerant codec (`parsing/x12`: X12Peek + X12Message + interchange splitter) | ✅ | ADR 0012 — on-demand against `RawMessage`; never pushed through the pipeline |
| Hardened `RawMessage.xml()` (defusedxml, XXE-safe) | ✅ | #31 / PR #422 — DOCTYPE / external-entity / billion-laughs **raise**, not parse |
| base64 binary-carriage codec (`parsing/binary`: `mfb64:v1:` + `RawMessage.from_bytes`/`.raw_bytes`/`.binary()`/`.is_binary`) | ✅ | ADR 0028 (#437) — NUL-safe arbitrary bytes over the str/TEXT ingress+store; HL7 OBX-5 ED embedding helpers; pure stdlib, no new dep |
| DICOM codec (`parsing/dicom`: DicomPeek + DicomDataset + SR→HL7 helpers) | ✅ | ADR 0025 Phase 1 (#439) — `[dicom]` extra (pydicom); headers + Structured Report only (no pixel data → no numpy); pure/console-importable; on-demand against `RawMessage` |

## 4. Pipeline & Reliability

| Feature | Status | Notes |
|---------|:--:|-------|
| Staged pipeline `ingress → routed → outbound` | ✅ | ADR 0001 Steps A+B |
| ACK-on-receipt + transactional stage handoff (at-least-once) | ✅ | Crash-safe, idempotent re-run |
| Disposition finalizer (single authority) | ✅ | RECEIVED/ROUTED/UNROUTED/PROCESSED/FILTERED/ERROR |
| `reset_stale_inflight` crash recovery (all stages) | ✅ | Lease-gated in cluster mode |
| FIFO-per-outbound ordering | ✅ | Ordering Phase 1 |
| Failure classification/policy (`NegativeAckError`, AR/CR fail-fast vs AE/CE retry) | ✅ | Per-connection overridable |
| Retry/backoff, dead-letter, **bulk replay** | ✅ | `/dead-letters` + CLI |
| Per-key / partition-key ordering lanes | ⏭️ | Single-feed scale path |
| `ack_after=delivered` (deferred ACK) | ⏭️ | Fail-closed at wiring today |

## 5. Message Store & Backends

| Feature | Status | Notes |
|---------|:--:|-------|
| SQLite (WAL) — default | ✅ | Single-node/dev; `synchronous=NORMAL` |
| PostgreSQL backend | ✅ | Production single-node; advisory-lock concurrency fixes; row leases |
| SQL Server backend | ✅ | Production: full staged pipeline + query/response (ADR 0001/0013) on a real SQL Server, CI-tested (store suite + load smoke) |
| Store abstraction (`Store` protocol / `open_store`) | ✅ | Single backend-selection seam |
| Encryption-at-rest (AES-256-GCM) + key rotation | ✅ (SQLite, PG, SQL Server) | |
| Retention / purge / maintenance | ✅ (SQLite, PG, SQL Server) | |
| SQLite → server-DB data migration | ⏭️ | v0.1 is **greenfield-only** (drain SQLite before cut-over) |
| MySQL / Oracle backends | 🧭 | Long-term |

## 6. High Availability

| Feature | Status | Notes |
|---------|:--:|-------|
| Cluster coordinator + `NullCoordinator` | ✅ | Track B Steps 3 |
| Leader election + leader-gated singletons | ✅ | Track B Step 4 |
| Leader-gated poll-source intake | ✅ | Track B Step 4b |
| Row leases + expiry-reclaim sweep | ✅ | Track B Step 2 |
| **Active-passive engine HA** (primary/failover) | ✅ | v0.1 HA model — leader-gates the whole graph; both PostgreSQL + SQL Server |
| Leadership lease + **self-fencing** (split-brain guard) | ✅ | The one core HA correctness item |
| `GET /cluster/status` | ✅ | Read-only observability for a cluster |
| **Active-active horizontal scale-out** (lane ownership, `renew_leases` heartbeat, cross-node FIFO) | — | **Dropped (2026-06-18) — code removed.** The active-active-specific code (per-lane ownership `lane_owner()`/`owns_lane()`, the `lane_leases` table, the `renew_leases` per-row heartbeat) was deleted and a `DROP TABLE IF EXISTS lane_leases` migration added. Not a planned milestone. Active-passive HA (above) is the supported HA model. |
| DB-tier HA (replication / Always On) | — | Delegated to the DB admins; not built by MF |

## 7. Security & Authentication

| Feature | Status | Notes |
|---------|:--:|-------|
| Local + Active Directory password authn (LDAP simple-bind) | ✅ | |
| Passwordless Windows SSO (Kerberos / SPNEGO) | ⏭️ | 0.2 — in-tree but experimental, off by default; needs CI coverage, full SPNEGO handshake, keytab/SPN preflight |
| RBAC — fixed roles, deny-by-default per-route, **per-channel** | ✅ | |
| Opaque sessions + full audit log (hash-chained, tamper-evident) | ✅ | |
| Encryption-at-rest for message bodies | ✅ | See §5 |
| API bind-guard (`serve --allow-insecure-bind`, fail-closed) | ✅ | |
| MLLP/inbound bind-guard | ✅ | Gate #4 — refuse non-loopback plaintext |
| Native API TLS (uvicorn) | ✅ | Gate #4 (WP-13a); HSTS already activates over https |
| MLLP-over-TLS | ✅ | Gate #4 (WP-13b) |
| Reverse-proxy TLS termination support (`trusted_proxies`) | ✅ | Offered alongside native TLS |
| TOTP MFA (local users) | ✅ | **Built (WP-14, ADR 0002 §3)** — RFC 6238 TOTP + single-use recovery codes for local accounts; `[auth].require_mfa` enforces it for the Administrator role at the step-up boundary. AD/Entra users' MFA stays delegated to the IdP. |
| Federated SSO — OAuth 2.0 / OIDC / SAML (Entra) | ⏭️ | 0.2 — admin browser SSO + service-to-service OAuth2; a dedicated federated-SSO ADR precedes the build |
| mTLS client/peer auth (console→API; MLLP partner) | ✅ | **Built (opt-in)** — the API requires a console client cert when `[api].tls_client_ca_file` is set (console presents `--client-cert`/`--client-key`); MLLP partner mTLS via the connection's `tls_ca_file`. Server-identity TLS stays the default; client certs are opt-in per the deploying org's PKI. |
| SMART Backend Services (FHIR **client** OAuth2) | ✅ | **ADR 0024 (Accepted) — #432.** OAuth2 `client_credentials` + signed-JWT `client_assertion` (`RS384`/`ES384`) authenticating the FHIR/REST **outbound** (ADR 0022) against real SMART-secured servers (Epic, Oracle Health). `with_smart_backend()` composer over `FHIR()`/`Rest()` extends the ADR 0018 signer; mints + expiry-caches a short-lived bearer, re-mints on 401, injects per request; token endpoint gated by `[egress].allowed_http`; secrets via `env()`; no new dependency. Client-only (App Launch / authZ-server out of lane → next row) |
| SMART App Launch / authorization server (FHIR **server** facade) | 🧭 | Out of an engine's lane / deferred — browser authorization-code + PKCE, EHR/standalone launch context, OIDC (`fhirUser`), scope **enforcement**, `.well-known/smart-configuration` publishing. Presupposes a human user (App Launch) or the system-of-record role (authZ/resource server); the latter also needs the unbuilt inbound FHIR facade (ADR 0023) |
| OWASP ASVS L3 posture | ✅ | Self-assessed against **Level 3** (345 reqs): **212 Pass / 0 Partial / 0 Fail / 133 N-A** — **0 open Partials and 0 open Fails; every control is built or documented-residual** (per [`ASVS-L3-ASSESSMENT.md`](security/ASVS-L3-ASSESSMENT.md) §2 — a *conditional-Pass-with-documented-residual* is scored Pass, not Partial; a point-in-time self-assessment, not a certification). Lineage: 155/40/9/141 at the L3 re-target → 178/20/6/141 (step-up WP-L3-16) → 186/21/5/133 (MFA WP-14) → 187/21/4/133 (admin defense WP-L3-13) → 192/20/0/133 (off-box log+audit #357/#363, closed 16.4.3 + 16.2.4) → **212/0/0/133** (partials sweep flipped the last 20 Partials — 18 L1+L2 + L3-only 12.3.5 intra-service mTLS & 15.2.5 runtime sandbox — to conditional Passes with explicit residual lines; heaviest residual = no hard in-process sandbox). Former Fails now built-with-residual: 4.1.5 opt-in detached-JWS signing #378; 12.1.4 VERIFY_X509_STRICT chains + org-PKI-delegated revocation #376; 13.3.3 operator-activated KeyProvider HSM/KMS/Vault seam #377. MFA (6.3.3), admin defense (8.4.2), off-box logs (16.4.3) all built |

## 8. PHI / Compliance

| Feature | Status | Notes |
|---------|:--:|-------|
| PHI-at-rest encryption + user-attributed PHI-access audit | ✅ | |
| python-hl7 PHI-logger silencing + control-char scrub filter | ✅ | Targeted, not a general redactor |
| **Full PHI log redaction** (chained-exception traceback scrubbing + proof test) | ✅ | **Gate #1** — safe to run above DEBUG with PHI |
| `serve` prod-DEBUG guard | ✅ | Gate #1 |
| structlog / JSON logs / off-box (SIEM) forwarding | ⏭️ | Gate #1 closes without structlog |
| De-identification framework (test harness + tee) | ✅ | ADR 0030 (#440) — `messagefoundry/anon/` (vendored byte-identical to `tee/anon/`); deterministic **secret-per-dataset** pseudonymization (width/shape-preserving), **field-anchored** site-code scrub, **fail-closed** leak gate (no un-scrubbed body ever emitted); `tee anonymize-captures` + harness hooks build PHI-free test datasets from real traffic; pure stdlib. Rules centralized — no inline ad-hoc de-id |

## 9. Observability & Alerting

| Feature | Status | Notes |
|---------|:--:|-------|
| Stats API + live WebSocket feed (`/ws/stats`) | ✅ | |
| AlertSink seam + `LoggingAlertSink` | ✅ | |
| Webhook + email notifier (`[alerts]`) | ✅ | #139 |
| `connection_stopped` + `queue_buildup` alerts | ✅ | Ordering Phase 1 Layer 4 |
| Load-test harness (profiles, governor, report/SLO verdict) | ✅ (PR #201) | Already caught a store concurrency bug (#200) |
| **Published throughput numbers + tuning baseline** | 🔨 | **Gate #3** — SQLite + PG + SQL Server + failover run |
| Metrics export (Prometheus/OpenTelemetry) | ✅ | #21 / PR #407 — `/metrics` exporter (`MONITORING_READ`-gated); `[otel]` extra |
| Alerts management page (console) | ✅ | #22 / PR #420 — read-only view over `GET /alerts/rules` (#22b / PR #415) |

## 10. Surfaces — Admin Console (PySide6)

| Feature | Status | Notes |
|---------|:--:|-------|
| Connection dashboard, message browser, parse-tree viewer | ✅ | |
| Delivery/audit trail + replay | ✅ | |
| Dead-letter list + replay (via API/CLI) | ✅ | Console **Dead Letters page** shipped — #22a / PR #413 |
| Cluster/leader status surface | 🔨 | Consumes `GET /cluster/status` |
| Off-thread API polling (no UI freeze on a slow node) | 🔨 | BACKLOG #2 / M-25 |
| Dead Letters page (list + replay) | ✅ | #22a / PR #413 |
| Alerts page (rules view over `GET /alerts/rules`) | ✅ | #22 / PR #420 |
| Multi-engine switcher | ⏭️ | CLI/API equivalents exist |

## 11. Surfaces — VS Code IDE

| Feature | Status | Notes |
|---------|:--:|-------|
| HL7 autocomplete (bundled hl7apy schema) + validate-on-save | ✅ | |
| Connections sidebar (filter/group) + Home authoring page | ✅ | |
| New Route Wizard (IB→Router→Handler→OB, one flow) | ✅ | |
| Test Bench (dry-run + before/after diff + debug step-through) | ✅ | |
| Stage → Promote to a running engine | ✅ | |
| `@messagefoundry` chat participant (provider-agnostic, PHI-safe) | ✅ | code + schema + graph only |
| `connections.toml` GUI editor | ✅ | ADR 0007 (#193) |
| Functional/runtime test harness | ⏭️ | BACKLOG #6 — build + type-check only today |

## 12. Config & Operations

| Feature | Status | Notes |
|---------|:--:|-------|
| Code-first wiring loader (`Registry`) | ✅ | Skips `_*` helper modules |
| `connections.toml` (config-as-data) + `connection` CLI | ✅ | ADR 0007 |
| Service settings — precedence CLI > env (`MEFOR_*`) > toml > default | ✅ | |
| Environments + deferred `env()` values (`environments/<env>.toml`) | ✅ | |
| Env-aware promote (dry-run pre-flight) | ✅ | |
| Config reload (`POST /config/reload`, allow-list-confined + audited) | ✅ | #85/#101 |
| CLI: `serve` / `check` / `generate` / `connection` | ✅ | |
| Synthetic HL7 generators (ADT, …) | ✅ | `messagefoundry generate`; corpus git-ignored |
| Windows service via NSSM | ✅ | docs/SERVICE.md |

## 13. Release & Distribution

| Feature | Status | Notes |
|---------|:--:|-------|
| AGPL-3.0 license + dual-licensing plan | ✅ | |
| Public OSS mirror + curated publish pipeline (forbidden-string/gitleaks gate) | ✅ | Owner runs the push (exfil guard) |
| CI: quartet (ruff/format/mypy/pytest) + security scans | ✅ | PG/SQL Server store jobs are service-container-gated |
| Version single-sourcing (drop the duplicate literal) | 🔨 | Workstream F |
| CHANGELOG.md + README roadmap refresh | 🔨 | Workstream F |
| `release.yml` — signed tag (Sigstore) + reproducible wheel/sdist + SBOM | 🔨 | Workstream F; per RELEASE-GATE.md |
| CLA activation / COMMERCIAL-LICENSE / NOTICE / SPDX headers | ⏭️ | Parallel legal track |

---

*Maintenance: update marks as features land. (`0.1.0` shipped 2026-06-18; **active-active scale-out was
dropped and its code removed** — see §6. **v0.2 wave on `main` (2026-06-19/20):** Prometheus `/metrics`
(#407), FHIR codec + REST destination (#416), console **Dead Letters** (#413) + **Alerts** (#420) pages,
`GET /alerts/rules` (#415), hardened `RawMessage.xml()` (#422), USER-GUIDE (#412); ADR 0021 §7
connection-error log + ADR 0026 update-check **Accepted**, on-trigger to build. **v0.3 connector wave on `main` (2026-06-20):** SMART Backend Services token provider (#432, ADR 0024), base64 binary-carriage codec (#437, ADR 0028), DICOM codec + C-STORE SCP Phase 1 (#439, ADR 0025), anonymizer / de-identification (#440, ADR 0030) — all four ADRs Accepted + shipped. **DICOM Phase 2 (#478, 2026-06-23):** outbound C-STORE SCU + C-ECHO + DICOMweb STOW-RS, completing ADR 0025.)*
