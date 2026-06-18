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
| Payload-agnostic ingress (`content_type` / `RawMessage`) | ✅ | ADR 0004 — non-HL7 bodies skip HL7 parsing |
| MLLP-over-TLS | ✅ | Gate #4 (WP-13b) |
| REST-IN / SOAP-IN inbound HTTP-listener sources | ⏭️ | Destinations exist; inbound listeners deferred |
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

## 6. High Availability & Scale-out

| Feature | Status | Notes |
|---------|:--:|-------|
| Cluster coordinator + `NullCoordinator` | ✅ | Track B Steps 3 |
| Leader election + leader-gated singletons | ✅ | Track B Step 4 |
| Leader-gated poll-source intake | ✅ | Track B Step 4b |
| Row leases + expiry-reclaim sweep | ✅ | Track B Step 2 |
| **Active-passive engine HA** (primary/failover) | ✅ | v0.1 HA model — leader-gates the whole graph; both PostgreSQL + SQL Server |
| Leadership lease + **self-fencing** (split-brain guard) | ✅ | The one core HA correctness item |
| `GET /cluster/status` | ✅ | Read-only observability for a cluster |
| **Active-active horizontal scale-out** (lane ownership, `renew_leases` heartbeat, cross-node FIFO) | ⏭️ | **0.2 headline**; code parked, run in active-passive mode for v0.1 |
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
| TOTP MFA (local users) | ⏭️ | 0.2 (WP-14); off-loopback v0.1 leans on AD/Entra IdP-MFA or an MFA-terminating proxy |
| Federated SSO — OAuth 2.0 / OIDC / SAML (Entra) | ⏭️ | 0.2 — admin browser SSO + service-to-service OAuth2; a dedicated federated-SSO ADR precedes the build |
| mTLS client/peer auth (console/IDE→API; MLLP partner) | ⏭️ | 0.2 — v0.1 native TLS is server-identity only |
| SMART on FHIR | 🧭 | Later — OAuth2 authZ profile for FHIR REST; needs a FHIR transport first (none today) |
| OWASP ASVS L3 posture | ✅ | Self-assessed against **Level 3** (345 reqs): **192 Pass / 20 Partial / 0 Fail / 133 N-A** (post-sec-offbox-log off-box log+audit forwarding #357/#363, which closed 16.4.3 + 16.2.4; was 187/21/4/133 after WP-L3-13 admin defense, 186/21/5/133 after WP-14 MFA, 178/20/6/141 after WP-L3-16 step-up, 155/40/9/141 at the re-target). 0 open Fails — the former three (4.1.5, 12.1.4, 13.3.3) are now built controls with documented residuals (4.1.5 opt-in detached-JWS outbound signing #378; 12.1.4 VERIFY_X509_STRICT chains + org-PKI-delegated revocation #376; 13.3.3 operator-activated KeyProvider HSM/KMS/Vault seam #377); MFA (6.3.3), admin defense (8.4.2) + off-box logs (16.4.3) are now built |

## 8. PHI / Compliance

| Feature | Status | Notes |
|---------|:--:|-------|
| PHI-at-rest encryption + user-attributed PHI-access audit | ✅ | |
| python-hl7 PHI-logger silencing + control-char scrub filter | ✅ | Targeted, not a general redactor |
| **Full PHI log redaction** (chained-exception traceback scrubbing + proof test) | ✅ | **Gate #1** — safe to run above DEBUG with PHI |
| `serve` prod-DEBUG guard | ✅ | Gate #1 |
| structlog / JSON logs / off-box (SIEM) forwarding | ⏭️ | Gate #1 closes without structlog |
| De-identification framework | 🧭 | Planned; centralize when built |

## 9. Observability & Alerting

| Feature | Status | Notes |
|---------|:--:|-------|
| Stats API + live WebSocket feed (`/ws/stats`) | ✅ | |
| AlertSink seam + `LoggingAlertSink` | ✅ | |
| Webhook + email notifier (`[alerts]`) | ✅ | #139 |
| `connection_stopped` + `queue_buildup` alerts | ✅ | Ordering Phase 1 Layer 4 |
| Load-test harness (profiles, governor, report/SLO verdict) | ✅ (PR #201) | Already caught a store concurrency bug (#200) |
| **Published throughput numbers + tuning baseline** | 🔨 | **Gate #3** — SQLite + PG + SQL Server + failover run |
| Metrics export (Prometheus/OpenTelemetry) | 🧭 | |
| Alerts management page (console) | ⏭️ | |

## 10. Surfaces — Admin Console (PySide6)

| Feature | Status | Notes |
|---------|:--:|-------|
| Connection dashboard, message browser, parse-tree viewer | ✅ | |
| Delivery/audit trail + replay | ✅ | |
| Dead-letter list + replay (via API/CLI) | ✅ | Console **Dead Letters page** is ⏭️ 0.2 |
| Cluster/leader status surface | 🔨 | Consumes `GET /cluster/status` |
| Off-thread API polling (no UI freeze on a slow node) | 🔨 | BACKLOG #2 / M-25 |
| Dead Letters page · Alerts page · multi-engine switcher | ⏭️ | CLI/API equivalents exist |

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

*Maintenance: update marks as features land. When `0.1.0` ships, flip its 🔨 rows to ✅ and promote
the 0.2 headline (active-active scale-out) per the [release plan](releases/v0.1-PLAN.md).*
