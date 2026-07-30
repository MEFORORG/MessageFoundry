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
`connections.toml` (ADR 0007). Engine = headless asyncio FastAPI service; the browser web console
(`/ui`) + VS Code IDE are separate surfaces over the localhost API.

---

## 1. Ingestion & Transports (Connections)

**Seventeen** connector types are registered today (`ConnectorType`,
[config/models.py](../messagefoundry/config/models.py)) — the `register_source` /
`register_destination` calls in [`transports/`](../messagefoundry/transports/) are the source of truth
for this table. This catalog does **not** grade competitors: a competitor claim appears only where it
is sourced, and the Mirth/NextGen Connect parity reference lives in
[CONNECTIONS.md](CONNECTIONS.md).

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
| DICOMweb STOW-RS destination (outbound HTTP) | ✅ | ADR 0025 Phase 2 (#478) — `DICOMweb()` store/send; stdlib sibling of `rest.py` (no new dep), `multipart/related` framing + `dicom+json` classification; `allowed_http` egress gate |
| DICOM — MWL / Query-Retrieve / DICOMweb retrieval / inbound STOW-RS / pixel data | ⛔ | Out of scope (ADR 0025): MWL owner-declined; C-FIND/C-MOVE/C-GET + QIDO/WADO + inbound STOW-RS receiver (an ADR 0023 HTTP-listener consumer — the listener is built, the receiver is not) + pixel data all not built |
| Inbound HTTP/1.1 listen source (`Http()`) | ✅ | ADR 0023 — a connector-owned `asyncio` socket in `transports/` (stdlib only, never a route in `api/`); `202 Accepted` the instant the body is committed to the ingress stage — the HTTP twin of ACK-on-receipt. Per-connection IP allowlist + inbound TLS + `max_connections` / `receive_timeout` / `max_body_bytes` caps; `GET`/`HEAD` answer a static non-PHI health response with no ingress row |
| Timer source (interval / cron) | ✅ | ADR 0011 — reads no external resource: each tick emits an operator-configured body. Leader-gated (a schedule is a shared trigger), stdlib 5-field cron evaluator with DST-correct wall-clock arithmetic |
| SMTP email destination | ✅ | ADR 0029 — stdlib `smtplib`; STARTTLS by default, cleartext credentials refused outright, `[egress].allowed_smtp` is the fail-closed host gate. No email *source* yet (IMAP/POP is Phase 2) |
| Direct-Project S/MIME-over-SMTP destination | ✅ | ADR 0085 PR1 — sign-then-encrypt to a per-partner recipient cert (core `cryptography` pkcs7, no new dep) over STARTTLS SMTP; `[egress].allowed_direct` gate; fail-loud at construction. Outbound only — inbound Direct mail, MDNs, DNS CERT / LDAP discovery and XDR/XDM are deferred |
| Internal inbounds — `Loopback()` + `PassThrough()` | ✅ | ADR 0013 — inert sources (no socket, no poll): a message arrives only via the internal handoff and is re-ingressed as a new inbound message with its own Router. `Loopback()` carries a captured reply (1:1); `PassThrough()` is the 1:N internal hop a Handler `Send`s into |
| MLLP-over-TLS | ✅ | Gate #4 (WP-13b) |
| SOAP-IN synchronous reply / FHIR-IN server facade | ⏭️ | The generic inbound HTTP listener above is built, so a partner can `POST` a JSON / XML / SOAP-envelope / FHIR body today and a Handler un-wraps it. Still deferred: the *synchronous* SOAP-envelope reply, routing on HTTP method/path/headers, on-socket request authentication (API key / bearer), and the inbound FHIR facade |
| MLLP persistent outbound connection (`persistent=true`) | ✅ | ADR 0067 — opt-in, **default off**: one lazily-established connection reused across deliveries (a single cached connection, **not** a pool), with a no-I/O liveness check before reuse plus idle/age caps. Removes the per-message handshake and its `TIME_WAIT` pressure; the default flips once the ADR 0067 §8 trigger is met |

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
| Parse-tree model + viewer | ✅ | The web console's message detail + the PySide6 test harness render it |
| MSH-driven encoding-character awareness | ✅ | No hardcoded separators |
| FHIR codec (`parsing/fhir`: FhirPeek + FhirResource) | ✅ | ADR 0022 (#20) — `[fhir]` extra; JSON; R4B/R5/STU3; FHIRPath; pure/client-importable |
| X12 EDI tolerant codec (`parsing/x12`: X12Peek + X12Message + interchange splitter) | ✅ | ADR 0012 — on-demand against `RawMessage`; never pushed through the pipeline |
| Hardened `RawMessage.xml()` (defusedxml, XXE-safe) | ✅ | #31 / PR #422 — DOCTYPE / external-entity / billion-laughs **raise**, not parse |
| base64 binary-carriage codec (`parsing/binary`: `mfb64:v1:` + `RawMessage.from_bytes`/`.raw_bytes`/`.binary()`/`.is_binary`) | ✅ | ADR 0028 (#437) — NUL-safe arbitrary bytes over the str/TEXT ingress+store; HL7 OBX-5 ED embedding helpers; pure stdlib, no new dep |
| DICOM codec (`parsing/dicom`: DicomPeek + DicomDataset + SR→HL7 helpers) | ✅ | ADR 0025 Phase 1 (#439) — `[dicom]` extra (pydicom); headers + Structured Report only (no pixel data → no numpy); pure/client-importable; on-demand against `RawMessage` |

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
| Passwordless Windows SSO (Kerberos / SPNEGO) | ✅ | **Browser SSO built (L5c, ADR 0068 §9 — experimental, off by default):** `GET /ui/sso` RFC 4559 challenge flow over the single-leg acceptor (Kerberos-only, no NTLM/multi-leg — any failure is an audited 303, never a challenge loop), one cookie session with `seed_reauth=False` (ambient proof ⇒ first sensitive action forces the directory-password step-up), boot-once keytab/SPN acceptor preflight degrading legibly (providers flag + login link + `e=sso_unavailable`). JSON `/auth/negotiate` unchanged. Mock-seam CI coverage; a domain-joined smoke is advised before recommending it (ADR 0068 open item) |
| RBAC — fixed roles, deny-by-default per-route, **per-channel** | ✅ | |
| Opaque sessions + full audit log (hash-chained, tamper-evident) | ✅ | |
| Encryption-at-rest for message bodies | ✅ | See §5 |
| API bind-guard (`serve --allow-insecure-bind`, fail-closed) | ✅ | |
| MLLP/inbound bind-guard | ✅ | Gate #4 — refuse non-loopback plaintext |
| Native API TLS (uvicorn) | ✅ | Gate #4 (WP-13a); HSTS already activates over https |
| MLLP-over-TLS | ✅ | Gate #4 (WP-13b) |
| Reverse-proxy TLS termination support (`trusted_proxies`) | ✅ | Offered alongside native TLS |
| TOTP MFA (local users) | ✅ | **Built (WP-14, ADR 0002 §3)** — RFC 6238 TOTP + single-use recovery codes for local accounts; `[auth].require_mfa` enforces it for the Administrator role at the step-up boundary. AD/Entra users' MFA stays delegated to the IdP. |
| WebAuthn/FIDO2 passkeys (local users, browser) | ✅ | **Built (WP-14b, ADR 0068 — web-console L5a)** — phishing-resistant second factor at the same step-up boundary via the optional `[webauthn]` extra (py_webauthn): browser-only ceremonies on `/ui` (enrollment behind the WP-14 password re-proof; the assertion satisfies the MFA leg only — the password leg keeps step-up freshness + the new-IP re-anchor); credential store across all 3 backends with sign-count CAS clone detection; RP identity rides `[api].public_origin` (fail-closed behind a declared proxy). TOTP stays the factor for non-browser clients (the JSON API's `/auth/mfa-verify` + `/me/mfa/*`, used by the PySide6 harness sign-in); AD users stay directory-delegated. |
| Browser ops console (`/ui`, zero-install web dashboard) | ✅ | **Built (ADR 0065 + 0068, #75 phases 1–4 + L5a/L5b + L6b)** — same-origin server-rendered ops console on the engine API: live monitoring/queues/connections, message search + raw/parse-tree views (single audited PHI path), replay/dead-letter ops behind the step-up-to-unlock primitive (per-connection + **all-channels** replay), config-deploy, full user/RBAC/AD-map admin, self-service account (password + TOTP + passkeys + **active-session management**), audit views, service-status badge, connection event log (**kind-filtered**), alerts, **per-connection stats reset**, and the **update-available** signal. Cookie confined to `/ui` (JSON API stays bearer-only), token-free CSRF (SameSite=Strict + Sec-Fetch-Site/Origin), strict CSP, off-loopback exposure behind the ADR 0068 startup ladder (TLS-or-refuse + `public_origin` binding + forced Secure/HSTS at declared exposure). Closed out at L6b with near-full parity against the desktop console, and it is now the **sole operator console**: the PySide6 desktop console was **retired** and `messagefoundry/console/` deleted (BACKLOG #103, ADR 0032 retired) — PySide6 backs only the standalone test harness. Two things it deliberately does not do: Windows service start/stop (the unprivileged tray service-manager, ADR 0113) and multi-engine switching (CLI/API-side). |
| Federated SSO — OIDC authorization-code + PKCE (Entra) | ✅ | **Built (ADR 0142) — default OFF, hybrid-only.** The two browser legs (`/ui/oidc/start`, `/ui/oidc/callback`) are declared only when `[auth].oidc_enabled` is set, so with federation off they are not in the route table at all. A federated login is a *login mechanism* for an identity that already exists in on-prem AD — the id_token is verified, then the username claim is resolved against AD, and **roles come from LDAP, never the token** — so `oidc_enabled` requires `ad_enabled`, an `[api].public_origin` (the redirect URI is derived from it), a client secret supplied by the environment or a `[secrets]` provider reference (never the config file), and https operator-pinned endpoints on a non-empty allow-list (no `.well-known` discovery). Each of those is refused **at load**, not at runtime. **SAML and service-to-service OAuth2 for the JSON API are not built.** |
| mTLS client/peer auth (API client→API; MLLP partner) | ✅ | **Built (opt-in)** — the API requires a client cert when `[api].tls_client_ca_file` is set (an API client presents one through the shared `apiclient`'s `tls_client_cert`/`tls_client_key`); MLLP partner mTLS via the connection's `tls_ca_file`. Server-identity TLS stays the default; client certs are opt-in per the deploying org's PKI. |
| SMART Backend Services (FHIR **client** OAuth2) | ✅ | **ADR 0024 (Accepted) — #432.** OAuth2 `client_credentials` + signed-JWT `client_assertion` (`RS384`/`ES384`) authenticating the FHIR/REST **outbound** (ADR 0022) against real SMART-secured servers (Epic, Oracle Health). `with_smart_backend()` composer over `FHIR()`/`Rest()` extends the ADR 0018 signer; mints + expiry-caches a short-lived bearer, re-mints on 401, injects per request; token endpoint gated by `[egress].allowed_http`; secrets via `env()`; no new dependency. Client-only (App Launch / authZ-server out of lane → next row) |
| SMART App Launch / authorization server (FHIR **server** facade) | 🧭 | Out of an engine's lane / deferred — browser authorization-code + PKCE, EHR/standalone launch context, OIDC (`fhirUser`), scope **enforcement**, `.well-known/smart-configuration` publishing. Presupposes a human user (App Launch) or the system-of-record role (authZ/resource server); the latter also needs the inbound FHIR facade, which is an ADR 0023 HTTP-listener consumer and is not built |
| OWASP ASVS L3 posture | ✅ | **A documented self-assessment against OWASP ASVS 5.0 Level 3 (345 requirements) exists, and every control is built or carries a documented residual.** **No pass/fail count is published here.** The scoring is under reconciliation (BACKLOG #310) and, by the project’s own rule, no figure is quotable until the final re-score lands — so quoting one here would be a claim we cannot stand behind. *(Earlier editions of this row quoted a four-figure count taken from a document that has since been marked **⛔ superseded as unreliable**: it reached zero Fails by introducing a “conditional Pass” — a verdict ASVS does not define — and scored strictly, that same source puts the shipped default posture materially lower. The figure and the link were removed 2026-07-25; the link also pointed into `docs/security/`, which is private and therefore absent from the public mirror.)* **Framing that must not be dropped:** this is a **point-in-time, AI-assisted self-assessment — not a certification, not an audit, and not an independent review**. There has been **no third-party assessment, no penetration test and no dynamic (DAST) testing** to date; that is a signed, dated standing risk acceptance which is **void on any off-loopback or production exposure**. The assessment set is maintained privately under `docs/security/` and can be made available to evaluators under NDA — see [`SECURITY-DOCS-POLICY.md`](SECURITY-DOCS-POLICY.md). |

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
| **Published throughput numbers + tuning baseline** | ✅ | **Gate #3** — [TUNING-BASELINE.md](benchmarks/TUNING-BASELINE.md) is the published, canonical record of what has been *measured*: SQLite + PostgreSQL + SQL Server + an active-passive failover profile, on a named reference config, under a two-tier gate (conformance = a hard blocker; performance = reported "as measured on config X"). Numbers there are not a guarantee for other hardware, and no target figure is a demonstrated one |
| Metrics export (Prometheus/OpenTelemetry) | ✅ | #21 / PR #407 — `/metrics` exporter (`MONITORING_READ`-gated); `[otel]` extra |
| Alerts management page (web console) | ✅ | Active instances (ack / resolve / windowed suspend, #143) + the loaded rules over `GET /alerts/rules` (#22b / PR #415) |

## 10. Surfaces — Operator console (browser, `/ui`) + the PySide6 harness

The **sole operator console** is the browser web console served same-origin at `/ui` by the engine's
own FastAPI app (`messagefoundry_webconsole`, ADR 0065) — the row in §7 carries its security posture.
The PySide6 **desktop console was retired** and `messagefoundry/console/` deleted (BACKLOG #103, ADR
0032 retired); PySide6 now backs only the standalone test harness (`harness/`, the `[harness]` extra).

| Feature | Status | Notes |
|---------|:--:|-------|
| Connection dashboard, message log, parse-tree viewer | ✅ | Raw + parse-tree views are the single audited PHI path |
| Delivery/audit trail + per-message replay | ✅ | On the audited message-detail page |
| Dead-letter list + bulk replay | ✅ | Per-connection, per-destination, and all-channels replay — step-up-gated |
| Alerts page (instances + loaded rules) | ✅ | Ack / resolve / windowed notification suspend (#143) |
| Cluster/leader status surface | ✅ | Engine-status page renders `GET /cluster/status` (role, clustered, is-leader, node id) |
| User/RBAC/AD-map admin + self-service account | ✅ | Body-carrying admin forms behind step-up-to-unlock; account = password + TOTP + passkeys + active sessions |
| Multi-engine switcher | ⏭️ | CLI/API equivalents exist |
| Windows service start/stop from a desktop surface | ✅ | The tokenless notification-area **tray service-manager** (ADR 0113, `messagefoundry-tray`) — deliberately not a second console: it reads only the SCM state + `GET /health` and deep-links to `/ui` |
| PySide6 **test harness** (send/receive/load/failover + Monitor tab) | ✅ | `harness/` — a separate process over the `apiclient` HTTP client; background poll off the GUI thread; reuses the view widgets rehomed from the retired console |

## 11. Surfaces — VS Code IDE

| Feature | Status | Notes |
|---------|:--:|-------|
| HL7 autocomplete (bundled hl7apy 2.5.1 schema) + validate-on-save | ✅ | `media/hl7schema.json` is generated ahead of time from `messagefoundry hl7schema`, so there is no per-keystroke Python; a Python save coalesces into one validate + graph + code-set refresh |
| Components sidebar — element / flow perspectives, filter + group | ✅ | The wired graph from `messagefoundry graph`; **Toggle Element / Flow View**, **Filter / Group Components**, Refresh |
| Translation Tables sidebar + CSV grid editor | ✅ | The code sets under `codesets/` (via `messagefoundry codeset`); New / Edit / Rename / Delete / Refresh, a CSV grid form editor (TOML-authored sets stay read-only) |
| Home authoring page (webview launchpad) | ✅ | Wizards / test & data / operate / setup actions in one panel |
| Wizards — Route, Connection, Router, Handler, Alert | ✅ | Route = IB→Router→Handler→OB in one flow; Connection also has a keyboard-only variant; Alert edits the service TOML's `[[alerts.rules]]` (ADR 0014) |
| Test Bench (dry-run + before/after diff + debug step-through) | ✅ | |
| Live Debug — annotate the code on save from a synthetic dry-run | ✅ | Disposition summary + per-line values; message-derived values **redacted by default** behind a separate *Reveal Values* toggle, synthetic samples only, never a real engine; debounced (`liveDebug.debounceMs`) |
| Steps view over a Handler `.py` | ✅ | ADR 0076 — a custom editor over the *real* Python via `messagefoundry lens parse` / `lens rewrite`; plain `.py` stays the only artifact and the only execution path |
| Wiring Map (read-only graph panel) | ✅ | Open from the Components title bar or *Show in Wiring Map*; no drag-drop and no editing of any kind |
| Insert Element + scaffold snippets + Cookbook | ✅ | `Ctrl+Alt+I` / `Cmd+Alt+I`, the bundled Python snippet set, and a searchable gallery of solved problems — each drops real, editable Python |
| Stage → Promote to a running engine | ✅ | `engineUrl` / `environments` (and an environment's engine instances) are **machine-scoped**, so a checked-in `.vscode/settings.json` cannot retarget a promote — and the credentials it carries — at another host |
| Engine status pill — sign in/out, re-check, log, open `/ui`, copy start command | ✅ | Reachability only; operating the engine belongs to the web console it deep-links to |
| Start / Stop / Restart a **local** engine + Python-env / engine setup | ✅ | ADR 0112 — offered for a local, loopback target in a trusted workspace |
| Opt-in live status + count decorations on connection rows | ✅ | `liveStatus.enabled` / `intervalSeconds` (≥5s) — polls `GET /connections` for status words and counts only, never message content |
| `connections.toml` GUI editor | ✅ | ADR 0007 (#193) — a custom editor over `**/connections.toml` |
| Security-settings editor, Generate Samples, version-control setup | ✅ | `[security]` posture switches via `messagefoundry security`; a synthetic corpus via `messagefoundry generate`; a guided git + commit-time `messagefoundry check` setup (`sourceControl.autoPrompt`) |
| `@messagefoundry` chat participant (provider-agnostic, PHI-safe) | ✅ | code + schema + graph only — `/explain`, `/transform`, `/router`, `/review`, `/migrate`, `/test`; `ai.contextCharLimit` bounds the editor code attached (`0` = graph names only), and *Show AI Policy* prints the governing policy |
| Getting-started walkthrough (9 cards) | ✅ | Engine target → config dir → Connection → Route → Insert Element → Test Bench → Live Debug → Cookbook → Stage → Promote |
| Untrusted-workspace limited mode | ✅ | `untrustedWorkspaces: limited` — the workspace Python CLI is not auto-run (validate / graph / codeset / promote disabled) until the workspace is trusted |
| Functional/runtime test harness | ✅ | BACKLOG #6 (DONE) — `@vscode/test-electron` + mocha headless harness; ubuntu + windows `ide` CI legs (#351) |

## 12. Config & Operations

| Feature | Status | Notes |
|---------|:--:|-------|
| Code-first wiring loader (`Registry`) | ✅ | Skips `_*` helper modules |
| `connections.toml` (config-as-data) + `connection` CLI | ✅ | ADR 0007 |
| Service settings — precedence CLI > env (`MEFOR_*`) > toml > default | ✅ | |
| Environments + deferred `env()` values (`environments/<env>.toml`) | ✅ | |
| Env-aware promote (dry-run pre-flight) | ✅ | |
| Config reload (`POST /config/reload`, allow-list-confined + audited) | ✅ | #85/#101 |
| CLI — 30 subcommands | ✅ | Run/author (`serve`, `supervise`, `init`, `import`, `validate`, `graph`, `dryrun`, `check`, `impact`, `connection`, `codeset`, `alert`, `security`, `generate`, `lens`, `hl7schema`, `hl7structures`, `adr-analyze`, `ai-policy`) + operate (`backup`, `restore-verify`, `rotate-key`, `rekey-audit`, `audit-verify`, `gen-key`, `protect-key`, `cert`, `verify`, `support-bundle`, `service`) — `_DISPATCH` in `__main__.py` is the registry |
| Synthetic HL7 generators (ADT, …) | ✅ | `messagefoundry generate`; corpus git-ignored |
| Windows service via NSSM | ✅ | docs/SERVICE.md |

## 13. Release & Distribution

| Feature | Status | Notes |
|---------|:--:|-------|
| AGPL-3.0 license + dual-licensing plan | ✅ | |
| Customer/PHI leak gate — forbidden-string + gitleaks, on every commit and in CI | ✅ | Fails closed with no token source |
| CI: quartet (ruff/format/mypy/pytest) + security scans | ✅ | PG/SQL Server store jobs are service-container-gated |
| Version single-sourcing (drop the duplicate literal) | ✅ | Workstream F — `pyproject.toml` declares `version` `dynamic` and `[tool.hatch.version]` reads `__version__` from `messagefoundry/__init__.py` |
| CHANGELOG.md + README roadmap refresh | ✅ | Workstream F — a Keep-a-Changelog `CHANGELOG.md` at the repo root, linked from the README |
| `release.yml` — signed tag (Sigstore) + wheel/sdist + SBOM | ✅ | Workstream F — on a `vX.Y.Z` tag the workflow builds the wheel + sdist, generates a CycloneDX SBOM from the hash-locked core runtime (ships an OpenVEX alongside it), Sigstore-signs, writes an `actions/attest-build-provenance` SLSA attestation, and publishes to PyPI via Trusted Publishing |
| CLA activation / COMMERCIAL-LICENSE / NOTICE / SPDX headers | ⏭️ | Parallel legal track |

---

*Maintenance: update marks as features land. (`0.1.0` shipped 2026-06-18; **active-active scale-out was
dropped and its code removed** — see §6. **v0.2 wave on `main` (2026-06-19/20):** Prometheus `/metrics`
(#407), FHIR codec + REST destination (#416), desktop-console **Dead Letters** (#413) + **Alerts** (#420)
pages (that console has since been retired — §10),
`GET /alerts/rules` (#415), hardened `RawMessage.xml()` (#422), USER-GUIDE (#412); ADR 0021 §7
connection-error log + ADR 0026 update-check **Accepted**, on-trigger to build. **v0.3 connector wave on `main` (2026-06-20):** SMART Backend Services token provider (#432, ADR 0024), base64 binary-carriage codec (#437, ADR 0028), DICOM codec + C-STORE SCP Phase 1 (#439, ADR 0025), anonymizer / de-identification (#440, ADR 0030) — all four ADRs Accepted + shipped. **DICOM Phase 2 (#478, 2026-06-23):** outbound C-STORE SCU + C-ECHO + DICOMweb STOW-RS, completing ADR 0025.)*
