[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 8. Engine HTTP/WebSocket API

**ID prefix:** `API` · **Surface:** engine (consumed by web console, IDE, tray, harness, CLI)
· **Primary risk:** the JSON/WS wire contract is unpinned — 121 Pydantic models back 105 route
objects, only 49 model *field-name* sets are snapshotted, so a rename, retype or optionality flip
ships green and breaks `apiclient`, the IDE's hand-mirrored TS interfaces, the tray probe and the
harness at runtime, with no failing test on either side.

### 8.1 Scope & objectives

This chapter covers the single FastAPI application built by
`create_app()` / `create_managed_app()` ([`messagefoundry/api/app.py:1018`](../../../messagefoundry/api/app.py),
`:5156`) — verified live at **105 route objects** (104 `APIRoute` + the `/ws/stats`
`APIWebSocketRoute`; 67 declared in `api/app.py`, 38 in `api/auth_routes.py`), **109** with
`expose_docs=True`, **203** with `serve_ui=True`.

In scope:

- **Route surface + wire contract.** Every path, method, status code and response model; the 121
  Pydantic models (`api/models.py` 89 + `api/auth_models.py` 32); OpenAPI drift; cross-language
  mirrors (`apiclient/client.py`, the IDE's TypeScript DTOs, the tray's `/health` key literal).
- **Deny-by-default authorization plumbing** as it is *enforced on the wire*: the nine factories in
  [`api/security.py`](../../../messagefoundry/api/security.py) — `require` (:182), `require_paced` (:250),
  `require_service_cert` (:430), `require_phi_read` (:504), `require_step_up` (:569),
  `require_reauth_only` (:609), `require_step_up_action` (:651), `require_reauth_only_action` (:694),
  `authorize_ws` (:768) — plus `enforce_phi_read_hop` (:480), `enforce_phi_read_pacing` (:523),
  `_enforce_admin_write_pacing` (:549) and field-level redaction (`api/field_authz.py`).
- **Error handling and status codes:** the catch-all 500 and PHI-safe 422 handlers
  (`api/app.py:1195-1221`), 405/411/413/400 framing refusals (`:1279-1333`), 503 fail-closed paths.
- **Read plane:** `/messages` filters + `limit`/`offset` + `total`, `/messages/{id}`, `/responses`,
  `/outbound`, attachment download, content search (ADR 0046), bulk NDJSON export (ADR 0131),
  saved + layered presets (ADR 0136), uploaded-logs viewer (ADR 0134), log level + tail (ADR 0130).
- **`/ws/stats`** lifecycle: auth (cookie hook OR bearer), Origin allow-list, the 64-socket cap and
  `ws_count` hygiene (`api/app.py:319-320`, `:4846`, `:4854`, `:4918-4919`), 3 s revalidation,
  frame-key contract, backpressure.
- **Exposure controls:** tokenless `/health`, `/metrics` gating, `expose_docs`, the serve bind ladder
  (`messagefoundry/__main__.py:1523-1610`), in-process TLS vs `tls_terminated_upstream` +
  `trusted_proxies`, `[security].allowed_client_networks` (ADR 0151), middleware order, rate limits.
- **`apiclient` parity** with the live route table (ADR 0088).

**Explicitly NOT in scope here — owned elsewhere, cited not restated:**

| Out of scope | Owner |
|---|---|
| The `/ui` console plane itself (97 routes + the `/ui/static` mount when `serve_ui=True`): rendering, nonce-CSP, `SameSite=Strict` cookie confinement, `Sec-Fetch-Site` CSRF, WebAuthn ceremonies, page-level RBAC | FEATURE-COVERAGE-PLAN.md §23 `[UI]` (`FCP:UI-1`…`FCP:UI-31`) and `FCP:API-27`; the master plan's web-console chapter. This chapter tests only the *middleware and app-level* properties that ride the same app. |
| Auth mechanics behind the gates — password hashing, TOTP/passkey enrolment, session lifetime, AD/Kerberos/OIDC login, custom-role CRUD semantics | FEATURE-COVERAGE-PLAN.md §13 `[AUTHN]`, §14 `[RBAC]`; `FCP:API-3`/`FCP:API-4` note the overlap. This chapter tests *route-level enforcement*, not the auth engine. |
| Store method behaviour (`list_messages`, `search_messages`, `record_audit`, `list_search_presets`) | FEATURE-COVERAGE-PLAN.md §9 `[STORE]`, §10 `[STOREF]`. This chapter tests those methods **as reached through a route**, which is the untested composition. |
| The inbound HTTP body-POST **Connection** (`transports/http_listener.py`, ADR 0023) — it is a data-plane Connection, not the operator API | FEATURE-COVERAGE-PLAN.md `FCP:API-18` (its DoS-soak gap is that row's). |
| Outbound HTTP auth (`transports/http_auth.py`) | FEATURE-COVERAGE-PLAN.md `FCP:API-29` / §5 `[HTTPFHIR]`. |
| On-host bind + unauthenticated-reject posture under the NSSM service identity | WIN2025-TEST-PLAN.md **`W25:S2.8`** (:492-509) and MANUAL row **`W25:S1.AC-API`** (:314). Re-run, do not re-author. |
| Pipeline/store load profiles | docs/LOAD-TESTING.md. This chapter adds an *API-layer* profile that reuses the same runner. |

**Objectives.** (1) Pin the wire contract so a breaking change cannot ship green. (2) Prove every
route behaves identically on SQLite, SQL Server and PostgreSQL. (3) Prove the framing/DoS defences on
a real socket, not a synthesized ASGI scope. (4) Prove deny-by-default holds for *all* 105 routes by
execution, not only by structural introspection. (5) Close the eight 2026-07 API surfaces that no
test-plan artifact currently owns. (6) Produce the first API-layer latency/throughput numbers.

### 8.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `tests/test_security_doc_drift.py` (1723 lines, 40 tests) | Route→permission→gate map drift, derived from the **live** app: exact counts (`_ROUTES_DEFAULT=105`, `_ROUTES_WITH_DOCS=109`, `_ROUTES_WITH_UI=203`), the 5 no-gate + 13 permissionless allowlists, the 87 gated count, the multi-permission set (`GET /messages/export`, `GET /ui/alerts`), gate-wrapper counts, the `/ui` route map, the `/ui/static` sole-mount posture, `PHI_FIELDS` ↔ doc table in both directions, and three planted-mutation self-tests (:831, :1297, :1434). |
| `tests/test_api.py` (909 lines) | 405 on wrong method, query-param pollution last-wins still validated (422), param length caps, docs off/on, messages list + filters + pagination shape, detail/outbound/audit-no-body, replay + 409, dead letters, connections rows, `/stats`, `/status` KPIs + log metering, integrity check, cluster status/nodes, engine-not-started 503, one `/ws/stats` push. |
| `tests/test_api_auth.py` (1402 lines) | Unauthenticated reject + `/health` open, login→permission enforced, PHI raw view requires operator, `view_raw` on outbound payloads, audit query/CSV export + formula-injection neutralization, admin-write pacing (429 + `Retry-After: 1`, NON-GET only) incl. headroom/shared-bucket/limiter-disabled parity, PHI-read throttle (429 + `Retry-After: 10`) per-actor across endpoints, session list/revoke, AD group mapping, disabled-auth fail-closed, posture gating, ADR 0150 `client=` on audit rows. |
| `tests/test_api_tls.py` (1300 lines) | SSL-context build (1.2/1.3 floor, encrypted key, mTLS), serve-path bind decisions with/without TLS and upstream terminator, `trusted_proxies` validation, cert→principal mapping incl. CN-cannot-collide-with-SAN, deny-by-default cert identity, `require_service_cert` PHI refusal *at construction*, `GET /service/identity` via cert, cert cannot bypass PHI/step-up routes, `service_cert_auth` audit, cert-expiry alerting, KEX allow-list, one real mutual-TLS handshake on the built context. |
| `tests/test_client_network_allowlist.py` (725 lines) | ADR 0151 end-to-end: empty = no-op, R1/R2/R3 topologies, forwarding headers never consulted, self-spoof defeated by uvicorn's reverse walk, loopback carve-out, IPv6/v4-mapped, unparseable client fails closed, denial headers + HTML page, denial precedes authn/authz, `/ui/static` covered, `/health` reachable + echoes `observed_client`, posture counters, per-address log rate limit, WS closed pre-accept, gate stays outermost with the console mounted, not a `BaseHTTPMiddleware`, lifespan passthrough. |
| `tests/test_no_store_phi_coverage.py` | ASVS 14.2.2 meta-guard: derives the PHI-read route set from the live app and asserts each is matched by a `_NO_STORE_PREFIXES` entry (`api/app.py:331`), pinning the expected set so a vacuous predicate fails. |
| `tests/test_attachment_download_api.py` (457) | Attachment metadata + byte round-trip, view+download audit **before** return, never logs bytes, active-MIME downgrade to `octet-stream`, overlong-label downgrade, sandbox CSP on both the JSON route and the `/ui` delegate, 404 for unknown/unlinked/out-of-scope. |
| `tests/test_content_search.py` (380) | ADR 0046: `make_spec` validation/clamping, substring + field-path matching, unparseable body = no match, encrypted-store parity, metadata pre-filter bounds the scan, scan cap truncates, result cap, scan off the event loop, no decrypt leak in logs, step-up required, redaction, audit records needle **shape** not value, 400 on bad request. |
| `tests/test_message_export.py` (294) | ADR 0131: distinct `messages:export` capability, step-up required, denied without it, 400 with no selection, save-all streams decrypted bodies, save-selected by ids, per-row scope skips out-of-scope ids, audit counts every body, charges the PHI-read budget, throttled-at-admission writes no audit and streams nothing. |
| `tests/test_upload_api.py` (477) + `tests/test_uploads.py` | ADR 0134: 503 when `[store].uploads_dir` unset, upload/list/browse round-trip, viewer denied, extension + content/extension mismatch rejects, 415 binary container / NUL body, 409 over quota + audit, path-traversal 404 on browse and delete, delete audit, resend injects via `store.enqueue_ingress` (not `reingress`), unknown/not-running inbound, browse requires step-up and audits needle shape. |
| `tests/test_search_presets_api.py` (189) + `tests/test_search_presets.py` | ADR 0136: preset CRUD + owner scoping, layered compose + conflict 400s, layered requires `messages:read`, store-level encryption of `criteria` at rest (SQLite). |
| `tests/test_logging_surfaces.py` (258) | ADR 0130: `GET`/`PATCH /logging/level` (effective vs configured, bad level 400, denied without `monitoring:diagnose`, audited); `/logs/tail` redacts + audits + pages from the end + degrades with no `log_dir` + denied without `logs:view`. |
| `tests/test_ws_stats_revalidation.py` (155) | SEC-018: revoked session closed promptly, disabled account closed, revocation before first send yields zero frames — through the real ASGI route on an in-memory websocket peer. |
| `tests/test_asvs_phase0.py:94-109` | `_ws_origin_allowed` unit table: no Origin (native) allowed; any browser Origin rejected with an empty allow-list; exact match required. |
| `tests/test_auth_hardening.py:554-627, :780` | `authorize_ws` permission denial + denial/grant audit rows for `/ws/stats`; `MONITORING_READ` excluded from the default grant-audit set, included under `audit_all_authz`. |
| `tests/test_metrics_exporter.py` | `/metrics` parseable exposition, never leaks PHI, latency histogram cumulative counts + negative clamp, pool-saturation gauges, store cost counters, gated by `monitoring:read`, OTel seam records without PHI. |
| `tests/test_metrics_history_graph.py` | `/metrics/history` ring dedupe on min-interval, oldest-first + capacity; `/graph/edges` node/edge derivation. |
| `tests/test_api_health_tokenless.py` | `/health` answers 200 with no `Authorization` header and stays open while every `require()` route is locked. |
| `tests/test_api_reload.py`, `test_dual_control_reload.py`, `test_approvals.py` | Reload root confinement (403/404/422), dry-run + missing-env 422, invalid-config 422, empty-dir 422; dual-control hold → distinct approver → audited; approvals list/approve/reject, no self-approve. |
| `tests/test_channel_rbac.py` | Per-channel scope on the operational + graph routes, incl. `/graph/edges` shared-outbound dropping and `/connections/{name}/test-credential`. |
| `tests/test_field_authz_enforcement_sites.py` + `test_security_doc_drift.py:1278-1387` | `PHI_FIELDS` equals the documented table both ways; mapped models have no ungated field outside the reviewed list; message-family models are mapped or reviewed PHI-free; enforcement sites are the expected set (incl. `/search/layered`). |
| `tests/test_webconsole_seam_snapshot.py` + `tests/golden/webconsole_seam.snapshot` (192 lines) | `ENGINE_UI_SEAM` integer (=15), `UiDeps`/`CoreHandlers`/`AdminHandlers` field names, curated `api.security` dep signatures + `AuthService` methods + `app.state` attrs, and the **field-name sets** of the 49 DTOs the console renders. |
| `tests/test_apiclient.py` (126) | Public re-export, import pulls in no PySide6/FastAPI (subprocess-verified), remote-plaintext transport guard, non-2xx→`ApiError`, bad-body decode→`ApiError`, path-length bounds match the transport constants. |
| `tests/test_dependency_boundaries.py` | One-way import direction (`transports`/`pipeline`/`store`/`config` never import `api/`) and `import messagefoundry.api` does not eagerly pull FastAPI (PEP 562 lazy export, `api/__init__.py:18`). |
| `tests/test_security_doc_rate_limits.py` | Every rate-limit setting is documented and contextual thresholds match shipped defaults (covers the PHI-read, admin-write and login limiters gating the API). |
| `tests/test_api_alerts.py`, `test_alerts_rules_api.py`, `test_alerts_test_email.py`, `test_connection_api.py`, `test_connection_event_api.py`, `test_connection_event_scope.py`, `test_dr_api_status.py`, `test_dr_rbac.py`, `test_resend.py`, `test_edit_resend.py`, `test_step_up.py`, `test_admin_new_ip.py`, `test_mfa_access_gate.py`, `test_custom_roles.py`, `test_last_admin_guard.py`, `test_api_security_posture.py` | The per-family functional + authorization behaviour of alerts, connection control/events, DR, resend/edit-resend, step-up windows and action-bound grants, new-client-IP re-anchoring, the ASVS 6.3.3 access-gate exemptions, custom-role authorization, last-admin protection, and `GET /security/posture`. |
| `.github/workflows/ci.yml:217-230` and `:245-254` | The whole `tests/` suite runs on `ubuntu-latest` + `windows-2022` + `windows-2025`, Python 3.14, `pytest-timeout` 60/120 s and a faulthandler watchdog; the web-console suite runs as a second step on the same leg. |
| FEATURE-COVERAGE-PLAN.md §15 `[API]`, rows `FCP:API-1`…`FCP:API-29` (:1127-1173) | **Owns** the pre-2026-07 API surface audit: route contract, bind/TLS/mTLS, reload confinement + dual control, alerts, resend/edit-resend, connection events, cluster, `/ws/stats`, `/metrics`, `apiclient`, layer guard. It already names its own open gaps: `FCP:API-13`/`FCP:API-14` (PG + SQL Server parity CI-only), `FCP:API-18` (listener DoS soak), and "no API-layer performance/load test exists anywhere". |
| WIN2025-TEST-PLAN.md **`W25:S2.8`** (:492-509) + MANUAL **`W25:S1.AC-API`** (:314) + the auth note at :327 | **Owns** the on-host posture check: loopback bind confirmed via `Get-NetTCPConnection -LocalPort 8765`, unauthenticated call → 401/403, authenticated → 200, under the NSSM service identity; and the requirement that every headless harness run passes `--token` against an auth-on engine. |
| docs/SECURITY.md §"Route → permission map (engine API)" (:294-500) | The authoritative per-route gate/permission documentation the drift guard enforces. |

**Done — do not re-plan.** Route→permission→gate structural drift; the gate factories' *unit*
semantics; PHI-read throttle and admin-write pacing behaviour; the TLS/mTLS context construction and
cert→identity mapping; `allowed_client_networks` topology matrix; `_NO_STORE_PREFIXES` coverage;
attachment download semantics and its sandbox CSP; content-search caps/redaction/audit-shape; export
capability + per-row scope + audit-before-stream; upload validation/quota/traversal/resend-path;
preset CRUD + owner scoping + layered conflicts; log level/tail redaction and gating; `/ws/stats`
session revalidation and the origin *predicate*; the `/metrics` exposition contents; reload
confinement + dual control; the webconsole seam snapshot for the 49 console-rendered DTOs. Every row
below is either a genuinely uncovered property, the same property on a backend or transport it has
never run on, or a measurement that has never been taken.

### 8.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| Wire contract unpinned for ~72 of 121 models | A field rename/retype/optionality flip on `UploadedFileInfo`, `SearchPresetList`, `LogTailPage`, `ResendResult`, `EditResendResult`, `ConnectionMetadata`, `AiPolicy`, `Health`, `StatsResponse`, `ApprovalList`, `MessageResponses`, `OutboundPayloads`… ships green | Every non-console consumer: `apiclient` (harness load/scenario/failover runners, service CLI), the IDE extension, the tray. Runtime `ApiError`/silent wrong render at the customer, not in CI | **No** — the seam snapshot pins field *names* for the 49 console-rendered DTOs only, and no types, optionality, path, method or status code | **P0** |
| No route ever runs against SQL Server or PostgreSQL | `create_app` appears in **zero** test that sets `MEFOR_TEST_SQLSERVER`/`MEFOR_TEST_POSTGRES` (verified by cross-grep). A backend divergence in `list_messages` + `count_messages` composition, `search_messages` truncation, `record_audit` with the ADR 0150 `client` column on `NVARCHAR(256)`, preset listing, dead-letter paging or audit filters surfaces first in production | Wrong/missing clinical rows on an operator read; a 500 on the console; an audit write that silently fails on the one backend a hospital runs | **No** | **P0** |
| Framing/DoS defences never tested on a real socket | Every API test uses `httpx.ASGITransport`/`TestClient` with headers httpx synthesized (`tests/test_api.py:88-105`). The CL.TE 400, chunked-411, invalid-CL 400 and 1 MiB/`max_upload_bytes` 413 (`api/app.py:1279-1333`) are asserted against fabricated scopes; h11's own limits, keep-alive, real chunked decoding and slow-loris behaviour are unexercised | A pre-auth memory/connection DoS, or a desync between a front proxy and h11, that CI cannot see. ADR 0092 already records "a full uvicorn-on-a-real-socket handshake through the live serve bind" as a deferred residual | **No** | **P1** |
| Deny-by-default proven structurally, not by execution | `test_security_doc_drift.py` reads the dependency graph. A route whose handler answers before its dependency is reached, a middleware short-circuit, a hand-registered Starlette route, or a closure shape that makes `_gate_of` return `None` while the allowlist is updated to match, all pass | Unauthenticated read of PHI or an admin write. Silent | Partially — spot checks only (`test_api_auth.py:97`, `:301`) | **P1** |
| `/ws/stats` cap and `ws_count` hygiene untested behaviourally | The 64-cap is asserted only as a **constant** (`test_threat_model_doc_drift.py:573`). Nothing proves the 65th handshake is refused, nor that `state.ws_count` returns to 0 on every exit path (`api/app.py:4846`, `:4854`, `:4918-4919`). Note the cap is checked *before* `accept()` and incremented *after* — a TOCTOU window and a Starlette pre-accept-close that surfaces as a rejected handshake, not a 1013 frame | A leaked counter permanently refuses every future console socket estate-wide; the live monitor dies silently and the 5 s poll fallback masks it | **No** | **P1** |
| `apiclient` ↔ live-route parity unenforced | `apiclient/client.py` references **49 distinct paths** (57 of the 105 route objects); **44 distinct paths have no client method at all** (uploads, presets, export, metrics, logs, DR, approvals, graph, posture, resend/edit-resend, attachments, `/ai/*`, `/service/*`, `/audit/export`…). Nothing asserts the 49 still resolve, nor that each `_decode(..., Model)` matches the route's declared `response_model` | A route rename turns a client call into a runtime 404 for the service CLI, the harness runners and every embedder — green suite | **No** | **P1** |
| IDE mirrors engine DTOs in TypeScript by hand | `ReloadResult` (`ide/src/promote.ts:20-21`), `ConnectionRowLite` (`ide/src/liveStatusModel.ts:13`), `HealthBody` (`ide/src/engineStatusModel.ts:255-258`). The tray likewise keys on the literal `"status"` in the `/health` body (`messagefoundry/tray/probe.py:62`) | A rename on `ReloadResult` makes VS Code "promote" report a wrong/empty deploy result — the operator believes config deployed when it did not. No failing test in either the Python or the Node leg | **No** | **P1** |
| 500 and 422 handlers untested at the app level | No test forces an unhandled exception and asserts the body is exactly `{"detail":"internal error"}` with no stack; only `test_edit_resend.py:437` covers the 422 `input`/`ctx` stripping, on one route | These are the last line before a PHI fragment or internal path reaches a client or a proxy access log (ASVS 16.5.1). A `debug=True`, a middleware reorder, or a re-registered default handler restores FastAPI's verbose 422 (which echoes `input`) across every body-carrying route | **No** | **P1** |
| Browser WebSocket handshake with a disallowed Origin never driven | Only the pure predicate is unit-tested. A refactor that moves the check after `accept()`, or a `ui_ws_authorize` hook that admits before the origin check, passes the unit test | Cross-site WebSocket hijacking leaks a live PHI-adjacent stats feed (and, with the console mounted, a server-rendered connections fragment) to a malicious page | **No** | **P1** |
| Eight shipped 2026-07 API surfaces owned by no plan artifact | ADRs 0130, 0131, 0134, 0136, 0142, 0143, 0148, 0150, 0151, 0152, 0153 return **zero** hits in both FEATURE-COVERAGE-PLAN.md and WIN2025-TEST-PLAN.md (verified by grep) | Regression ownership undefined exactly where new PHI-at-rest (uploads, presets) and new bulk-PHI-egress (export, log tail) surfaces were added | **No** (pytest coverage exists; plan ownership does not) | **P1** |
| Offset pagination over a live DESC feed | `GET /messages` passes `limit`/`offset` to `ORDER BY received_at DESC, id DESC LIMIT ? OFFSET ?`; `total` is a **second, separate** count (`api/app.py:2916-2929`) | While messages arrive, an operator paging back sees duplicates and **skips** rows — a message can be invisible to a human triaging an incident | **No** | **P2** |
| 37 GET routes carry no `limit`/`offset`/`cursor` at all | Verified by a live signature walk: `/users`, `/uploads`, `/approvals`, `/roles`, `/roles/custom`, `/connections`, `/channels`, `/graph/edges`, `/search/presets`, `/me/sessions`, `/ad-group-map`, `/ad-group-scope-map`, `/alerts/rules`, `/metrics/history`, `/cluster/nodes` … | Unbounded authenticated response; a large estate produces a multi-MB body that stalls the console and the event loop | **No** | **P2** |
| `GET /uploads` shows every uploader's filenames | `api/app.py:3764-3779` lists all files to any `files:browse` holder, unscoped and unpaged | Operator-supplied original filenames can carry patient/facility identifiers; ADR 0134's consent text says "authorized operators" but does not settle scoping | **No** | **P2** |
| Middleware order is load-bearing but unpinned | `_security_headers` → `_limit_request_body` → (mount_ui) → `AttachmentSecurityHeadersMiddleware` (`app.py:5021`) → `ClientNetworkMiddleware` (`:5035`); correctness rests on `add_middleware`'s index-0 insertion. Only the network gate's position is pinned (`test_client_network_allowlist.py:611`) | Inserting a middleware between them silently relaxes the attachment sandbox CSP → active-content XSS from an attacker-supplied attachment | Partially | **P2** |
| `/ws/stats` frame keys unpinned | Engine builds `{outbox_by_status, connections_html}` (`app.py:4895-4904`); `messagefoundry_webconsole/static/app.js:127-133` reads them; nothing asserts agreement | Renaming a key leaves the dashboard's live tiles permanently blank while the socket stays open — no error, and the poll fallback is disabled while the socket is up | **No** | **P2** |
| `/ws/stats` fan-out cost unmeasured | Per socket, per second: `store.stats()` plus — with the console mounted — a full `list_connections()` + server-side render (`app.py:4894-4905`) | 64 slow browsers = 64 store queries + 64 renders per second against the store the pipeline is writing to | **No** | **P2** |
| `expose_docs=true` off-loopback not refused or warned | The docs routes carry no auth dependency; the bind ladder (`__main__.py:1523-1610`) never consults `settings.api.expose_docs` (used only at `:2365`) | An operator enabling docs for debugging on a proxy-terminated bind publishes the entire route + model surface unauthenticated | **No** | **P2** |
| No API-layer latency/throughput number exists | Route dispatch, `/ws/stats` cadence, `/messages` on a large corpus, `/messages/search` scan latency on a large encrypted corpus | Console usability at real volume is unknown; ADR 0046's scan-and-decrypt is O(`scan_limit`) decrypts per query with no measured ceiling | **No** — FEATURE-COVERAGE-PLAN §15 and `FCP:STORE-20` (:930, "perf: large-corpus latency untested") both say so | **P2** |
| Capability catalogue understates the API | docs/FEATURE-MAP.md has no row for ADRs 0046/0130/0131/0134/0136/0150/0151; §10 (:162) still titles a live surface "Admin Console (PySide6)" and :131 says "the PySide6 desktop console stays (additive)"; :132 marks Federated SSO ⏭️ while ADR 0142 OIDC is built and registered (`app.py:1038`, `:4955`); `api/__init__.py:3-6` carries the same stale docstring. Separately, docs/SECURITY.md:298 and :481 state **201** routes / **95** console routes while the live app is **203** / **97** | First document a new contributor, an evaluator or the next test-plan author reads. Under-reports two PHI-at-rest surfaces and one bulk-PHI-egress surface; points at a retired surface | **No** — the drift test pins the integer `_ROUTES_WITH_UI=203` against its own constant, never against the doc's prose figure | **P2** |
| `/metrics` scrape cost unmeasured, label cardinality unbounded | `render_metrics` gathers off-loop then renders in-process; connection/destination label space grows with the estate | A 15 s Prometheus cadence against a slow gather is an availability drag on the engine loop | **No** — `FCP:API-24` already flags "not scraped under load"; the measurement itself is owned by ALERT-40/ALERT-61 | **P2** |

### 8.4 Test matrix

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion;
**only T rows count toward the release gate**. **C** = *Characterisation* — produces a recorded
measurement, finding or dated decision with no threshold yet; legitimate work that **cannot fail**,
so it never gates a release, and it becomes a T row the day its threshold is recorded. **A** =
*Assurance* — an external engagement, blocking **only** for an off-loopback / production-exposure
release and excluded from the ordinary P0 count.

This chapter has **73 rows: 66 T, 6 C (API-34, API-37, API-42, API-49, API-52, API-62), 1 A
(API-71)**. **7 rows are P0 and all 7 are T** (API-01…API-03 wire contract; API-09…API-12
cross-backend). Three T rows are *pointer* rows carrying no separate work (API-54 → ALERT-40/61;
API-66, API-67 → the MIG FEATURE-MAP drift-guard row). Foreign IDs are prefixed: `FCP:` =
FEATURE-COVERAGE-PLAN.md, `W25:` = WIN2025-TEST-PLAN.md; a bare `API-nn` is always this chapter's
own row.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| API-01 | OpenAPI wire-contract golden: reduce `create_app(expose_docs=True).openapi()` to a deterministic `(path, method, status, response-model field name + JSON type + required-flag)` serialization and diff against `tests/golden/api_openapi.snapshot` | Compat | pytest | container-CI | n/a | T | P0 | Snapshot regenerates byte-identically on a clean tree. A planted rename of one field on `UploadedFileInfo`, one type change on `StatsResponse`, and one optionality flip on `Health.version` each produce a diff and fail with the refresh hint naming the snapshot path |
| API-02 | Golden covers **all** 121 models, not just reachable ones: assert every `BaseModel` subclass declared in `api/models.py` (89) and `api/auth_models.py` (32) either appears in the snapshot or is on a pinned `_UNREACHABLE_MODELS` reviewed list | Compat | pytest | container-CI | n/a | T | P0 | `set(models) - set(snapshot) == _UNREACHABLE_MODELS`; the constant is non-empty only with a one-line reason per entry |
| API-03 | Golden refresh is a reviewed act: the failure message names `scripts/api_openapi_snapshot.py` and the test fails (not auto-heals) when the generated text differs | Compat | pytest | container-CI | n/a | T | P0 | Running the suite with a modified model fails; running the generator then the suite passes; no test writes the golden as a side effect |
| API-04 | `apiclient` path parity: parse every path literal and f-string template out of `messagefoundry/apiclient/client.py`, normalize `{var}`→`{}`, and assert each resolves to a route on `create_app()` | Compat | pytest | container-CI | n/a | T | P1 | All 49 distinct client paths match a live route; zero unmatched (today: only the base-URL `"/"` is unmatched and must be excluded explicitly). A planted route rename fails the test |
| API-05 | `apiclient` model parity: for every `_decode(..., Model)` call site, assert `Model` is the `response_model` declared on the matching route | Compat | pytest | container-CI | n/a | T | P1 | Every decode site matches; a planted swap of `StatsResponse` for `MessageList` fails |
| API-06 | `apiclient` coverage disposition is pinned: assert the set of live paths with **no** client method equals a reviewed `_APICLIENT_UNCOVERED` constant (44 paths today) | Compat | pytest | container-CI | n/a | T | P1 | The set matches exactly; adding a route without a client method fails the test until the author either adds the method or adds the path to the reviewed list |
| API-07 | IDE TypeScript DTO drift: generate `ide/src/generated/engineDtos.json` from `ReloadResult`, `ConnectionRow`, `Health` field sets at build time and assert the three hand-written TS interfaces (`ide/src/promote.ts:21`, `ide/src/liveStatusModel.ts:13`, `ide/src/engineStatusModel.ts:256`) are structural subsets | Compat | ide-mocha | container-CI | n/a | T | P1 | `npm run test:unit` fails when a Python-side field is renamed and the TS interface is not; the generated JSON is committed and its regeneration is part of the same CI leg |
| API-08 | Tray `/health` key contract: assert `Health` still declares `status` (the literal `messagefoundry/tray/probe.py:62` keys on) and that `classify_health` returns `OK` for the real serialized body | Compat | pytest | container-CI | n/a | T | P2 | Round-trip `Health().model_dump()` through `classify_health` yields `HealthProbe.OK`; renaming `status` fails |
| API-09 | Cross-backend read plane: `GET /messages` with each filter (`channel_id`, `status`, `message_type`, `control_id`, `received_from/to`), `limit`/`offset`, and `total` against a real SQL Server and a real PostgreSQL store behind `create_app(engine)` | Cross-backend | CI-leg | container-CI | x2 | T | P0 | Identical row ids, order and `total` to the SQLite run over the same seeded synthetic corpus; no 500; `MEFOR_TEST_SQLSERVER`/`MEFOR_TEST_POSTGRES` gate the module |
| API-10 | Cross-backend `GET /messages/search` + `GET /search/layered`: substring and `field_path` needles, `scan_limit` truncation, `truncated`/`scanned`/`matched` counters | Cross-backend | CI-leg | container-CI | x2 | T | P0 | Same matched id set and same `truncated` flag as SQLite for the same corpus and spec; the `message_search` audit row is written on all three |
| API-11 | Cross-backend audit plane: `GET /audit` filters + `GET /audit/export` CSV, with the ADR 0150 `client` value present, on `NVARCHAR(256)` (SQL Server) and `TEXT` (PostgreSQL) | Cross-backend | CI-leg | container-CI | x2 | T | P0 | The `client` column round-trips the exact address; the hash chain still verifies (`POST /status/integrity-check` → `ok`); CSV export byte-equals the SQLite export modulo ids/timestamps |
| API-12 | Cross-backend write plane through routes: `POST /messages/{id}/replay`, `/resend`, `/edit-resend`, `POST /dead-letters/replay`, `POST /uploads/{id}/resend` | Cross-backend | CI-leg | container-CI | x2 | T | P0 | Each returns the same status code and result model as SQLite; the produced rows reach the same disposition; no backend-specific 500. Complements `FCP:API-13`/`FCP:API-14`, which are store-level and CI-only |
| API-13 | Cross-backend presets + uploads + dead-letter paging via routes: `GET/POST/DELETE /search/presets`, `GET /uploads`, `GET /uploads/{id}/messages`, `GET /dead-letters` with `limit`/`offset` | Cross-backend | CI-leg | container-CI | x2 | T | P1 | Owner scoping, encrypted `criteria` round-trip and paging boundaries behave identically on all three backends |
| API-14 | Real-socket framing: spawn `python -m messagefoundry serve` on an ephemeral loopback port and drive raw sockets — CL+TE both present, `Transfer-Encoding: chunked` with no CL, a lying `Content-Length`, a 2 MiB body on a 1 MiB-capped path | Negative/Security | CI-leg | container-CI | SQLite | T | P1 | 400 / 411 / 400 / 413 respectively, returned on the wire; the listener accepts a subsequent well-formed request on a fresh connection (proving it stayed live) |
| API-15 | Real-socket resource limits: 200 request headers, a 64 KiB single header, a slow-loris header drip (1 byte/s for 60 s), and 200 simultaneous idle keep-alive connections | Performance | CI-leg | container-CI | SQLite | T | P1 | Each abusive request is rejected or timed out with a recorded status/close; RSS growth over the run stays under a pinned ceiling; a control request from a second client succeeds throughout |
| API-16 | Real-socket upload cap: with `[store].uploads_dir` set and `max_upload_bytes = N`, POST `N+1` bytes to `/uploads` and `N-1` bytes to `/messages` | Negative/Security | CI-leg | container-CI | SQLite | T | P1 | `/uploads` → 413 at `N+1`, 2xx/4xx-by-content at `N-1`; `/messages` still rejects at 1 MiB+1, proving `_UPLOAD_BODY_PATHS` (`app.py:314`) is path-scoped and not global |
| API-17 | Real-socket TLS: serve with `[api].tls_cert_file`/`tls_key_file` on a non-loopback bind and complete a real client handshake, then repeat with an expired cert and with a client cert against `tls_client_ca_file` | Negative/Security | CI-leg | dev-PC | SQLite | T | P1 | TLS 1.2 floor enforced on the live socket; `GET /service/identity` succeeds only with a mapped client cert; the ASVS 6.4.5 expiry alert fires on the expiring-cert fixture at handshake. Closes ADR 0092's deferred "uvicorn-on-a-real-socket" residual |
| API-18 | Serve bind ladder end-to-end on a real process: loopback default; non-loopback without TLS → refuse (exit 2); `--allow-insecure-bind` on a non-PHI/`enforcement=warn` instance → warn + start; `--allow-insecure-bind` on PHI + `enforcement=enforce` → refuse (exit 2) | Negative/Security | CI-leg | container-CI | SQLite | T | P1 | Exit codes and the exact stderr strings from `__main__.py:1545-1578` observed; a refused start binds no socket (verified by a connect attempt) |
| API-19 | `expose_docs=true` on a non-loopback or proxy-terminated bind is refused or loudly warned, joining the exposed-gate ladder | Negative/Security | pytest | container-CI | n/a | T | P2 | With `[api].expose_docs = true` and a non-loopback `[api].host`, `serve` emits a named warning (or exits 2 per the owner's decision in Q7) and the decision is asserted in both arms; loopback + docs stays silent |
| API-20 | `trusted_proxies` → `forwarded_allow_ips` is the single XFF trust point on a live process: send `X-Forwarded-For` from a declared and an undeclared peer | Negative/Security | CI-leg | container-CI | SQLite | T | P1 | From an undeclared peer the audit `client` and the network gate both see the socket peer; from a declared peer they see the forwarded address. Extends the synthesized-scope coverage in `test_client_network_allowlist.py` |
| API-21 | XFP tripwire fires exactly once: with `tls_terminated_upstream` declared, issue three cleartext `/ui` requests | Negative/Security | pytest | container-CI | n/a | T | P2 | Exactly one WARNING containing "not sending X-Forwarded-Proto" in `caplog` across the three requests (`app.py:1226-1251`) |
| API-22 | Tokenless sweep over **all** 105 routes: enumerate `create_app()` routes, issue each with its declared method and a minimal valid body/params, no `Authorization` | Negative/Security | pytest | container-CI | SQLite | T | P1 | Every route returns 401 or 403 except the pinned allowlist — `GET /auth/providers`, `POST /auth/login`, `POST /auth/negotiate`, `GET /health`, `GET /ai/policy`. No 200, no 500. Allowlist is a module constant and a planted removal of one gate fails |
| API-23 | Under-privileged sweep: repeat API-22 with a token holding only `monitoring:read` | Negative/Security | pytest | container-CI | SQLite | T | P1 | Every route outside the `monitoring:read` set and the 13 permissionless self-service routes returns 403; the monitoring set returns 2xx; the result set equals the derived expectation from `_route_rows()` |
| API-24 | Sweep with the console mounted (`serve_ui=True`, 203 routes) so the `/ui` plane rides the same harness | Negative/Security | pytest | container-CI | SQLite | T | P1 | Every `/ui` route redirects (303 to login) or 401/403 except the 10 reviewed no-gate `/ui` routes; `/ui/static` serves without auth as documented |
| API-25 | Fail-closed with no `AuthService`: build `create_app(engine)` with neither `auth=` nor `allow_no_auth=True` and sweep every gated route | Negative/Security | pytest | container-CI | SQLite | T | P1 | Every gated route returns 503 (`security.py:200-205`); `/health` still 200; `allow_no_auth=True` flips them to 200 under the system identity (SYS-1) |
| API-26 | MFA-pending access gate on the wire: with a session whose second factor is pending, request every route | Negative/Security | pytest | container-CI | SQLite | T | P1 | Only the six method-keyed exempt routes (`security.py:_MFA_EXEMPT_ROUTES`) answer; `GET /me/sessions` and `GET /me/security-events` are refused; must-change-password ordering is proven by a session that is both pending and must-change |
| API-27 | Cert-only identity cannot reach a PHI or step-up route on a live mTLS socket | Negative/Security | CI-leg | dev-PC | SQLite | T | P1 | `GET /service/identity` 200 with the cert; `GET /messages/{id}`, `GET /messages/search`, `GET /messages/export`, `GET /logs/tail`, `GET /uploads/{id}/messages` all refuse; a `service_cert_auth` audit row exists for the accepted call only |
| API-28 | PHI-read hop refusal on the wire: production-PHI instance on an unproven-secure serve hop | PHI | pytest | container-CI | SQLite | T | P1 | Every `require_phi_read` route and `/messages/search` return 403 with a PHI-free body; `/stats`, `/connections`, `/health` still 200; the refusal body contains no message content and no path |
| API-29 | Catch-all 500: monkeypatch one dependency per route family to raise, then request | Negative/Security | pytest | container-CI | SQLite | T | P1 | Response body is exactly `{"detail":"internal error"}` with status 500 and no `traceback`/`exc`/file-path substring; `caplog` contains the exception **type name** and the route, and does **not** contain `str(exc)` |
| API-30 | PHI-safe 422 across **every** body-carrying route: parametrize a deliberately invalid body carrying the planted marker `ZZPHIMARKERZZ` | PHI | pytest | container-CI | SQLite | T | P1 | No response contains `input`, `ctx`, or `ZZPHIMARKERZZ`; `caplog` contains neither; the body is a list of `{loc,msg,type}` objects only. Covers all POST/PUT/PATCH routes, not just `/messages/{id}/edit-resend` |
| API-31 | 422 handler cannot be silently replaced: assert `app.exception_handlers` maps `RequestValidationError` to the module's `_validation_error` and `Exception` to `_unhandled_exception` | Negative/Security | pytest | container-CI | n/a | T | P1 | Both handlers are the app's own functions (identity check on `__name__` + `__module__`); FastAPI's defaults are absent |
| API-32 | `debug` is never on: assert `create_app(...)` yields `app.debug is False` for every argument combination including `expose_docs=True` and `serve_ui=True` | Negative/Security | pytest | container-CI | n/a | T | P2 | `app.debug is False` in all arms |
| API-33 | Status-code contract: for each route assert the success status and that error paths use the documented codes (400 bad spec, 403 scope/permission, 404 unknown id, 409 conflict window, 411/413 framing, 422 validation, 429 pacing, 503 unconfigured/engine-absent) | Functional | pytest | container-CI | SQLite | T | P2 | A table of `(method, path, expected_success_status)` derived from the live app matches a pinned constant; each error family has at least one asserted route |
| API-34 | Pagination stability under concurrent ingest: page `GET /messages` with `limit=50` through 1 000 seeded synthetic messages while a writer inserts 10/s | Functional | pytest | container-CI | SQLite | C | P2 | Either (a) the union of pages covers every pre-existing id exactly once with no duplicate, or (b) the accepted skew is documented and the test asserts the documented bound. A stable cursor, if adopted (Q5), makes (a) mandatory |
| API-35 | `total` vs rows consistency: assert `total >= len(messages)` and that `offset >= total` yields an empty list, not a 500, under the same concurrent writer | Functional | pytest | container-CI | x3 | T | P2 | No 500; empty list at `offset == total`; `total` monotonic non-decreasing across the run |
| API-36 | Unbounded list surfaces: seed each of the 37 pageless GET routes past a threshold (1 000 users, 500 connections, 500 uploads, 200 approvals, 200 presets) and measure the response body size | Performance | pytest | container-CI | SQLite | T | P2 | Each route either returns a bounded page or appears in a drift-guarded `_UNPAGED_EXEMPT` constant with a reason; no response exceeds a pinned byte ceiling without an exemption |
| API-37 | `GET /uploads` visibility rule is explicit: two uploaders, one `files:browse` holder | PHI | pytest | container-CI | SQLite | C | P2 | The observed behaviour matches whichever rule the owner ratifies (Q6) and the test names ADR 0134 in its docstring. Today's behaviour (all uploaders' filenames visible to any `files:browse` holder, `app.py:3764-3779`) fails until it is pinned as a reviewed decision |
| API-38 | Search-preset criteria never round-trip: create a preset with a needle, list it, and recall it via `/search/layered` | PHI | pytest | container-CI | x3 | T | P1 | No response body from `GET /search/presets` or `GET /search/layered` contains the needle string; the `preset.layered_search` audit records shape only |
| API-39 | Layered compose bounds on the wire: 9 layers, two conflicting metadata scalars, zero content predicates, two content predicates | Negative/Security | pytest | container-CI | SQLite | T | P2 | 400 for each of the four arms with a distinct, PHI-free message; 8 layers with one content predicate succeeds |
| API-40 | Export audit precedes bytes: kill the client mid-stream after the first NDJSON line of a 1 000-row `GET /messages/export` | PHI | pytest | container-CI | SQLite | T | P1 | Exactly one `messages_export` audit row exists naming the full selected count; no message body appears in any log; the partial stream contains only synthetic bodies |
| API-41 | Export `Cache-Control: no-store` and `Content-Disposition`: assert on the streaming response headers | PHI | pytest | container-CI | SQLite | T | P2 | `Cache-Control: no-store` present (via `_NO_STORE_PREFIXES` `/messages`), a filename-bearing `Content-Disposition`, and `X-Content-Type-Options: nosniff` |
| API-42 | Content search scan latency vs `scan_limit` on a large encrypted corpus | Performance | load-harness | dev-PC | x3 | C | P2 | p50/p95 recorded for `scan_limit` ∈ {1 000, 10 000, `MAX_CONTENT_SCAN_LIMIT`} at 100 k and 1 M synthetic messages; the event loop's max lag during the scan stays under a recorded ceiling (the scan already runs off-loop — this measures the ceiling, not the property) |
| API-43 | Uploads unconfigured: with `[store].uploads_dir` unset, request all five upload routes | Functional | pytest | container-CI | SQLite | T | P2 | All five return 503 before any filesystem touch (`app.py:3643-3649`); no directory is created; already covered at unit level — this row asserts it for the full five-route set as a release gate |
| API-44 | Uploaded file at rest is encrypted when a store DEK is configured, and the plaintext-on-disk tier is loud when it is not | PHI | pytest | dev-PC | SQLite | T | P1 | With a DEK, the on-disk body does not contain a known synthetic marker string; without one, a startup/route-time warning naming the plaintext tier is emitted (docs/PHI.md §2) |
| API-45 | Upload → browse → resend → delete round-trip through a real running engine with a live inbound Connection | Functional | harness | dev-PC | x3 | T | P1 | The resent message appears with disposition `RECEIVED` then `PROCESSED`; `upload.delete` audit written; the file is gone from `uploads_dir`; the origin message has no `messages` parent row (proving `enqueue_ingress`, not `reingress`) |
| API-46 | Uploads quota + retention prune under the route: fill to `max_upload_bytes` quota, then upload once more | Negative/Security | pytest | container-CI | SQLite | T | P2 | 409 with a PHI-free body and a quota audit row; the opportunistic prune (`app.py:3755-3762`) does not raise on an `OSError` and logs a warning |
| API-47 | `/ws/stats` 64-socket cap behaviourally: open `_MAX_WS_CONNECTIONS` sockets, then one more | Negative/Security | pytest | container-CI | SQLite | T | P1 | The 65th handshake is refused (Starlette closes pre-`accept()`, so the client observes a rejected handshake, not a 1013 frame — assert the refusal, and assert the close code at the ASGI layer); the 64 established sockets keep receiving frames |
| API-48 | `ws_count` hygiene across every exit path: clean disconnect, revocation close (1008), engine-absent (1011), cap refusal, and an exception raised inside the send loop | Negative/Security | pytest | container-CI | SQLite | T | P1 | After each path, `app.state.ws_count == 0` and a fresh socket connects. Parametrized over all five; a planted early `return` before the `finally` fails the test |
| API-49 | `/ws/stats` cap TOCTOU: launch 80 handshakes concurrently against a 64-cap | Negative/Security | pytest | container-CI | SQLite | C | P2 | At most a documented overshoot is accepted (record the observed maximum); `ws_count` returns to 0 after all close. If the overshoot is unacceptable, the check/increment must move inside one critical section |
| API-50 | Browser CSWSH: `TestClient.websocket_connect("/ws/stats", headers={"Origin": "https://evil.example"})` against an app with an empty allow-list and with a populated one, both with and without the console's `ui_ws_authorize` hook installed | Negative/Security | pytest | container-CI | SQLite | T | P1 | Refused **before** any frame in all disallowed arms (zero frames received, connection rejected); the exact-match allowed Origin succeeds; a native client (no `Origin`) succeeds in every arm |
| API-51 | `/ws/stats` frame-key contract, two-sided: pin `{"outbox_by_status", "connections_html"}` in an engine constant, assert the route emits exactly those keys (counts-only without the render hook), and have the web-console suite assert the same constant against `app.js` | Compat | pytest | container-CI | SQLite | T | P2 | Both suites reference one shared constant; renaming a key fails on both sides |
| API-52 | `/ws/stats` backpressure and fan-out cost: N ∈ {1, 16, 64} concurrent consumers including deliberately non-reading ones, while the pipeline runs at a known rate | Performance | load-harness | dev-PC | x3 | C | P2 | Recorded: store query rate, per-frame render time with the console mounted, event-loop max lag, and the delta in pipeline delivered-throughput vs the 0-socket baseline. A regression ceiling is set from this first run |
| API-53 | `/health` disclosure matrix: tokenless, authenticated, with and without `allowed_client_networks` | Functional | pytest | container-CI | n/a | T | P2 | Tokenless → `version` null; authenticated → `version` set; `observed_client` present **only** when the allow-list is non-empty, matching `api/app.py:1335-1352`. Already partly covered — this row pins the four-cell matrix |
| API-54 | *Pointer* — `/metrics` cardinality + scrape cost under a real Prometheus cadence | Performance | — | — | — | T | P2 | Covered by ALERT-40/ALERT-61; no separate work scoped |
| API-55 | `/metrics` authentication for a scraper: prove the intended production credential works end-to-end | Functional | manual | W2025-box | SQLite | T | P2 | A service-account bearer scrapes successfully under the NSSM service identity; whether the mTLS service-cert plane is also offered is Q11 |
| API-56 | `/metrics/history` ring bounds through the route while `/ws/stats` sockets feed it | Functional | pytest | container-CI | SQLite | T | P2 | With 8 sockets open for 30 s, `samples` length ≤ `capacity` and no duplicate `ts` within the min-interval; `capacity` matches the configured ring size |
| API-57 | Docs surface off by default and complete when on | Functional | pytest | container-CI | n/a | T | P2 | Default `create_app()` → 404 on `/openapi.json`, `/docs`, `/redoc`; `expose_docs=True` → 200 on all four docs routes and `len(routes) == 109` |
| API-58 | Middleware order pinned: assert the exact ordered list of `app.user_middleware` class/function names for `serve_ui=False` and `serve_ui=True` | Negative/Security | pytest | container-CI | n/a | T | P2 | Both lists equal pinned constants; `ClientNetworkMiddleware` is outermost and `AttachmentSecurityHeadersMiddleware` is the last CSP writer in both arms. Extends `test_client_network_allowlist.py:611` from one position to the full stack |
| API-59 | Security-header matrix over one route per family: JSON PHI route, JSON non-PHI route, attachment download, `/ui` HTML, `/ui/static` asset | Negative/Security | pytest | container-CI | SQLite | T | P2 | `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `X-Frame-Options: DENY` on all; `Cache-Control: no-store` on every `_NO_STORE_PREFIXES` path and every `/ui` HTML path but **not** `/ui/static`; HSTS present only over https or `exposure_protected` |
| API-60 | Attachment sandbox CSP survives a newly inserted middleware: register a dummy CSP-setting middleware after `AttachmentSecurityHeadersMiddleware` and assert the test fails | Negative/Security | pytest | container-CI | SQLite | T | P2 | The self-test arm demonstrates the guard is not vacuous; the shipped arm passes |
| API-61 | `allowed_client_networks` on a real socket from a real second address (not a synthesized scope) | Negative/Security | CI-leg | dev-PC | SQLite | T | P1 | A request from a non-allowed local interface address is refused before routing with the denial marker header; the loopback carve-out still admits `127.0.0.1`; `/health` answers and echoes `observed_client`; `GET /security/posture` denial counter increments by exactly one |
| API-62 | API read-plane latency profile: p50/p95/p99 for `GET /messages` (default page), `GET /messages/{id}`, `GET /stats`, `GET /connections` at 10 k / 100 k / 1 M synthetic messages | Performance | load-harness | dev-PC | x3 | C | P2 | Numbers recorded per backend and archived alongside the LOAD-TESTING report; a regression ceiling is set from the first run. Closes the "no API-layer performance test exists anywhere" gap named in FEATURE-COVERAGE-PLAN §15 |
| API-63 | Concurrent read fan-out: 32 concurrent authenticated readers hitting the read plane while the pipeline ingests at a known rate | Performance | load-harness | dev-PC | x3 | T | P2 | Recorded: API p95, pipeline throughput delta vs baseline, store connection-pool saturation gauge. No 500s, no pool exhaustion error |
| API-64 | Rate-limit interaction under load: drive the PHI-read throttle and the admin-write pacer concurrently from two actors | Negative/Security | pytest | container-CI | SQLite | T | P2 | Actor A's 429 + `Retry-After: 10` does not throttle actor B; the admin-write pacer's `Retry-After: 1` fires on NON-GET only; both recover after the window |
| API-65 | Authorization-GRANT audit volume: with `audit_all_authz=False` then `True`, drive 200 mixed requests | Functional | pytest | container-CI | SQLite | T | P2 | Default writes grant rows only for the `_GRANT_AUDIT_PERMISSIONS` set on non-GET; `audit_all_authz=True` widens it; the row count difference matches the derived expectation |
| API-66 | *Pointer* — every Accepted+built API-route/`[api]`/`[security]`/`[store]` ADR (0046, 0130, 0131, 0134, 0136, 0142, 0143, 0150, 0151) has a FEATURE-MAP row | Compat | — | — | — | T | P1 | Covered by the MIG FEATURE-MAP drift-guard row (MIG-74, the consolidated row extending `tests/test_feature_map_claims.py`); no separate work scoped. This chapter contributes the ADR list only |
| API-67 | *Pointer* — FEATURE-MAP staleness: the retired PySide6 desktop console claims and the ⏭️ Federated SSO row while `oidc_enabled` registers routes (`api/app.py:1038`, `:4955`) | Compat | — | — | — | T | P1 | Covered by the MIG FEATURE-MAP drift-guard row (MIG-74); no separate work scoped. The `api/__init__.py:3-6` docstring correction rides the same change |
| API-68 | docs/SECURITY.md prose route figures are derived, not hand-written: assert the "yields 201" and "95 console routes" statements (:298, :481) equal the live walk | Compat | pytest | container-CI | n/a | T | P2 | The doc states **203** and **97** (today's live values) and the test parses those integers out of the prose rather than comparing to its own constant. Currently a real, unasserted drift |
| API-69 | On-host posture re-run under the NSSM service identity | Functional | verify | W2025-box | x3 | T | P1 | Execute WIN2025-TEST-PLAN.md **`W25:S2.8`** (:492-509) verbatim — do not re-author — and record the result into MANUAL row **`W25:S1.AC-API`** (:314). Pass = that row's own criteria hold on the box: `Get-NetTCPConnection -LocalPort 8765` shows `LocalAddress == 127.0.0.1`, an unauthenticated `GET /stats` returns 401/403, and the same call with a valid bearer returns 200, all under the NSSM service identity. A failure of any of the three is a red row, not a recorded observation |
| API-70 | Reverse-proxy topology matrix: nginx, Caddy and IIS+ARR terminating TLS in front of the engine with exact-peer `trusted_proxies` | Compat | manual | W2025-box | SQLite | T | P1 | For each proxy: audit `client` shows the real browser address; the ::1-vs-127.0.0.1 mismatch arms the XFP tripwire exactly once; `allowed_client_networks` evaluates the forwarded address (R2), and removing the `trusted_proxies` entry makes it inert (R3) with the monoculture tripwire lit |
| API-71 | Third-party penetration test / DAST against the running API | Negative/Security | external | cloud | SQLite | A | P1 | **Assurance row: blocking only for an off-loopback / production-exposure release, advisory for a loopback-only one; excluded from the ordinary P0 count.** Pass = an engagement report is delivered against the release-candidate serve posture (authn/authz, TLS/mTLS, `/ws/stats`, uploads, export, error handlers); **every Critical/High finding is closed or carries a dated, named risk acceptance before sign-off**; and the standing "no third-party assessment, no penetration test and no DAST" acceptance at `docs/FEATURE-MAP.md:136` is superseded by that report or re-signed with its new expiry. Scope/vendor gated on Q10 |
| API-72 | DNS failure of a route-reachable dependency mid-run: with the engine serving, make the target hostname of an outbound Connection, of `POST /alerts/test-email`'s SMTP host and of the OIDC issuer as reached by the login legs (`auth/oidc_http.py:69` `build_idp_opener`, `:107` `jwks_fetcher` — note the boot-time OIDC preflight at `api/app.py:5595-5607` is deliberately config-only and does no network I/O, so it is *not* the DNS-dependent path) stop resolving (resolver stub / hosts override), then drive `POST /connections/{name}/test-credential` (`api/app.py:2072`), `POST /alerts/test-email` (`api/app.py:2461`), `GET /connections`, `GET /stats`, `GET /health` and one login; restore DNS and repeat | Negative/Security | CI-leg | container-CI | SQLite | T | P2 | Each DNS-dependent route returns a bounded, PHI-free 502/503 within a pinned timeout (no hostname-internal detail, no credential, no stack); the read plane and `/health` keep answering with p95 unchanged and event-loop max lag under the pinned ceiling (proving resolution runs off the loop, never inline); no route hangs past the timeout and no worker is left wedged; after DNS is restored the same routes succeed with **no engine restart**. A planted inline `socket.getaddrinfo` on the request path fails the loop-lag arm |
| API-73 | Certificate expiry **during a live session** (not expiry *alerting*, which SEC owns): serve with a server cert and a mapped mTLS client cert that both expire N seconds after start; hold one keep-alive HTTPS connection and one `/ws/stats` socket open across `notAfter`, then (a) issue a request on the pre-existing connection, (b) open a fresh connection, (c) issue a `require_service_cert` call (`GET /service/identity`) on the pre-existing mTLS connection | Negative/Security | CI-leg | dev-PC | SQLite | T | P1 | (b) a new handshake fails closed after `notAfter` and the failure is logged without key material; (c) the first cert-authenticated request after `notAfter` on the **already-verified** connection is refused (401/403) and a `cert_expiry` alert is recorded with `days_remaining < 0` — today `resolve_client_cert_identity` treats expiry as advisory ("it never gates the resolution", `api/security.py:424-426`), so this arm is expected **red** on today's code and stays red until an expiry gate lands — it is a finding, not an exemption; (a) the plain-TLS keep-alive arm's observed behaviour is pinned as a constant so a change is visible; `ws_count` still returns to 0 when the socket closes |

### 8.5 Detailed scenarios

#### S-API-A — OpenAPI wire-contract golden (API-01/02/03)

**Preconditions.** Clean worktree; `pytest` and the project venv; no uncommitted model edits.

**Steps.**
1. Add `scripts/api_openapi_snapshot.py` exposing `build_snapshot() -> str`, mirroring
   `scripts/webconsole_seam_snapshot.py`'s shape so the two goldens are maintained the same way.
2. Inside it: `app = create_app(expose_docs=True)`; walk `app.openapi()`; for every
   `(path, method)` emit the declared success status and, for each `$ref`-ed schema, the sorted
   `(field name, JSON type, required?)` triples resolved one level deep. Sort everything; never emit
   descriptions or examples (they churn without breaking anyone).
3. Write `tests/golden/api_openapi.snapshot`; add `tests/test_api_openapi_snapshot.py` that
   regenerates and `difflib`-diffs, with a failure hint naming the generator.
4. **Self-test the guard.** Temporarily rename `UploadedFileInfo.original_name`, flip
   `Health.version` to required, and change `StatsResponse`'s counter type. Run the suite.
5. Revert all three; run again.

**Observation point.** Step 4 must produce three distinct diffs and a red test; step 5 green.

**Expected result.** A byte-stable golden and a demonstrably non-vacuous guard. Coverage of all 121
models asserted by API-02 so an unreachable model cannot hide.

**Cleanup.** `git checkout` the three planted edits. The golden itself is committed.

**PHI note.** The snapshot contains schema metadata only — no example values, no message content.

---

#### S-API-B — API routes on SQL Server and PostgreSQL (API-09…API-13)

**Preconditions.** SQL Server 2022/2025 reachable with ODBC Driver 18 and `sqlcmd`; a PostgreSQL
service container; `MEFOR_TEST_SQLSERVER=1` / `MEFOR_TEST_POSTGRES=1`; a synthetic PHI-free corpus.

**Steps.**
1. Generate the corpus once, to a scratch path **outside** the repo:
   `python -m messagefoundry generate --type ADT --count 2000 --seed 42 --out %TEMP%\mefor-api-corpus`
   (`generate` output can contain full bodies — it must never be redirected into a committed file, a
   ticket, or a CI log).
2. Add `tests/test_api_server_backends.py`, gated on the two env vars, with a fixture that opens the
   server-DB `Engine`, seeds the corpus through the store, then builds `create_app(engine, auth=…)`
   and drives it over `httpx.ASGITransport`. This is the **first** place `create_app` meets a
   server DB — verified today by cross-grepping `create_app` against every file setting those vars
   (zero results).
3. Run the representative route set: `GET /messages` (each filter, three page boundaries, `total`),
   `GET /messages/search` (substring + `PID-3` field path, `scan_limit` truncation),
   `GET /search/layered`, `GET /dead-letters` (paged), `GET /audit` + `GET /audit/export`,
   `POST /messages/{id}/replay`, `POST /messages/{id}/resend`, `GET /uploads/{id}/messages`.
4. Capture the SQLite baseline from the same corpus and seed, and diff the normalized results.
5. Run `POST /status/integrity-check` last.

**Observation point.** The normalized result diff (step 4) and the integrity result (step 5).

**Expected result.** Zero differences in row identity, ordering, `total`, `truncated`, and status
codes. The ADR 0150 `client` value round-trips on `NVARCHAR(256)` and the audit hash chain verifies.

**Cleanup.** Drop the test schema (`sqlcmd -Q "DROP DATABASE …"` / `dropdb`); delete the scratch
corpus directory. **Never** commit the corpus — it is git-ignored by design.

---

#### S-API-C — Real uvicorn socket: framing, limits and TLS (API-14…API-18, API-61)

**Preconditions.** An ephemeral loopback port; the project installed; on Windows, note the known
port-rebind lag called out in WIN2025-TEST-PLAN's host traps — the fixture must retry the bind.

**Steps.**
1. Pytest fixture: launch `python -m messagefoundry serve --config samples/config --db <tmp>/api.db
   --env dev` on a free port as a subprocess; poll `GET /health` until 200 (never `sleep`-and-hope);
   yield the base URL; on teardown terminate and wait.
2. Drive raw `socket` writes (not httpx — httpx would normalize the very headers under test):
   - `POST /auth/login HTTP/1.1` with **both** `Content-Length: 2` and `Transfer-Encoding: chunked`
     → expect `400`.
   - `Transfer-Encoding: chunked` with no `Content-Length` → expect `411`.
   - `Content-Length: notanumber` → expect `400`.
   - `Content-Length: 2097152` with a 2 MiB body on `/messages` → expect `413`.
   - 200 distinct request headers; one 64 KiB header → expect a 4xx/close, listener alive.
   - Slow-loris: open a connection, write `GET /health HTTP/1.1\r\n` then 1 byte/s for 60 s.
3. After each abusive case, issue a normal `GET /health` on a **fresh** connection.
4. TLS arm: configure `[api].tls_cert_file`/`tls_key_file` (self-signed fixture) on a non-loopback
   bind, complete a real handshake, assert the negotiated version floor, then repeat with the
   expiring-cert fixture and assert the ASVS 6.4.5 alert.
5. Bind-ladder arm: start with a non-loopback host and no TLS (expect exit 2 and the exact stderr
   string), then with `--allow-insecure-bind` on `[security].enforcement=warn` (expect the warning
   and a live socket), then with a PHI posture at `enforcement=enforce` (expect exit 2).

**Observation point.** The raw bytes returned on the socket; the subprocess exit code and stderr;
the successful control request in step 3.

**Expected result.** Every framing case returns the documented status **on the wire**, the listener
survives all of them, and the refusal arms bind no socket. This is the first evidence for h11's own
behaviour and closes the residual ADR 0092 records as deferred.

**Cleanup.** Terminate the subprocess in the fixture's `finally`; remove the temp DB and cert
fixtures. Never leave a non-loopback listener bound after the test.

**PHI note.** Only synthetic bodies; the oversize body is filler bytes, never a message.

---

#### S-API-D — `/ws/stats` cap, counter hygiene and CSWSH (API-47…API-51)

**Preconditions.** `create_app(engine, auth=…)` with a `monitoring:read` token; `TestClient` for
the browser-shaped arms.

**Steps.**
1. Open exactly `_MAX_WS_CONNECTIONS` (64, `api/app.py:319`) sockets against `/ws/stats`, each
   reading at least one frame. Assert `app.state.ws_count == 64`.
2. Attempt the 65th. Because the cap check runs **before** `websocket.accept()` (`:4846`), the
   client observes a rejected handshake rather than a 1013 close frame — assert the rejection at the
   client and the 1013 code at the ASGI layer (an in-memory peer, as
   `tests/test_ws_stats_revalidation.py` already does).
3. Close all 64; assert `ws_count == 0`; open a new socket and read a frame.
4. Parametrize the exit paths and re-assert `ws_count == 0` after each: clean disconnect; session
   revoked mid-stream (1008); `app.state.engine` removed (1011); cap refusal; an exception injected
   into `store.stats()` inside the send loop.
5. TOCTOU: launch 80 handshakes with `asyncio.gather`. Record the observed peak `ws_count`.
6. CSWSH: `websocket_connect("/ws/stats", headers={"Origin": "https://evil.example"})` against
   (a) empty `ws_allowed_origins`, (b) a populated one that does not match, (c) a populated one that
   matches exactly — each with and without a stub `app.state.ui_ws_authorize` installed.
7. Frame keys: assert the received frame's key set equals the pinned constant — `{outbox_by_status}`
   without a render hook, `{outbox_by_status, connections_html}` with one.

**Observation point.** `app.state.ws_count` after each arm; frames received (must be **zero** in
every refused CSWSH arm); the peak in step 5.

**Expected result.** Cap enforced, counter always returns to 0, no frame ever precedes an origin
refusal, and the frame keys match the constant the web console reads
(`messagefoundry_webconsole/static/app.js:127-133`).

**Cleanup.** Close every socket in a `finally`; the engine fixture is per-test.

---

#### S-API-E — Tokenless and under-privileged sweep over all 105 (203) routes (API-22…API-26)

**Preconditions.** A seeded engine so path params resolve to real ids (an unknown id yielding 404
would mask a missing gate — the sweep must reach the handler's gate, not its lookup).

**Steps.**
1. Build a `(method, path, sample_params, sample_body)` table by walking `create_app()` and filling
   `{…}` segments from seeded fixtures (one message id, one attachment id, one connection name, one
   user id, one alert id, one approval id, one preset id, one upload id, one session id).
2. Issue every route with **no** `Authorization` header. Assert 401/403 except the pinned five
   no-gate routes.
3. Repeat with a `monitoring:read`-only token; assert 403 outside the derived monitoring set and the
   13 permissionless self-service routes.
4. Repeat on `create_app(serve_ui=True)` (203 routes) so the `/ui` plane rides the same sweep;
   `/ui` routes may answer 303-to-login instead of 401.
5. Repeat with `create_app(engine)` and **no** `auth=` and no `allow_no_auth` → assert 503.
6. **Self-test.** Temporarily delete the `Depends(require(...))` from `GET /connections` and assert
   the sweep goes red; revert.

**Observation point.** The set of `(method, path)` returning 2xx in each arm.

**Expected result.** Each arm's 2xx set exactly equals the pinned expectation; step 6 proves the
sweep is not vacuous. This catches the class the structural drift guard cannot: a handler answering
before its dependency, a middleware short-circuit, or a `_gate_of` blind spot.

**Cleanup.** Revert the planted deletion. No state persists beyond the fixture DB.

---

#### S-API-F — API-layer latency and `/ws/stats` fan-out profile (API-42, API-52, API-62, API-63)

**Preconditions.** A dev PC (or the W2025 box) with the load harness available; an engine serving
`harness/config/load`; a synthetic corpus at 10 k / 100 k / 1 M.

**Steps.**
1. Serve the load config per docs/LOAD-TESTING.md:
   `MEFOR_LOAD_FANOUT=20 MEFOR_LOAD_SINK_PORT=2700 python -m messagefoundry serve --config
   harness/config/load --db ./load.db --env dev`.
2. Establish the pipeline baseline:
   `python -m harness --load fanout-baseline --engine http://127.0.0.1:8765 --token <T>
   --sink-port 2700 --report-json out/load/base.json`.
3. Add a new API profile to `harness/load/profiles/` that, alongside the sender, drives (a) a read
   fan-out of 32 authenticated clients across `/messages`, `/messages/{id}`, `/stats`,
   `/connections`, (b) N ∈ {0, 1, 16, 64} `/ws/stats` consumers of which a quarter deliberately do
   not read, and (c) a `/metrics` scrape every 15 s **as background load only** — the scrape-cost and
   cardinality numbers themselves are ALERT-40/ALERT-61's deliverable, not this chapter's.
4. Run the profile at each corpus size and on each backend.
5. Separately, time `GET /messages/search` at `scan_limit` ∈ {1 000, 10 000, `MAX_CONTENT_SCAN_LIMIT`}
   against the encrypted 100 k and 1 M corpora.

**Observation point.** The harness report JSON/CSV: API p50/p95/p99 per route, pipeline
delivered-throughput delta vs step 2, store query rate, event loop max lag. (`/metrics` render time
and body size are recorded by ALERT-40 on the same estate — do not duplicate the ceiling here.)

**Expected result.** First recorded numbers for every one of them, archived as the regression
baseline. Specifically answers whether the ~1 s per-socket `store.stats()` + server-side render at
64 sockets is acceptable (open question Q4).

**Cleanup.** Stop the engine; delete `load.db` and the scratch corpus; keep the report JSON/CSV
(metrics only, no message bodies) as the archived baseline. **Do not** archive any `dryrun`/
`generate` output.

---

#### S-API-G — Reverse-proxy and client-network topology matrix (API-20, API-61, API-70)

**Preconditions.** A W2025 box with nginx (or Caddy) and IIS+ARR installable; a second host or a
second local interface address; a server cert.

**Steps.**
1. **R2 (declared proxy).** Terminate TLS at the proxy; set `[api].tls_terminated_upstream = true`
   and `[api].trusted_proxies = ["<exact proxy peer IP>"]`. Browse `/ui` and call `/messages`.
   Observe the audit `client` column and `GET /security/posture`.
2. **XFP tripwire.** Configure the proxy to omit `X-Forwarded-Proto`, or connect over `::1` while
   `trusted_proxies` names `127.0.0.1`. Issue three `/ui` requests.
3. **`allowed_client_networks` with a proxy (R2).** Set `[security].allowed_client_networks` to a
   CIDR that excludes the browser's real address; retry.
4. **R3 (undeclared proxy).** Remove the `trusted_proxies` entry, keep the proxy. Retry step 3.
5. **Monoculture tripwire.** Confirm the engine flags `client_address_monoculture` when every
   observed address is the proxy's.
6. **Lockout diagnosability.** From a refused address, `curl http://<host>:8765/health`.

**Observation point.** Audit rows, engine log, `GET /security/posture` counters, the 403 page.

**Expected result.** Step 1: real browser address in `client`. Step 2: exactly one WARNING naming
X-Forwarded-Proto (`api/app.py:1234-1251`), and no second one on the later requests. Step 3: refused
before routing with the denial marker header. Step 4: the control is **inert** — the honest R3
limitation ADR 0151 pins — and the monoculture tripwire is lit. Step 6: `/health` answers 200 and
echoes `observed_client`, giving the locked-out operator the address the engine is matching.

**Cleanup.** Restore `[api]`/`[security]` config; restart the engine (the allow-list is
startup-only, so a lockout costs a restart — plan the maintenance window).

---

#### S-API-H — Error-handler PHI safety sweep (API-29, API-30, API-31)

**Preconditions.** An engine fixture; `caplog` at DEBUG for the API loggers.

**Steps.**
1. Enumerate every route declaring a request body (all POST/PUT/PATCH).
2. For each, POST a body that fails validation and embeds the literal marker
   `ZZPHIMARKERZZ` in the offending field (a synthetic marker, never a real HL7 body).
3. Assert `422`, and that the JSON text contains neither `"input"`, `"ctx"`, nor the marker.
4. Assert `caplog.text` contains neither the marker nor the field value — only the field locations
   and a count.
5. For one route per family, monkeypatch a dependency (e.g. `_get_engine`) to raise a custom
   exception whose `str()` is `ZZPHIMARKERZZ`. Assert `500`, body exactly
   `{"detail":"internal error"}`, and `caplog.text` contains the exception **type name** and the
   route path but not the marker.
6. Assert `app.exception_handlers[RequestValidationError]` and `[Exception]` are the module's own
   handlers, and `app.debug is False`.

**Observation point.** Response bodies and `caplog.text`.

**Expected result.** No marker anywhere in any response or log across every body-carrying route.
This generalizes `tests/test_edit_resend.py:437` from one route to the whole surface and is the
guard against a future middleware reorder or re-registered default handler.

**Cleanup.** `monkeypatch` undoes itself; no persistent state.

### 8.6 Automation disposition

**New pytest modules** (all under `tests/`):

| Module | Rows | Effort |
|---|---|---|
| `tests/test_api_openapi_snapshot.py` + `scripts/api_openapi_snapshot.py` + `tests/golden/api_openapi.snapshot` | API-01…API-03 | **M** |
| `tests/test_apiclient_route_parity.py` | API-04…API-06 | **S** |
| `tests/test_api_authz_sweep.py` | API-22…API-26 | **M** |
| `tests/test_api_error_handlers.py` | API-29…API-33 | **S** |
| `tests/test_ws_stats_lifecycle.py` | API-47…API-51 | **M** |
| `tests/test_api_pagination.py` | API-34…API-36 | **M** |
| `tests/test_api_middleware_stack.py` | API-58…API-60 | **S** |
| `tests/test_api_server_backends.py` (env-gated) | API-09…API-13 | **L** |
| `tests/test_api_wire_socket.py` (subprocess + raw sockets) | API-14…API-18, API-20, API-72, API-73 | **L** |

**Extends an existing module** (do not create a sibling):

- `tests/test_security_doc_drift.py` — API-68 (derive docs/SECURITY.md's 203/97 prose figures from
  the live walk; the module already derives `_ROUTES_DEFAULT`/`_ROUTES_WITH_UI`). **S**
- **No new FEATURE-MAP module.** API-66 and API-67 are pointer rows: the consolidated FEATURE-MAP
  drift guard is the MIG chapter's single row (MIG-74) extending `tests/test_feature_map_claims.py`.
  This chapter contributes only the ADR list and the `api/__init__.py:3-6` docstring correction.

- `tests/test_api.py` — API-53 (`/health` disclosure matrix), API-57 (docs on/off completeness),
  API-65 (grant-audit volume). **S**
- `tests/test_api_auth.py` — API-64 (concurrent limiter interaction). **S**
- `tests/test_api_tls.py` — API-17, API-27 (real-socket TLS/mTLS arms; the context-level arms are
  already there). **M**
- `tests/test_client_network_allowlist.py` — API-61 (real second-address arm). **M**
- `tests/test_upload_api.py` — API-37, API-43, API-44, API-46. **S**
- `tests/test_search_presets_api.py` — API-38, API-39. **S**
- `tests/test_message_export.py` — API-40, API-41. **S**
- `tests/test_metrics_history_graph.py` — API-56. **S**
- `tests/test_apiclient.py` — API-08 (tray `/health` key contract lives naturally beside the client
  contract tests). **S**

**New CI legs** (`.github/workflows/`):

- **`api-server-backends`** — extend the existing SQL Server / PostgreSQL legs
  (`ci.yml:484-723`, `selfhosted-win2025-sql.yml`) to also run
  `tests/test_api_server_backends.py`. This materially lengthens those legs — see Q3. **L**
- **`api-wire`** — an ubuntu + windows-2025 leg running `tests/test_api_wire_socket.py`, which needs
  a real subprocess and raw sockets and so should not ride the default fast leg. **M**
- **`ide-dto-drift`** — extend the existing Node leg (`ci.yml:290-315`) with the generated-DTO
  fixture check (API-07). **M**

**New harness / probe capability** (`harness/`):

- A new `harness/load/profiles/api-read-fanout.toml` plus an API-read driver and a `/ws/stats`
  consumer pool in `harness/load/`, reusing `harness/load/report.py` for the JSON/CSV output.
  Covers API-42, API-52, API-62, API-63. The 15 s `/metrics` scrape it drives is **background load
  only** — the scrape-cost and cardinality numbers are ALERT-40/ALERT-61's deliverable (API-54 is a
  pointer row and scopes no work here). **L**
- `harness/acceptance/probes.py` gains an API-contract probe that fetches `/health` and one gated
  route against a running engine and reports reachability + auth posture (the existing probes cover
  host prerequisites like port bindability, not the contract). **S**

**Stays manual, with the reason:**

- **API-69** — on-host loopback bind + unauthenticated reject under the NSSM service identity.
  Already owned and scripted as WIN2025-TEST-PLAN **`W25:S2.8`**; the service-identity context cannot be
  reproduced in CI. **S** (execution only.)
- **API-70** — reverse-proxy matrix (nginx / Caddy / IIS+ARR). Three real proxies, real certs and a
  real second address; the ::1-vs-127.0.0.1 mismatch is a property of the actual network stack. **L**
- **API-55** — Prometheus scraping with a production credential; needs a real Prometheus and the
  agreed scraper identity (Q11). **M**
- **API-71** — third-party penetration test / DAST. External engagement; blocked on Q10. **L**
- Browser-side `/ui` verification (CSP/nonce, `SameSite=Strict` confinement, `Sec-Fetch-Site` CSRF,
  the live dashboard swap) — needs a real browser and is owned by the web-console chapter, though it
  rides this app's middleware.
- WebAuthn passkey ceremonies, Kerberos/SPNEGO browser SSO, and OIDC against a real IdP — real
  authenticator / domain controller / tenant; owned by the auth chapter.
- Human review that a new response model carries no PHI-bearing property before it is added to, or
  deliberately omitted from, `field_authz.PHI_FIELDS`.
- Operator judgement on the legibility of the `/ui` denial page (`client_networks.py:88-109`) and
  the 403/503 copy for a locked-out human.

### 8.7 Environment, data & prerequisites

**Hosts and runtimes**

- Python **3.14+** on Linux and Windows; the CI matrix is `ubuntu-latest`, `windows-2022`,
  `windows-2025` (`ci.yml`). The new `api-wire` leg needs ubuntu + windows-2025 only.
- A **Windows Server 2025** box with NSSM and the intended production service identity
  (LocalSystem, or preferably a dedicated AD service account / gMSA) for API-69 and API-70.
  `Get-NetTCPConnection` is the bind observation tool.
- A **dev PC** with enough headroom for the load profiles (32 concurrent readers + 64 WebSocket
  consumers + the pipeline sender in one box).

**Services to stand up**

- **SQL Server 2022/2025** with **ODBC Driver 18** and `sqlcmd`; `MEFOR_TEST_SQLSERVER=1`.
  Grants `db_ddladmin` + `db_datawriter` + `db_datareader` for the test principal.
- **PostgreSQL** service container; `MEFOR_TEST_POSTGRES=1`.
- **nginx** or **Caddy**, and **IIS + ARR**, configurable for TLS termination, `X-Forwarded-*`
  and client-cert pass-through (API-70).
- **Prometheus** (or `promtool`) with a service bearer (API-55; ALERT-40/ALERT-61 reuse the same
  scraper for the cost/cardinality measurement API-54 points at).
- **Node 20+ / npm** for the IDE extension leg (API-07).

**Credentials, certs and keys — must be procured**

- A **server cert/key pair** plus an **internal CA** for client certs; an **expiring-cert fixture**
  for the ASVS 6.4.5 warn window; an **encrypted key** + `MEFOR_PFX_PASSWORD` for the encrypted-key
  arm.
- A **service bearer token** minted against the auth-on engine for every headless harness run
  (`--token <T>` — WIN2025-TEST-PLAN.md:327 makes this mandatory).
- A **store DEK** via `MEFOR_STORE_ENCRYPTION_KEY` (mint with `messagefoundry gen-key`) for the
  encrypted-at-rest upload and search arms. Secrets come from `MEFOR_*` environment variables only —
  never a file in the repo, never `.env`.
- An **AD lab** (domain controller + AD CS + a gMSA) and an **OIDC tenant** are prerequisites for
  the auth chapter's rows, not this one; API-70 needs neither.

**Configuration prerequisites**

- `[store].uploads_dir` on a writable path (default `None` ⇒ every upload route 503s,
  `config/settings.py:413`) plus `[store].max_upload_bytes` for API-16/API-44/API-46.
- `[api].expose_docs` for API-19/API-57; `[api].tls_cert_file`/`tls_key_file`/
  `tls_terminated_upstream`/`trusted_proxies` for API-17/API-18/API-20/API-70;
  `[security].allowed_client_networks` for API-61; `[security].enforcement` for the API-18 clamp arm;
  `[logging].log_dir` for the `/logs/tail` arms.

**Synthetic data — PHI-free, always**

- Corpora at **10 k / 100 k / 1 M** messages:
  `python -m messagefoundry generate --type ADT --count <n> --seed 42 --out <scratch>` (repeat for
  ORU). The corpus directory is **git-ignored by design and must never be committed**, and
  `generate`'s stdout can contain full bodies — never redirect it into a file that is committed, a
  ticket, or a CI log.
- The planted PHI marker used by API-30 is the literal string `ZZPHIMARKERZZ` — a synthetic
  canary, never a real identifier.
- Load traffic uses `harness/config/load` and the existing profiles in `harness/load/profiles/`,
  driven by `python -m harness --load <profile> --engine http://127.0.0.1:8765 --token <T>
  --sink-port <p>`.
- Reports carry **metrics and metadata only**. No report, snapshot or CI artifact produced by this
  chapter may contain a message body.

### 8.8 Exit criteria

This area is signed off for release when **all** of the following hold:

1. `tests/golden/api_openapi.snapshot` exists, is generated by a committed script, covers
   **all 121** response models (89 in `api/models.py` + 32 in `api/auth_models.py`) or names each
   omission on a reasoned exemption list, and is a **hard** CI failure on diff (subject to Q1).
   The three planted mutations in S-API-A all go red.
2. `tests/test_api_server_backends.py` runs green on **SQL Server** and **PostgreSQL** legs, with a
   zero-difference diff against the SQLite baseline for the full representative route set, and
   `POST /status/integrity-check` returns `ok` on all three after the audit writes.
3. `tests/test_api_wire_socket.py` runs green on the `api-wire` leg: CL+TE→400, chunked→411,
   invalid CL→400, oversize→413, the header/slow-loris arms bounded, and a control request succeeds
   after every abusive case. The bind-ladder arms produce the documented exit codes. The DNS-failure
   arms (API-72) bound every DNS-dependent route to a PHI-free 502/503 inside the pinned timeout,
   leave the read plane and `/health` answering, and recover with no engine restart. For the
   mid-session certificate-expiry arms (API-73) the fresh-handshake arm fails closed and the
   keep-alive arm's behaviour is pinned; the `require_service_cert`-after-`notAfter` arm is
   **expected red on today's code** and is tracked as an open finding with a named owner — it is not
   waived, and sign-off records it as outstanding rather than passing.
4. The tokenless and under-privileged sweeps cover **105** routes (and **203** with the console
   mounted) with the 2xx set exactly equal to the pinned allowlists, and the planted-gate-removal
   self-test goes red.
5. `app.state.ws_count` is proven to return to **0** on all five `/ws/stats` exit paths; the 65th
   handshake is refused; no CSWSH arm delivers a single frame; the frame-key constant is asserted on
   both the engine and the web-console side.
6. `tests/test_api_error_handlers.py` proves no `input`/`ctx`/planted-marker escapes on **any**
   body-carrying route, the 500 body is exactly `{"detail":"internal error"}`, both handlers are the
   app's own, and `app.debug is False` in every construction arm.
7. `apiclient` parity is enforced: all 49 referenced paths resolve, every `_decode` model matches its
   route's `response_model`, and the 44-path uncovered set is pinned as a reviewed constant
   (or reduced — Q2).
8. The IDE's three TypeScript DTO mirrors are checked against generated Python-side field sets in the
   Node CI leg, and the tray's `/health` `status` key is contract-tested.
9. Every one of ADRs **0046, 0130, 0131, 0134, 0136, 0142, 0143, 0150, 0151** is claimed by a row in
   this chapter (done) **and** has a docs/FEATURE-MAP.md row; the retired-PySide6-console claims at
   FEATURE-MAP.md:21, :131, :162 and `api/__init__.py:3-6` are corrected; the Federated SSO row
   reflects ADR 0142; docs/SECURITY.md:298 and :481 state **203** and **97** and a test derives those
   figures from the live walk.
10. Baseline performance numbers exist and are archived for: API read-plane p50/p95/p99 at 10 k /
    100 k / 1 M on all three backends; `/messages/search` scan latency vs `scan_limit` at 100 k and
    1 M; `/ws/stats` fan-out cost at 0/1/16/64 sockets. (`/metrics` render time and series count at
    50/200/500 outbound Connections is ALERT-40/ALERT-61's deliverable, consumed here, not produced
    here.) These are the chapter's **C** rows (API-42, API-52, API-62): the criterion is that each
    number is recorded and archived and a regression ceiling is set from the first run — no
    threshold gates this release, and each becomes a **T** row the day its ceiling is written down.
11. Pagination disposition is settled: either `GET /messages` offers a stable cursor and the
    union-of-pages test passes with zero duplicates and zero skips, or the skew is documented in
    docs/CONFIGURATION.md and the test asserts the documented bound (Q5).
12. Every pageless list route either pages or appears on the drift-guarded `_UNPAGED_EXEMPT`
    constant with a one-line reason; `GET /uploads` visibility is pinned as a reviewed decision
    naming ADR 0134 (Q6).
13. Middleware order is pinned for both `serve_ui` arms and the vacuity self-test (a middleware
    inserted after the attachment CSP writer) goes red.
14. WIN2025-TEST-PLAN **`W25:S2.8`** is executed on the W2025 box under the NSSM service identity and
    its result is recorded into MANUAL row **`W25:S1.AC-API`**; the reverse-proxy matrix (API-70) is executed
    for at least nginx and IIS+ARR with the XFP tripwire and R3-inert arms observed.
15. `ruff check`, `ruff format --check`, `mypy` (strict) and the full `pytest` suite are green on
    `ubuntu-latest`, `windows-2022` and `windows-2025`, plus the two new legs.
16. No artifact produced by this chapter — snapshot, report, CI log, ticket — contains a message
    body. Verified by a grep for the planted marker and for `MSH|` across the produced artifacts.

### 8.9 Open questions

1. **Is the OpenAPI golden a hard CI gate or advisory?** A hard gate (matching
   `tests/golden/webconsole_seam.snapshot`) means every additive response field becomes a reviewed
   snapshot refresh — real friction, real safety. Advisory means it can be ignored under deadline.
   *Blocks:* API-01…API-03 design and the exit criterion 1 wording.
2. **Should `apiclient` reach full parity with the 105 routes, or is the 49-path subset a deliberate
   "operator CLI + harness only" scope?** *Blocks:* whether API-06 pins the 44-path uncovered set as
   permanent or as a burn-down list.
3. **Do we run `create_app` against SQL Server and PostgreSQL in CI, or is store-layer parity
   considered sufficient?** A full API-over-server-DB leg materially lengthens the already-long SQL
   legs. *Blocks:* API-09…API-13 and the P0 exit criterion 2.
4. **Is the ~1 s per-socket `store.stats()` + server-side connections render at 64 concurrent
   `/ws/stats` sockets acceptable, or should the sampler be shared process-wide (one sampler,
   fan-out to sockets)?** *Blocks:* whether API-52's measurement is a baseline or a defect report.
5. **Should `GET /messages` gain a stable cursor/keyset option, or is the DESC+offset skew on a live
   feed an accepted, documented operator-facing limitation?** *Blocks:* API-34's pass criterion.
6. **Is `GET /uploads` intended to show every uploader's files to any `files:browse` holder, or
   should it be owner-scoped like search presets?** ADR 0134 says "authorized operators" but does not
   settle it, and original filenames can carry identifiers. *Blocks:* API-37.
7. **Should `[api].expose_docs = true` be refused, or only warned, on a non-loopback /
   proxy-terminated bind?** The bind ladder currently does not consult it at all. *Blocks:* API-19's
   pass criterion.
8. **Who owns correcting docs/FEATURE-MAP.md this cycle** — the retired PySide6 console rows (:21,
   :131, :162), the missing rows for ADRs 0046/0130/0131/0134/0136/0150/0151, and the ⏭️ Federated
   SSO row now built as ADR 0142 — and does docs/SECURITY.md's 201/95 figures get corrected to
   203/97 in the same change? *Blocks:* API-66…API-68.
9. **Does FEATURE-COVERAGE-PLAN.md §15 get amended in place with the 2026-07 wave, or does this
   chapter claim those surfaces and cite §15 only for `FCP:API-1`…`FCP:API-29`?** This chapter currently assumes
   the latter. *Blocks:* whether §15 needs an edit before sign-off.
10. **Is a third-party penetration test / DAST in scope for this release?** docs/FEATURE-MAP.md:136
    states the standing no-pentest risk acceptance is **void on any off-loopback or production
    exposure**, and ADR 0143 makes the console on by default. *Blocks:* API-71, and arguably the
    release posture itself if this ships an off-loopback default.
11. **What is the intended production authentication for a Prometheus scraper** — a long-lived local
    service-account bearer, or should `/metrics` gain the mTLS service-cert plane
    (`require_service_cert`) like `/service/identity`? *Blocks:* API-55.
12. **Should the `/ws/stats` frame key set and the IDE's three TypeScript mirrors be pinned by a
    two-sided shared constant, or generated from the OpenAPI golden once it exists?** Generating from
    the golden removes a second hand-maintained artifact but couples the Node leg to the Python
    build. *Blocks:* API-07 and API-51 implementation shape.
