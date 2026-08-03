[← Master Test Plan index](../MASTER-TEST-PLAN.md) · *Part II — Subsystem chapters*

---

## 10. Web Console (/ui)

**ID prefix:** `WEB` · **Surface:** web console
· **Primary risk:** the sole operator console's client-side security controls (the ASVS 14.3.1 session
watchdog that discards rendered PHI, both WebAuthn ceremonies, the live-fragment redirect guard) are
1,506 lines of `messagefoundry_webconsole/static/app.js` that **no test ever executes** — and no test
ever drives the console through a real browser, a real TLS listener, or a real reverse proxy.

### 10.1 Scope & objectives

This chapter covers the same-origin, server-rendered browser operations console
`messagefoundry_webconsole` — grafted onto the engine's FastAPI app by
`mount_ui` ([`messagefoundry_webconsole/mount.py:69`](messagefoundry_webconsole/mount.py)), ADR 0065 /
ADR 0143. It is the **sole** operator console; the PySide6 desktop console was retired (BACKLOG #103)
and PySide6 now backs only the standalone test harness. ~11.2k LOC of Python plus 1,506 lines of
`app.js` and 345 lines of `app.css`, shipped as a separately-versioned second wheel
(`packaging/messagefoundry-webconsole/`) with its own ~347-test suite run as a second CI step.

**In scope.** Every page and flow of the 98-route `/ui` surface pinned at
[`packaging/messagefoundry-webconsole/tests/golden/ui_routes.txt`](packaging/messagefoundry-webconsole/tests/golden/ui_routes.txt):
login and provider select, Kerberos/SPNEGO SSO, OIDC federated login, TOTP MFA lifecycle, WebAuthn
passkeys, must-change-password and `/ui/mfa` confinement; the connections dashboard, live fragment poll
and `/ws/stats` server-rendered enrichment, bulk connection control, per-connection and bulk statistics
reset, connection detail and the kind-filtered event log; the message log, dead-letter list, the audited
raw-detail / parse-tree / attachment-download PHI path, edit-and-resubmit, content search and saved /
layered presets; replay and dead-letter operations behind step-up-to-unlock (per-connection and
all-channels), queue purge; the config page, provenance badge and config reload; users / roles /
channel-scope / AD-group-map admin; self-service account and active-session management; audit and
security-events views; alerts, DR activate/release, store integrity check; the status page (health
rollup, security posture, FIPS and memory-encryption rows, cluster + DR, service badge,
update-available signal) and the nav-status badge; offline uploaded-log upload / browse / resend /
delete. Security properties: cookie confinement, token-free CSRF, the nonce CSP and the ASVS 3.7.5
degrade contract, template autoescape, clickjacking, the loopback secure-context posture (ADR 0143) and
the off-loopback exposure ladder (ADR 0068). Plus: browser and device matrix, accessibility, responsive
layout, long-session and token-expiry behaviour, error / empty / degraded / engine-down states,
performance and pagination at scale, and concurrent operators.

**Explicitly NOT in scope here.**

| Area | Owner |
|---|---|
| The 32-row `/ui` coverage-gap audit (rows `FCP:UI-1`..`FCP:UI-32`, six dimensions) | [`docs/testing/FEATURE-COVERAGE-PLAN.md`](docs/testing/FEATURE-COVERAGE-PLAN.md) §23, lines 1469–1517. Cited, not restated. Open rows: **FCP:UI-8**, **FCP:UI-23**, **FCP:UI-32**; **FCP:UI-12 closed 2026-07-13** (P2 STATUS block, `:142-152`). (`FCP:` marks a FEATURE-COVERAGE-PLAN ID; a bare `WEB-nn` is always this plan's own row.) |
| Package architecture, the three-layer seam handshake, the version-skew gate, dev-and-test instructions | [`docs/WEBCONSOLE-PACKAGE.md`](docs/WEBCONSOLE-PACKAGE.md) |
| Config-deploy semantics, promote/stage, provenance | the **PUB** chapter (this chapter tests only the console's *rendering and gating* of config reload) |
| Windows Server 2025 host / service-identity acceptance | [`docs/testing/WIN2025-TEST-PLAN.md`](docs/testing/WIN2025-TEST-PLAN.md) + [`WIN2025-TEST-MATRIX.md`](docs/testing/WIN2025-TEST-MATRIX.md) — but note: **neither carries a single `/ui` row** (verified: zero matches for `/ui`, "web console", "webconsole"). WEB-57/WEB-59 below add them (`W25:` marks a WIN2025 / acceptance-matrix ID); the *host* setup stays theirs. |
| Pipeline throughput | [`docs/LOAD-TESTING.md`](docs/LOAD-TESTING.md). This chapter adds only console-induced load and the engine-throughput delta it causes. |
| The VS Code IDE extension (Steps view, connections graph, ADR 0076/0091/0103) | the **IDE** chapter |
| Engine JSON API authz/PHI semantics | the **API** chapter. The console calls the same handlers through `UiDeps`; this chapter tests the `/ui` *gate* and *projection* on top. |

**Recon corrections made during authoring.**
1. The golden route/write-action files live at `packaging/messagefoundry-webconsole/tests/golden/`, **not** `tests/golden/` — `tests/golden/` holds only `webconsole_seam.snapshot`.
2. "Console default-ON" is narrower than stated: default-ON applies to **loopback binds only**. A *non-explicit* default-on console on an exposed bind **auto-degrades to JSON-only with a warning** ([`messagefoundry/__main__.py:1703-1727`](messagefoundry/__main__.py)); only an explicit `[security].serve_web_console=true` reaches the exposure ladder at `:1734-1827`.
3. The `[security]` public-origin key is `web_console_public_address` (aliased to `[api].public_origin`, [`config/settings.py:3479,3815`](messagefoundry/config/settings.py)) — the CLI messages name the `[security]` form.
4. Simulated-scheme ASGI clients live in `test_ui_hardening.py:34-37`, not `conftest.py:37` (which is the shared `engine` fixture).
5. `app.js` **does** set `aria-sort` (`app.js:708`) and the sort trigger **is** a native `<button>` (`app.js:794-804`) — keyboard-operable. What has no keyboard path is column **resize** (`app.js:832-863`, pointer events only) and column **reorder** (`app.js:880-911`, native HTML5 drag only). There is not one `keydown` listener in the file.
6. Page-builder approval line numbers: `pages/config.py:96-105`, `pages/connections.py:207-212`, `pages/messages.py:676-685`.
7. **New finding, not in the recon:** the console exposure ladder's operator-facing CLI messages point at `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` six times (`__main__.py:1724, 1763, 1779, 1792, 1803, 1814`), and 12+ ADRs link it — but `docs/security/` is **withheld from the public repo**, git-ignored post-cutover (`.gitignore:144`, rationale at `:148`: "32 files of posture/risk-register detail; an attacker roadmap"). The runbook is a real, maintained document on the owner's side; what does not exist is a *reachable copy* for an operator working from the published distribution, who hits the refusal and finds nothing at the path the CLI names. The defect is the dangling operator-facing path, not a missing document. See WEB-56.

### 10.2 Already covered — do not re-test

| Evidence | What it proves |
|---|---|
| `packaging/messagefoundry-webconsole/tests/test_webui.py` (243 tests, 5389 lines) | The bulk of `/ui` behaviour: cookie confinement, the JSON-API bearer boundary, CSRF on every write, replay / dead-letter / purge / bulk-control / stats-reset, users+roles+AD maps, account+MFA+passkeys+sessions, search, alerts/status/events, config reload, edit-and-resubmit, OIDC, SSO, off-loopback cookie/HSTS header strings. |
| `test_ui_csp_canary.py` (22 tests) | The ASVS 3.7.5 degrade contract is derived from CODE (header writes, `window.<Feature>` reads, `set_cookie` attributes) and every member is bucketed; canary emission/ordering, no-nonce byte-identity, and per-entry report filtering that still warns on a real violation. |
| `test_ui_session_watchdog.py` (21 tests) | The **server** half of ASVS 14.3.1: `activity=False` on background polls, `/ui/session-status` remaining-seconds + 303, `Clear-Site-Data` on every termination shape, the watchdog hook on every authenticated page. |
| `test_ui_hardening.py` (11 tests) | `__Host-` cookie over https, plain-cookie byte-identity over cleartext, loopback engaging headers while keeping the plain cookie (ADR 0143), nonce-CSP/COOP/CORP/Reporting, static asset not wrapped, org opt-out reverts. |
| `test_ui_origin_guard.py` (11 tests) | `Sec-Fetch-Site`/`Origin` refusal on the two unauthenticated POSTs, rejection preceding the rate limiter, and a **code-derived** check that every `/ui` POST route asserts request origin. |
| `test_ui_mfa_gate.py` (12) · `test_ui_logout_affordance.py` (10) · `test_ui_static_allowlist.py` (5) | ASVS 6.3.3 browser confinement (pending session pinned to `/ui/mfa`, no code echo, must-change outranks MFA); ASVS 7.4.4 sign-out affordance on every nav-suppressing page with an exhaustive accounting test; ASVS 13.4.7 runtime extension allowlist (`_static.py:42` — only `.css`/`.js`; planted `.env`/`.bak`/`.map`/`.py` 404 before any stat). |
| `test_golden_surface.py` (3) + `tests/golden/ui_routes.txt` (98) + `ui_write_actions.txt` (25) | The exact `(method, path)` surface, the step-up write-action pattern set, and 5 literal-before-`{param}` orderings are pinned against drift. |
| `test_pages_config.py` (4) · `test_search_presets_ui.py` (1) · `test_uploaded_logs_ui.py` (4) | Config provenance badge states; preset save + layer; uploaded-logs happy path / viewer denial / 503-unconfigured / consent affordance. |
| `tests/test_webconsole_mount.py` (4) · `tests/test_webconsole_absent.py` · `tests/test_webconsole_seam_snapshot.py` + `tests/golden/webconsole_seam.snapshot` | Engine-side mount smoke + a filesystem walk pinning `{app.css, app.js, csp-probe.js}`; engine boots and serves JSON with the wheel absent, plus the ADR 0143 soft-degrade vs explicit hard-refuse (exit 2); `ENGINE_UI_SEAM`, `UiDeps`/`CoreHandlers`/`AdminHandlers` field sets and rendered-DTO fields cannot change unbumped. |
| `tests/test_cli.py:1137-1370` | The whole serve-time exposure ladder as a unit: upstream proxy requires `public_origin`, `http://` `public_origin` refused under declared TLS, undeclared-proxy warning, ASVS 8.4.2 guidance, default-on loopback mounts, explicit off-loopback still refuses, default-on off-loopback degrades to JSON-only. |
| `tests/test_security_config.py:82-156` | `[security].serve_web_console` default `True`, rejection of the relocated raw `[api].serve_ui` in user TOML, the `serve_ui_explicit` marker. |
| `tests/test_webauthn*.py`, `tests/_webauthn_store_contract.py`, `tests/test_auth_oidc*.py` | Passkey ceremony verification + credential store across all three backends with sign-count CAS clone detection; OIDC service / flow-cache / PKCE mechanics — all against soft/mock counterparts. |
| `.github/workflows/ci.yml:159, :194, :254` · `codeql.yml:55` · `release.yml:353-450` | Console wheel installed editable; `mypy --strict` covers `messagefoundry_webconsole`; the package suite runs as a second pytest step on the same ubuntu + windows legs against the same engine build; `app.js` is inside CodeQL's `javascript-typescript` scope; the wheel builds and publishes independently on `webconsole-v*` tags. |
| `messagefoundry/tray/probe.py:97-104` + `tests/test_tray_probe.py` | A tokenless `GET /ui` probe distinguishes console-off (404) from mounted (303 to `/ui/login`) — the tray's console-enabled signal and deep-link target. |
| `tests/test_security_static.py`, `test_phi_logging_inventory.py`, `test_crypto_inventory_scanner.py`, `test_asvs_file_surface_doc_drift.py` | Cross-cutting static gates whose scan scope includes `messagefoundry_webconsole`. |
| `tests/test_webconsole_monitoring_fips.py` | The status page's FIPS row renders as "reported", never as a FIPS-140 certification (ADR 0120 AC-5). |

**DONE — do not re-plan.** Server-side authentication, RBAC, CSRF, CSWSH, cookie confinement, the
JSON-API bearer boundary, autoescaping, the static allowlist, the step-up-to-unlock primitive and the
action-bound single-use grant, the MFA/must-change confinement gates, the golden route + write-action
+ seam surfaces, the ASVS 3.7.5 degrade contract as a *code-derived* set, and the serve-time exposure
ladder as *CLI unit logic* are all mature and deeply covered. FEATURE-COVERAGE-PLAN §23 already grades
all of it. Everything below is either (a) a layer those tests structurally cannot reach — real browser
execution, real TLS, real scale, real concurrency, real assistive tech — or (b) a specific named gap
that audit left open (FCP:UI-8, FCP:UI-23, FCP:UI-32) or that this pass newly found.

### 10.3 Risk analysis

| Risk | Failure mode | Blast radius | Detected today? | Priority |
|---|---|---|---|---|
| `app.js` is never executed by any test | A refactor preserving the grep-matched strings but breaking execution (a thrown init, a changed selector, a bad `await`) silently disables the 14.3.1 watchdog | Rendered PHI stays on an abandoned or terminated tab indefinitely; both WebAuthn ceremonies dead; live fragment stops updating | **No.** `test_ui_session_watchdog.py:396-486` reads `app.js` as text and compares `index()` positions. CodeQL SAST only. | **P0** |
| Never served through real uvicorn + TLS + a browser cookie jar | Browser silently **rejects** the `__Host-`/`Secure` cookie, or the nonce CSP is not actually enforced | Login broken, or a script-injection control believed present is absent — first discovered by the first customer to expose `/ui` off-box | **No.** Everything is `httpx.ASGITransport` with a simulated scheme (`test_ui_hardening.py:34-37`). | **P0** |
| Dual-control operations initiated from `/ui` cannot be approved from `/ui` | Config reload / purge / bulk dead-letter replay held for approval renders "Approval id: X" and dead-ends (`pages/config.py:96-105`, `pages/connections.py:207-212`, `pages/messages.py:676-685`) | Under incident pressure the second approver must drop to the JSON API — or the org disables dual-control, defeating the control via its own UX | **No.** No `/ui/approvals` route in the golden table; no approvals field in the seam snapshot. Engine has `GET /approvals` + approve/reject at `api/app.py:2692-2721`. | **P0** |
| Three `app.js` features fetch `/ui` routes that do not exist | `/ui/logging/level` (`app.js:1259`), `/ui/logs/tail` (`:1308`), `/ui/messages/export` (`:1385-1386`, fetch at `:1412`) — no route, and no page builder emits `data-mf-log-level` / `data-mf-log-viewer` / `data-mf-msg-export` | ADR 0130/0131 and FEATURE-MAP present shipped capabilities that are unreachable; a PHI-egress feature is documented shipped with its audit/step-up path never exercised | **No.** Nothing in CI resolves a `fetch("/ui/...")` literal against the route table. | **P1** |
| No pagination controls anywhere | Message log and dead-letters accept `limit`/`offset` (`routes/core.py:410-411`, `:519-520`) but render a text readout only (`pages/messages.py:113-117`, `:601-605`); audit is hard-coded `limit=200` with no offset or filter (`routes/audit.py:30,38`); search takes `limit` with no `offset` at all (`routes/search.py:66`) | An incident investigator sees the newest 50 messages / 200 audit rows and cannot page back **in the console at all** — a blind spot on the tamper-evident trail a HIPAA investigation depends on | **No.** FEATURE-COVERAGE-PLAN rows FCP:UI-8 and FCP:UI-23 are open. | **P1** |
| No render-at-scale test, no performance budget | The connections fragment is re-rendered **server-side** and pushed on every `/ws/stats` tick to every connected operator (`api/app.py:4850-4852`, `pages.connections_fragment`) | A linear render over hundreds of Connections × N operators contends with the same event loop that runs the pipeline — presents as a *delivery* problem | **No.** `docs/LOAD-TESTING.md` covers pipeline throughput only. | **P1** |
| No negative PHI-render invariant | A new page, fragment or widened DTO field surfaces a message body on an unaudited route | Unaudited PHI exposure — exactly what the "single audited PHI path" design exists to prevent | **No.** The claim rests on construction plus one positive audit test (`test_webui.py:248`). | **P1** |
| Zero accessibility coverage; no WCAG target declared in the product docs (this plan adopts **WCAG 2.2 AA** — WEB-47/WEB-51 — pending owner ratification under Q2) | CSS-only `:hover`/`:focus-within` nav with `aria-expanded` deliberately omitted (`_html.py:463-465`); `.filterbox:focus{outline:none}` (`app.css:161`); column resize/reorder pointer-only | Procurement and (US public-sector / health) legal exposure; keyboard-only operators cannot resize or reorder a grid at all | **No.** One `aria-haspopup` count assertion (`test_webui.py:889`). | **P1** |
| No supported-browser matrix; `SYSTEM-REQUIREMENTS.md` materially wrong | Line 5 "the console is a separate desktop application"; line 121 "Desktop console — PySide6 … install with the `console` extra" (**no such extra**, `pyproject.toml:79-113`); line 123 "opt-in read-only ops dashboard … off by default" (ADR 0143 flipped it on; it performs replay, purge, config reload and user admin) | An evaluator sizes an install against a retired product and a nonexistent pip extra, understating the console's privilege; support cannot arbitrate a browser-specific defect | **No.** | **P1** |
| Unhandled `/ui` exception returns the engine's JSON 500 | `{"detail":"internal error"}` with a JSON content type (`api/app.py:1195-1204`) on an HTML route — no nav, no sign-out, no indication whether the engine or the session died | Operator blind spot during the incident the console exists to serve. Only `/ui/nav-status` guards its probes (`routes/status.py:131-176`). | **No.** | **P1** |
| No concurrent-operator test at the `/ui` layer | Two sessions racing bulk control on the same Connection; purge racing a replay; two step-ups against the same single-use ADR 0077 grant; a role edit racing the self-disable guard | Silent last-writer-wins on a destructive op, or a double-consumed single-use grant locking an operator out | **No.** | **P1** |
| The web console has **no row** in `harness/acceptance/matrix.py` or `WIN2025-TEST-MATRIX.md` | Both still carry retired-desktop rows: **W25:A7** "Console runs (Desktop Experience, PySide6)" with `probe_console_gui` naming the nonexistent `[console]` extra (`matrix.py:153-160`, `harness/acceptance/probes.py:170-179`), and **W25:F7** "No console-window flash" (`matrix.py:414-421`) | The Windows Server 2025 acceptance artifact used to sign off a host reports **nothing** about the operator console and reports MANUAL/SKIP rows about a retired product | **No.** | **P1** |
| Uploaded logs writes real HL7 PHI at rest, then decrypts and renders it — 4 tests | `POST /ui/uploaded-logs/upload` uses `require_ui(FILES_UPLOAD)` (`routes/uploaded_logs.py:63-70`) while the JSON twin uses `require_step_up(FILES_UPLOAD)` (`api/app.py:3667`) | A documented-but-unasserted step-up divergence can be widened either way with no failing test; browse-decrypt audit is unasserted at the `/ui` layer | **No.** | **P1** |
| `POST /ui/csp-report` unauthenticated, no rate limit | Guarded only by `assert_not_cross_site` (`routes/core.py:1025`); a conforming browser posts one canary report per page load | Unbounded WARNING-log writes from anyone who can reach `/ui` — log amplification / disk pressure on a host where the store shares the drive | **No.** Per-report content is bounded; frequency is not. | **P2** |
| Diff-coverage advisory is blind to the console | `quality-advisory.yml:311` runs `pytest -q --cov=messagefoundry` — the **engine** suite only | Every PR touching console code gets a diff-coverage report with no data for those lines, on the largest security-relevant surface in the repo | **No.** | **P2** |
| Stale CI seam-matrix comment | `ci.yml` (~:240-250) still says "the console now supports a RANGE (SUPPORTED_ENGINE_SEAMS), so the back-compat claim … is NOT exercised anywhere" — BACKLOG #279 narrowed it to `frozenset({15})` (`messagefoundry_webconsole/__init__.py:48`) precisely to remove that claim | Normalizes re-widening; a re-widened set without the promised MIN/MAX matrix renders `AttributeError`s at an operator instead of refusing at startup | **No.** | **P2** |
| Console suite is SQLite-only | The `/ui` layer adds its own projection, limit/offset defaults and scan ceilings on top of the shared handlers | A backend-specific ordering or NULL-handling difference shows as wrong rows on an operator page | Argued `na` in FEATURE-COVERAGE-PLAN §23 auditor notes. Low probability, moderate impact. | **P2** |

### 10.4 Test matrix

**Row class (`Cls`).** **T** = *Test* — a falsifiable assertion with an observable pass criterion;
**only T rows count toward the release gate.** **C** = *Characterisation* — produces a recorded
measurement, finding or dated owner decision with no threshold yet; legitimate work, but it **cannot
fail**, so it never gates a release (a C row becomes a T row the day its threshold is recorded).
**A** = *Assurance* — an external engagement (pen test, third-party review, DAST), blocking only for
an off-loopback / production-exposure release and excluded from the ordinary P0 count.

**This chapter has 72 rows: 69 T, 3 C, 0 A.** Of the 69 T rows, **16 are P0** — WEB-01..WEB-07,
WEB-09, WEB-10, WEB-15, WEB-17..WEB-20, WEB-22, WEB-34. (An earlier count of 17 swept in **WEB-21**,
which is **P1**: the runtime exposure-ladder walk, not a P0.) The 3 C rows are **WEB-50** (screen-reader
coherence), **WEB-70** (autofill / print / copy behaviour) and **WEB-71** (degraded-state legibility)
— each yields a written finding, not a threshold, so none of them may red a release. No row here is
an external assurance engagement; if the owner commissions a pen test of an exposed `/ui`, it lands
as a new **A** row, not inside these.

Three rows (**WEB-55**, **WEB-56**, **WEB-58**) are **pointer rows**: the deliverable is owned by
another chapter, this chapter scopes no separate work, and the row exists only so the WEB surface's
coverage stays legible end-to-end. A pointer row keeps its ID, carries Method `—` and Cls **T**, and
gates through its owner's row, not a second time here.

**Foreign IDs are prefixed.** `FCP:` = a [`docs/testing/FEATURE-COVERAGE-PLAN.md`](docs/testing/FEATURE-COVERAGE-PLAN.md)
gap ID (`FCP:UI-8`), `W25:` = a WIN2025 / `harness/acceptance/matrix.py` row (`W25:A7`). A bare
`WEB-nn` is always this plan's own row; unprefixed cross-chapter IDs (`MIG-28`, `TRAY-67`) are other
chapters of *this* plan.

| ID | Test | Type | Method | Env | Backend | Cls | Pri | Pass criteria |
|---|---|---|---|---|---|---|---|---|
| WEB-01 | Headless-browser CI leg exists: a real browser loads `/ui/login`, signs in and reaches `/ui` | Functional | browser | container-CI | SQLite | T | P0 | Leg green in CI; page reports `document.readyState==="complete"`, zero uncaught errors on `window.onerror`/`unhandledrejection`, and `app.js` responded 200 with `Content-Type: text/javascript`. |
| WEB-02 | Watchdog leg 1 — server-terminated session blanks the document **before** navigating | Negative/Security | browser | container-CI | SQLite | T | P0 | With a PHI detail page open, revoke the session server-side; within ≤35 s (one `PROBE_MS` tick) `document.body.childElementCount === 0` **and** `document.title === "Session ended — MessageFoundry"` are observed *before* the URL becomes `/ui/login?e=expired`. A seeded synthetic needle is absent from `document.documentElement.outerHTML` at the observation point. |
| WEB-03 | Watchdog leg 2 — absolute deadline fires on an idle tab | Negative/Security | browser | container-CI | SQLite | T | P0 | With `[auth]` absolute lifetime compressed to ≤120 s, an untouched PHI page blanks and lands on `/ui/login?e=expired` within deadline + 2 s, with no operator interaction. |
| WEB-04 | Watchdog leg 3 — unconfirmable session (engine killed / network down) still terminates | Negative/Security | browser | container-CI | SQLite | T | P0 | Kill the engine with a PHI page open and `STALE_LIMIT_MS` compressed; the document blanks even though `location.replace` cannot complete. Assert blanking, not navigation. |
| WEB-05 | Live fragment poller surfaces (never follows) the auth 303 | Negative/Security | browser | container-CI | SQLite | T | P0 | With the dashboard open, revoke the session; the `[data-mf-fragment]` container (`app.js:975`) never receives login-page markup — assert the container's innerHTML contains no `<form action="/ui/login"`. |
| WEB-06 | WebAuthn enrolment through a virtual authenticator | Functional | browser | container-CI | SQLite | T | P0 | CDP virtual authenticator attached; enrol from `/ui/account`; the credential appears in the passkey list on reload and a subsequent step-up succeeds with it. |
| WEB-07 | WebAuthn step-up assertion through a virtual authenticator | Functional | browser | container-CI | SQLite | T | P0 | A step-up-gated action (message replay) completes via `POST /ui/reauth/webauthn` with no password entry; the audit trail records the passkey factor. |
| WEB-08 | WebAuthn-absent browser degrades visibly | Negative/Security | browser | browser-matrix | SQLite | T | P1 | With `window.PublicKeyCredential` deleted, the enrol button has `disabled` set and the status line reads the documented copy ("This browser does not support passkeys."); no unhandled rejection. |
| WEB-09 | Live `/ws/stats` fragment swap preserves bulk-toolbar selection | Negative/Security | browser | container-CI | SQLite | T | P0 | Select two Connections, force a WS push that reorders/adds rows; after the swap exactly those two `data-mf-conns-cb` remain checked, by name. Then Stop applies to exactly those two names — asserted against the engine's connection state, not the DOM. |
| WEB-10 | WS drop falls back to the fragment poll and resumes | HA/Resilience | browser | container-CI | SQLite | T | P0 | Sever the socket; the dashboard continues to reflect a server-side state change within 2 poll intervals; on socket restore, duplicate updates do not double-apply (row count stable). |
| WEB-11 | Table sort / resize / reorder execute and persist | Functional | browser | container-CI | SQLite | T | P1 | Click-sort cycles asc→desc→none with `aria-sort` set/removed on exactly the active `<th>` (`app.js:701-709`); a pointer resize changes the `<col>` width; a drag reorder permutes cells by `data-mf-orig`; all three survive a reload from `localStorage` and are scoped per table key. |
| WEB-12 | Connections filter box + flagged-only filter | Functional | browser | container-CI | SQLite | T | P2 | Typing filters visible rows to matching names only; the flagged-only checkbox intersects with it; a hidden row's checkbox is not counted by the toolbar. |
| WEB-13 | Step-up auto-submit retry round-trips in a real browser | Functional | browser | container-CI | SQLite | T | P1 | With a stale step-up window, clicking Replay lands on `/ui/reauth`; after re-auth the browser auto-POSTs the original body-less action and the replay is observed in the store. No manual re-click. |
| WEB-14 | Edit-and-resubmit Modified badge + Revert | Functional | browser | container-CI | SQLite | T | P1 | Editing the textarea reveals the Modified badge; Revert restores the byte-identical original (compare a hash of the textarea value, never the body itself); mode radios toggle the reroute/direct fields. |
| WEB-15 | ASVS 3.7.5 detects actually fire in a real browser | Negative/Security | browser | browser-matrix | SQLite | T | P0 | (a) On a normal secure-context load, `#mf-csp-degraded-banner` is **absent** and the browser console shows the un-nonced `csp-probe.js` blocked; (b) with JS disabled, `#mf-scripts-blocked-banner` is **visible**; (c) over a cleartext non-loopback hop, `#mf-insecure-context-banner` is visible. |
| WEB-16 | Nav-status heart/bell recolour without `innerHTML` | Negative/Security | browser | container-CI | SQLite | T | P2 | Health transitions ok→warn→down flip only `classList` + `title`/`aria-label`; a MutationObserver records no `innerHTML` write into the glyph spans; a 403 hides the whole cluster. |
| WEB-17 | Real TLS: a browser stores and returns `__Host-mf_session` | Negative/Security | external | W2025-box | SQLite | T | P0 | Engine served by real uvicorn with `[api].tls_cert_file` on a non-loopback DNS name; after login the browser cookie jar contains `__Host-mf_session` with `Secure`, `HttpOnly`, `SameSite=Strict`, `Path=/`, **no** `Domain`; a subsequent navigation is authenticated. |
| WEB-18 | Real TLS: HSTS present and the nonce CSP is genuinely enforced | Negative/Security | external | W2025-box | SQLite | T | P0 | `Strict-Transport-Security` present on `/ui`; an injected un-nonced inline `<script>` (served from a test-only page under the same policy) is **blocked** by the browser and produces a `POST /ui/csp-report` entry that is *not* filtered as the canary. |
| WEB-19 | Off-loopback through a real reverse proxy with `public_origin` | Negative/Security | external | W2025-box | SQLite | T | P0 | nginx or IIS ARR terminating TLS, `[api].tls_terminated_upstream` + `[security].web_console_public_address` set to the external origin; full walk succeeds in a browser: login → step-up → audited PHI raw view → logout. Cookie is `__Host-` prefixed, HSTS present, and the audit rows carry the acting user. |
| WEB-20 | Real cross-site POST from a foreign origin is refused | Negative/Security | external | W2025-box | SQLite | T | P0 | A page on a different origin auto-submits a form to `POST /ui/connections/{name}/stop`; the browser sends no session cookie **and** the response is 403 (`Sec-Fetch-Site: cross-site`). The target Connection's state is unchanged. |
| WEB-21 | Off-loopback ladder verified at **runtime**, not just as CLI unit logic | Negative/Security | external | W2025-box | n/a | T | P1 | Four real `messagefoundry serve` invocations: (a) non-loopback + no TLS → exit 2 with the `refusing to serve the browser ops dashboard` message; (b) declared proxy + no public origin → exit 2; (c) `http://` public origin under declared TLS → exit 2; (d) default-on + exposed bind → **starts**, warns, and `GET /ui` returns 404 while `GET /health` returns 200. |
| WEB-22 | Dual-control approvals can be completed in the console | Functional | pytest | dev-PC | SQLite | T | P0 | With `[approvals]` gating `config_reload`: operator A triggers the reload and lands on the held page; operator B (distinct identity) sees it in a console approvals surface, approves, and the reload executes. Self-approval by A is refused; approve/reject require the approvals RBAC permission and a fresh step-up. **Until built:** the held page names the JSON-API/CLI approval path explicitly instead of dead-ending. |
| WEB-23 | Static guard — every `fetch("/ui/…")` literal in `app.js` resolves to a mounted route | Negative/Security | pytest | dev-PC | n/a | T | P1 | Parse every string literal passed to `fetch(` in `app.js`, strip the query, and match it against the mounted `/ui` route table (path-param aware). Currently fails on `/ui/logging/level`, `/ui/logs/tail`, `/ui/messages/export`. |
| WEB-24 | Static guard — every `feature("[data-mf-*]")` hook is emitted by ≥1 page builder | Negative/Security | pytest | dev-PC | n/a | T | P1 | Extract every hook selector registered via `feature(`/`securityFeature(` and assert each appears in rendered output from at least one `pages.*` builder. Currently fails on `data-mf-log-level`, `data-mf-log-viewer`, `data-mf-msg-export`. |
| WEB-25 | Route-shadow guard generalized beyond the 5 hard-coded pairs | Negative/Security | pytest | dev-PC | n/a | T | P1 | Derive every (literal, `{param}`-sibling) pair from the mounted route table and assert literal-first ordering for **all** of them — not the 5 in `test_golden_surface.py:93-98`. A hypothetical `/ui/messages/export` registered after `/ui/messages/{message_id}` fails. |
| WEB-26 | Message log pagination controls | Functional | pytest | dev-PC | SQLite | T | P1 | Seed 137 messages; `GET /ui/messages?limit=50` renders Next (and no Prev); page 2 renders both; the last page renders Prev only; `offset` beyond `total` renders an explicit empty state, not a blank table. Closes FCP:UI-8. |
| WEB-27 | Dead-letter list pagination controls | Functional | pytest | dev-PC | SQLite | T | P1 | Same shape as WEB-26 against `GET /ui/dead-letters`; the per-channel / per-(channel,destination) replay forms are derived from the **current page** and each names its exact scope. |
| WEB-28 | Audit + security-events pagination, filter, and escaping | Functional | pytest | dev-PC | SQLite | T | P1 | Seed 250 audit rows including HTML metacharacters in actor/detail; the page exposes offset paging and at least an actor or action filter; rendered rows are escaped (no live `<script>`/`<img onerror>`); no message body or PHI field appears. Closes FCP:UI-23. |
| WEB-29 | Search result ceiling is disclosed, not silently truncated | Functional | pytest | dev-PC | SQLite | T | P1 | With more matches than `limit`, the page states that results were capped and at what value; `routes/search.py` has no `offset` today, so either paging is added or the cap is stated in the rendered page. |
| WEB-30 | Connections dashboard render budget at 500 Connections | Performance | load-harness | dev-PC | SQLite | T | P1 | **Budget adopted by this plan** (a proposal the owner may overrule under Q8 — but the row fails against these numbers until it is overruled, so it is a T, not a placeholder): `GET /ui/connections` **p50 ≤ 400 ms** and **p99 ≤ 1200 ms**, measured server-side over 50 sequential requests on a seeded 500-Connection registry. Derivation: the dashboard's default fragment tick is 5 s (`app.js:68`, `data-poll-ms` default `"5000"`), so a p99 render above ~1.2 s cannot hold a 5 s cadence once 10 sockets are attached (WEB-31) without the render becoming the loop's dominant consumer. |
| WEB-31 | `/ws/stats` fragment push cost and its engine-throughput delta | Performance | load-harness | dev-PC | SQLite | T | P1 | 500 Connections, 10 concurrent operator sockets, 1 s tick: measured steady-state pipeline throughput degrades by **< 10 %** versus the same run with zero console sockets, and per-tick fragment render time p99 ≤ 250 ms. |
| WEB-32 | Message log at 1M rows | Performance | load-harness | dev-PC | x2 | T | P1 | `GET /ui/messages` with a 1M-row store returns p99 ≤ 2 s at `limit=50` for an indexed filter, and the request does not hold the event loop (concurrent `/health` p99 unchanged within 20 %). |
| WEB-33 | Audit page at 100k rows | Performance | load-harness | dev-PC | x2 | T | P2 | `GET /ui/audit` p99 ≤ 2 s; memory high-water of the render bounded (no full-table materialization). |
| WEB-34 | Negative PHI-render invariant across every GET route | PHI | pytest | dev-PC | SQLite | T | P0 | Seed one synthetic message containing a unique needle. As a fully-permissioned operator, crawl **every** GET row in `ui_routes.txt` (path params bound to the seeded ids). The needle appears **only** on the allow-listed audited paths (`/ui/messages/{id}`, `/ui/messages/{id}/edit`, `/ui/messages/{id}/parse-tree`, `/ui/messages/{id}/attachments/{aid}`, `/ui/messages/search`, `/ui/messages/search/layered`, `/ui/uploaded-logs/file/{id}`), and each of those emitted an audit row naming the acting user. |
| WEB-35 | Uploaded-logs browse decrypt is audited with the acting user | PHI | pytest | dev-PC | SQLite | T | P1 | `GET /ui/uploaded-logs/file/{id}` after step-up writes an audit row with the acting user id and the file id, and no message body reaches the log at any level. |
| WEB-36 | Uploaded-logs step-up posture pinned per verb | Negative/Security | pytest | dev-PC | SQLite | T | P1 | A test asserts the **intended** posture explicitly: `POST /ui/uploaded-logs/upload` = `require_ui(FILES_UPLOAD)` + `assert_same_origin` (no step-up, by the multipart-cannot-survive-redirect rationale), browse = `require_ui_step_up`, delete = registered write action, resend = named RBAC. Any change to any of the four fails. |
| WEB-37 | Uploaded-logs refusals render without echoing content | PHI | pytest | dev-PC | SQLite | T | P1 | A binary container (PNG) → 415 and an oversize body → 413; both re-render the upload page with an error banner containing no filename-derived content, no body bytes, and no stack. |
| WEB-38 | Unhandled `/ui` exception renders an HTML degraded page | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | With a store read patched to raise, `GET /ui/messages` returns `Content-Type: text/html`, a page with nav and a working sign-out form, no stack trace and no exception message; the server log records the exception type only. Repeat per page family: messages, connections, alerts, audit, status, account. |
| WEB-39 | Engine-down / store-unreachable degraded states are legible | HA/Resilience | pytest | dev-PC | SQLite | T | P1 | With the store unreachable, `/ui/nav-status` returns `health: "down"` with a reason and never 500s (guarded at `routes/status.py:131-158`); `/ui/status` renders the rollup with the failing probes marked unknown rather than omitted. |
| WEB-40 | Empty states on every list page | Functional | pytest | dev-PC | SQLite | T | P2 | On a fresh store, each of messages / dead-letters / alerts / events / audit / uploaded-logs / users / roles renders an explicit "no rows" affordance, not a bare header row. |
| WEB-41 | Version-skewed console refuses at startup, legibly | Compat | pytest | dev-PC | n/a | T | P1 | With `ENGINE_UI_SEAM` monkeypatched off `SUPPORTED_ENGINE_SEAMS`, `mount_ui` raises `UiSeamMismatch` whose message names both the console version and the engine seam; `serve` exits non-zero rather than serving a half-broken console. |
| WEB-42 | Two operators race bulk control on the same Connection | Functional | pytest | dev-PC | SQLite | T | P1 | Two authenticated clients issue `POST /ui/connections/{name}/stop` and `/restart` concurrently; the final engine state is one of the two requested states (never a torn state), each response names the outcome it achieved, and both are audited. No 500. |
| WEB-43 | Purge racing an in-flight replay | Functional | pytest | dev-PC | SQLite | T | P1 | Start a per-channel dead-letter replay, then issue `POST /ui/connections/{name}/purge/{scope}` for the same Connection; the purge either 409s (running) or completes without deleting rows the replay has already claimed. Row accounting before/after is exact. |
| WEB-44 | Single-use action-bound step-up grant cannot be double-consumed | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Under `[auth].require_action_step_up=true`, mint one grant for `webauthn-delete` and replay the POST twice concurrently; exactly one succeeds, the other 303s to `/ui/reauth`. Neither leaves the account in a half-deleted factor state. |
| WEB-45 | Role edit racing the last-administrator guard | Negative/Security | pytest | dev-PC | SQLite | T | P1 | Two admins concurrently remove the Administrator role from the two remaining admin accounts; at least one is refused and at least one Administrator remains. |
| WEB-46 | Two operators, live-swap while another changes state | Functional | browser | container-CI | SQLite | T | P2 | Operator A has the dashboard open with a Connection selected; operator B stops that Connection; A's next swap reflects the new state and A's selection either persists correctly or is visibly cleared — never silently applied to a different row. |
| WEB-47 | Automated axe-core scan at the declared WCAG target | Usability | browser | container-CI | SQLite | T | P1 | **The target is declared here as WCAG 2.2 AA** for the operator console — proposed by this plan under Q2; the owner may raise or lower the level, but not waive it, and the declared level is written into `docs/SYSTEM-REQUIREMENTS.md` so WEB-54 can pin it. An axe-core run with `tags: ["wcag2a","wcag2aa","wcag21a","wcag21aa","wcag22aa"]` over a representative page set (login, dashboard, messages, message detail, users, account, status) reports **zero** violations. **No per-violation waiver:** an accepted violation must be fixed, or the declared level lowered in the same change — "recorded with a rationale" is not a pass. Findings axe cannot see belong to WEB-48 / WEB-50 / WEB-51. |
| WEB-48 | Keyboard-only operation walk | Usability | manual | browser-matrix | SQLite | T | P1 | Tab order reaches every interactive control on login, the `:focus-within` nav dropdowns, the bulk-control toolbar, every step-up/confirm form, and the sort buttons; focus is always visible (note `.filterbox:focus{outline:none}`, `app.css:161`); no keyboard trap. |
| WEB-49 | Column resize and reorder have a keyboard path | Usability | browser | container-CI | SQLite | T | P1 | Resize (`app.js:832-863`, pointer events) and reorder (`:880-911`, HTML5 drag) are operable from the keyboard, **or** a documented reset control returns a mouse-made arrangement to the server order for a keyboard-only user. Today `app.js` registers zero `keydown` listeners. |
| WEB-50 | Screen-reader announcement pass | Usability | manual | browser-matrix | SQLite | C | P1 | NVDA (Windows) and VoiceOver (macOS): nav group state, live status-glyph `aria-label`s, `role="alert"` banners (`_html.py:380`), and table `aria-sort` are announced coherently; the CSS-only menu's omitted `aria-expanded` (`_html.py:463-465`) does not mislead. |
| WEB-51 | Colour-contrast sampling against the token palette | Usability | manual | browser-matrix | n/a | T | P2 | Ratios declared here from WEB-47's WCAG 2.2 AA target, so the row can fail: every text/background pair in `app.css` meets **1.4.3** — **≥ 4.5:1** for normal text, **≥ 3:1** for large text (≥ 18.66 px, or ≥ 14 px bold) — and every UI-component boundary, focus indicator and status glyph meets **1.4.11** at **≥ 3:1**. Sampled pairs must include the amber wordmark, the status pills and the blinking-red health heart. `prefers-reduced-motion` (`app.css:99`) suppresses the blink. A pair below its ratio is a defect; there is no "recorded exception" pass. |
| WEB-52 | Declared supported-browser matrix, then a per-browser smoke | Compat | manual | browser-matrix | SQLite | T | P1 | The matrix is written into `docs/SYSTEM-REQUIREMENTS.md` with minimum versions (Q1); a login → dashboard → PHI view → step-up → logout smoke passes on each named browser at that minimum. |
| WEB-53 | Responsive / small-screen decision is honoured | Compat | manual | browser-matrix | SQLite | T | P2 | `app.css` has **zero** width breakpoints (only `prefers-reduced-motion` at `:99`) while the shell emits a device-width viewport meta (`_html.py:169`). Either a tablet layout exists and is checked at 1024×768, or the docs state desktop-only and a minimum viewport width. |
| WEB-54 | Doc-drift test pinning `SYSTEM-REQUIREMENTS.md` to code facts | Compat | pytest | dev-PC | n/a | T | P1 | A test (precedent: `tests/test_asvs_file_surface_doc_drift.py`) fails while `docs/SYSTEM-REQUIREMENTS.md` names a `console` extra absent from `pyproject.toml`, describes the console as a desktop application, or calls `/ui` "opt-in read-only … off by default". |
| WEB-55 | FEATURE-MAP console-row drift guard — **pointer** | Compat | — | — | n/a | T | P2 | Covered by **MIG-28** (the single consolidated FEATURE-MAP drift guard, extending `tests/test_feature_map_claims.py`); no separate work scoped. The console-specific claims that guard must kill, verified in-repo and carried in Q12 rather than re-tested here: `docs/FEATURE-MAP.md` §10 "Surfaces — Admin Console (PySide6)" (**line 162**, not 158) marking a retired desktop console shipped; `:131` "The PySide6 desktop console stays (additive)"; `:130` "TOTP stays the desktop console's factor"; the absent rows for OIDC login, uploaded logs, edit-and-resubmit, session management and search presets; and the export / log-viewer rows that should read unbuilt. |
| WEB-56 | Operator-facing doc paths resolve — **pointer** | Compat | — | — | n/a | T | P2 | Covered by the MIG chapter's single "doc paths resolve" linter row (**MIG-42**, widened from `harness/**` / `tee/**` docstrings to every operator-facing doc path, with SEC-09 and MIG-35 folded in); no separate work scoped. The console's contribution to that row's evidence, verified in-repo and carried in Q13: the exposure ladder names `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` six times in operator-facing CLI messages (`__main__.py:1724, 1763, 1779, 1792, 1803, 1814`) while `docs/security/` is withheld from the public repo (git-ignored post-cutover, `.gitignore:144`, rationale `:148`). The linter's assertion is about the *operator-reachable* path, not the document's existence — the runbook is real and maintained, it simply does not ship here. |
| WEB-57 | `/ui` reachable under the NSSM service identity on Windows Server 2025 | Functional | acceptance-probe | W2025-box | x3 | T | P1 | New acceptance row: with the engine running as the NSSM service account, a tokenless `GET /ui` returns 303 to `/ui/login`; a real operator account logs in; an audited PHI raw view records the acting user; the TLS/cookie posture matches the declared configuration. |
| WEB-58 | Retire the retired-desktop acceptance rows — **pointer** | Functional | — | — | n/a | T | P1 | Covered by **TRAY-67** (the `[console]` extra / `check_console_importable` provenance — `messagefoundry/verify/checks.py:180-194` and the "console importable" claim at `docs/testing/VERIFY.md:40`) and **TRAY-69** (the `harness/acceptance/matrix.py` **W25:A7** retirement at `:154-160`, the **W25:F7** recaption at `:415`, and `probe_console_gui` at `harness/acceptance/probes.py:170`); no separate work scoped. The replacement `/ui` acceptance coverage this chapter does own is WEB-57 and WEB-59. |
| WEB-59 | `/ui` rows added to the WIN2025 matrix | Functional | verify | W2025-box | x3 | T | P1 | `docs/testing/WIN2025-TEST-MATRIX.md` and `WIN2025-ACCEPTANCE.md` each carry at least the WEB-57 row set; a WIN2025 acceptance run's output names the console. |
| WEB-60 | Console suite runs under coverage in the advisory leg | Functional | CI-leg | container-CI | SQLite | T | P2 | `quality-advisory.yml` measures `--cov=messagefoundry_webconsole` and executes the package suite inside the same coverage session; a PR adding an uncovered `/ui` route shows as uncovered diff lines. |
| WEB-61 | Seam-set narrowing is asserted and the stale comment corrected | Compat | CI-leg | container-CI | n/a | T | P2 | A test asserts `SUPPORTED_ENGINE_SEAMS == {ENGINE_UI_SEAM}`; the `ci.yml` comment no longer describes a range; widening the set fails CI unless the MIN/MAX engine matrix lands in the same change. |
| WEB-62 | `app.js` is linted and formatted in CI | Functional | CI-leg | container-CI | n/a | T | P2 | A JS linter runs over `messagefoundry_webconsole/static/*.js` in CI and is green; the choice of tool and whether it shares `ide/`'s npm project is recorded (Q3). |
| WEB-63 | `POST /ui/csp-report` cannot amplify the log | Negative/Security | pytest | dev-PC | n/a | T | P2 | 1,000 same-client reports in 10 s produce a bounded number of WARNING records (a per-client budget), and a genuine violation delivered after the budget is exhausted is still surfaced (counter or sampled record), not silently dropped. |
| WEB-64 | Thin console subset on SQL Server and PostgreSQL | Cross-backend | CI-leg | container-CI | x2 | T | P2 | Messages list, search, dead-letters, audit and purge pages render with identical row ordering and identical `total`/`offset` readouts on all three backends against the same seeded fixture. |
| WEB-65 | Long-session soak with a PHI page open | PHI | manual | dev-PC | SQLite | T | P1 | Leave a message detail open past both the idle and absolute deadlines on a real desktop browser; confirm the document blanks before navigation and that Back / bfcache does not resurrect the rendered page (`Clear-Site-Data` + `Cache-Control: no-store`). |
| WEB-66 | Real hardware authenticators | Compat | manual | dev-PC | SQLite | T | P1 | Enrol and step up with a Windows Hello platform authenticator and a roaming FIDO2 key; both appear in the passkey list with distinct labels; sign-count clone detection is not falsely triggered across ≥5 uses. |
| WEB-67 | Kerberos/SPNEGO browser SSO against a real domain | Compat | manual | AD-lab | SQLite | T | P1 | On a domain-joined host with the engine's SPN registered and the site in the browser's integrated-auth zone, `GET /ui/sso` mints exactly one cookie session without a password prompt; a non-domain browser falls back to the login form. Closes the ADR 0068 open item. |
| WEB-68 | OIDC round trip against a real IdP | Compat | manual | cloud | SQLite | T | P1 | Entra ID / Okta / Keycloak with a registered redirect URI: consent screen, the meta-refresh landing hop renders, `id_token.exp` caps the session's absolute deadline (observable via `/ui/session-status` remaining seconds), and the flow cookie is `__Host-` prefixed over TLS. |
| WEB-69 | Documented install path works once the wheel is published | Upgrade | manual | dev-PC | n/a | T | P2 | `pip install "messagefoundry-webconsole==<ver>"` from PyPI or the private index succeeds into an engine venv and `/ui` mounts — the command `docs/INSTALL-GUIDE.md:252` already instructs. Today the wheel installs only by path (`docs/WEBCONSOLE-PACKAGE.md:16-20`). |
| WEB-70 | Browser autofill, print and copy behaviour on PHI pages | PHI | manual | browser-matrix | SQLite | C | P2 | A password manager does not autofill the step-up form with the wrong credential; browser Print of a message detail is either suppressed or produces output the operator expects; copy from the raw view yields the raw text only, with no hidden markup. |
| WEB-71 | Operator legibility of every degraded state | Usability | manual | dev-PC | SQLite | C | P2 | Walk: engine down mid-session, store unreachable, console wheel absent (JSON-only + the ADR 0143 warning), explicit `serve_web_console=true` with the wheel absent (exit 2), version-skewed console. Each produces a message an operator can act on without reading source. |
| WEB-72 | Browser-tab resource leak over a full operator shift | Performance | browser | container-CI | SQLite | T | P1 | Distinct from WEB-65 (which is the PHI/watchdog soak): this row is about the tab an operator never closes. Hold the connections dashboard open for a shift-equivalent run (8 h, or ≥ 2,880 fragment ticks with `data-poll-ms` compressed), with session lifetimes long enough that the watchdog never fires. Every tick replaces the container's markup wholesale (`app.js:130` WS push, `:88-96` poll fallback, `:975-997` `[data-mf-fragment]`), and four unconditional timers run for the tab's whole life (`:102`, `:997`, `:1096`, `:1097`, plus the 15 s poll at `:1198`). Assert, sampling every 15 min after a 10-min warm-up: (a) JS heap (CDP `Runtime.getHeapUsage` after a forced GC) grows **< 20 %** between the warm-up sample and the final sample, and is not monotonically increasing across the last four samples; (b) `document.getElementsByTagName("*").length` stays within **±5 %** of the warm-up count; (c) detached-node count from a heap snapshot does not grow across samples; (d) after 20 forced socket drops, exactly **one** interval timer drives the fragment (`resumePoll`'s `if (!pollTimer)` guard, `:143-147`, must not stack duplicate pollers) and the fragment is still updating. **Recorded finding, not a pass criterion:** `ws.onclose` only resumes the poll — `app.js` never reopens the socket, so a shift-long tab silently runs on the 5 s poll after the first drop. |

### 10.5 Detailed scenarios

#### S1 — WEB-02 / WEB-03 / WEB-04: the session watchdog, executed (P0)

The single highest-value scenario in this chapter: the ASVS 14.3.1 control that discards rendered PHI
is 60 lines of `app.js` (`messagefoundry_webconsole/static/app.js:1030-1096`) verified today only by
string comparison.

**Preconditions.** A headless-browser runner (Playwright recommended — it exposes CDP virtual
authenticators, which WEB-06/07 also need). Engine served by real uvicorn on loopback so the
secure-context header path engages (ADR 0143). Session lifetimes compressed for the test run. Two
synthetic HL7 messages generated with `python -m messagefoundry generate` into a scratch corpus —
**never** redirect that output into a committed file or CI log.

**Steps (leg 1 — server-driven termination).**
1. Start the engine: `python -m messagefoundry serve --config samples/config --db <tmp>/web.db --env dev` with `[security].serve_web_console=true`.
2. Ingest one synthetic message; note its id.
3. Browser: log in, complete MFA, navigate to `/ui/messages/<id>`. Assert the seeded needle **is** present (this is the audited path).
4. Out of band, revoke that session — `POST /ui/account/sessions/{session_id}/revoke` from a second authenticated client, or an admin `POST /ui/users/{user_id}/revoke-sessions`.
5. **Observation point:** poll the page every 250 ms for up to 40 s, capturing `document.body.childElementCount`, `document.title`, and `location.pathname` **on every sample**. The ordering assertion needs the sample where `childElementCount === 0` while `pathname` is still the message path.

**Expected.** A sample exists with `childElementCount === 0` and `document.title === "Session ended —
MessageFoundry"` at a `pathname` that is still `/ui/messages/<id>`; a later sample shows
`/ui/login`. At no sample after blanking does the needle appear in `document.documentElement.outerHTML`.

**Steps (leg 2 — absolute deadline).** Same setup with the absolute session lifetime compressed to
≤120 s. Load the PHI page and **do not interact**. The nav-status and fragment polls run with
`activity=False` (`_auth.py:210, 224-231`; `routes/status.py:126`), so they must not slide the clock.
Expected: blanking + `/ui/login?e=expired` within deadline + 2 s.

**Steps (leg 3 — unconfirmable session).** Load the PHI page, then `taskkill`/SIGTERM the engine.
`STALE_LIMIT_MS` is 300 000 in source (`app.js:1033`); run this leg with a build-time-overridable
constant or accept a 5-minute wait. Expected: the document blanks even though `location.replace` cannot
resolve — assert **blanking**, not navigation. This is the exact case the ordering contract exists for.

**Cleanup.** Restore session-lifetime settings; delete the scratch DB and the generated corpus;
terminate the browser context (which drops the cookie jar).

#### S2 — WEB-17 / WEB-18 / WEB-19 / WEB-20: real TLS, real proxy, real cookie jar (P0)

**Preconditions.** A non-loopback host (the existing WIN2025 lab), a TLS certificate whose SAN matches
a DNS name, and nginx or IIS ARR in front. Two operator accounts. This is the first execution of the
off-loopback path outside header-string assertions.

**Steps.**
1. **Direct in-process TLS.** `[api].host` = the box's address, `[api].tls_cert_file` + key set, `[security].serve_web_console=true` (explicit — a default-on console on an exposed bind auto-degrades to JSON-only, `__main__.py:1713-1727`). Start; confirm no warning about a missing public origin is fatal (it is a warning, `__main__.py:1789-1800`) and that WebAuthn is fail-closed until `web_console_public_address` is set.
2. Browse to `https://<name>:<port>/ui`, log in, and **inspect the browser's cookie jar** (DevTools → Application → Cookies, or Playwright `context.cookies()`). Assert name `__Host-mf_session`, `secure: true`, `httpOnly: true`, `sameSite: "Strict"`, `path: "/"`, no domain attribute.
3. Assert `Strict-Transport-Security` on the `/ui` response and `Content-Security-Policy` containing `script-src 'nonce-` — then prove **enforcement**, not presence: request a test-only page under the same policy carrying an un-nonced inline script and confirm the browser blocks it and delivers a violation report that `routes/core.py:1063-1074` classifies as *real* (not the canary), producing a WARNING.
4. **Behind the proxy.** Switch to `[api].tls_terminated_upstream` + `trusted_proxies` + `[security].web_console_public_address = "https://<name>"`. Restart. Repeat the login and additionally: complete a step-up, open an audited PHI raw view, and sign out. Confirm the audit rows name the acting user and the client address seen through the proxy.
5. **Cross-site refusal.** Serve a one-page HTML file from a *different* origin that auto-submits a form to `https://<name>/ui/connections/<name>/stop`. Expected: the browser attaches no session cookie (SameSite=Strict), the response is 403 (`Sec-Fetch-Site: cross-site`, `_auth.py:318-319`), and the Connection is still running — verify against `GET /ui/connections`, not against the attacker page.

**Expected.** All of the above. Any browser-side cookie *rejection* (jar empty after login) is a P0
defect regardless of what the response headers said.

**Cleanup.** Stop the engine, remove the proxy site config, revoke the test sessions, and delete the
scratch store. Do not leave an off-loopback console running.

#### S3 — WEB-22: the dual-control dead-end (P0, currently a build item)

**Preconditions.** `[approvals]` enabled with `config_reload` in `operations`. Two accounts with
distinct identities, both holding `CONFIG_DEPLOY`; MFA enrolled on both.

**Steps.**
1. As operator A: `GET /ui/config`, click Reload. Step up when prompted.
2. **Observation point:** the rendered response. Today it is `pages/config.py:96-105` — an `<h1>Reload held for approval</h1>` with `Approval id: <id>` and no onward control.
3. As operator B: search the console for any surface listing pending approvals. There is none — no `/ui/approvals` route in `ui_routes.txt`, no approvals field in `tests/golden/webconsole_seam.snapshot`.
4. Confirm the only completion path is the engine JSON API: `GET /approvals`, `POST /approvals/{id}/approve` (`messagefoundry/api/app.py:2692-2721`) — which needs a bearer token the browser session cannot supply (`bearer_token()` is header-only; the cookie is refused on JSON routes).

**Expected once built.** B sees the pending item, approves it, and the reload executes; A's attempt to
self-approve is refused; approve/reject are RBAC-gated and step-up-gated; both decisions are audited.
**Expected until built.** The held page names the approval mechanism explicitly ("approve via
`POST /approvals/{id}/approve` on the JSON API") rather than dead-ending, and this limitation is
recorded in `docs/WEBCONSOLE-PACKAGE.md` and FEATURE-MAP.

**Cleanup.** Reject any approval left pending; disable `[approvals]` in the scratch config.

#### S4 — WEB-31: console-induced load on the pipeline (P1, easy to run wrong)

The trap: measuring the console in isolation says nothing. The claim under test is that the
**server-rendered** connections fragment, pushed to every socket on every `/ws/stats` tick, does not
steal the event loop from the pipeline.

**Preconditions.** A seeded registry of 500 Connections and a running inbound feed at a known steady
rate from `harness/load/`. A scratch store — never a production one.

**Steps.**
1. **Baseline.** Run the load profile with **zero** console sockets for 10 minutes. Record steady-state messages/second and delivery latency p50/p99 from the engine's own metrics.
2. **Loaded.** Repeat identically, but attach 10 authenticated `/ws/stats` browser sessions (real browser contexts, not raw WebSocket clients — the enriched fragment path only engages for a cookie-authorized same-origin handshake, `_auth.py:655-691`, `api/app.py:4830-4836`).
3. **Observation point:** the *engine* throughput and latency, not the console's. Also sample per-tick fragment render time.

**Expected.** Throughput degradation < 10 %; delivery p99 degradation < 20 %; fragment render p99
≤ 250 ms. A larger delta means the fragment render belongs off the loop or behind a cache — a finding,
not a tuning note.

**Cleanup.** Close all sockets, stop the load profile, drop the scratch store. Never run this against
a store containing real data.

#### S5 — WEB-34: the negative PHI-render crawl (P0)

**Preconditions.** A scratch store with exactly one synthetic message whose body contains a unique,
high-entropy needle (e.g. `ZZQA-<uuid4>` in PID-5). One operator account holding **every** permission,
so no route is skipped for authorization reasons. Step-up satisfied.

**Steps.**
1. Parse `packaging/messagefoundry-webconsole/tests/golden/ui_routes.txt` and take every `GET` row.
2. Bind path params: `{message_id}` to the seeded id, `{name}` to a seeded Connection, `{user_id}` / `{role_id}` / `{session_id}` / `{file_id}` / `{attachment_id}` / `{preset_id}` to seeded fixtures. A row whose params cannot be bound is a **failure of the test**, not a skip — record it explicitly.
3. Request each, following redirects, and search the response body for the needle.
4. Independently, snapshot the audit table before and after each request.

**Expected.** The needle appears on exactly the seven allow-listed audited paths named in WEB-34 and
nowhere else. Every appearance is accompanied by a new audit row naming the acting user. A needle on
any other route is a P0 unaudited-PHI-exposure defect. Extend the same crawl to the *log capture* for
the run: the needle must not appear at INFO or above anywhere.

**Cleanup.** Drop the scratch store; the needle is synthetic, but treat the corpus as disposable.

#### S6 — WEB-42 / WEB-44: concurrent operators (P1, timing-dependent)

**Preconditions.** Two authenticated console clients (`httpx.AsyncClient` against the same ASGI app is
sufficient and deterministic; a two-browser walk is the manual companion). `[auth].require_action_step_up`
default-on for the WEB-44 leg.

**Steps (WEB-42).** Both clients hold a fresh step-up. Fire `POST /ui/connections/IB_DEMO_ORU/stop`
and `POST /ui/connections/IB_DEMO_ORU/restart` with `asyncio.gather`. **Observation point:** the
engine's connection state after both settle, plus both response bodies and the audit rows.
**Expected:** a single coherent final state; each response accurately reports what it achieved; two
audit rows; no 500; no torn state (a Connection that is neither running nor stopped).

**Steps (WEB-44).** Complete one `/ui/reauth` bound to the `webauthn-delete` action (ADR 0077, single
use). Fire `POST /ui/account/webauthn/{hash}/delete` twice with `asyncio.gather`.
**Expected:** exactly one 303-to-success; the other 303s to `/ui/reauth` because the grant was
consumed. The credential list afterwards is internally consistent (the credential is either present or
absent — never a dangling row).

**Cleanup.** Restart the Connection to its pre-test state; re-enrol the deleted passkey fixture or
rebuild the account fixture.

### 10.6 Automation disposition

**New pytest modules** (in `packaging/messagefoundry-webconsole/tests/` unless noted):

| Module | Covers | Effort |
|---|---|---|
| `test_ui_client_contract.py` | WEB-23, WEB-24, WEB-25 — static guards resolving every `app.js` `fetch("/ui/…")` literal against the mounted route table, every `feature(...)` hook against page-builder output, and a generalized literal-before-`{param}` derivation | **S** |
| `test_ui_pagination.py` | WEB-26, WEB-27, WEB-28, WEB-29, WEB-40 — pagers, boundaries, empty states, audit filter + escaping. Closes FCP:UI-8 and FCP:UI-23 | **M** (the pager itself must be built first) |
| `test_ui_phi_crawl.py` | WEB-34, WEB-35 — the needle crawl over every golden GET route plus the audit-row assertion | **M** |
| `test_ui_degraded.py` | WEB-38, WEB-39, WEB-41 — injected failures per page family, the HTML degraded shell, seam-mismatch legibility | **M** (the HTML error page must be built first) |
| `test_ui_concurrency.py` | WEB-42, WEB-43, WEB-44, WEB-45 — interleaved writes with asserted 409/idempotency semantics | **M** |
| `test_ui_approvals.py` | WEB-22 — pending list, distinct-approver approve, reject, self-approval refusal, RBAC + step-up | **M** (gated on the build) |
| `test_ui_csp_report_budget.py` | WEB-63 — per-client log budget under a report flood | **S** |

**Extends an existing module:**
- `test_uploaded_logs_ui.py` → WEB-36, WEB-37 (per-verb step-up posture pinned; 415/413 non-echo). **S**
- `test_golden_surface.py` → WEB-25's generalized shadow guard can live here beside the existing 5-pair check. **S**
- `tests/test_webconsole_seam_snapshot.py` → WEB-61's `SUPPORTED_ENGINE_SEAMS == {ENGINE_UI_SEAM}` assertion. **S**
- A new engine-side `tests/test_doc_drift_console.py` → WEB-54 only (precedent: `tests/test_asvs_file_surface_doc_drift.py`). WEB-55 and WEB-56 are pointer rows: their guards are the MIG chapter's consolidated FEATURE-MAP drift row and its single "doc paths resolve" linter — this chapter scopes no module for them. **S**

**New CI legs:**
- **`webconsole-browser`** (Playwright, ubuntu + windows): WEB-01..WEB-16, WEB-46, WEB-49, and WEB-72 as a **scheduled** long-run job rather than per-PR (a shift-equivalent soak cannot sit in the PR budget). This is the single largest item in the chapter and the one ADR 0065 deliberately deferred; it needs an owner decision (Q3). **L**
- **`webconsole-crossdb`** (thin subset against the existing SQL Server + PostgreSQL containers): WEB-64. **S**
- **JS lint** step over `messagefoundry_webconsole/static/*.js`: WEB-62. **S**
- **Coverage** amendment to `quality-advisory.yml:311`: WEB-60. **S**

**Harness / acceptance-probe capability:**
- A new `probe_web_console` that performs the tokenless `GET /ui` (reusing the pattern in `messagefoundry/tray/probe.py:97-104`) plus an authenticated login + audited-PHI-view leg under the service identity — WEB-57 and WEB-59. Retiring `probe_console_gui` (**W25:A7**) and re-captioning **W25:F7** is TRAY's, not this chapter's (pointer WEB-58). Rows added to `harness/acceptance/matrix.py`, `docs/testing/WIN2025-TEST-MATRIX.md`, `WIN2025-ACCEPTANCE.md` and `docs/testing/VERIFY.md`. **M**

**Load harness:**
- A `harness/load/` console profile seeding 500 Connections / 1M messages / 100k audit rows and driving N concurrent `/ui` sessions with a paired zero-console baseline — WEB-30..WEB-33. **M**

**Stays manual, and why:**
- WEB-48 (keyboard walk), WEB-50 (screen readers), WEB-51 (contrast), WEB-52/WEB-53 (per-browser and responsive) — assistive technology and human judgement; axe-core (WEB-47) automates only the machine-checkable subset.
- WEB-65 (long-session soak on a real desktop browser), WEB-66 (hardware FIDO2 / Windows Hello), WEB-67 (domain-joined Kerberos), WEB-68 (real IdP), WEB-70 (autofill/print/copy), WEB-71 (degraded-state legibility) — each needs hardware, a domain, a tenant, or an operator's eyes.
- WEB-69 (published-wheel install) — blocked on the owner publishing the wheel.
- **Class note:** WEB-50, WEB-70 and WEB-71 are this chapter's only **C** rows. They are scheduled and their findings triaged, but each yields a written finding rather than a threshold, so none of them may red a release. WEB-48, WEB-51, WEB-52, WEB-53, WEB-65..WEB-69 are manual but still **T** — each has a criterion that can fail.
- WEB-17..WEB-21 are marked `external` rather than manual: they are scriptable, but only against a stood-up TLS host, so they run as a scheduled/manual lab job, not per-PR.

### 10.7 Environment, data & prerequisites

**Must be procured or stood up:**
1. **Headless-browser toolchain + CI leg.** Playwright (preferred, for the CDP virtual authenticator) or Selenium. The repo has **no** JS test toolchain for `app.js` today; `ide/` has a separate, unrelated npm project. Chromium + Firefox + WebKit channels for the matrix legs. WEB-72 additionally needs CDP access to `Runtime.getHeapUsage`, a forced-GC hook and heap snapshots (Chromium channel only), plus a runner slot that tolerates a multi-hour job.
2. **A JS lint/format decision** for `static/app.js` (currently unlinted, untyped, unbundled).
3. **A real TLS certificate** with a SAN matching a DNS name, plus **nginx or IIS ARR** on a non-loopback host, for WEB-17..WEB-21.
4. **The existing Windows Server 2025 lab** running the engine under NSSM with the dedicated service account, for WEB-57..WEB-59.
5. **Desktop clients:** Chrome, Edge, Firefox (Windows) and Safari (macOS), plus a tablet for the WEB-53 decision.
6. **A hardware FIDO2 key** and a **Windows Hello-capable machine** (WEB-66). CI uses only the soft authenticator at `packaging/messagefoundry-webconsole/tests/_soft_webauthn.py`.
7. **An AD domain controller** with an SPN/keytab for the engine host (WEB-67).
8. **An OIDC IdP tenant** (Entra ID, Okta or Keycloak) with a registered redirect URI (WEB-68).
9. **Screen readers** NVDA (Windows) and VoiceOver (macOS), plus axe-core (WEB-47/50).
10. **A published `messagefoundry-webconsole`** on PyPI or a private index (WEB-69). Today it installs only by path.
11. **SQL Server and PostgreSQL** instances for WEB-64 — the containers the WIN2025 legs already use suffice.

**Accounts.** Two operator identities with distinct roles (for WEB-42..WEB-46 and WEB-19), a second
approver identity plus an `[approvals]`-enabled config (WEB-22), one fully-permissioned account (WEB-34),
one viewer-only account (RBAC negatives), and one AD-backed account (WEB-67).

**Synthetic data — PHI-free, always.**
- Message corpus: `python -m messagefoundry generate` (see CLAUDE.md §7). **`generate` and `dryrun` emit full message bodies to stdout — never redirect them into a committed file, a ticket, or a CI log.**
- Scale fixture for WEB-30..WEB-33: 500 Connections, 1M messages, 100k audit rows, 10k dead letters, seeded directly into a scratch store by a fixture script, not by replaying traffic.
- WEB-34 needle: a single high-entropy synthetic token in PID-5 of one generated message.
- De-identification, if a captured dataset is ever used as a starting point, goes through `messagefoundry/anon/` (ADR 0030) — never ad-hoc.

**Standing configuration knobs the scenarios need:** compressed `[auth]` idle and absolute session
lifetimes (S1), `[auth].require_action_step_up` (WEB-44), `[approvals]` (WEB-22),
`[security].serve_web_console` + `web_console_public_address` + `[api].tls_cert_file` /
`tls_terminated_upstream` + `trusted_proxies` (WEB-17..WEB-21), `MEFOR_WEBCONSOLE_DISABLE_BROWSER_HARDENING`
for the opt-out regression, and a build-time-overridable `STALE_LIMIT_MS` if leg 3 of S1 is to run in
CI time.

### 10.8 Exit criteria

The web console area is signed off for release when **all** of the following hold:

1. **Every one of the 16 P0 rows (WEB-01..WEB-07, WEB-09, WEB-10, WEB-15, WEB-17..WEB-20, WEB-22, WEB-34) passes** — all 16 are class **T**; WEB-21 is P1, not P0 — with WEB-22 either passing against a built approvals surface or formally accepted as a documented limitation whose held-for-approval page names the JSON-API path.
2. A **headless-browser CI leg exists and is green on both ubuntu and windows**, executing `app.js`; the session-watchdog legs 1–3, both WebAuthn ceremonies, the fragment-swap selection guard and the CSP/scripts-blocked/insecure-context detects are behaviour-asserted, not grep-asserted.
3. An **off-loopback smoke has been executed at least once per release** on a real TLS host behind a real reverse proxy, with the browser's cookie jar inspected and the `__Host-` cookie confirmed stored.
4. **Zero unresolved dead client code:** WEB-23 and WEB-24 are green — every `fetch("/ui/…")` literal resolves to a mounted route and every `feature(...)` hook is emitted by a page builder. The three dead features are deleted or completed, and ADR 0131 / `docs/adr/README.md` / FEATURE-MAP reflect whichever was chosen.
5. **Pagination exists and is tested** on the message log, dead-letter list and audit page; FEATURE-COVERAGE-PLAN rows **FCP:UI-8** and **FCP:UI-23** are marked closed with the test names that closed them.
6. **The negative PHI invariant (WEB-34) is enforced in CI** and the allow-list of audited paths is pinned, so adding a route that renders a body fails the build.
7. **Performance budgets hold**: WEB-30..WEB-33 pass against the budgets this plan **adopts** (WEB-30 at p50 ≤ 400 ms / p99 ≤ 1200 ms; the owner may revise them under Q8, but until revised they are hard thresholds, not placeholders), WEB-31 shows < 10 % engine-throughput degradation with 10 console sockets at 500 Connections, and WEB-72's shift-long tab shows bounded heap and DOM growth with exactly one fragment poller after repeated socket drops.
8. **The declared accessibility target — WCAG 2.2 AA (WEB-47) — is met**: the axe-core run is at **zero** violations with no per-violation waiver, WEB-51's declared contrast ratios hold, WEB-48's keyboard walk passes, and WEB-49 has either a keyboard path or a documented reset control. WEB-50 (class **C**) has been walked once and its findings triaged — it informs, it does not gate.
9. **A supported-browser matrix is published** in `docs/SYSTEM-REQUIREMENTS.md` and WEB-52 has passed on each named browser at its minimum version.
10. **Doc drift is gated:** WEB-54 is green — `SYSTEM-REQUIREMENTS.md` no longer names a nonexistent `console` extra or calls `/ui` off-by-default and read-only — and the MIG-owned guards behind pointers WEB-55 and WEB-56 are green: FEATURE-MAP §10 no longer marks the retired desktop console shipped, and every operator-facing doc path the CLI emits either resolves in the distributed tree or stops being emitted (the `docs/security/` runbooks are withheld from the public repo by design, so the fix is the dangling path, not the document).
11. **The WIN2025 acceptance artifact reports on the console:** WEB-57 and WEB-59 pass, TRAY's retirement of **W25:A7** / re-caption of **W25:F7** (pointer WEB-58) has landed, and no acceptance row references the `[console]` extra.
12. **Concurrency semantics are asserted** (WEB-42..WEB-45) with no torn state and no double-consumed single-use grant.
13. **CI hygiene:** the console suite runs under coverage (WEB-60), `SUPPORTED_ENGINE_SEAMS == {ENGINE_UI_SEAM}` is asserted and the stale `ci.yml` comment corrected (WEB-61), and `app.js` is linted (WEB-62).
14. **No P0 or P1 row of class T is open without a written owner acceptance** recorded against the corresponding open question below. The three **C** rows (WEB-50, WEB-70, WEB-71) are exempt by construction — they must have been *run* and their findings recorded, but they cannot red the gate. There are no **A** rows in this chapter; a commissioned pen test of an exposed `/ui` would land as one and would block only an off-loopback release.

### 10.9 Open questions

1. **What is the supported-browser matrix, and what are the minimum versions?** Nothing in `docs/SYSTEM-REQUIREMENTS.md`, `docs/INSTALL-GUIDE.md`, ADR 0065 or `docs/SECURITY.md` declares one; the ASVS 3.7.5 degrade contract in `_security.py:51-59` says only "a current browser". *Blocks:* WEB-52, WEB-08, and any arbitration of a browser-specific defect.
2. **Does the owner ratify WCAG 2.2 AA as the console's conformance target, and is it contractual for healthcare / US public-sector buyers?** This plan **adopts 2.2 AA** so WEB-47 and WEB-51 have something falsifiable to assert against; the owner may raise or lower the level, but not waive it. *No longer blocks* WEB-47/WEB-51 — it only sets which level they assert and the priority of WEB-48..WEB-51.
3. **Is a headless-browser CI leg now accepted?** ADR 0065 deliberately kept the JS toolchain at zero and FCP:UI-32 records it as accept-by-design — but the session watchdog has since become an ASVS 14.3.1 *security control* verified only by string comparison. *Blocks:* WEB-01..WEB-16, WEB-46, WEB-49, WEB-72, and exit criterion 2. This is the single largest decision in the chapter.
4. **Should the console gain an approvals page, or is JSON-API/CLI approval the intended workflow?** If the latter, should the held-for-approval pages say so explicitly? *Blocks:* WEB-22 and exit criterion 1.
5. **Delete or complete the three dead `app.js` features?** `/ui/logs/tail` + `/ui/logging/level` (ADR 0130, BACKLOG #171 demand-gate) and `/ui/messages/export` (ADR 0131 — which, with `docs/adr/README.md:157` and FEATURE-MAP, currently implies the export is shipped). *Blocks:* WEB-23, WEB-24 and exit criterion 4.
6. **Is a responsive / tablet layout in scope, or is the console explicitly desktop-only?** `app.css` has zero width breakpoints while the shell emits a device-width viewport meta. If desktop-only, the docs should say so with a minimum viewport width. *Blocks:* WEB-53.
7. **Is the uploaded-logs step-up divergence intended and acceptable?** `require_ui(FILES_UPLOAD)` on `POST /ui/uploaded-logs/upload` vs `require_step_up(FILES_UPLOAD)` on the JSON twin, justified in-code by "a multipart body POST can't survive the re-auth redirect". *Blocks:* WEB-36 — the test must pin the *intended* posture, so it needs a decision, not an inference.
8. **What are the target list sizes, and is real pagination being built** for the message log, dead-letter list, audit page and connections dashboard? The render-latency budgets are **no longer open**: this plan adopts WEB-30 at p50 ≤ 400 ms / p99 ≤ 1200 ms (derived from the 5 s fragment cadence, `app.js:68`), WEB-31 at < 10 % throughput delta and p99 ≤ 250 ms render, and WEB-32/WEB-33 at p99 ≤ 2 s. The owner may overrule any number; until then each row fails against it. What remains open is the *list sizes* and the pager build. *Blocks:* WEB-26..WEB-29 (the pager must exist to be tested) — WEB-30..WEB-33 are now testable as written.
9. **Should `harness/acceptance/matrix.py` and the WIN2025 matrix gain `/ui` rows and retire W25:A7 (`probe_console_gui`, the nonexistent `[console]` extra) and W25:F7?** *Blocks:* WEB-57 and WEB-59 here, TRAY's rows behind pointer WEB-58, and exit criterion 11.
10. **Should an unhandled `/ui` exception render an HTML degraded page** instead of the engine's JSON 500 (`api/app.py:1195-1204`)? *Blocks:* WEB-38 — the test needs a defined expected shape.
11. **Is cross-backend execution of a console subset wanted**, or is the "upstream engine parity covers it" argument (FEATURE-COVERAGE-PLAN §23 auditor notes) accepted permanently? *Blocks:* WEB-64.
12. **Who owns correcting `docs/SYSTEM-REQUIREMENTS.md` (lines 5, 121, 123) and `docs/FEATURE-MAP.md` (§10 line 162, lines 130–131)** on the desktop-console retirement and the ADR 0143 default-on flip — and should a doc-drift test pin them? *Blocks:* WEB-54 and the MIG-owned guard behind pointer WEB-55, and exit criterion 10.
13. **`docs/security/OFF-LOOPBACK-DEPLOYMENT.md` is named in six operator-facing CLI messages and 12+ ADRs, but `docs/security/` is withheld from the public repo** (git-ignored post-cutover, `.gitignore:144`, rationale `:148` — 32 files of posture/risk-register detail deliberately not published). The runbook exists and is maintained; the question is only what an operator working from the public distribution should be pointed at. Ship a public, redacted off-loopback runbook, or have the CLI name a path that resolves in the distributed tree? *Blocks:* the MIG-owned linter behind pointer WEB-56.
14. **May `STALE_LIMIT_MS` (`app.js:1033`, 300 000 ms) become build-time overridable** so watchdog leg 3 can run inside a CI budget? Without it that leg is a 5-minute test or a manual-only row. *Blocks:* WEB-04 running in CI.
