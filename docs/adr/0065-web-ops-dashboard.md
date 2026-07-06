# ADR 0065 — Zero-install same-origin browser ops dashboard (read-only, M1)

- **Status:** **Accepted (2026-07-02) — building (M1).** Implements [BACKLOG #75](../BACKLOG.md) "option
  b" (the scheduled zero-install browser ops dashboard). This ADR settles the M1 (read-only) design; the
  safe-action + CSRF work is M2 and the full desktop-console port ("option c") stays gated per #75.
- **Builds on (must not redesign):** the API is the engine's only external boundary and every route
  resolves the live engine from `app.state` ([api/app.py](../../messagefoundry/api/app.py)); the opaque-
  token session store + RBAC + hash-chain audit ([auth/](../../messagefoundry/auth/),
  [api/security.py](../../messagefoundry/api/security.py)); the off-loopback TLS-or-refuse exposed gate +
  MFA-at-exposure ([config/settings.py](../../messagefoundry/config/settings.py) `exposure_protected`,
  [__main__.py](../../messagefoundry/__main__.py)); the one-way dependency rule (CLAUDE.md §4).

## Context

BACKLOG #75's audience decision (2026-06-29) locked an ops view that is **viewable without a Python or
desktop install** — a browser/URL. The engine already exposes a full RBAC/PHI-gated JSON API + a
hash-chain audit; what is missing is a browser surface that is a *client* of that API, served from the
same process. A 2026-07-01 evaluation (recorded in #75) decoupled this from the retired frozen installer
(#39/[ADR 0032](0032-console-desktop-launch.md)) and from the full desktop-console port, and the owner
locked three decisions: a **thin server-rendered** stack (no npm/build step), an **HttpOnly cookie**
session (CSRF deferred with the writes), and a **read-only M1**.

The API today is a pure JSON service: no HTML/static serving, no CORS, and `[api].ws_allowed_origins`
defaults empty so browsers are rejected on `/ws/stats`. The desktop console holds its bearer token in the
OS keyring and sends it in the `Authorization` header; a browser has neither. So a browser surface is
**net-new engine + security work**, not front-end-only.

## Decision

Serve a **read-only** ops dashboard under `/ui`, same-origin from the existing FastAPI app, gated behind a
new `[api].serve_ui` flag (default **False**) so a JSON-only deployment is byte-identical.

### 1. Serving — one app, one socket, no CORS
`messagefoundry/api/webui/` exposes `add_ui_routes(app)`, called from `create_app` right after
`add_auth_routes(app)` **only when `serve_ui` is true**, plus a `StaticFiles` mount at `/ui/static` for
vendored assets. The UI layer imports only `fastapi`, `api.security` deps, `api.models`, and the pure
`parsing/` lib — never `pipeline/`/`store/`/`transports/`/`config/`; it resolves the live engine through
the same `_get_engine` dep as the JSON routes. Same-origin ⇒ **no `CORSMiddleware`**.

### 2. Rendering — stdlib autoescape-by-default (no jinja2)
A small `webui/_html.py` element builder escapes every dynamic value by default; pre-trusted markup must be
explicitly wrapped (`Markup`). There is **no template-syntax escape hatch** (no `|safe`), so an
un-escaped injection of attacker-influenced HL7 is not expressible. This keeps the dependency footprint at
**zero new runtime deps** — no jinja2, no re-lock, no npm, no build step — which fits the hash-locked
DEP-1 / AGPL posture and the solo-dev constraint. (jinja2 was the plan's first choice; it was dropped only
because it is a genuine new locked dependency and `uv` was unavailable to re-lock reproducibly. The
renderer is a localized module — swapping to jinja2 later is a contained change.) All HL7/message content
is treated as hostile data; no `innerHTML`/`x-html` on message-derived values.

### 3. Session — a new HttpOnly cookie, confined to `/ui`
A browser login (`POST /ui/login`) calls the **same** `AuthService.login()` the JSON `/auth/login` uses and
sets `Set-Cookie: mf_session=<opaque token>; HttpOnly; SameSite=Strict; Path=/; Secure(when https)`. The
cookie carries the *identical* opaque token the session store already issues (stored SHA-256), so logout /
idle / absolute-timeout / revoke-on-role-change keep working unchanged. **Hard boundary:** the shared
`bearer_token()` ([security.py:47](../../messagefoundry/api/security.py)) stays **Authorization-header-
only**; a **separate** `ui_cookie_identity()` reader is used **only** by `/ui` HTML routes. A JSON API
route carrying only the cookie must still `401` (test-enforced) — otherwise the whole JSON API would be
reachable with ambient cookie authority, with SameSite as the sole CSRF defense. `/auth/login` stays
byte-identical and cookie-free for the desktop console / IDE. Logout both clears the cookie **and** revokes
the session server-side.

### 4. Live numbers — poll, not WebSocket (M1)
The dashboard polls `GET /stats` + `GET /connections` (both `monitoring:read`) same-origin over HTTP,
which sidesteps the browser-WS auth problem entirely (browsers cannot set the `Authorization` header on a
WS handshake, and the `?token=` query fallback was removed for ASVS). `/ws/stats`, `ws_token`,
`authorize_ws`, and `_ws_origin_allowed` are **untouched in M1**. Poll identity resolves with
`activity=False` so a left-open dashboard tab does not reset the idle-timeout clock. The WS via a
short-lived single-use `?ticket=` is **M2**; `?token=` stays removed.

### 5. Response hardening — CSP + no-store
A path-scoped pass **sets** (not `setdefault`) `Cache-Control: no-store` on every `/ui` HTML response and
on the PHI JSON reads, and ships a strict Content-Security-Policy on `/ui`:
`default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self';
font-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'` — **no**
`unsafe-eval`/`unsafe-inline`. It composes with the existing `_security_headers` middleware
([app.py:644](../../messagefoundry/api/app.py)) so nosniff / X-Frame-Options DENY / HSTS still apply.
Vendored `/ui/static` assets keep their own long cache (never templates).

### 6. PHI — the existing audited path only
The message-detail raw view reuses the **exact** `GET /messages/{id}` gate (`require_phi_read(view_raw)` +
per-channel 404 + `record_view` + `record_audit('message_view')` + `view_summary` redaction), factored into
a shared module-level helper both routes call — **one** audited PHI path, no duplicate. No server-side
parse-tree endpoint in M1 (the audited raw `<pre>` view is sufficient; a parse-tree route is M2). Nothing
PHI is placed in browser storage; the only stored item is the token, in an HttpOnly cookie JS cannot read.

### 7. Off-loopback posture
`serve_ui` off a loopback host **requires** `exposure_protected` (in-process TLS or a declared upstream
terminator) and is **refused even under `--allow-insecure-bind`** — the UI is a stricter surface than the
JSON API. M1 default is localhost; off-loopback is an explicit, TLS-gated opt-in. The WebAuthn #11 trigger
and the ASVS 8.4.2 managed-host residual bind only on off-loopback exposure and are the owner's call.

## Options considered

1. **Thin server-rendered, stdlib renderer, cookie, poll (CHOSEN).** Zero new runtime deps, secure-by-
   construction rendering, no browser-WS auth problem in M1, no npm/build/release-leg complexity.
2. **jinja2 templates.** The plan's first choice; identical architecture but adds a locked runtime
   dependency (needs `uv` to re-lock reproducibly, which was unavailable). Deferred, not rejected — the
   renderer is swap-able.
3. **TypeScript SPA.** Rejected for M1: adds the repo's first runtime npm supply chain + a node build leg +
   a browser-test toolchain, against a solo-dev constraint (kept as a possible option-c foundation).
4. **Live stats over `/ws/stats` in M1.** Deferred: browsers can't set the WS `Authorization` header and
   the query-token fallback was removed; polling is sufficient for a read-only milestone.

## Consequences

**Positive** — a zero-install browser ops view served from the engine the adopter already runs; no new
dependency, release leg, or npm; every server-side RBAC/PHI/audit control reused unchanged; JSON-only
deployments are byte-identical (`serve_ui=False`).

**Negative / risks** — a browser surface flips ASVS L3 cells that were N/A under "no browser frontend"
(V3 session mgmt, 14.3.2/14.3.3, 3.4.3 CSP) — re-assessed for read-only M1 below; `docs/PHI.md` needs a
browser-client section before GA; the cookie seam is the highest-risk code (confinement is test-enforced).

**Out of scope (M1)** — all writes + the CSRF token stack (M2); the `/ws/stats` browser channel (M2);
a server-side parse-tree endpoint (M2); user/RBAC/MFA admin + config-deploy (stay desktop); the full
desktop-console retirement ("option c", gated per #75).

> **M2a addendum (2026-07-02) — connection controls.** The first write slice ships inbound
> **start/stop/restart** (reusing the `connections:control` JSON handlers). Its CSRF defense is a
> **token-free Origin / Sec-Fetch-Site** same-origin check (`webui.assert_same_origin`) on top of the
> SameSite=Strict cookie — deliberately no synchronizer/double-submit **token**, because a token needs a
> `hmac`/`secrets` import that would trip the ASVS 11.1.3 crypto-inventory gate, and SameSite=Strict +
> origin-check already covers same-origin form POSTs.

> **M2b addendum (2026-07-02) — message replay + browser step-up.** Single-message **replay** ships (a
> Replay button on the message detail, reusing `replay_message`). Replay is `require_step_up` in the JSON
> API; the /ui route uses **`require_ui_step_up`** — the cookie-world analogue that re-applies the exact
> step-up checks (`mfa_satisfied` + `has_recent_step_up` + `flag_new_client_ip`) the direct handler call
> would otherwise skip, but on a stale step-up **303s to `/ui/reauth`** (password, + TOTP when MFA is
> required) instead of a 403 with `X-MFA-Required`/`X-Step-Up-Required` a browser can't act on. On success
> the browser **auto-retries** the pending action via a same-origin auto-submit form (first-party
> `app.js`; graceful "Continue" fallback with JS off). **Security gate:** the re-auth `next` target is
> validated by `is_safe_ui_action` to be a `/ui/messages/{id}/replay` path **only** — never an arbitrary
> URL — so the flow cannot become an open-redirect / open-POST gadget.

> **M3 addendum (2026-07-02) — dead-letter bulk replay.** A per-channel **Replay all dead** action
> (`POST /ui/dead-letters/{channel_id}/replay`) reusing the JSON `replay_dead_letters` handler. Same
> `require_ui_step_up` gate as message replay; the channel rides in the **path** (not a body) precisely so
> the step-up auto-retry — which re-POSTs only a URL — carries it, and `is_safe_ui_action` is widened to
> `^/ui/(messages/[^/?#]+|dead-letters/[^/?#]+)/replay$`. The handler's **dual-control approval gate**
> (ADR 0014) is honored: a held replay renders a "held for a second approver" page instead of redirecting.
> Single dead-lettered messages remain replayable via their audited detail page (M2b); per-destination
> granularity stays for a later milestone.

> **M-ws addendum (2026-07-02) — live `/ws/stats` browser channel.** The dashboard's `#livestats` strip
> is filled live over the existing `/ws/stats` WebSocket (which had no consumer — the desktop console
> polls). **Browser WS auth:** a browser cannot set the WS `Authorization` header (and the `?token=` query
> fallback was removed for ASVS), so a **same-origin** handshake authenticates via the `mf_session` cookie
> it automatically carries (`webui.authorize_ui_ws`, MONITORING_READ). **CSWSH defense — two independent
> layers:** (1) the handshake `Origin` must equal the `Host` (a cross-site page is rejected); (2)
> `mf_session` is `SameSite=Strict`, so a cross-site-initiated handshake carries **no** cookie at all.
> `ws_stats` tries this browser path first, then falls back to the native header path (`authorize_ws`) —
> a native client sends no `Origin`, so it is unaffected; the periodic session revalidation uses whichever
> token authorized. The client uses `textContent` (not markup) and the payload is engine store counts,
> never message content; the connections table keeps polling, so the strip degrades to empty if the socket
> can't connect. CSP `connect-src 'self'` already permits the same-origin socket.

> **Payload-enrichment addendum (2026-07-02).** `ws_stats` now also pushes the **server-rendered
> connections fragment** (`connections_html`, scoped to the authenticated identity via `list_connections`)
> alongside `outbox_by_status`, so the /ui table updates **live over the socket**: the client swaps the
> fragment in and stops the poll while the WS is open, and resumes polling if it drops. Rendering
> server-side reuses the poll path's escaping (no client-side table building, no XSS); a native client
> that only reads `outbox_by_status` ignores the extra field, and the existing `/ws/stats` payload tests
> still pass (the field is additive). Per-connection *rate* history over the socket is a further
> follow-up; today the fragment carries the same per-connection columns the poll did.

> **Parse-tree + per-destination addendum (2026-07-02).** (a) **HL7 parse-tree view:** the message detail
> links to `GET /ui/messages/{id}/parse-tree`, which **reuses the single audited `get_message` path** (no
> new PHI egress / no duplicate audit design) and renders the segment/field tree via the pure `parsing`
> lib, every value escaped; a non-HL7 body surfaces a "no parse tree" notice. (Chosen over an inline render
> so it mirrors the desktop console's Parse-tree tab and keeps the detail page lean.) (b) **Per-destination
> dead-letter replay:** `POST /ui/dead-letters/{channel_id}/{destination_name}/replay` alongside the
> channel-wide action, same `require_ui_step_up` + approval gate; `is_safe_ui_action` widened to the
> two-segment path and hardened to reject any `..` (a `CH/..` segment normalizes in the browser, so it must
> never validate). **Deferred:** WS payload enrichment (per-connection over the socket).

> **Off-loopback exposure addendum (2026-07-02).** The safe defaults from §7 stand: `[api].host` is
> `127.0.0.1`, and `serve_ui` off-loopback requires `exposure_protected` (TLS in-process or a declared
> upstream terminator), refused even under `--allow-insecure-bind`. The one functional gap for a real
> off-loopback deployment was the same-origin **CSRF/CSWSH** checks: they compare the browser `Origin` to
> the request `Host`, which breaks behind a reverse proxy that rewrites `Host`. New opt-in
> **`[api].public_origin`** (validated to a bare `scheme://host[:port]`) is then **authoritative** — the
> `Origin` is matched against it (in both `assert_same_origin` and `authorize_ui_ws` via `_origin_matches`)
> instead of `Host`. Unset (default) = unchanged loopback / Host-preserving-proxy behavior. The
> `Sec-Fetch-Site` primary CSRF path is proxy-independent and works off-loopback regardless. **Still the
> owner's call (not built here):** phishing-resistant MFA (WebAuthn, #11) and the managed-admin-host /
> proxy-mTLS device posture (ASVS 8.4.2) for off-loopback *admin* — these bind the moment `/ui` is exposed
> and are tracked with the ASVS L3 re-assessment sign-off, not this change.

> **L5 addendum (2026-07-03).** The owner's call landed: both residuals are designed and owner-accepted
> in [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (browser WebAuthn passkeys at the step-up
> boundary + the off-loopback exposure hardening, AD/Kerberos browser login, and the 8.4.2
> managed-admin-host / reverse-proxy-mTLS guidance deliverable). AC-2's cookie boundary is restated
> there (the WebAuthn verify legs are the sanctioned first cookie-authed JSON under `/ui`, still
> per-dependency confined) and AC-6's refusal ladder is extended — never weakened — with
> `serve_ui + tls_terminated_upstream` now requiring `[api].public_origin`.

- **AC-1** — WHEN `serve_ui` is False (default), THE SYSTEM SHALL register no `/ui` routes and no
  `/ui/static` mount (a JSON-only deployment is unchanged).
  → `tests/test_webui.py::test_ui_absent_when_disabled`
- **AC-2** — WHEN a request presents the `mf_session` cookie but no `Authorization` header to a JSON API
  route, THE SYSTEM SHALL respond 401 (the cookie is confined to `/ui`; `bearer_token()` stays header-only).
  → `tests/test_webui.py::test_cookie_not_accepted_on_json_api`
- **AC-3** — WHEN a browser logs in at `POST /ui/login`, THE SYSTEM SHALL set an `mf_session` cookie with
  `HttpOnly` and `SameSite=Strict` (and `Secure` over https), and `POST /ui/logout` SHALL clear it and
  revoke the session.
  → `tests/test_webui.py::test_login_sets_confined_cookie_and_logout_revokes`
- **AC-4** — WHEN a `/ui` HTML page renders a message field containing HTML metacharacters, THE SYSTEM
  SHALL emit them escaped (no executable markup reaches the DOM).
  → `tests/test_webui.py::test_hostile_hl7_is_escaped`
- **AC-5** — WHEN a `/ui` HTML response is returned, THE SYSTEM SHALL set `Cache-Control: no-store` and a
  `Content-Security-Policy` with no `unsafe-eval`/`unsafe-inline`, while nosniff / X-Frame-Options DENY
  remain.
  → `tests/test_webui.py::test_ui_security_headers`
- **AC-6** — WHEN `serve_ui` is True with a non-loopback host and no `exposure_protected`, THE SYSTEM SHALL
  refuse to start, even under `--allow-insecure-bind`.
  → `tests/test_webui.py::test_serve_ui_offloopback_requires_tls`
- **AC-7** — THE SYSTEM SHALL reuse the single audited `GET /messages/{id}` PHI path (record_view +
  record_audit) for the `/ui` message-detail raw view (no second PHI path).
  → `tests/test_webui.py::test_ui_message_detail_audits_like_json`

> M1 ships **no third-party static assets**: the live-poll layer is a ~15-line first-party `app.js`
> (couldn't/wouldn't vendor htmx offline; a first-party poller keeps the third-party JS supply chain at
> zero and CSP at `script-src 'self'`). So there is no `VENDOR.md`/SHA gate in M1; if a third-party asset
> (e.g. htmx) is vendored in M2, add the pinned-version + SHA-256 manifest + a hash-assert test then.

## Docs this reconciles (before GA)

`docs/security/ASVS-L3-ASSESSMENT.md` (the "no browser frontend" premise + the flipped cells),
`docs/SECURITY.md` (the exposed-gate now covers `/ui`), `docs/PHI.md` (write the missing browser-client
section), and supersedes the CORS + localStorage language in [BACKLOG #75](../BACKLOG.md).
