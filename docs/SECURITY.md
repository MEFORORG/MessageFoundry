# Users & Security (Authentication + RBAC)

MessageFoundry authenticates every operator and authorizes every action with **role-based access
control (RBAC)**. It supports **local users** and **Active Directory** (LDAP bind + optional Windows
SSO), maps **AD security groups to roles**, and attributes every action to a unique user in the audit
trail. The design meets or exceeds Mirth Connect and Corepoint on the points that matter for a
healthcare interface engine — notably: RBAC is built in (not a paid add-on), password policy ships
with secure defaults, and AD-group→role mapping is automatic.

> Carries PHI. This doc covers **identity, access control, and the audit of operator actions**.
> The protection of the *data* itself — at-rest storage/encryption, transport, logging/redaction,
> retention, and de-identification — lives in [PHI.md](PHI.md). MEFOR is deployed **inside the
> organization's private network, never internet-facing**; the trust boundary + the management/data/
> inbound three-plane posture are in [PHI.md §1](PHI.md) and [DEPLOYMENT.md](DEPLOYMENT.md).

---

## Enforcement model

Authentication is **required** for the running service. The engine `serve` command always attaches an
auth layer (`[security] require_sign_in = true` by default). Of the **108** engine route objects, **90 demand a
specific permission** and 18 do not — 3 are deliberately unauthenticated (`GET /auth/providers`, an
unbounded capability advertisement that carries no account state and charges **no** limiter;
`POST /auth/login` and `POST /auth/negotiate`, bounded by the per-IP **and** global login sliding
window instead), 2 answer a tokenless
client through `optional_identity` (`GET /health`, `GET /ai/policy`), and 13 are authenticated
self-service routes that require no permission. One route (`GET /service/identity`) accepts **no bearer
token at all** — it authenticates by verified mTLS client certificate only. Every route is enumerated,
with its gate, in [Route → permission map](#route--permission-map-engine-api) below; nothing is left
implicit.

The in-process embedding factory `create_app(engine)` is **fail-closed**: with no `AuthService`
attached it denies every protected route (503) unless the caller explicitly opts out with
`create_app(..., allow_no_auth=True)` — the deliberate embedding/local-dev escape hatch. The `serve`
path runs auth-enabled by default; if `[security] require_sign_in = false` it sets that opt-in itself, and
`__main__` refuses to serve auth-off on an exposed instance — a non-loopback host, or a loopback host
behind a declared TLS terminator — and, even with auth enabled, a
non-loopback bind requires **TLS**: in-process (`[api].tls_cert_file`, WP-13a) or terminated at a
trusted upstream proxy (`tls_terminated_upstream` + `trusted_proxies`, WP-15), or — as a dev override —
an explicit `serve --allow-insecure-bind` (without any of these, bearer tokens + PHI would cross the
network in cleartext, so it's refused). So there is no way to be accidentally served with silent,
unauthenticated full access — or to silently void the loopback assumption with a stray `[api].host`
edit (SYS-1).

### First-run bootstrap admin

On first start against an empty store, the engine creates a single **bootstrap admin**
(username `admin`, role `Administrator`) with a random one-time password **generated through the
active password policy**. The password is **written to an owner-only file** (`bootstrap-admin.txt`,
next to the store) — **never to the log** — and only the file's location is logged, so the credential
doesn't land in NSSM's broadly-readable stdout capture. Sign in with it, change the password
immediately (enforced — the account is flagged `must_change_password`), and delete the file. After any
user exists, no further bootstrap occurs.

**Auto-retirement (WP-3).** The bootstrap account exists only to seed the first real admin, so it
self-retires while still **unclaimed** — while its holder has never rotated the password themselves:
it is **disabled once a second administrator exists**, and — if left unclaimed — **disabled
`[auth].bootstrap_expiry_hours` after creation** (default 72 h; `0` disables the timer). Rotate its
password through self-service change-password and the account is **claimed**: it becomes a normal
admin account and is never auto-disabled, so a single-admin deployment can't be locked out. The claim
is **recorded** — `users.password_claimed_at`, stamped by that rotation and never cleared — rather
than inferred from the credential state the account currently carries
([ADR 0164](adr/0164-record-bootstrap-claimed-ness-never-infer-a-monotonic-lifecycle-fact-from-mutable-credential-state.md)),
so an [admin password reset](#admin-password-reset-wp-l3-12-asvs-646) of a claimed bootstrap account
does not un-claim it: the temp it issues must still be rotated, but retirement stays off. And
auto-retirement is not the only way to lose an administrator: the failed-attempt lockout is a
**separate mechanism** and it does reach a claimed sole administrator (see
[Brute-force & abuse protection](#brute-force--abuse-protection)). A retired
bootstrap login is refused like any other invalid credential and the retirement is audited
(`auth.bootstrap_admin_retired`).

### Admin password reset (WP-L3-12, ASVS 6.4.6)

An administrator (`users:manage`) recovers a locked-out or compromised **local** account with
`POST /users/{user_id}/reset-password`. The engine generates a **CSPRNG one-time password through the
active policy**, sets it with `must_change_password`, and **revokes the user's sessions**; the temp is
returned **once** in the response for the admin to convey out-of-band, and the affected user is also
emailed a reset notice (the same security-event channel as [Security-event notifications](#security-event-notifications-wp-l3-05-asvs-635--637)).
The administrator therefore never sets a *lasting* password the user keeps (ASVS 6.4.6) — the one-time
credential must be rotated on first login. AD users are refused (they authenticate against the
directory); resetting your own account is refused (use self-service change-password). The action is
audited (`auth.password_reset`). For the same reason, **admin-created accounts are flagged
`must_change_password`** so the operator's initial password is a one-time temp the user must rotate.

**Anti-automation (ASVS 2.4.2).** A per-actor human-timing *pacing floor* on sensitive authenticated
writes is **built** (BACKLOG #193). **Two** JSON-API gate families charge it, drawing **one bucket per
actor** (`allow_admin_write`, keyed on the acting user, `_enforce_admin_write_pacing` in
`api/security.py` is their only caller):

- **`require_step_up`** — the sensitive surface that also needs a fresh credential re-proof: purge,
  dead-letter and message replay/resend/edit-resend, `POST /config/reload`, **every** `users:manage`
  write — the `PATCH /users/{user_id}` exemption is gone, because BACKLOG #1148 made the action-bound
  `require_step_up_action` charge the same floor — the `/roles/custom` writes, the
  `/uploads` writes, `POST /search/presets`.
- **`require_paced`** — state-changing routes that warrant pacing but **not** a step-up re-proof:
  connection start/stop/restart/flag/test/test-credential, `POST /statistics/reset`, the four
  `/alerts/{id}/*` writes, approvals approve/reject, `POST /dr/activate|release`,
  `POST /status/integrity-check`.

Both charge **non-GET requests only**, so the step-up **GET**s are exempt from *that* limiter by design
— they are reads, not writes — but they are not unpaced: the **four** that select PHI in bulk
(`/messages/search`, `/messages/export`, `/search/layered`, `/uploads/{file_id}/messages`) charge the
per-actor **PHI-read** budget. `/search/layered` charges it at its own route; the other three charge
it INSIDE the shared implementation that each GET and its needle-bearing POST both call (BACKLOG
#1184), so a route pair is paced identically without either half having to remember to charge. The
budget charged is
(`allow_phi_read`, ASVS 2.4.1) at admission, so bulk egress cannot outrun the same bucket that bounds
`/messages`. Over the write floor the request is refused with `429 Too Many Requests` +
`Retry-After: 1`; over the PHI-read budget with `429` + `Retry-After: 10`. Both are logged (never
silent). The floor (`[auth].admin_write_rate_limit_per_actor` over
`admin_write_rate_limit_window_seconds`, default **12 writes per 1.0 s**) sits an order of magnitude
above human console interaction and above the worst-case `403 → POST /me/reauth → retry` burst, so an
operator is never throttled while a machine-speed loop trips immediately.

**The `/ui` write path is paced, and charges the floor itself.** The console's write routes call the
JSON handler *functions* directly, so the JSON route's pacing `Depends` never runs — `require_ui`
therefore charges `allow_admin_write` in its own right rather than inheriting it, exactly as it
already re-applies the per-actor **PHI-read** budget via `require_ui(..., phi=True)`. Provenance is
asserted before the charge, so a cross-site write is refused without spending the victim's budget.
The floor reaches every non-GET `/ui` route gated by `require_ui`; **seven are not so gated** -- the
sign-in and re-auth charge their own budgets; the remaining three charge nothing (BACKLOG #287).

Pacing complements — does not replace — the RBAC gate, the step-up re-verification, the sign-in
sliding window and the per-actor credential-ceremony limiter (`auth/ratelimit.py`), the per-account
lockout, the argon2 concurrency cap, the 1 MiB body cap, the per-actor PHI-read throttle, and the
pre-auth `[security].allowed_client_networks` gate — the full set is inventoried under
[Brute-force & abuse protection](#brute-force--abuse-protection). In-process only (per API process,
so N engine shards multiply every budget by N): an off-loopback deployment must additionally front the
API with a proxy/WAF limiter. Disable with `[auth].admin_write_rate_limit_enabled = false`.

**Authorization-decision audit (ASVS 16.3.2).** **Every** authorization grant is audited
(`auth.permission_granted`), the twin of the existing `auth.permission_denied` (BACKLOG #195a). PHI-view
grants are the one standing exclusion, because the PHI-access audit path already records those accesses
(no double-audit).

That is the shipped default as of BACKLOG #1277 (2026-09-02). Until then the grant audit was **scoped**
to the sensitive / state-changing / config / user-mgmt permission set (`_GRANT_AUDIT_PERMISSIONS` in
`api/security.py`) on non-GET requests only, on the ground that console polling and the `/ws/stats` feed
would flood the hash-chained audit log. **The console never traverses `require()`** — it is
server-rendered in-process and gates on its own cookie-world check — and `authorize_ws` fires once per
*connection*. Setting `[security].audit_all_authorization_decisions = false` restores the scoped
behaviour and is reported as a loosening; the volume it trades away is one row per authenticated request
per `require()`-gated route, on the JSON API.

**Delegated identity & admin device posture (#193 sibling; ASVS 13.2.1 / 13.3.2 / 8.4.2 — the delegation
boundary).** Three controls whose enforcement is largely the deploying organization's to provide.
MessageFoundry states the boundary and adds one opt-in precondition check (#203):

- **Managed identity over static credentials.** The store can authenticate with a managed / delegated
  identity — SQL Server `[store].auth = integrated` (gMSA / Windows Integrated) or `entra` (Microsoft
  Entra ID) — instead of a static username + password. Set `[store].require_managed_identity = true` to
  make it a **checked precondition**: on a **production** instance `serve` **refuses to start** (a
  non-production instance **warns**) if the store still uses a static SQL login, or a Postgres store
  (which has no managed-identity mode). Off by default. AD (`ad_bind_password`) and SMTP
  (`email_password`) have no managed-identity mode yet — supply those secrets via the environment
  (`MEFOR_*`, never the config file) under a least-privilege service account.
- **Least-privilege secret access** is the operator's precondition: secrets live in the environment, the
  engine's service account is granted only what it needs (the least-privilege account + ACLs are the
  Windows-service install's job), and at-rest custody is the DPAPI / KeyProvider chain. The precondition
  flag above surfaces the *store* slice of this at start time; the rest is asserted, not engine-checked.
- **Admin device posture** (managed / compliant admin endpoints) stays **100 % deployment-delegated**:
  enforce it at the reverse proxy (mTLS client certificates) plus MDM in front of an off-loopback `/ui`,
  not inside the engine — the engine has no device-attestation channel and does not attempt one.

---

## Roles & permissions

### Authorization design (ASVS 8.1.1)

Every request is authorized by the same chain. Each link can refuse on its own; a request reaches a
route handler only when all of them pass.

1. **Pre-routing client-network deny** — `ClientNetworkMiddleware` (registered last, so Starlette makes
   it the *outermost* user middleware) refuses a request whose client address falls outside
   `[security].allowed_client_networks` with **403** (`X-MessageFoundry-Denied: client-network`) or a
   pre-accept WebSocket close `1008`, before routing, dependencies, the body cap and auth. `GET /health`
   is the sole exempt path. Empty list (the default) = no restriction. See
   [Contextual and environmental security inputs](#contextual-and-environmental-security-inputs-asvs-813--814).
2. **Authentication plane selection** — one of three, and they never cross: an opaque **bearer session
   token** (the JSON API), a verified **mTLS client certificate** (only `GET /service/identity`), or the
   `/ui`-confined `SameSite=Strict` **session cookie** (the web console).
3. **The `require*()` deny-by-default ladder**, in this order: **503** `authentication is not configured`
   when no enabled `AuthService` is attached and `allow_no_auth` was not set (the fail-closed embedding
   guard, SYS-1) → **401** when the bearer token resolves to no identity → **403** `password change
   required` when the identity is flagged `must_change_password` and the path is not one of the three
   exempt paths (`/auth/logout`, `/auth/me`, `/me/password`) → **403** `missing permission: <value>`
   plus an `auth.permission_denied` audit row for the first unheld permission. On success it writes one
   `auth.permission_granted` row — **every satisfied route, GETs included**, since
   `[security].audit_all_authorization_decisions` defaults **on** (BACKLOG #1277). PHI-view grants are
   the standing exclusion: the PHI-access path records those. Turning the switch off narrows it to the
   sensitive permission set on non-GET requests only. ADR 0118 relocated the knob, and the old
   `[diagnostics].audit_all_authz` TOML spelling is **refused at load**.
4. **A second axis: per-channel scope** — `users.channel_scope` narrows operational routes to a set of
   connections, and it **denies by default**: a new non-administrator is granted no channel until
   somebody grants one (BACKLOG #1152; the full rule is *Per-channel scoping (DLQ-SCOPE)* below).
   Out-of-scope *message* access returns **404** (existence-hiding); connection control and inbound
   injection return **403**. Denials are audited `auth.channel_denied`.

The table below has **seven** rows. `require` is the ladder itself; five wrappers extend it
(`require_paced`, `require_phi_read`, `require_step_up`, `require_step_up_action`, and the shared
`require_reauth_only`/`require_reauth_only_action` row); `require_service_cert` deliberately
**bypasses** it — a separate, cert-only identity plane where none of `require`'s session concerns
apply. What each **adds** over plain `require()`:

| Gate wrapper | Routes | What it adds over `require()` |
|---|---|---|
| `require` | 43 | nothing — the ladder itself |
| `require_paced` | 16 | per-actor anti-automation pacing on **non-GET** requests (`allow_admin_write`), 429 + `Retry-After: 1` |
| `require_phi_read` | 7 | the ADR 0092 PHI-read hop refusal (`enforce_phi_read_hop`) **before** any identity work, then the per-actor PHI-read budget, 429 + `Retry-After: 10` |
| `require_step_up` | 27 | the same non-GET pacing, then the **MFA gate** (403 + `X-MFA-Required: 1`), the **new-client-IP** signal, and the credential-recency window (403 + `X-Step-Up-Required: 1`) |
| `require_step_up_action` | 4 | the same non-GET pacing (BACKLOG #1148), the **MFA gate**, then a **single-use, action-bound** step-up grant minted only by `POST /me/reauth` (403 + `X-Step-Up-Action: <action>`). Promoting a route here no longer drops the pacing floor |
| `require_reauth_only_action` | 4 | password step-up **without** the MFA gate — deadlock avoidance on the MFA-enrollment lanes, and on session terminate (ASVS 7.5.2), where the grant is action-bound so a login-seeded window does not unlock it. `require_reauth_only` still exists and still backs the `/ui` twin, but BACKLOG #1149 moved the last JSON route off it, so it no longer appears in this walk |
| `require_service_cert` | 1 | cert-only authentication (a bearer token gets 401), and a **PHI fence** that raises at *app construction* if asked to gate `messages:view_summary` / `messages:view_raw` |

`optional_identity` (2 routes) never raises, so a tokenless client is answered; `authorize_ws` (1 route)
validates the handshake `Origin` against `[api].ws_allowed_origins` **before** `accept()`, then the
bearer token, the must-change lockout and the permission.

### Permission catalogue (28)

The catalogue is `Permission` in [`auth/permissions.py`](../messagefoundry/auth/permissions.py); the
enum value **is** the wire/storage string. "Routes" counts engine route objects gated on that permission
under `create_app()` (they sum to 92, not 90, because BOTH `/messages/export` routes require two).

| Constant | Permission | PHI | Routes | Gates |
|---|---|---|:--:|---|
| `MONITORING_READ` | `monitoring:read` | | 19 | the whole read/dashboard surface + `GET /service/identity` (mTLS) + `WS /ws/stats` |
| `MONITORING_DIAGNOSE` | `monitoring:diagnose` | | 9 | `POST /statistics/reset`, the `/alerts` active+write routes, `GET`/`PATCH /logging/level`, `POST /status/integrity-check` |
| `MESSAGES_READ` | `messages:read` | | 9 | `/messages`, `/dead-letters`, `/messages/search` (GET **and** the needle-bearing POST), `/messages/{id}/responses`, `/search/*` |
| `MESSAGES_VIEW_SUMMARY` | `messages:view_summary` | **PHI** | 0 | no route — enforced **per property** by the field authorizer over 6 response models (see [Field-level authorization](#field-level-property-authorization-wp-9)) |
| `MESSAGES_VIEW_RAW` | `messages:view_raw` | **PHI** | 5 | the whole message body: `GET /messages/{id}`, `/attachments/{id}`, `/outbound`, `/messages/export`; also the per-property switch for the captured-reply `body` |
| `MESSAGES_REPLAY` | `messages:replay` | | 2 | `POST /dead-letters/replay`, `POST /messages/{id}/replay` |
| `MESSAGES_RESEND` | `messages:resend` | | 1 | `POST /messages/{id}/resend` — resend a stored body to an **alternate** outbound (ADR 0090) |
| `MESSAGES_EDIT` | `messages:edit` | **PHI** | 1 | `POST /messages/{id}/edit-resend`. The edited body **is** PHI, so it **implies** `messages:view_raw` **for the built-in roles** — every built-in role granting it also grants view_raw. **Minting** does not enforce that implication and deliberately still does not: `messages:edit` is not in `CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`, so a custom role holding it alone stays mintable. The **console editor** enforces it at the gate instead (BACKLOG #324) — `GET /ui/messages/{id}/edit` and `POST /ui/messages/{id}/edit-resend` require `messages:view_raw` **as well**, and fail closed on either, because the editor displays the body it edits |
| `MESSAGES_EXPORT` | `messages:export` | **PHI** | 2 | `GET`/`POST /messages/export` — the **largest PHI egress surface**; a capability distinct from `view_raw` (bulk ≠ opening one message), and the route requires **both** plus step-up |
| `MESSAGES_PURGE` | `messages:purge` | | 1 | `POST /connections/{name}/purge` |
| `CONNECTIONS_CONTROL` | `connections:control` | | 3 | `POST /connections/{name}/start`, `/stop`, `/restart` |
| `CONNECTIONS_TEST` | `connections:test` | | 2 | `POST /connections/{name}/test`, `/test-credential` |
| `DR_OPERATE` | `dr:operate` | | 2 | `POST /dr/activate`, `/dr/release` (ADR 0048). Never assignable to a custom role |
| `CONFIG_DEPLOY` | `config:deploy` | | 2 | `POST /config/reload` **and** `POST /connections/{name}/flag` |
| `CONFIG_VALIDATE` | `config:validate` | | 0 | no endpoint yet (see the note below) |
| `CODE_EDIT` | `code:edit` | | 0 | no endpoint yet |
| `AI_ASSIST` | `ai:assist` | | 1 | `POST /ai/chat`; also *reported* (not enforced) as `assist_permitted` on the unauthenticated `GET /ai/policy` |
| `SERVICE_CONFIGURE` | `service:configure` | | 1 | `POST /alerts/test-email` — a live outbound SMTP dial through the configured `[alerts]` mail transport (BACKLOG #118); service/settings administration, not the diagnostic ack/resolve tier |
| `USERS_READ` | `users:read` | | 4 | `GET /roles`, `/roles/custom`, `/users`, `/users/{id}/permissions` |
| `USERS_MANAGE` | `users:manage` | | 16 | every user/role/AD-map write **and** the three reads `GET /users/{id}/channel-scope`, `/ad-group-map`, `/ad-group-scope-map`. Never assignable to a custom role |
| `AUDIT_READ` | `audit:read` | | 1 | `GET /audit` |
| `AUDIT_EXPORT` | `audit:export` | | 1 | `GET /audit/export` — the filtered audit-report CSV (BACKLOG #170); distinct from `audit:read` |
| `LOGS_VIEW` | `logs:view` | **PHI** | 1 | `GET /logs/tail` — the best-effort-redacted application-log tail (residual single-token PHI is possible), so it rides `require_phi_read` and writes a `logs_view` audit row |
| `FILES_UPLOAD` | `files:upload` | **PHI** | 1 | `POST /uploads` — writes real HL7 PHI at rest |
| `FILES_BROWSE` | `files:browse` | **PHI** | 4 | `GET /uploads` (metadata), `GET /uploads/{id}/messages` (bulk decrypt+split), `POST /uploads/{id}/resend` |
| `FILES_DELETE` | `files:delete` | | 1 | `DELETE /uploads/{id}` — destructive, audited cleanup |
| `FILES_ACCESS_ANY` | `files:access_any` | **PHI** | 0 | no route — an **object-level** override (ASVS 8.2.2), enforced in the uploaded-files handler bodies rather than at a gate (the console calls those handlers directly over the seam, so a gate would not cover it). Uploaded files are **owner-only**: without this, `files:browse`/`files:delete` reach only what the caller uploaded; with it, every uploader's. It is not a capability of its own — the holder still needs `files:browse` / `files:delete` for the route. Never assignable to a custom role |
| `APPROVALS_APPROVE` | `approvals:approve` | | 3 | `GET /approvals`, `POST /approvals/{id}/approve`, `/reject` (dual control, ASVS 2.3.5). Never assignable to a custom role |

`config:validate` and `code:edit` have **no API endpoint yet**; they are defined so
the Deployment/Coding roles are complete and those endpoints can be gated the moment they land, without
a roles migration. They are still in `_GRANT_AUDIT_PERMISSIONS`, so a future route inherits grant
auditing for free.

### Built-in roles

Six fixed built-in roles (`Role` + `BUILTIN_ROLE_PERMISSIONS`). Holding multiple roles grants the
**union**; `Identity.has()` is a flat frozenset membership test, so there is no wildcard and no
inheritance — where a permission came from is invisible downstream.

| Role | Count | Permissions |
|---|:--:|---|
| **Administrator** | 28 | **every permission** — literally `frozenset(Permission)`, so a newly added permission is granted to it automatically |
| **Operator** | 16 | `monitoring:read`, `monitoring:diagnose`, `messages:read`, `messages:view_summary`, `messages:view_raw`, `messages:replay`, `messages:resend`, `messages:edit`, `messages:export`, `messages:purge`, `connections:control`, `connections:test`, `logs:view`, `files:upload`, `files:browse`, `files:delete` |
| **Deployment** | 4 | `monitoring:read`, `config:deploy`, `config:validate`, `connections:test` |
| **Coding** | 4 | `monitoring:read`, `code:edit`, `config:validate`, `ai:assist` |
| **Viewer** | 2 | `monitoring:read`, `messages:read` |
| **Auditor** | 3 | `monitoring:read`, `audit:read`, `audit:export` |

An Operator therefore reaches **five PHI-marked capabilities beyond viewing one message** — counted
straight off the catalogue's PHI column, minus the two that *are* viewing one message
(`messages:view_summary`, `messages:view_raw`): edit-and-resubmit (`messages:edit`, whose console
editor renders the full raw body at `GET /ui/messages/{id}/edit` — a route that requires
`messages:view_raw` alongside it, so the grant does not reach the body on its own), bulk raw export
(`messages:export`), the redacted log tail (`logs:view`), and the two PHI-touching uploaded-file
capabilities (`files:upload`, `files:browse`). `files:delete` is **not** in that count: it destroys
PHI, it does not emit it, and the catalogue leaves its PHI column empty. A Viewer holds no PHI-field
permission at all, so every gated property comes back `null` for them.

### Custom roles (ADR 0045)

The custom-role builder **is built** and is an *additive overlay* on the six built-ins, not a
replacement:

- A custom role is a named **subset of the existing 28-permission catalogue** — it can never define a
  new permission kind.
- Its id must carry the `custom:` prefix (`CUSTOM_ROLE_ID_PREFIX`), so it can never collide with a
  built-in role value or be mis-routed to the built-in resolver.
- It may **never** grant `users:manage`, `approvals:approve`, `dr:operate` or `files:access_any`
  (`CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`) — the escalation primitives stay admin-only.
- An empty set or an unknown permission string is rejected on write (`CustomRoleError`); a
  malformed/hand-edited persisted `roles.permissions` row decodes **defensively to the empty set**, and
  a forbidden value that somehow reached storage is dropped.
- A caller's effective permission set is the flat union of built-in-role permissions and custom-role
  `extra_permissions`, computed once per request in `Identity.build`.

Managed at `GET /roles/custom` (`users:read`) and `POST` / `PUT` / `DELETE /roles/custom[/{role_id}]`
(`users:manage` + step-up).

> **AI coding assistance is RBAC-gated and centrally policy-governed.** `ai:assist` (held by
> **Coding** and **Administrator**) controls whether an identity may use the IDE AI assistant; the
> assistant is additionally bounded by an environment-clamped, central **policy** (`mode` from
> OFF→PHI-safe, `data_scope`, `environment`) read via `GET /ai/policy` — see [AI.md](AI.md). That
> endpoint is intentionally **unauthenticated** (the install policy is non-sensitive operational
> config that a central *off* must be able to enforce on a tokenless client); the identity-dependent
> bit rides in its `assist_permitted` field, and policy reads are **not** audited in the MVP.
> Per-*use* egress auditing arrives with the future engine broker.

### Route → permission map (engine API)

**Counting basis.** `create_app()` with no arguments builds **108 route objects** — 67 declared in
[`api/app.py`](../messagefoundry/api/app.py) (66 HTTP + 1 WebSocket) and 38 declared in
[`api/auth_routes.py`](../messagefoundry/api/auth_routes.py). No other module in `api/` declares routes
and there is no `include_router` anywhere. `create_app(expose_docs=True)` yields 112 (`/openapi.json`,
`/docs`, `/docs/oauth2-redirect`, `/redoc`; off by default) and `create_app(serve_ui=True)` yields 201
(108 + the 97 console routes + the `/ui/static` mount). Of the 108: **90 are permission-gated**, 18 are
not. Every one is listed below — none is collapsed away.

#### Functions requiring no authorization

These are the routes the requirement equally demands be defined.

| Method | Path | Why | Compensating control |
|---|---|---|---|
| `GET` | `/auth/providers` | which sign-in pathways this install offers, needed to render the login page | login sliding window is **not** charged here |
| `POST` | `/auth/login` | the sign-in ceremony itself | per-IP **and** global login sliding window |
| `POST` | `/auth/negotiate` | Kerberos/SPNEGO sign-in | per-IP **and** global login sliding window |
| `GET` | `/health` | liveness must be answerable tokenless; the **only** path exempt from the pre-routing client-network gate | build version disclosed only to an authenticated caller (`optional_identity`) |
| `GET` | `/ai/policy` | a central `off` must be enforceable on a tokenless client | `assist_permitted` is `None` for an unauthenticated caller (`optional_identity`) |

#### Authentication & self-service — authenticated, no permission required

All 13 use `require()` / `require_reauth_only*` / `require_step_up_action` with an **empty** permission
tuple: they act only on the caller's own account.

| Method | Path | Gate | Extra constraints |
|---|---|---|---|
| `POST` | `/auth/logout` | `require` | exempt from the `must_change_password` confinement |
| `GET` | `/auth/me` | `require` | exempt from the `must_change_password` confinement |
| `POST` | `/me/password` | `require` | per-**actor** credential-ceremony limiter; refused (400) for an AD identity; exempt from the confinement |
| `POST` | `/me/reauth` | `require` | per-**actor** credential-ceremony limiter; mints the action-bound grant when `purpose=` is given |
| `POST` | `/auth/mfa-verify` | `require` | draws the **sign-in** window (per-IP + global); feeds the per-account lockout |
| `GET` | `/me/mfa` | `require` | |
| `POST` | `/me/mfa/enroll` | `require_reauth_only_action` (action `mfa_enroll`) | password-only step-up — the MFA gate is skipped so a required-but-unenrolled user cannot deadlock |
| `POST` | `/me/mfa/confirm` | `require_reauth_only_action` (action `mfa_confirm`) | per-actor ceremony limiter; password-only step-up |
| `DELETE` | `/me/mfa` | `require_step_up_action` (action `mfa_disable`) | step-up bound to the disable action (current factor + a fresh password). **Refuses (400) when TOTP is your last second factor and MFA is required for your account** — the same refusal, on the same condition, as the passkey removal path (`AuthService.disable_mfa`, ADR 0068 decision 5). The asymmetry this row used to record is closed (BACKLOG #1022) |
| `GET` | `/me/sessions` | `require` | |
| `GET` | `/me/security-events` | `require` | |
| `DELETE` | `/me/sessions/{session_id}` | `require_reauth_only_action` (action `session_terminate`) | password-only step-up, bound to the action (ASVS 7.5.2): a login-seeded window does not unlock a terminate |
| `DELETE` | `/me/sessions` | `require_reauth_only_action` (action `session_terminate`) | password-only step-up, bound to the action (ASVS 7.5.2) |

#### Users, roles & directory maps

| Method | Path | Permission | Gate |
|---|---|---|---|
| `GET` | `/roles` | `users:read` | `require` |
| `GET` | `/roles/custom` | `users:read` | `require` |
| `POST` | `/roles/custom` | `users:manage` | `require_step_up` |
| `PUT` | `/roles/custom/{role_id}` | `users:manage` | `require_step_up` |
| `DELETE` | `/roles/custom/{role_id}` | `users:manage` | `require_step_up` |
| `GET` | `/users` | `users:read` | `require` |
| `GET` | `/users/{user_id}/permissions` | `users:read` | `require` — the effective-permission inspector |
| `POST` | `/users` | `users:manage` | `require_step_up` |
| `PATCH` | `/users/{user_id}` | `users:manage` | `require_step_up_action` (action `admin_user_update`) |
| `DELETE` | `/users/{user_id}` | `users:manage` | `require_step_up` |
| `DELETE` | `/users/{user_id}/sessions` | `users:manage` | `require_step_up` |
| `PUT` | `/users/{user_id}/roles` | `users:manage` | `require_step_up` |
| `POST` | `/users/{user_id}/reset-password` | `users:manage` | `require_step_up_action` (action `admin_reset_password`) |
| `POST` | `/users/{user_id}/reset-mfa` | `users:manage` | `require_step_up_action` (action `admin_reset_mfa`); **refuses (400) when `user_id` is the caller's own** — use the self-service MFA settings instead. Targeting yourself here was a third route to zero factors that skipped the last-factor refusal both self-service paths make (BACKLOG #1022). Cross-user reset is untouched: it is the always-available recovery for a locked-out passkey user (ADR 0068 §2) |
| `GET` | `/users/{user_id}/channel-scope` | `users:manage` | `require` (a read on the `users:manage` tier, not `users:read`) |
| `PUT` | `/users/{user_id}/channel-scope` | `users:manage` | `require_step_up` |
| `GET` | `/ad-group-map` | `users:manage` | `require` |
| `PUT` | `/ad-group-map` | `users:manage` | `require_step_up` |
| `GET` | `/ad-group-scope-map` | `users:manage` | `require` |
| `PUT` | `/ad-group-scope-map` | `users:manage` | `require_step_up` |

#### Audit

| Method | Path | Permission | Gate |
|---|---|---|---|
| `GET` | `/audit` | `audit:read` | `require` |
| `GET` | `/audit/export` | `audit:export` | `require` — filtered CSV report (BACKLOG #170) |

#### Monitoring, status & diagnostics

| Method | Path | Permission | Gate |
|---|---|---|---|
| `GET` | `/security/posture` | `monitoring:read` | `require` |
| `GET` | `/channels` | `monitoring:read` | `require` |
| `GET` | `/connections` | `monitoring:read` | `require` |
| `GET` | `/connections/{name}/metadata` | `monitoring:read` | `require` — per-channel for inbound; a shared outbound is barred to scoped users; credentials scrubbed unconditionally |
| `GET` | `/events` | `monitoring:read` | `require` |
| `GET` | `/connections/{name}/events` | `monitoring:read` | `require` |
| `GET` | `/stats` | `monitoring:read` | `require` |
| `GET` | `/metrics` | `monitoring:read` | `require` |
| `GET` | `/metrics/history` | `monitoring:read` | `require` |
| `GET` | `/graph/edges` | `monitoring:read` | `require` |
| `GET` | `/alerts/rules` | `monitoring:read` | `require` |
| `GET` | `/config/provenance` | `monitoring:read` | `require` |
| `GET` | `/status` | `monitoring:read` | `require` |
| `GET` | `/cluster/status` | `monitoring:read` | `require` |
| `GET` | `/cluster/nodes` | `monitoring:read` | `require` |
| `GET` | `/dr/status` | `monitoring:read` | `require` |
| `GET` | `/service/status` | `monitoring:read` | `require` |
| `GET` | `/logging/level` | `monitoring:diagnose` | `require` |
| `PATCH` | `/logging/level` | `monitoring:diagnose` | `require` — **not** paced (see the gap note under [Brute-force & abuse protection](#brute-force--abuse-protection)) |
| `POST` | `/statistics/reset` | `monitoring:diagnose` | `require_paced` |
| `POST` | `/status/integrity-check` | `monitoring:diagnose` | `require_paced` |
| `GET` | `/alerts/active` | `monitoring:diagnose` | `require` |
| `POST` | `/alerts/{alert_id}/ack` | `monitoring:diagnose` | `require_paced` |
| `POST` | `/alerts/{alert_id}/resolve` | `monitoring:diagnose` | `require_paced` |
| `POST` | `/alerts/{alert_id}/suspend` | `monitoring:diagnose` | `require_paced` |
| `POST` | `/alerts/{alert_id}/resume` | `monitoring:diagnose` | `require_paced` |
| `POST` | `/alerts/test-email` | `service:configure` | `require` — operator test-send through the configured `[alerts]` email transport (BACKLOG #118); fires a live outbound SMTP dial, so it is admin-gated rather than `monitoring:diagnose`; sends a synthetic PHI-free event and returns no addresses; audited `alert_test_email` |
| `WS` | `/ws/stats` | `monitoring:read` | `authorize_ws` — `Origin` validated against `[api].ws_allowed_origins` **before** `accept()`; Authorization header only, no `?token=` fallback |
| `GET` | `/service/identity` | `monitoring:read` | `require_service_cert` — **mTLS client certificate only**; PHI-fenced at app construction; writes a `service_cert_auth` audit row |

#### Connections, approvals, DR & config

| Method | Path | Permission | Gate |
|---|---|---|---|
| `POST` | `/connections/{name}/start` | `connections:control` | `require_paced` |
| `POST` | `/connections/{name}/stop` | `connections:control` | `require_paced` |
| `POST` | `/connections/{name}/restart` | `connections:control` | `require_paced` |
| `POST` | `/connections/{name}/test` | `connections:test` | `require_paced` — reachability probe; honors `[egress]`, sends no real data, audited |
| `POST` | `/connections/{name}/test-credential` | `connections:test` | `require_paced` |
| `POST` | `/connections/{name}/flag` | `config:deploy` | `require_paced` |
| `POST` | `/connections/{name}/purge` | `messages:purge` | `require_step_up` — may return **202 + `approval_id`** under dual control |
| `POST` | `/config/reload` | `config:deploy` | `require_step_up` — the target dir must resolve within an allowed root (see below) |
| `GET` | `/approvals` | `approvals:approve` | `require` |
| `POST` | `/approvals/{approval_id}/approve` | `approvals:approve` | `require_paced` — the requester can never approve their own request |
| `POST` | `/approvals/{approval_id}/reject` | `approvals:approve` | `require_paced` |
| `POST` | `/dr/activate` | `dr:operate` | `require_paced` |
| `POST` | `/dr/release` | `dr:operate` | `require_paced` |

#### Messages (PHI)

| Method | Path | Permission | Gate | Extra constraints |
|---|---|---|---|---|
| `GET` | `/messages` | `messages:read` | `require_phi_read` | per-property redaction; `messages:view_summary` unlocks `summary`/`error`/`metadata`; per-channel scope |
| `GET` | `/messages/search` | `messages:read` | `require_step_up` | explicit `enforce_phi_read_hop` + `enforce_phi_read_pacing` (a bulk-selecting GET) |
| `GET` | `/messages/export` | `messages:export` **+** `messages:view_raw` | `require_step_up` | one of the two-permission routes **on the JSON plane** (the console plane has its own — see the [`/ui` route map](#the-ui-console-plane-serve_uitrue)); explicit PHI-read hop + pacing; streams NDJSON, bypassing the response models |
| `POST` | `/messages/search` | `messages:read` | `require_step_up` | the needle-bearing sibling of the GET above (BACKLOG #1184): `content`/`field_value` travel in the BODY so they never reach a URL, access log or browser history. Same gate, same shared implementation, so the PHI-read hop and budget are charged identically |
| `POST` | `/messages/export` | `messages:export` **+** `messages:view_raw` | `require_step_up` | the needle-bearing sibling of the export GET (BACKLOG #1184); same two permissions, same fail-closed-on-either behaviour, same pre-stream audit — only the criteria's carrier differs |
| `GET` | `/messages/{message_id}` | `messages:view_raw` | `require_phi_read` | per-property redaction of the wrapper **and** each nested `OutboxInfo`/`EventInfo` |
| `GET` | `/messages/{message_id}/attachments/{attachment_id}` | `messages:view_raw` | `require_phi_read` | raw attachment bytes |
| `GET` | `/messages/{message_id}/responses` | `messages:read` | `require_phi_read` | the reply **body** additionally needs `messages:view_raw`, enforced inline at the route |
| `GET` | `/messages/{message_id}/outbound` | `messages:view_raw` | `require_phi_read` | the transformed outbound payload |
| `POST` | `/messages/{message_id}/replay` | `messages:replay` | `require_step_up` | per-channel scope |
| `POST` | `/messages/{message_id}/resend` | `messages:resend` | `require_step_up` | per-channel access to **both** the origin's and the alternate outbound's channel |
| `POST` | `/messages/{message_id}/edit-resend` | `messages:edit` | `require_step_up` | implies `messages:view_raw`; the DIRECT `to` power-path additionally requires per-channel access to the alternate outbound's channel |
| `GET` | `/dead-letters` | `messages:read` | `require_phi_read` | per-property redaction; per-channel scope |
| `POST` | `/dead-letters/replay` | `messages:replay` | `require_step_up` | may return **202 + `approval_id`** under dual control |

#### Search presets & layered search (PHI)

| Method | Path | Permission | Gate | Extra constraints |
|---|---|---|---|---|
| `GET` | `/search/presets` | `messages:read` | `require` | **owner-scoped**: a caller sees only their OWN presets. Enforced on the identity's `user_id`, not on any client-supplied field, so the permission grants the FUNCTION and the row's owner grants the DATA (ASVS 8.1.1) |
| `POST` | `/search/presets` | `messages:read` | `require_step_up` | **owner-scoped**: a caller sees only their OWN presets. Enforced on the identity's `user_id`, not on any client-supplied field, so the permission grants the FUNCTION and the row's owner grants the DATA (ASVS 8.1.1) |
| `DELETE` | `/search/presets/{preset_id}` | `messages:read` | `require` | **not** paced; **owner-scoped**: a caller sees only their OWN presets. Enforced on the identity's `user_id`, not on any client-supplied field, so the permission grants the FUNCTION and the row's owner grants the DATA (ASVS 8.1.1). A preset id belonging to another user is a miss, not a 403 -- ownership is part of the lookup |
| `GET` | `/search/layered` | `messages:read` | `require_step_up` | explicit `enforce_phi_read_hop` + `enforce_phi_read_pacing` |

#### Uploaded files (PHI at rest)

| Method | Path | Permission | Gate | Extra constraints |
|---|---|---|---|---|
| `POST` | `/uploads` | `files:upload` | `require_step_up` | stdlib multipart parse (no `python-multipart`) |
| `GET` | `/uploads` | `files:browse` | `require` | metadata only — no body, no summary; **owner-scoped** (ASVS 8.2.2) — the caller sees only the files they uploaded unless they hold `files:access_any`; **paged** `limit`/`offset` (50, 1..500 / 0..), the window applied AFTER the owner filter so a page's length can never encode another operator's file count |
| `GET` | `/uploads/{file_id}/messages` | `files:browse` | `require_step_up` | explicit `enforce_phi_read_hop` + `enforce_phi_read_pacing` (bulk decrypt + split); **owner-only** — another operator's file answers **404**, before the decrypt |
| `POST` | `/uploads/{file_id}/messages/search` | `files:browse` | `require_step_up` | the needle-bearing sibling of the browse GET (BACKLOG #1184); same owner-only 404 before the decrypt, same bulk PHI-read pacing |
| `POST` | `/uploads/{file_id}/resend` | `files:browse` | `require_step_up` | per-channel `can_access_channel` check on the target inbound (403) **and** an owner check on the source file (404) |
| `DELETE` | `/uploads/{file_id}` | `files:delete` | `require_step_up` | destructive, audited; **owner-only** — another operator's file answers **404** and is never unlinked |

> **Object-level authorization for uploaded files (ASVS 8.2.2).** An uploaded file belongs to the
> **account** that uploaded it — `UploadedFileMeta.uploader_id`, which is `Identity.user_id` (an
> immutable `uuid4` hex), and *not* the username. A username is unique among live accounts but it is
> reusable: deleting a user frees the name and recreating it mints a different `user_id`, so a
> name-keyed rule would hand the recycled account the departed operator's files.
> `UploadedFileMeta.uploader` is retained as the **display/audit label** only. The per-uploader quota
> (ASVS 5.2.4) bills the same `uploader_id`, so ownership and the budget can never disagree about who
> a file belongs to.
>
> **Bound, and stated because the bound is the load-bearing part.** This closes local accounts and any
> AD account that goes through a MessageFoundry `delete_user`. It does **not** close a
> `sAMAccountName` recycled in the directory *without* one: `_upsert_ad_user` resolves by username and
> mints a new `user_id` only when no mirror row survives, so on the default AD path the surviving row
> is adopted and **its `user_id` is re-bound to the new principal**. A deploying site on AD would
> therefore still need the directory-immutable binding — AD to `objectGUID`/`objectSid`, the way OIDC
> binds `(issuer, sub)` — tracked as BACKLOG #1143. `AdPrincipal` carries no such identifier today, so
> `user_id` is the strongest key currently available, not a complete one.
>
> **Owner-only** is the whole rule: list, browse, resend and delete reach the caller's own files.
> `files:access_any` is the explicit cross-operator override, granted to **Administrator** only (it is
> the whole catalogue), never to Operator, and never mintable onto a custom role
> (`CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`). The channel axis is deliberately **not** used here, and one
> of the two reasons originally given has since expired. The surviving reason decides it on its own:
> an uploaded file carries no channel, so a channel-scoped rule has nothing to match on and would
> deny every scoped operator their own file. The expired reason was that `Identity.allowed_channels`
> defaulted to `null` (= every channel), so such a rule would have protected nobody on a default
> install — BACKLOG #1152 flipped that default to deny, which changes nothing about the owner-only
> decision but does retire half of its stated justification. A denied by-id request answers **404** with the same body as a
> malformed or absent id; what makes the by-id routes non-enumerable is that a `file_id` is 128 bits
> of `secrets.token_hex(16)` and the listing no longer hands out another operator's — the denial is
> still distinguishable by timing and by its audit row. That denial is audited as `upload.denied` with
> the acting username, the acting `user_id`, the `file_id` and the operation — never the filename, the
> owner or any content. The id is there because the username is the value this rule exists to distrust:
> recycle a name and the actor column can no longer say which principal was refused, but the id can. The
> checks live in the **handler bodies**, not in the route gates, because the console invokes those
> same handlers over the seam and never runs their `Depends`. A sidecar with no `uploader_id` (a
> hand-placed one; `save()` refuses to write one) matches nobody and is reachable **only** by an
> override holder — fail closed. The age-based retention sweep stays owner-blind by design: it
> deletes by age, for every uploader.

#### Logs & AI

| Method | Path | Permission | Gate | Extra constraints |
|---|---|---|---|---|
| `GET` | `/logs/tail` | `logs:view` | `require_phi_read` | best-effort-redacted; writes a `logs_view` audit row |
| `POST` | `/ai/chat` | `ai:assist` | `require` | **not** paced; bounded by the central AI policy |

**PHI-egress route set.** Of the 108 route objects a default `create_app()` serves, **fifteen** can put
PHI on the wire: the twelve message/search rows above marked PHI (`/messages`, `/messages/{id}`,
`/responses`, `/outbound`, `/attachments/{id}`, `/messages/search`, `/messages/export`,
`/search/layered`, the three `/search/presets` rows, `/dead-letters`), plus
`GET /uploads/{file_id}/messages`, `POST /uploads/{file_id}/resend` and `GET /logs/tail`. Eleven of
them carry an explicit PHI-read hop refusal + per-actor budget; the other four (`/search/presets` × 3
and `POST /uploads/{id}/resend`) return no body content of their own.

**With the console served** (`serve_ui=True` — the deployed posture for a console-served instance) **at least ten more** emit PHI. ⚠️ **This is deliberately not a closed enumeration**, per CLAUDE.md §11: a fixed count is a liability that the next PHI-emitting route silently falsifies, and this one already was — it read "nine more" and omitted `POST /ui/messages/{id}/edit-resend`, whose `_reject` arm re-renders both the pristine `core.get_message` detail and the operator's edited `raw_value`. **The authority is the code, not this list:** a `/ui` route emits PHI if it renders a message body, and the ones that charge the per-actor read budget are those passing `phi=True` to `require_ui` / `require_ui_step_up` (`messagefoundry_webconsole/_auth.py`) **or** that reach `enforce_phi_read_pacing` some other way — a reused engine handler that paces in its own body (`search_messages` / `layered_search` / `browse_uploaded_file`), or a console route that charges it inline on a short-circuit render (BACKLOG #1025). Known today:
`GET /ui/messages`, `/ui/messages/{id}`, `/ui/messages/{id}/parse-tree`,
`/ui/messages/{id}/attachments/{id}`, `/ui/messages/{id}/edit`, `POST /ui/messages/{id}/edit-resend`,
`GET /ui/messages/search`, `/ui/messages/search/layered`, `/ui/dead-letters` and
`/ui/uploaded-logs/file/{file_id}` — all four charge the per-actor read budget (BACKLOG #1025): the reused engine handlers behind search, layered and uploaded-browse pace it in their own body, and #1025 additionally charges the two search routes' short-circuit renders (bare-form / no-preset) **inline**, since those return before the handler runs — the uploaded-browse route needs no extra charge (its handler paces every call and it has no short-circuit, so any second charge would double-count). Note
`GET /ui/messages/{message_id}/edit`: it renders the full message detail, so it requires
`messages:view_raw` **as well as** `messages:edit` and fails closed on either (BACKLOG #324). The
catalogue's "implies `messages:view_raw`" for `messages:edit` remains a **built-in-role convention,
not a minting rule** — `messages:edit` is not in `CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`, so a custom role
holding it alone is still mintable; on a deploying instance that role would be refused the editor
rather than shown a body its permission set does not authorize.

#### The `/ui` console plane (`serve_ui=True`)

When the console is served, the `/ui` plane adds **95 routes + one `/ui/static` mount** (federation off,
the default — the two `/ui/oidc/*` routes are registered only when `[auth].oidc_enabled`). They are
functions too, and they gate on the **same 28-permission catalogue** through parallel wrappers —
`require_ui`, `require_ui_step_up`, `require_ui_reauth_only`, `require_ui_step_up_action`,
`require_ui_reauth_only_action` — but authenticate by the `/ui`-confined `SameSite=Strict` **session
cookie** rather than a bearer token, and refuse cross-site state changes on `Sec-Fetch-Site`/`Origin`.
**Route → permission map (`/ui` plane).** 87 of the 95 are gated; the 8 that are not are the
sign-in and re-auth entry points, listed after the table. Where the console is served it is the
*sole* operator UI, so ~20 of these have no JSON counterpart from which their authorization could be
inferred — `POST /ui/connections/bulk-control`, `POST /ui/connections/purge-bulk`, the
`/ui/statistics/reset-*` pair, the three `/ui/dead-letters/*/replay` variants,
`GET /ui/messages/{message_id}/parse-tree`, `GET /ui/messages/{message_id}/edit`,
`GET /ui/uploaded-logs/file/{file_id}` and the three `/ui/account/webauthn/*` routes among them.

| Method | Path | Permission | Gate |
|---|---|---|---|
| `GET` | `/ui` | `monitoring:read` | `require_ui` |
| `GET` | `/ui/account` | *(authenticated session only)* | `require_ui` |
| `GET` | `/ui/account/mfa/confirm` | *(authenticated session only)* | `require_ui_reauth_only` |
| `POST` | `/ui/account/mfa/disable` | *(authenticated session only)* | `require_ui_step_up_action` |
| `POST` | `/ui/account/mfa/enroll` | *(authenticated session only)* | `require_ui_reauth_only_action` |
| `POST` | `/ui/account/mfa/verify` | *(authenticated session only)* | `require_ui_reauth_only_action` |
| `GET` | `/ui/account/password` | *(authenticated session only)* | `require_ui` |
| `POST` | `/ui/account/password` | *(authenticated session only)* | `require_ui` |
| `GET` | `/ui/account/sessions` | *(authenticated session only)* | `require_ui` |
| `POST` | `/ui/account/sessions/revoke-others` | *(authenticated session only)* | `require_ui_reauth_only_action` |
| `POST` | `/ui/account/sessions/{session_id}/revoke` | *(authenticated session only)* | `require_ui_reauth_only_action` |
| `POST` | `/ui/account/webauthn/enroll` | *(authenticated session only)* | `require_ui_reauth_only_action` |
| `POST` | `/ui/account/webauthn/verify` | *(authenticated session only)* | `require_ui_reauth_only` |
| `POST` | `/ui/account/webauthn/{credential_id_hash}/delete` | *(authenticated session only)* | `require_ui_step_up_action` |
| `GET` | `/ui/ad-groups` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/ad-groups/map` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/ad-groups/scope-map` | `users:manage` | `require_ui_step_up` |
| `GET` | `/ui/alerts` | `monitoring:read`**+**`monitoring:diagnose` | `require_ui` |
| `POST` | `/ui/alerts/{alert_id}/ack` | `monitoring:diagnose` | `require_ui` |
| `POST` | `/ui/alerts/{alert_id}/resolve` | `monitoring:diagnose` | `require_ui` |
| `POST` | `/ui/alerts/{alert_id}/resume` | `monitoring:diagnose` | `require_ui` |
| `POST` | `/ui/alerts/{alert_id}/suspend` | `monitoring:diagnose` | `require_ui` |
| `GET` | `/ui/audit` | `audit:read` | `require_ui` |
| `GET` | `/ui/config` | `monitoring:read` | `require_ui` |
| `POST` | `/ui/config/reload` | `config:deploy` | `require_ui_step_up` |
| `GET` | `/ui/connection/{name}` | `monitoring:read` | `require_ui` |
| `GET` | `/ui/connections` | `monitoring:read` | `require_ui` |
| `POST` | `/ui/connections/bulk-control` | `connections:control` | `require_ui` |
| `POST` | `/ui/connections/purge-bulk` | `messages:purge` | `require_ui_step_up` |
| `GET` | `/ui/connections/purge-confirm` | `messages:purge` | `require_ui_step_up` |
| `POST` | `/ui/connections/{name}/flag` | `config:deploy` | `require_ui` |
| `POST` | `/ui/connections/{name}/purge/{scope}` | `messages:purge` | `require_ui_step_up` |
| `POST` | `/ui/connections/{name}/restart` | `connections:control` | `require_ui` |
| `POST` | `/ui/connections/{name}/start` | `connections:control` | `require_ui` |
| `POST` | `/ui/connections/{name}/stop` | `connections:control` | `require_ui` |
| `GET` | `/ui/dead-letters` | `messages:read` | `require_ui` |
| `POST` | `/ui/dead-letters/replay-all` | `messages:replay` | `require_ui_step_up` |
| `POST` | `/ui/dead-letters/{channel_id}/replay` | `messages:replay` | `require_ui_step_up` |
| `POST` | `/ui/dead-letters/{channel_id}/{destination_name}/replay` | `messages:replay` | `require_ui_step_up` |
| `POST` | `/ui/dr/activate` | `dr:operate` | `require_ui` |
| `POST` | `/ui/dr/release` | `dr:operate` | `require_ui` |
| `GET` | `/ui/events` | `monitoring:read` | `require_ui` |
| `GET` | `/ui/messages` | `messages:read` | `require_ui` |
| `GET` | `/ui/messages/search` | `messages:read` | `require_ui_step_up` |
| `GET` | `/ui/messages/search/layered` | `messages:read` | `require_ui_step_up` |
| `POST` | `/ui/messages/search/run` | `messages:read` | `require_ui_step_up` |
| `POST` | `/ui/messages/search/presets` | `messages:read` | `require_ui_step_up` |
| `POST` | `/ui/messages/search/presets/{preset_id}/delete` | `messages:read` | `require_ui` |
| `GET` | `/ui/messages/{message_id}` | `messages:view_raw` | `require_ui` |
| `GET` | `/ui/messages/{message_id}/attachments/{attachment_id}` | `messages:view_raw` | `require_ui` |
| `GET` | `/ui/messages/{message_id}/edit` | `messages:edit`**+**`messages:view_raw` | `require_ui_step_up` |
| `POST` | `/ui/messages/{message_id}/edit-resend` | `messages:edit`**+**`messages:view_raw` | `require_ui_step_up` |
| `GET` | `/ui/messages/{message_id}/parse-tree` | `messages:view_raw` | `require_ui` |
| `POST` | `/ui/messages/{message_id}/replay` | `messages:replay` | `require_ui_step_up` |
| `GET` | `/ui/monitoring` | `monitoring:read` | `require_ui` |
| `GET` | `/ui/monitoring/live` | `monitoring:read` | `require_ui` |
| `GET` | `/ui/nav-status` | `monitoring:read` | `require_ui` |
| `GET` | `/ui/roles` | `users:read` | `require_ui` |
| `GET` | `/ui/session-status` | *(none — authenticated, no permission)* | `require_ui` |
| `POST` | `/ui/roles/custom` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/roles/custom/{role_id}/delete` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/roles/custom/{role_id}/update` | `users:manage` | `require_ui_step_up` |
| `GET` | `/ui/roles/new` | `users:manage` | `require_ui_step_up` |
| `GET` | `/ui/roles/{role_id}/edit` | `users:manage` | `require_ui_step_up` |
| `GET` | `/ui/security-events` | *(authenticated session only)* | `require_ui` |
| `POST` | `/ui/statistics/reset` | `monitoring:diagnose` | `require_ui` |
| `POST` | `/ui/statistics/reset-many` | `monitoring:diagnose` | `require_ui` |
| `POST` | `/ui/statistics/reset-one` | `monitoring:diagnose` | `require_ui` |
| `GET` | `/ui/status` | `monitoring:read` | `require_ui` |
| `POST` | `/ui/status/integrity-check` | `monitoring:diagnose` | `require_ui` |
| `GET` | `/ui/uploaded-logs` | `files:browse` | `require_ui` |
| `GET` | `/ui/uploaded-logs/file/{file_id}` | `files:browse` | `require_ui_step_up` |
| `POST` | `/ui/uploaded-logs/file/{file_id}/filter` | `files:browse` | `require_ui_step_up` |
| `POST` | `/ui/uploaded-logs/file/{file_id}/delete` | `files:delete` | `require_ui_step_up` |
| `GET` | `/ui/uploaded-logs/file/{file_id}/delete-confirm` | `files:delete` | `require_ui` |
| `POST` | `/ui/uploaded-logs/file/{file_id}/resend` | `files:browse` | `require_ui_step_up` |
| `GET` | `/ui/uploaded-logs/file/{file_id}/resend-confirm` | `files:browse` | `require_ui` |
| `GET` | `/ui/uploaded-logs/upload` | `files:upload` | `require_ui` |
| `POST` | `/ui/uploaded-logs/upload` | `files:upload` | `require_ui` |
| `GET` | `/ui/users` | `users:read` | `require_ui` |
| `POST` | `/ui/users` | `users:manage` | `require_ui_step_up` |
| `GET` | `/ui/users/new` | `users:manage` | `require_ui_step_up` |
| `GET` | `/ui/users/{user_id}` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/users/{user_id}/channel-scope` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/users/{user_id}/delete` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/users/{user_id}/reset-mfa` | `users:manage` | `require_ui_step_up_action` (action `admin_reset_mfa`) |
| `POST` | `/ui/users/{user_id}/reset-password` | `users:manage` | `require_ui_step_up_action` (action `admin_reset_password`) |
| `POST` | `/ui/users/{user_id}/revoke-sessions` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/users/{user_id}/roles` | `users:manage` | `require_ui_step_up` |
| `POST` | `/ui/users/{user_id}/update` | `users:manage` | `require_ui_step_up` |

**The two-permission `/ui` routes**, each failing closed on either permission:

- `GET /ui/alerts` requires **both** `monitoring:read` and `monitoring:diagnose` — the page renders
  the active-alert census next to the diagnose-only controls.
- `GET /ui/messages/{message_id}/edit` and `POST /ui/messages/{message_id}/edit-resend` require
  **both** `messages:edit` and `messages:view_raw` (BACKLOG #324) — the editor *displays* the body it
  edits (the textarea, plus the pristine `data-original` copy behind Revert), and the POST's rejection
  arm re-renders that pristine copy. Reading the body is part of what the editor exercises, not an
  adjacent capability, so the read permission is required outright rather than implied.

Rows showing *(authenticated session only)* carry no permission: they are the caller's **own**
account surface (`/ui/account*`, `/ui/security-events`), authorized by session ownership rather than
by an RBAC grant — the same basis as the JSON `/me/*` routes.

**Unauthenticated `/ui` routes (10).** `GET`/`POST /ui/login`, `POST /ui/logout`, `GET /ui/sso`,
`POST /ui/csp-report`, `GET`/`POST /ui/reauth`, `POST /ui/reauth/webauthn` and `GET`/`POST /ui/mfa`
(plus `GET`/`POST /ui/oidc/start` and `GET /ui/oidc/callback` when federation is enabled). The three
`/ui/reauth*` routes authenticate the session cookie **manually** rather than through `require_ui`,
because a gate that demanded a fresh step-up to *perform* a step-up would deadlock. The two
`/ui/mfa` routes (ASVS 6.3.3) are the same shape for the same reason: `require_ui` 303s every
MFA-pending session **to** `/ui/mfa`, so gating that page would redirect it to itself. Both
re-implement the gate's checks by hand, in the gate's order (`must_change` before the second
factor), and neither is reachable without a live session cookie — "unauthenticated" here means
"carries no `Depends` gate", not "open".

The `/ui/static` **mount** is the ninth unauthenticated served path, and it is not a route at all:
`StaticFiles` serves it with **no gate whatsoever** — no session, no permission, not even the 503
fail-closed arm that `GET /ui` returns when no `AuthService` is attached. It carries only the console's
own versioned CSS/JS — no PHI, no account state, no engine data — and it is still subject to the
pre-routing client-network deny. It is the only mount the app registers; a second one carrying anything
else would need its own authorization rule stated here.

**Behavioural differences from the JSON plane**, stated rather than assumed away:

1. `require_ui_step_up` answers a stale session with a **303 to `/ui/reauth`** instead of a 403 the
   browser cannot act on.
2. **No `/ui` route charges the per-actor admin-write pacing floor** (see the interim note under
   [Anti-automation](#admin-password-reset-wp-l3-12-asvs-646)).
3. **One console route loses a step-up its JSON counterpart has**: `POST /ui/uploaded-logs/upload`
   is plain `require_ui`, while `POST /uploads` is `require_step_up` — a multipart body cannot
   survive the re-auth redirect. So a PHI-at-rest write is gated on `files:upload` alone on this
   plane. **The resend half of this divergence is CLOSED (BACKLOG #1227):**
   `POST /ui/uploaded-logs/file/{file_id}/resend` is now `require_ui_step_up`, reached through a
   body-less confirm step that carries its two parameters in the query, so it survives the re-auth
   redirect the way `delete` does. The premise that used to stand in for the gate — that the POST
   arrives from an already-stepped-up browse page — was never enforced by anything.
   That step introduces one *new*, narrower divergence, disclosed here rather than left to be
   discovered: `GET /ui/uploaded-logs/file/{file_id}/resend-confirm` is plain `require_ui` while the
   permission-equivalent JSON browse route carries a step-up. It **cannot** carry one, because it is
   the re-auth continuation itself — gating it would bounce the operator back to `/ui/reauth`
   indefinitely. It is accepted because the page renders **no message body**: a filename, an ordinal
   and a connection name, all three of which the operator supplied on the previous screen.
4. **The ADR 0092 PHI-read hop refusal does not apply on the `/ui` browse routes.**
   `enforce_phi_read_hop` appears nowhere in `messagefoundry_webconsole/`; the console's own gates —
   `require_ui(..., phi=True)` and `require_ui_step_up(..., phi=True)` — apply only the per-actor
   throttle. So `GET /ui/messages`, `/ui/messages/{message_id}`,
   `/ui/messages/{message_id}/parse-tree`,
   `/ui/messages/{message_id}/attachments/{attachment_id}`, `/ui/dead-letters` and the edit pair
   (`GET /ui/messages/{message_id}/edit`, `POST /ui/messages/{message_id}/edit-resend`) charge
   the PHI-read budget but not the posture-keyed refusal that the JSON `require_phi_read` adds — at
   least those; the set is whichever console gates pass `phi=True`, not a fixed list. Where a console
   route reaches a JSON handler that calls `enforce_phi_read_hop(request)` inline (search, export,
   uploads-browse, layered), that refusal DOES carry over.
5. **Three further console routes are weaker than a permission-equivalent JSON route**, each for a
   stated reason: `GET /ui/uploaded-logs` is plain `require_ui` — it mirrors `GET /uploads` (also
   plain `require`), a metadata-only listing, not the step-up'd `GET /uploads/{file_id}/messages`;
   `POST /ui/connections/{name}/flag` mirrors `POST /connections/{name}/flag` (`require_paced` — a
   deploy-flag toggle, not `POST /config/reload`'s step-up'd deploy); and
   `POST /ui/messages/search/presets/{preset_id}/delete` mirrors
   `DELETE /search/presets/{preset_id}` (also plain `require`), deleting a saved query, not PHI.

Differences 3–5 are derived and pinned: a `/ui` route that is weaker than **any** JSON route holding
the same permission set on the same method reds CI until it is listed here.

> **Per-channel scoping (DLQ-SCOPE), and it DENIES BY DEFAULT (BACKLOG #1152, ASVS 8.2.2).**
> Operational permissions are confined to a set of connections per user via `users.channel_scope`
> (`PUT /users/{id}/channel-scope`). A new non-administrator is granted **no channel** — `create_user`
> writes no scope, and an absent scope denies — so `messages:read/view_raw/replay`, dead-letter
> list/replay and `connections:control` reach nothing until somebody grants a channel. Out-of-scope
> message access returns 404 to avoid leaking existence; connection control returns 403; denials are
> audited `auth.channel_denied`. All-channels survives as a grant somebody typed: the `*` token in the
> scope list (`{"channels": ["*"]}`). Sending `{"channels": null}` **clears** the scope and therefore
> denies — it is not the wide value it was before #1152.
>
> **Administrators are always all-channels**, by role, which is what keeps the first operator of a
> fresh install from locking themselves out of their own console. A non-administrator with an empty
> scope sees an empty console, and the landing page says so in a sentence rather than leaving it to
> read as broken RBAC; that is deliberately a page banner and not a start-time refusal, which would
> make a fresh single-operator install unbootable for the same condition. Monitoring dashboards stay
> global. A channel-scoped user **cannot purge** a shared outbound (purge spans every inbound feeding
> it). **AD users** inherit their scope from the `ad_group_scope_map` (`GET/PUT /ad-group-scope-map`;
> channel `*` = all): on login the group-derived scope is persisted — a wildcard row persists the
> explicit `["*"]` grant — and stale sessions revoked. It's opt-in: with no matching mapped group the
> user's existing scope is left untouched, which for a never-granted account means it stays denied.

> **`/config/reload` executes Python** from the target directory in-process, so it is constrained
> beyond the `config:deploy` permission: the directory must resolve **within** an allowed root —
> the server's startup `--config` dir or an entry in `[api].config_reload_roots` — otherwise it is
> rejected (403). An omitted `config_dir` reloads the startup dir. Every reload (and every denial)
> is audited with the acting user; error responses are generic so a holder can't probe the
> filesystem via reload errors. Lock down the config/staging directories' ACLs accordingly
> (see [SERVICE.md](SERVICE.md#security-hardening-recommended)).

### Dual-control approval for high-value actions (WP-L3-04, ASVS 2.3.5)

High-value operations can require a **second approver** before they execute — a maker-checker control.
It is **opt-in and deny-by-default** (`[approvals]`, off unless `enabled`): a single-operator
deployment is never blocked, and existing behavior is unchanged until you turn it on.

When enabled for an operation, invoking it does **not** execute inline. The request (operation + its
parameters + the requester) is **persisted** and the endpoint returns **202** with an `approval_id`; the
action is held until a **distinct** user holding `approvals:approve` releases it via
`POST /approvals/{id}/approve`. The requester can **never approve their own request** (enforced
server-side, not a client confirmation). On release the captured operation is **re-executed** and
**both identities** are written to the hash-chained audit log (`approval.requested` by the maker,
`approval.approved` by the checker); `POST /approvals/{id}/reject` declines it (`approval.rejected`), and
a request older than `[approvals].expiry_hours` can no longer be approved. Approvers see the open queue
at `GET /approvals`.

The gated set is configurable (`[approvals].operations`); the first cut covers the two highest-PHI-impact
flows — **bulk dead-letter replay** and **connection purge**. (The web console's "are you
sure?" confirm prompts are **client-side only** and bypassable via the raw API — they are *not* a second approver
and do not satisfy this control.)

### Step-up re-verification on sensitive operations (WP-L3-16, ASVS 7.5.3)

A highly sensitive operation requires the caller's session to have **re-proved its credential recently** —
not merely to hold a valid token. The `require_step_up` dependency refuses with **403** (header
`X-Step-Up-Required: 1`) unless the session re-verified within `[auth].step_up_max_age_seconds` (default
**300s**). The **initial login counts as the first verification** (the sudo-timestamp model): the session's
`reauth_at` is stamped at login and refreshed by **`POST /me/reauth`**, so a session only needs to re-verify
once its window lapses. `POST /me/reauth` re-checks the **local** password (argon2) or performs a **live
Active Directory re-bind** for AD accounts, so AD operators are never locked out. It is rate-limited like the
password change and audited (`auth.reauth`).

**Gated operations — 28 route objects** (26 `require_step_up` + 2 action-bound `require_step_up_action`).
The complete set, as enumerated in the [route map](#route--permission-map-engine-api) above:

- **User / role administration** — `POST /users`, `DELETE /users/{id}`, `DELETE /users/{id}/sessions`,
  `PUT /users/{id}/roles`, `POST /users/{id}/reset-password`, `POST /users/{id}/reset-mfa`,
  `PUT /users/{id}/channel-scope`, `PUT /ad-group-map`, `PUT /ad-group-scope-map`, the three
  `/roles/custom` writes, and `PATCH /users/{id}` (action-bound `admin_user_update`).
- **Self-service** — `DELETE /me/mfa` (action-bound `mfa_disable`).
- **Message / config operations** — `POST /dead-letters/replay`, `POST /messages/{id}/replay`,
  `POST /messages/{id}/resend`, `POST /messages/{id}/edit-resend`, `POST /connections/{name}/purge`,
  `POST /config/reload`, `POST /search/presets`.
- **Uploaded files** — `POST /uploads`, `POST /uploads/{id}/resend`, `DELETE /uploads/{id}`.
- **Bulk-PHI reads** — `GET /messages/search`, `GET /messages/export`, `GET /search/layered`,
  `GET /uploads/{file_id}/messages`. These are **reads** and are step-up-gated deliberately, because
  they select PHI in bulk; the per-actor write pacing does not apply to them (it is non-GET only), so
  each charges the per-actor **PHI-read** budget explicitly instead.

Ordinary reads — listing users, the AD maps, the audit log, a single message — are **not** step-up
gated. Four routes take the *password-only* variant (`require_reauth_only[_action]`), deliberately
**without** the MFA gate so a required-but-unenrolled user cannot deadlock: `POST /me/mfa/enroll`,
`POST /me/mfa/confirm`, `DELETE /me/sessions/{session_id}`, `DELETE /me/sessions`.

This re-proves the password (secondary verification). With **WP-14 native TOTP MFA** built, the step-up
gate **also** requires the session's second factor: an MFA-required caller is refused with `403` +
`X-MFA-Required` until `POST /auth/mfa-verify` succeeds (TOTP or a single-use recovery code), so these
routes carry both a recent password re-verify **and** the MFA factor. The step-up window composes with the
dual-control approval above (the requester re-verifies; an independent approver still releases the action).

### Multi-factor authentication (TOTP, WP-14)

Local accounts can enroll a native **RFC 6238 TOTP** second factor (ASVS 6.3.3): `POST /me/mfa/enroll`
returns a setup key + `otpauth://` URI for an authenticator app, `POST /me/mfa/confirm` activates it and
returns the **single-use recovery codes** (shown once), and `POST /auth/mfa-verify` satisfies a session's
second factor with a TOTP code or a recovery code. `DELETE /me/mfa` disables it; an administrator clears a
lost authenticator via `POST /users/{id}/reset-mfa` (which also revokes the user's sessions). With
`[security].require_mfa` on — **the default since BACKLOG #187 (secure-by-default, including the
loopback bind)** — **every local account** must satisfy MFA: the scope is `every_local_account` by
default, and `administrators` narrows it to the **Administrator** role. It is an **access gate, not
only a step-up gate** — the gate returns `403` + `X-MFA-Required: 1` on **every** authorized route
until verified (console twin: a 303 to `/ui/mfa`), with the account and factor-enrolment routes
exempt so an un-enrolled user is not stranded. A required-but-unenrolled
admin is never locked out — the enroll/confirm routes sit behind an action-bound **password** step-up,
not the MFA gate, so the bootstrap admin enrolls then satisfies it. The documented org opt-out is
`[security].require_mfa = false` (the retired `[auth].require_mfa` spelling is refused at load). **AD/Kerberos MFA is delegated to the directory** (Entra Conditional Access
/ an MFA proxy) — a directory login is never prompted for an engine TOTP and is MFA-satisfied at issuance.
The TOTP secret is stored **encrypted at rest** (the store cipher) and recovery codes are
**argon2id-hashed**; verification uses the server clock and a constant-time compare over a **configurable
clock-skew window** (`[auth].totp_skew_steps`, **default `0` = the current 30 s step only** — strictest
replay window, ASVS 6.5.5; set `1`/`2` to restore RFC-6238 ±1 network-delay tolerance, the forward step
clamped to the current step to avoid a self-inflicted lockout). ⚠️ **Single-use (ASVS 6.5.1) holds only at
the default `0`.** At `totp_skew_steps >= 1` the clamp records a tolerated *future* code against the
current step, leaving that code's own step unspent — so the **same code verifies a second time** once the
clock reaches it. That is the cost of the opt-out, and it is why the default is `0`. TOTP is a
shared-secret factor — L3 *prefers*
phishing-resistant factors: **WebAuthn passkeys are the built WP-14b sibling** (next section), and TOTP
stays fully supported alongside them (a non-browser client — e.g. the test harness, or CLI/API
automation — has no `navigator.credentials`, so TOTP remains its usable second factor).

### WebAuthn passkeys (WP-14b, ADR 0068)

Local accounts can also enroll **WebAuthn/FIDO2 passkeys** as a phishing-resistant second factor at the
**same step-up boundary** — browser ceremonies on the `/ui` web console (requires the optional
**`[webauthn]` extra**; a non-browser client has no `navigator.credentials`, so keep TOTP enrolled for
step-up outside the browser). The browser step-up stays **two-credential**: the passkey assertion satisfies the
session's **MFA leg only**, and the mandatory password leg of `POST /ui/reauth` still stamps step-up
freshness and re-anchors the session's client IP (WP-L3-13) — so a passkey never silently relaxes the
password re-proof. Enrollment (`POST /ui/account/webauthn/enroll`) sits behind the **password-only
re-proof** (WP-14: a stolen pre-MFA cookie can never bind an attacker's passkey); removal sits behind the
full step-up, and removing the **last remaining second factor while MFA is required is refused**
("enroll another factor first"). `POST /users/{id}/reset-mfa` clears passkeys alongside TOTP — the
always-available recovery, because passkeys mint **no recovery codes by design** (codes are phishable
knowledge secrets that would undercut the phishing-resistant tier; enroll a second passkey or keep TOTP).

Mechanics: ceremony challenges are **first-party 64-byte CSPRNG values**, single-use, 120 s TTL, staged
in a bounded process-local cache (multi-node LBs need session affinity — the failure message says so).
That cache is bounded on **two** dimensions, asymmetrically and deliberately: **16 pending ceremonies
per user**, which evicts that *same* principal's oldest so one user can never deny another's ceremonies,
and a **4096 engine-wide** safety bound that *refuses* with a cause-naming `ChallengeCacheFullError`
(the message points at `admin_reset_mfa` as the recovery path). Both are counted as control 8 of the
[6.1.1 protection set](#the-documented-protection-set-asvs-611). Continuing the mechanics:
COSE **public keys are stored plaintext by design** (verification material, not secrets — deliberately
outside the store cipher, documented in the crypto inventory); the authenticator **sign counter is
updated via a strict compare-and-set** — a regression or a concurrent same-counter assertion is treated
as a **clone signal** (rejected + audited `auth.webauthn_clone_suspected`; a permanent counter of 0 is
normal for synced passkeys). Assertion failures are audited but deliberately do **not** feed the
account lockout (signatures aren't guessable secrets). Abuse is bounded instead by the **per-actor
credential-ceremony limiter** — the sole route that finishes an assertion, `POST /ui/reauth/webauthn`,
charges `allow_reauth_attempt`, not the sign-in window — plus cookie-holder-only reachability. The RP
identity (`rp_id`/origin) rides **`[api].public_origin`** when
set; on a plain loopback deployment it derives from the request URL, and behind a **declared reverse
proxy it fails closed** until `public_origin` is configured (anchoring the RP to a proxy-forwardable
Host header would defeat the origin binding that makes WebAuthn phishing-resistant). Credentials are
pinned to their mint-time `rp_id` — **changing `public_origin`'s host renders enrolled passkeys visibly
"unusable (origin changed)"** (re-enroll after an origin migration). AD/Kerberos users are excluded
exactly as with TOTP (directory-delegated MFA).

### Off-loopback browser console (L5b, ADR 0068 §8)

> The `/ui` browser console is now served by the separately-versioned **`messagefoundry-webconsole`**
> package (Option B, [ADR 0065](adr/0065-web-ops-dashboard.md)), which the engine **mounts same-origin,
> in-process** — it was previously the in-engine `messagefoundry/api/webui/` tree. The **same-origin
> security model is unchanged by that move**: the whole security core (the `/ui`-confined
> `SameSite=Strict` session cookie, the `Origin`/`Sec-Fetch-Site` CSRF check on every `/ui` POST, the
> step-up + `reauth_next` unlock flow, the CSWSH `Origin == Host` WebSocket check, and the WebAuthn
> ceremonies below) moved **verbatim** and reads `request(.websocket).app.state`, registering onto the
> same app object. See [WEBCONSOLE-PACKAGE.md](WEBCONSOLE-PACKAGE.md).

The console is **on by default** (`[security].serve_web_console`, [ADR 0143](adr/0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md))
for **local loopback** binds — the local-operator convenience. Off-box it stays **opt-in**: a *default-on*
(not explicitly requested) console on an **exposed** instance (a non-loopback host, a declared
TLS-terminating proxy, or a set `web_console_public_address`) **auto-degrades to JSON-only** with a
warning rather than tripping the exposure ladder, so a previously-working exposed JSON serve is never
turned into a start failure. An **explicit** `serve_web_console = true` off-box is left on and still runs
the full ladder (unchanged).

Exposing `/ui` off-box is a supported, **gated** posture. Beyond the existing TLS-or-refuse exposure
gate (refused even under `--allow-insecure-bind`), `serve` runs the **L5b exposure ladder** for an
explicitly-enabled console: with a **declared reverse proxy** (`tls_terminated_upstream`), `serve_ui`
**refuses to start without `[api].public_origin`** (behind a proxy the Host header is client-forwardable — the exact origin
anchors the same-origin CSRF check and the WebAuthn rp_id); an `http://` `public_origin` is refused
under any declared TLS posture; a set `public_origin` on an *undeclared* posture warns loudly (the
cookie would ship without `Secure`); and an exposed console emits the ASVS 8.4.2 pointer to
`OFF-LOOPBACK-DEPLOYMENT.md` (managed-admin-host runbook +
reverse-proxy-mTLS reference configs) plus an advisory when `[auth].admin_new_ip_step_up` is off on
a PHI instance (the default deliberately stays off — it remains advisory + step-up-forcing only,
never an authorization input). At runtime, **`exposure_protected` forces the session cookie's
`Secure` flag and HSTS regardless of the per-request scheme** — the scheme is computed once at
login, and a proxy that omits `X-Forwarded-Proto` would otherwise poison the whole session — and a
one-shot tripwire warns if a `/ui` request ever arrives `scheme=http` while a terminator is
declared (proxy not sending `X-Forwarded-Proto`, or its peer IP not matched by `trusted_proxies`).

**Browser AD login (L5b).** When AD is enabled, `/ui/login` offers a provider selector; an AD
password verifies through the **same** `auth.login` directory-bind seam as the JSON surface —
allow-listed provider values only, one session per form POST (the AD role-resync/revocation side
effect fires once at login, never per navigation), MFA stays delegated to the directory.

`require_mfa` defaults **on** (BACKLOG #187 — secure-by-default, including the loopback bind; the
documented org opt-out is `[security].require_mfa = false` — the `[auth]` spelling of this key is
**rejected at load** and `serve` exits 2 naming the replacement). The exposure gate now guards the **explicit
opt-out**: when the API is bound **off-loopback** with `require_mfa` *turned off*, `serve` makes the
posture explicit at startup — it **refuses to start** on a **production PHI** instance and **warns** on a
non-production PHI instance (a synthetic instance stays quiet), mirroring the keyless-store and
open-egress startup gates. So an exposed PHI deployment can't silently run the Administrator interface
single-factor. `require_mfa` is safe to keep on for an **AD-only** deployment's *directory* users:
AD/Kerberos identities are exempt under either `require_mfa_scope` value, their factor delegated to the
directory. An earlier revision of this sentence said it "gates only **local** Administrator accounts";
that was wrong. Under the shipped `[security] require_mfa_scope = "every_local_account"` it covers **every** local
account, which on an AD-only deployment still means the local bootstrap admin and any local service
accounts — a non-interactive local bearer-token account becomes MFA-pending and cannot enrol
unattended. **That is a decision a deploying site must make before first start:** either such an
account becomes an AD principal, or the scope is set to `administrators`. An operator who opts out at
exposure re-enables `[security].require_mfa = true` (or keeps the bind on loopback).
[CONFIGURATION.md](CONFIGURATION.md) `[security].require_mfa_scope` is the authority on the two
remedies and on why mTLS is not a third.

### Administrative-interface defense-in-depth (WP-L3-13, ASVS 8.4.2)

The administrative interface is defended by **multiple independent layers**, not network-location trust
alone:

1. **Source-network allow-list** — `[security].allowed_client_networks` (default `[]` = no
   restriction). When set, a request whose client address falls outside every listed CIDR/host is
   refused **403** (`X-MessageFoundry-Denied: client-network`) — or WebSocket close `1008` — in the
   **outermost** ASGI middleware, before routing, dependencies, the body cap and every auth check, and
   covering `/ui`, the `/ui/static` mount and `/ws/stats`. **Loopback is always allowed**,
   unconditionally, so restricting the console can never lock the box out of its own console.
   `GET /health` is the sole exempt path, and it echoes `observed_client` when the allow-list is in use
   — the one self-service diagnostic a locked-out operator has. Once this list is in use, every
   `[api].trusted_proxies` entry must be a **single host** (bare address, `/32` or `/128`) or the
   config is **refused at load**: any host inside a trusted range could forge its own
   `X-Forwarded-For` and reduce the allow-list to decoration. **Honest limit:** behind an
   **undeclared** proxy or NAT every request in the world resolves to the intermediary and this
   control is **inert**. It does not close that case and must never be documented as if it does — a
   one-shot monoculture tripwire (≥50 observations, all the same loopback address, no proxy declared)
   only *detects* it, surfacing as `client_address_monoculture` on `GET /security/posture`.
2. **Network-location / exposed-gate** — the API binds `127.0.0.1` by default, and a non-loopback
   *plaintext* bind is refused at startup unless `serve --allow-insecure-bind` (ADR 0002 §0). One layer,
   not the sole factor.
3. **Deny-by-default per-route RBAC** — every admin route asserts an explicit permission over an opaque
   Bearer token; a denial is audited (`require()`, ASVS 8.2.x).
4. **Step-up re-verification** within a short window on every sensitive admin route (`require_step_up`,
   above; ASVS 7.5.3).
5. **A genuine second authentication factor** at that step-up boundary — native TOTP MFA (WP-14), so an
   MFA-enrolled/required admin presents a TOTP/recovery code, not a re-prompt of the same password.
6. **A contextual-risk signal** — when `[auth].admin_new_ip_step_up` is on, a sensitive admin action
   arriving from a **client IP the session has not verified from** emits an `auth.admin_action_new_ip`
   audit event + an out-of-band notice and **forces a fresh step-up**; a successful `POST /me/reauth`
   (or `POST /auth/mfa-verify`) from that address re-anchors the session and clears the signal. The
   audit event + notice fire **once per (session, new address)** — a replayed token retrying from one
   address is force-stepped-up each time but cannot inflate the audit log / notifications. It is
   **advisory + step-up-forcing only** — it never changes an RBAC allow/deny and never blocks the
   non-admin request path. Default off and byte-identical on a single-host loopback bind (loopback
   addresses `127.0.0.1` and `::1` are treated as the same host, so a dual-stack box never spuriously
   fires); recommended on for an off-loopback admin deployment.

**Continuous identity verification** underpins all of the above: every request re-resolves the user and
roles from server-side state and re-checks idle/absolute timeout + live disabled/role status, so a
revoked privilege or disabled account takes effect immediately (ASVS 8.3.2).

**Device security-posture assessment is deployment-delegated**, not built in-process: an attested/managed
admin host and an **mTLS client certificate terminated at the reverse proxy** (WP-15) are the posture
control, consistent with the on-prem, loopback-first deployment model — Python's stdlib `ssl` performs no in-process
device attestation. This is the documented residual for 8.4.2's device-posture clause.

### Field-level (property) authorization (WP-9)

Beyond gating whole *endpoints*, the API gates individual **PHI-bearing properties** within a response,
so a caller can see an object without seeing its patient-identifying fields. The policy is declared in
one place — [`api/field_authz.py`](../messagefoundry/api/field_authz.py) — and enforced by a single
`redact_unauthorized()` helper applied to every returned row, rather than re-implemented inline per
endpoint (where a new endpoint or field could silently leak PHI — the BOPLA risk, ASVS 8.1.2 / 8.2.3).

**The default for a mapped model denies.** Each of the six response models below is a `PhiGatedModel`
([`api/phi_gate.py`](../messagefoundry/api/phi_gate.py)) that withholds every gated property from JSON
until an authorization decision is recorded on the instance; `redact_unauthorized()` is what records
one, releasing exactly the properties the caller's permissions unlock. A route that never calls it
therefore returns `null` — a functional defect its author sees — rather than the whole model in the
clear. The gate is on JSON serialization, which is every path by which one of these models reaches a
client; a python-mode `model_dump()` stays ungated by design, because the engine composes
`MessageDetail` from a `MessageSummary` dump before any authorization decision exists.

**Read rules — one row per (response object, property).** This table is 1:1 with `PHI_FIELDS`: eleven
entries over six response models. Keying on the *object* (not just the property name) is what makes it
mechanically comparable to the map — a CI guard asserts set equality in **both** directions, so the
table can neither omit a row nor invent one.

| Response object | Property | Carries | Unlocked by |
|---|---|---|---|
| `MessageSummary` | `summary` | patient identifiers (MRN / name; order / accession for ORM/ORU) | `messages:view_summary` |
| `MessageSummary` | `error` | handler exception text that can quote field values | `messages:view_summary` |
| `MessageSummary` | `metadata` | the operator/handler-attached user bag (ADR 0081), an EF-3 cipher-encrypted PHI-classified column | `messages:view_summary` |
| `MessageDetail` | `summary` | as above | `messages:view_summary` |
| `MessageDetail` | `error` | as above | `messages:view_summary` |
| `MessageDetail` | `metadata` | as above | `messages:view_summary` |
| `DeadLetterRow` | `summary` | as above | `messages:view_summary` |
| `DeadLetterRow` | `last_error` | disposition/exception text | `messages:view_summary` |
| `OutboxInfo` | `last_error` | disposition/exception text | `messages:view_summary` |
| `EventInfo` | `detail` | per-event disposition text | `messages:view_summary` |
| `CapturedResponseInfo` | `detail` | captured-reply disposition text | `messages:view_summary` |

`DeadLetterRow` has no `metadata` field, so its absence from the map is correct, not an omission.

**Default and resource attributes.** These are the rules ASVS 8.1.2 asks to be stated outright:

- **An object with no row is returned in full.** `gated_properties()` returns `{}` for an unmapped
  model, `redact_unauthorized()` then returns the object un-copied, and `count_exposed()` contributes
  0 — so an unmapped model is both un-redacted **and invisible to the exposure census**. This
  fail-open default is the single most load-bearing rule in the model, which is why the CI guard below
  detects a new response model rather than only re-checking mapped ones.
- **Matching is on the exact runtime type** (`type(model)`), with **no MRO walk**. That is why
  `MessageDetail` is listed separately even though it subclasses `MessageSummary`: without its own
  rows, its inherited PHI would be returned un-gated.
- **Withholding is whole-value nulling** (`model_copy(update={prop: None})`) — never partial or
  character-level masking.
- `count_exposed()` must be called **after** redaction, so the census reflects what was actually
  returned.

**Whole-body / route-level gates (deliberately not per-property).** These five surfaces are governed by
a coarse route gate instead, and their permission requirements differ:

| Surface | What it returns | Required | Enforced by |
|---|---|---|---|
| `GET /messages/{id}` → `MessageDetail.raw` | the full stored body | `messages:view_raw` | the route's `require_phi_read` gate |
| `GET /messages/{id}/attachments/{id}` | raw attachment bytes | `messages:view_raw` | the route's `require_phi_read` gate |
| `GET /messages/{id}/outbound` → payload | the transformed outbound payload | `messages:view_raw` | the route's `require_phi_read` gate |
| `CapturedResponseInfo.body` | the captured reply body | `messages:view_raw` | an **inline** per-property check at `GET /messages/{id}/responses`, *not* via `PHI_FIELDS` |
| `GET /messages/export` | bulk NDJSON bodies | `messages:export` **+** `messages:view_raw` | `require_step_up` — a second, dedicated bulk capability |

`GET /messages/export` bypasses the response models entirely (a hand-built NDJSON stream), so it never
calls `redact_unauthorized`. It is safe because its line emits only
`id`/`channel_id`/`received_at`/`message_type`/`control_id`/`status`/`raw` — **no map-gated property may
ever be added to that line** without a `PHI_FIELDS`-equivalent gate.

**Where redaction actually runs.** Six surfaces construct a mapped model, and all six redact:
`GET /dead-letters`, `GET /messages`, `GET /messages/search`, `GET /messages/{id}` (the wrapper **and**
each nested `OutboxInfo` / `EventInfo` individually, because the redactor keys on the exact type),
`GET /messages/{id}/responses` (#120), and `GET /search/layered`.

**Audit.** Four of those six additionally feed the **coalesced per-actor/hour PHI-summary exposure
census** (`/dead-letters`, `/messages`, `/messages/search`, `/messages/{id}`), so a scripted bulk read
cannot harvest the patient census unaudited. The other two do **not** call the coalescer — they write
their own dedicated audit rows instead (`response.read` for `GET /messages/{id}/responses`,
`preset.layered_search` for `GET /search/layered`). The four census surfaces are audited **only when a
gated property is actually returned** — `count_exposed()` is computed *post*-redaction and the
coalescer is called under `if exposed:` — so a fully-redacted list read by a caller without
`messages:view_summary` (a Viewer paging `GET /messages` or `GET /dead-letters`) writes **no audit row
at all**. That is accepted: those reads carry no PHI, and auditing them would let an unprivileged
caller amplify into unbounded `audit_log` growth. `GET /messages/{id}` and `GET /messages/search` write
unconditional dedicated rows (`message_view`, `message_search`) regardless, as do the other two
(`response.read`, `preset.layered_search`).

**Roles and visibility.** `messages:view_raw` is **not** a superset of `messages:view_summary` —
`Identity.has()` is a flat membership check. The built-in roles happen to grant them nested
(Administrator and Operator hold both; Viewer holds neither, so a Viewer sees the **six** rows it can
reach — `MessageSummary` × 3, `DeadLetterRow` × 2, `CapturedResponseInfo.detail` — as `null`, and is
refused `GET /messages/{id}` outright, since that route gates on `messages:view_raw`, which a Viewer
does not hold. The other five rows (`MessageDetail` × 3, `OutboxInfo.last_error`, `EventInfo.detail`)
are reached only by a role holding `view_raw` — including a custom role granted `view_raw` **without**
`view_summary`, which is precisely why those rows sit on the `view_summary` tier. Deployment, Coding
and Auditor hold neither either) — but that is a
**role-policy** convention, not a permission-model guarantee, and the split is **reachable**: a custom
role may be granted `view_raw` without `view_summary` (only `users:manage`, `approvals:approve` and
`dr:operate` are non-assignable). The disposition fields therefore sit on the `view_summary` tier
deliberately, so such a role still cannot reach exception text.

**Not part of this control.** Connection-credential scrubbing (`redacted_settings()` on
`GET /connections/{name}/metadata`) is applied **unconditionally, identically for every role including
Administrator** — a universal secret-scrub, not an authorization tier. `GET /uploads/{file_id}/messages`
returns `index`/`message_type`/`control_id`/`size` only, never a body or a summary, so it is correctly
outside the map.

`ConnectionEventInfo.reason` (`GET /events`, `GET /connections/{name}/events`) and
`AlertInstanceInfo.reason` (`GET /alerts/active`) are free text that [PHI.md](PHI.md) §2 classifies as
***possibly*** PHI-bearing. They are deliberately outside the per-property map: they are gated at
**route** level on `monitoring:read` / `monitoring:diagnose` — not a PHI permission — and defended by
`safe_exc()` at the emit site plus `safe_text(reason)[:200]` at the store, then cipher-encrypted
(PHI.md §2/§7). **Any new free-text field on those two models must be scrubbed the same way or moved
into `PHI_FIELDS`**; CI asserts each of their current fields is on a reviewed list.

**Caveat.** With `[security].require_sign_in = false` every route resolves to the built-in system
identity, which holds every role and therefore every permission, so the per-property gate withholds
nothing. The gate survives as code only; that posture is out of scope for a PHI deployment.

**Assurance — what CI actually asserts.** Three guards, deliberately covering the three distinct ways
this gate can be forgotten (the previous claim here was overstated: the old pinning tests iterate the
*map*, so a new model and a new field on a mapped model both passed them silently):

- **The policy is documented** — `tests/test_security_doc_drift.py` asserts the eleven-row table above
  equals `PHI_FIELDS` exactly, in **both** directions, permission literal included, plus a
  planted-omission self-test so a reformatted table cannot make the parser silently no-op.
- **The policy is complete** — the same module asserts every response model reachable on a
  message-family route is either mapped or on an explicit, reviewed no-PHI allow-list, and that every
  field of a mapped model is either gated or on a reviewed non-PHI list. So a **new PHI-bearing model**
  *and* a **new PHI field on an already-mapped model** both red CI.
- **The policy is applied** — `tests/test_field_authz_enforcement_sites.py` hits all six redaction
  surfaces over HTTP as a caller lacking `messages:view_summary` (a Viewer, plus a `custom:` role
  holding `view_raw` **without** `view_summary` for the detail route) and asserts every gated property
  comes back `null`, with a companion assertion that an administrator sees all eleven — matched **per
  model, not per property name** — so the negative cannot pass vacuously. That distinction is
  load-bearing: keyed on names, `last_error` looked covered by `DeadLetterRow.last_error` on
  `/dead-letters` while `OutboxInfo.last_error` had **zero** coverage, because the only message whose
  outbox row carries a non-null `last_error` is the dead-lettered one and its detail route was not in
  the surface list. It is now, and the coverage assertion is keyed on `(model, property)` pairs.
- **The default is fail-closed** — `tests/test_field_authz_fail_closed.py` mounts a PHI-returning
  route that *omits* the `redact_unauthorized` call and asserts the response carries `null` for every
  gated property, each assertion paired with a released positive control. It also pins `PHI_FIELDS`
  against each model's own `phi_gated_properties` in both directions, and proves class creation
  refuses a gated name the serializer does not cover. The enumeration of call sites above keeps the
  *shipped* surfaces honest; this is what makes the route nobody has written yet safe.

**Write side (engine → store).** Exception/disposition text is also scrubbed *before* it is stored: a
Router/Handler is user code that can `raise ValueError(f"...{raw}")`, so every value written to
`messages.error` / `queue.last_error` / `message_events.detail` (and a connector's captured-reply
`detail`) goes through the `safe_exc` / `safe_text` chokepoint
([`redaction.py`](../messagefoundry/redaction.py)) at the wiring runner, the connectors, **and** the store
write methods — so an HL7-shaped fragment can't land in those columns. HL7-shaped content (segment dumps,
≥2-delimiter field runs) is cut while the exception **type** / field **name** is kept; the residual control
for free-text PHI a script invents (e.g. a bare `"DOE^JANE"`) remains the read-side gate above + the "never
put PHI in an exception" convention. These columns are also **encrypted at rest on every backend** —
SQLite, Postgres, **and SQL Server** (H4 brought SQL Server to parity; `docs/PHI.md` §3) — as
defense-in-depth around the scrub.

**Write side — N/A by design.** The API exposes **no client-writable PHI properties**: every mutation is
a coarse, separately permission-gated action (`messages:replay` / `messages:resend` / `messages:edit` /
`messages:purge` / `config:deploy` / `connections:control`), not a per-field write. `messages:edit`
(`POST /messages/{id}/edit-resend`) **does** accept a client-supplied body — but it is submitted
**whole** and re-ingressed as a new correlated message, the original staying byte-identical, so it is a
coarse, step-up-gated action *on a message*, not a per-property write *on a stored object*. So there is
no per-property *write* authorization surface today. **Trigger to revisit:** the first endpoint that lets a client write a PHI property (e.g. an
edit/annotation API) — at which point add a writable-property→permission whitelist to `field_authz`
alongside the read map.

### Contextual and environmental security inputs (ASVS 8.1.3 / 8.1.4)

The two sections above define *what* a caller may reach (route → permission) and *which properties*
they see. This one defines the **environmental and contextual attributes** that additionally shape an
access decision — every one consumed at this release, on the control plane **and** the data plane.

**Scope frame.** There are **two independent source-address allow-lists** with the same syntax and the
same matcher, but deliberately different carve-outs. `[security].allowed_client_networks` restricts the
**operator surface** (JSON API + `/ui` + `/ws/stats`) and **never** restricts an ingest listener;
loopback is always allowed there. The per-connection `source_ip_allowlist` restricts **one ingest
listener** and deliberately does **not** inherit the loopback carve-out — an allow-list naming a partner
must not also admit anything running on the local box. ⚠️ That one is an **`inbound(...)` keyword** (or
the top-level key in a `connections.toml` `[[inbound]]` table); there is **no**
`[inbound].source_ip_allowlist` service setting. `[inbound]` carries only `bind_host`, `ack_after` and
`stream_inflight_budget_bytes`, and an unrecognized key in a known section is **refused at load** — so
that spelling in `messagefoundry.toml` **fails the start** (`serve` exit 2), naming the section and the
key. It used to be accepted and silently discarded, which left the listener ungated with nothing
reporting a problem; that is the failure mode the refusal exists to remove.

**Action vocabulary (closed set).** Every row below **opens its Action cell** with exactly one of:
**ALLOW** (pass through), **DENY** (403 / 401 / 400 / 409 / refused connection / DIMSE status /
`serve` exit 2), **CONFINE** (identity kept, but the reachable surface is narrowed to one set of
routes), **CHALLENGE** (force a fresh step-up), **THROTTLE** (429), **LOG** (record only, no decision
change). Where one attribute produced two different outcomes, the row is **split** so the mapping stays
one-to-one — that is why the bind/exposure posture occupies two rows and the AD reconciliation three.

#### Table A — control plane (operator API + web console)

| Attribute | Source of the value | Predicate / threshold | Action | Default | Knob |
|---|---|---|---|---|---|
| Client source network | ASGI `scope["client"][0]` (uvicorn's `ProxyHeadersMiddleware` is the single `X-Forwarded-For` trust point) | outside every listed CIDR/host; loopback always allowed; unresolvable address → fail closed | **DENY** 403 (`X-MessageFoundry-Denied: client-network`) / WS close `1008`, pre-routing; rate-limited WARNING; counted on `GET /security/posture`. `GET /health` is the sole exempt path and echoes `observed_client` when the allow-list is in use, so a locked-out operator can self-diagnose the address the engine actually sees | `[]` = no restriction | `[security].allowed_client_networks` |
| Client-address monoculture | the set of distinct observed client addresses | allow-list in use **and** no trusted proxy declared **and** ≥ 50 observations **and** all resolved to the same loopback address | **LOG** — one-shot WARNING + `client_address_monoculture` on `GET /security/posture` | n/a | (derived; no knob) |
| Login attempt rate, per client IP **and** globally | `request.client.host` (or the literal `"unknown"`) | > 10 attempts per IP (`login_rate_limit_per_ip`), or > 60 across all clients (`login_rate_limit_global`), in a rolling 60 s window (`login_rate_limit_window_seconds`); a refused attempt is not itself counted | **THROTTLE** — 429 `too many attempts` with **no** `Retry-After` on the three JSON routes; 429 + `Retry-After: 30` on `POST /ui/login`; a **303** redirect to `/ui/login?e=rate_limited` (no 429, no `Retry-After`) on `GET /ui/sso`, `GET /ui/oidc/start` and `GET /ui/oidc/callback`. WARNING-logged, deliberately **not** audited | on, 10 / 60 / 60 s | `[auth].login_rate_limit_enabled` |
| Credential-ceremony rate, per **actor** | `identity.user_id` (**not** an IP) | > `login_rate_limit_per_ip` (10) ceremonies per actor per 60 s; **no** global dimension (`glob=0`, deliberately) | **THROTTLE** 429, logged | on with the row above | *gated by the same* `[auth].login_rate_limit_enabled` |
| Consecutive credential failures on one account | the account's failure counter | ≥ 5 consecutive failures locks for 15 minutes; a lapsed window restarts the counter | **DENY** before any verify + an audit row whose name is leg-specific — `auth.login_locked` on the password path, `auth.mfa_failed` / `auth.webauthn_failed` with `reason=locked` on the TOTP/recovery and assertion legs (the password path still runs a dummy argon2 verify to keep timing flat) | 5 / 15 min | `[auth].lockout_threshold`, `lockout_minutes` |
| New client IP during a session | this request's address vs `session.client` | knob on **and** a session exists, is unrevoked, has an anchor, and the two are not the same host (both-loopback counts as one host) | **CHALLENGE** — force a fresh step-up; first sighting also writes `auth.admin_action_new_ip` + an out-of-band notice; repeats WARNING-log only. **Never** an RBAC deny | **off** | `[auth].admin_new_ip_step_up` |
| Credential recency | age of `session.reauth_at` | `now − reauth_at > step_up_max_age_seconds`, or `reauth_at is None` | **DENY** 403 + `X-Step-Up-Required: 1` (console: 303 → `/ui/reauth`) | 300 s | `[auth].step_up_max_age_seconds` |
| Action-bound step-up grant | a single-use grant minted only by `reauth(purpose=…)`, on the **monotonic** clock | no unconsumed grant for this route's action | **DENY** 403 + `X-Step-Up-Required` + `X-Step-Up-Action: <action>`; opting out falls back to the session window | on | `[auth].require_action_step_up` |
| MFA state | `session.mfa_verified_at` × factor enrollment × account roles | AD account → never required here (directory MFA is delegated); LOCAL + enrolled → always, whatever the scope says; LOCAL + un-enrolled → required when the knob is on **and** the scope covers the account — **`every_local_account` by default**, i.e. every local account, or the Administrator role only under `administrators` | **DENY** 403 + `X-MFA-Required: 1` on **every** authorized route — an **access gate**, not only a step-up gate; the console twin is a 303 to `/ui/mfa`, with the account and factor-enrolment routes exempt so an un-enrolled user is not stranded. An earlier revision of this row said Administrator-only and step-up-boundary-only; both were wrong | on; scope `every_local_account` | `[security].require_mfa`, `[security].require_mfa_scope` (the `[auth]` spellings are rejected at load) |
| Identity provider — local credential rotation | `identity.auth_provider` | the provider is AD (the credential is the directory's, not the engine's) | **DENY** `POST /me/password` with **400**; the step-up re-proof for that identity becomes a **live directory re-bind** instead of a local hash compare, so a disabled AD account cannot refresh its window, and the engine MFA gate never fires for it | n/a | `[auth].ad_enabled` |
| Authentication ambience | how the session was minted | browser Kerberos SSO and the OIDC callback mint with `seed_reauth=False` | **CHALLENGE** — the session is born **without** step-up freshness, so its first sensitive action forces an explicit credential step-up (the *second* signal in this table whose action is a challenge rather than a hard decision) | n/a | (by design) |
| Session age | `created_at` / `last_used_at` / `expires_at` vs wall clock, on **every** request | idle > 30 min; past the absolute expiry (12 h, or a tighter signature-verified federated `id_token.exp` cap); or a **backward** wall-clock step (NTP step-back, VM snapshot revert) | **DENY** — the session is revoked in the store, then 401. The idle clock is refreshed only by user-driven requests, so a background poll cannot keep a session alive | 30 min / 12 h | `[security].sign_out_after_idle_minutes`, `max_session_hours` (the ADR 0118 homes; `[auth].session_idle_timeout_minutes` / `session_absolute_hours` are the retired aliases), plus `[auth].oidc_session_max_hours` for a tighter federated cap |
| Account state — disabled | `user.disabled` | the account is disabled | **DENY** — no identity is built on **any** plane | n/a | (no knob — an admin action) |
| Account state — credential rotation pending | `user.must_change_password` | the flag is set | **CONFINE** — every route but the rotation routes is refused (403 JSON / 303 console / hard WS reject) | n/a | (no knob — set by admin creation and password reset) |
| Concurrent session count | the user's live session count at login | count would exceed the cap | **DENY** — this login proceeds; the user's **oldest** session is revoked | 5 sessions, `0` = unlimited | `[auth].max_sessions_per_user` |
| Live directory resolvability — probe strikes | a periodic AD probe of principals that still hold sessions | interval floored at 60 s; **2 consecutive** failed passes (`ad_session_recheck_strikes`); ≤ 200 users (`ad_session_recheck_max_users`) probed per pass, least-recently-probed first. Fail-**open** on DC unavailability (an unreachable DC revokes nothing) | **DENY** by revocation, `auth.ad_session_revoked` audited | **300 s** (the shipped default); `0` disables the loop entirely and is a named loosening | `[auth].ad_session_recheck_seconds`, `ad_session_recheck_strikes`, `ad_session_recheck_max_users` |
| Live directory group membership vs. the session's granted roles | the AD groups returned by that same reconciliation probe, mapped through the AD-group→role map | on a **successful (PRESENT)** probe, the mapped role set differs from the account's current roles — a **single** pass, **no** strike accrual (unlike the row above) | **DENY** by revocation of every session for that account (the new roles are persisted first), `auth.ad_session_revoked` with `reason = roles_changed`; charged against the same mass-revoke breaker as an absence | **300 s** (same loop; `0` disables it) | `[auth].ad_session_recheck_seconds` |
| Live directory mass-revoke breaker | the size of one pass's revocation set vs the probed population | the set exceeds **both** `ad_session_revoke_max` (**5**) **and** `ad_session_revoke_max_fraction` (**0.34**) — a second **binary** predicate layered on the row above, never a score (see "Directory session reconciliation") | **LOG** — the pass aborts revoking **nothing**, logs at ERROR and writes an `auth.ad_reconcile_aborted` audit row + loud alert | 5 / 0.34 | `[auth].ad_session_revoke_max`, `ad_session_revoke_max_fraction` |
| PHI-read volume, per actor | `identity.user_id` | > 120 reads (`phi_read_rate_limit_per_actor`) per 60 s (`phi_read_rate_limit_window_seconds`); the global dimension `phi_read_rate_limit_global` defaults to `0` = **off** | **THROTTLE** 429 + `Retry-After: 10`, WARNING-logged, charged at **admission** before any store work | on, 120 / 60 s | `[auth].phi_read_rate_limit_enabled` |
| Admin-write rate, per actor | `identity.user_id` × request method | **non-GET only**; > 12 writes (`admin_write_rate_limit_per_actor`) per 1.0 s (`admin_write_rate_limit_window_seconds`); no global dimension (`glob=0`) | **THROTTLE** 429 + `Retry-After: 1`, WARNING-logged. Charged on the JSON API and on `/ui`, which re-applies it | on, 12 writes / 1.0 s | `[auth].admin_write_rate_limit_enabled` |
| Serve-hop security posture | declared data class (`[ai].data_class`, or derived from `[ai].environment`) × `[security].enforcement` × (`api.is_loopback` **or** `exposure_protected`), via `phi_read_hop_disposition` | disposition is REFUSE — a **PHI** instance under `enforcement = enforce` whose serve hop is neither loopback, nor in-process TLS, nor a declared TLS-terminating proxy. Setting `[security].enforcement = warn` turns the refusal into WARN-and-serve; a non-PHI declared data class removes it entirely | **DENY** 403 (PHI-free message) on every **JSON-API** PHI-read route (`require_phi_read`, plus the step-up bulk routes), **before** any identity work. **Not applied on the `/ui` browse routes** — `enforce_phi_read_hop` has no console call site, so those get the per-actor budget only (pinned by `test_the_ui_phi_browse_gap_is_disclosed`) | ALLOW on loopback | `[security].enforcement`, `[ai].data_class`/`environment`, `[api].tls_cert_file`, `tls_terminated_upstream` + `trusted_proxies` |
| Bind / exposure posture — refusing arms | `[api].host` loopback-ness, `tls_terminated_upstream`, `trusted_proxies`, `public_origin`; derived `instance_exposed` (loopback-ness **or** a declared terminator) and `admin_exposed`, plus `ui_exposed` for the `/ui` arms only; `[security].enforcement`; declared data class | auth off on an exposed instance — a non-loopback bind **or** a declared terminator (`instance_exposed`); `/ui` exposed without the required origin/TLS declarations; `admin_exposed` + PHI + `enforcing` + `require_mfa` explicitly opted out | **DENY at startup** — `serve` prints an error and exits **2**. The refuse/warn dial is `[security].enforcement` (default `enforce`), **not** `production`: the auth-off and `/ui`-exposure arms refuse **unconditionally**, and the `require_mfa` arm refuses when the declared data class is PHI **and** enforcement is `enforce` — which includes the non-production `dev` and `staging` environments, both of which derive PHI — and warns otherwise. `[security].allow_single_factor_admin_when_exposed = true` downgrades that one arm to permitted-but-audited. **`admin_exposed` is `instance_exposed`, and reads no console flag** (BACKLOG #326): the ADR 0143 degrade arms rewrite `serve_ui` in place earlier in the same startup, so deriving an exposure decision from it made this arm and the dual-control arm below miss a declared-proxy instance whose console had been degraded or disabled — while the ASVS 11.7.1 arm called that same boot exposed. The same attributes force the session cookie's `Secure` flag + HSTS, and permit WebAuthn `rp_id` derivation from the request URL **only** on a loopback bind with no proxy declared | loopback, nothing declared | `[api].*`, `[security].enforcement`, `[security].allow_single_factor_admin_when_exposed`, `[ai].data_class`/`environment` |
| Bind / exposure posture — dual-control arm | `admin_exposed` (= `instance_exposed`: an off-loopback bind **or** a declared TLS terminator — never the console flag, BACKLOG #326) × `[approvals].enabled` × declared data class | `admin_exposed` **and** PHI **and** `[approvals].enabled` off — high-value actions complete on one caller's authority | **LOG** — a startup **WARNING only, on every instance including production**; `serve` does **not** refuse. The refuse arm is an explicit unresolved owner fork recorded in `__main__.py`, not a shipped control | approvals off | `[approvals].enabled` |
| Pending federated-login flows, per client IP | the `client_ip` recorded on each staged flow | ≥ **16** pending flows from this address (`DEFAULT_PER_IP_CAP`, no knob), or ≥ `oidc_flow_cache_max` (**512**) engine-wide; 300 s TTL; **reject-when-full, never evict** (evict-oldest would turn a start-leg flood into a login DoS) | **DENY** the start leg — `FlowCacheFullError` → **303** to `/ui/login?e=rate_limited`, WARNING-logged, deliberately **never** audited so a flood cannot amplify into `audit_log` growth | 16 / 512 / 300 s | `[auth].oidc_flow_cache_max`, `oidc_flow_ttl_seconds` |
| `Sec-Fetch-Mode` on the federated sign-in legs | the browser fetch-metadata header on `GET /ui/sso`, `POST /ui/oidc/start`, `GET /ui/oidc/callback` | header **present** and not `navigate` (absent = allowed, for non-browser clients). Distinct from the `Sec-Fetch-Site` row below: a different header, a different surface, and `assert_same_origin` deliberately does **not** run on the callback leg, whose `Sec-Fetch-Site` is legitimately cross-site | **DENY** — 303 → `/ui/login?e=sso_failed`\|`oidc_failed`, plus an **audited** `auth.login_failed` row carrying the closed-set slug `non_navigation_fetch`. Evaluated **after** the login limiter, so the audit write is itself rate-bounded | on | (no knob) |
| Instance environment posture × claimed AI data scope | `[ai].derived_posture()` (from `[ai].environment` / `data_class` / `production`; an unresolved posture defaults to the **strictest** ceiling) re-resolved server-side through `resolve_effective_policy` on every `POST /ai/chat` | the effective mode is not `managed_endpoint`, or the request's `data_scope` exceeds the server-enforced ceiling (the engine-broker MVP enforces `code_only` regardless of what the caller claims) | **DENY** — **409** on the mode mismatch, **403** on scope excess; each audited `ai.assist` with PHI-safe metadata only | `mode = byo`, `data_scope = code_only` | `[ai].mode`, `[ai].data_scope`, `[ai].environment`/`data_class`/`production` |
| Gated operation × requester-vs-approver identity × hold age | the pending-approval record: the operation name, the requesting identity, and the hold's creation time | `[approvals].enabled` **and** the operation is in `[approvals].operations` and has no approved unexpired release; the approver is the requester; the hold is older than `expiry_hours` | **DENY** the immediate execution — **202** hold + `approval.requested` audit; **403** on self-approval; **409** once expired or already decided | off; `['connection_purge','dead_letter_replay']`; 72 h | `[approvals].enabled`, `operations`, `expiry_hours` |
| mTLS client-certificate subject | the qualified subject-RDN / SAN names of a **verified** peer certificate | exact match against a deny-by-default map (empty map = feature off) | **ALLOW** — resolve to that principal's Identity (RBAC then authorizes); a disabled account grants none | `{}` = off | `[api].tls_client_cert_identities` (requires `tls_client_ca_file`) |
| Operator-listener peer client certificate | the TLS peer certificate presented at the API / `/ui` handshake | `[api].tls_client_ca_file` set (requires `tls_cert_file`) → `ssl.CERT_REQUIRED` plus strict RFC 5280 verify flags (`api/tls.py:47-50`); no client certificate, or one not issued by that CA | **DENY** — the TLS handshake fails, so the request never reaches the ASGI stack at all: no middleware runs, no route matches, no identity is resolved, and no 403 body is produced | unset = off (server-only TLS, no peer-certificate decision on the control plane) | `[api].tls_client_ca_file` |
| Declared token class of a federated assertion | the `typ` JOSE header, and the presence of an `events` claim, on a **signature-verified** JWS | `typ` present and — normalised `.strip().lower()` then `application/`-stripped — not `jwt`, so `at+jwt` (RFC 9068 access token), `logout+jwt` and `secevent+jwt` are refused while an **absent** `typ` is allowed (RFC 7519 §5.1 makes the header advisory); or the claim set carries `events`, i.e. an RFC 8417 security event token. Every such token is minted by the **same issuer under the same key**, so no signature or key rung distinguishes it | **DENY** the sign-in — `ClaimsError("wrong_token_type")` at the key-selection rung, `ClaimsError("unexpected_events_claim")` ahead of the nonce compare (a logout token carries no nonce, so a later check would misreport it as a browser-binding failure) | on | (no knob) |
| Federated authentication-context claims (`amr` / `acr`) | the `amr` list / `acr` string of a **signature-verified** `id_token` | `oidc_require_mfa_claim` on **and** neither an `amr` value in `[auth].oidc_mfa_amr_values` (default `["mfa"]`) nor an `acr` in `oidc_required_acr_values` (default `[]`, so the `amr` arm alone decides) | **DENY** the sign-in — `ClaimsError("mfa_claim_missing")`. An IdP **assertion**, never a proof | on, `["mfa"]` / `[]` | `[auth].oidc_require_mfa_claim`, `oidc_mfa_amr_values`, `oidc_required_acr_values` |
| UPN suffix of the federated username claim | the suffix after the FIRST `@` of the username claim | `oidc_username_strip_domain` on (default) **and** the suffix is not in `oidc_allowed_username_domains` (or `[auth].ad_domain`). With stripping **off** the claim is used verbatim and no suffix check runs | **DENY** the sign-in — `ClaimsError("username_domain_not_allowed")` | on | `[auth].oidc_allowed_username_domains`, `oidc_username_strip_domain` |
| Bootstrap-admin claim state × age × admin population | `users.password_claimed_at` and `users.created_at` for the built-in bootstrap account × whether a second enabled Administrator exists | still unclaimed (`password_claimed_at` unset — only the holder's own self-service rotation stamps it, and nothing clears it) **and** (`now ≥ created_at + bootstrap_expiry_hours × 3600` **or** another enabled admin exists); `0` = no time expiry | **DENY** — the account is disabled, **all** its sessions revoked, `auth.bootstrap_admin_retired` audited. A *claimed* bootstrap account is never touched, and an admin password reset does not un-claim it (ADR 0164) | 72 h | `[auth].bootstrap_expiry_hours` |
| Browser `Origin` at the WebSocket handshake | the `Origin` header on the upgrade | absent (a native client) → allowed; present → must be an exact member of the list, whose default `[]` rejects **every** browser Origin | **DENY** before `accept()`, so the route never runs | `[]` | `[api].ws_allowed_origins` |
| Cross-site request signal on a `/ui` state change | `Sec-Fetch-Site` (preferred) else `Origin` vs our own origin (`[api].public_origin` is authoritative when set; `Host` is the fallback) | `Sec-Fetch-Site` ∈ {cross-site, same-site}, or a non-matching `Origin` | **DENY** 403 — defence-in-depth over the `SameSite=Strict` cookie, deliberately token-free | on | `[api].public_origin` |

#### Table B — data plane (ingest listeners)

The per-connection `source_ip_allowlist` is enforced on **five** listener types — at **accept** on the four
stream listeners (MLLP, TCP, X12, HTTP), and for **DICOM inside the C-STORE handler**, i.e. after the
association has been negotiated and accepted and after the object has been received, but before any
durable commit. A non-allowlisted DICOM peer can therefore still establish an association, consume a
`max_associations` slot and transfer an object; each C-STORE is refused individually with `0x0124`.
`None`/empty
permits everyone; when set, the peer's IP must fall inside one listed IP or CIDR entry, a peer with **no
resolvable IP is denied** (fail closed), and an IPv4-mapped IPv6 peer on a dual-stack socket also
matches a plain IPv4 entry. Entries are validated at wiring time and the setting is legal only on a
listen source. The refusal action differs materially per listener, so each has its own row.

| Listener | Attribute | Predicate | Action |
|---|---|---|---|
| **MLLP** | peer socket address (`writer.get_extra_info('peername')`) | not in `source_ip_allowlist` | **DENY** — connection refused + WARNING log + a `peer_not_allowlisted` connection event; the refusal does **not** consume a `max_connections` slot |
| **TCP** | peer socket address | not in `source_ip_allowlist` | **DENY** — as MLLP (refuse, log, `peer_not_allowlisted` event) |
| **X12** | peer socket address | not in `source_ip_allowlist` | **DENY** — connection refused + WARNING log; **no connection event emitted** |
| **HTTP** | peer socket address | not in `source_ip_allowlist` | **DENY** — a real `403 {"error":"forbidden"}` is written to the peer, then close; WARNING log + `peer_not_allowlisted` event |
| **DICOM C-STORE SCP** | `event.assoc.requestor.address` | not in `source_ip_allowlist` | **DENY** — DIMSE status **`0x0124` (Not Authorized)** returned **before any durable commit**; WARNING log naming the peer IP and calling AE; **no connection event** |
| **MLLP / HTTP / DICOM** — peer client certificate | the TLS peer certificate presented at handshake | `tls = true` **and** `tls_ca_file` set → `ssl.CERT_REQUIRED` plus strict RFC 5280 verify flags; no client certificate, or one not issued by that CA | **DENY** — the TLS handshake fails and the connection **never reaches the accept path**, so there is **no** connection event and no allow-list evaluation. `tls_ca_file` unset → server-only TLS and no peer-certificate decision. TCP and X12 have no inbound TLS at this release |
| **DICOM** — calling AE | the requesting AE's Calling AE Title, at **association negotiation** | `calling_ae_allowlist` set and the title is not in it | **DENY** — the association is rejected by pynetdicom before any C-STORE callback runs (`ae.require_calling_aet`). `None` = any AE the peer-IP allow-list admits |
| **DICOM** — called AE | the AE Title the peer addressed the association to | not this engine's own `ae_title` | **DENY** at negotiation (`ae.require_called_aet`); **default `require_called_ae_title = true`** |
| **DICOM** — peer-control construction gate | the SCP's bind host × the presence of a **verifiable** peer control | non-loopback bind with **neither** `source_ip_allowlist` (an `inbound(...)` keyword — for a DICOM SCP the ONLY surface, since `DICOM()` is not authorable in `connections.toml`) **nor** mTLS (`tls` + `tls_ca_file` → `CERT_REQUIRED`). ⚠️ `calling_ae_allowlist` does **not** satisfy this gate alone (BACKLOG #316): an AE Title is caller-asserted with no cryptographic binding, so it is still enforced as a filter but must be **paired** with one of the two above | **DENY at construction** (ValueError). The connection degrades per ADR 0031 startup fault isolation and the fault surfaces under `messagefoundry check` / dry-run. Loopback hosts are exempt |

> **Telemetry honesty.** The `peer_not_allowlisted` connection event is durable when the connection's
> `capture_connection_errors` is `true`, **or is unset (`None`, the default) and the
> `[diagnostics].connection_events` master switch is on — which it is by default**. So on a default
> deployment MLLP, TCP and HTTP allow-list refusals **do** write a `connection_event` store row (never
> an audit row); X12 and DICOM emit no connection event at any setting and are log-only. The emit is
> fail-soft: a capture failure can never raise into the accept path.

> **Adjacent, and deliberately not a row above.** `[egress].allowed_db` / `allowed_http` / `allowed_tcp`
> gate where the **engine may connect out** (an inbound DATABASE source's server, a Handler's read-only
> `db_lookup` / `fhir_lookup`, an outbound destination's host), keyed on the **target** host — not on any
> consumer characteristic. `[egress].deny_by_default` makes an empty list a refusal rather than
> "unrestricted". They are authorization decisions, but not *consumer* authorization, so they are named
> here rather than tabulated.

#### How factors are graded (ASVS 8.1.4)

**This is the design, stated explicitly rather than left implied: every contextual signal above is a
binary predicate mapped to exactly one fixed action from the six-value vocabulary.** There is **no
composite risk score, no attribute weighting, and no graduated threshold ladder** anywhere in the
product. A signal either fires or it does not; when it fires, its action is the one named in its row —
and each row's Action cell opens with its one vocabulary word, so "the action" is never a judgement
call. Where a mechanism produces N outcomes it is **N rows**, each with its own predicate: the AD
reconciliation splits into a probe-strike DENY, a role-drift DENY and a mass-revoke-breaker LOG (the
role-drift arm revokes on a **single** pass, with no strike accrual), and the startup bind
posture splits into the arms that refuse (exit 2) and the dual-control arm that only warns. The
breaker's second predicate is itself binary (a threshold **pair**, both of which must be exceeded) —
still not a score.

The honest limits of that model, one sentence each:

- **Two** contextual signals are a CHALLENGE rather than a hard decision: the new-client-IP signal, and
  the authentication ambience of an SSO/OIDC-minted session (born without step-up freshness, so its
  first sensitive action forces one).
- The new-client-IP signal is **off by default**, and even when on it cannot fire on a single-host
  loopback session, because `127.0.0.1` and `::1` are folded into one host.
- The operator-surface network gate is **inert** behind an undeclared proxy or NAT (see layer 1 of
  [Administrative-interface defense-in-depth](#administrative-interface-defense-in-depth-wp-l3-13-asvs-842)).
- The per-actor admin-write floor is charged on the **JSON API only** at this release; the `/ui` write
  path charges none.
- The posture-keyed **PHI-read hop refusal** is likewise charged on the **JSON API only**:
  `enforce_phi_read_hop` has no `messagefoundry_webconsole/` call site, so the `/ui` browse routes
  (`GET /ui/messages`, `/ui/messages/{id}`, `/ui/messages/{id}/parse-tree`, …) are **not** gated by it
  and can emit PHI over a serve hop the JSON API would refuse. This is the larger of the two gaps.

**Attributes not consumed at this release** — stated so the inventory cannot be read as claiming more
than it does: time-of-day / hour-of-day, geolocation, device security posture or attestation,
user-agent / device fingerprint, behavioural baselines, and per-account login-**address history**.
Device posture specifically is deployment-delegated, not built in-process — see the residual note above.

Cross-links: function-level rules are the
[route → permission map](#route--permission-map-engine-api) (8.1.1); property-level rules are
[Field-level authorization](#field-level-property-authorization-wp-9) (8.1.2).

---

## Local vs Active Directory

Both kinds of user share one identity model (`users.auth_provider` is `local` or `ad`).

- **Local users** authenticate with an argon2id-hashed password and are assigned roles explicitly
  (`PUT /users/{id}/roles` or the web console Users page).
- **AD users** sign in through **Windows SSO or OIDC**, not with a directory password: the LDAP
  simple-bind sign-in is **retired**, and `POST /auth/login` with `provider=ad` is refused and
  audited. The engine still binds with a service account to find the user and resolve group
  membership (including **nested** groups via `LDAP_MATCHING_RULE_IN_CHAIN`), and their roles are
  still **re-synced from AD groups on every login** through the **AD-group→role map**, so manual
  role assignment doesn't apply to AD users. Binding **as the user** survives in one place only
  — step-up re-authentication at `POST /me/reauth`.
- **Windows SSO (Kerberos)** — optional, experimental. `POST /auth/negotiate` completes a SPNEGO
  exchange (`pyspnego`) for passwordless login on a domain-joined client; the resulting principal's
  groups are resolved the same way. Requires a server keytab/SPN. **Single-leg only:** the negotiate
  endpoint performs one SPNEGO step and does not return a `WWW-Authenticate` continuation token, so
  there is no mutual authentication and no NTLM-fallback / multi-leg exchange (those fail to
  authenticate). Every Kerberos reject path is audited (AUTH-K-AUDIT).
  **Browser SSO (L5c, ADR 0068 §9):** `GET /ui/sso` adds the RFC 4559 browser flow over the same
  single-leg acceptor — a 401 + `WWW-Authenticate: Negotiate` challenge (deliberately
  unthrottled; the token-bearing leg is rate-limited **first** — an exhausted limiter is
  throttle-logged, never audited, so a flood can't amplify into unbounded audit rows — then
  Sec-Fetch-Mode-hygiene-checked, with every reject beyond the throttle audited), minting ONE
  cookie session on success with **`seed_reauth=False`** (the SSO
  proof is ambient, so the first sensitive action forces the directory-password step-up at
  `/ui/reauth`; the JSON `/auth/negotiate` deliberately keeps its seeded window — the recorded
  asymmetry, flip approved as a follow-up). A **boot-once acceptor preflight** (app lifespan)
  degrades browser SSO legibly on a missing keytab/SPN — providers `kerberos=false`, the login
  link hidden, `/ui/sso` → `e=sso_unavailable` — instead of failing per-request; the JSON
  endpoint is unchanged (per-request attempt). Channel binding stays un-enforced
  (`channel_bindings=None` — EPA is structurally broken behind a TLS-terminating proxy; the
  acceptor-enforcement question is a recorded ADR 0068 spike). Still experimental + off by
  default; mock-seam test coverage only (no AD test infrastructure exists).

### AD-group → role mapping

An admin sets which AD groups govern which role via `GET/PUT /ad-group-map` (or the web console). Group
identifiers are matched case-insensitively and may be either the group **DN** or its
**sAMAccountName**. A user in multiple mapped groups gets the union of those roles.

```
CN=MF-Admins,OU=Groups,DC=example,DC=com  ->  administrator
CN=MF-Ops,OU=Groups,DC=example,DC=com     ->  operator
```

### Federated sign-in (OIDC, browser only — [ADR 0142](adr/0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md))

**Off by default** (`[auth].oidc_enabled = false`). When enabled, the browser console offers an OIDC
**authorization-code + PKCE** sign-in as a **third mechanism for an identity that already exists in
on-prem AD** — *not* a new identity provider. After the `id_token` verifies, the flow calls the same
password-free `resolve_principal()` the Kerberos path uses, so **roles come from LDAP, never from a
token claim**. There is no new `auth_provider` value: a federated login resolves to the AD identity.

- **Hybrid-only.** A principal with no on-prem AD object is refused (`not_in_directory`).
- **The username is bound to an allow-listed UPN suffix** (`[auth].oidc_allowed_username_domains`,
  defaulting to `ad_domain`). This is load-bearing, not hygiene: `preferred_username` is neither
  unique nor stable (OIDC Core §5.7) and is self-editable on several IdPs, so without it the claim's
  *local part alone* would decide which AD account is resolved — letting a federated principal pick a
  privileged one. Stripping a suffix with no allow-list configured is refused at startup.
- **MFA is an assertion, not a proof.** `oidc_require_mfa_claim` (default **on**) refuses a login
  whose verified token carries no configured `amr`/`acr` value. The engine verifies what the IdP
  **asserts**, cryptographically; it cannot prove the IdP *enforced* MFA, and this documentation will
  never claim otherwise. A compromised or misconfigured IdP can assert `amr:["mfa"]` falsely.
- **Session lifetime is capped at the verified `id_token.exp`** (ADR 0079 mechanism 1) — never
  extended by it. Local and AD session expiry are unchanged.
- **Endpoints are operator-pinned; there is no `.well-known` discovery**, so no attacker-influenced
  URL exists and a token's `kid` can never steer *where* the engine fetches from (no SSRF). It can
  still cause a refetch *of the pinned JWKS URI* — an unknown `kid` triggers at most one fetch per
  `[auth].oidc_jwks_min_refetch_seconds` (default 300s), globally, which is the amplification bound.
- **Degradation is isolated.** An unreachable IdP does not affect local, LDAPS or Kerberos sign-in,
  and federation recovers without an engine restart.
- **Step-up caveat.** Re-authentication for an AD identity re-binds with a **password**. An org that
  federates *because* its users are passwordless (WHfB/FIDO2) or smartcard-required may find those
  accounts cannot complete step-up. See ADR 0142 *Consequences*.
- **Out of scope:** SAML 2.0, cloud-only (non-hybrid) users, a JSON/API federated path (`/ui` only),
  refresh tokens, and RP-initiated logout.

Check the deployed posture with `messagefoundry verify --section federation`
([VERIFY.md](testing/VERIFY.md)), which can also replay a captured `id_token` offline through the
real validation ladder.

---

## Sessions

Sessions are **opaque server-side tokens** (not JWT): the client holds the token, the store keeps only
its SHA-256, so logout/expiry/role changes take effect immediately. Each request enforces an **idle
timeout** (default 30 min) and an **absolute lifetime** (default 12 h); changing a password,
disabling a user, or an **AD-group/role change on re-login** revokes that user's sessions. These two
defaults align the session controls with **NIST SP 800-63B §7.2** reauthentication at **AAL2** — a
**12-hour** maximum session length enforced regardless of activity, plus reauthentication after **30
minutes** of inactivity; raising `[security].max_session_hours` or `[security].sign_out_after_idle_minutes`
beyond those bounds is a **documented risk deviation** from AAL2, not a supported hardening knob, and
any such increase should be recorded as an accepted risk. Session
validation **fails closed on a backward wall-clock step** (NTP step-back / VM snapshot revert) rather
than reviving an expired token, and the idle clock is only refreshed by **user-driven** requests — a
background keepalive (the stats WebSocket re-checks itself, and is capped/short-lived) does not keep a
session alive. `[auth].max_sessions_per_user` caps concurrent sessions (default **5**; a login beyond
the cap revokes the user's oldest — ASVS 7.1.2; `0` = unlimited). Clients send the token as
`Authorization: Bearer <token>` (the WebSocket prefers the header; the legacy `?token=` query param is
deprecated because it leaks into proxy/access logs). The token is a **PHI-scoped** credential (the
user's full RBAC for the session lifetime): the web console holds it in the browser session and the
`apiclient` (test harness / automation) keeps it in memory, each re-validating it against `/auth/me`
before use (discarding a stale/revoked one); `apiclient` also **refuses to send credentials over
plaintext `http` to a non-loopback host** (no TLS yet) unless explicitly run with `--insecure` for
trusted-network dev. (The retired PySide6 desktop console's OS-keyring token cache is an accepted
retirement loss — BACKLOG #103.)

### Directory session reconciliation — propagating an AD disable (ADR 0079 mechanism 2)

Everything above revokes on a **local** event. A directory login is different: the engine mints its own
opaque session and, absent this control, **never re-consults AD again**. Disabling the account in Active
Directory therefore did **not** end the live session — it kept working, and kept refreshing, up to the
12-hour absolute cap.

The step-up surface was already partly covered, but not for the reason it looks like:
`require_step_up` performs **no** directory bind — it compares the session's stored `reauth_at` against
`[auth].step_up_max_age_seconds`. The live re-bind happens only in `POST /me/reauth`, which a disabled
account fails (`_find_user` rejects `userAccountControl & 0x2`). So purge / export / replay / config
reload / injection / user administration are lost by **inability to refresh**, leaving a residual of up
to `step_up_max_age_seconds` (300 s) from the last successful proof. What survived to the full 12 hours
was everything with no step-up gate: **bulk and raw PHI reads** (`GET /messages`, `/messages/{id}`,
attachments, `/dead-letters` — paced at `[auth].phi_read_rate_limit_per_actor`, 120/min) and
**connection start/stop/restart**.

`[auth].ad_session_recheck_seconds` (**default `300` s**; `0` = off) runs a background pass that re-resolves
every directory principal still holding a live session — via the same password-free service-account
lookup the Kerberos path uses — and revokes the sessions of accounts AD has disabled or deleted. Group
membership is re-diffed on the same pass at no extra directory cost, so a **role demotion** takes effect
without waiting for a login that may never happen. Revocations audit `auth.ad_session_revoked`.

Three safety properties, because the lookup returns one indistinguishable "not found" for *disabled*,
*deleted*, *moved out of the search base* and *the search base was never right*:

- **Fail-OPEN.** An unreachable domain controller revokes **nothing** and does not even accrue a strike.
  A fail-closed re-check would turn a directory blip into a total console outage during exactly the
  incident when operators need the console.
- **Two strikes** (`ad_session_recheck_strikes`, default 2) before any revocation.
- **A mass-revoke circuit breaker.** A misconfigured `ad_user_search_base`, an OU reorganisation, or a
  service account that lost read rights answers "not found" for *every* user. A pass whose revocation
  set exceeds **both** `ad_session_revoke_max` (5) **and** `ad_session_revoke_max_fraction` (0.34) of
  the probed population **aborts**: nothing is revoked, nothing is written, the engine logs at ERROR
  and audits `auth.ad_reconcile_aborted`, and the condition latches until a clean pass. Both thresholds
  must be exceeded — the floor alone would sign out a five-person site, the proportion alone would fire
  on a genuine 3-of-3 offboarding — so it trips only on a change that is simultaneously large and broad.

Revocation is therefore bounded by *interval × strikes* (10 minutes at the recommended 300 s), not
immediate, and one LDAP bind per signed-in directory user per pass is the cost —
`ad_session_recheck_max_users` (200) caps it, and it is zero when nobody is signed in. An off-loopback
PHI deployment serving AD accounts gets `ad_session_recheck_seconds = 300` by default; setting it to `0` is a declared loosening, not a neutral choice.

### Session inventory & targeted revocation (WP-10)

Users and admins can see and revoke individual sessions (ASVS 7.5.2 / 7.4.5):

- **`GET /me/sessions`** — your active sessions (created/last-used/expiry/client; the current one is
  flagged). The session `id` is the session's `token_hash` (a one-way hash of the opaque token, safe to
  expose).
- **`DELETE /me/sessions/{id}`** — revoke one of **your own** sessions (ownership-checked: another
  user's id returns 404, never revealing or touching it).
- **`DELETE /me/sessions`** — "sign out everywhere else": revoke all your sessions except the current.
- **`DELETE /users/{id}/sessions`** (`users:manage`) — admin force-sign-out of a user (offboarding /
  suspected compromise).

Every targeted revoke is audited (`auth.session_revoked`, with scope + actor). The **web console** surfaces
this: an **Active sessions…** view in the account menu lists your sessions and offers per-session
revoke + "sign out everywhere else" (the current session is shown but only revocable via *Sign out*),
and the **Users** page has a **Revoke sessions** action for admin force-sign-out.

### Security-event notifications (WP-L3-05, ASVS 6.3.5 / 6.3.7)

Users are notified of security-relevant changes to their account through **two** channels:

- **Out-of-band email to the affected user** (gated by `[auth].notify_security_events`, default on; it
  reuses the `[alerts]` SMTP transport and is sent to each user's **own** address — not the operator
  alert distribution list). Fired on: account **lockout** and the **first successful login after ≥3
  failed attempts** (suspicious-login signals, 6.3.5); and **password change**, **email change**, **role
  change**, and **account disable** (credential changes, 6.3.7). An email-change notice goes to the
  **old** address so the legitimate owner is alerted even if the change was hostile. With no `[alerts]`
  SMTP configured (or for accounts with no email on file), the email is simply skipped. Emission is
  **best-effort** — a notification failure is logged and never blocks a login or an admin action.
- **`GET /me/security-events`** — a pull-based feed of the caller's own audited `auth.*` events
  (sign-ins, lockouts, password changes), most-recent-first, for accounts without a deliverable mailbox.
  It is a read-only view over the tamper-evident audit log (no new store of record). Admin-initiated
  changes (whose audit `actor` is the admin) are delivered by the email channel, not shown in this self
  view.

MFA step-up is now built (WP-14 native TOTP); a web console banner for the feed remains future work (WS-G).

## Password policy

Local passwords follow an **ASVS 5.0-aligned** policy (WP-3): **min length 15**, **no mandatory
character-class composition** (the `require_*` class flags are opt-in, default off — ASVS forbids
mandatory composition), plus **offline breached/common-password screening** (a bundled offline
corpus, no live HIBP call) and a fixed **context-word deny-list**, enumerated in full below. Enforced
identically on create-user and change-password; tune via `[auth]` (see
[CONFIGURATION.md](CONFIGURATION.md)). AD passwords are governed by Active Directory.

**The context-word deny-list, in full.** A local password is refused if it *contains* any of these
twelve terms as a case-insensitive substring, anywhere in the value — not only as a prefix, and not
only as a whole word:

`messagefoundry`, `mefor`, `mllp`, `hl7`, `corepoint`, `mirth`, `rhapsody`, `changeme`, `bootstrap`,
`admin`, `administrator`, `password`

An earlier revision of this page described the list as "app/vendor/HL7 terms" and showed four of the
twelve as examples. That description was wrong in a way a reader could act on: five members —
`changeme`, `bootstrap`, `admin`, `administrator`, `password` — are generic credential words with no
connection to this application, to a vendor, or to HL7, so a passphrase chosen on the strength of the
old sentence could still be refused with no indication of which rule fired. The list above is the
whole of it, mirrored from `CONTEXT_WORDS` in
[`auth/policy.py`](../messagefoundry/auth/policy.py); the code is the authority if the two diverge.

**What a deploying site can and cannot tune here.** `password_check_context` is a whole-list on/off
switch, on by default. There is **no** setting that adds a site's own terms — its hospital
abbreviation, a partner or product name, the local domain — and none that removes a member whose
substring collides with a legitimate local word. A site that wants wider coverage supplies it through
`password_breach_corpus_file` below, which answers a different question: that corpus is matched
against the **whole** password, so a term added there is refused only when it *is* the password, never
when it appears inside a longer passphrase.

Two further screens (ASVS 6.2.11 / 6.2.12), both on by default and fully offline:

- **Username-in-password rejection** (`password_check_username`) — a password that *contains* the
  user's own username (case-insensitive, for usernames ≥ 4 chars) is rejected, catching the common
  `jsmith2026`-style choice that the corpus can't.
- **Larger operator breach corpus** (`password_breach_corpus_file`) — point this at an offline list to
  augment the bundled corpus: a **plaintext** file *or* an **HIBP-style SHA-1-hash export**
  (`HASH[:count]` lines, auto-detected), checked locally with no network call. Use a curated subset
  (it's loaded into memory), not the full ~40 GB HIBP set; a configured-but-unreadable path is warned
  at startup and falls back to the bundled list.

### Authentication pathways — comparative strength

**Five** authentication pathways ship: **three** interactive sign-ins (Local, Kerberos/SPNEGO,
OIDC), the **AD directory bind** — retained for step-up re-authentication after its sign-in was
retired — and the non-interactive mTLS service-identity plane.

| Pathway | Factor | Brute-force defense | Notes |
|---|---|---|---|
| **Local** (argon2id) | **password** (argon2id) **plus an engine second factor** — RFC 6238 TOTP, single-use recovery codes, or a WebAuthn/FIDO2 passkey. That factor is an **access gate, not merely a step-up boundary**: an MFA-pending session is refused on *every* authorized route with `X-MFA-Required: 1`, and a browser session is **redirected** to `/ui/mfa` — *not* confined to it, as an earlier revision of this cell said, because the account and factor-enrolment routes are declared MFA-pending-exempt, so a user with no factor yet enrols at `/ui/account`. It binds any local account that has enrolled a factor, plus every account `[security].require_mfa_scope` covers — **`every_local_account` by default** (`[security].require_mfa` defaults **on**; both keys are rejected under `[auth]` and fail the start). Set the scope to `administrators` for the earlier, narrower posture, in which a non-admin, un-enrolled local session is **password-only end to end**. Caveat: a passkey is asserted at `user_verification=preferred`, so for a passkey-only account the second factor may be **device possession alone** | **per-account lockout** (5/15 min), fed by **both** the password and the TOTP/recovery leg + breach/context policy + the per-IP **and** global sign-in window | the only pathway the engine itself can lock out; the only one with a phishing-resistant factor |
| **AD** (LDAP simple-bind, LDAPS by default) — **step-up re-authentication only; the sign-in was retired** | password, verified by a bind **as the user** against the DC. It no longer mints a session: `POST /auth/login` with `provider=ad` is refused and audited, and the bind survives only at `POST /me/reauth`, where it re-proves a session **another** pathway minted. So this row carries no MFA grant of its own — the session's MFA state was decided at sign-in by Kerberos or OIDC, and the delegated-directory relaxation now sits on the Kerberos row that still exercises it | the **directory's** lockout/complexity policy; engine-side, a **per-actor** step-up budget, **not** the sign-in limiter — the bind is post-session, so an unauthenticated flood cannot reach it, and `[auth].login_rate_limit_enabled=false` no longer strips this pathway bare — and **no** engine per-account lockout | password strength + lockout are the AD domain's responsibility. LDAPS is the default, not a structural guarantee: `[auth].ad_allow_insecure_ldap` opts into a plain bind, and `ad_tls_verify=false` is refused at startup unless the `MEFOR_ALLOW_INSECURE_TLS` dev escape is set |
| **Kerberos / SPNEGO** | domain ticket; MFA is **delegated and unverifiable at the engine** — the session is issued MFA-satisfied and no `amr`-equivalent evidence is received | the **domain's** controls; engine-side, the sign-in window on the token-bearing leg (`[auth].login_rate_limit_enabled`, default on — **off leaves this pathway with no engine-side control at all**; the RFC 4559 challenge leg is deliberately unthrottled either way) | experimental, off by default, **single-leg — no mutual authentication**, channel binding deliberately un-enforced. The browser leg (`GET /ui/sso`) mints with no step-up window, so the first sensitive action forces a step-up; the JSON `POST /auth/negotiate` seeds it |
| **OIDC federation** (browser only, hybrid AD-backed) | IdP-asserted, gated on a **signature-verified** `amr`/`acr` claim (`[auth].oidc_require_mfa_claim` defaults **on**) — an assertion, not a proof | no engine credential to guess, so no per-account lockout; both legs (`/ui/oidc/start`, `/ui/oidc/callback`) charge the sign-in window (`[auth].login_rate_limit_enabled`, default on — **off leaves this pathway with no engine-side control at all**, though the bounded pending-flow cache still caps concurrent start legs), plus the IdP's own lockout | hybrid-only: a federated principal with no on-prem AD object is refused. Roles come from LDAP, never from a token claim. When `[auth].oidc_username_strip_domain` is on (default), the claim's UPN suffix must match `oidc_allowed_username_domains` (or `[auth].ad_domain`); with stripping **off** the claim is used verbatim and no suffix check applies. The session's absolute lifetime is capped at the verified `id_token.exp`; minted with no step-up window |
| **mTLS service identity** (non-interactive, ADR 0083) | a **verified** client certificate mapped through a deny-by-default, name-space-qualified allow-list (`CN:` / `SAN:<type>:`) | **not applicable** — no guessable secret and no lockout; admission requires a chain verifying to the pinned client CA plus a listed qualified name | no session, no MFA, no step-up — which is why it is **PHI-fenced**: `require_service_cert` raises at **app construction** if asked to gate a PHI-view permission. One route only (`GET /service/identity`); every success is audited `service_cert_auth` |

Comparative properties on the dimensions the table's four columns cannot carry:

| Pathway | Phishing resistance | Replay resistance | Credential stored by the engine | MFA support | Revocation |
|---|---|---|---|---|---|
| **Local** | passkeys only (WebAuthn origin-bound, `attestation=none`, `user_verification=preferred`); password/TOTP are phishable | TOTP is single-use per 30 s step (`totp_skew_steps` default `0`); recovery codes single-use; passkey challenges are 64-byte CSPRNG, single-use, 120 s TTL, with a strict sign-counter compare-and-set | argon2id password hash (t=3, m=64 MiB, p=4); TOTP secret **cipher-encrypted**; recovery codes argon2id-hashed; COSE public keys **plaintext by design** | built (TOTP + passkeys) | disable the account or revoke sessions — immediate |
| **AD** | none | none beyond TLS | **none** — only the service-account bind password (env or a `[secrets]` reference, fail-closed) | **not asserted here** — the bind re-proves an existing session and grants nothing; the delegated, **unverifiable** MFA grant belongs to the Kerberos row | disabling in AD does **not** end a live session on its own; `[auth].ad_session_recheck_seconds` (default **300 s**) closes it, bounded by interval — strikes |
| **Kerberos** | none (single-leg, no channel binding) | ticket lifetime is the domain's | **none** — the acceptor keytab/SPN is OS-owned | delegated, unverifiable | as AD |
| **OIDC** | the IdP's, not the engine's | strongest of the four: server-side PKCE verifier + `state` (constant-time compare) + `nonce`, single-use flow, a `__Host-`-prefixed browser-binding cookie the callback requires, and a `typ`/kid/alg/signature/`events`/`iss`/`aud`/`exp`/`iat`/`nbf`/`nonce`/`sub` ladder under a bounded clock skew — `typ` and `events` assert the token **class** (an access token or a logout token carries the same issuer and key), and `sub`/`iat` are required rather than optional | **none** — only the confidential-client secret (env-only or a `[secrets]` reference, resolved eagerly at startup) | asserted via `amr`/`acr` **and enforced** — with `[auth].oidc_require_mfa_claim` on (default) a token carrying no configured `amr`/`acr` is refused at claims validation, and only then is the session minted MFA-verified; switch it off and the federated session is minted **un**verified, which `mfa_satisfied` refuses. This is the one directory leg whose factor the engine actually verifies | as AD, plus the `id_token.exp` cap; no refresh tokens and no RP-initiated logout |
| **mTLS** | n/a (no interactive ceremony) | n/a | **none** — the engine holds only the pinned client CA and the name map | none, structurally | **no revocation checking** — `VERIFY_X509_STRICT` is strict path validation, not OCSP/CRL; live revocation is the org's PKI. Engine-side: remove the allow-list entry (config change → restart) or disable the mapped account |

**Where each pathway is enforced, and what turns it on:** Local → `POST /auth/login` + `POST /ui/login`
(always available); AD → the same two routes with `provider=ad` (`[auth].ad_enabled`); Kerberos →
`POST /auth/negotiate` + `GET /ui/sso` (`[auth].kerberos_enabled`, default off); OIDC →
`GET`/`POST /ui/oidc/start` + `GET /ui/oidc/callback`, registered **only** when `[auth].oidc_enabled` (default
off, and it additionally requires `ad_enabled`); mTLS → `GET /service/identity`, active only when
`[api].tls_client_cert_identities` **and** `[api].tls_client_ca_file` are both set (default `{}` = off).

**A second gate applies to the three browser legs.** `POST /ui/login`, `GET /ui/sso` and the two
`GET /ui/oidc/*` routes are registered by the separately versioned web-console wheel, which is mounted
only when `[security].serve_web_console` is on (default on, but `serve` flips it off **in place** when
the console package is absent, and again when a non-explicit console would be exposed off-loopback).
Local and Kerberos survive that on their JSON routes (`POST /auth/login`, `POST /auth/negotiate`), so
**OIDC — browser-only — is unavailable in a JSON-only deployment even with `oidc_enabled = true`.**
`GET /auth/providers` reports **availability**, which is not the same as what is **configured**. Only
`local` (always true) and `ad` (`[auth].ad_enabled`) are pure config. `kerberos` is
`kerberos_available` — enabled **and** the boot-once SPNEGO acceptor preflight having passed, sticky
until restart (`auth/service.py:429-435`). `oidc` is `oidc_available` — `oidc_enabled` (which is
`[auth].oidc_enabled` **and** a directory to resolve roles against, `:448-452`) **and** the last IdP
interaction not having failed; that second term is deliberately **advisory and non-sticky**, set by a
failed login and cleared by the next success, and *no login path gates on it* (`:455-465`). Neither
flag consults `serve_ui`, so the route can still advertise `oidc: true` on a console-less engine that
registers no OIDC route. The mTLS plane is deliberately absent from it, because it is not a sign-in
offer.
`[security].allowed_client_networks` is a pre-auth network
gate that applies to **every** pathway equally, so it is a note here rather than a column.

**Lockout asymmetry and control coverage (ASVS 6.1.3 / 6.3.4).** The engine's per-account lockout
protects **Local** accounts only, and only the password and TOTP/recovery legs **feed** it; WebAuthn
assertion failures deliberately do not (signatures are not guessable secrets, and a flaky authenticator
must not lock an account) — **but an already-locked account IS refused at the assertion leg before any
verification** (`finish_webauthn_assertion` checks `locked_until` first and audits
`auth.webauthn_failed` with `reason=locked`), so the lock is *enforced* across every local factor even
though only two legs feed it. Neither fed nor enforced on `POST /me/reauth` or
`POST /me/password` — which now matters more, because since the AD sign-in was retired the step-up
re-auth route is the **only** place an AD password is still bound, and it is covered by a per-actor
budget rather than by either the lockout or the sign-in limiter. AD and Kerberos brute-force resistance
is the directory's job, so set the domain lockout/complexity policy accordingly. The engine-side
throttle that *does* cover Kerberos and OIDC is the sliding-window sign-in limiter — **per client IP and
globally**, not merely globally. **And it has one switch.** With
`[auth].login_rate_limit_enabled = false` the limiter is never constructed, so the Kerberos and
OIDC pathways retain only the directory's / IdP's own defenses and **no engine-side anti-automation at
all**, while Local keeps its per-account lockout and the AD step-up bind keeps its per-actor budget — which the 6.1.1 table records as having *no
dedicated off switch*. That one flag therefore **widens** the strength gap between the local and the
delegated pathways rather than narrowing it, and an operator turning it off must have the directory's
lockout policy carrying the whole load. OIDC has no engine credential to lock out; the mTLS plane has
no guessable secret at all, so no rate limit or lockout applies to it. **A genuine second factor is built
for local accounts only** — TOTP (WP-14) *and* WebAuthn passkeys (WP-14b), the latter being the only
phishing-resistant factor shipped; `[security].require_mfa` defaults **on** and its shipped scope is
**`every_local_account`** rather than the Administrator role, and it is enforced as an **access gate, not
only at the step-up boundary** — an MFA-pending session is refused on every authorized route. An earlier
revision of this sentence asserted the opposite on both counts and named the `[auth]` keys the loader
rejects; it also contradicted the Local row of the table above, which was right (see
[Multi-factor authentication](#multi-factor-authentication-totp-wp-14)).
AD/Kerberos MFA is delegated to the directory; OIDC's is asserted by the IdP and gated on a
signature-verified claim. **The consequence, stated plainly:** the AD and Kerberos pathways satisfy the
engine's MFA gates without an engine-verified factor, so a *domain ticket* on the Kerberos pathway
reaches the same PHI surface as a passkey-backed local Administrator. The mechanism is a **per-mechanism argument**, not a
blanket literal: `mfa_verified` is a keyword parameter of `_complete_ad_login`, and the Kerberos leg
passes `True` under the signed delegated-directory relaxation while the federated leg passes
`[auth].oidc_require_mfa_claim` itself — on by default, and reached only after the claim gate has already
refused any token carrying no configured `amr`/`acr`, so the grant there is engine-verified rather than
assumed. Turn that setting off and the federated session mints **un**verified, and `mfa_satisfied`
refuses it while `[security].require_mfa` is on (the default). An earlier revision of this sentence said
`_complete_ad_login` mints all three `mfa_verified=True` unconditionally; that was wrong about the
mechanism and contradicted the OIDC row of the table above. OIDC therefore remains the only delegated
pathway carrying engine-side evidence at all; AD and Kerberos carry none, and **closing that gap is the
deploying site's job, in the directory** — the engine accepts whatever the directory asserts, so the
domain's own MFA policy (Entra Conditional Access or an MFA proxy) is the only control over those two
pathways.

## Brute-force & abuse protection

### The documented protection set (ASVS 6.1.1)

Nine controls defend the authentication surface against automated attack. Each is named with its
threshold, the switch that disables it, and — the part that matters for "not disabled or bypassable" —
**what is left when it is off**.

| # | Control | Protects | Threshold / window | Disable switch | What remains when off |
|---|---|---|---|---|---|
| 1 | **Per-account lockout** | one account's credential-guessing, on the password **and** TOTP/recovery legs | 5 consecutive failures → 15 min; a lapsed window restarts the counter, so each lock expires on its own — but **repetition is unbounded**: an attacker who keeps failing re-locks the account as each window lapses. Signal, recovery and what to arrange in advance: below the table | **no dedicated off switch.** `lockout_minutes = 0` makes the lock expire instantly, which is the effective opt-out; `lockout_threshold = 0` is **not** an off switch — it locks on the *first* failure | limiters 2 + 3 only |
| 2 | **Sign-in sliding window** (`allow_login_attempt`) | password-spraying across many usernames, which never trips a single account's lockout | > 10 attempts per client IP **or** > 60 across all clients, per 60 s (either dimension alone refuses — `global_full or key_full`) | `[auth].login_rate_limit_enabled = false` | lockout only — **and limiter 3 disappears with it** (see below) |
| 3 | **Per-actor credential-ceremony budget** (`allow_reauth_attempt`) | a session holder guessing a password at the re-proof surface, where lockout does **not** apply | > 10 ceremonies per acting **user**, per 60 s. **No global dimension** (`glob=0`) | *the same* `[auth].login_rate_limit_enabled` | **nothing** — `POST /me/reauth` and `POST /me/password` then have no anti-automation control at all |
| 4 | **argon2 concurrency cap** | executor exhaustion under a login flood | an instance semaphore sized `max(2, min(8, cpu_count))`; every hash/verify runs off the event loop | none | n/a |
| 5 | **Request-body cap + field limits** | oversized/ambiguous auth requests | 1 MiB (the `/uploads` routes alone admit up to `[store].max_upload_bytes`), a **required** `Content-Length` for any body (a chunked body is refused **411**), and CL+TE ambiguous framing refused **400** — all as ASGI middleware ahead of every route | none | n/a |
| 6 | **Pre-auth client-network gate** | reaching the auth surface at all from an unlisted network | membership in `[security].allowed_client_networks` | `[]` = no restriction (the default) | limiters 1–3 |
| 7 | **Federated pending-flow bound** (`FlowCache.put`, **reject-when-full**) | flooding the OIDC start leg (`POST /ui/oidc/start` — the GET renders the 3.7.3 interstitial and stages nothing, so it is not a lever) to exhaust engine memory or deny federated sign-in | 16 pending flows per client IP, 512 engine-wide, 300 s TTL. It **rejects** rather than evicts — evict-oldest would turn a start-leg flood into a login DoS for legitimate users | **none** — and `oidc_flow_cache_max = 0` is not an opt-out either: `put` refuses at `len(entries) >= global_cap`, so `0` rejects **every** federated sign-in (`FlowCacheFullError` on the first flow, an OIDC denial of service). No validator floors it; treat it as a security-relevant value | limiter 2 (the same routes charge `allow_login_attempt` first) |
| 8 | **WebAuthn pending-ceremony bound** (`ChallengeCache.put`) | flooding passkey registration/assertion ceremonies | 16 pending ceremonies per **user** (evicts that *same* user's oldest, so one principal can never deny another's), 4096 engine-wide (**refuses** with a cause-naming `ChallengeCacheFullError`), 120 s TTL | none | limiter 3 on the assertion **finish** leg only — `POST /ui/reauth/webauthn` (`routes/core.py:689`) and the error re-render inside `POST /ui/reauth` (`:612`) charge `allow_reauth_attempt`. The routes that *stage* a ceremony — the thing `ChallengeCache.put` actually bounds — charge **no** limiter: `POST /ui/account/webauthn/enroll`, `POST /ui/account/webauthn/verify`, and `GET /ui/reauth`, which re-stages fresh assertion options on **every** render. There this bound plus cookie-holder-only reachability is all there is |
| 9 | **JWKS min-refetch floor** (`JwksCache.get_key`) | unauthenticated `kid`-driven refetch amplification against the IdP on the OIDC callback leg — the sibling of control 7 on the *other* federated leg | one upstream fetch per **300 s**, globally (`[auth].oidc_jwks_min_refetch_seconds`), plus a `_MAX_JWKS_BYTES` **512 KiB** response-body cap and a 3600 s key TTL. Within the floor an unknown `kid` raises `JwksError` and that login fails (a still-cached key is served even past the soft TTL rather than fail while throttled) | `oidc_jwks_min_refetch_seconds = 0` — no validator floor, so this **is** a genuine opt-out, and it restores the amplification | limiter 2 and control 7 (the same legs charge `allow_login_attempt` and stage a bounded flow first) |

**Control 1 bounds the lock, not the campaign.** Each lockout releases itself after
`lockout_minutes`, but `_register_failure` restarts the counter on a lapsed window and re-locks on the
next run to the threshold, and the account row persists a failure count and an expiry — never a count
of locks — so nothing accumulates across cycles and the number of cycles has no ceiling. The account
is reachable in the gap between one lock expiring and the next being set, and no longer. Sustaining
the re-lock costs far fewer attempts than control 2's sign-in window admits from a single client
address, so control 2 does not bound it either. The exposure is availability, not credential
disclosure, and its scope is narrow: only **local** accounts can be locked at all (the
lockout-asymmetry note above says why), and control 6 refuses an off-network client before any
failure is counted — but only where client addresses are meaningful. Behind an undeclared proxy or
NAT control 6 is **inert**, by its own honest-limit note above, so it narrows who can reach the
account rather than closing the case.

**Signal.** The account holder gets an `ACCOUNT_LOCKED` security event — mailed only under the
conditions the security-event notification section above states (an alert sink configured, the
notification setting on, and an address on the account), and recorded on `GET /me/security-events`,
which is a self-scoped feed the holder can read only while they still hold a live, fully-authenticated
session. Each refusal is also audited, so a campaign is visible in the audit log while it runs. What
is **not** available anywhere is **current lock state**: no API or console surface reports whether an
account is locked right now, and a locked account still lists as enabled. Diagnose a suspected lockout
from the audit log, not the user list.

**Recovery.** Absent a sustained attacker nothing is needed — the lock expires on its own. Against a
sustained one: across all three store backends the writes that clear `locked_until` are
`set_password`, the successful-login write and the failed-attempt write, and only `set_password` can
run while a lock is live — control 1 refuses before any credential is verified, so neither the
successful-login write nor the login-time rehash beside it is ever reached, and the failed-attempt
write only clears an **already lapsed** lock. Two routes reach `set_password` while an account is
locked, both local-account-only, and **both issue a new password rather than merely lifting the
lock**: the holder's own `POST /me/password`, reachable only while they still have a live session
(session validation never consults `locked_until`, and that route is exempt from both the must-change
and the MFA-pending gates), and the
[administrator's reset](#admin-password-reset-wp-l3-12-asvs-646). No shipped command clears a lock
without going through one of those two — the CLI manages no users.

**Arrange in advance.** Keep a **second administrator who can sign in**: the administrator reset
refuses a self-reset, so a sole administrator holding no live session has no in-band route back for as
long as an attacker sustains the lock.

> **Binding conditionality — controls 2 and 3 are one switch, not two.**
> `[auth].login_rate_limit_enabled = false` constructs **neither** limiter: `_login_limiter` and
> `_reauth_limiter` are both `None` and both accessors then return `True` unconditionally. They share
> the same thresholds (`login_rate_limit_per_ip`, `login_rate_limit_window_seconds` — the per-IP name is
> historical; limiter 3 keys on the **user**) and limiter 3 has no enable flag, no thresholds and no
> window of its own. They must never be described as independent controls. Turning that one flag off
> also removes the *only* bound on session-holder password guessing, because `POST /me/reauth` and
> `POST /me/password` verify a password with argon2 but check no `locked_until` and register no failure.

The two limiters exist separately for a reason: limiter 2's **global** budget is shared with the
unauthenticated sign-in surface, so anyone able to reach the login page could otherwise exhaust it and
deny re-authentication — and therefore every step-up action — to every signed-in operator, without
holding a credential.

**What a tripped control looks like (6.1.1's "consequences of these defenses being triggered").**
Control 1 refuses before any verify and audits the refusal — but the event name differs per leg:
`auth.login_locked` on the local password path (`auth/service.py:600`), `auth.mfa_failed` with
`reason=locked` on the TOTP/recovery leg (`:1801-1808`), and `auth.webauthn_failed` with
`reason=locked` on the assertion leg (`:2126-2133`). Controls 2 and 3
return **429**. `Retry-After: 30` is carried by `POST /ui/login` (control 2) and by `POST /ui/reauth`,
`POST /ui/reauth/webauthn` and `POST /ui/mfa` (control 3); the three JSON sign-in routes, the three JSON ceremony
routes (`POST /me/password`, `POST /me/reauth`, `POST /me/mfa/confirm`, all via
`auth_routes._rate_limited`) and `POST /ui/account/mfa/verify` (via the console `_rate_limited`) carry
none. The three console *entry* routes answer with a **303 redirect** instead of a 429 (see the limits
table below for that split). Control 7 rejects
with `FlowCacheFullError`, which the start leg turns into a **303 redirect to `/ui/login?e=rate_limited`**
— rendered as "Too many attempts — wait a moment and try again." — plus a `_log.warning`, and
deliberately **never** an audit row, so a flood cannot amplify into unbounded `audit_log` growth.
Control 8's per-user arm is silent (it evicts the same user's own oldest pending ceremony); its global
arm raises `ChallengeCacheFullError`, whose message names the cause and points at `admin_reset_mfa` as
the recovery path. Controls 4–6 are covered in their own rows.

### Route → limiter map

| Route | Limiter | Notes |
|---|---|---|
| `POST /auth/login` | sign-in window | |
| `POST /auth/negotiate` | sign-in window | |
| `POST /auth/mfa-verify` | sign-in window | an **authenticated** route drawing the sign-in budget (it is a mid-login challenge); also feeds the per-account lockout |
| `POST /ui/login` | sign-in window | 429 carries `Retry-After: 30` |
| `GET /ui/sso` | sign-in window | the token-bearing leg only; the RFC 4559 challenge leg is deliberately unthrottled |
| `POST /ui/oidc/start`, `GET /ui/oidc/callback` | sign-in window | one browser login charges it **twice**. ⚠️ The start leg is a **POST** since the ASVS 3.7.3 interstitial: `GET /ui/oidc/start` now renders the "you are leaving this site" page and mints **no** flow, so it charges no limiter — the flow starts only when the operator confirms. |
| `POST /me/password` | per-actor ceremony budget | **not** the sign-in window |
| `POST /me/reauth` | per-actor ceremony budget | |
| `POST /me/mfa/confirm` | per-actor ceremony budget | |
| `POST /ui/reauth`, `POST /ui/reauth/webauthn` | per-actor ceremony budget | the only route that finishes a WebAuthn assertion is the second one; **both carry `Retry-After: 30`** on the 429 (the first as an `HTTPException` header, the second on a `JSONResponse`) |
| `POST /ui/mfa` | per-actor ceremony budget | the ASVS 6.3.3 sign-in gate: it submits the second factor for a session that has already proven its password, so it draws the same budget as `POST /ui/reauth` and carries the same `Retry-After: 30` |
| `POST /ui/account/mfa/verify` | per-actor ceremony budget | |
| `POST /ui/account/password` | *(inherits)* | delegates to the JSON handler, which charges once; the 429 is re-raised intact — deliberately not double-charged |
| **No limiter of any kind** | — | `POST /auth/logout`, `POST /me/mfa/enroll`, `DELETE /me/mfa`, `DELETE /me/sessions[/{id}]`, `POST /ai/chat`, `DELETE /search/presets/{preset_id}`, `PATCH /logging/level`. `PATCH /users/{user_id}` USED to sit here: it lost the write pacing when it was promoted to an action-bound step-up gate. BACKLOG #1148 made `require_step_up_action` charge the floor, so it is paced again and has left this row. The `reauth_only` action gate still charges none. The console's WebAuthn **ceremony-staging** routes are here too — `POST /ui/account/webauthn/enroll`, `POST /ui/account/webauthn/verify` and `GET /ui/reauth` (which re-stages assertion options on every render) — so the `/ui` ceremony surface is **not** fully paced; only the `POST /ui/reauth/webauthn` finish leg charges limiter 3 |

The console resolves the ceremony gate through a `getattr` shim because it ships as a separately
versioned wheel: mounted on an engine that predates the method, it falls back to the **sign-in** budget.
Any statement about the `/ui` ceremony budget is therefore engine-version-conditional.

### Business-logic limits (ASVS 2.1.3)

Every enforced limit, with both dimensions stated even where one is hard-coded off, because "per-user
**and** globally" is the requirement's own wording. **Enforcement scope is stated per row, because it
is not uniform.** The four sliding-window limiters (sign-in, credential ceremony, PHI read, admin
write) and the two pending-flow caches are **in-process, per API process** — N engine shards multiply
*those* budgets by N. The account lockout, the concurrent-session cap and the bootstrap-admin timer are
**store-backed** (`record_login_failure` / `enforce_session_cap` / `set_user_disabled` against the one
unified store), so they are **shared** by every API process and are **not** multiplied by N. The
per-uploader file/byte quota is also **not** multiplied by N: it is scoped to the `uploads_dir` (an
uncached sidecar scan) with its check-then-write held as an atomic reservation on that same unified
store, so shards sharing one dir enforce one budget between them. The request-body cap and the
remote-file retrieve bound are **stateless** — a per-request and a per-file test that carry no budget
at all. An exposed or multi-host deployment must additionally front the API with a proxy/WAF limiter
and TLS.

| Limit | Setting(s) | Default | Window | Per-user | Global | Per-IP | Scope | On breach |
|---|---|---|---|---|---|---|---|---|
| Sign-in attempts | `[auth].login_rate_limit_enabled`, `login_rate_limit_per_ip`, `login_rate_limit_global`, `login_rate_limit_window_seconds` | on / 10 / 60 / 60.0 s | 60 s | no | **yes** (60) | **yes** (10) | **in-process** — 3 JSON + 4 console entry routes | logged, **not** audited. **429 + `Retry-After: 30` on `POST /ui/login`** — the only *sign-in-window* route that sends the header (the two `/ui/reauth*` **ceremony** routes send it too, see the row below); a **303 redirect to `/ui/login?e=rate_limited` (no 429, no `Retry-After`)** on `GET /ui/sso`, `GET /ui/oidc/start` and `GET /ui/oidc/callback`, because a browser navigation cannot render a 429 usefully; **429 with no `Retry-After`** on the three JSON routes |
| Credential ceremonies | *(shares* `login_rate_limit_per_ip` *and* `login_rate_limit_window_seconds`*, and the same enable flag)* | on / 10 / — / 60.0 s | 60 s | **yes** (10) | no (`glob=0`) | no | **in-process** — 3 JSON + 3 console ceremony routes | 429; `Retry-After: 30` on the two `/ui/reauth*` routes, none on the other four; logged |
| Account lockout | `[auth].lockout_threshold`, `lockout_minutes` | 5 / 15 min | — | **yes** | no | no | **store-backed** — local password + TOTP/recovery legs | refuse + an audit row, named per leg — `auth.login_locked` on the password leg, `auth.mfa_failed` / `auth.webauthn_failed` with `reason=locked` on the factor legs |
| PHI reads | `[auth].phi_read_rate_limit_enabled`, `phi_read_rate_limit_per_actor`, `phi_read_rate_limit_global`, `phi_read_rate_limit_window_seconds` | on / 120 / **0 = off** / 60.0 s | 60 s | **yes** (120) | off by default | no | **in-process** — 7 JSON routes via `require_phi_read`, 4 bulk-PHI step-up GETs charged at admission, 5 `/ui` views via `require_ui(phi=True)`, and 1 further `/ui` GET that inherits the charge by delegating into the handler body | 429 + `Retry-After: 10`, logged |
| Admin writes | `[auth].admin_write_rate_limit_enabled`, `admin_write_rate_limit_per_actor`, `admin_write_rate_limit_window_seconds` | on / 12 / 1.0 s | 1.0 s | **yes** (12) | no (`glob=0`) | no | **in-process** — **non-GET only**, via `require_step_up`, `require_step_up_action` **and** `require_paced`; `/ui` re-applies it in `require_ui` | 429 + `Retry-After: 1`, logged |
| Concurrent sessions | `[auth].max_sessions_per_user` | 5 (`0` = unlimited) | — | **yes** | no | no | **store-backed** — every login | the user's oldest session is revoked |
| Bootstrap-admin lifetime | `[auth].bootstrap_expiry_hours` | 72 h (`0` = no timer) | — | n/a | n/a | n/a | **store-backed** — the unclaimed bootstrap account | disabled + audited |
| Request body | `[store].max_upload_bytes` (the `/uploads` routes only) | 1 MiB elsewhere | per request | no | no | no | **stateless** — every route, in ASGI middleware | **413** over the cap, **400** on ambiguous CL+TE framing or an invalid `Content-Length`, **411** on a chunked body |
| Uploaded files retained, per uploader | `[store].max_upload_files_per_user`, `max_upload_total_bytes_per_user`, `uploads_retention_days` | 100 files / 250 MiB / 30 days | cumulative (no window; the retention age is what releases budget) | **yes** — a **cumulative** count *and* byte total, so the single-file cap above is not the only upload bound | no | no | **store-backed** — scoped to the `uploads_dir` via an uncached sidecar scan, with the check-then-write held as an atomic `reserve_upload_quota` on the unified store, so shards sharing a dir share one budget (separate dirs get separate budgets by construction) | **409** before any write, audited `upload.reject_quota`; over-age blob+meta pairs are pruned and audited `upload.prune`. Defaults-**on** with a `ge=1` floor once `uploads_dir` is set — the control cannot ship disabled |
| Remote-file retrieve | `max_file_bytes` (the `File(...)` and `Sftp`/`Ftp` inbound connections) | 16 MiB | per file | no | no | no | **stateless** — a per-file test carrying no budget, applied in the connector | the file is quarantined to `error_subdir` and WARNING-logged; it never becomes a received message, so there is no store disposition. **Charged twice on a remote source, and the second charge is the one that binds** (BACKLOG #1191): once against the size the partner server reported in its own directory listing, then again against the **bytes actually read**, streaming in 1 MiB chunks so a share that lists a small file and delivers an arbitrarily large body is cut off mid-transfer. That second charge is the only bound that can see this surface at all — the connector consumes the body *before* an ingress row exists |
| OIDC pending flows | `[auth].oidc_flow_cache_max` (global), `DEFAULT_PER_IP_CAP` (per-IP, no knob), `oidc_flow_ttl_seconds` | 512 / 16 / 300 s | 300 s TTL | no | **yes** (512) | **yes** (16) | **in-process** — `GET /ui/oidc/start` — reject-when-full, never evict | 303 → `/ui/login?e=rate_limited`, WARNING-logged, **never** audited |
| WebAuthn pending ceremonies | `GLOBAL_PENDING_CAP`, `PER_USER_PENDING_CAP`, `CHALLENGE_TTL_SECONDS` (module constants, no knobs) | 4096 / 16 / 120 s | 120 s TTL | **yes** (16) | **yes** (4096) | no | **in-process** — every passkey registration + assertion ceremony | per-user: evicts that user's **own** oldest pending ceremony (silent); global: `ChallengeCacheFullError` naming the cause + the `admin_reset_mfa` recovery path |
| **Ingest plane** | `max_messages_per_second`, `message_burst` (MLLP, raw-TCP, X12 and HTTP inbounds) | **off** (unset = no rate bound) | per message | no | no | no | **in-process** — one bucket per MLLP / raw-TCP / X12 **connection** and one per HTTP **listener**, so it neither coordinates across engine shards nor aggregates per peer | **Ships OFF, and the off default is ruled rather than accidental** — a rate on a clinical interface is only safe at a number taken from a real feed profile. **So a default install has NO message-RATE bound on the ingest plane**, and that is a deliberate posture, not a gap in the control. Both keys are parameters of the `MLLP()`, `Tcp()`, `X12()` and `Http()` factories, and `connections.toml` desugars through those same factories, so **the code-first and the TOML surface both express them** (BACKLOG #1249 for MLLP, BACKLOG #1114 for the other three — until #1249 landed the pacer was built and no documented configuration could turn it on, and until #1114 landed the other three intakes had no rate control in **any** configuration, which is a different and worse thing than being off). *What it does when set:* the listener **pauses reading before its next read** so TCP back-pressures the sender; no message is dropped, refused, NAK'd, 429'd or reordered — the count-and-log invariant forbids accept-and-drop, so a discarding limiter was never available. **The HTTP bucket is listener-wide, not per-connection**, because that connector answers one request per connection; a `GET`/`HEAD` probe waits behind an outstanding debt but charges nothing. **Not covered even when set:** the DICOM C-STORE SCP (a pace-before-decode bound does not transfer to an association), the File / RemoteFile / Database poll sources (they bind nothing and need a per-tick ceiling instead — a different shape), and any per-peer bound (MLLP, TCP and X12 peers are unauthenticated, so the only key would be source IP, which NAT collapses). **Resource bounds that DO ship on** — `max_connections` (256), `receive_timeout` (60.0 s), `max_frame_bytes` (16 MiB), per-connection `max_message_bytes`, `source_ip_allowlist` |

**What these limits defend, and what they do not.** The full inventory of resource-demanding
functionality — including the surfaces that remain **unbounded** at this release — is
security/THREAT-MODEL.md §Resource-demanding functionality (ASVS 15.1.3).
Read the two together: the table above is the operator-surface half, and that section is the whole
picture including the ingest plane. That document is maintainer-internal;
[SECURITY-DOCS-POLICY.md](SECURITY-DOCS-POLICY.md) explains what is withheld and what you can request.

**No limiter has a validator floor.** None of the eleven `*_rate_limit_*` fields, nor
`lockout_threshold` / `lockout_minutes`, carries a Pydantic validator. So a `per_key` or `glob` of `0`
silently disables that dimension, and a `*_window_seconds` of `0` ages every recorded hit out
immediately — disabling enforcement while the limiter still reports as "enabled". Treat these as
security-relevant values, not tuning knobs.

**Throttle observability.** A rate-limited auth attempt is written to the rotating general log at
WARNING with a route label and the client address, deliberately **not** to the hash-chained
`audit_log`, so a sustained flood cannot amplify into unbounded DB growth (ASVS 16.3.3); the durable
trail is the per-account `auth.login_failed` / `auth.login_locked` rows, plus `auth.mfa_failed` and
`auth.webauthn_failed` for refusals on the factor legs (a lockout hit while proving a second factor
is audited under those names, not `auth.login_locked`). PHI-read and admin-write
throttles log at WARNING with actor + path.

**Per-IP limiter caveat (SEC-024).** The per-client-IP sign-in window is in-process and keyed on the
caller's source address, so an attacker who can rotate source addresses creates a fresh empty per-IP
bucket each time and is bounded only by the **global** ceiling. The source IP is already proxy-aware —
uvicorn runs with `forwarded_allow_ips = settings.api.trusted_proxies` (defaults to `[]` = trust
nothing), and an off-loopback proxied bind is gated to require a declared trusted proxy — but an
in-process per-IP limiter inherently cannot stop pure IP rotation by a **directly-reachable** attacker.
The anti-guessing controls that survive rotation are the **global sign-in ceiling** plus the
**per-account argon2 lockout (5 / 15 min)**, applied to **both** the password and the MFA
second-factor paths, so guessing of a specific *local* account stays well-bounded **at the login
route**. That pair does **not** reach the credential re-proof surface: `POST /me/reauth` and
`POST /me/password` are covered only by the per-actor ceremony budget, which has no global dimension —
for a session holder the bound is 10 attempts / 60 s per actor, and nothing more. The default
`127.0.0.1` bind makes IP rotation moot; for an off-loopback bind without a fronting WAF, deploy a
global limiter / WAF in front (a modest unconditional global login/second-factor ceiling independent of
IP is a backlog follow-up).

## Audit

Every authentication and authorization event is written to the durable `audit_log` with the acting
user: `auth.login_success` / `auth.login_failed` / `auth.login_locked` / `auth.logout` /
`auth.permission_denied` / `auth.channel_denied`, plus `user.created` / `user.roles_changed` /
`user.channel_scope_changed` / `user.deleted`, `ad_group_map.updated` / `ad_group_scope_map.updated`,
and `auth.ad_scope_resynced`. PHI access (viewing a raw message or displaying patient summaries) is recorded
with the viewer. Read the trail via `GET /audit` (`audit:read`). **Credentials, tokens, and PHI bodies
are never logged** (only ids/counts land in `detail`).

**Client attribution ([ADR 0150](adr/0150-client-address-on-audit-entries.md)).** Every row also
carries a `client` column — the caller's network address, stamped at write time from the request via
the same `client_ip()` the new-client-IP risk signal uses (so behind a declared `trusted_proxies`
both see the real client, not the proxy). It answers *where from*, which the trail previously could
not: `actor` said who, but nothing said which host pulled a bulk PHI export. `NULL` means **no client
was in scope** — an engine-internal/background/`system` write — never "unknown" and never a value
inherited from another caller. It is surfaced on `GET /audit` and in the `audit:export` CSV.

> Do **not** attribute an action by joining to `sessions.client` instead. That address is captured at
> **login**, so on a **replayed token** it names the original victim's host — actively misleading
> rather than merely lossy. `audit_log.client` is the per-action address and is the one to trust.

**Tamper-evidence (AUDIT-INTEGRITY).** Each `audit_log` row carries a `row_hash` that chains the
previous row's hash with this row's content (SHA-256), so deleting, editing, or reordering any row is
detectable. Verify the chain with `messagefoundry audit-verify` — exit 0 means at least that no
surviving row was edited or reordered. It does **not** mean nothing was removed: deleting the *newest*
rows leaves a prefix that still chains cleanly, so a bare verify is clean after a tail-truncation. For
that, snapshot `messagefoundry audit-anchor` (`COUNT:HEAD`) and pass it back as `messagefoundry
audit-verify --expected-anchor`. It is an exact point-in-time seal, which fixes what it is for: it
seals a chain **at rest across a gap** — quiesce the engine, anchor, hold the value off-box, re-verify
while the chain is still quiesced (a maintenance window, a DB move, a backup/restore, a custodian
hand-off). Anchoring and re-verifying in one breath compares a value to itself, and a held anchor
re-checked against a **running** engine alarms on every boot, because a running engine writes audit
rows; for continuous coverage the off-box tee is still the control ([BACKLOG #328](BACKLOG.md); the
`[retention].audit_days` row in [`CONFIGURATION.md`](CONFIGURATION.md) is the source of record). Rows
written
before the feature are chained on first start. The `client` address is folded **inside** the chained
payload — deliberately, since attribution an attacker could rewrite without breaking tamper-evidence
would be worse than none — as a **conditional trailing element**, appended only when non-`NULL`. A
row with no client therefore hashes exactly as it did before the column existed, so legacy rows keep
verifying byte-identically and one chain spans both formats across the upgrade. This is in-DB tamper-*evidence*, not prevention —
restrict the store/file ACL (and run least-privilege; see [SERVICE.md](SERVICE.md)) so the log can't
be rewritten in the first place.

**Off-box forwarding (sec-offbox-log; ADR 0080).** The hash chain detects on-host tampering but lives on
the same host as the data it protects; if that host is compromised, local evidence can be tampered with.
The **general log** can therefore be shipped **off-box** to a syslog/SIEM collector
(`[logging].forward_host` + `_port`/`_protocol`/`_format`; structured JSON via `[logging].format = "json"`),
so an independent copy survives a host compromise. The same PHI-redaction + control-char-scrub filters apply
to the forwarded stream as to stdout (see [PHI.md §7](PHI.md#7-logging--phi-redaction)).

- **Default-on-when-configured (ADR 0080).** `forward_enabled` is unset by default and *derived* from whether
  a collector is named: pointing `forward_host` at a SIEM turns forwarding **on**, `forward_enabled = false`
  is the explicit opt-out, and with no `forward_host` forwarding stays **off** (byte-identical stdout-only
  startup). So an operator who configures a collector can't silently forget the enable flag.
- **Native TLS transport (`forward_protocol = "tls"`; RFC 5425, ADR 0080).** The hop can be encrypted
  **without a local agent** — an `ssl`-wrapped TCP socket. The collector's certificate is verified against an
  explicit PEM trust anchor (`forward_tls_ca_file`; **only** that CA is trusted, not the system bundle) with
  hostname checking on by default; `forward_tls_verify = false` is the documented insecure opt-out and
  `forward_tls_client_cert` adds mutual TLS. The handshake is bounded by the same socket timeout as a plain
  TCP send, so a stalled/mis-certified collector can't block the engine (it's skipped at startup with a loud
  warning). `udp`/`tcp` remain available — terminate TLS at a local forwarding agent instead if you prefer,
  or keep plaintext on a trusted management network.

The **`audit_log`** rows *themselves* are **also** forwarded off-box (sec-offbox-log #361/#363): every
committed audit row ships as PHI-redacted metadata through the `messagefoundry.audit` logger to the same
forwarder — so it inherits the TLS transport automatically — across all three store backends, so both the
operational log and the tamper-evident audit trail survive a host/DB compromise.

**Clock-sync gate (ASVS 16.2.2; ADR 0080).** Cross-host log/audit correlation assumes the engine host's
clock tracks a reference. `[logging].require_time_sync` + `ntp_peer` arms an **opt-in**, fully-bounded SNTP
probe at startup (before listeners begin): it **warns loudly** when the local clock skews past
`time_sync_max_skew_seconds` (default 2 s) or the peer is unreachable, and with `time_sync_fail_closed`
it **refuses to start** instead. It is opt-in rather than default-on because the engine cannot verify
synchronization without an operator-chosen peer; the default is a no-op.

### Outbound TLS trust anchor — pinned internal CA (`[tls]`, #190, ADR 0093)

An outbound connector that verifies a downstream **server** certificate (MLLP/DICOM-SCU/FTPS) anchors
trust in the **OS trust store** by default. A hospital estate whose internal endpoints present certs
from a **private / internal CA** not in the box-global store can pin that CA once via the small opt-in
`[tls]` section rather than installing it box-wide or repeating a per-connection `tls_ca_file`:

- `[tls].internal_ca_file` — a PEM **path** (NOT a secret) to the org internal CA.
- `[tls].trust_anchor_mode` — `system` (default; OS trust store only — **byte-identical**, the internal
  CA is ignored), `augment` (OS roots **plus** the internal CA — a mixed public + private estate), or
  `pinned` (**only** the internal CA, not the public bundle — a fully-private estate; the same
  single-anchor posture as the off-box syslog `forward_tls_ca_file`).

A connection that names its **own** `tls_ca_file` always **wins verbatim**; a loopback (on-box) hop is
exempt (it needs no org-PKI anchor). The anchor **supplies which roots verify the peer** — it **never
disables verification** — so it composes with, and never weakens, the existing fail-closed refusals: a
`tls_verify=false` hop is still refused (an internal CA cannot silence it), and a plaintext hop is still
governed by the posture-keyed cleartext refusal (ADR 0092). It is **not** applied to the API server
context (`build_api_ssl_context`), which verifies **client** certs for opt-in mTLS (ADR 0083) — a
different trust role. With no `[tls]` block the built SSL context is byte-identical to before.

### PHI data-plane integrity residuals — scope-outs (#190, ADR 0093)

BACKLOG #190 bundled three integrity residuals; #190 closes with **one built** and **two scoped out**:

- **Detached-JWS message signing — shipped (ADR 0018), scoped out.** A detached RFC 7515 JWS over the
  exact outbound body is already built (`transports/signing.py`, opt-in per REST/SOAP outbound). #190's
  ask was a *runbook decision* (does the exposure runbook mandate it), not new engine code. Every
  PHI-plane surface already carries integrity: outbound bodies (ADR 0018), the audit trail (the HMAC
  hash-chain), and data at rest (AES-256-GCM AEAD).
- **ECH (Encrypted Client Hello) for outbound SNI — buildable, deliberately not owned; accepted
  residual (12.1.5).** The destination hostname is visible in the outbound TLS ClientHello. CPython's
  stdlib `ssl` cannot hide it — ECH is an **OpenSSL 4.0** feature and the bundled OpenSSL 3.5.x
  exports no ECH symbols (CPython PR #135435 is still open) — but it **is** buildable off-stdlib (Go
  `crypto/tls`, rustls, sing-box), and one such terminating re-originator was written here and proven
  against a real ECH endpoint. So "infeasible" is **not** the reason and must not be offered as one.
  The reason is that it would hide nothing: a 2026-07-20 DoH probe found **no** partner endpoint
  publishing an `ECHConfig`. The engine therefore ships only the opt-in, fail-closed **routing** half
  (per-connection `ech_egress` / `ech_sidecar`, refused when the sidecar is non-loopback or paired
  with `proxy_url`), and the re-originator was retired from the tree on 2026-08-10 rather than carried
  as a second language nothing builds, tests or pins. Evidence, the retrieval SHA and the re-score
  trigger: [ADR 0139](adr/0139-ech-egress-sidecar-sni-hiding-for-asvs-12-1-5-demand-gated.md);
  operator contract: [`samples/ech-sidecar/`](../samples/ech-sidecar/README.md). The residual is
  metadata only — which partner, how often — with at least these compensating conditions: on-prem, a
  trusted network segment, an operator-configured `[egress]`-allowlisted destination, and TLS still
  protecting the payload. Re-open when a destination begins publishing an `ECHConfig`, or when CPython
  ships a first-class ECH API.

### In-use memory protection — best-effort partial + deployment requirement (13.3.3 / 11.7.1 / 11.7.2, #198)

The store cipher holds an unwrapped 32-byte DEK and transient plaintext PHI in process heap while it
runs bulk AES-256-GCM. #198 closes the **application-code-feasible** half and accepts the rest:

- **Built (best-effort partial).** Every key/plaintext buffer the cipher owns as a *mutable* `bytearray`
  — the unwrapped DEK, retired decrypt-only keys, and the `encrypt`/`decrypt` plaintext buffers — is
  best-effort `mlock`/`VirtualLock`-pinned (not paged to swap) and `memset`-zeroized the moment the AEAD
  has copied it ([store/crypto.py](../messagefoundry/store/crypto.py): `_lock_memory`/`_secure_zero`/
  `_install_key`). Both are fail-safe — a lock or wipe failure is swallowed, never raising, logging, or
  corrupting — and `mfenc:v1` ciphertext stays byte-identical. This is a **documented partial of ASVS
  13.3.3, not a full close.**
- **Accepted residual (application layer).** CPython **immutable** `str`/`bytes` have no wipe hook, so
  the caller plaintext, the returned marker (ciphertext-only), `cryptography`'s `decrypt()` output, the
  transient `bytes(dek)` copies its constructors consume, and **OpenSSL's internal `EVP` key copy** are
  **unreachable** to scrub. This residual is signed off in
  ASVS-L3-RISK-ACCEPTANCE-REGISTER.md theme 5 (owner as
  system + security owner), not hidden.
- **Deployment requirement (11.7.1).** Full in-use memory *encryption* (Intel TME/SGX/TDX, AMD SEV,
  confidential VMs) is a **host/hypervisor capability no pure-Python application library can provide**.
  It is carried as a **stated deployment requirement** — disabled/encrypted swap, restricted local
  admin, and a confidential-compute host where memory forensics is in scope (see
  [PHI.md §10](PHI.md#10-secure-deployment--operations-checklist)) — accepted via the same register
  entry rather than enforced by the engine. 11.7.2's encrypt-after-use guarantee is active only on a
  keyed instance (a key must be configured), which is already the case for any PHI-bearing deployment.

### HIPAA §164.312 alignment

- **Unique user identification** (required) — every user is a distinct account; no shared logins.
- **Person/entity authentication** (required) — local argon2id and/or AD bind; lockout on brute force.
- **Audit controls** (required) — durable, user-attributed audit trail (append-only via the store API).
- **Automatic logoff** (addressable) — idle + absolute session timeouts.
- **Emergency access** (required) — **not applicable to this component.** Break-glass exists so a
  clinician can reach a *patient's record* when normal authorisation would refuse it. This engine
  holds no point-of-care record: it routes and transforms messages in transit, and the record of
  authority lives in the systems on either side, which is where an emergency-access path belongs.
  The bootstrap admin is **not** a break-glass mechanism and is not a compliance control — it seeds
  the first real administrator and then self-retires (see *Auto-retirement (WP-3)* above).

---

## Web console sign-in

The browser web console (`/ui`) shows a sign-in form (Local / Active Directory) when the engine
requires auth, holds the token in the browser session, gates UI actions by permission, exposes a
**Users** admin page to `users:manage` holders, and offers **Sign out** (clears the session). The
former PySide6 desktop console was retired (BACKLOG #103).

---

## Configuration

All knobs live in the `[auth]` section of `messagefoundry.toml` (the AD bind password comes from
`MEFOR_AUTH_AD_BIND_PASSWORD`, never the file). See [CONFIGURATION.md](CONFIGURATION.md).

## Supply-chain & CI security

Automated security scanning runs in CI (`.github/workflows/security.yml`), so it lives there
rather than in the per-author `messagefoundry check` gate:

- **pip-audit** — audits the **committed lockfile** (`requirements.lock`) for known-CVE dependencies,
  so the audit is reproducible rather than auditing a fresh latest-resolve (advisory for now).
- **bandit** — Python SAST over `messagefoundry/` (advisory).
- **Dependabot** (`.github/dependabot.yml`) — weekly PRs for `pip` and `github-actions` updates.
- A private vulnerability-disclosure policy lives at [`.github/SECURITY.md`](../.github/SECURITY.md).

Enable via **GitHub Advanced Security** in repo settings (they need GHAS on a private repo, so they
can't be added by file alone): **CodeQL** code scanning and **secret scanning** + push protection.

**Planned CI additions:**

- **SBOM** — generate a CycloneDX SBOM (e.g. `cyclonedx-py`) from the committed lockfile in CI and keep it
  as a build artifact, so "are we exposed to CVE-X?" is answerable from a recorded bill of materials rather
  than a fresh resolve.
- **Secret-history scan** — a `gitleaks` (or trufflehog) job over the **full git history** in CI, to
  complement GHAS secret scanning above. Kept in CI rather than a per-author pre-commit hook, to match the
  pip-audit/bandit stance (one enforced gate, not optional local tooling).

### Dependency lockfile (DEP-1)

`pyproject.toml` carries lower-bound (`>=`) ranges; the **pinned, hashed** resolution lives in
**`uv.lock`** (the source of truth) and its exported view **`requirements.lock`** (cross-platform,
with per-package hashes), both committed. CI verifies they're in sync (`uv lock --check` + an export
`diff`) and audits `requirements.lock`. Refresh after any dependency change:

```
uv lock                                                              # update uv.lock from pyproject
uv export --all-extras --no-emit-project --format requirements.txt -o requirements.lock
```

For a fully reproducible, tamper-resistant install, `pip install --require-hashes -r requirements.lock`
(the SQL Server extra also needs the OS-level Microsoft ODBC Driver 18, which isn't pip-installable).
Before installing the engine wheel itself, **verify its release provenance** (`gh attestation verify`
SLSA + the Sigstore identity check) per [INSTALL-GUIDE.md](INSTALL-GUIDE.md#verify-the-release-before-you-install-supply-chain-integrity)
— hash-pinning proves bytes-match-lockfile, not who built the artifact.

### Nothing on the server refuses a push by content, so the private-docs guard is client-side and bypassable

Do not rely on the push guard. It is the only thing that can refuse a push carrying the
maintainer-internal `docs/security/` corpus to this public remote. It runs on the client,
`git push --no-verify` skips it, and a fresh clone does not have it at all. The owner accepted that
posture on 2026-09-03 (BACKLOG #1056). It is recorded here so that no later document describes the
arrangement as stronger than it is.

**GitHub offers this repository no content-based push control.** That was measured on 2026-08-05,
not inferred. A `file_path_restriction` push ruleset for `docs/security/**` is refused:

```
gh api -X POST repos/MEFORORG/MessageFoundry/rulesets -f name='block-private-docs' \
  -f target='push' -f enforcement='active' \
  -f 'rules[][type]=file_path_restriction' \
  -f 'rules[][parameters][restricted_file_paths][]=docs/security/**'
-> 422  "Source public repos cannot have push rules"
```

`enforce_admins` is not a substitute, whether or not it is enabled. It governs protected branches, so
it never sees an ordinary feature branch, and a feature branch is the ref a leak rides on. It is a
separate control with its own merits, and it does not answer this question. Read branch protection
directly if you need its current state; this document does not track it.

**What stands, and where each layer stops.** Read this as a floor rather than a full list. At least
these limits hold, and a reader should assume there are others:

- **Prevention runs on the client only.** `scripts/hooks/push_guard.py` refuses a pushed tip tree
  that carries `docs/security`, on every ref it is offered, branches and tags alike. A clone or
  worktree where `scripts/coord/install-git-hooks.ps1` has never run does not have it. It reads the
  tip tree, so it is not a history check, and it matches paths, not content. Its own module
  docstring lists the ways it is skipped or fails open. A client hook is advisory by construction:
  treat it as a way to catch your own mistake, never as a boundary.
- **Commit-time coverage is partial.** `scripts/security/scan_forbidden.py` refuses a *staged* file
  under `docs/security`. It does not see the vector that matters, where those files arrive inside a
  commit **tree** taken from another ref and never pass through the index.
- **Detection runs after the push.** `.github/workflows/branch-leak-scan.yml` scans every branch
  push. It exists because the `forbidden-content` job in `security.yml` triggers on pull requests,
  pushes to `main`, and a daily cron, so a branch pushed with no pull request is scanned by none of
  them. On a public repository the content is public the instant the push completes, so this layer
  reports a leak and cannot prevent one.

**What to do with this.** If you keep the private corpus beside this checkout, run
`scripts/coord/install-git-hooks.ps1` in every clone and worktree, and never reach for `--no-verify`
here. If you are assessing the repository, score the arrangement as detection with a client-side
aid, not as prevention. A leak is found by a scan minutes later, by which time the content is
already public, so the response is deleting the ref and assessing exposure, which limits reach
rather than undoing publication.

## Not yet built (deliberate follow-ups)

The remaining `code:edit` / `config:validate` / `service:configure` endpoints those permissions will
gate. (**OIDC federation is now built** — see "Federated sign-in" under *Local vs Active Directory* — and **custom roles shipped**
in 0.2.10; both were listed here after the fact.) **Transport TLS is built** — API/WS (WP-13a), the reverse-proxy / forwarded-header path (WP-15), and MLLP-over-TLS (WP-13b, per-connection `tls`/`tls_*`), per [ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md) (*Accepted*). The §0 **exposed-gate is enforced** — a non-loopback *plaintext* API or MLLP bind is refused at startup unless `serve --allow-insecure-bind`. ADR-0002 **MFA (WP-14) is now built** — native TOTP for local accounts (see "Multi-factor authentication" above); AD/Kerberos MFA is delegated to the directory. The **DICOM C-STORE SCP inbound** (ADR 0025 Phase 1) carries the same posture: it accepts only allowlisted calling AE titles + peer IPs, supports **DICOM-over-TLS**, and a non-loopback bind is refused unless explicitly overridden. **Outbound egress auth** for the FHIR/REST connector is built as a **SMART Backend Services token provider** (ADR 0024) — OAuth2 `client_credentials` with a signed-JWT (RS384/ES384) client assertion (extending the ADR 0018 signing core, no new dependency), opted in per connection via `with_smart_backend()`; it mints a per-request bearer and re-mints on `401`, and the token endpoint is gated by `[egress].allowed_http`. It is **client-only** — no App Launch flow and no authorization-server facade. **SMART trust boundary (BACKLOG #204, ASVS 10.4.16):** the engine *presents* a `private_key_jwt` client assertion (RFC 7523) to the token endpoint, but *enforcing* that method — validating the assertion signature/audience/expiry, refusing a weaker `client_secret_post`/`client_secret_basic` for this client, and replay-protecting the `jti` — is the **authorization server's responsibility**, a boundary the client engine does not and cannot police. MessageFoundry assumes an AS that mandates private_key_jwt for Backend Services clients; an AS that *also* accepts a weaker authentication method is an AS-side misconfiguration, not a client-engine defect. (Encryption at rest, audit hash-chaining,
**per-channel RBAC** — including the web console scope editor and AD-group→scope mapping — and the
**committed dependency lockfile** are now built; see [PHI.md §3](PHI.md#3-encryption-at-rest),
*Audit*, the per-channel-scoping note, and *Dependency lockfile (DEP-1)* above.)
