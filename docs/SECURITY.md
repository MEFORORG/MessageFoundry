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
auth layer (`[auth] enabled = true` by default), so all API routes except `GET /health` demand a valid
bearer token, and each route additionally demands a specific **permission**.

The in-process embedding factory `create_app(engine)` is **fail-closed**: with no `AuthService`
attached it denies every protected route (503) unless the caller explicitly opts out with
`create_app(..., allow_no_auth=True)` — the deliberate embedding/local-dev escape hatch. The `serve`
path runs auth-enabled by default; if `[auth] enabled = false` it sets that opt-in itself, and
`__main__` refuses to serve auth-off on a non-loopback host — and, even with auth enabled, a
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
self-retires while still **unclaimed** (never password-changed): it is **disabled once a second
administrator exists**, and — if left unclaimed — **disabled `[auth].bootstrap_expiry_hours` after
creation** (default 72 h; `0` disables the timer). Once you change its password it becomes a normal
admin account and is never auto-disabled, so a single-admin deployment can't be locked out. A retired
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

**Anti-automation (ASVS 2.4.2).** A per-actor/per-operation human-timing *pacing floor* on sensitive
authenticated writes is **deliberately not implemented** for the default deployment: the API binds
`127.0.0.1`, every sensitive write is RBAC-gated to an authenticated operator, and the unauthenticated
brute-force surface is already bounded by the sliding-window rate limiter (`auth/ratelimit.py`) plus
the per-actor PHI-read throttle. Machine-speed abuse of an authenticated admin endpoint is not material
in the single-tenant, on-loopback, desktop-console model; a pacing floor would be revisited only if a
sensitive write is exposed off-loopback (alongside the ADR 0002 transport work).

---

## Roles & permissions

Roles are a **fixed built-in set** (no custom-role builder yet). Each maps to permissions from this
catalog; holding multiple roles grants the **union** of their permissions (deny-by-default otherwise).

| Role | Permissions |
|---|---|
| **Administrator** | everything (incl. `users:manage`, `audit:read`) |
| **Operator** | `monitoring:read`, `monitoring:diagnose`, `messages:read`, `messages:view_summary`, `messages:view_raw`, `messages:replay`, `messages:purge`, `connections:control`, `connections:test` |
| **Deployment** | `monitoring:read`, `config:deploy`, `config:validate`, `connections:test` |
| **Coding** | `monitoring:read`, `code:edit`, `config:validate`, `ai:assist` |
| **Viewer** | `monitoring:read`, `messages:read` |
| **Auditor** | `monitoring:read`, `audit:read` |

Permission catalog: `monitoring:read`, `monitoring:diagnose`, `messages:read`,
`messages:view_summary` (PHI), `messages:view_raw` (PHI), `messages:replay`, `messages:purge`,
`connections:control`, `connections:test`, `config:deploy`, `config:validate`*, `code:edit`*,
`service:configure`*, `ai:assist`, `users:read`, `users:manage`, `audit:read`, `approvals:approve`.

\* `config:validate`, `code:edit`, and `service:configure` have no API endpoint yet; the permissions
are defined so the Deployment/Coding roles are complete and those endpoints can be gated the moment
they land. (`config:deploy` already gates `POST /config/reload`.)

> **AI coding assistance is RBAC-gated and centrally policy-governed.** `ai:assist` (held by
> **Coding** and **Administrator**) controls whether an identity may use the IDE AI assistant; the
> assistant is additionally bounded by an environment-clamped, central **policy** (`mode` from
> OFF→PHI-safe, `data_scope`, `environment`) read via `GET /ai/policy` — see [AI.md](AI.md). That
> endpoint is intentionally **unauthenticated** (the install policy is non-sensitive operational
> config that a central *off* must be able to enforce on a tokenless client); the identity-dependent
> bit rides in its `assist_permitted` field, and policy reads are **not** audited in the MVP.
> Per-*use* egress auditing arrives with the future engine broker.

### Route → permission map (engine API)

| Endpoint(s) | Permission |
|---|---|
| `GET /health` | none (liveness) |
| `GET /channels`, `/connections`, `/status`, `/stats`, `ws /ws/stats` | `monitoring:read` |
| `POST /status/integrity-check` | `monitoring:diagnose` |
| `GET /messages` | `messages:read`; `messages:view_summary` unlocks the `summary`/`error` fields (per-property — see *Field-level authorization*) |
| `GET /messages/{id}` | `messages:view_raw` (the raw body); `messages:view_summary` unlocks `summary`/`error` and the nested `last_error`/event `detail` (per-property — see *Field-level authorization*) |
| `GET /messages/{id}/responses` | `messages:read`; `messages:view_summary` unlocks the captured-reply `detail`, `messages:view_raw` the reply `body` (per-property) |
| `POST /messages/{id}/replay` | `messages:replay` |
| `GET /dead-letters` | `messages:read`; `messages:view_summary` unlocks the `summary`/`last_error` fields (per-property — see *Field-level authorization*) |
| `POST /dead-letters/replay` | `messages:replay` |
| `POST /connections/{name}/{start,stop,restart}` | `connections:control` |
| `GET /connections/{name}/metadata` | `monitoring:read` (per-channel for inbound; a shared outbound is barred to scoped users) |
| `POST /connections/{name}/test` | `connections:test` (reachability probe — builds a fresh connector, honors `[egress]`, sends no real data, audited; per-channel for inbound, a shared outbound barred to scoped users) |
| `POST /connections/{name}/purge` | `messages:purge` |
| `POST /config/reload` | `config:deploy` |
| `GET`/`PUT /users/{id}/channel-scope` | `users:manage` (per-channel RBAC) |
| `GET`/`PUT /ad-group-scope-map` | `users:manage` (AD-group→channel scope) |
| `GET /approvals`, `POST /approvals/{id}/approve`, `POST /approvals/{id}/reject` | `approvals:approve` (dual-control release/decline — see below) |

> **Per-channel scoping (DLQ-SCOPE).** Operational permissions can be confined to a set of
> connections per user via `users.channel_scope` (`PUT /users/{id}/channel-scope`; `null` = all,
> the default). When a user is scoped, `messages:read/view_raw/replay`, dead-letter list/replay, and
> `connections:control` are restricted to their channels (out-of-scope message access returns 404 to
> avoid leaking existence; connection control returns 403; denials are audited `auth.channel_denied`).
> **Administrators are always all-channels.** Monitoring dashboards stay global. A channel-scoped user
> **cannot purge** a shared outbound (purge spans every inbound feeding it). **AD users** inherit their
> scope from the `ad_group_scope_map` (`GET/PUT /ad-group-scope-map`; channel `*` = all): on login the
> group-derived scope is persisted and stale sessions revoked. It's opt-in — with no matching mapped
> group, the user's existing scope (all by default) is left untouched.

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
flows — **bulk dead-letter replay** and **connection purge**. (The console's `QMessageBox` "are you
sure?" prompts are **client-side only** and bypassable via the raw API — they are *not* a second approver
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

**Gated operations** (all `users:manage` admin flows + the replay/purge/config flows):
create / delete user, set roles, set channel scope, admin session-revoke, admin reset-password, AD-group
role/scope maps, dead-letter replay, single-message replay, connection purge, and config reload/deploy.
Reads (listing users, maps, the audit log) are **not** gated.

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
`[auth].require_mfa` on, the **Administrator** role must satisfy MFA before any step-up operation (the gate
returns `403` + `X-MFA-Required` until verified); other users may opt in by enrolling. **AD/Kerberos MFA is
delegated to the directory** (Entra Conditional Access / an MFA proxy) — a directory login is never
prompted for an engine TOTP and is MFA-satisfied at issuance. The TOTP secret is stored **encrypted at
rest** (the store cipher) and recovery codes are **argon2id-hashed**; verification uses the server clock and
a constant-time compare with a ±1-step window. TOTP is a shared-secret factor — L3 *prefers*
phishing-resistant factors: **WebAuthn passkeys are the built WP-14b sibling** (next section), and TOTP
stays fully supported alongside them (it remains the desktop console's second factor).

### WebAuthn passkeys (WP-14b, ADR 0068)

Local accounts can also enroll **WebAuthn/FIDO2 passkeys** as a phishing-resistant second factor at the
**same step-up boundary** — browser-only ceremonies on the `/ui` console (requires the optional
**`[webauthn]` extra**; the PySide6 console has no `navigator.credentials`, so keep TOTP enrolled for
desktop step-up). The browser step-up stays **two-credential**: the passkey assertion satisfies the
session's **MFA leg only**, and the mandatory password leg of `POST /ui/reauth` still stamps step-up
freshness and re-anchors the session's client IP (WP-L3-13) — so a passkey never silently relaxes the
password re-proof. Enrollment (`POST /ui/account/webauthn/enroll`) sits behind the **password-only
re-proof** (WP-14: a stolen pre-MFA cookie can never bind an attacker's passkey); removal sits behind the
full step-up, and removing the **last remaining second factor while MFA is required is refused**
("enroll another factor first"). `POST /users/{id}/reset-mfa` clears passkeys alongside TOTP — the
always-available recovery, because passkeys mint **no recovery codes by design** (codes are phishable
knowledge secrets that would undercut the phishing-resistant tier; enroll a second passkey or keep TOTP).

Mechanics: ceremony challenges are **first-party 64-byte CSPRNG values**, single-use, 120 s TTL, staged
in a bounded process-local cache (multi-node LBs need session affinity — the failure message says so);
COSE **public keys are stored plaintext by design** (verification material, not secrets — deliberately
outside the store cipher, documented in the crypto inventory); the authenticator **sign counter is
updated via a strict compare-and-set** — a regression or a concurrent same-counter assertion is treated
as a **clone signal** (rejected + audited `auth.webauthn_clone_suspected`; a permanent counter of 0 is
normal for synced passkeys). Assertion failures are audited but deliberately do **not** feed the
account lockout (signatures aren't guessable secrets; abuse is bounded by the login rate limiter and
cookie-holder-only reachability). The RP identity (`rp_id`/origin) rides **`[api].public_origin`** when
set; on a plain loopback deployment it derives from the request URL, and behind a **declared reverse
proxy it fails closed** until `public_origin` is configured (anchoring the RP to a proxy-forwardable
Host header would defeat the origin binding that makes WebAuthn phishing-resistant). Credentials are
pinned to their mint-time `rp_id` — **changing `public_origin`'s host renders enrolled passkeys visibly
"unusable (origin changed)"** (re-enroll after an origin migration). AD/Kerberos users are excluded
exactly as with TOTP (directory-delegated MFA).

### Off-loopback browser console (L5b, ADR 0068 §8)

Exposing `/ui` off-box is a supported, **gated** posture. Beyond the existing TLS-or-refuse exposure
gate (refused even under `--allow-insecure-bind`), `serve` now runs the **L5b exposure ladder**:
with a **declared reverse proxy** (`tls_terminated_upstream`), `serve_ui` **refuses to start without
`[api].public_origin`** (behind a proxy the Host header is client-forwardable — the exact origin
anchors the same-origin CSRF check and the WebAuthn rp_id); an `http://` `public_origin` is refused
under any declared TLS posture; a set `public_origin` on an *undeclared* posture warns loudly (the
cookie would ship without `Secure`); and an exposed console emits the ASVS 8.4.2 pointer to
[`OFF-LOOPBACK-DEPLOYMENT.md`](security/OFF-LOOPBACK-DEPLOYMENT.md) (managed-admin-host runbook +
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

`require_mfa` defaults **off** (the loopback shipping posture is byte-for-byte unchanged), but it is not
left purely to a runbook at exposure: when the API is bound **off-loopback** with `require_mfa` off,
`serve` makes the posture explicit at startup — it **refuses to start** on a **production PHI** instance
and **warns** on a non-production PHI instance (a synthetic instance stays quiet), mirroring the
keyless-store and open-egress startup gates. So an exposed PHI deployment can't silently run the
Administrator interface single-factor. `require_mfa` is safe to enable even on an **AD-only** deployment —
it gates only **local** Administrator accounts (AD/Kerberos MFA stays delegated to the directory), so the
remediation is always simply to set `[auth].require_mfa=true` (or keep the bind on loopback).

### Administrative-interface defense-in-depth (WP-L3-13, ASVS 8.4.2)

The administrative interface is defended by **multiple independent layers**, not network-location trust
alone:

1. **Network-location / exposed-gate** — the API binds `127.0.0.1` by default, and a non-loopback
   *plaintext* bind is refused at startup unless `serve --allow-insecure-bind` (ADR 0002 §0). One layer,
   not the sole factor.
2. **Deny-by-default per-route RBAC** — every admin route asserts an explicit permission over an opaque
   Bearer token; a denial is audited (`require()`, ASVS 8.2.x).
3. **Step-up re-verification** within a short window on every sensitive admin route (`require_step_up`,
   above; ASVS 7.5.3).
4. **A genuine second authentication factor** at that step-up boundary — native TOTP MFA (WP-14), so an
   MFA-enrolled/required admin presents a TOTP/recovery code, not a re-prompt of the same password.
5. **A contextual-risk signal** — when `[auth].admin_new_ip_step_up` is on, a sensitive admin action
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
control, consistent with the on-prem desktop-console model — Python's stdlib `ssl` performs no in-process
device attestation. This is the documented residual for 8.4.2's device-posture clause.

### Field-level (property) authorization (WP-9)

Beyond gating whole *endpoints*, the API gates individual **PHI-bearing properties** within a response,
so a caller can see an object without seeing its patient-identifying fields. The policy is declared in
one place — [`api/field_authz.py`](../messagefoundry/api/field_authz.py) — and enforced by a single
`redact_unauthorized()` helper applied to every returned row, rather than re-implemented inline per
endpoint (where a new endpoint or field could silently leak PHI — the BOPLA risk, ASVS 8.1.2 / 8.2.3).

| Response property | Carries | Unlocked by |
|---|---|---|
| `summary` (message / dead-letter / detail rows) | patient identifiers (MRN / name / order) | `messages:view_summary` |
| `error` / `last_error`, event `detail`, captured-response `detail` | exception / disposition text that can quote field values | `messages:view_summary` |
| `raw` (single-message body), captured-response `body` | the full message / reply | `messages:view_raw` (whole-body gate, at the endpoint) |

A caller lacking `messages:view_summary` receives those properties as `null`; everything returned
non-null is audited server-side (coalesced per actor/hour), so a scripted bulk read can't harvest the
patient census unaudited. The body (`raw`) is the coarser whole-object gate and stays at the endpoint.

The same logical disposition text gates on `messages:view_summary` on **every** surface that returns it —
the `GET /messages` and `GET /dead-letters` lists, the single-message detail `GET /messages/{id}` (where
the `MessageDetail` wrapper **and** each nested `OutboxInfo` / `EventInfo` are redacted individually,
because the redactor keys on the exact model type, not the MRO), and the captured replies
`GET /messages/{id}/responses` (#120). **`messages:view_raw` is not a superset of `messages:view_summary`** —
they are independent permission flags (`Identity.has()` is a flat membership check). The built-in roles
*happen* to grant them nested (`messages:read` ⊆ `…:view_summary` ⊆ `…:view_raw` — a **role-policy**
convention, not a permission-model guarantee), so the **Viewer** role sees metadata only; the disposition
fields are gated on `view_summary` (not the route's `view_raw`) deliberately, so a future custom role
holding `view_raw` without `view_summary` still cannot reach exception text. Adding a new PHI-bearing
response property means adding a row to `PHI_FIELDS` — a test asserts the map's properties exist and match
the expected set, so the gate can't be forgotten silently.

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
a coarse, separately permission-gated action (`messages:replay` / `messages:purge` / `config:deploy` /
`connections:control`), not a per-field write. So there is no per-property *write* authorization surface
today. **Trigger to revisit:** the first endpoint that lets a client write a PHI property (e.g. an
edit/annotation API) — at which point add a writable-property→permission whitelist to `field_authz`
alongside the read map.

---

## Local vs Active Directory

Both kinds of user share one identity model (`users.auth_provider` is `local` or `ad`).

- **Local users** authenticate with an argon2id-hashed password and are assigned roles explicitly
  (`PUT /users/{id}/roles` or the console Users page).
- **AD users** authenticate by LDAP simple-bind over **LDAPS**. The engine binds with a service
  account to find the user, binds as the user to verify the password, then resolves group membership
  (including **nested** groups via `LDAP_MATCHING_RULE_IN_CHAIN`). Their roles are **re-synced from
  AD groups on every login** through the **AD-group→role map**, so manual role assignment doesn't
  apply to AD users.
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

An admin sets which AD groups govern which role via `GET/PUT /ad-group-map` (or the console). Group
identifiers are matched case-insensitively and may be either the group **DN** or its
**sAMAccountName**. A user in multiple mapped groups gets the union of those roles.

```
CN=MF-Admins,OU=Groups,DC=example,DC=com  ->  administrator
CN=MF-Ops,OU=Groups,DC=example,DC=com     ->  operator
```

---

## Sessions

Sessions are **opaque server-side tokens** (not JWT): the client holds the token, the store keeps only
its SHA-256, so logout/expiry/role changes take effect immediately. Each request enforces an **idle
timeout** (default 30 min) and an **absolute lifetime** (default 12 h); changing a password,
disabling a user, or an **AD-group/role change on re-login** revokes that user's sessions. Session
validation **fails closed on a backward wall-clock step** (NTP step-back / VM snapshot revert) rather
than reviving an expired token, and the idle clock is only refreshed by **user-driven** requests — a
background keepalive (the stats WebSocket re-checks itself, and is capped/short-lived) does not keep a
session alive. `[auth].max_sessions_per_user` caps concurrent sessions (default **5**; a login beyond
the cap revokes the user's oldest — ASVS 7.1.2; `0` = unlimited). The console stores the token in the OS keyring (Windows Credential Manager) and sends it as
`Authorization: Bearer <token>` (the WebSocket prefers the header; the legacy `?token=` query param is
deprecated because it leaks into proxy/access logs). The keyring item is a **PHI-scoped** credential
(the user's full RBAC for the session lifetime); the console re-validates it against `/auth/me` on
startup (discarding a stale/revoked one) and **refuses to send credentials over plaintext `http` to a
non-loopback host** (no TLS yet) unless explicitly run with `--insecure` for trusted-network dev.

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

Every targeted revoke is audited (`auth.session_revoked`, with scope + actor). The **console** surfaces
this: an **Active sessions…** dialog in the account menu lists your sessions and offers per-session
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

MFA step-up is now built (WP-14 native TOTP); a console banner for the feed remains future work (WS-G).

## Password policy

Local passwords follow an **ASVS 5.0-aligned** policy (WP-3): **min length 15**, **no mandatory
character-class composition** (the `require_*` class flags are opt-in, default off — ASVS forbids
mandatory composition), plus **offline breached/common-password screening** (a bundled top-10k list,
no live HIBP call) and a small **context-word deny-list** (app/vendor/HL7 terms like `messagefoundry`,
`mefor`, `hl7`, `corepoint`). Enforced identically on create-user and change-password; tune via
`[auth]` (see [CONFIGURATION.md](CONFIGURATION.md)). AD passwords are governed by Active Directory.

Two further screens (ASVS 6.2.11 / 6.2.12), both on by default and fully offline:

- **Username-in-password rejection** (`password_check_username`) — a password that *contains* the
  user's own username (case-insensitive, for usernames ≥ 4 chars) is rejected, catching the common
  `jsmith2026`-style choice that the corpus can't.
- **Larger operator breach corpus** (`password_breach_corpus_file`) — point this at an offline list to
  augment the bundled top-10k: a **plaintext** file *or* an **HIBP-style SHA-1-hash export**
  (`HASH[:count]` lines, auto-detected), checked locally with no network call. Use a curated subset
  (it's loaded into memory), not the full ~40 GB HIBP set; a configured-but-unreadable path is warned
  at startup and falls back to the bundled list.

### Authentication pathways — comparative strength

| Pathway | Factor | Brute-force defense | Notes |
|---|---|---|---|
| **Local** (argon2id) | password | **per-account lockout** (5/15 min) + breach/context policy + global rate-limit | the only pathway the engine itself can lock out |
| **AD** (LDAPS simple-bind) | password | the **directory's** lockout/complexity policy (engine has the global rate-limit only) | password strength + lockout are the AD domain's responsibility |
| **Kerberos / SPNEGO** | domain ticket (often MFA-backed) | the **domain's** controls; passwordless on a joined client | experimental, single-leg; no engine-side password |

**Lockout asymmetry (ASVS 6.1.3/6.3.4):** the engine's per-account lockout protects **local** accounts
only. AD/Kerberos brute-force resistance is the directory's job — so for AD-backed deployments, set the
domain lockout/complexity policy accordingly; the engine's global sliding-window rate-limit is the only
engine-side throttle that also covers the AD login path. **Native TOTP MFA is built for local accounts** (WP-14; see "Multi-factor authentication" below); AD/Kerberos MFA is delegated to the directory.

## Brute-force & abuse protection

Beyond per-account lockout, the unauthenticated auth surface (`/auth/login`, `/auth/negotiate`,
`/me/password`) is **rate-limited** by an in-process sliding window — per client IP and globally —
so password-spraying across many usernames (which never trips a single account's lockout) is bounded,
and concurrent argon2 work is **capped** so a login flood can't exhaust the executor. Request bodies
are capped (1 MiB) and auth request fields have length limits.

The **authenticated PHI-read endpoints** (`/messages`, `/messages/{id}`, `/dead-letters`) carry a
**per-actor anti-automation throttle** (ASVS 2.4.1, `[auth].phi_read_rate_limit_*`) — a sliding window
keyed on the acting user, on by default at a generous cap (120 reads/min) that clears normal console
and human use while bounding scripted PHI harvesting. It complements the pagination + the per-access
audit trail on those routes; a throttled read is logged (never silent) and returns `429`.

These are all **in-process** protections; an exposed or multi-host deployment must additionally front
the API with a proxy/WAF limiter and TLS.

**Per-IP limiter caveat (SEC-024).** The per-client-IP login window is in-process and keyed on the
caller's source address, so an attacker who can rotate source addresses creates a fresh empty per-IP
bucket each time and is bounded only by the **global** ceiling. The source IP is already proxy-aware —
uvicorn runs with `forwarded_allow_ips = settings.api.trusted_proxies` (defaults to `[]` = trust
nothing), and an off-loopback proxied bind is gated to require a declared trusted proxy — but an
in-process per-IP limiter inherently cannot stop pure IP rotation by a **directly-reachable** attacker.
The real anti-guessing controls that survive rotation are the **global ceiling** plus the **per-account
argon2 lockout (5 / 15 min)**, which is applied to **both** the password and the MFA second-factor
paths, so guessing of a specific account stays well-bounded. The default `127.0.0.1` bind makes IP
rotation moot; for an off-loopback bind without a fronting WAF, deploy a global limiter / WAF in front
(a modest unconditional global login/second-factor ceiling independent of IP is a backlog follow-up).

## Audit

Every authentication and authorization event is written to the durable `audit_log` with the acting
user: `auth.login_success` / `auth.login_failed` / `auth.login_locked` / `auth.logout` /
`auth.permission_denied` / `auth.channel_denied`, plus `user.created` / `user.roles_changed` /
`user.channel_scope_changed` / `user.deleted`, `ad_group_map.updated` / `ad_group_scope_map.updated`,
and `auth.ad_scope_resynced`. PHI access (viewing a raw message or displaying patient summaries) is recorded
with the viewer. Read the trail via `GET /audit` (`audit:read`). **Credentials, tokens, and PHI bodies
are never logged** (only ids/counts land in `detail`).

**Tamper-evidence (AUDIT-INTEGRITY).** Each `audit_log` row carries a `row_hash` that chains the
previous row's hash with this row's content (SHA-256), so deleting, editing, or reordering any row is
detectable. Verify the chain with `messagefoundry audit-verify` (exit 0 = intact). Rows written
before the feature are chained on first start. This is in-DB tamper-*evidence*, not prevention —
restrict the store/file ACL (and run least-privilege; see [SERVICE.md](SERVICE.md)) so the log can't
be rewritten in the first place.

**Off-box forwarding (sec-offbox-log).** The hash chain detects on-host tampering but lives on the same
host as the data it protects; if that host is compromised, local evidence can be tampered with. The
**general log** can therefore be shipped **off-box** to a syslog/SIEM collector (`[logging].forward_enabled`
+ `forward_host`/`_port`/`_protocol`/`_format`; structured JSON via `[logging].format = "json"`), so an
independent copy survives a host compromise. The same PHI-redaction + control-char-scrub filters apply to
the forwarded stream as to stdout (see [PHI.md §7](PHI.md#7-logging--phi-redaction)); the syslog transport
is plaintext, so terminate it at a local TLS-forwarding agent or keep it on a trusted management network.
The **`audit_log`** rows *themselves* are **also** forwarded off-box (sec-offbox-log #361/#363): every
committed audit row ships as PHI-redacted metadata through the `messagefoundry.audit` logger to the same
forwarder, across all three store backends — so both the operational log and the tamper-evident audit
trail survive a host/DB compromise.

### HIPAA §164.312 alignment

- **Unique user identification** (required) — every user is a distinct account; no shared logins.
- **Person/entity authentication** (required) — local argon2id and/or AD bind; lockout on brute force.
- **Audit controls** (required) — durable, user-attributed audit trail (append-only via the store API).
- **Automatic logoff** (addressable) — idle + absolute session timeouts.
- **Emergency access** (required) — the bootstrap admin provides break-glass; treat its credential as
  a sealed secret.

---

## Console sign-in

`python -m messagefoundry.console` shows a sign-in dialog (Local / Active Directory) when the engine
requires auth, caches the token in the OS keyring, gates UI actions by permission, exposes a **Users**
admin page to `users:manage` holders, and offers **Sign out** (clears the token).

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

## Not yet built (deliberate follow-ups)

Entra ID / OIDC federation, custom roles, and the remaining `code:edit` / `config:validate` /
`service:configure` endpoints those permissions will gate. **Transport TLS is built** — API/WS (WP-13a), the reverse-proxy / forwarded-header path (WP-15), and MLLP-over-TLS (WP-13b, per-connection `tls`/`tls_*`), per [ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md) (*Accepted*). The §0 **exposed-gate is enforced** — a non-loopback *plaintext* API or MLLP bind is refused at startup unless `serve --allow-insecure-bind`. ADR-0002 **MFA (WP-14) is now built** — native TOTP for local accounts (see "Multi-factor authentication" above); AD/Kerberos MFA is delegated to the directory. The **DICOM C-STORE SCP inbound** (ADR 0025 Phase 1) carries the same posture: it accepts only allowlisted calling AE titles + peer IPs, supports **DICOM-over-TLS**, and a non-loopback bind is refused unless explicitly overridden. **Outbound egress auth** for the FHIR/REST connector is built as a **SMART Backend Services token provider** (ADR 0024) — OAuth2 `client_credentials` with a signed-JWT (RS384/ES384) client assertion (extending the ADR 0018 signing core, no new dependency), opted in per connection via `with_smart_backend()`; it mints a per-request bearer and re-mints on `401`, and the token endpoint is gated by `[egress].allowed_http`. It is **client-only** — no App Launch flow and no authorization-server facade. (Encryption at rest, audit hash-chaining,
**per-channel RBAC** — including the console scope editor and AD-group→scope mapping — and the
**committed dependency lockfile** are now built; see [PHI.md §3](PHI.md#3-encryption-at-rest),
*Audit*, the per-channel-scoping note, and *Dependency lockfile (DEP-1)* above.)
