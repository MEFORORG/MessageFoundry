# Users & Security (Authentication + RBAC)

MessageFoundry authenticates every operator and authorizes every action with **role-based access
control (RBAC)**. It supports **local users** and **Active Directory** (LDAP bind + optional Windows
SSO), maps **AD security groups to roles**, and attributes every action to a unique user in the audit
trail. The design meets or exceeds Mirth Connect and Corepoint on the points that matter for a
healthcare interface engine — notably: RBAC is built in (not a paid add-on), password policy ships
with secure defaults, and AD-group→role mapping is automatic.

> Carries PHI. This doc covers **identity, access control, and the audit of operator actions**.
> The protection of the *data* itself — at-rest storage/encryption, transport, logging/redaction,
> retention, and de-identification — lives in [PHI.md](PHI.md).

---

## Enforcement model

Authentication is **required** for the running service. The engine `serve` command always attaches an
auth layer (`[auth] enabled = true` by default), so all API routes except `GET /health` demand a valid
bearer token, and each route additionally demands a specific **permission**.

The in-process embedding factory `create_app(engine)` is **fail-closed**: with no `AuthService`
attached it denies every protected route (503) unless the caller explicitly opts out with
`create_app(..., allow_no_auth=True)` — the deliberate embedding/local-dev escape hatch. The `serve`
path runs auth-enabled by default; if `[auth] enabled = false` it sets that opt-in itself, and
`__main__` refuses to serve auth-off on a non-loopback host — and, even with auth enabled, refuses
any non-loopback bind unless `serve --allow-insecure-bind` is explicitly passed (Phase 1 ships no API
TLS, so an off-loopback bind would put bearer tokens + PHI on the wire in cleartext). So there is no
way to be accidentally served with silent, unauthenticated full access — or to silently void the
loopback assumption with a stray `[api].host` edit (SYS-1).

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

---

## Roles & permissions

Roles are a **fixed built-in set** (no custom-role builder yet). Each maps to permissions from this
catalog; holding multiple roles grants the **union** of their permissions (deny-by-default otherwise).

| Role | Permissions |
|---|---|
| **Administrator** | everything (incl. `users:manage`, `audit:read`) |
| **Operator** | `monitoring:read`, `monitoring:diagnose`, `messages:read`, `messages:view_summary`, `messages:view_raw`, `messages:replay`, `messages:purge`, `connections:control` |
| **Deployment** | `monitoring:read`, `config:deploy`, `config:validate` |
| **Coding** | `monitoring:read`, `code:edit`, `config:validate`, `ai:assist` |
| **Viewer** | `monitoring:read`, `messages:read` |
| **Auditor** | `monitoring:read`, `audit:read` |

Permission catalog: `monitoring:read`, `monitoring:diagnose`, `messages:read`,
`messages:view_summary` (PHI), `messages:view_raw` (PHI), `messages:replay`, `messages:purge`,
`connections:control`, `config:deploy`, `config:validate`*, `code:edit`*, `service:configure`*,
`ai:assist`, `users:read`, `users:manage`, `audit:read`.

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
| `GET /messages/{id}` (raw body) | `messages:view_raw` |
| `POST /messages/{id}/replay` | `messages:replay` |
| `GET /dead-letters` | `messages:read`; `messages:view_summary` unlocks the `summary`/`last_error` fields (per-property — see *Field-level authorization*) |
| `POST /dead-letters/replay` | `messages:replay` |
| `POST /connections/{name}/{start,stop,restart}` | `connections:control` |
| `POST /connections/{name}/purge` | `messages:purge` |
| `POST /config/reload` | `config:deploy` |
| `GET`/`PUT /users/{id}/channel-scope` | `users:manage` (per-channel RBAC) |
| `GET`/`PUT /ad-group-scope-map` | `users:manage` (AD-group→channel scope) |

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

### Field-level (property) authorization (WP-9)

Beyond gating whole *endpoints*, the API gates individual **PHI-bearing properties** within a response,
so a caller can see an object without seeing its patient-identifying fields. The policy is declared in
one place — [`api/field_authz.py`](../messagefoundry/api/field_authz.py) — and enforced by a single
`redact_unauthorized()` helper applied to every returned row, rather than re-implemented inline per
endpoint (where a new endpoint or field could silently leak PHI — the BOPLA risk, ASVS 8.1.2 / 8.2.3).

| Response property | Carries | Unlocked by |
|---|---|---|
| `summary` (message & dead-letter rows) | patient identifiers (MRN / name / order) | `messages:view_summary` |
| `error` / `last_error` | exception text that can quote field values | `messages:view_summary` |
| `raw` (single-message body) | the full message | `messages:view_raw` (whole-body gate, at the endpoint) |

A caller lacking `messages:view_summary` receives those properties as `null`; everything returned
non-null is audited server-side (coalesced per actor/hour), so a scripted bulk read can't harvest the
patient census unaudited. The body (`raw`) is the coarser whole-object gate and stays at the endpoint.
In practice the permissions nest by role (`messages:read` ⊆ `…:view_summary` ⊆ `…:view_raw`), so the
**Viewer** role sees metadata only. Adding a new PHI-bearing response property means adding a row to
`PHI_FIELDS` — a test asserts the map's properties exist and match the expected set, so the gate can't
be forgotten silently.

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
engine-side throttle that also covers the AD login path. MFA is not yet built (planned — see "Not yet built").

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

## Not yet built (deliberate follow-ups)

MFA, Entra ID / OIDC, custom roles, and the remaining `code:edit` / `config:validate` /
`service:configure` endpoints those permissions will gate. MFA and transport TLS (API/WS + MLLP) are **designed** in [ADR 0002](adr/0002-phase2-transport-security-and-strong-auth.md) — *Proposed*, built when off-loopback exposure is scheduled. (Encryption at rest, audit hash-chaining,
**per-channel RBAC** — including the console scope editor and AD-group→scope mapping — and the
**committed dependency lockfile** are now built; see [PHI.md §3](PHI.md#3-encryption-at-rest),
*Audit*, the per-channel-scoping note, and *Dependency lockfile (DEP-1)* above.)
