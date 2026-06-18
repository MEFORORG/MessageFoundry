# ADR 0002 — Phase 2: transport security & strong authentication (off-loopback exposure)

- **Status:** **Accepted (2026-06-14) — build authorized for the v0.1 transport-TLS subset.** The
  off-loopback trigger has fired: the [v0.1 Release Plan](../releases/v0.1-PLAN.md) makes **native
  off-loopback TLS a hard release gate (Gate #4)**, so **WP-13a (API/WSS TLS), WP-13b (MLLP-over-TLS),
  and WP-15 (reverse-proxy / forwarded headers) are authorized for v0.1**. **WP-14 (TOTP MFA) is now
  BUILT (2026-06-17)** — native RFC 6238 TOTP for local accounts, enforced for the Administrator role
  via `[auth].require_mfa` + the step-up gate; AD/Entra MFA stays delegated. *(Supersedes the
  2026-06-14 "defer to 0.2" decision — the owner pulled MFA forward because some level of local
  accounts is a supported deployment, so the engine carries its own MFA.)* On top of WP-14, the
  **multi-layer administrative-interface defense (ASVS 8.4.2, WP-L3-13) is now BUILT (2026-06-17)**:
  WP-14 MFA is wired as a genuine second factor at the step-up boundary, plus a **new-client-IP
  contextual-risk signal** (`[auth].admin_new_ip_step_up`, default off). **Device-posture assessment
  for 8.4.2 is delegated to the deployment** — a managed/attested host + an mTLS client cert terminated
  at the **WP-15** reverse proxy — not built in-process (stdlib `ssl` does no device attestation).
  **Federated SSO (OAuth 2.0 / OIDC /
  SAML via Entra) and SMART on FHIR are *out of this ADR's scope*** — they get a dedicated
  federated-SSO ADR when 0.2 design begins. *(Originally Proposed 2026-06-12 as design-only under the
  "design now, build then" rule; this acceptance supersedes that deferral.)*
- **Built:** Nothing in this ADR is built yet — it designs **WP-13a** (API/WebSocket TLS), **WP-13b**
  (MLLP-over-TLS, v0.1), **WP-14** (MFA, **built 2026-06-17 — see §3**), and **WP-15** (reverse-proxy /
  forwarded-header hardening). The
  Phase-0/1 groundwork it *builds on* is already shipped and must **not** be redesigned:
  the HSTS response header that fires on `https` ([api/app.py](../../messagefoundry/api/app.py)
  `_security_headers`), the transport-agnostic WebSocket `Origin` check
  ([api/security.py](../../messagefoundry/api/security.py) `_ws_origin_allowed`), the fail-closed
  non-loopback **bind guard** (`serve --allow-insecure-bind`, [__main__.py](../../messagefoundry/__main__.py)),
  and the house insecure-TLS escape hatch `insecure_tls_allowed()` / `MEFOR_ALLOW_INSECURE_TLS`
  ([config/settings.py](../../messagefoundry/config/settings.py), used by LDAPS + SQL Server).
- **Supersedes:** the `tls_*` "future" placeholder row in [CONFIGURATION.md](../CONFIGURATION.md) `[api]`
  and the one-line stub bullets under **Phase 2** in
  [ASVS-L2-REMEDIATION-PLAN.md](../security/ASVS-L2-REMEDIATION-PLAN.md) (expanded here).
- **Related:** [ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) (the five
  deferred-until-off-loopback Fails: HSTS 3.4.1, WSS 4.4.1, MFA 6.3.3, transport TLS 12.3.1, off-box
  logs 16.4.3 — this ADR addresses the first four), [PHI.md](../PHI.md) §4 (data in transit) + §11
  (roadmap P1-4 / P2-1 / P2-2 / P2-3), [SECURITY.md](../SECURITY.md) "Not yet built", and
  [ADR 0001](0001-staged-pipeline-architecture.md) (the staged pipeline these listeners feed).

## Context

MessageFoundry's L2 posture holds today **because the engine binds `127.0.0.1`**. A defined set of
controls are acceptable *only* under that loopback assumption and become **mandatory the instant the
API — or any inbound MLLP listener — binds off-loopback**:

- **API + WebSocket are plaintext** (`http`/`ws`): bearer tokens and PHI would cross the network in the
  clear (ASVS 12.3.1, 4.4.1; HSTS 3.4.1 can't engage without `https`).
- **MLLP is plaintext TCP** (`asyncio.open_connection` / `start_server`, no `ssl=`): HL7 bodies on the
  wire in the clear (12.3.1; [PHI.md](../PHI.md) §4 P1-4).
- **Authentication is single-factor** (local argon2id or AD bind/Kerberos): defensible on a trusted
  host, but single-factor remote PHI access is a HIPAA NPRM gap (6.3.3; [PHI.md](../PHI.md) P2-2).
- **No reverse-proxy trust:** the audit/rate-limit source IP is the direct TCP peer
  (`request.client.host`, [api/auth_routes.py](../../messagefoundry/api/auth_routes.py) `_client`); behind
  a proxy that becomes the proxy's IP unless forwarded headers are trusted from the proxy *only*
  (4.1.3, 4.2.1, 15.3.4).

The fail-closed bind guard (PR #165) already **refuses** a non-loopback bind unless the operator passes
`--allow-insecure-bind`, so this exposure can't happen *by accident*. This ADR designs what replaces
that escape hatch with real protection so a deliberate off-loopback deployment is **safe**, not merely
**acknowledged**.

**Design philosophy:** reuse the patterns already in the tree (the per-connection `settings` dict for
MLLP, the `insecure_tls_allowed()` gate, the store cipher for secrets, the sliding-window rate limiter,
the session model + revocation). Add the smallest surface that closes the gap; keep the on-prem,
broker-free, single-binary deployment story intact.

## Decision (proposed)

### 0. Cross-cutting — define "exposed" and gate on it

Introduce one predicate the whole engine agrees on: a deployment is **exposed** when the API
`[api].host` is not in `{127.0.0.1, localhost, ::1}` **or** any inbound MLLP `bind_host` is non-loopback.
The startup guard ([__main__.py](../../messagefoundry/__main__.py)) is extended so that, when exposed:

- the API must have **TLS configured** (WP-13a) **or** a declared upstream terminator (WP-15) — else
  refuse (today's `--allow-insecure-bind` warn-path becomes a TLS-or-refuse gate);
- a non-loopback **MLLP** listener must have per-connection TLS (WP-13b) — else refuse;
- `--allow-insecure-bind` survives only as the `insecure_tls_allowed()`-style **dev** override (loud
  warning), never the default.

This keeps "the loopback assumption" a single, enforced invariant rather than scattered checks.

### 1. WP-13a — Engine API + WebSocket TLS (primary termination path)

Terminate TLS **in-process** via uvicorn, the self-contained default. Add to `ApiSettings`
([config/settings.py](../../messagefoundry/config/settings.py)):

- `tls_cert_file: str | None`, `tls_key_file: str | None` (PEM paths; not secrets),
- `tls_key_password` (**secret**, env `MEFOR_API_TLS_KEY_PASSWORD`, for an encrypted key),
- `tls_min_version: str = "1.2"` (floor; 1.2+ per NIST 800-52r2),
- optional `tls_ciphers`, `tls_client_ca_file` (future mTLS for the console).

Wire them into the single `uvicorn.run(...)` call ([__main__.py](../../messagefoundry/__main__.py)) as
`ssl_certfile` / `ssl_keyfile` / `ssl_keyfile_password` / `ssl_version` / `ssl_ciphers`, **or** build an
`ssl.SSLContext` when finer control is needed. No new dependency.

Falls out for free:
- **HSTS** — `_security_headers` already emits `Strict-Transport-Security` when `request.url.scheme ==
  "https"` ([api/app.py](../../messagefoundry/api/app.py)); it activates the moment TLS is on. (3.4.1)
- **WSS** — `/ws/stats` is served over `wss` once the listener is TLS; the `Origin` + bearer handshake
  ([api/security.py](../../messagefoundry/api/security.py) `authorize_ws`) is transport-agnostic and
  needs **no** change. (4.4.1)
- **Console** — `EngineClient` already refuses plaintext `http` to a non-loopback host unless
  `--insecure` ([console/client.py](../../messagefoundry/console/client.py) `_assert_safe_transport`);
  point it at `https://`/`wss://` for remote engines.

### 2. WP-13b — MLLP-over-TLS

Add an `ssl.SSLContext` to the two asyncio call sites in
[transports/mllp.py](../../messagefoundry/transports/mllp.py): `asyncio.start_server(..., ssl=ctx)`
(inbound `MLLPSource`) and `asyncio.open_connection(..., ssl=ctx)` (outbound `MLLPDestination`).
Per-connection config rides the existing free-form `settings` dict (the established mechanism — no
pipeline change), declared on the `MLLP(...)` factory ([config/wiring.py](../../messagefoundry/config/wiring.py)):

- `tls: bool = False`, `tls_cert_file` / `tls_key_file` (server identity inbound; **client** identity
  for outbound mTLS), `tls_ca_file` (trust anchor), `tls_verify: bool = True`,
  `tls_check_hostname: bool = True`.

The `SSLContext` is built once in the connector `__init__` (mirroring the LDAPS pattern in
[auth/ldap.py](../../messagefoundry/auth/ldap.py)); `tls_verify=False` is refused unless
`insecure_tls_allowed()`, with a loud warning — exactly as LDAPS/SQL Server do. TLS **composes with**
the WP-11c egress allowlist (both are enforced; allowlist first). Optional **mTLS** (client cert) gives
partner mutual authentication. When exposed, a non-loopback MLLP `bind_host` requires `tls=True`.

### 3. WP-14 — Multi-factor authentication (TOTP, local users)

**TOTP (RFC 6238)** for **local** users, implemented on the stdlib (`hmac` + `hashlib` + `base64`) —
**no new dependency** (consistent with the offline, minimal-dep posture; the breach-list and crypto
work stayed stdlib-first too). AD/Kerberos users' MFA is **delegated to the IdP/AD** (Entra/AD already
enforce it for those shops); re-implementing a second factor in-engine for federated users duplicates
that and complicates the bind/SPNEGO flow — documented as N/A in-engine, with an optional future "require
an AD MFA claim" hook.

**Storage** (extends the user + session records,
[store/store.py](../../messagefoundry/store/store.py) + the SQL Server DDL in
[store/sqlserver.py](../../messagefoundry/store/sqlserver.py)):

- `users += totp_secret` (the base32 seed — a **secret**, so routed through the store cipher like
  `messages.raw`; MFA in prod therefore expects a store key, consistent with the at-rest posture),
  `totp_enabled: bool`, `totp_enrolled_at`,
- `users += totp_recovery_codes` (a JSON list of **argon2id-hashed**, single-use codes),
- `sessions += mfa_verified_at` (NULL = second factor not yet satisfied this session).

**Flow** — session-level step-up (reuses the session model + revocation; cleanest audit trail):

1. `POST /auth/login` verifies the password as today and issues a session. If the user is
   `totp_enabled`, the session's `mfa_verified_at` stays NULL and `LoginResponse` carries
   `mfa_required = true`.
2. A `require_mfa` dependency on protected routes rejects (401, `mfa_required`) while an enrolled user's
   `mfa_verified_at` is unset.
3. `POST /auth/mfa-verify` (bearer + 6-digit code, or a recovery code) sets `mfa_verified_at`. Failures
   are rate-limited (reuse the sliding-window limiter, [auth/ratelimit.py](../../messagefoundry/auth/ratelimit.py))
   and audited.
4. Enrollment: `GET /me/mfa` (status), `POST /me/mfa/enroll` (mint secret, return the `otpauth://` URI
   for a QR + the recovery codes once), `POST /me/mfa/verify-enroll` (confirm a code, flip
   `totp_enabled`), `DELETE /me/mfa` (disable; admin can reset another user's MFA via a `users:manage`
   route). New audit events `auth.mfa_enrolled` / `auth.mfa_verified` / `auth.mfa_failed` /
   `auth.mfa_disabled` / `auth.mfa_reset`.

`[auth].require_mfa` (default off; **recommended on for local admins when exposed**) lets an operator
make it mandatory. **Future (WP-14b):** WebAuthn/FIDO2 as a phishing-resistant follow-on — a documented
extension point at the same step-up boundary, not designed in detail here.

### 4. WP-15 — Reverse-proxy / forwarded-header path (alternative termination)

For shops that terminate TLS at a reverse proxy / load balancer (IIS, nginx, Caddy) — common in
enterprise healthcare — the engine stays `http` on a restricted interface **behind** the proxy:

- Run uvicorn with `proxy_headers=True` + `forwarded_allow_ips=<proxy>` so `X-Forwarded-For` /
  `X-Forwarded-Proto` are trusted **only** from the proxy; the audit/rate-limit source IP
  ([api/auth_routes.py](../../messagefoundry/api/auth_routes.py) `_client`) then reads the real client IP
  from the trusted XFF (4.1.3, 15.3.4).
- New `[api].trusted_proxies: list[str]` (empty = trust nothing, today's behavior) and
  `[api].tls_terminated_upstream: bool` — the latter satisfies the §0 exposed-gate **without** in-process
  TLS, but only when `trusted_proxies` is set (so the engine knows a terminator is really in front).
- Document the proxy↔uvicorn framing agreement (4.2.1) and explicit duplicate-query-parameter handling
  (HPP, 15.3.7).

## Options considered

1. **API TLS: built-in (uvicorn) vs reverse-proxy-only vs both.** Built-in alone is self-contained but
   forces small/direct deployments to hand-roll nothing while leaving enterprise proxy shops with an
   untrusted source IP. Proxy-only skips app-TLS code but makes the engine un-exposable without a proxy
   and discards the existing `tls_*` intent. **CHOSEN: both, built-in as the default (WP-13a) + a
   first-class proxy path (WP-15)** — they're already *separate* work packages, so covering both is the
   honest design, and the §0 gate accepts either terminator.
2. **MFA scope: local-only vs all-users vs local-now-+-WebAuthn-later.** All-users duplicates AD/Entra
   MFA and tangles the Kerberos path. **CHOSEN: TOTP local-only now, WebAuthn sketched as WP-14b** — fits
   the federated-delegation model and the offline posture; the WebAuthn door stays open.
3. **MFA secret: stdlib TOTP vs a library (e.g. `pyotp`).** A dependency is a supply-chain + lock cost
   for ~30 lines of HMAC. **CHOSEN: stdlib** (`hmac`/`hashlib`), matching the breach-screening/crypto
   precedent.
4. **MFA challenge: session-level step-up vs a separate provisional token.** A provisional token adds a
   second token type and lifecycle. **CHOSEN: session-level `mfa_verified_at`** — it reuses the existing
   session record, inventory, and revocation, and audits cleanly.

## Consequences

**Positive**
- Closes four of the five deferred-until-off-loopback Fails (3.4.1, 4.4.1, 6.3.3, 12.3.1) and the
  proxy-trust Partials (4.1.3/4.2.1) — the engine becomes **safely exposable**, not just refusable.
- No new runtime dependency; reuses the cipher, rate limiter, session model, `settings`-dict, and
  `insecure_tls_allowed()` patterns already in the tree.
- HSTS + WSS + the console plaintext-refuse are already built, so WP-13a is mostly *wiring*, not new
  security logic.

**Negative / risks**
- **Certificate lifecycle** is now an operator burden (issue/rotate/expire for API + MLLP). Mitigation:
  document an ops runbook; consider a cert-expiry alert (an `AlertSink` reason) — flagged to resolve.
- **MFA secret at rest** depends on the store key being set; MFA in prod therefore presumes the at-rest
  cipher is configured. Stated as a precondition, not silently assumed.
- **MLLP-over-TLS is per-connection**, so a mixed estate (some partners TLS, some not) is a config
  matrix; the §0 gate only forces TLS on *non-loopback* MLLP, so loopback test rigs stay plaintext.
- **Proxy path adds trust configuration** (`forwarded_allow_ips` must name the proxy precisely, or XFF
  spoofing returns) — the empty default (`trust nothing`) keeps it fail-safe.
- Build effort is **L** for 13a/13b/14 and **S** for 15; this is a multi-PR phase, not one change.

## To resolve on acceptance

1. **Cert management expectations** — do we ship a cert-expiry `AlertSink`, and is mTLS the *default* for
   MLLP or opt-in? (lean: expiry alert yes; mTLS opt-in.)
2. **`require_mfa` default when exposed** — recommend-only, or hard-require for local admins on an
   off-loopback bind? (lean: require for `Administrator`, recommend for others.)
3. **`tls_terminated_upstream`** — exact interplay with the §0 gate and the bind guard (must it pin the
   bind to a private interface?).
4. **Recovery codes** — count + regeneration policy; whether DELETE /me/mfa requires re-auth.
5. **Build order** — proposed **WP-13a → WP-15 → WP-13b → WP-14** (TLS + proxy first; they unblock the
   most ASVS rows and the console; MFA is independent and can land last).

---

*Accepted for v0.1 (Gate #4): build the transport-TLS subset in the order **WP-13a → WP-15 → WP-13b**,
one WP per branch/PR with the standard quartet gate. **WP-14 (MFA) was subsequently pulled forward and
BUILT 2026-06-17** (native RFC 6238 TOTP for local accounts) rather than waiting for 0.2, since the
engine must carry its own MFA for local-account deployments.
Flip the relevant [ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) rows and update
[PHI.md](../PHI.md) §4/§11 + [CONFIGURATION.md](../CONFIGURATION.md) + [SECURITY.md](../SECURITY.md) as
each lands. Update CLAUDE.md / ARCHITECTURE.md only when code ships, not now.*
