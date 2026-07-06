# 0068 — Browser WebAuthn passkeys + off-loopback browser exposure (web console L5)

- **Status:** Accepted (2026-07-03 — owner sign-off in-session; design produced and adversarially
  red-teamed before authoring, all owner calls resolved below)
- **Date:** 2026-07-03
- **Related:** [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §3 (WP-14b — **this ADR
  is its design amendment**, superseding the sketch and retiring the
  `MULTISESSION-PLAN-v0.2.md:437` "WP-14b design amendment authored+Accepted" gate) ·
  [ADR 0065](0065-web-ops-dashboard.md) (web console; its AC-2 cookie boundary and AC-6 off-loopback
  refusal are restated and extended here) · [BACKLOG](../BACKLOG.md) #11 / #75 ·
  [ASVS-L3-ASSESSMENT §2b](../security/ASVS-L3-ASSESSMENT.md) (both "Deferred (off-loopback / L5)"
  residuals) · [docs/SECURITY.md](../SECURITY.md)

---

## Context

The #75 browser ops console (ADR 0065, lanes L0–L4c) reached near-parity with the desktop console,
and the L4c ASVS reconciliation (#748) re-scoped the two remaining residuals — **phishing-resistant
MFA (WebAuthn, #11)** and the **ASVS 8.4.2 managed-admin-host / reverse-proxy-mTLS device posture**
— as items that *"firmly gate the off-loopback (L5) work."* The owner has committed off-loopback:
L5 ships AD/Kerberos **browser** login, `public_origin`/TLS hardening, the 8.4.2 posture deliverable,
and WebAuthn as the phishing-resistant second factor, using the **`py_webauthn`** library (the
deliberate ASVS 11.1.3 crypto-inventory checkpoint).

Constraints in play (CLAUDE.md and test-enforced invariants, verbatim where quoted):

- *"Authentication + RBAC are built … The API still binds `127.0.0.1` by default; remote **TLS**
  exposure is later."* — L5 is that "later": it makes off-loopback browser exposure a supported,
  hardened posture instead of a gate that merely refuses.
- ADR 0065 AC-2 (test-enforced): the `mf_session` cookie **never** authenticates a JSON API route;
  `bearer_token()` stays `Authorization`-header-only.
- ADR 0065 AC-6 (test-enforced): `serve_ui` off-loopback **refuses to start** without
  `exposure_protected`, even under `--allow-insecure-bind`. Extended here, never weakened.
- WP-14 (ADR 0002 §3): an MFA-pending session is issued with **no step-up freshness**
  (`seed_reauth=False`), so first-authenticator enrollment always requires an explicit password
  re-proof — a stolen pre-MFA cookie must never bind an attacker's authenticator.
- `flag_new_client_ip` stays **advisory + step-up-forcing only** — it never becomes an authorization
  input (the 8.1.3/8.1.4/8.2.4 N/A keystone in the ASVS L3 assessment).
- Additive only: the PySide6 console stays; shipped JSON endpoints keep their shapes.

## Decision

Ship L5 as four slices — **PR-0** (this ADR) → **PR-A** (WebAuthn) → **PR-B** (off-loopback
hardening + AD-password browser login + the 8.4.2 deliverable) → **PR-C** (browser Kerberos SSO,
deliberately peelable) — with the following design, each point owner-ratified:

### 1. WebAuthn scope and step-up position

**Local users only**, mirroring TOTP's directory-delegation model exactly (AD/Kerberos sessions are
minted `mfa_verified=True`; engine MFA never applies to directory identities — ADR 0002 option 2).
**Second factor at the existing WP-14b step-up boundary, browser-only ceremony**; no login-time
ceremony (the deferred-MFA posture stands — MFA is satisfied lazily at the first step-up).

The browser step-up stays **two-credential**: a passkey assertion replaces the TOTP-code leg and
stamps **`mfa_verified_at` only**; the operator then submits the existing `POST /ui/reauth`
password leg, which stamps `reauth_at` **and performs the `mark_session_reauthed(client)` new-IP
re-anchor**. The completed pair produces both stamps exactly as `verify_mfa` + reauth do today — so
the WP-L3-13 new-client-IP forced step-up clears and no redirect-loop class exists.
`user_verification=PREFERRED` explicitly (the knowledge factor is the password that accompanies
every step-up; `REQUIRED` would brick PIN-less U2F keys for no factor gain).

**`/ui/reauth` generalizes in place — no new branch mechanism** (the enumerated edit set): (a) both
GET+POST anti-loop diverts become `mfa.required and not (mfa.enabled or mfa.webauthn_enrolled) and
action.step_up`, the POST's check staying **textually before `allow_login_attempt`** (the
load-bearing ordering from the L4b review); (b) the GET renders the TOTP code field iff
`mfa.enabled` and the passkey hook iff `mfa.webauthn_enrolled`; (c) the POST's code demand stays
TOTP-gated — a code is never demanded from a WebAuthn-only user; (d) a **new pre-limiter guard**:
an MFA-pending WebAuthn-only user POSTing password-only gets a "complete the passkey prompt first"
error — never "Invalid code.", never a limiter slot; (e) both POST error re-renders re-stage fresh
assertion options so the passkey button survives a failed attempt.

Assertion failures deliberately do **not** feed the `_register_failure` account lockout (signatures
are not guessable secrets; a flaky authenticator must not lock an account) — abuse is bounded by the
route's `allow_login_attempt` gate, cookie-holder-only reachability, and `auth.webauthn_failed`
audits.

### 2. Ceremony state — in-memory, bounded, TTL'd

Challenges live in a process-local cache on `AuthService` (the rate-limiter precedent — single-API-
process is structural): key `(session token-hash, kind ∈ {register, assert})`, 64-byte first-party
`secrets.token_bytes(64)` challenges, 120 s monotonic TTL, single-use pop-on-verify, new ceremony
overwrites the session's pending one. Bounds are **per-user first** (cap 16; at cap the user's own
oldest entry is overwritten — self-harm only, one principal can never deny another's ceremonies),
with a global safety bound (4096) that refuses new ceremonies with a cause-naming error.
**Documented caveat:** an LB fronting multiple HA/shard API nodes without stickiness breaks a
begin-on-A/finish-on-B ceremony; the ceremony-failure error names it, and a store-backed challenge
table + reaper is the recorded upgrade path if multi-node `/ui` becomes supported.

### 3. Dependency — the deliberate ASVS 11.1.3 checkpoint

**`webauthn>=3.0.0,<4`** as a **new optional extra `[webauthn]`**, lazy-imported
(`parsing/dicom/_deps.py` pattern). PyPI name is **exactly `webauthn`** (duo-labs/py_webauthn,
BSD-3-Clause) — `py_webauthn`/`py-webauthn` pip-normalize to an **unrelated** package; the pyproject
comment pins this trap. Floor 3.0.0 because its `cbor2>=6.1.2` floor **guarantees at the floor
itself** the fix for the HIGH cbor2 DoS advisory that explicitly cites WebAuthn flows
(CVE-2026-26209, fixed in cbor2 5.9.0 — the 2.8.0 line's floor of 5.6.5 predates it, though a fresh
lock of that line also resolves clear today); `<4` because the 2.x/3.x cbor2 ranges are disjoint
(a bare `>=` spec silently jumps majors on re-lock); 2.8.0 is the recorded fallback line. Extra, not
core: the net-new transitive **pyOpenSSL hard-caps `cryptography<50`** — as an extra the coupling
binds only opt-in installs and `docker/locks/requirements-core.lock` stays byte-unchanged. The new
`messagefoundry/auth/webauthn.py` mints challenges first-party via `secrets` and registers in the
crypto inventory **in the same commit** as the import; the ci.yml test-install line gains the extra
in that commit too (else its tests silently skip).

### 4. Credential store — three-backend parity by construction

New multi-row `webauthn_credentials` table (all three backends + the `AuthStore` protocol,
idempotent CREATE-on-open). The PK is **`credential_id_hash`** — SHA-256 hex of the raw credential
id (the `sessions.token_hash` precedent): WebAuthn ids may be up to 1023 raw bytes, unboundable as a
SQL Server index key, so the digest is the parity-safe key; the full base64url id rides alongside as
a body column. `sign_count` is a WebAuthn uint32 ⇒ **BIGINT** on Postgres/SQL Server. `label` is
column-capped (100) so `UNIQUE(user_id, label)` stays fully bounded; the concurrent duplicate-label
race is caught as the backend's IntegrityError. **Public keys are stored plaintext by design** —
verification material, not secrets — and the table is deliberately excluded from the store cipher
and the id-keyed rekey loops (recorded at the loop and in ASVS-L2-PHASE0-CHANGES §4 so an auditor
reads it as a decision). `sign_count` updates are a strict **compare-and-set** (`FOR UPDATE` /
`UPDLOCK, ROWLOCK` per the `consume_totp_step` precedent); a CAS miss or py_webauthn counter
rejection is a **clone signal → reject + audit `auth.webauthn_clone_suspected`**; `0` is legitimate
and permanent for synced passkeys. The store contract test lives in an **extra-free module**
imported inside test functions of the SQLite *and both live* suites (a module-level
`importorskip("webauthn")` would silently skip parity on exactly the legs it exists to cover), and a
minimal TOTP-contract backfill lands in the same commit — finally executing the Postgres/SQL Server
row-lock paths under test.

### 5. Factor generalization and recovery

A new `_second_factor_enrolled(user)` predicate (TOTP **or** WebAuthn credentials) threads into
`_mfa_required_for(user, roles, *, second_factor_enrolled: bool)` as a pre-resolved parameter at its
three call sites (login, `mfa_satisfied`, `mfa_status`) — the method stays sync; the AD early-exit
stays first; `require_mfa` still targets local Administrators; enrolled-any-factor ⇒ always
required. On the wire, `MfaStatus.enabled` **stays == `totp_enabled`** (desktop console untouched)
with one additive `webauthn_enrolled: bool = False` field. `verify_mfa`'s refusal stays
TOTP-specific (a WebAuthn-only user's TOTP code gets "not enrolled", never a lockout attempt).

**No WebAuthn recovery codes** — they are phishable knowledge secrets that undercut the
phishing-resistant tier. Recovery = enroll ≥2 passkeys (UI nudge) / keep TOTP alongside /
`admin_reset_mfa`, which is **extended to also delete all WebAuthn credentials**. Deleting the
**last remaining second factor while MFA is required is refused** ("enroll another factor first");
TOTP-disable keeps its existing behavior this lane (parity follow-up recorded). Documented
consequence: a passkey-only local user cannot satisfy the TOTP-shaped JSON `/auth/mfa-verify`, so
desktop-console step-up actions become unavailable to them (enroll-page warning; owner-accepted).
An extra-less install with enrolled credentials gets a **startup advisory** naming
`admin_reset_mfa` and a legible "passkeys are unavailable on this install" reauth-page notice —
never a silent loop.

### 6. Ceremony endpoints — the first cookie-authed JSON under `/ui`

Ceremony *options* ride server-rendered HTML `data-*` attributes; only the two *verify* legs are
JSON POSTs (`/ui/account/webauthn/verify`, `/ui/reauth/webauthn`) — cookie-authenticated via the
`require_ui` family + `assert_same_origin`, `request.json()` bodies (no python-multipart). **This is
a sanctioned carve, recorded here**: ADR 0065 AC-2 is untouched — the boundary is per-dependency
(`bearer_token()` header-only; the cookie read only by `require_ui`-family deps), so cookie-authed
JSON under `/ui` is mechanically consistent, and each new JSON route also rejects a bearer header
without the cookie. Registration (`POST /ui/account/webauthn/enroll`, body-less → HTML) sits behind
**`require_ui_reauth_only`** (password-only re-proof — WP-14: full-MFA gating would deadlock first
enrollment) and registers `step_up=False` (threads the enroll-first anti-loop); credential deletion
(`POST /ui/account/webauthn/{credential_id}/delete`) is the body-less auto-retry shape behind the
full step-up. Body-carrying POSTs are **never** registered as continuations (hard invariant); the
verify route maps its stale-window redirect to the registered enroll action. All JS lives in
`/ui/static/app.js` (CSP `script-src 'self'`, no inline script), feature-detects
`PublicKeyCredential`, and disables the passkey button for the ceremony's duration (CAS
double-click false-positive mitigation). No new settings: installing the extra + enrolling is the
opt-in; RP identity rides `[api].public_origin`.

### 7. RP identity — fail-closed, keyed on the right signal

`_webauthn_rp()`: `public_origin` set ⇒ authoritative (never a second origin knob). Unset ⇒ derive
from the request URL **only when no proxy is declared and the bind is loopback** (dev flow). Unset
with **`tls_terminated_upstream` set or an off-loopback bind ⇒ ceremonies fail closed** — behind a
declared proxy the request `Host` is proxy-forwardable (client-controllable), and anchoring the
rp_id to it would defeat exactly the phishing resistance this lane adds. Every fail-closed surface
renders legibly (409 on ceremony endpoints; explanatory blocks on `/ui/account` and the reauth
page — never a redirect loop). Per-credential `rp_id` is persisted; credentials minted under a
different rp render "unusable (origin changed)" — changing `public_origin`'s host invalidates
passkeys, documented before the first off-loopback deployment enrolls its admins.

**New startup refusal (deliberate upgrade-time behavior change, owner-confirmed):**
`serve_ui + tls_terminated_upstream` now **requires `[api].public_origin`** — without it the
same-origin CSRF check also degrades to Host comparison behind the proxy. An existing proxied
browser-console deployment stops booting until one config line is added; the error names it.

### 8. Off-loopback hardening (PR-B)

The uvicorn `ProxyHeadersMiddleware` chain stays the **single** forwarded-header parser (no second
parser — several docstrings and ASVS 4.1.3 contractually depend on it). Fixes: **force the cookie
`Secure` flag and HSTS whenever `exposure_protected`** (the operator's declaration that the
browser-facing scheme is https — the per-request scheme is poisoned for the whole session if the
proxy omits `X-Forwarded-Proto` at login time); extend the existing `__main__.py` startup ladder —
the §7 refusal, an `http://` `public_origin` refused under **both** TLS termination modes, a loud
undeclared-proxy warning (`serve_ui` + `public_origin` set + not `exposure_protected`), the
extra-less-credentials advisory, the `admin_new_ip_step_up` off-loopback advisory (**default stays
False** — a flip would churn NAT'd hospital networks and risk the 8.1.3/8.1.4/8.2.4 N/A keystone),
and a one-shot runtime tripwire on any `/ui` request arriving `scheme=http` while
`tls_terminated_upstream` (names both causes: XFP missing; peer not in `trusted_proxies`). The
3.3.3 `__Host-` N/A posture stands (loopback-http dev flow retained). Browser AD-password login is
a provider `<select>` on `/ui/login` (rendered only when AD is enabled; allow-listed
`{"local","ad"}`) passing through to the existing `auth.login` — one session per POST, resync
side-effects fire once.

### 9. Browser Kerberos SSO — `GET /ui/sso` (PR-C, peelable)

Browsers never call the JSON `POST /auth/negotiate` (no 401 challenge; bearer body), so PR-C adds
the RFC 4559 route: no `Authorization` ⇒ **401 + `WWW-Authenticate: Negotiate`** (the challenge leg
is **not** rate-limited — throttling it would self-lock normal SSO traffic); the token-bearing leg
passes a `Sec-Fetch-Mode` hygiene check (non-`navigate` fetches rejected **and audited** — top-level
cross-site navigations allowed; residual harm of a forced navigation is self-login only), then
`allow_login_attempt` (exhaustion → `303 /ui/login?e=rate_limited`, audited — the login page's
three SSO-adjacent codes are `sso_failed` / `sso_unavailable` / `rate_limited`), then a
**single-leg, Kerberos-only** `kerberos_principal()` step (NTLM is
structurally unbuildable here and stays unsupported; **any** failure → audit with the `<kerberos>`
sentinel + `303 /ui/login?e=sso_failed` — never a second 401, no challenge loops). Success mints
**one** cookie session via `_complete_ad_login(..., seed_reauth=False)`: an SSO session's proof is
ambient, so the first sensitive action forces the directory-password step-up (`auth.reauth`
live-rebinds AD users — no new machinery). **The JSON `/auth/negotiate` is unchanged**, including
its `seed_reauth=True` — the asymmetry is deliberate this lane (a behavior flip on a shipped
endpoint; nothing ships that calls it) and recorded as an approved follow-up. A **boot-once**
acceptor preflight (`spnego.server()` in the app lifespan) degrades `kerberos_available` → the
providers flag flips false, the login-page SSO link hides, `/ui/sso` → `e=sso_unavailable`; a
transient DC/SPN failure at boot sticks until restart (recorded limitation). Channel binding:
`channel_bindings=None` always in L5 (behind a TLS-terminating proxy EPA is structurally broken;
never silently enforced), with the pyspnego acceptor-enforcement question a recorded spike. The
single-leg acceptor deliberately **discards the mutual-auth `out_token`** — the success 303
carries no `WWW-Authenticate` response header (consistent with SECURITY.md's "no mutual
authentication"); emitting it is a follow-up. Coverage is mock-seam only (no AD
exists in any test infra) — off-by-default containment; a domain-joined smoke is strongly advised
before *recommending* SSO (not a merge gate; owner-accepted).

### 10. ASVS 8.4.2 deliverable — guidance, not in-engine attestation

A new **`docs/security/OFF-LOOPBACK-DEPLOYMENT.md`**: managed-admin-host runbook, nginx/Caddy
reverse-proxy-mTLS reference configs (each pairing `ssl_verify_client`/`client_auth` with the
`X-Forwarded-Proto` line, exact-peer `trusted_proxies`, and the now-mandatory `public_origin`),
SPN checklist, CBT-per-termination-mode statement, and a 3 am triage table. No in-process
attestation (`stdlib ssl performs no in-process attestation` stays the accepted deliberate
residual; `tls_client_ca_file` remains the desktop console's in-process mTLS, never repurposed).
ASVS updates: the two §2b residual rows flip (residual-row edits only, per the §2b overlay rule);
**separately and called out as such**, two main-scorecard cells re-score because shipped code
changed their applicability — 6.7.2 (challenge nonce: first-party 64-byte single-use TTL'd
challenges) and 6.5.7 (UV authenticator-local + secondary) → applicable → Pass; 6.7.1
(assertion-verification certificate storage) stays N/A (attestation=none by policy — no attestation
certificates are consumed or stored); 8.1.3/8.1.4/8.2.4 stay N/A (`flag_new_client_ip`
advisory-only, restated).

## Acceptance Criteria

> EARS-form, each `→`-linked to the verifying test (built in PR-A/B/C; `messagefoundry adr-analyze`
> checks link resolution once the tests land).

- **AC-1** — WHILE a session is MFA-pending (no step-up freshness — WP-14), WHEN it POSTs
  `/ui/account/webauthn/enroll`, THE SYSTEM SHALL 303 to `/ui/reauth` and permit enrollment only
  after the password-only re-proof (a stolen pre-MFA cookie can never bind a passkey).
  → `tests/test_webui.py::test_webauthn_enroll_requires_password_reproof`
- **AC-2** — WHEN a passkey assertion verifies at `POST /ui/reauth/webauthn`, THE SYSTEM SHALL stamp
  `mfa_verified_at` ONLY (no `reauth_at`, no client re-anchor); the subsequent password leg SHALL
  stamp `reauth_at` and re-anchor the client IP.
  → `tests/test_webauthn.py::test_assertion_stamps_mfa_only_never_reauth`
- **AC-3** — WHILE a user's only enrolled factor is WebAuthn, WHEN they hit a `step_up=True` action,
  THE SYSTEM SHALL render the reauth page with the passkey prompt (never divert to
  `enroll_first`, never demand a TOTP code), and the generalized anti-loop check SHALL run before
  the login rate limiter.
  → `tests/test_webui.py::test_webauthn_browser_enroll_and_stepup_e2e`
- **AC-4** — IF an assertion reports a `sign_count` at or below the stored nonzero counter, THEN THE
  SYSTEM SHALL reject it and audit `auth.webauthn_clone_suspected`; WHILE both counters are 0
  (synced passkey), THE SYSTEM SHALL accept repeatedly.
  → `tests/test_webauthn.py::test_sign_count_cas_clone_detection_nonzero`
- **AC-5** — THE SYSTEM SHALL treat each ceremony challenge as single-use with a 120 s TTL, and a
  user at their pending-ceremony cap SHALL evict only their own oldest entry, never another
  user's.
  → `tests/test_webauthn.py::test_challenge_single_use_ttl_and_per_user_bound`
- **AC-6** — IF `serve_ui` and `tls_terminated_upstream` are set without `[api].public_origin`,
  THEN THE SYSTEM SHALL refuse to start with an error naming the missing setting.
  → `tests/test_cli.py::test_serve_ui_upstream_requires_public_origin`
- **AC-7** — WHILE `public_origin` is unset AND (`tls_terminated_upstream` is set OR the bind host
  is off-loopback), THE SYSTEM SHALL fail WebAuthn ceremonies closed with a legible notice on every
  affected surface (409 on endpoints; explanatory text on `/ui/account` and `/ui/reauth` — never a
  redirect loop, never a request-Host-derived rp_id).
  → `tests/test_webui.py::test_webauthn_rp_fail_closed_legible`
- **AC-8** — WHEN a request presents a bearer `Authorization` header without the `mf_session` cookie
  to a `/ui` WebAuthn JSON route, THE SYSTEM SHALL reject it; the ADR 0065 AC-2 inverse (cookie
  alone on a JSON API route → 401) SHALL keep passing untouched.
  → `tests/test_webui.py::test_webauthn_json_endpoints_reject_bearer_without_cookie`
- **AC-9** — WHEN any new `/ui` POST (enroll, verify, delete, `/ui/reauth/webauthn`) receives a
  cross-site request, THE SYSTEM SHALL reject it with 403.
  → `tests/test_webui.py::test_all_admin_posts_reject_cross_site`
- **AC-10** — IF deleting a WebAuthn credential would remove the user's last second factor WHILE MFA
  is required for them, THEN THE SYSTEM SHALL refuse with "enroll another factor first".
  → `tests/test_webauthn.py::test_last_factor_delete_refused_while_required`
- **AC-11** — WHEN `admin_reset_mfa` runs, THE SYSTEM SHALL delete the user's WebAuthn credentials
  alongside TOTP state (existing session-revoke semantics unchanged).
  → `tests/test_webauthn.py::test_admin_reset_mfa_clears_webauthn_credentials`
- **AC-12** — WHILE `exposure_protected` is true, THE SYSTEM SHALL set the session cookie `Secure`
  and emit HSTS regardless of the per-request scheme.
  → `tests/test_webui.py::test_forced_secure_cookie_and_hsts_when_protected`
- **AC-13** — WHEN `GET /ui/sso` is requested without an `Authorization` header, THE SYSTEM SHALL
  respond 401 + `WWW-Authenticate: Negotiate` without consuming a rate-limit slot; IF the
  token-bearing leg exhausts `allow_login_attempt` (checked FIRST, so it bounds every downstream
  audit write), THEN THE SYSTEM SHALL 303 to `/ui/login?e=rate_limited` — **throttle-logged,
  NOT audited** (parity with the JSON rate-limit path's anti-flood posture: an unauthenticated
  flood must not amplify into unbounded audit rows); WHEN the Kerberos/token-validation step
  fails for any
  reason, THE SYSTEM SHALL audit with the `<kerberos>` sentinel and 303 to `/ui/login?e=sso_failed`
  — never a second 401; WHEN `Sec-Fetch-Mode` is present and not `navigate` on the token leg, THE
  SYSTEM SHALL reject and audit likewise, WHILE cross-site top-level navigations SHALL be allowed.
  → `tests/test_webui.py::test_sso_challenge_and_single_leg_failure` +
  `tests/test_webui.py::test_sso_rate_limits_token_leg_only` +
  `tests/test_webui.py::test_sso_cross_site_hygiene`
- **AC-14** — WHEN a browser Kerberos SSO session is minted, THE SYSTEM SHALL issue it with
  `seed_reauth=False` (first sensitive action forces the directory-password step-up), WHILE
  AD-password login and the JSON `/auth/negotiate` keep seeding reauth (regression-pinned).
  → `tests/test_webui.py::test_sso_session_not_reauth_seeded`
- **AC-15** — THE SYSTEM SHALL exercise the `webauthn_credentials` store contract (multi-row CRUD,
  CAS under each backend's row-lock idiom, 1023-byte credential-id round-trip, duplicate-label
  IntegrityError) on SQLite, Postgres, and SQL Server via an extra-free contract module.
  → `tests/_webauthn_store_contract.py::_assert_webauthn_store_contract`
- **AC-16** — WHILE the `[webauthn]` extra is not installed AND a user has enrolled credentials, THE
  SYSTEM SHALL log a startup advisory naming `admin_reset_mfa` and render a legible
  "passkeys unavailable on this install" notice at reauth — never a silent loop.
  → `tests/test_webui.py::test_webauthn_extra_less_renders_notice` + `tests/test_webui.py::test_reauth_extra_less_with_credentials_renders_notice`

## Options considered

1. **Passkey = second factor at the step-up boundary, password leg mandatory (CHOSEN)** — preserves
   today's step-up posture exactly; the assertion satisfies only the MFA leg. *Rejected
   alternative (owner may reopen):* passkey-alone clears the full step-up — forces the UV-policy
   question (UV=REQUIRED bricking PIN-less keys) and silently relaxes the password re-proof.
2. **In-memory challenge cache (CHOSEN)** vs a store-backed challenge table — single-process is
   structural; seconds-scale single-use state is the rate-limiter class, not the TOTP-staging
   class. The store table is the recorded upgrade path for multi-node `/ui`.
3. **`[webauthn]` optional extra (CHOSEN)** vs core dependency — pyOpenSSL's `cryptography<50` cap
   must not gate repo-wide crypto upgrades; core would also change the docker core lock.
4. **`webauthn>=3.0.0,<4` (CHOSEN)** vs `>=2.8.0,<3` — 3.0.0's cbor2 floor guarantees the fix for
   the HIGH DoS advisory that explicitly cites WebAuthn flows at the floor itself (the 2.8.0
   line's floor predates it, relying on lock-time resolution instead); a floor-level guarantee vs
   a soak concern. 2.8.0 recorded as the deliberate fallback line.
5. **No WebAuthn recovery codes (CHOSEN)** vs extending the TOTP-minted pool — codes are phishable
   knowledge secrets that undercut the phishing-resistant tier; `admin_reset_mfa` + multi-passkey
   nudge + TOTP-alongside cover recovery.
6. **Kerberos-only single-leg SSO (CHOSEN)** vs NTLM/multi-leg — pyspnego's pure-Python NTLM
   acceptor needs an `NTLM_USER_FILE` (useless against AD), NTLM authenticates the TCP connection
   (ASGI exposes no affinity), and SECURITY.md already declares it unsupported.
7. **Reverse-proxy mTLS + managed-host guidance for 8.4.2 (CHOSEN — owner lock, #748)** vs
   in-engine client-cert verification / device attestation — the accepted residual says the engine
   performs no in-process attestation; `tls_client_ca_file` stays the desktop console's mTLS.
8. **Local-users-only WebAuthn (CHOSEN)** vs extending to AD/SSO identities — directory identities
   delegate MFA to the directory (ADR 0002 option 2); an engine-side factor for AD users would
   overturn the recorded federation model.

## Consequences

**Positive** — Phishing-resistant MFA gates the newly exposed browser admin surface; AD browser
login lands without touching shipped JSON contracts; the off-loopback posture becomes a supported,
documented deployment with fail-closed origin binding; the crypto-inventory checkpoint is exercised
genuinely (first-party challenges); live-backend auth parity finally gets tested (TOTP backfill).

**Negative / risks** — `webauthn` 3.0.0 is a days-old major (mitigations: `<4` cap, real-verify
tests, recorded 2.8.0 fallback); pyOpenSSL caps `cryptography<50` inside the single uv resolution
even as an extra; changing `public_origin`'s host invalidates every enrolled passkey (legible
per-credential, but an org rename means mass re-enrollment); the `serve_ui + tls_terminated_upstream
⇒ public_origin required` refusal is an upgrade-time behavior change (release-noted); passkey-only
local users lose desktop-console step-up (documented + enroll-page warning); Kerberos SSO ships
with zero real-AD validation (off-by-default containment); the boot-once preflight means a
transient DC outage at engine start disables browser SSO until restart; in-memory challenges break
begin/finish across non-sticky multi-node LBs (documented; upgrade path recorded).

**Out of scope** — WebAuthn for AD/SSO identities; JSON-API/desktop-console WebAuthn ceremonies;
passkey-alone step-up; CBT/EPA enforcement (spike recorded); a store-backed challenge table;
in-engine device attestation; NTLM/multi-leg SSO; TOTP-disable last-factor parity (follow-up);
flipping the JSON `/auth/negotiate` `seed_reauth` (approved follow-up); periodic Kerberos preflight
re-probe.

## Resolved on acceptance (owner sign-off, 2026-07-03)

- [x] Overall design + build order (PR-0 → A → B → C) — **go**.
- [x] `serve_ui + tls_terminated_upstream ⇒ public_origin` hard refusal — **confirmed** (upgrade-time
  change accepted).
- [x] Dependency line — **`webauthn>=3.0.0,<4`**.
- [x] Kerberos SSO ships in-lane as peelable PR-C, experimental/off-by-default, mock-tested — **yes**.
- [x] ADR vehicle: this new ADR 0068 satisfies and retires the WP-14b gate — **confirmed**.
- [x] No WebAuthn recovery codes — **accepted**.
- [x] Passkey-only users become browser-only for step-up (warn, don't force TOTP-first) — **accepted**.
- [x] In-process-TLS off-loopback with no `public_origin`: warn + fail-closed (not a refusal) — **accepted**.
- [x] `admin_new_ip_step_up` default stays False + off-loopback advisory — **accepted**.
- [x] Smartcard-only / passwordless AD accounts cannot pass browser step-up — **accepted, documented**.
- [x] Browser step-up keeps the password mandatory beside the passkey — **accepted** (passkey-alone
  recorded as a reopenable rejected alternative).
- [x] Domain-joined lab smoke before *recommending* SSO (not a merge gate) — **accepted**.
- [x] TOTP-disable last-factor parity deferred to a follow-up — **accepted**.
- [x] JSON `/auth/negotiate` keeps `seed_reauth=True` this lane; the flip is an approved follow-up — **accepted**.
- [x] `GET /ui/sso` **audit posture** (review-hardened): the rate-limiter runs first and bounds every downstream audit write; the rate-limit reject is throttle-logged (not audited); a token-bearing attempt while SSO is disabled/degraded redirects **without** auditing (no limiter fronts that branch, so auditing it would be the same unbounded-amplifier the anti-flood invariant forbids) — **accepted carve-out** to AUTH-K-AUDIT's every-reject rule.

## Open items (post-acceptance)

- [ ] pyspnego acceptor CBT-enforcement behavior spike (does a client-supplied CBT get enforced with
  `channel_bindings=None`?) — determines whether the WP-15 proxy posture needs an explicit knob.
- [ ] Domain-joined lab smoke for `GET /ui/sso` (SSPI/keytab/browser reality) before recommending SSO.
- [ ] Mutual-auth `out_token` emission on the success 303 (single-leg discards it today) + its
  cross-browser rendering, IF a deployment needs mutual auth.
- [ ] Store-backed challenge table + reaper if multi-node `/ui` becomes supported.
- [ ] Kerberos preflight periodic re-probe (today boot-once; DC outage at start sticks until restart).
- [ ] v3.0.0 `response.transports` struct path — mandatory build-time check at PR-A (recon flagged it
  uneyeballed).
