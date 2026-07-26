# ADR 0142 — Federated SSO: an OIDC authorization-code + PKCE relying party (hybrid, AD-backed)

- **Status:** Proposed — **code COMPLETE, awaiting lab validation**  <!-- all six layers built + green 2026-07-21; flips to Accepted only when runbook cells L6a, L9 and L18 report. Do NOT flip on the strength of a green test suite: L9 can invalidate the architecture (passwordless step-up) and L18 is the real-IdP proof of the AC-11 username binding. -->
- **Date:** 2026-07-21
- **Related:** [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (promises a dedicated
  federated-SSO ADR) · [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (browser SSO, the
  `/ui/sso` state machine this mirrors) · [ADR 0079](0079-kerberos-idp-session-coordination.md)
  (mechanism 1 ships here) · [ADR 0024](0024-smart-backend-services-token-provider.md) (the OUTBOUND
  OAuth2 posture, inverted here) · [ADR 0118](0118-secure-by-default-security-configuration-section.md)
  (`[security]` deliberately untouched) · BACKLOG #274 (this build), #99(g) (closed, delivered here),
  #187 / ASVS 7.1.3 · CLAUDE.md §9 (PHI), §4 (dependency direction)

---

## Context

MessageFoundry authenticates operators three ways today: a local account (password + TOTP/WebAuthn),
an **on-prem AD** LDAPS bind, and **Kerberos/SPNEGO** browser SSO. All three converge on one session
mint site, `AuthService._issue_session` (`auth/service.py`).

Two forcing problems arrived together.

**1. The engine cannot tell whether MFA actually happened for a directory login.** `auth/service.py`
issues every AD session with `mfa_verified=True`, commented *"AD/Kerberos MFA is delegated to the
directory"*, and `_mfa_required_for` returns `False` for any non-local provider. BACKLOG #99(g) filed
an engine-side "require an AD MFA claim" hook to fix that. **It is not buildable against on-prem AD
DS**: the LDAPS bind requests six attributes, none MFA-bearing (`auth/ldap.py:153-160`), a simple bind
proves only password possession, and `kerberos_principal` (`:255-284`) yields a bare account name with
no PAC/authorization-data accessor on pyspnego 0.12.1's public `ContextProxy`. Any hook there would
infer MFA from group membership or account policy — **a proxy signal presented as an assertion**, which
is a worse posture than the honest delegation already documented. #99(g) is therefore closed as
not-buildable-as-filed, and the only honest carrier of an MFA signal is a **signature-verified `amr` /
`acr` claim on a federated token**.

**2. ASVS 7.1.3 (session lifetime coordinated with the IdP) is accepted-but-open.** [ADR
0079](0079-kerberos-idp-session-coordination.md) designed it and deferred the build; its 2026-07-21
amendment records that mechanism 1's preferred input — the Kerberos ticket `endtime` — is unobtainable
via pyspnego, so on the Kerberos path it degrades to a second local constant. A federated `id_token`
carries `exp`, signed. **Mechanism 1 becomes buildable the moment a federated path exists.**

CLAUDE.md §9 binds the design: *"On-premises by default: no PHI leaves the local environment without
explicit, reviewed configuration"* and *"The API binds `127.0.0.1` by default and **requires
authentication**"*. Federation must therefore be **default-off**, must not weaken the loopback posture,
and must not make a reachable IdP a precondition for operating the engine.

The deployment shape that motivates this is **hybrid-joined**: an org with on-prem AD DS *and* a cloud
or federated IdP (Entra ID, AD FS, Okta) in front of it. That shape is what makes the cheap design below
possible — and its limits are stated honestly in *Consequences*.

## Decision

**Add cloud/federated login as a THIRD authentication mechanism for an identity that already exists in
on-prem AD — not as a new identity provider.** An OIDC **authorization-code + PKCE** relying party,
browser-only, default-off, with **no new dependency**.

The load-bearing property: once the `id_token` verifies, the flow extracts a username claim and calls
the **same password-free lookup the Kerberos path already uses** —
`LdapAuthenticator.resolve_principal(username)` — then `_complete_ad_login(...)` unchanged. Concretely:

- **Roles come from LDAP, never from the token.** A claims-parsing bug therefore degrades from
  *privilege escalation* to *wrong-user login*. In every design where the token carries groups, a
  parsing bug is directly role-bearing.
- **No new `AuthProvider` enum member.** `_build_identity` coerces any provider outside `{local, ad}`
  to `LOCAL`, which would route `reauth()` to a password check against a NULL hash and permanently 403
  every step-up route. Adding no member leaves that landmine unarmed.
- **Zero store work.** No column, no migration, no three-backend parity, no group-map namespace
  decision.
- **A principal with no on-prem AD object is refused** (`not_in_directory`). Hybrid-only, by design.
- **The username claim's UPN suffix is checked against an operator-pinned allow-list**
  (`[auth].oidc_allowed_username_domains`, defaulting to `ad_domain`) **before** the local part is used
  to resolve an account. *Added 2026-07-21 after an adversarial review of the W4-4 build found the
  omission was a live privilege-escalation path, not a theoretical one.* `preferred_username` is
  declared neither unique nor stable by OIDC Core §5.7 and is self-editable on several IdPs, so
  without this the **local part alone** decides which AD object is resolved: any principal the pinned
  IdP will issue a token for — an Entra B2B guest, a cloud-only account — could assert
  `Administrator@somewhere.else`, strip to `Administrator`, and log in as the on-prem Domain Admin
  with its full LDAP-derived roles. Every ladder rung passes legitimately, so nothing else catches it.
  **This is the load-bearing caveat to the "roles come from LDAP" argument above:** that argument
  bounds the damage of a *parsing bug* to an *accidental* wrong-user login, and it does not hold when
  the wrong user is **attacker-chosen**. The same defect also fires with no attacker at all — a guest
  `jsmith@partner.com` and an employee `jsmith` collide silently. Stripping without a configured
  suffix source is refused at config load, so the control cannot be left off by omission.

**Session lifetime (ADR 0079 mechanism 1, delivered).** `_issue_session` gains a keyword-only
`max_expires_at: float | None = None`; the expiry becomes a `min()` of the local absolute lifetime and
the verified `id_token.exp`. Local and AD callers pass nothing and stay byte-identical.

**The MFA gate (#99(g), delivered).** `oidc_require_mfa_claim` defaults **true**: a login whose verified
token carries no configured `amr`/`acr` value is refused with `sso_mfa_required`. The engine verifies
what the IdP **asserts**, cryptographically — not what it enforced. Every doc string says so.

### What it must not break

- **Default-off is byte-identical.** With `oidc_enabled=false` (the default) the acceptor construction,
  session minting, `/auth/providers` payload, and route table are unchanged. Proven by a captured
  baseline, not by inspection.
- **Degradation is isolated.** An unreachable IdP must not affect local, LDAPS, or Kerberos login.
- **The loopback default stands.** No new host/port knob; the redirect URI derives from the existing
  `[api].public_origin`, and enabling OIDC without a resolvable one is refused at load.
- **`[security]` is untouched.** Federation is plumbing and stays in `[auth]`, as AD/LDAP does. Stated
  positively so a reviewer does not "helpfully" add a posture key and four hand-maintained mirrors.

### Verification is hand-rolled — and that is the highest risk here

There is **no JWKS fetch, no OIDC discovery, and no third-party JWT verification anywhere in the repo
today**; `transports/smart.py` only *mints* our own assertions. Consuming an IdP token is a different
problem, and it is ~400–500 lines of security-critical code with no upstream CVE stream. Two structural
mitigations make it defensible rather than reckless:

1. **The closed `SignatureAlgorithm` enum has no `none` and no `HS*`** (`config/models.py`), and header
   `alg` is coerced through it. `alg:none` and RS256→HS256 confusion are foreclosed by the type system,
   not by a hand-written check someone can delete.
2. **An explicit key-material floor**, because the enum forecloses the classic mistakes but not a weak
   key: reject `kty` ∉ {RSA, EC}; RSA modulus < 2048 bits; curve not matching the header `alg`; `use`
   present and ≠ `sig`; `key_ops` present without `verify`; and **refuse a JWKS with duplicate `kid`s**
   rather than taking the first. `kid` is required — there is no try-every-key fallback.

"Structurally cannot make the classic mistakes" is **not** "correct". The verification function merges
alone, first, and gets an adversarial review pass in isolation.

### Browser-flow binding

Server-side `state` is a CSRF/mix-up defence, **not** a browser binding — whoever presents a valid
`(state, code)` pair would otherwise get a session minted in *their* browser. Three mechanisms:

- **Flow cookie** — `/ui/oidc/start` sets a short-lived `__Host-`-prefixed, `HttpOnly`,
  `SameSite=Lax` cookie carrying a flow id; the callback requires cookie-id **and** `state` to match,
  compared with `hmac.compare_digest`. Lax *is* sent on the top-level cross-site GET return, so it
  survives the IdP redirect. The session cookie's `SameSite=Strict` is untouched.
- **Same-site landing hop** — the callback returns 200 HTML with `<meta http-equiv="refresh"
  content="0;url=/ui">` rather than a 303, so the next request is initiated by our own document and the
  Strict session cookie is unambiguously sent. No JS, so it is CSP-compatible.
- **Start-leg rate limit** — the limiter runs on **both** legs, and the bounded flow cache **rejects**
  when full rather than evicting oldest. Evict-oldest would make a start-leg flood a login
  denial-of-service.

## Acceptance Criteria

- **AC-1** — WHILE `[auth].oidc_enabled` is false, THE SYSTEM SHALL behave byte-identically to the
  pre-federation build: no `/ui/oidc/*` routes, `providers.oidc == false`, and unchanged session expiry.
  → `packaging/messagefoundry-webconsole/tests/test_webui.py` <!-- console-package suite -->

- **AC-2** — WHEN a federated login completes, THE SYSTEM SHALL resolve roles from on-prem AD via
  `resolve_principal`, never from a token claim.
  → `tests/test_auth_oidc_service.py`
- **AC-3** — IF the `id_token` fails any verification rung (signature, `iss`, `aud`/`azp`, `exp`/`iat`
  skew, `nonce`, `kid` unknown/ambiguous, key below the floor), THEN THE SYSTEM SHALL refuse the login,
  mint no session, and audit a closed-set reason slug.
  → `tests/test_auth_oidc.py`
- **AC-4** — IF the protected header declares `alg` outside the configured allow-list, THEN THE SYSTEM
  SHALL raise before any signature computation (`none` and `HS*` are unrepresentable in
  `SignatureAlgorithm`).
  → `tests/test_compact_jws_verify.py`
- **AC-5** — WHEN `oidc_require_mfa_claim` is true and the verified token carries no configured
  `amr`/`acr` value, THE SYSTEM SHALL refuse with `sso_mfa_required` and audit `mfa_claim_missing`.
  → `tests/test_auth_oidc.py`, `tests/test_auth_oidc_service.py`
- **AC-6** — WHEN a federated session is minted, THE SYSTEM SHALL cap `expires_at` at the verified
  `id_token.exp`, and SHALL leave local and AD session expiry unchanged.
  → `tests/test_auth_session_lifecycle.py` (local/AD unchanged), `tests/test_auth_oidc_service.py` (the cap itself)
- **AC-7** — IF a callback arrives without a matching flow cookie, THEN THE SYSTEM SHALL refuse and
  audit `flow_binding_missing`, even when `state` and `code` are otherwise valid.
  → `packaging/messagefoundry-webconsole/tests/test_webui.py` <!-- console-package suite -->

- **AC-8** — WHILE the IdP is unreachable, THE SYSTEM SHALL continue to serve local, LDAPS, and Kerberos
  logins, and SHALL recover without an engine restart once it returns.
  → `tests/test_auth_oidc_service.py`
- **AC-9** — IF `oidc_enabled` is true without a resolvable `[api].public_origin`, a non-https endpoint,
  an empty allow-list, or an MFA gate that can never fire, THEN THE SYSTEM SHALL refuse at load, naming
  the exact key.
  → `tests/test_settings.py`
- **AC-10** — THE SYSTEM SHALL NOT log the client secret, authorization `code`, or any token.
  → `tests/test_auth_oidc_service.py`
- **AC-11** — IF the username claim's UPN suffix is absent, empty, or not in
  `oidc_allowed_username_domains` (defaulting to `ad_domain`), THEN THE SYSTEM SHALL refuse the login
  **before consulting the directory** and audit `username_domain_not_allowed`; AND IF
  `oidc_username_strip_domain` is true with no suffix source configured, the engine SHALL refuse at
  config load.
  → `tests/test_auth_oidc_service.py`, `tests/test_settings.py`

> **Note on the AC→test map.** AC-3/AC-5/AC-10 previously pointed at `tests/test_auth_oidc_claims.py`
> and `tests/test_auth_oidc_flow.py`, and AC-4 at `tests/test_outbound_signing.py`. None of those
> carried the tests: the package suite landed as a single `tests/test_auth_oidc.py`, and W4-1's
> adversarial cases as `tests/test_compact_jws_verify.py`. Corrected in place 2026-07-21.

## Options considered

1. **OIDC as a third mechanism for an existing AD identity — CHOSEN.** Cheapest, and its failure modes
   are structurally bounded (roles from LDAP, no enum member, no store change). Judged best on
   maintainability and deliverability.
2. **A pluggable federation seam (an `IdentityProvider` protocol the local/LDAP/Kerberos paths sit
   behind).** Rejected: speculative generality for a SAML implementation that is blocked regardless
   (below), bought with a refactor of shipped auth code, on a project with one maintainer. Revisit if a
   second federated protocol ever becomes real.
3. **A full external-identity spine, OIDC + SAML 2.0.** Best security analysis of the three, and its
   token-validation rigour is grafted in above — but ~2,000 engine LOC plus a three-backend migration
   for one login button.
4. **Cloud-only (non-hybrid) federated users.** Rejected for v1: requires `AuthProvider.OIDC`, the
   `_build_identity` coercion fix, a third `reauth()` arm, store parity, and a provider-qualified group
   map. Named here so the cost is known if the constraint ever bites.

**SAML 2.0 is declined for now, on XML-signature-wrapping grounds — not CSP grounds.** The existing
`parsing/xml/signature.py` verify path discards the verifier's return value and the caller re-reads the
original tree, which is the classic XSW footgun; a correct SP also needs reference resolution,
response-vs-assertion disambiguation, replay caching, metadata/cert rollover, and XML-Enc, and would
drag `lxml` + `signxml` out of an optional message codec into the always-loaded auth path. Recording the
*wrong* reason (a `form-action` CSP argument — `form-action 'self'` constrains submissions from
documents on **our** origin and does not block an IdP-served POST binding) would invite a future
reversal on a bad premise. Demand-gate trigger: **a named deployment whose IdP will not issue an OIDC
application registration for the console.**

## Consequences

**Positive** — Closes #99(g) with a real (IdP-asserted, signature-verified) MFA signal instead of an
inferred one. Delivers ADR 0079 mechanism 1 where the datum genuinely exists. Adds **no distribution**
to a hash-locked dependency set. Roles, revocation, and the group map stay single-sourced in on-prem AD.
Default-off and degradation-isolated, so the loopback posture is unchanged.

**Negative / risks** —
- Hand-rolled `id_token` verification is the highest-risk code in the change; a bug's failure mode is
  silent, total authentication bypass. Mitigations above are structural but not proof.
- **The engine verifies an assertion, not an enforcement.** A compromised or misconfigured IdP can
  assert `amr:["mfa"]` falsely. Strictly better than today's evidence-free `mfa_verified=True`, but the
  docs must never say "MFA was proven".
- **Step-up may be impossible for passwordless accounts.** `reauth()` for an AD identity re-binds with a
  password. If an org federates *because* its users are passwordless (WHfB/FIDO2) or smartcard-required,
  that bind cannot succeed and the user is permanently 403 on every step-up route — exactly the
  deployment shape that motivates federating. **This is tested in the lab and allowed to fail** (runbook
  cell L9). If it fails, the fallback (federated users needing admin writes retain a usable AD password,
  or admins use local accounts) is documented, and option 2 above is re-argued.
- **Enabling OIDC changes the ASVS 7.1.3 residual's premise.** The accepted register row reasons that
  "the shipped posture mints no federated session"; that becomes conditional the moment an operator sets
  `oidc_enabled=true`. The row's trigger language is updated in the same PR.
- **Flow state is process-local**, inheriting the WebAuthn single-API-process assumption. Behind a
  non-sticky load balancer a start-on-A/callback-on-B flow fails; it must fail legibly
  (`state_unknown`), not mysteriously.
- **This does not remove the on-prem AD dependency; it adds to it.** Every federated login still needs a
  reachable DC over LDAPS.
- The engine's own TLS trust for the IdP is a **build item**. *Corrected 2026-07-21 — the original
  wording here was factually wrong and is kept visible rather than silently rewritten, because the
  false version was the stated justification for `oidc_tls_ca_cert_file`.* It claimed
  `ssl.create_default_context()` "does not consult the Windows machine store". It does: CPython's
  `load_default_certs` iterates `('CA', 'ROOT')` on win32 (measured: **79 anchors** on a stock
  domain-joined box), so a group-policy-published AD-CS enterprise root **is** honoured. The genuine
  gaps are narrower — a self-signed IdP certificate in neither store is still untrusted, the anchors
  are a snapshot taken when the context is built (a root published later needs an engine restart), and
  there is no CryptoAPI chain building or AIA intermediate fetch. `oidc_tls_ca_cert_file` remains
  justified by the first of those; the other two are shared with every outbound hop in the engine.
- **`truststore` is deliberately not used for this hop**, despite being a base dependency and despite
  being what `apiclient` uses. Its `SSLContext` re-configures a *shared* inner context to
  `check_hostname=False` / `verify_mode=CERT_NONE` for the duration of each handshake and restores it
  when `wrap_socket` returns — but `_verify_peercerts` reads those attributes back off that shared
  context *after* the restore. The relying party shares one opener across `asyncio.to_thread` workers,
  so a concurrent federated login can observe `CERT_NONE` and skip certificate validation outright.
  On the hop that carries the identity assertion that is an authentication bypass, so the live-store
  benefit does not pay for it. (`apiclient`'s usage is not implicated by this build; it is a separate
  question against a different concurrency model.)

**Out of scope** — SAML 2.0 (above); cloud-only users; `AuthProvider.OIDC` and any store migration; a
JSON/API federated path (`/ui` only, matching the shipped `/ui/sso` vs `/auth/negotiate` asymmetry);
`.well-known` discovery (endpoints are operator-pinned, so no attacker-influenced URL exists and `kid`
never drives an SSRF); refresh tokens, `offline_access`, UserInfo, and any stored IdP token; back-channel
or RP-initiated logout and ADR 0079 mechanism 2; account linking, multi-IdP, dynamic client
registration; a periodic Kerberos preflight re-probe ([ADR 0068](0068-browser-webauthn-passkeys-offloopback.md)
open item 5 — **stays open**, and this ADR's non-sticky OIDC availability flag does **not** close it).

## To resolve on acceptance

- [ ] **Lab cell L9** — does step-up survive a passwordless / smartcard-required AD account? If not,
      record the documented fallback and re-argue option 2. **This gates flipping to Accepted.**
- [ ] **Lab cell L6a** — does the lab IdP accept a loopback redirect URI for a confidential client, and
      `code_challenge_method=S256`? If not, the engine needs an https origin and the EPA/proxy
      interaction re-enters scope.
- [ ] Settle the secret-reference key name: the house `<field>_secret` convention yields the absurd
      `oidc_client_secret_secret`; `oidc_client_secret_ref` is proposed, with no in-tree precedent for a
      field already ending in `_secret`.
- [ ] Decide whether `oidc_allowed_endpoints` earns its place given endpoints are already operator-pinned
      https — it ships only with named enforcement sites; a placebo control is worse than none.
- [x] **Availability recovery — RESOLVED (a), 2026-07-21.** The start leg attempts per-request and no
      login path gates on the flag; `oidc_available` is advisory and **non-sticky** (set by a failed
      IdP interaction, cleared by the next success). AC-8 requires recovery *without an engine
      restart*, and `kerberos_available` is boot-once and sticky-until-restart by design (ADR 0068
      §9), so mirroring it would have violated AC-8 by construction. Option (b) stays out of scope.
- [x] **Is `truststore` usable for the IdP CA — RESOLVED: no, 2026-07-21.** It *is* a base dependency
      (`pyproject.toml`), so availability was never the blocker; it is excluded for the shared-context
      verification race documented in *Consequences*. The unpinned branch uses
      `ssl.create_default_context()`, which does read the Windows machine store.
- [ ] **Lab cell L18 (new, 2026-07-21)** — attempt the username-collision attack against the real IdP:
      create/obtain a principal whose `preferred_username` local part matches a privileged on-prem
      sAMAccountName but whose UPN suffix is foreign, and confirm the login is refused with
      `username_domain_not_allowed` **before** any LDAP lookup. Also confirm a legitimate alternate
      UPN suffix in `oidc_allowed_username_domains` still succeeds. This cell exists because the
      control was added late, after a review found the omission was exploitable.
- [ ] Confirm whether `truststore` is a base dependency before relying on it for the IdP TLS-trust knob.
