# ADR 0083 — mTLS client-certificate identity (attested service-to-service authentication)

*(final ADR number assigned at merge — placeholder to avoid multisession churn)*

**Status:** Accepted (2026-07-10) — owner ratified. Model + resolver **built** (BACKLOG #200, PLAN-9
Wave 2); **activated** end-to-end (PLAN-9 Wave 3): a scope-populating shim now surfaces the verified peer
cert and a dedicated cert-only dependency gates a service-to-service route (see *Consequences → Activation*).
Formalizes and supersedes the inline sketch in
[ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §4.

## Context

ASVS 5.0 L3 cells 4.2.1 / 4.4.1 (verified client identity), 11.6.2 (KEX floor), 12.x. On an off-loopback
**Posture-B** bind (TLS terminated by an upstream proxy), the engine cannot self-verify two properties: the
**proxy→engine internal-hop** authentication, and the **browser↔proxy KEX floor** (it terminates no browser
TLS there). BACKLOG #200 tightened the serve gate so a **production-PHI** Posture-B start *refuses* unless
both are affirmatively declared (`[api].proxy_intra_service_auth` ≠ `none` **and** `proxy_tls_min_version`) —
attestations made fail-closed, mirroring the `require_mfa` PHI-prod ladder and ADR 0078's revocation gate.

This ADR formalizes the **identity** half: how a verified mTLS client certificate on a hardened internal hop
maps to a MessageFoundry principal. The owner ratified formalizing it as a dedicated ADR (the option ADR 0002
§4 left open).

## Decision

**Model.** With in-process mTLS (`[api].tls_client_ca_file`, which forces `ssl.CERT_REQUIRED`), a **verified**
peer certificate's subject/SAN maps to a principal via an explicit allow-list
`[api].tls_client_cert_identities` (`"CN:…"` / `"SAN:type:value"` → username; nested under the issuing
CA's DN since Amendment 1 below). Resolution
(`resolve_client_cert_identity`, [api/security.py](../../messagefoundry/api/security.py)) is:

- **deny-by-default** — an unmapped subject resolves to no identity;
- **namespace-qualified** — `CN:` and `SAN:` keys can never collide, defeating a spoofed-subject match;
- **rooted in TLS verification** — only `getpeercert()` on a `CERT_REQUIRED` socket returns a cert, so an
  unverified/self-signed cert never reaches the map;
- **fail-loud on misconfiguration** — a non-empty map *requires* `tls_client_ca_file` (validated at config
  load), so a map can never imply an unverified identity.

A new additive `AuthService.identity_for_username` turns the mapped username into an `Identity`, failing closed
on a disabled/unknown user. New settings are **TOML-only** (no env-string form — the map is never smeared
across process env).

**Trust boundary.** This is an **attested, service-to-service** identity for a hardened internal hop — *not*
an interactive-user login. It carries **no second factor, no session, and no step-up**.

**Server surfacing (the activation shim).** Stock uvicorn does **not** surface the peer certificate to the
ASGI scope (its `h11`/`httptools` implementations build `scope` with only `scheme` — no
`transport`/`ssl_object`, no ASGI-TLS extension), so the resolver was inert under the shipped server. The
pinned uvicorn cannot surface it without help, but it *can* be surfaced **without forking**: uvicorn copies
each protocol instance's `app_state` into `scope['state']` per request, and asyncio invokes
`connection_made` on an SSL transport only **after** the handshake completes. A minimal HTTP-protocol
subclass ([api/tls_client_cert.py](../../messagefoundry/api/tls_client_cert.py)) therefore reads
`transport.get_extra_info('ssl_object').getpeercert()` in `connection_made` and stashes the verified cert
under a private per-connection `scope['state']` key (never mutating the shared lifespan state, never placing
any PEM/secret in scope). `peer_cert_from_request` reads it back. We deliberately do **not** over-claim
ASVS 11.6.2 runtime KEX enforcement — the Posture-B intra-service-auth and KEX-floor checks remain operator
**attestations** made fail-closed.

## Consequences

- **Activated (PLAN-9 Wave 3), still fenced.** The resolver is live behind two pieces: (a) the
  scope-populating shim above, swapped in **only** when in-process mTLS (`tls_client_ca_file`) **and** a
  `tls_client_cert_identities` map are both configured — every other bind keeps the stock protocol; and
  (b) a dedicated **cert-only** dependency `require_service_cert` ([api/security.py](../../messagefoundry/api/security.py))
  wired onto a single non-interactive service route (`GET /service/identity`). **Critical constraint held:**
  `resolve_client_cert_identity` returns a **full-RBAC `Identity` with no MFA / no step-up / no session`, so
  it is NOT a drop-in for the bearer path. `require_service_cert` authenticates *only* the cert (never a
  bearer token), so the cert-identity plane and the session plane never cross — a cert client gets 401 on
  any `require`/`require_step_up`/PHI route, and `require_service_cert` additionally **refuses at app build**
  to gate any PHI-view permission. A cert-identity can therefore never satisfy a step-up-required or PHI
  route.
- **No weakening.** Loopback, synthetic, non-mTLS, and mutual-auth-only (client CA but no identity map)
  instances start byte-identically — the shim is never even instantiated. No new runtime dependency (stdlib
  `ssl` + the peer-cert dict shape).
- **Config surface:** `[api].tls_client_cert_identities`, `[api].proxy_intra_service_auth`,
  `[api].proxy_tls_min_version`, `[api].proxy_tls_ciphers` (coherence-validated via
  `validate_proxy_tls_posture`, [config/tls_policy.py](../../messagefoundry/config/tls_policy.py)).

See [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §0/§4 and
OFF-LOOPBACK-DEPLOYMENT.md.

## Amendment 1 (2026-09-28): the map is keyed by issuer (BACKLOG #2237)

**Why.** Owner ruling R7 (2026-09-28) holds that a client CA is an identity provider under ASVS V6.8.
Read that way, the map above had a gap. Its key named a subject but no issuer. With several CAs in
`[api].tls_client_ca_file`, two of them could each issue `CN=svc.internal`, and both certificates
reached the one account. Every CA in the bundle could speak for every mapped subject.

**Decision.** `[api].tls_client_cert_identities` is now nested: the outer key is the subject DN of the
CA certificate that verified the client's certificate, and the inner map is the qualified-name map
described above. In TOML:

```toml
[api.tls_client_cert_identities.'CN=Acme Service CA,O=Acme,C=US']
"CN:svc.internal" = "svc"
```

- **The issuer is the loaded CA that signed the leaf, not the leaf's issuer field.** The first
  design read the leaf's own issuer field from `getpeercert()`. Review showed that is unsound: the
  issuing CA writes that field, and OpenSSL matches it to a trusted CA loosely (case and whitespace
  folded). So a second trusted CA named `CN=ACME   CA` could sign a leaf whose field reads
  `CN=Acme CA`, and it mapped under `CN=Acme CA`. `IssuerIndex` in
  [pki.py](../../messagefoundry/pki.py) now indexes the CAs loaded from `tls_client_ca_file` once,
  when the API context is built, and names the one whose subject equals the leaf's issuer name
  exactly AND whose key verifies the leaf's signature (`verify_directly_issued_by`). A client
  certificate loaded as an anchor itself names itself.
- **Not the verified chain either.** A second design read `SSLObject.get_verified_chain()`. Review
  measured that on a RESUMED TLS session (1.2 and 1.3) OpenSSL keeps the peer certificate but not
  the chain, so every connection after a client's first was denied. The index needs only the leaf.
- **Only a loaded CA counts.** A client-sent intermediate never does, because any trusted CA could
  mint one carrying another CA's exact name. An operator whose client certificates come from an
  intermediate loads that intermediate and names it.
- **`serve` warns about a key that can never match**: one naming no loaded CA, or naming two loaded
  CAs with one subject, as a rollover does. Either would otherwise deny every certificate under it
  with nothing in the log.
- **Two loaded CAs with one name are ambiguous.** When another loaded CA certificate carries the same
  subject, the map cannot tell the two apart, so neither names an issuer.
- **One canonical form, compared exactly.** The DN is `cryptography`'s `Name.rfc4514_string()` of
  that certificate's subject. The loader parses each key with `Name.from_rfc4514_string()` and
  refuses one that round-trips to a different string, naming the string to write. A key that
  parser cannot read at all passes, since it rejects some names its own renderer prints for real
  CAs; the start-time warning covers it. Write the key TOML-single-quoted, so its backslashes stay
  as written.
- **The loader refuses what cannot match.** A flat entry with no issuer, an empty issuer, a key that
  is not an RFC 4514 name, an issuer with no names, a name no certificate can carry, and an empty or
  space-padded value are all refused at load.
- **The matcher looks only under the verified issuer.** `client_cert_principal_under_issuer` in
  [credential.py](../../messagefoundry/credential.py) reads the recorded issuer, selects its inner
  map, then applies the unchanged qualified-name match. It never reads the leaf's issuer field.
- **No compatibility shim.** The flat shape is refused rather than read. Nothing is deployed, so the
  break costs no one.

**What this does not close.**

- The loader cannot check RDN order. A DN written in certificate order parses and never matches.
- The key is a name, so a CA that is loaded twice under one name names no issuer rather than two.
  Keying by certificate fingerprint would avoid that, at the cost of a key an operator cannot read.
- The inbound HTTP listener's `intake_client_subjects` (ADR 0154) still matches a subject from any CA
  its listener trusts. It is a separate surface and was not in this change.
