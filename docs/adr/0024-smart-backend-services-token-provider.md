# ADR 0024 — SMART Backend Services token provider (OAuth2 client-credentials, signed-JWT client assertion) for the FHIR/REST outbound

- **Status:** **Accepted (2026-06-20); built and shipped (PR #432).** It is the bounded **client-side** OAuth2 layer that ADR
  0022's "Out of scope — SMART-on-FHIR OAuth2 flows" line deferred, and the concrete shape of the remaining
  [FEATURE-MAP.md](../FEATURE-MAP.md) §7 SMART item. Build may start once this ADR is **Accepted**; it depends
  **only** on the already-shipped ADR 0022 transport + ADR 0018 signing core.
- **Built (this ADR):** **shipped (PR #432)** — the SMART Backend Services token provider in [transports/smart.py](../../messagefoundry/transports/smart.py) (`with_smart_backend`). It layers a token-acquisition step onto **already-shipped** substrate:
  - the FHIR/REST outbound destinations ([transports/fhir.py](../../messagefoundry/transports/fhir.py),
    [transports/rest.py](../../messagefoundry/transports/rest.py)) that already POST/PUT FHIR over hardened,
    TLS-verifying, no-redirect, egress-gated HTTP — and already carry an `Authorization` header (static
    `bearer_token` today);
  - the per-connection JWS signing core ([transports/signing.py](../../messagefoundry/transports/signing.py),
    ADR 0018): `_load_private_key`/`_require_key_for_alg`/`_sign` already mint RSA/ECDSA signatures from an
    `env()`-supplied PEM on **core `cryptography` only** — no new dependency;
  - the `env()`/`EnvRef` secret path (`EnvRef` [config/wiring.py:141](../../messagefoundry/config/wiring.py),
    `env()` :154, `resolve_env_settings` :422, `_SECRET_SETTING_KEYS` :487) and the `redacted_settings` scrubber
    that keeps secrets out of `/metadata`.
- **Decision in one line:** add a pluggable **SMART Backend Services** token provider — mint a signed
  `client_assertion` JWT, exchange it at the authorization server's **token endpoint** for a short-lived bearer
  access token (`grant_type=client_credentials`), cache it with expiry awareness, and **inject it per-request**
  into the FHIR/REST destination's existing `Authorization` seam — by **extending the ADR 0018 signing core**
  (adding `RS384`/`ES384` + an **attached compact JWT** encoding) and reusing rest.py's hardened opener + the
  fail-closed egress gate, with **every secret via `env()`**. **No** App Launch, **no** authorization/resource
  **server**, **no** inbound facade.
- **Related:** [ADR 0022](0022-fhir-resource-codec-rest-client.md) (the FHIR codec + outbound REST client this
  authenticates; its `bearer_token` seam and "SMART-on-FHIR OAuth2 flows → later" out-of-scope line),
  [ADR 0018](0018-per-message-signatures-accepted-risk.md) (the detached-JWS signing core + the "core
  `cryptography`, no new dependency" posture this extends), [ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md)
  (the **value-placement contract** — a per-call non-deterministic credential is minted in `send()` past the
  queue boundary, never in a pure transform), [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (the REST
  destination + `[egress].allowed_http` gate the token endpoint must also pass), [ADR 0001](0001-staged-pipeline-architecture.md)
  (the at-least-once/purity invariant the per-request mint preserves), ADR 0023 (the **inbound** FHIR server
  facade — a *separate, deferred, not-yet-written* decision; this ADR is client-only and needs nothing from it),
  [CLAUDE.md](../../CLAUDE.md) §6/§8/§9 (asyncio-non-blocking, HL7/FHIR version-explicitness, never-log-secrets/PHI),
  [FEATURE-MAP.md](../FEATURE-MAP.md) §7, [BACKLOG.md](../BACKLOG.md) #35.

## Context

ADR 0022 shipped the FHIR data plane: a FHIR resource codec and an **outbound FHIR REST destination** that
delivers `Patient`/`Observation`/`Bundle`/… to a downstream FHIR server. Its authentication is a **static
credential** — `_build_headers` ([fhir.py:233-247](../../messagefoundry/transports/fhir.py),
[rest.py:188-204](../../messagefoundry/transports/rest.py)) reads a `bearer_token` (or basic creds) from
`env()` **once at connector construction** and freezes it into `self._headers` for the connector's lifetime.

That is sufficient for a partner that issues a long-lived API key, but it does **not** reach a real
**SMART-secured FHIR server**. Epic and Oracle Health (Cerner) — the two endpoints that matter for a migration
estate — both require **SMART Backend Services** authorization (HL7 SMART App Launch IG **v2.2.0**,
`backend-services.html` + `client-confidential-asymmetric.html`) for server-to-server, no-human access:

1. The client (mefor) pre-registers a **public key** with the server (out of band, via a JWKS the operator
   publishes/registers; not the engine's concern in this ADR).
2. At call time the client signs a one-time **`client_assertion` JWT** — the spec's five mandated claims
   `iss = sub = client_id`, `aud = token endpoint URL`, `exp ≤ 5 min`, and a unique `jti` (an `iat` is optional
   hygiene we may add, **not** spec-required) — with its **private** key. SMART **SHALL** support **`RS384`** and
   **`ES384`** (note: SHA-**384**, not the SHA-256 the ADR 0018 signer currently mints).
3. The client `POST`s `grant_type=client_credentials`,
   `client_assertion_type=urn:ietf:params:oauth:client-assertion-type:jwt-bearer`, `client_assertion=<jwt>`, and
   `scope=system/…` to the **token endpoint** (a host *distinct from* the FHIR base URL).
4. The server returns a **short-lived** bearer (`expires_in` **SHOULD NOT exceed 300 s** — a five-minute
   ceiling), and — per spec — **SHOULD NOT** issue a refresh token. The client **re-mints** by re-running the
   cheap assertion exchange when the token nears expiry.

So a static `bearer_token` in `env()` goes stale within minutes against these servers; nothing in the engine
acquires or renews a token. **This token-acquisition step is the one real gap** between "FHIR is built" and
"can deliver to a production SMART-secured FHIR API."

**What is *not* the gap (scope discipline).** SMART on FHIR is an OAuth2 *authorization* profile, not a data
format — and most of it exists to authorize a **third-party app acting for a human user** (browser
authorization-code redirect, mandatory PKCE, EHR/standalone launch, `launch/patient` context, OIDC `fhirUser`
login, user refresh tokens). A headless integration engine has no human, no browser, no EHR session — that
apparatus is **out of an engine's lane**, and no comparable engine (Mirth, Cloverleaf, Corepoint) ships it.
Hosting a FHIR API that SMART apps launch *against* (publishing `.well-known/smart-configuration`, running the
authorization/resource server, enforcing scopes) is the system-of-record's job and, for mefor, additionally
requires the **unbuilt inbound facade (the deferred, not-yet-written ADR 0023)**. This ADR builds **only** the machine-to-machine client
slice — `client_credentials` + signed-JWT assertion — which is exactly the no-human path.

## Decision (proposed)

A pluggable **SMART Backend Services token provider**, wired through existing seams. The FHIR/REST destination
gains an optional token provider that, when present, supplies a fresh bearer on every request; everything else
about the connector is unchanged. The pieces:

### 1. A code-first composer `with_smart_backend()` (mirrors `with_signing()`)

Authoring is one call layered over `Rest()`/`FHIR()`, exactly like `with_signing()`
([signing.py:279](../../messagefoundry/transports/signing.py)) — so the factory signatures (`Rest()`
[wiring.py:796](../../messagefoundry/config/wiring.py), `FHIR()` [wiring.py:839](../../messagefoundry/config/wiring.py))
are **untouched** and the auth is opt-in:

```python
from messagefoundry import FHIR, env, outbound
from messagefoundry.transports.smart import with_smart_backend

outbound("OB_EPIC_FHIR", with_smart_backend(
    FHIR(url=env("epic_fhir_base"), interaction="create"),
    token_url=env("epic_token_url"),       # the authorization server token endpoint
    client_id=env("epic_client_id"),
    scope="system/*.rs",                    # SMART v2 scopes; system/ = no-human
    private_key=env("epic_smart_key"),      # inline PEM via env(), or a PEM file path
    algorithm="RS384",                      # SMART SHALL: RS384 (default) | ES384
    key_id="epic-2026",                     # kid → the public key the server has registered
))
```

It writes flat `smart_*` settings into the spec (the `with_signing` pattern):
`smart_enabled`, `smart_token_url`, `smart_client_id`, `smart_scope`, `smart_algorithm`,
`smart_private_key`, `smart_private_key_password`, `smart_key_id`, and optional `smart_audience` (defaults to
`smart_token_url` per spec) and `smart_expiry_skew_seconds` (default 60). `token_url`, `client_id`,
`private_key`, and `private_key_password` may be `env()` refs. The composer accepts a `FHIR`/`Rest` spec only
(the two HTTP outbounds with an `Authorization` seam); any other type raises at authoring, like `with_signing`'s
REST/SOAP guard.

### 2. Extend the ADR 0018 signing core — `RS384`/`ES384` + an attached compact JWT

The `client_assertion` is itself a signed JWT, so the crypto belongs with the existing signer — **reuse, do not
re-implement**:
- Add **`RS384`** and **`ES384`** to `SignatureAlgorithm` ([config/models.py]) and the SHA-**384** branches to
  `_sign`/`_verify` ([signing.py:141/162](../../messagefoundry/transports/signing.py)) beside the existing
  SHA-256 ones (`ES384` is ECDSA on **P-384/secp384r1**, a 96-byte `r‖s`; relax `_require_key_for_alg`'s
  P-256-only curve check accordingly). `_load_private_key`/`_read_key_material`/`_b64u_*` are reused verbatim.
- Add an **attached compact JWS** encoder beside `detached_jws` ([signing.py:212](../../messagefoundry/transports/signing.py)):
  `BASE64URL(header) || '.' || BASE64URL(claims) || '.' || BASE64URL(signature)` (the payload segment is the
  base64url claim set — *not* empty as the detached form requires). The header carries `{"alg", "typ":"JWT",
  "kid"}`. This is a sibling function; the detached path REST/SOAP signing uses is unchanged.
- The `with_signing()` REST/SOAP gate ([signing.py:307-310](../../messagefoundry/transports/signing.py)) is
  **irrelevant** here — the token provider is a separate code path, not message signing.

The claim set (`{iss=sub=client_id, aud, exp=now+≤300s, jti=secrets.token_urlsafe(...)}` — the spec's five
mandated claims; an `iat` is optional hygiene, not spec-required) is minted fresh per token request; `exp ≤ 5
min` and a random `jti` are the spec's replay defenses.

### 3. The token provider — `transports/smart.py`

A new module (a sibling of `rest.py`/`signing.py`; **never** imports `api`/`console`; imports `config`, the
signing core, and rest.py's opener — the allowed direction):

- `SmartBackendTokenProvider.from_destination(config) -> SmartBackendTokenProvider | None` — built when
  `smart_enabled`, else `None` (every existing outbound unchanged), mirroring `signer_from_destination`. The key
  is loaded + validated **at construction** (a bad key/curve fails loud at `check`/dry-run/start, like a TLS
  cert).
- `access_token() -> str` (sync, called inside the connector's off-loop `send()` worker): returns a cached
  token if it is still valid past the skew; otherwise mints a `client_assertion`, `POST`s the token request to
  `smart_token_url` over **rest.py's `_NO_REDIRECT_OPENER`** (TLS-verified, redirect-refusing — a 3xx on a token
  fetch is refused, the same PHI/credential-redirect defense the data path uses), parses `access_token` +
  `expires_in`, caches, and returns it. A non-2xx / malformed token response raises `DeliveryError` (transient —
  the next delivery retry re-attempts) with a **PHI/secret-safe** message (status + redacted token-host only,
  **never** the response body, which may carry the token or error detail).
- A small lock guards the cache (one delivery worker per outbound means little real contention, but
  `test_connection`/`_probe` can also call — cheap insurance).

### 4. Inject per-request in `_post`, not in `_build_headers`

Because the token now **expires**, it must be applied per request — `_build_headers` is frozen at construction.
Mirror the existing signer hook in `_post` — **illustrative target shape**: fhir.py's
`_post(self, payload, method, url, extra_headers)` ([fhir.py:358](../../messagefoundry/transports/fhir.py))
already merges `extra_headers`, while rest.py's `_post(self, payload)`
([rest.py:242](../../messagefoundry/transports/rest.py)) currently builds `headers = self._headers` and gains the
same injection:

```python
headers = {**self._headers, **extra_headers}
if self._token_provider is not None:
    headers["Authorization"] = f"Bearer {self._token_provider.access_token()}"  # overrides any static bearer
if self._signer is not None:
    headers = {**headers, **self._signer.signature_headers(data)}
```

The mint + token `POST` happen inside `send()`'s `asyncio.to_thread` worker
([fhir.py:322](../../messagefoundry/transports/fhir.py), [rest.py:208](../../messagefoundry/transports/rest.py))
— **past the staged-queue boundary**, exactly where ADR 0015/0018 mint the WS-Security nonce and the JWS
signature. A re-run/retry re-mints the token; routers and transforms stay pure and the **at-least-once
invariant holds** (ADR 0001). **Re-mint on 401 (a *new* `_post` branch):** today `_post` has **no** 401-specific
handling — it dead-letters a 401 as a *permanent* `NegativeAckError` (rest.py via the "other 4xx" arm,
[rest.py:264-274](../../messagefoundry/transports/rest.py); fhir.py via `_classify_fhir`,
[fhir.py:378-387](../../messagefoundry/transports/fhir.py)); only `_probe` labels a 401/403 "check credentials"
([fhir.py:346-348](../../messagefoundry/transports/fhir.py), [rest.py:232-234](../../messagefoundry/transports/rest.py)).
The backstop therefore **adds** a 401 branch to `_post`: when a token provider is present, invalidate the cached
token and raise a *transient* `DeliveryError` so the next retry fetches a fresh one (covering a token that
expired between mint and use). `_probe` ([fhir.py:334](../../messagefoundry/transports/fhir.py)) likewise fetches
a token before its metadata GET so reachability reflects real credentials.

### 5. The token endpoint is a second egress host — gate it (security parity)

`check_egress_allowed`/`_allowlist_for` ([wiring_runner.py:1635-1639](../../messagefoundry/pipeline/wiring_runner.py))
today gate `dest.settings.get("url", "")` — the **FHIR base**. The `smart_token_url` is a **distinct host** the engine
also connects to; left ungated it is a fail-open egress (an SSRF-shaped hole — a crafted config could point the
signed-assertion `POST` anywhere). The egress check **must also** validate `smart_token_url` against
`[egress].allowed_http` when `smart_enabled`. This is the load-bearing security edit — the direct analog of ADR
0022 §3.4's reason for folding FHIR into the `allowed_http` arm.

### 6. Secrets & PHI

Add `smart_private_key` and `smart_private_key_password` to `_SECRET_SETTING_KEYS`
([wiring.py:487](../../messagefoundry/config/wiring.py)) so `redacted_settings` scrubs them from `/metadata`
(the minted **access token** and **client_assertion** are runtime-only and **never** persisted or logged —
mirror `_redact_url`; a token-endpoint failure logs status + redacted host only). No message body is involved,
so this is a **secret**-handling rule (the token is a bearer credential), parallel to the §9 PHI rule.

## Options considered

1. **SMART Backend Services token provider (CHOSEN) vs static bearer only vs full SMART App Launch.** Static
   bearer is what exists and is insufficient for Epic/Oracle (short-lived tokens). Full App Launch
   (authorization-code + PKCE + launch context + OIDC) authorizes a **human-user app** — there is no human in a
   headless engine, so it is out of lane and unbuildable without a browser/user session. **CHOSEN:** the
   machine-to-machine `client_credentials` + signed-assertion slice only.
2. **A composer `with_smart_backend()` (CHOSEN) vs flat kwargs on `FHIR()`/`Rest()` vs a generic OAuth2 client
   object.** A multi-field auth flow as flat factory kwargs would bloat two signatures; the established pattern
   for opt-in outbound auth is the `with_signing()` composer. **CHOSEN:** a composer, settings flattened as
   `smart_*` (the `sign_*` precedent).
3. **Extend `signing.py` on core `cryptography` (CHOSEN) vs add a JWT library (PyJWT/Authlib) vs hand-roll a
   third copy.** signing.py already loads RSA/EC PEMs and mints JOSE signatures; adding SHA-384 + an attached
   compact encoder reuses vetted code and keeps ADR 0018's **no-new-dependency** posture (no `PyJWT`/`Authlib`
   to verify/license/lock). **CHOSEN:** extend the signer; the JWT path is a sibling of the detached path.
4. **Proactive expiry-skew refresh + 401 backstop (CHOSEN) vs reactive-on-401-only vs refresh tokens.** Backend
   Services issues **no** refresh token (re-mint is the mechanism). Proactive skew-based renewal avoids a
   guaranteed 401 on every expiry; the 401 path is the backstop for clock skew between mint and use. **CHOSEN.**
5. **Explicit `token_url` at MVP (CHOSEN) vs mandatory `.well-known/smart-configuration` discovery.** Fetching
   the discovery doc to resolve the token endpoint is a small, deterministic later add; an explicit, `env()`-set
   `token_url` is testable and avoids a startup network dependency. **CHOSEN (MVP):** explicit URL; discovery is
   a deferred increment (and is itself a *client-side consume*, not the server-side *publish* that belongs to
   ADR 0023).
6. **Reuse rest.py's hardened opener + extend the egress gate to `token_url` (CHOSEN) vs an unguarded token
   fetch.** The token endpoint is a second egress host; reusing the no-redirect/TLS opener and adding it to
   `allowed_http` closes the fail-open hole. **CHOSEN.**

## Consequences

**Positive**
- **Real Epic/Oracle FHIR delivery.** Closes the one gap between "FHIR is built" and "can push/pull against a
  production SMART-secured FHIR API."
- **No new dependency.** Reuses core `cryptography` via the ADR 0018 signer and rest.py's stdlib `urllib`
  opener — nothing to verify/license/hash-lock/audit (DEP-1 untouched).
- **Generic by construction.** `client_credentials` + `private_key_jwt` + bearer injection is generic OAuth2
  that SMART Backend Services *profiles* — so the same provider authenticates any OAuth2-secured REST/FHIR
  endpoint, not only SMART servers.
- **Purity + at-least-once preserved.** The token is minted in `send()` past the queue boundary (like the JWS
  signature / WS-Security nonce), so routers/transforms stay pure and a retry simply re-mints.
- **Unlocks Bulk Data `$export` later.** `$export` delegates its auth to the *same* Backend Services flow — a
  future read/export client reuses this provider with no second auth effort.

**Negative / risks**
- **The token endpoint is a second egress host.** Mitigated by gating `smart_token_url` through
  `[egress].allowed_http` (§5) — but it is net-new attack surface that operators must allowlist.
- **Clock-skew sensitivity.** `exp ≤ 5 min` and short-lived tokens make the engine clock load-bearing; a badly
  skewed host gets `invalid_client`/401. The expiry skew + 401 re-mint bound it; operators must run NTP.
- **Per-connector token state + a network call on the delivery path.** A cached token is connector-local mutable
  state (guarded by a lock) and the first request (and each renewal) adds a token round-trip latency. Confined
  to the off-loop worker; does not touch the event loop.
- **Secret-leak risk in error/log paths.** The access token and `client_assertion` are bearer credentials; a
  careless log line could leak one. The §6 rule (token never logged/persisted; status + redacted host only;
  `smart_private_key*` in `_SECRET_SETTING_KEYS`) is a hard invariant covered by review and a test.
- **Crypto surface widens slightly.** Adding `RS384`/`ES384` + P-384 to the signer is small but must be tested
  (sign/verify round-trips, the attached-compact JWS shape, a wrong-curve/wrong-key rejection).

**Out of scope (deferred / explicitly NOT promised)**
- **SMART App Launch** — authorization-code + PKCE, EHR/standalone launch, `launch/patient` context, OIDC
  (`openid`/`fhirUser`/`id_token`), user refresh tokens. Human-user-app only; never an engine concern.
- **SMART authorization/resource *server*** — publishing `.well-known/smart-configuration`, running the authZ
  server, enforcing scopes, token introspection (RFC 7662). The system-of-record's role; for mefor it also
  needs the inbound facade (the deferred ADR 0023).
- **JWKS hosting / key-rotation endpoint** — the operator registers the **public** key with the FHIR server out
  of band; the engine holds only the private key (via `env()`) and names it with `kid`.
- **`.well-known/smart-configuration` discovery** — explicit `token_url` at MVP; auto-discovery is a later
  increment.
- **SMART Bulk Data `$export`** — unlocked by this provider but built later (it is also a *read* client, which
  ADR 0022 deferred).
- **Symmetric client authentication** (`client_secret_basic`/`client_secret_post`) — Backend Services mandates
  asymmetric; a symmetric fallback for non-SMART OAuth2 servers is a possible later add, not in scope.

## To resolve on acceptance

- **Confirm the ADR number is 0024** and the **client-only** scope boundary (App Launch + server facade stay
  out; the server facade is the separate, deferred ADR 0023); add the `Proposed` row to
  [docs/adr/README.md](README.md).
- **Confirm the composer name `with_smart_backend()`** and the `smart_*` settings keys; add `smart_private_key`
  + `smart_private_key_password` to `_SECRET_SETTING_KEYS`.
- **Confirm `RS384` default + `ES384`** are added to `SignatureAlgorithm`, with the SHA-384 / P-384 branches in
  `_sign`/`_verify`/`_require_key_for_alg`, and the **attached compact JWS** encoder placed beside `detached_jws`
  (the detached REST/SOAP path unchanged).
- **Confirm the `smart_token_url` is gated** through `[egress].allowed_http` in
  `check_egress_allowed`/`_allowlist_for` (no second fail-open egress).
- **Confirm per-request injection in `_post`** (not `_build_headers`), the proactive expiry-skew refresh, and the
  **re-mint-on-401** backstop in both `fhir.py` and `rest.py`.
- **Confirm no new dependency** — core `cryptography` + stdlib `urllib` only.
- **Decide the `.well-known/smart-configuration` discovery posture** — ship optional discovery in the MVP, or
  defer and require an explicit `token_url` (the recommended default).
- **Confirm the PHI/secret rule** — the minted access token + `client_assertion` are never logged/persisted; a
  token-endpoint failure surfaces status + redacted host only (a test asserts no token in logs/`/metadata`).
- **Build order on go** (each behind the standard quartet gate — `ruff format --check` · `ruff check` · `mypy
  messagefoundry` · `pytest` with `QT_QPA_PLATFORM=offscreen`): (1) extend `signing.py` (`RS384`/`ES384` +
  attached compact JWS) with sign/verify round-trip tests; (2) `transports/smart.py`
  (`SmartBackendTokenProvider`) with a stubbed token endpoint + the secret-no-log assertion; (3) wire the
  provider into `fhir.py`/`rest.py` `_post` + `_probe`, the `with_smart_backend()` composer, and the egress-gate
  arm; (4) docs — a `### SMART Backend Services` subsection in [CONNECTIONS.md](../CONNECTIONS.md), the
  FEATURE-MAP §7 split, a sample `outbound(...)` config, and flip this ADR's [README.md](README.md) row to
  Accepted.

## Amendment (2026-07-12) — generic outbound HTTP auth (BACKLOG #65)

The SMART provider proved the **bearer-token seam** on the HTTP destinations (mint + cache a short-lived
bearer, inject `Authorization: Bearer …` per request off-loop past the queue boundary). #65 generalizes
outbound HTTP auth into a small **pluggable provider seam** ([`transports/http_auth.py`](../../messagefoundry/transports/http_auth.py)),
additive and **off by default → byte-identical**, selected per connection on REST/SOAP/FHIR.

**Built.**

- **OAuth2 client-credentials with a SYMMETRIC `client_secret`** — `OAuth2ClientCredentialsProvider`, a
  `BearerTokenProvider` (the same `access_token()` / `invalidate()` structural interface the SMART provider
  already satisfies), so it slots into the destinations' **existing** per-request bearer-injection seam with
  no new plumbing. `client_secret_basic` (default) / `client_secret_post`; mint + cache + re-mint on `401`;
  the token endpoint is refused over cleartext `http`. `bearer_provider_from_settings` unifies SMART +
  OAuth2-CC and enforces they are **mutually exclusive** on one connection. Composer:
  `with_oauth2_client_credentials()` (mirrors `with_smart_backend`).
- **HTTP Digest (RFC 7616)** — the stdlib `urllib.request.HTTPDigestAuthHandler` answers the endpoint's
  `401` challenge and retries within one `opener.open()` (Digest is request-oriented, no connection pinning).
  Folded into a **per-connection** opener (never the shared `_NO_REDIRECT_OPENER`); refused over cleartext
  `http`; mutually exclusive with a bearer provider. Composer: `with_http_digest()`.

**Secrets.** `oauth2_client_secret` / `http_auth_password` are `env()`-resolved and redacted (added to
`_SECRET_SETTING_KEYS`); the minted bearer / digest response are runtime-only, never logged or persisted.
**No new dependency** — stdlib `urllib` + rest.py's hardened, TLS-verifying, no-redirect opener.

**Scoped out — NTLM / Negotiate.** NTLM's handshake is **connection-bound** (the type1/type2/type3 legs
must ride one keep-alive TCP connection). `urllib.request` opens a **fresh connection per `open()`**, so it
structurally cannot carry the handshake — a correct build needs a keep-alive HTTP client driven by
`pyspnego` (already in `requirements.lock`, backing the AD/SSO server path). Deferred as a follow-up; the
provider seam here is shaped to admit it (a challenge/response plug alongside the bearer + digest plugs).
