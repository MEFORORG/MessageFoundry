# ADR 0015 — WS-* SOAP outbound (mutual-TLS client cert + WS-Security / WS-Addressing)

- **Status:** **Accepted (2026-06-15)** — ratified on the owner's "go"; the open questions below are resolved. **No code written yet** (build authorized; not started).
- **Resolved open questions (owner go, 2026-06-15):** (1) **Fragment validation** = the hardened, non-resolving, no-DTD well-formedness check on the isolated `<Body>` (XXE-negative, and it still catches a malformed HL7-derived body) — adopted over the zero-parser balance check. (2) **XML-DSig body signing stays deferred** to a follow-up ADR (it needs a non-stdlib C14N+RSA dependency, which would breach ADR 0003's stdlib-only rule); a stable engine-side **idempotency key is designed alongside it**, not now. (3) **UsernameToken default = `ws_password_type="text"`** (PasswordText over mutual TLS); `PasswordDigest` is opt-in for partners that mandate it. (4) **WS-\* requires SOAP 1.2** — the `Soap()` factory raises on `soap_version="1.1"` when `ws_addressing`/`ws_security` is set. (5) **Egress gate** keeps the project-wide *fail-closed-once-configured* framing (no special hard-require); a `docs/CONNECTIONS.md` warning + dry-run surfacing flag a PHI mTLS destination whose `[egress].allowed_http` is empty. (6) **Idempotency** = accept that an at-least-once re-send mints a fresh `<wsa:MessageID>` (correct WS-\* retry semantics); the partner's submit operation must dedup — a stable engine-side key is deferred with #2.
- **Built:** nothing yet. This document is the design only.
- **Decision in one line:** add an **opt-in WS-\* mode to the existing SOAP destination**
  ([`transports/soap.py:92`](../../messagefoundry/transports/soap.py)) — **not** a new connector type — so
  it gains (a) a **per-connection client-certificate TLS opener** for mutual TLS and (b) a transport that
  **stamps the non-deterministic WS-Addressing / WS-Security headers at `send()` time** around a
  Handler-built `<Body>`, keeping the credential-bearing and non-deterministic parts out of the pure
  transform; envelope assembly stays **stdlib string templating** (no XML parser, matching the regex-only
  status quo); response capture / re-ingress reuse [ADR 0013](0013-query-response-orchestration.md) unchanged.
- **Related:** [ADR 0003](0003-non-hl7-transports-database-rest-soap.md) (the SOAP destination + the
  stdlib-only HTTP plumbing this extends), [ADR 0013](0013-query-response-orchestration.md) +
  [ADR 0013 Increment 2](0013-increment-2-reingress-design.md) (capture the partner's reply as a
  `DeliveryResponse`, optionally re-ingress it), [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)
  (the transport-TLS posture — `insecure_tls_allowed()` escape, TLS 1.2+ floor — this mirrors),
  [ADR 0012](0012-x12-edi-codec.md) (the precedent that a pure codec stays out of the pipeline; here the
  WS-\* envelope wrapper is a transport concern, not a stage), [ADR 0007](0007-gui-manageable-connections-toml.md)
  (the new settings desugar through the same `Soap()` factory and resolve secrets via `env()`/DPAPI),
  [CLAUDE.md](../../CLAUDE.md) §2 (the **re-run-purity / at-least-once** + **count-and-log** +
  **dependency-direction** invariants this must not break) and §9 (PHI: the envelope is PHI — encrypted at
  rest, never logged at INFO+).

## Context

A common class of certificate-authenticated SOAP web service (for example a state immunization registry
submission service, or an eligibility / order clearinghouse with a hardened WS-\* contract) requires more
than the current thin "POST a Handler-built envelope" SOAP destination provides:

1. **Mutual TLS.** The engine must present a **client certificate + private key**, validated by the peer.
   The current SOAP destination only does **server**-cert verification: `verify_tls=True` selects REST's
   `_NO_REDIRECT_OPENER` ([`transports/soap.py:118-119`](../../messagefoundry/transports/soap.py)), which
   has no `load_cert_chain` — there is **no client-cert path** anywhere on the HTTP egress side. (mTLS
   *does* exist elsewhere: the API server identity at [`api/tls.py:32`](../../messagefoundry/api/tls.py),
   and an outbound MLLP client cert at [`transports/mllp.py:352-353`](../../messagefoundry/transports/mllp.py) —
   precedents to reuse, not the HTTP path.)
2. **WS-Security** headers — at minimum a `<wsu:Timestamp>` (Created / Expires) and often a
   `<wsse:UsernameToken>`; sometimes a signature — and **WS-Addressing** headers (`<wsa:Action>`,
   `<wsa:To>`, `<wsa:MessageID>`).
3. A specific submit-style SOAP **operation** that wraps an HL7 v2 payload: the HL7 message becomes the
   body of a `submit`/`update` operation.
4. **Synchronous response/error capture**: the operation returns a confirmation or an error to be
   reconciled (or routed).

### The central tension: re-run purity vs. per-call non-deterministic headers

`<wsa:MessageID>` (a fresh UUID/URN per call), the `<wsu:Timestamp>` Created/Expires window, and any
WS-Security `<wsse:Nonce>` / `<wsu:Created>` are **per-call and non-deterministic**. The staged queue is
**at-least-once** and **re-runs a stage after a crash**, so the reliability invariant
([CLAUDE.md](../../CLAUDE.md) §2) forbids a **pure Router/transform** from producing any such value: a
crash-replay of the transform stage must re-derive **byte-identical** output, which a nonce or wall-clock
timestamp cannot. The existing SOAP destination already lives on the correct side of that boundary — it
runs in the **delivery worker, after the queue handoff**, not in the transform
([`transports/soap.py:156`](../../messagefoundry/transports/soap.py) is `send()`, invoked by the
per-outbound worker). So the WS-\* non-determinism **belongs in the transport's `send()`**, never in the
Handler. **That single value-placement decision (§1) is the spine of this ADR** — it, not any string scan,
is what guarantees re-run purity.

### Why this is additive, not a new connector

A new `ConnectorType.WSSOAP` would re-implement everything `soap.py` already owns: the SOAP 1.1/1.2
`Content-Type` + `SOAPAction` handling ([`soap.py:132-143`](../../messagefoundry/transports/soap.py)), the
`_classify_soap` Sender/Receiver fault routing ([`soap.py:70`](../../messagefoundry/transports/soap.py)),
the reused no-redirect opener, `refuse_cleartext_credentials`
([`rest.py:93`](../../messagefoundry/transports/rest.py)), and the ADR 0013 capture branch
([`soap.py:161-173`](../../messagefoundry/transports/soap.py)). It would also have to **re-earn two engine
guards that are keyed on `ConnectorType.SOAP`**:

- the **egress allowlist** branch [`wiring_runner.py:1490`](../../messagefoundry/pipeline/wiring_runner.py)
  is `dest.type in (ConnectorType.REST, ConnectorType.SOAP) and egress.allowed_http`. A *new* type would
  **fall through that `elif` chain and not be gated at all** — a fail-**open** egress hole, the inverse of
  the invariant — unless the branch is also amended. (See §6 for the important nuance that this branch is
  fail-closed *only once `allowed_http` is configured*.)
- the **capture-parity start guard** [`wiring_runner.py:382`](../../messagefoundry/pipeline/wiring_runner.py)
  refuses a capturing outbound on a backend that can't persist captures; it keys
  on the connector's `capture_response` attribute, which a new type would also have to expose.

Extending `ConnectorType.SOAP` **inherits both guards for free**. mTLS + WS-\* is purely additive: a
different opener and an envelope wrapper. This is the maximum-composition choice — smallest diff, zero new
`pipeline/`, `store/`, or `ConnectorType` surface.

## Decision

Extend the **existing** `SoapDestination` ([`transports/soap.py:92`](../../messagefoundry/transports/soap.py))
and its `Soap()` factory ([`config/wiring.py:928`](../../messagefoundry/config/wiring.py)) with an opt-in
WS-\* mode. Same `ConnectorType.SOAP`, same factory, same registration
([`soap.py:227`](../../messagefoundry/transports/soap.py)).

### 1. Value-placement contract (the re-run-purity argument, made explicit)

Every value the call needs is assigned to exactly one origin, chosen so that **everything
non-deterministic or secret originates in `send()` or in config — never in the pure transform**. This
placement contract is the *only* thing that guarantees purity; the §2 lint is a secondary defense, not the
guarantee.

| Value | Origin | Why there |
| --- | --- | --- |
| **The HL7 v2 payload mapping → the operation `<Body>` fragment** | **pure Handler transform** (returned as the `Send` payload, the `payload: str` arg to `send()`) | Domain logic; deterministic; message-in → body-out. Stays pure. |
| **Operation wrapper / `<Envelope>` skeleton / `<wsa:To>`** | **static transport config** (`url`) injected by `send()` | Constant per connection; no per-call variance. |
| **`<wsa:Action>`** | **static transport config** (`soap_action`) | Constant per connection (see §6 — reconciled with the SOAPAction header). |
| **`<wsa:MessageID>`** (fresh URN/UUID per call) | **transport `send()`** | Non-deterministic → cannot be in a re-runnable transform. |
| **`<wsu:Timestamp>` Created/Expires**, **`<wsse:Nonce>`**, **`<wsu:Created>`** | **transport `send()`** | Wall-clock / random → cannot be in a re-runnable transform. |
| **UsernameToken PasswordDigest** (if used) | **transport `send()`** (`hashlib`, from the send()-stamped Nonce + Created + secret) | Derived from per-call non-deterministic inputs → must live post-boundary (§4). |
| **Client cert + key + key password; UsernameToken username/password** | **config via `env()` / DPAPI** | Secrets — never source, never in a transform ([CLAUDE.md](../../CLAUDE.md) §9). |

The transform stays a pure `message-in → body-out` function; the transport owns the credential-bearing,
non-deterministic `<Header>`. Because the transport runs **after** the queue boundary, a legitimate
at-least-once **re-send mints a fresh `MessageID`** — which is **correct WS-\* retry semantics** (a retry
is a new message envelope), not a purity violation. (The idempotency footgun this creates is in
*Consequences*.)

### 2. Envelope assembly — hybrid (Handler builds `<Body>`, transport wraps `<Header>`)

- The **Handler** returns the operation **`<Body>` fragment** (the HL7-v2-wrapping submit operation) as
  the `Send` payload — it alone knows how the HL7 maps to the operation. This is the only author-controlled
  part and it is pure.
- The **transport** (`SoapDestination._wrap_envelope`, new) builds the `<soap:Envelope>`, injects the
  stamped `<soap:Header>` (`wsa:` + `wsse:` elements built in `send()`), serializes with the existing
  `encoding`, and POSTs via `_post` ([`soap.py:199`](../../messagefoundry/transports/soap.py)).

#### 2a. Envelope assembly mechanism — stdlib string templating, no XML parser (Q4)

This is **load-bearing** because the codebase is **regex-only and imports no XML parser** today: response
faults are detected by regex (`_FAULT_RE` / `_FAULTCODE_RE` /`_CODEVALUE_RE`,
[`soap.py:56-61`](../../messagefoundry/transports/soap.py)) and there is no `xml.etree` / `ElementTree` /
`lxml` / `defusedxml` import anywhere under `messagefoundry/`. We keep that posture:

- **Assembly is stdlib `str` templating** (an f-string / `str.format` skeleton), **not** `xml.etree`. The
  transport builds the `<soap:Envelope>` + `<soap:Header>` from its own controlled, namespace-fixed
  template and **concatenates** the Handler `<Body>` fragment into it. The transport-built header is
  trusted (it comes only from config + send()-stamped values, all XML-escaped via stdlib
  `xml.sax.saxutils.escape`/`quoteattr` — both are pure string helpers, **not** parsers).
- **Response classification stays regex** (`_classify_soap` + the new `_classify_wssecurity_fault`,
  §5) — **no XML parser is introduced on the response side either**, so no XXE / entity-expansion /
  billion-laughs surface is added. This is a deliberate continuation of the regex-only design, not an
  oversight.
- **Handler `<Body>` well-formedness is asserted before concatenation.** Because we do not parse, we cannot
  *prove* the fragment is valid XML; instead `_wrap_envelope` runs a **stdlib well-formedness assertion**
  on the fragment alone, *isolated from our envelope*, using `xml.sax`'s incremental parser in
  **non-resolving, no-DTD mode** (`feature_external_ges=False`, `feature_external_pes=False` — external
  entity resolution off, so it is **not** an XXE vector) — purely as a *balanced-tags / no-smuggled-close*
  gate on attacker-influenceable HL7-derived content. A fragment that fails (unbalanced tags, a smuggled
  `</soap:Body><soap:Header>`, a stray DOCTYPE, an unescaped `&`) is **rejected with a `ValueError`
  before any POST** — it never reaches the wire and never produces an attacker-shaped envelope. The
  fragment is checked **standalone** (wrapped in a throwaway single-element shell we discard), so a parser
  feature decision is contained to this one validation call; we do **not** keep or trust any parsed tree.
  *Owner question (below): accept this single, hardened, non-resolving `xml.sax` validation call, or drop
  to a stricter pure-string balance check with no parser at all.*

#### 2b. Purity-leak lint (best-effort defense-in-depth, NOT a structural guarantee)

`_wrap_envelope` additionally runs a **best-effort lint** that **rejects a Handler `<Body>` that appears to
already carry a `<soap:Header>` or WS-\* elements** (a `wsa`/`wsu`/`wsse` element by **namespace URI**, not
by prefix). This is a secondary guard against an author hand-building a header (and thus a nonce/timestamp)
inside the transform and quietly re-introducing non-determinism into a pure stage.

**Honesty about its limits.** This is a **lint, not a structural proof.** WS-\* namespace *prefixes* are
author-chosen (a contract may bind them to `o:`/`u:`/`a:`/`sec:`), so the lint matches on the **namespace
URI** (e.g. `http://www.w3.org/2005/08/addressing`,
`http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd`) rather than a fixed
prefix substring — but even URI matching can be evaded (an unusual declaration, a URI inside a comment or
CDATA) and can over-match. **The real purity guarantee is §1's value-placement contract** (the transport
mints these values in `send()`, after the queue boundary); the lint only catches an *accidental*
header-in-the-Handler mistake early with a clear error. We do **not** claim it makes a leak "structurally
impossible".

### 3. Mutual TLS — a third opener factory, REST's hardening preserved (Q2)

Add a per-connection client-cert opener **beside** `_NO_REDIRECT_OPENER` / `_insecure_opener`
([`rest.py:74-82`](../../messagefoundry/transports/rest.py)), reusing `_NoRedirectHandler`
([`rest.py:56`](../../messagefoundry/transports/rest.py)) so the PHI no-redirect defense is intact:

```python
def _client_cert_opener(certfile, keyfile, password):
    ctx = ssl.create_default_context()                 # verifies the server cert (server-auth always on)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2       # the ADR 0002 floor, as in mllp.py:326
    ctx.load_cert_chain(certfile, keyfile, password)   # the same call as api/tls.py:32 / mllp.py:353
    return urllib.request.build_opener(
        _NoRedirectHandler, urllib.request.HTTPSHandler(context=ctx)
    )
```

Built **once in `__init__`** (a bad cert/key fails fast at build, exactly like LDAPS / MLLP — the
"per-connection `SSLContext` gated by `insecure_tls_allowed()`" pattern at
[`mllp.py:312-353`](../../messagefoundry/transports/mllp.py), `server=False`). The cert/key/password reach
the connector as resolved settings via `env()`/DPAPI; `client_key_password` is a secret. This keeps REST's
two module-level singletons (`_NO_REDIRECT_OPENER` / `_insecure_opener`) **untouched** — the new opener is
per-connection, so a client cert on one SOAP destination never alters REST's shared opener.

#### 3a. Opener-selection control flow (the explicit change to soap.py:118-130)

Today `__init__` selects the opener purely from `verify_tls`
([`soap.py:118-130`](../../messagefoundry/transports/soap.py)): `True → _NO_REDIRECT_OPENER`,
`False → _insecure_opener()`. The new rule, stated precisely, **inserts a client-cert branch ahead of the
existing one**:

```python
if self.client_cert_file:                       # NEW — takes precedence
    # server verification is ALWAYS on (create_default_context); a client cert with an
    # unverified peer is incoherent and is a factory error (below), so this branch never
    # combines with verify_tls=False.
    self._opener = _client_cert_opener(self.client_cert_file, self.client_key_file,
                                       self.client_key_password)
elif bool(s.get("verify_tls", True)):           # unchanged
    self._opener = _NO_REDIRECT_OPENER
else:                                            # unchanged (dev-escape gated)
    ...
    self._opener = _insecure_opener()
```

So: **if `client_cert_file` is set, it overrides opener selection** and the peer's server cert is always
verified. `verify_tls` must be `True` (its default) when a client cert is set; **`verify_tls=False` + a
client cert is a wiring-time `ValueError`** (presenting an identity to an unverified peer is incoherent).
The existing `verify_tls=True`/`False` branches are otherwise unchanged.

### 4. WS-Security scope: Timestamp + UsernameToken now; XML-DSig signing as a follow-up

This ADR scopes WS-Security to **`<wsu:Timestamp>` + (optional) `<wsse:UsernameToken>`**. **XML Digital
Signature (signing the body+timestamp) is explicitly deferred to a follow-up ADR** (see *Alternatives* and
the open questions) because robust XML-DSig canonicalization (C14N) + RSA signing is beyond
`xml`/`hashlib`/`hmac` and would pull a new dependency — which needs its own ADR + the
dependency-verification gate ([CLAUDE.md](../../CLAUDE.md) §5).

#### 4a. UsernameToken password mode — PasswordText (recommended) vs PasswordDigest (Q3/§1)

A `<wsse:UsernameToken>` may carry the password two ways; the ADR supports both, controlled by a setting:

- **`ws_password_type="text"` (default, recommended over mTLS).** A `<wsse:Password
  Type="…#PasswordText">` carrying the secret verbatim. Over mutual TLS the channel is already
  confidential + peer-authenticated, so PasswordText is the simplest defensible choice and adds **no**
  per-call non-determinism (the username/password are config secrets via `env()`).
- **`ws_password_type="digest"`.** A `<wsse:Password Type="…#PasswordDigest">` =
  `Base64(SHA1(Nonce + Created + Password))`, accompanied by `<wsse:Nonce>` and `<wsu:Created>`. The digest
  and its inputs are **per-call non-deterministic**, so — per §1 — they are **computed in `send()`** using
  stdlib `hashlib.sha1` + `base64` (stdlib-OK, no new dependency). `Nonce` and `Created` are exactly the
  send()-stamped values already listed in §1; the SHA1-of-the-token-string construction here is the
  legacy WS-Security UsernameToken profile and is **not** a message-integrity signature (XML-DSig stays
  deferred).

The token credentials are dedicated `ws_username` / `ws_password` settings (falling back to
`basic_user`/`basic_password` if unset), resolved via `env()`/DPAPI — never source.

### 5. Response / error capture + classification (Q5) — reuse ADR 0013, extend the fault map

Capture is **already built** and stays regex-based (no XML parser; §2a). `_classify_soap`
([`soap.py:70`](../../messagefoundry/transports/soap.py)) distinguishes Sender(permanent) /
Receiver(transient) / HTTP; the `capture_response` branch
([`soap.py:161-173`](../../messagefoundry/transports/soap.py)) returns `DeliveryResponse`
([`transports/base.py:129`](../../messagefoundry/transports/base.py)) outcomes `accepted` / `rejected` /
`no_reply`. The capture is persisted by the delivery worker: on a captured reply it calls
`complete_with_response` ([`wiring_runner.py:883-891`](../../messagefoundry/pipeline/wiring_runner.py)),
which atomically persists the immutable `response` artifact **and** — only when `reingress_to` is set —
produces a `Stage.RESPONSE` work-row and wakes the re-ingress worker. The captured reply is then routed
back as a new inbound by the separate **atomic `ingress_handoff`** store method drained by that re-ingress
worker (ADR 0013 Increment 2, design doc lines [18](0013-increment-2-reingress-design.md) /
[87](0013-increment-2-reingress-design.md)) — **not** by `complete_with_response` itself; this ADR adds
nothing to that path. `reingress_to=` is declared on the factory
([`wiring.py:941`](../../messagefoundry/config/wiring.py)).

**One extension:** a `_classify_wssecurity_fault` step (composed into `_classify_soap`) maps the common
WS-Security fault codes — `wsse:FailedAuthentication`, `wsse:InvalidSecurityToken`,
`wsse:MessageExpired` — to **permanent** (`NegativeAckError`, `permanent=True`). A cert/credential reject
or an expired timestamp **won't fix on a retry**, so it must **dead-letter** rather than loop the FIFO
lane forever — consistent with the existing "unrecognized fault → permanent" stance
([`soap.py:82`](../../messagefoundry/transports/soap.py)). Fault bodies are still **not** echoed into
errors/logs (they may carry PHI; [`soap.py:16`](../../messagefoundry/transports/soap.py)).

### 6. Invariants (Q6) — inherited by staying `ConnectorType.SOAP`

- **Egress allowlist:** inherited from the `dest.type in (REST, SOAP) and egress.allowed_http` branch
  [`wiring_runner.py:1490`](../../messagefoundry/pipeline/wiring_runner.py). No new pipeline surface, and a
  new `ConnectorType` would have fallen through entirely (a fail-open hole). **Nuance worth stating:** like
  every sibling egress branch, this gate fires **only when `[egress].allowed_http` is configured** — an
  empty allowlist gates nothing. The inheritance argument is sound, but operators **must populate
  `[egress].allowed_http`** for any WS-\* mTLS destination (a PHI destination), or there is no egress
  restriction. This recommendation goes in `docs/CONNECTIONS.md` and is surfaced in dry-run output.
- **Capture backend parity:** inherited from the start guard
  [`wiring_runner.py:382`](../../messagefoundry/pipeline/wiring_runner.py). SQLite, Postgres, and SQL
  Server persist captures identically (ADR 0013, single committed transaction with
  `complete_with_response`).
- **PHI:** the envelope (and the captured reply) are PHI — encrypted at rest (AES-256-GCM when a key is
  set) and **never logged at INFO+**. Logging stays at today's level: only `_redact_url(self.url)`
  ([`rest.py:85`](../../messagefoundry/transports/rest.py)) + the WS-Action + the SOAP fault role/HTTP
  status — **never** the body, and **never a canonicalized/assembled XML dump** of the envelope (such a
  dump would emit a full PHI body, [CLAUDE.md](../../CLAUDE.md) §9). The assembled/captured body lives only
  in the encrypted-at-rest response artifact. No XML parser is added on the response side, so no
  parser-side PHI/entity-expansion surface either (§2a).
- **Cleartext credentials:** `refuse_cleartext_credentials`
  ([`rest.py:93`](../../messagefoundry/transports/rest.py)) already refuses an `Authorization` header over
  `http`; a UsernameToken is logically a credential too — WS-\* mTLS implies `https`, and a client cert
  over `http` is a factory error, so the cleartext-credential path cannot arise for a WS-\* destination.
- **Dependency direction:** the transport **returns** a `DeliveryResponse`; the **delivery worker** writes
  the store ([`wiring_runner.py:883`](../../messagefoundry/pipeline/wiring_runner.py)) — `transports/`
  still imports no `store/`, no `api/`, no `console/`.
- **Dry-run:** unchanged — dry-run runs no connectors / no `send()`, so no MessageID/Timestamp/Nonce is
  minted and no capture is simulated.
- **Wiring-time validation** (in `Soap()` / `SoapDestination.__init__`, surfaced by `messagefoundry check`
  / dry-run): require `client_cert_file` **and** `client_key_file` together; reject a client cert with
  `verify_tls=False` or an `http` URL; reject `ws_security=True` without a Timestamp source or credentials;
  **require `soap_version="1.2"` whenever `ws_addressing` or `ws_security` is set** (WS-Addressing /
  WS-Security are coherent only on SOAP 1.2 here, and 1.2 carries the action in the `Content-Type` rather
  than a `SOAPAction` header — so there is exactly one action surface); **reject specifying the action
  twice** — when `ws_addressing` is on, `<wsa:Action>` is sourced from `soap_action` and is the single
  source of truth, never a divergent second value; run the §2b purity-leak lint and the §2a fragment
  well-formedness check at runtime before POST.

### New settings (added to `Soap()` and consumed in `SoapDestination.__init__`)

Added to the `Soap()` factory ([`config/wiring.py:928`](../../messagefoundry/config/wiring.py)). The
existing factory already resolves `bearer_token`/`basic_*` through `env()` (only `headers` is marked
"no secrets — not env()-resolved", [`wiring.py:933`](../../messagefoundry/config/wiring.py)); the new
secret-bearing settings below are **declared `EnvRef`-typed and resolve through the same `env()`/DPAPI
path** (including via the `connections.toml` desugar, ADR 0007) — never source, never a static header:

- `client_cert_file: str | EnvRef` — PEM client-cert path (or the cert text via `env()`).
- `client_key_file: str | EnvRef` — PEM private-key path.
- `client_key_password: EnvRef | None` — key passphrase; a secret (`env()`/DPAPI), never source.
- `ws_security: bool = False` — stamp a transport-built `<wsse:Security>` (`Timestamp` + optional
  `UsernameToken`).
- `ws_username: str | EnvRef | None`, `ws_password: str | EnvRef | None` — UsernameToken credentials
  (default to `basic_user`/`basic_password` if unset); secrets via `env()`/DPAPI.
- `ws_password_type: str = "text"` — `"text"` (PasswordText; recommended over mTLS) | `"digest"`
  (PasswordDigest computed in `send()`; §4a).
- `ws_addressing: bool = False` — stamp `<wsa:Action>` (from `soap_action`), `<wsa:To>` (from `url`),
  `<wsa:MessageID>` (a per-call URN). Requires `soap_version="1.2"`.
- `ws_timestamp_ttl_seconds: int = 300` — the Created→Expires window (must be ≥ the max retry backoff; see
  *Consequences*).

No new `ConnectorType`, no new store table, no new `DeliveryResponse` outcome, no new dependency, no XML
parser.

## Consequences

### Positive

- **Smallest possible diff for a large capability.** One transport file + one factory; **zero** new
  `pipeline/`, `store/`, or `ConnectorType` surface. mTLS + WS-\* arrives as additive composition.
- **No fail-open egress hole and no new capture-parity bug** — both guards are inherited because the
  connector stays `ConnectorType.SOAP` (avoids the [`wiring_runner.py:1490`](../../messagefoundry/pipeline/wiring_runner.py)
  / [`:382`](../../messagefoundry/pipeline/wiring_runner.py) traps). (The egress gate is fail-closed only
  once `[egress].allowed_http` is populated — §6 — but that is the project-wide framing, not a regression.)
- **Re-run purity preserved by construction:** the value-placement contract (§1) puts every
  non-deterministic value in `send()` (post-queue-boundary). The §2b lint is a secondary catch for an
  accidental header-in-the-Handler mistake — not the guarantee itself.
- **No new XML-parsing attack surface.** Envelope assembly is stdlib string templating and response
  classification stays regex (§2a); the only parse is a single hardened, non-resolving, no-DTD
  well-formedness check of the attacker-influenceable `<Body>` fragment in isolation — so the project's
  deliberate "no XML parser / no XXE surface" posture holds.
- **Reuses proven crypto plumbing** — `load_cert_chain` exactly as `api/tls.py:32` / `mllp.py:353`, the
  per-connection `SSLContext`-gated-by-`insecure_tls_allowed()` shape from `mllp.py:312-353`, and REST's
  `_NoRedirectHandler` PHI defense.
- **Response capture / re-ingress is free** — ADR 0013 + Increment 2 untouched; a partner confirmation can
  be reconciled or routed with only the small `_classify_wssecurity_fault` extension.

### Negative / costs

- **At-least-once + fresh MessageID per re-send is a real footgun.** A crash-replayed delivery mints a
  *new* `<wsa:MessageID>` for the *same* clinical message. The submit **operation must be idempotent**
  ([`soap.py:19`](../../messagefoundry/transports/soap.py) already states this) and the **partner's
  dedup must treat a re-send as a retry, not a duplicate submission**. This must be documented loudly in
  `docs/CONNECTIONS.md`; it is not solvable in the engine without a stable idempotency key, which a signing
  follow-up must design.
- **`ws_timestamp_ttl_seconds` must be ≥ the max retry backoff window.** If the Created→Expires TTL is
  shorter than the worst-case retry delay, an at-least-once retry can fail the peer's `Expires` check.
  Since the timestamp is re-stamped on each `send()` this is usually fine, but a held FIFO lane plus a
  short TTL is a correctness footgun worth a config note.
- **The §2b lint can be evaded / over-match.** It is best-effort; a malicious or unusual Handler could
  still hand-build a header the lint misses. The *correctness* of purity does not depend on it (§1 does),
  but operators should not treat it as a hard wall.
- **`SoapDestination` grows** — the thin "POST an envelope" class now owns envelope wrapping + header
  stamping + a third opener + a fragment-validation call. Mitigated by keeping the wrapper a small,
  testable, pure helper (`_wrap_envelope`) and the header builders as pure functions taking an injected
  clock/UUID source (so they're unit-testable deterministically).
- **No signing in v1.** A peer that *requires* a signed body is not yet supported; this ADR ships
  Timestamp + UsernameToken and defers XML-DSig — an explicit, honest gap (avoids breaching ADR 0003's
  stdlib-only constraint with an unvetted signing dependency).
- **No WS-ReliableMessaging / WS-Trust / SAML** — out of scope; the engine's own reliability is the staged
  queue, not WS-RM.

## Testing strategy (required artifacts)

- **Opener unit tests** (faked SSL context / cert files, mirroring the REST faked-opener tests): assert
  `_client_cert_opener` calls `load_cert_chain` with the configured cert/key/password, sets the TLS 1.2+
  floor, retains `_NoRedirectHandler` (a 3xx still raises, not follows); assert the **opener-selection
  precedence** (`client_cert_file` set → client-cert opener even with `verify_tls` defaulted True; no
  client cert → unchanged `verify_tls` branches); assert `verify_tls=False` + a client cert is rejected at
  construction, and that REST's two module-level singletons are never mutated.
- **Header-stamping purity tests:** with an **injected clock + UUID source**, assert `MessageID`,
  `Timestamp` Created/Expires, and `Nonce` are produced in `send()` only; assert two successive `send()`
  calls on the same payload yield **different** MessageIDs/Timestamps (proving non-determinism lives in the
  transport) while the Handler `<Body>` is byte-identical.
- **PasswordDigest test:** with `ws_password_type="digest"` and an injected Nonce/Created, assert the
  digest = `Base64(SHA1(Nonce+Created+Password))` is computed in `send()`, varies per call, and that
  `"text"` emits PasswordText with no Nonce/Created.
- **Envelope-assembly tests:** assembly is stdlib string templating — a known `<Body>` + fixed clock/UUID
  produces a stable, correctly-namespaced `<Envelope><Header>…</Header><Body>…</Body></Envelope>` (SOAP 1.2
  only); send()-stamped values are XML-escaped; **no XML parser is imported on the assembly or response
  path** (assert via an import/grep guard test, mirroring the regex-only status quo).
- **Fragment well-formedness / injection tests:** a `<Body>` fragment that is unbalanced, smuggles a
  `</soap:Body><soap:Header>`, carries a `<!DOCTYPE>` / external-entity reference, or has an unescaped `&`
  is **rejected with `ValueError` before any POST**; assert the validation runs in **non-resolving, no-DTD**
  mode (an external-entity reference does not trigger network/file access — XXE-negative test).
- **Purity-leak lint tests:** a Handler `<Body>` that already declares a `<soap:Header>` or a `wsa`/`wsu`/`wsse`
  element **by namespace URI** is rejected; assert the lint matches on URI not prefix (an `o:`/`a:`-prefixed
  WS-\* element bound to the right URI is caught) and that the test documents the lint as best-effort
  (a token in a comment/CDATA is a known limitation, not a guarantee).
- **Factory-validation tests:** `ws_addressing`/`ws_security` with `soap_version="1.1"` is a wiring error;
  the action is not specifiable as both a divergent `SOAPAction` and `<wsa:Action>`; client cert without a
  key (or vice-versa) is an error; client cert with `http` URL or `verify_tls=False` is an error.
- **Fault-classification tests:** extend `_classify_soap` coverage — `wsse:FailedAuthentication` /
  `InvalidSecurityToken` / `MessageExpired` → permanent (dead-letter), Receiver fault → transient (retry),
  unrecognized → permanent; assert fault **bodies are not echoed** into the raised error / logs
  ([`soap.py:16`](../../messagefoundry/transports/soap.py)).
- **Capture tests:** `capture_response=True` returns `DeliveryResponse(outcome="accepted"/"rejected"/"no_reply")`
  for a clean confirmation / a `<Fault>` / an empty 2xx; backend-parity test that SQLite + Postgres persist
  the captured reply inside the same committed `complete_with_response` transaction
  ([`wiring_runner.py:883-891`](../../messagefoundry/pipeline/wiring_runner.py)); **start-guard test** that
  a capturing WS-\* SOAP outbound is **refused at engine start** on a backend that can't persist captures
  ([`wiring_runner.py:382`](../../messagefoundry/pipeline/wiring_runner.py)).
- **Egress test:** a WS-\* SOAP destination whose host is **not** in a *configured* `[egress].allowed_http`
  is **refused at load/start** ([`wiring_runner.py:1490`](../../messagefoundry/pipeline/wiring_runner.py)) —
  the fail-closed-when-configured inheritance proof.
- **`reingress_to` integration test:** a captured confirmation produces a `Stage.RESPONSE` work-row via
  `complete_with_response` ([`wiring_runner.py:883-891`](../../messagefoundry/pipeline/wiring_runner.py))
  and is then re-ingressed as a new inbound by the atomic `ingress_handoff` re-ingress worker (ADR 0013
  Increment 2, design doc lines [18](0013-increment-2-reingress-design.md) /
  [87](0013-increment-2-reingress-design.md)) — and a crash-re-run does not double-inject.
- **Dry-run test:** dry-run on a WS-\* SOAP destination runs no `send()`, mints no MessageID/Timestamp, and
  captures no response.
- **Quartet:** `ruff check` + `ruff format --check`, `mypy` (strict), `pytest`.

## Alternatives considered

| Alternative | Why considered | Why rejected | Verdict |
| --- | --- | --- | --- |
| **Extend `ConnectorType.SOAP` (chosen)** | mTLS + WS-\* is additive over `soap.py`; inherits the egress + capture-parity guards keyed on `ConnectorType.SOAP`. | — | **Chosen** |
| **New `ConnectorType.WSSOAP` connector** | A clean separation; WS-\* envelope generation + mTLS is a lot for the thin POST design. | Re-implements `_classify_soap`, the no-redirect opener, `refuse_cleartext_credentials`, and the capture branch; and a new type **falls through** the egress `elif` ([`wiring_runner.py:1490`](../../messagefoundry/pipeline/wiring_runner.py)) → **fail-open egress** unless the branch is also amended, plus must re-expose `capture_response` for [`:382`](../../messagefoundry/pipeline/wiring_runner.py). More surface, more risk. | Rejected |
| **Handler builds the **entire** WS-\* envelope (status quo)** | Today the Handler builds the full SOAP envelope ([`soap.py:6`](../../messagefoundry/transports/soap.py)); maximal author control. | Forces the **non-deterministic** MessageID/Timestamp/Nonce into a **pure transform**, breaking the at-least-once re-run-purity invariant ([CLAUDE.md](../../CLAUDE.md) §2); also puts **secrets** (UsernameToken/cert) into transform code. **Fatal.** | Rejected |
| **Assemble the envelope with `xml.etree` / `lxml`** | A parser would let us *validate* the Handler fragment and build the tree structurally. | Introduces a brand-new XML-parsing surface (XXE / billion-laughs) the codebase has deliberately avoided (regex-only today; no parser imported); contradicts ADR 0003 stdlib-minimalism (lxml) and adds entity-expansion risk on PHI bodies. We keep string templating + a single non-resolving well-formedness check (§2a). | Rejected |
| **Call the §2b namespace lint a "structural guarantee"** | A simple substring/regex scan reads like a hard wall against header-in-the-Handler. | WS-\* prefixes are author-chosen, so a prefix scan is trivially evaded and over-matches; even URI matching is best-effort. The guarantee is §1's value-placement, not a scan. We keep the lint but label it defense-in-depth. | Rejected (kept only as a lint) |
| **Stamp WS-\* values in the router/transform stage but persist them** | Make the values deterministic by recording them. | A second persisted artifact + re-derivation path for what the transport already produces post-boundary; needless `store/` surface; the transport is the natural, already-post-boundary home. | Rejected |
| **Ship XML-DSig body signing in v1** | Some WS-Security contracts require a signed body. | C14N + RSA signing exceeds stdlib, breaching ADR 0003's stdlib-only constraint ([`rest.py:13`](../../messagefoundry/transports/rest.py)); pulls an unvetted dependency; tangles with the idempotency-key decision. | Rejected — **deferred to a follow-up ADR** |
| **Add mTLS to REST's shared `_NO_REDIRECT_OPENER`** | One opener for all HTTP egress. | A client cert is **per-connection**; mutating the module-level singleton ([`rest.py:74`](../../messagefoundry/transports/rest.py)) would leak one destination's identity onto every REST/SOAP call. | Rejected — use a per-connection `_client_cert_opener` |
| **Use a SOAP/WS-\* library (e.g. a `zeep`-class client)** | Off-the-shelf WS-Security/WS-Addressing. | Heavy dependency, its own redirect/TLS posture (defeats the PHI no-redirect hardening), often pulls a sync HTTP stack that fights the `asyncio.to_thread` model; breaches ADR 0003 stdlib-only. | Rejected |
