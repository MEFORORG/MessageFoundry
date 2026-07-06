# ADR 0018 — Per-message digital signatures (ASVS 4.1.5): opt-in signing shipped (Pass-with-documented-residual)

- **Status:** **Amended (2026-06-18).** A **trigger fired** (build trigger 1 — a partner contract that
  verifies a message-level signature), so the previously-deferred capability is now **built, minimal and
  real**: opt-in, per-connection **detached-JWS signing** on the REST/SOAP outbound connectors. The
  verdict moves from **accepted-risk Fail → Pass-with-documented-residual** (the residual is recorded in
  the Amendment below). Supersedes the **Accepted (2026-06-16)** accepted-risk decision recorded below,
  which stands as the historical rationale.
- **Requirement:** OWASP ASVS 5.0 **4.1.5** (V4.1 Generic Web Service Security, **Level 3**) — *"Verify
  that per-message digital signatures are used to provide additional assurance on top of transport
  protections for requests or transactions which are highly sensitive or which traverse a number of
  systems."*

## Amendment (2026-06-18) — opt-in per-connection signing shipped

The honest way to flip 4.1.5 off a Fail is to **ship the control**, not re-score the gap. This amendment
records the shipped capability and the **residual** that keeps the claim truthful (a conditional Pass).

**What is built.** Opt-in, **per-connection** message signing on the **REST and SOAP outbound**
connectors. When a connection is configured to sign, the connector mints a **detached JWS** (RFC 7515
Appendix F) over the **exact outbound payload bytes** and carries it in a configurable HTTP header
(default `X-JWS-Signature`); a partner verifies it against the agreed **public** key, out-of-band per
contract. This is a message-level signature **on top of** TLS — it survives a re-encode at an
intermediary hop and binds origin + integrity independent of the channel, which is exactly what 4.1.5
asks for.

- **Crypto:** core `cryptography` only — **no new dependency**. RSA (`RS256` PKCS1-v1_5, `PS256` PSS) or
  ECDSA (`ES256`, P-256), all SHA-256. (`cryptography` was already named as the path in the original
  decision below.)
- **Where it is minted:** in the connector's `send()` boundary
  ([`pipeline/wiring_runner.py`](../../messagefoundry/pipeline/wiring_runner.py) drives the per-outbound
  delivery worker that calls `connector.send()`), over the bytes that actually go on the wire — for SOAP
  WS-\* that is the **wrapped envelope** built in `send()`. It runs in the same off-loop worker thread
  `send()` already uses, **past the queue boundary**, so a retry re-mints it and routers/transforms stay
  pure — the same discipline the WS-Security timestamp/nonce uses ([ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md) §1).
  PS256/ES256 are randomized (a fresh signature per call); RS256 is deterministic.
- **A verify counterpart** ships alongside (`verify_detached_jws` /
  [`transports/signing.py`](../../messagefoundry/transports/signing.py)) so a receiver — or a test —
  validates a signature and can **pin the algorithm** against a downgrade.
- **Config:** OFF by default. A per-connection `OutboundSigning` field lives in
  [`config/models.py`](../../messagefoundry/config/models.py) (`Destination.sign`); the runner's
  `_dest_config` assembles it from the env-resolved `sign_*` settings, so a bad key/algorithm **fails
  loud at `check`/dry-run/start**, like a bad TLS cert. Authored code-first with `with_signing(...)` over
  a `Rest()` / `Soap()` spec, e.g. `outbound("OB_ACME", with_signing(Rest(url=env("acme_url")),
  private_key=env("acme_sign_key"), algorithm="ES256", key_id="acme-2026"))`. Secrets (the key, an
  encrypted-key password) go in `env()`; the key never leaves the box — only the public-verifiable
  signature does.

**Residual (why this is a *conditional* Pass, not an unqualified one).**

1. **Not enforced on the default loopback path.** The default posture is **unsigned** — signing is
   **opt-in per partner contract**, activated only on the connections that need it. The supported on-prem,
   single-tenant, point-to-point model still relies on TLS + the trusted network for the unsigned default
   (the original decision's compensating controls, below), so an unsigned internal hop has no per-message
   signature to detect tampering. Accepted while that model holds; a partner/contract or an
   off-prem/untrusted-intermediary deployment is exactly when an operator turns signing **on**.
2. **Outbound only; inbound verification lands with an inbound HTTP source.** Signing is on the
   **outbound** REST/SOAP send (there is no REST/SOAP *source* yet). The `verify_detached_jws` counterpart
   is shipped + tested for receivers and round-trips; engine-side verification of an *inbound* signed
   request arrives when an HTTP listen source does.
3. **Operator-supplied key material.** The key is inline PEM (via `env()`) or a PEM file path
   (OS-protected, like a TLS key). A **managed key provider** (HSM/KMS/Vault, key rotation) is the
   separate [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) follow-up; `kid` is already carried in
   the JWS header so a provider/rotation slots in without a wire change.
4. **Activation surface.** Signing is reachable today via `with_signing(...)` / a raw `ConnectionSpec`
   (the public code-first API) and the runner wiring. Exposing it as `Rest(...)`/`Soap(...)` factory
   keyword args + `connections.toml` `sign_*` keys is a small follow-up (the factory **is** the schema for
   those data surfaces) and was kept out of this change's blast radius.
5. **Scorecards reconcile separately.** The L3 scorecards
   ([ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md),
   [ASVS-L3-STATUS.md](../security/ASVS-L3-STATUS.md),
   [ASVS-L3-REMEDIATION-PLAN.md](../security/ASVS-L3-REMEDIATION-PLAN.md)) and
   [SDS Appendix A.6](../Secure_Development_Standards.md) still record the **prior accepted-risk Fail /
   deferred-by-design** entry. **This ADR is the governing record of the shipped capability;** those docs
   are reconciled to "Pass (conditional, opt-in) with residual" in their next revision — a deliberate
   doc-only follow-up, not silently flipped here.

## Context (historical — the 2026-06-16 accepted-risk decision)

- MessageFoundry is a healthcare integration engine: it carries **PHI** ("highly sensitive") and, as
  middleware, a message **traverses a number of systems** (sender → MF → outbound → partner, often
  further downstream). Both triggers in 4.1.5 are satisfied by the OR, so the requirement is
  **applicable** — it is **not** Not-Applicable. (Marking it N/A would be score-optimization; "the
  industry doesn't do it" is a *practice* observation, not an applicability test.)
- 4.1.5 asks for a message-level signature **on top of** transport protection — valuable specifically
  when a message can be tampered with at an **intermediary hop**.
- Realities for the supported deployment model:
  - The data plane is already protected by **TLS** (1.2+ floor; API/WSS + MLLP-over-TLS, [ADR 0002](0002-phase2-transport-security-and-strong-auth.md)).
  - The supported model is **on-prem, single-tenant, point-to-point**, with **no untrusted intermediary**.
  - **Industry practice:** HL7 v2 interchange relies on transport/network security; per-message digital
    signatures are rare, and **no known partner system requires or supports** receiving a per-message
    signature on these feeds. A signature only has value if the receiver verifies it, and both parties
    must agree on the format and keys.
  - The local console → API call is explicitly **out of scope** of the requirement (a local call, not a
    sensitive multi-hop transaction).

## Decision (historical — now superseded by the Amendment above)

**Accept the risk and defer by design.** Do not build per-message signing now; record the compensating
controls and the build triggers, and revisit when a trigger fires.

- **Compensating controls:** TLS-protected data plane + a trusted single-tenant on-prem network (no
  untrusted intermediary); the count-and-log / per-message disposition record gives an integrity and
  audit trail of what was received and sent.
- **Build triggers (any one):**
  1. A **partner contract** that mandates (or offers to verify) a message-level signature.
  2. An **off-prem / cloud / shared-tenant** deployment, or any path through an **untrusted intermediary**.
- **When triggered, the implementation path is already scoped:** SOAP **XML-DSig** / WS-Security on the
  outbound SOAP connector ([ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md) §4a), or a **detached
  JWS** over the message body for HL7/JSON. `cryptography` is already a core dependency.

## Consequences (historical — as written for the accepted-risk decision)

> Superseded by the Amendment above as of 2026-06-18: the capability is now shipped, so 4.1.5 is
> **Pass-with-documented-residual**. The points below are the original accepted-risk consequences and the
> compensating controls that still govern the **unsigned default** path (residual item 1).

- ASVS **4.1.5 remains a Fail** on the scorecard — an *accepted* Fail is governed, not re-scored to Pass
  or N/A. It is recorded as a dated deviation in [SDS Appendix A.6](../Secure_Development_Standards.md)
  and tracked in [ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md).
- **Residual risk:** a compromised hop inside MF or on the (trusted) network could alter a message with
  no per-message signature to detect it; mitigated by the on-prem trust boundary, TLS, restricted service
  accounts, and the audit trail. Accepted while the supported model holds.
- Closing 4.1.5 is **not required** for the loopback-default posture and does not block v0.1.
- **Review:** at each release and on any trigger above. This ADR is superseded by the build decision when
  the signature path is implemented.

**Cross-references:** [ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) (4.1.5 verdict) ·
[ASVS-FAILS-REMEDIATION-PLAN.md](../security/ASVS-FAILS-REMEDIATION-PLAN.md) ·
[Secure_Development_Standards.md](../Secure_Development_Standards.md) §A.6 · [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) · [ADR 0015](0015-ws-soap-outbound-mtls-wssecurity.md).
