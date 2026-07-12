# ADR 0093 — Pinned internal-CA trust anchor (BACKLOG #190 remainder)

- **Status:** Accepted (2026-07-11) — pinned-CA built; JWS shipped (ADR 0018); ECH scoped out
- **Deciders:** owner-ratified (prior design + security-critic pass settled the three-way split)
- **Extends:** [ADR 0083](0083-mtls-client-certificate-identity.md) (mTLS identity),
  [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (posture-keyed
  hop refusal), [ADR 0080](0080-offbox-forwarding-tls-defaults.md) (the `forward_tls_ca_file`
  pinned-anchor template), [ADR 0018](0018-detached-jws-message-signing.md) (detached JWS)

## Context

BACKLOG #190 ("PHI data-plane integrity defaults") bundled three residual ASVS L3 items. Two of its
sharpest cells shipped in PLAN-9 Wave 2 (the per-key AES-GCM invocation counter, 11.3.4; the HMAC-keyed
audit chain, 16.4.2). This ADR closes the **remainder** — three pieces, of which exactly **one** is
built here. A prior design pass plus a security-critic review settled the split; it is recorded here so
#190 closes **honestly** rather than being silently dropped.

1. **BUILD — a pinned internal-CA trust anchor** (12.1.4-adjacent). An outbound connector that verifies
   a downstream *server* certificate anchors trust in the OS trust store by default. A hospital estate
   whose internal endpoints present certs from a **private / internal CA** not in the box-global OS
   store then cannot verify that hop without either installing the CA box-wide or repeating a
   per-connection `tls_ca_file` on every outbound. This is the gap the pinned internal-CA fallback fills.
2. **SCOPE OUT — detached-JWS message signing.** Already **shipped** (ADR 0018 /
   `transports/signing.py` mints a detached RFC 7515 JWS over the exact outbound body). Every
   PHI-plane surface already carries integrity: outbound bodies via ADR 0018, the audit log via the
   #899 HMAC hash-chain, at-rest data via GCM AEAD. #190's JWS ask was a *runbook decision* (does the
   exposure runbook mandate it), not new engine code — there is nothing to build.
3. **SCOPE OUT — ECH (Encrypted Client Hello) for outbound SNI.** Empirically **not buildable** under
   the project constraints (see *Decision* below). Recorded as a documented risk acceptance.

## Decision

### 1. Pinned internal-CA trust anchor (built)

A small, shared, opt-in **`[tls]`** section supplies a single internal CA PEM the operator pins once,
applied to internal **outbound** hops so they verify against the org PKI. Deliberately minimal (the
critic flagged a per-scope validator / two-branch model as over-engineering):

- **`config/settings.py` `[tls]`** — two keys: `internal_ca_file: str | None = None` (a PEM **path**,
  NOT a secret — like `tls_cert_file` / `forward_tls_ca_file`) and
  `trust_anchor_mode: "system" | "augment" | "pinned" = "system"`. Default (`system`, no CA) = a
  **no-op**: a config with no `[tls]` block builds a byte-identical SSL context. A single `model_validator`
  guard (not the rejected per-scope model) refuses `trust_anchor_mode = "pinned"` with **no**
  `internal_ca_file` at config load: pinned means *exclude* the public roots, but with nothing to pin the
  resolver falls back to the **full OS trust store**, so the exclusion silently collapses (a fail-open
  misconfig). Refusing it loud at load mirrors `[api]`'s half-configured-TLS guards; `augment` without a
  CA stays allowed (it equals `system` — harmless) and `system` ignores the field.
- **`config/tls_policy.py` `resolve_trust_anchor` (pure)** — precedence:
  1. a connection that names its **own** `tls_ca_file` **wins verbatim** (single-anchor, never
     overridden — the historical `create_default_context(cafile=…)` behaviour);
  2. else, a **loopback** hop (reusing `is_loopback_hop_host`), `system` mode, or an unset
     `internal_ca_file` → the **OS trust store only** (unchanged);
  3. else (a non-loopback internal hop with an internal CA): `pinned` → **only** the internal CA (no
     public bundle — the exact `forward_tls_ca_file` template, ADR 0080); `augment` → the OS roots
     **plus** the internal CA. `build_verifying_client_context` applies the resolved anchor (the
     `augment` "system + private CA" posture is the one a single `cafile=` argument cannot express).
- **Call sites — the internal-outbound connector context builders ONLY:** MLLP outbound
  (`_mllp_ssl_context` client arm), REMOTEFILE FTPS (`_ftps_ssl_context`), DICOM C-STORE SCU
  (`_client_ssl_context`) — the three that carry a per-connection `tls_ca_file` client-verify context.
  The policy is threaded as a typed `Destination.trust_anchor_policy` field via the runner's
  `_dest_config` (the single choke point feeding **both** `build_check` and **live** construction), so
  the anchor resolves identically offline and at the live handshake — mirroring how `tls_hop_attested`
  (ADR 0092) is threaded. Threaded `Engine → RegistryRunner → build_check_registry` alongside the
  existing `hop_posture`.
- **NOT wired into `api/tls.py` `build_api_ssl_context`.** That is the **server** context that verifies
  **client** certs for opt-in mTLS (ADR 0083) — a different trust role (which peers may connect), not
  which roots verify a downstream server. Wiring the internal-CA anchor there would be a category
  mismatch (the critic flagged it). REST/SOAP outbound verify against the OS store with no
  per-connection CA-file knob, so they are out of this seam's scope (a future increment could add one).

### Composition with the existing fail-closed refusals (must-fix)

The internal CA **supplies** a trust anchor to an **already-verifying** context — it selects *which
roots* verify the peer, it **never disables verification**. So it composes with, and never weakens, the
connectors' existing refusals:

- The `tls_verify=false` (MITM) refusal (`weakened_tls_escape_permitted_here`, ADR 0092) fires on the
  `CERT_NONE` branch, which the resolver never touches — a supplied internal CA can **never** silence
  it (a covering test asserts this).
- A plaintext (TLS-off) hop is guarded by the `InsecureHopGuard` posture gradient (ADR 0092); the
  resolver only runs on the verify-**on** TLS path, so the internal CA can never turn a refused
  cleartext hop into an allowed one.
- A non-loopback internal endpoint that presents a private-CA cert cannot be verified against the OS
  store alone; **without** a connection CA or an internal CA the hop simply fails to verify (or would
  require the refused `tls_verify=false`). The internal CA is what lets it verify against the org PKI —
  it closes the gap by *adding trust*, not by *removing verification*.

### Backward compatibility (load-bearing)

`trust_anchor_mode="system"` with no `[tls]` block ⇒ the built SSL context is **byte-identical** to
today (`resolve_trust_anchor` returns the OS-trust-store anchor, and `build_verifying_client_context`
reduces to `create_default_context()`); a per-connection `tls_ca_file` is untouched (it still wins
verbatim as the single anchor). A working public-CA or loopback deployment is unchanged. Verified by a
default-policy test asserting an identical trust store to the no-policy path.

### 2. Detached-JWS signing (scope out — shipped)

Detached RFC 7515 JWS over the outbound body is **built** (ADR 0018, `transports/signing.py`;
`MessageSigner` / `verify_detached_jws`), opt-in per REST/SOAP outbound. The #190 ask was whether the
exposure **runbook** mandates it — a documentation decision, not engine work. Recorded as scoped out:
no code is owed. Integrity on every PHI-plane surface is already present (bodies = ADR 0018; audit =
#899 HMAC chain; at-rest = GCM AEAD), so this is not an integrity gap.

### 3. ECH for outbound SNI (scope out — infeasible)

ECH (Encrypted Client Hello) would hide the destination hostname (partner/EHR identity) in the outbound
TLS ClientHello SNI. It is **not buildable** under the project's constraints, empirically:

- **Python 3.14 stdlib `ssl` exposes no ECH API** — no ECHConfig ingestion, no `set_ech`/GREASE-ECH
  surface. The underlying OpenSSL build the interpreter links does not offer it through the stdlib.
- **No SVCB/HTTPS DNS resolver** — ECHConfig is published via DNS SVCB/HTTPS records; the engine has no
  such resolver and adding one is out of scope (on-prem, offline-by-default).
- **It would violate the no-new-dependency rule** — a working ECH client would require a third-party
  TLS stack (a `cryptography`-external library), which the project's dependency discipline rejects for
  a security-core path.

Recorded as a **documented risk acceptance** (12.1.5): the destination SNI is visible on the outbound
handshake. Compensating context: on-prem deployment on a trusted network segment; the destination is
already an operator-configured, `[egress]`-allowlisted host; and TLS still protects the payload. Re-open
when the stdlib gains a first-class ECH API (no new dep) **and** an SVCB/HTTPS resolver is in scope.

## Consequences

- One new opt-in `[tls]` section (two keys) + a pure resolver + one context-builder helper; three
  outbound connector families thread the policy. No new dependency; no change to the API server context.
- #190 closes **honestly**: pinned-CA built, JWS shipped (ADR 0018), ECH scoped out with reasons
  (documented here and in `docs/SECURITY.md`).
- Secure-by-default preserved: default `system` mode is a byte-identical no-op; the internal CA can only
  *add* trust to a verifying context, never bypass a refusal.

## Alternatives considered

- **Wire the anchor into `build_api_ssl_context`** — rejected: server-side client-cert trust, a
  different role (ADR 0083); category mismatch.
- **A richer `[tls]` model (`pin_scope`, a two-branch validator)** — rejected as over-engineering for
  the single internal-CA use case (critic).
- **Desugar the resolved CA into each connection's `tls_ca_file`** — rejected: cannot express the
  `augment` (OS roots + private CA) posture through a single `cafile=` argument.
- **Build ECH now** — rejected: no stdlib API, no SVCB resolver, would need a new dependency (see above).
