# 0078 — Certificate revocation posture (OCSP/CRL): enforced start-time refusal + delegated proxy

- **Status:** Accepted (2026-07-10) — owner-ratified. Build authorized: the `[api]` in-process-TLS
  serve-time refusal + the `MEFOR_TLS_REVOCATION_ATTESTED` opt-out ship in this PR; the MLLP-over-TLS
  per-connection enforced gate and the scope-adjacent client paths (Postgres/REST/SOAP) are documented
  residuals (see *Out of scope*).
- **Deciders:** owner (ratified) · security working group
- **Related:** **refines the revocation residual in
  [ADR 0002 §"Certificate revocation (12.1.4)"](0002-phase2-transport-security-and-strong-auth.md)**
  (that ADR *documented* the delegation; this ADR makes it an **enforced** start-time control) ·
  flips the ASVS 12.1.4 row in [ASVS-L3-ASSESSMENT.md](../security/ASVS-L3-ASSESSMENT.md) from
  *documented-residual delegation* to *enforced delegation* · builds on the in-process API TLS
  (WP-13a) + reverse-proxy termination (WP-15) of ADR 0002 · the exposed-bind refusal ladder in
  [`__main__.py`](../../messagefoundry/__main__.py) `_serve` · the TLS hardening helpers in
  [`config/tls_policy.py`](../../messagefoundry/config/tls_policy.py) (`harden_verify_flags`) · the
  compensating [`pipeline/cert_expiry.py`](../../messagefoundry/pipeline/cert_expiry.py) monitor ·
  CLAUDE.md §2 ("on-premises by default: no PHI leaves the local environment without explicit,
  reviewed configuration"; the API binds `127.0.0.1` by default) · ASVS 12.1.4 · BACKLOG #201.

---

## Context

ASVS **12.1.4** asks that "proper certificate revocation, such as OCSP stapling, is enabled and
configured". Today the engine ORs `ssl.VERIFY_X509_STRICT` into every *verifying* TLS context it
builds ([`config/tls_policy.py`](../../messagefoundry/config/tls_policy.py) `harden_verify_flags`;
wired at [`api/tls.py`](../../messagefoundry/api/tls.py) `build_api_ssl_context`, the inbound /
verifying-outbound MLLP contexts in [`transports/mllp.py`](../../messagefoundry/transports/mllp.py),
and the DICOM / remote-file paths). That is **RFC 5280 chain strictness — NOT revocation**. A
grep across the whole tree confirms there is **zero OCSP/CRL code anywhere**.

Two constraints bound the choice:

- **Python's stdlib `ssl` exposes no online revocation check** — there is no built-in OCSP/CRL fetch.
  A hand-rolled in-engine OCSP/CRL client would need a **post-handshake AIA / CRL-DP outbound fetch**:
  a network side-channel that directly fights the CLAUDE.md §2 posture — *"on-premises by default: no
  PHI leaves the local environment without explicit, reviewed configuration"* and *"the API binds
  `127.0.0.1` by default"* — i.e. **offline-by-default**. Reaching out to a responder on every
  handshake is exactly the outbound behavior the on-prem model tries not to introduce, and OCSP
  clients are a notorious fail-open footgun (soft-fail on responder unreachability re-admits the very
  revoked cert we meant to reject).
- **Asymmetry (do not "fix" it in-engine).** The SQL Server ODBC path already terminates through the
  OS **SChannel** stack, which performs **OS-managed revocation on Windows** for free. The
  Python-`ssl` paths (the `[api]` uvicorn listener, MLLP-over-TLS, Postgres `asyncpg`) do **not** —
  they never touch SChannel. So revocation coverage is uneven *by which TLS stack terminates*, and the
  gap is specifically the Python-`ssl` in-process termination paths.

The forcing problem: an operator who exposes the engine off-loopback with **in-process** TLS
(`[api].tls_cert_file`) gets a listener that validates the chain but would still accept a
**revoked-but-unexpired** certificate — with no signal that revocation is unchecked. ADR 0002
*documented* this residual; it did not *enforce* it.

## Decision

**Enforced start-time refusal + delegated proxy — NOT in-engine OCSP.** Secure-by-default with an
explicit operator opt-out.

1. **No in-engine OCSP/CRL.** The engine attempts **no** stdlib OCSP/CRL fetch (there is none to
   attempt, and a hand-rolled one fights offline-by-default). This is unchanged and deliberate.

2. **"Revocation proven in front."** Revocation is delegated to the terminator that actually fronts
   the listener, proven by exactly one of:
   - a **declared TLS-terminating reverse proxy** — the existing
     `[api].tls_terminated_upstream` **+** `[api].trusted_proxies` (WP-15). The proxy (IIS / nginx /
     Caddy) does OCSP-must-staple / CRL revocation; the engine runs plaintext behind it and terminates
     no TLS itself, so there is nothing for the engine to revoke; **or**
   - an **explicit operator attestation** that the in-process terminator's certs are backed by a
     revocation-checking PKI (short-lived / ACME-rotated certs, an OCSP-must-staple issuer, an OS
     trust store that consults CRLs): the `MEFOR_TLS_REVOCATION_ATTESTED=1` env escape.

3. **Scope of the enforced gate.** The **in-process `[api]` uvicorn TLS path** is gated at
   `serve` time: WHEN the engine terminates TLS in-process (`[api].tls_cert_file` set) on a
   **network-reachable** host (`[api].host` non-loopback) and revocation is **not** proven in front,
   `serve` **refuses to start** (exit 2) with an actionable message. Direct **MLLP-over-TLS inbound
   termination** shares the identical posture (no in-engine revocation; the same attestation env is the
   operator's blanket attestation over their terminator/PKI) — its own per-connection enforced gate is
   a near-term follow-on (see *Out of scope*), so it is documented here, not yet enforced.

4. **Default = fail-closed.** Absent both proof forms, the in-process off-loopback TLS bind is
   **refused**. This is the secure default; the opt-out below is the escape.

5. **Compensating controls (already built).** The SChannel asymmetry means the SQL Server store path
   already gets OS-managed revocation. The [`pipeline/cert_expiry.py`](../../messagefoundry/pipeline/cert_expiry.py)
   `CertExpiryRunner` alerts on an expiring/expired `[api]` or connection cert, pushing operators
   toward **short-lived certs** — the pragmatic revocation substitute (a compromised short-lived cert
   self-retires quickly) that pairs naturally with the attestation opt-out.

### Opt-out (owner ruling: secure default + documented escape)

`MEFOR_TLS_REVOCATION_ATTESTED=1` (accepts `1`/`true`/`yes`/`on`). An org that terminates in-process
`[api]` TLS off-loopback but runs its own revocation-checking PKI sets it to start; it is the operator
taking responsibility for revocation. Loopback binds and proxy-terminated deployments never reach the
gate and start **byte-identically** — the default `127.0.0.1` posture is completely unchanged.

### What it must not break

- **Loopback byte-identity.** `[api].host` loopback (`127.0.0.1` / `localhost` / `::1`) never reaches
  the gate — the default engine start is byte-identical (no new env read affects it, no new TLS path).
- **The plaintext off-loopback path** (`--allow-insecure-bind`, no TLS) is untouched — the gate keys on
  `tls_enabled`, so a bind with no in-process cert never trips it.
- **The proxy-terminated path** (WP-15) is untouched — a declared proxy is "revocation proven in
  front" and starts unchanged.
- The gate **extends, never weakens**, the ADR 0002 §0 exposed-bind ladder (it is an additional refusal
  layered after it, mirroring the keyless-store / open-egress / MFA-at-exposure gates).

## Acceptance Criteria

- **AC-1** — WHEN `serve` is invoked with in-process `[api]` TLS (`tls_cert_file` set) on a
  non-loopback host and neither a declared TLS-terminating proxy nor `MEFOR_TLS_REVOCATION_ATTESTED`
  is present, THE SYSTEM SHALL refuse to start (exit 2) with a message naming ASVS 12.1.4 and the two
  remedies.
  → `tests/test_listener_tls_exposure.py::test_serve_refuses_inprocess_tls_offloopback_without_attestation`
- **AC-2** — WHERE `[api].host` is loopback, THE SYSTEM SHALL start unchanged even with in-process TLS
  configured (the gate never fires).
  → `tests/test_listener_tls_exposure.py::test_serve_loopback_inprocess_tls_starts`
- **AC-3** — WHERE a declared TLS-terminating proxy is configured
  (`tls_terminated_upstream` + `trusted_proxies`), THE SYSTEM SHALL start (revocation proven in front).
  → `tests/test_listener_tls_exposure.py::test_serve_proxy_terminated_offloopback_starts`
- **AC-4** — WHEN the operator sets `MEFOR_TLS_REVOCATION_ATTESTED=1`, THE SYSTEM SHALL start an
  in-process off-loopback TLS bind (the documented opt-out).
  → `tests/test_listener_tls_exposure.py::test_serve_inprocess_tls_offloopback_attested_starts`
- **AC-5** — THE `in_process_tls_revocation_refused` predicate SHALL return `False` for the loopback,
  plaintext, proxy-terminated, and attested cases, and `True` only for an unproven in-process
  off-loopback TLS bind.
  → `tests/test_tls_policy.py::test_in_process_tls_revocation_refused_matrix`

## Options considered

1. **In-engine OCSP/CRL client.** Fetch the AIA/CRL-DP after handshake and reject a revoked cert.
   Rejected: stdlib `ssl` has no such API (a bespoke client is significant surface + a fail-open
   footgun), and the post-handshake outbound fetch fights offline-by-default (CLAUDE.md §2).
2. **Documented-only delegation (status quo, ADR 0002).** Keep the residual as prose. Rejected: an
   operator can silently expose an in-process off-loopback TLS listener with unchecked revocation — the
   ASVS 12.1.4 intent ("enabled and configured") is not met by documentation alone.
3. **Enforced start-time refusal + delegated proxy + attestation opt-out.** **CHOSEN.** Fail-closed by
   default, delegates real revocation to the terminator that can do it (proxy / OS trust store), and
   gives an org running its own revocation-checking PKI a loud, explicit escape. No new outbound
   side-channel; loopback default byte-identical.

## Consequences

**Positive** — the ASVS 12.1.4 delegation is now **enforced**, not merely asserted: an off-loopback
in-process TLS bind with unchecked revocation refuses to start. Secure-by-default; no new outbound
network behavior; the loopback default is untouched. Nudges operators toward the two good postures
(terminate at a revocation-checking proxy, or run short-lived certs + attest).

**Negative / risks** — an org that legitimately terminates in-process TLS off-loopback must now set
`MEFOR_TLS_REVOCATION_ATTESTED=1` once (a one-time, documented step; surfaced by the refusal message).
The attestation is an honor-system claim — the engine cannot verify the operator's PKI actually checks
revocation (that is inherent to delegation). MLLP-over-TLS termination is **not yet** enforced at
serve time (documented residual below).

**Out of scope (documented residuals, not built here)** —
- **MLLP-over-TLS per-connection enforced gate.** Direct MLLP-over-TLS inbound termination shares this
  posture (no in-engine revocation) and is covered by the same attestation env, but enumerating each
  off-loopback `tls=true` MLLP inbound and refusing per-connection is a wiring-layer change (the MLLP
  exposure guards live in `pipeline/wiring_runner.py`, not `_serve`), deferred to a follow-on.
- **Postgres `asyncpg` store TLS.** The Postgres client path sets no `VERIFY_X509_STRICT` and does no
  revocation; it is a *store* backend (scope-guarded — `store/*.py` is not touched here). Scope-adjacent
  residual.
- **Outbound REST / SOAP / FHIR client contexts.** Verifying-outbound HTTP clients rely on the OS trust
  store + `VERIFY_X509_STRICT` (where wired) but perform no live revocation. Scope-adjacent residual.
- **SQL Server / SChannel** needs no change — the OS stack already does OS-managed revocation
  (the asymmetry noted in *Context*).

## To resolve on acceptance

- [x] Owner ratified the enforced-refusal + attestation-opt-out posture (secure default = refuse).
- [x] Env escape name fixed: `MEFOR_TLS_REVOCATION_ATTESTED` (sibling of `MEFOR_ALLOW_INSECURE_TLS`).
- [x] Follow-on (see Amendment 2026-07-12): extend the enforced gate to the **OUTBOUND** verifying-TLS
  connectors (MLLP-over-TLS egress, REST/SOAP/FHIR https, the Postgres asyncpg store hop).

---

## Amendment — 2026-07-12: extend the enforced refusal to OUTBOUND connector TLS (BACKLOG #201 residual)

**Status:** Accepted (2026-07-12) — owner-authorized backlog wave. Closes the *Out of scope* residuals
above (the MLLP-over-TLS per-connection gate + the Postgres / REST / SOAP / FHIR client paths) with the
**same posture-keyed start-time refusal**, keyed on the deriving instance's `HopPosture`.

### Context

The original decision ENFORCED the "no in-engine OCSP/CRL → refuse an unproven off-loopback in-process
`[api]` TLS bind" posture for the **listener** only. The identical blind spot exists on every **OUTBOUND**
connector that *verifies* a downstream server certificate over Python's `ssl` (which has no OCSP/CRL): the
chain is validated (+ strict RFC 5280 via `harden_verify_flags`) but a **revoked-but-unexpired** peer cert
is still accepted. Those were the documented *Out of scope* residuals; this amendment builds them.

### Decision

A **VERIFYING** outbound TLS hop that is **off-loopback, PHI, and production** with revocation **not proven
in front** is **REFUSED at construction / `messagefoundry check` / dry-run** (the store hop: at store open);
a non-production PHI hop **WARNs** (crosses, loud-logged); loopback / synthetic (non-PHI) / attested hops
are **byte-identical**. This reuses `config/tls_policy.py`, mirroring the #200/ADR-0092 seam exactly:

- **Pure predicate** `revocation_hop_disposition(*, is_phi, production, is_loopback_hop, proxy_proven,
  attested) -> HopDisposition` — the outbound sibling of `in_process_tls_revocation_refused`, using the
  `HopDisposition` gradient of `insecure_hop_disposition`. Precedence: loopback→ALLOW; `proxy_proven`
  (a declared revocation-checking egress terminator)→ALLOW; `attested`→ALLOW; synthetic→ALLOW;
  production→REFUSE; else non-prod-PHI→WARN. It carries **no global-escape arm** — the only relaxations are
  the on-box carve-out, a proven terminator, an operator attestation, or a synthetic instance.
- **Thin guard** `RevocationHopGuard.capture(...).enforce_construction()` — snapshots the active
  `HopPosture` (`current_hop_posture`, stamped by `build_check_registry`'s `active_hop_posture` scope) and
  folds the blanket `MEFOR_TLS_REVOCATION_ATTESTED` env into the per-connection attestation. No-op when the
  posture is unstamped (a live serve build after the pre-flight / a direct test), identical to the #200
  `InsecureHopGuard` — the build-check gate is the authority.
- **Attestation** — a new per-connection `tls_revocation_attested` flag (Destination), OR the existing
  blanket `MEFOR_TLS_REVOCATION_ATTESTED` env (the same opt-out the listener got). It is **distinct** from
  the #200 `tls_hop_attested` (which attests a *cleartext / verify-off* hop is secure by other means).

### Scope built

- **MLLP-over-TLS egress** (`MLLPDestination`) — guarded on the VERIFY path only (`verify_mode !=
  CERT_NONE`); the `tls_verify=false` / cleartext cases are already refused by `_mllp_ssl_context` / #200.
- **REST / SOAP / FHIR / DICOMweb https** — the shared `transports/rest.py:refuse_unrevoked_verified_hop(...)`
  fired on each connector's `verify_tls`-ON https path (covers the shared verifying opener, the ADR-0094
  expiry-relaxed opener, and SOAP mTLS). DICOMweb STOW-RS reuses REST's verifying urllib opener, so it takes
  the identical guard — a PHI-bearing verified-https imaging hop is not left unguarded beside its siblings.
- **SMTP-over-TLS email** (`EmailDestination`, ADR 0029) — guarded on the `use_tls`-ON path (STARTTLS on 587
  / implicit `SMTP_SSL` on 465). smtplib is a different construction seam (not the urllib/ssl scheme), so it
  calls `RevocationHopGuard.capture(...).enforce_construction()` directly rather than the https-scheme-keyed
  `refuse_unrevoked_verified_hop`. The message body carries PHI over the verified SMTP session, so the same
  posture-keyed refusal applies; the `use_tls=false` cleartext path is already refused separately.
- **Postgres asyncpg store hop** — `store/postgres.py:_refuse_store_revocation(...)` at `_build_ssl` on the
  two verifying branches (pinned CA + system trust store); attestation is the blanket env only (the store
  has no per-connection TOML). Sits beside — and composes with — the existing weakened-TLS refusal.

### Composition with #200 (no double-refusal)

#200 refuses the **cleartext / verify-off** hop; this amendment fires **only on a VERIFYING hop**. The two
gates key on disjoint conditions, so a given hop is refused by exactly one of them, never both.

### Still out of scope (unchanged, documented)

- **SQL Server / SChannel** — the OS stack already does OS-managed revocation (no change).
- **DICOM-SCU / FTPS verifying contexts** — a follow-on may extend the identical `RevocationHopGuard` to
  the DIMSE-over-TLS SCU and the FTPS control/data channel; deferred to bound this wave. No new OCSP.
- **The FhirLookup read path** (`fhir_lookup`, ADR 0043) — scope-adjacent; the same helper applies when it
  is a near-term extension. No in-engine OCSP is introduced anywhere — this stays a posture-keyed refusal.
