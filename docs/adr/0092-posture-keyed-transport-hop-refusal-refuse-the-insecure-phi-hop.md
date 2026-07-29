# ADR 0092 — Posture-keyed transport-hop refusal (refuse the insecure PHI hop)

> **AMENDED by [ADR 0153](0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md)
> (built 2026-07-28) — decisions 1 and 2.** The precedence below is no longer current: arm 3
> (`not is_phi → ALLOW`) is **deleted**, so `insecure_hop_disposition` no longer takes `is_phi`, and the
> `audited_opt_out` arm went with it, so `MEFOR_ALLOW_INSECURE_TLS` can no longer influence a
> cleartext-hop decision. The live precedence is: loopback → ALLOW, `hop_attested` → ALLOW,
> `cleartext_accepted` → WARN, not `enforcing` → WARN, else REFUSE.
>
> Everything else in this ADR **stands**: the one-authority structure, the loopback carve-out
> (decision 1 arm 1), the attestation (decision 3), the two-layer construction/send gating (decision 4)
> and the no-loosen rule (decision 5) — which 0153 preserves *by construction*, since the only deleted
> arm returned ALLOW. `MEFOR_ALLOW_INSECURE_TLS` itself is unhooked from the **cleartext** decision, not
> deleted. It survives for the non-connection cells (engine→store TLS, LDAPS, the webhook alert sink, the
> AI broker, the `[logging]` forwarder and the API PHI-read serve hop) that have nowhere to carry a
> per-connection declaration, **and for the weakened-TLS cells** — `verify_tls=false` on
> REST/SOAP/FHIR/DICOMweb, `tls_verify=false` on MLLP and FTPS, `trust_server_certificate` on the store.
> A verify-off hop is encrypted-but-unauthenticated rather than cleartext, so it sits outside 0153's
> stated scope: it keeps this ADR's clamped escape unchanged, and `cleartext_accepted` does not reach it.

**Status:** Accepted (2026-07-11) — owner-ratified design (a prior design pass + an adversarial security
critic set the decisions below; they are not re-litigated here). CORE built (BACKLOG #200): the shared
authority + escape clamp + per-hop attestation field + posture threading. The transport **cells** that
consume the authority (HTTP cleartext egress, engine→store TLS, credentialed FTP, MLLP verify-off) are
built in follow-up lanes; the #200 banner flips when the whole set is green. Extends
[ADR 0083](0083-mtls-client-certificate-identity.md) / [ADR 0078] revocation-refusal and the inline
transport-security sketch in [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) §4.

## Context

MessageFoundry carries PHI. Several transport cells already **refuse** an insecure egress hop today — the
HTTP cleartext-egress refusal (`transports/rest.refuse_cleartext_egress`), the engine→store TLS gate, the
credentialed-FTP refusal, and the MLLP `tls_verify=false` refusal — but each cell **hard-codes its own
decision** against the blunt global escape `MEFOR_ALLOW_INSECURE_TLS`. Two problems follow:

1. **Inconsistent coverage.** A guarded cell refuses a hop that an *unguarded* cell warns-and-crosses, so
   whether a given PHI hop is refused depends on which connector it rides, not on the instance's posture.
2. **A blunt escape.** `MEFOR_ALLOW_INSECURE_TLS` silences the refusal in **every** environment, including
   production — one env var relaxes a production-PHI refusal globally.

We want one authority every cell consumes so all decide identically, keyed on the instance's **posture**
(does it carry PHI? is it production?), plus a *surgical, audited* per-connection opt-in for a legitimately-
secure hop (a proxy-terminated / trusted-segment hop) that replaces reliance on the blunt global escape.

## Decision

**1. One pure authority** (`config/tls_policy.py`). `HopDisposition` (`ALLOW`/`WARN`/`REFUSE`) + a pure
`insecure_hop_disposition(*, is_phi, production, is_loopback_hop, hop_attested, audited_opt_out)` with an
**explicit early-return precedence** (the order is load-bearing):

1. `is_loopback_hop` → **ALLOW** (an on-box hop is not a network exposure);
2. `hop_attested` → **ALLOW** (a per-connection, load-validated, audited attestation);
3. not `is_phi` (synthetic) → **ALLOW** (no PHI on the hop);
4. `audited_opt_out` → **WARN** (the escape — already clamped to non-prod by the caller);
5. `production` → **REFUSE** (a production PHI hop with no attestation);
6. else (non-prod PHI — dev/staging) → **WARN**.

A thin `enforce_insecure_hop(disp, *, message, cell, audit_sink)` acts on the decision: raise
`InsecureHopRefused` (a `ValueError`, so it surfaces as a config-load / `build_check` error) on REFUSE;
loud-log **+ audit** on WARN; no-op on ALLOW. `transports/rest._is_loopback_egress_host` is **hoisted** to
`tls_policy.is_loopback_hop_host` (literal `127.0.0.0/8`, `::1`, `localhost`, empty host) so the HTTP-egress
cell and the authority share **one** definition; it **never resolves DNS** — an unprovable name is REMOTE
(fail-closed), so a hostname can't smuggle an off-box hop past the on-box carve-out.

**2. Escape clamp.** `MEFOR_ALLOW_INSECURE_TLS` may only downgrade **REFUSE→WARN on a non-production**
instance; it can **never** satisfy a production-PHI hop. Implemented as `settings.hop_insecure_escape_
downgrades(*, production)` (returns `insecure_tls_allowed() and not production`), which the cells pass as the
predicate's `audited_opt_out` — so on production that argument is always `False` and the `production` REFUSE
arm always wins. **This is a deliberate behaviour change** from the pre-#200 escape, which silenced the
refusal in every environment.

**3. Per-hop attestation.** A per-connection `tls_hop_attested: bool = False` (+ optional
`tls_hop_attested_reason`) on `Source`/`Destination` (and `connections.toml`), **load-validated** (a reason
without the flag, or a blank reason, fails loud). It is the surgical opt-in for a legitimately-secure
proxy-terminated / trusted-segment hop and is **audited by the cell when it suppresses a would-be
production refusal**. This replaces reliance on the blunt global escape for the prod case — attestation is
the **only** per-hop way across a prod-PHI hop.

**4. Layering (defense-in-depth).** The **construction-time** gate is the ENFORCED one — it fires at
`messagefoundry check` / dry-run / reload when connectors are built. The authority's active posture is
stamped (`tls_policy.active_hop_posture`) around the connector-construction block in `build_check_registry`.
A **zero-I/O send-time assertion** at the byte-crossing is the second layer (defense against a reload /
per-message-target route sneaking PHI past a construction-only check); the cell captures the posture at
construction and re-asserts at send.

**5. No-loosen rule.** The gradient only **adds** coverage to unguarded cells. It must **not** loosen any
already-shipped refusal: the cells that refuse **both** staging and production PHI today (HTTP
`refuse_cleartext_egress`, engine→store, credentialed-FTP, verify-off) keep REFUSE for both. A staging-PHI
hop that refuses today must not become warn-and-cross.

**6. Deferred (residual).** The API PHI-read **request-time** data-path guard (`require_secure_hop`) is out
of scope; the shipped #906 start-gate covers prod-PHI Posture-B in the meantime.

**7. Posture threading.** `messagefoundry check` and the reload dry-run resolve the connector posture to the
**LOADED config's declared posture** (`settings.hop_posture_from_ai` over `AiSettings.derived_posture()`),
**not strictest-by-default** — leaving the posture holder unstamped there would break the CI gate or default
wrong. `Engine` derives the posture from `[ai]` and threads it into every `RegistryRunner` it builds; the
`connection` CLI edit-check passes it too. An unresolved custom-env posture fails **closed** (`is_phi=True`,
`production=True`).

## Consequences

- One authority; every insecure-egress cell decides identically, keyed on posture.
- Production-PHI cleartext/unverified hops are refused unless per-connection attested; the blunt global
  escape can no longer silence a production refusal.
- Config surface: two additive per-connection fields (default off → existing configs byte-identical).
- Follow-up: the transport cells adopt `current_hop_posture()` + `insecure_hop_disposition` /
  `enforce_insecure_hop` and add the send-time assertion; the #200 banner flips when they are all green.
- Residual: the API request-time PHI-read hop guard (`require_secure_hop`).

## Amendment (2026-07-12) — generic ODBC dialect is TLS-delegating, not posture-refused (BACKLOG #66)

The DATABASE connector's **generic ODBC dialect** (`dialect="generic"`, BACKLOG #66) is **intentionally
exempt** from the posture-keyed weakened-TLS refusal above. The refusal keys on introspectable TLS knobs
(SQL Server's `Encrypt`/`TrustServerCertificate`, Postgres asyncpg's SSL context); an **arbitrary
OS-installed ODBC driver** exposes its TLS posture only through **driver-specific keywords**
(`SSLmode=verify-full`, `SSLMODE=VERIFY_IDENTITY`, …) MessageFoundry cannot enumerate or interpret. So the
generic path **delegates TLS enforcement to the operator/driver**: `_build_connection` reports the hop as
non-weakened and the send-time assertion is a no-op there.

This is **not** a loosening of an already-shipped refusal (No-loosen rule §5): the SQL Server preset —
the only DB dialect that shipped before #66 — keeps its refusal byte-identical; the generic path is a
**new** cell whose TLS posture is unknowable to the engine, not a previously-refused hop turned
warn-and-cross. To keep the delegation from being *silent* (the fail-safe intent of this ADR), generic-
dialect construction **logs it**: a `WARNING` when no ssl/tls/encrypt keyword is present in `odbc_params`,
dropped to `DEBUG` when one is (`transports/database._warn_generic_tls_unenforced`). A future native-driver
connector (asyncpg-as-connector, scoped out of #66) that *can* introspect TLS should re-enter this
authority rather than delegate.

## Amendment (2026-07-13) — the DEFERRED residuals closed (BACKLOG #200)

The core shipment (serve/reload posture stamping + the production-PHI escape clamp) left four residual
paths OPEN in decision 6 / the #200 banner. They are now built, each extending — never weakening — the
authority above:

1. **API PHI-read data-path guard (the decision-6 residual).** The posture-keyed refusal now applies to
   the API's PHI-read **RESPONSE** path, not only to the transport egress cells. `create_app` derives the
   **API serve-hop disposition** once from `(instance posture, is the serve hop loopback / in-process TLS /
   proxy-terminated)` via the new pure `tls_policy.phi_read_hop_disposition` — which reuses the ONE
   `insecure_hop_disposition` authority with the production-PHI clamp (`hop_insecure_escape_downgrades`)
   supplied as `audited_opt_out` — and stashes it on `app.state`. `api/security.enforce_phi_read_hop`
   (folded into `require_phi_read`; called explicitly by the step-up `search` route) then **refuses (403,
   PHI-free)** a PHI read on a production-PHI instance whose serve hop is not proven secure, so PHI is
   never emitted over an unstamped/weakened API hop. A secure serve hop is modelled as the authority's
   on-box carve-out (`is_loopback_hop`); `posture is None` (no `[ai]`, an embedding/test) and every
   synthetic / dev / loopback / TLS lane are **ALLOW** → **byte-identical**. `_serve` passes
   `phi_read_hop_secure = api.is_loopback or api.exposure_protected`; `create_app` defaults it to secure so
   an embedding is unaffected. Composes with the serve-start exposed-gate (that gate refuses the *bind*;
   this refuses the *response* — defense-in-depth, never a double-refusal on a legitimate lane).
2. **db_lookup / fhir_lookup live-read posture stamp.** The `db_lookup` (ADR 0010) / `fhir_lookup`
   (ADR 0043) executors are built by `RegistryRunner` at `engine.start()` / reload **outside**
   `build_check_registry`'s `active_hop_posture` scope, so their weakened-TLS / cleartext hop check keyed
   on the **UNCLAMPED** escape (`insecure_tls_allowed()`, posture unstamped) — a production-PHI instance
   could do a weakened-TLS live read, and a synthetic cleartext FHIR read was false-closed. The live
   builders (`_build_lookup_executor` / `_build_fhir_lookup_executor`) now wrap construction in
   `active_hop_posture(self._hop_posture)`, so the production-PHI clamp (`weakened_tls_escape_permitted` /
   `hop_insecure_escape_downgrades`) actually applies — mirroring the connector-build stamping the core
   shipment already added at `_start_outbound`/`_start_inbound_unsafe`.
3. **`messagefoundry check` posture-stamped build_check.** `serve`/`reload` run the posture-stamped
   `build_check_registry`; the commit/CI gate (`checks.run_checks`) ran only `validate_config` (which
   never constructs connectors), so it could pass a config `serve` would REFUSE. A new **required**
   `build-check` (`checks._check_build`) loads this instance's `messagefoundry.toml`, resolves `env()`
   against the active environment, and runs the same posture-stamped `build_check_registry` — so a
   prod-PHI cleartext hop FAILS at commit/CI. **Fail-safe SKIP** with no `messagefoundry.toml` /
   unloadable settings/graph (a bare dir has no declared posture) → byte-identical for a dev checkout.
4. **Posture-B tails.** (a) A **cert-authenticated intra-service auth** is now **audited**: the
   `GET /service/identity` route (the only `require_service_cert` surface) writes a `service_cert_auth`
   row into the tamper-evident chain naming the mapped principal (PHI/secret-free — auth plane + route
   only). (b) **Runtime KEX enforcement** is verified: when the engine terminates TLS in-process,
   `build_api_ssl_context` pins the approved forward-secret groups (`harden_kex_groups`), and a real
   handshake test proves a client offering only a non-approved FFDHE group is refused — runtime
   enforcement, not the operator attestation the proxy-terminated (Posture-B) case still relies on. (c) A
   real **mutual-TLS handshake** test exercises the exact server context the serve path builds
   (`CERT_REQUIRED`): a trusted client cert completes, a missing one is refused. **Genuinely deferred
   (infra-bound):** a full uvicorn-on-a-real-socket mTLS handshake through the live serve bind is left to
   the Windows TLS CI legs — the handshake tests here exercise the same `build_api_ssl_context` context,
   so the only drift they don't catch is the uvicorn wiring, not the TLS policy.

All four **compose with** the existing #200 serve-path enforcement, the #201 outbound revocation guard
(fires only on a VERIFYING hop — disjoint from the cleartext/verify-off condition), the #199 cleartext-
egress refusal, and the #129 expiry-relaxation (which stays a VERIFIED hop the posture gate never keys
on). The production-PHI clamp (`weakened_tls_escape_permitted` / `hop_insecure_escape_downgrades`) remains
the **single authority** for the global escape on every path; no path logs PHI or a secret.

## Amendment (2026-07-20) — two acknowledged production-PHI carve-outs to the No-loosen rule (§5)

The No-loosen rule (§5) is refined by [ADR 0140](0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md): two production-PHI floor items may now
be lifted, each behind a **dedicated, single-purpose `[security]` acknowledgment switch** (default `false` →
byte-identical) — `allow_single_factor_admin_when_exposed` (the exposed-prod-PHI `require_mfa`-off refusal)
and `allow_unencrypted_phi_in_production` (prod keyless PHI, which also requires `allow_unencrypted_phi`).
Each downgrades the production refusal to a loud, audited warning surfaced in `GET /security/posture`. These
are the **only** two carve-outs: the cleartext/verify-off transport-hop clamp of this ADR (the escape-clamp
of §2, `hop_insecure_escape_downgrades`) is **unchanged** and can still never satisfy a production-PHI hop;
cleartext off-box bind, no-auth-to-network, open egress, and unbounded PHI retention stay hard-refused; and
ePHI-access auditing (the ADR 0118 invariant #2) stays unconditional.

## Amendment (2026-07-21) — refuse/warn dial + escape-clamp re-keyed from `production` to `[security].enforcement` (ADR 0148 §5/§7)

[ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (GIVEN 2) replaces the
derived `production` tier as the **refuse/warn dial** (§5 No-loosen severity) **and** the escape-clamp key
(§2/§7 — `hop_insecure_escape_downgrades` / `weakened_tls_escape_permitted`, i.e. the `--allow-insecure-bind`
/ `MEFOR_ALLOW_INSECURE_TLS` escapes) with an explicit `[security].enforcement` level (`enforce` default |
`warn`). `HopPosture.production` is renamed `enforcing`. Every re-keyed site **retains its `is_phi`
conjunct**, so no synthetic hop is newly refused; at the default (`enforce` × PHI) every gate decision and
every escape-clamp is **byte-identical** to the former production-PHI behaviour (adversarially verified), and
`enforcement = warn` reproduces the historical non-production warn-and-cross (a loud, audited loosening). The
two carve-outs of the 2026-07-20 amendment re-key to `enforcement`, and the keyless-PHI ack is renamed
`allow_unencrypted_phi_in_production` → `allow_unencrypted_phi_under_strict_enforcement` (see the ADR 0140
amendment). The four hard-refused floor items and the unconditional ePHI audit are unchanged.
