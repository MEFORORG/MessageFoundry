# ADR 0092 — Posture-keyed transport-hop refusal (refuse the insecure PHI hop)

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
