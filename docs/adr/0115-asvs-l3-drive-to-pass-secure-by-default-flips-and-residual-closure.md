# ADR 0115 — ASVS L3 drive-to-Pass: secure-by-default flips and residual closure

- **Status:** Accepted (2026-07-16) — owner-directed scope decision; builds phased across BACKLOG #242–#246, pushes/PRs owner-approved.
- **Deciders:** owner (chose the drive-to-Pass sweep over leaving the shipped controls as accepted residuals) + the 2026-07-16 ASVS re-score's per-cell reconciliation.
- **Related:** ASVS-L3-ASSESSMENT-2026-07-16.md (the 59 open cells this drives) · ASVS-REMEDIATION-2026-07.md (the plan + per-cell mapping) · ASVS-L3-RISK-ACCEPTANCE-REGISTER.md (the residuals that stay owned) · amends [ADR 0018](0018-per-message-signatures-accepted-risk.md) (JWS default), [ADR 0080](0080-offbox-forwarding-tls-defaults.md) (forwarding default), [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (WebAuthn), [ADR 0014](0014-alerting-rules-engine.md) (approvals/notify), [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (AAD/nonce), [ADR 0004](0004-payload-agnostic-ingress.md) (magic-byte), [ADR 0077](0077-action-bound-step-up.md) (step-up), [ADR 0105](0105-streaming-very-large-hl7-attachments-detach-the-opaque-document-from-the-transformable-skeleton.md) (served filename) · BACKLOG **#242–#246**.

---

## Context

The 2026-07-16 ASVS 5.0 L3 re-score records **50 Partials (Posture A) / 51 (Posture B) and 2 Fails**. Almost every Partial is a control that is **built and shipped** but scored Partial because it is **opt-in, off-by-default, or delegated** — the four-verdict rubric's honest treatment of "built but not effective without operator action." The prior remediation waves (#186–#205) deliberately shipped many of these **off by default** for real reasons: HL7 real-world tolerance (strict validation), partner compatibility (per-message signing), no-collector installs (off-box forwarding), keyless synthetic/CI parity (at-rest encryption), single-operator loopback (maker-checker approvals).

The owner faced a fork: **accept these as owned residuals** (they are, in the signed register), or **drive them to Pass**. The owner chose **drive-to-Pass** — but a naïve "flip every default on" is wrong: an unconditional flip would break a legitimate deployment (a dev box with no SMTP collector, a partner with no JWS verifier, a single-operator loopback install). The decision must distinguish *where a global flip is safe* from *where the secure posture belongs to the documented off-loopback deployment*.

## Decision

Adopt a **secure-by-default-where-safe, runbook-instructed-otherwise** posture, applied per control:

1. **Flip the global default ON only where it cannot break a valid deployment.** These are controls whose secure setting is already conditioned on a signal that means "this is real": on a `data_class=phi` instance, ship a bounded default `[retention]` window (14.2.4/14.2.7) and keep egress deny-by-default (13.2.4/13.2.5) and cleartext-egress refusal (12.2.1) — the PHI posture already gates them, so a synthetic/CI box stays byte-identical.

2. **Instruct the control in the Posture-B runbook where a global flip would break a valid install.** For maker-checker approvals (2.3.5), per-message JWS signing (4.1.5), off-box log forwarding (16.4.3), and the phishing-resistant WebAuthn factor (6.3.3/6.5.7/6.7.2), the secure setting is deployment-specific: `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` gains an explicit instruction (and, where a fail-closed prod-PHI serve gate is defensible, an enforcement), so the **documented deployment** earns Pass while the loopback/no-collector/partner-less default stays unchanged. A control scored off in Posture B because no guidance turns it on is not a Pass — so the runbook instruction is the deliverable, not a code flip.

3. **Build the small missing last-mile controls** where the gap is genuinely a missing mechanism, not a default: AEAD context-binding (11.3.3), the AES-GCM invocation counter (11.3.4), time-sync enforcement (16.2.2), log-all-authorization-decisions (16.3.2), the keyed audit chain default (16.4.2), accept-time magic-byte validation (5.2.2), extended anti-automation pacing (2.4.2), and action-bound step-up on the remaining sensitive lanes (7.5.1/7.5.2).

4. **Refresh the maintained inventories** (11.1.2, 13.1.1, 13.1.4) — pure documentation drift; the artifacts simply fell behind in-window code.

5. **Formally accept the genuinely delegated residuals** (WP #246): the Posture-B proxy-TLS floor/cipher/hop (12.1.x, 12.3.x, 4.2.1, 4.4.1, 11.6.2) the engine cannot inspect because it terminates no browser TLS; backend-credential least-privilege (13.2.1/13.2.2) and SMART AS enforcement (10.4.16) that belong to the org / authorization server; AV scanning (5.4.3). These stay Partial but move from *silently* Partial to *explicitly owned* in the register.

6. **Leave the scope-C heavies and accepted deviations owned as signed residuals** (not in this ADR's scope): the in-process runtime sandbox (15.2.5), hardware/HSM key custody (13.3.1/13.3.3), the ECH/in-use-memory platform gaps (12.1.5/11.7.2), and the tolerant-HL7 accepted deviations (2.2.1/2.2.3). An owner elects these separately.

Each flip/build amends its owning feature ADR (see Related); no control's secure posture is changed without its ADR record updated in the same work.

## Consequences

- **Byte-identical where it matters:** a synthetic/CI/loopback install, and any install with no PHI class declared, sees no behavior change from the WP #243 flips — the secure defaults are conditioned on the PHI posture or instructed only in the off-loopback runbook.
- **The documented off-loopback deployment earns materially more Passes** without the engine pretending to enforce a control it delegates (the honesty rule from the assessment is preserved: a runbook instruction that the operator must follow is what lifts Posture B, and a fail-closed serve gate is added only where refusing to start is defensible).
- **The residual set shrinks to the genuinely-delegated + platform-bound cells.** After #242–#245, the open Partials should be dominated by WP #246 (delegated) and the scope-C heavies — a smaller, fully-owned set. A fresh assessment records the actual movement; this ADR does not re-score.
- **The two Fails (12.1.5 ECH, 13.3.3 isolated crypto module) are unchanged** — they are the scope-C platform builds, deferred by design.
- **Build discipline:** each WP is one coherent layer per commit, new behavior gets a test, and the pushes/PRs are owner-approved. The ADR amendments land with their builds.

## Amendment (2026-07-17) — WP #243-A landed the PHI-gated flips; 12.2.1 stays posture-gated (WP #243)

**Status:** Built + doc-only, per §Decision item 1. WP #243-A landed the **PHI-class-gated** global
flips that cannot break a synthetic/CI/loopback install: egress **deny-by-default** (13.2.4 / 13.2.5)
and a bounded **non-production-PHI retention** default (14.2.7) now apply on a `data_class = "phi"`
instance, while a box with no PHI class declared stays byte-identical.

The cleartext-egress control (**12.2.1**) is **PHI-posture-gated by design** and is *not* globally
flipped: `insecure_hop_disposition` ([`config/tls_policy.py`](../../messagefoundry/config/tls_policy.py))
ALLOWs a cleartext `http://` hop on a **non-PHI** instance (§Decision item 1 forbids unconditionally
refusing it) and REFUSEs only a **production-PHI** hop with no attestation. So 12.2.1 lifts to Pass on
a **production-PHI instance** (the Posture-B deployment) but **stays Partial on a non-PHI Posture-A
box** — and a non-production PHI instance only WARNs-and-crosses, so it stays effectively Partial too.
The accepted, by-design residual.

The runbook-instructed controls (2.3.5 / 4.1.5 / 6.3.3 · 6.5.7 · 6.7.2 / 16.4.3) land as amendments
on their owning feature ADRs (0014 / 0018 / 0068 / 0080); this ADR does not re-score.

## Amendment (2026-07-21) — the default/CI "byte-identical keyless synthetic-CI parity" promise is retired (ADR 0148)

[ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (GIVEN 1) remaps the
built-in `dev` env from `(SYNTHETIC, non-prod)` to `(PHI, non-prod)`, so the **default/CI path now runs the
PHI configuration** (store key required, deny-by-default egress, bounded retention, the PHI transport-hop
authority armed). This **retires this ADR's stated CI-parity property for the default** — a genuinely-
throwaway box must now declare `[security].handles_real_patient_data = false` **explicitly** (a loud, audited
opt-out), and CI provisions a runtime-generated synthetic store key + an egress allow-list on the real-serve
legs. The trade is deliberate: **deployment fidelity** (staging / pre-prod exercises the hardened paths prod
depends on) over zero-secret CI convenience. Separately, ADR 0148 (GIVEN 2) decouples the refuse/warn dial
from the `production` tier onto `[security].enforcement` (default `enforce`); the Posture-B scorecard framing
this ADR references collapses to {loopback, off-loopback} (both assumed PHI + enforcing) in the current
assessment.
