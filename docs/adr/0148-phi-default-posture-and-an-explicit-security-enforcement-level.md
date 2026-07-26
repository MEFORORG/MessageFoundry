<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0148 — PHI-default posture and an explicit `[security].enforcement` level (deployment scoring collapses to loopback vs off-loopback)

- **Status:** Accepted (2026-07-21) — owner-decided; build phased (GIVEN 1 flip → GIVEN 2 enforcement) **+ deferred-docs landed** on branch `sec-enforce` (rebased onto `origin/main`; full suite green, 7870 passed). The per-cell **scorecard re-score + owner re-signature remain pending (an owner act, assessment §6)** — the reframe framing + honesty footnotes are recorded as an unsigned pending note. Pushes/PR owner-approved.
- **Date:** 2026-07-21
- **Related:** [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) §5/§7 (the No-loosen rule + `HopPosture` — amended: the `production` arm and clamp key become `enforcement`) · [ADR 0140](0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) (the two carve-outs — re-keyed to `enforcement`; `allow_unencrypted_phi_in_production` renamed) · [ADR 0118](0118-secure-by-default-security-configuration-section.md) §1/§3/§5 (the `[security]` section gains `enforcement`; `production_instance` demoted to an informational tier fact) · [ADR 0115](0115-asvs-l3-drive-to-pass-secure-by-default-flips-and-residual-closure.md) (retires the "byte-identical keyless synthetic-CI parity" promise for the default/CI) · [ADR 0109](0109-at-rest-encryption-fail-closed-on-an-undeclared-phi-posture.md) (Rejected — this ADR **adopts its rejected direction** for the *default env*, by a narrower mechanism; it does not resurrect 0109's undeclared→PHI resolver) · [ADR 0017](0017-consumer-deployment-model.md) (posture decoupled from the environment name) · [docs/SECURITY-LOOSENING.md](../SECURITY-LOOSENING.md) (invariant #1 + a new `enforcement=warn` deviation) · [docs/security/OFF-LOOPBACK-DEPLOYMENT.md](../security/OFF-LOOPBACK-DEPLOYMENT.md) (startup ladder rephrase) · [docs/security/ASVS-L3-ASSESSMENT-2026-07-20.md](../security/ASVS-L3-ASSESSMENT-2026-07-20.md) (scorecard reframe, deferred)

---

## Context

The engine keys its secure-by-default serve-gate ladder and the ADR 0092 transport-hop authority on **two
operator-derived posture axes** plus one exposure fact:

1. **`data_class`** (`SYNTHETIC` | `PHI`, `messagefoundry/config/ai_policy.py`) — arms the PHI at-rest,
   egress-lock, retention, and cleartext-hop controls only when `phi`.
2. **`production`** (a bool, derived from the env name via `_KNOWN_ENV_POSTURE`) — a **refuse-vs-warn
   severity dial**: every PHI gate reads `if production: exit 2 else: warn-and-cross`. It is **also** an
   **escape-clamp**: the blunt escapes (`MEFOR_ALLOW_INSECURE_TLS` via `hop_insecure_escape_downgrades` /
   `weakened_tls_escape_permitted`, and per-hop attestation) are **forbidden from loosening a production-PHI
   hop** (ADR 0092 decision 2 / #200; ADR 0140).
3. **Exposure** — loopback vs off-loopback (`ApiSettings.is_loopback` / `exposure_protected`).

Two consequences the owner set out to fix:

- **The ASVS scorecard silently conflates these axes.** It reports two columns (Posture A / Posture B) but
  makes "Posture A" mean *loopback **and** synthetic **and** non-production* and "Posture B" mean
  *off-loopback **and** PHI **and** production*. Several controls (e.g. 11.3.4, 16.4.2, the egress-allowlist
  and retention families, 12.2.1, 6.3.5) read as "Partial in A" for a **data-class / production** reason
  dressed up as an **exposure** reason.
- **A non-production instance runs a *different configuration* than production.** Because `data_class` and
  `production` are derived from the env name and relax the PHI/refuse controls off-production, a staging /
  pre-prod box exercises **none** of the hardened paths prod depends on (the store-cipher path, the egress
  allow-list, the retention purge, the TLS-hop refusals, the MFA/notification/approvals gates). The
  hardened config is therefore **first exercised in production**. This is a dev/prod **configuration-parity**
  defect: the "byte-identical dev/CI parity" property (ADR 0109's rejection rationale, ADR 0115) is valuable
  for an **ephemeral unit-test CI runner** but was allowed to bleed into the meaning of "non-PHI *instance*",
  so a **pre-prod** box that must mirror prod inherited a CI runner's looseness.

The owner set **two design givens**: (1) the **default configuration and CI run the PHI path**; (2) replace
`production` as a *derived posture input* with an **explicit, operator-chosen enforcement level** defaulting
to today's production behaviour. With both, `data_class` and `production` stop being *deployment postures*
(they become documented loosenings), and the honest deployment scorecard collapses to the one axis the
engine cannot control on-box: **loopback vs off-loopback**, both assumed PHI + enforcing.

## Decision

### GIVEN 1 — PHI is the default posture; `synthetic` is an explicit opt-out

`_KNOWN_ENV_POSTURE["dev"]` changes from `(SYNTHETIC, False)` to `(PHI, False)`, so the default/CI env runs
the PHI path (store-encryption key required, egress `deny_by_default`, bounded retention, the PHI hop
authority armed) at **non-production** severity. `synthetic` becomes a **rare, explicit, warned opt-out**
(`[security].handles_real_patient_data = false` → `data_class = synthetic`) for a genuinely-throwaway CI /
dev box; it surfaces as a loosening (`security_loosenings()` + `GET /security/posture` + a
`docs/SECURITY-LOOSENING.md` entry). This adopts the *direction* ADR 0109 was rejected for, by a narrower
mechanism (remap the `dev` derivation + provision CI, **not** default an undeclared `data_class` to PHI —
`require_posture()` stays fail-closed on a custom/unset env, see FIX 1). CI provisions a synthetic store key
(generated at runtime, never a committed literal) + an egress allow-list on the real-serve legs.

### GIVEN 2 — `[security].enforcement` replaces `production` as the refuse/warn dial and the escape-clamp key

A single new field `[security].enforcement`, enum `SecurityEnforcement` = `enforce` (default) | `warn`,
added beside `DataClass` in `config/ai_policy.py`:

- **`enforce`** (default) reproduces today's **production** behaviour: every PHI serve-gate **refuses**
  (exit 2), and every escape-clamp is **shut** (a production-PHI hop cannot be loosened).
- **`warn`** reproduces today's **non-production** behaviour: the same gates log + audit + continue, and the
  blunt escapes are honoured — the loud, audited, documented **loosening**.

Everywhere the code today asks *"is this a production-PHI hop? → refuse / the escape can't loosen it"* it
instead asks *"is `enforcement is ENFORCE` **and** `is_phi`?"*. Because `enforcement` defaults `enforce` and
GIVEN 1 defaults `data_class=phi`, the **default answer is byte-identical to today's production-PHI answer**.
`HopPosture.production` is renamed `enforcing` (`config/tls_policy.py`), `fail_closed` keeps `enforcing=True`
(unchanged strictness), and `hop_posture_from_ai` threads `settings.security.enforcement`. The refuse/warn
**dial** sites (`insecure_hop_disposition` / `revocation_hop_disposition` arms; the `__main__.py` serve
gates for egress, Posture-B attestation, MFA-at-exposure, retention, security-notifications) and the
**escape-clamp** sites (`hop_insecure_escape_downgrades`, `weakened_tls_escape_permitted`,
`_inbound_insecure_bind_permitted`, the `--allow-insecure-bind` API-bind clamp) all re-key from `production`
to `enforcement`, **retaining every `is_phi` conjunct** (so no synthetic hop is newly refused).

### Wiring — direct-read, no desugar (the ADR 0140 precedent)

`enforcement` is a brand-new `SecuritySettings` field, read **directly** as `settings.security.enforcement`.
It is deliberately **NOT** in `_SECURITY_PASSTHROUGH`, **NOT** in `_RELOCATED_TO_SECURITY`, has no `[ai]`
alias and no internal twin — exactly like the ADR 0140 acks and `require_encryption_for_remote`. Env override
`MEFOR_SECURITY_ENFORCEMENT=warn` works via the standard `MEFOR_<SECTION>_<KEY>` path. It is surfaced
read-only in `GET /security/posture`, and `enforcement=warn` is named by `security_loosenings()`.

**Binary, not three-level.** The dial being replaced is binary (refuse vs warn); the "silence entirely"
outcome is already `data_class=synthetic`. An `off` level would manufacture a "cross a PHI cleartext hop
silently" capability ADR 0092 forbids; it is not introduced.

### Four adjudications from the adversarial no-loosen verification (build to these, not the raw design)

- **FIX 1 — `require_posture()` stays fail-closed.** It is **not** relaxed. A custom-env PHI box that leaves
  `production_instance` unset still **refuses to serve**; the serve gate simply stops reading its `production`
  element. Relaxing it would default `production=True`, which is the *most-permissive* value for the AI
  data-scope ceiling — a fail-open. (Rejected relaxation.)
- **FIX 2 — the AI data-scope ceiling stays on the retained `production` tier fact, decoupled from
  `enforcement` (a deliberate decision, owner-confirmed).** Splitting `production` (AI ceiling) from
  `enforcement` (security) makes `production_instance=true` + `enforcement=warn` reachable (permissive-AI +
  lax-security), a combination welded shut today. Practical exploitability is ~nil (`data_scope=phi` needs a
  BAA-managed mode, not yet wired), but it is recorded here as intentional: **lowering `enforcement` does NOT
  lower the AI ceiling.** The ceiling remains keyed on `production` in `resolve_effective_policy`.
- **FIX 3 — the DEBUG-logging refusal stays keyed on the retained `production` tier fact**, NOT on
  `enforcement` (which would let `warn` re-enable DEBUG-with-PHI-in-logs) and NOT on `data_class` (which,
  once GIVEN 1 defaults `dev→phi`, would refuse DEBUG on a routine loopback dev box). Byte-identical to today
  (prod refuses; dev/staging allow) and un-openable by `enforcement=warn`.
- **FIX 4 — orthogonality wording corrected.** The re-keyed ADR 0140 acks are `if enforcement is ENFORCE and
  not <ack>: refuse`, so `enforcement=warn` **voids** the second-ack requirement along with every other
  refuse arm (this equals today's non-production behaviour — not a *new* looser state, and loud/audited). The
  two single-purpose acks remain the **surgical stay-at-`enforce`, lift-exactly-one-control** alternative;
  they are not described as unaffected by `enforcement`.

### Fate of `production` / `_KNOWN_ENV_POSTURE`

`production` is **retained, demoted to informational**: it feeds the AI data-scope ceiling (FIX 2) and
reporting (`GET /security/posture`, the startup log, `checks.py`), and continues to be derived from the env
name via `_KNOWN_ENV_POSTURE` for those consumers. It no longer drives any refuse/warn or escape-clamp
decision.

## Consequences

- **The one behaviour change** — a box that is *today* non-production (staging = PHI/non-prod, or a custom
  PHI-loopback env) currently **warns** on the PHI ladder and honours `--allow-insecure-bind`; under the
  default `enforce` it now **refuses** until the operator sets `[security].enforcement = warn`. Strict-by-
  default; opt down loudly. `dev` stays open only if declared `synthetic`. Every stock production instance is
  byte-identical (it was `enforce`-equivalent already).
- **Deployment scoring collapses to {loopback, off-loopback}** — the scored default `(is_phi=True,
  enforcing=True)` is byte-identical to today's `(is_phi=True, production=True)`, so both retired posture
  *inputs* (`data_class`, `production`) become footnoted loosenings, not scored columns. **Deferred:** the
  scorecard re-score + risk-register re-sign is owed once GIVEN 1 + GIVEN 2 land, and is **held** until the
  parallel ADR 0143 "owner re-sign" of `docs/security/ASVS-L3-*` settles, to avoid two sessions rewriting the
  same assessment tables in parallel (see the sequencing note).
- **Dev/prod configuration parity** — staging/pre-prod now exercises the store-cipher path, the egress
  allow-list, the retention purge, and the TLS-hop refusals that production depends on, so a config error
  (key mount, egress list, proxy attestation, retention window) surfaces on the safe box, not in production.
- **CI cost** — the default/CI path now requires a (synthetic) store key + an egress allow-list on the
  real-serve legs; a genuinely-no-PHI box must now write `handles_real_patient_data = false` explicitly. This
  is the intended trade (deployment fidelity over CI convenience) and reverses ADR 0115's stated CI-parity
  promise for the default.

### What stays no-loosen on a PHI instance at `enforce`

Byte-for-byte with today's production-PHI floor: the cleartext off-box bind clamp (ADR 0092), no-auth-to-
network refusal, open-egress refusal, unbounded-PHI-retention refusal, and the unconditional tamper-evident
ePHI-access audit. The two ADR 0140 carve-outs still require their acks at `enforce`.

## Acceptance Criteria (implemented + verified 2026-07-21 — GIVEN 1 then GIVEN 2; full suite green)

- [x] **AC-1** — `SecurityEnforcement` enum (`enforce`|`warn`); `SecuritySettings.enforcement` defaults
  `enforce`, direct-read, absent from `_SECURITY_PASSTHROUGH`/`_RELOCATED_TO_SECURITY`;
  `MEFOR_SECURITY_ENFORCEMENT` overrides.
- [x] **AC-2** — at the default (`enforce` × PHI) every serve-gate decision, exit code, and every escape-clamp
  is **byte-identical** to today's production-PHI behaviour (parity tests per gate + per clamp).
- [x] **AC-3** — `enforcement = warn` reproduces today's non-production warn behaviour on every gate, and is
  named exactly once by `security_loosenings()` and in `GET /security/posture`.
- [x] **AC-4** — the DEBUG-logging refusal keys on the retained `production` tier fact (not `enforcement`,
  not `data_class`); `enforcement=warn` cannot re-enable DEBUG on a production instance.
- [x] **AC-5** — `require_posture()` still exits 2 on a custom/unset-env PHI instance with no explicit
  `production_instance` (fail-closed unchanged).
- [x] **AC-6** — `_KNOWN_ENV_POSTURE["dev"]` derives `(PHI, False)`; a keyless `--env dev` **refuses** unless
  `handles_real_patient_data = false`; the CI real-serve legs pass with a synthetic key + egress allow-list.
- [x] **AC-7** — the two ADR 0140 acks (renamed `allow_unencrypted_phi_in_production` →
  `allow_unencrypted_phi_under_strict_enforcement`) still refuse-without-ack at `enforce`; `enforcement=warn`
  voids them like every other refuse arm.

## Options considered

1. **Explicit `[security].enforcement` (binary, default `enforce`) replacing `production` as the dial +
   clamp key; `production` retained informational for the AI ceiling.** **CHOSEN** — smallest surface,
   preserves the no-loosen guarantee byte-for-byte at the default, gives the operator the explicit choice.
2. **Keep `production` as the derived dial; only reframe the scorecard docs.** Rejected — leaves the dev/prod
   configuration-parity defect (staging still diverges from prod) unaddressed.
3. **Drop the `data_class` axis and force PHI-grade config on every box (default→PHI globally, incl.
   ephemeral CI, with a mandatory key everywhere).** Rejected — the ADR 0109 rejection stands for *ephemeral
   CI*: it breaks the zero-secret unit-test path for no security gain, and does not fix the silent
   forgot-to-declare fail-open (a loud explicit `synthetic` opt-out does).
4. **A three-level `enforcement` (`enforce`|`warn`|`off`).** Rejected — `off` manufactures a
   silently-cross-a-PHI-cleartext-hop capability ADR 0092 forbids; the "silence" outcome is `synthetic`.

## To resolve on acceptance

- [x] GIVEN 1: `_KNOWN_ENV_POSTURE["dev"] → (PHI, False)`; CI synthetic-key fixture + egress allow-list on
  the real-serve legs; `docs/SECURITY-LOOSENING.md` synthetic-opt-out entry.
- [x] GIVEN 2: `SecurityEnforcement` enum + `SecuritySettings.enforcement`; `HopPosture.production→enforcing`;
  all dial + escape-clamp re-keys with `is_phi` conjuncts retained; FIX 1–4; ADR 0140 ack rename; message
  strings that hardcode "production" reworded.
- [x] Surface `enforcement` in `GET /security/posture` + the startup log + `checks.py`.
- [x] Tests: default-`enforce` parity per gate/clamp; `warn` reproduces non-prod; DEBUG on the tier fact;
  `require_posture` fail-closed; `dev→phi` refusal. (Full suite green post-rebase: 7870 passed / 680 skipped.)
- [x] **Deferred-docs — landed 2026-07-21** (the ADR 0143 re-sign `9e2b337d` settled, unblocking these):
  `docs/CONFIGURATION.md` `[security]` `enforcement` row; `docs/SECURITY-LOOSENING.md` invariant #1 reframe +
  `enforcement`/synthetic deviations + rename; `docs/security/OFF-LOOPBACK-DEPLOYMENT.md` ladder rephrase
  (refuse-at-`enforce` / warn-at-`warn`); `docs/PHI.md` §3; `docs/EARLY-ADOPTER-GUIDE.md` gen-key onboarding
  note; amendment cross-refs into ADR 0092 §5/§7, 0115, 0118 §1/§3/§5, 0140. **Scorecard reframe:** the
  {loopback, off-loopback} reframe *framing* + honesty footnotes are recorded as an **unsigned pending note**
  in `docs/security/ASVS-L3-ASSESSMENT-2026-07-20.md` (+ pending-re-sign markers in `Secure_Build_Scorecard`
  and the risk register); the per-cell **re-score + owner re-signature remain an owner act** (assessment §6),
  not performed here. 11.3.3 held Partial (needs `aad_bind` default — separate decision).
