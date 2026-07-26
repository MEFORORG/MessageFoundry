# 0109 — At-rest encryption fail-closed on an undeclared PHI posture

- **Status:** Rejected (2026-07-14)  <!-- premise refuted on close code review — see the Rejection note below -->
- **Date:** 2026-07-14
- **Related:** [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (fail-closed escape pattern) · [ADR 0019](0019-pluggable-keyprovider-hsm-kms-vault.md) (KeyProvider) · [ADR 0036](0036-windows-config-source-trust.md) (the `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE` audited-escape precedent) · [Secure Development Standards](../Secure_Development_Standards.md) **PW.9** (secure defaults) · [Secure Build Scorecard](../Secure_Build_Scorecard_MEFOR.md) gap #4 · [CLAUDE.md](../../CLAUDE.md) §9 (PHI). **Tier: S2×P2 ⇒ T3.**

> ## ⛔ REJECTED (2026-07-14) — the premise does not hold
>
> On close review of the actual `serve` path, **the "undeclared → cleartext PHI" hole this ADR set out to close does not exist.** `serve` **requires an environment** (`__main__.py:938`), and `AiSettings.require_posture()` (`settings.py:1625`) **fails closed** — a custom env with no explicit `data_class` raises → refuse to start. The built-in derivations (`settings.py:1560`) are `dev→SYNTHETIC`, `staging→PHI`, `prod→PHI`. So the value reaching the keyless-at-rest gate is **always a resolved posture**: every PHI posture already refuses a keyless start (fail-closed), and cleartext at rest occurs **only** for a declared/derived **SYNTHETIC** instance (`dev` or explicit `synthetic`) — which asserts no real PHI by design (`ai_policy.py:66`).
>
> "Default undeclared → PHI" therefore targets a state that **cannot run**. The change would affect only `--env dev` / explicit-synthetic instances — breaking the deliberate CI/dev keyless-synthetic workflow for **zero PHI-security gain** (the "Option A too blunt" failure this ADR itself rejected). The residual — an operator running a synthetic-declared env while actually holding real PHI — is an operator misdeclaration the engine trusts (like the audited `allow_unencrypted_phi` opt-out), recorded as a standing note in the [risk-acceptance register](../security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md). The [Secure Build Scorecard](../Secure_Build_Scorecard_MEFOR.md) gap #4 was corrected accordingly (at-rest is fail-closed-by-default for every PHI posture). **No code shipped.**
>
> *The design content below is retained as append-only history — it records the option that was considered and why it was declined.*

---

## Context

The [Secure Build Scorecard](../Secure_Build_Scorecard_MEFOR.md) (gap #4) flags that at-rest store encryption "ships OFF by default." An adversarial read of the code (2026-07-14) refined that picture — the current posture is smarter than the one-line finding, and the residual hole is narrower and specific:

- At-rest encryption is enabled by configuring a **key** (`[store].encryption_key` / `encryption_key_file`); with no key the store uses `IdentityCipher` — plaintext (`store/crypto.py:454`).
- `[store].require_encryption` (default `False`, `config/settings.py:301`) is **not** the encryption switch. It is a serve-time guard that, when `True`, refuses a keyless start in *any* environment (`__main__.py:981-988`).
- A **`data_class==phi`** instance with no key **already hard-fails closed** at startup (`__main__.py:980-1004`, exit 2) *unless* the operator sets the audited opt-out `[store].allow_unencrypted_phi=true`. Built-in `--env prod` derives `data_class=phi`, so a production deployment is **already** protected.
- **The residual hole:** an instance whose `data_class` is **undeclared / underived** is treated as **not PHI** (`config/settings.py:1643-1662`) and is therefore permitted to run cleartext at rest. The common out-of-box case that ships cleartext is precisely an instance that has *not asserted* its PHI posture.

This is a **fail-open-on-ambiguity** default. The governing principle is SDS **PW.9**: "Ships secure-by-default … encryption on …; insecure options require explicit, documented opt-in." And [CLAUDE.md](../../CLAUDE.md) §9, verbatim:

> **On-premises by default:** no PHI leaves the local environment without explicit, reviewed configuration. The API binds `127.0.0.1` by default and **requires authentication**; every PHI access (raw view, summary display) is audited with the acting user.

An engine that carries PHI should not persist it in cleartext merely because the operator forgot to declare a posture. The reliability, purity, and count-and-log invariants are untouched by this change (it is a startup-gate default, not a pipeline change).

## Decision

**Default an undeclared / underived `data_class` to PHI, so an instance that has not proven it is synthetic fails closed on a keyless start** — reusing the already-built keyless-PHI serve gate (`__main__.py:980-1004`) rather than adding a new enforcement path.

Concretely:

- When `[ai].data_class` is neither explicitly set nor derived from a built-in env, resolve it to **PHI** (was: non-PHI).
- The existing gate then refuses a keyless start (exit 2) unless the operator makes an **explicit, audited choice**, one of:
  1. **Declare `[ai].data_class = synthetic`** — the honest assertion "this instance carries no PHI"; returns to the permissive (keyless-OK) path. Primary opt-out for dev / test / CI / synthetic.
  2. **Configure a key** (`encryption_key` / `encryption_key_file`) — at-rest encryption on.
  3. **`[store].allow_unencrypted_phi=true`** — the pre-existing audited "PHI, but accept cleartext at rest" override (emits a WARNING audit line), unchanged.

It must **not** break: the keyless→keyed read path (existing cleartext rows must stay readable — verified: `AesGcmCipher.decrypt` passes marker-less values through, `crypto.py:397-398`); prod (already fail-closed); or the count-and-log / reliability invariants.

## Acceptance Criteria

> EARS, each linked (`→`) to the test that verifies it. Tests are **to be authored on build** (this ADR is Proposed / no code yet), so `adr-analyze` will report the links as pending until then.

- **AC-1** — WHEN `serve` starts with no store key configured AND `data_class` is undeclared/underived, THE SYSTEM SHALL refuse to start (exit 2) with a message naming the three opt-outs.
  → `tests/test_store_key_posture.py::test_undeclared_dataclass_refuses_keyless_start`
- **AC-2** — WHERE `[ai].data_class = synthetic` is declared, THE SYSTEM SHALL start keyless (permissive path preserved).
  → `tests/test_store_key_posture.py::test_declared_synthetic_starts_keyless`
- **AC-3** — WHILE a store key is configured, THE SYSTEM SHALL encrypt at rest regardless of `data_class` (no regression).
  → `tests/test_store_crypto.py::test_keyed_store_encrypts`
- **AC-4** — WHEN a keyed store reads a row written earlier by the keyless `IdentityCipher`, THE SYSTEM SHALL return the original plaintext value (mixed-store back-compat).
  → `tests/test_store_crypto.py::test_keyed_reads_legacy_plaintext`
- **AC-5** — IF `[store].allow_unencrypted_phi=true`, THEN THE SYSTEM SHALL start keyless AND emit a WARNING audit line (audited opt-out, unchanged).
  → `tests/test_store_key_posture.py::test_allow_unencrypted_phi_audited_optout`

## Options considered

1. **Fail-closed on unknown posture — default undeclared→PHI, reuse the built gate.** Closes the residual hole with the smallest surface; makes cleartext-at-rest an explicit, audited choice everywhere; "clamp up on ambiguity" (mirrors the Secure AI-Assisted Development Standards fail-closed resolver and the `127.0.0.1` bind guard). **CHOSEN.**
2. **Global `require_encryption=True` default.** Rejected: too blunt — refuses *every* keyless start incl. synthetic/dev/CI/harness/first-run, forces an operator secret everywhere (no zero-config key path exists), for no PHI-coverage gain over the already-built PHI gate.
3. **First-run auto-mint + DPAPI-protect key (the "Layer 2" zero-config path).** The only route to *literal* encryption-on-with-zero-config, but **deferred to a follow-on ADR** (out of scope here): it is net-new code, Windows-bound (DPAPI), and inverts CI/synthetic parity. This ADR (Layer 1) closes the gap independently and more cheaply.
4. **Accept the risk (no change).** Rejected in favour of the fix (owner elected Layer 1). A dated risk-acceptance in the signed register remains the fallback if the change proves too disruptive.

## Consequences

**Positive** — Cleartext-at-rest becomes an explicit, audited opt-out at every posture, not a silent default for undeclared instances; aligns with SDS PW.9 and the fail-closed house pattern; reuses a built, tested gate (no new enforcement path); prod unaffected (already fail-closed); back-compat safe on reads. Closes Secure Build Scorecard gap #4 → the composite re-grades **B+ → A−** once merged (the only remaining A− blocker was "at-rest-on-by-default OR independent verification").

**Negative / risks** — Behaviour change: an existing keyless deployment on a *custom/no env with undeclared `data_class`* will now refuse to start until it declares `synthetic`, configures a key, or sets `allow_unencrypted_phi`. Blast radius is bounded but real — every dev / CI / harness / sample-config / test-fixture that starts a keyless store *without declaring a posture* must be updated in the same change or the required gate reddens. Keyed→keyless remains unsafe (removing a key orphans encrypted rows — a pre-existing property, not introduced here).

**Out of scope** — Layer 2 first-run auto-key (separate ADR); DPAPI / KeyProvider changes (ADR 0019); keyed→keyless migration; backend-native TDE (SQL Server / Postgres).

## To resolve on acceptance

- [ ] Confirm the exact `data_class` derivation for built-in env names (`dev` / `staging` / `prod`) so `--env dev` stays permissive (synthetic) and **only** truly-undeclared instances flip.
- [ ] Decide the opt-out surface: are `data_class=synthetic` + the existing `allow_unencrypted_phi` sufficient, or do we **also** add a dedicated ergonomic env escape `MEFOR_ALLOW_CLEARTEXT_AT_REST` (mirroring `MEFOR_ALLOW_INSECURE_CONFIG_SOURCE`, ADR 0036) for dev/test?
- [ ] Inventory and update every keyless-start site (tests / fixtures / CI / harness / sample configs) so the required gate stays green in the same change.
- [ ] Confirm the Secure Build Scorecard credits "fail-closed-on-unknown" as closing gap #4 (vs. insisting on literal encryption-on, which would require Layer 2).
- [ ] Docs to update on build: `PHI.md` (at-rest), `SECURITY.md`, the ASVS 11.3.x residual notes + the signed register, and the scorecard re-grade to A−.
