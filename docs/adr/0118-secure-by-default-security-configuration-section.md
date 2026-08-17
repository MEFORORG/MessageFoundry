# ADR 0118 — Secure-by-default `[security]` configuration section (plain-language, replace scattered keys)

- **Status:** Accepted (2026-07-17) — owner signed off; implemented under BACKLOG [#270](../BACKLOG.md)
- **Date:** 2026-07-17
- **Related:** [CLAUDE.md](../../CLAUDE.md) §2 (auth/RBAC), §9 (PHI/HIPAA), §12 (prefer TOML) · [ADR 0007](0007-gui-manageable-connections-toml.md) (GUI-manageable config-as-data) · [ADR 0017](0017-consumer-deployment-model.md) (org-owned config repo) · [ADR 0065](0065-web-ops-dashboard.md) (web console) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) (posture-keyed refusal + escape clamp) · [ADR 0002](0002-phase2-transport-security-and-strong-auth.md) (transport security) · [docs/research/config-ux-review.md](../research/config-ux-review.md) defect **DD2** · ASVS drive-to-pass (WP242–246, SHIPPED)

> **Amended by [ADR 0143](0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md) (2026-07-21):**
> `serve_web_console` defaults **`true`** (the console is on by default) and is reframed as a
> surface-*reducing* opt-out — **not** a loosening (it does not appear in `security_loosenings()`;
> disabling it shrinks the `/ui` attack surface).

> **Amended by [ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (2026-07-21):**
> the `[security]` section gains an explicit **`enforcement`** dial (`enforce` default | `warn`) that replaces
> the derived `production` tier as the serve-gate refuse/warn key **and** the ADR 0092 escape-clamp key (§1 the
> section, §3 the loosening it warns). `production_instance` is **demoted to an informational tier fact** (it
> drives the AI data-scope ceiling + the DEBUG-log refusal + reporting only, not the security dial), and the
> built-in `dev`/`staging`/`prod` envs **all derive PHI** (GIVEN 1 — a genuinely-synthetic box sets
> `handles_real_patient_data = false` explicitly, a loud audited opt-out). The ADR 0140 keyless-PHI ack is
> renamed `allow_unencrypted_phi_in_production` → `allow_unencrypted_phi_under_strict_enforcement` (§5). At the
> default (`enforce` × PHI) serve is byte-identical to the former production-PHI behaviour.

---

## Context

MessageFoundry carries PHI and is **on-premises by default**. [CLAUDE.md](../../CLAUDE.md) §9 states, verbatim:

> **On-premises by default:** no PHI leaves the local environment without explicit, reviewed
> configuration. The API binds `127.0.0.1` by default and **requires authentication**; every PHI
> access (raw view, summary display) is audited with the acting user.

The behaviour that enforces this is already built and fail-closed — a long serve-time gate ladder in
[__main__.py](../../messagefoundry/__main__.py) (`_serve`), mirrored at commit/CI by
[checks.py](../../messagefoundry/checks.py). A branch-scoped survey confirmed the **defaults are already
the secure position** (loopback bind, auth-on, MFA-required, TLS floor, deny-by-default egress for PHI,
keyless-PHI refusal). So this is **not** a security rewrite.

The problem is **discoverability and jargon**, not enforcement:

1. **Scattered.** Security-relevant settings live across ~19 TOML sections. There is **no `[security]`
   section** — only a future-only placeholder in [docs/CONFIGURATION.md](../CONFIGURATION.md) that the
   project's own config-UX review already flags as defect **DD2** ("`[security]` heading is a
   future-only placeholder … reads like a config section but isn't one").
2. **The master lever is mis-homed.** Nearly every secure default keys on the instance **posture triple**
   `[ai].data_class` / `[ai].production` / `[ai].environment` — the single most important security fact
   about an instance ("does this carry real patient data?") is buried in a section named for AI-assistance
   policy.
3. **Engine jargon.** The behaviourally-central concepts are Python *properties* — `is_loopback`,
   `exposure_protected`, `tls_enabled` — with no plain-language operator-facing name.

We want a customer (often not a security expert) to open one section, read plainly-named controls, see
that each **defaults to the secure position**, and make a **deliberate, warned** decision to loosen any of
them. This is the CISA *Secure by Design* model: "a secure configuration should be the default baseline";
"make customers acutely aware when they deviate from safe defaults"; and "ideally a setting should not
exist … each new setting increases the cognitive burden" — i.e. keep the section **lean**.

**Constraint (do not break):** every refusal the current gate ladder makes must still fire. This ADR
**re-points** the gates at friendlier keys; it must not loosen any shipped refusal (the No-loosen rule of
[ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) §5 applies here too).

**Nothing is deployed yet.** There are no external operators holding references to the current key names,
so we **replace** the scattered keys outright — no deprecation, alias, or migration window.

## Decision

**Introduce a dedicated `[security]` TOML section as the *canonical, sole* home for the high-value security
posture switches, named in plain language, each defaulting to the secure position; delete the scattered
legacy keys and re-point every serve gate + the `checks.py` mirror at the new section. Editing is
IDE-only; the web console stays read-only.**

### 1. The `[security]` section (lean, secure-by-default)

Only **posture switches** move here. Low-level *plumbing* (TLS cert paths, egress allow-list *contents*, DB
connection identity, password-policy knobs, rate limits, AD/LDAP) **stays in its functional section** — per
CISA "minimize settings", the section a non-expert reads must not become a 100-knob panel. All booleans use
**positive framing: secure state is `true`** (`require_*` / `*_only`), consistently, to avoid the
double-negative footgun.

```toml
[security]
# ── Network access (operator API + web console) ──────────────────
local_access_only            = true          # reachable only from this machine
listen_address               = "127.0.0.1"   # used only when local_access_only = false
require_encryption_for_remote = true         # any off-machine access must be over TLS
serve_web_console            = false         # mount the browser ops console at /ui
web_console_public_address   = ""            # external origin when the console is exposed

# ── Encryption of stored data ────────────────────────────────────
encrypt_stored_data          = true          # PHI encrypted at rest (key from env)
allow_unencrypted_phi        = false         # audited escape: start a PHI instance with no key

# ── Sign-in & identity ───────────────────────────────────────────
require_sign_in              = true          # authenticate every request
require_mfa                  = true          # second factor for admin step-up
sign_out_after_idle_minutes  = 30
max_session_hours            = 12

# ── Data handling ────────────────────────────────────────────────
block_unlisted_outbound      = true          # deny-by-default egress; only allow-listed destinations send
delete_message_bodies_after_days = 30        # 0 = keep indefinitely (audited)
allow_keeping_phi_indefinitely   = false
audit_all_authorization_decisions = true     # PHI access is ALWAYS audited; this adds full authz tracing
                                             # (was false here; flipped by ADR 0168 / BACKLOG #1277)

# ── What this instance handles (the master posture lever) ────────
handles_real_patient_data    = true          # was [ai].data_class = "phi"
production_instance          = true          # was [ai].production
```

### 2. Replacement map (delete → re-point)

| New `[security]` key | Replaces | Gate re-pointed |
|---|---|---|
| `local_access_only` (guard) + `listen_address` | `[api].host` | `is_loopback` / exposed-bind gate ([__main__.py](../../messagefoundry/__main__.py)) |
| `require_encryption_for_remote` | (absence of TLS) | `exposure_protected` + the ADR 0092 cleartext-hop refusals |
| `serve_web_console` | `[api].serve_ui` | `/ui` off-loopback refuse gate |
| `web_console_public_address` | `[api].public_origin` | CSRF/CSWSH + WebAuthn RP-id gate |
| `encrypt_stored_data` / `allow_unencrypted_phi` | `[store].require_encryption` / `[store].allow_unencrypted_phi` | keyless-PHI refuse gate |
| `require_sign_in` | `[auth].enabled` | auth-off + non-loopback refuse |
| `require_mfa` | `[auth].require_mfa` | MFA-at-exposure gate |
| `sign_out_after_idle_minutes` / `max_session_hours` | `[auth].session_idle_timeout_minutes` / `session_absolute_hours` | session lifetime checks |
| `block_unlisted_outbound` | `[egress].deny_by_default` | egress deny-by-default (allow-list *contents* stay in `[egress]`) |
| `delete_message_bodies_after_days` / `allow_keeping_phi_indefinitely` | `[retention].messages_days` / `allow_unbounded_phi` | retention auto-bound + prod refuse |
| `audit_all_authorization_decisions` | `[diagnostics].audit_all_authz` | grant-audit scope |
| `handles_real_patient_data` / `production_instance` | `[ai].data_class` / `[ai].production` | the posture triple every gate + the AI-policy clamp reads |

`environment` selection (which `environments/<env>.toml` loads) is **not** a security posture switch and
stays where it is; `handles_real_patient_data` / `production_instance` keep deriving from the environment
name exactly as `[ai]` does today, so a stock dev/staging/prod instance needs no explicit value.

### 3. Loosening is deliberate and warned (CISA "loosening guide")

Setting any protection to its insecure value:
- **logs a plain-language warning** at serve naming the risk incurred (reuse the existing exposure-gate
  warning machinery), and
- **still refuses** wherever the pre-refactor gate refused — the production-PHI clamp of
  [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) is unchanged: a
  loosening key can **never** relax a production-PHI refusal, exactly as `--allow-insecure-bind` /
  `MEFOR_ALLOW_INSECURE_TLS` cannot today.

A new **`docs/SECURITY-LOOSENING.md`** carries one entry per opt-out — *what you lose / when it is
acceptable / compensating controls* — the inverted-hardening-guide CISA prescribes.

### 4. Editing is IDE-only; reporting is read-only

- **Engine** reads `[security]` from the config file / `/config/reload`. There is **no settings-write API**.
- **Web console** shows the effective posture **read-only** via the existing `GET /security/posture`
  ([api/app.py](../../messagefoundry/api/app.py)), extended to render the `[security]` values, any active
  loosenings, and the synthetic-relaxation notice (§5). It gains **no** editor.
- **VS Code extension** ([ide/](../../ide/)) is the **sole authoring surface** — a GUI editor for
  `[security]` with friendly labels, secure defaults pre-filled, inline plain-language descriptions, and a
  loosening warning shown in-editor when a protection is toggled off. This follows the
  [ADR 0007](0007-gui-manageable-connections-toml.md) config-as-data GUI precedent.

### 5. Two default-value judgments (owner veto points)

- **SUPERSEDED 2026-08-17 by [ADR 0168](0168-default-the-authorization-grant-audit-on-the-console-cannot-flood-it.md)
  (BACKLOG #1277): the default is now `true`.** The bullet below is kept verbatim rather than edited,
  because the *reason* it gives is the part that was later falsified and a reader needs to see it. The
  flood it names was never measured when this was written; measured afterwards, it is not connected to
  this switch — the browser console never traverses the gate that records grants, and WebSocket
  authorization fires once per connection. Everything else in this ADR stands.
- **`audit_all_authorization_decisions` defaults `false`.** ePHI access is **already always audited** (the
  tamper-evident audit hash-chain and the message-event compliance floor are unconditional, independent of
  this key). This toggle only extends tracing to *every* authorization decision including non-sensitive
  ones — defense-in-depth, not a HIPAA requirement — and forcing it on by default risks **flooding the
  audit log**, which itself degrades security monitoring. So the secure-and-usable default is scoped, with
  the friendly name/description making the always-on PHI auditing explicit.
- **Preserve the PHI-vs-synthetic split, made visible.** A synthetic/dev instance carries no ePHI, so the
  strict PHI-only gates (at-rest-encryption refusal, deny-by-default egress, bounded retention) staying
  relaxed there is defensible risk-based tailoring and preserves dev ergonomics — it is what the engine
  does today. `handles_real_patient_data` is the lever; the posture view **states** "strict controls
  relaxed: instance marked synthetic" so the relaxation is never silent.

## Acceptance Criteria

- **AC-1** — THE SYSTEM SHALL resolve every security posture switch listed in §2 from the `[security]`
  section, and the legacy scattered keys SHALL no longer be accepted.
  → `tests/test_security_config.py::test_security_section_is_canonical`
- **AC-2** — WHEN a `[security]` protection is absent, THE SYSTEM SHALL apply its secure default (the value
  shown in §1).
  → `tests/test_security_config.py::test_secure_defaults_applied`
- **AC-3** — WHEN `local_access_only = true` AND `listen_address` is non-loopback, THE SYSTEM SHALL refuse
  to start (exit 2) — parity with the pre-refactor `[api].host` gate.
  → `tests/test_security_config.py::test_local_access_only_refuses_nonloopback`
- **AC-4** — WHEN a protection is set to its insecure value, THE SYSTEM SHALL log a plain-language warning
  naming the risk; and IF the instance is production-PHI, THEN THE SYSTEM SHALL still refuse wherever the
  pre-refactor gate refused (the ADR 0092 clamp is not relaxed).
  → `tests/test_security_config.py::test_loosening_warns_and_prod_phi_refuses`
- **AC-5** — THE SYSTEM SHALL expose the effective `[security]` posture (incl. active loosenings and the
  synthetic-relaxation notice) read-only via `GET /security/posture`, and SHALL expose no endpoint that
  writes any security setting.
  → `tests/test_api_security_posture.py::test_posture_reports_security_and_has_no_write_route`
- **AC-6** — WHERE `handles_real_patient_data = false`, THE SYSTEM SHALL relax the PHI-only gates AND the
  posture view SHALL state the relaxation.
  → `tests/test_security_config.py::test_synthetic_relaxation_visible`
- **AC-7** — THE SYSTEM SHALL refuse every bind/hop the pre-refactor gate ladder refused (no shipped
  refusal loosened), verified through the new keys by the `checks.py` commit/CI mirror.
  → `tests/test_checks_gate_parity.py::test_gate_parity_through_security_keys`

## Options considered

1. **Dedicated `[security]` section, replace the scattered keys, IDE-only editing** — one discoverable,
   plain-language home; lean per CISA; re-points proven gates. **CHOSEN.**
2. **Posture presets (`posture = standard|locked-down|custom`)** — CIS-tier model (L1 usable / L2
   defense-in-depth). Rejected/deferred: adds a second cognitive layer over the keys for this operator
   audience; revisit only if operators ask.
3. **Inline friendly aliases beside the existing keys** — leaves the jargon sections in place; does not
   fix discoverability (DD2). Rejected.
4. **Docs-only (name/describe the existing keys better)** — cheapest, but the scatter and the mis-homed
   posture lever remain. Rejected.
5. **Deprecate + alias for back-compat** — the industry norm, but there are **no deployed operators** to
   protect, so it is pure cost. Rejected in favour of a straight replace.

## Consequences

**Positive**
- One discoverable, plain-language home; every control visibly defaults secure; loosening is deliberate and
  warned (CISA loosening-guide).
- The single most important security fact — "does this carry real patient data?" — is surfaced as
  `handles_real_patient_data` instead of buried in `[ai]`.
- Strengthens the ASVS / HIPAA-§164.312 evidence story (access restriction, transmission security,
  authentication, audit) without touching enforcement.
- Clears config-UX defect **DD2**.

**Negative / risks**
- A **wide rename sweep**: `config/settings.py`, the `__main__.py` gate ladder, `checks.py`,
  `environments/*.toml`, `samples/`, and the test suite change in lockstep. A missed reference is the main
  risk — mitigated by `mypy --strict`, the `checks.py` mirror, and the **gate-parity** test (AC-7).
- Two **behavioural default judgments** (§5) are called by the author for the owner to veto.
- The per-setting **ASVS v5 / NIST 800-53r5 mapping table** must be finalized against primary texts — the
  research could confirm the HIPAA→800-53r5 crosswalk (NIST SP 800-66r2 App. D) and AC-6 (Least Privilege)
  but not each individual ASVS ID, so the table is assembled, not asserted.

**Out of scope**
- Posture presets (option 2); changing any enforcement *logic*; a settings-write API; renaming the
  low-level plumbing keys (TLS cert paths, egress allow-list contents, DB identity, password policy, rate
  limits) — those stay in their functional sections.

## Resolved on acceptance (2026-07-17)

- [x] **Two default-value judgments (§5) — owner confirmed both.** `audit_all_authorization_decisions`
      defaults **`false`** (ePHI access is always audited regardless; this only extends tracing to every
      authz decision, and forcing it on risks flooding the audit log). The **PHI-vs-synthetic split is
      preserved and surfaced**: a synthetic instance keeps the PHI-only gates relaxed exactly as today, and
      the posture view **states** the relaxation so it is never silent.
- [x] **Move-vs-stay boundary — owner delegated to the author; §1/§2 adopted verbatim** with these
      implementation judgments:
  - **Desugar, don't re-point (ADR 0007 precedent).** `[security]` is a thin **input layer**: the loader
    reads it, **rejects** the legacy keys as file/env input (AC-1), and **populates the existing internal
    fields** (`ai.data_class`, `api.host`, `auth.enabled`, `egress.deny_by_default`, …) from it at a
    precedence *below* CLI flags (so `--db`/`--host` still override). The serve gate ladder, the
    `checks.py` mirror, `hop_posture_from_ai`, and the AI-policy resolver then keep reading those internal
    fields **unchanged** — which is what makes AC-7 gate-parity provable and confines the blast radius to
    the loader + tests. The posture *representation* stays `DataClass`-enum + `bool` internally; the
    `handles_real_patient_data` ↔ enum mapping happens only at the TOML edge.
  - **`handles_real_patient_data` / `production_instance` default = derived-from-environment**, not a
    literal `true`. A stock dev→synthetic / staging·prod→PHI instance needs no explicit value (parity); a
    custom-named env with no explicit posture still **fails closed** (`require_posture()` raises), which is
    at least as strict as defaulting `true`. The §1 `= true` is the *resolved secure position* shown for
    documentation, not the raw default.
  - **`encrypt_stored_data` (default true)** is the headline; its insecure value contributes to the store's
    audited keyless-PHI opt-out (`store.allow_unencrypted_phi = allow_unencrypted_phi OR NOT
    encrypt_stored_data`), preserving exact parity (PHI refuses keyless by default; synthetic runs keyless).
    The niche **`[store].require_encryption`** ("force a key even on a synthetic instance") **stays in
    `[store]` as plumbing** so no shipped refusal is lost.
  - **`require_encryption_for_remote` (default true)** re-expresses the existing off-loopback-needs-TLS
    refusal; its insecure value is the config-file twin of `--allow-insecure-bind`, under the **same
    ADR 0092 production-PHI clamp** (can never relax a production-PHI cleartext bind).
  - **`local_access_only` + `listen_address`:** when `local_access_only=true` the effective bind is forced
    loopback; a contradictory `local_access_only=true` **and** a non-loopback `listen_address` **refuses to
    start** (AC-3) rather than silently overriding.
  - **Stay-in-place plumbing** (not moved): TLS cert paths, `[egress].allowed_*` contents,
    `[retention].dead_letter_days` (keeps its own auto-bound), DB identity, password policy, rate limits,
    AD/LDAP.
- [x] **ASVS v5 / NIST 800-53r5 mapping** — finalized against primary texts in `docs/SECURITY-LOOSENING.md`
      (HIGH-confidence IDs cited from primary sources; anything unverifiable is marked, not asserted).
- [x] **VS Code extension is the sole editing surface**; the web console stays read-only
      (`GET /security/posture`, no settings-write route). The `[security]` GUI editor follows the ADR 0007
      `connections.toml` precedent with secure defaults pre-filled and an in-editor loosening warning.
- [x] **Loosening-warning wording + `docs/SECURITY-LOOSENING.md` entry set** — one entry per opt-out
      (*what you lose / when it is acceptable / compensating controls*), with the serve-time warning naming
      the risk incurred.

## Amendment (2026-07-20) — two production-PHI acknowledgment switches (§1/§3/§5)

[ADR 0140](0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md) adds two switches to the `[security]` section of §1:
`allow_single_factor_admin_when_exposed` and `allow_unencrypted_phi_in_production` (both default `false`,
byte-identical). They are the two named exceptions to §3's rule that "a loosening key can never relax a
production-PHI refusal": each is a deliberate, single-purpose acknowledgment that drops exactly one
production-PHI refusal (single-factor admin at exposure; keyless PHI in production, which also requires
`allow_unencrypted_phi`) to a loud, audited warning, surfaced read-only in `GET /security/posture`. Every
other production-PHI floor item stays hard-refused and the always-on ePHI auditing (§5 / SECURITY-LOOSENING
invariant #2) is untouched. Unlike the §2 relocated keys, these two are brand-new fields read directly by
the serve gate (no legacy key, no desugar passthrough). See ADR 0140 for the fixed code/doc discrepancy
(the shipped keyless gate had no production branch).
