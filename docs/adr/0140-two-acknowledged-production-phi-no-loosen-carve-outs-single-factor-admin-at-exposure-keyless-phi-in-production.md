<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0140 — Two acknowledged production-PHI No-loosen carve-outs: single-factor admin at exposure + keyless PHI in production

- **Status:** Accepted (2026-07-20)
- **Date:** 2026-07-20
- **Related:** [ADR 0118](0118-secure-by-default-security-configuration-section.md) (the `[security]` secure-by-default section — amended §1/§3/§5) · [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md) §5 (the No-loosen rule — amended) · [docs/SECURITY-LOOSENING.md](../SECURITY-LOOSENING.md) (invariant #1 corrected)

---

## Context

The `[security]` section ([ADR 0118](0118-secure-by-default-security-configuration-section.md)) ships
**secure by default**, and [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
§5 (the **No-loosen rule**) has been documented — via `docs/SECURITY-LOOSENING.md` invariant #1 — as an
absolute floor: *no* `[security]` value can start a **production instance that handles real patient data**
with a cleartext off-box bind, no auth, **single-factor admin**, **keyless PHI**, open egress, or unbounded
PHI retention.

Two operators with a genuine, reviewed need asked to deliberately weaken exactly two of those controls on a
production-PHI instance where a **compensating control lives outside MessageFoundry** — an MFA-enforcing
reverse proxy in front of the admin surface, and a host whose **volume/disk encryption** protects the store
while application-key provisioning is pending. Both requests were owner-approved. Granting them requires a
single-purpose, loud, audited acknowledgment — not a broad relaxation of the floor.

Mapping the two controls to the shipped code surfaced a **code/doc discrepancy**:

- **Keyless PHI (over-claimed as immovable).** The shipped keyless-store serve-gate
  (`messagefoundry/__main__.py`, under `if data_class is DataClass.PHI:`) has **no `production` branch**:
  `[security].allow_unencrypted_phi=true` **alone** already booted a production instance keyless, in every
  environment. So invariant #1's claim that keyless PHI was immovable on production was **never true in
  code**. This ADR both corrects the doc and *adds* the missing production branch (a deliberate slight
  **tightening**, below).
- **Single-factor admin (genuinely immovable).** The require-MFA-at-exposure gate did enforce a hard
  production refusal (`if production: … return 2`). That one was accurate; this ADR lifts exactly it behind
  an ack.

## Decision

Introduce **two dedicated, single-purpose `[security]` acknowledgment switches**, each a plain `bool`
defaulting `false` (⇒ serve behaviour byte-identical to today for every stock and every keyed instance):

1. **`allow_single_factor_admin_when_exposed`** — on a **production** PHI instance whose admin surface is
   exposed (off-loopback bind, or a declared reverse proxy) with `require_mfa` off, the gate normally
   **refuses to start**. When this ack is set, the refusal is lifted to the **same loud warning a
   non-production PHI exposure already emits**, plus a startup **AUDIT** line. Off-production it is a no-op
   (there is no refusal to lift); on a **loopback** bind it is a no-op (no exposure).
2. **`allow_unencrypted_phi_in_production`** — the keyless-store gate gains a **production branch**: a
   production PHI instance may start keyless only when **both** `allow_unencrypted_phi` **and** this second
   ack are set. Missing the second ack on production **refuses fail-closed** (exit 2). A **non-production**
   PHI instance is unchanged — the single `allow_unencrypted_phi` opt-out still applies. With both set, the
   keyless start emits its existing loud warning + a startup **AUDIT** line that names both flags.

Each switch is **loud** (a `serve`-time warning), **audited** (a `WARNING`-level `AUDIT:` log line on the
weakened path), and **surfaced** read-only in `GET /security/posture` via `security_loosenings()`.

> **Precision on "byte-identical":** at defaults the serve **decision and exit code** are unchanged on
> every path, and every **non-production** output is verbatim. The only text delta is that the two
> **production refuse** messages (keyless-prod and exposed-prod-MFA-off) each gain a one-clause pointer to
> their new ack, so an operator who hits the refusal is told how to opt in — the refusal itself is
> unchanged (still exit 2).

### Deliberate tightening (switch 2)

Switch 2 is **not byte-identical** for one pre-existing configuration: `{production PHI + no key +
allow_unencrypted_phi=true}` **booted keyless before** and now **refuses** unless
`allow_unencrypted_phi_in_production` is also set. This is the owner-approved, deliberate correction — the
highest-risk posture (real PHI + production) must never be one flag away from plaintext at rest. Every stock
secure-default instance (`allow_unencrypted_phi` unset → refused at the first gate) and every keyed instance
is entirely unaffected.

### What stays hard-refused on production PHI

These are the **only** two carve-outs. Every other production-PHI floor item remains **unconditionally**
fail-closed, unmovable by any `[security]` value or the `--allow-insecure-bind` / `MEFOR_ALLOW_INSECURE_TLS`
escapes:

1. a **cleartext off-box bind** (the ADR 0092 posture clamp cannot be relaxed);
2. **no authentication to the network** (auth off + non-loopback is a hard refuse at any posture);
3. **open egress** (fully-unrestricted outbound on a production PHI instance);
4. **unbounded PHI retention** on production (beyond the existing `allow_keeping_phi_indefinitely` audited
   downgrade).

The always-on **ePHI-access audit** (the tamper-evident hash-chain + message-event floor, ADR 0118
invariant #2 / §5) is **untouched** and remains unconditional.

### Wiring — direct-read, no desugar

Both switches are **brand-new `SecuritySettings` fields** with **no legacy home**. They follow the
`require_encryption_for_remote` precedent: the serve gate reads them **directly** as
`settings.security.<name>`. They are deliberately **NOT** added to `_SECURITY_PASSTHROUGH`, **NOT** added to
`_RELOCATED_TO_SECURITY`, **NOT** handled in `_desugar_security`, and have **no** `StoreSettings` /
`AuthSettings` twin — a desugar-to-internal-field would build a dead second home and a duplicate loosening
row. `security_loosenings()` is extended to name each when `True`. No default is flipped; no other gate is
changed; `api/` and the webconsole seam snapshot are untouched (the acks surface through the existing nested
`security` model-dump + `loosenings`).

## Consequences

- **Positive** — a reviewed production deployment with an external compensating control can deliberately
  weaken exactly one of two controls, loudly and audibly, without the operator patching source; the keyless
  floor is corrected so production is no longer one flag from plaintext at rest.
- **Negative / risk** — switch 2 is a behaviour change (the deliberate tightening) for the one config above;
  it is called out here and in `docs/SECURITY-LOOSENING.md`. An operator who sets an ack takes on the
  documented compensating-control obligation.
- **Doc corrections** — `docs/SECURITY-LOOSENING.md` invariant #1 is rewritten to four immovable items + the
  two named carve-outs; [ADR 0092](0092-posture-keyed-transport-hop-refusal-refuse-the-insecure-phi-hop.md)
  §5 and [ADR 0118](0118-secure-by-default-security-configuration-section.md) §1/§3/§5 carry amendment
  cross-refs to this ADR.

## Acceptance Criteria

- **AC-1** — WHEN a production PHI instance has `allow_unencrypted_phi=true` and no key but **not**
  `allow_unencrypted_phi_in_production`, `serve` SHALL exit 2 naming `allow_unencrypted_phi_in_production`.
  → `tests/test_cli.py::test_serve_keyless_prod_phi_single_flag_refuses`,
  `tests/test_checks_gate_parity.py` (`keyless-prod-phi-single-flag-refuses`).
- **AC-2** — WHEN both keyless acks are set on a production PHI instance with no key (other prod gates
  satisfied), `serve` SHALL start and emit the loud audited keyless warning. →
  `tests/test_cli.py::test_serve_keyless_prod_phi_both_acks_starts_with_warning`,
  `tests/test_checks_gate_parity.py` (`keyless-prod-phi-both-acks-allows`).
- **AC-3** — WHEN a non-production PHI instance is keyless with only `allow_unencrypted_phi`, `serve` SHALL
  still start and warn (byte-identical). → `tests/test_cli.py::test_serve_keyless_phi_override_starts_with_warning` (unchanged).
- **AC-4** — WHEN an exposed production PHI instance runs `require_mfa` off **with**
  `allow_single_factor_admin_when_exposed=true`, `serve` SHALL start with the warn + a startup AUDIT line
  (no refusal). → `tests/test_cli.py::test_serve_exposed_prod_phi_single_factor_ack_starts_with_warning`,
  `tests/test_checks_gate_parity.py` (`mfa-off-exposed-prod-phi-single-factor-ack-allows`).
- **AC-5** — WHEN the ack is absent, the exposed production PHI `require_mfa`-off bind SHALL still exit 2. →
  `tests/test_cli.py::test_serve_refuses_exposed_without_mfa_in_prod` (unchanged).
- **AC-6** — Both fields SHALL default `false` and SHALL each appear in `security_loosenings()` exactly once
  when set, and in `GET /security/posture`. → `tests/test_security_config.py::test_secure_defaults_applied`,
  `test_production_acks_are_loosenings_when_set`, `tests/test_api_security_posture.py::test_posture_reports_production_ack_switches`.

## Options considered

1. **Two direct-read `[security]` acks (default false), gate-read like `require_encryption_for_remote`.**
   **CHOSEN** — smallest surface, single canonical home, no dead twins.
2. **Desugar each ack into a `[store]`/`[auth]` internal twin** (passthrough + relocated-key reject). —
   **Rejected**: invents a spurious internal field for a serve-gate-only acknowledgment, and the gate would
   still read `settings.security.<name>` (which exists), making the twin dead code.
3. **A single combined "I accept production weakening" master switch.** — **Rejected**: it would relax more
   than one control at once, defeating the single-purpose, per-control audit intent.

## To resolve on acceptance

- [x] Two `SecuritySettings` bool fields (default `false`), read directly by the serve gates.
- [x] `security_loosenings()` names each ack exactly once when set.
- [x] Keyless gate gains the production sub-branch (both acks required); non-production byte-identical.
- [x] require-MFA gate lifts the production refusal behind the ack with an AUDIT line; non-production byte-identical.
- [x] `docs/SECURITY-LOOSENING.md` invariant #1 corrected + two deviation entries + switch-table + standards rows.
- [x] Amendment cross-refs appended to ADR 0092 §5 and ADR 0118 §1/§3/§5.
- [x] IDE `[security]` editor gains both switches; CLI `security show` needs no change (generic model-dump).

## Amendment (2026-07-21) — re-keyed to `[security].enforcement`; the keyless ack renamed (ADR 0148)

[ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (GIVEN 2) replaces the
derived `production` tier with an explicit `[security].enforcement` level (`enforce` default | `warn`) as the
serve-gate refuse/warn dial. Both carve-outs re-key accordingly — each gate is now `if enforcement is ENFORCE
and not <ack>: refuse` (the `is_phi` conjunct retained). The keyless-PHI ack is **renamed**
`allow_unencrypted_phi_in_production` → `allow_unencrypted_phi_under_strict_enforcement` (the single-factor
ack keeps its name). At the default (`enforce` × PHI) behaviour is **byte-identical** to this ADR;
`enforcement = warn` **voids both acks** along with every other refuse arm (reproducing the historical
non-production warn-and-start), so the two acks remain the **surgical stay-at-`enforce`, lift-exactly-one-
control** alternative. The four floor items that stay hard-refused and the unconditional ePHI audit are
unchanged. (This supersedes the original ack name in §Decision item 2 and the switch-2 discussion above.)

## Amendment (2026-08-04) — the exposure predicate no longer reads the console flag (BACKLOG #326)

The single-factor-admin-at-exposure carve-out above is keyed on `admin_exposed`. As shipped that was
`not settings.api.is_loopback or ui_exposed`, and `ui_exposed` is derived from `settings.api.serve_ui`
— a field the two [ADR 0143](0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md)
degrade arms rewrite **in place** earlier in the same `serve` call (soft-degrade when the console wheel
is absent; auto-degrade when a default-on console meets an exposed bind). By the time this gate read it,
`serve_ui` answered "is `/ui` mounted?" — a presentation fact — rather than "is the admin interface
reachable from the network?", the exposure fact the carve-out is about.

The consequence would have been visible on first deployment of the topology the runbooks **recommend**:
a loopback bind behind a declared TLS terminator, with `[security].serve_web_console` left at its
default. The auto-degrade clears the console flag, so `admin_exposed` evaluated `False`, so a production
PHI instance under `enforcement = enforce` with `[security].require_mfa = false` would have started
clean — with the JSON operator API reachable off-box through that proxy on a single admin factor, and
with `allow_single_factor_admin_when_exposed` having nothing to lift. The same boot was simultaneously
classified **exposed** by the ASVS 11.7.1 arm ([ADR 0152](0152-in-use-data-protection-for-phi-platform-memory-encryption-attestation-asvs-11-7-1.md)),
which already used the console-independent predicate. One startup, two contradictory answers to "is this
instance exposed?".

**Corrected keying.** `instance_exposed = not settings.api.is_loopback or
settings.api.tls_terminated_upstream` is now defined **once**, above the first consumer, and both the
MFA-at-exposure arm (`admin_exposed = instance_exposed`) and the ASVS 11.7.1 arm read that one
definition. Neither reads `serve_ui`. `ui_exposed` survives, scoped to what it actually describes: the
`/ui`-specific origin/TLS refusals and the browser-console advisories.

**What changes.** The refusal now fires on at least three postures it did not reach before: a declared
proxy with the console default-on (auto-degraded), a declared proxy with `serve_web_console = false`,
and a declared proxy where the console wheel is simply not installed. An off-loopback bind behaved
correctly before and is unchanged. A plain loopback bind with nothing declared is **not** exposed and
is byte-identical — the property the loopback-quiet tests pin.

**This is a tightening, and it is deliberate.** A configuration that starts today would refuse on first
deployment of the corrected build. Per the owner ruling of 2026-08-04 it ships as a real refusal: no
warning-first phase, no dated flip, and **no new opt-in gating it**. There are no deployments to protect
from an upgrade, so the simple correct end state is what gets built. The refusal continues to ride the
existing `[security].enforcement` refuse/warn split like every sibling gate.

**The acknowledgment is unchanged.** `[security].allow_single_factor_admin_when_exposed` still lifts this
one refusal to permitted-but-audited, with its WARNING-level `AUDIT:` line and its entry in
`security_loosenings()`. The ruling forbade a *new* opt-in gating the corrected refusal; it did not
retire this one. Its practical reach grows, because it now has the postures above to act on.

**Residual, deliberately left open — an UNDECLARED proxy is still not "exposed", and it now has its own
warning.** A set `[api].public_origin` (`[security].web_console_public_address`) with no
`tls_terminated_upstream` on a loopback bind does not satisfy `instance_exposed`, so this refusal does
not fire there. That is a choice: nothing has been declared, so exposure would be an *inference*, and
the ruling that tightened this gate was about a **declared** proxy. Promoting an inference to a refusal
is a different decision, and was not authorised here.

An earlier draft of this amendment justified leaving it open by asserting the case "still warns",
pointing at the ADR 0068 §8 undeclared-proxy heuristic. **That premise was false, and measurement is
what showed it**, so it is corrected here rather than quietly dropped. §8's warning is about the `/ui`
session cookie and HSTS — it says nothing about admin factors — and it is gated on
`settings.api.serve_ui`, which the ADR 0143 auto-degrade clears in place for exactly this input (a
default-on console plus a set `public_origin`). On the commonest shape of the posture it therefore did
not print at all: the residual was not "warned rather than refused", it was **silent**. A compensating
control must not rest on a false premise, so the control was built rather than the sentence softened —
a dedicated arm now warns, naming single-factor admin, when `public_origin` is set, the instance is not
`instance_exposed`, the declared data class is PHI, and `require_mfa` was explicitly opted out. A truly
signal-less undeclared proxy — no `public_origin` either — remains undetectable in-engine and
runbook-only, as ADR 0068 §8 records.

**A second residual, NOT closed here — the auth-disabled refusal still keys on the bind alone.** The
much earlier startup arm for `[auth] enabled = false` reads `not settings.api.is_loopback`, several
hundred lines above where `instance_exposed` is defined, and this change does not touch it. So a PHI
instance with authentication entirely off, on a loopback bind behind a declared terminator, would still
start on first deployment — and the loosening text it prints still reads "loopback-only; a non-loopback
bind refuses", which the corrected exposure model contradicts. That is the same
two-answers-in-one-startup shape this amendment corrects, one arm over. It was left alone deliberately:
the owner ruling named `admin_exposed`, and re-keying the auth-off arm needs its own hoist (it runs
long before the current definition) plus its own adjudication, because it would convert that topology
from starting to refusing. **Recorded here as an open item for the owner** so it is not rediscovered as
a surprise.

**Also amended:** [ADR 0143](0143-web-console-on-by-default-disableable-with-loopback-secure-context-browser-hardening.md)
carries a cross-reference noting that its in-place `serve_ui = False` flips no longer feed any exposure
predicate.
