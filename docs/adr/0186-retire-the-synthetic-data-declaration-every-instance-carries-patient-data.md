# ADR 0186 — Retire the synthetic-data declaration: every instance carries patient data

**Status:** Accepted (2026-09-09) — owner ruling, given directly: *"I don't want to use
`handles_real_patient_data` any more. I want mefor to always take a PHI posture as the default. Users
can adjust individual settings as they need, but not use `handles_real_patient_data = false` as a
combined override."* **BUILT 2026-09-09** under BACKLOG #1279. Completes the direction
[ADR 0153](0153-collapse-the-posture-gradient-no-data-label-may-allow-a-cleartext-hop.md) started and
[ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) GIVEN 1 half-took.
Amends [ADR 0118](0118-secure-by-default-security-configuration-section.md) §1/§3 (the posture lever)
and [ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) GIVEN 1 (the
explicit synthetic opt-out). Retains ADR 0148 GIVEN 2 (`[security].enforcement`) unchanged, and
retains the production **tier** everywhere it is read.

**Scope:** the **data-class axis** and nothing else. The production tier, the enforcement dial, every
per-gate switch and every per-connection declaration keep their inputs and their behaviour.

## Context

`[security].handles_real_patient_data = false` translated to `[ai].data_class = "synthetic"` and, on
that one line, turned off **nineteen** start-up gates. Measured at `0ce6d95cf`, before this change:

| Gate | Where | Effect when synthetic |
|---|---|---|
| Keyless at-rest encryption | `__main__.py` `_serve` | started with no key; bodies, MRN, patient name plaintext |
| Unrestricted-egress refusal | `__main__.py` `_serve` | started with every destination open |
| Egress deny-by-default auto-flip | `__main__.py` `_serve` | stayed allow-any per transport |
| `--allow-insecure-bind` clamp | `__main__.py` `_serve` | the escape was honored again |
| Proxy attestation (intra-service auth + TLS floor) | `__main__.py` `_serve` | no attestation required |
| Proxy mTLS declared-but-unverified | `tls_policy.proxy_mtls_declared_but_unverified` | silent |
| Admin new-IP step-up advisory | `__main__.py` `_serve` | silent |
| MFA-at-exposure refusal | `__main__.py` `_serve` | single-factor admin over the network |
| Undeclared-proxy MFA warning | `__main__.py` `_serve` | silent |
| Dual-control at exposure | `__main__.py` `_serve` | silent |
| Terminator without a public origin | `__main__.py` `_serve` | started |
| ASVS 12.1.1 TLS-floor probe | `__main__.py` `_serve` | never ran |
| PHI retention bound | `__main__.py` `_serve` | no refusal, no 30-day auto-bound |
| Security-notification channel | `__main__.py` `_serve` | started with no push channel |
| Unauthenticated alert SMTP hop | `__main__.py` `_serve` | cleartext SMTP accepted |
| Memory-encryption declaration at exposure | `__main__.py` `_serve` | silent |
| Deliverable admin notice address | `api/app.py` lifespan | refusal suppressed |
| API PHI-read over an unproven serve hop | `tls_policy.api_phi_hop_disposition` | ALLOW |
| Outbound TLS hop with no revocation check | `tls_policy.revocation_hop_disposition` | ALLOW |

Eight of those are hard refusals a stock instance takes under the shipped `enforcement = enforce`.

**Three facts made this the right time.**

**1. The lever was not the loud, audited opt-out the documentation claimed.**
`docs/SECURITY-LOOSENING.md` said it was *"named by `security_loosenings()`, surfaced in
`GET /security/posture`, and warned at `serve`"*. Measured: `security_loosenings()` spans 364 lines
and contained zero occurrences of `handles_real_patient_data`, `data_class`, `DataClass` or
`synthetic`. The serve-time loosening warning reads that same registry, so **it never fired for the
widest relaxation the product shipped**. The posture view carried it, but as a separate
`synthetic_relaxation` string that the web console rendered in the `muted` class — one line above the
`banner` class real loosenings get.

`tests/test_security_posture_defaults.py` exempted the field with the reason *"the data-class lever
has its own entry keyed on the derived posture"*. There was no such entry. The exemption was also
unreachable: the completeness loop skips any field whose default is not a `bool`, and this one
defaults to `None`. Two lines of dead code carrying a false statement about a security control — the
compensating-control-on-a-false-premise defect **SDS-3.7** names, sitting in the test that exists to
prevent it.

**2. Half the removal had already happened, twice, for reasons that generalize.**
ADR 0153 removed `is_phi` from `insecure_hop_disposition` because *"`data_class` is authored in the
same file as the hosts it governs and a typo in it is indistinguishable from a declaration, with
every transport hop in the product as its blast radius."* That argument was never specific to
cleartext hops. ADR 0148 GIVEN 1 then made all three built-in environment names derive PHI, leaving
the label with exactly one job: being an opt-out.

**3. The stated benefit was already available per-gate.** Every one of the nineteen has its own
switch — `allow_unencrypted_phi`, `block_unlisted_outbound`, `allow_keeping_phi_indefinitely`,
`allow_single_factor_admin_when_exposed`, `allow_unverified_alert_smtp_tls`,
`[alerts].security_notifications_required`, a per-connection `cleartext_accepted` /
`tls_revocation_attested`, or the `[security].enforcement` dial. Each is separately named, separately
audited and separately reported. The lever added no capability; it added a way to reach all nineteen
without naming any of them.

Per CLAUDE.md §0 there are zero deployments, so removal costs no migration.

## Decision

**1. `[security].handles_real_patient_data` and `[ai].data_class` are removed, and the `DataClass`
enum with them.** Every instance carries patient data. The PHI gates apply unconditionally.

**2. Both spellings are REFUSED at load, not ignored.** `_REMOVED_KEYS` in `config/settings.py`
raises with a message naming the per-gate switches. Refusing matters more for a removed posture
switch than for a misspelled one: ignoring it would start the engine with all nineteen gates ON,
which is the safe direction but a silent contradiction of what the operator's config says — and the
next person to read that file would draw the wrong conclusion about the running instance.

**3. `HopPosture` loses `is_phi`.** ADR 0153 had already removed it from the widest consumer; the
remaining three (`api_phi_hop_disposition`, `revocation_hop_disposition`,
`proxy_mtls_declared_but_unverified`) lose it here, as do `weakened_tls_escape_permitted` and the two
`wiring_runner` bind predicates. A field that cannot vary is a constant, not a posture dimension.

**4. Two ADR 0153 scope carve-outs are resolved by subtraction rather than decision.**
`api_phi_hop_disposition` and `forward_hop_disposition` each *restated* the `not is_phi` ALLOW arm
locally, because neither cell is a connection and so neither can carry a per-hop
`cleartext_accepted`. That reasoning stands and is preserved in both docstrings. What it bought was
an arm with no instance left to fire on. **The follow-up 0153 recorded — a `[security]`-level
declaration for these two cells — becomes load-bearing rather than optional:** under `enforce`, an
unproven API serve hop and an unattested plaintext log-forwarding hop now have no per-cell way to say
yes. Filed, not built here.

**5. The production tier is retained, untouched.** It is a true property of an instance and it drives
the AI data-scope ceiling and the DEBUG-log refusal, neither of which is a PHI gate.
`derived_posture()` and `require_posture()` now return the tier alone. A custom environment name must
still declare it or `serve` fails closed (ADR 0017).

**6. The wire contract drops `data_class` and `synthetic_relaxation`** from `SecurityPosture`, and
`data_class` from `AiPolicy`. Nothing is deployed, so there is no compatibility shim: a relaxed
control is a named entry in `loosenings`, or it is not reported at all.

## What this costs, stated plainly

**CI's SQL Server load leg and the failover load harness both used the declaration to start.** Each
now names the gate it needs instead:

- **CI (`sqlserver` load leg):** `enforcement: warn`. Its store container's certificate is
  self-signed, and `weakened_tls_escape_permitted` clamps `MEFOR_ALLOW_INSECURE_TLS` inert while
  enforcing. GitHub starts a `services:` container before any step runs, so a cert generated in a
  step cannot be mounted into it, and the store hop carries no per-hop attestation. Restoring
  `enforce` needs the job moved onto a `docker run` with a real generated cert — worth doing
  deliberately, and unchanged as a residual by this ADR.
- **Failover harness node:** `[security].enforcement = warn`,
  `[security].allow_unencrypted_phi = true`, `[security].block_unlisted_outbound = false`. The middle one keeps the benchmark measuring the write path it
  has always measured; adding encryption there would change the number, not the risk.

**Both replacements are narrower than what they replace.** The retired declaration silenced nineteen
gates; `enforcement = warn` downgrades them to warnings and silences none.

**A stock `serve --env dev` with no store key now refuses.** It refused before this change too, for
any instance that had not opted out — ADR 0148 GIVEN 1 made that the default. What changes is that
the opt-out is gone, so the refusal is no longer escapable in one line. The per-gate path is
`[security].allow_unencrypted_phi = true`, plus
`[security].allow_unencrypted_phi_under_strict_enforcement = true` under the shipped `enforce`
(ADR 0140 — keyless PHI under strict enforcement is never one flag away).

## Honest residuals

- **The two non-connection cells named in decision 4 have no acceptance mechanism.** Under `enforce`
  they refuse or they do not; there is no way to declare an accepted risk on either. This is a real
  gap and it is filed, unallocated — the `[security]`-level declaration ADR 0153 recorded as a
  follow-up for the API serve hop, and its `[logging]` sibling for the forwarder.
- **No instrument stops the same shape recurring.** Nothing in the repository would have reported
  that `security_loosenings()` did not name its own widest switch; the test that existed to catch it
  was structurally incapable of firing. This ADR removes the instance, not the class.

## Explicitly out of scope

`AiDataScope` — the AI-assist context axis, whose `synthetic` member is a different concept and
stays. `[security].enforcement` (ADR 0148 GIVEN 2). The production tier. Every per-gate switch. Every
per-connection declaration. `[store].require_encryption`, which still forces a key past
`allow_unencrypted_phi`.
