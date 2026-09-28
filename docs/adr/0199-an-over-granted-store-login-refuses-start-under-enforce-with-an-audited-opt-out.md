<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Foundation, LLC and contributors -->

# 0199 — An over-granted store login refuses start under enforce, with an audited opt-out

- **Status:** Accepted (2026-09-27) -- by an owner ruling given to a Manager seat through
  AskUserQuestion, after an adversarial review returned the question UNDECIDABLE on the record. Built
  with the change.
- **Date:** 2026-09-27
- **Related:** BACKLOG #305 (the Gate this closes), #1008 (the preflight, and its 2026-09-14 closure
  this narrows), ASVS 13.2.2 ·
  [ADR 0148](0148-phi-default-posture-and-an-explicit-security-enforcement-level.md) (the
  `[security].enforcement` dial) ·
  [ADR 0186](0186-retire-the-synthetic-data-declaration-every-instance-carries-patient-data.md)
  (every instance carries patient data) ·
  [ADR 0192](0192-server-db-schema-is-provisioned-externally-by-default-the-runtime-login-runs-no-ddl.md)
  (the runtime login runs no DDL, so `db_ddladmin` is excess under `external`) ·
  [ADR 0140](0140-two-acknowledged-production-phi-no-loosen-carve-outs-single-factor-admin-at-exposure-keyless-phi-in-production.md)
  (the acknowledged opt-out shape)

---

## Context

The startup preflight in `messagefoundry/store/privilege.py` reads the store login's effective
privileges at every start and compares them with the grant `docs/DEPLOY-SERVER-DB.md` prescribes.
Until this change it could refuse only when an operator set `[store].require_least_privilege = true`.
That setting defaults to `false`, so on the shipped defaults an over-granted login always started
with a warning.

The owner ratified that shape on 2026-09-14, when BACKLOG #1008 closed. The #1008 row's *Split the
arms* paragraph asked that the WARN arm ship on and the REFUSE arm sit behind an operator setting.
BACKLOG #305's Gate then asked for the opposite on the scored posture: an over-privileged store login
on an enforcing PHI instance should refuse start, with an audited opt-out. An adversarial review
found the two records could not be reconciled from what they say, so the question went to the owner.

**The owner ruled on 2026-09-27, in these terms:**

1. Under `[security].enforcement = enforce`, a store login the preflight finds OVER-GRANTED refuses
   engine start by default.
2. An audited opt-out lets an operator accept the over-grant. It writes an audit row and is visible
   at startup, in the shape of the engine's other audited opt-outs.
3. An UNOBSERVABLE probe, one that cannot read the login's rights, still only warns. It does not
   refuse by default. An operator who sets `[store].require_least_privilege = true` keeps today's
   stricter behaviour, which refuses on an unobservable probe too.
4. Non-PHI instances and enforcement modes other than `enforce` are unchanged: they warn, unless
   `require_least_privilege` is set. The gate uses the same PHI-instance predicate as the other ADR
   0148 serve gates.
5. SQLite is not applicable and is unchanged.

**What point 4 resolves to in the code.** ADR 0186 retired the data class, so there is no non-PHI
instance and no `is_phi` predicate left. The other ADR 0148 serve gates key on
`[security].enforcement is ENFORCE` alone. This gate does the same. So the "non-PHI" arm of the ruling
is empty by construction, and `enforcement = warn` is the only way to reach the warn-only path.

## Decision

`preflight_outcome` in `store/privilege.py` states the decision once. The serve lifespan and
`messagefoundry check-privileges` both call it, so they cannot disagree.

| Finding | `enforcement` | `require_least_privilege` | `allow_over_granted_store_principal` | Outcome |
|---|---|---|---|---|
| none (clean, or SQLite) | any | any | any | start |
| over-granted | `warn` | any | any | warn and start |
| unobservable | `warn` | any | any | warn and start |
| over-granted | `enforce` | `false` | `false` | **refuse** (new) |
| over-granted | `enforce` | `false` | `true` | start, audited (new) |
| over-granted | `enforce` | `true` | any | refuse |
| unobservable | `enforce` | `false` | any | warn and start (owner choice) |
| unobservable | `enforce` | `true` | any | refuse |

**The opt-out is `[security].allow_over_granted_store_principal`.** It follows
`allow_unverified_alert_smtp_tls`: a `[security]` acknowledgment switch, default `false`, read
directly by the serve lifespan and never desugared. When it lets an over-granted login start:

- the preflight logs a WARNING line that starts `AUDIT:` and names the switch;
- the preflight's existing `store_privilege_preflight` audit row carries `over_grant_accepted: true`
  beside `refused: false`, so the durable record says a refusal was lifted, not that none applied;
- `security_loosenings()` names it, so `GET /security/posture` shows it, and the observed
  `store_principal_over_granted` entry still appears beside it.

It lifts this one refusal and nothing else. It does not quiet the warning or the
`store_privilege_warning` alert, and it never lifts an unobservable refusal.

**`require_least_privilege` outranks the opt-out.** It is the stricter declaration, so with both set
an over-grant refuses. This is the precedence `[store].require_encryption` has over
`allow_unencrypted_phi`.

**`check-privileges` prints what serve would do.** A last `serve:` line (the `serve` key under
`--json`) states the outcome for the observation it just made under the loaded settings. Its exit
codes are unchanged: an over-grant exits 3 even when the opt-out would let serve start, because the
grant is still wider than the runbook's.

## Consequences

- **A server-DB instance whose login holds more than the runbook grant no longer starts under the
  shipped defaults.** This is a breaking change. Its cost is currently zero, because MessageFoundry
  is a not-deployed beta with no running instance. The fix is to reduce the grant, or to set the
  opt-out, or `enforcement = warn`.
- **It is an exception to the scoping rule "a new refusal fires only on a new opt-in"**
  (`docs/CONFIGURATION.md`, on `require_memory_encryption_declaration`). At least one other is
  recorded: the `allow_single_factor_admin_when_exposed` refusal, by the ADR 0140 amendment. This one
  rests on the 2026-09-27 ruling. Neither generalises.
- **It narrows the 2026-09-14 ratification of #1008** for the over-grant arm only. The WARN arm
  still ships on, and the unobservable arm keeps the gating that ratification described.
- **Places that log in as a superuser now need the opt-out or `warn`.** The local `ha` profile in
  `docker/compose.yaml` logs in as the Postgres image's `POSTGRES_USER`, which is a superuser, so it
  sets the opt-out with a DEV-ONLY comment. The CI serve legs against SQL Server and Postgres, the
  benchmark legs and the load harness already run under `enforcement = warn`, so they are unchanged.
- **The PHI predicate the ruling named does not exist, and the ADR says so** rather than inventing
  one. If a data class ever returns, this gate must be revisited with the rest of the ADR 0148 family.

## Alternatives considered

- **Refuse on an unobservable probe by default too.** Rejected by the owner. A probe can fail for
  reasons the operator cannot fix at start, such as a permission a DBA has not yet granted to read
  role membership, and the warning already says the result is not clean.
- **Flip `require_least_privilege` to default `true`.** Rejected: that would also refuse on an
  unobservable probe, which point 3 of the ruling rules out, and it would leave no audited way to
  accept a known over-grant short of `enforcement = warn`, which relaxes every other gate too.
- **Put the opt-out under `[store]`.** Rejected: ADR 0118 makes `[security]` the home of posture
  switches, and the completeness floor in `tests/test_security_posture_defaults.py` then forces the
  loosening entry to exist.
