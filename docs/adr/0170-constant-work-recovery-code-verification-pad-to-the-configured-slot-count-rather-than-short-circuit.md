<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0170 — Constant-work recovery-code verification: pad to the configured slot count rather than short-circuit

- **Status:** Accepted (2026-08-22) — built with the change; see §"Consequences"
- **Date:** 2026-08-22
- **Related:** [BACKLOG #1167](../BACKLOG.md) (ASVS 11.2.4) · [auth/service.py](../../messagefoundry/auth/service.py) `_verify_second_factor` · [ADR 0077](0077-action-bound-step-up.md) (the neighbouring step-up work) · [CLAUDE.md](../../CLAUDE.md) §9 (PHI/security guardrails), §0 (not-deployed beta)

---

## Context

`AuthService._verify_second_factor` walked the user's argon2id recovery-code hashes and `return`ed
on the first match. ASVS **11.2.4** asks that cryptographic operations be constant-time "with no
short-circuit operations in comparisons, calculations, or returns".

**Two leaks, and only one of them matters.**

| what varied | who can measure it | worth |
|---|---|---|
| the matched code's **index** | someone who already holds a working code | ~nothing — they hold the secret and get the answer in the response |
| the **remaining code count**, on the FAILURE path | anyone holding the password but not a code | **real** — a failed attempt costs one argon2 verify per *remaining* code |

The second is the finding. An attacker who has the password can submit a wrong recovery code and
time the refusal, learning how many recovery codes the account has left. That is a fact about the
account's secret material, taken without authenticating.

### The item rated this difficulty 7, and the rating rested on a premise that is false

BACKLOG #1167's re-score says the obvious constant-time loop "multiplies a 64 MiB argon2id
verification by the slot count on every attempt, converting a timing leak into a memory and CPU
amplification target". **That is the right objection to raise and it does not survive measurement.**

**The failure path already verifies every remaining hash.** A non-matching code walks the whole list
today. So making the walk unconditional does not introduce a new cost — it makes **today's worst
case** the only case.

## Decision

**Always perform exactly `mfa_recovery_code_count` argon2 verifications**, padding the live hashes
with the same fixed dummy hash the local login leg already uses (`_DUMMY_PASSWORD_HASH`), and select
the winner *after* the loop instead of returning inside it.

Concretely `slots = max(mfa_recovery_code_count, len(real))` — the `max` covers the degenerate case
where an operator lowers the setting after codes are minted, and in that case the cost is
`len(real)`, which is exactly what ships today.

### Why this is not an amplification trade

- **The ceiling does not move.** `mfa_recovery_code_count` defaults to **10** and its validator caps
  it at **50**. A failed attempt already costs up to that many verifies.
- **The concurrency footprint does not move either.** `_argon2` holds `_argon2_sem`, a semaphore
  bounded by `_ARGON2_MAX_CONCURRENCY`, so this cannot widen the number of argon2 hashes in flight.
  It can only change how long one attempt holds a slot — and the failure path, which is the
  adversary's path, already held it that long.
- **This path is behind a password.** The second factor is only reached after primary
  authentication, so it is not an unauthenticated flood surface.

## What this explicitly does NOT claim

**Constant WORK, not constant TIME.** The argon2 verifies dominate by orders of magnitude and are
what is equalized. Not equalized, and not claimed to be:

- the store round trip on a match (`consume_recovery_code_hash`) — a success does one more thing
  than a failure, and the response already reveals which happened;
- the TOTP branch above, which returns before recovery codes are read at all;
- anything about the underlying argon2 implementation, whose constant-timeness is **inherited from
  `argon2-cffi` and has never been measured in this tree** — a gap #1167 names and this does not close.

**No timing measurement has been run**, by the item or by this change. The claim is about the code
path and the verification count, both of which are asserted by test.

## Alternatives rejected

**Leave the short-circuit and record the leak as accepted.** Rejected: the remaining-count leak is
measurable by an attacker who has not authenticated to the second factor, and the fix turned out to
cost nothing against the existing ceiling. "Accepted" would have been a judgement made before the
amplification premise was checked.

**Look the code up by a non-secret index so only one verify ever runs.** Strictly better on both
axes — one verify, no leak. Rejected here as **out of scope, not wrong**: it needs a schema change
across three backends and a migration for existing codes, where #1167's build is contained in one
module. Recorded so it is not re-derived: this is the design to reach for if the argon2 cost of a
constant walk ever becomes a real problem.

## Consequences

- A recovery-code attempt now costs a fixed number of argon2id verifications instead of a variable
  one. On the shipped default that is 10 where a *successful* attempt previously averaged about
  half that. **Successes get slower; failures do not.**
- Three parametrized tests pin the count at the configured slot count for a first-slot match, a
  last-slot match and a non-match. Proven red-first: removing the padding reds **all three** with the
  diagnostic naming the short-circuit, and the file restores byte-identical by SHA-256.
- **Severity is conditional per CLAUDE.md §0** — zero deployments, so this is what a first
  deployment would have inherited, not a live exposure.
