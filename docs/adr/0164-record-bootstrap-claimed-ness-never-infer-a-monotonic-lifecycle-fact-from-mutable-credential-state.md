<!-- SPDX-License-Identifier: AGPL-3.0-or-later -->
<!-- Copyright (C) 2026 MessageFoundry Organization and contributors -->

# ADR 0164 — Record bootstrap claimed-ness; never infer a monotonic lifecycle fact from mutable credential state

- **Status:** Proposed (2026-08-13)
- **Date:** 2026-08-13
- **Related:** [BACKLOG #1245](../BACKLOG.md) · [SECURITY.md](../SECURITY.md) §"Auto-retirement (WP-3)" · [ADR 0158](0158-silent-controls-green-signals-that-mean-nothing-and-shape-over-detection.md) (a control that cannot observe its own failure) · [ADR 0156](0156-asvs-scorecard-as-data-a-derived-count-verified-evidence-anchors-and-a-fail-closed-drift-gate.md) (a claim maintained as prose is a claim nothing checks) · [CLAUDE.md](../../CLAUDE.md) §0 (not deployed), §9 (PHI), §11 (SDS-3.5, SDS-3.7)

---

## Context

### The mechanism, measured at `96c9a860`

Bootstrap auto-retirement (WP-3) disables the first-run `admin` account once it has been superseded
by a real administrator or once its time window lapses. It is gated on a single boolean:

```
auth/service.py:584   if boot is None or boot.disabled or not boot.must_change_password:
auth/service.py:585       return  # gone, already disabled, or claimed (a real account now)
```

`must_change_password` is being read as **"this account was never claimed."** That reading is sound
only while the flag has one writer. It has five, and one of them runs long after a claim:

```
auth/service.py:2733   must_change_password=True,      # admin_reset_password
```

So an administrator resetting the password of the account named `admin` makes it look **unclaimed
again**, and the next trigger disables it. The triggers need no further operator action: the victim's
own next login (`service.py:651`, which fires *before* the row is fetched at `:652` and before the
credential is verified at `:669`), an engine restart through `initialize()` (`service.py:518`), or any
call to `create_local_user` (`service.py:2551`).

### Why no amount of care fixes this in place

**"Never claimed" is monotonic — once claimed, always claimed. `must_change_password` is not:**
self-service rotation clears it (`service.py:1911`), an administrative reset re-raises it
(`:2733`). **No non-monotonic bit can encode a monotonic predicate across a re-set.** The defect is
therefore structural, not a missing guard, and it is on the **reader**, not the writer — all five
writers assert the same true proposition ("the credential now on this account is issuer-issued, not
holder-chosen"). Only the retirement gate over-reads that into a lifecycle claim.

The same file already contains a **second reader of the same flag that gets it right**, because it
pairs the flag with a timestamp the reset refreshes (`service.py:697-700` against
`password_changed_at`, which `store.py:7725` updates). The retirement reader instead pairs it with
`created_at`, which no reset touches — a fresh flag held against a stale clock.

### The failure was already written down, in prose, twice

The defeated property is asserted in the docstring at `service.py:579-581` and in shipped operator
documentation at `SECURITY.md:58-59` and `:1164`. **Prose is exactly what failed**, and that is the
argument for an ADR rather than a comment: bootstrap retirement has no ADR today and lives only in
`SECURITY.md`, which is how the guarantee drifted from the code with nothing reporting it.

### Consequences a first deployment would hit

Written in the conditional throughout — there are **zero deployments** (CLAUDE.md §0), so nothing is
broken today.

- The reset destroys the account it was performed to recover. Neither party is told: the
  administrator sees success and hands over a temporary credential; the holder sees a deliberately
  generic refusal (`service.py:653-663`); the only trace is one audit row (`service.py:594`) that
  nobody would look for behind what presents as a typo.
- The obvious repair fails the same silent way. `create_local_user` mints with
  `must_change_password=True` (`:2544`) and then retires unconditionally (`:2551`), so
  delete-and-recreate under the same name yields a **second** silently-dead account.
- Re-enabling does not break the loop: `set_user_disabled` leaves the flag set, so the next login as
  `admin` re-enters `:651` and re-disables.

**This is not a whole-system lockout, and the item does not claim one.** `USERS_MANAGE` cannot be
minted into a custom role (`permissions.py`, `CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`) and self-reset is
refused (`auth_routes.py:762`), so the resetter is necessarily a second enabled administrator and
administrative access is never lost.

---

## Decision

**Record claimed-ness as a fact. Stop inferring it.**

1. **New column `users.password_claimed_at`** — nullable epoch seconds, all three backends. It records
   exactly one thing: *the holder set their own credential via authenticated self-service rotation.*
   It does **not** record "the holder is still in control", and that narrowness is deliberate.

2. **One writer, and the honest account of what enforces it.** A claim is recorded only by a
   `set_password` call whose `must_change_password` argument is `False`. The bootstrap mint,
   `create_local_user` and `admin_reset_password` all pass `True` and therefore cannot claim.

   **A draft of this section claimed the constraint was "structural, not conventional" and that "you
   cannot record a claim without being the authenticated holder". Both were false, and the review
   that caught it measured them.** The store surface declared the **claiming** value as its default
   (`must_change_password: bool = False`), so a caller that merely *omitted* the keyword recorded a
   claim — demonstrated against a live store — and `scripts/security/dast_target.py` is an existing
   caller passing `False` outside self-service rotation. Asserting a structural guarantee in the same
   paragraph that says a conventional one is not good enough is the compensating-control-on-a-false-
   premise defect (SDS-3.7) appearing inside the document written to prevent it. **The retraction is
   kept rather than deleted, because the deleted version is what a later reader would re-derive.**

   What is true now, in two parts:
   - **The accidental path is closed structurally.** `set_password`'s default is flipped to `True`
     across the protocol and all three backends, so **omission is the SAFE branch** and a forgotten
     keyword can no longer stamp a claim. Every existing caller passes the argument explicitly, so
     this changes no current behaviour — it bounds the next caller. (`create_user`'s default stays
     `False`: it never writes this column, and AD provisioning depends on it.)
   - **The deliberate path remains conventional, and is stated as such.** A caller can still pass
     `False`. **The invariant is not "one caller" but "every caller passing `False` has just
     authenticated the holder"**, and what enforces that is review, not the type system. A store
     method taking no `must_change_password` at all — one that claims by construction — would make
     it fully structural, and is the obvious next step if this ever needs strengthening.

3. **Monotonicity enforced in SQL**, not in Python: `password_claimed_at = COALESCE(password_claimed_at, ?)`
   when a claim occurs, and the column is absent from the `SET` list otherwise. No statement anywhere
   may assign `NULL` after creation.

4. **`admin_reset_password` stays byte-identical.** No bootstrap carve-out on the reset path. This is
   a constraint, not an omission: suppressing the flag there would mean an administrative reset of
   `admin` no longer forces rotation, breaking the ASVS 6.4.6 property that path exists to provide.
   **The fix that the defect's own wording most naturally suggests is the wrong one.**

5. **One named predicate, called from both gates.** `_retire_superseded_bootstrap` (`:584`) and
   `bootstrap_expiry_warning` (`:618`) carried the identical open-coded test. Two copies of one
   lifecycle question is how the warning path inherited the blind spot; the predicate carries the
   mechanism in its docstring, stated once (SDS-3.5).

6. **A one-time backfill, inside the column-creation guard.** An existing developer database holds
   claimed accounts whose new column would be `NULL`, and the new gate would read `NULL` as unclaimed
   and retire them — this defect, re-introduced by its own fix. The guard placement is load-bearing:
   hoisted out, the backfill becomes a permanent **second writer** of the field whose single-writer
   property is the entire point.

---

## Rejected alternatives

Both are re-proposable and both are wrong in non-obvious ways, so they are recorded with the
measurement that killed them.

### Derive claimed-ness from `last_login_at` — rejected, deletes a control

Genuinely unforgeable by the reset, which is why it is attractive. But it is written at
`service.py:716`, **after** the credential check and **before** the must-change flag is reported to
the caller. So a bootstrap that logs in once with the printed one-time password and never rotates
would become **permanently non-retirable** — silently deleting the ASVS 6.4.5 time-expiry arm for
precisely the case it exists to cover, a printed credential left lying around.

It cannot be repaired within its own inputs. The obvious patch — `last_login_at is not None and not
must_change_password` — re-breaks on the filed scenario, because after a reset the flag is `True`
again. **Both of its inputs are re-armed by the reset.** That is a structural dead end, and since it
was the best no-schema candidate, it is also the cleanest available proof that schema is required.

This is the shape ADR 0158 is about, and the worst version of it: a change that reads as hardening
while removing a control, in the direction nobody would notice.

### Derive it from `password_changed_at != created_at` — rejected, the reset refreshes it

`store.py:7725` updates `password_changed_at` on every `set_password`, including the reset. It is
also equal to `created_at` at mint by construction, so the relation is a latent signal that flips
`True` on the first administrative reset of a **never-claimed** bootstrap too — which would let a
re-issued unclaimed bootstrap escape the supersession arm.

---

## Consequences and residual risk

- **The username-as-identity proxy is untouched, and this fix must not pretend otherwise.**
  `service.py:583` fetches by literal username with `BOOTSTRAP_USERNAME = "admin"` (`:71`) — no marker
  column, no role check — so **any** local account named `admin` is subject to this logic. Recording
  claimed-ness narrows the blast radius (such an account survives once claimed) but does not remove
  the second, stacked proxy. Filed separately; not fixed here.
- **Both server backends' schema hashes move**, forcing one guarded DDL re-run on next open (ADR 0064,
  by design).
- **Backend coverage is asymmetric.** The SQL Server and Postgres legs are CI-only, so the new
  column's persistence is exercised on one backend of three unless a round-trip assertion is added to
  each server suite.
- **Two existing tests were rewritten, not deleted.** Both faked a claim with a direct store write
  rather than going through the service, which is exactly why the second writer was invisible to the
  suite. They pinned the proxy instead of the property; rewriting them is the correct outcome.

---

## The durable rule this records

**A monotonic lifecycle fact must be RECORDED, with exactly one structurally-constrained writer —
never INFERRED from mutable credential state.**

The test to apply at the next such gate: *if some other code path sets this field for its own valid
reason, does my reading of it become false?* If yes, the field is not the fact — it is a correlate,
and correlates decay silently. There is no error, no exception and no failing test at the moment the
inference stops holding; the only symptom is a control doing the opposite of what it documents.
