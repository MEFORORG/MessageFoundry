# 0198 — The AD session reconciler revokes on a directory channel-scope change

- **Status:** Proposed -- for the owner to accept. The owner ruled the direction on 2026-09-26 (quoted
  under *Basis*), so this ADR records a ruling rather than asking for one. Accepting it is the owner's
  act. The build rides the same branch because the ruling said to build.
  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-09-27
- **Supersedes:** one sentence of [ADR 0079](0079-kerberos-idp-session-coordination.md), in its
  2026-07-22 amendment under *Decision additions*: "**Channel scope is deliberately NOT re-diffed**".
  The rest of ADR 0079 stands.
- **Related:** [ADR 0079](0079-kerberos-idp-session-coordination.md) (mechanism 2, the reconciler and
  its mass-revoke breaker) · [ADR 0195](0195-brake-the-ad-session-reconciler-on-an-undetermined-useraccountcontrol-wave.md)
  (the undetermined-wave hold, which also edits `plan_pass`) · [CLAUDE.md](../../CLAUDE.md) section 0
  (not deployed) · BACKLOG #1957 (this item) · BACKLOG #1927 (login withdraws an unvouched scope) ·
  BACKLOG #1532 (the revoke-every-pass loop) · BACKLOG #1154 (the propagation-lag item)

---

## Basis

The owner's ruling, verbatim, as recorded in the owner's runbook workbook on 2026-09-26:

> OWNER RULED 2026-09-26, after adversarial review: YES, by REVOKE ON CHANGE. The AD reconciler ends a
> user's sessions (new revocation reason, e.g. scope_changed) when the directory-derived scope would
> change -- withdrawn OR narrowed -- and the next login writes the new scope; the reconciler never
> writes channel_scope. Conditions: plan these revocations inside plan_pass, count them against the
> mass-revoke breaker with one count per principal (role and scope deltas together), drop them on
> abort (keeps ADR 0079's byte-identical-abort guarantee); planner and login share ONE pure
> scope-decision function, or the #1532 revoke-every-pass loop returns. Hazard to test: loss of read
> on memberOf makes _resolve_groups return empty groups on a PRESENT probe, estate-wide; the breaker
> is the brake. Steps: (1) a new ADR superseding ADR 0079's 'Channel scope is deliberately NOT
> re-diffed' -- the owner has ruled, so write it for acceptance; (2) build; (3) sequence with ADR 0195
> (#2039), which also edits plan_pass; (4) fix docs/SECURITY.md's stale 'No item yet tracks the
> reconciler's missing scope re-check'; (5) record the ruling on #1154.

## Context

The reconciler re-resolves each directory principal that holds a live session. On a PRESENT probe it
already re-diffs roles, for free, because the probe returns the group set. It did not re-diff channel
scope. ADR 0079 chose that when login never narrowed scope. BACKLOG #1927 changed login: a login whose
groups match no scope-mapped group now withdraws any scope an administrator did not set. So a user
dropped from their last scope-mapped group in the directory would keep the old scope in every live
session until the next login, up to the 12-hour absolute cap. On a first deployment that is a
withdrawn grant that keeps working.

## Decision

**The reconciler ends a principal's sessions when the directory would take scope away. It never
writes `channel_scope`; the next login does.**

1. **One pure decision, two callers.** `decide_ad_channel_scope` in
   [`auth/reconcile.py`](../../messagefoundry/auth/reconcile.py) takes the account's stored scope, who
   wrote it, the channels its groups map to, and whether its roles include Administrator. It returns
   what login would write and whether that write removes access. `_sync_ad_channel_scope` (login) and
   `plan_pass` (the reconciler) both call it. A second copy of the rule is how the #1532 loop would
   come back: the pass would revoke for a scope that login never writes, so every pass would revoke
   again.
2. **What "would change" means here.** The pass revokes when the decision **narrows** access: the
   scope is withdrawn, or the new channel set drops at least one channel the stored one reached,
   including all-channels to a list. It does **not** revoke when the scope only widens, or when only
   the provenance moves. A widening leaves a live token under-privileged, which is safe, and charging
   it to the breaker would let a benign map widening abort a pass that also carries a genuine
   offboarding. Login keeps its own wider trigger and revokes on any change. That cannot loop: any
   decision that narrows is also one that login writes.
3. **The revocation reason is `scope_changed`.** A principal whose roles also changed gets **one**
   revocation, reason `roles_changed`, which persists the new roles as before and records
   `scope_changed: true` in its audit row. So the breaker counts one per principal.
4. **Planned inside `plan_pass`, dropped on abort.** Scope revocations are ordinary entries in
   `ReconcilePlan.revocations`. A breaker trip drops them with every other write, so ADR 0079's
   byte-identical abort still holds. Since the reconciler writes no scope, a scope revocation writes
   only the session rows and the audit row.
5. **Built on ADR 0195.** Step 3 of the ruling asks for sequencing with ADR 0195. That ADR is built and
   merged (engine PR 1661). Scope revocations come only from PRESENT probes, which ADR 0195 never
   holds, and the breaker still judges `ReconcilePlan.judged`.
6. **No out-of-band notice.** A scope revocation sends no `account_disabled` notice, since the account
   is not disabled. Login's own scope re-sync sends no notice either. The audit row and the
   `ad_session_revoked` alert carry the event.

## The hazard the ruling names

If the bind account loses read on `memberOf`, `_resolve_groups` returns an empty group set on a
PRESENT probe, for every principal at once. Before this ADR, a site that mapped scope but not roles
would have seen nothing. Now every principal with a directory scope plans a `scope_changed`
revocation on the same pass. **The mass-revoke breaker is the brake**, as the ruling says: above its
floor the pass aborts and nothing is revoked or written. At or below the floor (five by default) those
sessions are revoked. That is the same floor ADR 0079 accepted for a mass absence, and those users'
next logins would read the same empty groups and withdraw the scope anyway. ADR 0195's hold does not
cover this: it keys on an unreadable `userAccountControl`, and a `memberOf` loss leaves that readable.

## Acceptance Criteria

- **AC-1** -- WHEN a PRESENT probe's groups no longer match any scope-mapped group and the stored scope
  is not an administrator's, THE SYSTEM SHALL revoke the principal's sessions with reason
  `scope_changed` and leave `channel_scope` unwritten.
  → `tests/test_ad_session_reconcile.py::test_a_withdrawn_directory_scope_revokes_on_the_next_pass`
- **AC-2** -- WHEN the mapped channel set drops a channel the stored scope reached, THE SYSTEM SHALL
  revoke with `scope_changed`.
  → `tests/test_ad_session_reconcile.py::test_a_narrowed_directory_scope_revokes`
- **AC-3** -- WHEN the mapped scope is unchanged or only wider, THE SYSTEM SHALL NOT revoke.
  → `tests/test_ad_session_reconcile.py::test_an_unchanged_or_wider_directory_scope_does_not_revoke`
- **AC-4** -- WHERE an administrator set the scope and no mapped group matches, THE SYSTEM SHALL NOT
  revoke. → `tests/test_ad_session_reconcile.py::test_a_manual_scope_with_no_mapped_group_survives`
- **AC-5** -- WHEN one principal has both a role delta and a scope delta, THE SYSTEM SHALL plan one
  revocation and count it once against the breaker.
  → `tests/test_ad_session_reconcile.py::test_a_role_and_scope_delta_count_once_against_the_breaker`
- **AC-6** -- IF the breaker aborts a pass, THEN THE SYSTEM SHALL drop its scope revocations and leave
  the store byte-identical.
  → `tests/test_ad_session_reconcile.py::test_an_aborted_pass_drops_scope_revocations_and_writes_nothing`
- **AC-7** -- IF every PRESENT probe returns empty groups above the breaker's floor, THEN THE SYSTEM
  SHALL abort the pass rather than revoke.
  → `tests/test_ad_session_reconcile.py::test_a_lost_memberof_read_trips_the_breaker_rather_than_revoking_everyone`
- **AC-8** -- WHEN the next login has written the new scope, THE SYSTEM SHALL NOT revoke that principal
  again on a later pass. → `tests/test_ad_session_reconcile.py::test_after_the_next_login_writes_the_new_scope_the_pass_does_not_revoke_again`
- **AC-9** -- THE SYSTEM SHALL decide login's write and the reconciler's revocation with one function.
  → `tests/test_ad_session_reconcile.py::test_login_and_the_planner_share_one_scope_decision`

## Options considered

1. **Revoke on change; login writes the scope.** The owner's ruling. **CHOSEN.**
2. **The reconciler writes the new scope itself.** Rejected by the ruling: the reconciler never writes
   `channel_scope`. It would also add a second scope writer that an abort must roll back.
3. **Leave scope to the next login (ADR 0079 as written).** Rejected: the withdrawn grant lasts up to
   the absolute cap.

## Consequences

**Positive** -- A scope the directory withdraws or narrows stops working within about one interval,
like a role change. The login rule and the reconciler rule cannot drift, because there is one.

**Negative / risks** -- A pass can now revoke on a scope delta, so the breaker sees more revocations
on a map change made in the directory. A `memberOf` read loss revokes up to the breaker's floor on a
small estate. A widened scope still waits for the next login.

**Out of scope** -- A service-certificate identity mapped to an AD account holds no session, so no
pass reaches it. Probing the directory at dual-control release is not built.

## To resolve on acceptance

- [ ] The owner accepts the reading of "would change -- withdrawn OR narrowed" in Decision item 2: a
  pure widening does not revoke. If the owner wants any change to revoke, the planner reads
  `ScopeDecision.changes` instead of `ScopeDecision.narrows`, and a widening then counts against the
  breaker.
- [ ] Step 5 of the ruling, recording it on BACKLOG #1154, is ledger work for the Lander.
