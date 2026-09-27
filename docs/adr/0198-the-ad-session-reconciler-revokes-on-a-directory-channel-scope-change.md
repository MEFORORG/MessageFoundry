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
   [`auth/channel_scope.py`](../../messagefoundry/auth/channel_scope.py) takes the account's stored
   scope, who wrote it, the channels its groups map to, and whether its roles include Administrator.
   It returns what login would write and whether that write removes access.
   `_sync_ad_channel_scope` (login) and `plan_pass` (the reconciler) both call it. The same module's
   `scope_channels` parses the stored value for both the decision and every request's scope. A second copy of the rule is how the #1532 loop would
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
   revocation, reason `roles_changed`, which persists the new roles as before. So the breaker
   counts one per principal. Either way the audit row carries `scope_changed: true` with
   `scope_from` (the stored scope) and `scope_to` (the directory's, null for a withdrawal). The
   reconciler writes no scope, so that row is the only record of what the directory took away until
   the next login writes it.
4. **Planned inside `plan_pass`, dropped on abort.** Scope revocations are ordinary entries in
   `ReconcilePlan.revocations`. A breaker trip drops them with every other write, so ADR 0079's
   byte-identical abort still holds. Since the reconciler writes no scope, a scope revocation writes
   only the session rows and the audit row.
5. **Built on ADR 0195.** Step 3 of the ruling asks for sequencing with ADR 0195. That ADR is built and
   merged (engine PR 1661). Scope revocations come only from PRESENT probes, which ADR 0195 never
   holds, and the breaker still judges `ReconcilePlan.judged`.
6. **The scope is read after the probes, and checked again at apply time.** The pass re-reads
   each PRESENT principal's row after probing, as it already did for roles. A login that lands
   during the probes has already written the new scope. Judging the row listed at the start would
   revoke the session that login just minted. The apply step reads the row once more and skips a
   scope revocation whose stored scope has moved. The returned plan then omits it, so it is not
   alerted. A role revocation is never skipped this way.
7. **No out-of-band notice.** A scope revocation sends no `account_disabled` notice, since the account
   is not disabled. Login's own scope re-sync sends no notice either. The audit row and the
   `ad_session_revoked` alert carry the event.

## The hazard the ruling names

If the bind account loses read on `memberOf`, `_resolve_groups` returns an empty group set on a
PRESENT probe, for every principal at once. Before this ADR, a site that mapped scope but not roles
would have seen nothing. Now every principal with a directory scope plans a `scope_changed`
revocation on the same pass.

**The mass-revoke breaker is the brake**, as the ruling says, and it is a partial one. It aborts a
pass only when the planned revocations exceed **both** its floor (five by default) **and** its
fraction (0.34 by default) of the probes it judged.

So it stops the wave only where directory scopes are common among the signed-in principals. Take 9
of 30 principals with a directory scope and the rest with an administrator's scope. The pass applies
all 9. At or below the floor it applies them too. That is the same AND that ADR 0079 accepted for a
mass absence.

Those users' next logins would read the same empty groups and withdraw the scope anyway. So the
revocation brings forward what login would do. It does nothing login would not. ADR 0195's hold does not
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
- **AC-7** -- IF every PRESENT probe returns empty groups and the scope revocations exceed both the
  breaker's floor and its fraction, THEN THE SYSTEM SHALL abort the pass rather than revoke. Below
  either threshold it applies them, and a test pins that too, so no document can claim more.
  → `tests/test_ad_session_reconcile.py::test_a_lost_memberof_read_trips_the_breaker_rather_than_revoking_everyone`
  → `tests/test_ad_session_reconcile.py::test_a_lost_memberof_read_below_the_breakers_fraction_still_revokes`
- **AC-8** -- WHEN the next login has written the new scope, THE SYSTEM SHALL NOT revoke that principal
  again on a later pass. → `tests/test_ad_session_reconcile.py::test_after_the_next_login_writes_the_new_scope_the_pass_does_not_revoke_again`
- **AC-9** -- THE SYSTEM SHALL decide login's write and the reconciler's revocation with one function.
  → `tests/test_ad_session_reconcile.py::test_login_and_the_planner_share_one_scope_decision`
  → `tests/test_ad_session_reconcile.py::test_login_writes_exactly_what_the_shared_decision_says`
- **AC-10** -- WHEN the pass revokes for a scope delta, THE SYSTEM SHALL audit the stored scope and the
  directory's. → `tests/test_ad_session_reconcile.py::test_a_scope_revocation_audits_what_the_directory_took_away`

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
on a map change made in the directory. A `memberOf` read loss is revoked outright wherever it stays
under either breaker threshold (see *The hazard the ruling names*). A widened scope still waits for
the next login. Each PRESENT principal costs two more store reads per pass, its row and its mapped
channels.

A legitimate directory reorganisation can now trip the breaker. Say an AD administrator moves 20 of
40 signed-in users to a group with fewer channels. Every pass plans 20 scope revocations and aborts.
The reconciler writes no scope, so nothing settles until those users sign in again or their sessions
expire. Until then, every aborted pass also withholds any genuine disable in the estate. A mass role
change has always had this property. Scope is a new way to reach it.

A matching group replaces an administrator's scope (BACKLOG #1927). So a directory group ADD can
narrow a user whose manual scope the group does not cover, and the pass revokes that user.

**Out of scope** -- A service-certificate identity mapped to an AD account holds no session, so no
pass reaches it. Probing the directory at dual-control release is not built.

## To resolve on acceptance

- [ ] The owner accepts the reading of "would change -- withdrawn OR narrowed" in Decision item 2: a
  pure widening does not revoke. If the owner wants any change to revoke, the planner reads
  `ScopeDecision.changes` instead of `ScopeDecision.narrows`, and a widening then counts against the
  breaker.
- [ ] Step 5 of the ruling, recording it on BACKLOG #1154, is ledger work for the Lander.
