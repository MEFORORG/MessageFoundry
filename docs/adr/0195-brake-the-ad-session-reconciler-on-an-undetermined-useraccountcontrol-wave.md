# ADR 0195 — Brake the AD session reconciler on an undetermined userAccountControl wave

- **Status:** Proposed -- for the owner to accept. No code until Accepted.
  <!-- Proposed (no code yet) -> Accepted (build may start) -> Superseded by NNNN / Rejected -->
- **Date:** 2026-09-26
- **Related:** [ADR 0079](0079-kerberos-idp-session-coordination.md) (mechanism 2, the directory
  session reconciler, and its mass-revoke breaker) · [CLAUDE.md](../../CLAUDE.md) section 0 (not
  deployed) and section 11 (SDS-3.6, SDS-3.7) · BACKLOG #1639 (the fail-closed read this follows) ·
  BACKLOG #2039 (this item)

---

## Context

The Active Directory (AD) session reconciler would sign out a whole small estate if the bind account
lost read on one attribute. This ADR decides how to stop that without undoing BACKLOG #1639.

**What #1639 changed.** Engine PR 1538 made `_account_enabled` in
[`auth/ldap.py`](../../messagefoundry/auth/ldap.py) fail closed. It returns `True` only for a readable
integer `userAccountControl` with ACCOUNTDISABLE (0x2) clear. An absent, empty or non-numeric value
returns `False`, the same answer a disabled account gets. `_search_user` then returns `None`. Two
kinds of caller read that `None`:

- **Every AD sign-in and step-up path** refuses the account. That is the point of #1639, and this
  ADR keeps it.
- **The reconciler** (`_probe_principal` in
  [`auth/service.py`](../../messagefoundry/auth/service.py)) maps `None` to `ProbeOutcome.ABSENT`.
  So an unreadable attribute, a set disabled bit and a search that matched nothing all read the same.

**What the breaker does with that.** `plan_pass` in
[`auth/reconcile.py`](../../messagefoundry/auth/reconcile.py) aborts a pass with
`mass_revoke_breaker` only when the planned revocations exceed two limits at once. They are
`[auth].ad_session_revoke_max` (default 5) and `ad_session_revoke_max_fraction` (default 0.34) of
the principals probed.
`breaker_tripped` states the AND. It counts principals, one `SessionRevocation` per user, and not
sessions. ADR 0079 names the cost as an "Acknowledged floor": at 5 or fewer signed-in directory
principals, the breaker cannot tell a wave from real offboarding, and revokes.

**Why the floor bites harder now.** Before #1639, an unreadable attribute read PRESENT and revoked
nothing. Now a bind account that loses read on `userAccountControl` turns every signed-in principal
ABSENT at once. Traced against the code at `0bbe01d22`, with the defaults
(`ad_session_recheck_strikes` 2, `ad_session_recheck_max_users` 200):

| Signed-in AD principals | What today's code would do on a first deployment |
|---|---|
| 3 | Pass 1 strikes all three. Pass 2 revokes all three. No breaker alert. `test_below_the_breaker_floor_the_same_wave_revokes` pins this. |
| 12 | Pass 1 strikes. Passes 2 onward abort with `mass_revoke_breaker` and alert. `test_a_bind_account_that_cannot_read_the_attribute_trips_the_breaker` pins four passes. |
| 300 | The pass probes 200. Pass 2 plans 100 revocations of 200 probed and trips; pass 3 plans 200 and trips. |

**On a larger estate the breaker only delays the wave.** Nobody can sign back in, because every
sign-in path refuses the same attribute. The reconciler probes only users holding a live session
(`list_sessions` filters out revoked and expired rows). Strikes survive an aborted pass. So as
sessions expire, the signed-in count falls. Once 5 or fewer principals remain, the next pass revokes
them all. That pass is not aborted, so it also clears `_reconcile_alert` while the attribute is still
unreadable. The 12-user test stops at four passes and does not reach that point.

**The owner ruled on PR 1538 on 2026-09-26: "Merge as is, file the brake."** This is the brake.
Section 0 of CLAUDE.md applies: no instance runs this code, so every consequence above is what a
deploying site would see, not something happening now.

**Constraints the choice must keep.**

1. Sign-in keeps refusing every undetermined attribute. Nothing here touches that answer.
2. One account whose own attribute is unreadable, among accounts whose attribute reads fine, is
   still revoked at the strike threshold. That is #1639's reconciler half.
3. The probe must not report an undetermined attribute as `UNAVAILABLE`. `UNAVAILABLE` never
   revokes, and the comment in `_search_user` names that as "the same fail-open in a new place".
4. ADR 0079's all-or-nothing pass stays: an aborted pass leaves the store byte-identical.

## Options considered

Five options. Each is scored on the same cases. "Readable" means the probe read a usable
`userAccountControl`, whether the disabled bit was set or clear. The 300 column assumes the per-pass
budget of 200. The partial-wave column assumes an access-control change that hides the attribute on
one organizational unit (OU) holding 40 signed-in users, out of 200 probed.

1. **UNDETERMINED never revokes.** Add a probe outcome that strikes, never revokes, and raises an
   alert.
2. **Share threshold, no floor.** Add the outcome. Abort the whole pass when the undetermined share
   of the probed set exceeds a fraction F, at any estate size.
3. **Preflight canary.** Before each pass, read the attribute on one known account. Skip the pass and
   alert if that read fails.
4. **Accept and document.** Keep today's code. Correct the settings comment and ADR 0079.
5. **Count-and-control hold.** Add the outcome. Undetermined answers may revoke only when the
   reconciler knows of exactly one, beside at least one readable answer. Otherwise it holds every
   undetermined account, and reconciles the rest of the estate as today.

| Option | One unreadable account among readable ones | Whole-estate wave, 3 signed in | Whole-estate wave, 300 signed in | Partial wave, 40 of 200 | Operator signal | Failure mode |
|---|---|---|---|---|---|---|
| 1. Never revokes | **Not revoked.** Session runs to its absolute cap. Sign-in refused. | Nothing revoked; alert | Nothing revoked; alert | Nothing revoked; alert | Alert on any undetermined answer | Reopens #1639's reconciler half. Breaks constraint 2. |
| 2. Share threshold | Revoked when 1 of N is at or under F. **Held** on a pass small enough that 1 of N exceeds F. | Aborts every pass; nothing revoked; alert | Aborts every pass through attrition, including the last session; alert | Depends on F. At the breaker's own 0.34, 20% is under it and **40 are revoked**. An F under 0.20 catches it, but then holds a genuine single on any pass of 5 or fewer. | Aborted alert, new slug | A fraction with no evidence behind it, trading partial waves against small passes. Whole-pass abort freezes the estate's other revocations while it holds. |
| 3. Preflight canary | Revoked (canary reads fine) | Pass skipped; nothing revoked; alert | Pass skipped; nothing revoked; alert | Canary in a readable OU: **not caught, 40 revoked** | Skip alert | The canary reports its own permissions, which may differ from the users'. A moved or deleted canary skips every pass, turning the reconciler off estate-wide behind one alert. New config key and one more search per pass. |
| 4. Accept | Revoked at threshold | **All 3 revoked on pass 2.** No breaker alert; one revocation alert each | Breaker holds from pass 2 until 5 or fewer principals remain; then **all revoked and the alert clears** | 40 revoked (40 is not over 68, so the breaker passes it) | Breaker alert while it holds; revocation alerts; a once-per-shape log warning | Today's behaviour. The breaker delays the wave and does not stop it. |
| 5. Count-and-control hold | **Revoked at threshold** | All 3 held; nothing revoked; alert | All held through attrition, including the last session; alert | The 40 held; **the other 160 reconciled as today**; alert | A new held alert and audit row, naming the attribute and the bind account's read rights | See below. |

**Option 5's failure mode, stated in full.** It holds more than it strictly needs to.

- **Two genuinely unreadable accounts are held, where today's code revokes both.** One way to get
  there: two people are offboarded on the same day into an OU inside the search base where the bind
  account cannot read the attribute. Their sessions then run to the absolute cap instead of ending
  at the second pass. That is the gap ADR 0079 closed, reopened for those accounts only, and alerted
  while it lasts.
- **The same hold can be caused on purpose.** Someone able to change permissions on two signed-in
  accounts could deny the bind account read on the attribute, then have the accounts disabled. Both
  would keep their sessions to the cap, behind one alert. That actor already holds rights over those
  accounts in the directory. Whether that makes this acceptable is the owner's call.
- **A lone signed-in account with an unreadable attribute is held**, because nothing readable sits
  beside it in its pass. It starts striking once a pass also reads a readable account, and is revoked
  `ad_session_recheck_strikes` passes later.
- **The hysteresis holds a genuine single too.** While a hold is engaged, a new single unreadable
  account is held with the rest, until every held account has left the record.
- **Every hold is bounded.** Sign-in refuses an undetermined account, so it cannot mint a new
  session. It leaves the candidate set when its current sessions expire, at most
  `session_absolute_hours` (12 by default) after the condition starts.
- **What the bound does not cover.** The rule assumes an undetermined answer is a standing property
  of an account or of an access-control change. Suppose a directory can return the attribute on one
  read and omit it on the next for the same account. Then accounts that sign in fine could read
  undetermined in passes, and the reconciler would hold them often. The rest of the estate would
  still be reconciled. No test here can show what a real domain controller does;
  `tests/test_ad_user_account_control.py` says the same about its own doubles.

## Decision

**Proposed, the drafter's recommendation: option 5, holding only the undetermined accounts, with the
count taken across the probe rotation.** Confidence: **medium-high** on a distinct outcome plus a
rule with no floor. **Medium** on the count of one, and on holding only the undetermined accounts
rather than aborting the whole pass.

**Why option 5.** It is the only option that meets all four constraints and also catches the partial
wave.

- Option 1 breaks constraint 2.
- Option 3 measures a different object than the ones it acts on. A canary that goes missing switches
  the reconciler off.
- Option 2 handles a whole-estate wave. Catching a partial wave as well needs a fraction low enough
  to hold genuine singles on small passes, and no evidence picks that number.
- Option 4 is the defect #2039 filed.
- Option 5's count of one needs no tuning, because the case it protects is rare by construction. For
  one account's attribute to be unreadable while others read fine takes a per-object access
  difference. Two at once is more likely a misconfiguration than two coincidences, though the
  offboarding case above shows it is not certain.
- Two parts handle attrition. The last signed-in session in a whole-estate wave has nothing
  readable beside it, so it is held. The last of a partial wave is kept held by the hold's
  hysteresis (rule item 6).

**Why hold only the undetermined accounts, not abort the whole pass.** A whole-pass abort would
freeze every genuine disable and role demotion in the estate. It would last as long as two
unreadable accounts hold live sessions, which is up to 12 hours by default. Holding only those
accounts keeps that cost on them. It does cost more to build. A pass that is not aborted clears `_reconcile_alert`, so the hold needs
its own latch, audit row and alert type. The whole-pass abort is the listed alternative.

**Why the count spans the rotation, not one pass.** Above `ad_session_recheck_max_users`, each pass
probes a sample. Counted per pass, two unreadable accounts that land in different samples would each
look single. They would be struck and revoked, and the alert would flicker as samples changed.
Counting `u` from each candidate's most recent probe keeps the answer steady. When the estate fits
in one pass, the two counts are the same. The readable count `r` stays per pass, for the reason rule
item 5 gives. This argument holds at the default of two strikes; the limits below say what happens
at one.

**What would change the recommendation.**

- **Evidence that undetermined answers are transient per account on real directories.** The rule
  would then hold often. Raise the count, or weigh option 2.
- **Evidence that same-day offboarding into an unreadable OU is common practice.** The rule would
  then hold genuinely disabled accounts routinely. Prefer a count above one.
- **An owner preference for the smallest change in `plan_pass`.** Option 2 with a whole-pass abort
  reuses the existing abort path, at the cost of the partial wave.
- **An owner judgement that the deliberate hold above is not acceptable.** Then the count arm needs
  a limit in time, such as releasing a held account to normal striking after a set number of passes.

### What the rule is, precisely

1. **Two new probe outcomes.** `DISABLED`: the entry was found and the attribute read, with the
   disabled bit set. `UNDETERMINED`: the entry was found and the attribute was absent, empty or not
   an integer. `ABSENT` keeps every other `None`: a search that matched nothing, and an id-keyed
   probe whose stored `objectGUID` could not be parsed, so no search ran. `DISABLED` behaves exactly
   as `ABSENT` does today in `plan_pass`: it strikes and revokes at the threshold.
2. **The directory layer reports the reason without raising.** The reconciler needs to know why an
   account was refused. The probe must not learn it from an `LdapError` (constraint 3). Every other
   caller keeps its `None`. That includes at least `LdapAuthenticator.authenticate`, which `_reauth_ad`
   uses for the step-up re-bind, and the `resolve_principal` calls in `_authenticate_kerberos`,
   `authenticate_oidc`, `create_directory_account` and `_reauth_ad`. The exact seam is a build choice.
3. **A process-local record of each candidate's latest outcome.** The reconciler already keeps
   several such ledgers: strikes, last-probed times and a set of reported unkeyed bindings. This one
   is pruned to live candidates the same way, and a restart resets it. `prune_ledger` cannot hold an
   enum as it stands, since its type bound and its value-sorted cap expect numbers. So the build
   either widens that helper or carries the outcome in the strike ledger's value.
4. **What updates the record.** This pass's outcomes are written in BEFORE the hold is judged. A
   `PRESENT`, `DISABLED`, `ABSENT` or `UNDETERMINED` probe replaces the account's entry. An
   `UNAVAILABLE` probe leaves the prior entry in place, so a directory blip on one held account does
   not make another look single.
5. **The two counts.** `u` is the number of candidates whose record reads `UNDETERMINED`, taken
   across the rotation. `r` is the number of probes in THIS pass that read `PRESENT` or `DISABLED`.
   `r` is per pass on purpose. A readable answer from before the wave began is no evidence that the
   attribute is readable now.
6. **The hold, with hysteresis.** Judged in `plan_pass` after the all-`UNAVAILABLE` check and before
   the mass-revoke breaker. The hold engages when `u > 1`, or when `u == 1` and `r == 0`. Once
   engaged, it releases only when `u == 0`. Without that, attrition would defeat it: as a partial
   wave's sessions expire, the last held account would read as a single and be revoked. The rule
   applies at any estate size, with no floor.
7. **While held.** Every `UNDETERMINED` probe plans no revocation, and its strike count is reset to
   0. So an account still unreadable after a fix needs `ad_session_recheck_strikes` fresh passes
   before it is revoked. That covers an access change that is still replicating. The existing breaker
   keeps strikes on abort to stop its alert flickering. That reason does not apply here, because the
   hold does not read strikes. Every other probe plans as today. The mass-revoke breaker then judges
   what remains, with held probes left out of its probed count.
8. **When not held**, a single `UNDETERMINED` probe strikes and revokes exactly as `ABSENT` does, and
   counts against the mass-revoke breaker's budget.
9. **Operator signal.** Every pass that holds writes its own audit row and raises its own alert type.
   That includes a pass the mass-revoke breaker also aborts. The new type gets its own notification
   throttle key, separate from `ad_reconcile_aborted`'s. Neither the row nor the alert carries the
   breaker's revocation ceiling, which means nothing for a hold. The hold latches its own message,
   naming `userAccountControl` and the `ad_bind_dn` account's read rights. It clears when the hold
   releases. A pass with no candidates clears nothing, as today.
10. **Unchanged.** Every sign-in refusal. The mass-revoke breaker, its settings and its AND. The
    two-strike rule. Fail-open on an unreachable directory.

**Limits of the rule at non-default settings.** The rotation argument assumes
`ad_session_recheck_strikes` of at least 2. At 1, an undetermined account probed before a second one
is seen is revoked on that first pass. With `ad_session_recheck_max_users` of 1, `r` is 0 on every
pass that probes an undetermined account, so a genuine single is held until its sessions expire.
Both settings are allowed today.

## Acceptance Criteria

- **AC-1** -- WHEN every probe reads `UNDETERMINED` with three signed-in principals, THE SYSTEM SHALL
  revoke nothing and raise the held alert. -> test to build, replacing
  `test_below_the_breaker_floor_the_same_wave_revokes` (BACKLOG #2039 closing item 5)
- **AC-2** -- WHILE the attribute stays unreadable for every account, as signed-in principals fall
  from 12 to 1, THE SYSTEM SHALL revoke no session on any pass and SHALL keep the held alert latched.
  -> test to build, replacing
  `test_a_bind_account_that_cannot_read_the_attribute_trips_the_breaker`, whose breaker-trip
  assertions stop being true under the hold (the attrition path that test does not reach)
- **AC-3** -- WHEN exactly one candidate's latest outcome is `UNDETERMINED` and at least one other's
  is readable, THE SYSTEM SHALL strike that account and revoke it at the strike threshold.
  -> `tests/test_ad_user_account_control.py::test_the_reconciler_revokes_an_account_whose_disabled_bit_is_set_or_undetermined`,
  kept, with its revocation reason as settled on acceptance
- **AC-4** -- WHEN more than one candidate reads `UNDETERMINED` and others read the attribute, THE
  SYSTEM SHALL hold the undetermined accounts and SHALL still revoke a genuinely absent or disabled
  account in the same pass. -> test to build (the partial wave)
- **AC-5** -- IF three signed-in accounts are genuinely absent, or three have the disabled bit set,
  THEN THE SYSTEM SHALL still revoke all three on the second pass. -> tests to build (the controls
  for AC-1)
- **AC-6** -- WHILE the reconciler holds, THE SYSTEM SHALL leave every `UNDETERMINED` account's
  strike count unchanged. -> unit test to build against `plan_pass`
- **AC-7** -- WHEN two undetermined accounts fall in different samples of an estate larger than
  `ad_session_recheck_max_users`, at the default strike count, THE SYSTEM SHALL revoke neither and
  SHALL keep the alert latched from the pass that first sees both. -> test to build
- **AC-9** -- WHILE a hold is engaged, WHEN held sessions expire until one held account remains
  beside readable ones, THE SYSTEM SHALL keep that account held. -> test to build (the hysteresis)
- **AC-8** -- THE SYSTEM SHALL keep refusing an AD sign-in on the Kerberos and id-keyed paths for the
  absent, empty and non-numeric shapes.
  -> `tests/test_ad_user_account_control.py::test_login_refuses_an_account_whose_disabled_bit_is_set_or_undetermined`,
  unchanged

## Consequences

**Positive.** A bind account that loses read on `userAccountControl` would no longer sign out a small
estate, or finish off a large one by attrition. A partial loss would be held for the affected
accounts only. The alert would stay up while any affected account holds a live session. After that
the reconciler can no longer see the condition; the refused sign-ins and the once-per-shape log
warning remain the signal. #1639's sign-in refusal
and its single-account revocation both stand.

**Negative / risks.** Two genuinely unreadable accounts, or one with nothing readable beside it, are
held rather than revoked, for up to the absolute session cap. `ProbeOutcome` grows from three members
to five. The reconciler gains one more process-local ledger beside the three it keeps, a second latched
alert, a new audit action and a new alert type.

**Out of scope.** Reading `accountExpires` or lockout, which `_account_enabled` does not check today.
Changing the mass-revoke breaker's floor or fraction for `ABSENT`. A bind account that loses read on
`memberOf` alone: depending on how groups are resolved, that could plan a role-demotion wave, and
only the floored breaker would meet it. The floor itself is the wider question, and this ADR does not
reopen it.

## To resolve on acceptance

- [ ] Hold only the undetermined accounts (recommended), or abort the whole pass through the
      existing `plan.aborted` path.
- [ ] Is the count of one a fixed rule (recommended; there is no deploying site to tune for) or a new
      `[auth]` setting?
- [ ] Names: the held audit action, the alert type, and the reason slug.
- [ ] The revocation `reason` for `DISABLED` and a single `UNDETERMINED`. Keeping `directory_absent`
      leaves audit readers and the AC-3 test unchanged. A new reason tells an operator more.
- [ ] Whether ADR 0079's "Acknowledged floor" paragraph and its Consequences residual get a dated
      pointer amendment to this ADR. The drafter's lean is yes, since both argue the opposite for
      this case.
- [ ] Prose the build must correct, at least: the comment above `ad_session_revoke_max` in
      `config/settings.py` (BACKLOG #2039 closing item 5); the `_account_enabled` warning text, which
      says the reconciler reads these accounts as absent; the `reconcile.py` module docstring and the
      `ProbeOutcome.ABSENT` docstring; the `_search_user` comment and the `_probe_principal`
      docstring; and both tests AC-1 and AC-2 replace.
