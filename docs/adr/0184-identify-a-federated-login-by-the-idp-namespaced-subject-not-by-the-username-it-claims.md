# ADR 0184 — Identify a federated login by the IdP-namespaced subject, not by the username it claims

- **Status:** Proposed — **the build must not start yet.** The owner trust decision was TAKEN on
  2026-09-06 (recorded against the first item under *To resolve on acceptance*), so the sentence that
  stood here — that the code cannot be written until it is taken — no longer states what blocks this.
  Four items remain open, and the second follows directly from the ruling: the bootstrap posture.
  Accepting this ADR is a separate act and has not happened.
- **Date:** 2026-09-05
- **Related:** [ADR 0142](0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md)
  and its Amendment A (subject continuity) · [ADR 0136](0136-per-user-saved-and-layered-log-search-filter-presets-extends-the-adr-0046-search-seam.md)
  (cites the same root cause) · [BACKLOG](../BACKLOG.md) #1143 (the research this records), #1015
  (the continuity guard), #1256 (the exclusivity veto and the filtered unique index) ·
  ASVS 6.8.1 · [CLAUDE.md](../../CLAUDE.md) section 0

> **Everything here is cited by symbol, never by line number.** BACKLOG #1143 has carried three sets
> of line numbers and every one of them moved. Two of its passes spent their opening effort
> re-deriving anchors that had drifted. `roles/COMMON.md` states the rule already: cite a file by
> symbol name or section heading, never by a line number. A reader can find
> `AuthService._complete_ad_login` in one grep, and it will still be there next month.

---

## Context

ASVS **6.8.1** (L2) asks that a user's identity cannot be spoofed through another supported identity
provider, and names the mitigation: register and identify the user by the IdP's id plus the user's id
inside that IdP. The pinned verb is quoted in full in BACKLOG #1143 and is not repeated here.

The engine supports four ways in: a local password, an AD simple bind, Kerberos, and OIDC. All three
directory mechanisms converge on `AuthService._complete_ad_login`. Every account lives in one
username namespace: `users.username` is declared `NOT NULL UNIQUE` in all three store backends
(`store/store.py`, `store/postgres.py`, `store/sqlserver.py`). The provider is a column beside that
key, not part of it.

**What already shipped, so nobody re-derives it.** The store carries the pair. `oidc_issuer` and
`oidc_subject` are columns on `users`; `ux_users_federated_subject` is a filtered unique index over
them on all three backends; `AuthStore.get_user_by_federated_subject` and
`AuthStore.set_user_federated_subject` are on the protocol with three implementations. Measured
2026-09-05 at engine `a083cdb89`: the same probe that returned **0/0/0** unique indexes naming those
columns in 2026-08-13 now returns **1/1/1**, against a still-firing control of 10/6/8 total `UNIQUE`
declarations. The 2026-08-13 amendment predicted the SQL Server key-width trap and #1256 paid it: the
columns there are a bounded `NVARCHAR`, with a `COL_LENGTH`-guarded re-type migration.

**What did not ship is the thing the verb actually asks for: identification.** The engine stores the
pair and can look an account up by it. It does not select an account with it. The federated leg
reaches its account through three username-keyed reads and consults the pair only afterwards:

| Site (by symbol) | What it does with the username |
|---|---|
| `AuthService.authenticate_oidc`, at the `resolve_principal` call | Resolves the directory principal from the token's username claim |
| `AuthService.authenticate_oidc`, the #1015 continuity guard | Fetches by `principal.username`, then compares the pair |
| `AuthService._complete_ad_login`, its `get_user_by_username` call | Fetches by `principal.username` again. **This read returns the row the session is issued for.** |
| `AuthService._complete_ad_login`, the `federated_subject` branch | Reaches `get_user_by_federated_subject` **after** `_upsert_ad_user` has already run, so the pair is an exclusivity veto over an account chosen by username |

**The continuity guard cannot cover first contact, by construction.** Its test includes
`bound.oidc_subject is not None`, so it short-circuits on every account that has never
federated-logged-in. That is the default state of every account: the whole population before
federation is enabled, plus every account the simple-bind and Kerberos paths create afterwards, since
they pass no subject. ADR 0142 Amendment A recorded the same window and reproduced it end to end.

**Nothing else can tell the mechanisms apart at runtime.** `AuthProvider` has two members, `LOCAL` and
`AD`. A federated session and an LDAP simple bind report the same value. The audit half of that
condition is not true and should not be repeated: `_complete_ad_login` adds `mech` and an `amr`/`acr`/
`sub` evidence block to `auth.login_success` on the federated path only, and binding emits its own
`auth.federated_subject_bound` row. An operator reading the audit store can tell them apart. What
cannot is any code making a runtime authorization decision.

**Severity, in the conditional the project requires.** The engine has zero deployments
([CLAUDE.md](../../CLAUDE.md) section 0), so nothing here is a live exposure. On a first deployment
running both the directory and the pinned OIDC issuer, a principal that issuer will mint an
allow-listed-suffix username for could land on a never-federated AD account and inherit its
directory-derived roles, with no credential compromised. The suffix allow-list in
`auth/oidc/claims.py` constrains the suffix only and defaults to the configured `ad_domain`; the claim
it reads defaults to `preferred_username`, which OIDC Core calls neither unique nor stable. Whether an
operator's IdP will mint such a name is a property of that tenancy, not of this engine.

---

## Decision

**A federated login's identity is the `(issuer, subject)` pair. The account is selected by that pair
before any username is read, and the directory principal is then re-resolved from the bound row's own
stored username.** That removes identifier equality from the identification path, which is literally
what the pinned verb's parenthetical names.

Four parts, and the fourth is gated on the owner decision below.

1. **Resolve by the pair at the head of `_complete_ad_login`**, before its `get_user_by_username` call.
   `federated_subject` is already a parameter there and already defaults to `None`, so the simple-bind
   and Kerberos callers take no new branch. This is a re-ordering of existing primitives, not a new
   one, and it writes no DDL.

2. **On a hit, re-resolve the directory principal from the bound row's stored username.** The
   `AdPrincipal` that arrives was resolved from the token's claim. It must not be reused once a
   different row has been selected. See *What it must not break*.

3. **Keep the provider-confusion guard, and move it onto whichever row was resolved.** Today the guard
   refuses a row whose `auth_provider` is not the AD value, and it depends on the username lookup that
   precedes it. Under pair-keyed resolution its original job is discharged a second way, because
   identifier equality never enters the selection. It still has work: a binding placed by any future
   administrative surface could sit on a `LOCAL` row, and only this guard would catch that. So the
   guard survives and its subject changes from "the row this username found" to "the row we resolved".

4. **Delete the unbound short-circuit in the continuity guard, once first contact has an answer.**
   Removing it without a bind path refuses every federated login on a fresh deployment. That is the
   open decision, not a detail of this one.

### What it must not break

- **AD simple bind and Kerberos stay byte-identical.** They pass no `federated_subject`, so the new
  branch is unreachable from them. This is the existing design working, not a limit to be argued over.
- **Roles stay LDAP-sourced.** ADR 0142's Decision holds. Nothing here reads a role from a token claim.
- **The #1256 exclusivity veto and `ux_users_federated_subject` stay.** Pair-keyed resolution makes the
  veto's read redundant on the hit path, not wrong. The index is what makes the check-then-act guard
  atomic and must not be dropped as "now unreachable".
- **A half-done re-ordering is a privilege-transfer bug, and it is the likely way to get this wrong.**
  Resolve by the pair to row R, then carry on with the `AdPrincipal` resolved from the token's claimed
  username U, and two things go wrong at once: `_upsert_ad_user` looks U up and touches a *different*
  row, and `roles_for_ad_groups(principal.groups)` writes U's directory groups onto R. The holder of R
  gains U's roles. Part 2 above is not a refinement. It is load-bearing.
- **The directory reconciler must not stay username-keyed.** `AuthService.reconcile_directory_sessions`
  runs on a shipped 300-second default over every AD-provider account holding a live session. Every
  federated-bound account is an AD-provider account, because `_upsert_ad_user` creates them that way.
  Its candidate filter has no exclusion for a bound row, and `_probe_principal` re-resolves with
  `resolve_principal(user.username)` and then rewrites the role set in both directions. Keying
  identification at login while leaving this loop keyed on the username leaves the same-identifier
  attachment live after login: a bound account would acquire a reassigned name's new holder's roles
  within one interval, with no assertion presented by anyone.

---

## Acceptance Criteria

> **No test below is written yet, and that is deliberate.** The build is blocked on the owner decision,
> and AC-4 cannot even be stated until that decision is taken. Each `→` names the module the test
> belongs in.

- **AC-1** — WHEN a federated login presents an `(issuer, sub)` already bound to an account, THE SYSTEM
  SHALL select that account by the pair before reading any username, and SHALL issue the session for
  that account even when the token's username claim resolves to a different directory principal.
  → `tests/test_auth_oidc_service.py`
- **AC-2** — WHEN the pair selects an account, THE SYSTEM SHALL re-resolve the directory principal from
  that account's stored username, and SHALL derive roles only from the re-resolved principal's groups.
  → `tests/test_auth_oidc_service.py`
- **AC-3** — IF the pair-selected account's `auth_provider` is not the AD value, THEN THE SYSTEM SHALL
  refuse the login with an audited `local_account_conflict` and mint no session.
  → `tests/test_auth_oidc_service.py`
- **AC-4** — (first contact) **Unwritable until the ceremony decision is taken.** It is named here so
  its absence is visible rather than forgotten.
- **AC-5** — WHILE an account carries a federated binding, THE SYSTEM SHALL NOT re-resolve that account
  from its username in `reconcile_directory_sessions`.
  → `tests/test_ad_session_reconcile.py`
- **AC-6** — WHEN a federated login presents no `federated_subject` (the simple-bind and Kerberos
  callers), THE SYSTEM SHALL take no pair-keyed branch and SHALL emit the same audit row it emits today.
  → `tests/test_ad_login_pathway_split.py`

---

## Options considered

1. **Pair-keyed resolution with a re-resolve from the bound row.** **CHOSEN.** It is what the verb's
   own mitigation describes, it needs no schema change, and the `None` default scopes it to the one
   path that carries a subject.

2. **Widen the continuity guard to unbound accounts and leave resolution keyed on the username.**
   Rejected: it refuses first contact without providing any way to bind, and today there is no other
   way (see *Consequences*). It is a policy that sits on top of the administrative surface option 1
   also needs, not an alternative to this decision.

3. **A third `AuthProvider` member for federated accounts.** Rejected, and this was measured rather
   than argued. `username` is globally unique across one namespace, all three directory mechanisms
   converge on `_complete_ad_login`, and its provider guard refuses any row whose provider is not the
   AD value. A third member either breaks hybrid login at that guard or is written nowhere and enforces
   nothing. A mechanism discriminator belongs on the **session**, and it must name a consumer that can
   read it — which the reconciler is not, since it iterates account rows.

4. **Ground the 6.8.1 cell on the `(issuer, sub)` continuity pair and rescore.** Rejected. That is
   10.5.2's verb, which is scoped to one identity provider. The pair cannot do cross-provider work
   here at all: `auth/oidc/claims.py` rejects any token whose `iss` differs from the single pinned
   issuer before any guard runs.

5. **Rescore `na` because `oidc_enabled` ships `False`.** Rejected. A disabled feature removes the
   trigger, not the control.

6. **Bind the account to a directory-held immutable attribute and authenticate on that.** Rejected.
   The attribute is directory-readable and is not a secret, so an issuer willing to mint an arbitrary
   username claim will mint an arbitrary claim of any name. Note this rejection is about
   *authentication*. It does not rule the same attribute out for the reconciler, whose job is
   re-resolving an account that has already been identified.

---

## Consequences

**Positive.** Identification stops depending on an identifier the counterparty controls. A legitimately
renamed directory account keeps resolving to its own row instead of being refused, which turns ADR 0142
Amendment A's availability residual from a permanent lockout into an ordinary rename. The change is
code only on the login path: no DDL, no migration, no backfill.

**Negative and risks.** Pair-keyed resolution adds a second LDAP round trip on the federated path, off
the event loop. A bound account whose stored username no longer exists in the directory now fails with
`not_in_directory`, which is a lockout that only a rebind path can clear. The privilege-transfer
hazard above is a live risk during implementation, not a theoretical one.

**A cost nobody has priced yet, and it belongs on the record.** `AuthStore.set_user_federated_subject`
takes `issuer: str, subject: str`. **Both are required, so there is no way to express an unbind.** Any
administrative surface that needs to *clear* a binding, rather than only re-point it, is a protocol
change plus three backend implementations, not a route. Whether it needs a clear at all depends on the
ceremony decision, so this is priced here and decided there.

**And the measurement that frames that decision.** `set_user_federated_subject` has exactly **one**
caller in the engine: the bind-on-first-presentation site in `_complete_ad_login`. Measured 2026-09-05
against a positive control of five callers for the sibling `set_user_roles`, so the probe
discriminates. `api/auth_routes.py` has no federated route, and the web console has no federated
surface. **The engine's only way to create a binding today is the one the verb forbids.**

That has a consequence for the ceremony options that ADR 0142 Amendment A stated as an either/or.
Its option (a), refuse an unbound account, says "until an operator binds them" — and its option (b) is
the surface that would let an operator do that. **They are not alternatives.** An administrative
binding surface is the floor under every ceremony that closes the verb, because bind-on-first-
presentation *is* the defect and every other candidate presupposes an out-of-band bind. What is
genuinely still open is narrower: **what, besides that surface, may create a binding.**

### Out of scope, and this boundary is load-bearing

**This ADR covers the federated (OIDC) leg only. It does not close the AD identifier-recycle limb,
and three places in the engine tell a reader it does.** These name BACKLOG #1143 as the fix for a
different problem: `_upsert_ad_user` adopts a surviving mirror row by `sAMAccountName` and re-binds its
`user_id`, so a directory-side recycle without a MessageFoundry `delete_user` hands the new holder the
departed operator's immutable id.

| Site | What it says #1143 will fix |
|---|---|
| `api/app.py`, `_may_access_upload` docstring | Object-level authorization over uploaded PHI. Names #1143 as "not solvable inside this function" |
| `uploads.py`, the `UploadedFileMeta` docstring | The same id, keying ownership and the per-uploader quota |
| `tests/test_upload_api.py`, the recycle test's scope note | Says the default AD path "is not closeable by this key" |

[ADR 0136](0136-per-user-saved-and-layered-log-search-filter-presets-extends-the-adr-0046-search-seam.md)
says the same of saved search presets: "BACKLOG #1143 is the real close."

That limb is **not 6.8.1's verb** — a recycled name inside one directory is not cross-IdP spoofing —
so a 6.8.1 rescore can be honest and leave all four citations unaddressed. Whoever closes #1143 must
either re-point those four or leave the item open for that limb. The failure mode is quiet: a citation
to a closed item reads as done.

---

## To resolve on acceptance

- [x] **THE OWNER DECISION. What, besides an administrative binding surface, may create a federated
      binding?** The surface itself is entailed (see *Consequences*). The residue is the policy on top
      of it: bind on first presentation during a bounded bootstrap window, a self-service link proved
      by the user's own directory password (unavailable for Kerberos-only and other passwordless
      accounts, so it can never be the only path), or nothing at all. This is a trust decision about a
      counterparty, and it is not a researcher's or a builder's to take.
      > **RULED 2026-09-06 by the owner: NOTHING ELSE. The administrative binding surface is the only
      > path that may create a federated binding.** Neither bind-on-first-presentation nor the
      > self-service link is adopted. **What this buys:** the spoofing path 6.8.1 names is closed by
      > construction rather than bounded by a window — there is no state in which presenting a claim
      > creates a binding, so the never-federated account the severity statement is about cannot be
      > landed on at all. **What it costs, and it is not small:** a site enabling federation must bind
      > every account through the administrative surface before its users can log in federated, and
      > the second box below is now the live question rather than an open one — a fresh deployment
      > refusing every federated login until an operator acts is the direct consequence of this
      > ruling, and whether that is the shipped default still needs answering.
      > **Bounding the ruling, so it is not read wider than it was given:** it decides what may CREATE
      > a binding. It does not decide the resolution ORDER (the body of this ADR), the reconciler
      > question, or the AD limb, which is BACKLOG #1471 and is not governed by this ADR at all.
- [ ] **The bootstrap posture that follows from it.** With no bindings and no bind-on-first-
      presentation, a fresh deployment refuses every federated login until an operator binds each
      account. Is that the shipped default? Zero deployments means migration cost is zero, which
      removes a cost from the comparison. It does not choose.
- [ ] **The reconciler: exclude bound rows, or re-key the probe?** Excluding needs no schema at all,
      since `UserRecord` already carries `oidc_subject`, but it trades away directory disable and role
      reconciliation for bound accounts — a security control given up to fix a security control.
      Re-keying costs one nullable column on three backends with no index (so no SQL Server width
      trap), plus a new LDAP attribute read and a lookup path: `resolve_principal` takes only a
      username, and `AdPrincipal` carries `dn`, which is the wrong attribute because a DN changes on
      rename or a move between organizational units. `objectGUID` is the immutable key and is read
      nowhere today. **Re-keying is also the work the four out-of-scope citations above are waiting
      on**, so the two options differ by more than their own price.
- [ ] **Does the administrative surface need an unbind, or only a rebind?** Decides whether
      `set_user_federated_subject` grows an optional-clear form on the protocol and all three backends.
- [ ] Whether the mechanism discriminator belongs on `SessionRecord`, which carries no mechanism field
      today, and which consumer would read it.
