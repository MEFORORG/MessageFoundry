# 0079 — Kerberos/AD engine-session lifetime coordinated with the directory (IdP)

- **Status:** Accepted (mechanism 2 built 2026-07-22)  <!-- mech 1 Kerberos path closed by acceptance; mech 1 federated path shipped in ADR 0142 -->
- **Date:** 2026-07-10
- **Related:** [ADR 0002](0002-auth-rbac.md) (auth/RBAC, AD/Kerberos delegation) · [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (browser Kerberos SSO seed_reauth) · [docs/SECURITY.md](../SECURITY.md) · ASVS 7.1.3 · BACKLOG #187

---

## Context

For a directory (AD / Kerberos-SSO) login the engine mints its **own** opaque session whose lifetime is
completely independent of the directory's. In `AuthService._complete_ad_login` the authenticated AD
principal is turned into a local session by `_issue_session` (`auth/service.py`), which stamps:

```python
expires_at = time.time() + self._settings.session_absolute_hours * 3600   # default 12h, flat
```

plus the `[auth].session_idle_timeout_minutes` idle window. Neither value is derived from anything the
directory said about *this* login. That produces two IdP-coordination gaps:

1. **Ticket lifetime is ignored.** A Kerberos TGT / service ticket carries its own `endtime` (domain
   policy — often shorter, sometimes longer than 12h). The engine session neither shortens to the
   ticket's remaining validity nor renews with it; it just runs the flat local absolute timer.
2. **IdP-side termination does not propagate.** When the directory disables the account, forces a
   sign-out, or Entra **Conditional Access** revokes the session, the engine has no channel that hears
   it. The local session stays live until the local absolute/idle timer elapses (already tracked as a
   CISO-review open item: *"AD-disable keeps live sessions"*). AD role/scope changes ARE re-synced on
   the **next** login (`_sync_ad_channel_scope`, `set_user_roles` revoke-on-change), but a login that
   never recurs leaves a stale-privilege or disabled-account session running for up to the absolute
   window.

This is the ASVS **7.1.3** concern: when authentication is delegated to an IdP, the relying party's
session lifetime should be **coordinated with** the IdP session, not set by an unrelated local
constant.

### Binding constraints (why this is not a quick change)

- **Three-backend store surface.** Coordinating lifetime needs the `sessions` row to carry directory
  provenance — at least a directory-derived expiry and a "last re-validated at" timestamp — plus a
  background re-validation loop. That touches `store/store.py`, `store/sqlserver.py`, and
  `store/postgres.py` (a co-owned migration surface) and adds an LDAP round-trip off the event loop.
- **Local accounts must be unaffected.** Local (non-directory) sessions have no IdP to coordinate
  with; their `session_absolute_hours` / idle behaviour must stay byte-identical.
- **Loopback default unchanged.** The engine is localhost-by-default; this control must not alter the
  no-collector / no-TLS / 127.0.0.1 paths.
- **AD MFA stays delegated.** MFA for directory accounts is the IdP's job (ADR 0002); this ADR is
  strictly about *session lifetime*, not a second factor.

## Decision

**Adopt, as a Proposed and DEFERRED design, coordinating the AD/Kerberos engine session's lifetime
with the directory instead of the flat local `session_absolute_hours`.** Two coordinated mechanisms:

1. **Honor the directory ticket lifetime (upper bound the absolute expiry).** When a login is a
   directory login, cap the engine session's `expires_at` at the directory-provided lifetime rather
   than always `now + session_absolute_hours*3600`:
   - Prefer the Kerberos ticket `endtime` when the SSO path exposes it.
   - Otherwise use a domain-aligned `[auth].ad_session_max_hours` (a new knob; when unset, fall back
     to `session_absolute_hours`, so behaviour is unchanged until an operator opts in).
   The engine session is therefore **never longer** than what the directory authorized for this login;
   renewal (if any) re-derives from a fresh directory proof, never from the local clock alone.

2. **Propagate IdP-side termination (bounded re-validation).** A background, cooperatively-cancellable
   task periodically re-validates each live directory session against the directory — account still
   enabled, still a member of the mapped groups, not administratively signed out — every
   `[auth].ad_session_recheck_seconds` (a new knob; `0` = off = today's behaviour). A failed
   re-validation **revokes** the engine session (`revoke_user_sessions` / `revoke_session`) and audits
   `auth.ad_session_revoked`, so an IdP disable/logout takes effect within one recheck interval instead
   of at the absolute timeout. This mirrors the existing on-login re-sync, just moved onto a timer so it
   fires without a new login. It runs **off the event loop** (LDAP is blocking) and fails **safe**: a
   transient directory outage does not revoke (to avoid a directory blip logging every SSO user out),
   but is rate-limited and audited.

### Secure-by-default + opt-out (owner ruling, BACKLOG #187)

Both knobs ship with a documented org opt-out and a conservative default: `ad_session_max_hours` unset
falls back to today's `session_absolute_hours`; `ad_session_recheck_seconds = 0` disables the
re-validation loop. An operator whose domain policy warrants tight IdP coordination sets them; the flat
local behaviour remains available. (When built, the recommended default for a PHI/off-loopback
deployment would flip these on, per the #187 secure-default posture — decided at build time.)

## Status / scope — DEFERRED, not built in this lane

This ADR is **design only**. Item #187 (authentication defaults) ships the TOTP-skew knob and the
`require_mfa` default flip; the Kerberos/IdP session-coordination change is a **three-backend session
schema + background-task change** that belongs in its own lane and is explicitly **out of scope here**.
No code, migration, or settings field for this ADR is added in the #187 change. It is recorded now so
the coordination gap is captured against ASVS 7.1.3 with an agreed shape.

## Consequences

- **Positive.** IdP disable/logout and Conditional Access revocation propagate to the engine within a
  bounded interval; engine sessions can no longer outlive the directory ticket that authorized them;
  closes the CISO "AD-disable keeps live sessions" item. Local sessions and the loopback default are
  untouched.
- **Negative / cost.** A new background LDAP re-validation loop (blocking, off-thread), added
  `sessions` columns across three store backends, and two new `[auth]` knobs. A misconfigured short
  recheck against a flaky directory could churn re-validation — hence the fail-safe + rate-limit and
  the default-off posture until an operator opts in.
- **Alternatives considered.** (a) Keep the flat local absolute timer and rely on on-next-login
  re-sync — rejected: a never-recurring login leaves a stale/disabled session live for the whole
  window. (b) Push-based revocation (directory → engine webhook) — rejected for now: needs
  directory-side configuration the on-prem adopter may not control; the pull re-validation loop is
  self-contained. (c) Shorten `session_absolute_hours` globally — rejected: penalizes local accounts
  and still ignores the ticket lifetime.

---

## Amendment (2026-07-21) — mechanism 1's preferred input is unobtainable via pyspnego; ASVS 7.1.3 closed by ACCEPTANCE, status stays Proposed

**Status is unchanged: `Proposed` / DEFERRED.** This amendment records *why* the build did not happen
when the demand trigger (a domain-joined lab) finally arrived, so the gap is not silently re-planned.

**Finding — the Kerberos ticket `endtime` is not reachable.** The Decision above hedges mechanism 1 with
*"Prefer the Kerberos ticket `endtime` **when the SSO path exposes it**"*. It does not, on the shipped
stack:

- `spnego.server()` (pyspnego 0.12.1, `spnego/auth.py:173-183`) exposes no expiry on the acceptor it
  returns, and the public `ContextProxy` surface has no ticket-lifetime accessor.
- The datum *does* exist one layer down on Windows — `sspilib`'s `AcceptContextResult.expiry` is SSPI's
  `ptsExpiry` from `AcceptSecurityContext`, which for the Kerberos package derives from the service
  ticket end time — but `spnego`'s `SSPIProxy.step()` discards it.

Obtaining it therefore requires forking or monkeypatching `spnego.SSPIProxy.step`, upstreaming an
`expiry` property to pyspnego (plus a `SecPkgContextLifespan` binding to sspilib), or bypassing pyspnego
entirely. **Forking a security library to satisfy an already-accepted control is not a trade this project
makes.** Without it, mechanism 1 on the Kerberos/LDAPS path degrades to the `[auth].ad_session_max_hours`
fallback — *a second operator-set local constant presented as directory-derived data*, which is worse
than the honest flat `session_absolute_hours` it would replace, because it invites the reader to believe
the directory bounded the session when it did not.

**Consequence for ASVS 7.1.3 — accepted, not built.** The cell is already signed-accepted
([`ASVS-L3-RESCORE-2026-07-17.md`](../security/ASVS-L3-RESCORE-2026-07-17.md) §3; register row
[`ASVS-L3-RISK-ACCEPTANCE-REGISTER.md`](../security/ASVS-L3-RISK-ACCEPTANCE-REGISTER.md):73, signed
theme 3, next review 2027-01-14). BACKLOG #187's residual therefore **closes by acceptance**, and this
ADR's *"Proposed→Accepted if 7.1.3 is built"* promotion trigger is **NOT fired**.

**Mechanism 1 does ship — on the federated path only.** Where the engine consumes a federated OIDC
`id_token`, the authorizing lifetime is present and signature-verified as the `exp` claim. The federated
relying-party build applies it as a `min()` at the single session-mint site
(`AuthService._issue_session`, `auth/service.py`), so a federated session is never longer than the
token that authorized it. That is mechanism 1 delivered where the datum genuinely exists, rather than
simulated where it does not. Note the corollary: this ADR's residual language ("the shipped posture
mints no federated session") becomes conditional the moment an operator sets `oidc_enabled = true`.

**Mechanism 2 (the background directory re-validation loop) stays deferred**, unchanged: a `sessions`
schema change across three store backends plus a supervised lifespan task, for a control already
accepted. Revisit on a named requirement for directory-revocation propagation.

---

## Amendment (2026-07-22) — mechanism 2 is BUILT; the schema cost was illusory; a mass-revoke circuit breaker is added

**Status moves to `Accepted` for mechanism 2.** Mechanism 1 on the Kerberos/LDAPS path remains closed
by acceptance (previous amendment, unchanged); mechanism 1 on the federated path shipped with ADR 0142.

### Why now — the residual is narrower than the original Context implied, and worse where it survives

An adversarial re-read of the code narrowed the blast radius, and the narrowing is worth recording
because it contradicts the loose reading of *"the local session stays live"*:

- **`require_step_up` performs no directory bind.** It calls `has_recent_step_up(token)`
  (`auth/service.py`), which compares the session's stored `reauth_at` against
  `[auth].step_up_max_age_seconds` — a pure timestamp check. The live bind lives only in
  `_reauth_ad` → `LdapAuthenticator.authenticate` → `_find_user`, which rejects
  `userAccountControl & 0x2`, and that is reached **only** via `POST /me/reauth`.
- **So the step-up surface is protected by inability to REFRESH, not by re-checking.** Purge, export,
  bulk replay, config reload, message injection and the whole `/users*` admin surface are
  `require_step_up`; a disabled AD account cannot mint a fresh `reauth_at`, so it loses them — but
  only **once its existing window lapses**. A directory login is born with the window seeded
  (`_complete_ad_login(seed_reauth=True)`), so there is a residual of up to
  `step_up_max_age_seconds` (300 s default) in which an already-disabled account can still purge or
  export.
- **What survives to the 12-hour cap** is everything with no step-up gate at all: bulk and raw PHI
  reads (`GET /messages`, `/messages/{id}`, attachments, `/dead-letters` — `require_phi_read`, paced
  at `phi_read_rate_limit_per_actor = 120`/min) and connection start/stop/restart
  (`require_paced(CONNECTIONS_CONTROL)`). A disabled clinician keeps harvesting PHI at 120 reads a
  minute, and a disabled operator can still stop an interface.

That is a smaller surface than "a disabled account keeps everything", and a materially worse one than
"they just lose admin": it is exactly PHI egress plus availability.

### The binding constraint that deferred this was wrong

The original Context deferred mechanism 2 partly on *"a `sessions` schema change across three store
backends (a co-owned migration surface)"*. **No schema change is needed.** The candidate set —
directory-backed principals still holding a live session — is derivable from the existing
`list_users()` + `list_sessions(user_id)` (the latter already filters revoked/expired). Provenance
columns (`directory_expiry`, `last_revalidated_at`) were only ever required by **mechanism 1**, which
is not being built here. `store/store.py`, `store/sqlserver.py` and `store/postgres.py` are untouched.

The remaining stated cost — the supervised lifespan task — is one `asyncio.create_task` beside the
existing `_session_reaper`, cancelled in the same `finally`.

### Decision additions

Mechanism 2 ships as designed (per-interval re-validation via the password-free `resolve_principal`,
off the event loop, fail-safe, `ad_session_recheck_seconds = 0` = off, audited) **plus three
properties the original design did not name**:

1. **Two-strike before revoking** (`[auth].ad_session_recheck_strikes`, default 2). The original text
   said "fails safe" only about *outages*. It missed that a *successful* lookup returning nothing is
   itself ambiguous: `_find_user` returns `None` identically for disabled, deleted, moved out of the
   search base, and never-was-in-the-search-base. Two agreeing probes cost at most one extra interval
   of exposure and buy immunity to a single flaky search.

2. **A mass-revoke circuit breaker** — the load-bearing addition. A misconfigured `ad_user_search_base`,
   an OU reorganisation, or a service account that lost read rights returns "not found" for **every**
   user, which is *indistinguishable* from "everyone was disabled". Un-braked, mechanism 2 converts a
   directory misconfiguration into a total console outage — strictly worse than the gap it closes,
   and precisely during an incident. A pass whose revocation set exceeds **both**
   `[auth].ad_session_revoke_max` (5) **and** `[auth].ad_session_revoke_max_fraction` (0.34) of the
   probed population **aborts**: nothing is revoked, nothing is written, a latched operator alert is
   raised and `auth.ad_reconcile_aborted` is audited.

   **Why AND, not OR.** The absolute floor alone would sign out a 5-person site on a bad search base;
   the proportion alone would fire on a 3-of-3 genuine offboarding, where 100 % is meaningless.
   Requiring both means the breaker fires only on a change simultaneously **large in absolute terms**
   and **broad relative to the signed-in population** — the signature of a misconfiguration, not of
   offboarding. A 50-of-300 batch offboarding (17 %) still applies; a 300-of-300 wipe does not.
   **Acknowledged floor:** below 6 concurrent directory sessions the breaker cannot distinguish the
   two cases and will revoke. Signing out five operators is recoverable, and if the directory really
   is broken they cannot sign back in — which is the loudest possible signal.

3. **All-or-nothing passes.** The pass is planned in full (`auth/reconcile.py`, a pure decision layer)
   before any store write, so an abort leaves the store byte-identical. The strike ledger is
   *deliberately* exempt: it is process-local bookkeeping, not store state, and keeping it across an
   abort makes a standing misconfiguration trip on **every** pass instead of oscillating
   (accrue → trip → reset → accrue) and flickering the alert.

**Group re-diff rides the same pass, free.** `resolve_principal` already returns the group set, so a
role **demotion** is applied without a login that may never come (closing the "a login that never
recurs leaves a stale-privilege session running" half of the original Context). It is counted against
the **same** breaker budget, because an emptied `ad_group_role_map` is exactly as suspicious as a mass
disable. **Channel scope is deliberately NOT re-diffed:** `_sync_ad_channel_scope` is opt-in and
never-clobbering (`if not channels: return user`), so replicating that rule inside the planner would
complicate the breaker's exactness for a narrower residual. Scope still re-syncs on next login —
a recorded, narrower residual.

### Directory load

One `resolve_principal` per **distinct signed-in directory user** per pass — a service-account bind
plus one subtree search, plus one nested-group search when `ad_use_nested_groups` (the default). Zero
binds when nobody is signed in, when AD is off, or at the default interval of 0. Bounded above by
`[auth].ad_session_recheck_max_users` (200), so it does **not** grow with estate size: 50 concurrent
operators at 300 s is ~0.17 binds/s; the 200-user cap at the 60 s floor is ~3.3 binds/s. A pass that
cannot reach everyone rotates least-recently-probed-first, degrading to a longer effective interval.

### Consequences (delta)

- **Positive.** The CISO "AD-disable keeps live sessions" item closes for the surfaces that actually
  survived — bulk/raw PHI reads and connection control — and role demotions no longer wait for a
  login. No store schema change, so the three-backend migration risk the deferral cited is void.
- **Negative / residual.** Revocation is bounded by the interval plus the strike count (default
  2 × 300 s = up to 10 minutes), not immediate. Strike state is process-local, so a restart resets it
  (biased toward *not* revoking). The ≤`step_up_max_age_seconds` step-up residual above is unchanged
  by this ADR. Below the breaker's absolute floor, a whole small estate can still be signed out by a
  misconfiguration.
- **Not changed.** `_mfa_required_for` still returns False for every non-LOCAL provider — AD MFA stays
  delegated to the directory (ADR 0002). Local sessions, the loopback default, and every path with
  `ad_session_recheck_seconds = 0` are byte-identical.

## Amendment 2026-07-28 — `[auth].ad_session_recheck_seconds` now defaults to 300 (ADR 0148 GIVEN 1)

**What changed.** `[auth].ad_session_recheck_seconds` flips `0` (off) → **`300`** (five minutes), the
value this ADR and `docs/SECURITY.md` already recommended for an off-loopback PHI deployment. Everything
else about mechanism 2 — the 60 s floor, `ad_session_recheck_strikes`, `ad_session_recheck_max_users`,
the mass-revoke breaker, the fail-open-on-DC-unavailability posture — is unchanged.

**Why.** ADR 0148 GIVEN 1: the hardened path is the shipped path. Left at `0`, directory revocation did
not propagate at all — an AD account disabled or deleted kept its live engine sessions until the
`[security].max_session_hours` cap. A recommendation that must be typed to take effect is a control that
is off in most deployments.

**Why the shipped default does not break a non-AD deployment.** The loop requires an LDAP client:
`AuthService.should_reconcile()` checks for one, so a deployment that never enables `ad_enabled` creates
no task and issues no bind. The default is therefore **inert** without AD.

**The cross-field refusal is re-keyed, not removed.** `ad_session_recheck_seconds` without `ad_enabled`
used to fail startup — correctly, because an operator who typed it believed directory revocation now
propagated, and a silently-dead security control is worse than one never enabled. With a non-zero
*shipped* default that rule would fail startup on every non-AD box. It is now keyed on
`model_fields_set`: an **explicitly configured** value without `ad_enabled` still refuses (the case the
rule exists for), while an untouched default — which carries no operator belief to falsify, and is inert
anyway — does not.

**Visibility.** `ad_session_recheck_seconds = 0` **with** `ad_enabled` is a **loosening**:
`security_loosenings()` names it, so it appears in the serve-time warning and in
`GET /security/posture`, with an entry in [docs/SECURITY-LOOSENING.md](../SECURITY-LOOSENING.md). It is
deliberately conditional — with no directory to reconcile against, `0` is not a weaker choice, it is the
only meaningful one, so it is not reported as a deviation on a non-AD instance.
