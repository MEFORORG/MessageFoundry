# 0079 — Kerberos/AD engine-session lifetime coordinated with the directory (IdP)

- **Status:** Proposed  <!-- design only; DEFERRED build — no code in this lane -->
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
