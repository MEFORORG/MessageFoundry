# 0077 — Action-bound step-up re-verification for durable-takeover operations

- **Status:** Accepted  <!-- built in this PR -->
- **Date:** 2026-07-10
- **Related:** [ADR 0002](0002-auth-rbac.md) (WP-14 MFA / step-up) · [ADR 0068](0068-browser-webauthn-passkeys-offloopback.md) (browser step-up + the WebAuthn ceremony cache) · [docs/SECURITY.md](../SECURITY.md) · ASVS 7.5.1 / 8.2.4 · BACKLOG #194

---

## Context

Step-up re-verification (ASVS 7.5.3, WP-L3-16) protects the engine's highly sensitive operations by
requiring the session to have re-proved its credential "recently". As built, "recently" was **pure
recency on a single session-wide timestamp**: `has_recent_step_up(token)` compared
`sessions.reauth_at` against `[auth].step_up_max_age_seconds` (default 300s). Two facts made that a
weak default for the **factor-binding** operations specifically:

1. **Login seeds the window.** `_issue_session(..., seed_reauth=mfa_verified)` writes
   `reauth_at = now` for a fully-authenticated session, so for the first 300s after login *every*
   step-up-gated action is unlocked with **no fresh proof at all**.
2. **The window is a single shared grant.** The one action-tied proof — `POST /me/reauth`'s
   `verify_current_password` — refreshes that same session-wide `reauth_at`, which any subsequent
   sensitive action then reuses. A proof gathered "to change my password" also unlocked "enroll an
   attacker's authenticator".

Threat (most-exploitable default): an attacker who hijacks a live session (stolen cookie/bearer,
borrowed unlocked console) within the login window can **bind their own MFA factor** — TOTP enroll +
confirm, or a WebAuthn passkey register — with no interaction from the victim, achieving durable
account takeover. ASVS **7.5.1** ("full re-authentication before changes to sensitive
authenticators") and **8.2.4** want the re-proof tied to *that* change, not to a broad window.

Binding invariants in play. The engine is on-premises, localhost-by-default; **default 127.0.0.1
loopback behaviour must stay byte-identical** (this control ships secure-by-default but must not
alter the no-collector/no-TLS/loopback paths). The store files (`store/store.py`,
`store/sqlserver.py`, `store/postgres.py`) are **co-owned by another wave** — a `sessions.reauth_purpose`
column would drag a three-backend migration through that shared surface. Per CLAUDE.md the browser
WebAuthn ceremony cache is already a **"bounded, TTL'd, process-local"** staging structure
(`ChallengeCache`, ADR 0068 §2) with the accepted caveat that it is per-process.

## Decision

**Bind the fresh step-up proof to the specific action it unlocks, single-use, via a process-local
grant cache — not to the session's login window.**

- A new **process-local, bounded, TTL'd, single-use** grant cache on `AuthService`, keyed
  `(session token-hash, action)` and modelled on the existing `_new_ip_seen` / `_webauthn_challenges`
  process-local caches. `has_action_step_up(token, action)` **checks and consumes** a grant.
- `reauth(..., purpose=<action>)` **mints** a grant for exactly that action (in addition to the
  existing session-window `reauth_at` refresh, which stays for the broad admin/replay/config routes).
  **Login and `verify_mfa` never mint a grant** — so a login-seeded window can no longer bind a factor.
- New dependencies `require_step_up_action(action, …)` (MFA-gated, for disable-MFA) and
  `require_reauth_only_action(action, …)` (password-only, for the enroll/confirm flows a
  required-but-unenrolled session must still be able to reach) gate the **durable-takeover** JSON routes
  (`/me/mfa/enroll`, `/me/mfa/confirm`, `DELETE /me/mfa`) on a *matching* per-action grant instead of the
  session window. The broad admin / replay / config / purge routes keep the existing session-window
  `require_step_up` (7.5.3 stays Pass).
- The 403 carries `X-Step-Up-Action: <action>` alongside `X-Step-Up-Required: 1`, so the desktop
  console (the primary shipped client) echoes the action back as `POST /me/reauth {"purpose": …}`.
- The **browser `/ui` surface is left entirely on the legacy session-window step-up this PR** — none
  of the action-binding wiring lands in the `messagefoundry_webconsole` package (which is owned by a
  concurrent Wave-1 track). Binding the `/ui` factor-binding routes (the `action=` params on
  `require_ui_step_up`/`require_ui_reauth_only`, an `action` on `UiWriteAction`, and `/ui/reauth` minting
  `reauth(purpose=<continuation.action>)`) is a **Wave-1-owned follow-on**, kept separate because it
  interacts with the existing CSRF-vs-step-up dependency ordering and rewrites ~15 `/ui` step-up
  contract tests (see *Out of scope* / residuals). The engine additive surface it will consume —
  `reauth(purpose=…)` and `has_action_step_up` — already exists and is backward-compatible, so no
  `ENGINE_UI_SEAM` bump is required (the console keeps supporting seam 1).

**Opt-out (owner ruling — secure-by-default + a documented escape):** `[auth].require_action_step_up`
(default **True**). When **False**, `require_step_up_action` / `require_reauth_only_action` fall back to
the legacy `has_recent_step_up` session-window behaviour, so an org can revert to 0.2.x semantics.

**Must not break:** the default loopback bind (this is a pure auth-decision change — no bind, TLS, or
collector path is touched); the broad session-window step-up on admin/replay/config/purge; and the
browser `/ui` step-up flow (untouched this PR — no `messagefoundry_webconsole` file is modified, so its
behaviour is byte-identical).

## Acceptance Criteria

- **AC-1** — WHILE a session is inside its login-seeded step-up window, WHEN it calls `/me/mfa/enroll`
  or `/me/mfa/confirm`, THE SYSTEM SHALL respond 403 + `X-Step-Up-Required` (+ `X-Step-Up-Action`) until
  a fresh `POST /me/reauth` carrying the matching `purpose`.
  → `tests/test_step_up.py::test_login_window_does_not_unlock_factor_binding`
- **AC-2** — WHEN a fresh `reauth(purpose=<action>)` is made, THE SYSTEM SHALL grant exactly that
  action once (single-use); a second sensitive action re-prompts.
  → `tests/test_step_up.py::test_action_grant_is_single_use_and_bound`
- **AC-3** — WHEN a session logs in or satisfies `verify_mfa`, THE SYSTEM SHALL NOT mint any per-action
  grant.
  → `tests/test_step_up.py::test_login_and_verify_mfa_never_grant_an_action`
- **AC-4** — WHERE `[auth].require_action_step_up` is False, THE SYSTEM SHALL fall back to the legacy
  session-window step-up (opt-out).
  → `tests/test_step_up.py::test_opt_out_restores_session_window`
- **AC-5** — IF a session is MFA-pending or on an AD account, THEN THE SYSTEM SHALL NOT deadlock: the
  password-only per-action reauth still unlocks the factor-binding routes.
  → `tests/test_step_up.py::test_mfa_pending_and_ad_do_not_deadlock`

## Options considered

1. **Process-local single-use per-action grant cache (`AuthService`), minted by `reauth(purpose=)`.**
   No schema change; reuses the exact bounded/TTL'd/process-local pattern the WebAuthn ceremony cache
   already ships. **CHOSEN.**
2. **A persisted `sessions.reauth_purpose` column (+ a mint timestamp) across all three backends.**
   Durable across restart and coherent behind a multi-node LB, but it drags a three-backend migration
   through the Wave-1-owned `store/sqlserver.py` + `store/postgres.py` + `store/store.py`, and couples
   this control to a schema change on a co-owned surface. **Rejected** for this PR (revisit if/when the
   store owner lands a migration; the process-local caveat below is the same one ADR 0068 already accepts).

## Consequences

**Positive** — A hijacked session inside the login window can no longer bind an authenticator: each
durable-takeover action demands its own fresh, single-use, action-bound proof (ASVS 7.5.1 / 8.2.4).
No store schema change; no touch to the co-owned store backends. Secure-by-default with a documented
opt-out. Loopback default behaviour is byte-identical (auth-decision-only change).

**Negative / risks** — More friction: a TOTP enroll+confirm now costs two re-proofs (each action is
independently bound + single-use). Grants are **process-local**: on an engine restart, or behind a
multi-node load balancer where the reauth and the follow-up action land on different processes, the
follow-up re-prompts (fail-safe: a re-prompt, never a bypass) — the **same caveat the WebAuthn ceremony
cache already carries** (service.py, ADR 0068 §2). `[auth].require_action_step_up=False` restores the
old single-window behaviour for orgs that prefer it.

**Out of scope / residuals** — Persisting the grant (option 2); a `sessions.reauth_purpose` column; any
store change. Recovery-code regeneration and a dedicated admin email-edit route do not exist as endpoints
in this build, so they are named residuals, not wired. **WebAuthn passkey register** and the **browser
`/ui` factor-binding routes** are deferred to a **Wave-1-owned follow-on**: they live in the separately
owned `messagefoundry_webconsole` package (and, for register, its `account.py`), so this PR does not
touch them — they keep the legacy session-window step-up meanwhile. Wiring them means adding the
`action=` params to `require_ui_step_up`/`require_ui_reauth_only`, an `action` on `UiWriteAction`, and
`/ui/reauth` minting `reauth(purpose=<continuation.action>)`, which also interacts with the `/ui` CSRF
(`assert_same_origin`)-vs-step-up dependency ordering and rewrites ~15 `/ui` step-up contract tests —
kept separate so this PR lands the JSON/console surface cleanly and green without touching Wave-1 turf.
The engine additive surface those routes will consume (`reauth(purpose=…)`, `has_action_step_up`) is
already shipped here and backward-compatible. The primary shipped client (the desktop console) rides
the protected JSON routes.

## To resolve on acceptance

- [x] Which routes bind to an action vs. keep the session window — the JSON TOTP enroll/confirm/disable
      routes bind; admin/replay/config/purge keep the window; WebAuthn register and the browser `/ui`
      twins are deferred to the Wave-1 follow-on (residuals). Recorded in `api/security.py` +
      `api/auth_routes.py`.

## Amendment (2026-07-17, WP245 — ASVS 7.5.2): re-auth before self-service session terminate

The self-service **session-TERMINATE** routes — JSON `DELETE /me/sessions` and `DELETE
/me/sessions/{id}`, and the `/ui` twins `POST /ui/account/sessions/{id}/revoke` +
`.../sessions/revoke-others` — now gate on the **session-window re-auth** (`require_reauth_only` /
`require_ui_reauth_only`, **password-only, no MFA gate** so a no-factor user can still revoke), instead
of the plain authenticated dependency they carried before. This satisfies the ASVS 7.5.2 requirement
that terminating a session re-proves the credential, closing the window in which a hijacked live session
could silently sign the victim out everywhere.

This is the **session-window family** (like admin/replay/config), deliberately **NOT** the single-use
action-bound grants — those stay reserved for the durable-takeover factor-binding routes (this ADR's
Decision). The two body-less `/ui` terminate actions are registered as `step_up=False` `auto_retry`
continuations, so a stale-window `require_ui_reauth_only` 303 to `/ui/reauth?next=<action>` can re-POST
them after re-verification (without the registry entry `lookup_ui_action` returns None and the revoke
silently no-ops). No new setting — the gate reuses the shipped `[auth].step_up_max_age_seconds` window
that login already seeds, so the fresh immediate-post-login revoke is byte-identical; the re-proof
triggers only on a stale window or a new client IP. Ownership stays **404-not-403** (the re-auth gate
runs before the body and returns the same 403 for owned and foreign ids, leaking no ownership). This
closes the **terminate slice** of the deferred browser-`/ui` step-up residual.

## Amendment (2026-07-17, WP245 — ASVS 7.5.1): /ui twins wired + admin-user-update binding

The two residuals this ADR deferred are now built; 7.5.1 moves from Partial to Pass.

**(a) JSON admin-user-update binding.** `PATCH /users/{user_id}` moves from the session-window
`require_step_up(USERS_MANAGE)` to `require_step_up_action(STEP_UP_ACTION_ADMIN_USER_UPDATE,
USERS_MANAGE)` (new constant in `auth/service.py`). It is the one *broad-admin* route promoted to
action-binding as ASVS 7.5.1 coverage on the user-management surface; the other
`require_step_up(USERS_MANAGE)` routes and all admin/replay/config/purge routes keep the session window
(7.5.3). Trade-off recorded: `require_step_up_action` does not carry the BACKLOG #193 / ASVS 2.4.2
`allow_admin_write` NON-GET throttle that `require_step_up` applies, so that per-actor pacing no longer
covers this route directly — accepted because each action-bound PATCH now requires its own fresh
single-use grant, i.e. a fresh `POST /me/reauth`, which is itself login-rate-limited
(`allow_login_attempt`), pacing scripted repeats indirectly.

**(b) Browser /ui factor-binding twins.** The `messagefoundry_webconsole` surface no longer rides the
legacy window for factor binding. New cookie-world deps `require_ui_step_up_action` /
`require_ui_reauth_only_action` (in `webconsole/_auth.py`) consume `has_action_step_up` (falling back to
`has_recent_step_up` under the `require_action_step_up=False` opt-out, via a `_ui_action_step_up_ok`
helper mirroring `api/security.py:_action_step_up_ok`). `UiWriteAction` gains an `action` tag, and
`POST /ui/reauth` mints the matching single-use grant by threading `reauth(purpose=<action.action>)`
(None for every non-factor continuation, so replay/purge/config/create-user stay byte-identical). New
constants `STEP_UP_ACTION_WEBAUTHN_ENROLL` / `STEP_UP_ACTION_WEBAUTHN_DELETE` join the MFA ones. Bound
lanes: `POST /ui/account/mfa/enroll` (MFA_ENROLL), `POST /ui/account/mfa/verify` (MFA_CONFIRM),
`POST /ui/account/mfa/disable` (MFA_DISABLE), `POST /ui/account/webauthn/enroll` (WEBAUTHN_ENROLL),
`POST /ui/account/webauthn/{id}/delete` (WEBAUTHN_DELETE).

**Single-use consume rule (the design invariant that made the /ui twin non-trivial).** Because
`has_action_step_up` is single-use (pops the grant), each durable /ui action has exactly ONE consuming
dependency per reauth. Intermediate hops a preceding reauth transits before the terminal mutation stay
on the NON-consuming window dep: the `GET /ui/account/mfa/confirm` unlock form keeps
`require_ui_reauth_only`, and the WebAuthn ceremony finish `POST /ui/account/webauthn/verify` keeps
`require_ui_reauth_only`. Making either action-consuming would burn the single grant the reauth minted
and infinite-loop.

**CSRF-vs-step-up ordering (the interaction this ADR warned of).** The action grant is consumed in the
dependency, before the in-body `assert_same_origin`. This is fail-safe: `SameSite=Strict` +
`require_ui` reject a cross-site POST (no cookie → 303 to login) before the dependency runs, and an
errant consume only re-prompts, never bypasses. The `new_ip or not _ui_action_step_up_ok(...)`
short-circuit is preserved verbatim so a forced new-IP step-up leaves the grant UNCONSUMED (mirrors
`api/security.py`).

**Still deferred (named residuals, not built here):** the /ui *admin* user-management lane
`POST /ui/users/{user_id}/update` (`webconsole/routes/admin.py`) stays window-gated, so the browser
admin-user-update path diverges from the now-action-bound JSON `PATCH /users/{user_id}` — both still
step-up-gated (no hole), coverage only. The process-local grant caveat (restart / multi-node LB →
re-prompt, fail-safe) now applies to the /ui lanes too, unchanged from Consequences.

## Acceptance Criteria (amendment)

- **AC-6** — WHILE a /ui session is inside its login-seeded window, WHEN it POSTs a /ui factor-binding
  lane (mfa/enroll, mfa/verify, mfa/disable, webauthn/enroll, webauthn/{id}/delete), THE SYSTEM SHALL
  303 to /ui/reauth and complete only after a password (+factor) re-proof mints the matching grant.
- **AC-7** — WHEN /ui/reauth re-proves for an unlock/auto-retry continuation carrying an `action`, THE
  SYSTEM SHALL mint exactly that single-use grant; the GET unlock form and the WebAuthn verify hop
  SHALL NOT consume it.
- **AC-8** — WHERE [auth].require_action_step_up is False, THE /ui twins SHALL fall back to the session
  window (byte-identical to pre-amendment /ui behaviour).
- **AC-9** — WHEN PATCH /users/{user_id} is called inside the login window, THE SYSTEM SHALL 403 +
  X-Step-Up-Action: admin_user_update until POST /me/reauth carries that purpose (single-use).
