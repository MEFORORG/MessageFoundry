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
