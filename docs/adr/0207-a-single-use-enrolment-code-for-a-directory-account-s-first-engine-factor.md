# 0207 -- A single-use enrolment code for a directory account's first engine factor

- **Status:** Proposed (2026-10-05). Drafted on the owner's direction of 2026-10-05, given in
  session to the batch 194 Manager: design this ceremony as an ADR in status Proposed. Merging this
  record files it as Proposed and accepts nothing. The Lander merges; only the owner can move it to
  Accepted. No code may follow until it is Accepted.
- **Date:** 2026-10-05
- **Related:** vault BACKLOG #2609 (its closing item 2; item 1 shipped as engine PR 1918) · vault
  BACKLOG #2711 (no host recovery when every Administrator needs an outside service) · vault BACKLOG
  #2738 item 7 (a factor enrolled before a bind) ·
  [ADR 0142](0142-federated-sso-oidc-authorization-code-pkce-relying-party-hybrid-ad-backed.md)
  Amendment C (which left this to "its own decision") and Amendment B (step-up for an OIDC session) ·
  [ADR 0184](0184-identify-a-federated-login-by-the-idp-namespaced-subject-not-by-the-username-it-claims.md)
  AC-4 (a federated login never binds) ·
  [ADR 0197](0197-cap-repeated-lock-cycles-on-one-account-without-making-malicious-lockout-cheaper.md)
  Amendment A (the generated credential a local account starts with) ·
  [ADR 0171](0171-offline-administrator-unlock-a-host-gated-cli-recovery-path-for-a-sole-administrator-lockout.md)
  (`admin-unlock` and its host gate) ·
  [ADR 0183](0183-provision-the-first-administrator-offline-no-default-account-at-first-run.md)
  (`provision-admin`) ·
  [ADR 0194](0194-refuse-to-start-a-keyless-audit-chain-at-the-store-open-seam.md) (a keyless audit
  chain) · [`docs/SECURITY.md`](../SECURITY.md) · CLAUDE.md section 0

This record names a gap in the shipped code before its fix lands. `docs/SECURITY.md` already states
the gap as a shipped limit, and ADR 0142 Amendment C states it too. Context items 6 and 7 are first
stated in this record. `docs/SECURITY.md` says only that the passkey finish route charges the
console write floor, and it has no statement of item 6. MessageFoundry has zero deployments
(CLAUDE.md section 0). Nothing below is a live exposure: each case is what a deploying site would
meet.

---

## Context

Every fact below was read at engine `origin/main` `923277d3e9` on 2026-10-05. Items 3, 6 and 7 of
the list below were re-read at `11495e53fa` the same day, after the Lander's review of this record.
Items 6 and 7 were read again at `040c03f50f`, after its second review.
Find each one by the symbol named. Line numbers are left out on purpose.

### How a directory account gets a session today

A directory account is a user row whose `auth_provider` is `ad`. AD password sign-in is retired
(`_dispatch_login`, BACKLOG #1137), so two sign-ins remain.

| Sign-in | Which accounts it serves | The session at mint |
|---|---|---|
| Windows SSO (Kerberos), `_authenticate_kerberos` | unbound accounts only, since ADR 0142 Amendment C | `mfa_verified=False`: one factor proven, none asserted |
| Federated (OIDC), through `_complete_ad_login` | bound accounts only, since ADR 0184 AC-4 | stamped verified when `[auth].oidc_require_mfa_claim` is on (the default); unverified when it is off |

So an unverified directory session comes from two places: every Kerberos sign-in, and every
federated sign-in on a site that turned the claim gate off.

### What that session can do

1. Under `[security].require_mfa` (on by default), `_unverified_session_owes_factor` floors every
   unstamped directory session. It still reaches at least the MFA-exempt routes, the enrolment
   ceremonies, and the session-termination routes that ride the reauth-only gate.
2. The enrolment ceremonies sit behind the reauth-only gate. A Kerberos session re-proves by a live
   bind with the directory password (`_reauth_ad`). An OIDC session goes back to the identity
   provider (ADR 0142 Amendment B).
3. `_factor_binding_is_blocked` refuses only an account that already holds a factor. An account
   with none passes. That carve-out is deliberate: without it, an account with no factor could
   never enrol. The step-up gates of the TOTP begin and confirm routes and of the passkey begin
   route ask it. The web console's passkey finish route, `/ui/account/webauthn/verify`, uses the
   action-less `require_ui_reauth_only`, which does not, and `finish_webauthn_registration` does not
   re-check either. That gap reaches a directory account under the shipped posture, because item 5
   lets a passkey be its first factor. A local account meets it only outside that posture.
4. `begin_mfa_enrollment` accepts a directory account on purpose (BACKLOG #1144).
   `confirm_mfa_enrollment` then stamps the session MFA-verified and rotates it.
   `finish_webauthn_registration` writes the passkey, then does the same.
5. A passkey can be a directory account's first factor even under `require_mfa`.
   `begin_webauthn_registration` raises `FactorEnrolmentRequired` only when
   `_covered_by_requirement` holds, and that reads local accounts only. So the TOTP-first rule of
   ADR 0197 Amendment A does not reach a directory account, and the passkey path is as open as the
   TOTP path.
6. **A TOTP begin is not inert, and the enable does not bind what the confirm verified.**
   `begin_mfa_enrollment` refuses an unknown account and an account whose TOTP is already on, and
   nothing else. Otherwise it writes a
   fresh secret over whatever is staged, and `set_totp_secret` does that unconditionally on all three
   store backends. `confirm_mfa_enrollment` reads the staged secret once and verifies the code
   against it. Then it stamps and rotates the session, and only then calls `enable_totp`, which turns
   TOTP on keyed by the account id alone. Nothing ties the secret that is enabled to the secret that
   was verified. So a begin from another session on the same account, landing between the read and
   the enable, decides which authenticator the account ends up holding. The session that proved the
   first code is stamped all the same. This gap is in the shared step, so it reaches every account
   type. The Lander's review of this record says it goes to the maintainer ledger as its own row.
7. **The passkey finish route draws the console write floor, but not the ceremony budget.** The
   engine API's `POST /me/mfa/confirm` and the web console's TOTP confirm route (`ui_mfa_verify`)
   both draw the per-actor ceremony budget (`allow_reauth_attempt`) before the service runs. The
   passkey finish route (`ui_webauthn_verify`) never calls it. Its gate, the action-less
   `require_ui_reauth_only`, is built on `require_ui`, which charges the console write floor
   (`allow_admin_write`) on every non-GET request. So the route "still charges the floor before its
   own checks", as `docs/SECURITY.md` says, and no single-use step-up grant bounds it. Today most
   attempts also cost a ceremony, because `finish_webauthn_registration` pops the staged challenge
   before it verifies the response. A call with an empty or over-long label is the exception: the
   method refuses it before the pop, so the challenge stays staged. Since BACKLOG #2389 a call
   inside the login-to-MFA floor is a second exception. It is refused before the pop too, and it
   verifies nothing, so it gains no information about the response.

That is the chain BACKLOG #2609 ran end to end. Someone who holds only a directory password signs
in by Windows SSO, re-proves the same password, and enrols an authenticator they control. They then
hold a full session, as Administrator if the directory maps the account there. The factor they
bound is now the account's own, so the real holder is shut out of it. On a site with the claim gate
off, the same shape works with only the identity provider's password.

### What is closed, and what is not

- **Closed by engine PR 1918 (item 1).** Windows SSO refuses a bound account, so Kerberos no
  longer goes around the identity provider's own MFA.
- **Not closed (item 2).** An unbound account still enrols its first engine factor on the directory
  credential alone. ADR 0142 Amendment C says so and leaves it to "its own decision". This ADR is
  that decision.
- **A local account has the answer under the shipped posture.** ADR 0197 Amendment A gives each
  local account a generated credential nobody can guess. An Administrator issues it and hands it
  over out of band. Where `require_mfa` covers the account, the holder must enrol a factor before
  replacing that credential. A directory account has no such credential, because the engine never
  holds its password.

What the engine lacks, then, is one thing proven to it that a password holder does not have. For a
local account that is the generated credential. For a directory account nothing plays that part.
The fix is a credential with the same three properties: the engine issues it, an Administrator
hands it over, and the holder proves it once.

## Decision

**A directory account's first engine factor is bound only with a single-use enrolment code. An
Administrator issues the code and hands it over out of band.**

### 1. What the binding step checks

The binding step is the one that writes the factor and stamps the session. When the session is not
stamped MFA-verified (its `mfa_verified_at` is null) and the account's `auth_provider` is `ad`, that
step checks two things itself:

1. **The account still holds no engine factor.** If it now holds TOTP or a passkey
   (`_second_factor_enrolled`), the step refuses: that factor must be proven first. The step asks
   this itself because the passkey finish route's gate does not (Context item 3). Without it, a
   passkey challenge staged while the account had no factor could finish after the real holder
   enrolled, with no code asked.
2. **Otherwise, a valid enrolment code** for this account.

The rule reads the account and what the session proved. It never reads `SessionMechanism`, and it
never reads `kerberos_enabled`.

| Case | What the binding step requires |
|---|---|
| Kerberos session, unbound account, no factor | A code, with `require_mfa` on or off |
| OIDC session, claim gate on | Nothing new. The identity provider asserted MFA, so the session is stamped |
| OIDC session, claim gate off | A code. The session is unstamped |
| Unstamped directory session, the account already holds a factor | A refusal. Prove the factor first |
| A local account | Nothing new. See Context, and *Out of scope* for the postures ADR 0197 leaves open |

**Why also with `require_mfa` off.** There a Kerberos session already reaches everything, so the
code does not change what the session can do. It changes who may bind the account's factor. Without
it, whoever signs in first binds a factor the real holder cannot prove. If the site later turns
`require_mfa` on, the real holder is locked out of their own account.

### 2. Where the control sits

The control sits in `AuthService`, in `confirm_mfa_enrollment` for TOTP and
`finish_webauthn_registration` for a passkey. It does not sit in a route dependency, for a reason
the code makes plain: no single route reaches both. The web console's `ui_mfa_verify` calls
`confirm_mfa_enrollment` directly, its `ui_webauthn_verify` calls `finish_webauthn_registration`
directly, and the engine API has no passkey registration route at all. So the code travels three
ways, and the service checks it on every one:

- the engine API, in the `POST /me/mfa/confirm` body;
- the web console's TOTP confirm form;
- the JSON body the web console's passkey page script sends to `/ui/account/webauthn/verify`.

The begin steps, `begin_mfa_enrollment` and `begin_webauthn_registration`, do not take or consume
the code. A begin proves nothing, but it is not inert: a TOTP begin replaces the account's staged
secret (Context item 6). So a code checked at the begin would not tie the factor that is later
enabled to the person who showed the code. The check belongs at the step that writes the factor,
and that step must also enable only the secret it verified (section 3). The begins may say early
that a code will be needed, as a courtesy, the way `must_enrol_before_rotating` does for a password
change.

### 3. The code

- **Entropy and form.** At least 128 bits from `secrets`, shown as grouped base32 so a person can
  read it aloud. Input is normalised for case, spaces and hyphens.
- **Storage.** Only its `hash_token` digest (SHA-256) is stored, as for a session token. A slow
  hash buys nothing on a code nobody can guess. Recovery codes use Argon2 because they are short.
- **One per account.** Two nullable columns on the `users` row hold the digest and the expiry.
  Issuing a new code replaces an outstanding one, so no new table is needed.
- **Lifetime.** 24 hours from issue, fixed rather than a setting. See *To resolve on acceptance*.
- **Bound to its account.** The check reads the digest on the session's own user row, so a code
  proves nothing for any other account.
- **Single use, spent atomically.** One conditional write clears the digest only where it still
  matches and has not expired. Only a write that changed a row counts, so two racing ceremonies
  cannot both spend one code.
- **The order in `confirm_mfa_enrollment`.** First read the code: present, well formed, and
  matching the account's digest and expiry. A missing or wrong code is refused here, before the TOTP
  step is consumed, so the holder does not lose that step. Then verify and consume the TOTP step.
  Then spend the code. Then stamp and rotate the session, then enable TOTP.
- **The enable turns on only the secret that was verified.** Today it turns on whatever the column
  holds at that later moment (Context item 6). The build binds the two: the enable writes the secret
  this call verified, in the same statement that turns TOTP on, and only where TOTP is still off.
  A compare-and-set is an acceptable equal: enable only where the staged secret still matches the
  one this call read, and otherwise fail closed with TOTP off. Either way a begin that lands
  mid-ceremony can make a pending confirm fail, but it can no longer change which authenticator is
  enabled. This rule binds the shared step, so it holds for local accounts too, code or no code.
- **A confirm whose enable did not take effect ends its session.** The order above stamps and
  rotates the session before the enable. So when the enable changes no row, or fails, the rotated
  session is already factor-satisfied on an account that holds no factor. The confirm then ends
  that session and returns no token, as it returns `session_lost` today for a session revoked
  mid-ceremony. It never hands the rotated token back for a retry, and it writes no enrolment row.
  The holder signs in again and starts over.
- **The order in `finish_webauthn_registration`.** This method writes the credential
  (`add_webauthn_credential`) before it stamps. So the code is spent before that write, not merely
  before the stamp. A check placed only before the stamp would leave the attacker's passkey bound.
  The label and duplicate checks run before the spend, so a refusal they cause does not cost the
  code.
- **Where the code check sits against the challenge pop.** The factor check of section 1 and the
  code read (present, well formed, matching, not expired) run before the method pops the staged
  challenge. So a refused code costs neither the code nor the ceremony, as on the TOTP path. The
  spend runs after the response verifies and after the duplicate check, and before the credential
  is written. Because a refused code leaves the challenge staged, three things bound repeated tries
  against one ceremony: the console write floor, the challenge's 120 second life
  (`CHALLENGE_TTL_SECONDS`), and the ceremony budget section 7 adds. Both budgets can be switched
  off. The ceremony budget holds only while `[auth].login_rate_limit_enabled` is on: with it off,
  `allow_reauth_attempt` always proceeds. The challenge's life holds in every posture.
- **One reply for every refused code.** A missing, never-issued, wrong, expired or spent code gets
  the same client-facing reply: one status and one message. The audit row keeps that rule too,
  because the account's own security-event feed returns it (section 7). So a caller learns nothing,
  from the reply or from that feed, about whether a code is outstanding. A `factor_present` refusal
  may say "prove your factor first", since the account's MFA status already tells the session that.
- **Disabling the account clears an outstanding code.** `set_user_disabled` clears the digest and
  the expiry in the same statement that disables, so every caller clears it. Re-enabling the account
  inside 24 hours therefore revives nothing. The spend also refuses a disabled account on its own.
- **A failure after the spend costs the code.** A session revoked mid-ceremony (BACKLOG #1902), an
  `enable_totp` that fails after a good rotation, or a compare-and-set enable that finds the staged
  secret changed, leaves TOTP off and the code spent. Today a plain retry recovers from the first
  two; with this ADR the holder needs a new code. On the passkey path the
  credential is already written, so the factor is enrolled and the holder proves it at the next
  sign-in. Both fail closed, and both are stated so nobody mistakes them for defects.
- **Never in plaintext at rest, never in a log, never in a URL.** Each reply that carries it sends
  `Cache-Control: no-store` because its response model subclasses `CredentialReply`, as the MFA
  reset reply already does. (Until BACKLOG #2372 this read "through `_no_store_reply`", the
  per-route dependency that change retired.)

### 4. Who issues it, and how it reaches the holder

- **An Administrator, from either plane.** A new route, `POST /users/{user_id}/enrolment-code`, sits
  behind `require_step_up_action` with a new action constant and `Permission.USERS_MANAGE`. Only
  the Administrator role holds that permission: a custom role may not grant it
  (`CUSTOM_ROLE_FORBIDDEN_PERMISSIONS`, ADR 0045 D1). So the issuing Administrator is MFA-satisfied
  and has just re-proved. The web console gets a button on the user page and a page that shows the
  code once.
- **Never for the caller's own account.** The route refuses self-targeting, as `reset-mfa` and the
  federated-identity routes do. A directory Administrator with no factor therefore cannot issue one
  for itself. Section 6 covers that case.
- **Refused for** a local account, an account that already holds an engine factor ("reset its MFA
  first"), a disabled account, and an unknown account.
- **Its write is one conditional statement, like the host command's.** It sets the digest only where
  the account is `ad`, enabled, and holds no factor. An issue whose write changes no row is refused,
  and nothing is shown. So a disable, or a factor, that lands between the route's checks and its
  write leaves no code on the account.
- **Revocable.** `DELETE` on the same path clears an outstanding code, for a handover that went
  wrong. It sits behind the same gate, with its own step-up action constant.
- **Shown once.** The reply carries the code and its expiry. The engine keeps only the digest.
- **The engine never sends the code.** An Administrator hands it over.
- **The handover is the control, so it must not run through the directory.** The code is worth
  what the handover checks, and no more. An Administrator must confirm who is asking by something the
  directory password does not give: in person, a call-back to a number on file, or the site's own
  identity check. The code must not go back through the account's own mail or chat, because the same
  password opens them. That is the ground on which alternative 3 fails, and it applies to a person
  replying by mail just as it does to the engine. The engine cannot enforce this. So
  `docs/SECURITY.md` states it as the operator's duty, and the pending-MFA page tells a directory
  user to contact an Administrator through the site's identity check. It does not invite a request
  from whoever holds the session.
- **A notice, as a courtesy and not a control.** Issuing may send the account's `notify_email` a
  notice that a code was issued, naming no code. Nothing rests on it. A new directory account often
  has no address yet, and where one is set it may be a mailbox the same password opens.

### 5. An MFA reset on an enabled directory account issues a code

`admin_reset_mfa` removes every factor and ends every session. On a local account it also issues a
generated credential, returned once (ADR 0197 Amendment A, AC-A4). After a reset, a directory
account needs a code to enrol again. So the reset of an enabled directory account issues one, and
`MfaResetResponse` returns it once. Otherwise the reset leaves the Administrator a second step that
is easy to forget. The reset of a disabled account issues none, because the route would refuse one.

### 6. The first directory Administrator gets a code from a host command

A site can reach a state where nobody can issue a code: every enabled Administrator is a directory
account, and none holds an engine factor. Under `require_mfa`, none of them gets past the floor in
Context item 1, so none can call the issuing route.

**`messagefoundry issue-enrolment-code --username <name> [--json]`** covers that case.

- **It runs on the engine host, behind the guards `admin-unlock` uses.** That is
  `_host_gated_store_settings` for the settings and the missing-store refusal, the keyless-chain
  refusal at `open_store` (`keyless_opt_out_refusal`), and `_refuse_an_unauditable_write` before the
  write (ADR 0194). ADR 0171 states why host access is a real gate: whoever holds the service
  config, the store and its key already holds the database.
- **Its write is one conditional statement.** It sets the digest only where the account is `ad`,
  enabled, and holds no factor. So it has no read-then-write window for a live engine to slip into.
- **Whether it may run beside a live engine is not settled here.** That turns on whether a second
  process may append to the audit chain safely. Until the build shows it can, the command follows
  `admin-unlock`'s rule and runs with the engine stopped. That rule is documented in `admin-unlock`,
  not enforced by it.
- It prints the code once and writes the same audit row as the route. The actor names the OS user.
- It applies the route's refusals except self-targeting, which has no meaning at a terminal.
- It issues for any directory account, not only an Administrator. Host access already grants
  everything, so narrowing it would add a rule with no security gain.

**How this relates to BACKLOG #2711.** The two share a gate and a shape, but they solve different
problems. This command is not #2711's answer.

- #2711 is recovery **during an outage** of the directory or the identity provider. A code does not
  help there: using one needs a session, and a Kerberos session needs the directory.
- This command changes no rule of ADR 0183. `provision-admin` still refuses while any enabled
  Administrator exists, and #2711's step 1 still owes its own decision on that.
- The documented advice stands: keep a local Administrator (`docs/SECURITY.md`, "Keep a local
  Administrator"). A site that does so issues codes from that account and never needs this command.

### 7. Audit

| Audit action | Written when | Actor | Detail it carries (never the code or its digest) |
|---|---|---|---|
| `auth.enrolment_code_issued` | the route, the console, an MFA reset, or the host command issued one | the issuing Administrator, or the OS user for the host command | the target account, the expiry, `via` (`api`, `ui`, `reset` or `host`), whether it replaced a code, whether the account is bound |
| `auth.enrolment_code_revoked` | an Administrator cleared one | the Administrator | the target account |
| `auth.enrolment_code_used` | a ceremony spent one | the account that enrolled | `ceremony`: `totp` or `webauthn` |
| `auth.enrolment_code_refused` | a binding step refused | the account whose session tried | `reason`: `not_presented` (the request carried no code), `code_refused` (a code was sent and refused: never issued, wrong, expired or already spent), or `factor_present` (the account gained a factor; prove it first) |

**Who reads these rows.** Every audit row stays with `Permission.AUDIT_READ`, as today. All four
actions also start `auth.`, so `GET /me/security-events` returns each to the account named as its
actor, with its detail (`security_events_for_user` selects by actor). So the issued and revoked rows
reach the Administrator who wrote them, and never the target. The used and refused rows reach the
account itself, so its real holder sees every refused try on it.

**The one-reply rule holds in that feed too.** The feed sits behind the MFA gate, but on a site with
`require_mfa` off an unstamped session reaches it. So the refused row's detail does not tell the
refused-code cases apart: one `code_refused` reason covers all four. `not_presented` tells the caller
only what its own request held. An Administrator who needs the finer case reads it from the issued,
used and revoked rows and the expiry they carry.

The engine API's confirm route and the web console's TOTP confirm route already draw the per-actor
ceremony budget (`allow_reauth_attempt`) on every attempt, before the service runs. The passkey
finish route draws only the console write floor (Context item 7). **The build adds the
ceremony-budget draw to `ui_webauthn_verify`, before the service runs**, refusing over budget as
`ui_mfa_verify` does. A code nobody can guess needs no guess limit, so the budget is not there for
the code's sake. Today the write floor and the challenge's 120 second life already bound the tries
against one ceremony. What the ceremony budget adds is the bound every other credential ceremony
already has. A refused code now leaves the challenge staged (section 3), so the tries against one
ceremony, and the `auth.enrolment_code_refused` rows they write, then count against the same
per-actor budget as the TOTP confirm and the step-up. A site that loosens the write floor for its
console writes does not loosen this one. The budget holds only while
`[auth].login_rate_limit_enabled` is on. With it off, `allow_reauth_attempt` always proceeds, and
the write floor and the challenge's life are the bounds left. The service adds no counter of its
own. The existing `MFA_ENABLED` notice still fires on success.

### 8. The lockout this makes deliberate

Under `require_mfa`, a directory operator's first session stays behind the floor in Context item 1
until an Administrator issues a code. `_authenticate_kerberos` warns of exactly this: minting at the
minimum is "only safe CO-LANDED with" directory enrolment. This ADR keeps directory enrolment and
puts a code in front of it, so that lockout becomes an onboarding step. The build must say so where
a person meets it, on the pending-MFA page, worded as section 4's handover rule requires. That
comment in `_authenticate_kerberos` changes in the same build.

### What it must not break

- Local accounts: their generated credential, and ADR 0197 Amendment A's enrol-before-rotate order.
- An account that already holds a factor. It proves that factor, as today, and never needs a code.
- A federated sign-in with the claim gate on. It never needs a code.
- `admin_reset_mfa` as the always-available recovery for a lost authenticator.

## Acceptance Criteria

The tests named below are written with the build; none exists yet.

- **AC-1** -- WHEN a Kerberos session on an unbound directory account with no engine factor
  re-proves its directory password and confirms a TOTP enrolment without a code, THE SYSTEM SHALL
  refuse the confirmation, leave TOTP off, and leave the session unstamped. This is #2609's chain,
  and the test must fail on the code before this build.
  → `tests/test_directory_enrolment_code.py`
- **AC-2** -- WHEN the same session presents a valid code for its own account, THE SYSTEM SHALL
  enable TOTP, stamp the session, spend the code, and write `auth.enrolment_code_used`.
  → `tests/test_directory_enrolment_code.py`
- **AC-3** -- IF the code is not presented, wrong, expired, already spent, or issued for another
  account, THEN THE SYSTEM SHALL refuse the binding step before consuming the TOTP step or popping
  the passkey challenge, answer with one client-facing reply whatever the reason, and write
  `auth.enrolment_code_refused` with the reason section 7 names for that case. The refused row SHALL
  carry the one `code_refused` reason for a wrong, expired, spent or never-issued code, so the
  account's own security-event feed does not tell those cases apart either.
  → `tests/test_directory_enrolment_code.py`
- **AC-4** -- THE SYSTEM SHALL apply AC-1 to AC-3 to a passkey: `finish_webauthn_registration`
  SHALL spend the code before it writes the credential, and a refused code SHALL leave no credential
  row. The TOTP arm SHALL hold on the engine API and the web console; the passkey arm on the web
  console, which is the only plane that registers one.
  → `tests/test_directory_enrolment_code.py`, and a web console test under
  `packaging/messagefoundry-webconsole/tests/`
- **AC-5** -- IF a passkey challenge staged while the account had no factor finishes after the
  account gained one, THEN THE SYSTEM SHALL refuse it with `factor_present`, bind nothing, and stamp
  nothing.
  → `tests/test_directory_enrolment_code.py`
- **AC-6** -- WHEN `oidc_require_mfa_claim` is off, THE SYSTEM SHALL require a code for a federated
  session's first factor; WHEN it is on, THE SYSTEM SHALL NOT.
  → `tests/test_directory_enrolment_code.py`
- **AC-7** -- THE SYSTEM SHALL require the code whether `[security].require_mfa` is on or off, and
  whether `[auth].kerberos_enabled` is on or off.
  → `tests/test_directory_enrolment_code.py`
- **AC-8** -- WHEN an Administrator issues a code, THE SYSTEM SHALL return it once with `no-store`,
  store only its digest, and notify the target's `notify_email` without the code where one is set.
  IF the target is the caller, a local account, an account holding a factor, a disabled account, or
  unknown, THEN THE SYSTEM SHALL refuse.
  → `tests/test_directory_enrolment_code.py`
- **AC-9** -- WHEN an Administrator revokes an outstanding code, THE SYSTEM SHALL require the same
  step-up and permission as issuing, clear the digest, and write `auth.enrolment_code_revoked`.
  → `tests/test_directory_enrolment_code.py`
- **AC-10** -- WHEN two ceremonies present one code at once, THE SYSTEM SHALL let exactly one spend
  it, on every store backend.
  → `tests/test_directory_enrolment_code.py`, with the SQL Server and Postgres legs
- **AC-11** -- WHEN `issue-enrolment-code` runs on the host gate, THE SYSTEM SHALL print the code
  once, audit it naming the OS user, refuse a store that does not exist rather than create one, and
  refuse a store whose audit append would be refused.
  → `tests/test_directory_enrolment_code.py`
- **AC-12** -- WHEN an Administrator resets an enabled directory account's MFA, THE SYSTEM SHALL
  issue a code and return it once in the reset reply; for a disabled account it SHALL issue none.
  → `tests/test_directory_enrolment_code.py`
- **AC-13** -- IF a TOTP begin from another session replaces the staged secret after
  `confirm_mfa_enrollment` read the secret and verified a code against it, THEN THE SYSTEM SHALL
  NOT enable the replacing secret. It SHALL enable the verified secret, or leave TOTP off. IF the
  enable does not take effect after the session was stamped and rotated, THEN THE SYSTEM SHALL end
  that session and return no token, so no factor-satisfied session is left on an account with no
  factor. This holds for a local account and a directory account alike, and the test must fail on
  the code before this build.
  → `tests/test_directory_enrolment_code.py`
- **AC-14** -- WHEN the web console's passkey finish route is called with the per-actor ceremony
  budget (`allow_reauth_attempt`) refused and the console write floor not exhausted, THE SYSTEM
  SHALL refuse the attempt before the service runs, as the TOTP confirm route does, and write no
  credential row. The test must fail on the code before this build. A test that drives the route
  past the write floor instead passes on today's code, so it does not meet this criterion. The
  discriminating form already exists in `test_l4b_rate_limit_paths`
  (`packaging/messagefoundry-webconsole/tests/test_webui.py`): it re-proves first, then replaces
  `service.allow_reauth_attempt` with a deny and leaves the write floor alone.
  → a web console test under `packaging/messagefoundry-webconsole/tests/`
- **AC-15** -- WHEN an account holding an outstanding code is disabled, THE SYSTEM SHALL clear the
  code. IF the account is re-enabled before that code would have expired, THEN THE SYSTEM SHALL
  refuse the old code. IF a disable lands between an issue's checks and its write, THEN THE SYSTEM
  SHALL refuse the issue and leave no code on the account.
  → `tests/test_directory_enrolment_code.py`

## Alternatives considered

1. **Password only, as today.** The first factor is bound on the directory credential alone. This is
   the shipped limit ADR 0142 Amendment C records. Rejected: it is the #2609 chain. The only proof is
   the password, and the password holder is the attacker this guards against.
2. **A TOTP-on-directory-password shortcut.** Keep enrolment on the directory password re-proof, and
   tighten it: a short window after first sign-in, one enrolment only, a notice to the holder.
   Rejected: every variant still proves only what the attacker holds, so it stays first-come. A
   window changes when the race runs, not who can win it. A notice is detection after the fact, and
   only where a notifier and an address exist.
3. **An emailed enrolment link.** The engine mails a one-time link to `notify_email`. Rejected on
   four grounds. A directory user's mailbox often sits behind the same directory password, so it
   proves nothing new. It needs a working notifier, which is optional. It puts a secret in a URL. And
   it trains people to follow sign-in links in mail, which is how phishing works.
4. **The Administrator-issued single-use code.** **CHOSEN.** It adds one thing the password holder
   does not have, checked by a person who already holds the power to grant roles. It mirrors the
   generated credential a local account already gets. Its strength rests on the handover in
   section 4, and this ADR says so rather than hiding it.
5. **Gate on `SessionMechanism.KERBEROS`, or on `kerberos_enabled`.** Rejected: both miss the
   federated session with the claim gate off. They also make a settings flag the control, when the
   condition is about the account.
6. **A short code, hashed with Argon2.** Easier to read aloud. Rejected: a guessable code needs a
   guess limit, and ADR 0197 shows a guess limit others can trip is a lockout anyone can cause. A
   code nobody can guess needs no limit.
7. **Take the code at the begin step, or in a route gate.** Rejected as the control. A begin proves
   nothing, and a later begin replaces the staged TOTP secret (Context item 6), so a code shown at
   the begin would not tie the enabled factor to its bearer. No single route reaches both binding
   steps either (section 2). The begin step may still warn early.
8. **The Administrator enrols the factor for the holder.** Rejected: the Administrator would then
   see the holder's TOTP secret, so two people would hold one person's factor.
9. **Let an Administrator issue a code for its own account.** Rejected: an Administrator with no
   factor would bind its own first factor on its own say. The host command covers the case where no
   other Administrator exists.
10. **Refuse `kerberos_enabled` together with `oidc_enabled` at load.** Rejected, as #2609 already
    found: too blunt, and it does not help a Kerberos-only site.

## Consequences

**Positive.** A directory password alone no longer binds an engine factor. The rule covers Kerberos
and the claim-off federated case with one condition. Directory and local accounts now follow the
same pattern: an Administrator-issued secret stands in front of the first factor.

**Negative.**

- The control's strength rests on a human step the engine cannot check: the Administrator's
  identity check at handover.
- Every directory operator needs an Administrator before their first real session, under the default
  `require_mfa`. That is new onboarding work for each person.
- A site with no local Administrator needs the host command once, with the engine stopped until a
  build shows it need not be.
- A code lost mid-ceremony, or after a failure past the spend, means asking for a new one.

**What the build costs.** The filed difficulty, 3/10, covered both items, and the cheap one has
shipped. What remains is a new authentication ceremony: realistically **6/10**, about the size of
ADR 0197 Amendment A's wave 1. It changes a security control, so it gets its own pull request
(CLAUDE.md section 5). It touches at least:

- **the store:** two nullable `users` columns, and issue, spend and clear methods, on all three
  backends (`store/store.py`, `store/sqlserver.py`, `store/postgres.py`) and the `Store` protocol,
  with their migrations, which `messagefoundry store provision-schema` applies on a server store
  (ADR 0192); an `enable_totp` that binds the verified secret, and a `set_user_disabled` that clears
  an outstanding code, on all three;
- **the auth service:** issue, revoke and spend; both checks in both binding steps; the MFA reset;
  two new step-up actions; four audit actions; one notice kind;
- **the engine API:** the issue and revoke routes, a code field on `POST /me/mfa/confirm`, the reset
  reply, and the MFA status reply saying a code is needed;
- **the web console:** the issue button and one-time page, a code field on the TOTP confirm form and
  in the passkey page script's body, the ceremony budget on the passkey finish route, and the
  pending-MFA notice;
- **the CLI:** `issue-enrolment-code`, and its row in the CLI tier list;
- **documents:** the Kerberos row of the pathway table, the "Limit: an account with no binding is
  unchanged" bullet, and the handover duty, all in `docs/SECURITY.md`, whose pathway rows
  `tests/test_docs_security_pathways.py` checks;
- **tests:** the criteria above, including the SQL Server and Postgres legs, which run only on hosted
  runners.

**Out of scope.**

- Local accounts under a non-default posture: `require_mfa` off, or `require_mfa_scope =
  "administrators"` for a non-Administrator. There the holder may replace the generated credential
  before enrolling, and the first factor is then first-come on a chosen password. ADR 0197
  Amendment A's acceptance left those postures as its residual 1. This ADR does not reach them, so
  directory accounts get a code in a posture where local accounts get none. Extending the code to
  them is a separate decision.
- The passkey finish route's gate not asking `_factor_binding_is_blocked`, for local accounts.
  That gap reaches a directory account under the shipped posture (Context item 3), and section 1
  closes it there by the step's own check. A local account meets it only outside the shipped
  posture, and that case is not decided here.
- Vault BACKLOG #2738 item 7: a bind clears no factor, so a factor enrolled first-come on Kerberos
  proof before or during a bind survives the bind. It has the same root, but closing it is a
  separate decision. With zero deployments, no such factor exists today.
- BACKLOG #2711's step 1, the recovery shape during an outage.
- Whether a Windows acceptor's `DOMAIN\user` name form stops Kerberos sign-in on a Windows host. A
  run against a real domain decides that, as #2609 records.

## To resolve on acceptance

- [ ] Require the code with `[security].require_mfa` off as well. Recommended yes, for the reason in
  Decision section 1.
- [ ] Keep the lifetime fixed at 24 hours. The alternative is an `[auth]` setting, as
  `initial_password_expiry_hours` is for a local credential. Recommended fixed, since the code exists
  for one handover.
- [ ] Have an MFA reset of an enabled directory account issue a code in the same reply. Recommended
  yes.
- [ ] Let the host command issue for any directory account, not only an Administrator. Recommended
  yes.
