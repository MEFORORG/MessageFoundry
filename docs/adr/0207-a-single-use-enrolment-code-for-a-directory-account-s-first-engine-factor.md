# 0207 -- A single-use enrolment code for a directory account's first engine factor

- **Status:** Accepted (2026-10-27), with Amendment A. Accepted by the batch 447 Manager under the
  Owner's delegation of 2026-10-27 (CLAUDE.md section 5, "A delegated decision counts as that
  ruling", owner ruling 2026-10-22), after two adversarial reviews; Amendment A records the
  question, the answer and both reviews. Two repair rounds after both reviews (`2a6f30037`,
  `83d038b7c`, branch commits the pull request names) changed design text, and a third
  adversarial read at `83d038b7c` covered those commits and returned *keep accepted after named
  small fixes*, which the commit after it applies. Amendment A records that read too, and says
  which text of that last commit no adversarial read has seen. The text below says only the owner can move this record to
  Accepted: that delegation record is the owner's ruling under CLAUDE.md section 5, so the
  acceptance rests on it. Three *To resolve on acceptance* items stay open, each with its
  recommendation; the build follows the recommendation unless the owner rules otherwise.
  Previously Proposed (2026-10-05): drafted on the owner's direction of 2026-10-05, given in
  session to the batch 194 Manager: design this ceremony as an ADR in status Proposed. Merging this
  record filed it as Proposed and accepted nothing. The Lander merges; only the owner can move it to
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
   provider (ADR 0142 Amendment B). *Amendment A, A1, says what holds once owner ruling A5 removes
   that bind.*
3. `_factor_binding_is_blocked` refuses only an account that already holds a factor. An account
   with none passes. That carve-out is deliberate: without it, an account with no factor could
   never enrol. The step-up gates of the TOTP begin and confirm routes and of the passkey begin
   route ask it. The web console's passkey finish route, `/ui/account/webauthn/verify`, uses the
   action-less `require_ui_reauth_only`, which does not, and `finish_webauthn_registration` does not
   re-check either. That gap reaches a directory account under the shipped posture, because item 5
   lets a passkey be its first factor. A local account meets it only outside that posture.
   *Closed at the binding step since this was drafted (BACKLOG #3014, #3061); see Amendment A, A2.*
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

   *Note (2026-10-16).* The shared-step fix was built under BACKLOG #3025 (first pushed as branch `b259-3025`):
   `enable_totp` turns TOTP on only while the row still holds the secret cell the confirm
   verified, and `set_totp_secret` writes only where TOTP is off. This item describes the code as
   it stood when this record was drafted.
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
   *Closed since this was drafted (BACKLOG #3014); see Amendment A, A2.*

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
   *Note (2026-10-29, BACKLOG #3690 item 3).* This check is shipped on the passkey path, for every
   account type: `finish_webauthn_registration` asks it twice, and the store asks it a third time
   inside the credential insert's own transaction (BACKLOG #3014, #3061, #3690 item 1). The build
   adds no factor check of its own; Amendment A, A2, says what it adds.
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
- **Single use, spent atomically.** One conditional sealed write, through `_write_user` (Amendment
  A, *What this amendment changes in the build's cost*), clears the digest only where it still
  matches and has not expired. Only a write that changed a row counts, so two racing ceremonies
  cannot both spend one code.
- **The order in `confirm_mfa_enrollment`.** First read the code: present, well formed, and
  matching the account's digest and expiry. A missing or wrong code is refused here, before the TOTP
  step is consumed, so the holder does not lose that step. Then verify and consume the TOTP step.
  Then spend the code. Then stamp and rotate the session, then enable TOTP. *Amended by A3: the
  code is read after the directory lookup, and spent in the enable's own write.*
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
  code. *Amended by A3: that needs a new label read before the spend, step 9.*
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
  sign-in. Both fail closed, and both are stated so nobody mistakes them for defects. *Amended
  by A3: on the TOTP path a failure at or before the enable now costs no code.*
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
- **Its write is one conditional sealed write through `_write_user`, like the host command's.** It
  sets the digest only where
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
- **Its write is one conditional sealed write through `_write_user`.** It sets the digest only
  where the account is `ad`, enabled, and holds no factor. `_write_user` reads the record, applies
  the change to what it read, and writes with a compare on the seal it read, so the conditions are
  judged on the record the write replaces. On a store with no row sealer that seal is empty and the
  compare guards nothing across processes, which is one reason the next item keeps the engine
  stopped.
- **Whether it may run beside a live engine is not settled here.** That turns on whether a second
  process may append to the audit chain safely. Until the build shows it can, the command follows
  `admin-unlock`'s rule and runs with the engine stopped. That rule is documented in `admin-unlock`,
  not enforced by it. *Amendment A, A4, makes the command enforce it.*
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
  *(Amended 2026-10-16: step 1 is decided, by owner ruling B258-R4. `provision-admin` now refuses
  only while an enabled local Administrator has a usable password; see ADR 0183 Amendment E. This
  command is still not #2711's answer.)*
- The documented advice stands: keep a local Administrator (`docs/SECURITY.md`, "Keep a local
  Administrator"). A site that does so issues codes from that account and never needs this command.

### 7. Audit

| Audit action | Written when | Actor | Detail it carries (never the code or its digest) |
|---|---|---|---|
| `auth.enrolment_code_issued` | the route, the console, an MFA reset, or the host command issued one | the issuing Administrator, or the OS user for the host command | the target account, the expiry, `via` (`api`, `ui`, `reset` or `host`), whether it replaced a code, whether the account is bound |
| `auth.enrolment_code_revoked` | an Administrator cleared one | the Administrator | the target account |
| `auth.enrolment_code_used` | a ceremony spent one | the account that enrolled | `ceremony`: `totp` or `webauthn` |
| `auth.enrolment_code_refused` | a binding step refused | the account whose session tried | `reason`: `not_presented` (the request carried no code), `code_refused` (a code was sent and refused: never issued, wrong, expired or already spent), or `factor_present` (the account gained a factor; prove it first) |
| `auth.enrolment_code_spent_notice` | a ceremony spent a code an Administrator issued (Amendment A, A5) | the issuing Administrator, as the row's **recipient**: the issuer did not act | `actor_role`: `recipient`, which marks the actor column as the notice's recipient and not the account that acted; the account that spent the code; `ceremony`: `totp` or `webauthn`; the client address the spend came from |

**Who reads these rows.** Every audit row stays with `Permission.AUDIT_READ`, as today. All four
actions (five with Amendment A's spent notice) also start `auth.`, so `GET /me/security-events` returns each to the account named as its
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
`ui_mfa_verify` does (*shipped since, BACKLOG #3014; Amendment A, A2*). A code nobody can guess needs no guess limit, so the budget is not there for
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

The tests named below are written with the build; none exists yet. *Amendment A restates AC-5,
AC-13 and AC-14 as regression pins on tests that already exist, scopes AC-3 to a code refused at
the code read (A3), and adds AC-16 to AC-19.*

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
  account's own security-event feed does not tell those cases apart either. *(Amendment A, A3: this
  holds for a code refused at the code read. A code that passed the read and is revoked, expires or
  is spent before the spend is the race A3 names, refused after the consume or the pop.)*
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
  (`packaging/messagefoundry-webconsole/tests/test_webui_account.py`): it re-proves first, then replaces
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
  *Closed since this was drafted (BACKLOG #3014): the finish's own check reaches a local account
  too, so this bullet no longer names open work; see Amendment A, A2.*
- Vault BACKLOG #2738 item 7: a bind clears no factor, so a factor enrolled first-come on Kerberos
  proof before or during a bind survives the bind. It has the same root, but closing it is a
  separate decision. With zero deployments, no such factor exists today.
- BACKLOG #2711's step 1, the recovery shape during an outage.
- Whether a Windows acceptor's `DOMAIN\user` name form stops Kerberos sign-in on a Windows host. A
  run against a real domain decides that, as #2609 records.

## To resolve on acceptance

- [x] Require the code with `[security].require_mfa` off as well. **Answered yes (Amendment A,
  2026-10-27).** Beyond the reason in Decision section 1: once owner ruling A5 removes the
  directory re-bind, Amendment A1 makes the code the only proof at the binding step. A *no* would
  either leave a bind on a stolen session token alone for a `require_mfa`-off site, or keep the
  re-bind for such sites. Ruling A5 left that posture to this ADR (A1), and keeping the re-bind
  there would keep the engine collecting the directory password, the one proof this ADR's attacker
  already holds, which is what A5 chose to end.
- [ ] Keep the lifetime fixed at 24 hours. The alternative is an `[auth]` setting, as
  `initial_password_expiry_hours` is for a local credential. Recommended fixed, since the code exists
  for one handover.
- [ ] Have an MFA reset of an enabled directory account issue a code in the same reply. Recommended
  yes.
- [ ] Let the host command issue for any directory account, not only an Administrator. Recommended
  yes.

## Amendment A (2026-10-27) -- the re-proof once the directory re-bind goes, a re-baseline, and an enforced engine-stopped rule

**Decided by the batch 447 Manager under the Owner's delegation of 2026-10-27** (CLAUDE.md section
5, "A delegated decision counts as that ruling", owner ruling 2026-10-22). The Manager asked the
owner, in its own chat by `AskUserQuestion` on 2026-10-27 at about 13:35 UTC, this question,
quoted verbatim:

> "ADR 0207 review result: ACCEPT WITH NAMED AMENDMENTS (reviewer confidence medium-high). The core
> design held up: a 128-bit, single-use code bound to one account, spent atomically, issued by an
> Administrator with step-up. The reviewer found no way to replay it, guess it, or use it on another
> account. Four amendments: (1) say what a factorless Kerberos session must re-prove after ruling A5
> removes the directory re-bind. If this stays open, a Builder could simply drop the gate. That is
> the one unsafe-build gap. (2) Re-baseline to today's tree: BACKLOG #3025 and #3014 already shipped
> parts of it, so three acceptance tests can no longer 'fail before the build'. (3) Fix the order of
> checks against the newer _directory_vouches_for_factor lookup. (4) Enforce, rather than only
> document, that the host command runs with the engine stopped, so the audit chain can't fork.
> Optional: also notify the issuing Administrator when a code is used, and shorten the 24h
> lifetime. How do you want to proceed?"

The options offered were "Amend, then I accept (Recommended)", "Accept as written now" and "Not
now". The owner answered *"/driver"*, which delegated that question to the Manager. The review the
delegation requires is two adversarial reviews: the first, of the record as proposed, returned
*accept with named amendments*; the second, of this amendment at `1d119a284`, returned *accept
after named small fixes* (its fixes F1 to F4, applied below) and affirmed A4's SQLite-only refusal
after verifying in code that all three backends serialize the audit append. The Manager took the
recommended option, reading its "I accept" as the delegate's once the question was delegated.
The Builder's two code-review rounds after the acceptance commit changed design text too (at least
the TOTP fold's no-passkey condition, the non-database refusal, the sealed columns, and where the
begin routes' budget draw is built). Those two repair rounds, `2a6f30037` and `83d038b7c`, came
after both adversarial reviews, so a third adversarial read at `83d038b7c` covered them. It
returned *keep accepted after named small fixes*: record that read in the Status line and here,
name how the new columns survive the users-row seal, name the code's writes as conditional sealed
writes through `_write_user`, and list the spent notice among the audit rows docs/PHI.md says
store a client address. The commit after
`83d038b7c` applies them. The third read asked for the seal mechanism to be named, not for a
mechanism it had approved, so the mechanism that commit names (each new column sealed only when
non-null), the issuer capture in A5, and the qualifications it adds to the seal and the host
command's write are design text no adversarial read has seen; the pull request names that commit.
The original acceptance's decision log id is
`d20261027T133727170-18c43f`. This amendment changes the design the record proposes, and the
record was accepted with it on 2026-10-27, under the same delegation (see Status).

Every fact below was read at engine `origin/main` `93f6438c7` on 2026-10-27, by symbol. Where this
amendment and an earlier section disagree, this amendment wins.

### A1. What the reauth-only gate asks of a factorless directory session once the re-bind goes

**The premise moved.** Context item 2 says a Kerberos session re-proves by a live bind with the
directory password (`_reauth_ad`, reached from `_reproof_serialized`). Owner ruling A5 of 2026-10-08
(vault, *OWNER-RULINGS-2026-10-08-BATCH207*, entry A5, row #1137) says a Kerberos session may step up
with its engine factor instead, and that the directory-password re-bind is removed once this ADR is
decided. A5's own record lists, among what it does not decide, this ADR and the case of a
`[security].require_mfa = false` directory session with no factor to challenge; A1 is this record's answer to
that case. That removal is its own build row, sequenced behind this ADR. After it, an unstamped
directory session on an account with no engine factor, whose step-up is not at the identity
provider, has nothing to re-prove with. Today that is every Kerberos session on an unbound account
with no factor. So this record must say what the reauth-only gates ask of it.

**The decided answer: at the binding step the enrolment code is the re-proof, the enrolment
begins and the console's TOTP confirm form are admitted with no step-up grant, and every other
step-up action stays refused until a factor exists.** Route by route, for that session:

| Route | Gate today | What it asks once the re-bind is gone |
|---|---|---|
| The TOTP begins (`POST /me/mfa/enroll`, `STEP_UP_ACTION_MFA_ENROLL`, and `POST /ui/account/mfa/enroll`) and the console's passkey begin | a password re-proof | Admitted with no step-up grant. A begin binds nothing (section 2). **New: it draws the per-actor ceremony budget**, which no begin route draws today, and may say early that a code will be needed |
| The console's TOTP confirm form, `GET /ui/account/mfa/confirm` | the action-less `require_ui_reauth_only` | Admitted with no step-up window, so the form the binding step re-enters is not a dead end |
| The binding steps: `POST /me/mfa/confirm` (`STEP_UP_ACTION_MFA_CONFIRM`), `ui_mfa_verify`, and `ui_webauthn_verify` | a password re-proof, or the action-less `require_ui_reauth_only` | Admitted with no step-up grant. The service demands a valid code (section 1), and that code is the re-proof. The per-actor ceremony budget is still drawn |
| Session termination, `STEP_UP_ACTION_SESSION_TERMINATE`: `DELETE /me/sessions`, `DELETE /me/sessions/{session_id}`, `POST /ui/account/sessions/{session_id}/revoke` and `POST /ui/account/sessions/revoke-others` | a password re-proof | Refused until the account holds a factor |
| Every other step-up action, under `[security].require_mfa = false` | `require_step_up` or `require_step_up_action`, a password re-proof | Refused until the account holds a factor |
| The same, under `require_mfa` on | already refused by the floor in Context item 1 | Unchanged |

`POST /me/reauth` and `POST /ui/reauth` with a directory password are refused for that session,
and no bind is made. Signing out its own current session (`POST /auth/logout`) is not a step-up
action and stays open.

**The new-address check stays on every admitted route.** The reauth-only gates force a fresh
step-up when the request's address differs from the session's own anchor (`flag_new_client_ip`).
For this session class nothing answers that step-up once the re-bind is gone, so a request from a
new address is refused. That is not permanent: a fresh Windows SSO sign-in from the new address
mints a session anchored there. So the check is kept, and where it runs, a stolen token replayed
from another address cannot reach the binding step. It does not run in every posture:
`flag_new_client_ip` raises nothing when `[auth].admin_new_ip_step_up` is off, a named loosening,
or when the session recorded no client address. There a replayed token reaches the admitted
routes from any address. It still binds nothing without the code; what it can do is restage the
TOTP secret and draw the account's ceremony budget, the two costs named below.

**This rests on the code being required with `require_mfa` off**, which *To resolve on acceptance*
now answers yes. Once the re-bind goes, the code is the only proof at the binding step in every
posture, so with `require_mfa` off and no code a stolen session token alone would bind a factor.

**Why session termination is refused rather than admitted.** The route comment on
`revoke_my_session`, and the matching comments on the console's revoke routes, say a no-factor user
must remain able to revoke. For this session class that no longer holds. Whoever holds the directory password alone could otherwise sign every other session of
the account out, the real holder's included, with no proof beyond the sign-in. An Administrator can
still end an account's sessions, and the holder can still sign out the session in hand. The build
that removes the re-bind changes those comments, and owes two more changes with them:

- **`docs/SECURITY.md`, wherever it says a no-factor user can still end its sessions.** At least
  these passages: the gate-wrapper row for `require_reauth_only_action` ("deadlock avoidance on
  the MFA-enrollment lanes, and on session terminate"); the step-up paragraph that says four routes
  take the password-only variant "so a required-but-unenrolled user cannot deadlock", which names
  `DELETE /me/sessions/{session_id}` and `DELETE /me/sessions` among them; the session-termination
  paragraph that says a second-factor gate "would deadlock an MFA-required-but-unenrolled operator
  out of revoking their own sessions"; and the route rows for `DELETE /me/sessions/{session_id}`,
  `DELETE /me/sessions`, `POST /ui/account/sessions/revoke-others` and
  `POST /ui/account/sessions/{session_id}/revoke`. Each must say that a factorless directory
  session whose step-up is not at the identity provider is refused there.
- **A vault re-read of the session-termination cell** of the security record, whose evidence
  rests on a no-factor user being able to revoke. The build names that re-read in its pull request,
  and a Manager dispatches it as record work.

**What it does not change.** A local account still re-proves by its password. An `oidc` session
still steps up at the identity provider (ADR 0142 Amendment B), with or without a factor. A
directory session on an account that holds a factor steps up with that factor, as A5 rules.

**Sequencing.** The binding step demands the code whether or not the session also re-proved a
password, so this ADR's build does not depend on the re-bind's removal. Before that removal a
Kerberos session re-proves its password and then shows a code; after it, the code alone. Whichever
build removes `_reauth_ad` must cite this Amendment's A1 and AC-16, and must carry the gate change
in the table above in the same change. It must not remove the re-bind without admitting the
binding steps, or a factorless directory account could never enrol, and it must not admit them
without the code check this ADR's build adds. That build's ledger row is unfiled: it is the build
that removes the directory re-bind under owner ruling A5, and the Lander files it.

**Two costs, named.**

- Admitting the TOTP begin with no grant lets anyone holding a session on the account restage its
  secret. The #3025 compare-and-set then fails a confirm the real holder had in flight, and that
  confirm ends its session (section A2). It cannot change which secret is enabled, and it binds
  nothing. **It must not cost the holder's code either**, so on the TOTP path the spend is folded
  into the enable's conditional sealed write through `_write_user` (section A3): a confirm whose enable matches no row spends
  nothing. The begin's ceremony-budget draw bounds how often it can restage.
- The per-actor ceremony budget (`allow_reauth_attempt`) is keyed on the account. So whoever holds a
  session on the account can spend it with refused codes and make the holder's attempt wait out the
  window. A session-token holder can already do that today, since `POST /me/reauth` draws the
  budget before it checks the password. What changes is what stops it: today each wrong password
  also counts toward the session's re-proof cap, which revokes the session, and toward the lockout.
  A refused code counts toward neither, so a token holder can keep draining the budget for as long
  as the session lives. The code itself needs no guess limit, so the budget only paces attempts.
  For a token thief that drain is bounded by the session's life. For this ADR's own attacker, who
  holds the directory password and can mint a fresh Windows SSO session at will, it is not: ending
  the session only starts another. What ends it is disabling the account, or the directory password
  being changed. This is accepted as a nuisance that denies enrolment and binds nothing. Nothing
  alerts an Administrator: the refused rows reach the account's own feed and the audit log, which an
  Administrator reads with `Permission.AUDIT_READ`; once the holder reports it, the Administrator
  can disable the account.

### A2. Re-baseline: what has shipped since this record was drafted

At least four parts of the record describe code that has since changed. Each is marked done here.

- **Context item 6 is closed (BACKLOG #3025).** `set_totp_secret` stages a secret only where TOTP is
  off (`totp_stage`), on all three backends. `enable_totp` takes `expected_secret_cell`, the cell
  the confirm verified a code against, and writes only where the row still holds it and TOTP is
  still off. `confirm_mfa_enrollment` takes `verified_cell` from the same account read as the staged
secret, before the floor and the directory lookup, and on an enable that
  matches no row it ends the session it rotated, returns `session_lost`, and writes
  `auth.mfa_enroll_refused`. **Section 3's bullets "The enable turns on only the secret that was
  verified" and "A confirm whose enable did not take effect ends its session" are shipped**, and
  the build adds nothing for them. The Consequences line "an `enable_totp` that binds the verified
  secret" is dropped from what the build costs.
- **Context item 7 is closed (BACKLOG #3014).** `ui_webauthn_verify` draws `allow_reauth_attempt`
  after the gate's write-floor charge and before the service runs, and refuses over budget.
  **Section 7's "The build adds the ceremony-budget draw to `ui_webauthn_verify`" is shipped**, and
  the Consequences line "the ceremony budget on the passkey finish route" is dropped.
  *Note (2026-10-29, BACKLOG #3690 items 5 and 6).* The route now asks the factor-binding rule
  first and skips the draw for a session it refuses, logging each such request instead, so a
  password holder refused there in a loop spends none of the real holder's budget on this route.
  At least `POST /ui/mfa`, `POST /ui/reauth` and `POST /ui/reauth/webauthn` still draw it for that
  session. A refused code is not that
  case: it comes from a session on an account with no factor, which is still charged, so section
  7's bound on code tries holds. The route's 429 sends the console ceremony routes' constant
  `Retry-After: 30`.
- **Context item 3 is closed for the binding step (BACKLOG #3014, #3061).**
  `finish_webauthn_registration` asks `_factor_binding_is_blocked` itself, before the floor, and
  again after the directory lookup, both before the challenge pop. So section 1's check 1 is
  already made on the passkey path. On the TOTP path, `confirm_mfa_enrollment` asks it once after
  the lookup and refuses only a passkey; a TOTP enabled meanwhile is left to the compare-and-set.
  *Note (2026-10-29, BACKLOG #3690 items 1 and 3).* The passkey path has a third ask since engine
  PR 2617: `add_webauthn_credential(for_session=...)` asks the same rule inside the insert's own
  transaction, so a factor bound after the second ask is refused at the write too.
  The build adds no factor check of its own. It adds the `auth.enrolment_code_refused` row with
  `factor_present` beside the `auth.mfa_denied` row those refusals already write, for an unstamped
  directory session only. The Consequences line "both checks in both binding steps" now means the
  code check alone.
- **The Out-of-scope bullet on the passkey finish route for local accounts is closed too.** The
  finish's own `_factor_binding_is_blocked` asks (#3014) apply to every account type, since
  `_owes_enrolled_factor_hash` is not limited to directory accounts there. That case is no longer
  open.

**Three criteria become regression pins.** What each names as pinned already passes, so none can
"fail on the code before this build". The build keeps the named test green, and adds only what the
bullet says.

- **AC-5** (restated) -- IF a passkey challenge staged while the account had no factor finishes
  after the account gained one, THEN THE SYSTEM SHALL refuse it, bind nothing, and stamp nothing.
  Pinned today by `tests/test_passkey_finish_factor_binding.py`. The build adds, for an unstamped
  directory session, the `auth.enrolment_code_refused` row with `factor_present`.
- **AC-13** (restated) -- the #3025 behaviour: no replacing secret is enabled, and an enable that
  does not take effect ends the rotated session and returns no token, for a local account and a
  directory account alike. The local-account half is pinned today by the BACKLOG #3025 tests in
  `tests/test_mfa.py`, which all sign in a local account. The directory-account half has no test
  yet: the build adds one, in which a valid code was presented and, because the enable did not take
  effect, was not spent (section A3).
- **AC-14** (restated) -- the passkey finish route refuses before the service runs when
  `allow_reauth_attempt` refuses and the write floor is not exhausted. Pinned today by
  `test_webauthn_verify_draws_on_the_ceremony_budget` in
  `packaging/messagefoundry-webconsole/tests/test_webui_search_sso.py`, not the file AC-14 names.
  *Note (2026-10-29, BACKLOG #3690 item 6).* Except for a session the factor-binding rule refuses:
  the route does not draw the budget for it, and the service answers it. A refused code comes from
  a session that rule does not refuse, so AC-14 still holds for every code try.

### A3. The order of the checks in the binding steps

`finish_webauthn_registration` gained a directory re-lookup, `_directory_vouches_for_factor`
(BACKLOG #3061), which this record did not name. The code check goes after it. The order after the
build, with what the challenge does at each refusal:

1. Load the account, and check the label. A refusal leaves the challenge staged.
2. Peek the staged challenge. If none matches, pop it and answer "ceremony expired".
3. The dead-session guard, then the #3014 factor check. A refusal pops the challenge.
4. The login-to-MFA floor. A refusal leaves the challenge staged.
5. The #3061 directory lookup. A `session_lost` refusal pops the challenge, and any other refusal
   leaves it staged.
6. The dead-session guard again, then the factor check again. A refusal pops the challenge.
7. **New: the code read**, for an unstamped session on an `ad` account: present, well formed,
   matching the digest on the account row the lookup returned, and not expired. A refusal leaves
   the challenge staged, gets the one reply of section 3, and writes `auth.enrolment_code_refused`.
8. Pop the challenge, and verify the attestation.
9. The discoverable check, then the duplicate check on the credential id, then **new: a read of
   whether the account already holds a passkey with this label**.
10. **New: the spend**, one conditional sealed write through `_write_user`. It clears the code's digest only where the digest
    still matches and has not expired, the account is enabled, TOTP is still off, and the account
    holds no passkey, the same conditions the TOTP fold below puts on its write. So a
    factor bound by a path that asks no code, after the step 6 re-check and before this write, is
    not skipped over. A spend that changes no row is refused, as `factor_present` when a re-read
    shows the account now holds a factor and as `code_refused` otherwise. The challenge is already
    popped, so that ceremony ends, nothing is written, and the code is not spent.
11. Write the credential, then stamp and rotate the session.

**The residual after step 10, named.** A factor bound by a path that asks no code between the spend
and the credential write in step 11 is not seen. That window holds no awaited read, unlike the one
between steps 6 and 10, which awaits the duplicate read and the label read (step 7 reads the code
against the row the lookup returned, so it adds no read), and in
which another process on the same store, an engine shard included, can write. (The attestation
verify itself runs on the event loop and yields to nothing.) The code is spent by then, and the
second passkey binds on a code the holder did show.
*Note (2026-10-29, BACKLOG #3690 items 1 and 3).* Narrowed since this was written: step 11's
credential write is itself conditional (engine PR 2617), so a factor bound in that window is
refused at the write and the second passkey does not bind, provided the build keeps the
conditional write. What the residual still costs is the code, which step 10 spent.

**The label check before the spend is new.** Today the method checks only the label's length before
the pop. A clash with another of the account's labels shows only when `add_webauthn_credential`
fails on the `(user_id, label)` index, which is after the spend. Without the read in step 9, a
refusal section 3 says "does not cost the code" would cost it. The insert's integrity error stays
the backstop for a label written concurrently, and that rare race does cost the code.

**A `factor_present` refusal keeps popping the challenge, as it does today.** The ceremony was staged
against an account state that no longer holds, and a fresh begin re-asks the begin gate, which
refuses the session until it proves the factor it now has. A refused code does not pop, so a
mistyped code costs neither the code nor the ceremony.

**Why after the lookup, not before.** The lookup re-reads the account, so the code is checked
against the row as it stands after the network round trip. A directory refusal also tells the
caller nothing about whether a code is outstanding, because no code was read.

`confirm_mfa_enrollment` follows the same order up to the code: read the staged secret and
`verified_cell`, then the floor, the directory lookup, the dead-session guard and its one factor
check, **then the code read**. After those come the TOTP step verify and consume, then the stamp and
rotation, **then the enable with the spend folded into it**: one conditional sealed write, through
`_write_user`, that turns TOTP
on and clears the code's digest, only where the staged cell is still `verified_cell`, TOTP is still
off, the account holds no passkey, the account is enabled, and the digest still matches and has not
expired. The no-passkey condition is new, and it binds only this code-carrying write, for an
unstamped directory session: the TOTP leg asks the factor check once, before the recovery codes
are hashed off the event loop, and a passkey bound in that window by a path that asks no code would
otherwise be skipped over. A confirm that carries no code, a stamped session adding TOTP beside a
passkey it holds included, keeps today's enable, conditioned on the staged cell and TOTP off
alone. A fold that fails on its code keeps today's `auth.mfa_enroll_refused` reason, which the
store state decides, and writes no `auth.enrolment_code_refused` row, so the account's feed still
cannot tell the code cases apart. So a confirm whose
enable matches no row spends nothing, and two ceremonies racing one code still cannot both succeed.
**The fold's cost, named.** A code that passed the read but is revoked, expires, or is spent by a
racing passkey ceremony before the enable now fails at the enable. By then the TOTP step is
consumed and the session rotated, so that confirm answers `session_lost` and writes
`auth.mfa_enroll_refused`, not the one code-refused reply of section 3. AC-3 holds for a code
refused at the read, which is every case but that race. The race fails closed, binds nothing, and
tells the caller nothing about the code it did not already know. That enable already
ends the rotated session when it changes no row (#3025). Section 3's "First read the code" is
amended to that place: still before the TOTP step is consumed, but after the floor, the lookup and
the re-check. Section 3's "Then spend the code" before the stamp, and its "A failure after the spend
costs the code" for the TOTP path, are replaced by this folded write. A session revoked mid-ceremony
now costs a TOTP step and no code.

### A4. The host command refuses while an engine holds the store

Section 6 left the engine-stopped rule documented and unenforced, as `admin-unlock` and
`provision-admin` leave it today. The review asked for it to be enforced, on the ground that a second
process appending to the audit chain could fork it (ADR 0194). **The tree does not bear that
ground out, so this record does not rest on it.** Every backend already serializes an append from a
second process. On SQLite, `_append_audit_row` names *"a CLI command run beside a serving engine"*:
the UNIQUE constraint on `seq` refuses the second row, and one retry under the write lock takes the
next position. PostgreSQL takes `pg_advisory_xact_lock` on the chain (H-7), and SQL Server takes an
application lock on it (`_AUDIT_APPEND_LOCK`). The command's issue is also one conditional sealed write
through `_write_user` (section 6). So beside a live engine its audit row would not fork the chain.

**What is enforced, and why.** This answers section 6's "until the build shows it can" and the
Consequences line that leans on it: a second process can append safely, so audit-chain safety is no
longer a reason for the rule. The rule rests on one reason only. A host command that mints a
credential should not run against a store a serving engine is using **where it can tell**, and a
file that is not the store must never be keyed by it. So `issue-enrolment-code` checks before it
opens the store or writes, where the tree has a check.

- **On SQLite.** The command calls `_sqlite_store_held_elsewhere` (BACKLOG #1915), as `rotate-key`
  does, on the settings `_host_gated_store_settings` resolves. **It refuses on `held`, on
  `not_a_store`, and on `unchecked`.** `held` is a serving engine's lock. `not_a_store` is a
  zero-byte file or a SQLite file with no audit table, which the store open would otherwise build
  and key as a new store; AC-11 already says refuse rather than create, and `rotate-key` refuses it
  too. A file that is not a SQLite database at all is a fourth case: today the probe answers
  all-clear on `SQLITE_NOTADB` and leaves that file to the store open to report. The build adds a
  refusal for it before the open, so AC-17 holds for it. `unchecked` is a store the probe cannot
  read, or one not in WAL mode, where an idle engine
  holds no lock. Refusing that is stricter than `rotate-key`, which prints a note and goes on: a
  command that issues a credential fails closed when it cannot tell. **The cost, named:** a SQLite
  site whose store stays `unchecked`, not in WAL mode or not openable read-write by the operator's
  account, has no host path until it fixes that state. A server store in the same cannot-tell state
  proceeds with a note, because there no probe exists to fix, and the append locks above answer
  the chain. Keeping a local Administrator (section 6) avoids both.
- **On PostgreSQL and SQL Server, nothing in the tree probes for an engine, and the command does not
  refuse.** Refusing there would remove the host path from the site section 6 exists for, a
  server-store site with no Administrator who can issue a code, on a ground the append locks above
  already answer. The command prints a note that it could not check, as `rotate-key` does there.
  So the engine-stopped rule is enforced on SQLite only, and documented for a server store.
- **Not done here: the same probe in the shared host gate.** `_host_gated_store_settings` also
  serves at least `admin-unlock` and `admin-reset-totp`, which document the same rule and enforce
  none. Moving the probe into that gate would cover them all. That changes commands this ADR does
  not decide, so it is left as its own item, unfiled; by subject, "the shared host gate probes for
  a serving engine".
- **The residual, named.** An engine started after the probe is not seen, as `rotate-key`'s own
  docstring states. The probe narrows the window to the command's run; it does not close it.

### A5. The issuing Administrator learns when a code is spent

Section 7 routes `auth.enrolment_code_used` to the account that enrolled, and the issued row to the
issuer. So the one person who knows whether the handover went to the right holder never learns that
the code was used, or from where. **When a code is spent, the issuing Administrator is told.**

- The `users` row records the issuer with the digest: a third nullable column holding the issuing
  Administrator's account id, or null for a code the host command issued. Issuing writes it with
  the digest, and every statement that clears the digest clears it too. The spend's conditional
  sealed write returns the issuer it cleared, so the step that writes the rows below knows whom to
  tell. `_write_user` returns the record after the change, where the issuer is already null, so the
  spend's change captures the issuer from the record `_write_user` read, in the same write, and
  never from a separate read before it, which a re-issue between the two would make name the wrong
  Administrator.
- `auth.enrolment_code_used` does not name the issuer. Section 7 returns that row to the account
  that spent the code, and whoever spent it, an interceptor included, should not learn which
  Administrator issued it. Its client column records where the spend came from, as every audit
  row's does.
- **A second row, `auth.enrolment_code_spent_notice`, is written under the issuer's name** in the
  same step, its detail naming the account that spent the code, the ceremony, and the client
  address the spend came from. It is a separate
  row because `GET /me/security-events` selects `auth.*` rows by actor, on an index keyed on actor
  (`_security_events_where`). Widening that query to a detail field would give up the index. The
  issuer's own feed therefore returns the notice row with no query change. **The cost:** a filter by
  actor over the audit log returns this row under the issuer, though the issuer did not act. Its
  action name says it is a notice, its detail marks the actor column as the recipient
  (`actor_role`: `recipient`, section 7), and its detail names the account that did act. The build
  documents that, in `docs/SECURITY.md`'s Audit section, as the one audit row whose actor is not
  the account that acted, so an investigator filtering by actor does not read it as the issuer's
  act.
- Where the issuer has a `notify_email`, the engine sends it a notice that the code was spent,
  naming the account and the time and never the code. As in section 4, that notice is a courtesy:
  the security-event row is the record.
- A code from the host command, or one whose issuer's account no longer exists, has no one to
  notify. Its used row is read with `Permission.AUDIT_READ`, as every audit row is.

### A6. Two points the review raised that are not adopted

- **A shorter lifetime than 24 hours.** A shorter life narrows the window in which an intercepted
  code still works. It is kept at 24 hours. A code handed over late in a day, or across time zones,
  would otherwise often expire before use, and each re-issue is one more handover, which is the step
  the control rests on. Single use and revocation already bound what an intercepted code is worth.
  The issuer's notice (A5) bounds nothing: it arrives after the spend, as detection, and is named
  here only because it shortens how long a wrong spend goes unnoticed. The *To resolve on acceptance* item on the lifetime stands, with this
  trade recorded.
- **On an OIDC site whose identity provider asserts MFA, bind the first factor through the identity
  provider instead of a code.** Noted, not adopted. A federated session with the claim gate on is
  already stamped and needs no code (section 1). The cases a code covers are a Kerberos session,
  which serves unbound accounts only (ADR 0142 Amendment C, engine PR 1918) and so has no
  identity-provider subject to step up against, and a federated session on a site that turned the claim gate off, where the
  identity provider's MFA assertion is what the site chose not to rely on. A later ADR may take it
  up for a site that binds every directory account.

### What this amendment changes in the build's cost

Read the Consequences list with these changes. The `users` row gains three nullable columns, not
two: the digest, the expiry and the issuer. There are five audit actions, not four, with
`auth.enrolment_code_spent_notice`; section 7's "All four actions" reads five. There are two notice
kinds, not one: the issue notice and the spent notice. The TOTP enable's conditional sealed write also
spends the code (A3), and so does the passkey spend, each conditioned on the account holding no
factor; the condition binds only the code-carrying write, never the enable of a confirm that
carries no code. The passkey finish gains a label read (A3). The three new columns join the
`users` row's integrity seal (BACKLOG #2592), so on a store with a row sealer a database write
without the sealing key cannot plant a code digest or redirect the spent notice. A store with no
row sealer has no such control, as for every other sealed column. Added as plain sealed fields they
would break every existing user's seal: `UserAuthzRecord.seal_fields` seals every `UserRow` field
but `authz_seal`, and `seal_bytes` encodes a `None` field by its name, so three new fields change
the sealed bytes of every existing user, and `reseal_user_records`, rotate-key's pass, refuses a
record that fails its seal. So each new column enters the sealed field set only when it is
non-null, as `passkey_digest` already does for a passkey's `discoverable` (it leaves the field out
of the digest while it is false): a user who never held a code keeps the seal it was sealed under,
and on a store with a row sealer a code digest planted outside the store still fails the seal. The
build pins that rule with a test that a non-null value of each column changes the seal. Every
write that sets or clears them goes through `_write_user`: at least the code's issue, its spend,
the TOTP fold, the revoke and the disable's clear. The issue, the spend and the fold are
conditional sealed writes; the disable's clear is unconditional (section 3). The static scan in
`tests/test_user_seal.py` pins each `users` UPDATE written as SQL text in the store modules to the
sealing writers. The host command gains the SQLite probe refusals and the non-database refusal (A4).
**The begin routes' ceremony-budget draw, and the rest of the A1 table, belong to the build that
removes `_reauth_ad`**, the one that admits the begins with no grant (A1, *Sequencing*; AC-16).
This ADR's build does not add them, and that build must not admit a begin without the draw. The two lines A2 drops are dropped. Section 6's no-issuer state, "under
`require_mfa`", holds with `require_mfa` off too once the re-bind is gone, since A1 refuses a
factorless directory Administrator every step-up action, the issuing route's included. **And a
negative the list above does not name:** on a `[security].require_mfa = false` site, once the re-bind goes,
every directory operator with no factor loses every step-up-gated action, admin writes and session
termination included, until an Administrator issues a code and the operator enrols. Under the
default `require_mfa` the floor already refused those actions, so only the off posture changes.

### A7. Acceptance criteria this amendment adds

- **AC-16** -- WHEN an unstamped directory session on an account with no engine factor, whose
  step-up is not at the identity provider, calls a session-termination route, or with
  `[security].require_mfa` off calls any step-up action other than an enrolment begin or a binding
  step, THE SYSTEM SHALL refuse it once the directory re-bind is removed, on the engine API and the
  web console alike, and SHALL refuse `POST /me/reauth` and `POST /ui/reauth` with a directory
  password without making a bind. WHEN that session calls an enrolment begin, the console's TOTP
  confirm form, or a binding step from its own anchored address, in either `require_mfa` posture,
  THE SYSTEM SHALL admit it without a step-up grant, SHALL draw the per-actor ceremony budget at
  each begin, and SHALL bind the factor only with a valid code for the account. WHERE the
  new-address check runs, THE SYSTEM SHALL refuse each of those routes from an address other than
  the session's anchor.
  → `tests/test_directory_enrolment_code.py`, in the build that removes `_reauth_ad`
- **AC-17** -- WHEN `issue-enrolment-code` runs against a SQLite store that another connection holds,
  a file that is not a store, or a store the probe cannot check, THE SYSTEM SHALL refuse before it
  opens the store, issue no code, append no audit row, and leave the file as it was. WHEN it runs
  against a PostgreSQL or SQL Server store, THE SYSTEM SHALL print a note that it could not check
  for a serving engine.
  → `tests/test_directory_enrolment_code.py`
- **AC-18** -- WHEN a code an Administrator issued is spent, THE SYSTEM SHALL write
  `auth.enrolment_code_spent_notice` under that Administrator's name, SHALL return the notice row
  in that Administrator's own `GET /me/security-events` with the client address the spend came
  from, and SHALL send the Administrator's
  `notify_email`, where one is set, a notice that names no code. THE SYSTEM SHALL NOT name the
  issuer in the `auth.enrolment_code_used` row.
  → `tests/test_directory_enrolment_code.py`
- **AC-19** -- WHEN a binding step on an unstamped directory session is refused for its code at the
  code read (A3 step 7, and its place in the TOTP order), THE SYSTEM SHALL leave the passkey
  challenge staged and the TOTP step unconsumed. A code refused later, at the passkey spend or at
  the TOTP fold, is the race A3 names: that refusal comes after the pop or the consume, and this
  criterion does not reach it. WHEN it is refused
  as `factor_present`, THE SYSTEM SHALL pop the passkey challenge. In both binding steps the code
  SHALL be read after `_directory_vouches_for_factor` and the factor check that follows it. WHEN a
  TOTP confirm's enable matches no row, THE SYSTEM SHALL leave the code unspent. WHEN a passkey
  label clashes with one the account holds, THE SYSTEM SHALL refuse before the spend. IF the
  account gains TOTP or a passkey after the passkey finish's step 6 re-check and before its spend,
  THEN THE SYSTEM SHALL refuse the spend, spend nothing in that ceremony, and write no credential
  row. IF the account gains a passkey after the TOTP confirm's factor check and before its enable,
  THEN THE SYSTEM SHALL leave TOTP off and spend nothing in that ceremony. Where that factor was
  bound by a path that asks no code, the code stays unspent.
  → `tests/test_directory_enrolment_code.py`
